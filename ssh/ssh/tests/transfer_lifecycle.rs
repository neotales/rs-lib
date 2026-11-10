//! Hermetic lifecycle coverage for a caller-managed SSH transfer.
//!
//! This test drives the public `neotales-ssh` session and SCP transfer state
//! machines directly, because a CLI front end is the thing that would normally
//! sit on top of them and this repository does not contain one.
//! The stream is loopback-only, the peer is dropped in the middle of a body,
//! and the test owns the same cancellation/deadline/staging guard a future
//! task adapter would use.

use std::{
    collections::VecDeque,
    fs,
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use neotales_ssh::{
    ClientSessions, ScpClient, Writer,
    channel::{
        ChannelTransport, INITIAL_CHANNEL_WINDOW, MAX_CHANNEL_PACKET_SIZE, SSH_MSG_CHANNEL_OPEN,
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS,
    },
    scp::ScpError,
    session::SessionEvent,
};

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn direct_child_process_count(pid: u32) -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "pid=", "--ppid", &pid.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| line.trim().parse::<u32>().is_ok())
                .count(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-axo", "pid=,ppid="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    let process = fields.next()?.parse::<u32>().ok()?;
                    let parent = fields.next()?.parse::<u32>().ok()?;
                    (parent == pid).then_some(process)
                })
                .count(),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "@(Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} }}).Count"
        );
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<usize>()
            .ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        None
    }
}

#[derive(Default)]
struct SessionTransport {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl ChannelTransport for SessionTransport {
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.outbound.push(payload.to_vec());
        Ok(())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.inbound.pop_front().ok_or(())
    }
}

fn channel_confirmation() -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    writer.write_uint32(0);
    writer.write_uint32(7);
    writer.write_uint32(INITIAL_CHANNEL_WINDOW);
    writer.write_uint32(MAX_CHANNEL_PACKET_SIZE);
    writer.into_bytes()
}

fn channel_success() -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_SUCCESS);
    writer.write_uint32(0);
    writer.into_bytes()
}

fn open_exec_session() -> ClientSessions<SessionTransport> {
    let mut transport = SessionTransport::default();
    transport.inbound.push_back(channel_confirmation());
    let mut sessions = ClientSessions::new(transport);
    let session = sessions.open_session().unwrap();
    assert!(matches!(
        sessions.dispatch_one().unwrap(),
        SessionEvent::Opened { session: opened } if opened == session
    ));
    sessions
        .request_exec(session, b"scp -f -- artifact.bin", true)
        .unwrap();
    transport_inbound_success(&mut sessions);
    assert!(matches!(
        sessions.dispatch_one().unwrap(),
        SessionEvent::RequestSucceeded { .. }
    ));
    sessions
}

fn transport_inbound_success(sessions: &mut ClientSessions<SessionTransport>) {
    sessions
        .connection_mut()
        .transport_mut()
        .inbound
        .push_back(channel_success());
}

struct ManagedStream {
    stream: TcpStream,
    partial: fs::File,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl ManagedStream {
    fn new(
        stream: TcpStream,
        partial_path: PathBuf,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self, io::Error> {
        stream.set_read_timeout(Some(Duration::from_millis(5)))?;
        let partial = OpenOptions::new()
            .create(true)
            .append(true)
            .open(partial_path)?;
        Ok(Self {
            stream,
            partial,
            cancelled,
            deadline,
        })
    }
}

impl Read for ManagedStream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "transfer cancellation requested",
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "transfer deadline reached",
                ));
            }
            match self.stream.read(target) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                result => {
                    if let Ok(count) = result
                        && count > 0
                    {
                        self.partial.write_all(&target[..count])?;
                    }
                    return result;
                }
            }
        }
    }
}

impl Write for ManagedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "transfer cancellation requested",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transfer deadline reached",
            ));
        }
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

struct ActiveThread(Arc<AtomicUsize>);

impl ActiveThread {
    fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(counter))
    }
}

impl Drop for ActiveThread {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Staging {
    root: PathBuf,
}

impl Staging {
    fn new() -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            ".neotales-ssh-transfer-{}-{time}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("artifact.partial"), b"partial bytes").unwrap();
        Self { root }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
enum FailureMode {
    PeerDisconnect,
    Cancellation,
    Timeout,
}

// Keep one scenario together so each failure mode exercises the same complete
// worker, peer, child-process, and staging cleanup lifecycle.
#[allow(clippy::too_many_lines)]
fn run_disconnect(mode: FailureMode) {
    let child_processes_before = direct_child_process_count(std::process::id());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (peer_ready_sender, peer_ready_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let active_threads = Arc::new(AtomicUsize::new(0));
    let peer_active = ActiveThread::enter(&active_threads);
    let peer = thread::spawn(move || {
        let _active = peer_active;
        let (mut stream, _) = listener.accept().unwrap();
        // The client may already be gone. Every failure mode this test exercises
        // *is* the client going away, so end-of-stream here is the expected
        // outcome rather than an error. A blocking `read_exact` turned that
        // expected outcome into a panic inside this thread, which surfaced as an
        // unrelated failure with no connection to what was being tested.
        let mut acknowledgement = [0_u8; 1];
        match stream.read(&mut acknowledgement) {
            Ok(0) | Err(_) => return,
            Ok(_) => assert_eq!(acknowledgement[0], 0),
        }
        stream.write_all(b"C0644 1048576 artifact.bin\n").unwrap();
        stream.write_all(&[b'x'; 4096]).unwrap();
        stream.flush().unwrap();
        peer_ready_sender.send(()).unwrap();
        release_receiver.recv().unwrap();
        drop(stream);
    });

    let stream = TcpStream::connect(address).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now()
        + match mode {
            FailureMode::PeerDisconnect | FailureMode::Cancellation => Duration::from_secs(2),
            FailureMode::Timeout => Duration::from_millis(120),
        };
    let staging = Staging::new();
    let staging_root = staging.root.clone();
    let partial_path = staging.root.join("artifact.partial");
    let stream =
        ManagedStream::new(stream, partial_path, Arc::clone(&cancelled), deadline).unwrap();
    let worker_active = ActiveThread::enter(&active_threads);
    let worker = thread::spawn(move || {
        let _active = worker_active;
        let mut transfer = ScpClient::new(stream);
        let result = transfer.download();
        if let Ok(file) = &result {
            fs::write(staging.root.join("published.bin"), &file.data).unwrap();
        }
        drop(transfer);
        drop(staging);
        result
    });

    // Generous, because this is not a test about a one-second bound. Waiting
    // exactly long enough for the peer to get 4 KiB into a transfer, on a machine
    // running the whole suite in parallel, is a race with the scheduler. One
    // second was chosen when the machine was idle and became a failure when it
    // was not.
    peer_ready_receiver
        .recv_timeout(Duration::from_secs(60))
        .expect("peer did not reach the middle of the transfer");
    let sessions = open_exec_session();
    assert_eq!(
        sessions
            .connection()
            .transport()
            .outbound
            .first()
            .and_then(|payload| payload.first()),
        Some(&SSH_MSG_CHANNEL_OPEN)
    );
    assert_eq!(
        sessions
            .connection()
            .transport()
            .outbound
            .get(1)
            .and_then(|payload| payload.first()),
        Some(&SSH_MSG_CHANNEL_REQUEST)
    );

    let peer_released = match mode {
        FailureMode::PeerDisconnect => {
            release_sender.send(()).unwrap();
            true
        }
        FailureMode::Cancellation => {
            cancelled.store(true, Ordering::Release);
            false
        }
        FailureMode::Timeout => false,
    };
    let result = worker.join().unwrap();
    if !peer_released {
        release_sender.send(()).unwrap();
    }
    peer.join().unwrap();
    drop(sessions);

    assert!(matches!(result, Err(ScpError::Io(_))));
    assert_eq!(active_threads.load(Ordering::Acquire), 0);
    // Poll rather than sampling once. Joining the worker means the transfer's own
    // thread has finished, but the process it forked is a separate thing with its
    // own exit and its own reaping, and on a loaded machine that can still be in
    // flight at the instant the first sample is taken. Sampling once made this
    // fail intermittently, and only under a full parallel run -- it passed every
    // time in isolation, which is the signature of a race rather than of a leak.
    //
    // A genuinely abandoned child never exits, so waiting for the count to settle
    // does not weaken the assertion: it distinguishes "still on its way out" from
    // "left behind", which a single sample cannot.
    if let Some(before) = child_processes_before {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match direct_child_process_count(std::process::id()) {
                Some(after) if after == before => break,
                Some(after) if after < before => break,
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                let after = direct_child_process_count(std::process::id());
                panic!(
                    "the transfer left a child process behind: {after:?} direct children, \
                     expected {before}"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
    assert!(
        !staging_root.exists(),
        "disconnect left staging content at {}",
        staging_root.display()
    );
    assert!(!Path::new(&staging_root).exists());
}

#[test]
fn peer_disconnect_cancellation_and_timeout_join_workers_and_remove_staging() {
    // The client/session and transfer modules deliberately do not create a
    // process. This source-level assertion makes that invariant explicit
    // alongside the runtime thread and staging assertions below.
    for source in [
        include_str!("../src/session.rs"),
        include_str!("../src/scp.rs"),
    ] {
        assert!(!source.contains("std::process"));
    }

    run_disconnect(FailureMode::PeerDisconnect);
    run_disconnect(FailureMode::Cancellation);
    run_disconnect(FailureMode::Timeout);
}
