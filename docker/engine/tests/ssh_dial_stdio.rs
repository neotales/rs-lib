//! A remote daemon, reached only over SSH, answering a real Engine request.
//!
//! `RawTarget::Stream` exists for an endpoint the transport cannot dial, and
//! this file is the proof that it is more than a type that compiles. Every test
//! that needs a peer stands up a **real `sshd`** on a loopback port, runs
//! `docker system dial-stdio` through it, and reads the answer off the wire —
//! for both mechanisms, because two mechanisms where one proves nothing leaves
//! the other unmeasured.
//!
//! # Why a real `sshd` and not a fixture
//!
//! A duplex fixture can show that the transport sends a request and reads a
//! response. It cannot show that an SSH session can *carry* Engine traffic, and
//! that is the whole question: the `dial-stdio` channel is a process's standard
//! streams, the Engine's responses are binary, and SSH adds its own packet
//! framing, its own window, and its own cipher on top. `neotales-ssh`'s own
//! notes record that a **handshake-only** lane could not find a real packet-cipher
//! defect — the keys agree and then both sides stop, so the nonce never appears
//! in a sealed packet. The same argument applies with more force here: a lane
//! that stopped at "the connection opened" would pass against a transport that
//! cannot complete a request.
//!
//! So each test drives a complete request and asserts on the Engine's own
//! answer. `_ping`, `info`, and a 404 are used rather than a hand-written
//! document, because the answer then comes from the daemon and not from this
//! file. A fixture is still used where the claim is about *this crate* — the
//! per-request factory contract, the `Host` header, the frame reader — and never
//! where the claim is about the wire.
//!
//! ## The measure
//!
//! Revert `docker/engine/src/raw/transport.rs` and every test here that carries
//! a request fails, because the `Stream` variant and the arm in `connect` are
//! what carry it. Break one mechanism and only that mechanism's tests fail,
//! which is what makes the two worth having separately.
//!
//! ## Opt-in
//!
//! The tests that need a peer are `#[ignore]`d and run explicitly:
//!
//! ```text
//! ./eng/ci/with-private-account-db.sh cargo test -p neotales-docker --all-features \
//!   --test ssh_dial_stdio -- --include-ignored --test-threads=1
//! ```
//!
//! They need Linux, OpenSSH tools, a reachable Docker daemon, a `docker` group,
//! and non-interactive `sudo` access to create and remove a disposable group
//! member. The wrapper additionally needs sudo permission to create private
//! mount and PID namespaces with private `/proc`, plus kernel support for tmpfs
//! and overlay filesystems. It isolates account databases, `/tmp`, and the mail
//! spool so fixture account operations cannot modify host account data. Missing
//! host prerequisites print why and return; the Gitea long-test job checks them
//! before running so its green result cannot be a silent skip.
//!
//! Gitea selects `NEOTALES_DOCKER_SSH_FIXTURE=debian`: the same real SSH and
//! Engine assertions use the repository's disposable Debian SSH server with the
//! host Docker socket. Credentials are streamed into the container rather than
//! bind-mounted from private `/tmp`; no host account or `SELinux` policy changes
//! are needed. Each authentication mode still permits only its own mechanism.

#![allow(missing_docs)]
// Every test in this file drives an SSH session, and the `ssh` feature is off by
// default. The gate is at the crate root rather than on each test so that a
// default-features build compiles an empty test binary instead of failing on four
// references to a constructor that does not exist. `stream_target.rs` is the
// counterpart: it covers the same `RawTarget::Stream` without needing a peer, and
// it runs in every lane.
#![cfg(all(feature = "ssh", unix))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use neotales_docker::raw::{
    Duplex, RawEngine, RawRequest, RawTarget, StreamFactory, engine_result, info, ping,
};
use neotales_docker::{ApiVersion, Error, raw};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

#[path = "support/docker_ssh_fixture.rs"]
mod docker_ssh_fixture;

const MAX_ACCOUNT_LOCK_ATTEMPTS: usize = 40;

/// The version the owned transport is pinned to, matching the crate's ceiling.
const VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 53,
};

/// How long a fixture waits for the port it asked for.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may take end to end.
///
/// Every wait in this file is bounded. A duplex that never completes is the
/// failure this suite most wants to report, and an unbounded test turns that
/// into a hung run rather than a readable one.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The per-record bound this file's event stream is read at.
///
/// Above [`raw::MAX_RECORD_BYTES`], which is 8 MiB, because the largest
/// `exec_create` event the daemon measured here was 60,500,326 bytes and the
/// stream refuses a record rather than truncating it. Round to 64 MiB, which
/// admits that record with room to spare and stays a bound. See the test below
/// for why the crate default is not raised instead.
const EVENT_LIMIT: usize = 64 * 1024 * 1024;

/// Collects every JSON record in `response`, refusing a record over `limit`.
///
/// [`collect_json_frames`] is the one this suite would otherwise call, and it
/// reads at the crate default. The event test needs a different number, so it
/// gets the reader directly rather than the convenience wrapper — there is no
/// way to hand a limit to the wrapper, and adding one for a single test would
/// widen the public surface this suite is not here to widen.
async fn collect_json_frames_bounded(
    response: raw::RawResponse,
    limit: usize,
) -> Result<Vec<serde_json::Value>, Error> {
    let mut frames = response.into_frames().with_record_limit(limit);
    let mut values = Vec::new();
    while let Some(value) = frames.next_json().await? {
        values.push(value);
    }
    Ok(values)
}

/// How the fixture's `sshd` will authenticate the login user.
///
/// A parameter rather than three separate fixtures, because the three ways in
/// are the claim under test and a fixture per way would be three copies of the
/// server setup to keep in step. The default is the public-key one every other
/// test in this file uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Auth {
    /// One unencrypted Ed25519 identity, listed in `authorized_keys`.
    KeyFile,
    /// The same identity, encrypted with [`PASSPHRASE`], and the passphrase
    /// handed to the client. Exercises the encrypted-key path end to end.
    EncryptedKeyFile,
    /// No public key at all, and the login user's password verified instead.
    Password,
}

/// The passphrase the encrypted identity is locked with.
///
/// A canary rather than a word, so a test that accidentally prints it is
/// visible. It is a *fixture* value and appears in this file's source on purpose;
/// the redaction claim is about a value a caller supplies, which is what
/// `tests/debug_surface.rs` checks.
const PASSPHRASE: &str = "ndocker-ssh-fixture-passphrase-4c1e8a7b";

/// A throwaway `sshd`, its keys, and the paths a client needs to reach it.
struct Fixture {
    server: FixtureServer,
    _directory_guard: tempfile::TempDir,
    directory: PathBuf,
    port: u16,
    identity: PathBuf,
    known_hosts: PathBuf,
    user: String,
}

enum FixtureServer {
    Host {
        child: Child,
        account: TemporaryAccount,
        log: PathBuf,
    },
    Docker(docker_ssh_fixture::DockerFixture),
}

impl Fixture {
    /// `sshd`'s own account of what it just did.
    fn sshd_log(&self) -> String {
        match &self.server {
            FixtureServer::Host { log, .. } => std::fs::read_to_string(log).unwrap_or_default(),
            FixtureServer::Docker(server) => server.logs(),
        }
    }

    fn password(&self) -> &str {
        match &self.server {
            FixtureServer::Host { account, .. } => account.password.as_str(),
            FixtureServer::Docker(server) => server.password.as_str(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let FixtureServer::Host { child, .. } = &mut self.server else {
            return;
        };
        let pgid = child.id().to_string();
        signal_fixture_group(&pgid, "TERM");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && fixture_group_exists(&pgid) {
            std::thread::sleep(Duration::from_millis(25));
        }
        if fixture_group_exists(&pgid) {
            signal_fixture_group(&pgid, "KILL");
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn signal_fixture_group(pgid: &str, signal: &str) {
    let group = format!("-{pgid}");
    let _ = Command::new("sudo")
        .args(["-n", "kill", signal, "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn fixture_group_exists(pgid: &str) -> bool {
    let group = format!("-{pgid}");
    Command::new("sudo")
        .args(["-n", "kill", "-0", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Fixture-owned account; its destructor covers every early return and panic
/// after successful creation, including setup before `Fixture` is assembled.
struct TemporaryAccount {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
    password: Zeroizing<String>,
}

impl TemporaryAccount {
    fn identity_matches(&self) -> bool {
        account_identity_matches(&self.name, self.uid, self.gid)
    }

    fn verify_identity(&self, operation: &str) -> bool {
        if self.identity_matches() {
            true
        } else {
            eprintln!(
                "disposable Docker SSH test account {} changed UID/GID before {operation}; refusing the operation",
                self.name
            );
            false
        }
    }
}

impl Drop for TemporaryAccount {
    fn drop(&mut self) {
        if !self.identity_matches() {
            eprintln!(
                "disposable Docker SSH test account {} no longer has its original UID/GID; leaving it untouched",
                self.name
            );
            return;
        }
        // The server's unprivileged session child can take a short moment to
        // observe that its master sshd has exited. Terminate any such remainder
        // before `userdel`, which correctly refuses to remove an account in use.
        let _ = Command::new("sudo")
            .args(["-n", "pkill", "-KILL", "-u", &self.uid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let running = Command::new("sudo")
                .args(["-n", "pgrep", "-u", &self.uid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !running {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let running = Command::new("sudo")
            .args(["-n", "pgrep", "-u", &self.uid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if running {
            eprintln!(
                "a process still uses disposable Docker SSH test account {}; leaving it intact",
                self.name
            );
            return;
        }
        if self.home != Path::new("/tmp").join(&self.name) {
            eprintln!(
                "disposable Docker SSH test account {} has an unexpected home path; leaving it intact",
                self.name
            );
            return;
        }
        if !account_identity_matches(&self.name, self.uid, self.gid) {
            eprintln!(
                "disposable Docker SSH test account {} changed UID/GID during cleanup; leaving it untouched",
                self.name
            );
            return;
        }
        let cleanup = Command::new("sudo")
            .args(["-n", "userdel", &self.name])
            .stdout(Stdio::null())
            .output();
        match cleanup {
            Ok(output) if output.status.success() => {
                let remove_home = Command::new("sudo")
                    .args(["-n", "/usr/bin/rm", "-rf", "--"])
                    .arg(&self.home)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if !remove_home.is_ok_and(|status| status.success())
                    || std::fs::symlink_metadata(&self.home).is_ok()
                {
                    eprintln!(
                        "could not remove private home for disposable Docker SSH test account {}",
                        self.name
                    );
                    return;
                }
                remove_private_group(&self.name, self.gid);
            }
            Ok(output) => eprintln!(
                "could not remove disposable Docker SSH test account {}: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!(
                "could not remove disposable Docker SSH test account {}: {error}",
                self.name
            ),
        }
    }
}

fn lookup_passwd_uid(name: &str) -> Option<u32> {
    lookup_numeric_id("passwd", name, 2)
}

fn lookup_passwd_gid(name: &str) -> Option<u32> {
    lookup_numeric_id("passwd", name, 3)
}

fn lookup_private_group_gid(name: &str) -> Option<u32> {
    lookup_numeric_id("group", name, 2)
}

fn account_identity_matches(name: &str, uid: u32, gid: u32) -> bool {
    lookup_passwd_uid(name) == Some(uid) && lookup_passwd_gid(name) == Some(gid)
}

fn lookup_numeric_id(database: &str, name: &str, field: usize) -> Option<u32> {
    let output = Command::new("getent")
        .args([database, name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let record = String::from_utf8_lossy(&output.stdout);
    let mut fields = record.trim_end().split(':');
    if fields.next()? != name {
        return None;
    }
    record.trim_end().split(':').nth(field)?.parse().ok()
}

impl Fixture {
    /// The `ssh://` address of this server.
    ///
    /// The login name and the port are both in the address rather than in a
    /// configuration file, because the managed client reads them from the
    /// endpoint: `ssh://user@host:port` is the whole of what it is given. A
    /// fixture that only worked through a configuration file would not be
    /// exercising the endpoint parser this crate ships.
    fn address(&self) -> String {
        format!("ssh://{}@127.0.0.1:{}", self.user, self.port)
    }

    /// Writes an OpenSSH configuration that makes the `ssh` binary behave the
    /// way a test needs it to, and returns its path.
    ///
    /// `StrictHostKeyChecking` and `UserKnownHostsFile` are the reason this file
    /// exists. The `ssh` binary inherits the invoking user's configuration, so a
    /// test that did not pin them would either prompt or refuse — and it would
    /// do so based on whatever happens to be in the developer's home directory,
    /// which is a different answer on every machine.
    fn write_client_config(&self) -> PathBuf {
        let path = self.directory.join("ssh_config");
        std::fs::write(
            &path,
            format!(
                "Host dockerssh-fixture\n\
                 \x20   HostName 127.0.0.1\n\
                 \x20   Port {port}\n\
                 \x20   User {user}\n\
                 \x20   IdentityFile {identity}\n\
                 \x20   IdentitiesOnly yes\n\
                 \x20   UserKnownHostsFile {known_hosts}\n\
                 \x20   StrictHostKeyChecking accept-new\n\
                 \x20   BatchMode yes\n\
                 \x20   LogLevel ERROR\n",
                port = self.port,
                user = self.user,
                identity = self.identity.display(),
                known_hosts = self.known_hosts.display(),
            ),
        )
        .expect("write the fixture's ssh_config");
        path
    }
}

/// Starts a loopback `sshd` that will run `docker system dial-stdio`.
///
/// Returns `None` — rather than failing — when a prerequisite is missing.
fn start() -> Option<Fixture> {
    start_with(Auth::KeyFile)
}

/// Starts a loopback `sshd` that authenticates one particular way.
///
/// Returns `None` — rather than failing — when a prerequisite is missing, and
/// says which. "not run here" and "the feature is broken" are different findings
/// and only one of them is a defect.
fn start_with(auth: Auth) -> Option<Fixture> {
    if !cfg!(target_os = "linux") {
        return missing_fixture_prerequisite(
            "the disposable Docker-group account fixture requires Linux",
        );
    }
    for program in ["ssh", "ssh-keygen"] {
        if which(program).is_none() {
            return missing_fixture_prerequisite(&format!("{program} is not on PATH"));
        }
    }
    if secure_sshd_path().is_none() {
        return missing_fixture_prerequisite("no root-owned sshd executable in a system directory");
    }
    if !Command::new("docker")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return missing_fixture_prerequisite("no reachable Docker CLI/daemon");
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_nanos();
    let directory_guard = tempfile::Builder::new()
        .prefix(&format!("ndocker-ssh-{}-{nonce}-", std::process::id()))
        .tempdir_in("/tmp")
        .expect("create the private fixture directory");
    let directory = directory_guard.path().to_path_buf();

    let host_key = directory.join("host_ed25519");
    let plain_identity = directory.join("id_ed25519");
    for key in [&host_key, &plain_identity] {
        let generated = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        assert!(
            generated.is_ok_and(|status| status.success()),
            "ssh-keygen could not create {}",
            key.display()
        );
    }
    let authorized_source = directory.join("authorized_keys");
    std::fs::copy(plain_identity.with_extension("pub"), &authorized_source)
        .expect("stage the public key");
    set_private(&plain_identity);
    let known_hosts = directory.join("known_hosts");
    let _ignored = std::fs::remove_file(&known_hosts);

    let identity = identity_for(auth, &directory, &plain_identity);
    set_private(&identity);

    if std::env::var("NEOTALES_DOCKER_SSH_FIXTURE").as_deref() == Ok("debian") {
        return Some(start_debian(directory_guard, auth, identity, known_hosts));
    }

    // Every SSH mode needs a login whose Docker socket permissions are explicit.
    // Using the invoking user made public-key tests depend on whether sshd's
    // unprivileged child inherited the runner's supplementary groups (and on
    // runner-specific socket ACLs), while the password test used a known-good
    // docker-group account. Keep the identity modes comparable by using the same
    // disposable account and only vary the SSH authentication mechanism.
    let Some(test_user) = password_account() else {
        return missing_fixture_prerequisite(
            "could not provision a disposable Docker-group account",
        );
    };
    let user = test_user.name.clone();
    let Some(authorized) = install_authorized_key(&test_user, &authorized_source) else {
        drop(test_user);
        return missing_fixture_prerequisite(
            "could not install the disposable login's authorized_keys",
        );
    };

    // The port is chosen by binding and releasing, which is the only portable
    // way to ask for a free one. The readiness wait below covers the race
    // between the release and the server binding it.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
    let port = listener.local_addr().expect("read the bound port").port();
    drop(listener);
    std::fs::write(directory.join("port"), port.to_string()).expect("record the reserved port");

    let config = write_sshd_config(&directory, &host_key, &authorized, &user, auth);
    let (child, log_path) = spawn_sshd(&config);

    let fixture = Fixture {
        server: FixtureServer::Host {
            child,
            account: test_user,
            log: log_path,
        },
        _directory_guard: directory_guard,
        directory,
        port,
        identity,
        known_hosts,
        user,
    };
    await_listening(&fixture, port);
    Some(fixture)
}

fn start_debian(
    directory_guard: tempfile::TempDir,
    auth: Auth,
    identity: PathBuf,
    known_hosts: PathBuf,
) -> Fixture {
    let directory = directory_guard.path().to_path_buf();
    let password = Zeroizing::new(random_fixture_password().expect("fixture password entropy"));
    let server =
        docker_ssh_fixture::DockerFixture::start(&directory, password, auth == Auth::Password);
    let port = server.port;
    let fixture = Fixture {
        server: FixtureServer::Docker(server),
        _directory_guard: directory_guard,
        directory,
        port,
        identity,
        known_hosts,
        user: "sshfixture".to_owned(),
    };
    await_listening(&fixture, port);
    fixture
}

fn missing_fixture_prerequisite(message: &str) -> Option<Fixture> {
    assert!(
        std::env::var_os("NEOTALES_REQUIRE_DOCKER_SSH_TESTS").is_none(),
        "required Docker-over-SSH test prerequisite is missing: {message}"
    );
    eprintln!("skipping Docker-over-SSH test: {message}");
    None
}

fn install_authorized_key(account: &TemporaryAccount, public_key: &Path) -> Option<PathBuf> {
    if !account.verify_identity("installing its .ssh directory") {
        return None;
    }
    let ssh_directory = account.home.join(".ssh");
    let install_ssh_dir = Command::new("sudo")
        .args([
            "-n",
            "install",
            "-d",
            "-m",
            "0700",
            "-o",
            &account.uid.to_string(),
            "-g",
            &account.gid.to_string(),
        ])
        .arg(&ssh_directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !install_ssh_dir.is_ok_and(|status| status.success()) {
        return None;
    }
    let authorized = ssh_directory.join("authorized_keys");
    if !account.verify_identity("installing authorized_keys") {
        return None;
    }
    let install_authorized = Command::new("sudo")
        .args([
            "-n",
            "install",
            "-m",
            "0600",
            "-o",
            &account.uid.to_string(),
            "-g",
            &account.gid.to_string(),
        ])
        .arg(public_key)
        .arg(&authorized)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    install_authorized
        .is_ok_and(|status| status.success())
        .then_some(authorized)
}

/// Writes the fixture server's configuration and returns its path.
///
/// `yes`/`no` rather than a bool: OpenSSH's configuration is a language with its
/// own spelling, and `PasswordAuthentication true` is refused by `sshd` with a
/// message about the line — which a fixture that swallows its stderr turns into
/// "the server never came up".
fn write_sshd_config(
    directory: &Path,
    host_key: &Path,
    authorized: &Path,
    user: &str,
    auth: Auth,
) -> PathBuf {
    let (yes, no) = ("yes", "no");
    let (password_authentication, pubkey_authentication) = match auth {
        Auth::Password => (yes, no),
        Auth::KeyFile | Auth::EncryptedKeyFile => (no, yes),
    };
    let config = directory.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             UsePAM no\n\
             UseDNS no\n\
             PasswordAuthentication {password_authentication}\n\
             KbdInteractiveAuthentication {no}\n\
             PubkeyAuthentication {pubkey_authentication}\n\
             AuthorizedKeysFile {authorized}\n\
             AllowUsers {user}\n\
             AllowTcpForwarding no\n\
             AllowAgentForwarding no\n\
             X11Forwarding no\n\
             PermitTunnel no\n\
             PermitUserRC no\n\
             PermitRootLogin no\n\
             StrictModes yes\n\
             LoginGraceTime 60\n\
             LogLevel VERBOSE\n",
            port = read_port(directory),
            host_key = host_key.display(),
            authorized = authorized.display(),
            user = user,
        ),
    )
    .expect("write sshd_config");
    config
}

/// The port the fixture reserved, read back from a file the configuration names.
///
/// Written into the configuration's own directory rather than returned beside
/// it, so the port and the directory cannot be paired wrongly by a caller.
fn read_port(directory: &Path) -> u16 {
    std::fs::read_to_string(directory.join("port"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .expect("the reserved port was recorded")
}

/// Waits until the fixture server is accepting connections.
///
/// A bound port and a listening server are not the same instant, and the gap is
/// the reason the port is chosen by binding and releasing. The wait is bounded so
/// a server that never came up fails with its own log attached rather than
/// hanging.
fn await_listening(fixture: &Fixture, port: u16) {
    let deadline = Instant::now() + LISTEN_TIMEOUT;
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the fixture sshd never began listening on 127.0.0.1:{port}:\n{}",
            fixture.sshd_log()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Starts `sshd` on the configuration and returns where it will write its log.
///
/// The fixture server runs through `sudo` so the temporary login is handled by
/// the normal account and supplementary-group database. This makes the Docker
/// socket authorization identical for key and password tests, instead of
/// depending on the runner process's inherited groups.
///
/// The log is kept rather than discarded. Every failure here is a server-side
/// refusal, and a swallowed stderr turns "the password was wrong" and "this
/// server will not offer the password method" into the same one-line assertion,
/// which is a bad way to find out which.
fn spawn_sshd(config: &Path) -> (Child, PathBuf) {
    use std::os::unix::process::CommandExt as _;

    let log_path = config
        .parent()
        .expect("a config has a directory")
        .join("sshd.log");
    let log = std::fs::File::create(&log_path).expect("create the sshd log");
    let errors = log.try_clone().expect("clone the sshd log handle");
    let sshd = secure_sshd_path().expect("a root-owned system sshd path");
    let mut command = Command::new("sudo");
    command.args(["-n", sshd.to_str().expect("an sshd path is UTF-8")]);
    command.process_group(0);
    let child = command
        .args(["-D", "-e", "-f"])
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("start sshd");
    drop(log);
    (child, log_path)
}

/// Builds the identity file a client reads, for the mode the fixture is in.
///
/// The identity is generated the same way in every mode, because the point of
/// the encrypted mode is the *passphrase*, not a different key type. An
/// encrypted Ed25519 key is a real `ssh-keygen` product with the same public half,
/// so the authorized-keys file is the same file in both.
fn identity_for(auth: Auth, directory: &Path, plain: &Path) -> PathBuf {
    match auth {
        Auth::KeyFile | Auth::Password => plain.to_path_buf(),
        Auth::EncryptedKeyFile => {
            // Copied and re-keyed in place, so the file the client reads is a
            // genuine `ssh-keygen -p` product: the same `openssh-key-v1`
            // container, bcrypt-wrapped and AES-encrypted. A fixture that
            // hand-rolled the encryption would be testing its own writer, and
            // `ssh-keygen -p` refuses to work unless it is pointed at the key it
            // is re-keying, which is why the copy comes first.
            let encrypted = directory.join("id_ed25519_encrypted");
            std::fs::copy(plain, &encrypted).expect("copy the identity to re-key");
            let rekeyed = Command::new("ssh-keygen")
                .args(["-q", "-p", "-P", "", "-N", PASSPHRASE, "-f"])
                .arg(&encrypted)
                .stdin(std::process::Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            assert!(
                rekeyed.is_ok_and(|status| status.success()),
                "ssh-keygen could not re-key {} with a passphrase",
                plain.display()
            );
            let armored = std::fs::read(&encrypted).expect("read the encrypted identity");
            assert!(
                String::from_utf8_lossy(&armored).contains("BEGIN OPENSSH PRIVATE KEY"),
                "the encrypted identity is not in OpenSSH's armored format, so the client \
                 would not be reading what a user's file looks like"
            );
            encrypted
        }
    }
}

/// Creates a throwaway login user with access to the Docker socket.
///
/// Returns `None` — having said why — when this needs a privilege the invoking
/// user does not have. After its UID and GID are verified, [`TemporaryAccount`]
/// removes the account on every early return and when [`Fixture`] is dropped.
fn password_account() -> Option<TemporaryAccount> {
    use std::io::Write as _;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_nanos();
    // Include both process ID and clock entropy so separate runner processes
    // cannot collide on the same account name.
    let name = format!("ndockssh{}{}", std::process::id(), nonce % 1_000_000);
    let password = Zeroizing::new(random_fixture_password()?);
    let home = PathBuf::from(format!("/tmp/{name}"));
    if !create_password_account(&name, &home, nonce) {
        eprintln!(
            "skipping the password fixture: useradd could not create the unique \
             disposable account; no account was removed because this invocation did not create it"
        );
        return None;
    }
    let Some(uid) = lookup_passwd_uid(&name) else {
        eprintln!("useradd succeeded but its UID could not be verified; leaving {name} untouched");
        return None;
    };
    let Some(gid) = lookup_private_group_gid(&name) else {
        eprintln!(
            "useradd succeeded but its private GID could not be verified; leaving {name} untouched"
        );
        return None;
    };
    // Take ownership immediately: every subsequent early return and panic must
    // remove the account, even before `Fixture` itself has been assembled.
    let account = TemporaryAccount {
        name,
        uid,
        gid,
        home,
        password,
    };
    if !account.verify_identity("adding it to the docker group") {
        return None;
    }
    // The account has to reach the Docker socket, because `docker system
    // dial-stdio` runs as the login user. Treat a failed group update as a
    // missing prerequisite rather than letting the later API request obscure it.
    let added_to_docker = Command::new("sudo")
        .args(["-n", "usermod", "-aG", "docker", &account.name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !added_to_docker.is_ok_and(|status| status.success()) {
        eprintln!("skipping the Docker SSH fixture: could not add its login to the docker group");
        return None;
    }
    if !account.verify_identity("setting its password") {
        return None;
    }
    let set = Command::new("sudo")
        .args(["-n", "chpasswd"])
        .stdin(std::process::Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let set = match set {
        Ok(mut child) => {
            let record =
                Zeroizing::new(format!("{}:{}\n", account.name, account.password.as_str()));
            let written = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "no stdin"))
                .and_then(|mut input| input.write_all(record.as_bytes()));
            let status = child.wait();
            match (written, status) {
                (Ok(()), Ok(status)) => Ok(status),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    if !set.is_ok_and(|status| status.success()) {
        eprintln!("skipping the password fixture: this needs sudo to set a password");
        return None;
    }
    Some(account)
}

fn create_password_account(name: &str, home: &Path, nonce: u128) -> bool {
    let mut attempt = 0;
    loop {
        match Command::new("sudo")
            .args([
                "-n",
                "useradd",
                "-l",
                "-m",
                "-U",
                "-K",
                "MAIL_DIR=/tmp/neotales-private-mail-spool",
                "-d",
            ])
            .arg(home)
            .args(["-s", "/bin/sh", name])
            .output()
        {
            Ok(output) if output.status.success() => return true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("cannot lock /etc/passwd")
                    && attempt + 1 < MAX_ACCOUNT_LOCK_ATTEMPTS
                {
                    attempt += 1;
                    // Separate runner processes share the host account database;
                    // jitter retries to avoid repeatedly colliding with a holder.
                    let jitter = u64::try_from(nonce.wrapping_add((attempt as u128) * 137) % 501)
                        .expect("the jitter is always less than 501");
                    std::thread::sleep(Duration::from_millis(250 + jitter));
                    continue;
                }
                if stderr.contains("cannot lock /etc/passwd") {
                    report_account_lock_diagnostics();
                }
                eprintln!(
                    "useradd failed for the disposable Docker SSH account: {}",
                    stderr.trim()
                );
                return false;
            }
            Err(error) => {
                eprintln!("could not run useradd for the disposable Docker SSH account: {error}");
                return false;
            }
        }
    }
}

/// Collects narrow, read-only account-lock diagnostics after retries are exhausted.
fn report_account_lock_diagnostics() {
    eprintln!("Account database lock diagnostics (read-only):");
    // Keep this to the mount covering /etc and metadata for the account files:
    // never ask a diagnostic command to print the databases' contents.
    report_optional_diagnostic(
        "findmnt view for /etc",
        "findmnt",
        &["--target", "/etc", "--output", "TARGET,SOURCE,FSTYPE"],
        8,
    );
    report_optional_diagnostic(
        "account-file metadata (mode, owner, device, inode, SELinux context)",
        "stat",
        &[
            "--printf",
            "%n mode=%a uid=%u gid=%g dev=%d inode=%i context=%C\\n",
            "/etc",
            "/etc/passwd",
            "/etc/passwd-",
            "/etc/group",
            "/etc/group-",
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/gshadow",
            "/etc/gshadow-",
            "/etc/.pwd.lock",
            "/etc/passwd.lock",
            "/etc/group.lock",
            "/etc/shadow.lock",
            "/etc/gshadow.lock",
        ],
        32,
    );
    report_optional_diagnostic("SELinux enforcement", "getenforce", &[], 4);

    match timed_diagnostic_command("ps")
        .args(["-eo", "pid=,ppid=,uid=,comm="])
        .output()
    {
        Ok(output) => {
            for (emitted, line) in String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| {
                    line.split_whitespace().last().is_some_and(|name| {
                        matches!(
                            name,
                            "useradd"
                                | "usermod"
                                | "userdel"
                                | "groupadd"
                                | "groupmod"
                                | "groupdel"
                                | "passwd"
                                | "chpasswd"
                        )
                    })
                })
                .enumerate()
            {
                if emitted == 64 {
                    eprintln!("... process output truncated ...");
                    break;
                }
                let line: String = line.chars().take(512).collect();
                eprintln!("{line}");
            }
        }
        Err(error) => eprintln!("could not inspect account-management processes: {error}"),
    }
    match timed_diagnostic_command("sudo")
        .args([
            "-n",
            "fuser",
            "-v",
            "/etc/passwd",
            "/etc/passwd-",
            "/etc/group",
            "/etc/group-",
            "/etc/.pwd.lock",
            "/etc/passwd.lock",
            "/etc/group.lock",
        ])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            for (emitted, line) in stdout.lines().chain(stderr.lines()).enumerate() {
                if emitted == 32 {
                    eprintln!("... lock-holder output truncated ...");
                    break;
                }
                let line: String = line.chars().take(512).collect();
                eprintln!("{line}");
            }
        }
        Err(error) => eprintln!("could not inspect account-database lock holders: {error}"),
    }
}

/// Runs an optional, fixed-argument diagnostic and emits only a bounded result.
///
/// The commands passed here are read-only and their arguments name metadata or
/// mount information, never account-file contents or credential-bearing input.
fn report_optional_diagnostic(label: &str, program: &str, args: &[&str], max_lines: usize) {
    let Some(executable) = which(program) else {
        eprintln!("{label}: {program} is unavailable");
        return;
    };
    match timed_diagnostic_command(&executable).args(args).output() {
        Ok(output) => {
            eprintln!("{label} ({}):", output.status);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            for (emitted, line) in stdout.lines().chain(stderr.lines()).enumerate() {
                if emitted == max_lines {
                    eprintln!("... output truncated ...");
                    break;
                }
                // Cap individual lines as well as line count, so an unexpected
                // mount option or diagnostic cannot flood the test log.
                let line: String = line.chars().take(512).collect();
                eprintln!("{line}");
            }
        }
        Err(error) => eprintln!("{label}: could not run {program}: {error}"),
    }
}

/// Bounds a fixed, read-only diagnostic command even if the inspected host is
/// unusually slow or the utility hangs.
fn timed_diagnostic_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new("timeout");
    command.args(["--signal=TERM", "--kill-after=1s", "5s"]);
    command.arg(program);
    command
}

/// Removes the private primary group created with `useradd -U`, if it remains.
fn remove_private_group(name: &str, expected_gid: u32) {
    match lookup_private_group_gid(name) {
        Some(gid) if gid == expected_gid => {}
        Some(_) => {
            eprintln!(
                "private group for SSH test account {name} changed GID; leaving it untouched"
            );
            return;
        }
        None => return,
    }
    if !Command::new("sudo")
        .args(["-n", "groupdel", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!("could not remove private group for SSH test account {name}");
    }
}

/// Generates a one-run password from the operating system's CSPRNG.
fn random_fixture_password() -> Option<String> {
    use std::fmt::Write as _;
    use std::io::Read as _;
    use zeroize::Zeroize as _;

    let mut bytes = [0_u8; 32];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .is_err()
    {
        eprintln!("skipping the Docker SSH fixture: the OS random source is unavailable");
        return None;
    }
    let mut password = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut password, "{byte:02x}").expect("writing to a String cannot fail");
    }
    bytes.zeroize();
    Some(password)
}

/// Tightens permissions on a file `sshd` and `ssh` refuse to read otherwise.
fn set_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ignored = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Returns the absolute path of an executable, or `None`.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(program);
        candidate.is_file().then_some(candidate)
    })
}

/// Finds `sshd` only in standard system directories and verifies root ownership.
/// The path is passed to `sudo`, so trusting an arbitrary PATH entry would turn
/// a test-runner environment variable into root code execution.
fn secure_sshd_path() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", "/bin/sshd"]
        .into_iter()
        .filter_map(|candidate| std::fs::canonicalize(candidate).ok())
        .find(|path| {
            std::fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.mode() & 0o111 != 0
            })
        })
}

/// The time budget one request runs under.
///
/// A `Duration` rather than an `Instant` because that is what
/// `tokio::time::timeout` takes, and naming it in one place means a test that
/// changes the bound changes it once.
fn budget() -> Duration {
    REQUEST_TIMEOUT
}

/// The native `ssh` binary mechanism, written the way a caller outside this
/// crate writes it.
///
/// `StreamFactory` is public, so this is reachable from the public surface: a
/// closure that spawns a process per request and hands the transport its two
/// streams. There is no crate-owned constructor that does this, and the fact
/// that a test can do it without one is part of what the `Stream` variant
/// bought.
fn native_ssh_factory(config: PathBuf) -> impl Fn() -> raw::StreamFuture + Send + Sync + 'static {
    move || {
        let config = config.clone();
        Box::pin(async move {
            let mut child = tokio::process::Command::new("ssh")
                .arg("-T")
                .arg("-F")
                .arg(&config)
                .arg("--")
                .arg("dockerssh-fixture")
                .arg("docker")
                .arg("system")
                .arg("dial-stdio")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|error| Error::transport(format!("start ssh: {error}")))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::transport("ssh has no standard input".to_owned()))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| Error::transport("ssh has no standard output".to_owned()))?;
            Ok(Box::new(SshProcess {
                stdin,
                stdout,
                _child: child,
            }) as Box<dyn Duplex>)
        })
    }
}

/// The two halves of a running `ssh` process.
struct SshProcess {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    /// Held for the duplex's lifetime and never read.
    ///
    /// It is the ownership of the process, and dropping it is the cancellation:
    /// the spawn set `kill_on_drop`, so dropping the handle terminates the local
    /// `ssh`. An earlier version of this test dropped the handle here instead
    /// and every live test failed with "connection closed before message
    /// completed", because the process was killed the moment the duplex was
    /// built.
    _child: tokio::process::Child,
}

impl AsyncRead for SshProcess {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stdout).poll_read(context, buffer)
    }
}

impl AsyncWrite for SshProcess {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stdin).poll_write(context, bytes)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stdin).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stdin).poll_shutdown(context)
    }
}

/// The daemon's own answer to `GET /v1.53/_ping`, read over a real SSH session.
///
/// This is the load-bearing test of the whole slice, through the **native `ssh`
/// binary**. It asserts three claims at once: the SSH session carried a complete
/// HTTP request, the far end was a real `docker system dial-stdio` rather than
/// a simulator, and the request was **versioned** — `/v1.53/_ping`, which is the
/// escape criterion the owned transport exists to satisfy and which the
/// generated client does not send.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh binary, and a reachable Docker daemon"]
async fn the_native_ssh_binary_carries_a_versioned_engine_request() {
    let Some(fixture) = start() else { return };
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: StreamFactory::new(native_ssh_factory(fixture.write_client_config())),
        },
        VERSION,
    );

    let capabilities = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the ping did not finish in time")
        .expect("the daemon answered _ping over SSH");

    // `/_ping` reports its answer in headers, and it is the one route the Engine
    // answers on any version, so a 200 with an `Api-Version` header is the
    // daemon saying it is a Docker Engine and not something else on the same
    // socket.
    assert_eq!(
        capabilities.os_type.as_deref(),
        Some("linux"),
        "the far end was not a Docker Engine on Linux"
    );
    assert!(
        capabilities.api_version.is_some(),
        "the daemon reported no API version, so it did not answer as an Engine"
    );
}

/// The same claim through `neotales-ssh`, this repository's own SSH crate.
///
/// The mechanism is chosen by a `known_hosts` file rather than by a private
/// option: `connect_ssh_with_known_hosts` is the existing public entry point for
/// "make host-key policy explicit", so this exercises a path a caller can reach
/// today rather than one that only exists inside the crate.
#[tokio::test]
#[ignore = "needs a real sshd and a reachable Docker daemon"]
async fn neotales_ssh_carries_a_versioned_engine_request() {
    let Some(fixture) = start() else { return };
    let client = neotales_docker::DockerClient::connect_ssh_with_known_hosts(
        &fixture.address(),
        Duration::from_secs(30),
        Some(fixture.identity.as_path()),
        fixture.known_hosts.as_path(),
    )
    .expect("build an SSH client");
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");

    let capabilities = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the ping did not finish in time")
        .expect("the daemon answered _ping over a neotales-ssh session");

    assert_eq!(
        capabilities.os_type.as_deref(),
        Some("linux"),
        "the far end was not a Docker Engine on Linux"
    );
    assert!(
        capabilities.api_version.is_some(),
        "the daemon reported no API version, so it did not answer as an Engine"
    );
}

/// `neotales-ssh` records the host key it saw, which is the host-key check
/// running and not a connection that happened to open.
///
/// A handshake that skipped verification would pass the test above. This asserts
/// the file the caller named now contains the host, which is what
/// `StrictHostKeyChecking accept-new` does and what the managed client does by
/// hand — and a second connection then *matches* that entry rather than adding a
/// second one.
#[tokio::test]
#[ignore = "needs a real sshd and a reachable Docker daemon"]
async fn neotales_ssh_records_the_host_key_it_accepted() {
    let Some(fixture) = start() else { return };
    let address = fixture.address();
    let client = neotales_docker::DockerClient::connect_ssh_with_known_hosts(
        &address,
        Duration::from_secs(30),
        Some(fixture.identity.as_path()),
        fixture.known_hosts.as_path(),
    )
    .expect("build an SSH client");
    let engine = client.raw_engine().expect("an owned transport");

    let _first = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the first ping did not finish in time")
        .expect("the first ping answered");

    let recorded = std::fs::read_to_string(&fixture.known_hosts).unwrap_or_default();
    assert!(
        recorded.contains("127.0.0.1") || recorded.contains("[127.0.0.1]"),
        "the managed client did not record the host key it accepted:\n{recorded}"
    );
    let entries = recorded
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    assert_eq!(
        entries, 1,
        "more than one host key was recorded:\n{recorded}"
    );

    // A second connection must match the recorded key. A client that appended
    // unconditionally would pass the first half of this test and fail here.
    let again = neotales_docker::DockerClient::connect_ssh_with_known_hosts(
        &address,
        Duration::from_secs(30),
        Some(fixture.identity.as_path()),
        fixture.known_hosts.as_path(),
    )
    .expect("build a second SSH client");
    let engine = again.raw_engine().expect("an owned transport");
    let _second = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the second ping did not finish in time")
        .expect("the second ping answered against the recorded host key");
}

/// `info` is the strongest available check that the whole path works.
///
/// It is a much larger document than `/_ping` — several kilobytes of JSON, which
/// crosses the SSH channel's initial window in a way a ping does not — and it is
/// decoded by the crate's own `engine_result` and projection, not compared
/// against a value written in this file. The fields asserted on are the two the
/// daemon cannot answer without: its own version string, and an operating system
/// it probed at runtime.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh binary, and a reachable Docker daemon"]
async fn the_native_ssh_binary_decodes_a_multi_kilobyte_engine_document() {
    let Some(fixture) = start() else { return };
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: StreamFactory::new(native_ssh_factory(fixture.write_client_config())),
        },
        VERSION,
    );

    let document = tokio::time::timeout(budget(), info(&engine))
        .await
        .expect("the info request did not finish in time")
        .expect("the daemon answered info over SSH");

    let version = document
        .get("ServerVersion")
        .and_then(serde_json::Value::as_str)
        .expect("the daemon reported a ServerVersion");
    assert!(
        !version.is_empty(),
        "the daemon reported an empty ServerVersion"
    );
    let operating_system = document
        .get("OperatingSystem")
        .and_then(serde_json::Value::as_str)
        .expect("the daemon reported an OperatingSystem");
    assert!(!operating_system.is_empty());
}

/// Two requests over one managed SSH target, each on its own session.
///
/// `dial-stdio` is one process per connection, so a managed client that reused
/// one session would serve the first request and then answer the second from a
/// closed stream. Two requests is the smallest number that catches it.
#[tokio::test]
#[ignore = "needs a real sshd and a reachable Docker daemon"]
async fn neotales_ssh_serves_a_second_request_on_a_new_session() {
    let Some(fixture) = start() else { return };
    let client = neotales_docker::DockerClient::connect_ssh_with_known_hosts(
        &fixture.address(),
        Duration::from_secs(30),
        Some(fixture.identity.as_path()),
        fixture.known_hosts.as_path(),
    )
    .expect("build an SSH client");
    let engine = client.raw_engine().expect("an owned transport");

    let first = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the first ping did not finish in time")
        .expect("the first ping answered");
    let second = tokio::time::timeout(budget(), info(&engine))
        .await
        .expect("the second request did not finish in time")
        .expect("the second request answered");
    assert_eq!(first.os_type.as_deref(), Some("linux"));
    assert!(second.get("ServerVersion").is_some());
}

/// An Engine error status crosses the same path and is read by the one status
/// mapping.
///
/// The message is the daemon's own word and is carried through unchanged. That
/// is the property escape criterion 6 is about — a transport error that renders
/// as a bare string reaches nobody — so this asserts the *text*, not merely that
/// an error came back.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh binary, and a reachable Docker daemon"]
async fn an_engine_error_over_ssh_carries_the_daemons_own_message() {
    let Some(fixture) = start() else { return };
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: StreamFactory::new(native_ssh_factory(fixture.write_client_config())),
        },
        VERSION,
    );

    let response = tokio::time::timeout(
        budget(),
        engine.send(RawRequest::new(
            hyper::Method::GET,
            "/containers/ndocker-ssh-fixture-missing/json",
        )),
    )
    .await
    .expect("the inspect did not finish in time")
    .expect("the daemon answered the inspect");
    let error = engine_result(response)
        .await
        .expect_err("inspecting a container that does not exist must fail");

    let api = error
        .api_error()
        .expect("an Engine rejection is reported as an API error");
    assert_eq!(api.status_code, 404);
    assert!(
        api.message.contains("ndocker-ssh-fixture-missing"),
        "the daemon's own message was not carried through: {}",
        api.message
    );
}

/// A real Engine stream, over a real SSH session, read by the one frame reader.
///
/// The in-process fixture in `stream_target.rs` proves the reader is reached.
/// This proves the *wire* is: `GET /events` over a bounded window is newline
/// delimited JSON, it is produced by the daemon rather than written here, and
/// crossing an SSH channel's window boundary in the middle of it is exactly the
/// thing a head-only fixture cannot see.
///
/// The window is a real interval ending now, so the stream terminates. With no
/// `until` the daemon writes one object per line for as long as it runs, which is
/// the right shape for a follower and the wrong one for a test that has to finish.
///
/// # Why this test raises the record bound
///
/// `GET /events` returns whatever the daemon recorded, and a daemon records
/// `exec_create` by echoing the caller's whole `Cmd` array back. On the host
/// where this was last run, that produced records of 60,500,326 bytes — a
/// caller passed a 60 MB argument, which the kernel would refuse to *run* (its
/// `ARG_MAX` is 2 MB) but the daemon faithfully *recorded*. The crate's 8 MiB
/// default therefore refuses a record this stream really received, and the
/// choice is between raising the bound and losing the event.
///
/// The bound is raised here, on this stream, rather than by changing the crate
/// default, and the distinction is the point. A 60 MB event is a fact about one
/// host's one caller; a default raised to admit it would charge that much to
/// every concurrent stream on every host that has never seen such a record, and
/// the per-stream override is the mechanism built for exactly this — a caller who
/// has measured a larger legitimate record on their own daemon. The test is such
/// a caller.
///
/// It is still a bound. [`EVENT_LIMIT`] is a constant here, not "unlimited", and
/// a peer streaming junk with no newline is still refused at it — which is the
/// property worth keeping while raising the number that sets it.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh binary, and a reachable Docker daemon"]
async fn an_event_stream_over_a_real_ssh_session_is_decoded_frame_by_frame() {
    let Some(fixture) = start() else { return };
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: StreamFactory::new(native_ssh_factory(fixture.write_client_config())),
        },
        VERSION,
    );

    // Unix seconds, which is the spelling the Engine's own `since` and `until`
    // accept. Measured: an RFC 3339 timestamp with a `Z` is refused with
    // `invalid value for 'since': ... invalid syntax`, so the seconds form is
    // not a guess.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the Unix epoch")
        .as_secs();
    let request = RawRequest::new(hyper::Method::GET, "/events")
        .with_query(format!("since={}&until={now}", now.saturating_sub(86_400)));
    let response = tokio::time::timeout(budget(), engine.send(request))
        .await
        .expect("the event stream did not finish in time")
        .expect("the event stream was opened");
    let frames = tokio::time::timeout(budget(), collect_json_frames_bounded(response, EVENT_LIMIT))
        .await
        .expect("the frame reader did not finish in time")
        .expect("the event records were decoded");

    // A window of one day on a daemon that has been running will normally carry
    // records, but a daemon started inside that window with nothing to report
    // legitimately carries none. The assertion is therefore on the *shape* of
    // every record that did arrive, and the emptiness case says so rather than
    // failing: "no records" is not a transport defect and "records that are not
    // event documents" is.
    for frame in &frames {
        assert!(
            frame.is_object(),
            "an event record was not a JSON object: {frame:?}"
        );
        assert!(
            frame.get("Type").is_some_and(serde_json::Value::is_string),
            "an event record carried no Type: {frame:?}"
        );
        assert!(
            frame
                .get("Action")
                .is_some_and(serde_json::Value::is_string),
            "an event record carried no Action: {frame:?}"
        );
    }
    if frames.is_empty() {
        eprintln!("the daemon reported no events in the last day; the shape was not exercised");
    } else {
        println!(
            "decoded {} event records over a real SSH session",
            frames.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Auth breadth and connection reuse.
//
// Everything above this line is the transport, and this file's own claim is that
// it does not care which credential or which connection policy got it there.
// These tests are that claim, made: each opens a real `sshd` that authenticates
// one particular way, drives a complete Engine request through it, and asserts
// on the daemon's own answer.
// ---------------------------------------------------------------------------

/// An SSH password reaches the daemon and carries real Engine traffic.
///
/// The password is a **value the caller supplies**, not something the client
/// asks for. The test therefore builds a client with
/// [`ManagedSshClient::password`] and never expects a prompt; if the client tried
/// to prompt it would have nowhere to prompt into and the request would hang, so
/// the bounded timeout is also the assertion that it did not.
#[tokio::test]
#[ignore = "needs a real sshd, a throwaway login user, and a reachable Docker daemon"]
async fn a_password_credential_reaches_the_daemon_over_managed_ssh() {
    let Some(fixture) = start_with(Auth::Password) else {
        return;
    };
    let client = neotales_docker::DockerClient::connect_ssh_managed(
        &fixture.address(),
        fixture.known_hosts.as_path(),
    )
    .timeout(Duration::from_secs(30))
    .password(neotales_docker::SshSecret::new(fixture.password()))
    .connect()
    .expect("build a password-authenticated SSH client");
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");

    let document = tokio::time::timeout(budget(), info(&engine))
        .await
        .expect("the info request did not finish in time")
        .unwrap_or_else(|error| {
            panic!(
                "the daemon answered nothing over a password session: \
             {error}\nsshd said:\n{}",
                fixture.sshd_log()
            )
        });

    // `info` rather than `_ping`: several kilobytes of JSON produced by the
    // daemon, which crosses the SSH channel's window in a way a ping does not.
    assert!(
        document
            .get("ServerVersion")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|version| !version.is_empty()),
        "the daemon reported no ServerVersion over a password-authenticated session"
    );
}

/// The same daemon, refused for want of a credential.
///
/// A password server and a public-key client are different *modes*, and the one
/// that matters is that a credential this server does not accept is refused
/// with the server's own refusal rather than being retried into something else.
/// It also pins the shape of the failure a caller sees when a credential is
/// wrong, which is the message they will read.
#[tokio::test]
#[ignore = "needs a real sshd, a throwaway login user, and a reachable Docker daemon"]
async fn a_password_the_server_refuses_is_reported_not_retried() {
    let Some(fixture) = start_with(Auth::Password) else {
        return;
    };
    let client = neotales_docker::DockerClient::connect_ssh_managed(
        &fixture.address(),
        fixture.known_hosts.as_path(),
    )
    .timeout(Duration::from_secs(30))
    .password(neotales_docker::SshSecret::new("not-the-password"))
    .connect()
    .expect("build a password-authenticated SSH client");
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");

    let refused = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the refused request did not finish in time")
        .expect_err("a password the server does not accept must not authenticate");
    eprintln!("sshd said:\n{}", fixture.sshd_log());
    assert_eq!(
        refused.kind(),
        neotales_docker::ErrorKind::Transport,
        "an authentication refusal should be a transport failure: {refused}"
    );
    let rendered = refused.to_string();
    assert!(
        rendered.contains(&fixture.user),
        "the refusal must name the login it was for: {rendered}"
    );
}

/// An encrypted identity file, with the caller's passphrase, reaches the daemon.
///
/// The fixture re-keys a real `ssh-keygen` identity with a passphrase, so the
/// file the client reads is a genuine bcrypt-wrapped, AES-encrypted
/// `openssh-key-v1` container. A fixture that synthesised the encryption would be
/// testing its own writer.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh-keygen, and a reachable Docker daemon"]
async fn an_encrypted_identity_and_its_passphrase_reach_the_daemon() {
    let Some(fixture) = start_with(Auth::EncryptedKeyFile) else {
        return;
    };
    let client = neotales_docker::DockerClient::connect_ssh_managed(
        &fixture.address(),
        fixture.known_hosts.as_path(),
    )
    .timeout(Duration::from_secs(30))
    .identity_file_with_passphrase(
        fixture.identity.as_path(),
        neotales_docker::SshSecret::new(PASSPHRASE),
    )
    .connect()
    .expect("build an SSH client with an encrypted identity");
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");

    let document = tokio::time::timeout(budget(), info(&engine))
        .await
        .expect("the info request did not finish in time")
        .expect("the daemon answered info over an encrypted-identity session");

    assert!(
        document.get("ServerVersion").is_some(),
        "the daemon answered nothing recognisable over an encrypted-identity session"
    );
}

/// The wrong passphrase is refused, and refused as a passphrase.
///
/// The distinction the error text has to make is "your passphrase is wrong" and
/// not "this key is encrypted, give me a passphrase" — the caller *did* give one.
/// Without the distinction a caller cannot tell a typo from a wrong key file.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh-keygen, and a reachable Docker daemon"]
async fn a_wrong_passphrase_names_the_passphrase() {
    let Some(fixture) = start_with(Auth::EncryptedKeyFile) else {
        return;
    };
    let client = neotales_docker::DockerClient::connect_ssh_managed(
        &fixture.address(),
        fixture.known_hosts.as_path(),
    )
    .timeout(Duration::from_secs(30))
    .identity_file_with_passphrase(
        fixture.identity.as_path(),
        neotales_docker::SshSecret::new("not-the-passphrase"),
    )
    .connect()
    .expect("build an SSH client with the wrong passphrase");
    // `connect` succeeds because the key is only read when a request is made, so
    // the passphrase is not exercised until here.
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");
    let refused = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the refused request did not finish in time")
        .expect_err("a wrong passphrase must not authenticate");
    let rendered = refused.to_string();
    assert!(
        rendered.to_lowercase().contains("passphrase"),
        "the refusal must name the passphrase as the thing that was wrong: {rendered}"
    );
}

/// A key file with no passphrase is refused as *needing* one.
///
/// The container parser's own words for an encrypted key with an empty passphrase
/// are about an unsupported algorithm, which is true and useless. This is the
/// one place a caller's mistake is reported in terms of the fix.
#[tokio::test]
#[ignore = "needs a real sshd, an ssh-keygen, and a reachable Docker daemon"]
async fn an_encrypted_key_given_as_a_plain_one_is_refused_with_the_fix() {
    let Some(fixture) = start_with(Auth::EncryptedKeyFile) else {
        return;
    };
    let client = neotales_docker::DockerClient::connect_ssh_managed(
        &fixture.address(),
        fixture.known_hosts.as_path(),
    )
    .timeout(Duration::from_secs(30))
    .identity_file(fixture.identity.as_path())
    .connect()
    .expect("build an SSH client with an encrypted identity named as a plain one");
    let engine = client
        .raw_engine()
        .expect("the owned transport reaches an ssh:// endpoint");

    let refused = tokio::time::timeout(budget(), ping(&engine))
        .await
        .expect("the refused request did not finish in time")
        .expect_err("an encrypted key with no passphrase must not authenticate");
    let rendered = refused.to_string();
    assert!(
        rendered.contains("EncryptedKeyFile"),
        "the refusal must name the call that would work: {rendered}"
    );
}
