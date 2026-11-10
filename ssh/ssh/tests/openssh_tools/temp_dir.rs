//! Collision-safe temporary directories for the live OpenSSH tests.

use std::fs;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CREATE_ATTEMPTS: u64 = 64;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// A uniquely created temporary directory removed when its owner is dropped.
#[derive(Debug)]
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Creates a unique directory under the platform temporary directory.
    pub(crate) fn new(prefix: &str) -> io::Result<Self> {
        Self::new_in(&std::env::temp_dir(), prefix)
    }

    /// Creates a unique directory under `root`.
    pub(crate) fn new_in(root: &Path, prefix: &str) -> io::Result<Self> {
        create_unique_with(root, |attempt| {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            root.join(format!(
                "{prefix}-{}-{time}-{sequence}-{attempt}",
                std::process::id()
            ))
        })
    }
}

impl Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "could not remove temporary directory {}: {error}",
                self.0.display()
            );
        }
    }
}

/// Owns a spawned child until it is either transferred to a longer-lived guard
/// or explicitly reaped. `Child` itself does not terminate its process on drop.
pub(crate) struct ChildGuard {
    child: Option<Child>,
    terminate_tree: bool,
    running: bool,
}

impl ChildGuard {
    pub(crate) fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            terminate_tree: false,
            running: true,
        }
    }

    /// Spawns a process whose descendants must not outlive the test lane.
    pub(crate) fn spawn_tree(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        Ok(Self {
            child: Some(command.spawn()?),
            terminate_tree: true,
            running: true,
        })
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self
            .child
            .as_mut()
            .expect("child guard is active")
            .try_wait()?;
        if status.is_some() {
            self.running = false;
        }
        Ok(status)
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.as_ref().expect("child guard is active").id()
    }

    pub(crate) fn into_inner(mut self) -> Child {
        self.child.take().expect("child guard is active")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if !self.running {
                return;
            }
            if self.terminate_tree {
                #[cfg(unix)]
                if let Ok(pid) = i32::try_from(child.id()) {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                #[cfg(windows)]
                kill_windows_process_tree(child);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(windows)]
fn kill_windows_process_tree(child: &mut Child) {
    let Some(system_root) = std::env::var_os("SystemRoot")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("windir").filter(|value| !value.is_empty()))
    else {
        return;
    };
    let system32 = if cfg!(all(windows, target_pointer_width = "32")) {
        "Sysnative"
    } else {
        "System32"
    };
    let taskkill = PathBuf::from(system_root)
        .join(system32)
        .join("taskkill.exe");
    if taskkill.is_file() {
        let _ = Command::new(taskkill)
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn create_unique_with(
    root: &Path,
    mut candidate: impl FnMut(u64) -> PathBuf,
) -> io::Result<TempDir> {
    let mut last_path = PathBuf::new();
    for attempt in 0..MAX_CREATE_ATTEMPTS {
        let path = candidate(attempt);
        last_path.clone_from(&path);
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    {
                        let _ = fs::remove_dir(&path);
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "cannot secure temporary directory {}: {error}",
                                path.display()
                            ),
                        ));
                    }
                }
                return Ok(TempDir(path));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot create temporary directory {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "could not create a unique temporary directory under {} after {MAX_CREATE_ATTEMPTS} attempts (last candidate: {})",
            root.display(),
            last_path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::{MAX_CREATE_ATTEMPTS, TempDir, create_unique_with};
    use std::collections::HashSet;
    use std::fs;
    use std::io;
    use std::process::{Command, Stdio};

    #[test]
    fn concurrent_directories_are_unique_and_cleaned_up() {
        const COUNT: usize = 64;
        let root = std::env::temp_dir();
        let directories: Vec<TempDir> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..COUNT)
                .map(|_| {
                    let root = root.clone();
                    scope.spawn(move || TempDir::new_in(&root, "neotales-temp-test").unwrap())
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect()
        });
        assert!(directories.iter().all(|directory| directory.is_dir()));
        assert!(
            directories
                .iter()
                .all(|directory| directory.parent() == Some(root.as_path()))
        );
        assert_eq!(
            directories
                .iter()
                .map(|directory| directory.to_path_buf())
                .collect::<HashSet<_>>()
                .len(),
            COUNT
        );
        let paths: Vec<_> = directories
            .iter()
            .map(|directory| directory.to_path_buf())
            .collect();
        drop(directories);
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn existing_candidates_are_retried_and_exhaustion_is_bounded() {
        let root = TempDir::new("neotales-temp-collision-test").unwrap();
        let collision = root.join("occupied");
        fs::create_dir(&collision).unwrap();

        let mut calls = 0;
        let error = create_unique_with(&root, |_| {
            calls += 1;
            collision.clone()
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            error
                .to_string()
                .contains(collision.to_string_lossy().as_ref())
        );
        assert_eq!(
            calls,
            usize::try_from(MAX_CREATE_ATTEMPTS).expect("attempt limit fits usize")
        );
    }

    #[test]
    fn retries_a_collision_then_creates_the_next_candidate() {
        let root = TempDir::new("neotales-temp-retry-test").unwrap();
        let collision = root.join("occupied");
        fs::create_dir(&collision).unwrap();
        let created = root.join("available");
        let directory = create_unique_with(&root, |attempt| {
            if attempt == 0 {
                collision.clone()
            } else {
                created.clone()
            }
        })
        .unwrap();
        assert_eq!(&*directory, created.as_path());
        assert!(directory.is_dir());
    }

    #[test]
    fn reports_a_missing_parent_instead_of_creating_it() {
        let parent = TempDir::new("neotales-temp-missing-parent-test").unwrap();
        let missing = parent.join("missing");
        let error = TempDir::new_in(&missing, "child").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .contains(missing.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn temporary_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new("neotales-temp-permissions-test").unwrap();
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn into_inner_transfers_child_ownership() {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .spawn()
            .unwrap();
        let child = super::ChildGuard::new(child).into_inner();
        assert!(child.wait_with_output().unwrap().status.success());
    }

    #[cfg(unix)]
    #[test]
    fn dropping_tree_guard_kills_and_reaps_descendants() {
        let directory = TempDir::new("neotales-child-guard-test").unwrap();
        let descendant_pid_file = directory.join("descendant.pid");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "openssh_tools::temp_dir::tests::child_guard_test_helper",
                "--nocapture",
            ])
            .env("NEOTALES_CHILD_GUARD_TEST_PARENT", &descendant_pid_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = super::ChildGuard::spawn_tree(&mut command).unwrap();
        let child_pid = i32::try_from(child.id()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let descendant_pid = loop {
            if let Ok(contents) = fs::read_to_string(&descendant_pid_file)
                && let Ok(pid) = contents.trim().parse::<i32>()
            {
                break pid;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "helper did not write a valid descendant pid"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        drop(child);

        let reap_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for pid in [child_pid, descendant_pid] {
            while !matches!(
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
                Err(nix::errno::Errno::ESRCH)
            ) && std::time::Instant::now() < reap_deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                matches!(
                    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
                    Err(nix::errno::Errno::ESRCH)
                ),
                "process {pid} survived tree-guard drop"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn dropping_single_child_guard_kills_and_reaps_child() {
        let child = spawn_helper("NEOTALES_CHILD_GUARD_TEST_CHILD");
        let pid = i32::try_from(child.id()).unwrap();
        drop(super::ChildGuard::new(child));
        assert!(matches!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        ));
    }

    #[test]
    fn child_guard_test_helper() {
        if std::env::var_os("NEOTALES_CHILD_GUARD_TEST_PARENT").is_some() {
            let marker = std::env::var_os("NEOTALES_CHILD_GUARD_TEST_PARENT").unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "openssh_tools::temp_dir::tests::child_guard_test_helper",
                    "--nocapture",
                ])
                .env("NEOTALES_CHILD_GUARD_TEST_GRANDCHILD", "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = command.spawn().unwrap();
            let marker = std::path::PathBuf::from(marker);
            let pending_marker = marker.with_extension("pid.tmp");
            fs::write(&pending_marker, child.id().to_string()).unwrap();
            fs::rename(pending_marker, marker).unwrap();
            let _ = child.wait();
        }
        if std::env::var_os("NEOTALES_CHILD_GUARD_TEST_GRANDCHILD").is_some()
            || std::env::var_os("NEOTALES_CHILD_GUARD_TEST_CHILD").is_some()
        {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
    }

    #[cfg(unix)]
    fn spawn_helper(variable: &str) -> std::process::Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "openssh_tools::temp_dir::tests::child_guard_test_helper",
                "--nocapture",
            ])
            .env(variable, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.spawn().unwrap()
    }
}
