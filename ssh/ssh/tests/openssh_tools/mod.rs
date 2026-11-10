//! Locating the OpenSSH programs the live lanes drive.
//!
//! # Why this module exists
//!
//! The live lanes used to name `sshd` by absolute path, and they named it two
//! different ways inside one area: `/usr/bin/sshd` in `openssh_interop.rs` and
//! `openssh_channels.rs`, `/usr/sbin/sshd` in `openssh_identities.rs`. Both
//! spellings resolve on a Linux distribution with a merged `/usr`, and on a
//! split-`/usr` one `/usr/bin/sshd` is a symlink into the same place, so the
//! difference was invisible on the machine the lanes were written on. **Half of
//! that is wrong on macOS**: the server is `/usr/sbin/sshd` and has never been
//! anywhere else, so the 12 lanes in the two `/usr/bin` files could not spawn a
//! peer there at all — they failed on the spawn, before any protocol code ran,
//! and the message was `No such file or directory (os error 2)`, which names the
//! wrong problem.
//!
//! `ssh-agent` and `ssh-add` were absolute too, and for the same reason: they
//! are in `/usr/bin` on both platforms today, which is a coincidence rather
//! than a contract.
//!
//! # The order
//!
//! Two orders, both explicit, and both tested in `openssh_discovery.rs`:
//!
//! 1. [`Order::DirectoriesFirst`] — the install directories, then `PATH`. This
//!    is `sshd`'s order. It is a system daemon, and `sbin` is not on an
//!    unprivileged `PATH` on every distribution, so a `PATH`-only lookup finds
//!    nothing on a machine that has a perfectly good `sshd`.
//! 2. [`Order::PathFirst`] — `PATH`, then the install directories. This is the
//!    client tools' order, because a caller is far more likely to have put its
//!    own `ssh-keygen` on `PATH` deliberately, and preferring it is the useful
//!    reading.
//!
//! Install directories are platform-specific. Unix searches its system and
//! package-manager locations; Windows searches the in-box System32 OpenSSH
//! directory and the Win32-OpenSSH Program Files installation. Windows client
//! and server tools use `.exe` files and are searched without invoking shell
//! scripts.
//!
//! # What happens when a program is absent
//!
//! **The lane fails, and the failure says what was missing and where it looked.**
//! It does not print "skipping" and pass.
//!
//! This is a deliberate difference from `docker/engine/tests/ssh_dial_stdio.rs`,
//! which probes for its three programs on `PATH` and returns early with a
//! printed "skipping" line. That file's header gives the reason it can afford
//! to: the lanes it guards are not a claim this repository makes about
//! interoperability, they are coverage of a transport, and a coverage lane that
//! reports "not run here" is still reporting honestly.
//!
//! These lanes *are* the interoperability claim. `docs/support-matrix.md`
//! records `neotales-ssh` as verified against a live `sshd`, and the only
//! evidence for that is a green run of exactly these tests. A lane that turns
//! itself green because it could not start a peer would make the recorded claim
//! unfalsifiable, which is the specific failure
//! `docs/support-matrix.md`'s own preamble says this section exists to prevent.
//! So the absence of a prerequisite is an error, the error names the program and
//! every path that was tried, and it names the package that provides it.
//!
//! The tests are `#[ignore]`d, so this only fires for a caller who asked for the
//! live lanes on purpose — `cargo test -p neotales-ssh -- --include-ignored`, or
//! one test target with `--ignored`.
//!
//! # What is *not* claimed here
//!
//! Tool discovery passing is not itself interoperability evidence; the live
//! `sshd` lanes are run separately on each claimed platform. Windows agent lanes
//! are excluded because this crate does not implement the named-pipe agent
//! protocol. See `docs/support-matrix.md` and `docs/parity.md`.

#![allow(dead_code)]

pub(crate) mod temp_dir;

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// Directories OpenSSH installs into, in the order they are tried.
///
/// `sshd` is a system daemon, not a user tool, and this list is why a `PATH`
/// lookup is not enough for it: on several distributions `/usr/sbin` is absent
/// from the `PATH` a plain non-login shell is given, and a lane that concluded
/// "OpenSSH is not installed" from that would be wrong.
const UNIX_INSTALL_DIRECTORIES: &[&str] = &[
    // Linux with a split /usr (Fedora, Arch, SUSE, Debian before the merge)
    // and macOS, where the server has never moved out of /usr/sbin.
    "/usr/sbin",
    // Linux with a merged /usr, which is most distributions now, and macOS for
    // the client tools.
    "/usr/bin",
    // A source or `make install` under a local prefix.
    "/usr/local/sbin",
    "/usr/local/bin",
    // Homebrew on Apple silicon. Its `openssh` formula is keg-only, so it is
    // not on a default PATH, and a lane that could not find it would blame the
    // base system.
    "/opt/homebrew/bin",
    // Homebrew on Intel, and MacPorts.
    "/opt/local/bin",
];

/// The platform's OpenSSH install directories, in the order they are tried.
pub(crate) fn install_directories() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut directories = Vec::new();
        let system_root = std::env::var_os("SystemRoot")
            .filter(|value| !value.is_empty())
            .or_else(|| std::env::var_os("windir").filter(|value| !value.is_empty()));
        if let Some(root) = system_root {
            let directory = PathBuf::from(root).join("System32").join("OpenSSH");
            if directory.is_absolute() {
                directories.push(directory);
            }
        }
        if let Some(program_files) =
            std::env::var_os("ProgramFiles").filter(|value| !value.is_empty())
        {
            let directory = PathBuf::from(program_files).join("OpenSSH");
            if directory.is_absolute() && !directories.contains(&directory) {
                directories.push(directory);
            }
        }
        directories
    }
    #[cfg(not(windows))]
    {
        UNIX_INSTALL_DIRECTORIES.iter().map(PathBuf::from).collect()
    }
}

/// The `sshd` program name, as it appears on disk on every unix platform.
const SSHD: &str = "sshd";

/// Which of the two lookups to perform for a program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Order {
    /// The install directories, then `PATH`. For `sshd`.
    DirectoriesFirst,
    /// `PATH`, then the install directories. For the client tools.
    PathFirst,
}

/// A program the live lanes need that is not installed.
///
/// This is an error rather than a skip; see the module documentation for why.
/// Its [`fmt::Display`] is the whole message a caller sees, so it names the
/// program, every location that was tried, and the package that provides it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Missing {
    program: &'static str,
    searched: Vec<PathBuf>,
    provider: &'static str,
}

impl Missing {
    /// Builds a missing-program error from the same candidates the lookup uses.
    pub(crate) fn new(program: &'static str, order: Order, provider: &'static str) -> Self {
        Self {
            program,
            searched: candidates(program, order),
            provider,
        }
    }

    pub(crate) const fn program(&self) -> &'static str {
        self.program
    }
}

impl fmt::Debug for Missing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Missing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "`{}` is not installed, so the live OpenSSH lanes cannot run.",
            self.program
        )?;
        writeln!(formatter, "Searched {} location(s):", self.searched.len())?;
        for candidate in &self.searched {
            writeln!(formatter, "  {}", candidate.display())?;
        }
        writeln!(formatter, "\nInstall it with: {}", self.provider)?;
        formatter.write_str(
            "This is reported as a failure rather than a skip on purpose. These lanes are the \
             evidence behind the interoperability claim in docs/support-matrix.md, and a lane \
             that reports success because it never started a peer would make that claim \
             unfalsifiable.",
        )
    }
}

impl std::error::Error for Missing {}

/// Every path that will be tried for `program`, in the order the lookup tries
/// them.
///
/// Exposed for the ordering test rather than for the lanes, so the order in the
/// module documentation is a thing a test can check and not only a thing a
/// reader can believe.
pub(crate) fn candidates(program: &str, order: Order) -> Vec<PathBuf> {
    let mut from_directories: Vec<PathBuf> = install_directories()
        .into_iter()
        .flat_map(|directory| {
            executable_names(program)
                .into_iter()
                .map(move |name| directory.join(name))
        })
        .collect();
    let mut from_path: Vec<PathBuf> = path_directories()
        .into_iter()
        .flat_map(|directory| {
            executable_names(program)
                .into_iter()
                .map(move |name| directory.join(name))
        })
        .collect();
    match order {
        Order::DirectoriesFirst => {
            from_directories.append(&mut from_path);
            from_directories
        }
        Order::PathFirst => {
            from_path.append(&mut from_directories);
            from_path
        }
    }
}

/// Every directory on `PATH`, in `PATH`'s own order.
///
/// Windows OpenSSH tools are executable `.exe` files; selecting only that suffix
/// avoids returning batch files that `Command::new` refuses to spawn with
/// ordinary argument handling.
pub(crate) fn path_directories() -> Vec<PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    std::env::split_paths(&path)
        .filter(|directory| !directory.as_os_str().is_empty() && directory.is_absolute())
        .collect()
}

/// The names a program may have on disk for a given bare name.
///
/// The bare name on Unix and the native `.exe` spelling on Windows.
fn executable_names(program: &str) -> Vec<OsString> {
    #[cfg(windows)]
    {
        vec![OsString::from(format!("{program}.exe"))]
    }
    #[cfg(not(windows))]
    {
        vec![OsString::from(program)]
    }
}

/// The lookup itself: the first candidate that is a file on disk.
///
/// Split out from [`find`] so the ordering test can assert on a resolution
/// without going through the error type, and so the predicate that decides "this
/// is the program" exists exactly once.
pub(crate) fn locate(program: &str, order: Order) -> Option<PathBuf> {
    locate_in(&candidates(program, order))
}

fn locate_in(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| is_program(candidate))
        .cloned()
}

fn is_program(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Runs the ordered lookup and retains the exact candidate list on a miss.
fn find(program: &'static str, order: Order, provider: &'static str) -> Result<PathBuf, Missing> {
    let searched = Missing::new(program, order, provider);
    match locate_in(&searched.searched) {
        Some(path) => Ok(path),
        None => Err(searched),
    }
}

/// The `sshd` to spawn.
///
/// Resolved once per lane rather than at compile time, because a path baked
/// into a test is a path that is wrong on some platform the test claims.
pub(crate) fn sshd() -> Result<PathBuf, Missing> {
    #[cfg(windows)]
    const PROVIDER: &str = "Install the OpenSSH Server optional capability from an elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.";
    #[cfg(not(windows))]
    const PROVIDER: &str = "`apt-get install openssh-server`, `dnf install openssh-server`, `pacman -S openssh`, or `apk add openssh`. On macOS it ships in the base system as /usr/sbin/sshd and needs no install.";
    find(SSHD, Order::DirectoriesFirst, PROVIDER)
}

/// The `ssh-keygen` that mints the throwaway host and user keys.
pub(crate) fn ssh_keygen() -> Result<PathBuf, Missing> {
    #[cfg(windows)]
    const PROVIDER: &str = "Install the OpenSSH Client optional capability from an elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`.";
    #[cfg(not(windows))]
    const PROVIDER: &str = "It ships with the OpenSSH client: `apt-get install openssh-client`, `dnf install openssh-clients`, `pacman -S openssh`, or `brew install openssh`. On macOS it is /usr/bin/ssh-keygen and needs no install.";
    find("ssh-keygen", Order::PathFirst, PROVIDER)
}

/// The `ssh-agent` that holds a real key for the agent lanes.
pub(crate) fn ssh_agent() -> Result<PathBuf, Missing> {
    #[cfg(windows)]
    const PROVIDER: &str = "Install the OpenSSH Client optional capability from an elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`.";
    #[cfg(not(windows))]
    const PROVIDER: &str = "It ships with the OpenSSH client: `apt-get install openssh-client`, `dnf install openssh-clients`, `pacman -S openssh`, or `brew install openssh`. On macOS it is /usr/bin/ssh-agent and needs no install.";
    find("ssh-agent", Order::PathFirst, PROVIDER)
}

/// The `ssh-add` that loads a key into the agent.
pub(crate) fn ssh_add() -> Result<PathBuf, Missing> {
    #[cfg(windows)]
    const PROVIDER: &str = "Install the OpenSSH Client optional capability from an elevated PowerShell: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`.";
    #[cfg(not(windows))]
    const PROVIDER: &str = "It ships with the OpenSSH client: `apt-get install openssh-client`, `dnf install openssh-clients`, `pacman -S openssh`, or `brew install openssh`. On macOS it is /usr/bin/ssh-add and needs no install.";
    find("ssh-add", Order::PathFirst, PROVIDER)
}

/// Username of the process running the live lane, requiring a nonempty UTF-8
/// environment value rather than guessing a local account name.
pub(crate) fn current_user() -> std::io::Result<String> {
    username_from_values(
        ["USER", "LOGNAME", "USERNAME"]
            .into_iter()
            .filter_map(std::env::var_os),
    )
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine a nonempty UTF-8 username from USER, LOGNAME, or USERNAME",
        )
    })
}

fn username_from_values(values: impl IntoIterator<Item = OsString>) -> Option<String> {
    values.into_iter().find_map(|value| {
        if value.is_empty() {
            return None;
        }
        value.into_string().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{current_user, username_from_values};
    use std::ffi::OsString;

    #[test]
    fn current_username_is_nonempty() {
        assert!(!current_user().unwrap().is_empty());
    }

    #[test]
    fn current_username_skips_empty_and_non_utf8_candidates() {
        let candidates = {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                vec![
                    OsString::new(),
                    OsString::from_vec(vec![0xff]),
                    OsString::from("usable-user"),
                ]
            }
            #[cfg(not(unix))]
            {
                vec![OsString::new(), OsString::from("usable-user")]
            }
        };
        assert_eq!(
            username_from_values(candidates),
            Some("usable-user".to_owned())
        );
    }
}
