//! The OpenSSH program lookup the live lanes depend on.
//!
//! ```text
//! cargo test -p neotales-ssh --test openssh_discovery
//! ```
//!
//! # Why this file is not `#[ignore]`d
//!
//! The lanes in `openssh_interop.rs`, `openssh_channels.rs` and
//! `openssh_identities.rs` are all `#[ignore]`d, because they need a real
//! `sshd`. **This file needs nothing installed**, and it is the only coverage
//! of the mechanism that decides whether those lanes can run at all.
//!
//! That gap is the reason the mechanism was worth writing down. The lanes used
//! to hardcode `/usr/bin/sshd` and `/usr/sbin/sshd` — two spellings of one
//! binary, and neither of them the macOS path for the file that matters — and
//! nothing tested the lookup, because there was no lookup to test. A lane that
//! could not find its peer failed with `No such file or directory (os error 2)`,
//! which names a missing file rather than a missing package.
//!
//! # What is and is not established here
//!
//! Established: the search order, that the order is the one the module
//! documents, that a resolution returns a path from the candidate list, and
//! that an absent program produces a message naming every location searched and
//! the package that provides it.
//!
//! Not established: that lookup tests alone prove live interoperability. These
//! tests never spawn `sshd`; they only resolve where it would be looked for.
//! Native live-lane evidence and current revalidation are recorded in
//! `docs/support-matrix.md` and `docs/parity.md`.
//!
//! Nothing here writes `PATH`. `std::env::set_var` is `unsafe` in edition 2024
//! and this workspace `forbid`s `unsafe_code`, so a test that faked a `PATH`
//! would have to be exactly the kind of test the lint exists to keep out of a
//! test target. Reading it concurrently is fine, because nothing in this binary
//! writes it.

#![allow(missing_docs)]

mod openssh_tools;

use std::path::{Path, PathBuf};

use openssh_tools::{Missing, Order, candidates, install_directories, locate, path_directories};

/// The install directories the module documents, in the documented order.
///
/// Spelled out here rather than imported, so a change to either list is a test
/// failure. An ordering claim checked against the thing it is a claim about is
/// not a check.
#[cfg(not(windows))]
const UNIX_INSTALL_DIRECTORIES: &[&str] = &[
    "/usr/sbin",
    "/usr/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
];

/// A program name that cannot be installed anywhere, on any platform.
///
/// Used where the assertion is about a miss. A name that did not exist could
/// make a broken lookup look correct.
const ABSENT: &str = "neotales-no-such-openssh-program";

/// The directories the candidate list came from, in order.
///
/// Every candidate is `<directory>/<program>`, so the parent is the directory.
/// Comparing parents compares the order without depending on the program name
/// or on `PATHEXT` expansion.
fn directories_of(candidates: &[PathBuf]) -> Vec<PathBuf> {
    candidates
        .iter()
        .map(|candidate| {
            candidate
                .parent()
                .map_or_else(|| PathBuf::from("<no parent>"), Path::to_path_buf)
        })
        .collect()
}

#[test]
fn sshd_is_looked_for_in_the_install_directories_before_path() {
    let directories = directories_of(&candidates("sshd", Order::DirectoriesFirst));
    let expected = install_directories();
    assert!(
        !expected.is_empty(),
        "the platform's OpenSSH install directory list must not be empty"
    );
    let head: Vec<PathBuf> = directories.iter().take(expected.len()).cloned().collect();
    assert_eq!(
        head, expected,
        "`sshd` must be tried in the install directories first, in this order: it is a \
         system daemon and `sbin` is not on an unprivileged PATH everywhere"
    );
    let expected_path = path_directories();
    let actual_path: Vec<PathBuf> = directories.into_iter().skip(expected.len()).collect();
    assert_eq!(actual_path, expected_path);
}

#[test]
#[cfg(not(windows))]
fn unix_install_directories_include_the_system_sshd_locations() {
    // The two spellings the lanes used to hardcode, and the reason one of them
    // was wrong: macOS has never moved `sshd` out of `/usr/sbin`, while Linux
    // distributions with a merged `/usr` reach the same file through
    // `/usr/bin`. A lookup that tried only one of the two could not run on one
    // of the two platforms this repository claims.
    let directories: Vec<String> = candidates("sshd", Order::DirectoriesFirst)
        .iter()
        .filter_map(|candidate| candidate.parent()?.to_str().map(str::to_owned))
        .collect();
    let expected: Vec<String> = UNIX_INSTALL_DIRECTORIES
        .iter()
        .map(|directory| (*directory).to_owned())
        .collect();
    assert_eq!(
        &directories[..expected.len()],
        expected,
        "Unix install directories must be searched in the documented order"
    );
    assert!(
        directories.iter().any(|directory| directory == "/usr/sbin"),
        "no candidate under /usr/sbin, so macOS's own location is not searched: {directories:?}"
    );
    assert!(
        directories.iter().any(|directory| directory == "/usr/bin"),
        "no candidate under /usr/bin, so a merged-/usr Linux is not searched: {directories:?}"
    );
}

#[test]
fn the_client_tools_are_looked_for_on_path_before_the_install_directories() {
    let directories = directories_of(&candidates("ssh-keygen", Order::PathFirst));
    let path_directories = path_directories();
    assert!(
        directories.len() >= path_directories.len(),
        "candidate list is shorter than the filtered PATH directories"
    );
    assert_eq!(
        &directories[..path_directories.len()],
        path_directories,
        "a caller who put their own ssh-keygen on PATH should get theirs, not the distribution's"
    );
    assert_eq!(
        &directories[path_directories.len()..],
        install_directories(),
        "install directories must be the fallback for the client tools"
    );
}

#[test]
fn every_candidate_is_an_absolute_path() {
    for order in [Order::DirectoriesFirst, Order::PathFirst] {
        for program in ["sshd", "ssh-keygen", "ssh-agent", "ssh-add"] {
            for candidate in candidates(program, order) {
                assert!(candidate.is_absolute(), "relative candidate: {candidate:?}");
            }
        }
    }
}

#[test]
#[cfg(windows)]
fn windows_sshd_candidates_start_at_the_systemroot_install() {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .filter(|value| !value.is_empty())
        .expect("Windows defines a nonempty SystemRoot or windir");
    let in_box = PathBuf::from(root).join("System32").join("OpenSSH");
    let directories = install_directories();
    assert_eq!(directories.first(), Some(&in_box));

    let paths = candidates("sshd", Order::DirectoriesFirst);
    assert_eq!(paths.first(), Some(&in_box.join("sshd.exe")));
    assert!(
        paths.iter().any(|path| path == &in_box.join("sshd.exe")),
        "the in-box sshd.exe must be searched: {paths:?}"
    );

    let actual = locate("sshd", Order::DirectoriesFirst);
    if in_box.join("sshd.exe").is_file() {
        assert_eq!(actual, Some(in_box.join("sshd.exe")));
    }
}

#[test]
#[cfg(windows)]
fn windows_candidates_use_only_native_executables() {
    for program in ["sshd", "ssh-keygen", "ssh-agent", "ssh-add"] {
        for candidate in candidates(program, Order::DirectoriesFirst) {
            assert_eq!(candidate.extension(), Some(std::ffi::OsStr::new("exe")));
        }
    }
}

#[test]
fn a_resolution_returns_a_path_from_the_candidate_list() {
    let searched = candidates("sshd", Order::DirectoriesFirst);
    match locate("sshd", Order::DirectoriesFirst) {
        Some(path) => {
            assert!(
                searched.contains(&path),
                "a resolution returned {path:?}, which is not one of the candidates that \
                 were searched: {searched:?}"
            );
            assert!(path.is_absolute() && path.is_file());
        }
        None => {
            // OpenSSH is not installed here, which is not a defect. What has to
            // hold is that the miss is a miss: every candidate really is absent,
            // so nothing was skipped that should have been taken.
            for candidate in &searched {
                assert!(
                    !candidate.is_file(),
                    "{} exists but the lookup did not return it",
                    candidate.display()
                );
            }
        }
    }
}

#[test]
fn a_program_that_is_not_installed_resolves_to_nothing() {
    assert_eq!(
        locate(ABSENT, Order::DirectoriesFirst),
        None,
        "`{ABSENT}` is not installed anywhere, so it must not resolve"
    );
    assert_eq!(
        locate(ABSENT, Order::PathFirst),
        None,
        "`{ABSENT}` is not installed anywhere, so it must not resolve"
    );
}

#[test]
fn an_absent_program_is_reported_with_everywhere_it_looked() {
    let missing = Missing::new(ABSENT, Order::PathFirst, "a package that provides it");
    let searched = candidates(ABSENT, Order::PathFirst);
    let message = missing.to_string();
    assert_eq!(format!("{missing:?}"), message);

    // A reader who hits this has to learn three things: which program, where it
    // was looked for, and what to install. A message missing any of the three
    // sends them back to the same search the code just did.
    assert!(
        message.contains(&format!("`{ABSENT}` is not installed")),
        "the message does not name the program: {message}"
    );
    for candidate in &searched {
        assert!(
            message.contains(&candidate.display().to_string()),
            "the message does not name {}: {message}",
            candidate.display()
        );
    }
    assert!(
        message.contains("a package that provides it"),
        "the message does not say what to install: {message}"
    );
    assert!(
        message.contains("rather than a skip"),
        "the message does not say that an absent prerequisite is a failure, which is \
         the whole reason this type exists instead of a printed line: {message}"
    );
}

#[test]
fn the_installed_openssh_tools_are_discoverable_or_the_message_is_usable() {
    // The one test here that touches the machine's real OpenSSH, and it passes
    // either way on purpose. A machine without OpenSSH is not a broken machine,
    // and this repository's standard is that an exclusion is never a *silent*
    // skip — so the absence is asserted to be loud, not asserted to be an
    // error. On a machine with OpenSSH, the discovery is exercised for real.
    for resolved in [
        openssh_tools::sshd(),
        openssh_tools::ssh_keygen(),
        openssh_tools::ssh_agent(),
        openssh_tools::ssh_add(),
    ] {
        match resolved {
            Ok(path) => assert!(
                path.is_absolute() && path.is_file(),
                "a resolved program must be an absolute path to a file that exists, or a \
                 later change of working directory would change what it names: {path:?}"
            ),
            Err(missing) => {
                eprintln!("{missing}");
                let message = missing.to_string();
                assert!(
                    message.lines().count() > 4,
                    "the absence message is too short to be actionable: {message}"
                );
                assert!(
                    message.contains(missing.program()),
                    "the absence message does not name the program it is about: {message}"
                );
            }
        }
    }
}
