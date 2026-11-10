// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code, clippy::pedantic)]
#[path = "support/cli_support.rs"]
mod support;

use std::process::{ExitStatus, Output};

use neotales_keepass::{KdbxCredentials, KdbxFile, KdbxReadLimits};
use support::{CliFixture, ENTRY_PASSWORD, KEY_FILE, MASTER_PASSWORD, find_leak};

#[cfg(unix)]
fn status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

#[cfg(windows)]
fn status() -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

fn output(stdout: &[u8], stderr: &[u8]) -> Output {
    Output {
        status: status(),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

fn failure_status() -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(256)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(1)
    }
}

#[test]
fn disposable_vaults_open_with_only_the_right_credential_sources() {
    for with_key_file in [false, true] {
        let fixture = CliFixture::new(with_key_file);
        let mut credentials = if with_key_file {
            KdbxCredentials::with_provider(
                Some(MASTER_PASSWORD),
                Box::new(neotales_keepass::KdbxKeyFile::parse(KEY_FILE).unwrap()),
            )
            .unwrap()
        } else {
            KdbxCredentials::password(MASTER_PASSWORD).unwrap()
        };
        let database = KdbxFile::load(
            std::fs::File::open(fixture.vault()).unwrap(),
            &mut credentials,
            &KdbxReadLimits::default(),
        )
        .unwrap();
        let entry = &database.root.entries[0];
        assert_eq!(
            entry.password.reveal_text().unwrap().as_str(),
            ENTRY_PASSWORD
        );
        assert_eq!(
            database
                .binary_pool
                .get(entry.attachments[0].reference)
                .unwrap()
                .data,
            support::ATTACHMENT
        );
        assert_eq!(
            entry
                .field("Private custom field")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            support::CUSTOM_FIELD
        );
        assert_eq!(
            entry
                .field("otp")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            support::OTP_URI
        );

        let mut wrong = KdbxCredentials::password(support::WRONG_PASSWORD).unwrap();
        assert!(
            KdbxFile::load(
                std::fs::File::open(fixture.vault()).unwrap(),
                &mut wrong,
                &KdbxReadLimits::default()
            )
            .is_err()
        );
        assert!(
            KdbxFile::load(
                std::fs::File::open(fixture.corrupt_vault()).unwrap(),
                &mut credentials,
                &KdbxReadLimits::default()
            )
            .is_err()
        );
    }
}

#[test]
fn byte_scanner_catches_stdout_stderr_and_invalid_utf8_without_echoing_values() {
    let clean = output(b"fixture-login\n", b"invalid credentials\n");
    assert_eq!(find_leak(&clean), None);
    for (label, marker) in [
        ("master password", MASTER_PASSWORD.as_bytes()),
        ("wrong password", support::WRONG_PASSWORD.as_bytes()),
        ("entry password", ENTRY_PASSWORD.as_bytes()),
        ("username", support::USERNAME.as_bytes()),
        ("notes", support::NOTES.as_bytes()),
        ("custom field", support::CUSTOM_FIELD.as_bytes()),
        ("otp seed", support::OTP_SEED.as_bytes()),
        ("attachment", support::ATTACHMENT),
        ("key file", support::KEY_FILE.as_slice()),
        ("missing path", b"missing-entry-SENTINEL-2d5c83"),
        ("otp uri fragment", b"secret="),
    ] {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(marker);
        assert_eq!(find_leak(&output(&bytes, b"")).unwrap().marker, label);
        assert_eq!(find_leak(&output(b"", &bytes)).unwrap().channel, "stderr");
    }
}

#[test]
fn suite_requires_all_public_and_error_scenarios() {
    let fixture = CliFixture::new(false);
    let mut visited = Vec::new();
    support::assert_public_surfaces(&fixture, |scenario, _| {
        visited.push(scenario);
        let mut result = output(b"fixture-login", b"");
        if matches!(
            scenario,
            support::Scenario::MissingEntry
                | support::Scenario::WrongPassword
                | support::Scenario::CorruptVault
        ) {
            result.status = failure_status();
        }
        result
    });
    assert_eq!(visited.len(), 7);
}
