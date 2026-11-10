// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

//! Optional external-client check. Fixture tests remain unconditional in roundtrip.rs.
use std::io::Write;
use std::process::{Command, Stdio};

use neotales_keepass::{
    Entry, Kdbx3WriteOptions, KdbxCompression, KdbxCredentials, KdbxFile, KdbxKdf, KdbxOuterCipher,
    KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_argon2_variants() {
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("argon2-interop"));
    for kdf in [KdbxKdf::Argon2d, KdbxKdf::Argon2id] {
        let path = directory.path().join(format!("{kdf:?}.kdbx"));
        let mut file = std::fs::File::create(&path).unwrap();
        KdbxFile::save(
            &database,
            &mut file,
            &mut KdbxCredentials::password("argon2-interop-password").unwrap(),
            KdbxWriteOptions {
                kdf,
                argon2_memory_kib: 32,
                argon2_time: 1,
                argon2_lanes: 1,
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &limits,
        )
        .unwrap();
        drop(file);

        let mut child = Command::new("keepassxc-cli")
            .arg("db-info")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"argon2-interop-password\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "KeePassXC could not list {kdf:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Number of entries: 1"));
    }
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_kdbx3_variants() {
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .root
        .entries
        .push(Entry::new("kdbx3-external-client-check"));

    for compression in [KdbxCompression::None, KdbxCompression::GZip] {
        let path = directory.path().join(format!("kdbx3-{compression:?}.kdbx"));
        let mut file = std::fs::File::create(&path).unwrap();
        KdbxFile::save_kdbx3(
            &database,
            &mut file,
            &mut KdbxCredentials::password("kdbx3-interop-password").unwrap(),
            Kdbx3WriteOptions {
                compression,
                aes_kdf_rounds: 8,
                block_bytes: 1024,
            },
            &limits,
        )
        .unwrap();
        drop(file);

        let mut child = Command::new("keepassxc-cli")
            .arg("db-info")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"kdbx3-interop-password\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "KeePassXC could not list KDBX3/{compression:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info = String::from_utf8_lossy(&output.stdout);
        assert!(
            info.contains("Number of entries: 1"),
            "KeePassXC did not read the KDBX3 entry count: {info}"
        );
    }
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_cipher_and_compression_matrix() {
    // Only absence skips this test; an installed but broken CLI fails the gate.
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .root
        .entries
        .push(Entry::new("external-client-check"));

    for cipher in [KdbxOuterCipher::Aes, KdbxOuterCipher::ChaCha20] {
        for compression in [KdbxCompression::None, KdbxCompression::GZip] {
            let path = directory
                .path()
                .join(format!("{cipher:?}-{compression:?}.kdbx"));
            let mut file = std::fs::File::create(&path).unwrap();
            KdbxFile::save(
                &database,
                &mut file,
                &mut KdbxCredentials::password("interop-test-password").unwrap(),
                KdbxWriteOptions {
                    cipher,
                    compression,
                    aes_kdf_rounds: 8,
                    ..KdbxWriteOptions::default()
                },
                &limits,
            )
            .unwrap();
            drop(file);

            let mut child = Command::new("keepassxc-cli")
                .arg("db-info")
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"interop-test-password\n")
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "KeePassXC could not list {cipher:?}/{compression:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let info = String::from_utf8_lossy(&output.stdout);
            assert!(
                info.contains("Number of entries: 1"),
                "KeePassXC did not read the entry count for {cipher:?}/{compression:?}: {info}"
            );
            let expected_cipher = match cipher {
                KdbxOuterCipher::Aes => "Cipher: AES 256-bit",
                KdbxOuterCipher::ChaCha20 => "Cipher: ChaCha20 256-bit",
            };
            assert!(
                info.contains(expected_cipher),
                "KeePassXC cipher mismatch: {info}"
            );
        }
    }
}
