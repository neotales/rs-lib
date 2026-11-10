//! Interoperation against a reference age implementation.
//!
//! These tests shell out to a reference CLI, so they are `#[ignore]`d and run in
//! the interop lane rather than in an ordinary `cargo test`. A test that silently
//! passes because the tool was missing is worse than no test, so when one of these
//! does run and cannot find the tool, it fails. There is no skip path.
//!
//! Run them with:
//!
//! ```text
//! cargo test -p neotales-age --test interop -- --ignored
//! ```
//!
//! The tool is located through `NEOTALES_AGE_REFERENCE_BIN`, and falls back to
//! `rage` on `PATH`. The lane is run on all three platforms, and the version used
//! is recorded in the area README rather than discovered at test time, so a
//! reference implementation that changes behaviour shows up as a version bump
//! rather than as a mystery.

#![allow(missing_docs)] // A test binary has no public API to document.

use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locates the reference CLI, or fails with a message that says how to provide it.
fn reference_bin() -> PathBuf {
    if let Some(path) = std::env::var_os("NEOTALES_AGE_REFERENCE_BIN") {
        return path.into();
    }
    PathBuf::from("rage")
}

/// A scratch directory for one test, cleaned up when the test ends.
///
/// The existing crate tests name theirs after the process id. These run in
/// parallel inside one process, so the name has to carry the test as well:
/// sharing a directory means one test's cleanup deletes the files another is
/// still reading, which fails intermittently and looks like a format problem.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "neotales-age-interop-{}-{test}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch directory");
        Self { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Runs the reference CLI, failing with its own stderr if it is unhappy.
///
/// Panicking on a non-zero status is the point. A reference tool that exits
/// non-zero has told us the container is wrong, and a test that treats that as a
/// pass is the exact failure this file exists to prevent.
fn reference(args: &[&str]) -> Vec<u8> {
    let bin = reference_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run the reference tool {}: {e}", bin.display()));

    assert!(
        output.status.success(),
        "reference tool {} {:?} failed: {}",
        bin.display(),
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write file");
}

#[test]
#[ignore = "requires the reference age CLI; run in the interop lane"]
fn reference_tool_decrypts_a_container_we_wrote() {
    let scratch = Scratch::new("we-write");
    let key = AgeKey::generate().expect("key");
    let identity_file = scratch.file("identity.txt");
    write(&identity_file, key.private_key.as_bytes());

    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let plaintext = b"written by neotales-age, read by the reference tool\n";
    let ciphertext = AgeFile::encrypt(plaintext, &[recipient]).expect("encrypt");

    let container = scratch.file("container.age");
    write(&container, &ciphertext);

    let decrypted = reference(&[
        "-d",
        "-i",
        identity_file.to_str().expect("path"),
        container.to_str().expect("path"),
    ]);

    assert_eq!(
        decrypted, plaintext,
        "reference tool decrypted to different bytes"
    );
}

#[test]
#[ignore = "requires the reference age CLI; run in the interop lane"]
fn we_decrypt_a_container_the_reference_tool_wrote() {
    let scratch = Scratch::new("they-write");
    let key = AgeKey::generate().expect("key");
    let identity_file = scratch.file("identity.txt");
    write(&identity_file, key.private_key.as_bytes());

    let plaintext_file = scratch.file("plaintext.txt");
    let plaintext = b"written by the reference tool, read by neotales-age\n";
    write(&plaintext_file, plaintext);

    let ciphertext = reference(&[
        "-r",
        &key.public_key,
        plaintext_file.to_str().expect("path"),
    ]);

    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let decrypted = AgeFile::decrypt(&ciphertext, &[identity]).expect("decrypt");

    assert_eq!(decrypted, plaintext, "we decrypted to different bytes");
}

#[test]
#[ignore = "requires the reference age CLI; run in the interop lane"]
fn armored_containers_interoperate_in_both_directions() {
    let scratch = Scratch::new("armored");
    let key = AgeKey::generate().expect("key");
    let identity_file = scratch.file("identity.txt");
    write(&identity_file, key.private_key.as_bytes());
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");

    // Our armored output, read by the reference tool.
    let ours = b"armored, written by neotales-age\n";
    let armored =
        AgeFile::encrypt_armored(ours, std::slice::from_ref(&recipient)).expect("encrypt armored");
    let armored_file = scratch.file("container.age");
    write(&armored_file, armored.as_bytes());

    let decrypted = reference(&[
        "-d",
        "-i",
        identity_file.to_str().expect("path"),
        armored_file.to_str().expect("path"),
    ]);
    assert_eq!(decrypted, ours, "reference tool did not read our armor");

    // The reference tool's armored output, read by us.
    let theirs = b"armored, written by the reference tool\n";
    let plaintext_file = scratch.file("plaintext.txt");
    write(&plaintext_file, theirs);
    let their_armored = reference(&[
        "-a",
        "-r",
        &key.public_key,
        plaintext_file.to_str().expect("path"),
    ]);
    let their_armored = String::from_utf8(their_armored).expect("armor is utf-8");

    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let decrypted = AgeFile::decrypt_armored(&their_armored, &[identity]).expect("decrypt armored");
    assert_eq!(decrypted, theirs, "we did not read their armor");
}
