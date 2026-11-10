// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

//! End-of-stream and framing invariants a future selected-entry scan must retain.
use std::io::{self, Read};

use neotales_keepass::{
    Entry, KdbxCancellation, KdbxCancellationToken, KdbxCredentials, KdbxFailureKind, KdbxFile,
    KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

struct ObserveEof<'a> {
    remaining: &'a [u8],
    eof_seen: &'a mut bool,
}

impl Read for ObserveEof<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.remaining.len());
        output[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        if count == 0 {
            *self.eof_seen = true;
        }
        Ok(count)
    }
}

fn vault() -> Vec<u8> {
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("selected"));
    database.root.entries.push(Entry::new("other"));
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    bytes
}

#[test]
fn successful_load_requires_eof_and_a_complete_input_budget() {
    let bytes = vault();
    let mut eof_seen = false;
    let reader = ObserveEof {
        remaining: &bytes,
        eof_seen: &mut eof_seen,
    };
    let loaded = KdbxFile::load(
        reader,
        &mut KdbxCredentials::password("pw").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert!(eof_seen);
    assert_eq!(loaded.root.entries[0].title, "selected");

    let limits = KdbxReadLimits {
        max_input_bytes: (bytes.len() - 1) as u64,
        ..KdbxReadLimits::default()
    };
    let error = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::ResourceLimit);
}

#[test]
fn terminal_authentication_and_trailing_bytes_are_checked_even_when_entry_exists() {
    let bytes = vault();
    // The writer's last block is the 36-byte authenticated empty terminal block.
    let mut bad_terminal = bytes.clone();
    bad_terminal[bytes.len() - 36] ^= 1;
    let error = KdbxFile::load_password(bad_terminal.as_slice(), "pw", &KdbxReadLimits::default())
        .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Authentication);

    let mut trailing = bytes;
    trailing.push(0);
    assert!(
        KdbxFile::load_password(trailing.as_slice(), "pw", &KdbxReadLimits::default()).is_err()
    );
}

#[test]
fn cancellation_at_eof_prevents_returning_a_selected_entry() {
    struct CancelAtEof<'a> {
        remaining: &'a [u8],
        token: KdbxCancellationToken,
    }
    impl Read for CancelAtEof<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.remaining.len());
            output[..count].copy_from_slice(&self.remaining[..count]);
            self.remaining = &self.remaining[count..];
            if count == 0 {
                self.token.cancel();
            }
            Ok(count)
        }
    }
    let bytes = vault();
    let token = KdbxCancellationToken::new();
    let error = KdbxFile::load_with_cancellation(
        CancelAtEof {
            remaining: &bytes,
            token: token.clone(),
        },
        &mut KdbxCredentials::password("pw").unwrap(),
        &KdbxReadLimits::default(),
        KdbxCancellation::from_token(&token),
    )
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);
}
