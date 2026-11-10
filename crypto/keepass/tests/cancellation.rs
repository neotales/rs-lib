// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::io::{self, Read};

use neotales_keepass::{
    KdbxCancellation, KdbxCancellationToken, KdbxCredentials, KdbxFailureKind, KdbxFile,
    KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

struct CancellingReader<'a> {
    bytes: &'a [u8],
    token: KdbxCancellationToken,
    calls: usize,
}

impl Read for CancellingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls == 2 {
            self.token.cancel();
        }
        let count = buffer.len().min(3).min(self.bytes.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn cancellation_before_and_during_input_does_not_return_a_database() {
    let limits = KdbxReadLimits::default();
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();

    let token = KdbxCancellationToken::new();
    token.cancel();
    let error = KdbxFile::load_with_cancellation(
        bytes.as_slice(),
        &mut KdbxCredentials::password("pw").unwrap(),
        &limits,
        KdbxCancellation::from_token(&token),
    )
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);

    let token = KdbxCancellationToken::new();
    let reader = CancellingReader {
        bytes: &bytes,
        token: token.clone(),
        calls: 0,
    };
    let error = KdbxFile::load_with_cancellation(
        reader,
        &mut KdbxCredentials::password("pw").unwrap(),
        &limits,
        KdbxCancellation::from_token(&token),
    )
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);

    let loaded = KdbxFile::load_with_cancellation(
        bytes.as_slice(),
        &mut KdbxCredentials::password("pw").unwrap(),
        &limits,
        KdbxCancellation::never(),
    )
    .unwrap();
    assert_eq!(loaded.root.name, "Root");
}
