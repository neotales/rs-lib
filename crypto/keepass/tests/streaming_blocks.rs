// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::io::{self, Read};

use neotales_keepass::{
    Entry, Kdbx4AuthenticatedBlockReader, KdbxCancellation, KdbxCancellationToken, KdbxCredentials,
    KdbxFailureKind, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

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

fn open<'a, R: Read>(
    source: R,
    limits: &KdbxReadLimits,
    cancellation: KdbxCancellation<'a>,
) -> Result<Kdbx4AuthenticatedBlockReader<'a, R>, neotales_keepass::KdbxError> {
    Kdbx4AuthenticatedBlockReader::open(
        source,
        &mut KdbxCredentials::password("pw").unwrap(),
        limits,
        cancellation,
    )
}

#[test]
fn authenticated_blocks_are_incremental_and_finish_consumes_eof() {
    struct Chunked<'a> {
        bytes: &'a [u8],
    }
    impl Read for Chunked<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(3).min(self.bytes.len());
            output[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    let bytes = vault();
    let limits = KdbxReadLimits::default();
    let mut reader = open(
        Chunked { bytes: &bytes },
        &limits,
        KdbxCancellation::never(),
    )
    .unwrap();
    let mut blocks = 0;
    let mut largest_block = 0;
    while let Some(block) = reader.next_block().unwrap() {
        blocks += 1;
        largest_block = largest_block.max(block.len());
    }
    assert!(blocks >= 2, "test vault must contain multiple data blocks");
    assert!(largest_block <= 64);
    assert!(reader.is_fully_authenticated());
    reader.finish().unwrap();
    assert!(reader.next_block().unwrap().is_none());
}

#[test]
fn terminal_hmac_eof_truncation_and_trailing_bytes_are_enforced() {
    let bytes = vault();
    let limits = KdbxReadLimits::default();

    let mut terminal_tamper = bytes.clone();
    terminal_tamper[bytes.len() - 36] ^= 1;
    let mut reader = open(
        terminal_tamper.as_slice(),
        &limits,
        KdbxCancellation::never(),
    )
    .unwrap();
    assert_eq!(
        reader.finish().unwrap_err().kind,
        KdbxFailureKind::Authentication
    );

    let mut truncated = bytes.clone();
    truncated.pop();
    let mut reader = open(truncated.as_slice(), &limits, KdbxCancellation::never()).unwrap();
    assert_eq!(
        reader.finish().unwrap_err().kind,
        KdbxFailureKind::Truncated
    );

    let mut trailing = bytes;
    trailing.push(0);
    let mut reader = open(trailing.as_slice(), &limits, KdbxCancellation::never()).unwrap();
    assert_eq!(
        reader.finish().unwrap_err().kind,
        KdbxFailureKind::Malformed
    );
}

#[test]
fn block_input_and_count_limits_apply_before_unbounded_work() {
    let bytes = vault();

    let block_limits = KdbxReadLimits {
        max_block_bytes: 32,
        ..KdbxReadLimits::default()
    };
    let mut reader = open(bytes.as_slice(), &block_limits, KdbxCancellation::never()).unwrap();
    assert_eq!(
        reader.next_block().unwrap_err().kind,
        KdbxFailureKind::ResourceLimit
    );

    let count_limits = KdbxReadLimits {
        max_blocks: 1,
        ..KdbxReadLimits::default()
    };
    let mut reader = open(bytes.as_slice(), &count_limits, KdbxCancellation::never()).unwrap();
    assert!(reader.next_block().unwrap().is_some());
    assert_eq!(
        reader.next_block().unwrap_err().kind,
        KdbxFailureKind::ResourceLimit
    );

    let input_limits = KdbxReadLimits {
        max_input_bytes: bytes.len() as u64 - 1,
        ..KdbxReadLimits::default()
    };
    let mut reader = open(bytes.as_slice(), &input_limits, KdbxCancellation::never()).unwrap();
    assert_eq!(
        reader.finish().unwrap_err().kind,
        KdbxFailureKind::ResourceLimit
    );
}

#[test]
fn cancellation_at_terminal_eof_does_not_report_full_authentication() {
    struct CancelAtEof<'a> {
        bytes: &'a [u8],
        token: KdbxCancellationToken,
    }
    impl Read for CancelAtEof<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.bytes.len());
            output[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            if count == 0 {
                self.token.cancel();
            }
            Ok(count)
        }
    }

    let bytes = vault();
    let token = KdbxCancellationToken::new();
    let mut reader = open(
        CancelAtEof {
            bytes: &bytes,
            token: token.clone(),
        },
        &KdbxReadLimits::default(),
        KdbxCancellation::from_token(&token),
    )
    .unwrap();
    assert_eq!(
        reader.finish().unwrap_err().kind,
        KdbxFailureKind::Cancelled
    );
    assert!(!reader.is_fully_authenticated());
}
