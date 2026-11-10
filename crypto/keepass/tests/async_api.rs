// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::future::Future;
use std::io;
use std::task::{Context, Poll, Waker};

use neotales_keepass::{
    KdbxAsyncRead, KdbxAsyncWrite, KdbxCancellation, KdbxCancellationToken, KdbxCredentials,
    KdbxFailureKind, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

fn drive<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    for _ in 0..100_000 {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
    panic!("future did not complete");
}

fn vault() -> Vec<u8> {
    let mut output = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut output,
        &mut KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    output
}

struct ChunkReader<'a> {
    bytes: &'a [u8],
    position: usize,
    pending_once: bool,
    eof_seen: bool,
    cancel_at_eof: Option<KdbxCancellationToken>,
}

impl<'a> ChunkReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            pending_once: true,
            eof_seen: false,
            cancel_at_eof: None,
        }
    }
}

impl KdbxAsyncRead for ChunkReader<'_> {
    fn poll_read(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.pending_once {
            self.pending_once = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.position == self.bytes.len() {
            self.eof_seen = true;
            if let Some(token) = &self.cancel_at_eof {
                token.cancel();
            }
            return Poll::Ready(Ok(0));
        }
        let count = buffer.len().min(3).min(self.bytes.len() - self.position);
        buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(count))
    }
}

struct PartialWriter {
    bytes: Vec<u8>,
    pending_write_once: bool,
    pending_flush_once: bool,
    flushes: usize,
}

impl PartialWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            pending_write_once: true,
            pending_flush_once: true,
            flushes: 0,
        }
    }
}

impl KdbxAsyncWrite for PartialWriter {
    fn poll_write(&mut self, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        if self.pending_write_once {
            self.pending_write_once = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = buffer.len().min(2);
        self.bytes.extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush_once {
            self.pending_flush_once = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }
}

struct CancelAfterWrite {
    bytes: Vec<u8>,
    token: KdbxCancellationToken,
    cancelled: bool,
    flushes: usize,
}

impl KdbxAsyncWrite for CancelAfterWrite {
    fn poll_write(&mut self, _cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let count = buffer.len().min(2);
        self.bytes.extend_from_slice(&buffer[..count]);
        if !self.cancelled {
            self.cancelled = true;
            self.token.cancel();
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn async_load_reads_in_chunks_requires_eof_and_preserves_auth_and_limit_errors() {
    let bytes = vault();
    let mut reader = ChunkReader::new(&bytes);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let loaded = drive(KdbxFile::load_async(
        &mut reader,
        &mut credentials,
        &KdbxReadLimits::default(),
        KdbxCancellation::never(),
    ))
    .unwrap();
    assert!(reader.eof_seen);
    assert_eq!(loaded.root.name, "Root");

    let mut truncated = ChunkReader::new(&bytes[..bytes.len() - 1]);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::load_async(
        &mut truncated,
        &mut credentials,
        &KdbxReadLimits::default(),
        KdbxCancellation::never(),
    ))
    .unwrap_err();
    assert!(truncated.eof_seen);
    assert_eq!(error.kind, KdbxFailureKind::Truncated);

    let mut tampered_bytes = bytes.clone();
    tampered_bytes[bytes.len() - 36] ^= 1;
    let mut tampered = ChunkReader::new(&tampered_bytes);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::load_async(
        &mut tampered,
        &mut credentials,
        &KdbxReadLimits::default(),
        KdbxCancellation::never(),
    ))
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Authentication);

    let limits = KdbxReadLimits {
        max_input_bytes: (bytes.len() - 1) as u64,
        ..KdbxReadLimits::default()
    };
    let mut over_limit = ChunkReader::new(&bytes);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::load_async(
        &mut over_limit,
        &mut credentials,
        &limits,
        KdbxCancellation::never(),
    ))
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::ResourceLimit);

    let invalid_limits = KdbxReadLimits {
        max_input_bytes: 0,
        ..KdbxReadLimits::default()
    };
    let mut never_read = ChunkReader::new(&bytes);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::load_async(
        &mut never_read,
        &mut credentials,
        &invalid_limits,
        KdbxCancellation::never(),
    ))
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::InvalidArgument);
    assert!(!never_read.eof_seen);
}

#[test]
fn async_load_observes_cancellation_at_eof() {
    let bytes = vault();
    let token = KdbxCancellationToken::new();
    let mut reader = ChunkReader::new(&bytes);
    reader.cancel_at_eof = Some(token.clone());
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::load_async(
        &mut reader,
        &mut credentials,
        &KdbxReadLimits::default(),
        KdbxCancellation::from_token(&token),
    ))
    .unwrap_err();
    assert!(reader.eof_seen);
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);
}

#[test]
fn async_save_handles_partial_writes_and_flushes_before_completing() {
    let mut writer = PartialWriter::new();
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    drive(KdbxFile::save_async(
        &KeePassDatabase::default(),
        &mut writer,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
        KdbxCancellation::never(),
    ))
    .unwrap();
    assert_eq!(writer.flushes, 1);
    let loaded =
        KdbxFile::load_password(writer.bytes.as_slice(), "pw", &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.root.name, "Root");
}

#[test]
fn async_save_cancellation_after_partial_write_is_reported_without_flush() {
    let token = KdbxCancellationToken::new();
    let mut writer = CancelAfterWrite {
        bytes: Vec::new(),
        token: token.clone(),
        cancelled: false,
        flushes: 0,
    };
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::save_async(
        &KeePassDatabase::default(),
        &mut writer,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
        KdbxCancellation::from_token(&token),
    ))
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);
    assert!(!writer.bytes.is_empty());
    assert_eq!(writer.flushes, 0);
}

#[test]
fn async_save_cancellation_before_encoding_writes_nothing() {
    let token = KdbxCancellationToken::new();
    token.cancel();
    let mut writer = PartialWriter::new();
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = drive(KdbxFile::save_async(
        &KeePassDatabase::default(),
        &mut writer,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
        KdbxCancellation::from_token(&token),
    ))
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);
    assert!(writer.bytes.is_empty());
    assert_eq!(writer.flushes, 0);
}
