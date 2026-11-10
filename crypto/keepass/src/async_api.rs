//! Runtime-neutral, poll-based transport boundaries for KDBX operations.
//!
//! These traits deliberately do not implement [`std::io::Read`] or
//! [`std::io::Write`]. A transport adapter must call its runtime's readiness
//! API from these methods and return [`Poll::Pending`] without blocking. The
//! KDBX futures therefore never turn a blocking transport operation into an
//! asynchronous one.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::cancellation::KdbxCancellation;
use crate::credentials::KdbxCredentials;
use crate::error::{KdbxError, KdbxFailureKind};
use crate::file::{KdbxFile, KdbxWriteOptions};
use crate::limits::KdbxReadLimits;
use crate::model::KeePassDatabase;

/// A non-blocking, runtime-neutral byte reader used by asynchronous KDBX load.
///
/// Implementations are responsible for arranging a wakeup whenever a
/// previously returned [`Poll::Pending`] can make progress. They must not block
/// in `poll_read`. `Ok(0)` means end-of-file; it is not an error and is always
/// observed before a KDBX operation can return successfully.
pub trait KdbxAsyncRead {
    /// Attempts to read bytes into `buffer` without blocking.
    fn poll_read(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>>;
}

/// A non-blocking, runtime-neutral byte writer used by asynchronous KDBX save.
///
/// Implementations are responsible for arranging a wakeup whenever a
/// previously returned [`Poll::Pending`] can make progress. They must not block
/// in `poll_write` or `poll_flush`. A successful save calls `poll_flush` after
/// all bytes have been accepted; it does not imply that the destination has
/// been closed.
pub trait KdbxAsyncWrite {
    /// Attempts to accept bytes without blocking.
    fn poll_write(&mut self, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>>;

    /// Attempts to flush accepted bytes without blocking.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// A future returned by [`KdbxFile::load_async`].
///
/// The future uses bounded storage for the complete KDBX input, then invokes
/// the existing authenticated decoder. Transport I/O is poll-driven and does
/// not call a blocking [`std::io::Read`] method. The KDF, codec, and XML
/// stages remain synchronous; callers needing to keep an executor thread
/// responsive during those CPU stages must schedule the future accordingly.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `input` is the complete KDBX
/// document in the bounded buffer, and `credentials` points at the master
/// password; a derived `Debug` would print the first and dereference into the
/// second. `R` is the caller's transport, and putting an `R: Debug` bound here
/// would make this type unusable with the tokio, smol, or hand-rolled
/// transports a caller may have chosen for their own reasons — the future holds
/// a `&mut R`, and how a caller implements `KdbxAsyncRead` has nothing to do
/// with whether it is printable. The progress fields are what a caller polling
/// a stuck load needs: the stage the future is in, how much has been buffered,
/// and whether the header has been validated. `cancellation` is delegated to,
/// which is safe because its own `Debug` reports the kind of check rather than
/// a caller's closure.
#[must_use = "futures do nothing unless polled"]
pub struct KdbxLoadFuture<'a, R: KdbxAsyncRead + ?Sized> {
    source: &'a mut R,
    credentials: &'a mut KdbxCredentials,
    limits: &'a KdbxReadLimits,
    cancellation: KdbxCancellation<'a>,
    input: Vec<u8>,
    validated: bool,
    state: LoadState,
}

impl<R: KdbxAsyncRead + ?Sized> fmt::Debug for KdbxLoadFuture<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note there is no `R: Debug` bound. `source` is the caller's
        // transport, `input` is the buffered KDBX document, and `credentials`
        // points at the master password; none of the three is printed.
        formatter
            .debug_struct("KdbxLoadFuture")
            .field("state", &self.state)
            .field("buffered", &self.input.len())
            .field("validated", &self.validated)
            .field("cancellation", &self.cancellation)
            .finish_non_exhaustive()
    }
}

// `Debug` is needed by `KdbxLoadFuture`'s hand-written `Debug`, which reports
// the stage. It is a private type, so `missing_debug_implementations` does not
// ask for it, and the derive is safe: three fieldless variants and no state.
#[derive(Debug)]
enum LoadState {
    Reading,
    Decoding,
    Complete,
}

impl<'a, R: KdbxAsyncRead + ?Sized> KdbxLoadFuture<'a, R> {
    pub(crate) fn new(
        source: &'a mut R,
        credentials: &'a mut KdbxCredentials,
        limits: &'a KdbxReadLimits,
        cancellation: KdbxCancellation<'a>,
    ) -> Self {
        Self {
            source,
            credentials,
            limits,
            cancellation,
            input: Vec::new(),
            validated: false,
            state: LoadState::Reading,
        }
    }
}

impl<R: KdbxAsyncRead + ?Sized> Future for KdbxLoadFuture<'_, R> {
    type Output = Result<KeePassDatabase, KdbxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.validated {
                if let Err(error) = this.cancellation.checkpoint() {
                    return Poll::Ready(Err(error));
                }
                if let Err(error) = this.limits.validate() {
                    return Poll::Ready(Err(error));
                }
                this.validated = true;
            }
            if let Err(error) = this.cancellation.checkpoint() {
                return Poll::Ready(Err(error));
            }
            match this.state {
                LoadState::Reading => {
                    let remaining = this
                        .limits
                        .max_input_bytes
                        .saturating_sub(this.input.len() as u64);
                    let request_len = (remaining.saturating_add(1)).min(8192) as usize;
                    let mut chunk = [0_u8; 8192];
                    let result = this.source.poll_read(cx, &mut chunk[..request_len]);
                    let count = match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(read_error(error)));
                        }
                        Poll::Ready(Ok(count)) => count,
                    };
                    if let Err(error) = this.cancellation.checkpoint() {
                        return Poll::Ready(Err(error));
                    }
                    if count > request_len {
                        return Poll::Ready(Err(KdbxError::new(
                            KdbxFailureKind::Malformed,
                            "KDBX async reader returned an invalid byte count",
                        )));
                    }
                    if count == 0 {
                        this.state = LoadState::Decoding;
                        continue;
                    }
                    if count as u64 > remaining {
                        return Poll::Ready(Err(KdbxError::resource_limit(
                            "KDBX input exceeds the configured limit",
                        )));
                    }
                    this.input.extend_from_slice(&chunk[..count]);
                }
                LoadState::Decoding => {
                    let input = std::mem::take(&mut this.input);
                    let result = KdbxFile::load_with_cancellation(
                        input.as_slice(),
                        this.credentials,
                        this.limits,
                        this.cancellation,
                    );
                    this.state = LoadState::Complete;
                    return Poll::Ready(result);
                }
                LoadState::Complete => {
                    panic!("KDBX load future polled after completion");
                }
            }
        }
    }
}

/// A future returned by [`KdbxFile::save_async`].
///
/// The KDBX document is encoded into a complete intermediate buffer before any
/// bytes are submitted to the asynchronous destination. This keeps
/// cancellation and encoding errors from leaving a partially encoded stream,
/// but it does not provide a transactional destination. A write, flush, or
/// cancellation error may leave bytes already accepted by the destination.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `encoded` is the complete
/// encoded KDBX document, `database` points at every entry in the vault, and
/// `credentials` points at the master password. `W` is the caller's
/// destination, and an `W: Debug` bound here would tax the caller for this
/// crate's sake: the future holds a `&mut W` and a destination has no reason to
/// be printable. The reported fields are the ones that describe a save that is
/// not finishing — the stage, how much is encoded, and how much of that has
/// been written.
#[must_use = "futures do nothing unless polled"]
pub struct KdbxSaveFuture<'a, W: KdbxAsyncWrite + ?Sized> {
    database: &'a KeePassDatabase,
    destination: &'a mut W,
    credentials: &'a mut KdbxCredentials,
    options: KdbxWriteOptions,
    limits: &'a KdbxReadLimits,
    cancellation: KdbxCancellation<'a>,
    encoded: Vec<u8>,
    position: usize,
    state: SaveState,
}

impl<W: KdbxAsyncWrite + ?Sized> fmt::Debug for KdbxSaveFuture<'_, W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note there is no `W: Debug` bound. `destination` is the caller's
        // sink, `encoded` is the encoded vault, and `database` and
        // `credentials` are borrowed secrets; none of the four is printed.
        formatter
            .debug_struct("KdbxSaveFuture")
            .field("state", &self.state)
            .field("encoded", &self.encoded.len())
            .field("position", &self.position)
            .field("cancellation", &self.cancellation)
            .finish_non_exhaustive()
    }
}

// As with `LoadState`, `Debug` exists for `KdbxSaveFuture`'s hand-written
// `Debug` and is safe: fieldless variants, no state.
#[derive(Debug)]
enum SaveState {
    Encoding,
    Writing,
    Flushing,
    Complete,
}

impl<'a, W: KdbxAsyncWrite + ?Sized> KdbxSaveFuture<'a, W> {
    pub(crate) fn new(
        database: &'a KeePassDatabase,
        destination: &'a mut W,
        credentials: &'a mut KdbxCredentials,
        options: KdbxWriteOptions,
        limits: &'a KdbxReadLimits,
        cancellation: KdbxCancellation<'a>,
    ) -> Self {
        Self {
            database,
            destination,
            credentials,
            options,
            limits,
            cancellation,
            encoded: Vec::new(),
            position: 0,
            state: SaveState::Encoding,
        }
    }
}

impl<W: KdbxAsyncWrite + ?Sized> Future for KdbxSaveFuture<'_, W> {
    type Output = Result<(), KdbxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        loop {
            if let Err(error) = this.cancellation.checkpoint() {
                return Poll::Ready(Err(error));
            }
            match this.state {
                SaveState::Encoding => {
                    let mut encoded = Vec::new();
                    let result = KdbxFile::save_with_cancellation(
                        this.database,
                        &mut encoded,
                        this.credentials,
                        this.options,
                        this.limits,
                        this.cancellation,
                    );
                    match result {
                        Ok(()) => {
                            this.encoded = encoded;
                            this.position = 0;
                            this.state = SaveState::Writing;
                        }
                        Err(error) => {
                            this.state = SaveState::Complete;
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                SaveState::Writing => {
                    if this.position == this.encoded.len() {
                        this.state = SaveState::Flushing;
                        continue;
                    }
                    let remaining = this.encoded.len() - this.position;
                    let result = this
                        .destination
                        .poll_write(cx, &this.encoded[this.position..this.position + remaining]);
                    let count = match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(write_error(error))),
                        Poll::Ready(Ok(count)) => count,
                    };
                    if let Err(error) = this.cancellation.checkpoint() {
                        return Poll::Ready(Err(error));
                    }
                    if count == 0 || count > remaining {
                        return Poll::Ready(Err(KdbxError::new(
                            KdbxFailureKind::Malformed,
                            "KDBX async writer made invalid write progress",
                        )));
                    }
                    this.position += count;
                }
                SaveState::Flushing => match this.destination.poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(write_error(error))),
                    Poll::Ready(Ok(())) => {
                        if let Err(error) = this.cancellation.checkpoint() {
                            return Poll::Ready(Err(error));
                        }
                        this.state = SaveState::Complete;
                        return Poll::Ready(Ok(()));
                    }
                },
                SaveState::Complete => {
                    panic!("KDBX save future polled after completion");
                }
            }
        }
    }
}

fn read_error(_: io::Error) -> KdbxError {
    KdbxError::new(KdbxFailureKind::Truncated, "unable to read KDBX input")
}

fn write_error(_: io::Error) -> KdbxError {
    KdbxError::new(KdbxFailureKind::Malformed, "KDBX stream I/O failed")
}
