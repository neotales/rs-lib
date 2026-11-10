//! The container logs endpoint, including the Engine's multiplexed framing.
//!
//! `/containers/{id}/logs` is the one streaming endpoint whose body is *not*
//! free-form bytes. When the container has no TTY the daemon wraps every write
//! in an eight-byte header, and a client that forwards the body without
//! decoding it emits the header as visible garbage. Decoding that framing is
//! the substance of this module, and it is the reason a client cannot be
//! replaced by a thin HTTP wrapper.
//!
//! # The framing, exactly
//!
//! For a container without a TTY each frame on the wire is:
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | stream | 0      | 0      | 0      | length (big-endian u32)      |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | payload: `length` bytes                                            |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! ```
//!
//! `stream` is `0` for stdin, `1` for stdout, and `2` for stderr. Bytes 1
//! through 3 are always zero. The length covers the payload only, never the
//! header. The daemon sends this inside an HTTP response that is itself
//! chunked, so the transport layer and the framing layer are separate concerns:
//! `hyper` decodes the chunking, and [`LogDecoder`] decodes the frames.
//!
//! For a container *with* a TTY the daemon sends the container's output
//! verbatim, with no header at all, because a terminal cannot be interleaved.
//! The endpoint itself does not say which of the two it is doing — that is a
//! property of the container, from `GET /containers/{id}/json` — so a caller
//! must state it. Guessing from the first bytes is not safe: a TTY container
//! is entirely free to begin with a NUL, which is indistinguishable from a
//! header.
//!
//! # Bytes, not text
//!
//! Frame payloads are bytes. A container writing to stdout is not producing
//! text, and a log reader that assumes UTF-8 either loses data or refuses to
//! return. Nothing here decodes, normalizes, or line-splits: `length` counts
//! bytes on the wire and so does this module.
//!
//! # What one frame is allowed to cost
//!
//! The length in a header is a number the daemon wrote, and a number a peer
//! chooses is not a bound. [`LogDecoder`] refuses a frame that declares more
//! than [`MAX_FRAME_BYTES`] of payload, at the moment the header is parsed and
//! before one byte of that payload is buffered, so what a log stream holds for
//! a frame the daemon has not finished sending is this client's decision rather
//! than the peer's. That constant says what the bound is and why it is not a
//! tighter one.
//!
//! It is a bound on a *multiplexed* frame. A TTY body has no header and so no
//! declared length to check, and a console frame is bounded only by the size of
//! the read that carried it. That asymmetry follows from the wire format rather
//! than from a gap in the check, and [`MAX_FRAME_BYTES`] says so where a caller
//! will look for it.

use bytes::{Bytes, BytesMut};
use hyper::Method;

use crate::Error;
use crate::raw::body::{FrameStream, MAX_RECORD_BYTES};
use crate::raw::containers::{Query, container_path, with_query};
use crate::raw::transport::{RawEngine, RawRequest, engine_result};

/// The number of bytes in one multiplexed frame header.
pub const FRAME_HEADER_BYTES: usize = 8;

/// The largest payload [`LogDecoder`] will assemble for one **multiplexed**
/// frame.
///
/// # It bounds a framed frame, and a TTY body has no frames
///
/// The constant is a bound on a *multiplexed frame's payload*, and it is worth
/// being precise about what that leaves out, because a reader who takes the name
/// at face value will draw the wrong conclusion about where the memory goes.
///
/// A container with a TTY is unframed: the daemon writes its output verbatim,
/// with no header, so there is no declared length and nothing to check the
/// length of. [`LogStream::Console`] frames are whatever arrived since the last
/// read, and this constant does not apply to them — a `LogDecoder` built with
/// `new(true)` never refuses a frame for size, and a caller reading a TTY log
/// is bounded by the size of a single transport read rather than by this number.
/// That is a deliberate consequence of the wire format and not a gap in the
/// check: the bound exists to stop a peer *declaring* an enormous length, and an
/// unframed peer declares nothing. It is stated here rather than left to be
/// discovered, because "the decoder bounds frames" reads as a bound on the
/// decoder's memory use, and on a TTY body it is not one.
///
/// A caller that wants a bound on a console frame's size has to impose it
/// downstream, on what it does with each [`LogFrame`]; this module cannot, for
/// the same reason it cannot impose one on a frame that arrives whole in a
/// single read.
///
/// # Why a frame needs a bound
///
/// The length in a header is the one number in a frame this client cannot
/// check, and it is the one the peer picks for free. A decoder that records the
/// length and then waits for that many bytes has made the daemon's `u32` the
/// ceiling on this client's heap: a peer that declared four gigabytes and then
/// kept writing would grow the buffer by that much without ever sending a frame,
/// and a caller running one `follow` stream per container multiplies it by the
/// number of containers. Declaring a length costs nothing; delivering it is the
/// expensive part, which is why the length is where the check has to be.
///
/// The check is on the *declared* length, when the header is parsed and before
/// a single payload byte is taken. A decoder that buffered first and measured
/// afterwards would have allocated the whole oversized frame before refusing it,
/// which is the same unbounded allocation with a check attached to its end.
///
/// # Why this number, and not a tighter one
///
/// [`MAX_RECORD_BYTES`] — the bound this crate already holds one `stats` or
/// `events` record to — rather than a smaller number chosen for frames. A frame
/// is one write a container made, so a real daemon's frames are far smaller than
/// this in practice and a tighter bound would be easy to pick. The reason not to
/// is the one [`MAX_RECORD_BYTES`] documents at length: a previous bound of
/// 4 MiB refused a real 4,195,572-byte `exec_create` record, and the lesson was
/// that a bound which cannot tell a legitimate frame from a hostile one is not a
/// defence, it is a guess that happens to be cheap. Having one number for "what
/// this client will buffer for one thing a peer says is one thing" also leaves
/// one number to reason about and one to change.
///
/// # A frame of exactly this many bytes is read
///
/// One byte more is refused. The check is on the declared length and not on what
/// has arrived, so it does not matter how the frame was divided among reads: a
/// frame split into a thousand reads is held to the same bound as one delivered
/// whole, and a read carrying fifty small frames is fifty small frames rather
/// than one oversized one.
///
/// # Refusal ends the body, and that is deliberate
///
/// An over-long frame is an error rather than a skip, and the alternative was
/// rejected on purpose. Recovering would mean finding where the refused frame
/// ends — which means taking the length just refused on faith as a count to
/// throw away, and letting a peer that declared `u32::MAX` keep this client
/// reading and discarding bytes indefinitely. Skipping only the header is not an
/// option either: the bytes behind it are that frame's payload, and reading them
/// as a header is how a decoder ends up emitting plausible-looking garbage for
/// the rest of the transfer.
///
/// So the refusal is final for the body. [`LogDecoder`] stops taking bytes,
/// drops what it was holding, and reports the same refusal — same
/// [`ErrorKind`](crate::ErrorKind), same cause — on every later call. A caller
/// that keeps polling therefore cannot grow a buffer behind a stream that will
/// never decode again, and it is told the same thing each time rather than a
/// generic "already refused" that names a different cause than the one it hit.
/// Failing at the header bounds the memory and the time, and leaves the caller
/// with an error it can report instead of a log that silently stopped.
///
/// It does not mean the frames *before* the refused one are lost. One transport
/// read can complete several frames and then carry the one this client refuses,
/// and [`LogDecoder::push`] returns the frames it completed; the refusal is
/// reported by the call after.
pub const MAX_FRAME_BYTES: usize = MAX_RECORD_BYTES;

/// Options for `GET /containers/{id}/logs`, in the Engine's own types.
///
/// The `since` and `until` bounds are signed 64-bit Unix timestamps because
/// that is what the Engine's `OpenAPI` specification declares. The narrower type
/// that some generated clients use is a truncation of the specification, and it
/// silently caps every timestamp a caller can express at 2038-01-19. Reading
/// the value as `i64` here keeps the owned backend from inheriting that limit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerLogOptions {
    /// Keep the response open and stream logs as they are written.
    pub follow: bool,
    /// Include standard output.
    pub stdout: bool,
    /// Include standard error.
    pub stderr: bool,
    /// Return logs at or after this Unix timestamp in seconds; zero for no bound.
    pub since: i64,
    /// Return logs before this Unix timestamp in seconds; zero for no bound.
    pub until: i64,
    /// Prefix each log line with an RFC 3339 timestamp.
    pub timestamps: bool,
    /// Number of trailing lines to return, or `all`.
    pub tail: String,
    /// Whether the container was created with a TTY.
    ///
    /// The endpoint cannot report this, and it changes how the body must be
    /// read, so it is the caller's answer — normally from an inspect — rather
    /// than a guess. A TTY body is returned verbatim as [`LogStream::Console`];
    /// a non-TTY body is decoded into [`LogStream::Stdout`] and
    /// [`LogStream::Stderr`] frames. Saying this wrongly is visible as
    /// corrupted output rather than as an error, so it is stated rather than
    /// inferred.
    pub tty: bool,
}

impl Default for ContainerLogOptions {
    /// Defaults to a non-TTY container with both streams selected and no bounds.
    ///
    /// `stdout` and `stderr` default to true here, unlike the generated clients
    /// which default both to false and therefore return an empty body unless
    /// the caller asks for a stream explicitly. A logs call that returns nothing
    /// because nobody set a flag reads as "the container logged nothing", which
    /// is a different and wrong conclusion.
    fn default() -> Self {
        Self {
            follow: false,
            stdout: true,
            stderr: true,
            since: 0,
            until: 0,
            timestamps: false,
            tail: "all".to_owned(),
            tty: false,
        }
    }
}

impl ContainerLogOptions {
    /// Declares whether the container was created with a TTY.
    #[must_use]
    pub const fn with_tty(mut self, tty: bool) -> Self {
        self.tty = tty;
        self
    }
}

/// Which stream one frame of container output came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogStream {
    /// Standard input. The Engine multiplexes it on the same wire format but
    /// never writes it to a container's log, so it is reachable only from an
    /// attach-style endpoint.
    Stdin,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// Unframed output from a container with a TTY.
    ///
    /// A TTY merges the two streams into one, so there is nothing to
    /// demultiplex and the payload is the container's output exactly as written.
    ///
    /// "Exactly as written" includes the size: one console frame is whatever the
    /// transport delivered since the last read, with no declared length behind it
    /// and so no [`MAX_FRAME_BYTES`] check. [`LogDecoder::new`] takes the TTY
    /// flag rather than inferring it, because a body that begins with NUL is
    /// indistinguishable from a header — the one case where guessing would be
    /// most confidently wrong.
    Console,
}

impl LogStream {
    /// Returns whether the frame came from a multiplexed rather than a TTY body.
    #[must_use]
    pub const fn is_multiplexed(self) -> bool {
        !matches!(self, Self::Console)
    }
}

/// One frame of decoded container output.
///
/// `Debug` is hand-written rather than derived, because `payload` is the
/// container's own stdout and a derive renders it as a decimal byte list —
/// the one form a search for the payload as text would miss. The payload is
/// still a public field and still returned by value: redaction is a property of
/// the *formatting*, not a change to what a caller can read, and a caller that
/// wants the bytes has [`Self::payload`].
///
/// The same reasoning applies to
/// [`ContainerLogFrame`](crate::ContainerLogFrame), the Bollard-backed spelling
/// of this shape, and the two are kept in step deliberately. Leaving one of them
/// derived would mean the same bytes were redacted on one path and printed on
/// the other depending on which transport a caller happened to configure.
#[derive(Clone, Eq, PartialEq)]
pub struct LogFrame {
    /// Which stream this frame came from.
    pub stream: LogStream,
    /// The payload bytes, with any frame header removed.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for LogFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogFrame")
            .field("stream", &self.stream)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl LogFrame {
    /// Creates a typed frame.
    #[must_use]
    pub const fn new(stream: LogStream, payload: Vec<u8>) -> Self {
        Self { stream, payload }
    }
}

/// Turns a log body into frames, one network read at a time.
///
/// The decoder is separated from the transport because the interesting
/// behaviour is how it handles reads that do not line up with frames, and that
/// has to be testable without a socket. A single read may contain half a
/// header, three whole frames, or the end of one payload and the start of the
/// next header; every one of those must produce the same frames as a body
/// delivered one byte at a time.
///
/// # Two buffers, and not one that is drained
///
/// The shape that reads a whole transport read into a `Vec` and takes frames
/// off the front looks simpler and is quadratic twice over. Taking bytes off the
/// front of a `Vec` relocates everything behind them, so a read carrying *n*
/// frames moves the remaining bytes *n* times; and re-joining a partly arrived
/// payload to the next read copies what is already buffered, so a frame split
/// across *k* reads moves its own bytes *k* times. The arithmetic is quadratic
/// in the frame count and in the reads a frame took, so there is no read size at
/// which it is cheap.
///
/// Neither happens here, and the two buffers are why. `ready` holds the frames
/// the last read already carried whole, and they come out of it by
/// [`Bytes::split_to`] — a pointer bump — and the transport's own bytes are
/// sliced rather than copied. `partial` holds only the one frame the
/// daemon has not finished sending, and it is appended to as reads arrive, so a
/// frame split into a thousand reads is copied once. It is the only buffer this
/// crate grows, and it is the only one the bound has to cap, because it is the
/// only one whose length the peer decides.
///
/// What is left is one copy per frame — the payload into the
/// [`LogFrame::payload`] a caller is handed — and that copy cannot be avoided
/// while the payload is a public `Vec<u8>` rather than a view.
#[derive(Clone)]
pub struct LogDecoder {
    /// Payload bytes of a frame the daemon has not finished sending.
    ///
    /// Appended to as reads arrive, so each read costs one copy of the bytes it
    /// brought and none of the bytes already held. In multiplexed mode it never
    /// exceeds [`MAX_FRAME_BYTES`], because `decode` refuses the declared length
    /// before one byte of it is taken. TTY mode has no declared frame length and
    /// holds one transport read at a time; that path has no `MAX_FRAME_BYTES` cap.
    partial: Vec<u8>,
    /// Whole frames the last read carried, not yet handed over.
    ///
    /// The transport's own [`Bytes`], sliced rather than copied, so holding them
    /// costs a refcount rather than a second copy of the read. A frame is taken
    /// with `split_to`, which moves a pointer; taking one out of a `Vec` instead
    /// relocates every byte behind it, and that is what makes the shape quadratic
    /// in the number of frames a single read happened to carry.
    ready: Bytes,
    /// The stream the buffered header selected, held across reads.
    stream: LogStream,
    /// Payload length the buffered header promised, or `None` when the next
    /// bytes to read are a header.
    expected: Option<usize>,
    /// Whether the body is unframed TTY output.
    tty: bool,
    /// Why this body was refused, and the error every later call reports.
    ///
    /// A refused frame desynchronizes the byte stream: the bytes behind its
    /// header are that frame's payload, and reading them as a header is how a
    /// decoder ends up emitting plausible-looking garbage — the one outcome this
    /// module argues against at length. So once a frame has been refused the
    /// decoder keeps saying so and stops taking bytes, rather than growing a
    /// buffer behind a stream that can never decode again. A caller that wants
    /// another stream opens another one; the caller drops this stream to drop its
    /// connection.
    ///
    /// The *cause* is kept rather than the [`Error`], because the two refusals
    /// this module makes are different failures with different classes and
    /// different messages, and a repeat that reported both as one generic
    /// refusal would answer a question nobody asked: which of them happened.
    /// [`Refusal::error`] builds the same error from the same data every time,
    /// so the first report and every later one are the same failure rather than
    /// two descriptions of it.
    ///
    /// One field rather than a latch plus a "not yet reported" flag: a body that
    /// was refused while [`Self::drain_frames`] was holding frames it had already
    /// decoded needs no separate pending error, because the *next* call reading
    /// this field reports the identical error whether it is the one that deferred
    /// or the tenth one after. A second copy of the message stored alongside the
    /// cause would be one more thing that could disagree with it.
    refusal: Option<Refusal>,
}

impl std::fmt::Debug for LogDecoder {
    /// Reports the framing state and how much is buffered, and no payload.
    ///
    /// A `#[derive(Debug)]` here compiles and leaks, and it is the one type in
    /// this module a derive gets wrong on its own: `partial` and `ready` hold the
    /// container's own stdout — one mid-frame, one whole frames the caller has not
    /// been given yet — for frames no caller can see through any other door. A
    /// derived impl renders them as a decimal byte list, which is the form a
    /// search for the payload as text would miss, and this type is `pub` —
    /// re-exported from [`crate::raw`] — so the leak reaches a consumer's panic
    /// message and log line, not only this crate's.
    ///
    /// What is printed instead is what a caller diagnosing a stalled log needs
    /// and cannot otherwise get: which stream the buffered header selected, how
    /// many payload bytes it promised, whether the body is framed at all, and
    /// how many bytes have arrived without yet forming a frame. The count is
    /// what distinguishes "waiting for a slow container" from "truncated", and
    /// the promised length is what says whether the buffer is mid-header or
    /// mid-payload.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogDecoder")
            .field("stream", &self.stream)
            .field("expected", &self.expected)
            .field("tty", &self.tty)
            .field("refused", &self.refusal)
            .field("buffered", &self.buffered())
            .finish_non_exhaustive()
    }
}

impl LogDecoder {
    /// Creates a decoder for a body in the framing `tty` selects.
    #[must_use]
    pub const fn new(tty: bool) -> Self {
        Self {
            partial: Vec::new(),
            ready: Bytes::new(),
            stream: LogStream::Console,
            expected: None,
            tty,
            refusal: None,
        }
    }

    /// How many bytes have arrived but not yet become a frame.
    ///
    /// Crate-internal because the number is a diagnostic and the bytes are not:
    /// this is what the `Debug` impls of [`LogFrames`] and
    /// [`SwarmLogFrames`](crate::raw::SwarmLogFrames) report in place of the
    /// buffer itself, and neither can read a private field of a type in another
    /// module.
    ///
    /// The header of a frame already parsed counts even though it has left
    /// `ready`: it has not become a frame either, and counting it is what makes
    /// the number say "mid-payload" rather than "waiting for a header".
    pub(crate) const fn buffered(&self) -> usize {
        self.partial.len()
            + self.ready.len()
            + if self.expected.is_some() {
                FRAME_HEADER_BYTES
            } else {
                0
            }
    }

    /// Whether this decoder is reading unframed TTY output.
    pub(crate) const fn is_tty(&self) -> bool {
        self.tty
    }

    /// Records the cause this body was refused for and releases what it holds.
    ///
    /// The buffers are dropped rather than emptied, which is the point of the
    /// call. `ready` is a [`Bytes`] slice of the transport's own allocation and,
    /// in multiplexed mode, `partial` is at most [`MAX_FRAME_BYTES`] of assembled
    /// payload. Neither is readable any more, because the bytes behind a refused header *are* that
    /// frame's payload and this decoder will not parse them as framing. Holding
    /// them pins memory for the rest of the stream's life — which, after a
    /// refusal, is however long the caller chooses to hold a dead handle. It is
    /// bounded, and it is bounded on the wrong side of the refusal: the caller
    /// pays for the whole partial frame and gets nothing for it.
    ///
    /// Emptying them would keep the allocation, which is the same pinning with
    /// a friendlier-looking [`Self::buffered`].
    fn latch(&mut self, refusal: Refusal) {
        self.refusal = Some(refusal);
        self.ready = Bytes::new();
        self.partial = Vec::new();
        self.expected = None;
    }

    /// Moves what is left of the last read into the buffer the frame in progress
    /// is assembled in, and reports whether more bytes are still owed.
    ///
    /// `ready` is sliced rather than copied and `partial` is appended to, so this
    /// costs the bytes the read carried and nothing that was already held.
    ///
    /// No reservation against `length` happens here, deliberately. Reserving the
    /// declared length would avoid the repeated reallocation a large frame pays
    /// as it arrives — and would also let eight bytes of header allocate the whole
    /// [`MAX_FRAME_BYTES`] without a byte of payload existing to justify it, which
    /// is the exact allocation the bound on that number exists to prevent. The
    /// bound is only a ceiling, not a promise that a frame will use it, so
    /// treating it as a size to reserve would make a peer choose this client's
    /// peak allocation for it. Growing on arrival keeps the cost proportional to
    /// what was actually delivered.
    fn fill_partial(&mut self, length: usize) -> bool {
        if self.partial.len() >= length {
            return true;
        }
        let taking = (length - self.partial.len()).min(self.ready.len());
        let taken = self.ready.split_to(taking);
        self.partial.extend_from_slice(&taken);
        self.partial.len() >= length
    }

    /// Decodes the next frame, or `None` when more bytes are needed.
    ///
    /// A header is parsed as soon as its eight bytes have arrived, so the payload
    /// length is known — and refused if it is over [`MAX_FRAME_BYTES`] — before
    /// the payload does, and a partial header is simply left buffered.
    ///
    /// A zero-length frame is a header for a write that produced nothing. It
    /// carries nothing a caller can use, so it is consumed and the next frame is
    /// decoded from the same buffer. That is why this loops rather than
    /// returning on the first empty frame: `None` means "more bytes needed", and
    /// an empty frame already buffered is not that.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not valid multiplexed framing, which is
    /// what a TTY body looks like if the caller declared the container
    /// non-TTY, and when a header declares a payload over
    /// [`MAX_FRAME_BYTES`]. Failing here rather than emitting plausible-looking
    /// garbage for the whole transfer is the point of checking the reserved
    /// bytes; refusing the length is the same argument about the same bytes, and
    /// it happens before the payload is taken rather than after.
    ///
    /// A refusal desynchronizes the body, so it is also final for this decoder:
    /// every later call reports the *same* refusal without reading again. Resuming
    /// would mean parsing the refused frame's payload as framing, and a new
    /// stream is the only honest way to continue.
    ///
    /// "The same refusal" is meant literally. A caller that hits a four-gigabyte
    /// frame and then polls again is asking a second time about the thing that
    /// stopped it, and an answer that named a different cause than the first one
    /// — an unframed body, say, for a refusal that was an oversized frame — is
    /// worse than no answer: it sends the caller looking for a TTY it does not
    /// have. The [`ErrorKind`](crate::ErrorKind) is part of that, not only the
    /// message: a repeat that came back as `Transport` for an `InvalidInput`
    /// refusal would defeat a caller matching on the class, which is the only part
    /// of the error most callers can branch on. The error is rebuilt from the
    /// latched cause every time rather than stored once, so the first report and
    /// every later one are the same failure rather than two descriptions of it.
    pub fn decode(&mut self) -> Result<Option<LogFrame>, Error> {
        if let Some(refusal) = self.refusal {
            return Err(refusal.error());
        }
        self.decode_once().map_err(|refusal| {
            self.latch(refusal);
            refusal.error()
        })
    }

    /// One decoding step, with the refusal bookkeeping left to [`Self::decode`].
    ///
    /// The error type is [`Refusal`] rather than [`Error`] so that the cause can
    /// be latched and rebuilt; converting once, at the edge, is what keeps the
    /// repeat identical to the original instead of to a generic refusal.
    fn decode_once(&mut self) -> Result<Option<LogFrame>, Refusal> {
        if self.tty {
            // Unframed output has no boundary to land on, so what has arrived is
            // one frame, and it is the whole buffer rather than a frame-sized piece
            // of it. Taken rather than copied, because `partial` is a `Vec` and the
            // console output is already in one.
            if self.partial.is_empty() {
                return Ok(None);
            }
            let payload = std::mem::take(&mut self.partial);
            return Ok(Some(LogFrame::new(LogStream::Console, payload)));
        }
        loop {
            let Some(length) = self.expected else {
                // The next bytes are a header, and the header may itself be split
                // across reads, which is what the few leftover bytes in `ready`
                // are. A partial one is left buffered rather than guessed at.
                if self.ready.len() < FRAME_HEADER_BYTES {
                    return Ok(None);
                }
                let (stream, declared) = decode_header(&self.ready[..FRAME_HEADER_BYTES])?;
                // A conversion rather than a cast. `u32` fits `usize` on every
                // target this crate builds for, so the `Err` arm is unreachable
                // today; it is written because the alternative is a `as` that
                // silently truncates if the declared length's type ever widens,
                // and a truncated length is a length that looks legal. The old
                // code cast and then added `FRAME_HEADER_BYTES` to it, which is
                // also where it would have overflowed on a 32-bit target.
                //
                // The failure is reported as an oversized frame because that is
                // what it is from a caller's side: a length this client cannot
                // express as a count of bytes it will hold.
                let length =
                    usize::try_from(declared).map_err(|_| Refusal::OversizedFrame { declared })?;
                // Refused with the header parsed and nothing of the payload
                // buffered. Checking after the bytes arrived would have assembled
                // the whole oversized frame first, which is the allocation this
                // bound exists to prevent.
                if length > MAX_FRAME_BYTES {
                    return Err(Refusal::OversizedFrame { declared });
                }
                self.stream = stream;
                self.expected = Some(length);
                // `split_to` rather than a drain: the header is gone and the
                // frames behind it are where they were.
                let _header = self.ready.split_to(FRAME_HEADER_BYTES);
                continue;
            };
            if !self.fill_partial(length) {
                return Ok(None);
            }
            // The payload of a frame that arrived across reads is already
            // assembled, so it is taken rather than copied again.
            let payload = std::mem::take(&mut self.partial);
            self.expected = None;
            if payload.is_empty() {
                continue;
            }
            return Ok(Some(LogFrame::new(self.stream, payload)));
        }
    }

    /// Appends a network read to the buffer and returns the frames it completed.
    ///
    /// A read usually completes more than one frame, so this returns a vector
    /// rather than a single frame; a caller should drain it before asking for
    /// more bytes.
    ///
    /// # Errors
    ///
    /// Returns the latched error if this body was already refused. If these bytes
    /// first reveal invalid framing or an oversized frame, valid frames before the
    /// refusal are returned (possibly none) and the same error is reported by the
    /// next call to [`Self::decode`], [`Self::push`], or [`Self::finish`].
    ///
    /// A read can complete frames and *then* carry one this client refuses. Those
    /// frames are returned and the refusal is reported by the following call
    /// rather than in place of them, so a log is not shortened by exactly the
    /// lines that arrived before the bad one.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<LogFrame>, Error> {
        // Before the copy, not after. A refused decoder holds nothing and can
        // never hold anything again, so copying a caller's bytes in only to
        // refuse them is a copy of a follow stream's output paid for nothing —
        // once per poll, for as long as the caller keeps polling, which is the
        // case this latch exists to make cheap.
        if let Some(refusal) = self.refusal {
            return Err(refusal.error());
        }
        self.absorb(Bytes::copy_from_slice(bytes));
        Ok(self.drain_frames())
    }

    /// Appends a transport read and returns the frames it completed, without
    /// copying the read first.
    ///
    /// The same thing [`Self::push`] does, for a caller that already holds the
    /// read as [`Bytes`] — which is what the transport hands over — so this is
    /// the path a live stream uses. Without it every byte of a container's output
    /// is copied once into the decoder on the way in and once into the
    /// [`LogFrame::payload`] on the way out, and the first of those copies buys
    /// nothing: the frames come out of the read either way.
    ///
    /// # Errors
    ///
    /// Returns the latched error if this body was already refused. If this read
    /// first reveals invalid framing or an oversized frame, valid frames before
    /// the refusal are returned (possibly none) and the same error is reported by
    /// the next call to [`Self::decode`], [`Self::push`], or [`Self::finish`].
    ///
    /// If a read completes valid frames before a refused frame, those frames are
    /// returned first. The refusal is reported by the next call, not in place of
    /// the frames that preceded it.
    pub(crate) fn push_read(&mut self, read: &Bytes) -> Result<Vec<LogFrame>, Error> {
        // Same check before the clone, for the same reason: `read.clone()` on a
        // [`Bytes`] is a refcount bump rather than a copy of the payload, but it
        // pins the transport's allocation for as long as the decoder holds it, so
        // a refused decoder must not take the handle at all.
        if let Some(refusal) = self.refusal {
            return Err(refusal.error());
        }
        self.absorb(read.clone());
        Ok(self.drain_frames())
    }

    /// Appends a read to what has not yet become a frame.
    ///
    /// The read is adopted whole — a pointer and a length — whenever `ready` is
    /// empty, which is the steady state of a `follow` stream: every read lands
    /// where the last one was fully consumed, or where the frame it finished left
    /// nothing behind.
    ///
    /// When `ready` is not empty the join below copies it with the new read, and
    /// on the path that matters that is bounded by the header rather than by the
    /// read. `decode` leaves nothing else behind: it stops either with fewer than
    /// eight bytes waiting, or with a frame half-arrived — in which case it has
    /// already moved what arrived into `partial` and emptied `ready`. Re-joining a
    /// whole partly arrived payload on every read is the quadratic this design
    /// exists to avoid.
    ///
    /// A refused decoder takes nothing at all, which is what stops a caller that
    /// keeps polling after a fatal error from growing the buffer behind a stream
    /// that will never decode again.
    ///
    /// This guard is the second line, not the first: [`Self::push`] and
    /// [`Self::push_read`] both refuse before they get here, so that a caller that
    /// keeps polling does not pay for a copy it cannot use. It stays because
    /// `absorb` is also reachable from a test that drives the buffers directly,
    /// and a decoder that adopted bytes here would hold them with no door able to
    /// take them back out.
    fn absorb(&mut self, read: Bytes) {
        if self.refusal.is_some() {
            return;
        }
        if self.tty {
            self.partial.extend_from_slice(&read);
            return;
        }
        if self.ready.is_empty() {
            self.ready = read;
            return;
        }
        let mut joined = BytesMut::with_capacity(self.ready.len() + read.len());
        joined.extend_from_slice(&self.ready);
        joined.extend_from_slice(&read);
        self.ready = joined.freeze();
    }

    /// Decodes every frame the buffer now holds, and returns them in order.
    ///
    /// Stops on either of two things, and returns the frames decoded before
    /// whichever it was:
    ///
    /// - More bytes are needed. A half-arrived header or payload stays buffered
    ///   for the next read, as it always has.
    /// - A frame was refused. [`Self::decode`] has latched the cause and
    ///   dropped what it was holding, and this loop stops rather than continuing
    ///   over bytes that belong to the refused frame's payload.
    ///
    /// # The refusal is reported by the next call, not this one
    ///
    /// This is the whole reason the two exits are not distinguished in the
    /// return type. A read is one transport chunk, and a chunk can hold several
    /// good frames followed by one this client refuses. Those good frames are
    /// output the container already produced, and returning the error *instead*
    /// of them drops exactly the lines that arrived before the bad one — the one
    /// failure mode a log reader can least afford, and the one this module
    /// argues against everywhere else. A caller cannot tell a log that stopped
    /// short from a log that finished, so losing those frames with the error is
    /// indistinguishable from losing them silently.
    ///
    /// The error is not lost, only moved one call later: the next [`Self::decode`],
    /// [`Self::push`], or [`Self::finish`] reports it. It is the *same* error,
    /// because [`Self::decode`] latched the [`Refusal`] cause and
    /// [`Refusal::error`] rebuilds it from that cause — so the deferred report
    /// and every report after it carry the same kind and the same message as the
    /// call that deferred them. Only the frames in front of it come first.
    fn drain_frames(&mut self) -> Vec<LogFrame> {
        let mut frames = Vec::new();
        loop {
            match self.decode() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) | Err(_) => return frames,
            }
        }
    }

    /// Decides what an exhausted body means.
    ///
    /// A body that ends exactly on a frame boundary is a normal end of stream.
    /// One that ends part-way through a header or a payload is a truncated
    /// transfer, and reporting that as a clean end would silently shorten a log:
    /// the caller would have no way to tell a short log from a finished one.
    ///
    /// # Errors
    ///
    /// Returns an error when bytes remain that do not form a whole frame.
    ///
    /// A body that was already refused reports that refusal rather than a
    /// truncation, with the same kind and the same cause as the call that
    /// refused it. Both are errors and a caller treats both as fatal, so the
    /// choice is about what the diagnostic says: the bytes are gone because the
    /// decoder dropped them when it refused, so "ended mid-frame" would be
    /// describing a body that is no longer there, and it would send a caller
    /// looking for a truncation on the wire that never happened. This also
    /// answers the caller who was handed the frames in front of the refused one
    /// and has not yet been told what stopped the stream.
    pub fn finish(&self) -> Result<(), Error> {
        if let Some(refusal) = self.refusal {
            return Err(refusal.error());
        }
        if self.tty {
            // Unframed output ends wherever it ends; there is no boundary to
            // land on, so trailing bytes are a complete final frame.
            return Ok(());
        }
        if self.partial.is_empty() && self.ready.is_empty() && self.expected.is_none() {
            return Ok(());
        }
        Err(Error::transport(format!(
            "the Engine log stream ended mid-frame: {} byte(s) buffered, {} byte(s) of payload outstanding",
            self.buffered(),
            self.expected.unwrap_or(0),
        )))
    }
}

/// A stream of decoded container log frames.
///
/// Dropping this closes the connection and ends the transfer, which is also how
/// a `follow` stream is cancelled.
pub struct LogFrames {
    frames: FrameStream,
    decoder: LogDecoder,
    /// Frames a single network read completed beyond the first.
    ///
    /// One read can finish several frames, and the next call must not lose the
    /// ones it did not return. The buffer is drained before another read, so a
    /// caller sees every frame exactly once and in order.
    ready: std::collections::VecDeque<LogFrame>,
}

impl std::fmt::Debug for LogFrames {
    /// Reports the framing and how much is buffered, and no payload.
    ///
    /// A `#[derive(Debug)]` here compiles and leaks. Two of the three fields
    /// carry container output: `decoder` holds the bytes of a frame whose header
    /// has not finished arriving, and `ready` holds the payloads of the frames
    /// one network read completed. Both are rendered in full by the `Debug` impls
    /// they already have, so a derive would put a container's stdout into every
    /// panic message, test failure, and log line that mentioned this handle.
    ///
    /// What is printed instead is what a caller diagnosing a stalled log needs
    /// and cannot otherwise get: whether the body is framed, and how much has
    /// arrived without yet forming a frame.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogFrames")
            .field("tty", &self.decoder.is_tty())
            .field("buffered", &self.decoder.buffered())
            .field("ready_frames", &self.ready.len())
            .finish_non_exhaustive()
    }
}

impl LogFrames {
    /// Reads the next decoded frame, or `None` at end of stream.
    ///
    /// Every frame the connection delivered is returned before the error that
    /// stopped the stream. One read can complete several frames and then carry
    /// one this client refuses; the completed ones are handed over first, and
    /// only then does the next call report the refusal. A caller that stops on
    /// the error has therefore already seen every frame that was decodable, and
    /// one that keeps calling gets the refusal on the call after — not instead
    /// of the output that preceded it.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails mid-transfer, when the body
    /// is not valid framing for the declared [`ContainerLogOptions::tty`], when
    /// a frame declares a payload over [`MAX_FRAME_BYTES`], or when the body
    /// ends part-way through a frame. A refusal repeats with the same
    /// [`ErrorKind`](crate::ErrorKind) and the same cause as the first report.
    pub async fn next_frame(&mut self) -> Result<Option<LogFrame>, Error> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            if let Some(frame) = self.decoder.decode()? {
                return Ok(Some(frame));
            }
            // A response can end cleanly between frames, which is the only way
            // to get here: the buffer was drained at the top of the loop.
            let Some(data) = self.frames.next_data().await.map_err(Error::from)? else {
                self.decoder.finish()?;
                return Ok(None);
            };
            self.ready.extend(self.decoder.push_read(&data)?);
        }
    }
}

/// Opens the container logs stream and decodes the Engine's framing.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request.
/// A body framed wrongly for the declared [`ContainerLogOptions::tty`] is
/// reported by [`LogFrames::next_frame`] rather than here, because one read is
/// not enough to tell a valid stream from a corrupt one.
pub async fn logs(
    engine: &RawEngine,
    container: &str,
    options: &ContainerLogOptions,
) -> Result<LogFrames, Error> {
    let response = engine.send(logs_request(container, options)?).await?;
    // The status has to be checked before the body is handed out, or a 404 whose
    // body happens to parse as framing would surface as a log stream.
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(LogFrames {
        frames: response.into_frames(),
        decoder: LogDecoder::new(options.tty),
        ready: std::collections::VecDeque::new(),
    })
}

/// Builds the `GET /containers/{id}/logs` request.
fn logs_request(container: &str, options: &ContainerLogOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("follow", options.follow);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    // Sent unconditionally, as the Engine's generated clients do, so the request
    // shape is identical to every other client's and costs nothing.
    query.value("since", &options.since.to_string());
    query.value("until", &options.until.to_string());
    query.flag("timestamps", options.timestamps);
    query.value("tail", &options.tail);
    Ok(with_query(
        RawRequest::new(Method::GET, &container_path(container, "/logs")?),
        query.finish(),
    ))
}

/// Why a body cannot be decoded any further.
///
/// This is the *cause*, kept so that [`LogDecoder::decode`] can report the same
/// failure every time it is asked. It exists instead of a `bool` because the
/// refusals this module makes are not one failure: a body that is not multiplexed
/// framing is a `Transport` error about a mis-declared container, while an
/// oversized frame is an `InvalidInput` error about a length the daemon wrote.
/// A latch that could only say "refused" would collapse those into one, and a
/// caller branching on [`ErrorKind`] would be told the wrong class for as long
/// as it kept polling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal {
    /// The body is not multiplexed framing.
    NotFramed,
    /// A header named a stream byte this crate does not know.
    UnknownStream {
        /// The byte the header carried in its stream position.
        byte: u8,
    },
    /// A header was shorter than the eight bytes a header is.
    ShortHeader,
    /// A header declared a payload over [`MAX_FRAME_BYTES`].
    OversizedFrame {
        /// The length the header promised.
        declared: u32,
    },
}

impl Refusal {
    /// Builds the error this cause is reported as.
    ///
    /// Deliberately a function of the cause rather than a stored [`Error`]: the
    /// error is rebuilt from the same data on every report, so the second call
    /// cannot drift from the first. A latch that stored the error itself and
    /// replayed it would need the error to be cloneable and would still have to
    /// choose a kind up front, which is where the wrong kind would come from.
    fn error(self) -> Error {
        match self {
            // `Transport`, not `InvalidInput`: this is what a TTY body looks like
            // when the caller declared the container non-TTY. The connection is
            // fine, the daemon is answering, and the request was well formed —
            // the declaration was the caller's and it was wrong, which is a
            // different thing from an invalid command.
            Self::NotFramed => Error::transport(String::from(
                "the Engine log stream is not multiplexed; the container may have a TTY",
            )),
            Self::UnknownStream { byte } => Error::transport(format!(
                "the Engine log stream used an unknown stream byte {byte}"
            )),
            Self::ShortHeader => Error::transport(String::from(
                "the Engine returned a log frame header that was too short",
            )),
            // `InvalidInput` for the reason
            // [`FrameStream::next_json`](crate::raw::FrameStream::next_json)
            // refuses an oversized record: the connection is fine and the daemon
            // answered, and the identical request would produce the identical
            // frame. The declared length is in the message because it is a
            // number this crate read rather than text the daemon wrote, so it is
            // the one part of the diagnostic a caller can act on.
            Self::OversizedFrame { declared } => Error::invalid_input(format!(
                "the Engine declared a log frame of {declared} byte(s), over the \
                 {MAX_FRAME_BYTES}-byte frame limit; the frame was refused rather than buffered"
            )),
        }
    }
}

/// Decodes one eight-byte multiplexed frame header.
///
/// The three bytes after the stream byte are specified to be zero. A client that
/// ignored them would still work against this daemon, so checking them is a
/// deliberate choice: it makes a stream that is not multiplexed framing fail at
/// the first frame instead of emitting plausible-looking garbage for the whole
/// transfer. Bytes 4 through 8 are the payload length, big-endian.
fn decode_header(header: &[u8]) -> Result<(LogStream, u32), Refusal> {
    let bytes = header
        .get(..FRAME_HEADER_BYTES)
        .ok_or(Refusal::ShortHeader)?;
    if bytes[1] != 0 || bytes[2] != 0 || bytes[3] != 0 {
        return Err(Refusal::NotFramed);
    }
    let stream = match bytes[0] {
        0 => LogStream::Stdin,
        1 => LogStream::Stdout,
        2 => LogStream::Stderr,
        other => {
            return Err(Refusal::UnknownStream { byte: other });
        }
    };
    let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Ok((stream, length))
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerLogOptions, FRAME_HEADER_BYTES, LogDecoder, LogStream, MAX_FRAME_BYTES, Refusal,
        decode_header, logs_request,
    };
    use crate::ErrorKind;
    use bytes::Bytes;

    /// Decodes a header, mapping failure to a sentinel so a header can be
    /// compared with `assert_eq!`. [`crate::Error`] deliberately has no
    /// `PartialEq` — two errors with the same kind can differ in message, and
    /// equality would invite tests that pass on the wrong one.
    fn header(bytes: &[u8]) -> Result<(LogStream, u32), &'static str> {
        decode_header(bytes).map_err(|_| "rejected")
    }

    /// Builds a frame header declaring `length` bytes of payload, with none of
    /// that payload present.
    ///
    /// This is the shape a peer sends when it wants to promise bytes it has not
    /// written yet, which is the only shape in which the declared length is
    /// testable on its own: a frame that carries its payload says nothing about
    /// what the bound does.
    fn header_of_length(stream: u8, length: u32) -> Vec<u8> {
        let mut out = vec![stream, 0, 0, 0];
        out.extend_from_slice(&length.to_be_bytes());
        out
    }

    /// Builds one multiplexed frame exactly as the Engine writes it.
    fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = header_of_length(stream, length_of(payload));
        out.extend_from_slice(payload);
        out
    }

    /// The length a test payload carries.
    fn length_of(payload: &[u8]) -> u32 {
        u32::try_from(payload.len()).expect("a test payload fits u32")
    }

    /// The frame bound, and one byte past it, as a header declares a length.
    ///
    /// The bound is a `usize` and a header's length is a `u32`, so the boundary
    /// is written through a checked conversion rather than a cast. The two are the
    /// same value and a cast would be shorter, but a test that pins the boundary
    /// ought not to be one line away from silently testing a different one on a
    /// target where they are not.
    fn at_and_past_the_bound() -> (u32, u32) {
        let bound = u32::try_from(MAX_FRAME_BYTES).expect("the frame bound fits u32");
        (bound, bound + 1)
    }

    /// Whether these bytes point inside `read`'s own allocation.
    ///
    /// By address rather than by asking the decoder to report what it did: a
    /// self-reported counter only sees the paths that increment it, and aliasing
    /// cannot be faked that way. A decoder that copied the read into a buffer of
    /// its own and handed frames out of that has a pointer somewhere else, and
    /// fails on the first check.
    ///
    /// A range rather than equality, because a frame is a sub-slice of the read,
    /// and an empty slice left after the last frame sits one past its final byte —
    /// hence the inclusive end.
    fn points_into(candidate: &[u8], read: &Bytes) -> bool {
        let base = read.as_ptr() as usize;
        let at = candidate.as_ptr() as usize;
        (base..=base + read.len()).contains(&at)
    }

    /// Feeds a body to a decoder in the given chunk sizes and collects frames.
    fn decode_in_chunks(chunks: &[usize], tty: bool) -> Result<Vec<super::LogFrame>, crate::Error> {
        let mut body = Vec::new();
        body.extend(frame(1, b"to-stdout\n"));
        body.extend(frame(2, b"to-stderr\n"));
        let mut decoder = LogDecoder::new(tty);
        let mut frames = Vec::new();
        let mut offset = 0;
        for size in chunks {
            let end = (offset + size).min(body.len());
            frames.extend(decoder.push(&body[offset..end])?);
            offset = end;
        }
        frames.extend(decoder.push(&body[offset..])?);
        decoder.finish()?;
        Ok(frames)
    }

    /// Pushes a body and returns the refusal it ends in, for a body with no
    /// frames to hand over first.
    ///
    /// A refusal is reported by the call *after* the one that read the bad bytes,
    /// so the read itself returns the frames it completed rather than the error.
    /// A test that wants the error and does not care about the frames asks for it
    /// here rather than reaching for `expect_err` on the push and being surprised
    /// when it returns `Ok`.
    fn refusal_after(decoder: &mut LogDecoder, body: &[u8]) -> crate::Error {
        let frames = decoder
            .push(body)
            .expect("a refused read reports its frames, not its error");
        assert!(
            frames.is_empty(),
            "this helper is for a body that decodes nothing before its refusal"
        );
        decoder
            .decode()
            .expect_err("the refusal is reported by the next call")
    }

    /// The `(kind, message)` pair an error renders as.
    ///
    /// Compared by rendering rather than by a second `Error`, because
    /// [`crate::Error`] has no `PartialEq`: the property under test is that two
    /// *reports* are the same report, and the report is what a caller sees. Both
    /// halves are taken — the kind on its own, because most callers branch on the
    /// class and never read the message, and the message because a caller that
    /// does read it must not be told a different cause.
    fn reported(error: &crate::Error) -> (ErrorKind, String) {
        (error.kind(), error.to_string())
    }

    #[test]
    fn a_header_decodes_to_its_stream_and_length() {
        assert_eq!(header(&frame(1, b"hello")), Ok((LogStream::Stdout, 5)));
        assert_eq!(header(&frame(2, b"")), Ok((LogStream::Stderr, 0)));
        assert_eq!(header(&frame(0, b"in")), Ok((LogStream::Stdin, 2)));
    }

    /// A payload length of 10 puts a newline byte in the header. That is why a
    /// decoder that split on newlines looked correct on small frames and
    /// mangled everything else; this one reads the length from bytes 4..8 and so
    /// reads 10 here, not the byte before it.
    #[test]
    fn a_payload_length_is_read_from_the_last_four_bytes() {
        assert_eq!(
            header(&[1u8, 0, 0, 0, 0, 0, 0, 0x0a]),
            Ok((LogStream::Stdout, 10))
        );
    }

    #[test]
    fn a_non_zero_reserved_byte_is_rejected() {
        assert!(
            decode_header(&[1u8, 0, 1, 0, 0, 0, 0, 4]).is_err(),
            "the reserved bytes must be zero"
        );
    }

    #[test]
    fn an_unknown_stream_byte_is_rejected() {
        assert!(decode_header(&[9u8, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn a_short_header_is_rejected() {
        assert!(decode_header(&[1, 0, 0]).is_err());
    }

    #[test]
    fn a_multiplexed_body_is_decoded_frame_by_frame() {
        let frames = decode_in_chunks(&[body_len()], false).expect("decodes");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream, LogStream::Stdout);
        assert_eq!(frames[0].payload, b"to-stdout\n");
        assert_eq!(frames[1].stream, LogStream::Stderr);
        assert_eq!(frames[1].payload, b"to-stderr\n");
        assert!(frames[0].stream.is_multiplexed());
    }

    /// The header and payload may arrive in any split, because the transport
    /// chooses chunk boundaries and knows nothing about frames.
    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        for size in 1..=body_len() {
            let frames = decode_in_chunks(&[size], false).expect("decodes");
            assert_eq!(frames.len(), 2, "chunk size {size}");
            assert_eq!(frames[0].payload, b"to-stdout\n", "chunk size {size}");
            assert_eq!(frames[1].payload, b"to-stderr\n", "chunk size {size}");
        }
    }

    /// One byte at a time is the worst case for a decoder that assumed a read
    /// was frame-aligned.
    #[test]
    fn a_body_delivered_one_byte_at_a_time_is_decoded() {
        let frames = decode_in_chunks(&[1; 64], false).expect("decodes");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, b"to-stdout\n");
    }

    #[test]
    fn a_zero_length_frame_is_skipped() {
        let mut body = frame(1, b"");
        body.extend(frame(1, b"after-empty"));
        let mut decoder = LogDecoder::new(false);
        let frames = decoder.push(&body).expect("decodes");
        assert_eq!(frames.len(), 1, "an empty frame carries nothing");
        assert_eq!(frames[0].payload, b"after-empty");
    }

    /// A body that stops part-way is a truncated transfer, and reporting it as a
    /// clean end would shorten a log without the caller noticing.
    #[test]
    fn a_body_that_ends_mid_frame_is_an_error() {
        let mut body = frame(1, b"complete");
        body.truncate(body.len() - 2);
        let mut decoder = LogDecoder::new(false);
        decoder.push(&body).expect("decodes");
        assert!(
            decoder.finish().is_err(),
            "a truncated frame must not read as a clean end of stream"
        );
    }

    #[test]
    fn a_body_that_ends_on_a_boundary_is_a_clean_end() {
        let mut decoder = LogDecoder::new(false);
        decoder.push(&frame(1, b"complete")).expect("decodes");
        decoder.finish().expect("a boundary is a clean end");
    }

    /// A TTY body has no frames, so the boundary check that rejects a truncated
    /// multiplexed body must not reject a TTY body that ends mid-"line".
    #[test]
    fn a_tty_body_is_returned_verbatim() {
        let mut decoder = LogDecoder::new(true);
        let frames = decoder.push(b"raw tty output").expect("decodes");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream, LogStream::Console);
        assert_eq!(frames[0].payload, b"raw tty output");
        assert!(!frames[0].stream.is_multiplexed());
        decoder.push(b" and more").expect("decodes");
        decoder.finish().expect("unframed output ends anywhere");
    }

    /// A TTY body is not held to the frame bound, because there is nothing on
    /// the wire to bound.
    ///
    /// [`MAX_FRAME_BYTES`] is a bound on a *multiplexed frame's* payload: it is
    /// checked against the length a frame header declares, before a byte of that
    /// payload is taken. A TTY body has no header — the daemon writes the
    /// container's output verbatim — so it has no declared length, and applying
    /// the constant to it would refuse output based on a number nobody wrote.
    ///
    /// That is what the constant's own documentation says, and it is what this
    /// pins: a console frame larger than the bound is returned, not refused. The
    /// counterpart is [`a_multiplexed_body_is_decoded_frame_by_frame`] plus the
    /// oversized tests — between them, "the bound applies to frames and only to
    /// frames" is a statement about behaviour rather than about a doc comment.
    ///
    /// Two reads rather than one, because a single read is drained whole and the
    /// interesting question is what a caller reading a live TTY stream holds at
    /// once: one read's worth, which the transport bounds and this crate does not.
    #[test]
    fn a_tty_frame_is_not_bounded_by_the_multiplexed_frame_limit() {
        let mut decoder = LogDecoder::new(true);
        let over = MAX_FRAME_BYTES + 1024;
        let mut sent = 0;
        let mut frames = 0;
        while sent < over {
            let chunk = 64 * 1024;
            let end = (sent + chunk).min(over);
            let delivered = decoder
                .push(&vec![b'z'; end - sent])
                .expect("an unframed body has no declared length to exceed");
            frames += delivered.len();
            sent = end;
        }
        assert!(
            frames > 0,
            "{over} bytes of console output are delivered, not refused: the frame bound is a \
             bound on a length a header declares, and a TTY body declares none"
        );
        decoder.finish().expect("unframed output ends anywhere");
    }

    /// A refused body reports the refusal at the end of the stream, not a
    /// truncation.
    ///
    /// The bytes are gone because the decoder dropped them when it refused, so
    /// "ended mid-frame" would describe a body that is no longer on the wire, and
    /// it would send a caller looking for a truncation that never happened. This
    /// is also the report a caller gets who was handed the frames in front of the
    /// refused one and has not been told yet what stopped the stream.
    #[test]
    fn finish_after_a_refusal_reports_the_refusal_rather_than_a_truncation() {
        let mut decoder = LogDecoder::new(false);
        let first = reported(&refusal_after(&mut decoder, &header_of_length(1, u32::MAX)));
        let error = decoder
            .finish()
            .expect_err("a refused body does not end cleanly");
        let at_finish = reported(&error);
        assert_eq!(
            at_finish, first,
            "finish reports the same refusal the stream stopped on"
        );
        assert!(
            !at_finish.1.contains("mid-frame"),
            "the message describes a truncation the wire never had: {}",
            at_finish.1
        );
    }

    /// A body whose bytes are not framing must be rejected rather than printed.
    ///
    /// The assertion is on the error *kind*, not the message: the facade keeps
    /// daemon and transport text out of `Display` so a log payload can never
    /// leak through an error, and a test that read the message would be testing
    /// a string no caller can see.
    #[test]
    fn a_body_that_is_not_framing_is_rejected() {
        // A TTY program writing text: the reserved bytes are not zero, so this
        // cannot be a header.
        let mut decoder = LogDecoder::new(false);
        let error = refusal_after(&mut decoder, b"hello from a tty\n");
        assert_eq!(error.kind(), ErrorKind::Transport);
    }

    /// One read can finish several frames, and every one of them is owed to the
    /// caller. A decoder that returned the first and dropped the rest would lose
    /// log lines silently, which is the failure mode a log reader can least
    /// afford.
    #[test]
    fn every_frame_a_single_read_completes_is_returned() {
        let mut body = Vec::new();
        for index in 0..5u8 {
            body.extend(frame(1, &[b'a' + index; 16]));
        }
        let mut decoder = LogDecoder::new(false);
        // One read, five frames.
        let frames = decoder.push(&body).expect("decodes");
        assert_eq!(
            frames.len(),
            5,
            "one read must surface every frame it holds"
        );
        let payloads: Vec<Vec<u8>> = frames.into_iter().map(|frame| frame.payload).collect();
        for (index, payload) in payloads.iter().enumerate() {
            let expected = vec![b'a' + u8::try_from(index).expect("five frames fits u8"); 16];
            assert_eq!(payload, &expected, "frame {index}");
        }
    }

    /// A read that ends part-way into a frame, followed by one that finishes it,
    /// must still yield the frame exactly once.
    #[test]
    fn a_frame_spanning_two_reads_is_returned_once() {
        let whole = frame(1, b"spanning");
        let (head, tail) = whole.split_at(6);
        let mut decoder = LogDecoder::new(false);
        assert!(
            decoder.push(head).expect("decodes").is_empty(),
            "a partial header yields no frame"
        );
        let frames = decoder.push(tail).expect("decodes");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"spanning");
        assert!(
            decoder.push(&[]).expect("decodes").is_empty(),
            "the frame is not repeated"
        );
    }

    #[test]
    fn a_payload_containing_nul_bytes_survives() {
        let payload = b"A\0B\n";
        let mut decoder = LogDecoder::new(false);
        let frames = decoder.push(&frame(1, payload)).expect("decodes");
        assert_eq!(frames[0].payload, payload.to_vec());
    }

    #[test]
    fn a_payload_larger_than_the_header_survives() {
        // A frame longer than 8 bytes is the case a header-truncating decoder
        // gets wrong, and also the case a length byte count confuses.
        let payload = vec![b'x'; 4096];
        let mut decoder = LogDecoder::new(false);
        let frames = decoder.push(&frame(1, &payload)).expect("decodes");
        assert_eq!(frames[0].payload.len(), 4096);
    }

    /// The declared length is the one number in a frame this client cannot
    /// check, and the peer picks it for free, so it is the number that needed a
    /// bound.
    ///
    /// `u32::MAX` is the shape that matters: a header alone is eight bytes and
    /// promises four gigabytes, and a decoder that took the promise at face value
    /// would hold this client's heap to whatever the peer went on to send.
    #[test]
    fn an_oversized_declared_length_is_refused() {
        let mut decoder = LogDecoder::new(false);
        let error = refusal_after(&mut decoder, &header_of_length(1, u32::MAX));
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    /// The refusal happens with the header parsed and *nothing* of the payload
    /// buffered, which is the whole reason to check the declared length rather
    /// than the bytes received.
    ///
    /// Checking after the payload arrived would have assembled the entire
    /// oversized frame first and then reported it, so the bound on its own is not
    /// the property; where the check sits is. Eight bytes is what this decoder
    /// holds: the header, and not one payload byte.
    ///
    /// Asserted against `decode_once`, not through `push`, because the public
    /// door drops what it held on the way out — a refused decoder releases its
    /// buffers, which is the *other* half of this same property. Going through
    /// `push` would see zero bytes buffered and could not tell "refused at the
    /// header" apart from "buffered eight megabytes and then dropped them",
    /// which is the implementation this test exists to rule out. `decode_once` is
    /// the step that refuses and has not yet released anything.
    #[test]
    fn an_oversized_frame_is_refused_before_its_payload_is_buffered() {
        let (_, past) = at_and_past_the_bound();
        let mut decoder = LogDecoder::new(false);
        decoder.absorb(Bytes::from(header_of_length(1, past)));
        let error = decoder
            .decode_once()
            .expect_err("one byte over the bound is refused");
        assert_eq!(error, Refusal::OversizedFrame { declared: past });
        assert_eq!(
            decoder.buffered(),
            FRAME_HEADER_BYTES,
            "the refused frame's payload must never have been taken: holding the header alone is \
             what proves the check ran before the copy"
        );
    }

    /// A refusal drops what the decoder was holding, rather than keeping it until
    /// the handle is dropped.
    ///
    /// The bytes behind a refused header cannot be told apart from that frame's
    /// payload, so they are never readable again — but `ready` is a slice of the
    /// *transport's* allocation, and keeping it pins that allocation for however
    /// long the caller holds a handle it has just been told to throw away.
    /// Emptying the buffer without freeing its allocation would keep the memory
    /// and only make the number here look better, so the assertion is on the
    /// bytes held *and* on the read no longer being aliased.
    #[test]
    fn a_refusal_releases_what_it_was_holding() {
        let read = Bytes::from(header_of_length(1, u32::MAX));
        let mut decoder = LogDecoder::new(false);

        // Before: the decoder is holding the transport's own allocation.
        decoder.absorb(read.clone());
        assert!(
            points_into(&decoder.ready, &read),
            "the read is adopted rather than copied, so it is held before the refusal"
        );
        assert_eq!(decoder.buffered(), FRAME_HEADER_BYTES);

        let error = decoder
            .decode()
            .expect_err("a frame of four gigabytes is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            decoder.buffered(),
            0,
            "a refused decoder keeps nothing: the bytes behind a refused header are that frame's \
             payload and are never readable again"
        );
        assert!(
            !points_into(&decoder.ready, &read),
            "the transport's allocation is still pinned after the refusal, so a caller that keeps \
             the dead handle alive keeps the read alive with it"
        );
    }

    /// A frame of exactly the bound is read and one byte more is refused.
    ///
    /// The check is on the declared length rather than on what has arrived, so
    /// this needs no payload at all: the bound is a statement about what this
    /// client will assemble, and a frame inside it is *promised*, not yet
    /// delivered. Asserting the boundary at the header is also what keeps the
    /// test cheap — materialising eight megabytes of payload to prove an
    /// off-by-one would be the wasteful way to say the same thing.
    #[test]
    fn the_frame_bound_admits_exactly_the_bound() {
        let (at, past) = at_and_past_the_bound();
        let mut decoder = LogDecoder::new(false);
        decoder
            .push(&header_of_length(1, at))
            .expect("a frame at the bound is read");
        // A second decoder, because a header cannot follow the first one on the
        // wire until the frame it promised has been delivered: this is testing the
        // bound, not the framing.
        let mut decoder = LogDecoder::new(false);
        let error = refusal_after(&mut decoder, &header_of_length(1, past));
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidInput,
            "one byte over the bound"
        );
    }

    /// The header is eight bytes and arrives wherever the transport put it, so the
    /// bound has to hold when the header is split across reads as well as when it
    /// is not. Every split point is tried, because the interesting one is the
    /// last: seven bytes buffered, which is the only state a `push` can find.
    #[test]
    fn an_oversized_length_is_refused_however_the_header_arrives() {
        let head = header_of_length(1, u32::MAX);
        for split in 1..FRAME_HEADER_BYTES {
            let mut decoder = LogDecoder::new(false);
            assert!(
                decoder.push(&head[..split]).is_ok(),
                "split {split}: a partial header is not yet a frame"
            );
            let error = refusal_after(&mut decoder, &head[split..]);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "split {split}");
        }
    }

    /// A refusal ends the body, and a decoder that has refused one says so forever
    /// without reading again.
    ///
    /// This is the case a `follow` subscriber hits when one frame is not one this
    /// client will assemble, and the decision is deliberate rather than a gap.
    /// Resuming would mean parsing the refused frame's payload as a header, which
    /// is the plausible-looking garbage this module refuses to emit; and it would
    /// mean keeping the bytes behind a stream that cannot decode again, so a
    /// caller that kept polling would grow the buffer for nothing. A caller that
    /// wants another stream opens another one — dropping `LogFrames` closes the
    /// connection, so continuing is a new request and not a retry of this one.
    ///
    /// The frame that arrived before the refused one is still delivered: the
    /// refusal is what stopped the read, not a rollback of what was already
    /// decoded. That frame is output the container already wrote, and returning
    /// the error *instead* of it would shorten the log by exactly the lines that
    /// arrived before the bad one — indistinguishable, from the caller's side,
    /// from losing them silently.
    ///
    /// So the read returns the frame and the refusal comes on the next call. The
    /// frames behind the refused header are gone with it and are not delivered:
    /// they are that frame's payload, which this module refuses to parse as
    /// framing.
    #[test]
    fn a_refused_body_stays_refused_and_grows_nothing() {
        let mut body = frame(1, b"before");
        body.extend(header_of_length(2, u32::MAX));
        body.extend(frame(1, b"behind the bad header"));
        let mut decoder = LogDecoder::new(false);

        let frames = decoder
            .push(&body)
            .expect("the frame in front of the refusal is handed over");
        assert_eq!(
            frames.len(),
            1,
            "the frame decoded before the refused one is still owed to the caller"
        );
        assert_eq!(frames[0].payload, b"before");
        assert_eq!(
            frames[0].stream,
            LogStream::Stdout,
            "and it keeps the stream its header selected"
        );

        // The refusal follows it, with the class the first report had.
        let error = decoder
            .decode()
            .expect_err("the oversized frame in the middle is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        // Reading again is an error rather than an attempt, and taking more bytes
        // does not grow what is held.
        let buffered = decoder.buffered();
        for _ in 0..4 {
            assert!(
                decoder.push(&frame(1, b"more")).is_err(),
                "a refused body cannot be read into"
            );
            assert_eq!(
                decoder.buffered(),
                buffered,
                "a refused decoder must not take bytes: a caller that keeps polling would grow \
                 the buffer behind a stream that can never decode again"
            );
        }
        assert!(
            decoder.push(&frame(1, b"more")).is_err(),
            "and the repeated refusals stay refusals"
        );
    }

    /// Every frame a read completes before the frame it refuses is handed over,
    /// in order, and none of the frames behind the refusal is.
    ///
    /// The multi-frame case, because a decoder that keeps only the *last* frame
    /// before the refusal still passes a one-frame test, and one that keeps none
    /// passes a test with no good frames. Three before, so a partial delivery is
    /// visible as a count that is neither zero nor all.
    #[test]
    fn every_frame_before_a_refusal_is_delivered_and_none_behind_it() {
        let mut body = Vec::new();
        for index in 0..3u8 {
            body.extend(frame(1 + index % 2, &[b'a' + index; 8]));
        }
        body.extend(header_of_length(2, u32::MAX));
        for index in 0..3u8 {
            body.extend(frame(1, &[b'z' - index; 8]));
        }

        let mut decoder = LogDecoder::new(false);
        let frames = decoder
            .push(&body)
            .expect("the frames in front of the refusal are delivered");
        let payloads: Vec<Vec<u8>> = frames.into_iter().map(|frame| frame.payload).collect();
        assert_eq!(
            payloads,
            vec![vec![b'a'; 8], vec![b'b'; 8], vec![b'c'; 8]],
            "every frame decoded before the refused one, in order"
        );

        // The three behind it are that frame's payload. They are not frames, so
        // they are not delivered, and nothing further decodes.
        let error = decoder
            .decode()
            .expect_err("the oversized frame is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    /// A refusal repeats with the same class and the same cause it first reported.
    ///
    /// The two refusals are different failures — a body that is not framing is a
    /// `Transport` error about a mis-declared container, an oversized frame is an
    /// `InvalidInput` error about a length the daemon wrote — and a latch that
    /// could only say "refused" would collapse them. A caller matching on
    /// [`ErrorKind`] is the one that suffers, because most callers branch on the
    /// class and never read the message at all.
    #[test]
    fn a_refusal_repeats_its_own_cause_and_its_own_kind() {
        // Each refusal on its own decoder, so the two cannot contaminate each
        // other's latch.
        let bodies = [
            // An oversized frame: `InvalidInput`, and the declared length is in
            // the message.
            (
                header_of_length(1, u32::MAX),
                ErrorKind::InvalidInput,
                "declared",
            ),
            // Not multiplexed framing: `Transport`, and the TTY is named.
            (b"hello from a tty\n".to_vec(), ErrorKind::Transport, "TTY"),
            // An unknown stream byte: `Transport`, and the byte is named.
            (
                vec![9u8, 0, 0, 0, 0, 0, 0, 0],
                ErrorKind::Transport,
                "stream byte 9",
            ),
        ];
        for (body, kind, cause) in bodies {
            let mut decoder = LogDecoder::new(false);
            let first = reported(&refusal_after(&mut decoder, &body));
            assert_eq!(first.0, kind, "the class the cause is reported as");
            assert!(
                first.1.contains(cause),
                "the message names its own cause, so a repeat can be checked against it: {}",
                first.1
            );

            // Every later door: `decode`, both pushes, and `finish`.
            let mut later = decoder
                .decode()
                .expect_err("the refusal repeats on decode")
                .to_string();
            for index in 0..3 {
                let repeated = decoder
                    .push(&frame(1, b"more"))
                    .expect_err("the refusal repeats on push");
                assert_eq!(
                    reported(&repeated),
                    first,
                    "push {index}: a refusal that changed its kind or its cause between calls is \
                     not a repeat"
                );
                later = repeated.to_string();
            }
            let on_finish = decoder.finish().expect_err("the refusal repeats on finish");
            assert_eq!(reported(&on_finish), first, "finish");
            assert_eq!(
                later, first.1,
                "the rendering a caller sees is the same every time"
            );

            let read = Bytes::from(frame(1, b"more"));
            let on_read = decoder
                .push_read(&read)
                .expect_err("the refusal repeats on push_read");
            assert_eq!(reported(&on_read), first, "push_read");
        }
    }

    /// A refused decoder rejects a read before taking a handle on it.
    ///
    /// `push` copies its argument and `push_read` clones the `Bytes`, and on a
    /// refused decoder both are wasted: the bytes cannot be decoded and are not
    /// kept. On a `follow` stream that is a copy of the output on every poll for
    /// as long as the caller keeps polling, which is the case the refusal latch
    /// exists to make cheap.
    ///
    /// Checked by aliasing rather than by counting copies: `push_read` takes a
    /// `Bytes`, and a decoder that held on to it would pin the transport's
    /// allocation. The slice door cannot be watched that way, so it is checked
    /// through the buffer the copy would have landed in — which stays empty.
    #[test]
    fn a_refused_decoder_takes_no_read_on_the_way_in() {
        let mut decoder = LogDecoder::new(false);
        refusal_after(&mut decoder, &header_of_length(1, u32::MAX));

        let read = Bytes::from(vec![b'q'; 64 * 1024]);
        for _ in 0..3 {
            assert!(
                decoder.push_read(&read).is_err(),
                "a refused body cannot be read into"
            );
            assert!(
                decoder.push(&vec![b'q'; 64 * 1024]).is_err(),
                "a refused body cannot be read into"
            );
            assert_eq!(
                decoder.buffered(),
                0,
                "a refused decoder takes nothing: the copy a push makes before it refuses is a copy \
                 of the caller's output paid for nothing, and the clone a push_read makes pins the \
                 transport's allocation"
            );
            assert!(
                !points_into(&decoder.ready, &read),
                "the transport's allocation is pinned by a decoder that was handed a read it \
                 refused"
            );
        }
    }

    #[test]
    fn absorb_drops_a_read_after_refusal() {
        let read = Bytes::from(vec![b'q'; 64 * 1024]);
        for tty in [false, true] {
            let mut decoder = LogDecoder::new(tty);
            // TTY bodies do not normally latch framing refusals. Set the private
            // state directly to exercise the defensive guard before either
            // buffering branch can adopt the read.
            decoder.refusal = Some(Refusal::OversizedFrame { declared: u32::MAX });
            decoder.absorb(read.clone());

            assert_eq!(decoder.buffered(), 0, "tty={tty}");
            assert!(decoder.ready.is_empty(), "tty={tty}");
            assert!(decoder.partial.is_empty(), "tty={tty}");
            assert!(!points_into(&decoder.ready, &read), "tty={tty}");
        }
    }

    /// The same contract through the door the Swarm slice uses, on a body it
    /// cannot produce otherwise.
    ///
    /// [`SwarmLogFrames`](crate::raw::SwarmLogFrames) has no public constructor
    /// and no fixture socket behind it, so its `next_frame` cannot be driven from
    /// here. What it *does* do is drive this decoder through `push_read` with
    /// `new(false)` — a task's container has no TTY, so its body is always
    /// multiplexed — and that combination is what this pins: the frames a read
    /// completed are handed over, and the refusal follows them.
    ///
    /// The body is deliberately the shape the container slice cannot produce
    /// alone: an oversized frame after two good ones, read through the
    /// non-copying door. So the two slices are asserted to agree about a case
    /// neither would catch alone, rather than each catching its own.
    #[test]
    fn the_swarm_slice_doors_deliver_frames_before_a_refusal_the_same_way() {
        let mut body = frame(1, b"task output");
        body.extend(frame(2, b"more task output"));
        body.extend(header_of_length(1, u32::MAX));

        // `new(false)` and `push_read`, which is exactly what
        // `SwarmLogFrames::next_frame` uses.
        let mut decoder = LogDecoder::new(false);
        assert!(!decoder.is_tty(), "a task's body is always multiplexed");
        let frames = decoder
            .push_read(&Bytes::from(body))
            .expect("a refused read reports its frames");
        let payloads: Vec<Vec<u8>> = frames.into_iter().map(|frame| frame.payload).collect();
        assert_eq!(
            payloads,
            vec![b"task output".to_vec(), b"more task output".to_vec()],
            "both frames the read completed, in order"
        );

        let error = decoder
            .decode()
            .expect_err("the oversized frame ends the task log");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains(&u32::MAX.to_string()),
            "the message names the declared length a caller can act on: {error}"
        );
        assert_eq!(
            decoder.finish().expect_err("and finish agrees").kind(),
            ErrorKind::InvalidInput,
            "every door reports the same class for this refusal"
        );
    }

    /// A payload that arrives in pieces is assembled into this crate's own buffer,
    /// and it is assembled *up to* its declared length and no further.
    ///
    /// The second half is the part that needs saying out loud: a peer that
    /// promises a frame inside the bound can make this client hold up to that much
    /// of it, and one that promises a byte more gets nothing at all. A quarter of
    /// the bound in kilobyte reads is enough to be many reads and few enough to
    /// keep the test quick.
    #[test]
    fn a_frame_split_across_many_reads_is_held_within_its_declared_length() {
        let total = MAX_FRAME_BYTES / 4;
        let chunk = 1024;
        let mut decoder = LogDecoder::new(false);
        decoder
            .push(&header_of_length(1, length_of(&vec![0; total])))
            .expect("a frame inside the bound is read");
        let mut frames = Vec::new();
        let mut sent = 0;
        while sent < total {
            let end = (sent + chunk).min(total);
            frames.extend(
                decoder
                    .push(&vec![b'z'; end - sent])
                    .expect("a partly arrived payload cannot be refused"),
            );
            sent = end;
            if sent < total {
                assert!(
                    frames.is_empty(),
                    "{sent} of {total} bytes is not a frame yet"
                );
                assert_eq!(
                    decoder.buffered(),
                    FRAME_HEADER_BYTES + sent,
                    "the decoder is holding the header and exactly what has arrived"
                );
            }
        }
        assert_eq!(frames.len(), 1, "the last read completes the frame");
        assert_eq!(frames[0].payload.len(), total);
        assert_eq!(decoder.buffered(), 0, "a consumed frame buffers nothing");
    }

    /// One read carrying four whole frames and part of a fifth: every frame it
    /// completed is owed to the caller, and the partial header behind them stays
    /// buffered for the next read.
    #[test]
    fn several_frames_and_a_partial_header_in_one_read_are_all_decoded() {
        let mut body = Vec::new();
        for index in 0..4u8 {
            body.extend(frame(1, &[b'a' + index; 12]));
        }
        let fifth = frame(2, b"cut-off");
        body.extend_from_slice(&fifth[..6]);

        let mut decoder = LogDecoder::new(false);
        let frames = decoder.push(&body).expect("four whole frames decode");
        assert_eq!(frames.len(), 4, "a read must surface every frame it holds");
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.stream, LogStream::Stdout);
            assert_eq!(
                frame.payload,
                vec![b'a' + u8::try_from(index).expect("four frames fits u8"); 12],
                "frame {index} keeps its order"
            );
        }
        assert_eq!(
            decoder.buffered(),
            6,
            "six bytes is a header in progress, not a frame"
        );

        // And the read that completes it is read from the same place.
        let frames = decoder.push(&fifth[6..]).expect("decodes");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream, LogStream::Stderr);
        assert_eq!(frames[0].payload, b"cut-off");
        assert_eq!(decoder.buffered(), 0);
    }

    /// The join branch in `absorb`: a read that arrives while a header is partial.
    ///
    /// `decode` leaves a partial header as fewer than eight bytes waiting in `ready`;
    /// the next read takes the join branch, copying those leftover header bytes onto
    /// the front of the new read. That copy is the price of the layout and it is
    /// bounded by the header rather than by the read, because the leftover is at
    /// most seven bytes. A partial payload lives in `partial` instead and does not
    /// exercise this branch.
    ///
    /// What is pinned here is that the join keeps the two halves in order. A decoder
    /// that appended the new read *before* the leftover, or dropped one of them,
    /// would still pass a test whose split happens to leave nothing behind. So this
    /// splits the header at every byte position, which catches a join that gets the
    /// order backwards for some split — and a split of one leaves the smallest
    /// leftover.
    #[test]
    fn a_read_joined_to_a_partly_arrived_header_keeps_both_halves_in_order() {
        let whole = frame(1, b"a payload that spans the join");
        for split in 1..FRAME_HEADER_BYTES {
            let mut decoder = LogDecoder::new(false);
            assert!(
                decoder
                    .push(&whole[..split])
                    .expect("a partly arrived frame is not refused")
                    .is_empty(),
                "split {split}: fewer than the whole frame"
            );
            let frames = decoder
                .push(&whole[split..])
                .expect("the read completes the frame it was cut in half from");
            assert_eq!(
                frames.len(),
                1,
                "split {split}: the join lost or duplicated a frame"
            );
            assert_eq!(
                frames[0].payload,
                whole[FRAME_HEADER_BYTES..],
                "split {split}: the join put the two halves in the wrong order"
            );
            assert_eq!(decoder.buffered(), 0, "split {split}");
        }
    }

    /// The join branch with a large read behind a small leftover, which is the
    /// shape a live stream produces when a header straddles two transport reads.
    ///
    /// The first test pins the join's *order*; this pins what it costs and what it
    /// leaves behind. The joined buffer is this crate's own allocation, so frames
    /// handed out after a join do not alias the transport's read — the adoption
    /// the steady state gets is not available on this path, and a caller
    /// diagnosing a stalled log should be able to tell the two apart from
    /// `buffered`.
    #[test]
    fn a_join_leaves_the_whole_of_a_large_read_behind_in_one_buffer() {
        let first = frame(1, b"a payload long enough to split across the join");
        let mut body = first[..FRAME_HEADER_BYTES + 4].to_vec();
        body.extend_from_slice(&first[FRAME_HEADER_BYTES + 4..]);
        for index in 0..8u8 {
            body.extend(frame(2, &[b'a' + index; 64]));
        }

        let mut decoder = LogDecoder::new(false);
        assert!(
            decoder
                .push(&first[..FRAME_HEADER_BYTES + 4])
                .expect("decodes")
                .is_empty(),
            "the first read is a header and a fragment"
        );
        let frames = decoder
            .push(&body[FRAME_HEADER_BYTES + 4..])
            .expect("the joined read decodes");
        assert_eq!(
            frames.len(),
            9,
            "the frame the join completed plus the eight behind it, once each"
        );
        assert_eq!(frames[0].payload, first[FRAME_HEADER_BYTES..]);
        for (index, frame) in frames[1..].iter().enumerate() {
            assert_eq!(frame.stream, LogStream::Stderr, "frame {index}");
            assert_eq!(
                frame.payload,
                vec![b'a' + u8::try_from(index).expect("eight frames fits u8"); 64],
                "frame {index} keeps its order through the join"
            );
        }
        assert_eq!(decoder.buffered(), 0, "a consumed body buffers nothing");
    }

    /// A payload split across reads, with whole frames behind it in the read that
    /// finishes it.
    ///
    /// This is the interaction the two buffers have to get right: the frame in
    /// progress is assembled in `partial` and the frames behind it stay in
    /// `ready`, so completing the first has to leave the rest where it was. A
    /// decoder that rebuilt the buffer when it released the finished frame would
    /// lose them.
    #[test]
    fn a_frame_finished_by_a_read_that_also_carries_more_frames_is_decoded_with_them() {
        let first = frame(1, b"a payload long enough to split");
        let second = frame(2, b"and the next one");
        let mut decoder = LogDecoder::new(false);
        assert!(
            decoder.push(&first[..10]).expect("decodes").is_empty(),
            "half a payload is not a frame"
        );

        // The read that completes the first frame also carries the whole second
        // one, which is what a transport hands over most of the time.
        let mut read = first[10..].to_vec();
        read.extend_from_slice(&second);
        let frames = decoder.push(&read).expect("decodes");
        assert_eq!(frames.len(), 2, "both frames are owed to the caller");
        assert_eq!(frames[0].payload, b"a payload long enough to split");
        assert_eq!(frames[1].stream, LogStream::Stderr);
        assert_eq!(frames[1].payload, b"and the next one");
        decoder.finish().expect("the body ended on a boundary");
    }

    /// A read of many small frames is consumed without being copied.
    ///
    /// The property is that reading *n* frames costs one pass over the bytes, not
    /// *n* passes. Wall-clock would be the obvious way to assert that and it is
    /// the wrong instrument: it is a race against the machine the suite runs on,
    /// it fails on a loaded CI runner rather than on a bad decoder, and it cannot
    /// tell a quadratic decoder from a linear one until the quadratic is big enough
    /// to be slow — which is the very condition that makes such a test useless in
    /// a suite.
    ///
    /// So this checks *where the bytes live*. Every frame is handed over out of
    /// the transport's own `Bytes` by `split_to`, so that allocation is still the
    /// one behind `ready` for every frame. The shape being avoided copies the read
    /// into a `Vec` and takes frames off the front, which relocates everything
    /// behind each one — a buffer of its own, somewhere else in memory — and this
    /// fails on the first frame it hands over.
    #[test]
    fn a_read_of_many_frames_is_adopted_without_copying_the_read() {
        let unit = frame(1, b"xxxxxxxx");
        let frames_in_read = (1 << 16) / unit.len();
        let read = Bytes::from(unit.repeat(frames_in_read));
        let mut decoder = LogDecoder::new(false);

        decoder.absorb(read.clone());
        let mut handed = 0;
        while let Some(frame) = decoder.decode().expect("a small frame decodes") {
            handed += 1;
            assert_eq!(frame.payload.as_slice(), b"xxxxxxxx", "frame {handed}");
            assert!(
                points_into(&decoder.ready, &read),
                "frame {handed} was not sliced out of the transport's own read, so it came out of \
                 a copy: taking a frame off the front of a `Vec` moves everything behind it, \
                 which is what makes that shape quadratic in the number of frames"
            );
        }
        assert_eq!(handed, frames_in_read, "every frame in the read, once");
        assert_eq!(
            decoder.buffered(),
            0,
            "a fully consumed read buffers nothing"
        );
    }

    /// The same read through the door a live stream uses, which must adopt the
    /// transport's bytes rather than copy them.
    #[test]
    fn a_transport_read_is_adopted_rather_than_copied() {
        let unit = frame(1, b"xxxxxxxx");
        let frames_in_read = 1024;
        let read = Bytes::from(unit.repeat(frames_in_read));
        let mut decoder = LogDecoder::new(false);

        // Taken before the drain, because a fully consumed buffer is empty and an
        // empty buffer points nowhere worth comparing.
        decoder.absorb(read.clone());
        assert!(
            points_into(&decoder.ready, &read),
            "the transport's allocation was copied into a buffer of this crate's own, so every \
             byte of a container's output is copied twice on its way through"
        );

        let handed = decoder.drain_frames();
        assert_eq!(
            handed.len(),
            frames_in_read,
            "one read must surface every frame it holds"
        );
        assert_eq!(decoder.buffered(), 0);
    }

    /// The two doors onto the decoder must not disagree.
    ///
    /// [`LogDecoder::push`] is what a caller outside this crate reaches and
    /// `push_read` is what a live stream uses, so a change to one that the other
    /// did not get would be invisible until the paths diverged in production.
    #[test]
    fn the_slice_and_the_transport_read_decode_the_same_frames() {
        let mut body = Vec::new();
        body.extend(frame(1, b"one"));
        body.extend(frame(2, b""));
        body.extend(frame(0, b"three"));
        body.extend(frame(1, b"four"));
        body.extend(frame(1, b"a fifth\nwith a newline in it"));
        let read = Bytes::from(body.clone());

        // Ragged chunks, so the two paths also agree about a frame that spans
        // reads and about the zero-length one in the middle.
        let mut from_slice = LogDecoder::new(false);
        let mut from_bytes = LogDecoder::new(false);
        let mut sliced = Vec::new();
        let mut adopted = Vec::new();
        let mut offset = 0;
        for size in [1, 3, 8, 13, 21, 5, 1, 64] {
            let end = (offset + size).min(body.len());
            let chunk = &body[offset..end];
            sliced.extend(from_slice.push(chunk).expect("decodes"));
            adopted.extend(
                from_bytes
                    .push_read(&read.slice(offset..end))
                    .expect("decodes"),
            );
            offset = end;
        }
        from_slice.finish().expect("a clean end");
        from_bytes.finish().expect("a clean end");

        assert_eq!(sliced.len(), 4, "the empty frame carries nothing");
        assert_eq!(sliced, adopted, "the two doors must decode the same frames");
        assert_eq!(sliced[0].payload, b"one");
        assert_eq!(sliced[1].stream, LogStream::Stdin);
        assert_eq!(
            sliced[3].payload, b"a fifth\nwith a newline in it",
            "the payload is the write, not the line"
        );
    }

    /// The shape being avoided, written out, and what it costs on the same bytes.
    ///
    /// The test above says the work is not being done. This says what the work
    /// *would* be, in the five lines of the decoder this replaced — one `Vec`,
    /// appended to per read, drained from the front per frame — so the assertion
    /// above guards against a real alternative rather than a hypothetical one.
    ///
    /// Both numbers are arithmetic on one fixture, so nothing here depends on how
    /// fast the machine is. The comparison is what says the change was worth
    /// making rather than merely tidy.
    #[test]
    fn draining_a_read_from_the_front_relocates_proportionally_to_its_size() {
        let unit = frame(1, b"xxxxxxxx");
        let read_bytes = 1 << 16;
        let frames_in_read = read_bytes / unit.len();
        let payload_len = unit.len() - FRAME_HEADER_BYTES;

        // What the old shape did, and what each `drain` cost it: every byte after
        // the removed range moves to the front.
        let mut drained_from_front = unit.repeat(frames_in_read);
        let mut relocations = 0_usize;
        let mut drained_frames = 0_usize;
        while drained_from_front.len() >= FRAME_HEADER_BYTES {
            let length = u32::from_be_bytes(
                drained_from_front[4..8]
                    .try_into()
                    .expect("four bytes of length"),
            ) as usize;
            assert_eq!(length, payload_len, "the fixture is uniform");
            let end = FRAME_HEADER_BYTES + length;
            relocations += drained_from_front.len() - end;
            let _frame: Vec<u8> = drained_from_front
                .drain(..end)
                .skip(FRAME_HEADER_BYTES)
                .collect();
            drained_frames += 1;
        }

        // What this decoder does, on the same bytes.
        let read = Bytes::from(unit.repeat(frames_in_read));
        let mut decoder = LogDecoder::new(false);
        decoder.absorb(read.clone());
        let mut sliced_frames = 0_usize;
        while let Some(frame) = decoder.decode().expect("a small frame decodes") {
            assert_eq!(frame.payload.len(), payload_len);
            assert!(
                points_into(&decoder.ready, &read),
                "frame {sliced_frames} was not sliced out of the transport's own read"
            );
            sliced_frames += 1;
        }

        // Both deliver every frame, so the difference is entirely cost.
        assert_eq!(drained_frames, frames_in_read);
        assert_eq!(sliced_frames, frames_in_read);
        // Each drain moved everything still behind the frame it took, so the sum
        // is the read's own size once per frame, halving as the read empties:
        // `read_bytes * (frames_in_read - 1) / 2`.
        assert_eq!(
            relocations,
            read_bytes * (frames_in_read - 1) / 2,
            "the front-draining shape moved every remaining byte once per frame"
        );
        assert!(
            relocations > 1000 * read_bytes,
            "handing over {frames_in_read} frames cost {relocations} byte moves for {read_bytes} \
             bytes of body, and that ratio grows with the square of the frame count"
        );
        assert_eq!(
            decoder.partial.len(),
            0,
            "nothing had to be assembled: every frame arrived whole in one read"
        );
    }

    /// A frame split across reads is appended to, not re-joined.
    ///
    /// The other half of the linearity argument, and the half that is easy to get
    /// wrong: a decoder that keeps the partly arrived frame in one buffer has to
    /// join the next read to it, and joining *the whole partial payload* on every
    /// read is quadratic in the number of reads — measured on this host, doubling
    /// the frame from 1 MiB to 2 MiB and reading it in kilobytes took 174 ms
    /// against 736 ms, which is the 4x of a quadratic rather than the 2x of a
    /// linear one.
    ///
    /// So this checks where the bytes live too, on the path that has to assemble.
    /// The partial payload is this crate's own `Vec`, appended to per read, and
    /// what matters is that it never had to be copied out of a buffer and back.
    #[test]
    fn a_frame_split_across_reads_is_appended_to_rather_than_re_joined() {
        let total = 64 * 1024;
        let chunk = 1024;
        let mut decoder = LogDecoder::new(false);
        decoder
            .push(&header_of_length(1, length_of(&vec![0; total])))
            .expect("a frame inside the bound is read");
        let mut sent = 0;
        while sent < total {
            let end = (sent + chunk).min(total);
            decoder
                .push(&vec![b'z'; end - sent])
                .expect("a partly arrived payload is never refused");
            sent = end;
            if sent < total {
                // The whole of what has arrived, and nothing more: a decoder that
                // re-joined on every read would be holding a copy of the same bytes
                // somewhere as well.
                assert_eq!(
                    decoder.partial.len(),
                    sent,
                    "{sent} bytes sent and {sent} held, so the payload was appended to rather \
                     than copied out of a buffer and joined back to the next read"
                );
                assert!(
                    decoder.ready.is_empty(),
                    "{sent} bytes sent and nothing left over, so a read was not held twice"
                );
            }
        }
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn the_request_selects_the_container_and_its_bounds() {
        let options = ContainerLogOptions {
            follow: true,
            stdout: true,
            stderr: false,
            // Beyond the year 2038, which a 32-bit bound cannot express.
            since: 4_102_444_800,
            until: 0,
            timestamps: true,
            tail: "20".to_owned(),
            tty: false,
        };
        let request = logs_request("my container/1", &options).expect("request");
        assert_eq!(request.method, hyper::Method::GET);
        assert_eq!(
            request.path, "/containers/my%20container%2F1/logs",
            "the reference is escaped so it cannot reshape the path"
        );
        let query = request.query.expect("query");
        // Booleans are spelled `true`/`false` rather than `1`/`0`, which is the
        // convention every other owned request already uses; the Engine's Go
        // side parses both.
        for expected in [
            "follow=true",
            "stdout=true",
            "stderr=false",
            "since=4102444800",
            "until=0",
            "timestamps=true",
            "tail=20",
        ] {
            assert!(
                query.contains(expected),
                "query {query} is missing {expected}"
            );
        }
    }

    #[test]
    fn a_timestamp_beyond_2038_survives() {
        // The reason the owned options are not the narrower type some
        // generated clients use.
        let far = 4_102_444_800i64;
        assert_eq!(far.to_string(), "4102444800");
        assert!(
            i32::try_from(far).is_err(),
            "the value is outside a 32-bit bound, which is the whole point"
        );
        // The low 32 bits, read back as a signed value without a lossy cast, are
        // what a client using the narrower type would actually send.
        let low = i32::from_le_bytes(far.to_le_bytes()[..4].try_into().expect("four bytes"));
        assert_eq!(low, -192_522_496, "the 32-bit reading is a different date");
    }

    #[test]
    fn both_streams_are_selected_by_default() {
        // A logs call that returns nothing because nobody set a flag reads as
        // "the container logged nothing", which is a different and wrong
        // conclusion.
        let options = ContainerLogOptions::default();
        assert!(options.stdout && options.stderr);
        assert!(!options.follow);
    }

    #[test]
    fn an_empty_container_reference_is_rejected() {
        assert!(logs_request("", &ContainerLogOptions::default()).is_err());
    }

    #[test]
    fn a_reference_with_a_question_mark_cannot_add_a_query() {
        let options = ContainerLogOptions::default();
        let request = logs_request("c?follow=1", &options).expect("request");
        assert!(request.path.contains("%3F"), "path: {}", request.path);
        // The smuggled query stays in the path segment and cannot be parsed as
        // a parameter, because the real `?` never appears.
        assert!(!request.path.contains('?'));
    }

    fn body_len() -> usize {
        frame(1, b"to-stdout\n").len() + frame(2, b"to-stderr\n").len()
    }
}
