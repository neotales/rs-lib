//! Repository-owned request and response bodies for the raw Engine backend.
//!
//! The Engine API has three request shapes and two response shapes, and a
//! client that only handles one of them cannot express the whole contract:
//!
//! - requests with no body (`GET`, `DELETE`);
//! - requests with a single in-memory buffer (a JSON spec, a tar context);
//! - requests with a caller-owned stream (a large build context, an attached
//!   container's stdin), which must reach the socket incrementally rather than
//!   being buffered whole; and
//! - responses that are one bounded document, and responses that are an
//!   unbounded sequence of newline-delimited JSON frames.
//!
//! [`RawBody`] is the owned union of the request shapes and [`RawResponse`] is
//! the owned union of the response shapes. Keeping them here rather than
//! reconstructing them per operation is what lets a later operation be added
//! without revisiting the transport.
//!
//! Three properties are deliberate and load-bearing:
//!
//! - **Bounded documents.** A single-document response is read through
//!   [`RawResponse::document`], which refuses to buffer more than
//!   [`MAX_DOCUMENT_BYTES`]. The limit is enforced while reading, not from
//!   `Content-Length`, because a streaming or dishonest response does not carry
//!   an accurate one.
//! - **Bounded records.** A streaming response is a sequence of records, and
//!   [`FrameStream::next_json`] refuses to assemble one larger than
//!   [`MAX_RECORD_BYTES`]. Without it the memory a stream costs is set by the
//!   peer rather than by this crate: `/events` and `/stats` are long-lived
//!   streams where the daemon decides when a record ends, so a peer that never
//!   writes the terminator would grow the buffer until the process died. The
//!   check happens on the read that carries the record past the line, before
//!   those bytes are copied in, so what this crate holds for a record the daemon
//!   has not finished sending never exceeds the limit.
//!
//!   Records that arrive whole inside one read are not copied at all: they stay
//!   in the transport's own buffer and are sliced out of it, so a read carrying
//!   a hundred thousand small records costs this crate nothing per record and
//!   this crate's own memory stays at one partial record regardless. What is
//!   still held for the duration of a read is the transport's allocation that
//!   the slice points into, which is the read's own size and exists whether or
//!   not this client keeps a reference to it.
//! - **Streaming responses are never buffered whole.** [`RawResponse::into_frames`]
//!   hands back the frame stream as it arrives, so an endless stream costs a
//!   bounded amount of memory — one record, or one log frame, and never the
//!   length of the stream — and dropping it closes the connection. That drop is
//!   the cancellation mechanism; there is no separate cancel protocol.
//!
//! Two framings sit on top of that one stream, and both are here rather than in
//! an operation: [`FrameStream::next_json`] reads the Engine's
//! newline-delimited JSON, which is what `stats`, `events`, `build`, `pull`, and
//! `push` write, and [`crate::raw::LogDecoder`] reads the multiplexed frame
//! format, which is what a container without a TTY writes to `logs`. Keeping
//! both decoders next to the stream is what makes adding an operation a matter
//! of naming a request rather than of building a second streaming path.

use std::pin::Pin;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};

/// The largest single-document Engine response this client will buffer.
///
/// Engine documents such as `info` and `version` are kilobytes. A multi-megabyte
/// single-document response indicates something other than a normal Engine
/// answer, and buffering it without a limit would be a denial-of-service vector.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// The largest single record [`FrameStream::next_json`] will assemble.
///
/// A record is a complete JSON document on one line, and this bound is on the
/// assembled record rather than on the stream, so a stream that never ends
/// still costs a bounded amount of memory. It is enforced on the read that
/// carries a record past the line, before those bytes are copied in.
///
/// # Why this value, and not [`MAX_DOCUMENT_BYTES`]
///
/// [`MAX_DOCUMENT_BYTES`] is the bound for a whole response, and it is not
/// tight enough to hand to a long-lived stream: at 16 MiB a single peer can
/// hold every concurrent event or stats stream at 16 MiB of buffer, and there
/// is no reason a *record* needs what a whole document needs.
///
/// # The value, and what it stopped being derived from
///
/// The value is set from what a daemon actually emits, measured against Docker
/// Engine 29.7.2 serving API v1.55 on a 12-CPU, 67 GiB Linux host:
///
/// | stream | largest record observed |
/// | --- | --- |
/// | `GET /containers/{id}/stats?stream=true` | 1,726 bytes |
/// | `GET /events` (start, exec, pause, die) | 371 bytes |
/// | `GET /events` (`exec_create`, one record) | 4,195,572 bytes |
///
/// `stats` grows with the host's CPU count — the `percpu_usage` arrays carry
/// one entry per CPU — and `events` grows with the size of the object the event
/// is about. Neither is a fixed number, so the bound is not derived from the
/// table. The largest records have a real cause: an `exec_create` or
/// `exec_start` event echoes the whole `Cmd` array back, so the record is the
/// command line, and the command line is what the caller chose to hand
/// `docker exec`.
///
/// **This bound previously followed from `ARG_MAX`, and that argument was
/// wrong.** Linux caps the total of a command's arguments and environment at
/// `ARG_MAX` (2,097,152 bytes measured here) and a *single* argument at
/// `MAX_ARG_STRLEN` (128 KiB), but neither is a cap on the environment of a
/// process the daemon spawns on the caller's behalf, and a record carries the
/// environment as well as the command. A real `exec_create` record of
/// 4,195,572 bytes was refused by the 4 MiB bound this crate shipped, and the
/// size of that record is not a kernel limit at all — it is a caller who passed
/// a large argument vector, which the daemon will run. The refusal was not a
/// denial-of-service defence doing its job; it was a bound that could not tell a
/// legitimate record from a hostile one, and it got the legitimate one wrong.
///
/// So the value is now a round 8 MiB, chosen as **twice the largest record in
/// the table above** rather than as a multiple of anything a kernel enforces.
/// That is deliberately a slack factor over a measurement rather than a
/// derivation: the measurement is the honest floor, the factor covers the
/// host-to-host variation a single host's table cannot, and a round power of two
/// makes the number recognisable in a log line as a limit rather than as a
/// measurement. 8 MiB is about 4,860 times the largest `stats` record measured
/// here, and half of [`MAX_DOCUMENT_BYTES`] — still a bound, and still half the
/// memory a single peer could hold for one concurrent stream under the document
/// bound. It is not, and cannot be, a bound on what one caller may hand
/// `docker exec`; the paragraph below is about that.
///
/// That is a bound, not a promise: a daemon that emits a larger record — an
/// `exec_create` echoing a multi-megabyte command, or a peer streaming junk
/// with no newline at all — is refused here rather than buffered. A caller who
/// has measured a larger legitimate record on their own daemon raises the bound
/// per stream with [`FrameStream::with_record_limit`], which is why the default
/// is a constant this crate can change and the override is the one a caller owns.
///
/// That override is not a theoretical affordance. The same host measured here
/// carries `exec_create` records of 60,500,326 bytes, from a caller that passed
/// a 60 MB argument to `docker exec` — a command line far past the 2 MB
/// `ARG_MAX` the kernel would accept to run, echoed back verbatim by a daemon
/// that recorded the request rather than the run. So on a host where such a
/// caller exists, even 8 MiB refuses a record the daemon really sent, and the
/// only two correct answers are to raise the bound for that stream or to lose
/// the event. The crate's own `tests/ssh_dial_stdio.rs` does the former, and the
/// bound it asks for is a constant in the test file rather than a change to the
/// default — because a 60 MB event is a fact about one host's
/// one caller, and a default raised to cover it would hand that cost to every
/// concurrent stream on every host that has never seen such a record.
///
/// The limit is on the record and excludes the newline that terminates it, so a
/// record of exactly this many bytes is read and one byte more is refused. The
/// same bound applies whether the record arrives in one read or in a million.
///
/// # It bounds input bytes, not what the record becomes
///
/// This is a ceiling on the bytes of a record *as the daemon writes them*, checked
/// on the way in. It is not a ceiling on the memory a record occupies once
/// [`FrameStream::next_json`] has parsed it into a [`serde_json::Value`], and the
/// two are not proportional: a decoded value is a tree, and the shape a peer picks
/// decides how much bigger.
///
/// Measured on this host, holding the parsed value: a record shaped like the ones
/// a daemon really sends — a wide object of short strings — costs about what it
/// weighs, while a 4 MiB array of bare numbers holds **128 MiB** of live heap,
/// thirty-two times its own length, because every element is a whole `Value`. The
/// multiplier is a property of the record's *shape* and not of its size, so it is
/// not a number to quote: nesting amplifies further, and the arithmetic runs the
/// other way for the shapes this crate actually reads, where the ratio is near
/// one. Doubling the input ceiling doubles the worst case this table describes,
/// which is part of why it is a round 8 MiB and not a round number. What the
/// constant does fix is the input side, which is the side a peer chooses and the
/// side worth bounding.
///
/// So a caller reading several streams multiplies whatever this produces by the
/// number of them, and a caller who raises the bound with
/// [`FrameStream::with_record_limit`] raises the input a peer may present for
/// every one of those streams — the parsing cost and the resulting allocation
/// both scale from the new ceiling, not from the old one. Neither is anything this
/// crate bounds on a caller's behalf. A caller who needs a real ceiling on decoded
/// memory has to impose it where the values are: by holding fewer streams at once,
/// by bounding the item type rather than the transport, or by decoding a stream's
/// records into a borrowed or streamed form instead of a `Value`.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// The owned request body type used by the raw Engine transport.
pub type RequestBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// The handle that stops driving a response's connection.
///
/// hyper's HTTP/1 client only reads from the socket and fills the response body
/// while its connection future is being polled, and the documented way to
/// achieve that is to drive it as a task. The response keeps the abort handle so
/// dropping the response also stops the task.
pub type ConnectionDriver = tokio::task::AbortHandle;

/// An owned request body.
///
/// `Stream` is boxed so the type stays small: every request pays one pointer for
/// the streaming case, and the streaming case is the rare one.
pub enum RawBody {
    /// No request body.
    Empty,
    /// A complete, already-materialized body.
    Bytes(Bytes),
    /// A caller-owned stream of chunks, sent as they are produced.
    Stream(Pin<Box<dyn futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send>>),
}

impl std::fmt::Debug for RawBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("RawBody::Empty"),
            Self::Bytes(bytes) => write!(formatter, "RawBody::Bytes({} bytes)", bytes.len()),
            // A stream is never rendered: its chunks may carry build context or
            // credential material.
            Self::Stream(_) => formatter.write_str("RawBody::Stream"),
        }
    }
}

impl RawBody {
    /// Creates a body from a slice.
    #[must_use]
    pub fn from_slice(value: impl AsRef<[u8]>) -> Self {
        Self::Bytes(Bytes::copy_from_slice(value.as_ref()))
    }

    /// Creates a body from an owned buffer.
    #[must_use]
    pub fn from_bytes(value: Bytes) -> Self {
        Self::Bytes(value)
    }

    /// Creates a streaming body from a caller-owned stream.
    #[must_use]
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        Self::Stream(Box::pin(stream))
    }

    /// Returns the exact length when it is known before sending.
    ///
    /// An unknown length is sent with chunked transfer encoding, which the
    /// Engine accepts for streaming endpoints. A length is only reported for
    /// the shapes where it is provably correct, because announcing a length the
    /// body does not match would truncate the request.
    #[must_use]
    pub fn known_len(&self) -> Option<u64> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(bytes) => Some(bytes.len() as u64),
            Self::Stream(_) => None,
        }
    }

    /// Converts the body into the transport's request body type.
    pub fn into_request(self) -> RequestBody {
        match self {
            // `Full` is infallible, so its error type is uninhabited and the
            // conversion is a `match` rather than a fabricated error.
            Self::Empty => Full::new(Bytes::new()).map_err(unreachable).boxed_unsync(),
            Self::Bytes(bytes) => Full::new(bytes).map_err(unreachable).boxed_unsync(),
            Self::Stream(stream) => StreamBody::new(stream.map_ok(Frame::data)).boxed_unsync(),
        }
    }
}

/// Maps the uninhabited `Full` error type onto a real one.
fn unreachable(never: std::convert::Infallible) -> std::io::Error {
    match never {}
}

/// The two halves of a connection the daemon switched protocols on.
///
/// The halves are the same socket, split, so dropping both closes it and the
/// daemon observes the transfer ending. It is named because the type is long
/// enough that repeating it in a signature is a readability cost in itself, and
/// because the two halves must always be the same connection — a signature that
/// spelled them out separately would let a caller pair a read half with some
/// other connection's write half.
pub type SwitchedConnection = (SwitchedReadHalf, SwitchedWriteHalf);

/// The read half of a connection the daemon switched protocols on.
pub type SwitchedReadHalf = tokio::io::ReadHalf<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

/// The write half of a connection the daemon switched protocols on.
pub type SwitchedWriteHalf =
    tokio::io::WriteHalf<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

/// A response from the Engine API whose body has not been read.
///
/// The `Debug` impl is derived, which is the one place in this module where
/// that is the right answer rather than the lazy one. Every field renders
/// something bounded and already public:
///
/// - `body` is a hyper [`Incoming`] **that has not been read**, and hyper's own
///   `Debug` for it prints the body's *kind* — `Body(Streaming)` or
///   `Body(Empty)` — and never its bytes. The bytes this client will later
///   buffer are the Engine's to hand over, not this struct's to show, which is
///   the same reason [`RawBody`] counts a `Bytes` body instead of printing it.
/// - `extensions` prints the *type names* hyper stored, which is how the
///   `101` upgrade handle appears as `OnUpgrade` without the handle itself.
/// - `headers` are the daemon's own response headers. An Engine answer carries
///   its negotiation in them — `Api-Version`, `Ostype`, `Swarm`,
///   `Www-Authenticate` — and none of that is a credential; the registry
///   credential a request carries travels in the *request*, and a response body
///   is not rendered here.
///
/// A caller diagnosing a failed operation needs the status and the headers, and
/// a hand-written impl that omitted them would be a worse tool in exchange for
/// a guarantee this type does not need. `tests/debug_surface.rs` asserts the
/// body bytes cannot appear, so the property is checked rather than argued.
#[derive(Debug)]
pub struct RawResponse {
    /// The HTTP status code the daemon returned.
    pub status: hyper::StatusCode,
    /// The response headers.
    pub headers: hyper::HeaderMap,
    /// The response extensions, kept because hyper puts the pending `OnUpgrade`
    /// handle in them.
    ///
    /// They are not a public API for anything else, and nothing should read them
    /// but [`RawResponse::into_upgraded`]. Dropping them silently removed the
    /// only route back to a connection the daemon had switched protocols on.
    extensions: hyper::http::Extensions,
    body: Incoming,
    driver: Option<ConnectionDriver>,
}

impl RawResponse {
    /// Wraps an incoming hyper response together with the connection driving it.
    ///
    /// The driver is owned rather than spawned on purpose. A spawned driver
    /// belongs to the runtime that created it, so a caller that reads the body
    /// on a later runtime — or after the first one has been dropped — would see
    /// the socket close under it with no indication why. Owning it means the
    /// connection lives exactly as long as the response does.
    #[must_use]
    pub fn new(
        status: hyper::StatusCode,
        headers: hyper::HeaderMap,
        body: Incoming,
        driver: ConnectionDriver,
    ) -> Self {
        Self::with_extensions(
            status,
            headers,
            hyper::http::Extensions::new(),
            body,
            driver,
        )
    }

    /// Wraps an incoming hyper response together with the connection driving it,
    /// keeping the response extensions.
    #[must_use]
    pub fn with_extensions(
        status: hyper::StatusCode,
        headers: hyper::HeaderMap,
        extensions: hyper::http::Extensions,
        body: Incoming,
        driver: ConnectionDriver,
    ) -> Self {
        Self {
            status,
            headers,
            extensions,
            body,
            driver: Some(driver),
        }
    }

    /// Takes the connection the daemon switched protocols on, as a read half and
    /// a write half.
    ///
    /// This is what an operation like `attach` or an interactive `exec` needs: a
    /// live bidirectional connection, not a body. The read half is the raw stream
    /// rather than this response's `body`, because after a `101` the bytes arrive
    /// on the connection itself.
    ///
    /// # Errors
    ///
    /// Returns an error when the response carries no upgrade handle, which is
    /// what a daemon that did not answer `101` looks like, and when the
    /// connection cannot be taken.
    pub async fn into_upgraded(mut self) -> Result<SwitchedConnection, crate::Error> {
        // The handle is taken out of the extensions rather than read back through
        // `hyper::upgrade::on`, which needs a `Response` that this type does not
        // keep. hyper inserted it there when the daemon's answer was a `101`.
        let Some(upgrade) = self.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
            return Err(crate::Error::transport(format!(
                "the daemon answered {} rather than switching protocols, so there is no \
                 connection to take",
                self.status
            )));
        };
        // The response body belongs to the daemon's framing, not to the switched
        // connection, so it is released rather than read. Dropping the response
        // also aborts the driver task, which has already finished: the
        // upgrade-capable connection hands its parts to this handle and returns.
        drop(self);
        let upgraded = upgrade.await.map_err(|error| {
            crate::Error::transport(format!(
                "the daemon did not hand over a switched connection: {error}"
            ))
        })?;
        let (read, write) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
        Ok((read, write))
    }

    /// Returns whether the status is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Reads the body as one bounded buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the body cannot be read or exceeds
    /// [`MAX_DOCUMENT_BYTES`].
    pub async fn document(mut self) -> Result<Bytes, RawBodyError> {
        let mut collected = BoundedBuffer::new(MAX_DOCUMENT_BYTES);
        while let Some(frame) = self.body.frame().await {
            let frame = frame.map_err(RawBodyError::Transport)?;
            if let Some(data) = frame.data_ref() {
                collected.push(data)?;
            }
        }
        Ok(collected.finish())
    }

    /// Returns the frame stream for a response that never ends on its own.
    ///
    /// The returned handle borrows nothing, so a caller can keep polling it
    /// across awaits while the request is otherwise finished.
    ///
    /// Records read through [`FrameStream::next_json`] are bounded by
    /// [`MAX_RECORD_BYTES`]. A caller who has measured a larger legitimate
    /// record on their own daemon raises it with
    /// [`FrameStream::with_record_limit`].
    #[must_use]
    pub fn into_frames(self) -> FrameStream {
        FrameStream {
            response: self,
            records: RecordBuffer::new(),
        }
    }
}

impl Drop for RawResponse {
    /// Stops driving the connection when the response is abandoned.
    ///
    /// Dropping the body is already enough to close the socket — that is what
    /// makes the daemon observe a disconnect — but the driver task would keep
    /// being polled against a body nobody is reading. Aborting it as well means
    /// an abandoned streaming response costs nothing after it is dropped, rather
    /// than leaving a task and its buffer alive until the daemon closes the
    /// transfer.
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// A stream of response frames that the caller polls.
///
/// Dropping the stream drops the underlying body, which closes the connection
/// and aborts the transfer. Cancellation is therefore just "stop polling and
/// drop", with no out-of-band signal to get wrong.
pub struct FrameStream {
    response: RawResponse,
    /// The records the stream has not finished yet, and the bound on them.
    ///
    /// A network read lands wherever it lands, so a record can be split across
    /// any number of reads; records are handed over as soon as their newline
    /// arrives and a record that outgrows the limit is refused before its bytes
    /// are copied in, so what this crate holds for a record the daemon has not
    /// finished sending is bounded by the record bound rather than by the length
    /// of the stream.
    records: RecordBuffer,
}

impl std::fmt::Debug for FrameStream {
    /// Names the buffers and nothing else.
    ///
    /// The buffered bytes are container output, build progress, or registry
    /// credential material, so they are counted rather than rendered. A caller
    /// that formats a stream to report a failure therefore cannot leak its
    /// payload through a diagnostic.
    ///
    /// The two numbers are counted separately because they are held differently:
    /// `buffered` is this crate's own buffer for the record in progress, and
    /// `ready` is a slice of the transport's last read that has whole records
    /// still to hand over.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrameStream")
            .field("buffered", &self.records.buffered())
            .field("ready_records", &self.records.ready())
            .finish_non_exhaustive()
    }
}

impl FrameStream {
    /// Returns this stream with a caller-chosen per-record bound.
    ///
    /// The default is [`MAX_RECORD_BYTES`], and this exists so a caller who has
    /// *measured* a larger legitimate record on their own daemon can read it
    /// without waiting for a release. It cannot be reached by accident: the
    /// limit is a named argument rather than a field, so a caller has to write
    /// the number down and say so at the call site.
    ///
    /// The bound is the same in kind as the default — a ceiling on the assembled
    /// record, checked before the bytes are copied in — so raising it moves the
    /// bound rather than turning it off. Lowering it is equally allowed and is
    /// the other half of the point: a caller reading a known-small stream can
    /// hold the buffer down without changing the daemon's behaviour.
    ///
    /// Raising it is not free of consequence, and the thing to weigh is that the
    /// number is on *input* bytes. [`MAX_RECORD_BYTES`] says what this does and
    /// does not bound, and the short of it: a larger record is a larger input for
    /// [`Self::next_json`] to parse and a larger value for it to produce, and the
    /// ratio between them is the record's shape rather than this argument. A
    /// caller raising the bound on several concurrent streams is raising the work
    /// and the memory for all of them at once, so the concurrency is part of the
    /// decision even though it is not an argument here.
    ///
    /// It is a builder rather than an argument to [`RawResponse::into_frames`]
    /// because the operations that hand back a stream — `events`,
    /// `stats_stream`, `pull_stream`, `build` — return the
    /// [`FrameStream`] itself rather than a response, so a constructor argument
    /// would only be reachable on the paths that do not exist yet.
    ///
    /// # Panics
    ///
    /// Panics if the bound cannot be set — see [`Self::try_with_record_limit`],
    /// which is the same call without the panic and with the reason. Prefer it
    /// wherever the stream might already have been read: the panic here says a
    /// stream was configured after it had delivered records, and the alternative
    /// this used to have — silently replacing the reader — dropped those records
    /// without saying anything at all.
    ///
    /// # Examples
    ///
    /// ```
    /// use neotales_docker::raw::{FrameStream, MAX_RECORD_BYTES};
    ///
    /// fn allow_a_larger_record(stream: FrameStream) -> FrameStream {
    ///     stream.with_record_limit(MAX_RECORD_BYTES * 2)
    /// }
    ///
    /// let _ = allow_a_larger_record;
    /// ```
    #[must_use]
    pub fn with_record_limit(mut self, record_limit: usize) -> Self {
        self.try_with_record_limit(record_limit)
            .unwrap_or_else(|error| panic!("{error}"));
        self
    }

    /// Sets a caller-chosen per-record bound, or says why it cannot be set.
    ///
    /// The bound is fixed once the stream has been read from, and this is where
    /// that is enforced rather than documented. It cannot be enforced by refusing
    /// only the obvious states, because a fully drained buffer is empty in every
    /// one of them and is just as configured as a half-read one — so the reader
    /// records whether it has been read from at all, and that is what this checks.
    ///
    /// Enforcing it is not optional. A reader that has already been handed a
    /// record from the transport is holding bytes the daemon sent and the caller
    /// has not seen, and possibly a refusal in progress, and a fresh buffer has
    /// neither. Replacing one for the other is a *silent* failure: the stream
    /// keeps working, records the daemon sent are simply never delivered, and on
    /// `/events` that is an event a caller is waiting for that never arrives.
    ///
    /// Takes `&mut self` and returns `()` rather than being a consuming builder,
    /// so that a refused call leaves the caller's stream exactly as it was. A
    /// builder taking `self` would consume the stream on the error path, which is
    /// the data loss this exists to prevent, one level up.
    ///
    /// # Examples
    ///
    /// ```
    /// use neotales_docker::raw::{FrameStream, RecordLimitError};
    ///
    /// fn configure_record_limit(stream: &mut FrameStream) -> Result<(), RecordLimitError> {
    ///     stream.try_with_record_limit(64 * 1024)
    /// }
    ///
    /// let _ = configure_record_limit;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RecordLimitError::AlreadyReading`] once the stream has been read
    /// from, and [`RecordLimitError::ZeroLimit`] for a bound of zero. Neither
    /// leaves the stream modified.
    pub fn try_with_record_limit(&mut self, record_limit: usize) -> Result<(), RecordLimitError> {
        self.records.set_limit(record_limit)
    }

    /// Reads the next data frame, or `None` at end of stream.
    ///
    /// Trailer and other non-data frames are skipped rather than surfaced, so
    /// a caller implementing newline-delimited JSON never has to distinguish
    /// them.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails mid-transfer.
    pub async fn next_data(&mut self) -> Result<Option<Bytes>, RawBodyError> {
        loop {
            let Some(frame) = self.response.body.frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(RawBodyError::Transport)?;
            if let Some(data) = frame.data_ref() {
                return Ok(Some(data.clone()));
            }
        }
    }

    /// Reads the next complete newline-delimited JSON record, or `None` at end
    /// of stream.
    ///
    /// The Engine's `stats`, `events`, `build`, `pull`, and `push` endpoints all
    /// write one JSON value per line, and this is the reader for that shape. It
    /// is a decoder over [`FrameStream`], not a second streaming path: the
    /// transport, the connection lifetime, and the cancellation behaviour are
    /// the same, and dropping the stream still closes the socket.
    ///
    /// A record is returned as soon as its newline arrives, so an endless stream
    /// costs one record of memory. A blank line — the Engine uses one as a
    /// record separator in `build` output — yields `None` records and is
    /// skipped.
    ///
    /// A record that arrived whole inside one read is not copied out of it: it
    /// is a slice of the transport's own buffer, handed over as it is. Only a
    /// record split across reads is assembled, and only that buffer is this
    /// crate's own memory — so how many records a single read carried does not
    /// change what this client allocates.
    ///
    /// A final record with no trailing newline is returned. Measured against
    /// Docker Engine 29.8.0, `stats?stream=true` terminates every sample with a
    /// newline, so this only matters for a daemon that closes the connection
    /// immediately after writing; reporting the record is the difference between
    /// a caller seeing it and not.
    ///
    /// # Bounded records
    ///
    /// What a stream costs in memory is set here rather than by the peer: a
    /// record larger than this stream's `record_limit` — [`MAX_RECORD_BYTES`]
    /// unless the caller set its own — is refused rather than assembled, so a
    /// peer that never writes the terminator of a record cannot grow the buffer
    /// without bound. `/events` and `/stats` are the reachable case, because
    /// both are long-lived streams where the daemon, not the request, decides
    /// when a record ends.
    ///
    /// The check happens **before** the bytes are copied in, on the read that
    /// would carry the record past the line. A decoder that copied first and
    /// measured afterwards would have allocated the whole oversized record
    /// before refusing it, which is the same unbounded allocation with a check
    /// attached afterwards.
    ///
    /// A record of exactly `record_limit` bytes is read, and one byte more is
    /// refused. The newline that terminates a record does not count against the
    /// limit, so a stream that emits a maximal record and terminates it is
    /// accepted. The limit is on one record, so how the record was divided
    /// among reads does not change what is accepted: a record split into a
    /// thousand reads is bounded by the same number, and a read carrying fifty
    /// small records is fifty small records rather than one oversized one.
    ///
    /// # What the bound does not cover
    ///
    /// The bytes of one record the daemon has not finished sending, which is
    /// what a peer can keep extending without end. It does not cover the
    /// transport's own read buffer, and the honest reason is that this client
    /// does not own it or size it: a record that arrived whole is a slice of the
    /// buffer the transport read into, held until the caller has taken the last
    /// record in it. So a stream's peak is one partial record plus one
    /// transport read, where the second term is the transport's allocation and
    /// exists whether or not anything holds a reference to it — what is added is
    /// the *delay* before it is released, not the memory itself. Copying each
    /// read into a buffer of this crate's own instead would make the second term
    /// a second copy of the read rather than a refcount on the first, which is
    /// the worse of the two and is what this shape exists to avoid.
    ///
    /// The one thing that would put the read's size under this crate's
    /// control — a read smaller than the record limit — is not available here:
    /// the read size is the transport's, and asking for it to be smaller would
    /// mean a read per few hundred bytes on every stream in exchange for a
    /// bound the peer cannot reach anyway, since the peer chooses record
    /// lengths. So it is stated here rather than left to be discovered.
    ///
    /// It does not cover the [`serde_json::Value`] either, and this is the one a
    /// caller is most likely to be surprised by. The bound is on the record as
    /// the daemon wrote it; what this method returns is a parsed tree, and a tree
    /// of small elements is many times the size of the text it came from — a
    /// 4 MiB array of bare numbers, within the default limit, becomes a value
    /// holding about 128 MiB while the caller holds it — so a record at the full
    /// default bound would be worse still. The factor is a property of the
    /// record's shape and is not bounded by this limit, so a caller with
    /// several streams open multiplies it by the number of them, and a caller who
    /// raises the bound with [`Self::with_record_limit`] raises the input for all
    /// of them. [`MAX_RECORD_BYTES`] states the same thing next to the number
    /// that is being raised; it is repeated here because this is the method that
    /// does the parsing, and this is where the cost lands.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails mid-transfer, when a complete
    /// record is not JSON, when a record exceeds the bound above, or when the
    /// body ends part-way through a record. The last of those is deliberately an
    /// error: a truncated trailing record is indistinguishable from a whole one
    /// that happened to lack a newline, and guessing wrong either loses data the
    /// caller could have used or reports a daemon-side truncation as a clean
    /// end.
    ///
    /// The refusal is [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput)
    /// rather than `Transport`: the connection is fine and the daemon answered,
    /// and retrying the identical request would produce the identical stream.
    ///
    /// A refusal is terminal for the *record*, not for the stream. The buffered
    /// bytes are released, the refused record is not decoded, and any records
    /// that shared its read are kept, so a caller that keeps polling recovers at
    /// the next record rather than being handed the tail of a discarded one. The
    /// daemon sent one line this client will not accept, not a broken stream,
    /// and reporting that is more useful on a long-lived `/events`
    /// subscription than ending the transfer over it.
    pub async fn next_json(&mut self) -> Result<Option<serde_json::Value>, crate::Error> {
        loop {
            // A record the transport's read already carried whole. This is the
            // steady state on a stream of small records: the common case costs a
            // pointer bump and no copy, and the bytes are the transport's.
            if let Some(record) = self.records.next_record().map_err(oversized_record)? {
                if let Some(value) = decode_record(record.bytes())? {
                    return Ok(Some(value));
                }
                continue;
            }
            let Some(frame) = self.response.body.frame().await else {
                return self.finish_pending();
            };
            let frame =
                frame.map_err(|error| crate::Error::from(RawBodyError::Transport(error)))?;
            if let Some(data) = frame.data_ref() {
                // A read that finishes the record in progress hands it over
                // directly, rather than going round the loop to collect it. The
                // two shapes are one statement rather than two because they are
                // one thing: either a record was available, or it was not.
                let completed = self.records.push(data).map_err(oversized_record)?;
                if let Some(record) = completed
                    && let Some(value) = decode_record(record.bytes())?
                {
                    return Ok(Some(value));
                }
            }
        }
    }

    /// Decides what the bytes left at end of stream mean.
    fn finish_pending(&mut self) -> Result<Option<serde_json::Value>, crate::Error> {
        // The buffered bytes are within the limit by construction — `push` and
        // `append` refuse anything past it — so a trailing record here is a
        // record the daemon chose to leave unterminated, not one that outgrew
        // the bound.
        match self.records.take_trailing().map_err(oversized_record)? {
            None => Ok(None),
            Some(record) => decode_record(record.bytes()),
        }
    }
}

/// Why a per-record bound could not be set.
///
/// Reachable from [`FrameStream::try_with_record_limit`] and from
/// [`FrameStream::with_record_limit`], which wraps it and panics on this error.
/// Both variants answer a question about *when* the call was made rather than
/// about the daemon — which is why neither is an [`crate::Error`]: nothing about
/// the request or the connection is wrong, and a caller that sees one has a bug
/// in its own call site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordLimitError {
    /// The stream has already been read from, so its bound can no longer change.
    ///
    /// The records already delivered from the transport are held in the reader's
    /// buffers, and replacing those to apply a new bound would drop them. A caller
    /// that needs a different bound has to set it before the first read, or open a
    /// second stream.
    AlreadyReading,
    /// The bound was zero, which would refuse every record including the empty one.
    ZeroLimit,
}

impl std::fmt::Display for RecordLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReading => formatter.write_str(
                "the per-record bound can only be set before the stream is read; this stream \
                 has already delivered records, and replacing its buffer would drop them",
            ),
            Self::ZeroLimit => {
                formatter.write_str("a per-record bound of zero would refuse every record")
            }
        }
    }
}

impl std::error::Error for RecordLimitError {}

/// Reports a record the daemon wrote that this client will not assemble.
///
/// Typed rather than a bare string so the reader above has one place to compose
/// the diagnostic and a test can name the class instead of matching on a
/// message. It carries the length the record had *reached*, because "at least
/// N" is the honest statement: the record may have been longer, and the bytes
/// that would have said so are the ones that were not buffered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OversizedRecord {
    /// The most the record could be known to be, at the moment it was refused.
    assembled: usize,
    /// The bound it was refused against.
    limit: usize,
}

impl std::fmt::Display for OversizedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the Engine wrote a stream record of at least {} byte(s), over the {}-byte record \
             limit; the record was refused rather than buffered",
            self.assembled, self.limit
        )
    }
}

/// Composes the crate-level error for a refused record.
fn oversized_record(error: OversizedRecord) -> crate::Error {
    // `InvalidInput` rather than `Transport`: the connection is fine and the
    // daemon answered. The request produced a stream this client will not read,
    // which is the same class as a document that is not the shape the operation
    // expects, and retrying the identical request would produce the identical
    // stream.
    crate::Error::invalid_input(error.to_string())
}

/// One record, and where its bytes live.
///
/// Two variants because there are two ways a record arrives, and the difference
/// is a copy. A record the daemon wrote inside a single read is still the
/// transport's [`Bytes`], sliced to the record's extent, so handing it over
/// costs a pointer bump and this crate never allocates for it. Only a record
/// that arrives across several reads has to be assembled into a buffer this
/// crate owns, and that is the one the limit caps.
#[derive(Debug)]
enum Record {
    /// Assembled from more than one read, in a buffer this crate owns.
    Assembled(Vec<u8>),
    /// Wholly inside one transport read, and not copied out of it.
    InPlace(Bytes),
}

impl Record {
    /// The record's bytes, terminator excluded.
    ///
    /// `&[u8]` and not a `Cow`: a record is either one or the other, never
    /// both, and the caller decodes it out of whichever it is without deciding
    /// which.
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Assembled(bytes) => bytes,
            Self::InPlace(bytes) => bytes,
        }
    }

    /// Whether these bytes point inside `read`, the transport buffer they came
    /// from.
    ///
    /// This is the property the quadratic guard is built on, and it is checked by
    /// pointer rather than by asking the decoder to report what it did. A
    /// self-reported counter can only see the paths that increment it, and the
    /// hand-over in `next_record` is a path a counter might not cover — a decoder
    /// that copied the read into a `Vec` there and drained it from the front
    /// would report nothing wrong while doing the quadratic work. Aliasing cannot
    /// be faked that way: a copied record has its own allocation, wherever the
    /// counter is.
    ///
    /// Ranges rather than equality, because a record is a sub-slice of the read
    /// rather than the whole of it, and the last record in a read may share its
    /// final byte.
    #[cfg(test)]
    fn aliases(&self, read: &Bytes) -> bool {
        let start = read.as_ptr() as usize;
        let end = start + read.len();
        let record = self.bytes().as_ptr() as usize;
        record >= start && record + self.bytes().len() <= end
    }
}

/// Assembles newline-delimited records out of reads that do not line up with
/// them.
///
/// Separate from [`FrameStream`] so the bound is testable without a socket. The
/// interesting behaviour of this decoder is what it does with a record that
/// outgrows the limit, and a test that needs a loopback server to reach it is a
/// test that will be skipped the first time the fixture is inconvenient.
///
/// # Two buffers, and why
///
/// The shape that reads a whole transport read into a `Vec` and drains it from
/// the front looks simpler and is quadratic. `Vec::drain` relocates everything
/// after the removed range, so a read carrying *n* records moves the remaining
/// bytes *n* times. A one-megabyte read of eight-byte records is 116,508 of them,
/// and draining it moves **61,083,105,510 bytes — 56.9 GiB — for a megabyte of
/// payload**, 58,253× the read. The arithmetic is quadratic in the record count
/// and linear in the record length, so there is no read size at which it is
/// cheap; measured, that same fixture takes 1.03 s at 800 KB against 3.8 ms for
/// slicing it.
///
/// So the bytes that are already records are never copied in. They stay in the
/// transport's own [`Bytes`] as `ready`, and are handed out by
/// [`Bytes::split_to`], which moves a pointer. `partial` holds only the record
/// the daemon has not finished sending, and that is the only buffer this crate
/// grows — and it is the only one the limit has to cap, because it is the only
/// one whose length the peer decides.
#[derive(Debug)]
struct RecordBuffer {
    /// The bytes of a record the daemon has not finished sending.
    ///
    /// Never contains a terminator: `push` stops at the first one, so a non-empty
    /// `partial` always means "incomplete" and the two buffers below are never
    /// both populated. Never longer than `limit`, because `push` checks before
    /// it copies.
    partial: Vec<u8>,
    /// Whole records the last read carried, after `partial`'s.
    ///
    /// The transport's own bytes, sliced rather than copied. Holding them costs
    /// a refcount, not a second copy of the read, which is what makes this a
    /// streaming design rather than a per-read copy: this crate's own memory
    /// stays at one partial record no matter how many records a read carried.
    ready: Bytes,
    /// The largest record this buffer will assemble, in bytes.
    limit: usize,
    /// Whether the rest of a refused record is still arriving and must be thrown
    /// away rather than read.
    ///
    /// A record refused in a single read is gone: its terminator was in the same
    /// read, so `ready` already starts at the record after it. A record refused
    /// across reads is not — the terminator has not arrived yet, and the bytes
    /// that follow are its tail. Reading them as a record would hand the caller
    /// the middle of something it was already told about, so they are dropped
    /// until the terminator does arrive.
    discarding: bool,
    /// The most bytes of an *unterminated* record this crate has held, test-only.
    ///
    /// This is the memory the peer controls: how much of a record the daemon has
    /// not finished sending this crate is holding. It cannot be observed from the
    /// state *after* a refusal, because a refusal releases the buffer either way,
    /// so a decoder that copied first and measured afterwards would pass every
    /// assertion on what is left behind while having assembled the whole oversized
    /// record first.
    #[cfg(test)]
    high_water: usize,
    /// The most bytes of one record this crate has *copied out of a transport
    /// read*, test-only.
    ///
    /// A **copy count**, written on the one path that copies: a record that
    /// arrived in pieces, in `append` and in the assembled branch of `push`. A
    /// record that arrived whole in a read is never copied, so it does not move
    /// this number.
    ///
    /// It is deliberately *not* used as the algorithmic guard. A counter the code
    /// increments about itself cannot detect a change to a path it does not
    /// cover, and the hand-over in `next_record` is such a path: a decoder that
    /// copied the read into a `Vec` there and drained it from the front would
    /// leave this at zero while doing the quadratic work. The guard for that is
    /// [`Record::InPlace`] aliasing the transport's own allocation, which is
    /// checked by pointer rather than reported by the code under test.
    #[cfg(test)]
    assembled: usize,
    /// Whether a read has ever been pushed.
    ///
    /// A real field rather than a test-only one, because it is what
    /// [`RecordBuffer::set_limit`] guards, and a guard that only exists under
    /// `cfg(test)` is not a guard: a release build would take a different branch
    /// and the condition would be untested exactly where it is load-bearing. One
    /// `bool` per buffer is not worth a different rule in the two profiles.
    ///
    /// The distinction it draws is "empty because nothing has arrived" from
    /// "empty because everything has been handed over", and that is what makes
    /// replacing the limit safe: the first may have its bound replaced, the
    /// second must not, because replacing it would drop records already read from
    /// the transport and out of the caller's hands.
    read: bool,
}

impl RecordBuffer {
    /// Creates a buffer with the crate's default bound.
    fn new() -> Self {
        Self::with_limit(MAX_RECORD_BYTES)
    }

    /// Creates a buffer with a caller-chosen bound.
    ///
    /// # Panics
    ///
    /// Panics when `limit` is zero, which would refuse every record including
    /// the empty one. There is no useful meaning for a record bound that admits
    /// no records, and a caller that computed zero — a subtraction underflowed,
    /// a config field was empty — should find out where they passed the number
    /// rather than on the first record of every later stream.
    fn with_limit(limit: usize) -> Self {
        assert!(
            limit > 0,
            "a per-record bound of zero would refuse every record"
        );
        Self {
            partial: Vec::new(),
            ready: Bytes::new(),
            limit,
            discarding: false,
            #[cfg(test)]
            high_water: 0,
            #[cfg(test)]
            assembled: 0,
            read: false,
        }
    }

    /// The most bytes this crate's own buffer has held, test-only.
    #[cfg(test)]
    const fn high_water(&self) -> usize {
        self.high_water
    }

    /// Replaces the bound, refusing once the buffer has been read from.
    ///
    /// Reconstructing the buffer would be the obvious way to do this and it is
    /// wrong: a buffer that has already been read holds records the transport
    /// delivered and the caller has not seen, plus a refusal state that says a
    /// record is still arriving. Both live in the fields a fresh buffer would not
    /// have, so a new one would silently drop records the daemon sent and start
    /// reading a record the caller was already told about. An empty buffer is not
    /// enough to tell the cases apart, since a fully drained one is empty too,
    /// which is why the flag is separate from the lengths.
    ///
    /// # Errors
    ///
    /// Returns [`RecordLimitError::AlreadyReading`] once a read has been pushed,
    /// and [`RecordLimitError::ZeroLimit`] for a bound of zero. `ZeroLimit` can
    /// be fixed by retrying with any nonzero bound; `AlreadyReading` needs a
    /// fresh stream.
    ///
    /// The buffer is not modified on either path — the checks run to completion
    /// before the assignment — so a refused call leaves the caller's records and
    /// refusal state exactly as they were.
    fn set_limit(&mut self, limit: usize) -> Result<(), RecordLimitError> {
        if limit == 0 {
            return Err(RecordLimitError::ZeroLimit);
        }
        if self.read {
            return Err(RecordLimitError::AlreadyReading);
        }
        self.limit = limit;
        Ok(())
    }

    /// The most bytes copied out of a transport read for one record, test-only.
    ///
    /// A copy count rather than a time: see the `assembled` field's
    /// documentation for why that distinction is the whole point of the
    /// measurement, and for why it is not the algorithmic guard.
    #[cfg(test)]
    const fn assembled_high_water(&self) -> usize {
        self.assembled
    }

    /// Whether this buffer has ever been given a byte to read, test-only.
    ///
    /// Not the same as "is empty": a buffer that has been read and drained is
    /// empty and already configured, and replacing it would reset the refusal
    /// state along with the limit. [`Self::set_limit`] is what the flag guards.
    #[cfg(test)]
    const fn was_read(&self) -> bool {
        self.read
    }

    /// How many bytes are held for the record in progress.
    fn buffered(&self) -> usize {
        self.partial.len()
    }

    /// How many bytes of whole records are waiting to be handed over.
    ///
    /// Diagnostic only, and it is the transport's read size rather than
    /// anything the peer chose to keep sending: these bytes arrived in one
    /// `read` and this crate holds a slice of them rather than a copy.
    fn ready(&self) -> usize {
        self.ready.len()
    }

    /// Takes the next whole record, if one is waiting.
    ///
    /// Costs a pointer bump per record rather than a relocation, which is the
    /// whole difference between this and draining a `Vec` from the front: a
    /// read of *n* records is *n* pointer bumps here and *n* memmoves there.
    ///
    /// # Errors
    ///
    /// Returns an error when a record in `ready` is over the limit. It is
    /// checked here rather than when the read arrived, for the same reason the
    /// record is not copied when the read arrived: the bytes are not this
    /// crate's until they are handed over, and a record that was never assembled
    /// cannot cost anything to refuse.
    fn next_record(&mut self) -> Result<Option<Record>, OversizedRecord> {
        if self.ready.is_empty() {
            return Ok(None);
        }
        // `push` fills `ready` only when it also completes `partial`, and
        // `next_record` is what hands that record over, so the two are never
        // both populated, and `discarding` implies `ready` is empty: `push` runs
        // the discard itself, so by the time a caller asks for a record there is
        // nothing of the refused one left to discard.
        debug_assert!(
            self.partial.is_empty() && !self.discarding,
            "a record in progress and whole records at once"
        );
        let Some(newline) = self.ready.iter().position(|byte| *byte == b'\n') else {
            let head = self.ready.split_to(self.ready.len());
            self.append(&head)?;
            return Ok(None);
        };
        if newline > self.limit {
            // Drop the refused record and keep the ones behind it, so the caller
            // that keeps polling resumes at the next record. Its terminator was
            // in `ready` with it, so there is no tail still arriving and nothing
            // to discard.
            let _refused = self.ready.split_to(newline + 1);
            return Err(OversizedRecord {
                assembled: newline,
                limit: self.limit,
            });
        }
        // `split_to` twice rather than once to `newline + 1`: the terminator is
        // the record's, not the next one's, and slicing past it would put the
        // newline in front of the next record.
        //
        // Nothing is moved. `split_to` advances an offset, so handing over a
        // record out of a read carrying a thousand of them costs a thousand
        // pointer bumps and no relocations. The old shape, draining a `Vec` from
        // the front, cost a memmove per record — and the property that makes this
        // one linear is the returned `Record::InPlace` still pointing into the
        // read, which a test checks by address rather than by a counter this
        // function maintains about itself.
        let record = self.ready.split_to(newline);
        let _terminator = self.ready.split_to(1);
        Ok(Some(Record::InPlace(record)))
    }

    /// Throws away the rest of a refused record.
    ///
    /// A record refused in one read is gone — its terminator arrived with it. A
    /// record refused across reads is not: the terminator has not come yet, and
    /// the bytes still to arrive are its tail. The only thing that ends it is the
    /// terminator, so that is what this waits for.
    ///
    /// The tail is *dropped*, not measured, and that is the whole point. Finding
    /// the end by buffering the tail would be buffering exactly the bytes the
    /// refusal was raised to keep out of memory, one read later and under a
    /// different justification.
    ///
    /// Returns nothing, always: a record was found only in order to throw it away,
    /// so there is never a record to hand the caller from here.
    fn discard_until_terminator(&mut self) {
        let Some(newline) = self.ready.iter().position(|byte| *byte == b'\n') else {
            // Still arriving, and still nothing to find. The slice is dropped
            // rather than kept: it is a reference to the transport's read, and
            // holding it would keep that allocation alive across a read whose only
            // purpose is to be discarded.
            self.ready = Bytes::new();
            return;
        };
        // The refused record ends here, so whatever follows is a new record.
        // Clearing the flag is what makes the stream resume: leaving it set would
        // discard every later record too, which is a stream that never recovers
        // rather than one that skipped a line.
        self.discarding = false;
        self.ready = self.ready.slice(newline + 1..);
        // A blank line immediately after is not dropped. It is handed over as the
        // empty record it is, because the reader is the thing that skips blanks;
        // skipping it here would make this decoder decide what a record is, and
        // would be a special case a blank-line-bearing stream then depended on.
    }

    /// The record the body ended on, if there was one.
    ///
    /// A whole record the last read carried comes first; failing that, the bytes
    /// of a record the daemon never terminated. The second is a record rather
    /// than a truncation only because it is within the limit, which is what
    /// makes reporting it better than dropping it.
    fn take_trailing(&mut self) -> Result<Option<Record>, OversizedRecord> {
        if let Some(record) = self.next_record()? {
            return Ok(Some(record));
        }
        let assembled = std::mem::take(&mut self.partial);
        Ok((!assembled.is_empty()).then_some(Record::Assembled(assembled)))
    }

    /// Appends a read, returning the record when that read finished it.
    ///
    /// The limit is checked against what the record would become and the bytes
    /// are not taken until it passes, so a refused record is never assembled.
    /// `data` is the transport's own buffer, so refusing costs nothing: no copy
    /// has been made and the slice this crate would have taken is dropped.
    ///
    /// Bytes after the record's terminator are whole records that the transport
    /// still owns, and they are sliced into `ready` rather than appended. That
    /// is both the streaming property and the linear-time property — the read is
    /// walked once, here, and every record behind the terminator is then handed
    /// over without another pass over the bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the record this read completes or extends is over
    /// the limit, and releases the bytes held for it. The records behind it in
    /// the same read are kept, so a caller that keeps polling resumes at the next
    /// record: the read that carried an oversized record usually carried the
    /// next one too, and a decoder that dropped the whole read would report the
    /// bad line and then lose a good one.
    fn push(&mut self, data: &Bytes) -> Result<Option<Record>, OversizedRecord> {
        // The reader drains `ready` before asking for a read, so these are the
        // only unconsumed bytes.
        debug_assert!(
            self.ready.is_empty(),
            "a read arrived with records still to hand over"
        );
        self.read = true;
        if self.discarding {
            // The refused record is still arriving. Its bytes are dropped rather
            // than buffered, so the memory the caller was protected from does not
            // come back one read later.
            self.ready = data.clone();
            self.discard_until_terminator();
            return Ok(None);
        }
        let Some(newline) = data.iter().position(|byte| *byte == b'\n') else {
            self.append(data)?;
            return Ok(None);
        };
        // What follows the terminator is whole records, still the transport's.
        self.ready = data.slice(newline + 1..);
        if self.partial.is_empty() {
            // Nothing was being assembled, so this record is wholly inside the
            // read and can be handed over as a slice of the transport's bytes.
            if newline > self.limit {
                return Err(OversizedRecord {
                    assembled: newline,
                    limit: self.limit,
                });
            }
            return Ok(Some(Record::InPlace(data.slice(..newline))));
        }
        // The terminator is not part of the record, so it does not count against
        // the limit. The record is released before the check so a refusal does not
        // leave a partial record for the caller to be handed as the next one, and
        // the length is measured before the release, because the bytes are about
        // to be gone.
        let mut assembled = std::mem::take(&mut self.partial);
        let total = assembled.len().saturating_add(newline);
        if total > self.limit {
            // Read before releasing, on the refusal path as well as the success
            // path: a decoder that copied first and measured second clears the
            // buffer here too, so nothing left behind would tell the two apart.
            #[cfg(test)]
            {
                self.high_water = self.high_water.max(assembled.len());
            }
            // The terminator arrived with this read, so the record is whole and
            // there is no tail still to come: `discarding` stays false and the
            // records behind this one in the same read are still read. Setting it
            // here would discard them too, which loses good records to a bad one
            // that was already refused.
            return Err(OversizedRecord {
                assembled: total,
                limit: self.limit,
            });
        }
        assembled.extend_from_slice(&data[..newline]);
        #[cfg(test)]
        {
            self.high_water = self.high_water.max(assembled.len());
            // One copy, of one record. Not one per read: the record's earlier
            // pieces are already in `assembled` and this adds only what this read
            // carried.
            self.assembled = self.assembled.max(assembled.len());
        }
        Ok(Some(Record::Assembled(assembled)))
    }

    /// Appends a read that ends no record, refusing when the record crosses the
    /// limit.
    fn append(&mut self, data: &[u8]) -> Result<(), OversizedRecord> {
        let total = self.partial.len().saturating_add(data.len());
        if total > self.limit {
            // Read the buffer before releasing it, and on the refusal path as
            // well as the success path: a decoder that copied first and checked
            // second clears the buffer here too, so nothing left behind would
            // tell the two apart.
            #[cfg(test)]
            {
                self.high_water = self.high_water.max(self.partial.len());
            }
            self.partial = Vec::new();
            // This read ended no record, so the refused one is still arriving and
            // its remaining bytes have to be thrown away rather than read as the
            // next record.
            self.discarding = true;
            return Err(OversizedRecord {
                assembled: total,
                limit: self.limit,
            });
        }
        self.partial.extend_from_slice(data);
        #[cfg(test)]
        {
            // The buffer's high-water mark, which is the memory: a refused record
            // is refused before this line, so it never reaches the mark.
            self.high_water = self.high_water.max(self.partial.len());
            // The copy count, which is the work: every read of an unfinished
            // record copies what it carried, so this grows with the record's
            // length however many reads took to assemble it — and with nothing
            // else.
            self.assembled = self.assembled.max(self.partial.len());
        }
        Ok(())
    }
}

/// Decodes one newline-delimited record, skipping the blank lines the Engine
/// uses as record separators.
fn decode_record(line: &[u8]) -> Result<Option<serde_json::Value>, crate::Error> {
    let trimmed = super::transport::trim_ascii(line);
    if trimmed.is_empty() {
        return Ok(None);
    }
    super::transport::decode(trimmed).map(Some)
}

/// Errors from reading a response body.
#[derive(Debug)]
pub enum RawBodyError {
    /// The body exceeded [`MAX_DOCUMENT_BYTES`] while being buffered.
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The connection failed or the body was malformed.
    Transport(hyper::Error),
}

impl std::fmt::Display for RawBodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(formatter, "Engine response exceeds the {limit}-byte limit")
            }
            Self::Transport(error) => {
                write!(formatter, "Engine response transport error: {error}")
            }
        }
    }
}

impl std::error::Error for RawBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

/// An accumulator that refuses to grow past its limit.
///
/// The limit is checked on every push rather than once at the end, so an
/// oversized response is refused as soon as it crosses the line instead of after
/// the whole body has already been allocated.
struct BoundedBuffer {
    buffer: Vec<u8>,
    limit: usize,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            limit,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), RawBodyError> {
        if self.buffer.len().saturating_add(chunk.len()) > self.limit {
            return Err(RawBodyError::TooLarge { limit: self.limit });
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn finish(self) -> Bytes {
        Bytes::from(self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_DOCUMENT_BYTES, MAX_RECORD_BYTES, RawBody, RawBodyError};
    use bytes::Bytes;

    #[test]
    fn a_buffered_body_reports_its_exact_length_and_a_stream_reports_none() {
        assert_eq!(RawBody::Empty.known_len(), Some(0));
        assert_eq!(RawBody::from_slice("abc").known_len(), Some(3));
        let stream = futures_util::stream::iter(vec![Ok(Bytes::from_static(b"a"))]);
        assert_eq!(RawBody::from_stream(stream).known_len(), None);
    }

    #[test]
    fn a_streaming_body_never_renders_its_contents() {
        // Build contexts and registry credentials travel in streamed bodies, so
        // rendering one into a log or an error message would leak them.
        let stream = futures_util::stream::iter(vec![Ok(Bytes::from_static(b"hunter2"))]);
        let rendered = format!("{:?}", RawBody::from_stream(stream));
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn a_buffered_body_debug_reports_only_its_size() {
        let rendered = format!("{:?}", RawBody::from_slice("hunter2"));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("7 bytes"), "{rendered}");
    }

    #[test]
    fn the_document_limit_is_refused_while_reading_not_after() {
        // Filling the buffer exactly to the limit succeeds, because a response
        // of exactly the documented size is legitimate.
        let mut exact = super::BoundedBuffer::new(8);
        exact.push(b"12345678").expect("exactly at the limit");
        assert_eq!(exact.finish().len(), 8);

        // One byte more is refused, and the refusal names the bound that was
        // exceeded so the diagnostic is actionable.
        let mut past = super::BoundedBuffer::new(8);
        past.push(b"12345678").expect("exactly at the limit");
        let error = past.push(b"9").expect_err("past the limit");
        assert!(
            matches!(error, RawBodyError::TooLarge { limit: 8 }),
            "{error:?}"
        );
    }

    #[test]
    fn a_single_oversized_chunk_is_refused_without_buffering_it() {
        let mut buffer = super::BoundedBuffer::new(4);
        let error = buffer.push(b"123456").expect_err("past the limit");
        assert!(matches!(error, RawBodyError::TooLarge { limit: 4 }));
    }

    #[test]
    fn the_default_document_limit_is_a_real_bound() {
        // A compile-time assertion, so changing the constant to something
        // unbounded or absurd fails the build rather than a test run.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        const { assert!(MAX_DOCUMENT_BYTES <= 64 * 1024 * 1024) };
    }

    #[test]
    fn the_default_record_limit_is_a_real_bound() {
        // The same compile-time gate as the document limit, plus the two
        // properties the choice of the value rests on. A record bound of zero
        // refuses every record, so the constructor would panic on every stream;
        // a record bound above the document bound would be a stream that accepts
        // records the crate already refuses as documents, which is the
        // inconsistency the two constants exist to prevent.
        const { assert!(MAX_RECORD_BYTES > 0) };
        const { assert!(MAX_RECORD_BYTES <= MAX_DOCUMENT_BYTES) };
    }

    /// The `exec_create` event record that a real daemon emitted and the 4 MiB
    /// bound this crate used to ship refused.
    ///
    /// Recorded rather than invented, because the whole argument for the current
    /// default is that a real record was turned away by the old one. A round
    /// number of bytes would have made the same point with less to be wrong
    /// about.
    const OBSERVED_EXEC_CREATE_EVENT: usize = 4_195_572;

    #[test]
    fn the_default_record_limit_admits_a_record_a_real_daemon_emitted() {
        // The regression this default exists for. The 4 MiB bound the crate
        // shipped refused a real `GET /events` record of 4,195,572 bytes — an
        // `exec_create` echoing the caller's own `Cmd` — and the refusal was not
        // a defence working: the size is a caller's argument vector, not a
        // kernel limit, so the bound could not tell that record from a hostile
        // one and got the legitimate one wrong.
        //
        // Pinned against the recorded size rather than against a freshly chosen
        // number, so raising the constant above the measurement is a decision
        // somebody has to make rather than one this test quietly absorbs.
        //
        // A `const` block, so it is a build failure rather than a test failure —
        // the crate's own gate for a constant's properties, and the reason a
        // redefinition of this bound is a compile error and not something a
        // release pipeline can miss by not running tests.
        const {
            assert!(
                MAX_RECORD_BYTES > OBSERVED_EXEC_CREATE_EVENT,
                "the default record bound must admit a real daemon's exec_create event"
            );
        }
    }

    #[test]
    fn the_default_record_limit_is_still_a_bound_and_still_refuses() {
        // The other half, and the reason the value is a round multiple of the
        // measurement rather than the measurement itself. Raising the default
        // must not have raised it to "whatever a peer presents": a stream with
        // no newline at all must still be refused at a fixed ceiling, and a
        // caller who raises the bound further does so per stream, explicitly.
        //
        // The relationship to the measurement is the argument, so it is asserted
        // as a relationship rather than left implicit. The bound must stay a
        // **round power of two** — that is what makes it recognisable in a log
        // line as a limit rather than as a measurement — and it must stay a
        // **small multiple** of the largest record a daemon really emitted, so
        // it remains a bound chosen from a measurement rather than a ceiling
        // someone liked. The slack is the part that is not 2x exactly: 8 MiB is
        // the next power of two above the record, and 2 * 4,195,572 is not a
        // power of two, so asserting equality with the double would be asserting
        // a number the reasoning never claimed.
        const {
            assert!(
                MAX_RECORD_BYTES.is_power_of_two(),
                "the default record bound must be a round power of two; the roundness is how a \
                 reader tells a limit from a measurement"
            );
        }
        const {
            assert!(
                MAX_RECORD_BYTES <= 4 * OBSERVED_EXEC_CREATE_EVENT,
                "the default record bound must stay within a small multiple of the largest record \
                 a daemon was measured to emit, so the value is still derived from the \
                 measurement"
            );
        }

        // The refusal itself, at the shipped number rather than a stand-in.
        let mut past = Reader::new(MAX_RECORD_BYTES);
        past.feed(&record_of(MAX_RECORD_BYTES + 1));
        assert_eq!(past.refused.len(), 1, "{:?}", past.refused);
        assert_eq!(past.refused[0].limit, MAX_RECORD_BYTES);
        assert!(
            past.records.is_empty(),
            "a refused record must not also be delivered"
        );
    }

    /// Builds a record of exactly `len` bytes that parses as JSON.
    ///
    /// A record is a JSON document on one line, so a boundary test that used a
    /// run of `x` would be testing a length the daemon never sends. This is
    /// `{"k":"aaa…"}` with the padding sized so the whole record is `len` bytes.
    fn record_of(len: usize) -> Vec<u8> {
        const OPEN: &[u8] = b"{\"k\":\"";
        const CLOSE: &[u8] = b"\"}";
        let envelope = OPEN.len() + CLOSE.len();
        assert!(len >= envelope, "the envelope alone is eight bytes");
        let mut record = OPEN.to_vec();
        record.extend(std::iter::repeat_n(b'x', len - envelope));
        record.extend_from_slice(CLOSE);
        assert_eq!(record.len(), len, "the padding is what makes the length");
        record
    }

    /// A record with its terminator, as the transport would deliver it.
    fn terminated(len: usize) -> Vec<u8> {
        let mut record = record_of(len);
        record.push(b'\n');
        record
    }

    /// Drives a [`RecordBuffer`] the way [`FrameStream::next_json`] does.
    ///
    /// Feeds reads, takes every record each one yields, and keeps going after a
    /// refusal, because that is the order the reader uses and the property under
    /// test is often about what happens *after* something. Without this the
    /// tests would each restate the loop, and a restatement is where a
    /// difference from the real one hides.
    struct Reader {
        buffer: super::RecordBuffer,
        records: Vec<Vec<u8>>,
        refused: Vec<super::OversizedRecord>,
    }

    impl Reader {
        fn new(limit: usize) -> Self {
            Self {
                buffer: super::RecordBuffer::with_limit(limit),
                records: Vec::new(),
                refused: Vec::new(),
            }
        }

        /// Collects one record, dropping a blank one.
        ///
        /// Takes the record by reference and copies what it keeps, which is the
        /// only copy in a test: the records are compared against what was fed, so
        /// they outlive the buffer's view of them.
        ///
        /// Blanks are dropped because the reader drops them — `decode_record`
        /// turns an empty line into no record, the Engine uses one as a
        /// separator — and a driver that kept them would count a record no caller
        /// sees. It matters after a refusal in particular: the newline that ended
        /// the refused record arrives as its own read, and reading it as an empty
        /// record is the reader's behaviour, not a leak of the refused bytes.
        fn collect(&mut self, record: &super::Record) {
            if !record.bytes().is_empty() {
                self.records.push(record.bytes().to_vec());
            }
        }

        /// Feeds one read and collects everything it produced.
        ///
        /// The record a read completes is collected here rather than on the next
        /// call, because that is what the reader does: `push` hands it straight
        /// over. A test driver that dropped it and waited for `next_record` would
        /// be testing a shape the reader does not have.
        fn feed(&mut self, read: &[u8]) -> &mut Self {
            let data = Bytes::copy_from_slice(read);
            match self.buffer.push(&data) {
                Ok(Some(record)) => self.collect(&record),
                Ok(None) => {}
                Err(error) => self.refused.push(error),
            }
            self.drain();
            self
        }

        /// Feeds every read in turn.
        fn feed_all(&mut self, reads: &[&[u8]]) -> &mut Self {
            for read in reads {
                self.feed(read);
            }
            self
        }

        /// Takes every record waiting, leaving the buffer empty of them.
        ///
        /// Bounded, and the bound is the point. The reader's own loop is "until
        /// there is nothing left", and a decoder that never consumes what it is
        /// given — a refused record it does not drop, say — makes that loop
        /// infinite. Without a bound the failure is a hung test suite rather than a
        /// failed assertion, which is a much worse report: it says nothing about
        /// what broke, and it is exactly the shape a well-meaning but wrong
        /// decoder takes. This was found by a mutation, not by reasoning.
        ///
        /// A million calls, which is nine times the densest fixture here (116,508
        /// records in one read) and still reached in a fraction of a second, so
        /// the bound cannot mask a decoder that drops records — only one that
        /// invents them.
        fn drain(&mut self) -> &mut Self {
            const CEILING: usize = 1 << 20;
            for _ in 0..CEILING {
                match self.buffer.next_record() {
                    Ok(Some(record)) => self.collect(&record),
                    Ok(None) => return self,
                    Err(error) => self.refused.push(error),
                }
            }
            panic!(
                "the reader produced records for {CEILING} calls without running out; a decoder \
                 that does not consume what it is given makes the reader's loop infinite"
            );
        }

        /// Ends the stream and collects the record it ended on, if any.
        fn finish(&mut self) -> Result<Option<Vec<u8>>, super::OversizedRecord> {
            self.drain();
            Ok(self
                .buffer
                .take_trailing()?
                .map(|record| record.bytes().to_vec()))
        }
    }

    #[test]
    fn a_record_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() {
        // The boundary, asserted on both sides because a bound that is off by
        // one in the refusing direction rejects a legitimate record and one that
        // is off by one in the accepting direction does not bound anything.
        let mut exact = Reader::new(64);
        exact.feed_all(&[&record_of(64), b"\n"]);
        assert_eq!(exact.records, vec![record_of(64)], "a record at the limit");
        assert!(exact.refused.is_empty(), "{:?}", exact.refused);

        let mut past = Reader::new(64);
        past.feed(&record_of(65));
        assert_eq!(
            past.refused,
            vec![super::OversizedRecord {
                assembled: 65,
                limit: 64
            }],
            "the refusal names the length reached and the limit it crossed"
        );
        assert!(past.records.is_empty(), "the refused record was returned");
    }

    #[test]
    fn a_refused_record_is_not_accepted_after_the_bytes_arrive_in_pieces() {
        // The same record, delivered one byte at a time. A decoder that checked
        // the bound only against a whole read would pass the test above and
        // fail this one, which is the whole point of checking per push: the
        // transport decides where reads land, and the bound cannot depend on it.
        let over = record_of(65);
        let reads: Vec<Bytes> = over.iter().map(|byte| Bytes::from(vec![*byte])).collect();
        let mut reader = Reader::new(64);
        for read in &reads {
            reader.feed(read);
        }
        assert_eq!(
            reader.refused,
            vec![super::OversizedRecord {
                assembled: 65,
                limit: 64
            }],
            "a record split across reads must meet the same bound"
        );
        assert!(reader.records.is_empty());
    }

    #[test]
    fn an_unterminated_record_never_grows_the_buffer_past_the_limit() {
        // The buffer, for a record the daemon has not finished sending, never
        // holds more than the limit. This is the memory a caller is actually
        // paying for and the thing the bound exists to cap, so it is measured
        // rather than inferred from the state after a refusal: a refusal empties
        // the buffer either way, which means the leftover state alone cannot
        // tell a decoder that refused first from one that allocated and then
        // noticed.
        //
        // Across the sweep rather than at a chosen length, because the property
        // is about a maximum and a maximum is only pinned by the lengths around
        // it.
        let limit = 32;
        for len in 8..=(limit + 4) {
            for shape in ReadShape::ALL {
                let mut buffer = super::RecordBuffer::with_limit(limit);
                let read = terminated(len);
                for chunk in shape.split(&read) {
                    let data = Bytes::from(chunk);
                    let _unused = buffer.push(&data);
                }
                assert!(
                    buffer.high_water() <= limit,
                    "{len} bytes, {shape}: the buffer held {} bytes of an unterminated record, \
                     over a {limit}-byte limit",
                    buffer.high_water()
                );
            }
        }
    }

    #[test]
    fn a_refusal_on_the_read_that_completes_a_record_never_assembles_it() {
        // The one read shape the length sweep does not reach: the record's
        // terminator arrives in a read that *also* carries the bytes after it.
        //
        // A read that ends a record and continues into the next is the ordinary
        // case whenever the transport's read boundary lands there, and it is the
        // only path that takes the record out of `partial`, measures it, and
        // appends what the read carried. The check on that path has to be before
        // the append: a decoder that appended first would have assembled the
        // record it is about to refuse.
        //
        // The assertion is on the buffer's high-water mark rather than on the
        // error, because the error is the same either way and the error is not the
        // property.
        let limit = 32;
        for len in [limit + 1, limit + 2, limit + 8, limit * 2] {
            let record = record_of(len);
            // Read one is exactly the bound, so the record is still arriving and
            // still within it. A first piece that were already over the bound
            // would be refused by `append`, which is a different path and is what
            // the length sweep covers.
            let mut second = record[limit..].to_vec();
            second.push(b'\n');
            second.extend_from_slice(&terminated(12));

            let mut buffer = super::RecordBuffer::with_limit(limit);
            let first = Bytes::copy_from_slice(&record[..limit]);
            assert!(
                buffer.push(&first).is_ok(),
                "{len} bytes: a first piece at the bound must be within it"
            );
            let second = Bytes::from(second);
            let error = buffer
                .push(&second)
                .expect_err("the read that completed an oversized record must refuse it");
            assert_eq!(
                error,
                super::OversizedRecord {
                    assembled: len,
                    limit
                },
                "{len} bytes: refused at the wrong length"
            );
            assert!(
                buffer.high_water() <= limit,
                "{len} bytes: the read that completed the record assembled {} bytes before \
                 refusing it",
                buffer.high_water()
            );
            // The record that shared the read is still there.
            assert_eq!(
                buffer
                    .next_record()
                    .expect("no error")
                    .expect("the following record is kept")
                    .bytes(),
                record_of(12),
                "{len} bytes: the record behind the refused one was lost"
            );
        }
    }

    #[test]
    fn a_refused_record_is_not_left_buffered() {
        // The other half, and the part that is observable from outside: a
        // caller that keeps polling after a refusal must not be handed the
        // refused record or its tail as if it were the next one.
        let mut reader = Reader::new(64);
        reader.feed(&record_of(65));
        assert_eq!(reader.refused.len(), 1);
        assert_eq!(
            reader.buffer.buffered(),
            0,
            "the refused record must not be left buffered"
        );
        assert!(reader.records.is_empty());
    }

    #[test]
    fn a_refused_record_releases_the_bytes_already_held() {
        // A peer that sends most of a record and then crosses the line leaves
        // bytes in the buffer. A caller that keeps polling must not be handed
        // that record's tail as if it were the next one, so the partial record
        // is released rather than kept.
        let mut reader = Reader::new(64);
        reader.feed(b"{\"k\":\"");
        assert_eq!(reader.buffer.buffered(), 6);
        reader.feed(&[b'x'; 64]);
        assert_eq!(
            reader.refused,
            vec![super::OversizedRecord {
                assembled: 70,
                limit: 64
            }]
        );
        assert_eq!(
            reader.buffer.buffered(),
            0,
            "the partial record is released"
        );
        assert!(
            reader.records.is_empty(),
            "a released record must not be returned later"
        );
    }

    #[test]
    fn a_refused_record_keeps_the_records_that_shared_its_read() {
        // The read that carried an oversized record usually carried the next one
        // as well, and a decoder that dropped the whole read would report the bad
        // record and then lose a good one. On `/events` that is the difference
        // between one refused line and a silently shortened subscription.
        let oversized = record_of(96);
        let following = record_of(12);
        let mut read = oversized.clone();
        read.push(b'\n');
        read.extend_from_slice(&terminated(12));

        let mut reader = Reader::new(64);
        reader.feed(&read);
        assert_eq!(
            reader.refused,
            vec![super::OversizedRecord {
                assembled: 96,
                limit: 64
            }]
        );
        assert_eq!(
            reader.records,
            vec![following],
            "the record that shared the refused record's read was lost"
        );
    }

    #[test]
    fn a_refused_record_with_no_terminator_discards_its_tail_and_resumes_after() {
        // The peer that never terminates a record, the reachable remote case on
        // `/events` and `/stats`. The refusal lands on the read that crossed the
        // line, and the record is *still arriving* — so the bytes that follow are
        // its tail, and reading them as a record would hand the caller the middle
        // of something it was already told about.
        //
        // So they are thrown away until the terminator that ends the refused
        // record arrives, and the record after *that* is read normally. The
        // alternative — resuming at the next read — is unrecoverable: there is
        // nothing for a caller to match those bytes against.
        let mut reader = Reader::new(64);
        reader.feed(&[b'x'; 128]);
        assert_eq!(reader.refused.len(), 1, "{:?}", reader.refused);
        assert_eq!(
            reader.buffer.buffered(),
            0,
            "the refused bytes are released"
        );

        // The tail, then the terminator. Neither is a record.
        reader.feed(b"more of the refused record");
        reader.feed(b"\n");
        assert!(reader.records.is_empty(), "{:?}", reader.records);
        assert_eq!(reader.buffer.buffered(), 0, "the tail was not buffered");

        // The next record is read, so the stream is still usable.
        reader.feed(&terminated(12));
        assert_eq!(reader.records, vec![record_of(12)]);
    }

    #[test]
    fn a_refused_record_with_no_terminator_never_buffers_its_own_tail() {
        // The memory property behind the test above. The tail of a refused record
        // is the one input that would defeat the bound if it were assembled: a
        // peer that crosses the line and then keeps sending would have its
        // refused bytes reassembled in a buffer of this crate's own, which is
        // the allocation the refusal was supposed to prevent.
        let limit = 32;
        let mut buffer = super::RecordBuffer::with_limit(limit);
        let data = Bytes::from(vec![b'x'; limit * 8]);
        assert!(
            buffer.push(&data).is_err(),
            "the first read of an endless record is refused"
        );
        for _round in 0..8 {
            let data = Bytes::from(vec![b'x'; limit]);
            let _unused = buffer.push(&data);
        }
        assert_eq!(buffer.buffered(), 0, "the tail was buffered");
        assert_eq!(buffer.ready(), 0, "the tail was held in `ready`");
    }

    #[test]
    fn a_read_carrying_many_records_is_not_charged_to_the_incomplete_one() {
        // A read can land in the middle of a stream and carry fifty whole
        // records plus the start of a fifty-first. Only the bytes up to the
        // first terminator belong to the record in progress, so the fifty whole
        // ones must not count against the limit — otherwise a stream of small
        // records delivered in large reads is refused even though every record in
        // it is small.
        let mut read = Vec::new();
        for _ in 0..50 {
            read.extend_from_slice(&terminated(12));
        }
        // A partial record after them, which is what the limit is then about.
        read.extend_from_slice(b"{\"k\":\"");

        let mut reader = Reader::new(16);
        reader.feed(&read);
        assert!(reader.refused.is_empty(), "{:?}", reader.refused);
        assert_eq!(reader.records, vec![record_of(12); 50]);
        // The fifty-first is buffered but not complete, so it is not a record
        // yet and the reader is waiting for the rest of it.
        assert!(reader.buffer.next_record().expect("no error").is_none());
        assert_eq!(reader.buffer.buffered(), 6);
    }

    #[test]
    fn a_read_whose_terminator_lands_exactly_on_the_limit_is_accepted() {
        // The terminator is not part of the record, so a record of exactly the
        // limit followed by its newline is a whole record and not one byte too
        // long. Getting this wrong rejects the largest legitimate record, which
        // is the failure mode a caller feels as "it works until it doesn't".
        let mut reader = Reader::new(8);
        reader.feed(b"12345678\n");
        assert!(reader.refused.is_empty(), "{:?}", reader.refused);
        assert_eq!(reader.records, vec![b"12345678".to_vec()]);
    }

    #[test]
    fn a_blank_line_is_no_record_and_does_not_count_towards_anything() {
        // The Engine uses a blank line as a record separator in `build` output,
        // so a read that is nothing but separators must not accumulate, and the
        // caller must see no record rather than an empty one. The buffer hands
        // the reader an empty line and `decode_record` is what turns it into no
        // record, so both halves are asserted: the buffer drains, and the reader
        // reports nothing.
        let mut buffer = super::RecordBuffer::with_limit(4);
        let data = Bytes::from_static(b"\n\n\n\n");
        // The first separator arrives as the record this read completes, and the
        // other three as records behind it.
        let mut blanks = Vec::new();
        if let Some(record) = buffer.push(&data).expect("separators are not a record") {
            blanks.push(record);
        }
        while let Ok(Some(record)) = buffer.next_record() {
            blanks.push(record);
        }
        assert_eq!(blanks.len(), 4, "every separator is handed over once");
        for blank in &blanks {
            assert!(
                super::decode_record(blank.bytes())
                    .expect("a blank line is not a decode failure")
                    .is_none(),
                "a blank line must yield no record"
            );
        }
        assert!(
            buffer.next_record().expect("no error").is_none(),
            "the read is fully drained"
        );
        assert_eq!(buffer.buffered(), 0, "nothing is left buffered");
    }

    #[test]
    fn many_small_records_in_one_read_are_all_returned_in_order() {
        // The valid multi-record case: a whole stream's worth of records in one
        // read, none of them near the limit, every one of them returned. A
        // decoder that dropped or merged records when a read carried several
        // would pass the boundary tests and fail here.
        let mut read = Vec::new();
        for _ in 0..64 {
            read.extend_from_slice(&terminated(8));
        }
        let mut reader = Reader::new(MAX_RECORD_BYTES);
        reader.feed(&read);
        assert!(reader.refused.is_empty(), "{:?}", reader.refused);
        assert_eq!(reader.records, vec![record_of(8); 64]);
    }

    #[test]
    fn a_record_delivered_one_byte_at_a_time_is_assembled_and_returned() {
        // The worst case for a decoder that assumed a read was record-aligned,
        // and the case the ticket named: a frame boundary inside a record. The
        // bound is per record, so delivering it this way must not change what is
        // accepted.
        let reads: Vec<Bytes> = terminated(24)
            .into_iter()
            .map(|b| Bytes::from(vec![b]))
            .collect();
        let mut reader = Reader::new(24);
        for read in &reads {
            reader.feed(read);
        }
        assert!(reader.refused.is_empty(), "{:?}", reader.refused);
        assert_eq!(reader.records, vec![record_of(24)]);
    }

    #[test]
    fn the_default_record_limit_reads_a_record_at_the_default_bound() {
        // The boundary, against the real default rather than a small stand-in,
        // so the shipped number is exercised at the edge it was chosen for.
        // This is the one test that allocates a record of the full size.
        let mut exact = Reader::new(MAX_RECORD_BYTES);
        exact.feed_all(&[&record_of(MAX_RECORD_BYTES), b"\n"]);
        assert!(exact.refused.is_empty(), "{:?}", exact.refused);
        assert_eq!(exact.records.len(), 1);
        assert_eq!(exact.records[0].len(), MAX_RECORD_BYTES);

        let mut past = Reader::new(MAX_RECORD_BYTES);
        past.feed(&record_of(MAX_RECORD_BYTES + 1));
        assert_eq!(past.refused.len(), 1, "{:?}", past.refused);
        assert_eq!(past.refused[0].limit, MAX_RECORD_BYTES);
    }

    #[test]
    fn a_record_with_a_multibyte_character_split_across_reads_is_assembled() {
        // The ticket names a chunk boundary inside a multi-byte character. The
        // decoder splits on a byte, so this must work — and it is the one place
        // it could plausibly not, since a decoder that scanned for a *character*
        // boundary would either panic or drop the record.
        let record = "{\"k\":\"é☃\"}".as_bytes().to_vec();
        // Split in the middle of the two-byte `é` and the three-byte `☃`.
        for split in 1..record.len() {
            let mut reader = Reader::new(record.len());
            reader.feed_all(&[&record[..split], &record[split..], b"\n"]);
            assert!(reader.refused.is_empty(), "split at byte {split}");
            assert_eq!(
                reader.records,
                vec![record.clone()],
                "a split at byte {split} changed the record"
            );
        }
    }

    #[test]
    fn a_trailing_record_with_no_newline_is_taken_rather_than_dropped() {
        // The daemon that closes the connection immediately after writing. The
        // bytes are within the limit, so this is a record rather than the
        // truncated tail of one, and dropping it would lose a record the daemon
        // really sent.
        let mut reader = Reader::new(64);
        reader.feed(b"{\"k\":\"tail\"}");
        assert_eq!(
            reader
                .finish()
                .expect("no refusal")
                .expect("a trailing record"),
            b"{\"k\":\"tail\"}"
        );
        assert!(reader.finish().expect("no refusal").is_none(), "taken once");
    }

    #[test]
    fn a_trailing_record_at_the_limit_is_taken_rather_than_refused() {
        // The boundary again, on the path a caller reaches at end of stream: a
        // maximal record the daemon chose not to terminate is a record at the
        // limit, not one over it.
        let mut reader = Reader::new(8);
        reader.feed(b"12345678");
        assert_eq!(reader.buffer.buffered(), 8);
        assert_eq!(
            reader
                .finish()
                .expect("no refusal")
                .expect("a trailing record"),
            b"12345678"
        );
    }

    #[test]
    fn a_trailing_record_over_the_limit_is_refused_before_end_of_stream() {
        // The refusing side of the end-of-stream boundary. The refusal lands on
        // the read that crossed the line rather than at `take_trailing`, which is
        // the earlier of the two: a record the daemon never terminated is
        // refused as soon as it is over the bound, not held in the hope that the
        // connection will end before anyone notices.
        let mut reader = Reader::new(8);
        reader.feed(b"123456789");
        assert_eq!(
            reader.refused,
            vec![super::OversizedRecord {
                assembled: 9,
                limit: 8
            }],
            "the over-limit record was not refused as it arrived"
        );
        // Nothing is left for the end of the stream to report: the refused bytes
        // were released rather than decoded by a path that forgot to check.
        assert_eq!(reader.buffer.buffered(), 0);
        assert!(reader.finish().expect("no second refusal").is_none());
    }

    #[test]
    fn the_refusal_names_the_limit_and_the_length_rather_than_the_bytes() {
        // The diagnostic is what a caller acts on, so it must carry both numbers
        // and none of the payload: the record is container output, build
        // progress, or an `exec_create` echo of a command line, and none of it
        // belongs in an error message.
        let secret = b"{\"k\":\"hunter2\"}";
        let mut reader = Reader::new(4);
        reader.feed(secret);
        let error = reader.refused[0].to_string();
        assert!(error.contains("4-byte record limit"), "{error}");
        assert!(
            error.contains(&format!("{} byte(s)", secret.len())),
            "{error}"
        );
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[test]
    fn a_whole_record_behind_another_is_checked_against_the_bound_on_its_own() {
        // The limit is per record, so it is checked again on each record handed
        // over rather than once per read: a read whose first record is fine and
        // whose second is over the bound must refuse the second, not wave it
        // through because the read as a whole was not one enormous record.
        //
        // Both sides of the bound are here, because a record of *exactly* the
        // limit sitting behind another is the case an off-by-one in this
        // comparison would refuse, and refusing it would break every stream whose
        // records are large. The oversized case comes first, the exact one after.
        let oversized = record_of(96);
        let mut read = terminated(8);
        read.extend_from_slice(&oversized);
        read.push(b'\n');
        read.extend_from_slice(&terminated(8));

        let mut reader = Reader::new(64);
        reader.feed(&read);
        assert_eq!(
            reader.refused,
            vec![super::OversizedRecord {
                assembled: 96,
                limit: 64
            }],
            "the oversized record behind a small one was not refused"
        );
        assert_eq!(
            reader.records,
            vec![record_of(8), record_of(8)],
            "the records around the refused one must survive"
        );

        // A record of exactly the limit, behind another, in one read.
        let mut read = terminated(8);
        read.extend_from_slice(&terminated(64));
        let mut reader = Reader::new(64);
        reader.feed(&read);
        assert!(
            reader.refused.is_empty(),
            "a record of exactly the bound was refused: {:?}",
            reader.refused
        );
        assert_eq!(reader.records, vec![record_of(8), record_of(64)]);
    }

    /// Every record length from nothing to a full record past the bound, at
    /// three different read shapes.
    ///
    /// The chosen lengths above test three points. This walks the space between
    /// them, because the bug this ticket describes is a *boundary* bug: a
    /// decoder that compares the wrong thing — the read rather than the record,
    /// the buffered length plus the terminator, the length before rather than
    /// after the append — agrees with the chosen lengths and disagrees with
    /// something in between. The only way to know which is the case is to ask
    /// every length.
    ///
    /// Three read shapes per length, because the comparison a decoder makes
    /// depends on how the transport happened to divide the bytes: one read, one
    /// byte at a time, and a read split so that the terminator lands in the
    /// second half. A bound that holds for one and not another is not a bound on
    /// the record, it is a bound on the reads.
    #[test]
    fn every_record_length_is_accepted_up_to_the_bound_and_refused_past_it() {
        // Small, so the sweep is a few hundred iterations rather than a few
        // million, and the arithmetic under the real default is the same code
        // path — asserted at the default in the test above.
        let limit = 32;
        for len in 0..=(limit + 4) {
            for shape in ReadShape::ALL {
                // A record needs its envelope, so the shortest length this can
                // build is eight. Below that there is no record to send.
                if len < 8 {
                    continue;
                }
                // The terminator is appended for every length, including the
                // refused ones: a record is only complete once it is terminated,
                // and a sweep that skipped the terminator would be asserting
                // about trailing bytes rather than about records.
                let read = terminated(len);
                let mut reader = Reader::new(limit);
                for chunk in shape.split(&read) {
                    reader.feed(&chunk);
                }
                if len <= limit {
                    // Accepted: the record that comes out is the record that
                    // went in, at every read shape.
                    assert!(
                        reader.refused.is_empty(),
                        "{len} bytes, {shape}: {refused:?}",
                        refused = reader.refused
                    );
                    assert_eq!(
                        reader.records,
                        vec![record_of(len)],
                        "{len} bytes, {shape}: the record came back changed or was lost"
                    );
                } else {
                    // Refused as a typed error, and refused as early as the
                    // shape allows: the length named is where the record was when
                    // the line was crossed, which is one byte past the bound for
                    // a byte-at-a-time read and the whole record for a read that
                    // arrived all at once. That range is the property — the
                    // record was stopped at the bound rather than after the rest
                    // of it was buffered.
                    let error = reader.refused.first().unwrap_or_else(|| {
                        panic!("{len} bytes, {shape}: a record over the bound was accepted")
                    });
                    assert_eq!(error.limit, limit, "{len} bytes, {shape}");
                    assert!(
                        (limit + 1..=len).contains(&error.assembled),
                        "{len} bytes, {shape}: refused at {} rather than between {} and {len}",
                        error.assembled,
                        limit + 1
                    );
                    assert!(
                        reader.records.is_empty(),
                        "{len} bytes, {shape}: a refused record was returned anyway"
                    );
                }
                assert!(
                    reader.buffer.high_water() <= limit,
                    "{len} bytes, {shape}: the buffer held {} bytes over a {limit}-byte limit",
                    reader.buffer.high_water()
                );
            }
        }
    }

    /// How one record is divided among reads.
    ///
    /// The transport chooses read boundaries and this decoder must not treat
    /// them as record boundaries, so the same record has to be read identically
    /// however it arrives.
    #[derive(Clone, Copy, Debug)]
    enum ReadShape {
        /// The whole record, terminator included, in one read.
        Whole,
        /// One byte per read.
        ByteAtATime,
        /// The record split so the terminator lands in the second read.
        SplitBeforeTerminator,
    }

    impl ReadShape {
        const ALL: [Self; 3] = [Self::Whole, Self::ByteAtATime, Self::SplitBeforeTerminator];

        /// Splits `record` into the reads this shape describes.
        fn split(self, record: &[u8]) -> Vec<Vec<u8>> {
            match self {
                Self::Whole => vec![record.to_vec()],
                Self::ByteAtATime => record.iter().map(|byte| vec![*byte]).collect(),
                // The terminator is the last byte, so splitting before it puts
                // the record's end and the terminator in different reads.
                Self::SplitBeforeTerminator => {
                    vec![
                        record[..record.len() - 1].to_vec(),
                        record[record.len() - 1..].to_vec(),
                    ]
                }
            }
        }
    }

    impl std::fmt::Display for ReadShape {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let name = match self {
                Self::Whole => "one read",
                Self::ByteAtATime => "one byte per read",
                Self::SplitBeforeTerminator => "split before the terminator",
            };
            formatter.write_str(name)
        }
    }

    /// Every record length from nothing to a full record past the bound, at
    /// three different read shapes.
    ///
    /// # Why the shape, and what it is not
    ///
    /// The property is that reading *n* records costs one pass over the bytes,
    /// not *n* passes. Wall-clock would be the obvious way to assert that and it
    /// is the wrong instrument: it is a race against the machine the test runs on,
    /// it fails on a loaded CI runner rather than on a bad decoder, and it cannot
    /// tell a quadratic decoder from a linear one until the quadratic is big
    /// enough to be slow — which is the very condition that makes such a test
    /// useless in a suite.
    ///
    /// So this checks *where the bytes live*, which is the thing the quadratic
    /// shape cannot fake. Every record handed over from a read must point inside
    /// that read's own allocation: not equal to it, not a copy of it, but within
    /// its address range. A decoder that copied the read into a `Vec` and drained
    /// records from the front hands over records with their own allocation
    /// wherever the draining happens, and this fails on the first one.
    ///
    /// The previous version of this test asserted a self-reported relocation
    /// counter instead, and that was not a guard at all: the counter was written
    /// on the assembling path in `push` and never from `next_record`, so a decoder
    /// that drained in the hand-over would have left it at zero. A counter the
    /// code under test maintains about itself is only as good as its coverage of
    /// the code under test, and here the coverage was exactly the part that
    /// mattered.
    #[test]
    fn densely_packed_records_are_handed_over_as_slices_of_the_read() {
        // A megabyte of small records in a single read: the case the old shape was
        // quadratic in. 256 times the record limit, so it is also a read far larger
        // than the bound a record is held to, which is the point — the read size
        // and the record bound are different things and the decoder has to keep
        // them apart.
        let limit = 4096;
        let record = terminated(8);
        let total_bytes = 1 << 20;
        let records = total_bytes / record.len();

        let mut buffer = super::RecordBuffer::with_limit(limit);
        let read = Bytes::from(record.repeat(records));
        // Every record is checked where its bytes live, not counted. `aliases`
        // compares the record's address range against the read's, so a record
        // handed over as a slice of the read passes and a record copied into a
        // `Vec` fails on the first one out.
        let mut handed = 0_usize;
        let check = |record: &super::Record, index: usize| {
            assert!(
                record.aliases(&read),
                "record {index} of {records} does not point into the transport's read: it was \
                 copied out of it, and copying a read to hand over its records is the shape that \
                 costs a memmove per record"
            );
        };

        if let Some(first) = buffer
            .push(&read)
            .unwrap_or_else(|error| panic!("a read of small records was refused: {error}"))
        {
            check(&first, handed);
            handed += 1;
        }
        while let Some(record) = buffer
            .next_record()
            .unwrap_or_else(|error| panic!("a small record was refused: {error}"))
        {
            check(&record, handed);
            handed += 1;
        }

        assert_eq!(handed, records, "every record was handed over exactly once");
        // The copy count agrees, and it is the weaker of the two assertions: it
        // only covers the paths that increment it. It is here because it is what
        // says the *other* case — a record split across reads — is bounded by the
        // record's own length rather than by the read's.
        assert_eq!(
            buffer.assembled_high_water(),
            0,
            "a read of {records} small records copied bytes into this crate's own buffer; \
             every record should have been handed over as a slice of the transport's read"
        );
    }

    /// The old shape, written out, and what it costs on the same input.
    ///
    /// The test above checks that every record aliases the read, which says the
    /// work is not being done. This one says what the work *would* be, in five
    /// lines of the shape that is being avoided: one buffer, appended to per read,
    /// drained from the front per record. It is the code the previous version of
    /// this decoder ran, and it is here so the aliasing assertion is not a guard
    /// against a strawman.
    ///
    /// Both numbers are arithmetic on the same fixture, so nothing here depends on
    /// how fast the machine is. The comparison is what says the fix is worth
    /// having rather than merely tidy.
    ///
    /// The wall-clock on the same fixture, measured once while this was written,
    /// is here so the arithmetic has a scale attached to it. It is a note rather
    /// than an assertion, because an assertion on a stopwatch fails on a loaded
    /// machine and an assertion on a megabyte does not:
    ///
    /// ```text
    ///   records      bytes       drain      slice    ratio
    ///     20,000    200,000    80.6 ms     1.7 ms     48x
    ///     40,000    400,000   397.3 ms     4.2 ms     94x
    ///     80,000    800,000     1.03 s     3.8 ms    267x
    ///    160,000  1,600,000     5.72 s    13.6 ms    421x
    ///    320,000  3,200,000    20.52 s    27.5 ms    747x
    /// ```
    ///
    /// The drain column quadruples per doubling of the record count and the ratio
    /// climbs with it, which is what quadratic looks like from the outside. The
    /// slice column roughly doubles. At the 8 MiB record bound the drain shape is
    /// not slow — it is minutes, which is the reviewer's figure and the reason
    /// this was worth changing rather than documenting.
    #[test]
    fn draining_a_read_from_the_front_relocates_proportionally_to_its_size() {
        let record = terminated(8);
        let total_bytes = 1 << 16;
        let records = total_bytes / record.len();

        // What the old shape did, and what each `drain` cost it: every byte after
        // the removed range moves to the front.
        let mut drained_from_front: Vec<u8> = record.repeat(records);
        let mut old_shape_relocations = 0_usize;
        let mut old_shape_records = 0_usize;
        while let Some(newline) = drained_from_front.iter().position(|byte| *byte == b'\n') {
            old_shape_relocations += drained_from_front.len() - newline;
            let _moved: Vec<u8> = drained_from_front.drain(..=newline).collect();
            old_shape_records += 1;
        }

        // What this decoder does, on the same bytes.
        let mut buffer = super::RecordBuffer::with_limit(4096);
        let read = Bytes::from(record.repeat(records));
        let mut new_shape_records = 0_usize;
        if let Some(record) = buffer
            .push(&read)
            .unwrap_or_else(|error| panic!("a read of small records was refused: {error}"))
        {
            assert!(record.aliases(&read), "the first record was copied");
            new_shape_records += 1;
        }
        while let Some(record) = buffer
            .next_record()
            .unwrap_or_else(|error| panic!("a small record was refused: {error}"))
        {
            assert!(
                record.aliases(&read),
                "a record was copied out of the read rather than sliced from it"
            );
            new_shape_records += 1;
        }

        // Both deliver every record, so the difference is entirely cost.
        assert_eq!(old_shape_records, records);
        assert_eq!(new_shape_records, records);
        // The old shape moved 238,532,841 bytes to hand over 65,536 bytes of
        // records — 3,640 times the read, and the figure grows with the square of
        // the record count. The bound is a factor rather than the exact number
        // because the exact one depends on the record length; the order is the
        // point, and it is the order this decoder does not have.
        //
        // The exact figure for this fixture was measured rather than derived: an
        // earlier version of this comment quoted 238,576,527, which is what
        // `read × records / 2` gives and is not what the loop does. The difference
        // is small and the conclusion is the same, which is exactly why a
        // number in a comment that nobody checked is worth less than one they
        // did.
        assert!(
            old_shape_relocations > total_bytes * 1000,
            "draining {records} records from a {total_bytes}-byte read relocated \
             {old_shape_relocations} bytes, which is expected to be many times the read's size"
        );
    }

    #[test]
    fn a_record_assembled_from_many_reads_copies_its_bytes_once() {
        // The other side of the same property: a record that genuinely has to be
        // assembled, because the transport delivered it a byte at a time. The
        // copies are bounded by the record, not by the number of reads — a
        // decoder that re-copied what it had on each read would be quadratic in
        // the reads for a linear result, and would show a high-water mark at the
        // limit while doing orders of magnitude more work.
        let limit = 64;
        let record = terminated(48);
        let mut buffer = super::RecordBuffer::with_limit(limit);
        let mut completed = None;
        for byte in &record {
            completed = match buffer.push(&Bytes::from(vec![*byte])) {
                Ok(completed) => completed,
                Err(error) => panic!("a byte of a valid record was refused: {error}"),
            };
        }
        let handed = completed
            .map(|record| record.bytes().to_vec())
            .expect("the last read completes the record");
        assert_eq!(handed, record_of(48), "the record came back changed");
        // The copy count, bounded by the record rather than by the number of
        // reads. This is the case the aliasing check does not cover — a record
        // delivered in pieces genuinely has to be written into a buffer — and the
        // bound is what says it was written once, not rewritten on every read,
        // which would be quadratic in the reads for a linear result.
        assert_eq!(
            buffer.assembled_high_water(),
            48,
            "the assembled record is its own length, whatever the number of reads"
        );
    }

    /// The bound can be set until the first read, and not after.
    ///
    /// The condition is on *whether the stream has been read from*, not on whether
    /// the buffer happens to be empty, because those are different states: a
    /// stream whose first read has been fully drained is empty in every field and
    /// is just as configured as one that is half-read. A guard written on the
    /// lengths would let the second call through on the first and refuse it on the
    /// second, which is the worst of both.
    ///
    /// What a replacement would cost is the point. `ready` holds records the
    /// transport delivered and the caller has not seen, and `discarding` says a
    /// refused record is still arriving; a fresh buffer has neither, so the
    /// failure is records the daemon sent and the caller never will — on
    /// `/events`, an event that a caller watching for simply never arrives.
    #[test]
    fn a_bound_can_be_set_until_the_first_read_and_not_after() {
        let mut buffer = super::RecordBuffer::with_limit(MAX_RECORD_BYTES);
        assert!(
            !buffer.was_read(),
            "a buffer nothing has been pushed into has not been read"
        );
        assert_eq!(buffer.set_limit(64), Ok(()));
        // Still settable, repeatedly, before any read: setting it twice is a
        // caller's second thoughts, not a state change.
        assert_eq!(buffer.set_limit(128), Ok(()));

        let read = Bytes::from(terminated(8));
        assert!(buffer.push(&read).is_ok(), "the read is within the bound");
        assert!(
            buffer.was_read(),
            "a buffer that has been pushed into is read"
        );
        assert_eq!(
            buffer.set_limit(64),
            Err(super::RecordLimitError::AlreadyReading),
            "a read stream took a new bound, losing the records it already holds"
        );
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_panicking_or_being_applied() {
        let mut buffer = super::RecordBuffer::with_limit(MAX_RECORD_BYTES);
        assert_eq!(
            buffer.set_limit(0),
            Err(super::RecordLimitError::ZeroLimit),
            "a zero bound would refuse every record, including the empty one"
        );
        // Refused, not applied: the previous bound still stands, so a caller that
        // computed zero and carried on reads records rather than being handed an
        // error on every one of them.
        assert!(
            buffer.push(&Bytes::from(terminated(8))).is_ok(),
            "the refused bound must not have replaced the real one"
        );
    }

    /// A refused record's state survives a caller's failed attempt to reconfigure.
    ///
    /// `try_with_record_limit` returns `Err` and the stream is unchanged, so the
    /// record the daemon is still sending is still being discarded and the record
    /// after it is still read. A builder that replaced the buffer *before*
    /// checking would have cleared `discarding` and handed the caller the middle
    /// of the record it had just been told about.
    #[test]
    fn a_refused_reconfiguration_leaves_the_refusal_state_alone() {
        let limit = 32;
        let oversized = record_of(limit * 2);
        let mut reader = Reader::new(limit);
        // Refuse a record that has not finished arriving.
        reader.feed(&oversized[..limit * 2 - 1]);
        assert_eq!(reader.refused.len(), 1, "{:?}", reader.refused);
        assert!(reader.buffer.discarding, "the record is still arriving");

        // The caller tries to change the bound. It is refused...
        assert_eq!(
            reader.buffer.set_limit(limit * 4),
            Err(super::RecordLimitError::AlreadyReading)
        );
        // ...and the refusal is still in effect.
        assert!(reader.buffer.discarding, "the refusal state was cleared");

        // The rest of the refused record, then the terminator: discarded.
        reader.feed(&oversized[limit * 2 - 1..]);
        reader.feed(b"\n");
        assert!(reader.records.is_empty(), "{:?}", reader.records);

        // And the record after it is read normally.
        reader.feed(&terminated(12));
        assert_eq!(reader.records, vec![record_of(12)]);
    }

    #[test]
    #[should_panic(expected = "a per-record bound of zero would refuse every record")]
    fn a_zero_record_bound_is_refused_where_it_is_passed() {
        // The bound is an argument, so a caller computes it, and a zero is a
        // plausible result of an underflowed subtraction or an empty config
        // field. It has to be refused where it was passed: raising it later
        // would put the panic on the first record of every stream, at a point
        // that reads as a transport fault rather than as the caller's
        // arithmetic.
        let _unused = super::RecordBuffer::with_limit(0);
    }
}
