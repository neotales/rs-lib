//! The repository-owned Engine transport.
//!
//! This is the first vertical slice of the owned backend described in
//! `docs/docker/engine-backend-alternatives.md`. It owns the whole request path
//! instead of delegating it: the versioned URI, the connection, the request
//! body, the response status, and the error mapping.
//!
//! # Why a hand-rolled connection rather than a client library
//!
//! `hyper_util`'s legacy client needs a `tower_service` connector, and its stock
//! `HttpConnector` cannot open a Unix socket. Bollard's answer is a
//! `connect_with_custom_transport` callback layered on top of a client it owns,
//! which is exactly the arrangement that makes proxy, SSH, and cancellation
//! behavior hard to compose. Driving `hyper::client::conn::http1` directly
//! removes the connector abstraction: the socket, the request, and the
//! connection lifetime are all values this module holds.
//!
//! One connection is used per request, which is what the Docker CLI does and
//! what keeps connection-pool bugs out of the transport. Streaming responses
//! keep their connection alive through the response body, so a long pull is not
//! cut short by the request returning.
//!
//! # Cancellation
//!
//! There is no cancel channel. A caller stops polling the response body and
//! drops it; the body and the connection driver are dropped with it, the socket
//! closes, and the daemon observes the disconnect. Cancellation is therefore a
//! consequence of ownership rather than a protocol that has to be implemented
//! correctly on both sides.

use std::fmt;
use std::future::Future;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use hyper::Request;
use hyper::body::Body as _;
use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::body::{RawBody, RawResponse};
use crate::{ApiVersion, Error};

/// A byte stream the owned HTTP/1 connection can be driven over.
///
/// This is the object a [`StreamFactory`] hands back, so it is public for the
/// same reason the factory is: a factory outside this crate cannot name a type
/// it cannot return. It is a marker over `AsyncRead + AsyncWrite + Unpin +
/// Send` rather than a new I/O trait, because the transport wraps whatever it
/// is given in `hyper_util::rt::TokioIo` and adds nothing of its own. Anything
/// that satisfies the bounds is a duplex — a socket, a process's piped
/// standard streams, or an SSH session channel.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// The future a [`StreamFactory`] call returns.
pub type StreamFuture = Pin<Box<dyn Future<Output = Result<Box<dyn Duplex>, Error>> + Send>>;

/// A closure that opens one fresh duplex for one Engine request.
///
/// # The contract, and why it is a factory and not a stream
///
/// **The transport calls this once per request.** Not once per target, not once
/// per connection pool entry: once for each `RawEngine::send` and once for each
/// `RawEngine::send_upgrading`.
///
/// The reason is in [`RawEngine::send`]: it calls `connect()` and then
/// `exchange()`, and `exchange` runs a fresh `hyper` handshake per request and
/// drops the stream when the response is dropped. A target that held a single
/// duplex would therefore serve exactly one request and fail on the second — and
/// it would fail with a protocol error from `hyper` that says nothing about
/// exhaustion, which is the hardest version of this bug to diagnose.
///
/// Two things keep an implementation honest, and they are different in kind.
///
/// *Structurally*, the variant holds a factory and no duplex field, so there is
/// nowhere in [`RawTarget`] to memoise a stream even by accident. The one call
/// site is `RawEngine::connect`, and it is reached from `send` and
/// `send_upgrading` only.
///
/// *By test*, `stream_target_opens_a_fresh_duplex_for_every_request` asserts that
/// two requests over one target each open their own duplex, against a factory
/// that hands out a stream which is already closed on the second call. A factory
/// that cached would serve the dead stream and fail.
///
/// The duplex a call returns is owned by the caller: hyper writes the request
/// through it and the caller reads the response through it, and dropping the
/// response closes it. A factory that hands out the *same* duplex twice is
/// outside what the type can prevent, and the test above is what catches it.
#[derive(Clone)]
pub struct StreamFactory {
    open: Arc<dyn Fn() -> StreamFuture + Send + Sync>,
}

impl StreamFactory {
    /// Wraps a closure that opens one duplex.
    #[must_use]
    pub fn new<F>(open: F) -> Self
    where
        F: Fn() -> StreamFuture + Send + Sync + 'static,
    {
        Self {
            open: Arc::new(open),
        }
    }

    /// Wraps an `async fn`-shaped closure that opens one duplex.
    ///
    /// This is the form a caller writes when the work is naturally async, such
    /// as spawning a process or completing a handshake. The future is boxed by
    /// this constructor rather than by the caller, so a closure that already
    /// returns a [`StreamFuture`] should use [`Self::new`] instead and skip the
    /// box:
    ///
    /// ```
    /// # use neotales_docker::Error;
    /// # use neotales_docker::raw::{Duplex, StreamFactory};
    /// /// A duplex that reports end of input immediately. It is a real
    /// /// `Duplex`; it is just not a conversation.
    /// # struct Empty;
    /// # impl tokio::io::AsyncRead for Empty {
    /// #     fn poll_read(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #         _: &mut tokio::io::ReadBuf<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// # }
    /// # impl tokio::io::AsyncWrite for Empty {
    /// #     fn poll_write(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #         bytes: &[u8],
    /// #     ) -> std::task::Poll<std::io::Result<usize>> {
    /// #         std::task::Poll::Ready(Ok(bytes.len()))
    /// #     }
    /// #     fn poll_flush(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// #     fn poll_shutdown(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// # }
    /// let factory = StreamFactory::from_fn(|| async {
    ///     Err::<Box<dyn Duplex>, Error>(Error::transport("no Engine is configured here"))
    /// });
    ///
    /// // The factory is called once per request, and the transport asks for a
    /// // fresh one every time.
    /// let target = neotales_docker::raw::RawTarget::Stream {
    ///     authority: "docker".to_owned(),
    ///     open: factory,
    /// };
    /// assert!(matches!(target, neotales_docker::raw::RawTarget::Stream { .. }));
    /// # let _ = Empty;
    /// ```
    #[must_use]
    pub fn from_fn<F, Fut>(open: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Box<dyn Duplex>, Error>> + Send + 'static,
    {
        Self::new(move || Box::pin(open()))
    }

    /// Opens one duplex. The transport calls this once per request.
    #[must_use]
    pub fn open(&self) -> StreamFuture {
        (self.open)()
    }
}

impl<F> From<F> for StreamFactory
where
    F: Fn() -> StreamFuture + Send + Sync + 'static,
{
    fn from(open: F) -> Self {
        Self::new(open)
    }
}

// A derive would print the closure's address, which is noise, and would put a
// `Debug` bound on a caller's own closure for no reason they asked for.
impl fmt::Debug for StreamFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamFactory(<opaque>)")
    }
}

/// Where the owned transport connects.
///
/// `Debug`, `Eq`, and `PartialEq` are hand-written rather than derived, because
/// [`RawTarget::Stream`] holds a [`StreamFactory`] and a closure satisfies none
/// of them. One consequence is documented on [`RawTarget::Stream`] and pinned by
/// a test: two `Stream` targets with the same authority compare equal even when
/// their factories differ, because a closure is not a value. Nothing in the
/// crate decides anything with that comparison.
#[derive(Clone)]
pub enum RawTarget {
    /// A Unix domain socket, as used by a local Docker or Podman daemon.
    ///
    /// The variant exists on every target so that a `match` written by a
    /// downstream caller is portable. Connecting to one on a platform that has
    /// no Unix sockets is an error naming the path, not a compile failure — see
    /// `RawEngine::connect`.
    Unix(PathBuf),
    /// A Windows named pipe, as used by a local Windows daemon.
    ///
    /// The canonical Windows path is `\\.\pipe\docker_engine`. Docker context
    /// files and callers also commonly use `//./pipe/docker_engine`; the Windows
    /// transport normalizes either separator spelling before opening the pipe.
    /// As with [`RawTarget::Unix`], the variant is not gated: a target that
    /// cannot open a pipe reports that rather than failing to compile.
    NamedPipe(PathBuf),
    /// A TCP endpoint, with or without TLS applied by the caller.
    Tcp {
        /// The host to connect to.
        host: String,
        /// The TCP port.
        port: u16,
    },
    /// An endpoint the transport cannot name, opened one duplex at a time.
    ///
    /// This is for a daemon reached by running a command whose standard streams
    /// *are* the Engine's HTTP connection — `docker system dial-stdio` over an
    /// SSH session, which is how Docker itself reaches a remote daemon. There is
    /// no host and port to dial, and no socket to open, so the only way to reach
    /// it is to be handed the bytes.
    ///
    /// `open` is a [`StreamFactory`] and **is called once per request**. See that
    /// type for why it is a factory rather than a duplex, and for the test that
    /// holds an implementation to it. The practical rule for a caller: build the
    /// connection inside the closure and do not keep it.
    ///
    /// `authority` is the value sent in the `Host` header. A `dial-stdio` peer
    /// sees one connection per request and has no authority of its own, but
    /// HTTP/1.1 requires a syntactically valid one; `localhost` is what the
    /// socket and pipe variants send for the same reason, and Docker's own
    /// transport sends `http://docker/` for an SSH endpoint.
    Stream {
        /// The value sent in the `Host` header.
        authority: String,
        /// Opens a fresh duplex for one request.
        open: StreamFactory,
    },
}

impl RawTarget {
    /// Returns the value sent in the `Host` header.
    ///
    /// A socket has no meaningful authority, and the Engine ignores the value,
    /// but HTTP/1.1 requires the header to be present and syntactically valid.
    fn authority(&self) -> String {
        match self {
            // A socket and a pipe have no meaningful authority, and the Engine
            // ignores the value, but HTTP/1.1 requires a syntactically valid one.
            Self::Unix(_) | Self::NamedPipe(_) => "localhost".to_owned(),
            Self::Tcp { host, port } => {
                // A bare IPv6 literal must be bracketed to be a valid authority.
                if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
            Self::Stream { authority, .. } => authority.clone(),
        }
    }
}

impl fmt::Debug for RawTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => formatter.debug_tuple("Unix").field(path).finish(),
            Self::NamedPipe(path) => formatter.debug_tuple("NamedPipe").field(path).finish(),
            Self::Tcp { host, port } => formatter
                .debug_struct("Tcp")
                .field("host", host)
                .field("port", port)
                .finish(),
            // The factory is not printed. It is an opaque closure, so the only
            // thing a reader could be shown is an address, which tells them
            // nothing and changes every run.
            Self::Stream { authority, open } => formatter
                .debug_struct("Stream")
                .field("authority", authority)
                .field("open", open)
                .finish(),
        }
    }
}

impl PartialEq for RawTarget {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unix(left), Self::Unix(right))
            | (Self::NamedPipe(left), Self::NamedPipe(right)) => left == right,
            (Self::Tcp { host: lh, port: lp }, Self::Tcp { host: rh, port: rp }) => {
                lh == rh && lp == rp
            }
            (
                Self::Stream {
                    authority: left, ..
                },
                Self::Stream {
                    authority: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }
}

impl Eq for RawTarget {}

/// A request the owned transport can send.
///
/// The path is given without the API version prefix: the transport adds it from
/// its negotiated version, so no caller can forget it or disagree about it.
///
/// # `Debug` redacts
///
/// Not derived. `x-registry-auth` and `x-registry-config` carry a registry
/// credential base64-encoded, and a derived `Debug` printed them. Measured, not
/// assumed: a `RawRequest` with a canary in that header rendered as
/// `headers: {"x-registry-auth": "Y2FuYXJ5LXNlY3JldC1oZWFkZXI="}`. Base64 is not
/// a redaction, and this crate has already been bitten twice by a credential
/// reaching somewhere it could be read.
///
/// The **query** is redacted wholesale rather than filtered by name. It is a
/// caller-supplied `String`, and the set of parameters the Engine accepts is not a
/// closed list this crate controls: printed verbatim it leaked a canary before
/// this was noticed, and a name allow-list would have been a guess about a wire
/// protocol. The **path** is not redacted — it is built from names and ids by this
/// crate's own escaping, and it is the part a reader diagnosing a failed request
/// needs.
pub struct RawRequest {
    /// The HTTP method.
    pub method: Method,
    /// The unversioned path, beginning with `/`.
    pub path: String,
    /// An already-encoded query string, without the leading `?`.
    pub query: Option<String>,
    /// Extra request headers.
    pub headers: hyper::HeaderMap,
    /// The request body.
    pub body: RawBody,
}

/// Header names whose value is a credential.
///
/// **This is a deny-list and it fails open**, which the previous version of this
/// comment claimed was not the case. It said the redaction was "an allow-list of
/// what is safe rather than a deny-list of what is not, which is the only
/// direction that fails safe when the Engine grows a new credential header", and
/// then conceded in the same paragraph that a new header prints. The two
/// sentences contradict each other and the first is wrong.
///
/// A header allow-list is not available, and pretending otherwise would be worse
/// than the gap: the honest choices are a deny-list of the two credential headers
/// the Engine defines, or redacting every header value, and the second throws
/// away `content-type` and the other headers a reader diagnosing a failed request
/// actually needs. **The gap is real and it is named: a credential in any other
/// header prints.** What makes that survivable is the test beside it, which holds
/// a canary in *each* of these headers — so adding a credential header means the
/// test goes quiet on that header, which is a signal to add it here.
///
/// [`RawRequest`]'s own documentation makes the same argument about the query and
/// reaches the opposite conclusion there, for the same reason: the set of names
/// the Engine accepts is not a closed list this crate controls. The difference is
/// that a query value has no non-secret members worth keeping, and a header value
/// does.
const CREDENTIAL_HEADERS: &[&str] = &["x-registry-auth", "x-registry-config"];

impl std::fmt::Debug for RawRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query.as_ref().map(|_| "<redacted>"))
            .field("headers", &RedactedHeaders(&self.headers))
            .field("body", &self.body)
            .finish()
    }
}

/// Prints every header name, and a value only where the name is not a credential.
struct RedactedHeaders<'headers>(&'headers hyper::HeaderMap);

impl std::fmt::Debug for RedactedHeaders<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for name in self.0.keys() {
            let is_credential = CREDENTIAL_HEADERS
                .iter()
                .any(|known| name.as_str().eq_ignore_ascii_case(known));
            let value = if is_credential {
                "<redacted>".to_owned()
            } else {
                self.0
                    .get(name)
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                    .unwrap_or_default()
            };
            map.entry(&name.as_str(), &value);
        }
        map.finish()
    }
}

impl RawRequest {
    /// Creates a bodyless request.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: None,
            headers: hyper::HeaderMap::new(),
            body: RawBody::Empty,
        }
    }

    /// Sets the query string.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Sets the request body.
    #[must_use]
    pub fn with_body(mut self, body: RawBody) -> Self {
        self.body = body;
        self
    }

    /// Adds one header.
    #[must_use]
    pub fn with_header(mut self, name: hyper::header::HeaderName, value: &str) -> Self {
        if let Ok(value) = hyper::header::HeaderValue::from_str(value) {
            self.headers.insert(name, value);
        }
        self
    }
}

/// A repository-owned Engine client for the raw backend.
///
/// The type is private to the crate on purpose: it is the implementation under
/// the public facade, not a second public client. The migration order in the
/// decision record promotes it out of the crate only if the differential
/// fixtures justify replacing the Bollard path outright.
#[derive(Clone, Debug)]
pub struct RawEngine {
    target: RawTarget,
    version: ApiVersion,
}

impl RawEngine {
    /// Creates a transport for one target and API version.
    #[must_use]
    pub const fn new(target: RawTarget, version: ApiVersion) -> Self {
        Self { target, version }
    }

    /// Returns the API version this transport prefixes onto every path.
    #[must_use]
    pub const fn version(&self) -> ApiVersion {
        self.version
    }

    /// Builds the versioned, query-suffixed request URI.
    ///
    /// Returns an error when the path is not an absolute path, because a
    /// relative path would silently be sent against the wrong resource.
    ///
    /// `pub(crate)` rather than `pub(super)` so the facade's tests can read the
    /// prefix off a real engine. Those tests are where the claim "the owned
    /// transport speaks `API_VERSION`" is checked, and a check that could only
    /// read `version()` would pass even if the prefix were rendered from some
    /// other value. Not `pub`: this is not part of the crate's contract, and a
    /// caller wanting to know the version reads [`Self::version`].
    pub(crate) fn request_uri(&self, request: &RawRequest) -> Result<String, Error> {
        if !request.path.starts_with('/') {
            return Err(Error::invalid_input(format!(
                "Engine request path must start with '/', got '{}'",
                request.path
            )));
        }
        let mut uri = format!("/v{}.{}", self.version.major, self.version.minor);
        uri.push_str(&request.path);
        if let Some(query) = &request.query {
            uri.push('?');
            uri.push_str(query);
        }
        Ok(uri)
    }

    /// Opens a connection, sends the request, and returns the live response.
    ///
    /// The response body must be read on the same runtime that made the call.
    /// hyper's HTTP/1 client only reads from the socket while its connection
    /// future is being polled, and that future runs as a task on the runtime that
    /// dialled, so a body read on a different runtime finds the socket gone.
    /// Reading the body on the same runtime — or on a task of it — always works.
    ///
    /// Dropping the response cancels the transfer: the body is dropped, the
    /// connection task is stopped, and the daemon observes the disconnect. There
    /// is no cancel message to send and therefore no way for the two ends to
    /// disagree about whether a transfer is still wanted.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not absolute, the socket cannot be
    /// opened, or the request cannot be written. A daemon that answers with a
    /// non-2xx status is **not** an error here: status interpretation belongs
    /// to the operation layer, which knows what a 404 or a 500 means for that
    /// specific call.
    pub async fn send(&self, request: RawRequest) -> Result<RawResponse, Error> {
        let uri = self.request_uri(&request)?;
        let stream = self.connect().await?;
        self.exchange(stream, request, &uri).await
    }

    /// Opens the transport connection for the configured target.
    ///
    /// Each variant's arm is gated rather than the variant itself, so the public
    /// enum is the same on every target and a caller can write a portable
    /// `match`. A target the host cannot provide reports why, naming the path it
    /// was asked for — which is the difference between "this platform has no
    /// Unix sockets" and a caller that silently reached for the wrong transport.
    async fn connect(&self) -> Result<Box<dyn Duplex>, Error> {
        match &self.target {
            RawTarget::Unix(path) => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(path)
                        .await
                        .map_err(|error| {
                            transport_error(format!("connect to {}", path.display()), error)
                        })?;
                    Ok(Box::new(stream))
                }
                #[cfg(not(unix))]
                {
                    Err(transport_error(
                        format!("connect to {}", path.display()),
                        std::io::Error::other(
                            "this platform has no Unix domain sockets; \
                             a local daemon is reached through a named pipe or TCP",
                        ),
                    ))
                }
            }
            RawTarget::NamedPipe(path) => {
                #[cfg(windows)]
                {
                    let canonical_path = normalize_windows_pipe_path(path);
                    let stream = tokio::net::windows::named_pipe::ClientOptions::new()
                        .open(&canonical_path)
                        .map_err(|error| {
                            transport_error(
                                format!("connect to {}", canonical_path.display()),
                                error,
                            )
                        })?;
                    Ok(Box::new(stream))
                }
                #[cfg(not(windows))]
                {
                    Err(transport_error(
                        format!("connect to {}", path.display()),
                        std::io::Error::other(
                            "this platform has no named pipes; \
                             a local daemon is reached through a Unix socket or TCP",
                        ),
                    ))
                }
            }
            RawTarget::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|error| transport_error(format!("connect to {host}:{port}"), error))?;
                // The Engine speaks HTTP/1.1, and a Nagle-disabled stream keeps
                // small request/response pairs from paying a delayed-ACK stall.
                let _ignored = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
            RawTarget::Stream { authority, open } => {
                // Called once per request, and the duplex is handed straight to
                // `exchange`, which drops it with the response. There is no
                // field on the target to cache one in, which is the structural
                // half of the contract `StreamFactory` documents.
                //
                // The factory's error is rendered through its *source chain*
                // rather than its `Display`. `ErrorKind::Transport` currently
                // prints the bare string "Docker transport error" and keeps the
                // composed message in its source — escape criterion 6, recorded
                // in the project's own notes and still open — so formatting the
                // summary here would replace every reason a factory has with
                // the same eleven words. Walking the chain keeps the factory's
                // own words whichever kind it used. The bare `Display` is
                // reported rather than fixed: changing what every caller prints
                // is not this change's decision.
                open.open().await.map_err(|error| {
                    Error::transport(format!(
                        "open a duplex for the Engine at {authority}: {}",
                        describe(&error)
                    ))
                })
            }
        }
    }

    /// Writes the request over an open stream and hands back the response.
    /// Sends `request` on a connection that can switch protocols, for an
    /// operation the daemon answers with `101`.
    ///
    /// This is the only route to a live bidirectional connection on this
    /// transport. A connection built any other way answers a protocol switch by
    /// failing the pending upgrade with `new_user_manual_upgrade`, and the
    /// response extensions that carry the handle are then never populated, so a
    /// caller would get an opaque error where it asked for a socket.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the connection, handshake, or request
    /// cannot be completed.
    pub(crate) async fn send_upgrading(&self, request: RawRequest) -> Result<RawResponse, Error> {
        let uri = self.request_uri(&request)?;
        let stream = self.connect().await?;
        self.exchange_inner(stream, request, &uri, true).await
    }

    /// Opens a connection and sends `request`, for an operation that will read a
    /// complete document.
    async fn exchange(
        &self,
        stream: Box<dyn Duplex>,
        request: RawRequest,
        uri: &str,
    ) -> Result<RawResponse, Error> {
        self.exchange_inner(stream, request, uri, false).await
    }

    /// Opens a connection and sends `request`, for an operation that expects the
    /// daemon to switch protocols and hand the connection over.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the connection, handshake, or request
    /// cannot be completed.
    async fn exchange_inner(
        &self,
        stream: Box<dyn Duplex>,
        request: RawRequest,
        uri: &str,
        upgrade: bool,
    ) -> Result<RawResponse, Error> {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| transport_error("Engine handshake", error))?;
        // A connection that is not upgrade-capable answers a protocol switch by
        // failing the pending upgrade with `new_user_manual_upgrade`, so the
        // caller would see an opaque error instead of the socket it asked for.
        // `with_upgrades` hands the connection's parts to the pending upgrade
        // instead, which is the only way a hyper 1 *client* can end up owning the
        // raw stream after a `101`. The type is unnameable outside hyper, so it
        // is spawned directly and never named.
        let driver = if upgrade {
            let connection = connection.with_upgrades();
            tokio::spawn(async move {
                // The connection's own result is surfaced through the body or the
                // upgrade handle once the request is written, which is where a
                // mid-transfer failure can still be attributed to the request that
                // caused it.
                let _finished = connection.await;
            })
            .abort_handle()
        } else {
            // Started before the request so it is already being polled by the time
            // `send_request` is awaited; without it hyper never writes the request.
            tokio::spawn(async move {
                let _finished = connection.await;
            })
            .abort_handle()
        };

        let known_len = request.body.known_len();
        let body = request.body.into_request();
        let length = known_len.map_or_else(|| body.size_hint().exact(), Some);

        // The connection is left open rather than closed after the response.
        // With `Connection: close`, hyper finishes the connection as soon as it
        // has the whole message in its buffer, which races the body read and
        // turns a complete response into a truncated one. Leaving it open also
        // matches how the Bollard path behaves, so the differential fixtures
        // compare like with like.
        let mut builder = Request::builder()
            .method(request.method)
            .uri(uri)
            .header(HOST, self.target.authority());
        if let Some(length) = length {
            builder = builder.header(CONTENT_LENGTH, length);
        } else {
            builder = builder.header(TRANSFER_ENCODING, "chunked");
        }
        for (name, value) in &request.headers {
            // Caller headers are applied last so an operation can override a
            // transport default such as `Content-Type`, but never a framing
            // header, which the body length above already decided.
            if is_framing_header(name) {
                continue;
            }
            // `Connection` decides the connection's lifetime, which is why the
            // framing check above refuses it by default. On a request that exists
            // to switch protocols it is the opposite: `Connection: Upgrade` is the
            // request, and withholding it is what makes the daemon answer `200`
            // with an ordinary body instead of handing over the connection. The
            // one value refused even here is `close`, which would ask for the
            // connection to be dropped in the same breath as asking to keep it.
            if name == CONNECTION && (!upgrade || is_connection_close(value)) {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }

        let message = builder
            .body(body)
            .map_err(|error| transport_error("building the Engine request", error))?;

        // `send_request` does not make progress on its own: hyper's HTTP/1
        // client only writes the request and reads the response head while the
        // connection future is being polled. Awaiting the request without
        // driving the connection deadlocks, so the two are polled together.
        //
        // The connection is then handed to the response rather than spawned. A
        // spawned task belongs to the runtime that created it, so a caller that
        // read the body on a later runtime would find the socket closed
        // underneath it with nothing to explain why.
        let response = sender
            .send_request(message)
            .await
            .map_err(|error| transport_error("sending the Engine request", error))?;

        let (parts, body) = response.into_parts();
        // The extensions are kept because hyper puts the pending `OnUpgrade` in
        // them when the daemon answers `101`, and that handle is the only route
        // back to the socket. Discarding them with the rest of the parts is what
        // made a protocol switch unusable here: the caller had a status and a
        // body and no way to reach the connection the daemon had just handed over.
        Ok(RawResponse::with_extensions(
            parts.status,
            parts.headers,
            parts.extensions,
            body,
            driver,
        ))
    }
}

/// Reports whether a header decides message framing.
///
/// `Connection` is handled separately, by the request loop, because whether it
/// is honoured depends on why the request was sent.
fn is_framing_header(name: &hyper::header::HeaderName) -> bool {
    name == CONTENT_LENGTH || name == TRANSFER_ENCODING
}

/// Reports whether a `Connection` header value asks for the socket to be closed.
///
/// Compared token by token rather than by whole value, because the header
/// carries a comma-separated list of directives and `close` is only meaningful
/// as one of them.
fn is_connection_close(value: &hyper::header::HeaderValue) -> bool {
    value.to_str().is_ok_and(|text| {
        text.split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

/// Wraps a connection or request failure with the target it happened against.
fn transport_error(what: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::transport(format!("failed to {what}: {error}"))
}

/// Renders an error together with every cause beneath it.
///
/// `Display` alone is not enough for an [`Error`] in this crate. `ErrorKind::Transport`
/// renders as a fixed string and keeps the composed message — the operation and
/// the target — in its `source`, so a formatter that reads only the summary
/// reports the same eleven words for every failure on every path. That is escape
/// criterion 6 in the project's own notes, and it is still open.
///
/// Two links are joined with `: `, which is the spelling the rest of this
/// module already uses, and the chain is bounded by the `source` chain itself:
/// a cycle would have to be built deliberately, and `Error::source` returns a
/// borrow of the same object rather than a fresh one.
fn describe(error: &Error) -> String {
    let mut rendered = error.to_string();
    let mut current = std::error::Error::source(error);
    while let Some(source) = current {
        rendered.push_str(": ");
        rendered.push_str(&source.to_string());
        current = source.source();
    }
    rendered
}

/// Sets a JSON `Content-Type` on a request.
pub fn json_content_type(request: RawRequest) -> RawRequest {
    request.with_header(CONTENT_TYPE, "application/json")
}

/// Serializes a value as a JSON request body.
///
/// # Errors
///
/// Returns an error when the value cannot be encoded. Serialization happens
/// before the connection is opened, so a caller never has to roll back a request
/// that was partially written.
pub fn json_body<T>(value: &T) -> Result<RawBody, Error>
where
    T: serde::Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(value).map_err(|error| {
        Error::invalid_input(format!("failed to encode the Engine request body: {error}"))
    })?;
    Ok(RawBody::from_bytes(Bytes::from(encoded)))
}

/// Interprets a response status and, when it is not a success, its body.
///
/// An Engine error body is a JSON object with a `message` member. The message is
/// preserved verbatim so a caller can print the daemon's own words under
/// `--raw-error`, but it is never logged, wrapped, or truncated by this layer.
///
/// # Errors
///
/// Returns an error when the daemon rejected the request, carrying the status
/// and the daemon's message in [`Error::api_error`], or when a success response
/// body could not be read within the document limit.
pub async fn engine_result(response: RawResponse) -> Result<Bytes, Error> {
    let status = response.status;
    if status.is_success() {
        return response.document().await.map_err(Error::from);
    }
    let raw = response.document().await.unwrap_or_else(|_| Bytes::new());
    Err(Error::engine_api(status, engine_message(&raw, status)))
}

/// Extracts the `message` member of an Engine error body.
///
/// A body that is absent, truncated, or not JSON is reported by status alone
/// rather than replacing the daemon's answer with a parsing complaint: a user
/// debugging a daemon failure needs the real status, not this layer's opinion.
pub(super) fn engine_message(raw: &[u8], status: StatusCode) -> String {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| {
            format!(
                "daemon returned HTTP {} {}",
                status.as_u16(),
                status
                    .canonical_reason()
                    .unwrap_or("without a reason phrase")
            )
        })
}

/// Decodes a bounded Engine document into a repository-owned model.
///
/// # Errors
///
/// Returns an error when the document is not the expected shape. The raw bytes
/// are named in the diagnostic but never the decoded value, because documents
/// such as `info` and `version` can carry host detail a caller did not ask to
/// see printed.
pub fn decode<T>(raw: &[u8]) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(raw).map_err(|error| {
        Error::invalid_input(format!(
            "failed to decode the Engine response document: {error}"
        ))
    })
}

/// Collects a streaming response into newline-delimited JSON values.
///
/// This is the shape the Engine uses for `build`, `pull`, `push`, and `events`.
/// The records are read one at a time by `FrameStream::next_json`, so an
/// endless event stream never accumulates in memory. A record over
/// [`MAX_RECORD_BYTES`](crate::raw::MAX_RECORD_BYTES) is an error rather than a
/// larger `Vec`, which is the case that stops the accumulation from being the
/// peer's to decide.
///
/// It is the bounded form of that reader: it runs until the daemon closes the
/// body, which is the right shape for a stream that ends (`build`, a finished
/// `pull`) and the wrong one for a stream that does not (`stats` with
/// `stream=true`, `events` with a filter that keeps matching). A caller that
/// wants to stop early drops the `FrameStream` instead of calling this.
///
/// # Errors
///
/// Returns an error when the connection fails mid-transfer or when a record is
/// not JSON. A trailing partial record is reported rather than silently
/// dropped, because a truncated final message would hide a daemon-side failure.
///
/// One behavior changed when this moved onto `FrameStream::next_json`: a
/// final record with no trailing newline used to be parsed and then discarded,
/// and is now returned. The old shape lost a record the daemon had sent.
pub async fn collect_json_frames(response: RawResponse) -> Result<Vec<serde_json::Value>, Error> {
    let mut frames = response.into_frames();
    let mut values = Vec::new();
    while let Some(value) = frames.next_json().await? {
        values.push(value);
    }
    Ok(values)
}

/// Trims ASCII whitespace from both ends of a slice.
pub(super) fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &value[start..end]
}

/// Converts `/` separators to the native `\` form without changing any other
/// UTF-16 code units in a Windows named-pipe path.
#[cfg(any(windows, test))]
fn normalize_windows_pipe_separators(units: impl IntoIterator<Item = u16>) -> Vec<u16> {
    units
        .into_iter()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect()
}

#[cfg(windows)]
fn normalize_windows_pipe_path(path: &std::path::Path) -> PathBuf {
    let units = normalize_windows_pipe_separators(path.as_os_str().encode_wide());
    PathBuf::from(std::ffi::OsString::from_wide(&units))
}

#[cfg(test)]
mod pipe_path_tests {
    use super::normalize_windows_pipe_separators;

    #[test]
    fn either_pipe_separator_spelling_becomes_the_native_form() {
        for input in [
            r"\\.\pipe\docker_engine",
            "//./pipe/docker_engine",
            r"\\./pipe/docker_engine",
            r"\\.\pipe/docker_engine",
        ] {
            let normalized = normalize_windows_pipe_separators(input.encode_utf16());
            assert_eq!(
                String::from_utf16(&normalized).expect("valid UTF-16 remains valid"),
                r"\\.\pipe\docker_engine",
                "input: {input:?}"
            );
        }
    }
}
