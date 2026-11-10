//! Container control operations: `kill`, `pause`, `unpause`, `rename`,
//! `resize`, and `attach`.
//!
//! These are the container endpoints whose success is a status rather than a
//! document, plus the two that take a query the caller has to spell out. They
//! share one shape — a versioned path, an optional query, and a body that is
//! either empty or a two-field document — so the shared
//! [`completed`](super::containers::completed) mapping is used rather than a
//! per-operation status check.
//!
//! # `204` is a success, not an empty document
//!
//! `kill`, `pause`, `unpause`, and `rename` answer `204` with no body and no
//! `Content-Length`, measured against Docker Engine 29.8.0. The body is read and
//! discarded, never handed to a JSON decoder: a client that decoded every
//! success as JSON would report a successful lifecycle call as a parse failure.
//!
//! # `resize` answers `200` with no body
//!
//! `POST /containers/{id}/resize` is a `200` with an empty body rather than a
//! `204`, so it takes the same path through [`completed`] but for a different
//! reason. Nothing here decides what a status means; that belongs to
//! [`engine_result`](super::engine_result), which is shared with every other
//! operation in the backend.
//!
//! # `attach` starts; it does not attach
//!
//! `POST /containers/{id}/attach` does not answer with a document. Measured
//! against Docker Engine 29.8.0 with `stream=1`:
//!
//! | Request | Answer |
//! | --- | --- |
//! | no `Connection: Upgrade` header | `200`, `Content-Type: application/vnd.docker.raw-stream`, then the connection carries the raw stream and stays open |
//! | `Connection: Upgrade`, `Upgrade: tcp` | `101 UPGRADED`, then the raw stream |
//!
//! Neither answer has a length, so the body cannot be read as a document: the
//! daemon holds the connection open and writes container output to it until the
//! attach ends. This backend owns that connection for the length of the
//! response and does not take it over, because taking it over is the hijack and
//! h2c work that the decision record lists as an open item (step 6 of the
//! migration order). [`attach`] therefore sends the request, reports the status
//! the daemon chose, and drops the response — which closes the socket, and is
//! therefore an attach that ends immediately. That is a real answer for the
//! case a caller has: it is the `docker start -a` shape of "this container has
//! an output stream and I do not want it", and it is a *refusal* to pretend for
//! the case a caller wants the stream. The difference is reported rather than
//! hidden: [`Attached`] says the daemon started streaming and this client is
//! not reading it.
//!
//! # The `stream` and `stdin` flags are always spelled
//!
//! Every flag is sent as `true`/`false` on every call, so a recorded request
//! says what it meant. An omitted flag is the daemon's default, and a recorded
//! `POST /containers/{id}/attach?logs=1` that does not say whether stdout was
//! wanted is not a request anybody can reproduce.

use hyper::Method;

use super::body::{SwitchedConnection, SwitchedReadHalf, SwitchedWriteHalf};
use super::containers::{Query, completed, container_path, with_query};
use super::transport::{RawEngine, RawRequest, engine_result};
use crate::Error;

/// Options for `POST /containers/{id}/kill`.
///
/// The signal is omitted rather than sent empty. An empty `signal=` is not the
/// same as no `signal`: the Engine parses the parameter with
/// `strconv.Atoi` falling back to a signal-name lookup, and an empty value is
/// neither, so it is a `400`. Measured against Docker Engine 29.8.0, the facade's
/// recorded request for a kill with no signal is
/// `POST /containers/c/kill` with no query at all, and the daemon answers `204`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContainerKillOptions {
    /// The signal name or number, such as `SIGKILL` or `9`.
    ///
    /// Omitted when unset, so the daemon applies its own default — `SIGKILL` —
    /// rather than this client's guess.
    pub signal: Option<String>,
}

/// Options for `POST /containers/{id}/resize`.
///
/// The Engine declares `h` and `w` as `uint`; the repository's terminal sizes
/// are `u16` characters, which is the range a terminal can express and the range
/// every other client sends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContainerResizeOptions {
    /// Terminal height in characters.
    pub height: u16,
    /// Terminal width in characters.
    pub width: u16,
}

/// Options for `POST /containers/{id}/attach`.
///
/// The boolean count is the endpoint's: the Engine declares five stream-selection
/// flags for an attach and a client that offered fewer would be choosing which
/// output the caller can have.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerAttachOptions {
    /// Ask the daemon to keep the connection open and stream both output streams.
    ///
    /// With `stream` set the daemon's answer is a hijacked or upgraded
    /// connection, which [`attach`] reports rather than reads.
    pub stream: bool,
    /// Keep standard input open on the attachment.
    pub stdin: bool,
    /// Include standard output.
    pub stdout: bool,
    /// Include standard error.
    pub stderr: bool,
    /// Replay the container's existing log before streaming new output.
    pub logs: bool,
    /// The detach-key sequence, as the Engine spells it: `ctrl-p,ctrl-q`.
    pub detach_keys: Option<String>,
}

impl Default for ContainerAttachOptions {
    /// Defaults to both output streams without replaying logs.
    ///
    /// `stdout` and `stderr` default to true for the same reason
    /// [`ContainerLogOptions`](super::ContainerLogOptions) defaults them to true:
    /// an attach that returns nothing because nobody set a flag is
    /// indistinguishable from a container that produced no output, and only one
    /// of those is a real answer.
    fn default() -> Self {
        Self {
            stream: false,
            stdin: false,
            stdout: true,
            stderr: true,
            logs: false,
            detach_keys: None,
        }
    }
}

/// What the daemon did with an attach request.
///
/// The distinction is the whole answer. [`Self::Ended`] means the daemon
/// accepted the request and this client closed the connection, so the attachment
/// is over. [`Self::Started`] means the daemon is now writing the container's
/// output on that connection and this client is not reading it, which is what
/// happens when the caller asked only for the attachment to begin.
/// [`Self::Upgraded`] means the daemon switched protocols and this client is
/// holding the connection, so the output can be read and input written.
///
/// Reporting which of the three happened is what keeps the second from reading as
/// the third: both leave the daemon writing, and only one of them leaves the
/// caller able to do anything about it.
#[derive(Debug)]
pub enum Attached {
    /// The daemon switched protocols and this client holds the connection.
    ///
    /// The two halves are the same socket, split. Dropping both closes it, which
    /// the daemon observes as the attach ending — the same contract the
    /// generated client offers, so a caller cannot tell which transport served it.
    Upgraded {
        /// The status the daemon answered with, `101` when it switched protocols.
        status: hyper::StatusCode,
        /// The read half: the container's multiplexed output frames.
        read: SwitchedReadHalf,
        /// The write half: the caller's input to the container.
        write: SwitchedWriteHalf,
    },
    /// The daemon began streaming and this client is not reading the stream.
    ///
    /// Dropping the response closed the connection, so the daemon has already
    /// observed the disconnect. Any output the container produced in between is
    /// gone; the log endpoint is where it can still be read.
    Started {
        /// The status the daemon answered with: `101` when it upgraded the
        /// connection and `200` when it hijacked it.
        status: hyper::StatusCode,
    },
    /// The daemon accepted the request and the attachment is over.
    Ended {
        /// The status the daemon answered with.
        status: hyper::StatusCode,
    },
}

impl Attached {
    /// Returns the status the daemon answered with.
    #[must_use]
    pub const fn status(&self) -> hyper::StatusCode {
        match self {
            Self::Upgraded { status, .. } | Self::Started { status } | Self::Ended { status } => {
                *status
            }
        }
    }

    /// Returns whether the daemon is streaming output this client is not reading.
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        matches!(self, Self::Started { .. })
    }

    /// Takes the connection the daemon switched protocols on, as a read half and
    /// a write half.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon did not switch protocols, which is the
    /// case a caller reaches by asking for a connection the daemon declined to
    /// give.
    pub fn into_connection(self) -> Result<SwitchedConnection, crate::Error> {
        match self {
            Self::Upgraded { read, write, .. } => Ok((read, write)),
            other => Err(crate::Error::transport(format!(
                "the daemon answered {} and did not switch protocols, so there is no \
                 connection to take",
                other.status()
            ))),
        }
    }
}

/// Sends a signal to a container.
///
/// `POST /containers/{id}/kill` answers `204`, so the status is the whole
/// result. A kill of a container that has already stopped is *not* an error:
/// measured against Docker Engine 29.8.0, killing a stopped container answers
/// `204` with no body, so this call is idempotent and does not need a state
/// check first.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `cannot kill container: <name>: No such
/// container: <name>`, or a `409` for a container the daemon will not signal —
/// or when a signal name the Engine does not know arrives as a `400`.
pub async fn kill(
    engine: &RawEngine,
    container: &str,
    options: &ContainerKillOptions,
) -> Result<(), Error> {
    completed(engine, kill_request(container, options)?).await
}

/// Builds the `POST /containers/{id}/kill` request.
fn kill_request(container: &str, options: &ContainerKillOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(signal) = &options.signal {
        query.value("signal", signal);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/kill")?),
        query.finish(),
    ))
}

/// Pauses every process in a container.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request. A `409` is the answer for a container that is not running: measured
/// against Docker Engine 29.8.0, pausing a stopped container answers
/// `409 container <id> is not running`.
pub async fn pause(engine: &RawEngine, container: &str) -> Result<(), Error> {
    completed(engine, pause_request(container)?).await
}

/// Builds the `POST /containers/{id}/pause` request.
fn pause_request(container: &str) -> Result<RawRequest, Error> {
    control_request(container, "pause")
}

/// Resumes every paused process in a container.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `409` for a container that is not paused.
pub async fn unpause(engine: &RawEngine, container: &str) -> Result<(), Error> {
    completed(engine, unpause_request(container)?).await
}

/// Builds the `POST /containers/{id}/unpause` request.
fn unpause_request(container: &str) -> Result<RawRequest, Error> {
    control_request(container, "unpause")
}

/// Renames a container.
///
/// The name is a query value. The Engine's rename endpoint has no body, so there
/// is nowhere else for it to go, and a rename whose name did not travel is a
/// container the caller can no longer address by the name it asked for.
///
/// The `link` parameter the Engine also accepts is not sent. It is the legacy
/// "rename this link too" flag, it was deprecated in the Engine's own
/// documentation, and the current facade does not send it either. Measured
/// against Docker Engine 29.8.0, `?name=<new>&link=<old>` is accepted with a
/// `204` and renames the container, so omitting it costs nothing here.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request — a `404` for a name that is taken, or a `400` for a name the
/// Engine's `[a-zA-Z0-9][a-zA-Z0-9_.-]` rule rejects.
pub async fn rename(engine: &RawEngine, container: &str, name: &str) -> Result<(), Error> {
    completed(engine, rename_request(container, name)?).await
}

/// Builds the `POST /containers/{id}/rename` request.
fn rename_request(container: &str, name: &str) -> Result<RawRequest, Error> {
    if name.is_empty() {
        return Err(Error::invalid_input(
            "the new container name must not be empty",
        ));
    }
    let mut query = Query::default();
    query.value("name", name);
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/rename")?),
        query.finish(),
    ))
}

/// Resizes a container's pseudo-TTY.
///
/// The daemon ignores the request when the container was created without a TTY,
/// and answers `200` either way, so a successful return is not a statement that
/// the terminal changed size. That is the Engine's behaviour rather than a
/// limitation of this client, and it is recorded here because a caller that
/// resizes and then reads [`ContainerInspect::tty`](super::ContainerInspect::tty)
/// should not be surprised.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the container reference is empty.
pub async fn resize(
    engine: &RawEngine,
    container: &str,
    options: &ContainerResizeOptions,
) -> Result<(), Error> {
    completed(engine, resize_request(container, *options)?).await
}

/// Builds the `POST /containers/{id}/resize` request.
///
/// `h` is sent before `w`, which is the order the Engine's own documentation
/// spells them in and the order the current facade's exec resize produces
/// (measured: `POST /exec/<id>/resize?h=40&w=100`).
fn resize_request(container: &str, options: ContainerResizeOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("h", &options.height.to_string());
    query.value("w", &options.width.to_string());
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/resize")?),
        query.finish(),
    ))
}

/// Starts an attachment to a container's output streams.
///
/// The daemon's answer is not a document, so this reports what it did instead of
/// reading a body. See the module documentation for the measured `200` and `101`
/// answers and for what this does and does not do with the stream.
///
/// The request deliberately carries no `Connection: Upgrade` or `Upgrade` header.
/// [`RawEngine`](super::RawEngine) owns message framing and refuses to let an
/// operation set those headers, because an operation that could close the socket
/// would be able to do it underneath the response it is about to read. The
/// consequence is that this path always takes the daemon's `200` answer, never
/// the `101`.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` for a container that does not exist, or a `500` for a
/// container that is not running — or when the container reference is empty.
pub async fn attach(
    engine: &RawEngine,
    container: &str,
    options: &ContainerAttachOptions,
) -> Result<Attached, Error> {
    let response = engine
        .send_upgrading(attach_request(container, options)?)
        .await?;
    let status = response.status;
    if !is_accepted(status) {
        // The failure is the daemon's answer, with its status and message; it is
        // never a body to be read as an attachment.
        return Err(engine_result(response)
            .await
            .expect_err("a rejection status is an error"));
    }
    // A daemon that answered `101` switched protocols and handed the connection
    // over, so this client holds it and can both read the container's output and
    // write the caller's input.
    //
    // The previous code dropped the response here, which closed the connection
    // and let the daemon observe the attach ending — so `attach` reported success
    // and delivered nothing. That was correct only for a caller that asked for
    // the attachment to begin and not to read it, which is what
    // [`Attached::Started`] is for and what it still means.
    if status == hyper::StatusCode::SWITCHING_PROTOCOLS && (options.stream || options.stdin) {
        let (read, write) = response.into_upgraded().await?;
        return Ok(Attached::Upgraded {
            status,
            read,
            write,
        });
    }
    drop(response);
    Ok(if options.stream || options.stdin {
        Attached::Started { status }
    } else {
        Attached::Ended { status }
    })
}

/// Builds the `POST /containers/{id}/attach` request.
fn attach_request(container: &str, options: &ContainerAttachOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    // The order matches the Engine's own parameter order so a recorded request
    // reads the way the documentation for the endpoint does.
    query.flag("stream", options.stream);
    query.flag("stdin", options.stdin);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    query.flag("logs", options.logs);
    if let Some(keys) = &options.detach_keys {
        query.value("detachKeys", keys);
    }
    Ok(with_query(
        // The two upgrade headers are not decoration: without them the daemon
        // answers `200` with an ordinary response body, so the caller would get a
        // finished document where it asked for a connection. Measured against
        // Engine 29.8.0 on a running container, both with and without.
        RawRequest::new(Method::POST, &container_path(container, "/attach")?)
            .with_header(hyper::header::CONNECTION, "Upgrade")
            .with_header(hyper::header::UPGRADE, "tcp"),
        query.finish(),
    ))
}

/// Returns whether a status means the daemon accepted the request.
///
/// `101 Switching Protocols` is an *informational* status, so
/// [`hyper::StatusCode::is_success`] is false for it, and the answer to an
/// attach that the daemon upgraded is exactly that status. Treating a `1xx` as a
/// failure would report a successful upgrade as a rejection, so the acceptance
/// test here is "not a rejection" rather than "a success".
fn is_accepted(status: hyper::StatusCode) -> bool {
    status.is_informational() || status.is_success()
}

/// Builds a `POST /containers/{id}/{action}` request with no query.
///
/// `pause` and `unpause` take no parameters, and their request lines are
/// therefore the shortest in the backend: an empty query is `None` rather than
/// `""`, so the recorded line has no trailing `?`.
fn control_request(container: &str, action: &str) -> Result<RawRequest, Error> {
    let request = RawRequest::new(
        Method::POST,
        &container_path(container, &format!("/{action}"))?,
    );
    Ok(with_query(request, None))
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerAttachOptions, ContainerKillOptions, ContainerResizeOptions, attach_request,
        control_request, kill_request, rename_request, resize_request,
    };
    use crate::raw::{RawEngine, RawTarget};
    use crate::{ApiVersion, ErrorKind};

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &super::RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    #[test]
    fn kill_sends_the_signal_and_omits_it_when_there_is_none() {
        let signalled = kill_request(
            "web 1",
            &ContainerKillOptions {
                signal: Some("SIGKILL".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&signalled),
            crate::raw::at_api_version(
                "POST /v1.API/containers/web%201/kill?signal=SIGKILL HTTP/1.1"
            )
        );
        // An empty `signal=` is not "no signal": the Engine parses the parameter
        // as a number and then as a name, and an empty value is neither. The
        // measured facade request for a kill with no signal carries no query.
        let plain = kill_request("web", &ContainerKillOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/containers/web/kill HTTP/1.1")
        );
    }

    #[test]
    fn pause_and_unpause_send_no_query_at_all() {
        for (request, expected) in [
            (
                super::pause_request("web").expect("request"),
                crate::raw::at_api_version("POST /v1.API/containers/web/pause HTTP/1.1"),
            ),
            (
                super::unpause_request("web").expect("request"),
                crate::raw::at_api_version("POST /v1.API/containers/web/unpause HTTP/1.1"),
            ),
        ] {
            assert_eq!(request_line(&request), expected);
            assert_eq!(request.query, None, "an empty query is not `?`");
        }
    }

    #[test]
    fn rename_puts_the_new_name_in_the_query_and_sends_no_body() {
        let request = rename_request("old", "new name/1").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/old/rename?name=new+name%2F1 HTTP/1.1"
            )
        );
        // The endpoint has no body, so a request that carried one would be
        // inventing a member the Engine does not read.
        assert_eq!(request.body.known_len(), Some(0));
        // The deprecated `link` flag is not sent; see the function's docs.
        assert!(!request.query.expect("a query").contains("link"));
    }

    #[test]
    fn a_rename_to_an_empty_name_is_refused_before_the_socket() {
        // `/containers/x/rename?name=` is a request to rename a container to
        // nothing, and the Engine answers it with a `500` about an empty name.
        let error = rename_request("x", "").expect_err("an empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn resize_sends_the_height_before_the_width() {
        let request = resize_request(
            "web",
            ContainerResizeOptions {
                height: 40,
                width: 100,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/web/resize?h=40&w=100 HTTP/1.1")
        );
    }

    #[test]
    fn attach_spells_every_flag_so_a_recorded_request_is_reproducible() {
        let request = attach_request(
            "web",
            &ContainerAttachOptions {
                stream: true,
                stdin: true,
                stdout: true,
                stderr: false,
                logs: true,
                detach_keys: Some("ctrl-p,ctrl-q".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/web/attach?stream=true&stdin=true&stdout=true&stderr=false&logs=true&detachKeys=ctrl-p%2Cctrl-q HTTP/1.1"
            )
        );
        // The attach endpoint takes no body, so the request is a bare `POST`
        // with a `Content-Length: 0`. Measured against Docker Engine 29.8.0,
        // which answers exactly that with `200` and the raw stream.
        assert_eq!(request.body.known_len(), Some(0));
    }

    #[test]
    fn an_upgrade_is_an_accepted_status_and_not_a_rejection() {
        // `101` is informational, so `is_success()` is false for it. A backend
        // that used the 2xx test would report a successful upgrade as a failure.
        use hyper::StatusCode;
        assert!(!StatusCode::SWITCHING_PROTOCOLS.is_success());
        assert!(super::is_accepted(StatusCode::SWITCHING_PROTOCOLS));
        assert!(super::is_accepted(StatusCode::OK));
        assert!(!super::is_accepted(StatusCode::NOT_FOUND));
        assert!(!super::is_accepted(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn an_attach_keeps_both_output_streams_by_default() {
        // An attach that returns nothing because nobody set a flag is
        // indistinguishable from a container that produced no output.
        let options = ContainerAttachOptions::default();
        assert!(options.stdout && options.stderr);
        assert!(!options.stream, "streaming is a decision, not a default");
        assert!(!options.logs);
    }

    #[test]
    fn an_empty_reference_is_refused_by_every_control_operation() {
        assert_eq!(
            kill_request("", &ContainerKillOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            control_request("", "pause")
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            resize_request("", ContainerResizeOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            attach_request("", &ContainerAttachOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_control_request_never_streams_a_body() {
        // Every operation in this module has an empty request body, so the
        // transport sends a `Content-Length: 0` rather than chunked framing.
        for request in [
            super::pause_request("web").expect("request"),
            super::unpause_request("web").expect("request"),
            rename_request("web", "other").expect("request"),
            resize_request("web", ContainerResizeOptions::default()).expect("request"),
            attach_request("web", &ContainerAttachOptions::default()).expect("request"),
        ] {
            assert_eq!(
                request.body.known_len(),
                Some(0),
                "{}",
                request_line(&request)
            );
        }
    }
}
