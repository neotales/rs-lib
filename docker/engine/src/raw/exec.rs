//! The exec endpoints: create, start, inspect, and resize.
//!
//! # Exec is four endpoints, not one
//!
//! Creating an exec instance and running it are separate calls with separate
//! identifiers, and the id is what the other three take. So `create` returns an
//! owned [`ExecCreateResult`] rather than a bare string, and the three follow-up
//! operations take that id — percent-encoded into one path segment exactly as a
//! container reference is, for the same reason: `/exec/a/b/json` is a
//! three-segment path, not the inspect of an exec named `a/b`.
//!
//! # `start` reports what the daemon did; it does not read the output
//!
//! `POST /exec/{id}/start` has two answers and neither is a document. Measured
//! against Docker Engine 29.8.0:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `{"Detach":true,"Tty":false}` | `200`, no body, no length, and the exec runs unattended |
//! | `{"Detach":false,"Tty":false}` | `200`, `Content-Type: application/vnd.docker.raw-stream`, no `Content-Length` and no `Transfer-Encoding`, then the exec's output on a connection the daemon holds open |
//!
//! The attached answer declares no length at all, so the body cannot be read as
//! a document: a `document()` read would wait for the daemon to close a
//! connection it has no reason to close. The current dependency solves this by
//! asking for an HTTP upgrade and taking the socket over; that is the hijack and
//! h2c work the decision record lists as an open item, and it is not attempted
//! here. [`exec_start`] therefore checks the status, reports whether the caller
//! asked to detach, and drops the response — which closes the connection and is
//! therefore an exec whose output is discarded. [`ExecStarted::is_attached`]
//! says so, so a caller cannot mistake this for a session it is reading.
//!
//! # The inspect answer keeps every member, and none of them in a log
//!
//! `GET /exec/{id}/json` answers eleven members against Docker Engine 29.8.0:
//! `ID`, `Running`, `ExitCode`, `ProcessConfig`, `OpenStdin`, `OpenStderr`,
//! `OpenStdout`, `CanRemove`, `ContainerID`, `DetachKeys`, and `Pid`. The
//! repository's [`ExecState`] holds three of them, and the current facade maps
//! the answer onto that model, so eight members the daemon sent are dropped
//! before a caller sees them. [`ExecInspect`] keeps the document and reads the
//! three out of it, which is the same answer with nothing lost.
//!
//! Retaining the whole document is also what makes its `Debug` hand-written, and
//! the member that decides it is `ProcessConfig.env`: the environment the exec
//! was **created** with, echoed back, which is where a caller putting `--env`
//! credentials into a one-off command has just put them. `ProcessConfig` also
//! carries the command line, where `--token` lives, so none of the block is
//! rendered and the summary reports its two array lengths instead. See the
//! type's own documentation.
//!
//! # `resize` needs a live exec session, and says so
//!
//! `POST /exec/{id}/resize` is refused by the daemon unless an exec session is
//! actually running with a TTY. Measured against Docker Engine 29.8.0, a
//! resize against a created-but-unstarted exec is answered
//! `500 {"message":"timeout waiting for exec session ready"}`, and against an
//! exec that has already exited,
//! `404 {"message":"NotFound: process does not exist <id>: not found"}`. Both
//! arrive here as an error carrying the daemon's own message, which is the right
//! answer: a client cannot know whether a session is about to become ready.

use std::fmt;

use hyper::Method;
use serde::{Deserialize, Serialize};

use super::containers::{Query, completed, container_path, escape_path_segment, with_query};
use super::inspect::MAX_SUMMARY_TEXT;
use super::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::{Error, ExecOptions, ExecResizeOptions, ExecState};

/// The `POST /containers/{id}/exec` answer, in the Engine's spelling.
///
/// The Engine declares exactly one member here, `Id`, and a daemon that sent
/// another one would be a daemon this client has not seen; the id is the whole
/// answer, and returning it as its own type is what makes the three follow-up
/// calls take a value rather than a string that might be something else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecCreateResult {
    /// The exec instance's id, which the other three exec operations take.
    pub id: String,
}

/// What the daemon did with an exec start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecStarted {
    /// The status the daemon answered with.
    pub status: hyper::StatusCode,
    /// Whether the caller asked to detach.
    ///
    /// When this is `false` the daemon is writing the exec's output on the
    /// connection this client just dropped. The output is not read, and the
    /// daemon has already seen the disconnect.
    pub detached: bool,
}

impl ExecStarted {
    /// Returns whether the exec's output is being written to a connection this
    /// client is not reading.
    ///
    /// This is the question a caller actually has after an exec start: whether a
    /// successful call means a session it can read from.
    #[must_use]
    pub const fn is_attached(&self) -> bool {
        !self.detached
    }
}

/// The `GET /exec/{id}/json` answer, with the daemon's document kept intact.
///
/// # Why `Debug` is hand-written
///
/// The same reasoning as
/// [`ContainerInspect`](super::ContainerInspect), and for the same reason: this
/// type keeps the document rather than decoding it into a model, which is
/// exactly what makes the derived impl a defect instead of a convenience. The
/// module's own argument is that eight of the eleven members the daemon sends
/// would be dropped otherwise, and a caller can only have them if the value keeps
/// what arrived.
///
/// `ProcessConfig.env` is the member that makes it a credential rather than an
/// inconvenience. It is the environment the exec was **created** with — sent by
/// [`ExecOptions::environment`], the input side of the same operation — and the
/// daemon echoes it back verbatim. A caller creating an exec inside a container
/// passes `AWS_SECRET_ACCESS_KEY`, a database URL, a signing key, and then reads
/// this document back to find out why the command produced no output. That is
/// the ordinary sequence, and a derived `Debug` puts the key in the panic
/// message, the `tracing` field, or the CI log that records the failure.
///
/// The other two `ProcessConfig` members are caller-supplied too, and neither is
/// safe to print by association: `entrypoint` and `arguments` are a command line,
/// which is where `--token` and `--password` live. So the impl reaches none of
/// them and reports a count for each instead, and the two lengths are the whole
/// diagnostic — a reader learns the exec was given an environment without
/// learning what was in it.
///
/// What it does report is two digests, two numbers, and four booleans —
/// everything that is either an identifier the caller already holds or a value
/// the caller could not have learned from the document by eye, and nothing that
/// is caller- or daemon-chosen text. `finish_non_exhaustive` closes the door
/// behind that, so a member added later renders as `..` rather than appearing in
/// full by default.
///
/// [`document`](Self::document) and [`into_document`](Self::into_document) are
/// untouched. A caller that *asks* for the environment is making a different
/// decision from one that formats the value while diagnosing a failure.
#[derive(Clone, PartialEq)]
pub struct ExecInspect {
    document: serde_json::Value,
}

impl fmt::Debug for ExecInspect {
    /// Reports the exec's identity and state, and how much of it this crate
    /// does not model.
    ///
    /// Never `ProcessConfig`, in whole or in part, and never the document. Every
    /// field is a digest, a boolean, a number, or a count, so there is no
    /// arbitrary daemon text anywhere in the rendering for a caller to
    /// accidentally log.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecInspect")
            .field("id", &SummaryText(self.id()))
            .field("container", &SummaryText(self.container()))
            .field("running", &self.running())
            .field("exit_code", &self.exit_code())
            .field("pid", &self.pid())
            .field("open_stdin", &self.flag("OpenStdin"))
            .field("open_stdout", &self.flag("OpenStdout"))
            .field("open_stderr", &self.flag("OpenStderr"))
            .field("env", &self.env_count())
            .field("arguments", &self.argument_count())
            .field("members", &self.member_count())
            .finish_non_exhaustive()
    }
}

/// One identity member of the document, rendered with a length bound.
///
/// The same shape as the one in `inspect`, duplicated because a two-line
/// `Debug` helper is not worth a shared module, and the bound it applies is the
/// single shared [`MAX_SUMMARY_TEXT`] rather than a second constant. A
/// truncation is a **length** bound and not a redaction — the prefix is still
/// printed — so it applies to the two digests and to nothing else, and never to
/// anything that could be a credential.
struct SummaryText<'a>(Option<&'a str>);

impl fmt::Debug for SummaryText<'_> {
    /// Prints the member, or how much of it was withheld.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(text) = self.0 else {
            return formatter.write_str("None");
        };
        if text.len() <= MAX_SUMMARY_TEXT {
            return write!(formatter, "Some({text:?})");
        }
        // A `&str` may be cut anywhere, so the bound lands on the next char
        // boundary. Three bytes is the most a UTF-8 character can need to
        // straddle it.
        let mut end = MAX_SUMMARY_TEXT;
        while !text.is_char_boundary(end) {
            end += 1;
        }
        write!(
            formatter,
            "Some({:?}…(+{} byte(s) withheld))",
            &text[..end],
            text.len() - end
        )
    }
}

impl ExecInspect {
    /// Returns the document exactly as the daemon sent it.
    #[must_use]
    pub const fn document(&self) -> &serde_json::Value {
        &self.document
    }

    /// Consumes the answer and returns the document.
    #[must_use]
    pub fn into_document(self) -> serde_json::Value {
        self.document
    }

    /// Projects the answer onto the repository's exec-state model.
    ///
    /// The projection is the one the current facade performs, and it is a view:
    /// the members it has no field for — `ProcessConfig`, `OpenStdin`,
    /// `OpenStderr`, `OpenStdout`, `CanRemove`, `ContainerID`, `DetachKeys`, and
    /// `Pid` — are still in [`ExecInspect::document`].
    ///
    /// **`running` cannot distinguish an absent `Running` from a stopped exec.**
    /// A document of `{}` projects `running: false`, which is also what a daemon
    /// sends for an exec that has exited. Measured against a fixture answering
    /// `200 {}`: `missing Running in document Object {}; projected running =
    /// false`. The information is not lost — `document` has it, or has its absence
    /// — but a caller reading only `state()` cannot tell the two apart, and
    /// `Option<bool>` here would be a different type from the current facade's
    /// `ExecState`. So this is a projection limitation, stated, rather than a
    /// claim that the field is always present.
    #[must_use]
    pub fn state(&self) -> ExecState {
        ExecState {
            id: self.text("ID").map(ToOwned::to_owned),
            running: self.flag("Running").unwrap_or(false),
            // The same read the summary's `exit_code` field makes, through the
            // helper rather than inlined. Two spellings of one member is how a
            // redaction and a projection end up disagreeing about what the
            // member says.
            exit_code: self.exit_code(),
        }
    }

    /// Returns the exec instance's id.
    ///
    /// The Engine spells this member `ID` here and `Id` on the create answer,
    /// which no casing rule produces.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.text("ID")
    }

    /// Returns whether the exec's command is still running.
    #[must_use]
    pub fn running(&self) -> Option<bool> {
        self.flag("Running")
    }

    /// Returns the host pid of the exec process.
    #[must_use]
    pub fn pid(&self) -> Option<i64> {
        self.document.get("Pid").and_then(serde_json::Value::as_i64)
    }

    /// Returns the container this exec belongs to.
    #[must_use]
    pub fn container(&self) -> Option<&str> {
        self.text("ContainerID")
    }

    /// Reads a top-level member as text.
    fn text(&self, member: &str) -> Option<&str> {
        self.document
            .get(member)
            .and_then(serde_json::Value::as_str)
    }

    /// Reads a top-level member as a boolean.
    fn flag(&self, member: &str) -> Option<bool> {
        self.document
            .get(member)
            .and_then(serde_json::Value::as_bool)
    }

    /// Reads a member of the `ProcessConfig` block.
    ///
    /// The block is spelled in **lower** camel case where every other member of
    /// this document is `PascalCase` — `env` and `arguments`, not `Env` and
    /// `Arguments` — because it mirrors the exec-create request this crate
    /// itself sends. The create body writes `Env` and `Cmd`; the daemon stores
    /// the process configuration under its own spelling and returns it that way.
    /// A redaction that looked for the spelling used on the way *in* would find
    /// nothing and report a member as absent, which is the failure mode a count
    /// makes visible: `env: None` would be a claim, and a wrong one.
    fn in_process_config(&self, member: &str) -> Option<&serde_json::Value> {
        self.document.get("ProcessConfig")?.get(member)
    }

    /// Counts the environment entries the exec was created with.
    ///
    /// The count and never the values, which is the entire point: the values are
    /// the credentials, and the count is the question a reader actually has,
    /// which is whether the exec was given an environment at all. `None` rather
    /// than zero for a document with no `ProcessConfig`, so "the daemon sent no
    /// process configuration" and "the exec was created with an empty
    /// environment" stay two different facts.
    fn env_count(&self) -> Option<usize> {
        self.in_process_config("env")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
    }

    /// Counts the arguments the exec's command was created with.
    ///
    /// Counted for the same reason [`env_count`](Self::env_count) counts, and
    /// for one more: a command line is caller-supplied text that regularly
    /// carries a credential in an argument, so a length is the diagnostic and
    /// the text is not.
    fn argument_count(&self) -> Option<usize> {
        self.in_process_config("arguments")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
    }

    /// Counts the top-level members the daemon sent.
    ///
    /// The count that is this type's reason for existing, for the reason
    /// [`ContainerInspect::member_count`](super::ContainerInspect) counts: a
    /// caller can only notice a member it cannot see if the rendering says how
    /// many arrived. `None` rather than zero when the body was not an object.
    fn member_count(&self) -> Option<usize> {
        self.document.as_object().map(serde_json::Map::len)
    }

    /// Returns the last process exit status.
    ///
    /// A running exec reports the status of the process it replaced, so this is
    /// only the exec's exit status once it has stopped — the same caveat
    /// [`ContainerInspect::exit_code`](super::ContainerInspect::exit_code)
    /// carries.
    fn exit_code(&self) -> Option<i64> {
        self.document
            .get("ExitCode")
            .and_then(serde_json::Value::as_i64)
    }
}

/// Options for `POST /exec/{id}/start`.
///
/// The Engine declares two members, `Detach` and `Tty`, and both are always
/// sent. `Tty` is not a request to allocate one — that happened at create time —
/// but a statement about the session being started, and the daemon uses it to
/// decide whether the output it streams is multiplexed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecStartOptions {
    /// Detach from the command, so the daemon returns immediately and the exec's
    /// output is discarded.
    pub detach: bool,
    /// Whether the exec instance was created with a pseudo-TTY.
    pub tty: bool,
}

/// Creates an exec instance inside a container.
///
/// `Cmd` is always sent, even when it is empty. An empty command is refused by
/// the daemon — measured against Docker Engine 29.8.0, both `{}` and
/// `{"Cmd":[]}` are answered `400 {"message":"No exec command specified"}` — and
/// sending it as an empty array rather than omitting it makes that the daemon's
/// answer about an empty command instead of about a missing one.
///
/// Every other member is omitted when the caller did not set it, for the reason
/// the create container body records: the Engine reads a missing member and a
/// `null` member differently for several of them.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` for a container that does not exist, or the `400` above for
/// an empty command — or when the response is not a create document.
pub async fn exec_create(
    engine: &RawEngine,
    container: &str,
    options: &ExecOptions,
) -> Result<ExecCreateResult, Error> {
    let response = engine
        .send(exec_create_request(container, options)?)
        .await?;
    let document = engine_result(response).await?;
    let document: ExecCreateDocument = decode(&document)?;
    Ok(ExecCreateResult { id: document.id })
}

/// Builds the `POST /containers/{id}/exec` request.
fn exec_create_request(container: &str, options: &ExecOptions) -> Result<RawRequest, Error> {
    let request = json_content_type(RawRequest::new(
        Method::POST,
        &container_path(container, "/exec")?,
    ))
    .with_body(json_body(&ExecConfigDocument::new(options))?);
    Ok(request)
}

/// Starts a previously created exec instance.
///
/// The answer is not a document, and the attached case is not read. See
/// [`ExecStarted::is_attached`] and the module documentation for the measured
/// `200` answers.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` for an exec id the daemon does not know — or when the exec
/// reference is empty.
pub async fn exec_start(
    engine: &RawEngine,
    exec: &str,
    options: &ExecStartOptions,
) -> Result<ExecStarted, Error> {
    let response = engine.send(exec_start_request(exec, *options)?).await?;
    let status = response.status;
    // An exec start is accepted on a `2xx` and on the `101` the daemon answers
    // when it upgrades the connection, so the test is "not a rejection" rather
    // than "a success": `101` is informational and `is_success()` is false.
    if !(status.is_informational() || status.is_success()) {
        return Err(engine_result(response)
            .await
            .expect_err("a rejection status is an error"));
    }
    // A detached start answers `200` with no body, so there is nothing to read.
    // An attached start answers with a body the daemon has no reason to end, and
    // dropping the response is what stops it: the socket closes, the daemon
    // observes the disconnect, and the exec's output is discarded.
    drop(response);
    Ok(ExecStarted {
        status,
        detached: options.detach,
    })
}

/// Builds the `POST /exec/{id}/start` request.
fn exec_start_request(exec: &str, options: ExecStartOptions) -> Result<RawRequest, Error> {
    let request = json_content_type(RawRequest::new(Method::POST, &exec_path(exec, "/start")?))
        .with_body(json_body(&ExecStartDocument {
            detach: options.detach,
            tty: options.tty,
        })?);
    Ok(request)
}

/// Reads an exec instance's state.
///
/// The answer is a single JSON document and is bounded like every other
/// document read. It is returned with the daemon's members intact; see the module
/// documentation for what the current facade's projection drops.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such exec instance: <id>`, measured — or when
/// the response is not a JSON document.
pub async fn exec_inspect(engine: &RawEngine, exec: &str) -> Result<ExecInspect, Error> {
    let response = engine.send(exec_inspect_request(exec)?).await?;
    let document = engine_result(response).await?;
    let document: serde_json::Value = decode(&document)?;
    Ok(ExecInspect { document })
}

/// Builds the `GET /exec/{id}/json` request.
fn exec_inspect_request(exec: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(Method::GET, &exec_path(exec, "/json")?))
}

/// Resizes an exec instance's pseudo-TTY.
///
/// The daemon ignores this unless an exec session is actually running with a
/// TTY, and answers `500` or `404` rather than a success. See the module
/// documentation for both measured answers.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the exec reference is empty.
pub async fn exec_resize(
    engine: &RawEngine,
    exec: &str,
    options: &ExecResizeOptions,
) -> Result<(), Error> {
    // A resize answers `200` with no body, so the status is the whole answer
    // and the shared status mapping reads and discards the empty body.
    completed(engine, exec_resize_request(exec, *options)?).await
}

/// Builds the `POST /exec/{id}/resize` request.
///
/// `h` is sent before `w`, which is the order the Engine's documentation spells
/// them in and the order the current facade produces (measured:
/// `POST /exec/<id>/resize?h=40&w=100`).
fn exec_resize_request(exec: &str, options: ExecResizeOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("h", &options.height.to_string());
    query.value("w", &options.width.to_string());
    Ok(with_query(
        RawRequest::new(Method::POST, &exec_path(exec, "/resize")?),
        query.finish(),
    ))
}

/// Builds the `/exec/{reference}{suffix}` path with the reference escaped.
///
/// An empty reference is refused for the reason a container reference is:
/// `/exec//json` is not a request about an exec instance.
fn exec_path(exec: &str, suffix: &str) -> Result<String, Error> {
    if exec.is_empty() {
        return Err(Error::invalid_input(
            "the Engine exec reference must not be empty",
        ));
    }
    Ok(format!("/exec/{}{suffix}", escape_path_segment(exec)))
}

/// The `POST /containers/{id}/exec` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ExecCreateDocument {
    #[serde(rename = "Id")]
    id: String,
}

/// The `POST /containers/{id}/exec` body, in the Engine's spelling.
///
/// The Engine's `ExecConfig` has exactly these members, and the four attach
/// flags are sent only when the caller set them, because a `false` the caller
/// never set and a `false` the caller set are the same request.
#[derive(Debug, Serialize)]
struct ExecConfigDocument<'a> {
    #[serde(rename = "AttachStdin", skip_serializing_if = "Option::is_none")]
    attach_stdin: Option<bool>,
    #[serde(rename = "AttachStdout", skip_serializing_if = "Option::is_none")]
    attach_stdout: Option<bool>,
    #[serde(rename = "AttachStderr", skip_serializing_if = "Option::is_none")]
    attach_stderr: Option<bool>,
    #[serde(rename = "Tty", skip_serializing_if = "Option::is_none")]
    tty: Option<bool>,
    #[serde(rename = "DetachKeys", skip_serializing_if = "Option::is_none")]
    detach_keys: Option<&'a str>,
    #[serde(rename = "Env", skip_serializing_if = "Option::is_none")]
    environment: Option<&'a [String]>,
    // Always sent, including when empty: an absent `Cmd` and an empty one are
    // different requests, and the daemon's `400 No exec command specified`
    // answers both.
    #[serde(rename = "Cmd")]
    command: &'a [String],
    #[serde(rename = "Privileged", skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(rename = "WorkingDir", skip_serializing_if = "Option::is_none")]
    working_dir: Option<&'a str>,
}

impl<'a> ExecConfigDocument<'a> {
    /// Projects the repository's exec options onto the Engine's body.
    fn new(options: &'a ExecOptions) -> Self {
        Self {
            attach_stdin: true_when(options.attach_stdin),
            attach_stdout: true_when(options.attach_stdout),
            attach_stderr: true_when(options.attach_stderr),
            tty: true_when(options.tty),
            detach_keys: options.detach_keys.as_deref(),
            environment: (!options.environment.is_empty()).then_some(&options.environment[..]),
            command: &options.command,
            privileged: true_when(options.privileged),
            user: options.user.as_deref(),
            working_dir: options.working_dir.as_deref(),
        }
    }
}

/// The `POST /exec/{id}/start` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct ExecStartDocument {
    #[serde(rename = "Detach")]
    detach: bool,
    #[serde(rename = "Tty")]
    tty: bool,
}

/// Returns the Engine's spelling of a boolean, or nothing when it is false.
fn true_when(value: bool) -> Option<bool> {
    value.then_some(true)
}

#[cfg(test)]
mod tests {
    use super::{
        ExecConfigDocument, ExecCreateDocument, ExecInspect, ExecStartOptions, exec_create_request,
        exec_inspect_request, exec_path, exec_resize_request, exec_start_request,
    };
    use crate::raw::{RawBody, RawEngine, RawTarget};
    use crate::{ApiVersion, ErrorKind, ExecOptions, ExecResizeOptions};

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

    /// Renders the request body as parsed JSON, so an assertion names members
    /// rather than depending on their order in the serialized text.
    fn request_body(request: &super::RawRequest) -> serde_json::Value {
        match &request.body {
            RawBody::Bytes(bytes) => serde_json::from_slice(bytes).expect("a JSON body"),
            other => panic!("expected a buffered body, got {other:?}"),
        }
    }

    /// The exec-inspect answer recorded from Docker Engine 29.8.0, abbreviated
    /// only in `ProcessConfig`'s value.
    const EXEC_INSPECT_BODY: &[u8] = br#"{
        "CanRemove":false,"ContainerID":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344",
        "DetachKeys":"","ExitCode":0,
        "ID":"3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477",
        "OpenStderr":true,"OpenStdin":false,"OpenStdout":true,"Pid":935200,
        "ProcessConfig":{"tty":false,"entrypoint":"echo","arguments":["exechello"],"privileged":false},
        "Running":false}"#;

    /// The same answer as the daemon sends it when the exec was created with an
    /// environment, which is the case [`EXEC_INSPECT_BODY`] above is not.
    ///
    /// `ProcessConfig.env` is the member the whole `Debug` impl exists for, so
    /// the recorded body has to carry one or there is nothing to withhold — and
    /// it has to carry the daemon's lower-camel-case spelling, because an `Env`
    /// here would let an accessor written for the create request's spelling pass
    /// a test it should fail.
    const EXEC_INSPECT_BODY_WITH_ENV: &[u8] = br#"{
        "CanRemove":false,"ContainerID":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344",
        "DetachKeys":"","ExitCode":0,
        "ID":"3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477",
        "OpenStderr":true,"OpenStdin":false,"OpenStdout":true,"Pid":935200,
        "ProcessConfig":{"tty":false,"entrypoint":"echo","arguments":["exechello"],
            "env":["PATH=/usr/bin","AWS_SECRET_ACCESS_KEY=AKIA-EXAMPLE-NOT-REAL",
                   "DATABASE_URL=postgres://user:pw@db/web"]},
        "Running":false}"#;

    /// Builds an inspect answer from a body, the way `exec_inspect` does.
    fn of(body: &[u8]) -> ExecInspect {
        let document: serde_json::Value =
            super::super::decode(body).expect("the fixture is a document");
        ExecInspect { document }
    }

    #[test]
    fn the_summary_never_renders_the_process_configuration() {
        let rendered = format!("{:?}", of(EXEC_INSPECT_BODY_WITH_ENV));
        // Every member of `ProcessConfig` is caller-supplied, so every one of
        // them is withheld: the two credentials, the command line, and the
        // working directory the daemon echoes from the create request.
        assert!(!rendered.contains("AWS_SECRET_ACCESS_KEY"), "{rendered}");
        assert!(!rendered.contains("DATABASE_URL"), "{rendered}");
        assert!(!rendered.contains("postgres://"), "{rendered}");
        assert!(!rendered.contains("exechello"), "{rendered}");
        assert!(!rendered.contains("echo"), "{rendered}");
        assert!(!rendered.contains("PATH=/usr/bin"), "{rendered}");

        // What a caller reads an exec inspect answer for all survives, so the
        // redaction has not cost the type its reason to exist.
        assert!(rendered.contains("id: Some(\"3101d054e782"), "{rendered}");
        assert!(
            rendered.contains("container: Some(\"38df04270233"),
            "{rendered}"
        );
        assert!(rendered.contains("running: Some(false)"), "{rendered}");
        assert!(rendered.contains("exit_code: Some(0)"), "{rendered}");
        assert!(rendered.contains("pid: Some(935200)"), "{rendered}");
        assert!(rendered.contains("open_stdin: Some(false)"), "{rendered}");
        assert!(rendered.contains("open_stdout: Some(true)"), "{rendered}");
        assert!(rendered.contains("open_stderr: Some(true)"), "{rendered}");
        // The counts stand in for what was withheld, so a reader can tell an
        // exec given three environment entries from one given none — which is
        // the question a failing one-off command actually raises.
        assert!(rendered.contains("env: Some(3)"), "{rendered}");
        assert!(rendered.contains("arguments: Some(1)"), "{rendered}");
        assert!(rendered.contains("members: Some(11)"), "{rendered}");
        // And the door left open for a member added later.
        assert!(rendered.contains(".."), "{rendered}");
    }

    #[test]
    fn an_exec_with_no_process_configuration_says_none_was_reported() {
        // "The daemon sent no process configuration" and "the exec was created
        // with an empty environment" are different facts, and a rendering that
        // showed a count for a member that never arrived would be telling a
        // reader the implementation looked somewhere it did not.
        let rendered = format!("{:?}", of(br#"{"ID":"3101d054e782"}"#));
        assert!(rendered.contains("env: None"), "{rendered}");
        assert!(rendered.contains("arguments: None"), "{rendered}");
        assert!(rendered.contains("members: Some(1)"), "{rendered}");
        // The identity members still read, so this is not merely a shape.
        assert!(
            rendered.contains("id: Some(\"3101d054e782\")"),
            "{rendered}"
        );
        assert!(rendered.contains("container: None"), "{rendered}");
    }

    #[test]
    fn an_empty_environment_counts_as_zero_rather_than_being_absent() {
        // The create request omits `Env` when the caller set none, so the daemon
        // may report the member as an empty array rather than omitting it. Both
        // are real answers and only one of them is "the caller passed nothing",
        // so they are not the same rendering.
        let with_member = format!("{:?}", of(br#"{"ID":"x","ProcessConfig":{"env":[]}}"#));
        assert!(with_member.contains("env: Some(0)"), "{with_member}");
        let without = format!("{:?}", of(br#"{"ID":"x","ProcessConfig":{}}"#));
        assert!(without.contains("env: None"), "{without}");
    }

    #[test]
    fn a_member_longer_than_the_bound_is_cut_at_a_character_boundary() {
        // The same arithmetic as the bound beside `ContainerInspect`: one ASCII
        // byte, then two-byte characters, so the bound at 128 lands inside the
        // 64th of them. Without the boundary walk this panics, which is the
        // whole reason the walk is there.
        let long = format!("x{}", "é".repeat(100));
        assert!(
            !long.is_char_boundary(super::MAX_SUMMARY_TEXT),
            "the fixture must straddle the bound, or this test proves nothing"
        );
        let cut = format!("x{}", "é".repeat(64));
        let withheld = long.len() - cut.len();

        let rendered = format!(
            "{:?}",
            of(&{
                let mut body = br#"{"ID":""#.to_vec();
                body.extend_from_slice(long.as_bytes());
                body.extend_from_slice(br#""}"#);
                body
            })
        );
        assert!(
            rendered.contains(&format!("Some({cut:?}…(+{withheld} byte(s) withheld))")),
            "{rendered}"
        );
        assert!(!rendered.contains(&long), "{rendered}");
    }

    #[test]
    fn a_body_that_is_not_an_object_reports_no_members_rather_than_zero() {
        let rendered = format!("{:?}", of(b"null"));
        assert!(rendered.contains("members: None"), "{rendered}");
        assert!(rendered.contains("id: None"), "{rendered}");
        assert!(rendered.contains("env: None"), "{rendered}");
    }

    #[test]
    fn the_projection_and_the_document_are_untouched_by_the_summary() {
        // The redaction is a property of `Debug` and not of the API, so
        // `state()`, `document()` and `into_document()` still see the
        // environment in full — a caller that asks for it is making a different
        // decision from one that formats the value.
        let inspect = of(EXEC_INSPECT_BODY_WITH_ENV);
        assert!(
            serde_json::to_string(inspect.document())
                .expect("a document serialises")
                .contains("AWS_SECRET_ACCESS_KEY")
        );
        assert_eq!(
            inspect.id(),
            Some("3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477")
        );
        assert_eq!(inspect.running(), Some(false));
        assert_eq!(inspect.pid(), Some(935_200));
        assert_eq!(
            inspect.container(),
            Some("38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344")
        );
        let state = inspect.state();
        assert!(!state.running);
        assert_eq!(state.exit_code, Some(0));
        // Clone and PartialEq still compare the document.
        assert_eq!(inspect, inspect.clone());
        assert_ne!(inspect, of(EXEC_INSPECT_BODY));
    }

    fn options() -> ExecOptions {
        ExecOptions {
            attach_stdin: true,
            attach_stdout: true,
            attach_stderr: true,
            tty: true,
            detach_keys: Some("ctrl-p,ctrl-q".to_owned()),
            environment: vec!["A=B".to_owned()],
            command: vec!["echo".to_owned(), "hi".to_owned()],
            privileged: true,
            user: Some("root".to_owned()),
            working_dir: Some("/tmp".to_owned()),
        }
    }

    #[test]
    fn exec_create_sends_the_versioned_path_and_the_engines_member_names() {
        let request = exec_create_request("web/1", &options()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/web%2F1/exec HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["AttachStdin"], true);
        assert_eq!(body["AttachStdout"], true);
        assert_eq!(body["AttachStderr"], true);
        assert_eq!(body["Tty"], true);
        assert_eq!(body["DetachKeys"], "ctrl-p,ctrl-q");
        assert_eq!(body["Env"][0], "A=B");
        assert_eq!(body["Cmd"][1], "hi");
        assert_eq!(body["Privileged"], true);
        assert_eq!(body["User"], "root");
        assert_eq!(body["WorkingDir"], "/tmp");
    }

    #[test]
    fn an_unset_exec_member_is_omitted_rather_than_sent_as_false() {
        // The Engine reads a missing member and a `false` one differently for
        // several of these, and an unset repository option means "not asked for".
        let body =
            request_body(&exec_create_request("web", &ExecOptions::default()).expect("request"));
        let object = body.as_object().expect("an object");
        // Only `Cmd` is unconditional, and it is empty here.
        assert_eq!(object.keys().collect::<Vec<_>>(), vec!["Cmd"]);
        assert_eq!(body["Cmd"], serde_json::json!([]));
    }

    #[test]
    fn an_empty_command_is_sent_as_an_empty_array_not_as_an_absent_member() {
        // The daemon answers a missing `Cmd` and an empty one with the same
        // `400 No exec command specified`, and a body that says which one was
        // sent is a body somebody can debug.
        let body = request_body(
            &exec_create_request(
                "web",
                &ExecOptions {
                    command: Vec::new(),
                    ..Default::default()
                },
            )
            .expect("request"),
        );
        assert!(body.get("Cmd").is_some(), "{body}");
        assert!(
            body.get("Cmd")
                .expect("Cmd")
                .as_array()
                .expect("an array")
                .is_empty()
        );
    }

    #[test]
    fn exec_start_sends_both_members_even_when_they_are_false() {
        // `Tty` is a statement about the session being started, not a request to
        // allocate one, so it is always present.
        let request = exec_start_request("e1", ExecStartOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/exec/e1/start HTTP/1.1")
        );
        assert_eq!(
            request_body(&request),
            serde_json::json!({"Detach": false, "Tty": false})
        );
    }

    #[test]
    fn a_detached_start_is_the_shape_a_caller_can_use() {
        let request = exec_start_request(
            "e1",
            ExecStartOptions {
                detach: true,
                tty: true,
            },
        )
        .expect("request");
        assert_eq!(
            request_body(&request),
            serde_json::json!({"Detach": true, "Tty": true})
        );
    }

    #[test]
    fn exec_inspect_and_resize_address_the_exec_and_nothing_else() {
        assert_eq!(
            request_line(&exec_inspect_request("e1").expect("request")),
            crate::raw::at_api_version("GET /v1.API/exec/e1/json HTTP/1.1")
        );
        assert_eq!(
            request_line(
                &exec_resize_request(
                    "e1",
                    ExecResizeOptions {
                        height: 40,
                        width: 100,
                    },
                )
                .expect("request")
            ),
            crate::raw::at_api_version("POST /v1.API/exec/e1/resize?h=40&w=100 HTTP/1.1")
        );
    }

    #[test]
    fn an_exec_reference_cannot_reshape_its_path() {
        // `/exec/a/b/json` is a three-segment path, not the inspect of an exec
        // named `a/b`.
        assert_eq!(
            exec_path("a/b", "/json").expect("a path"),
            "/exec/a%2Fb/json"
        );
        assert_eq!(
            request_line(&exec_inspect_request("a/b").expect("request")),
            crate::raw::at_api_version("GET /v1.API/exec/a%2Fb/json HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_exec_reference_is_refused_by_every_operation() {
        for error in [
            exec_path("", "/json").expect_err("empty reference"),
            exec_start_request("", ExecStartOptions::default()).expect_err("empty reference"),
            exec_inspect_request("").expect_err("empty reference"),
            exec_resize_request("", ExecResizeOptions::default()).expect_err("empty reference"),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
        assert_eq!(
            exec_create_request("", &ExecOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn the_exec_body_documents_serialize_to_the_engines_member_names() {
        // The `ExecConfig` member names are all PascalCase, and a `rename_all`
        // rule would have produced the same result here by luck rather than by
        // intent, so the mapping is asserted member by member.
        let body = crate::raw::json_body(&ExecConfigDocument::new(&options())).expect("a body");
        let RawBody::Bytes(bytes) = body else {
            panic!("a buffered body");
        };
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        for member in [
            "AttachStdin",
            "AttachStdout",
            "AttachStderr",
            "Tty",
            "DetachKeys",
            "Env",
            "Cmd",
            "Privileged",
            "User",
            "WorkingDir",
        ] {
            assert!(decoded.get(member).is_some(), "member {member} is missing");
        }
    }

    #[test]
    fn a_create_answer_reads_the_engines_spelling() {
        // `Id` here and `ID` in the inspect answer: the Engine is not
        // consistent, and a casing rule cannot produce both.
        let document: ExecCreateDocument =
            super::decode(br#"{"Id":"3101d054e782"}"#).expect("a create document");
        assert_eq!(document.id, "3101d054e782");
    }

    #[test]
    fn the_exec_inspect_document_keeps_all_eleven_members() {
        let inspect: ExecInspect = {
            let document: serde_json::Value = super::decode(EXEC_INSPECT_BODY).expect("a document");
            ExecInspect { document }
        };
        for member in [
            "CanRemove",
            "ContainerID",
            "DetachKeys",
            "ExitCode",
            "ID",
            "OpenStderr",
            "OpenStdin",
            "OpenStdout",
            "Pid",
            "ProcessConfig",
            "Running",
        ] {
            assert!(
                inspect.document().get(member).is_some(),
                "member {member} was dropped"
            );
        }
        assert_eq!(
            inspect.document().as_object().expect("an object").len(),
            11,
            "every member the daemon sent is still here"
        );
    }

    #[test]
    fn the_exec_state_projection_is_the_three_members_the_repository_model_has() {
        let inspect: ExecInspect = {
            let document: serde_json::Value = super::decode(EXEC_INSPECT_BODY).expect("a document");
            ExecInspect { document }
        };
        let state = inspect.state();
        assert_eq!(
            state.id.as_deref(),
            Some("3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477")
        );
        assert!(!state.running);
        assert_eq!(state.exit_code, Some(0));
        // The eight members the projection has no field for are still readable
        // from the same value.
        assert_eq!(inspect.pid(), Some(935_200));
        assert_eq!(
            inspect.container(),
            Some("38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344")
        );
        assert_eq!(inspect.running(), Some(false));
        assert_eq!(inspect.id(), state.id.as_deref());
    }

    #[test]
    fn an_exec_that_has_not_run_reports_a_null_exit_code_as_absent() {
        // Recorded from Docker Engine 29.8.0 for a created-but-unstarted exec:
        // `"ExitCode":null`. A null is not a status, so it is reported as unknown
        // rather than as zero, which would be indistinguishable from a command
        // that exited successfully.
        let inspect: ExecInspect = {
            let document: serde_json::Value =
                super::decode(br#"{"ID":"e1","Running":false,"ExitCode":null}"#)
                    .expect("a document");
            ExecInspect { document }
        };
        assert_eq!(inspect.state().exit_code, None);
    }
}
