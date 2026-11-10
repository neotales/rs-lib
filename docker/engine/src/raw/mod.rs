//! The repository-owned Engine backend.
//!
//! This module is the implementation side of the escape path described in
//! `docs/docker/engine-backend-alternatives.md`. The public `DockerClient` still
//! speaks to Bollard; nothing here is reachable from outside the crate, and
//! nothing here changes existing behavior. It exists so that the alternative can
//! be built, measured, and differentially tested against the current
//! implementation instead of argued about.
//!
//! # What the backend covers
//!
//! The first vertical slice is the one the decision record nominates: `ping`,
//! `version`, and `info`, over a Unix socket and over TCP. Those three
//! operations are enough to exercise every part of the transport that matters —
//! versioned paths, query encoding, response decoding, header access, status
//! mapping, and Engine error bodies — without yet depending on streaming,
//! attach, or bidirectional I/O.
//!
//! The second slice is the container lifecycle:
//! [`container_list`],
//! [`container_create`],
//! [`container_start`],
//! [`container_stop`],
//! [`container_remove`] and
//! [`container_wait`]. It adds the two request shapes the first
//! slice had no use for — a buffered JSON request body, and a success whose
//! status is the whole answer (`204` with no body) — and it decodes into the
//! repository-owned container models rather than into generated ones. It was
//! verified end to end against Docker Engine 29.8.0 over a Unix socket, not
//! only against fixtures.
//!
//! The third slice is the rest of the container surface: [`inspect`], [`kill`],
//! [`pause`], [`unpause`], [`rename`], [`update`], [`prune`], [`changes`],
//! [`resize`], [`stats`], [`stats_stream`], [`attach`], and the four exec
//! operations. One of them needs a streaming answer and two of them need a
//! connection the daemon takes over, and each of those three facts is stated
//! where it is implemented rather than guessed at from the endpoint name.
//!
//! # Which answers are documents and which are streams
//!
//! This is the decision every added operation has to make, so it is recorded
//! once here. An operation's answer is a **document** unless the daemon writes
//! more than the caller can hold, and a document goes through
//! [`RawResponse::document`] and is therefore bounded by
//! [`MAX_DOCUMENT_BYTES`]. A stream is not read that way. Newline-delimited JSON
//! records read through [`FrameStream::next_json`] are bounded separately by
//! [`MAX_RECORD_BYTES`]; this is not a universal limit on every streaming
//! decoder, though the other one is held to the same number. The
//! multiplexed-frame decoder used by [`logs`] is bounded by
//! [`MAX_FRAME_BYTES`], which is [`MAX_RECORD_BYTES`] again: it is the declared
//! length in a frame header rather than a terminator that sets the ceiling
//! there, so the check happens when the header is parsed and before the payload
//! is taken. It bounds a *framed* frame: a TTY body has no header and so no
//! declared length, which is stated at the constant rather than left to be
//! inferred from a name. The streaming cases in this module, and only these:
//!
//! | Operation | Answer | Why it cannot be a document |
//! | --- | --- | --- |
//! | [`logs`] | a frame stream | `follow` keeps writing for as long as the container runs |
//! | [`stats_stream`] | a frame stream | one JSON object per second, forever, while the container runs |
//! | [`attach`] | not read at all | the daemon hijacks the connection and declares no length |
//! | [`exec_start`] | not read at all | the same, for an attached exec |
//!
//! A request body never streams. Nothing in the container surface uploads
//! anything a caller would not want buffered — archives and build contexts do,
//! and those are not here.
//!
//! # What the backend deliberately does not cover
//!
//! - **TLS, SSH, and forward-proxy connections.** [`RawTarget::Tcp`] is a plain
//!   TCP stream. Wrapping it in a TLS or SSH stream is additive, but it is not
//!   written yet and no code pretends otherwise.
//! - **Connection hijack and h2c, partly.** [`attach`] now takes the upgraded
//!   (`101`) connection and returns it as [`Attached::Upgraded`] when the caller
//!   asked to stream or to write, so it does **not** drop the response in that
//!   case; the "reports the status and drops it" description here was stale. What
//!   is still missing is the hijacked body — `200` with no content length, which
//!   the daemon uses for some stdio paths — and h2c. That remains step 6 of the
//!   decision record's migration order.
//!
//!   [`exec_start`] still reports the status and drops the response, which closes
//!   the socket, and still calls `is_attached()` true once the output socket has
//!   been discarded. So the two operations named side by side here no longer
//!   behave alike, and only one of them is done.
//! - **Streaming request bodies.** [`RawBody::Stream`] exists and is tested
//!   at the transport layer, but no Engine operation sends one yet.
//! - **Images, networks, volumes, system, and plugins.** Migration steps 3
//!   through 4. The container surface is done apart from `commit`, checkpoints,
//!   `top`, and the archive endpoints.
//!
//! - **Socket-level differential fixtures for the Swarm slice.** The Swarm
//!   operations are pinned by request-line and body unit tests and decode the
//!   repository's own Swarm fixture documents, but no fixture *server* stands in
//!   for the daemon, so no claim is made that the owned path and the Bollard path
//!   agree byte for byte over a connection the way the container slice's
//!   differential fixtures show. The container slice is the one with that
//!   evidence; Swarm has the typed-model evidence and not yet the wire evidence.
//!
//! Each of those is a real gap, stated here rather than left for a caller to
//! discover.
//!
//! # Example
//!
//! ```
//! # use neotales_docker::raw::{RawEngine, RawTarget, info, ping};
//! # use neotales_docker::raw::{container_create, container_list, container_start};
//! # use neotales_docker::{ContainerCreateOptions, ContainerListOptions, ContainerStartOptions};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = RawEngine::new(
//!     RawTarget::Unix("/var/run/docker.sock".into()),
//!     neotales_docker::API_VERSION,
//! );
//!
//! // `/_ping` carries its answer in headers, so the owned client returns them
//! // typed instead of collapsing five capabilities into one string.
//! let capabilities = ping(&engine).await?;
//! println!(
//!     "daemon API {:?}, swarm {:?}",
//!     capabilities.api_version, capabilities.swarm
//! );
//!
//! // Versioned paths: the daemon receives `/v1.55/info`, not `/info` -- the
//! // version is `API_VERSION`, so this moves when the ceiling does.
//! let daemon = info(&engine).await?;
//! println!("{}", daemon.get("ServerVersion").and_then(|value| value.as_str()).unwrap_or("?"));
//!
//! // The container slice speaks the same versioned paths and hands back the
//! // repository-owned models rather than generated ones.
//! let containers = container_list(&engine, &ContainerListOptions { all: true, ..Default::default() }).await?;
//! println!("{} containers", containers.len());
//! let created = container_create(&engine, &ContainerCreateOptions {
//!     image: "alpine:3.19".to_owned(),
//!     name: Some("slice".to_owned()),
//!     ..Default::default()
//! })
//! .await?;
//! container_start(&engine, &created.id, &ContainerStartOptions::default()).await?;
//! # Ok(())
//! # }
//! ```

/// Substitutes the crate's live Engine API version into a request-line
/// expectation.
///
/// The request-shape assertions across this module's submodules spell out whole
/// request lines, and every one of them begins `GET /v1.NN/...`. Those are
/// *plumbing* assertions: their subject is the path and the query encoding, not
/// the number in the prefix. Spelling the number as a literal in 130 of them
/// means a legitimate ceiling change breaks 130 tests that were correct, and the
/// result is that whoever raises the ceiling deletes them instead of reading
/// them — which is how a request-shape check stops existing without anyone
/// deciding it should.
///
/// So the expectations carry a `v1.API` marker and this substitutes the live
/// constant. The check is not weakened: the substituted value is
/// `crate::API_VERSION`, so a request that put a *different* version on the
/// wire still fails here. Only the number's spelling is no longer duplicated.
///
/// This is a test-only helper rather than one more piece of public surface,
/// which is why it is `#[cfg(test)]` and `pub(crate)`.
#[cfg(test)]
pub(crate) fn at_api_version(line: &str) -> String {
    const MARKER: &str = "/v1.API";
    let prefix = format!(
        "/v{}.{}",
        crate::API_VERSION.major,
        crate::API_VERSION.minor
    );
    assert!(
        line.contains(MARKER),
        "a request-line expectation must carry the {MARKER} marker so the version is \
         substituted rather than duplicated: {line:?}"
    );
    line.replace(MARKER, &prefix)
}

/// The `/v1.NN` prefix the owned transport puts on every path.
#[cfg(test)]
pub(crate) fn api_version_prefix() -> String {
    format!(
        "/v{}.{}",
        crate::API_VERSION.major,
        crate::API_VERSION.minor
    )
}

mod body;
mod containers;
mod control;
mod exec;
mod image_transfer;
mod images;
mod inspect;
mod logs;
mod networks;
mod plugins;
mod resources;
mod stats;
mod swarm;
mod system;
mod transport;
mod volumes;

use hyper::Method;
use hyper::header::HeaderName;

pub use body::{
    ConnectionDriver, FrameStream, MAX_DOCUMENT_BYTES, MAX_RECORD_BYTES, RawBody, RawBodyError,
    RawResponse, RecordLimitError, RequestBody, SwitchedConnection, SwitchedReadHalf,
    SwitchedWriteHalf,
};
pub use containers::{
    container_create, container_list, container_remove, container_start, container_stop,
    container_wait,
};
pub use control::{
    Attached, ContainerAttachOptions, ContainerKillOptions, ContainerResizeOptions, attach, kill,
    pause, rename, resize, unpause,
};
pub use exec::{
    ExecCreateResult, ExecInspect, ExecStartOptions, ExecStarted, exec_create, exec_inspect,
    exec_resize, exec_start,
};
pub use image_transfer::{
    MAX_UPLOAD_BYTES, RegistryAuth, build, import, load, progress_error, pull_stream, push_stream,
    save,
};
pub use images::{
    image_history, image_history_documents, image_inspect, image_inspect_document, image_list,
    image_list_documents, image_prune, image_prune_document, image_pull_document,
    image_push_document, image_remove, image_search, image_search_documents, image_tag,
};
pub use inspect::{ContainerInspect, inspect};
pub use logs::{
    ContainerLogOptions, FRAME_HEADER_BYTES, LogDecoder, LogFrame, LogFrames, LogStream,
    MAX_FRAME_BYTES, logs,
};
pub use networks::{
    NetworkEntry, network_connect, network_create, network_disconnect, network_inspect,
    network_list, network_prune, network_remove,
};
pub use plugins::{
    plugin_disable, plugin_enable, plugin_inspect, plugin_list, plugin_privileges, plugin_pull,
    plugin_remove, plugin_upgrade,
};
pub use resources::{changes, prune, update};
pub use stats::{StatsOptions, stats, stats_stream};
pub use swarm::{
    SwarmLogFrames, config_create, config_inspect, config_list, config_remove, config_update,
    node_inspect, node_list, node_remove, node_update, secret_create, secret_inspect, secret_list,
    secret_remove, secret_update, service_create, service_inspect, service_list, service_logs,
    service_remove, service_update, swarm_certificates, swarm_init, swarm_inspect, swarm_join,
    swarm_join_token, swarm_leave, swarm_unlock, swarm_unlock_key, swarm_update, task_inspect,
    task_list, task_logs,
};
pub use system::{DiskUsageReport, disk_usage, events, prune_build_cache};
pub use transport::{
    Duplex, RawEngine, RawRequest, RawTarget, StreamFactory, StreamFuture, collect_json_frames,
    decode, engine_result, json_body, json_content_type,
};
pub use volumes::{volume_create, volume_inspect, volume_list, volume_prune, volume_remove};

use crate::Error;

/// The `API-Version` header of a `GET /_ping` response.
///
/// The Engine's capability headers are not standard HTTP header names, so
/// `hyper` provides no constants for them and they are spelled here once rather
/// than as string literals at each use.
static API_VERSION: HeaderName = HeaderName::from_static("api-version");
/// The `OSType` header of a `GET /_ping` response.
static OSTYPE: HeaderName = HeaderName::from_static("ostype");
/// The `Docker-Experimental` header of a `GET /_ping` response.
static DOCKER_EXPERIMENTAL: HeaderName = HeaderName::from_static("docker-experimental");
/// The `Builder-Version` header of a `GET /_ping` response.
static BUILDER_VERSION: HeaderName = HeaderName::from_static("builder-version");
/// The `Swarm` header of a `GET /_ping` response.
static SWARM: HeaderName = HeaderName::from_static("swarm");

impl From<RawBodyError> for Error {
    /// Classifies a body read failure as a transport failure.
    ///
    /// A daemon that answers and then drops the connection has not rejected the
    /// request, so reporting that as invalid input would blame the caller for
    /// something they did not do.
    fn from(error: RawBodyError) -> Self {
        Error::transport(error.to_string())
    }
}

/// The `GET /_ping` answer.
///
/// `/_ping` carries its result in headers, not a body, and the headers are the
/// only way to learn the daemon's API version, operating system, and Swarm state
/// before committing to a request. A `String` return cannot express that, which
/// is the concrete reason the owned backend keeps its own type here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ping {
    /// The highest Engine API version the daemon serves.
    pub api_version: Option<String>,
    /// The daemon's operating-system family, such as `linux`.
    pub os_type: Option<String>,
    /// Whether the daemon has experimental features enabled.
    pub experimental: Option<bool>,
    /// The daemon's builder version, when it reports one.
    pub builder_version: Option<String>,
    /// The Swarm node state, when the daemon is part of a Swarm.
    pub swarm: Option<String>,
}

impl Ping {
    /// Reads the answer out of the response headers.
    #[must_use]
    pub fn from_headers(headers: &hyper::HeaderMap) -> Self {
        Self {
            api_version: text(headers, &API_VERSION),
            os_type: text(headers, &OSTYPE),
            experimental: flag(headers, &DOCKER_EXPERIMENTAL),
            builder_version: text(headers, &BUILDER_VERSION),
            swarm: text(headers, &SWARM),
        }
    }
}

/// Reads a header as UTF-8 text.
fn text(headers: &hyper::HeaderMap, name: &HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Reads a boolean header, treating an unparsable value as absent.
///
/// The Engine spells this header `true` or `false`. A daemon that sends
/// something else has not made a claim this client can act on, so the field is
/// reported as unknown instead of guessing.
fn flag(headers: &hyper::HeaderMap, name: &HeaderName) -> Option<bool> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

/// Pings the daemon and reads its capability headers.
///
/// The status is checked, but the body is not required: a daemon that answers a
/// healthy `/_ping` with an empty body is normal, and one that answers `200`
/// with a failure in the body is a daemon bug rather than a client concern. The
/// headers are the answer.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, or when it rejects the
/// request instead of reporting its capabilities.
pub async fn ping(engine: &RawEngine) -> Result<Ping, Error> {
    let response = engine.send(RawRequest::new(Method::GET, "/_ping")).await?;
    if !response.is_success() {
        return Err(Error::engine_api(
            response.status,
            format!(
                "daemon rejected /_ping with HTTP {}",
                response.status.as_u16()
            ),
        ));
    }
    Ok(Ping::from_headers(&response.headers))
}

/// Reads the daemon version document.
///
/// The document is returned as JSON rather than a generated struct on purpose:
/// the Engine adds members to it between releases, and a client that drops
/// unknown members would report a version the daemon did not send. Callers that
/// want typed fields read them out of the returned value.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it reports a
/// failure, or when the response is not a JSON object.
pub async fn version(engine: &RawEngine) -> Result<serde_json::Value, Error> {
    let response = engine
        .send(RawRequest::new(Method::GET, "/version"))
        .await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Reads the daemon `info` document.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it reports a
/// failure, or when the response is not a JSON object.
pub async fn info(engine: &RawEngine) -> Result<serde_json::Value, Error> {
    let response = engine.send(RawRequest::new(Method::GET, "/info")).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Decodes a list member the Engine answers with `null` rather than `[]`.
///
/// The Engine sends `"Warnings": null` for an operation that produced none, and
/// `#[serde(default)]` does not help there: it covers an *absent* member, while
/// this is a member that is present and null. Measured on Docker 29.8.0:
/// `POST /containers/{id}/update` answers `{"Warnings":null}`, and so does
/// `POST /services/create` when the service came up without a complaint. Without
/// this, every such response fails to decode and the operation reports an
/// invalid-input error for a request the daemon accepted.
///
/// The alternative — telling the Engine not to send null — does not exist, and
/// treating a null list as empty is what a reader of the response means by it.
pub(crate) fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    // A path through `Option` rather than a match on the deserializer: `null` is
    // the one input that has to become an empty list, and every other input has
    // to be a real list or a real error.
    Ok(<Option<Vec<T>> as serde::Deserialize>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::api_version_prefix;
    use super::at_api_version;
    use super::transport::{engine_message, trim_ascii};
    use super::{Ping, RawEngine, RawRequest, RawTarget};
    use crate::{ApiVersion, ErrorKind};
    use hyper::{Method, StatusCode};

    /// The version this module's assertions build requests at.
    ///
    /// The crate's ceiling, not a literal. Every assertion here is about how the
    /// prefix is *built* — that it is present, that it precedes the path, that
    /// the query follows it — and none of them is about the number, so a literal
    /// would make a correct ceiling change look like a regression.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    #[test]
    fn every_path_is_prefixed_with_the_negotiated_version() {
        let request =
            RawRequest::new(Method::GET, "/containers/json").with_query("all=1&filters=%7B%7D");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(
            uri,
            format!(
                "{}/containers/json?all=1&filters=%7B%7D",
                api_version_prefix()
            )
        );
    }

    /// The prefix is the crate's ceiling, and a literal says so out loud.
    ///
    /// The test above derives its expectation, which is right for what it is
    /// about but means nothing in the file asserts the *number*. If
    /// `at_api_version` or `api_version_prefix` were reading a constant other
    /// than the one `API_VERSION` names, every derived assertion in the module
    /// would still agree with itself and pass. This is the one place that
    /// compares the rendered prefix against the number written by hand, which
    /// is why it keeps a literal where its neighbours do not.
    #[test]
    fn the_prefix_is_the_version_the_crate_claims() {
        let request = RawRequest::new(Method::GET, "/info");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(uri, "/v1.55/info");
        assert_eq!(api_version_prefix(), "/v1.55");
        assert_eq!(
            at_api_version("GET /v1.API/info HTTP/1.1"),
            "GET /v1.55/info HTTP/1.1"
        );
    }

    #[test]
    fn a_relative_path_is_refused_rather_than_guessed() {
        let request = RawRequest::new(Method::GET, "containers/json");
        let error = engine().request_uri(&request).expect_err("relative path");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_query_is_appended_after_the_versioned_path() {
        let request = RawRequest::new(Method::GET, "/containers/json").with_query("all=1");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(
            uri,
            format!("{}/containers/json?all=1", api_version_prefix())
        );
    }

    #[test]
    fn a_request_without_a_query_has_no_question_mark() {
        let request = RawRequest::new(Method::GET, "/info");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(uri, format!("{}/info", api_version_prefix()));
        assert!(!uri.contains('?'));
    }

    #[test]
    fn ping_reads_every_capability_header_the_daemon_sends() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("api-version", "1.53".parse().expect("header"));
        headers.insert("ostype", "linux".parse().expect("header"));
        headers.insert("docker-experimental", "true".parse().expect("header"));
        headers.insert("builder-version", "2".parse().expect("header"));
        headers.insert("swarm", "active".parse().expect("header"));
        let ping = Ping::from_headers(&headers);
        assert_eq!(ping.api_version.as_deref(), Some("1.53"));
        assert_eq!(ping.os_type.as_deref(), Some("linux"));
        assert_eq!(ping.experimental, Some(true));
        assert_eq!(ping.builder_version.as_deref(), Some("2"));
        assert_eq!(ping.swarm.as_deref(), Some("active"));
    }

    #[test]
    fn an_unparsable_boolean_header_is_unknown_rather_than_guessed() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("docker-experimental", "maybe".parse().expect("header"));
        assert_eq!(Ping::from_headers(&headers).experimental, None);
    }

    #[test]
    fn a_daemon_error_message_is_preserved_verbatim() {
        let message = engine_message(
            br#"{"message":"no such container: ghost"}"#,
            StatusCode::NOT_FOUND,
        );
        assert_eq!(message, "no such container: ghost");
    }

    #[test]
    fn an_unparsable_error_body_falls_back_to_the_status_rather_than_a_parse_complaint() {
        let message = engine_message(b"<html>gateway timeout</html>", StatusCode::BAD_GATEWAY);
        assert_eq!(message, "daemon returned HTTP 502 Bad Gateway");
        let empty = engine_message(b"", StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(empty, "daemon returned HTTP 500 Internal Server Error");
    }

    #[test]
    fn an_empty_error_message_does_not_become_the_user_facing_text() {
        let message = engine_message(br#"{"message":""}"#, StatusCode::CONFLICT);
        assert_eq!(message, "daemon returned HTTP 409 Conflict");
    }

    #[test]
    fn ascii_trimming_handles_both_ends_and_all_whitespace() {
        assert_eq!(trim_ascii(b"  {} \r\n"), b"{}");
        assert_eq!(trim_ascii(b"{}"), b"{}");
        assert_eq!(trim_ascii(b"   "), b"");
        assert_eq!(trim_ascii(b""), b"");
    }
}
