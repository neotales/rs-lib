//! `GET /containers/{id}/stats`: the one container endpoint with two answers.
//!
//! # `stats` is either a document or a stream, and the caller has to say which
//!
//! Measured against Docker Engine 29.8.0, the same endpoint answers two
//! completely different shapes depending on one query parameter:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `?stream=false` | `200`, `1835` bytes, one JSON object with 13 members, and the body ends |
//! | `?stream=true` | `200`, `Transfer-Encoding: chunked`, one JSON object per line, about one every second, and the body does not end |
//!
//! There is no way to tell from the response which one arrived, and a client
//! that guessed would either hang forever on a document request or truncate a
//! stream. So the two shapes are two functions, [`stats`] and [`stats_stream`],
//! and each refuses the other's option rather than reading a body that will not
//! end. Nothing is buffered in the streaming case: the answer is the existing
//! [`FrameStream`], read a record at a time by
//! [`FrameStream::next_json`](super::FrameStream::next_json), and dropping it
//! closes the connection — which is how a caller stops following a container
//! that will otherwise stream until the container stops.
//!
//! # No member is dropped
//!
//! The one-shot answer is returned as the JSON value the daemon sent. That is
//! deliberate for the same reason as inspect: the stats document is a large,
//! version-dependent structure — `cpu_stats`, `precpu_stats`, `memory_stats`,
//! `blkio_stats`, `networks`, `pids_stats`, `storage_stats`, and a member per
//! network interface under `networks` — and a model with declared fields would
//! drop the members added after it was written. A caller that wants one number
//! reads it out of the value; a caller that wants to forward the whole sample
//! gets the whole sample.
//!
//! # `one-shot` is not sent
//!
//! The Engine still accepts the `one-shot` parameter the current facade sends
//! alongside `stream`, and ignores it: it was deprecated in favour of
//! `stream=false` and the daemon's own answer no longer distinguishes the two.
//! Sending both makes a recorded request say two things where one decides the
//! answer, so only `stream` is sent.

use hyper::Method;

use super::containers::{Query, container_path, with_query};
use super::transport::{RawEngine, RawRequest, engine_result};
use crate::Error;
use crate::raw::FrameStream;

/// Options for `GET /containers/{id}/stats`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatsOptions {
    /// Whether the daemon keeps the response open and emits a sample per
    /// interval.
    ///
    /// This one flag decides the shape of the answer, so the constructors
    /// [`StatsOptions::one_shot`] and [`StatsOptions::following`] are the way to
    /// choose: a `Default` is `false`, which is the shape that ends.
    pub stream: bool,
}

impl StatsOptions {
    /// Asks for a single sample, which the daemon sends as one JSON object and
    /// then closes the body.
    #[must_use]
    pub const fn one_shot() -> Self {
        Self { stream: false }
    }

    /// Asks for a sample per interval, which the daemon sends as an endless
    /// sequence of newline-delimited JSON objects.
    #[must_use]
    pub const fn following() -> Self {
        Self { stream: true }
    }
}

/// Reads one sample of a container's resource usage.
///
/// Refuses [`StatsOptions::stream`] rather than reading a body that will not
/// end. The daemon's streaming answer has no length and does not close, so
/// reading it as a document would block for as long as the container runs —
/// which, for a long-running container, is forever.
///
/// The answer is returned as the JSON value the daemon sent, so a member this
/// client does not know about is still in it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such container: <name>`, measured — when the
/// options ask for a stream, or when the response is not a JSON document.
pub async fn stats(
    engine: &RawEngine,
    container: &str,
    options: StatsOptions,
) -> Result<serde_json::Value, Error> {
    if options.stream {
        return Err(Error::invalid_input(
            "a streaming stats answer does not end; use stats_stream for it",
        ));
    }
    let response = engine.send(stats_request(container, options)?).await?;
    let document = engine_result(response).await?;
    super::transport::decode(&document)
}

/// Opens a container's resource-usage stream.
///
/// The answer is the backend's existing [`FrameStream`], not a new streaming
/// type: the transport, the connection lifetime, and the cancellation behaviour
/// are the same as for every other streamed response here. The Engine writes one
/// JSON value per line on this endpoint — verified against Docker Engine 29.8.0,
/// where a four-second capture held 4096 bytes with two newlines and every
/// complete line parsed as one object — so a record is read with
/// [`FrameStream::next_json`].
///
/// Refuses [`StatsOptions::stream`] being false: a non-streaming answer is one
/// document and ends, and reading it through a record reader would be a way of
/// asking for a shape the caller did not request.
///
/// Dropping the returned stream closes the connection, which is how a follower
/// stops. There is no separate cancellation message to get wrong.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the options ask for a single sample instead of a stream.
pub async fn stats_stream(
    engine: &RawEngine,
    container: &str,
    options: StatsOptions,
) -> Result<FrameStream, Error> {
    if !options.stream {
        return Err(Error::invalid_input(
            "a single stats sample is one document; use stats for it",
        ));
    }
    let response = engine.send(stats_request(container, options)?).await?;
    // The status is checked before the body is handed out, or a 404 whose body
    // happened to parse as a JSON record would surface as a stats stream.
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(response.into_frames())
}

/// Builds the `GET /containers/{id}/stats` request.
///
/// Only `stream` is spelled. The Engine also accepts the deprecated `one-shot`
/// flag, which the current facade sends alongside it; the daemon ignores it in
/// favour of `stream`, so sending it would make a recorded request say two
/// things where one decides the shape of the answer.
fn stats_request(container: &str, options: StatsOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("stream", options.stream);
    Ok(with_query(
        RawRequest::new(Method::GET, &container_path(container, "/stats")?),
        query.finish(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{StatsOptions, stats_request};
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
    fn the_stream_flag_is_always_spelled_and_one_shot_is_never_sent() {
        let one = stats_request("web", StatsOptions::one_shot()).expect("request");
        assert_eq!(
            request_line(&one),
            crate::raw::at_api_version("GET /v1.API/containers/web/stats?stream=false HTTP/1.1")
        );
        let following = stats_request("web", StatsOptions::following()).expect("request");
        assert_eq!(
            request_line(&following),
            crate::raw::at_api_version("GET /v1.API/containers/web/stats?stream=true HTTP/1.1")
        );
        // `one-shot` is accepted and ignored by the daemon; sending it would
        // make a recorded request say two things where one decides the answer.
        assert!(!following.query.expect("a query").contains("one-shot"));
    }

    #[test]
    fn a_default_is_the_shape_that_ends() {
        // `Default` for a bool is false, and false is the one-shot shape, so the
        // default is the request that cannot hang.
        let options = StatsOptions::default();
        assert!(!options.stream);
        assert_eq!(options, StatsOptions::one_shot());
        assert_ne!(options, StatsOptions::following());
    }

    #[tokio::test]
    async fn the_two_functions_refuse_each_others_shape() {
        // There is no way to tell from the response which shape arrived, so the
        // choice is made by the caller and enforced rather than guessed at.
        let engine = engine();
        let Err(error) = super::stats(&engine, "web", StatsOptions::following()).await else {
            panic!("a streaming answer is not a document");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let Err(error) = super::stats_stream(&engine, "web", StatsOptions::one_shot()).await else {
            panic!("a single sample is not a stream");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_reference_cannot_reshape_the_stats_path() {
        let request = stats_request("a/b", StatsOptions::one_shot()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/a%2Fb/stats?stream=false HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        assert_eq!(
            stats_request("", StatsOptions::one_shot())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }
}
