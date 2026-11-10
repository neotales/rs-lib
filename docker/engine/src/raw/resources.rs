//! Container resource operations: `prune`, `update`, and `changes`.
//!
//! # The update body has no `Resources` wrapper, and that is measurable
//!
//! The Engine's published schema for `POST /containers/{id}/update` describes
//! the body as `{"Resources": {"CpuShares": …, "Memory": …}}`. Docker Engine
//! 29.8.0 does not read it that way. Measured on one container, reading
//! `HostConfig.CpuShares` back through inspect after each request:
//!
//! | Request body | Answer | `HostConfig.CpuShares` afterwards |
//! | --- | --- | --- |
//! | `{"Resources":{"CpuShares":222}}` | `200 {"Warnings":null}` | unchanged |
//! | `{"CpuShares":333}` | `200 {"Warnings":null}` | `333` |
//! | `{"Resources":{"CpuShares":444},"CpuShares":555}` | `200 {"Warnings":null}` | `555` |
//! | `{}` | `200 {"Warnings":null}` | unchanged |
//!
//! So the documented spelling is accepted with a success status and does
//! nothing, and the members that work are the top-level ones. That is not a
//! guess about the Go side: the daemon's update config embeds its resources
//! struct, and Go's JSON decoder promotes an embedded struct's fields to the
//! enclosing object, so the members the Engine reads are the promoted ones. This
//! is the failure mode the whole owned backend exists to avoid — a success
//! status for a request that changed nothing — so [`update`] sends the members
//! the daemon reads, and the measurement is recorded here because a future
//! daemon that starts honouring `Resources` would be worth noticing.
//!
//! # `Warnings` may be `null`
//!
//! Every `update` answer measured from Docker Engine 29.8.0 is
//! `{"Warnings":null}`, including the ones where nothing was updated. A `null`
//! warning list is an empty one, not a missing member, so
//! [`ContainerUpdateResult::warnings`](crate::containers::ContainerUpdateResult::warnings)
//! projects it to an empty vector.
//!
//! # `prune` reports what it deleted, and `null` means nothing
//!
//! `POST /containers/prune` answers `{"ContainersDeleted":[…],"SpaceReclaimed":N}`.
//! When no container matched, the same daemon answers
//! `{"ContainersDeleted":null,"SpaceReclaimed":0}`, measured both ways: a prune
//! with `filters={"until":["1s"]}` against three stopped containers reported
//! all three ids and `4096` bytes, and the identical call immediately afterwards
//! reported `null` and `0`.
//!
//! Filters are only sent when they are non-empty, for the reason the container
//! list records: an empty filter object is a filter that matches the daemon's
//! own "no filter" case and would only add noise to a recorded request. The
//! filter map is ordered, so the encoded JSON is byte-for-byte reproducible
//! between runs; the current facade converts it to a `HashMap` first, so its key
//! order varies.

use hyper::Method;
use serde::{Deserialize, Serialize};

use super::containers::{Query, container_path, encode_filters, with_query};
use super::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::containers::ContainerUpdateResult;
use crate::{
    ContainerPruneOptions, ContainerPruneResult, ContainerUpdateOptions, Error, FilesystemChange,
};

/// Prunes stopped containers.
///
/// The answer is one JSON document, so it is a bounded document read and not a
/// stream; the daemon closes the body when it has written it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `500` for filters the daemon cannot parse, which is a caller
/// mistake this layer does not pre-empt because the Engine's own filter grammar
/// is larger than any check worth duplicating here — or when the response is not
/// a prune document.
pub async fn prune(
    engine: &RawEngine,
    options: &ContainerPruneOptions,
) -> Result<ContainerPruneResult, Error> {
    let response = engine.send(prune_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<PruneDocument>(&document).map(ContainerPruneResult::from)
}

/// Builds the `POST /containers/prune` request.
fn prune_request(options: &ContainerPruneOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, "/containers/prune"),
        query.finish(),
    ))
}

/// Updates a container's mutable resource limits.
///
/// The members are sent at the top level of the body, which is where the Engine
/// reads them; the module documentation has the measurement that rules out the
/// `Resources` wrapper the published schema shows. A member the caller did not
/// set is omitted rather than sent as `null` or as a zero, because `0` is not
/// "unset" to the daemon: measured above, `{"CpuShares":0}` leaves the limit
/// alone rather than setting it to zero, and a `null` is not a number the Go
/// decoder will accept for an `int64`.
///
/// A `200` is not a statement that anything changed. The Engine answers `200`
/// with `{"Warnings":null}` for a body it did not act on, and the warnings are
/// the only place it says so, which is why the answer is decoded rather than
/// discarded: the current facade discards it, so a caller of that path cannot
/// tell a warning from a silence.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `409` carrying `Cannot update container <id>: …` for a limit the
/// daemon will not move, which is measured — or when the response is not an
/// update document.
pub async fn update(
    engine: &RawEngine,
    container: &str,
    options: &ContainerUpdateOptions,
) -> Result<ContainerUpdateResult, Error> {
    let response = engine.send(update_request(container, options)?).await?;
    let document = engine_result(response).await?;
    decode::<UpdateDocument>(&document).map(ContainerUpdateResult::from)
}

/// Builds the `POST /containers/{id}/update` request.
fn update_request(container: &str, options: &ContainerUpdateOptions) -> Result<RawRequest, Error> {
    let request = json_content_type(RawRequest::new(
        Method::POST,
        &container_path(container, "/update")?,
    ))
    .with_body(json_body(&UpdateBodyDocument {
        cpu_shares: options.cpu_shares,
        memory: options.memory,
    })?);
    Ok(request)
}

/// Lists what changed in a container's filesystem.
///
/// The answer is one JSON array, so it is a bounded document read. A container
/// that has changed nothing answers `[]`, which is not the same as no answer and
/// is decoded as an empty list rather than treated as a missing body.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such container: <name>` — or when the response
/// is not a change array.
pub async fn changes(engine: &RawEngine, container: &str) -> Result<Vec<FilesystemChange>, Error> {
    let response = engine.send(changes_request(container)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<ChangeDocument> = decode(&document)?;
    Ok(entries.into_iter().map(FilesystemChange::from).collect())
}

/// Builds the `GET /containers/{id}/changes` request.
fn changes_request(container: &str) -> Result<RawRequest, Error> {
    let request = RawRequest::new(Method::GET, &container_path(container, "/changes")?);
    Ok(with_query(request, None))
}

/// The `POST /containers/prune` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct PruneDocument {
    #[serde(default, rename = "ContainersDeleted")]
    containers_deleted: Option<Vec<String>>,
    #[serde(default, rename = "SpaceReclaimed")]
    space_reclaimed: Option<i64>,
}

impl From<PruneDocument> for ContainerPruneResult {
    /// Projects the daemon's answer onto the repository model.
    ///
    /// Both members are optional on the wire because the Engine sends `null` for
    /// each of them when there is nothing to report, and a `null` here means
    /// "nothing", not "unknown".
    fn from(document: PruneDocument) -> Self {
        Self {
            deleted: document.containers_deleted.unwrap_or_default(),
            space_reclaimed: document.space_reclaimed.unwrap_or_default(),
        }
    }
}

/// The `POST /containers/{id}/update` body, in the spelling the Engine reads.
///
/// The member names are the top-level promoted names rather than the nested
/// `Resources` block the published schema shows. See the module documentation
/// for the measurement.
#[derive(Debug, Serialize)]
struct UpdateBodyDocument {
    #[serde(rename = "CpuShares", skip_serializing_if = "Option::is_none")]
    cpu_shares: Option<i64>,
    #[serde(rename = "Memory", skip_serializing_if = "Option::is_none")]
    memory: Option<i64>,
}

/// The `POST /containers/{id}/update` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct UpdateDocument {
    // Measured from Docker Engine 29.8.0 as `null` on every answer, including
    // the ones that changed nothing, so a missing member and a null one are the
    // same answer here.
    #[serde(default, rename = "Warnings")]
    warnings: Option<Vec<String>>,
}

impl From<UpdateDocument> for ContainerUpdateResult {
    fn from(document: UpdateDocument) -> Self {
        Self {
            warnings: document.warnings.unwrap_or_default(),
        }
    }
}

/// One entry of a `GET /containers/{id}/changes` answer.
///
/// The Engine declares exactly these two members for a change — `Path` and
/// `Kind` — so nothing a daemon sends here can be dropped by naming them.
#[derive(Debug, Deserialize)]
struct ChangeDocument {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Kind")]
    kind: i64,
}

impl From<ChangeDocument> for FilesystemChange {
    /// Projects the wire kind onto the repository's numeric change kind.
    ///
    /// The Engine's kind is an `int`; the repository type is an `i32`. A kind
    /// outside that range is not a value the repository model can hold, and
    /// saturating keeps the change visible rather than reporting a decode
    /// failure for the whole array.
    fn from(document: ChangeDocument) -> Self {
        Self {
            path: document.path,
            kind: i32::try_from(document.kind).unwrap_or(i32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ChangeDocument, PruneDocument, UpdateBodyDocument, UpdateDocument, changes_request,
        prune_request, update_request,
    };
    use crate::raw::{RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, ContainerPruneOptions, ContainerUpdateOptions, ErrorKind, FilesystemChange,
    };

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

    fn filters() -> BTreeMap<String, Vec<String>> {
        let mut filters = BTreeMap::new();
        filters.insert("label".to_owned(), vec!["tier=web".to_owned()]);
        filters.insert("until".to_owned(), vec!["1h".to_owned()]);
        filters
    }

    #[test]
    fn prune_sends_no_query_when_there_are_no_filters() {
        let request = prune_request(&ContainerPruneOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/prune HTTP/1.1")
        );
    }

    #[test]
    fn prune_encodes_its_filters_in_a_stable_key_order() {
        // A recorded request whose JSON key order varies between runs of the
        // same command cannot be diffed against anything. The current facade
        // converts the ordered map to a `HashMap` first, so its recorded order
        // does vary.
        let request =
            prune_request(&ContainerPruneOptions { filters: filters() }).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/prune?filters=%7B%22label%22%3A%5B%22tier%3Dweb%22%5D%2C%22until%22%3A%5B%221h%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_prune_that_deleted_nothing_reports_an_empty_list_and_no_space() {
        // Recorded from Docker Engine 29.8.0: the second identical prune call
        // answers `{"ContainersDeleted":null,"SpaceReclaimed":0}`.
        let document: PruneDocument =
            super::decode(br#"{"ContainersDeleted":null,"SpaceReclaimed":0}"#)
                .expect("a prune document");
        let result = crate::ContainerPruneResult::from(document);
        assert!(result.deleted.is_empty());
        assert_eq!(result.space_reclaimed, 0);
    }

    #[test]
    fn a_prune_that_deleted_containers_reports_every_id() {
        // Recorded from Docker Engine 29.8.0:
        // `{"ContainersDeleted":["af62aaa1…","68ff235f…","5429f912…"],"SpaceReclaimed":4096}`.
        let document: PruneDocument = super::decode(
            br#"{"ContainersDeleted":["af62aaa1","68ff235f","5429f912"],"SpaceReclaimed":4096}"#,
        )
        .expect("a prune document");
        let result = crate::ContainerPruneResult::from(document);
        assert_eq!(result.deleted.len(), 3);
        assert_eq!(result.space_reclaimed, 4096);
    }

    #[test]
    fn a_prune_answer_with_no_members_at_all_decodes_to_nothing_deleted() {
        let document: PruneDocument = super::decode(b"{}").expect("a prune document");
        let result = crate::ContainerPruneResult::from(document);
        assert!(result.deleted.is_empty());
        assert_eq!(result.space_reclaimed, 0);
    }

    #[test]
    fn update_sends_the_members_the_engine_reads_and_not_a_resources_wrapper() {
        // The published schema nests these under `Resources`. Docker Engine
        // 29.8.0 does not read them there: `{"Resources":{"CpuShares":222}}` is
        // answered `200 {"Warnings":null}` and leaves `HostConfig.CpuShares`
        // unchanged, while the top-level member is applied. See the module
        // documentation for the full measurement.
        let body = request_body(
            &update_request(
                "web",
                &ContainerUpdateOptions {
                    cpu_shares: Some(512),
                    memory: Some(268_435_456),
                },
            )
            .expect("request"),
        );
        assert_eq!(body["CpuShares"], 512);
        assert_eq!(body["Memory"], 268_435_456);
        assert!(
            body.get("Resources").is_none(),
            "the wrapper is accepted and does nothing: {body}"
        );
    }

    #[test]
    fn an_update_with_nothing_set_sends_no_members_at_all() {
        // A `null` is not a number the daemon's Go decoder will accept for an
        // `int64`, and a zero is "leave it alone" rather than "set it to zero",
        // so an unset limit has to be an absent member.
        let body = request_body(
            &update_request("web", &ContainerUpdateOptions::default()).expect("request"),
        );
        assert_eq!(body.as_object().expect("an object").len(), 0, "{body}");
    }

    #[test]
    fn update_targets_the_container_and_declares_a_json_body() {
        let request = update_request(
            "web 1",
            &ContainerUpdateOptions {
                cpu_shares: Some(1),
                memory: None,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/web%201/update HTTP/1.1")
        );
        let content_type = request
            .headers
            .get("content-type")
            .expect("a content type")
            .to_str()
            .expect("ASCII");
        assert_eq!(content_type, "application/json");
    }

    #[test]
    fn an_update_answer_of_null_warnings_is_an_empty_warning_list() {
        // Every update answer measured from Docker Engine 29.8.0 is
        // `{"Warnings":null}`, including the ones that changed nothing.
        let document: UpdateDocument =
            super::decode(br#"{"Warnings":null}"#).expect("an update document");
        assert!(
            crate::containers::ContainerUpdateResult::from(document)
                .warnings
                .is_empty()
        );
    }

    #[test]
    fn an_update_answer_keeps_the_daemons_warnings() {
        // The current facade discards this body, so a caller of that path
        // cannot tell a warning from a silence.
        let document: UpdateDocument = super::decode(
            br#"{"Warnings":["Your kernel does not support memory limit capabilities"]}"#,
        )
        .expect("an update document");
        assert_eq!(
            crate::containers::ContainerUpdateResult::from(document).warnings,
            vec!["Your kernel does not support memory limit capabilities".to_owned()]
        );
    }

    #[test]
    fn changes_reads_a_bounded_array_and_keeps_the_daemons_kinds() {
        // Recorded from Docker Engine 29.8.0 for a container that made a
        // directory and a file: `[{"Path":"/probe","Kind":1},{"Path":"/probe/f","Kind":1}]`.
        let entries: Vec<ChangeDocument> = super::decode(
            br#"[{"Path":"/probe","Kind":1},{"Path":"/probe/f","Kind":1},{"Path":"/etc/hosts","Kind":2}]"#,
        )
        .expect("a change array");
        let changes: Vec<FilesystemChange> =
            entries.into_iter().map(FilesystemChange::from).collect();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].path, "/probe");
        assert_eq!(changes[0].kind, 1);
        assert_eq!(changes[2].kind, 2);
    }

    #[test]
    fn a_container_with_no_changes_answers_an_empty_array_not_a_missing_body() {
        let entries: Vec<ChangeDocument> = super::decode(b"[]").expect("a change array");
        assert!(entries.is_empty());
    }

    #[test]
    fn changes_sends_a_bare_get_with_no_query() {
        let request = changes_request("web/1").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/web%2F1/changes HTTP/1.1")
        );
        assert_eq!(request.query, None);
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        assert_eq!(
            changes_request("").expect_err("empty reference").kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            update_request("", &ContainerUpdateOptions::default())
                .expect_err("empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn the_body_documents_serialize_to_the_engines_member_names() {
        // The rename is spelled out rather than derived, because a casing rule
        // would produce `CpuShares` from `cpu_shares` by accident and a future
        // edit could break it silently.
        let body = super::json_body(&UpdateBodyDocument {
            cpu_shares: Some(2),
            memory: Some(3),
        })
        .expect("a body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body_bytes(&body)).expect("JSON"),
            serde_json::json!({"CpuShares": 2, "Memory": 3})
        );
    }

    /// Returns the bytes of a buffered body, so the assertion above can decode
    /// it without reaching into the transport's request type.
    fn body_bytes(body: &crate::raw::RawBody) -> bytes::Bytes {
        match body {
            RawBody::Bytes(bytes) => bytes.clone(),
            other => panic!("expected a buffered body, got {other:?}"),
        }
    }
}
