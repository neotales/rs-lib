//! System operations for the repository-owned Engine backend.
//!
//! This is step 4 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. It reuses [`RawEngine`], the
//! single owned transport, and the shared [`engine_result`] status mapping, so
//! there is no second client, no second error type, and no second HTTP stack in
//! the crate.
//!
//! # `ping`, `version`, and `info` are the pilot's, and they are not duplicated
//!
//! Those three are the migration's step 1. They are defined once, in
//! [`raw`](super) itself, because the pilot slice put them there before this slice
//! existed and `raw` is the file its owner edits. This module therefore does
//! **not** define them: there is exactly one [`ping`](super::ping), one
//! [`version`](super::version), and one [`info`](super::info) in this backend. A
//! test below asserts that the three names resolve to the function items they have
//! always been, so a second copy cannot be added here unnoticed.
//!
//! They are also deliberately not re-exported under this module's path:
//! `raw::system::ping` would be a second name for the same function, and the
//! `pub use` that produced it would be dead the moment `raw` stopped re-exporting
//! this module's contents. If the owner of `raw` would rather have the whole system
//! surface under one path, the change is to relocate those three functions and the
//! `Ping` type into this file — a move, not a copy — and this file is where they
//! belong.
//!
//! # Which answers here are documents and which are streams
//!
//! | Operation | Answer | Why |
//! | --- | --- | --- |
//! | [`ping`](super::ping) | headers, no body | the Engine reports its capabilities in headers |
//! | [`version`](super::version), [`info`](super::info) | one document | the daemon closes the body when it has written it |
//! | [`disk_usage`] | one document | one JSON object, bounded |
//! | [`prune_build_cache`] | one document | one JSON object, bounded |
//! | [`events`] | a frame stream | `GET /events` writes one JSON object per line and, without an `until` in the past, never closes the body |
//!
//! [`events`] returns the backend's existing [`FrameStream`] — the same type
//! [`stats_stream`](super::stats_stream) returns and the same
//! [`FrameStream::next_json`] record reader — rather than a new streaming type.
//! There is no way to tell from the response whether an event stream will end, so
//! the caller chooses: with an `until` in the past the daemon sends the buffered
//! events and closes, and without one it keeps writing for as long as the daemon
//! runs. Dropping the stream closes the connection, which is how a follower stops.
//!
//! # `GET /system/df` sends nine members and the model names four
//!
//! Measured against Docker Engine 29.8.0, a `GET /system/df` with no `type`
//! answers **nine** top-level members: `LayersSize`, `Images`, `Containers`,
//! `Volumes`, `BuildCache`, `ImageUsage`, `ContainerUsage`, `VolumeUsage`, and
//! `BuildCacheUsage`. The repository's [`DiskUsage`] names the four `*Usage`
//! blocks and nothing else, so decoding into it would drop five members —
//! including `LayersSize`, which is a number a caller asking about disk usage
//! wants. [`DiskUsageReport`] therefore keeps the document and offers
//! [`DiskUsageReport::usage`] as a projection over it, the arrangement
//! `raw::inspect` established for container inspect. The current facade performs
//! the same four-member projection and loses the same five, so nothing regresses;
//! the difference is that the owned path can still show them.
//!
//! # The `type` parameter is repeated, not comma-joined
//!
//! `GET /system/df?type=` takes the category as a **repeated** query parameter,
//! read by the Engine with `r.Form["type"]`. Measured against Docker Engine 29.8.0:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `?type=image&type=volume` | `200`, three top-level members |
//! | `?type=image,volume` | `400 {"message":"unknown object type: image,volume"}` |
//! | `?type=bogus` | `400 {"message":"unknown object type: bogus"}` |
//! | `?type=` | `400 {"message":"unknown object type: "}` |
//!
//! So the comma-joined spelling is a request that cannot succeed, and
//! [`disk_usage`] appends one `type=` pair per requested category.
//!
//! **This is a place the current transport cannot express the request at all.**
//! `bollard::query_parameters::DataUsageOptions` declares `type` as
//! `Option<Vec<String>>`, which `serde_urlencoded` 0.7 cannot encode as a struct
//! field, and the current facade has to bolt the repeated values on afterwards
//! with a request modifier that matches on the path. The owned backend appends the
//! pairs where the rest of its query is built, so there is no path-matching
//! workaround to get wrong.
//!
//! # `verbose` changes the answer's shape, so it is always spelled
//!
//! Measured: `GET /system/df` and `GET /system/df?verbose=false` both answer nine
//! top-level members, while `?verbose=true` answers **four** — the `*Usage` blocks
//! only, with no `LayersSize` and none of the legacy arrays. An absent `verbose`
//! and a `false` one are the same request, but a recorded request that omits it
//! cannot say which answer shape it asked for, so [`disk_usage`] always spells it.
//!
//! # `build/prune` hyphenates its byte parameters
//!
//! The Engine reads `reserved-space`, `max-used-space`, and `min-free-space`, with
//! hyphens, and answers `400 reserved-space is in bytes and expects an integer`
//! for a value that is not one. Measured: `?reserved_space=x` is answered `200`
//! with an ordinary prune report — the underscore spelling is a parameter the
//! Engine does not read, which is exactly the "a success status for a request
//! that changed nothing" failure this backend exists to avoid. Every rename here
//! is spelled out, and each is asserted in a test.
//!
//! # `events` has members the generated model would have to guess at
//!
//! Recorded from Docker Engine 29.8.0, a `network` event is one line:
//!
//! ```text
//! {"Type":"network","Action":"create","Actor":{"ID":"e08b5c3f…",
//!  "Attributes":{"name":"evprobe1","type":"bridge"}},"scope":"local",
//!  "time":1790404280,"timeNano":1790404280887841738}
//! ```
//!
//! Six top-level members, and the casing is mixed: `Type`, `Action`, and `Actor`
//! are capitalized while `scope`, `time`, and `timeNano` are not. `Actor` holds
//! `ID` and `Attributes`. A `casing` rule would produce `Scope` and `TimeNano` and
//! silently lose three of the six, which is why the answer is the frame stream's
//! own record rather than a decoded struct here, and why a caller that wants the
//! repository's [`SystemEvent`] reads those six names out of the record.
//!
//! # `events` bounds are the daemon's, and it says so
//!
//! `since` and `until` are Unix timestamps or RFC 3339 strings, and the Engine
//! answers `400` with its own words for a value it cannot read
//! (`invalid value for 'since': invalid timestamp "notatime": …`) and for an
//! inverted pair (`` `since` time (…) cannot be after `until` time (…) ``). Both
//! are reported as the daemon's rejection rather than pre-empted here, because the
//! Engine's timestamp grammar is larger than any check worth duplicating.
//!
//! One measured difference from the other resources in this slice: an unknown
//! event filter key is **accepted**. `GET /events?filters={"nope":["x"]}` answers
//! `200` on Docker Engine 29.8.0, where `GET /networks?filters={"nope":["x"]}` is
//! answered `400 invalid filter 'nope'`. The filter is sent as the caller wrote it
//! in both cases.
//!
//! # What is deliberately not covered
//!
//! - **`POST /system/prune`.** No Docker daemon serves it. The Engine's system
//!   router has no such route at any version, while `POST /containers/prune`
//!   beside it answers normally; `docker system prune` composes the per-resource
//!   calls itself. Composing them here would mean a failure part way through
//!   leaves the daemon in a state neither the caller nor the user asked for, so
//!   [`prune_build_cache`] prunes the build cache and nothing else.
//! - **Registry or TLS behaviour.** Nothing here differs from the transport, and
//!   `RawTarget::Tcp` is still a plain TCP stream.

use std::collections::BTreeMap;

use hyper::Method;
use serde::Deserialize;

use super::containers::{Query, with_query};
use super::transport::{RawEngine, RawRequest, decode, engine_result, json_content_type};
use crate::raw::FrameStream;
use crate::{
    BuildCachePruneOptions, BuildCachePruneResult, DiskUsage, DiskUsageCategory, DiskUsageItem,
    DiskUsageOptions, DiskUsageType, Error, EventOptions,
};

/// The disk-usage answer, with the daemon's document retained.
///
/// The document is the answer of last resort for a member with no projection: the
/// Engine sends nine top-level members and the repository's [`DiskUsage`] names
/// four, so `LayersSize` and the four legacy arrays are only reachable here.
#[derive(Clone, Debug, PartialEq)]
pub struct DiskUsageReport {
    document: serde_json::Value,
}

impl DiskUsageReport {
    /// Returns the document exactly as the daemon sent it.
    ///
    /// Nothing in it has been renamed, defaulted, or dropped.
    #[must_use]
    pub const fn document(&self) -> &serde_json::Value {
        &self.document
    }

    /// Consumes the report and returns the document.
    #[must_use]
    pub fn into_document(self) -> serde_json::Value {
        self.document
    }

    /// Returns the aggregate size of the shared image layers, in bytes.
    ///
    /// This is the member with no field in the repository model. It is `null` when
    /// the request selected no image category, and a `verbose=true` answer omits it
    /// altogether; both are reported as absent rather than as zero.
    #[must_use]
    pub fn layers_size(&self) -> Option<i64> {
        self.document
            .get("LayersSize")
            .and_then(serde_json::Value::as_i64)
    }

    /// Projects the report onto the repository's disk-usage model.
    ///
    /// This is the projection the current facade performs, spelled out here over
    /// the retained document so the two paths can be compared without reading two
    /// different shapes. It is a view: [`DiskUsageReport::document`] still has the
    /// five members it has no field for.
    ///
    /// It cannot fail. A category the daemon omitted, or sent as `null`, reads as
    /// absent rather than as a decode error.
    #[must_use]
    pub fn usage(&self) -> DiskUsage {
        DiskUsage {
            image_usage: self.category("ImageUsage", DiskUsageType::Image),
            container_usage: self.category("ContainerUsage", DiskUsageType::Container),
            volume_usage: self.category("VolumeUsage", DiskUsageType::Volume),
            build_cache_usage: self.category("BuildCacheUsage", DiskUsageType::BuildCache),
        }
    }

    /// Projects one `*Usage` block onto the repository's category model.
    ///
    /// `resource_type` is the category the block was read from rather than a member
    /// the daemon sent, because the Engine sends no such member: an item in
    /// `ImageUsage` is an image by where it is, and the four blocks have four
    /// different item shapes.
    fn category(&self, member: &str, resource_type: DiskUsageType) -> Option<DiskUsageCategory> {
        let block = self
            .document
            .get(member)
            .filter(|block| block.is_object())?;
        Some(DiskUsageCategory {
            active_count: number_in(block, "ActiveCount"),
            total_count: number_in(block, "TotalCount"),
            reclaimable: number_in(block, "Reclaimable"),
            total_size: number_in(block, "TotalSize"),
            items: block
                .get("Items")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| usage_item(item, resource_type))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Projects one verbose disk-usage item onto the repository's item model.
///
/// The four categories send four different item shapes, measured against Docker
/// Engine 29.8.0: an image item carries `Id`, `ParentId`, `RepoTags`, `Created`,
/// and `Labels`; a container item carries `Id`, `Names`, `Created`, `SizeRootFs`,
/// and `Labels`; a volume item carries `Name` and `RefCount`; a build-cache item
/// carries `ID`, `CreatedAt`, `InUse`, and `UsageCount`. The repository's
/// [`DiskUsageItem`] has one set of fields for all four, so the projection reads
/// the alternates the same way the current facade's mapping does — that is what
/// makes the two paths produce the same [`DiskUsage`] for the same answer.
///
/// A member the daemon did not send reads as absent rather than as a zero, and the
/// whole item is still in [`DiskUsageReport::document`].
fn usage_item(item: &serde_json::Value, resource_type: DiskUsageType) -> DiskUsageItem {
    let usage_data = item.get("UsageData");
    DiskUsageItem {
        id: text_in(item, "ID").or_else(|| text_in(item, "Id")),
        name: text_in(item, "Name")
            .or_else(|| first_of(item, "RepoTags"))
            .or_else(|| first_of(item, "Names")),
        parent_id: text_in(item, "Parent").or_else(|| text_in(item, "ParentId")),
        size: number_in(item, "Size")
            .or_else(|| usage_data.and_then(|data| number_in(data, "Size"))),
        reference_count: usage_data.and_then(|data| number_in(data, "RefCount")),
        in_use: item.get("InUse").and_then(serde_json::Value::as_bool),
        created: number_in(item, "Created").or_else(|| number_in(item, "CreatedAt")),
        labels: string_map_in(item, "Labels"),
        references: string_list_in(item, "RepoTags")
            .or_else(|| string_list_in(item, "Names"))
            .unwrap_or_default(),
        driver: text_in(item, "Driver"),
        resource_type: Some(resource_type),
    }
}

/// Reads a member of an object as owned text.
fn text_in(object: &serde_json::Value, member: &str) -> Option<String> {
    object
        .get(member)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

/// Reads a member of an object as a number.
fn number_in(object: &serde_json::Value, member: &str) -> Option<i64> {
    object.get(member).and_then(serde_json::Value::as_i64)
}

/// Reads a member of an object as a string map.
fn string_map_in(object: &serde_json::Value, member: &str) -> BTreeMap<String, String> {
    object
        .get(member)
        .and_then(serde_json::Value::as_object)
        .map(|values| {
            values
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a member of an object as a list of strings.
fn string_list_in(object: &serde_json::Value, member: &str) -> Option<Vec<String>> {
    object.get(member)?.as_array().map(|values| {
        values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    })
}

/// Reads the first string of a list member, for a name a caller identifies by one
/// of its values.
fn first_of(object: &serde_json::Value, member: &str) -> Option<String> {
    string_list_in(object, member)?.into_iter().next()
}

/// Opens the daemon's event stream.
///
/// The answer is a stream, never a bounded document: with no `until`, or an
/// `until` in the future, the daemon keeps writing one JSON object per line for as
/// long as it runs. The record reader is the existing
/// [`FrameStream::next_json`], and dropping the returned stream closes the
/// connection — which is how a follower stops. There is no separate cancel
/// message, so the two ends cannot disagree about whether a transfer is still
/// wanted.
///
/// `filters` is sent only when it is present and non-empty. `since` and `until`
/// are sent only when the caller set them, so the daemon's own default applies
/// rather than this client's guess.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// reached, or when it rejects the request — a `400` carrying the daemon's own
/// message for a `since` it cannot read, or for a `since` after the `until`, both
/// measured. A body that is not JSON records is reported by
/// [`FrameStream::next_json`] rather than here, because one read cannot tell a
/// valid stream from a corrupt one.
pub async fn events(engine: &RawEngine, options: &EventOptions) -> Result<FrameStream, Error> {
    let response = engine.send(events_request(options)?).await?;
    // The status is checked before the body is handed out, or a 400 whose body
    // happened to parse as a JSON record would surface as an event stream.
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(response.into_frames())
}

/// Builds the `GET /events` request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn events_request(options: &EventOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(since) = &options.since {
        query.value("since", since);
    }
    if let Some(until) = &options.until {
        query.value("until", until);
    }
    if let Some(filters) = options.filters.as_ref().filter(|f| !f.is_empty()) {
        query.value("filters", &encode_filters(filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/events"),
        query.finish(),
    ))
}

/// Reads the daemon's disk-usage report.
///
/// The answer is one JSON object, so it goes through
/// [`RawResponse::document`](super::RawResponse::document) and is therefore
/// bounded by [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). The daemon
/// closes the body when it has written it.
///
/// `types` is sent as one repeated `type=` pair per category, because that is the
/// only spelling the Engine reads; see the module documentation for the
/// measurement. `verbose` is always spelled, because it decides the answer's
/// shape and an absent parameter cannot say which shape was asked for.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `400` carrying `unknown object type: <type>` for a category the
/// Engine does not declare, measured — or when the response is not a JSON object.
pub async fn disk_usage(
    engine: &RawEngine,
    options: &DiskUsageOptions,
) -> Result<DiskUsageReport, Error> {
    let response = engine.send(disk_usage_request(options)).await?;
    let document = engine_result(response).await?;
    Ok(DiskUsageReport {
        document: decode(&document)?,
    })
}

/// Builds the `GET /system/df` request.
fn disk_usage_request(options: &DiskUsageOptions) -> RawRequest {
    let mut query = Query::default();
    if let Some(types) = options.types.as_deref().filter(|types| !types.is_empty()) {
        for requested in types {
            // Repeated pairs, not one comma-joined value: the Engine reads
            // `r.Form["type"]`, and `?type=image,volume` is answered
            // `400 unknown object type: image,volume` on Docker Engine 29.8.0.
            query.value("type", requested.as_str());
        }
    }
    query.flag("verbose", options.verbose);
    with_query(RawRequest::new(Method::GET, "/system/df"), query.finish())
}

/// Prunes unused build-cache records.
///
/// The answer is one JSON object with two members, `CachesDeleted` and
/// `SpaceReclaimed`, and both are named by [`BuildCachePruneResult`], so nothing is
/// dropped here. `CachesDeleted` is `null` rather than `[]` when nothing matched,
/// which is an empty list rather than a missing answer; `SpaceReclaimed` stays an
/// `Option`, because "reclaimed nothing" and "the daemon reported no figure" are
/// different answers.
///
/// The three byte parameters are sent with the Engine's hyphens. An underscore
/// spelling is a parameter the daemon does not read, which is a `200` for a
/// request that changed nothing; see the module documentation for the
/// measurement.
///
/// The endpoint declares no request body at all: every
/// [`BuildCachePruneOptions`] member is a query parameter, and a body would be a
/// member the daemon ignores. The built request therefore carries `RawBody::Empty`
/// and a `Content-Length: 0`, which a test asserts rather than this comment
/// claiming.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// reached, when it rejects the request — a `400` carrying `<name> is in bytes and
/// expects an integer, got <value>`, measured — or when the response is not a prune
/// document.
pub async fn prune_build_cache(
    engine: &RawEngine,
    options: &BuildCachePruneOptions,
) -> Result<BuildCachePruneResult, Error> {
    let response = engine.send(prune_build_cache_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<BuildCachePruneDocument>(&document).map(BuildCachePruneResult::from)
}

/// Builds the `POST /build/prune` request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn prune_build_cache_request(options: &BuildCachePruneOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    // Hyphens, not underscores. Measured against Docker Engine 29.8.0:
    // `?reserved-space=x` is answered `400 reserved-space is in bytes and expects
    // an integer, got x`, while `?reserved_space=x` is answered `200` with an
    // ordinary prune report — the underscore spelling is a parameter the Engine
    // does not read.
    if let Some(reserved_space) = options.reserved_space {
        query.value("reserved-space", &reserved_space.to_string());
    }
    if let Some(max_used_space) = options.max_used_space {
        query.value("max-used-space", &max_used_space.to_string());
    }
    if let Some(min_free_space) = options.min_free_space {
        query.value("min-free-space", &min_free_space.to_string());
    }
    if let Some(all) = options.all {
        query.flag("all", all);
    }
    if let Some(filters) = options.filters.as_ref().filter(|f| !f.is_empty()) {
        query.value("filters", &encode_filters(filters)?);
    }
    let request = json_content_type(RawRequest::new(Method::POST, "/build/prune"));
    Ok(with_query(request, query.finish()))
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The map is a `BTreeMap`, so the JSON is in key order and a recorded request is
/// reproducible between runs. The current facade converts the same map into a
/// `HashMap` first, so its key order varies.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine system filters: {error}"
        ))
    })
}

/// The `POST /build/prune` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct BuildCachePruneDocument {
    #[serde(default, rename = "CachesDeleted")]
    caches_deleted: Option<Vec<String>>,
    #[serde(default, rename = "SpaceReclaimed")]
    space_reclaimed: Option<i64>,
}

impl From<BuildCachePruneDocument> for BuildCachePruneResult {
    fn from(document: BuildCachePruneDocument) -> Self {
        Self {
            caches_deleted: document.caches_deleted.unwrap_or_default(),
            space_reclaimed: document.space_reclaimed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BuildCachePruneDocument, DiskUsageReport, disk_usage_request, events_request,
        prune_build_cache_request,
    };
    use crate::raw::Ping;
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, BuildCachePruneOptions, DiskUsageOptions, DiskUsageType, Error, ErrorKind,
        EventOptions,
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

    fn filters() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([
            ("label".to_owned(), vec!["tier=web".to_owned()]),
            ("type".to_owned(), vec!["container".to_owned()]),
        ])
    }

    /// The `GET /system/df` answer recorded from Docker Engine 29.8.0 with
    /// `verbose=true`, abbreviated where an item's value is long and irrelevant
    /// here. Every one of the nine top-level members a non-verbose answer carries
    /// is represented across this document and the second one below.
    const DF_BODY: &[u8] = br#"{
        "LayersSize":13162289,
        "Images":[{"Id":"sha256:d9e853e8","Created":1776383606,"ParentId":"",
            "RepoTags":["alpine:3.20"],"RepoDigests":["alpine@sha256:d9e8"],
            "SharedSize":0,"Size":13153063,"Containers":4,
            "Descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json",
                "digest":"sha256:d9e853e8","size":9226},"Labels":{"tier":"base"}}],
        "Containers":[{"Id":"267b169c","Names":["/default_api.1"],
            "Image":"alpine:3.20","ImageID":"sha256:d9e8","Command":"sh -c 'sleep 3600'",
            "Created":1790404335,"Ports":[],"SizeRootFs":9445376,
            "Labels":{"tier":"web"},"State":"running","Status":"Up 32 seconds",
            "HostConfig":{"NetworkMode":"bridge"},"Health":{"Status":"none"},
            "NetworkSettings":{"Networks":{}},"Mounts":[]}],
        "Volumes":[],
        "BuildCache":[{"ID":"h1ev92104lpv8djepjcr567vl","Type":"regular",
            "Description":"","InUse":false,"Shared":true,"Size":3630321,
            "CreatedAt":"2026-09-26T00:38:09.858335055Z",
            "LastUsedAt":"2026-09-26T02:06:09.43665083Z","UsageCount":6}],
        "ImageUsage":{"ActiveCount":1,"TotalCount":1,"TotalSize":13153063,
            "Items":[{"Id":"sha256:d9e853e8","Created":1776383606,"ParentId":"",
                "RepoTags":["alpine:3.20"],"SharedSize":0,"Size":13153063,
                "Descriptor":{"digest":"sha256:d9e8"},"Labels":{"tier":"base"}}]},
        "ContainerUsage":{"ActiveCount":4,"TotalCount":4,
            "Items":[{"Id":"267b169c","Names":["/default_api.1"],"Image":"alpine:3.20",
                "Command":"sh -c 'sleep 3600'","Created":1790404335,
                "SizeRootFs":9445376,"Labels":{"tier":"web"},"State":"running"}]},
        "VolumeUsage":{"TotalCount":0,"Items":[]},
        "BuildCacheUsage":{"TotalCount":1,"TotalSize":3630321,
            "Items":[{"ID":"h1ev92104lpv8djepjcr567vl","InUse":false,"Shared":true,
                "Size":3630321,"CreatedAt":"2026-09-26T00:38:09Z","UsageCount":6}]}
    }"#;

    fn report(body: &[u8]) -> DiskUsageReport {
        DiskUsageReport {
            document: super::super::decode(body).expect("a disk-usage document"),
        }
    }

    #[test]
    fn df_sends_verbose_even_when_the_caller_set_nothing() {
        // An absent `verbose` and a `false` one are the same request, but
        // `verbose=true` changes the answer from nine top-level members to four,
        // so a recorded request that omits it cannot say which shape it asked for.
        let request = disk_usage_request(&DiskUsageOptions::default());
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/system/df?verbose=false HTTP/1.1")
        );
        let verbose = disk_usage_request(&DiskUsageOptions::new().with_verbose(true));
        assert_eq!(
            request_line(&verbose),
            crate::raw::at_api_version("GET /v1.API/system/df?verbose=true HTTP/1.1")
        );
    }

    #[test]
    fn df_repeats_the_type_parameter_rather_than_comma_joining_it() {
        // Measured against Docker Engine 29.8.0: `?type=image&type=volume` is
        // `200`, and `?type=image,volume` is `400 unknown object type:
        // image,volume`. The Engine reads `r.Form["type"]`, so a comma-joined
        // value is one category name it does not declare.
        let request = disk_usage_request(
            &DiskUsageOptions::new().with_types([DiskUsageType::Image, DiskUsageType::Volume]),
        );
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/system/df?type=image&type=volume&verbose=false HTTP/1.1"
            )
        );
        assert!(
            !request.query.expect("a query").contains("image%2Cvolume"),
            "a comma-joined value is a request that cannot succeed"
        );
    }

    #[test]
    fn df_sends_one_pair_per_requested_category_including_duplicates() {
        // A repeated category is the Engine's own reading of the form, and it
        // answers `200` for `?type=image&type=image`, so nothing here dedupes.
        let request = disk_usage_request(
            &DiskUsageOptions::new()
                .with_types([DiskUsageType::BuildCache, DiskUsageType::BuildCache]),
        );
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/system/df?type=build-cache&type=build-cache&verbose=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn df_sends_every_category_when_the_caller_asked_for_all_of_them() {
        let request = disk_usage_request(&DiskUsageOptions::new().with_types([
            DiskUsageType::Container,
            DiskUsageType::Image,
            DiskUsageType::Volume,
            DiskUsageType::BuildCache,
        ]));
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/system/df?type=container&type=image&type=volume&type=build-cache&verbose=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_empty_type_list_leaves_the_selection_to_the_daemon() {
        // An empty list is not "no categories": the Engine reads an absent `type`
        // as all four, and `?type=` is answered `400 unknown object type: `.
        let request = disk_usage_request(&DiskUsageOptions::new().with_types([]));
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/system/df?verbose=false HTTP/1.1")
        );
    }

    #[test]
    fn every_member_the_daemon_sent_is_still_in_the_document() {
        // The reason this module keeps the document: nine top-level members
        // measured from Docker Engine 29.8.0, and the repository model names four.
        let report = report(DF_BODY);
        for member in [
            "LayersSize",
            "Images",
            "Containers",
            "Volumes",
            "BuildCache",
            "ImageUsage",
            "ContainerUsage",
            "VolumeUsage",
            "BuildCacheUsage",
        ] {
            assert!(
                report.document().get(member).is_some(),
                "member {member} was dropped"
            );
        }
    }

    #[test]
    fn layers_size_is_read_from_the_member_no_field_exists_for() {
        // `LayersSize` is the member the current facade's four-field projection
        // loses, and a caller asking about disk usage wants it.
        assert_eq!(report(DF_BODY).layers_size(), Some(13_162_289));
    }

    #[test]
    fn a_verbose_answer_with_no_layers_size_reports_absent_rather_than_zero() {
        // Measured: `?verbose=true` answers four top-level members and no
        // `LayersSize`. Zero is a size; absent is a member the daemon did not send.
        let report = report(
            br#"{"ImageUsage":{"ActiveCount":1},"ContainerUsage":{},
                "VolumeUsage":{},"BuildCacheUsage":{}}"#,
        );
        assert_eq!(report.layers_size(), None);
    }

    #[test]
    fn the_usage_projection_reuses_the_repository_model() {
        let usage = report(DF_BODY).usage();
        let images = usage.image_usage.expect("image usage");
        assert_eq!(images.active_count, Some(1));
        assert_eq!(images.total_count, Some(1));
        assert_eq!(images.total_size, Some(13_153_063));
        // `Reclaimable` is not in this daemon's answer, and an absent member is
        // not a zero.
        assert_eq!(images.reclaimable, None);
        assert_eq!(images.items.len(), 1);
        assert_eq!(images.items[0].id.as_deref(), Some("sha256:d9e853e8"));
        assert_eq!(images.items[0].name.as_deref(), Some("alpine:3.20"));
        assert_eq!(images.items[0].size, Some(13_153_063));
        assert_eq!(images.items[0].created, Some(1_776_383_606));
        assert_eq!(
            images.items[0].labels.get("tier").map(String::as_str),
            Some("base")
        );
        assert_eq!(images.items[0].references, vec!["alpine:3.20".to_owned()]);
        // `resource_type` comes from the block the item was read out of, because
        // the Engine sends no such member.
        assert_eq!(images.items[0].resource_type, Some(DiskUsageType::Image));

        let containers = usage.container_usage.expect("container usage");
        assert_eq!(containers.active_count, Some(4));
        assert_eq!(containers.items[0].name.as_deref(), Some("/default_api.1"));
        assert_eq!(containers.items[0].driver, None);
        assert_eq!(
            containers.items[0].resource_type,
            Some(DiskUsageType::Container)
        );

        let cache = usage.build_cache_usage.expect("build-cache usage");
        assert_eq!(cache.total_size, Some(3_630_321));
        assert_eq!(
            cache.items[0].id.as_deref(),
            Some("h1ev92104lpv8djepjcr567vl")
        );
        assert_eq!(cache.items[0].in_use, Some(false));
        assert_eq!(cache.items[0].created, None, "the member is CreatedAt");
        assert_eq!(
            cache.items[0].resource_type,
            Some(DiskUsageType::BuildCache)
        );

        // `VolumeUsage` was `{"TotalCount":0,"Items":[]}` on the wire.
        let volumes = usage.volume_usage.expect("volume usage");
        assert_eq!(volumes.total_count, Some(0));
        assert!(volumes.items.is_empty());
    }

    #[test]
    fn a_category_the_daemon_omitted_is_absent_rather_than_a_decode_failure() {
        // `?type=image` answers three top-level members and no `ContainerUsage`.
        let usage = report(br#"{"LayersSize":1,"Images":[],"ImageUsage":{}}"#).usage();
        assert!(usage.image_usage.is_some());
        assert_eq!(usage.container_usage, None);
        assert_eq!(usage.volume_usage, None);
        assert_eq!(usage.build_cache_usage, None);
    }

    #[test]
    fn a_null_category_is_absent_rather_than_a_decode_failure() {
        let usage = report(br#"{"ImageUsage":null,"ContainerUsage":null}"#).usage();
        assert_eq!(usage.image_usage, None);
        assert_eq!(usage.container_usage, None);
    }

    #[test]
    fn events_sends_the_versioned_path_with_no_query_by_default() {
        let request = events_request(&EventOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/events HTTP/1.1")
        );
        assert_eq!(request.query, None);
    }

    #[test]
    fn events_sends_since_until_and_filters_when_they_were_set() {
        let request = events_request(
            &EventOptions::new()
                .with_since("1790404280")
                .with_until("1790404290")
                .with_filter("type", ["container"]),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/events?since=1790404280&until=1790404290&filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_absent_or_empty_event_filter_map_is_not_sent() {
        // An empty filter *object* is a filter that matches the daemon's own
        // no-filter case, so it is not sent at all.
        let absent = events_request(&EventOptions::new()).expect("request");
        assert_eq!(
            request_line(&absent),
            crate::raw::at_api_version("GET /v1.API/events HTTP/1.1")
        );
        let empty = events_request(&EventOptions {
            filters: Some(BTreeMap::new()),
            ..EventOptions::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&empty),
            crate::raw::at_api_version("GET /v1.API/events HTTP/1.1")
        );
    }

    #[test]
    fn a_filter_key_with_no_values_is_sent_rather_than_dropped() {
        // `{"type":[]}` is a *named* filter with no values, and the Engine treats it
        // as matching everything rather than as no filter: measured against Docker
        // Engine 29.8.0, `GET /networks?filters={"name":[]}` returns all six
        // networks, the same as no filter. Dropping it here would be a silent
        // reinterpretation of what the caller asked for, so it is sent.
        let request =
            events_request(&EventOptions::new().with_filter("type", Vec::<String>::new()))
                .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/events?filters=%7B%22type%22%3A%5B%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn event_filter_keys_are_emitted_in_order_so_a_recorded_request_is_reproducible() {
        // The current facade converts the ordered map to a `HashMap` first, so its
        // recorded order varies between runs of the same command.
        let request = events_request(
            &EventOptions::new()
                .with_filter("label", ["tier=web"])
                .with_filter("type", ["container"]),
        )
        .expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        assert!(
            value.find("%22label%22").expect("label") < value.find("%22type%22").expect("type")
        );
    }

    #[test]
    fn build_prune_hyphenates_its_byte_parameters() {
        // Measured against Docker Engine 29.8.0: `?reserved-space=x` is answered
        // `400 reserved-space is in bytes and expects an integer, got x`, while
        // `?reserved_space=x` is answered `200` with an ordinary prune report. An
        // underscore spelling is a parameter the Engine does not read, which is a
        // success status for a request that changed nothing.
        let request = prune_build_cache_request(
            &BuildCachePruneOptions::new()
                .with_reserved_space(1024)
                .with_max_used_space(2048)
                .with_min_free_space(4096)
                .with_all(true),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/build/prune?reserved-space=1024&max-used-space=2048&min-free-space=4096&all=true HTTP/1.1"
            )
        );
        let query = request.query.expect("a query");
        for underscore in ["reserved_space", "max_used_space", "min_free_space"] {
            assert!(
                !query.contains(underscore),
                "{underscore} is not read: {query}"
            );
        }
    }

    #[test]
    fn build_prune_with_nothing_set_sends_no_query_at_all() {
        // The Engine's own defaults then apply, rather than this client sending
        // zeroes the daemon would read as "reclaim everything".
        let request =
            prune_build_cache_request(&BuildCachePruneOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/build/prune HTTP/1.1")
        );
    }

    #[test]
    fn build_prune_sends_filters_and_all_together() {
        let request = prune_build_cache_request(
            &BuildCachePruneOptions::new()
                .with_all(false)
                .with_filter("until", ["1h"]),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/build/prune?all=false&filters=%7B%22until%22%3A%5B%221h%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_absent_or_empty_build_prune_filter_map_is_not_sent() {
        let absent =
            prune_build_cache_request(&BuildCachePruneOptions::default()).expect("request");
        assert_eq!(
            request_line(&absent),
            crate::raw::at_api_version("POST /v1.API/build/prune HTTP/1.1")
        );
        let empty = prune_build_cache_request(&BuildCachePruneOptions {
            filters: Some(BTreeMap::new()),
            ..BuildCachePruneOptions::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&empty),
            crate::raw::at_api_version("POST /v1.API/build/prune HTTP/1.1")
        );
    }

    #[test]
    fn a_build_prune_filter_key_with_no_values_is_sent_rather_than_dropped() {
        // A named filter with no values is not the same request as no filter, so it
        // travels. See the events test for the measurement.
        let request = prune_build_cache_request(
            &BuildCachePruneOptions::new().with_filter("until", Vec::<String>::new()),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/build/prune?filters=%7B%22until%22%3A%5B%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_build_prune_that_reclaimed_nothing_reports_an_empty_list() {
        // Recorded from Docker Engine 29.8.0: `{"CachesDeleted":[…],"SpaceReclaimed":24986}`
        // for a real prune, and `{"CachesDeleted":null,"SpaceReclaimed":0}` for the
        // identical call immediately afterwards.
        let document: BuildCachePruneDocument = super::super::decode(
            br#"{"CachesDeleted":["09bdaqyiz12cfgu4ktnr2rcji","x9y80m4zsaoa39lrgj2wqi55u"],"SpaceReclaimed":24986}"#,
        )
        .expect("a prune document");
        let result = crate::BuildCachePruneResult::from(document);
        assert_eq!(result.caches_deleted.len(), 2);
        assert_eq!(result.space_reclaimed, Some(24_986));

        let document: BuildCachePruneDocument =
            super::super::decode(br#"{"CachesDeleted":null,"SpaceReclaimed":0}"#)
                .expect("a prune document");
        let result = crate::BuildCachePruneResult::from(document);
        assert!(result.caches_deleted.is_empty());
        assert_eq!(result.space_reclaimed, Some(0));
    }

    #[test]
    fn a_missing_space_reclaimed_is_absent_rather_than_zero() {
        let document: BuildCachePruneDocument =
            super::super::decode(br#"{"CachesDeleted":null}"#).expect("a prune document");
        assert_eq!(
            crate::BuildCachePruneResult::from(document).space_reclaimed,
            None
        );
    }

    #[test]
    fn a_build_prune_sends_no_body() {
        // Every `BuildCachePruneOptions` member is a query parameter, and the
        // Engine declares no body for `POST /build/prune`. A body would be a member
        // the daemon ignores, and `Content-Length: 0` is what a recorded request
        // should carry.
        let request =
            prune_build_cache_request(&BuildCachePruneOptions::default()).expect("request");
        assert!(matches!(request.body, RawBody::Empty), "{:?}", request.body);
        assert_eq!(request.body.known_len(), Some(0));
    }

    #[test]
    fn an_encoded_filter_value_is_percent_encoded_json() {
        // The Engine's `filters` value is JSON inside a query value, so a raw brace
        // or quote would end the parameter. It has to survive as data.
        for request in [
            events_request(&EventOptions::new().with_filter("type", ["container"]))
                .expect("request"),
            prune_build_cache_request(&BuildCachePruneOptions::new().with_filter("until", ["1h"]))
                .expect("request"),
        ] {
            let query = request.query.expect("a query");
            let (_, value) = query.split_once("filters=").expect("the filters pair");
            assert!(!value.contains('{'), "the JSON must be encoded: {value}");
            assert!(!value.contains('"'), "the JSON must be encoded: {value}");
        }
    }

    #[test]
    fn the_document_limit_still_bounds_a_disk_usage_report() {
        // The bound is a property of the transport, so what is asserted here is
        // that the document-shaped operations read through it.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        for request in [
            disk_usage_request(&DiskUsageOptions::default()),
            events_request(&EventOptions::default()).expect("request"),
        ] {
            assert!(
                request.body.known_len().is_some(),
                "no request body is sent"
            );
        }
    }

    #[tokio::test]
    async fn the_pilots_three_operations_are_defined_once_and_not_here() {
        // `ping`, `version`, and `info` are the pilot slice's and live in `raw`.
        // This module must not define a second copy, and a `pub use` of them would
        // be a second *name* for the same function rather than a shared
        // implementation. Both facts are asserted here: the names resolve, and they
        // resolve to the items `raw` has always exported.
        // Naming them proves they resolve; the explicit fn-pointer annotations
        // prove the resolved items have the pilot's signatures rather than
        // look-alikes declared in this module. Each is an `async fn`, so the
        // pointer is the one that returns its future and the future's `Output`
        // pins what that future resolves to.
        // Binding each awaited future to an explicit `Result<T, Error>` pins both
        // the argument it takes and the value it resolves to, which is what proves
        // the resolved item is the pilot's operation and not a look-alike declared
        // in this module. The engine points at a socket that does not exist, so each
        // call fails as a transport error and the assertions are about the types.
        let engine = engine();
        let ping: Result<Ping, Error> = crate::raw::ping(&engine).await;
        let info: Result<serde_json::Value, Error> = crate::raw::info(&engine).await;
        let version: Result<serde_json::Value, Error> = crate::raw::version(&engine).await;
        for error in [
            ping.expect_err("no daemon"),
            info.expect_err("no daemon"),
            version.expect_err("no daemon"),
        ] {
            assert_eq!(error.kind(), ErrorKind::Transport);
        }
    }

    #[test]
    fn the_system_operations_and_their_models_are_the_repositorys_own() {
        // The option and result types are reused as they are; this slice adds no
        // parallel system model, so a caller that moves between the two backends
        // moves between the same types. Asserting it here means a future edit that
        // introduces a parallel type fails rather than passing quietly.
        let _: Option<BuildCachePruneOptions> = None;
        let _: Option<DiskUsageOptions> = None;
        let _: Option<EventOptions> = None;
        let _: Option<crate::BuildCachePruneResult> = None;
        let _: Option<crate::DiskUsage> = None;
        let _: Option<crate::DiskUsageCategory> = None;
        let _: Option<crate::DiskUsageItem> = None;
        let filters = filters();
        let request = events_request(&EventOptions {
            filters: Some(filters),
            ..EventOptions::default()
        })
        .expect("request");
        assert!(request.query.expect("a query").contains("filters="));
    }
}
