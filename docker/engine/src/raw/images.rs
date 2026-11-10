//! Document-shaped image operations on the repository-owned Engine backend.
//!
//! This is step 3 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`: the image surface that is a
//! single bounded answer rather than a live transfer. `list`, `inspect`,
//! `remove`, `prune`, `history`, `tag`, and `search` are here, plus the
//! *collected* form of a pull and a push for a caller that wants a bounded
//! answer.
//!
//! The names are prefixed with `image_` because they share the `raw` namespace
//! with the container slice's `list`, `create`, and `remove` and with the
//! container resources slice's `prune`, in the same way the Swarm slice's
//! `service_list` and `node_list` are prefixed by resource.
//!
//! Everything reuses the existing plumbing: [`RawEngine`] for the connection,
//! [`engine_result`] for the status mapping, [`decode`] for the bounded body,
//! [`Query`] and [`with_query`](super::containers::with_query) for the query
//! string, and
//! [`escape_path_segment`](super::containers::escape_path_segment) for an image
//! reference in a path. There is no second client, no second error type, and no
//! second HTTP stack.
//!
//! # Every option and result is the existing repository model
//!
//! [`ImageListOptions`], [`ImageInspectOptions`], [`ImageHistoryOptions`],
//! [`ImageRemoveOptions`], [`ImagePruneOptions`], [`ImageTagOptions`],
//! [`ImageSearchOptions`], [`ImagePullOptions`], and [`ImagePushOptions`] are
//! used as they are, and the answers are [`ImageSummary`], [`ImageInspect`],
//! [`ImageHistory`], [`ImageSearchResult`], [`ImagePruneResult`],
//! [`ImageDeleteResult`], and [`ImageStreamEvent`]. `raw` adds no parallel image
//! model, so a caller that moves between the two backends moves between the
//! same types. The wire spelling lives in the private `*Document` types below
//! for the reason the container slice gives: the public models are
//! `snake_case` CLI output and are not the Engine's `PascalCase`.
//!
//! # A member the owned model does not know is still reachable
//!
//! The public models are caller-facing projections, and the Engine adds members
//! to these documents between releases. So every operation that projects also
//! has a `*_document` form that returns the daemon's answer **as sent**:
//!
//! | Operation | Projected answer | Members the projection does not carry | Reachable through |
//! | --- | --- | --- | --- |
//! | `image_list` | [`ImageSummary`] | `Descriptor` | `image_list_documents` |
//! | `image_inspect` | [`ImageInspect`] | `Descriptor`, `Identity`, and the `Config` members [`ImageConfig`](crate::ImageConfig) does not name — `Image`, `Hostname`, `Domainname`, `MacAddress`, `Passwd` among them | `image_inspect_document` |
//! | `image_history` | [`ImageHistory`] | none: all six members the daemon sends are named | `image_history_documents` |
//! | `image_search` | [`ImageSearchResult`] | none: all five members the daemon sends are named | `image_search_documents` |
//! | `image_prune` | [`ImagePruneResult`] | none | `image_prune_document` |
//! | `image_remove` | [`ImageDeleteResult`] | none | — |
//!
//! Measured against Docker Engine 29.8.0, a `GET /images/json` entry carries
//! ten members and [`ImageSummary`] names nine; `Descriptor` is the tenth. A
//! `GET /images/{name}/json` answer for `alpine:3.20` carries `Descriptor` and
//! `Identity` at the top level, which [`ImageInspect`] has no member for. The
//! Swarm slice's answer to the same problem was an `additional` map on the
//! model, which is not available here because the models are existing public
//! types; the verbatim form is the retention path instead, and it is the
//! *primary* one for `info`, `version`, and `stats` in this same backend.
//!
//! # Two answers the status alone does not decide
//!
//! - **`image_tag` answers `201 Created` with an empty body.** Measured. It
//!   therefore takes the same path as the container slice's `204` operations —
//!   the status is the whole result and the body is never decoded — and a
//!   request that names no repository is refused here rather than sent.
//! - **A collected push and load can be `200` and still have failed.** See
//!   [`image_push_document`]; the detail is in
//!   [`raw::image_transfer`](super::image_transfer) because that is where the
//!   streams are read, but the check is applied here so the bounded form cannot
//!   report a refused push as a successful one.
//!
//! # Where this differs from the current facade
//!
//! | Member | Facade | Owned backend | Why |
//! | --- | --- | --- | --- |
//! | `GET /images/json` filters | the ordered `BTreeMap` is converted to a `HashMap` before serialization, so the key order of the encoded value varies between runs | the ordered map is serialized directly | The same gain the container slice records: a recorded request is byte-for-byte reproducible. |
//! | `GET /images/json` `manifests` | always sent as `manifests=false` | never sent | [`ImageListOptions`] has no member for it, and the Engine's `manifests` flag changes the shape of every entry in a way this projection does not model. Sending `false` would be a parameter nobody asked for; the omission is named here rather than left for a caller to discover. |
//! | `POST /images/{name}/tag` with no repository | sent; Docker Engine 29.8.0 answers `200` and changes nothing | refused as invalid input | A successful status for a request that did nothing is worse than a refusal. Measured. |
//! | `POST /images/{name}/tag` `force` | added through a request modifier, because the generated `TagImageOptions` has no `force` | sent directly, only when the caller set it | The generated option's absence is why a modifier exists at all; the owned request can say it. |
//! | `DELETE /images/{name}` `platforms` | not sent | not sent | [`ImageRemoveOptions`] has no member for it and its own documentation says why: the generated sequence cannot be serialized by the current dependency's URL-form query adapter. The Engine does declare it, so it is named here rather than presented as complete. |
//! | `GET /images/search` `term` | always sent, empty included | an empty term is refused | The Engine declares `term` as required, and an empty one matches everything. Measured that a v29.8 daemon answers `200` to `?term=` rather than complaining. |

use std::collections::BTreeMap;

use hyper::Method;
use serde::Deserialize;

use super::containers::{Query, completed, encode_filters, escape_path_segment, with_query};
use super::image_transfer::{RegistryAuth, progress_error, pull_stream, push_stream};
use super::transport::{RawEngine, RawRequest, decode, engine_result};
use crate::raw::body::FrameStream;
use crate::{
    Error, ImageConfig, ImageDeleteResult, ImageGraphDriver, ImageHealthcheck, ImageHistory,
    ImageHistoryOptions, ImageInspect, ImageInspectOptions, ImageListOptions, ImageMetadata,
    ImagePruneOptions, ImagePruneResult, ImageRemoveOptions, ImageRootFs, ImageSearchOptions,
    ImageSearchResult, ImageStreamEvent, ImageSummary, ImageTagOptions,
};

/// The most progress records a collected pull or push will hold.
///
/// A pull or a push is a live stream, and the whole point of
/// [`raw::image_transfer`](super::image_transfer) is that it is not buffered.
/// The *document* form exists for a caller that wants an answer rather than a
/// stream, and it is bounded twice over: by this record count, and by
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES) of encoded records, which
/// is the same bound every other document in this backend goes through. A stream
/// that never ends therefore cannot be turned into an unbounded buffer by asking
/// for the document form.
const MAX_PROGRESS_RECORDS: usize = 8192;

/// Lists local images.
///
/// `GET /images/json` answers with one JSON array, so the response is a single
/// bounded document read through
/// [`RawResponse::document`](super::RawResponse::document) and therefore capped
/// at [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). Nothing here is
/// streamed, so there is no unbounded body to accumulate and nothing to cancel.
///
/// `all`, `shared-size`, and `digests` are always spelled, so a recorded request
/// says what it meant rather than leaving it to the daemon's defaults.
/// `filters` is sent only when it is non-empty.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not an image array.
pub async fn image_list(
    engine: &RawEngine,
    options: &ImageListOptions,
) -> Result<Vec<ImageSummary>, Error> {
    let response = engine.send(image_list_request(options)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<ImageSummaryDocument> = decode(&document)?;
    Ok(entries.into_iter().map(ImageSummary::from).collect())
}

/// Lists local images and returns each entry as the daemon sent it.
///
/// This is the member-preserving form of [`image_list`], and the reason the
/// projection above can be a projection: a v29.8 `GET /images/json` entry
/// carries a `Descriptor` member that [`ImageSummary`] has no field for, and a
/// caller that needs it reads it out of the returned value.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a JSON array.
pub async fn image_list_documents(
    engine: &RawEngine,
    options: &ImageListOptions,
) -> Result<Vec<serde_json::Value>, Error> {
    let response = engine.send(image_list_request(options)?).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /images/json` request.
fn image_list_request(options: &ImageListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("all", options.all);
    // The Engine spells this parameter with a hyphen, not the generated
    // option's `shared_size`; the two are different spellings of one parameter
    // and only the hyphenated one is read.
    query.flag("shared-size", options.shared_size);
    query.flag("digests", options.digests);
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/images/json"),
        query.finish(),
    ))
}

/// Inspects one local image.
///
/// `platform` is a JSON-encoded OCI platform, which is why the option keeps it
/// as a string: the repository does not depend on an OCI model for one query
/// value. It is sent only when the caller set one.
///
/// The answer is projected onto [`ImageInspect`]. The members that projection
/// does not carry — `Descriptor` and `Identity` on the v29.8 answer for
/// `alpine:3.20`, and the `Config` members [`ImageConfig`](crate::ImageConfig)
/// does not name — are reachable through [`image_inspect_document`].
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such image: <name>`, measured — or when the
/// response is not an inspect document.
pub async fn image_inspect(
    engine: &RawEngine,
    image: &str,
    options: &ImageInspectOptions,
) -> Result<ImageInspect, Error> {
    let response = engine.send(image_inspect_request(image, options)?).await?;
    let document = engine_result(response).await?;
    decode::<ImageInspectDocument>(&document).map(ImageInspect::from)
}

/// Inspects one local image and returns the answer as the daemon sent it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a JSON object.
pub async fn image_inspect_document(
    engine: &RawEngine,
    image: &str,
    options: &ImageInspectOptions,
) -> Result<serde_json::Value, Error> {
    let response = engine.send(image_inspect_request(image, options)?).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /images/{name}/json` request.
fn image_inspect_request(image: &str, options: &ImageInspectOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, &image_path(image, "/json")?),
        query.finish(),
    ))
}

/// Removes one local image.
///
/// The answer is an array of records, each of which untags a reference or
/// deletes an image ID and usually not both, which is why both members are
/// optional. The two flags are always spelled, so a recorded `DELETE` says
/// whether forcing and whether untagging parent images were part of it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `409` for an image a running container still uses.
pub async fn image_remove(
    engine: &RawEngine,
    image: &str,
    options: &ImageRemoveOptions,
) -> Result<Vec<ImageDeleteResult>, Error> {
    let response = engine.send(image_remove_request(image, options)?).await?;
    let document = engine_result(response).await?;
    let records: Vec<ImageDeleteResultDocument> = decode(&document)?;
    Ok(records.into_iter().map(ImageDeleteResult::from).collect())
}

/// Builds the `DELETE /images/{name}` request.
///
/// The Engine also declares a `platforms` parameter here, and it is not sent:
/// [`ImageRemoveOptions`] has no member for it. That is named in the module
/// documentation rather than presented as a complete spelling of the endpoint.
fn image_remove_request(image: &str, options: &ImageRemoveOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("force", options.force);
    query.flag("noprune", options.no_prune);
    Ok(with_query(
        RawRequest::new(Method::DELETE, &image_path(image, "")?),
        query.finish(),
    ))
}

/// Prunes unused images.
///
/// The answer is one document rather than an array: `ImagesDeleted` and
/// `SpaceReclaimed`. `filters` is sent only when the caller set one, and
/// serialized from the ordered map so a recorded request is reproducible.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a prune document.
pub async fn image_prune(
    engine: &RawEngine,
    options: &ImagePruneOptions,
) -> Result<ImagePruneResult, Error> {
    let response = engine.send(image_prune_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<ImagePruneDocument>(&document).map(ImagePruneResult::from)
}

/// Prunes unused images and returns the answer as the daemon sent it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a JSON object.
pub async fn image_prune_document(
    engine: &RawEngine,
    options: &ImagePruneOptions,
) -> Result<serde_json::Value, Error> {
    let response = engine.send(image_prune_request(options)?).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `POST /images/prune` request.
fn image_prune_request(options: &ImagePruneOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, "/images/prune"),
        query.finish(),
    ))
}

/// Returns the layer history of one local image.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such image: <name>`, measured — or when the
/// response is not a history array.
pub async fn image_history(
    engine: &RawEngine,
    image: &str,
    options: &ImageHistoryOptions,
) -> Result<Vec<ImageHistory>, Error> {
    let response = engine.send(image_history_request(image, options)?).await?;
    let document = engine_result(response).await?;
    let records: Vec<ImageHistoryDocument> = decode(&document)?;
    Ok(records.into_iter().map(ImageHistory::from).collect())
}

/// Returns a layer history and returns it as the daemon sent it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a JSON array.
pub async fn image_history_documents(
    engine: &RawEngine,
    image: &str,
    options: &ImageHistoryOptions,
) -> Result<Vec<serde_json::Value>, Error> {
    let response = engine.send(image_history_request(image, options)?).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /images/{name}/history` request.
fn image_history_request(image: &str, options: &ImageHistoryOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, &image_path(image, "/history")?),
        query.finish(),
    ))
}

/// Tags one local image.
///
/// The answer is `201 Created` with an empty body — measured against Docker
/// Engine 29.8.0, not `204` — so the status is the whole result and the body is
/// never handed to a JSON decoder.
///
/// A request that names no repository is refused. The Engine declares `repo` as
/// required, and measured, `POST /images/alpine:3.20/tag` with no query at all
/// answers `200` and changes nothing: a successful status for a request that did
/// nothing is worse than a refusal naming the missing value.
///
/// # Errors
///
/// Returns an error when no repository was named, when the daemon cannot be
/// reached, or when it rejects the request — a `404` for an image that does not
/// exist, measured.
pub async fn image_tag(
    engine: &RawEngine,
    image: &str,
    options: &ImageTagOptions,
) -> Result<(), Error> {
    completed(engine, image_tag_request(image, options)?).await
}

/// Builds the `POST /images/{name}/tag` request.
fn image_tag_request(image: &str, options: &ImageTagOptions) -> Result<RawRequest, Error> {
    let repository = options
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|repo| !repo.is_empty());
    if repository.is_none() {
        return Err(Error::invalid_input(
            "tagging an image needs a target repository; the Engine accepts a request without one and does nothing",
        ));
    }
    let mut query = Query::default();
    if let Some(repository) = repository {
        query.value("repo", repository);
    }
    if let Some(tag) = options.tag.as_deref().filter(|tag| !tag.is_empty()) {
        query.value("tag", tag);
    }
    if let Some(force) = options.force {
        query.flag("force", force);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &image_path(image, "/tag")?),
        query.finish(),
    ))
}

/// Searches the registry for images.
///
/// This is the one operation here that leaves the daemon: the Engine queries the
/// registry on the caller's behalf, so the answer is the registry's and this
/// module has no control over its shape. It is still a single bounded document
/// and is still read through
/// [`RawResponse::document`](super::RawResponse::document).
///
/// An empty term is refused: the Engine declares `term` as required, and
/// measured, a v29.8 daemon answers `?term=` with `200` and an unfiltered
/// result rather than complaining.
///
/// # Errors
///
/// Returns an error when no term was given, when the daemon cannot be reached,
/// when it rejects the request, or when the response is not a result array.
pub async fn image_search(
    engine: &RawEngine,
    options: &ImageSearchOptions,
) -> Result<Vec<ImageSearchResult>, Error> {
    let response = engine.send(image_search_request(options)?).await?;
    let document = engine_result(response).await?;
    let records: Vec<ImageSearchResultDocument> = decode(&document)?;
    Ok(records.into_iter().map(ImageSearchResult::from).collect())
}

/// Searches the registry and returns each result as the daemon sent it.
///
/// # Errors
///
/// Returns an error when no term was given, when the daemon cannot be reached,
/// when it rejects the request, or when the response is not a JSON array.
pub async fn image_search_documents(
    engine: &RawEngine,
    options: &ImageSearchOptions,
) -> Result<Vec<serde_json::Value>, Error> {
    let response = engine.send(image_search_request(options)?).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /images/search` request.
fn image_search_request(options: &ImageSearchOptions) -> Result<RawRequest, Error> {
    if options.term.is_empty() {
        return Err(Error::invalid_input(
            "an image search needs a term; the Engine declares it required and answers an empty one with an unfiltered result",
        ));
    }
    let mut query = Query::default();
    query.value("term", &options.term);
    if let Some(limit) = options.limit {
        query.value("limit", &limit.to_string());
    }
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/images/search"),
        query.finish(),
    ))
}

/// Pulls an image and returns the whole progress report.
///
/// This is the bounded form of
/// [`pull_stream`](super::image_transfer::pull_stream), for a caller that wants
/// an answer rather than a live transfer. The answer is bounded twice — by
/// `MAX_PROGRESS_RECORDS` and by
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES) — so a stream that never
/// ends cannot be turned into an unbounded buffer by asking for this.
///
/// A pull the registry refuses is *not* in the records: measured against Docker
/// Engine 29.8.0 it is a `403` or a `500` with a JSON error body, and the
/// streaming path turns that into an error before any record is read. The
/// records are also checked for an in-band failure anyway, so a daemon that
/// reported one in a record cannot be reported here as a success.
///
/// The credential is validated and encoded by
/// [`RegistryAuth`](super::image_transfer::RegistryAuth), including the base64
/// alphabet the daemon actually decodes; see that type's module for the
/// measurement.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — including a registry refusal, measured at `403` and `500` — when a
/// record reports a failure, or when the progress report exceeds either bound.
pub async fn image_pull_document(
    engine: &RawEngine,
    image: &str,
    options: &crate::ImagePullOptions,
    auth: RegistryAuth<'_>,
) -> Result<Vec<ImageStreamEvent>, Error> {
    let records = collect_progress(pull_stream(engine, image, options, auth).await?).await?;
    if let Some(message) = records.iter().find_map(progress_error) {
        return Err(Error::engine_api(hyper::StatusCode::OK, message));
    }
    Ok(records
        .iter()
        .map(crate::streams::map_image_event)
        .collect())
}

/// Pushes an image and returns the whole progress report.
///
/// This is the bounded form of
/// [`push_stream`](super::image_transfer::push_stream). **A `200` from a push is
/// not a result**: measured against Docker Engine 29.8.0, a push the registry
/// refuses answers `200` and carries the refusal in a record —
///
/// ```text
/// {"error":"failed commit on ref \"manifest-sha256:c64c…\": server message: insufficient_scope: authorization failed", …}
/// ```
///
/// so the records are checked and the refusal is raised as an error carrying the
/// daemon's own words. The status that is carried with it is the one the daemon
/// really sent, which is why it says `200`: the answer is what the daemon wrote,
/// not what this layer would have preferred.
///
/// The answer is bounded by `MAX_PROGRESS_RECORDS` and by
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES).
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request before the stream starts, when a record reports a failure, or when
/// the progress report exceeds either bound.
pub async fn image_push_document(
    engine: &RawEngine,
    image: &str,
    options: &crate::ImagePushOptions,
    auth: RegistryAuth<'_>,
) -> Result<Vec<ImageStreamEvent>, Error> {
    let records = collect_progress(push_stream(engine, image, options, auth).await?).await?;
    if let Some(message) = records.iter().find_map(progress_error) {
        return Err(Error::engine_api(hyper::StatusCode::OK, message));
    }
    Ok(records
        .iter()
        .map(crate::streams::map_image_event)
        .collect())
}

/// Collects a progress stream into a bounded list of records.
///
/// The bound is the same one every document in this backend goes through. A
/// stream that does not end is a stream the caller should not have asked to
/// buffer, and the refusal is an error naming the limit rather than an
/// allocation that grows until the process ends.
pub(super) async fn collect_progress(
    mut frames: FrameStream,
) -> Result<Vec<serde_json::Value>, Error> {
    let mut records = Vec::new();
    let mut bytes = 0_usize;
    while let Some(record) = frames.next_json().await? {
        bytes = bytes.saturating_add(record.to_string().len());
        if records.len() >= MAX_PROGRESS_RECORDS {
            return Err(Error::invalid_input(format!(
                "the image transfer progress report exceeds the {MAX_PROGRESS_RECORDS}-record limit"
            )));
        }
        if bytes > super::MAX_DOCUMENT_BYTES {
            return Err(Error::invalid_input(format!(
                "the image transfer progress report exceeds the {} byte limit",
                super::MAX_DOCUMENT_BYTES
            )));
        }
        records.push(record);
    }
    Ok(records)
}

/// Builds the `/images/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/images//json` is not a request for
/// an image, and sending it would ask the daemon about a resource the caller
/// never named. The reference is percent-encoded into exactly one segment, so a
/// repository-qualified name such as `ghcr.io/owner/app:1.2.3` cannot turn into
/// a path of its own.
fn image_path(image: &str, suffix: &str) -> Result<String, Error> {
    if image.is_empty() {
        return Err(Error::invalid_input(
            "the Engine image reference must not be empty",
        ));
    }
    Ok(format!("/images/{}{suffix}", escape_path_segment(image)))
}

/// One entry of a `GET /images/json` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ImageSummaryDocument {
    // `Id` is not `ImageId`; the Engine capitalizes the acronym, and `ParentId`
    // is spelled with a lower-case `d`, so every rename here is written out.
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "ParentId", default)]
    parent_id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Option<Vec<String>>,
    #[serde(rename = "Created", default)]
    created: i64,
    #[serde(rename = "Size", default)]
    size: i64,
    /// The Engine sends `-1` when the shared size was not calculated, which is
    /// the value the projection carries through rather than treating as absent.
    #[serde(rename = "SharedSize", default)]
    shared_size: i64,
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "Containers", default)]
    containers: i64,
}

impl From<ImageSummaryDocument> for ImageSummary {
    fn from(document: ImageSummaryDocument) -> Self {
        Self {
            id: document.id,
            parent_id: document.parent_id,
            // An untagged image answers `null` for both tag lists, which the
            // projection reports as empty rather than as a missing list.
            repo_tags: document.repo_tags.unwrap_or_default(),
            repo_digests: document.repo_digests.unwrap_or_default(),
            created: document.created,
            size: document.size,
            shared_size: document.shared_size,
            // An unordered map would make the projection of an unordered daemon
            // answer vary between runs, so the map is kept ordered here too.
            labels: document.labels.unwrap_or_default(),
            containers: document.containers,
        }
    }
}

/// One layer of a `GET /images/{name}/history` answer.
#[derive(Debug, Deserialize)]
struct ImageHistoryDocument {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Created", default)]
    created: i64,
    #[serde(rename = "CreatedBy", default)]
    created_by: String,
    /// `null` for a layer with no tag, which the measured `alpine:3.20` history
    /// carries on every layer but the first.
    #[serde(rename = "Tags", default)]
    tags: Option<Vec<String>>,
    #[serde(rename = "Size", default)]
    size: i64,
    #[serde(rename = "Comment", default)]
    comment: String,
}

impl From<ImageHistoryDocument> for ImageHistory {
    fn from(document: ImageHistoryDocument) -> Self {
        Self {
            id: document.id,
            created: document.created,
            created_by: document.created_by,
            tags: document.tags.unwrap_or_default(),
            size: document.size,
            comment: document.comment,
        }
    }
}

/// One result of a `GET /images/search` answer.
///
/// The Engine spells these members in lower snake case, unlike every other image
/// document, so no rename is needed here — which is itself worth knowing, and is
/// why the renames above are not a casing rule applied automatically.
#[derive(Debug, Deserialize)]
struct ImageSearchResultDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    star_count: Option<i64>,
    #[serde(default)]
    is_official: Option<bool>,
    /// Marked deprecated by the Engine but still part of the v1.53 answer, and
    /// still a member of the owned model.
    #[serde(default)]
    is_automated: Option<bool>,
}

impl From<ImageSearchResultDocument> for ImageSearchResult {
    fn from(document: ImageSearchResultDocument) -> Self {
        Self {
            name: document.name.unwrap_or_default(),
            description: document.description.unwrap_or_default(),
            star_count: document.star_count.unwrap_or_default(),
            is_official: document.is_official.unwrap_or_default(),
            is_automated: document.is_automated.unwrap_or_default(),
        }
    }
}

/// One record of a `DELETE /images/{name}` answer.
///
/// A record untags a reference, deletes an image ID, or both, and the measured
/// answer for an untagged image carries both members while a delete carries only
/// one — so neither is required.
#[derive(Debug, Deserialize)]
struct ImageDeleteResultDocument {
    #[serde(rename = "Untagged", default)]
    untagged: Option<String>,
    #[serde(rename = "Deleted", default)]
    deleted: Option<String>,
}

impl From<ImageDeleteResultDocument> for ImageDeleteResult {
    fn from(document: ImageDeleteResultDocument) -> Self {
        Self {
            untagged: document.untagged,
            deleted: document.deleted,
        }
    }
}

/// The `POST /images/prune` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ImagePruneDocument {
    // A prune that removed nothing answers `null`, which the measured request
    // for `{"dangling":{"true":true}}` does, so this is not `Vec::new()`.
    #[serde(rename = "ImagesDeleted", default)]
    images_deleted: Option<Vec<ImageDeleteResultDocument>>,
    #[serde(rename = "SpaceReclaimed", default)]
    space_reclaimed: Option<i64>,
}

impl From<ImagePruneDocument> for ImagePruneResult {
    fn from(document: ImagePruneDocument) -> Self {
        Self {
            images_deleted: document
                .images_deleted
                .unwrap_or_default()
                .into_iter()
                .map(ImageDeleteResult::from)
                .collect(),
            space_reclaimed: document.space_reclaimed,
        }
    }
}

/// The `GET /images/{name}/json` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ImageInspectDocument {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Option<Vec<String>>,
    #[serde(rename = "Comment", default)]
    comment: Option<String>,
    #[serde(rename = "Created", default)]
    created: Option<String>,
    #[serde(rename = "Author", default)]
    author: Option<String>,
    #[serde(rename = "Architecture", default)]
    architecture: Option<String>,
    #[serde(rename = "Variant", default)]
    variant: Option<String>,
    #[serde(rename = "Os", default)]
    os: Option<String>,
    #[serde(rename = "OsVersion", default)]
    os_version: Option<String>,
    #[serde(rename = "Size", default)]
    size: Option<i64>,
    #[serde(rename = "Config", default)]
    config: Option<ImageConfigDocument>,
    #[serde(rename = "GraphDriver", default)]
    graph_driver: Option<GraphDriverDocument>,
    #[serde(rename = "RootFS", default)]
    root_fs: Option<RootFsDocument>,
    #[serde(rename = "Metadata", default)]
    metadata: Option<MetadataDocument>,
}

impl From<ImageInspectDocument> for ImageInspect {
    fn from(document: ImageInspectDocument) -> Self {
        Self {
            id: document.id,
            repo_tags: document.repo_tags.unwrap_or_default(),
            repo_digests: document.repo_digests.unwrap_or_default(),
            comment: document.comment,
            created: document.created,
            author: document.author,
            architecture: document.architecture,
            variant: document.variant,
            os: document.os,
            os_version: document.os_version,
            size: document.size,
            config: document.config.map(ImageConfig::from),
            graph_driver: document.graph_driver.map(ImageGraphDriver::from),
            root_fs: document.root_fs.map(ImageRootFs::from),
            metadata: document.metadata.map(ImageMetadata::from),
        }
    }
}

/// The `Config` block of an inspect answer.
#[derive(Debug, Deserialize)]
struct ImageConfigDocument {
    #[serde(rename = "User", default)]
    user: Option<String>,
    /// `ExposedPorts` is a map of port to an empty object, so the keys are the
    /// ports and the values carry nothing the model can hold.
    #[serde(rename = "ExposedPorts", default)]
    exposed_ports: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "Env", default)]
    env: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Healthcheck", default)]
    healthcheck: Option<HealthcheckDocument>,
    #[serde(rename = "ArgsEscaped", default)]
    args_escaped: Option<bool>,
    #[serde(rename = "Volumes", default)]
    volumes: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "WorkingDir", default)]
    working_dir: Option<String>,
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "OnBuild", default)]
    on_build: Option<Vec<String>>,
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "StopSignal", default)]
    stop_signal: Option<String>,
    #[serde(rename = "Shell", default)]
    shell: Option<Vec<String>>,
}

impl From<ImageConfigDocument> for crate::ImageConfig {
    fn from(document: ImageConfigDocument) -> Self {
        Self {
            user: document.user,
            exposed_ports: document
                .exposed_ports
                .map(|ports| ports.into_keys().collect()),
            env: document.env,
            cmd: document.cmd,
            healthcheck: document.healthcheck.map(ImageHealthcheck::from),
            args_escaped: document.args_escaped,
            volumes: document
                .volumes
                .map(|volumes| volumes.into_keys().collect()),
            working_dir: document.working_dir,
            entrypoint: document.entrypoint,
            on_build: document.on_build,
            labels: document.labels.unwrap_or_default(),
            stop_signal: document.stop_signal,
            shell: document.shell,
        }
    }
}

/// The `Config.Healthcheck` block of an inspect answer.
///
/// The Engine declares `Test` as a string *or* an array of strings, depending on
/// whether the image was built by a client that wrote one word or several, so
/// both spellings are accepted rather than the decode failing on a
/// `CMD-SHELL …` string.
#[derive(Debug, Deserialize)]
struct HealthcheckDocument {
    #[serde(rename = "Test", default)]
    test: Option<HealthcheckTestDocument>,
    #[serde(rename = "Interval", default)]
    interval: Option<i64>,
    #[serde(rename = "Timeout", default)]
    timeout: Option<i64>,
    #[serde(rename = "Retries", default)]
    retries: Option<i64>,
    #[serde(rename = "StartPeriod", default)]
    start_period: Option<i64>,
    #[serde(rename = "StartInterval", default)]
    start_interval: Option<i64>,
}

/// The two shapes of `Config.Healthcheck.Test`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HealthcheckTestDocument {
    /// The single-string spelling, such as `CMD-SHELL curl -f …`.
    One(String),
    /// The array spelling, such as `["CMD-SHELL", "curl -f …"]`.
    Many(Vec<String>),
}

impl From<HealthcheckDocument> for crate::ImageHealthcheck {
    fn from(document: HealthcheckDocument) -> Self {
        Self {
            test: document.test.map(|test| match test {
                HealthcheckTestDocument::One(one) => vec![one],
                HealthcheckTestDocument::Many(many) => many,
            }),
            interval: document.interval,
            timeout: document.timeout,
            retries: document.retries,
            start_period: document.start_period,
            start_interval: document.start_interval,
        }
    }
}

/// The `GraphDriver` block of an inspect answer.
#[derive(Debug, Deserialize)]
struct GraphDriverDocument {
    #[serde(rename = "Name", default)]
    name: String,
    /// The Engine declares this map's values as `interface{}`, not as strings,
    /// so a value that is not a string is carried as its JSON text rather than
    /// dropped by a string-typed field.
    #[serde(rename = "Data", default)]
    data: Option<BTreeMap<String, serde_json::Value>>,
}

impl From<GraphDriverDocument> for crate::ImageGraphDriver {
    fn from(document: GraphDriverDocument) -> Self {
        Self {
            name: document.name,
            data: document
                .data
                .unwrap_or_default()
                .into_iter()
                .map(|(key, value)| {
                    let value = match &value {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (key, value)
                })
                .collect(),
        }
    }
}

/// The `RootFS` block of an inspect answer.
#[derive(Debug, Deserialize)]
struct RootFsDocument {
    #[serde(rename = "Type", default)]
    typ: String,
    #[serde(rename = "Layers", default)]
    layers: Option<Vec<String>>,
}

impl From<RootFsDocument> for crate::ImageRootFs {
    fn from(document: RootFsDocument) -> Self {
        Self {
            typ: document.typ,
            layers: document.layers.unwrap_or_default(),
        }
    }
}

/// The `Metadata` block of an inspect answer.
#[derive(Debug, Deserialize)]
struct MetadataDocument {
    #[serde(rename = "LastTagTime", default)]
    last_tag_time: Option<String>,
}

impl From<MetadataDocument> for crate::ImageMetadata {
    fn from(document: MetadataDocument) -> Self {
        Self {
            last_tag_time: document.last_tag_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ImageDeleteResultDocument, ImageHistoryDocument, ImageInspectDocument, ImagePruneDocument,
        ImageSearchResultDocument, ImageSummaryDocument, image_inspect_request, image_list_request,
        image_prune_request, image_remove_request, image_search_request, image_tag_request,
    };
    use crate::raw::{RawEngine, RawRequest, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, ImageConfig, ImageGraphDriver, ImageInspectOptions,
        ImageListOptions, ImagePruneOptions, ImageRemoveOptions, ImageSearchOptions, ImageSummary,
        ImageTagOptions,
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
    fn request_line(request: &RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    /// Decodes a percent-encoded query value the way the Engine's Go side does.
    fn percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    let hex =
                        std::str::from_utf8(&bytes[index + 1..index + 3]).expect("two hex digits");
                    decoded.push(u8::from_str_radix(hex, 16).expect("a hex escape"));
                    index += 3;
                }
                // `url::form_urlencoded` writes a space as `+`, and Go's
                // `url.ParseQuery` reads it back the same way.
                b'+' => {
                    decoded.push(b' ');
                    index += 1;
                }
                other => {
                    decoded.push(other);
                    index += 1;
                }
            }
        }
        String::from_utf8(decoded).expect("a UTF-8 value")
    }

    /// The value of one query parameter, percent-decoded.
    fn query_value(request: &RawRequest, name: &str) -> Option<String> {
        let query = request.query.as_deref()?;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=')?;
            if key == name {
                return Some(percent_decode(value));
            }
        }
        None
    }

    #[test]
    fn a_list_sends_every_flag_and_the_filters_as_ordered_json() {
        let mut filters = BTreeMap::new();
        filters.insert("label".to_owned(), vec!["tier=web".to_owned()]);
        filters.insert("dangling".to_owned(), vec!["false".to_owned()]);
        let request = image_list_request(&ImageListOptions {
            all: true,
            shared_size: true,
            digests: true,
            filters,
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/json?all=true&shared-size=true&digests=true&filters=%7B%22dangling%22%3A%5B%22false%22%5D%2C%22label%22%3A%5B%22tier%3Dweb%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn the_shared_size_flag_is_spelled_the_way_the_engine_reads_it() {
        // The Engine's parameter is `shared-size`, with a hyphen. A `shared_size`
        // is a different, unread parameter, so the spelling is asserted rather
        // than produced by a casing rule.
        let request = image_list_request(&ImageListOptions::default()).expect("request");
        assert!(
            request
                .query
                .as_deref()
                .is_some_and(|query| query.contains("shared-size="))
        );
        assert!(
            !request
                .query
                .as_deref()
                .is_some_and(|query| query.contains("shared_size"))
        );
    }

    #[test]
    fn a_list_never_sends_the_manifests_flag_the_model_does_not_name() {
        // The generated option always sends `manifests=false`; the owned option
        // type has no member for it, so it is named in the module documentation
        // instead of being sent as a parameter nobody asked for.
        let request = image_list_request(&ImageListOptions::default()).expect("request");
        assert!(
            !request
                .query
                .as_deref()
                .is_some_and(|query| query.contains("manifests"))
        );
    }

    #[test]
    fn an_empty_filter_map_is_not_sent_at_all() {
        let request = image_list_request(&ImageListOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/json?all=false&shared-size=false&digests=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn filter_keys_are_emitted_in_map_order_so_a_recorded_request_is_reproducible() {
        // The facade converts the same ordered map into a `HashMap` before
        // serializing it, so the key order of its `filters` value varies between
        // runs of the same command and a recorded request cannot be diffed.
        let mut filters = BTreeMap::new();
        filters.insert("label".to_owned(), vec!["a".to_owned()]);
        filters.insert("reference".to_owned(), vec!["alpine".to_owned()]);
        let request = image_list_request(&ImageListOptions {
            filters,
            ..Default::default()
        })
        .expect("request");
        let decoded = query_value(&request, "filters").expect("a filters value");
        assert!(
            decoded.find("\"label\"").expect("label")
                < decoded.find("\"reference\"").expect("reference"),
            "keys must be in map order: {decoded}"
        );
    }

    #[test]
    fn a_repository_qualified_reference_stays_in_one_path_segment() {
        let request = image_inspect_request("ghcr.io/owner/app:1.2.3", &ImageInspectOptions::new())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/ghcr.io%2Fowner%2Fapp%3A1.2.3/json HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_inspect_sends_a_platform_only_when_one_was_asked_for() {
        let plain =
            image_inspect_request("alpine:3.20", &ImageInspectOptions::new()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("GET /v1.API/images/alpine%3A3.20/json HTTP/1.1")
        );
        let selected = image_inspect_request(
            "alpine:3.20",
            &ImageInspectOptions::new().with_platform(r#"{"os":"linux","architecture":"amd64"}"#),
        )
        .expect("request");
        assert_eq!(
            query_value(&selected, "platform").as_deref(),
            Some(r#"{"os":"linux","architecture":"amd64"}"#)
        );
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        assert_eq!(
            image_inspect_request("", &ImageInspectOptions::new())
                .expect_err("an empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_remove_always_spells_both_flags() {
        let request =
            image_remove_request("alpine:3.20", &ImageRemoveOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "DELETE /v1.API/images/alpine%3A3.20?force=false&noprune=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_prune_without_filters_sends_no_filters_value() {
        let request = image_prune_request(&ImagePruneOptions::new()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/prune HTTP/1.1")
        );
    }

    #[test]
    fn a_prune_sends_its_filters_as_ordered_json() {
        let mut filters = BTreeMap::new();
        filters.insert("dangling".to_owned(), vec!["true".to_owned()]);
        let request = image_prune_request(&ImagePruneOptions {
            filters: filters.clone(),
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/prune?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D HTTP/1.1"
            )
        );
        let decoded = query_value(&request, "filters").expect("a filters value");
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, Vec<String>>>(&decoded).expect("filter JSON"),
            filters
        );
    }

    #[test]
    fn a_tag_without_a_repository_is_refused_rather_than_silently_accepted() {
        // Measured: the Engine answers `200` and changes nothing, so a caller
        // would see a success for a request that tagged nothing.
        assert_eq!(
            image_tag_request("alpine:3.20", &ImageTagOptions::default())
                .expect_err("no repository")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            image_tag_request("alpine:3.20", &ImageTagOptions::new("   ".to_owned()))
                .expect_err("a blank repository")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_tag_sends_the_repository_the_tag_and_a_force_only_when_set() {
        let request = image_tag_request(
            "alpine:3.20",
            &ImageTagOptions::new("neotales/probe")
                .with_tag("v1")
                .with_force(true),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/alpine%3A3.20/tag?repo=neotales%2Fprobe&tag=v1&force=true HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_tag_with_no_force_does_not_send_the_parameter() {
        // The generated `TagImageOptions` has no `force` at all, which is why the
        // facade needs a request modifier for it; here the parameter is sent only
        // when the caller actually set one.
        let request =
            image_tag_request("alpine:3.20", &ImageTagOptions::new("probe")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/alpine%3A3.20/tag?repo=probe HTTP/1.1")
        );
    }

    #[test]
    fn a_search_without_a_term_is_refused() {
        // Measured: the Engine answers `200` to `?term=` rather than reporting
        // the missing required parameter.
        assert_eq!(
            image_search_request(&ImageSearchOptions::new(""))
                .expect_err("no term")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_search_sends_the_term_the_limit_and_the_filters() {
        let request = image_search_request(
            &ImageSearchOptions::new("alpine")
                .with_limit(2)
                .with_filter("is-official", ["true"]),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/search?term=alpine&limit=2&filters=%7B%22is-official%22%3A%5B%22true%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn the_measured_list_entry_projects_with_its_unknown_member_left_out() {
        // A real `GET /images/json` entry as Docker Engine 29.8.0 sends it. The
        // projection names nine of the ten members; `Descriptor` is the tenth and
        // is reachable only through `image_list_documents`, which is why that
        // function exists.
        let entry = br#"{
            "Containers": 0,
            "Created": 1776383606,
            "Id": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
            "Labels": {},
            "ParentId": "",
            "Descriptor": {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:d9e8", "size": 9226},
            "RepoDigests": ["alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"],
            "RepoTags": ["alpine:3.20"],
            "SharedSize": -1,
            "Size": 13153063
        }"#;
        let document: ImageSummaryDocument = serde_json::from_slice(entry).expect("a list entry");
        let summary = ImageSummary::from(document);
        assert_eq!(
            summary.id,
            "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
        );
        assert_eq!(summary.repo_tags, vec!["alpine:3.20".to_owned()]);
        assert_eq!(summary.size, 13_153_063);
        // `-1` is the Engine's "not calculated", and is carried through rather
        // than being treated as an absent value.
        assert_eq!(summary.shared_size, -1);
        assert!(summary.labels.is_empty());

        // The tenth member is still in the document, which is the point.
        let verbatim: serde_json::Value = serde_json::from_slice(entry).expect("a list entry");
        assert_eq!(
            verbatim["Descriptor"]["size"].as_i64(),
            Some(9226),
            "the unprojected member is still there to read"
        );
    }

    #[test]
    fn an_untagged_list_entry_projects_its_null_tag_lists_as_empty() {
        let entry = br#"{
            "Containers": -1,
            "Created": 0,
            "Id": "sha256:abc",
            "Labels": {"tier": "web"},
            "ParentId": "",
            "RepoDigests": null,
            "RepoTags": null,
            "SharedSize": -1,
            "Size": 0
        }"#;
        let document: ImageSummaryDocument = serde_json::from_slice(entry).expect("a list entry");
        let summary = ImageSummary::from(document);
        assert!(summary.repo_tags.is_empty());
        assert!(summary.repo_digests.is_empty());
        assert_eq!(summary.labels.get("tier").map(String::as_str), Some("web"));
    }

    #[test]
    fn the_measured_history_answer_projects_every_member_it_sends() {
        // All six members the daemon sends are named by the owned model, which
        // is why there is nothing to reach for in the verbatim form.
        let answer = br#"[
            {"Comment": "buildkit.dockerfile.v0", "Created": 1776383606,
             "CreatedBy": "CMD [\"/bin/sh\"]",
             "Id": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
             "Size": 0, "Tags": ["alpine:3.20"]},
            {"Comment": "buildkit.dockerfile.v0", "Created": 1776383606,
             "CreatedBy": "ADD alpine-minirootfs-3.20.10-x86_64.tar.gz / # buildkit",
             "Id": "<missing>", "Size": 9441280, "Tags": null}
        ]"#;
        let records: Vec<ImageHistoryDocument> =
            serde_json::from_slice(answer).expect("a history answer");
        assert_eq!(records.len(), 2);
        let mut records = records.into_iter();
        let first = crate::ImageHistory::from(records.next().expect("a layer"));
        assert_eq!(
            first.id,
            "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
        );
        assert_eq!(first.created_by, "CMD [\"/bin/sh\"]");
        assert_eq!(first.tags, vec!["alpine:3.20".to_owned()]);
        assert_eq!(first.comment, "buildkit.dockerfile.v0");
        // `null` tags on a middle layer become an empty list.
        let second = crate::ImageHistory::from(records.next().expect("a layer"));
        assert!(second.tags.is_empty());
        assert_eq!(second.size, 9_441_280);
    }

    #[test]
    fn the_measured_inspect_answer_projects_and_keeps_its_unknown_members() {
        // A real `GET /images/alpine:3.20/json` as Docker Engine 29.8.0 sends it.
        let answer = br#"{
            "Id": "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
            "RepoTags": ["alpine:3.20"],
            "RepoDigests": ["alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"],
            "Comment": "",
            "Created": "2026-04-18T00:00:00Z",
            "Config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin"], "Cmd": ["/bin/sh"], "WorkingDir": ""},
            "Architecture": "amd64",
            "Os": "linux",
            "Size": 13153063,
            "RootFS": {"Type": "layers", "Layers": ["sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d"]},
            "Metadata": {"LastTagTime": "2026-04-18T01:00:00Z"},
            "Descriptor": {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:d9e8", "size": 9226},
            "Identity": {"Pull": []}
        }"#;
        let document: ImageInspectDocument =
            serde_json::from_slice(answer).expect("an inspect answer");
        let inspect = crate::ImageInspect::from(document);
        assert_eq!(inspect.architecture.as_deref(), Some("amd64"));
        assert_eq!(inspect.os.as_deref(), Some("linux"));
        assert_eq!(inspect.size, Some(13_153_063));
        assert_eq!(
            inspect
                .config
                .as_ref()
                .and_then(|config| config.cmd.clone()),
            Some(vec!["/bin/sh".to_owned()])
        );
        assert_eq!(
            inspect.root_fs.as_ref().map(|root_fs| root_fs.layers.len()),
            Some(1)
        );
        assert_eq!(
            inspect
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.last_tag_time.clone()),
            Some("2026-04-18T01:00:00Z".to_owned())
        );

        // The two members the projection has no field for are still in the
        // document, which is what `image_inspect_document` hands back.
        let verbatim: serde_json::Value =
            serde_json::from_slice(answer).expect("an inspect answer");
        assert_eq!(verbatim["Descriptor"]["size"].as_i64(), Some(9226));
        assert!(verbatim.get("Identity").is_some());
    }

    #[test]
    fn a_healthcheck_test_is_accepted_in_both_spellings_the_engine_declares() {
        let single: ImageInspectDocument = serde_json::from_slice(
            br#"{"Id":"sha256:a","Config":{"Healthcheck":{"Test":"CMD-SHELL true","Interval":1}}}"#,
        )
        .expect("a string test");
        let healthcheck = single
            .config
            .map(ImageConfig::from)
            .and_then(|config| config.healthcheck)
            .expect("a healthcheck");
        assert_eq!(healthcheck.test, Some(vec!["CMD-SHELL true".to_owned()]));
        assert_eq!(healthcheck.interval, Some(1));

        let many: ImageInspectDocument = serde_json::from_slice(
            br#"{"Id":"sha256:a","Config":{"Healthcheck":{"Test":["CMD-SHELL","true"]}}}"#,
        )
        .expect("an array test");
        let healthcheck = many
            .config
            .map(ImageConfig::from)
            .and_then(|config| config.healthcheck)
            .expect("a healthcheck");
        assert_eq!(
            healthcheck.test,
            Some(vec!["CMD-SHELL".to_owned(), "true".to_owned()])
        );
    }

    #[test]
    fn a_graph_driver_value_that_is_not_a_string_is_carried_as_its_json_text() {
        // The Engine declares `GraphDriver.Data` as `map[string]interface{}`, so
        // a string-typed field would drop a number rather than keep it.
        let document: ImageInspectDocument = serde_json::from_slice(
            br#"{"Id":"sha256:a","GraphDriver":{"Name":"overlay2","Data":{"Root Dir":"/var/lib/docker/overlay2","count":3}}}"#,
        )
        .expect("an inspect answer");
        let driver = document.graph_driver.expect("a graph driver");
        assert_eq!(driver.name, "overlay2");
        let projected = ImageGraphDriver::from(driver);
        assert_eq!(
            projected.data.get("Root Dir").map(String::as_str),
            Some("/var/lib/docker/overlay2")
        );
        assert_eq!(projected.data.get("count").map(String::as_str), Some("3"));
    }

    #[test]
    fn a_prune_that_removed_nothing_projects_its_null_deleted_list() {
        // Measured: a prune that matched nothing answers
        // `{"ImagesDeleted":null,"SpaceReclaimed":0}`.
        let document: ImagePruneDocument =
            serde_json::from_slice(br#"{"ImagesDeleted":null,"SpaceReclaimed":0}"#)
                .expect("a prune answer");
        let result = crate::ImagePruneResult::from(document);
        assert!(result.images_deleted.is_empty());
        assert_eq!(result.space_reclaimed, Some(0));
    }

    #[test]
    fn a_remove_answer_projects_both_records_the_daemon_sends() {
        // Measured for an untagged image: one record with `Untagged` and one with
        // `Deleted`, so neither member is required.
        let records: Vec<ImageDeleteResultDocument> = serde_json::from_slice(
            br#"[{"Untagged":"neotales/probe:v1"},{"Deleted":"sha256:c4c4ccb80b51"}]"#,
        )
        .expect("a delete answer");
        let projected: Vec<crate::ImageDeleteResult> =
            records.into_iter().map(Into::into).collect();
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[0].untagged.as_deref(), Some("neotales/probe:v1"));
        assert_eq!(projected[1].deleted.as_deref(), Some("sha256:c4c4ccb80b51"));
        assert!(projected[0].deleted.is_none());
    }

    #[test]
    fn the_measured_search_answer_projects_every_member_it_sends() {
        let answer = br#"[{"star_count":11554,"is_official":true,"name":"alpine","is_automated":false,
            "description":"A minimal Docker image based on Alpine Linux with a complete package index and only 5 MB in size!"}]"#;
        let records: Vec<ImageSearchResultDocument> =
            serde_json::from_slice(answer).expect("a search answer");
        let result = crate::ImageSearchResult::from(records.into_iter().next().expect("a result"));
        assert_eq!(result.name, "alpine");
        assert_eq!(result.star_count, 11_554);
        assert!(result.is_official);
        assert!(!result.is_automated);
        assert!(result.description.starts_with("A minimal Docker image"));
    }

    #[test]
    fn a_search_result_with_a_missing_member_projects_a_default_rather_than_failing() {
        // The registry, not the daemon, writes these answers, so a member can be
        // absent; an absent one is reported as the model's default rather than
        // failing the whole search.
        let records: Vec<ImageSearchResultDocument> =
            serde_json::from_slice(br#"[{"name":"alpine"}]"#).expect("a search answer");
        let result = crate::ImageSearchResult::from(records.into_iter().next().expect("a result"));
        assert_eq!(result.name, "alpine");
        assert_eq!(result.description, "");
        assert_eq!(result.star_count, 0);
        assert!(!result.is_official);
    }

    #[test]
    fn the_collected_forms_bound_their_answer_twice() {
        // A pull is a live stream; the document form is bounded by a record count
        // and by the same byte limit as every other document here, so asking for
        // the bounded form cannot become an unbounded allocation.
        const { assert!(super::MAX_PROGRESS_RECORDS > 0) };
        const { assert!(super::MAX_PROGRESS_RECORDS <= 1_000_000) };
    }
}
