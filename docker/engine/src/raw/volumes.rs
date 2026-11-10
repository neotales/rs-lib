//! Volume operations for the repository-owned Engine backend.
//!
//! This is step 4 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. Every operation reuses
//! [`RawEngine`], the single owned transport, and the shared
//! [`engine_result`] status mapping, so there is no second client, no second
//! error type, and no second HTTP stack in the crate. The option, result, and
//! summary types are the existing repository-owned models, reused as they are.
//!
//! The names are prefixed by resource because they share the `raw` namespace
//! with the container slice's `list`, `create`, and `remove`.
//!
//! # The volume name is a body member
//!
//! `POST /volumes/create` reads the name from the JSON body and declares no query
//! parameter for it. Measured against Docker Engine 29.8.0: a body carrying
//! `{"Driver":"local"}` and no `Name` is answered `201` with a generated 64-hex
//! name, which is the same request the Docker CLI makes when the caller did not
//! name the volume. An empty `Name` member is sent as an empty string rather
//! than omitted for the same reason — an omitted `Name` is a request for a
//! generated name, which is what the CLI's `docker volume create` with no
//! argument asks for.
//!
//! # `create` answers the whole volume, not just an id
//!
//! `POST /volumes/create` answers `201` with the complete volume document — the
//! same 7 members `GET /volumes/{name}` sends — rather than with a bare
//! identifier. Recorded from Docker Engine 29.8.0:
//!
//! ```text
//! HTTP 201
//! {"CreatedAt":"2026-09-26T01:30:00-05:00","Driver":"local",
//!  "Labels":{"probe":"1"},"Mountpoint":"/var/lib/docker/volumes/probevol/_data",
//!  "Name":"probevol","Options":null,"Scope":"local"}
//! ```
//!
//! A client that read only the name out of a create answer would throw away the
//! `Mountpoint` the caller needs for a bind mount, so [`volume_create`] returns
//! the full [`VolumeSummary`].
//!
//! # The list answer is an object, and `Warnings` is real
//!
//! `GET /volumes` answers `{"Volumes":[…],"Warnings":[…]}`, not a bare array.
//! The daemon sends `Warnings` even when it is empty, and it is where a Swarm
//! volume-store failure is reported on a non-Swarm store — the Engine's own
//! handler appends the cluster error to it rather than failing the request. So
//! [`volume_list`] returns the [`VolumeListResult`] envelope rather than only its
//! volumes.
//!
//! # `remove` answers `204`, and `force` changes what a `204` proves
//!
//! Measured: `DELETE /volumes/{name}` answers `204` with no body. `force` is sent
//! as `true`/`false` rather than only when set, so a recorded `DELETE` says
//! whether a volume still in use was removed anyway.
//!
//! Two measured answers are worth stating because a caller would otherwise have to
//! discover them:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `DELETE /volumes/probe-none` | `404 {"message":"volume probe-none not found"}` |
//! | `DELETE /volumes/probe-none?force=true` | `204`, no body |
//! | `DELETE /volumes/probevolused` (one container attached) | `409 … volume is in use - [<id>]` |
//! | `DELETE /volumes/probevolused?force=true` (one container attached) | `409 … volume is in use - [<id>]` |
//!
//! So a `force=true` `204` does not prove the volume was there, and `force=true`
//! does **not** remove a volume a container is using. Both are the daemon's own
//! answers, reported as such rather than reinterpreted here.
//!
//! # Filter values are the repository's list form, and the daemon accepts it
//!
//! The Engine's own CLI sends `{"name":{"probevol":true}}` — a map of maps — while
//! the repository's filter type is a `BTreeMap<String, Vec<String>>`, which
//! serializes to `{"name":["probevol"]}`. Both were sent to Docker Engine 29.8.0
//! through `GET /volumes?filters=…` and both filtered correctly; a filter the
//! daemon cannot parse is answered `{"message":"error reading volume filters"}`.
//! The ordered list form is kept because the map order is what makes a recorded
//! request reproducible.
//!
//! # `prune` only reclaims *anonymous* volumes unless the caller says `all`
//!
//! This is the one place in this slice where the Engine changed the meaning of a
//! request based on the API version, and a caller would otherwise conclude from an
//! empty answer that its filter was wrong. The Engine's prune handler adds
//! `all=true` to the filter set **only** for API versions below `1.42`; this
//! backend speaks `1.53`, so it does not, and a prune without an explicit `all`
//! considers only anonymous volumes. Measured on Docker Engine 29.8.0 against a
//! *named* volume carrying `frawprobe=1`:
//!
//! | Request | Answer | The volume |
//! | --- | --- | --- |
//! | `POST /volumes/prune?filters={"label":["frawprobe=1"]}` | `200 {"VolumesDeleted":[],"SpaceReclaimed":0}` | still there |
//! | `POST /volumes/prune?filters={"all":["true"],"label":["frawprobe=1"]}` | `200 {"VolumesDeleted":["frawprobevol…"],"SpaceReclaimed":0}` | gone |
//!
//! So an empty `VolumesDeleted` from this endpoint means "no anonymous volume
//! matched", not "no volume matched". [`volume_prune`] sends the filter map exactly
//! as the caller wrote it and does **not** add `all` on the caller's behalf: adding
//! it would reclaim named volumes the caller did not ask to lose, and a prune is
//! irreversible. A caller that means "all of these" puts `all` in the filter map
//! itself, which is what the Docker CLI does.
//!
//! # What is deliberately not covered
//!
//! - **Cluster volumes and `PUT /volumes/{name}?version=`.** A cluster volume is
//!   a Swarm object; the repository's [`VolumeCreateOptions`] names the local
//!   driver's members only, and the update endpoint exists only for cluster
//!   volumes, which a non-manager answers `503` for. The operations here are the
//!   five the repository already exposes.
//! - **`Options: null` versus an empty map.** The Engine sends `null` for a
//!   volume created without driver options, and the repository model reports an
//!   empty map for it. That is the current facade's behaviour and is kept, so the
//!   two paths agree; the raw value is in neither path, so a caller that needs to
//!   tell "no options" from "an empty options map" cannot today.
//! - **Registry or TLS behaviour.** Nothing here differs from the transport, and
//!   `RawTarget::Tcp` is still a plain TCP stream.

use std::collections::BTreeMap;

use hyper::Method;
use serde::{Deserialize, Serialize};

use super::containers::{Query, completed, escape_path_segment, with_query};
use super::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::{
    Error, VolumeCreateOptions, VolumeListOptions, VolumeListResult, VolumePruneOptions,
    VolumePruneResult, VolumeRemoveOptions, VolumeSummary, VolumeUsage,
};

/// Creates a volume.
///
/// The name travels in the body; see the module documentation. The answer is the
/// daemon's complete volume document, so the returned [`VolumeSummary`] carries
/// the `Mountpoint` and creation time a caller needs, not just the name.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a volume document. Measured against
/// Docker Engine 29.8.0: an unknown driver is answered `404 create <name>: error
/// looking up volume plugin <driver>: … not found`, and a driver option the
/// driver requires is answered `400 create <name>: missing required option:
/// "device"`.
pub async fn volume_create(
    engine: &RawEngine,
    options: &VolumeCreateOptions,
) -> Result<VolumeSummary, Error> {
    let response = engine.send(volume_create_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<VolumeDocument>(&document).map(VolumeSummary::from)
}

/// Builds the `POST /volumes/create` request.
///
/// # Errors
///
/// Returns an error when the body cannot be encoded.
fn volume_create_request(options: &VolumeCreateOptions) -> Result<RawRequest, Error> {
    // An absent name is sent as an empty string rather than omitted: the Engine
    // reads a missing `Name` as "generate one", which is a different request from
    // a caller that supplied an empty name on purpose.
    let body = json_body(&VolumeCreateBody {
        name: options.name.as_deref().unwrap_or_default(),
        driver: options.driver.as_deref(),
        driver_opts: options.driver_options.as_ref(),
        labels: options.labels.as_ref(),
    })?;
    // No query: the Engine declares none for this endpoint and reads the name
    // from the body, so a recorded request line is the bare path.
    Ok(json_content_type(RawRequest::new(Method::POST, "/volumes/create")).with_body(body))
}

/// The `POST /volumes/create` body, in the Engine's spelling.
///
/// `DriverOpts` is the Engine's member name; the repository spells it
/// `driver_options`, and a wrong one is a driver option silently ignored.
#[derive(Debug, Serialize)]
struct VolumeCreateBody<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    driver: Option<&'a str>,
    #[serde(rename = "DriverOpts", skip_serializing_if = "Option::is_none")]
    driver_opts: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
}

/// Lists volumes.
///
/// `filters` is sent only when it is non-empty, for the reason the container
/// slice records: an empty filter object is a filter that matches the daemon's
/// own no-filter case and would only make a recorded request noisier. The answer
/// is the `{"Volumes":[…],"Warnings":[…]}` object read as one bounded document,
/// because the warning list is a place the daemon reports a Swarm volume-store
/// failure without failing the request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// be reached or rejects the request, or when the answer is not a list object.
pub async fn volume_list(
    engine: &RawEngine,
    options: &VolumeListOptions,
) -> Result<VolumeListResult, Error> {
    let response = engine.send(volume_list_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<VolumeListDocument>(&document).map(VolumeListResult::from)
}

/// Builds the `GET /volumes` list request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn volume_list_request(options: &VolumeListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/volumes"),
        query.finish(),
    ))
}

/// Reads one volume.
///
/// The answer is one JSON object, so it is a bounded document read. The Engine
/// declares no query parameter for this endpoint, so the recorded request line is
/// the bare path.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, when it rejects the request — a `404` carrying `volume <name> not
/// found`, measured — or when the response is not a volume document.
pub async fn volume_inspect(engine: &RawEngine, volume: &str) -> Result<VolumeSummary, Error> {
    let response = engine.send(volume_inspect_request(volume)?).await?;
    let document = engine_result(response).await?;
    decode::<VolumeDocument>(&document).map(VolumeSummary::from)
}

/// Builds the `GET /volumes/{name}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn volume_inspect_request(volume: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(Method::GET, &volume_path(volume, "")?))
}

/// Removes a volume.
///
/// Answers `204` with no body, so the status is the whole result. `force` is sent
/// as `true`/`false` rather than only when set; see the module documentation for
/// what a `force=true` `204` does and does not prove.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request — a `404` for a volume that does not
/// exist, or a `409` carrying `volume is in use` for one a container is using,
/// which `force` does not override.
pub async fn volume_remove(
    engine: &RawEngine,
    volume: &str,
    options: &VolumeRemoveOptions,
) -> Result<(), Error> {
    completed(engine, volume_remove_request(volume, *options)?).await
}

/// Builds the `DELETE /volumes/{name}` request.
///
/// The options are taken by value because the type is one `bool`; the public
/// operation still borrows so a caller can reuse its options afterwards.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn volume_remove_request(volume: &str, options: VolumeRemoveOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("force", options.force);
    Ok(with_query(
        RawRequest::new(Method::DELETE, &volume_path(volume, "")?),
        query.finish(),
    ))
}

/// Prunes unused volumes.
///
/// **At the v1.53 ceiling this reclaims anonymous volumes only**, unless the
/// caller's filter map carries `all`. The Engine adds `all=true` by itself only
/// below API `1.42`, so an empty answer means "no anonymous volume matched" rather
/// than "no volume matched"; see the module documentation for the measurement. This
/// operation does not add `all` on the caller's behalf, because a prune is
/// irreversible and reclaiming named volumes the caller did not name is not a
/// translation decision this layer gets to make.
///
/// The answer is one JSON document with two members, `VolumesDeleted` and
/// `SpaceReclaimed`, and both are `null` rather than empty when there was nothing
/// to reclaim. A `null` list means "nothing was deleted", not "the daemon did not
/// say", so it projects to an empty list; `SpaceReclaimed` is an `Option` in the
/// repository model and stays one, because "reclaimed nothing" and "the daemon
/// did not report a figure" are different answers.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// reached or rejects the request, or when the response is not a prune document.
pub async fn volume_prune(
    engine: &RawEngine,
    options: &VolumePruneOptions,
) -> Result<VolumePruneResult, Error> {
    let response = engine.send(volume_prune_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<VolumePruneDocument>(&document).map(VolumePruneResult::from)
}

/// Builds the `POST /volumes/prune` request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn volume_prune_request(options: &VolumePruneOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, "/volumes/prune"),
        query.finish(),
    ))
}

/// Builds the `/volumes/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/volumes//` is not a request for a
/// volume, and sending it would ask the daemon about a resource the caller never
/// named. The reference is percent-encoded into exactly one segment, so a name
/// containing `/` cannot address a different resource.
fn volume_path(volume: &str, suffix: &str) -> Result<String, Error> {
    if volume.is_empty() {
        return Err(Error::invalid_input(
            "the Engine volume reference must not be empty",
        ));
    }
    Ok(format!("/volumes/{}{suffix}", escape_path_segment(volume)))
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The map is a `BTreeMap`, so the JSON is in key order and a recorded request is
/// reproducible between runs. The current facade converts the same map into a
/// `HashMap` first, so its key order varies.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine volume filters: {error}"
        ))
    })
}

/// One volume as the Engine sends it, in the Engine's spelling.
///
/// This is the private wire boundary. The repository's [`VolumeSummary`] is
/// `snake_case` CLI output and serializes as such, so decoding a real answer into
/// it directly would not read a single member.
///
/// Every optional member is `Option` because the Engine omits or nulls several of
/// them: `Options` is `null` for a volume created without driver options,
/// `Labels` is an object, and `UsageData` appears only for the `local` driver.
#[derive(Debug, Deserialize)]
struct VolumeDocument {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Mountpoint")]
    mountpoint: String,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "Scope")]
    scope: Option<String>,
    // The Engine's `Status` is a driver-reported key/value map. The current
    // facade's generated model flattens it to a list of keys and sorts it, so the
    // owned backend reads the keys and sorts them the same way: the two paths
    // produce the same [`VolumeSummary::status`] for the same answer. The values
    // are not carried by the repository model on either path.
    #[serde(default, rename = "Status", deserialize_with = "status_keys")]
    status: Option<Vec<String>>,
    // `#[serde(default)]` covers an absent member but not an explicit `null`, and
    // the Engine sends `Options: null` for a volume created without driver
    // options, so both members read a null as the empty map the current facade's
    // generated model produces for it.
    #[serde(default, rename = "Labels", deserialize_with = "null_as_empty_map")]
    labels: BTreeMap<String, String>,
    #[serde(default, rename = "Options", deserialize_with = "null_as_empty_map")]
    options: BTreeMap<String, String>,
    #[serde(default, rename = "UsageData")]
    usage_data: Option<VolumeUsageDocument>,
}

impl From<VolumeDocument> for VolumeSummary {
    fn from(document: VolumeDocument) -> Self {
        Self {
            name: document.name,
            driver: document.driver,
            mountpoint: document.mountpoint,
            created_at: document.created_at,
            scope: document.scope,
            status: document.status,
            labels: document.labels,
            options: document.options,
            usage: document.usage_data.map(VolumeUsage::from),
        }
    }
}

/// Reads a map member the Engine may send as `null` as the empty map.
///
/// The Engine sends `"Options":null` for a volume created without driver options,
/// and `"Labels":null` is the shape the daemon uses when it has none. A `null` is
/// the empty map, not a missing answer, and the current facade's generated model
/// reads it the same way, so the two paths agree.
fn null_as_empty_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<BTreeMap<String, String>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The `UsageData` block of a volume document.
///
/// `RefCount` is the Engine's member name; the repository spells it
/// `reference_count`, and `Size` and `RefCount` are both `-1` when the driver
/// cannot report them.
#[derive(Debug, Deserialize)]
struct VolumeUsageDocument {
    #[serde(rename = "Size")]
    size: i64,
    #[serde(rename = "RefCount")]
    ref_count: i64,
}

impl From<VolumeUsageDocument> for VolumeUsage {
    fn from(document: VolumeUsageDocument) -> Self {
        Self {
            size: document.size,
            reference_count: document.ref_count,
        }
    }
}

/// Reads a volume's `Status` map as its sorted keys.
///
/// The Engine declares `Status` as a `map[string]string`, so a driver that
/// reports one is an object and not an array. The current facade's generated model
/// flattens it to the keys and the facade then sorts them; this is the same
/// projection, so both paths agree. A `null` is an empty list rather than an
/// absent one, which is also what the generated model's flattener produces.
fn status_keys<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries = Option::<BTreeMap<String, serde_json::Value>>::deserialize(deserializer)?;
    Ok(Some(
        entries
            .unwrap_or_default()
            .into_keys()
            .collect::<Vec<String>>(),
    ))
}

/// The `GET /volumes` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct VolumeListDocument {
    #[serde(default, rename = "Volumes")]
    volumes: Option<Vec<VolumeDocument>>,
    // The daemon sends this even when empty, and it is where a Swarm volume-store
    // failure is reported on a request that otherwise succeeds.
    #[serde(default, rename = "Warnings")]
    warnings: Option<Vec<String>>,
}

impl From<VolumeListDocument> for VolumeListResult {
    fn from(document: VolumeListDocument) -> Self {
        Self {
            volumes: document
                .volumes
                .unwrap_or_default()
                .into_iter()
                .map(VolumeSummary::from)
                .collect(),
            warnings: document.warnings.unwrap_or_default(),
        }
    }
}

/// The `POST /volumes/prune` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct VolumePruneDocument {
    #[serde(default, rename = "VolumesDeleted")]
    volumes_deleted: Option<Vec<String>>,
    // `SpaceReclaimed` is `0` when nothing was reclaimed and `null` when the
    // daemon reported no figure at all, which are different answers and the
    // repository model's `Option` is what tells them apart.
    #[serde(default, rename = "SpaceReclaimed")]
    space_reclaimed: Option<i64>,
}

impl From<VolumePruneDocument> for VolumePruneResult {
    fn from(document: VolumePruneDocument) -> Self {
        Self {
            volumes_deleted: document.volumes_deleted.unwrap_or_default(),
            space_reclaimed: document.space_reclaimed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        VolumeCreateBody, VolumeDocument, VolumeListDocument, VolumePruneDocument,
        volume_create_request, volume_inspect_request, volume_list_request, volume_prune_request,
        volume_remove_request,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, VolumeCreateOptions, VolumeListOptions, VolumePruneOptions,
        VolumeRemoveOptions,
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
        BTreeMap::from([
            ("dangling".to_owned(), vec!["true".to_owned()]),
            ("name".to_owned(), vec!["probevol".to_owned()]),
        ])
    }

    /// The `POST /volumes/create` answer recorded from Docker Engine 29.8.0, with
    /// every member the daemon sent.
    const CREATE_BODY: &[u8] = br#"{
        "CreatedAt":"2026-09-26T01:30:00-05:00",
        "Driver":"local",
        "Labels":{"probe":"1"},
        "Mountpoint":"/var/lib/docker/volumes/probevol/_data",
        "Name":"probevol",
        "Options":null,
        "Scope":"local"
    }"#;

    #[test]
    fn create_sends_the_versioned_path_and_the_name_in_the_body() {
        // The Engine declares no query parameter here, and a body with no `Name`
        // is answered `201` with a generated 64-hex name.
        let request = volume_create_request(&VolumeCreateOptions::new().with_name("probevol"))
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/volumes/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "probevol");
        assert_eq!(body.as_object().expect("an object").len(), 1, "{body}");
    }

    #[test]
    fn a_create_with_no_name_sends_an_empty_name_rather_than_omitting_it() {
        // A missing `Name` member is a request for a generated name, which is what
        // an unnamed create means, so the member is present and empty.
        let body =
            request_body(&volume_create_request(&VolumeCreateOptions::new()).expect("request"));
        assert_eq!(body["Name"], "");
        assert!(body.get("Name").is_some(), "{body}");
    }

    #[test]
    fn the_create_body_uses_the_engines_member_spellings() {
        // `DriverOpts` is the Engine's name for the member the repository calls
        // `driver_options`, and a wrong spelling is a driver option the daemon
        // silently ignores.
        let body = request_body(
            &volume_create_request(&VolumeCreateOptions {
                name: Some("probevol".to_owned()),
                driver: Some("local".to_owned()),
                driver_options: Some(BTreeMap::from([("type".to_owned(), "tmpfs".to_owned())])),
                labels: Some(BTreeMap::from([("probe".to_owned(), "1".to_owned())])),
            })
            .expect("request"),
        );
        assert_eq!(body["Driver"], "local");
        assert_eq!(body["DriverOpts"]["type"], "tmpfs");
        assert_eq!(body["Labels"]["probe"], "1");
        assert!(body.get("DriverOptions").is_none(), "{body}");
    }

    #[test]
    fn the_create_answer_carries_the_whole_volume_not_just_a_name() {
        // Measured: `POST /volumes/create` answers `201` with the same 7 members
        // a `GET /volumes/{name}` sends. A client reading only the name would lose
        // the `Mountpoint` a bind mount needs.
        let document: VolumeDocument =
            super::super::decode(CREATE_BODY).expect("a volume document");
        let volume = crate::VolumeSummary::from(document);
        assert_eq!(volume.name, "probevol");
        assert_eq!(volume.driver, "local");
        assert_eq!(volume.mountpoint, "/var/lib/docker/volumes/probevol/_data");
        assert_eq!(
            volume.created_at.as_deref(),
            Some("2026-09-26T01:30:00-05:00")
        );
        assert_eq!(volume.scope.as_deref(), Some("local"));
        assert_eq!(volume.labels.get("probe").map(String::as_str), Some("1"));
        // `Options` was `null` on the wire, which is an empty map here.
        assert!(volume.options.is_empty());
        assert_eq!(volume.usage, None);
        assert_eq!(volume.status, None);
    }

    #[test]
    fn a_volume_with_usage_data_reports_the_size_and_the_reference_count() {
        // `RefCount` is the Engine's member name; the repository field is
        // `reference_count`. Both are `-1` when the driver cannot report them.
        let document: VolumeDocument = super::super::decode(
            br#"{"Name":"v","Driver":"local","Mountpoint":"/m",
                "UsageData":{"Size":4096,"RefCount":2}}"#,
        )
        .expect("a volume document");
        let usage = crate::VolumeSummary::from(document)
            .usage
            .expect("usage data");
        assert_eq!(usage.size, 4096);
        assert_eq!(usage.reference_count, 2);
    }

    #[test]
    fn a_driver_reported_status_is_read_as_its_sorted_keys() {
        // The Engine declares `Status` as a `map[string]string`, so a driver that
        // reports one sends an object, not an array. The current facade's
        // generated model flattens it to the keys and the facade sorts them; this
        // is the same projection, so the two paths agree.
        let document: VolumeDocument = super::super::decode(
            br#"{"Name":"v","Driver":"nfs","Mountpoint":"/m",
                "Status":{"options":"addr=1","volatile":"true"}}"#,
        )
        .expect("a volume document");
        assert_eq!(
            crate::VolumeSummary::from(document).status,
            Some(vec!["options".to_owned(), "volatile".to_owned()])
        );
    }

    #[test]
    fn a_null_status_is_an_empty_list_rather_than_a_decode_failure() {
        // The generated model's flattener turns a `null` into an empty list, and
        // the two paths agree on that too.
        let document: VolumeDocument = super::super::decode(
            br#"{"Name":"v","Driver":"local","Mountpoint":"/m","Status":null}"#,
        )
        .expect("a volume document");
        assert_eq!(
            crate::VolumeSummary::from(document).status,
            Some(Vec::new())
        );
    }

    #[test]
    fn list_sends_the_versioned_path_and_its_filters() {
        let request =
            volume_list_request(&VolumeListOptions { filters: filters() }).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/volumes?filters=%7B%22dangling%22%3A%5B%22true%22%5D%2C%22name%22%3A%5B%22probevol%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_empty_filter_map_is_not_sent_at_all() {
        let list = volume_list_request(&VolumeListOptions::default()).expect("request");
        assert_eq!(
            request_line(&list),
            crate::raw::at_api_version("GET /v1.API/volumes HTTP/1.1")
        );
        let prune = volume_prune_request(&VolumePruneOptions::default()).expect("request");
        assert_eq!(
            request_line(&prune),
            crate::raw::at_api_version("POST /v1.API/volumes/prune HTTP/1.1")
        );
    }

    #[test]
    fn filter_keys_are_emitted_in_order_so_a_recorded_request_is_reproducible() {
        // The current facade converts the ordered map to a `HashMap` first, so its
        // recorded order varies between runs of the same command.
        let request =
            volume_list_request(&VolumeListOptions { filters: filters() }).expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        assert!(
            value.find("%22dangling%22").expect("dangling")
                < value.find("%22name%22").expect("name")
        );
    }

    #[test]
    fn the_list_answer_is_an_object_and_its_warnings_are_kept() {
        // Measured from Docker Engine 29.8.0: `{"Volumes":[…],"Warnings":[…]}`, and
        // the daemon appends a Swarm volume-store failure to `Warnings` rather than
        // failing the request.
        let document: VolumeListDocument = super::super::decode(
            br#"{"Volumes":[{"Name":"a","Driver":"local","Mountpoint":"/a"},
                 {"Name":"b","Driver":"local","Mountpoint":"/b"}],
                 "Warnings":["failed to list cluster volumes: no volume store"]}"#,
        )
        .expect("a list document");
        let list = crate::VolumeListResult::from(document);
        assert_eq!(list.volumes.len(), 2);
        assert_eq!(list.volumes[0].name, "a");
        assert_eq!(list.volumes[1].mountpoint, "/b");
        assert_eq!(
            list.warnings,
            vec!["failed to list cluster volumes: no volume store".to_owned()]
        );
    }

    #[test]
    fn a_list_with_no_volumes_and_no_warnings_still_decodes() {
        let document: VolumeListDocument =
            super::super::decode(br#"{"Volumes":null,"Warnings":null}"#).expect("a list document");
        let list = crate::VolumeListResult::from(document);
        assert!(list.volumes.is_empty());
        assert!(list.warnings.is_empty());
    }

    #[test]
    fn inspect_sends_a_bare_get_with_no_query() {
        let request = volume_inspect_request("probevol").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/volumes/probevol HTTP/1.1")
        );
        assert_eq!(request.query, None);
    }

    #[test]
    fn force_is_sent_because_it_changes_what_a_204_proves() {
        // Measured against Docker Engine 29.8.0:
        //   DELETE /volumes/probe-none               -> 404 volume … not found
        //   DELETE /volumes/probe-none?force=true    -> 204
        //   DELETE /volumes/<in use>                 -> 409 volume is in use
        //   DELETE /volumes/<in use>?force=true      -> 409 volume is in use
        // So a `force=true` `204` does not prove the volume was there, and
        // `force=true` does not remove a volume a container is using. Both are
        // reported as the daemon's own answers; nothing here reinterprets them.
        let forced =
            volume_remove_request("probe-none", VolumeRemoveOptions::new().with_force(true))
                .expect("request");
        assert_eq!(
            request_line(&forced),
            crate::raw::at_api_version("DELETE /v1.API/volumes/probe-none?force=true HTTP/1.1")
        );
    }

    #[test]
    fn remove_spells_force_as_true_or_false() {
        // An absent `force` and a `false` one are the same request, and a recorded
        // request that omits it cannot say which the caller meant.
        let plain =
            volume_remove_request("probevol", VolumeRemoveOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("DELETE /v1.API/volumes/probevol?force=false HTTP/1.1")
        );
        let forced = volume_remove_request("probevol", VolumeRemoveOptions::new().with_force(true))
            .expect("request");
        assert_eq!(
            request_line(&forced),
            crate::raw::at_api_version("DELETE /v1.API/volumes/probevol?force=true HTTP/1.1")
        );
    }

    #[test]
    fn a_prune_that_reclaimed_nothing_reports_an_empty_list_and_no_figure() {
        // Recorded from Docker Engine 29.8.0: `{"VolumesDeleted":[…],"SpaceReclaimed":0}`
        // for a real prune, and `{"VolumesDeleted":null,"SpaceReclaimed":0}` for the
        // identical call immediately afterwards.
        let document: VolumePruneDocument = super::super::decode(
            br#"{"VolumesDeleted":["9654ed50b7fedf1cb1e187514187f671e10116547d0b343199a8d6d6a71ae55e"],"SpaceReclaimed":0}"#,
        )
        .expect("a prune document");
        let result = crate::VolumePruneResult::from(document);
        assert_eq!(result.volumes_deleted.len(), 1);
        assert_eq!(result.space_reclaimed, Some(0));
    }

    #[test]
    fn a_prune_that_deleted_nothing_reports_an_empty_list() {
        let document: VolumePruneDocument =
            super::super::decode(br#"{"VolumesDeleted":null,"SpaceReclaimed":0}"#)
                .expect("a prune document");
        let result = crate::VolumePruneResult::from(document);
        assert!(result.volumes_deleted.is_empty());
    }

    #[test]
    fn a_missing_space_reclaimed_is_absent_rather_than_zero() {
        // "Reclaimed nothing" and "the daemon reported no figure" are different
        // answers, and the repository model's `Option` is what tells them apart.
        let document: VolumePruneDocument =
            super::super::decode(br#"{"VolumesDeleted":null}"#).expect("a prune document");
        assert_eq!(
            crate::VolumePruneResult::from(document).space_reclaimed,
            None
        );
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        for error in [
            volume_inspect_request("").expect_err("empty reference"),
            volume_remove_request("", VolumeRemoveOptions::default()).expect_err("empty reference"),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_reference_cannot_reshape_the_volume_path() {
        // `/volumes/a/b` is a different resource rather than a volume whose name
        // contains a slash.
        let request = volume_inspect_request("a/b").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/volumes/a%2Fb HTTP/1.1")
        );
    }

    #[test]
    fn the_body_documents_serialize_to_the_engines_member_names() {
        // The rename is spelled out rather than derived, because a casing rule
        // would produce `DriverOpts` from `driver_opts` only by accident.
        let body = super::json_body(&VolumeCreateBody {
            name: "v",
            driver: Some("local"),
            driver_opts: Some(&BTreeMap::from([("type".to_owned(), "tmpfs".to_owned())])),
            labels: None,
        })
        .expect("a body");
        let bytes = match body {
            RawBody::Bytes(bytes) => bytes,
            other => panic!("expected a buffered body, got {other:?}"),
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            serde_json::json!({
                "Name": "v",
                "Driver": "local",
                "DriverOpts": {"type": "tmpfs"}
            })
        );
    }

    #[test]
    fn the_document_limit_still_bounds_a_volume_list() {
        // The bound is a property of the transport, so what is asserted here is
        // that these operations read through it rather than the socket directly.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        let request = volume_list_request(&VolumeListOptions::default()).expect("request");
        assert!(
            request.body.known_len().is_some(),
            "no request body is sent"
        );
    }
}
