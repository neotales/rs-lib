//! Plugin operations for the repository-owned Engine backend.
//!
//! This is step 4 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. Every operation reuses
//! [`RawEngine`], the single owned transport, and the shared
//! [`engine_result`] status mapping, so there is no second client, no second
//! error type, and no second HTTP stack in the crate. The option, summary, and
//! privilege types are the existing repository-owned models, reused as they are.
//!
//! The names are prefixed by resource because they share the `raw` namespace with
//! the container slice's `list`, `create`, and `remove`.
//!
//! # Which answers here are documents and which are streams
//!
//! | Operation | Answer | Why |
//! | --- | --- | --- |
//! | [`plugin_list`], [`plugin_inspect`] | one document | one JSON array or object, bounded |
//! | [`plugin_remove`] | one document | the daemon answers the removed plugin's own document |
//! | [`plugin_privileges`] | one document | one JSON array, bounded |
//! | [`plugin_enable`], [`plugin_disable`] | a status, no body | `200` with an empty body |
//! | [`plugin_pull`], [`plugin_upgrade`] | a frame stream | the Engine writes one JSON progress object per line for as long as the install runs |
//!
//! [`plugin_pull`] and [`plugin_upgrade`] return the backend's existing
//! [`FrameStream`] — the same type [`stats_stream`](super::stats_stream) returns,
//! read by the same [`FrameStream::next_json`] — rather than a new streaming type.
//! An install is a minutes-long operation whose progress is the answer, and
//! buffering it would mean holding the whole thing to show none of it.
//!
//! # A failure can arrive as a status *or* as a record inside a `200`
//!
//! This is the fact that decides the shape above, and it is not visible from the
//! endpoint name. The Engine's plugin handlers write progress through a
//! flush-on-write writer and then check it: a failure **before the first record**
//! becomes an HTTP error status, and a failure **after** the first record is
//! already a `200`, so it can only be reported as one more progress object. Both
//! cases were measured on Docker Engine 29.8.0 for `POST /plugins/pull`:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `POST /plugins/pull?remote=nonexistent/nope:latest` with `[]` | `500 {"message":"error resolving plugin reference: pull access denied, …"}` |
//! | `POST /plugins/ghost/upgrade?remote=…` | `404 {"message":"plugin \"ghost:latest\" not found"}` |
//!
//! Note that the pull failure's message is the *registry's* words and does not
//! repeat the reference this client sent, so a caller cannot match the error text
//! against the remote it asked for. That is the daemon's answer, preserved verbatim
//! rather than rewritten here.
//!
//! So [`plugin_pull`] checks the status and hands out the stream on success, and a
//! caller reading records must still treat a record carrying `errorDetail` as a
//! failure. That is why the frame stream is returned raw rather than wrapped in a
//! decoder that would have to make the same judgement: a caller that wants the
//! distinction can see it, and one that does not cannot have it made for it.
//!
//! The status is checked *before* the body is handed out, or a `404` whose body
//! happened to parse as a progress record would surface as an install stream.
//!
//! # `enable` requires its timeout and `disable` does not
//!
//! Measured against Docker Engine 29.8.0:
//!
//! | Request | Answer |
//! | --- | --- |
//! | `POST /plugins/ghost/enable` (no `timeout`) | `400 {"message":"strconv.Atoi: parsing \"\": invalid syntax"}` |
//! | `POST /plugins/ghost/enable?timeout=abc` | `400 {"message":"strconv.Atoi: parsing \"abc\": invalid syntax"}` |
//! | `POST /plugins/ghost/enable?timeout=0` | `404 {"message":"plugin \"ghost\" not found"}` |
//! | `POST /plugins/ghost/disable` (no `force`) | `404 {"message":"plugin \"ghost\" not found"}` |
//!
//! The Engine parses `timeout` with an unconditional `strconv.Atoi`, so an absent
//! `timeout` is a `400` rather than a default. That is why
//! [`PluginEnableOptions`](crate::PluginEnableOptions) has no "unset" state — its
//! `timeout_seconds` is not an `Option` — and why [`plugin_enable`] always sends
//! it. `force` on disable and remove has no such requirement and is sent only when
//! the caller set it, as `true` or `false`.
//!
//! # `privileges` is a `GET`, and a missing `remote` is a `400`
//!
//! Measured: `POST /plugins/privileges?remote=x` is answered `404 page not found`,
//! while `GET /plugins/privileges?remote=nonexistent/nope:latest` is `200` with an
//! array. [`plugin_privileges`] sends the `GET`. An empty or absent `remote` is
//! answered `400 {"message":"invalid reference format"}` — the same answer `POST
//! /plugins/pull` and `POST /plugins/{name}/upgrade` give without a `remote` — so
//! an empty remote is refused here before the socket rather than sent to be
//! rejected.
//!
//! # The privilege body is a bare JSON array, and a wrong shape is a `400`
//!
//! `POST /plugins/pull` and `POST /plugins/{name}/upgrade` read their body into the
//! Engine's `plugin.Privileges`, which is a list. Measured: a body of `{}` is
//! answered `400 {"message":"invalid JSON: json: cannot unmarshal object into Go
//! value of type plugin.Privileges"}`. An empty list is sent when the caller granted
//! nothing, because an absent body is a body the Engine's decoder rejects, whereas
//! `[]` is the request for "no privileges".
//!
//! Each privilege is the Engine's `{"Name":…,"Description":…,"Value":[…]}`; the
//! repository's [`PluginPrivilege`](crate::PluginPrivilege) spells the last member
//! `values`, and a `Value` member is what the daemon reads.
//!
//! # Plugin list filters are validated, unlike event filters
//!
//! Measured: `GET /plugins?filters={"nope":["x"]}` is answered `400 {"message":
//! "invalid filter 'nope'"}` on Docker Engine 29.8.0, where the same unknown key on
//! `GET /events` is accepted. The filter is sent as the caller wrote it in both
//! cases and the daemon's own rejection is reported.
//!
//! # What is deliberately not covered
//!
//! - **Registry authentication.** `POST /plugins/pull` and
//!   `POST /plugins/{name}/upgrade` read an `X-Registry-Auth` header. The
//!   repository's [`PluginInstallOptions`](crate::PluginInstallOptions) and
//!   [`PluginUpgradeOptions`](crate::PluginUpgradeOptions) carry no credential —
//!   the current facade takes one through separate `*_with_credentials` methods —
//!   so no such header is sent here rather than an empty one that would look like
//!   an attempt to pull with no credentials. A private-registry install is
//!   therefore a `500` from the daemon, which is the same answer a caller with no
//!   credentials gets today.
//! - **`POST /plugins/create` (a plugin from a local tar archive) and
//!   `POST /plugins/{name}/set`.** Both take a request body this module does not
//!   model: an opaque archive and a `KEY=VALUE` list respectively. The repository
//!   exposes them; the owned backend does not yet, and stating that is better than
//!   a wrapper whose body it cannot build.
//! - **`POST /plugins/{name}/push`.** It is a registry write with the same
//!   credential boundary as `pull`, for the same reason.
//! - **A plugin answer is smaller than the Engine's `Plugin` type, and that is the
//!   repository model's business.** The Engine sends `Config`, `Enabled`, `Id`,
//!   `Name`, `PluginReference`, and `Settings`, and `Config` alone carries fourteen
//!   declared members. The repository's
//!   [`PluginSummary`](crate::PluginSummary) names five. This module does not
//!   change that: the summary is the caller-facing shape both backends return, and
//!   narrowing or widening it is the facade's decision, not a wire concern. Unlike
//!   the network and disk-usage answers, no raw document is retained here, and a
//!   member with no field in the shared model is dropped on **both** paths — see
//!   the report for the exact count.

use std::collections::BTreeMap;

use hyper::Method;
use serde::{Deserialize, Serialize};

use super::containers::{Query, completed, escape_path_segment, with_query};
use super::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::raw::FrameStream;
use crate::{
    Error, PluginDisableOptions, PluginEnableOptions, PluginInstallOptions, PluginListOptions,
    PluginPrivilege, PluginRemoveOptions, PluginSummary, PluginUpgradeOptions,
};

/// Lists installed plugins.
///
/// `filters` is sent only when it is non-empty, for the reason the container slice
/// records: an empty filter object is a filter that matches the daemon's own
/// no-filter case and would only make a recorded request noisier. The answer is one
/// JSON array read as a single bounded document.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// reached, or when it rejects the request — a `400` carrying `invalid filter
/// '<key>'` for a filter key the Engine does not declare, measured.
pub async fn plugin_list(
    engine: &RawEngine,
    options: &PluginListOptions,
) -> Result<Vec<PluginSummary>, Error> {
    let response = engine.send(plugin_list_request(options)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<PluginDocument> = decode(&document)?;
    Ok(entries.into_iter().map(PluginSummary::from).collect())
}

/// Builds the `GET /plugins` list request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn plugin_list_request(options: &PluginListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/plugins"),
        query.finish(),
    ))
}

/// Reads one installed plugin.
///
/// The answer is one JSON object, so it is a bounded document read.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, when it rejects the request — a `404` carrying `plugin "<name>" not
/// found`, measured — or when the response is not a plugin document.
pub async fn plugin_inspect(engine: &RawEngine, plugin: &str) -> Result<PluginSummary, Error> {
    let response = engine.send(plugin_inspect_request(plugin)?).await?;
    let document = engine_result(response).await?;
    decode::<PluginDocument>(&document).map(PluginSummary::from)
}

/// Builds the `GET /plugins/{name}/json` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn plugin_inspect_request(plugin: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(Method::GET, &plugin_path(plugin, "/json")?))
}

/// Removes an installed plugin and returns what was removed.
///
/// The answer is the removed plugin's own document, not an empty body: the Engine
/// writes the plugin as it was at the moment of removal, which is the only place a
/// caller learns what has just gone. It is a bounded document read.
///
/// `force` is sent only when the caller set it, as `true` or `false`. An absent
/// `force` and a `false` one are the same request to the Engine, and neither is a
/// spelling the Engine reads differently, so the parameter is left off unless it
/// was asked for.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, when it rejects the request — a `404` for a plugin that is not
/// installed, measured — or when the response is not a plugin document.
pub async fn plugin_remove(
    engine: &RawEngine,
    plugin: &str,
    options: &PluginRemoveOptions,
) -> Result<PluginSummary, Error> {
    let response = engine
        .send(plugin_remove_request(plugin, *options)?)
        .await?;
    let document = engine_result(response).await?;
    decode::<PluginDocument>(&document).map(PluginSummary::from)
}

/// Builds the `DELETE /plugins/{name}` request.
///
/// The options are taken by value because the type is one `Option<bool>`; the
/// public operation still borrows so a caller can reuse its options afterwards.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn plugin_remove_request(plugin: &str, options: PluginRemoveOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(force) = options.force {
        query.flag("force", force);
    }
    Ok(with_query(
        RawRequest::new(Method::DELETE, &plugin_path(plugin, "")?),
        query.finish(),
    ))
}

/// Installs a remote plugin and returns its progress stream.
///
/// The answer is a stream: the Engine writes one JSON progress object per line for
/// as long as the install runs, and an install is a minutes-long operation. The
/// record reader is the existing [`FrameStream::next_json`], and dropping the
/// returned stream closes the connection — which is how a caller cancels an install
/// it no longer wants, with no cancel message to get wrong.
///
/// `remote` and the optional `name` travel in the query, because that is where the
/// Engine reads them; the granted privileges are the body. `name` is sent only when
/// the caller set one: an absent `name` asks the Engine to derive the local name
/// from the reference, and an empty `name=` is a request for a plugin literally
/// named nothing.
///
/// **A record carrying `errorDetail` is a failure, not progress.** The Engine
/// reports a failure that happens after the first record inside the `200` body
/// rather than as a status, so a caller reading records has to make that judgement.
/// See the module documentation for the measurement.
///
/// # Errors
///
/// Returns an error when no remote was named, when the privileges cannot be
/// encoded, when the daemon cannot be reached, or when it rejects the request
/// before writing anything — a `400 invalid reference format` for a missing or
/// unparsable `remote`, or a `500` carrying the registry's own message for one it
/// refuses, both measured.
pub async fn plugin_pull(
    engine: &RawEngine,
    options: &PluginInstallOptions,
) -> Result<FrameStream, Error> {
    open_progress(engine, plugin_pull_request(options)?).await
}

/// Builds the `POST /plugins/pull` request.
///
/// # Errors
///
/// Returns an error when no remote was named, or when the privilege body cannot be
/// encoded.
fn plugin_pull_request(options: &PluginInstallOptions) -> Result<RawRequest, Error> {
    if options.remote.trim().is_empty() {
        return Err(Error::invalid_input(
            "installing a plugin needs the remote reference to install from",
        ));
    }
    let mut query = Query::default();
    query.value("remote", &options.remote);
    if let Some(name) = &options.name {
        query.value("name", name);
    }
    let request = json_content_type(RawRequest::new(Method::POST, "/plugins/pull"))
        .with_body(json_body(&privilege_body(&options.privileges))?);
    Ok(with_query(request, query.finish()))
}

/// Upgrades an installed plugin and returns its progress stream.
///
/// The answer is a stream for the same reason [`plugin_pull`]'s is: the Engine
/// writes one JSON progress object per line through the same flush-on-write writer
/// and checks it afterwards, so a failure after the first record is reported inside
/// a `200` body as an `errorDetail` record. The record reader is the existing
/// [`FrameStream::next_json`], and dropping the stream closes the connection.
///
/// `remote` travels in the query and the granted privileges are the body. There is
/// no `name` parameter on this endpoint: the plugin to upgrade is the path
/// segment, which is why the reference is escaped into exactly one.
///
/// **The current transport cannot see this stream at all.** The pinned
/// `bollard::Docker::upgrade_plugin` is declared to return `Result<(), Error>` and
/// reaches the response through a "unit" decoder, so a caller of that path observes
/// neither the progress nor the in-band `errorDetail` failure. The endpoint's
/// answer is a stream, and this is one more place where the endpoint name is not
/// the answer's shape.
///
/// # Errors
///
/// Returns an error when the reference or the remote is empty, when the privilege
/// body cannot be encoded, when the daemon cannot be reached, or when it rejects
/// the request before writing anything — a `404` carrying `plugin "<name>" not
/// found` for a plugin that is not installed, or a `400 invalid reference format`
/// for a missing `remote`, both measured.
pub async fn plugin_upgrade(
    engine: &RawEngine,
    plugin: &str,
    options: &PluginUpgradeOptions,
) -> Result<FrameStream, Error> {
    open_progress(engine, plugin_upgrade_request(plugin, options)?).await
}

/// Builds the `POST /plugins/{name}/upgrade` request.
///
/// # Errors
///
/// Returns an error when the reference is empty, when no remote was named, or when
/// the privilege body cannot be encoded.
fn plugin_upgrade_request(
    plugin: &str,
    options: &PluginUpgradeOptions,
) -> Result<RawRequest, Error> {
    if options.remote.trim().is_empty() {
        return Err(Error::invalid_input(
            "upgrading a plugin needs the remote reference to upgrade to",
        ));
    }
    let mut query = Query::default();
    query.value("remote", &options.remote);
    let request = json_content_type(RawRequest::new(
        Method::POST,
        &plugin_path(plugin, "/upgrade")?,
    ))
    .with_body(json_body(&privilege_body(&options.privileges))?);
    Ok(with_query(request, query.finish()))
}

/// Enables an installed plugin.
///
/// Answers `200` with an empty body, so the status is the whole result and the body
/// is read and discarded rather than decoded. `timeout` is always sent: the Engine
/// parses it with an unconditional `strconv.Atoi`, so an absent `timeout` is a `400`
/// rather than a default. That is measured, and it is why the repository's
/// [`PluginEnableOptions`] has no unset state.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request — a `404` for a plugin that is not
/// installed, or a `400` for a `timeout` that is not a number, both measured.
pub async fn plugin_enable(
    engine: &RawEngine,
    plugin: &str,
    options: &PluginEnableOptions,
) -> Result<(), Error> {
    completed(engine, plugin_enable_request(plugin, *options)?).await
}

/// Builds the `POST /plugins/{name}/enable` request.
///
/// The options are taken by value because the type is one `i32`; the public
/// operation still borrows so a caller can reuse its options afterwards.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn plugin_enable_request(plugin: &str, options: PluginEnableOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("timeout", &options.timeout_seconds.to_string());
    Ok(with_query(
        RawRequest::new(Method::POST, &plugin_path(plugin, "/enable")?),
        query.finish(),
    ))
}

/// Disables an installed plugin.
///
/// Answers `200` with an empty body, so the status is the whole result. `force` is
/// sent only when the caller set it, as `true` or `false`; the Engine's disable
/// handler reads `force` with a defaulted boolean, so an absent parameter is a
/// plain disable rather than an error.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request — a `404` for a plugin that is not
/// installed, or a `500` for a plugin that is in use, measured for the first.
pub async fn plugin_disable(
    engine: &RawEngine,
    plugin: &str,
    options: &PluginDisableOptions,
) -> Result<(), Error> {
    completed(engine, plugin_disable_request(plugin, *options)?).await
}

/// Builds the `POST /plugins/{name}/disable` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn plugin_disable_request(
    plugin: &str,
    options: PluginDisableOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(force) = options.force {
        query.flag("force", force);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &plugin_path(plugin, "/disable")?),
        query.finish(),
    ))
}

/// Reads the privileges a remote plugin requires.
///
/// The answer is one JSON array, so it is a bounded document read.
///
/// An empty `remote` is refused before the socket: the Engine answers
/// `400 {"message":"invalid reference format"}`, so there is nothing a request
/// without one can accomplish. This is the only plugin read that takes its subject
/// in the query rather than the path, and it is a `GET` — a `POST` to the same path
/// is answered `404 page not found`, measured.
///
/// # Errors
///
/// Returns an error when no remote was named, when the daemon cannot be reached,
/// when it rejects the request, or when the response is not a privilege array.
pub async fn plugin_privileges(
    engine: &RawEngine,
    remote: &str,
) -> Result<Vec<PluginPrivilege>, Error> {
    let response = engine.send(plugin_privileges_request(remote)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<PrivilegeDocument> = decode(&document)?;
    Ok(entries.into_iter().map(PluginPrivilege::from).collect())
}

/// Builds the `GET /plugins/privileges` request.
///
/// # Errors
///
/// Returns an error when no remote was named.
fn plugin_privileges_request(remote: &str) -> Result<RawRequest, Error> {
    if remote.trim().is_empty() {
        return Err(Error::invalid_input(
            "reading a plugin's privileges needs the remote reference to read them for",
        ));
    }
    let mut query = Query::default();
    query.value("remote", remote);
    Ok(with_query(
        RawRequest::new(Method::GET, "/plugins/privileges"),
        query.finish(),
    ))
}

/// Sends a progress request and hands back the frame stream.
///
/// The status is checked before the body is handed out, or a `404` whose body
/// happened to parse as a progress record would surface as an install stream.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, carrying the status and the daemon's own message.
async fn open_progress(engine: &RawEngine, request: RawRequest) -> Result<FrameStream, Error> {
    let response = engine.send(request).await?;
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(response.into_frames())
}

/// Builds the `/plugins/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/plugins//enable` is not a request for
/// a plugin, and sending it would ask the daemon about a resource the caller never
/// named. The reference is percent-encoded into exactly one segment, so a name
/// containing `/` cannot address a different resource.
fn plugin_path(plugin: &str, suffix: &str) -> Result<String, Error> {
    if plugin.is_empty() {
        return Err(Error::invalid_input(
            "the Engine plugin reference must not be empty",
        ));
    }
    Ok(format!("/plugins/{}{suffix}", escape_path_segment(plugin)))
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The map is a `BTreeMap`, so the JSON is in key order and a recorded request is
/// reproducible between runs. The current facade converts the same map into a
/// `HashMap` first, so its key order varies.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine plugin filters: {error}"
        ))
    })
}

/// The privilege list body of a pull or an upgrade, in the Engine's spelling.
///
/// The Engine reads this into a list, so the body is a bare JSON array and an empty
/// grant is `[]` rather than an absent or `null` body: a body of `{}` is answered
/// `400 invalid JSON: json: cannot unmarshal object into Go value of type
/// plugin.Privileges`, measured.
#[derive(Debug, Serialize)]
struct PrivilegeBody<'a> {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(rename = "Description", skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(rename = "Value")]
    values: &'a [String],
}

/// Projects the repository's privileges onto the Engine's list.
///
/// The result is a `Vec` rather than a wrapper type so that it serializes as the
/// bare JSON array the Engine's decoder requires, including as `[]` when nothing was
/// granted.
fn privilege_body(privileges: &[PluginPrivilege]) -> Vec<PrivilegeBody<'_>> {
    privileges
        .iter()
        .map(|privilege| PrivilegeBody {
            name: privilege.name.as_deref(),
            description: privilege.description.as_deref(),
            values: &privilege.values,
        })
        .collect()
}

/// One privilege of a `GET /plugins/privileges` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct PrivilegeDocument {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The Engine omits `Value` for a privilege that grants nothing, and an absent
    // member is an empty grant rather than an unknown one.
    #[serde(default, rename = "Value")]
    values: Option<Vec<String>>,
}

impl From<PrivilegeDocument> for PluginPrivilege {
    fn from(document: PrivilegeDocument) -> Self {
        Self {
            name: document.name,
            description: document.description,
            values: document.values.unwrap_or_default(),
        }
    }
}

/// One installed plugin as the Engine sends it, in the Engine's spelling.
///
/// This is the private wire boundary, and it is deliberately a *partial* projection
/// of the Engine's `Plugin` type: the Engine sends `Config`, `Enabled`, `Id`,
/// `Name`, `PluginReference`, and `Settings`, and this names the five the
/// repository's [`PluginSummary`] carries. `Config.Description` is the plugin's
/// description and lives inside the `Config` object rather than beside it, which is
/// the one nesting a flat rename cannot express.
///
/// The members not named here are dropped on this path exactly as they are on the
/// current facade's, because both project into the same repository model. Decoding
/// the whole `Config` block into a type the repository does not have would be a
/// parallel plugin model, which is the one thing this backend does not add.
#[derive(Debug, Deserialize)]
struct PluginDocument {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    // The Engine sends `Enabled` as a bare boolean rather than omitting it, so a
    // `false` is "installed but not running" and not "the daemon did not say".
    #[serde(default, rename = "Enabled")]
    enabled: bool,
    #[serde(rename = "PluginReference")]
    plugin_reference: Option<String>,
    // `#[serde(default)]` covers an absent `Config` but not an explicit `null`, and
    // a `null` in place of the block is how a daemon reports a plugin with no
    // config, so the member reads a null as the empty block.
    #[serde(
        default,
        rename = "Config",
        deserialize_with = "null_as_default_config"
    )]
    config: PluginConfigDocument,
}

/// Reads a `Config` block the Engine may send as `null` as the empty block.
///
/// A `null` is a plugin with no description, not a missing answer, so it decodes to
/// the empty block rather than failing the whole document.
fn null_as_default_config<'de, D>(deserializer: D) -> Result<PluginConfigDocument, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<PluginConfigDocument>::deserialize(deserializer)?.unwrap_or_default())
}

/// The `Config` block of a plugin document, in the Engine's spelling.
#[derive(Debug, Default, Deserialize)]
struct PluginConfigDocument {
    #[serde(default, rename = "Description")]
    description: String,
}

impl From<PluginDocument> for PluginSummary {
    fn from(document: PluginDocument) -> Self {
        Self {
            id: document.id,
            name: document.name,
            enabled: document.enabled,
            description: document.config.description,
            plugin_reference: document.plugin_reference,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        PluginDocument, PrivilegeDocument, plugin_disable_request, plugin_enable_request,
        plugin_inspect_request, plugin_list_request, plugin_privileges_request,
        plugin_pull_request, plugin_remove_request, plugin_upgrade_request,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, PluginDisableOptions, PluginEnableOptions, PluginInstallOptions,
        PluginListOptions, PluginPrivilege, PluginRemoveOptions, PluginUpgradeOptions,
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
            ("capability".to_owned(), vec!["volumedriver".to_owned()]),
            ("enabled".to_owned(), vec!["true".to_owned()]),
        ])
    }

    fn privileges() -> Vec<PluginPrivilege> {
        vec![
            PluginPrivilege {
                name: Some("network".to_owned()),
                description: Some("Allow access to host network".to_owned()),
                values: vec!["host".to_owned()],
            },
            PluginPrivilege {
                name: Some("mount".to_owned()),
                description: Some("Allow local mounts".to_owned()),
                values: Vec::new(),
            },
        ]
    }

    /// A plugin document shaped like the Engine's, with the members the repository
    /// model names plus the ones it does not.
    const PLUGIN_BODY: &[u8] = br#"{
        "Id":"9df1a2b3c4d5",
        "Name":"vieux/sshfs:latest",
        "Enabled":true,
        "PluginReference":"vieux/sshfs:latest",
        "Settings":{"Mounts":[],"Env":[],"Args":{}},
        "Config":{
            "Description":"Slow SSHFS",
            "Documentation":"https://docs.example/sshfs",
            "Interface":{"Types":["docker.volumedriver/1.0"],"Socket":"sshfs.sock"},
            "Entrypoint":["/usr/bin/sshfs"],
            "WorkDir":"/home",
            "Env":[],"Args":{"Name":"..."},"Mounts":[],"Network":{"Type":"host"},
            "Linux":{"Capabilities":["CAP_SYS_ADMIN"]},
            "PropagatedMount":"/dev","IpcHost":false,"PidHost":false,
            "DockerVersion":"29.8.0","rootfs":{"type":"layers"}
        }
    }"#;

    #[test]
    fn list_sends_the_versioned_path_and_its_filters() {
        let request =
            plugin_list_request(&PluginListOptions { filters: filters() }).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/plugins?filters=%7B%22capability%22%3A%5B%22volumedriver%22%5D%2C%22enabled%22%3A%5B%22true%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_empty_filter_map_is_not_sent_at_all() {
        let request = plugin_list_request(&PluginListOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/plugins HTTP/1.1")
        );
    }

    #[test]
    fn filter_keys_are_emitted_in_order_so_a_recorded_request_is_reproducible() {
        // The current facade converts the ordered map to a `HashMap` first, so its
        // recorded order varies between runs of the same command.
        let request =
            plugin_list_request(&PluginListOptions { filters: filters() }).expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        assert!(
            value.find("%22capability%22").expect("capability")
                < value.find("%22enabled%22").expect("enabled")
        );
    }

    #[test]
    fn inspect_sends_the_json_suffix_the_engine_serves() {
        let request = plugin_inspect_request("vieux/sshfs:latest").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/plugins/vieux%2Fsshfs%3Alatest/json HTTP/1.1")
        );
        assert_eq!(request.query, None);
    }

    #[test]
    fn remove_sends_force_only_when_the_caller_set_it() {
        // An absent `force` and a `false` one are the same request to the Engine, and
        // the Engine reads both the same way, so the parameter is left off unless it
        // was asked for.
        let plain =
            plugin_remove_request("ghost", PluginRemoveOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("DELETE /v1.API/plugins/ghost HTTP/1.1")
        );
        let forced = plugin_remove_request("ghost", PluginRemoveOptions { force: Some(true) })
            .expect("request");
        assert_eq!(
            request_line(&forced),
            crate::raw::at_api_version("DELETE /v1.API/plugins/ghost?force=true HTTP/1.1")
        );
        let false_ = plugin_remove_request("ghost", PluginRemoveOptions { force: Some(false) })
            .expect("request");
        assert_eq!(
            request_line(&false_),
            crate::raw::at_api_version("DELETE /v1.API/plugins/ghost?force=false HTTP/1.1")
        );
    }

    #[test]
    fn enable_always_sends_its_timeout() {
        // The Engine parses `timeout` with an unconditional `strconv.Atoi`, so an
        // absent `timeout` is `400 strconv.Atoi: parsing "": invalid syntax`, measured.
        // That is why the repository's enable options have no unset state.
        let request = plugin_enable_request("ghost", PluginEnableOptions::new(0)).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/plugins/ghost/enable?timeout=0 HTTP/1.1")
        );
        let timed = plugin_enable_request("ghost", PluginEnableOptions::new(30)).expect("request");
        assert_eq!(
            request_line(&timed),
            crate::raw::at_api_version("POST /v1.API/plugins/ghost/enable?timeout=30 HTTP/1.1")
        );
    }

    #[test]
    fn disable_sends_force_only_when_the_caller_set_it() {
        let plain =
            plugin_disable_request("ghost", PluginDisableOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/plugins/ghost/disable HTTP/1.1")
        );
        let forced = plugin_disable_request("ghost", PluginDisableOptions { force: Some(true) })
            .expect("request");
        assert_eq!(
            request_line(&forced),
            crate::raw::at_api_version("POST /v1.API/plugins/ghost/disable?force=true HTTP/1.1")
        );
    }

    #[test]
    fn privileges_is_a_get_with_the_remote_in_the_query() {
        // Measured: `POST /plugins/privileges?remote=x` is `404 page not found`,
        // while the `GET` is `200`.
        let request = plugin_privileges_request("vieux/sshfs:latest").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/plugins/privileges?remote=vieux%2Fsshfs%3Alatest HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_empty_remote_is_refused_before_the_socket() {
        // The Engine answers `400 invalid reference format` for an empty or absent
        // `remote` on privileges, pull, and upgrade alike, so there is nothing a
        // request without one can accomplish.
        assert_eq!(
            plugin_privileges_request("")
                .expect_err("empty remote")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            plugin_pull_request(&PluginInstallOptions::new("  "))
                .expect_err("blank remote")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            plugin_upgrade_request("ghost", &PluginUpgradeOptions::new(""))
                .expect_err("empty remote")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn pull_sends_the_remote_and_name_in_the_query_and_the_privileges_as_a_body() {
        let request = plugin_pull_request(&PluginInstallOptions {
            remote: "vieux/sshfs:latest".to_owned(),
            name: Some("my-sshfs".to_owned()),
            privileges: privileges(),
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/plugins/pull?remote=vieux%2Fsshfs%3Alatest&name=my-sshfs HTTP/1.1"
            )
        );
        let body = request_body(&request);
        assert_eq!(body.as_array().expect("a JSON array").len(), 2);
        assert_eq!(body[0]["Name"], "network");
        assert_eq!(body[0]["Description"], "Allow access to host network");
        // The Engine's member is `Value`; the repository's field is `values`.
        assert_eq!(body[0]["Value"][0], "host");
        assert!(body[0].get("Values").is_none(), "{body}");
        assert_eq!(body[1]["Name"], "mount");
        assert_eq!(body[1]["Value"], serde_json::json!([]));
    }

    #[test]
    fn a_pull_with_no_privileges_sends_an_empty_array_rather_than_no_body() {
        // The Engine reads the body into a list, and a body of `{}` is answered
        // `400 invalid JSON: json: cannot unmarshal object into Go value of type
        // plugin.Privileges`. `[]` is the request for "no privileges granted".
        let request =
            plugin_pull_request(&PluginInstallOptions::new("vieux/sshfs:latest")).expect("request");
        assert_eq!(request_body(&request), serde_json::json!([]));
        assert!(matches!(request.body, RawBody::Bytes(_)));
    }

    #[test]
    fn a_pull_with_no_local_name_leaves_the_name_out() {
        // An absent `name` asks the Engine to derive the local name from the
        // reference; an empty `name=` is a request for a plugin named nothing.
        let request =
            plugin_pull_request(&PluginInstallOptions::new("vieux/sshfs:latest")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/plugins/pull?remote=vieux%2Fsshfs%3Alatest HTTP/1.1"
            )
        );
        assert!(!request.query.expect("a query").contains("name="));
    }

    #[test]
    fn upgrade_names_the_plugin_in_the_path_and_the_remote_in_the_query() {
        // There is no `name` parameter on this endpoint: the plugin is the path
        // segment.
        let request = plugin_upgrade_request(
            "vieux/sshfs",
            &PluginUpgradeOptions {
                remote: "vieux/sshfs:latest".to_owned(),
                privileges: privileges(),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/plugins/vieux%2Fsshfs/upgrade?remote=vieux%2Fsshfs%3Alatest HTTP/1.1"
            )
        );
        assert_eq!(
            request_body(&request).as_array().expect("an array").len(),
            2
        );
    }

    #[test]
    fn a_pull_and_an_upgrade_carry_no_registry_auth_header() {
        // The repository's install and upgrade options carry no credential, and an
        // empty `X-Registry-Auth` would look like an attempt to pull with no
        // credentials. The header is absent rather than empty.
        for request in [
            plugin_pull_request(&PluginInstallOptions::new("vieux/sshfs:latest")).expect("request"),
            plugin_upgrade_request(
                "vieux/sshfs",
                &PluginUpgradeOptions::new("vieux/sshfs:latest"),
            )
            .expect("request"),
        ] {
            assert!(
                request.headers.get("x-registry-auth").is_none(),
                "{:?}",
                request.headers
            );
        }
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        for error in [
            plugin_inspect_request("").expect_err("empty reference"),
            plugin_remove_request("", PluginRemoveOptions::default()).expect_err("empty reference"),
            plugin_enable_request("", PluginEnableOptions::new(0)).expect_err("empty reference"),
            plugin_disable_request("", PluginDisableOptions::default())
                .expect_err("empty reference"),
            plugin_upgrade_request("", &PluginUpgradeOptions::new("r"))
                .expect_err("empty reference"),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_reference_cannot_reshape_the_plugin_path() {
        // `/plugins/a/b/enable` is a different resource rather than an enable of a
        // plugin whose name contains a slash.
        let request = plugin_enable_request("a/b", PluginEnableOptions::new(0)).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/plugins/a%2Fb/enable?timeout=0 HTTP/1.1")
        );
    }

    #[test]
    fn the_summary_reads_the_description_out_of_the_config_object() {
        // `Config.Description` is the plugin's description and lives inside the
        // `Config` object, which is the one nesting a flat rename cannot express.
        let document: PluginDocument =
            super::super::decode(PLUGIN_BODY).expect("a plugin document");
        let summary = crate::PluginSummary::from(document);
        assert_eq!(summary.id.as_deref(), Some("9df1a2b3c4d5"));
        assert_eq!(summary.name, "vieux/sshfs:latest");
        assert!(summary.enabled);
        assert_eq!(summary.description, "Slow SSHFS");
        assert_eq!(
            summary.plugin_reference.as_deref(),
            Some("vieux/sshfs:latest")
        );
    }

    #[test]
    fn a_disabled_plugin_reports_enabled_false_rather_than_unknown() {
        // The Engine sends `Enabled` as a bare boolean rather than omitting it, so a
        // `false` is "installed but not running" and not "the daemon did not say".
        let document: PluginDocument =
            super::super::decode(br#"{"Name":"p","Enabled":false,"Config":{"Description":"d"}}"#)
                .expect("a plugin document");
        let summary = crate::PluginSummary::from(document);
        assert!(!summary.enabled);
        assert_eq!(summary.id, None);
        assert_eq!(summary.plugin_reference, None);
    }

    #[test]
    fn a_plugin_with_no_config_still_decodes() {
        // A `null` in place of a block is how a member appears when the daemon has
        // nothing to report, and it must not be a decode failure.
        let document: PluginDocument =
            super::super::decode(br#"{"Name":"p","Enabled":true,"Config":null}"#)
                .expect("a plugin document");
        let summary = crate::PluginSummary::from(document);
        assert_eq!(summary.name, "p");
        assert_eq!(summary.description, "");
    }

    #[test]
    fn a_privilege_reads_its_values_out_of_the_value_member() {
        // The Engine omits `Value` for a privilege that grants nothing, and an
        // absent member is an empty grant rather than an unknown one.
        let documents: Vec<PrivilegeDocument> = super::super::decode(
            br#"[{"Name":"network","Description":"Allow access to host network","Value":["host"]},
                {"Name":"mount","Description":"Allow local mounts"},
                {"Name":"device","Description":"Allow device access","Value":null}]"#,
        )
        .expect("a privilege array");
        let entries: Vec<PluginPrivilege> = documents.into_iter().map(Into::into).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name.as_deref(), Some("network"));
        assert_eq!(entries[0].values, vec!["host".to_owned()]);
        assert_eq!(
            entries[0].description.as_deref(),
            Some("Allow access to host network")
        );
        assert!(entries[1].values.is_empty());
        assert!(entries[2].values.is_empty());
    }

    #[test]
    fn the_document_limit_still_bounds_a_plugin_list() {
        // The bound is a property of the transport, so what is asserted here is that
        // the document-shaped operations read through it. The two streaming ones do
        // not: they hand out the frame stream, which buffers one record.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        for request in [
            plugin_list_request(&PluginListOptions::default()).expect("request"),
            plugin_privileges_request("vieux/sshfs:latest").expect("request"),
        ] {
            assert!(
                request.body.known_len().is_some(),
                "no request body is sent"
            );
        }
    }
}
