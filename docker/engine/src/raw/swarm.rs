//! Swarm operations on the repository-owned Engine backend.
//!
//! This is step 5 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`, and it is the step that exists
//! for a measured reason rather than for tidiness: **the current transport
//! cannot carry a Swarm service's `Placement` or `RestartPolicy` at all.**
//!
//! # The blocker this module removes
//!
//! `bollard::models::ServiceSpec` in the pinned `bollard = "=0.21.1"` has eight
//! members — `name`, `labels`, `task_template`, `mode`, `endpoint_spec`,
//! `networks`, `update_config`, `rollback_config` — and no `placement` and no
//! `restart_policy`. A `Serialize` -> `DeserializeOwned` round trip into that
//! struct therefore discards both, with no error: serde ignores members the
//! target does not name. There is no way around it from outside the crate
//! either, because `build_request`, `process_request`, and `serialize_payload`
//! are all `pub(crate)`, so no untyped request path is reachable at all. A
//! `deploy.placement.constraints: [node.role == worker]` and a
//! `deploy.restart_policy` are simply not expressible.
//!
//! [`service_create`] sends the repository-owned
//! [`ServiceSpec`](crate::ServiceSpec) member for member, with no generated
//! struct in the path, so both reach the daemon. The contrast is measured rather
//! than asserted about: one test sends the *same* specification through both
//! paths and checks that the owned body carries `Placement` and `RestartPolicy`
//! while the dependency's own serialization of that value carries neither.
//!
//! # What is covered
//!
//! - The cluster: `swarm_init`, `swarm_join`, `swarm_leave`, `swarm_inspect`,
//!   `swarm_update`, `swarm_unlock`, `swarm_unlock_key`, `swarm_certificates`,
//!   and `swarm_join_token`.
//! - Services: `service_list`, `service_create`, `service_inspect`,
//!   `service_update`, `service_remove`, `service_logs`.
//! - Nodes: `node_list`, `node_inspect`, `node_update`, `node_remove`.
//! - Tasks: `task_list`, `task_inspect`, `task_logs`.
//! - Configs: `config_list`, `config_create`, `config_inspect`,
//!   `config_update`, `config_remove`.
//! - Secrets: `secret_list`, `secret_create`, `secret_inspect`,
//!   `secret_update`, `secret_remove`.
//!
//! The names are prefixed by resource because they share the `raw` namespace
//! with the container slice's `list`, `create`, and `remove`.
//!
//! # What is deliberately not covered
//!
//! - **Registry authentication for `POST /services/create`.** The Engine reads
//!   it from an `X-Registry-Auth` header. The repository's service-create input
//!   is a bare [`ServiceSpec`](crate::ServiceSpec) and carries no credential, so
//!   this module sends no such header rather than sending an empty one that
//!   would look like an attempt to pull with no credentials.
//! - **The v1.53 `SwarmInitRequest` members the option type does not name**:
//!   `Labels`, `AutoLockManagers`, `DefaultAddrPool`, and `SubnetSize`.
//!   [`SwarmInitOptions`](crate::SwarmInitOptions) has five members, and adding
//!   more would mean the Bollard-backed facade silently ignored them, which is
//!   the exact failure this work exists to remove. They are stated here instead.
//! - **`GET /swarm/cert` on a current daemon.** The endpoint is absent from the
//!   Engine's API specification as of v1.35, and a v29.8 daemon answers
//!   `404 page not found` for it. [`swarm_certificates`] exists because the
//!   repository already exposes the material, not because the endpoint is
//!   dependable; a `404` is reported as the daemon's own rejection.
//! - **Key material generation.** `swarm_update` sends the three rotation flags
//!   the Engine declares. Nothing here mints a key.
//!
//! # Conflict safety is the daemon's, not this module's
//!
//! Every update carries the caller's `version` as the Engine declares it, and a
//! stale version stays the daemon's `409 Conflict`. Nothing here retries: a
//! second writer's changes are not overwritten by a retry that usually works.
//! The Engine declares the parameter as `int32` for a service and `int64` for
//! the others, and both conversions are done here rather than truncating one
//! into the other.
//!
//! # A member a typed field cannot hold is retained, never dropped
//!
//! The repository models are caller-facing, so a few of them cannot express
//! every member the Engine sends. Two of those gaps are structural. The Engine's
//! `Placement.Preferences` is a list of objects —
//! `[{"Spread":{"SpreadDescriptor":"node.labels.zone"}}]` — and not the list of
//! strings a Compose `deploy:` block writes; and `Placement.Platforms` has no
//! counterpart at all. A silently dropped constraint is a *safety* difference,
//! not a formatting one, so this module uses one convention for it: **a member
//! of a typed sub-object that the type cannot express is retained in the
//! enclosing model's `additional` map under the key `"<SubObject>.<Member>"`.**
//!
//! The Engine spells no member with a dot in it, so such a key can never collide
//! with a real member, and it never duplicates a key the typed fields already
//! emit — which is what would happen if the whole sub-object were copied
//! alongside the typed field. [`service_spec_body`] reads those keys back out
//! and merges them into the `Placement` object it sends, so a specification that
//! came from an inspect re-sends what the daemon sent.
//!
//! A whole sub-object that has no typed field at all — a service's `Endpoint`, a
//! node's `Description`, a task's `Spec` — is retained verbatim under its own
//! Engine name, which covers its members with no special case. That is also why
//! a service's published ports survive intact: `ServicePort` has no field for
//! `PortConfig.Name`, but the `Endpoint` those ports came from is still there.
//!
//! # The wire models are private to this module
//!
//! The `*Document` types below are the only wire-shaped values here, for the
//! reason `raw::containers` gives: the public models are ordered for callers,
//! and a few of them differ from the Engine's spelling, so decoding an Engine
//! answer straight into one of them is what loses members. They are not the
//! dependency's generated models — importing those would tie the escape path
//! back to the crate it exists to leave.
//!
//! Every option, result, and specification type is the existing repository-owned
//! model, reused as it is. This module adds no parallel Swarm model, so a caller
//! that moves between the two backends moves between the same types.

use std::collections::{BTreeMap, VecDeque};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::Method;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::raw::body::FrameStream;
use crate::raw::containers::{Query, with_query};
use crate::raw::logs::{LogDecoder, LogFrame};
use crate::raw::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::swarm::{
    ConfigCreateOptions, ConfigUpdateOptions, NodeManagerStatus, NodeRemoveOptions, NodeSpec,
    NodeUpdateOptions, SecretCreateOptions, SecretUpdateOptions, ServiceCreateResult,
    ServicePlacement, ServicePort, ServiceRestartPolicy, ServiceSpec, ServiceStatus,
    ServiceUpdateOptions, ServiceUpdateResult, SwarmCertificates, SwarmConfig, SwarmConfigSpec,
    SwarmInfo, SwarmInitOptions, SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions,
    SwarmListOptions, SwarmLogOptions, SwarmNode, SwarmSecret, SwarmSecretSpec, SwarmService,
    SwarmTask, SwarmTaskStatus, SwarmUnlockKey, SwarmUnlockOptions, SwarmUpdateOptions,
    SwarmVersion, checked_i32, checked_i64,
};

/// Initializes a Swarm on this node and returns the manager node ID.
///
/// `POST /swarm/init` answers `200` with a JSON string, `"nodeid"`, rather than
/// with an object, so the answer is decoded as the string it is and returned as
/// one.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a node that is already in a Swarm answers `500` or `503` here — or
/// when the answer is not a node ID.
pub async fn swarm_init(engine: &RawEngine, options: &SwarmInitOptions) -> Result<String, Error> {
    let response = engine.send(init_request(options)).await?;
    let document = engine_result(response).await?;
    decode::<String>(&document)
}

/// Builds the `POST /swarm/init` request.
fn init_request(options: &SwarmInitOptions) -> RawRequest {
    let body = json_body(&InitDocument {
        listen_address: options.listen_address.as_deref(),
        advertise_address: options.advertise_address.as_deref(),
        data_path_address: options.data_path_address.as_deref(),
        data_path_port: options.data_path_port,
        force_new_cluster: options.force_new_cluster,
    })
    .expect("a document of owned strings always encodes");
    json_content_type(RawRequest::new(Method::POST, "/swarm/init")).with_body(body)
}

/// The `POST /swarm/init` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct InitDocument<'a> {
    #[serde(rename = "ListenAddr", skip_serializing_if = "Option::is_none")]
    listen_address: Option<&'a str>,
    #[serde(rename = "AdvertiseAddr", skip_serializing_if = "Option::is_none")]
    advertise_address: Option<&'a str>,
    #[serde(rename = "DataPathAddr", skip_serializing_if = "Option::is_none")]
    data_path_address: Option<&'a str>,
    #[serde(rename = "DataPathPort", skip_serializing_if = "Option::is_none")]
    data_path_port: Option<u32>,
    #[serde(rename = "ForceNewCluster", skip_serializing_if = "Option::is_none")]
    force_new_cluster: Option<bool>,
}

/// Joins this node to an existing Swarm.
///
/// # Errors
///
/// Returns an error when no manager address was given — a join with nothing to
/// reach is refused here rather than sent for the daemon to reject — or when the
/// daemon cannot be reached or rejects the request.
pub async fn swarm_join(engine: &RawEngine, options: &SwarmJoinOptions) -> Result<(), Error> {
    completed(engine, join_request(options)?).await
}

/// Builds the `POST /swarm/join` request.
///
/// # Errors
///
/// Returns an error when the caller named no manager address.
fn join_request(options: &SwarmJoinOptions) -> Result<RawRequest, Error> {
    if options.remote_addresses.is_empty() {
        return Err(Error::invalid_input(
            "joining a Swarm needs at least one manager address to reach",
        ));
    }
    let body = json_body(&JoinDocument {
        listen_address: options.listen_address.as_deref(),
        advertise_address: options.advertise_address.as_deref(),
        data_path_address: options.data_path_address.as_deref(),
        remote_addresses: &options.remote_addresses,
        token: &options.token,
    })?;
    Ok(json_content_type(RawRequest::new(Method::POST, "/swarm/join")).with_body(body))
}

/// The `POST /swarm/join` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct JoinDocument<'a> {
    #[serde(rename = "ListenAddr", skip_serializing_if = "Option::is_none")]
    listen_address: Option<&'a str>,
    #[serde(rename = "AdvertiseAddr", skip_serializing_if = "Option::is_none")]
    advertise_address: Option<&'a str>,
    #[serde(rename = "DataPathAddr", skip_serializing_if = "Option::is_none")]
    data_path_address: Option<&'a str>,
    // Sent always, and never as an empty array: there is no manager to ask
    // otherwise, and an empty `RemoteAddrs` is a join request that cannot
    // succeed. `join_request` refuses the input before this is reached.
    #[serde(rename = "RemoteAddrs")]
    remote_addresses: &'a [String],
    #[serde(rename = "JoinToken")]
    token: &'a str,
}

/// Leaves the Swarm this node belongs to.
///
/// `force` is always spelled, so a recorded request says whether leaving a
/// manager was part of it. The dependency sends the parameter only when it is
/// true, which makes a recorded `POST /swarm/leave` ambiguous between "not
/// forced" and "not sent".
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request.
pub async fn swarm_leave(engine: &RawEngine, options: &SwarmLeaveOptions) -> Result<(), Error> {
    completed(engine, leave_request(*options)).await
}

/// Builds the `POST /swarm/leave` request.
///
/// The options are taken by value for the reason [`node_remove_request`] gives.
fn leave_request(options: SwarmLeaveOptions) -> RawRequest {
    let mut query = Query::default();
    query.flag("force", options.force);
    with_query(
        RawRequest::new(Method::POST, "/swarm/leave"),
        query.finish(),
    )
}

/// Reads the active Swarm.
///
/// `GET /swarm` is also the only endpoint that reports join tokens, so this is
/// the read behind [`swarm_join_token`] and behind
/// [`SwarmInfo::trust_root`](crate::SwarmInfo::trust_root).
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a Swarm document.
pub async fn swarm_inspect(engine: &RawEngine) -> Result<SwarmInfo, Error> {
    let response = engine.send(swarm_inspect_request()).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /swarm` request.
fn swarm_inspect_request() -> RawRequest {
    RawRequest::new(Method::GET, "/swarm")
}

/// Updates the Swarm at an explicit expected version.
///
/// The three rotation flags are always spelled, for the reason given on
/// [`swarm_leave`], and `version` is converted to the `int64` the Engine
/// declares for this endpoint.
///
/// # Errors
///
/// Returns an error when the version does not fit the Engine's `int64`, when the
/// specification cannot be encoded, or when the daemon rejects the request. A
/// stale version stays a `409 Conflict`.
pub async fn swarm_update(engine: &RawEngine, options: &SwarmUpdateOptions) -> Result<(), Error> {
    completed(engine, update_request(options)?).await
}

/// Builds the `POST /swarm/update` request.
///
/// # Errors
///
/// Returns an error when the version does not fit the Engine's `int64`.
fn update_request(options: &SwarmUpdateOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("version", &checked_i64(options.version)?.to_string());
    query.flag("rotateWorkerToken", options.rotate_worker_token);
    query.flag("rotateManagerToken", options.rotate_manager_token);
    query.flag("rotateManagerUnlockKey", options.rotate_manager_unlock_key);
    let request = json_content_type(RawRequest::new(Method::POST, "/swarm/update"))
        .with_body(json_body(&options.spec)?);
    Ok(with_query(request, query.finish()))
}

/// Unlocks a Swarm manager whose key was rotated or lost.
///
/// This is one of the two endpoints the dependency cannot reach: Bollard 0.21.1
/// has no method for it, and the facade has to borrow an unrelated generated
/// method and rewrite the path after the fact. The owned transport names the
/// path it means.
///
/// # Errors
///
/// Returns an error when the key cannot be encoded or when the daemon rejects
/// the request, which is what a wrong key answers.
pub async fn swarm_unlock(engine: &RawEngine, options: &SwarmUnlockOptions) -> Result<(), Error> {
    completed(engine, swarm_unlock_request(options)).await
}

/// Builds the `POST /swarm/unlock` request.
fn swarm_unlock_request(options: &SwarmUnlockOptions) -> RawRequest {
    let body = json_body(&UnlockDocument {
        unlock_key: &options.key,
    })
    .expect("a document of one string always encodes");
    json_content_type(RawRequest::new(Method::POST, "/swarm/unlock")).with_body(body)
}

/// The `POST /swarm/unlock` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct UnlockDocument<'a> {
    #[serde(rename = "UnlockKey")]
    unlock_key: &'a str,
}

/// Reads the manager unlock key of a Swarm with autolock enabled.
///
/// The key is a credential: it is returned to the caller, redacted from `Debug`,
/// and zeroized when dropped. Nothing here logs or formats it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not an unlock-key document.
pub async fn swarm_unlock_key(engine: &RawEngine) -> Result<SwarmUnlockKey, Error> {
    let response = engine
        .send(RawRequest::new(Method::GET, "/swarm/unlockkey"))
        .await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Reads the Swarm root CA and the certificates issued for this node.
///
/// See the module documentation: the Engine stopped serving this path, so a
/// current daemon answers `404` and this reports that rejection rather than
/// pretending the material is missing for some other reason.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a certificates document.
pub async fn swarm_certificates(engine: &RawEngine) -> Result<SwarmCertificates, Error> {
    let response = engine
        .send(RawRequest::new(Method::GET, "/swarm/cert"))
        .await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Reads the join token for one role.
///
/// `None` means the daemon reported no token for that role, which is what a
/// worker reports for the manager token. The token is a credential and is
/// returned to the caller and written nowhere else.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a Swarm document.
pub async fn swarm_join_token(
    engine: &RawEngine,
    role: SwarmJoinTokenRole,
) -> Result<Option<String>, Error> {
    let swarm = swarm_inspect(engine).await?;
    Ok(swarm
        .join_tokens
        .as_ref()
        .and_then(|tokens| tokens.get(role.join_token_member()))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned))
}

/// Lists Swarm services.
///
/// `filters` is sent only when it is non-empty: an empty filter object is a
/// filter that matches the daemon's own no-filter case and would only make a
/// recorded request noisier.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a service
/// array.
pub async fn service_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmService>, Error> {
    let entries = list::<ServiceDocument>(engine, service_list_request(options)?).await?;
    entries.into_iter().map(SwarmService::try_from).collect()
}

/// Lists Swarm nodes.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a node array.
pub async fn node_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmNode>, Error> {
    let entries = list::<NodeDocument>(engine, node_list_request(options)?).await?;
    entries.into_iter().map(SwarmNode::try_from).collect()
}

/// Lists Swarm tasks.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a task array.
pub async fn task_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmTask>, Error> {
    let entries = list::<TaskDocument>(engine, task_list_request(options)?).await?;
    entries.into_iter().map(SwarmTask::try_from).collect()
}

/// Lists Swarm configs.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a config array.
pub async fn config_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmConfig>, Error> {
    let entries = list::<ConfigDocument>(engine, config_list_request(options)?).await?;
    entries.into_iter().map(SwarmConfig::try_from).collect()
}

/// Lists Swarm secrets.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a secret array.
pub async fn secret_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmSecret>, Error> {
    let entries = list::<SecretDocument>(engine, secret_list_request(options)?).await?;
    entries.into_iter().map(SwarmSecret::try_from).collect()
}

/// Sends a list request and decodes the one array it answers with.
///
/// Every Swarm list endpoint answers `[{…},{…}]` and nothing else, so one
/// bounded document read per resource is the whole shape of it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not an array.
async fn list<D>(engine: &RawEngine, request: RawRequest) -> Result<Vec<D>, Error>
where
    D: for<'de> Deserialize<'de>,
{
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /{resource}` list request every list endpoint shares.
///
/// The resource name is a literal at each of the five call sites, never anything
/// a caller supplies, so it cannot become a path the Engine does not serve.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn list_request(resource: &str, options: &SwarmListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, format!("/{resource}")),
        query.finish(),
    ))
}

/// Builds the `GET /services` list request.
fn service_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("services", options)
}

/// Builds the `GET /nodes` list request.
fn node_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("nodes", options)
}

/// Builds the `GET /tasks` list request.
fn task_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("tasks", options)
}

/// Builds the `GET /configs` list request.
fn config_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("configs", options)
}

/// Builds the `GET /secrets` list request.
fn secret_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("secrets", options)
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The repository map is a `BTreeMap`, so the JSON is in key order and the
/// recorded request is reproducible. The dependency converts the same map into a
/// `HashMap` before serializing it, so the key order of its `filters` value
/// varies between runs of the same command.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine swarm filters: {error}"
        ))
    })
}

/// Decodes one member of an Engine answer into a repository-owned model.
///
/// A sub-object that is projected out of a larger document — the published ports
/// out of a service's `Endpoint` — is decoded on its own, and the diagnostic is
/// the one [`decode`](crate::raw::decode) gives, naming the member rather than
/// the whole document, because that is the part that failed.
///
/// # Errors
///
/// Returns an error when the member is not the shape the Engine declares. It is
/// reported rather than dropped: a service whose port list did not decode is not
/// a service with no ports.
fn decode_value<T>(value: &serde_json::Value) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value.clone()).map_err(|error| {
        Error::invalid_input(format!(
            "failed to decode the Engine response member: {error}"
        ))
    })
}

/// Creates a Swarm service and returns its ID with any daemon warnings.
///
/// The body is the repository-owned [`ServiceSpec`] itself, spelled member for
/// member, so `Placement` and `RestartPolicy` are on the wire. See the module
/// documentation for the measured reason the dependency cannot do this.
///
/// # Errors
///
/// Returns an error when a placement preference is not a spelling the Engine
/// accepts, when the specification cannot be encoded, or when the daemon
/// rejects the request — an invalid specification arrives as a `400`.
pub async fn service_create(
    engine: &RawEngine,
    spec: &ServiceSpec,
) -> Result<ServiceCreateResult, Error> {
    let request = service_create_request(spec)?;
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    decode::<ServiceCreateDocument>(&document).map(ServiceCreateResult::from)
}

/// Builds the `POST /services/create` request.
///
/// # Errors
///
/// Returns an error when a placement preference is not a spelling the Engine
/// accepts.
fn service_create_request(spec: &ServiceSpec) -> Result<RawRequest, Error> {
    let body = json_body(&service_spec_body(spec)?)?;
    Ok(json_content_type(RawRequest::new(Method::POST, "/services/create")).with_body(body))
}

/// Builds the `POST /services/create` and `POST /services/{id}/update` body.
///
/// The typed members are spelled first and the specification's `additional` map
/// is merged over them, so a caller that needs a member this module does not name
/// sends it and it arrives. A member retained under the
/// `"<SubObject>.<Member>"` convention is merged back *into* its sub-object
/// rather than emitted under its dotted key, because `Placement.Platforms` is
/// not an Engine member name and the daemon would ignore it.
///
/// An `additional` entry always wins over a typed member of the same name. That
/// is the point of the escape hatch: it is how a caller overrides a spelling
/// this module chose, and a member the daemon itself sent is always the more
/// faithful value.
///
/// # Errors
///
/// Returns an error when a placement preference is not a spelling the Engine
/// accepts, or when a retained dotted key names a parent this module spelled as
/// something other than an object.
fn service_spec_body(spec: &ServiceSpec) -> Result<serde_json::Value, Error> {
    let typed = ServiceSpecDocument {
        name: spec.name.as_deref(),
        labels: spec.labels.as_ref(),
        task_template: spec.task_template.as_ref(),
        mode: spec.mode.as_ref(),
        endpoint_spec: spec.endpoint_spec.as_ref(),
        networks: spec.networks.as_ref(),
        update_config: spec.update_config.as_ref(),
        rollback_config: spec.rollback_config.as_ref(),
        // `Placement` and `RestartPolicy` are added to `TaskTemplate` below
        // rather than encoded here, because that is where the create request
        // reads them.
        placement: None,
        restart_policy: None,
    };
    // A document of named members always encodes to an object; anything else is
    // a defect here rather than anything a caller controls.
    let Ok(serde_json::Value::Object(members)) = serde_json::to_value(typed) else {
        return Err(Error::invalid_input(String::from(
            "the service specification did not encode as a JSON object",
        )));
    };
    let mut members = members;
    // `RestartPolicy` is a member of `TaskTemplate`, not of the service. The typed
    // `ServiceSpec` carries it at the top level because that is where an inspect
    // response reports it, and the two spellings have to be reconciled here.
    //
    // Measured, and the cost of getting it wrong is invisible: a Swarm service
    // whose specification says nothing is created with `Condition: any`,
    // `Delay: 5s`, and `MaxAttempts: 0` — the daemon's own defaults. A document
    // asking for `on-failure` with three attempts and a five-second delay
    // therefore *looks* correct when the policy is dropped entirely, because the
    // delay it asked for is the delay it gets. That is how a misplaced member
    // survives review: the one value a reader would check is the one the default
    // happens to match.
    // `Placement` and `RestartPolicy` are both members of `TaskTemplate`, not of
    // the service. The typed `ServiceSpec` carries them at the top level because
    // that is roughly where an inspect reports them, and the two spellings have to
    // be reconciled here.
    //
    // Measured, and the cost of getting it wrong is invisible in the way that
    // matters most. A Swarm service created with a specification that says nothing
    // gets `Condition: any`, `Delay: 5s`, `MaxAttempts: 0`, and no placement at
    // all — the daemon's own defaults. A document asking for `on-failure` with
    // three attempts and a five-second delay therefore *looks* right when the
    // policy is dropped outright, because the delay it asked for is the delay it
    // gets. That is how a misplaced member survives review: the one value a reader
    // would check is the one the default happens to match. A placement constraint
    // has no such consolation — it is simply absent, and a task lands on a node
    // the document forbade.
    // Each member is encoded on its own and only when the specification set it,
    // rather than through one collection, because their error types differ:
    // `Placement` can fail its *encoding* (an unusable preference spelling) while
    // `RestartPolicy` is a plain struct.
    let into_template = |members: &mut serde_json::Map<String, serde_json::Value>,
                         member: &str,
                         value: serde_json::Value|
     -> Result<(), Error> {
        let template = members
            .entry("TaskTemplate".to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if !template.is_object() {
            return Err(Error::invalid_input(String::from(
                "the task template did not encode as a JSON object, so a member cannot be \
                 placed inside it",
            )));
        }
        if let serde_json::Value::Object(template) = template {
            template.insert(member.to_owned(), value);
        }
        Ok(())
    };
    if let Some(policy) = spec.restart_policy.as_ref() {
        let encoded = serde_json::to_value(policy).map_err(|error| {
            Error::invalid_input(format!("failed to encode the restart policy: {error}"))
        })?;
        into_template(&mut members, "RestartPolicy", encoded)?;
    }
    if let Some(placement) = spec.placement.as_ref() {
        let encoded =
            serde_json::to_value(PlacementDocument::new(placement)?).map_err(|error| {
                Error::invalid_input(format!("failed to encode the placement: {error}"))
            })?;
        into_template(&mut members, "Placement", encoded)?;
    }
    members.remove("RestartPolicy");
    members.remove("Placement");

    for (key, value) in &spec.additional {
        match dotted(key) {
            Some((parent, member)) => {
                // `Placement` and `RestartPolicy` live inside `TaskTemplate` on the
                // wire, so a retained member of theirs has to be restored there
                // too. Putting `Placement.Platforms` back at the top level would
                // re-create the very member the Engine ignores.
                let target = if matches!(parent, "Placement" | "RestartPolicy") {
                    let template = members
                        .entry("TaskTemplate".to_owned())
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                    if let serde_json::Value::Object(template) = template {
                        template
                            .entry(parent.to_owned())
                            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                    } else {
                        return Err(Error::invalid_input(String::from(
                            "the task template is not an object, so a retained member cannot \
                             be restored into it",
                        )));
                    }
                } else {
                    members
                        .entry(parent.to_owned())
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                };
                let serde_json::Value::Object(object) = target else {
                    // A typed member and a dotted key disagree about the parent's
                    // shape. Overwriting the typed member would be a silent loss
                    // and keeping both would be a duplicate key, so it is
                    // reported rather than chosen between.
                    return Err(Error::invalid_input(format!(
                        "the service specification's '{parent}' is not an object, so '{key}' \
                         cannot be restored into it"
                    )));
                };
                object.insert(member.to_owned(), value.clone());
            }
            None => {
                members.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(serde_json::Value::Object(members))
}

/// Splits a `"<SubObject>.<Member>"` key into its two halves.
///
/// The Engine spells no member with a dot, so a dotted key is unambiguously a
/// retained member of a sub-object rather than a member of the object itself.
fn dotted(key: &str) -> Option<(&str, &str)> {
    key.split_once('.')
}

/// The `POST /services/create` and `POST /services/{id}/update` body.
#[derive(Debug, Serialize)]
struct ServiceSpecDocument<'a> {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "TaskTemplate", skip_serializing_if = "Option::is_none")]
    task_template: Option<&'a serde_json::Value>,
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    mode: Option<&'a serde_json::Value>,
    #[serde(rename = "EndpointSpec", skip_serializing_if = "Option::is_none")]
    endpoint_spec: Option<&'a serde_json::Value>,
    #[serde(rename = "Networks", skip_serializing_if = "Option::is_none")]
    networks: Option<&'a serde_json::Value>,
    #[serde(rename = "UpdateConfig", skip_serializing_if = "Option::is_none")]
    update_config: Option<&'a serde_json::Value>,
    #[serde(rename = "RollbackConfig", skip_serializing_if = "Option::is_none")]
    rollback_config: Option<&'a serde_json::Value>,
    #[serde(rename = "Placement", skip_serializing_if = "Option::is_none")]
    placement: Option<PlacementDocument<'a>>,
    #[serde(rename = "RestartPolicy", skip_serializing_if = "Option::is_none")]
    restart_policy: Option<&'a ServiceRestartPolicy>,
}

/// The `Placement` block of a service body, in the Engine's spelling.
///
/// `Preferences` is where the two paths differ most visibly. The Engine's type
/// is a list of objects, while a Compose `deploy:` block — and therefore
/// [`ServicePlacement::preferences`] — carries strings such as
/// `spread=node.labels.zone`. A list of strings sent as-is is a body the Engine
/// cannot decode, so each string is converted here into the object it declares,
/// and a string that is not a `spread=` preference is refused before the socket
/// rather than sent to be rejected.
///
/// `Platforms` has no counterpart in the repository type at all. A caller sets
/// it through the specification's `additional` map under the key
/// `Platforms` or `Placement.Platforms`, and it is merged into this object by
/// [`service_spec_body`].
#[derive(Debug, Serialize)]
struct PlacementDocument<'a> {
    #[serde(rename = "Constraints", skip_serializing_if = "Option::is_none")]
    constraints: Option<&'a [String]>,
    #[serde(rename = "Preferences", skip_serializing_if = "Vec::is_empty")]
    preferences: Vec<PreferenceDocument<'a>>,
    #[serde(rename = "MaxReplicas", skip_serializing_if = "is_zero")]
    max_replicas: u32,
}

impl<'a> PlacementDocument<'a> {
    /// Projects the repository placement onto the Engine's block.
    ///
    /// # Errors
    ///
    /// Returns an error when a preference string is not a `spread=` preference.
    /// The Engine declares exactly one preference kind, so a string outside
    /// that spelling has no translation, and inventing one would place tasks
    /// somewhere the caller did not ask for.
    fn new(placement: &'a ServicePlacement) -> Result<Self, Error> {
        let preferences = placement
            .preferences
            .iter()
            .map(PreferenceDocument::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            constraints: nonempty(&placement.constraints),
            preferences,
            max_replicas: placement.max_replicas,
        })
    }
}

/// One `Placement.Preferences` entry, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct PreferenceDocument<'a> {
    /// The Engine's `Spread` member, the only preference kind it declares.
    #[serde(rename = "Spread")]
    spread: SpreadDocument<'a>,
}

/// The `Spread` member of a placement preference.
#[derive(Debug, Serialize)]
struct SpreadDocument<'a> {
    /// The node-label or node-id expression to spread across.
    #[serde(rename = "SpreadDescriptor")]
    descriptor: &'a str,
}

impl<'a> PreferenceDocument<'a> {
    /// Converts one written preference into the Engine's object.
    ///
    /// # Errors
    ///
    /// Returns an error when the string does not start with `spread=` and names
    /// nothing after it. That is the only form Docker's own CLI accepts, and so
    /// the only one this crate can translate without guessing.
    fn new(preference: &'a String) -> Result<Self, Error> {
        let Some(descriptor) = preference.strip_prefix("spread=") else {
            return Err(Error::invalid_input(format!(
                "invalid swarm placement preference '{preference}'; the Engine accepts \
                 'spread=<label expression>'"
            )));
        };
        if descriptor.is_empty() {
            return Err(Error::invalid_input(String::from(
                "a swarm placement preference must name a label expression after 'spread='",
            )));
        }
        Ok(Self {
            spread: SpreadDocument { descriptor },
        })
    }
}

/// Returns the slice when it has values, or nothing when it does not.
///
/// An empty JSON array is not the same as an absent member to every daemon, and
/// an unset restriction means "no constraint" rather than "an empty list of
/// constraints".
fn nonempty(values: &[String]) -> Option<&[String]> {
    (!values.is_empty()).then_some(values)
}

/// Reports whether a `u32` is zero, for a `skip_serializing_if` that treats zero
/// as unset.
///
/// Takes the value by reference because serde hands a `skip_serializing_if` a
/// reference; the lint about passing it by value does not apply to a function
/// whose whole job is to be handed one.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// The `POST /services/create` answer, in the Engine's spelling.
///
/// The member is `ID`, not `Id`: the container create endpoint answers `Id` and
/// this one answers `ID`, and a client that spelled it the container way would
/// report an empty service ID for a service that was created.
#[derive(Debug, Deserialize)]
struct ServiceCreateDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(
        default,
        rename = "Warnings",
        deserialize_with = "super::null_as_empty"
    )]
    warnings: Vec<String>,
}

impl From<ServiceCreateDocument> for ServiceCreateResult {
    fn from(document: ServiceCreateDocument) -> Self {
        Self {
            id: document.id.unwrap_or_default(),
            warnings: document.warnings,
        }
    }
}

/// Inspects one Swarm service.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a service.
pub async fn service_inspect(engine: &RawEngine, id: &str) -> Result<SwarmService, Error> {
    let response = engine.send(service_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmService::try_from(decode::<ServiceDocument>(&document)?)
}

/// Builds the `GET /services/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("services", id, "")?,
    ))
}

/// Updates or rolls back a service at an explicit expected version.
///
/// `rollback` is sent only when the caller asked for it, and as the Engine's
/// `previous` spelling. The Engine reads the parameter as a task ID or the word
/// `previous`, so `rollback=false` would be a request to roll back to a task
/// named `false`. Omitting it is the only correct way to say "do not roll back".
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int32`, when a placement preference is not a spelling the
/// Engine accepts, or when the daemon rejects the request. A stale version stays
/// a `409 Conflict`.
pub async fn service_update(
    engine: &RawEngine,
    id: &str,
    options: &ServiceUpdateOptions,
) -> Result<ServiceUpdateResult, Error> {
    let request = service_update_request(id, options)?;
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    decode::<ServiceUpdateDocument>(&document).map(ServiceUpdateResult::from)
}

/// Builds the `POST /services/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int32`, or when the specification cannot be encoded.
fn service_update_request(id: &str, options: &ServiceUpdateOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("version", &checked_i32(options.version)?.to_string());
    if options.rollback {
        query.value("rollback", "previous");
    }
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path("services", id, "/update")?,
        ))
        .with_body(json_body(&service_spec_body(&options.spec)?)?),
        query.finish(),
    );
    Ok(request)
}

/// The `POST /services/{id}/update` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ServiceUpdateDocument {
    #[serde(
        default,
        rename = "Warnings",
        deserialize_with = "super::null_as_empty"
    )]
    warnings: Vec<String>,
}

impl From<ServiceUpdateDocument> for ServiceUpdateResult {
    fn from(document: ServiceUpdateDocument) -> Self {
        Self {
            warnings: document.warnings,
        }
    }
}

/// Removes one Swarm service.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `404` for a service that
/// does not exist.
pub async fn service_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed(engine, service_remove_request(id)?).await
}

/// Builds the `DELETE /services/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("services", id, "")?,
    ))
}

/// Inspects one Swarm node.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a node.
pub async fn node_inspect(engine: &RawEngine, id: &str) -> Result<SwarmNode, Error> {
    let response = engine.send(node_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmNode::try_from(decode::<NodeDocument>(&document)?)
}

/// Builds the `GET /nodes/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn node_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("nodes", id, "")?,
    ))
}

/// Updates one Swarm node at an explicit expected version.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, when the specification cannot be encoded, or when the
/// daemon rejects the request. A stale version stays a `409 Conflict`.
pub async fn node_update(
    engine: &RawEngine,
    id: &str,
    options: &NodeUpdateOptions,
) -> Result<(), Error> {
    completed(engine, node_update_request(id, options)?).await
}

/// Builds the `POST /nodes/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, or when the specification cannot be encoded.
fn node_update_request(id: &str, options: &NodeUpdateOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("version", &checked_i64(options.version)?.to_string());
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path("nodes", id, "/update")?,
        ))
        .with_body(json_body(&options.spec)?),
        query.finish(),
    );
    Ok(request)
}

/// Removes one Swarm node.
///
/// `force` is always spelled, for the reason given on [`swarm_leave`]. A manager
/// cannot be removed without it, and a recorded request that omits the parameter
/// cannot say whether the caller meant to.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `400` for a manager
/// removed without `force`.
pub async fn node_remove(
    engine: &RawEngine,
    id: &str,
    options: &NodeRemoveOptions,
) -> Result<(), Error> {
    completed(engine, node_remove_request(id, *options)?).await
}

/// Builds the `DELETE /nodes/{id}` request.
///
/// The options are taken by value because the type is one `bool`; the public
/// operation still borrows, so a caller can reuse its options afterwards.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn node_remove_request(id: &str, options: NodeRemoveOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("force", options.force);
    Ok(with_query(
        RawRequest::new(Method::DELETE, &resource_path("nodes", id, "")?),
        query.finish(),
    ))
}

/// Inspects one Swarm task.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a task.
pub async fn task_inspect(engine: &RawEngine, id: &str) -> Result<SwarmTask, Error> {
    let response = engine.send(task_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmTask::try_from(decode::<TaskDocument>(&document)?)
}

/// Builds the `GET /tasks/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn task_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("tasks", id, "")?,
    ))
}

/// Inspects one Swarm config.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a config.
pub async fn config_inspect(engine: &RawEngine, id: &str) -> Result<SwarmConfig, Error> {
    let response = engine.send(config_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmConfig::try_from(decode::<ConfigDocument>(&document)?)
}

/// Builds the `GET /configs/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("configs", id, "")?,
    ))
}

/// Creates a Swarm config and returns its ID.
///
/// `data` is base64-encoded here because the Engine declares `ConfigSpec.Data` as
/// a base64 string. A list answer omits the member and an inspect answer
/// includes it, so a config read back carries the bytes the daemon stored.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request,
/// such as a `409` for a name the Swarm already uses.
pub async fn config_create(
    engine: &RawEngine,
    options: &ConfigCreateOptions,
) -> Result<String, Error> {
    let request = config_create_request(options);
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    id_from(&document)
}

/// Builds the `POST /configs/create` request.
fn config_create_request(options: &ConfigCreateOptions) -> RawRequest {
    let body = json_body(&ResourceCreateDocument {
        name: &options.name,
        labels: options.labels.as_ref(),
        data: options.data.as_deref().map(|data| STANDARD.encode(data)),
    })
    .expect("a document of owned values always encodes");
    json_content_type(RawRequest::new(Method::POST, "/configs/create")).with_body(body)
}

/// Updates a Swarm config at an explicit expected version.
///
/// `Data` is left out of the body. The Engine's update endpoint cannot change a
/// config's data — `docker config update` sends the name and labels only — and
/// the repository specification carries `Data` because an *inspect* answer
/// includes it. Sending a read-only member back would ask the daemon to change
/// something it cannot, which is a rejection at best and a silent no-op at worst.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, or when the daemon rejects the request.
pub async fn config_update(
    engine: &RawEngine,
    id: &str,
    options: &ConfigUpdateOptions,
) -> Result<(), Error> {
    completed(
        engine,
        config_update_request(id, checked_i64(options.version)?, &options.spec)?,
    )
    .await
}

/// Builds the `POST /configs/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_update_request(
    id: &str,
    version: i64,
    spec: &SwarmConfigSpec,
) -> Result<RawRequest, Error> {
    resource_update_request(
        "configs",
        id,
        version,
        ResourceUpdateDocument {
            name: spec.name.as_deref(),
            labels: spec.labels.as_ref(),
        },
    )
}

/// Removes one Swarm config.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `400` for a config a
/// running task still uses.
pub async fn config_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed(engine, config_remove_request(id)?).await
}

/// Builds the `DELETE /configs/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("configs", id, "")?,
    ))
}

/// Inspects one Swarm secret, without exposing the secret's data.
///
/// The Engine never returns secret data from an inspect or a list, so there is
/// nothing here to withhold; the type simply has no member for it.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a secret.
pub async fn secret_inspect(engine: &RawEngine, id: &str) -> Result<SwarmSecret, Error> {
    let response = engine.send(secret_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmSecret::try_from(decode::<SecretDocument>(&document)?)
}

/// Builds the `GET /secrets/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("secrets", id, "")?,
    ))
}

/// Creates a Swarm secret and returns its ID.
///
/// The bytes are base64-encoded for the wire, and the caller's own copy is
/// zeroized when it is dropped, which is the handling the repository type gives
/// them everywhere else.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request.
pub async fn secret_create(
    engine: &RawEngine,
    options: &SecretCreateOptions,
) -> Result<String, Error> {
    let request = secret_create_request(options);
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    id_from(&document)
}

/// Builds the `POST /secrets/create` request.
fn secret_create_request(options: &SecretCreateOptions) -> RawRequest {
    let body = json_body(&ResourceCreateDocument {
        name: &options.name,
        labels: options.labels.as_ref(),
        data: options
            .data
            .as_ref()
            .map(|data| STANDARD.encode(data.as_bytes())),
    })
    .expect("a document of owned values always encodes");
    json_content_type(RawRequest::new(Method::POST, "/secrets/create")).with_body(body)
}

/// Updates secret metadata at an explicit expected version.
///
/// The Engine's update endpoint cannot change a secret's data, so the body
/// carries the name and labels only, for the reason given on [`config_update`].
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, or when the daemon rejects the request.
pub async fn secret_update(
    engine: &RawEngine,
    id: &str,
    options: &SecretUpdateOptions,
) -> Result<(), Error> {
    completed(
        engine,
        secret_update_request(id, checked_i64(options.version)?, &options.spec)?,
    )
    .await
}

/// Builds the `POST /secrets/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_update_request(
    id: &str,
    version: i64,
    spec: &SwarmSecretSpec,
) -> Result<RawRequest, Error> {
    resource_update_request(
        "secrets",
        id,
        version,
        ResourceUpdateDocument {
            name: spec.name.as_deref(),
            labels: spec.labels.as_ref(),
        },
    )
}

/// Removes one Swarm secret.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request.
pub async fn secret_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed(engine, secret_remove_request(id)?).await
}

/// Builds the `DELETE /secrets/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("secrets", id, "")?,
    ))
}

/// The `POST /configs/create` and `POST /secrets/create` body.
#[derive(Debug, Serialize)]
struct ResourceCreateDocument<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
    /// Absent when the caller supplied no bytes, which the Engine reads as a
    /// request for an external object rather than for an empty one.
    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

/// The `POST /configs/{id}/update` and `POST /secrets/{id}/update` body.
#[derive(Debug, Serialize)]
struct ResourceUpdateDocument<'a> {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
}

/// Builds the update request the config and secret endpoints share.
///
/// # Errors
///
/// Returns an error when the reference is empty or the body cannot be encoded.
fn resource_update_request<D>(
    resource: &str,
    id: &str,
    version: i64,
    body: D,
) -> Result<RawRequest, Error>
where
    D: Serialize,
{
    let mut query = Query::default();
    query.value("version", &version.to_string());
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path(resource, id, "/update")?,
        ))
        .with_body(json_body(&body)?),
        query.finish(),
    );
    Ok(request)
}

/// The `POST /{resource}/create` answer, which is `{"ID":"…"}` for both a config
/// and a secret.
#[derive(Debug, Deserialize)]
struct IdDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
}

/// Reads the `ID` member of a create answer.
///
/// # Errors
///
/// Returns an error when the answer has no `ID`, rather than reporting an empty
/// resource ID for a resource that was created. The caller has no other way to
/// learn what was created.
fn id_from(document: &[u8]) -> Result<String, Error> {
    let document: IdDocument = decode(document)?;
    document.id.ok_or_else(|| {
        Error::invalid_input(String::from(
            "the Engine created the resource but reported no ID for it",
        ))
    })
}

/// Opens the service logs stream.
///
/// The body is multiplexed exactly as a container's is — an eight-byte frame
/// header per write — and is decoded by [`SwarmLogFrames`] with the same
/// [`LogDecoder`] the container slice uses, so a service log is read by the same
/// rules rather than by a second set of them.
///
/// `details` is always sent as `true`, the Engine's own default, so a recorded
/// request says what it meant instead of relying on the daemon.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request. A body that is not multiplexed
/// framing — or one carrying a frame over
/// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) — is reported by
/// [`SwarmLogFrames::next_frame`] rather than here, because one read cannot tell
/// a valid stream from a corrupt one, and cannot tell whether the frames behind
/// the refused one are still coming.
pub async fn service_logs(
    engine: &RawEngine,
    id: &str,
    options: &SwarmLogOptions,
) -> Result<SwarmLogFrames, Error> {
    open_logs(engine, service_log_request(id, options)?).await
}

/// Builds the `GET /services/{id}/logs` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_log_request(id: &str, options: &SwarmLogOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("details", true);
    query.flag("follow", options.follow);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    query.value("since", &options.since.to_string());
    query.value("until", &options.until.to_string());
    query.flag("timestamps", options.timestamps);
    query.value("tail", &options.tail);
    Ok(with_query(
        RawRequest::new(Method::GET, &resource_path("services", id, "/logs")?),
        query.finish(),
    ))
}

/// Opens the task logs stream.
///
/// The Engine's task-logs endpoint declares four query parameters — `since`,
/// `until`, `timestamps`, and `tail` — and not the `follow`, `stdout`, `stderr`,
/// or `details` parameters the service and container endpoints have. Only the
/// four are sent, because a parameter the endpoint does not declare is one whose
/// effect nobody can predict.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request.
pub async fn task_logs(
    engine: &RawEngine,
    id: &str,
    options: &SwarmLogOptions,
) -> Result<SwarmLogFrames, Error> {
    open_logs(engine, task_log_request(id, options)?).await
}

/// Builds the `GET /tasks/{id}/logs` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn task_log_request(id: &str, options: &SwarmLogOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("since", &options.since.to_string());
    query.value("until", &options.until.to_string());
    query.flag("timestamps", options.timestamps);
    query.value("tail", &options.tail);
    Ok(with_query(
        RawRequest::new(Method::GET, &resource_path("tasks", id, "/logs")?),
        query.finish(),
    ))
}

/// Sends a logs request and wraps the response in a frame decoder.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request.
async fn open_logs(engine: &RawEngine, request: RawRequest) -> Result<SwarmLogFrames, Error> {
    let response = engine.send(request).await?;
    // The status is checked before the body is handed out, or a 404 whose body
    // happened to parse as framing would surface as a log stream.
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(SwarmLogFrames {
        frames: response.into_frames(),
        decoder: LogDecoder::new(false),
        ready: VecDeque::new(),
    })
}

/// A stream of decoded Swarm log frames.
///
/// The logic is the container slice's, duplicated rather than shared because
/// [`LogFrames`](crate::raw::LogFrames) has no public constructor: it can only
/// be built for `/containers/{id}/logs`, and a Swarm task's container cannot be
/// addressed by that path. The *decoding* is not duplicated — the same
/// [`LogDecoder`] and the same frame rules are used — so the two cannot disagree
/// about what a frame is.
///
/// The framing is always the multiplexed one. A Swarm task's container
/// specification has no TTY option, so a task's output is always framed, and a
/// body that is not framed is reported as an error rather than forwarded as
/// plausible-looking garbage. Because every body here is framed, the
/// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) payload bound applies to
/// every task and service log with no TTY exception: unlike the container slice,
/// there is no unframed body for the bound not to cover.
///
/// Dropping this closes the connection and ends the transfer, which is also how
/// a `follow` stream is cancelled.
pub struct SwarmLogFrames {
    frames: FrameStream,
    decoder: LogDecoder,
    /// Frames a single network read completed beyond the first.
    ///
    /// One read can finish several frames, so the ones already complete are
    /// queued rather than dropped, and a caller sees every frame exactly once
    /// and in order.
    ready: VecDeque<LogFrame>,
}

impl std::fmt::Debug for SwarmLogFrames {
    /// Reports how much is buffered, and no payload.
    ///
    /// The same reasoning as [`LogFrames`](crate::raw::LogFrames), which this
    /// type duplicates: `decoder` holds the bytes of a partly-arrived frame and
    /// `ready` holds completed payloads, and both render in full. A task's
    /// output is whatever the task's image chose to print, so it is counted
    /// rather than shown. The framing is not reported because it is always the
    /// multiplexed one — a task specification has no TTY option.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SwarmLogFrames")
            .field("buffered", &self.decoder.buffered())
            .field("ready_frames", &self.ready.len())
            .finish_non_exhaustive()
    }
}

impl SwarmLogFrames {
    /// Reads the next decoded frame, or `None` at end of stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails mid-transfer, when the body is
    /// not valid multiplexed framing, or when the body ends part-way through a
    /// frame — which is how a truncated log would otherwise be
    /// indistinguishable from a short one.
    ///
    /// A frame whose header declares more than
    /// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) of payload is refused
    /// here as well, with the same kind and the same cause the container slice
    /// reports: the two use one [`LogDecoder`], so a task log cannot fail for a
    /// reason a container log would not. It is stated on this method rather than
    /// left to be discovered, because a Swarm task has no TTY and so no
    /// unframed fallback to explain a large write — the only reason a real task
    /// can produce such a frame is a task producing a single enormous one.
    ///
    /// Every frame the connection delivered is returned before that error. One
    /// read can complete several frames and then carry one this client refuses,
    /// and the completed ones are handed over first.
    pub async fn next_frame(&mut self) -> Result<Option<LogFrame>, Error> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            if let Some(frame) = self.decoder.decode()? {
                return Ok(Some(frame));
            }
            let Some(data) = self.frames.next_data().await.map_err(Error::from)? else {
                self.decoder.finish()?;
                return Ok(None);
            };
            // `push_read`, not `push`: the transport hands the read over as
            // `Bytes`, and `push` would copy the whole of it before the decoder
            // could take the frames out of it. That copy is a second copy of
            // every byte of a task's output, bought for nothing — the frames
            // come out of the read either way — and a Swarm log is read the same
            // way a container log is, so it should cost the same.
            self.ready.extend(self.decoder.push_read(&data)?);
        }
    }
}

/// Sends a request whose success is a status rather than a document.
///
/// A `200` with an empty body is a success: the Engine answers `POST /swarm/join`,
/// `POST /swarm/leave`, `POST /swarm/unlock`, and every node, config, and secret
/// update with no body at all, and decoding that as a document would turn a
/// successful call into a parse failure.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, carrying the status and the daemon's own message.
async fn completed(engine: &RawEngine, request: RawRequest) -> Result<(), Error> {
    let response = engine.send(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Builds the `/{resource}/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/services//start` is not a request
/// for a service, and sending it would ask the daemon about a resource the
/// caller never named.
///
/// The reference is percent-encoded into exactly one segment. An unescaped
/// reference would silently address a *different* resource, because `/` is a
/// path separator: `GET /services/a/b` is a four-segment path, not an inspect of
/// a service named `a/b`.
fn resource_path(resource: &str, reference: &str, suffix: &str) -> Result<String, Error> {
    if reference.is_empty() {
        return Err(Error::invalid_input(format!(
            "the Engine {resource} reference must not be empty"
        )));
    }
    Ok(format!(
        "/{resource}/{}{suffix}",
        escape_path_segment(reference)
    ))
}

/// Percent-encodes one path segment.
///
/// Everything outside the unreserved set `A-Z a-z 0-9 - . _ ~` is encoded, and
/// `%` is encoded too, so a reference that already contains a percent sign
/// cannot smuggle an escape sequence past this function. This is the function
/// `raw::containers` already has; it is spelled again here because that
/// module's copy is private to it, and two copies of a twenty-line encoder is
/// cheaper than a helper neither of those modules can be edited into.
fn escape_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => {
                use std::fmt::Write as _;
                let _written = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

/// A service as the Engine sends it, in the Engine's spelling.
///
/// `Endpoint` and `Spec` are kept whole rather than projected: the repository
/// service model has no field for either, and the typed views it does have — the
/// published ports and the task counts — are read out of them. A member of the
/// endpoint that no typed field names, such as a port's `Name`, is therefore
/// still there in `additional["Endpoint"]`.
#[derive(Debug, Deserialize)]
struct ServiceDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<ServiceSpecDocumentView>,
    #[serde(rename = "Endpoint")]
    endpoint: Option<serde_json::Value>,
    #[serde(rename = "ServiceStatus")]
    service_status: Option<ServiceStatus>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ServiceDocument> for SwarmService {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the published ports or the service specification
    /// are not the shape the Engine declares. They are reported rather than
    /// dropped: a service whose port list did not decode is not a service with no
    /// ports.
    fn try_from(document: ServiceDocument) -> Result<Self, Error> {
        let mut additional = document.additional;
        let ports = match document
            .endpoint
            .as_ref()
            .and_then(|endpoint| endpoint.get("Ports"))
        {
            Some(ports) => Some(decode_value::<Vec<ServicePort>>(ports)?),
            None => None,
        };
        if let Some(endpoint) = document.endpoint {
            additional.insert(String::from("Endpoint"), endpoint);
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec.map(ServiceSpec::try_from).transpose()?,
            ports,
            status: document.service_status,
            additional,
        })
    }
}

/// A service specification as the Engine sends it.
///
/// The named members are decoded into the repository's own specification, and
/// the members that specification cannot express are retained under the
/// `"<SubObject>.<Member>"` convention the module documentation describes.
#[derive(Debug, Deserialize)]
struct ServiceSpecDocumentView {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "TaskTemplate")]
    task_template: Option<serde_json::Value>,
    #[serde(rename = "Mode")]
    mode: Option<serde_json::Value>,
    #[serde(rename = "EndpointSpec")]
    endpoint_spec: Option<serde_json::Value>,
    #[serde(rename = "Networks")]
    networks: Option<serde_json::Value>,
    #[serde(rename = "UpdateConfig")]
    update_config: Option<serde_json::Value>,
    #[serde(rename = "RollbackConfig")]
    rollback_config: Option<serde_json::Value>,
    #[serde(rename = "Placement")]
    placement: Option<PlacementDocumentView>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: Option<ServiceRestartPolicy>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ServiceSpecDocumentView> for ServiceSpec {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the restart policy is not the shape the Engine
    /// declares. `ServiceRestartPolicy::condition` is not optional, so a policy
    /// without one is reported instead of being read as a policy that restarts
    /// never.
    fn try_from(document: ServiceSpecDocumentView) -> Result<Self, Error> {
        let mut additional = document.additional;
        let placement = match document.placement {
            Some(placement) => {
                let view = ServicePlacement::from(&placement);
                // A daemon's preferences are objects and a `Vec<String>` cannot
                // hold them, so they are retained verbatim under the key that
                // puts them back where they came from.
                let objects = if placement.preferences_are_objects() {
                    Some(serde_json::Value::Array(placement.preferences))
                } else {
                    None
                };
                let mut retained = placement.additional;
                if let Some(preferences) = objects {
                    retained.insert(String::from("Preferences"), preferences);
                }
                for (member, value) in retained {
                    additional.insert(format!("Placement.{member}"), value);
                }
                Some(view)
            }
            None => None,
        };
        Ok(Self {
            name: document.name,
            labels: document.labels,
            task_template: document.task_template,
            mode: document.mode,
            endpoint_spec: document.endpoint_spec,
            networks: document.networks,
            update_config: document.update_config,
            rollback_config: document.rollback_config,
            placement,
            restart_policy: document.restart_policy,
            additional,
        })
    }
}

/// The `Placement` block as the Engine sends it.
///
/// The preferences are inspected in both spellings they can arrive in, because
/// the two are not interchangeable: a caller writes strings, the Engine sends
/// objects.
#[derive(Debug, Deserialize)]
struct PlacementDocumentView {
    #[serde(default, rename = "Constraints")]
    constraints: Vec<String>,
    #[serde(default, rename = "Preferences")]
    preferences: Vec<serde_json::Value>,
    #[serde(default, rename = "MaxReplicas")]
    max_replicas: u32,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl From<&PlacementDocumentView> for ServicePlacement {
    /// Projects the Engine's placement onto the repository type.
    ///
    /// The members this type cannot express — the Engine's object-form
    /// preferences and `Platforms` — are *not* projected here; the caller that
    /// read them is responsible for retaining them, because only the caller
    /// knows which map they belong beside.
    fn from(view: &PlacementDocumentView) -> Self {
        Self {
            constraints: view.constraints.clone(),
            preferences: view.preference_strings(),
            max_replicas: view.max_replicas,
        }
    }
}

impl PlacementDocumentView {
    /// Returns the preferences a caller could have written.
    ///
    /// A mixed array is treated as the Engine's form: one entry that is an
    /// object means the daemon sent its own `Spread` objects, and guessing which
    /// of the remaining entries were meant to be strings would be inventing a
    /// member.
    fn preference_strings(&self) -> Vec<String> {
        self.preferences
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    }

    /// Returns whether any preference arrived in the Engine's object form.
    fn preferences_are_objects(&self) -> bool {
        self.preferences.iter().any(|value| !value.is_string())
    }
}

/// A node as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct NodeDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<NodeSpec>,
    #[serde(rename = "Status")]
    status: Option<serde_json::Value>,
    #[serde(rename = "Description")]
    description: Option<serde_json::Value>,
    #[serde(rename = "ManagerStatus")]
    manager_status: Option<NodeManagerStatus>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<NodeDocument> for SwarmNode {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the manager status or the node specification is not
    /// the shape the Engine declares. `EngineVersion` is a *view* of
    /// `Description.Engine`, and the description itself is retained whole, so a
    /// member of it that the view does not read is not lost.
    fn try_from(document: NodeDocument) -> Result<Self, Error> {
        let mut additional = document.additional;
        let engine_version = document
            .description
            .as_ref()
            .and_then(|description| description.get("Engine"))
            .and_then(|engine| {
                engine
                    .get("EngineVersion")
                    .or_else(|| engine.get("Version"))
            })
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(description) = document.description {
            additional.insert(String::from("Description"), description);
        }
        if let Some(manager) = &document.manager_status {
            for member in ["Addr", "Address"] {
                if let Some(address) = manager.additional.get(member) {
                    additional.insert(format!("ManagerStatus.{member}"), address.clone());
                }
            }
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            status: document.status,
            manager_status: document.manager_status,
            engine_version,
            additional,
        })
    }
}

/// A task as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct TaskDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "ServiceID", default)]
    service_id: String,
    #[serde(rename = "Slot", default)]
    slot: i64,
    #[serde(rename = "NodeID", default)]
    node_id: String,
    #[serde(rename = "Status")]
    status: Option<SwarmTaskStatus>,
    #[serde(rename = "DesiredState")]
    desired_state: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<serde_json::Value>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<TaskDocument> for SwarmTask {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the task status is not the shape the Engine
    /// declares. The image is a view of `Spec.ContainerSpec.Image` and the
    /// specification is retained whole beside it, so a member of the container
    /// specification the view does not read is not lost.
    fn try_from(document: TaskDocument) -> Result<Self, Error> {
        let mut additional = document.additional;
        let image = document
            .spec
            .as_ref()
            .and_then(|spec| spec.get("ContainerSpec"))
            .and_then(|container| container.get("Image"))
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(spec) = document.spec.clone() {
            additional.insert(String::from("Spec"), spec);
        }
        if let Some(status) = &document.status
            && let Some(container) = status.additional.get("ContainerStatus")
        {
            additional.insert(String::from("Status.ContainerStatus"), container.clone());
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            name: document.name,
            labels: document.labels,
            image,
            service_id: document.service_id,
            slot: document.slot,
            node_id: document.node_id,
            status: document.status,
            desired_state: document.desired_state,
            spec: document.spec,
            additional,
        })
    }
}

/// A config as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ConfigDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<SwarmConfigSpec>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ConfigDocument> for SwarmConfig {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the config specification is not the shape the
    /// Engine declares. Members this model does not name are retained in
    /// `additional` rather than dropped.
    fn try_from(document: ConfigDocument) -> Result<Self, Error> {
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            additional: document.additional,
        })
    }
}

/// A secret as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct SecretDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<SwarmSecretSpec>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<SecretDocument> for SwarmSecret {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the secret specification is not the shape the
    /// Engine declares. Members this model does not name are retained in
    /// `additional` rather than dropped.
    fn try_from(document: SecretDocument) -> Result<Self, Error> {
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            additional: document.additional,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::raw::{RawBody, RawEngine, RawTarget, decode};
    use crate::swarm::{SwarmSecretData, SwarmUnlockOptions};
    use crate::{
        ApiVersion, ConfigCreateOptions, Error, ErrorKind, NodeRemoveOptions, NodeSpec,
        NodeUpdateOptions, SecretCreateOptions, ServiceCreateResult, ServicePlacement,
        ServiceRestartPolicy, ServiceSpec, ServiceStatus, ServiceUpdateOptions,
        ServiceUpdateResult, SwarmConfig, SwarmConfigSpec, SwarmInfo, SwarmInitOptions,
        SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions, SwarmListOptions, SwarmLogOptions,
        SwarmNode, SwarmSecret, SwarmSecretSpec, SwarmService, SwarmSpec, SwarmTask,
        SwarmUpdateOptions, SwarmVersion,
    };

    use super::{
        ConfigDocument, NodeDocument, SecretDocument, ServiceCreateDocument, ServiceDocument,
        ServiceSpecDocumentView, ServiceUpdateDocument, TaskDocument, config_create_request,
        config_list_request, config_update_request, escape_path_segment, id_from, init_request,
        join_request, leave_request, node_list_request, node_remove_request, node_update_request,
        resource_path, secret_create_request, secret_list_request, secret_update_request,
        service_create_request, service_inspect_request, service_list_request, service_log_request,
        service_remove_request, service_spec_body, service_update_request, swarm_inspect_request,
        swarm_unlock_request, task_inspect_request, task_list_request, task_log_request,
        update_request,
    };

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    /// The Swarm documents this repository keeps as fixtures.
    const SERVICE: &str = include_str!("../../../../fixtures/docker/engine/swarm/service.json");
    const SERVICES: &str = include_str!("../../../../fixtures/docker/engine/swarm/services.json");
    const NODE: &str = include_str!("../../../../fixtures/docker/engine/swarm/node.json");
    const NODES: &str = include_str!("../../../../fixtures/docker/engine/swarm/nodes.json");
    const TASK: &str = include_str!("../../../../fixtures/docker/engine/swarm/task.json");
    const TASKS: &str = include_str!("../../../../fixtures/docker/engine/swarm/tasks.json");
    const CONFIG: &str = include_str!("../../../../fixtures/docker/engine/swarm/config.json");
    const CONFIGS: &str = include_str!("../../../../fixtures/docker/engine/swarm/configs.json");
    const SECRET: &str = include_str!("../../../../fixtures/docker/engine/swarm/secret.json");
    const SECRETS: &str = include_str!("../../../../fixtures/docker/engine/swarm/secrets.json");
    const SWARM: &str = include_str!("../../../../fixtures/docker/engine/swarm/inspect.json");

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

    /// Decodes every entry of a Swarm list fixture and projects it.
    fn project<T, D>(document: &str) -> Vec<T>
    where
        T: TryFrom<D, Error = Error>,
        D: for<'de> serde::Deserialize<'de>,
    {
        decode::<Vec<D>>(document.as_bytes())
            .expect("a list document")
            .into_iter()
            .map(T::try_from)
            .collect::<Result<Vec<_>, _>>()
            .expect("every entry converts")
    }

    /// A service specification with every member the type names, and one it does
    /// not.
    ///
    /// A projection that quietly forgets a member shows up in the assertions that
    /// follow, so the fixture is deliberately exhaustive.
    fn complete_spec() -> ServiceSpec {
        ServiceSpec {
            name: Some("web".to_owned()),
            labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
            task_template: Some(serde_json::json!({
                "ContainerSpec": {"Image": "nginx:alpine"},
            })),
            mode: Some(serde_json::json!({"Replicated": {"Replicas": 2}})),
            endpoint_spec: Some(serde_json::json!({"Mode": "vip"})),
            networks: Some(serde_json::json!([{"Target": "net"}])),
            update_config: Some(serde_json::json!({"Parallelism": 1})),
            rollback_config: Some(serde_json::json!({"Parallelism": 1})),
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                preferences: vec!["spread=node.labels.zone".to_owned()],
                max_replicas: 2,
            }),
            restart_policy: Some(ServiceRestartPolicy {
                condition: String::from("on-failure"),
                delay: Some(5_000_000_000),
                max_attempts: Some(3),
                window: Some(120_000_000_000),
                failure_action: Some(String::from("pause")),
            }),
            additional: BTreeMap::from([(
                String::from("UnknownMember"),
                serde_json::json!({"kept": true}),
            )]),
        }
    }

    #[test]
    fn a_service_create_body_carries_placement_and_restart_policy() {
        // This is the whole reason the owned backend exists. The generated
        // `ServiceSpec` in the pinned dependency has neither member, so a
        // specification that names them cannot be sent through it at all; here
        // they are on the wire.
        let body = service_spec_body(&complete_spec()).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Constraints"][0], "node.role == worker",
            "the constraint must reach the daemon: {body}"
        );
        assert_eq!(body["TaskTemplate"]["Placement"]["MaxReplicas"], 2);
        assert!(
            body.get("Placement").is_none(),
            "the top-level spelling must not also go on the wire: {body}"
        );
        // `RestartPolicy` lives inside `TaskTemplate`, and the assertion says so:
        // the top-level spelling is where an inspect *reports* the policy, and a
        // create request that carries it there is silently ignored by the daemon.
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Condition"],
            "on-failure"
        );
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Delay"],
            5_000_000_000i64
        );
        assert_eq!(body["TaskTemplate"]["RestartPolicy"]["MaxAttempts"], 3);
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Window"],
            120_000_000_000i64
        );
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["FailureAction"],
            "pause"
        );
        assert!(
            body.get("RestartPolicy").is_none(),
            "the top-level spelling must not also go on the wire: {body}"
        );
    }

    #[test]
    fn the_dependency_cannot_carry_the_two_members_the_owned_body_carries() {
        // The contrast, measured rather than asserted about: the *same*
        // specification goes through the pinned dependency's generated type, and
        // the members this module relies on are absent from the result with no
        // error at all. If a future `bollard` release adds them, this fails and
        // the decision to own the path is revisited instead of rotting into a
        // stale assumption.
        let encoded = serde_json::to_value(complete_spec()).expect("the specification encodes");
        let through_dependency: bollard::models::ServiceSpec =
            serde_json::from_value(encoded).expect("the generated type accepts it");
        let re_encoded = serde_json::to_value(&through_dependency).expect("it encodes again");
        assert!(
            re_encoded.get("Placement").is_none(),
            "the dependency is expected to have no Placement member: {re_encoded}"
        );
        assert!(
            re_encoded.get("RestartPolicy").is_none(),
            "the dependency is expected to have no RestartPolicy member: {re_encoded}"
        );
        // Every member the generated type *does* name still survives there, so
        // the difference is exactly the two members and not a broken fixture.
        assert_eq!(re_encoded["Name"], "web");
        assert_eq!(
            re_encoded["TaskTemplate"]["ContainerSpec"]["Image"],
            "nginx:alpine"
        );
    }

    #[test]
    fn the_owned_body_keeps_every_member_the_typed_specification_names() {
        // A projection that dropped a member would be a silent request for less
        // than the caller asked for, so the typed body is compared member for
        // member against a plain serialization of the same specification. The
        // one expected difference is `Placement.Preferences`, which the Engine
        // spells as objects.
        let spec = complete_spec();
        let typed = serde_json::to_value(&spec).expect("the specification encodes");
        let body = service_spec_body(&spec).expect("an encodable specification");
        for member in [
            "Name",
            "Labels",
            "Mode",
            "EndpointSpec",
            "Networks",
            "UpdateConfig",
            "RollbackConfig",
        ] {
            assert_eq!(body[member], typed[member], "{member} must survive");
        }
        // `Placement` is compared apart from its preferences, which the
        // projection rewrites into the Engine's object form because a Compose
        // `deploy:` block writes strings and the Engine declares objects. That
        // rewrite has its own test below.
        // `Placement` moves into `TaskTemplate` like the restart policy, and its
        // preferences are rewritten into the Engine's object form. The comparison
        // is made where the value actually lands.
        let mut expected_placement = typed["Placement"].clone();
        expected_placement["Preferences"] =
            body["TaskTemplate"]["Placement"]["Preferences"].clone();
        assert_eq!(body["TaskTemplate"]["Placement"], expected_placement);
        // `TaskTemplate` is compared apart from the restart policy, which is the
        // one member the projection *adds* to it — see below.
        // Two members are *moved* into the task template rather than copied, and
        // both are compared where they land rather than exempted from the
        // comparison.
        let mut expected_template = typed["TaskTemplate"].clone();
        expected_template["RestartPolicy"] = typed["RestartPolicy"].clone();
        let mut moved_placement = typed["Placement"].clone();
        moved_placement["Preferences"] = body["TaskTemplate"]["Placement"]["Preferences"].clone();
        expected_template["Placement"] = moved_placement;
        assert_eq!(
            body["TaskTemplate"], expected_template,
            "TaskTemplate must survive with the restart policy and the placement added to \
             it"
        );
        // `RestartPolicy` is the one member that is *moved* rather than copied:
        // the typed specification carries it at the top level because that is
        // where an inspect reports it, and the create request wants it inside
        // `TaskTemplate`. Every other member must be identical, and this one
        // must be identical once relocated — so the two are compared after the
        // move rather than exempted from the comparison.
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"], typed["RestartPolicy"],
            "the restart policy must survive the move into the task template"
        );
        assert_eq!(body["UnknownMember"]["kept"], true);
        assert_eq!(
            typed["Placement"]["Preferences"][0],
            "spread=node.labels.zone"
        );
    }

    #[test]
    fn placement_preferences_are_sent_in_the_shape_the_engine_declares() {
        // The Engine's `Placement.Preferences` is a list of objects. A list of
        // strings is a body it cannot decode, and a Compose `deploy:` block
        // writes strings, so the conversion has to happen here or a working
        // stack file stops deploying.
        let body = service_spec_body(&complete_spec()).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
    }

    #[test]
    fn a_preference_the_engine_would_reject_is_refused_before_the_socket() {
        for rejected in ["node.labels.zone", "spread=", "spread", "", "SPREAD=x"] {
            let spec = ServiceSpec {
                placement: Some(ServicePlacement {
                    preferences: vec![rejected.to_owned()],
                    ..ServicePlacement::default()
                }),
                ..ServiceSpec::default()
            };
            let error = service_spec_body(&spec).expect_err("an untranslatable preference");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{rejected}");
        }
    }

    #[test]
    fn an_unrepresentable_placement_member_survives_a_round_trip_through_the_daemon() {
        // `Platforms` has no field on the repository type and the Engine's
        // preferences are objects, so an answer carrying them keeps both — and a
        // specification read back from an inspect re-sends them inside
        // `Placement`, where the Engine reads them, rather than under a name the
        // Engine would ignore.
        let document: ServiceSpecDocumentView = decode(
            br#"{"Name":"web","Placement":{"Constraints":["node.role == worker"],
                "Platforms":[{"Architecture":"amd64","OS":"linux"}],
                "Preferences":[{"Spread":{"SpreadDescriptor":"node.labels.zone"}}],
                "MaxReplicas":2}}"#,
        )
        .expect("a service specification");
        let spec = ServiceSpec::try_from(document).expect("it converts");
        let placement = spec.placement.as_ref().expect("a placement");
        assert_eq!(
            placement.constraints,
            vec!["node.role == worker".to_owned()]
        );
        assert_eq!(placement.max_replicas, 2);
        // The daemon's preferences are objects, so they are kept verbatim rather
        // than forced into the string list a caller writes.
        assert!(placement.preferences.is_empty());
        assert_eq!(
            spec.additional["Placement.Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
        assert_eq!(
            spec.additional["Placement.Platforms"][0]["Architecture"],
            "amd64"
        );

        let body = service_spec_body(&spec).expect("it encodes again");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Platforms"][0]["OS"],
            "linux"
        );
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
        // A dotted key is a retention convention, not an Engine member name, so
        // it must never reach the wire as one.
        assert!(
            body.get("Placement.Platforms").is_none()
                && body.get("Placement.Preferences").is_none(),
            "{body}"
        );
    }

    #[test]
    fn the_placement_block_is_exactly_the_shape_the_engine_declares() {
        // The whole block, asserted at once. A member spelled wrongly here is
        // not a decode failure: the Engine ignores a member it does not know, so
        // a wrong spelling is a service that schedules somewhere the caller did
        // not ask for.
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                preferences: vec!["spread=node.labels.zone".to_owned()],
                max_replicas: 1,
            }),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"],
            serde_json::json!({
                "Constraints": ["node.role == worker"],
                "Preferences": [
                    {"Spread": {"SpreadDescriptor": "node.labels.zone"}},
                ],
                "MaxReplicas": 1,
            })
        );
    }

    #[test]
    fn a_spread_descriptor_keeps_the_expression_the_caller_wrote() {
        // Only the leading `spread=` is consumed. A descriptor is a label
        // expression and routinely contains dots, dashes, and further separators;
        // rewriting any of them would spread across a different set of nodes.
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                preferences: vec!["spread=node.labels.tier-web".to_owned()],
                ..ServicePlacement::default()
            }),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.tier-web"
        );
    }

    #[test]
    fn members_that_mean_nothing_are_omitted_rather_than_sent_empty() {
        // `MaxReplicas: 0` means "no limit", and an unset restriction is left
        // out rather than sent as an empty constraint list.
        let body = service_spec_body(&ServiceSpec::default()).expect("an empty specification");
        assert!(body.as_object().expect("an object").is_empty(), "{body}");
        let request = init_request(&SwarmInitOptions::default());
        assert!(
            request_body(&request)
                .as_object()
                .expect("an object")
                .is_empty()
        );
    }

    #[test]
    fn a_service_create_sends_the_versioned_path_and_the_whole_specification() {
        let request = service_create_request(&complete_spec()).expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/services/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "web");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Constraints"][0],
            "node.role == worker"
        );
    }

    #[test]
    fn a_service_update_carries_the_version_and_a_rollback_only_when_asked() {
        let plain = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: false,
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/services/web/update?version=7 HTTP/1.1")
        );
        // An update carries the same specification as a create, placement and
        // restart policy included: a conflict-safe update built from an inspect
        // has to keep the constraints it read.
        assert_eq!(
            request_body(&plain)["TaskTemplate"]["Placement"]["MaxReplicas"],
            2
        );
        assert_eq!(
            request_body(&plain)["TaskTemplate"]["RestartPolicy"]["Condition"],
            "on-failure"
        );
        // The Engine reads `rollback` as a task ID or the word `previous`, so
        // `rollback=false` would name a task called `false`.
        let rolled_back = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: true,
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&rolled_back),
            crate::raw::at_api_version(
                "POST /v1.API/services/web/update?version=7&rollback=previous HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_version_the_engine_cannot_express_is_refused_before_the_socket() {
        // The Engine declares the service parameter as `int32` and the others as
        // `int64`; a version that does not fit is a caller mistake rather than a
        // silent truncation into a different version.
        let service = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: u64::from(u32::MAX) + 1,
                spec: ServiceSpec::default(),
                rollback: false,
            },
        )
        .expect_err("too large for int32");
        assert_eq!(service.kind(), ErrorKind::InvalidVersion);
        let node = node_update_request(
            "node-1",
            &NodeUpdateOptions {
                version: u64::MAX,
                spec: NodeSpec::default(),
            },
        )
        .expect_err("too large for int64");
        assert_eq!(node.kind(), ErrorKind::InvalidVersion);
        let swarm = update_request(&SwarmUpdateOptions {
            version: u64::MAX,
            spec: SwarmSpec::default(),
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        })
        .expect_err("too large for int64");
        assert_eq!(swarm.kind(), ErrorKind::InvalidVersion);
    }

    #[test]
    fn every_list_sends_its_filters_only_when_there_are_some() {
        for (resource, request) in [
            (
                "services",
                service_list_request(&SwarmListOptions::default()),
            ),
            ("nodes", node_list_request(&SwarmListOptions::default())),
            ("tasks", task_list_request(&SwarmListOptions::default())),
            ("configs", config_list_request(&SwarmListOptions::default())),
            ("secrets", secret_list_request(&SwarmListOptions::default())),
        ] {
            assert_eq!(
                request_line(&request.expect("a request")),
                format!(
                    "GET {}/{resource} HTTP/1.1",
                    crate::raw::api_version_prefix()
                )
            );
        }
        let filtered = service_list_request(
            &SwarmListOptions::new()
                .with_filter("name", ["web"])
                .with_filter("label", ["tier=web"]),
        )
        .expect("a request");
        assert_eq!(
            request_line(&filtered),
            crate::raw::at_api_version(
                "GET /v1.API/services?filters=%7B%22label%22%3A%5B%22tier%3Dweb%22%5D%2C%22name%22%3A%5B%22web%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_reference_cannot_escape_its_own_path_segment() {
        assert_eq!(escape_path_segment("a/b"), "a%2Fb");
        assert_eq!(escape_path_segment("a%2Fb"), "a%252Fb");
        for untouched in ["web", "8c968e1567aaf07c", "a.b_c~d", "web.1.abc"] {
            assert_eq!(escape_path_segment(untouched), untouched);
        }
        assert_eq!(
            request_line(&service_inspect_request("a/b").expect("a request")),
            crate::raw::at_api_version("GET /v1.API/services/a%2Fb HTTP/1.1")
        );
        assert_eq!(
            request_line(&task_inspect_request("a/b").expect("a request")),
            crate::raw::at_api_version("GET /v1.API/tasks/a%2Fb HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_reference_is_refused_by_every_operation_that_takes_one() {
        let spec = ServiceSpec::default();
        let refusals: Vec<Error> = vec![
            service_inspect_request("").expect_err("empty"),
            service_remove_request("").expect_err("empty"),
            service_log_request("", &SwarmLogOptions::default()).expect_err("empty"),
            task_log_request("", &SwarmLogOptions::default()).expect_err("empty"),
            node_remove_request("", NodeRemoveOptions::default()).expect_err("empty"),
            service_update_request(
                "",
                &ServiceUpdateOptions {
                    version: 1,
                    spec: spec.clone(),
                    rollback: false,
                },
            )
            .expect_err("empty"),
            config_update_request("", 1, &SwarmConfigSpec::default()).expect_err("empty"),
            secret_update_request("", 1, &SwarmSecretSpec::default()).expect_err("empty"),
        ];
        assert_eq!(refusals.len(), 8);
        for error in refusals {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_reference_stays_one_path_segment_next_to_the_endpoint_suffix() {
        assert_eq!(
            resource_path("services", "web", "/update").expect("a path"),
            "/services/web/update"
        );
        assert_eq!(
            resource_path("tasks", "web.1.abc", "/logs").expect("a path"),
            "/tasks/web.1.abc/logs"
        );
    }

    #[test]
    fn swarm_init_sends_only_the_options_that_were_set() {
        assert_eq!(
            request_line(&init_request(&SwarmInitOptions::default())),
            crate::raw::at_api_version("POST /v1.API/swarm/init HTTP/1.1")
        );
        let request = init_request(&SwarmInitOptions {
            listen_address: Some("0.0.0.0:2377".to_owned()),
            advertise_address: Some("10.0.0.1:2377".to_owned()),
            data_path_address: Some("10.0.0.1".to_owned()),
            data_path_port: Some(4789),
            force_new_cluster: Some(true),
        });
        let body = request_body(&request);
        assert_eq!(body["ListenAddr"], "0.0.0.0:2377");
        assert_eq!(body["AdvertiseAddr"], "10.0.0.1:2377");
        assert_eq!(body["DataPathAddr"], "10.0.0.1");
        assert_eq!(body["DataPathPort"], 4789);
        assert_eq!(body["ForceNewCluster"], true);
    }

    #[test]
    fn a_join_with_no_manager_address_is_refused_rather_than_sent() {
        let error = join_request(&SwarmJoinOptions {
            token: "SWMTKN-1-x".to_owned(),
            ..SwarmJoinOptions::default()
        })
        .expect_err("no address to reach");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_join_carries_the_token_and_the_manager_addresses() {
        let request = join_request(&SwarmJoinOptions {
            token: "SWMTKN-1-x".to_owned(),
            remote_addresses: vec!["10.0.0.1:2377".to_owned()],
            ..SwarmJoinOptions::default()
        })
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/swarm/join HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["JoinToken"], "SWMTKN-1-x");
        assert_eq!(body["RemoteAddrs"][0], "10.0.0.1:2377");
        assert!(
            body.get("ListenAddr").is_none(),
            "an unset address is left out: {body}"
        );
    }

    #[test]
    fn a_leave_and_a_node_removal_spell_their_force_flag() {
        assert_eq!(
            request_line(&leave_request(SwarmLeaveOptions { force: true })),
            crate::raw::at_api_version("POST /v1.API/swarm/leave?force=true HTTP/1.1")
        );
        assert_eq!(
            request_line(&leave_request(SwarmLeaveOptions { force: false })),
            crate::raw::at_api_version("POST /v1.API/swarm/leave?force=false HTTP/1.1")
        );
        assert_eq!(
            request_line(
                &node_remove_request("node-1", NodeRemoveOptions { force: true })
                    .expect("a request")
            ),
            crate::raw::at_api_version("DELETE /v1.API/nodes/node-1?force=true HTTP/1.1")
        );
    }

    #[test]
    fn a_swarm_update_carries_the_version_and_every_rotation_flag() {
        let request = update_request(&SwarmUpdateOptions {
            version: 12,
            spec: SwarmSpec {
                name: Some("default".to_owned()),
                labels: Some(BTreeMap::from([("tier".to_owned(), "prod".to_owned())])),
                // A member the repository type does not name: the Engine's
                // `Orchestration` block. It has to reach the daemon, or a
                // conflict-safe update built from an inspect would delete it.
                additional: BTreeMap::from([(
                    String::from("Orchestration"),
                    serde_json::json!({"TaskHistoryRetentionLimit": 5}),
                )]),
            },
            rotate_worker_token: true,
            rotate_manager_token: false,
            rotate_manager_unlock_key: true,
        })
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/swarm/update?version=12&rotateWorkerToken=true&rotateManagerToken=false&rotateManagerUnlockKey=true HTTP/1.1"
            )
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "default");
        assert_eq!(body["Orchestration"]["TaskHistoryRetentionLimit"], 5);
    }

    #[test]
    fn an_unlock_names_the_endpoint_the_dependency_has_no_method_for() {
        let request = swarm_unlock_request(&SwarmUnlockOptions {
            key: "SWMKEY-1-x".to_owned(),
        });
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/swarm/unlock HTTP/1.1")
        );
        assert_eq!(request_body(&request)["UnlockKey"], "SWMKEY-1-x");
    }

    #[test]
    fn the_swarm_inspect_path_is_the_one_join_tokens_come_from() {
        assert_eq!(
            request_line(&swarm_inspect_request()),
            crate::raw::at_api_version("GET /v1.API/swarm HTTP/1.1")
        );
    }

    #[test]
    fn a_join_token_is_read_from_the_members_the_engine_spells_capitalized() {
        // `GET /swarm` is the only endpoint that reports tokens, and the members
        // are `Worker` and `Manager` — capitalized, unlike the role names the
        // CLI takes. A worker reports no manager token, and an empty token is
        // `None` rather than an empty string a caller could paste into a join.
        let document: SwarmInfo = decode(
            br#"{"ID":"sw","JoinTokens":{"Worker":"SWMTKN-1-worker","Manager":"SWMTKN-1-manager"}}"#,
        )
        .expect("a swarm document");
        assert_eq!(
            document
                .join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get(SwarmJoinTokenRole::Worker.join_token_member()))
                .and_then(serde_json::Value::as_str),
            Some("SWMTKN-1-worker")
        );
        assert_eq!(
            document
                .join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get(SwarmJoinTokenRole::Manager.join_token_member()))
                .and_then(serde_json::Value::as_str),
            Some("SWMTKN-1-manager")
        );
        let bare: SwarmInfo =
            decode(br#"{"ID":"sw","JoinTokens":{"Worker":""}}"#).expect("a swarm document");
        assert_eq!(
            bare.join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get("Manager"))
                .and_then(serde_json::Value::as_str),
            None
        );
    }

    #[test]
    fn a_swarm_document_keeps_the_members_the_typed_fields_do_not_name() {
        // `Orchestration` and `Dispatcher` are blocks of the specification that
        // the repository type does not name, and the token block is a member no
        // field names at all. A conflict-safe update built from this document has
        // to carry all three, or the daemon loses the settings and the caller
        // cannot join another node.
        let swarm: SwarmInfo = decode(SWARM.as_bytes()).expect("a swarm document");
        assert_eq!(swarm.id.as_deref(), Some("swarm-fixture"));
        assert_eq!(swarm.version, Some(SwarmVersion { index: Some(12) }));
        let spec = swarm.spec.as_ref().expect("the specification");
        assert_eq!(spec.name.as_deref(), Some("fixture-swarm"));
        assert_eq!(
            spec.additional["Orchestration"]["TaskHistoryRetentionLimit"],
            5
        );
        assert_eq!(
            spec.additional["Dispatcher"]["HeartbeatPeriod"],
            5_000_000_000i64
        );
        let tokens = swarm.join_tokens.as_ref().expect("the join tokens");
        assert_eq!(tokens["Worker"], "worker-token");
        assert_eq!(tokens["Manager"], "manager-token");
    }

    #[test]
    fn a_service_document_projects_the_typed_views_and_keeps_the_endpoint() {
        // `Endpoint` is where the published ports live, and the repository model
        // names them as a top-level member. The endpoint is also kept whole, so a
        // member of it that no typed field names — a port's `Name`, say — is not
        // lost on the way through.
        let document: ServiceDocument = decode(SERVICE.as_bytes()).expect("a service document");
        let service = SwarmService::try_from(document).expect("it converts");
        assert_eq!(service.id.as_deref(), Some("service0123456789abcdef"));
        assert_eq!(service.version, Some(SwarmVersion { index: Some(7) }));
        assert_eq!(
            service.additional["Endpoint"]["Ports"][0]["PublishedPort"],
            8080
        );
        let ports = service.ports.as_ref().expect("the published ports");
        assert_eq!(ports[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(ports[0].target_port, Some(80));
        assert_eq!(ports[0].published_port, Some(8080));
        assert_eq!(
            service.status,
            Some(ServiceStatus {
                running_tasks: 2,
                desired_tasks: 2,
            })
        );
        let spec = service.spec.as_ref().expect("the specification");
        assert_eq!(spec.name.as_deref(), Some("web"));
        assert_eq!(
            spec.task_template
                .as_ref()
                .and_then(|template| template.get("ContainerSpec")),
            Some(&serde_json::json!({"Image": "nginx:alpine"}))
        );
    }

    #[test]
    fn every_list_answer_decodes_into_its_own_model() {
        let services = project::<SwarmService, ServiceDocument>(SERVICES);
        let nodes = project::<SwarmNode, NodeDocument>(NODES);
        let tasks = project::<SwarmTask, TaskDocument>(TASKS);
        let configs = project::<SwarmConfig, ConfigDocument>(CONFIGS);
        let secrets = project::<SwarmSecret, SecretDocument>(SECRETS);
        assert_eq!(services.len(), 1);
        assert_eq!(nodes.len(), 1);
        assert_eq!(tasks.len(), 1);
        assert_eq!(configs.len(), 1);
        assert_eq!(secrets.len(), 1);
        // `PreviousSpec` is what a rollback restores, and no typed field names
        // it, so it is retained beside the specification the model does have.
        // A decode that dropped it would leave a rollback with nothing to
        // restore.
        assert_eq!(
            services[0].additional["PreviousSpec"]["TaskTemplate"]["ContainerSpec"]["Image"],
            "nginx:1.25"
        );
        assert_eq!(
            nodes[0]
                .status
                .as_ref()
                .and_then(|status| status.get("Addr"))
                .and_then(serde_json::Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            tasks[0]
                .status
                .as_ref()
                .and_then(|status| status.error.as_deref()),
            Some("pull access denied")
        );
    }

    #[test]
    fn a_node_document_reads_the_engine_version_out_of_the_description() {
        let document: NodeDocument = decode(NODE.as_bytes()).expect("a node document");
        let node = SwarmNode::try_from(document).expect("it converts");
        assert_eq!(node.engine_version.as_deref(), Some("27.1.1"));
        // The description is kept whole, so a member of it the projection does
        // not read is not lost.
        assert_eq!(
            node.additional["Description"]["Engine"]["EngineVersion"],
            "27.1.1"
        );
        let spec = node.spec.as_ref().expect("the node specification");
        assert_eq!(spec.role.as_deref(), Some("manager"));
        assert_eq!(spec.availability.as_deref(), Some("active"));
        let manager = node.manager_status.as_ref().expect("the manager status");
        assert_eq!(manager.leader, Some(true));
        assert_eq!(manager.reachability.as_deref(), Some("reachable"));
    }

    #[test]
    fn a_task_document_reads_the_image_out_of_the_container_specification() {
        let document: TaskDocument = decode(TASK.as_bytes()).expect("a task document");
        let task = SwarmTask::try_from(document).expect("it converts");
        assert_eq!(task.image.as_deref(), Some("nginx:alpine"));
        assert_eq!(task.service_id, "service0123456789abcdef");
        assert_eq!(task.slot, 1);
        assert_eq!(task.node_id, "node0123456789abcdef");
        assert_eq!(task.name.as_deref(), Some("web.1"));
        let status = task.status.as_ref().expect("the task status");
        assert_eq!(status.state.as_deref(), Some("running"));
        assert_eq!(status.message.as_deref(), Some("started"));
        // The specification is kept whole beside the typed image.
        assert_eq!(
            task.additional["Spec"]["ContainerSpec"]["Image"],
            "nginx:alpine"
        );
    }

    #[test]
    fn a_task_that_has_not_been_assigned_still_decodes() {
        // An unassigned task reports an empty `NodeID`, and a task document that
        // omits the member entirely must not become a decode failure: waiting for
        // a node is a normal state, not a broken answer.
        let document: TaskDocument =
            decode(br#"{"ID":"t","ServiceID":"s","Slot":0,"Status":{"State":"pending"}}"#)
                .expect("a task document");
        let task = SwarmTask::try_from(document).expect("it converts");
        assert_eq!(task.node_id, "");
        assert_eq!(task.slot, 0);
        assert_eq!(task.image, None);
    }

    #[test]
    fn a_config_document_keeps_its_data_and_a_secret_document_keeps_its_driver() {
        let config = SwarmConfig::try_from(
            decode::<ConfigDocument>(CONFIG.as_bytes()).expect("a config document"),
        )
        .expect("it converts");
        assert_eq!(config.id.as_deref(), Some("config0123456789abcdef"));
        let spec = config.spec.as_ref().expect("the config specification");
        assert_eq!(spec.name.as_deref(), Some("app-config"));
        // The Engine base64-encodes config data on the wire.
        assert_eq!(spec.data.as_deref(), Some("aGVsbG8="));

        let secret = SwarmSecret::try_from(
            decode::<SecretDocument>(SECRET.as_bytes()).expect("a secret document"),
        )
        .expect("it converts");
        assert_eq!(secret.id.as_deref(), Some("secret0123456789abcdef"));
        let spec = secret.spec.as_ref().expect("the secret specification");
        assert_eq!(spec.name.as_deref(), Some("db-password"));
        assert_eq!(
            spec.driver.as_ref().and_then(|driver| driver.get("Name")),
            Some(&serde_json::json!("vault"))
        );
    }

    #[test]
    fn a_config_create_base64_encodes_the_data_the_engine_declares() {
        let request = config_create_request(&ConfigCreateOptions {
            name: "app-config".to_owned(),
            data: Some(b"hello".to_vec()),
            labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
        });
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/configs/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "app-config");
        assert_eq!(body["Labels"]["tier"], "web");
        assert_eq!(body["Data"], "aGVsbG8=");
    }

    #[test]
    fn a_create_with_no_bytes_omits_the_data_member() {
        // A missing `Data` asks the daemon for an external object; an empty
        // string asks it to store nothing at all.
        let config = request_body(&config_create_request(&ConfigCreateOptions {
            name: "external".to_owned(),
            data: None,
            labels: None,
        }));
        assert!(config.get("Data").is_none(), "{config}");
        let secret = request_body(&secret_create_request(&SecretCreateOptions::new(
            "external", None,
        )));
        assert!(secret.get("Data").is_none(), "{secret}");
    }

    #[test]
    fn a_secret_create_base64_encodes_the_callers_bytes() {
        let request = secret_create_request(&SecretCreateOptions::new(
            "db-password",
            Some(SwarmSecretData::new(b"s3cret".to_vec())),
        ));
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/secrets/create HTTP/1.1")
        );
        assert_eq!(request_body(&request)["Data"], "czNjcmV0");
    }

    #[test]
    fn a_create_answer_with_no_id_is_an_error_rather_than_an_empty_resource() {
        // The caller has no other way to learn what was created, so a missing
        // `ID` is reported instead of answered with an empty string.
        let error = id_from(r#"{"Warnings":[]}"#.as_bytes()).expect_err("no ID");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            id_from(r#"{"ID":"cfg-1"}"#.as_bytes()).expect("an ID"),
            "cfg-1"
        );
    }

    #[test]
    fn a_config_update_leaves_the_read_only_data_member_out() {
        // The Engine's update endpoint cannot change a config's data, and the
        // repository specification carries it because an inspect answer does.
        let request = config_update_request(
            "app-config",
            3,
            &SwarmConfigSpec {
                name: Some("app-config".to_owned()),
                labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
                data: Some("aGVsbG8=".to_owned()),
                additional: BTreeMap::new(),
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/configs/app-config/update?version=3 HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "app-config");
        assert_eq!(body["Labels"]["tier"], "web");
        assert!(body.get("Data").is_none(), "{body}");
    }

    #[test]
    fn a_secret_update_sends_the_version_and_the_metadata() {
        let request = secret_update_request(
            "db-password",
            2,
            &SwarmSecretSpec {
                name: Some("db-password".to_owned()),
                labels: None,
                driver: Some(serde_json::json!({"Name": "vault"})),
                additional: BTreeMap::new(),
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/secrets/db-password/update?version=2 HTTP/1.1"
            )
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "db-password");
        // The driver is not part of an update: the Engine's endpoint reads the
        // name and labels, and a member it does not read is not sent.
        assert!(body.get("Driver").is_none(), "{body}");
    }

    #[test]
    fn a_node_update_sends_the_repository_node_specification() {
        let request = node_update_request(
            "node-1",
            &NodeUpdateOptions {
                version: 4,
                spec: NodeSpec {
                    name: Some("manager-one".to_owned()),
                    role: Some("manager".to_owned()),
                    availability: Some("drain".to_owned()),
                    labels: Some(BTreeMap::from([(
                        "org.example.node".to_owned(),
                        "fixture".to_owned(),
                    )])),
                    additional: BTreeMap::new(),
                },
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/nodes/node-1/update?version=4 HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "manager-one");
        assert_eq!(body["Role"], "manager");
        assert_eq!(body["Availability"], "drain");
        assert_eq!(body["Labels"]["org.example.node"], "fixture");
    }

    #[test]
    fn a_service_create_answer_is_read_from_the_id_member_not_the_container_one() {
        // The container create endpoint answers `{"Id":…}` and this one answers
        // `{"ID":…}`. A client that spelled it the container way would report an
        // empty service ID for a service that was created.
        let document: ServiceCreateDocument =
            decode(br#"{"ID":"svc-1","Warnings":["no suitable nodes"]}"#)
                .expect("a create document");
        let result = ServiceCreateResult::from(document);
        assert_eq!(result.id, "svc-1");
        assert_eq!(result.warnings, vec!["no suitable nodes".to_owned()]);
        let bare: ServiceCreateDocument =
            decode(r#"{"ID":"svc-1"}"#.as_bytes()).expect("a create document");
        assert!(ServiceCreateResult::from(bare).warnings.is_empty());
    }

    #[test]
    fn a_service_update_answer_carries_only_warnings() {
        let document: ServiceUpdateDocument =
            decode(br#"{"Warnings":["rolling back"]}"#).expect("an update document");
        assert_eq!(
            ServiceUpdateResult::from(document).warnings,
            vec!["rolling back".to_owned()]
        );
        let empty: ServiceUpdateDocument = decode(b"{}").expect("an update document");
        assert!(ServiceUpdateResult::from(empty).warnings.is_empty());
    }

    #[test]
    fn service_and_task_logs_send_the_parameters_their_endpoints_declare() {
        // The service endpoint declares `details`, `follow`, `stdout`, `stderr`,
        // `since`, `until`, `timestamps`, and `tail`. The task endpoint declares
        // only the last four, so the first four are not sent to it.
        let options = SwarmLogOptions {
            follow: true,
            stdout: true,
            stderr: true,
            since: 1,
            until: 2,
            timestamps: true,
            tail: "50".to_owned(),
        };
        assert_eq!(
            request_line(&service_log_request("web", &options).expect("a request")),
            crate::raw::at_api_version(
                "GET /v1.API/services/web/logs?details=true&follow=true&stdout=true&stderr=true\
             &since=1&until=2&timestamps=true&tail=50 HTTP/1.1"
            )
        );
        assert_eq!(
            request_line(&task_log_request("web.1.abc", &options).expect("a request")),
            crate::raw::at_api_version(
                "GET /v1.API/tasks/web.1.abc/logs?since=1&until=2&timestamps=true&tail=50 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_logs_query_says_what_it_meant_even_when_nothing_is_selected() {
        // The repository's log options default both streams to `false`, so a
        // caller that only sets `tail` gets an empty body. That is the option
        // type's choice, and it is visible in the request line rather than
        // hidden, which is the point of spelling every parameter.
        let request = service_log_request("web", &SwarmLogOptions::default()).expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/services/web/logs?details=true&follow=false&stdout=false&stderr=false\
             &since=0&until=0&timestamps=false&tail=all HTTP/1.1"
            )
        );
    }
}
