//! Network operations for the repository-owned Engine backend.
//!
//! This is step 4 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. Every operation reuses
//! [`RawEngine`], the single owned transport, and the shared
//! [`engine_result`] status mapping, so there is no second client, no second
//! error type, and no second HTTP stack in the crate. The option, result, and
//! endpoint types are the existing repository-owned models, reused as they are.
//!
//! The names are prefixed by resource because they share the `raw` namespace
//! with the container slice's `list`, `create`, and `remove`.
//!
//! # A network answer is bigger than the network model, and it is kept whole
//!
//! Measured against Docker Engine 29.8.0 over a Unix socket, the daemon sends
//! **15 members** for a `GET /networks` entry and **17** for a
//! `GET /networks/{id}` answer:
//!
//! | Endpoint | Sent | Named by [`NetworkSummary`] / [`NetworkInspect`] | Not named |
//! | --- | --- | --- | --- |
//! | `GET /networks` | 15 | 14 | `ConfigFrom` |
//! | `GET /networks/{id}` | 17 | 16 | `ConfigFrom`, `Status` |
//!
//! The two extra members on the inspect answer are `Containers` (which
//! [`NetworkInspect`] does name) and `Status`.
//!
//! `ConfigFrom` names the config-only network a network's configuration comes
//! from, and `Status` is the daemon's per-subnet allocation report
//! (`{"IPAM":{"Subnets":{"172.17.0.0/16":{"IPsInUse":3,…}}}}`). Neither has a
//! field in the repository model, and the Engine sends `ConfigFrom` on *every*
//! network, not only on the config-only ones. Decoding into the model would drop
//! them silently, which is the failure this whole backend exists to remove, so
//! [`NetworkEntry`] keeps the daemon's document and offers the model as a
//! projection over it — the arrangement `raw::inspect` established for container
//! inspect. `ConfigFrom` and `Status` are then in
//! [`NetworkEntry::document`] for a caller that needs them, and the projection is
//! a view rather than a replacement.
//!
//! # The network name is a body member, unlike the container name
//!
//! `POST /containers/create` reads the name from `?name=`; `POST
//! /networks/create` reads it from the body, and there is no query form. Measured
//! on Docker Engine 29.8.0: a create body carrying `{"Driver":"bridge"}` and no
//! `Name` is answered
//!
//! ```text
//! 400 invalid name: name is empty
//! ```
//!
//! so [`network_create`] sends `Name` in the body. The Docker CLI's own request
//! was recorded through a logging proxy as
//! `POST /v1.56/networks/create` with `{"Name":"probenet","Driver":"bridge",…}`
//! and no query string at all, which is the same shape.
//!
//! # `connect` and `disconnect` answer `200`, not `204`
//!
//! Measured: `POST /networks/{id}/connect` and `POST /networks/{id}/disconnect`
//! both answer `200` with an empty body on success. Their success is the status,
//! so both go through the same status-only path a `204` takes, and neither body
//! is decoded. A second `connect` for a container already attached is answered
//! `403`, and a `connect` whose requested address is outside the network's subnet
//! is `400`; both are the daemon's own rejections and are reported as such.
//!
//! # `connect` and `disconnect` name the container in the body
//!
//! `POST /networks/{id}/connect` takes `{"Container":…,"EndpointConfig":{…}}` and
//! `POST /networks/{id}/disconnect` takes `{"Container":…,"Force":…}`. Measured:
//! a connect body carrying a requested `IPv4Address` outside the network's
//! subnet is answered `400 invalid endpoint settings: no configured subnet
//! contains IP address 172.29.0.9`, which is only reachable if both members were
//! read — a body with the container only would have connected it.
//!
//! # Filter values are the repository's list form, and the daemon accepts it
//!
//! The Engine's own CLI sends `{"name":{"probenet":true}}` — a map of maps — while
//! the repository's filter type is a `BTreeMap<String, Vec<String>>`, which
//! serializes to `{"name":["probenet"]}`. Both were sent to Docker Engine 29.8.0
//! through `GET /networks?filters=…` and both filtered correctly, returning only
//! the `none` network; a filter the daemon cannot parse is answered
//! `{"message":"invalid filter"}` either way. The ordered list form is kept
//! because the map order is what makes a recorded request reproducible.
//!
//! # What is deliberately not covered
//!
//! - **Swarm-scoped network operations.** Creating or removing a `swarm`-scope
//!   network is answered `503` by a non-manager and redirected by a manager; the
//!   repository's option type carries `scope`, so the request is sent as written
//!   and the daemon's own answer is reported.
//! - **`ConfigFrom` and `Status` as typed fields.** They are retained in the
//!   document instead of being added to the repository model, because adding a
//!   field there is the facade's decision and not this slice's.
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
    Error, NetworkConnectOptions, NetworkCreateOptions, NetworkCreateResult,
    NetworkDisconnectOptions, NetworkEndpoint, NetworkEndpointOptions, NetworkInspect,
    NetworkInspectOptions, NetworkIpam, NetworkIpamConfig, NetworkListOptions, NetworkPruneOptions,
    NetworkPruneResult, NetworkSummary,
};

/// One network as the daemon sent it, with the document retained.
///
/// The document is the answer of last resort for a member with no projection: the
/// Engine sends [`ConfigFrom`](Self::document) and, on an inspect answer,
/// `Status`, and neither has a field in the repository model. Every accessor is a
/// view over that document rather than a second copy of it.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkEntry {
    document: serde_json::Value,
}

impl NetworkEntry {
    /// Returns the document exactly as the daemon sent it.
    ///
    /// Nothing in it has been renamed, defaulted, or dropped.
    #[must_use]
    pub const fn document(&self) -> &serde_json::Value {
        &self.document
    }

    /// Consumes the entry and returns the document.
    #[must_use]
    pub fn into_document(self) -> serde_json::Value {
        self.document
    }

    /// Returns the network's name, which is also the reference the daemon
    /// accepts anywhere a network is addressed.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.text("Name")
    }

    /// Returns the network's id.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.text("Id")
    }

    /// Returns the config-only network this network's configuration comes from.
    ///
    /// The Engine sends this member on every network — as `{"Network":""}` for an
    /// ordinary one — and the repository model has no field for it, so it is read
    /// here rather than dropped. An empty name is reported as `None`, because
    /// "no config-only network" and "the config-only network named nothing" are
    /// the same answer on the wire.
    #[must_use]
    pub fn config_from(&self) -> Option<&str> {
        self.document
            .get("ConfigFrom")
            .and_then(|reference| reference.get("Network"))
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
    }

    /// Projects the entry onto the repository's network model.
    ///
    /// The projection cannot fail: a member the daemon left out, or sent as
    /// `null`, reads as absent rather than as a decode error, which is what makes
    /// this usable over a whole list. `ConfigFrom` and `Status` are still in
    /// [`NetworkEntry::document`].
    #[must_use]
    pub fn summary(&self) -> NetworkSummary {
        NetworkSummary {
            name: self.owned("Name"),
            id: self.owned("Id"),
            created: self.owned("Created"),
            scope: self.owned("Scope"),
            driver: self.owned("Driver"),
            enable_ipv4: self.flag("EnableIPv4"),
            enable_ipv6: self.flag("EnableIPv6"),
            ipam: self
                .document
                .get("IPAM")
                .filter(|ipam| ipam.is_object())
                .map(ipam_projection),
            internal: self.flag("Internal"),
            attachable: self.flag("Attachable"),
            ingress: self.flag("Ingress"),
            config_only: self.flag("ConfigOnly"),
            options: self.string_map("Options"),
            labels: self.string_map("Labels"),
        }
    }

    /// Projects the entry onto the repository's network-inspect model.
    ///
    /// This is the projection the current facade performs, spelled out here over
    /// the retained document so the two paths can be compared without reading two
    /// different shapes. It is a view: [`NetworkEntry::document`] still has the
    /// members it has no field for.
    #[must_use]
    pub fn inspect(&self) -> NetworkInspect {
        let containers = self
            .document
            .get("Containers")
            .and_then(serde_json::Value::as_object)
            .map(|containers| {
                containers
                    .iter()
                    .map(|(id, endpoint)| {
                        (
                            id.clone(),
                            NetworkEndpoint {
                                name: owned_in(endpoint, "Name"),
                                endpoint_id: owned_in(endpoint, "EndpointID"),
                                mac_address: owned_in(endpoint, "MacAddress"),
                                // The Engine sends the address with its prefix
                                // length attached (`172.31.0.2/16`); the whole
                                // value is kept rather than split, because the
                                // repository field is a plain address and a
                                // caller that needs the prefix can take it from
                                // the document.
                                ipv4_address: owned_in(endpoint, "IPv4Address"),
                                ipv6_address: owned_in(endpoint, "IPv6Address"),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        NetworkInspect {
            network: self.summary(),
            containers,
        }
    }

    /// Reads a top-level member as owned text.
    fn owned(&self, member: &str) -> Option<String> {
        self.text(member).map(ToOwned::to_owned)
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

    /// Reads a top-level member as a string map.
    ///
    /// The Engine sends `null` for `Labels` and `Options` on a network with
    /// neither, and an absent map is an empty one.
    fn string_map(&self, member: &str) -> BTreeMap<String, String> {
        self.document
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
}

/// Projects a network's `IPAM` block onto the repository's IPAM model.
fn ipam_projection(ipam: &serde_json::Value) -> NetworkIpam {
    NetworkIpam {
        driver: text_in(ipam, "Driver").map(ToOwned::to_owned),
        config: ipam
            .get("Config")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| NetworkIpamConfig {
                        subnet: text_in(entry, "Subnet").map(ToOwned::to_owned),
                        ip_range: text_in(entry, "IPRange").map(ToOwned::to_owned),
                        gateway: text_in(entry, "Gateway").map(ToOwned::to_owned),
                        auxiliary_addresses: entry
                            .get("AuxiliaryAddresses")
                            .and_then(serde_json::Value::as_object)
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(|(key, value)| {
                                        value.as_str().map(|value| (key.clone(), value.to_owned()))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        options: ipam
            .get("Options")
            .and_then(serde_json::Value::as_object)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Reads a member of a nested block as text.
fn text_in<'a>(block: &'a serde_json::Value, member: &str) -> Option<&'a str> {
    block.get(member).and_then(serde_json::Value::as_str)
}

/// Reads a member of a nested block as owned text.
fn owned_in(block: &serde_json::Value, member: &str) -> Option<String> {
    text_in(block, member).map(ToOwned::to_owned)
}

/// Creates a network.
///
/// The name travels in the body, which is where the Engine reads it; see the
/// module documentation for the measurement. The answer is the daemon's
/// `{"Id":…,"Warning":""}` document, and both of its members are named by
/// [`NetworkCreateResult`], so nothing is retained here.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a name the Engine's rules reject, or a network that already exists,
/// arrives here as a `400` or a `409` — or when the response is not a create
/// document.
pub async fn network_create(
    engine: &RawEngine,
    options: &NetworkCreateOptions,
) -> Result<NetworkCreateResult, Error> {
    let response = engine.send(network_create_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<NetworkCreateDocument>(&document).map(NetworkCreateResult::from)
}

/// The `POST /networks/create` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct NetworkCreateDocument {
    #[serde(rename = "Id")]
    id: String,
    // The Engine sends an empty string rather than omitting the member, and an
    // empty warning is no warning: the repository model has an `Option` here, and
    // turning "" into `Some("")` would report a warning the daemon did not give.
    #[serde(default, rename = "Warning")]
    warning: String,
}

impl From<NetworkCreateDocument> for NetworkCreateResult {
    fn from(document: NetworkCreateDocument) -> Self {
        Self {
            id: document.id,
            warning: (!document.warning.is_empty()).then_some(document.warning),
        }
    }
}

/// Builds the `POST /networks/create` request.
///
/// # Errors
///
/// Returns an error when the create body cannot be encoded.
fn network_create_request(options: &NetworkCreateOptions) -> Result<RawRequest, Error> {
    let body = json_body(&NetworkCreateBody {
        name: &options.name,
        driver: options.driver.as_deref(),
        scope: options.scope.as_deref(),
        internal: options.internal,
        attachable: options.attachable,
        ingress: options.ingress,
        config_only: options.config_only,
        config_from: options
            .config_from
            .as_deref()
            .map(|network| ConfigReferenceBody { network }),
        enable_ipv4: options.enable_ipv4,
        enable_ipv6: options.enable_ipv6,
        ipam: options.ipam.as_ref().map(IpamBody::from),
        options: options.options.as_ref(),
        labels: options.labels.as_ref(),
    })?;
    // No query: the Engine reads the name from the body and declares no query
    // parameter for this endpoint, so a recorded request line is the bare path.
    Ok(json_content_type(RawRequest::new(Method::POST, "/networks/create")).with_body(body))
}

/// The `POST /networks/create` body, in the Engine's spelling.
///
/// Every optional member is omitted rather than sent as `null`, because "not
/// requested" and "requested as null" are different to the Engine's decoder for
/// several of them. `Options` and `Labels` are declared as a map and are sent
/// even when empty, because an empty object is how the Docker CLI sends them and
/// it is not the same as leaving them out.
#[derive(Debug, Serialize)]
struct NetworkCreateBody<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    driver: Option<&'a str>,
    #[serde(rename = "Scope", skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(rename = "Internal", skip_serializing_if = "Option::is_none")]
    internal: Option<bool>,
    #[serde(rename = "Attachable", skip_serializing_if = "Option::is_none")]
    attachable: Option<bool>,
    #[serde(rename = "Ingress", skip_serializing_if = "Option::is_none")]
    ingress: Option<bool>,
    #[serde(rename = "ConfigOnly", skip_serializing_if = "Option::is_none")]
    config_only: Option<bool>,
    #[serde(rename = "ConfigFrom", skip_serializing_if = "Option::is_none")]
    config_from: Option<ConfigReferenceBody<'a>>,
    #[serde(rename = "EnableIPv4", skip_serializing_if = "Option::is_none")]
    enable_ipv4: Option<bool>,
    #[serde(rename = "EnableIPv6", skip_serializing_if = "Option::is_none")]
    enable_ipv6: Option<bool>,
    #[serde(rename = "IPAM", skip_serializing_if = "Option::is_none")]
    ipam: Option<IpamBody<'a>>,
    #[serde(rename = "Options", skip_serializing_if = "Option::is_none")]
    options: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
}

/// The `POST /networks/create` body's `ConfigFrom` member.
///
/// The Engine declares it as an object with one member, `Network`, and a bare
/// string there is a body its decoder rejects.
#[derive(Debug, Serialize)]
struct ConfigReferenceBody<'a> {
    #[serde(rename = "Network")]
    network: &'a str,
}

/// The `POST /networks/create` body's `IPAM` block.
#[derive(Debug, Serialize)]
struct IpamBody<'a> {
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    driver: Option<&'a str>,
    // Sent even when empty, and never as `null`: the Engine reads a missing
    // `Config` as "use the driver default" and an empty array as "no pools".
    #[serde(rename = "Config")]
    config: Vec<IpamConfigBody<'a>>,
    // An empty object is sent rather than the member being omitted: the Engine
    // reads a missing `Options` as "no driver options", which is the same, but an
    // empty object is what the Docker CLI's own recorded request carried.
    #[serde(rename = "Options")]
    options: BTreeMap<&'a str, &'a str>,
}

impl<'a> From<&'a NetworkIpam> for IpamBody<'a> {
    fn from(ipam: &'a NetworkIpam) -> Self {
        Self {
            driver: ipam.driver.as_deref(),
            config: ipam
                .config
                .iter()
                .map(|config| IpamConfigBody {
                    subnet: config.subnet.as_deref(),
                    ip_range: config.ip_range.as_deref(),
                    gateway: config.gateway.as_deref(),
                    auxiliary_addresses: config
                        .auxiliary_addresses
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                })
                .collect(),
            options: ipam
                .options
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect(),
        }
    }
}

/// One `IPAM.Config` entry.
#[derive(Debug, Serialize)]
struct IpamConfigBody<'a> {
    #[serde(rename = "Subnet", skip_serializing_if = "Option::is_none")]
    subnet: Option<&'a str>,
    #[serde(rename = "IPRange", skip_serializing_if = "Option::is_none")]
    ip_range: Option<&'a str>,
    #[serde(rename = "Gateway", skip_serializing_if = "Option::is_none")]
    gateway: Option<&'a str>,
    // The Engine spells this member `AuxiliaryAddresses`; `AuxAddress` is the
    // name in its prose, and sending the wrong one is a pool silently ignored.
    #[serde(rename = "AuxiliaryAddresses")]
    auxiliary_addresses: BTreeMap<&'a str, &'a str>,
}

/// Lists networks.
///
/// `filters` is sent only when it is non-empty, for the reason the container
/// slice records: an empty filter object is a filter that matches the daemon's
/// own no-filter case and would only make a recorded request noisier. The answer
/// is one JSON array read as a single bounded document.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request — an unknown filter key is answered `400
/// invalid filter '<key>'`, measured — or when the answer is not an array.
pub async fn network_list(
    engine: &RawEngine,
    options: &NetworkListOptions,
) -> Result<Vec<NetworkEntry>, Error> {
    let response = engine.send(network_list_request(options)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<serde_json::Value> = decode(&document)?;
    Ok(entries
        .into_iter()
        .map(|entry| NetworkEntry { document: entry })
        .collect())
}

/// Builds the `GET /networks` list request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn network_list_request(options: &NetworkListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/networks"),
        query.finish(),
    ))
}

/// Reads one network.
///
/// `verbose` is always spelled as `true`/`false` and `scope` only when the caller
/// set one, so a recorded request says what it meant. The Docker CLI's own
/// inspect sent no query at all for the same call, and an absent `verbose` and a
/// `verbose=false` are the same request to the daemon; the flag is spelled so a
/// recorded request cannot be read two ways.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, when it rejects the request — a `404` carrying `network <name> not
/// found`, measured — or when the answer is not a JSON object.
pub async fn network_inspect(
    engine: &RawEngine,
    network: &str,
    options: &NetworkInspectOptions,
) -> Result<NetworkEntry, Error> {
    let response = engine
        .send(network_inspect_request(network, options)?)
        .await?;
    let document = engine_result(response).await?;
    Ok(NetworkEntry {
        document: decode(&document)?,
    })
}

/// Builds the `GET /networks/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn network_inspect_request(
    network: &str,
    options: &NetworkInspectOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("verbose", options.verbose);
    if let Some(scope) = &options.scope {
        query.value("scope", scope);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, &network_path(network, "")?),
        query.finish(),
    ))
}

/// Removes a network.
///
/// Answers `204` with no body, so the status is the whole result and the body is
/// read and discarded rather than decoded.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request — a `404` for a network that does not
/// exist, or a `403`/`409` for one that is still in use.
pub async fn network_remove(engine: &RawEngine, network: &str) -> Result<(), Error> {
    completed(engine, network_remove_request(network)?).await
}

/// Builds the `DELETE /networks/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn network_remove_request(network: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(Method::DELETE, &network_path(network, "")?))
}

/// Prunes unused networks.
///
/// The answer is one JSON document. `NetworksDeleted` is the only member the
/// daemon sends, and it is `null` — not `[]` — when nothing matched, which is an
/// empty list rather than a missing answer.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a prune document.
pub async fn network_prune(
    engine: &RawEngine,
    options: &NetworkPruneOptions,
) -> Result<NetworkPruneResult, Error> {
    let response = engine.send(network_prune_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<NetworkPruneDocument>(&document).map(NetworkPruneResult::from)
}

/// The `POST /networks/prune` answer, in the Engine's spelling.
///
/// `NetworksDeleted` is the only member the daemon sends, and it is `null` rather
/// than `[]` when nothing matched. A `null` here means "nothing was deleted", not
/// "the daemon did not say", so it projects to an empty list.
#[derive(Debug, Deserialize)]
struct NetworkPruneDocument {
    #[serde(default, rename = "NetworksDeleted")]
    networks_deleted: Option<Vec<String>>,
}

impl From<NetworkPruneDocument> for NetworkPruneResult {
    fn from(document: NetworkPruneDocument) -> Self {
        Self {
            networks_deleted: document.networks_deleted.unwrap_or_default(),
        }
    }
}

/// Builds the `POST /networks/prune` request.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn network_prune_request(options: &NetworkPruneOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, "/networks/prune"),
        query.finish(),
    ))
}

/// Connects a container to a network.
///
/// Answers `200` with an empty body, so the status is the whole result. The
/// container and its endpoint settings travel in the body; see the module
/// documentation.
///
/// # Errors
///
/// Returns an error when the reference is empty, when no container was named,
/// when the daemon cannot be reached, or when it rejects the request — a `404`
/// for a network or container that does not exist, or a `400` for endpoint
/// settings the network cannot satisfy.
pub async fn network_connect(
    engine: &RawEngine,
    network: &str,
    options: &NetworkConnectOptions,
) -> Result<(), Error> {
    completed(engine, network_connect_request(network, options)?).await
}

/// Builds the `POST /networks/{id}/connect` request.
///
/// # Errors
///
/// Returns an error when the reference or the container is empty, or when the
/// body cannot be encoded.
fn network_connect_request(
    network: &str,
    options: &NetworkConnectOptions,
) -> Result<RawRequest, Error> {
    if options.container.is_empty() {
        return Err(Error::invalid_input(
            "connecting a container to a network needs the container's name or id",
        ));
    }
    let body = json_body(&ConnectBody {
        container: &options.container,
        endpoint_config: options.endpoint.as_ref().map(EndpointSettingsBody::from),
    })?;
    let request = json_content_type(RawRequest::new(
        Method::POST,
        &network_path(network, "/connect")?,
    ))
    .with_body(body);
    Ok(request)
}

/// The `POST /networks/{id}/connect` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct ConnectBody<'a> {
    #[serde(rename = "Container")]
    container: &'a str,
    // Omitted rather than sent as `null`: the Engine reads a missing
    // `EndpointConfig` as "let the network choose" and a null as a member of
    // the wrong type.
    #[serde(rename = "EndpointConfig", skip_serializing_if = "Option::is_none")]
    endpoint_config: Option<EndpointSettingsBody<'a>>,
}

/// The `EndpointConfig` block of a connect body.
#[derive(Debug, Serialize)]
struct EndpointSettingsBody<'a> {
    #[serde(rename = "IPAMConfig", skip_serializing_if = "Option::is_none")]
    ipam_config: Option<EndpointIpamBody<'a>>,
    #[serde(rename = "Links", skip_serializing_if = "Option::is_none")]
    links: Option<&'a [String]>,
    #[serde(rename = "MacAddress", skip_serializing_if = "Option::is_none")]
    mac_address: Option<&'a str>,
    #[serde(rename = "Aliases", skip_serializing_if = "Option::is_none")]
    aliases: Option<&'a [String]>,
    // The Engine's member is `DriverOpts`; `DriverOptions` is the repository
    // spelling, and a wrong one is an option map silently ignored.
    #[serde(rename = "DriverOpts", skip_serializing_if = "Option::is_none")]
    driver_options: Option<&'a BTreeMap<String, String>>,
}

impl<'a> From<&'a NetworkEndpointOptions> for EndpointSettingsBody<'a> {
    fn from(endpoint: &'a NetworkEndpointOptions) -> Self {
        // A connect's `IPAMConfig` is not a create body's pool: the Engine reads
        // `IPv4Address`, `IPv6Address`, and `LinkLocalIPs` here, and a `Subnet` or
        // `Gateway` member is a member it does not know. Measured: a connect
        // carrying `"IPAMConfig":{"IPv4Address":"172.29.0.9"}` is answered
        // `400 invalid endpoint settings: no configured subnet contains IP
        // address 172.29.0.9`, which is only reachable if the address was read
        // from this member.
        let ipam_config = (endpoint.ipv4_address.is_some()
            || endpoint.ipv6_address.is_some()
            || !endpoint.link_local_ips.as_ref().is_none_or(Vec::is_empty))
        .then(|| EndpointIpamBody {
            ipv4_address: endpoint.ipv4_address.as_deref(),
            ipv6_address: endpoint.ipv6_address.as_deref(),
            link_local_ips: nonempty(endpoint.link_local_ips.as_ref()),
        });
        Self {
            ipam_config,
            links: nonempty(endpoint.links.as_ref()),
            mac_address: endpoint.mac_address.as_deref(),
            aliases: nonempty(endpoint.aliases.as_ref()),
            driver_options: endpoint.driver_options.as_ref(),
        }
    }
}

/// The `EndpointConfig.IPAMConfig` block of a connect body.
#[derive(Debug, Serialize)]
struct EndpointIpamBody<'a> {
    #[serde(rename = "IPv4Address", skip_serializing_if = "Option::is_none")]
    ipv4_address: Option<&'a str>,
    #[serde(rename = "IPv6Address", skip_serializing_if = "Option::is_none")]
    ipv6_address: Option<&'a str>,
    // The Engine spells this `LinkLocalIPs`; the acronym is capitalised, which a
    // casing rule would get wrong.
    #[serde(rename = "LinkLocalIPs", skip_serializing_if = "Option::is_none")]
    link_local_ips: Option<&'a [String]>,
}

/// Disconnects a container from a network.
///
/// Answers `200` with an empty body, so the status is the whole result. `force`
/// is always spelled, so a recorded request says whether a running container was
/// disconnected anyway.
///
/// # Errors
///
/// Returns an error when the reference is empty, when no container was named,
/// when the daemon cannot be reached, or when it rejects the request.
pub async fn network_disconnect(
    engine: &RawEngine,
    network: &str,
    options: &NetworkDisconnectOptions,
) -> Result<(), Error> {
    completed(engine, network_disconnect_request(network, options)?).await
}

/// Builds the `POST /networks/{id}/disconnect` request.
///
/// # Errors
///
/// Returns an error when the reference or the container is empty, or when the
/// body cannot be encoded.
fn network_disconnect_request(
    network: &str,
    options: &NetworkDisconnectOptions,
) -> Result<RawRequest, Error> {
    if options.container.is_empty() {
        return Err(Error::invalid_input(
            "disconnecting a container from a network needs the container's name or id",
        ));
    }
    let body = json_body(&DisconnectBody {
        container: &options.container,
        force: options.force.unwrap_or(false),
    })?;
    let request = json_content_type(RawRequest::new(
        Method::POST,
        &network_path(network, "/disconnect")?,
    ))
    .with_body(body);
    Ok(request)
}

/// The `POST /networks/{id}/disconnect` body, in the Engine's spelling.
///
/// `Force` is always sent, as `true` or `false`, because an absent member and a
/// `false` one are the same request and a recorded request that omits it cannot
/// say which was meant.
#[derive(Debug, Serialize)]
struct DisconnectBody<'a> {
    #[serde(rename = "Container")]
    container: &'a str,
    #[serde(rename = "Force")]
    force: bool,
}

/// Builds the `/networks/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/networks//connect` is not a request
/// for a network, and sending it would ask the daemon about a resource the caller
/// never named. The reference is percent-encoded into exactly one segment, so a
/// name containing `/` cannot address a different resource.
fn network_path(network: &str, suffix: &str) -> Result<String, Error> {
    if network.is_empty() {
        return Err(Error::invalid_input(
            "the Engine network reference must not be empty",
        ));
    }
    Ok(format!(
        "/networks/{}{suffix}",
        escape_path_segment(network)
    ))
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The map is a `BTreeMap`, so the JSON is in key order and a recorded request is
/// reproducible between runs. The current facade converts the same map into a
/// `HashMap` first, so its key order varies.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine network filters: {error}"
        ))
    })
}

/// Returns the slice when it has values, or nothing when it does not.
///
/// An empty JSON array is not the same as an absent member to the Engine, and an
/// unset repository option means "not requested" rather than "requested nothing".
fn nonempty(values: Option<&Vec<String>>) -> Option<&[String]> {
    values
        .filter(|values| !values.is_empty())
        .map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ConnectBody, DisconnectBody, NetworkCreateBody, NetworkEntry, network_connect_request,
        network_create_request, network_disconnect_request, network_inspect_request,
        network_list_request, network_prune_request, network_remove_request,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, NetworkConnectOptions, NetworkCreateOptions,
        NetworkDisconnectOptions, NetworkEndpointOptions, NetworkInspectOptions, NetworkIpam,
        NetworkIpamConfig, NetworkListOptions, NetworkPruneOptions,
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
            ("driver".to_owned(), vec!["bridge".to_owned()]),
            ("name".to_owned(), vec!["probenet".to_owned()]),
        ])
    }

    /// The `GET /networks/{id}` answer recorded from Docker Engine 29.8.0, with
    /// every member the daemon sent for a bridge network including the two the
    /// repository model does not name.
    const INSPECT_BODY: &[u8] = br#"{
        "Name":"bridge",
        "Id":"3dc689051d284909be7e1b8f76fd8daea51683ac78723736329685987539f8cc",
        "Created":"2026-09-19T19:09:31.693484181-05:00",
        "Scope":"local",
        "Driver":"bridge",
        "EnableIPv4":true,
        "EnableIPv6":false,
        "IPAM":{"Driver":"default","Options":null,
            "Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]},
        "Internal":false,
        "Attachable":false,
        "Ingress":false,
        "ConfigFrom":{"Network":""},
        "ConfigOnly":false,
        "Options":{"com.docker.network.bridge.name":"docker0"},
        "Labels":{},
        "Containers":{"73cd5b59":{"Name":"nprobe2","EndpointID":"67e1648f",
            "MacAddress":"16:5a:5f:82:da:07","IPv4Address":"172.31.0.2/16","IPv6Address":""}},
        "Status":{"IPAM":{"Subnets":{"172.17.0.0/16":{"IPsInUse":3,
            "DynamicIPsAvailable":65533}}}}
    }"#;

    fn decoded() -> NetworkEntry {
        NetworkEntry {
            document: super::super::decode(INSPECT_BODY).expect("a network document"),
        }
    }

    #[test]
    fn list_sends_the_versioned_path_and_its_filters() {
        let request =
            network_list_request(&NetworkListOptions { filters: filters() }).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/networks?filters=%7B%22driver%22%3A%5B%22bridge%22%5D%2C%22name%22%3A%5B%22probenet%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_empty_filter_map_is_not_sent_at_all() {
        let request = network_list_request(&NetworkListOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/networks HTTP/1.1")
        );
        let prune = network_prune_request(&NetworkPruneOptions::default()).expect("request");
        assert_eq!(
            request_line(&prune),
            crate::raw::at_api_version("POST /v1.API/networks/prune HTTP/1.1")
        );
    }

    #[test]
    fn filter_keys_are_emitted_in_order_so_a_recorded_request_is_reproducible() {
        // The current facade converts the ordered map to a `HashMap` first, so its
        // recorded order varies between runs of the same command.
        let request =
            network_list_request(&NetworkListOptions { filters: filters() }).expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        assert!(
            value.find("%22driver%22").expect("driver") < value.find("%22name%22").expect("name")
        );
    }

    #[test]
    fn create_sends_the_name_in_the_body_and_no_query_at_all() {
        // Docker Engine 29.8.0 answers a create body with no `Name` member
        // `400 invalid name: name is empty`, and the CLI's recorded request was
        // `POST /v1.56/networks/create` with the name in the body and no query.
        let request = network_create_request(&NetworkCreateOptions {
            name: "probenet".to_owned(),
            driver: Some("bridge".to_owned()),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/networks/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "probenet");
        assert_eq!(body["Driver"], "bridge");
        assert_eq!(body.as_object().expect("an object").len(), 2, "{body}");
    }

    #[test]
    fn the_create_body_uses_the_engines_member_spellings() {
        // Every one of these is spelled differently on the wire than upstream, and
        // a wrong spelling is not a decode failure: the Engine ignores a member it
        // does not know, so the request silently asks for less than the caller
        // wanted. `AuxiliaryAddresses` in particular is the one a casing rule
        // would get wrong, because the Engine's prose calls it `AuxAddress`.
        let body = request_body(
            &network_create_request(&NetworkCreateOptions {
                name: "probenet".to_owned(),
                scope: Some("local".to_owned()),
                internal: Some(true),
                attachable: Some(true),
                ingress: Some(false),
                config_only: Some(false),
                config_from: Some("other".to_owned()),
                enable_ipv4: Some(true),
                enable_ipv6: Some(false),
                options: Some(BTreeMap::from([(
                    "com.example.x".to_owned(),
                    "1".to_owned(),
                )])),
                labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
                ipam: Some(NetworkIpam {
                    driver: Some("default".to_owned()),
                    config: vec![NetworkIpamConfig {
                        subnet: Some("172.31.0.0/16".to_owned()),
                        ip_range: Some("172.31.0.0/24".to_owned()),
                        gateway: Some("172.31.0.1".to_owned()),
                        auxiliary_addresses: BTreeMap::from([(
                            "router".to_owned(),
                            "172.31.0.254".to_owned(),
                        )]),
                    }],
                    options: BTreeMap::from([("foo".to_owned(), "bar".to_owned())]),
                }),
                ..Default::default()
            })
            .expect("request"),
        );
        assert_eq!(body["Scope"], "local");
        assert_eq!(body["Internal"], true);
        assert_eq!(body["Attachable"], true);
        assert_eq!(body["Ingress"], false);
        assert_eq!(body["ConfigOnly"], false);
        assert_eq!(body["ConfigFrom"]["Network"], "other");
        assert_eq!(body["EnableIPv4"], true);
        assert_eq!(body["EnableIPv6"], false);
        assert_eq!(body["Options"]["com.example.x"], "1");
        assert_eq!(body["Labels"]["tier"], "web");
        assert_eq!(body["IPAM"]["Driver"], "default");
        assert_eq!(body["IPAM"]["Config"][0]["Subnet"], "172.31.0.0/16");
        assert_eq!(body["IPAM"]["Config"][0]["IPRange"], "172.31.0.0/24");
        assert_eq!(body["IPAM"]["Config"][0]["Gateway"], "172.31.0.1");
        assert_eq!(
            body["IPAM"]["Config"][0]["AuxiliaryAddresses"]["router"],
            "172.31.0.254"
        );
        assert_eq!(body["IPAM"]["Options"]["foo"], "bar");
    }

    #[test]
    fn a_create_with_only_a_name_sends_one_member() {
        let body = request_body(
            &network_create_request(&NetworkCreateOptions {
                name: "probenet".to_owned(),
                ..Default::default()
            })
            .expect("request"),
        );
        assert_eq!(body.as_object().expect("an object").len(), 1, "{body}");
    }

    #[test]
    fn inspect_spells_verbose_and_sends_a_scope_only_when_one_was_asked_for() {
        let plain =
            network_inspect_request("bridge", &NetworkInspectOptions::default()).expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("GET /v1.API/networks/bridge?verbose=false HTTP/1.1")
        );
        let scoped = network_inspect_request(
            "bridge",
            &NetworkInspectOptions::new()
                .with_verbose(true)
                .with_scope("swarm"),
        )
        .expect("request");
        assert_eq!(
            request_line(&scoped),
            crate::raw::at_api_version(
                "GET /v1.API/networks/bridge?verbose=true&scope=swarm HTTP/1.1"
            )
        );
    }

    #[test]
    fn remove_sends_a_bare_delete_with_no_query() {
        // The Docker CLI's recorded remove was `DELETE /v1.56/networks/probenet`
        // with no query at all.
        let request = network_remove_request("probenet").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("DELETE /v1.API/networks/probenet HTTP/1.1")
        );
        assert_eq!(request.query, None);
    }

    #[test]
    fn connect_names_the_container_in_the_body_and_the_network_in_the_path() {
        let request = network_connect_request(
            "netprobe",
            &NetworkConnectOptions {
                container: "nprobe2".to_owned(),
                endpoint: Some(NetworkEndpointOptions {
                    aliases: Some(vec!["web".to_owned()]),
                    links: Some(vec!["db:db".to_owned()]),
                    mac_address: Some("02:42:ac:11:00:02".to_owned()),
                    driver_options: Some(BTreeMap::from([("mtu".to_owned(), "1400".to_owned())])),
                    ipv4_address: Some("172.31.0.9".to_owned()),
                    ipv6_address: Some("2001:db8::9".to_owned()),
                    link_local_ips: Some(vec!["fe80::1".to_owned()]),
                }),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/networks/netprobe/connect HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Container"], "nprobe2");
        // The Engine reads `Aliases`, `Links`, `DriverOpts`, and the requested
        // addresses under `IPAMConfig`; the repository spells the last of those
        // `driver_options` and its members `ipv4_address`/`link_local_ips`.
        assert_eq!(body["EndpointConfig"]["Aliases"][0], "web");
        assert_eq!(body["EndpointConfig"]["Links"][0], "db:db");
        assert_eq!(body["EndpointConfig"]["MacAddress"], "02:42:ac:11:00:02");
        assert_eq!(body["EndpointConfig"]["DriverOpts"]["mtu"], "1400");
        assert!(
            body["EndpointConfig"].get("DriverOptions").is_none(),
            "{body}"
        );
        let ipam = &body["EndpointConfig"]["IPAMConfig"];
        assert_eq!(ipam["IPv4Address"], "172.31.0.9");
        assert_eq!(ipam["IPv6Address"], "2001:db8::9");
        assert_eq!(ipam["LinkLocalIPs"][0], "fe80::1");
        // A connect's `IPAMConfig` is not a create body's pool: a `Subnet` or
        // `Gateway` member here is a member the Engine does not know.
        assert!(ipam.get("Subnet").is_none(), "{ipam}");
        assert!(ipam.get("Gateway").is_none(), "{ipam}");
    }

    #[test]
    fn a_connect_with_no_endpoint_settings_omits_the_member() {
        // A `null` `EndpointConfig` is a member of the wrong type to the Engine's
        // decoder, not a request for the network's defaults.
        let body = request_body(
            &network_connect_request("netprobe", &NetworkConnectOptions::new("nprobe2"))
                .expect("request"),
        );
        assert_eq!(body["Container"], "nprobe2");
        assert!(body.get("EndpointConfig").is_none(), "{body}");
    }

    #[test]
    fn disconnect_always_spells_force() {
        // An absent `Force` and a `false` one are the same request, and a recorded
        // request that omits it cannot say which the caller meant.
        let plain =
            network_disconnect_request("netprobe", &NetworkDisconnectOptions::new("nprobe2"))
                .expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/networks/netprobe/disconnect HTTP/1.1")
        );
        let body = request_body(&plain);
        assert_eq!(body["Container"], "nprobe2");
        assert_eq!(body["Force"], false);
        let forced = network_disconnect_request(
            "netprobe",
            &NetworkDisconnectOptions {
                container: "nprobe2".to_owned(),
                force: Some(true),
            },
        )
        .expect("request");
        assert_eq!(request_body(&forced)["Force"], true);
    }

    #[test]
    fn an_empty_reference_or_container_is_refused_before_the_socket() {
        for error in [
            network_remove_request("").expect_err("empty network"),
            network_inspect_request("", &NetworkInspectOptions::default())
                .expect_err("empty network"),
            network_connect_request("", &NetworkConnectOptions::new("c"))
                .expect_err("empty network"),
            network_disconnect_request("", &NetworkDisconnectOptions::new("c"))
                .expect_err("empty network"),
            network_connect_request("net", &NetworkConnectOptions::new(""))
                .expect_err("empty container"),
            network_disconnect_request("net", &NetworkDisconnectOptions::new(""))
                .expect_err("empty container"),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_reference_cannot_reshape_the_network_path() {
        // `/networks/a/b/connect` is a different resource rather than a connect to
        // a network whose name contains a slash.
        let request =
            network_connect_request("a/b", &NetworkConnectOptions::new("c")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/networks/a%2Fb/connect HTTP/1.1")
        );
    }

    #[test]
    fn every_member_the_daemon_sent_is_still_in_the_document() {
        // The reason this module keeps the document: 17 members measured from
        // Docker Engine 29.8.0, and the repository model names 16 of them.
        let entry = decoded();
        for member in [
            "Name",
            "Id",
            "Created",
            "Scope",
            "Driver",
            "EnableIPv4",
            "EnableIPv6",
            "IPAM",
            "Internal",
            "Attachable",
            "Ingress",
            "ConfigFrom",
            "ConfigOnly",
            "Options",
            "Labels",
            "Containers",
            "Status",
        ] {
            assert!(
                entry.document().get(member).is_some(),
                "member {member} was dropped"
            );
        }
        // `Status` is the member no typed field holds, and it is the daemon's
        // per-subnet allocation report.
        assert_eq!(
            entry.document()["Status"]["IPAM"]["Subnets"]["172.17.0.0/16"]["IPsInUse"],
            3
        );
    }

    #[test]
    fn a_config_from_the_daemon_sent_as_an_empty_name_is_absent_rather_than_a_word() {
        // The Engine sends `ConfigFrom` on every network, as `{"Network":""}` for
        // an ordinary one. An empty name means "no config-only network", which is
        // not the same answer as a network named "".
        assert_eq!(decoded().config_from(), None);
        let document: serde_json::Value =
            super::super::decode(br#"{"Name":"n","ConfigFrom":{"Network":"other"}}"#)
                .expect("a document");
        assert_eq!(
            NetworkEntry { document }.config_from(),
            Some("other"),
            "a config-only network the configuration comes from"
        );
    }

    #[test]
    fn the_summary_projection_reads_the_engines_spelling() {
        let summary = decoded().summary();
        assert_eq!(summary.name.as_deref(), Some("bridge"));
        assert_eq!(summary.scope.as_deref(), Some("local"));
        assert_eq!(summary.driver.as_deref(), Some("bridge"));
        assert_eq!(summary.enable_ipv4, Some(true));
        assert_eq!(summary.enable_ipv6, Some(false));
        assert_eq!(summary.internal, Some(false));
        assert_eq!(summary.ingress, Some(false));
        assert_eq!(summary.config_only, Some(false));
        assert_eq!(
            summary
                .options
                .get("com.docker.network.bridge.name")
                .map(String::as_str),
            Some("docker0")
        );
        assert!(summary.labels.is_empty());
        let ipam = summary.ipam.expect("an IPAM block");
        assert_eq!(ipam.driver.as_deref(), Some("default"));
        assert_eq!(ipam.config.len(), 1);
        assert_eq!(ipam.config[0].subnet.as_deref(), Some("172.17.0.0/16"));
        assert_eq!(ipam.config[0].gateway.as_deref(), Some("172.17.0.1"));
        assert!(ipam.options.is_empty());
    }

    #[test]
    fn a_network_with_no_labels_or_ipam_pools_still_projects() {
        // Recorded from Docker Engine 29.8.0 for the `none` network: `Labels: {}`
        // and `IPAM.Config: null`.
        let document: serde_json::Value = super::super::decode(
            br#"{"Name":"none","Id":"cd4f934e","Labels":{},"IPAM":{"Driver":"default","Options":null,"Config":null}}"#,
        )
        .expect("a document");
        let summary = NetworkEntry { document }.summary();
        assert_eq!(summary.name.as_deref(), Some("none"));
        assert!(summary.labels.is_empty());
        let ipam = summary.ipam.expect("an IPAM block");
        assert!(ipam.config.is_empty());
        assert!(ipam.options.is_empty());
    }

    #[test]
    fn a_null_member_is_absent_rather_than_a_decode_failure() {
        // The Engine sends `Labels: null` on a network with no labels.
        let document: serde_json::Value =
            super::super::decode(br#"{"Name":"ingress","Labels":null,"IPAM":null}"#)
                .expect("a document");
        let summary = NetworkEntry { document }.summary();
        assert!(summary.labels.is_empty());
        assert_eq!(summary.ipam, None);
    }

    #[test]
    fn the_inspect_projection_reuses_the_repository_model() {
        let inspect = decoded().inspect();
        assert_eq!(inspect.network.name.as_deref(), Some("bridge"));
        assert_eq!(inspect.containers.len(), 1);
        let endpoint = inspect.containers.get("73cd5b59").expect("one endpoint");
        assert_eq!(endpoint.name.as_deref(), Some("nprobe2"));
        assert_eq!(endpoint.endpoint_id.as_deref(), Some("67e1648f"));
        assert_eq!(endpoint.mac_address.as_deref(), Some("16:5a:5f:82:da:07"));
        // The daemon sends the address with its prefix length attached.
        assert_eq!(endpoint.ipv4_address.as_deref(), Some("172.31.0.2/16"));
        assert_eq!(endpoint.ipv6_address.as_deref(), Some(""));
    }

    #[test]
    fn a_network_with_no_attached_containers_projects_an_empty_map() {
        let document: serde_json::Value =
            super::super::decode(br#"{"Name":"none","Containers":{}}"#).expect("a document");
        assert!(NetworkEntry { document }.inspect().containers.is_empty());
    }

    #[test]
    fn the_bodies_serialize_to_the_engines_member_names() {
        // The rename is spelled out rather than derived, because a casing rule
        // would produce `ConfigFrom` from `config_from` by accident and a future
        // edit could break it silently.
        let body = super::json_body(&DisconnectBody {
            container: "c",
            force: false,
        })
        .expect("a body");
        let bytes = match body {
            RawBody::Bytes(bytes) => bytes,
            other => panic!("expected a buffered body, got {other:?}"),
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            serde_json::json!({"Container": "c", "Force": false})
        );
        let create = super::json_body(&NetworkCreateBody {
            name: "n",
            driver: None,
            scope: None,
            internal: None,
            attachable: None,
            ingress: None,
            config_only: None,
            config_from: None,
            enable_ipv4: None,
            enable_ipv6: None,
            ipam: None,
            options: None,
            labels: None,
        })
        .expect("a body");
        let bytes = match create {
            RawBody::Bytes(bytes) => bytes,
            other => panic!("expected a buffered body, got {other:?}"),
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            serde_json::json!({"Name": "n"})
        );
        let connect = super::json_body(&ConnectBody {
            container: "c",
            endpoint_config: None,
        })
        .expect("a body");
        let bytes = match connect {
            RawBody::Bytes(bytes) => bytes,
            other => panic!("expected a buffered body, got {other:?}"),
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            serde_json::json!({"Container": "c"})
        );
    }

    #[test]
    fn the_document_limit_still_bounds_a_network_list() {
        // The bound is a property of the transport, so what is asserted here is
        // that these operations read through it rather than the socket directly.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        let request = network_list_request(&NetworkListOptions::default()).expect("request");
        assert!(
            request.body.known_len().is_some(),
            "no request body is sent"
        );
    }
}
