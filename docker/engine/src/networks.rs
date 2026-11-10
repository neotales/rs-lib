//! Repository-owned Docker Engine network operations.
//!
//! Bollard models and request types remain private to this module. The public
//! values contain the stable v1.53 network fields needed by callers while
//! leaving daemon-specific nested data outside the facade.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use bollard::{
    models::{
        ConfigReference, EndpointIpamConfig, EndpointSettings, Ipam, IpamConfig, Network,
        NetworkConnectRequest, NetworkCreateRequest,
        NetworkCreateResponse as BollardNetworkCreateResponse, NetworkDisconnectRequest,
        NetworkInspect as BollardNetworkInspect,
        NetworkPruneResponse as BollardNetworkPruneResponse,
    },
    query_parameters::{InspectNetworkOptions, InspectNetworkOptionsBuilder},
};

use crate::{DockerClient, Error, raw, raw::NetworkEntry, resource};

/// Options for the Engine network-list operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkListOptions {
    /// Docker network filters, such as `name`, `driver`, `label`, or `scope`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl NetworkListOptions {
    /// Creates empty network-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one network filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// Options for the Engine network-inspect operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkInspectOptions {
    /// Request verbose inspect output.
    pub verbose: bool,
    /// Restrict a swarm-scoped lookup to a scope.
    pub scope: Option<String>,
}

impl NetworkInspectOptions {
    /// Creates empty network-inspect options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            verbose: false,
            scope: None,
        }
    }

    /// Enables or disables verbose output.
    #[must_use]
    pub const fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Sets the optional network scope.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    fn into_bollard(self) -> Option<InspectNetworkOptions> {
        if self == Self::default() {
            return None;
        }
        let mut builder = InspectNetworkOptionsBuilder::default().verbose(self.verbose);
        if let Some(scope) = self.scope.as_deref() {
            builder = builder.scope(scope);
        }
        Some(builder.build())
    }
}

/// A typed IPAM pool used by network creation and inspection.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkIpamConfig {
    /// IPv4 subnet in CIDR notation.
    pub subnet: Option<String>,
    /// IPv4 address range.
    pub ip_range: Option<String>,
    /// IPv4 gateway.
    pub gateway: Option<String>,
    /// Named auxiliary addresses.
    pub auxiliary_addresses: BTreeMap<String, String>,
}

impl NetworkIpamConfig {
    fn from_bollard(config: IpamConfig) -> Self {
        Self {
            subnet: config.subnet,
            ip_range: config.ip_range,
            gateway: config.gateway,
            auxiliary_addresses: config
                .auxiliary_addresses
                .unwrap_or_default()
                .into_iter()
                .collect(),
        }
    }

    fn into_bollard(self) -> IpamConfig {
        IpamConfig {
            subnet: self.subnet,
            ip_range: self.ip_range,
            gateway: self.gateway,
            auxiliary_addresses: (!self.auxiliary_addresses.is_empty())
                .then(|| self.auxiliary_addresses.into_iter().collect()),
        }
    }
}

/// Typed IPAM configuration for a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkIpam {
    /// IPAM driver name.
    pub driver: Option<String>,
    /// Address pools.
    pub config: Vec<NetworkIpamConfig>,
    /// IPAM driver options.
    pub options: BTreeMap<String, String>,
}

impl NetworkIpam {
    fn from_bollard(ipam: Ipam) -> Self {
        Self {
            driver: ipam.driver,
            config: ipam
                .config
                .unwrap_or_default()
                .into_iter()
                .map(NetworkIpamConfig::from_bollard)
                .collect(),
            options: ipam.options.unwrap_or_default().into_iter().collect(),
        }
    }

    fn into_bollard(self) -> Ipam {
        Ipam {
            driver: self.driver,
            config: (!self.config.is_empty()).then(|| {
                self.config
                    .into_iter()
                    .map(NetworkIpamConfig::into_bollard)
                    .collect()
            }),
            options: (!self.options.is_empty()).then(|| self.options.into_iter().collect()),
        }
    }
}

/// Options for creating a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkCreateOptions {
    /// Required network name.
    pub name: String,
    /// Network driver name.
    pub driver: Option<String>,
    /// Network scope, such as `local` or `swarm`.
    pub scope: Option<String>,
    /// Restrict external access to the network.
    pub internal: Option<bool>,
    /// Allow regular containers to attach to a global network.
    pub attachable: Option<bool>,
    /// Mark the network as the Swarm ingress network.
    pub ingress: Option<bool>,
    /// Create a config-only network.
    pub config_only: Option<bool>,
    /// Name of a config-only network providing this network's configuration.
    pub config_from: Option<String>,
    /// Enable IPv4 on the network.
    pub enable_ipv4: Option<bool>,
    /// Enable IPv6 on the network.
    pub enable_ipv6: Option<bool>,
    /// IPAM configuration.
    pub ipam: Option<NetworkIpam>,
    /// Network-driver options.
    pub options: Option<BTreeMap<String, String>>,
    /// User-defined labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl NetworkCreateOptions {
    /// Creates options for a named network.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    fn into_bollard(self) -> NetworkCreateRequest {
        NetworkCreateRequest {
            name: self.name,
            driver: self.driver,
            scope: self.scope,
            internal: self.internal,
            attachable: self.attachable,
            ingress: self.ingress,
            config_only: self.config_only,
            config_from: self.config_from.map(|network| ConfigReference {
                network: Some(network),
            }),
            ipam: self.ipam.map(NetworkIpam::into_bollard),
            enable_ipv4: self.enable_ipv4,
            enable_ipv6: self.enable_ipv6,
            options: self.options.map(into_hash_map),
            labels: self.labels.map(into_hash_map),
        }
    }
}

/// A network endpoint requested when connecting a container.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkEndpointOptions {
    /// DNS aliases for the endpoint.
    pub aliases: Option<Vec<String>>,
    /// Legacy container links.
    pub links: Option<Vec<String>>,
    /// Requested endpoint MAC address.
    pub mac_address: Option<String>,
    /// Driver-specific endpoint options.
    pub driver_options: Option<BTreeMap<String, String>>,
    /// Requested IPv4 address.
    pub ipv4_address: Option<String>,
    /// Requested IPv6 address.
    pub ipv6_address: Option<String>,
    /// Requested link-local IPv6 addresses.
    pub link_local_ips: Option<Vec<String>>,
}

impl NetworkEndpointOptions {
    fn into_bollard(self) -> EndpointSettings {
        let ipam_config = (self.ipv4_address.is_some()
            || self.ipv6_address.is_some()
            || self.link_local_ips.is_some())
        .then_some(EndpointIpamConfig {
            ipv4_address: self.ipv4_address,
            ipv6_address: self.ipv6_address,
            link_local_ips: self.link_local_ips,
        });
        EndpointSettings {
            ipam_config,
            links: self.links,
            mac_address: self.mac_address,
            aliases: self.aliases,
            driver_opts: self.driver_options.map(into_hash_map),
            ..EndpointSettings::default()
        }
    }
}

/// Options for connecting a container to a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkConnectOptions {
    /// Container ID or name.
    pub container: String,
    /// Optional endpoint settings.
    pub endpoint: Option<NetworkEndpointOptions>,
}

impl NetworkConnectOptions {
    /// Creates options for a container connection.
    #[must_use]
    pub fn new(container: impl Into<String>) -> Self {
        Self {
            container: container.into(),
            endpoint: None,
        }
    }

    fn into_bollard(self) -> NetworkConnectRequest {
        NetworkConnectRequest {
            container: self.container,
            endpoint_config: self.endpoint.map(NetworkEndpointOptions::into_bollard),
        }
    }
}

/// Options for disconnecting a container from a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkDisconnectOptions {
    /// Container ID or name.
    pub container: String,
    /// Force disconnection when the container is running.
    pub force: Option<bool>,
}

impl NetworkDisconnectOptions {
    /// Creates options for a container disconnection.
    #[must_use]
    pub fn new(container: impl Into<String>) -> Self {
        Self {
            container: container.into(),
            force: None,
        }
    }

    fn into_bollard(self) -> NetworkDisconnectRequest {
        NetworkDisconnectRequest {
            container: self.container,
            force: self.force,
        }
    }
}

/// Options for pruning unused networks.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkPruneOptions {
    /// Docker network-prune filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl NetworkPruneOptions {
    /// Creates empty network-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one network-prune filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// Stable network fields returned by list and inspect operations.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkSummary {
    /// Network name.
    pub name: Option<String>,
    /// Network ID.
    pub id: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: Option<String>,
    /// Network scope.
    pub scope: Option<String>,
    /// Network driver.
    pub driver: Option<String>,
    /// Whether IPv4 is enabled.
    pub enable_ipv4: Option<bool>,
    /// Whether IPv6 is enabled.
    pub enable_ipv6: Option<bool>,
    /// IPAM configuration.
    pub ipam: Option<NetworkIpam>,
    /// Whether the network is internal.
    pub internal: Option<bool>,
    /// Whether regular containers may attach to the network.
    pub attachable: Option<bool>,
    /// Whether the network is the Swarm ingress network.
    pub ingress: Option<bool>,
    /// Whether the network is config-only.
    pub config_only: Option<bool>,
    /// Network-driver options.
    pub options: BTreeMap<String, String>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
}

impl NetworkSummary {
    fn from_bollard(network: Network) -> Self {
        Self {
            name: network.name,
            id: network.id,
            created: network.created,
            scope: network.scope,
            driver: network.driver,
            enable_ipv4: network.enable_ipv4,
            enable_ipv6: network.enable_ipv6,
            ipam: network.ipam.map(NetworkIpam::from_bollard),
            internal: network.internal,
            attachable: network.attachable,
            ingress: network.ingress,
            config_only: network.config_only,
            options: network.options.unwrap_or_default().into_iter().collect(),
            labels: network.labels.unwrap_or_default().into_iter().collect(),
        }
    }
}

/// A typed endpoint attached to an inspected network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkEndpoint {
    /// Container name reported by Docker.
    pub name: Option<String>,
    /// Endpoint ID.
    pub endpoint_id: Option<String>,
    /// Endpoint MAC address.
    pub mac_address: Option<String>,
    /// Endpoint IPv4 address.
    pub ipv4_address: Option<String>,
    /// Endpoint IPv6 address.
    pub ipv6_address: Option<String>,
}

impl NetworkEndpoint {
    fn from_bollard(endpoint: bollard::models::EndpointResource) -> Self {
        Self {
            name: endpoint.name,
            endpoint_id: endpoint.endpoint_id,
            mac_address: endpoint.mac_address,
            ipv4_address: endpoint.ipv4_address,
            ipv6_address: endpoint.ipv6_address,
        }
    }
}

/// A typed network-inspect result.
///
/// Daemon-specific service, peer, and status objects are intentionally omitted
/// from this bounded projection.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkInspect {
    /// Stable network fields.
    pub network: NetworkSummary,
    /// Containers attached to the network.
    pub containers: BTreeMap<String, NetworkEndpoint>,
}

impl NetworkInspect {
    fn from_bollard(inspect: BollardNetworkInspect) -> Self {
        Self {
            network: NetworkSummary {
                name: inspect.name,
                id: inspect.id,
                created: inspect.created,
                scope: inspect.scope,
                driver: inspect.driver,
                enable_ipv4: inspect.enable_ipv4,
                enable_ipv6: inspect.enable_ipv6,
                ipam: inspect.ipam.map(NetworkIpam::from_bollard),
                internal: inspect.internal,
                attachable: inspect.attachable,
                ingress: inspect.ingress,
                config_only: inspect.config_only,
                options: inspect.options.unwrap_or_default().into_iter().collect(),
                labels: inspect.labels.unwrap_or_default().into_iter().collect(),
            },
            containers: inspect
                .containers
                .unwrap_or_default()
                .into_iter()
                .map(|(id, endpoint)| (id, NetworkEndpoint::from_bollard(endpoint)))
                .collect(),
        }
    }
}

/// Result of creating a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkCreateResult {
    /// ID of the created network.
    pub id: String,
    /// Warning returned by the daemon, when present.
    pub warning: Option<String>,
}

impl NetworkCreateResult {
    fn from_bollard(response: BollardNetworkCreateResponse) -> Self {
        Self {
            id: response.id,
            warning: (!response.warning.is_empty()).then_some(response.warning),
        }
    }
}

/// Result of pruning unused networks.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkPruneResult {
    /// IDs or names of deleted networks.
    pub networks_deleted: Vec<String>,
}

impl NetworkPruneResult {
    fn from_bollard(response: BollardNetworkPruneResponse) -> Self {
        Self {
            networks_deleted: response.networks_deleted.unwrap_or_default(),
        }
    }
}

/// Compatibility name matching the Engine response terminology.
pub type NetworkResponse = NetworkSummary;
/// Compatibility name matching the Engine response terminology.
pub type NetworkCreateResponse = NetworkCreateResult;
/// Compatibility name matching the Engine response terminology.
pub type NetworkPruneResponse = NetworkPruneResult;

fn into_hash_map(values: BTreeMap<String, String>) -> HashMap<String, String> {
    values.into_iter().collect()
}

impl DockerClient {
    /// Lists networks using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_networks(
        &self,
        options: Option<NetworkListOptions>,
    ) -> Result<Vec<NetworkSummary>, Error> {
        // The repository-owned transport first, Bollard second. See the note on
        // `DockerClient::raw_engine` for the routing rule and why both paths
        // stay.
        if let Ok(engine) = self.raw_engine() {
            // The owned path returns the daemon's own document and offers
            // `NetworkSummary` as a projection over it, so the facade's value is
            // unchanged and `ConfigFrom` — which the generated model also drops,
            // because `NetworkSummary` has no field for it — is retained in
            // `NetworkEntry::document` for a caller that reaches past the
            // projection.
            return raw::network_list(&engine, &options.unwrap_or_default())
                .await
                .map(|entries| entries.iter().map(NetworkEntry::summary).collect());
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/networks", filters);
        let networks = docker.list_networks(None).await?;
        Ok(networks
            .into_iter()
            .map(NetworkSummary::from_bollard)
            .collect())
    }

    /// Inspects one network using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn inspect_network(
        &self,
        name: &str,
        options: Option<NetworkInspectOptions>,
    ) -> Result<NetworkInspect, Error> {
        // See `DockerClient::raw_engine` for the routing rule. The owned path
        // spells `verbose` as `true`/`false` where the generated client omits an
        // unset option, which is the same request to the daemon and a recorded
        // one that cannot be read two ways.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_inspect(&engine, name, &options.unwrap_or_default())
                .await
                .map(|entry| entry.inspect());
        }
        let options = options.and_then(NetworkInspectOptions::into_bollard);
        self.inner
            .inspect_network(name, options)
            .await
            .map(NetworkInspect::from_bollard)
            .map_err(Error::from)
    }

    /// Creates a network from repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or response
    /// decoding failures.
    pub async fn create_network(
        &self,
        options: NetworkCreateOptions,
    ) -> Result<NetworkCreateResult, Error> {
        // See `DockerClient::raw_engine` for the routing rule. The name travels
        // in the body on both paths; the owned one omits an unset member rather
        // than sending it as `null`, which the Engine's decoder distinguishes.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_create(&engine, &options).await;
        }
        self.inner
            .create_network(options.into_bollard())
            .await
            .map(NetworkCreateResult::from_bollard)
            .map_err(Error::from)
    }

    /// Removes a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn remove_network(&self, name: &str) -> Result<(), Error> {
        // See `DockerClient::raw_engine` for the routing rule. Both paths read
        // the `204`'s status as the whole result.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_remove(&engine, name).await;
        }
        self.inner.remove_network(name).await.map_err(Error::from)
    }

    /// Connects a container to a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or daemon
    /// failures.
    pub async fn connect_network(
        &self,
        name: &str,
        options: NetworkConnectOptions,
    ) -> Result<(), Error> {
        // See `DockerClient::raw_engine` for the routing rule. The container and
        // its endpoint settings travel in the body on both paths.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_connect(&engine, name, &options).await;
        }
        self.inner
            .connect_network(name, options.into_bollard())
            .await
            .map_err(Error::from)
    }

    /// Disconnects a container from a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or daemon
    /// failures.
    pub async fn disconnect_network(
        &self,
        name: &str,
        options: NetworkDisconnectOptions,
    ) -> Result<(), Error> {
        // See `DockerClient::raw_engine` for the routing rule. The owned path
        // always spells `Force` as `true`/`false`, because an absent member and a
        // `false` one are the same request and a recorded body that omits it
        // cannot say which was meant.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_disconnect(&engine, name, &options).await;
        }
        self.inner
            .disconnect_network(name, options.into_bollard())
            .await
            .map_err(Error::from)
    }

    /// Prunes unused networks using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn prune_networks(
        &self,
        options: Option<NetworkPruneOptions>,
    ) -> Result<NetworkPruneResult, Error> {
        // See `DockerClient::raw_engine` for the routing rule. A `null`
        // `NetworksDeleted` means "nothing was deleted" on both paths, and both
        // project it to an empty list rather than to a missing answer.
        if let Ok(engine) = self.raw_engine() {
            return raw::network_prune(&engine, &options.unwrap_or_default()).await;
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/networks/prune", filters);
        docker
            .prune_networks(None)
            .await
            .map(NetworkPruneResult::from_bollard)
            .map_err(Error::from)
    }
}
