//! Repository-owned Docker Engine Swarm service, node, config, secret, and
//! task operations over Bollard.
//!
//! The public models intentionally follow the Engine API v1.53 contract used
//! by this crate. Flexible specification members remain JSON values and
//! specification objects retain unknown v1.53 members, while generated Bollard
//! request and response types stay private to this module.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bollard::{
    models::{
        ConfigSpec as BollardConfigSpec, Node as BollardNode, NodeSpec as BollardNodeSpec,
        SecretSpec as BollardSecretSpec, Service as BollardService,
        ServiceCreateResponse as BollardServiceCreateResponse, ServiceSpec as BollardServiceSpec,
        ServiceUpdateResponse as BollardServiceUpdateResponse,
        SwarmInitRequest as BollardSwarmInitRequest, SwarmJoinRequest as BollardSwarmJoinRequest,
        SwarmSpec as BollardSwarmSpec, Task as BollardTask,
    },
    query_parameters::{
        DeleteNodeOptionsBuilder, UpdateConfigOptionsBuilder, UpdateNodeOptionsBuilder,
        UpdateSecretOptionsBuilder, UpdateServiceOptionsBuilder, UpdateSwarmOptionsBuilder,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use crate::{
    ContainerLogFrame, DockerClient, DockerStream, Error, resource,
    streams::{log_options, map_container_log_stream},
};

/// Ordered filters shared by Swarm list endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SwarmListOptions {
    /// Docker filters, such as `name`, `label`, `service`, or `node`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl SwarmListOptions {
    /// Creates options without filters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one filter key.
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

/// Compatibility name for service-list options.
pub type ServiceListOptions = SwarmListOptions;
/// Compatibility name for node-list options.
pub type NodeListOptions = SwarmListOptions;
/// Compatibility name for config-list options.
pub type ConfigListOptions = SwarmListOptions;
/// Compatibility name for secret-list options.
pub type SecretListOptions = SwarmListOptions;
/// Compatibility name for task-list options.
pub type TaskListOptions = SwarmListOptions;

/// Monotonic version used for conflict-safe Swarm updates.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmVersion {
    /// Engine object version index.
    #[serde(rename = "Index", skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
}

/// Options for initializing a Swarm.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SwarmInitOptions {
    /// Manager listen address.
    pub listen_address: Option<String>,
    /// Manager advertise address.
    pub advertise_address: Option<String>,
    /// Data-path address.
    pub data_path_address: Option<String>,
    /// Data-path port.
    pub data_path_port: Option<u32>,
    /// Request creation of a new cluster.
    pub force_new_cluster: Option<bool>,
}

impl SwarmInitOptions {
    /// Creates empty initialization options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            listen_address: None,
            advertise_address: None,
            data_path_address: None,
            data_path_port: None,
            force_new_cluster: None,
        }
    }
}

/// Options for joining a Swarm.
///
/// `Debug` is hand-written rather than derived, because `token` is a credential:
/// it is the same value [`SwarmJoinTokenRole`] reads back out of a `SwarmInfo`,
/// and it is exactly what the crate refuses to render in
/// [`SwarmCertificates::key`] and [`SwarmUnlockKey::key`]. A derived impl here
/// printed it in full and undid that, on the *input* side of the same operation.
///
/// The addresses survive, because they are what a caller diagnosing a join
/// needs and they are not secret. The redaction is visible rather than an
/// omission, so a reader can tell "no token was set" from "a token was withheld".
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SwarmJoinOptions {
    /// Join token.
    pub token: String,
    /// Existing manager addresses.
    pub remote_addresses: Vec<String>,
    /// Optional local listen address.
    pub listen_address: Option<String>,
    /// Optional local advertise address.
    pub advertise_address: Option<String>,
    /// Optional local data-path address.
    pub data_path_address: Option<String>,
}

impl fmt::Debug for SwarmJoinOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmJoinOptions")
            .field("token", &RedactedToken::new(&self.token))
            .field("remote_addresses", &self.remote_addresses)
            .field("listen_address", &self.listen_address)
            .field("advertise_address", &self.advertise_address)
            .field("data_path_address", &self.data_path_address)
            .finish_non_exhaustive()
    }
}

/// Options for leaving a Swarm.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SwarmLeaveOptions {
    /// Leave even when this node is a manager.
    pub force: bool,
}

/// Options for unlocking a Swarm manager.
///
/// `Debug` is hand-written rather than derived, because `key` is the manager
/// unlock key — the value [`SwarmUnlockKey`] reads back and refuses to render.
/// Redacting the response type and deriving on the request type would protect
/// the credential on the way out and print it on the way in.
///
/// [`SwarmUnlockKey`]: crate::SwarmUnlockKey
#[derive(Clone, Eq, PartialEq)]
pub struct SwarmUnlockOptions {
    /// Manager unlock key.
    pub key: String,
}

impl fmt::Debug for SwarmUnlockOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmUnlockOptions")
            .field("key", &RedactedToken::new(&self.key))
            .finish_non_exhaustive()
    }
}

/// A credential rendered as its presence, never its value.
///
/// Used by the `Debug` impls of the types whose fields *are* credentials, so
/// that "the caller set one" and "the caller left it empty" stay distinguishable
/// — a rendering that simply omitted the field would make a failed join and a
/// join with no token look identical, and both are ordinary misconfigurations a
/// reader of a log line has to tell apart.
///
/// An empty value renders as `None` rather than `<redacted>` on purpose: the
/// absence of a credential is not itself sensitive, and printing `<redacted>` for
/// a field that holds nothing teaches a reader to stop looking at the marker.
struct RedactedToken<'a>(&'a str);

impl<'a> RedactedToken<'a> {
    const fn new(value: &'a str) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RedactedToken<'_> {
    /// Renders `None` for an empty credential and `Some(<redacted>)` otherwise.
    ///
    /// The `if` is load-bearing in one direction only: it must be a *branch on
    /// emptiness*, never a rendering of the value. `match self.0.is_empty()` was
    /// the first spelling and clippy's `match_bool` is right to reject it — a
    /// `match` on a bare bool reads like a decision about the credential rather
    /// than about its length, and the next edit to it could plausibly move the
    /// value into an arm. The redaction does not depend on which branch is taken,
    /// only on the fact that neither arm can reach `self.0`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            formatter.write_str("None")
        } else {
            formatter.write_str("Some(<redacted>)")
        }
    }
}

/// The role a Swarm join token admits a node as.
///
/// A worker token makes the node a worker; a manager token makes it a manager,
/// which is the only role that can run the Swarm's control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwarmJoinTokenRole {
    /// A node that runs tasks.
    Worker,
    /// A node that runs tasks and takes part in the control plane.
    Manager,
}

impl SwarmJoinTokenRole {
    /// Returns the Docker command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Manager => "manager",
        }
    }

    /// Returns the `GET /swarm` `JoinTokens` member that holds this role's token.
    ///
    /// The Engine capitalizes both members, which is the opposite of the role
    /// names its own CLI takes, so the two spellings are mapped here once rather
    /// than at each read.
    pub(crate) const fn join_token_member(self) -> &'static str {
        match self {
            Self::Worker => "Worker",
            Self::Manager => "Manager",
        }
    }
}

/// The root CA certificate and the certificates issued for this node.
///
/// The node key is a credential. It is reachable only through [`Self::key`], it
/// is redacted from `Debug`, and it is zeroized when the value is dropped, so
/// formatting one of these cannot carry it into a log line.
///
/// The type decodes the Engine's `GET /swarm/cert` document directly. It used
/// to be decoded through a private document type, and having two spellings of
/// the same wire shape is how the two drift apart; the manual `Debug`, `Drop`,
/// and accessors below are unaffected by the derive.
#[derive(Deserialize)]
pub struct SwarmCertificates {
    /// The node the certificates were issued for.
    #[serde(rename = "NodeID")]
    node_id: Option<String>,
    /// The PEM-encoded Swarm root CA certificate.
    #[serde(rename = "RootCA")]
    root_ca: Option<String>,
    /// The PEM-encoded certificate issued for this node.
    #[serde(rename = "Cert")]
    cert: Option<String>,
    /// The PEM-encoded private key issued for this node.
    #[serde(rename = "Key")]
    key: Option<String>,
}

impl SwarmCertificates {
    /// Returns the node the certificates were issued for.
    #[must_use]
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }

    /// Returns the PEM-encoded Swarm root CA certificate.
    #[must_use]
    pub fn root_ca(&self) -> Option<&str> {
        self.root_ca.as_deref()
    }

    /// Returns the PEM-encoded certificate issued for this node.
    #[must_use]
    pub fn cert(&self) -> Option<&str> {
        self.cert.as_deref()
    }

    /// Returns the PEM-encoded private key issued for this node.
    ///
    /// The key is a private credential of the Swarm. A caller that prints it is
    /// the caller's decision; nothing in this crate logs, formats, or
    /// serializes it on the way here.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl fmt::Debug for SwarmCertificates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmCertificates")
            .field("node_id", &self.node_id)
            .field("root_ca", &self.root_ca)
            .field("cert", &self.cert)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for SwarmCertificates {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

/// The manager unlock key of a Swarm with autolock enabled.
///
/// The key is a credential: it is redacted from `Debug` and zeroized when the
/// value is dropped.
///
/// The type decodes the Engine's `GET /swarm/unlockkey` document directly, for
/// the reason [`SwarmCertificates`] gives.
#[derive(Deserialize)]
pub struct SwarmUnlockKey {
    /// The unlock key, when the Swarm has autolock enabled.
    #[serde(rename = "UnlockKey")]
    key: Option<String>,
}

impl SwarmUnlockKey {
    /// Returns the unlock key, when the Swarm has one.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl fmt::Debug for SwarmUnlockKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmUnlockKey")
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for SwarmUnlockKey {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

/// Complete, conflict-safe Swarm update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwarmUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: SwarmSpec,
    /// Rotate the worker join token.
    pub rotate_worker_token: bool,
    /// Rotate the manager join token.
    pub rotate_manager_token: bool,
    /// Rotate the manager unlock key.
    pub rotate_manager_unlock_key: bool,
}

/// A `#[serde(flatten)]` catch-all map, rendered as a count instead of itself.
///
/// Every type with a flattened `additional` accepts **arbitrary daemon JSON** in
/// that map. It is not a typed projection with a known member set; it is whatever
/// the peer sent that the named fields did not consume, at any depth. So the map
/// is a channel the daemon — or anyone standing in for it — chooses, and a
/// `Debug` that renders it renders daemon-chosen strings verbatim.
///
/// That is not hypothetical here. A `GET /swarm` document reports the same
/// cluster state under two spellings: the Engine's own top-level `JoinTokens`,
/// which [`SwarmInfo`] names and so redacts, and swarmkit's `ClusterInfo`, which
/// nests a second `JoinTokens` and is *not* a named field, so it lands here. One
/// Engine version change, or one daemon choosing the other spelling, puts the
/// join tokens back into a `Debug` output through a field that looks like
/// forward-compatibility plumbing.
///
/// Hence the count, and only the count. Key names were considered and rejected:
/// a name is daemon-chosen too, so printing one is printing daemon-controlled
/// text, and the count already answers the question a reader actually has —
/// "did the daemon send me anything this crate does not model?"
///
/// [`SwarmInfo`]: crate::SwarmInfo
struct AdditionalCount(usize);

impl fmt::Debug for AdditionalCount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} unmodeled member(s)", self.0)
    }
}

/// User-modifiable Swarm specification.
///
/// Unknown members returned by the v1.53 Engine are retained in stable key
/// order so conflict-safe updates do not silently discard daemon state.
///
/// `Debug` is hand-written rather than derived, because `additional` is an
/// arbitrary daemon-supplied map rather than a set of typed members, and a
/// derive renders it in full. That matters past this type: [`SwarmUpdateOptions`]
/// holds a `SwarmSpec`, so a derived `Debug` there routes the same untrusted
/// values into every panic message about an update.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSpec {
    /// Swarm name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User-defined labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Additional v1.53 specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmSpec {
    /// Reports the members this crate models, and how much it does not.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSpec")
            .field("name", &self.name)
            .field("labels", &self.labels)
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Docker Swarm metadata.
///
/// `Debug` is hand-written rather than derived, and for two separate reasons —
/// either of which alone would defeat a redaction that handled only the other.
///
/// - `join_tokens` holds the worker and manager join tokens, which are
///   credentials. That is the same class of value as [`SwarmCertificates::key`]
///   and [`SwarmUnlockKey::key`], which are redacted beside this type, and the
///   inconsistency was the defect: a caller printing a `SwarmInfo` for its ID and
///   version has no way to ask for the tokens and no way to stop them.
/// - `additional` is a `#[serde(flatten)]` catch-all holding arbitrary daemon
///   JSON, and the join tokens arrive there too under swarmkit's `ClusterInfo`
///   spelling. The catch-all is therefore reported as a count of unmodelled
///   members rather than as itself — key names withheld too, since a key name is
///   daemon-chosen — so redacting the named field alone is not a redaction with
///   a documented bypass.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmInfo {
    /// Swarm ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Swarm version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Complete Swarm specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSpec>,
    /// Join tokens, when returned by the daemon.
    #[serde(rename = "JoinTokens", skip_serializing_if = "Option::is_none")]
    pub join_tokens: Option<serde_json::Value>,
    /// Additional stable v1.53 Swarm members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmInfo {
    /// Reports the Swarm's identity, and how much of its state is not modelled.
    ///
    /// The tokens themselves are never formatted, in either spelling. A derived
    /// `Debug` renders `join_tokens` in full because `serde_json::Value`'s own
    /// `Debug` prints its strings verbatim, and it renders `additional` in full
    /// for the same reason — which is where the tokens come back under
    /// `ClusterInfo`. `docker swarm join --token` accepts what is printed, so a
    /// rendered `SwarmInfo` is an invitation to join somebody else's Swarm.
    ///
    /// The redactions are *visible* rather than omissions. A reader has to be
    /// able to tell "the daemon sent no tokens" from "the tokens were withheld",
    /// which are different facts about a node, and has to be able to tell that
    /// unmodelled members were received rather than silently dropped — that is
    /// what makes a `SwarmInfo` worth logging at all.
    ///
    /// `finish_non_exhaustive` is deliberate: a member added to this type later
    /// renders as `..` rather than appearing in full by default. That is the
    /// property this impl exists to have, and a plain `finish()` would quietly
    /// give it back the moment someone added a field and kept deriving.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmInfo")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("spec", &self.spec)
            .field(
                "join_tokens",
                &self.join_tokens.as_ref().map(|_| "<redacted>"),
            )
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

impl SwarmInfo {
    /// Returns the root CA certificate the Swarm validates node certificates
    /// against, as PEM.
    ///
    /// This is what `docker swarm ca` prints, read from `GET /swarm`. The Engine
    /// reports it as a **top-level** `TLSInfo.TrustRoot`; the `swarmkit` store
    /// nests the same value under `ClusterInfo`, so a document carrying
    /// both spellings is read from the Engine's one first. During a root
    /// rotation the value holds more than one certificate, so it is returned
    /// whole rather than split.
    #[must_use]
    pub fn trust_root(&self) -> Option<&str> {
        fn trust_root_in(tls_info: &serde_json::Value) -> Option<&str> {
            tls_info
                .get("TrustRoot")
                .and_then(serde_json::Value::as_str)
        }
        trust_root_in(self.additional.get("TLSInfo")?)
            .or_else(|| self.additional.get("ClusterInfo").and_then(trust_root_in))
    }
}

/// The port a Swarm manager listens on when the spec does not say.
///
/// 2377 is Docker's Swarm default, and it is what `Swarm.RemoteManagers[].Addr`
/// reports on a Swarm left at the default. A Swarm that listens elsewhere
/// reports that port in the same field, so this is only the fallback for a
/// document that has no manager address at all.
const DEFAULT_SWARM_PORT: u16 = 2377;

/// Complete service specification used for create, update, and rollback.
///
/// `task_template`, `mode`, `endpoint_spec`, and the two update configurations are
/// carried as [`serde_json::Value`] because each is a tagged union in the Engine
/// model — `Replicated` or `Global`, a port list or a mode string — and a typed
/// wrapper would have to encode a grammar the Engine owns. The members that *are*
/// structures are typed here, so a caller building a spec does not hand-assemble
/// JSON for them.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceSpec {
    /// Service name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Service labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Task template.
    #[serde(rename = "TaskTemplate", skip_serializing_if = "Option::is_none")]
    pub task_template: Option<serde_json::Value>,
    /// Replicated, global, or job mode.
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<serde_json::Value>,
    /// Endpoint specification.
    #[serde(rename = "EndpointSpec", skip_serializing_if = "Option::is_none")]
    pub endpoint_spec: Option<serde_json::Value>,
    /// Deprecated service-level network attachments.
    #[serde(rename = "Networks", skip_serializing_if = "Option::is_none")]
    pub networks: Option<serde_json::Value>,
    /// Update configuration.
    #[serde(rename = "UpdateConfig", skip_serializing_if = "Option::is_none")]
    pub update_config: Option<serde_json::Value>,
    /// Rollback configuration.
    #[serde(rename = "RollbackConfig", skip_serializing_if = "Option::is_none")]
    pub rollback_config: Option<serde_json::Value>,
    /// Which nodes may run this service's tasks.
    ///
    /// Typed rather than left in `additional`, because it is the member a caller
    /// most often sets from a document's `placement:` block and hand-writing its
    /// `Constraints` array is how a misspelled key turns into a service that
    /// schedules everywhere.
    #[serde(rename = "Placement", skip_serializing_if = "Option::is_none")]
    pub placement: Option<ServicePlacement>,
    /// When and how often a failed task is restarted.
    #[serde(rename = "RestartPolicy", skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<ServiceRestartPolicy>,
    /// Additional v1.53 specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Node selection for a Swarm service.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServicePlacement {
    /// Constraints a node must satisfy, such as `node.role == worker`.
    #[serde(rename = "Constraints", default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    /// Soft placement preferences, applied in order.
    #[serde(rename = "Preferences", default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<String>,
    /// Tasks this service may place on one node. Zero means no limit.
    #[serde(rename = "MaxReplicas", default, skip_serializing_if = "is_zero")]
    pub max_replicas: u32,
}

/// When and how often Swarm restarts a failed task.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceRestartPolicy {
    /// `none`, `on-failure`, or `any`.
    #[serde(rename = "Condition")]
    pub condition: String,
    /// How long to wait before restarting, in nanoseconds.
    #[serde(rename = "Delay", skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,
    /// Retries allowed within `window`.
    #[serde(rename = "MaxAttempts", skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<i64>,
    /// Window retries are counted in, in nanoseconds.
    #[serde(rename = "Window", skip_serializing_if = "Option::is_none")]
    pub window: Option<i64>,
    /// `pause`, `continue`, or `rollback`.
    #[serde(rename = "FailureAction", skip_serializing_if = "Option::is_none")]
    pub failure_action: Option<String>,
}

/// Whether a `u32` is zero, for a `skip_serializing_if` that treats zero as unset.
///
/// Takes the value by reference because serde calls a `skip_serializing_if` with a
/// reference; the lint about passing it by value does not apply to a function
/// whose whole job is to be handed one.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Published or exposed service port.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServicePort {
    /// IP protocol.
    #[serde(rename = "Protocol", skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Container target port.
    #[serde(rename = "TargetPort", skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u32>,
    /// Published host port.
    #[serde(rename = "PublishedPort", skip_serializing_if = "Option::is_none")]
    pub published_port: Option<u32>,
    /// Published host IP.
    #[serde(rename = "PublishedIP", skip_serializing_if = "Option::is_none")]
    pub published_ip: Option<String>,
    /// Endpoint publishing mode.
    #[serde(rename = "PublishMode", skip_serializing_if = "Option::is_none")]
    pub publish_mode: Option<String>,
}

/// Running and desired task counts for a service.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceStatus {
    /// Running task count.
    #[serde(rename = "RunningTasks")]
    pub running_tasks: u64,
    /// Desired task count.
    #[serde(rename = "DesiredTasks")]
    pub desired_tasks: u64,
}

/// Docker service metadata.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmService {
    /// Service ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Service version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Current service specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<ServiceSpec>,
    /// Published/exposed ports.
    #[serde(rename = "Ports", skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<ServicePort>>,
    /// Current task counts.
    #[serde(rename = "ServiceStatus", skip_serializing_if = "Option::is_none")]
    pub status: Option<ServiceStatus>,
    /// Additional stable v1.53 service members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// ID and warnings returned by service creation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceCreateResult {
    /// Created service ID.
    pub id: String,
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Warnings returned by service update or rollback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceUpdateResult {
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Complete conflict-safe service update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: ServiceSpec,
    /// Ask the daemon to roll back to `PreviousSpec`.
    pub rollback: bool,
}

/// User-modifiable node specification.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeSpec {
    /// Node name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Node labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// `worker` or `manager`.
    #[serde(rename = "Role", skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `active`, `pause`, or `drain`.
    #[serde(rename = "Availability", skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    /// Additional v1.53 node-specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Manager reachability and leadership state.
///
/// `Addr`, the address other members use to reach this manager, is one of the
/// members the Engine sends and this type does not name, so it is retained in
/// `additional` rather than dropped.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeManagerStatus {
    /// Whether this manager is the leader.
    #[serde(rename = "Leader", skip_serializing_if = "Option::is_none")]
    pub leader: Option<bool>,
    /// Manager reachability.
    #[serde(rename = "Reachability", skip_serializing_if = "Option::is_none")]
    pub reachability: Option<String>,
    /// Additional stable v1.53 manager-status members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Docker node metadata.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmNode {
    /// Node ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Node version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Node specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<NodeSpec>,
    /// Runtime state.
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
    /// Manager status.
    #[serde(rename = "ManagerStatus", skip_serializing_if = "Option::is_none")]
    pub manager_status: Option<NodeManagerStatus>,
    /// Engine version reported by the node.
    #[serde(rename = "EngineVersion", skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Additional stable v1.53 node members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Complete conflict-safe node update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: NodeSpec,
}

/// Options for removing a node.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeRemoveOptions {
    /// Remove even when the node is a manager.
    pub force: bool,
}

/// Config specification retained at the v1.53 boundary.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmConfigSpec {
    /// Config name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Config labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Base64-encoded config data returned by Docker.
    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Additional v1.53 config-specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Options for creating a config.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigCreateOptions {
    /// Config name.
    pub name: String,
    /// Config data.
    pub data: Option<Vec<u8>>,
    /// Config labels.
    pub labels: Option<BTreeMap<String, String>>,
}

/// Docker config metadata.
///
/// Members this type does not name are retained in `additional`, in the order
/// the daemon sent them, so a decode never reports a config that is missing
/// something the Engine reported.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmConfig {
    /// Config ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Config version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Config specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmConfigSpec>,
    /// Additional stable v1.53 config members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Complete conflict-safe config update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: SwarmConfigSpec,
}

/// Secret bytes with redacted diagnostics and zeroizing destruction.
pub struct SwarmSecretData(Vec<u8>);

impl SwarmSecretData {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the secret bytes without creating another owning copy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SwarmSecretData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSecretData")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Drop for SwarmSecretData {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret specification returned by Docker. Secret data is intentionally not
/// retained in inspect/list responses.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSecretSpec {
    /// Secret name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Secret labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// External secret driver, when configured.
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    pub driver: Option<serde_json::Value>,
    /// Additional v1.53 secret-specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Options for creating a secret.
#[derive(Debug)]
pub struct SecretCreateOptions {
    /// Secret name.
    pub name: String,
    /// Secret data.
    pub data: Option<SwarmSecretData>,
    /// Secret labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl SecretCreateOptions {
    /// Creates named secret options.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Option<SwarmSecretData>) -> Self {
        Self {
            name: name.into(),
            data,
            labels: None,
        }
    }
}

/// Docker secret metadata.
///
/// Members this type does not name are retained in `additional`, in the order
/// the daemon sent them, so a decode never reports a secret that is missing
/// something the Engine reported.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSecret {
    /// Secret ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Secret version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Secret specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSecretSpec>,
    /// Additional stable v1.53 secret members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Complete conflict-safe secret update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement metadata. Secret data cannot be changed by the
    /// Engine update endpoint and is therefore not part of this type.
    pub spec: SwarmSecretSpec,
}

/// Task state and failure information.
///
/// `ContainerStatus`, the container's own exit and health state, is a member the
/// Engine sends and this type does not name, so it is retained in `additional`
/// rather than dropped.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmTaskStatus {
    /// Runtime state.
    #[serde(rename = "State", skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Human-readable daemon message.
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Daemon error.
    #[serde(rename = "Err", skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Status timestamp.
    #[serde(rename = "Timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Additional stable v1.53 task-status members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Docker Swarm task metadata.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmTask {
    /// Task ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Task version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Task name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Task labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Container image used by the task.
    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Owning service ID.
    #[serde(rename = "ServiceID")]
    pub service_id: String,
    /// Replica slot.
    #[serde(rename = "Slot")]
    pub slot: i64,
    /// Assigned node ID.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Runtime status.
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<SwarmTaskStatus>,
    /// Desired state.
    #[serde(rename = "DesiredState", skip_serializing_if = "Option::is_none")]
    pub desired_state: Option<String>,
    /// Complete task specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
    /// Additional stable v1.53 task members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Options for service or task log streams.
pub type SwarmLogOptions = crate::ContainerLogsOptions;

fn convert<B, T>(value: B) -> Result<T, Error>
where
    B: Serialize,
    T: DeserializeOwned,
{
    serde_json::to_value(value)
        .map_err(Error::serialization)
        .and_then(|value| serde_json::from_value(value).map_err(Error::serialization))
}

fn into_bollard<T, B>(value: T) -> Result<B, Error>
where
    T: Serialize,
    B: DeserializeOwned,
{
    serde_json::to_value(value)
        .map_err(Error::serialization)
        .and_then(|value| serde_json::from_value(value).map_err(Error::serialization))
}

/// Converts a caller's version to the `int64` the Engine declares for it.
///
/// The Engine's specification is not uniform: a service update parameter is an
/// `int32` and the swarm, node, config, and secret parameters are `int64`. A
/// version that does not fit is a caller mistake rather than a number to
/// truncate into a *different* version, which is a conflict against the wrong
/// object.
pub(crate) fn checked_i64(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::invalid_version())
}

/// Converts a caller's version to the `int32` a service update parameter is.
pub(crate) fn checked_i32(value: u64) -> Result<i32, Error> {
    i32::try_from(value).map_err(|_| Error::invalid_version())
}

fn hash_map(values: Option<BTreeMap<String, String>>) -> Option<HashMap<String, String>> {
    values.map(|values| values.into_iter().collect())
}

fn service_from_bollard(service: BollardService) -> Result<SwarmService, Error> {
    let value = serde_json::to_value(service).map_err(Error::serialization)?;
    let mut object = value.as_object().cloned().ok_or_else(|| {
        Error::serialization(serde::de::Error::custom("service is not an object"))
    })?;

    let ports: Option<Vec<ServicePort>> = object.remove("Endpoint").and_then(|endpoint| {
        endpoint
            .get("Ports")
            .cloned()
            .and_then(|ports| serde_json::from_value(ports).ok())
    });
    let status: Option<ServiceStatus> = object
        .remove("ServiceStatus")
        .and_then(|status| serde_json::from_value(status).ok());

    if let Some(ports) = ports {
        object.insert(
            "Ports".to_owned(),
            serde_json::to_value(ports).map_err(Error::serialization)?,
        );
    }
    if let Some(status) = status {
        object.insert(
            "ServiceStatus".to_owned(),
            serde_json::to_value(status).map_err(Error::serialization)?,
        );
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(Error::serialization)
}

fn node_from_bollard(node: BollardNode) -> Result<SwarmNode, Error> {
    let value = serde_json::to_value(node).map_err(Error::serialization)?;
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| Error::serialization(serde::de::Error::custom("node is not an object")))?;
    let engine_version = object
        .get("Description")
        .and_then(|description| description.get("Engine"))
        .and_then(|engine| {
            engine
                .get("EngineVersion")
                .or_else(|| engine.get("Version"))
        })
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    if let Some(engine_version) = engine_version {
        object.insert(
            "EngineVersion".to_owned(),
            serde_json::Value::String(engine_version),
        );
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(Error::serialization)
}

fn task_from_bollard(task: BollardTask) -> Result<SwarmTask, Error> {
    let value = serde_json::to_value(task).map_err(Error::serialization)?;
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| Error::serialization(serde::de::Error::custom("task is not an object")))?;
    let image = object
        .get("Spec")
        .and_then(|spec| spec.get("ContainerSpec"))
        .and_then(|container| container.get("Image"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    if let Some(image) = image {
        object.insert("Image".to_owned(), serde_json::Value::String(image));
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(Error::serialization)
}

impl DockerClient {
    /// Initializes a Swarm and returns the manager node ID.
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization or the Engine operation fails.
    pub async fn initialize_swarm(&self, options: SwarmInitOptions) -> Result<String, Error> {
        let request = BollardSwarmInitRequest {
            listen_addr: options.listen_address,
            advertise_addr: options.advertise_address,
            data_path_addr: options.data_path_address,
            data_path_port: options.data_path_port,
            force_new_cluster: options.force_new_cluster,
            ..BollardSwarmInitRequest::default()
        };
        Ok(self.inner.init_swarm(request).await?)
    }

    /// Joins the local Engine to a Swarm.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the join request.
    pub async fn join_swarm(&self, options: SwarmJoinOptions) -> Result<(), Error> {
        let request = BollardSwarmJoinRequest {
            listen_addr: options.listen_address,
            advertise_addr: options.advertise_address,
            data_path_addr: options.data_path_address,
            remote_addrs: (!options.remote_addresses.is_empty())
                .then_some(options.remote_addresses),
            join_token: Some(options.token),
        };
        Ok(self.inner.join_swarm(request).await?)
    }

    /// Leaves the active Swarm.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the operation.
    pub async fn leave_swarm(&self, options: SwarmLeaveOptions) -> Result<(), Error> {
        let options = options.force.then(|| {
            bollard::query_parameters::LeaveSwarmOptionsBuilder::default()
                .force(true)
                .build()
        });
        Ok(self.inner.leave_swarm(options).await?)
    }

    /// Unlocks an encrypted Swarm manager.
    ///
    /// Bollard 0.21.1 does not expose this endpoint directly. The facade uses a
    /// request modifier to compose the documented v1.53 request through a
    /// unit-returning Bollard method; no independent Engine HTTP client is
    /// introduced.
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization or the Engine operation fails.
    pub async fn unlock_swarm(&self, options: SwarmUnlockOptions) -> Result<(), Error> {
        let body = serde_json::to_vec(&serde_json::json!({ "UnlockKey": options.key }))
            .map_err(Error::serialization)?;
        let marker = "/configs/__neotales_swarm_unlock";
        let docker = self
            .inner
            .clone()
            .with_request_modifier(move |mut request| {
                if let Some(prefix) = request.uri().path().strip_suffix(marker).map(str::to_owned) {
                    *request.method_mut() = http::Method::POST;
                    if let Ok(parts) =
                        format!("{prefix}/swarm/unlock").parse::<http::uri::PathAndQuery>()
                    {
                        let mut uri_parts = request.uri().clone().into_parts();
                        uri_parts.path_and_query = Some(parts);
                        if let Ok(uri) = http::Uri::from_parts(uri_parts) {
                            *request.uri_mut() = uri;
                        }
                    }
                    *request.body_mut() = bollard::body_full(body.clone().into());
                }
                request
            });
        Ok(docker.delete_config("__neotales_swarm_unlock").await?)
    }

    /// Reads the Swarm root CA and the certificates issued for this node.
    ///
    /// `GET /swarm/cert` is the only endpoint that has ever returned the node
    /// certificate and key, and the Engine no longer serves it: it is absent
    /// from the API specification as of v1.35, and a v29.8 daemon answers
    /// `404 page not found` for it at every version prefix. A caller therefore
    /// gets a `404` API error from a current daemon, which it can report, and
    /// this method is the only way to read the material where it does exist.
    /// The root CA itself is read from [`SwarmInfo::trust_root`] instead, which
    /// is where `docker swarm ca` reads it.
    ///
    /// Bollard 0.21.1 has no method for the path and no public way to build an
    /// arbitrary request, so the facade sends a `GET` through a generated method
    /// and rewrites the path after Bollard has versioned it. The body comes back
    /// as text and is decoded here into repository-owned types, so no generated
    /// model decides which members survive.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request or answers with a
    /// document the facade cannot decode.
    pub async fn swarm_certificates(&self) -> Result<SwarmCertificates, Error> {
        let body = self.swarm_document("/swarm/cert").await?;
        serde_json::from_str::<SwarmCertificates>(&body).map_err(Error::serialization)
    }

    /// Reads the manager unlock key of a Swarm with autolock enabled.
    ///
    /// The endpoint is `GET /swarm/unlockkey`; see [`Self::swarm_certificates`]
    /// for how a request the generated client does not expose is composed.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request or answers with a
    /// document the facade cannot decode.
    pub async fn swarm_unlock_key(&self) -> Result<SwarmUnlockKey, Error> {
        let body = self.swarm_document("/swarm/unlockkey").await?;
        serde_json::from_str::<SwarmUnlockKey>(&body).map_err(Error::serialization)
    }

    /// Reads the join token for one role from `GET /swarm`.
    ///
    /// `None` means the daemon reported no token for that role, which is what a
    /// worker sees for the manager token. The token is a credential: it is
    /// returned to the caller and written nowhere else in this crate.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn swarm_join_token(
        &self,
        role: SwarmJoinTokenRole,
    ) -> Result<Option<String>, Error> {
        let swarm = self.inspect_swarm().await?;
        Ok(swarm
            .join_tokens
            .as_ref()
            .and_then(|tokens| tokens.get(role.join_token_member()))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned))
    }

    /// Reads the address other Swarm members use to reach this node.
    ///
    /// This is the `Swarm.NodeAddr` member of `GET /info`, which the Engine
    /// documents as the address at which this node can be reached by other nodes
    /// in the Swarm. `None` means the daemon is not part of a Swarm, or reported
    /// no address, so a caller that needs an address to hand to another machine
    /// has nothing to print.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine operation or its decoding fails.
    pub async fn swarm_advertise_address(&self) -> Result<Option<String>, Error> {
        let info = self.info_value().await?;
        let text = |value: Option<&serde_json::Value>| {
            value
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(ToOwned::to_owned)
        };
        // A manager address is preferred, and it already carries the swarm port:
        // `127.0.0.1:2377`. `Swarm.NodeAddr` is the bare host with no port, and a
        // join command built from it is not runnable — `docker swarm join
        // --token … 127.0.0.1` has no port to connect to, which is why the CLI
        // prints the manager's address rather than this one.
        if let Some(manager) = info
            .pointer("/Swarm/RemoteManagers/0/Addr")
            .and_then(serde_json::Value::as_str)
        {
            let manager = manager.trim();
            if !manager.is_empty() {
                return Ok(Some(manager.to_owned()));
            }
        }
        // The fallback keeps the Swarm default port, because NodeAddr never
        // carries one and a join line with no port cannot work.
        Ok(text(info.pointer("/Swarm/NodeAddr"))
            .map(|address| format!("{address}:{DEFAULT_SWARM_PORT}")))
    }

    /// Sends a `GET` the generated client has no method for and returns the body.
    ///
    /// `GET /_ping` is a public Bollard method that returns the response body
    /// verbatim, and the marker below is its only path, so the rewrite is
    /// unambiguous. Only the path changes: the method stays `GET`.
    ///
    /// The request keeps whatever the generated client would have sent, which
    /// includes *not* prefixing an API version. That is the generated client's
    /// own behavior — the Engine serves its current API for an unversioned
    /// request — so a request composed here is consistent with every other one
    /// the facade sends rather than being the odd one out. A test in
    /// `raw_backend_differential.rs` pins the unversioned behavior so the two
    /// cannot drift apart silently.
    async fn swarm_document(&self, path: &'static str) -> Result<String, Error> {
        const MARKER: &str = "/_ping";
        let docker = self
            .inner
            .clone()
            .with_request_modifier(move |mut request| {
                if let Some(prefix) = request.uri().path().strip_suffix(MARKER)
                    && let Ok(parts) = format!("{prefix}{path}").parse::<http::uri::PathAndQuery>()
                {
                    let mut uri_parts = request.uri().clone().into_parts();
                    uri_parts.path_and_query = Some(parts);
                    if let Ok(uri) = http::Uri::from_parts(uri_parts) {
                        *request.uri_mut() = uri;
                    }
                }
                request
            });
        Ok(docker.ping().await?)
    }

    /// Inspects the active Swarm.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_swarm(&self) -> Result<SwarmInfo, Error> {
        let swarm = self.inner.inspect_swarm().await?;
        convert(swarm)
    }

    /// Updates the Swarm using an explicitly supplied expected version.
    ///
    /// A stale version remains an Engine `409 Conflict`; the facade does not
    /// silently retry and overwrite another writer's changes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, serialization failure, or Engine
    /// rejection.
    pub async fn update_swarm(&self, options: SwarmUpdateOptions) -> Result<(), Error> {
        let version = checked_i64(options.version)?;
        let spec: BollardSwarmSpec = into_bollard(options.spec)?;
        let query = UpdateSwarmOptionsBuilder::default()
            .version(version)
            .rotate_worker_token(options.rotate_worker_token)
            .rotate_manager_token(options.rotate_manager_token)
            .rotate_manager_unlock_key(options.rotate_manager_unlock_key)
            .build();
        Ok(self.inner.update_swarm(spec, query).await?)
    }

    /// Lists Swarm services using deterministic filter encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn list_services(
        &self,
        options: Option<ServiceListOptions>,
    ) -> Result<Vec<SwarmService>, Error> {
        let filters = options.as_ref().map(|options| &options.filters);
        // One modifier, carrying both `status=true` and the caller's filters —
        // bollard's `with_request_modifier` replaces rather than chains, so a
        // second call would drop the filters. See
        // `resource::with_service_list_query`.
        let docker = resource::with_service_list_query(&self.inner, filters);
        docker
            .list_services(None)
            .await?
            .into_iter()
            .map(service_from_bollard)
            .collect()
    }

    /// Creates a Swarm service.
    ///
    /// # Errors
    ///
    /// Returns an error when request conversion or the Engine operation fails.
    pub async fn create_service(&self, spec: ServiceSpec) -> Result<ServiceCreateResult, Error> {
        let spec: BollardServiceSpec = into_bollard(spec)?;
        let response: BollardServiceCreateResponse = self.inner.create_service(spec, None).await?;
        Ok(ServiceCreateResult {
            id: response.id.unwrap_or_default(),
            warnings: response.warnings.unwrap_or_default(),
        })
    }

    /// Inspects one Swarm service.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_service(&self, id: &str) -> Result<SwarmService, Error> {
        service_from_bollard(self.inner.inspect_service(id, None).await?)
    }

    /// Updates or rolls back a service at an explicit expected version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, conversion failure, or Engine
    /// rejection. A version conflict remains a `409 Conflict` API error.
    pub async fn update_service(
        &self,
        id: &str,
        options: ServiceUpdateOptions,
    ) -> Result<ServiceUpdateResult, Error> {
        let version = checked_i32(options.version)?;
        let spec: BollardServiceSpec = into_bollard(options.spec)?;
        let mut builder = UpdateServiceOptionsBuilder::default().version(version);
        if options.rollback {
            builder = builder.rollback("previous");
        }
        let response: BollardServiceUpdateResponse = self
            .inner
            .update_service(id, spec, builder.build(), None)
            .await?;
        Ok(ServiceUpdateResult {
            warnings: response.warnings.unwrap_or_default(),
        })
    }

    /// Removes one Swarm service.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_service(&self, id: &str) -> Result<(), Error> {
        Ok(self.inner.delete_service(id).await?)
    }

    /// Streams service log frames through a caller-owned handle.
    pub fn service_logs(
        &self,
        id: &str,
        options: Option<SwarmLogOptions>,
    ) -> DockerStream<ContainerLogFrame> {
        let options = log_options(options);
        map_container_log_stream(self.inner.service_logs(id, options))
    }

    /// Lists Swarm nodes using deterministic filter encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn list_nodes(
        &self,
        options: Option<NodeListOptions>,
    ) -> Result<Vec<SwarmNode>, Error> {
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/nodes", filters);
        docker
            .list_nodes(None)
            .await?
            .into_iter()
            .map(node_from_bollard)
            .collect()
    }

    /// Inspects one Swarm node.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_node(&self, id: &str) -> Result<SwarmNode, Error> {
        node_from_bollard(self.inner.inspect_node(id).await?)
    }

    /// Updates one Swarm node at an explicit expected version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, conversion failure, or Engine
    /// rejection. A version conflict remains a `409 Conflict` API error.
    pub async fn update_node(&self, id: &str, options: NodeUpdateOptions) -> Result<(), Error> {
        let version = checked_i64(options.version)?;
        let spec: BollardNodeSpec = into_bollard(options.spec)?;
        let query = UpdateNodeOptionsBuilder::default().version(version).build();
        Ok(self.inner.update_node(id, spec, query).await?)
    }

    /// Removes one Swarm node.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_node(&self, id: &str, options: NodeRemoveOptions) -> Result<(), Error> {
        let options = options
            .force
            .then(|| DeleteNodeOptionsBuilder::default().force(true).build());
        Ok(self.inner.delete_node(id, options).await?)
    }

    /// Lists Swarm configs using deterministic filter encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn list_configs(
        &self,
        options: Option<ConfigListOptions>,
    ) -> Result<Vec<SwarmConfig>, Error> {
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/configs", filters);
        docker
            .list_configs(None)
            .await?
            .into_iter()
            .map(convert)
            .collect()
    }

    /// Creates a Swarm config.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding or the Engine operation fails.
    pub async fn create_config(&self, options: ConfigCreateOptions) -> Result<String, Error> {
        let spec = BollardConfigSpec {
            name: Some(options.name),
            labels: hash_map(options.labels),
            data: options.data.as_ref().map(|data| STANDARD.encode(data)),
            ..BollardConfigSpec::default()
        };
        Ok(self.inner.create_config(spec).await?.id)
    }

    /// Inspects one Swarm config.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_config(&self, id: &str) -> Result<SwarmConfig, Error> {
        convert(self.inner.inspect_config(id).await?)
    }

    /// Updates one Swarm config at an explicit expected version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, conversion failure, or Engine
    /// rejection.
    pub async fn update_config(&self, id: &str, options: ConfigUpdateOptions) -> Result<(), Error> {
        let version = checked_i64(options.version)?;
        let spec: BollardConfigSpec = into_bollard(options.spec)?;
        let query = UpdateConfigOptionsBuilder::default()
            .version(version)
            .build();
        Ok(self.inner.update_config(id, spec, query).await?)
    }

    /// Removes one Swarm config.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_config(&self, id: &str) -> Result<(), Error> {
        Ok(self.inner.delete_config(id).await?)
    }

    /// Lists Swarm secrets using deterministic filter encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn list_secrets(
        &self,
        options: Option<SecretListOptions>,
    ) -> Result<Vec<SwarmSecret>, Error> {
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/secrets", filters);
        docker
            .list_secrets(None)
            .await?
            .into_iter()
            .map(convert)
            .collect()
    }

    /// Creates a Swarm secret from caller-owned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when base64 encoding or the Engine operation fails.
    pub async fn create_secret(&self, options: SecretCreateOptions) -> Result<String, Error> {
        let data = options
            .data
            .as_ref()
            .map(|data| STANDARD.encode(data.as_bytes()));
        let spec = BollardSecretSpec {
            name: Some(options.name),
            labels: hash_map(options.labels),
            data,
            ..BollardSecretSpec::default()
        };
        Ok(self.inner.create_secret(spec).await?.id)
    }

    /// Inspects one Swarm secret without exposing secret data.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_secret(&self, id: &str) -> Result<SwarmSecret, Error> {
        convert(self.inner.inspect_secret(id).await?)
    }

    /// Updates secret metadata at an explicit expected version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, conversion failure, or Engine
    /// rejection.
    pub async fn update_secret(&self, id: &str, options: SecretUpdateOptions) -> Result<(), Error> {
        let version = checked_i64(options.version)?;
        let spec: BollardSecretSpec = into_bollard(options.spec)?;
        let query = UpdateSecretOptionsBuilder::default()
            .version(version)
            .build();
        Ok(self.inner.update_secret(id, spec, query).await?)
    }

    /// Removes one Swarm secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_secret(&self, id: &str) -> Result<(), Error> {
        Ok(self.inner.delete_secret(id).await?)
    }

    /// Lists Swarm tasks using deterministic filter encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn list_tasks(
        &self,
        options: Option<TaskListOptions>,
    ) -> Result<Vec<SwarmTask>, Error> {
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/tasks", filters);
        docker
            .list_tasks(None)
            .await?
            .into_iter()
            .map(task_from_bollard)
            .collect()
    }

    /// Inspects one Swarm task.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_task(&self, id: &str) -> Result<SwarmTask, Error> {
        task_from_bollard(self.inner.inspect_task(id).await?)
    }

    /// Streams task log frames through a caller-owned handle.
    pub fn task_logs(
        &self,
        id: &str,
        options: Option<SwarmLogOptions>,
    ) -> DockerStream<ContainerLogFrame> {
        let options = log_options(options);
        map_container_log_stream(self.inner.task_logs(id, options))
    }
}

#[cfg(test)]
mod trust_root_probe {
    use super::SwarmInfo;

    /// A `GET /swarm` document, trimmed to the members a reader depends on but
    /// otherwise exactly as a v29.8 daemon sent it.
    const DOCUMENT: &str = r#"{"ID":"tpruk002s2087sl5n8njv8ex5","Version":{"Index":10},"CreatedAt":"2026-09-25T23:55:58.494057145Z","UpdatedAt":"2026-09-25T23:55:59.042379153Z","TLSInfo":{"TrustRoot":"-----BEGIN CERTIFICATE-----\nMIIBajCCARCgAwIBAgIUB28pCWqKAZc+lxt6+AwKx+dGdLEwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjYwOTI1MjM1MTAwWhcNNDYwOTIwMjM1\nMTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABC5j2g8W6ju209OT0HT2GcHSWZQswEiiCD+cCZo5Yvbz8RxFQbuLpJXchGPg\ntkE2Rx5kCy97cFFKJbFBp2n9xZCjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBQHQh+LrsEveVL16S9A0IMveHO1njAKBggqhkjO\nPQQDAgNIADBFAiADpWFkXjrmtxETJ8y/GCEajZvW8lIyHpXy2PtTIDcldAIhAOj4\nLyVyX23Tqm5rI36T0sNNZaPxLA7CUUsTegmPwAhN\n-----END CERTIFICATE-----\n","CertIssuerSubject":"MBMxETAPBgNVBAMTCHN3YXJtLWNh","CertIssuerPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELmPaDxbqO7bT05PQdPYZwdJZlCzASKIIP5wJmjli9vPxHEVBu4ukldyEY+C2QTZHHmQLL3twUUolsUGnaf3FkA=="},"DataPathPort":4789,"RootRotationInProgress":false,"DefaultAddrPool":null,"SubnetSize":24,"Spec":{"Name":"default"},"JoinTokens":{"Worker":"<redacted>","Manager":"<redacted>"}}"#;

    /// The root CA is read from the Engine's own spelling of the document.
    ///
    /// `docker swarm ca` prints `TLSInfo.TrustRoot` from `GET /swarm`, and its
    /// output is byte-identical to that member. Reading it from the wrong place
    /// is what made the command report "no root CA certificate" against a
    /// perfectly healthy Swarm, so the member's position is pinned here.
    #[test]
    fn the_root_ca_is_read_from_the_engines_top_level_tls_info() {
        let info: SwarmInfo = serde_json::from_str(DOCUMENT).expect("the document decodes");
        let trust_root = info.trust_root().expect("a Swarm manager has a root CA");
        assert!(
            trust_root.starts_with("-----BEGIN CERTIFICATE-----"),
            "{trust_root}"
        );
        assert!(
            trust_root.trim_end().ends_with("-----END CERTIFICATE-----"),
            "{trust_root}"
        );
    }

    /// A document with no `TLSInfo` has no root CA, rather than an empty one.
    ///
    /// A worker node is given the CA too, but a document that genuinely omits it
    /// must not be reported as a Swarm with a blank certificate.
    #[test]
    fn a_document_without_tls_info_reports_no_root_ca() {
        let info: SwarmInfo =
            serde_json::from_str(r#"{"ID":"x","DataPathPort":2377}"#).expect("decodes");
        assert_eq!(info.trust_root(), None);
    }
}
