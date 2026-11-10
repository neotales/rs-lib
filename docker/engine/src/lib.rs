//! Repository-native Docker Engine API access over Bollard.
//!
//! The compatibility ceiling is Docker Engine API version 1.55. The
//! facade keeps Bollard behind a small public surface while higher-level
//! Docker concerns remain separate crates. Streaming responses are adapted
//! into repository-owned, caller-owned handles.
#![doc = include_str!("../README.md")]

use std::fmt;

#[cfg(all(feature = "ssh", unix))]
use std::time::Duration;

use bollard::{ClientVersion, Docker};

mod config;
mod containers;
mod context;
mod context_archive;
mod context_store;
mod credentials;
mod endpoint;
mod engine;
mod image_transfer;
mod images;
mod link_guard;
mod networks;
mod plugins;
mod proxy;
pub mod raw;
mod registry_auth;
mod resource;
mod streams;
mod swarm;
mod system;
mod volumes;

#[cfg(all(feature = "ssh", unix))]
mod ssh_auth;

#[cfg(all(feature = "ssh", unix))]
mod ssh_dial_stdio;

#[cfg(all(feature = "ssh", unix))]
mod ssh_neotales;

#[cfg(all(feature = "ssh", unix))]
mod ssh_transport;

#[cfg(all(feature = "ssh", unix))]
pub use ssh_auth::{ManagedSshClient, SshIdentity, SshSecret};

pub use streams::{
    ContainerLogFrame, ContainerLogStream, ContainerLogsOptions, ContainerStats,
    ContainerStatsOptions, ContainerStatsResponse, DockerEvent, DockerEventActor,
    DockerEventResponse, DockerEventsOptions, DockerStream, EventsOptions, ImageProgress,
    ImageProgressEvent, ImagePullOptions, ImagePushOptions, ImageStreamEvent, LogFrame, LogStream,
    LogsOptions, StatsOptions,
};

pub use config::{
    DOCKER_HUB_REGISTRY, DockerConfigError, DockerConfigSummary, RegistryConfigStore,
    RegistryLogoutResult, display_server, registry_key,
};
pub use containers::{
    AttachedSession, Checkpoint, CheckpointOptions, CommitContainerOptions, ContainerArchive,
    ContainerArchiveUploadOptions, ContainerCreateOptions, ContainerCreateResult, ContainerDetails,
    ContainerEndpointSettings, ContainerHostConfig, ContainerListOptions,
    ContainerNetworkingConfig, ContainerPathStat, ContainerPort, ContainerPortBinding,
    ContainerPruneOptions, ContainerPruneResult, ContainerRemoveOptions, ContainerRestartOptions,
    ContainerStartOptions, ContainerStopOptions, ContainerSummary, ContainerTop,
    ContainerUpdateOptions, ContainerUpdateResult, ContainerWaitOptions, ContainerWaitResult,
    DeviceMapping, DeviceRequest, ExecOptions, ExecResizeOptions, ExecSession, ExecState,
    FilesystemChange, HealthConfig, LogConfig, PortMapping, RestartPolicy, SessionInput, Ulimit,
};
pub use context::{
    CONTAINER_HOST_VARIABLE, ContextError, ContextResolver, EndpointSource, NERDCTL_ROOTFUL_SOCKET,
    PODMAN_ROOTFUL_SOCKET, PathProbe, ResolvedEndpoint, nerdctl_socket_candidates,
    nerdctl_socket_sources, podman_socket_candidates, podman_socket_sources,
};
pub use context_archive::{
    ContextArchiveError, ContextArchiveLimits, ContextArchiveStore, ContextArchiveSummary,
};
pub use context_store::{
    ContextCreateOptions, ContextStore, ContextTlsFiles, ContextUpdateOptions, DockerContext,
};
pub use credentials::{
    CredentialError, DockerCredentialHelper, InMemoryRegistryCredentialProvider,
    RegistryCredentialProvider, RegistryCredentials, normalize_registry, registry_for_image,
};
pub use endpoint::{Endpoint, EndpointError, TlsMaterial};
pub use engine::{
    ENGINE_ENVIRONMENT_VARIABLE, EngineCapability, EngineError, EngineKind, EngineProfile,
    EngineSource, UnsupportedCapability,
};
pub use image_transfer::{
    ImageBuildAux, ImageBuildBackend, ImageBuildContext, ImageBuildError, ImageBuildEvent,
    ImageBuildKitOption, ImageBuildOptions, ImageBuildResponse, ImageBuildResult,
    ImageContextError, ImageImportEvent, ImageImportOptions, ImageLoadEvent, ImageLoadOptions,
    ImageLoadResponse, ImageLoadResult, ImageOperationError, ImageSaveError, ImageSaveOptions,
    ImageSaveResult, ImageTransferError, ImageTransferLimits,
};
pub use images::{
    ImageConfig, ImageDeleteResult, ImageGraphDriver, ImageHealthcheck, ImageHistory,
    ImageHistoryEntry, ImageHistoryOptions, ImageHistoryResponse, ImageInspect,
    ImageInspectOptions, ImageInspectResponse, ImageListOptions, ImageMetadata, ImagePruneDelete,
    ImagePruneOptions, ImagePruneResponse, ImagePruneResult, ImageRemoveOptions, ImageRootFs,
    ImageSearchOptions, ImageSearchResponse, ImageSearchResult, ImageSearchResultItem,
    ImageSummary, ImageTagOptions,
};
pub use link_guard::{is_link_or_reparse_point, path_is_link_or_reparse_point};
pub use networks::{
    NetworkConnectOptions, NetworkCreateOptions, NetworkCreateResponse, NetworkCreateResult,
    NetworkDisconnectOptions, NetworkEndpoint, NetworkEndpointOptions, NetworkInspect,
    NetworkInspectOptions, NetworkIpam, NetworkIpamConfig, NetworkListOptions, NetworkPruneOptions,
    NetworkPruneResponse, NetworkPruneResult, NetworkResponse, NetworkSummary,
};
pub use plugins::{
    PluginDisableOptions, PluginEnableOptions, PluginInstallOptions, PluginListOptions,
    PluginPrivilege, PluginRemoveOptions, PluginSummary, PluginUpgradeOptions,
};
pub use proxy::{
    ForwardProxy, MAX_PROXY_AUTHORIZATION_BYTES, MAX_PROXY_PASSWORD_BYTES, MAX_PROXY_URL_BYTES,
    MAX_PROXY_USERNAME_BYTES, ProxyCredentials, ProxyError, ProxyPolicy,
};
pub use registry_auth::RegistryAuthenticationResult;
pub use swarm::{
    ConfigCreateOptions, ConfigListOptions, ConfigUpdateOptions, NodeListOptions,
    NodeManagerStatus, NodeRemoveOptions, NodeSpec, NodeUpdateOptions, SecretCreateOptions,
    SecretListOptions, SecretUpdateOptions, ServiceCreateResult, ServiceListOptions,
    ServicePlacement, ServicePort, ServiceRestartPolicy, ServiceSpec, ServiceStatus,
    ServiceUpdateOptions, ServiceUpdateResult, SwarmCertificates, SwarmConfig, SwarmConfigSpec,
    SwarmInfo, SwarmInitOptions, SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions,
    SwarmListOptions, SwarmLogOptions, SwarmNode, SwarmSecret, SwarmSecretData, SwarmSecretSpec,
    SwarmService, SwarmSpec, SwarmTask, SwarmTaskStatus, SwarmUnlockKey, SwarmUnlockOptions,
    SwarmUpdateOptions, SwarmVersion, TaskListOptions,
};
pub use system::{
    BuildCachePruneOptions, BuildCachePruneResult, DiskUsage, DiskUsageCategory, DiskUsageItem,
    DiskUsageOptions, DiskUsageType, EventActor, EventOptions, EventStream, SystemEvent,
    SystemInfo,
};
pub use volumes::{
    VolumeCreateOptions, VolumeListOptions, VolumeListResponse, VolumeListResult,
    VolumePruneOptions, VolumePruneResponse, VolumePruneResult, VolumeRemoveOptions,
    VolumeResponse, VolumeSummary, VolumeUsage,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

/// The Engine API version handed to Bollard, and it is **not** [`API_VERSION`].
///
/// Bollard 0.21.1's schema models are generated against Engine API 1.53. The
/// version it is given is not only a path prefix — it is Bollard's statement
/// about which generated types describe the daemon's answers, and it is what
/// `negotiate_version` will lower against. Handing Bollard 1.55 would assert
/// model coverage of 1.54 and 1.55 that its generated code does not have: the
/// attestation model and the per-device blkio fields that arrived in those two
/// versions are simply not in the crate, so the assertion would be false and
/// the failure would surface as a silently-missing field rather than an error.
///
/// This constant is therefore pinned, deliberately, below the ceiling. It is
/// raised only when Bollard's own generated models move, and that is a
/// dependency upgrade, not a decision this crate can make for itself.
///
/// [`BOLLARD_API_VERSION`]: https://docs.rs/bollard
const BOLLARD_API_VERSION: ClientVersion = ClientVersion {
    major_version: 1,
    minor_version: 53,
};

/// Docker Engine API version used by the initial client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    /// Major API version.
    pub major: usize,
    /// Minor API version.
    pub minor: usize,
}

impl From<ClientVersion> for ApiVersion {
    fn from(version: ClientVersion) -> Self {
        Self {
            major: version.major_version,
            minor: version.minor_version,
        }
    }
}

impl From<ApiVersion> for ClientVersion {
    fn from(version: ApiVersion) -> Self {
        Self {
            major_version: version.major,
            minor_version: version.minor,
        }
    }
}

/// The Engine API version the repository-owned client targets.
///
/// This is the crate's compatibility claim, and it is set here as a literal on
/// purpose. It used to be *derived* from `BOLLARD_API_VERSION`, which made the
/// claim and Bollard's ceiling the same number by construction and left nothing
/// to say which of the two a given call site meant. The two are now separate
/// facts with separate reasons to change, and the relationship between them is
/// asserted by the tests at the bottom of this file rather than by a shared
/// definition.
///
/// The owned transport owns its own request encoding, so raising this raises
/// what it can actually say. It does **not** raise the models. The flexible
/// Engine members that go through Bollard are still converted from Bollard's
/// 1.53 generated types, so a 1.54 or 1.55 response field has no typed home in
/// this crate unless a repository-owned document function returns it. The
/// precise list of what 1.54 and 1.55 added that this crate does not expose is
/// in the crate README's conformance table, and in `API_VERSION_ADDITIONS`.
///
/// Note what this does *not* license. Because `validate_client_version` bounds a
/// caller-supplied version by this constant, a caller can now pass 1.54 or 1.55
/// to `connect_endpoint_with_version`, and that value reaches Bollard's
/// `connect_with_*` as well as the owned transport. Passing the crate's own
/// `API_VERSION` is therefore supported; passing an intermediate version is the
/// caller's choice about a ceiling Bollard's models do not cover, and it is
/// their call to make.
pub const API_VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 55,
};

/// The Engine API changes in 1.54 and 1.55 that this crate does not implement.
///
/// Raising [`API_VERSION`] above Bollard's 1.53 ceiling is a claim, and a claim
/// needs a boundary as much as it needs the number. This is the list, derived
/// from the difference between moby's `api/docs/v1.53.yaml` and `v1.55.yaml`
/// (which is purely additive: no path, definition, field, or required member was
/// removed across the two versions) crossed with `api/docs/CHANGELOG.md`'s
/// per-version notes, which record two daemon behaviour changes that no schema
/// diff can show.
///
/// Each entry is `(version, what the version added, what this crate does)`. All
/// four gaps are real and none of them is visible in this crate's types, which
/// is the whole reason the list is written down rather than inferred.
///
/// The user-facing copy of this table is in `README.md`, which is the crate's
/// documentation through `#![doc = include_str!("../README.md")]`. Keeping it
/// here as well is not duplication for its own sake: `conformance_table_matches_
/// the_readme` fails if the two disagree, so neither copy can quietly fall
/// behind the other.
///
/// Two further 1.55 changes are documentation-only and are recorded in the
/// README rather than here: a `StopTimeout` description that now names the
/// `default-stop-timeout` setting, and clarifications to the `/secrets` and
/// `/configs` filter documentation.
///
/// # Provenance
///
/// So a later reader can re-derive the table rather than trust it:
///
/// - Changelog, per-version notes:
///   <https://github.com/moby/moby/blob/master/api/docs/CHANGELOG.md>
/// - Schema, both documents:
///   <https://github.com/moby/moby/blob/master/api/docs/v1.53.yaml> and
///   <https://github.com/moby/moby/blob/master/api/docs/v1.55.yaml>
/// - The live daemon, whose version gate is the ceiling this crate claims:
///   `GET /v1.56/_ping` answers `400` with `client version 1.56 is too new.
///   Maximum supported API version is 1.55`.
///
/// The two schema documents differ only by addition, which is the finding that
/// makes raising the ceiling safe for everything already implemented: nothing in
/// 1.53 was removed by 1.55, so no existing request shape or response field can
/// have become wrong. The two entries a schema diff cannot show -- the
/// `MacAddress` fix and the per-device blkio fix -- are in the changelog, and
/// both are daemon behaviour changes to fields that already existed.
///
/// This is scoped to `cfg(test)` because it is documentation a test reads rather
/// than code that runs: compiling it only is what lets
/// `every_recorded_addition_is_a_change_above_bollard_and_at_or_below_the_ceiling`
/// and `conformance_table_matches_the_readme` have something to check, which is
/// what keeps it from drifting. An `allow(dead_code)` in a normal build would be
/// the alternative and would be worse — it would suppress the lint on a table
/// nobody was reading.
#[cfg(test)]
pub(crate) const API_VERSION_ADDITIONS: &[(&str, &str, &str)] = &[
    (
        "1.54",
        "`GET /images/json` gains an `identity` query parameter, and each manifest summary gains an `Identity` member",
        "not implemented: the owned list request does not send `identity` and no repository-owned model carries `Identity`",
    ),
    (
        "1.54",
        "`POST /networks/{id}/connect` now applies the `MacAddress` in `EndpointSettings`, which the daemon had accepted and ignored since 1.44",
        "implemented by not needing to be: the owned connect body has always sent `MacAddress`, so the field becomes live rather than inert",
    ),
    (
        "1.55",
        "`GET /images/{name}/attestations`, a new endpoint returning in-toto attestation statements filtered by `platform`, `type`, and `statement`",
        "not implemented: no owned function reaches the endpoint and no model describes an `AttestationStatement`",
    ),
    (
        "1.55",
        "`POST /containers/{id}/update` honours the per-device blkio members it had always accepted and ignored",
        "not implemented and not reachable: `ContainerUpdateOptions` carries only `cpu_shares` and `memory`",
    ),
];

/// The crate's Engine API ceiling, spelled the way the error text spells it.
///
/// Three error messages name the version this crate supports, and all three used
/// to carry a literal. A literal in a message is a claim about the world that no
/// compile step checks and no test notices, so a raised ceiling would leave all
/// three saying a version the crate no longer targets. They read this instead.
pub(crate) fn api_version_ceiling() -> String {
    format!("v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Splits a `host:port` endpoint address into an owned-transport target.
///
/// A bare host is given the Engine's default port, which is what Docker's own
/// endpoint resolution does. An address that cannot be split returns `None`
/// rather than a guess, so a caller never dials a port it invented.
fn raw_target_for_address(address: &str) -> Option<raw::RawTarget> {
    let authority = address.rsplit_once("://").map_or(address, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    // A bracketed IPv6 literal keeps its brackets in the authority, and the port
    // separator is the one after the closing bracket.
    let parse_port = |text: &str| text.parse::<u16>().ok();
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .map_or(Some(DEFAULT_ENGINE_PORT), parse_port)?;
        (host.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), parse_port(port)?),
            None => (authority.to_owned(), DEFAULT_ENGINE_PORT),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(raw::RawTarget::Tcp {
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    })
}

/// The port a Docker endpoint uses when the address does not name one.
const DEFAULT_ENGINE_PORT: u16 = 2375;

fn validate_client_version(version: ClientVersion) -> Result<ClientVersion, Error> {
    if version.major_version != 1 || version.minor_version > API_VERSION.minor {
        return Err(Error::invalid_api_version());
    }
    Ok(version)
}

/// Selected daemon version fields exposed by the foundation facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonVersion {
    /// Docker daemon version.
    pub version: Option<String>,
    /// Highest API version advertised by the daemon.
    pub api_version: Option<String>,
    /// Minimum API version supported by the daemon.
    pub min_api_version: Option<String>,
    /// Operating system reported by the daemon.
    pub os: Option<String>,
    /// Architecture reported by the daemon.
    pub arch: Option<String>,
}

/// A Docker Engine API error returned by the daemon.
///
/// This is a repository-owned projection of the status and message returned by
/// Bollard. The underlying transport error remains available through
/// [`std::error::Error::source`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerApiError {
    /// HTTP status code returned by the Engine API.
    pub status_code: u16,
    /// Message returned in the Engine API error response.
    pub message: String,
}

impl fmt::Display for DockerApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "daemon returned HTTP {}: {}",
            self.status_code, self.message
        )
    }
}

impl std::error::Error for DockerApiError {}

/// Error category for the facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// The underlying Docker client rejected the request or configuration.
    Docker,
    /// A zero timeout would not provide a useful transport deadline.
    InvalidTimeout,
    /// A socket path was not valid UTF-8.
    InvalidSocketPath,
    /// An SSH identity path was not valid UTF-8.
    InvalidIdentityPath,
    /// The HTTPS endpoint has no context-local TLS material.
    TlsMaterialUnavailable,
    /// The `tls` feature is required for HTTPS endpoints.
    TlsFeatureUnavailable,
    /// The `ssh` feature is required for SSH endpoints.
    SshFeatureUnavailable,
    /// A directly supplied SSH endpoint is invalid.
    InvalidEndpoint,
    /// Docker context resolution failed.
    Context,
    /// A response could not be converted to the repository-owned model.
    Serialization,
    /// A repository-owned command option is invalid.
    InvalidInput,
    /// A Swarm resource version cannot be represented by the v1.53 request.
    InvalidVersion,
    /// The selected Engine API version is outside the supported v1.53 range.
    InvalidApiVersion,
    /// Registry credentials are unavailable, invalid, or oversized.
    Credentials,
    /// A caller-owned operation requires an asynchronous runtime.
    Runtime,
    /// Explicit proxy policy or transport configuration is invalid.
    Proxy,
    /// The connection to the daemon failed, or the request could not be sent.
    ///
    /// This is distinct from `InvalidInput`: the caller's request was valid and
    /// the daemon was never reached, which is a different thing for a user to be
    /// told and a different thing for a retry to act on.
    Transport,
}

/// Errors returned while constructing or using a Docker client.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    api: Option<DockerApiError>,
}

impl Error {
    fn docker(error: bollard::errors::Error) -> Self {
        let api_error = match &error {
            bollard::errors::Error::DockerResponseServerError {
                status_code,
                message,
            } => Some(DockerApiError {
                status_code: *status_code,
                message: message.clone(),
            }),
            _ => None,
        };
        Self {
            kind: ErrorKind::Docker,
            source: Some(Box::new(error)),
            api: api_error,
        }
    }

    fn serialization(error: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Serialization,
            source: Some(Box::new(error)),
            api: None,
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            source: Some(Box::new(std::io::Error::other(message.into()))),
            api: None,
        }
    }

    pub(crate) fn runtime(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Runtime,
            source: Some(Box::new(std::io::Error::other(message.into()))),
            api: None,
        }
    }

    pub(crate) fn invalid_version() -> Self {
        Self {
            kind: ErrorKind::InvalidVersion,
            source: None,
            api: None,
        }
    }

    /// Records an Engine API rejection reported by the repository-owned
    /// transport.
    ///
    /// The daemon's message is carried through unchanged in
    /// [`Error::api_error`] so a caller can print the daemon's own words under
    /// `--raw-error`. It is stored, never logged or reformatted.
    /// Records a failure to reach the daemon at all.
    ///
    /// The message names both the operation and the target, because
    /// "connection refused" on its own does not say which socket was tried.
    ///
    /// This is public so that a [`StreamFactory`](raw::StreamFactory) written
    /// outside this crate can report a failed open. A factory is handed a
    /// request it has to answer with an [`Error`], and a constructor that is
    /// `pub(crate)` leaves a factory outside the crate with no way to build one.
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Transport,
            source: Some(Box::new(std::io::Error::other(message.into()))),
            api: None,
        }
    }

    pub(crate) fn engine_api(status: http::StatusCode, message: String) -> Self {
        let api = DockerApiError {
            status_code: status.as_u16(),
            message,
        };
        Self {
            kind: ErrorKind::Docker,
            // `DockerApiError` is both the source and the structured report, so
            // the message is cloned once here rather than being reconstructed by
            // `Display` and losing the distinction between them.
            source: Some(Box::new(DockerApiError {
                status_code: api.status_code,
                message: api.message.clone(),
            })),
            api: Some(api),
        }
    }

    fn invalid_api_version() -> Self {
        Self {
            kind: ErrorKind::InvalidApiVersion,
            source: None,
            api: None,
        }
    }

    /// The class of failure, for a caller that wants to branch on it rather than
    /// match on the message.
    ///
    /// The [`Display`](std::fmt::Display) rendering is what a log wants; this is
    /// what a `match` wants.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the Engine API status and message when the daemon rejected the
    /// request.
    #[must_use]
    pub fn api_error(&self) -> Option<&DockerApiError> {
        self.api.as_ref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            // The daemon's own words are included when there are any. A bare
            // "Docker client error" is useless in a log line or a panic message:
            // it is the one case where the underlying cause is known and was
            // simply not being shown. The CLI already reads `api_error()` and
            // formats its own message, so this does not change what a user sees
            // there — it makes the error readable wherever it is printed.
            ErrorKind::Docker => match &self.api {
                Some(api) => write!(
                    formatter,
                    "Docker API error {}: {}",
                    api.status_code, api.message
                ),
                None => write!(formatter, "Docker client error"),
            },
            ErrorKind::InvalidTimeout => {
                write!(formatter, "Docker client timeout must be positive")
            }
            ErrorKind::InvalidSocketPath => {
                write!(formatter, "Docker socket path is not valid UTF-8")
            }
            ErrorKind::InvalidIdentityPath => {
                write!(formatter, "Docker SSH identity path is not valid UTF-8")
            }
            ErrorKind::TlsMaterialUnavailable => {
                write!(formatter, "Docker HTTPS endpoint has no TLS material")
            }
            ErrorKind::TlsFeatureUnavailable => {
                write!(formatter, "Docker HTTPS support requires the tls feature")
            }
            ErrorKind::SshFeatureUnavailable => {
                write!(formatter, "Docker SSH support requires the ssh feature")
            }
            ErrorKind::InvalidEndpoint => write!(formatter, "Docker SSH endpoint is invalid"),
            ErrorKind::Context => write!(formatter, "Docker context resolution failed"),
            ErrorKind::Serialization => {
                write!(formatter, "Docker response serialization error")
            }
            // The specific reason is included, as `Runtime` does. An
            // invalid-input error that cannot say *what* was invalid is the one
            // a caller cannot act on: the category alone is the same text for
            // every bad argument the crate rejects.
            ErrorKind::InvalidInput => {
                if let Some(source) = &self.source {
                    write!(formatter, "Docker command input is invalid: {source}")
                } else {
                    write!(formatter, "Docker command input is invalid")
                }
            }
            ErrorKind::InvalidVersion => {
                write!(
                    formatter,
                    "Docker resource version is outside the {} range",
                    api_version_ceiling()
                )
            }
            ErrorKind::InvalidApiVersion => {
                write!(
                    formatter,
                    "Docker Engine API version must be v{}.x no higher than {}",
                    API_VERSION.major,
                    api_version_ceiling()
                )
            }
            ErrorKind::Credentials => write!(formatter, "Docker registry credentials are invalid"),
            ErrorKind::Runtime => {
                if let Some(source) = &self.source {
                    write!(formatter, "Docker operation failed: {source}")
                } else {
                    write!(formatter, "Docker operation requires a Tokio runtime")
                }
            }
            ErrorKind::Proxy => write!(formatter, "Docker proxy configuration is invalid"),
            // Names the operation and the target, as `Error::transport`'s
            // documentation promises. It did not: every transport failure
            // rendered as the bare string "Docker transport error", and the
            // message was reachable only through `source()` -- which nothing
            // documented as the way to read it. Measured: a response truncated
            // mid-body printed `truncated HTTP: Some("Docker transport error")`
            // where the parse cause alongside it printed in full.
            //
            // The reason is rendered here rather than hidden, because this crate
            // keeps daemon and transport text out of *types that carry payloads*:
            // `raw/logs.rs` records that rule for log frames, and a
            // `std::io::Error`'s message is a diagnostic string with no payload
            // in it. What must not happen is a secret reaching it, and a
            // connection error carries a socket path, not a credential.
            ErrorKind::Transport => {
                let reason = self.source.as_ref().map(std::string::ToString::to_string);
                match reason {
                    Some(reason) => write!(formatter, "Docker transport error: {reason}"),
                    None => formatter.write_str("Docker transport error"),
                }
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<bollard::errors::Error> for Error {
    fn from(error: bollard::errors::Error) -> Self {
        Self::docker(error)
    }
}

impl From<ContextError> for Error {
    fn from(error: ContextError) -> Self {
        Self {
            kind: ErrorKind::Context,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

impl From<CredentialError> for Error {
    fn from(error: CredentialError) -> Self {
        Self {
            kind: ErrorKind::Credentials,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

impl From<ProxyError> for Error {
    fn from(error: ProxyError) -> Self {
        Self {
            kind: ErrorKind::Proxy,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

/// A Docker Engine client using the repository's initial API version.
#[derive(Clone, Debug)]
pub struct DockerClient {
    inner: Docker,
    proxy_policy: ProxyPolicy,
    raw_exec_endpoint: Option<String>,
    /// Where the owned transport connects, when that transport can reach the
    /// endpoint at all.
    ///
    /// `None` is a real answer, not a placeholder: an HTTPS or SSH endpoint
    /// needs TLS material or an OpenSSH child process, and the owned transport
    /// has neither yet. Keeping that as a `None` rather than guessing is what
    /// lets [`Self::raw_engine`] say which endpoint kind it cannot serve instead
    /// of failing later with a connection error.
    raw_target: OwnedTarget,
    /// The API version the owned transport prefixes onto every path.
    raw_version: ApiVersion,
}

/// What the owned transport can do with the endpoint this client was built for.
///
/// The two cases are kept apart rather than collapsed into an
/// `Option<RawTarget>` because the *reason* is the part a caller needs. Every
/// rewired facade method follows `if let Ok(engine) = self.raw_engine()`, so a
/// transport that cannot reach an endpoint falls back to Bollard without
/// anything counting it. A caller who asks [`DockerClient::raw_engine`] and is
/// told "not supported" learns nothing about which part was missing; a caller
/// told "the managed Engine SSH client authenticates with a key file and
/// `ssh://deploy@host` has no identity file" can act.
#[derive(Clone, Debug)]
enum OwnedTarget {
    /// The owned transport reaches this endpoint.
    Reachable(raw::RawTarget),
    /// It does not, and this is the reason it could not be built.
    Unreachable(String),
}

impl OwnedTarget {}

/// The reason a client built with no endpoint description gives.
const NO_ENDPOINT_KIND: &str = "this client was built without an endpoint description, so the \
                                owned transport has nothing to connect to; it supports a Unix \
                                socket, a Windows named pipe, plain HTTP, and an ssh:// endpoint \
                                reached with `docker system dial-stdio`, but not TLS";

impl DockerClient {
    fn from_inner(inner: Docker) -> Self {
        Self {
            inner,
            proxy_policy: ProxyPolicy::Direct,
            raw_exec_endpoint: None,
            raw_target: OwnedTarget::Unreachable(NO_ENDPOINT_KIND.to_owned()),
            raw_version: API_VERSION,
        }
    }

    fn from_inner_with_policy(inner: Docker, proxy_policy: ProxyPolicy) -> Self {
        Self {
            inner,
            proxy_policy,
            raw_exec_endpoint: None,
            raw_target: OwnedTarget::Unreachable(NO_ENDPOINT_KIND.to_owned()),
            raw_version: API_VERSION,
        }
    }

    /// Builds the owned transport for this client.
    ///
    /// The owned transport is the escape hatch for an Engine endpoint the
    /// generated client does not express. `POST /system/prune` is the first such
    /// endpoint: it has existed since Engine API v1.25, but Bollard 0.21.1 does
    /// not generate it, so there is no upstream change to wait for and no typed
    /// call to fall back to.
    ///
    /// # The routing rule every rewired facade method follows
    ///
    /// A facade method prefers this transport and keeps its Bollard path for the
    /// endpoint kinds this cannot reach:
    ///
    /// ```ignore
    /// if let Ok(engine) = self.raw_engine() {
    ///     return raw::some_operation(&engine, options).await;
    /// }
    /// // the existing Bollard path
    /// ```
    ///
    /// Two consequences are worth stating plainly, because both are easy to
    /// discover later as a surprise.
    ///
    /// **The fallback is silent, and that is the risk.** A defect in an
    /// owned-path implementation would then be visible only on the endpoint kinds
    /// the owned transport *does* reach — every Unix socket and `tcp://` client,
    /// which is the overwhelming majority. Nothing counts the fallbacks. The
    /// `raw_differential_*` test suites are what make it observable: each asserts
    /// that the owned transport and the Bollard facade put the *same request line*
    /// on the wire and read the *same document* back, for the same recorded
    /// daemon. A test that only compared decoded values would miss a path or
    /// version difference, and a version prefix changes which API the daemon
    /// answers with.
    ///
    /// **The request shape changes when a method is rewired.** The owned
    /// transport sends the API version prefix (`/v1.53/containers/json`) and
    /// encodes filters from a `BTreeMap`; the generated client sends an
    /// unversioned path and builds its filter JSON from a `HashMap`, so the
    /// parameter order is not stable between runs. Fixtures that assert a request
    /// line must be updated to the owned shape when a method moves — and that
    /// churn is the point, not an accident: the versioned path is what the
    /// decision record says the facade must never send.
    ///
    /// The two implementations return the same repository-owned types, so a
    /// rewired method's public signature and its result do not change, and a
    /// caller cannot tell which transport served it.
    ///
    /// # Errors
    ///
    /// Returns an error naming *which part* of this endpoint the owned transport
    /// cannot reach. An `ssh://` endpoint is reachable: it is opened as a
    /// `docker system dial-stdio` session, and it fails here only when the
    /// endpoint is missing something that session needs — a login name, an
    /// identity file, or a known-hosts file. An HTTPS endpoint still needs TLS
    /// material the owned transport does not hold, and a client built with no
    /// endpoint description has nothing to connect to.
    pub fn raw_engine(&self) -> Result<raw::RawEngine, Error> {
        match &self.raw_target {
            OwnedTarget::Reachable(target) => {
                Ok(raw::RawEngine::new(target.clone(), self.raw_version))
            }
            OwnedTarget::Unreachable(reason) => Err(Error::invalid_input(format!(
                "the owned transport cannot reach this endpoint: {reason}"
            ))),
        }
    }

    /// Connects using Docker's configured endpoint and environment defaults.
    ///
    /// This honors `DOCKER_HOST` when set and otherwise uses the platform
    /// default. Endpoint resolution selects the crate's API ceiling (v1.55);
    /// calls backed by Bollard's generated models remain capped at v1.53.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured endpoint is invalid or unsupported.
    pub fn connect_defaults() -> Result<Self, Error> {
        let resolver = ContextResolver::from_environment()?;
        let selection = resolver.resolve()?;
        Self::connect_endpoint_with_version(&selection.endpoint, selection.client_version)
    }

    /// Connects using Docker's configured endpoint and an explicit proxy
    /// policy.
    ///
    /// Context and endpoint selection remain unchanged; only the caller's
    /// explicit `ProxyPolicy` chooses the TCP transport route.
    ///
    /// # Errors
    ///
    /// Returns an error when context resolution fails or the policy is not
    /// valid for the selected endpoint.
    pub fn connect_defaults_with_policy(policy: ProxyPolicy) -> Result<Self, Error> {
        let resolver = ContextResolver::from_environment()?;
        let selection = resolver.resolve()?;
        Self::connect_endpoint_with_version_and_policy(
            &selection.endpoint,
            policy,
            selection.client_version,
        )
    }

    /// Connects to a typed Docker endpoint without a proxy.
    ///
    /// This method is the direct-policy path. It does not inspect process
    /// proxy environment variables. Use
    /// [`Self::connect_endpoint_with_policy`] for an explicit forward proxy.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is unavailable or its required
    /// transport feature is not enabled.
    pub fn connect_endpoint(endpoint: &Endpoint) -> Result<Self, Error> {
        Self::connect_endpoint_with_version(endpoint, API_VERSION)
    }

    /// Connects to a typed Docker endpoint with an explicit Engine API version.
    ///
    /// The version is applied to HTTP, socket, TLS, and SSH transports. It must
    /// be a v1 version no higher than the facade's v1.55 ceiling. The method
    /// does not contact the daemon while constructing the client.
    ///
    /// One version is named, and it reaches both paths. The owned transport
    /// follows the caller here rather than defaulting to
    /// [`API_VERSION`]: a caller who asked for 1.47 asked
    /// for it on every path this client can reach. Note that the Bollard half
    /// of such a client is then speaking a version Bollard's models cover, and
    /// the owned half is speaking one Bollard knows nothing about, which is the
    /// split in full.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is outside the supported range, the
    /// endpoint is unavailable, or its required transport feature is not
    /// enabled.
    pub fn connect_endpoint_with_version(
        endpoint: &Endpoint,
        version: impl Into<ClientVersion>,
    ) -> Result<Self, Error> {
        let client_version = validate_client_version(version.into())?;
        let owned_version: ApiVersion = client_version.into();
        match endpoint {
            Endpoint::Unix(path) => Self::connect_socket_with_version(
                path,
                raw::RawTarget::Unix(path.clone()),
                client_version,
                owned_version,
            ),
            Endpoint::NamedPipe(path) => Self::connect_socket_with_version(
                std::path::Path::new(path),
                raw::RawTarget::NamedPipe(std::path::PathBuf::from(path)),
                client_version,
                owned_version,
            ),
            Endpoint::Http(address) => {
                Self::connect_http_with_version(address, client_version, owned_version)
            }
            Endpoint::Https { address, material } => {
                #[cfg(feature = "tls")]
                {
                    let material = material.as_ref().ok_or(Error {
                        kind: ErrorKind::TlsMaterialUnavailable,
                        source: None,
                        api: None,
                    })?;
                    Ok(Self::from_inner(Docker::connect_with_ssl(
                        address,
                        &material.key_path,
                        &material.cert_path,
                        &material.ca_path,
                        DEFAULT_TIMEOUT_SECONDS,
                        &client_version,
                    )?))
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = (address, material, client_version);
                    Err(Error {
                        kind: ErrorKind::TlsFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
            Endpoint::Ssh {
                address,
                identity_path,
            } => {
                #[cfg(all(feature = "ssh", unix))]
                {
                    // The default here is the native `ssh` binary, because this
                    // constructor is how `DOCKER_HOST=ssh://…` arrives and that
                    // spelling carries no known-hosts file. The managed client
                    // refuses an endpoint with no key and no known-hosts file,
                    // so choosing it here would make the ordinary
                    // `DOCKER_HOST` case stop working in the owned path.
                    Self::connect_ssh_inner(
                        address,
                        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
                        identity_path.as_deref(),
                        &client_version,
                    )
                }
                #[cfg(not(all(feature = "ssh", unix)))]
                {
                    let _ = (address, identity_path, client_version);
                    Err(Error {
                        kind: ErrorKind::SshFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
        }
    }

    /// Connects to a typed Docker endpoint with an explicit version and proxy.
    ///
    /// This is the version-aware counterpart to
    /// [`Self::connect_endpoint_with_policy`]. Proxy selection and validation
    /// are otherwise unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, invalid proxy policy, or
    /// unsupported endpoint/proxy combination.
    pub fn connect_endpoint_with_version_and_policy(
        endpoint: &Endpoint,
        policy: ProxyPolicy,
        version: impl Into<ClientVersion>,
    ) -> Result<Self, Error> {
        let client_version = validate_client_version(version.into())?;
        match (&policy, endpoint) {
            (ProxyPolicy::Direct, _) => {
                Self::connect_endpoint_with_version(endpoint, client_version)
            }
            (ProxyPolicy::Http(proxy), Endpoint::Http(address)) => {
                let inner = proxy::connect_http(address, proxy, &client_version)?;
                Ok(Self::from_inner_with_policy(inner, policy))
            }
            (ProxyPolicy::Http(proxy), Endpoint::Https { address, material }) => {
                let Some(material) = material else {
                    return Err(Error {
                        kind: ErrorKind::TlsMaterialUnavailable,
                        source: None,
                        api: None,
                    });
                };
                #[cfg(feature = "tls")]
                {
                    let inner = proxy::connect_https(address, material, proxy, &client_version)?;
                    Ok(Self::from_inner_with_policy(inner, policy))
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = (address, material, proxy, client_version);
                    Err(Error {
                        kind: ErrorKind::TlsFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
            (ProxyPolicy::Http(_), _) => Err(ProxyError::EndpointNotProxyable.into()),
        }
    }

    /// Connects to a typed Docker endpoint with an explicit proxy policy.
    ///
    /// The default [`ProxyPolicy::Direct`] never reads process proxy variables.
    /// A [`ProxyPolicy::Http`] policy is accepted only for TCP HTTP/HTTPS
    /// endpoints; Unix sockets, named pipes, and SSH are rejected rather than
    /// silently ignoring the policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid proxy policy, an unsupported endpoint
    /// combination, missing TLS material, or an unavailable required feature.
    pub fn connect_endpoint_with_policy(
        endpoint: &Endpoint,
        policy: ProxyPolicy,
    ) -> Result<Self, Error> {
        Self::connect_endpoint_with_version_and_policy(endpoint, policy, API_VERSION)
    }

    /// Connects to the platform's default local Docker endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the local endpoint cannot be constructed.
    pub fn connect_local() -> Result<Self, Error> {
        Ok(Self::from_inner(Docker::connect_with_local_defaults()?))
    }

    /// Connects to an explicit plain HTTP endpoint without a proxy.
    ///
    /// Use [`Self::connect_endpoint_with_policy`] with an explicit
    /// [`ProxyPolicy::Http`] when forwarding is required. This direct method
    /// does not inspect process proxy environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is invalid.
    pub fn connect_http(endpoint: &str) -> Result<Self, Error> {
        Self::connect_http_with_version(endpoint, BOLLARD_API_VERSION, API_VERSION)
    }

    /// Builds a plain-HTTP client for `client_version`, with the owned
    /// transport on `owned_version`.
    ///
    /// The two arguments are separate for the same reason
    /// [`Self::connect_socket_with_version`]'s are: Bollard's ceiling and the
    /// owned transport's are different facts, and deriving one from the other
    /// is what made the coupling invisible while both were 1.53.
    fn connect_http_with_version(
        endpoint: &str,
        client_version: ClientVersion,
        owned_version: ApiVersion,
    ) -> Result<Self, Error> {
        let parsed = Endpoint::parse(endpoint).map_err(|source| Error {
            kind: ErrorKind::InvalidEndpoint,
            source: Some(Box::new(source)),
            api: None,
        })?;
        let raw_exec_endpoint = match parsed {
            Endpoint::Http(address) => Some(address),
            _ => None,
        };
        Ok(Self {
            inner: Docker::connect_with_http(endpoint, DEFAULT_TIMEOUT_SECONDS, &client_version)?,
            proxy_policy: ProxyPolicy::Direct,
            raw_exec_endpoint,
            raw_target: match Endpoint::parse(endpoint) {
                Ok(Endpoint::Http(address)) => raw_target_for_address(&address).map_or_else(
                    || {
                        OwnedTarget::Unreachable(format!(
                            "'{endpoint}' is not a host and port the owned transport can dial"
                        ))
                    },
                    OwnedTarget::Reachable,
                ),
                _ => OwnedTarget::Unreachable(format!(
                    "'{endpoint}' is not a plain-HTTP endpoint; the owned transport reaches a \
                     Unix socket, a Windows named pipe, and an ssh:// endpoint"
                )),
            },
            raw_version: owned_version,
        })
    }

    /// Connects to a Unix socket or Windows named pipe path.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is invalid or unavailable.
    pub fn connect_socket(path: &std::path::Path) -> Result<Self, Error> {
        Self::connect_socket_with_version(
            path,
            raw::RawTarget::Unix(path.to_path_buf()),
            BOLLARD_API_VERSION,
            API_VERSION,
        )
    }

    /// Builds a socket-backed client whose owned transport uses `raw_target`.
    ///
    /// The two are separate arguments because they are genuinely separate. This
    /// method is reached from both `Endpoint::Unix` and `Endpoint::NamedPipe`,
    /// and Bollard takes a single path for either, so it cannot tell them apart.
    /// The owned backend can, and must: handing it `\\.\pipe\docker_engine` in
    /// the `Unix` variant would ask for a Unix socket by a name that is not one,
    /// and the resulting error would name a path the caller never wrote.
    ///
    /// `client_version` and `owned_version` are separate for the same reason
    /// they are separate constants. Deriving one from the other here is what
    /// made this invisible for as long as the two were the same number: with
    /// both at 1.53, a caller that did not choose a version and a caller that
    /// chose 1.53 were indistinguishable, so nothing said which constructor
    /// was quietly holding the owned transport below the ceiling. The
    /// no-version constructors pass `BOLLARD_API_VERSION` for Bollard and
    /// `API_VERSION` for the owned transport, because Bollard is pinned by its
    /// models and the owned transport is pinned by nothing.
    fn connect_socket_with_version(
        path: &std::path::Path,
        raw_target: raw::RawTarget,
        client_version: ClientVersion,
        owned_version: ApiVersion,
    ) -> Result<Self, Error> {
        let path = path.to_str().ok_or(Error {
            kind: ErrorKind::InvalidSocketPath,
            source: None,
            api: None,
        })?;
        let mut client = Self::from_inner(Docker::connect_with_socket(
            path,
            DEFAULT_TIMEOUT_SECONDS,
            &client_version,
        )?);
        client.raw_target = OwnedTarget::Reachable(raw_target);
        client.raw_version = owned_version;
        Ok(client)
    }

    /// Connects to Docker over native OpenSSH.
    ///
    /// This requires the crate's `ssh` feature and uses the repository-owned
    /// Hyper/OpenSSH transport rather than Bollard's built-in SSH connector.
    /// The transport preserves explicit ports (for example, `:2222`) before
    /// OpenSSH destination resolution. The remote command is the Docker CLI's
    /// `docker system dial-stdio` process.
    ///
    /// The owned transport is reached over the **native `ssh` binary**, which
    /// is what makes an endpoint with no identity file or known-hosts file work
    /// at all: it inherits the invoking user's OpenSSH configuration, agent,
    /// and connection multiplexing, exactly as `docker` does. Use
    /// [`Self::connect_ssh_with_known_hosts`] for the managed `neotales-ssh`
    /// mechanism, which needs both a key file and a known-hosts file and makes
    /// host-key acceptance explicit rather than ambient.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timeout or SSH configuration.
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
    ) -> Result<Self, Error> {
        Self::connect_ssh_inner(endpoint, timeout, identity_path, &BOLLARD_API_VERSION)
    }

    /// Connects over native OpenSSH with an explicit known-hosts file.
    ///
    /// This is useful for disposable integration fixtures that must make host
    /// key acceptance and mismatch behavior explicit without relying on the
    /// invoking user's ambient SSH configuration.
    ///
    /// The owned transport uses the **managed `neotales-ssh` mechanism** here.
    /// The reason is the parameter: a caller who names a known-hosts file has
    /// said they want host-key policy to be explicit, and the managed client is
    /// the mechanism that can honour a *specific* file — it reads it directly
    /// rather than handing the decision to a process-wide OpenSSH
    /// configuration. The native binary has no way to be told which file to use
    /// without an `-F` argument the caller did not supply.
    ///
    /// This is [`Self::connect_ssh_managed`] with the two settings this signature
    /// can express named as arguments: a timeout, and an unencrypted identity
    /// file if a path was given. Everything else the managed client can do — an
    /// encrypted identity and its passphrase, or an SSH password — is a method
    /// on the builder this is built from, because each of those needs a value of
    /// its own and a fifth positional parameter is what makes a signature
    /// unreadable.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint, timeout, identity path, or
    /// known-hosts path.
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh_with_known_hosts(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
        known_hosts_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let builder = Self::connect_ssh_managed(endpoint, known_hosts_path).timeout(timeout);
        let builder = match identity_path {
            Some(path) => builder.identity_file(path),
            None => builder,
        };
        builder.connect()
    }

    /// Starts describing a managed `neotales-ssh` connection to a remote Engine.
    ///
    /// The managed mechanism is the one that reads a **named** known-hosts file
    /// rather than handing host-key policy to a process-wide OpenSSH
    /// configuration, so a known-hosts path is required here and is not
    /// optional the way it is for [`Self::connect_ssh`]. Host-key policy is not
    /// something a caller reaches this mechanism without naming.
    ///
    /// A credential is *not* required here, and that is deliberate: a caller who
    /// named none gets a client whose first request reports that no credential
    /// was given, which is a different and more actionable failure than a
    /// description that cannot be built at all. A default credential would be
    /// worse than either — reading the invoking user's `~/.ssh/id_rsa` behind
    /// the caller's back is what the native `ssh` binary does, and the reason
    /// this mechanism exists is to be explicit instead.
    ///
    /// # Errors
    ///
    /// This cannot fail; the error comes from [`ManagedSshClient::connect`].
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh_managed(
        endpoint: &str,
        known_hosts_path: &std::path::Path,
    ) -> ManagedSshClient {
        ManagedSshClient::new(endpoint, known_hosts_path)
    }

    /// The body of [`ManagedSshClient::connect`].
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout, a path that is not valid UTF-8, and
    /// a connection policy whose limits cannot be honoured. The endpoint and the
    /// credential have already been checked by the time this is called, and the
    /// target itself is recorded rather than raised: see the note on
    /// `connect_ssh_inner` for why an owned-path gap does not become a
    /// connection error when the Bollard facade above it has already succeeded.
    #[cfg(all(feature = "ssh", unix))]
    pub(crate) fn connect_ssh_managed_inner(
        builder: &ManagedSshClient,
        options: crate::ssh_neotales::ManagedSshOptions,
    ) -> Result<Self, Error> {
        let timeout_seconds = builder.request_timeout().as_secs();
        if timeout_seconds == 0 {
            return Err(Error {
                kind: ErrorKind::InvalidTimeout,
                source: None,
                api: None,
            });
        }
        // The Bollard facade above the owned transport still goes through the
        // native `ssh` binary, which discovers its own credential. A password
        // or an encrypted key is the *owned* transport's credential and the
        // native binary is not told it: a caller who wants the facade to use a
        // password should use `connect_ssh` and let OpenSSH prompt. Passing the
        // identity path where there is one keeps the common case working on both
        // paths.
        let native_identity = builder
            .credential()
            .and_then(SshIdentity::key_file)
            .and_then(|path| path.to_str().map(str::to_owned));
        let inner = crate::ssh_transport::connect(
            builder.endpoint(),
            timeout_seconds,
            native_identity,
            None,
            &BOLLARD_API_VERSION,
        )?;
        let mut client = Self::from_inner(inner);
        // `inner.client_version()` is Bollard's, and reads 1.53 because Bollard
        // is pinned there by its generated models. The owned transport reaches
        // the same daemon over the same endpoint and is pinned by no
        // dependency, so it starts at the crate's ceiling. Taking the two from
        // one source is what this assignment used to do, and while both were
        // 1.53 that was indistinguishable from being correct.
        client.raw_version = API_VERSION;
        client.raw_target =
            OwnedTarget::Reachable(crate::ssh_neotales::managed_ssh_target(options));
        Ok(client)
    }

    /// Builds the owned `RawTarget` for an `ssh://` endpoint reached with the
    /// native `ssh` binary.
    ///
    /// The managed `neotales-ssh` mechanism has its own constructor,
    /// [`Self::connect_ssh_managed`], because it needs a credential and a
    /// connection policy that this four-argument signature has nowhere to put.
    /// There is no reason for a managed target to pass through here, so it does
    /// not.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is not an `ssh://` endpoint or cannot
    /// be split into a destination.
    #[cfg(all(feature = "ssh", unix))]
    fn ssh_raw_target(
        endpoint: &str,
        identity_path: Option<&std::path::Path>,
    ) -> Result<raw::RawTarget, Error> {
        let destination = ssh_dial_stdio::SshDestination::parse(endpoint)?;
        Ok(crate::ssh_dial_stdio::native_ssh_target(
            ssh_dial_stdio::NativeSshOptions {
                program: "ssh".to_owned(),
                destination: destination.argument(),
                // The default port is left to OpenSSH so a `Port` in the user's
                // own configuration still applies.
                port: (destination.port != 22).then_some(destination.port),
                identity_path: identity_path.map(std::path::Path::to_path_buf),
                config_file: None,
            },
        ))
    }

    /// The shared body of both `ssh://` constructors, for the native `ssh`
    /// binary only.
    ///
    /// # Errors
    ///
    /// Returns an error for an address that is not an `ssh://` endpoint, a zero
    /// timeout, a path that is not valid UTF-8, and a Bollard SSH client that
    /// could not be built.
    #[cfg(all(feature = "ssh", unix))]
    fn connect_ssh_inner(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
        client_version: &ClientVersion,
    ) -> Result<Self, Error> {
        let parsed_endpoint = Endpoint::parse(endpoint).map_err(|source| Error {
            kind: ErrorKind::InvalidEndpoint,
            source: Some(Box::new(source)),
            api: None,
        })?;
        if !matches!(parsed_endpoint, Endpoint::Ssh { .. }) {
            return Err(Error {
                kind: ErrorKind::InvalidEndpoint,
                source: None,
                api: None,
            });
        }

        let timeout_seconds = timeout.as_secs();
        if timeout_seconds == 0 {
            return Err(Error {
                kind: ErrorKind::InvalidTimeout,
                source: None,
                api: None,
            });
        }

        let identity = match identity_path {
            Some(path) => Some(
                path.to_str()
                    .ok_or(Error {
                        kind: ErrorKind::InvalidIdentityPath,
                        source: None,
                        api: None,
                    })?
                    .to_owned(),
            ),
            None => None,
        };

        let inner = crate::ssh_transport::connect(
            endpoint,
            timeout_seconds,
            identity,
            None,
            client_version,
        )?;
        let mut client = Self::from_inner(inner);
        // As in `connect_ssh_managed_inner`: the version the Bollard client
        // negotiated is not the version the owned transport should speak, and
        // `client_version` here is always `BOLLARD_API_VERSION` because
        // `connect_ssh_inner` has one caller and that caller does not take a
        // version.
        client.raw_version = API_VERSION;
        // The owned transport reaches the same daemon over the same endpoint,
        // through a `docker system dial-stdio` session rather than through
        // bollard's OpenSSH connector. It is a *second* transport to the same
        // place, not a second transport implementation: everything above
        // `RawTarget` is the one `raw::transport`.
        //
        // A failure to describe the endpoint is recorded, not raised. The
        // OpenSSH-backed facade above has already succeeded at this point, and
        // turning an owned-path gap into a connection error would take away a
        // path that works. The reason is carried so `raw_engine` can report it.
        client.raw_target = match Self::ssh_raw_target(endpoint, identity_path) {
            Ok(target) => OwnedTarget::Reachable(target),
            Err(error) => OwnedTarget::Unreachable(error.to_string()),
        };
        Ok(client)
    }

    /// Returns the explicit proxy policy selected for this client.
    #[must_use]
    pub const fn proxy_policy(&self) -> &ProxyPolicy {
        &self.proxy_policy
    }

    /// Returns the version Bollard is using.
    ///
    /// This is **not** the crate's ceiling, and it is not the version the owned
    /// transport sends. It is the version the generated client was constructed
    /// with, which on every constructor that takes no explicit version is
    /// `BOLLARD_API_VERSION` (1.53) regardless of
    /// [`API_VERSION`] being 1.55.
    ///
    /// It is left reading Bollard's value because that is what it has always
    /// read and what a caller of a Bollard-backed client means by it; making it
    /// report the owned transport's version would have a method named for the
    /// generated client answer for something else. The owned transport's
    /// version is observable through [`Self::raw_engine`] instead, whose request
    /// lines carry the prefix.
    #[must_use]
    pub fn client_version(&self) -> ApiVersion {
        self.inner.client_version().into()
    }

    /// Negotiates the API version down to the daemon's supported version.
    ///
    /// The client never raises its own v1.55 ceiling, and it never raises
    /// Bollard's v1.53 either: a negotiation only ever lowers.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon version cannot be read or parsed.
    pub async fn negotiate_version(self) -> Result<Self, Error> {
        let proxy_policy = self.proxy_policy;
        let raw_exec_endpoint = self.raw_exec_endpoint;
        let raw_target = self.raw_target;
        let inner = self.inner.negotiate_version().await?;
        // The negotiation can lower the version, and the owned transport has to
        // speak the same one, or a path this client believes exists would be sent
        // to a daemon that has never heard of it. It is Bollard's negotiation, so
        // it begins at Bollard's 1.53 and can only land at or below it: against a
        // daemon advertising a maximum of 1.55 this leaves the owned transport at
        // 1.53. That is below the crate's ceiling and is the correct outcome --
        // a negotiation result is not a statement about what the crate supports,
        // it is a statement about what this daemon speaks.
        let raw_version = inner.client_version().into();
        Ok(Self {
            inner,
            proxy_policy,
            raw_exec_endpoint,
            raw_target,
            raw_version,
        })
    }

    /// Sends a ping request to the daemon.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the daemon is unavailable.
    pub async fn ping(&self) -> Result<String, Error> {
        Ok(self.inner.ping().await?)
    }

    /// Returns selected daemon version information.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn version(&self) -> Result<DaemonVersion, Error> {
        let version = self.inner.version().await?;
        Ok(DaemonVersion {
            version: version.version,
            api_version: version.api_version,
            min_api_version: version.min_api_version,
            os: version.os,
            arch: version.arch,
        })
    }

    /// Returns the daemon version response as repository-owned JSON.
    ///
    /// This makes the complete v1.53 response available to output formatters
    /// without exposing Bollard's generated model.
    ///
    /// # Errors
    ///
    /// Returns a transport or serialization error.
    pub async fn version_value(&self) -> Result<serde_json::Value, Error> {
        self.inner
            .version()
            .await
            .map_err(Error::from)
            .and_then(|value| serde_json::to_value(value).map_err(Error::serialization))
    }

    /// Lists images using repository-owned options.
    ///
    /// The response contains the stable v1.53 image-summary fields supported by
    /// this crate. Experimental manifest and descriptor fields remain outside
    /// this first resource boundary.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn list_images(
        &self,
        options: Option<ImageListOptions>,
    ) -> Result<Vec<ImageSummary>, Error> {
        let options = options.and_then(ImageListOptions::into_bollard);
        let images = self.inner.list_images(options).await?;
        Ok(images.into_iter().map(ImageSummary::from_bollard).collect())
    }

    /// Removes an image and returns the daemon's untagged/deleted records.
    ///
    /// Registry authentication headers are intentionally not accepted by this
    /// first boundary; image pull/push and credential integration remain a
    /// separate operation slice.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn remove_image(
        &self,
        name: &str,
        options: Option<ImageRemoveOptions>,
    ) -> Result<Vec<ImageDeleteResult>, Error> {
        let options = options.and_then(ImageRemoveOptions::into_bollard);
        let results = self.inner.remove_image(name, options, None).await?;
        Ok(results
            .into_iter()
            .map(ImageDeleteResult::from_bollard)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiVersion, BOLLARD_API_VERSION, DockerClient, Endpoint, Error, ErrorKind};

    /// Pins the number the crate claims to target.
    ///
    /// This one keeps a literal on purpose, and it is the deliberate exception
    /// to the rule every other test in this crate follows. Almost everything
    /// else here derives from `API_VERSION` because its subject is plumbing --
    /// the path a request takes, the prefix it carries -- and a literal in those
    /// would only mean the ceiling had to be re-typed in 30 places before a
    /// legitimate change to it could be made. This test's subject *is* the
    /// number. Derive it and it asserts that `API_VERSION` equals itself, which
    /// is the same as asserting nothing, and the crate's central claim becomes
    /// untested.
    #[test]
    fn api_version_claims_one_fifty_five() {
        assert_eq!(
            super::API_VERSION,
            ApiVersion {
                major: 1,
                minor: 55,
            }
        );
    }

    /// Pins Bollard's version, and fails if anyone raises it.
    ///
    /// Bollard 0.21.1's models are generated at 1.53. Raising this constant
    /// without a Bollard upgrade asserts model coverage the dependency does not
    /// have, and the failure mode is a silently absent field rather than an
    /// error -- which is why this is a test and not a comment.
    #[test]
    fn bollards_version_stays_at_one_fifty_three() {
        assert_eq!(BOLLARD_API_VERSION.major_version, 1);
        assert_eq!(BOLLARD_API_VERSION.minor_version, 53);
    }

    /// Fails if the two are made equal again.
    ///
    /// They were the same number by construction until the ceiling was raised,
    /// and that is exactly the state in which a future edit cannot tell which
    /// constant a given call site was supposed to mean: an author reading
    /// `BOLLARD_API_VERSION` at a Bollard call site would reasonably conclude
    /// the number did not matter, and would not notice the day it started to.
    /// The gap between the two is the whole point of the split, so a diff that
    /// closes it is a regression whether or not the resulting code compiles.
    #[test]
    fn the_owned_ceiling_and_bollards_ceiling_are_intentionally_different() {
        let owned = super::API_VERSION;
        let bollard = ApiVersion::from(BOLLARD_API_VERSION);
        assert_ne!(
            (owned.major, owned.minor),
            (bollard.major, bollard.minor),
            "API_VERSION and BOLLARD_API_VERSION are the same number again, so the \
             two have collapsed into one fact and the Bollard call sites no longer \
             say which ceiling they mean"
        );
        assert!(
            owned.minor > bollard.minor,
            "the owned client targets API {owned:?}, which is below Bollard's {bollard:?}; \
             the owned transport owns its own request encoding and is not limited by it"
        );
    }

    /// The two conversions round-trip, because four call sites depend on it.
    ///
    /// `API_VERSION` and `BOLLARD_API_VERSION` are different types now and the
    /// `From` impls between them are the only thing that makes an
    /// `ApiVersion` usable where Bollard wants a `ClientVersion`. If that
    /// conversion ever starts clamping or offsetting, every Bollard call site
    /// silently changes version and this is the only thing that would say so.
    #[test]
    fn the_api_version_conversions_round_trip() {
        let version = super::API_VERSION;
        let client: bollard::ClientVersion = version.into();
        assert_eq!(ApiVersion::from(client), version);
        let bollard_version = ApiVersion::from(BOLLARD_API_VERSION);
        assert_eq!(
            bollard::ClientVersion::from(bollard_version),
            BOLLARD_API_VERSION
        );
    }

    /// Fails if the conformance table drifts from the version it describes.
    ///
    /// Every entry claims to be a change in a version at or below the ceiling
    /// and above Bollard's. An entry naming a version the crate does not
    /// target is a claim about a version this crate makes no conformance
    /// promise for, and an entry naming 1.53 or below is a change this crate
    /// already implemented or already never had.
    #[test]
    fn every_recorded_addition_is_a_change_above_bollard_and_at_or_below_the_ceiling() {
        let floor = super::ApiVersion::from(BOLLARD_API_VERSION).minor;
        for (version, change, status) in super::API_VERSION_ADDITIONS {
            let minor: usize = version
                .strip_prefix("v1.")
                .or_else(|| version.strip_prefix("1."))
                .unwrap_or_else(|| panic!("entry {change:?} names version {version:?}"))
                .parse()
                .unwrap_or_else(|_| panic!("entry {change:?} names version {version:?}"));
            assert!(
                minor > floor && minor <= super::API_VERSION.minor,
                "entry {change:?} is recorded against {version}, which is outside the \
                 band this crate raised its ceiling across ({floor} < v <= {})",
                super::API_VERSION.minor
            );
            assert!(
                !status.trim().is_empty(),
                "entry {change:?} has an empty status, which reads as 'nothing to say' \
                 rather than as a decision"
            );
        }
    }

    /// The README is the crate's public documentation, so its copy of the
    /// conformance table has to be the same table.
    ///
    /// Two copies of the same list is duplication with a failure mode, and the
    /// failure mode is the one this repository keeps finding: a doc that asserts
    /// a check catches something it does not. `API_VERSION_ADDITIONS` is what a
    /// test can check, and the README is what a reader reads, so this test is
    /// what stops the second from quietly describing a different boundary.
    #[test]
    fn conformance_table_matches_the_readme() {
        let readme = include_str!("../README.md");
        for (version, change, status) in super::API_VERSION_ADDITIONS {
            for (what, needle) in [
                ("version", *version),
                ("change", *change),
                ("status", *status),
            ] {
                assert!(
                    readme.contains(needle),
                    "the README's conformance table does not carry the {what} of the \
                     {version} entry ({needle:?}); README.md is the crate's documentation \
                     through #![doc = include_str!], so a reader sees a boundary the code \
                     no longer holds"
                );
            }
        }
    }

    #[test]
    fn reports_invalid_timeout() {
        let error = Error {
            kind: ErrorKind::InvalidTimeout,
            source: None,
            api: None,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidTimeout);
        assert_eq!(error.to_string(), "Docker client timeout must be positive");
    }

    #[tokio::test]
    async fn bollard_stays_at_1_53_while_the_owned_transport_reaches_the_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let mut request = [0; 2048];
            let length = stream
                .read(&mut request)
                .map_err(|error| error.to_string())?;
            let request =
                std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
            assert!(request.starts_with("GET /_ping "), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_http(&format!("http://{address}"))?;

        // The Bollard half, and the reason `BOLLARD_API_VERSION` exists.
        assert_eq!(
            client.client_version(),
            ApiVersion::from(super::BOLLARD_API_VERSION),
            "Bollard must stay at the version its models are generated for"
        );

        // The owned half, and the reason it is a separate value at all. This
        // assertion is the whole decoupling: before the split, `raw_version`
        // was read back out of the argument passed to Bollard, so it was 1.53
        // here for no reason anyone had stated, and no test could have said so
        // because `client_version()` and `raw_version` agreed by construction.
        let engine = client.raw_engine()?;
        assert_eq!(engine.version(), super::API_VERSION);
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(hyper::Method::GET, "/info"))
            .expect("an absolute path");
        assert_eq!(
            uri,
            format!(
                "/v{}.{}/info",
                super::API_VERSION.major,
                super::API_VERSION.minor
            ),
            "the owned transport must speak the crate's ceiling, not Bollard's pin"
        );

        assert_eq!(client.ping().await?, "OK");
        server
            .join()
            .expect("HTTP fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[tokio::test]
    async fn selected_client_version_is_used_over_http() -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let mut request = [0; 2048];
            let length = stream
                .read(&mut request)
                .map_err(|error| error.to_string())?;
            let request =
                std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
            assert!(request.starts_with("GET /_ping "), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http(format!("http://{address}")),
            ApiVersion {
                major: 1,
                minor: 47,
            },
        )?;
        assert_eq!(
            client.client_version(),
            ApiVersion {
                major: 1,
                minor: 47
            }
        );
        assert_eq!(client.ping().await?, "OK");
        server
            .join()
            .expect("HTTP fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    /// The boundary itself: 1.55 in, 1.56 and 2.0 out.
    ///
    /// This replaced a test that rejected 1.54, which is the boundary this
    /// crate had when its ceiling was Bollard's 1.53. It is worth naming what
    /// changed, because the old test was not merely stale -- it asserted the
    /// *opposite* of the decision, and it passed. A test that says 1.54 must be
    /// rejected keeps passing right up to the moment the ceiling is raised, and
    /// then has to be deleted rather than trusted, which is the shape of change
    /// that quietly removes a check.
    ///
    /// The accepted half matters as much as the rejected half. Checking only
    /// that 1.56 fails would also pass against a ceiling of 1.40, and this is
    /// the test that says 1.55 is reachable.
    #[test]
    fn accepts_the_ceiling_and_rejects_just_above_it() {
        let endpoint = Endpoint::Http("http://127.0.0.1:2375".to_owned());

        let accepted = DockerClient::connect_endpoint_with_version(
            &endpoint,
            ApiVersion {
                major: 1,
                minor: 55,
            },
        )
        .expect("the crate's own API version must be accepted");
        assert_eq!(accepted.client_version(), super::API_VERSION);

        for version in [
            ApiVersion {
                major: 1,
                minor: 56,
            },
            ApiVersion { major: 2, minor: 0 },
            ApiVersion {
                major: 1,
                minor: 900,
            },
        ] {
            let error = DockerClient::connect_endpoint_with_version(&endpoint, version)
                .expect_err("unsupported API version must fail before transport setup");
            assert_eq!(error.kind(), ErrorKind::InvalidApiVersion);
        }
    }

    /// 1.54 is below the new ceiling and above the old one, and must be valid.
    ///
    /// This is the version a raise quietly gets wrong. It is the only value
    /// that separates "the ceiling moved" from "the check was deleted", so it
    /// is asserted on its own rather than folded into the test above: a ceiling
    /// left at 1.53 rejects it, and a ceiling left un-bounded accepts 1.56 as
    /// well, and neither mistake is visible in the other test alone.
    #[test]
    fn one_fifty_four_is_below_the_ceiling_and_still_valid() {
        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http("http://127.0.0.1:2375".to_owned()),
            ApiVersion {
                major: 1,
                minor: 54,
            },
        )
        .expect("1.54 is below the ceiling and must be accepted");
        assert_eq!(
            client.client_version(),
            ApiVersion {
                major: 1,
                minor: 54
            }
        );
    }

    /// The API-version error text has to name the version the crate targets.
    ///
    /// This reads the rendered string and then pins the number separately,
    /// because the failure being guarded against is a message that formats the
    /// *wrong* number while everything else in the file derives correctly. A
    /// test that built its expectation from the same helper the message uses
    /// would pass in exactly that case -- the helper would be wrong too.
    #[test]
    fn the_invalid_api_version_message_names_the_live_ceiling() {
        assert_eq!(
            super::api_version_ceiling(),
            "v1.55",
            "the rendered ceiling must be the live number, not Bollard's 1.53"
        );

        let rendered = Error {
            kind: ErrorKind::InvalidApiVersion,
            source: None,
            api: None,
        }
        .to_string();
        assert_eq!(
            rendered,
            "Docker Engine API version must be v1.x no higher than v1.55"
        );
    }

    /// The Swarm resource-version message names the same live ceiling.
    ///
    /// This one is a resource version rather than an API version, so it is easy
    /// to leave behind when the other two move: it reads like a statement about
    /// a Swarm document version, and the version in it looks like part of that
    /// sentence rather than a claim about this crate.
    #[test]
    fn the_resource_version_message_names_the_live_ceiling() {
        let rendered = Error {
            kind: ErrorKind::InvalidVersion,
            source: None,
            api: None,
        }
        .to_string();
        assert_eq!(
            rendered,
            "Docker resource version is outside the v1.55 range"
        );
    }

    /// No reachable error text may still name Bollard's 1.53 as this crate's
    /// ceiling.
    ///
    /// The three messages are checked one at a time above, which catches a
    /// change to any of them. This catches the fourth: one added later, or one
    /// in a module nobody looked at. It cannot enumerate future messages, so it
    /// is a backstop rather than the primary check, and the primary checks are
    /// the ones that would say which message moved.
    #[test]
    fn no_error_kind_renders_a_stale_ceiling() {
        for kind in [ErrorKind::InvalidApiVersion, ErrorKind::InvalidVersion] {
            let rendered = Error {
                kind,
                source: None,
                api: None,
            }
            .to_string();
            assert!(
                !rendered.contains("v1.53"),
                "{kind:?} renders {rendered:?}, which names Bollard's 1.53 rather than \
                 this crate's ceiling"
            );
        }
    }

    /// The socket constructor decouples the two versions too.
    ///
    /// The plain-HTTP case above already fails if `raw_version` is derived from
    /// the Bollard argument, so the coupling was not invisible. It was invisible
    /// *here*, on the socket constructor, which is the one almost every caller
    /// reaches — `connect_defaults` and `connect_endpoint` both land on it. The
    /// reason it is a separate test rather than another assertion in the first
    /// one is that it is a separate line of code: `connect_socket_with_version`
    /// assigns `raw_version` itself rather than going through the struct
    /// literal the HTTP path uses, so a fix to one does nothing for the other.
    /// Both were re-coupled during this change and only the HTTP one was
    /// caught, which is the reason this test exists.
    #[test]
    fn the_socket_constructor_speaks_the_ceiling_to_the_owned_transport() {
        // A real socket file, because Bollard resolves the path when the client
        // is built and refuses one that does not exist. It is never dialled:
        // the owned transport's version is decided before any connection is
        // attempted, and nothing here sends a byte.
        let path = std::env::temp_dir().join("api155-decoupling-probe.sock");
        std::fs::write(&path, b"").expect("a placeholder socket path");
        let client = DockerClient::connect_socket(&path)
            .expect("a client can be built for a path that exists");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            client.client_version(),
            ApiVersion::from(super::BOLLARD_API_VERSION),
            "Bollard is pinned at 1.53 by its generated models"
        );
        let engine = client.raw_engine().expect("a Unix socket is reachable");
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(
                hyper::Method::GET,
                "/containers/json",
            ))
            .expect("an absolute path");
        assert_eq!(
            uri,
            format!(
                "/v{}.{}/containers/json",
                super::API_VERSION.major,
                super::API_VERSION.minor
            ),
            "the socket constructor must not hand the owned transport Bollard's 1.53"
        );
    }

    /// A caller-selected version reaches both paths, and both report it.
    ///
    /// The decoupling above is about the *defaults*. This is the other
    /// direction: `connect_endpoint_with_version` takes one version, and the
    /// owned transport follows the caller rather than reverting to
    /// `API_VERSION`. A caller who asked for 1.47 asked for it everywhere, so a
    /// test that only checked the defaults would not notice the owned half
    /// ignoring an explicit choice — and would not notice it reverting either.
    #[test]
    fn a_caller_selected_version_reaches_the_owned_transport_too() {
        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http("http://127.0.0.1:2375".to_owned()),
            ApiVersion {
                major: 1,
                minor: 47,
            },
        )
        .expect("1.47 is below the ceiling");
        let engine = client
            .raw_engine()
            .expect("a plain HTTP endpoint is reachable");
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(hyper::Method::GET, "/info"))
            .expect("an absolute path");
        assert_eq!(
            uri, "/v1.47/info",
            "the owned transport must follow the caller's choice, not the ceiling"
        );
    }

    #[tokio::test]
    async fn exercises_container_lifecycle_request_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            for expected in [
                ("POST", "/containers/demo/start"),
                ("POST", "/containers/demo/stop?signal=SIGTERM&t=7"),
                ("DELETE", "/containers/demo?v=true&force=true&link=false"),
            ] {
                let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
                let mut request = [0; 4096];
                let length = stream
                    .read(&mut request)
                    .map_err(|error| error.to_string())?;
                let request =
                    std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
                let request_line = request.lines().next().ok_or("missing request line")?;
                assert!(request_line.starts_with(expected.0), "{request_line}");
                assert!(request_line.contains(expected.1), "{request_line}");
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_http(&format!("http://{address}"))?;
        client.start_container("demo").await?;
        client
            .stop_container(
                "demo",
                Some(super::ContainerStopOptions {
                    signal: Some("SIGTERM".to_owned()),
                    timeout_seconds: Some(7),
                }),
            )
            .await?;
        client
            .remove_container(
                "demo",
                Some(super::ContainerRemoveOptions {
                    remove_volumes: true,
                    force: true,
                    remove_link: false,
                }),
            )
            .await?;
        server
            .join()
            .expect("container lifecycle fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[test]
    fn reports_missing_socket() {
        let path = std::path::Path::new("/path/that/does/not/exist/docker.sock");
        assert!(matches!(
            DockerClient::connect_socket(path),
            Err(error) if error.kind() == ErrorKind::Docker
        ));
    }

    #[cfg(all(feature = "ssh", unix))]
    #[test]
    fn rejects_invalid_direct_ssh_endpoint_before_connecting() {
        let result = DockerClient::connect_ssh(
            "ssh://user:password@example.com",
            std::time::Duration::from_secs(1),
            None,
        );
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidEndpoint));
    }

    #[cfg(all(feature = "ssh", unix))]
    #[test]
    fn rejects_zero_ssh_timeout_before_connecting() {
        let result =
            DockerClient::connect_ssh("ssh://example.invalid", std::time::Duration::ZERO, None);
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidTimeout));
    }
}
