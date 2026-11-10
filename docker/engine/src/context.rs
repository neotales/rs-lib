//! Docker context and endpoint resolution.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ApiVersion, Endpoint, EndpointError, EngineCapability, EngineKind, EngineProfile, TlsMaterial,
    UnsupportedCapability,
};

/// Rootful Podman service socket, per Podman's documented location.
pub const PODMAN_ROOTFUL_SOCKET: &str = "/run/podman/podman.sock";

/// Rootful nerdctl Docker-compatible socket.
///
/// Upstream `nerdctl` is a CLI and does not ship a Docker-compatible API
/// server; the `nerdctl.sock` endpoint is provided by a separate
/// Docker-compatible daemon, and `/run/nerdctl/nerdctl.sock` is its documented
/// rootful location (`ListenStream=%t/nerdctl/nerdctl.sock`, with `%t` = `/run`).
pub const NERDCTL_ROOTFUL_SOCKET: &str = "/run/nerdctl/nerdctl.sock";

/// Directory that holds an engine's service socket, relative to a user runtime
/// directory.
const NERDCTL_SOCKET_DIRECTORY: &str = "nerdctl";

/// Environment variable Podman itself honors for its service endpoint.
///
/// The nerdctl profile honors the same variable as an explicit override so both
/// Docker-compatible profiles resolve the same way. `nerdctl` itself does not
/// read it: it addresses containerd through `CONTAINERD_ADDRESS`.
pub const CONTAINER_HOST_VARIABLE: &str = "CONTAINER_HOST";

/// Source that supplied a resolved Docker endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointSource {
    /// `DOCKER_CONTEXT` selected a named context.
    EnvironmentContext(String),
    /// `config.json` selected the current context.
    CurrentContext(String),
    /// `DOCKER_HOST` supplied the endpoint.
    DockerHost,
    /// The platform default was used.
    PlatformDefault,
    /// `CONTAINER_HOST` supplied a Podman service endpoint.
    PodmanContainerHost,
    /// The rootful Podman service socket was selected.
    PodmanRootfulSocket,
    /// The rootless Podman service socket was selected.
    PodmanRootlessSocket,
    /// `CONTAINER_HOST` supplied a nerdctl Docker-compatible endpoint.
    NerdctlContainerHost,
    /// The rootful nerdctl Docker-compatible socket was selected.
    NerdctlRootfulSocket,
    /// The rootless nerdctl Docker-compatible socket was selected.
    NerdctlRootlessSocket,
}

/// A resolved Docker endpoint and its provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEndpoint {
    /// Typed endpoint selected for the client.
    pub endpoint: Endpoint,
    /// Source that selected the endpoint.
    pub source: EndpointSource,
    /// Engine profile the endpoint was resolved for.
    pub profile: EngineProfile,
    /// Engine API version selected for the client.
    pub client_version: ApiVersion,
}

/// Errors returned while resolving Docker configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// The Docker configuration directory could not be determined.
    MissingConfigDirectory,
    /// A configuration or metadata file could not be read.
    Io(String),
    /// Docker configuration JSON was malformed.
    InvalidJson(String),
    /// A selected Docker context did not exist.
    ContextNotFound(String),
    /// A context did not contain a Docker endpoint.
    MissingContextEndpoint(String),
    /// A context requested disabled TLS verification.
    TlsVerificationDisabled(String),
    /// A context endpoint was invalid.
    InvalidEndpoint {
        /// Context name, when the endpoint came from a context.
        context: Option<String>,
        /// Endpoint parsing error.
        source: EndpointError,
    },
    /// `DOCKER_API_VERSION` was not a supported Engine API version.
    InvalidApiVersion(String),
    /// A context HTTPS endpoint did not contain TLS material.
    MissingTlsMaterial(String),
    /// A context name is empty, reserved, or unsafe for metadata storage.
    InvalidContextName(String),
    /// Context creation would replace existing metadata.
    ContextAlreadyExists(String),
    /// Context metadata is malformed or internally inconsistent.
    InvalidMetadata(String),
    /// A configuration or source path is a link or has the wrong file type.
    UnsafeConfigurationPath(String),
    /// The engine profile name was not a supported engine.
    InvalidEngineProfile(String),
    /// A Docker-only capability was requested under another engine profile.
    UnsupportedCapability(UnsupportedCapability),
    /// No Podman service socket was found at any documented location.
    PodmanSocketNotFound(Vec<PathBuf>),
    /// No nerdctl Docker-compatible socket was found at any documented location.
    NerdctlSocketNotFound(Vec<PathBuf>),
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingConfigDirectory => {
                write!(formatter, "Docker configuration directory is unavailable")
            }
            Self::Io(message) => write!(formatter, "Docker configuration I/O failed: {message}"),
            Self::InvalidJson(message) => {
                write!(formatter, "Docker configuration JSON is invalid: {message}")
            }
            Self::ContextNotFound(name) => {
                write!(formatter, "Docker context does not exist: {name}")
            }
            Self::MissingContextEndpoint(name) => {
                write!(formatter, "Docker context has no Docker endpoint: {name}")
            }
            Self::TlsVerificationDisabled(name) => write!(
                formatter,
                "Docker context disables TLS verification and is rejected: {name}"
            ),
            Self::InvalidEndpoint { context, source } => {
                if let Some(context) = context {
                    write!(
                        formatter,
                        "Docker context {context} has invalid endpoint: {source}"
                    )
                } else {
                    write!(formatter, "Docker endpoint is invalid: {source}")
                }
            }
            Self::InvalidApiVersion(value) => {
                write!(
                    formatter,
                    "DOCKER_API_VERSION is invalid: {value}; expected v{}.x no higher than {}",
                    crate::API_VERSION.major,
                    crate::api_version_ceiling()
                )
            }
            Self::MissingTlsMaterial(name) => {
                write!(formatter, "Docker context has no TLS material: {name}")
            }
            Self::InvalidContextName(name) => {
                write!(formatter, "Docker context name is invalid: {name}")
            }
            Self::ContextAlreadyExists(name) => {
                write!(formatter, "Docker context already exists: {name}")
            }
            Self::InvalidMetadata(message) => {
                write!(formatter, "Docker context metadata is invalid: {message}")
            }
            Self::UnsafeConfigurationPath(path) => {
                write!(formatter, "Docker context path is unsafe: {path}")
            }
            Self::InvalidEngineProfile(message) => {
                write!(formatter, "Engine profile is invalid: {message}")
            }
            Self::UnsupportedCapability(unsupported) => write!(formatter, "{unsupported}"),
            Self::PodmanSocketNotFound(candidates) => {
                write!(
                    formatter,
                    "no Podman service socket was found; set {CONTAINER_HOST_VARIABLE} or \
                     DOCKER_HOST, pass --host, or start the podman service"
                )?;
                write_probed(formatter, candidates)?;
                Ok(())
            }
            Self::NerdctlSocketNotFound(candidates) => {
                write!(
                    formatter,
                    "no nerdctl Docker-compatible socket was found; set {CONTAINER_HOST_VARIABLE} \
                     or DOCKER_HOST, pass --host, or start the nerdctl-compatible API"
                )?;
                write_probed(formatter, candidates)?;
                Ok(())
            }
        }
    }
}

/// Appends the probed socket locations to a not-found diagnostic.
fn write_probed(
    formatter: &mut std::fmt::Formatter<'_>,
    candidates: &[PathBuf],
) -> std::fmt::Result {
    for candidate in candidates {
        write!(formatter, "\n  probed {}", candidate.display())?;
    }
    Ok(())
}

impl std::error::Error for ContextError {}

/// Existence seam for platform socket discovery.
///
/// The default probes the real filesystem. Tests and embedders that cannot
/// create `/run` paths declare the paths that exist instead, so endpoint
/// selection order is testable without a daemon, a container runtime, or
/// process-global state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PathProbe {
    /// Probe the real filesystem.
    #[default]
    Filesystem,
    /// Treat an explicit set of paths as existing.
    Declared(BTreeSet<PathBuf>),
}

impl PathProbe {
    /// Creates a probe that treats the given paths as existing.
    #[must_use]
    pub fn declared<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self::Declared(paths.into_iter().map(Into::into).collect())
    }

    /// Returns whether a path is considered to exist.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        match self {
            Self::Filesystem => path.exists(),
            Self::Declared(paths) => paths.contains(path),
        }
    }
}

/// Resolves Docker contexts without changing process-global state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextResolver {
    config_directory: PathBuf,
    environment: BTreeMap<String, String>,
    probe: PathProbe,
}

impl ContextResolver {
    /// Creates a resolver with an explicit configuration directory and
    /// environment map that probes the real filesystem.
    #[must_use]
    pub fn new(
        config_directory: impl Into<PathBuf>,
        environment: BTreeMap<String, String>,
    ) -> Self {
        Self::new_with_probe(config_directory, environment, PathProbe::default())
    }

    /// Creates a resolver with an explicit configuration directory,
    /// environment map, and socket-existence seam.
    #[must_use]
    pub fn new_with_probe(
        config_directory: impl Into<PathBuf>,
        environment: BTreeMap<String, String>,
        probe: PathProbe,
    ) -> Self {
        Self {
            config_directory: config_directory.into(),
            environment,
            probe,
        }
    }

    /// Returns the Docker configuration directory used by this resolver.
    #[must_use]
    pub fn config_directory(&self) -> &Path {
        &self.config_directory
    }

    /// Creates a resolver from the current process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when neither `DOCKER_CONFIG` nor a home directory is
    /// available.
    pub fn from_environment() -> Result<Self, ContextError> {
        let environment = [
            "DOCKER_API_VERSION",
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "HOME",
            crate::engine::ENGINE_ENVIRONMENT_VARIABLE,
            CONTAINER_HOST_VARIABLE,
            "XDG_RUNTIME_DIR",
            "UID",
        ]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect();
        let config_directory = std::env::var_os("DOCKER_CONFIG")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(|home| PathBuf::from(home).join(".docker"))
            })
            .ok_or(ContextError::MissingConfigDirectory)?;
        Ok(Self::new(config_directory, environment))
    }

    /// Resolves the configured endpoint for the environment-selected engine
    /// profile.
    ///
    /// The profile comes from `NDOCKER_ENGINE`; see [`Self::profile`].
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid engine profile, an invalid endpoint, or
    /// missing or malformed Docker context metadata.
    pub fn resolve(&self) -> Result<ResolvedEndpoint, ContextError> {
        self.resolve_for(self.profile()?)
    }

    /// Returns the engine profile selected by this resolver's environment.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidEngineProfile`] when `NDOCKER_ENGINE` is
    /// not a supported engine name.
    pub fn profile(&self) -> Result<EngineProfile, ContextError> {
        EngineProfile::resolve(None, &self.environment)
            .map_err(|error| ContextError::InvalidEngineProfile(error.to_string()))
    }

    /// Resolves the configured endpoint for an explicit engine profile.
    ///
    /// The profile selects the resolution order. It is never inferred from a
    /// socket path: [`EngineKind::Docker`] keeps the Docker context and
    /// platform-default order, [`EngineKind::Podman`] follows Podman's own
    /// documented service locations, and [`EngineKind::Nerdctl`] follows the
    /// documented nerdctl Docker-compatible socket locations.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint, missing or malformed Docker
    /// context metadata, a Docker-only capability requested under a
    /// non-Docker profile, or an absent service socket.
    pub fn resolve_for(&self, profile: EngineProfile) -> Result<ResolvedEndpoint, ContextError> {
        let client_version = self.client_version()?;
        match profile.kind {
            EngineKind::Docker => self.resolve_docker(client_version, profile),
            EngineKind::Podman => self.resolve_podman(client_version, profile),
            EngineKind::Nerdctl => self.resolve_nerdctl(client_version, profile),
        }
    }

    fn resolve_docker(
        &self,
        client_version: ApiVersion,
        profile: EngineProfile,
    ) -> Result<ResolvedEndpoint, ContextError> {
        if let Some(context) = self.environment.get("DOCKER_CONTEXT")
            && context != "default"
            && !context.is_empty()
        {
            return self.resolve_context(
                context,
                EndpointSource::EnvironmentContext(context.clone()),
                client_version,
                profile,
            );
        }

        if let Some(context) = self.current_context()?
            && context != "default"
            && !context.is_empty()
        {
            return self.resolve_context(
                &context,
                EndpointSource::CurrentContext(context.clone()),
                client_version,
                profile,
            );
        }

        if let Some(host) = self.environment.get("DOCKER_HOST") {
            let endpoint =
                Endpoint::parse(host).map_err(|source| ContextError::InvalidEndpoint {
                    context: None,
                    source,
                })?;
            return Ok(ResolvedEndpoint {
                endpoint,
                source: EndpointSource::DockerHost,
                profile,
                client_version,
            });
        }

        Ok(ResolvedEndpoint {
            endpoint: self.platform_default(),
            source: EndpointSource::PlatformDefault,
            profile,
            client_version,
        })
    }

    /// Resolves a Podman service endpoint in an explicit, documented order.
    ///
    /// 1. `CONTAINER_HOST`, the variable Podman itself honors.
    /// 2. `DOCKER_HOST`, because a Docker client is pointed at a Podman
    ///    service socket that way today. It is an explicit user override and
    ///    is honored under every profile.
    /// 3. The rootful service socket, `/run/podman/podman.sock`.
    /// 4. The rootless service socket, `$XDG_RUNTIME_DIR/podman/podman.sock`
    ///    and then `/run/user/<uid>/podman/podman.sock`.
    ///
    /// When no socket exists, resolution fails with the probed locations
    /// instead of falling back to a Docker socket. A non-default
    /// `DOCKER_CONTEXT` fails instead of being ignored, and the v1.53 ceiling
    /// and `DOCKER_API_VERSION` selection still apply; the compatibility layer
    /// itself decides which version it answers.
    fn resolve_podman(
        &self,
        client_version: ApiVersion,
        profile: EngineProfile,
    ) -> Result<ResolvedEndpoint, ContextError> {
        let candidates = podman_socket_sources(&self.environment);
        let probed = probed_paths(&candidates);
        self.resolve_service_endpoint(
            client_version,
            profile,
            EndpointSource::PodmanContainerHost,
            &candidates,
        )?
        .ok_or(ContextError::PodmanSocketNotFound(probed))
    }

    /// Resolves a nerdctl Docker-compatible endpoint in an explicit,
    /// documented order.
    ///
    /// 1. `CONTAINER_HOST`. `nerdctl` itself does not read it, but the
    ///    Docker-compatible profiles share one resolution shape, and a caller
    ///    that sets it has named the engine explicitly.
    /// 2. `DOCKER_HOST`, the explicit user override honored under every
    ///    profile and the way a Docker client reaches a `nerdctl.sock`.
    /// 3. The rootful socket, `/run/nerdctl/nerdctl.sock`.
    /// 4. The rootless socket, `$XDG_RUNTIME_DIR/nerdctl/nerdctl.sock` and
    ///    then `/run/user/<uid>/nerdctl/nerdctl.sock`.
    ///
    /// As with Podman, an absent socket fails with the probed locations and
    /// never falls back to a Docker socket, and a non-default `DOCKER_CONTEXT`
    /// fails instead of being ignored.
    fn resolve_nerdctl(
        &self,
        client_version: ApiVersion,
        profile: EngineProfile,
    ) -> Result<ResolvedEndpoint, ContextError> {
        let candidates = nerdctl_socket_sources(&self.environment);
        let probed = probed_paths(&candidates);
        self.resolve_service_endpoint(
            client_version,
            profile,
            EndpointSource::NerdctlContainerHost,
            &candidates,
        )?
        .ok_or(ContextError::NerdctlSocketNotFound(probed))
    }

    /// Resolves the ordered endpoint for a Docker-compatible service engine.
    ///
    /// The order is shared by the Podman and nerdctl profiles so the two
    /// cannot drift: an explicit `CONTAINER_HOST`, then an explicit
    /// `DOCKER_HOST`, then the first declared service socket that exists
    /// under this resolver's [`PathProbe`]. `Ok(None)` means no socket was
    /// found, which each caller reports with its own diagnostic.
    ///
    /// # Errors
    ///
    /// Returns an error when a non-default `DOCKER_CONTEXT` is rejected for the
    /// profile, or when an explicit host is not a valid endpoint.
    fn resolve_service_endpoint(
        &self,
        client_version: ApiVersion,
        profile: EngineProfile,
        container_host_source: EndpointSource,
        candidates: &[(PathBuf, EndpointSource)],
    ) -> Result<Option<ResolvedEndpoint>, ContextError> {
        if let Some(context) = self.environment.get("DOCKER_CONTEXT")
            && context != "default"
            && !context.is_empty()
            && let Some(unsupported) = profile.rejection(EngineCapability::DockerContext)
        {
            return Err(ContextError::UnsupportedCapability(unsupported));
        }

        for (variable, source) in [
            (CONTAINER_HOST_VARIABLE, container_host_source),
            ("DOCKER_HOST", EndpointSource::DockerHost),
        ] {
            let Some(host) = self
                .environment
                .get(variable)
                .map(|value| value.trim())
                .filter(|host| !host.is_empty())
            else {
                continue;
            };
            let endpoint =
                Endpoint::parse(host).map_err(|error| ContextError::InvalidEndpoint {
                    context: None,
                    source: error,
                })?;
            return Ok(Some(ResolvedEndpoint {
                endpoint,
                source,
                profile,
                client_version,
            }));
        }

        let found = candidates
            .iter()
            .find(|(path, _)| self.probe.contains(path))
            .map(|(path, source)| ResolvedEndpoint {
                endpoint: Endpoint::Unix(path.clone()),
                source: source.clone(),
                profile,
                client_version,
            });
        Ok(found)
    }

    /// Returns the explicitly selected Engine API version.
    ///
    /// The default is [`crate::API_VERSION`]. When `DOCKER_API_VERSION` is
    /// present, it must be a v1 version no higher than the facade's v1.53
    /// ceiling. This method does not read or mutate process-global state.
    ///
    /// # Errors
    ///
    /// Returns an error when `DOCKER_API_VERSION` is malformed, is not a v1
    /// version, or exceeds v1.53.
    pub fn client_version(&self) -> Result<ApiVersion, ContextError> {
        let Some(value) = self.environment.get("DOCKER_API_VERSION") else {
            return Ok(crate::API_VERSION);
        };
        parse_api_version(value)
    }

    fn current_context(&self) -> Result<Option<String>, ContextError> {
        let path = self.config_directory.join("config.json");
        if !path.exists() {
            return Ok(None);
        }
        let document = read_json(&path)?;
        Ok(document
            .get("currentContext")
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    fn resolve_context(
        &self,
        name: &str,
        source: EndpointSource,
        client_version: ApiVersion,
        profile: EngineProfile,
    ) -> Result<ResolvedEndpoint, ContextError> {
        let context_hash = context_hash(name);
        let metadata_path = self
            .config_directory
            .join("contexts")
            .join("meta")
            .join(&context_hash)
            .join("meta.json");
        if !metadata_path.exists() {
            return Err(ContextError::ContextNotFound(name.to_owned()));
        }

        let document = read_json(&metadata_path)?;
        let docker = document
            .get("Endpoints")
            .and_then(|endpoints| endpoints.get("docker"))
            .ok_or_else(|| ContextError::MissingContextEndpoint(name.to_owned()))?;
        if docker
            .get("SkipTLSVerify")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(ContextError::TlsVerificationDisabled(name.to_owned()));
        }

        let address = docker
            .get("Host")
            .and_then(Value::as_str)
            .ok_or_else(|| ContextError::MissingContextEndpoint(name.to_owned()))?;
        let mut endpoint =
            Endpoint::parse(address).map_err(|error| ContextError::InvalidEndpoint {
                context: Some(name.to_owned()),
                source: error,
            })?;

        let has_tls_material = document.get("TLSMaterial").is_some();
        if has_tls_material {
            let material = self
                .context_tls_material(&document, name, &context_hash)?
                .ok_or_else(|| ContextError::MissingTlsMaterial(name.to_owned()))?;
            endpoint = match endpoint {
                Endpoint::Http(address) | Endpoint::Https { address, .. } => Endpoint::Https {
                    address,
                    material: Some(material),
                },
                other => other,
            };
        } else if matches!(&endpoint, Endpoint::Https { .. }) {
            return Err(ContextError::MissingTlsMaterial(name.to_owned()));
        }

        Ok(ResolvedEndpoint {
            endpoint,
            source,
            profile,
            client_version,
        })
    }

    fn context_tls_material(
        &self,
        document: &Value,
        name: &str,
        context_hash: &str,
    ) -> Result<Option<TlsMaterial>, ContextError> {
        let Some(material) = document
            .get("TLSMaterial")
            .and_then(|value| value.get("docker"))
            .and_then(Value::as_array)
            .and_then(|materials| materials.first())
        else {
            return Err(ContextError::MissingTlsMaterial(name.to_owned()));
        };

        let tls_directory = self
            .config_directory
            .join("contexts")
            .join("tls")
            .join(context_hash)
            .join("docker");
        let mut paths: [Option<PathBuf>; 3] = [None, None, None];
        for (index, key) in ["CA", "Cert", "Key"].into_iter().enumerate() {
            let value = material
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| ContextError::MissingTlsMaterial(name.to_owned()))?;
            paths[index] = Some(resolve_material_path(&tls_directory, value));
        }

        Ok(Some(TlsMaterial {
            ca_path: paths[0]
                .clone()
                .ok_or_else(|| ContextError::MissingTlsMaterial(name.to_owned()))?,
            cert_path: paths[1]
                .clone()
                .ok_or_else(|| ContextError::MissingTlsMaterial(name.to_owned()))?,
            key_path: paths[2]
                .clone()
                .ok_or_else(|| ContextError::MissingTlsMaterial(name.to_owned()))?,
        }))
    }

    fn platform_default(&self) -> Endpoint {
        #[cfg(windows)]
        {
            Endpoint::NamedPipe(r"\\.\pipe\docker_engine".to_owned())
        }
        #[cfg(not(windows))]
        {
            // The Linux socket paths, and — on macOS — the one Docker Desktop
            // actually uses. This was `#[cfg(not(windows))]` over two Linux
            // paths, so on macOS the resolver could only ever answer
            // `/var/run/docker.sock`, which Docker Desktop does not create: its
            // `desktop-linux` context points at `~/.docker/run/docker.sock`. The
            // `HOME`-derived candidate is what makes the default endpoint real
            // there. `HOME` comes from the resolver's own environment map, not
            // from the process, so the order stays testable through `PathProbe`.
            let mut candidates: Vec<PathBuf> =
                vec![Path::new("/var/run/docker.sock").to_path_buf()];
            if let Some(home) = self.environment.get("HOME").filter(|home| !home.is_empty()) {
                candidates.push(Path::new(home).join(".docker/run/docker.sock"));
            }
            candidates.push(Path::new("/run/docker.sock").to_path_buf());
            let path = candidates
                .iter()
                .find(|path| self.probe.contains(path))
                .cloned()
                .unwrap_or_else(|| candidates[0].clone());
            Endpoint::Unix(path)
        }
    }
}

/// Returns the socket paths of a candidate list, in order.
///
/// This is the list reported when a service socket is not found.
fn probed_paths(candidates: &[(PathBuf, EndpointSource)]) -> Vec<PathBuf> {
    candidates.iter().map(|(path, _)| path.clone()).collect()
}

/// Returns the Podman service sockets probed for an environment, in order.
///
/// The order is Podman's own documented precedence: the rootful service socket
/// first, then the rootless socket under `XDG_RUNTIME_DIR`, then the
/// conventional `/run/user/<uid>` rootless location derived from `UID`. The
/// rootless entries are omitted when the environment does not identify a user
/// runtime directory.
///
/// No socket is inspected here; [`ContextResolver`] decides which candidate
/// exists through its [`PathProbe`].
#[must_use]
pub fn podman_socket_sources(
    environment: &BTreeMap<String, String>,
) -> Vec<(PathBuf, EndpointSource)> {
    let mut sources = vec![(
        PathBuf::from(PODMAN_ROOTFUL_SOCKET),
        EndpointSource::PodmanRootfulSocket,
    )];

    if let Some(runtime_directory) = environment
        .get("XDG_RUNTIME_DIR")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        sources.push((
            Path::new(runtime_directory)
                .join("podman")
                .join("podman.sock"),
            EndpointSource::PodmanRootlessSocket,
        ));
    }

    if let Some(uid) = environment
        .get("UID")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()))
    {
        sources.push((
            PathBuf::from(format!("/run/user/{uid}/podman/podman.sock")),
            EndpointSource::PodmanRootlessSocket,
        ));
    }

    sources
}

/// Returns the Podman service socket paths probed for an environment, in order.
///
/// This is the candidate list reported when no Podman service socket exists.
#[must_use]
pub fn podman_socket_candidates(environment: &BTreeMap<String, String>) -> Vec<PathBuf> {
    probed_paths(&podman_socket_sources(environment))
}

/// Returns the nerdctl Docker-compatible sockets probed for an environment, in
/// order.
///
/// The order mirrors the Podman profile exactly: the documented rootful socket
/// `/run/nerdctl/nerdctl.sock` first, then the rootless socket under
/// `XDG_RUNTIME_DIR`, then the conventional `/run/user/<uid>` rootless location
/// derived from `UID`. Rootless entries are omitted when the environment does
/// not identify a user runtime directory.
///
/// No socket is inspected here; [`ContextResolver`] decides which candidate
/// exists through its [`PathProbe`].
#[must_use]
pub fn nerdctl_socket_sources(
    environment: &BTreeMap<String, String>,
) -> Vec<(PathBuf, EndpointSource)> {
    let mut sources = vec![(
        PathBuf::from(NERDCTL_ROOTFUL_SOCKET),
        EndpointSource::NerdctlRootfulSocket,
    )];

    if let Some(runtime_directory) = environment
        .get("XDG_RUNTIME_DIR")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        sources.push((
            Path::new(runtime_directory)
                .join(NERDCTL_SOCKET_DIRECTORY)
                .join("nerdctl.sock"),
            EndpointSource::NerdctlRootlessSocket,
        ));
    }

    if let Some(uid) = environment
        .get("UID")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()))
    {
        sources.push((
            PathBuf::from(format!(
                "/run/user/{uid}/{NERDCTL_SOCKET_DIRECTORY}/nerdctl.sock"
            )),
            EndpointSource::NerdctlRootlessSocket,
        ));
    }

    sources
}

/// Returns the nerdctl Docker-compatible socket paths probed for an
/// environment, in order.
///
/// This is the candidate list reported when no nerdctl socket exists.
#[must_use]
pub fn nerdctl_socket_candidates(environment: &BTreeMap<String, String>) -> Vec<PathBuf> {
    probed_paths(&nerdctl_socket_sources(environment))
}

fn parse_api_version(value: &str) -> Result<ApiVersion, ContextError> {
    let mut parts = value.split('.');
    let major = parts.next().unwrap_or_default();
    let minor = parts.next().unwrap_or_default();
    if major.is_empty()
        || minor.is_empty()
        || !major.chars().all(|character| character.is_ascii_digit())
        || !minor.chars().all(|character| character.is_ascii_digit())
        || parts.next().is_some()
    {
        return Err(ContextError::InvalidApiVersion(value.to_owned()));
    }

    let major = major
        .parse::<usize>()
        .map_err(|_| ContextError::InvalidApiVersion(value.to_owned()))?;
    let minor = minor
        .parse::<usize>()
        .map_err(|_| ContextError::InvalidApiVersion(value.to_owned()))?;
    if major != 1 || minor > crate::API_VERSION.minor {
        return Err(ContextError::InvalidApiVersion(value.to_owned()));
    }
    Ok(ApiVersion { major, minor })
}

fn read_json(path: &Path) -> Result<Value, ContextError> {
    let bytes = fs::read(path).map_err(|error| ContextError::Io(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| ContextError::InvalidJson(error.to_string()))
}

pub(crate) fn context_hash(name: &str) -> String {
    let digest = Sha256::digest(name.as_bytes());
    format!("{digest:x}")
}

fn resolve_material_path(directory: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_owned()
    } else {
        directory.join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
    };

    use tempfile::tempdir;

    use super::{ContextError, ContextResolver, EndpointSource};
    use crate::{ApiVersion, Endpoint, EndpointError};

    #[test]
    fn resolves_environment_context_without_environment_mutation() {
        let directory = tempdir().expect("temporary directory");
        let context_name = "production";
        let hash = super::context_hash(context_name);
        let metadata = directory.path().join("contexts/meta").join(&hash);
        fs::create_dir_all(&metadata).expect("metadata directory");
        fs::write(
            metadata.join("meta.json"),
            r#"{
                "Name": "production",
                "Endpoints": {
                    "docker": {
                        "Host": "ssh://deploy@example.com"
                    }
                }
            }"#,
        )
        .expect("metadata");

        let mut environment = BTreeMap::new();
        environment.insert("DOCKER_API_VERSION".to_owned(), "1.47".to_owned());
        environment.insert("DOCKER_CONTEXT".to_owned(), context_name.to_owned());
        let resolver = ContextResolver::new(directory.path(), environment);
        let selection = resolver.resolve().expect("context resolution");
        assert!(matches!(selection.endpoint, Endpoint::Ssh { .. }));
        assert_eq!(
            selection.source,
            EndpointSource::EnvironmentContext(context_name.to_owned())
        );
        assert_eq!(
            selection.client_version,
            ApiVersion {
                major: 1,
                minor: 47
            }
        );
    }

    #[test]
    fn uses_context_local_tls_for_tcp_endpoints() {
        let directory = tempdir().expect("temporary directory");
        let context_name = "secure";
        let hash = super::context_hash(context_name);
        let metadata = directory.path().join("contexts/meta").join(&hash);
        let tls = directory
            .path()
            .join("contexts/tls")
            .join(&hash)
            .join("docker");
        fs::create_dir_all(&metadata).expect("metadata directory");
        fs::create_dir_all(&tls).expect("TLS directory");
        for file in ["ca.pem", "cert.pem", "key.pem"] {
            fs::write(tls.join(file), file).expect("TLS fixture");
        }
        fs::write(
            metadata.join("meta.json"),
            r#"{
                "Endpoints": {
                    "docker": {
                        "Host": "tcp://docker.example:2376"
                    }
                },
                "TLSMaterial": {
                    "docker": [{
                        "CA": "ca.pem",
                        "Cert": "cert.pem",
                        "Key": "key.pem"
                    }]
                }
            }"#,
        )
        .expect("metadata");

        let mut environment = BTreeMap::new();
        environment.insert("DOCKER_CONTEXT".to_owned(), context_name.to_owned());
        let resolver = ContextResolver::new(directory.path(), environment);
        let selection = resolver.resolve().expect("context resolution");
        let Endpoint::Https {
            address,
            material: Some(material),
        } = selection.endpoint
        else {
            panic!("expected context TLS endpoint");
        };
        assert_eq!(address, "tcp://docker.example:2376");
        assert_eq!(material.ca_path, tls.join("ca.pem"));
        assert_eq!(material.cert_path, tls.join("cert.pem"));
        assert_eq!(material.key_path, tls.join("key.pem"));
    }

    #[test]
    fn uses_docker_host_before_platform_default() {
        let directory = tempdir().expect("temporary directory");
        let mut environment = BTreeMap::new();
        environment.insert("DOCKER_HOST".to_owned(), "tcp://127.0.0.1:2375".to_owned());
        let resolver = ContextResolver::new(directory.path(), environment);
        let selection = resolver.resolve().expect("host resolution");
        assert_eq!(selection.source, EndpointSource::DockerHost);
        assert_eq!(
            selection.endpoint,
            Endpoint::Http("tcp://127.0.0.1:2375".to_owned())
        );
        // With no `DOCKER_API_VERSION` the resolver hands back the crate's
        // ceiling, which is what `connect_defaults` then passes to
        // `connect_endpoint_with_version` -- and therefore to Bollard as well as
        // to the owned transport. That is worth seeing stated rather than
        // inherited from a literal: it is the one path where Bollard is
        // deliberately given 1.55, and the models it deserializes with are
        // still 1.53's.
        assert_eq!(selection.client_version, crate::API_VERSION);
    }

    #[test]
    fn selects_explicit_api_version_from_environment() {
        let directory = tempdir().expect("temporary directory");
        let mut environment = BTreeMap::new();
        environment.insert("DOCKER_API_VERSION".to_owned(), "1.47".to_owned());
        environment.insert("DOCKER_HOST".to_owned(), "tcp://127.0.0.1:2375".to_owned());
        let resolver = ContextResolver::new(directory.path(), environment);
        let selection = resolver.resolve().expect("version selection");
        assert_eq!(
            selection.client_version,
            ApiVersion {
                major: 1,
                minor: 47
            }
        );
    }

    #[test]
    fn rejects_malformed_non_v1_and_above_ceiling_api_versions() {
        let directory = tempdir().expect("temporary directory");
        // `1.54` was in this list as a must-reject and is not any more: it was
        // the ceiling when the list was written, and the ceiling has moved. The
        // entry that replaced it is `1.56`, which is one above the ceiling and
        // is the value that actually distinguishes "bounded by 1.55" from
        // "bounded by nothing". `v1.53` stays in the list for a different
        // reason: the `v` prefix is malformed regardless of the number.
        for value in ["", "1", "1.x", "2.0", "1.56", "v1.53", "v1.99"] {
            let mut environment = BTreeMap::new();
            environment.insert("DOCKER_API_VERSION".to_owned(), value.to_owned());
            environment.insert("DOCKER_HOST".to_owned(), "tcp://127.0.0.1:2375".to_owned());
            let resolver = ContextResolver::new(directory.path(), environment);
            assert!(
                matches!(resolver.resolve(), Err(ContextError::InvalidApiVersion(_))),
                "expected {value:?} to be rejected"
            );
        }
    }

    /// `DOCKER_API_VERSION` at or below the ceiling is accepted.
    ///
    /// The list above is entirely rejections, which is a shape that cannot tell
    /// a correct ceiling from an absent one: if the bound were dropped
    /// altogether, every value in that list except `1.56` would still be
    /// rejected for being malformed or non-v1, and the suite would be green.
    /// This is the half that says the bound exists *and* is 1.55.
    #[test]
    fn accepts_api_versions_at_or_below_the_ceiling() {
        let directory = tempdir().expect("temporary directory");
        for value in ["1.55", "1.54", "1.53", "1.24", "1.1"] {
            let mut environment = BTreeMap::new();
            environment.insert("DOCKER_API_VERSION".to_owned(), value.to_owned());
            environment.insert("DOCKER_HOST".to_owned(), "tcp://127.0.0.1:2375".to_owned());
            let resolver = ContextResolver::new(directory.path(), environment);
            let selection = resolver
                .resolve()
                .unwrap_or_else(|error| panic!("expected {value:?} to be accepted, got {error}"));
            let minor: usize = value
                .split_once('.')
                .expect("dotted version")
                .1
                .parse()
                .expect("numeric minor");
            assert_eq!(
                selection.client_version,
                ApiVersion { major: 1, minor },
                "the selected version should be the one the environment named"
            );
        }
    }

    /// The `DOCKER_API_VERSION` rejection names the live ceiling.
    ///
    /// Read from the rendered text, and the number pinned separately, for the
    /// same reason as the equivalent check on the facade's own error: a helper
    /// that formats the wrong number would be wrong on both sides of an
    /// expectation built from it.
    #[test]
    fn the_context_error_message_names_the_live_ceiling() {
        assert_eq!(
            crate::api_version_ceiling(),
            "v1.55",
            "the rendered ceiling must be the live number, not Bollard's 1.53"
        );
        let rendered = ContextError::InvalidApiVersion("1.99".to_owned()).to_string();
        assert_eq!(
            rendered,
            "DOCKER_API_VERSION is invalid: 1.99; expected v1.x no higher than v1.55"
        );
    }

    #[test]
    fn rejects_contexts_that_disable_tls_verification() {
        let directory = tempdir().expect("temporary directory");
        let context_name = "insecure";
        let hash = super::context_hash(context_name);
        let metadata = directory.path().join("contexts/meta").join(&hash);
        fs::create_dir_all(&metadata).expect("metadata directory");
        fs::write(
            metadata.join("meta.json"),
            r#"{
                "Endpoints": {
                    "docker": {
                        "Host": "https://example.com:2376",
                        "SkipTLSVerify": true
                    }
                }
            }"#,
        )
        .expect("metadata");

        let mut environment = BTreeMap::new();
        environment.insert("DOCKER_CONTEXT".to_owned(), context_name.to_owned());
        let resolver = ContextResolver::new(directory.path(), environment);
        assert!(matches!(
            resolver.resolve(),
            Err(ContextError::TlsVerificationDisabled(name)) if name == context_name
        ));
    }

    #[test]
    fn parses_invalid_environment_endpoint() {
        let directory = tempdir().expect("temporary directory");
        let mut environment = BTreeMap::new();
        environment.insert(
            "DOCKER_HOST".to_owned(),
            "ssh://user:password@example.com".to_owned(),
        );
        let resolver = ContextResolver::new(directory.path(), environment);
        assert!(matches!(
            resolver.resolve(),
            Err(ContextError::InvalidEndpoint {
                source: EndpointError::PasswordInSshEndpoint,
                ..
            })
        ));
    }

    fn service_environment(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn service_resolver(
        directory: &Path,
        environment: BTreeMap<String, String>,
        existing: &[&str],
    ) -> ContextResolver {
        ContextResolver::new_with_probe(
            directory,
            environment,
            crate::PathProbe::declared(existing.iter().map(Path::new)),
        )
    }

    #[test]
    fn podman_candidates_follow_documented_order() {
        let rootful = PathBuf::from(super::PODMAN_ROOTFUL_SOCKET);
        let runtime = PathBuf::from("/run/user/1000/podman/podman.sock");

        let only_rootful = service_environment(&[("UID", "1000")]);
        assert_eq!(
            super::podman_socket_candidates(&only_rootful),
            vec![rootful.clone(), runtime.clone()]
        );

        let xdg = service_environment(&[("XDG_RUNTIME_DIR", "/run/user/4242")]);
        assert_eq!(
            super::podman_socket_candidates(&xdg),
            vec![
                rootful.clone(),
                PathBuf::from("/run/user/4242/podman/podman.sock")
            ]
        );

        // A non-numeric or empty UID is not a user runtime directory.
        for value in ["", " ", "root", "1000x"] {
            let environment = service_environment(&[("UID", value)]);
            assert_eq!(
                super::podman_socket_candidates(&environment),
                vec![rootful.clone()],
                "expected UID {value:?} to be ignored"
            );
        }
        assert_eq!(
            super::podman_socket_candidates(&BTreeMap::new()),
            vec![rootful]
        );
    }

    #[test]
    fn podman_prefers_container_host_over_every_socket() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[
            ("CONTAINER_HOST", "unix:///run/user/1000/podman/podman.sock"),
            ("DOCKER_HOST", "tcp://127.0.0.1:9999"),
            ("UID", "1000"),
        ]);
        let resolver =
            service_resolver(directory.path(), environment, &["/run/podman/podman.sock"]);
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect("podman selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/1000/podman/podman.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::PodmanContainerHost);
    }

    #[test]
    fn podman_accepts_docker_host_as_an_explicit_override() {
        let directory = tempdir().expect("temporary directory");
        let environment =
            service_environment(&[("DOCKER_HOST", "tcp://127.0.0.1:9999"), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &[
                "/run/podman/podman.sock",
                "/run/user/1000/podman/podman.sock",
            ],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect("podman selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Http("tcp://127.0.0.1:9999".into())
        );
        assert_eq!(selection.source, EndpointSource::DockerHost);
    }

    #[test]
    fn podman_selects_the_rootful_socket_before_the_rootless_one() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &[
                "/run/podman/podman.sock",
                "/run/user/1000/podman/podman.sock",
            ],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect("podman selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/podman/podman.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::PodmanRootfulSocket);
    }

    #[test]
    fn podman_falls_back_to_the_rootless_socket_only() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000"), ("XDG_RUNTIME_DIR", "")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/podman/podman.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect("podman selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/1000/podman/podman.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::PodmanRootlessSocket);
    }

    #[test]
    fn podman_uses_the_xdg_runtime_directory_when_present() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("XDG_RUNTIME_DIR", "/run/user/4242")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/4242/podman/podman.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect("podman selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/4242/podman/podman.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::PodmanRootlessSocket);
    }

    #[test]
    fn podman_never_falls_back_to_a_docker_socket() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/var/run/docker.sock", "/run/docker.sock"],
        );
        let error = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman))
            .expect_err("no podman socket");
        let ContextError::PodmanSocketNotFound(candidates) = error else {
            panic!("expected a Podman socket diagnostic");
        };
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/run/podman/podman.sock"),
                PathBuf::from("/run/user/1000/podman/podman.sock")
            ]
        );
    }

    #[test]
    fn podman_profile_rejects_docker_contexts() {
        let directory = tempdir().expect("temporary directory");
        let context_name = "production";
        let hash = super::context_hash(context_name);
        let metadata = directory.path().join("contexts/meta").join(&hash);
        fs::create_dir_all(&metadata).expect("metadata directory");
        fs::write(
            metadata.join("meta.json"),
            r#"{"Endpoints":{"docker":{"Host":"tcp://docker.example:2375"}}}"#,
        )
        .expect("metadata");

        let environment = service_environment(&[("DOCKER_CONTEXT", context_name), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/podman/podman.sock"],
        );
        assert!(matches!(
            resolver.resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Podman)),
            Err(ContextError::UnsupportedCapability(
                crate::UnsupportedCapability {
                    capability: crate::EngineCapability::DockerContext,
                    ..
                }
            ))
        ));
        // The same environment still resolves through the Docker profile.
        let selection = resolver.resolve().expect("docker selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Http("tcp://docker.example:2375".into())
        );
        assert_eq!(selection.profile, crate::EngineProfile::docker());
    }

    #[test]
    fn nerdctl_candidates_follow_documented_order() {
        let rootful = PathBuf::from(super::NERDCTL_ROOTFUL_SOCKET);
        let runtime = PathBuf::from("/run/user/1000/nerdctl/nerdctl.sock");

        let only_rootful = service_environment(&[("UID", "1000")]);
        assert_eq!(
            super::nerdctl_socket_candidates(&only_rootful),
            vec![rootful.clone(), runtime.clone()]
        );

        let xdg = service_environment(&[("XDG_RUNTIME_DIR", "/run/user/4242")]);
        assert_eq!(
            super::nerdctl_socket_candidates(&xdg),
            vec![
                rootful.clone(),
                PathBuf::from("/run/user/4242/nerdctl/nerdctl.sock")
            ]
        );

        // Both rootless forms are probed when both variables are usable.
        let both = service_environment(&[("UID", "1000"), ("XDG_RUNTIME_DIR", "/run/user/4242")]);
        assert_eq!(
            super::nerdctl_socket_candidates(&both),
            vec![
                rootful.clone(),
                PathBuf::from("/run/user/4242/nerdctl/nerdctl.sock"),
                PathBuf::from("/run/user/1000/nerdctl/nerdctl.sock"),
            ]
        );

        // A non-numeric or empty UID is not a user runtime directory.
        for value in ["", " ", "root", "1000x"] {
            let environment = service_environment(&[("UID", value)]);
            assert_eq!(
                super::nerdctl_socket_candidates(&environment),
                vec![rootful.clone()],
                "expected UID {value:?} to be ignored"
            );
        }
        assert_eq!(
            super::nerdctl_socket_candidates(&BTreeMap::new()),
            vec![rootful]
        );
    }

    #[test]
    fn nerdctl_prefers_container_host_over_every_socket() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[
            (
                "CONTAINER_HOST",
                "unix:///run/user/1000/nerdctl/nerdctl.sock",
            ),
            ("DOCKER_HOST", "tcp://127.0.0.1:9999"),
            ("UID", "1000"),
        ]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/nerdctl/nerdctl.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/1000/nerdctl/nerdctl.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::NerdctlContainerHost);
        assert_eq!(
            selection.profile,
            crate::EngineProfile::explicit(crate::EngineKind::Nerdctl)
        );
    }

    #[test]
    fn nerdctl_accepts_docker_host_as_an_explicit_override() {
        let directory = tempdir().expect("temporary directory");
        let environment =
            service_environment(&[("DOCKER_HOST", "tcp://127.0.0.1:9999"), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &[
                "/run/nerdctl/nerdctl.sock",
                "/run/user/1000/nerdctl/nerdctl.sock",
            ],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Http("tcp://127.0.0.1:9999".into())
        );
        assert_eq!(selection.source, EndpointSource::DockerHost);
    }

    #[test]
    fn nerdctl_selects_the_rootful_socket_before_the_rootless_one() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &[
                "/run/nerdctl/nerdctl.sock",
                "/run/user/1000/nerdctl/nerdctl.sock",
            ],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/nerdctl/nerdctl.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::NerdctlRootfulSocket);
    }

    #[test]
    fn nerdctl_falls_back_to_the_uid_derived_rootless_socket_only() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000"), ("XDG_RUNTIME_DIR", "")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/nerdctl/nerdctl.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/1000/nerdctl/nerdctl.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::NerdctlRootlessSocket);
    }

    #[test]
    fn nerdctl_uses_the_xdg_runtime_directory_when_present() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("XDG_RUNTIME_DIR", "/run/user/4242")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/4242/nerdctl/nerdctl.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Unix("/run/user/4242/nerdctl/nerdctl.sock".into())
        );
        assert_eq!(selection.source, EndpointSource::NerdctlRootlessSocket);
    }

    #[test]
    fn nerdctl_never_falls_back_to_a_docker_socket() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/var/run/docker.sock", "/run/docker.sock"],
        );
        let error = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect_err("no nerdctl socket");
        let ContextError::NerdctlSocketNotFound(candidates) = error else {
            panic!("expected a nerdctl socket diagnostic");
        };
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/run/nerdctl/nerdctl.sock"),
                PathBuf::from("/run/user/1000/nerdctl/nerdctl.sock")
            ]
        );
        let message = ContextError::NerdctlSocketNotFound(candidates).to_string();
        assert!(
            message.contains("no nerdctl Docker-compatible socket was found"),
            "{message}"
        );
        assert!(
            message.contains("probed /run/nerdctl/nerdctl.sock"),
            "{message}"
        );
        assert!(!message.contains("docker.sock"), "{message}");
    }

    #[test]
    fn nerdctl_profile_rejects_docker_contexts() {
        let directory = tempdir().expect("temporary directory");
        let context_name = "production";
        let hash = super::context_hash(context_name);
        let metadata = directory.path().join("contexts/meta").join(&hash);
        fs::create_dir_all(&metadata).expect("metadata directory");
        fs::write(
            metadata.join("meta.json"),
            r#"{"Endpoints":{"docker":{"Host":"tcp://docker.example:2375"}}}"#,
        )
        .expect("metadata");

        let environment = service_environment(&[("DOCKER_CONTEXT", context_name), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/nerdctl/nerdctl.sock"],
        );
        assert!(matches!(
            resolver.resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl)),
            Err(ContextError::UnsupportedCapability(
                crate::UnsupportedCapability {
                    capability: crate::EngineCapability::DockerContext,
                    ..
                }
            ))
        ));
        // The same environment still resolves through the Docker profile.
        let selection = resolver.resolve().expect("docker selection");
        assert_eq!(
            selection.endpoint,
            Endpoint::Http("tcp://docker.example:2375".into())
        );
        assert_eq!(selection.profile, crate::EngineProfile::docker());
    }

    #[test]
    fn nerdctl_keeps_the_api_version_ceiling_and_selection() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[("DOCKER_API_VERSION", "1.47"), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/nerdctl/nerdctl.sock"],
        );
        let selection = resolver
            .resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl))
            .expect("nerdctl selection");
        assert_eq!(
            selection.client_version,
            ApiVersion {
                major: 1,
                minor: 47
            }
        );

        // One above the ceiling. This was `1.54` when the ceiling was 1.53, and
        // a value at the old ceiling would not reject here, so it moved with
        // the ceiling rather than staying behind as a stale regression marker.
        let environment = service_environment(&[("DOCKER_API_VERSION", "1.56"), ("UID", "1000")]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/nerdctl/nerdctl.sock"],
        );
        assert!(matches!(
            resolver.resolve_for(crate::EngineProfile::explicit(crate::EngineKind::Nerdctl)),
            Err(ContextError::InvalidApiVersion(_))
        ));
    }

    #[test]
    fn engine_profile_comes_from_the_environment_and_is_recorded() {
        let directory = tempdir().expect("temporary directory");
        let environment = service_environment(&[
            (crate::ENGINE_ENVIRONMENT_VARIABLE, "podman"),
            ("UID", "1000"),
        ]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/podman/podman.sock"],
        );
        let selection = resolver.resolve().expect("podman selection");
        assert_eq!(
            selection.profile,
            crate::EngineProfile::new(crate::EngineKind::Podman, crate::EngineSource::Environment)
        );

        let environment = service_environment(&[
            (crate::ENGINE_ENVIRONMENT_VARIABLE, "nerdctl"),
            ("UID", "1000"),
        ]);
        let resolver = service_resolver(
            directory.path(),
            environment,
            &["/run/user/1000/nerdctl/nerdctl.sock"],
        );
        let selection = resolver.resolve().expect("nerdctl selection");
        assert_eq!(
            selection.profile,
            crate::EngineProfile::new(crate::EngineKind::Nerdctl, crate::EngineSource::Environment)
        );
        assert_eq!(selection.source, EndpointSource::NerdctlRootlessSocket);

        let environment = service_environment(&[(crate::ENGINE_ENVIRONMENT_VARIABLE, "libpod")]);
        let resolver = ContextResolver::new(directory.path(), environment);
        assert!(matches!(
            resolver.profile(),
            Err(ContextError::InvalidEngineProfile(_))
        ));
    }

    #[test]
    fn platform_default_uses_the_injected_existence_seam() {
        let directory = tempdir().expect("temporary directory");
        let resolver = ContextResolver::new_with_probe(
            directory.path(),
            BTreeMap::new(),
            crate::PathProbe::declared(["/run/docker.sock"]),
        );
        let selection = resolver.resolve().expect("docker selection");
        #[cfg(not(windows))]
        {
            assert_eq!(
                selection.endpoint,
                Endpoint::Unix("/run/docker.sock".into())
            );
            assert_eq!(selection.source, EndpointSource::PlatformDefault);

            // `from_environment()` captures HOME so Docker Desktop's macOS
            // socket is visible to the same resolver used by connect_defaults.
            let home_socket = "/home/test-user/.docker/run/docker.sock";
            let mut environment = BTreeMap::new();
            environment.insert("HOME".to_owned(), "/home/test-user".to_owned());
            let resolver = ContextResolver::new_with_probe(
                directory.path(),
                environment,
                crate::PathProbe::declared([home_socket]),
            );
            let selection = resolver.resolve().expect("Docker Desktop selection");
            assert_eq!(selection.endpoint, Endpoint::Unix(home_socket.into()));
            assert_eq!(selection.source, EndpointSource::PlatformDefault);
        }
        #[cfg(windows)]
        {
            assert_eq!(
                selection.endpoint,
                Endpoint::NamedPipe(r"\\.\pipe\docker_engine".to_owned())
            );
            assert_eq!(selection.source, EndpointSource::PlatformDefault);
        }
    }
}
