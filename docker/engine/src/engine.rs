//! Explicit engine profiles for Docker-compatible Engine endpoints.
//!
//! An [`EngineKind`] is always an explicit caller selection. This module never
//! infers an engine from which socket happens to exist on the machine: Docker,
//! Podman, and nerdctl are routinely installed side by side, and silently
//! talking to the wrong engine is worse than failing with a diagnostic that
//! says which engines exist.
//!
//! The profile is a small, repository-owned value. It selects an endpoint
//! resolution order, it names Docker-only capabilities that a different
//! conformance surface does not provide, and it travels with the resolved
//! endpoint so callers can report exactly what they are talking to.

use std::collections::BTreeMap;
use std::fmt;

/// Environment variable that selects an engine profile when no explicit
/// option is supplied.
///
/// The name is historical: it predates this crate's public existence and comes
/// from an internal tool that is not part of this repository. It is kept as it is
/// because it is a **published interface** — callers set it, and renaming it would
/// silently change behaviour for anyone already doing so, which is not a change a
/// port is allowed to make quietly. Every consumer that matters selects a profile
/// through [`ENGINE_ENVIRONMENT_VARIABLE`] or an explicit option rather than by
/// hard-coding the string, so the rename is a contained change when it is made.
pub const ENGINE_ENVIRONMENT_VARIABLE: &str = "NDOCKER_ENGINE";

/// Reason reported for Podman Swarm-only command groups.
const REASON_PODMAN_SWARM: &str = "Podman's Docker-compatible API does not implement \
     Swarm services, nodes, tasks, or configs. It does implement /secrets, but \
     there is no Swarm for a secret to belong to";

/// Reason reported for Podman `stack` deployment.
const REASON_PODMAN_STACK: &str = "stack deployment requires Docker Swarm mode, \
     which Podman does not implement";

/// Reason reported for the Docker plugin manager under Podman.
const REASON_PODMAN_PLUGIN: &str = "Docker plugin manager endpoints are not implemented \
     by Podman's Docker-compatible layer";

/// Reason reported for container checkpoints under Podman.
const REASON_PODMAN_CHECKPOINT: &str = "container checkpoint endpoints are Docker-specific \
     and are not implemented by Podman's Docker-compatible layer";

/// Reason reported for Docker contexts under Podman.
const REASON_PODMAN_CONTEXT: &str = "Docker contexts are Docker CLI metadata under \
     DOCKER_CONFIG; a Podman service is selected with CONTAINER_HOST or an \
     explicit endpoint";

/// Reason reported for the Docker credential store under Podman.
const REASON_PODMAN_CREDENTIALS: &str = "Docker stores registry credentials in \
     config.json while Podman uses auth.json, so this crate will not write Docker \
     credentials for a Podman profile";

/// Reason reported for nerdctl Swarm-only command groups.
///
/// Grounded in nerdctl's own `docs/command-reference.md`, "Unimplemented Docker
/// commands": "Swarm commands are unimplemented and will not be implemented:
/// `docker swarm|node|service|config|secret|stack *`".
const REASON_NERDCTL_SWARM: &str = "nerdctl documents Swarm commands as unimplemented \
     and never to be implemented, so it has no services, nodes, tasks, configs, \
     or secrets";

/// Reason reported for nerdctl `stack` deployment.
///
/// The same nerdctl document groups `stack *` with the Swarm commands as
/// unimplemented.
const REASON_NERDCTL_CHECKPOINT: &str = "nerdctl does not implement the container \
     checkpoint endpoints, so the call cannot succeed against any reachable \
     daemon";
const REASON_NERDCTL_STACK: &str = "stack deployment requires Docker Swarm mode, \
     which nerdctl documents as unimplemented and never to be implemented";

/// Reason reported for the Docker plugin manager under nerdctl.
///
/// Grounded in the same nerdctl document: "Plugin commands are unimplemented and
/// will not be implemented: `docker plugin *`".
const REASON_NERDCTL_PLUGIN: &str = "nerdctl documents plugin commands as unimplemented \
     and never to be implemented";

/// Reason reported for Docker contexts under nerdctl.
///
/// Grounded in the same nerdctl document, which lists `docker context` under
/// "Others" as unimplemented. nerdctl addresses containerd through an explicit
/// `--address` or socket, not through Docker context metadata.
const REASON_NERDCTL_CONTEXT: &str = "nerdctl documents docker context as unimplemented; \
     a nerdctl endpoint is selected with CONTAINER_HOST, DOCKER_HOST, or an \
     explicit socket";

/// A container engine addressed through a Docker-compatible Engine API.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EngineKind {
    /// Docker Engine. The default profile.
    #[default]
    Docker,
    /// Podman's Docker-compatible API.
    Podman,
    /// nerdctl's Docker-compatible API.
    Nerdctl,
}

impl EngineKind {
    /// Every engine name accepted by [`Self::parse`].
    pub const NAMES: [&'static str; 3] = ["docker", "podman", "nerdctl"];

    /// Returns the stable engine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Nerdctl => "nerdctl",
        }
    }

    /// Parses an explicit engine name.
    ///
    /// Matching ignores surrounding whitespace and ASCII case. Any other value
    /// is rejected: a socket path is never inspected to guess an engine.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnknownEngine`] for an unrecognized name.
    pub fn parse(value: &str) -> Result<Self, EngineError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            "nerdctl" => Ok(Self::Nerdctl),
            _ => Err(EngineError::UnknownEngine(value.trim().to_owned())),
        }
    }

    /// Returns why a Docker-only capability is unavailable under this engine.
    ///
    /// `None` means the engine's own conformance surface is the reference and
    /// no repository-level rejection applies.
    ///
    /// nerdctl deliberately rejects fewer capabilities than Podman. Its
    /// documented unimplemented-command list is Swarm, `stack`, `plugin`, and
    /// `docker context`. Container checkpoints and the Docker `config.json`
    /// credential store are *not* rejected: nerdctl ships
    /// `nerdctl checkpoint create|list|remove`, and its registry authentication
    /// uses `${DOCKER_CONFIG}/config.json`, the same store this crate writes.
    #[must_use]
    pub const fn unsupported_reason(self, capability: EngineCapability) -> Option<&'static str> {
        match self {
            Self::Docker => None,
            Self::Podman => match capability {
                // Podman stores secrets outside any Swarm: `GET /secrets`
                // answers 200 with a list, `POST /secrets/create` works, and
                // `podman secret` is an ordinary subcommand. Verified against a
                // live Podman 5.8 socket.
                EngineCapability::Secret => None,
                EngineCapability::Swarm => Some(REASON_PODMAN_SWARM),
                EngineCapability::Stack => Some(REASON_PODMAN_STACK),
                EngineCapability::Plugin => Some(REASON_PODMAN_PLUGIN),
                EngineCapability::Checkpoint => Some(REASON_PODMAN_CHECKPOINT),
                EngineCapability::DockerContext => Some(REASON_PODMAN_CONTEXT),
                EngineCapability::DockerCredentialStore => Some(REASON_PODMAN_CREDENTIALS),
            },
            Self::Nerdctl => match capability {
                // nerdctl has no API daemon socket at all, so a Docker-API
                // client cannot reach any route — secrets included, for the same
                // reason as the other Swarm groups.
                EngineCapability::Swarm | EngineCapability::Secret => Some(REASON_NERDCTL_SWARM),
                EngineCapability::Stack => Some(REASON_NERDCTL_STACK),
                EngineCapability::Plugin => Some(REASON_NERDCTL_PLUGIN),
                EngineCapability::DockerContext => Some(REASON_NERDCTL_CONTEXT),
                // nerdctl serves no checkpoint route, so this is not an
                // unverified capability but an absent one. Verified: the
                // container checkpoint routes answer 404 on nerdctl, and Docker
                // itself answers 501 unless the daemon was started with
                // --checkpoint-dir, so nothing reachable makes a checkpoint call
                // succeed.
                EngineCapability::Checkpoint => Some(REASON_NERDCTL_CHECKPOINT),
                EngineCapability::DockerCredentialStore => None,
            },
        }
    }

    /// Returns whether a Docker-only capability exists under this engine.
    #[must_use]
    pub const fn supports(self, capability: EngineCapability) -> bool {
        self.unsupported_reason(capability).is_none()
    }
}

impl fmt::Display for EngineKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A Docker-owned capability that a different conformance surface may not
/// provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineCapability {
    /// Swarm services, nodes, tasks, and configs.
    Swarm,
    /// Swarm secrets, which Podman implements independently of Swarm.
    ///
    /// This is separate from [`Self::Swarm`] because the two engines differ:
    /// Podman has no Swarm, and yet it does serve `GET /secrets` and
    /// `POST /secrets/create` and ships `podman secret` as a real subcommand.
    /// Folding secrets in with the Swarm groups refused a command that works, and
    /// gave the refusal a reason that was not true.
    Secret,
    /// `stack` deployment and rollback.
    Stack,
    /// The Docker plugin manager.
    Plugin,
    /// Docker container checkpoint create/list/remove.
    Checkpoint,
    /// Docker CLI context metadata under `DOCKER_CONFIG`.
    DockerContext,
    /// The Docker `config.json` registry credential store.
    DockerCredentialStore,
}

impl EngineCapability {
    /// Returns the stable capability name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Swarm => "swarm",
            Self::Secret => "secret",
            Self::Stack => "stack",
            Self::Plugin => "plugin",
            Self::Checkpoint => "checkpoint",
            Self::DockerContext => "docker-context",
            Self::DockerCredentialStore => "docker-credential-store",
        }
    }
}

impl fmt::Display for EngineCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a resolved engine profile came from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EngineSource {
    /// An explicit command-line option.
    CommandLine,
    /// The `NDOCKER_ENGINE` environment variable.
    Environment,
    /// No explicit selection; the Docker default applies.
    #[default]
    Default,
}

impl EngineSource {
    /// Returns the stable source name used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandLine => "command_line",
            Self::Environment => "environment",
            Self::Default => "default",
        }
    }
}

impl fmt::Display for EngineSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An engine selection and its provenance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineProfile {
    /// Selected engine.
    pub kind: EngineKind,
    /// How the engine was selected.
    pub source: EngineSource,
}

impl EngineProfile {
    /// Creates a profile from an explicit kind and source.
    #[must_use]
    pub const fn new(kind: EngineKind, source: EngineSource) -> Self {
        Self { kind, source }
    }

    /// Creates a profile from an explicit command-line selection.
    #[must_use]
    pub const fn explicit(kind: EngineKind) -> Self {
        Self::new(kind, EngineSource::CommandLine)
    }

    /// Creates the default Docker profile.
    #[must_use]
    pub const fn docker() -> Self {
        Self::new(EngineKind::Docker, EngineSource::Default)
    }

    /// Resolves a profile from an explicit selection and an environment map.
    ///
    /// An explicit selection always wins. Otherwise `NDOCKER_ENGINE` is read
    /// from the supplied map; an absent, empty, or whitespace-only value leaves
    /// the Docker default in place. No process-global environment is read.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnknownEngine`] when `NDOCKER_ENGINE` is not one
    /// of [`EngineKind::NAMES`].
    pub fn resolve(
        explicit: Option<EngineKind>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, EngineError> {
        if let Some(kind) = explicit {
            return Ok(Self::explicit(kind));
        }
        match environment.get(ENGINE_ENVIRONMENT_VARIABLE) {
            Some(value) if !value.trim().is_empty() => Ok(Self::new(
                EngineKind::parse(value)?,
                EngineSource::Environment,
            )),
            _ => Ok(Self::docker()),
        }
    }

    /// Returns a rejection for a capability this engine does not provide.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Unsupported`] with a stable reason when the
    /// capability is a Docker-only surface.
    pub fn require(self, capability: EngineCapability) -> Result<(), EngineError> {
        self.rejection(capability).map_or(Ok(()), |unsupported| {
            Err(EngineError::Unsupported(unsupported))
        })
    }

    /// Returns the rejection value for a capability this engine does not
    /// provide, or `None` when the capability is available.
    #[must_use]
    pub const fn rejection(self, capability: EngineCapability) -> Option<UnsupportedCapability> {
        match self.kind.unsupported_reason(capability) {
            Some(reason) => Some(UnsupportedCapability {
                engine: self.kind,
                capability,
                reason,
            }),
            None => None,
        }
    }
}

impl fmt::Display for EngineProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.kind, self.source)
    }
}

/// A Docker-only capability that an engine profile does not provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedCapability {
    /// Engine profile that rejected the capability.
    pub engine: EngineKind,
    /// Capability that was requested.
    pub capability: EngineCapability,
    /// Why the capability is unavailable.
    pub reason: &'static str,
}

impl fmt::Display for UnsupportedCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is not available for the {} engine profile: {}",
            self.capability, self.engine, self.reason
        )
    }
}

/// Errors returned while selecting or applying an engine profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineError {
    /// An explicit engine name was not recognized.
    UnknownEngine(String),
    /// A Docker-only capability was requested under another engine profile.
    Unsupported(UnsupportedCapability),
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEngine(value) => write!(
                formatter,
                "unknown engine: {value}; use {}",
                EngineKind::NAMES.join(" or ")
            ),
            Self::Unsupported(unsupported) => write!(formatter, "{unsupported}"),
        }
    }
}

impl std::error::Error for EngineError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ENGINE_ENVIRONMENT_VARIABLE, EngineCapability, EngineError, EngineKind, EngineProfile,
        EngineSource, UnsupportedCapability,
    };

    #[test]
    fn parses_known_engines_and_rejects_everything_else() {
        assert_eq!(
            EngineKind::parse("docker").expect("docker"),
            EngineKind::Docker
        );
        assert_eq!(
            EngineKind::parse(" Podman ").expect("podman"),
            EngineKind::Podman
        );
        assert_eq!(
            EngineKind::parse(" NERDCTL ").expect("nerdctl"),
            EngineKind::Nerdctl
        );
        for value in [
            "",
            " ",
            "containerd",
            "docker-engine",
            "libpod",
            "podman.exe",
            "nerdctl-full",
            "nerdctl.sock",
        ] {
            assert_eq!(
                EngineKind::parse(value),
                Err(EngineError::UnknownEngine(value.trim().to_owned())),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn default_profile_is_docker_and_never_inferred() {
        assert_eq!(
            EngineProfile::resolve(None, &BTreeMap::new()),
            Ok(EngineProfile::docker())
        );
        let mut environment = BTreeMap::new();
        environment.insert(ENGINE_ENVIRONMENT_VARIABLE.to_owned(), "  ".to_owned());
        assert_eq!(
            EngineProfile::resolve(None, &environment),
            Ok(EngineProfile::docker())
        );
    }

    #[test]
    fn explicit_selection_wins_over_the_environment() {
        let mut environment = BTreeMap::new();
        environment.insert(ENGINE_ENVIRONMENT_VARIABLE.to_owned(), "podman".to_owned());
        assert_eq!(
            EngineProfile::resolve(Some(EngineKind::Docker), &environment),
            Ok(EngineProfile::new(
                EngineKind::Docker,
                EngineSource::CommandLine
            ))
        );
    }

    #[test]
    fn environment_selection_records_its_source() {
        let mut environment = BTreeMap::new();
        environment.insert(ENGINE_ENVIRONMENT_VARIABLE.to_owned(), "PODMAN".to_owned());
        assert_eq!(
            EngineProfile::resolve(None, &environment),
            Ok(EngineProfile::new(
                EngineKind::Podman,
                EngineSource::Environment
            ))
        );

        let mut environment = BTreeMap::new();
        environment.insert(ENGINE_ENVIRONMENT_VARIABLE.to_owned(), "Nerdctl".to_owned());
        assert_eq!(
            EngineProfile::resolve(None, &environment),
            Ok(EngineProfile::new(
                EngineKind::Nerdctl,
                EngineSource::Environment
            ))
        );
    }

    #[test]
    fn invalid_environment_value_is_an_error() {
        let mut environment = BTreeMap::new();
        environment.insert(
            ENGINE_ENVIRONMENT_VARIABLE.to_owned(),
            "containerd".to_owned(),
        );
        assert_eq!(
            EngineProfile::resolve(None, &environment),
            Err(EngineError::UnknownEngine("containerd".to_owned()))
        );
    }

    #[test]
    fn podman_rejects_docker_only_capabilities() {
        for capability in [
            EngineCapability::Swarm,
            EngineCapability::Stack,
            EngineCapability::Plugin,
            EngineCapability::Checkpoint,
            EngineCapability::DockerContext,
            EngineCapability::DockerCredentialStore,
        ] {
            assert!(
                EngineProfile::explicit(EngineKind::Docker)
                    .require(capability)
                    .is_ok(),
                "docker must allow {capability}"
            );
            let error = EngineProfile::explicit(EngineKind::Podman)
                .require(capability)
                .expect_err("podman must reject");
            let EngineError::Unsupported(unsupported) = error else {
                panic!("expected an unsupported capability for {capability}");
            };
            assert_eq!(unsupported.engine, EngineKind::Podman);
            assert_eq!(unsupported.capability, capability);
            assert!(!unsupported.reason.is_empty());
            assert!(unsupported.to_string().contains("podman"));
        }
    }

    #[test]
    fn nerdctl_rejects_only_the_capabilities_nerdctl_documents_as_unimplemented() {
        // nerdctl's own "Unimplemented Docker commands" list covers Swarm,
        // stack, plugin, and docker context.
        for capability in [
            EngineCapability::Swarm,
            EngineCapability::Stack,
            EngineCapability::Plugin,
            EngineCapability::DockerContext,
        ] {
            let error = EngineProfile::explicit(EngineKind::Nerdctl)
                .require(capability)
                .expect_err("nerdctl must reject");
            let EngineError::Unsupported(unsupported) = error else {
                panic!("expected an unsupported capability for {capability}");
            };
            assert_eq!(unsupported.engine, EngineKind::Nerdctl);
            assert_eq!(unsupported.capability, capability);
            assert!(
                unsupported.reason.contains("nerdctl"),
                "{}",
                unsupported.reason
            );
            assert!(unsupported.to_string().contains("nerdctl"));
        }

        // nerdctl's registry authentication uses ${DOCKER_CONFIG}/config.json,
        // the same store this crate writes, so that capability is allowed.
        assert!(
            EngineProfile::explicit(EngineKind::Nerdctl)
                .require(EngineCapability::DockerCredentialStore)
                .is_ok(),
            "nerdctl uses the Docker credential store"
        );
        assert!(EngineKind::Nerdctl.supports(EngineCapability::DockerCredentialStore));
    }

    /// Checkpoints are refused for nerdctl, and the reason is a route, not a
    /// guess.
    ///
    /// An earlier version allowed this because `nerdctl checkpoint
    /// create|list|remove` exist as CLI subcommands. That is not the same thing:
    /// A client calling `container checkpoint` calls the Engine's
    /// `POST /containers/{id}/checkpoints`, and the nerdctl subcommands are
    /// implemented client-side against a daemon API that nerdctl does not expose.
    /// Measured: `/run/nerdctl/nerdctl.sock` does not exist, so there is nothing
    /// for a Docker-API client to dial at all; the checkpoint routes answer 404 on
    /// both nerdctl and Podman; and Docker answers 501 unless its daemon was
    /// started with `--checkpoint-dir`. So no reachable daemon makes the call
    /// succeed, and refusing it here turns a 404 from mid-operation into a
    /// diagnostic before anything is sent.
    #[test]
    fn checkpoint_is_refused_for_nerdctl_because_no_route_exists() {
        let error = EngineProfile::explicit(EngineKind::Nerdctl)
            .require(EngineCapability::Checkpoint)
            .expect_err("nerdctl serves no checkpoint route");
        let EngineError::Unsupported(unsupported) = error else {
            panic!("expected an unsupported capability");
        };
        assert_eq!(unsupported.capability, EngineCapability::Checkpoint);
        assert!(
            unsupported.reason.contains("checkpoint"),
            "the reason must name what is missing: {}",
            unsupported.reason
        );
        assert!(!EngineKind::Nerdctl.supports(EngineCapability::Checkpoint));
    }

    /// Docker is still allowed the capability, because there the route exists.
    ///
    /// Docker answers 501 rather than 404 on a daemon started without
    /// `--checkpoint-dir`, which is a daemon configuration matter rather than a
    /// missing API. Refusing the command for a Docker user whose daemon does
    /// support checkpoints would be wrong, and a client cannot tell the two apart
    /// before sending the request.
    #[test]
    fn docker_keeps_the_checkpoint_capability_because_the_route_exists() {
        assert!(EngineKind::Docker.supports(EngineCapability::Checkpoint));
        assert!(
            EngineProfile::explicit(EngineKind::Docker)
                .require(EngineCapability::Checkpoint)
                .is_ok()
        );
    }

    #[test]
    fn display_forms_are_stable() {
        assert_eq!(EngineKind::Podman.to_string(), "podman");
        assert_eq!(EngineKind::Nerdctl.to_string(), "nerdctl");
        assert_eq!(EngineSource::CommandLine.to_string(), "command_line");
        assert_eq!(
            EngineProfile::explicit(EngineKind::Podman).to_string(),
            "podman (command_line)"
        );
        assert_eq!(
            EngineProfile::new(EngineKind::Nerdctl, EngineSource::Environment).to_string(),
            "nerdctl (environment)"
        );
        assert_eq!(
            EngineError::UnknownEngine("x".to_owned()).to_string(),
            "unknown engine: x; use docker or podman or nerdctl"
        );
        let unsupported = UnsupportedCapability {
            engine: EngineKind::Podman,
            capability: EngineCapability::Swarm,
            reason: "no swarm",
        };
        assert_eq!(
            unsupported.to_string(),
            "swarm is not available for the podman engine profile: no swarm"
        );
        let unsupported = UnsupportedCapability {
            engine: EngineKind::Nerdctl,
            capability: EngineCapability::Swarm,
            reason: "no swarm",
        };
        assert_eq!(
            unsupported.to_string(),
            "swarm is not available for the nerdctl engine profile: no swarm"
        );
    }
}
