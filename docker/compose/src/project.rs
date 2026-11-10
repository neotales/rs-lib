#![allow(
    clippy::if_same_then_else,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

//! Normalized, daemon-free Compose project model used by planning and CLI
//! integration.
//!
//! The original bounded document model intentionally remains small and
//! stable.  This module adds the small, typed subset needed to describe local
//! lifecycle intent without pretending to implement the whole Compose
//! specification.  Every value is resolved from caller-owned interpolation
//! values; this module never reads a process environment or an implicit dotenv
//! file.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::{
    ComposeError, ComposeValidationMode, EnvFilePolicy, InterpolationPolicy, InterpolationValues,
    MergePolicy, interpolate,
};

/// Maximum source size accepted by the normalized project loader.
pub const MAX_COMPOSE_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// The protocol used by a published service port.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComposePortProtocol {
    /// TCP ports.
    #[default]
    Tcp,
    /// UDP ports.
    Udp,
    /// SCTP ports.
    Sctp,
}

impl ComposePortProtocol {
    /// Returns the Engine protocol spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        }
    }
}

/// A normalized service port declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposePort {
    /// Container-side port.
    pub target: u16,
    /// Optional host-published port.
    pub published: Option<u16>,
    /// Port protocol.
    pub protocol: ComposePortProtocol,
    /// Optional host address for a published port.
    pub host_ip: Option<String>,
    /// Whether the published port goes through the ingress network or straight
    /// to the host.
    ///
    /// Not cosmetic: `host` skips the routing mesh, so a port published that way
    /// is not reachable through a Swarm overlay. A renderer that hardcoded
    /// `ingress` would place the port somewhere the document did not ask for. The
    /// default is `ingress` because that is Compose's default and what Docker
    /// prints for a short-form `8080:80`.
    #[serde(default)]
    pub mode: ComposePortMode,
}

/// Whether a published port goes through the ingress network or straight to the
/// host.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposePortMode {
    /// Published on the host directly, skipping the routing mesh.
    Host,
    /// Published through the ingress network. Compose's default.
    #[default]
    Ingress,
}

/// The kind of a normalized service mount.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComposeMountKind {
    /// A host bind mount. The loader records the path but never reads it.
    Bind,
    /// A named or anonymous volume mount.
    Volume,
    /// A tmpfs mount.
    Tmpfs,
}

impl ComposeMountKind {
    /// Returns the stable lower-case spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Volume => "volume",
            Self::Tmpfs => "tmpfs",
        }
    }
}

/// A normalized service mount.
///
/// The last three members exist because Docker renders a mount from the spelling
/// the document used, not only from what the mount means. Measured on 29.8, the
/// same `bind` mount renders three different ways:
///
/// ```text
/// $ docker compose config   # over the three spellings below, in order
///       - type: bind
///         source: /p
///         target: /d1          # the long form with no `bind:` key: no sub-map
///       - type: bind
///         source: /p
///         target: /d2
///         bind: {}             # the long form that wrote an empty sub-map
///       - type: bind
///         source: /p
///         target: /d3
///         bind: {}             # the short form, which synthesizes one
/// ```
///
/// The first and the third differ only in the spelling, so a model that keeps
/// only the kind, source, target, and read-only flag cannot tell them apart and
/// has to pick one rendering for both.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeMount {
    /// Mount kind.
    pub kind: ComposeMountKind,
    /// Source path or volume name, when supplied.
    pub source: Option<String>,
    /// Container target path.
    pub target: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
    /// The kind's sub-mapping, exactly as the document wrote it.
    ///
    /// `None` means the document wrote no sub-mapping. The short
    /// `source:target` spelling has none to write and still gets one, so this is
    /// `Some` of an empty sub-mapping for it — see [`Self::short_form`], which is
    /// what tells the two apart again for the v3 rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtree: Option<ComposeMountSubtree>,
    /// Whether the document used the short `source:target[:options]` spelling.
    ///
    /// This is the one distinction an `Option` cannot carry: a long form that
    /// wrote no sub-mapping and a short form that synthesized one both mean
    /// "nothing was written", and only the spelling says which one Compose will
    /// print.
    #[serde(default)]
    pub short_form: bool,
}

/// The sub-mapping that matches a mount's kind.
///
/// One enum rather than a struct with a member per kind, so a `nocopy` can never
/// be printed under `bind` and the renderer does not have to re-check the kind it
/// was handed. A sub-mapping whose key does not match the mount's `type` is not
/// representable and is dropped, which is what Compose's own model does with it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComposeMountSubtree {
    /// The `bind:` sub-mapping.
    Bind(ComposeBindOptions),
    /// The `volume:` sub-mapping.
    Volume(ComposeVolumeOptions),
    /// The `tmpfs:` sub-mapping.
    Tmpfs(ComposeTmpfsOptions),
}

impl ComposeMountSubtree {
    /// The Compose key this sub-mapping is written under.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::Volume(_) => "volume",
            Self::Tmpfs(_) => "tmpfs",
        }
    }
}

/// The `bind:` sub-mapping of a `type: bind` mount.
///
/// `create_host_path` is parsed and not carried: measured on 29.8, a document
/// that sets it prints no such key, because Compose resolves the directory at
/// deploy time rather than describing it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBindOptions {
    /// Mount propagation, such as `rprivate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation: Option<String>,
    /// The `z` or `Z` relabeling mount option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux: Option<String>,
}

/// The `volume:` sub-mapping of a `type: volume` mount.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeVolumeOptions {
    /// Whether the volume's existing contents are copied into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nocopy: Option<bool>,
    /// Path inside the volume to mount instead of its root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
}

/// The `tmpfs:` sub-mapping of a `type: tmpfs` mount.
///
/// `size` is a resolved byte count rather than a size string: measured on 29.8,
/// `size: 10m` prints as `size: "10485760"`, so a rendered document that kept the
/// suffix would print something the document did not write.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeTmpfsOptions {
    /// Size of the tmpfs, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// Permission bits of the tmpfs root, as a number.
    ///
    /// A number and not a mode string: measured on 29.8, `mode: 0444` prints as
    /// `mode: 292` and the quoted spelling is refused outright.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<i64>,
}

/// A service dependency and its readiness condition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeDependency {
    /// Referenced service name.
    pub service: String,
    /// Compose readiness condition.
    pub condition: String,
    /// Whether the dependency is required.
    pub required: bool,
}

/// A service's attachment to a project network.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeServiceNetwork {
    /// Network resource key.
    pub name: String,
    /// Optional DNS aliases.
    pub aliases: Vec<String>,
}

/// A normalized top-level `configs` declaration.
///
/// Only the members the bounded model can honor are retained: the Engine
/// resource `name`, whether the object is managed outside the project, the
/// explicitly declared `file` a Swarm deploy may read, and resource labels.
/// The file is never opened by this crate; reading it is the caller's
/// decision, so a document can be loaded, rendered, and digested with no host
/// access at all.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeProjectConfig {
    /// Engine config name.
    pub name: String,
    /// Whether the config is managed outside this project.
    #[serde(default)]
    pub external: bool,
    /// Explicitly declared backing file, relative to the project directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Environment variable whose value becomes the config's contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Config labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// A normalized top-level `secrets` declaration.
///
/// The declared *sources* are recorded and no secret material is ever retained in
/// the model. Reading a `file:` is the caller's job — it is the only layer that
/// knows the project directory and the host-path policy — and the value of an
/// `environment:` source is read at the moment it is written into a container, so
/// nothing sensitive is held here or in a rendered plan.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeProjectSecret {
    /// Engine secret name.
    pub name: String,
    /// Whether the secret is managed outside this project.
    #[serde(default)]
    pub external: bool,
    /// Explicitly declared backing file, relative to the project directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Environment variable whose value becomes the secret's contents.
    ///
    /// This is how a secret gets a value that was never a file, and Docker
    /// supports it: `environment: DB_PASSWORD` puts the variable's bytes at
    /// `/run/secrets/<target>`. Refusing the field, as this crate did, made an
    /// ordinary compose file unusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Secret labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// A service's reference to a top-level `configs` entry.
///
/// `target` is what the document *wrote*, not what it means, and the two are not
/// the same: measured on 29.8, `docker compose config` and `docker stack config`
/// both print `- source: c1` and nothing else for the short form, and print the
/// target verbatim for the long form. Defaulting the member to the referenced key,
/// as this did, makes the two indistinguishable and forces the long form to print
/// a key the document never wrote. `None` is the short form; the in-container name
/// a caller needs is `target.as_deref().unwrap_or(&source)`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeServiceConfig {
    /// Referenced top-level config key.
    pub source: String,
    /// In-container file name, when the document wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// A service's reference to a top-level `secrets` entry.
///
/// `target` is `None` for the short form for the same reason as
/// [`ComposeServiceConfig`], and the two render differently *from each other*:
/// measured on 29.8, `docker compose config` prints
/// `- {source: s1, target: /run/secrets/s1}` for a short-form reference, because
/// Compose's own default location has to appear somewhere, while
/// `docker stack config` prints `- source: s1` and stops. The default therefore
/// belongs to the renderer that prints it, and the model keeps the written form.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeServiceSecret {
    /// Referenced top-level secret key.
    pub source: String,
    /// In-container file name, when the document wrote one.
    ///
    /// A name without a leading `/` is a file under `/run/secrets/`; see
    /// [`ComposeServiceSecret`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// A `build` field that only a BuildKit-backed builder can honor.
///
/// The fields are parsed so that a caller diagnoses them by name instead of
/// silently ignoring a declaration that would otherwise change the result of a
/// build.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposeBuildKitField {
    /// `build.secrets`.
    Secrets,
    /// `build.ssh`.
    Ssh,
    /// `build.cache_to`.
    CacheTo,
    /// `build.outputs`.
    Outputs,
    /// `build.additional_contexts`.
    AdditionalContexts,
    /// `build.frontend`.
    Frontend,
    /// `build.isolation`.
    Isolation,
}

impl ComposeBuildKitField {
    /// Returns every BuildKit-only field with its Compose key.
    #[must_use]
    pub const fn all() -> [(&'static str, Self); 7] {
        [
            ("secrets", Self::Secrets),
            ("ssh", Self::Ssh),
            ("cache_to", Self::CacheTo),
            ("outputs", Self::Outputs),
            ("additional_contexts", Self::AdditionalContexts),
            ("frontend", Self::Frontend),
            ("isolation", Self::Isolation),
        ]
    }

    /// Returns the Compose key that selects this field.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Ssh => "ssh",
            Self::CacheTo => "cache_to",
            Self::Outputs => "outputs",
            Self::AdditionalContexts => "additional_contexts",
            Self::Frontend => "frontend",
            Self::Isolation => "isolation",
        }
    }
}

/// A bounded build declaration used to produce a plan operation.
///
/// Every field is the normalized, daemon-free declaration. The model never
/// opens the context, reads a Dockerfile, or contacts a builder.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBuild {
    /// Build context path. It is never opened by the model.
    pub context: String,
    /// Optional Dockerfile path, relative to the context.
    pub dockerfile: Option<String>,
    /// Optional target stage.
    pub target: Option<String>,
    /// Optional platform selector.
    pub platform: Option<String>,
    /// Whether cache is disabled.
    pub no_cache: bool,
    /// Whether the builder pulls a newer base image. `None` leaves the choice
    /// to the builder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull: Option<bool>,
    /// Explicit build arguments.
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
    /// Image labels applied to the built image.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Cache images the builder may reuse.
    #[serde(default)]
    pub cache_from: Vec<String>,
    /// BuildKit-only fields this slice parses but never applies.
    #[serde(default)]
    pub buildkit: Vec<ComposeBuildKitField>,
}

/// One host device made available to a service's containers.
///
/// Compose accepts the short `host:container[:permissions]` spelling and the long
/// mapping form. Measured against `docker compose config` on Docker 29.8, the
/// short form is normalized into this shape with `permissions` defaulting to
/// `rwm`, and `target` defaulting to `source` when the entry names only a host
/// path — so the three fields are always populated and never carry the
/// "was it declared?" question the model answers with `Option` elsewhere.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComposeDevice {
    /// Host path.
    pub source: String,
    /// Container path.
    pub target: String,
    /// cgroup permission set, such as `rwm`.
    pub permissions: String,
}

/// One `blkio_config` device entry, either a weight or a rate.
///
/// The five per-device lists `blkio_config` carries differ only in what the
/// number means: `weight_device` is a `uint16` weight, `device_read_bps` and
/// `device_write_bps` are bytes per second, and `device_read_iops` and
/// `device_write_iops` are operations per second. They are one struct because
/// they are one YAML shape — `{path, weight}` or `{path, rate}` — and a reader
/// of the field name already knows which is which. `value` is a resolved count:
/// bytes for the two bandwidth lists, and operations for the two `iops` lists.
/// Docker accepts a size suffix on *all four* rate lists, including the `iops`
/// ones, which was measured on 29.8 with
/// `device_read_iops: [{path: /dev/sda, rate: 12m}]` printing `rate: "12582912"`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComposeBlkioDevice {
    /// Host device path.
    pub path: String,
    /// Weight, or a resolved per-second rate.
    pub value: i64,
}

/// A normalized `blkio_config` block.
///
/// Every member is optional and an empty block is kept, because Docker renders
/// `blkio_config: {}` for a document that declares an empty one: the declaration
/// exists even when it constrains nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComposeBlkioConfig {
    /// Block-I/O weight for the whole container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// Per-device weights.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weight_device: Vec<ComposeBlkioDevice>,
    /// Per-device read bandwidth, in bytes per second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_read_bps: Vec<ComposeBlkioDevice>,
    /// Per-device read rate, in operations per second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_read_iops: Vec<ComposeBlkioDevice>,
    /// Per-device write bandwidth, in bytes per second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_write_bps: Vec<ComposeBlkioDevice>,
    /// Per-device write rate, in operations per second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_write_iops: Vec<ComposeBlkioDevice>,
}

/// A Windows credential specification, by source.
///
/// Compose accepts any subset of the three keys and Docker renders whichever were
/// declared, so all three are optional and an empty specification is kept: it is
/// the only way a document can say "ask for a credential spec" without saying
/// where it comes from.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComposeCredentialSpec {
    /// Path of a credential-specification file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Named credential-specification configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    /// Credential specification to read from the registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

/// A normalized service declaration used for local lifecycle planning.
///
/// Six fields are booleans — `tty`, `stdin_open`, `privileged`, `read_only`,
/// `init`, and `oom_kill_disable` — and clippy's default limit is three. They are
/// kept flat because each is a separate Compose declaration with its own name in
/// the document, and grouping them behind a wrapper would make every caller reach
/// through it to say something as simple as `service.tty`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeProjectService {
    /// Image used by the service.
    pub image: String,
    /// Explicit command argv. An empty vector means the service default.
    #[serde(default)]
    pub command: Vec<String>,
    /// Optional entrypoint argv.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Resolved environment values.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Published/exposed ports.
    #[serde(default)]
    pub ports: Vec<ComposePort>,
    /// Mounts declared by the service.
    #[serde(default)]
    pub volumes: Vec<ComposeMount>,
    /// Service dependencies.
    #[serde(default)]
    pub depends_on: Vec<ComposeDependency>,
    /// Project networks used by the service.
    #[serde(default)]
    pub networks: Vec<ComposeServiceNetwork>,
    /// User-defined labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Profile names that gate this service.
    ///
    /// An empty list means the service is unconditional: it is part of the
    /// project whatever profiles are active. A non-empty list means the service
    /// is only part of the project while one of the names it declares is
    /// active. An explicitly empty `profiles: []` is the unconditional case
    /// again, which is how Compose reads it.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Number of ordinary replicas.
    pub replicas: u32,
    /// Optional fixed container name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    /// Optional image pull policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
    /// Optional build declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<ComposeBuild>,
    /// Optional working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Optional user specification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Optional hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Whether a TTY is requested.
    #[serde(default)]
    pub tty: bool,
    /// Whether stdin is kept open.
    #[serde(default)]
    pub stdin_open: bool,
    /// Whether the service requests privileged mode.
    #[serde(default)]
    pub privileged: bool,
    /// Top-level `configs` entries mounted into the service.
    #[serde(default)]
    pub configs: Vec<ComposeServiceConfig>,
    /// Top-level `secrets` entries mounted into the service.
    #[serde(default)]
    pub secrets: Vec<ComposeServiceSecret>,
    /// Files whose contents seed this service's environment.
    ///
    /// Resolved against the directory of the Compose file that declared them and
    /// read from a caller-supplied map; see [`EnvFilePolicy`]. Values from these
    /// files are loaded first and the service's own `environment` overrides
    /// them, which is what makes `env_file` a way to supply a secret without
    /// putting it in the document.
    #[serde(default)]
    pub env_file: Vec<String>,
    /// Files whose contents seed this service's labels, with the same
    /// precedence and the same caller-supplied read as `env_file`.
    #[serde(default)]
    pub label_file: Vec<String>,
    /// Restart policy, normalized to the Engine's own spelling.
    ///
    /// Compose accepts both a bare word (`always`, `unless-stopped`,
    /// `on-failure:3`) and a mapping with `condition`, `max_attempts`,
    /// `window`, and `delay`. Both are normalized here so everything downstream
    /// sees one shape; the value is the Engine's `RestartPolicyName` and the
    /// retry count is separate, because that is how the Engine wants it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<ComposeRestart>,
    /// Health check, or `disable: true` to say there deliberately is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<ComposeHealthcheck>,
    /// Ports the service listens on without publishing them to the host.
    ///
    /// `expose` is documentation plus a hint to a co-located service; it does
    /// not bind a host port. It is carried because a document that declares it
    /// and gets it dropped on the floor is a document whose `config` output
    /// lies about the container.
    #[serde(default)]
    pub expose: Vec<String>,
    /// Extra `/etc/hosts` entries, in the Engine's `name=value` spelling.
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// Linux capabilities added to the container.
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// Linux capabilities removed from the container.
    #[serde(default)]
    pub cap_drop: Vec<String>,
    /// Whether the container's root filesystem is mounted read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Whether an init process is injected ahead of the service's own.
    #[serde(default)]
    pub init: bool,
    /// How long the Engine waits after a stop signal before killing the
    /// container, in nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_grace_period: Option<i64>,
    /// Signal sent to stop the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,
    /// Platform the image is pulled for, such as `linux/amd64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Logging driver and its options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<ComposeLogging>,
    /// Size of `/dev/shm`, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<i64>,
    /// DNS servers.
    #[serde(default)]
    pub dns: Vec<String>,
    /// DNS search domains.
    #[serde(default)]
    pub dns_search: Vec<String>,
    /// DNS resolver options, in the Engine's `name:value` spelling.
    #[serde(default)]
    pub dns_opt: Vec<String>,
    /// Additional group IDs or names.
    #[serde(default)]
    pub group_add: Vec<String>,
    /// Kernel parameters set inside the container.
    #[serde(default)]
    pub sysctls: BTreeMap<String, String>,
    /// Per-process resource limits, in the Engine's spelling.
    #[serde(default)]
    pub ulimits: Vec<ComposeUlimit>,
    /// Security options such as `label=disable`.
    #[serde(default)]
    pub security_opt: Vec<String>,
    /// Container technology the service is isolated with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
    /// Runtime the container runs under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// PID namespace mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    /// User namespace mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userns_mode: Option<String>,
    /// Opaque annotations, which the Engine ignores and other tools read.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// Explicit network mode, when the document asks for one instead of
    /// attaching the service to a network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
    /// tmpfs mounts keyed by container target path, with the size as written.
    #[serde(default)]
    pub tmpfs: BTreeMap<String, String>,
    /// Network Policy DNS name, which is a different field from `hostname`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,
    /// `deploy:` in the long form.
    ///
    /// Swarm and `stack deploy` read this; `compose up` reads the parts that
    /// have an ordinary container meaning. It is parsed either way so a document
    /// that is valid for one is valid for the other, and so a refusal names the
    /// field the caller has to change rather than the whole document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<ComposeDeploy>,
    /// Host devices mapped into the container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<ComposeDevice>,
    /// Memory limit, in bytes (`mem_limit`).
    ///
    /// Resolved through the one size table `shm_size` uses, so `512m` and
    /// `536870912` cannot land in two different units. Zero is Compose's "no
    /// limit" and is normalized to `None`, which is what Docker prints: measured
    /// on 29.8, `mem_limit: 0` renders no key at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_limit: Option<i64>,
    /// Soft memory limit, in bytes (`mem_reservation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_reservation: Option<i64>,
    /// Kernel swappiness, 0 through 100 (`mem_swappiness`).
    ///
    /// Kept as a plain integer even though Docker *prints* it as a quoted string
    /// (`mem_swappiness: "60"`): the daemon takes a number, and the quoted form
    /// is only how Compose spells one in its output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_swappiness: Option<i64>,
    /// Total memory-plus-swap limit, in bytes (`memswap_limit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memswap_limit: Option<i64>,
    /// Soft memory-plus-swap limit, in bytes (`memswap_reservation`).
    ///
    /// A Compose file version 1 field that Docker 29.8 refuses outright
    /// (`additional properties 'memswap_reservation' not allowed`, measured). It
    /// is modeled anyway: refusing a field a document may legitimately carry
    /// makes the loader useless for that document, and the normalized value is
    /// what a caller would need if the Engine ever grows the knob. No Engine
    /// `ContainerHostConfig` field takes it today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memswap_reservation: Option<i64>,
    /// Available CPU, in nano-CPUs (`cpus`).
    ///
    /// `cpus` is a decimal number of CPUs, but the Engine's field is a whole
    /// nano-CPU count, so the value is resolved here rather than carried as a
    /// float. Measured on 29.8: `0.5` and `"1.5"` both print as bare numbers
    /// (`cpus: 0.5`), `0.0000001234` prints as `1.234e-07` (123 nano-CPUs), and
    /// `0.0000019` prints as `1.9e-06` (1900 nano-CPUs) — which is rounding to
    /// the nearest nano-CPU rather than truncating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<i64>,
    /// Relative CPU weight, in the Engine's `cpu_shares` units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<i64>,
    /// CFS scheduler period, in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<i64>,
    /// CFS scheduler quota, in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,
    /// CPUs the container may run on, such as `0,1` (`cpuset`).
    ///
    /// Named for the Compose key, not for the Engine's `CpusetCpus`, so the model
    /// field and the document key are the same word. The value is carried
    /// verbatim: it is a CPU-list grammar the Engine owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
    /// Number of CPUs the container may use, on Windows hosts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i64>,
    /// Usable CPU percentage, on Windows hosts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<i64>,
    /// Real-time scheduler period, in microseconds.
    ///
    /// A whole number of microseconds, not a Compose duration: measured on 29.8,
    /// `cpu_rt_period: 1400us` is refused with a cast error while
    /// `cpu_rt_period: 1400` is accepted. Compose's own documentation spells it
    /// with a unit, which is a documentation bug rather than a feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_rt_period: Option<i64>,
    /// Real-time scheduler runtime, in microseconds. Whole microseconds, as with
    /// [`Self::cpu_rt_period`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_rt_runtime: Option<i64>,
    /// Maximum number of processes and threads.
    ///
    /// Zero is the daemon's own "unlimited" and is normalized to `None` because
    /// Docker prints no key for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,
    /// Whether the out-of-memory killer is disabled for the container.
    ///
    /// A plain `bool` with no `declared` check at the render site, because
    /// `false` is the daemon default and Docker prints no key for it: measured on
    /// 29.8, `oom_kill_disable: false` renders nothing while `true` renders
    /// `true`. The merge still consults the declared set so an override that says
    /// `false` clears a base that said `true`.
    #[serde(default)]
    pub oom_kill_disable: bool,
    /// Out-of-memory score adjustment, from -1000 to 1000.
    ///
    /// The range is Compose's, and Compose enforces it: measured on 29.8,
    /// `oom_score_adj: 1001` and `"-1001"` are both refused. Zero is the daemon
    /// default and is normalized to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i64>,
    /// Block-I/O tuning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blkio_config: Option<ComposeBlkioConfig>,
    /// Parent cgroup for the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,
    /// Windows credential specification source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_spec: Option<ComposeCredentialSpec>,
    /// cgroup device-access rules, in the kernel's own spelling.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_cgroup_rules: Vec<String>,
    /// Links to containers outside this project, in `name` or `name:alias` form.
    ///
    /// Carried verbatim: the value names a container on the same host that this
    /// model has no way to look up, so parsing it into a struct here would only
    /// move a string the caller has to resolve anyway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_links: Vec<String>,
    /// IPC namespace sharing mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc: Option<String>,
    /// MAC address assigned to the container's network endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// Storage-driver options for the container's writable layer, such as
    /// `size: 10G`.
    ///
    /// A mapping only, not the `key=value` sequence a string map usually takes:
    /// measured on 29.8, `storage_opt: ["size=10G"]` is refused with "must be a
    /// mapping".
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage_opt: BTreeMap<String, String>,
    /// UTS namespace sharing mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uts: Option<String>,
    /// Containers whose volumes are inherited, in the Engine's own spelling.
    ///
    /// Docker accepts three forms — a service in this project, `service:ro`, and
    /// `container:name` for one outside it — and prints each verbatim. A bare
    /// service name in this document additionally becomes a `service_started`
    /// dependency, because that is what Compose does: `docker compose config` on
    /// a service with `volumes_from: [other]` prints a `depends_on` entry for
    /// `other`, and refuses the document when `other` is not declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes_from: Vec<String>,
    /// Names of the fields this declaration actually set.
    ///
    /// Merging Compose files has to tell "the override did not mention this
    /// field" apart from "the override set it to the default". For `Option` and
    /// collection fields the normalized value already carries that
    /// distinction, but for `image`, `replicas`, `tty`, `stdin_open`,
    /// `privileged`, and `oom_kill_disable` an absent field and an explicit
    /// `false` or `1` look identical, so the override would silently erase the
    /// base value.
    ///
    /// The set records what the source declared, so the merge can leave a base
    /// value intact. It is derived from the source and never serialized, so it
    /// does not affect the rendered document or the configuration digest beyond
    /// the fields that are themselves rendered.
    #[serde(default, skip_serializing)]
    pub declared: BTreeSet<String>,
}

impl ComposeProjectService {
    /// Creates a service with Compose's default single replica.
    ///
    /// A service built this way declares `image` and nothing else, so it merges
    /// over a base service by replacing only the image.
    #[must_use]
    pub fn new(image: impl Into<String>) -> Self {
        let mut declared = BTreeSet::new();
        declared.insert("image".to_owned());
        Self {
            image: image.into(),
            command: Vec::new(),
            entrypoint: Vec::new(),
            environment: BTreeMap::new(),
            ports: Vec::new(),
            volumes: Vec::new(),
            depends_on: Vec::new(),
            networks: Vec::new(),
            labels: BTreeMap::new(),
            profiles: Vec::new(),
            replicas: 1,
            container_name: None,
            pull_policy: None,
            build: None,
            working_dir: None,
            user: None,
            hostname: None,
            tty: false,
            stdin_open: false,
            privileged: false,
            configs: Vec::new(),
            secrets: Vec::new(),
            env_file: Vec::new(),
            label_file: Vec::new(),
            restart: None,
            healthcheck: None,
            expose: Vec::new(),
            extra_hosts: Vec::new(),
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            read_only: false,
            init: false,
            stop_grace_period: None,
            stop_signal: None,
            platform: None,
            logging: None,
            shm_size: None,
            dns: Vec::new(),
            dns_search: Vec::new(),
            dns_opt: Vec::new(),
            group_add: Vec::new(),
            sysctls: BTreeMap::new(),
            ulimits: Vec::new(),
            security_opt: Vec::new(),
            isolation: None,
            runtime: None,
            pid: None,
            userns_mode: None,
            annotations: BTreeMap::new(),
            network_mode: None,
            tmpfs: BTreeMap::new(),
            domainname: None,
            deploy: None,
            devices: Vec::new(),
            mem_limit: None,
            mem_reservation: None,
            mem_swappiness: None,
            memswap_limit: None,
            memswap_reservation: None,
            cpus: None,
            cpu_shares: None,
            cpu_period: None,
            cpu_quota: None,
            cpuset: None,
            cpu_count: None,
            cpu_percent: None,
            cpu_rt_period: None,
            cpu_rt_runtime: None,
            pids_limit: None,
            oom_kill_disable: false,
            oom_score_adj: None,
            blkio_config: None,
            cgroup_parent: None,
            credential_spec: None,
            device_cgroup_rules: Vec::new(),
            external_links: Vec::new(),
            ipc: None,
            mac_address: None,
            storage_opt: BTreeMap::new(),
            uts: None,
            volumes_from: Vec::new(),
            declared,
        }
    }

    /// Returns whether this declaration set the named field.
    #[must_use]
    pub fn declared_field(&self, field: &str) -> bool {
        self.declared.contains(field)
    }

    /// Records that the source set the named field.
    pub fn mark_declared(&mut self, field: &str) {
        self.declared.insert(field.to_owned());
    }

    /// Returns whether the service declares a host bind mount.
    #[must_use]
    pub fn has_bind_mount(&self) -> bool {
        self.volumes
            .iter()
            .any(|mount| mount.kind == ComposeMountKind::Bind)
    }
}

/// A named Compose network or volume.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeProjectResource {
    /// Engine resource name override.
    pub name: String,
    /// Whether the resource is managed outside this project.
    #[serde(default)]
    pub external: bool,
    /// Optional driver name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// Explicitly declared backing file, relative to the project directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Environment variable whose value becomes the resource's contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Resource labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// A normalized restart policy.
///
/// Compose spells the policy either as a bare word or as a mapping; the Engine
/// wants a name and a separate retry count. Normalizing here means the renderer,
/// the digest, and the container create all read one shape, and a document that
/// says `restart: on-failure:3` and one that says
/// `restart: {condition: on-failure, max_attempts: 3}` cannot produce two
/// different containers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeRestart {
    /// The Engine's restart-policy name: `no`, `always`, `unless-stopped`, or
    /// `on-failure`.
    pub name: String,
    /// Maximum retries, for `on-failure`. Docker accepts the `on-failure:N`
    /// spelling and rejects a bare number in the mapping form; both land here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_retry_count: Option<i64>,
}

/// A normalized health check.
///
/// Durations stay as written rather than becoming integers, because the
/// container-create payload is the only place that converts them and a rendered
/// document should read the way its author wrote it. `disable` is kept
/// separately from an absent check so that "no health check on purpose" and "no
/// health check mentioned" do not render the same — the first one has to be
/// expressible or a user cannot turn one off.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeHealthcheck {
    /// The check as an argv. `CMD` and `CMD-SHELL` forms are kept verbatim
    /// because the Engine interprets the first element.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub test: Vec<String>,
    /// Time between checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// Time one check may take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Consecutive failures before the container is called unhealthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<i64>,
    /// Startup grace period during which a failure does not count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_period: Option<String>,
    /// Interval between checks during the startup grace period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_interval: Option<String>,
    /// Whether the check is deliberately turned off.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disable: bool,
}

/// A normalized logging configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeLogging {
    /// Logging driver name, defaulting to the daemon's own.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub driver: String,
    /// Driver options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

/// One `ulimits` entry, in the Engine's shape.
///
/// A bare integer is Docker's shorthand for "soft and hard are both this", and it
/// is common enough in hand-written documents that rejecting it would be a
/// refusal nobody would thank me for. Docker also prints it back the way it was
/// written — measured on 29.8, `nproc: 65535` renders as `nproc: 65535` and not as
/// the `{soft, hard}` mapping it means — so the shorthand is recorded rather than
/// normalized away. It cannot be an `Option` on `soft`/`hard`, because the long
/// form and the short form carry the same two numbers and only the spelling
/// differs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeUlimit {
    /// Limit name, such as `nofile`.
    pub name: String,
    /// Soft limit.
    pub soft: i64,
    /// Hard limit.
    ///
    /// [`i64::MAX`] when the document left this end open, which the Engine's
    /// `Ulimits` has no spelling for. Compose refuses a mapping that names only
    /// one end, so this only happens for a document Docker would not load.
    pub hard: i64,
    /// Whether the document wrote a bare number instead of a `{soft, hard}`.
    #[serde(default)]
    pub short_form: bool,
}

/// The parts of `deploy:` that have a meaning outside Swarm.
///
/// `replicas` is honored by `compose up`; the resource limits map onto the
/// Engine's own knobs. Everything Swarm-specific under `deploy` — `mode`,
/// `placement`, `update_config`, `rollback_config`, `endpoint_mode`,
/// `restart_policy` — is parsed by the Swarm side, not here, and a document
/// carrying only those still loads.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeDeploy {
    /// Requested replica count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
    /// Whether a failure to deploy should leave the existing containers alone.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub replace: bool,
    /// Replicated or global, and the count that goes with it.
    ///
    /// A `global` service runs one task per node and has no replica count, so
    /// treating the two as one number would either deploy the wrong number of
    /// tasks or refuse a document Docker deploys happily.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ComposeDeployMode>,
    /// Resource limits, as written.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, String>,
    /// Resource reservations, as written.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub reservations: BTreeMap<String, String>,
    /// Service labels, which Swarm applies to the service and every task.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Which nodes may run this service's tasks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<ComposePlacement>,
    /// How tasks are replaced when the service is updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_config: Option<ComposeUpdateConfig>,
    /// How tasks are replaced when an update is rolled back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_config: Option<ComposeUpdateConfig>,
    /// When and how often a failed task is restarted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<ComposeRestart>,
    /// Delay, in nanoseconds, before a task is restarted after a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_delay: Option<i64>,
    /// How a failure that outlives every retry is reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_failure_action: Option<String>,
    /// Window in which a restart policy's retries are counted, in nanoseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_window: Option<i64>,
    /// Whether the proxy routes to every task or only to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_mode: Option<String>,
}

/// Whether a Swarm service is replicated or global.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposeDeployMode {
    /// One task per eligible node.
    Global,
    /// A fixed number of tasks.
    Replicated,
}

/// Node selection for a Swarm service.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposePlacement {
    /// Constraints a node must satisfy, such as `node.role == worker`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    /// Soft preferences, applied in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<String>,
    /// Tasks this service may place on one node. Zero means no limit, which is
    /// Compose's own default and Swarm's.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_replicas_per_node: u32,
}

/// How a Swarm service's tasks are replaced.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeUpdateConfig {
    /// How many tasks are replaced at once. Zero means one at a time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// How long the daemon waits before stopping the next task, in nanoseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,
    /// What happens when a task fails to start: `pause`, `continue`, or
    /// `rollback`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_action: Option<String>,
    /// How many failures the update tolerates, zero meaning the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_failure_ratio: Option<String>,
    /// Whether old tasks are stopped before or after new ones start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
}

/// A fully normalized, daemon-free Compose project.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeProject {
    /// Project name used in Engine names and ownership labels.
    pub name: String,
    /// The Compose schema version the document declared, verbatim.
    ///
    /// Obsolete for the Compose specification, which has one schema, and kept
    /// only so `stack config` can echo it: `docker stack config` prints the
    /// version it read, or the version its own CLI speaks when the document
    /// declared none. It selects nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Services keyed by Compose service name.
    pub services: BTreeMap<String, ComposeProjectService>,
    /// Named networks keyed by Compose key.
    pub networks: BTreeMap<String, ComposeProjectResource>,
    /// Named volumes keyed by Compose key.
    pub volumes: BTreeMap<String, ComposeProjectResource>,
    /// Top-level `configs` keyed by Compose key.
    pub configs: BTreeMap<String, ComposeProjectConfig>,
    /// Top-level `secrets` keyed by Compose key.
    pub secrets: BTreeMap<String, ComposeProjectSecret>,
    /// Every profile name the document declared, sorted and deduplicated.
    ///
    /// Recorded from the merged document *before* profile selection removes
    /// anything, so a caller can still report the profiles a project defines
    /// when none of them is active. This is what `compose config --profiles`
    /// prints. It is not part of the rendered document: Compose has no
    /// top-level `profiles` key.
    #[serde(default)]
    pub profiles: BTreeSet<String>,
    /// Deterministic dependency order.
    pub dependency_order: Vec<String>,
}

impl ComposeProject {
    /// Parses one YAML or JSON Compose source into the lifecycle model.
    ///
    /// This is an alias for [`Self::parse_yaml`] useful to callers that use a
    /// format-agnostic source loader.
    ///
    /// # Examples
    ///
    /// ```
    /// use neotales_docker_compose::{ComposeProject, ComposeProjectOptions, InterpolationValues};
    ///
    /// let project = ComposeProject::parse_yaml(
    ///     "services:\n  web:\n    image: example/web:1\n",
    ///     "compose.yaml",
    ///     &InterpolationValues::new(),
    ///     ComposeProjectOptions::default(),
    /// )?;
    /// assert!(project.service("web").is_some());
    ///
    /// let rejected = ComposeProject::parse_yaml(
    ///     "not: [valid compose",
    ///     "bad.yaml",
    ///     &InterpolationValues::new(),
    ///     ComposeProjectOptions::default(),
    /// );
    /// assert!(rejected.is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a bounded validation/interpolation error without including
    /// secret-like values in diagnostics.
    pub fn parse_yaml(
        source: &str,
        path: &str,
        values: &InterpolationValues,
        options: ComposeProjectOptions,
    ) -> Result<Self, ComposeError> {
        if source.len() > MAX_COMPOSE_SOURCE_BYTES {
            return Err(compose_error(
                "compose_source_too_large",
                format!("Compose source exceeds the {MAX_COMPOSE_SOURCE_BYTES}-byte limit"),
                Some(path),
                "$",
            ));
        }
        let mut project = parse_source(source, path, values, &options)?;
        apply_profiles(&mut project, &options)?;
        if let Some(name) = options.project_name {
            project.name = name;
        }
        validate_project(&project, path)?;
        Ok(project)
    }

    /// Parses one source using the same bounded lifecycle loader.
    ///
    /// # Errors
    ///
    /// Returns the same validation and interpolation errors as
    /// [`Self::parse_yaml`].
    pub fn parse(
        source: &str,
        path: &str,
        values: &InterpolationValues,
        options: ComposeProjectOptions,
    ) -> Result<Self, ComposeError> {
        Self::parse_yaml(source, path, values, options)
    }

    /// Parses and merges explicitly supplied sources in caller order.
    ///
    /// The default merge policy rejects multiple documents. Set
    /// [`MergePolicy::LastWins`] explicitly when an invocation intends to
    /// provide an override file.
    ///
    /// # Errors
    ///
    /// Returns a validation, merge, or interpolation error.
    pub fn parse_sources<S, P>(
        sources: &[(S, P)],
        values: &InterpolationValues,
        options: ComposeProjectOptions,
    ) -> Result<Self, ComposeError>
    where
        S: AsRef<str>,
        P: AsRef<str>,
    {
        if sources.is_empty() {
            return Err(compose_error(
                "compose_empty_input",
                "at least one Compose source is required",
                None,
                "$",
            ));
        }
        if sources.len() > 1 && options.merge == MergePolicy::Reject {
            return Err(compose_error(
                "compose_merge_rejected",
                "multiple Compose sources require an explicit merge policy",
                None,
                "$",
            ));
        }

        let mut merged: Option<Self> = None;
        for (source, path) in sources {
            let source = source.as_ref();
            let path = path.as_ref();
            if source.len() > MAX_COMPOSE_SOURCE_BYTES {
                return Err(compose_error(
                    "compose_source_too_large",
                    format!("Compose source exceeds the {MAX_COMPOSE_SOURCE_BYTES}-byte limit"),
                    Some(path),
                    "$",
                ));
            }
            let mut parsed = parse_source(source, path, values, &options)?;
            resolve_env_files(&mut parsed, path, &options)?;
            merged = Some(match merged {
                None => parsed,
                Some(previous) => merge_projects(previous, parsed, &options)?,
            });
        }
        let mut project = merged.ok_or_else(|| {
            compose_error(
                "compose_empty_input",
                "at least one Compose source is required",
                None,
                "$",
            )
        })?;
        // Profile selection runs on the merged document, not on each source: an
        // override that adds `profiles` gates a service the base file left
        // unconditional, so the gate is only knowable once every file is in.
        apply_profiles(&mut project, &options)?;
        if let Some(name) = options.project_name {
            project.name = name;
        }
        project.dependency_order = dependency_order(&project.services)?;
        // The merged document has no single source file, so it is labelled as
        // such. Naming one of the inputs would send a reader to a file that
        // does not contain the offending service.
        validate_project(&project, "<merged>")?;
        Ok(project)
    }

    /// Projects the original bounded resolved document into the lifecycle
    /// model. Rich source-only fields remain empty; this constructor is
    /// useful for callers that already own an explicit normalized image and
    /// environment document.
    #[must_use]
    pub fn from_resolved(document: &crate::ResolvedComposeDocument) -> Self {
        let services = document
            .services
            .iter()
            .map(|(name, service)| {
                let mut project_service = ComposeProjectService::new(service.image.as_str());
                project_service.environment = service.environment.clone();
                (name.clone(), project_service)
            })
            .collect();
        let mut project = Self {
            // No path here: this constructor takes an already-resolved document
            // and has no file behind it, so a caller that wants a specific name
            // sets one on the document.
            name: document
                .name
                .clone()
                .unwrap_or_else(|| "default".to_owned()),
            services,
            ..Self::default()
        };
        project.dependency_order = dependency_order(&project.services).unwrap_or_default();
        project
    }

    /// Returns the deterministic ordinary container name for a replica.
    #[must_use]
    pub fn container_name(&self, service: &str, replica: u32) -> String {
        self.services
            .get(service)
            .and_then(|service| service.container_name.clone())
            .unwrap_or_else(|| format!("{}-{service}-{replica}", self.name))
    }

    /// Returns the Engine resource name for a project network or volume.
    #[must_use]
    pub fn resource_name(&self, key: &str, network: bool) -> String {
        let resource = if network {
            self.networks.get(key)
        } else {
            self.volumes.get(key)
        };
        resource
            .filter(|resource| !resource.name.is_empty() && resource.name != key)
            .map_or_else(
                || format!("{}_{key}", self.name),
                |resource| resource.name.clone(),
            )
    }

    /// Returns the Engine name of the implicit default project network.
    ///
    /// Compose attaches every service that declares no network to this
    /// network, so the name follows the same override rules as any other
    /// declared network.
    #[must_use]
    pub fn default_network_name(&self) -> String {
        self.resource_name(crate::COMPOSE_DEFAULT_NETWORK_KEY, true)
    }

    /// Returns whether any service implicitly or explicitly uses the default
    /// project network.
    #[must_use]
    pub fn uses_default_network(&self) -> bool {
        self.services.values().any(|service| {
            service
                .networks
                .iter()
                .any(|network| network.name == crate::COMPOSE_DEFAULT_NETWORK_KEY)
                || service.networks.is_empty()
        })
    }

    /// Returns a service in deterministic project order.
    #[must_use]
    pub fn service(&self, name: &str) -> Option<&ComposeProjectService> {
        self.services.get(name)
    }

    /// Selects services by name while retaining project order.
    ///
    /// # Errors
    ///
    /// Returns an error if a requested service is not declared.
    pub fn select_services(
        &self,
        selection: &BTreeSet<String>,
    ) -> Result<Vec<String>, ComposeError> {
        if selection.is_empty() {
            return Ok(self.dependency_order.clone());
        }
        for name in selection {
            if !self.services.contains_key(name) {
                return Err(compose_error(
                    "compose_unknown_service",
                    format!("Compose service '{name}' is not declared"),
                    None,
                    "$.services",
                ));
            }
        }
        Ok(self
            .dependency_order
            .iter()
            .filter(|name| selection.contains(*name))
            .cloned()
            .collect())
    }

    /// Selects services by name together with every service they require.
    ///
    /// The result keeps the deterministic dependency order, so a caller can
    /// apply a narrowed project without recomputing the graph. An empty
    /// selection means every service.
    ///
    /// # Errors
    ///
    /// Returns an error if a requested service is not declared.
    pub fn select_services_with_dependencies(
        &self,
        selection: &BTreeSet<String>,
    ) -> Result<Vec<String>, ComposeError> {
        if selection.is_empty() {
            return Ok(self.dependency_order.clone());
        }
        self.validate_selection(selection)?;
        let mut required: BTreeSet<String> = BTreeSet::new();
        let mut pending: Vec<String> = selection.iter().cloned().collect();
        while let Some(name) = pending.pop() {
            if !required.insert(name.clone()) {
                continue;
            }
            if let Some(service) = self.services.get(&name) {
                for dependency in &service.depends_on {
                    if dependency.required && !required.contains(&dependency.service) {
                        pending.push(dependency.service.clone());
                    }
                }
            }
        }
        Ok(self
            .dependency_order
            .iter()
            .filter(|name| required.contains(*name))
            .cloned()
            .collect())
    }

    /// Returns a copy that contains only the selected services and the
    /// networks and volumes those services reference.
    ///
    /// The narrowed project keeps the same name, so ownership labels, Engine
    /// names, and the configuration digest are unaffected. Unreferenced
    /// resources are dropped so an applied plan never creates a resource the
    /// selected services cannot use.
    #[must_use]
    pub fn narrow(&self, names: &BTreeSet<String>) -> Self {
        let services = self
            .services
            .iter()
            .filter(|(name, _)| names.contains(*name))
            .map(|(name, service)| (name.clone(), service.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut network_keys = BTreeSet::new();
        for service in services.values() {
            for network in &service.networks {
                network_keys.insert(network.name.clone());
            }
            if service.networks.is_empty() {
                network_keys.insert(crate::COMPOSE_DEFAULT_NETWORK_KEY.to_owned());
            }
        }
        let networks = self
            .networks
            .iter()
            .filter(|(key, _)| network_keys.contains(*key))
            .map(|(key, resource)| (key.clone(), resource.clone()))
            .collect();
        let mut volume_keys = BTreeSet::new();
        for service in services.values() {
            for mount in &service.volumes {
                if let Some(source) = &mount.source
                    && self.volumes.contains_key(source)
                {
                    volume_keys.insert(source.clone());
                }
            }
        }
        let volumes = self
            .volumes
            .iter()
            .filter(|(key, _)| volume_keys.contains(*key))
            .map(|(key, resource)| (key.clone(), resource.clone()))
            .collect();
        let mut config_keys = BTreeSet::new();
        let mut secret_keys = BTreeSet::new();
        for service in services.values() {
            for config in &service.configs {
                config_keys.insert(config.source.clone());
            }
            for secret in &service.secrets {
                secret_keys.insert(secret.source.clone());
            }
        }
        let configs = self
            .configs
            .iter()
            .filter(|(key, _)| config_keys.contains(*key))
            .map(|(key, resource)| (key.clone(), resource.clone()))
            .collect();
        let secrets = self
            .secrets
            .iter()
            .filter(|(key, _)| secret_keys.contains(*key))
            .map(|(key, resource)| (key.clone(), resource.clone()))
            .collect();
        Self {
            name: self.name.clone(),
            version: self.version.clone(),
            dependency_order: self
                .dependency_order
                .iter()
                .filter(|name| names.contains(*name))
                .cloned()
                .collect(),
            services,
            networks,
            volumes,
            configs,
            secrets,
            // The document's profile inventory describes the document, not the
            // selected services, so narrowing keeps it.
            profiles: self.profiles.clone(),
        }
    }

    fn validate_selection(&self, selection: &BTreeSet<String>) -> Result<(), ComposeError> {
        for name in selection {
            if !self.services.contains_key(name) {
                return Err(compose_error(
                    "compose_unknown_service",
                    format!("Compose service '{name}' is not declared"),
                    None,
                    "$.services",
                ));
            }
        }
        Ok(())
    }
}

/// Options for the normalized project loader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeProjectOptions {
    /// Optional caller-selected project name override.
    ///
    /// This wins over a `name:` in the document, which is what an explicit flag
    /// means. The name used when the document declares none is
    /// [`ComposeProjectOptions::default_project_name`].
    pub project_name: Option<String>,
    /// The name to use when the document declares none.
    ///
    /// Compose derives it from the project directory, and only the caller knows
    /// the working directory. See `project_name_from_path`.
    pub default_project_name: Option<String>,

    /// Explicitly selected services. Empty means all services.
    ///
    /// A non-empty selection is not filtered by profile: naming a service
    /// selects it whether or not its profile is active.
    pub services: BTreeSet<String>,
    /// Profile names the caller activated. Empty means none.
    ///
    /// A service that declares no `profiles` is unconditional. A service that
    /// declares some is part of the project only while at least one of them is
    /// here. The single name `*` activates every profile-gated service.
    pub profiles: BTreeSet<String>,
    /// Unknown-field policy.
    pub validation: ComposeValidationMode,
    /// Explicit scalar interpolation policy.
    pub interpolation: InterpolationPolicy,
    /// Explicit multi-source merge policy.
    pub merge: MergePolicy,
    /// How a service's `env_file` and `label_file` are read.
    pub env_file: EnvFilePolicy,
    /// File contents available to `env_file` and `label_file`, keyed by the
    /// path resolved against the declaring Compose file's directory.
    ///
    /// The key is one spelling on every platform: the resolved path with `/` as
    /// the separator, which is how a Compose document writes a path and how a
    /// `compose_env_file_missing` diagnostic names it. A key spelled with this
    /// host's own separator is accepted too, because it is normalized the same
    /// way before the lookup, so `C:\p\app.env` and `C:/p/app.env` are one entry
    /// rather than two. On Unix the text is used as written, because there a
    /// backslash is an ordinary character in a filename and rewriting it would
    /// merge two different files into one key.
    pub env_files: BTreeMap<String, String>,
}

impl Default for ComposeProjectOptions {
    fn default() -> Self {
        Self {
            project_name: None,
            default_project_name: None,
            services: BTreeSet::new(),
            profiles: BTreeSet::new(),
            validation: ComposeValidationMode::Strict,
            interpolation: InterpolationPolicy::default(),
            merge: MergePolicy::Reject,
            env_file: EnvFilePolicy::default(),
            env_files: BTreeMap::new(),
        }
    }
}

fn parse_source(
    source: &str,
    path: &str,
    values: &InterpolationValues,
    options: &ComposeProjectOptions,
) -> Result<ComposeProject, ComposeError> {
    let value: Value = serde_yaml::from_str(source).map_err(|error| {
        compose_error(
            "compose_parse",
            format!("could not parse Compose YAML: {error}"),
            Some(path),
            "$",
        )
    })?;
    let root = mapping(&value, path, "$")?;
    reject_duplicate(root, path, "$")?;
    let mut project = ComposeProject {
        name: String::new(),
        version: None,
        ..ComposeProject::default()
    };

    for (key, value) in root {
        let key = scalar_key(key, path, "$")?;
        match key.as_str() {
            "name" => project.name = scalar(value, path, "$.name")?,
            "version" => {
                // Compose's obsolete version field selects no schema, but
                // `stack config` echoes it because Docker's does.
                project.version = Some(scalar(value, path, "$.version")?);
            }
            "services" => project.services = parse_services(value, path, values, options)?,
            "networks" => project.networks = parse_resources(value, path, "networks")?,
            "volumes" => project.volumes = parse_resources(value, path, "volumes")?,
            "configs" => project.configs = parse_config_resources(value, path, "configs")?,
            "secrets" => project.secrets = parse_secret_resources(value, path, "secrets")?,
            // `models` is validated and then dropped, which is exactly what
            // Docker does with it: measured on 29.8, a document with a `models`
            // block prints no `models` key at all, while `models: {llm: {}}` is
            // still refused for the missing `model`. It is read here so the
            // refusal names the missing key rather than reporting a field outside
            // the model, and so this loader and Docker accept the same documents.
            "models" => {
                drop(parse_models(value, path)?);
            }
            "include" => {
                return Err(compose_error(
                    "compose_include_requires_explicit_loader",
                    "include requires the caller-supplied Compose include policy",
                    Some(path),
                    "$.include",
                ));
            }
            _ if key.starts_with("x-") => {}
            _ if options.validation == ComposeValidationMode::Loose => {}
            _ => {
                return Err(compose_error(
                    "compose_unknown_field",
                    format!("top-level field '{key}' is outside the supported Compose model"),
                    Some(path),
                    "$.{key}",
                ));
            }
        }
    }
    if project.name.is_empty() {
        // An empty `name:` is the same as no `name:`: both mean the name comes
        // from where the document lives.
        project.name = project_name_from_path(path, options.default_project_name.as_deref());
    }
    project.dependency_order = dependency_order(&project.services)?;
    Ok(project)
}

fn parse_services(
    value: &Value,
    path: &str,
    values: &InterpolationValues,
    options: &ComposeProjectOptions,
) -> Result<BTreeMap<String, ComposeProjectService>, ComposeError> {
    let services = mapping(value, path, "$.services")?;
    reject_duplicate(services, path, "$.services")?;
    let mut result = BTreeMap::new();
    // `extends` cannot be applied while a single service is being read, because
    // the base it inherits from is another service declaration. The declarations
    // are collected here and resolved once every service in the document is
    // known.
    let mut extends: Vec<(String, ComposeExtends)> = Vec::new();
    for (name, service) in services {
        let name = scalar_key(name, path, "$.services")?;
        validate_service_name(&name, path, &format!("$.services.{name}"))?;
        let service_path = format!("$.services.{name}");
        let service_map = mapping(service, path, &service_path)?;
        reject_duplicate(service_map, path, &service_path)?;
        let mut parsed = ComposeProjectService::new(String::new());
        let mut image = None;
        // Every key the source set is recorded, so a later merge can tell a
        // field the override omitted from one it set to the default.
        let mut declared = BTreeSet::new();
        for (key, value) in service_map {
            let key = scalar_key(key, path, &service_path)?;
            declared.insert(key.clone());
            match key.as_str() {
                "image" => {
                    image = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.image"),
                        values,
                        options.interpolation,
                    )?);
                }
                "command" => {
                    parsed.command = parse_argv(
                        value,
                        path,
                        &format!("{service_path}.command"),
                        values,
                        options.interpolation,
                    )?;
                }
                "entrypoint" => {
                    parsed.entrypoint = parse_argv(
                        value,
                        path,
                        &format!("{service_path}.entrypoint"),
                        values,
                        options.interpolation,
                    )?;
                }
                "environment" => {
                    parsed.environment = parse_environment(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                }
                "ports" => {
                    parsed.ports =
                        parse_ports(value, path, &service_path, values, options.interpolation)?;
                }
                "volumes" => {
                    parsed.volumes =
                        parse_mounts(value, path, &service_path, values, options.interpolation)?;
                }
                "depends_on" => {
                    parsed.depends_on = parse_dependencies(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                }
                "networks" => {
                    parsed.networks = parse_service_networks(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                }
                "env_file" => {
                    parsed.env_file = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.env_file"),
                        values,
                        options.interpolation,
                    )?;
                }
                "label_file" => {
                    parsed.label_file = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.label_file"),
                        values,
                        options.interpolation,
                    )?;
                }
                "labels" => {
                    parsed.labels = parse_string_map(
                        value,
                        path,
                        &format!("{service_path}.labels"),
                        values,
                        options.interpolation,
                    )?;
                }
                // `scale:` is Compose's older spelling of `deploy.replicas` and is
                // still what a `docker-compose.yml` in the wild uses, so both map
                // onto the one replica count.
                "scale" => {
                    parsed.replicas =
                        parse_replicas(value, path, &service_path, values, options.interpolation)?;
                    // Recorded under the model field name rather than the source
                    // key, so the merge consults one spelling.
                    declared.insert("replicas".to_owned());
                }
                // `deploy:` is read in full by `parse_deploy`, because it carries
                // more than a count: resource limits, and the Swarm-only keys that
                // have to be accepted for a stack file to load at all.
                // `tmpfs` and `expose` are both mount-ish declarations at the
                // service level, and both are handled alongside `volumes:` because
                // they end up in the same request fields. They are parsed here
                // rather than left to the shared path-list reader because Docker
                // accepts a bare string for each and the sizes need normalizing.
                "tmpfs" => {
                    parsed.tmpfs = parse_tmpfs(
                        value,
                        path,
                        &format!("{service_path}.tmpfs"),
                        values,
                        options.interpolation,
                    )?;
                }
                "deploy" => {
                    let deploy = parse_deploy(value, path, &service_path)?;
                    if let Some(count) = deploy.replicas {
                        parsed.replicas = count;
                        declared.insert("replicas".to_owned());
                    }
                    parsed.deploy = Some(deploy);
                }
                "profiles" => {
                    parsed.profiles = parse_profiles(
                        value,
                        path,
                        &format!("{service_path}.profiles"),
                        values,
                        options.interpolation,
                    )?;
                }
                "container_name" => {
                    parsed.container_name = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.container_name"),
                        values,
                        options.interpolation,
                    )?);
                }
                "pull_policy" => {
                    let policy = resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.pull_policy"),
                        values,
                        options.interpolation,
                    )?;
                    if !matches!(
                        policy.as_str(),
                        "always" | "never" | "missing" | "if_not_present" | "build" | "daily"
                    ) {
                        return Err(compose_error(
                            "compose_invalid_pull_policy",
                            "pull_policy is not a supported Compose policy",
                            Some(path),
                            &format!("{service_path}.pull_policy"),
                        ));
                    }
                    parsed.pull_policy = Some(policy);
                }
                "build" => {
                    parsed.build = Some(parse_build(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?);
                }
                "working_dir" => {
                    parsed.working_dir = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.working_dir"),
                        values,
                        options.interpolation,
                    )?);
                }
                "user" => {
                    parsed.user = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.user"),
                        values,
                        options.interpolation,
                    )?);
                }
                "hostname" => {
                    parsed.hostname = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.hostname"),
                        values,
                        options.interpolation,
                    )?);
                }
                // `domainname` is the Network Policy DNS name, which is a separate
                // request field from `hostname` — the container's own resolver
                // name — and conflating them would put a value in a field whose
                // meaning is different.
                "domainname" => {
                    parsed.domainname = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.domainname"),
                        values,
                        options.interpolation,
                    )?);
                }
                "tty" => parsed.tty = parse_bool(value, path, &service_path, "tty")?,
                "stdin_open" => {
                    parsed.stdin_open = parse_bool(value, path, &service_path, "stdin_open")?;
                }
                "configs" => {
                    parsed.configs = parse_service_configs(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                }
                "secrets" => {
                    parsed.secrets = parse_service_secrets(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                }
                "privileged" => {
                    parsed.privileged = parse_bool(value, path, &service_path, "privileged")?;
                }
                "restart" => {
                    parsed.restart = Some(parse_restart(value, path, &service_path, values)?);
                }
                "healthcheck" => {
                    parsed.healthcheck = Some(parse_healthcheck(value, path, &service_path)?);
                }
                "expose" => {
                    parsed.expose = parse_port_list(
                        value,
                        path,
                        &format!("{service_path}.expose"),
                        values,
                        options.interpolation,
                    )?;
                }
                "extra_hosts" => {
                    parsed.extra_hosts =
                        parse_extra_hosts(value, path, &format!("{service_path}.extra_hosts"))?;
                }
                "cap_add" => {
                    parsed.cap_add = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.cap_add"),
                        values,
                        options.interpolation,
                    )?;
                }
                "cap_drop" => {
                    parsed.cap_drop = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.cap_drop"),
                        values,
                        options.interpolation,
                    )?;
                }
                "read_only" => {
                    parsed.read_only = parse_bool(value, path, &service_path, "read_only")?;
                }
                "init" => {
                    parsed.init = parse_init(value, path, &service_path)?;
                }
                "stop_grace_period" => {
                    parsed.stop_grace_period = Some(parse_duration_nanos(
                        &scalar(value, path, &format!("{service_path}.stop_grace_period"))?,
                        &format!("{service_path}.stop_grace_period"),
                        path,
                    )?);
                }
                "stop_signal" => {
                    parsed.stop_signal = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.stop_signal"),
                        values,
                        options.interpolation,
                    )?);
                }
                "platform" => {
                    parsed.platform = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.platform"),
                        values,
                        options.interpolation,
                    )?);
                }
                "logging" => {
                    parsed.logging = Some(parse_logging(value, path, &service_path)?);
                }
                "shm_size" => {
                    parsed.shm_size = Some(parse_size_bytes(
                        &scalar(value, path, &format!("{service_path}.shm_size"))?,
                        &format!("{service_path}.shm_size"),
                        path,
                    )?);
                }
                "dns" => {
                    parsed.dns = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.dns"),
                        values,
                        options.interpolation,
                    )?;
                }
                "dns_search" => {
                    parsed.dns_search = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.dns_search"),
                        values,
                        options.interpolation,
                    )?;
                }
                "dns_opt" => {
                    parsed.dns_opt = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.dns_opt"),
                        values,
                        options.interpolation,
                    )?;
                }
                "group_add" => {
                    parsed.group_add = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.group_add"),
                        values,
                        options.interpolation,
                    )?;
                }
                "sysctls" => {
                    parsed.sysctls = string_map_without_interpolation(
                        value,
                        path,
                        &format!("{service_path}.sysctls"),
                    )?;
                }
                "ulimits" => {
                    parsed.ulimits =
                        parse_ulimits(value, path, &format!("{service_path}.ulimits"))?;
                }
                "security_opt" => {
                    parsed.security_opt = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.security_opt"),
                        values,
                        options.interpolation,
                    )?;
                }
                "isolation" => {
                    parsed.isolation =
                        Some(scalar(value, path, &format!("{service_path}.isolation"))?);
                }
                "runtime" => {
                    parsed.runtime = Some(scalar(value, path, &format!("{service_path}.runtime"))?);
                }
                "pid" => {
                    parsed.pid = Some(scalar(value, path, &format!("{service_path}.pid"))?);
                }
                "userns_mode" => {
                    parsed.userns_mode =
                        Some(scalar(value, path, &format!("{service_path}.userns_mode"))?);
                }
                "annotations" => {
                    parsed.annotations = string_map_without_interpolation(
                        value,
                        path,
                        &format!("{service_path}.annotations"),
                    )?;
                }
                "network_mode" => {
                    parsed.network_mode = Some(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.network_mode"),
                        values,
                        options.interpolation,
                    )?);
                }
                // The memory knobs all read through the one size table so
                // `512m` and `536870912` cannot disagree about what a limit is.
                // `mem_swappiness` is a percentage rather than a size, so it takes
                // the integer reader instead.
                "mem_limit" => {
                    parsed.mem_limit = nonzero(parse_size_bytes(
                        &scalar(value, path, &format!("{service_path}.mem_limit"))?,
                        &format!("{service_path}.mem_limit"),
                        path,
                    )?);
                }
                "mem_reservation" => {
                    parsed.mem_reservation = nonzero(parse_size_bytes(
                        &scalar(value, path, &format!("{service_path}.mem_reservation"))?,
                        &format!("{service_path}.mem_reservation"),
                        path,
                    )?);
                }
                "memswap_limit" => {
                    parsed.memswap_limit = nonzero(parse_size_bytes(
                        &scalar(value, path, &format!("{service_path}.memswap_limit"))?,
                        &format!("{service_path}.memswap_limit"),
                        path,
                    )?);
                }
                "memswap_reservation" => {
                    parsed.memswap_reservation = nonzero(parse_size_bytes(
                        &scalar(value, path, &format!("{service_path}.memswap_reservation"))?,
                        &format!("{service_path}.memswap_reservation"),
                        path,
                    )?);
                }
                "mem_swappiness" => {
                    parsed.mem_swappiness = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.mem_swappiness"),
                    )?);
                }
                "cpus" => {
                    parsed.cpus = nonzero(parse_cpu_nanos(
                        &scalar(value, path, &format!("{service_path}.cpus"))?,
                        &format!("{service_path}.cpus"),
                        path,
                    )?);
                }
                "cpu_shares" => {
                    parsed.cpu_shares = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.cpu_shares"),
                    )?);
                }
                "cpu_period" => {
                    parsed.cpu_period = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.cpu_period"),
                    )?);
                }
                "cpu_quota" => {
                    parsed.cpu_quota = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.cpu_quota"),
                    )?);
                }
                // The CPU set is a CPU-list grammar the Engine owns, so the
                // value is carried as written rather than parsed into a set.
                "cpuset" => {
                    parsed.cpuset = optional_scalar(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.cpuset"),
                        values,
                        options.interpolation,
                    )?);
                }
                "cpu_count" => {
                    parsed.cpu_count = nonzero(parse_count(
                        value,
                        path,
                        &format!("{service_path}.cpu_count"),
                    )?);
                }
                "cpu_percent" => {
                    parsed.cpu_percent = nonzero(parse_count(
                        value,
                        path,
                        &format!("{service_path}.cpu_percent"),
                    )?);
                }
                "cpu_rt_period" => {
                    parsed.cpu_rt_period = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.cpu_rt_period"),
                    )?);
                }
                "cpu_rt_runtime" => {
                    parsed.cpu_rt_runtime = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.cpu_rt_runtime"),
                    )?);
                }
                "pids_limit" => {
                    parsed.pids_limit = nonzero(parse_service_int(
                        value,
                        path,
                        &format!("{service_path}.pids_limit"),
                    )?);
                }
                "oom_kill_disable" => {
                    parsed.oom_kill_disable =
                        parse_bool(value, path, &service_path, "oom_kill_disable")?;
                }
                "oom_score_adj" => {
                    parsed.oom_score_adj = nonzero(parse_oom_score_adj(
                        value,
                        path,
                        &format!("{service_path}.oom_score_adj"),
                    )?);
                }
                "blkio_config" => {
                    parsed.blkio_config = Some(parse_blkio_config(value, path, &service_path)?);
                }
                "cgroup_parent" => {
                    parsed.cgroup_parent = optional_scalar(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.cgroup_parent"),
                        values,
                        options.interpolation,
                    )?);
                }
                "credential_spec" => {
                    parsed.credential_spec =
                        Some(parse_credential_spec(value, path, &service_path)?);
                }
                "device_cgroup_rules" => {
                    parsed.device_cgroup_rules = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.device_cgroup_rules"),
                        values,
                        options.interpolation,
                    )?;
                }
                "devices" => {
                    parsed.devices =
                        parse_devices(value, path, &service_path, values, options.interpolation)?;
                }
                "external_links" => {
                    parsed.external_links = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.external_links"),
                        values,
                        options.interpolation,
                    )?;
                }
                "volumes_from" => {
                    parsed.volumes_from = parse_path_list(
                        value,
                        path,
                        &format!("{service_path}.volumes_from"),
                        values,
                        options.interpolation,
                    )?;
                }
                "ipc" => {
                    parsed.ipc = optional_scalar(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.ipc"),
                        values,
                        options.interpolation,
                    )?);
                }
                "uts" => {
                    parsed.uts = optional_scalar(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.uts"),
                        values,
                        options.interpolation,
                    )?);
                }
                "mac_address" => {
                    parsed.mac_address = optional_scalar(resolved_scalar(
                        value,
                        path,
                        &format!("{service_path}.mac_address"),
                        values,
                        options.interpolation,
                    )?);
                }
                "storage_opt" => {
                    parsed.storage_opt =
                        mapping_string_map(value, path, &format!("{service_path}.storage_opt"))?;
                }
                // `extends` is resolved rather than recorded: Docker does not
                // render an `extends` key, it renders the fields it inherited, so
                // a model that kept the declaration would render a document whose
                // service is missing everything the base contributed. See
                // `resolve_extends`.
                "extends" => {
                    let declaration = parse_extends_declaration(
                        value,
                        path,
                        &service_path,
                        values,
                        options.interpolation,
                    )?;
                    extends.push((name.clone(), declaration));
                }
                _ if key.starts_with("x-") => {}
                _ if options.validation == ComposeValidationMode::Loose => {}
                _ => {
                    return Err(compose_error(
                        "compose_unsupported_field",
                        format!("service field '{key}' is outside the supported Compose model"),
                        Some(path),
                        &format!("{service_path}.{key}"),
                    ));
                }
            }
        }
        // The image requirement is deliberately *not* enforced here. A Compose
        // source that is one layer of an override legitimately has no image of
        // its own, and Docker Compose only requires an image on the merged
        // document. Requiring it per source would make the common pattern of a
        // base file plus a small override file impossible to express. The
        // requirement is enforced once, after the merge, in `validate_project`.
        parsed.image = image.unwrap_or_default();
        if parsed.image.is_empty() {
            declared.remove("image");
        } else {
            declared.insert("image".to_owned());
        }
        parsed.declared = declared;
        if parsed.container_name.as_deref().is_some_and(str::is_empty) {
            return Err(compose_error(
                "compose_invalid_container_name",
                "container_name must not be empty",
                Some(path),
                &format!("{service_path}.container_name"),
            ));
        }
        if result.insert(name.clone(), parsed).is_some() {
            return Err(compose_error(
                "compose_duplicate_service",
                "service names must be unique",
                Some(path),
                &service_path,
            ));
        }
    }
    if !extends.is_empty() {
        resolve_extends(&mut result, extends, path, values, options)?;
    }
    add_volumes_from_dependencies(&mut result, path)?;
    Ok(result)
}

/// Adds the dependency Compose derives from a `volumes_from` entry.
///
/// A `volumes_from: [other]` entry naming a service in the same document means
/// the container needs that service's volumes, so the other service has to exist
/// first. Compose encodes that as a plain `service_started` dependency: measured
/// on 29.8, `docker compose config` on a service with `volumes_from: [other]`
/// prints a `depends_on` entry for `other`, and a document whose `volumes_from`
/// names an undeclared service is refused with "depends on undefined service".
/// Both fall out of adding the dependency here — the ordering the plan needs, and
/// the refusal `dependency_order` already produces for a dangling dependency.
///
/// A `container:`-prefixed entry names a container outside the project, so it
/// creates no dependency and no reference this model could check.
fn add_volumes_from_dependencies(
    services: &mut BTreeMap<String, ComposeProjectService>,
    path: &str,
) -> Result<(), ComposeError> {
    let mut derived: BTreeMap<String, Vec<ComposeDependency>> = BTreeMap::new();
    for (name, service) in services.iter() {
        for entry in &service.volumes_from {
            let Some(source) = inherited_service_name(entry) else {
                continue;
            };
            if !services.contains_key(source) {
                // Not this document's service. Compose's own answer for a name it
                // cannot resolve is a dependency error, and leaving it out would
                // let a document through that Compose refuses.
                return Err(compose_error(
                    "compose_unknown_dependency",
                    format!("service '{name}' inherits volumes from undeclared service '{source}'"),
                    Some(path),
                    &format!("$.services.{name}.volumes_from"),
                ));
            }
            if source == name {
                return Err(compose_error(
                    "compose_dependency_cycle",
                    format!("service '{name}' inherits volumes from itself"),
                    Some(path),
                    &format!("$.services.{name}.volumes_from"),
                ));
            }
            let dependency = ComposeDependency {
                service: source.to_owned(),
                condition: "service_started".to_owned(),
                required: true,
            };
            let entry = derived.entry(name.clone()).or_default();
            if !entry.contains(&dependency) {
                entry.push(dependency);
            }
        }
    }
    for (name, dependencies) in derived {
        let Some(service) = services.get_mut(&name) else {
            continue;
        };
        service.depends_on.extend(dependencies);
        service
            .depends_on
            .sort_by(|left, right| left.service.cmp(&right.service));
        service.depends_on.dedup();
    }
    Ok(())
}

/// The service a `volumes_from` entry inherits from, when it names one in this
/// document.
///
/// The Engine's own spelling has three shapes: `name`, `name:ro`, and
/// `container:name` for a container outside the project. Only the first two name
/// a Compose service, and `container:` is checked first because `container` is
/// also a service name someone could legitimately write — the prefix is what
/// makes it a foreign container, not the word itself.
fn inherited_service_name(entry: &str) -> Option<&str> {
    let entry = entry.trim();
    if entry.starts_with("container:") {
        return None;
    }
    let name = entry.split_once(':').map_or(entry, |(name, _)| name);
    let name = name.trim();
    (!name.is_empty()).then_some(name)
}

/// A top-level `models` entry.
///
/// Read and discarded, deliberately. Docker 29.8 validates a `models` block —
/// `models: {llm: {}}` is refused for the missing `model`, and an unknown key
/// is refused by name — and then prints nothing for it, so a rendered document
/// that carried one would differ from `docker compose config` on a key that has
/// no container-level meaning. Keeping the validation and dropping the value is
/// the reading that matches both halves of what Docker does.
///
/// The three members were measured on 29.8: `model` is required, `context_size`
/// must be an integer, and `name` is an accepted rename.
struct ComposeModel {
    /// Engine model reference.
    model: String,
    /// Context window size, in tokens.
    context_size: Option<i64>,
    /// Engine-side name override.
    name: Option<String>,
}

/// Validates and discards a top-level `models` block.
///
/// # Errors
///
/// Returns an error naming the offending path when an entry is not a mapping, is
/// missing `model`, or carries a key Compose does not define.
fn parse_models(value: &Value, path: &str) -> Result<Vec<ComposeModel>, ComposeError> {
    let field_path = "$.models";
    let models = mapping(value, path, field_path)?;
    reject_duplicate(models, path, field_path)?;
    let mut parsed = Vec::with_capacity(models.len());
    for (name, model) in models {
        let name = scalar_key(name, path, field_path)?;
        let entry = format!("{field_path}.{name}");
        let map = mapping(model, path, &entry)?;
        reject_duplicate(map, path, &entry)?;
        let mut fields = ComposeModel {
            model: String::new(),
            context_size: None,
            name: None,
        };
        for (key, value) in map {
            let key = scalar_key(key, path, &entry)?;
            let slot = format!("{entry}.{key}");
            match key.as_str() {
                "model" => fields.model = scalar(value, path, &slot)?,
                "name" => fields.name = Some(scalar(value, path, &slot)?),
                "context_size" => {
                    fields.context_size = Some(parse_service_int(value, path, &slot)?);
                }
                _ if key.starts_with("x-") => {}
                _ => {
                    return Err(compose_error(
                        "compose_unsupported_model_field",
                        format!("models field '{key}' is outside the supported Compose model"),
                        Some(path),
                        &slot,
                    ));
                }
            }
        }
        if fields.model.is_empty() {
            return Err(compose_error(
                "compose_model_requires_reference",
                format!("model '{name}' must declare the model it names"),
                Some(path),
                &entry,
            ));
        }
        parsed.push(fields);
    }
    Ok(parsed)
}

/// Normalizes a candidate project name the way Compose does.
///
/// A project name is a Docker object name, so it is restricted to characters a
/// name may contain, and the default — the base name of the project directory —
/// is arbitrary text that usually is not. Measured against Docker 29.8.0:
///
/// | directory | project name |
/// | --- | --- |
/// | `tabw` | `tabw` |
/// | `My Project.v2` | `myprojectv2` |
/// | `--Leading` | `leading` |
///
/// So the rule is: lower-case, keep only `[a-z0-9_-]`, then trim leading `_`
/// and `-`. The last step is not cosmetic — a directory whose name starts with a
/// separator would otherwise produce a name that is not a legal object name at
/// all, and Compose trims rather than rejecting.
///
/// An explicitly declared `name:` is normalized the same way, so a document that
/// declares `name: My Project` and one that relies on the default agree.
#[must_use]
pub fn normalized_project_name(candidate: &str) -> String {
    candidate
        .to_ascii_lowercase()
        .chars()
        .filter(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || *character == '_'
                || *character == '-'
        })
        .collect::<String>()
        .trim_start_matches(['_', '-'])
        .to_owned()
}

/// The default project name for a document at `path`: the normalized base name
/// of the directory holding it, or `fallback` when the path names no directory.
///
/// This is Compose's rule, and the literal `default` it replaces was wrong in a
/// way that only shows up with two projects: every invocation that did not pass
/// `-p` addressed one project named `default`, so two compose files in two
/// directories collided on one set of containers, networks, and volumes, and
/// `compose ls` showed a project that owned neither.
///
/// Measured against Docker 29.8.0, `docker compose config` in a directory named
/// `My Project.v2` prints `name: myprojectv2`.
///
/// The `fallback` is the caller's because only the caller knows the working
/// directory. A bare relative file name — `-f compose.yaml` — carries no
/// directory at all: `Path::new("compose.yaml").parent()` is `Some("")`, so
/// deriving the name here alone produced `composeyaml`, the *file* name with its
/// dot stripped. This crate does not read the working directory, so the caller
/// supplies it.
fn project_name_from_path(path: &str, fallback: Option<&str>) -> String {
    let candidate = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .and_then(std::path::Path::file_name)
        .map_or_else(
            || fallback.unwrap_or(path).to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
    let normalized = normalized_project_name(&candidate);
    if normalized.is_empty() {
        "default".to_owned()
    } else {
        normalized
    }
}

fn parse_resources(
    value: &Value,
    path: &str,
    kind: &str,
) -> Result<BTreeMap<String, ComposeProjectResource>, ComposeError> {
    let resources = mapping(value, path, &format!("$.{kind}"))?;
    reject_duplicate(resources, path, &format!("$.{kind}"))?;
    let mut result = BTreeMap::new();
    for (name, resource) in resources {
        let name = scalar_key(name, path, &format!("$.{kind}"))?;
        validate_service_name(&name, path, &format!("$.{kind}.{name}"))?;
        let resource_path = format!("$.{kind}.{name}");
        // A resource declared with no body — `data:` — is a named resource with
        // default settings, and Docker accepts it. Measured against Docker
        // 29.8.0, `volumes: { data: }` renders as
        //
        // ```yaml
        // volumes:
        //   data:
        //     name: tabw_data
        // ```
        //
        // so the key is the declaration and the empty body means "all defaults",
        // which is exactly what an empty mapping says. Refusing it made an
        // ordinary compose file unusable, and the document is not exotic: a
        // named volume with no options is the most common way to declare one.
        let empty = Mapping::new();
        let resource_map = if resource.is_null() {
            &empty
        } else {
            mapping(resource, path, &resource_path)?
        };
        reject_duplicate(resource_map, path, &resource_path)?;
        let mut parsed = ComposeProjectResource {
            name: name.clone(),
            ..ComposeProjectResource::default()
        };
        for (key, value) in resource_map {
            let key = scalar_key(key, path, &resource_path)?;
            match key.as_str() {
                "name" => parsed.name = scalar(value, path, &format!("{resource_path}.name"))?,
                "external" => {
                    parsed.external = parse_bool(value, path, &resource_path, "external")?;
                }
                "driver" => {
                    parsed.driver = Some(scalar(value, path, &format!("{resource_path}.driver"))?);
                }
                // An `environment:` source names a variable rather than a file,
                // and Docker supports it for both configs and secrets. Refusing
                // the field made an ordinary compose file unusable, and the value
                // is only read at the moment it is written into a container.
                "environment" => {
                    parsed.environment = Some(scalar(
                        value,
                        path,
                        &format!("{resource_path}.environment"),
                    )?);
                }
                "labels" => {
                    parsed.labels = string_map_without_interpolation(
                        value,
                        path,
                        &format!("{resource_path}.labels"),
                    )?;
                }
                _ if key.starts_with("x-") => {}
                _ => {
                    return Err(compose_error(
                        "compose_unsupported_resource_field",
                        format!("resource field '{key}' is outside the supported Compose model"),
                        Some(path),
                        &format!("{resource_path}.{key}"),
                    ));
                }
            }
        }
        if parsed.name.trim().is_empty() {
            return Err(compose_error(
                "compose_invalid_resource_name",
                "resource name must not be empty",
                Some(path),
                &resource_path,
            ));
        }
        result.insert(name, parsed);
    }
    Ok(result)
}

/// The normalized members a top-level `configs` or `secrets` declaration
/// shares: Engine name, external flag, declared file, and resource labels.
/// The fields a top-level `configs` or `secrets` entry contributes.
///
/// A struct rather than a tuple because there are now five of them and
/// `(name, external, file, environment, labels)` is not a thing a reader can hold
/// in their head.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SwarmResourceFields {
    name: String,
    external: bool,
    file: Option<String>,
    environment: Option<String>,
    labels: BTreeMap<String, String>,
}

/// Shared shape of a top-level `configs` and `secrets` entry.
///
/// Both are recorded exactly as written. A declared `file` is never opened
/// here, and a secret declaration never keeps any material, so loading,
/// rendering, and digesting a document cannot read or leak a host file.
fn parse_swarm_resource(
    value: &Value,
    path: &str,
    kind: &str,
    name: &str,
    resource_path: &str,
) -> Result<SwarmResourceFields, ComposeError> {
    let resource_map = mapping(value, path, resource_path)?;
    reject_duplicate(resource_map, path, resource_path)?;
    let mut engine_name = name.to_owned();
    let mut external = false;
    let mut file = None;
    let mut environment = None;
    let mut labels = BTreeMap::new();
    for (key, value) in resource_map {
        let key = scalar_key(key, path, resource_path)?;
        match key.as_str() {
            "name" => engine_name = scalar(value, path, &format!("{resource_path}.name"))?,
            "external" => external = parse_bool(value, path, resource_path, "external")?,
            "file" => {
                file = Some(scalar(value, path, &format!("{resource_path}.file"))?);
            }
            // An `environment:` source names a variable rather than a file, and
            // Docker supports it for both configs and secrets. Refusing the field
            // made an ordinary compose file unusable, and the value is only read
            // at the moment it is written into a container, so nothing sensitive
            // is retained here.
            "environment" => {
                environment = Some(scalar(
                    value,
                    path,
                    &format!("{resource_path}.environment"),
                )?);
            }
            "labels" => {
                labels = string_map_without_interpolation(
                    value,
                    path,
                    &format!("{resource_path}.labels"),
                )?;
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_resource_field",
                    format!("{kind} field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &format!("{resource_path}.{key}"),
                ));
            }
        }
    }
    if engine_name.trim().is_empty() {
        return Err(compose_error(
            "compose_invalid_resource_name",
            format!("{kind} name must not be empty"),
            Some(path),
            resource_path,
        ));
    }
    if external && (file.is_some() || environment.is_some()) {
        return Err(compose_error(
            "compose_external_resource_with_source",
            format!("an external {kind} must not declare a file or an environment variable"),
            Some(path),
            &format!("{resource_path}.file"),
        ));
    }
    // An external resource has no source *here* by definition: whatever holds it
    // is outside this project. That is checked when it is attached, because only
    // the attach knows whether a container can be given one at all.
    //
    // A managed resource needs exactly one source. Two is ambiguous — which one
    // fills the file the container reads? — and naming the field is the only way
    // the caller can find the mistake.
    match (file.is_some(), environment.is_some()) {
        (false, false) if !external => {
            return Err(compose_error(
                "compose_resource_requires_source",
                format!(
                    "a managed {kind} must declare a file or an environment variable; a host \
                     secret is never read implicitly"
                ),
                Some(path),
                resource_path,
            ));
        }
        (true, true) => {
            return Err(compose_error(
                "compose_resource_with_two_sources",
                format!(
                    "a managed {kind} declares both a file and an environment variable; exactly \
                     one may supply its contents"
                ),
                Some(path),
                resource_path,
            ));
        }
        _ => {}
    }
    if let Some(variable) = environment.as_deref()
        && variable.trim().is_empty()
    {
        return Err(compose_error(
            "compose_invalid_resource_source",
            format!("a {kind} environment source must name a variable"),
            Some(path),
            &format!("{resource_path}.environment"),
        ));
    }
    Ok(SwarmResourceFields {
        name: engine_name,
        external,
        file,
        environment,
        labels,
    })
}

fn parse_config_resources(
    value: &Value,
    path: &str,
    kind: &str,
) -> Result<BTreeMap<String, ComposeProjectConfig>, ComposeError> {
    let resources = mapping(value, path, &format!("$.{kind}"))?;
    reject_duplicate(resources, path, &format!("$.{kind}"))?;
    let mut result = BTreeMap::new();
    for (name, resource) in resources {
        let name = scalar_key(name, path, &format!("$.{kind}"))?;
        validate_service_name(&name, path, &format!("$.{kind}.{name}"))?;
        let resource_path = format!("$.{kind}.{name}");
        let fields = parse_swarm_resource(resource, path, kind, &name, &resource_path)?;
        result.insert(
            name,
            ComposeProjectConfig {
                name: fields.name,
                external: fields.external,
                file: fields.file,
                environment: fields.environment,
                labels: fields.labels,
            },
        );
    }
    Ok(result)
}

fn parse_secret_resources(
    value: &Value,
    path: &str,
    kind: &str,
) -> Result<BTreeMap<String, ComposeProjectSecret>, ComposeError> {
    let resources = mapping(value, path, &format!("$.{kind}"))?;
    reject_duplicate(resources, path, &format!("$.{kind}"))?;
    let mut result = BTreeMap::new();
    for (name, resource) in resources {
        let name = scalar_key(name, path, &format!("$.{kind}"))?;
        validate_service_name(&name, path, &format!("$.{kind}.{name}"))?;
        let resource_path = format!("$.{kind}.{name}");
        let fields = parse_swarm_resource(resource, path, kind, &name, &resource_path)?;
        result.insert(
            name,
            ComposeProjectSecret {
                name: fields.name,
                external: fields.external,
                file: fields.file,
                environment: fields.environment,
                labels: fields.labels,
            },
        );
    }
    Ok(result)
}

/// Parses the `source`/`target` reference list a service uses for configs and
/// secrets. Both lists share one shape; only the recorded key differs.
fn parse_service_resource_references(
    value: &Value,
    path: &str,
    service_path: &str,
    kind: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<(String, Option<String>)>, ComposeError> {
    let reference_path = format!("{service_path}.{kind}s");
    let mut result: Vec<(String, Option<String>)> = Vec::new();
    let entries = match value {
        Value::Sequence(sequence) => sequence
            .iter()
            .enumerate()
            .map(|(index, item)| (format!("{reference_path}[{index}]"), item))
            .collect::<Vec<_>>(),
        Value::Mapping(named) => {
            reject_duplicate(named, path, &reference_path)?;
            let mut resolved = Vec::with_capacity(named.len());
            for (source, target) in named {
                let source = scalar_key(source, path, &reference_path)?;
                resolved.push((format!("{reference_path}.{source}"), target));
            }
            resolved
        }
        _ => {
            return Err(compose_error(
                "compose_invalid_resource_reference",
                format!("service {kind}s must be a sequence or mapping"),
                Some(path),
                &reference_path,
            ));
        }
    };
    for (item_path, item) in entries {
        let (source, target) = match item {
            Value::Mapping(details) => {
                let source = details
                    .get(Value::String("source".to_owned()))
                    .ok_or_else(|| {
                        compose_error(
                            "compose_invalid_resource_reference",
                            format!("a service {kind} reference requires a source"),
                            Some(path),
                            &item_path,
                        )
                    })
                    .and_then(|value| resolved_scalar(value, path, &item_path, values, policy))?;
                let target = details
                    .get(Value::String("target".to_owned()))
                    .map(|value| resolved_scalar(value, path, &item_path, values, policy))
                    .transpose()?;
                (source, target)
            }
            scalar_item => {
                let source = resolved_scalar(scalar_item, path, &item_path, values, policy)?;
                (source, None)
            }
        };
        validate_service_name(&source, path, &item_path)?;
        // A relative `target:` is a file name under `/run/secrets/`, which is
        // Compose's default location and the only one most applications look in.
        // An *absolute* `target:` places the secret elsewhere, and Compose allows
        // it — refusing it made a legitimate document unusable, and it is the only
        // way to deliver a secret somewhere an application already reads.
        if let Some(target) = &target
            && (target.trim().is_empty()
                || (target.contains('/') && !target.starts_with('/'))
                || target.split('/').any(|segment| segment == ".."))
        {
            return Err(compose_error(
                "compose_invalid_resource_target",
                format!("a service {kind} target must be a bare file name"),
                Some(path),
                &item_path,
            ));
        }
        // A reference repeated in one service is one reference, but the *order* the
        // document wrote is part of the rendered document: measured on 29.8, a
        // service declaring `configs: [zz, aa, mm]` gets them back in that order.
        // Deduplicating therefore keeps the first position rather than sorting.
        if !result
            .iter()
            .any(|(existing, _)| existing == &source && target.is_none())
        {
            result.push((source, target));
        }
    }
    Ok(result)
}

fn parse_service_configs(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeServiceConfig>, ComposeError> {
    Ok(
        parse_service_resource_references(value, path, service_path, "config", values, policy)?
            .into_iter()
            .map(|(source, target)| ComposeServiceConfig { source, target })
            .collect(),
    )
}

fn parse_service_secrets(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeServiceSecret>, ComposeError> {
    Ok(
        parse_service_resource_references(value, path, service_path, "secret", values, policy)?
            .into_iter()
            .map(|(source, target)| ComposeServiceSecret { source, target })
            .collect(),
    )
}

fn parse_environment(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let environment_path = format!("{service_path}.environment");
    let mut result = BTreeMap::new();
    let insert = |result: &mut BTreeMap<String, String>, key: String, value: String| {
        result.insert(key, value);
    };
    match value {
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, &environment_path)?;
            for (key, value) in mapping {
                let key = scalar_key(key, path, &environment_path)?;
                let resolved_key = resolved_text(
                    &key,
                    path,
                    &format!("{environment_path}.key"),
                    values,
                    policy,
                )?;
                let resolved_value = match value {
                    Value::Null if policy.mode == crate::InterpolationMode::Disabled => {
                        return Err(compose_error(
                            "compose_interpolation_disabled",
                            "pass-through environment values require explicit interpolation",
                            Some(path),
                            &environment_path,
                        ));
                    }
                    Value::Null => values
                        .get(&resolved_key)
                        .map_or_else(
                            || {
                                if policy.missing == crate::MissingVariablePolicy::Error {
                                    Err(compose_error(
                                        "compose_missing_interpolation",
                                        format!("required environment variable '{resolved_key}' is not injected"),
                                        Some(path),
                                        &environment_path,
                                    ))
                                } else {
                                    Ok(String::new())
                                }
                            },
                            |value| Ok(value.to_owned()),
                        )?,
                    _ => resolved_scalar(
                        value,
                        path,
                        &format!("{environment_path}.{key}"),
                        values,
                        policy,
                    )?,
                };
                validate_environment_name(&resolved_key, path, &environment_path)?;
                insert(&mut result, resolved_key, resolved_value);
            }
        }
        Value::Sequence(sequence) => {
            for (index, item) in sequence.iter().enumerate() {
                let item_path = format!("{environment_path}[{index}]");
                let text = resolved_scalar(item, path, &item_path, values, policy)?;
                let (key, value) = text
                    .split_once('=')
                    .map_or((text.as_str(), None), |(key, value)| (key, Some(value)));
                let key = resolved_text(key, path, &item_path, values, policy)?;
                let value = value.map_or_else(
                    || {
                        if policy.mode == crate::InterpolationMode::Disabled {
                            return Err(compose_error(
                                "compose_interpolation_disabled",
                                "pass-through environment values require explicit interpolation",
                                Some(path),
                                &item_path,
                            ));
                        }
                        values.get(&key).map_or_else(
                            || {
                                if policy.missing == crate::MissingVariablePolicy::Error {
                                    Err(compose_error(
                                        "compose_missing_interpolation",
                                        format!(
                                            "required environment variable '{key}' is not injected"
                                        ),
                                        Some(path),
                                        &item_path,
                                    ))
                                } else {
                                    Ok(String::new())
                                }
                            },
                            |value| Ok(value.to_owned()),
                        )
                    },
                    |value| resolved_text(value, path, &item_path, values, policy),
                )?;
                validate_environment_name(&key, path, &item_path)?;
                insert(&mut result, key, value);
            }
        }
        _ => {
            return Err(compose_error(
                "compose_invalid_environment",
                "environment must be a mapping or sequence",
                Some(path),
                &environment_path,
            ));
        }
    }
    Ok(result)
}

fn parse_argv(
    value: &Value,
    path: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<String>, ComposeError> {
    match value {
        Value::String(value) => {
            let value = resolved_text(value, path, field_path, values, policy)?;
            split_command(&value, path, field_path)
        }
        Value::Sequence(sequence) => sequence
            .iter()
            .enumerate()
            .map(|(index, item)| {
                resolved_scalar(
                    item,
                    path,
                    &format!("{field_path}[{index}]"),
                    values,
                    policy,
                )
            })
            .collect(),
        _ => Err(compose_error(
            "compose_invalid_argv",
            "command and entrypoint must be a scalar or sequence",
            Some(path),
            field_path,
        )),
    }
}

fn parse_ports(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposePort>, ComposeError> {
    let port_path = format!("{service_path}.ports");
    let sequence = sequence(value, path, &port_path)?;
    let mut result = Vec::new();
    for (index, item) in sequence.iter().enumerate() {
        let item_path = format!("{port_path}[{index}]");
        let port = match item {
            Value::Mapping(mapping) => {
                reject_duplicate(mapping, path, &item_path)?;
                let target = required_map_scalar(mapping, "target", path, &item_path)?;
                let published = mapping
                    .get(Value::String("published".to_owned()))
                    .map(|value| scalar(value, path, &format!("{item_path}.published")))
                    .transpose()?;
                let protocol = mapping
                    .get(Value::String("protocol".to_owned()))
                    .map(|value| scalar(value, path, &format!("{item_path}.protocol")))
                    .transpose()?
                    .unwrap_or_else(|| "tcp".to_owned());
                let host_ip = mapping
                    .get(Value::String("host_ip".to_owned()))
                    .map(|value| scalar(value, path, &format!("{item_path}.host_ip")))
                    .transpose()?;
                // `mode` is read from the long form only. The short form has no
                // spelling for it, and Compose's default is `ingress`, which is
                // what a short form means.
                let mode = match mapping.get(Value::String("mode".to_owned())) {
                    Some(value) => {
                        match scalar(value, path, &format!("{item_path}.mode"))?.as_str() {
                            "host" => ComposePortMode::Host,
                            "ingress" => ComposePortMode::Ingress,
                            other => {
                                return Err(compose_error(
                                    "compose_invalid_port_mode",
                                    format!("port mode must be 'ingress' or 'host', not '{other}'"),
                                    Some(path),
                                    &format!("{item_path}.mode"),
                                ));
                            }
                        }
                    }
                    None => ComposePortMode::Ingress,
                };
                ComposePort {
                    target: parse_port_number(&target, path, &item_path)?,
                    published: published
                        .as_deref()
                        .map(|value| parse_port_number(value, path, &item_path))
                        .transpose()?,
                    protocol: parse_protocol(&protocol, path, &item_path)?,
                    host_ip,
                    mode,
                }
            }
            _ => {
                let text = resolved_scalar(item, path, &item_path, values, policy)?;
                parse_short_port(&text, path, &item_path)?
            }
        };
        result.push(port);
    }
    Ok(result)
}

fn parse_mounts(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeMount>, ComposeError> {
    let mount_path = format!("{service_path}.volumes");
    let sequence = sequence(value, path, &mount_path)?;
    let mut result = Vec::new();
    for (index, item) in sequence.iter().enumerate() {
        let item_path = format!("{mount_path}[{index}]");
        let mount = match item {
            Value::Mapping(mapping) => {
                reject_duplicate(mapping, path, &item_path)?;
                let kind = mapping
                    .get(Value::String("type".to_owned()))
                    .map(|value| scalar(value, path, &format!("{item_path}.type")))
                    .transpose()?
                    .unwrap_or_else(|| "volume".to_owned());
                let kind = parse_mount_kind(&kind, path, &item_path)?;
                let source = mapping
                    .get(Value::String("source".to_owned()))
                    .map(|value| scalar(value, path, &format!("{item_path}.source")))
                    .transpose()?;
                let target = required_map_scalar(mapping, "target", path, &item_path)?;
                let read_only = mapping
                    .get(Value::String("read_only".to_owned()))
                    .map(|value| parse_bool(value, path, &item_path, "read_only"))
                    .transpose()?
                    .unwrap_or(false);
                // A sub-mapping whose key does not match the mount's `type` has no
                // meaning in Compose's own model either, so it is not read: keeping
                // it would mean rendering a `nocopy` under a `bind`.
                let subtree = mapping
                    .get(Value::String(kind.as_str().to_owned()))
                    .map(|value| parse_mount_subtree(kind, value, path, &item_path))
                    .transpose()?;
                ComposeMount {
                    kind,
                    source,
                    target,
                    read_only,
                    subtree,
                    short_form: false,
                }
            }
            _ => {
                let text = resolved_scalar(item, path, &item_path, values, policy)?;
                parse_short_mount(&text, path, &item_path)?
            }
        };
        if mount.target.trim().is_empty() {
            return Err(compose_error(
                "compose_invalid_mount",
                "mount target must not be empty",
                Some(path),
                &item_path,
            ));
        }
        result.push(mount);
    }
    Ok(result)
}

/// Reads the sub-mapping that matches a mount's kind.
///
/// # Errors
///
/// Returns an error naming `item_path` when a member is not the value Compose
/// declares for it.
fn parse_mount_subtree(
    kind: ComposeMountKind,
    value: &Value,
    path: &str,
    item_path: &str,
) -> Result<ComposeMountSubtree, ComposeError> {
    let entry_path = format!("{item_path}.{}", kind.as_str());
    let mapping = mapping(value, path, &entry_path)?;
    reject_duplicate(mapping, path, &entry_path)?;
    let mut bind = ComposeBindOptions::default();
    let mut volume = ComposeVolumeOptions::default();
    let mut tmpfs = ComposeTmpfsOptions::default();
    for (key, value) in mapping {
        let key = scalar_key(key, path, &entry_path)?;
        let slot = format!("{entry_path}.{key}");
        let text = || scalar(value, path, &slot);
        match (kind, key.as_str()) {
            (ComposeMountKind::Bind, "propagation") => bind.propagation = Some(text()?),
            (ComposeMountKind::Bind, "selinux") => bind.selinux = Some(text()?),
            (ComposeMountKind::Volume, "nocopy") => {
                volume.nocopy = Some(parse_bool(value, path, item_path, "nocopy")?);
            }
            (ComposeMountKind::Volume, "subpath") => volume.subpath = Some(text()?),
            (ComposeMountKind::Tmpfs, "size") => {
                tmpfs.size = Some(parse_size_bytes(&text()?, &slot, path)?);
            }
            (ComposeMountKind::Tmpfs, "mode") => {
                tmpfs.mode = Some(parse_permission_bits(value, path, &slot)?);
            }
            // `create_host_path` is a real Compose key that Compose does not print,
            // and `x-` keys are the extension prefix every list in this model
            // accepts. Neither is representable, so neither is read.
            (_, key) if key == "create_host_path" || key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!(
                        "{item_path}: '{}' is not a member of a {} mount",
                        key,
                        kind.as_str()
                    ),
                    Some(path),
                    &slot,
                ));
            }
        }
    }
    Ok(match kind {
        ComposeMountKind::Bind => ComposeMountSubtree::Bind(bind),
        ComposeMountKind::Volume => ComposeMountSubtree::Volume(volume),
        ComposeMountKind::Tmpfs => ComposeMountSubtree::Tmpfs(tmpfs),
    })
}

fn parse_dependencies(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeDependency>, ComposeError> {
    let dependency_path = format!("{service_path}.depends_on");
    let mut result = Vec::new();
    match value {
        Value::Sequence(sequence) => {
            for (index, item) in sequence.iter().enumerate() {
                let item_path = format!("{dependency_path}[{index}]");
                let service = resolved_scalar(item, path, &item_path, values, policy)?;
                validate_service_name(&service, path, &item_path)?;
                result.push(ComposeDependency {
                    service,
                    condition: "service_started".to_owned(),
                    required: true,
                });
            }
        }
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, &dependency_path)?;
            for (service, condition) in mapping {
                let service = scalar_key(service, path, &dependency_path)?;
                validate_service_name(&service, path, &dependency_path)?;
                let (condition, required) = match condition {
                    Value::String(value) => (value.clone(), true),
                    Value::Mapping(details) => {
                        let condition = details
                            .get(Value::String("condition".to_owned()))
                            .map(|value| scalar(value, path, &dependency_path))
                            .transpose()?
                            .unwrap_or_else(|| "service_started".to_owned());
                        let required = details
                            .get(Value::String("required".to_owned()))
                            .map(|value| parse_bool(value, path, &dependency_path, "required"))
                            .transpose()?
                            .unwrap_or(true);
                        (condition, required)
                    }
                    _ => {
                        return Err(compose_error(
                            "compose_invalid_dependency",
                            "depends_on entries must be names or condition mappings",
                            Some(path),
                            &dependency_path,
                        ));
                    }
                };
                let condition = resolved_text(&condition, path, &dependency_path, values, policy)?;
                if !matches!(
                    condition.as_str(),
                    "service_started" | "service_healthy" | "service_completed_successfully"
                ) {
                    return Err(compose_error(
                        "compose_invalid_dependency_condition",
                        "depends_on condition is not supported",
                        Some(path),
                        &dependency_path,
                    ));
                }
                result.push(ComposeDependency {
                    service,
                    condition,
                    required,
                });
            }
        }
        _ => {
            return Err(compose_error(
                "compose_invalid_dependency",
                "depends_on must be a sequence or mapping",
                Some(path),
                &dependency_path,
            ));
        }
    }
    result.sort_by(|left, right| left.service.cmp(&right.service));
    Ok(result)
}

fn parse_service_networks(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeServiceNetwork>, ComposeError> {
    let network_path = format!("{service_path}.networks");
    let mut result = Vec::new();
    match value {
        Value::Sequence(sequence) => {
            for (index, item) in sequence.iter().enumerate() {
                let item_path = format!("{network_path}[{index}]");
                let name = resolved_scalar(item, path, &item_path, values, policy)?;
                validate_service_name(&name, path, &item_path)?;
                result.push(ComposeServiceNetwork {
                    name,
                    aliases: Vec::new(),
                });
            }
        }
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, &network_path)?;
            for (name, aliases) in mapping {
                let name = scalar_key(name, path, &network_path)?;
                validate_service_name(&name, path, &network_path)?;
                let aliases = match aliases {
                    Value::Null => Vec::new(),
                    Value::Sequence(sequence) => parse_network_aliases(
                        sequence,
                        path,
                        &format!("{network_path}.{name}"),
                        values,
                        policy,
                    )?,
                    Value::Mapping(details) => {
                        reject_duplicate(details, path, &network_path)?;
                        let mut parsed = Vec::new();
                        for (key, value) in details {
                            let key = scalar_key(key, path, &network_path)?;
                            if key != "aliases" {
                                return Err(compose_error(
                                    "compose_unsupported_network_field",
                                    format!(
                                        "network field '{key}' is outside the supported Compose model"
                                    ),
                                    Some(path),
                                    &format!("{network_path}.{name}"),
                                ));
                            }
                            let sequence =
                                sequence(value, path, &format!("{network_path}.{name}.aliases"))?;
                            parsed = parse_network_aliases(
                                sequence,
                                path,
                                &format!("{network_path}.{name}.aliases"),
                                values,
                                policy,
                            )?;
                        }
                        parsed
                    }
                    _ => {
                        return Err(compose_error(
                            "compose_invalid_network",
                            "network aliases must be a sequence or an aliases mapping",
                            Some(path),
                            &network_path,
                        ));
                    }
                };
                result.push(ComposeServiceNetwork { name, aliases });
            }
        }
        _ => {
            return Err(compose_error(
                "compose_invalid_network",
                "networks must be a sequence or mapping",
                Some(path),
                &network_path,
            ));
        }
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

fn parse_network_aliases(
    sequence: &[Value],
    path: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<String>, ComposeError> {
    let mut aliases = sequence
        .iter()
        .enumerate()
        .map(|(index, item)| {
            resolved_scalar(
                item,
                path,
                &format!("{field_path}[{index}]"),
                values,
                policy,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    aliases.sort();
    aliases.dedup();
    Ok(aliases)
}

fn parse_build(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<ComposeBuild, ComposeError> {
    let build_path = format!("{service_path}.build");
    let result = match value {
        Value::String(context) => ComposeBuild {
            context: resolved_text(context, path, &build_path, values, policy)?,
            ..ComposeBuild::default()
        },
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, &build_path)?;
            let context = required_map_scalar(mapping, "context", path, &build_path)?;
            let dockerfile = mapping
                .get(Value::String("dockerfile".to_owned()))
                .map(|value| scalar(value, path, &format!("{build_path}.dockerfile")))
                .transpose()?;
            let target = mapping
                .get(Value::String("target".to_owned()))
                .map(|value| scalar(value, path, &format!("{build_path}.target")))
                .transpose()?;
            let platform = mapping
                .get(Value::String("platform".to_owned()))
                .map(|value| scalar(value, path, &format!("{build_path}.platform")))
                .transpose()?;
            let no_cache = mapping
                .get(Value::String("no_cache".to_owned()))
                .map(|value| parse_bool(value, path, &build_path, "no_cache"))
                .transpose()?
                .unwrap_or(false);
            let pull = mapping
                .get(Value::String("pull".to_owned()))
                .map(|value| parse_bool(value, path, &build_path, "pull"))
                .transpose()?;
            let arguments = mapping
                .get(Value::String("args".to_owned()))
                .map(|value| {
                    parse_string_map(value, path, &format!("{build_path}.args"), values, policy)
                })
                .transpose()?
                .unwrap_or_default();
            let labels = mapping
                .get(Value::String("labels".to_owned()))
                .map(|value| {
                    parse_string_map(value, path, &format!("{build_path}.labels"), values, policy)
                })
                .transpose()?
                .unwrap_or_default();
            let cache_from = parse_cache_from(mapping, path, &build_path)?;
            let buildkit = parse_buildkit_fields(mapping, path, &build_path)?;
            ComposeBuild {
                context: resolved_text(&context, path, &build_path, values, policy)?,
                dockerfile,
                target,
                platform,
                no_cache,
                pull,
                arguments,
                labels,
                cache_from,
                buildkit,
            }
        }
        _ => {
            return Err(compose_error(
                "compose_invalid_build",
                "build must be a context string or mapping",
                Some(path),
                &build_path,
            ));
        }
    };
    if result.context.trim().is_empty() {
        return Err(compose_error(
            "compose_invalid_build",
            "build context must not be empty",
            Some(path),
            &build_path,
        ));
    }
    Ok(result)
}

/// Parses `build.cache_from`, which Compose accepts as one image reference or a
/// list of them.
fn parse_cache_from(
    mapping: &Mapping,
    path: &str,
    build_path: &str,
) -> Result<Vec<String>, ComposeError> {
    let field_path = format!("{build_path}.cache_from");
    let Some(value) = mapping.get(Value::String("cache_from".to_owned())) else {
        return Ok(Vec::new());
    };
    let entries = match value {
        Value::Sequence(entries) => entries.iter().collect::<Vec<_>>(),
        single => vec![single],
    };
    entries
        .into_iter()
        .map(|entry| scalar(entry, path, &field_path))
        .collect()
}

/// Records every BuildKit-only `build` field the document declares.
///
/// The values are intentionally not modeled: only a classic Engine builder is
/// applied by this slice, so the declaration is reported by name rather than
/// partially honored.
fn parse_buildkit_fields(
    mapping: &Mapping,
    path: &str,
    build_path: &str,
) -> Result<Vec<ComposeBuildKitField>, ComposeError> {
    let mut fields = Vec::new();
    for (key, field) in ComposeBuildKitField::all() {
        let Some(value) = mapping.get(Value::String(key.to_owned())) else {
            continue;
        };
        if value.is_null() {
            return Err(compose_error(
                "compose_invalid_build",
                "build field must not be empty",
                Some(path),
                &format!("{build_path}.{key}"),
            ));
        }
        fields.push(field);
    }
    Ok(fields)
}

fn parse_replicas(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<u32, ComposeError> {
    let text = match value {
        Value::Mapping(mapping) => {
            if mapping.len() == 1 {
                if let Some(replicas) = mapping.get(Value::String("replicas".to_owned())) {
                    scalar(replicas, path, &format!("{service_path}.deploy.replicas"))?
                } else {
                    return Err(compose_error(
                        "compose_unsupported_deploy",
                        "only deploy.replicas is supported by the local Compose model",
                        Some(path),
                        &format!("{service_path}.deploy"),
                    ));
                }
            } else {
                return Err(compose_error(
                    "compose_unsupported_deploy",
                    "only deploy.replicas is supported by the local Compose model",
                    Some(path),
                    &format!("{service_path}.deploy"),
                ));
            }
        }
        _ => resolved_scalar(
            value,
            path,
            &format!("{service_path}.scale"),
            values,
            policy,
        )?,
    };
    let replicas = text.parse::<u32>().map_err(|_| {
        compose_error(
            "compose_invalid_replicas",
            "service replicas must be a non-negative integer",
            Some(path),
            &format!("{service_path}.scale"),
        )
    })?;
    if replicas == 0 || replicas > 10_000 {
        return Err(compose_error(
            "compose_invalid_replicas",
            "service replicas must be between 1 and 10000",
            Some(path),
            &format!("{service_path}.scale"),
        ));
    }
    Ok(replicas)
}

/// Reads one entry of the sequence spelling of a Compose string map.
///
/// Docker Compose accepts either a mapping or a sequence of `key=value` strings
/// wherever a string map is expected (`labels`, `build.args`, `build.labels`,
/// and resource labels). The entry splits at the **first** `=`, so a value may
/// itself contain `=`; an entry with no `=` is a bare key with an empty value,
/// which is how a valueless label is written.
fn string_map_sequence_entry(
    entry: &Value,
    source: &str,
    field_path: &str,
) -> Result<(String, String), ComposeError> {
    let text = scalar(entry, source, field_path)?;
    Ok(match text.split_once('=') {
        Some((key, value)) => (key.to_owned(), value.to_owned()),
        None => (text, String::new()),
    })
}

/// Reports the error for a string map that is neither accepted spelling.
///
/// Naming both spellings matters: the message is the only thing a user sees when
/// a `key=value` list is rejected, and "expected a mapping" reads as though the
/// list form were not a thing.
fn string_map_type_error(source: &str, field_path: &str) -> ComposeError {
    compose_error(
        "compose_expected_mapping",
        "expected a mapping or a sequence of key=value strings",
        Some(source),
        field_path,
    )
}

/// Parses a `env_file`/`label_file` entry, which is either one path or a list.
fn parse_path_list(
    value: &Value,
    source: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<String>, ComposeError> {
    match value {
        Value::String(single) => Ok(vec![resolved_text(
            single, source, field_path, values, policy,
        )?]),
        Value::Sequence(entries) => entries
            .iter()
            .map(|entry| {
                let entry = scalar(entry, source, field_path)?;
                resolved_text(&entry, source, field_path, values, policy)
            })
            .collect(),
        _ => Err(compose_error(
            "compose_invalid_path_list",
            "expected a path or a list of paths",
            Some(source),
            field_path,
        )),
    }
}

/// Parses a `restart` declaration in either of Compose's two spellings.
///
/// Docker accepts a bare word — `always`, `unless-stopped`, `no`, and
/// `on-failure` with an optional `:N` retry count — and a mapping with
/// `condition`, `max_attempts`, `window`, and `delay`. Both are normalized to the
/// Engine's name-plus-count so that two documents meaning the same thing cannot
/// produce two different restart behaviors.
///
/// A retry count on a policy that has no notion of one is refused rather than
/// dropped: `restart: {condition: always, max_attempts: 3}` asks for something
/// that does not exist, and quietly ignoring the `3` would leave a document that
/// looks like it retries and does not.
fn parse_restart(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
) -> Result<ComposeRestart, ComposeError> {
    let field_path = format!("{service_path}.restart");
    let known = ["no", "always", "unless-stopped", "on-failure"];
    let build = |name: &str, retries: Option<i64>| -> Result<ComposeRestart, ComposeError> {
        if !known.contains(&name) {
            return Err(compose_error(
                "compose_invalid_restart_policy",
                format!(
                    "restart condition '{name}' must be one of no, always, unless-stopped, \
                     on-failure"
                ),
                Some(path),
                &field_path,
            ));
        }
        if retries.is_some() && name != "on-failure" {
            return Err(compose_error(
                "compose_invalid_restart_policy",
                format!(
                    "a restart retry count only applies to the on-failure condition, not '{name}'"
                ),
                Some(path),
                &field_path,
            ));
        }
        Ok(ComposeRestart {
            name: name.to_owned(),
            maximum_retry_count: retries,
        })
    };
    match value {
        Value::String(word) => {
            let word = resolved_text(
                word,
                path,
                &field_path,
                values,
                InterpolationPolicy::default(),
            )?;
            // `on-failure:3` is the one spelling with an argument, and splitting on
            // the first colon keeps a value that itself contains a colon intact
            // enough to be refused by the name check rather than mangled.
            match word.split_once(':') {
                Some((condition, count)) => {
                    let count = count.trim().parse::<i64>().map_err(|_| {
                        compose_error(
                            "compose_invalid_restart_policy",
                            format!("restart retry count '{count}' is not a number"),
                            Some(path),
                            &field_path,
                        )
                    })?;
                    build(condition.trim(), Some(count))
                }
                None => build(word.trim(), None),
            }
        }
        Value::Mapping(map) => {
            reject_duplicate(map, path, &field_path)?;
            let mut condition = None;
            let mut retries = None;
            for (key, value) in map {
                let key = scalar_key(key, path, &field_path)?;
                match key.as_str() {
                    "condition" => {
                        condition = Some(scalar(value, path, &format!("{field_path}.condition"))?);
                    }
                    "max_attempts" => {
                        retries = Some(
                            scalar(value, path, &format!("{field_path}.max_attempts"))?
                                .trim()
                                .parse::<i64>()
                                .map_err(|_| {
                                    compose_error(
                                        "compose_invalid_restart_policy",
                                        "restart max_attempts must be a number",
                                        Some(path),
                                        &format!("{field_path}.max_attempts"),
                                    )
                                })?,
                        );
                    }
                    // `window` and `delay` have no Engine counterpart in this
                    // request shape. They are recorded by the document and ignored
                    // by the container create rather than refused, because a
                    // document that a Swarm deploy will honor should still load
                    // here.
                    "window" | "delay" => {}
                    _ if key.starts_with("x-") => {}
                    _ => {
                        return Err(compose_error(
                            "compose_unsupported_field",
                            format!("restart field '{key}' is outside the supported Compose model"),
                            Some(path),
                            &format!("{field_path}.{key}"),
                        ));
                    }
                }
            }
            build(condition.as_deref().unwrap_or("no").trim(), retries)
        }
        _ => Err(compose_error(
            "compose_invalid_restart_policy",
            "expected a restart condition or a restart mapping",
            Some(path),
            &field_path,
        )),
    }
}

/// Parses a `healthcheck` declaration.
///
/// `disable: true` is the only spelling for "no health check on purpose", and it
/// has to survive parsing: without it a document cannot turn a check off, and the
/// alternative — writing a check that always passes — is a lie the Engine would
/// have to be told.
fn parse_healthcheck(
    value: &Value,
    path: &str,
    service_path: &str,
) -> Result<ComposeHealthcheck, ComposeError> {
    let field_path = format!("{service_path}.healthcheck");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut parsed = ComposeHealthcheck::default();
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            // A health check is a `test`, and Compose writes the test either as a
            // list or as a single string. The string form is kept as one element
            // rather than split: a shell command's own quoting is the author's,
            // and splitting on whitespace here would break `["CMD-SHELL",
            // "curl -f http://x || exit 1"]` for no gain.
            "test" => {
                parsed.test = match value {
                    Value::String(command) => vec![command.clone()],
                    Value::Sequence(entries) => entries
                        .iter()
                        .enumerate()
                        .map(|(index, entry)| {
                            scalar(entry, path, &entry_path(&field_path, "test", index))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => {
                        return Err(compose_error(
                            "compose_invalid_healthcheck",
                            "healthcheck test must be a string or a list of strings",
                            Some(path),
                            &entry,
                        ));
                    }
                };
            }
            "disable" => {
                parsed.disable = parse_bool(value, path, service_path, "disable")?;
            }
            "interval" | "timeout" | "start_period" | "start_interval" => {
                let duration = scalar(value, path, &entry)?;
                // Validated at parse time so a typo is reported against the field
                // that has it, rather than becoming a nanosecond count the Engine
                // will reject with a message that names no field.
                parse_duration_nanos(&duration, &entry, path)?;
                match key.as_str() {
                    "interval" => parsed.interval = Some(duration),
                    "timeout" => parsed.timeout = Some(duration),
                    "start_period" => parsed.start_period = Some(duration),
                    _ => parsed.start_interval = Some(duration),
                }
            }
            "retries" => {
                let count = scalar(value, path, &entry)?;
                parsed.retries = Some(count.trim().parse::<i64>().map_err(|_| {
                    compose_error(
                        "compose_invalid_healthcheck",
                        "healthcheck retries must be a number",
                        Some(path),
                        &entry,
                    )
                })?);
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("healthcheck field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// The JSON path of one sequence entry, for a diagnostic that has to name it.
///
/// The index is the entry's position, because that is what a reader can act on: a
/// message naming `test[0]` points at the first line of the list, and one that
/// quoted the entry's own text would name a value rather than a place.
fn entry_path(field_path: &str, key: &str, index: usize) -> String {
    format!("{field_path}.{key}[{index}]")
}

/// Parses a service's `tmpfs` list into container-path/size pairs.
///
/// The value is a path, optionally followed by `:size` and `:mode`, which is the
/// same shape the Engine's tmpfs map wants. The size is resolved to bytes here so
/// a `64m` in a document and a `64m` on a command line mean one number, and the
/// bare-path form — which is most of what people write — yields an empty size,
/// meaning "the Engine's default".
fn parse_tmpfs(
    value: &Value,
    path: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let entries = parse_path_list(value, path, field_path, values, policy)?;
    let mut result = BTreeMap::new();
    for entry in entries {
        // Split on the *first* colon only, so a Windows-style or otherwise
        // colon-bearing path is not torn into pieces. A tmpfs target is
        // container-side and Linux-shaped in every real document, but splitting
        // the tail rather than the head is what keeps this from guessing.
        let (target, options) = entry
            .split_once(':')
            .map_or((entry.as_str(), ""), |(target, rest)| (target, rest));
        if target.is_empty() {
            return Err(compose_error(
                "compose_invalid_tmpfs",
                format!("tmpfs entry '{entry}' does not name a path"),
                Some(path),
                field_path,
            ));
        }
        let mut size = String::new();
        for option in options.split(':').filter(|option| !option.is_empty()) {
            if let Some(digits) = option.strip_prefix("size=") {
                // Validated so a typo is reported against the option that has it.
                parse_size_bytes(digits, &format!("{field_path}.size"), path)?;
                digits.clone_into(&mut size);
            }
            // `mode=` is accepted and not carried: the Engine's tmpfs map takes
            // only a size, so there is nowhere for a mode to go. Refusing the
            // whole entry would break documents that only want the size.
        }
        result.insert(target.to_owned(), size);
    }
    Ok(result)
}

/// Parses an `init` declaration.
///
/// Compose spells this as a boolean, and the YAML shorthand `init: true` arrives
/// as a boolean, so the ordinary path is the ordinary one. The `docker-init`
/// spelling is accepted too because a document that names the binary is asking
/// for the same thing and refusing it would be a refusal about spelling.
fn parse_init(value: &Value, path: &str, service_path: &str) -> Result<bool, ComposeError> {
    let field_path = format!("{service_path}.init");
    match value {
        Value::String(name) => match name.as_str() {
            "true" | "docker-init" | "" => Ok(true),
            "false" => Ok(false),
            other => Err(compose_error(
                "compose_invalid_init",
                format!("init must be true, false, or 'docker-init', not '{other}'"),
                Some(path),
                &field_path,
            )),
        },
        other => parse_bool(other, path, service_path, "init"),
    }
}

/// Parses a `logging` declaration.
fn parse_logging(
    value: &Value,
    path: &str,
    service_path: &str,
) -> Result<ComposeLogging, ComposeError> {
    let field_path = format!("{service_path}.logging");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut parsed = ComposeLogging::default();
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "driver" => parsed.driver = scalar(value, path, &entry)?,
            "options" => {
                parsed.options = string_map_without_interpolation(value, path, &entry)?;
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("logging field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parses a `ulimits` declaration in either of Compose's spellings.
///
/// A bare integer is Docker's shorthand for "soft and hard are both this" and is
/// common enough in hand-written documents that refusing it would be a refusal
/// nobody would thank me for.
fn parse_ulimits(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<Vec<ComposeUlimit>, ComposeError> {
    let map = mapping(value, path, field_path)?;
    reject_duplicate(map, path, field_path)?;
    let mut limits = Vec::new();
    for (key, value) in map {
        let name = scalar_key(key, path, field_path)?;
        let entry = format!("{field_path}.{name}");
        // The bare number is recorded as its own spelling, because Docker prints
        // it back as a bare number. A mapping that means exactly the same thing
        // prints as a mapping, and only the spelling tells them apart.
        let short_form = matches!(value, Value::Number(_));
        let (soft, hard) = match value {
            Value::Number(number) => {
                let single = number.as_i64().ok_or_else(|| {
                    compose_error(
                        "compose_invalid_ulimit",
                        format!("ulimit '{name}' must be a whole number"),
                        Some(path),
                        &entry,
                    )
                })?;
                (single, single)
            }
            Value::Mapping(inner) => {
                reject_duplicate(inner, path, &entry)?;
                let mut soft = None;
                let mut hard = None;
                for (key, value) in inner {
                    let key = scalar_key(key, path, &entry)?;
                    let slot = format!("{entry}.{key}");
                    let read = |target: &mut Option<i64>| -> Result<(), ComposeError> {
                        *target = Some(scalar(value, path, &slot)?.trim().parse::<i64>().map_err(
                            |_| {
                                compose_error(
                                    "compose_invalid_ulimit",
                                    format!("ulimit '{name}' {key} must be a number"),
                                    Some(path),
                                    &slot,
                                )
                            },
                        )?);
                        Ok(())
                    };
                    match key.as_str() {
                        "soft" => read(&mut soft)?,
                        "hard" => read(&mut hard)?,
                        _ if key.starts_with("x-") => {}
                        _ => {
                            return Err(compose_error(
                                "compose_unsupported_field",
                                format!(
                                    "ulimit field '{key}' is outside the supported Compose model"
                                ),
                                Some(path),
                                &slot,
                            ));
                        }
                    }
                }
                match (soft, hard) {
                    (Some(soft), Some(hard)) => (soft, hard),
                    (Some(soft), None) => (soft, i64::MAX),
                    (None, Some(hard)) => (i64::MAX, hard),
                    (None, None) => {
                        return Err(compose_error(
                            "compose_invalid_ulimit",
                            format!("ulimit '{name}' declares neither a soft nor a hard limit"),
                            Some(path),
                            &entry,
                        ));
                    }
                }
            }
            _ => {
                return Err(compose_error(
                    "compose_invalid_ulimit",
                    format!("ulimit '{name}' must be a number or a soft/hard mapping"),
                    Some(path),
                    &entry,
                ));
            }
        };
        limits.push(ComposeUlimit {
            name,
            soft,
            hard,
            short_form,
        });
    }
    limits.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(limits)
}

/// Reads a file-permission mask the way Docker's YAML reader does.
///
/// A `mode` is a number of permission bits, and the two spellings have to agree
/// because a document may use either. Measured on 29.8: `mode: 0444` prints as
/// `mode: 292` and `mode: 292` prints as `mode: 292`, while the quoted spelling
/// `mode: "1777"` is refused outright.
///
/// The leading-zero form is a YAML 1.1 octal, which is what `go-yaml` — and so
/// Compose — reads it as. `serde_yaml` implements YAML 1.2, where `0444` is the
/// *string* `"0444"` rather than a number, so the octal has to be recognized here
/// from the text the reader produced or `0444` would become the decimal 444.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is neither a number nor a
/// leading-zero octal one.
fn parse_permission_bits(value: &Value, path: &str, field_path: &str) -> Result<i64, ComposeError> {
    let text = scalar(value, path, field_path)?;
    let invalid = || {
        compose_error(
            "compose_invalid_mount_mode",
            format!("mount mode '{text}' must be a number"),
            Some(path),
            field_path,
        )
    };
    if let Some(octal) = text.strip_prefix('0').filter(|rest| !rest.is_empty()) {
        return i64::from_str_radix(octal, 8).map_err(|_| invalid());
    }
    text.parse::<i64>().map_err(|_| invalid())
}

/// Reads a scalar that Compose declares as an integer.
///
/// The scalar reader already turns a YAML number into its own text, so both
/// `500` and `"500"` arrive here as digits and either spelling is accepted —
/// which is what Compose does for these fields: measured on 29.8,
/// `cpu_count: "2"` and `cpu_count: 2` both print `cpu_count: 2`.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not an integer.
fn parse_service_int(value: &Value, path: &str, field_path: &str) -> Result<i64, ComposeError> {
    scalar(value, path, field_path)?
        .trim()
        .parse::<i64>()
        .map_err(|_| {
            compose_error(
                "compose_invalid_integer",
                format!(
                    "'{}' is not a whole number",
                    scalar(value, path, field_path).unwrap_or_default()
                ),
                Some(path),
                field_path,
            )
        })
}

/// Reads a count Compose refuses to accept as a negative number.
///
/// `cpu_count` and `cpu_percent` are the two such fields: measured on 29.8,
/// `cpu_count: -1` is refused while `cpu_count: 0` is accepted and then dropped
/// from the output as the default.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not a non-negative
/// integer.
fn parse_count(value: &Value, path: &str, field_path: &str) -> Result<i64, ComposeError> {
    let count = parse_service_int(value, path, field_path)?;
    if count < 0 {
        return Err(compose_error(
            "compose_invalid_integer",
            format!("'{field_path}' must not be negative"),
            Some(path),
            field_path,
        ));
    }
    Ok(count)
}

/// Parses `cpus` into whole nano-CPUs.
///
/// The document's value is a decimal number of CPUs and the Engine's is an
/// integer count of billionths, so the conversion happens once, here, with the
/// same integer arithmetic the duration and size tables use. Rounding is to the
/// nearest nano-CPU, which is what Docker's own output implies: measured on 29.8,
/// `cpus: 0.0000001234` prints `1.234e-07` (123 nano-CPUs) and `cpus: 0.0000019`
/// prints `1.9e-06` (1900), where truncation would have printed `1.8999999e-06`.
///
/// An exponent is read as part of the number because a YAML reader hands the
/// same value over in either spelling: `0.0000019` reaches this function as
/// `1.9e-6` from `serde_yaml`, and refusing that would refuse a document
/// Compose accepts.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not a decimal number or
/// when the nano-CPU count is larger than a 64-bit integer holds.
fn parse_cpu_nanos(value: &str, field_path: &str, path: &str) -> Result<i64, ComposeError> {
    let invalid = |reason: &str| {
        compose_error(
            "compose_invalid_cpus",
            format!("'{value}' is not a CPU count: {reason}"),
            Some(path),
            field_path,
        )
    };
    let trimmed = value.trim();
    let (sign, number) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1_i128, rest),
        None => (1_i128, trimmed),
    };
    // The number is the leading run of digits and decimal points; whatever
    // follows is the exponent, which `decimal_exponent` reads.
    let digits = number.len()
        - number
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
            .len();
    if digits == 0 {
        return Err(invalid("it does not start with a number"));
    }
    let (mantissa, places) =
        decimal_exponent(number).ok_or_else(|| invalid("it is not a number"))?;
    let scaled = match u32::try_from(places) {
        Ok(places) => {
            // Half of the divisor is added before dividing so the quotient rounds
            // to the nearest nano-CPU rather than dropping the remainder. Integer
            // division truncates, so the sign is reapplied afterwards instead of
            // being carried through the addition.
            let divisor = power_of_ten(places);
            let scaled = mantissa
                .checked_mul(1_000_000_000)
                .ok_or_else(|| invalid("it is larger than a 64-bit nano-CPU count"))?;
            (scaled + divisor / 2) / divisor
        }
        // A negative count of places is a positive exponent: the value is larger
        // than one, so there is no remainder to round away.
        Err(_) => {
            let magnitude = places
                .checked_neg()
                .and_then(|places| u32::try_from(places).ok())
                .map(power_of_ten)
                .ok_or_else(|| invalid("it is larger than a 64-bit nano-CPU count"))?;
            mantissa
                .checked_mul(magnitude)
                .and_then(|scaled| scaled.checked_mul(1_000_000_000))
                .ok_or_else(|| invalid("it is larger than a 64-bit nano-CPU count"))?
        }
    };
    i64::try_from(sign * scaled).map_err(|_| invalid("it is larger than a 64-bit nano-CPU count"))
}

/// Splits a decimal that may carry an exponent into digits and decimal places.
///
/// `1.9e-6` becomes `(19, 7)` — the same value as `0.0000019` — and `2e3`
/// becomes `(2, -3)`, a negative count of places meaning the value is that many
/// orders of magnitude larger than one. A negative `places` is the only way a
/// value above one can be described without multiplying it out first.
///
/// The exponent is *subtracted* because `places` counts how far the value is
/// divided down: multiplying by `10^e` moves the other way, and `1.9e-6` is
/// `19` divided by `10^7`, not by `10^-5`.
fn decimal_exponent(value: &str) -> Option<(i128, i32)> {
    let exponent_at = value.find(['e', 'E']);
    let (mantissa_text, exponent) = match exponent_at {
        Some(at) => (value.get(..at)?, value.get(at + 1..)?.parse::<i32>().ok()?),
        None => (value, 0),
    };
    let (mantissa, places) = decimal(mantissa_text)?;
    let places = i32::try_from(places).ok()?;
    Some((mantissa, places.checked_sub(exponent)?))
}

/// A limit Compose declares as a number, with zero normalized to "unset".
///
/// Every numeric limit in this set treats zero as "no limit", and Docker prints
/// no key for it: measured on 29.8, `mem_limit: 0`, `mem_swappiness: 0`,
/// `cpu_shares: 0`, `cpu_period: 0`, `pids_limit: 0`, and `oom_score_adj: 0` all
/// render nothing. Normalizing here is what lets a rendered document match
/// without the renderer having to know which fields carry that rule.
fn nonzero(value: i64) -> Option<i64> {
    (value != 0).then_some(value)
}

/// Reads an `oom_score_adj`, enforcing the range Compose enforces.
///
/// Measured on 29.8, `oom_score_adj: 1001` and `oom_score_adj: "-1001"` are both
/// refused and the range is -1000 through 1000.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not an integer or falls
/// outside the range.
fn parse_oom_score_adj(value: &Value, path: &str, field_path: &str) -> Result<i64, ComposeError> {
    let score = parse_service_int(value, path, field_path)?;
    if !(-1000..=1000).contains(&score) {
        return Err(compose_error(
            "compose_invalid_oom_score_adj",
            format!("oom_score_adj must be between -1000 and 1000, not {score}"),
            Some(path),
            field_path,
        ));
    }
    Ok(score)
}

/// Returns `None` for an empty scalar, so an empty value is not rendered.
///
/// Compose's own output drops every empty string in this set: measured on 29.8,
/// `cgroup_parent: ""`, `cpuset: ""`, and an empty `ipc` all render no key at
/// all. Storing `None` is what makes the rendered document match without the
/// renderer having to know which fields have that rule.
fn optional_scalar(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// Reads a string map that Compose accepts only as a mapping.
///
/// `storage_opt` is the field this exists for: measured on 29.8,
/// `storage_opt: ["size=10G"]` is refused with "must be a mapping", so accepting
/// the sequence spelling a string map normally takes would be accepting a
/// document Docker rejects.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not a mapping or holds
/// a duplicate key.
fn mapping_string_map(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let map = mapping(value, path, field_path)?;
    string_map_without_interpolation(&Value::Mapping(map.clone()), path, field_path)
}

/// Parses a `devices` list in either of Compose's two spellings.
///
/// The short form is `host:container[:permissions]` and the long form is a
/// mapping with `source`, `target`, and `permissions`. Measured against
/// `docker compose config` on 29.8, Docker fills in the two defaults itself:
/// a short entry that names only a host path gets that path as its target, and
/// every entry without permissions gets `rwm`. Both defaults are applied here so
/// the model never carries a device whose permissions the Engine would guess.
fn parse_devices(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<ComposeDevice>, ComposeError> {
    let field_path = format!("{service_path}.devices");
    let sequence = sequence(value, path, &field_path)?;
    let mut devices = Vec::new();
    for (index, item) in sequence.iter().enumerate() {
        let entry = format!("{field_path}[{index}]");
        let device = match item {
            Value::Mapping(map) => {
                reject_duplicate(map, path, &entry)?;
                let source = required_map_scalar(map, "source", path, &entry)?;
                let target = map
                    .get(Value::String("target".to_owned()))
                    .map(|value| scalar(value, path, &format!("{entry}.target")))
                    .transpose()?
                    .unwrap_or_else(|| source.clone());
                let permissions = map
                    .get(Value::String("permissions".to_owned()))
                    .map(|value| scalar(value, path, &format!("{entry}.permissions")))
                    .transpose()?
                    .unwrap_or_else(|| DEFAULT_DEVICE_PERMISSIONS.to_owned());
                ComposeDevice {
                    source,
                    target,
                    permissions,
                }
            }
            short => {
                let short = resolved_scalar(short, path, &entry, values, policy)?;
                let mut parts = short.splitn(3, ':');
                let source = parts.next().unwrap_or_default();
                let (target, permissions) = match parts.next() {
                    None => (source, DEFAULT_DEVICE_PERMISSIONS),
                    Some(target) => (target, parts.next().unwrap_or(DEFAULT_DEVICE_PERMISSIONS)),
                };
                ComposeDevice {
                    source: source.to_owned(),
                    target: target.to_owned(),
                    permissions: permissions.to_owned(),
                }
            }
        };
        if device.source.is_empty() || device.target.is_empty() {
            return Err(compose_error(
                "compose_invalid_device",
                format!("devices entry '{entry}' must name a host device"),
                Some(path),
                &entry,
            ));
        }
        devices.push(device);
    }
    Ok(devices)
}

/// The cgroup permission set Compose gives a device that names none.
///
/// Measured on 29.8: `devices: ["/dev/sda"]` prints `permissions: rwm`, and so
/// does a long-form entry with no `permissions` key.
const DEFAULT_DEVICE_PERMISSIONS: &str = "rwm";

/// Parses a `credential_spec` block.
///
/// Docker accepts any subset of the three keys and prints whichever were
/// declared, so an empty block is a valid declaration and is kept. Every value
/// is a name or a path, never the credential material itself, so nothing
/// sensitive enters the model.
fn parse_credential_spec(
    value: &Value,
    path: &str,
    service_path: &str,
) -> Result<ComposeCredentialSpec, ComposeError> {
    let field_path = format!("{service_path}.credential_spec");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut parsed = ComposeCredentialSpec::default();
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "file" => parsed.file = Some(scalar(value, path, &entry)?),
            "config" => parsed.config = Some(scalar(value, path, &entry)?),
            "registry" => parsed.registry = Some(scalar(value, path, &entry)?),
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("credential_spec field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parses a `blkio_config` block.
///
/// The five device lists share one shape — a list of `{path, …}` mappings — so
/// one reader produces all of them. The rate lists resolve their value through
/// the size table, because Compose accepts a size suffix on all four of them
/// including the `iops` ones: measured on 29.8,
/// `device_read_iops: [{path: /dev/sda, rate: 12m}]` prints `rate: "12582912"`.
///
/// The two weights are the exception: Compose types them as a `uint16` and
/// refuses a quoted one, so they are read as YAML numbers and are not run
/// through the scalar reader that accepts both spellings.
fn parse_blkio_config(
    value: &Value,
    path: &str,
    service_path: &str,
) -> Result<ComposeBlkioConfig, ComposeError> {
    let field_path = format!("{service_path}.blkio_config");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut parsed = ComposeBlkioConfig::default();
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "weight" => {
                let weight = yaml_weight(value, path, &entry)?;
                parsed.weight = Some(weight);
            }
            "weight_device" => {
                parsed.weight_device = parse_blkio_weights(value, path, &entry)?;
            }
            "device_read_bps" => {
                parsed.device_read_bps = parse_blkio_rates(value, path, &entry)?;
            }
            "device_read_iops" => {
                parsed.device_read_iops = parse_blkio_rates(value, path, &entry)?;
            }
            "device_write_bps" => {
                parsed.device_write_bps = parse_blkio_rates(value, path, &entry)?;
            }
            "device_write_iops" => {
                parsed.device_write_iops = parse_blkio_rates(value, path, &entry)?;
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("blkio_config field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Reads a YAML number, refusing a quoted string.
///
/// Used for the two `blkio_config` weights, which Compose types as `uint16`:
/// measured on 29.8, `blkio_config: {weight: "300"}` is refused with "expected
/// type 'uint16', got unconvertible type 'string'" while `weight: 300` is
/// accepted.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is not a whole number in
/// the `uint16` range.
fn yaml_weight(value: &Value, path: &str, field_path: &str) -> Result<u16, ComposeError> {
    let number = value.as_i64().ok_or_else(|| {
        compose_error(
            "compose_invalid_blkio_weight",
            format!("'{field_path}' must be a whole number, not a string"),
            Some(path),
            field_path,
        )
    })?;
    u16::try_from(number).map_err(|_| {
        compose_error(
            "compose_invalid_blkio_weight",
            format!("'{field_path}' must be between 0 and 65535, not {number}"),
            Some(path),
            field_path,
        )
    })
}

/// Reads a `blkio_config` weight list, in the Engine's `{path, weight}` shape.
fn parse_blkio_weights(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<Vec<ComposeBlkioDevice>, ComposeError> {
    let sequence = sequence(value, path, field_path)?;
    let mut devices = Vec::new();
    for (index, item) in sequence.iter().enumerate() {
        let entry = format!("{field_path}[{index}]");
        let map = mapping(item, path, &entry)?;
        reject_duplicate(map, path, &entry)?;
        let mut path_name = None;
        let mut weight = None;
        for (key, value) in map {
            let key = scalar_key(key, path, &entry)?;
            match key.as_str() {
                "path" => {
                    path_name = Some(required_map_scalar(map, "path", path, &entry)?);
                }
                "weight" => weight = Some(yaml_weight(value, path, &format!("{entry}.weight"))?),
                _ if key.starts_with("x-") => {}
                _ => {
                    return Err(compose_error(
                        "compose_unsupported_field",
                        format!(
                            "blkio_config weight entry field '{key}' is outside the supported \
                             Compose model"
                        ),
                        Some(path),
                        &format!("{entry}.{key}"),
                    ));
                }
            }
        }
        devices.push(ComposeBlkioDevice {
            path: path_name.unwrap_or_default(),
            value: i64::from(weight.unwrap_or_default()),
        });
    }
    Ok(devices)
}

/// Reads a `blkio_config` rate list, in the Engine's `{path, rate}` shape.
///
/// The rate goes through the one size table, because a Compose rate is written
/// with a size suffix on every one of the four rate lists.
fn parse_blkio_rates(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<Vec<ComposeBlkioDevice>, ComposeError> {
    let sequence = sequence(value, path, field_path)?;
    let mut devices = Vec::new();
    for (index, item) in sequence.iter().enumerate() {
        let entry = format!("{field_path}[{index}]");
        let map = mapping(item, path, &entry)?;
        reject_duplicate(map, path, &entry)?;
        let mut path_name = None;
        let mut rate = None;
        for (key, value) in map {
            let key = scalar_key(key, path, &entry)?;
            match key.as_str() {
                "path" => {
                    path_name = Some(required_map_scalar(map, "path", path, &entry)?);
                }
                "rate" => {
                    let slot = format!("{entry}.rate");
                    rate = Some(parse_size_bytes(&scalar(value, path, &slot)?, &slot, path)?);
                }
                _ if key.starts_with("x-") => {}
                _ => {
                    return Err(compose_error(
                        "compose_unsupported_field",
                        format!(
                            "blkio_config rate entry field '{key}' is outside the supported \
                             Compose model"
                        ),
                        Some(path),
                        &format!("{entry}.{key}"),
                    ));
                }
            }
        }
        devices.push(ComposeBlkioDevice {
            path: path_name.unwrap_or_default(),
            value: rate.unwrap_or_default(),
        });
    }
    Ok(devices)
}

/// One `extends` declaration, before it is applied.
struct ComposeExtends {
    /// Name of the service being inherited from, or a placeholder for the inline
    /// spelling, which names no other service.
    service: String,
    /// The Compose file that declares the base service.
    file: Option<String>,
    /// The base service's own fields, for the inline spelling.
    inline: Option<Mapping>,
}

/// Reads an `extends` declaration.
///
/// Three spellings reach here, and only one of them needs a second source:
///
/// - `service: <name>`, naming a service in this same document;
/// - `service: {<fields>}`, the specification's inline spelling, which puts the
///   base service's own fields directly in the document;
/// - `file: <path>` together with `service: <name>`, naming another Compose file.
///
/// The first two are resolved in this crate. The third is refused, for the same
/// reason `env_file`, `label_file`, and `include` are: a Compose file named inside
/// another one is a host read, and this crate does not perform a read a document
/// asked for on its own. See [`resolve_extends`].
///
/// Measured on 29.8, Docker accepts the first and third spellings and refuses the
/// second with `extends.app.service is required`. The inline spelling is still
/// read here: the Compose specification defines it, it needs no host read, and a
/// loader that exists to accept the specification should not refuse a documented
/// form because one implementation's schema has not caught up.
fn parse_extends_declaration(
    value: &Value,
    path: &str,
    service_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<ComposeExtends, ComposeError> {
    let field_path = format!("{service_path}.extends");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut service = None;
    let mut file = None;
    let mut inline = None;
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "service" => match value {
                Value::String(name) => {
                    let name = resolved_text(name, path, &entry, values, policy)?;
                    validate_service_name(&name, path, &entry)?;
                    service = Some(name);
                }
                Value::Mapping(fields) => {
                    reject_duplicate(fields, path, &entry)?;
                    // The inline spelling has no name to read: the fields are the
                    // base service's, and the service that inherits them is the
                    // one this declaration is attached to. The placeholder name
                    // only ever appears in the file-form diagnostic.
                    inline = Some(fields.clone());
                    service = Some("base".to_owned());
                }
                _ => {
                    return Err(compose_error(
                        "compose_invalid_extends",
                        "extends service must be a name or an inline service declaration",
                        Some(path),
                        &entry,
                    ));
                }
            },
            "file" => {
                file = Some(resolved_scalar(value, path, &entry, values, policy)?);
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("extends field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    let Some(service) = service else {
        return Err(compose_error(
            "compose_invalid_extends",
            "extends must name the service it inherits from",
            Some(path),
            &field_path,
        ));
    };
    Ok(ComposeExtends {
        service,
        file,
        inline,
    })
}

/// Applies every `extends` declaration in one document.
///
/// Docker does not render an `extends` key: it renders the fields the base
/// service contributed, so a model that kept the declaration would produce a
/// service missing everything the base declared. The declaration is therefore
/// applied here and does not survive into the model. The base service itself is
/// left in the document, which is also what Docker does — an `extends` is not a
/// reference that removes the thing it points at.
///
/// A base named in this same document and an inline base are both applied in
/// full, because neither needs a second source. A base named in another file is
/// refused rather than silently ignored; the refusal names the field so the
/// caller can put the base service in the same document instead.
fn resolve_extends(
    services: &mut BTreeMap<String, ComposeProjectService>,
    declarations: Vec<(String, ComposeExtends)>,
    path: &str,
    values: &InterpolationValues,
    options: &ComposeProjectOptions,
) -> Result<(), ComposeError> {
    reject_extends_cycles(&declarations, path)?;
    for (name, extends) in declarations {
        let service_path = format!("$.services.{name}.extends");
        let mut base = match (&extends.file, &extends.inline) {
            (Some(file), _) => {
                return Err(compose_error(
                    "compose_extends_requires_explicit_loader",
                    format!(
                        "service '{name}' extends service '{}' from '{file}'; a file the \
                         document did not name is never read",
                        extends.service
                    ),
                    Some(path),
                    &service_path,
                ));
            }
            // The base is re-read through the ordinary service reader, so an
            // inline base gets the same parsing, the same validation, and the
            // same normalization as a service written at the top level.
            (None, Some(fields)) => {
                inline_base_service(&name, fields, path, values, options, &service_path)?
            }
            (None, None) => services.get(&extends.service).cloned().ok_or_else(|| {
                compose_error(
                    "compose_unknown_extends_service",
                    format!(
                        "service '{name}' extends service '{}', which this document does not \
                         declare",
                        extends.service
                    ),
                    Some(path),
                    &service_path,
                )
            })?,
        };
        let Some(current) = services.get(&name).cloned() else {
            continue;
        };
        // The base is the thing being merged *over*: the extending service's own
        // fields win, which is the rule Docker applies and the reason an override
        // can narrow what it inherits. Measured on 29.8, a service that extends a
        // base declaring `SHARED=1` and that itself declares `OWN=1` prints both.
        merge_service(&mut base, current);
        // The declaration itself is not a field of the merged service, and
        // leaving it in the declared set would let a later merge think a second
        // file set an `extends` key that no longer exists.
        base.declared.remove("extends");
        services.insert(name, base);
    }
    Ok(())
}

/// Refuses a chain of `extends` that loops back on itself.
///
/// Two services extending each other has no base, and resolving it in place
/// would produce a service that silently holds whichever declaration was applied
/// first. The walk is bounded by the number of declarations rather than by a
/// fixed depth so a long, legitimate chain is not mistaken for a loop.
fn reject_extends_cycles(
    declarations: &[(String, ComposeExtends)],
    path: &str,
) -> Result<(), ComposeError> {
    let bases = declarations
        .iter()
        .filter(|(_, extends)| extends.file.is_none() && extends.inline.is_none())
        .map(|(name, extends)| (name.as_str(), extends.service.as_str()))
        .collect::<BTreeMap<_, _>>();
    for start in bases.keys() {
        let start = *start;
        let mut current = start;
        for _ in 0..bases.len() {
            let Some(next) = bases.get(current) else {
                break;
            };
            if *next == start {
                return Err(compose_error(
                    "compose_extends_cycle",
                    format!("service '{start}' extends itself through '{current}'"),
                    Some(path),
                    &format!("$.services.{start}.extends"),
                ));
            }
            current = next;
        }
    }
    Ok(())
}

/// Reads an inline `extends` base as a normalized service.
///
/// The base is wrapped in a one-service document and handed to the ordinary
/// service reader rather than being parsed field by field here, so there is one
/// implementation of "what a service key means" in this crate. The wrapper's
/// service name is the extending service's, which keeps diagnostics pointed at
/// the service the author wrote.
fn inline_base_service(
    name: &str,
    fields: &Mapping,
    path: &str,
    values: &InterpolationValues,
    options: &ComposeProjectOptions,
    service_path: &str,
) -> Result<ComposeProjectService, ComposeError> {
    let mut wrapper = Mapping::new();
    wrapper.insert(
        Value::String(name.to_owned()),
        Value::Mapping(fields.clone()),
    );
    parse_services(&Value::Mapping(wrapper), path, values, options)?
        .remove(name)
        .ok_or_else(|| {
            compose_error(
                "compose_invalid_extends",
                format!("service '{name}' has an empty extends declaration"),
                Some(path),
                service_path,
            )
        })
}

/// Parses a `deploy` declaration down to the parts that mean something here.
///
/// The Swarm-only keys are accepted and not interpreted, because the same
/// document has to load for `compose up` and for `stack deploy`; refusing
/// `placement` here would make a valid stack file unusable for a local run.
fn parse_deploy(
    value: &Value,
    path: &str,
    service_path: &str,
) -> Result<ComposeDeploy, ComposeError> {
    let field_path = format!("{service_path}.deploy");
    let map = mapping(value, path, &field_path)?;
    reject_duplicate(map, path, &field_path)?;
    let mut parsed = ComposeDeploy::default();
    for (key, value) in map {
        let key = scalar_key(key, path, &field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "replicas" => {
                let count = scalar(value, path, &entry)?;
                parsed.replicas = Some(count.trim().parse::<u32>().map_err(|_| {
                    compose_error(
                        "compose_invalid_deploy",
                        "deploy replicas must be a whole number",
                        Some(path),
                        &entry,
                    )
                })?);
            }
            "replace" => {
                parsed.replace = parse_bool(value, path, service_path, "replace")?;
            }
            "resources" => {
                let resources = mapping(value, path, &entry)?;
                reject_duplicate(resources, path, &entry)?;
                for (key, value) in resources {
                    let key = scalar_key(key, path, &entry)?;
                    let slot = format!("{entry}.{key}");
                    // Limits and reservations are both a map of resource name to
                    // value. The values stay as written here; turning `cpus: 0.5`
                    // into a nano-cpu count belongs to the layer that knows what
                    // the Engine accepts, and a wrong guess made at parse time
                    // would be baked into the digest.
                    let values = string_map_without_interpolation(value, path, &slot)?;
                    match key.as_str() {
                        "limits" => parsed.limits = values,
                        "reservations" => parsed.reservations = values,
                        _ if key.starts_with("x-") => {}
                        _ => {
                            return Err(compose_error(
                                "compose_unsupported_field",
                                format!(
                                    "deploy resources field '{key}' is outside the supported Compose model"
                                ),
                                Some(path),
                                &slot,
                            ));
                        }
                    }
                }
            }
            "mode" => {
                parsed.mode = Some(match scalar(value, path, &entry)?.as_str() {
                    "global" => ComposeDeployMode::Global,
                    // Compose's default is `replicated`, and a document that spells
                    // it out means the same thing as one that does not.
                    "replicated" | "" => ComposeDeployMode::Replicated,
                    other => {
                        return Err(compose_error(
                            "compose_invalid_deploy_mode",
                            format!("deploy mode must be 'global' or 'replicated', not '{other}'"),
                            Some(path),
                            &entry,
                        ));
                    }
                });
            }
            "labels" => {
                parsed.labels = string_map_without_interpolation(value, path, &entry)?;
            }
            "placement" => {
                parsed.placement = Some(parse_placement(value, path, &entry)?);
            }
            "update_config" => {
                parsed.update_config = Some(parse_update_config(value, path, &entry)?);
            }
            "rollback_config" => {
                parsed.rollback_config = Some(parse_update_config(value, path, &entry)?);
            }
            "endpoint_mode" => {
                let mode = scalar(value, path, &entry)?;
                if !matches!(mode.as_str(), "vip" | "dnsrr") {
                    return Err(compose_error(
                        "compose_invalid_endpoint_mode",
                        format!("endpoint_mode must be 'vip' or 'dnsrr', not '{mode}'"),
                        Some(path),
                        &entry,
                    ));
                }
                parsed.endpoint_mode = Some(mode);
            }
            "restart_policy" => {
                // The `restart_policy:` *value* is the same shape a service's
                // `restart:` takes, so the same reader applies. The only extra
                // keys Swarm adds are the retry timing ones, read below.
                let policy = parse_restart(
                    value,
                    path,
                    &format!("{service_path}.deploy"),
                    &InterpolationValues::new(),
                )?;
                parsed.restart_policy = Some(policy);
                if let Value::Mapping(map) = value {
                    for (key, value) in map {
                        let key = scalar_key(key, path, &entry)?;
                        let slot = format!("{entry}.{key}");
                        match key.as_str() {
                            "delay" => {
                                parsed.restart_delay = Some(parse_duration_nanos(
                                    &scalar(value, path, &slot)?,
                                    &slot,
                                    path,
                                )?);
                            }
                            "window" => {
                                parsed.restart_window = Some(parse_duration_nanos(
                                    &scalar(value, path, &slot)?,
                                    &slot,
                                    path,
                                )?);
                            }
                            "failure_action" => {
                                parsed.restart_failure_action = Some(scalar(value, path, &slot)?);
                            }
                            "condition" | "max_attempts" => {}
                            _ if key.starts_with("x-") => {}
                            _ => {
                                return Err(compose_error(
                                    "compose_unsupported_field",
                                    format!(
                                        "restart_policy field '{key}' is outside the supported \
                                         Compose model"
                                    ),
                                    Some(path),
                                    &slot,
                                ));
                            }
                        }
                    }
                }
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("deploy field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parses a `placement` block into node constraints and preferences.
///
/// A constraint is a Swarm expression such as `node.role == worker`, and the
/// Engine takes these as free-form strings, so they are carried verbatim. Parsing
/// the expression here would mean owning Swarm's grammar, and a document that
/// used a feature this crate has not seen would be refused for a reason the
/// author could not act on.
fn parse_placement(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<ComposePlacement, ComposeError> {
    let map = mapping(value, path, field_path)?;
    reject_duplicate(map, path, field_path)?;
    let mut parsed = ComposePlacement::default();
    for (key, value) in map {
        let key = scalar_key(key, path, field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "constraints" => {
                parsed.constraints = parse_path_list(
                    value,
                    path,
                    &entry,
                    &InterpolationValues::new(),
                    InterpolationPolicy::default(),
                )?;
            }
            "preferences" => {
                parsed.preferences = parse_path_list(
                    value,
                    path,
                    &entry,
                    &InterpolationValues::new(),
                    InterpolationPolicy::default(),
                )?;
            }
            "max_replicas_per_node" => {
                let count = scalar(value, path, &entry)?;
                parsed.max_replicas_per_node = count.trim().parse::<u32>().map_err(|_| {
                    compose_error(
                        "compose_invalid_placement",
                        "max_replicas_per_node must be a whole number",
                        Some(path),
                        &entry,
                    )
                })?;
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("placement field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parses an `update_config` or `rollback_config` block.
fn parse_update_config(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<ComposeUpdateConfig, ComposeError> {
    let map = mapping(value, path, field_path)?;
    reject_duplicate(map, path, field_path)?;
    let mut parsed = ComposeUpdateConfig::default();
    for (key, value) in map {
        let key = scalar_key(key, path, field_path)?;
        let entry = format!("{field_path}.{key}");
        match key.as_str() {
            "parallelism" => {
                let count = scalar(value, path, &entry)?;
                parsed.parallelism = Some(count.trim().parse::<u32>().map_err(|_| {
                    compose_error(
                        "compose_invalid_update_config",
                        "parallelism must be a whole number",
                        Some(path),
                        &entry,
                    )
                })?);
            }
            "delay" => {
                let duration = scalar(value, path, &entry)?;
                parse_duration_nanos(&duration, &entry, path)?;
                parsed.delay = parse_duration_nanos(&duration, &entry, path).ok();
            }
            "failure_action" => {
                let action = scalar(value, path, &entry)?;
                if !matches!(action.as_str(), "pause" | "continue" | "rollback") {
                    return Err(compose_error(
                        "compose_invalid_update_config",
                        format!(
                            "failure_action must be 'pause', 'continue', or 'rollback', \
                             not '{action}'"
                        ),
                        Some(path),
                        &entry,
                    ));
                }
                parsed.failure_action = Some(action);
            }
            "max_failure_ratio" => {
                parsed.max_failure_ratio = Some(scalar(value, path, &entry)?);
            }
            "order" => {
                let order = scalar(value, path, &entry)?;
                if !matches!(order.as_str(), "stop-first" | "start-first") {
                    return Err(compose_error(
                        "compose_invalid_update_config",
                        format!("order must be 'stop-first' or 'start-first', not '{order}'"),
                        Some(path),
                        &entry,
                    ));
                }
                parsed.order = Some(order);
            }
            "monitor" | "failure_delay" => {
                // Timing knobs the Engine accepts and this slice does not yet
                // apply. They are read and ignored rather than refused, because a
                // document that also sets `order` and `parallelism` should deploy
                // with those honored.
            }
            _ if key.starts_with("x-") => {}
            _ => {
                return Err(compose_error(
                    "compose_unsupported_field",
                    format!("update_config field '{key}' is outside the supported Compose model"),
                    Some(path),
                    &entry,
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parses a Compose duration into nanoseconds.
///
/// Public because the container-create layer needs the same reading of the same
/// spelling: two copies of this table would disagree about `1m30s`, and the
/// disagreement would only show up as a container with a surprising timeout.
///
/// Docker spells these as a number followed by a unit, with `us`, `ms`, `s`, `m`,
/// and `h` and a Go duration string also accepted. A bare number is seconds,
/// which is Docker's own reading and the one a document written by hand usually
/// means. The parser is here rather than in the container-create layer because a
/// malformed duration has to be reported against the field that holds it.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value is empty, does not begin
/// with a number, carries a unit that is not one of `ns`, `us`, `ms`, `s`, `m`,
/// or `h`, or totals more nanoseconds than a 64-bit integer holds.
pub fn parse_duration_nanos(
    value: &str,
    field_path: &str,
    path: &str,
) -> Result<i64, ComposeError> {
    let invalid = |reason: &str| {
        compose_error(
            "compose_invalid_duration",
            format!("'{value}' is not a duration: {reason}"),
            Some(path),
            field_path,
        )
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid("it is empty"));
    }
    // A Go duration may be a sum, such as `1m30s`, so the terms are accumulated
    // rather than the string being rejected for carrying two units.
    let mut total: i128 = 0;
    let mut rest = trimmed;
    let mut saw_term = false;
    while !rest.is_empty() {
        let digits = rest.len()
            - rest
                .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
                .len();
        if digits == 0 {
            return Err(invalid("it does not start with a number"));
        }
        let (number, tail) = rest.split_at(digits);
        let tail = tail.trim_start();
        let (unit, remainder) = split_duration_unit(tail);
        // Integer arithmetic throughout. A Compose duration is a decimal number of
        // a power-of-ten unit, so a float would only add a rounding step between
        // the two, and `0.5ms` becoming 499999ns is a bug this avoids by
        // construction rather than by luck.
        let (mantissa, places) = decimal(number).ok_or_else(|| invalid("it is not a number"))?;
        let multiplier: i128 = match unit.as_str() {
            "ns" => 1,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            // A bare number is seconds, which is Docker's own reading and why the
            // empty unit is in this table rather than an error.
            "s" | "" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(invalid("its unit is not one of ns, us, ms, s, m, h")),
        };
        let scaled = mantissa
            .checked_mul(multiplier)
            .ok_or_else(|| invalid("it is larger than a 64-bit nanosecond count"))?;
        let term = scaled / power_of_ten(places);
        total = total
            .checked_add(term)
            .ok_or_else(|| invalid("it is larger than a 64-bit nanosecond count"))?;
        saw_term = true;
        rest = remainder.trim_start();
    }
    if !saw_term {
        return Err(invalid("it is empty"));
    }
    i64::try_from(total).map_err(|_| invalid("it is larger than a 64-bit nanosecond count"))
}

/// Splits a decimal into its integer digits and its count of decimal places.
///
/// `1.5` becomes `(15, 1)`: the value is `mantissa / 10^places`. Keeping the two
/// parts rather than a single scaled integer is what lets a caller apply a
/// multiplier that is not a power of ten — a binary size unit, say — without the
/// decimal places being lost.
fn decimal(value: &str) -> Option<(i128, u32)> {
    if value.is_empty() || value.matches('.').count() > 1 {
        return None;
    }
    let digits: String = value
        .chars()
        .filter(|character| *character != '.')
        .collect();
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    // The places are the digits *after* the point, not the characters removed by
    // taking the point out: `1.25` is `125 / 10^2`, and reading it as
    // `125 / 10^1` would make every size and duration with two decimal places
    // ten times too large.
    let places = match value.split_once('.') {
        Some((_, fraction)) => u32::try_from(fraction.len()).ok()?,
        None => 0,
    };
    // Leading zeros are harmless to strip and keep the `parse` from being the one
    // that overflows on a value like `00000000000000000000000001`.
    let trimmed = digits.trim_start_matches('0');
    let mantissa = if trimmed.is_empty() {
        0
    } else {
        trimmed.parse::<i128>().ok()?
    };
    Some((mantissa, places))
}

/// Ten to a small power, for the decimal places a value carried.
fn power_of_ten(places: u32) -> i128 {
    10_i128.checked_pow(places).unwrap_or(i128::MAX)
}

/// Splits a duration's unit from the rest of the string.
fn split_duration_unit(tail: &str) -> (String, &str) {
    for unit in ["ns", "us", "µs", "ms", "s", "m", "h"] {
        if let Some(rest) = tail.strip_prefix(unit) {
            return (unit.to_owned(), rest);
        }
    }
    // No unit at all is seconds, which is why the empty case is in the
    // multiplier table rather than an error.
    (String::new(), tail)
}

/// Parses a size in bytes.
///
/// Public for the same reason as []: one table, so a size
/// means the same thing everywhere it is read.
///
/// Compose writes these as a number with an optional binary unit — `k`, `m`, `g`
/// are powers of 1024, which is Docker's reading — and a bare number is bytes.
///
/// # Errors
///
/// Returns an error naming `field_path` when the value does not begin with a
/// number, carries a unit that is not one of `b`, `k`, `m`, `g`, `t`, or `p`, is
/// negative, or totals more bytes than a 64-bit integer holds.
pub fn parse_size_bytes(value: &str, field_path: &str, path: &str) -> Result<i64, ComposeError> {
    let invalid = |reason: &str| {
        compose_error(
            "compose_invalid_size",
            format!("'{value}' is not a size: {reason}"),
            Some(path),
            field_path,
        )
    };
    let trimmed = value.trim();
    let digits = trimmed
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .len();
    if digits == 0 {
        return Err(invalid("it does not start with a number"));
    }
    let (number, suffix) = trimmed.split_at(digits);
    let (mantissa, places) = decimal(number).ok_or_else(|| invalid("it is not a number"))?;
    // `k`, `m`, and `g` are powers of 1024 — Compose's reading, not SI's — so the
    // multiplier is a binary one and the division by the decimal places comes
    // after the multiplication. Doing it the other way round would round `1.5k`
    // to 1500 bytes, and the truncation that leaves is sub-byte precision nobody
    // asks a container for.
    let mut multiplier: i128 = 1;
    for _ in 0..match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" => 1,
        "m" | "mb" => 2,
        "g" | "gb" => 3,
        "t" | "tb" => 4,
        "p" | "pb" => 5,
        _ => return Err(invalid("its unit is not one of b, k, m, g, t, p")),
    } {
        multiplier = multiplier
            .checked_mul(1024)
            .ok_or_else(|| invalid("it is larger than a 64-bit byte count"))?;
    }
    let scaled = mantissa
        .checked_mul(multiplier)
        .ok_or_else(|| invalid("it is larger than a 64-bit byte count"))?;
    let bytes = scaled / power_of_ten(places);
    i64::try_from(bytes).map_err(|_| invalid("it is larger than a 64-bit byte count"))
}

/// Parses an `expose` list, keeping each entry as the document wrote it.
///
/// Not normalized to `port/tcp`, which is what this did: measured on Docker
/// 29.8, `docker compose config` and `docker stack config` both print `expose:
/// ["9000"]` for `- 9000` and `expose: [9001/udp]` for `- 9001/udp`. A protocol
/// the document did not write is a key the rendered document would be asserting
/// on its own, and a reader comparing the two outputs is comparing spellings.
///
/// The value is still a validated port range, because a rendered document is meant
/// to be loadable and `expose: nonsense` is not.
fn parse_port_list(
    value: &Value,
    path: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<String>, ComposeError> {
    parse_path_list(value, path, field_path, values, policy)
}

/// Parses `extra_hosts` into the Engine's `name=value` spelling.
///
/// Compose documents write `name:address`, and the Engine wants `name=address`.
/// The colon spelling is what every example on the internet uses, so accepting
/// only the equals sign would be refusing the documented form.
fn parse_extra_hosts(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<Vec<String>, ComposeError> {
    let entries = match value {
        Value::String(single) => vec![single.clone()],
        Value::Sequence(items) => items
            .iter()
            .map(|item| scalar(item, path, field_path))
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(compose_error(
                "compose_invalid_extra_hosts",
                "expected a host entry or a list of host entries",
                Some(path),
                field_path,
            ));
        }
    };
    let mut hosts = Vec::new();
    for entry in entries {
        let entry = entry.trim().to_owned();
        if entry.is_empty() {
            return Err(compose_error(
                "compose_invalid_extra_hosts",
                "an extra_hosts entry must not be empty",
                Some(path),
                field_path,
            ));
        }
        // The first separator wins, so an IPv6 literal — which has colons of its
        // own — still splits into a name and an address rather than into three
        // pieces.
        let separator = if entry.contains('=') { '=' } else { ':' };
        let Some((name, address)) = entry.split_once(separator) else {
            return Err(compose_error(
                "compose_invalid_extra_hosts",
                format!("extra_hosts entry '{entry}' must be written as 'name{separator}address'"),
                Some(path),
                field_path,
            ));
        };
        if name.is_empty() || address.is_empty() {
            return Err(compose_error(
                "compose_invalid_extra_hosts",
                format!("extra_hosts entry '{entry}' must name both a host and an address"),
                Some(path),
                field_path,
            ));
        }
        hosts.push(format!("{name}={address}"));
    }
    Ok(hosts)
}

/// Parses a service's `profiles` declaration.
///
/// Compose requires a list of strings here. A bare scalar is rejected, and so
/// is a non-string entry, because a profile name is something a person types on
/// a command line and `1` is not a name anybody can pass to `--profile`.
/// Interpolation still applies, so a document may parameterize the name the
/// same way it parameterizes anything else.
fn parse_profiles(
    value: &Value,
    source: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<Vec<String>, ComposeError> {
    let Value::Sequence(entries) = value else {
        return Err(compose_error(
            "compose_invalid_profiles",
            "profiles must be a list of profile names",
            Some(source),
            field_path,
        ));
    };
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let Value::String(name) = entry else {
                return Err(compose_error(
                    "compose_invalid_profile",
                    "a profile name must be a string",
                    Some(source),
                    &format!("{field_path}[{index}]"),
                ));
            };
            resolved_text(name, source, field_path, values, policy)
        })
        .collect()
}

fn parse_string_map(
    value: &Value,
    path: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let mut result = BTreeMap::new();
    let mut insert = |key: String, value: String| -> Result<(), ComposeError> {
        if result.insert(key.clone(), value).is_some() {
            return Err(compose_error(
                "compose_duplicate_key",
                format!("duplicate string map key '{key}'"),
                Some(path),
                field_path,
            ));
        }
        Ok(())
    };
    match value {
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, field_path)?;
            for (key, value) in mapping {
                let key = resolved_text(
                    &scalar_key(key, path, field_path)?,
                    path,
                    field_path,
                    values,
                    policy,
                )?;
                let value =
                    resolved_scalar(value, path, &format!("{field_path}.{key}"), values, policy)?;
                insert(key, value)?;
            }
        }
        Value::Sequence(entries) => {
            for entry in entries {
                let (key, value) = string_map_sequence_entry(entry, path, field_path)?;
                // Both halves are interpolated: a Compose author may parameterize
                // the name as readily as the value.
                let key = resolved_text(&key, path, field_path, values, policy)?;
                let value =
                    resolved_text(&value, path, &format!("{field_path}.{key}"), values, policy)?;
                insert(key, value)?;
            }
        }
        _ => return Err(string_map_type_error(path, field_path)),
    }
    Ok(result)
}

fn string_map_without_interpolation(
    value: &Value,
    path: &str,
    field_path: &str,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let mut result = BTreeMap::new();
    let mut insert = |key: String, value: String| -> Result<(), ComposeError> {
        if result.insert(key.clone(), value).is_some() {
            return Err(compose_error(
                "compose_duplicate_key",
                format!("duplicate string map key '{key}'"),
                Some(path),
                field_path,
            ));
        }
        Ok(())
    };
    match value {
        Value::Mapping(mapping) => {
            reject_duplicate(mapping, path, field_path)?;
            for (key, value) in mapping {
                insert(
                    scalar_key(key, path, field_path)?,
                    scalar(value, path, field_path)?,
                )?;
            }
        }
        Value::Sequence(entries) => {
            for entry in entries {
                let (key, value) = string_map_sequence_entry(entry, path, field_path)?;
                insert(key, value)?;
            }
        }
        _ => return Err(string_map_type_error(path, field_path)),
    }
    Ok(result)
}

fn parse_bool(
    value: &Value,
    _path: &str,
    field_path: &str,
    _name: &str,
) -> Result<bool, ComposeError> {
    value
        .as_bool()
        .or_else(|| {
            value.as_str().and_then(|value| match value {
                "true" | "True" | "TRUE" | "yes" | "on" => Some(true),
                "false" | "False" | "FALSE" | "no" | "off" => Some(false),
                _ => None,
            })
        })
        .ok_or_else(|| {
            compose_error(
                "compose_invalid_boolean",
                "expected a boolean value",
                None,
                field_path,
            )
        })
}

fn parse_protocol(
    value: &str,
    path: &str,
    field_path: &str,
) -> Result<ComposePortProtocol, ComposeError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(ComposePortProtocol::Tcp),
        "udp" => Ok(ComposePortProtocol::Udp),
        "sctp" => Ok(ComposePortProtocol::Sctp),
        _ => Err(compose_error(
            "compose_invalid_port_protocol",
            "port protocol must be tcp, udp, or sctp",
            Some(path),
            field_path,
        )),
    }
}

fn parse_port_number(value: &str, path: &str, field_path: &str) -> Result<u16, ComposeError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            compose_error(
                "compose_invalid_port",
                "port must be an integer between 1 and 65535",
                Some(path),
                field_path,
            )
        })
}

fn parse_short_port(
    value: &str,
    path: &str,
    field_path: &str,
) -> Result<ComposePort, ComposeError> {
    let (address, protocol) = value
        .rsplit_once('/')
        .map_or((value, "tcp"), |(address, protocol)| (address, protocol));
    let protocol = parse_protocol(protocol, path, field_path)?;
    let (host_ip, published, target) = if let Some(value) = address.strip_prefix('[') {
        let end = value.find(']').ok_or_else(|| {
            compose_error(
                "compose_invalid_port",
                "bracketed IPv6 host address is not closed",
                Some(path),
                field_path,
            )
        })?;
        let host = &value[..end];
        let remainder = &value[end + 1..];
        let target = remainder.strip_prefix(':').ok_or_else(|| {
            compose_error(
                "compose_invalid_port",
                "IPv6 port mapping requires a target port",
                Some(path),
                field_path,
            )
        })?;
        (Some(host.to_owned()), None, target)
    } else if let Some((left, right)) = address.rsplit_once(':') {
        if left.is_empty() {
            return Err(compose_error(
                "compose_invalid_port",
                "port mapping contains an empty host component",
                Some(path),
                field_path,
            ));
        }
        if let Some((host_ip, published)) = left.rsplit_once(':') {
            (Some(host_ip.to_owned()), Some(published), right)
        } else if left.chars().all(|character| character.is_ascii_digit()) {
            (None, Some(left), right)
        } else {
            (Some(left.to_owned()), None, right)
        }
    } else {
        (None, None, address)
    };
    Ok(ComposePort {
        target: parse_port_number(target, path, field_path)?,
        published: published
            .map(|value| parse_port_number(value, path, field_path))
            .transpose()?,
        protocol,
        // The short form has no spelling for a mode, and Compose's default is the
        // one a short form means.
        mode: ComposePortMode::Ingress,
        host_ip,
    })
}

fn parse_mount_kind(
    value: &str,
    path: &str,
    field_path: &str,
) -> Result<ComposeMountKind, ComposeError> {
    match value.to_ascii_lowercase().as_str() {
        "bind" => Ok(ComposeMountKind::Bind),
        "volume" => Ok(ComposeMountKind::Volume),
        "tmpfs" => Ok(ComposeMountKind::Tmpfs),
        _ => Err(compose_error(
            "compose_invalid_mount_type",
            "mount type must be bind, volume, or tmpfs",
            Some(path),
            field_path,
        )),
    }
}

fn parse_short_mount(
    value: &str,
    _path: &str,
    _field_path: &str,
) -> Result<ComposeMount, ComposeError> {
    let [first, second, third] = split_short_mount(value);
    let first = first.unwrap_or_default();
    let (source, target, read_only) = match (second, third) {
        (Some(target), None) => {
            let target = target.to_owned();
            if target.is_empty() {
                (None, target, false)
            } else {
                (Some(first.to_owned()), target, false)
            }
        }
        (Some(target), Some(options)) => {
            let options = options.split(',').collect::<Vec<_>>();
            let read_only = options.contains(&"ro");
            (Some(first.to_owned()), target.to_owned(), read_only)
        }
        (None, _) => (None, first.to_owned(), false),
    };
    let kind = if target_is_path(&target) && source.as_deref().is_some_and(is_host_path) {
        ComposeMountKind::Bind
    } else {
        ComposeMountKind::Volume
    };
    Ok(ComposeMount {
        kind,
        source,
        target,
        read_only,
        // The short spelling has no sub-mapping to write, and Compose synthesizes
        // an empty one: measured on 29.8, `- shortvol:/data` renders as
        // `volume: {}` and `- /tmp:/mnt` as `bind: {}`. Recorded as written, so
        // the specification renderer prints what Compose prints; `short_form` is
        // what tells the v3 renderer to leave it out again.
        subtree: Some(match kind {
            ComposeMountKind::Bind => ComposeMountSubtree::Bind(ComposeBindOptions::default()),
            ComposeMountKind::Volume => {
                ComposeMountSubtree::Volume(ComposeVolumeOptions::default())
            }
            ComposeMountKind::Tmpfs => ComposeMountSubtree::Tmpfs(ComposeTmpfsOptions::default()),
        }),
        short_form: true,
    })
}

/// Splits a short-syntax mount into its `source`, `target`, and `options`.
///
/// The fields are separated by `:`, but a Windows drive letter's `:` is not a
/// separator: `C:\data:/data` is the standard Windows spelling of a bind of the
/// host's `C:\data`, and splitting on every colon read it as the volume `C`
/// mounted at `\data`. Measured on this host, before the drive was recognized,
/// that document produced `type: volume / source: C / target: \data`. Docker
/// keeps the colon with the drive, and so does this.
///
/// The test for "that is a drive" is deliberately narrow: a single ASCII letter,
/// the colon, and then a separator. Requiring the separator that follows a drive
/// letter is what keeps a one-letter *volume* name from swallowing the rest of
/// the mount, and `Path` is not asked because the value is a document's text
/// rather than a path this host can open — `Path` also answers differently per
/// platform, which is the bug.
///
/// A missing field is `None` rather than an empty string, because the two mean
/// different things to the caller: `/anon` declares an anonymous volume at
/// `/anon`, while `source:` with nothing after it declares a mount with no
/// source at all.
fn split_short_mount(value: &str) -> [Option<&str>; 3] {
    let mut fields: [Option<&str>; 3] = [None, None, None];
    let mut start = 0;
    let mut found = 0;
    for (index, character) in value.char_indices() {
        if found == fields.len() - 1 {
            break;
        }
        if character == ':' && !is_drive_letter_colon(value, index) {
            fields[found] = Some(&value[start..index]);
            found += 1;
            start = index + character.len_utf8();
        }
    }
    if found < fields.len() {
        fields[found] = Some(&value[start..]);
    }
    fields
}

/// Whether the `:` at `index` is the colon of a Windows drive letter.
///
/// `index` is a byte offset, which is safe to compare against these byte
/// patterns because every byte examined is ASCII: a multi-byte character's
/// bytes are all above `0x7F` and cannot match.
fn is_drive_letter_colon(value: &str, index: usize) -> bool {
    let bytes = value.as_bytes();
    index == 1
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .get(2)
            .is_some_and(|byte| matches!(byte, b'\\' | b'/'))
}

/// Whether a short-syntax `target` names a path inside the container.
///
/// Only the container's own spellings count: `/`, `.`, and `~`. A Windows path
/// is a path on the *host* and a target is not, so accepting one here would
/// decide a mount's kind from a namespace this crate does not model. A document
/// that mounts a Windows path into a Windows container is outside this slice,
/// and saying so is better than guessing which of the two was meant.
fn target_is_path(target: &str) -> bool {
    target.starts_with('/') || target.starts_with('.') || target.starts_with('~')
}

/// Whether a short-syntax `source` names a path on the host rather than a
/// volume key.
///
/// A volume key is a bare name, so anything that names a location is a path. On
/// a Windows host that includes a drive path and a UNC share, which is what
/// makes `C:\data:/data` a bind: without it the split above is right and the
/// *kind* is still wrong.
///
/// The rule is host-independent on purpose. A `C:\data` written on Windows and
/// parsed on Linux is a relative path with a backslash in its name, and Compose
/// reads it the same way there — as the volume `C` — because Compose's own
/// splitting is a text rule too. Deciding from the document's spelling rather
/// than from the host means the same document produces the same project
/// everywhere.
fn is_host_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('.')
        || value.starts_with('~')
        || is_windows_path(value)
}

/// A path spelled as a Windows drive root or a UNC share.
///
/// `C:` alone is not one: it is drive-relative, and it names a directory on
/// whichever drive is current rather than a location in its own right.
fn is_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let is_drive_root = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    is_drive_root || bytes.starts_with(b"\\\\")
}

fn split_command(value: &str, path: &str, field_path: &str) -> Result<Vec<String>, ComposeError> {
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                token.push(character);
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !token.is_empty() {
                result.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err(compose_error(
            "compose_invalid_command",
            "command contains an unterminated quote or escape",
            Some(path),
            field_path,
        ));
    }
    if !token.is_empty() {
        result.push(token);
    }
    Ok(result)
}

/// Loads the contents a service's `env_file` and `label_file` declared.
///
/// Compose resolves these paths against the directory holding the file that
/// declared them, and the contents are then loaded *before* the service's own
/// `environment` and `labels`, so an explicit entry in the document wins over a
/// file. That is what makes `env_file` a way to supply a secret without putting
/// it in the Compose file, while still allowing the document to override one
/// value deliberately.
///
/// The bytes always come from the caller's map. Nothing here opens a file, so a
/// document cannot cause a read the caller did not supply, and a declared entry
/// with no supplied content is an error naming the exact path that is missing
/// rather than a silently empty environment.
fn resolve_env_files(
    project: &mut ComposeProject,
    source_path: &str,
    options: &ComposeProjectOptions,
) -> Result<(), ComposeError> {
    let declares_anything = project
        .services
        .values()
        .any(|service| !service.env_file.is_empty() || !service.label_file.is_empty());
    if !declares_anything {
        return Ok(());
    }
    if options.env_file == EnvFilePolicy::Reject {
        let (name, field) = project
            .services
            .iter()
            .find_map(|(name, service)| {
                if !service.env_file.is_empty() {
                    Some((name.clone(), "env_file"))
                } else if !service.label_file.is_empty() {
                    Some((name.clone(), "label_file"))
                } else {
                    None
                }
            })
            .expect("a service was just found to declare one");
        return Err(compose_error(
            "compose_env_file_rejected",
            format!(
                "service '{name}' declares {field}; env_file and label_file read from \
                 caller-supplied contents"
            ),
            Some(source_path),
            &format!("$.services.{name}.{field}"),
        ));
    }

    let directory = std::path::Path::new(source_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    // The caller's keys are normalized with the same spelling the resolved keys
    // get, so the two sides of the lookup agree on a host whose separator is not
    // `/` without asking the caller to know which host will read the document.
    let supplied = options
        .env_files
        .iter()
        .map(|(key, contents)| (key_spelling(key), contents.as_str()))
        .collect::<BTreeMap<String, &str>>();
    // Loaded first so the document's own entries overwrite them.
    let mut pending: Vec<PendingEnvFiles> = Vec::new();
    for (name, service) in &project.services {
        let mut environment = BTreeMap::new();
        for declared in &service.env_file {
            let key = resolve_against(&directory, declared);
            let Some(contents) = supplied.get(key.as_str()) else {
                return Err(missing_env_file(name, "env_file", &key, source_path));
            };
            let loaded = parse_env_file(contents, &key, &format!("$.services.{name}.env_file"))?;
            for (key, value) in loaded {
                environment.insert(key, value);
            }
        }
        let mut labels = BTreeMap::new();
        for declared in &service.label_file {
            let key = resolve_against(&directory, declared);
            let Some(contents) = supplied.get(key.as_str()) else {
                return Err(missing_env_file(name, "label_file", &key, source_path));
            };
            let loaded = parse_env_file(contents, &key, &format!("$.services.{name}.label_file"))?;
            for (key, value) in loaded {
                labels.insert(key, value);
            }
        }
        if !environment.is_empty() || !labels.is_empty() {
            pending.push((name.clone(), environment, labels));
        }
    }
    for (name, environment, labels) in pending {
        let Some(service) = project.services.get_mut(&name) else {
            continue;
        };
        // The document's own entries win, so extend with the file values first.
        let mut merged_environment = environment;
        merged_environment.extend(service.environment.clone());
        service.environment = merged_environment;
        let mut merged_labels = labels;
        merged_labels.extend(service.labels.clone());
        service.labels = merged_labels;
        // The files are resolved, so a later merge compares the same service
        // rather than a stale declaration.
        service.declared.insert("environment".to_owned());
        service.declared.insert("labels".to_owned());
    }
    Ok(())
}

/// The file-supplied values waiting to be merged into one service.
type PendingEnvFiles = (String, BTreeMap<String, String>, BTreeMap<String, String>);

/// Reports a declared `env_file`/`label_file` with no supplied content.
///
/// The message names the lookup key rather than the path as this host's `Path`
/// would print it, because the key is the text the caller has to look up in
/// `env_files`; naming anything else would send them looking for a spelling this
/// crate will not accept.
fn missing_env_file(service: &str, field: &str, key: &str, source: &str) -> ComposeError {
    compose_error(
        "compose_env_file_missing",
        format!(
            "service '{service}' declares {field} '{key}' and the caller supplied no contents \
             for it",
        ),
        Some(source),
        &format!("$.services.{service}.{field}"),
    )
}

/// Resolves a declared path against the directory of the declaring file, and
/// returns it as the key the caller's contents map is looked up under.
///
/// A relative path is taken from the Compose file's directory, which is where
/// Compose looks for it. A file with no directory component resolves against
/// `.`, so a bare `env_file: app.env` and a file named `app.env` in the working
/// directory produce the same key on both sides of the lookup. A *rooted* path
/// is kept as written. `..` is not rejected here: the caller supplied the
/// contents and so already chose the file, and refusing to honor it would be a
/// check the caller can bypass anyway.
///
/// The test for "already anchored" is `has_root`, not `is_absolute`, and that is
/// the whole of the Windows half of this function. On Windows a path is absolute
/// only when it has a drive prefix *and* a root, so the `/secrets/app.env` that
/// this document wrote is not absolute there: `Path::join` would produce
/// `\secrets\app.env`, which is not that file at all but a drive-relative path
/// resolved against whatever drive the process happens to have current. A
/// rooted path is already anchored to a filesystem root, so re-basing it onto
/// the declaring directory can only change which file is named. On Unix a
/// non-empty path is rooted exactly when it is absolute, so this changes
/// nothing there.
fn resolve_against(directory: &std::path::Path, declared: &str) -> String {
    let candidate = std::path::Path::new(declared);
    if candidate.has_root() {
        return key_spelling(declared);
    }
    key_spelling(&directory.join(candidate).display().to_string())
}

/// Parses a dotenv file into key/value pairs for a service environment.
///
/// Reuses the dotenv reader so `env_file` and `--env-file` accept exactly the
/// same syntax, rather than a second parser that would drift from it.
fn parse_env_file(
    contents: &str,
    key: &str,
    field_path: &str,
) -> Result<BTreeMap<String, String>, ComposeError> {
    let label = key.to_owned();
    let source = crate::dotenv::DotenvSource::new(label.clone(), contents.to_owned());
    let loaded = crate::dotenv::load_dotenv_sources(
        std::slice::from_ref(&source),
        &crate::InterpolationValues::new(),
        crate::DotenvOptions::default(),
    )
    .map_err(|error| {
        compose_error(
            "compose_env_file_invalid",
            format!("failed to read Compose {field_path} '{label}': {error}"),
            Some(label.as_str()),
            field_path,
        )
    })?;
    Ok(loaded
        .iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

/// Renders a path in the one spelling `env_files` keys and diagnostics use.
///
/// The spelling is `/`-separated on every platform, because that is how a
/// Compose document writes a path and how Docker accepts one on Windows too, and
/// because the caller's map is keyed by text. The platform's own separator is
/// what made the natural spelling miss: `Path::join` writes `\`, so a document
/// at `/p/compose.yaml` declaring `env_file: app.env` asked the caller for
/// `/p\app.env`, which nobody writes, while the same call succeeded on Linux
/// and hid the divergence from every Linux run of the suite.
///
/// The rewrite is the host's `MAIN_SEPARATOR` and not `/` unconditionally,
/// because on Unix a backslash is an ordinary character in a filename: a file
/// named `back\slash.env` is a different file from `back/slash.env`, and
/// rewriting the caller's key would merge them. There the text is already
/// correct and is returned unchanged.
fn key_spelling(text: &str) -> String {
    if std::path::MAIN_SEPARATOR == '/' {
        return text.to_owned();
    }
    text.replace(std::path::MAIN_SEPARATOR, "/")
}

fn merge_projects(
    mut left: ComposeProject,
    right: ComposeProject,
    options: &ComposeProjectOptions,
) -> Result<ComposeProject, ComposeError> {
    if options.merge == MergePolicy::Reject {
        return Err(compose_error(
            "compose_merge_rejected",
            "multiple Compose sources require an explicit merge policy",
            None,
            "$",
        ));
    }
    if !right.name.is_empty() {
        left.name = right.name;
    }
    match options.merge {
        // Whole-service replacement: the incoming declaration wins outright.
        MergePolicy::LastWins => left.services.extend(right.services),
        MergePolicy::MergeServices => {
            for (name, service) in right.services {
                match left.services.get_mut(&name) {
                    Some(base) => merge_service(base, service),
                    None => {
                        left.services.insert(name, service);
                    }
                }
            }
        }
        // Rejected before this point.
        MergePolicy::Reject => {}
    }
    left.networks.extend(right.networks);
    left.volumes.extend(right.volumes);
    left.configs.extend(right.configs);
    left.secrets.extend(right.secrets);
    left.dependency_order = dependency_order(&left.services)?;
    Ok(left)
}

/// Merges one service declaration over another, field by field.
///
/// The rule at every field is the same: a field the incoming declaration did
/// **not** set leaves the base value alone. An override that only adds an
/// environment variable must not erase the base image, command, or ports.
/// Replacing the whole service instead produces a different project than the
/// author wrote, and does so silently.
///
/// Treatment then follows the shape of the value, which is what makes the result
/// match Docker Compose's own merge:
///
/// - `environment` and `labels` are maps, so they merge key by key with the
///   incoming value winning per key;
/// - sequences concatenate base-then-incoming, so an override adds to a list
///   instead of silently replacing it;
/// - sub-documents and scalars replace outright, but only when supplied.
fn merge_service(base: &mut ComposeProjectService, incoming: ComposeProjectService) {
    // The declared set is read throughout, so it is taken before any field is
    // moved out of the incoming declaration.
    let declared = incoming.declared.clone();
    let sets = |field: &str| declared.contains(field);

    base.environment.extend(incoming.environment);
    base.labels.extend(incoming.labels);

    base.command.extend(incoming.command);
    base.entrypoint.extend(incoming.entrypoint);
    base.ports.extend(incoming.ports);
    base.volumes.extend(incoming.volumes);
    base.depends_on.extend(incoming.depends_on);
    base.networks.extend(incoming.networks);
    base.configs.extend(incoming.configs);
    base.secrets.extend(incoming.secrets);
    base.profiles.extend(incoming.profiles);
    base.devices.extend(incoming.devices);
    base.device_cgroup_rules
        .extend(incoming.device_cgroup_rules);
    base.external_links.extend(incoming.external_links);
    base.volumes_from.extend(incoming.volumes_from);
    base.storage_opt.extend(incoming.storage_opt);

    if sets("build") {
        base.build = incoming.build;
    }
    if sets("container_name") {
        base.container_name = incoming.container_name;
    }
    if sets("pull_policy") {
        base.pull_policy = incoming.pull_policy;
    }
    if sets("working_dir") {
        base.working_dir = incoming.working_dir;
    }
    if sets("user") {
        base.user = incoming.user;
    }
    if sets("hostname") {
        base.hostname = incoming.hostname;
    }

    // The remaining scalar and sub-document fields replace outright, but only
    // when the incoming declaration set them. Every `Option` field is listed
    // explicitly rather than by reflection: a field that is added to the model
    // and forgotten here would be silently dropped by every override, which is
    // the one failure mode a merge is not allowed to have.
    if sets("restart") {
        base.restart = incoming.restart;
    }
    if sets("healthcheck") {
        base.healthcheck = incoming.healthcheck;
    }
    if sets("expose") {
        base.expose = incoming.expose;
    }
    if sets("extra_hosts") {
        base.extra_hosts = incoming.extra_hosts;
    }
    if sets("cap_add") {
        base.cap_add = incoming.cap_add;
    }
    if sets("cap_drop") {
        base.cap_drop = incoming.cap_drop;
    }
    if sets("read_only") {
        base.read_only = incoming.read_only;
    }
    if sets("init") {
        base.init = incoming.init;
    }
    if sets("stop_grace_period") {
        base.stop_grace_period = incoming.stop_grace_period;
    }
    if sets("stop_signal") {
        base.stop_signal = incoming.stop_signal;
    }
    if sets("platform") {
        base.platform = incoming.platform;
    }
    if sets("logging") {
        base.logging = incoming.logging;
    }
    if sets("shm_size") {
        base.shm_size = incoming.shm_size;
    }
    if sets("dns") {
        base.dns = incoming.dns;
    }
    if sets("dns_search") {
        base.dns_search = incoming.dns_search;
    }
    if sets("dns_opt") {
        base.dns_opt = incoming.dns_opt;
    }
    if sets("group_add") {
        base.group_add = incoming.group_add;
    }
    if sets("sysctls") {
        base.sysctls = incoming.sysctls;
    }
    if sets("ulimits") {
        base.ulimits = incoming.ulimits;
    }
    if sets("security_opt") {
        base.security_opt = incoming.security_opt;
    }
    if sets("isolation") {
        base.isolation = incoming.isolation;
    }
    if sets("runtime") {
        base.runtime = incoming.runtime;
    }
    if sets("pid") {
        base.pid = incoming.pid;
    }
    if sets("userns_mode") {
        base.userns_mode = incoming.userns_mode;
    }
    if sets("annotations") {
        base.annotations = incoming.annotations;
    }
    if sets("network_mode") {
        base.network_mode = incoming.network_mode;
    }
    if sets("tmpfs") {
        base.tmpfs = incoming.tmpfs;
    }
    if sets("domainname") {
        base.domainname = incoming.domainname;
    }
    if sets("deploy") {
        base.deploy = incoming.deploy;
    }
    if sets("env_file") {
        base.env_file = incoming.env_file;
    }
    if sets("label_file") {
        base.label_file = incoming.label_file;
    }
    if sets("mem_limit") {
        base.mem_limit = incoming.mem_limit;
    }
    if sets("mem_reservation") {
        base.mem_reservation = incoming.mem_reservation;
    }
    if sets("mem_swappiness") {
        base.mem_swappiness = incoming.mem_swappiness;
    }
    if sets("memswap_limit") {
        base.memswap_limit = incoming.memswap_limit;
    }
    if sets("memswap_reservation") {
        base.memswap_reservation = incoming.memswap_reservation;
    }
    if sets("cpus") {
        base.cpus = incoming.cpus;
    }
    if sets("cpu_shares") {
        base.cpu_shares = incoming.cpu_shares;
    }
    if sets("cpu_period") {
        base.cpu_period = incoming.cpu_period;
    }
    if sets("cpu_quota") {
        base.cpu_quota = incoming.cpu_quota;
    }
    if sets("cpuset") {
        base.cpuset = incoming.cpuset;
    }
    if sets("cpu_count") {
        base.cpu_count = incoming.cpu_count;
    }
    if sets("cpu_percent") {
        base.cpu_percent = incoming.cpu_percent;
    }
    if sets("cpu_rt_period") {
        base.cpu_rt_period = incoming.cpu_rt_period;
    }
    if sets("cpu_rt_runtime") {
        base.cpu_rt_runtime = incoming.cpu_rt_runtime;
    }
    if sets("pids_limit") {
        base.pids_limit = incoming.pids_limit;
    }
    // A `false` here is not the default — the base may have said `true` — so this
    // one field genuinely needs the declared set even though the renderer drops
    // the value.
    if sets("oom_kill_disable") {
        base.oom_kill_disable = incoming.oom_kill_disable;
    }
    if sets("oom_score_adj") {
        base.oom_score_adj = incoming.oom_score_adj;
    }
    if sets("blkio_config") {
        base.blkio_config = incoming.blkio_config;
    }
    if sets("cgroup_parent") {
        base.cgroup_parent = incoming.cgroup_parent;
    }
    if sets("credential_spec") {
        base.credential_spec = incoming.credential_spec;
    }
    if sets("ipc") {
        base.ipc = incoming.ipc;
    }
    if sets("uts") {
        base.uts = incoming.uts;
    }
    if sets("mac_address") {
        base.mac_address = incoming.mac_address;
    }

    // These have no `Option` wrapper, so a normalized value cannot say whether
    // the source set it. The declared set is the only way to tell an explicit
    // `replicas: 1` from a file that never mentioned replicas.
    if sets("image") {
        base.image = incoming.image;
    }
    if sets("replicas") {
        base.replicas = incoming.replicas;
    }
    if sets("tty") {
        base.tty = incoming.tty;
    }
    if sets("stdin_open") {
        base.stdin_open = incoming.stdin_open;
    }
    if sets("privileged") {
        base.privileged = incoming.privileged;
    }

    base.declared.extend(declared);
}

/// Applies the caller's active profiles to a merged project.
///
/// Compose's rule is that a service with no `profiles` key is unconditional
/// and a service with one belongs to the project only while a name it declares
/// is active. The inactive ones are therefore *removed* rather than reported:
/// every later step — the rendered document, the plan, `up`, `ps`, `logs` — then
/// simply never sees them, which is what makes `compose ps` and `compose logs`
/// agree with `compose up` about which services exist.
///
/// The name `*` is a wildcard. Activating it includes every profile-gated
/// service, which is how one invocation asks for the whole document.
///
/// A non-empty explicit service selection is not filtered. Naming a service
/// selects it whatever its profile says, so a project can still be driven one
/// service at a time without enabling anything.
///
/// # Errors
///
/// Returns the same undeclared-dependency and cycle errors as
/// [`dependency_order`]. Recomputing the order is what makes a dangling
/// `depends_on` onto a filtered-out service an error, exactly as it is when the
/// service is simply absent from the document.
fn apply_profiles(
    project: &mut ComposeProject,
    options: &ComposeProjectOptions,
) -> Result<(), ComposeError> {
    project.profiles = project
        .services
        .values()
        .flat_map(|service| service.profiles.iter().cloned())
        .collect();
    if !options.services.is_empty() {
        return Ok(());
    }
    let wildcard = options.profiles.contains("*");
    project.services.retain(|_, service| {
        service.profiles.is_empty()
            || wildcard
            || service
                .profiles
                .iter()
                .any(|profile| options.profiles.contains(profile))
    });
    project.dependency_order = dependency_order(&project.services)?;
    Ok(())
}

fn dependency_order(
    services: &BTreeMap<String, ComposeProjectService>,
) -> Result<Vec<String>, ComposeError> {
    let mut indegree = services
        .keys()
        .map(|name| (name.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, service) in services {
        for dependency in &service.depends_on {
            if !services.contains_key(&dependency.service) {
                return Err(compose_error(
                    "compose_unknown_dependency",
                    format!("service '{name}' depends on an undeclared service"),
                    None,
                    "$.services",
                ));
            }
            *indegree
                .get_mut(name)
                .expect("service key was just inserted") += 1;
            dependents
                .entry(dependency.service.clone())
                .or_default()
                .push(name.clone());
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(name, degree)| (*degree == 0).then_some(name.clone()))
        .collect::<Vec<_>>();
    ready.sort();
    let mut queue = ready.into_iter().collect::<VecDeque<_>>();
    let mut result = Vec::with_capacity(services.len());
    while let Some(name) = queue.pop_front() {
        result.push(name.clone());
        if let Some(children) = dependents.get(&name) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("dependent service key was just inserted");
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(child.clone());
                }
            }
        }
    }
    if result.len() != services.len() {
        return Err(compose_error(
            "compose_dependency_cycle",
            "Compose service dependencies contain a cycle",
            None,
            "$.services",
        ));
    }
    Ok(result)
}

fn validate_project(project: &ComposeProject, source: &str) -> Result<(), ComposeError> {
    if !valid_project_name(&project.name) {
        return Err(compose_error(
            "compose_invalid_project_name",
            "project name must use lowercase letters, digits, hyphens, or underscores",
            Some(source),
            "$.name",
        ));
    }
    for (service_name, service) in &project.services {
        if service.image.trim().is_empty() {
            // Checked after the merge rather than per source, so an override
            // layer may omit the image and inherit it from the base.
            return Err(compose_error(
                "compose_service_requires_image",
                "every normalized service requires an image",
                Some(source),
                &format!("$.services.{service_name}"),
            ));
        }
        if service.image.chars().any(char::is_whitespace) {
            return Err(compose_error(
                "compose_invalid_image",
                "service image must be non-empty and contain no whitespace",
                Some(source),
                "$.services",
            ));
        }
        for config in &service.configs {
            if !project.configs.contains_key(&config.source) {
                return Err(compose_error(
                    "compose_unknown_config",
                    format!("service '{service_name}' mounts an undeclared config"),
                    Some(source),
                    &format!("$.services.{service_name}.configs"),
                ));
            }
        }
        for secret in &service.secrets {
            if !project.secrets.contains_key(&secret.source) {
                return Err(compose_error(
                    "compose_unknown_secret",
                    format!("service '{service_name}' mounts an undeclared secret"),
                    Some(source),
                    &format!("$.services.{service_name}.secrets"),
                ));
            }
        }
    }
    Ok(())
}

fn valid_project_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_')
        })
}

fn validate_service_name(value: &str, source: &str, field_path: &str) -> Result<(), ComposeError> {
    if !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        Ok(())
    } else {
        Err(compose_error(
            "compose_invalid_service_name",
            "service or resource name contains unsupported characters",
            Some(source),
            field_path,
        ))
    }
}

fn validate_environment_name(
    value: &str,
    source: &str,
    field_path: &str,
) -> Result<(), ComposeError> {
    let mut characters = value.chars();
    if characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(compose_error(
            "compose_invalid_environment_name",
            "environment name is not a valid environment variable",
            Some(source),
            field_path,
        ))
    }
}

fn resolved_scalar(
    value: &Value,
    source: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<String, ComposeError> {
    let text = scalar(value, source, field_path)?;
    resolved_text(&text, source, field_path, values, policy)
}

fn resolved_text(
    value: &str,
    source: &str,
    field_path: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<String, ComposeError> {
    interpolate(value, values, policy)
        .map_err(|error| compose_error(error.code(), error.message(), Some(source), field_path))
}

fn required_map_scalar(
    mapping: &Mapping,
    key: &str,
    source: &str,
    field_path: &str,
) -> Result<String, ComposeError> {
    mapping
        .get(Value::String(key.to_owned()))
        .map(|value| scalar(value, source, &format!("{field_path}.{key}")))
        .transpose()?
        .ok_or_else(|| {
            compose_error(
                "compose_missing_field",
                format!("'{key}' is required"),
                Some(source),
                field_path,
            )
        })
}

fn mapping<'a>(
    value: &'a Value,
    source: &str,
    field_path: &str,
) -> Result<&'a Mapping, ComposeError> {
    value.as_mapping().ok_or_else(|| {
        compose_error(
            "compose_expected_mapping",
            "expected a mapping",
            Some(source),
            field_path,
        )
    })
}

fn sequence<'a>(
    value: &'a Value,
    source: &str,
    field_path: &str,
) -> Result<&'a Vec<Value>, ComposeError> {
    value.as_sequence().ok_or_else(|| {
        compose_error(
            "compose_expected_sequence",
            "expected a sequence",
            Some(source),
            field_path,
        )
    })
}

fn scalar(value: &Value, source: &str, field_path: &str) -> Result<String, ComposeError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(compose_error(
            "compose_invalid_scalar",
            "expected a scalar value",
            Some(source),
            field_path,
        )),
    }
}

fn scalar_key(value: &Value, source: &str, field_path: &str) -> Result<String, ComposeError> {
    value.as_str().map(str::to_owned).ok_or_else(|| {
        compose_error(
            "compose_invalid_key",
            "mapping keys must be strings",
            Some(source),
            field_path,
        )
    })
}

fn reject_duplicate(mapping: &Mapping, source: &str, field_path: &str) -> Result<(), ComposeError> {
    let mut keys = BTreeSet::new();
    for key in mapping.keys() {
        let key = scalar_key(key, source, field_path)?;
        if !keys.insert(key.clone()) {
            return Err(compose_error(
                "compose_duplicate_key",
                format!("duplicate mapping key '{key}'"),
                Some(source),
                field_path,
            ));
        }
    }
    Ok(())
}

/// Whether a `u32` is zero, for a `skip_serializing_if` that treats zero as unset.
///
/// The reference is serde's calling convention, not a preference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn compose_error(
    code: impl Into<String>,
    message: impl Into<String>,
    source: Option<&str>,
    field_path: &str,
) -> ComposeError {
    ComposeError::new(
        code,
        message,
        source.map(str::to_owned),
        field_path.to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ComposeMountKind, ComposeProject, ComposeProjectOptions, ComposeProjectService,
        is_host_path, is_windows_path, key_spelling, resolve_against, split_short_mount,
    };
    use crate::{InterpolationPolicy, InterpolationValues};

    /// The Compose-spec service fields this slice added on top of the 23 it
    /// already modeled, with the document that exercises each one.
    ///
    /// Every expectation below is a value `docker compose config` printed on
    /// Docker 29.8, so a change that breaks one of them is a change that stops
    /// agreeing with Docker.
    const RESOURCE_LIMITS: &str = "
name: demo
services:
  app:
    image: alpine
    mem_limit: 512m
    mem_reservation: 128m
    mem_swappiness: 60
    memswap_limit: 1g
    memswap_reservation: 256m
    cpus: 0.5
    cpu_shares: 73
    cpu_period: 100000
    cpu_quota: 50000
    cpuset: \"0,1\"
    cpu_count: 2
    cpu_percent: 80
    cpu_rt_period: 1400
    cpu_rt_runtime: 400
    pids_limit: 100
    oom_kill_disable: true
    oom_score_adj: 500
";

    fn project_of(source: &str) -> ComposeProject {
        ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project")
    }

    fn app_of(source: &str) -> ComposeProjectService {
        project_of(source).service("app").expect("app").clone()
    }

    /// Every memory field goes through the one size table, which is what makes
    /// `512m` and `536870912` the same number. The byte counts are exactly the
    /// strings `docker compose config` printed for the same declarations.
    #[test]
    fn memory_limits_resolve_through_the_shared_size_table() {
        let app = app_of(RESOURCE_LIMITS);
        assert_eq!(app.mem_limit, Some(512 * 1024 * 1024));
        assert_eq!(app.mem_reservation, Some(128 * 1024 * 1024));
        assert_eq!(app.memswap_limit, Some(1024 * 1024 * 1024));
        assert_eq!(app.memswap_reservation, Some(256 * 1024 * 1024));
        // The same table, so `shm_size` and `mem_limit` cannot disagree.
        assert_eq!(
            ComposeProject::parse_yaml(
                "services:\n  app:\n    image: alpine\n    shm_size: 512m\n",
                "compose.yaml",
                &InterpolationValues::new(),
                ComposeProjectOptions::default(),
            )
            .expect("project")
            .service("app")
            .expect("app")
            .shm_size,
            app.mem_limit
        );
        // A swappiness percentage is a number, not a size, even though Docker
        // prints it as a quoted string.
        assert_eq!(app.mem_swappiness, Some(60));
    }

    /// Zero is Compose's "no limit" and Docker prints no key for it, so it is
    /// normalized away rather than carried as a value a renderer must remember to
    /// drop. Measured on 29.8: every one of these renders nothing.
    #[test]
    fn a_zero_limit_is_normalized_to_unset() {
        let app = app_of(
            "name: demo
services:
  app:
    image: alpine
    mem_limit: 0
    mem_reservation: 0
    mem_swappiness: 0
    memswap_limit: 0
    cpuset: \"\"
    cgroup_parent: \"\"
    cpu_shares: 0
    cpu_period: 0
    cpu_quota: 0
    cpu_rt_period: 0
    cpu_rt_runtime: 0
    pids_limit: 0
    oom_score_adj: 0
",
        );
        assert_eq!(app.mem_limit, None);
        assert_eq!(app.mem_reservation, None);
        assert_eq!(app.mem_swappiness, None);
        assert_eq!(app.memswap_limit, None);
        assert_eq!(app.cpuset, None);
        assert_eq!(app.cgroup_parent, None);
        assert_eq!(app.cpu_shares, None);
        assert_eq!(app.cpu_period, None);
        assert_eq!(app.cpu_quota, None);
        assert_eq!(app.cpu_rt_period, None);
        assert_eq!(app.cpu_rt_runtime, None);
        assert_eq!(app.pids_limit, None);
        assert_eq!(app.oom_score_adj, None);
    }

    /// `cpus` becomes whole nano-CPUs, rounding to the nearest one. Both
    /// expectations are values `docker compose config` printed: `1.9e-06` for
    /// `0.0000019` and `1.234e-07` for `0.0000001234`. Truncation would print
    /// `1.8999999e-06` for the first, which is how the rounding is known to be
    /// Docker's.
    #[test]
    fn cpus_becomes_whole_nano_cpus_rounded_to_nearest() {
        let nano = |value: &str| {
            app_of(&format!(
                "name: demo\nservices:\n  app:\n    image: alpine\n    cpus: {value}\n"
            ))
            .cpus
        };
        assert_eq!(nano("0.5"), Some(500_000_000));
        assert_eq!(nano("\"1.5\""), Some(1_500_000_000));
        assert_eq!(nano("8"), Some(8_000_000_000));
        assert_eq!(nano("0.0000019"), Some(1_900));
        assert_eq!(nano("0.0000001234"), Some(123));
        assert_eq!(nano("1.9999999"), Some(1_999_999_900));
    }

    /// The remaining CPU and process knobs are whole numbers in the units the
    /// Engine request wants, so nothing downstream has to convert them.
    #[test]
    fn cpu_and_process_knobs_keep_their_engine_units() {
        let app = app_of(RESOURCE_LIMITS);
        assert_eq!(app.cpu_shares, Some(73));
        assert_eq!(app.cpu_period, Some(100_000));
        assert_eq!(app.cpu_quota, Some(50_000));
        assert_eq!(app.cpuset.as_deref(), Some("0,1"));
        assert_eq!(app.cpu_count, Some(2));
        assert_eq!(app.cpu_percent, Some(80));
        assert_eq!(app.cpu_rt_period, Some(1_400));
        assert_eq!(app.cpu_rt_runtime, Some(400));
        assert_eq!(app.pids_limit, Some(100));
        assert_eq!(app.oom_score_adj, Some(500));
        assert!(app.oom_kill_disable);
    }

    /// Compose documents a real-time period with a unit and the Engine takes
    /// whole microseconds. Docker refuses the documented spelling, so this does
    /// too — with a message naming the field, rather than quietly reading
    /// `1400us` as `1400`.
    #[test]
    fn a_unit_suffixed_real_time_period_is_refused() {
        let error = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    cpu_rt_period: 1400us\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a duration is not a microsecond count");
        assert_eq!(error.code(), "compose_invalid_integer");
        assert_eq!(error.path(), "$.services.app.cpu_rt_period");
    }

    /// `oom_score_adj` has a range Compose enforces, so enforcing it here is
    /// matching Docker rather than inventing a restriction.
    #[test]
    fn oom_score_adj_is_refused_outside_the_kernel_range() {
        for value in ["1001", "\"-1001\""] {
            let error = ComposeProject::parse_yaml(
                &format!("services:\n  app:\n    image: alpine\n    oom_score_adj: {value}\n"),
                "compose.yaml",
                &InterpolationValues::new(),
                ComposeProjectOptions::default(),
            )
            .expect_err("out of range");
            assert_eq!(error.code(), "compose_invalid_oom_score_adj");
        }
        assert_eq!(
            app_of("services:\n  app:\n    image: alpine\n    oom_score_adj: -1000\n")
                .oom_score_adj,
            Some(-1000)
        );
    }

    /// The short spelling is normalized into the Engine's three fields, with the
    /// two defaults Docker fills in itself: the target repeats the source and the
    /// permissions are `rwm`.
    #[test]
    fn devices_normalize_the_short_and_long_spellings() {
        let app = app_of(
            "name: demo
services:
  app:
    image: alpine
    devices:
      - \"/dev/sda\"
      - \"/dev/ttyUSB0:/dev/ttyUSB1:rwm\"
      - source: /dev/sdb
        target: /dev/xvdc
",
        );
        assert_eq!(app.devices.len(), 3);
        assert_eq!(app.devices[0].source, "/dev/sda");
        assert_eq!(app.devices[0].target, "/dev/sda");
        assert_eq!(app.devices[0].permissions, "rwm");
        assert_eq!(app.devices[1].target, "/dev/ttyUSB1");
        assert_eq!(app.devices[2].source, "/dev/sdb");
        assert_eq!(app.devices[2].target, "/dev/xvdc");
        assert_eq!(app.devices[2].permissions, "rwm");
    }

    /// The five device lists share one shape and one size table. The `iops` list
    /// taking a size suffix is not obvious — it was measured, not assumed: Docker
    /// prints `rate: "12582912"` for `device_read_iops: [{path: /dev/sda,
    /// rate: 12m}]`.
    #[test]
    fn blkio_config_resolves_every_device_list() {
        let app = app_of(
            "name: demo
services:
  app:
    image: alpine
    blkio_config:
      weight: 300
      weight_device:
        - path: /dev/sda
          weight: 400
      device_read_bps:
        - path: /dev/sda
          rate: 12m
      device_read_iops:
        - path: /dev/sda
          rate: 120
      device_write_bps:
        - path: /dev/sdb
          rate: 1024k
      device_write_iops:
        - path: /dev/sdb
          rate: 30
",
        );
        let blkio = app.blkio_config.expect("blkio_config");
        assert_eq!(blkio.weight, Some(300));
        assert_eq!(blkio.weight_device[0].path, "/dev/sda");
        assert_eq!(blkio.weight_device[0].value, 400);
        assert_eq!(blkio.device_read_bps[0].value, 12 * 1024 * 1024);
        assert_eq!(blkio.device_read_iops[0].value, 120);
        assert_eq!(blkio.device_write_bps[0].value, 1024 * 1024);
        assert_eq!(blkio.device_write_iops[0].value, 30);
    }

    /// The two weights are the one place a quoted number is refused, because
    /// Compose types them as a `uint16` and Docker refuses a string there.
    #[test]
    fn a_quoted_blkio_weight_is_refused() {
        let error = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    blkio_config:\n      weight: \"300\"\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a string is not a uint16");
        assert_eq!(error.code(), "compose_invalid_blkio_weight");
    }

    /// `storage_opt` is a mapping only. The `key=value` sequence a string map
    /// normally takes is refused by Docker, so accepting it would be accepting a
    /// document Compose rejects.
    #[test]
    fn storage_opt_is_a_mapping_and_not_a_list() {
        let app = app_of(
            "name: demo
services:
  app:
    image: alpine
    storage_opt:
      size: 10G
      dm.basesize: 20G
",
        );
        assert_eq!(app.storage_opt.get("size").map(String::as_str), Some("10G"));
        let error = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    storage_opt: [\"size=10G\"]\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a list is not a mapping");
        assert_eq!(error.code(), "compose_expected_mapping");
    }

    /// A `volumes_from` entry naming a service in this document becomes a
    /// `service_started` dependency, which is what Compose does: the container
    /// needs those volumes, so the other service has to exist first. This is what
    /// puts the extending service after the one it inherits from in the plan.
    #[test]
    fn volumes_from_derives_a_dependency_on_the_service_it_names() {
        let project = project_of(
            "name: demo
services:
  other:
    image: alpine
    volumes:
      - data:/data
  app:
    image: alpine
    volumes_from:
      - other
      - container:elsewhere
volumes:
  data: {}
",
        );
        assert_eq!(project.dependency_order, ["other", "app"]);
        let app = project.service("app").expect("app");
        assert_eq!(app.volumes_from, ["other", "container:elsewhere"]);
        assert_eq!(app.depends_on.len(), 1);
        assert_eq!(app.depends_on[0].service, "other");
        assert_eq!(app.depends_on[0].condition, "service_started");
    }

    /// A `volumes_from` that names a service the document does not declare is
    /// Compose's own refusal — "service depends on undefined service" — and the
    /// derived dependency is what produces it.
    #[test]
    fn volumes_from_naming_an_undeclared_service_is_refused() {
        let error = ComposeProject::parse_yaml(
            "name: demo\nservices:\n  app:\n    image: alpine\n    volumes_from:\n      - other\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("undefined service");
        assert_eq!(error.code(), "compose_unknown_dependency");
    }

    /// The inline `extends` spelling needs no second source, so it is applied in
    /// full: the service that extends one gets the base's fields, its own
    /// declaration wins where the two overlap, and no `extends` key survives —
    /// Docker renders the inherited fields, not the declaration.
    #[test]
    fn an_inline_extends_is_applied_and_its_fields_win() {
        let project = project_of(
            "name: demo
services:
  app:
    extends:
      service:
        image: alpine
        mem_limit: 512m
        environment:
          - SHARED=1
    image: busybox
    environment:
      - OWN=1
",
        );
        let app = project.service("app").expect("app");
        assert_eq!(app.image, "busybox");
        assert_eq!(app.mem_limit, Some(512 * 1024 * 1024));
        assert_eq!(app.environment.get("SHARED").map(String::as_str), Some("1"));
        assert_eq!(app.environment.get("OWN").map(String::as_str), Some("1"));
    }

    /// A base named in this same document is applied too, and the base service
    /// stays in the project: an `extends` is a reference, not a removal.
    /// Measured on 29.8, `docker compose config` on a document with a `base`
    /// service and an `app` that extends it prints both, with `app` carrying the
    /// union of the two environments and its own image winning.
    #[test]
    fn an_extends_within_one_document_is_applied_and_the_base_stays() {
        let project = project_of(
            "name: demo
services:
  base:
    image: alpine
    mem_limit: 512m
    environment:
      - SHARED=1
  app:
    extends:
      service: base
    image: busybox
    environment:
      - OWN=1
",
        );
        assert_eq!(project.services.keys().collect::<Vec<_>>(), ["app", "base"]);
        let app = project.service("app").expect("app");
        assert_eq!(app.image, "busybox");
        assert_eq!(app.mem_limit, Some(512 * 1024 * 1024));
        assert_eq!(app.environment.get("SHARED").map(String::as_str), Some("1"));
        assert_eq!(app.environment.get("OWN").map(String::as_str), Some("1"));
    }

    /// Two services extending each other has no base. Resolving it in place would
    /// produce a service holding whichever declaration happened to be applied
    /// first, which is the silent-wrong-answer this check exists to prevent.
    #[test]
    fn an_extends_cycle_is_refused() {
        let error = ComposeProject::parse_yaml(
            "name: demo
services:
  a:
    image: alpine
    extends:
      service: b
  b:
    image: alpine
    extends:
      service: a
",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a cycle has no base");
        assert_eq!(error.code(), "compose_extends_cycle");
    }

    /// A base the document does not declare is Docker's own refusal — `service
    /// "base" not found` — reported here against the `extends` that named it.
    #[test]
    fn an_extends_naming_an_undeclared_service_is_refused() {
        let error = ComposeProject::parse_yaml(
            "name: demo\nservices:\n  app:\n    image: alpine\n    extends:\n      service: base\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("undeclared base");
        assert_eq!(error.code(), "compose_unknown_extends_service");
        assert_eq!(error.path(), "$.services.app.extends");
    }

    /// The file spelling names another Compose file, which is a host read. This
    /// crate does not perform a read a document asked for on its own, so the
    /// declaration is refused by name — the same posture as `env_file` and
    /// `include` — rather than accepted and quietly ignored.
    #[test]
    fn an_extends_that_names_a_file_is_refused_by_name() {
        let error = ComposeProject::parse_yaml(
            "name: demo\nservices:\n  app:\n    extends:\n      file: common.yaml\n      service: base\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a document-named file is not read");
        assert_eq!(error.code(), "compose_extends_requires_explicit_loader");
        assert_eq!(error.path(), "$.services.app.extends");
    }

    /// A top-level `models` block is validated and then dropped, because that is
    /// what Docker does with one: `models: {llm: {}}` is refused for the missing
    /// `model`, and a complete block prints no `models` key at all.
    #[test]
    fn a_models_block_is_validated_and_not_rendered() {
        let project = project_of(
            "name: demo
models:
  llm:
    model: ai/llama3-8b
    context_size: 2048
    name: renamed
services:
  app:
    image: alpine
",
        );
        let rendered: serde_json::Value =
            serde_json::from_str(&crate::ComposeConfigRenderer::render(&project)).expect("json");
        assert!(rendered.get("models").is_none());
        let missing = ComposeProject::parse_yaml(
            "name: demo\nmodels:\n  llm: {}\nservices:\n  app:\n    image: alpine\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a model must name a model");
        assert_eq!(missing.code(), "compose_model_requires_reference");
    }

    /// An override that names a field replaces it; one that does not leaves the
    /// base value alone. This is the rule every new field has to keep, because
    /// the alternative — an override that adds one environment variable erasing
    /// the base's memory limit — is a different project than the author wrote.
    #[test]
    fn a_new_field_survives_an_override_that_omits_it() {
        let project = ComposeProject::parse_sources(
            &[
                (
                    "services:\n  app:\n    image: alpine\n    mem_limit: 512m\n    cpus: 0.5\n    pids_limit: 100\n    oom_kill_disable: true\n",
                    "base.yaml",
                ),
                (
                    "services:\n  app:\n    environment:\n      - KEY=value\n",
                    "over.yaml",
                ),
            ],
            &InterpolationValues::new(),
            ComposeProjectOptions {
                merge: crate::MergePolicy::MergeServices,
                ..ComposeProjectOptions::default()
            },
        )
        .expect("merged project");
        let app = project.service("app").expect("app");
        assert_eq!(app.mem_limit, Some(512 * 1024 * 1024));
        assert_eq!(app.cpus, Some(500_000_000));
        assert_eq!(app.pids_limit, Some(100));
        assert!(app.oom_kill_disable);
    }

    /// `oom_kill_disable: false` in an override is a real statement — the base
    /// said `true` — so it has to reach the merged service even though the
    /// renderer drops the key.
    #[test]
    fn an_override_can_turn_a_boolean_off() {
        let project = ComposeProject::parse_sources(
            &[
                (
                    "services:\n  app:\n    image: alpine\n    oom_kill_disable: true\n",
                    "base.yaml",
                ),
                (
                    "services:\n  app:\n    oom_kill_disable: false\n",
                    "over.yaml",
                ),
            ],
            &InterpolationValues::new(),
            ComposeProjectOptions {
                merge: crate::MergePolicy::MergeServices,
                ..ComposeProjectOptions::default()
            },
        )
        .expect("merged project");
        assert!(!project.service("app").expect("app").oom_kill_disable);
    }

    /// The shared decimal reader counts the digits *after* the point, not the
    /// characters taking the point out. A value with two decimal places is the
    /// case that catches it: `1.25g` is 1.25 gibibytes, not 12.5.
    #[test]
    fn a_size_or_duration_with_two_decimal_places_keeps_its_value() {
        let bytes =
            |value: &str| super::parse_size_bytes(value, "$.size", "compose.yaml").expect("size");
        assert_eq!(bytes("1.5g"), 1_610_612_736);
        assert_eq!(bytes("1.25g"), 1_342_177_280);
        assert_eq!(
            super::parse_duration_nanos("0.25s", "$.duration", "compose.yaml").expect("duration"),
            250_000_000
        );
        assert_eq!(
            super::parse_duration_nanos("1.5ms", "$.duration", "compose.yaml").expect("duration"),
            1_500_000
        );
    }

    #[test]
    fn project_normalizes_ports_mounts_and_dependencies() {
        let source = r#"
name: demo
services:
  db:
    image: postgres:16
  app:
    image: alpine:3.20
    depends_on: [db]
    ports: ["8080:80"]
    volumes: ["data:/data", "./src:/src:ro"]
    networks: [front]
    scale: 2
networks:
  front: {}
volumes:
  data: {}
"#;
        let project = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project");
        assert_eq!(project.dependency_order, vec!["db", "app"]);
        let app = project.service("app").expect("app");
        assert_eq!(app.replicas, 2);
        assert_eq!(app.ports[0].published, Some(8080));
        assert_eq!(app.volumes[0].kind, super::ComposeMountKind::Volume);
        assert_eq!(app.volumes[1].kind, super::ComposeMountKind::Bind);
        assert_eq!(project.resource_name("front", true), "demo_front");
    }

    #[test]
    fn project_does_not_use_process_environment_for_pass_through_values() {
        let source = "services:\n  app:\n    image: alpine\n    environment:\n      - SECRET\n";
        let error = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions {
                interpolation: InterpolationPolicy::default()
                    .with_missing(crate::MissingVariablePolicy::Error),
                ..ComposeProjectOptions::default()
            },
        )
        .expect_err("missing explicit value");
        assert_eq!(error.code(), "compose_missing_interpolation");
    }

    #[test]
    fn explicit_project_sources_can_be_constructed_without_yaml() {
        let service = ComposeProjectService::new("alpine");
        assert_eq!(service.image, "alpine");
    }

    #[test]
    fn build_declarations_normalize_every_supported_field() {
        let source = "
name: demo
services:
  app:
    image: registry.example/app:1
    build:
      context: app
      dockerfile: Containerfile
      target: runtime
      platform: linux/amd64
      no_cache: true
      pull: true
      args:
        MODE: test
      labels:
        org.example.team: platform
      cache_from: [registry.example/app:cache]
";
        let project = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project");
        let build = project
            .service("app")
            .and_then(|service| service.build.clone())
            .expect("build declaration");
        assert_eq!(build.context, "app");
        assert_eq!(build.dockerfile.as_deref(), Some("Containerfile"));
        assert_eq!(build.target.as_deref(), Some("runtime"));
        assert_eq!(build.platform.as_deref(), Some("linux/amd64"));
        assert!(build.no_cache);
        assert_eq!(build.pull, Some(true));
        assert_eq!(
            build.arguments.get("MODE").map(String::as_str),
            Some("test")
        );
        assert_eq!(
            build.labels.get("org.example.team").map(String::as_str),
            Some("platform")
        );
        assert_eq!(build.cache_from, ["registry.example/app:cache"]);
        assert!(build.buildkit.is_empty());

        // A single image reference is the shorthand Compose also accepts.
        let single = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    build:\n      context: app\n      cache_from: alpine\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("shorthand");
        assert_eq!(
            single
                .service("app")
                .and_then(|service| service.build.clone())
                .expect("build")
                .cache_from,
            ["alpine"]
        );
    }

    #[test]
    fn build_declarations_record_buildkit_only_fields_by_name() {
        let source = "
services:
  app:
    image: alpine
    build:
      context: app
      secrets:
        - source: token
      ssh: default
      frontend: dockerfile.v0
";
        let project = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project");
        let build = project
            .service("app")
            .and_then(|service| service.build.clone())
            .expect("build declaration");
        // The values are not modeled, but the declaration is never silently
        // dropped: a caller reports the exact fields it cannot apply.
        assert_eq!(
            build
                .buildkit
                .iter()
                .map(|field| field.key())
                .collect::<Vec<_>>(),
            ["secrets", "ssh", "frontend"]
        );
    }

    /// A document with one unconditional service and three gated ones, reused by
    /// every profile test so they all speak about the same project.
    const PROFILED: &str = "
name: demo
services:
  always:
    image: alpine
  debug:
    image: alpine
    profiles: [debug]
  batch:
    image: alpine
    profiles: [batch]
  both:
    image: alpine
    profiles: [debug, batch]
";

    fn profiled(active: &[&str]) -> ComposeProject {
        ComposeProject::parse_yaml(
            PROFILED,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions {
                profiles: active.iter().map(|name| (*name).to_owned()).collect(),
                ..ComposeProjectOptions::default()
            },
        )
        .expect("project")
    }

    /// The rule that makes the whole feature work: a service whose profiles are
    /// all inactive is not an error and is not kept. It is simply not part of
    /// the project, so nothing downstream can start it.
    #[test]
    fn an_inactive_profile_removes_the_service_from_the_project() {
        let project = profiled(&[]);
        assert_eq!(project.services.keys().collect::<Vec<_>>(), ["always"]);
        assert_eq!(project.dependency_order, ["always"]);
    }

    #[test]
    fn an_active_profile_keeps_the_services_that_declare_it() {
        let project = profiled(&["debug"]);
        assert_eq!(
            project.services.keys().collect::<Vec<_>>(),
            ["always", "both", "debug"]
        );
        assert_eq!(
            project.service("both").expect("both").profiles,
            ["debug", "batch"],
            "a kept service keeps every profile it declares, not just the active one"
        );
    }

    /// A service with no `profiles` key is not gated by anything. This is the
    /// case that must not regress: it is the ordinary service in every project.
    #[test]
    fn a_service_without_profiles_is_kept_by_every_active_set() {
        for active in [vec![], vec!["debug"], vec!["nothing-matches"]] {
            let project = profiled(&active);
            assert!(
                project.service("always").is_some(),
                "an unconditional service disappeared for {active:?}"
            );
            assert!(
                project
                    .service("always")
                    .is_some_and(|service| service.profiles.is_empty()),
                "an unconditional service must not acquire a gate"
            );
        }
    }

    /// `--profile` repeats, so the active set is the union of every flag. The
    /// reference accumulates them the same way.
    #[test]
    fn several_active_profiles_accumulate() {
        let project = profiled(&["debug", "batch"]);
        assert_eq!(
            project.services.keys().collect::<Vec<_>>(),
            ["always", "batch", "both", "debug"]
        );
    }

    /// `*` is a wildcard, not a profile name: it activates every gated service.
    #[test]
    fn the_wildcard_profile_activates_every_gated_service() {
        let project = profiled(&["*"]);
        assert_eq!(
            project.services.keys().collect::<Vec<_>>(),
            ["always", "batch", "both", "debug"]
        );
    }

    /// Naming a service selects it, profile or not. This is the reference's
    /// rule, and it is what lets a project be driven one service at a time
    /// without enabling anything.
    ///
    /// The loader only skips the filter; narrowing to the selection stays the
    /// caller's step through [`ComposeProject::select_services`]. Narrowing here
    /// would drop the dependencies a caller still has to add, because those are
    /// not in the selection either.
    #[test]
    fn an_explicit_service_selection_is_not_filtered_by_profile() {
        let project = ComposeProject::parse_yaml(
            PROFILED,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions {
                services: ["batch".to_owned()].into_iter().collect(),
                ..ComposeProjectOptions::default()
            },
        )
        .expect("project");
        assert!(
            project.service("batch").is_some(),
            "a named service must survive filtering, or it could never be selected"
        );
        assert_eq!(
            project
                .select_services(&["batch".to_owned()].into_iter().collect())
                .expect("selection"),
            ["batch"]
        );
    }

    /// The document's profile inventory is a property of the document, so it
    /// survives filtering. `compose config --profiles` reads exactly this, and
    /// it has to be able to answer even when nothing is active.
    #[test]
    fn the_document_records_every_declared_profile() {
        for active in [vec![], vec!["*"], vec!["debug"]] {
            let project = profiled(&active);
            assert_eq!(
                project
                    .profiles
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["batch", "debug"],
                "the declared profiles changed for {active:?}"
            );
        }
    }

    /// A rendered document has to gate the same way when it is loaded again, so
    /// the renderer keeps a service's gate and stays quiet about the absence of
    /// one.
    #[test]
    fn a_rendered_service_keeps_only_the_gate_it_declared() {
        let project = profiled(&["debug"]);
        let rendered: serde_json::Value =
            serde_json::from_str(&crate::ComposeConfigRenderer::render(&project)).expect("json");
        let services = rendered
            .get("services")
            .and_then(serde_json::Value::as_object)
            .expect("services");
        assert_eq!(services["debug"]["profiles"], serde_json::json!(["debug"]));
        assert!(
            services["always"].get("profiles").is_none(),
            "an unconditional service must not render an empty profiles list"
        );
    }

    /// `profiles` is a sequence, so an override adds to it the way every other
    /// sequence in this model does. Read from `docker compose -f base -f over
    /// --profile two config`, which prints `one` then `two`.
    #[test]
    fn profiles_merge_base_then_override() {
        let project = ComposeProject::parse_sources(
            &[
                (
                    "services:\n  app:\n    image: alpine\n    profiles: [one]\n",
                    "base.yaml",
                ),
                ("services:\n  app:\n    profiles: [two]\n", "over.yaml"),
            ],
            &InterpolationValues::new(),
            ComposeProjectOptions {
                merge: crate::MergePolicy::MergeServices,
                profiles: ["two".to_owned()].into_iter().collect(),
                ..ComposeProjectOptions::default()
            },
        )
        .expect("merged project");
        assert_eq!(
            project.service("app").expect("app").profiles,
            ["one", "two"]
        );
        assert_eq!(project.profiles.iter().collect::<Vec<_>>(), ["one", "two"]);
    }

    /// A bare scalar is not a list. Compose rejects it, and so does this, with
    /// the same kind of message rather than a guess about what was meant.
    #[test]
    fn profiles_must_be_a_list_of_strings() {
        let scalar = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    profiles: debug\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a scalar is not a list");
        assert_eq!(scalar.code(), "compose_invalid_profiles");

        // A number is not a name a caller could pass to `--profile` either.
        let numeric = ComposeProject::parse_yaml(
            "services:\n  app:\n    image: alpine\n    profiles: [1]\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("a number is not a name");
        assert_eq!(numeric.code(), "compose_invalid_profile");
        assert!(
            numeric.path().ends_with("profiles[0]"),
            "the offending entry should be named: {numeric:?}"
        );
    }

    /// Profile selection happens after the merge, so a dependency onto a service
    /// the active set removed is a dangling dependency. Docker Compose reports
    /// the same thing, for the same reason: the service is not in the project.
    #[test]
    fn a_dependency_on_an_inactive_profile_is_an_undeclared_dependency() {
        let source = "services:\n  app:\n    image: alpine\n    depends_on: [db]\n  db:\n    \
                      image: postgres:16\n    profiles: [debug]\n";
        let error = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect_err("db is not in the project");
        assert_eq!(error.code(), "compose_unknown_dependency");

        let active = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions {
                profiles: ["debug".to_owned()].into_iter().collect(),
                ..ComposeProjectOptions::default()
            },
        )
        .expect("db is in the project");
        assert_eq!(active.dependency_order, ["db", "app"]);
    }

    /// The `:` in a Windows drive letter belongs to the drive.
    ///
    /// The third field is the remainder, so `a:b:c:d` keeps `c:d` in one piece
    /// exactly as `splitn(3, ':')` did; a field that was not written is `None`
    /// rather than empty, because `/anon` and `source:` mean different mounts.
    #[test]
    fn a_drive_letter_colon_is_not_a_short_mount_separator() {
        assert_eq!(
            split_short_mount("/tmp:/mnt"),
            [Some("/tmp"), Some("/mnt"), None]
        );
        assert_eq!(
            split_short_mount("C:\\data:/data"),
            [Some("C:\\data"), Some("/data"), None]
        );
        assert_eq!(
            split_short_mount("C:/data:/data:ro"),
            [Some("C:/data"), Some("/data"), Some("ro")]
        );
        // A UNC share has no drive colon, so the ordinary split still applies.
        assert_eq!(
            split_short_mount("\\\\server\\share:/data"),
            [Some("\\\\server\\share"), Some("/data"), None]
        );
        assert_eq!(
            split_short_mount("shortvol"),
            [Some("shortvol"), None, None]
        );
        assert_eq!(split_short_mount(""), [Some(""), None, None]);
        assert_eq!(
            split_short_mount("a:b:c:d"),
            [Some("a"), Some("b"), Some("c:d")]
        );
        // `c:data` is not a drive root, so its colon does separate.
        assert_eq!(
            split_short_mount("c:data:/mnt"),
            [Some("c"), Some("data"), Some("/mnt")]
        );
    }

    /// `C:\data:/data` is a bind of a host path, not the volume `C`.
    ///
    /// Measured on Linux before the fix, with `source: C` and `target: \data`
    /// rendered as `type: volume`. The misparse is host-independent — it comes
    /// from splitting text — so the same document is read the same way on every
    /// host now, which is what the comment on `is_host_path` claims.
    #[test]
    fn a_windows_drive_source_is_a_bind_and_not_a_volume() {
        let project = ComposeProject::parse_yaml(
            concat!(
                "name: drive\n",
                "services:\n",
                "  a:\n",
                "    image: busybox\n",
                "    volumes:\n",
                "      - 'C:\\data:/data'\n",
                "      - '\\\\server\\share:/share'\n",
                "      - nv:/named\n",
            ),
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("a Windows-authored document loads on any host");
        let volumes = &project.services["a"].volumes;
        let kinds = volumes
            .iter()
            .map(|mount| (mount.kind, mount.source.as_deref(), mount.target.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                (ComposeMountKind::Bind, Some("C:\\data"), "/data"),
                (ComposeMountKind::Bind, Some("\\\\server\\share"), "/share"),
                (ComposeMountKind::Volume, Some("nv"), "/named"),
            ]
        );
    }

    /// Only a drive *root* names a location. `C:` alone is drive-relative.
    #[test]
    fn only_a_drive_root_or_a_unc_share_is_a_windows_host_path() {
        assert!(is_windows_path("C:\\data"));
        assert!(is_windows_path("c:/data"));
        assert!(is_windows_path("\\\\server\\share"));
        assert!(!is_windows_path("C:"));
        assert!(!is_windows_path("nv"));
        assert!(!is_windows_path("CC:\\data"));
        assert!(is_host_path("C:\\data"));
        assert!(!is_host_path("nv"));
    }

    /// A resolved `env_file` key is the `/`-spelled text on every platform.
    ///
    /// The join is what makes this a portability test rather than a Linux one:
    /// on Windows `directory.join(candidate)` produces a `\`, and the key is
    /// what a caller's `env_files` map is indexed by. `key_spelling` then puts
    /// it back to `/`, so the same text works on both.
    #[test]
    fn a_resolved_file_key_is_spelled_the_same_way_on_every_host() {
        let directory = std::path::Path::new("/p");
        assert_eq!(resolve_against(directory, "app.env"), "/p/app.env");
        assert_eq!(
            resolve_against(directory, "nested/app.env"),
            "/p/nested/app.env"
        );
        // A file named with no directory component resolves against `.`, and
        // both sides of the lookup spell it the same way.
        assert_eq!(
            resolve_against(std::path::Path::new("."), "app.env"),
            key_spelling("./app.env")
        );
    }

    /// A rooted declared path is the path the author wrote, on every host.
    ///
    /// This is the case `is_absolute` got wrong. On Windows `/secrets/app.env`
    /// has a root and no drive, so it is not absolute, and joining it produced
    /// `\secrets\app.env` — a *different* file, resolved against whatever drive
    /// the process happens to have current. The expectation is one string, so
    /// this test is the same assertion on both hosts and fails on Windows
    /// without the fix.
    #[test]
    fn a_rooted_declared_path_is_never_rebased_onto_the_directory() {
        assert_eq!(
            resolve_against(std::path::Path::new("/p"), "/secrets/app.env"),
            "/secrets/app.env"
        );
    }

    /// A drive-rooted declared path is kept as written too.
    ///
    /// This half is gated because on Unix `C:\secrets\app.env` is a *relative*
    /// path — a filename that happens to contain a backslash — so it resolves
    /// against the directory and comes out as `/p/C:\secrets\app.env`. That is
    /// right for a Unix host, which has no such drive; the drive half of the
    /// rule only has anything to say on a host that has drives.
    #[cfg(windows)]
    #[test]
    fn a_drive_rooted_declared_path_is_kept_as_written() {
        assert_eq!(
            resolve_against(std::path::Path::new("C:\\p"), "C:\\secrets\\app.env"),
            "C:/secrets/app.env"
        );
    }

    /// The spelling rewrite is the host separator, never a bare `/`.
    ///
    /// On Unix a backslash is a character in a filename, so `key_spelling` there
    /// is the identity and a file named `back\slash.env` keeps its own key. On
    /// Windows it is the separator, so the same text and a `/`-spelled one are
    /// one key. Only the Windows half can be asserted here; the Unix half is
    /// the identity and is what every Linux run of this suite has been checking
    /// all along.
    #[test]
    fn a_backslash_is_only_a_separator_on_a_host_that_says_so() {
        if std::path::MAIN_SEPARATOR == '/' {
            assert_eq!(key_spelling("/p\\app.env"), "/p\\app.env");
            assert_eq!(key_spelling("C:\\p\\app.env"), "C:\\p\\app.env");
        } else {
            assert_eq!(key_spelling("/p\\app.env"), "/p/app.env");
            assert_eq!(key_spelling("C:\\p\\app.env"), "C:/p/app.env");
        }
    }
}
