#![allow(
    clippy::format_collect,
    clippy::missing_panics_doc,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

//! Deterministic, daemon-free Compose lifecycle plans and policy gates.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plan_yaml;
use crate::{ComposeBuild, ComposeError, ComposeMountKind, ComposeProject};

/// Compose project ownership label key applied to every created resource.
pub const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
/// Compose service ownership label key applied to service containers.
pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
/// Compose implementation label key applied to every created resource.
pub const COMPOSE_VERSION_LABEL: &str = "com.docker.compose.version";
/// Compose implementation label value written by this implementation.
pub const COMPOSE_VERSION_VALUE: &str = "neotales";
/// Configuration digest label used to detect Compose configuration drift.
pub const COMPOSE_CONFIG_DIGEST_LABEL: &str = "com.neotales.compose.config-digest";
/// One-based container number label key.
pub const COMPOSE_CONTAINER_NUMBER_LABEL: &str = "com.docker.compose.container-number";
/// One-off container marker label key.
pub const COMPOSE_ONEOFF_LABEL: &str = "com.docker.compose.oneoff";
/// One-off container marker value used for project containers.
pub const COMPOSE_ONEOFF_VALUE: &str = "False";
/// Primary network label key.
pub const COMPOSE_NETWORK_LABEL: &str = "com.docker.compose.network";
/// Dependency service list label key.
pub const COMPOSE_DEPENDS_ON_LABEL: &str = "com.docker.compose.depends-on";
/// Compose network key attached to services that declare no network.
pub const COMPOSE_DEFAULT_NETWORK_KEY: &str = "default";

/// The explicit Engine intent represented by one plan operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposePlanOperationKind {
    /// Pull an image.
    PullImage,
    /// Build an image.
    BuildImage,
    /// Create a project network.
    CreateNetwork,
    /// Create a project volume.
    CreateVolume,
    /// Create a service container.
    CreateContainer,
    /// Start a service container.
    StartContainer,
    /// Stop a service container.
    StopContainer,
    /// Restart a service container.
    RestartContainer,
    /// Kill a service container.
    KillContainer,
    /// Pause a service container.
    PauseContainer,
    /// Unpause a service container.
    UnpauseContainer,
    /// Remove a service container.
    RemoveContainer,
    /// Remove a project network.
    RemoveNetwork,
    /// Remove a project volume.
    RemoveVolume,
}

impl ComposePlanOperationKind {
    /// Returns whether this operation mutates or removes an existing resource.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::RemoveContainer | Self::RemoveNetwork | Self::RemoveVolume
        )
    }
}

/// One explicit, serializable operation in a Compose plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposePlanOperation {
    /// Stable operation identifier.
    pub id: String,
    /// Operation kind.
    pub kind: ComposePlanOperationKind,
    /// Engine resource name or image reference.
    pub resource_name: String,
    /// Ownership and user labels for the operation.
    pub labels: BTreeMap<String, String>,
    /// Redacted operation-specific intent.
    pub intent: BTreeMap<String, String>,
    /// Whether the operation removes an existing resource.
    pub destructive: bool,
    /// Whether the operation can affect daemon-visible state.
    pub externally_visible: bool,
}

/// A policy violation raised before a plan can be executed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposePolicyViolation {
    /// Stable policy code.
    pub code: String,
    /// Safe explanation without secret values.
    pub message: String,
    /// Operation that caused the violation.
    pub operation: ComposePlanOperation,
}

/// Explicit gates for operations that can expose the host or daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComposePlanPolicy {
    /// Permit bind mounts from the host.
    pub allow_host_paths: bool,
    /// Permit device requests.
    pub allow_devices: bool,
    /// Permit privileged services and capabilities.
    pub allow_privileged_services: bool,
    /// Permit host-published ports.
    pub allow_published_ports: bool,
    /// Permit image pulls.
    pub allow_image_pulls: bool,
    /// Permit build contexts.
    pub allow_build_contexts: bool,
    /// Permit mounts of a Docker socket.
    pub allow_docker_socket_mounts: bool,
}

impl Default for ComposePlanPolicy {
    fn default() -> Self {
        Self {
            allow_host_paths: false,
            allow_devices: false,
            allow_privileged_services: false,
            allow_published_ports: false,
            allow_image_pulls: true,
            allow_build_contexts: false,
            allow_docker_socket_mounts: false,
        }
    }
}

impl ComposePlanPolicy {
    /// Returns a policy with every host-impacting gate explicitly enabled.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            allow_host_paths: true,
            allow_devices: true,
            allow_privileged_services: true,
            allow_published_ports: true,
            allow_image_pulls: true,
            allow_build_contexts: true,
            allow_docker_socket_mounts: true,
        }
    }

    /// Evaluates one operation without contacting a daemon.
    #[must_use]
    pub fn evaluate(&self, operation: &ComposePlanOperation) -> Option<ComposePolicyViolation> {
        let denied = (operation.kind == ComposePlanOperationKind::PullImage
            && !self.allow_image_pulls)
            || (operation.intent.contains_key("hostPath") && !self.allow_host_paths)
            || (operation.intent.contains_key("device") && !self.allow_devices)
            || (operation.intent.contains_key("privileged") && !self.allow_privileged_services)
            || (operation.intent.contains_key("publishedPort") && !self.allow_published_ports)
            || (operation.intent.contains_key("buildContext") && !self.allow_build_contexts)
            || (operation.intent.contains_key("dockerSocket") && !self.allow_docker_socket_mounts);
        denied.then(|| ComposePolicyViolation {
            code: "CP4001".to_owned(),
            message: format!(
                "policy rejected {:?} for '{}'",
                operation.kind, operation.resource_name
            ),
            operation: operation.clone(),
        })
    }
}

/// Options controlling a local Compose plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComposePlanOptions {
    /// Include image pull operations.
    pub pull_images: bool,
    /// Include start operations after container creation.
    pub start_services: bool,
    /// Include reverse-order teardown operations.
    pub include_down_operations: bool,
    /// Create the implicit `<project>_default` network required by services
    /// that declare no network.
    pub default_network: bool,
    /// Explicit policy gates.
    pub policy: ComposePlanPolicy,
}

impl Default for ComposePlanOptions {
    fn default() -> Self {
        Self {
            pull_images: true,
            start_services: true,
            include_down_operations: false,
            default_network: false,
            policy: ComposePlanPolicy::default(),
        }
    }
}

impl ComposePlanOptions {
    /// Creates options for a create-only plan.
    #[must_use]
    pub const fn create() -> Self {
        Self {
            pull_images: true,
            start_services: false,
            include_down_operations: false,
            default_network: false,
            policy: ComposePlanPolicy {
                allow_host_paths: false,
                allow_devices: false,
                allow_privileged_services: false,
                allow_published_ports: false,
                allow_image_pulls: true,
                allow_build_contexts: false,
                allow_docker_socket_mounts: false,
            },
        }
    }

    /// Creates options for a teardown plan.
    #[must_use]
    pub const fn down() -> Self {
        Self {
            pull_images: false,
            start_services: false,
            include_down_operations: true,
            default_network: false,
            policy: ComposePlanPolicy {
                allow_host_paths: false,
                allow_devices: false,
                allow_privileged_services: false,
                allow_published_ports: false,
                allow_image_pulls: false,
                allow_build_contexts: false,
                allow_docker_socket_mounts: false,
            },
        }
    }

    /// Enables or disables the implicit default network.
    ///
    /// The daemon-free default is `false` so an explicitly modeled project is
    /// planned exactly as written. A caller that executes containers against a
    /// daemon must enable it so services without a declared network still get
    /// a Compose-managed network.
    #[must_use]
    pub const fn with_default_network(mut self, enabled: bool) -> Self {
        self.default_network = enabled;
        self
    }

    /// Creates options for an applied `create` plan.
    #[must_use]
    pub fn applied_create() -> Self {
        Self::create().with_default_network(true)
    }

    /// Creates options for an applied `up` plan.
    #[must_use]
    pub fn applied_up() -> Self {
        Self {
            default_network: true,
            ..Self::default()
        }
    }
}

/// A deterministic, inspectable Compose lifecycle plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposePlan {
    /// Project name.
    pub project_name: String,
    /// SHA-256 digest of the redacted canonical configuration.
    pub configuration_digest: String,
    /// Canonical redacted JSON configuration.
    pub config_json: String,
    /// Ordered operations.
    pub operations: Vec<ComposePlanOperation>,
}

impl ComposePlan {
    /// Serializes the plan as deterministic pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Compose plan must serialize")
    }

    /// Serializes the plan as YAML.
    #[must_use]
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("Compose plan must serialize")
    }
}

/// Builds deterministic lifecycle plans without a Docker client.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComposePlanner;

impl ComposePlanner {
    /// Creates a plan for a normalized project.
    ///
    /// # Errors
    ///
    /// Returns a policy violation before any operation can be executed.
    pub fn create(
        project: &ComposeProject,
        options: ComposePlanOptions,
    ) -> Result<ComposePlan, ComposeError> {
        let config_json = render_config(project, true, &ComposeRenderOptions::default());
        let configuration_digest = digest(&config_json);
        let mut operations = Vec::new();

        // Compose attaches every service without a declared network to
        // `<project>_default`. The network is planned first so creation,
        // rollback, and teardown order stay deterministic.
        if options.default_network && project.uses_default_network() {
            add_operation(
                &mut operations,
                operation(
                    "network",
                    ComposePlanOperationKind::CreateNetwork,
                    project.default_network_name(),
                    resource_labels(project, None, &configuration_digest, &BTreeMap::new()),
                    BTreeMap::new(),
                ),
                options.policy,
            )?;
        }
        for (key, resource) in &project.networks {
            if resource.external || (options.default_network && key == COMPOSE_DEFAULT_NETWORK_KEY)
            {
                continue;
            }
            let name = project.resource_name(key, true);
            let labels = resource_labels(project, None, &configuration_digest, &resource.labels);
            let intent = resource_intent(resource.driver.as_deref());
            add_operation(
                &mut operations,
                operation(
                    "network",
                    ComposePlanOperationKind::CreateNetwork,
                    name,
                    labels,
                    intent,
                ),
                options.policy,
            )?;
        }
        for (key, resource) in &project.volumes {
            if resource.external {
                continue;
            }
            let name = project.resource_name(key, false);
            let labels = resource_labels(project, None, &configuration_digest, &resource.labels);
            let intent = resource_intent(resource.driver.as_deref());
            add_operation(
                &mut operations,
                operation(
                    "volume",
                    ComposePlanOperationKind::CreateVolume,
                    name,
                    labels,
                    intent,
                ),
                options.policy,
            )?;
        }

        for service_name in &project.dependency_order {
            let service = project
                .service(service_name)
                .expect("dependency order only contains declared services");
            let labels = resource_labels(
                project,
                Some(service_name),
                &configuration_digest,
                &service.labels,
            );
            if options.pull_images
                && !matches!(service.pull_policy.as_deref(), Some("never" | "build"))
            {
                let mut intent = BTreeMap::new();
                if let Some(policy) = &service.pull_policy {
                    intent.insert("pull_policy".to_owned(), policy.clone());
                }
                add_operation(
                    &mut operations,
                    operation(
                        "pull",
                        ComposePlanOperationKind::PullImage,
                        service.image.clone(),
                        labels.clone(),
                        intent,
                    ),
                    options.policy,
                )?;
            }
            if let Some(build) = &service.build {
                let mut intent = build_intent(build);
                intent.insert("service".to_owned(), service_name.clone());
                add_operation(
                    &mut operations,
                    operation(
                        "build",
                        ComposePlanOperationKind::BuildImage,
                        service.image.clone(),
                        labels.clone(),
                        intent,
                    ),
                    options.policy,
                )?;
            }
            for replica in 1..=service.replicas {
                let name = project.container_name(service_name, replica);
                let intent = service_intent(service);
                add_operation(
                    &mut operations,
                    operation(
                        "container",
                        ComposePlanOperationKind::CreateContainer,
                        name.clone(),
                        labels.clone(),
                        intent,
                    ),
                    options.policy,
                )?;
                if options.start_services {
                    add_operation(
                        &mut operations,
                        operation(
                            "start",
                            ComposePlanOperationKind::StartContainer,
                            name,
                            labels.clone(),
                            BTreeMap::new(),
                        ),
                        options.policy,
                    )?;
                }
            }
        }

        if options.include_down_operations {
            for service_name in project.dependency_order.iter().rev() {
                let service = project
                    .service(service_name)
                    .expect("dependency order only contains declared services");
                let labels = resource_labels(
                    project,
                    Some(service_name),
                    &configuration_digest,
                    &service.labels,
                );
                for replica in (1..=service.replicas).rev() {
                    add_operation(
                        &mut operations,
                        operation(
                            "remove-container",
                            ComposePlanOperationKind::RemoveContainer,
                            project.container_name(service_name, replica),
                            labels.clone(),
                            BTreeMap::new(),
                        ),
                        options.policy,
                    )?;
                }
            }
            for (key, resource) in project.networks.iter().rev() {
                if resource.external
                    || (options.default_network && key == COMPOSE_DEFAULT_NETWORK_KEY)
                {
                    continue;
                }
                add_operation(
                    &mut operations,
                    operation(
                        "remove-network",
                        ComposePlanOperationKind::RemoveNetwork,
                        project.resource_name(key, true),
                        resource_labels(project, None, &configuration_digest, &resource.labels),
                        BTreeMap::new(),
                    ),
                    options.policy,
                )?;
            }
            if options.default_network && project.uses_default_network() {
                add_operation(
                    &mut operations,
                    operation(
                        "remove-network",
                        ComposePlanOperationKind::RemoveNetwork,
                        project.default_network_name(),
                        resource_labels(project, None, &configuration_digest, &BTreeMap::new()),
                        BTreeMap::new(),
                    ),
                    options.policy,
                )?;
            }
            for (key, resource) in project.volumes.iter().rev() {
                if resource.external {
                    continue;
                }
                add_operation(
                    &mut operations,
                    operation(
                        "remove-volume",
                        ComposePlanOperationKind::RemoveVolume,
                        project.resource_name(key, false),
                        resource_labels(project, None, &configuration_digest, &resource.labels),
                        BTreeMap::new(),
                    ),
                    options.policy,
                )?;
            }
        }

        Ok(ComposePlan {
            project_name: project.name.clone(),
            configuration_digest,
            config_json,
            operations,
        })
    }
}

fn add_operation(
    operations: &mut Vec<ComposePlanOperation>,
    operation: ComposePlanOperation,
    policy: ComposePlanPolicy,
) -> Result<(), ComposeError> {
    if let Some(violation) = policy.evaluate(&operation) {
        return Err(ComposeError::new(
            violation.code,
            violation.message,
            None,
            "$.plan",
        ));
    }
    operations.push(operation);
    Ok(())
}

fn operation(
    prefix: &str,
    kind: ComposePlanOperationKind,
    resource_name: String,
    labels: BTreeMap<String, String>,
    intent: BTreeMap<String, String>,
) -> ComposePlanOperation {
    ComposePlanOperation {
        id: format!("{prefix}:{resource_name}"),
        kind,
        resource_name,
        labels,
        intent,
        destructive: kind.is_destructive(),
        externally_visible: true,
    }
}

fn resource_labels(
    project: &ComposeProject,
    service: Option<&str>,
    digest: &str,
    labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut result = labels
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                if sensitive_name(key) {
                    "<redacted>".to_owned()
                } else {
                    value.clone()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    result.insert(
        "com.docker.compose.project".to_owned(),
        project.name.clone(),
    );
    result.insert(
        "com.docker.compose.version".to_owned(),
        "neotales".to_owned(),
    );
    result.insert(
        "com.neotales.compose.config-digest".to_owned(),
        digest.to_owned(),
    );
    if let Some(service) = service {
        result.insert("com.docker.compose.service".to_owned(), service.to_owned());
    }
    result
}

fn resource_intent(driver: Option<&str>) -> BTreeMap<String, String> {
    driver.map_or_else(BTreeMap::new, |driver| {
        BTreeMap::from([("driver".to_owned(), driver.to_owned())])
    })
}

fn build_intent(build: &ComposeBuild) -> BTreeMap<String, String> {
    let mut intent = BTreeMap::from([
        ("buildContext".to_owned(), build.context.clone()),
        ("noCache".to_owned(), build.no_cache.to_string()),
    ]);
    if let Some(dockerfile) = &build.dockerfile {
        intent.insert("dockerfile".to_owned(), dockerfile.clone());
    }
    if let Some(target) = &build.target {
        intent.insert("target".to_owned(), target.clone());
    }
    if let Some(platform) = &build.platform {
        intent.insert("platform".to_owned(), platform.clone());
    }
    if let Some(pull) = build.pull {
        intent.insert("pull".to_owned(), pull.to_string());
    }
    // Build arguments and labels are deliberately absent: the intent map is
    // rendered by `compose plan`, so a secret value must never reach it.
    intent
}

fn service_intent(service: &crate::ComposeProjectService) -> BTreeMap<String, String> {
    let mut intent = BTreeMap::new();
    if service.ports.iter().any(|port| port.published.is_some()) {
        intent.insert("publishedPort".to_owned(), "true".to_owned());
    }
    if service.has_bind_mount() {
        intent.insert("hostPath".to_owned(), "true".to_owned());
    }
    if service.volumes.iter().any(|mount| {
        mount
            .source
            .as_deref()
            .is_some_and(|source| matches!(source, "/var/run/docker.sock" | "/run/docker.sock"))
    }) {
        intent.insert("dockerSocket".to_owned(), "true".to_owned());
    }
    if service.privileged {
        intent.insert("privileged".to_owned(), "true".to_owned());
    }
    if service.build.is_some() {
        intent.insert("buildContext".to_owned(), "true".to_owned());
    }
    if service
        .volumes
        .iter()
        .any(|mount| mount.kind == ComposeMountKind::Tmpfs)
    {
        intent.insert("tmpfs".to_owned(), "true".to_owned());
    }
    intent
}

/// Renders the normalized project as canonical, secret-safe JSON.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComposeConfigRenderer;

/// How a normalized project is rendered for `compose config`.
///
/// The directory matters because a relative `volumes:` source is resolved against
/// it: Docker's `config` prints an absolute path, and a document that printed
/// `./data` would mean a different directory the next time it was loaded from
/// somewhere else.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeRenderOptions<'a> {
    /// Directory a relative path in the document resolves against.
    pub project_directory: Option<&'a std::path::Path>,
}

impl ComposeConfigRenderer {
    /// Renders a project with sensitive environment, label, build-argument,
    /// and resource-label values replaced by `<redacted>`.
    #[must_use]
    pub fn render(project: &ComposeProject) -> String {
        render_config(project, true, &ComposeRenderOptions::default())
    }

    /// Renders a project with the paths a caller would resolve them against.
    #[must_use]
    pub fn render_with(project: &ComposeProject, options: &ComposeRenderOptions<'_>) -> String {
        render_config(project, true, options)
    }

    /// Renders a project as YAML in the Docker CLI's style.
    ///
    /// This is the form `compose config` prints by default, and it is not the
    /// same document as [`Self::render`]: the key order is Compose's own rather
    /// than alphabetical, sequences are indented under their key, and a scalar
    /// is quoted only where a plain one would be read as something else. The JSON
    /// form stays alphabetical because it is machine-read, and this one is not,
    /// which is why the two are separate functions rather than one format
    /// argument over a shared value.
    #[must_use]
    pub fn render_yaml(project: &ComposeProject) -> String {
        render_yaml_config(project, true, &ComposeRenderOptions::default())
    }

    /// Renders a project as YAML in the Docker CLI's style, resolving relative
    /// paths against a directory.
    #[must_use]
    pub fn render_yaml_with(
        project: &ComposeProject,
        options: &ComposeRenderOptions<'_>,
    ) -> String {
        render_yaml_config(project, true, options)
    }

    /// Renders a project in the Swarm Compose v3 form `docker stack config`
    /// prints.
    ///
    /// This is a *different schema* from the Compose specification, not a
    /// different formatting of the same one, and conflating the two is the reason
    /// `stack config` used to print a document Docker would have refused.
    /// Measured against `docker stack config` on Docker 29.8:
    ///
    /// ```text
    /// $ docker stack config -c stack.yaml
    /// version: "3.13"
    /// services:
    ///   web:
    ///     depends_on:
    ///       - api
    ///     networks:
    ///       private:
    ///         aliases:
    ///           - frontend
    /// networks:
    ///   private: {}
    /// ```
    ///
    /// Four differences, all of them load-bearing:
    ///
    /// - `version:` leads and `name:` is absent, because a v3 file names its
    ///   stack on the command line rather than in the document.
    /// - `depends_on` is a **list** of names, not the specification's mapping of
    ///   a name to `{condition, required}`. The long form does not exist in v3.
    /// - Only *declared* networks appear. The Compose-spec renderer synthesizes
    ///   the project's implicit `default` network, and a v3 file has no such
    ///   concept — a service not attached to a network is attached to none.
    /// - A declared resource renders as the declaration, with no Engine `name:`
    ///   synthesized beside it.
    #[must_use]
    pub fn render_stack_yaml_with(
        project: &ComposeProject,
        options: &ComposeRenderOptions<'_>,
    ) -> String {
        crate::plan_yaml::to_yaml(&render_stack_document(project, true, options))
    }

    /// Returns the SHA-256 digest of the rendered, redacted configuration.
    ///
    /// The digest is the value the `com.neotales.compose.config-digest`
    /// ownership label carries, so a caller that reconciles a live resource can
    /// use exactly the digest the planner would have written.
    #[must_use]
    pub fn digest(project: &ComposeProject) -> String {
        digest(&render_config(
            project,
            true,
            &ComposeRenderOptions::default(),
        ))
    }
}

/// Compose's service key order, measured against Docker 29.8.
///
/// A document declaring every field below was run through `docker compose
/// config`; the sequence Compose printed is this list. It is alphabetical except
/// that `hostname` precedes `healthcheck` — which is compose-go's `ServiceConfig`
/// field order rather than a sort — and `profiles` is printed ahead of all of
/// them. The list is the single source of that order: the renderer builds each
/// service in whatever order is convenient and reorders it here, so a field
/// added to the model cannot land in an arbitrary place in the output.
const SERVICE_KEY_ORDER: &[&str] = &[
    "profiles",
    "annotations",
    "blkio_config",
    "build",
    "cap_add",
    "cap_drop",
    "cgroup_parent",
    "command",
    "configs",
    "container_name",
    "cpu_count",
    "cpu_percent",
    "cpu_period",
    "cpu_quota",
    "cpu_rt_period",
    "cpu_rt_runtime",
    "cpu_shares",
    "cpus",
    "cpuset",
    "credential_spec",
    "depends_on",
    "deploy",
    "device_cgroup_rules",
    "devices",
    "dns",
    "dns_opt",
    "dns_search",
    "domainname",
    "entrypoint",
    "env_file",
    "environment",
    "expose",
    "external_links",
    "extra_hosts",
    "group_add",
    "hostname",
    "healthcheck",
    "image",
    "init",
    "ipc",
    "isolation",
    "label_file",
    "labels",
    "logging",
    "mac_address",
    "mem_limit",
    "mem_reservation",
    "mem_swappiness",
    "memswap_limit",
    "memswap_reservation",
    "network_mode",
    "networks",
    "oom_kill_disable",
    "oom_score_adj",
    "pid",
    "pids_limit",
    "platform",
    "ports",
    "privileged",
    "pull_policy",
    "read_only",
    "replicas",
    "restart",
    "runtime",
    "secrets",
    "security_opt",
    "shm_size",
    "stdin_open",
    "stop_grace_period",
    "stop_signal",
    "storage_opt",
    "sysctls",
    "tmpfs",
    "tty",
    "ulimits",
    "user",
    "userns_mode",
    "uts",
    "volumes",
    "volumes_from",
    "working_dir",
];

/// Renders the project as deterministic pretty JSON.
fn render_config(
    project: &ComposeProject,
    redact: bool,
    options: &ComposeRenderOptions<'_>,
) -> String {
    serde_json::to_string_pretty(
        &render_document(project, redact, options, ComposeDialect::Spec).to_json_value(),
    )
    .expect("normalized Compose project must serialize")
}

/// Renders the project as YAML in the Docker CLI's style.
fn render_yaml_config(
    project: &ComposeProject,
    redact: bool,
    options: &ComposeRenderOptions<'_>,
) -> String {
    plan_yaml::to_yaml(&render_document(
        project,
        redact,
        options,
        ComposeDialect::Spec,
    ))
}

/// Which of the two Compose schemas a rendering is written in.
///
/// The specification renderer is the one place a field's *meaning* is decided, so
/// the two places where the schemas genuinely disagree about the same field —
/// whether a short-form secret reference prints a `target`, and whether a
/// short-form mount prints its sub-mapping — are decided here from the model
/// rather than by a transform that would have to guess which spelling produced the
/// tree in front of it. Everything else that differs between the schemas is a
/// subtraction or a change of one member's shape, which a transform reads off the
/// rendered document correctly; see [`render_stack_document`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ComposeDialect {
    /// The Compose specification, which is what `docker compose config` prints.
    #[default]
    Spec,
    /// The Swarm Compose v3 schema, which is what `docker stack config` prints.
    StackV3,
}

/// The in-container directory a service secret is mounted in, and the name a
/// short-form reference gets there.
///
/// Measured on Docker 29.8: `docker compose config` renders
/// `- {source: s1, target: /run/secrets/s1}` for a service that wrote `- s1`.
const COMPOSE_SECRET_DIRECTORY: &str = "/run/secrets";

/// The version `docker stack config` prints for a document that declared none.
///
/// Measured on Docker 29.8: a v3.8 file came back as `version: "3.8"` and a file
/// with no `version:` came back as `version: "3.13"`. The declared value wins,
/// because that is what a reader is checking, and this is only the fallback.
const DEFAULT_STACK_VERSION: &str = "3.13";

/// The Compose-spec document, reshaped into the Swarm v3 form.
///
/// A transform rather than a second set of render arms. Every field, every quote,
/// every key position and every sequence indent is already decided by
/// [`render_document`]; duplicating that here would be five hundred lines that can
/// drift from the specification rendering on the first change to either. What
/// differs between the two schemas is four things, and they are all subtractions
/// or a change of one member's shape.
fn render_stack_document(
    project: &ComposeProject,
    redact: bool,
    options: &ComposeRenderOptions<'_>,
) -> plan_yaml::OrderedValue {
    use plan_yaml::{OrderedMap, OrderedValue};

    let mut document = match render_document(project, redact, options, ComposeDialect::StackV3) {
        OrderedValue::Mapping(map) => map,
        other => return other,
    };

    // A v3 file names its stack on the command line, so `name:` is not a member
    // of one, and `version:` leads instead.
    document.remove("name");
    let mut root = OrderedMap::new();
    root.insert(
        "version",
        OrderedValue::string(
            project
                .version
                .clone()
                .unwrap_or_else(|| DEFAULT_STACK_VERSION.to_owned()),
        ),
    );
    for (key, value) in document.iter() {
        root.insert(key, clone_value(value));
    }

    // The implicit `default` network is a Compose-spec concept. A v3 service that
    // names no network is attached to none, so the synthesized attachment and the
    // synthesized top-level declaration both come out.
    if let Some(OrderedValue::Mapping(networks)) = root.get("networks").cloned() {
        let mut declared = networks;
        declared.remove(crate::COMPOSE_DEFAULT_NETWORK_KEY);
        if declared.is_empty() {
            root.remove("networks");
        } else {
            root.insert("networks", OrderedValue::Mapping(declared));
        }
    }

    // A resource the document renamed keeps its `name:`; a resource it did not
    // loses the one the renderer synthesized. Measured on Docker 29.8: with
    // `plain: {}`, `named: {name: custom-net}`, and `driven: {driver: overlay}`,
    // `docker stack config` printed `driven: {driver: overlay}`,
    // `named: {name: custom-net}`, and `plain: {}` — so the distinction is
    // exactly "did the author name it", and comparing against the synthesized
    // spelling is what tells the two apart.
    for section in ["networks", "volumes", "configs", "secrets"] {
        let Some(OrderedValue::Mapping(resources)) = root.get(section).cloned() else {
            continue;
        };
        let mut rewritten = OrderedMap::new();
        for (key, resource) in resources.iter() {
            rewritten.insert(
                key,
                match resource {
                    OrderedValue::Mapping(entry) => {
                        let mut entry = entry.clone();
                        let synthesized = format!("{}_{key}", project.name);
                        if entry
                            .get("name")
                            .is_some_and(|value| *value == OrderedValue::string(&synthesized))
                        {
                            entry.remove("name");
                        }
                        OrderedValue::Mapping(entry)
                    }
                    other => clone_value(other),
                },
            );
        }
        if rewritten.is_empty() {
            root.remove(section);
        } else {
            root.insert(section, OrderedValue::Mapping(rewritten));
        }
    }

    // A v3 `ports` entry prints `published` as a bare number where the
    // specification prints it as a string. Measured on Docker 29.8: the same
    // `8080:80` renders as `published: "8080"` under `compose config` and
    // `published: 8080` under `stack config`.
    if let Some(OrderedValue::Mapping(services)) = root.get("services").cloned() {
        let mut converted = OrderedMap::new();
        for (name, service) in services.iter() {
            let mut item = match service {
                OrderedValue::Mapping(map) => map.clone(),
                other => {
                    converted.insert(name, clone_value(other));
                    continue;
                }
            };
            if let Some(OrderedValue::Sequence(ports)) = item.get("ports").cloned() {
                let rewritten = ports
                    .iter()
                    .map(|port| match port {
                        OrderedValue::Mapping(entry) => {
                            let mut entry = entry.clone();
                            if let Some(OrderedValue::String(published)) = entry.get("published")
                                && let Ok(number) = published.parse::<i64>()
                            {
                                entry.replace("published", OrderedValue::Number(number.into()));
                            }
                            OrderedValue::Mapping(entry)
                        }
                        other => clone_value(other),
                    })
                    .collect();
                item.replace("ports", OrderedValue::Sequence(rewritten));
            }
            converted.insert(name, OrderedValue::Mapping(item));
        }
        root.insert("services", OrderedValue::Mapping(converted));
    }

    // `depends_on` in v3 is a list of names. The specification's mapping of a name
    // to `{condition, required}` has no v3 spelling, and Docker's own
    // `stack config` prints the list.
    if let Some(OrderedValue::Mapping(services)) = root.get("services").cloned() {
        let mut converted = OrderedMap::new();
        for (name, service) in services.iter() {
            let mut item = match service {
                OrderedValue::Mapping(map) => map.clone(),
                other => {
                    converted.insert(name, clone_value(other));
                    continue;
                }
            };
            if let Some(OrderedValue::Mapping(dependencies)) = item.get("depends_on").cloned() {
                // Replaced in place: a remove-then-insert would move the member to
                // the end of the service, and Docker's v3 output has it in
                // Compose's own key position.
                item.replace(
                    "depends_on",
                    OrderedValue::Sequence(
                        dependencies
                            .iter()
                            .map(|(name, _)| OrderedValue::string(name))
                            .collect(),
                    ),
                );
            }
            // A service's `replicas` is the Compose specification's spelling and
            // has no v3 equivalent — the count lives in `deploy.replicas`, which is
            // what Docker prints. Emitting both would be a count the v3 reader
            // ignores, and one that disagrees with `deploy` if either was edited.
            item.remove("replicas");
            // A service attached to the synthesized default network shows that
            // attachment as `networks: {default: null}`; v3 has no such network.
            if let Some(OrderedValue::Mapping(attachments)) = item.get("networks").cloned() {
                let mut declared = attachments;
                declared.remove(crate::COMPOSE_DEFAULT_NETWORK_KEY);
                if declared.is_empty() {
                    item.remove("networks");
                } else {
                    item.insert("networks", OrderedValue::Mapping(declared));
                }
            }
            converted.insert(name, OrderedValue::Mapping(item));
        }
        root.insert("services", OrderedValue::Mapping(converted));
    }
    OrderedValue::Mapping(root)
}

/// Copies an ordered value.
///
/// The transform reads a document it does not own and writes a new one, and the
/// value type has no clone impl because its members are already owned — a
/// hand-written copy is the price of that, and it is four arms.
fn clone_value(value: &plan_yaml::OrderedValue) -> plan_yaml::OrderedValue {
    use plan_yaml::{OrderedMap, OrderedValue};
    match value {
        OrderedValue::Null => OrderedValue::Null,
        OrderedValue::Bool(inner) => OrderedValue::Bool(*inner),
        OrderedValue::Number(inner) => OrderedValue::Number(inner.clone()),
        OrderedValue::String(inner) => OrderedValue::String(inner.clone()),
        OrderedValue::Sequence(items) => {
            OrderedValue::Sequence(items.iter().map(clone_value).collect())
        }
        OrderedValue::Mapping(map) => OrderedValue::Mapping(
            map.iter()
                .map(|(key, inner)| (key.to_owned(), clone_value(inner)))
                .collect::<OrderedMap>(),
        ),
    }
}

/// Builds the rendered document, with every mapping in Compose's own key order.
///
/// This is the one place the rendered document is described. The JSON and YAML
/// renderings are two encodings of the value this returns, so a field added here
/// reaches both without either one being able to drift from the other.
fn render_document(
    project: &ComposeProject,
    redact: bool,
    options: &ComposeRenderOptions<'_>,
    dialect: ComposeDialect,
) -> plan_yaml::OrderedValue {
    let mut root = crate::plan_yaml::OrderedMap::new();
    root.insert(
        "name",
        crate::plan_yaml::OrderedValue::string(&project.name),
    );
    // Docker's implicit network is the document key `default` whose Engine name
    // is `{project}_default`, and every service is attached to it whether or not
    // the document says so. A rendered document that omitted it would, loaded
    // again, produce a different set of networks.
    //
    // The key is `default` rather than the Engine name on purpose: a Compose
    // document names its networks, and `mt_default` in a document would ask for a
    // network literally called `mt_default`.
    let default_network = format!("{}_default", project.name);
    let default_network_key = COMPOSE_DEFAULT_NETWORK_KEY;
    let mut services = crate::plan_yaml::OrderedMap::new();
    for (name, service) in &project.services {
        let mut item = crate::plan_yaml::OrderedMap::new();
        item.insert(
            "image",
            crate::plan_yaml::OrderedValue::string(&service.image),
        );
        insert_if_present(&mut item, "command", json_list(&service.command));
        insert_if_present(&mut item, "entrypoint", json_list(&service.entrypoint));
        // A gated service keeps its gate, so a rendered document loaded again
        // gates the same way. An unconditional service renders no key at all:
        // `profiles: []` would be a spelling nobody writes for "always".
        if !service.profiles.is_empty() {
            item.insert("profiles", json_list(&service.profiles));
        }
        insert_if_present(
            &mut item,
            "environment",
            redacted_map(&service.environment, redact),
        );
        insert_if_present(
            &mut item,
            "ports",
            plan_yaml::OrderedValue::sequence(
                service
                    .ports
                    .iter()
                    .map(|port| {
                        // compose-go's `ServicePortConfig` field order, measured:
                        // name, mode, host_ip, target, published, protocol,
                        // app_protocol. A port with no host address prints no
                        // `host_ip` key at all rather than a null one.
                        let mut entry = crate::plan_yaml::OrderedMap::new();
                        // `mode` is printed even when it is the default, because
                        // Docker prints it: measured, a short-form `8080:80`
                        // renders as `mode: ingress`. A renderer that omitted it
                        // would be relying on a reader's default, which is the
                        // one thing a rendered document should not.
                        entry.insert(
                            "mode",
                            crate::plan_yaml::OrderedValue::string(match port.mode {
                                crate::project::ComposePortMode::Host => "host",
                                crate::project::ComposePortMode::Ingress => "ingress",
                            }),
                        );
                        entry.insert("host_ip", optional_string(port.host_ip.as_deref()));
                        entry.insert(
                            "target",
                            plan_yaml::OrderedValue::from(serde_json::Value::from(port.target)),
                        );
                        entry.insert(
                            // Compose models a published port as a string, so the
                            // reference prints `"8080"` where a bare `8080` would
                            // read back as a number.
                            "published",
                            optional_string(port.published.map(|port| port.to_string()).as_deref()),
                        );
                        entry.insert(
                            "protocol",
                            crate::plan_yaml::OrderedValue::string(port.protocol.as_str()),
                        );
                        compact(&mut entry);
                        plan_yaml::OrderedValue::mapping(entry)
                    })
                    .collect(),
            ),
        );
        insert_if_present(
            &mut item,
            "volumes",
            plan_yaml::OrderedValue::sequence(
                service
                    .volumes
                    .iter()
                    .map(|mount| render_mount(mount, options, dialect))
                    .collect(),
            ),
        );
        if !service.depends_on.is_empty() {
            // A dependency is a mapping, not a scalar: Compose prints
            // `db: {condition: service_started, required: true}`. Measured, and
            // `required` is a field the model carries, so dropping it would
            // render a document that means something weaker than the input.
            let mut entries = crate::plan_yaml::OrderedMap::new();
            for dependency in &service.depends_on {
                let mut entry = crate::plan_yaml::OrderedMap::new();
                entry.insert(
                    "condition",
                    crate::plan_yaml::OrderedValue::string(&dependency.condition),
                );
                entry.insert(
                    "required",
                    crate::plan_yaml::OrderedValue::Bool(dependency.required),
                );
                entries.insert(
                    dependency.service.clone(),
                    plan_yaml::OrderedValue::mapping(entry),
                );
            }
            item.insert("depends_on", plan_yaml::OrderedValue::mapping(entries));
        }
        if service.networks.is_empty() {
            // Docker attaches the project's default network to every service that
            // does not name one, and renders the attachment as `default: null` —
            // null because the network's own definition lives at the top level.
            item.insert(
                "networks",
                plan_yaml::OrderedValue::Mapping(
                    [(
                        default_network_key.to_owned(),
                        plan_yaml::OrderedValue::Null,
                    )]
                    .into_iter()
                    .collect(),
                ),
            );
        } else {
            // A service's networks are a mapping keyed by network name, not a
            // sequence. Measured on Docker 29.8: `docker compose config` prints
            // `networks: {demo_default: {aliases: [a1]}}`, and it *refuses* the
            // sequence-of-objects spelling this renderer used to emit, so that
            // output could not be loaded again by either tool.
            let mut entries = crate::plan_yaml::OrderedMap::new();
            for network in &service.networks {
                entries.insert(
                    network.name.clone(),
                    if network.aliases.is_empty() {
                        plan_yaml::OrderedValue::Null
                    } else {
                        plan_yaml::OrderedValue::Mapping(
                            [("aliases".to_owned(), json_list(&network.aliases))]
                                .into_iter()
                                .collect(),
                        )
                    },
                );
            }
            item.insert("networks", plan_yaml::OrderedValue::Mapping(entries));
        }
        insert_if_present(&mut item, "labels", redacted_map(&service.labels, redact));
        // `replicas: 1` is the default and Docker omits it, so a rendered
        // document of a single-replica service says nothing about scaling.
        if service.replicas != 1 {
            item.insert(
                "replicas",
                plan_yaml::OrderedValue::from(serde_json::Value::from(service.replicas)),
            );
        }
        // Only the reference is rendered. No config or secret material ever
        // enters the model, so there is nothing here to leak.
        //
        // `target` is rendered only when the document wrote one, and the two
        // schemas disagree about the short form of a secret. Measured on 29.8
        // against a service declaring `- c1` and `{source: s1}`:
        //
        // ```text
        // $ docker compose config          $ docker stack config
        //   configs:                          configs:
        //     - source: c1                      - source: c1
        //   secrets:                          secrets:
        //     - source: s1                      - source: s1
        //       target: /run/secrets/s1
        // ```
        //
        // A config's short form has no default to print in either schema. A
        // secret's does in the specification, because the mount lands in
        // `/run/secrets/` and a rendered document that omitted the name would not
        // say where; v3 has no such default and prints only what was written.
        insert_if_present(
            &mut item,
            "configs",
            plan_yaml::OrderedValue::sequence(
                service
                    .configs
                    .iter()
                    .map(|config| {
                        let mut entry = crate::plan_yaml::OrderedMap::new();
                        entry.insert(
                            "source",
                            crate::plan_yaml::OrderedValue::string(&config.source),
                        );
                        if let Some(target) = &config.target {
                            entry.insert("target", crate::plan_yaml::OrderedValue::string(target));
                        }
                        plan_yaml::OrderedValue::mapping(entry)
                    })
                    .collect(),
            ),
        );
        insert_if_present(
            &mut item,
            "secrets",
            plan_yaml::OrderedValue::sequence(
                service
                    .secrets
                    .iter()
                    .map(|secret| {
                        let mut entry = crate::plan_yaml::OrderedMap::new();
                        entry.insert(
                            "source",
                            crate::plan_yaml::OrderedValue::string(&secret.source),
                        );
                        match (&secret.target, dialect) {
                            (Some(target), _) => {
                                entry.insert(
                                    "target",
                                    crate::plan_yaml::OrderedValue::string(target),
                                );
                            }
                            (None, ComposeDialect::Spec) => {
                                entry.insert(
                                    "target",
                                    crate::plan_yaml::OrderedValue::string(format!(
                                        "{COMPOSE_SECRET_DIRECTORY}/{}",
                                        secret.source
                                    )),
                                );
                            }
                            (None, ComposeDialect::StackV3) => {}
                        }
                        plan_yaml::OrderedValue::mapping(entry)
                    })
                    .collect(),
            ),
        );
        if let Some(policy) = &service.pull_policy {
            item.insert(
                "pull_policy",
                crate::plan_yaml::OrderedValue::string(policy),
            );
        }
        if let Some(build) = &service.build {
            item.insert("build", render_build(build, redact));
        }
        // The remaining fields are the ones whose request shape the Engine
        // expresses directly. Each is rendered only when the document set it, so
        // an absent field and a field set to its default do not both appear.
        if !service.expose.is_empty() {
            item.insert("expose", json_list(&service.expose));
        }
        if !service.extra_hosts.is_empty() {
            // The Engine wants `name=address`; both schemas print `name:address`.
            // Measured on 29.8, the same document came back as
            // `extra_hosts: ["host=1.2.3.4"]` under `compose config` and
            // `extra_hosts: ["host:1.2.3.4"]` under `stack config`. Rendered from
            // the model rather than by a transform, because a transform would have
            // to guess which schema produced the tree in front of it.
            item.insert(
                "extra_hosts",
                plan_yaml::OrderedValue::sequence(
                    service
                        .extra_hosts
                        .iter()
                        .map(|host| match dialect {
                            ComposeDialect::Spec => plan_yaml::OrderedValue::string(host),
                            ComposeDialect::StackV3 => {
                                plan_yaml::OrderedValue::string(host.replacen('=', ":", 1))
                            }
                        })
                        .collect(),
                ),
            );
        }
        if !service.cap_add.is_empty() {
            item.insert("cap_add", json_list(&service.cap_add));
        }
        if !service.cap_drop.is_empty() {
            item.insert("cap_drop", json_list(&service.cap_drop));
        }
        // Only `init` is a pointer in compose-go, so it is the only one of these
        // booleans that Compose prints when the document set it to `false`.
        // Measured on Docker 29.8 against a document declaring all five: it
        // printed `init: false` and `read_only: true` and nothing at all for
        // `tty: false`, `stdin_open: false`, `read_only: false` or
        // `privileged: false`. A boolean Compose drops when false is a boolean
        // whose value the rendered document would otherwise assert on its own.
        if service.declared_field("init") {
            item.insert("init", crate::plan_yaml::OrderedValue::Bool(service.init));
        }
        for (key, declared, value) in [
            (
                "read_only",
                service.declared_field("read_only"),
                service.read_only,
            ),
            (
                "privileged",
                service.declared_field("privileged"),
                service.privileged,
            ),
            ("tty", service.declared_field("tty"), service.tty),
            (
                "stdin_open",
                service.declared_field("stdin_open"),
                service.stdin_open,
            ),
        ] {
            if declared && value {
                item.insert(key, crate::plan_yaml::OrderedValue::Bool(value));
            }
        }
        if let Some(restart) = &service.restart {
            // Both spellings are rendered the way they were written. Docker prints
            // `restart: on-failure:3` for the short form, so re-rendering the long
            // form as a mapping would make an equivalent document look different.
            let value = restart.maximum_retry_count.map_or_else(
                || restart.name.clone(),
                |count| format!("{}:{count}", restart.name),
            );
            item.insert("restart", crate::plan_yaml::OrderedValue::string(value));
        }
        if let Some(check) = &service.healthcheck {
            item.insert("healthcheck", render_healthcheck(check));
        }
        if let Some(platform) = &service.platform {
            item.insert("platform", crate::plan_yaml::OrderedValue::string(platform));
        }
        if let Some(logging) = &service.logging {
            let mut entry = crate::plan_yaml::OrderedMap::new();
            if !logging.driver.is_empty() {
                entry.insert(
                    "driver",
                    crate::plan_yaml::OrderedValue::string(&logging.driver),
                );
            }
            if !logging.options.is_empty() {
                entry.insert("options", redacted_map(&logging.options, redact));
            }
            item.insert("logging", plan_yaml::OrderedValue::mapping(entry));
        }
        if let Some(size) = service.shm_size {
            // Compose prints the size in bytes, as a quoted string, because the
            // value it read may have been written as `64m`. Printing the resolved
            // number is what makes the rendered document say what the container
            // will actually get.
            //
            // v3 does not: it prints the document's own spelling back, so `64m`
            // stays `64m` there. The model resolves the size to bytes and does not
            // keep the text, so that rendering cannot be produced from what the
            // model has. Recorded rather than approximated: printing `64MiB` for a
            // document that said `64m` would be a third spelling neither command
            // prints.
            item.insert(
                "shm_size",
                crate::plan_yaml::OrderedValue::string(size.to_string()),
            );
        }
        for (key, values) in [
            ("dns", &service.dns),
            ("dns_search", &service.dns_search),
            ("dns_opt", &service.dns_opt),
            ("group_add", &service.group_add),
            ("security_opt", &service.security_opt),
        ] {
            if !values.is_empty() {
                item.insert(key, json_list(values));
            }
        }
        // The resource limits, each rendered the way Docker renders it. The rule
        // that took measuring: a byte count is a *quoted string* and a bare
        // integer is a number. `mem_limit: 512m` comes out as `"536870912"` and
        // `cpu_shares: 73` as `73`, and a rendered document that mixed the two
        // would not compare equal to one Docker produced.
        for (key, bytes) in [
            ("mem_limit", service.mem_limit),
            ("mem_reservation", service.mem_reservation),
            ("memswap_limit", service.memswap_limit),
            ("memswap_reservation", service.memswap_reservation),
        ] {
            if let Some(bytes) = bytes {
                item.insert(key, json_value_string(&bytes.to_string()).into());
            }
        }
        // `mem_swappiness` is a number the daemon wants as a number but Docker
        // prints quoted, the same as a byte count. It is quoted here for the same
        // reason and not because the value is a size.
        if let Some(swappiness) = service.mem_swappiness {
            item.insert(
                "mem_swappiness",
                json_value_string(&swappiness.to_string()).into(),
            );
        }
        // A bare JSON number, and the reader divided by the same 1e9 it will be
        // multiplied by on the way into the request.
        if let Some(nano) = service.cpus {
            // The division is in `f64` because Docker prints a JSON number and a
            // nano-CPU count divided by 1e9 is not an integer. A count beyond the
            // mantissa would lose its last bits, and no accepted value is near it:
            // a node has at most a few thousand cores.
            #[allow(clippy::cast_precision_loss)]
            let cpus = nano as f64 / 1e9;
            // v3's `cpus` is a string, because Swarm's own field is: measured on
            // 29.8, the same `cpus: "0.5"` came out as `cpus: 0.5` under
            // `compose config` and `cpus: "0.5"` under `stack config`. The number
            // is rendered the same way in both and only the quoting differs.
            item.insert(
                "cpus",
                match dialect {
                    ComposeDialect::Spec => serde_json::json!(cpus).into(),
                    ComposeDialect::StackV3 => plan_yaml::OrderedValue::string(format!("{cpus}")),
                },
            );
        }
        for (key, value) in [
            ("cpu_shares", service.cpu_shares),
            ("cpu_period", service.cpu_period),
            ("cpu_quota", service.cpu_quota),
            ("cpu_count", service.cpu_count),
            ("cpu_percent", service.cpu_percent),
            ("cpu_rt_period", service.cpu_rt_period),
            ("cpu_rt_runtime", service.cpu_rt_runtime),
            ("pids_limit", service.pids_limit),
            ("oom_score_adj", service.oom_score_adj),
        ] {
            if let Some(value) = value {
                item.insert(key, serde_json::json!(value).into());
            }
        }
        // Only when true. Docker prints no key for `oom_kill_disable: false`,
        // because zero and false are "no limit" and "not disabled" respectively —
        // neither is a declaration worth round-tripping.
        if service.oom_kill_disable {
            item.insert("oom_kill_disable", serde_json::json!(true).into());
        }
        for (key, value) in [
            ("cpuset", &service.cpuset),
            ("cgroup_parent", &service.cgroup_parent),
            ("ipc", &service.ipc),
            ("uts", &service.uts),
            ("mac_address", &service.mac_address),
        ] {
            if let Some(value) = value {
                item.insert(key, json_value_string(value).into());
            }
        }
        for (key, values) in [
            ("device_cgroup_rules", &service.device_cgroup_rules),
            ("external_links", &service.external_links),
            ("volumes_from", &service.volumes_from),
        ] {
            if !values.is_empty() {
                item.insert(key, json_list(values));
            }
        }
        if !service.devices.is_empty() {
            item.insert(
                "devices",
                serde_json::Value::Array(
                    service
                        .devices
                        .iter()
                        .map(|device| {
                            serde_json::json!({
                                "source": device.source,
                                "target": device.target,
                                "permissions": device.permissions,
                            })
                        })
                        .collect(),
                )
                .into(),
            );
        }
        if !service.storage_opt.is_empty() {
            item.insert("storage_opt", redacted_map(&service.storage_opt, redact));
        }
        // Both blocks are printed even when empty, because Docker prints `{}` for
        // a declared-but-empty block and omitting the key would make the rendered
        // document load differently from the one that produced it.
        if let Some(blkio) = &service.blkio_config {
            item.insert("blkio_config", render_blkio(blkio).into());
        }
        if let Some(spec) = &service.credential_spec {
            let mut entry = serde_json::Map::new();
            for (key, value) in [
                ("file", &spec.file),
                ("config", &spec.config),
                ("registry", &spec.registry),
            ] {
                if let Some(value) = value {
                    entry.insert(key.to_owned(), json_value_string(value));
                }
            }
            item.insert("credential_spec", serde_json::Value::Object(entry).into());
        }
        if !service.sysctls.is_empty() {
            item.insert("sysctls", redacted_map(&service.sysctls, redact));
        }
        if !service.tmpfs.is_empty() {
            item.insert("tmpfs", redacted_map(&service.tmpfs, redact));
        }
        if !service.ulimits.is_empty() {
            let mut entries = crate::plan_yaml::OrderedMap::new();
            for limit in &service.ulimits {
                // The spelling is the document's, not the model's. Measured on
                // 29.8: `nproc: 65535` comes back as `nproc: 65535` and
                // `{soft: 65535, hard: 65535}` comes back as the mapping, in both
                // schemas. Comparing `soft` against `hard` cannot tell those two
                // apart, which is why the loader records which one was written.
                //
                // A long form that named only one end is not a case Docker has an
                // output for — it refuses the document — so the end that was left
                // open is omitted rather than printed as the sentinel that stands
                // in for it.
                let value = if limit.short_form {
                    plan_yaml::OrderedValue::from(serde_json::Value::from(limit.soft))
                } else {
                    let mut entry = crate::plan_yaml::OrderedMap::new();
                    if limit.soft != i64::MAX {
                        entry.insert(
                            "soft",
                            plan_yaml::OrderedValue::from(serde_json::Value::from(limit.soft)),
                        );
                    }
                    if limit.hard != i64::MAX {
                        entry.insert(
                            "hard",
                            plan_yaml::OrderedValue::from(serde_json::Value::from(limit.hard)),
                        );
                    }
                    plan_yaml::OrderedValue::mapping(entry)
                };
                entries.insert(limit.name.clone(), value);
            }
            item.insert("ulimits", plan_yaml::OrderedValue::Mapping(entries));
        }
        for (key, value) in [
            ("isolation", &service.isolation),
            ("runtime", &service.runtime),
            ("pid", &service.pid),
            ("userns_mode", &service.userns_mode),
            ("network_mode", &service.network_mode),
            ("stop_signal", &service.stop_signal),
            ("domainname", &service.domainname),
            ("user", &service.user),
            ("working_dir", &service.working_dir),
            ("hostname", &service.hostname),
        ] {
            if let Some(value) = value {
                item.insert(key, crate::plan_yaml::OrderedValue::string(value));
            }
        }
        if let Some(name) = &service.container_name {
            item.insert(
                "container_name",
                crate::plan_yaml::OrderedValue::string(name),
            );
        }
        if !service.label_file.is_empty() {
            // `env_file` is deliberately not rendered. Its contents are already
            // in `environment`, because the loader read the file, and that is
            // what Compose prints too: measured on Docker 29.8, a document with
            // `env_file: ./labels.txt` rendered the file's keys under
            // `environment` and printed no `env_file` key. Printing the path as
            // well would name a file the rendered document does not need.
            item.insert(
                "label_file",
                plan_yaml::OrderedValue::sequence(
                    service
                        .label_file
                        .iter()
                        .map(|file| match options.project_directory {
                            Some(directory) => crate::plan_yaml::OrderedValue::string(
                                absolute_path(directory, file),
                            ),
                            None => crate::plan_yaml::OrderedValue::string(file),
                        })
                        .collect(),
                ),
            );
        }
        if let Some(period) = service.stop_grace_period {
            item.insert(
                "stop_grace_period",
                crate::plan_yaml::OrderedValue::string(render_duration(period)),
            );
        }
        if !service.annotations.is_empty() {
            item.insert("annotations", redacted_map(&service.annotations, redact));
        }
        if let Some(deploy) = &service.deploy {
            item.insert("deploy", render_deploy(deploy, redact, dialect));
        }
        services.insert(
            name.clone(),
            plan_yaml::OrderedValue::mapping(ordered_by_service_key(&item)),
        );
    }
    root.insert("services", plan_yaml::OrderedValue::Mapping(services));
    // An empty top-level collection is omitted rather than rendered as `{}`.
    //
    // This is the difference between a document a person can read and one they
    // have to filter. Measured against `docker compose config` on a two-service
    // file, Docker printed `name`, `services`, and `networks` — three keys — while
    // this printed `configs: {}`, `networks: {}`, `secrets: {}`, and `volumes: {}`
    // on top of them, and a `command: []` and `labels: {}` for every service. The
    // information is the same; the signal-to-noise is not, and the whole point of
    // `config` is to be diffed and read.
    // The implicit network is declared at the top level so a rendered document,
    // loaded again, produces the same set of networks rather than a new one.
    //
    // It is declared only when some service is actually attached to it. Measured
    // on 29.8: a document whose only service is gated behind an inactive profile
    // rendered as `name: p3` and `services: {}` with no `networks` key at all, and
    // a document that declared `networks: {default: {driver: bridge}}` alongside a
    // service attached to `other` printed `networks: {other: ...}` — the declared
    // `default` was pruned like any other unreferenced network, not resurrected.
    // Pruning is a Compose-schema rule and the v3 schema has no such rule, so the
    // v3 rendering keeps every declared resource. See [`ReferencedResources`].
    let declared = match dialect {
        ComposeDialect::Spec => ReferencedResources::of(project),
        ComposeDialect::StackV3 => ReferencedResources::everything(project),
    };
    let mut networks = match resource_map(&project.networks, &project.name, redact) {
        plan_yaml::OrderedValue::Mapping(map) => map,
        other => {
            debug_assert!(
                false,
                "resource_map always renders a mapping, got {other:?}"
            );
            crate::plan_yaml::OrderedMap::new()
        }
    };
    networks.retain(|key| declared.networks.contains(key));
    if declared.networks.contains(default_network_key)
        && networks.get(default_network_key).is_none()
    {
        networks.insert(
            default_network_key,
            plan_yaml::OrderedValue::Mapping(
                [(
                    "name".to_owned(),
                    crate::plan_yaml::OrderedValue::string(&default_network),
                )]
                .into_iter()
                .collect(),
            ),
        );
    }
    let networks = plan_yaml::OrderedValue::Mapping(sorted_by_key(&networks));
    insert_if_present(&mut root, "networks", networks);
    insert_if_present(
        &mut root,
        "volumes",
        sorted_map(retained(
            resource_map(&project.volumes, &project.name, redact),
            &declared.volumes,
        )),
    );
    insert_if_present(
        &mut root,
        "secrets",
        sorted_map(retained(
            secret_map(&project.secrets, &project.name, options, redact),
            &declared.secrets,
        )),
    );
    insert_if_present(
        &mut root,
        "configs",
        sorted_map(retained(
            config_map(&project.configs, &project.name, options, redact),
            &declared.configs,
        )),
    );
    plan_yaml::OrderedValue::Mapping(root)
}

/// The top-level resource keys some service in the project still refers to.
///
/// This is the pruning set [`render_document`] filters the top-level
/// `networks`/`volumes`/`secrets`/`configs` blocks with. It is a *rendering*
/// decision rather than a loading one on purpose: the model describes the document
/// as written, so a caller asking "what did this file declare?" still gets every
/// entry, and the pruning is visible in exactly one place — the `config` output
/// that is meant to be comparable with Docker's.
///
/// Measured on Docker 29.8, and the two schemas differ, so this is not a rule that
/// can be applied to the model once:
///
/// ```text
/// $ cat prune.yml            # service `a` uses `used`, and `unused` uses nothing
/// services: {a: {volumes: [used:/u], ...}}
/// networks: {used: {}, unused: {}}
/// volumes:  {used: {}, unused: {}}
///
/// $ docker compose config | grep -c unused   # 0
/// $ docker stack config  | grep -c unused    # 4
/// ```
///
/// `docker compose config` prunes every top-level resource no surviving service
/// refers to, and `docker stack config` keeps them all — a v3 file is a Swarm
/// service definition where an unreferenced volume is still something an operator
/// asked for. An `external: true` resource is pruned by the Compose schema too,
/// measured: a document whose only service referenced nothing rendered as
/// `name`, `services`, and `networks` and nothing else.
///
/// A resource referenced by a service that a later merge or profile gate removed
/// does not keep it alive, because the reference is read from the services that
/// survived, not from the document.
struct ReferencedResources {
    /// Network keys, including the implicit one when a service is attached to it.
    networks: std::collections::BTreeSet<String>,
    /// Named-volume keys a `type: volume` mount names as its source.
    volumes: std::collections::BTreeSet<String>,
    /// Top-level config keys a service mounts.
    configs: std::collections::BTreeSet<String>,
    /// Top-level secret keys a service mounts.
    secrets: std::collections::BTreeSet<String>,
}

impl ReferencedResources {
    /// Collects the references every surviving service makes.
    fn of(project: &ComposeProject) -> Self {
        let mut referenced = Self {
            networks: std::collections::BTreeSet::new(),
            volumes: std::collections::BTreeSet::new(),
            configs: std::collections::BTreeSet::new(),
            secrets: std::collections::BTreeSet::new(),
        };
        // The implicit network exists only where the Compose specification puts
        // it. A v3 service attached to no network is attached to none, and the
        // transform that reshapes the document for v3 strips the synthesized
        // `default` again anyway, so nothing is added to the set here.
        if project.uses_default_network() {
            referenced
                .networks
                .insert(crate::COMPOSE_DEFAULT_NETWORK_KEY.to_owned());
        }
        for service in project.services.values() {
            for network in &service.networks {
                referenced.networks.insert(network.name.clone());
            }
            for mount in &service.volumes {
                // Only a named-volume mount names a top-level volume. A bind's
                // source is a path, and an anonymous mount has none, so counting
                // either would keep a volume whose key happens to look like one.
                if mount.kind != ComposeMountKind::Volume {
                    continue;
                }
                if let Some(source) = &mount.source {
                    referenced.volumes.insert(source.clone());
                }
            }
            for config in &service.configs {
                referenced.configs.insert(config.source.clone());
            }
            for secret in &service.secrets {
                referenced.secrets.insert(secret.source.clone());
            }
        }
        referenced
    }

    /// The set that keeps every declared resource, which is what v3 renders.
    ///
    /// The implicit `default` network is deliberately absent: a v3 document has no
    /// such network, so the renderer must not add one, and the transform strips a
    /// synthesized one for the same reason.
    fn everything(project: &ComposeProject) -> Self {
        Self {
            networks: project.networks.keys().cloned().collect(),
            volumes: project.volumes.keys().cloned().collect(),
            configs: project.configs.keys().cloned().collect(),
            secrets: project.secrets.keys().cloned().collect(),
        }
    }
}

/// Drops the entries a rendering does not refer to from a resource mapping.
fn retained(
    value: plan_yaml::OrderedValue,
    keep: &std::collections::BTreeSet<String>,
) -> plan_yaml::OrderedValue {
    match value {
        plan_yaml::OrderedValue::Mapping(mut map) => {
            map.retain(|key| keep.contains(key));
            plan_yaml::OrderedValue::Mapping(map)
        }
        other => other,
    }
}

/// Alphabetizes a top-level resource mapping, if it is one.
fn sorted_map(value: plan_yaml::OrderedValue) -> plan_yaml::OrderedValue {
    match value {
        plan_yaml::OrderedValue::Mapping(map) => {
            plan_yaml::OrderedValue::Mapping(sorted_by_key(&map))
        }
        other => other,
    }
}

/// Reorders a mapping alphabetically by key.
///
/// The top-level `networks`, `volumes`, `secrets` and `configs` blocks are Go
/// maps in Compose, and `go-yaml` sorts a Go map's keys when it marshals one.
/// Measured: a document declaring `networks: {demo_default: {}}` on top of the
/// implicit `default` printed `default` first, even though the implicit network
/// is the one this renderer adds last.
fn sorted_by_key(map: &plan_yaml::OrderedMap) -> plan_yaml::OrderedMap {
    let mut entries: Vec<(String, plan_yaml::OrderedValue)> = map
        .iter()
        .map(|(key, value)| (key.to_owned(), value.clone()))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries.into_iter().collect()
}

/// Reorders a service mapping into [`SERVICE_KEY_ORDER`].
///
/// A key the list does not name keeps its relative position at the end of the
/// mapping rather than being dropped or panicking, so a field added to
/// [`crate::ComposeProjectService`] without a `SERVICE_KEY_ORDER` entry still
/// renders — visibly out of order, which is the point: the omission shows up in
/// a diff instead of in a rendered document that quietly lost a field.
fn ordered_by_service_key(item: &plan_yaml::OrderedMap) -> plan_yaml::OrderedMap {
    let rank = |key: &str| {
        SERVICE_KEY_ORDER
            .iter()
            .position(|candidate| *candidate == key)
            .unwrap_or(SERVICE_KEY_ORDER.len())
    };
    let mut entries: Vec<(String, plan_yaml::OrderedValue)> = item
        .iter()
        .map(|(key, value)| (key.to_owned(), value.clone()))
        .collect();
    entries.sort_by_key(|(key, _)| rank(key));
    entries.into_iter().collect()
}

/// Renders one long-form mount, in compose-go's `ServiceVolumeConfig` order.
///
/// Measured: `type`, `source`, `target`, `read_only`, `consistency`, `bind`,
/// `volume`, `tmpfs`, `image`. `read_only` appears only when it is true, and the
/// sub-mapping that matches the mount kind is written even when it is empty:
/// Docker prints `bind: {}` for a bind mount and `volume: {}` for a named
/// volume.
fn render_mount(
    mount: &crate::ComposeMount,
    options: &ComposeRenderOptions<'_>,
    dialect: ComposeDialect,
) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    entry.insert(
        "type",
        crate::plan_yaml::OrderedValue::string(mount.kind.as_str()),
    );
    // A named volume's source is a key, not a path, and Docker prints it as the
    // key: measured on 29.8, `- data:/data` renders as `source: data` while a
    // relative bind renders as an absolute path. Resolving a name against the
    // project directory produced `/project/data`, a path to nothing.
    if let Some(source) = mount.source.as_deref() {
        entry.insert(
            "source",
            match mount.kind {
                ComposeMountKind::Bind => resolved_source(options, Some(source)),
                ComposeMountKind::Volume | ComposeMountKind::Tmpfs => {
                    crate::plan_yaml::OrderedValue::string(source)
                }
            },
        );
    }
    entry.insert(
        "target",
        crate::plan_yaml::OrderedValue::string(&mount.target),
    );
    if mount.read_only {
        entry.insert("read_only", crate::plan_yaml::OrderedValue::Bool(true));
    }
    // The sub-mapping is printed when the document has one to print. The short
    // `source:target` spelling has none and Compose synthesizes an empty one, so
    // the loader gives it an empty sub-mapping and `short_form` is what the v3
    // rendering uses to leave it out again: measured on 29.8, `docker compose
    // config` prints `volume: {}` for `- nv:/data` and `docker stack config`
    // prints nothing there.
    if let Some(subtree) = &mount.subtree
        && !(dialect == ComposeDialect::StackV3 && mount.short_form)
    {
        entry.insert(subtree.key(), render_mount_subtree(subtree, dialect));
    }
    plan_yaml::OrderedValue::mapping(entry)
}

/// Renders a mount's sub-mapping, in the member order Compose prints.
///
/// Measured on 29.8 against a document declaring every member: `bind` printed
/// `selinux` before `propagation`, `volume` printed `nocopy` before `subpath`, and
/// `tmpfs` printed `size` before `mode`. `size` is a quoted byte count because
/// Compose's own field is a string, and `mode` is a bare number because Compose
/// reads it as one.
fn render_mount_subtree(
    subtree: &crate::project::ComposeMountSubtree,
    dialect: ComposeDialect,
) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    match subtree {
        crate::project::ComposeMountSubtree::Bind(options) => {
            // v3 has no `selinux` member: measured on 29.8, the same document
            // printed `bind: {selinux: Z, propagation: rshared}` under
            // `compose config` and `bind: {propagation: rshared}` under
            // `stack config`.
            if dialect == ComposeDialect::Spec
                && let Some(selinux) = &options.selinux
            {
                entry.insert("selinux", plan_yaml::OrderedValue::string(selinux));
            }
            if let Some(propagation) = &options.propagation {
                entry.insert("propagation", plan_yaml::OrderedValue::string(propagation));
            }
        }
        crate::project::ComposeMountSubtree::Volume(options) => {
            if let Some(nocopy) = options.nocopy {
                entry.insert("nocopy", plan_yaml::OrderedValue::Bool(nocopy));
            }
            if let Some(subpath) = &options.subpath {
                entry.insert("subpath", plan_yaml::OrderedValue::string(subpath));
            }
        }
        crate::project::ComposeMountSubtree::Tmpfs(options) => {
            if let Some(size) = options.size {
                // The same disagreement as `published`: measured on 29.8, the
                // specification prints `size: "1024"` and v3 prints `size: 1024`,
                // because Compose's own field is a string and Swarm's is not.
                entry.insert(
                    "size",
                    match dialect {
                        ComposeDialect::Spec => plan_yaml::OrderedValue::string(size.to_string()),
                        ComposeDialect::StackV3 => {
                            plan_yaml::OrderedValue::from(serde_json::Value::from(size))
                        }
                    },
                );
            }
            // v3 has no `mode` member at all: measured, the same document printed
            // `mode: 292` under `compose config` and nothing under `stack config`.
            if let Some(mode) = options.mode
                && dialect == ComposeDialect::Spec
            {
                entry.insert(
                    "mode",
                    plan_yaml::OrderedValue::from(serde_json::Value::from(mode)),
                );
            }
        }
    }
    plan_yaml::OrderedValue::Mapping(entry)
}

/// Renders a `healthcheck:` block, in compose-go's `HealthCheckConfig` order.
///
/// Measured on Docker 29.8 against a document declaring all six fields: the CLI
/// printed `test`, `timeout`, `interval`, `retries`, `start_period`,
/// `start_interval`, with `disable` ahead of all of them. `interval` before
/// `timeout` is alphabetical and is *not* what the CLI prints.
fn render_healthcheck(check: &crate::ComposeHealthcheck) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    if check.disable {
        entry.insert("disable", crate::plan_yaml::OrderedValue::Bool(true));
    }
    if !check.test.is_empty() {
        entry.insert("test", json_list(&check.test));
    }
    for (key, value) in [("timeout", &check.timeout), ("interval", &check.interval)] {
        if let Some(value) = value {
            entry.insert(key, crate::plan_yaml::OrderedValue::string(value));
        }
    }
    if let Some(retries) = check.retries {
        entry.insert(
            "retries",
            plan_yaml::OrderedValue::from(serde_json::Value::from(retries)),
        );
    }
    for (key, value) in [
        ("start_period", &check.start_period),
        ("start_interval", &check.start_interval),
    ] {
        if let Some(value) = value {
            entry.insert(key, crate::plan_yaml::OrderedValue::string(value));
        }
    }
    plan_yaml::OrderedValue::mapping(entry)
}

/// Renders a `build:` block, in compose-go's `BuildConfig` order.
///
/// Measured on Docker 29.8: `context`, `dockerfile`, `args`, `labels`,
/// `cache_from`, `no_cache`, `additional_contexts`, `target`. The fields Compose
/// 29.8 no longer accepts — `platform` and `pull` — keep the model's order
/// among themselves at the end, because there is no reference output to order
/// them against.
fn render_build(build: &crate::ComposeBuild, redact: bool) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    entry.insert(
        "context",
        crate::plan_yaml::OrderedValue::string(&build.context),
    );
    if let Some(dockerfile) = &build.dockerfile {
        entry.insert(
            "dockerfile",
            crate::plan_yaml::OrderedValue::string(dockerfile),
        );
    }
    if !build.arguments.is_empty() {
        entry.insert("args", redacted_map(&build.arguments, redact));
    }
    if !build.labels.is_empty() {
        entry.insert("labels", redacted_map(&build.labels, redact));
    }
    if !build.cache_from.is_empty() {
        entry.insert("cache_from", json_list(&build.cache_from));
    }
    if build.no_cache {
        entry.insert("no_cache", crate::plan_yaml::OrderedValue::Bool(true));
    }
    if let Some(target) = &build.target {
        entry.insert("target", crate::plan_yaml::OrderedValue::string(target));
    }
    if let Some(platform) = &build.platform {
        entry.insert("platform", crate::plan_yaml::OrderedValue::string(platform));
    }
    if let Some(pull) = build.pull {
        entry.insert("pull", crate::plan_yaml::OrderedValue::Bool(pull));
    }
    if !build.buildkit.is_empty() {
        entry.insert(
            "buildkit",
            plan_yaml::OrderedValue::sequence(
                build
                    .buildkit
                    .iter()
                    .map(|field| crate::plan_yaml::OrderedValue::string(field.key()))
                    .collect(),
            ),
        );
    }
    plan_yaml::OrderedValue::mapping(entry)
}

/// A string value, or `null` when the document did not set one.
fn optional_string(value: Option<&str>) -> plan_yaml::OrderedValue {
    value.map_or(
        plan_yaml::OrderedValue::Null,
        plan_yaml::OrderedValue::string,
    )
}

/// Drops the keys whose value carries nothing.
///
/// Measured: a published port with no host address prints neither `host_ip` nor
/// `published`, and a null in the middle of a mapping is noise the reference
/// never prints.
fn compact(entry: &mut plan_yaml::OrderedMap) {
    let mut compact = crate::plan_yaml::OrderedMap::new();
    for (key, value) in entry.iter() {
        if !value.is_empty() {
            compact.insert(key.to_owned(), value.clone());
        }
    }
    *entry = compact;
}

/// A volume source as an absolute path, when the project directory is known.
///
/// A relative source is left exactly as written when there is no directory to
/// resolve it against, because inventing an absolute path from the process's
/// working directory would be a guess about where the document will be loaded
/// from — and a guess about *where a secret or a bind is read from* is the one
/// kind of guess worth refusing to make.
fn resolved_source(
    options: &ComposeRenderOptions<'_>,
    source: Option<&str>,
) -> plan_yaml::OrderedValue {
    let Some(source) = source else {
        return plan_yaml::OrderedValue::Null;
    };
    let Some(directory) = options.project_directory else {
        return crate::plan_yaml::OrderedValue::string(source);
    };
    crate::plan_yaml::OrderedValue::string(absolute_path(directory, source))
}

/// Joins a relative path to a directory and prints it the way Compose does.
///
/// Measured: Docker prints `/tmp/project/src` for a document that wrote
/// `./src`, and a plain `Path::join` prints `/tmp/project/./src` — a path that
/// means the same directory but is not the string a reader is comparing against.
/// The `.` components are dropped rather than the path being canonicalized,
/// because canonicalizing would also resolve symlinks, and a rendered document
/// that names a different path than the document did is worse than one that is
/// merely untidy.
///
/// The join is spelled out rather than collected into a `PathBuf` and printed,
/// because printing a `PathBuf` prints the host's separator: a function named
/// `absolute_path` returned `\project\src` on Windows, and re-collecting a
/// rooted-but-prefixless directory produced `\project\src` again, which on
/// Windows is not an absolute path at all but a drive-relative one resolved
/// against whatever drive the process happens to have current.
///
/// A rooted `relative` is returned as written, which is what `is_absolute` did
/// on Unix and what `has_root` does here: a path the author anchored is the
/// path they meant, and re-basing it onto the directory would name a different
/// file. `has_root` rather than `is_absolute` because on Windows the latter
/// also requires a drive prefix, and `/src` — the spelling a Compose document
/// uses for an absolute path — has a root and no prefix. This is the same rule
/// `project::resolve_against` applies to `env_file`, and the two must agree: one
/// names a path in a rendered document, the other names the file a document
/// reads.
///
/// The spelling stays `/` even on a Windows host, where Go's `filepath.Join`
/// would print `\`. One rendering across platforms is what makes two rendered
/// documents comparable, and the two spellings name the same file. It is also
/// unverified against Docker on Windows, which cannot be measured from Linux.
fn absolute_path(directory: &std::path::Path, relative: &str) -> String {
    let path = std::path::Path::new(relative);
    if path.has_root() {
        return relative.to_owned();
    }
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts: Vec<String> = Vec::new();
    for component in directory.components().chain(path.components()) {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::RootDir => rooted = true,
            // The `C:` of `C:\project`. The separator that has to follow it is
            // the root, recorded separately so the two cannot come out reversed.
            std::path::Component::Prefix(prefix_component) => {
                prefix = prefix_component.as_os_str().to_string_lossy().into_owned();
            }
            other => parts.push(other.as_os_str().to_string_lossy().into_owned()),
        }
    }
    // A rooted path with no drive stays rooted rather than being given an
    // invented one. Naming a drive letter would be a guess about which drive a
    // bind or a secret is read from, and that is the one guess this function
    // exists to avoid; a rooted path is already anchored to the root of
    // whichever drive is current, which is what the author asked for.
    let mut joined = prefix;
    if rooted {
        joined.push('/');
    }
    joined.push_str(&parts.join("/"));
    joined
}

/// Renders a nanosecond count back into Compose's duration spelling.
///
/// The round trip matters because a rendered document is meant to be readable and
/// re-loadable. Printing `5000000000` where the author wrote `5s` would be
/// correct and useless; printing `5s` keeps the output looking like the input,
/// which is what someone comparing two documents actually wants.
///
/// The spelling is Go's `time.Duration`, because that is what Compose writes.
/// Measured on Docker 29.8: `120s` comes back as `2m0s`, `90s` as `1m30s`,
/// `3600s` as `1h0m0s`, and `1500ms` as `1.5s`. A duration that carries minutes
/// always carries seconds and a duration that carries hours always carries
/// minutes, which is why the largest-unit rule alone printed `2m` where the
/// reference prints `2m0s`.
fn render_duration(nanos: i64) -> String {
    if nanos == 0 {
        return "0s".to_owned();
    }
    let (sign, magnitude) = if nanos < 0 {
        ("-", nanos.unsigned_abs())
    } else {
        ("", nanos.unsigned_abs())
    };
    if magnitude < 1_000_000_000 {
        // Under a second, Go picks the largest unit that leaves a fraction and
        // prints it: `1500ms` is `1.5s` but `1500000ns` is `1.5ms`.
        for (unit, scale) in [("ms", 1_000_000_u64), ("µs", 1_000), ("ns", 1)] {
            if magnitude >= scale {
                return format!("{sign}{}{unit}", fraction(magnitude, scale));
            }
        }
    }
    let total = magnitude / 1_000_000_000;
    let (hours, rest) = (total / 3_600, total % 3_600);
    let minutes = rest / 60;
    let seconds = seconds_field(magnitude % 60_000_000_000);
    // A duration that carries hours always carries minutes, and one that carries
    // minutes always carries seconds. That is why `120s` is `2m0s` and `3600s`
    // is `1h0m0s` rather than the `2m` and `1h` a largest-unit rule alone gives.
    if hours > 0 {
        format!("{sign}{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{sign}{minutes}m{seconds}s")
    } else {
        format!("{sign}{seconds}s")
    }
}

/// Formats the seconds field of a Go duration: `5`, `1.5`, `0.000001`.
fn seconds_field(nanos: u64) -> String {
    let whole = nanos / 1_000_000_000;
    let remainder = nanos % 1_000_000_000;
    if remainder == 0 {
        return whole.to_string();
    }
    let mut digits = format!("{remainder:09}");
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits}")
}

/// Formats `value / scale` with up to nine decimal places and no trailing zeros.
fn fraction(value: u64, scale: u64) -> String {
    let whole = value / scale;
    let remainder = value % scale;
    if remainder == 0 {
        return whole.to_string();
    }
    // The remainder is in units of `1 / scale`, so it is scaled up to nine
    // decimal places before the trailing zeros come off.
    let mut digits = format!("{:09}", remainder * 1_000_000_000 / scale);
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits}")
}

/// Renders a `deploy:` block.
fn render_deploy(
    deploy: &crate::project::ComposeDeploy,
    redact: bool,
    dialect: ComposeDialect,
) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    // The order here is Compose's own, measured against `docker stack config` on a
    // v3.8 file: mode, replicas, labels, update_config, resources, restart_policy,
    // placement. Rendering in a different order would make an otherwise identical
    // document diff against the reference for no reason.
    if let Some(mode) = deploy.mode {
        entry.insert(
            "mode",
            crate::plan_yaml::OrderedValue::string(match mode {
                crate::project::ComposeDeployMode::Global => "global",
                crate::project::ComposeDeployMode::Replicated => "replicated",
            }),
        );
    }
    if let Some(count) = deploy.replicas {
        entry.insert(
            "replicas",
            plan_yaml::OrderedValue::from(serde_json::Value::from(count)),
        );
    }
    if deploy.replace {
        entry.insert("replace", crate::plan_yaml::OrderedValue::Bool(true));
    }
    if !deploy.labels.is_empty() {
        entry.insert("labels", redacted_map(&deploy.labels, redact));
    }
    if let Some(update) = &deploy.update_config {
        entry.insert("update_config", render_update_config(update));
    }
    if !deploy.limits.is_empty() || !deploy.reservations.is_empty() {
        let mut resources = crate::plan_yaml::OrderedMap::new();
        if !deploy.limits.is_empty() {
            resources.insert("limits", render_resources(&deploy.limits, dialect));
        }
        if !deploy.reservations.is_empty() {
            resources.insert(
                "reservations",
                render_resources(&deploy.reservations, dialect),
            );
        }
        entry.insert("resources", plan_yaml::OrderedValue::Mapping(resources));
    }
    if let Some(policy) = &deploy.restart_policy {
        // A restart policy is a Go map in Compose, so its keys are alphabetical:
        // `condition`, `delay`, `max_attempts`, `window`.
        let mut restart = crate::plan_yaml::OrderedMap::new();
        restart.insert(
            "condition",
            crate::plan_yaml::OrderedValue::string(&policy.name),
        );
        if let Some(count) = policy.maximum_retry_count {
            restart.insert(
                "max_attempts",
                plan_yaml::OrderedValue::from(serde_json::Value::from(count)),
            );
        }
        if let Some(delay) = deploy.restart_delay {
            restart.insert(
                "delay",
                crate::plan_yaml::OrderedValue::string(render_duration(delay)),
            );
        }
        if let Some(window) = deploy.restart_window {
            restart.insert(
                "window",
                crate::plan_yaml::OrderedValue::string(render_duration(window)),
            );
        }
        if let Some(action) = &deploy.restart_failure_action {
            restart.insert(
                "failure_action",
                crate::plan_yaml::OrderedValue::string(action),
            );
        }
        entry.insert(
            "restart_policy",
            plan_yaml::OrderedValue::Mapping(sorted_by_key(&restart)),
        );
    }
    if let Some(placement) = &deploy.placement {
        let mut place = crate::plan_yaml::OrderedMap::new();
        if !placement.constraints.is_empty() {
            place.insert("constraints", json_list(&placement.constraints));
        }
        if !placement.preferences.is_empty() {
            place.insert("preferences", json_list(&placement.preferences));
        }
        if placement.max_replicas_per_node > 0 {
            place.insert(
                "max_replicas_per_node",
                plan_yaml::OrderedValue::from(serde_json::Value::from(
                    placement.max_replicas_per_node,
                )),
            );
        }
        if !place.is_empty() {
            entry.insert("placement", plan_yaml::OrderedValue::Mapping(place));
        }
    }
    if let Some(mode) = &deploy.endpoint_mode {
        entry.insert(
            "endpoint_mode",
            crate::plan_yaml::OrderedValue::string(mode),
        );
    }
    plan_yaml::OrderedValue::mapping(entry)
}

/// Renders a `deploy.resources` map with sizes resolved.
///
/// `memory: 128M` is printed as `"134217728"`, which is what Compose does, and the
/// reason is that a rendered document is meant to be comparable: one that says
/// `128M` and one that says `134217728` describe the same limit, and only one of
/// them can be compared by value.
///
/// A resources map is a Go map, so its keys are alphabetical.
fn render_resources(
    values: &BTreeMap<String, String>,
    dialect: ComposeDialect,
) -> plan_yaml::OrderedValue {
    let mut rendered = crate::plan_yaml::OrderedMap::new();
    for (key, value) in values {
        let entry = if key == "memory" {
            // A value that does not parse is passed through as written rather than
            // refused, because a rendered document should not be the place a
            // document fails to load.
            match crate::project::parse_size_bytes(value, "$.deploy.resources", "$") {
                Ok(bytes) => crate::plan_yaml::OrderedValue::string(bytes.to_string()),
                Err(_) => crate::plan_yaml::OrderedValue::string(value),
            }
        } else if key == "cpus" {
            // v3's `cpus` is a string because Swarm's own field is one. Measured on
            // 29.8, the same `cpus: "0.5"` came out as `cpus: 0.5` under
            // `compose config` and `cpus: "0.5"` under `stack config`. The number
            // is computed the same way in both; only the quoting differs.
            match value.parse::<f64>() {
                Ok(number) => match dialect {
                    ComposeDialect::Spec => {
                        plan_yaml::OrderedValue::from(serde_json::Value::from(number))
                    }
                    ComposeDialect::StackV3 => plan_yaml::OrderedValue::string(format!("{number}")),
                },
                Err(_) => crate::plan_yaml::OrderedValue::string(value),
            }
        } else {
            crate::plan_yaml::OrderedValue::string(value)
        };
        rendered.insert(key.clone(), entry);
    }
    plan_yaml::OrderedValue::Mapping(rendered)
}

/// Renders a `deploy.update_config` or `rollback_config` block.
///
/// compose-go models this as a struct rather than a map, so the order is its
/// field order: `parallelism`, `delay`, `monitor`, `max_failure_ratio`,
/// `failure_action`, `order`. Measured: the CLI printed `parallelism`, `delay`,
/// `failure_action`, `order` for a document that set exactly those four.
fn render_update_config(config: &crate::project::ComposeUpdateConfig) -> plan_yaml::OrderedValue {
    let mut entry = crate::plan_yaml::OrderedMap::new();
    if let Some(parallelism) = config.parallelism {
        entry.insert(
            "parallelism",
            plan_yaml::OrderedValue::from(serde_json::Value::from(parallelism)),
        );
    }
    if let Some(delay) = config.delay {
        entry.insert(
            "delay",
            crate::plan_yaml::OrderedValue::string(render_duration(delay)),
        );
    }
    if let Some(action) = &config.failure_action {
        entry.insert(
            "failure_action",
            crate::plan_yaml::OrderedValue::string(action),
        );
    }
    if let Some(ratio) = &config.max_failure_ratio {
        entry.insert(
            "max_failure_ratio",
            crate::plan_yaml::OrderedValue::string(ratio),
        );
    }
    if let Some(order) = &config.order {
        entry.insert("order", crate::plan_yaml::OrderedValue::string(order));
    }
    plan_yaml::OrderedValue::Mapping(entry)
}

/// A string as a JSON value, for the arms that need one explicitly.
fn json_value_string(value: &str) -> serde_json::Value {
    serde_json::Value::String(value.to_owned())
}

/// Renders a `blkio_config` block.
///
/// The two weights are bare numbers and the four rates are *quoted strings* of a
/// resolved count, and Docker resolves an `iops` rate with a size suffix the same
/// way it resolves a byte rate — measured, `rate: 12m` on `device_read_iops`
/// renders `"12582912"`. The reader has already resolved them to counts.
fn render_blkio(blkio: &crate::project::ComposeBlkioConfig) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    if let Some(weight) = blkio.weight {
        entry.insert("weight".to_owned(), serde_json::json!(weight));
    }
    if !blkio.weight_device.is_empty() {
        entry.insert(
            "weight_device".to_owned(),
            serde_json::Value::Array(
                blkio
                    .weight_device
                    .iter()
                    .map(|device| serde_json::json!({"path": device.path, "weight": device.value}))
                    .collect(),
            ),
        );
    }
    for (key, devices) in [
        ("device_read_bps", &blkio.device_read_bps),
        ("device_read_iops", &blkio.device_read_iops),
        ("device_write_bps", &blkio.device_write_bps),
        ("device_write_iops", &blkio.device_write_iops),
    ] {
        if devices.is_empty() {
            continue;
        }
        entry.insert(
            key.to_owned(),
            serde_json::Value::Array(
                devices
                    .iter()
                    .map(|device| {
                        serde_json::json!({"path": device.path, "rate": device.value.to_string()})
                    })
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(entry)
}

/// Inserts a key only when it carries something.
///
/// Used for every rendered collection, so "absent" and "present but empty" cannot
/// drift apart between two places that both decided to render one.
fn insert_if_present(root: &mut plan_yaml::OrderedMap, key: &str, value: plan_yaml::OrderedValue) {
    if !value.is_empty() {
        root.insert(key.to_owned(), value);
    }
}

/// Renders top-level `configs`.
///
/// Only declarations are rendered. A declared `file` is a path the caller
/// wrote, not its content, so rendering cannot expose a config payload.
///
/// The order is compose-go's `FileObjectConfig` field order, measured: name,
/// file, labels, external. A field the document did not set is omitted rather
/// than rendered as `null` or `false`, because Docker prints neither
/// `external: false` nor `labels: {}` on a declared resource.
fn config_map(
    configs: &BTreeMap<String, crate::ComposeProjectConfig>,
    project_name: &str,
    options: &ComposeRenderOptions<'_>,
    redact: bool,
) -> plan_yaml::OrderedValue {
    let mut rendered = crate::plan_yaml::OrderedMap::new();
    for (key, config) in configs {
        let mut entry = crate::plan_yaml::OrderedMap::new();
        entry.insert(
            "name",
            crate::plan_yaml::OrderedValue::string(engine_name(
                config.name.as_str(),
                key,
                project_name,
                config.external,
            )),
        );
        if let Some(file) = &config.file {
            entry.insert("file", resolved_source(options, Some(file.as_str())));
        }
        if let Some(environment) = &config.environment {
            entry.insert(
                "environment",
                crate::plan_yaml::OrderedValue::string(environment),
            );
        }
        if !config.labels.is_empty() {
            entry.insert("labels", redacted_map(&config.labels, redact));
        }
        if config.external {
            entry.insert("external", crate::plan_yaml::OrderedValue::Bool(true));
        }
        rendered.insert(key.clone(), plan_yaml::OrderedValue::Mapping(entry));
    }
    plan_yaml::OrderedValue::Mapping(rendered)
}

/// Renders top-level `secrets`.
///
/// The model never holds secret material, so a declaration, its declared
/// `file` path, and its labels are all that can be rendered.
fn secret_map(
    secrets: &BTreeMap<String, crate::ComposeProjectSecret>,
    project_name: &str,
    options: &ComposeRenderOptions<'_>,
    redact: bool,
) -> plan_yaml::OrderedValue {
    let mut rendered = crate::plan_yaml::OrderedMap::new();
    for (key, secret) in secrets {
        let mut entry = crate::plan_yaml::OrderedMap::new();
        entry.insert(
            "name",
            crate::plan_yaml::OrderedValue::string(engine_name(
                secret.name.as_str(),
                key,
                project_name,
                secret.external,
            )),
        );
        if let Some(file) = &secret.file {
            entry.insert("file", resolved_source(options, Some(file.as_str())));
        }
        if let Some(environment) = &secret.environment {
            entry.insert(
                "environment",
                crate::plan_yaml::OrderedValue::string(environment),
            );
        }
        if !secret.labels.is_empty() {
            entry.insert("labels", redacted_map(&secret.labels, redact));
        }
        if secret.external {
            entry.insert("external", crate::plan_yaml::OrderedValue::Bool(true));
        }
        rendered.insert(key.clone(), plan_yaml::OrderedValue::Mapping(entry));
    }
    plan_yaml::OrderedValue::Mapping(rendered)
}

/// The Engine name of a declared top-level resource.
///
/// Measured: `docker compose config` printed `name: demo_sec` for a document that
/// declared `secrets: {sec: {file: …}}` and `name: sec` for one that declared
/// `secrets: {sec: {external: true}}`. An external resource keeps the document's
/// own name, because the project prefix is not applied to something the project
/// does not own.
fn engine_name<'a>(
    declared: &'a str,
    key: &'a str,
    project_name: &str,
    external: bool,
) -> std::borrow::Cow<'a, str> {
    if !declared.is_empty() && declared != key {
        return declared.into();
    }
    if external {
        return key.into();
    }
    format!("{project_name}_{key}").into()
}

/// Renders top-level `networks` and `volumes`.
///
/// Measured on Docker 29.8: a declared network printed `name`, `driver`,
/// `labels`, and a declared volume printed `name`, `driver`. Both printed
/// nothing at all for a field the document did not set, so this omits an absent
/// driver, an unset `external`, and an empty `labels` rather than writing
/// `driver: null` and `labels: {}` the way the JSON-only renderer did.
fn resource_map(
    resources: &BTreeMap<String, crate::ComposeProjectResource>,
    project_name: &str,
    redact: bool,
) -> plan_yaml::OrderedValue {
    let mut rendered = crate::plan_yaml::OrderedMap::new();
    for (key, resource) in resources {
        let mut entry = crate::plan_yaml::OrderedMap::new();
        entry.insert(
            "name",
            crate::plan_yaml::OrderedValue::string(engine_name(
                resource.name.as_str(),
                key,
                project_name,
                resource.external,
            )),
        );
        if let Some(driver) = &resource.driver {
            entry.insert("driver", crate::plan_yaml::OrderedValue::string(driver));
        }
        if let Some(file) = &resource.file {
            entry.insert("file", crate::plan_yaml::OrderedValue::string(file));
        }
        if !resource.labels.is_empty() {
            entry.insert("labels", redacted_map(&resource.labels, redact));
        }
        if resource.external {
            entry.insert("external", crate::plan_yaml::OrderedValue::Bool(true));
        }
        rendered.insert(key.clone(), plan_yaml::OrderedValue::Mapping(entry));
    }
    plan_yaml::OrderedValue::Mapping(rendered)
}

/// A Compose mapping whose keys are a Go map, so alphabetical.
///
/// `go-yaml` sorts the keys of a Go map when it marshals one, which is why
/// `environment`, `labels`, `sysctls` and `deploy.resources.limits` come out
/// alphabetized while the blocks Compose models as structs do not. Going through
/// `serde_json::Map` — a `BTreeMap` — reproduces that for free.
fn redacted_map(values: &BTreeMap<String, String>, redact: bool) -> plan_yaml::OrderedValue {
    plan_yaml::OrderedValue::from(serde_json::Value::Object(
        values
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    serde_json::Value::String(if redact && sensitive_name(key) {
                        "<redacted>".to_owned()
                    } else {
                        value.clone()
                    }),
                )
            })
            .collect(),
    ))
}

fn json_list(values: &[String]) -> plan_yaml::OrderedValue {
    plan_yaml::OrderedValue::sequence(values.iter().map(plan_yaml::OrderedValue::string).collect())
}

fn sensitive_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
        "auth",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ComposePlanOperationKind, ComposePlanOptions, ComposePlanPolicy, ComposePlanner,
        absolute_path, render_duration,
    };
    use crate::{
        ComposeConfigRenderer, ComposeProject, ComposeProjectOptions, ComposeRenderOptions,
        InterpolationValues,
    };

    fn project(source: &str) -> ComposeProject {
        ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project")
    }

    #[test]
    fn plan_is_deterministic_and_redacts_secret_values() {
        let project = project(
            "name: demo\nservices:\n  app:\n    image: alpine\n    environment:\n      API_TOKEN: super-secret\n    ports: ['8080:80']\n",
        );
        let policy = ComposePlanPolicy::permissive();
        let first = ComposePlanner::create(
            &project,
            ComposePlanOptions {
                policy,
                ..ComposePlanOptions::default()
            },
        )
        .expect("plan");
        let second = ComposePlanner::create(
            &project,
            ComposePlanOptions {
                policy,
                ..ComposePlanOptions::default()
            },
        )
        .expect("plan");
        assert_eq!(first, second);
        assert!(!first.config_json.contains("super-secret"));
        assert!(!first.to_json().contains("super-secret"));
        assert!(first.config_json.contains("<redacted>"));
        assert_eq!(
            first.operations[0].kind,
            ComposePlanOperationKind::PullImage
        );
    }

    /// A Compose document that exercises every field this crate's model can
    /// represent, and the exact bytes `docker compose config` printed for it on
    /// Docker 29.8.
    ///
    /// This is the parity claim in test form: the expected value was captured
    /// from the CLI, not written by hand, so a change in the renderer that moves
    /// a key, changes a quote style, or changes an indentation shows up as a diff
    /// against a real reference rather than against another reading of the same
    /// intent.
    ///
    /// Two declarations are deliberately absent, because the model cannot
    /// represent what Compose prints for them and guessing would render a
    /// document that means something else:
    ///
    /// * `ports`. Compose always prints `mode: ingress` for a published port, and
    ///   [`crate::ComposePort`] has no field for the mode, so a document using
    ///   `mode: host` would be rendered as `ingress`. `a_published_port_renders_
    ///   the_string_the_reference_prints` pins what is rendered instead.
    /// * `replicas`. The model folds `scale`, a service-level `replicas`, and
    ///   `deploy.replicas` into one count and records the field as declared for
    ///   all three, so the renderer cannot tell a document that asked for a
    ///   service-level `replicas` from one that only set `deploy.replicas`. The
    ///   count is still rendered, under `deploy`, so nothing is lost.
    const PARITY_SOURCE: &str = r#"name: demo
services:
  app:
    image: alpine:3.20
    profiles: [full]
    command: ["sleep", "1"]
    entrypoint: ["/bin/sh", "-c"]
    environment:
      NUMERIC: "1"
      PLAIN: value
      RESEMBLES_NUMBER: "1.5"
      LOOKS_BOOL: "yes"
    volumes:
      - /srv/data:/src:ro
    depends_on:
      db:
        condition: service_started
    networks:
      demo_default:
        aliases: [a1, a2]
    labels:
      com.example.a: b
    pull_policy: always
    extra_hosts: ["host=1.2.3.4"]
    cap_add: [NET_ADMIN]
    cap_drop: [MKNOD]
    read_only: true
    init: false
    privileged: true
    tty: true
    stdin_open: true
    restart: on-failure:3
    healthcheck:
      test: ["CMD", "true"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
    platform: linux/amd64
    logging:
      driver: json-file
      options:
        max-size: 10m
    shm_size: 64m
    dns: [8.8.8.8]
    dns_search: [example.com]
    dns_opt: [ndots:2]
    group_add: ["1000:1000"]
    security_opt: ["label=disable"]
    sysctls:
      net.core.somaxconn: 1024
    ulimits:
      nofile: 65535
    isolation: default
    runtime: runc
    pid: host
    userns_mode: host
    stop_signal: SIGTERM
    domainname: example.com
    stop_grace_period: 120s
    annotations:
      note: hi
    deploy:
      labels:
        com.example: b
      update_config:
        parallelism: 2
        delay: 10s
        failure_action: continue
        order: start-first
      resources:
        limits:
          memory: 128M
          cpus: "0.5"
      restart_policy:
        condition: on-failure
        max_attempts: 3
        delay: 5s
        window: 120s
      placement:
        constraints: ["node.role == worker"]
        max_replicas_per_node: 1
  db:
    image: postgres:16
networks:
  demo_default: {}
"#;

    const PARITY_RENDERED: &str = r#"name: demo
services:
  app:
    profiles:
      - full
    annotations:
      note: hi
    cap_add:
      - NET_ADMIN
    cap_drop:
      - MKNOD
    command:
      - sleep
      - "1"
    depends_on:
      db:
        condition: service_started
        required: true
    deploy:
      labels:
        com.example: b
      update_config:
        parallelism: 2
        delay: 10s
        failure_action: continue
        order: start-first
      resources:
        limits:
          cpus: 0.5
          memory: "134217728"
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 2m0s
      placement:
        constraints:
          - node.role == worker
        max_replicas_per_node: 1
    dns:
      - 8.8.8.8
    dns_opt:
      - ndots:2
    dns_search:
      - example.com
    domainname: example.com
    entrypoint:
      - /bin/sh
      - -c
    environment:
      LOOKS_BOOL: 'yes'
      NUMERIC: "1"
      PLAIN: value
      RESEMBLES_NUMBER: "1.5"
    extra_hosts:
      - host=1.2.3.4
    group_add:
      - 1000:1000
    healthcheck:
      test:
        - CMD
        - "true"
      timeout: 5s
      interval: 30s
      retries: 3
      start_period: 10s
    image: alpine:3.20
    init: false
    isolation: default
    labels:
      com.example.a: b
    logging:
      driver: json-file
      options:
        max-size: 10m
    networks:
      demo_default:
        aliases:
          - a1
          - a2
    pid: host
    platform: linux/amd64
    privileged: true
    pull_policy: always
    read_only: true
    restart: on-failure:3
    runtime: runc
    security_opt:
      - label=disable
    shm_size: "67108864"
    stdin_open: true
    stop_grace_period: 2m0s
    stop_signal: SIGTERM
    sysctls:
      net.core.somaxconn: "1024"
    tty: true
    ulimits:
      nofile: 65535
    userns_mode: host
    volumes:
      - type: bind
        source: /srv/data
        target: /src
        read_only: true
        bind: {}
  db:
    image: postgres:16
    networks:
      default: null
networks:
  default:
    name: demo_default
  demo_default:
    name: demo_demo_default
"#;

    fn parity_project() -> ComposeProject {
        ComposeProject::parse_yaml(
            PARITY_SOURCE,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions {
                profiles: ["*".to_owned()].into_iter().collect(),
                ..ComposeProjectOptions::default()
            },
        )
        .expect("the parity document loads")
    }

    #[test]
    fn the_rendered_yaml_matches_the_docker_cli_byte_for_byte() {
        let rendered = ComposeConfigRenderer::render_yaml_with(
            &parity_project(),
            &ComposeRenderOptions {
                project_directory: None,
            },
        );
        assert_eq!(rendered, PARITY_RENDERED);
    }

    #[test]
    fn the_json_rendering_stays_machine_read_and_alphabetical() {
        let json = ComposeConfigRenderer::render(&parity_project());
        // The JSON form is sorted by key because `serde_json::Map` is a
        // `BTreeMap` in this workspace, which is what keeps it stable to read and
        // to hash. The YAML form is the ordered one, and it is the one a person
        // diffs against Docker.
        let services = json
            .split_once("\"services\"")
            .expect("the rendered document has services")
            .1;
        let environment = services
            .find("\"environment\"")
            .expect("a service environment");
        let image = services.find("\"image\"").expect("a service image");
        assert!(environment < image, "JSON keys are alphabetical");
        assert!(json.contains("\"shm_size\": \"67108864\""));
    }

    #[test]
    fn a_published_port_renders_the_string_the_reference_prints() {
        let project = project(concat!(
            "name: demo\n",
            "services:\n",
            "  app:\n",
            "    image: alpine\n",
            "    ports:\n",
            "      - target: 80\n",
            "        published: \"8080\"\n",
            "        host_ip: 127.0.0.1\n",
            "        protocol: tcp\n",
        ));
        assert_eq!(
            ComposeConfigRenderer::render_yaml(&project),
            concat!(
                "name: demo\n",
                "services:\n",
                "  app:\n",
                "    image: alpine\n",
                "    networks:\n",
                "      default: null\n",
                "    ports:\n",
                // `mode` is printed even though the long form here declared no
                // mode, because Docker prints it: `ingress` is the default, and a
                // rendered document says which one it means rather than leaving
                // the reader to know a default. Measured on a short-form
                // `127.0.0.1:8080:80`.
                "      - mode: ingress\n",
                "        host_ip: 127.0.0.1\n",
                "        target: 80\n",
                "        published: \"8080\"\n",
                "        protocol: tcp\n",
                "networks:\n",
                "  default:\n",
                "    name: demo_default\n",
            )
        );
    }

    #[test]
    fn a_duration_is_written_the_way_go_writes_it() {
        // Measured against `docker compose config`: `120s` is `2m0s`, not `2m`.
        assert_eq!(render_duration(120_000_000_000), "2m0s");
        assert_eq!(render_duration(90_000_000_000), "1m30s");
        assert_eq!(render_duration(3_600_000_000_000), "1h0m0s");
        assert_eq!(render_duration(1_500_000_000), "1.5s");
        assert_eq!(render_duration(1_500_000), "1.5ms");
        assert_eq!(render_duration(0), "0s");
    }

    /// Model fields this renderer accounts for without a `SERVICE_KEY_ORDER`
    /// entry, with the reason each one is not simply rendered.
    ///
    /// This is the list a new [`crate::ComposeProjectService`] field has to be
    /// added to, or given a render arm for, before this test passes again. The
    /// alternative is a field that parses, plans, and deploys correctly and then
    /// vanishes from `compose config` — which is the one failure a config command
    /// cannot have.
    const ACCOUNTED_WITHOUT_A_RENDER_ARM: &[(&str, &str)] = &[
        // The loader has already read the file, so its keys are in `environment`.
        // Compose prints it the same way: the contents, and no `env_file` key.
        ("env_file", "consumed into environment by the loader"),
        // The set the loader uses to tell an absent field from an explicit
        // default. It is never serialized and must never be rendered.
        ("declared", "merge bookkeeping, never part of a document"),
    ];

    #[test]
    fn every_model_field_is_either_rendered_or_accounted_for() {
        // `Debug` prints every field of the model, including the ones the
        // serializer skips, so this sees a field the day it is added and not
        // only the day someone sets it in a fixture.
        let rendered = format!("{:?}", crate::ComposeProjectService::new("alpine"));
        let fields: Vec<&str> = rendered
            .split(['{', ',', '}'])
            .filter_map(|field| field.split_once(':').map(|(name, _)| name.trim()))
            .filter(|name| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            })
            .collect();
        assert!(
            fields.len() > 40,
            "the model field list looks wrong: {fields:?}"
        );
        let unaccounted: Vec<&str> = fields
            .iter()
            .copied()
            .filter(|field| {
                !super::SERVICE_KEY_ORDER.contains(field)
                    && !ACCOUNTED_WITHOUT_A_RENDER_ARM
                        .iter()
                        .any(|(name, _)| name == field)
            })
            .collect();
        assert!(
            unaccounted.is_empty(),
            "every ComposeProjectService field needs a render arm in render_document and a \
             SERVICE_KEY_ORDER entry so it is not dropped and lands in the right place; \
             unaccounted: {unaccounted:?}"
        );
    }

    #[test]
    fn a_key_the_order_list_does_not_name_still_renders() {
        // The failure mode this guards: a field added to the model without a
        // `SERVICE_KEY_ORDER` entry. It must still appear in the document, at the
        // end, rather than being dropped or panicking.
        let mut unordered = crate::plan_yaml::OrderedMap::new();
        unordered.insert("image", crate::plan_yaml::OrderedValue::string("alpine"));
        unordered.insert(
            "a_field_the_order_list_does_not_name",
            crate::plan_yaml::OrderedValue::Bool(true),
        );
        unordered.insert("healthcheck", crate::plan_yaml::OrderedValue::Bool(true));
        assert_eq!(
            crate::plan_yaml::to_yaml(&crate::plan_yaml::OrderedValue::mapping(
                super::ordered_by_service_key(&unordered)
            )),
            concat!(
                "healthcheck: true\n",
                "image: alpine\n",
                "a_field_the_order_list_does_not_name: true\n",
            )
        );
    }

    #[test]
    fn safe_policy_rejects_host_impact_before_execution() {
        let project = project(
            "name: demo\nservices:\n  app:\n    image: alpine\n    volumes: ['./src:/src']\n",
        );
        let error = ComposePlanner::create(&project, ComposePlanOptions::default())
            .expect_err("bind mount rejected");
        assert_eq!(error.code(), "CP4001");
    }

    /// The rendered path is one spelling on every host, and keeps a root.
    ///
    /// Every expectation is the same string the Linux run produced, so this
    /// suite is what says the rendering did not change; the `\` that used to
    /// come out of a collected `PathBuf` on a Windows host is what these pin.
    #[test]
    fn an_absolute_path_is_joined_without_the_hosts_separator_or_a_lost_root() {
        let joined = |directory: &str, relative: &str| {
            absolute_path(std::path::Path::new(directory), relative)
        };
        // The measured case: Docker prints `/tmp/project/src` for `./src`.
        assert_eq!(joined("/tmp/project", "./src"), "/tmp/project/src");
        assert_eq!(joined("/tmp/project", "src"), "/tmp/project/src");
        assert_eq!(joined("/tmp/project", ""), "/tmp/project");
        assert_eq!(
            joined("/tmp/project", "../sibling"),
            "/tmp/project/../sibling"
        );
        // A relative directory stays relative; nothing here invents a root.
        assert_eq!(joined("relative/dir", "src"), "relative/dir/src");
        assert_eq!(joined("", "src"), "src");
        // The filesystem root is a path, not an empty one.
        assert_eq!(joined("/", "src"), "/src");
        assert_eq!(joined("/", ""), "/");
        // A path the author rooted is returned as written, not re-based.
        assert_eq!(joined("/project", "/elsewhere/rel"), "/elsewhere/rel");
        // A directory that is rooted but names no drive stays rooted: before
        // the fix the components were re-collected into a `PathBuf`, which on
        // Windows turned this into the drive-relative `\project\rel`.
        assert_eq!(joined("/project", "rel"), "/project/rel");
    }

    /// A drive-rooted directory keeps the drive, and gains no second separator.
    ///
    /// Gated because Unix has no `Prefix` component, so the case cannot be
    /// constructed there at all; on Unix the same document renders
    /// `/project/rel` from the test above.
    #[cfg(windows)]
    #[test]
    fn a_drive_rooted_directory_renders_as_one_slash_spelled_path() {
        assert_eq!(
            absolute_path(std::path::Path::new("C:\\project"), "./rel"),
            "C:/project/rel"
        );
        assert_eq!(
            absolute_path(std::path::Path::new("C:\\project"), "\\rel"),
            "\\rel",
            "a rooted relative is kept exactly as written"
        );
    }
}
