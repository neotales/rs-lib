//! Typed, daemon-free runtime binding for a normalized Compose project.
//!
//! The planner produces a redacted, serializable description of intent. That
//! is the right artifact to print and to diff, but it is deliberately not an
//! Engine request: environment values, bind sources, and user labels are
//! redacted there. This module produces the opposite projection — the concrete,
//! typed values an Engine request needs — while remaining free of any daemon
//! client. A caller adapts these specs to its own Engine facade.
//!
//! Two properties are deliberate:
//!
//! * Unsupported input is rejected while binding, so no request is issued for
//!   a service that cannot be created.
//! * A resource the project does not own is never adopted. Specs describe
//!   creation only, and every owned name carries the project label.

use std::collections::BTreeMap;

use crate::{
    COMPOSE_CONFIG_DIGEST_LABEL,
    COMPOSE_CONTAINER_NUMBER_LABEL,
    COMPOSE_DEFAULT_NETWORK_KEY,
    COMPOSE_DEPENDS_ON_LABEL,
    COMPOSE_NETWORK_LABEL,
    COMPOSE_ONEOFF_LABEL,
    COMPOSE_ONEOFF_VALUE,
    COMPOSE_PROJECT_LABEL,
    COMPOSE_SERVICE_LABEL,
    COMPOSE_VERSION_LABEL,
    COMPOSE_VERSION_VALUE,
    ComposeError,
    ComposeHealthcheck,
    ComposeLogging,
    ComposeMountKind,
    ComposePlan,
    ComposePlanOperationKind,
    ComposeProject,
    ComposeProjectService,
    ComposeRestart,
    ComposeUlimit,
    // Declared alongside the rest of the model in `project`, and reached by their
    // module path here because `lib.rs` is the only place a crate-root alias is
    // declared and it does not list them yet.
    project::{ComposeBlkioConfig, ComposeCredentialSpec, ComposeDevice},
};

/// One `secrets:` entry and where its bytes come from.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComposeSecretDelivery {
    /// In-container path, under `/run/secrets/` unless the document gave an
    /// absolute `target`.
    pub target: String,
    /// How the bytes are obtained.
    pub source: ComposeSecretSource,
}

/// Where a secret's bytes come from.
///
/// A `file:` secret becomes a read-only bind of the host file, which is what
/// Docker's non-Swarm Compose does — it leaves no Engine secret behind for a
/// file-backed one. An `environment:` secret has no host file, so its bytes are
/// written into the container once it is running; Docker's does the same and its
/// container shows no mount at all, just a 0444 file under `/run/secrets/`.
///
/// Neither form carries the material itself. A `file:` carries a *path* and an
/// `environment:` carries a *variable name*, so no secret value is ever held in a
/// spec that gets rendered into a plan document.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ComposeSecretSource {
    /// A host file, absolute or relative to the project directory.
    File(String),
    /// An environment variable whose value is the secret's contents.
    Environment(String),
}

/// A host port published for one container port.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComposePortPublication {
    /// Optional host address. `None` asks the daemon for the default.
    pub host_ip: Option<String>,
    /// Optional host port. `None` asks the daemon to choose one.
    pub host_port: Option<u16>,
}

/// A container port and every host publication for it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComposePortSpec {
    /// Container port and protocol, such as `80/tcp`.
    pub container_port: String,
    /// Host publications, in declaration order.
    pub publications: Vec<ComposePortPublication>,
}

/// One network attachment requested for a service container.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComposeNetworkAttachment {
    /// Engine network name.
    pub network: String,
    /// DNS aliases registered for the container on this network.
    pub aliases: Vec<String>,
}

/// A typed container-creation request for one Compose replica.
///
/// The booleans are the document's own flags — `privileged`, `read_only`,
/// `init`, `tty`, `stdin_open`, and `oom_kill_disable` — carried flat because
/// each maps to one request field and a wrapper would only make the mapping
/// harder to see.
///
/// Fields the Engine request has no place for are carried anyway, following
/// `isolation`: a service that declares a knob the container will not get must be
/// refusable by name, and silently dropping it is the failure this projection
/// exists to prevent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeContainerSpec {
    /// Plan operation identifier that creates this container.
    pub operation_id: String,
    /// Engine container name.
    pub name: String,
    /// Compose service name.
    pub service: String,
    /// One-based replica number.
    pub replica: u32,
    /// Image reference.
    pub image: String,
    /// Literal command argv. Empty uses the image default.
    pub command: Vec<String>,
    /// Entrypoint override. `None` uses the image default.
    pub entrypoint: Option<Vec<String>>,
    /// Environment entries in `NAME=value` form, in deterministic order.
    pub environment: Vec<String>,
    /// Ownership and user labels written to the Engine request.
    pub labels: BTreeMap<String, String>,
    /// Ports and their host publications, in deterministic order.
    pub ports: Vec<ComposePortSpec>,
    /// Mount specifications in Docker bind form, in declaration order.
    pub binds: Vec<String>,
    /// tmpfs mounts keyed by container target path.
    pub tmpfs: BTreeMap<String, String>,
    /// Restart policy, or `None` when the document did not declare one.
    pub restart: Option<ComposeRestart>,
    /// Health check, or `None` when the document did not declare one.
    pub healthcheck: Option<ComposeHealthcheck>,
    /// Ports the container listens on without publishing them to the host.
    pub expose: Vec<String>,
    /// Extra `/etc/hosts` entries, in the Engine's `name=value` spelling.
    pub extra_hosts: Vec<String>,
    /// Linux capabilities added to the container.
    pub cap_add: Vec<String>,
    /// Linux capabilities removed from the container.
    pub cap_drop: Vec<String>,
    /// Whether the container's root filesystem is mounted read-only.
    pub read_only: bool,
    /// Whether an init process is injected ahead of the service's own.
    pub init: bool,
    /// Stop grace period in nanoseconds, as the Engine's request wants it.
    ///
    /// The conversion from Compose's duration spelling happens while parsing, so
    /// a malformed duration is reported against the field that holds it rather
    /// than becoming a number the Engine rejects with a message naming no field.
    pub stop_grace_period: Option<i64>,
    /// Signal sent to stop the container.
    pub stop_signal: Option<String>,
    /// Logging driver and its options.
    pub logging: Option<ComposeLogging>,
    /// Size of `/dev/shm`, in bytes.
    pub shm_size: Option<i64>,
    /// DNS servers.
    pub dns: Vec<String>,
    /// DNS search domains.
    pub dns_search: Vec<String>,
    /// DNS resolver options.
    pub dns_opt: Vec<String>,
    /// Additional group IDs or names.
    pub group_add: Vec<String>,
    /// Kernel parameters set inside the container.
    pub sysctls: BTreeMap<String, String>,
    /// Per-process resource limits.
    pub ulimits: Vec<ComposeUlimit>,
    /// Security options such as `label=disable`.
    pub security_opt: Vec<String>,
    /// Container technology the service is isolated with.
    ///
    /// Carried so a caller can refuse it by name. The container-create request
    /// has no field for it, and a service that asks to be isolated and is not is a
    /// security-relevant difference that must not pass silently.
    pub isolation: Option<String>,
    /// Runtime the container runs under.
    pub runtime: Option<String>,
    /// PID namespace mode.
    pub pid: Option<String>,
    /// User namespace mode.
    pub userns_mode: Option<String>,
    /// Explicit network mode, when the document asks for one.
    pub network_mode: Option<String>,
    /// Requested replica count, when `deploy:` declared one.
    pub deploy_replicas: Option<u32>,
    /// Network Policy DNS name.
    pub domainname: Option<String>,
    /// `secrets:` entries the caller must deliver into the container.
    ///
    /// These are kept separate from `binds` rather than merged into them,
    /// because delivering one is the caller's job and not the library's: only the
    /// caller knows the project directory a relative path resolves against, and
    /// only the caller holds the host-path policy that decides whether a host file
    /// may be read at all. Merging them here would either resolve the path in the
    /// wrong place or make the policy unreachable.
    pub secrets: Vec<ComposeSecretDelivery>,
    /// Network attachments applied in order.
    pub networks: Vec<ComposeNetworkAttachment>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User specification.
    pub user: Option<String>,
    /// Container hostname.
    pub hostname: Option<String>,
    /// Whether a TTY is requested.
    pub tty: bool,
    /// Whether standard input is kept open.
    pub stdin_open: bool,
    /// Whether the service requests privileged mode.
    pub privileged: bool,
    /// Host devices mapped into the container, in the Engine's own shape.
    pub devices: Vec<ComposeDevice>,
    /// Memory limit, in bytes.
    pub mem_limit: Option<i64>,
    /// Soft memory limit, in bytes.
    pub mem_reservation: Option<i64>,
    /// Kernel swappiness, 0 through 100.
    pub mem_swappiness: Option<i64>,
    /// Total memory-plus-swap limit, in bytes.
    pub memswap_limit: Option<i64>,
    /// Soft memory-plus-swap limit, in bytes.
    ///
    /// Carried for completeness. No Engine `ContainerHostConfig` field takes it,
    /// so a caller mapping this spec has nowhere to put the value; it is here so
    /// the caller can refuse it by name instead of finding it silently gone.
    pub memswap_reservation: Option<i64>,
    /// Available CPU, in nano-CPUs. The Engine's own unit for `cpus`.
    pub nano_cpus: Option<i64>,
    /// Relative CPU weight.
    pub cpu_shares: Option<i64>,
    /// CFS scheduler period, in microseconds.
    pub cpu_period: Option<i64>,
    /// CFS scheduler quota, in microseconds.
    pub cpu_quota: Option<i64>,
    /// CPUs the container may run on, such as `0,1`.
    pub cpuset_cpus: Option<String>,
    /// Number of CPUs the container may use, on Windows hosts only.
    pub cpu_count: Option<i64>,
    /// Usable CPU percentage, on Windows hosts only.
    pub cpu_percent: Option<i64>,
    /// Real-time scheduler period, in microseconds.
    pub cpu_rt_period: Option<i64>,
    /// Real-time scheduler runtime, in microseconds.
    pub cpu_rt_runtime: Option<i64>,
    /// Maximum number of processes and threads.
    pub pids_limit: Option<i64>,
    /// Whether the out-of-memory killer is disabled for the container.
    pub oom_kill_disable: bool,
    /// Out-of-memory score adjustment, from -1000 to 1000.
    pub oom_score_adj: Option<i64>,
    /// Block-I/O tuning.
    pub blkio_config: Option<ComposeBlkioConfig>,
    /// Parent cgroup for the container.
    pub cgroup_parent: Option<String>,
    /// Windows credential specification source.
    pub credential_spec: Option<ComposeCredentialSpec>,
    /// cgroup device-access rules, in the kernel's own spelling.
    pub device_cgroup_rules: Vec<String>,
    /// Links to containers outside this project.
    pub external_links: Vec<String>,
    /// IPC namespace sharing mode.
    pub ipc_mode: Option<String>,
    /// MAC address for the container's first network endpoint.
    pub mac_address: Option<String>,
    /// Storage-driver options for the container's writable layer.
    pub storage_opt: BTreeMap<String, String>,
    /// UTS namespace sharing mode.
    pub uts_mode: Option<String>,
    /// Containers whose volumes are inherited, in the Engine's own spelling.
    pub volumes_from: Vec<String>,
}

impl ComposeContainerSpec {
    /// Returns the container port keys, such as `80/tcp`.
    #[must_use]
    pub fn exposed_ports(&self) -> Vec<String> {
        self.ports
            .iter()
            .map(|port| port.container_port.clone())
            .collect()
    }

    /// Returns the published ports that require a host binding, in order.
    #[must_use]
    pub fn published_ports(&self) -> Vec<(&ComposePortSpec, &ComposePortPublication)> {
        self.ports
            .iter()
            .flat_map(|port| {
                port.publications
                    .iter()
                    .map(move |publication| (port, publication))
            })
            .collect()
    }
}

/// A typed network-creation request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeNetworkSpec {
    /// Plan operation identifier that creates this network.
    pub operation_id: String,
    /// Engine network name.
    pub name: String,
    /// Optional driver name.
    pub driver: Option<String>,
    /// Ownership and user labels written to the Engine request.
    pub labels: BTreeMap<String, String>,
}

/// A typed volume-creation request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeVolumeSpec {
    /// Plan operation identifier that creates this volume.
    pub operation_id: String,
    /// Engine volume name.
    pub name: String,
    /// Optional driver name.
    pub driver: Option<String>,
    /// Ownership and user labels written to the Engine request.
    pub labels: BTreeMap<String, String>,
}

/// The concrete, daemon-free binding between a project and its Engine requests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeRuntime {
    /// Project name used for Engine names and ownership labels.
    pub project_name: String,
    /// Digest of the redacted canonical configuration.
    pub configuration_digest: String,
    /// Network specs keyed by plan operation identifier.
    pub networks: BTreeMap<String, ComposeNetworkSpec>,
    /// Volume specs keyed by plan operation identifier.
    pub volumes: BTreeMap<String, ComposeVolumeSpec>,
    /// Container specs in plan order.
    pub containers: Vec<ComposeContainerSpec>,
}

impl ComposeRuntime {
    /// Builds the runtime binding for a plan.
    ///
    /// Every create operation in the plan must have exactly one matching spec,
    /// and every spec must be reachable from a plan operation. A mismatch is an
    /// error rather than a partially-applied request, because the executor
    /// drives creation by plan operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan and the project disagree or when a
    /// service uses an input this slice cannot express.
    pub fn bind(project: &ComposeProject, plan: &ComposePlan) -> Result<Self, ComposeError> {
        if plan.project_name != project.name {
            return Err(runtime_error(
                "compose_runtime_project_mismatch",
                "the plan and the normalized project describe different projects".to_owned(),
                "$.name",
            ));
        }
        let mut runtime = Self {
            project_name: project.name.clone(),
            configuration_digest: plan.configuration_digest.clone(),
            networks: BTreeMap::new(),
            volumes: BTreeMap::new(),
            containers: Vec::new(),
        };
        runtime.bind_networks(project, plan);
        runtime.bind_volumes(project, plan);
        runtime.bind_containers(project, plan)?;
        runtime.verify(project, plan)?;
        Ok(runtime)
    }

    /// Returns the network spec for a plan operation.
    #[must_use]
    pub fn network(&self, operation_id: &str) -> Option<&ComposeNetworkSpec> {
        self.networks.get(operation_id)
    }

    /// Returns the volume spec for a plan operation.
    #[must_use]
    pub fn volume(&self, operation_id: &str) -> Option<&ComposeVolumeSpec> {
        self.volumes.get(operation_id)
    }

    /// Returns the container spec for a plan operation.
    #[must_use]
    pub fn container(&self, operation_id: &str) -> Option<&ComposeContainerSpec> {
        self.containers
            .iter()
            .find(|container| container.operation_id == operation_id)
    }

    /// Returns the container specs in plan order.
    #[must_use]
    pub fn containers(&self) -> &[ComposeContainerSpec] {
        &self.containers
    }

    fn bind_networks(&mut self, project: &ComposeProject, plan: &ComposePlan) {
        for (key, resource) in &project.networks {
            if resource.external {
                continue;
            }
            if key == COMPOSE_DEFAULT_NETWORK_KEY && !project.uses_default_network() {
                continue;
            }
            let name = project.resource_name(key, true);
            let operation_id = network_operation_id(&name);
            self.networks.insert(
                operation_id.clone(),
                ComposeNetworkSpec {
                    operation_id,
                    name,
                    driver: resource.driver.clone(),
                    labels: resource_labels(project, plan, None, &resource.labels),
                },
            );
        }
        // The implicit `<project>_default` network has no source declaration.
        // It exists only when the plan created it for a service that declares
        // no network of its own.
        let default_name = project.default_network_name();
        let default_operation = network_operation_id(&default_name);
        if !self.networks.contains_key(&default_operation)
            && plan
                .operations
                .iter()
                .any(|operation| operation.id == default_operation)
        {
            self.networks.insert(
                default_operation.clone(),
                ComposeNetworkSpec {
                    operation_id: default_operation,
                    name: default_name,
                    driver: None,
                    labels: resource_labels(project, plan, None, &BTreeMap::new()),
                },
            );
        }
    }

    fn bind_volumes(&mut self, project: &ComposeProject, plan: &ComposePlan) {
        for (key, resource) in &project.volumes {
            if resource.external {
                continue;
            }
            let name = project.resource_name(key, false);
            let operation_id = volume_operation_id(&name);
            self.volumes.insert(
                operation_id.clone(),
                ComposeVolumeSpec {
                    operation_id,
                    name,
                    driver: resource.driver.clone(),
                    labels: resource_labels(project, plan, None, &resource.labels),
                },
            );
        }
    }

    /// Binds one container spec per replica of every service.
    ///
    /// The body is long because the spec is a flat enumeration of the request:
    /// every field is a copy of a model field that is already in the Engine's own
    /// shape, so there is nothing to factor out that would not be one field per
    /// function. Splitting it would move the whole mapping decision — which
    /// field goes where — out of view.
    #[allow(clippy::too_many_lines)]
    fn bind_containers(
        &mut self,
        project: &ComposeProject,
        plan: &ComposePlan,
    ) -> Result<(), ComposeError> {
        for service_name in &project.dependency_order {
            let service = project
                .service(service_name)
                .expect("dependency order only contains declared services");
            let attachments = network_attachments(project, service_name, service)?;
            let mounts = mounts(project, service_name, service)?;
            let depends_on = service
                .depends_on
                .iter()
                .map(|dependency| dependency.service.clone())
                .collect::<Vec<_>>()
                .join(",");
            for replica in 1..=service.replicas {
                let name = project.container_name(service_name, replica);
                let mut labels =
                    resource_labels(project, plan, Some(service_name), &service.labels);
                labels.insert(
                    COMPOSE_CONTAINER_NUMBER_LABEL.to_owned(),
                    replica.to_string(),
                );
                labels.insert(
                    COMPOSE_ONEOFF_LABEL.to_owned(),
                    COMPOSE_ONEOFF_VALUE.to_owned(),
                );
                if !depends_on.is_empty() {
                    labels.insert(COMPOSE_DEPENDS_ON_LABEL.to_owned(), depends_on.clone());
                }
                if let Some(attachment) = attachments.first() {
                    labels.insert(COMPOSE_NETWORK_LABEL.to_owned(), attachment.network.clone());
                }
                self.containers.push(ComposeContainerSpec {
                    operation_id: container_operation_id(&name),
                    name,
                    service: service_name.clone(),
                    replica,
                    image: service.image.clone(),
                    command: service.command.clone(),
                    entrypoint: (!service.entrypoint.is_empty())
                        .then(|| service.entrypoint.clone()),
                    environment: service
                        .environment
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect(),
                    labels,
                    ports: port_specs(service),
                    binds: mounts.binds.clone(),
                    // The service's own `tmpfs:` declarations merge with the ones a
                    // `volumes:` entry asked for, because both end up in the same
                    // request field and a document that sets both means the union.
                    tmpfs: {
                        let mut tmpfs = service.tmpfs.clone();
                        tmpfs.extend(mounts.tmpfs.clone());
                        tmpfs
                    },
                    secrets: mounts.secrets.clone(),
                    networks: attachments.clone(),
                    working_dir: service.working_dir.clone(),
                    user: service.user.clone(),
                    hostname: service.hostname.clone(),
                    restart: service.restart.clone(),
                    healthcheck: service.healthcheck.clone(),
                    expose: service.expose.clone(),
                    extra_hosts: service.extra_hosts.clone(),
                    cap_add: service.cap_add.clone(),
                    cap_drop: service.cap_drop.clone(),
                    read_only: service.read_only,
                    init: service.init,
                    stop_grace_period: service.stop_grace_period,
                    stop_signal: service.stop_signal.clone(),
                    logging: service.logging.clone(),
                    shm_size: service.shm_size,
                    dns: service.dns.clone(),
                    dns_search: service.dns_search.clone(),
                    dns_opt: service.dns_opt.clone(),
                    group_add: service.group_add.clone(),
                    sysctls: service.sysctls.clone(),
                    ulimits: service.ulimits.clone(),
                    security_opt: service.security_opt.clone(),
                    isolation: service.isolation.clone(),
                    runtime: service.runtime.clone(),
                    pid: service.pid.clone(),
                    userns_mode: service.userns_mode.clone(),
                    network_mode: service.network_mode.clone(),
                    domainname: service.domainname.clone(),
                    // `deploy.replicas` and the service's own `replicas` are two
                    // spellings of one number, and Compose honors the `deploy`
                    // form when both are present because that is the one Swarm and
                    // `compose up` scale from.
                    deploy_replicas: service
                        .deploy
                        .as_ref()
                        .and_then(|deploy| deploy.replicas)
                        .or(if service.declared_field("replicas") {
                            Some(service.replicas)
                        } else {
                            None
                        }),
                    tty: service.tty,
                    stdin_open: service.stdin_open,
                    privileged: service.privileged,
                    // The resource limits, devices, and namespace modes are
                    // carried straight across: the model already resolved every
                    // one of them to the unit the Engine request wants, so there
                    // is nothing left to decide here. `cpus` is the one rename —
                    // Compose spells it as a fraction of a CPU and the request
                    // field is a nano-CPU count.
                    devices: service.devices.clone(),
                    mem_limit: service.mem_limit,
                    mem_reservation: service.mem_reservation,
                    mem_swappiness: service.mem_swappiness,
                    memswap_limit: service.memswap_limit,
                    memswap_reservation: service.memswap_reservation,
                    nano_cpus: service.cpus,
                    cpu_shares: service.cpu_shares,
                    cpu_period: service.cpu_period,
                    cpu_quota: service.cpu_quota,
                    cpuset_cpus: service.cpuset.clone(),
                    cpu_count: service.cpu_count,
                    cpu_percent: service.cpu_percent,
                    cpu_rt_period: service.cpu_rt_period,
                    cpu_rt_runtime: service.cpu_rt_runtime,
                    pids_limit: service.pids_limit,
                    oom_kill_disable: service.oom_kill_disable,
                    oom_score_adj: service.oom_score_adj,
                    blkio_config: service.blkio_config.clone(),
                    cgroup_parent: service.cgroup_parent.clone(),
                    credential_spec: service.credential_spec.clone(),
                    device_cgroup_rules: service.device_cgroup_rules.clone(),
                    external_links: service.external_links.clone(),
                    ipc_mode: service.ipc.clone(),
                    mac_address: service.mac_address.clone(),
                    storage_opt: service.storage_opt.clone(),
                    uts_mode: service.uts.clone(),
                    volumes_from: service.volumes_from.clone(),
                });
            }
        }
        Ok(())
    }

    fn verify(&self, project: &ComposeProject, plan: &ComposePlan) -> Result<(), ComposeError> {
        for operation in &plan.operations {
            let bound = match operation.kind {
                ComposePlanOperationKind::CreateNetwork => {
                    self.networks.contains_key(&operation.id)
                }
                ComposePlanOperationKind::CreateVolume => self.volumes.contains_key(&operation.id),
                ComposePlanOperationKind::CreateContainer => {
                    self.container(&operation.id).is_some()
                }
                _ => true,
            };
            if !bound {
                return Err(runtime_error(
                    "compose_runtime_unbound_operation",
                    format!(
                        "plan operation '{}' has no runtime request specification",
                        operation.id
                    ),
                    "$.plan",
                ));
            }
        }
        for container in &self.containers {
            if container.image.trim().is_empty() {
                return Err(runtime_error(
                    "compose_runtime_missing_image",
                    format!("service '{}' has no image to create", container.service),
                    "$.services",
                ));
            }
            for attachment in &container.networks {
                let managed = self
                    .networks
                    .values()
                    .any(|spec| spec.name == attachment.network);
                let external = project.networks.iter().any(|(key, resource)| {
                    resource.external && project.resource_name(key, true) == attachment.network
                });
                if !managed && !external {
                    return Err(runtime_error(
                        "compose_runtime_unplanned_network",
                        format!(
                            "service '{}' attaches to network '{}' which the plan does not create",
                            container.service, attachment.network
                        ),
                        "$.plan",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Resolved mount values for one service.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ComposeMountValues {
    binds: Vec<String>,
    tmpfs: BTreeMap<String, String>,
    secrets: Vec<ComposeSecretDelivery>,
}

/// Returns the plan operation identifier that creates a network.
#[must_use]
pub fn network_operation_id(name: &str) -> String {
    format!("network:{name}")
}

/// Returns the plan operation identifier that creates a volume.
#[must_use]
pub fn volume_operation_id(name: &str) -> String {
    format!("volume:{name}")
}

/// Returns the plan operation identifier that creates a container.
#[must_use]
pub fn container_operation_id(name: &str) -> String {
    format!("container:{name}")
}

fn resource_labels(
    project: &ComposeProject,
    plan: &ComposePlan,
    service: Option<&str>,
    user_labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut labels = user_labels.clone();
    labels.insert(COMPOSE_PROJECT_LABEL.to_owned(), project.name.clone());
    labels.insert(
        COMPOSE_VERSION_LABEL.to_owned(),
        COMPOSE_VERSION_VALUE.to_owned(),
    );
    labels.insert(
        COMPOSE_CONFIG_DIGEST_LABEL.to_owned(),
        plan.configuration_digest.clone(),
    );
    if let Some(service) = service {
        labels.insert(COMPOSE_SERVICE_LABEL.to_owned(), service.to_owned());
    }
    labels
}

fn network_attachments(
    project: &ComposeProject,
    service_name: &str,
    service: &ComposeProjectService,
) -> Result<Vec<ComposeNetworkAttachment>, ComposeError> {
    if service.networks.is_empty() {
        return Ok(vec![ComposeNetworkAttachment {
            network: project.default_network_name(),
            aliases: vec![service_name.to_owned()],
        }]);
    }
    let mut attachments = Vec::with_capacity(service.networks.len());
    for network in &service.networks {
        if !project.networks.contains_key(&network.name) {
            return Err(runtime_error(
                "compose_undeclared_network",
                format!(
                    "service '{service_name}' uses undeclared network '{}'",
                    network.name
                ),
                "$.networks",
            ));
        }
        let mut aliases = network.aliases.clone();
        if service.container_name.is_none() && !aliases.iter().any(|alias| alias == service_name) {
            aliases.insert(0, service_name.to_owned());
        }
        attachments.push(ComposeNetworkAttachment {
            network: project.resource_name(&network.name, true),
            aliases,
        });
    }
    attachments.sort();
    attachments.dedup();
    Ok(attachments)
}

fn port_specs(service: &ComposeProjectService) -> Vec<ComposePortSpec> {
    let mut specs: Vec<ComposePortSpec> = Vec::new();
    for port in &service.ports {
        let container_port = format!("{}/{}", port.target, port.protocol.as_str());
        let Some(published) = port.published else {
            if !specs
                .iter()
                .any(|spec| spec.container_port == container_port)
            {
                specs.push(ComposePortSpec {
                    container_port,
                    publications: Vec::new(),
                });
            }
            continue;
        };
        let publication = ComposePortPublication {
            host_ip: port.host_ip.clone(),
            host_port: Some(published),
        };
        match specs
            .iter_mut()
            .find(|spec| spec.container_port == container_port)
        {
            Some(spec) => {
                if !spec.publications.contains(&publication) {
                    spec.publications.push(publication);
                }
            }
            None => specs.push(ComposePortSpec {
                container_port,
                publications: vec![publication],
            }),
        }
    }
    specs.sort();
    specs
}

fn mounts(
    project: &ComposeProject,
    service_name: &str,
    service: &ComposeProjectService,
) -> Result<ComposeMountValues, ComposeError> {
    let mut values = ComposeMountValues::default();
    for secret in &service.secrets {
        let Some(resource) = project.secrets.get(&secret.source) else {
            return Err(runtime_error(
                "compose_undeclared_secret",
                format!(
                    "service '{service_name}' mounts undeclared secret '{}'",
                    secret.source
                ),
                "$.secrets",
            ));
        };
        // Docker's own non-Swarm Compose does not attach an external secret: it
        // answers "unsupported external secret" and starts nothing. Refusing here
        // is the same answer, and it is the only safe one — silently starting a
        // container whose `/run/secrets/<target>` does not exist is the failure
        // this whole change exists to remove.
        if resource.external {
            return Err(runtime_error(
                "compose_external_secret_not_attached",
                format!(
                    "service '{service_name}' mounts external secret '{}'; Compose does not \
                     attach Engine secrets outside Swarm mode",
                    secret.source
                ),
                "$.secrets",
            ));
        }
        // A short-form reference mounts under the referenced key, which is what
        // `docker compose config` prints as `/run/secrets/<source>`.
        let target = secret_target(secret.target.as_deref(), &secret.source);
        let source = match (resource.environment.as_deref(), resource.file.as_deref()) {
            (Some(variable), _) => ComposeSecretSource::Environment(variable.to_owned()),
            (None, Some(file)) => ComposeSecretSource::File(file.to_owned()),
            // The parser requires exactly one source for a managed resource, so
            // reaching here means the project and the declaration disagree.
            (None, None) => {
                return Err(runtime_error(
                    "compose_secret_without_source",
                    format!(
                        "secret '{}' declares neither a file nor an environment variable",
                        secret.source
                    ),
                    "$.secrets",
                ));
            }
        };
        values
            .secrets
            .push(ComposeSecretDelivery { target, source });
    }
    for mount in &service.volumes {
        match mount.kind {
            ComposeMountKind::Tmpfs => {
                values.tmpfs.insert(mount.target.clone(), String::new());
            }
            ComposeMountKind::Bind => {
                let Some(source) = mount.source.as_deref() else {
                    return Err(runtime_error(
                        "compose_bind_mount_requires_source",
                        format!("service '{service_name}' has a bind mount without a source"),
                        "$.services",
                    ));
                };
                values
                    .binds
                    .push(bind_entry(source, &mount.target, mount.read_only));
            }
            ComposeMountKind::Volume => match mount.source.as_deref() {
                None => values.binds.push(mount.target.clone()),
                Some(source) => {
                    let Some(resource) = project.volumes.get(source) else {
                        return Err(runtime_error(
                            "compose_undeclared_volume",
                            format!("service '{service_name}' mounts undeclared volume '{source}'"),
                            "$.volumes",
                        ));
                    };
                    if resource.external {
                        return Err(runtime_error(
                            "compose_external_volume_not_attached",
                            format!(
                                "service '{service_name}' mounts external volume '{source}'; \
                                 the bounded create slice does not attach external volumes"
                            ),
                            "$.volumes",
                        ));
                    }
                    let resolved = project.resource_name(source, false);
                    values
                        .binds
                        .push(bind_entry(&resolved, &mount.target, mount.read_only));
                }
            },
        }
    }
    Ok(values)
}

/// Where a `secrets:` entry appears inside the container.
///
/// `/run/secrets/` unless the document gave an absolute `target`, which Compose
/// allows and which is the only way to place a secret outside that directory.
/// `None` is the short `- source` form, whose name is the referenced key.
fn secret_target(target: Option<&str>, source: &str) -> String {
    let Some(target) = target else {
        return format!("/run/secrets/{source}");
    };
    if target.starts_with('/') {
        return target.to_owned();
    }
    let name = if target.is_empty() { source } else { target };
    format!("/run/secrets/{name}")
}

fn bind_entry(source: &str, target: &str, read_only: bool) -> String {
    if read_only {
        format!("{source}:{target}:ro")
    } else {
        format!("{source}:{target}")
    }
}

fn runtime_error(code: &str, message: String, path: &str) -> ComposeError {
    ComposeError::new(code, message, None, path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{ComposeRuntime, container_operation_id, network_operation_id};
    use crate::{
        ComposeMount, ComposeMountKind, ComposePlanOptions, ComposePlanPolicy, ComposePlanner,
        ComposeProject, ComposeProjectOptions, InterpolationValues,
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

    fn bind(source: &str) -> Result<ComposeRuntime, crate::ComposeError> {
        let project = project(source);
        let plan = ComposePlanner::create(
            &project,
            ComposePlanOptions {
                policy: ComposePlanPolicy::permissive(),
                ..ComposePlanOptions::default()
            }
            .with_default_network(true),
        )
        .expect("plan");
        ComposeRuntime::bind(&project, &plan)
    }

    #[test]
    fn binding_is_deterministic_and_ordered_by_dependency() {
        let source = "name: demo\nservices:\n  db:\n    image: postgres:16\n  app:\n    image: alpine:3.20\n    depends_on: [db]\n";
        let first = bind(source).expect("binding");
        let second = bind(source).expect("binding");
        assert_eq!(first, second);
        assert_eq!(
            first
                .containers()
                .iter()
                .map(|container| container.name.as_str())
                .collect::<Vec<_>>(),
            ["demo-db-1", "demo-app-1"]
        );
        assert_eq!(
            first
                .network(&network_operation_id("demo_default"))
                .expect("default network")
                .name,
            "demo_default"
        );
    }

    #[test]
    fn ownership_labels_identify_project_service_and_digest() {
        let runtime = bind("name: demo\nservices:\n  app:\n    image: alpine\n").expect("binding");
        let container = runtime
            .container(&container_operation_id("demo-app-1"))
            .expect("app");
        let digest = runtime.configuration_digest.clone();
        assert_eq!(
            container.labels.get("com.docker.compose.project"),
            Some(&"demo".to_owned())
        );
        assert_eq!(
            container.labels.get("com.docker.compose.service"),
            Some(&"app".to_owned())
        );
        assert_eq!(
            container.labels.get("com.docker.compose.container-number"),
            Some(&"1".to_owned())
        );
        assert_eq!(
            container.labels.get("com.docker.compose.oneoff"),
            Some(&"False".to_owned())
        );
        assert_eq!(
            container.labels.get("com.neotales.compose.config-digest"),
            Some(&digest)
        );
        assert_eq!(
            container.labels.get("com.docker.compose.network"),
            Some(&"demo_default".to_owned())
        );
    }

    #[test]
    fn default_network_is_created_only_when_a_service_uses_it() {
        let runtime =
            bind("name: demo\nservices:\n  app:\n    image: alpine\n    networks: [front]\nnetworks:\n  front: {}\n")
                .expect("binding");
        assert!(
            runtime
                .networks
                .contains_key(&network_operation_id("demo_front"))
        );
        assert!(
            !runtime
                .networks
                .contains_key(&network_operation_id("demo_default"))
        );
    }

    #[test]
    fn undeclared_network_and_volume_are_rejected_before_any_request() {
        let network =
            bind("name: demo\nservices:\n  app:\n    image: alpine\n    networks: [missing]\n")
                .expect_err("undeclared network");
        assert_eq!(network.code(), "compose_undeclared_network");
        let volume =
            bind("name: demo\nservices:\n  app:\n    image: alpine\n    volumes: ['data:/data']\n")
                .expect_err("undeclared volume");
        assert_eq!(volume.code(), "compose_undeclared_volume");
    }

    #[test]
    fn ports_binds_and_tmpfs_map_to_typed_request_values() {
        let runtime = bind(
            "name: demo\nservices:\n  app:\n    image: alpine\n    ports:\n      - '8080:80'\n      - '90/udp'\n    volumes:\n      - data:/data:ro\n      - type: tmpfs\n        target: /scratch\nvolumes:\n  data: {}\n",
        )
        .expect("binding");
        let container = runtime
            .container(&container_operation_id("demo-app-1"))
            .expect("app");
        assert_eq!(
            container.exposed_ports(),
            ["80/tcp".to_owned(), "90/udp".to_owned()]
        );
        assert_eq!(container.published_ports().len(), 1);
        assert_eq!(container.binds, ["demo_data:/data:ro".to_owned()]);
        assert_eq!(container.tmpfs.keys().collect::<Vec<_>>(), vec!["/scratch"]);
    }

    #[test]
    fn bind_mount_requires_an_explicit_source() {
        let mut project = project("name: demo\nservices:\n  app:\n    image: alpine\n");
        let mut service = project.service("app").expect("app").clone();
        service.volumes.push(ComposeMount {
            kind: ComposeMountKind::Bind,
            source: None,
            target: "/data".to_owned(),
            read_only: false,
            subtree: None,
            short_form: false,
        });
        project.services.insert("app".to_owned(), service);
        let plan = ComposePlanner::create(
            &project,
            ComposePlanOptions {
                policy: ComposePlanPolicy::permissive(),
                ..ComposePlanOptions::default()
            },
        )
        .expect("plan");
        let error = ComposeRuntime::bind(&project, &plan).expect_err("bind without source");
        assert_eq!(error.code(), "compose_bind_mount_requires_source");
    }

    #[test]
    fn a_plan_without_the_default_network_operation_is_rejected() {
        let project = project("name: demo\nservices:\n  app:\n    image: alpine\n");
        let plan = ComposePlanner::create(
            &project,
            ComposePlanOptions {
                policy: ComposePlanPolicy::permissive(),
                ..ComposePlanOptions::default()
            },
        )
        .expect("plan");
        let error = ComposeRuntime::bind(&project, &plan).expect_err("missing default network");
        assert_eq!(error.code(), "compose_runtime_unplanned_network");
    }

    /// The resource limits, devices, and namespace modes reach the request spec
    /// with nothing left to decide. `cpus` is the one rename — the document
    /// spells it as a fraction of a CPU and the request field is a nano-CPU
    /// count — and `cpuset` is the other, because that is the Engine's spelling
    /// of the same thing.
    #[test]
    fn resource_limits_devices_and_namespace_modes_reach_the_spec() {
        let runtime = bind(
            "name: demo
services:
  app:
    image: alpine
    mem_limit: 512m
    mem_swappiness: 60
    memswap_limit: 1g
    cpus: 0.5
    cpu_shares: 73
    cpuset: \"0,1\"
    pids_limit: 100
    oom_kill_disable: true
    oom_score_adj: 500
    devices:
      - \"/dev/sda\"
    device_cgroup_rules:
      - \"c 1:3 mr\"
    ipc: host
    uts: host
    mac_address: 02:42:ac:11:00:02
    cgroup_parent: m-executor-abcd
    storage_opt:
      size: 10G
    volumes_from:
      - container:elsewhere
    external_links:
      - redis
",
        )
        .expect("binding");
        let container = runtime
            .container(&container_operation_id("demo-app-1"))
            .expect("app");
        assert_eq!(container.mem_limit, Some(512 * 1024 * 1024));
        assert_eq!(container.mem_swappiness, Some(60));
        assert_eq!(container.memswap_limit, Some(1024 * 1024 * 1024));
        assert_eq!(container.nano_cpus, Some(500_000_000));
        assert_eq!(container.cpu_shares, Some(73));
        assert_eq!(container.cpuset_cpus.as_deref(), Some("0,1"));
        assert_eq!(container.pids_limit, Some(100));
        assert!(container.oom_kill_disable);
        assert_eq!(container.oom_score_adj, Some(500));
        assert_eq!(container.devices[0].target, "/dev/sda");
        assert_eq!(container.device_cgroup_rules, ["c 1:3 mr"]);
        assert_eq!(container.ipc_mode.as_deref(), Some("host"));
        assert_eq!(container.uts_mode.as_deref(), Some("host"));
        assert_eq!(container.mac_address.as_deref(), Some("02:42:ac:11:00:02"));
        assert_eq!(container.cgroup_parent.as_deref(), Some("m-executor-abcd"));
        assert_eq!(
            container.storage_opt.get("size").map(String::as_str),
            Some("10G")
        );
        assert_eq!(container.volumes_from, ["container:elsewhere"]);
        assert_eq!(container.external_links, ["redis"]);
        // Nothing the Engine request cannot express is dropped on the way here:
        // a caller has to be able to refuse these by name.
        assert_eq!(container.mem_reservation, None);
        assert!(container.blkio_config.is_none());
        assert!(container.credential_spec.is_none());
    }
}
