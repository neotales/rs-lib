//! Repository-owned Engine container operations over Bollard.
//!
//! Public values in this module intentionally use only repository types,
//! strings, numbers, and JSON values. Bollard's generated request and response
//! models stay private to this adapter.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::pin::Pin;

use bytes::{Buf, Bytes, BytesMut};
use futures_core::Stream;
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;

use super::streams::{map_bollard_stream, map_log_frame};
use super::{ContainerLogFrame, DockerClient, DockerStream, Error};
use crate::raw;

/// Options for `GET /containers/json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerListOptions {
    /// Include stopped containers.
    pub all: bool,
    /// Limit the number of returned containers.
    pub limit: Option<i32>,
    /// Ask the daemon to include size fields.
    pub size: bool,
    /// Ordered Engine filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

/// One published or exposed port in a container-list response.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPort {
    /// Host IP address.
    pub ip: Option<String>,
    /// Container port.
    pub private_port: u16,
    /// Published host port.
    pub public_port: Option<u16>,
    /// Transport protocol.
    pub protocol: Option<String>,
}

/// Stable fields used by Docker-compatible container-list output.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummary {
    /// Container ID.
    pub id: Option<String>,
    /// Container names.
    pub names: Option<Vec<String>>,
    /// Image reference used to create the container.
    pub image: Option<String>,
    /// Image ID used to create the container.
    pub image_id: Option<String>,
    /// Quoted command displayed by `ps`.
    pub command: Option<String>,
    /// Creation time as Unix seconds.
    pub created: Option<i64>,
    /// Published and exposed ports.
    pub ports: Vec<ContainerPort>,
    /// Daemon state name.
    pub state: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// User-defined metadata reported by the daemon.
    ///
    /// Bollard already carries this value; the projection is a
    /// [`BTreeMap`] so the ordering of the map is deterministic for callers
    /// that compare or serialize it. A container without labels projects to
    /// an empty map.
    pub labels: BTreeMap<String, String>,
}

/// A host port binding for container creation or inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPortBinding {
    /// Host IP address. An empty value asks Docker to choose the default.
    pub host_ip: Option<String>,
    /// Host port.
    pub host_port: Option<String>,
}

/// A normalized published-port mapping.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortMapping {
    /// Container port key such as `80/tcp`.
    pub container_port: String,
    /// Host bindings for the container port.
    pub bindings: Vec<ContainerPortBinding>,
}

/// A host device exposed inside a container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceMapping {
    /// Host path.
    pub path_on_host: String,
    /// Container path.
    pub path_in_container: String,
    /// cgroup permission set.
    pub cgroup_permissions: String,
}

/// A device-driver request such as an NVIDIA GPU allocation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// Device driver name.
    pub driver: Option<String>,
    /// Requested device count.
    pub count: Option<i64>,
    /// Explicit device identifiers.
    pub device_ids: Option<Vec<String>>,
    /// Driver capabilities.
    pub capabilities: Option<Vec<Vec<String>>>,
}

/// A named process limit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ulimit {
    /// Limit name.
    pub name: String,
    /// Soft limit.
    pub soft: i64,
    /// Hard limit.
    pub hard: i64,
}

/// Restart policy for a newly-created container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// `no`, `always`, `unless-stopped`, or `on-failure`.
    pub name: String,
    /// Maximum retries for `on-failure`.
    pub maximum_retry_count: Option<i64>,
}

/// Container logging configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogConfig {
    /// Logging driver.
    pub driver: Option<String>,
    /// Driver options.
    pub options: BTreeMap<String, String>,
}

/// Container health-check configuration. Durations are nanoseconds.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Literal test array, such as `CMD-SHELL` plus its command.
    pub test: Option<Vec<String>>,
    /// Check interval.
    pub interval: Option<i64>,
    /// Check timeout.
    pub timeout: Option<i64>,
    /// Consecutive failures before unhealthy.
    pub retries: Option<i64>,
    /// Initialization period.
    pub start_period: Option<i64>,
    /// Check interval during the start period.
    pub start_interval: Option<i64>,
}

/// Host-specific options for a newly-created container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerHostConfig {
    /// Bind mount specifications.
    pub binds: Vec<String>,
    /// Published port mappings.
    pub port_bindings: Vec<PortMapping>,
    /// Initial umask.
    pub umask: Option<String>,
    /// Extended privileges.
    pub privileged: bool,
    /// DNS server addresses.
    pub dns: Vec<String>,
    /// Restart policy.
    pub restart_policy: Option<RestartPolicy>,
    /// Host device mappings.
    pub devices: Vec<DeviceMapping>,
    /// Additional `/etc/hosts` entries.
    pub extra_hosts: Vec<String>,
    /// Added Linux capabilities.
    pub cap_add: Vec<String>,
    /// Dropped Linux capabilities.
    pub cap_drop: Vec<String>,
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// Run an init process.
    pub init: bool,
    /// Size of `/dev/shm` in bytes.
    pub shm_size: Option<i64>,
    /// Stop timeout in seconds.
    pub stop_timeout: Option<i64>,
    /// Temporary filesystem mounts.
    pub tmpfs: BTreeMap<String, String>,
    /// Process limits.
    pub ulimits: Vec<Ulimit>,
    /// Additional groups.
    pub group_add: Vec<String>,
    /// Kernel parameters.
    pub sysctls: BTreeMap<String, String>,
    /// Security options.
    pub security_options: Vec<String>,
    /// DNS search domains.
    pub dns_search: Vec<String>,
    /// Logging configuration.
    pub log_config: Option<LogConfig>,
    /// Network mode or custom network name.
    pub network_mode: Option<String>,
    /// IPC namespace mode.
    pub ipc_mode: Option<String>,
    /// PID namespace mode.
    pub pid_mode: Option<String>,
    /// User namespace mode.
    pub userns_mode: Option<String>,
    /// Available CPU quota in nano-CPUs.
    pub nano_cpus: Option<i64>,
    /// Memory limit in bytes.
    pub memory: Option<i64>,
    /// Memory reservation in bytes.
    pub memory_reservation: Option<i64>,
    /// Maximum process and thread count.
    pub pids_limit: Option<i64>,
    /// Relative CPU weight.
    pub cpu_shares: Option<i64>,
    /// CFS period in microseconds.
    pub cpu_period: Option<i64>,
    /// CFS quota in microseconds.
    pub cpu_quota: Option<i64>,
    /// Allowed CPU set.
    pub cpuset_cpus: Option<String>,
    /// Resolver options.
    pub dns_options: Vec<String>,
    /// UTS namespace mode.
    pub uts_mode: Option<String>,
    /// Containers whose volumes are inherited.
    pub volumes_from: Vec<String>,
    /// Device-driver requests.
    pub device_requests: Vec<DeviceRequest>,
    /// Windows isolation technology.
    pub isolation: Option<String>,
    /// OCI runtime.
    pub runtime: Option<String>,
    /// Disable the out-of-memory killer.
    pub oom_kill_disable: bool,
    /// Out-of-memory score adjustment.
    pub oom_score_adj: Option<i64>,
}

impl ContainerHostConfig {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The networks a container is attached to when it is created.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerNetworkingConfig {
    /// Endpoint settings keyed by network name or ID.
    pub endpoints: BTreeMap<String, ContainerEndpointSettings>,
}

/// Per-network settings for a container endpoint.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerEndpointSettings {
    /// DNS aliases the container answers to on this network.
    pub aliases: Vec<String>,
    /// Links to other containers on the same network.
    pub links: Vec<String>,
    /// A MAC address to assign to this endpoint.
    pub mac_address: Option<String>,
}

/// Repository-owned `POST /containers/create` body and query values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerCreateOptions {
    /// Image reference.
    pub image: String,
    /// Literal command argv.
    pub command: Vec<String>,
    /// Optional entrypoint override. One empty string resets the image entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Environment entries in `NAME=value` form.
    pub environment: Vec<String>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Exposed container ports, such as `80/tcp`.
    pub exposed_ports: Vec<String>,
    /// Hostname.
    pub hostname: Option<String>,
    /// NIS domain name.
    pub domainname: Option<String>,
    /// MAC address.
    pub mac_address: Option<String>,
    /// User used to run the container.
    pub user: Option<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Stop signal.
    pub stop_signal: Option<String>,
    /// Allocate a pseudo-TTY.
    pub tty: bool,
    /// Keep standard input open.
    pub open_stdin: bool,
    /// Attach standard input.
    pub attach_stdin: bool,
    /// Attach standard output.
    pub attach_stdout: bool,
    /// Attach standard error.
    pub attach_stderr: bool,
    /// Health-check configuration.
    pub healthcheck: Option<HealthConfig>,
    /// Host-specific configuration.
    pub host_config: Option<ContainerHostConfig>,
    /// The networks the container is attached to at creation.
    ///
    /// A container created with `NetworkMode` of `none` can never be attached to
    /// another network, so the networks a Compose service declares have to be
    /// part of the create request. Attaching them afterwards with a separate
    /// connect request works only for a container the daemon is willing to move,
    /// and leaves the declared DNS aliases unapplied in the meantime.
    pub networking_config: Option<ContainerNetworkingConfig>,
    /// Optional container name query value.
    pub name: Option<String>,
    /// Optional target platform query value.
    pub platform: Option<String>,
}

/// Result of `POST /containers/create`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerCreateResult {
    /// Created container ID.
    pub id: String,
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Options for `POST /containers/{id}/start`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerStartOptions {
    /// Optional detach-key sequence.
    pub detach_keys: Option<String>,
}

/// Options for `POST /containers/{id}/stop`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerStopOptions {
    /// Optional signal name or number.
    pub signal: Option<String>,
    /// Seconds to wait before killing the container.
    pub timeout_seconds: Option<i32>,
}

/// Options for `POST /containers/{id}/restart`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerRestartOptions {
    /// Optional signal name or number.
    pub signal: Option<String>,
    /// Seconds to wait before killing the container.
    pub timeout_seconds: Option<i32>,
}

/// Options for `DELETE /containers/{id}`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerRemoveOptions {
    /// Remove anonymous volumes associated with the container.
    pub remove_volumes: bool,
    /// Kill a running container before removing it.
    pub force: bool,
    /// Remove the specified link.
    pub remove_link: bool,
}

/// Options for `POST /containers/prune`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPruneOptions {
    /// Ordered Engine filters such as `until` or `label`.
    pub filters: BTreeMap<String, Vec<String>>,
}

/// Result of a resource-specific container prune.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPruneResult {
    /// IDs of containers removed by this request.
    pub deleted: Vec<String>,
    /// Bytes reclaimed by the daemon.
    pub space_reclaimed: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
/// Resource limits to apply to a running container.
///
/// Every field is optional and every `None` is left unchanged, which mirrors the
/// Engine API: the update request is a patch, and omitting a field does not mean
/// "unlimited".
pub struct ContainerUpdateOptions {
    /// Relative CPU weight.
    pub cpu_shares: Option<i64>,
    /// Memory limit in bytes.
    pub memory: Option<i64>,
}

/// Result of a successful resource update.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerUpdateResult {
    /// Warnings returned by API versions that expose them.
    ///
    /// The generated client discards the `POST /containers/{id}/update` response
    /// body, so the Bollard path can only ever report an empty list. The
    /// repository-owned transport reads the `Warnings` the daemon sent, and it
    /// is the transport every plain-HTTP and Unix-socket client now reaches, so
    /// this is populated wherever the daemon had something to say.
    pub warnings: Vec<String>,
}

/// Options for `POST /containers/{id}/wait`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitOptions {
    /// `not-running` or `removed`.
    pub condition: Option<String>,
}

/// One completed container wait operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitResult {
    /// Container exit status.
    pub status_code: i64,
    /// Daemon-reported wait error.
    pub error: Option<String>,
}

/// A process list returned by `GET /containers/{id}/top`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerTop {
    /// Column titles.
    pub titles: Vec<String>,
    /// Process rows.
    pub processes: Vec<Vec<String>>,
}

/// One filesystem change returned by `GET /containers/{id}/changes`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemChange {
    /// Absolute path in the container.
    pub path: String,
    /// Docker numeric change kind.
    pub kind: i32,
}

/// Select container-inspect fields needed by attach, port, exit, and readiness
/// handling.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerDetails {
    /// Whether the container has a pseudo-TTY.
    pub tty: bool,
    /// Last process exit code.
    pub exit_code: Option<i64>,
    /// Current status.
    pub status: Option<String>,
    /// Published ports keyed by normalized container port.
    pub ports: BTreeMap<String, Vec<ContainerPortBinding>>,
    /// Docker health status reported by the daemon, lowercased.
    ///
    /// The daemon spells this `healthy`, `unhealthy`, `starting`, or `none`.
    /// The projection is `None` when the container has no health state at all,
    /// which is how a container without a healthcheck appears, so a caller can
    /// tell "no healthcheck" apart from a healthcheck that has not run yet.
    pub health: Option<String>,
    /// Whether the daemon reports the container as running.
    ///
    /// A running container can also be paused, so this is a convenience
    /// projection of `State.Running` rather than a state name. It is `None`
    /// when the daemon omits the field.
    pub running: Option<bool>,
}

/// HEAD metadata for a path downloaded from a container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPathStat {
    /// Base name reported by the daemon.
    pub name: String,
    /// File size.
    pub size: i64,
    /// Unix-style file mode.
    pub mode: u32,
    /// Symbolic-link target, when present.
    pub link_target: Option<String>,
}

impl ContainerPathStat {
    /// Whether the path is a directory.
    ///
    /// The type bits are not where a `chmod`-shaped mode would put them, and
    /// getting this wrong is not a detail. Measured against a live daemon, the
    /// `X-Docker-Container-Path-Stat` header reports:
    ///
    /// | path          | reported mode    |
    /// |---------------|------------------|
    /// | a directory   | `2147484141` (`0x800001ED`) |
    /// | a regular file| `420` (`0o644`)  |
    ///
    /// So the low twelve bits are the permissions and the type is carried in the
    /// high bits. A `mode & 0xf000 == 0o4000` test — the obvious one, and the one
    /// this used — reads `0x1ED` there and answers "not a directory", which made
    /// `docker cp ctr:/dir ./dir` treat the directory as a file and
    /// `docker cp local.txt ctr:/existing-dir` overwrite that directory with a
    /// file. The POSIX `S_IFDIR` spelling is accepted too, because a different
    /// daemon or a transport that reshapes the header may use it.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        const S_IFDIR: u32 = 0o040_000;
        const GO_MODE_DIR: u32 = 0x8000_0000;
        self.mode & S_IFDIR == S_IFDIR || self.mode & GO_MODE_DIR != 0
    }
}

/// Caller-owned container archive response.
#[must_use = "a ContainerArchive owns a response and should be consumed or cancelled"]
pub struct ContainerArchive {
    /// Path metadata used to decide extraction semantics.
    pub stat: ContainerPathStat,
    /// Archive byte stream.
    pub stream: DockerStream<Vec<u8>>,
}

impl std::fmt::Debug for ContainerArchive {
    /// Reports the path metadata and the handle, and no archive byte.
    ///
    /// `#[derive(Debug)]` would compile here, because [`DockerStream`]'s own
    /// `Debug` prints no item, and it is tempting for exactly that reason. It is
    /// hand-written anyway: the safety of this rendering would then rest on a
    /// decision taken in another module about another type, and the archive is
    /// the container's filesystem — whatever the caller copied out of it may be
    /// a credential file. The guarantee belongs to the type that owns the
    /// archive, not to the layer below it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerArchive")
            .field("stat", &self.stat)
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl ContainerArchive {
    /// Reads the next archive chunk.
    pub async fn next(&mut self) -> Option<Result<Vec<u8>, Error>> {
        self.stream.next().await
    }

    /// Cancels and releases the response stream.
    pub fn cancel(&mut self) {
        self.stream.cancel();
    }
}

/// Options for `PUT /containers/{id}/archive`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerArchiveUploadOptions {
    /// Absolute destination directory in the container.
    pub path: String,
    /// Preserve numeric user/group IDs from archive entries.
    pub copy_user_and_group: bool,
    /// Reject directory/non-directory replacement.
    pub no_overwrite_directory_with_file: bool,
}

/// Options for `POST /commit`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitContainerOptions {
    /// Source container ID or name.
    pub container: String,
    /// Target repository.
    pub repository: Option<String>,
    /// Target tag.
    pub tag: Option<String>,
    /// Commit message.
    pub comment: Option<String>,
    /// Commit author.
    pub author: Option<String>,
    /// Pause the container during commit.
    pub pause: bool,
    /// Dockerfile changes. The command parser currently accepts `CMD` and `ENV`.
    pub changes: Vec<String>,
}

/// Options shared by checkpoint create/list/remove operations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointOptions {
    /// Checkpoint identifier for create/remove.
    pub checkpoint_id: Option<String>,
    /// Custom checkpoint directory.
    pub checkpoint_dir: Option<String>,
    /// Stop the container after checkpoint creation.
    pub exit: bool,
}

/// One container checkpoint name.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint name.
    pub name: String,
}

/// Options for creating an exec instance.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExecOptions {
    /// Attach standard input.
    pub attach_stdin: bool,
    /// Attach standard output.
    pub attach_stdout: bool,
    /// Attach standard error.
    pub attach_stderr: bool,
    /// Allocate a pseudo-TTY.
    pub tty: bool,
    /// Detach-key sequence.
    pub detach_keys: Option<String>,
    /// Additional environment.
    pub environment: Vec<String>,
    /// Literal command argv.
    pub command: Vec<String>,
    /// Run with extended privileges.
    pub privileged: bool,
    /// User override.
    pub user: Option<String>,
    /// Working directory.
    pub working_dir: Option<String>,
}

/// State returned by `GET /exec/{id}/json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecState {
    /// Exec instance ID.
    pub id: Option<String>,
    /// Whether the command is still running.
    pub running: bool,
    /// Exit code after completion.
    pub exit_code: Option<i64>,
}

/// Options for `POST /exec/{id}/resize`.
///
/// The daemon only honors these values for an exec instance created with a
/// pseudo-TTY.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecResizeOptions {
    /// Terminal height in characters.
    pub height: u16,
    /// Terminal width in characters.
    pub width: u16,
}

/// Caller-owned write half of an upgraded Engine connection.
pub struct SessionInput {
    inner: Box<dyn AsyncWrite + Send + Unpin>,
}

impl SessionInput {
    fn new(inner: Pin<Box<dyn AsyncWrite + Send>>) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    /// Writes all input bytes to the Engine connection.
    ///
    /// # Errors
    ///
    /// Returns a Docker transport error when the upgraded connection fails.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.inner.write_all(bytes).await.map_err(|error| {
            Error::invalid_input(format!("failed to write attached input: {error}"))
        })
    }

    /// Half-closes the Engine input stream.
    ///
    /// # Errors
    ///
    /// Returns a Docker transport error when the upgraded connection fails.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown().await.map_err(|error| {
            Error::invalid_input(format!("failed to close attached input: {error}"))
        })
    }
}

impl std::fmt::Debug for SessionInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionInput")
    }
}

/// An attached or exec session that owns both upgraded connection halves.
///
/// Dropping the session releases its output body and input socket. Callers can
/// also cancel output explicitly while retaining the input half if needed.
pub struct AttachedSession {
    output: DockerStream<ContainerLogFrame>,
    input: SessionInput,
}

impl std::fmt::Debug for AttachedSession {
    /// Reports both halves by name, and no byte from either.
    ///
    /// The input half is where a caller types into an attached container and the
    /// output half is what the container types back, so a rendering of this value
    /// is a rendering of a live terminal session — including whatever a caller
    /// pasted into it, and whatever the container answered with. `SessionInput`
    /// already prints only its own name for this reason, and the pair keeps that
    /// shape here, where both halves are owned.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachedSession")
            .field("output", &self.output)
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

impl AttachedSession {
    /// Returns the caller-owned output stream.
    pub const fn output(&self) -> &DockerStream<ContainerLogFrame> {
        &self.output
    }

    /// Returns the caller-owned output stream for polling.
    pub fn output_mut(&mut self) -> &mut DockerStream<ContainerLogFrame> {
        &mut self.output
    }

    /// Returns the caller-owned input stream.
    pub const fn input_mut(&mut self) -> &mut SessionInput {
        &mut self.input
    }

    /// Cancels output while preserving the input handle.
    pub fn cancel_output(&mut self) {
        self.output.cancel();
    }

    /// Splits the session into its two explicitly owned connection halves.
    pub fn into_parts(self) -> (DockerStream<ContainerLogFrame>, SessionInput) {
        (self.output, self.input)
    }

    /// Drops both connection halves and releases their resources.
    pub fn cancel(self) {}
}

/// Exec sessions use the same upgraded, bidirectional connection contract.
pub type ExecSession = AttachedSession;

const MAX_EXEC_FRAME_BYTES: usize = 16 * 1024 * 1024;

struct RawExecDecoder {
    tty: bool,
}

impl RawExecDecoder {
    fn new(tty: bool) -> Self {
        Self { tty }
    }
}

impl Decoder for RawExecDecoder {
    type Item = bollard::container::LogOutput;
    type Error = io::Error;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if source.is_empty() {
            return Ok(None);
        }
        if self.tty || source[0] > 2 {
            let message = source.split().freeze();
            return Ok(Some(bollard::container::LogOutput::Console { message }));
        }
        if source.len() < 8 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([source[4], source[5], source[6], source[7]]) as usize;
        if length > MAX_EXEC_FRAME_BYTES {
            return Err(io::Error::other(format!(
                "Docker exec output frame exceeds {MAX_EXEC_FRAME_BYTES} bytes"
            )));
        }
        if source.len() < length + 8 {
            return Ok(None);
        }
        let stream_type = source[0];
        source.advance(8);
        let message = source.split_to(length).freeze();
        let output = match stream_type {
            0 => bollard::container::LogOutput::StdIn { message },
            1 => bollard::container::LogOutput::StdOut { message },
            2 => bollard::container::LogOutput::StdErr { message },
            _ => {
                return Err(io::Error::other(format!(
                    "invalid Docker exec output stream type {stream_type}"
                )));
            }
        };
        Ok(Some(output))
    }

    fn decode_eof(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode(source)
    }
}

fn exec_stream_error(error: impl std::fmt::Display) -> Error {
    Error::runtime(format!("Docker exec output stream failed: {error}"))
}

fn raw_exec_tcp_stream(
    stream: TcpStream,
    initial: &[u8],
    tty: bool,
) -> impl Stream<Item = Result<bollard::container::LogOutput, Error>> + Send + 'static {
    stream::unfold(
        (
            stream,
            BytesMut::from(initial),
            RawExecDecoder::new(tty),
            false,
        ),
        |(mut stream, mut buffer, mut decoder, done)| async move {
            if done {
                return match decoder.decode_eof(&mut buffer) {
                    Ok(Some(output)) => Some((Ok(output), (stream, buffer, decoder, true))),
                    Ok(None) if buffer.is_empty() => None,
                    Ok(None) => Some((
                        Err(exec_stream_error(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Docker exec response ended in the middle of a frame",
                        ))),
                        (stream, buffer, decoder, true),
                    )),
                    Err(error) => Some((
                        Err(exec_stream_error(error)),
                        (stream, buffer, decoder, true),
                    )),
                };
            }
            loop {
                match decoder.decode(&mut buffer) {
                    Ok(Some(output)) => {
                        return Some((Ok(output), (stream, buffer, decoder, false)));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Some((
                            Err(exec_stream_error(error)),
                            (stream, buffer, decoder, true),
                        ));
                    }
                }
                let mut chunk = [0_u8; 16 * 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) => {
                        return match decoder.decode_eof(&mut buffer) {
                            Ok(Some(output)) => Some((Ok(output), (stream, buffer, decoder, true))),
                            Ok(None) => None,
                            Err(error) => Some((
                                Err(exec_stream_error(error)),
                                (stream, buffer, decoder, true),
                            )),
                        };
                    }
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    Err(error) => {
                        return Some((
                            Err(exec_stream_error(error)),
                            (stream, buffer, decoder, true),
                        ));
                    }
                }
            }
        },
    )
}

async fn start_http_exec(
    endpoint: &str,
    exec_id: &str,
    tty: bool,
) -> Result<(DockerStream<ContainerLogFrame>, SessionInput), Error> {
    let url = url::Url::parse(endpoint).map_err(|error| Error::runtime(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::runtime("Docker HTTP exec endpoint has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::runtime("Docker HTTP exec endpoint has no port"))?;
    let request_host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]:{port}"),
        _ => format!("{host}:{port}"),
    };
    let mut stream = TcpStream::connect((host, port)).await.map_err(|error| {
        Error::runtime(format!(
            "failed to connect to Docker exec endpoint: {error}"
        ))
    })?;
    let body = serde_json::to_vec(&serde_json::json!({
        "Detach": false,
        "Tty": tty,
    }))
    .map_err(Error::serialization)?;
    let request = format!(
        "POST /exec/{exec_id}/start HTTP/1.1\r\nHost: {request_host}\r\nApi-Version: {}.{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        super::API_VERSION.major,
        super::API_VERSION.minor,
        body.len()
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(&body);
    stream
        .write_all(&request_bytes)
        .await
        .map_err(|error| Error::runtime(format!("failed to send Docker exec request: {error}")))?;
    let mut response_bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = response_bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break position + 4;
        }
        if response_bytes.len() > 64 * 1024 {
            return Err(Error::runtime("Docker exec response headers exceed 64 KiB"));
        }
        let mut chunk = [0_u8; 8 * 1024];
        let read = stream.read(&mut chunk).await.map_err(|error| {
            Error::runtime(format!("failed to read Docker exec response: {error}"))
        })?;
        if read == 0 {
            return Err(Error::runtime("Docker exec response ended before headers"));
        }
        response_bytes.extend_from_slice(&chunk[..read]);
    };
    let headers = std::str::from_utf8(&response_bytes[..header_end]).map_err(|error| {
        Error::runtime(format!(
            "Docker exec response headers are not UTF-8: {error}"
        ))
    })?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::runtime("Docker exec response has no HTTP status"))?;
    if !(200..300).contains(&status) && status != 101 {
        return Err(Error::runtime(format!(
            "Docker exec start returned HTTP status {status}"
        )));
    }
    let initial = Bytes::from(response_bytes.split_off(header_end));
    Ok((
        DockerStream::new(
            raw_exec_tcp_stream(stream, &initial, tty).map(|item| item.map(map_log_frame)),
        ),
        SessionInput::new(Box::pin(tokio::io::sink())),
    ))
}

fn optional_vec<T>(values: Vec<T>) -> Option<Vec<T>> {
    (!values.is_empty()).then_some(values)
}

fn optional_map<K, V>(values: BTreeMap<K, V>) -> Option<HashMap<K, V>>
where
    K: Ord + Eq + std::hash::Hash,
{
    (!values.is_empty()).then(|| values.into_iter().collect())
}

fn to_bollard_port_bindings(
    mappings: &[PortMapping],
) -> HashMap<String, Option<Vec<bollard::models::PortBinding>>> {
    mappings
        .iter()
        .map(|mapping| {
            (
                mapping.container_port.clone(),
                Some(
                    mapping
                        .bindings
                        .iter()
                        .map(|binding| bollard::models::PortBinding {
                            host_ip: binding.host_ip.clone(),
                            host_port: binding.host_port.clone(),
                        })
                        .collect(),
                ),
            )
        })
        .collect()
}

/// Adds the `HostConfig.Umask` value that Bollard 0.21.1 cannot express.
///
/// The generated Bollard `HostConfig` model has no `umask` field, so the value
/// is serialized into the Engine `Umask` member after Bollard has serialized
/// the rest of the create body. The patched body is installed with a request
/// modifier so the request still travels over Bollard's own transport.
///
/// The Engine's `HostConfig.Umask` is a `uint32`, and it has to be sent as a
/// JSON **number**. `ContainerHostConfig::umask` carries the conventional octal
/// spelling (`0022`), which is how a user, a Compose file, and `chmod` all write
/// a umask, so the digits are converted rather than forwarded. Forwarding the
/// string is not a tolerated difference: Docker Engine 29.8.0 rejects
/// `POST /containers/create` whose body carries `"Umask":"0022"` with
///
/// ```text
/// 400 invalid JSON: json: cannot unmarshal string into
///     Go struct field HostConfig.HostConfig.Umask of type uint32
/// ```
///
/// so the whole create fails, not just the umask.
fn with_umask_host_config(
    docker: &bollard::Docker,
    body: &bollard::models::ContainerCreateBody,
    umask: &str,
) -> Result<bollard::Docker, Error> {
    let mut document = serde_json::to_value(body).map_err(Error::serialization)?;
    let host_config = document
        .get_mut("HostConfig")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| Error::invalid_input("container umask requires a host config"))?;
    host_config.insert(
        "Umask".to_owned(),
        serde_json::Value::from(umask_number(umask)?),
    );
    let payload = serde_json::to_vec(&document).map_err(Error::serialization)?;
    let content_length = payload.len();
    Ok(docker.clone().with_request_modifier(move |mut request| {
        if request.uri().path().ends_with("/containers/create") {
            request.headers_mut().insert(
                http::header::CONTENT_LENGTH,
                http::header::HeaderValue::from(content_length),
            );
            *request.body_mut() = bollard::body_full(payload.clone().into());
        }
        request
    }))
}

/// Converts a caller-written umask into the number the Engine declares.
///
/// # Errors
///
/// Returns an error when the value is not octal digits or does not fit the
/// Engine's `uint32`. A umask the daemon would refuse is a caller's mistake, and
/// rejecting it here names the value rather than reporting a `400` about JSON
/// types from the other end of a socket.
fn umask_number(umask: &str) -> Result<u32, Error> {
    let digits = umask.strip_prefix("0o").unwrap_or(umask);
    u32::from_str_radix(digits, 8).map_err(|error| {
        Error::invalid_input(format!("invalid container umask '{umask}': {error}"))
    })
}

/// Maps the host configuration Bollard 0.21.1 can express directly.
///
/// `ContainerHostConfig::umask` is applied separately by
/// [`with_umask_host_config`] because the generated model has no such field.
#[allow(clippy::too_many_lines)]
fn to_bollard_host_config(
    config: ContainerHostConfig,
) -> Result<bollard::models::HostConfig, Error> {
    let restart_policy = config
        .restart_policy
        .map(|policy| {
            let name = policy
                .name
                .parse::<bollard::models::RestartPolicyNameEnum>()
                .map_err(|_| Error::invalid_input("invalid container restart policy"))?;
            Ok::<_, Error>(bollard::models::RestartPolicy {
                name: Some(name),
                maximum_retry_count: policy.maximum_retry_count,
            })
        })
        .transpose()?;
    let log_config = config
        .log_config
        .map(|log| bollard::models::HostConfigLogConfig {
            typ: log.driver,
            config: optional_map(log.options),
        });
    let isolation = config
        .isolation
        .map(|value| {
            value
                .parse::<bollard::models::HostConfigIsolationEnum>()
                .map_err(|_| Error::invalid_input("invalid container isolation value"))
        })
        .transpose()?;

    Ok(bollard::models::HostConfig {
        binds: optional_vec(config.binds),
        port_bindings: (!config.port_bindings.is_empty())
            .then(|| to_bollard_port_bindings(&config.port_bindings)),
        privileged: config.privileged.then_some(true),
        dns: optional_vec(config.dns),
        restart_policy,
        devices: optional_vec(
            config
                .devices
                .into_iter()
                .map(|device| bollard::models::DeviceMapping {
                    path_on_host: Some(device.path_on_host),
                    path_in_container: Some(device.path_in_container),
                    cgroup_permissions: Some(device.cgroup_permissions),
                })
                .collect(),
        ),
        extra_hosts: optional_vec(config.extra_hosts),
        cap_add: optional_vec(config.cap_add),
        cap_drop: optional_vec(config.cap_drop),
        readonly_rootfs: config.read_only_rootfs.then_some(true),
        init: config.init.then_some(true),
        shm_size: config.shm_size,
        tmpfs: optional_map(config.tmpfs),
        ulimits: optional_vec(
            config
                .ulimits
                .into_iter()
                .map(|limit| bollard::models::ResourcesUlimits {
                    name: Some(limit.name),
                    soft: Some(limit.soft),
                    hard: Some(limit.hard),
                })
                .collect(),
        ),
        group_add: optional_vec(config.group_add),
        sysctls: optional_map(config.sysctls),
        security_opt: optional_vec(config.security_options),
        dns_search: optional_vec(config.dns_search),
        log_config,
        network_mode: config.network_mode,
        ipc_mode: config.ipc_mode,
        pid_mode: config.pid_mode,
        userns_mode: config.userns_mode,
        nano_cpus: config.nano_cpus,
        memory: config.memory,
        memory_reservation: config.memory_reservation,
        pids_limit: config.pids_limit,
        cpu_shares: config.cpu_shares,
        cpu_period: config.cpu_period,
        cpu_quota: config.cpu_quota,
        cpuset_cpus: config.cpuset_cpus,
        dns_options: optional_vec(config.dns_options),
        uts_mode: config.uts_mode,
        volumes_from: optional_vec(config.volumes_from),
        device_requests: optional_vec(
            config
                .device_requests
                .into_iter()
                .map(|request| bollard::models::DeviceRequest {
                    driver: request.driver,
                    count: request.count,
                    device_ids: request.device_ids,
                    capabilities: request.capabilities,
                    options: None,
                })
                .collect(),
        ),
        isolation,
        runtime: config.runtime,
        oom_kill_disable: config.oom_kill_disable.then_some(true),
        oom_score_adj: config.oom_score_adj,
        ..Default::default()
    })
}

fn to_bollard_health(config: HealthConfig) -> bollard::models::HealthConfig {
    bollard::models::HealthConfig {
        test: config.test,
        interval: config.interval,
        timeout: config.timeout,
        retries: config.retries,
        start_period: config.start_period,
        start_interval: config.start_interval,
    }
}

fn map_summary(summary: bollard::models::ContainerSummary) -> ContainerSummary {
    ContainerSummary {
        id: summary.id,
        names: summary.names,
        image: summary.image,
        image_id: summary.image_id,
        command: summary.command,
        created: summary.created,
        ports: summary
            .ports
            .unwrap_or_default()
            .into_iter()
            .map(|port| ContainerPort {
                ip: port.ip,
                private_port: port.private_port,
                public_port: port.public_port,
                protocol: port.typ.map(|protocol| protocol.to_string()),
            })
            .collect(),
        state: summary.state.map(|state| state.to_string()),
        status: summary.status,
        // Bollard's map is unordered; the repository-owned projection is
        // deterministic so a caller that hashes or prints labels gets the same
        // answer on every call.
        labels: summary.labels.unwrap_or_default().into_iter().collect(),
    }
}

fn map_details(details: bollard::models::ContainerInspectResponse) -> ContainerDetails {
    let tty = details
        .config
        .as_ref()
        .and_then(|config| config.tty)
        .unwrap_or(false);
    let exit_code = details.state.as_ref().and_then(|state| state.exit_code);
    let status = details
        .state
        .as_ref()
        .and_then(|state| state.status.map(|status| status.to_string()));
    // Health and running are read from the same daemon state so a caller never
    // has to reason about two snapshots of one container. An empty daemon
    // spelling projects to `None`: "no health state" is a distinct, reportable
    // answer from an empty status, and it keeps the projection deterministic.
    let running = details.state.as_ref().and_then(|state| state.running);
    let health = details
        .state
        .as_ref()
        .and_then(|state| state.health.as_ref())
        .and_then(|health| health.status)
        .map(|status| status.to_string())
        .filter(|status| !status.is_empty());
    let ports = details
        .network_settings
        .and_then(|settings| settings.ports)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(port, bindings)| {
            bindings.map(|bindings| {
                (
                    port,
                    bindings
                        .into_iter()
                        .map(|binding| ContainerPortBinding {
                            host_ip: binding.host_ip,
                            host_port: binding.host_port,
                        })
                        .collect(),
                )
            })
        })
        .collect();
    ContainerDetails {
        tty,
        exit_code,
        status,
        ports,
        health,
        running,
    }
}

fn session_from_attach(result: bollard::container::AttachContainerResults) -> AttachedSession {
    AttachedSession {
        output: map_bollard_stream(result.output, |frame| Ok(map_log_frame(frame))),
        input: SessionInput::new(result.input),
    }
}

impl DockerClient {
    /// Lists containers using the daemon's default options.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>, Error> {
        self.list_containers_with_options(None).await
    }

    /// Lists containers using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or response error.
    pub async fn list_containers_with_options(
        &self,
        options: Option<ContainerListOptions>,
    ) -> Result<Vec<ContainerSummary>, Error> {
        // The repository-owned transport first, Bollard second.
        //
        // `raw_engine()` is `Err` for an endpoint kind the owned transport does
        // not reach — TLS, SSH, or a forward proxy — and that is the only
        // condition, so the fallback is a *routing* decision rather than an
        // error path. See the note on `DockerClient::raw_engine` for why both
        // paths stay.
        if let Ok(engine) = self.raw_engine() {
            return raw::container_list(&engine, &options.unwrap_or_default()).await;
        }
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::ListContainersOptionsBuilder::default()
                .all(options.all)
                .size(options.size);
            if let Some(limit) = options.limit {
                builder = builder.limit(limit);
            }
            if !options.filters.is_empty() {
                let filters = options.filters.into_iter().collect::<HashMap<_, _>>();
                builder = builder.filters(&filters);
            }
            builder.build()
        });
        let containers = self.inner.list_containers(options).await?;
        Ok(containers.into_iter().map(map_summary).collect())
    }

    /// Creates a container without starting it.
    ///
    /// # Errors
    ///
    /// Returns a validation, transport, or response error.
    pub async fn create_container(
        &self,
        options: ContainerCreateOptions,
    ) -> Result<ContainerCreateResult, Error> {
        // The repository-owned transport first, Bollard second. See the note on
        // `DockerClient::raw_engine` for why both paths stay.
        //
        // This one needed a change in `raw/` before it could move. The owned
        // create body had no `NetworkingConfig` member, so a container created
        // through it was attached to no network — with no alias, no link, and no
        // endpoint MAC address — while the caller had asked for all of them, and
        // nothing said so. `docker compose` sets that member for every service
        // on more than one network, so the shortfall was not a missing
        // convenience: it was a container that could reach nothing, discovered
        // when the service failed its first request. `raw::containers` now
        // carries the member, and this method can finally prefer the owned
        // transport.
        if let Ok(engine) = self.raw_engine() {
            return raw::container_create(&engine, &options).await;
        }
        let mut query = bollard::query_parameters::CreateContainerOptionsBuilder::default();
        if let Some(name) = options.name.as_deref() {
            query = query.name(name);
        }
        if let Some(platform) = options.platform.as_deref() {
            query = query.platform(platform);
        }
        let stop_timeout = options
            .host_config
            .as_ref()
            .and_then(|config| config.stop_timeout);
        let umask = options
            .host_config
            .as_ref()
            .and_then(|config| config.umask.clone());
        let host_config = options
            .host_config
            .filter(|config| !config.is_empty())
            .map(to_bollard_host_config)
            .transpose()?;
        let body = bollard::models::ContainerCreateBody {
            hostname: options.hostname,
            domainname: options.domainname,
            user: options.user,
            attach_stdin: options.attach_stdin.then_some(true),
            attach_stdout: options.attach_stdout.then_some(true),
            attach_stderr: options.attach_stderr.then_some(true),
            exposed_ports: optional_vec(options.exposed_ports),
            tty: options.tty.then_some(true),
            open_stdin: options.open_stdin.then_some(true),
            env: optional_vec(options.environment),
            cmd: optional_vec(options.command),
            healthcheck: options.healthcheck.map(to_bollard_health),
            image: Some(options.image),
            working_dir: options.working_dir,
            entrypoint: options.entrypoint,
            labels: optional_map(options.labels),
            stop_signal: options.stop_signal,
            stop_timeout,
            host_config,
            networking_config: options.networking_config.as_ref().map(|networking| {
                bollard::models::NetworkingConfig {
                    endpoints_config: Some(
                        networking
                            .endpoints
                            .iter()
                            .map(|(name, settings)| {
                                (
                                    name.clone(),
                                    bollard::models::EndpointSettings {
                                        aliases: optional_vec(settings.aliases.clone()),
                                        links: optional_vec(settings.links.clone()),
                                        mac_address: settings.mac_address.clone(),
                                        ..Default::default()
                                    },
                                )
                            })
                            .collect(),
                    ),
                }
            }),
            ..Default::default()
        };
        let docker = match umask {
            Some(umask) => with_umask_host_config(&self.inner, &body, &umask)?,
            None => self.inner.clone(),
        };
        let result = docker.create_container(Some(query.build()), body).await?;
        Ok(ContainerCreateResult {
            id: result.id,
            warnings: result.warnings,
        })
    }

    /// Starts a container with daemon defaults.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn start_container(&self, container: &str) -> Result<(), Error> {
        self.start_container_with_options(container, None).await
    }

    /// Starts a container using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn start_container_with_options(
        &self,
        container: &str,
        options: Option<ContainerStartOptions>,
    ) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. See the note on
        // `DockerClient::raw_engine` for why both paths stay.
        if let Ok(engine) = self.raw_engine() {
            return raw::container_start(&engine, container, &options.unwrap_or_default()).await;
        }
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::StartContainerOptionsBuilder::default();
            if let Some(keys) = options.detach_keys {
                builder = builder.detach_keys(&keys);
            }
            builder.build()
        });
        self.inner
            .start_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Stops a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn stop_container(
        &self,
        container: &str,
        options: Option<ContainerStopOptions>,
    ) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. `t` is the
        // Engine's own spelling of the graceful-stop timeout and is sent only
        // when the caller set one, so the daemon's default applies otherwise.
        if let Ok(engine) = self.raw_engine() {
            return raw::container_stop(&engine, container, &options.unwrap_or_default()).await;
        }
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::StopContainerOptionsBuilder::default();
            if let Some(signal) = options.signal.as_deref() {
                builder = builder.signal(signal);
            }
            if let Some(timeout) = options.timeout_seconds {
                builder = builder.t(timeout);
            }
            builder.build()
        });
        self.inner
            .stop_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Restarts a container.
    ///
    /// This has no owned equivalent: `POST /containers/{id}/restart` takes the
    /// same `signal` and `t` parameters as `stop`, but the owned transport has
    /// no `container_restart`, and an operation was not invented for it. See
    /// the note on `DockerClient::raw_engine` for why the fallback exists at all.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn restart_container(
        &self,
        container: &str,
        options: Option<ContainerRestartOptions>,
    ) -> Result<(), Error> {
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::RestartContainerOptionsBuilder::default();
            if let Some(signal) = options.signal.as_deref() {
                builder = builder.signal(signal);
            }
            if let Some(timeout) = options.timeout_seconds {
                builder = builder.t(timeout);
            }
            builder.build()
        });
        self.inner
            .restart_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Removes a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn remove_container(
        &self,
        container: &str,
        options: Option<ContainerRemoveOptions>,
    ) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. All three flags
        // are spelled out on the wire, so a recorded `DELETE` says whether
        // volumes, a running process, and a link were part of the request.
        if let Ok(engine) = self.raw_engine() {
            return raw::container_remove(&engine, container, &options.unwrap_or_default()).await;
        }
        let options = options.map(|options| {
            bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                .v(options.remove_volumes)
                .force(options.force)
                .link(options.remove_link)
                .build()
        });
        self.inner
            .remove_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Prunes stopped containers using a resource-specific Engine request.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or Engine API error.
    pub async fn prune_containers(
        &self,
        options: Option<ContainerPruneOptions>,
    ) -> Result<ContainerPruneResult, Error> {
        // The repository-owned transport first, Bollard second. `filters` is
        // encoded from the repository's ordered map, so the recorded query is
        // the same on every run; the generated client builds the same JSON from
        // a `HashMap` and does not.
        if let Ok(engine) = self.raw_engine() {
            return raw::prune(&engine, &options.unwrap_or_default()).await;
        }
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::PruneContainersOptionsBuilder::default();
            if !options.filters.is_empty() {
                let filters = options.filters.into_iter().collect::<HashMap<_, _>>();
                builder = builder.filters(&filters);
            }
            builder.build()
        });
        let response = self.inner.prune_containers(options).await?;
        Ok(ContainerPruneResult {
            deleted: response.containers_deleted.unwrap_or_default(),
            space_reclaimed: response.space_reclaimed.unwrap_or_default(),
        })
    }

    /// Renames a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn rename_container(&self, container: &str, name: &str) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. The new name is
        // a query value there, which is the only place the Engine reads it from.
        if let Ok(engine) = self.raw_engine() {
            return raw::rename(&engine, container, name).await;
        }
        let options = bollard::query_parameters::RenameContainerOptionsBuilder::default()
            .name(name)
            .build();
        self.inner
            .rename_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Sends a signal to a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn kill_container(&self, container: &str, signal: Option<&str>) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. An absent signal
        // stays absent rather than becoming this client's guess at the daemon's
        // default.
        if let Ok(engine) = self.raw_engine() {
            return raw::kill(
                &engine,
                container,
                &raw::ContainerKillOptions {
                    signal: signal.map(ToOwned::to_owned),
                },
            )
            .await;
        }
        let options = signal.map(|signal| {
            bollard::query_parameters::KillContainerOptionsBuilder::default()
                .signal(signal)
                .build()
        });
        self.inner
            .kill_container(container, options)
            .await
            .map_err(Error::from)
    }

    /// Pauses a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn pause_container(&self, container: &str) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second.
        if let Ok(engine) = self.raw_engine() {
            return raw::pause(&engine, container).await;
        }
        self.inner
            .pause_container(container)
            .await
            .map_err(Error::from)
    }

    /// Unpauses a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn unpause_container(&self, container: &str) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second.
        if let Ok(engine) = self.raw_engine() {
            return raw::unpause(&engine, container).await;
        }
        self.inner
            .unpause_container(container)
            .await
            .map_err(Error::from)
    }

    /// Opens a caller-owned wait stream.
    ///
    /// The signature is a stream rather than a `Result`, so the owned path
    /// cannot simply `await` here: the request has to be built lazily, at the
    /// first poll, or `wait_container` would open a connection before the caller
    /// asked for one. `stream::once` over an `async` block gives exactly that —
    /// constructing the future performs no I/O, because the body does not run
    /// until the block is polled — and it preserves the laziness the generated
    /// client's own stream had.
    pub fn wait_container(
        &self,
        container: &str,
        options: Option<ContainerWaitOptions>,
    ) -> DockerStream<ContainerWaitResult> {
        // The repository-owned transport first, Bollard second. The reference
        // and the options are moved into the future because `DockerStream`
        // requires a `'static` producer, and the wait blocks for as long as the
        // container runs.
        if let Ok(engine) = self.raw_engine() {
            let container = container.to_owned();
            let options = options.unwrap_or_default();
            return DockerStream::new(stream::once(async move {
                raw::container_wait(&engine, &container, &options).await
            }));
        }
        let options = options.and_then(|options| {
            options.condition.map(|condition| {
                bollard::query_parameters::WaitContainerOptionsBuilder::default()
                    .condition(&condition)
                    .build()
            })
        });
        DockerStream::new(self.inner.wait_container(container, options).map(
            |result| match result {
                Ok(result) => Ok(ContainerWaitResult {
                    status_code: result.status_code,
                    error: result.error.and_then(|error| error.message),
                }),
                Err(bollard::errors::Error::DockerContainerWaitError { code, .. }) => {
                    Ok(ContainerWaitResult {
                        status_code: code,
                        error: None,
                    })
                }
                Err(error) => Err(Error::from(error)),
            },
        ))
    }

    /// Updates mutable container resources.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn update_container(
        &self,
        container: &str,
        options: ContainerUpdateOptions,
    ) -> Result<ContainerUpdateResult, Error> {
        // The repository-owned transport first, Bollard second.
        //
        // The answer differs from the fallback in one way worth stating: the
        // generated client discards the `POST /containers/{id}/update` body
        // entirely, so it can only ever report an empty warning list. The owned
        // transport reads the `Warnings` the daemon actually sent. The result
        // type is the same, and the warnings are the daemon's, so a caller that
        // prints them prints the truth.
        if let Ok(engine) = self.raw_engine() {
            return raw::update(&engine, container, &options).await;
        }
        self.inner
            .update_container(
                container,
                bollard::models::ContainerUpdateBody {
                    cpu_shares: options.cpu_shares,
                    memory: options.memory,
                    ..Default::default()
                },
            )
            .await?;
        Ok(ContainerUpdateResult::default())
    }

    /// Returns the raw Engine v1.53 container-inspect object.
    ///
    /// The owned path hands back the daemon's document unchanged, and the
    /// fallback re-serializes the generated model over it. The two differ by
    /// members the generated model *drops*: `bollard-stubs` annotates
    /// `exec_ids` `skip_serializing_if = "Option::is_none"` and the daemon sends
    /// `"ExecIDs": null`, so the round trip through the model loses a member the
    /// daemon did send. The owned document is the same object with more of it
    /// present, not a different shape.
    ///
    /// # Errors
    ///
    /// Returns a transport or serialization error.
    pub async fn inspect_container(&self, container: &str) -> Result<serde_json::Value, Error> {
        // The repository-owned transport first, Bollard second.
        if let Ok(engine) = self.raw_engine() {
            return Ok(raw::inspect(&engine, container).await?.into_document());
        }
        self.inner
            .inspect_container(container, None)
            .await
            .map_err(Error::from)
            .and_then(|value| serde_json::to_value(value).map_err(Error::serialization))
    }

    /// Returns repository-owned container details used by CLI commands.
    ///
    /// The projection carries the daemon health status and running flag, so a
    /// caller can evaluate a readiness condition with one request instead of
    /// re-reading the raw inspect object.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn container_details(&self, container: &str) -> Result<ContainerDetails, Error> {
        // The repository-owned transport first, Bollard second. The projection
        // is `ContainerInspect::details`, which is deliberately the same one the
        // fallback performs over the generated model — see its documentation
        // for the field-by-field correspondence.
        if let Ok(engine) = self.raw_engine() {
            return Ok(raw::inspect(&engine, container).await?.details());
        }
        self.inner
            .inspect_container(container, None)
            .await
            .map(map_details)
            .map_err(Error::from)
    }

    /// Lists processes in a container.
    ///
    /// This has no owned equivalent: `GET /containers/{id}/top` is a single
    /// bounded document, and the owned transport has no `container_top`. One was
    /// not invented for it, because the rule is that the owned backend gains an
    /// operation when it can express it, not when a facade method needs one.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or response error.
    pub async fn container_top(
        &self,
        container: &str,
        process_options: Option<&str>,
    ) -> Result<ContainerTop, Error> {
        let options = process_options
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                bollard::query_parameters::TopOptionsBuilder::default()
                    .ps_args(value)
                    .build()
            });
        let result = self.inner.top_processes(container, options).await?;
        Ok(ContainerTop {
            titles: result.titles.unwrap_or_default(),
            processes: result.processes.unwrap_or_default(),
        })
    }

    /// Lists container filesystem changes.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn container_changes(&self, container: &str) -> Result<Vec<FilesystemChange>, Error> {
        // The repository-owned transport first, Bollard second. The Engine
        // declares exactly `Path` and `Kind` for a change, so nothing the daemon
        // sends here can be lost in either direction.
        if let Ok(engine) = self.raw_engine() {
            return raw::changes(&engine, container).await;
        }
        let changes = self
            .inner
            .container_changes(container)
            .await?
            .unwrap_or_default();
        Ok(changes
            .into_iter()
            .map(|change| FilesystemChange {
                path: change.path,
                kind: change.kind as i32,
            })
            .collect())
    }

    /// Opens a bidirectional attachment to a container.
    ///
    /// This stays on the generated client, and the reason is not that the
    /// endpoint is unreached — the owned transport has `raw::attach` and sends
    /// the same request. It is that `raw::attach` deliberately *discards* the
    /// transfer: it drops the response, which closes the connection, and reports
    /// only whether the daemon started streaming. An [`AttachedSession`] is a
    /// caller-owned output stream and input handle, and there is no way to build
    /// one out of "the daemon began streaming and this client is not reading the
    /// stream". Routing this method to the owned transport would hand every
    /// caller a session that produces no output.
    ///
    /// # Errors
    ///
    /// Returns a transport or HTTP-upgrade error.
    pub async fn attach_container(
        &self,
        container: &str,
        stdin: bool,
        logs: bool,
        detach_keys: Option<&str>,
    ) -> Result<AttachedSession, Error> {
        let mut builder = bollard::query_parameters::AttachContainerOptionsBuilder::default()
            .stream(true)
            .stdin(stdin)
            .stdout(true)
            .stderr(true)
            .logs(logs);
        if let Some(keys) = detach_keys {
            builder = builder.detach_keys(keys);
        }
        self.inner
            .attach_container(container, Some(builder.build()))
            .await
            .map(session_from_attach)
            .map_err(Error::from)
    }

    /// Opens an uncompressed container filesystem archive stream.
    pub fn export_container(&self, container: &str) -> DockerStream<Vec<u8>> {
        map_bollard_stream(self.inner.export_container(container), |chunk| {
            Ok(chunk.to_vec())
        })
    }

    /// Commits container filesystem changes to an image.
    ///
    /// No owned equivalent: the owned transport has no `container_commit`, and
    /// none was invented. `POST /commit` carries its container, pause flag, repo,
    /// tag, comment, author, and changes as query parameters and answers with an
    /// image id, so a `raw::commit` would be a mechanical projection once there
    /// is a reason to have one.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or Engine API error.
    pub async fn commit_container(&self, options: CommitContainerOptions) -> Result<String, Error> {
        let mut builder = bollard::query_parameters::CommitContainerOptionsBuilder::default()
            .container(&options.container)
            .pause(options.pause);
        if let Some(repository) = options.repository.as_deref() {
            builder = builder.repo(repository);
        }
        if let Some(tag) = options.tag.as_deref() {
            builder = builder.tag(tag);
        }
        if let Some(comment) = options.comment.as_deref() {
            builder = builder.comment(comment);
        }
        if let Some(author) = options.author.as_deref() {
            builder = builder.author(author);
        }
        if !options.changes.is_empty() {
            builder = builder.changes(&options.changes.join("\n"));
        }
        self.inner
            .commit_container(builder.build(), bollard::models::ContainerConfig::default())
            .await
            .map(|response| response.id)
            .map_err(Error::from)
    }

    /// Opens a container path archive after fetching its HEAD metadata.
    ///
    /// No owned equivalent: this is a `HEAD /containers/{id}/archive` followed by
    /// a streaming `GET` of the same path, and the owned transport has neither an
    /// archive operation nor a hijacked-response stream to hand back as a
    /// [`DockerStream`].
    ///
    /// # Errors
    ///
    /// Returns a transport, missing-header, or response error.
    pub async fn container_archive(
        &self,
        container: &str,
        path: &str,
    ) -> Result<ContainerArchive, Error> {
        let info = bollard::query_parameters::ContainerArchiveInfoOptionsBuilder::default()
            .path(path)
            .build();
        let stat = self
            .inner
            .get_container_archive_info(container, Some(info))
            .await
            .map_err(Error::from)?;
        let download = bollard::query_parameters::DownloadFromContainerOptionsBuilder::default()
            .path(path)
            .build();
        let stream = map_bollard_stream(
            self.inner
                .download_from_container(container, Some(download)),
            |chunk| Ok(chunk.to_vec()),
        );
        Ok(ContainerArchive {
            stat: ContainerPathStat {
                name: stat.name,
                size: stat.size,
                mode: stat.file_mode,
                link_target: (!stat.link_target.is_empty()).then_some(stat.link_target),
            },
            stream,
        })
    }

    /// Reports what a path inside a container is, without reading it.
    ///
    /// The copy path needs this to tell a destination directory from a
    /// destination *file name*, and the two are not distinguishable from the
    /// local side: `docker cp a.txt web:/tmp/b.txt` and `docker cp a.txt
    /// web:/tmp/existing-dir` differ only in what the container already holds.
    ///
    /// The Engine answers a missing path with 404, which is an answer rather
    /// than a failure: "not there" is exactly what a caller asking whether a
    /// destination exists wants to know. Every other error is returned, because
    /// a caller that cannot tell a missing path from an unreachable daemon
    /// would guess.
    ///
    /// # Errors
    ///
    /// Returns an Engine API or transport error other than a 404 for the path.
    /// No owned equivalent: there is no `raw` archive operation, and the
    /// `404`-means-`None` rule above is part of this method's contract rather
    /// than a transport detail, so it stays where it can be read.
    pub async fn container_path_stat(
        &self,
        container: &str,
        path: &str,
    ) -> Result<Option<ContainerPathStat>, Error> {
        let info = bollard::query_parameters::ContainerArchiveInfoOptionsBuilder::default()
            .path(path)
            .build();
        match self
            .inner
            .get_container_archive_info(container, Some(info))
            .await
        {
            Ok(stat) => Ok(Some(ContainerPathStat {
                name: stat.name,
                size: stat.size,
                mode: stat.file_mode,
                link_target: (!stat.link_target.is_empty()).then_some(stat.link_target),
            })),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(None),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Streams an archive file into a container path.
    ///
    /// No owned equivalent: `PUT /containers/{id}/archive` needs a request body
    /// produced from a file handle as it is read, and the owned transport has no
    /// archive operation to carry one.
    ///
    /// The file handle is owned by the request body and is dropped only after
    /// upload completion or cancellation.
    ///
    /// # Errors
    ///
    /// Returns a file-open, transport, or Engine API error.
    pub async fn upload_container_archive(
        &self,
        container: &str,
        archive_path: &Path,
        options: ContainerArchiveUploadOptions,
    ) -> Result<(), Error> {
        let file = tokio::fs::File::open(archive_path).await.map_err(|error| {
            Error::invalid_input(format!(
                "failed to open copy archive '{}': {error}",
                archive_path.display()
            ))
        })?;
        let bytes = stream::unfold(Some(file), |state| async move {
            let mut file = state?;
            let mut buffer = vec![0_u8; 64 * 1024];
            match file.read(&mut buffer).await {
                Ok(0) => None,
                Ok(read) => {
                    buffer.truncate(read);
                    Some((Ok(buffer.into()), Some(file)))
                }
                Err(error) => Some((Err(error), None)),
            }
        });
        let mut query = bollard::query_parameters::UploadToContainerOptionsBuilder::default()
            .path(&options.path)
            .copy_uidgid(if options.copy_user_and_group {
                "1"
            } else {
                "0"
            });
        if options.no_overwrite_directory_with_file {
            query = query.no_overwrite_dir_non_dir("1");
        }
        self.inner
            .upload_to_container(
                container,
                Some(query.build()),
                bollard::body_try_stream(bytes),
            )
            .await
            .map_err(Error::from)
    }

    /// Creates a container checkpoint.
    ///
    /// No owned equivalent: the owned transport has no checkpoint operation, and
    /// none was invented. `create_checkpoint`, `list_checkpoints`, and
    /// `remove_checkpoint` are the same one gap, and these endpoints also need
    /// the API version that carries them, which a client that omits the version
    /// is answered with a different one of.
    ///
    /// # Errors
    ///
    /// Returns a transport or daemon-capability error when checkpointing is not
    /// enabled by the daemon.
    pub async fn create_checkpoint(
        &self,
        container: &str,
        options: CheckpointOptions,
    ) -> Result<(), Error> {
        self.inner
            .create_checkpoint(
                container,
                bollard::container::CreateCheckpointOptions {
                    checkpoint_id: options.checkpoint_id.unwrap_or_default(),
                    checkpoint_dir: options.checkpoint_dir,
                    exit: options.exit,
                },
            )
            .await
            .map_err(Error::from)
    }

    /// Lists checkpoints for a container.
    ///
    /// No owned equivalent: the owned transport has no checkpoint operation.
    ///
    /// # Errors
    ///
    /// Returns a transport or daemon-capability error.
    pub async fn list_checkpoints(
        &self,
        container: &str,
        checkpoint_dir: Option<&str>,
    ) -> Result<Vec<Checkpoint>, Error> {
        let options = checkpoint_dir.map(|directory| bollard::container::ListCheckpointsOptions {
            checkpoint_dir: Some(directory.to_owned()),
        });
        self.inner
            .list_checkpoints(container, options)
            .await
            .map(|checkpoints| {
                checkpoints
                    .into_iter()
                    .map(|checkpoint| Checkpoint {
                        name: checkpoint.name,
                    })
                    .collect()
            })
            .map_err(Error::from)
    }

    /// Removes a container checkpoint.
    ///
    /// No owned equivalent: the owned transport has no checkpoint operation.
    ///
    /// # Errors
    ///
    /// Returns a transport or daemon-capability error.
    pub async fn remove_checkpoint(
        &self,
        container: &str,
        checkpoint: &str,
        checkpoint_dir: Option<&str>,
    ) -> Result<(), Error> {
        let options = checkpoint_dir.map(|directory| bollard::container::DeleteCheckpointOptions {
            checkpoint_dir: Some(directory.to_owned()),
        });
        self.inner
            .delete_checkpoint(container, checkpoint, options)
            .await
            .map_err(Error::from)
    }

    /// Creates an exec instance and opens its caller-owned session.
    ///
    /// This stays on the generated client for the same reason
    /// [`attach_container`](Self::attach_container) does, and one step further
    /// along: `raw::exec_start` sends `POST /exec/{id}/start` and then drops the
    /// response, so it reports only that the daemon accepted the start. The
    /// returned [`ExecSession`] is a live output stream and input handle. The
    /// owned `raw::exec_create` would cover the first half of this call, but
    /// routing only that half would put the create on one transport and the start
    /// on another for the same logical operation, which is worse than leaving
    /// both on one.
    ///
    /// # Errors
    ///
    /// Returns a transport, HTTP-upgrade, or response error.
    pub async fn start_exec(
        &self,
        container: &str,
        options: ExecOptions,
    ) -> Result<(String, ExecSession), Error> {
        let tty = options.tty;
        let raw_endpoint = self
            .raw_exec_endpoint
            .as_deref()
            .filter(|_| !options.attach_stdin);
        let created = self
            .inner
            .create_exec(
                container,
                bollard::exec::CreateExecOptions {
                    attach_stdin: options.attach_stdin.then_some(true),
                    attach_stdout: options.attach_stdout.then_some(true),
                    attach_stderr: options.attach_stderr.then_some(true),
                    tty: options.tty.then_some(true),
                    detach_keys: options.detach_keys,
                    env: optional_vec(options.environment),
                    cmd: Some(options.command),
                    privileged: options.privileged.then_some(true),
                    user: options.user,
                    working_dir: options.working_dir,
                },
            )
            .await
            .map_err(Error::from)?;
        if let Some(endpoint) = raw_endpoint {
            let (output, input) = start_http_exec(endpoint, &created.id, tty).await?;
            return Ok((created.id, AttachedSession { output, input }));
        }
        let started = self
            .inner
            .start_exec(
                &created.id,
                Some(bollard::exec::StartExecOptions {
                    detach: false,
                    tty: options.tty,
                    output_capacity: Some(32 * 1024),
                }),
            )
            .await
            .map_err(Error::from)?;
        match started {
            bollard::exec::StartExecResults::Attached { output, input } => Ok((
                created.id,
                AttachedSession {
                    output: map_bollard_stream(output, |frame| Ok(map_log_frame(frame))),
                    input: SessionInput::new(input),
                },
            )),
            bollard::exec::StartExecResults::Detached => Err(Error::invalid_input(
                "daemon detached a non-detached exec session",
            )),
        }
    }

    /// Reads exec state after an attached session ends.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn exec_state(&self, exec_id: &str) -> Result<ExecState, Error> {
        // The repository-owned transport first, Bollard second. The Engine spells
        // the id `ID` on this answer and `Id` on the create answer, and the
        // owned `ExecInspect::state` reads the one that is actually sent.
        if let Ok(engine) = self.raw_engine() {
            return Ok(raw::exec_inspect(&engine, exec_id).await?.state());
        }
        self.inner
            .inspect_exec(exec_id)
            .await
            .map(|state| ExecState {
                id: state.id,
                running: state.running.unwrap_or(false),
                exit_code: state.exit_code,
            })
            .map_err(Error::from)
    }

    /// Resizes the pseudo-TTY of an exec instance.
    ///
    /// The daemon ignores the request when the exec instance was created
    /// without `tty`.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn resize_exec(
        &self,
        exec_id: &str,
        options: ExecResizeOptions,
    ) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second.
        if let Ok(engine) = self.raw_engine() {
            return raw::exec_resize(&engine, exec_id, &options).await;
        }
        self.inner
            .resize_exec(
                exec_id,
                bollard::exec::ResizeExecOptions {
                    height: options.height,
                    width: options.width,
                },
            )
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod create_answer_tests {
    //! What the generated client does with a create *answer*.
    //!
    //! `create_container` prefers the owned transport, so on a plain-HTTP or
    //! Unix-socket client the fallback is unreachable and the integration suite
    //! can only measure one implementation. This module measures the other half:
    //! it decodes the recorded daemon bytes through the generated model, which is
    //! the only place that model can still be reached from a test at all.
    //!
    //! It is reachable here — and only here — because this is an in-crate test.
    //! `bollard` is a dependency of the library, not a dev-dependency, so a test
    //! under `tests/` cannot name it; and `ContainerCreateDocument` is private to
    //! `raw::containers`, so the owned projection cannot be named from here
    //! either. The two halves are therefore measured in the two places each is
    //! visible, over the same four recorded answers, and
    //! `raw_differential_container_ops.rs` asserts the owned half against these
    //! bytes.

    use crate::ContainerCreateResult;

    /// The answer a real daemon gives a create with nothing to warn about.
    ///
    /// Recorded from Docker Engine 29.8.0.
    const NO_WARNINGS: &str = r#"{"Id":"ebf1546b","Warnings":[]}"#;

    /// The answer a real daemon gives a create it had something to say about.
    const WITH_WARNINGS: &str = r#"{"Id":"ebf1546b","Warnings":["port 80 is already in use"]}"#;

    /// The answer a daemon gives when the list is explicitly null.
    const NULL_WARNINGS: &str = r#"{"Id":"ebf1546b","Warnings":null}"#;

    /// The answer a daemon gives when it has no list to send at all.
    const NO_MEMBER: &str = r#"{"Id":"ebf1546b"}"#;

    /// Decodes through the generated model, which is what the fallback does.
    fn through_generated(answer: &str) -> Result<ContainerCreateResult, String> {
        let response: bollard::models::ContainerCreateResponse =
            serde_json::from_str(answer).map_err(|error| error.to_string())?;
        Ok(ContainerCreateResult {
            id: response.id,
            warnings: response.warnings,
        })
    }

    #[test]
    fn the_generated_client_reads_the_daemons_warnings() {
        // The two answers a real daemon sends, decoded to the repository-owned
        // result. `Warnings` carries `deserialize_nonoptional_vec`, so `null`
        // becomes an empty list, and the id is the Engine's own `Id` member.
        let empty = through_generated(NO_WARNINGS).expect("an empty warning list");
        assert_eq!(empty.id, "ebf1546b");
        assert!(empty.warnings.is_empty());

        let warned = through_generated(WITH_WARNINGS).expect("a populated warning list");
        assert_eq!(warned.id, "ebf1546b");
        assert_eq!(
            warned.warnings,
            vec!["port 80 is already in use".to_owned()]
        );
    }

    #[test]
    fn a_null_warning_list_is_an_empty_list() {
        // `deserialize_nonoptional_vec` maps `Option::None` to `Vec::new()`,
        // which is the right reading: a daemon that sends `null` has nothing to
        // warn about, which is not the same as a list this client failed to read.
        let result = through_generated(NULL_WARNINGS).expect("a null warning list");
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn a_missing_warning_list_is_a_decode_error_on_the_generated_path() {
        // This is the one place the two paths differ, and it is measured rather
        // than assumed. The generated model declares `warnings` with no
        // `#[serde(default)]`, so an answer that omits the member entirely is a
        // decode error. The owned document declares `#[serde(default)]` over the
        // same non-optional `Vec`, so it reads the same bytes as an empty list.
        //
        // The divergence is in the owned transport's favour and does not arise
        // against a daemon that sends the member — Engine 29.8.0 answers every
        // create with a `Warnings` array. It is recorded because "the two paths
        // return the same value" is otherwise only true of the answers a daemon
        // actually sends, and someone deciding whether the paths are
        // interchangeable should know which one is which.
        let error = through_generated(NO_MEMBER).expect_err("a missing member must not decode");
        assert!(
            error.contains("Warnings"),
            "the failure must name the member it wanted: {error}"
        );
    }
}
