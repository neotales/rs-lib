//! Typed Docker Engine system operations.
//!
//! Bollard owns transport, API-version selection, and wire decoding. This
//! module maps the system endpoints to repository-owned public types.
//!
//! # Which transport serves a system operation
//!
//! [`DockerClient::info`], [`DockerClient::info_value`],
//! [`DockerClient::disk_usage`], and [`DockerClient::prune_build_cache`] prefer
//! the repository-owned Engine transport and keep their generated-client paths,
//! following the rule on [`DockerClient::raw_engine`]: the fallback is a
//! *routing* decision for the endpoint kinds the owned transport cannot reach,
//! not an error path.
//!
//! [`DockerClient::system_events`] still uses the generated client. The owned
//! [`raw::events`] answers a frame stream and this method's contract is a typed
//! [`EventStream`] over the generated model, so moving it would change the
//! value a caller receives rather than only the transport that produced it.
//! That is separate work, and it is stated here so no caller discovers it by
//! looking for a missing version prefix.
//!
//! # A `GET /info` answer is returned as sent, and that is a gain
//!
//! The owned [`raw::info`] returns the daemon's document rather than a
//! generated struct, which matters more for `/info` than for most endpoints: the
//! generated `SystemInfo` model declares closed enums for `CgroupDriver`,
//! `CgroupVersion`, and `Isolation`, so a value this client does not enumerate
//! fails the *whole* decode. The owned path has no enum to disagree with, and
//! [`map_info_document`] reads the members the repository's [`SystemInfo`]
//! names out of the document by name.
//!
//! Every wire spelling is written out rather than derived from a casing rule,
//! because a rule would be wrong: the Engine sends `NCPU`, `MemTotal`,
//! `NEventsListener`, `OSVersion`, `OSType`, `CPUShares`, `CPUSet`, and
//! `IPv4Forwarding` in four different conventions at once.

use std::{
    collections::BTreeMap,
    fmt,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::Stream;
use serde::Serialize;
use serde_json::Value;

use crate::{DockerClient, Error, raw};

/// Resource categories accepted by `GET /system/df`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum DiskUsageType {
    /// Container usage.
    Container,
    /// Image usage.
    Image,
    /// Volume usage.
    Volume,
    /// Build-cache usage.
    BuildCache,
}

impl DiskUsageType {
    /// Returns the Engine query value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Image => "image",
            Self::Volume => "volume",
            Self::BuildCache => "build-cache",
        }
    }
}

impl fmt::Display for DiskUsageType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Query options for `GET /system/df`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiskUsageOptions {
    /// Resource categories to request. `None` leaves selection to the daemon.
    pub types: Option<Vec<DiskUsageType>>,
    /// Request detailed usage entries.
    pub verbose: bool,
}

impl DiskUsageOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            types: None,
            verbose: false,
        }
    }

    /// Sets the resource categories.
    #[must_use]
    pub fn with_types<I>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = DiskUsageType>,
    {
        self.types = Some(types.into_iter().collect());
        self
    }

    /// Enables or disables detailed entries.
    #[must_use]
    pub const fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

/// Aggregate usage for one Docker resource category.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsageCategory {
    /// Number of active resources.
    pub active_count: Option<i64>,
    /// Number of known resources.
    pub total_count: Option<i64>,
    /// Reclaimable bytes.
    pub reclaimable: Option<i64>,
    /// Bytes in use.
    pub total_size: Option<i64>,
    /// Typed projections of verbose entries.
    pub items: Vec<DiskUsageItem>,
}

/// A bounded, repository-owned projection of a verbose disk-usage entry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsageItem {
    /// Resource identifier.
    pub id: Option<String>,
    /// Resource name, tag, or container name.
    pub name: Option<String>,
    /// Parent identifier, when applicable.
    pub parent_id: Option<String>,
    /// Resource size in bytes.
    pub size: Option<i64>,
    /// Volume reference count, when available.
    pub reference_count: Option<i64>,
    /// Build-cache in-use flag, when available.
    pub in_use: Option<bool>,
    /// Creation timestamp, when available.
    pub created: Option<i64>,
    /// Resource labels.
    pub labels: BTreeMap<String, String>,
    /// Image tags or container names.
    pub references: Vec<String>,
    /// Volume storage driver.
    pub driver: Option<String>,
    /// Category that produced this projection.
    pub resource_type: Option<DiskUsageType>,
}

/// Disk usage returned by Engine API v1.53.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsage {
    /// Image usage.
    pub image_usage: Option<DiskUsageCategory>,
    /// Container usage.
    pub container_usage: Option<DiskUsageCategory>,
    /// Volume usage.
    pub volume_usage: Option<DiskUsageCategory>,
    /// Build-cache usage.
    pub build_cache_usage: Option<DiskUsageCategory>,
}

/// Stable scalar fields selected from `GET /info`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SystemInfo {
    /// Daemon identifier.
    pub id: Option<String>,
    /// Total containers.
    pub containers: Option<i64>,
    /// Running containers.
    pub containers_running: Option<i64>,
    /// Paused containers.
    pub containers_paused: Option<i64>,
    /// Stopped containers.
    pub containers_stopped: Option<i64>,
    /// Total images.
    pub images: Option<i64>,
    /// Storage driver.
    pub storage_driver: Option<String>,
    /// Storage-driver status rows.
    pub driver_status: Option<Vec<Vec<String>>>,
    /// Docker state directory.
    pub docker_root_dir: Option<String>,
    /// Host operating system.
    pub operating_system: Option<String>,
    /// Host operating-system version.
    pub os_version: Option<String>,
    /// Generic operating-system type.
    pub os_type: Option<String>,
    /// Daemon architecture.
    pub architecture: Option<String>,
    /// Logical CPU count.
    pub cpu_count: Option<i64>,
    /// Total memory in bytes.
    pub memory_total: Option<i64>,
    /// Hostname.
    pub name: Option<String>,
    /// Docker daemon version.
    pub server_version: Option<String>,
    /// Host kernel version.
    pub kernel_version: Option<String>,
    /// Daemon system time.
    pub system_time: Option<String>,
    /// Default logging driver.
    pub logging_driver: Option<String>,
    /// Default OCI runtime.
    pub default_runtime: Option<String>,
    /// Cgroup driver.
    pub cgroup_driver: Option<String>,
    /// Cgroup version.
    pub cgroup_version: Option<String>,
    /// Host capability flags.
    pub memory_limit: Option<bool>,
    /// Host capability flags.
    pub swap_limit: Option<bool>,
    /// Host capability flags.
    pub cpu_cfs_period: Option<bool>,
    /// Host capability flags.
    pub cpu_cfs_quota: Option<bool>,
    /// Host capability flags.
    pub cpu_shares: Option<bool>,
    /// Host capability flags.
    pub cpu_set: Option<bool>,
    /// Host capability flags.
    pub pids_limit: Option<bool>,
    /// Host capability flags.
    pub oom_kill_disable: Option<bool>,
    /// IPv4 forwarding state.
    pub ipv4_forwarding: Option<bool>,
    /// Debug-mode state.
    pub debug: Option<bool>,
    /// Active event-listener count.
    pub event_listeners: Option<i64>,
    /// Daemon labels.
    pub labels: Option<Vec<String>>,
    /// Security options.
    pub security_options: Option<Vec<String>>,
    /// Daemon warnings.
    pub warnings: Option<Vec<String>>,
    /// Experimental-build state.
    pub experimental_build: Option<bool>,
    /// Live-restore state.
    pub live_restore_enabled: Option<bool>,
    /// Isolation technology.
    pub isolation: Option<String>,
    /// docker-init binary name.
    pub init_binary: Option<String>,
}

/// Actor metadata attached to a Docker event.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EventActor {
    /// Resource identifier.
    pub id: Option<String>,
    /// Resource attributes.
    pub attributes: BTreeMap<String, String>,
}

/// A repository-owned Docker event projection.
///
/// Type and scope remain strings so daemon-specific values can pass through
/// without exposing Bollard generated enums.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SystemEvent {
    /// Resource type, such as `container` or `image`.
    pub resource_type: Option<String>,
    /// Event action, such as `start` or `die`.
    pub action: Option<String>,
    /// Resource that emitted the event.
    pub actor: Option<EventActor>,
    /// Event scope.
    pub scope: Option<String>,
    /// Unix event time in seconds.
    pub time: Option<i64>,
    /// Unix event time in nanoseconds.
    pub time_nano: Option<i64>,
}

/// Query options for `GET /events`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventOptions {
    /// Lower event-time bound.
    pub since: Option<String>,
    /// Upper event-time bound.
    pub until: Option<String>,
    /// Docker event filters.
    pub filters: Option<BTreeMap<String, Vec<String>>>,
}

impl EventOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            since: None,
            until: None,
            filters: None,
        }
    }

    /// Sets the lower event-time bound.
    #[must_use]
    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = Some(since.into());
        self
    }

    /// Sets the upper event-time bound.
    #[must_use]
    pub fn with_until(mut self, until: impl Into<String>) -> Self {
        self.until = Some(until.into());
        self
    }

    /// Adds or replaces one event filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// An owned response stream for `GET /events`.
///
/// The handle owns the response body independently of the client borrow. Drop
/// or [`EventStream::cancel`] releases the body and cancels the HTTP response.
#[must_use = "an EventStream must be consumed or explicitly cancelled"]
pub struct EventStream {
    inner: Pin<Box<dyn Stream<Item = Result<SystemEvent, Error>> + Send>>,
}

impl std::fmt::Debug for EventStream {
    /// Prints the handle's name, because there is nothing else it may print.
    ///
    /// The field is a `Pin<Box<dyn Stream<Item = Result<SystemEvent, Error>>>>`
    /// and a `dyn Stream` is not `Debug`, so this cannot be derived at all. The
    /// items are the daemon's event log — container ids, image names, and the
    /// attribute map the daemon attaches to each — and none of it has been read
    /// yet, so there is no progress to report either.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EventStream")
    }
}

impl EventStream {
    fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<bollard::models::EventMessage, bollard::errors::Error>>
            + Send
            + 'static,
    {
        Self {
            inner: Box::pin(MappedEventStream {
                inner: Box::pin(stream),
            }),
        }
    }

    /// Waits for the next event or stream error.
    #[must_use]
    pub async fn next(&mut self) -> Option<Result<SystemEvent, Error>> {
        poll_fn(|context| self.inner.as_mut().poll_next(context)).await
    }

    /// Explicitly cancels and releases the response stream.
    pub fn cancel(self) {
        drop(self);
    }
}

impl Stream for EventStream {
    type Item = Result<SystemEvent, Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

// The pinned allocation is behind a Box, so moving the handle cannot move
// the stream allocation.
impl Unpin for EventStream {}

struct MappedEventStream<S> {
    inner: Pin<Box<S>>,
}

impl<S> Stream for MappedEventStream<S>
where
    S: Stream<Item = Result<bollard::models::EventMessage, bollard::errors::Error>> + Send,
{
    type Item = Result<SystemEvent, Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut().inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event))) => Poll::Ready(Some(Ok(map_event(event)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(Error::from(error)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Unpin for MappedEventStream<S> {}

/// Query options for `POST /build/prune`.
///
/// Engine API v1.53 has no daemon-wide `/system/prune` endpoint. This type
/// covers the native build-cache prune operation; resource-specific prune
/// calls are not silently composed here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BuildCachePruneOptions {
    /// Cache bytes to retain.
    pub reserved_space: Option<i64>,
    /// Maximum cache bytes to retain.
    pub max_used_space: Option<i64>,
    /// Target free space after pruning.
    pub min_free_space: Option<i64>,
    /// Remove all cache types.
    pub all: Option<bool>,
    /// Build-cache filters.
    pub filters: Option<BTreeMap<String, Vec<String>>>,
}

impl BuildCachePruneOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reserved_space: None,
            max_used_space: None,
            min_free_space: None,
            all: None,
            filters: None,
        }
    }

    /// Sets retained cache bytes.
    #[must_use]
    pub const fn with_reserved_space(mut self, bytes: i64) -> Self {
        self.reserved_space = Some(bytes);
        self
    }

    /// Sets maximum retained cache bytes.
    #[must_use]
    pub const fn with_max_used_space(mut self, bytes: i64) -> Self {
        self.max_used_space = Some(bytes);
        self
    }

    /// Sets target free space.
    #[must_use]
    pub const fn with_min_free_space(mut self, bytes: i64) -> Self {
        self.min_free_space = Some(bytes);
        self
    }

    /// Selects all cache types.
    #[must_use]
    pub const fn with_all(mut self, all: bool) -> Self {
        self.all = Some(all);
        self
    }

    /// Adds or replaces one build-cache filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// Result of `POST /build/prune`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BuildCachePruneResult {
    /// Removed cache identifiers.
    pub caches_deleted: Vec<String>,
    /// Reclaimed bytes.
    pub space_reclaimed: Option<i64>,
}

impl DockerClient {
    /// Reads selected fields from `GET /info`.
    ///
    /// # Errors
    ///
    /// Returns a repository error for a daemon, transport, or decode failure.
    pub async fn info(&self) -> Result<SystemInfo, Error> {
        // The repository-owned transport first, Bollard second. See the note on
        // `DockerClient::raw_engine` for why the fallback is a routing decision
        // rather than an error path.
        if let Ok(engine) = self.raw_engine() {
            return Ok(map_info_document(&raw::info(&engine).await?));
        }
        self.inner
            .info()
            .await
            .map(map_system_info)
            .map_err(Error::from)
    }

    /// Returns the complete `GET /info` object as repository-owned JSON.
    ///
    /// # Errors
    ///
    /// Returns a transport or serialization error.
    pub async fn info_value(&self) -> Result<Value, Error> {
        // The owned transport hands back the document exactly as the daemon
        // sent it, where the generated path decodes into a model and
        // re-serializes it — which drops every member the model does not
        // declare and *fails outright* on a closed enum the daemon has grown a
        // value for. The declared return type is the same JSON either way, so
        // this is a widening, not a change of contract.
        if let Ok(engine) = self.raw_engine() {
            return raw::info(&engine).await;
        }
        self.inner
            .info()
            .await
            .map_err(Error::from)
            .and_then(|value| serde_json::to_value(value).map_err(Error::serialization))
    }

    /// Reads `GET /system/df` using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for query serialization, transport, or
    /// response-decoding failures.
    pub async fn disk_usage(&self, options: Option<DiskUsageOptions>) -> Result<DiskUsage, Error> {
        // The repository-owned transport first, Bollard second.
        //
        // `raw::disk_usage` answers a retained document rather than the typed
        // model, and its `usage()` is the same four-member projection this
        // method has always returned — so the answer a caller receives does not
        // change, while the request does: the owned path appends the repeated
        // `type=` pairs where the rest of the query is built, instead of bolting
        // them on afterwards with a request modifier that matches on the path.
        if let Ok(engine) = self.raw_engine() {
            let report = raw::disk_usage(&engine, &options.unwrap_or_default()).await?;
            return Ok(report.usage());
        }
        let options = match options {
            Some(options) => {
                let type_query = options
                    .types
                    .as_deref()
                    .filter(|types| !types.is_empty())
                    .map(encode_type_query);
                let bollard_options = bollard::query_parameters::DataUsageOptionsBuilder::default()
                    .verbose(options.verbose)
                    .build();
                if let Some(type_query) = type_query {
                    // Bollard 0.21.1 exposes `type` as a nested sequence,
                    // which serde_urlencoded 0.7 cannot encode as a struct
                    // field. Add the repeated values with Bollard's request
                    // modifier while retaining its normal response decoder.
                    let docker = self
                        .inner
                        .clone()
                        .with_request_modifier(move |mut request| {
                            if request.uri().path().ends_with("/system/df") {
                                add_query_parameter(&mut request, &type_query, true);
                            }
                            request
                        });
                    return docker
                        .df(Some(bollard_options))
                        .await
                        .map(map_disk_usage)
                        .map_err(Error::from);
                }
                Some(bollard_options)
            }
            None => None,
        };
        self.inner
            .df(options)
            .await
            .map(map_disk_usage)
            .map_err(Error::from)
    }

    /// Opens an owned response stream for `GET /events`.
    ///
    /// Request and response errors are delivered as stream items. Dropping the
    /// returned handle or calling [`EventStream::cancel`] cancels the body.
    pub fn system_events(&self, options: Option<EventOptions>) -> EventStream {
        let filter_query = options
            .as_ref()
            .and_then(|options| options.filters.as_ref())
            .map(encode_filters);
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::EventsOptionsBuilder::default();
            if let Some(since) = options.since.as_deref() {
                builder = builder.since(since);
            }
            if let Some(until) = options.until.as_deref() {
                builder = builder.until(until);
            }
            builder.build()
        });
        let docker = self
            .inner
            .clone()
            .with_request_modifier(move |mut request| {
                if request.uri().path().ends_with("/events") {
                    if let Some(filter_query) = filter_query.as_deref() {
                        add_query_parameter(&mut request, filter_query, false);
                    }
                    request.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                request
            });
        EventStream::new(docker.events(options))
    }

    /// Removes unused build-cache records with `POST /build/prune`.
    ///
    /// The Engine API reference documents a daemon-wide `POST /system/prune`,
    /// but no Docker daemon serves it: the route is absent at every version,
    /// while `POST /containers/prune` beside it answers normally. `docker
    /// system prune` therefore composes the per-resource prune calls itself,
    /// which is why it can name the networks it deleted while a single
    /// summary could not.
    ///
    /// This method composes nothing. Reclaiming a category is destructive and
    /// irreversible, and calling the prune endpoints one after another means a
    /// failure part way through leaves the daemon in a state neither the caller
    /// nor the user asked for, with no summary of what was already gone. The CLI
    /// reports that rather than performing it.
    ///
    /// # Errors
    ///
    /// Returns a repository error for query serialization, transport, or
    /// response-decoding failures.
    pub async fn prune_build_cache(
        &self,
        options: Option<BuildCachePruneOptions>,
    ) -> Result<BuildCachePruneResult, Error> {
        // The repository-owned transport first, Bollard second. The byte
        // parameters keep the Engine's hyphens on both paths, so this is a
        // path and ordering change rather than a spelling change.
        if let Ok(engine) = self.raw_engine() {
            return raw::prune_build_cache(&engine, &options.unwrap_or_default()).await;
        }
        let filter_query = options
            .as_ref()
            .and_then(|options| options.filters.as_ref())
            .map(encode_filters);
        let options = options.map(|options| {
            let mut builder = bollard::query_parameters::PruneBuildOptionsBuilder::default();
            if let Some(reserved_space) = options.reserved_space {
                builder = builder.reserved_space(reserved_space);
            }
            if let Some(max_used_space) = options.max_used_space {
                builder = builder.max_used_space(max_used_space);
            }
            if let Some(min_free_space) = options.min_free_space {
                builder = builder.min_free_space(min_free_space);
            }
            if let Some(all) = options.all {
                builder = builder.all(all);
            }
            builder.build()
        });
        let response = if let Some(filter_query) = filter_query {
            let docker = self
                .inner
                .clone()
                .with_request_modifier(move |mut request| {
                    if request.uri().path().ends_with("/build/prune") {
                        add_query_parameter(&mut request, &filter_query, false);
                    }
                    request
                });
            docker.prune_build(options).await
        } else {
            self.inner.prune_build(options).await
        };
        response.map(map_build_cache_prune).map_err(Error::from)
    }
}

/// Projects the daemon's `GET /info` document onto the repository's model.
///
/// This is the same projection [`map_system_info`] performs over the generated
/// model, spelled out over the document the owned transport returned as sent.
/// Every member the generated model declares is read here, and three of them —
/// `CgroupDriver`, `CgroupVersion`, and `Isolation` — are closed enums there,
/// so a value this client does not enumerate fails the whole decode on that
/// path and reads as the daemon's own text here.
///
/// A member the daemon did not send reads as absent rather than as a zero, and
/// the whole document is still available from [`raw::info`] for a member this
/// model has no field for.
fn map_info_document(info: &Value) -> SystemInfo {
    SystemInfo {
        id: string_field(info, "ID"),
        containers: integer_field(info, "Containers"),
        containers_running: integer_field(info, "ContainersRunning"),
        containers_paused: integer_field(info, "ContainersPaused"),
        containers_stopped: integer_field(info, "ContainersStopped"),
        images: integer_field(info, "Images"),
        storage_driver: string_field(info, "Driver"),
        driver_status: string_rows_field(info, "DriverStatus"),
        docker_root_dir: string_field(info, "DockerRootDir"),
        operating_system: string_field(info, "OperatingSystem"),
        os_version: string_field(info, "OSVersion"),
        os_type: string_field(info, "OSType"),
        architecture: string_field(info, "Architecture"),
        cpu_count: integer_field(info, "NCPU"),
        memory_total: integer_field(info, "MemTotal"),
        name: string_field(info, "Name"),
        server_version: string_field(info, "ServerVersion"),
        kernel_version: string_field(info, "KernelVersion"),
        system_time: string_field(info, "SystemTime"),
        logging_driver: string_field(info, "LoggingDriver"),
        default_runtime: string_field(info, "DefaultRuntime"),
        cgroup_driver: string_field(info, "CgroupDriver"),
        cgroup_version: string_field(info, "CgroupVersion"),
        memory_limit: bool_field(info, "MemoryLimit"),
        swap_limit: bool_field(info, "SwapLimit"),
        cpu_cfs_period: bool_field(info, "CpuCfsPeriod"),
        cpu_cfs_quota: bool_field(info, "CpuCfsQuota"),
        cpu_shares: bool_field(info, "CPUShares"),
        cpu_set: bool_field(info, "CPUSet"),
        pids_limit: bool_field(info, "PidsLimit"),
        oom_kill_disable: bool_field(info, "OomKillDisable"),
        ipv4_forwarding: bool_field(info, "IPv4Forwarding"),
        debug: bool_field(info, "Debug"),
        event_listeners: integer_field(info, "NEventsListener"),
        labels: string_list_field(info, "Labels"),
        security_options: string_list_field(info, "SecurityOptions"),
        warnings: string_list_field(info, "Warnings"),
        experimental_build: bool_field(info, "ExperimentalBuild"),
        live_restore_enabled: bool_field(info, "LiveRestoreEnabled"),
        isolation: string_field(info, "Isolation"),
        init_binary: string_field(info, "InitBinary"),
    }
}

fn map_system_info(info: bollard::models::SystemInfo) -> SystemInfo {
    SystemInfo {
        id: info.id,
        containers: info.containers,
        containers_running: info.containers_running,
        containers_paused: info.containers_paused,
        containers_stopped: info.containers_stopped,
        images: info.images,
        storage_driver: info.driver,
        driver_status: info.driver_status,
        docker_root_dir: info.docker_root_dir,
        operating_system: info.operating_system,
        os_version: info.os_version,
        os_type: info.os_type,
        architecture: info.architecture,
        cpu_count: info.ncpu,
        memory_total: info.mem_total,
        name: info.name,
        server_version: info.server_version,
        kernel_version: info.kernel_version,
        system_time: info.system_time,
        logging_driver: info.logging_driver,
        default_runtime: info.default_runtime,
        cgroup_driver: info.cgroup_driver.map(|value| value.to_string()),
        cgroup_version: info.cgroup_version.map(|value| value.to_string()),
        memory_limit: info.memory_limit,
        swap_limit: info.swap_limit,
        cpu_cfs_period: info.cpu_cfs_period,
        cpu_cfs_quota: info.cpu_cfs_quota,
        cpu_shares: info.cpu_shares,
        cpu_set: info.cpu_set,
        pids_limit: info.pids_limit,
        oom_kill_disable: info.oom_kill_disable,
        ipv4_forwarding: info.ipv4_forwarding,
        debug: info.debug,
        event_listeners: info.n_events_listener,
        labels: info.labels,
        security_options: info.security_options,
        warnings: info.warnings,
        experimental_build: info.experimental_build,
        live_restore_enabled: info.live_restore_enabled,
        isolation: info.isolation.map(|value| value.to_string()),
        init_binary: info.init_binary,
    }
}

fn map_event(event: bollard::models::EventMessage) -> SystemEvent {
    SystemEvent {
        resource_type: event.typ.map(|value| value.to_string()),
        action: event.action,
        actor: event.actor.map(|actor| EventActor {
            id: actor.id,
            attributes: actor.attributes.unwrap_or_default().into_iter().collect(),
        }),
        scope: event.scope.map(|value| value.to_string()),
        time: event.time,
        time_nano: event.time_nano,
    }
}

fn map_disk_usage(usage: bollard::models::SystemDataUsageResponse) -> DiskUsage {
    DiskUsage {
        image_usage: usage.image_usage.map(map_image_usage),
        container_usage: usage.container_usage.map(map_container_usage),
        volume_usage: usage.volume_usage.map(map_volume_usage),
        build_cache_usage: usage.build_cache_usage.map(map_build_cache_usage),
    }
}

fn map_image_usage(usage: bollard::models::ImagesDiskUsage) -> DiskUsageCategory {
    DiskUsageCategory {
        active_count: usage.active_count,
        total_count: usage.total_count,
        reclaimable: usage.reclaimable,
        total_size: usage.total_size,
        items: usage
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| map_disk_usage_item(&item, DiskUsageType::Image))
            .collect(),
    }
}

fn map_container_usage(usage: bollard::models::ContainersDiskUsage) -> DiskUsageCategory {
    DiskUsageCategory {
        active_count: usage.active_count,
        total_count: usage.total_count,
        reclaimable: usage.reclaimable,
        total_size: usage.total_size,
        items: usage
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| map_disk_usage_item(&item, DiskUsageType::Container))
            .collect(),
    }
}

fn map_volume_usage(usage: bollard::models::VolumesDiskUsage) -> DiskUsageCategory {
    DiskUsageCategory {
        active_count: usage.active_count,
        total_count: usage.total_count,
        reclaimable: usage.reclaimable,
        total_size: usage.total_size,
        items: usage
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| map_disk_usage_item(&item, DiskUsageType::Volume))
            .collect(),
    }
}

fn map_build_cache_usage(usage: bollard::models::BuildCacheDiskUsage) -> DiskUsageCategory {
    DiskUsageCategory {
        active_count: usage.active_count,
        total_count: usage.total_count,
        reclaimable: usage.reclaimable,
        total_size: usage.total_size,
        items: usage
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| map_disk_usage_item(&item, DiskUsageType::BuildCache))
            .collect(),
    }
}

fn map_disk_usage_item(value: &Value, resource_type: DiskUsageType) -> DiskUsageItem {
    let usage_data = value.get("UsageData");
    DiskUsageItem {
        id: string_field(value, "ID").or_else(|| string_field(value, "Id")),
        name: string_field(value, "Name")
            .or_else(|| first_string_field(value, "RepoTags"))
            .or_else(|| first_string_field(value, "Names")),
        parent_id: string_field(value, "Parent").or_else(|| string_field(value, "ParentId")),
        size: integer_field(value, "Size")
            .or_else(|| usage_data.and_then(|data| integer_field(data, "Size"))),
        reference_count: usage_data.and_then(|data| integer_field(data, "RefCount")),
        in_use: bool_field(value, "InUse"),
        created: integer_field(value, "Created").or_else(|| integer_field(value, "CreatedAt")),
        labels: string_map_field(value, "Labels"),
        references: string_list_field(value, "RepoTags")
            .or_else(|| string_list_field(value, "Names"))
            .unwrap_or_default(),
        driver: string_field(value, "Driver"),
        resource_type: Some(resource_type),
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn first_string_field(value: &Value, key: &str) -> Option<String> {
    string_list_field(value, key)?.into_iter().next()
}

fn string_list_field(value: &Value, key: &str) -> Option<Vec<String>> {
    value.get(key)?.as_array().map(|values| {
        values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn integer_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

/// Reads a member the Engine sends as a list of label/value rows.
///
/// `DriverStatus` is the only such member the repository's model names, and the
/// generated type it is read from is `Option<Vec<Vec<String>>>`, so a row with
/// no strings in it is preserved as an empty row rather than dropped: the row's
/// *position* is the pairing.
fn string_rows_field(value: &Value, key: &str) -> Option<Vec<Vec<String>>> {
    value.get(key)?.as_array().map(|rows| {
        rows.iter()
            .map(|row| {
                row.as_array().map_or_else(Vec::new, |values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
            })
            .collect()
    })
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_map_field(value: &Value, key: &str) -> BTreeMap<String, String> {
    value
        .get(key)
        .and_then(Value::as_object)
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

// Bollard's builders accept HashMap filters, whose JSON key order is not
// stable. Serialize the repository-owned BTreeMap first so fixtures and wire
// requests remain deterministic.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> String {
    let json = serde_json::to_string(filters).expect("BTreeMap filters must serialize");
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("filters", &json);
    serializer.finish()
}

fn add_query_parameter(
    request: &mut bollard::BollardRequest,
    encoded_parameter: &str,
    prepend: bool,
) {
    let existing = request.uri().query().unwrap_or_default();
    let query = if existing.is_empty() {
        encoded_parameter.to_owned()
    } else if prepend {
        format!("{encoded_parameter}&{existing}")
    } else {
        format!("{existing}&{encoded_parameter}")
    };
    let path_and_query = format!("{}?{}", request.uri().path(), query);
    if let Ok(path_and_query) = path_and_query.parse::<http::uri::PathAndQuery>() {
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }
}

fn encode_type_query(types: &[DiskUsageType]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for ty in types {
        serializer.append_pair("type", ty.as_str());
    }
    serializer.finish()
}

fn map_build_cache_prune(response: bollard::models::BuildPruneResponse) -> BuildCachePruneResult {
    BuildCachePruneResult {
        caches_deleted: response.caches_deleted.unwrap_or_default(),
        space_reclaimed: response.space_reclaimed,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct DropStream {
        dropped: Arc<AtomicBool>,
    }

    impl Stream for DropStream {
        type Item = Result<bollard::models::EventMessage, bollard::errors::Error>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    impl Drop for DropStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn cancel_drops_the_owned_response_stream() {
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = EventStream::new(DropStream {
            dropped: Arc::clone(&dropped),
        });
        stream.cancel();
        assert!(dropped.load(Ordering::Acquire));
    }
}
