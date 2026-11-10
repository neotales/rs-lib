//! Repository-owned Docker Engine image operations.
//!
//! Bollard models and generated request types remain private to this module.
//! Public values contain the stable Engine image fields used by the facade;
//! experimental manifest/descriptor data and other daemon-specific nested
//! objects are deliberately not exposed.

use std::collections::{BTreeMap, HashMap};

use bollard::{
    models::{
        DriverData as BollardDriverData, HealthConfig as BollardHealthConfig,
        ImageConfig as BollardImageConfig, ImageDeleteResponseItem,
        ImageHistoryResponseItem as BollardImageHistory, ImageInspect as BollardImageInspect,
        ImageInspectMetadata as BollardImageInspectMetadata,
        ImageInspectRootFs as BollardImageInspectRootFs,
        ImagePruneResponse as BollardImagePruneResponse,
        ImageSearchResponseItem as BollardImageSearchResult, ImageSummary as BollardImageSummary,
    },
    query_parameters::{
        ListImagesOptions, ListImagesOptionsBuilder, PruneImagesOptionsBuilder, RemoveImageOptions,
        RemoveImageOptionsBuilder, SearchImagesOptionsBuilder, TagImageOptions,
        TagImageOptionsBuilder,
    },
};

use crate::{DockerClient, Error, raw, resource};

/// Options for the Engine image-list operation.
///
/// Filters use the Docker Engine JSON filter representation. The map is kept
/// ordered at the public boundary so caller policy is stable; the fixture suite
/// asserts decoded query values rather than relying on Bollard's map iteration
/// order.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageListOptions {
    /// Include intermediate image layers.
    pub all: bool,
    /// Ask the daemon to calculate shared image sizes.
    pub shared_size: bool,
    /// Ask the daemon to include repository digests.
    pub digests: bool,
    /// Docker image filters, such as `label` or `reference`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl ImageListOptions {
    pub(crate) fn into_bollard(self) -> Option<ListImagesOptions> {
        if self == Self::default() {
            return None;
        }

        let filters: HashMap<String, Vec<String>> = self.filters.into_iter().collect();
        let mut builder = ListImagesOptionsBuilder::default()
            .all(self.all)
            .shared_size(self.shared_size)
            .digests(self.digests);
        if !filters.is_empty() {
            builder = builder.filters(&filters);
        }
        Some(builder.build())
    }
}

/// Options for the Engine image-delete operation.
///
/// Platform-specific deletion is intentionally omitted: Bollard 0.21.1's
/// generated `platforms` sequence cannot be serialized by its URL-form query
/// adapter without a narrow transport/query extension.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageRemoveOptions {
    /// Remove the image even when it is referenced by stopped containers or
    /// has other tags.
    pub force: bool,
    /// Do not delete untagged parent images.
    pub no_prune: bool,
}

impl ImageRemoveOptions {
    pub(crate) fn into_bollard(self) -> Option<RemoveImageOptions> {
        if self == Self::default() {
            return None;
        }

        let builder = RemoveImageOptionsBuilder::default()
            .force(self.force)
            .noprune(self.no_prune);
        Some(builder.build())
    }
}

/// Query options for the Engine image-inspect operation.
///
/// `platform` is the JSON-encoded OCI platform accepted by the Engine API. It
/// remains a string at this boundary so callers do not need to depend on a
/// Bollard OCI model.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageInspectOptions {
    /// JSON-encoded OCI platform used to select an image variant.
    pub platform: Option<String>,
}

impl ImageInspectOptions {
    /// Creates default image-inspect options.
    #[must_use]
    pub const fn new() -> Self {
        Self { platform: None }
    }

    /// Sets a JSON-encoded OCI platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    fn into_query(self) -> Option<String> {
        let platform = self.platform?;
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("platform", &platform);
        Some(serializer.finish())
    }
}

/// Query options for the Engine image-history operation.
///
/// `platform` is the JSON-encoded OCI platform accepted by the Engine API.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHistoryOptions {
    /// JSON-encoded OCI platform used to select an image variant.
    pub platform: Option<String>,
}

impl ImageHistoryOptions {
    /// Creates default image-history options.
    #[must_use]
    pub const fn new() -> Self {
        Self { platform: None }
    }

    /// Sets a JSON-encoded OCI platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    fn into_query(self) -> Option<String> {
        let platform = self.platform?;
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("platform", &platform);
        Some(serializer.finish())
    }
}

/// Query options for the Engine image-tag operation.
///
/// `force` is added through the repository-owned request modifier because
/// Bollard 0.21.1's generated `TagImageOptions` contains `repo` and `tag` but
/// omits the Engine's optional `force` query flag.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageTagOptions {
    /// Target repository, without a registry scheme.
    pub repo: Option<String>,
    /// Target tag.
    pub tag: Option<String>,
    /// Overwrite an existing target tag.
    pub force: Option<bool>,
}

impl ImageTagOptions {
    /// Creates options for a target repository.
    #[must_use]
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            repo: Some(repo.into()),
            tag: None,
            force: None,
        }
    }

    /// Sets the target repository.
    #[must_use]
    pub fn with_repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    /// Sets the target tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Enables or disables replacement of an existing target tag.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = Some(force);
        self
    }

    fn into_bollard_and_force(self) -> (TagImageOptions, Option<String>) {
        let mut builder = TagImageOptionsBuilder::default();
        if let Some(repo) = self.repo.as_deref() {
            builder = builder.repo(repo);
        }
        if let Some(tag) = self.tag.as_deref() {
            builder = builder.tag(tag);
        }
        let force = self.force.map(|force| {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("force", if force { "true" } else { "false" });
            serializer.finish()
        });
        (builder.build(), force)
    }
}

/// Query options for the Engine image-search operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageSearchOptions {
    /// Required registry search term.
    pub term: String,
    /// Maximum number of results requested from the registry.
    pub limit: Option<i32>,
    /// Docker search filters, such as `is-official` or `stars`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl ImageSearchOptions {
    /// Creates options for a required search term.
    #[must_use]
    pub fn new(term: impl Into<String>) -> Self {
        Self {
            term: term.into(),
            limit: None,
            filters: BTreeMap::new(),
        }
    }

    /// Sets the maximum result count.
    #[must_use]
    pub const fn with_limit(mut self, limit: i32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Adds or replaces one image-search filter.
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

    fn into_bollard(self) -> bollard::query_parameters::SearchImagesOptions {
        let mut builder = SearchImagesOptionsBuilder::default().term(&self.term);
        if let Some(limit) = self.limit {
            builder = builder.limit(limit);
        }
        builder.build()
    }
}

/// Query options for the Engine image-prune operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImagePruneOptions {
    /// Docker image-prune filters, such as `dangling`, `until`, or `label`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl ImagePruneOptions {
    /// Creates empty image-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one image-prune filter.
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

/// Stable image-list values exposed by the repository facade.
///
/// Experimental manifest and descriptor fields from newer Engine responses
/// are intentionally not included in this first slice.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ImageSummary {
    /// Content-addressable image ID.
    pub id: String,
    /// Parent image ID, when one is present.
    pub parent_id: String,
    /// Local repository tags.
    pub repo_tags: Vec<String>,
    /// Repository digests reported by the daemon.
    pub repo_digests: Vec<String>,
    /// Creation time as a Unix timestamp.
    pub created: i64,
    /// Total image size in bytes.
    pub size: i64,
    /// Shared layer size in bytes, or `-1` when it was not calculated.
    pub shared_size: i64,
    /// User-defined image labels.
    pub labels: BTreeMap<String, String>,
    /// Number of containers using the image, or `-1` when unknown.
    pub containers: i64,
}

impl ImageSummary {
    pub(crate) fn from_bollard(summary: BollardImageSummary) -> Self {
        Self {
            id: summary.id,
            parent_id: summary.parent_id,
            repo_tags: summary.repo_tags,
            repo_digests: summary.repo_digests,
            created: summary.created,
            size: summary.size,
            shared_size: summary.shared_size,
            labels: summary.labels.into_iter().collect(),
            containers: summary.containers,
        }
    }
}

/// A typed health-check policy from an inspected image configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHealthcheck {
    /// Health-check command, including its `CMD` or `CMD-SHELL` selector.
    pub test: Option<Vec<String>>,
    /// Interval in nanoseconds.
    pub interval: Option<i64>,
    /// Timeout in nanoseconds.
    pub timeout: Option<i64>,
    /// Number of retries.
    pub retries: Option<i64>,
    /// Start period in nanoseconds.
    pub start_period: Option<i64>,
    /// Start interval in nanoseconds.
    pub start_interval: Option<i64>,
}

impl ImageHealthcheck {
    fn from_bollard(healthcheck: BollardHealthConfig) -> Self {
        Self {
            test: healthcheck.test,
            interval: healthcheck.interval,
            timeout: healthcheck.timeout,
            retries: healthcheck.retries,
            start_period: healthcheck.start_period,
            start_interval: healthcheck.start_interval,
        }
    }
}

/// Stable image configuration values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageConfig {
    /// User used for commands run inside the image.
    pub user: Option<String>,
    /// Ports declared by the image.
    pub exposed_ports: Option<Vec<String>>,
    /// Environment variables declared by the image.
    pub env: Option<Vec<String>>,
    /// Default command.
    pub cmd: Option<Vec<String>>,
    /// Health-check policy.
    pub healthcheck: Option<ImageHealthcheck>,
    /// Whether Windows arguments are escaped.
    pub args_escaped: Option<bool>,
    /// Volumes declared by the image.
    pub volumes: Option<Vec<String>>,
    /// Default working directory.
    pub working_dir: Option<String>,
    /// Default entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// ONBUILD instructions.
    pub on_build: Option<Vec<String>>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Stop signal.
    pub stop_signal: Option<String>,
    /// Default shell.
    pub shell: Option<Vec<String>>,
}

impl ImageConfig {
    fn from_bollard(config: BollardImageConfig) -> Self {
        Self {
            user: config.user,
            exposed_ports: config.exposed_ports,
            env: config.env,
            cmd: config.cmd,
            healthcheck: config.healthcheck.map(ImageHealthcheck::from_bollard),
            args_escaped: config.args_escaped,
            volumes: config.volumes,
            working_dir: config.working_dir,
            entrypoint: config.entrypoint,
            on_build: config.on_build,
            labels: config.labels.unwrap_or_default().into_iter().collect(),
            stop_signal: config.stop_signal,
            shell: config.shell,
        }
    }
}

/// Stable root-filesystem values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageRootFs {
    /// Root filesystem type, normally `layers`.
    pub typ: String,
    /// Content-addressable layer IDs.
    pub layers: Vec<String>,
}

impl ImageRootFs {
    fn from_bollard(root_fs: BollardImageInspectRootFs) -> Self {
        Self {
            typ: root_fs.typ,
            layers: root_fs.layers.unwrap_or_default(),
        }
    }
}

/// Stable storage-driver values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageGraphDriver {
    /// Storage-driver name.
    pub name: String,
    /// Driver-specific metadata.
    pub data: BTreeMap<String, String>,
}

impl ImageGraphDriver {
    fn from_bollard(driver: BollardDriverData) -> Self {
        Self {
            name: driver.name,
            data: driver.data.into_iter().collect(),
        }
    }
}

/// Stable local-cache metadata returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageMetadata {
    /// RFC 3339 timestamp of the most recent local tag operation.
    pub last_tag_time: Option<String>,
}

impl ImageMetadata {
    fn from_bollard(metadata: BollardImageInspectMetadata) -> Self {
        Self {
            last_tag_time: metadata.last_tag_time,
        }
    }
}

/// A typed, bounded projection of an inspected local image.
///
/// Experimental OCI descriptors, manifest summaries, and identity records are
/// intentionally outside this first v1.53 facade.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageInspect {
    /// Content-addressable image ID.
    pub id: String,
    /// Local repository tags.
    pub repo_tags: Vec<String>,
    /// Repository digests.
    pub repo_digests: Vec<String>,
    /// Optional image comment.
    pub comment: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: Option<String>,
    /// Image author.
    pub author: Option<String>,
    /// CPU architecture.
    pub architecture: Option<String>,
    /// CPU architecture variant.
    pub variant: Option<String>,
    /// Operating-system name.
    pub os: Option<String>,
    /// Operating-system version.
    pub os_version: Option<String>,
    /// Total image size in bytes.
    pub size: Option<i64>,
    /// Image configuration.
    pub config: Option<ImageConfig>,
    /// Storage-driver information.
    pub graph_driver: Option<ImageGraphDriver>,
    /// Root filesystem layer information.
    pub root_fs: Option<ImageRootFs>,
    /// Local image-store metadata.
    pub metadata: Option<ImageMetadata>,
}

impl ImageInspect {
    fn from_bollard(inspect: BollardImageInspect) -> Self {
        Self {
            id: inspect.id.unwrap_or_default(),
            repo_tags: inspect.repo_tags.unwrap_or_default(),
            repo_digests: inspect.repo_digests.unwrap_or_default(),
            comment: inspect.comment,
            created: inspect.created,
            author: inspect.author,
            architecture: inspect.architecture,
            variant: inspect.variant,
            os: inspect.os,
            os_version: inspect.os_version,
            size: inspect.size,
            config: inspect.config.map(ImageConfig::from_bollard),
            graph_driver: inspect.graph_driver.map(ImageGraphDriver::from_bollard),
            root_fs: inspect.root_fs.map(ImageRootFs::from_bollard),
            metadata: inspect.metadata.map(ImageMetadata::from_bollard),
        }
    }
}

/// One layer in an image history response.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHistory {
    /// Layer image ID.
    pub id: String,
    /// Layer creation time as a Unix timestamp.
    pub created: i64,
    /// Command that created the layer.
    pub created_by: String,
    /// Tags associated with the layer.
    pub tags: Vec<String>,
    /// Layer size in bytes.
    pub size: i64,
    /// Layer comment.
    pub comment: String,
}

impl ImageHistory {
    fn from_bollard(history: BollardImageHistory) -> Self {
        Self {
            id: history.id,
            created: history.created,
            created_by: history.created_by,
            tags: history.tags,
            size: history.size,
            comment: history.comment,
        }
    }
}

/// One result returned by the Engine image-search operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageSearchResult {
    /// Repository name.
    pub name: String,
    /// Repository description.
    pub description: String,
    /// Number of repository stars.
    pub star_count: i64,
    /// Whether the repository is official.
    pub is_official: bool,
    /// Whether the repository is automated.
    ///
    /// Docker marks this field deprecated, but it remains part of the v1.53
    /// response projection for callers that need the legacy field.
    pub is_automated: bool,
}

impl ImageSearchResult {
    fn from_bollard(result: BollardImageSearchResult) -> Self {
        Self {
            name: result.name.unwrap_or_default(),
            description: result.description.unwrap_or_default(),
            star_count: result.star_count.unwrap_or_default(),
            is_official: result.is_official.unwrap_or_default(),
            is_automated: result.is_automated.unwrap_or_default(),
        }
    }
}

/// One record returned by the Engine image-prune operation.
pub type ImagePruneDelete = ImageDeleteResult;

/// Result of pruning unused images.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImagePruneResult {
    /// Images that were deleted or untagged.
    pub images_deleted: Vec<ImageDeleteResult>,
    /// Reclaimed disk space in bytes.
    pub space_reclaimed: Option<i64>,
}

impl ImagePruneResult {
    fn from_bollard(response: BollardImagePruneResponse) -> Self {
        Self {
            images_deleted: response
                .images_deleted
                .unwrap_or_default()
                .into_iter()
                .map(ImageDeleteResult::from_bollard)
                .collect(),
            space_reclaimed: response.space_reclaimed,
        }
    }
}

/// One record returned by the Engine image-delete operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageDeleteResult {
    /// Image reference that was untagged, when applicable.
    pub untagged: Option<String>,
    /// Image ID that was deleted, when applicable.
    pub deleted: Option<String>,
}

impl ImageDeleteResult {
    pub(crate) fn from_bollard(result: ImageDeleteResponseItem) -> Self {
        Self {
            untagged: result.untagged,
            deleted: result.deleted,
        }
    }
}

/// Compatibility names matching Engine response terminology.
pub type ImageInspectResponse = ImageInspect;
/// Compatibility name for an image-history entry.
pub type ImageHistoryEntry = ImageHistory;
/// Compatibility name for an image-history response item.
pub type ImageHistoryResponse = ImageHistory;
/// Compatibility name for an image-search response item.
pub type ImageSearchResponse = ImageSearchResult;
/// Compatibility name for an image-search result.
pub type ImageSearchResultItem = ImageSearchResult;
/// Compatibility name for an image-prune response.
pub type ImagePruneResponse = ImagePruneResult;

impl DockerClient {
    /// Inspects one local image.
    ///
    /// The default request uses the Engine's ordinary v1.53 inspect shape.
    /// Use [`Self::inspect_image_with_options`] when a platform selector is
    /// required.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn inspect_image(&self, name: &str) -> Result<ImageInspect, Error> {
        self.inspect_image_with_options(name, None).await
    }

    /// Inspects one local image using repository-owned query options.
    ///
    /// **This is the canonical image inspect.** [`Self::inspect_image`] is an
    /// alias for the no-options case and delegates here, so the owned transport
    /// is reached once, from one place, rather than per spelling.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn inspect_image_with_options(
        &self,
        name: &str,
        options: Option<ImageInspectOptions>,
    ) -> Result<ImageInspect, Error> {
        // The repository-owned transport first, Bollard second.
        //
        // `raw_engine()` is `Err` for an endpoint kind the owned transport does
        // not reach — TLS, SSH, or a forward proxy — and that is the only
        // condition, so the fallback is a *routing* decision rather than an
        // error path. See the note on `DockerClient::raw_engine`.
        //
        // `raw::image_inspect` fetches `GET /images/{name}/json`, which is the
        // endpoint this path already fetched, so the answer a caller sees does
        // not change with the transport. That is not a formality: the *other*
        // image endpoint, `GET /images/json`, is a summary, and for
        // `alpine:3.21` on Docker 29.8.0 the two disagree about the size of the
        // same image (13150566 in the list, 13064837 in the document), so
        // routing an inspect-shaped call at the summary would change a value
        // rather than a spelling.
        if let Ok(engine) = self.raw_engine() {
            return raw::image_inspect(&engine, name, &options.unwrap_or_default()).await;
        }
        let query = options.and_then(ImageInspectOptions::into_query);
        let docker = query.map_or_else(
            || self.inner.clone(),
            |query| resource::with_query_parameter(&self.inner, "/json", query),
        );
        docker
            .inspect_image(name)
            .await
            .map(ImageInspect::from_bollard)
            .map_err(Error::from)
    }

    /// Returns the layer history for one local image.
    ///
    /// The default request uses the Engine's ordinary v1.53 history shape. Use
    /// [`Self::image_history_with_options`] to select a platform variant.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn image_history(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history_with_options(name, None).await
    }

    /// Returns the layer history using repository-owned query options.
    ///
    /// **This is the canonical image history.** [`Self::image_history`],
    /// [`Self::history_image`], and [`Self::get_image_history`] are three
    /// spellings of the no-options case and all delegate here, so the transport
    /// is chosen once. Giving each its own `raw::image_history` call would be
    /// four copies of the same routing decision to keep in step.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn image_history_with_options(
        &self,
        name: &str,
        options: Option<ImageHistoryOptions>,
    ) -> Result<Vec<ImageHistory>, Error> {
        // The repository-owned transport first, Bollard second. See
        // `DockerClient::raw_engine` for why both paths stay and why the
        // fallback is a routing decision rather than an error path.
        if let Ok(engine) = self.raw_engine() {
            return raw::image_history(&engine, name, &options.unwrap_or_default()).await;
        }
        let query = options.and_then(ImageHistoryOptions::into_query);
        let docker = query.map_or_else(
            || self.inner.clone(),
            |query| resource::with_query_parameter(&self.inner, "/history", query),
        );
        docker
            .image_history(name)
            .await
            .map(|history| {
                history
                    .into_iter()
                    .map(ImageHistory::from_bollard)
                    .collect()
            })
            .map_err(Error::from)
    }

    /// Compatibility name for [`Self::image_history`].
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn history_image(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history(name).await
    }

    /// Compatibility name for [`Self::image_history`].
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn get_image_history(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history(name).await
    }

    /// Tags one local image using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn tag_image(
        &self,
        name: &str,
        options: Option<ImageTagOptions>,
    ) -> Result<(), Error> {
        // The repository-owned transport first, Bollard second. See
        // `DockerClient::raw_engine`.
        //
        // **One answer changes with this routing, and it is deliberate.** The
        // owned `raw::image_tag` refuses a request that names no repository;
        // measured against Docker 29.8.0, the generated client's version of the
        // same request answers `200` and tags nothing, so a caller saw a success
        // for a request that did nothing. The refusal is `ErrorKind::InvalidInput`
        // and it happens before a connection is opened. The only in-tree caller
        // (`docker image tag`) always names a repository, so nothing in this
        // repository observes the difference; an out-of-tree caller that passed
        // `None` would, and it would see a refusal where it saw a success that
        // tagged nothing.
        if let Ok(engine) = self.raw_engine() {
            return raw::image_tag(&engine, name, &options.unwrap_or_default()).await;
        }
        let (bollard_options, force_query) = match options {
            Some(options) => {
                let (options, force) = ImageTagOptions::into_bollard_and_force(options);
                (Some(options), force)
            }
            None => (None, None),
        };
        let docker = force_query.map_or_else(
            || self.inner.clone(),
            |query| resource::with_query_parameter(&self.inner, "/tag", query),
        );
        docker
            .tag_image(name, bollard_options)
            .await
            .map_err(Error::from)
    }

    /// Searches the registry for images using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn search_images(
        &self,
        options: ImageSearchOptions,
    ) -> Result<Vec<ImageSearchResult>, Error> {
        // The repository-owned transport first, Bollard second. See
        // `DockerClient::raw_engine`.
        //
        // **As with `tag_image`, one answer changes with this routing.** The
        // owned `raw::image_search` refuses an empty term; measured against
        // Docker 29.8.0, the generated client sends `?term=` and is answered
        // with `200` and an *unfiltered* result — every repository the registry
        // has — which is not what an empty search means. The only in-tree caller
        // (`docker search`) always has a term, so nothing in this repository
        // observes the difference.
        if let Ok(engine) = self.raw_engine() {
            return raw::image_search(&engine, &options).await;
        }
        let filters = (!options.filters.is_empty()).then_some(&options.filters);
        let docker = resource::with_filter_query(&self.inner, "/images/search", filters);
        docker
            .search_images(options.into_bollard())
            .await
            .map(|results| {
                results
                    .into_iter()
                    .map(ImageSearchResult::from_bollard)
                    .collect()
            })
            .map_err(Error::from)
    }

    /// Prunes unused images using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn prune_images(
        &self,
        options: Option<ImagePruneOptions>,
    ) -> Result<ImagePruneResult, Error> {
        // The repository-owned transport first, Bollard second. See
        // `DockerClient::raw_engine`.
        if let Ok(engine) = self.raw_engine() {
            return raw::image_prune(&engine, &options.unwrap_or_default()).await;
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/images/prune", filters);
        let bollard_options = options
            .as_ref()
            .filter(|options| !options.filters.is_empty())
            .map(|_| {
                // The filter is added by the deterministic request modifier.
                // Keeping it out of Bollard's HashMap-backed option avoids a
                // second, nondeterministic `filters` query value.
                PruneImagesOptionsBuilder::default().build()
            });
        docker
            .prune_images(bollard_options)
            .await
            .map(ImagePruneResult::from_bollard)
            .map_err(Error::from)
    }
}
