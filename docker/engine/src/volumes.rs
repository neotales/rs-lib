//! Repository-owned Docker Engine volume operations.
//!
//! Bollard models and generated request types stay behind this module. The
//! facade projects stable v1.53 volume fields and omits daemon-specific
//! cluster-volume objects from this bounded slice.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use bollard::{
    models::{
        Volume as BollardVolume, VolumeCreateRequest,
        VolumeListResponse as BollardVolumeListResponse,
        VolumePruneResponse as BollardVolumePruneResponse,
    },
    query_parameters::{RemoveVolumeOptions, RemoveVolumeOptionsBuilder},
};

use crate::{DockerClient, Error, raw, resource};

/// Options for the Engine volume-list operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeListOptions {
    /// Docker volume filters, such as `name`, `driver`, `label`, or `dangling`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl VolumeListOptions {
    /// Creates empty volume-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one volume filter.
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

/// Options for creating a volume.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeCreateOptions {
    /// Optional volume name. The daemon generates one when omitted.
    pub name: Option<String>,
    /// Volume driver name.
    pub driver: Option<String>,
    /// Driver-specific options.
    pub driver_options: Option<BTreeMap<String, String>>,
    /// User-defined labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl VolumeCreateOptions {
    /// Creates unnamed volume options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name: None,
            driver: None,
            driver_options: None,
            labels: None,
        }
    }

    /// Sets an explicit volume name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds or replaces one user-defined label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), value.into());
        self
    }

    fn into_bollard(self) -> VolumeCreateRequest {
        VolumeCreateRequest {
            name: self.name,
            driver: self.driver,
            driver_opts: self.driver_options.map(into_hash_map),
            labels: self.labels.map(into_hash_map),
            ..VolumeCreateRequest::default()
        }
    }
}

/// Options for removing a volume.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VolumeRemoveOptions {
    /// Force removal of a volume that is still in use.
    pub force: bool,
}

impl VolumeRemoveOptions {
    /// Creates default volume-removal options.
    #[must_use]
    pub const fn new() -> Self {
        Self { force: false }
    }

    /// Enables or disables forced removal.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    fn into_bollard(self) -> Option<RemoveVolumeOptions> {
        if !self.force {
            return None;
        }
        Some(RemoveVolumeOptionsBuilder::default().force(true).build())
    }
}

/// Options for pruning unused volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumePruneOptions {
    /// Docker volume-prune filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl VolumePruneOptions {
    /// Creates empty volume-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one volume-prune filter.
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

/// Volume usage fields returned by Engine volume endpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct VolumeUsage {
    /// Disk space used by the volume in bytes, or `-1` when unavailable.
    pub size: i64,
    /// Number of containers referencing the volume, or `-1` when unavailable.
    pub reference_count: i64,
}

/// Stable volume fields returned by list, create, and inspect operations.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeSummary {
    /// Volume name.
    pub name: String,
    /// Volume driver.
    pub driver: String,
    /// Host mount point.
    pub mountpoint: String,
    /// RFC 3339 creation timestamp.
    pub created_at: Option<String>,
    /// Volume scope.
    pub scope: Option<String>,
    /// Driver status rows.
    pub status: Option<Vec<String>>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Driver-specific options.
    pub options: BTreeMap<String, String>,
    /// Optional usage details.
    pub usage: Option<VolumeUsage>,
}

impl VolumeSummary {
    fn from_bollard(volume: BollardVolume) -> Self {
        Self {
            name: volume.name,
            driver: volume.driver,
            mountpoint: volume.mountpoint,
            created_at: volume.created_at,
            scope: volume.scope.map(|scope| scope.to_string()),
            status: volume.status.map(|mut status| {
                status.sort();
                status
            }),
            labels: volume.labels.into_iter().collect(),
            options: volume.options.into_iter().collect(),
            usage: volume.usage_data.map(|usage| VolumeUsage {
                size: usage.size,
                reference_count: usage.ref_count,
            }),
        }
    }
}

/// Result of listing volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeListResult {
    /// Matching volumes.
    pub volumes: Vec<VolumeSummary>,
    /// Warnings returned by the daemon.
    pub warnings: Vec<String>,
}

impl VolumeListResult {
    fn from_bollard(response: BollardVolumeListResponse) -> Self {
        Self {
            volumes: response
                .volumes
                .unwrap_or_default()
                .into_iter()
                .map(VolumeSummary::from_bollard)
                .collect(),
            warnings: response.warnings.unwrap_or_default(),
        }
    }
}

/// Result of pruning unused volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumePruneResult {
    /// Names of deleted volumes.
    pub volumes_deleted: Vec<String>,
    /// Reclaimed disk space in bytes.
    pub space_reclaimed: Option<i64>,
}

impl VolumePruneResult {
    fn from_bollard(response: BollardVolumePruneResponse) -> Self {
        Self {
            volumes_deleted: response.volumes_deleted.unwrap_or_default(),
            space_reclaimed: response.space_reclaimed,
        }
    }
}

/// Compatibility name matching the Engine response terminology.
pub type VolumeResponse = VolumeSummary;
/// Compatibility name matching the Engine response terminology.
pub type VolumeListResponse = VolumeListResult;
/// Compatibility name matching the Engine response terminology.
pub type VolumePruneResponse = VolumePruneResult;

fn into_hash_map(values: BTreeMap<String, String>) -> HashMap<String, String> {
    values.into_iter().collect()
}

impl DockerClient {
    /// Lists volumes using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_volumes(
        &self,
        options: Option<VolumeListOptions>,
    ) -> Result<VolumeListResult, Error> {
        // The repository-owned transport first, Bollard second. See the note on
        // `DockerClient::raw_engine` for the routing rule and why both paths
        // stay.
        if let Ok(engine) = self.raw_engine() {
            return raw::volume_list(&engine, &options.unwrap_or_default()).await;
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/volumes", filters);
        let response = docker
            .list_volumes(None::<bollard::query_parameters::ListVolumesOptions>)
            .await?;
        Ok(VolumeListResult::from_bollard(response))
    }

    /// Creates a volume from repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or response
    /// decoding failures.
    pub async fn create_volume(
        &self,
        options: VolumeCreateOptions,
    ) -> Result<VolumeSummary, Error> {
        // See `DockerClient::raw_engine` for the routing rule. The name travels
        // in the body on both paths. Note that the two paths are *not*
        // interchangeable on a daemon answer that carries a member the generated
        // model cannot express — a `Scope` outside its closed enum, or a
        // document omitting the `Scope`, `Labels`, or `Options` member the
        // generated model requires. Those are a decode failure on the generated
        // path and a value on the owned one; see
        // `tests/raw_differential_resources.rs`, which pins each of them.
        if let Ok(engine) = self.raw_engine() {
            return raw::volume_create(&engine, &options).await;
        }
        self.inner
            .create_volume(options.into_bollard())
            .await
            .map(VolumeSummary::from_bollard)
            .map_err(Error::from)
    }

    /// Inspects one volume.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn inspect_volume(&self, name: &str) -> Result<VolumeSummary, Error> {
        // See the note on `create_volume` for what the two paths disagree about,
        // and `DockerClient::raw_engine` for the routing rule.
        if let Ok(engine) = self.raw_engine() {
            return raw::volume_inspect(&engine, name).await;
        }
        self.inner
            .inspect_volume(name)
            .await
            .map(VolumeSummary::from_bollard)
            .map_err(Error::from)
    }

    /// Removes a volume.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn remove_volume(
        &self,
        name: &str,
        options: Option<VolumeRemoveOptions>,
    ) -> Result<(), Error> {
        // See `DockerClient::raw_engine` for the routing rule. `force` is spelled
        // as `true`/`false` on the owned path where the generated client omits an
        // unset option; an absent `force` and a `force=false` are the same
        // request to the daemon.
        if let Ok(engine) = self.raw_engine() {
            return raw::volume_remove(&engine, name, &options.unwrap_or_default()).await;
        }
        let options = options.and_then(VolumeRemoveOptions::into_bollard);
        self.inner
            .remove_volume(name, options)
            .await
            .map_err(Error::from)
    }

    /// Prunes unused volumes using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn prune_volumes(
        &self,
        options: Option<VolumePruneOptions>,
    ) -> Result<VolumePruneResult, Error> {
        // See `DockerClient::raw_engine` for the routing rule. `SpaceReclaimed`
        // stays an `Option` on both paths, because `0` and `null` are different
        // answers: "reclaimed nothing" and "the daemon reported no figure".
        if let Ok(engine) = self.raw_engine() {
            return raw::volume_prune(&engine, &options.unwrap_or_default()).await;
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/volumes/prune", filters);
        docker
            .prune_volumes(None::<bollard::query_parameters::PruneVolumesOptions>)
            .await
            .map(VolumePruneResult::from_bollard)
            .map_err(Error::from)
    }
}
