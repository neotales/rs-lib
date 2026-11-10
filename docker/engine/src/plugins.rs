//! Repository-owned Docker Engine plugin operations.
//!
//! Bollard models, generated query parameters, and credential conversion remain
//! private to this module. Public values contain only the stable Engine API
//! v1.53 fields used by this repository's clients and others.
//!
//! # Which transport serves a plugin operation
//!
//! Every method here prefers the repository-owned Engine transport and keeps
//! its generated-client path, following the rule on [`DockerClient::raw_engine`]:
//! the fallback is a *routing* decision for the endpoint kinds the owned
//! transport cannot reach, not an error path.
//!
//! Three methods keep the generated client unconditionally, because the owned
//! backend has no operation for them:
//!
//! - [`DockerClient::create_plugin`] (`POST /plugins/create`, an opaque
//!   in-memory TAR archive);
//! - [`DockerClient::set_plugin_config`] (`POST /plugins/{name}/set`, a
//!   `KEY=VALUE` list);
//! - [`DockerClient::push_plugin`] and its credentialed variants
//!   (`POST /plugins/{name}/push`, a registry write).
//!
//! The credentialed install and upgrade variants are a fourth case, and the
//! reason is the repository's standing order about secrets. The owned
//! [`raw::plugin_pull`] and [`raw::plugin_upgrade`] take no credential and send
//! **no** `X-Registry-Auth` header at all, which is correct — an empty header
//! would look like an attempt to authenticate with nothing — but it means
//! routing a credentialed call onto them would drop the credential silently.
//! The daemon would then answer with the *anonymous* failure and "no
//! credentials were sent" would be indistinguishable from "credentials were
//! sent and were rejected", which is the one confusion this repository treats
//! as a defect. Those variants stay on the generated client and the gap is
//! reported rather than papered over. See
//! `docs/docker/engine-backend-alternatives.md`; adding a credential to the
//! owned pull and upgrade is a change to `raw/plugins.rs`, which this module
//! does not own.
//!
//! One further consequence is worth stating. The generated client encodes
//! `X-Registry-Auth` with `bollard::auth::base64_url_encode`, which despite its
//! name is `base64::engine::general_purpose::STANDARD`; the Engine decodes that
//! header with Go's `base64.URLEncoding`, and on a decode failure it does not
//! reject the request — it proceeds with an empty auth config. That is a
//! recorded defect on the paths that still use the generated client, and it is
//! measured rather than assumed in
//! `tests/raw_differential_plugins_system.rs`.

use std::collections::BTreeMap;

use bollard::query_parameters::{
    CreatePluginOptionsBuilder, DisablePluginOptionsBuilder, EnablePluginOptionsBuilder,
    GetPluginPrivilegesOptionsBuilder, InstallPluginOptionsBuilder, RemovePluginOptionsBuilder,
    UpgradePluginOptionsBuilder,
};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::{
    DockerClient, DockerStream, Error, ImageStreamEvent, RegistryCredentialProvider,
    RegistryCredentials, raw, resource, streams,
};

/// Options for listing installed plugins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PluginListOptions {
    /// Ordered plugin filters, such as `capability` or `enabled`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl PluginListOptions {
    /// Creates empty plugin-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one plugin filter.
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

/// Stable fields returned by plugin list and inspect operations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PluginSummary {
    /// Plugin ID.
    pub id: Option<String>,
    /// Installed plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Human-readable plugin description.
    pub description: String,
    /// Remote reference used to pull or push the plugin.
    pub plugin_reference: Option<String>,
}

impl PluginSummary {
    fn from_bollard(plugin: bollard::models::Plugin) -> Self {
        Self {
            id: plugin.id,
            name: plugin.name,
            enabled: plugin.enabled,
            description: plugin.config.description,
            plugin_reference: plugin.plugin_reference,
        }
    }
}

/// A plugin privilege and its accepted values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PluginPrivilege {
    /// Privilege name.
    pub name: Option<String>,
    /// Human-readable privilege description.
    pub description: Option<String>,
    /// Values granted for the privilege.
    pub values: Vec<String>,
}

impl PluginPrivilege {
    fn from_bollard(privilege: bollard::models::PluginPrivilege) -> Self {
        Self {
            name: privilege.name,
            description: privilege.description,
            values: privilege.value.unwrap_or_default(),
        }
    }

    fn into_bollard(self) -> bollard::models::PluginPrivilege {
        bollard::models::PluginPrivilege {
            name: self.name,
            description: self.description,
            value: Some(self.values),
        }
    }
}

/// Options for enabling a plugin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginEnableOptions {
    /// Daemon-side enable timeout in seconds.
    pub timeout_seconds: i32,
}

impl PluginEnableOptions {
    /// Creates plugin-enable options.
    #[must_use]
    pub const fn new(timeout_seconds: i32) -> Self {
        Self { timeout_seconds }
    }
}

/// Options for disabling a plugin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PluginDisableOptions {
    /// Disable even when the plugin is in use.
    pub force: Option<bool>,
}

/// Options for removing a plugin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PluginRemoveOptions {
    /// Disable the plugin before removing it.
    pub force: Option<bool>,
}

/// Options for installing a remote plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInstallOptions {
    /// Remote plugin reference.
    pub remote: String,
    /// Optional local plugin name.
    pub name: Option<String>,
    /// Privileges granted to the plugin.
    pub privileges: Vec<PluginPrivilege>,
}

impl PluginInstallOptions {
    /// Creates options for a remote plugin.
    #[must_use]
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            name: None,
            privileges: Vec::new(),
        }
    }
}

/// Options for upgrading an installed plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginUpgradeOptions {
    /// Remote reference to upgrade to.
    pub remote: String,
    /// Privileges granted to the upgraded plugin.
    pub privileges: Vec<PluginPrivilege>,
}

impl PluginUpgradeOptions {
    /// Creates options for a remote plugin upgrade.
    #[must_use]
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            privileges: Vec::new(),
        }
    }
}

fn into_privileges(privileges: Vec<PluginPrivilege>) -> Vec<bollard::models::PluginPrivilege> {
    privileges
        .into_iter()
        .map(PluginPrivilege::into_bollard)
        .collect()
}

fn into_credentials(
    credentials: Option<RegistryCredentials>,
    registry: &str,
) -> Result<Option<bollard::auth::DockerCredentials>, Error> {
    credentials
        .map(|credentials| {
            credentials.validate_for(registry)?;
            Ok(credentials.into_engine_credentials(registry))
        })
        .transpose()
}

/// Bridges the owned backend's progress stream onto the facade's event stream.
///
/// The owned backend answers a plugin install with a [`raw::FrameStream`] — one
/// JSON record per line, read as it arrives — while the facade's contract is a
/// [`DockerStream`] of [`ImageStreamEvent`]. The records go through the same
/// [`streams::map_image_event`] the generated path uses, so the event values a
/// caller sees do not change when the transport does.
///
/// The request is opened inside the spawned task rather than before it, because
/// the owned transport is asynchronous and the facade's install contract is a
/// synchronous call that returns a stream. An empty remote is therefore
/// reported as the first stream item rather than as the returned `Err`, which
/// is where the generated path puts a request-build failure too.
///
/// A record carrying `errorDetail` is a failure, not progress, and the Engine
/// reports one *inside* a `200` body. The generated client turns that record
/// into a stream item error; this does the same, so a caller that matches on an
/// item error keeps matching. The two members are read straight out of the
/// record rather than through the generated model, because decoding through it
/// is the truncation this migration exists to remove — a progress record whose
/// shape the model cannot express would be dropped on the owned path and
/// accepted on the generated one, which is the wrong way round.
fn owned_progress_stream(
    engine: raw::RawEngine,
    options: PluginInstallOptions,
) -> Result<DockerStream<ImageStreamEvent>, Error> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error {
        kind: crate::ErrorKind::Runtime,
        source: Some(Box::new(error)),
        api: None,
    })?;
    let (sender, receiver) = mpsc::channel(16);
    runtime.spawn(async move {
        let mut frames = match raw::plugin_pull(&engine, &options).await {
            Ok(frames) => frames,
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                return;
            }
        };
        loop {
            let item = match frames.next_json().await {
                Ok(Some(value)) => match in_band_failure(&value) {
                    Some(message) => Err(Error::from(bollard::errors::Error::DockerStreamError {
                        error: message,
                    })),
                    None => Ok(streams::map_image_event(&value)),
                },
                Ok(None) => break,
                Err(error) => Err(error),
            };
            if sender.send(item).await.is_err() {
                break;
            }
        }
    });
    Ok(DockerStream::new(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
    )))
}

/// Reads the message of a progress record that reports a failure in band.
///
/// The Engine's plugin handlers write progress through a flush-on-write writer
/// and check it afterwards, so a failure *after* the first record is already a
/// `200` and can only be reported as one more progress object. That is the
/// daemon's answer, preserved rather than rewritten.
fn in_band_failure(record: &serde_json::Value) -> Option<String> {
    record
        .get("errorDetail")
        .and_then(|detail| detail.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

impl DockerClient {
    /// Lists installed plugins with deterministic filter ordering.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_plugins(
        &self,
        options: Option<PluginListOptions>,
    ) -> Result<Vec<PluginSummary>, Error> {
        // The repository-owned transport first, Bollard second.
        //
        // `raw_engine()` is `Err` for an endpoint kind the owned transport does
        // not reach — TLS, SSH, or a forward proxy — and that is the only
        // condition, so the fallback is a *routing* decision rather than an
        // error path. See the note on `DockerClient::raw_engine` for why both
        // paths stay.
        if let Ok(engine) = self.raw_engine() {
            return raw::plugin_list(&engine, &options.unwrap_or_default()).await;
        }
        let filters = options.as_ref().map(|options| &options.filters);
        let docker = resource::with_filter_query(&self.inner, "/plugins", filters);
        // Avoid passing the generated HashMap-backed query. The request modifier
        // above owns the only encoded filter value.
        let plugins = docker.list_plugins(None).await?;
        Ok(plugins
            .into_iter()
            .map(PluginSummary::from_bollard)
            .collect())
    }

    /// Inspects one installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn inspect_plugin(&self, name: &str) -> Result<PluginSummary, Error> {
        if let Ok(engine) = self.raw_engine() {
            return raw::plugin_inspect(&engine, name).await;
        }
        self.inner
            .inspect_plugin(name)
            .await
            .map(PluginSummary::from_bollard)
            .map_err(Error::from)
    }

    /// Enables an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for invalid options, transport, or daemon
    /// failures.
    pub async fn enable_plugin(
        &self,
        name: &str,
        options: Option<PluginEnableOptions>,
    ) -> Result<(), Error> {
        if let Ok(engine) = self.raw_engine() {
            // The Engine parses `timeout` with an unconditional `strconv.Atoi`,
            // so an *absent* `timeout` is `400 strconv.Atoi: parsing "":
            // invalid syntax`, measured. The owned path therefore always sends
            // it, and a caller that passed no options gets `timeout=0` — the
            // Engine's "do not wait" spelling — where the generated path sent
            // nothing and the daemon refused the request outright. That is a
            // behaviour change, and it is the correction: `PluginEnableOptions`
            // has no unset state precisely because the Engine has no default.
            return raw::plugin_enable(
                &engine,
                name,
                &options.unwrap_or_else(|| PluginEnableOptions::new(0)),
            )
            .await;
        }
        let options = options.map(|options| {
            EnablePluginOptionsBuilder::default()
                .timeout(options.timeout_seconds)
                .build()
        });
        self.inner
            .enable_plugin(name, options)
            .await
            .map_err(Error::from)
    }

    /// Disables an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn disable_plugin(
        &self,
        name: &str,
        options: Option<PluginDisableOptions>,
    ) -> Result<(), Error> {
        if let Ok(engine) = self.raw_engine() {
            return raw::plugin_disable(&engine, name, &options.unwrap_or_default()).await;
        }
        let options = options.and_then(|options| {
            options
                .force
                .map(|force| DisablePluginOptionsBuilder::default().force(force).build())
        });
        self.inner
            .disable_plugin(name, options)
            .await
            .map_err(Error::from)
    }

    /// Removes an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn remove_plugin(
        &self,
        name: &str,
        options: Option<PluginRemoveOptions>,
    ) -> Result<PluginSummary, Error> {
        if let Ok(engine) = self.raw_engine() {
            return raw::plugin_remove(&engine, name, &options.unwrap_or_default()).await;
        }
        let options = options.and_then(|options| {
            options
                .force
                .map(|force| RemovePluginOptionsBuilder::default().force(force).build())
        });
        self.inner
            .remove_plugin(name, options)
            .await
            .map(PluginSummary::from_bollard)
            .map_err(Error::from)
    }

    /// Changes plugin settings using Docker's `KEY=VALUE` wire shape.
    ///
    /// This stays on the generated client: the owned backend has no operation
    /// for `POST /plugins/{name}/set`, and the body is a `KEY=VALUE` list it
    /// does not model. Stating the gap is better than a wrapper whose body it
    /// cannot build.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or daemon
    /// failures.
    pub async fn set_plugin_config(&self, name: &str, settings: Vec<String>) -> Result<(), Error> {
        self.inner
            .set_plugin_config(name, settings)
            .await
            .map_err(Error::from)
    }

    /// Creates a plugin from an in-memory TAR archive.
    ///
    /// Callers should bound archive size before allocating the vector. The
    /// facade keeps the archive and generated request model out of its public
    /// contract.
    ///
    /// This stays on the generated client: the owned backend has no operation
    /// for `POST /plugins/create`, whose body is an opaque archive.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn create_plugin(&self, name: &str, archive: Vec<u8>) -> Result<(), Error> {
        let options = CreatePluginOptionsBuilder::default().name(name).build();
        self.inner
            .create_plugin(options, bollard::body_full(archive.into()))
            .await
            .map_err(Error::from)
    }

    /// Reads the privileges required by a remote plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn plugin_privileges(&self, remote: &str) -> Result<Vec<PluginPrivilege>, Error> {
        if let Ok(engine) = self.raw_engine() {
            return raw::plugin_privileges(&engine, remote).await;
        }
        let options = GetPluginPrivilegesOptionsBuilder::default()
            .remote(remote)
            .build();
        self.inner
            .get_plugin_privileges(options)
            .await
            .map(|values| {
                values
                    .into_iter()
                    .map(PluginPrivilege::from_bollard)
                    .collect()
            })
            .map_err(Error::from)
    }

    /// Installs a plugin without registry credentials.
    ///
    /// This is the canonical form of the install family: the credentialed
    /// variants differ from it only in how a registry credential is resolved,
    /// so all three converge on `DockerClient::install_plugin_with_optional_credentials`
    /// and the transport decision is made once, there.
    ///
    /// # Errors
    ///
    /// Returns an error when no asynchronous runtime is available. Engine
    /// request and response failures are delivered as stream items.
    pub fn install_plugin(
        &self,
        options: PluginInstallOptions,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        self.install_plugin_with_optional_credentials(options, None)
    }

    /// Installs a plugin with caller-owned registry credentials.
    ///
    /// This stays on the generated client even where the anonymous install has
    /// moved, because the owned [`raw::plugin_pull`] sends no
    /// `X-Registry-Auth` header at all. See the module documentation for why
    /// dropping that header would be worse than keeping the slower path.
    ///
    /// # Errors
    ///
    /// Returns a credential error before opening the stream when credentials
    /// are invalid. Request and response failures are delivered as stream items.
    pub fn install_plugin_with_credentials(
        &self,
        options: PluginInstallOptions,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        self.install_plugin_with_optional_credentials(options, Some((registry, credentials)))
    }

    /// Installs a plugin with credentials from an explicit provider.
    ///
    /// This stays on the generated client for the same reason as
    /// [`DockerClient::install_plugin_with_credentials`].
    ///
    /// # Errors
    ///
    /// Returns a provider or validation error before opening the stream.
    pub fn install_plugin_with_provider(
        &self,
        options: PluginInstallOptions,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        let credentials = provider.credentials_for(&registry)?;
        self.install_plugin_with_optional_credentials(options, Some((registry, credentials)))
    }

    fn install_plugin_with_optional_credentials(
        &self,
        options: PluginInstallOptions,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        // The owned backend can express this install, but only the anonymous
        // one. `raw::plugin_pull` takes no credential and sends **no**
        // `X-Registry-Auth` header, which is the correct spelling for "no
        // credentials" — but routing a credentialed call onto it would drop
        // the credential silently, and the daemon's answer would then be the
        // anonymous failure. "No credentials were sent" has to stay
        // distinguishable from "credentials were sent and were rejected", so the
        // presence of a credential is part of the routing decision rather than
        // a detail of the call.
        if credentials.is_none()
            && let Ok(engine) = self.raw_engine()
        {
            return owned_progress_stream(engine, options);
        }
        let mut builder = InstallPluginOptionsBuilder::default().remote(&options.remote);
        if let Some(name) = options.name.as_deref() {
            builder = builder.name(name);
        }
        let credentials = match credentials {
            Some((registry, credentials)) => into_credentials(Some(credentials), &registry)?,
            None => None,
        };
        let privileges = into_privileges(options.privileges);
        let docker = self.inner.clone();
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error {
            kind: crate::ErrorKind::Runtime,
            source: Some(Box::new(error)),
            api: None,
        })?;
        let (sender, receiver) = mpsc::channel(16);
        runtime.spawn(async move {
            let mut source = docker.install_plugin(builder.build(), privileges, credentials);
            while let Some(item) = source.next().await {
                let item = item.map_err(Error::from).and_then(|value| {
                    serde_json::to_value(value)
                        .map(|value| streams::map_image_event(&value))
                        .map_err(Error::serialization)
                });
                if sender.send(item).await.is_err() {
                    break;
                }
            }
        });
        Ok(DockerStream::new(futures_util::stream::unfold(
            receiver,
            |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
        )))
    }

    /// Upgrades a plugin without registry credentials.
    ///
    /// This is the canonical form of the upgrade family: the credentialed
    /// variants differ from it only in how a registry credential is resolved,
    /// so all three converge on
    /// `DockerClient::upgrade_plugin_with_optional_credentials` and the
    /// transport decision is made once, there.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn upgrade_plugin(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
    ) -> Result<(), Error> {
        self.upgrade_plugin_with_optional_credentials(name, options, None)
            .await
    }

    /// Upgrades a plugin with caller-owned registry credentials.
    ///
    /// This stays on the generated client even where the anonymous upgrade has
    /// moved, because the owned [`raw::plugin_upgrade`] sends no
    /// `X-Registry-Auth` header at all. See the module documentation for why
    /// dropping that header would be worse than keeping the slower path.
    ///
    /// # Errors
    ///
    /// Returns a credential, transport, or daemon error.
    pub async fn upgrade_plugin_with_credentials(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        credentials: RegistryCredentials,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        self.upgrade_plugin_with_optional_credentials(name, options, Some((registry, credentials)))
            .await
    }

    /// Upgrades a plugin with credentials from an explicit provider.
    ///
    /// This stays on the generated client for the same reason as
    /// [`DockerClient::upgrade_plugin_with_credentials`].
    ///
    /// # Errors
    ///
    /// Returns a provider, credential, transport, or daemon error.
    pub async fn upgrade_plugin_with_provider(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        let credentials = provider.credentials_for(&registry)?;
        self.upgrade_plugin_with_optional_credentials(name, options, Some((registry, credentials)))
            .await
    }

    async fn upgrade_plugin_with_optional_credentials(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<(), Error> {
        // The credential gate is the same one the install family uses, and for
        // the same reason: the owned upgrade sends no `X-Registry-Auth`.
        if credentials.is_none()
            && let Ok(engine) = self.raw_engine()
        {
            // The owned answer is a progress stream while this method's
            // signature is `Result<(), Error>`, and the signature is not
            // changing. `raw::plugin_upgrade` checks the status *before*
            // handing out the stream, so a daemon rejection is already an
            // `Err` at this point; the stream is then dropped, which closes
            // the connection. That is exactly what the generated client's
            // `process_into_unit` does — it returns the response without
            // reading the body — so the two agree on what the caller
            // observes, and neither one can see the progress records.
            let _progress = raw::plugin_upgrade(&engine, name, &options).await?;
            return Ok(());
        }
        let query = UpgradePluginOptionsBuilder::default()
            .remote(&options.remote)
            .build();
        let credentials = match credentials {
            Some((registry, credentials)) => into_credentials(Some(credentials), &registry)?,
            None => None,
        };
        self.inner
            .upgrade_plugin(
                name,
                query,
                into_privileges(options.privileges),
                credentials,
            )
            .await
            .map_err(Error::from)
    }

    /// Pushes a plugin without registry credentials.
    ///
    /// This stays on the generated client: the owned backend has no operation
    /// for `POST /plugins/{name}/push`. The owned `plugin_pull` is Docker's
    /// *install-from-registry* route, not a registry push, and treating the two
    /// as the same endpoint would be a request the daemon cannot answer.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn push_plugin(&self, name: &str) -> Result<(), Error> {
        self.push_plugin_with_optional_credentials(name, None).await
    }

    /// Pushes a plugin with caller-owned registry credentials.
    ///
    /// This stays on the generated client for the same reason as
    /// [`DockerClient::push_plugin`].
    ///
    /// # Errors
    ///
    /// Returns a credential, transport, or daemon error.
    pub async fn push_plugin_with_credentials(
        &self,
        name: &str,
        credentials: RegistryCredentials,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(name)?;
        self.push_plugin_with_optional_credentials(name, Some((registry, credentials)))
            .await
    }

    /// Pushes a plugin with credentials from an explicit provider.
    ///
    /// This stays on the generated client for the same reason as
    /// [`DockerClient::push_plugin`].
    ///
    /// # Errors
    ///
    /// Returns a provider, credential, transport, or daemon error.
    pub async fn push_plugin_with_provider(
        &self,
        name: &str,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(name)?;
        let credentials = provider.credentials_for(&registry)?;
        self.push_plugin_with_optional_credentials(name, Some((registry, credentials)))
            .await
    }

    async fn push_plugin_with_optional_credentials(
        &self,
        name: &str,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<(), Error> {
        let credentials = match credentials {
            Some((credential_registry, credentials)) => {
                into_credentials(Some(credentials), &credential_registry)?
            }
            None => None,
        };
        self.inner
            .push_plugin(name, credentials)
            .await
            .map_err(Error::from)
    }
}
