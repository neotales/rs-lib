//! Bounded Docker configuration and registry credential persistence.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tempfile::Builder as TempFileBuilder;
use zeroize::Zeroizing;

use crate::{CredentialError, DockerCredentialHelper, RegistryCredentials};

const CONFIG_FILE_NAME: &str = "config.json";
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(30);

/// Docker Hub's canonical key in `config.json`.
pub const DOCKER_HUB_REGISTRY: &str = "https://index.docker.io/v1/";

/// Errors returned while reading or mutating Docker configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerConfigError {
    /// The configuration path is unsafe or has the wrong file type.
    UnsafePath(String),
    /// Docker configuration JSON is invalid or has an unexpected shape.
    InvalidConfig(String),
    /// A configuration or helper I/O operation failed.
    Io(String),
    /// A registry credential helper failed, timed out, or returned invalid data.
    Credential(CredentialError),
}

impl std::fmt::Display for DockerConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafePath(path) => {
                write!(formatter, "Docker config path is unsafe: {path}")
            }
            Self::InvalidConfig(message) => {
                write!(formatter, "Docker config is invalid: {message}")
            }
            Self::Io(message) => write!(formatter, "Docker config I/O failed: {message}"),
            Self::Credential(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DockerConfigError {}

impl From<CredentialError> for DockerConfigError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

/// Result of removing registry credentials from Docker configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RegistryLogoutResult {
    /// User-visible registry name.
    pub server: String,
    /// Whether an `auths` marker or inline entry was removed.
    pub had_entry: bool,
    /// Whether a per-registry or global credential helper was configured.
    pub had_helper: bool,
    /// Redacted warning when helper erasure failed.
    pub warning: Option<String>,
}

/// Reads and writes registry credentials in one Docker configuration directory.
///
/// File-backed credentials are stored as Docker's base64 `auth` value. Helper
/// selection honors `credHelpers` before global `credsStore`; helper programs
/// are executed directly by [`DockerCredentialHelper`], never through a shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryConfigStore {
    config_directory: PathBuf,
    helper_search_paths: Option<Vec<PathBuf>>,
    helper_timeout: Duration,
}

impl RegistryConfigStore {
    /// Creates a store rooted at an explicit Docker configuration directory.
    #[must_use]
    pub fn new(config_directory: impl Into<PathBuf>) -> Self {
        Self {
            config_directory: config_directory.into(),
            helper_search_paths: None,
            helper_timeout: DEFAULT_HELPER_TIMEOUT,
        }
    }

    /// Creates a store using `DOCKER_CONFIG`, then `HOME`/`USERPROFILE`.
    ///
    /// # Errors
    ///
    /// Returns an error when no Docker configuration directory can be found.
    pub fn from_environment() -> Result<Self, DockerConfigError> {
        let config_directory = std::env::var_os("DOCKER_CONFIG")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(|home| PathBuf::from(home).join(".docker"))
            })
            .ok_or_else(|| {
                DockerConfigError::InvalidConfig(
                    "configuration directory is unavailable; set DOCKER_CONFIG or HOME".to_owned(),
                )
            })?;
        Ok(Self::new(config_directory))
    }

    /// Uses explicit helper search directories and timeout.
    ///
    /// This is primarily useful for hermetic callers and tests. Passing an
    /// empty list intentionally searches no directory.
    #[must_use]
    pub fn with_helper_policy(mut self, search_paths: Vec<PathBuf>, timeout: Duration) -> Self {
        self.helper_search_paths = Some(search_paths);
        self.helper_timeout = timeout;
        self
    }

    /// Returns the configuration directory.
    #[must_use]
    pub fn config_directory(&self) -> &Path {
        &self.config_directory
    }

    /// Returns the `config.json` path.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.config_directory.join(CONFIG_FILE_NAME)
    }

    /// Stores credentials after validating them for `server`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed config, invalid credentials, or helper
    /// and filesystem failures. Secret values are not included in errors.
    pub async fn store(
        &self,
        server: Option<&str>,
        credentials: RegistryCredentials,
    ) -> Result<(), DockerConfigError> {
        let registry_key = registry_key(server);
        credentials.validate_for(&registry_key)?;

        let mut root = self.load_object()?;
        let helper = resolve_helper(&root, &registry_key, server);
        if let Some(helper) = helper.as_deref() {
            let helper = self.helper(helper)?;
            helper.store(&registry_key, &credentials).await?;
            let auths = ensure_object(
                root.entry("auths".to_owned())
                    .or_insert_with(|| Value::Object(Map::new())),
                "auths",
            )?;
            let entry = ensure_object(
                auths
                    .entry(registry_key.clone())
                    .or_insert_with(|| Value::Object(Map::new())),
                "auth entry",
            )?;
            entry.remove("auth");
            entry.remove("username");
            entry.remove("password");
        } else {
            let (username, secret) = credentials.into_stored_parts();
            let auths = ensure_object(
                root.entry("auths".to_owned())
                    .or_insert_with(|| Value::Object(Map::new())),
                "auths",
            )?;
            let entry = ensure_object(
                auths
                    .entry(registry_key.clone())
                    .or_insert_with(|| Value::Object(Map::new())),
                "auth entry",
            )?;
            let encoded = BASE64.encode(Zeroizing::new(format!("{username}:{secret}")));
            entry.insert("auth".to_owned(), Value::String(encoded));
            entry.remove("password");
            if username == "<token>" {
                entry.insert("username".to_owned(), Value::String(username));
            } else {
                entry.remove("username");
            }
        }
        self.save_object(&root)
    }

    /// Reads credentials for `server`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid config or a configured helper that fails,
    /// times out, or returns malformed output.
    pub async fn credentials(
        &self,
        server: Option<&str>,
    ) -> Result<Option<RegistryCredentials>, DockerConfigError> {
        let registry_key = registry_key(server);
        let root = self.load_object()?;
        if let Some(helper) = resolve_helper(&root, &registry_key, server) {
            return Ok(Some(self.helper(&helper)?.get(&registry_key).await?));
        }
        let Some(auth) = root
            .get("auths")
            .and_then(Value::as_object)
            .and_then(|auths| auths.get(&registry_key))
            .and_then(Value::as_object)
            .and_then(|entry| entry.get("auth"))
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let bytes = BASE64
            .decode(auth)
            .map_err(|_| DockerConfigError::InvalidConfig("registry auth is not base64".into()))?;
        let mut bytes = Zeroizing::new(bytes);
        let text =
            Zeroizing::new(String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| {
                DockerConfigError::InvalidConfig("registry auth is not UTF-8".into())
            })?);
        let (username, secret) = text
            .split_once(':')
            .filter(|(username, secret)| !username.is_empty() && !secret.is_empty())
            .ok_or_else(|| {
                DockerConfigError::InvalidConfig(
                    "registry auth does not contain a username and secret".into(),
                )
            })?;
        let credentials = if username == "<token>" {
            RegistryCredentials::from_identity_token(secret)
        } else {
            RegistryCredentials::new(username, secret)
        }
        .with_server_address(&registry_key);
        credentials.validate_for(&registry_key)?;
        Ok(Some(credentials))
    }

    /// Removes credentials for `server` and reports what was present.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed config or filesystem failures. Helper
    /// erasure failures are returned as redacted warnings after inline entries
    /// have been removed.
    pub async fn logout(
        &self,
        server: Option<&str>,
    ) -> Result<RegistryLogoutResult, DockerConfigError> {
        let registry_key = registry_key(server);
        let mut root = self.load_object()?;
        let helper = resolve_helper(&root, &registry_key, server);
        let mut had_entry = false;
        if let Some(auths) = root.get_mut("auths") {
            let auths = auths.as_object_mut().ok_or_else(|| {
                DockerConfigError::InvalidConfig("auths must be a JSON object".into())
            })?;
            had_entry |= auths.remove(&registry_key).is_some();
            if let Some(display) = server.map(str::trim).filter(|value| !value.is_empty())
                && display != registry_key
            {
                had_entry |= auths.remove(display).is_some();
            }
        }
        let warning = if let Some(helper) = helper.as_deref() {
            match self.helper(helper) {
                Ok(helper) => match helper.erase(&registry_key).await {
                    Ok(()) => None,
                    Err(_) => Some("credential helper could not erase credentials".to_owned()),
                },
                Err(_) => Some("credential helper could not erase credentials".to_owned()),
            }
        } else {
            None
        };
        if had_entry {
            self.save_object(&root)?;
        }
        Ok(RegistryLogoutResult {
            server: display_server(server),
            had_entry,
            had_helper: helper.is_some(),
            warning,
        })
    }

    fn helper(&self, suffix: &str) -> Result<DockerCredentialHelper, DockerConfigError> {
        let file_name = format!("docker-credential-{suffix}");
        let paths = self.helper_search_paths.as_ref().map_or_else(
            || {
                std::env::var_os("PATH")
                    .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .unwrap_or_default()
            },
            Clone::clone,
        );
        for directory in paths {
            let mut candidate = directory.join(&file_name);
            if !candidate.is_file() && cfg!(windows) {
                candidate.set_extension("exe");
            }
            if candidate.is_file() {
                return Ok(DockerCredentialHelper::from_path(
                    &candidate,
                    self.helper_timeout,
                )?);
            }
        }
        Err(CredentialError::HelperFailed.into())
    }

    fn load_object(&self) -> Result<Map<String, Value>, DockerConfigError> {
        read_config_object(&self.config_path())
    }

    fn save_object(&self, root: &Map<String, Value>) -> Result<(), DockerConfigError> {
        write_config_object(&self.config_directory, &self.config_path(), root)
    }
}

/// Returns Docker's canonical configuration key for a registry.
#[must_use]
pub fn registry_key(server: Option<&str>) -> String {
    let server = server.map(str::trim).unwrap_or_default();
    if server.is_empty() || is_docker_hub(server) {
        DOCKER_HUB_REGISTRY.to_owned()
    } else {
        server.to_owned()
    }
}

/// Returns the user-visible registry name used by login/logout messages.
#[must_use]
pub fn display_server(server: Option<&str>) -> String {
    server
        .map(str::trim)
        .filter(|server| !server.is_empty())
        .unwrap_or(DOCKER_HUB_REGISTRY)
        .to_owned()
}

fn is_docker_hub(server: &str) -> bool {
    matches!(
        server.to_ascii_lowercase().as_str(),
        "docker.io"
            | "index.docker.io"
            | "registry-1.docker.io"
            | "https://index.docker.io/v1"
            | "https://index.docker.io/v1/"
            | "http://index.docker.io/v1/"
    )
}

fn resolve_helper(
    root: &Map<String, Value>,
    registry_key: &str,
    server: Option<&str>,
) -> Option<String> {
    if let Some(helpers) = root.get("credHelpers").and_then(Value::as_object) {
        let selected = helpers
            .get(registry_key)
            .or_else(|| server.and_then(|server| helpers.get(server.trim())))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if selected.is_some() {
            return selected.map(str::to_owned);
        }
    }
    root.get("credsStore")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn ensure_object<'a>(
    value: &'a mut Value,
    description: &str,
) -> Result<&'a mut Map<String, Value>, DockerConfigError> {
    if value.is_null() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().ok_or_else(|| {
        DockerConfigError::InvalidConfig(format!("{description} must be a JSON object"))
    })
}

pub(crate) fn read_config_object(path: &Path) -> Result<Map<String, Value>, DockerConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(error) => {
            return Err(DockerConfigError::Io(format!(
                "{}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DockerConfigError::UnsafePath(path.display().to_string()));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(DockerConfigError::InvalidConfig(format!(
            "{} exceeds {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| DockerConfigError::Io(format!("{}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| DockerConfigError::Io(format!("{}: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(DockerConfigError::InvalidConfig(format!(
            "{} exceeds {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        DockerConfigError::InvalidConfig(format!("{}: {error}", path.display()))
    })?;
    match value {
        Value::Object(root) => Ok(root),
        _ => Err(DockerConfigError::InvalidConfig(format!(
            "{} must contain a JSON object",
            path.display()
        ))),
    }
}

pub(crate) fn write_config_object(
    config_directory: &Path,
    destination: &Path,
    root: &Map<String, Value>,
) -> Result<(), DockerConfigError> {
    let created = !config_directory.exists();
    if created {
        fs::create_dir_all(config_directory).map_err(|error| {
            DockerConfigError::Io(format!("{}: {error}", config_directory.display()))
        })?;
        set_unix_mode(config_directory, 0o700)?;
    } else {
        let metadata = fs::symlink_metadata(config_directory).map_err(|error| {
            DockerConfigError::Io(format!("{}: {error}", config_directory.display()))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DockerConfigError::UnsafePath(
                config_directory.display().to_string(),
            ));
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(destination)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(DockerConfigError::UnsafePath(
            destination.display().to_string(),
        ));
    }

    let parent = destination
        .parent()
        .ok_or_else(|| DockerConfigError::UnsafePath(destination.display().to_string()))?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".neotales-docker-config-")
        .tempfile_in(parent)
        .map_err(|error| DockerConfigError::Io(error.to_string()))?;
    set_unix_mode(temporary.path(), 0o600)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), root)
        .map_err(|error| DockerConfigError::InvalidConfig(error.to_string()))?;
    temporary
        .as_file_mut()
        .write_all(b"\n")
        .map_err(|error| DockerConfigError::Io(error.to_string()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| DockerConfigError::Io(error.to_string()))?;
    temporary
        .persist(destination)
        .map_err(|error| DockerConfigError::Io(error.error.to_string()))?;
    Ok(())
}

fn set_unix_mode(path: &Path, mode: u32) -> Result<(), DockerConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| DockerConfigError::Io(format!("{}: {error}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// A deterministic, secret-free view of a Docker configuration document.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DockerConfigSummary {
    /// Current context, when configured.
    pub current_context: Option<String>,
    /// Registry keys, including helper markers, in stable order.
    pub registries: BTreeMap<String, bool>,
}
