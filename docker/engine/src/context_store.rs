//! Local Docker context listing and mutation.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};
use tempfile::Builder as TempFileBuilder;

use crate::{
    ContextArchiveLimits, ContextArchiveStore, ContextError, Endpoint,
    config::{read_config_object, write_config_object},
    context::context_hash,
};

const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_TLS_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_TLS_FILES: usize = 32;

/// A local Docker context projected into repository-owned values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContext {
    /// Context name.
    pub name: String,
    /// Context description.
    pub description: String,
    /// Typed Docker endpoint.
    pub endpoint: Endpoint,
    /// Whether the context stores TLS material.
    pub use_tls: bool,
    /// Context-local TLS directory, when present.
    pub tls_directory: Option<PathBuf>,
}

/// Files copied into a context's `tls/<hash>/docker` directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContextTlsFiles {
    /// CA certificate source path.
    pub ca: Option<PathBuf>,
    /// Client certificate source path.
    pub certificate: Option<PathBuf>,
    /// Client private-key source path.
    pub key: Option<PathBuf>,
}

/// Options for creating a local context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextCreateOptions {
    /// New context name.
    pub name: String,
    /// Explicit endpoint. Required unless `from_context` is set.
    pub endpoint: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Existing context to copy.
    pub from_context: Option<String>,
    /// Optional TLS files to copy.
    pub tls: Option<ContextTlsFiles>,
}

/// Options for updating a local context. Unset fields remain unchanged.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContextUpdateOptions {
    /// Existing context name.
    pub name: String,
    /// Replacement endpoint.
    pub endpoint: Option<String>,
    /// Replacement description.
    pub description: Option<String>,
    /// Replacement TLS files.
    pub tls: Option<ContextTlsFiles>,
}

/// Reads and mutates Docker contexts rooted in one configuration directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextStore {
    config_directory: PathBuf,
    archive_limits: ContextArchiveLimits,
}

impl ContextStore {
    /// Creates a context store for an explicit Docker configuration directory.
    #[must_use]
    pub fn new(config_directory: impl Into<PathBuf>) -> Self {
        Self {
            config_directory: config_directory.into(),
            archive_limits: ContextArchiveLimits::default(),
        }
    }

    /// Creates a store with explicit context-archive limits.
    #[must_use]
    pub fn with_archive_limits(
        config_directory: impl Into<PathBuf>,
        archive_limits: ContextArchiveLimits,
    ) -> Self {
        Self {
            config_directory: config_directory.into(),
            archive_limits,
        }
    }

    /// Returns the configuration directory.
    #[must_use]
    pub fn config_directory(&self) -> &Path {
        &self.config_directory
    }

    /// Returns a safe archive facade sharing this store's limits.
    #[must_use]
    pub fn archive_store(&self) -> ContextArchiveStore {
        ContextArchiveStore::with_limits(self.config_directory.clone(), self.archive_limits)
    }

    /// Lists named contexts in stable case-insensitive name order.
    ///
    /// The implicit `default` context is not stored and is therefore omitted,
    /// matching Docker's metadata-directory model.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths or malformed context metadata.
    pub fn list(&self) -> Result<Vec<DockerContext>, ContextError> {
        let root = self.config_directory.join("contexts/meta");
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ContextError::Io(format!("{}: {error}", root.display()))),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ContextError::UnsafeConfigurationPath(
                root.display().to_string(),
            ));
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&root)
            .map_err(|error| ContextError::Io(format!("{}: {error}", root.display())))?
        {
            let entry =
                entry.map_err(|error| ContextError::Io(format!("{}: {error}", root.display())))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(ContextError::UnsafeConfigurationPath(
                    path.display().to_string(),
                ));
            }
            let hash = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| ContextError::UnsafeConfigurationPath(path.display().to_string()))?;
            records.push((
                read_context(&self.config_directory, &path.join("meta.json"), hash)?,
                path,
            ));
        }
        records.sort_by(|(left, _), (right, _)| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(records.into_iter().map(|(context, _)| context).collect())
    }

    /// Reads one named context.
    ///
    /// # Errors
    ///
    /// Returns a not-found, unsafe-path, or metadata error.
    pub fn get(&self, name: &str) -> Result<DockerContext, ContextError> {
        validate_name(name, false)?;
        let hash = context_hash(name);
        let path = self.metadata_directory(name).join("meta.json");
        if !path.is_file() {
            return Err(ContextError::ContextNotFound(name.to_owned()));
        }
        read_context(&self.config_directory, &path, &hash)
    }

    /// Returns the environment override or configured current context.
    ///
    /// # Errors
    ///
    /// Returns an error when `config.json` is unsafe or malformed.
    pub fn current_name(
        &self,
        environment_context: Option<&str>,
    ) -> Result<Option<String>, ContextError> {
        if let Some(name) = environment_context
            .map(str::trim)
            .filter(|name| !name.is_empty() && *name != "default")
        {
            return Ok(Some(name.to_owned()));
        }
        Ok(read_config_object(&self.config_path())
            .map_err(map_config_error)?
            .get("currentContext")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && *name != "default")
            .map(str::to_owned))
    }

    /// Creates a context and publishes its metadata last.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid names/endpoints, existing storage,
    /// disabled TLS verification, unsafe source files, or filesystem failures.
    pub fn create(&self, options: ContextCreateOptions) -> Result<(), ContextError> {
        validate_name(&options.name, false)?;
        if self.metadata_directory(&options.name).exists() {
            return Err(ContextError::ContextAlreadyExists(options.name));
        }
        validate_tls_sources(options.tls.as_ref())?;
        let source = options
            .from_context
            .as_deref()
            .map(|name| self.get(name))
            .transpose()?;
        if let Some(source) = source.as_ref() {
            validate_context(source, &options.name)?;
        }
        let endpoint = match (options.endpoint.as_deref(), source.as_ref()) {
            (Some(endpoint), _) => validate_endpoint(endpoint, &options.name)?,
            (None, Some(source)) => source.endpoint.clone(),
            (None, None) => {
                return Err(ContextError::MissingContextEndpoint(options.name));
            }
        };
        let host = endpoint_text(&endpoint);
        let source_metadata = source
            .as_ref()
            .map(|source| {
                read_json_bounded(&self.metadata_directory(&source.name).join("meta.json"))
            })
            .transpose()?;
        let mut metadata = source_metadata.unwrap_or_else(new_metadata);
        metadata.insert("Name".to_owned(), Value::String(options.name.clone()));
        set_docker_endpoint(&mut metadata, &host);
        if let Some(description) = options.description.as_deref() {
            set_description(&mut metadata, description);
        }
        if let Some(tls) = options.tls.as_ref() {
            set_tls_material(&mut metadata, tls);
        }
        validate_metadata(&metadata, &options.name)?;

        ensure_safe_directory(&self.config_directory.join("contexts"))?;
        ensure_safe_directory(&self.config_directory.join("contexts/meta"))?;
        ensure_safe_directory(&self.config_directory.join("contexts/tls"))?;
        let stage = TempFileBuilder::new()
            .prefix(".neotales-context-create-")
            .tempdir_in(self.config_directory.join("contexts"))
            .map_err(|error| ContextError::Io(error.to_string()))?;
        let hash = context_hash(&options.name);
        let staged_metadata = stage.path().join("meta");
        let staged_tls = stage.path().join("tls");
        create_private_directory(&staged_metadata)?;
        write_json_bounded(&staged_metadata.join("meta.json"), &metadata, false)?;
        if let Some(source) = source.as_ref() {
            copy_context_tls(
                &self.config_directory,
                &source.name,
                &staged_tls.join(&hash),
            )?;
        }
        write_provided_tls(&staged_tls.join(&hash), options.tls.as_ref())?;

        let final_metadata = self.metadata_directory(&options.name);
        let final_tls = self.config_directory.join("contexts/tls").join(&hash);
        if let Some(parent) = final_tls.parent() {
            create_private_directory(parent)?;
        }
        if staged_tls.exists() {
            if final_tls.exists() {
                return Err(ContextError::ContextAlreadyExists(options.name));
            }
            fs::rename(&staged_tls, &final_tls)
                .map_err(|error| ContextError::Io(error.to_string()))?;
        }
        if let Err(error) = fs::rename(&staged_metadata, &final_metadata) {
            if final_tls.exists() {
                let _ = fs::remove_dir_all(&final_tls);
            }
            return Err(ContextError::Io(format!(
                "{}: {error}",
                final_metadata.display()
            )));
        }
        Ok(())
    }

    /// Updates endpoint, description, and/or TLS files.
    ///
    /// # Errors
    ///
    /// Returns an error for missing context, invalid endpoint/TLS policy,
    /// unsafe sources, or filesystem failures.
    pub fn update(&self, options: ContextUpdateOptions) -> Result<(), ContextError> {
        validate_name(&options.name, false)?;
        validate_tls_sources(options.tls.as_ref())?;
        let metadata_path = self.metadata_directory(&options.name).join("meta.json");
        if !metadata_path.is_file() {
            return Err(ContextError::ContextNotFound(options.name));
        }
        let mut metadata = read_json_bounded(&metadata_path)?;
        if let Some(endpoint) = options.endpoint.as_deref() {
            let endpoint = validate_endpoint(endpoint, &options.name)?;
            set_docker_endpoint(&mut metadata, &endpoint_text(&endpoint));
        }
        if let Some(description) = options.description.as_deref() {
            set_description(&mut metadata, description);
        }
        validate_metadata(&metadata, &options.name)?;
        write_json_bounded(&metadata_path, &metadata, true)?;
        if let Some(tls) = options.tls.as_ref() {
            let hash = context_hash(&options.name);
            let directory = self.config_directory.join("contexts/tls").join(&hash);
            write_provided_tls(&directory, Some(tls))?;
            let mut published = read_json_bounded(&metadata_path)?;
            set_tls_material(&mut published, tls);
            write_json_bounded(&metadata_path, &published, true)?;
        }
        Ok(())
    }

    /// Removes a named context while refusing the implicit default.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/unsafe context or filesystem failure.
    pub fn remove(&self, name: &str) -> Result<(), ContextError> {
        validate_name(name, false)?;
        let metadata = self.metadata_directory(name);
        if !metadata.join("meta.json").is_file() {
            return Err(ContextError::ContextNotFound(name.to_owned()));
        }
        reject_symlink(&metadata)?;
        let tls = self
            .config_directory
            .join("contexts/tls")
            .join(context_hash(name));
        if tls.exists() {
            reject_symlink(&tls)?;
            fs::remove_dir_all(&tls)
                .map_err(|error| ContextError::Io(format!("{}: {error}", tls.display())))?;
        }
        fs::remove_dir_all(&metadata)
            .map_err(|error| ContextError::Io(format!("{}: {error}", metadata.display())))
    }

    /// Selects a context in `config.json`, preserving every unrelated key.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing context, unsafe config, or write failure.
    pub fn use_context(&self, name: &str) -> Result<(), ContextError> {
        if name.is_empty() {
            return Err(ContextError::InvalidContextName(name.to_owned()));
        }
        if name != "default" {
            self.get(name)?;
        }
        let path = self.config_path();
        let mut root = read_config_object(&path).map_err(map_config_error)?;
        if name == "default" {
            root.remove("currentContext");
        } else {
            root.insert("currentContext".to_owned(), Value::String(name.to_owned()));
        }
        write_config_object(&self.config_directory, &path, &root).map_err(map_config_error)
    }

    fn config_path(&self) -> PathBuf {
        self.config_directory.join("config.json")
    }

    fn metadata_directory(&self, name: &str) -> PathBuf {
        self.config_directory
            .join("contexts/meta")
            .join(context_hash(name))
    }
}

fn read_context(
    config_directory: &Path,
    metadata_path: &Path,
    expected_hash: &str,
) -> Result<DockerContext, ContextError> {
    reject_symlink(metadata_path)?;
    let metadata = read_json_bounded(metadata_path)?;
    let name = metadata
        .get("Name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| ContextError::InvalidMetadata("Name is required".into()))?
        .to_owned();
    validate_name(&name, false)?;
    if context_hash(&name) != expected_hash {
        return Err(ContextError::InvalidMetadata(
            "metadata directory does not match context name".into(),
        ));
    }
    let endpoint = context_endpoint(&metadata, &name)?;
    let use_tls = metadata.get("TLSMaterial").is_some();
    Ok(DockerContext {
        description: metadata
            .get("Metadata")
            .and_then(|metadata| metadata.get("Description"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        name,
        endpoint,
        use_tls,
        tls_directory: use_tls.then(|| {
            config_directory
                .join("contexts/tls")
                .join(expected_hash)
                .join("docker")
        }),
    })
}

fn context_endpoint(metadata: &Map<String, Value>, name: &str) -> Result<Endpoint, ContextError> {
    let docker = metadata
        .get("Endpoints")
        .and_then(|endpoints| endpoints.get("docker"))
        .and_then(Value::as_object)
        .ok_or_else(|| ContextError::MissingContextEndpoint(name.to_owned()))?;
    if docker
        .get("SkipTLSVerify")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ContextError::TlsVerificationDisabled(name.to_owned()));
    }
    let host = docker
        .get("Host")
        .and_then(Value::as_str)
        .ok_or_else(|| ContextError::MissingContextEndpoint(name.to_owned()))?;
    validate_endpoint(host, name)
}

fn validate_context(context: &DockerContext, target_name: &str) -> Result<(), ContextError> {
    if context.use_tls
        && context
            .tls_directory
            .as_deref()
            .is_none_or(|path| !path.is_dir())
    {
        return Err(ContextError::MissingTlsMaterial(target_name.to_owned()));
    }
    Ok(())
}

fn validate_endpoint(host: &str, name: &str) -> Result<Endpoint, ContextError> {
    if host.trim().is_empty() {
        return Err(ContextError::MissingContextEndpoint(name.to_owned()));
    }
    Endpoint::parse(host).map_err(|source| ContextError::InvalidEndpoint {
        context: Some(name.to_owned()),
        source,
    })
}

fn endpoint_text(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Unix(path) => format!("unix://{}", path.display()),
        Endpoint::NamedPipe(path) => format!("npipe://{path}"),
        Endpoint::Http(path) | Endpoint::Https { address: path, .. } => path.clone(),
        Endpoint::Ssh { address, .. } => address.clone(),
    }
}

fn new_metadata() -> Map<String, Value> {
    let mut root = Map::new();
    root.insert("Name".to_owned(), Value::String(String::new()));
    root.insert("Metadata".to_owned(), Value::Object(Map::new()));
    root.insert("Endpoints".to_owned(), Value::Object(Map::new()));
    root
}

fn set_description(metadata: &mut Map<String, Value>, description: &str) {
    let details = metadata
        .entry("Metadata".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !details.is_object() {
        *details = Value::Object(Map::new());
    }
    details
        .as_object_mut()
        .expect("description metadata was made an object")
        .insert(
            "Description".to_owned(),
            Value::String(description.to_owned()),
        );
}

fn set_docker_endpoint(metadata: &mut Map<String, Value>, host: &str) {
    let endpoints = metadata
        .entry("Endpoints".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !endpoints.is_object() {
        *endpoints = Value::Object(Map::new());
    }
    let mut docker = endpoints
        .as_object_mut()
        .expect("endpoints metadata was made an object")
        .remove("docker")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    docker.insert("Host".to_owned(), Value::String(host.to_owned()));
    docker.insert("SkipTLSVerify".to_owned(), Value::Bool(false));
    endpoints
        .as_object_mut()
        .expect("endpoints metadata was made an object")
        .insert("docker".to_owned(), Value::Object(docker));
}

fn set_tls_material(metadata: &mut Map<String, Value>, tls: &ContextTlsFiles) {
    let mut material = Map::new();
    if let Some(ca) = tls.ca.as_deref() {
        material.insert("CA".to_owned(), Value::String(file_name(ca)));
    }
    if let Some(certificate) = tls.certificate.as_deref() {
        material.insert("Cert".to_owned(), Value::String(file_name(certificate)));
    }
    if let Some(key) = tls.key.as_deref() {
        material.insert("Key".to_owned(), Value::String(file_name(key)));
    }
    let mut tls_material = Map::new();
    tls_material.insert(
        "docker".to_owned(),
        Value::Array(vec![Value::Object(material)]),
    );
    metadata.insert("TLSMaterial".to_owned(), Value::Object(tls_material));
}

fn validate_metadata(metadata: &Map<String, Value>, name: &str) -> Result<(), ContextError> {
    let _ = context_endpoint(metadata, name)?;
    Ok(())
}

fn validate_name(name: &str, allow_default: bool) -> Result<(), ContextError> {
    let valid = !name.is_empty()
        && name.trim() == name
        && name.len() <= 255
        && !name.chars().any(char::is_control)
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && (allow_default || name != "default");
    if valid {
        Ok(())
    } else {
        Err(ContextError::InvalidContextName(name.to_owned()))
    }
}

fn validate_tls_sources(tls: Option<&ContextTlsFiles>) -> Result<(), ContextError> {
    let Some(tls) = tls else {
        return Ok(());
    };
    for source in [
        tls.ca.as_deref(),
        tls.certificate.as_deref(),
        tls.key.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let metadata = fs::symlink_metadata(source)
            .map_err(|error| ContextError::Io(format!("{}: {error}", source.display())))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ContextError::UnsafeConfigurationPath(
                source.display().to_string(),
            ));
        }
        if metadata.len() > MAX_TLS_FILE_BYTES {
            return Err(ContextError::InvalidMetadata(format!(
                "TLS source {} exceeds {MAX_TLS_FILE_BYTES} bytes",
                source.display()
            )));
        }
    }
    Ok(())
}

fn write_provided_tls(tls_root: &Path, tls: Option<&ContextTlsFiles>) -> Result<(), ContextError> {
    let Some(tls) = tls else {
        return Ok(());
    };
    let directory = tls_root.join("docker");
    create_private_directory(&directory)?;
    for (source, name, mode) in [
        (tls.ca.as_deref(), "ca.pem", 0o644_u32),
        (tls.certificate.as_deref(), "cert.pem", 0o644_u32),
        (tls.key.as_deref(), "key.pem", 0o600_u32),
    ] {
        if let Some(source) = source {
            copy_bounded(source, &directory.join(name), MAX_TLS_FILE_BYTES)?;
            set_unix_mode(&directory.join(name), mode)?;
        }
    }
    Ok(())
}

fn copy_context_tls(
    config_directory: &Path,
    source_name: &str,
    destination: &Path,
) -> Result<(), ContextError> {
    let source = config_directory
        .join("contexts/tls")
        .join(context_hash(source_name));
    if !source.exists() {
        return Ok(());
    }
    reject_symlink(&source)?;
    let files = fs::read_dir(&source)
        .map_err(|error| ContextError::Io(format!("{}: {error}", source.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ContextError::Io(error.to_string()))?;
    if files.len() > MAX_TLS_FILES {
        return Err(ContextError::InvalidMetadata(
            "context has too many TLS files".into(),
        ));
    }
    for entry in files {
        let file_type = entry
            .file_type()
            .map_err(|error| ContextError::Io(error.to_string()))?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(ContextError::UnsafeConfigurationPath(
                entry.path().display().to_string(),
            ));
        }
        let target = destination.join("docker").join(entry.file_name());
        copy_bounded(&entry.path(), &target, MAX_TLS_FILE_BYTES)?;
        if entry.file_name() == "key.pem" {
            set_unix_mode(&target, 0o600)?;
        }
    }
    Ok(())
}

fn copy_bounded(source: &Path, destination: &Path, limit: u64) -> Result<(), ContextError> {
    if let Some(parent) = destination.parent() {
        create_private_directory(parent)?;
    }
    let mut input = File::open(source)
        .map_err(|error| ContextError::Io(format!("{}: {error}", source.display())))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(destination)
        .map_err(|error| ContextError::Io(format!("{}: {error}", destination.display())))?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| ContextError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| ContextError::InvalidMetadata("TLS file size overflow".into()))?;
        if total > limit {
            return Err(ContextError::InvalidMetadata(format!(
                "TLS file {} exceeds {limit} bytes",
                source.display()
            )));
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| ContextError::Io(error.to_string()))?;
    }
    Ok(())
}

fn read_json_bounded(path: &Path) -> Result<Map<String, Value>, ContextError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ContextError::UnsafeConfigurationPath(
            path.display().to_string(),
        ));
    }
    if metadata.len() > MAX_METADATA_BYTES {
        return Err(ContextError::InvalidMetadata(format!(
            "{} exceeds {MAX_METADATA_BYTES} bytes",
            path.display()
        )));
    }
    let bytes =
        fs::read(path).map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ContextError::InvalidJson(error.to_string()))?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| ContextError::InvalidMetadata("metadata must be a JSON object".into()))
}

fn write_json_bounded(
    path: &Path,
    value: &Map<String, Value>,
    replace: bool,
) -> Result<(), ContextError> {
    let parent = path
        .parent()
        .ok_or_else(|| ContextError::UnsafeConfigurationPath(path.display().to_string()))?;
    create_private_directory(parent)?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".neotales-context-metadata-")
        .tempfile_in(parent)
        .map_err(|error| ContextError::Io(error.to_string()))?;
    set_unix_mode(temporary.path(), 0o644)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)
        .map_err(|error| ContextError::InvalidMetadata(error.to_string()))?;
    temporary
        .as_file_mut()
        .write_all(b"\n")
        .map_err(|error| ContextError::Io(error.to_string()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| ContextError::Io(error.to_string()))?;
    if replace {
        temporary
            .persist(path)
            .map_err(|error| ContextError::Io(error.error.to_string()))?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| ContextError::Io(error.error.to_string()))?;
    }
    Ok(())
}

fn ensure_safe_directory(path: &Path) -> Result<(), ContextError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            ContextError::UnsafeConfigurationPath(path.display().to_string()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
            set_unix_mode(path, 0o700)
        }
        Err(error) => Err(ContextError::Io(format!("{}: {error}", path.display()))),
    }
}

fn create_private_directory(path: &Path) -> Result<(), ContextError> {
    ensure_safe_directory(path)?;
    set_unix_mode(path, 0o700)
}

fn reject_symlink(path: &Path) -> Result<(), ContextError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() {
        Err(ContextError::UnsafeConfigurationPath(
            path.display().to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg_attr(
    not(unix),
    allow(
        clippy::unnecessary_wraps,
        reason = "Windows has no mode bits; the Result stays so the unix body and its callers share one signature"
    )
)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<(), ContextError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| ContextError::Io(format!("{}: {error}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source.pem")
        .to_owned()
}

fn map_config_error(error: crate::DockerConfigError) -> ContextError {
    match error {
        crate::DockerConfigError::UnsafePath(path) => ContextError::UnsafeConfigurationPath(path),
        crate::DockerConfigError::InvalidConfig(message) => ContextError::InvalidJson(message),
        crate::DockerConfigError::Io(message) => ContextError::Io(message),
        crate::DockerConfigError::Credential(error) => ContextError::Io(error.to_string()),
    }
}
