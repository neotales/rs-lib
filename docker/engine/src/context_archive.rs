//! Bounded Docker context archive import and export.

use crate::link_guard::is_link_or_reparse_point;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};
use tempfile::Builder as TempFileBuilder;

use crate::{ContextError, ContextResolver, Endpoint, context::context_hash};

const MEBIBYTE: u64 = 1024 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PUBLIC_FILE_MODE: u32 = 0o644;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Resource limits applied while reading or writing context archives.
///
/// The defaults match the limits used by the repository's reference context
/// store while also bounding the physical archive and ZIP expansion ratio.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextArchiveLimits {
    /// Maximum number of files and directories in one archive.
    pub max_entries: usize,
    /// Maximum uncompressed size of any one file.
    pub max_entry_bytes: u64,
    /// Maximum combined uncompressed file size.
    pub max_total_bytes: u64,
    /// Maximum physical size of the TAR or ZIP container.
    pub max_archive_bytes: u64,
    /// Maximum UTF-8 byte length of an archive path.
    pub max_path_bytes: usize,
    /// Maximum uncompressed-to-compressed ratio for each ZIP file.
    pub max_compression_ratio: u64,
}

impl Default for ContextArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_entry_bytes: 10 * MEBIBYTE,
            max_total_bytes: 50 * MEBIBYTE,
            max_archive_bytes: 64 * MEBIBYTE,
            max_path_bytes: 1024,
            max_compression_ratio: 1000,
        }
    }
}

impl ContextArchiveLimits {
    fn validate(&self) -> Result<(), ContextArchiveError> {
        if self.max_entries == 0 {
            return Err(ContextArchiveError::InvalidLimits(
                "max_entries must be positive",
            ));
        }
        if self.max_archive_bytes == 0 {
            return Err(ContextArchiveError::InvalidLimits(
                "max_archive_bytes must be positive",
            ));
        }
        if self.max_path_bytes == 0 {
            return Err(ContextArchiveError::InvalidLimits(
                "max_path_bytes must be positive",
            ));
        }
        if self.max_compression_ratio == 0 {
            return Err(ContextArchiveError::InvalidLimits(
                "max_compression_ratio must be positive",
            ));
        }
        Ok(())
    }
}

/// Size information for an imported or exported context archive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContextArchiveSummary {
    /// Number of files and directory records inspected or written.
    pub entry_count: usize,
    /// Combined uncompressed regular-file size.
    pub uncompressed_bytes: u64,
}

/// Errors returned while importing or exporting Docker context archives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextArchiveError {
    /// A configured resource limit is not usable.
    InvalidLimits(&'static str),
    /// Docker configuration discovery failed.
    Configuration(String),
    /// A context name is empty, reserved, or otherwise invalid.
    InvalidContextName(String),
    /// The requested context does not exist.
    ContextNotFound(String),
    /// Import would replace or conflict with existing context storage.
    ContextAlreadyExists(String),
    /// A configuration path is a link or is not a directory.
    UnsafeConfigurationPath(String),
    /// An archive entry path is unsafe or is outside Docker's context shape.
    UnsafeArchivePath(String),
    /// The archive contains the same logical path more than once.
    DuplicateArchiveEntry(String),
    /// The archive contains a link, device, FIFO, or other special entry.
    UnsupportedArchiveEntry {
        /// Archive entry name.
        entry: String,
        /// Stable description of the rejected entry kind.
        kind: &'static str,
    },
    /// The archive has more entries than the configured limit.
    TooManyEntries {
        /// Observed entry count.
        actual: usize,
        /// Configured entry limit.
        limit: usize,
    },
    /// A file declares or produces more bytes than the per-file limit.
    EntryTooLarge {
        /// Archive entry name.
        entry: String,
        /// Observed or declared size.
        actual: u64,
        /// Configured per-file limit.
        limit: u64,
    },
    /// The combined uncompressed size exceeds the configured limit.
    TotalSizeExceeded {
        /// Configured combined-size limit.
        limit: u64,
    },
    /// The physical archive exceeds the configured limit.
    ArchiveTooLarge {
        /// Observed or attempted size.
        actual: u64,
        /// Configured physical-size limit.
        limit: u64,
    },
    /// A ZIP entry expands beyond the configured compression ratio.
    CompressionRatioExceeded {
        /// Archive entry name.
        entry: String,
        /// Configured expansion-ratio limit.
        limit: u64,
    },
    /// The archive is malformed or uses an unsupported TAR/ZIP feature.
    InvalidArchive(String),
    /// The input is neither a supported TAR nor ZIP archive.
    UnsupportedFormat,
    /// The archive does not contain exactly one `meta.json` file.
    MissingMetadata,
    /// Context metadata is malformed or unsafe.
    InvalidMetadata(String),
    /// A filesystem or archive I/O operation failed.
    Io(String),
}

impl fmt::Display for ContextArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(message) => {
                write!(
                    formatter,
                    "Docker context archive limits are invalid: {message}"
                )
            }
            Self::Configuration(message) => {
                write!(
                    formatter,
                    "Docker context archive configuration failed: {message}"
                )
            }
            Self::InvalidContextName(name) => {
                write!(formatter, "Docker context name is invalid: {name}")
            }
            Self::ContextNotFound(name) => {
                write!(formatter, "Docker context does not exist: {name}")
            }
            Self::ContextAlreadyExists(name) => {
                write!(formatter, "Docker context already exists: {name}")
            }
            Self::UnsafeConfigurationPath(path) => {
                write!(formatter, "Docker configuration path is unsafe: {path}")
            }
            Self::UnsafeArchivePath(path) => {
                write!(formatter, "Docker context archive path is unsafe: {path}")
            }
            Self::DuplicateArchiveEntry(path) => {
                write!(
                    formatter,
                    "Docker context archive contains duplicate path: {path}"
                )
            }
            Self::UnsupportedArchiveEntry { entry, kind } => write!(
                formatter,
                "Docker context archive entry {entry} is an unsupported {kind}"
            ),
            Self::TooManyEntries { actual, limit } => write!(
                formatter,
                "Docker context archive has {actual} entries; limit is {limit}"
            ),
            Self::EntryTooLarge {
                entry,
                actual,
                limit,
            } => write!(
                formatter,
                "Docker context archive entry {entry} is {actual} bytes; limit is {limit}"
            ),
            Self::TotalSizeExceeded { limit } => write!(
                formatter,
                "Docker context archive exceeds the total-size limit of {limit} bytes"
            ),
            Self::ArchiveTooLarge { actual, limit } => write!(
                formatter,
                "Docker context archive is or would be {actual} bytes; limit is {limit}"
            ),
            Self::CompressionRatioExceeded { entry, limit } => write!(
                formatter,
                "Docker context archive entry {entry} exceeds compression ratio {limit}"
            ),
            Self::InvalidArchive(message) => {
                write!(formatter, "Docker context archive is invalid: {message}")
            }
            Self::UnsupportedFormat => {
                write!(formatter, "Docker context archive is not TAR or ZIP")
            }
            Self::MissingMetadata => {
                write!(formatter, "Docker context archive has no unique meta.json")
            }
            Self::InvalidMetadata(message) => {
                write!(
                    formatter,
                    "Docker context archive metadata is invalid: {message}"
                )
            }
            Self::Io(message) => write!(formatter, "Docker context archive I/O failed: {message}"),
        }
    }
}

impl std::error::Error for ContextArchiveError {}

impl From<ContextError> for ContextArchiveError {
    fn from(error: ContextError) -> Self {
        Self::Configuration(error.to_string())
    }
}

/// Reads and writes Docker context archives rooted in one configuration directory.
///
/// Import accepts Docker's root-level `meta.json` and
/// `tls/<endpoint>/<file>` layout from uncompressed TAR and ZIP archives.
/// Every archive is fully inspected before staged files are written. The
/// metadata directory is published last, making a context visible atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextArchiveStore {
    config_directory: PathBuf,
    limits: ContextArchiveLimits,
}

impl ContextArchiveStore {
    /// Creates a store for an explicit Docker configuration directory.
    #[must_use]
    pub fn new(config_directory: impl Into<PathBuf>) -> Self {
        Self {
            config_directory: config_directory.into(),
            limits: ContextArchiveLimits::default(),
        }
    }

    /// Creates a store with explicit archive resource limits.
    #[must_use]
    pub fn with_limits(config_directory: impl Into<PathBuf>, limits: ContextArchiveLimits) -> Self {
        Self {
            config_directory: config_directory.into(),
            limits,
        }
    }

    /// Creates a store using `DOCKER_CONFIG`, `HOME`, or `USERPROFILE`.
    ///
    /// # Errors
    ///
    /// Returns an error when a Docker configuration directory cannot be found.
    pub fn from_environment() -> Result<Self, ContextArchiveError> {
        let resolver = ContextResolver::from_environment()?;
        Ok(Self::new(resolver.config_directory()))
    }

    /// Returns the configured Docker configuration directory.
    #[must_use]
    pub fn config_directory(&self) -> &Path {
        &self.config_directory
    }

    /// Returns the configured archive limits.
    #[must_use]
    pub const fn limits(&self) -> &ContextArchiveLimits {
        &self.limits
    }

    /// Exports one context as an uncompressed, deterministic TAR archive.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or missing context, unsafe source files,
    /// exceeded resource limits, malformed metadata, or archive output failure.
    pub fn export<W: Write>(
        &self,
        context: &str,
        destination: W,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.limits.validate()?;
        validate_context_name(context)?;
        let root = existing_configuration_root(&self.config_directory)?;
        let source = collect_export_source(&root, context, self.limits)?;
        let mut writer = BoundedWriter::new(destination, self.limits.max_archive_bytes);
        write_tar(&source, &mut writer)?;
        writer.flush().map_err(map_output_error)?;
        Ok(source.summary)
    }

    /// Exports one context as a deterministic ZIP archive.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or missing context, unsafe source files,
    /// exceeded resource limits, malformed metadata, or archive output failure.
    pub fn export_zip<W: Write + Seek>(
        &self,
        context: &str,
        destination: W,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.limits.validate()?;
        validate_context_name(context)?;
        let root = existing_configuration_root(&self.config_directory)?;
        let source = collect_export_source(&root, context, self.limits)?;
        write_zip(&source, destination, self.limits)?;
        Ok(source.summary)
    }

    /// Atomically exports one context as TAR at `destination`.
    ///
    /// The destination is replaced only after a complete archive has been
    /// written and synced beside it. Existing content is left unchanged on
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns an error when export, temporary-file creation, syncing, or the
    /// final atomic rename fails.
    pub fn export_to_path(
        &self,
        context: &str,
        destination: impl AsRef<Path>,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.write_atomic_destination(destination.as_ref(), |output| self.export(context, output))
    }

    /// Atomically exports one context as ZIP at `destination`.
    ///
    /// # Errors
    ///
    /// Returns an error when export, temporary-file creation, syncing, or the
    /// final atomic rename fails.
    pub fn export_zip_to_path(
        &self,
        context: &str,
        destination: impl AsRef<Path>,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.write_atomic_destination(destination.as_ref(), |output| {
            self.export_zip(context, output)
        })
    }

    /// Imports a seekable TAR or ZIP archive as `context`.
    ///
    /// The complete entry table is validated before extraction. Files are
    /// staged below the Docker configuration root, all TLS keys are forced to
    /// mode `0600` on Unix, and metadata is published atomically last.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, unsafe archive entries, exceeded
    /// limits, an existing context, or filesystem/publication failures.
    pub fn import<R: Read + Seek>(
        &self,
        context: &str,
        archive: &mut R,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.limits.validate()?;
        validate_context_name(context)?;

        let archive_size = archive
            .seek(SeekFrom::End(0))
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        if archive_size > self.limits.max_archive_bytes {
            return Err(ContextArchiveError::ArchiveTooLarge {
                actual: archive_size,
                limit: self.limits.max_archive_bytes,
            });
        }
        archive
            .seek(SeekFrom::Start(0))
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;

        let inspected = inspect_archive(archive, self.limits)?;
        let raw_metadata = read_metadata(archive, &inspected, self.limits)?;
        let (metadata, required_tls) = prepare_metadata(&raw_metadata, context)?;
        validate_required_tls(&inspected, &required_tls)?;
        let metadata_output_size = metadata.len() as u64;
        let payload_without_metadata = inspected
            .total_bytes
            .checked_sub(inspected.metadata_size)
            .ok_or_else(|| {
            ContextArchiveError::InvalidArchive("metadata size underflow".to_owned())
        })?;
        let expected_total = add_entry_size(
            payload_without_metadata,
            metadata_output_size,
            "meta.json",
            self.limits,
        )?;

        let root = prepare_import_root(&self.config_directory)?;
        let hash = context_hash(context);
        let final_metadata = root.join("contexts/meta").join(&hash);
        let final_tls = root.join("contexts/tls").join(&hash);
        ensure_import_target_available(context, &final_metadata, &final_tls)?;

        let stage = TempFileBuilder::new()
            .prefix(".neotales-context-import-")
            .tempdir_in(&root)
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        let staged_metadata = stage.path().join("meta").join(&hash);
        let staged_tls = stage.path().join("tls").join(&hash);
        create_private_directory(&staged_metadata)?;
        if !inspected.files.is_empty() {
            create_private_directory(&staged_tls)?;
        }
        write_new_file(
            &staged_metadata.join("meta.json"),
            &metadata,
            PRIVATE_FILE_MODE,
        )?;

        let actual_total = extract_tls_files(
            archive,
            &inspected,
            &staged_tls,
            metadata_output_size,
            self.limits,
        )?;
        if actual_total != expected_total {
            return Err(ContextArchiveError::InvalidArchive(
                "entry sizes changed while reading the archive".to_owned(),
            ));
        }

        publish_import(
            context,
            &final_metadata,
            &final_tls,
            &staged_metadata,
            &staged_tls,
            !inspected.files.is_empty(),
        )?;
        drop(stage);

        Ok(ContextArchiveSummary {
            entry_count: inspected.entry_count,
            uncompressed_bytes: inspected.total_bytes,
        })
    }

    /// Imports a TAR or ZIP file as `context`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is not a regular bounded file or when
    /// [`Self::import`] rejects its contents.
    pub fn import_path(
        &self,
        context: &str,
        archive: impl AsRef<Path>,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.limits.validate()?;
        let path = archive.as_ref();
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| ContextArchiveError::Io(format!("{}: {error}", path.display())))?;
        if !metadata.file_type().is_file() {
            return Err(ContextArchiveError::UnsupportedArchiveEntry {
                entry: path.display().to_string(),
                kind: "filesystem entry",
            });
        }
        reject_hard_link(&metadata, &path.display().to_string())?;
        if metadata.len() > self.limits.max_archive_bytes {
            return Err(ContextArchiveError::ArchiveTooLarge {
                actual: metadata.len(),
                limit: self.limits.max_archive_bytes,
            });
        }
        let mut file = File::open(path)
            .map_err(|error| ContextArchiveError::Io(format!("{}: {error}", path.display())))?;
        self.import(context, &mut file)
    }

    fn write_atomic_destination(
        &self,
        destination: &Path,
        write: impl FnOnce(&mut File) -> Result<ContextArchiveSummary, ContextArchiveError>,
    ) -> Result<ContextArchiveSummary, ContextArchiveError> {
        self.limits.validate()?;
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = TempFileBuilder::new()
            .prefix(".neotales-context-export-")
            .tempfile_in(parent)
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        set_unix_mode(temporary.path(), PRIVATE_FILE_MODE)?;
        let summary = write(temporary.as_file_mut())?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        temporary
            .persist(destination)
            .map_err(|error| ContextArchiveError::Io(error.error.to_string()))?;
        Ok(summary)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveFormat {
    Tar,
    Zip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveFile {
    ordinal: usize,
    path: String,
    endpoint: String,
    file_name: String,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InspectedArchive {
    format: ArchiveFormat,
    entry_count: usize,
    total_bytes: u64,
    metadata_ordinal: usize,
    metadata_size: u64,
    files: Vec<ArchiveFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClassifiedPath {
    Metadata,
    TlsDirectory(Option<String>),
    TlsFile { endpoint: String, file_name: String },
}

fn inspect_archive<R: Read + Seek>(
    reader: &mut R,
    limits: ContextArchiveLimits,
) -> Result<InspectedArchive, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut signature = [0_u8; 4];
    let read = read_up_to(reader, &mut signature)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    if read == 0 {
        return Err(ContextArchiveError::UnsupportedFormat);
    }
    if read == signature.len()
        && signature[0] == b'P'
        && signature[1] == b'K'
        && matches!(signature[2], 0x03 | 0x05 | 0x07)
        && matches!(signature[3], 0x04 | 0x06 | 0x08)
    {
        inspect_zip(reader, limits)
    } else {
        inspect_tar(reader, limits)
    }
}

#[allow(clippy::too_many_lines)]
fn inspect_tar<R: Read + Seek>(
    reader: &mut R,
    limits: ContextArchiveLimits,
) -> Result<InspectedArchive, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let archive_length = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;

    let mut archive = tar::Archive::new(&mut *reader);
    archive.set_ignore_zeros(false);
    let mut entry_count = 0_usize;
    let mut ordinal = 0_usize;
    let mut total_bytes = 0_u64;
    let mut metadata_ordinal = None;
    let mut metadata_size = 0_u64;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut last_entry_end = 0_u64;

    {
        let entries = archive
            .entries_with_seek()
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
            entry_count = increment_entry_count(entry_count, limits.max_entries)?;
            ordinal += 1;
            let kind = entry.header().entry_type();
            let is_directory = kind.is_dir();
            if !is_directory && !kind.is_file() {
                let entry_name = display_archive_path(&entry.path_bytes());
                return Err(ContextArchiveError::UnsupportedArchiveEntry {
                    entry: entry_name,
                    kind: tar_entry_kind(kind),
                });
            }
            let path_bytes = entry.path_bytes().into_owned();
            let path = std::str::from_utf8(&path_bytes).map_err(|_| {
                ContextArchiveError::UnsafeArchivePath(
                    String::from_utf8_lossy(&path_bytes).into_owned(),
                )
            })?;
            let classified = classify_archive_path(path, is_directory, limits)?;
            let normalized = normalized_path(path, is_directory, &classified);
            if !seen.insert(normalized.clone()) {
                return Err(ContextArchiveError::DuplicateArchiveEntry(normalized));
            }
            let size = entry.size();
            if is_directory && size != 0 {
                return Err(ContextArchiveError::UnsupportedArchiveEntry {
                    entry: normalized,
                    kind: "directory with file data",
                });
            }
            if !is_directory {
                total_bytes = add_entry_size(total_bytes, size, &normalized, limits)?;
                match classified {
                    ClassifiedPath::Metadata => {
                        metadata_ordinal = Some(ordinal);
                        metadata_size = size;
                    }
                    ClassifiedPath::TlsFile {
                        endpoint,
                        file_name,
                    } => files.push(ArchiveFile {
                        ordinal,
                        path: normalized,
                        endpoint,
                        file_name,
                        size,
                    }),
                    ClassifiedPath::TlsDirectory(_) => unreachable!(),
                }
            }
            let padded_size = size
                .checked_add(511)
                .map(|value| value / 512 * 512)
                .ok_or_else(|| {
                    ContextArchiveError::InvalidArchive("TAR size overflow".to_owned())
                })?;
            let entry_end = entry
                .raw_file_position()
                .checked_add(padded_size)
                .ok_or_else(|| {
                    ContextArchiveError::InvalidArchive("TAR entry offset overflow".to_owned())
                })?;
            last_entry_end = last_entry_end.max(entry_end);
        }
    }
    validate_tar_tail(reader, last_entry_end, archive_length)?;
    let metadata_ordinal = metadata_ordinal.ok_or(ContextArchiveError::MissingMetadata)?;
    Ok(InspectedArchive {
        format: ArchiveFormat::Tar,
        entry_count,
        total_bytes,
        metadata_ordinal,
        metadata_size,
        files,
    })
}

#[allow(clippy::too_many_lines)]
fn preflight_zip_central_directory<R: Read + Seek>(
    reader: &mut R,
    limits: ContextArchiveLimits,
) -> Result<usize, ContextArchiveError> {
    const END_OF_CENTRAL_DIRECTORY: &[u8; 4] = b"PK\x05\x06";
    const CENTRAL_FILE_HEADER: &[u8; 4] = b"PK\x01\x02";
    const MAXIMUM_EOCD_SIZE: u64 = 65_557;
    const CENTRAL_HEADER_SIZE: usize = 46;

    let archive_length = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let tail_length = archive_length.min(MAXIMUM_EOCD_SIZE);
    let tail_size = usize::try_from(tail_length)
        .map_err(|_| ContextArchiveError::InvalidArchive("ZIP is too large to index".to_owned()))?;
    let tail_offset = i64::try_from(tail_length).map_err(|_| {
        ContextArchiveError::InvalidArchive("ZIP end offset is unsupported".to_owned())
    })?;
    reader
        .seek(SeekFrom::End(-tail_offset))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut tail = vec![0_u8; tail_size];
    reader
        .read_exact(&mut tail)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    let relative_eocd = tail
        .windows(END_OF_CENTRAL_DIRECTORY.len())
        .rposition(|window| window == END_OF_CENTRAL_DIRECTORY)
        .ok_or_else(|| ContextArchiveError::InvalidArchive("ZIP EOCD is missing".to_owned()))?;
    if tail.len() - relative_eocd < 22 {
        return Err(ContextArchiveError::InvalidArchive(
            "ZIP EOCD is truncated".to_owned(),
        ));
    }
    let eocd = &tail[relative_eocd..];
    let disk = read_u16(&eocd[4..], "ZIP disk")?;
    let directory_disk = read_u16(&eocd[6..], "ZIP directory disk")?;
    let entries_on_disk = read_u16(&eocd[8..], "ZIP disk entry count")?;
    let entry_count = read_u16(&eocd[10..], "ZIP entry count")?;
    let directory_size = u64::from(read_u32(&eocd[12..], "ZIP directory size")?);
    let directory_offset = u64::from(read_u32(&eocd[16..], "ZIP directory offset")?);
    if disk != 0
        || directory_disk != 0
        || entries_on_disk != entry_count
        || entry_count == u16::MAX
        || directory_size == u64::from(u32::MAX)
        || directory_offset == u64::from(u32::MAX)
    {
        return Err(ContextArchiveError::InvalidArchive(
            "multi-disk and ZIP64 context archives are unsupported".to_owned(),
        ));
    }
    let directory_end = directory_offset
        .checked_add(directory_size)
        .ok_or_else(|| ContextArchiveError::InvalidArchive("ZIP directory overflow".to_owned()))?;
    if directory_end > archive_length {
        return Err(ContextArchiveError::InvalidArchive(
            "ZIP central directory is outside the archive".to_owned(),
        ));
    }
    let entry_count = usize::from(entry_count);
    if entry_count > limits.max_entries {
        return Err(ContextArchiveError::TooManyEntries {
            actual: entry_count,
            limit: limits.max_entries,
        });
    }

    reader
        .seek(SeekFrom::Start(directory_offset))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut seen = BTreeSet::new();
    let mut position = directory_offset;
    for _ in 0..entry_count {
        if position + CENTRAL_HEADER_SIZE as u64 > directory_end {
            return Err(ContextArchiveError::InvalidArchive(
                "ZIP central-directory header is truncated".to_owned(),
            ));
        }
        let mut fixed = [0_u8; CENTRAL_HEADER_SIZE];
        reader
            .read_exact(&mut fixed)
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        if &fixed[..4] != CENTRAL_FILE_HEADER {
            return Err(ContextArchiveError::InvalidArchive(
                "ZIP central-directory header signature is invalid".to_owned(),
            ));
        }
        let name_length = usize::from(read_u16(&fixed[28..], "ZIP name length")?);
        let extra_length = usize::from(read_u16(&fixed[30..], "ZIP extra length")?);
        let comment_length = usize::from(read_u16(&fixed[32..], "ZIP comment length")?);
        if name_length == 0 || name_length > limits.max_path_bytes {
            return Err(ContextArchiveError::UnsafeArchivePath(
                "ZIP entry has an invalid path length".to_owned(),
            ));
        }
        let variable_length = (name_length + extra_length + comment_length) as u64;
        if position + CENTRAL_HEADER_SIZE as u64 + variable_length > directory_end {
            return Err(ContextArchiveError::InvalidArchive(
                "ZIP central-directory entry is truncated".to_owned(),
            ));
        }
        let mut name_bytes = vec![0_u8; name_length];
        reader
            .read_exact(&mut name_bytes)
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        let name = std::str::from_utf8(&name_bytes).map_err(|_| {
            ContextArchiveError::UnsafeArchivePath(
                String::from_utf8_lossy(&name_bytes).into_owned(),
            )
        })?;
        let is_directory = name.ends_with('/');
        let classified = classify_archive_path(name, is_directory, limits)?;
        let normalized = normalized_path(name, is_directory, &classified);
        if !seen.insert(normalized.clone()) {
            return Err(ContextArchiveError::DuplicateArchiveEntry(normalized));
        }
        position += CENTRAL_HEADER_SIZE as u64 + variable_length;
        reader
            .seek(SeekFrom::Start(position))
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    }
    if position != directory_end {
        return Err(ContextArchiveError::InvalidArchive(
            "ZIP central directory has undeclared records".to_owned(),
        ));
    }
    Ok(entry_count)
}

fn read_u16(bytes: &[u8], description: &str) -> Result<u16, ContextArchiveError> {
    let bytes: [u8; 2] = bytes
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ContextArchiveError::InvalidArchive(format!("{description} is truncated"))
        })?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(bytes: &[u8], description: &str) -> Result<u32, ContextArchiveError> {
    let bytes: [u8; 4] = bytes
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ContextArchiveError::InvalidArchive(format!("{description} is truncated"))
        })?;
    Ok(u32::from_le_bytes(bytes))
}

#[allow(clippy::too_many_lines)]
fn inspect_zip<R: Read + Seek>(
    reader: &mut R,
    limits: ContextArchiveLimits,
) -> Result<InspectedArchive, ContextArchiveError> {
    let declared_entries = preflight_zip_central_directory(reader, limits)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut archive = zip::ZipArchive::new(&mut *reader)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    if archive.len() != declared_entries {
        return Err(ContextArchiveError::InvalidArchive(
            "ZIP central-directory entry count is inconsistent".to_owned(),
        ));
    }
    if archive.len() > limits.max_entries {
        return Err(ContextArchiveError::TooManyEntries {
            actual: archive.len(),
            limit: limits.max_entries,
        });
    }

    let mut total_bytes = 0_u64;
    let mut total_compressed = 0_u64;
    let mut metadata_ordinal = None;
    let mut metadata_size = 0_u64;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for ordinal in 0..archive.len() {
        let entry = archive
            .by_index(ordinal)
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        let name = entry
            .name()
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?
            .into_owned();
        let is_directory = entry.is_dir();
        if entry.encrypted() {
            return Err(ContextArchiveError::UnsupportedArchiveEntry {
                entry: name,
                kind: "encrypted ZIP entry",
            });
        }
        validate_zip_entry_type(&entry, &name, is_directory)?;
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(ContextArchiveError::UnsupportedArchiveEntry {
                entry: name,
                kind: "ZIP compression method",
            });
        }
        let classified = classify_archive_path(&name, is_directory, limits)?;
        let normalized = normalized_path(&name, is_directory, &classified);
        if !seen.insert(normalized.clone()) {
            return Err(ContextArchiveError::DuplicateArchiveEntry(normalized));
        }
        let size = entry.size();
        if is_directory && size != 0 {
            return Err(ContextArchiveError::UnsupportedArchiveEntry {
                entry: normalized,
                kind: "directory with file data",
            });
        }
        let compressed_size = entry.compressed_size();
        total_compressed = total_compressed
            .checked_add(compressed_size)
            .ok_or_else(|| ContextArchiveError::InvalidArchive("ZIP size overflow".to_owned()))?;
        if total_compressed > limits.max_archive_bytes {
            return Err(ContextArchiveError::ArchiveTooLarge {
                actual: total_compressed,
                limit: limits.max_archive_bytes,
            });
        }
        if !is_directory {
            if compressed_size == 0 && size != 0 {
                return Err(ContextArchiveError::CompressionRatioExceeded {
                    entry: normalized.clone(),
                    limit: limits.max_compression_ratio,
                });
            }
            if size > compressed_size.saturating_mul(limits.max_compression_ratio) {
                return Err(ContextArchiveError::CompressionRatioExceeded {
                    entry: normalized.clone(),
                    limit: limits.max_compression_ratio,
                });
            }
            total_bytes = add_entry_size(total_bytes, size, &normalized, limits)?;
            match classified {
                ClassifiedPath::Metadata => {
                    metadata_ordinal = Some(ordinal);
                    metadata_size = size;
                }
                ClassifiedPath::TlsFile {
                    endpoint,
                    file_name,
                } => files.push(ArchiveFile {
                    ordinal,
                    path: normalized,
                    endpoint,
                    file_name,
                    size,
                }),
                ClassifiedPath::TlsDirectory(_) => unreachable!(),
            }
        }
    }
    let metadata_ordinal = metadata_ordinal.ok_or(ContextArchiveError::MissingMetadata)?;
    let entry_count = archive.len();
    drop(archive);
    Ok(InspectedArchive {
        format: ArchiveFormat::Zip,
        entry_count,
        total_bytes,
        metadata_ordinal,
        metadata_size,
        files,
    })
}

fn validate_zip_entry_type<R: Read + ?Sized>(
    entry: &zip::read::ZipFile<'_, R>,
    name: &str,
    is_directory: bool,
) -> Result<(), ContextArchiveError> {
    let file_type = entry.unix_mode().map(|mode| mode & 0o170_000);
    if entry.is_symlink() || matches!(file_type, Some(0o120_000 | 0o060_000)) {
        return Err(ContextArchiveError::UnsupportedArchiveEntry {
            entry: name.to_owned(),
            kind: "link",
        });
    }
    let expected = if is_directory { 0o040_000 } else { 0o100_000 };
    if file_type.is_some_and(|file_type| file_type != 0 && file_type != expected) {
        return Err(ContextArchiveError::UnsupportedArchiveEntry {
            entry: name.to_owned(),
            kind: "special ZIP entry",
        });
    }
    Ok(())
}

fn read_metadata<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    limits: ContextArchiveLimits,
) -> Result<Vec<u8>, ContextArchiveError> {
    match inspected.format {
        ArchiveFormat::Tar => read_tar_metadata(reader, inspected, limits),
        ArchiveFormat::Zip => read_zip_metadata(reader, inspected, limits),
    }
}

fn read_tar_metadata<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    limits: ContextArchiveLimits,
) -> Result<Vec<u8>, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut archive = tar::Archive::new(&mut *reader);
    archive.set_ignore_zeros(false);
    let entries = archive
        .entries()
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    for (ordinal, entry) in entries.enumerate() {
        let mut entry =
            entry.map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        if ordinal + 1 == inspected.metadata_ordinal {
            return read_entry_to_vec(
                &mut entry,
                inspected.metadata_size,
                "meta.json",
                limits.max_entry_bytes,
            );
        }
    }
    Err(ContextArchiveError::MissingMetadata)
}

fn read_zip_metadata<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    limits: ContextArchiveLimits,
) -> Result<Vec<u8>, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut archive = zip::ZipArchive::new(&mut *reader)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    let mut entry = archive
        .by_index(inspected.metadata_ordinal)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    read_entry_to_vec(
        &mut entry,
        inspected.metadata_size,
        "meta.json",
        limits.max_entry_bytes,
    )
}

fn extract_tls_files<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    destination: &Path,
    mut total_bytes: u64,
    limits: ContextArchiveLimits,
) -> Result<u64, ContextArchiveError> {
    if inspected.files.is_empty() {
        return Ok(total_bytes);
    }
    match inspected.format {
        ArchiveFormat::Tar => {
            extract_tar_tls(reader, inspected, destination, &mut total_bytes, limits)
        }
        ArchiveFormat::Zip => {
            extract_zip_tls(reader, inspected, destination, &mut total_bytes, limits)
        }
    }
}

fn extract_tar_tls<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    destination: &Path,
    total_bytes: &mut u64,
    limits: ContextArchiveLimits,
) -> Result<u64, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut archive = tar::Archive::new(&mut *reader);
    archive.set_ignore_zeros(false);
    let entries = archive
        .entries()
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    let files = inspected
        .files
        .iter()
        .map(|file| (file.ordinal, file))
        .collect::<BTreeMap<_, _>>();
    let mut extracted = 0_usize;
    for (ordinal, entry) in entries.enumerate() {
        let mut entry =
            entry.map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        let Some(file) = files.get(&(ordinal + 1)) else {
            continue;
        };
        let path = destination.join(&file.endpoint).join(&file.file_name);
        let parent = path.parent().expect("validated TLS file has a parent");
        fs::create_dir_all(parent).map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        set_unix_mode(parent, PRIVATE_DIRECTORY_MODE)?;
        let mode = if file.file_name == "key.pem" {
            PRIVATE_FILE_MODE
        } else {
            PUBLIC_FILE_MODE
        };
        let mut output = create_private_file(&path, mode)?;
        let copied = copy_entry(
            &mut entry,
            &mut output,
            file.size,
            &file.path,
            *total_bytes,
            limits,
        )?;
        set_unix_mode(&path, mode)?;
        *total_bytes = copied;
        extracted += 1;
    }
    if extracted != inspected.files.len() {
        return Err(ContextArchiveError::InvalidArchive(
            "TAR entries changed while extracting".to_owned(),
        ));
    }
    Ok(*total_bytes)
}

fn extract_zip_tls<R: Read + Seek>(
    reader: &mut R,
    inspected: &InspectedArchive,
    destination: &Path,
    total_bytes: &mut u64,
    limits: ContextArchiveLimits,
) -> Result<u64, ContextArchiveError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut archive = zip::ZipArchive::new(&mut *reader)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    for file in &inspected.files {
        let mut entry = archive
            .by_index(file.ordinal)
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        let path = destination.join(&file.endpoint).join(&file.file_name);
        fs::create_dir_all(path.parent().expect("validated TLS file has a parent"))
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        set_unix_mode(
            path.parent().expect("validated TLS file has a parent"),
            PRIVATE_DIRECTORY_MODE,
        )?;
        let mode = if file.file_name == "key.pem" {
            PRIVATE_FILE_MODE
        } else {
            PUBLIC_FILE_MODE
        };
        let mut output = create_private_file(&path, mode)?;
        *total_bytes = copy_entry(
            &mut entry,
            &mut output,
            file.size,
            &file.path,
            *total_bytes,
            limits,
        )?;
        set_unix_mode(&path, mode)?;
    }
    Ok(*total_bytes)
}

fn copy_entry<R: Read>(
    input: &mut R,
    output: &mut impl Write,
    expected_size: u64,
    name: &str,
    total_before: u64,
    limits: ContextArchiveLimits,
) -> Result<u64, ContextArchiveError> {
    let mut entry_bytes = 0_u64;
    let mut total_bytes = total_before;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
        if read == 0 {
            break;
        }
        entry_bytes = entry_bytes
            .checked_add(read as u64)
            .ok_or_else(|| ContextArchiveError::InvalidArchive("entry size overflow".to_owned()))?;
        if entry_bytes > expected_size {
            return Err(ContextArchiveError::InvalidArchive(format!(
                "entry {name} produced more data than declared"
            )));
        }
        if entry_bytes > limits.max_entry_bytes {
            return Err(ContextArchiveError::EntryTooLarge {
                entry: name.to_owned(),
                actual: entry_bytes,
                limit: limits.max_entry_bytes,
            });
        }
        total_bytes = total_bytes
            .checked_add(read as u64)
            .ok_or_else(|| ContextArchiveError::InvalidArchive("total size overflow".to_owned()))?;
        if total_bytes > limits.max_total_bytes {
            return Err(ContextArchiveError::TotalSizeExceeded {
                limit: limits.max_total_bytes,
            });
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    }
    if entry_bytes != expected_size {
        return Err(ContextArchiveError::InvalidArchive(format!(
            "entry {name} declared {expected_size} bytes but produced {entry_bytes}"
        )));
    }
    Ok(total_bytes)
}

fn read_entry_to_vec<R: Read>(
    input: &mut R,
    expected_size: u64,
    name: &str,
    max_entry_bytes: u64,
) -> Result<Vec<u8>, ContextArchiveError> {
    if expected_size > max_entry_bytes {
        return Err(ContextArchiveError::EntryTooLarge {
            entry: name.to_owned(),
            actual: expected_size,
            limit: max_entry_bytes,
        });
    }
    let capacity = usize::try_from(expected_size).map_err(|_| {
        ContextArchiveError::InvalidArchive("entry is too large to index".to_owned())
    })?;
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).map_err(|_| {
        ContextArchiveError::InvalidArchive("unable to reserve metadata buffer".to_owned())
    })?;
    let mut limited = BoundedReader::new(input, expected_size, name, max_entry_bytes)?;
    limited
        .read_to_end(&mut output)
        .map_err(|error| ContextArchiveError::InvalidArchive(error.to_string()))?;
    if output.len() as u64 != expected_size {
        return Err(ContextArchiveError::InvalidArchive(format!(
            "entry {name} has an inconsistent size"
        )));
    }
    Ok(output)
}

fn classify_archive_path(
    name: &str,
    is_directory: bool,
    limits: ContextArchiveLimits,
) -> Result<ClassifiedPath, ContextArchiveError> {
    if name.is_empty() || name.len() > limits.max_path_bytes {
        return Err(ContextArchiveError::UnsafeArchivePath(name.to_owned()));
    }
    if name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
    {
        return Err(ContextArchiveError::UnsafeArchivePath(name.to_owned()));
    }
    if Path::new(name).is_absolute() || has_drive_prefix(name) {
        return Err(ContextArchiveError::UnsafeArchivePath(name.to_owned()));
    }

    let logical = if is_directory {
        let logical = name.strip_suffix('/').unwrap_or(name);
        if logical.is_empty() || logical.ends_with('/') {
            return Err(ContextArchiveError::UnsafeArchivePath(name.to_owned()));
        }
        logical
    } else {
        name
    };
    let parts = logical.split('/').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(ContextArchiveError::UnsafeArchivePath(name.to_owned()));
    }
    if is_directory {
        return match parts.as_slice() {
            ["tls"] => Ok(ClassifiedPath::TlsDirectory(None)),
            ["tls", endpoint] => {
                validate_archive_segment(endpoint, name, limits)?;
                Ok(ClassifiedPath::TlsDirectory(Some((*endpoint).to_owned())))
            }
            _ => Err(ContextArchiveError::UnsafeArchivePath(name.to_owned())),
        };
    }
    match parts.as_slice() {
        ["meta.json"] => Ok(ClassifiedPath::Metadata),
        ["tls", endpoint, file_name] => {
            validate_archive_segment(endpoint, name, limits)?;
            validate_archive_segment(file_name, name, limits)?;
            Ok(ClassifiedPath::TlsFile {
                endpoint: (*endpoint).to_owned(),
                file_name: (*file_name).to_owned(),
            })
        }
        _ => Err(ContextArchiveError::UnsafeArchivePath(name.to_owned())),
    }
}

fn normalized_path(name: &str, is_directory: bool, classified: &ClassifiedPath) -> String {
    if let ClassifiedPath::TlsFile {
        endpoint,
        file_name,
    } = classified
    {
        return format!("tls/{endpoint}/{file_name}");
    }
    if is_directory {
        return name.strip_suffix('/').unwrap_or(name).to_owned();
    }
    name.to_owned()
}

fn validate_archive_segment(
    segment: &str,
    entry: &str,
    limits: ContextArchiveLimits,
) -> Result<(), ContextArchiveError> {
    if segment.is_empty()
        || segment.len() > 255
        || segment.len() > limits.max_path_bytes
        || segment == "."
        || segment == ".."
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment.contains(':')
        || segment.chars().any(char::is_control)
    {
        return Err(ContextArchiveError::UnsafeArchivePath(entry.to_owned()));
    }
    Ok(())
}

fn has_drive_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn add_entry_size(
    current: u64,
    size: u64,
    name: &str,
    limits: ContextArchiveLimits,
) -> Result<u64, ContextArchiveError> {
    if size > limits.max_entry_bytes {
        return Err(ContextArchiveError::EntryTooLarge {
            entry: name.to_owned(),
            actual: size,
            limit: limits.max_entry_bytes,
        });
    }
    let total = current
        .checked_add(size)
        .ok_or_else(|| ContextArchiveError::InvalidArchive("total size overflow".to_owned()))?;
    if total > limits.max_total_bytes {
        return Err(ContextArchiveError::TotalSizeExceeded {
            limit: limits.max_total_bytes,
        });
    }
    Ok(total)
}

fn increment_entry_count(current: usize, limit: usize) -> Result<usize, ContextArchiveError> {
    let count = current
        .checked_add(1)
        .ok_or_else(|| ContextArchiveError::InvalidArchive("entry count overflow".to_owned()))?;
    if count > limit {
        return Err(ContextArchiveError::TooManyEntries {
            actual: count,
            limit,
        });
    }
    Ok(count)
}

fn validate_tar_tail<R: Read + Seek>(
    reader: &mut R,
    last_entry_end: u64,
    archive_length: u64,
) -> Result<(), ContextArchiveError> {
    if last_entry_end > archive_length {
        return Err(ContextArchiveError::InvalidArchive(
            "TAR entry extends beyond the archive".to_owned(),
        ));
    }
    reader
        .seek(SeekFrom::Start(last_entry_end))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    let mut remaining = archive_length - last_entry_end;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(COPY_BUFFER_SIZE as u64))
            .expect("bounded copy buffer length fits usize");
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        if read == 0 || buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(ContextArchiveError::InvalidArchive(
                "TAR contains trailing or concatenated data".to_owned(),
            ));
        }
        remaining -= read as u64;
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    Ok(())
}

fn tar_entry_kind(kind: tar::EntryType) -> &'static str {
    if kind.is_symlink() {
        "symbolic link"
    } else if kind.is_hard_link() {
        "hard link"
    } else if kind.is_character_special() {
        "character device"
    } else if kind.is_block_special() {
        "block device"
    } else if kind.is_fifo() {
        "FIFO"
    } else {
        "special TAR entry"
    }
}

fn display_archive_path(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

#[derive(Clone, Debug)]
enum ExportPayload {
    Directory,
    Bytes(Vec<u8>),
    File { path: PathBuf, size: u64 },
}

#[derive(Clone, Debug)]
struct ExportEntry {
    archive_name: String,
    payload: ExportPayload,
    mode: u32,
}

#[derive(Clone, Debug)]
struct ExportSource {
    entries: Vec<ExportEntry>,
    summary: ContextArchiveSummary,
}

fn collect_export_source(
    root: &Path,
    context: &str,
    limits: ContextArchiveLimits,
) -> Result<ExportSource, ContextArchiveError> {
    let hash = context_hash(context);
    let metadata_directory = checked_existing_directory(
        &root.join("contexts/meta").join(&hash),
        "context metadata directory",
    )?;
    let metadata_path = metadata_directory.join("meta.json");
    let (mut metadata_file, metadata_len) = checked_source_file(&metadata_path, "meta.json")?;
    let raw_metadata = read_source_bounded(
        &mut metadata_file,
        metadata_len,
        "meta.json",
        limits.max_entry_bytes,
    )?;
    let (metadata_bytes, required_tls) = prepare_metadata(&raw_metadata, context)?;
    let metadata_size = metadata_bytes.len() as u64;
    add_entry_size(0, metadata_size, "meta.json", limits)?;

    let tls_root_path = root.join("contexts/tls").join(&hash);
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut available_tls = BTreeSet::new();
    let mut total_bytes = metadata_size;
    if fs::symlink_metadata(&tls_root_path).is_ok() {
        let tls_root = checked_existing_directory(&tls_root_path, "context TLS directory")?;
        directories.push(ExportEntry {
            archive_name: "tls".to_owned(),
            payload: ExportPayload::Directory,
            mode: PRIVATE_DIRECTORY_MODE,
        });
        let mut endpoints = read_directory_sorted(&tls_root)?;
        for endpoint_path in endpoints.drain(..) {
            let endpoint = utf8_file_name(&endpoint_path, "TLS endpoint")?;
            validate_archive_segment(&endpoint, &endpoint, limits)?;
            let endpoint_directory =
                checked_existing_directory(&endpoint_path, "TLS endpoint directory")?;
            directories.push(ExportEntry {
                archive_name: format!("tls/{endpoint}"),
                payload: ExportPayload::Directory,
                mode: PRIVATE_DIRECTORY_MODE,
            });
            let mut endpoint_files = read_directory_sorted(&endpoint_directory)?;
            for file_path in endpoint_files.drain(..) {
                let file_name = utf8_file_name(&file_path, "TLS file")?;
                validate_archive_segment(&file_name, &file_name, limits)?;
                let archive_name = format!("tls/{endpoint}/{file_name}");
                let (_file, size) = checked_source_file(&file_path, &archive_name)?;
                total_bytes = add_entry_size(total_bytes, size, &archive_name, limits)?;
                if endpoint == "docker" {
                    available_tls.insert(file_name.clone());
                }
                files.push(ExportEntry {
                    archive_name,
                    payload: ExportPayload::File {
                        path: file_path,
                        size,
                    },
                    mode: if file_name == "key.pem" {
                        PRIVATE_FILE_MODE
                    } else {
                        PUBLIC_FILE_MODE
                    },
                });
            }
        }
    }
    validate_required_tls_set(&available_tls, &required_tls)?;

    let mut entries = Vec::with_capacity(directories.len() + files.len() + 1);
    let mut entry_count = increment_entry_count(0, limits.max_entries)?;
    entries.push(ExportEntry {
        archive_name: "meta.json".to_owned(),
        payload: ExportPayload::Bytes(metadata_bytes),
        mode: PUBLIC_FILE_MODE,
    });
    for directory in directories {
        entry_count = increment_entry_count(entry_count, limits.max_entries)?;
        entries.push(directory);
    }
    for file in files {
        entry_count = increment_entry_count(entry_count, limits.max_entries)?;
        entries.push(file);
    }
    Ok(ExportSource {
        entries,
        summary: ContextArchiveSummary {
            entry_count,
            uncompressed_bytes: total_bytes,
        },
    })
}

fn utf8_file_name(path: &Path, kind: &str) -> Result<String, ContextArchiveError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            ContextArchiveError::UnsafeConfigurationPath(format!("{kind} at {}", path.display()))
        })
}

fn read_directory_sorted(directory: &Path) -> Result<Vec<PathBuf>, ContextArchiveError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|error| ContextArchiveError::Io(error.to_string()))?
    {
        let entry = entry.map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        entries.push(entry.path());
    }
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(entries)
}

fn checked_source_file(
    path: &Path,
    archive_name: &str,
) -> Result<(File, u64), ContextArchiveError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ContextArchiveError::Io(format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(ContextArchiveError::UnsupportedArchiveEntry {
            entry: archive_name.to_owned(),
            kind: "filesystem link or special entry",
        });
    }
    reject_hard_link(&metadata, archive_name)?;
    let file = File::open(path)
        .map_err(|error| ContextArchiveError::Io(format!("{}: {error}", path.display())))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    if !opened_metadata.file_type().is_file() || opened_metadata.len() != metadata.len() {
        return Err(ContextArchiveError::InvalidArchive(format!(
            "source entry {archive_name} changed while opening"
        )));
    }
    Ok((file, opened_metadata.len()))
}

fn read_source_bounded(
    input: &mut impl Read,
    expected_size: u64,
    name: &str,
    max_entry_bytes: u64,
) -> Result<Vec<u8>, ContextArchiveError> {
    let capacity = usize::try_from(expected_size)
        .map_err(|_| ContextArchiveError::InvalidArchive("source entry is too large".to_owned()))?;
    if expected_size > max_entry_bytes {
        return Err(ContextArchiveError::EntryTooLarge {
            entry: name.to_owned(),
            actual: expected_size,
            limit: max_entry_bytes,
        });
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        ContextArchiveError::InvalidArchive("unable to reserve source buffer".to_owned())
    })?;
    let mut reader = BoundedReader::new(input, expected_size, name, max_entry_bytes)?;
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    if bytes.len() as u64 != expected_size {
        return Err(ContextArchiveError::InvalidArchive(format!(
            "source entry {name} changed while reading"
        )));
    }
    Ok(bytes)
}

fn prepare_metadata(
    raw: &[u8],
    context: &str,
) -> Result<(Vec<u8>, BTreeSet<String>), ContextArchiveError> {
    parse_prepared_metadata(raw, context)
}

fn parse_prepared_metadata(
    raw: &[u8],
    context: &str,
) -> Result<(Vec<u8>, BTreeSet<String>), ContextArchiveError> {
    let mut root = serde_json::from_slice::<Value>(raw)
        .map_err(|error| ContextArchiveError::InvalidMetadata(error.to_string()))?;
    let object = root.as_object_mut().ok_or_else(|| {
        ContextArchiveError::InvalidMetadata("metadata must be a JSON object".to_owned())
    })?;
    promote(object, "name", "Name");
    promote(object, "metadata", "Metadata");
    promote(object, "endpoints", "Endpoints");
    validate_context_name(context)
        .map_err(|error| ContextArchiveError::InvalidMetadata(error.to_string()))?;
    object.insert("Name".to_owned(), Value::String(context.to_owned()));

    let endpoints = object
        .get_mut("Endpoints")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ContextArchiveError::InvalidMetadata("metadata has no Endpoints object".to_owned())
        })?;
    let docker = endpoints
        .get_mut("docker")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ContextArchiveError::InvalidMetadata("metadata has no docker endpoint".to_owned())
        })?;
    promote(docker, "host", "Host");
    promote(docker, "skiptlsverify", "SkipTLSVerify");
    let host = docker.get("Host").and_then(Value::as_str).ok_or_else(|| {
        ContextArchiveError::InvalidMetadata("docker endpoint has no Host".to_owned())
    })?;
    let endpoint = Endpoint::parse(host).map_err(|error| {
        ContextArchiveError::InvalidMetadata(format!("docker endpoint is invalid: {error}"))
    })?;
    if docker
        .get("SkipTLSVerify")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ContextArchiveError::InvalidMetadata(
            "SkipTLSVerify contexts are not supported".to_owned(),
        ));
    }

    let required = match object.get("TLSMaterial") {
        None | Some(Value::Null) => BTreeSet::new(),
        Some(value) => {
            let tls = value.as_object().ok_or_else(|| {
                ContextArchiveError::InvalidMetadata("TLSMaterial must be an object".to_owned())
            })?;
            let docker = tls.get("docker").and_then(Value::as_array).ok_or_else(|| {
                ContextArchiveError::InvalidMetadata(
                    "TLSMaterial has no docker material list".to_owned(),
                )
            })?;
            let first = docker.first().and_then(Value::as_object).ok_or_else(|| {
                ContextArchiveError::InvalidMetadata("TLSMaterial docker list is empty".to_owned())
            })?;
            let mut required = BTreeSet::new();
            for key in ["CA", "Cert", "Key"] {
                let value = first.get(key).and_then(Value::as_str).ok_or_else(|| {
                    ContextArchiveError::InvalidMetadata(format!(
                        "TLSMaterial docker entry has no {key}"
                    ))
                })?;
                validate_metadata_segment(value)?;
                required.insert(value.to_owned());
            }
            required
        }
    };
    if matches!(endpoint, Endpoint::Https { .. }) && required.is_empty() {
        return Err(ContextArchiveError::InvalidMetadata(
            "HTTPS endpoint has no TLS material".to_owned(),
        ));
    }

    let name = object
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or("context")
        .to_owned();
    validate_context_name(&name)
        .map_err(|error| ContextArchiveError::InvalidMetadata(error.to_string()))?;
    object.insert("Name".to_owned(), Value::String(name));
    let mut bytes = serde_json::to_vec_pretty(&root)
        .map_err(|error| ContextArchiveError::InvalidMetadata(error.to_string()))?;
    bytes.push(b'\n');
    Ok((bytes, required))
}

fn validate_metadata_segment(value: &str) -> Result<(), ContextArchiveError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || value.len() > 255
    {
        return Err(ContextArchiveError::InvalidMetadata(format!(
            "TLS material path {value} is unsafe"
        )));
    }
    Ok(())
}

fn validate_required_tls(
    inspected: &InspectedArchive,
    required: &BTreeSet<String>,
) -> Result<(), ContextArchiveError> {
    let available = inspected
        .files
        .iter()
        .filter(|file| file.endpoint == "docker")
        .map(|file| file.file_name.clone())
        .collect::<BTreeSet<_>>();
    validate_required_tls_set(&available, required)
}

fn validate_required_tls_set(
    available: &BTreeSet<String>,
    required: &BTreeSet<String>,
) -> Result<(), ContextArchiveError> {
    if required
        .iter()
        .any(|required| !available.contains(required))
    {
        return Err(ContextArchiveError::InvalidMetadata(
            "TLS material references a file missing from the archive".to_owned(),
        ));
    }
    Ok(())
}

fn promote(object: &mut Map<String, Value>, lower: &str, canonical: &str) {
    if object.contains_key(canonical) {
        return;
    }
    if let Some(value) = object.remove(lower) {
        object.insert(canonical.to_owned(), value);
    }
}

fn write_tar<W: Write>(
    source: &ExportSource,
    destination: &mut W,
) -> Result<(), ContextArchiveError> {
    let mut archive = tar::Builder::new(destination);
    for entry in &source.entries {
        let mut header = tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header
            .set_path(&entry.archive_name)
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        match &entry.payload {
            ExportPayload::Directory => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(entry.mode);
                header.set_size(0);
                header.set_cksum();
                archive
                    .append_data(&mut header, format!("{}/", entry.archive_name), io::empty())
                    .map_err(map_output_error)?;
            }
            ExportPayload::Bytes(bytes) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(entry.mode);
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                archive
                    .append(&header, io::Cursor::new(bytes))
                    .map_err(map_output_error)?;
            }
            ExportPayload::File { path, size } => {
                let mut input =
                    File::open(path).map_err(|error| ContextArchiveError::Io(error.to_string()))?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(entry.mode);
                header.set_size(*size);
                header.set_cksum();
                archive
                    .append(&header, &mut input)
                    .map_err(map_output_error)?;
            }
        }
    }
    archive.finish().map_err(map_output_error)?;
    Ok(())
}

fn write_zip<W: Write + Seek>(
    source: &ExportSource,
    destination: W,
    limits: ContextArchiveLimits,
) -> Result<(), ContextArchiveError> {
    let destination = BoundedWriter::new(destination, limits.max_archive_bytes);
    let mut archive = zip::ZipWriter::new(destination);
    let file_options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default());
    for entry in &source.entries {
        match &entry.payload {
            ExportPayload::Directory => archive
                .add_directory(
                    format!("{}/", entry.archive_name),
                    file_options.unix_permissions(entry.mode),
                )
                .map_err(map_zip_output_error)?,
            ExportPayload::Bytes(bytes) => {
                archive
                    .start_file(
                        &entry.archive_name,
                        file_options.unix_permissions(entry.mode),
                    )
                    .map_err(map_zip_output_error)?;
                archive.write_all(bytes).map_err(map_output_error)?;
            }
            ExportPayload::File { path, size } => {
                let mut input =
                    File::open(path).map_err(|error| ContextArchiveError::Io(error.to_string()))?;
                archive
                    .start_file(
                        &entry.archive_name,
                        file_options.unix_permissions(entry.mode),
                    )
                    .map_err(map_zip_output_error)?;
                let copied =
                    copy_export_file(&mut input, &mut archive, *size, &entry.archive_name)?;
                if copied != *size {
                    return Err(ContextArchiveError::InvalidArchive(format!(
                        "source entry {} changed while exporting",
                        entry.archive_name
                    )));
                }
            }
        }
    }
    let mut destination = archive.finish().map_err(map_zip_output_error)?;
    destination.flush().map_err(map_output_error)
}

fn copy_export_file(
    input: &mut impl Read,
    output: &mut impl Write,
    expected_size: u64,
    name: &str,
) -> Result<u64, ContextArchiveError> {
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            ContextArchiveError::InvalidArchive("export size overflow".to_owned())
        })?;
        if copied > expected_size {
            return Err(ContextArchiveError::InvalidArchive(format!(
                "source entry {name} grew while exporting"
            )));
        }
        output
            .write_all(&buffer[..read])
            .map_err(map_output_error)?;
    }
    Ok(copied)
}

fn prepare_import_root(config_directory: &Path) -> Result<PathBuf, ContextArchiveError> {
    match fs::symlink_metadata(config_directory) {
        Ok(metadata) if is_link_or_reparse_point(&metadata) => {
            return Err(ContextArchiveError::UnsafeConfigurationPath(
                config_directory.display().to_string(),
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ContextArchiveError::UnsafeConfigurationPath(
                config_directory.display().to_string(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(config_directory)
                .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        }
        Err(error) => {
            return Err(ContextArchiveError::Io(format!(
                "{}: {error}",
                config_directory.display()
            )));
        }
    }
    let root = config_directory
        .canonicalize()
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    ensure_real_directory(&root, "contexts", true)?;
    ensure_real_directory(&root.join("contexts"), "meta", true)?;
    ensure_real_directory(&root.join("contexts"), "tls", true)?;
    Ok(root)
}

fn existing_configuration_root(config_directory: &Path) -> Result<PathBuf, ContextArchiveError> {
    let metadata = fs::symlink_metadata(config_directory).map_err(|_| {
        ContextArchiveError::ContextNotFound(config_directory.display().to_string())
    })?;
    if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(ContextArchiveError::UnsafeConfigurationPath(
            config_directory.display().to_string(),
        ));
    }
    let root = config_directory
        .canonicalize()
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    ensure_real_directory(&root, "contexts", false)?;
    ensure_real_directory(&root.join("contexts"), "meta", false)?;
    ensure_optional_real_directory(&root.join("contexts"), "tls")?;
    Ok(root)
}

fn ensure_real_directory(
    parent: &Path,
    name: &str,
    create: bool,
) -> Result<(), ContextArchiveError> {
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if is_link_or_reparse_point(&metadata) || !metadata.is_dir() => Err(
            ContextArchiveError::UnsafeConfigurationPath(path.display().to_string()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            fs::create_dir(&path).map_err(|error| ContextArchiveError::Io(error.to_string()))?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
            if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
                return Err(ContextArchiveError::UnsafeConfigurationPath(
                    path.display().to_string(),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(
            ContextArchiveError::ContextNotFound(path.display().to_string()),
        ),
        Err(error) => Err(ContextArchiveError::Io(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

fn ensure_optional_real_directory(parent: &Path, name: &str) -> Result<(), ContextArchiveError> {
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if is_link_or_reparse_point(&metadata) || !metadata.is_dir() => Err(
            ContextArchiveError::UnsafeConfigurationPath(path.display().to_string()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ContextArchiveError::Io(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

fn checked_existing_directory(
    path: &Path,
    description: &str,
) -> Result<PathBuf, ContextArchiveError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ContextArchiveError::Io(format!("{description}: {error}")))?;
    if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(ContextArchiveError::UnsafeConfigurationPath(
            path.display().to_string(),
        ));
    }
    path.canonicalize()
        .map_err(|error| ContextArchiveError::Io(error.to_string()))
}

fn ensure_import_target_available(
    context: &str,
    metadata: &Path,
    tls: &Path,
) -> Result<(), ContextArchiveError> {
    if path_exists(metadata) || path_exists(tls) {
        return Err(ContextArchiveError::ContextAlreadyExists(
            context.to_owned(),
        ));
    }
    Ok(())
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn publish_import(
    context: &str,
    final_metadata: &Path,
    final_tls: &Path,
    staged_metadata: &Path,
    staged_tls: &Path,
    has_tls: bool,
) -> Result<(), ContextArchiveError> {
    ensure_import_target_available(context, final_metadata, final_tls)?;
    let mut tls_published = false;
    if has_tls {
        fs::rename(staged_tls, final_tls)
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        tls_published = true;
    }
    if let Err(error) = fs::rename(staged_metadata, final_metadata) {
        if tls_published {
            let _ = fs::remove_dir_all(final_tls);
        }
        return Err(ContextArchiveError::Io(error.to_string()));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), ContextArchiveError> {
    fs::create_dir_all(path).map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    set_unix_mode(path, PRIVATE_DIRECTORY_MODE)
}

fn create_private_file(path: &Path, mode: u32) -> Result<File, ContextArchiveError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let file = options
        .open(path)
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    set_unix_mode(path, mode)?;
    Ok(file)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ContextArchiveError> {
    let mut file = create_private_file(path, mode)?;
    file.write_all(bytes)
        .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    set_unix_mode(path, mode)
}

#[cfg_attr(
    not(unix),
    allow(
        clippy::unnecessary_wraps,
        reason = "Windows has no mode bits; the Result stays so the unix body and its callers share one signature"
    )
)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<(), ContextArchiveError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg_attr(
    not(unix),
    allow(
        clippy::unnecessary_wraps,
        reason = "Windows has no link count; the Result stays so the unix body and its callers share one signature"
    )
)]
fn reject_hard_link(metadata: &fs::Metadata, entry: &str) -> Result<(), ContextArchiveError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(ContextArchiveError::UnsupportedArchiveEntry {
                entry: entry.to_owned(),
                kind: "hard-linked file",
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, entry);
    Ok(())
}

fn validate_context_name(name: &str) -> Result<(), ContextArchiveError> {
    if name == "default" {
        return Err(ContextArchiveError::InvalidContextName(
            "default is reserved".to_owned(),
        ));
    }
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return Err(ContextArchiveError::InvalidContextName(
            "name cannot be empty".to_owned(),
        ));
    };
    if name.len() < 2 || name.len() > 256 || !first.is_ascii_alphanumeric() {
        return Err(ContextArchiveError::InvalidContextName(name.to_owned()));
    }
    if characters.any(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '+' | '-'))
    }) {
        return Err(ContextArchiveError::InvalidContextName(name.to_owned()));
    }
    Ok(())
}

struct BoundedReader<'a, R> {
    input: &'a mut R,
    remaining: u64,
}

impl<'a, R> BoundedReader<'a, R> {
    fn new(
        input: &'a mut R,
        remaining: u64,
        name: &str,
        maximum: u64,
    ) -> Result<Self, ContextArchiveError> {
        if remaining > maximum {
            return Err(ContextArchiveError::EntryTooLarge {
                entry: name.to_owned(),
                actual: remaining,
                limit: maximum,
            });
        }
        Ok(Self { input, remaining })
    }
}

impl<R: Read> Read for BoundedReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let wanted = usize::try_from(self.remaining.min(buffer.len() as u64))
            .expect("bounded read length fits usize");
        let read = self.input.read(&mut buffer[..wanted])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

struct BoundedWriter<W> {
    inner: W,
    position: u64,
    maximum: u64,
}

impl<W> BoundedWriter<W> {
    fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            position: 0,
            maximum,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let attempted = self.position.saturating_add(buffer.len() as u64);
        if attempted > self.maximum {
            return Err(io::Error::other(OutputLimitExceeded {
                maximum: self.maximum,
                attempted,
            }));
        }
        let written = self.inner.write(buffer)?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for BoundedWriter<W> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = self.inner.seek(position)?;
        self.position = next;
        Ok(next)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        let position = self.inner.stream_position()?;
        self.position = position;
        Ok(position)
    }
}

#[derive(Debug)]
struct OutputLimitExceeded {
    maximum: u64,
    attempted: u64,
}

impl fmt::Display for OutputLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "archive output limit {} exceeded", self.maximum)
    }
}

impl std::error::Error for OutputLimitExceeded {}

#[allow(clippy::needless_pass_by_value)]
fn map_output_error(error: io::Error) -> ContextArchiveError {
    if let Some(limit_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<OutputLimitExceeded>())
    {
        return ContextArchiveError::ArchiveTooLarge {
            actual: limit_error.attempted,
            limit: limit_error.maximum,
        };
    }
    ContextArchiveError::Io(error.to_string())
}

fn map_zip_output_error(error: zip::result::ZipError) -> ContextArchiveError {
    match error {
        zip::result::ZipError::Io(error) => map_output_error(error),
        error => ContextArchiveError::Io(error.to_string()),
    }
}

fn read_up_to<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, ContextArchiveError> {
    let mut read = 0_usize;
    while read < buffer.len() {
        let amount = reader
            .read(&mut buffer[read..])
            .map_err(|error| ContextArchiveError::Io(error.to_string()))?;
        if amount == 0 {
            break;
        }
        read += amount;
    }
    Ok(read)
}
