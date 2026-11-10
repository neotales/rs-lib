#![allow(clippy::doc_markdown)]
//! Repository-owned Engine image build, import, load, and save operations.
//!
//! The operations in this module deliberately keep Bollard's generated
//! request and response models private. Build contexts are inspected as bounded
//! TAR archives before an Engine request is opened, while load/import bodies
//! remain caller-owned streams. The classic Engine builder is used here; the
//! separate `neotales-docker-buildkit` crate is a transport-free contract and
//! is not silently substituted for a real Engine build.
//!
//! # The registry-credential header is base64 **URL-safe**
//!
//! The Engine decodes both `X-Registry-Auth` and `X-Registry-Config` with Go's
//! `base64.URLEncoding`, and a value it cannot decode is **not** an error: the
//! daemon proceeds as though no credential had been sent at all. The two
//! alphabets differ only in `+` against `-` and `/` against `_`, so a
//! standard-alphabet header is byte-for-byte an anonymous request whenever the
//! encoded JSON happens to contain one of those four characters.
//!
//! Measured against Docker Engine 29.7.2, a pull of
//! `ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz:latest` answers:
//!
//! | `X-Registry-Auth` | Answer |
//! | --- | --- |
//! | header absent | `500 error from registry: denied\ndenied` |
//! | **standard** base64 of a real credential | `500 error from registry: denied\ndenied` — byte-identical to no header |
//! | **URL-safe** base64 of the same credential | `403 error from registry: denied` — the credential was read |
//!
//! `POST /build` is quieter still: a standard-alphabet or outright unparseable
//! `X-Registry-Config` is **ignored** and the build runs, so an authenticated
//! build against a private registry silently builds anonymously and fails later
//! at the layer-fetch step. So the encoding here is
//! `base64::engine::general_purpose::URL_SAFE` — which is also what the pinned
//! generated client's `base64_url_encode` *name* claims and its
//! `general_purpose::STANDARD` body does not deliver.
//!
//! # The two registry headers are not interchangeable
//!
//! | Request | Header | Value |
//! | --- | --- | --- |
//! | `POST /build` | `X-Registry-Config` | a **map** of registry to auth object |
//! | `POST /images/load` | `X-Registry-Auth` | **one** auth object |
//! | `POST /images/create?fromSrc=` | `X-Registry-Auth` | **one** auth object |
//!
//! The Engine reads a load's and an import's credential out of `X-Registry-Auth`
//! and nowhere else, and it decodes exactly one auth object from it — the daemon
//! wraps that object in a one-entry map itself. So a load request carrying
//! `X-Registry-Config` carries a credential the daemon does not read, and a map
//! of two or more registries has no faithful spelling for this endpoint at all.
//! The second is refused, with both header names in the message, rather than
//! sent as the nearest available approximation.
//!
//! The import's header *name* was already right and its alphabet was not: the
//! credential was handed to the generated client, whose `base64_url_encode` is
//! `general_purpose::STANDARD`, and the Engine decoded a value it could not read
//! as *no credential*. The credential is now composed here and set by a request
//! modifier, so one encoder produces every header on this path. What that path
//! still does not do is send the API version prefix — it is the generated
//! client's transport, and moving the request onto the owned one is a transport
//! change rather than a header fix.
//!
//! **The header name is documented, not measured, and the code says so.** Every
//! spelling of `X-Registry-Auth` and `X-Registry-Config` was tried against
//! Docker Engine 29.7.2 on a real three-megabyte archive, with the control
//! request alongside it, and all six answers were
//! `200 {"stream":"Loaded image: alpine:3.20\n"}` — the archive is parsed
//! before the credential is read, and this archive needed no fetch. So the
//! claim that one header is ignored and the other honoured rests on the
//! Engine's API reference and its source, not on a measurement, and
//! `tests/registry_credential_headers.rs` asserts the header this crate
//! *sends* rather than pretending to have observed the daemon's reaction to it.

use crate::link_guard::is_link_or_reparse_point;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    fs::{self, File},
    future::Future,
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64};
use bytes::Bytes;
use futures_core::Stream;
use futures_util::{StreamExt, stream};
use http::{HeaderValue, header::CONTENT_TYPE};
use tar::{Builder as TarBuilder, EntryType, Header};
use tokio::sync::{mpsc, oneshot};

use bollard::{
    Docker,
    auth::DockerCredentials,
    body_stream, body_try_stream,
    query_parameters::{
        BuildImageOptionsBuilder, CreateImageOptionsBuilder, ImportImageOptionsBuilder,
    },
};

use crate::{
    CredentialError, DockerClient, DockerStream, Error, ImageProgress, ImageStreamEvent,
    RegistryCredentialProvider, RegistryCredentials, normalize_registry, registry_for_image,
    resource,
};

const MEBIBYTE: u64 = 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_MAX_CONTEXT_BYTES: u64 = 64 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_ENTRIES: usize = 16_384;
const DEFAULT_MAX_CONTEXT_ENTRY_BYTES: u64 = 32 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_TOTAL_BYTES: u64 = 128 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_PATH_BYTES: usize = 4096;
const DEFAULT_MAX_STREAM_BYTES: u64 = 256 * MEBIBYTE;
const MAX_REFERENCE_BYTES: usize = 4096;
const MAX_PLATFORM_BYTES: usize = 255;
const MAX_TAG_BYTES: usize = 1024;
type EngineCredentialMap = HashMap<String, DockerCredentials>;
type CredentialConfig = Option<(EngineCredentialMap, String)>;

/// Resource limits applied to a build context or an upload stream.
///
/// The defaults are intentionally finite so a caller cannot accidentally turn
/// a Docker image operation into an unbounded memory or disk operation. A
/// caller can choose stricter limits, but cannot disable them with zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTransferLimits {
    /// Maximum number of TAR records in a build context.
    pub max_entries: usize,
    /// Maximum declared and observed size of one context file.
    pub max_entry_bytes: u64,
    /// Maximum combined size of context files.
    pub max_total_bytes: u64,
    /// Maximum physical size of the context TAR.
    pub max_archive_bytes: u64,
    /// Maximum UTF-8 byte length of a TAR path.
    pub max_path_bytes: usize,
    /// Maximum number of bytes accepted from a load/import stream.
    pub max_stream_bytes: u64,
}

impl Default for ImageTransferLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_CONTEXT_ENTRIES,
            max_entry_bytes: DEFAULT_MAX_CONTEXT_ENTRY_BYTES,
            max_total_bytes: DEFAULT_MAX_CONTEXT_TOTAL_BYTES,
            max_archive_bytes: DEFAULT_MAX_CONTEXT_BYTES,
            max_path_bytes: DEFAULT_MAX_CONTEXT_PATH_BYTES,
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
        }
    }
}

impl ImageTransferLimits {
    fn validate(self) -> Result<Self, ImageTransferError> {
        if self.max_entries == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_entries must be positive",
            ));
        }
        if self.max_entry_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_entry_bytes must be positive",
            ));
        }
        if self.max_total_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_total_bytes must be positive",
            ));
        }
        if self.max_archive_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_archive_bytes must be positive",
            ));
        }
        if self.max_path_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_path_bytes must be positive",
            ));
        }
        if self.max_stream_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_stream_bytes must be positive",
            ));
        }
        if self.max_entry_bytes > self.max_total_bytes {
            return Err(ImageTransferError::InvalidLimits(
                "max_entry_bytes cannot exceed max_total_bytes",
            ));
        }
        if self.max_archive_bytes < 512 {
            return Err(ImageTransferError::InvalidLimits(
                "max_archive_bytes must be at least one TAR record",
            ));
        }
        Ok(self)
    }

    /// Returns a copy with a different upload-stream ceiling.
    #[must_use]
    pub const fn with_max_stream_bytes(mut self, max_stream_bytes: u64) -> Self {
        self.max_stream_bytes = max_stream_bytes;
        self
    }
}

/// Errors raised before an Engine image-transfer request is opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageTransferError {
    /// A configured limit is unusable.
    InvalidLimits(&'static str),
    /// The TAR is malformed, truncated, or has trailing data.
    InvalidArchive(String),
    /// A TAR path is absolute, traversing, or otherwise ambiguous.
    UnsafeArchivePath(String),
    /// The TAR contains the same logical path more than once.
    DuplicateArchiveEntry(String),
    /// The TAR contains a link, device, FIFO, or other special record.
    UnsupportedArchiveEntry {
        /// Archive entry name.
        entry: String,
        /// Stable description of the rejected entry kind.
        kind: &'static str,
    },
    /// The TAR has too many records.
    TooManyEntries {
        /// Observed record count.
        actual: usize,
        /// Configured record limit.
        limit: usize,
    },
    /// A TAR file is larger than its per-file limit.
    EntryTooLarge {
        /// Archive entry name.
        entry: String,
        /// Observed or declared size.
        actual: u64,
        /// Configured per-file limit.
        limit: u64,
    },
    /// The combined TAR payload is too large.
    TotalSizeExceeded {
        /// Configured combined-size limit.
        limit: u64,
    },
    /// The physical TAR is too large.
    ArchiveTooLarge {
        /// Observed or attempted size.
        actual: u64,
        /// Configured physical-size limit.
        limit: u64,
    },
    /// A selected Dockerfile is missing or names a directory.
    DockerfileMissing(String),
    /// An image reference, tag, platform, or source is invalid.
    InvalidOption {
        /// Option name.
        name: &'static str,
        /// Safe validation detail.
        detail: String,
    },
    /// A save request did not contain an image name.
    MissingImageName,
    /// A classic Engine build cannot represent a requested BuildKit option.
    UnsupportedBuildKit(ImageBuildKitOption),
    /// A registry credential policy is invalid.
    Credentials(CredentialError),
    /// A filesystem operation failed.
    Io(String),
}

impl fmt::Display for ImageTransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(message) => {
                write!(formatter, "image transfer limits are invalid: {message}")
            }
            Self::InvalidArchive(message) => {
                write!(formatter, "image build context is invalid: {message}")
            }
            Self::UnsafeArchivePath(path) => {
                write!(formatter, "image build context path is unsafe: {path}")
            }
            Self::DuplicateArchiveEntry(path) => {
                write!(
                    formatter,
                    "image build context contains duplicate path: {path}"
                )
            }
            Self::UnsupportedArchiveEntry { entry, kind } => {
                write!(
                    formatter,
                    "image build context entry {entry} is an unsupported {kind}"
                )
            }
            Self::TooManyEntries { actual, limit } => write!(
                formatter,
                "image build context has {actual} entries; limit is {limit}"
            ),
            Self::EntryTooLarge {
                entry,
                actual,
                limit,
            } => write!(
                formatter,
                "image build context entry {entry} is {actual} bytes; limit is {limit}"
            ),
            Self::TotalSizeExceeded { limit } => write!(
                formatter,
                "image build context exceeds the total-size limit of {limit} bytes"
            ),
            Self::ArchiveTooLarge { actual, limit } => write!(
                formatter,
                "image build context is or would be {actual} bytes; limit is {limit}"
            ),
            Self::DockerfileMissing(path) => {
                write!(
                    formatter,
                    "build context does not contain Dockerfile: {path}"
                )
            }
            Self::InvalidOption { name, detail } => {
                write!(formatter, "image {name} option is invalid: {detail}")
            }
            Self::MissingImageName => write!(formatter, "at least one image name is required"),
            Self::UnsupportedBuildKit(option) => write!(
                formatter,
                "BuildKit image option {option} is not supported by the Engine facade"
            ),
            Self::Credentials(error) => write!(formatter, "image registry credentials: {error}"),
            Self::Io(message) => write!(formatter, "image transfer I/O failed: {message}"),
        }
    }
}

impl std::error::Error for ImageTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Credentials(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialError> for ImageTransferError {
    fn from(error: CredentialError) -> Self {
        Self::Credentials(error)
    }
}

impl From<io::Error> for ImageTransferError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Compatibility name for callers that treat context validation as a build
/// error.
pub type ImageBuildError = ImageTransferError;
/// Compatibility name for the bounded context constructor.
pub type ImageContextError = ImageTransferError;
/// Compatibility name for save setup errors.
pub type ImageSaveError = ImageTransferError;

/// A BuildKit-only option that is intentionally not silently downgraded to a
/// classic Engine build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageBuildKitOption {
    /// BuildKit builder/session selection.
    BuilderSession,
    /// BuildKit cache export configuration.
    CacheTo,
    /// BuildKit output/export configuration.
    Outputs,
    /// BuildKit secret mounts.
    Secrets,
    /// BuildKit SSH mounts.
    Ssh,
    /// BuildKit provenance attestation.
    Provenance,
    /// BuildKit SBOM attestation.
    Sbom,
    /// BuildKit entitlement requests.
    Entitlements,
    /// BuildKit named build contexts.
    NamedContexts,
    /// BuildKit frontend selection.
    Frontend,
    /// Multi-platform BuildKit output selection.
    MultiPlatform,
}

impl fmt::Display for ImageBuildKitOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BuilderSession => "builder/session",
            Self::CacheTo => "cache-to",
            Self::Outputs => "outputs",
            Self::Secrets => "secret",
            Self::Ssh => "ssh",
            Self::Provenance => "provenance",
            Self::Sbom => "sbom",
            Self::Entitlements => "entitlements",
            Self::NamedContexts => "named-context",
            Self::Frontend => "frontend",
            Self::MultiPlatform => "multi-platform",
        };
        formatter.write_str(name)
    }
}

/// The Engine builder selected for a build request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImageBuildBackend {
    /// The real Docker Engine legacy builder exposed by `/build`.
    #[default]
    Classic,
    /// Reserved for a future real BuildKit transport; rejected by this slice.
    BuildKit,
}

/// A bounded, validated TAR build context.
///
/// Construction reads and validates the complete archive before any HTTP
/// request is opened. The bytes are immutable and shared by the request body,
/// so no caller-owned stream is buffered behind the facade a second time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildContext {
    bytes: Arc<[u8]>,
    files: BTreeSet<String>,
    limits: ImageTransferLimits,
}

impl ImageBuildContext {
    /// Reads and validates a TAR archive from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe paths, special entries,
    /// malformed TARs, or exceeded limits.
    pub fn from_tar<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ImageTransferError> {
        Self::from_tar_with_limits(bytes, ImageTransferLimits::default())
    }

    /// Reads and validates a TAR archive with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid limits, unsafe paths,
    /// special entries, malformed TARs, or exceeded limits.
    pub fn from_tar_with_limits<B: AsRef<[u8]>>(
        bytes: B,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let bytes = bytes.as_ref();
        if bytes.len() as u64 > limits.max_archive_bytes {
            return Err(ImageTransferError::ArchiveTooLarge {
                actual: bytes.len() as u64,
                limit: limits.max_archive_bytes,
            });
        }
        let files = inspect_tar(bytes, limits)?;
        Ok(Self {
            bytes: Arc::<[u8]>::from(bytes.to_vec().into_boxed_slice()),
            files,
            limits,
        })
    }

    /// Alias for [`Self::from_tar`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_tar`].
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ImageTransferError> {
        Self::from_tar(bytes)
    }

    /// Reads and validates a TAR archive from a synchronous reader.
    ///
    /// The reader is consumed at most one byte beyond the configured archive
    /// limit, which makes an oversized reader fail without unbounded buffering.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for I/O, malformed archives, or limits.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, ImageTransferError> {
        Self::from_reader_with_limits(reader, ImageTransferLimits::default())
    }

    /// Reads and validates a TAR archive with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for I/O, malformed archives, or limits.
    pub fn from_reader_with_limits<R: Read>(
        reader: R,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let mut bytes = Vec::new();
        let mut reader = reader.take(limits.max_archive_bytes.saturating_add(1));
        reader.read_to_end(&mut bytes)?;
        Self::from_tar_with_limits(bytes, limits)
    }

    /// Reads and validates a regular TAR file.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an unsafe/non-regular path, an
    /// oversized file, or invalid TAR contents.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ImageTransferError> {
        Self::from_path_with_limits(path, ImageTransferLimits::default())
    }

    /// Reads and validates a regular TAR file with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe/non-regular paths, an
    /// oversized file, or invalid TAR contents.
    pub fn from_path_with_limits(
        path: impl AsRef<Path>,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", path.display())))?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: path.display().to_string(),
                kind: "filesystem path",
            });
        }
        if metadata.len() > limits.max_archive_bytes {
            return Err(ImageTransferError::ArchiveTooLarge {
                actual: metadata.len(),
                limit: limits.max_archive_bytes,
            });
        }
        let file = File::open(path)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", path.display())))?;
        Self::from_reader_with_limits(file, limits)
    }

    /// Creates a deterministic, bounded TAR from a directory tree.
    ///
    /// Symbolic links, hard links, device nodes, FIFOs, and other special
    /// filesystem entries are rejected rather than followed or serialized.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe trees, I/O failures, or
    /// exceeded limits.
    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self, ImageTransferError> {
        Self::from_directory_with_limits(path, ImageTransferLimits::default())
    }

    /// Creates a deterministic, bounded TAR from a directory with limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe trees, I/O failures, or
    /// exceeded limits.
    pub fn from_directory_with_limits(
        path: impl AsRef<Path>,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let root = path.as_ref();
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", root.display())))?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: root.display().to_string(),
                kind: "filesystem directory",
            });
        }
        let mut entries = Vec::new();
        collect_directory_entries(root, root, &mut entries, limits)?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let mut builder = TarBuilder::new(Vec::new());
        for entry in entries {
            match entry.kind {
                DirectoryEntryKind::Directory => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Directory);
                    header.set_mode(0o755);
                    header.set_size(0);
                    header.set_mtime(0);
                    header.set_cksum();
                    let path = format!("{}/", entry.path);
                    builder
                        .append_data(&mut header, path, io::empty())
                        .map_err(ImageTransferError::from)?;
                }
                DirectoryEntryKind::File { size } => {
                    let file =
                        File::open(root.join(&entry.path)).map_err(ImageTransferError::from)?;
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Regular);
                    header.set_mode(0o644);
                    header.set_size(size);
                    header.set_mtime(0);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, &entry.path, file)
                        .map_err(ImageTransferError::from)?;
                }
            }
        }
        let bytes = builder.into_inner().map_err(ImageTransferError::from)?;
        Self::from_tar_with_limits(bytes, limits)
    }

    /// Returns the number of validated context files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Returns the physical archive size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the validated context has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the validated context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validates that the selected Dockerfile is a regular file in the context.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError::DockerfileMissing`] for an unsafe or
    /// missing Dockerfile path.
    pub fn validate_for(&self, options: &ImageBuildOptions) -> Result<(), ImageTransferError> {
        let path = validate_relative_path(&options.dockerfile, "dockerfile").map_err(|detail| {
            ImageTransferError::InvalidOption {
                name: "dockerfile",
                detail,
            }
        })?;
        if !self.files.contains(&path) {
            return Err(ImageTransferError::DockerfileMissing(path));
        }
        Ok(())
    }

    fn request_body(&self) -> impl Stream<Item = Bytes> + Send + 'static {
        let bytes = Arc::clone(&self.bytes);
        stream::iter(
            bytes
                .chunks(COPY_BUFFER_SIZE)
                .map(Bytes::copy_from_slice)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug)]
struct DirectoryEntry {
    path: String,
    kind: DirectoryEntryKind,
}

#[derive(Clone, Copy, Debug)]
enum DirectoryEntryKind {
    Directory,
    File { size: u64 },
}

fn collect_directory_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<DirectoryEntry>,
    limits: ImageTransferLimits,
) -> Result<(), ImageTransferError> {
    let mut children = fs::read_dir(current)
        .map_err(|error| ImageTransferError::Io(format!("{}: {error}", current.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ImageTransferError::Io(format!("{}: {error}", current.display())))?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let metadata = fs::symlink_metadata(child.path()).map_err(|error| {
            ImageTransferError::Io(format!("{}: {error}", child.path().display()))
        })?;
        if is_link_or_reparse_point(&metadata) {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: child.path().display().to_string(),
                kind: "symbolic link",
            });
        }
        let relative = child
            .path()
            .strip_prefix(root)
            .map_err(|_| ImageTransferError::UnsafeArchivePath(child.path().display().to_string()))?
            .to_str()
            .ok_or_else(|| {
                ImageTransferError::UnsafeArchivePath(child.path().display().to_string())
            })?
            .replace('\\', "/");
        let path = validate_relative_path(&relative, "context path")
            .map_err(ImageTransferError::UnsafeArchivePath)?;
        if entries.len() >= limits.max_entries {
            return Err(ImageTransferError::TooManyEntries {
                actual: entries.len().saturating_add(1),
                limit: limits.max_entries,
            });
        }
        if metadata.is_dir() {
            entries.push(DirectoryEntry {
                path: path.clone(),
                kind: DirectoryEntryKind::Directory,
            });
            collect_directory_entries(root, &child.path(), entries, limits)?;
        } else if metadata.is_file() {
            if metadata.len() > limits.max_entry_bytes {
                return Err(ImageTransferError::EntryTooLarge {
                    entry: path,
                    actual: metadata.len(),
                    limit: limits.max_entry_bytes,
                });
            }
            let mut total = 0_u64;
            for entry in entries
                .iter()
                .filter(|entry| matches!(entry.kind, DirectoryEntryKind::File { .. }))
            {
                if let DirectoryEntryKind::File { size } = entry.kind {
                    total = total.saturating_add(size);
                }
            }
            let new_total = total.checked_add(metadata.len()).ok_or({
                ImageTransferError::InvalidArchive("context size overflow".to_owned())
            })?;
            if new_total > limits.max_total_bytes {
                return Err(ImageTransferError::TotalSizeExceeded {
                    limit: limits.max_total_bytes,
                });
            }
            entries.push(DirectoryEntry {
                path,
                kind: DirectoryEntryKind::File {
                    size: metadata.len(),
                },
            });
        } else {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: child.path().display().to_string(),
                kind: "special filesystem entry",
            });
        }
    }
    Ok(())
}

fn display_archive_path(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

fn tar_entry_kind(kind: EntryType) -> &'static str {
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

#[allow(clippy::too_many_lines)]
fn inspect_tar(
    bytes: &[u8],
    limits: ImageTransferLimits,
) -> Result<BTreeSet<String>, ImageTransferError> {
    let archive_length = bytes.len() as u64;
    let mut reader = Cursor::new(bytes);
    let mut archive = tar::Archive::new(&mut reader);
    archive.set_ignore_zeros(false);
    let mut files = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    let mut last_entry_end = 0_u64;
    {
        let entries = archive
            .entries_with_seek()
            .map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
        for entry in entries {
            let mut entry =
                entry.map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
            count = count.checked_add(1).ok_or_else(|| {
                ImageTransferError::InvalidArchive("entry count overflow".to_owned())
            })?;
            if count > limits.max_entries {
                return Err(ImageTransferError::TooManyEntries {
                    actual: count,
                    limit: limits.max_entries,
                });
            }
            let kind = entry.header().entry_type();
            if !kind.is_dir() && !kind.is_file() {
                let path = display_archive_path(&entry.path_bytes());
                return Err(ImageTransferError::UnsupportedArchiveEntry {
                    entry: path,
                    kind: tar_entry_kind(kind),
                });
            }
            let path_bytes = entry.path_bytes().into_owned();
            if path_bytes.len() > limits.max_path_bytes {
                return Err(ImageTransferError::UnsafeArchivePath(display_archive_path(
                    &path_bytes,
                )));
            }
            let path = std::str::from_utf8(&path_bytes)
                .map_err(|_| {
                    ImageTransferError::UnsafeArchivePath(display_archive_path(&path_bytes))
                })?
                .to_owned();
            let normalized = validate_relative_path(&path, "context path")
                .map_err(ImageTransferError::UnsafeArchivePath)?;
            if !seen.insert(normalized.clone()) {
                return Err(ImageTransferError::DuplicateArchiveEntry(normalized));
            }
            let size = entry.size();
            if kind.is_dir() {
                if size != 0 {
                    return Err(ImageTransferError::UnsupportedArchiveEntry {
                        entry: normalized,
                        kind: "directory with data",
                    });
                }
            } else {
                if size > limits.max_entry_bytes {
                    return Err(ImageTransferError::EntryTooLarge {
                        entry: normalized,
                        actual: size,
                        limit: limits.max_entry_bytes,
                    });
                }
                total = total.checked_add(size).ok_or_else(|| {
                    ImageTransferError::InvalidArchive("context size overflow".to_owned())
                })?;
                if total > limits.max_total_bytes {
                    return Err(ImageTransferError::TotalSizeExceeded {
                        limit: limits.max_total_bytes,
                    });
                }
                let copied = io::copy(&mut entry.by_ref().take(size), &mut io::sink())
                    .map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
                if copied != size {
                    return Err(ImageTransferError::InvalidArchive(format!(
                        "entry {normalized} ended at {copied} bytes; declared {size}"
                    )));
                }
                files.insert(normalized);
            }
            let padded_size = size
                .checked_add(511)
                .map(|value| value / 512 * 512)
                .ok_or_else(|| {
                    ImageTransferError::InvalidArchive("TAR size overflow".to_owned())
                })?;
            let entry_end = entry
                .raw_file_position()
                .checked_add(padded_size)
                .ok_or_else(|| {
                    ImageTransferError::InvalidArchive("TAR offset overflow".to_owned())
                })?;
            last_entry_end = last_entry_end.max(entry_end);
        }
    }
    if count == 0 {
        return Err(ImageTransferError::InvalidArchive(
            "TAR contains no entries".to_owned(),
        ));
    }
    validate_tar_tail(bytes, last_entry_end, archive_length)?;
    Ok(files)
}

fn validate_tar_tail(
    bytes: &[u8],
    last_entry_end: u64,
    archive_length: u64,
) -> Result<(), ImageTransferError> {
    if last_entry_end > archive_length {
        return Err(ImageTransferError::InvalidArchive(
            "TAR entry extends beyond the archive".to_owned(),
        ));
    }
    let tail = &bytes[usize::try_from(last_entry_end).map_err(|_| {
        ImageTransferError::InvalidArchive("TAR tail offset does not fit usize".to_owned())
    })?..];
    if tail.iter().any(|byte| *byte != 0) {
        return Err(ImageTransferError::InvalidArchive(
            "TAR contains trailing or concatenated data".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &str, option: &str) -> Result<String, String> {
    if path.is_empty() || path.len() > MAX_REFERENCE_BYTES {
        return Err(format!("{option} path is empty or too long"));
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return Err(format!(
            "{option} path must be relative and use '/' separators"
        ));
    }
    if path
        .chars()
        .any(|character| character.is_control() || character == '\0')
    {
        return Err(format!("{option} path contains a control character"));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "{option} path contains an empty or traversing component"
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(format!("{option} path is empty"));
    }
    Ok(components.join("/"))
}

fn validate_image_name(name: &str, option: &'static str) -> Result<(), ImageTransferError> {
    if name.is_empty() || name.len() > MAX_REFERENCE_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: option,
            detail: "name is empty or too long".to_owned(),
        });
    }
    if name
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || name.contains('?')
        || name.contains('#')
    {
        return Err(ImageTransferError::InvalidOption {
            name: option,
            detail: "name contains whitespace, control, query, or fragment characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ImageTransferError> {
    if tag.is_empty() || tag.len() > MAX_TAG_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "tag",
            detail: "tag is empty or too long".to_owned(),
        });
    }
    if tag
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ImageTransferError::InvalidOption {
            name: "tag",
            detail: "tag contains whitespace or a control character".to_owned(),
        });
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<(), ImageTransferError> {
    if platform.is_empty() || platform.len() > MAX_PLATFORM_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "platform is empty or too long".to_owned(),
        });
    }
    if platform
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || platform.contains('?')
        || platform.contains('#')
    {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "platform contains unsafe characters".to_owned(),
        });
    }
    let parts: Vec<_> = platform.split('/').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "use os[/architecture[/variant]]".to_owned(),
        });
    }
    Ok(())
}

fn validate_source(source: &str) -> Result<(), ImageTransferError> {
    if source == "-" {
        return Ok(());
    }
    if source.is_empty() || source.len() > MAX_REFERENCE_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source is empty or too long".to_owned(),
        });
    }
    if source
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source contains whitespace or a control character".to_owned(),
        });
    }
    let url = url::Url::parse(source).map_err(|_| ImageTransferError::InvalidOption {
        name: "source",
        detail: "source must be an HTTP(S) URL or '-'".to_owned(),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source must be an HTTP(S) URL or '-'".to_owned(),
        });
    }
    Ok(())
}

/// Options for the Engine `/build` endpoint.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildOptions {
    /// Dockerfile path relative to the validated TAR context.
    pub dockerfile: String,
    /// Optional image names/tags to apply.
    pub tags: Vec<String>,
    /// Optional target stage.
    pub target: Option<String>,
    /// Optional target platform in `os/architecture[/variant]` form.
    pub platform: Option<String>,
    /// Suppress verbose build output.
    pub quiet: bool,
    /// Disable the Engine build cache.
    pub no_cache: bool,
    /// Pull newer base images when true; leave unset to use daemon behavior.
    pub pull: Option<bool>,
    /// Remove intermediate containers after success.
    pub remove_intermediate: bool,
    /// Remove intermediate containers after failure.
    pub force_remove_intermediate: bool,
    /// Ordered build arguments.
    pub build_args: BTreeMap<String, String>,
    /// Ordered image labels.
    pub labels: BTreeMap<String, String>,
    /// Cache image references.
    pub cache_from: Vec<String>,
    /// Optional `/etc/hosts` additions.
    pub extra_hosts: Option<String>,
    /// Optional build network mode.
    pub network_mode: Option<String>,
    /// Optional memory limit in bytes.
    pub memory: Option<i32>,
    /// Optional memory-plus-swap limit in bytes.
    pub memswap: Option<i32>,
    /// Optional CPU shares.
    pub cpu_shares: Option<i32>,
    /// Optional CPU affinity list.
    pub cpuset_cpus: Option<String>,
    /// Optional CPU period.
    pub cpu_period: Option<i32>,
    /// Optional CPU quota.
    pub cpu_quota: Option<i32>,
    /// Optional `/dev/shm` size.
    pub shm_size: Option<i32>,
    /// Optional classic-builder squash flag.
    pub squash: Option<bool>,
    /// Optional remote context URL. It is rejected by this bounded-context
    /// operation rather than downloading unvalidated input.
    pub remote: Option<String>,
    /// Explicit registry credentials keyed by registry authority.
    pub registry_credentials: BTreeMap<String, RegistryCredentials>,
    /// Builder backend. BuildKit is rejected until a real transport exists.
    pub backend: ImageBuildBackend,
    /// Explicitly requested unsupported BuildKit options.
    pub buildkit_options: Vec<ImageBuildKitOption>,
}

impl Default for ImageBuildOptions {
    fn default() -> Self {
        Self {
            dockerfile: "Dockerfile".to_owned(),
            tags: Vec::new(),
            target: None,
            platform: None,
            quiet: false,
            no_cache: false,
            pull: None,
            remove_intermediate: true,
            force_remove_intermediate: false,
            build_args: BTreeMap::new(),
            labels: BTreeMap::new(),
            cache_from: Vec::new(),
            extra_hosts: None,
            network_mode: None,
            memory: None,
            memswap: None,
            cpu_shares: None,
            cpuset_cpus: None,
            cpu_period: None,
            cpu_quota: None,
            shm_size: None,
            squash: None,
            remote: None,
            registry_credentials: BTreeMap::new(),
            backend: ImageBuildBackend::Classic,
            buildkit_options: Vec::new(),
        }
    }
}

impl ImageBuildOptions {
    /// Creates default classic Engine build options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Dockerfile path.
    #[must_use]
    pub fn with_dockerfile(mut self, dockerfile: impl Into<String>) -> Self {
        self.dockerfile = dockerfile.into();
        self
    }

    /// Adds one image tag/name.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Replaces the image tag/name list.
    #[must_use]
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Enables or disables quiet build output.
    #[must_use]
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Sets the target build stage.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Sets the target platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Enables or disables base-image pulling.
    #[must_use]
    pub const fn with_pull(mut self, pull: bool) -> Self {
        self.pull = Some(pull);
        self
    }

    /// Disables the build cache.
    #[must_use]
    pub const fn with_no_cache(mut self, no_cache: bool) -> Self {
        self.no_cache = no_cache;
        self
    }

    /// Adds one ordered build argument.
    #[must_use]
    pub fn with_build_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.build_args.insert(key.into(), value.into());
        self
    }

    /// Adds one ordered image label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Adds one cache-from image reference.
    #[must_use]
    pub fn with_cache_from(mut self, image: impl Into<String>) -> Self {
        self.cache_from.push(image.into());
        self
    }

    /// Adds explicit registry credentials for base-image pulls.
    #[must_use]
    pub fn with_registry_credentials(
        mut self,
        registry: impl Into<String>,
        credentials: RegistryCredentials,
    ) -> Self {
        self.registry_credentials
            .insert(registry.into(), credentials);
        self
    }

    /// Marks a BuildKit-only option as requested.
    #[must_use]
    pub fn with_buildkit_option(mut self, option: ImageBuildKitOption) -> Self {
        self.buildkit_options.push(option);
        self
    }

    /// Selects the real classic Engine builder.
    #[must_use]
    pub const fn with_classic_builder(mut self) -> Self {
        self.backend = ImageBuildBackend::Classic;
        self
    }

    /// Selects BuildKit. The current Engine facade rejects this explicitly.
    #[must_use]
    pub const fn with_buildkit(mut self) -> Self {
        self.backend = ImageBuildBackend::BuildKit;
        self
    }

    /// Validates options that can be checked without contacting a daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid names, paths, options, or
    /// explicitly requested BuildKit-only features.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        validate_relative_path(&self.dockerfile, "dockerfile").map_err(|detail| {
            ImageTransferError::InvalidOption {
                name: "dockerfile",
                detail,
            }
        })?;
        for tag in &self.tags {
            validate_image_name(tag, "tag")?;
        }
        if let Some(platform) = &self.platform {
            validate_platform(platform)?;
        }
        if let Some(target) = &self.target
            && (target.is_empty() || target.chars().any(char::is_control))
        {
            return Err(ImageTransferError::InvalidOption {
                name: "target",
                detail: "target is empty or contains a control character".to_owned(),
            });
        }
        if let Some(remote) = &self.remote {
            validate_source(remote)?;
            return Err(ImageTransferError::InvalidOption {
                name: "remote",
                detail: "remote contexts are not accepted by the bounded TAR operation".to_owned(),
            });
        }
        if self.memory.is_some_and(|value| value <= 0)
            || self.memswap.is_some_and(|value| value == 0 || value < -1)
            || self.cpu_shares.is_some_and(|value| value <= 0)
            || self.cpu_period.is_some_and(|value| value <= 0)
            || self.cpu_quota.is_some_and(|value| value == 0)
            || self.shm_size.is_some_and(|value| value <= 0)
        {
            return Err(ImageTransferError::InvalidOption {
                name: "resource",
                detail: "resource limits must be positive (memswap may be -1)".to_owned(),
            });
        }
        for image in &self.cache_from {
            validate_image_name(image, "cache-from")?;
        }
        validate_key_values(&self.build_args, "build-arg")?;
        validate_key_values(&self.labels, "label")?;
        if self.backend == ImageBuildBackend::BuildKit {
            return Err(ImageTransferError::UnsupportedBuildKit(
                ImageBuildKitOption::BuilderSession,
            ));
        }
        if let Some(option) = self.buildkit_options.first().copied() {
            return Err(ImageTransferError::UnsupportedBuildKit(option));
        }
        Ok(())
    }
}

fn validate_key_values(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), ImageTransferError> {
    for (key, value) in values {
        if key.is_empty()
            || key.len() > 4096
            || value.len() > 128 * 1024
            || key.chars().chain(value.chars()).any(char::is_control)
        {
            return Err(ImageTransferError::InvalidOption {
                name,
                detail: "key or value is empty, too long, or contains a control character"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

/// Options for importing an image from a remote TAR source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageImportOptions {
    /// HTTP(S) source URL, or `-` for a caller-owned request stream.
    pub source: String,
    /// Optional destination repository.
    pub repository: Option<String>,
    /// Optional destination tag.
    pub tag: Option<String>,
    /// Optional import commit message.
    pub message: Option<String>,
    /// Dockerfile changes applied while importing.
    pub changes: Vec<String>,
    /// Optional imported platform.
    pub platform: Option<String>,
}

impl ImageImportOptions {
    /// Creates import options for a source URL.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            ..Self::default()
        }
    }

    /// Sets the destination repository.
    #[must_use]
    pub fn with_repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    /// Sets the destination tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Sets the import platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Adds one Dockerfile change.
    #[must_use]
    pub fn with_change(mut self, change: impl Into<String>) -> Self {
        self.changes.push(change.into());
        self
    }

    /// Validates options without contacting a daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid source, repository, tag,
    /// platform, or change.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        validate_source(&self.source)?;
        if let Some(repository) = &self.repository {
            validate_image_name(repository, "repository")?;
        }
        if let Some(tag) = &self.tag {
            validate_tag(tag)?;
        }
        if let Some(platform) = &self.platform {
            validate_platform(platform)?;
        }
        for change in &self.changes {
            if change.is_empty()
                || change.len() > 128 * 1024
                || change.chars().any(char::is_control)
            {
                return Err(ImageTransferError::InvalidOption {
                    name: "change",
                    detail: "change is empty, too long, or contains a control character".to_owned(),
                });
            }
        }
        if self.message.as_ref().is_some_and(|message| {
            message.is_empty()
                || message.len() > 128 * 1024
                || message.chars().any(char::is_control)
        }) {
            return Err(ImageTransferError::InvalidOption {
                name: "message",
                detail: "message is empty, too long, or contains a control character".to_owned(),
            });
        }
        Ok(())
    }
}

/// Options for loading a Docker image archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadOptions {
    /// Suppress progress details.
    pub quiet: bool,
    /// Optional platform selectors encoded using Docker's v1.53 array form.
    pub platforms: Vec<String>,
}

impl ImageLoadOptions {
    /// Creates default load options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quiet: false,
            platforms: Vec::new(),
        }
    }

    /// Enables or disables quiet progress.
    #[must_use]
    pub const fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Adds one platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platforms.push(platform.into());
        self
    }

    /// Replaces the platform selector list.
    #[must_use]
    pub fn with_platforms<I, S>(mut self, platforms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.platforms = platforms.into_iter().map(Into::into).collect();
        self
    }

    /// Validates load options.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid platform selector.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        for platform in &self.platforms {
            validate_platform(platform)?;
        }
        Ok(())
    }
}

/// Options for saving one or more images as a Docker archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageSaveOptions {
    /// Image names or IDs to include in the archive.
    pub names: Vec<String>,
    /// Optional target platform.
    pub platform: Option<String>,
}

impl ImageSaveOptions {
    /// Creates save options for one or more image names.
    #[must_use]
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
            platform: None,
        }
    }

    /// Adds one image name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.names.push(name.into());
        self
    }

    /// Sets the target platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Validates names and platform selection.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] when no valid image name is supplied or
    /// the platform is malformed.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        if self.names.is_empty() {
            return Err(ImageTransferError::MissingImageName);
        }
        for name in &self.names {
            validate_image_name(name, "name")?;
        }
        if let Some(platform) = &self.platform {
            validate_platform(platform)?;
        }
        Ok(())
    }
}

/// A typed build response line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageBuildEvent {
    /// Layer or operation identifier.
    pub id: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// Raw textual build output.
    pub stream: Option<String>,
    /// Structured progress details.
    pub progress: Option<ImageProgress>,
    /// Error text embedded in a successful HTTP stream.
    pub error: Option<String>,
    /// Classic builder auxiliary image ID, when supplied.
    pub aux: Option<ImageBuildAux>,
}

/// Auxiliary values emitted by a build response.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageBuildAux {
    /// Resulting image ID.
    pub image_id: Option<String>,
    /// Resulting digest, when supplied by a newer daemon.
    pub digest: Option<String>,
    /// BuildKit reference, when supplied by a newer daemon.
    pub build_ref: Option<String>,
}

/// A typed load response line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadEvent {
    /// Layer or image identifier.
    pub id: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// Raw textual output.
    pub stream: Option<String>,
    /// Structured progress details.
    pub progress: Option<ImageProgress>,
    /// Error text embedded in a successful HTTP stream.
    pub error: Option<String>,
}

/// Alias matching the Engine terminology.
pub type ImageBuildResponse = ImageBuildEvent;
/// Alias matching the Engine terminology.
pub type ImageLoadResponse = ImageLoadEvent;
/// Import uses the same progress shape as pull/push.
pub type ImageImportEvent = ImageStreamEvent;

/// A collected successful build result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageBuildResult {
    /// The resulting image ID, when the daemon emitted one.
    pub image_id: Option<String>,
    /// All typed response lines in daemon order.
    pub events: Vec<ImageBuildEvent>,
}

/// A collected successful load result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadResult {
    /// IDs observed in load progress events.
    pub image_ids: Vec<String>,
    /// All typed response lines in daemon order.
    pub events: Vec<ImageLoadEvent>,
}

/// A high-level save result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImageSaveResult {
    /// Number of response chunks written.
    pub chunks: u64,
    /// Total bytes written.
    pub bytes: u64,
}

/// Errors returned while consuming a build/load/save response stream.
#[derive(Debug)]
pub enum ImageOperationError {
    /// Invalid request options or context.
    Transfer(ImageTransferError),
    /// Docker transport/API error.
    Docker(Error),
    /// The daemon embedded an error in an otherwise successful stream.
    Daemon(String),
    /// Caller-owned output/input I/O failed.
    Io(String),
}

impl fmt::Display for ImageOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transfer(error) => write!(formatter, "{error}"),
            Self::Docker(error) => write!(formatter, "{error}"),
            Self::Daemon(message) => write!(formatter, "Docker image operation failed: {message}"),
            Self::Io(message) => write!(formatter, "image operation I/O failed: {message}"),
        }
    }
}

impl std::error::Error for ImageOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transfer(error) => Some(error),
            Self::Docker(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImageTransferError> for ImageOperationError {
    fn from(error: ImageTransferError) -> Self {
        Self::Transfer(error)
    }
}

impl From<Error> for ImageOperationError {
    fn from(error: Error) -> Self {
        Self::Docker(error)
    }
}

fn map_build_event(info: bollard::models::BuildInfo) -> ImageBuildEvent {
    let aux = info.aux.map(|aux| ImageBuildAux {
        image_id: aux.id,
        digest: None,
        build_ref: None,
    });
    ImageBuildEvent {
        id: info.id,
        status: info.status,
        stream: info.stream,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: info.error_detail.and_then(|detail| detail.message),
        aux,
    }
}

fn map_load_event(info: bollard::models::BuildInfo) -> ImageLoadEvent {
    ImageLoadEvent {
        id: info.id,
        status: info.status,
        stream: info.stream,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: info.error_detail.and_then(|detail| detail.message),
    }
}

fn map_create_event(info: bollard::models::CreateImageInfo) -> ImageStreamEvent {
    ImageStreamEvent {
        id: info.id,
        status: info.status,
        stream: None,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: info.error_detail.and_then(|detail| detail.message),
    }
}

fn build_bollard_options(
    options: &ImageBuildOptions,
) -> bollard::query_parameters::BuildImageOptions {
    let mut builder = BuildImageOptionsBuilder::default()
        .dockerfile(&options.dockerfile)
        .q(options.quiet)
        .nocache(options.no_cache)
        .rm(options.remove_intermediate)
        .forcerm(options.force_remove_intermediate);
    if let Some(tag) = options.tags.first() {
        builder = builder.t(tag);
    }
    if let Some(target) = &options.target {
        builder = builder.target(target);
    }
    if let Some(platform) = &options.platform {
        builder = builder.platform(platform);
    }
    if let Some(pull) = options.pull {
        builder = builder.pull(if pull { "true" } else { "false" });
    }
    if let Some(extra_hosts) = &options.extra_hosts {
        builder = builder.extrahosts(extra_hosts);
    }
    if let Some(network_mode) = &options.network_mode {
        builder = builder.networkmode(network_mode);
    }
    if let Some(memory) = options.memory {
        builder = builder.memory(memory);
    }
    if let Some(memswap) = options.memswap {
        builder = builder.memswap(memswap);
    }
    if let Some(cpu_shares) = options.cpu_shares {
        builder = builder.cpushares(cpu_shares);
    }
    if let Some(cpuset_cpus) = &options.cpuset_cpus {
        builder = builder.cpusetcpus(cpuset_cpus);
    }
    if let Some(cpu_period) = options.cpu_period {
        builder = builder.cpuperiod(cpu_period);
    }
    if let Some(cpu_quota) = options.cpu_quota {
        builder = builder.cpuquota(cpu_quota);
    }
    if let Some(shm_size) = options.shm_size {
        builder = builder.shmsize(shm_size);
    }
    if let Some(squash) = options.squash {
        builder = builder.squash(squash);
    }
    if !options.cache_from.is_empty() {
        builder = builder.cachefrom(&options.cache_from);
    }
    builder.build()
}

fn import_bollard_options(
    options: &ImageImportOptions,
) -> bollard::query_parameters::CreateImageOptions {
    let mut builder = CreateImageOptionsBuilder::default().from_src(&options.source);
    if let Some(repository) = &options.repository {
        builder = builder.repo(repository);
    }
    if let Some(tag) = &options.tag {
        builder = builder.tag(tag);
    }
    if let Some(message) = &options.message {
        builder = builder.message(message);
    }
    if let Some(platform) = &options.platform {
        builder = builder.platform(platform);
    }
    if !options.changes.is_empty() {
        builder = builder.changes(options.changes.clone());
    }
    builder.build()
}

fn load_bollard_options(
    options: &ImageLoadOptions,
) -> bollard::query_parameters::ImportImageOptions {
    let mut builder = ImportImageOptionsBuilder::default().quiet(options.quiet);
    if !options.platforms.is_empty() {
        builder = builder.platform(options.platforms.clone());
    }
    builder.build()
}

fn encode_json_parameter(
    key: &str,
    value: &impl serde::Serialize,
) -> Result<(String, String), ImageTransferError> {
    let json = serde_json::to_string(value).map_err(|error| ImageTransferError::InvalidOption {
        name: "json",
        detail: error.to_string(),
    })?;
    Ok((key.to_owned(), json))
}

/// The Engine header a registry credential travels in, with its encoded value.
///
/// The two names are not interchangeable, and neither is the value's shape:
///
/// | Request | Header | Value |
/// | --- | --- | --- |
/// | `POST /build` | `X-Registry-Config` | a *map* of registry to auth object |
/// | `POST /images/load` | `X-Registry-Auth` | *one* auth object |
///
/// The Engine reads `POST /images/load`'s credential from `X-Registry-Auth` and
/// nowhere else — see [`load_registry_header`] — and reads `POST /build`'s from
/// `X-Registry-Config`; a request that carries the other one is answered as
/// though no credential were sent.
struct RegistryHeader {
    name: &'static str,
    value: String,
}

impl RegistryHeader {
    /// A `X-Registry-Config` value: a map of every registry the caller named.
    fn config(value: String) -> Self {
        Self {
            name: "x-registry-config",
            value,
        }
    }

    /// An `X-Registry-Auth` value: one registry's auth object.
    fn auth(value: String) -> Self {
        Self {
            name: "x-registry-auth",
            value,
        }
    }
}

/// Encodes the credential an endpoint reads out of `X-Registry-Auth`.
///
/// `POST /images/load` and `POST /images/create?fromSrc=` both read a single
/// auth object from that header, and the Engine decodes exactly one: the daemon
/// wraps the object in a one-entry map itself. A map of two or more registries
/// therefore has no faithful spelling for either endpoint and is refused with
/// both header names in the message rather than sent as something the daemon
/// will not read.
fn single_registry_header(
    values: BTreeMap<String, RegistryCredentials>,
) -> Result<RegistryHeader, ImageTransferError> {
    let count = values.len();
    let mut entries = values.into_iter();
    let Some((registry, credentials)) = entries.next() else {
        return Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: "credential map must not be empty".to_owned(),
        });
    };
    if count > 1 {
        let others = entries
            .map(|(registry, _)| registry)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: format!(
                "POST /images/load reads one registry from X-Registry-Auth, and \
                 X-Registry-Config is the header POST /build reads, so {count} \
                 registries have no faithful spelling here; {registry}, {others} \
                 were given"
            ),
        });
    }
    let (_, engine) = single_registry_credentials(&registry, credentials)?;
    let json =
        serde_json::to_string(&engine).map_err(|error| ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: error.to_string(),
        })?;
    Ok(RegistryHeader::auth(BASE64.encode(json)))
}

fn registry_credentials(
    values: &BTreeMap<String, RegistryCredentials>,
) -> Result<CredentialConfig, ImageTransferError> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut normalized = BTreeMap::new();
    for (registry, credentials) in values {
        let registry = normalize_registry(registry)?;
        credentials.validate_for(&registry)?;
        normalized.insert(registry, credentials.clone());
    }
    let canonical: BTreeMap<String, DockerCredentials> = normalized
        .iter()
        .map(|(registry, credentials)| {
            (
                registry.clone(),
                credentials.clone().into_engine_credentials(registry),
            )
        })
        .collect();
    let json =
        serde_json::to_string(&canonical).map_err(|error| ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: error.to_string(),
        })?;
    // URL-safe, and never an empty header: the Engine reads a value it cannot
    // decode as *no credential*, so a header that fails to encode would have to
    // be an error rather than an absence nobody can see. The module
    // documentation has the measurement.
    let header = BASE64.encode(json);
    let engine = canonical.into_iter().collect();
    Ok(Some((engine, header)))
}

fn single_registry_credentials(
    registry: &str,
    credentials: RegistryCredentials,
) -> Result<(String, DockerCredentials), ImageTransferError> {
    let registry = normalize_registry(registry)?;
    credentials.validate_for(&registry)?;
    let engine = credentials.into_engine_credentials(&registry);
    Ok((registry, engine))
}

fn bounded_upload<S, E>(
    source: S,
    max_bytes: u64,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
{
    let source = Box::pin(source);
    stream::unfold(
        (source, 0_u64, max_bytes, false),
        |(mut source, total, max_bytes, failed)| async move {
            if failed {
                return None;
            }
            let item = source.as_mut().next().await?;
            match item {
                Ok(chunk) => {
                    let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    let Some(next_total) = total.checked_add(length) else {
                        return Some((
                            Err(io::Error::other("image upload size overflow")),
                            (source, total, max_bytes, true),
                        ));
                    };
                    if next_total > max_bytes {
                        return Some((
                            Err(io::Error::other(format!(
                                "image upload exceeds the {max_bytes}-byte limit"
                            ))),
                            (source, next_total, max_bytes, true),
                        ));
                    }
                    Some((
                        Ok(Bytes::from(chunk)),
                        (source, next_total, max_bytes, false),
                    ))
                }
                Err(error) => Some((
                    Err(io::Error::other(error)),
                    (source, total, max_bytes, true),
                )),
            }
        },
    )
}

fn modify_query(
    request: &mut bollard::BollardRequest,
    path: &str,
    additions: &[(String, String)],
    replacements: &[&str],
) {
    if !request.uri().path().ends_with(path) {
        return;
    }
    let existing = request.uri().query().unwrap_or_default();
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(existing.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .filter(|(key, _)| !replacements.iter().any(|candidate| candidate == key))
        .collect();
    let addition_keys: BTreeSet<String> = additions.iter().map(|(key, _)| key.clone()).collect();
    for key in &addition_keys {
        pairs.retain(|(existing_key, _)| existing_key != key);
    }
    for (key, value) in additions {
        pairs.push((key.clone(), value.clone()));
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    let path_and_query = if query.is_empty() {
        request.uri().path().to_owned()
    } else {
        format!("{}?{query}", request.uri().path())
    };
    if let Ok(path_and_query) = path_and_query.parse::<http::uri::PathAndQuery>() {
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }
}

/// Sets the registry-credential header a request already names.
///
/// `insert` rather than `append`, so the value this crate composed is the one on
/// the wire even where the generated client would have set the same header from
/// the credentials it was handed. A value that does not fit an HTTP header is
/// dropped here and nowhere else, and the only caller that can produce one is
/// the load path, whose base64 value is always a legal header value.
fn set_registry_header(request: &mut bollard::BollardRequest, header: &RegistryHeader) {
    if let Ok(value) = HeaderValue::from_str(&header.value) {
        request.headers_mut().insert(header.name, value);
    }
}

fn with_content_type(
    docker: Docker,
    content_type: &'static str,
    registry_header: Option<RegistryHeader>,
) -> Docker {
    docker.with_request_modifier(move |mut request| {
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        if let Some(header) = &registry_header {
            set_registry_header(&mut request, header);
        }
        request
    })
}

/// Carries one registry credential on a request the generated client builds
/// without one.
///
/// Used where the endpoint reads `X-Registry-Auth` and the generated client
/// would have set that header from a credential the *caller* supplied — which is
/// how the standard alphabet reached the wire in the first place. Passing `None`
/// for the generated client's own credentials and setting the header here keeps
/// one encoder, and this is the one the Engine's decoder can read.
fn with_registry_header(docker: Docker, registry_header: RegistryHeader) -> Docker {
    docker.with_request_modifier(move |mut request| {
        set_registry_header(&mut request, &registry_header);
        request
    })
}

fn build_docker_with_modifiers(
    docker: &Docker,
    options: &ImageBuildOptions,
) -> Result<(Docker, Option<HashMap<String, DockerCredentials>>), ImageTransferError> {
    let mut additions = Vec::new();
    for tag in &options.tags {
        additions.push(("t".to_owned(), tag.clone()));
    }
    let mut replacements = Vec::new();
    if !options.build_args.is_empty() {
        let (key, value) = encode_json_parameter("buildargs", &options.build_args)?;
        additions.push((key, value));
        replacements.push("buildargs");
    }
    if !options.labels.is_empty() {
        let (key, value) = encode_json_parameter("labels", &options.labels)?;
        additions.push((key, value));
        replacements.push("labels");
    }
    let credentials = registry_credentials(&options.registry_credentials)?;
    if additions.is_empty() && credentials.is_none() {
        return Ok((docker.clone(), None));
    }
    let header = credentials
        .as_ref()
        .map(|(_, value)| RegistryHeader::config(value.clone()));
    let docker = docker.clone().with_request_modifier(move |mut request| {
        modify_query(&mut request, "/build", &additions, &replacements);
        if let Some(header) = &header {
            set_registry_header(&mut request, header);
        }
        request
    });
    Ok((docker, credentials.map(|(credentials, _)| credentials)))
}

fn spawn_build_stream<F, Fut>(operation: F) -> DockerStream<ImageBuildEvent>
where
    F: FnOnce(oneshot::Receiver<()>, mpsc::Sender<Result<ImageBuildEvent, Error>>) -> Fut
        + Send
        + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    DockerStream::spawn(operation)
}

fn spawn_create_stream<F, Fut>(operation: F) -> DockerStream<ImageStreamEvent>
where
    F: FnOnce(oneshot::Receiver<()>, mpsc::Sender<Result<ImageStreamEvent, Error>>) -> Fut
        + Send
        + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    DockerStream::spawn(operation)
}

fn spawn_load_stream<S, E>(
    docker: Docker,
    options: bollard::query_parameters::ImportImageOptions,
    source: S,
    max_bytes: u64,
    registry_header: Option<RegistryHeader>,
) -> DockerStream<ImageLoadEvent>
where
    S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
{
    DockerStream::spawn(move |mut cancellation, sender| async move {
        let body = bounded_upload(source, max_bytes);
        let docker = with_content_type(docker, "application/x-tar", registry_header);
        // `None` credentials on purpose: the generated client turns that argument
        // into the same `X-Registry-Config` header the build path uses, which
        // `POST /images/load` does not read. The header the Engine reads is set
        // by the modifier above, and it is URL-safe base64 of one auth object.
        let stream = docker.import_image_stream(options, body, None);
        futures_util::pin_mut!(stream);
        loop {
            let next = tokio::select! {
                _ = &mut cancellation => break,
                next = stream.next() => next,
            };
            let Some(item) = next else { break };
            let item = match item {
                Ok(value) => Ok(map_load_event(value)),
                Err(error) => Err(Error::from(error)),
            };
            let sent = tokio::select! {
                _ = &mut cancellation => break,
                sent = sender.send(item) => sent,
            };
            if sent.is_err() {
                break;
            }
        }
    })
}

impl DockerClient {
    /// Builds an image from a validated, bounded TAR context.
    ///
    /// The returned handle owns the HTTP response and the request body. It can
    /// be cancelled or dropped independently of this client. The real Engine
    /// `/build` endpoint is used; the fixture-only BuildKit adapter is not
    /// called.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] before opening a request when the
    /// Dockerfile, options, credentials, or BuildKit policy is invalid.
    #[allow(clippy::needless_pass_by_value)]
    pub fn build_image(
        &self,
        context: ImageBuildContext,
        options: Option<ImageBuildOptions>,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError> {
        let options = options.unwrap_or_default();
        options.validate()?;
        context.validate_for(&options)?;
        let (docker, credentials) = build_docker_with_modifiers(&self.inner, &options)?;
        let bollard_options = build_bollard_options(&options);
        let body = body_stream(context.request_body());
        Ok(spawn_build_stream(
            move |mut cancellation, sender| async move {
                let stream = docker.build_image(bollard_options, credentials, Some(body));
                futures_util::pin_mut!(stream);
                loop {
                    let next = tokio::select! {
                        _ = &mut cancellation => break,
                        next = stream.next() => next,
                    };
                    let Some(item) = next else { break };
                    let item = match item {
                        Ok(value) => Ok(map_build_event(value)),
                        Err(error) => Err(Error::from(error)),
                    };
                    let sent = tokio::select! {
                        _ = &mut cancellation => break,
                        sent = sender.send(item) => sent,
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            },
        ))
    }

    /// Builds an image using an explicit credential map, replacing the map in
    /// `options`.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid options or credentials.
    pub fn build_image_with_credentials(
        &self,
        context: ImageBuildContext,
        mut options: ImageBuildOptions,
        credentials: BTreeMap<String, RegistryCredentials>,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError> {
        options.registry_credentials = credentials;
        self.build_image(context, Some(options))
    }

    /// Builds an image with credentials supplied by a caller-owned provider.
    ///
    /// The provider is queried synchronously before the request task is
    /// created. Registry names are explicit because a provider must not be
    /// allowed to discover arbitrary registries from a Dockerfile.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid registry, provider
    /// failure, or invalid build options.
    pub fn build_image_with_provider<P, I>(
        &self,
        context: ImageBuildContext,
        mut options: ImageBuildOptions,
        provider: &P,
        registries: I,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError>
    where
        P: RegistryCredentialProvider + ?Sized,
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut credentials = BTreeMap::new();
        for registry in registries {
            let registry = normalize_registry(registry.as_ref())?;
            let value = provider.credentials_for(&registry)?;
            credentials.insert(registry, value);
        }
        options.registry_credentials = credentials;
        self.build_image(context, Some(options))
    }

    /// Builds an image and collects all response lines.
    ///
    /// # Errors
    ///
    /// Returns [`ImageOperationError`] for request validation, transport/API
    /// errors, or an error embedded in the response stream.
    pub async fn build_image_to_completion(
        &self,
        context: ImageBuildContext,
        options: Option<ImageBuildOptions>,
    ) -> Result<ImageBuildResult, ImageOperationError> {
        let mut stream = self
            .build_image(context, options)
            .map_err(ImageOperationError::Transfer)?;
        let mut result = ImageBuildResult::default();
        while let Some(item) = stream.next().await {
            let event = item.map_err(ImageOperationError::Docker)?;
            if let Some(error) = &event.error {
                return Err(ImageOperationError::Daemon(error.clone()));
            }
            if let Some(image_id) = event.aux.as_ref().and_then(|aux| aux.image_id.clone()) {
                result.image_id = Some(image_id);
            }
            result.events.push(event);
        }
        Ok(result)
    }

    /// Imports an image from a remote TAR URL.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] before opening a request for invalid
    /// source or import options.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image(
        &self,
        options: ImageImportOptions,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        options.validate()?;
        if options.source == "-" {
            return Err(ImageTransferError::InvalidOption {
                name: "source",
                detail: "use import_image_from_stream for '-'".to_owned(),
            });
        }
        let bollard_options = import_bollard_options(&options);
        let docker = self.inner.clone();
        Ok(spawn_create_stream(
            move |mut cancellation, sender| async move {
                let stream = docker.create_image(Some(bollard_options), None, None);
                futures_util::pin_mut!(stream);
                loop {
                    let next = tokio::select! {
                        _ = &mut cancellation => break,
                        next = stream.next() => next,
                    };
                    let Some(item) = next else { break };
                    let item = match item {
                        Ok(value) => Ok(map_create_event(value)),
                        Err(error) => Err(Error::from(error)),
                    };
                    let sent = tokio::select! {
                        _ = &mut cancellation => break,
                        sent = sender.send(item) => sent,
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            },
        ))
    }

    /// Imports an image from a caller-owned root-filesystem stream.
    ///
    /// The stream is moved into an owned request task and is bounded by the
    /// supplied limits. The response handle is caller-owned and cancellable.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid import options or limits.
    pub fn import_image_from_stream<S, E>(
        &self,
        mut options: ImageImportOptions,
        source: S,
        limits: ImageTransferLimits,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        options.source.clear();
        options.source.push('-');
        options.validate()?;
        let limits = limits.validate()?;
        let bollard_options = import_bollard_options(&options);
        let body = body_try_stream(bounded_upload(source, limits.max_stream_bytes));
        let docker = with_content_type(self.inner.clone(), "application/x-tar", None);
        Ok(spawn_create_stream(
            move |mut cancellation, sender| async move {
                let stream = docker.create_image(Some(bollard_options), Some(body), None);
                futures_util::pin_mut!(stream);
                loop {
                    let next = tokio::select! {
                        _ = &mut cancellation => break,
                        next = stream.next() => next,
                    };
                    let Some(item) = next else { break };
                    let item = match item {
                        Ok(value) => Ok(map_create_event(value)),
                        Err(error) => Err(Error::from(error)),
                    };
                    let sent = tokio::select! {
                        _ = &mut cancellation => break,
                        sent = sender.send(item) => sent,
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            },
        ))
    }

    /// Imports a remote image with a single registry credential.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid import options or credentials.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image_with_credentials(
        &self,
        options: ImageImportOptions,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        let registry =
            registry_for_image(&options.source).map_err(ImageTransferError::Credentials)?;
        self.import_image_with_credentials_for_registry(options, &registry, credentials)
    }

    /// Imports a remote image with an explicitly selected registry credential.
    ///
    /// `POST /images/create?fromSrc=` reads its credential from
    /// `X-Registry-Auth`, and this crate composes and sets that header itself
    /// rather than handing the credential to the generated client, which would
    /// encode it with the standard alphabet the Engine cannot read.
    ///
    /// This path still sends an **unversioned** request line, because it is the
    /// generated client's transport. The credential is the defect that is fixed
    /// here; the missing version prefix is the transport change this crate has
    /// not made, and moving the request onto [`raw`](crate::raw) is what would
    /// fix both at once.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid options or credentials.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image_with_credentials_for_registry(
        &self,
        options: ImageImportOptions,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        options.validate()?;
        if options.source == "-" {
            return Err(ImageTransferError::InvalidOption {
                name: "source",
                detail: "use import_image_from_stream for '-'".to_owned(),
            });
        }
        let mut header_credentials = BTreeMap::new();
        header_credentials.insert(registry.to_owned(), credentials);
        let registry_header = single_registry_header(header_credentials)?;
        let bollard_options = import_bollard_options(&options);
        // No credentials for the generated client: it would set `X-Registry-Auth`
        // from them with the standard alphabet, which the Engine reads as no
        // credential at all. The modifier sets the header instead, with the one
        // encoder the Engine's decoder can read.
        let docker = with_registry_header(self.inner.clone(), registry_header);
        Ok(spawn_create_stream(
            move |mut cancellation, sender| async move {
                let stream = docker.create_image(Some(bollard_options), None, None);
                futures_util::pin_mut!(stream);
                loop {
                    let next = tokio::select! {
                        _ = &mut cancellation => break,
                        next = stream.next() => next,
                    };
                    let Some(item) = next else { break };
                    let item = match item {
                        Ok(value) => Ok(map_create_event(value)),
                        Err(error) => Err(Error::from(error)),
                    };
                    let sent = tokio::select! {
                        _ = &mut cancellation => break,
                        sent = sender.send(item) => sent,
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            },
        ))
    }

    /// Loads a Docker image archive from a caller-owned stream.
    ///
    /// The input stream is never collected by the facade. It is bounded while
    /// it is moved into the request and the response handle is independently
    /// cancellable.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid options or limits.
    pub fn load_image<S, E>(
        &self,
        source: S,
        options: Option<ImageLoadOptions>,
        limits: ImageTransferLimits,
    ) -> Result<DockerStream<ImageLoadEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let options = options.unwrap_or_default();
        options.validate()?;
        let limits = limits.validate()?;
        Ok(spawn_load_stream(
            self.inner.clone(),
            load_bollard_options(&options),
            source,
            limits.max_stream_bytes,
            None,
        ))
    }

    /// Loads an image archive with explicit registry credentials.
    ///
    /// Docker normally does not need registry credentials for a local archive.
    /// This variant is for an archive whose referenced layers the daemon has to
    /// fetch, and the credential travels in **`X-Registry-Auth`**, which is the
    /// header `POST /images/load` reads. `X-Registry-Config` is the *map* header
    /// `POST /build` reads; a load request carrying it is answered as though no
    /// credential had been sent, which is what this method used to do.
    ///
    /// The Engine decodes one auth object out of `X-Registry-Auth` and wraps it
    /// in a one-entry map itself, so a map of two or more registries has no
    /// faithful spelling here and is refused rather than sent as something the
    /// daemon will not read. The error names both headers so a caller can tell
    /// which endpoint its multi-registry credential belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid options, credentials, or
    /// limits, and for a credential map that is empty or names more than one
    /// registry.
    #[allow(clippy::needless_pass_by_value)]
    pub fn load_image_with_credentials<S, E>(
        &self,
        source: S,
        options: Option<ImageLoadOptions>,
        limits: ImageTransferLimits,
        credentials: BTreeMap<String, RegistryCredentials>,
    ) -> Result<DockerStream<ImageLoadEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let options = options.unwrap_or_default();
        options.validate()?;
        let limits = limits.validate()?;
        let registry_header = single_registry_header(credentials)?;
        Ok(spawn_load_stream(
            self.inner.clone(),
            load_bollard_options(&options),
            source,
            limits.max_stream_bytes,
            Some(registry_header),
        ))
    }

    /// Saves one or more images as a caller-owned archive byte stream.
    ///
    /// Names are sent in the caller's order and the optional platform is
    /// encoded through a narrow request modifier because Bollard 0.21.1's
    /// `export_images` helper does not expose that query field.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] before opening a request for an empty or
    /// invalid name list or platform.
    pub fn save_images(
        &self,
        options: ImageSaveOptions,
    ) -> Result<DockerStream<Vec<u8>>, ImageTransferError> {
        options.validate()?;
        let names: Vec<&str> = options.names.iter().map(String::as_str).collect();
        let docker = if let Some(platform) = options.platform {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("platform", &platform);
            let query = serializer.finish();
            resource::with_query_parameter(&self.inner, "/images/get", query)
        } else {
            self.inner.clone()
        };
        Ok(DockerStream::new(docker.export_images(&names).map(
            |item| item.map(|chunk| chunk.to_vec()).map_err(Error::from),
        )))
    }

    /// Saves one image as a caller-owned archive byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid image name or platform.
    pub fn save_image(
        &self,
        name: impl Into<String>,
        platform: Option<String>,
    ) -> Result<DockerStream<Vec<u8>>, ImageTransferError> {
        let mut options = ImageSaveOptions::new([name.into()]);
        options.platform = platform;
        self.save_images(options)
    }

    /// Saves all requested images into a caller-owned writer.
    ///
    /// The response is consumed one chunk at a time; it is not collected into
    /// a second archive buffer. Dropping the stream on a write error releases
    /// the HTTP response.
    ///
    /// # Errors
    ///
    /// Returns [`ImageOperationError`] for validation, API/transport, or output
    /// errors.
    pub async fn save_images_to_writer<W: Write>(
        &self,
        options: ImageSaveOptions,
        writer: &mut W,
    ) -> Result<ImageSaveResult, ImageOperationError> {
        let mut stream = self
            .save_images(options)
            .map_err(ImageOperationError::Transfer)?;
        let mut result = ImageSaveResult::default();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(ImageOperationError::Docker)?;
            writer
                .write_all(&chunk)
                .map_err(|error| ImageOperationError::Io(error.to_string()))?;
            result.chunks += 1;
            result.bytes = result
                .bytes
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    ImageOperationError::Io("saved chunk length does not fit u64".to_owned())
                })?)
                .ok_or_else(|| ImageOperationError::Io("saved byte count overflow".to_owned()))?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialConfig, registry_credentials};
    use crate::RegistryCredentials;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE},
    };

    /// Candidate secrets, in the order the search tries them.
    ///
    /// The standard and URL-safe base64 alphabets differ only in `+`/`-` and
    /// `/`/`_`, and an encoded JSON only reaches those characters when a byte of
    /// the credential lands on a six-bit group of 62 or 63 — which for ASCII
    /// means `>`, `?` and `~` at a particular alignment. Over short
    /// alphanumeric passwords almost none of them do, so a test that hard-coded
    /// a password would quietly stop testing the alphabet the day somebody
    /// changed it. The search is what makes the assertion below non-vacuous.
    const CANDIDATE_SECRETS: &[&str] = &[
        "a?b", "aa~bb", "p>ss", "s?cret", ">>", "~~", "?>", "~?", "z~>", "0?1", "x>y~z?w",
    ];

    /// Encodes `secret` the way the build header does and reports whether the
    /// result tells the two alphabets apart.
    ///
    /// `true` means the URL-safe spelling contains at least one `-` or `_` and
    /// no `+` or `/`, which is exactly the condition under which the standard
    /// alphabet cannot read the value the Engine would be given.
    fn discriminates_the_alphabets(secret: &str) -> bool {
        let mut values = std::collections::BTreeMap::new();
        values.insert(
            "ghcr.io".to_owned(),
            RegistryCredentials::new("probeuser", secret),
        );
        let Some((_, header)) = registry_credentials(&values).expect("valid credential") else {
            return false;
        };
        (header.contains('-') || header.contains('_'))
            && !(header.contains('+') || header.contains('/'))
    }

    /// Returns the first candidate secret whose encoding tells the alphabets
    /// apart.
    fn discriminating_secret() -> &'static str {
        CANDIDATE_SECRETS
            .iter()
            .copied()
            .find(|secret| discriminates_the_alphabets(secret))
            .expect("at least one candidate secret exercises the URL-safe alphabet")
    }

    /// The header the build path sends is readable by the Engine and invisible
    /// to the standard alphabet.
    ///
    /// The Engine decodes `X-Registry-Config` with `base64.URLEncoding` and
    /// treats a decode failure as *no credential*, so a standard-alphabet header
    /// is an authenticated build that silently runs anonymously. Asserting the
    /// alphabet only proves something if the secret discriminates, which is why
    /// the secret is searched for rather than written down.
    #[test]
    fn the_registry_credential_header_uses_the_url_safe_alphabet() {
        let secret = discriminating_secret();
        let mut values = std::collections::BTreeMap::new();
        values.insert(
            "ghcr.io".to_owned(),
            RegistryCredentials::new("probeuser", secret),
        );

        let Some((engine, header)) = registry_credentials(&values).expect("valid credential")
        else {
            panic!("one registry produces a header");
        };

        // The guard the search exists to protect: this exact header is one the
        // two alphabets disagree about, so the next two assertions are about the
        // alphabet and not about base64 in general.
        assert!(
            header.contains('-') || header.contains('_'),
            "the searched secret must still discriminate: {header}"
        );
        assert!(
            STANDARD.decode(&header).is_err(),
            "the standard alphabet must not be able to read the Engine's header: {header}"
        );

        let decoded = URL_SAFE
            .decode(&header)
            .expect("the Engine's alphabet reads its own header");
        let document: serde_json::Value =
            serde_json::from_slice(&decoded).expect("the header carries JSON");
        assert_eq!(document["ghcr.io"]["username"], "probeuser");
        assert_eq!(document["ghcr.io"]["password"], secret);
        assert_eq!(document["ghcr.io"]["serveraddress"], "ghcr.io");
        // The same credential is what the generated client is handed, so the
        // header and the body cannot disagree about what is being sent.
        assert_eq!(
            engine
                .get("ghcr.io")
                .map(|credentials| credentials.password.as_deref()),
            Some(Some(secret))
        );
    }

    /// An empty credential map sends no header rather than an empty one.
    ///
    /// "No credentials were sent" and "credentials were sent and the registry
    /// refused" are different answers, and an empty header is how the second one
    /// gets reported when nothing was.
    #[test]
    fn no_credential_map_encodes_no_header() {
        let empty: CredentialConfig = registry_credentials(&std::collections::BTreeMap::new())
            .expect("an empty map is not an error");
        assert!(empty.is_none());
    }
}
