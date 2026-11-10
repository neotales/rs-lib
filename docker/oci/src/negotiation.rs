//! Explicit media-type and response-content policy for registry manifests.

use std::{collections::BTreeSet, fmt};

use crate::digest::{Digest, DigestError};

/// OCI image manifest media type.
pub const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index media type.
pub const OCI_IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// Docker Schema 2 image manifest media type.
pub const DOCKER_IMAGE_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker Schema 2 manifest-list media type.
pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// OCI artifact manifest media type used by artifact-oriented clients.
pub const OCI_ARTIFACT_MANIFEST: &str = "application/vnd.oci.artifact.manifest.v1+json";

/// A validated media type or media-range token.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MediaType(String);

impl MediaType {
    /// Parses a media type, preserving parameters in canonical spelling.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::InvalidMediaType`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, NegotiationError> {
        let value = value.trim();
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(NegotiationError::InvalidMediaType);
        }
        let mut parts = value.split(';');
        let essence = parts.next().unwrap_or_default().trim();
        let (type_name, subtype) = essence
            .split_once('/')
            .ok_or(NegotiationError::InvalidMediaType)?;
        if !valid_token(type_name) || !valid_subtype(subtype) {
            return Err(NegotiationError::InvalidMediaType);
        }
        let mut normalized = format!(
            "{}/{}",
            type_name.to_ascii_lowercase(),
            subtype.to_ascii_lowercase()
        );
        for parameter in parts {
            let parameter = parameter.trim();
            if parameter.is_empty() {
                return Err(NegotiationError::InvalidMediaType);
            }
            let (key, value) = parameter
                .split_once('=')
                .ok_or(NegotiationError::InvalidMediaType)?;
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            if !valid_token(key)
                || value.is_empty()
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(NegotiationError::InvalidMediaType);
            }
            normalized.push_str("; ");
            normalized.push_str(&key.to_ascii_lowercase());
            normalized.push('=');
            normalized.push_str(value);
        }
        Ok(Self(normalized))
    }

    /// Parses a media type and panics only for a compile-time-known constant.
    ///
    /// # Panics
    ///
    /// Panics when `value` is not a valid media type.
    #[must_use]
    pub fn constant(value: &str) -> Self {
        Self::parse(value).expect("constant media type must be valid")
    }

    /// Returns the canonical media type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the type/subtype portion without parameters.
    #[must_use]
    pub fn essence(&self) -> &str {
        self.0.split(';').next().unwrap_or(&self.0)
    }

    /// Returns whether this is an exact type/subtype rather than a wildcard.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.essence() != "*/*" && !self.essence().ends_with("/*")
    }

    /// Returns whether this media range matches `candidate`.
    #[must_use]
    pub fn matches(&self, candidate: &MediaType) -> bool {
        let (left_type, left_subtype) = self.essence().split_once('/').unwrap_or_default();
        let (right_type, right_subtype) = candidate.essence().split_once('/').unwrap_or_default();
        (left_type == "*" || left_type == right_type)
            && (left_subtype == "*" || left_subtype == right_subtype)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("MediaType").field(&self.0).finish()
    }
}

/// One entry in an `Accept` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptEntry {
    media_type: MediaType,
    quality: u16,
}

impl AcceptEntry {
    /// Creates an entry with quality `1.0`.
    ///
    /// # Errors
    ///
    /// This constructor currently cannot fail; the result keeps the entry
    /// construction API uniform with quality-bearing constructors.
    pub fn new(media_type: MediaType) -> Result<Self, NegotiationError> {
        Ok(Self {
            media_type,
            quality: 1_000,
        })
    }

    /// Creates an entry with a quality value in thousandths (`0..=1000`).
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::InvalidQuality`] above `1000`.
    pub fn with_quality(media_type: MediaType, quality: u16) -> Result<Self, NegotiationError> {
        if quality > 1_000 {
            return Err(NegotiationError::InvalidQuality);
        }
        Ok(Self {
            media_type,
            quality,
        })
    }

    /// Returns the media range.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns the quality value in thousandths.
    #[must_use]
    pub const fn quality(&self) -> u16 {
        self.quality
    }

    fn rendered(&self) -> String {
        if self.quality == 1_000 {
            self.media_type.to_string()
        } else {
            format!(
                "{};q={:.3}",
                self.media_type,
                f64::from(self.quality) / 1000.0
            )
        }
    }
}

/// Parsed and rendered `Accept` header entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptHeader {
    entries: Vec<AcceptEntry>,
}

impl AcceptHeader {
    /// Parses an `Accept` header, retaining caller order for deterministic ties.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty header, malformed media range, or invalid
    /// quality value.
    pub fn parse(value: &str) -> Result<Self, NegotiationError> {
        if value.trim().is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(NegotiationError::EmptyAcceptHeader);
        }
        let mut entries = Vec::new();
        for raw_entry in split_header_parts(value) {
            let raw_entry = raw_entry.trim();
            if raw_entry.is_empty() {
                continue;
            }
            let mut pieces = raw_entry.split(';');
            let media_type = MediaType::parse(pieces.next().unwrap_or_default())?;
            let mut quality = 1_000;
            for parameter in pieces {
                let (key, value) = parameter
                    .split_once('=')
                    .ok_or(NegotiationError::InvalidQuality)?;
                if key.trim().eq_ignore_ascii_case("q") {
                    quality = parse_quality(value.trim())?;
                }
            }
            entries.push(AcceptEntry {
                media_type,
                quality,
            });
        }
        if entries.is_empty() {
            return Err(NegotiationError::EmptyAcceptHeader);
        }
        Ok(Self { entries })
    }

    /// Builds an accept header from entries.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::EmptyAcceptHeader`] for no entries.
    pub fn from_entries(entries: Vec<AcceptEntry>) -> Result<Self, NegotiationError> {
        if entries.is_empty() {
            return Err(NegotiationError::EmptyAcceptHeader);
        }
        Ok(Self { entries })
    }

    /// Returns the entries in deterministic caller order.
    #[must_use]
    pub fn entries(&self) -> &[AcceptEntry] {
        &self.entries
    }

    /// Renders the header.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        self.entries
            .iter()
            .map(AcceptEntry::rendered)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Selects the best matching entry for a response media type.
    #[must_use]
    pub fn negotiate(&self, response: &MediaType) -> Option<&AcceptEntry> {
        let mut selected = None;
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.quality > 0 && entry.media_type.matches(response))
        {
            if selected.is_none_or(|current: &AcceptEntry| entry.quality > current.quality) {
                selected = Some(entry);
            }
        }
        selected
    }
}

/// Explicit response policy for a registry transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentPolicy {
    accepted: Vec<MediaType>,
    max_bytes: usize,
    require_digest_header: bool,
}

impl Default for ContentPolicy {
    fn default() -> Self {
        Self {
            accepted: default_manifest_media_types(),
            max_bytes: 4 * 1024 * 1024,
            require_digest_header: true,
        }
    }
}

impl ContentPolicy {
    /// Creates a policy from explicit accepted media types.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list, duplicate media type, or zero byte
    /// limit.
    pub fn new(
        accepted: impl IntoIterator<Item = MediaType>,
        max_bytes: usize,
    ) -> Result<Self, NegotiationError> {
        if max_bytes == 0 {
            return Err(NegotiationError::InvalidLimit);
        }
        let accepted: Vec<_> = accepted.into_iter().collect();
        if accepted.is_empty() {
            return Err(NegotiationError::EmptyAcceptHeader);
        }
        let mut seen = BTreeSet::new();
        if accepted
            .iter()
            .any(|media_type| !seen.insert(media_type.clone()))
        {
            return Err(NegotiationError::DuplicateMediaType);
        }
        Ok(Self {
            accepted,
            max_bytes,
            require_digest_header: true,
        })
    }

    /// Creates the standard OCI/Docker manifest policy.
    #[must_use]
    pub fn manifests() -> Self {
        Self::default()
    }

    /// Creates a bounded opaque-blob policy.
    ///
    /// # Errors
    ///
    /// Returns an error when `max_bytes` is zero.
    pub fn blob(max_bytes: usize) -> Result<Self, NegotiationError> {
        Self::new([MediaType::constant("application/octet-stream")], max_bytes)
    }

    /// Returns the accepted media types in caller order.
    #[must_use]
    pub fn accepted_media_types(&self) -> &[MediaType] {
        &self.accepted
    }

    /// Returns the maximum response size in bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Returns whether a digest header is mandatory.
    #[must_use]
    pub const fn require_digest_header(&self) -> bool {
        self.require_digest_header
    }

    /// Changes the maximum response size.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::InvalidLimit`] when `max_bytes` is zero.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Result<Self, NegotiationError> {
        if max_bytes == 0 {
            return Err(NegotiationError::InvalidLimit);
        }
        self.max_bytes = max_bytes;
        Ok(self)
    }

    /// Allows a computed digest when a registry omits `Docker-Content-Digest`.
    #[must_use]
    pub const fn without_digest_header(mut self) -> Self {
        self.require_digest_header = false;
        self
    }

    /// Renders the explicit `Accept` header.
    #[must_use]
    pub fn accept_header(&self) -> String {
        self.accepted
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Returns whether a media type is explicitly accepted for an upload.
    #[must_use]
    pub fn accepts_upload(&self, media_type: &MediaType) -> bool {
        self.accepted
            .iter()
            .any(|accepted| accepted.matches(media_type))
    }

    /// Verifies and bounds a response body.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized body, missing/unsupported media type,
    /// missing/malformed digest header, or digest mismatch.
    pub fn verify(
        &self,
        content_type: Option<&str>,
        docker_content_digest: Option<&str>,
        content: &[u8],
    ) -> Result<VerifiedContent, NegotiationError> {
        if content.len() > self.max_bytes {
            return Err(NegotiationError::ResponseTooLarge {
                actual: content.len(),
                maximum: self.max_bytes,
            });
        }
        let content_type = content_type.ok_or(NegotiationError::MissingContentType)?;
        let response_type = MediaType::parse(content_type)?;
        if !self
            .accepted
            .iter()
            .any(|accepted| accepted.matches(&response_type))
        {
            return Err(NegotiationError::UnsupportedMediaType(response_type));
        }
        let digest = if self.require_digest_header {
            let header = docker_content_digest.ok_or(NegotiationError::MissingDigestHeader)?;
            let advertised = Digest::parse(header).map_err(NegotiationError::InvalidDigest)?;
            if !advertised.matches(content) {
                return Err(NegotiationError::DigestMismatch);
            }
            advertised
        } else {
            Digest::sha256(content)
        };
        Ok(VerifiedContent {
            content: content.to_vec(),
            media_type: response_type,
            digest,
        })
    }

    /// Verifies a response using an already parsed digest header.
    ///
    /// # Errors
    ///
    /// Returns the same policy errors as [`ContentPolicy::verify`].
    pub fn verify_with_digest(
        &self,
        content_type: Option<&str>,
        docker_content_digest: Option<&str>,
        content: &[u8],
    ) -> Result<VerifiedContent, NegotiationError> {
        self.verify(content_type, docker_content_digest, content)
    }
}

/// Content that passed media-type, size, and digest checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedContent {
    content: Vec<u8>,
    media_type: MediaType,
    digest: Digest,
}

impl VerifiedContent {
    /// Returns the verified bytes.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Consumes the value and returns the verified bytes.
    #[must_use]
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }

    /// Returns the negotiated media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns the verified digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the number of verified bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns whether the verified content is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

/// Errors returned by media-type and content policy checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiationError {
    /// A media type was empty, malformed, or contained a control character.
    InvalidMediaType,
    /// An `Accept` header had no usable entries.
    EmptyAcceptHeader,
    /// A quality value was outside `0.0..=1.0` or malformed.
    InvalidQuality,
    /// The same media type was listed more than once.
    DuplicateMediaType,
    /// A configured transfer limit was zero.
    InvalidLimit,
    /// The response exceeded the configured byte limit.
    ResponseTooLarge {
        /// Actual response size.
        actual: usize,
        /// Configured maximum size.
        maximum: usize,
    },
    /// The response did not provide `Content-Type`.
    MissingContentType,
    /// The response media type was not accepted by policy.
    UnsupportedMediaType(MediaType),
    /// The response did not provide the required digest header.
    MissingDigestHeader,
    /// The digest header was malformed.
    InvalidDigest(DigestError),
    /// The response digest did not match its bytes.
    DigestMismatch,
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMediaType => formatter.write_str("media type is invalid"),
            Self::EmptyAcceptHeader => {
                formatter.write_str("content negotiation has no accepted media types")
            }
            Self::InvalidQuality => formatter.write_str("content negotiation quality is invalid"),
            Self::DuplicateMediaType => {
                formatter.write_str("content negotiation contains duplicate media types")
            }
            Self::InvalidLimit => formatter.write_str("content transfer limit must be positive"),
            Self::ResponseTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "content response is too large: {actual} bytes exceeds {maximum}"
                )
            }
            Self::MissingContentType => formatter.write_str("content response has no media type"),
            Self::UnsupportedMediaType(media_type) => write!(
                formatter,
                "content media type is not accepted: {media_type}"
            ),
            Self::MissingDigestHeader => {
                formatter.write_str("content response has no Docker-Content-Digest header")
            }
            Self::InvalidDigest(error) => {
                write!(formatter, "content digest header is invalid: {error}")
            }
            Self::DigestMismatch => {
                formatter.write_str("content response digest does not match its bytes")
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Backwards-compatible descriptive alias for callers that prefer the longer
/// registry terminology.
pub type ContentNegotiation = ContentPolicy;
/// Alias for the manifest-specific policy name.
pub type ManifestContentPolicy = ContentPolicy;

fn default_manifest_media_types() -> Vec<MediaType> {
    [
        OCI_IMAGE_MANIFEST,
        OCI_IMAGE_INDEX,
        DOCKER_IMAGE_MANIFEST,
        DOCKER_MANIFEST_LIST,
        OCI_ARTIFACT_MANIFEST,
    ]
    .into_iter()
    .map(MediaType::constant)
    .collect()
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_subtype(value: &str) -> bool {
    valid_token(value)
}

fn parse_quality(value: &str) -> Result<u16, NegotiationError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'.')
    {
        return Err(NegotiationError::InvalidQuality);
    }
    let mut parts = value.split('.');
    let whole = parts.next().ok_or(NegotiationError::InvalidQuality)?;
    let fraction = parts.next().unwrap_or("0");
    if parts.next().is_some() || whole.is_empty() || fraction.len() > 3 {
        return Err(NegotiationError::InvalidQuality);
    }
    let whole_value: u16 = whole
        .parse()
        .map_err(|_| NegotiationError::InvalidQuality)?;
    if whole_value > 1 {
        return Err(NegotiationError::InvalidQuality);
    }
    let mut fraction_value = 0_u16;
    for (index, byte) in fraction.bytes().enumerate() {
        let digit = u16::from(byte - b'0');
        fraction_value = fraction_value * 10 + digit;
        if index >= 3 {
            return Err(NegotiationError::InvalidQuality);
        }
    }
    for _ in fraction.len()..3 {
        fraction_value *= 10;
    }
    Ok(whole_value * 1_000 + fraction_value)
}

fn split_header_parts(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ',' && !quoted {
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    parts.push(&value[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::{ContentPolicy, MediaType, OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST};

    #[test]
    fn renders_explicit_accept_header() {
        let policy = ContentPolicy::new(
            [
                MediaType::constant(OCI_IMAGE_MANIFEST),
                MediaType::constant(OCI_IMAGE_INDEX),
            ],
            1024,
        )
        .expect("policy");
        assert_eq!(
            policy.accept_header(),
            "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"
        );
    }

    #[test]
    fn verifies_content_type_size_and_digest() {
        let policy = ContentPolicy::default();
        let body = b"{}";
        let digest = super::Digest::sha256(body);
        let content = policy
            .verify(Some(OCI_IMAGE_MANIFEST), Some(&digest.to_string()), body)
            .expect("verified content");
        assert_eq!(content.content(), body);
        assert_eq!(content.digest(), &digest);
    }

    #[test]
    fn rejects_mismatch_and_oversized_content() {
        let policy = ContentPolicy::default().with_max_bytes(1).expect("limit");
        let body = b"{}";
        let wrong = super::Digest::sha256(b"other");
        assert!(
            policy
                .verify(Some(OCI_IMAGE_MANIFEST), Some(&wrong.to_string()), body)
                .is_err()
        );
        let digest = super::Digest::sha256(body);
        assert!(
            policy
                .verify(Some(OCI_IMAGE_MANIFEST), Some(&digest.to_string()), body)
                .is_err()
        );
    }
}
