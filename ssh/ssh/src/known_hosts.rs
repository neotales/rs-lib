//! OpenSSH `known_hosts` parsing, matching, and line writing.
//!
//! The matcher is intentionally small and fail-closed.  It understands the
//! OpenSSH host-token conventions used by this crate, wildcard host patterns,
//! salted `|1|` host entries, and the two markers that affect host-key
//! decisions.  Certificate validation is outside this module: a
//! certificate-authority result means that the offered blob exactly matched a
//! stored CA entry, not that a certificate was verified.

#![allow(clippy::doc_markdown, dead_code)]

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;

/// The prefix used by OpenSSH's version-one hashed host entries.
pub const HASHED_HOST_PREFIX: &str = "|1|";

/// The number of bytes in an OpenSSH version-one host-hash salt.
pub const HASHED_HOST_SALT_LENGTH: usize = 20;

/// The prefix used by OpenSSH SHA-256 public-key fingerprints.
pub const SHA256_FINGERPRINT_PREFIX: &str = "SHA256:";

/// The marker for an explicitly revoked key.
pub const REVOKED_MARKER: &str = "@revoked";

/// The marker for a trusted certificate-authority key.
pub const CERTIFICATE_AUTHORITY_MARKER: &str = "@cert-authority";

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HMAC_SHA1_OUTPUT_LENGTH: usize = 20;

/// A parsing, formatting, or writing error produced by this module.
///
/// Error values intentionally do not contain line contents, key bytes, or
/// other attacker-controlled payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostsError {
    /// A non-comment line did not contain the required fields.
    MalformedLine,
    /// A line used a marker other than `@revoked` or `@cert-authority`.
    UnsupportedMarker,
    /// A standard-base64 token was malformed or non-canonical.
    InvalidBase64,
    /// A `|1|` host token was malformed or had an invalid salt or MAC.
    InvalidHashedHost,
    /// A host pattern or host list was empty or malformed.
    InvalidHostPattern,
    /// A host argument was empty or contained a delimiter or whitespace.
    InvalidHost,
    /// A port was outside the valid TCP port range.
    InvalidPort,
    /// A key blob did not begin with a usable SSH string algorithm field.
    InvalidKeyBlob,
    /// A caller-supplied host-hash salt was not exactly 20 bytes.
    InvalidHashSaltLength,
    /// The operating system did not provide random bytes.
    EntropyFailure,
    /// An output file operation failed.
    Io(std::io::ErrorKind),
}

impl fmt::Display for KnownHostsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedLine => formatter.write_str("known_hosts line is malformed"),
            Self::UnsupportedMarker => formatter.write_str("known_hosts marker is unsupported"),
            Self::InvalidBase64 => formatter.write_str("known_hosts contains invalid base64"),
            Self::InvalidHashedHost => formatter.write_str("known_hosts hashed host is invalid"),
            Self::InvalidHostPattern => formatter.write_str("known_hosts host pattern is invalid"),
            Self::InvalidHost => formatter.write_str("known_hosts host is invalid"),
            Self::InvalidPort => formatter.write_str("known_hosts port is invalid"),
            Self::InvalidKeyBlob => formatter.write_str("SSH public-key blob is invalid"),
            Self::InvalidHashSaltLength => {
                formatter.write_str("known_hosts hash salt must be 20 bytes")
            }
            Self::EntropyFailure => formatter.write_str("known_hosts entropy source failed"),
            Self::Io(_) => formatter.write_str("known_hosts output operation failed"),
        }
    }
}

impl std::error::Error for KnownHostsError {}

/// A compatibility name for [`KnownHostsError`].
pub type Error = KnownHostsError;

/// A compatibility name for [`KnownHostsError`].
pub type ParseError = KnownHostsError;

/// The result of looking up an offered key in a known-hosts file.
///
/// `CertificateAuthority` is deliberately distinct from `Trusted`: this
/// module does not verify certificates and never turns a CA match into trust
/// for a raw host key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostsStatus {
    /// An explicitly matching key is revoked.
    Revoked,
    /// A plain entry exactly matches the offered host key.
    Trusted,
    /// A plain entry matches the host but not the offered key.
    Changed,
    /// A certificate-authority entry exactly matches the offered blob.
    CertificateAuthority,
    /// No applicable entry matched the offered host and key.
    NotFound,
}

impl KnownHostsStatus {
    /// A compatibility name for [`KnownHostsStatus::NotFound`].
    #[allow(non_upper_case_globals)]
    pub const Unknown: Self = Self::NotFound;

    /// A compatibility name for [`KnownHostsStatus::CertificateAuthority`].
    #[allow(non_upper_case_globals)]
    pub const CertAuthority: Self = Self::CertificateAuthority;

    /// Returns whether this status represents an acceptable plain host key.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// A compatibility name for [`KnownHostsStatus`].
pub type KnownHostStatus = KnownHostsStatus;

/// A compatibility name for [`KnownHostsStatus`].
pub type SshKnownHostStatus = KnownHostsStatus;

/// The optional marker written at the beginning of a known-hosts line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostsMarker {
    /// Write an ordinary, unmarked host-key entry.
    None,
    /// Write an `@revoked` entry.
    Revoked,
    /// Write an `@cert-authority` entry.
    CertificateAuthority,
}

impl KnownHostsMarker {
    /// A compatibility name for [`KnownHostsMarker::None`].
    #[allow(non_upper_case_globals)]
    pub const Plain: Self = Self::None;

    /// A compatibility name for [`KnownHostsMarker::CertificateAuthority`].
    #[allow(non_upper_case_globals)]
    pub const CertAuthority: Self = Self::CertificateAuthority;

    /// Returns the wire spelling of the marker, if it has one.
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Revoked => Some(REVOKED_MARKER),
            Self::CertificateAuthority => Some(CERTIFICATE_AUTHORITY_MARKER),
        }
    }
}

/// A compatibility name for [`KnownHostsMarker`].
pub type KnownHostMarker = KnownHostsMarker;

/// A short compatibility name for [`KnownHostsMarker`].
pub type Marker = KnownHostsMarker;

/// A compatibility name for [`KnownHostsMarker`].
pub type AppendMarker = KnownHostsMarker;

/// One explicit line to write through [`append`] or [`format_append_entry`].
///
/// `host_patterns` contains individual patterns; the writer joins them with
/// commas.  When `hash_hosts` is true, every pattern must be a concrete host
/// token and is replaced with a freshly salted OpenSSH `|1|` token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendEntry {
    /// The individual host names or patterns to write.
    pub host_patterns: Vec<String>,
    /// The complete SSH public-key blob to encode on the line.
    pub key_blob: Vec<u8>,
    /// The optional OpenSSH marker.
    pub marker: KnownHostsMarker,
    /// Whether concrete host patterns should be emitted as `|1|` hashes.
    pub hash_hosts: bool,
}

/// A compatibility name for [`AppendEntry`].
pub type KnownHostsAppendEntry = AppendEntry;

impl AppendEntry {
    /// Creates an append description from individual host patterns.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError::InvalidHostPattern`] when no patterns are
    /// supplied.  Pattern syntax and hashing constraints are checked when the
    /// entry is formatted.
    pub fn new<I, S>(
        host_patterns: I,
        key_blob: &[u8],
        marker: KnownHostsMarker,
        hash_hosts: bool,
    ) -> Result<Self, KnownHostsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let host_patterns = host_patterns
            .into_iter()
            .map(|pattern| pattern.as_ref().to_owned())
            .collect::<Vec<_>>();
        if host_patterns.is_empty() {
            return Err(KnownHostsError::InvalidHostPattern);
        }
        Ok(Self {
            host_patterns,
            key_blob: key_blob.to_vec(),
            marker,
            hash_hosts,
        })
    }

    /// Creates an unmarked entry for one concrete host token.
    ///
    /// # Errors
    ///
    /// Returns an error when `host` is empty.
    pub fn plain(host: &str, key_blob: &[u8]) -> Result<Self, KnownHostsError> {
        validate_host(host)?;
        Self::new([host], key_blob, KnownHostsMarker::None, false)
    }

    /// Creates an unmarked entry that will be emitted with a random host hash.
    ///
    /// # Errors
    ///
    /// Returns an error when `host` is empty.
    pub fn hashed(host: &str, key_blob: &[u8]) -> Result<Self, KnownHostsError> {
        validate_host(host)?;
        Self::new([host], key_blob, KnownHostsMarker::None, true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostPattern {
    Plain {
        negated: bool,
        pattern: String,
    },
    Hashed {
        negated: bool,
        salt: [u8; HASHED_HOST_SALT_LENGTH],
        digest: [u8; HMAC_SHA1_OUTPUT_LENGTH],
    },
}

impl HostPattern {
    fn parse(token: &str) -> Result<Self, KnownHostsError> {
        if token.is_empty() {
            return Err(KnownHostsError::InvalidHostPattern);
        }

        let (negated, body) = match token.strip_prefix('!') {
            Some(body) => {
                if body.is_empty() {
                    return Err(KnownHostsError::InvalidHostPattern);
                }
                (true, body)
            }
            None => (false, token),
        };
        if body.starts_with('@') {
            return Err(KnownHostsError::UnsupportedMarker);
        }

        if let Some(hashed) = body.strip_prefix(HASHED_HOST_PREFIX) {
            return parse_hashed_pattern(negated, hashed);
        }

        Ok(Self::Plain {
            negated,
            pattern: body.to_owned(),
        })
    }

    fn matches(&self, host_token: &str) -> bool {
        match self {
            Self::Plain { pattern, .. } => wildcard_match(pattern, host_token),
            Self::Hashed { salt, digest, .. } => {
                let Ok(actual) = hmac_sha1(salt, host_token.as_bytes()) else {
                    return false;
                };
                constant_time_equal(&actual, digest)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    marker: Option<KnownHostsMarker>,
    hosts: Vec<HostPattern>,
    algorithm: String,
    key_blob: Vec<u8>,
}

impl Entry {
    fn matches_host(&self, host_token: &str) -> bool {
        let mut has_positive_match = false;
        let mut has_negative_match = false;
        for pattern in &self.hosts {
            let matches = pattern.matches(host_token);
            if matches {
                if pattern_is_negated(pattern) {
                    has_negative_match = true;
                } else {
                    has_positive_match = true;
                }
            }
        }
        has_positive_match && !has_negative_match
    }

    fn matches_key(&self, offered_key: &[u8], offered_algorithm: Option<&[u8]>) -> bool {
        if self.key_blob != offered_key {
            return false;
        }
        let line_algorithm = first_ssh_string(&self.key_blob);
        line_algorithm.is_some_and(|value| value == self.algorithm.as_bytes())
            && offered_algorithm.is_some_and(|value| value == self.algorithm.as_bytes())
    }
}

fn pattern_is_negated(pattern: &HostPattern) -> bool {
    match pattern {
        HostPattern::Plain { negated, .. } | HostPattern::Hashed { negated, .. } => *negated,
    }
}

/// A parsed, immutable OpenSSH known-hosts file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

/// A compatibility name for [`KnownHosts`].
pub type KnownHostsFile = KnownHosts;

impl KnownHosts {
    /// Parses a complete known-hosts document.
    ///
    /// Empty lines and lines whose first non-whitespace character is `#` are
    /// ignored.  Any malformed non-comment line, including an unknown marker,
    /// rejects the complete document.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError`] for malformed fields, invalid base64, an
    /// invalid hashed host token, or an unknown marker.
    pub fn parse(text: &str) -> Result<Self, KnownHostsError> {
        let mut entries = Vec::new();
        for raw_line in text.split('\n') {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields = line.split_whitespace().collect::<Vec<_>>();
            let Some(first_field) = fields.first().copied() else {
                return Err(KnownHostsError::MalformedLine);
            };

            let (marker, host_index) = if first_field.starts_with('@') {
                let marker = match first_field {
                    REVOKED_MARKER => KnownHostsMarker::Revoked,
                    CERTIFICATE_AUTHORITY_MARKER => KnownHostsMarker::CertificateAuthority,
                    _ => return Err(KnownHostsError::UnsupportedMarker),
                };
                (Some(marker), 1)
            } else {
                (None, 0)
            };

            if fields.len() < host_index + 3 {
                return Err(KnownHostsError::MalformedLine);
            }
            for (index, field) in fields.iter().enumerate() {
                if field.starts_with('#') {
                    break;
                }
                if field.starts_with('@') && !(index == 0 && marker.is_some()) {
                    return Err(KnownHostsError::UnsupportedMarker);
                }
            }

            let host_field = fields
                .get(host_index)
                .copied()
                .ok_or(KnownHostsError::MalformedLine)?;
            let algorithm = fields
                .get(host_index + 1)
                .copied()
                .ok_or(KnownHostsError::MalformedLine)?;
            let encoded_key = fields
                .get(host_index + 2)
                .copied()
                .ok_or(KnownHostsError::MalformedLine)?;
            if algorithm.is_empty() || !algorithm.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(KnownHostsError::InvalidKeyBlob);
            }
            let hosts = parse_host_list(host_field)?;
            let key_blob = decode_base64(encoded_key)?;
            if key_blob.is_empty() {
                return Err(KnownHostsError::InvalidKeyBlob);
            }
            entries.push(Entry {
                marker,
                hosts,
                algorithm: algorithm.to_owned(),
                key_blob,
            });
        }
        Ok(Self { entries })
    }

    /// Checks an offered key against this file.
    ///
    /// Invalid host arguments are treated as not found.  Use
    /// [`Self::try_check`] when malformed input must be distinguished from a
    /// normal negative lookup.
    #[must_use]
    pub fn check(&self, host: &str, port: u16, key_blob: &[u8]) -> KnownHostsStatus {
        let Ok(host_token) = try_host_token(host, port) else {
            return KnownHostsStatus::NotFound;
        };
        self.check_host_token(&host_token, key_blob)
    }

    /// Checks an already formed OpenSSH host token.
    #[must_use]
    pub fn check_host_token(&self, host_token: &str, key_blob: &[u8]) -> KnownHostsStatus {
        let offered_algorithm = first_ssh_string(key_blob);
        let mut revoked = false;
        let mut trusted = false;
        let mut plain_host_match = false;
        let mut certificate_authority = false;

        for entry in &self.entries {
            if !entry.matches_host(host_token) {
                continue;
            }
            plain_host_match |= entry.marker.is_none();
            let key_matches = entry.matches_key(key_blob, offered_algorithm);
            match entry.marker {
                Some(KnownHostsMarker::Revoked) if key_matches => revoked = true,
                None if key_matches => trusted = true,
                Some(KnownHostsMarker::CertificateAuthority) if key_matches => {
                    certificate_authority = true;
                }
                _ => {}
            }
        }

        if revoked {
            KnownHostsStatus::Revoked
        } else if trusted {
            KnownHostsStatus::Trusted
        } else if plain_host_match {
            KnownHostsStatus::Changed
        } else if certificate_authority {
            KnownHostsStatus::CertificateAuthority
        } else {
            KnownHostsStatus::NotFound
        }
    }

    /// Checks an offered key and reports malformed host or key arguments.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError::InvalidHost`], [`KnownHostsError::InvalidPort`],
    /// or [`KnownHostsError::InvalidKeyBlob`] for malformed arguments.
    pub fn try_check(
        &self,
        host: &str,
        port: u16,
        key_blob: &[u8],
    ) -> Result<KnownHostsStatus, KnownHostsError> {
        let _host_token = try_host_token(host, port)?;
        if first_ssh_string(key_blob).is_none() {
            return Err(KnownHostsError::InvalidKeyBlob);
        }
        Ok(self.check(host, port, key_blob))
    }

    /// Returns the number of parsed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the file contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl FromStr for KnownHosts {
    type Err = KnownHostsError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Parses a complete known-hosts document.
///
/// This is the free-function form of [`KnownHosts::parse`].
pub fn parse(text: &str) -> Result<KnownHosts, KnownHostsError> {
    KnownHosts::parse(text)
}

/// Checks an offered key using a parsed known-hosts document.
///
/// This is the free-function form of [`KnownHosts::check`].
#[must_use]
pub fn check(known_hosts: &KnownHosts, host: &str, port: u16, key_blob: &[u8]) -> KnownHostsStatus {
    known_hosts.check(host, port, key_blob)
}

/// Verifies an offered key using a parsed known-hosts document.
///
/// This is a compatibility spelling of [`check`].
#[must_use]
pub fn verify(
    known_hosts: &KnownHosts,
    host: &str,
    port: u16,
    key_blob: &[u8],
) -> KnownHostsStatus {
    known_hosts.check(host, port, key_blob)
}

/// Forms the OpenSSH host token used for a connection.
///
/// Port 22 uses the hostname directly.  Every other port uses the
/// `[hostname]:port` form.  The returned value preserves the caller's case;
/// matching is case-sensitive as specified by this ticket.
pub fn format_host_token(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Validates and forms the OpenSSH host token used for a connection.
///
/// # Errors
///
/// Returns [`KnownHostsError::InvalidHost`] for an empty host or a host with
/// whitespace, a comma, or a marker prefix, and [`KnownHostsError::InvalidPort`]
/// for port zero.
pub fn try_host_token(host: &str, port: u16) -> Result<String, KnownHostsError> {
    validate_host(host)?;
    if port == 0 {
        return Err(KnownHostsError::InvalidPort);
    }
    Ok(format_host_token(host, port))
}

/// A compatibility name for [`try_host_token`].
pub fn host_token(host: &str, port: u16) -> Result<String, KnownHostsError> {
    try_host_token(host, port)
}

/// Hashes one already formed host token with a caller-supplied salt.
///
/// The salt must contain exactly 20 bytes.  The returned token uses padded
/// standard base64 for both the salt and HMAC-SHA1 result.
///
/// # Errors
///
/// Returns [`KnownHostsError::InvalidHashSaltLength`] when `salt` is not
/// exactly 20 bytes.
pub fn hash_host_token_with_salt(host_token: &str, salt: &[u8]) -> Result<String, KnownHostsError> {
    if salt.len() != HASHED_HOST_SALT_LENGTH {
        return Err(KnownHostsError::InvalidHashSaltLength);
    }
    let digest = hmac_sha1(salt, host_token.as_bytes())?;
    Ok(format!(
        "{HASHED_HOST_PREFIX}{}|{}",
        encode_base64(salt),
        encode_base64(&digest)
    ))
}

/// A compatibility spelling of [`hash_host_token_with_salt`].
pub fn hash_host_with_salt(host_token: &str, salt: &[u8]) -> Result<String, KnownHostsError> {
    hash_host_token_with_salt(host_token, salt)
}

/// Hashes one already formed host token with a fresh 20-byte salt.
///
/// # Errors
///
/// Returns [`KnownHostsError::EntropyFailure`] if operating-system entropy is
/// unavailable, or [`KnownHostsError::InvalidHashSaltLength`] if the internal
/// salt size invariant is violated.
pub fn hash_host_token(host_token: &str) -> Result<String, KnownHostsError> {
    let mut salt = [0_u8; HASHED_HOST_SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(|_error| KnownHostsError::EntropyFailure)?;
    hash_host_token_with_salt(host_token, &salt)
}

/// A compatibility spelling of [`hash_host_token`].
pub fn hash_host(host_token: &str) -> Result<String, KnownHostsError> {
    hash_host_token(host_token)
}

/// Hashes a host and port using a fresh OpenSSH salt.
///
/// # Errors
///
/// Returns any error from [`try_host_token`] or [`hash_host_token`].
pub fn hash_hostname(host: &str, port: u16) -> Result<String, KnownHostsError> {
    let token = try_host_token(host, port)?;
    hash_host_token(&token)
}

/// Hashes a host and port with a caller-supplied OpenSSH salt.
///
/// # Errors
///
/// Returns any error from [`try_host_token`] or
/// [`hash_host_token_with_salt`].
pub fn hash_hostname_with_salt(
    host: &str,
    port: u16,
    salt: &[u8],
) -> Result<String, KnownHostsError> {
    let token = try_host_token(host, port)?;
    hash_host_token_with_salt(&token, salt)
}

/// Returns the OpenSSH SHA-256 fingerprint of a raw public-key blob.
///
/// The SHA-256 digest is encoded as unpadded standard base64 and prefixed
/// with `SHA256:`.  No padding character is emitted.
#[must_use]
pub fn fingerprint(key_blob: &[u8]) -> String {
    let digest = sha2::Sha256::digest(key_blob);
    let encoded = encode_base64(digest.as_slice());
    let unpadded = encoded.trim_end_matches('=');
    format!("{SHA256_FINGERPRINT_PREFIX}{unpadded}")
}

/// A compatibility spelling of [`fingerprint`].
#[must_use]
pub fn fingerprint_sha256(key_blob: &[u8]) -> String {
    fingerprint(key_blob)
}

/// A compatibility spelling of [`fingerprint`].
#[must_use]
pub fn sha256_fingerprint(key_blob: &[u8]) -> String {
    fingerprint(key_blob)
}

/// Encodes bytes as padded standard base64.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let first = match chunk.first() {
            Some(value) => *value,
            None => continue,
        };
        let second = match chunk.get(1) {
            Some(value) => *value,
            None => 0,
        };
        let third = match chunk.get(2) {
            Some(value) => *value,
            None => 0,
        };
        push_base64_character(&mut output, (first >> 2) & 0x3f);
        push_base64_character(&mut output, ((first & 0x03) << 4) | (second >> 4));
        if chunk.len() > 1 {
            push_base64_character(&mut output, ((second & 0x0f) << 2) | (third >> 6));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            push_base64_character(&mut output, third & 0x3f);
        } else {
            output.push('=');
        }
    }
    output
}

/// Encodes bytes as unpadded standard base64.
#[must_use]
pub fn encode_base64_unpadded(bytes: &[u8]) -> String {
    encode_base64(bytes).trim_end_matches('=').to_owned()
}

/// Decodes padded standard base64.
///
/// The decoder rejects whitespace, URL-safe characters, misplaced padding,
/// invalid lengths, and non-zero discarded pad bits.
///
/// # Errors
///
/// Returns [`KnownHostsError::InvalidBase64`] for every malformed input.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, KnownHostsError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(KnownHostsError::InvalidBase64);
    }

    let mut padding = 0_usize;
    while padding < bytes.len() && bytes.get(bytes.len() - 1 - padding) == Some(&b'=') {
        padding += 1;
    }
    if padding > 2 {
        return Err(KnownHostsError::InvalidBase64);
    }
    let data_len = bytes
        .len()
        .checked_sub(padding)
        .ok_or(KnownHostsError::InvalidBase64)?;
    if data_len % 4 == 1 {
        return Err(KnownHostsError::InvalidBase64);
    }
    if padding > 0
        && bytes
            .get(..data_len)
            .is_some_and(|part| part.contains(&b'='))
    {
        return Err(KnownHostsError::InvalidBase64);
    }

    let mut output = Vec::with_capacity(data_len / 4 * 3);
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let first = base64_value(*bytes.get(offset).ok_or(KnownHostsError::InvalidBase64)?)?;
        let second = base64_value(
            *bytes
                .get(offset + 1)
                .ok_or(KnownHostsError::InvalidBase64)?,
        )?;
        let third_byte = bytes
            .get(offset + 2)
            .copied()
            .ok_or(KnownHostsError::InvalidBase64)?;
        let fourth_byte = bytes
            .get(offset + 3)
            .copied()
            .ok_or(KnownHostsError::InvalidBase64)?;
        let last_quartet = offset + 4 == bytes.len();
        let third_is_padding = third_byte == b'=';
        let fourth_is_padding = fourth_byte == b'=';

        if third_is_padding {
            if !last_quartet || !fourth_is_padding || padding != 2 {
                return Err(KnownHostsError::InvalidBase64);
            }
            if second & 0x0f != 0 {
                return Err(KnownHostsError::InvalidBase64);
            }
            output.push((first << 2) | (second >> 4));
        } else {
            let third = base64_value(third_byte)?;
            if fourth_is_padding {
                if !last_quartet || padding != 1 {
                    return Err(KnownHostsError::InvalidBase64);
                }
                if third & 0x03 != 0 {
                    return Err(KnownHostsError::InvalidBase64);
                }
                output.push((first << 2) | (second >> 4));
                output.push(((second & 0x0f) << 4) | (third >> 2));
            } else {
                let fourth = base64_value(fourth_byte)?;
                output.push((first << 2) | (second >> 4));
                output.push(((second & 0x0f) << 4) | (third >> 2));
                output.push(((third & 0x03) << 6) | fourth);
            }
        }
        offset += 4;
    }
    Ok(output)
}

/// A compatibility spelling of [`encode_base64`].
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    encode_base64(bytes)
}

/// A compatibility spelling of [`decode_base64`].
pub fn base64_decode(text: &str) -> Result<Vec<u8>, KnownHostsError> {
    decode_base64(text)
}

/// Formats one newline-terminated known-hosts line.
///
/// # Errors
///
/// Returns [`KnownHostsError`] for an invalid host pattern, invalid key blob,
/// or entropy failure when `hash_hosts` is enabled.
pub fn format_append_entry(entry: &AppendEntry) -> Result<String, KnownHostsError> {
    format_append_entry_inner(entry, None)
}

/// Formats one newline-terminated known-hosts line with a fixed hash salt.
///
/// This is primarily useful for deterministic persistence and tests.  The
/// salt is used for every pattern when `entry.hash_hosts` is true.
///
/// # Errors
///
/// Returns [`KnownHostsError`] for an invalid host pattern, invalid key blob,
/// or a salt whose length is not 20 bytes.
pub fn format_append_entry_with_salt(
    entry: &AppendEntry,
    salt: &[u8],
) -> Result<String, KnownHostsError> {
    if entry.hash_hosts && salt.len() != HASHED_HOST_SALT_LENGTH {
        return Err(KnownHostsError::InvalidHashSaltLength);
    }
    format_append_entry_inner(entry, Some(salt))
}

/// Writes one newline-terminated known-hosts line to `writer`.
///
/// # Errors
///
/// Returns any formatting error or an [`KnownHostsError::Io`] error from the
/// writer.
pub fn append<W: Write>(writer: &mut W, entry: &AppendEntry) -> Result<(), KnownHostsError> {
    let line = format_append_entry(entry)?;
    write_line(writer, &line)
}

/// Writes one entry with a caller-supplied hash salt.
///
/// # Errors
///
/// Returns any formatting error, an invalid salt length, or an
/// [`KnownHostsError::Io`] error from the writer.
pub fn append_with_salt<W: Write>(
    writer: &mut W,
    entry: &AppendEntry,
    salt: &[u8],
) -> Result<(), KnownHostsError> {
    let line = format_append_entry_with_salt(entry, salt)?;
    write_line(writer, &line)
}

fn write_line<W: Write>(writer: &mut W, line: &str) -> Result<(), KnownHostsError> {
    writer
        .write_all(line.as_bytes())
        .map_err(|error| KnownHostsError::Io(error.kind()))
}

/// Writes one entry to a file, creating its parent directory when needed.
///
/// # Errors
///
/// Returns any formatting error, an entropy error while hashing, or an
/// [`KnownHostsError::Io`] error while opening or writing the file.
pub fn append_to_path<P: AsRef<Path>>(path: P, entry: &AppendEntry) -> Result<(), KnownHostsError> {
    let path = path.as_ref();
    let line = format_append_entry(entry)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| KnownHostsError::Io(error.kind()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| KnownHostsError::Io(error.kind()))?;
    write_line(&mut file, &line)
}

/// A compatibility spelling of [`append_to_path`].
pub fn append_file<P: AsRef<Path>>(path: P, entry: &AppendEntry) -> Result<(), KnownHostsError> {
    append_to_path(path, entry)
}

/// Writes an unmarked entry for one validated host token.
///
/// # Errors
///
/// Returns any error from [`try_host_token`] or [`append`].
pub fn append_plain<W: Write>(
    writer: &mut W,
    host: &str,
    port: u16,
    key_blob: &[u8],
) -> Result<(), KnownHostsError> {
    let token = try_host_token(host, port)?;
    let entry = AppendEntry {
        host_patterns: vec![token],
        key_blob: key_blob.to_vec(),
        marker: KnownHostsMarker::None,
        hash_hosts: false,
    };
    append(writer, &entry)
}

/// Writes an unmarked entry using a fresh salted host hash.
///
/// # Errors
///
/// Returns any error from [`try_host_token`], [`hash_host_token`], or
/// [`append`].
pub fn append_hashed<W: Write>(
    writer: &mut W,
    host: &str,
    port: u16,
    key_blob: &[u8],
) -> Result<(), KnownHostsError> {
    let token = try_host_token(host, port)?;
    let entry = AppendEntry {
        host_patterns: vec![token],
        key_blob: key_blob.to_vec(),
        marker: KnownHostsMarker::None,
        hash_hosts: true,
    };
    append(writer, &entry)
}

/// Writes an unmarked entry using a caller-supplied host-hash salt.
///
/// # Errors
///
/// Returns any error from [`try_host_token`], [`append_with_salt`], or an
/// invalid salt length.
pub fn append_hashed_with_salt<W: Write>(
    writer: &mut W,
    host: &str,
    port: u16,
    key_blob: &[u8],
    salt: &[u8],
) -> Result<(), KnownHostsError> {
    let token = try_host_token(host, port)?;
    let entry = AppendEntry {
        host_patterns: vec![token],
        key_blob: key_blob.to_vec(),
        marker: KnownHostsMarker::None,
        hash_hosts: true,
    };
    append_with_salt(writer, &entry, salt)
}

/// Writes an `@revoked` entry for one validated host token.
///
/// # Errors
///
/// Returns any error from [`try_host_token`] or [`append`].
pub fn append_revoked<W: Write>(
    writer: &mut W,
    host: &str,
    port: u16,
    key_blob: &[u8],
) -> Result<(), KnownHostsError> {
    let token = try_host_token(host, port)?;
    let entry = AppendEntry {
        host_patterns: vec![token],
        key_blob: key_blob.to_vec(),
        marker: KnownHostsMarker::Revoked,
        hash_hosts: false,
    };
    append(writer, &entry)
}

/// Writes an `@cert-authority` entry for one validated host token.
///
/// # Errors
///
/// Returns any error from [`try_host_token`] or [`append`].
pub fn append_certificate_authority<W: Write>(
    writer: &mut W,
    host: &str,
    port: u16,
    key_blob: &[u8],
) -> Result<(), KnownHostsError> {
    let token = try_host_token(host, port)?;
    let entry = AppendEntry {
        host_patterns: vec![token],
        key_blob: key_blob.to_vec(),
        marker: KnownHostsMarker::CertificateAuthority,
        hash_hosts: false,
    };
    append(writer, &entry)
}

fn format_append_entry_inner(
    entry: &AppendEntry,
    fixed_salt: Option<&[u8]>,
) -> Result<String, KnownHostsError> {
    if entry.host_patterns.is_empty() {
        return Err(KnownHostsError::InvalidHostPattern);
    }
    let algorithm = read_key_algorithm(&entry.key_blob)?;
    let mut line = String::new();
    if let Some(marker) = entry.marker.as_str() {
        line.push_str(marker);
        line.push(' ');
    }

    for (index, pattern) in entry.host_patterns.iter().enumerate() {
        if index != 0 {
            line.push(',');
        }
        if entry.hash_hosts {
            validate_hashable_pattern(pattern)?;
            let hashed = if let Some(salt) = fixed_salt {
                hash_host_token_with_salt(pattern, salt)?
            } else {
                hash_host_token(pattern)?
            };
            line.push_str(&hashed);
        } else {
            validate_append_pattern(pattern)?;
            line.push_str(pattern);
        }
    }
    line.push(' ');
    line.push_str(&algorithm);
    line.push(' ');
    line.push_str(&encode_base64(&entry.key_blob));
    line.push('\n');
    Ok(line)
}

fn validate_host(host: &str) -> Result<(), KnownHostsError> {
    if host.is_empty()
        || host.starts_with('@')
        || host.contains(',')
        || host.contains('#')
        || host.chars().any(char::is_whitespace)
    {
        return Err(KnownHostsError::InvalidHost);
    }
    Ok(())
}

fn validate_append_pattern(pattern: &str) -> Result<(), KnownHostsError> {
    if pattern.is_empty()
        || pattern.starts_with('@')
        || pattern.contains(',')
        || pattern.contains('#')
        || pattern.chars().any(char::is_whitespace)
    {
        return Err(KnownHostsError::InvalidHostPattern);
    }
    if pattern.starts_with(HASHED_HOST_PREFIX)
        || pattern
            .strip_prefix('!')
            .is_some_and(|body| body.starts_with(HASHED_HOST_PREFIX))
    {
        let hashed_pattern = match pattern.strip_prefix('!') {
            Some(body) => body,
            None => pattern,
        };
        parse_hashed_pattern(false, hashed_pattern)?;
    }
    Ok(())
}

fn validate_hashable_pattern(pattern: &str) -> Result<(), KnownHostsError> {
    validate_append_pattern(pattern)?;
    let body = match pattern.strip_prefix('!') {
        Some(value) => value,
        None => pattern,
    };
    if pattern.starts_with('!')
        || body.is_empty()
        || body.starts_with(HASHED_HOST_PREFIX)
        || body.contains('*')
        || body.contains('?')
    {
        return Err(KnownHostsError::InvalidHostPattern);
    }
    Ok(())
}

fn parse_host_list(field: &str) -> Result<Vec<HostPattern>, KnownHostsError> {
    if field.is_empty() {
        return Err(KnownHostsError::InvalidHostPattern);
    }
    field
        .split(',')
        .map(HostPattern::parse)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_hashed_pattern(negated: bool, encoded: &str) -> Result<HostPattern, KnownHostsError> {
    let mut pieces = encoded.split('|');
    let salt_text = pieces.next().ok_or(KnownHostsError::InvalidHashedHost)?;
    let digest_text = pieces.next().ok_or(KnownHostsError::InvalidHashedHost)?;
    if pieces.next().is_some() || salt_text.is_empty() || digest_text.is_empty() {
        return Err(KnownHostsError::InvalidHashedHost);
    }

    let salt_bytes =
        decode_padded_base64(salt_text).map_err(|_error| KnownHostsError::InvalidHashedHost)?;
    let digest_bytes =
        decode_padded_base64(digest_text).map_err(|_error| KnownHostsError::InvalidHashedHost)?;
    if salt_bytes.len() != HASHED_HOST_SALT_LENGTH || digest_bytes.len() != HMAC_SHA1_OUTPUT_LENGTH
    {
        return Err(KnownHostsError::InvalidHashedHost);
    }
    let salt = salt_bytes
        .try_into()
        .map_err(|_error| KnownHostsError::InvalidHashedHost)?;
    let digest = digest_bytes
        .try_into()
        .map_err(|_error| KnownHostsError::InvalidHashedHost)?;
    Ok(HostPattern::Hashed {
        negated,
        salt,
        digest,
    })
}

fn decode_padded_base64(text: &str) -> Result<Vec<u8>, KnownHostsError> {
    if !text.ends_with('=') {
        return Err(KnownHostsError::InvalidBase64);
    }
    decode_base64(text)
}

fn read_key_algorithm(key_blob: &[u8]) -> Result<String, KnownHostsError> {
    let algorithm = first_ssh_string(key_blob).ok_or(KnownHostsError::InvalidKeyBlob)?;
    let algorithm =
        std::str::from_utf8(algorithm).map_err(|_error| KnownHostsError::InvalidKeyBlob)?;
    if algorithm.is_empty()
        || algorithm.starts_with('@')
        || !algorithm.bytes().all(|byte| byte.is_ascii_graphic())
        || algorithm
            .bytes()
            .any(|byte| matches!(byte, b'#' | b',' | b'|'))
    {
        return Err(KnownHostsError::InvalidKeyBlob);
    }
    Ok(algorithm.to_owned())
}

fn first_ssh_string(input: &[u8]) -> Option<&[u8]> {
    let length_bytes = input.get(..4)?;
    let length = u32::from_be_bytes(length_bytes.try_into().ok()?);
    let length = usize::try_from(length).ok()?;
    let end = 4_usize.checked_add(length)?;
    input.get(4..end)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA1_OUTPUT_LENGTH], KnownHostsError> {
    type HmacSha1 = Hmac<sha1::Sha1>;
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(key)
        .map_err(|_error| KnownHostsError::InvalidHashSaltLength)?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; HMAC_SHA1_OUTPUT_LENGTH];
    output.copy_from_slice(bytes.as_slice());
    Ok(output)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn push_base64_character(output: &mut String, index: u8) {
    if let Some(character) = BASE64_ALPHABET.get(index as usize) {
        output.push(char::from(*character));
    }
}

fn base64_value(byte: u8) -> Result<u8, KnownHostsError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(KnownHostsError::InvalidBase64),
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
    let mut pattern_index = 0_usize;
    let mut value_index = 0_usize;
    let mut star_index = None;
    let mut star_value_index = 0_usize;

    while value_index < value.len() {
        match pattern.get(pattern_index).copied() {
            Some('*') => {
                star_index = Some(pattern_index);
                star_value_index = value_index;
                pattern_index += 1;
            }
            Some('?') => {
                pattern_index += 1;
                value_index += 1;
            }
            Some(expected) if value.get(value_index).copied() == Some(expected) => {
                pattern_index += 1;
                value_index += 1;
            }
            _ => {
                let Some(star) = star_index else {
                    return false;
                };
                star_value_index += 1;
                value_index = star_value_index;
                pattern_index = star + 1;
            }
        }
    }
    while pattern.get(pattern_index) == Some(&'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}
