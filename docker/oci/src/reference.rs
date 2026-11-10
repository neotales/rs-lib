//! Normalized registry endpoints, repository names, and image references.

use std::fmt;

use url::{Host, Url};

use crate::digest::{Digest, DigestError};

/// The registry used when an image reference does not name one explicitly.
pub const DEFAULT_REGISTRY: &str = "docker.io";
/// Docker Hub's registry-facing hostname.
pub const DOCKER_HUB_REGISTRY: &str = "registry-1.docker.io";

/// The transport scheme used to contact a registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RegistryScheme {
    /// Plain HTTP, intended for local disposable registries.
    Http,
    /// HTTPS, the default for remote registries.
    Https,
}

impl RegistryScheme {
    /// Returns the URL scheme name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl fmt::Display for RegistryScheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated, credential-free registry endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RegistryEndpoint {
    scheme: RegistryScheme,
    host: String,
    port: Option<u16>,
    base_path: String,
}

impl RegistryEndpoint {
    /// Parses and normalizes an HTTP(S) registry URL.
    ///
    /// A missing scheme defaults to HTTPS.  User information, query strings,
    /// fragments, and path traversal are rejected rather than retained in a
    /// request URL.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid URL, scheme, host, path, or embedded
    /// user information.
    pub fn parse(value: &str) -> Result<Self, ReferenceError> {
        let value = value.trim();
        if value.is_empty() || contains_control(value) {
            return Err(ReferenceError::EmptyEndpoint);
        }
        let candidate = if value.contains("://") {
            value.to_owned()
        } else {
            format!("https://{value}")
        };
        let parsed = Url::parse(&candidate).map_err(|_| ReferenceError::InvalidEndpoint)?;
        Self::from_url(&parsed)
    }

    /// Constructs an endpoint from already separated URL components.
    ///
    /// # Errors
    ///
    /// Returns an error when a component or path prefix is invalid.
    pub fn from_parts(
        scheme: RegistryScheme,
        host: &str,
        port: Option<u16>,
        base_path: &str,
    ) -> Result<Self, ReferenceError> {
        if host.is_empty() || contains_control(host) || host.contains('@') {
            return Err(ReferenceError::InvalidEndpoint);
        }
        let base_path = base_path.trim_matches('/');
        let candidate = if base_path.is_empty() {
            format!("{scheme}://{host}/")
        } else {
            format!("{scheme}://{host}/{base_path}/")
        };
        let parsed = Url::parse(&candidate).map_err(|_| ReferenceError::InvalidEndpoint)?;
        let mut endpoint = Self::from_url(&parsed)?;
        if let Some(port) = port {
            endpoint.port = (port != scheme.default_port()).then_some(port);
        }
        Ok(endpoint)
    }

    /// Returns the endpoint scheme.
    #[must_use]
    pub const fn scheme(&self) -> RegistryScheme {
        self.scheme
    }

    /// Returns the normalized host, including brackets for IPv6 literals.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns an explicitly configured non-default port.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the normalized path prefix without leading or trailing slashes.
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Returns the host and optional port used as a registry key.
    #[must_use]
    pub fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// Returns a canonical absolute URL with one trailing slash.
    #[must_use]
    pub fn url(&self) -> String {
        let path = if self.base_path.is_empty() {
            String::new()
        } else {
            format!("/{}/", self.base_path)
        };
        format!("{}://{}{path}", self.scheme, self.authority())
    }

    /// Alias for [`RegistryEndpoint::url`].
    #[must_use]
    pub fn as_url(&self) -> String {
        self.url()
    }

    /// Builds a request path below the endpoint's normalized base path.
    #[must_use]
    pub fn request_path(&self, suffix: &str) -> String {
        let suffix = suffix.trim_start_matches('/');
        if self.base_path.is_empty() {
            format!("/{suffix}")
        } else {
            format!("/{}/{suffix}", self.base_path)
        }
    }

    /// Resolves a registry upload location and rejects cross-origin results.
    ///
    /// Relative locations are resolved against this endpoint.  Absolute
    /// locations must have the same scheme, host, and effective port.  Query
    /// parameters are retained because the Distribution upload protocol uses
    /// them for the final digest, but fragments and user information are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::ForeignOrigin`] for a different origin and
    /// [`ReferenceError::InvalidLocation`] for malformed locations.
    pub fn resolve_location(&self, location: &str) -> Result<String, ReferenceError> {
        if location.trim().is_empty() || contains_control(location) {
            return Err(ReferenceError::InvalidLocation);
        }
        let base = self.url();
        let parsed = match Url::parse(location) {
            Ok(absolute) => absolute,
            Err(_) => Url::parse(&base)
                .and_then(|url| url.join(location))
                .map_err(|_| ReferenceError::InvalidLocation)?,
        };
        if parsed.fragment().is_some() {
            return Err(ReferenceError::InvalidLocation);
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || !same_origin_url(&parsed, self.scheme, &self.host, self.port)
        {
            return Err(ReferenceError::ForeignOrigin);
        }
        Ok(parsed.to_string())
    }

    /// Returns whether two endpoints have the same effective origin.
    #[must_use]
    pub fn same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.host.eq_ignore_ascii_case(&other.host)
            && effective_port(self.scheme, self.port) == effective_port(other.scheme, other.port)
    }

    fn from_url(parsed: &Url) -> Result<Self, ReferenceError> {
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ReferenceError::UnsupportedScheme(
                parsed.scheme().to_owned(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ReferenceError::CredentialsInUrl);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ReferenceError::EndpointHasQueryOrFragment);
        }
        let scheme = if parsed.scheme() == "http" {
            RegistryScheme::Http
        } else {
            RegistryScheme::Https
        };
        let host = match parsed.host() {
            Some(Host::Domain(domain)) => {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty() || contains_control(&domain) {
                    return Err(ReferenceError::InvalidEndpoint);
                }
                domain
            }
            Some(Host::Ipv4(address)) => address.to_string(),
            Some(Host::Ipv6(address)) => format!("[{address}]"),
            None => return Err(ReferenceError::InvalidEndpoint),
        };
        let port = parsed.port().filter(|port| *port != scheme.default_port());
        let base_path = normalize_path_prefix(parsed.path())?;
        Ok(Self {
            scheme,
            host,
            port,
            base_path,
        })
    }
}

impl fmt::Display for RegistryEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.url())
    }
}

/// The immutable or mutable part of a registry reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceKind {
    /// A mutable tag.
    Tag(String),
    /// An immutable content digest.
    Digest(Digest),
}

impl ReferenceKind {
    /// Returns the tag, if this is a tag reference.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Tag(tag) => Some(tag),
            Self::Digest(_) => None,
        }
    }

    /// Returns the digest, if this is a digest reference.
    #[must_use]
    pub fn digest(&self) -> Option<&Digest> {
        match self {
            Self::Tag(_) => None,
            Self::Digest(digest) => Some(digest),
        }
    }

    /// Returns whether this reference is digest-addressed.
    #[must_use]
    pub const fn is_digest(&self) -> bool {
        matches!(self, Self::Digest(_))
    }

    /// Returns the reference spelling without a repository or registry.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Tag(tag) => tag.clone(),
            Self::Digest(digest) => digest.to_string(),
        }
    }
}

/// A normalized registry/repository/reference tuple.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RegistryReference {
    endpoint: RegistryEndpoint,
    registry: String,
    repository: String,
    kind: ReferenceKind,
}

impl fmt::Display for ReferenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(tag) => formatter.write_str(tag),
            Self::Digest(digest) => write!(formatter, "{digest}"),
        }
    }
}

impl RegistryReference {
    /// Parses an image reference.
    ///
    /// A bare repository is normalized to Docker Hub's `library` namespace
    /// and the conventional `latest` tag.  Use [`RegistryReference::parse_explicit`]
    /// when a tag or digest must be supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed references, repositories, tags, or
    /// digests.
    pub fn parse(value: &str) -> Result<Self, ReferenceError> {
        Self::parse_inner(value, false)
    }

    /// Parses a reference and rejects an omitted tag or digest.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::MissingReference`] when no tag or digest is
    /// supplied, or another reference error for malformed input.
    pub fn parse_explicit(value: &str) -> Result<Self, ReferenceError> {
        Self::parse_inner(value, true)
    }

    /// Alias for [`RegistryReference::parse`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`RegistryReference::parse`].
    pub fn parse_with_default_tag(value: &str) -> Result<Self, ReferenceError> {
        Self::parse(value)
    }

    /// Constructs a reference from separately supplied components.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid registry, repository, tag, or digest.
    pub fn from_parts(
        registry: &str,
        repository: &str,
        reference: &str,
    ) -> Result<Self, ReferenceError> {
        let endpoint = RegistryEndpoint::parse(registry)?;
        let (repository, kind) = split_repository_reference(repository, reference, false)?;
        let repository = normalize_repository_for_endpoint(&endpoint, &repository)?;
        Ok(Self::new(endpoint, repository, kind))
    }

    /// Constructs a tag reference.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid registry, repository, or tag.
    pub fn from_tag(registry: &str, repository: &str, tag: &str) -> Result<Self, ReferenceError> {
        validate_tag(tag)?;
        Self::from_parts(registry, repository, tag)
    }

    /// Constructs a digest reference.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid registry or repository.
    pub fn from_digest(
        registry: &str,
        repository: &str,
        digest: &Digest,
    ) -> Result<Self, ReferenceError> {
        Self::from_parts(registry, repository, &digest.to_string())
    }

    /// Returns the normalized registry host and optional port.
    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// Returns the validated repository name.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the tag or digest component.
    #[must_use]
    pub const fn reference(&self) -> &ReferenceKind {
        &self.kind
    }

    /// Returns the tag component, if present.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.kind.tag()
    }

    /// Returns the digest component, if present.
    #[must_use]
    pub fn digest(&self) -> Option<&Digest> {
        self.kind.digest()
    }

    /// Returns whether this reference is digest-addressed.
    #[must_use]
    pub const fn is_digest(&self) -> bool {
        self.kind.is_digest()
    }

    /// Returns the normalized endpoint used to contact the registry.
    #[must_use]
    pub const fn endpoint(&self) -> &RegistryEndpoint {
        &self.endpoint
    }

    /// Returns the canonical reference spelling.
    #[must_use]
    pub fn as_string(&self) -> String {
        self.to_string()
    }

    /// Returns a URL-style spelling including the endpoint scheme.
    #[must_use]
    pub fn as_url(&self) -> String {
        let separator = if self.is_digest() { "@" } else { ":" };
        format!(
            "{}://{}/{}{separator}{}",
            self.endpoint.scheme,
            self.registry,
            self.repository,
            self.kind.as_str()
        )
    }

    /// Returns the API path for this reference's manifest.
    #[must_use]
    pub fn manifest_path(&self) -> String {
        self.endpoint.request_path(&format!(
            "v2/{}/manifests/{}",
            self.repository,
            self.kind.as_str()
        ))
    }

    /// Returns the API path for a blob digest.
    #[must_use]
    pub fn blob_path(&self, digest: &Digest) -> String {
        self.endpoint
            .request_path(&format!("v2/{}/blobs/{}", self.repository, digest))
    }

    fn parse_inner(value: &str, explicit: bool) -> Result<Self, ReferenceError> {
        let value = value.trim();
        if value.is_empty() || contains_control(value) {
            return Err(ReferenceError::EmptyReference);
        }
        let (endpoint, remainder) = split_endpoint_and_repository(value)?;
        let (repository, kind) = split_repository_reference(&remainder, "", explicit)?;
        let repository = normalize_repository_for_endpoint(&endpoint, &repository)?;
        Ok(Self::new(endpoint, repository, kind))
    }

    fn new(endpoint: RegistryEndpoint, repository: String, kind: ReferenceKind) -> Self {
        let registry = endpoint.authority();
        Self {
            endpoint,
            registry,
            repository,
            kind,
        }
    }
}

impl fmt::Display for RegistryReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let separator = if self.is_digest() { "@" } else { ":" };
        write!(
            formatter,
            "{}/{}{separator}{}",
            self.registry, self.repository, self.kind
        )
    }
}

/// Errors returned while normalizing registry references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// An endpoint or reference was empty.
    EmptyEndpoint,
    /// An image reference was empty.
    EmptyReference,
    /// The endpoint could not be parsed or contained an invalid host.
    InvalidEndpoint,
    /// Only HTTP and HTTPS registry endpoints are supported.
    UnsupportedScheme(String),
    /// URLs containing user information are forbidden.
    CredentialsInUrl,
    /// Registry endpoint query strings and fragments are forbidden.
    EndpointHasQueryOrFragment,
    /// A repository path is not a canonical OCI repository name.
    InvalidRepository,
    /// A tag is not a valid OCI tag.
    InvalidTag,
    /// A reference must explicitly include a tag or digest.
    MissingReference,
    /// A digest was malformed.
    InvalidDigest(DigestError),
    /// An upload location was empty, malformed, or contained a fragment.
    InvalidLocation,
    /// An upload location pointed at a different origin.
    ForeignOrigin,
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEndpoint => formatter.write_str("registry endpoint is empty"),
            Self::EmptyReference => formatter.write_str("registry reference is empty"),
            Self::InvalidEndpoint => formatter.write_str("registry endpoint is invalid"),
            Self::UnsupportedScheme(scheme) => {
                write!(formatter, "unsupported registry scheme: {scheme}")
            }
            Self::CredentialsInUrl => {
                formatter.write_str("registry URL user information is forbidden")
            }
            Self::EndpointHasQueryOrFragment => {
                formatter.write_str("registry URL query and fragment are forbidden")
            }
            Self::InvalidRepository => formatter.write_str("registry repository name is invalid"),
            Self::InvalidTag => formatter.write_str("registry tag is invalid"),
            Self::MissingReference => {
                formatter.write_str("registry reference must include a tag or digest")
            }
            Self::InvalidDigest(error) => {
                write!(formatter, "registry reference digest is invalid: {error}")
            }
            Self::InvalidLocation => formatter.write_str("registry upload location is invalid"),
            Self::ForeignOrigin => {
                formatter.write_str("registry upload location is outside the configured origin")
            }
        }
    }
}

impl std::error::Error for ReferenceError {}

impl From<DigestError> for ReferenceError {
    fn from(error: DigestError) -> Self {
        Self::InvalidDigest(error)
    }
}

/// Parses and normalizes a registry endpoint.
///
/// # Errors
///
/// Returns an error for an invalid registry endpoint.
pub fn normalize_registry(value: &str) -> Result<String, ReferenceError> {
    Ok(RegistryEndpoint::parse(value)?.authority())
}

/// Parses and normalizes a repository name.
///
/// # Errors
///
/// Returns [`ReferenceError::InvalidRepository`] for an unsafe or malformed
/// repository path.
pub fn normalize_repository(value: &str) -> Result<String, ReferenceError> {
    normalize_repository_for_endpoint(&RegistryEndpoint::parse("https://docker.io")?, value)
}

fn split_endpoint_and_repository(
    value: &str,
) -> Result<(RegistryEndpoint, String), ReferenceError> {
    if let Some((scheme, rest)) = value.split_once("://") {
        if !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "http" | "https" | "oci" | "docker"
        ) {
            return Err(ReferenceError::UnsupportedScheme(scheme.to_owned()));
        }
        let endpoint_scheme = if scheme.eq_ignore_ascii_case("http") {
            "http"
        } else {
            "https"
        };
        let parsed = Url::parse(&format!("{endpoint_scheme}://{rest}"))
            .map_err(|_| ReferenceError::InvalidEndpoint)?;
        let mut endpoint_url = parsed.clone();
        endpoint_url.set_path("/");
        let mut endpoint = RegistryEndpoint::from_url(&endpoint_url)?;
        // In a reference URL the path is the repository, not an endpoint
        // prefix.  Endpoint prefixes are configured explicitly through
        // `RegistryEndpoint::parse` or `from_parts`.
        endpoint.base_path.clear();
        let repository = parsed.path().trim_matches('/').to_owned();
        if repository.is_empty() {
            return Err(ReferenceError::EmptyReference);
        }
        return Ok((endpoint, repository));
    }

    let first_component = value.split('/').next().unwrap_or_default();
    let has_explicit_registry = value.contains('/')
        && (first_component.eq_ignore_ascii_case("localhost")
            || first_component.contains('.')
            || first_component.contains(':')
            || first_component.starts_with('['));
    if has_explicit_registry {
        let slash = value.find('/').ok_or(ReferenceError::InvalidEndpoint)?;
        let authority = &value[..slash];
        let repository = value[slash + 1..].to_owned();
        let endpoint = RegistryEndpoint::parse(authority)?;
        if repository.is_empty() {
            return Err(ReferenceError::EmptyReference);
        }
        Ok((endpoint, repository))
    } else {
        let endpoint = RegistryEndpoint::parse(DEFAULT_REGISTRY)?;
        Ok((endpoint, value.to_owned()))
    }
}

fn split_repository_reference(
    value: &str,
    supplied_reference: &str,
    explicit: bool,
) -> Result<(String, ReferenceKind), ReferenceError> {
    let (repository, reference) = if supplied_reference.is_empty() {
        split_reference_component(value)?
    } else {
        (value.to_owned(), supplied_reference.to_owned())
    };
    if repository.is_empty() || repository.starts_with('/') || repository.ends_with('/') {
        return Err(ReferenceError::InvalidRepository);
    }
    let kind = if reference.is_empty() {
        if explicit {
            return Err(ReferenceError::MissingReference);
        }
        ReferenceKind::Tag("latest".to_owned())
    } else if reference.starts_with("sha256:") || reference.starts_with("sha512:") {
        ReferenceKind::Digest(Digest::parse(&reference).map_err(ReferenceError::InvalidDigest)?)
    } else {
        validate_tag(&reference)?;
        ReferenceKind::Tag(reference)
    };
    Ok((repository, kind))
}

fn split_reference_component(value: &str) -> Result<(String, String), ReferenceError> {
    if let Some(at) = value.rfind('@') {
        if value[..at].contains('@') || at == 0 || at + 1 >= value.len() {
            return Err(ReferenceError::InvalidRepository);
        }
        return Ok((value[..at].to_owned(), value[at + 1..].to_owned()));
    }
    let slash = value.rfind('/').map_or(0, |index| index + 1);
    if let Some(colon) = value[slash..].find(':') {
        let separator = slash + colon;
        if separator == 0 || separator + 1 >= value.len() {
            return Err(ReferenceError::InvalidTag);
        }
        return Ok((
            value[..separator].to_owned(),
            value[separator + 1..].to_owned(),
        ));
    }
    Ok((value.to_owned(), String::new()))
}

fn normalize_repository_for_endpoint(
    endpoint: &RegistryEndpoint,
    value: &str,
) -> Result<String, ReferenceError> {
    let mut repository = value.to_ascii_lowercase();
    if repository.is_empty()
        || repository.len() > 255
        || repository.starts_with('/')
        || repository.ends_with('/')
        || repository.contains("//")
        || repository
            .split('/')
            .any(|segment| !valid_repository_segment(segment))
    {
        return Err(ReferenceError::InvalidRepository);
    }
    if is_docker_hub(&endpoint.authority()) && !repository.contains('/') {
        repository = format!("library/{repository}");
    }
    Ok(repository)
}

fn valid_repository_segment(segment: &str) -> bool {
    if segment.is_empty()
        || segment == "."
        || segment == ".."
        || !segment.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return false;
    }
    let bytes = segment.as_bytes();
    if !is_repository_alphanumeric(bytes[0]) {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let component_start = index;
        while index < bytes.len() && is_repository_alphanumeric(bytes[index]) {
            index += 1;
        }
        if component_start == index {
            return false;
        }
        if index == bytes.len() {
            return true;
        }
        match bytes[index] {
            b'-' => {
                while index < bytes.len() && bytes[index] == b'-' {
                    index += 1;
                }
            }
            b'_' => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                    if bytes.get(index) == Some(&b'_') {
                        return false;
                    }
                }
            }
            b'.' => index += 1,
            _ => return false,
        }
        if index >= bytes.len() || !is_repository_alphanumeric(bytes[index]) {
            return false;
        }
    }
    false
}

fn is_repository_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn validate_tag(tag: &str) -> Result<(), ReferenceError> {
    if tag.is_empty()
        || tag.len() > 128
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ReferenceError::InvalidTag);
    }
    let first = tag.as_bytes()[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(ReferenceError::InvalidTag);
    }
    Ok(())
}

fn normalize_path_prefix(path: &str) -> Result<String, ReferenceError> {
    if path.contains('\\')
        || path.contains("%2f")
        || path.contains("%2F")
        || path.contains("%5c")
        || path.contains("%5C")
    {
        return Err(ReferenceError::InvalidEndpoint);
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.split('/').any(|segment| {
        segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            })
    }) {
        return Err(ReferenceError::InvalidEndpoint);
    }
    Ok(trimmed.to_owned())
}

fn is_docker_hub(authority: &str) -> bool {
    matches!(
        authority,
        DEFAULT_REGISTRY | "index.docker.io" | DOCKER_HUB_REGISTRY
    )
}

fn effective_port(scheme: RegistryScheme, port: Option<u16>) -> u16 {
    port.unwrap_or_else(|| scheme.default_port())
}

fn same_origin_url(parsed: &Url, scheme: RegistryScheme, host: &str, port: Option<u16>) -> bool {
    let parsed_scheme = match parsed.scheme() {
        "http" => RegistryScheme::Http,
        "https" => RegistryScheme::Https,
        _ => return false,
    };
    let parsed_host = match parsed.host() {
        Some(Host::Domain(value)) => value.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(value)) => value.to_string(),
        Some(Host::Ipv6(value)) => format!("[{value}]"),
        None => return false,
    };
    parsed_scheme == scheme
        && parsed_host.eq_ignore_ascii_case(host)
        && effective_port(parsed_scheme, parsed.port()) == effective_port(scheme, port)
}

fn contains_control(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::{ReferenceError, RegistryEndpoint, RegistryReference, normalize_repository};

    #[test]
    fn normalizes_docker_hub_and_explicit_registries() {
        let reference = RegistryReference::parse("ALPINE").expect("bare reference");
        assert_eq!(reference.registry(), "docker.io");
        assert_eq!(reference.repository(), "library/alpine");
        assert_eq!(reference.tag(), Some("latest"));

        let digest = format!("sha256:{}", "a".repeat(64));
        let digest_reference = RegistryReference::parse(&format!(
            "https://REGISTRY.example:443/base/team/app@{digest}"
        ))
        .expect("digest reference");
        assert_eq!(digest_reference.registry(), "registry.example");
        assert_eq!(digest_reference.repository(), "base/team/app");
        assert!(digest_reference.is_digest());
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_references() {
        assert_eq!(
            RegistryReference::parse_explicit("registry.example/team/app"),
            Err(ReferenceError::MissingReference)
        );
        assert!(matches!(
            RegistryReference::parse("registry.example/team/../app:latest"),
            Err(ReferenceError::InvalidRepository)
        ));
        assert!(matches!(
            RegistryReference::parse("registry.example/team/app:bad tag"),
            Err(ReferenceError::InvalidTag)
        ));
        assert!(matches!(
            RegistryEndpoint::parse("https://user:password@registry.example"),
            Err(ReferenceError::CredentialsInUrl)
        ));
    }

    #[test]
    fn validates_repository_names() {
        assert_eq!(
            normalize_repository("Team/App").expect("repository"),
            "team/app"
        );
        assert!(normalize_repository("team//app").is_err());
        assert!(normalize_repository("team/../app").is_err());
        assert_eq!(
            normalize_repository("team/foo__bar--baz.qux").expect("repository"),
            "team/foo__bar--baz.qux"
        );
        assert!(normalize_repository("team/foo___bar").is_err());
        assert!(normalize_repository("team/foo._bar").is_err());
    }

    #[test]
    fn endpoint_parts_preserve_prefixes_and_non_default_ports() {
        let endpoint = super::RegistryEndpoint::from_parts(
            super::RegistryScheme::Http,
            "localhost",
            Some(5000),
            "registry-prefix",
        )
        .expect("endpoint");
        assert_eq!(endpoint.url(), "http://localhost:5000/registry-prefix/");
        assert_eq!(
            endpoint.request_path("v2/team/app"),
            "/registry-prefix/v2/team/app"
        );
    }

    #[test]
    fn upload_locations_must_remain_on_origin() {
        let endpoint = RegistryEndpoint::parse("https://registry.example/base/").expect("endpoint");
        assert_eq!(
            endpoint
                .resolve_location("/upload/42?digest=sha256%3Aabc")
                .expect("location"),
            "https://registry.example/upload/42?digest=sha256%3Aabc"
        );
        assert_eq!(
            endpoint.resolve_location("https://attacker.example/upload"),
            Err(ReferenceError::ForeignOrigin)
        );
    }
}
