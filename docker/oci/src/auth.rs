//! Secret-safe authentication policy for OCI Distribution requests.
//!
//! This module intentionally defines its own credential provider.  It does
//! not consume Docker Engine credentials, `X-Registry-Auth`, or a Docker
//! credential-helper response.  A distribution caller must pass a provider
//! explicitly to the transport it constructs.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::reference::{ReferenceError, normalize_registry};

const REDACTED: &str = "[REDACTED]";

/// The HTTP authentication scheme used by a registry credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialScheme {
    /// RFC 7617-style username/password authentication.
    Basic,
    /// A bearer token issued by a registry token service.
    Bearer,
}

impl CredentialScheme {
    /// Returns the canonical scheme name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "Basic",
            Self::Bearer => "Bearer",
        }
    }
}

impl fmt::Display for CredentialScheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
struct SecretValue(String);

impl SecretValue {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A credential scoped to one registry operation.
///
/// The secret is zeroized on drop and is always redacted from `Debug` and
/// `Display`.  [`RegistryCredential::authorization_value`] is the explicit
/// escape hatch for a transport that must construct an HTTP header.
pub struct RegistryCredential {
    scheme: CredentialScheme,
    username: Option<String>,
    secret: SecretValue,
}

impl RegistryCredential {
    /// Creates username/password credentials.
    #[must_use]
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            scheme: CredentialScheme::Basic,
            username: Some(username.into()),
            secret: SecretValue::new(password.into()),
        }
    }

    /// Creates bearer-token credentials.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        Self {
            scheme: CredentialScheme::Bearer,
            username: None,
            secret: SecretValue::new(token.into()),
        }
    }

    /// Validates and creates username/password credentials.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::InvalidCredential`] for empty or control-
    /// character-bearing values.
    pub fn try_basic(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty()
            || password.is_empty()
            || contains_control(&username)
            || contains_control(&password)
        {
            return Err(CredentialError::InvalidCredential);
        }
        Ok(Self::basic(username, password))
    }

    /// Validates and creates bearer-token credentials.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::InvalidCredential`] for an empty token or
    /// one containing whitespace/control characters.
    pub fn try_bearer(token: impl Into<String>) -> Result<Self, CredentialError> {
        let token = token.into();
        if token.is_empty()
            || token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(CredentialError::InvalidCredential);
        }
        Ok(Self::bearer(token))
    }

    /// Parses one `Authorization` header value.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsupported, or empty authorization
    /// values.
    pub fn from_authorization(value: &str) -> Result<Self, CredentialError> {
        let (scheme, parameter) = value
            .split_once(char::is_whitespace)
            .ok_or(CredentialError::InvalidAuthorization)?;
        let parameter = parameter.trim();
        if parameter.is_empty() || parameter.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(CredentialError::InvalidAuthorization);
        }
        if scheme.eq_ignore_ascii_case("basic") {
            let decoded = STANDARD
                .decode(parameter)
                .map_err(|_| CredentialError::InvalidAuthorization)?;
            let decoded =
                String::from_utf8(decoded).map_err(|_| CredentialError::InvalidAuthorization)?;
            let (username, password) = decoded
                .split_once(':')
                .ok_or(CredentialError::InvalidAuthorization)?;
            Self::try_basic(username, password)
        } else if scheme.eq_ignore_ascii_case("bearer") {
            Self::try_bearer(parameter)
        } else {
            Err(CredentialError::UnsupportedScheme)
        }
    }

    /// Returns the authentication scheme.
    #[must_use]
    pub const fn scheme(&self) -> CredentialScheme {
        self.scheme
    }

    /// Returns the non-secret username for basic credentials.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Returns whether a secret is present.
    #[must_use]
    pub fn has_secret(&self) -> bool {
        !self.secret.expose().is_empty()
    }

    /// Constructs an explicitly requested HTTP authorization value.
    ///
    /// The returned [`Zeroizing`] wrapper clears the temporary header string
    /// when it is dropped.  Callers should still avoid logging it.
    #[must_use]
    pub fn authorization_value(&self) -> Zeroizing<String> {
        let value = match self.scheme {
            CredentialScheme::Basic => {
                let username = self.username.as_deref().unwrap_or_default();
                let encoded = STANDARD.encode(format!("{username}:{}", self.secret.expose()));
                format!("Basic {encoded}")
            }
            CredentialScheme::Bearer => format!("Bearer {}", self.secret.expose()),
        };
        Zeroizing::new(value)
    }

    /// Returns a safe diagnostic representation of the authorization scheme.
    #[must_use]
    pub fn redacted_authorization(&self) -> String {
        format!("{} {REDACTED}", self.scheme)
    }

    /// Returns whether this credential authenticates the supplied header.
    #[must_use]
    pub fn matches_authorization(&self, value: &str) -> bool {
        Self::from_authorization(value).is_ok_and(|candidate| self.constant_time_eq(&candidate))
    }

    fn constant_time_eq(&self, other: &Self) -> bool {
        if self.scheme != other.scheme || self.username != other.username {
            return false;
        }
        let left = self.secret.expose().as_bytes();
        let right = other.secret.expose().as_bytes();
        let mut difference = left.len() ^ right.len();
        for (left_byte, right_byte) in left.iter().zip(right) {
            difference |= usize::from(left_byte ^ right_byte);
        }
        difference == 0
    }
}

impl PartialEq for RegistryCredential {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for RegistryCredential {}

impl Clone for RegistryCredential {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme,
            username: self.username.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl fmt::Debug for RegistryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCredential")
            .field("scheme", &self.scheme)
            .field("username", &self.username.as_ref().map(|_| REDACTED))
            .field("secret", &REDACTED)
            .finish()
    }
}

impl fmt::Display for RegistryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted_authorization())
    }
}

/// A challenge advertised by a registry or token service.
#[derive(Clone, Eq, PartialEq)]
pub enum AuthChallenge {
    /// A basic-auth challenge, optionally naming a realm.
    Basic {
        /// Optional human-readable realm.
        realm: Option<String>,
    },
    /// A bearer challenge with the parameters needed to request a token.
    Bearer {
        /// Absolute HTTP(S) token endpoint.
        realm: String,
        /// Optional registry service name.
        service: Option<String>,
        /// Optional repository scope.
        scope: Option<String>,
    },
}

impl fmt::Debug for AuthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { realm } => formatter
                .debug_struct("Basic")
                .field(
                    "realm",
                    &realm.as_ref().map(|value| redact_sensitive_text(value)),
                )
                .finish(),
            Self::Bearer {
                realm,
                service,
                scope,
            } => formatter
                .debug_struct("Bearer")
                .field("realm", &redact_sensitive_text(realm))
                .field("service", service)
                .field("scope", scope)
                .finish(),
        }
    }
}

impl AuthChallenge {
    /// Returns the challenge scheme.
    #[must_use]
    pub const fn scheme(&self) -> CredentialScheme {
        match self {
            Self::Basic { .. } => CredentialScheme::Basic,
            Self::Bearer { .. } => CredentialScheme::Bearer,
        }
    }

    /// Returns the realm associated with the challenge, if one is present.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        match self {
            Self::Basic { realm } => realm.as_deref(),
            Self::Bearer { realm, .. } => Some(realm),
        }
    }

    /// Renders a challenge header.  The output contains no credential secret.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        match self {
            Self::Basic { realm: None } => "Basic".to_owned(),
            Self::Basic { realm: Some(realm) } => {
                format!("Basic realm=\"{}\"", escape_quoted(realm))
            }
            Self::Bearer {
                realm,
                service,
                scope,
            } => {
                let mut value = format!("Bearer realm=\"{}\"", escape_quoted(realm));
                if let Some(service) = service {
                    value.push_str(",service=\"");
                    value.push_str(&escape_quoted(service));
                    value.push('"');
                }
                if let Some(scope) = scope {
                    value.push_str(",scope=\"");
                    value.push_str(&escape_quoted(scope));
                    value.push('"');
                }
                value
            }
        }
    }
}

/// Errors returned by the independent registry credential boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialError {
    /// No credential was configured for the normalized registry.
    Unavailable(String),
    /// A supplied credential was empty or contained control characters.
    InvalidCredential,
    /// An authorization header was malformed.
    InvalidAuthorization,
    /// The authorization scheme is not supported.
    UnsupportedScheme,
    /// A challenge header was malformed.
    InvalidChallenge,
    /// A bearer challenge did not contain a valid HTTP(S) realm.
    InvalidRealm,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(registry) => write!(
                formatter,
                "registry credential is unavailable for {registry}"
            ),
            Self::InvalidCredential => formatter.write_str("registry credential is invalid"),
            Self::InvalidAuthorization => {
                formatter.write_str("registry authorization value is invalid")
            }
            Self::UnsupportedScheme => {
                formatter.write_str("registry authorization scheme is unsupported")
            }
            Self::InvalidChallenge => {
                formatter.write_str("registry authentication challenge is invalid")
            }
            Self::InvalidRealm => formatter.write_str("registry bearer challenge realm is invalid"),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<ReferenceError> for CredentialError {
    fn from(_: ReferenceError) -> Self {
        Self::Unavailable("<invalid registry>".to_owned())
    }
}

/// Supplies registry credentials without coupling to Engine authentication.
pub trait RegistryCredentialProvider: Send + Sync {
    /// Returns an owned credential for a normalized registry key.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is invalid or no credential is
    /// available.
    fn credential_for(&self, registry: &str) -> Result<RegistryCredential, CredentialError>;

    /// Returns an owned credential for a registry/repository scope.
    ///
    /// The default keeps providers simple while allowing a future provider to
    /// distinguish pull and push scopes without changing the transport.
    ///
    /// # Errors
    ///
    /// Returns an error when no scoped credential is available.
    fn credential_for_scope(
        &self,
        registry: &str,
        _repository: &str,
    ) -> Result<RegistryCredential, CredentialError> {
        self.credential_for(registry)
    }
}

/// A deterministic provider backed by an application-owned map.
#[derive(Clone, Default)]
pub struct InMemoryRegistryCredentialProvider {
    credentials: BTreeMap<String, RegistryCredential>,
}

impl InMemoryRegistryCredentialProvider {
    /// Creates an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a credential using a normalized registry key.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry key cannot be normalized.
    pub fn insert(
        &mut self,
        registry: &str,
        credential: RegistryCredential,
    ) -> Result<(), CredentialError> {
        let key = normalize_registry(registry)
            .map_err(|_| CredentialError::Unavailable("<invalid registry>".to_owned()))?;
        self.credentials.insert(key, credential);
        Ok(())
    }

    /// Returns whether a key has a configured credential without exposing it.
    #[must_use]
    pub fn contains(&self, registry: &str) -> bool {
        normalize_registry(registry).is_ok_and(|key| self.credentials.contains_key(&key))
    }
}

impl fmt::Debug for InMemoryRegistryCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryRegistryCredentialProvider")
            .field("registries", &self.credentials.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RegistryCredentialProvider for InMemoryRegistryCredentialProvider {
    fn credential_for(&self, registry: &str) -> Result<RegistryCredential, CredentialError> {
        let key = normalize_registry(registry)
            .map_err(|_| CredentialError::Unavailable("<invalid registry>".to_owned()))?;
        self.credentials
            .get(&key)
            .cloned()
            .ok_or(CredentialError::Unavailable(key))
    }
}

/// A provider that always returns one explicitly supplied credential.
#[derive(Clone)]
pub struct StaticRegistryCredentialProvider {
    credential: RegistryCredential,
}

impl StaticRegistryCredentialProvider {
    /// Creates a provider for one credential.
    #[must_use]
    pub fn new(credential: RegistryCredential) -> Self {
        Self { credential }
    }
}

impl fmt::Debug for StaticRegistryCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticRegistryCredentialProvider")
            .field("credential", &self.credential)
            .finish()
    }
}

impl RegistryCredentialProvider for StaticRegistryCredentialProvider {
    fn credential_for(&self, _registry: &str) -> Result<RegistryCredential, CredentialError> {
        Ok(self.credential.clone())
    }
}

/// Parses one or more `WWW-Authenticate` challenge values.
///
/// # Errors
///
/// Returns an error for malformed challenges or an invalid bearer realm.
pub fn parse_auth_challenges(value: &str) -> Result<Vec<AuthChallenge>, CredentialError> {
    if value.trim().is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(CredentialError::InvalidChallenge);
    }
    let mut challenges = Vec::new();
    for part in split_challenge_parts(value) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (scheme, parameters) = part
            .split_once(char::is_whitespace)
            .map_or((part, ""), |(scheme, parameters)| (scheme, parameters));
        let parameters = parse_parameters(parameters)?;
        if scheme.eq_ignore_ascii_case("basic") {
            let realm = parameters.get("realm").cloned();
            challenges.push(AuthChallenge::Basic { realm });
        } else if scheme.eq_ignore_ascii_case("bearer") {
            let realm = parameters
                .get("realm")
                .ok_or(CredentialError::InvalidChallenge)?;
            let parsed = Url::parse(realm).map_err(|_| CredentialError::InvalidRealm)?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(CredentialError::InvalidRealm);
            }
            challenges.push(AuthChallenge::Bearer {
                realm: parsed.to_string(),
                service: parameters.get("service").cloned(),
                scope: parameters.get("scope").cloned(),
            });
        } else {
            return Err(CredentialError::InvalidChallenge);
        }
    }
    if challenges.is_empty() {
        Err(CredentialError::InvalidChallenge)
    } else {
        Ok(challenges)
    }
}

/// Parses a single challenge and returns it.
///
/// # Errors
///
/// Returns an error when the value is malformed or contains multiple
/// challenges.
pub fn parse_auth_challenge(value: &str) -> Result<AuthChallenge, CredentialError> {
    let mut challenges = parse_auth_challenges(value)?;
    if challenges.len() != 1 {
        return Err(CredentialError::InvalidChallenge);
    }
    challenges.pop().ok_or(CredentialError::InvalidChallenge)
}

/// Redacts common bearer, basic, token, password, and secret assignments.
///
/// This helper is intended for diagnostics assembled from headers or fixture
/// errors.  It is not a replacement for keeping secret-bearing types out of
/// debug implementations.
#[must_use]
pub fn redact_sensitive_text(value: &str) -> String {
    const KEYS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "identitytoken",
        "identityToken",
        "authToken",
        "credential",
    ];
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < value.len() {
        if let Some((key_end, value_start)) = sensitive_assignment(value, cursor, KEYS) {
            output.push_str(&value[cursor..key_end]);
            output.push_str(REDACTED);
            cursor = value_start;
            continue;
        }
        if let Some((scheme_end, secret_start)) = auth_scheme_assignment(value, cursor) {
            output.push_str(&value[cursor..scheme_end]);
            output.push_str(REDACTED);
            cursor = secret_start;
            continue;
        }
        let character = value[cursor..].chars().next().unwrap_or_default();
        output.push(character);
        cursor += character.len_utf8();
    }
    output
}

fn sensitive_assignment(value: &str, start: usize, keys: &[&str]) -> Option<(usize, usize)> {
    let tail = &value[start..];
    for key in keys {
        let Some(candidate) = tail.get(..key.len()) else {
            continue;
        };
        if !candidate.eq_ignore_ascii_case(key) {
            continue;
        }
        let before = value[..start].chars().next_back();
        if before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_') {
            continue;
        }
        let key_end = start + key.len();
        let mut cursor = key_end;
        let quote = match value.as_bytes().get(cursor) {
            Some(b'"') => {
                cursor += 1;
                Some(b'"')
            }
            Some(b'\'') => {
                cursor += 1;
                Some(b'\'')
            }
            _ => None,
        };
        while cursor < value.len() && value.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if !matches!(value.as_bytes().get(cursor), Some(b'=' | b':')) {
            continue;
        }
        cursor += 1;
        while cursor < value.len() && value.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if let Some(quote) = quote {
            if cursor < value.len() && value.as_bytes()[cursor] == quote {
                cursor += 1;
                while cursor < value.len() {
                    if value.as_bytes()[cursor] == b'\\' {
                        cursor = (cursor + 2).min(value.len());
                    } else if value.as_bytes()[cursor] == quote {
                        cursor += 1;
                        break;
                    } else {
                        cursor += 1;
                    }
                }
            }
        } else {
            cursor = consume_unquoted(value, cursor);
        }
        return Some((key_end, cursor));
    }
    None
}

fn consume_unquoted(value: &str, mut cursor: usize) -> usize {
    for scheme in ["Bearer", "Basic"] {
        if value
            .get(cursor..cursor + scheme.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(scheme))
        {
            let scheme_end = cursor + scheme.len();
            if value
                .as_bytes()
                .get(scheme_end)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor = scheme_end;
                while cursor < value.len() && value.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if matches!(value.as_bytes().get(cursor), Some(b'"' | b'\'')) {
                    let quote = value.as_bytes()[cursor];
                    cursor += 1;
                    while cursor < value.len() {
                        if value.as_bytes()[cursor] == b'\\' {
                            cursor = (cursor + 2).min(value.len());
                        } else if value.as_bytes()[cursor] == quote {
                            cursor += 1;
                            break;
                        } else {
                            cursor += 1;
                        }
                    }
                } else {
                    while cursor < value.len() && !value.as_bytes()[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                }
                return cursor;
            }
        }
    }
    while cursor < value.len()
        && !matches!(
            value.as_bytes()[cursor],
            b' ' | b'\t' | b',' | b';' | b'&' | b'}' | b']'
        )
    {
        cursor += 1;
    }
    cursor
}

fn auth_scheme_assignment(value: &str, start: usize) -> Option<(usize, usize)> {
    for scheme in ["Bearer", "Basic"] {
        let Some(candidate) = value.get(start..start + scheme.len()) else {
            continue;
        };
        if !candidate.eq_ignore_ascii_case(scheme) {
            continue;
        }
        let before = value[..start].chars().next_back();
        if before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_') {
            continue;
        }
        let mut cursor = start + scheme.len();
        if !value
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            continue;
        }
        while cursor < value.len() && value.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let secret_start = cursor;
        if matches!(value.as_bytes().get(cursor), Some(b'"' | b'\'')) {
            let quote = value.as_bytes()[cursor];
            cursor += 1;
            while cursor < value.len() {
                if value.as_bytes()[cursor] == b'\\' {
                    cursor = (cursor + 2).min(value.len());
                } else if value.as_bytes()[cursor] == quote {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
        } else {
            while cursor < value.len() && !value.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
        }
        if secret_start < cursor {
            return Some((start + scheme.len(), cursor));
        }
    }
    None
}

fn split_quoted_parts(value: &str) -> Vec<&str> {
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

fn split_challenge_parts(value: &str) -> Vec<&str> {
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
            let next = value[index + 1..].trim_start();
            if next
                .split_once(char::is_whitespace)
                .is_some_and(|(scheme, _)| {
                    matches!(scheme.to_ascii_lowercase().as_str(), "basic" | "bearer")
                })
            {
                parts.push(&value[start..index]);
                start = index + character.len_utf8();
            }
        }
    }
    parts.push(&value[start..]);
    parts
}

fn parse_parameters(value: &str) -> Result<BTreeMap<String, String>, CredentialError> {
    let mut parameters = BTreeMap::new();
    for parameter in split_quoted_parts(value) {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            continue;
        }
        let (key, raw_value) = parameter
            .split_once('=')
            .ok_or(CredentialError::InvalidChallenge)?;
        if key.trim().is_empty() || raw_value.is_empty() {
            return Err(CredentialError::InvalidChallenge);
        }
        let raw_value = raw_value.trim();
        let unquoted =
            if raw_value.len() >= 2 && raw_value.starts_with('"') && raw_value.ends_with('"') {
                &raw_value[1..raw_value.len() - 1]
            } else {
                raw_value
            };
        if unquoted.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(CredentialError::InvalidChallenge);
        }
        parameters.insert(
            key.trim().to_ascii_lowercase(),
            unquoted.replace("\\\"", "\""),
        );
    }
    Ok(parameters)
}

fn escape_quoted(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_control() {
                '_'
            } else {
                character
            }
        })
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn contains_control(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::{
        AuthChallenge, CredentialError, InMemoryRegistryCredentialProvider, RegistryCredential,
        RegistryCredentialProvider, parse_auth_challenge, redact_sensitive_text,
    };

    #[test]
    fn credentials_are_redacted_and_zeroized_by_type() {
        let credential = RegistryCredential::basic("alice", "super-secret");
        let debug = format!("{credential:?}");
        let display = credential.to_string();
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("super-secret"));
        assert!(!display.contains("super-secret"));
    }

    #[test]
    fn provider_is_scoped_and_does_not_expose_secrets() {
        let mut provider = InMemoryRegistryCredentialProvider::new();
        provider
            .insert(
                "https://REGISTRY.example:443",
                RegistryCredential::bearer("token-secret"),
            )
            .expect("insert");
        let credential = provider
            .credential_for("registry.example")
            .expect("credential");
        assert_eq!(credential.scheme(), super::CredentialScheme::Bearer);
        assert!(!format!("{provider:?}").contains("token-secret"));
        assert!(matches!(
            provider.credential_for("other.example"),
            Err(CredentialError::Unavailable(_))
        ));
    }

    #[test]
    fn parses_bearer_challenge_without_losing_scope() {
        let challenge = parse_auth_challenge(
            "Bearer realm=\"https://auth.example/token\",service=\"registry.example\",scope=\"repository:team/app:pull\"",
        )
        .expect("challenge");
        assert_eq!(
            challenge,
            AuthChallenge::Bearer {
                realm: "https://auth.example/token".to_owned(),
                service: Some("registry.example".to_owned()),
                scope: Some("repository:team/app:pull".to_owned()),
            }
        );
    }

    #[test]
    fn redacts_headers_and_structured_values() {
        let input = "Authorization: Bearer token-secret Basic dXNlcjpwYXNz {\"password\":\"pw\"}?access_token=query-secret";
        let output = redact_sensitive_text(input);
        assert!(!output.contains("token-secret"));
        assert!(!output.contains("dXNlcjpwYXNz"));
        assert!(!output.contains("pw"));
        assert!(!output.contains("query-secret"));
        assert!(output.contains("[REDACTED]"));

        let quoted = redact_sensitive_text("Authorization: Bearer \"quoted-secret\"");
        assert!(!quoted.contains("quoted-secret"));
        let basic = redact_sensitive_text("Proxy-Authorization: Basic dXNlcjpwYXNz");
        assert!(!basic.contains("dXNlcjpwYXNz"));
    }
}
