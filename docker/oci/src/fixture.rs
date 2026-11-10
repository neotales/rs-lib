//! A deterministic in-memory OCI Distribution registry fixture.
//!
//! The fixture is deliberately transport-free.  It gives the first slice a
//! local, bounded round-trip surface while the eventual HTTP transport remains
//! a separate concern.  No Docker Engine client, socket, credential helper,
//! or ambient environment state is consulted.

use std::{cell::RefCell, collections::BTreeMap, fmt};

use crate::{
    auth::{
        AuthChallenge, CredentialError, RegistryCredential, parse_auth_challenge,
        redact_sensitive_text,
    },
    digest::Digest,
    negotiation::{
        ContentPolicy, MediaType, NegotiationError, OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST,
        VerifiedContent,
    },
    reference::{ReferenceError, RegistryReference, normalize_repository},
    transfer::{TransferError, TransferPolicy, TransferReceipt},
};

/// Repository used by [`crate::deterministic_fixture`].
pub const FIXTURE_REPOSITORY: &str = "neotales/fixture";
/// Tag used by [`crate::deterministic_fixture`].
pub const FIXTURE_TAG: &str = "stable";
/// Index tag used by [`crate::deterministic_fixture`].
pub const FIXTURE_INDEX_TAG: &str = "multiarch";
/// Stable blob bytes used by [`crate::deterministic_fixture`].
pub const FIXTURE_BLOB: &[u8] = b"neotales-oci-distribution deterministic fixture\n";

/// Authentication policy enforced by a local fixture.
#[derive(Clone)]
pub enum FixtureAuth {
    /// Requests are accepted without credentials.
    Anonymous,
    /// Requests must present the configured basic credential.
    Basic(RegistryCredential),
    /// Requests must present the configured bearer credential.
    Bearer {
        /// The credential the fixture expects.
        credential: RegistryCredential,
        /// The challenge the fixture issues before accepting it.
        challenge: AuthChallenge,
    },
}

impl FixtureAuth {
    /// Creates an anonymous policy.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self::Anonymous
    }

    /// Creates a basic-auth policy.
    #[must_use]
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic(RegistryCredential::basic(username, password))
    }

    /// Creates a bearer-auth policy with a deterministic challenge.
    ///
    /// # Panics
    ///
    /// Panics only if the crate's fixed challenge fixture is malformed.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        let challenge = parse_auth_challenge(
            "Bearer realm=\"https://auth.fixture/token\",service=\"registry.fixture\",scope=\"repository:neotales/fixture:pull,push\"",
        )
        .expect("constant fixture challenge must parse");
        Self::Bearer {
            credential: RegistryCredential::bearer(token),
            challenge,
        }
    }

    fn challenge(&self) -> Option<&AuthChallenge> {
        match self {
            Self::Bearer { challenge, .. } => Some(challenge),
            Self::Anonymous | Self::Basic(_) => None,
        }
    }

    fn accepts(&self, credential: Option<&RegistryCredential>) -> bool {
        match (self, credential) {
            (Self::Anonymous, _) => true,
            (Self::Basic(expected), Some(actual)) => {
                expected.matches_authorization(&actual.authorization_value())
            }
            (
                Self::Bearer {
                    credential: expected,
                    ..
                },
                Some(actual),
            ) => expected.matches_authorization(&actual.authorization_value()),
            (Self::Basic(_) | Self::Bearer { .. }, None) => false,
        }
    }
}

impl fmt::Debug for FixtureAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => formatter.write_str("Anonymous"),
            Self::Basic(credential) => formatter.debug_tuple("Basic").field(credential).finish(),
            Self::Bearer {
                credential,
                challenge,
            } => formatter
                .debug_struct("Bearer")
                .field("credential", credential)
                .field("challenge", challenge)
                .finish(),
        }
    }
}

/// A bounded, deterministic registry fixture.
#[derive(Clone)]
pub struct LocalRegistryFixture {
    blobs: RefCell<BTreeMap<String, Vec<u8>>>,
    manifests: RefCell<BTreeMap<String, StoredManifest>>,
    auth: FixtureAuth,
    default_policy: TransferPolicy,
}

impl fmt::Debug for LocalRegistryFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRegistryFixture")
            .field("blob_count", &self.blobs.borrow().len())
            .field("manifest_count", &self.manifests.borrow().len())
            .field("auth", &self.auth)
            .field("default_policy", &self.default_policy)
            .finish()
    }
}

impl Default for LocalRegistryFixture {
    fn default() -> Self {
        Self {
            blobs: RefCell::new(BTreeMap::new()),
            manifests: RefCell::new(BTreeMap::new()),
            auth: FixtureAuth::Anonymous,
            default_policy: TransferPolicy::bounded(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredManifest {
    content: Vec<u8>,
    media_type: MediaType,
    digest: Digest,
}

impl LocalRegistryFixture {
    /// Creates an empty anonymous fixture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty fixture with explicit authentication policy.
    #[must_use]
    pub fn with_auth(auth: FixtureAuth) -> Self {
        Self {
            auth,
            ..Self::default()
        }
    }

    /// Creates an empty fixture with a bounded default transfer policy.
    #[must_use]
    pub fn with_policy(auth: FixtureAuth, policy: TransferPolicy) -> Self {
        Self {
            auth,
            default_policy: policy,
            ..Self::default()
        }
    }

    /// Creates the fixed anonymous fixture used by conformance tests.
    ///
    /// # Panics
    ///
    /// Panics only if the crate's fixed manifest fixture is malformed.
    #[must_use]
    pub fn deterministic() -> Self {
        let fixture = Self::new();
        let blob_digest = fixture
            .seed_blob(FIXTURE_REPOSITORY, FIXTURE_BLOB)
            .expect("fixture blob seed");
        let manifest = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"{OCI_IMAGE_MANIFEST}\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{blob_digest}\",\"size\":{}}},\"layers\":[]}}",
            FIXTURE_BLOB.len()
        );
        let manifest_digest = fixture
            .seed_manifest(
                FIXTURE_REPOSITORY,
                FIXTURE_TAG,
                manifest.as_bytes(),
                &MediaType::constant(OCI_IMAGE_MANIFEST),
            )
            .expect("fixture manifest seed");
        let index = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"{OCI_IMAGE_INDEX}\",\"manifests\":[{{\"mediaType\":\"{OCI_IMAGE_MANIFEST}\",\"digest\":\"{manifest_digest}\",\"size\":{},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}}]}}",
            manifest.len()
        );
        fixture
            .seed_manifest(
                FIXTURE_REPOSITORY,
                FIXTURE_INDEX_TAG,
                index.as_bytes(),
                &MediaType::constant(OCI_IMAGE_INDEX),
            )
            .expect("fixture index seed");
        fixture
    }

    /// Alias for [`LocalRegistryFixture::deterministic`].
    #[must_use]
    pub fn fixture() -> Self {
        Self::deterministic()
    }

    /// Returns the bearer challenge advertised by a protected fixture.
    #[must_use]
    pub fn challenge(&self) -> Option<&AuthChallenge> {
        self.auth.challenge()
    }

    /// Returns the default transfer limit.
    #[must_use]
    pub fn default_policy(&self) -> TransferPolicy {
        self.default_policy
    }

    /// Starts an explicitly credentialed operation session.
    pub fn session(&self, credential: Option<RegistryCredential>) -> FixtureSession<'_> {
        FixtureSession {
            fixture: self,
            credential,
        }
    }

    /// Performs an anonymous operation directly on an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid references, authentication, digest, or
    /// transfer bounds.
    pub fn put_blob(
        &self,
        repository: &str,
        content: &[u8],
        expected_digest: Option<&Digest>,
        policy: TransferPolicy,
    ) -> Result<TransferReceipt, FixtureError> {
        self.session(None)
            .put_blob(repository, content, expected_digest, policy)
    }

    /// Retrieves a blob from an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication, lookup, bounds, or digest policy
    /// fails.
    pub fn get_blob(
        &self,
        repository: &str,
        digest: &Digest,
        policy: TransferPolicy,
    ) -> Result<VerifiedContent, FixtureError> {
        FixtureSession {
            fixture: self,
            credential: None,
        }
        .get_blob(repository, digest, policy)
    }

    /// Publishes a manifest on an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid references, authentication, media type,
    /// digest, or transfer bounds.
    pub fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        content: &[u8],
        media_type: &MediaType,
        policy: TransferPolicy,
    ) -> Result<TransferReceipt, FixtureError> {
        self.session(None)
            .put_manifest(repository, reference, content, media_type, policy)
    }

    /// Retrieves a manifest from an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication, lookup, media negotiation, or
    /// digest policy fails.
    pub fn get_manifest(
        &self,
        repository: &str,
        reference: &str,
        accepted: &[MediaType],
        policy: TransferPolicy,
    ) -> Result<VerifiedContent, FixtureError> {
        FixtureSession {
            fixture: self,
            credential: None,
        }
        .get_manifest(repository, reference, accepted, policy)
    }

    /// Publishes an OCI image index on an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest operation cannot be completed.
    pub fn put_index(
        &self,
        repository: &str,
        reference: &str,
        content: &[u8],
        policy: TransferPolicy,
    ) -> Result<TransferReceipt, FixtureError> {
        let media_type = MediaType::constant(OCI_IMAGE_INDEX);
        self.put_manifest(repository, reference, content, &media_type, policy)
    }

    /// Retrieves an OCI image index from an anonymous fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when lookup, authentication, negotiation, or content
    /// kind validation fails.
    pub fn get_index(
        &self,
        repository: &str,
        reference: &str,
        policy: TransferPolicy,
    ) -> Result<VerifiedContent, FixtureError> {
        let result = self.get_manifest(
            repository,
            reference,
            &[MediaType::constant(OCI_IMAGE_INDEX)],
            policy,
        )?;
        if result.media_type().essence() != OCI_IMAGE_INDEX {
            return Err(FixtureError::WrongContentKind {
                expected: OCI_IMAGE_INDEX.to_owned(),
                actual: result.media_type().essence().to_owned(),
            });
        }
        Ok(result)
    }

    /// Adds deterministic blob data without invoking authentication policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid repository or a body over the default
    /// bound.
    pub fn seed_blob(&self, repository: &str, content: &[u8]) -> Result<Digest, FixtureError> {
        let repository = normalize_fixture_repository(repository)?;
        self.default_policy
            .check_size(content.len())
            .map_err(FixtureError::Transfer)?;
        let digest = Digest::sha256(content);
        self.blobs
            .borrow_mut()
            .insert(blob_key(&repository, &digest), content.to_vec());
        Ok(digest)
    }

    /// Adds deterministic manifest data without invoking authentication policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid reference, media type, digest, or body
    /// over the default bound.
    pub fn seed_manifest(
        &self,
        repository: &str,
        reference: &str,
        content: &[u8],
        media_type: &MediaType,
    ) -> Result<Digest, FixtureError> {
        let repository = normalize_fixture_repository(repository)?;
        let reference = normalize_manifest_reference(&repository, reference)?;
        self.default_policy
            .check_size(content.len())
            .map_err(FixtureError::Transfer)?;
        if !ContentPolicy::default().accepts_upload(media_type) {
            return Err(FixtureError::Negotiation(
                NegotiationError::UnsupportedMediaType(media_type.clone()),
            ));
        }
        let digest = Digest::sha256(content);
        if let Some(expected) = reference.digest()
            && expected != &digest
        {
            return Err(FixtureError::DigestMismatch);
        }
        self.manifests.borrow_mut().insert(
            manifest_key(&repository, &reference.reference().as_str()),
            StoredManifest {
                content: content.to_vec(),
                media_type: media_type.clone(),
                digest: digest.clone(),
            },
        );
        Ok(digest)
    }

    /// Returns the number of stored blobs.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.blobs.borrow().len()
    }

    /// Returns the number of stored manifests.
    #[must_use]
    pub fn manifest_count(&self) -> usize {
        self.manifests.borrow().len()
    }
}

/// A credential-scoped operation session for a local registry fixture.
pub struct FixtureSession<'a> {
    fixture: &'a LocalRegistryFixture,
    credential: Option<RegistryCredential>,
}

impl fmt::Debug for FixtureSession<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureSession")
            .field("credential", &self.credential)
            .field("fixture", &self.fixture)
            .finish()
    }
}

impl FixtureSession<'_> {
    /// Uploads and content-addresses a blob.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, invalid input, digest
    /// mismatch, or an oversized body.
    pub fn put_blob(
        &self,
        repository: &str,
        content: &[u8],
        expected_digest: Option<&Digest>,
        policy: TransferPolicy,
    ) -> Result<TransferReceipt, FixtureError> {
        self.authorize()?;
        let repository = normalize_fixture_repository(repository)?;
        policy
            .check_size(content.len())
            .map_err(FixtureError::Transfer)?;
        let actual = Digest::sha256(content);
        if expected_digest.is_some_and(|expected| expected != &actual) {
            return Err(FixtureError::DigestMismatch);
        }
        self.fixture
            .blobs
            .borrow_mut()
            .insert(blob_key(&repository, &actual), content.to_vec());
        Ok(TransferReceipt::new(actual, content.len()))
    }

    /// Downloads and verifies a blob.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, lookup, bounds, or content
    /// verification.
    pub fn get_blob(
        &self,
        repository: &str,
        digest: &Digest,
        policy: TransferPolicy,
    ) -> Result<VerifiedContent, FixtureError> {
        self.authorize()?;
        let repository = normalize_fixture_repository(repository)?;
        let blobs = self.fixture.blobs.borrow();
        let content = blobs
            .get(&blob_key(&repository, digest))
            .ok_or(FixtureError::BlobNotFound)?;
        policy
            .check_size(content.len())
            .map_err(FixtureError::Transfer)?;
        let blob_policy = ContentPolicy::blob(policy.max_bytes())
            .map_err(FixtureError::Negotiation)?
            .without_digest_header();
        let verified = blob_policy
            .verify(Some("application/octet-stream"), None, content)
            .map_err(FixtureError::from)?;
        if verified.digest() != digest {
            return Err(FixtureError::DigestMismatch);
        }
        Ok(verified)
    }

    /// Publishes a manifest or index under a tag or digest.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, invalid reference or media
    /// type, digest mismatch, or an oversized body.
    pub fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        content: &[u8],
        media_type: &MediaType,
        policy: TransferPolicy,
    ) -> Result<TransferReceipt, FixtureError> {
        self.authorize()?;
        let repository = normalize_fixture_repository(repository)?;
        let reference = normalize_manifest_reference(&repository, reference)?;
        policy
            .check_size(content.len())
            .map_err(FixtureError::Transfer)?;
        if !ContentPolicy::default().accepts_upload(media_type) {
            return Err(FixtureError::Negotiation(
                NegotiationError::UnsupportedMediaType(media_type.clone()),
            ));
        }
        let digest = Digest::sha256(content);
        if reference
            .digest()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(FixtureError::DigestMismatch);
        }
        self.fixture.manifests.borrow_mut().insert(
            manifest_key(&repository, &reference.reference().as_str()),
            StoredManifest {
                content: content.to_vec(),
                media_type: media_type.clone(),
                digest: digest.clone(),
            },
        );
        Ok(TransferReceipt::new(digest, content.len()))
    }

    /// Downloads and verifies a manifest using explicit accepted media types.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, lookup, negotiation, or
    /// digest verification.
    pub fn get_manifest(
        &self,
        repository: &str,
        reference: &str,
        accepted: &[MediaType],
        policy: TransferPolicy,
    ) -> Result<VerifiedContent, FixtureError> {
        self.authorize()?;
        let repository = normalize_fixture_repository(repository)?;
        let reference = normalize_manifest_reference(&repository, reference)?;
        let manifests = self.fixture.manifests.borrow();
        let key = manifest_key(&repository, &reference.reference().as_str());
        let stored = manifests
            .get(&key)
            .or_else(|| {
                reference.digest().and_then(|expected| {
                    manifests.iter().find_map(|(stored_key, manifest)| {
                        (stored_key.split('\u{0000}').next() == Some(repository.as_str())
                            && manifest.digest == *expected)
                            .then_some(manifest)
                    })
                })
            })
            .ok_or(FixtureError::ManifestNotFound)?;
        let content_policy = ContentPolicy::new(accepted.iter().cloned(), policy.max_bytes())
            .map_err(FixtureError::Negotiation)?;
        content_policy
            .verify(
                Some(stored.media_type.as_str()),
                Some(&stored.digest.to_string()),
                &stored.content,
            )
            .map_err(FixtureError::from)
    }

    fn authorize(&self) -> Result<(), FixtureError> {
        if self.fixture.auth.accepts(self.credential.as_ref()) {
            Ok(())
        } else {
            Err(FixtureError::Unauthorized {
                challenge: self.fixture.auth.challenge().cloned(),
            })
        }
    }
}

/// Errors returned by the deterministic registry fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureError {
    /// A repository or reference was invalid.
    Reference(ReferenceError),
    /// Authentication was absent or rejected.
    Unauthorized {
        /// Optional bearer challenge; it never contains a credential.
        challenge: Option<AuthChallenge>,
    },
    /// The requested blob was not present.
    BlobNotFound,
    /// The requested manifest was not present.
    ManifestNotFound,
    /// The content kind did not match the requested operation.
    WrongContentKind {
        /// Expected media type.
        expected: String,
        /// Actual media type.
        actual: String,
    },
    /// A supplied digest did not match the content.
    DigestMismatch,
    /// A transfer exceeded its configured bound.
    Transfer(TransferError),
    /// A response violated content negotiation policy.
    Negotiation(NegotiationError),
    /// A credential could not be constructed.
    Credential(CredentialError),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(error) => write!(formatter, "fixture reference is invalid: {error}"),
            Self::Unauthorized { challenge } => {
                formatter.write_str("fixture request is unauthorized")?;
                if let Some(challenge) = challenge {
                    write!(
                        formatter,
                        " ({})",
                        redact_sensitive_text(&challenge.to_header_value())
                    )?;
                }
                Ok(())
            }
            Self::BlobNotFound => formatter.write_str("fixture blob was not found"),
            Self::ManifestNotFound => formatter.write_str("fixture manifest was not found"),
            Self::WrongContentKind { expected, actual } => {
                write!(
                    formatter,
                    "fixture content kind mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DigestMismatch => formatter.write_str("fixture content digest does not match"),
            Self::Transfer(error) => write!(formatter, "fixture transfer failed: {error}"),
            Self::Negotiation(error) => write!(formatter, "fixture content policy failed: {error}"),
            Self::Credential(error) => write!(formatter, "fixture credential failed: {error}"),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<ReferenceError> for FixtureError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(error)
    }
}

impl From<TransferError> for FixtureError {
    fn from(error: TransferError) -> Self {
        Self::Transfer(error)
    }
}

impl From<NegotiationError> for FixtureError {
    fn from(error: NegotiationError) -> Self {
        Self::Negotiation(error)
    }
}

impl From<CredentialError> for FixtureError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

fn normalize_fixture_repository(repository: &str) -> Result<String, FixtureError> {
    normalize_repository(repository).map_err(FixtureError::Reference)
}

fn normalize_manifest_reference(
    repository: &str,
    reference: &str,
) -> Result<RegistryReference, FixtureError> {
    RegistryReference::from_parts("registry.fixture", repository, reference)
        .map_err(FixtureError::Reference)
}

fn blob_key(repository: &str, digest: &Digest) -> String {
    format!("{repository}\u{0000}{digest}")
}

fn manifest_key(repository: &str, reference: &str) -> String {
    format!("{repository}\u{0000}{reference}")
}

/// Alias emphasizing that the fixture is a local registry rather than an
/// Engine daemon.
pub type RegistryFixture = LocalRegistryFixture;
/// Alias for the bounded fixture session.
pub type LocalRegistrySession<'a> = FixtureSession<'a>;

#[cfg(test)]
mod tests {
    use super::{FIXTURE_BLOB, FIXTURE_REPOSITORY, FIXTURE_TAG, FixtureAuth, LocalRegistryFixture};
    use crate::{
        auth::RegistryCredential,
        negotiation::{MediaType, OCI_IMAGE_MANIFEST},
        transfer::TransferPolicy,
    };

    #[test]
    fn deterministic_fixture_round_trips_blob_and_manifest() {
        let fixture = LocalRegistryFixture::deterministic();
        let digest = crate::digest::Digest::sha256(FIXTURE_BLOB);
        let blob = fixture
            .get_blob(FIXTURE_REPOSITORY, &digest, TransferPolicy::bounded())
            .expect("blob");
        assert_eq!(blob.content(), FIXTURE_BLOB);
        let manifest = fixture
            .get_manifest(
                FIXTURE_REPOSITORY,
                FIXTURE_TAG,
                &[MediaType::constant(OCI_IMAGE_MANIFEST)],
                TransferPolicy::bounded(),
            )
            .expect("manifest");
        assert_eq!(manifest.digest().to_string().len(), 71);
    }

    #[test]
    fn protected_fixture_requires_explicit_scoped_credentials() {
        let fixture =
            LocalRegistryFixture::with_auth(FixtureAuth::basic("alice", "fixture-password"));
        let policy = TransferPolicy::bounded();
        assert!(
            fixture
                .session(None)
                .get_blob(
                    FIXTURE_REPOSITORY,
                    &crate::digest::Digest::sha256(b"missing"),
                    policy
                )
                .is_err()
        );
        fixture
            .session(Some(RegistryCredential::basic("alice", "fixture-password")))
            .put_blob(FIXTURE_REPOSITORY, b"payload", None, policy)
            .expect("authorized upload");
    }

    #[test]
    fn bearer_fixture_challenge_is_safe_to_display() {
        let fixture = LocalRegistryFixture::with_auth(FixtureAuth::bearer("fixture-token"));
        let challenge = fixture.challenge().expect("challenge");
        assert!(!format!("{challenge:?}").contains("fixture-token"));
        assert!(
            !format!(
                "{:?}",
                LocalRegistryFixture::with_auth(FixtureAuth::bearer("fixture-token"))
            )
            .contains("fixture-token")
        );
    }
}
