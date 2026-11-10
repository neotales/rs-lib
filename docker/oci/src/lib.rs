//! Separate OCI Distribution policy and fixture boundary.
//!
//! `neotales-oci-distribution` is intentionally independent from the Docker
//! Engine client.  It owns registry reference normalization, content
//! addressing, explicit media-type negotiation, and short-lived registry
//! authentication policy.  The first bounded slice uses a deterministic
//! in-memory fixture; an HTTP transport, retries, resumable uploads, and
//! mirroring remain follow-up work.
//!
//! No type in this crate reads Docker Engine credentials or
//! `X-Registry-Auth`.  Callers provide an independent
//! [`RegistryCredentialProvider`] to a future transport.

pub mod auth;
pub mod digest;
pub mod fixture;
pub mod negotiation;
pub mod reference;
pub mod transfer;

pub use auth::{
    AuthChallenge, CredentialError, CredentialScheme, InMemoryRegistryCredentialProvider,
    RegistryCredential, RegistryCredentialProvider, StaticRegistryCredentialProvider,
    parse_auth_challenge, parse_auth_challenges, redact_sensitive_text,
};
pub use digest::{Digest, DigestAlgorithm, DigestError, DigestMismatch, HeaderDigestError};
pub use fixture::{
    FIXTURE_BLOB, FIXTURE_INDEX_TAG, FIXTURE_REPOSITORY, FIXTURE_TAG, FixtureAuth, FixtureError,
    FixtureSession, LocalRegistryFixture, LocalRegistrySession, RegistryFixture,
};
pub use negotiation::{
    AcceptEntry, AcceptHeader, ContentNegotiation, ContentPolicy, DOCKER_IMAGE_MANIFEST,
    DOCKER_MANIFEST_LIST, ManifestContentPolicy, MediaType, NegotiationError,
    OCI_ARTIFACT_MANIFEST, OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST, VerifiedContent,
};
pub use reference::{
    DEFAULT_REGISTRY, DOCKER_HUB_REGISTRY, ReferenceError, ReferenceKind, RegistryEndpoint,
    RegistryReference, RegistryScheme, normalize_registry, normalize_repository,
};
pub use transfer::{
    BoundedTransferPolicy, DEFAULT_MAX_TRANSFER_BYTES, TransferError, TransferLimits,
    TransferPolicy, TransferProgress, TransferReceipt,
};

/// The long-form package name used in documentation and issue references.
pub const CRATE_NAME: &str = "neotales-oci-distribution";

/// Compatibility aliases for callers that use the OCI terminology directly.
///
/// The OCI specification calls these things a reference, a digest and a
/// credential. The crate's own names say "registry" instead, which reads better
/// next to a Docker Engine client, so both spellings resolve to the same type
/// rather than forcing a caller to pick one.
pub type OciReference = RegistryReference;
/// An alias for [`Digest`], under the OCI spelling.
pub type OciDigest = Digest;
/// An alias for [`RegistryCredential`], under the OCI spelling.
pub type OciRegistryCredential = RegistryCredential;
/// An alias for [`RegistryCredentialProvider`], under the OCI spelling.
pub use RegistryCredentialProvider as OciRegistryCredentialProvider;
/// An alias for [`RegistryCredential`], under the OCI spelling.
pub type OciRegistryAuth = RegistryCredential;
/// An alias for [`TransferPolicy`], under the OCI spelling.
pub type OciTransferPolicy = TransferPolicy;

/// Creates the fixed local registry fixture used by deterministic tests.
#[must_use]
pub fn deterministic_fixture() -> LocalRegistryFixture {
    LocalRegistryFixture::deterministic()
}

#[cfg(test)]
mod tests {
    use super::{ContentPolicy, Digest, MediaType, OCI_IMAGE_MANIFEST, redact_sensitive_text};

    #[test]
    fn root_exports_keep_the_boundary_usable_without_engine_types() {
        let digest = Digest::sha256(b"boundary");
        assert!(digest.verify(b"boundary").is_ok());
        let policy =
            ContentPolicy::new([MediaType::constant(OCI_IMAGE_MANIFEST)], 32).expect("policy");
        assert!(policy.accept_header().contains("application/vnd.oci"));
        assert!(!redact_sensitive_text("Bearer top-secret").contains("top-secret"));
    }
}
