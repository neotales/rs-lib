//! Conformance tests for the OCI Distribution boundary.
//!
//! These run against the crate exactly as a consumer would, through its public
//! API only, so they cannot pass by reaching into an internal detail that the
//! published surface does not actually offer.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file rather than the workspace, so a genuinely
// undocumented public item in the crate is still reported.
#![allow(missing_docs)]

use neotales_oci_distribution::{
    AuthChallenge, ContentPolicy, Digest, FixtureAuth, LocalRegistryFixture, MediaType,
    OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST, ReferenceError, RegistryCredential, RegistryEndpoint,
    RegistryReference, TransferPolicy, deterministic_fixture, redact_sensitive_text,
};

#[test]
fn normalizes_references_and_rejects_cross_origin_locations() {
    let reference = RegistryReference::parse("HTTPS://REGISTRY.EXAMPLE:443/Team/App:Stable")
        .expect("reference");
    assert_eq!(reference.registry(), "registry.example");
    assert_eq!(reference.repository(), "team/app");
    assert_eq!(reference.tag(), Some("Stable"));
    assert_eq!(reference.to_string(), "registry.example/team/app:Stable");

    let endpoint = RegistryEndpoint::parse("https://registry.example/prefix/").expect("endpoint");
    assert_eq!(
        endpoint
            .resolve_location("https://registry.example/upload/1?digest=sha256%3Aabc")
            .expect("same origin"),
        "https://registry.example/upload/1?digest=sha256%3Aabc"
    );
    assert_eq!(
        endpoint.resolve_location("https://attacker.example/upload/1"),
        Err(ReferenceError::ForeignOrigin)
    );
}

#[test]
fn verifies_digest_and_explicit_media_negotiation() {
    let body = br#"{"schemaVersion":2}"#;
    let digest = Digest::sha256(body);
    let policy = ContentPolicy::new(
        [
            MediaType::constant(OCI_IMAGE_MANIFEST),
            MediaType::constant(OCI_IMAGE_INDEX),
        ],
        body.len(),
    )
    .expect("policy");
    assert_eq!(
        policy.accept_header(),
        "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"
    );
    let content = policy
        .verify(Some(OCI_IMAGE_MANIFEST), Some(digest.as_str()), body)
        .expect("verified content");
    assert_eq!(content.digest(), &digest);
    assert!(
        policy
            .verify(Some(OCI_IMAGE_MANIFEST), Some("sha256:bad"), body)
            .is_err()
    );
}

#[test]
fn deterministic_fixture_round_trips_and_bounds_transfers() {
    let fixture = deterministic_fixture();
    let digest = Digest::sha256(neotales_oci_distribution::FIXTURE_BLOB);
    let blob = fixture
        .get_blob(
            neotales_oci_distribution::FIXTURE_REPOSITORY,
            &digest,
            TransferPolicy::bounded(),
        )
        .expect("blob");
    assert_eq!(blob.content(), neotales_oci_distribution::FIXTURE_BLOB);

    let manifest = fixture
        .get_manifest(
            neotales_oci_distribution::FIXTURE_REPOSITORY,
            neotales_oci_distribution::FIXTURE_TAG,
            &[MediaType::constant(OCI_IMAGE_MANIFEST)],
            TransferPolicy::bounded(),
        )
        .expect("manifest");
    assert_eq!(manifest.media_type().as_str(), OCI_IMAGE_MANIFEST);
    let index = fixture
        .get_index(
            neotales_oci_distribution::FIXTURE_REPOSITORY,
            neotales_oci_distribution::FIXTURE_INDEX_TAG,
            TransferPolicy::bounded(),
        )
        .expect("index");
    assert_eq!(index.media_type().as_str(), OCI_IMAGE_INDEX);
    assert!(
        fixture
            .get_manifest(
                neotales_oci_distribution::FIXTURE_REPOSITORY,
                neotales_oci_distribution::FIXTURE_TAG,
                &[MediaType::constant(OCI_IMAGE_MANIFEST)],
                TransferPolicy::new(1).expect("limit"),
            )
            .is_err()
    );
}

#[test]
fn fixture_keeps_auth_secrets_out_of_diagnostics() {
    let fixture = LocalRegistryFixture::with_auth(FixtureAuth::bearer("fixture-bearer-secret"));
    let challenge = fixture.challenge().expect("bearer challenge");
    assert!(matches!(challenge, AuthChallenge::Bearer { .. }));
    let diagnostics = format!("{fixture:?} {challenge:?}");
    assert!(!diagnostics.contains("fixture-bearer-secret"));
    assert!(
        !redact_sensitive_text("Authorization: Bearer fixture-bearer-secret")
            .contains("fixture-bearer-secret")
    );

    let basic = LocalRegistryFixture::with_auth(FixtureAuth::basic("alice", "fixture-password"));
    basic
        .session(Some(RegistryCredential::basic("alice", "fixture-password")))
        .put_blob("team/app", b"payload", None, TransferPolicy::bounded())
        .expect("authorized upload");
}

#[test]
fn digest_addressed_manifest_can_be_read_back() {
    let fixture = LocalRegistryFixture::new();
    let body = br#"{"schemaVersion":2}"#;
    let media_type = MediaType::constant(OCI_IMAGE_MANIFEST);
    let receipt = fixture
        .put_manifest(
            "team/app",
            "stable",
            body,
            &media_type,
            TransferPolicy::bounded(),
        )
        .expect("manifest upload");
    let loaded = fixture
        .get_manifest(
            "team/app",
            receipt.digest().as_str(),
            &[media_type],
            TransferPolicy::bounded(),
        )
        .expect("digest lookup");
    assert_eq!(loaded.content(), body);
}
