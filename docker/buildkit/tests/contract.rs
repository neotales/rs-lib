// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::time::Duration;

use neotales_docker_buildkit::{
    AdapterError, BuildContext, BuildKitAdapter, BuildKitAdapterFixture, BuilderEndpoint,
    BuilderSelection, CancellationRequest, DockerfilePath, SolveRequest, SolveStatus,
};

const SUCCESS_FIXTURE: &str = include_str!("fixtures/solve-success.json");

fn selection(label: &str) -> BuilderSelection {
    selection_for(label, "https://builder.fixture:9443")
}

fn selection_for(label: &str, endpoint: &str) -> BuilderSelection {
    BuilderSelection::new(
        label,
        BuilderEndpoint::parse(endpoint).expect("validated fixture endpoint"),
    )
    .expect("validated fixture selection")
}

fn request(builder: BuilderSelection) -> SolveRequest {
    SolveRequest::new(
        builder,
        BuildContext::new(b"FROM scratch\n".to_vec()).expect("bounded context"),
        DockerfilePath::new("Dockerfile").expect("contained Dockerfile"),
    )
}

#[tokio::test]
async fn replays_checked_in_status_fixture() {
    let adapter = BuildKitAdapterFixture::from_json(selection("contract"), SUCCESS_FIXTURE)
        .expect("checked-in fixture");
    let capabilities = adapter.capabilities();
    assert!(capabilities.solve);
    assert!(capabilities.status);
    assert!(capabilities.cancellation);
    assert!(!capabilities.sessions);
    assert!(!capabilities.cache_import_export);
    assert!(!capabilities.h2c);

    let mut handle = adapter
        .start_solve(request(adapter.builder().clone()))
        .await
        .expect("fixture solve");
    let mut statuses = Vec::new();
    while let Some(status) = handle.next_status().await {
        statuses.push(status.expect("fixture status"));
    }

    assert_eq!(
        statuses,
        vec![
            SolveStatus::Queued,
            SolveStatus::PreparingContext { context_bytes: 13 },
            SolveStatus::Solving {
                vertex: "[internal] load build definition from Dockerfile".to_owned(),
                current: 1,
                total: Some(1),
            },
            SolveStatus::Exporting {
                image_ref: "registry.example/buildkit-fixture:latest".to_owned(),
            },
            SolveStatus::Completed {
                image_refs: vec!["registry.example/buildkit-fixture:latest".to_owned()],
            },
        ]
    );
    assert!(statuses.last().expect("terminal status").is_terminal());
}

#[tokio::test]
async fn rejects_a_different_explicit_builder() {
    let adapter = BuildKitAdapterFixture::from_json(selection("expected"), SUCCESS_FIXTURE)
        .expect("checked-in fixture");
    let result = adapter
        .start_solve(request(selection_for(
            "development",
            "https://development-builder.example:9443",
        )))
        .await;

    assert!(matches!(result, Err(AdapterError::BuilderMismatch { .. })));
}

#[tokio::test]
async fn caller_owns_cancellation_signal_but_adapter_owns_cleanup() {
    let adapter = BuildKitAdapterFixture::from_json(selection("cancel"), SUCCESS_FIXTURE)
        .expect("checked-in fixture")
        .with_initial_delay(Duration::from_secs(60));
    let mut handle = adapter
        .start_solve(request(adapter.builder().clone()))
        .await
        .expect("fixture solve");
    let cancellation = handle.cancellation();

    assert_eq!(handle.cancel(), CancellationRequest::Requested);
    assert_eq!(cancellation.cancel(), CancellationRequest::AlreadyRequested);
    assert_eq!(handle.next_status().await, Some(Ok(SolveStatus::Cancelled)));
}
