//! Checked-in fixture adapter for the pre-transport BuildKit contract.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::Deserialize;
use tokio::sync::mpsc;

use crate::{
    AdapterCapabilities, AdapterError, BuildKitAdapter, BuilderSelection, MAX_BUILD_CONTEXT_BYTES,
    SolveCancellation, SolveHandle, SolveId, SolveRequest, SolveStatus, StartSolveFuture,
};

/// Current version of the JSON status-plan fixture format.
pub const FIXTURE_FORMAT_VERSION: u8 = 1;

/// Maximum accepted JSON fixture size.
pub const MAX_FIXTURE_BYTES: usize = 1024 * 1024;

const MAX_FIXTURE_STATUSES: usize = 1024;
const MAX_STATUS_TEXT_BYTES: usize = 4096;
const MAX_IMAGE_REF_BYTES: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureDocument {
    version: u8,
    statuses: Vec<SolveStatus>,
}

/// A deterministic in-memory BuildKit adapter.
///
/// The adapter replays a validated status plan for one exact builder endpoint.
/// It performs no network, filesystem, session, cache, or exporter operation.
#[derive(Clone, Debug)]
pub struct BuildKitAdapterFixture {
    builder: BuilderSelection,
    statuses: Arc<[SolveStatus]>,
    context_limit: usize,
    initial_delay: Duration,
    next_solve: Arc<AtomicU64>,
}

impl BuildKitAdapterFixture {
    /// Creates a fixture from a programmatic status plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is empty, contains malformed status data,
    /// or does not end with exactly one terminal status.
    pub fn new(
        builder: BuilderSelection,
        statuses: Vec<SolveStatus>,
    ) -> Result<Self, AdapterError> {
        validate_statuses(&statuses)?;
        Ok(Self {
            builder,
            statuses: Arc::from(statuses),
            context_limit: MAX_BUILD_CONTEXT_BYTES,
            initial_delay: Duration::ZERO,
            next_solve: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Creates a fixture from the versioned JSON status-plan format.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized or malformed document, an unsupported
    /// format version, or an invalid status plan.
    pub fn from_json(builder: BuilderSelection, fixture: &str) -> Result<Self, AdapterError> {
        if fixture.len() > MAX_FIXTURE_BYTES {
            return Err(AdapterError::InvalidFixture(format!(
                "JSON exceeds {MAX_FIXTURE_BYTES} bytes"
            )));
        }
        let document: FixtureDocument = serde_json::from_str(fixture)
            .map_err(|error| AdapterError::InvalidFixture(error.to_string()))?;
        if document.version != FIXTURE_FORMAT_VERSION {
            return Err(AdapterError::InvalidFixture(format!(
                "version {} is unsupported; expected {FIXTURE_FORMAT_VERSION}",
                document.version
            )));
        }
        Self::new(builder, document.statuses)
    }

    /// Sets a lower application-specific context archive limit.
    ///
    /// # Errors
    ///
    /// Returns an error when `maximum` is zero or greater than the repository
    /// context limit.
    pub fn with_context_limit(mut self, maximum: usize) -> Result<Self, AdapterError> {
        if maximum == 0 || maximum > MAX_BUILD_CONTEXT_BYTES {
            return Err(AdapterError::InvalidFixture(format!(
                "context limit must be between 1 and {MAX_BUILD_CONTEXT_BYTES} bytes"
            )));
        }
        self.context_limit = maximum;
        Ok(self)
    }

    /// Delays the first fixture status so cancellation can be tested without a
    /// real BuildKit daemon.
    #[must_use]
    pub const fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }
}

impl BuildKitAdapter for BuildKitAdapterFixture {
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            solve: true,
            status: true,
            cancellation: true,
            sessions: false,
            cache_import_export: false,
            h2c: false,
        }
    }

    fn builder(&self) -> &BuilderSelection {
        &self.builder
    }

    fn start_solve(&self, request: SolveRequest) -> StartSolveFuture {
        let expected = self.builder.clone();
        let statuses = Arc::clone(&self.statuses);
        let context_limit = self.context_limit;
        let initial_delay = self.initial_delay;
        let next_solve = Arc::clone(&self.next_solve);

        Box::pin(async move {
            if request.builder.endpoint() != expected.endpoint() {
                return Err(AdapterError::BuilderMismatch {
                    requested: request.builder.endpoint().clone(),
                    expected: expected.endpoint().clone(),
                });
            }
            let actual = request.context.len();
            if actual > context_limit {
                return Err(AdapterError::ContextTooLarge {
                    actual,
                    maximum: context_limit,
                });
            }

            let sequence = next_solve.fetch_add(1, Ordering::Relaxed);
            let solve_id = SolveId::new(format!("fixture-{sequence:08}"))
                .map_err(|error| AdapterError::InvalidFixture(error.to_string()))?;
            let cancellation = SolveCancellation::new();
            let worker_cancellation = cancellation.clone();
            let (sender, receiver) = mpsc::channel(statuses.len().saturating_add(1));

            tokio::spawn(async move {
                emit_fixture_statuses(statuses, sender, worker_cancellation, initial_delay).await;
            });

            Ok(SolveHandle::new(solve_id, cancellation, receiver))
        })
    }
}

async fn emit_fixture_statuses(
    statuses: Arc<[SolveStatus]>,
    sender: mpsc::Sender<Result<SolveStatus, AdapterError>>,
    cancellation: SolveCancellation,
    initial_delay: Duration,
) {
    if !initial_delay.is_zero() {
        tokio::select! {
            () = cancellation.cancelled() => {
                send_cancelled(&sender).await;
                return;
            }
            () = tokio::time::sleep(initial_delay) => {}
        }
    }

    for status in statuses.iter() {
        if cancellation.is_requested() {
            send_cancelled(&sender).await;
            return;
        }
        if sender.send(Ok(status.clone())).await.is_err() {
            return;
        }
    }
}

async fn send_cancelled(sender: &mpsc::Sender<Result<SolveStatus, AdapterError>>) {
    let _result = sender.send(Ok(SolveStatus::Cancelled)).await;
}

fn validate_statuses(statuses: &[SolveStatus]) -> Result<(), AdapterError> {
    if statuses.len() > MAX_FIXTURE_STATUSES {
        return Err(AdapterError::InvalidFixture(format!(
            "status plan exceeds {MAX_FIXTURE_STATUSES} entries"
        )));
    }
    let Some(last) = statuses.last() else {
        return Err(AdapterError::InvalidFixture(
            "status plan must not be empty".to_owned(),
        ));
    };
    if !last.is_terminal() {
        return Err(AdapterError::InvalidFixture(
            "status plan must end with a terminal status".to_owned(),
        ));
    }
    if statuses[..statuses.len() - 1]
        .iter()
        .any(SolveStatus::is_terminal)
    {
        return Err(AdapterError::InvalidFixture(
            "status plan contains more than one terminal status".to_owned(),
        ));
    }

    for status in statuses {
        match status {
            SolveStatus::PreparingContext { context_bytes } => {
                if *context_bytes > MAX_BUILD_CONTEXT_BYTES as u64 {
                    return Err(AdapterError::InvalidFixture(format!(
                        "context status exceeds {MAX_BUILD_CONTEXT_BYTES} bytes"
                    )));
                }
            }
            SolveStatus::Solving {
                vertex,
                current,
                total,
            } => {
                if !bounded_text(vertex)
                    || *current == 0
                    || total.is_some_and(|total| total < *current)
                {
                    return Err(AdapterError::InvalidFixture(
                        "solving status has an invalid vertex or progress count".to_owned(),
                    ));
                }
            }
            SolveStatus::Exporting { image_ref } => {
                if !valid_image_ref(image_ref) {
                    return Err(AdapterError::InvalidFixture(
                        "exporting status has an invalid image reference".to_owned(),
                    ));
                }
            }
            SolveStatus::Completed { image_refs } => {
                if image_refs.is_empty() || image_refs.iter().any(|value| !valid_image_ref(value)) {
                    return Err(AdapterError::InvalidFixture(
                        "completed status has invalid image references".to_owned(),
                    ));
                }
            }
            SolveStatus::Failed { code, message } => {
                if !bounded_text(code) || !bounded_text(message) {
                    return Err(AdapterError::InvalidFixture(
                        "failed status has an invalid code or message".to_owned(),
                    ));
                }
            }
            SolveStatus::Queued | SolveStatus::Cancelled => {}
        }
    }
    Ok(())
}

fn valid_image_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IMAGE_REF_BYTES && !value.chars().any(char::is_control)
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STATUS_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BuildKitAdapterFixture, MAX_FIXTURE_BYTES};
    use crate::{
        AdapterError, BuildKitAdapter, BuilderEndpoint, BuilderSelection, CancellationRequest,
        SolveRequest, SolveStatus,
    };
    use crate::{BuildContext, DockerfilePath};

    fn builder(name: &str) -> BuilderSelection {
        BuilderSelection::new(
            name,
            BuilderEndpoint::parse("https://builder.fixture:9443").expect("fixture endpoint"),
        )
        .expect("fixture selection")
    }

    fn other_builder() -> BuilderSelection {
        BuilderSelection::new(
            "other",
            BuilderEndpoint::parse("https://other-builder.fixture:9443")
                .expect("other fixture endpoint"),
        )
        .expect("other fixture selection")
    }

    fn request(builder: BuilderSelection) -> SolveRequest {
        SolveRequest::new(
            builder,
            BuildContext::new(b"FROM scratch\n".to_vec()).expect("context"),
            DockerfilePath::new("Dockerfile").expect("Dockerfile"),
        )
    }

    #[tokio::test]
    async fn cancellation_replaces_delayed_status_plan() {
        let adapter = BuildKitAdapterFixture::new(
            builder("cancel"),
            vec![SolveStatus::Queued, SolveStatus::Cancelled],
        )
        .expect("status plan")
        .with_initial_delay(Duration::from_secs(60));
        let mut handle = adapter
            .start_solve(request(adapter.builder().clone()))
            .await
            .expect("fixture solve");

        assert_eq!(handle.cancel(), CancellationRequest::Requested);
        assert_eq!(handle.next_status().await, Some(Ok(SolveStatus::Cancelled)));
        assert_eq!(handle.cancel(), CancellationRequest::AlreadyRequested);
    }

    #[tokio::test]
    async fn mismatched_builder_never_falls_back() {
        let adapter = BuildKitAdapterFixture::new(
            builder("expected"),
            vec![SolveStatus::Completed {
                image_refs: vec!["registry.example/fixture:latest".to_owned()],
            }],
        )
        .expect("status plan");
        let result = adapter.start_solve(request(other_builder())).await;

        assert!(matches!(result, Err(AdapterError::BuilderMismatch { .. })));
    }

    #[tokio::test]
    async fn enforces_adapter_context_limit() {
        let adapter = BuildKitAdapterFixture::new(
            builder("bounded"),
            vec![SolveStatus::Completed {
                image_refs: vec!["registry.example/fixture:latest".to_owned()],
            }],
        )
        .expect("status plan")
        .with_context_limit(4)
        .expect("bounded fixture");
        let result = adapter.start_solve(request(builder("bounded"))).await;

        assert!(matches!(
            result,
            Err(AdapterError::ContextTooLarge {
                actual: 13,
                maximum: 4
            })
        ));
    }

    #[test]
    fn rejects_invalid_or_oversized_fixtures() {
        assert!(matches!(
            BuildKitAdapterFixture::new(
                builder("invalid"),
                vec![SolveStatus::Queued, SolveStatus::Queued]
            ),
            Err(AdapterError::InvalidFixture(_))
        ));
        assert!(matches!(
            BuildKitAdapterFixture::from_json(
                builder("oversized"),
                &"x".repeat(MAX_FIXTURE_BYTES + 1)
            ),
            Err(AdapterError::InvalidFixture(_))
        ));
    }
}
