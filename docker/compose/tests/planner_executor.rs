//! Integration tests for Compose lifecycle planning and executor operation ordering.

use std::sync::{Arc, Mutex};

use neotales_docker_compose::{
    ComposeExecutionOptions, ComposeExecutor, ComposeOperationResult, ComposeOperationSink,
    ComposePlan, ComposePlanOperation, ComposePlanner, ComposeProject, ComposeProjectOptions,
    InterpolationValues, MergePolicy,
};

const SOURCE: &str = include_str!("../../../fixtures/compose/v1/lifecycle-plan.yaml");
const EXPECTED_CALLS: &str =
    include_str!("../../../fixtures/compose/v1/executor-calls.expected.json");

fn project() -> ComposeProject {
    ComposeProject::parse_sources(
        &[(SOURCE, "lifecycle-plan.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions {
            merge: MergePolicy::LastWins,
            ..ComposeProjectOptions::default()
        },
    )
    .expect("lifecycle fixture")
}

fn plan() -> ComposePlan {
    ComposePlanner::create(
        &project(),
        neotales_docker_compose::ComposePlanOptions::default(),
    )
    .expect("lifecycle plan")
}

struct Recorder {
    calls: Arc<Mutex<Vec<String>>>,
}

impl ComposeOperationSink for Recorder {
    fn execute<'a>(
        &'a self,
        operation: &'a ComposePlanOperation,
    ) -> neotales_docker_compose::ComposeOperationFuture<'a, ComposeOperationResult> {
        let calls = Arc::clone(&self.calls);
        let id = operation.id.clone();
        let created = matches!(
            operation.kind,
            neotales_docker_compose::ComposePlanOperationKind::CreateNetwork
                | neotales_docker_compose::ComposePlanOperationKind::CreateVolume
                | neotales_docker_compose::ComposePlanOperationKind::CreateContainer
        );
        Box::pin(async move {
            calls.lock().expect("recorder lock").push(id);
            Ok(ComposeOperationResult::new(operation, created))
        })
    }
}

#[tokio::test]
async fn planner_executor_fixture_has_stable_order_and_rolls_forward() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder {
        calls: Arc::clone(&calls),
    };
    let results = ComposeExecutor::apply(&recorder, &plan(), &ComposeExecutionOptions::new())
        .await
        .expect("fixture execution");
    assert_eq!(results.len(), plan().operations.len());
    let expected: Vec<String> = serde_json::from_str(EXPECTED_CALLS).expect("expected calls");
    assert_eq!(&*calls.lock().expect("calls lock"), &expected);
}

#[tokio::test]
async fn cancellation_stops_before_the_next_operation_and_rolls_back() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder {
        calls: Arc::clone(&calls),
    };
    let calls_for_cancel = Arc::clone(&calls);
    let options = ComposeExecutionOptions::new().with_cancellation(Arc::new(move || {
        !calls_for_cancel.lock().expect("calls lock").is_empty()
    }));
    let error = ComposeExecutor::apply(&recorder, &plan(), &options)
        .await
        .expect_err("cancelled execution");
    assert_eq!(error.code(), "compose_cancelled");
    let calls = calls.lock().expect("calls lock");
    assert!(calls.iter().any(|call| call.starts_with("rollback:")));
}
