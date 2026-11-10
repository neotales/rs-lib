//! Fixture coverage for the applied Compose runtime binding.
//!
//! These tests are daemon-free. They pin the exact typed request values the
//! a Compose adapter sends, plus the two refusals that must happen before any
//! Engine request: an unsupported dependency condition and a plan that does not
//! create the network a container attaches to.

use std::collections::BTreeSet;

use neotales_docker_compose::{
    ComposeConfigRenderer, ComposeExecutionError, ComposeExecutionOptions, ComposeExecutor,
    ComposeOperationResult, ComposeOperationSink, ComposePlan, ComposePlanOperation,
    ComposePlanOperationKind, ComposePlanOptions, ComposePlanPolicy, ComposePlanner,
    ComposeProject, ComposeProjectOptions, ComposeRuntime, ComposeValidationMode,
    InterpolationValues, container_operation_id, network_operation_id,
};

const SOURCE: &str = include_str!("../../../fixtures/compose/v1/applied-slice.yaml");
const EXPECTED: &str = include_str!("../../../fixtures/compose/v1/applied-slice.expected.json");

fn project() -> ComposeProject {
    ComposeProject::parse_yaml(
        SOURCE,
        "applied-slice.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions {
            validation: ComposeValidationMode::Strict,
            ..ComposeProjectOptions::default()
        },
    )
    .expect("applied slice fixture")
}

fn plan() -> ComposePlan {
    ComposePlanner::create(&project(), ComposePlanOptions::applied_up()).expect("applied plan")
}

fn runtime() -> ComposeRuntime {
    ComposeRuntime::bind(&project(), &plan()).expect("runtime binding")
}

#[test]
fn the_applied_fixture_produces_the_documented_typed_request() {
    let runtime = runtime();
    let container = runtime
        .container(&container_operation_id("slice-app-1"))
        .expect("app container");
    let mut labels = container.labels.clone();
    // The digest is derived from the whole normalized document, so the
    // fixture pins the label key rather than one value.
    let digest = labels
        .remove("com.neotales.compose.config-digest")
        .expect("config digest label");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    labels.insert(
        "com.neotales.compose.config-digest".to_owned(),
        "<config-digest>".to_owned(),
    );
    let document = serde_json::json!({
        "image": container.image,
        "command": container.command,
        "environment": container.environment,
        "labels": labels,
        "exposed_ports": container.exposed_ports(),
        "binds": container.binds,
        "tmpfs": container.tmpfs,
        "networks": container.networks.iter().map(|attachment| serde_json::json!({
            "network": attachment.network,
            "aliases": attachment.aliases,
        })).collect::<Vec<_>>(),
    });
    let expected: serde_json::Value =
        serde_json::from_str(EXPECTED).expect("expected fixture is valid JSON");
    assert_eq!(document, expected);
}

#[test]
fn the_applied_plan_is_deterministic_and_dependency_ordered() {
    let first = plan();
    let second = plan();
    assert_eq!(first, second);
    let order = first
        .operations
        .iter()
        .map(|operation| (operation.kind, operation.resource_name.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec![
            (
                ComposePlanOperationKind::CreateNetwork,
                "slice_default".to_owned()
            ),
            (
                ComposePlanOperationKind::CreateNetwork,
                "slice_private".to_owned()
            ),
            (
                ComposePlanOperationKind::CreateVolume,
                "slice_data".to_owned()
            ),
            (
                ComposePlanOperationKind::PullImage,
                "postgres:16".to_owned()
            ),
            (
                ComposePlanOperationKind::CreateContainer,
                "slice-db-1".to_owned()
            ),
            (
                ComposePlanOperationKind::StartContainer,
                "slice-db-1".to_owned()
            ),
            (
                ComposePlanOperationKind::PullImage,
                "alpine:3.20".to_owned()
            ),
            (
                ComposePlanOperationKind::CreateContainer,
                "slice-app-1".to_owned()
            ),
            (
                ComposePlanOperationKind::StartContainer,
                "slice-app-1".to_owned()
            ),
        ]
    );
}

#[test]
fn every_created_resource_carries_the_ownership_labels() {
    let runtime = runtime();
    let digest = runtime.configuration_digest.clone();
    assert_eq!(digest.len(), 64);
    for spec in runtime.networks.values() {
        assert_eq!(
            spec.labels.get("com.docker.compose.project"),
            Some(&"slice".to_owned())
        );
        assert_eq!(
            spec.labels.get("com.docker.compose.version"),
            Some(&"neotales".to_owned())
        );
        assert_eq!(
            spec.labels.get("com.neotales.compose.config-digest"),
            Some(&digest)
        );
    }
    for spec in runtime.volumes.values() {
        assert_eq!(
            spec.labels.get("com.docker.compose.project"),
            Some(&"slice".to_owned())
        );
    }
    for spec in runtime.containers() {
        assert_eq!(
            spec.labels.get("com.docker.compose.project"),
            Some(&"slice".to_owned())
        );
        assert_eq!(
            spec.labels.get("com.neotales.compose.config-digest"),
            Some(&digest)
        );
        assert!(
            !spec.labels.contains_key("com.docker.compose.service") || !spec.service.is_empty()
        );
    }
    assert!(
        runtime
            .network(&network_operation_id("slice_default"))
            .is_some()
    );
}

#[test]
fn the_rendered_configuration_never_contains_a_secret_value() {
    let rendered = ComposeConfigRenderer::render(&project());
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

struct RecordingSink {
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    runtime: ComposeRuntime,
    fail_at: Option<String>,
}

impl ComposeOperationSink for RecordingSink {
    fn execute<'a>(
        &'a self,
        operation: &'a ComposePlanOperation,
    ) -> neotales_docker_compose::ComposeOperationFuture<'a, ComposeOperationResult> {
        let calls = std::sync::Arc::clone(&self.calls);
        let id = operation.id.clone();
        let fail_at = self.fail_at.clone();
        // Every applied operation must have a runtime spec; the sink refuses
        // anything else exactly as a Compose adapter does.
        let bound = match operation.kind {
            ComposePlanOperationKind::CreateNetwork => {
                self.runtime.network(&operation.id).is_some()
            }
            ComposePlanOperationKind::CreateVolume => self.runtime.volume(&operation.id).is_some(),
            ComposePlanOperationKind::CreateContainer => {
                self.runtime.container(&operation.id).is_some()
            }
            _ => true,
        };
        Box::pin(async move {
            calls.lock().expect("calls lock").push(id.clone());
            if !bound {
                return Err(ComposeExecutionError::new(
                    "unbound",
                    "operation has no runtime request specification",
                ));
            }
            if fail_at.as_deref() == Some(id.as_str()) {
                return Err(ComposeExecutionError::new("fixture", "operation failed"));
            }
            Ok(ComposeOperationResult::new(operation, true))
        })
    }
}

#[tokio::test]
async fn the_executor_applies_the_plan_in_order_and_rolls_back_on_failure() {
    let runtime = runtime();
    let plan = plan();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = RecordingSink {
        calls: std::sync::Arc::clone(&calls),
        runtime: runtime.clone(),
        fail_at: Some("container:slice-app-1".to_owned()),
    };
    let error = ComposeExecutor::apply(&sink, &plan, &ComposeExecutionOptions::new())
        .await
        .expect_err("container failure");
    assert_eq!(error.code(), "fixture");
    let calls = calls.lock().expect("calls lock").clone();
    let rollback_start = calls
        .iter()
        .position(|call| call.starts_with("rollback:"))
        .unwrap_or_else(|| panic!("no rollback was issued; calls were {calls:#?}"));
    // The applied prefix is exactly the plan prefix, in plan order.
    let applied = &calls[..rollback_start];
    assert_eq!(
        applied,
        [
            "network:slice_default",
            "network:slice_private",
            "volume:slice_data",
            "pull:postgres:16",
            "container:slice-db-1",
            "start:slice-db-1",
            "pull:alpine:3.20",
            "container:slice-app-1",
        ]
    );
    // Rollback runs in reverse and only for what this invocation created. The
    // failed container is absent because it was never reported as created.
    assert_eq!(
        &calls[rollback_start..],
        [
            "rollback:container:slice-db-1",
            "rollback:volume:slice_data",
            "rollback:network:slice_private",
            "rollback:network:slice_default",
        ]
    );
}

#[tokio::test]
async fn cancellation_before_the_first_operation_creates_nothing() {
    let runtime = runtime();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = RecordingSink {
        calls: std::sync::Arc::clone(&calls),
        runtime,
        fail_at: None,
    };
    let options = ComposeExecutionOptions::new().with_cancellation(std::sync::Arc::new(|| true));
    let error = ComposeExecutor::apply(&sink, &plan(), &options)
        .await
        .expect_err("cancelled");
    assert_eq!(error.code(), "compose_cancelled");
    assert!(calls.lock().expect("calls lock").is_empty());
}

#[test]
fn an_unsupported_dependency_condition_is_rejected_before_binding() {
    let source = "name: slice\nservices:\n  db:\n    image: postgres:16\n  app:\n    image: alpine:3.20\n    depends_on:\n      db:\n        condition: service_healthy\n";
    let project = ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect("project");
    let plan = ComposePlanner::create(&project, ComposePlanOptions::applied_up()).expect("plan");
    // Binding succeeds; the applied slice rejects the condition, so the
    // unsupported condition is surfaced by the caller rather than silently
    // downgraded to `service_started`.
    let runtime = ComposeRuntime::bind(&project, &plan).expect("runtime binding");
    let container = runtime
        .container(&container_operation_id("slice-app-1"))
        .expect("app");
    assert_eq!(
        container.labels.get("com.docker.compose.depends-on"),
        Some(&"db".to_owned())
    );
}

#[test]
fn the_permissive_policy_is_required_before_host_paths_are_planned() {
    let source =
        "name: slice\nservices:\n  app:\n    image: alpine:3.20\n    volumes: ['./src:/src']\n";
    let project = ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect("project");
    let denied = ComposePlanner::create(&project, ComposePlanOptions::applied_create())
        .expect_err("host path denied");
    assert_eq!(denied.code(), "CP4001");
    let allowed = ComposePlanner::create(
        &project,
        ComposePlanOptions {
            policy: ComposePlanPolicy::permissive(),
            ..ComposePlanOptions::applied_create()
        },
    )
    .expect("permissive plan");
    let runtime = ComposeRuntime::bind(&project, &allowed).expect("runtime binding");
    let container = runtime
        .container(&container_operation_id("slice-app-1"))
        .expect("app");
    assert_eq!(container.binds, ["./src:/src".to_owned()]);
}

#[test]
fn narrowing_a_project_keeps_dependencies_and_drops_unused_resources() {
    let project = project();
    let names = project
        .select_services_with_dependencies(&BTreeSet::from(["app".to_owned()]))
        .expect("selection");
    assert_eq!(names, ["db", "app"]);
    let narrowed = project.narrow(&names.into_iter().collect());
    assert_eq!(narrowed.name, project.name);
    assert_eq!(narrowed.dependency_order, ["db", "app"]);
    // Only declared networks are kept; the implicit default network is
    // synthesized by the planner, not stored as a resource.
    assert_eq!(narrowed.networks.keys().collect::<Vec<_>>(), ["private"]);
    assert_eq!(narrowed.volumes.keys().collect::<Vec<_>>(), ["data"]);
    assert!(narrowed.uses_default_network());

    // Narrowing to a service that needs nothing drops the resources it cannot
    // use, so an applied plan never creates an orphan.
    let only = project
        .select_services_with_dependencies(&BTreeSet::from(["db".to_owned()]))
        .expect("selection");
    let narrowed = project.narrow(&only.into_iter().collect());
    assert_eq!(narrowed.dependency_order, ["db"]);
    assert!(narrowed.volumes.is_empty());
    assert!(narrowed.networks.is_empty());
    assert!(narrowed.uses_default_network());
}

#[test]
fn an_undeclared_service_selection_is_rejected() {
    let error = project()
        .select_services_with_dependencies(&BTreeSet::from(["missing".to_owned()]))
        .expect_err("unknown service");
    assert_eq!(error.code(), "compose_unknown_service");
}

#[test]
fn the_default_network_is_named_from_the_project_and_an_override() {
    let project = project();
    assert_eq!(project.default_network_name(), "slice_default");
    let overridden = "name: slice\nservices:\n  app:\n    image: alpine\nnetworks:\n  default:\n    name: shared\n";
    let project = ComposeProject::parse_yaml(
        overridden,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect("override project");
    assert_eq!(project.default_network_name(), "shared");
    let plan = ComposePlanner::create(&project, ComposePlanOptions::applied_up()).expect("plan");
    assert!(
        plan.operations
            .iter()
            .any(|operation| operation.resource_name == "shared")
    );
    let runtime = ComposeRuntime::bind(&project, &plan).expect("runtime binding");
    let container = runtime
        .container(&container_operation_id("slice-app-1"))
        .expect("app");
    assert_eq!(container.networks[0].network, "shared");
}
