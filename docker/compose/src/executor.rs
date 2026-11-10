//! Typed, daemon-free Compose operation execution boundary.
//!
//! The executor deliberately knows nothing about Bollard or a process.  A
//! caller supplies one operation sink (a Compose adapter uses the public
//! `neotales-docker` facade; tests use a deterministic recorder).  This keeps
//! planning, ordering, cancellation checks, and rollback policy in the Compose
//! crate while leaving transport and stream ownership at the facade boundary.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{ComposeError, ComposePlan, ComposePlanOperation, ComposePlanOperationKind};

/// A boxed future returned by a Compose operation sink.
pub type ComposeOperationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ComposeExecutionError>> + Send + 'a>>;

/// A safe error raised while applying a Compose plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposeExecutionError {
    code: String,
    message: String,
    raw: Option<String>,
}

impl ComposeExecutionError {
    /// Creates a safe execution error.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            raw: None,
        }
    }

    /// Attaches unmodified lower-layer error text for caller-owned raw output.
    ///
    /// The text is never included in [`Self::message`] and is not used to build
    /// diagnostics; a caller that renders raw errors decides whether to print
    /// it. Values that could contain secrets must not be attached.
    #[must_use]
    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self
    }

    /// Returns the stable error code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the safe human-readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the unmodified lower-layer error text, when one was attached.
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        self.raw.as_deref()
    }
}

impl std::fmt::Display for ComposeExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ComposeExecutionError {}

impl From<ComposeError> for ComposeExecutionError {
    fn from(error: ComposeError) -> Self {
        Self::new(error.code(), error.message())
    }
}

/// Result of applying one explicit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeOperationResult {
    /// Operation identifier that was executed.
    pub operation_id: String,
    /// Resource name affected by the operation.
    pub resource_name: String,
    /// Whether the sink created a new resource.
    pub created: bool,
}

impl ComposeOperationResult {
    /// Creates a successful operation result.
    #[must_use]
    pub fn new(operation: &ComposePlanOperation, created: bool) -> Self {
        Self {
            operation_id: operation.id.clone(),
            resource_name: operation.resource_name.clone(),
            created,
        }
    }
}

/// A typed destination for one plan operation.
///
/// Implementations must return an unsupported-operation error rather than
/// silently emulating an operation with a shell or an unrelated Engine call.
pub trait ComposeOperationSink {
    /// Executes one operation.
    fn execute<'a>(
        &'a self,
        operation: &'a ComposePlanOperation,
    ) -> ComposeOperationFuture<'a, ComposeOperationResult>;
}

/// Cooperative cancellation and rollback policy for the executor.
#[derive(Clone, Default)]
pub struct ComposeExecutionOptions {
    /// Optional callback checked before each operation.
    pub is_cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Remove resources created by the current invocation when a later step
    /// fails or cancellation is observed.
    pub rollback_on_failure: bool,
}

impl ComposeExecutionOptions {
    /// Creates options with rollback enabled and no cancellation callback.
    #[must_use]
    pub fn new() -> Self {
        Self {
            is_cancelled: None,
            rollback_on_failure: true,
        }
    }

    /// Adds one cooperative cancellation callback.
    #[must_use]
    pub fn with_cancellation(mut self, callback: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.is_cancelled = Some(callback);
        self
    }

    /// Enables or disables rollback for this invocation.
    #[must_use]
    pub const fn with_rollback(mut self, enabled: bool) -> Self {
        self.rollback_on_failure = enabled;
        self
    }
}

impl std::fmt::Debug for ComposeExecutionOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComposeExecutionOptions")
            .field("has_cancellation", &self.is_cancelled.is_some())
            .field("rollback_on_failure", &self.rollback_on_failure)
            .finish()
    }
}

/// Executes local Compose plans through a typed operation sink.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComposeExecutor;

impl ComposeExecutor {
    /// Applies non-destructive operations and starts declared containers.
    ///
    /// # Errors
    ///
    /// Returns a sink error or cancellation. If rollback is enabled, only
    /// resources successfully created by this invocation are removed in
    /// reverse order.
    pub async fn apply<S>(
        sink: &S,
        plan: &ComposePlan,
        options: &ComposeExecutionOptions,
    ) -> Result<Vec<ComposeOperationResult>, ComposeExecutionError>
    where
        S: ComposeOperationSink + ?Sized,
    {
        execute_selected(sink, plan, options, |operation| !operation.destructive).await
    }

    /// Creates resources and containers without starting them.
    ///
    /// # Errors
    ///
    /// Returns a sink error or cancellation with the same rollback guarantee
    /// as [`Self::apply`].
    pub async fn create<S>(
        sink: &S,
        plan: &ComposePlan,
        options: &ComposeExecutionOptions,
    ) -> Result<Vec<ComposeOperationResult>, ComposeExecutionError>
    where
        S: ComposeOperationSink + ?Sized,
    {
        execute_selected(sink, plan, options, |operation| {
            !operation.destructive && operation.kind != ComposePlanOperationKind::StartContainer
        })
        .await
    }

    /// Executes only destructive teardown operations.
    ///
    /// # Errors
    ///
    /// Returns a sink error or cancellation.
    pub async fn down<S>(
        sink: &S,
        plan: &ComposePlan,
        options: &ComposeExecutionOptions,
    ) -> Result<Vec<ComposeOperationResult>, ComposeExecutionError>
    where
        S: ComposeOperationSink + ?Sized,
    {
        execute_selected(sink, plan, options, |operation| operation.destructive).await
    }
}

async fn execute_selected<S, F>(
    sink: &S,
    plan: &ComposePlan,
    options: &ComposeExecutionOptions,
    include: F,
) -> Result<Vec<ComposeOperationResult>, ComposeExecutionError>
where
    S: ComposeOperationSink + ?Sized,
    F: Fn(&ComposePlanOperation) -> bool,
{
    let mut completed = Vec::new();
    let mut created = Vec::new();
    for operation in plan
        .operations
        .iter()
        .filter(|operation| include(operation))
    {
        if cancelled(options) {
            if options.rollback_on_failure {
                rollback(sink, &created).await;
            }
            return Err(ComposeExecutionError::new(
                "compose_cancelled",
                "Compose operation was cancelled",
            ));
        }
        match sink.execute(operation).await {
            Ok(result) => {
                if result.created && is_creation(operation.kind) {
                    created.push(rollback_operation(operation));
                }
                completed.push(result);
            }
            Err(error) => {
                if options.rollback_on_failure {
                    rollback(sink, &created).await;
                }
                return Err(error);
            }
        }
    }
    Ok(completed)
}

async fn rollback<S>(sink: &S, created: &[ComposePlanOperation])
where
    S: ComposeOperationSink + ?Sized,
{
    for operation in created.iter().rev() {
        let _ = sink.execute(operation).await;
    }
}

fn is_creation(kind: ComposePlanOperationKind) -> bool {
    matches!(
        kind,
        ComposePlanOperationKind::CreateNetwork
            | ComposePlanOperationKind::CreateVolume
            | ComposePlanOperationKind::CreateContainer
    )
}

fn rollback_operation(operation: &ComposePlanOperation) -> ComposePlanOperation {
    let kind = match operation.kind {
        ComposePlanOperationKind::CreateNetwork => ComposePlanOperationKind::RemoveNetwork,
        ComposePlanOperationKind::CreateVolume => ComposePlanOperationKind::RemoveVolume,
        ComposePlanOperationKind::CreateContainer => ComposePlanOperationKind::RemoveContainer,
        _ => return operation.clone(),
    };
    ComposePlanOperation {
        id: format!("rollback:{}", operation.id),
        kind,
        resource_name: operation.resource_name.clone(),
        labels: operation.labels.clone(),
        intent: BTreeMap::new(),
        destructive: true,
        externally_visible: true,
    }
}

fn cancelled(options: &ComposeExecutionOptions) -> bool {
    options
        .is_cancelled
        .as_ref()
        .is_some_and(|is_cancelled| is_cancelled())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        ComposeExecutionError, ComposeExecutionOptions, ComposeExecutor, ComposeOperationResult,
        ComposeOperationSink,
    };
    use crate::{
        ComposePlan, ComposePlanOperationKind, ComposePlanner, ComposeProject,
        ComposeProjectOptions, InterpolationValues,
    };

    struct Recorder {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl ComposeOperationSink for Recorder {
        fn execute<'a>(
            &'a self,
            operation: &'a crate::ComposePlanOperation,
        ) -> super::ComposeOperationFuture<'a, ComposeOperationResult> {
            let calls = Arc::clone(&self.calls);
            let id = operation.id.clone();
            let created = matches!(
                operation.kind,
                ComposePlanOperationKind::CreateNetwork
                    | ComposePlanOperationKind::CreateVolume
                    | ComposePlanOperationKind::CreateContainer
            );
            Box::pin(async move {
                calls.lock().expect("recorder lock").push(id);
                Ok(ComposeOperationResult::new(operation, created))
            })
        }
    }

    fn plan() -> ComposePlan {
        let project = ComposeProject::parse_yaml(
            "name: demo\nservices:\n  app:\n    image: alpine\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project");
        ComposePlanner::create(
            &project,
            crate::ComposePlanOptions {
                policy: crate::ComposePlanPolicy::permissive(),
                ..crate::ComposePlanOptions::default()
            },
        )
        .expect("plan")
    }

    #[tokio::test]
    async fn executor_rolls_back_only_resources_created_by_the_invocation() {
        struct Failing {
            calls: Arc<Mutex<Vec<String>>>,
        }
        impl ComposeOperationSink for Failing {
            fn execute<'a>(
                &'a self,
                operation: &'a crate::ComposePlanOperation,
            ) -> super::ComposeOperationFuture<'a, ComposeOperationResult> {
                let calls = Arc::clone(&self.calls);
                let id = operation.id.clone();
                let should_fail = operation.kind == ComposePlanOperationKind::StartContainer;
                Box::pin(async move {
                    calls.lock().expect("calls lock").push(id);
                    if should_fail {
                        Err(ComposeExecutionError::new("fixture", "start failed"))
                    } else {
                        Ok(ComposeOperationResult::new(operation, true))
                    }
                })
            }
        }
        let sink = Failing {
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let error = ComposeExecutor::apply(&sink, &plan(), &ComposeExecutionOptions::new())
            .await
            .expect_err("start failure");
        assert_eq!(error.code(), "fixture");
        let calls = sink.calls.lock().expect("calls lock");
        assert!(calls.iter().any(|call| call.starts_with("rollback:")));
    }

    #[tokio::test]
    async fn cancellation_is_checked_before_the_first_operation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            calls: Arc::clone(&calls),
        };
        let options = ComposeExecutionOptions::new().with_cancellation(Arc::new(|| true));
        let result = ComposeExecutor::apply(&recorder, &plan(), &options).await;
        assert_eq!(result.expect_err("cancelled").code(), "compose_cancelled");
        assert!(calls.lock().expect("calls lock").is_empty());
    }
}
