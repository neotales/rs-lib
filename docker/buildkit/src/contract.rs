//! Adapter, status stream, and cancellation ownership contracts.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::Deserialize;
use tokio::sync::{mpsc, watch};

use crate::{BuilderEndpoint, BuilderSelection, SolveRequest};

const MAX_SOLVE_ID_BYTES: usize = 128;

/// Capabilities exposed by a BuildKit adapter implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct AdapterCapabilities {
    /// The adapter can start Dockerfile solves.
    pub solve: bool,
    /// The adapter exposes solve status updates.
    pub status: bool,
    /// The adapter observes caller cancellation requests.
    pub cancellation: bool,
    /// The adapter owns a remote BuildKit session.
    pub sessions: bool,
    /// The adapter supports cache import or export.
    pub cache_import_export: bool,
    /// The adapter can connect over cleartext HTTP/2.
    pub h2c: bool,
}

/// BuildKit features that this first adapter contract does not provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedFeature {
    /// Remote BuildKit session ownership.
    Sessions,
    /// Cache import or export.
    Cache,
    /// Cleartext HTTP/2 transport.
    H2c,
}

impl fmt::Display for UnsupportedFeature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sessions => formatter.write_str("BuildKit session ownership"),
            Self::Cache => formatter.write_str("BuildKit cache import/export"),
            Self::H2c => formatter.write_str("cleartext HTTP/2 transport"),
        }
    }
}

/// Stable error categories returned by an adapter boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    /// The request endpoint did not match the adapter's configured endpoint.
    BuilderMismatch {
        /// Builder endpoint requested by the solve.
        requested: BuilderEndpoint,
        /// Builder endpoint configured on the adapter.
        expected: BuilderEndpoint,
    },
    /// The context exceeded the adapter's application-specific limit.
    ContextTooLarge {
        /// Actual context size in bytes.
        actual: usize,
        /// Adapter context limit in bytes.
        maximum: usize,
    },
    /// A checked-in or programmatic fixture status plan was invalid.
    InvalidFixture(String),
    /// A required transport or BuildKit feature is not implemented.
    Unsupported(UnsupportedFeature),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuilderMismatch {
                requested,
                expected,
            } => write!(
                formatter,
                "BuildKit builder mismatch: requested {requested}, adapter requires {expected}"
            ),
            Self::ContextTooLarge { actual, maximum } => write!(
                formatter,
                "Build context has {actual} bytes; adapter limit is {maximum}"
            ),
            Self::InvalidFixture(message) => {
                write!(formatter, "invalid BuildKit fixture: {message}")
            }
            Self::Unsupported(feature) => write!(formatter, "unsupported {feature}"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Result of requesting cancellation for a solve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationRequest {
    /// This call made the first cancellation request.
    Requested,
    /// Cancellation had already been requested.
    AlreadyRequested,
}

/// A cloneable caller-owned cancellation signal for one solve.
///
/// Requesting cancellation is idempotent. The adapter owns remote BuildKit
/// cleanup and must observe this signal; callers do not own or directly tear
/// down the remote session.
#[derive(Clone)]
pub struct SolveCancellation {
    inner: Arc<CancellationInner>,
}

struct CancellationInner {
    requested: AtomicBool,
    sender: watch::Sender<bool>,
}

impl SolveCancellation {
    /// Creates an uncancelled solve signal.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            inner: Arc::new(CancellationInner {
                requested: AtomicBool::new(false),
                sender,
            }),
        }
    }

    /// Requests cancellation and reports whether this call was the first.
    #[must_use]
    pub fn cancel(&self) -> CancellationRequest {
        if self.inner.requested.swap(true, Ordering::AcqRel) {
            CancellationRequest::AlreadyRequested
        } else {
            self.inner.sender.send_replace(true);
            CancellationRequest::Requested
        }
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.inner.requested.load(Ordering::Acquire)
    }

    /// Waits until cancellation is requested.
    pub async fn cancelled(&self) {
        let mut receiver = self.inner.sender.subscribe();
        loop {
            if *receiver.borrow_and_update() || self.is_requested() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for SolveCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SolveCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SolveCancellation")
            .field("requested", &self.is_requested())
            .finish()
    }
}

/// Errors returned while validating a BuildKit solve reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolveIdError {
    /// The solve reference was empty or too long.
    InvalidLength,
    /// The solve reference contained a control character.
    InvalidCharacter,
}

/// A bounded BuildKit solve reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SolveId(String);

impl SolveId {
    /// Validates a BuildKit solve reference.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is empty, too long, or contains a
    /// control character.
    pub fn new(value: impl Into<String>) -> Result<Self, SolveIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SOLVE_ID_BYTES {
            return Err(SolveIdError::InvalidLength);
        }
        if value.chars().any(char::is_control) {
            return Err(SolveIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the solve reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SolveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for SolveIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("BuildKit solve ID is empty or too long"),
            Self::InvalidCharacter => {
                formatter.write_str("BuildKit solve ID contains a control character")
            }
        }
    }
}

impl std::error::Error for SolveIdError {}

/// A transport-neutral status update from one solve.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SolveStatus {
    /// The adapter accepted the solve but has not prepared its context.
    Queued,
    /// The adapter bounded and transferred the build context.
    PreparingContext {
        /// Number of context bytes in the archive.
        context_bytes: u64,
    },
    /// A BuildKit vertex made progress.
    Solving {
        /// Stable BuildKit vertex identifier or a sanitized display name.
        vertex: String,
        /// Current progress count.
        current: u64,
        /// Optional total progress count.
        total: Option<u64>,
    },
    /// An image reference is being exported.
    Exporting {
        /// Explicit image reference selected by the caller or adapter policy.
        image_ref: String,
    },
    /// The solve completed successfully.
    Completed {
        /// Exported image references.
        image_refs: Vec<String>,
    },
    /// The solve failed.
    Failed {
        /// Stable machine-readable failure category.
        code: String,
        /// Bounded, diagnostic-safe failure summary.
        message: String,
    },
    /// The adapter observed cancellation and stopped the solve.
    Cancelled,
}

impl SolveStatus {
    /// Returns whether this status ends the status stream.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Failed { .. } | Self::Cancelled
        )
    }
}

/// Future returned when starting a solve.
///
/// The future is `'static` so adapters can be held behind trait objects and
/// own any connection setup needed before returning [`SolveHandle`].
pub type StartSolveFuture =
    Pin<Box<dyn Future<Output = Result<SolveHandle, AdapterError>> + Send + 'static>>;

/// Status receiver and cancellation control for one active solve.
///
/// Dropping the handle requests cancellation. Cancellation is cooperative: the
/// adapter owns remote teardown, and the caller observes the terminal
/// [`SolveStatus::Cancelled`] when cleanup completes.
pub struct SolveHandle {
    solve_id: SolveId,
    cancellation: SolveCancellation,
    statuses: mpsc::Receiver<Result<SolveStatus, AdapterError>>,
}

impl SolveHandle {
    /// Creates a solve handle from an adapter-owned status receiver.
    #[must_use]
    pub const fn new(
        solve_id: SolveId,
        cancellation: SolveCancellation,
        statuses: mpsc::Receiver<Result<SolveStatus, AdapterError>>,
    ) -> Self {
        Self {
            solve_id,
            cancellation,
            statuses,
        }
    }

    /// Returns the selected builder's solve reference.
    #[must_use]
    pub const fn solve_id(&self) -> &SolveId {
        &self.solve_id
    }

    /// Waits for the next status update.
    ///
    /// A conforming adapter emits exactly one terminal status before closing
    /// the stream. `None` is reserved for an adapter that ended without a
    /// terminal update.
    pub async fn next_status(&mut self) -> Option<Result<SolveStatus, AdapterError>> {
        self.statuses.recv().await
    }

    /// Returns a cloneable cancellation signal for this solve.
    #[must_use]
    pub fn cancellation(&self) -> SolveCancellation {
        self.cancellation.clone()
    }

    /// Requests cancellation through the adapter-owned signal.
    #[must_use]
    pub fn cancel(&self) -> CancellationRequest {
        self.cancellation.cancel()
    }
}

impl fmt::Debug for SolveHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SolveHandle")
            .field("solve_id", &self.solve_id)
            .field("cancellation_requested", &self.cancellation.is_requested())
            .finish_non_exhaustive()
    }
}

impl Drop for SolveHandle {
    fn drop(&mut self) {
        let _request = self.cancellation.cancel();
    }
}

/// Transport-neutral BuildKit adapter boundary.
pub trait BuildKitAdapter: Send + Sync {
    /// Returns the capabilities implemented by this adapter.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Returns the one builder endpoint this adapter will accept.
    fn builder(&self) -> &BuilderSelection;

    /// Starts a solve without falling back to another builder.
    fn start_solve(&self, request: SolveRequest) -> StartSolveFuture;
}

#[cfg(test)]
mod tests {
    use super::{CancellationRequest, SolveCancellation, SolveId, SolveIdError, SolveStatus};

    #[tokio::test]
    async fn cancellation_is_cloneable_idempotent_and_wakes_waiters() {
        let cancellation = SolveCancellation::new();
        let waiter = cancellation.clone();
        let waiting = tokio::spawn(async move { waiter.cancelled().await });

        assert_eq!(cancellation.cancel(), CancellationRequest::Requested);
        assert_eq!(cancellation.cancel(), CancellationRequest::AlreadyRequested);
        waiting.await.expect("cancellation waiter");
        assert!(cancellation.is_requested());
    }

    #[test]
    fn solve_ids_and_terminal_statuses_are_bounded() {
        assert_eq!(
            SolveId::new("contains\ncontrol"),
            Err(SolveIdError::InvalidCharacter)
        );
        assert!(SolveStatus::Cancelled.is_terminal());
        assert!(!SolveStatus::Queued.is_terminal());
    }
}
