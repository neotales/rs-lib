use thiserror::Error;

use crate::model::MemoryProtectionError;

/// Broad failure categories exposed by the KDBX API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdbxFailureKind {
    /// Input ended before a declared value.
    Truncated,
    /// Input was structurally invalid.
    Malformed,
    /// The requested feature is recognized but not implemented.
    Unsupported,
    /// A caller-controlled resource limit was exceeded.
    ResourceLimit,
    /// Authentication or integrity verification failed.
    Authentication,
    /// A model or path operation was invalid.
    InvalidArgument,
    /// A caller-owned stream failed. The underlying error is intentionally not
    /// retained because an I/O error may contain sensitive path or device data.
    Io,
    /// The caller requested cancellation at a cooperative checkpoint.
    Cancelled,
}

/// The Argon2 parameter that exceeded a resource limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdbxLimitParameter {
    /// Total memory in kibibytes.
    Argon2Memory,
    /// Number of passes.
    Argon2Time,
    /// Number of lanes.
    Argon2Lanes,
    /// Total memory in kibibytes multiplied by passes.
    Argon2Work,
}

/// Numeric details for an Argon2 resource-limit failure.
///
/// ```
/// use neotales_keepass::{KdbxLimitDetail, KdbxLimitParameter};
/// let detail = KdbxLimitDetail {
///     parameter: KdbxLimitParameter::Argon2Work,
///     actual: 32,
///     maximum: 16,
/// };
/// assert!(detail.actual > detail.maximum);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdbxLimitDetail {
    /// Parameter that failed, in memory, time, lanes, then work order.
    pub parameter: KdbxLimitParameter,
    /// Requested value. Work overflow is represented by `u64::MAX`.
    pub actual: u64,
    /// Configured ceiling.
    pub maximum: u64,
}

/// An error returned by a KeePass operation.
#[derive(Debug, Error)]
#[error("KeePass operation failed ({kind:?}): {message}")]
pub struct KdbxError {
    /// Stable failure category.
    pub kind: KdbxFailureKind,
    /// Safe, non-secret diagnostic text.
    pub message: String,
    limit_detail: Option<KdbxLimitDetail>,
}

impl KdbxError {
    /// Creates an error with a caller-supplied diagnostic message.
    ///
    /// Crate-generated messages exclude credentials and decrypted values.
    /// Custom [`crate::CredentialProvider`] implementations and other callers
    /// must not place secrets in this string because the error does not
    /// sanitize it.
    #[must_use]
    pub fn new(kind: KdbxFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            limit_detail: None,
        }
    }

    /// Creates a truncated-input error.
    #[must_use]
    pub fn truncated() -> Self {
        Self::new(KdbxFailureKind::Truncated, "input ended unexpectedly")
    }

    /// Creates a malformed-input error.
    #[must_use]
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(KdbxFailureKind::Malformed, message)
    }

    /// Creates an unsupported-feature error.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(KdbxFailureKind::Unsupported, message)
    }

    /// Creates a resource-limit error.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::new(KdbxFailureKind::ResourceLimit, message)
    }

    /// Returns numeric details for an Argon2 resource-limit failure.
    /// Other errors, including other resource limits, return `None`.
    #[must_use]
    pub fn limit_detail(&self) -> Option<&KdbxLimitDetail> {
        self.limit_detail.as_ref()
    }

    pub(crate) fn argon2_limit(detail: KdbxLimitDetail) -> Self {
        Self {
            kind: KdbxFailureKind::ResourceLimit,
            message: format!(
                "{:?} exceeds the configured limit (actual {}, maximum {})",
                detail.parameter, detail.actual, detail.maximum
            ),
            limit_detail: Some(detail),
        }
    }

    /// Creates a caller-cancellation error.
    #[must_use]
    pub fn cancelled() -> Self {
        Self::new(KdbxFailureKind::Cancelled, "KDBX operation cancelled")
    }
}

impl From<MemoryProtectionError> for KdbxError {
    fn from(error: MemoryProtectionError) -> Self {
        let (kind, message) = match error {
            MemoryProtectionError::EntropyUnavailable => (
                KdbxFailureKind::Authentication,
                "operating-system entropy is unavailable",
            ),
            MemoryProtectionError::ProtectFailed => {
                (KdbxFailureKind::Authentication, "memory protection failed")
            }
            MemoryProtectionError::UnprotectFailed => (
                KdbxFailureKind::Authentication,
                "memory unprotection failed",
            ),
            MemoryProtectionError::InvalidPlaintextLength => (
                KdbxFailureKind::Authentication,
                "memory provider returned an invalid plaintext length",
            ),
            MemoryProtectionError::PlatformUnavailable => (
                KdbxFailureKind::Unsupported,
                "memory protection platform is unavailable",
            ),
            MemoryProtectionError::PinningUnavailable => (
                KdbxFailureKind::Unsupported,
                "memory pinning is unavailable",
            ),
            MemoryProtectionError::PinningFailed => {
                (KdbxFailureKind::Authentication, "memory pinning failed")
            }
        };
        Self::new(kind, message)
    }
}
