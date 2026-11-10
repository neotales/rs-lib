//! Finite-size transfer policy shared by registry transports and fixtures.

use std::fmt;

use crate::digest::Digest;

/// Default maximum size for a manifest or blob handled by the initial slice.
pub const DEFAULT_MAX_TRANSFER_BYTES: usize = 8 * 1024 * 1024;

/// A finite byte limit applied before content is accepted or returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferPolicy {
    max_bytes: usize,
}

impl TransferPolicy {
    /// Creates a policy with a positive byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidLimit`] when `max_bytes` is zero.
    pub fn new(max_bytes: usize) -> Result<Self, TransferError> {
        if max_bytes == 0 {
            return Err(TransferError::InvalidLimit);
        }
        Ok(Self { max_bytes })
    }

    /// Creates the default finite policy.
    #[must_use]
    pub fn bounded() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_TRANSFER_BYTES,
        }
    }

    /// Returns the maximum number of bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Returns a copy with a different positive limit.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidLimit`] when `max_bytes` is zero.
    pub fn with_max_bytes(self, max_bytes: usize) -> Result<Self, TransferError> {
        Self::new(max_bytes)
    }

    /// Checks a size before allocating or returning a body.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::TooLarge`] when the body exceeds the limit.
    pub fn check_size(self, actual: usize) -> Result<(), TransferError> {
        if actual > self.max_bytes {
            return Err(TransferError::TooLarge {
                actual,
                maximum: self.max_bytes,
            });
        }
        Ok(())
    }

    /// Copies a body only after checking the configured limit.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::TooLarge`] when the body exceeds the limit.
    pub fn copy_bounded(self, content: &[u8]) -> Result<Vec<u8>, TransferError> {
        self.check_size(content.len())?;
        Ok(content.to_vec())
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self::bounded()
    }
}

/// The result of a successful content-addressed transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    digest: Digest,
    bytes: usize,
}

impl TransferReceipt {
    /// Creates a receipt after the caller has independently checked the digest.
    #[must_use]
    pub fn new(digest: Digest, bytes: usize) -> Self {
        Self { digest, bytes }
    }

    /// Returns the verified digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the transferred byte count.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

/// A credential-free transfer progress snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferProgress {
    digest: Digest,
    transferred_bytes: usize,
    total_bytes: Option<usize>,
    complete: bool,
}

impl TransferProgress {
    /// Creates a progress snapshot.
    #[must_use]
    pub const fn new(
        digest: Digest,
        transferred_bytes: usize,
        total_bytes: Option<usize>,
        complete: bool,
    ) -> Self {
        Self {
            digest,
            transferred_bytes,
            total_bytes,
            complete,
        }
    }

    /// Returns the digest being transferred.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the number of bytes transferred so far.
    #[must_use]
    pub const fn transferred_bytes(&self) -> usize {
        self.transferred_bytes
    }

    /// Returns the expected total, when advertised by the transport.
    #[must_use]
    pub const fn total_bytes(&self) -> Option<usize> {
        self.total_bytes
    }

    /// Returns whether the transfer is complete.
    #[must_use]
    pub const fn completed(&self) -> bool {
        self.complete
    }
}

/// Errors produced by a bounded transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferError {
    /// A configured limit was zero.
    InvalidLimit,
    /// The body exceeded the configured limit.
    TooLarge {
        /// Actual body size.
        actual: usize,
        /// Configured maximum size.
        maximum: usize,
    },
    /// The supplied expected digest did not match the content.
    DigestMismatch,
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("transfer limit must be positive"),
            Self::TooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "transfer is too large: {actual} bytes exceeds {maximum}"
                )
            }
            Self::DigestMismatch => formatter.write_str("transfer content digest does not match"),
        }
    }
}

impl std::error::Error for TransferError {}

/// Descriptive aliases used by transport adapters.
///
/// A transport author reaching for a name that describes what the policy
/// *bounds* rather than what it *is* should not have to learn a second name for
/// the same type. Both of these are the same [`TransferPolicy`].
pub type TransferLimits = TransferPolicy;
/// An alias for [`TransferPolicy`], named for the fact that it bounds a transfer.
pub type BoundedTransferPolicy = TransferPolicy;

#[cfg(test)]
mod tests {
    use super::{TransferError, TransferPolicy};

    #[test]
    fn rejects_zero_and_oversized_transfers() {
        assert_eq!(TransferPolicy::new(0), Err(TransferError::InvalidLimit));
        let policy = TransferPolicy::new(2).expect("policy");
        assert_eq!(
            policy.copy_bounded(b"three"),
            Err(TransferError::TooLarge {
                actual: 5,
                maximum: 2
            })
        );
        assert_eq!(policy.copy_bounded(b"ok").expect("copy"), b"ok");
    }
}
