use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::error::KdbxError;

/// A small, runtime-neutral cancellation token.
///
/// The token is intentionally independent of any executor and may be shared
/// with synchronous callers.
///
/// [`Debug`](std::fmt::Debug) is derived rather than hand-written, and this is
/// the one type in the crate where that is provably safe: the only state is a
/// single `AtomicBool` whose whole value is whether cancellation was requested.
/// There is no key material, no plaintext, and no buffer behind it, so a derive
/// has nothing to leak. The rendered output is the flag itself, which is the
/// entire reason a caller would log a token.
#[derive(Clone, Debug, Default)]
pub struct KdbxCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl KdbxCancellationToken {
    /// Creates a token in the running state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// A borrowed cancellation policy used at operation checkpoints.
///
/// `KdbxCancellation::never()` is the policy used by the original synchronous
/// APIs. Call [`KdbxCancellation::from_token`] or
/// [`KdbxCancellation::from_fn`] when a caller needs cooperative cancellation.
/// A synchronous cryptographic primitive may only observe the policy before
/// and after the primitive unless it explicitly supports internal checkpoints.
///
/// [`Debug`](std::fmt::Debug) is hand-written and reports which kind of check is
/// installed, never the check itself. A `Callback` variant holds the caller's
/// closure, which is not `Debug` at all, and adding a `Debug` bound to the
/// caller's type would make this struct's trait implementation depend on
/// something the caller cannot see. A token-backed policy is in the opposite
/// position: it is printable, and the token's own `Debug` is the flag, so
/// delegating to it stays inside the same "no secret" claim. Which check is
/// installed is the whole diagnostic content here — a load that is not
/// cancellable is a different bug from one whose callback returns the wrong
/// answer.
#[derive(Clone, Copy, Default)]
pub struct KdbxCancellation<'a> {
    check: CancellationCheck<'a>,
}

#[derive(Clone, Copy, Default)]
enum CancellationCheck<'a> {
    #[default]
    Never,
    Callback(&'a (dyn Fn() -> bool + Send + Sync)),
    Token(&'a KdbxCancellationToken),
}

impl<'a> KdbxCancellation<'a> {
    /// Creates a policy which never requests cancellation.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            check: CancellationCheck::Never,
        }
    }

    /// Creates a policy backed by a caller-provided callback.
    #[must_use]
    pub fn from_fn(check: &'a (dyn Fn() -> bool + Send + Sync)) -> Self {
        Self {
            check: CancellationCheck::Callback(check),
        }
    }

    /// Creates a policy backed by a cancellation token.
    #[must_use]
    pub const fn from_token(token: &'a KdbxCancellationToken) -> Self {
        Self {
            check: CancellationCheck::Token(token),
        }
    }

    /// Returns whether the policy currently requests cancellation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        match self.check {
            CancellationCheck::Never => false,
            CancellationCheck::Callback(check) => check(),
            CancellationCheck::Token(token) => token.is_cancelled(),
        }
    }

    /// Raises a typed cancellation error at an operation checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a cancelled error when the policy is set.
    pub fn checkpoint(&self) -> Result<(), KdbxError> {
        if self.is_cancelled() {
            Err(KdbxError::cancelled())
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for KdbxCancellation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `check` is matched rather than printed so that the `Callback`
        // variant's closure is never handed to `Debug`. Delegating to the
        // token in the `Token` variant is safe because `KdbxCancellationToken`
        // wraps a single `AtomicBool` and nothing else.
        let mut debug = formatter.debug_struct("KdbxCancellation");
        match &self.check {
            CancellationCheck::Never => debug.field("check", &"never"),
            CancellationCheck::Callback(_) => debug.field("check", &"callback"),
            CancellationCheck::Token(token) => debug.field("check", &"token").field("token", token),
        }
        .finish()
    }
}
