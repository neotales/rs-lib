use std::fmt;

use neotales_keepass::{
    MemoryPinningPolicy, MemoryPinningStatus, MemoryProtectionError, MemoryProtectionProvider,
    SecretBytes,
};
use zeroize::Zeroizing;

/// The Windows DPAPI scope used to protect a value.
///
/// User scope is tied to the current Windows account and is the appropriate
/// default for a user's `KeePass` secrets. Machine scope allows any local user
/// on the machine to decrypt the value and must be selected explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpapiScope {
    /// Bind ciphertext to the current Windows user account.
    User,
    /// Bind ciphertext to the local machine rather than one user.
    Machine,
}

/// A safe adapter for Windows DPAPI-backed [`MemoryProtectionProvider`].
///
/// The adapter is optional and is compiled only with the `windows-dpapi`
/// feature. On non-Windows targets the type remains available when the feature
/// is selected so configuration code can be compiled, but both protection
/// operations return [`MemoryProtectionError::PlatformUnavailable`].
///
/// DPAPI protects the stored representation; it does not pin the plaintext
/// returned by a reveal operation. This provider consequently reports
/// [`MemoryPinningPolicy::Disabled`] and [`MemoryPinningStatus::NotPinned`].
pub struct WindowsDpapiProvider {
    scope: DpapiScope,
    entropy: Option<Zeroizing<Vec<u8>>>,
}

impl WindowsDpapiProvider {
    /// Creates a provider without optional entropy.
    #[must_use]
    pub fn new(scope: DpapiScope) -> Self {
        Self {
            scope,
            entropy: None,
        }
    }

    /// Creates a provider with explicit DPAPI entropy.
    ///
    /// The same entropy bytes must be supplied when the value is unprotected.
    /// Entropy is additional context, not a replacement for user-scope DPAPI;
    /// callers should store it using the same protection policy as other
    /// application configuration. The bytes are zeroized when the provider is
    /// dropped.
    #[must_use]
    pub fn with_entropy(scope: DpapiScope, entropy: impl Into<Vec<u8>>) -> Self {
        Self {
            scope,
            entropy: Some(Zeroizing::new(entropy.into())),
        }
    }

    /// Returns the configured DPAPI scope.
    #[must_use]
    pub const fn scope(&self) -> DpapiScope {
        self.scope
    }

    /// Returns whether explicit entropy was configured.
    #[must_use]
    pub const fn has_entropy(&self) -> bool {
        self.entropy.is_some()
    }

    #[cfg(windows)]
    fn entropy(&self) -> Option<&[u8]> {
        self.entropy.as_ref().map(|value| value.as_slice())
    }
}

impl fmt::Debug for WindowsDpapiProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsDpapiProvider")
            .field("scope", &self.scope)
            .field("has_entropy", &self.has_entropy())
            .finish_non_exhaustive()
    }
}

impl MemoryProtectionProvider for WindowsDpapiProvider {
    #[cfg(windows)]
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        // DATA_BLOB uses a 32-bit length. Reject an unrepresentable input
        // rather than allowing a dependency to truncate it.
        if plaintext.len() > u32::MAX as usize
            || self
                .entropy()
                .is_some_and(|entropy| entropy.len() > u32::MAX as usize)
        {
            return Err(MemoryProtectionError::ProtectFailed);
        }
        windows_dpapi::encrypt_data(plaintext, native_scope(self.scope), self.entropy())
            .map_err(|_| MemoryProtectionError::ProtectFailed)
    }

    #[cfg(not(windows))]
    fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        Err(MemoryProtectionError::PlatformUnavailable)
    }

    #[cfg(windows)]
    fn unprotect(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<SecretBytes, MemoryProtectionError> {
        if protected.len() > u32::MAX as usize
            || self
                .entropy()
                .is_some_and(|entropy| entropy.len() > u32::MAX as usize)
        {
            return Err(MemoryProtectionError::UnprotectFailed);
        }
        let plaintext = Zeroizing::new(
            windows_dpapi::decrypt_data(protected, native_scope(self.scope), self.entropy())
                .map_err(|_| MemoryProtectionError::UnprotectFailed)?,
        );
        if plaintext.len() != max_plaintext_len {
            return Err(MemoryProtectionError::InvalidPlaintextLength);
        }
        // The dependency returns an owned Vec after freeing the native output.
        // Keep that temporary zeroizing while making the ownership transfer to
        // the core crate explicit.
        Ok(SecretBytes::from_vec(plaintext.to_vec()))
    }

    #[cfg(not(windows))]
    fn unprotect(
        &self,
        _protected: &[u8],
        _max_plaintext_len: usize,
    ) -> Result<SecretBytes, MemoryProtectionError> {
        Err(MemoryProtectionError::PlatformUnavailable)
    }

    fn pinning_policy(&self) -> MemoryPinningPolicy {
        MemoryPinningPolicy::Disabled
    }

    fn pinning_status(&self) -> MemoryPinningStatus {
        MemoryPinningStatus::NotPinned
    }
}

#[cfg(windows)]
fn native_scope(scope: DpapiScope) -> windows_dpapi::Scope {
    match scope {
        DpapiScope::User => windows_dpapi::Scope::User,
        DpapiScope::Machine => windows_dpapi::Scope::Machine,
    }
}
