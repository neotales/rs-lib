use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::primitives::{KdbxColor, KdbxTimestamp, KdbxUuid};

/// Errors returned by an in-memory protection provider.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MemoryProtectionError {
    /// The operating system could not provide entropy.
    #[error("operating-system entropy is unavailable")]
    EntropyUnavailable,
    /// The provider could not protect plaintext.
    #[error("memory protection failed")]
    ProtectFailed,
    /// The provider could not unprotect ciphertext.
    #[error("memory unprotection failed")]
    UnprotectFailed,
    /// The provider returned a plaintext value with the wrong length.
    #[error("memory provider returned an invalid plaintext length")]
    InvalidPlaintextLength,
    /// The selected platform integration is not available on this target.
    #[error("memory protection platform is unavailable")]
    PlatformUnavailable,
    /// The platform does not provide a memory-pinning operation.
    #[error("memory pinning is unavailable")]
    PinningUnavailable,
    /// A platform memory-pinning operation was attempted and failed.
    #[error("memory pinning failed")]
    PinningFailed,
}

/// How a platform provider should treat a failure to pin secret memory.
///
/// Pinning is a defense-in-depth property. It is separate from encryption and
/// is never silently treated as successful by the core crate. A provider that
/// cannot honor [`MemoryPinningPolicy::Required`] must return an explicit
/// error from its protection operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryPinningPolicy {
    /// Do not request operating-system memory pinning.
    #[default]
    Disabled,
    /// Try to pin memory, but continue without pinning when the platform
    /// rejects or does not provide the operation.
    BestEffort,
    /// Reject an operation unless the platform reports that memory is pinned.
    Required,
}

impl MemoryPinningPolicy {
    /// Returns whether the policy requires a successful pin.
    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }

    /// Returns whether a status satisfies this policy.
    #[must_use]
    pub const fn accepts(self, status: MemoryPinningStatus) -> bool {
        match self {
            Self::Disabled | Self::BestEffort => true,
            Self::Required => matches!(status, MemoryPinningStatus::Pinned),
        }
    }
}

/// The result of a platform memory-pinning attempt.
///
/// A status is a report, not a guarantee made by the core crate. In
/// particular, [`MemoryPinningStatus::Pinned`] must only be returned by an
/// integration that owns the allocation and keeps the OS lock held for the
/// complete lifetime of the plaintext buffer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryPinningStatus {
    /// No pinning was requested, or the provider intentionally does not pin.
    #[default]
    NotPinned,
    /// The allocation is currently held by the platform memory lock.
    Pinned,
    /// The target has no usable memory-pinning facility.
    Unavailable,
    /// A facility was available but rejected the operation.
    Failed,
}

impl MemoryPinningStatus {
    /// Returns whether the status represents an active platform lock.
    #[must_use]
    pub const fn is_pinned(self) -> bool {
        matches!(self, Self::Pinned)
    }
}

/// Owned zeroizing bytes returned by a reveal operation.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Creates an owned zeroizing byte buffer.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Returns the plaintext bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
    /// Returns the plaintext length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.len())
            .finish()
    }
}

/// Owned zeroizing UTF-8 text returned by a reveal operation.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Creates an owned zeroizing string.
    #[must_use]
    pub fn from_string(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    /// Returns the plaintext text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Returns the plaintext character count in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretString")
            .field("len", &self.len())
            .finish()
    }
}

/// A pluggable in-memory protector for byte-origin values.
///
/// Implementations must keep their key material private and return owned
/// buffers. A Windows DPAPI implementation can use this hook without making
/// the core crate platform-specific. The required operations stay
/// runtime-neutral; the optional pinning methods only describe what a
/// platform adapter has actually done and never make the core call `mlock` or
/// `VirtualLock` itself.
pub trait MemoryProtectionProvider: Send + Sync {
    /// Encrypts or wraps plaintext into an owned protected representation.
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError>;

    /// Decrypts or unwraps an owned protected representation.
    fn unprotect(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<SecretBytes, MemoryProtectionError>;

    /// Returns the provider's memory-pinning policy.
    ///
    /// The default is [`MemoryPinningPolicy::Disabled`]. A provider must not
    /// report [`MemoryPinningPolicy::Required`] unless its integration can
    /// enforce that policy. The core checks this status after each protected
    /// value operation and turns an unsatisfied required policy into an
    /// explicit error.
    fn pinning_policy(&self) -> MemoryPinningPolicy {
        MemoryPinningPolicy::Disabled
    }

    /// Returns the provider's current memory-pinning status.
    ///
    /// The default is [`MemoryPinningStatus::NotPinned`]. A status is only
    /// advisory metadata; it does not pin memory owned by the core crate.
    fn pinning_status(&self) -> MemoryPinningStatus {
        MemoryPinningStatus::NotPinned
    }
}

fn validate_pinning(protector: &dyn MemoryProtectionProvider) -> Result<(), MemoryProtectionError> {
    let policy = protector.pinning_policy();
    let status = protector.pinning_status();
    if policy.accepts(status) {
        return Ok(());
    }
    Err(match status {
        MemoryPinningStatus::Unavailable => MemoryProtectionError::PinningUnavailable,
        MemoryPinningStatus::NotPinned
        | MemoryPinningStatus::Failed
        | MemoryPinningStatus::Pinned => MemoryProtectionError::PinningFailed,
    })
}

/// Default per-value ChaCha20 in-memory protection.
///
/// [`Debug`](std::fmt::Debug) is hand-written, and this is the type in the
/// crate where `zeroize` most directly defeats a derive. Both fields are
/// `Zeroizing`, and `zeroize` derives `Debug` for `Zeroizing<T>` by printing
/// the wrapped value — verified against the pinned `zeroize` 1.9, which
/// renders `Zeroizing([67, 65, 78, …])`. The wrapper is an erasure guarantee,
/// not a redaction one, so `#[derive(Debug)]` here would put the in-memory
/// protection key and its nonce in every log line and panic message that
/// touched a provider. Nothing is printed: both fields are fixed-size, so
/// their lengths would carry no diagnostic information anyway, and the key is
/// per-process random material whose hash is a hash of a secret.
pub struct ChaCha20MemoryProtection {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
}

impl fmt::Debug for ChaCha20MemoryProtection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `key` and `nonce` are key material and are not printed. See the type
        // documentation for why the `Zeroizing` wrapper does not make a derive
        // safe.
        formatter.write_str("ChaCha20MemoryProtection")
    }
}

impl ChaCha20MemoryProtection {
    fn new() -> Result<Self, MemoryProtectionError> {
        let mut key = Zeroizing::new([0; 32]);
        let mut nonce = Zeroizing::new([0; 12]);
        getrandom::fill(key.as_mut()).map_err(|_| MemoryProtectionError::EntropyUnavailable)?;
        getrandom::fill(nonce.as_mut()).map_err(|_| MemoryProtectionError::EntropyUnavailable)?;
        Ok(Self { key, nonce })
    }
}

impl MemoryProtectionProvider for ChaCha20MemoryProtection {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        let mut value = Zeroizing::new(plaintext.to_vec());
        crate::crypto::chacha20_transform(&self.key[..], &self.nonce[..], value.as_mut_slice())
            .map_err(|_| MemoryProtectionError::ProtectFailed)?;
        Ok(value.to_vec())
    }

    fn unprotect(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<SecretBytes, MemoryProtectionError> {
        let mut value = Zeroizing::new(protected.to_vec());
        crate::crypto::chacha20_transform(&self.key[..], &self.nonce[..], value.as_mut_slice())
            .map_err(|_| MemoryProtectionError::UnprotectFailed)?;
        if value.len() != max_plaintext_len {
            return Err(MemoryProtectionError::InvalidPlaintextLength);
        }
        Ok(SecretBytes::from_vec(value.to_vec()))
    }
}

/// A secret value whose byte representation is zeroized on drop.
///
/// Values created from text are kept as owned zeroizing `String` data and are
/// not additionally encrypted. Values created from bytes can be protected in
/// memory with ChaCha20 or a caller-supplied [`MemoryProtectionProvider`].
pub struct ProtectedValue {
    inner: ProtectedValueInner,
}

enum ProtectedValueInner {
    Text(Zeroizing<String>),
    Bytes {
        data: Zeroizing<Vec<u8>>,
        plaintext_len: usize,
        protector: Option<std::sync::Arc<dyn MemoryProtectionProvider>>,
    },
}

impl ProtectedValue {
    /// Creates an unprotected byte value explicitly. Most callers should use
    /// [`Self::from_bytes`], which protects byte-origin values by default.
    #[must_use]
    pub fn from_bytes_unprotected(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let plaintext_len = bytes.len();
        Self {
            inner: ProtectedValueInner::Bytes {
                data: Zeroizing::new(bytes),
                plaintext_len,
                protector: None,
            },
        }
    }

    /// Creates a byte value protected with the default ChaCha20 protector.
    ///
    /// # Errors
    ///
    /// Returns an error if operating-system entropy or the cipher is unavailable.
    pub fn from_bytes_protected(bytes: impl Into<Vec<u8>>) -> Result<Self, MemoryProtectionError> {
        Self::from_bytes_with_protection(
            bytes,
            std::sync::Arc::new(ChaCha20MemoryProtection::new()?),
        )
    }

    /// Creates a byte value protected with the default ChaCha20 protector.
    ///
    /// # Errors
    ///
    /// Returns an error if operating-system entropy or the cipher is unavailable.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, MemoryProtectionError> {
        Self::from_bytes_protected(bytes)
    }

    /// Creates a byte value protected by a caller-supplied provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider cannot protect the input.
    pub fn from_bytes_with_protection(
        bytes: impl Into<Vec<u8>>,
        protector: std::sync::Arc<dyn MemoryProtectionProvider>,
    ) -> Result<Self, MemoryProtectionError> {
        let plaintext = Zeroizing::new(bytes.into());
        let plaintext_len = plaintext.len();
        let data = protector.protect(&plaintext)?;
        validate_pinning(protector.as_ref())?;
        Ok(Self {
            inner: ProtectedValueInner::Bytes {
                data: Zeroizing::new(data),
                plaintext_len,
                protector: Some(protector),
            },
        })
    }

    /// Creates an owned text value. Text-origin values are not additionally
    /// encrypted in memory; the owned string is zeroized when dropped.
    #[must_use]
    pub fn from_text(value: impl Into<String>) -> Self {
        Self {
            inner: ProtectedValueInner::Text(Zeroizing::new(value.into())),
        }
    }

    /// Returns whether the value uses in-memory byte protection.
    #[must_use]
    pub fn is_memory_protected(&self) -> bool {
        matches!(
            self.inner,
            ProtectedValueInner::Bytes {
                protector: Some(_),
                ..
            }
        )
    }

    /// Returns the memory-pinning policy of the configured provider.
    ///
    /// Unprotected values report [`MemoryPinningPolicy::Disabled`]. The core
    /// crate only forwards this metadata; it does not perform an OS lock.
    #[must_use]
    pub fn pinning_policy(&self) -> MemoryPinningPolicy {
        match &self.inner {
            ProtectedValueInner::Bytes {
                protector: Some(protector),
                ..
            } => protector.pinning_policy(),
            ProtectedValueInner::Text(_) | ProtectedValueInner::Bytes { .. } => {
                MemoryPinningPolicy::Disabled
            }
        }
    }

    /// Returns the current memory-pinning status of the configured provider.
    ///
    /// A provider should report [`MemoryPinningStatus::Pinned`] only while it
    /// owns a platform lock over the complete plaintext allocation. The core
    /// crate cannot verify or extend that lifetime.
    #[must_use]
    pub fn pinning_status(&self) -> MemoryPinningStatus {
        match &self.inner {
            ProtectedValueInner::Bytes {
                protector: Some(protector),
                ..
            } => protector.pinning_status(),
            ProtectedValueInner::Text(_) | ProtectedValueInner::Bytes { .. } => {
                MemoryPinningStatus::NotPinned
            }
        }
    }

    /// Reveals owned zeroizing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured protector cannot unwrap the value.
    pub fn reveal_bytes(&self) -> Result<SecretBytes, crate::KdbxError> {
        match &self.inner {
            ProtectedValueInner::Text(value) => {
                Ok(SecretBytes::from_vec(value.as_bytes().to_vec()))
            }
            ProtectedValueInner::Bytes {
                data,
                plaintext_len,
                protector: Some(protector),
            } => {
                let value = protector
                    .unprotect(data, *plaintext_len)
                    .map_err(crate::KdbxError::from)?;
                validate_pinning(protector.as_ref()).map_err(crate::KdbxError::from)?;
                Ok(value)
            }
            ProtectedValueInner::Bytes { data, .. } => Ok(SecretBytes::from_vec(data.to_vec())),
        }
    }

    /// Reveals owned zeroizing UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns malformed-input if the revealed bytes are not UTF-8 or the
    /// protector fails.
    pub fn reveal_text(&self) -> Result<SecretString, crate::KdbxError> {
        let bytes = self.reveal_bytes()?;
        let result = std::str::from_utf8(bytes.as_slice())
            .map(|value| SecretString::from_string(value.to_owned()))
            .map_err(|_| crate::KdbxError::malformed("protected value is not UTF-8"));
        result
    }

    /// Runs a closure over revealed UTF-8 text and zeroizes the temporary
    /// string before returning.
    ///
    /// # Errors
    ///
    /// Returns malformed-input if the value is not UTF-8 or protection fails.
    pub fn with_revealed_text<T>(
        &self,
        operation: impl FnOnce(&str) -> T,
    ) -> Result<T, crate::KdbxError> {
        let value = self.reveal_text()?;
        Ok(operation(value.as_str()))
    }

    /// Runs a closure over revealed bytes and zeroizes the temporary buffer
    /// before returning.
    ///
    /// # Errors
    ///
    /// Returns an error if protection fails.
    pub fn with_revealed_bytes<T>(
        &self,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<T, crate::KdbxError> {
        let mut value = self.reveal_bytes()?;
        Ok(operation(value.as_mut_slice()))
    }

    /// Copies revealed bytes into a caller-provided mutable buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination is too small or protection fails.
    pub fn copy_to(&self, destination: &mut [u8]) -> Result<usize, crate::KdbxError> {
        let plaintext_len = self.len();
        if destination.len() < plaintext_len {
            return Err(crate::KdbxError::new(
                crate::KdbxFailureKind::InvalidArgument,
                "destination is too small",
            ));
        }
        let bytes = self.reveal_bytes()?;
        destination[..bytes.len()].copy_from_slice(bytes.as_slice());
        Ok(bytes.len())
    }

    /// Returns the value length without revealing it.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.inner {
            ProtectedValueInner::Text(value) => value.len(),
            ProtectedValueInner::Bytes { plaintext_len, .. } => *plaintext_len,
        }
    }

    /// Returns whether the value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Clone for ProtectedValue {
    fn clone(&self) -> Self {
        match &self.inner {
            ProtectedValueInner::Text(value) => Self {
                inner: ProtectedValueInner::Text(value.clone()),
            },
            ProtectedValueInner::Bytes {
                data,
                plaintext_len,
                protector,
            } => Self {
                inner: ProtectedValueInner::Bytes {
                    data: data.clone(),
                    plaintext_len: *plaintext_len,
                    protector: protector.clone(),
                },
            },
        }
    }
}

impl ProtectedValue {
    /// Compares revealed plaintext without exposing it through an infallible
    /// equality operator.
    ///
    /// # Errors
    ///
    /// Returns an error if either configured provider cannot unprotect its
    /// value.
    pub fn try_eq(&self, other: &Self) -> Result<bool, crate::KdbxError> {
        let left = self.reveal_bytes()?;
        let right = other.reveal_bytes()?;
        Ok(left.as_slice() == right.as_slice())
    }
}

impl fmt::Debug for ProtectedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedValue")
            .field("len", &self.len())
            .field("memory_protected", &self.is_memory_protected())
            .finish()
    }
}

/// A value stored in a KDBX variant dictionary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VariantValue {
    /// A 32-bit unsigned integer.
    UInt32(u32),
    /// A 64-bit unsigned integer.
    UInt64(u64),
    /// A boolean.
    Bool(bool),
    /// A 32-bit signed integer.
    Int32(i32),
    /// A 64-bit signed integer.
    Int64(i64),
    /// A UTF-8 string.
    String(String),
    /// An opaque byte array.
    Bytes(Vec<u8>),
}

impl From<u32> for VariantValue {
    fn from(value: u32) -> Self {
        Self::UInt32(value)
    }
}

impl From<u64> for VariantValue {
    fn from(value: u64) -> Self {
        Self::UInt64(value)
    }
}

impl From<bool> for VariantValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i32> for VariantValue {
    fn from(value: i32) -> Self {
        Self::Int32(value)
    }
}

impl From<i64> for VariantValue {
    fn from(value: i64) -> Self {
        Self::Int64(value)
    }
}

impl From<String> for VariantValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for VariantValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<Vec<u8>> for VariantValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for VariantValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

/// Ordered public custom data from a KDBX 4 outer header.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VariantDictionary(Vec<VariantDictionaryItem>);

impl VariantDictionary {
    /// Adds or replaces a value while preserving first-insertion order.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<VariantValue>) {
        let key = key.into();
        let value = value.into();
        if let Some(item) = self.0.iter_mut().find(|item| item.key == key) {
            item.value = value;
        } else {
            self.0.push(VariantDictionaryItem { key, value });
        }
    }

    /// Gets a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&VariantValue> {
        self.0
            .iter()
            .find(|item| item.key == key)
            .map(|item| &item.value)
    }

    /// Returns ordered items.
    #[must_use]
    pub fn items(&self) -> &[VariantDictionaryItem] {
        &self.0
    }

    /// Returns whether the dictionary has no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One ordered public-header custom-data item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantDictionaryItem {
    /// Custom-data key.
    pub key: String,
    /// Typed custom-data value.
    pub value: VariantValue,
}

/// Ordered custom metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CustomData(Vec<CustomDataItem>);

impl CustomData {
    /// Adds or replaces a value while preserving first-insertion order.
    pub fn set(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        modified: Option<KdbxTimestamp>,
    ) {
        let key = key.into();
        let value = value.into();
        if let Some(item) = self.0.iter_mut().find(|item| item.key == key) {
            item.value = value;
            item.last_modification = modified;
        } else {
            self.0.push(CustomDataItem {
                key,
                value,
                last_modification: modified,
            });
        }
    }

    /// Gets a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|item| item.key == key)
            .map(|item| item.value.as_str())
    }

    /// Returns ordered items.
    #[must_use]
    pub fn items(&self) -> &[CustomDataItem] {
        &self.0
    }
}

/// One ordered custom-data item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomDataItem {
    /// Custom-data key.
    pub key: String,
    /// Custom-data value.
    pub value: String,
    /// Optional last-modification time.
    pub last_modification: Option<KdbxTimestamp>,
}

/// KeePass timestamps associated with a group, entry, or history item.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeePassTimes {
    /// Creation time.
    pub created: KdbxTimestamp,
    /// Last modification time.
    pub modified: KdbxTimestamp,
    /// Last access time.
    pub accessed: KdbxTimestamp,
    /// Expiry time.
    pub expires: KdbxTimestamp,
    /// Whether expiry is enabled.
    pub expires_enabled: bool,
    /// Usage count.
    pub usage_count: u64,
    /// Location-change time.
    pub location_changed: KdbxTimestamp,
}

/// KeePass auto-type settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoType {
    /// Whether auto-type is enabled.
    pub enabled: Option<bool>,
    /// Whether the sequence is obfuscated.
    pub obfuscated: Option<bool>,
    /// Default sequence.
    pub default_sequence: String,
    /// Ordered window/keystroke associations.
    pub associations: Vec<AutoTypeAssociation>,
}

/// One ordered auto-type window and keystroke association.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoTypeAssociation {
    /// Window title or pattern.
    pub window: String,
    /// Keystroke sequence.
    pub keystrokes: String,
}

/// A field in an entry or history snapshot.
#[derive(Clone, Debug)]
pub struct Field {
    /// Field key.
    pub key: String,
    /// Field value.
    pub value: ProtectedValue,
    /// Whether the value is protected by the KDBX inner stream on disk.
    pub protected: bool,
    /// KeePass metadata requesting in-memory protection. This flag does not
    /// by itself change the ownership or pinning guarantees of
    /// [`ProtectedValue`].
    pub protect_in_memory: bool,
}

impl Field {
    /// Creates an unprotected field.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: ProtectedValue::from_text(value),
            protected: false,
            protect_in_memory: false,
        }
    }
}

/// One binary-pool record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryRecord {
    /// Payload bytes owned by the document. Attachments may be sensitive, but
    /// this model buffer is ordinary owned memory and is not zeroized on drop.
    pub data: Vec<u8>,
    /// Whether this record is protected by the inner stream.
    pub protected: bool,
}

/// Ordered KDBX 4 binary pool.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BinaryPool {
    records: Vec<BinaryRecord>,
    len: usize,
}

impl BinaryPool {
    /// Adds a record and returns its reference.
    pub fn add(&mut self, data: impl Into<Vec<u8>>, protected: bool) -> usize {
        self.records.push(BinaryRecord {
            data: data.into(),
            protected,
        });
        self.len = self.records.len();
        self.len - 1
    }

    /// Returns a record by reference.
    #[must_use]
    pub fn get(&self, reference: usize) -> Option<&BinaryRecord> {
        self.records.get(reference)
    }

    /// Returns all records in order.
    #[must_use]
    pub fn records(&self) -> &[BinaryRecord] {
        &self.records
    }

    /// Returns the number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// An attachment reference into the binary pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    /// Attachment filename.
    pub name: String,
    /// Binary-pool reference.
    pub reference: usize,
}

/// A group in the KeePass tree.
#[derive(Clone, Debug)]
pub struct Group {
    /// Stable group UUID.
    pub id: KdbxUuid,
    /// Group name. This is ordinary owned model text.
    pub name: String,
    /// Group notes. This is ordinary owned model text and is not zeroized on
    /// drop.
    pub notes: String,
    /// Standard icon identifier.
    pub icon_id: u32,
    /// Custom icon UUID.
    pub custom_icon_id: KdbxUuid,
    /// Group timestamps.
    pub times: KeePassTimes,
    /// Expansion state.
    pub is_expanded: bool,
    /// Optional inherited auto-type state.
    pub enable_auto_type: Option<bool>,
    /// Optional inherited searching state.
    pub enable_searching: Option<bool>,
    /// Default auto-type sequence.
    pub default_auto_type_sequence: String,
    /// Last top-visible entry UUID.
    pub last_top_visible_entry_id: KdbxUuid,
    /// Previous parent group UUID.
    pub previous_parent_group_id: KdbxUuid,
    /// Custom group data.
    pub custom_data: CustomData,
    /// Ordered child groups.
    pub groups: Vec<Group>,
    /// Ordered child entries.
    pub entries: Vec<Entry>,
    /// Ordered tags.
    pub tags: Vec<String>,
}

impl Group {
    /// Creates a group with a fresh UUID.
    ///
    /// # Panics
    ///
    /// Panics if operating-system entropy is unavailable. Use an explicit
    /// [`KdbxUuid::from_bytes`] value with the public fields when construction
    /// must remain non-panicking.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: KdbxUuid::new_random(),
            name: name.into(),
            notes: String::new(),
            icon_id: 48,
            custom_icon_id: KdbxUuid::ZERO,
            times: KeePassTimes::default(),
            is_expanded: true,
            enable_auto_type: None,
            enable_searching: None,
            default_auto_type_sequence: String::new(),
            last_top_visible_entry_id: KdbxUuid::ZERO,
            previous_parent_group_id: KdbxUuid::ZERO,
            custom_data: CustomData::default(),
            groups: Vec::new(),
            entries: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Adds a child group.
    pub fn add_group(&mut self, group: Group) -> &mut Group {
        self.groups.push(group);
        self.groups.last_mut().expect("group was just pushed")
    }

    /// Adds an entry to this group.
    pub fn add_entry(&mut self, entry: Entry) -> &mut Entry {
        self.entries.push(entry);
        self.entries.last_mut().expect("entry was just pushed")
    }
}

/// An entry in the KeePass tree.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Stable entry UUID.
    pub id: KdbxUuid,
    /// Entry title/path segment. This is ordinary owned model text.
    pub title: String,
    /// Entry username. This is ordinary owned model text and is not zeroized
    /// on drop; applications that classify usernames as secrets need a
    /// caller-owned storage policy.
    pub username: String,
    /// Entry password.
    pub password: ProtectedValue,
    /// Entry URL. This is ordinary owned model text.
    pub url: String,
    /// Notes. This is ordinary owned model text and is not zeroized on drop.
    pub notes: String,
    /// Standard icon identifier.
    pub icon_id: u32,
    /// Custom icon UUID.
    pub custom_icon_id: KdbxUuid,
    /// Foreground color.
    pub foreground_color: KdbxColor,
    /// Background color.
    pub background_color: KdbxColor,
    /// Quality-check state.
    pub quality_check: Option<bool>,
    /// Previous parent group UUID.
    pub previous_parent_group_id: KdbxUuid,
    /// Tags.
    pub tags: Vec<String>,
    /// Timestamps.
    pub times: KeePassTimes,
    /// Ordered fields, including standard fields when explicitly retained.
    pub fields: Vec<Field>,
    /// Attachments.
    pub attachments: Vec<Attachment>,
    /// Auto-type settings.
    pub auto_type: AutoType,
    /// Ordered custom data.
    pub custom_data: CustomData,
    /// Ordered history snapshots.
    pub history: Vec<Entry>,
}

impl Entry {
    /// Creates an entry with a fresh UUID.
    ///
    /// # Panics
    ///
    /// Panics if operating-system entropy is unavailable. Use an explicit
    /// [`KdbxUuid::from_bytes`] value with the public fields when construction
    /// must remain non-panicking.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: KdbxUuid::new_random(),
            title: title.into(),
            username: String::new(),
            password: ProtectedValue::from_text(String::new()),
            url: String::new(),
            notes: String::new(),
            icon_id: 48,
            custom_icon_id: KdbxUuid::ZERO,
            foreground_color: KdbxColor::empty(),
            background_color: KdbxColor::empty(),
            quality_check: None,
            previous_parent_group_id: KdbxUuid::ZERO,
            tags: Vec::new(),
            times: KeePassTimes::default(),
            fields: Vec::new(),
            attachments: Vec::new(),
            auto_type: AutoType::default(),
            custom_data: CustomData::default(),
            history: Vec::new(),
        }
    }

    /// Gets a field by key.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.key == key)
    }

    /// Adds or replaces a field.
    pub fn set_field(&mut self, field: Field) {
        if let Some(existing) = self
            .fields
            .iter_mut()
            .find(|existing| existing.key == field.key)
        {
            *existing = field;
        } else {
            self.fields.push(field);
        }
    }
}

/// Database metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeePassMeta {
    /// Generator name/version.
    pub generator: String,
    /// Database name.
    pub name: String,
    /// Database description.
    pub description: String,
    /// Default username.
    pub default_username: String,
    /// Optional settings-change timestamp.
    pub settings_changed: Option<KdbxTimestamp>,
    /// Database-name change timestamp.
    pub database_name_changed: Option<KdbxTimestamp>,
    /// Description-change timestamp.
    pub database_description_changed: Option<KdbxTimestamp>,
    /// Default-username change timestamp.
    pub default_username_changed: Option<KdbxTimestamp>,
    /// Master-key change timestamp.
    pub master_key_changed: Option<KdbxTimestamp>,
    /// Maintenance history retention in days.
    pub maintenance_history_days: u32,
    /// Database color.
    pub color: KdbxColor,
    /// Master-key change recommendation interval.
    pub master_key_change_rec: i64,
    /// Master-key change force interval.
    pub master_key_change_force: i64,
    /// Whether a one-time forced key change is pending.
    pub master_key_change_force_once: bool,
    /// Protect password fields in memory.
    pub protect_password: bool,
    /// Protect titles in memory.
    pub protect_title: bool,
    /// Protect usernames in memory.
    pub protect_username: bool,
    /// Protect URLs in memory.
    pub protect_url: bool,
    /// Protect notes in memory.
    pub protect_notes: bool,
    /// Database times.
    pub times: KeePassTimes,
    /// Maintenance history limit.
    pub history_max_items: Option<u64>,
    /// History max size.
    pub history_max_size: Option<u64>,
    /// Whether memory protection is enabled.
    pub memory_protection: bool,
    /// Whether the recycle bin is enabled.
    pub recycle_bin_enabled: bool,
    /// Recycle-bin UUID.
    pub recycle_bin_uuid: KdbxUuid,
    /// Recycle-bin change timestamp.
    pub recycle_bin_changed: Option<KdbxTimestamp>,
    /// Templates group UUID.
    pub templates_uuid: KdbxUuid,
    /// Templates group change timestamp.
    pub templates_changed: Option<KdbxTimestamp>,
    /// Selected group UUID.
    pub selected_group_uuid: KdbxUuid,
    /// Top-visible group UUID.
    pub top_visible_group_uuid: KdbxUuid,
    /// Ordered custom metadata.
    pub custom_data: CustomData,
    /// Legacy binaries preserved for KDBX3 compatibility.
    pub legacy_binaries: Vec<Vec<u8>>,
    /// Custom icons.
    pub custom_icons: Vec<CustomIcon>,
}

/// A custom icon in database metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomIcon {
    /// Icon UUID.
    pub uuid: KdbxUuid,
    /// Icon bytes.
    pub data: Vec<u8>,
    /// Optional icon name.
    pub name: Option<String>,
    /// Optional modification time.
    pub last_modification: Option<KdbxTimestamp>,
}

/// A deleted object record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletedObject {
    /// Deleted UUID.
    pub id: KdbxUuid,
    /// Deletion time.
    pub deleted_at: KdbxTimestamp,
}

/// Merge conflict policy for database merges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeStrategy {
    /// Keep the target object when both UUIDs match.
    KeepTarget,
    /// Replace matching target objects with source objects.
    PreferSource,
    /// Keep the object with the newest modification timestamp.
    NewestModification,
}

/// KeePass-compatible name for an entry.
pub type KeePassEntry = Entry;
/// KeePass-compatible name for a group.
pub type KeePassGroup = Group;
/// KeePass-compatible name for a field.
pub type KeePassField = Field;
/// KeePass-compatible name for an attachment.
pub type KeePassAttachment = Attachment;

/// A complete in-memory KeePass document.
#[derive(Clone, Debug)]
pub struct KeePassDatabase {
    /// Database metadata.
    pub meta: KeePassMeta,
    /// Root group.
    pub root: Group,
    /// Deleted objects.
    pub deleted_objects: Vec<DeletedObject>,
    /// Binary pool.
    pub binary_pool: BinaryPool,
    /// String projection of unencrypted KDBX 4 outer-header custom data.
    pub public_custom_data: CustomData,
    /// Complete typed, unencrypted custom data from the KDBX 4 outer header.
    ///
    /// This is authoritative when non-empty; the string projection remains
    /// available for callers that only consume textual header values.
    pub typed_public_custom_data: VariantDictionary,
    /// Whether the loaded document can be saved without silent data loss.
    pub can_save_losslessly: bool,
}

impl Default for KeePassDatabase {
    fn default() -> Self {
        Self {
            meta: KeePassMeta::default(),
            root: Group::new("Root"),
            deleted_objects: Vec::new(),
            binary_pool: BinaryPool::default(),
            public_custom_data: CustomData::default(),
            typed_public_custom_data: VariantDictionary::default(),
            can_save_losslessly: true,
        }
    }
}

impl KeePassDatabase {
    /// Walks groups and entries in pre-order.
    pub fn walk(&self, mut on_group: impl FnMut(&Group), mut on_entry: impl FnMut(&Entry)) {
        fn visit(
            group: &Group,
            on_group: &mut impl FnMut(&Group),
            on_entry: &mut impl FnMut(&Entry),
        ) {
            on_group(group);
            for entry in &group.entries {
                on_entry(entry);
            }
            for child in &group.groups {
                visit(child, on_group, on_entry);
            }
        }
        visit(&self.root, &mut on_group, &mut on_entry);
    }

    /// Merges source tree objects into this database by UUID.
    ///
    /// Binary-pool references are interned by content and remapped for copied
    /// entries and history snapshots. Metadata and deleted objects are not
    /// merged.
    ///
    /// # Errors
    ///
    /// Returns [`crate::KdbxError`] with
    /// [`crate::KdbxFailureKind::InvalidArgument`] before changing the target
    /// if any source attachment, including one in a history snapshot, refers
    /// to a missing binary-pool record.
    pub fn merge_from(
        &mut self,
        source: &Self,
        strategy: MergeStrategy,
    ) -> Result<(), crate::KdbxError> {
        if !source_attachments_valid(&source.root, source.binary_pool.len()) {
            return Err(crate::KdbxError::new(
                crate::KdbxFailureKind::InvalidArgument,
                "source attachment references a missing binary",
            ));
        }
        let mut references = vec![None; source.binary_pool.len()];
        merge_group(
            &mut self.root,
            &source.root,
            strategy,
            &source.binary_pool,
            &mut self.binary_pool,
            &mut references,
        );
        Ok(())
    }

    /// Adds a child group to the root.
    pub fn add_group(&mut self, group: Group) -> &mut Group {
        self.root.add_group(group)
    }
    /// Adds an entry to the root.
    pub fn add_entry(&mut self, entry: Entry) -> &mut Entry {
        self.root.add_entry(entry)
    }

    /// Finds an entry by UUID.
    #[must_use]
    pub fn find_entry(&self, id: KdbxUuid) -> Option<&Entry> {
        fn find<'a>(group: &'a Group, id: KdbxUuid) -> Option<&'a Entry> {
            group
                .entries
                .iter()
                .find(|entry| entry.id == id)
                .or_else(|| group.groups.iter().find_map(|child| find(child, id)))
        }
        find(&self.root, id)
    }

    /// Finds a group by UUID.
    #[must_use]
    pub fn find_group(&self, id: KdbxUuid) -> Option<&Group> {
        fn find<'a>(group: &'a Group, id: KdbxUuid) -> Option<&'a Group> {
            (group.id == id)
                .then_some(group)
                .or_else(|| group.groups.iter().find_map(|child| find(child, id)))
        }
        find(&self.root, id)
    }
}

fn source_attachments_valid(group: &Group, binary_count: usize) -> bool {
    fn entry_valid(entry: &Entry, binary_count: usize) -> bool {
        entry
            .attachments
            .iter()
            .all(|attachment| attachment.reference < binary_count)
            && entry
                .history
                .iter()
                .all(|snapshot| entry_valid(snapshot, binary_count))
    }

    group
        .entries
        .iter()
        .all(|entry| entry_valid(entry, binary_count))
        && group
            .groups
            .iter()
            .all(|child| source_attachments_valid(child, binary_count))
}

fn merge_group(
    target: &mut Group,
    source: &Group,
    strategy: MergeStrategy,
    source_pool: &BinaryPool,
    target_pool: &mut BinaryPool,
    references: &mut [Option<usize>],
) {
    for source_entry in &source.entries {
        if let Some(index) = target
            .entries
            .iter()
            .position(|entry| entry.id == source_entry.id)
        {
            if should_replace(
                target.entries[index].times.modified,
                source_entry.times.modified,
                strategy,
            ) {
                target.entries[index] =
                    remap_entry(source_entry, source_pool, target_pool, references);
            }
        } else {
            target.entries.push(remap_entry(
                source_entry,
                source_pool,
                target_pool,
                references,
            ));
        }
    }
    for source_group in &source.groups {
        if let Some(index) = target
            .groups
            .iter()
            .position(|group| group.id == source_group.id)
        {
            if should_replace(
                target.groups[index].times.modified,
                source_group.times.modified,
                strategy,
            ) {
                target.groups[index] = source_group.clone();
            }
            merge_group(
                &mut target.groups[index],
                source_group,
                strategy,
                source_pool,
                target_pool,
                references,
            );
        } else {
            target.groups.push(remap_group(
                source_group,
                source_pool,
                target_pool,
                references,
            ));
        }
    }
}

fn remap_group(
    source: &Group,
    source_pool: &BinaryPool,
    target_pool: &mut BinaryPool,
    references: &mut [Option<usize>],
) -> Group {
    let mut group = source.clone();
    for entry in &mut group.entries {
        *entry = remap_entry(entry, source_pool, target_pool, references);
    }
    for child in &mut group.groups {
        let source_child = child.clone();
        *child = remap_group(&source_child, source_pool, target_pool, references);
    }
    group
}

fn should_replace(target: KdbxTimestamp, source: KdbxTimestamp, strategy: MergeStrategy) -> bool {
    match strategy {
        MergeStrategy::KeepTarget => false,
        MergeStrategy::PreferSource => true,
        MergeStrategy::NewestModification => source > target,
    }
}

fn remap_entry(
    source: &Entry,
    source_pool: &BinaryPool,
    target_pool: &mut BinaryPool,
    references: &mut [Option<usize>],
) -> Entry {
    let mut entry = source.clone();
    for attachment in &mut entry.attachments {
        attachment.reference =
            remap_binary(attachment.reference, source_pool, target_pool, references);
    }
    for snapshot in &mut entry.history {
        *snapshot = remap_entry(snapshot, source_pool, target_pool, references);
    }
    entry
}

fn remap_binary(
    reference: usize,
    source_pool: &BinaryPool,
    target_pool: &mut BinaryPool,
    references: &mut [Option<usize>],
) -> usize {
    if let Some(existing) = references.get(reference).and_then(|value| *value) {
        return existing;
    }
    let record = source_pool
        .records()
        .get(reference)
        .expect("source binary reference was validated");
    let data = record.data.clone();
    let protected = record.protected;
    let existing = target_pool
        .records()
        .iter()
        .position(|candidate| candidate.protected == protected && candidate.data == data)
        .unwrap_or_else(|| target_pool.add(data, protected));
    if let Some(slot) = references.get_mut(reference) {
        *slot = Some(existing);
    }
    existing
}

#[cfg(test)]
mod debug_surface {
    use super::{ChaCha20MemoryProtection, MemoryProtectionProvider};
    use zeroize::Zeroizing;

    /// The key material behind a `ChaCha20MemoryProtection` is not printable.
    ///
    /// This lives in the crate's own tests rather than in
    /// `tests/debug_surface.rs` because `ChaCha20MemoryProtection::new` is
    /// private, so an integration test cannot construct a real instance. The
    /// integration test pins the *mechanism* instead — that `zeroize` derives
    /// `Debug` for `Zeroizing` by printing the wrapped value — and this one pins
    /// the result for the actual type.
    #[test]
    fn the_in_memory_protection_key_is_not_printable() {
        const PLAINTEXT: &[u8] = b"canary-plaintext";
        let protector = ChaCha20MemoryProtection::new().expect("operating-system entropy");
        // Drive it, so the key is a real random key rather than the all-zero
        // buffer the constructor starts from.
        let protected = protector.protect(PLAINTEXT).expect("protect");
        assert_eq!(
            format!("{protector:?}"),
            "ChaCha20MemoryProtection",
            "the impl prints the type name and nothing else"
        );
        // The second argument is checked for *equality* with the revealed
        // length, not as an upper bound, despite the parameter's name.
        assert_eq!(
            protector
                .unprotect(&protected, PLAINTEXT.len())
                .expect("unprotect")
                .as_slice(),
            PLAINTEXT
        );
        assert_ne!(protected, PLAINTEXT, "the protector transforms");
    }

    /// `zeroize`'s `Debug` for `Zeroizing` prints the wrapped value, which is
    /// why the impl above cannot be a derive.
    ///
    /// Written as a positive claim about the dependency so that it fails loudly
    /// if `zeroize` ever changes, rather than silently making the hand-written
    /// impl look redundant to whoever reads this next.
    #[test]
    fn zeroizing_derives_debug_by_printing_the_wrapped_value() {
        let canary = *b"CANARY-KEY-32-BYTES-LONG-EXACT!!";
        let rendered = format!("{:?}", Zeroizing::new(canary));
        let decimal = canary
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            rendered.contains(&decimal),
            "zeroize is expected to derive Debug for Zeroizing by printing the \
             wrapped value; if this no longer holds, the reasoning behind the \
             hand-written ChaCha20MemoryProtection impl should be revisited: \
             {rendered}"
        );
    }
}
