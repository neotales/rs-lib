//! Platform-owned Unix `mlock` buffer.
//!
//! The core reveal path returns a separately allocated `SecretBytes` value.
//! This module therefore does not implement `MemoryProtectionProvider` and
//! never reports that core buffer as pinned.

use std::fmt;
#[cfg(unix)]
use std::mem::ManuallyDrop;

use neotales_keepass::{MemoryPinningPolicy, MemoryPinningStatus, MemoryProtectionError};
#[cfg(unix)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Largest plaintext this adapter will ask the operating system to pin.
///
/// The bound matches the core crate's default binary limit. The operating
/// system still rounds a successful pin up to a whole page, and that rounded
/// size must also fit in this bound.
pub const MAX_PINNED_BYTES: usize = 64 * 1024 * 1024;

/// A secret buffer owned by this crate, optionally locked in RAM.
///
/// [`MemoryPinningStatus::Pinned`] means this value still owns a page-aligned
/// allocation and the operating-system lock. Drop overwrites that allocation
/// before the lock is released. Pinning is best effort against swap; it does
/// not hide memory from a debugger, administrator, crash dump, or another
/// process with the same privileges.
///
/// # Examples
///
/// ```
/// use neotales_keepass::MemoryPinningPolicy;
/// use neotales_keepass_platform::PinnedBytes;
///
/// let pinned = PinnedBytes::from_bytes(MemoryPinningPolicy::Disabled, b"secret".to_vec())
///     .expect("disabled policy does not call the operating system");
/// assert_eq!(pinned.as_slice(), b"secret");
/// assert!(!format!("{pinned:?}").contains("secret"));
/// ```
pub struct PinnedBytes {
    policy: MemoryPinningPolicy,
    status: MemoryPinningStatus,
    storage: Storage,
}

enum Storage {
    Heap(Zeroizing<Vec<u8>>),
    #[cfg(unix)]
    Mapped(MappedSecret),
}

#[cfg(unix)]
struct MappedSecret {
    map: Option<memmap2::MmapMut>,
    len: usize,
    locked: bool,
}

impl PinnedBytes {
    /// Copies `plaintext` into a platform-owned buffer and applies `policy`.
    ///
    /// The owned input is zeroized after it is copied, or when this function
    /// returns an error. An empty input is not locked: both `mlock` and
    /// `mlock` rejects a zero length.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryProtectionError::PinningUnavailable`] when `policy` is
    /// [`MemoryPinningPolicy::Required`] and this target cannot pin, including
    /// for an empty buffer. Returns [`MemoryProtectionError::PinningFailed`]
    /// when a required lock is rejected or `plaintext` exceeds
    /// [`MAX_PINNED_BYTES`].
    pub fn from_bytes(
        policy: MemoryPinningPolicy,
        plaintext: impl Into<Vec<u8>>,
    ) -> Result<Self, MemoryProtectionError> {
        let plaintext = Zeroizing::new(plaintext.into());
        if policy == MemoryPinningPolicy::Disabled {
            return Ok(Self::heap(
                policy,
                MemoryPinningStatus::NotPinned,
                plaintext,
            ));
        }
        if plaintext.is_empty() {
            return unpinned(policy, MemoryPinningStatus::Unavailable, plaintext);
        }
        if plaintext.len() > MAX_PINNED_BYTES {
            return unpinned(policy, MemoryPinningStatus::Failed, plaintext);
        }
        try_platform_pin(policy, plaintext)
    }

    /// Runs `operation` while any acquired platform lock is still held.
    ///
    /// The closure cannot outlive the lock. The input is zeroized even when
    /// the callback is not invoked.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_bytes`]. The callback is not
    /// called when pinning is required and cannot be established.
    pub fn with_bytes<T>(
        policy: MemoryPinningPolicy,
        plaintext: impl Into<Vec<u8>>,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, MemoryProtectionError> {
        let pinned = Self::from_bytes(policy, plaintext)?;
        Ok(operation(pinned.as_slice()))
    }

    /// Returns the policy used to create this buffer.
    #[must_use]
    pub const fn policy(&self) -> MemoryPinningPolicy {
        self.policy
    }

    /// Returns the pinning status for this buffer.
    #[must_use]
    pub const fn status(&self) -> MemoryPinningStatus {
        self.status
    }

    /// Returns the plaintext copied into this buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match &self.storage {
            Storage::Heap(bytes) => bytes.as_slice(),
            #[cfg(unix)]
            Storage::Mapped(mapped) => mapped.as_slice(),
        }
    }

    /// Returns the plaintext length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    fn heap(
        policy: MemoryPinningPolicy,
        status: MemoryPinningStatus,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            policy,
            status,
            storage: Storage::Heap(plaintext),
        }
    }
}

impl fmt::Debug for PinnedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedBytes")
            .field("policy", &self.policy)
            .field("status", &self.status)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

fn unpinned(
    policy: MemoryPinningPolicy,
    status: MemoryPinningStatus,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<PinnedBytes, MemoryProtectionError> {
    if policy.is_required() {
        return Err(required_error(status));
    }
    Ok(PinnedBytes::heap(policy, status, plaintext))
}

fn required_error(status: MemoryPinningStatus) -> MemoryProtectionError {
    match status {
        MemoryPinningStatus::Unavailable => MemoryProtectionError::PinningUnavailable,
        MemoryPinningStatus::NotPinned
        | MemoryPinningStatus::Failed
        | MemoryPinningStatus::Pinned => MemoryProtectionError::PinningFailed,
    }
}

#[cfg(not(unix))]
fn try_platform_pin(
    policy: MemoryPinningPolicy,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<PinnedBytes, MemoryProtectionError> {
    unpinned(policy, MemoryPinningStatus::Unavailable, plaintext)
}

#[cfg(unix)]
fn try_platform_pin(
    policy: MemoryPinningPolicy,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<PinnedBytes, MemoryProtectionError> {
    let len = plaintext.len();
    let Some(bytes) = page_rounded(len) else {
        return unpinned(policy, MemoryPinningStatus::Unavailable, plaintext);
    };
    if bytes > MAX_PINNED_BYTES {
        return unpinned(policy, MemoryPinningStatus::Failed, plaintext);
    }
    let mut map = match memmap2::MmapMut::map_anon(bytes) {
        Ok(map) if is_exclusive_page_mapping(&map, bytes) => map,
        Ok(_) => return unpinned(policy, MemoryPinningStatus::Unavailable, plaintext),
        Err(error) => return unpinned(policy, io_status(&error), plaintext),
    };
    match map.lock() {
        Ok(()) => {
            write_secret(&mut map, &plaintext);
            Ok(PinnedBytes {
                policy,
                status: MemoryPinningStatus::Pinned,
                storage: Storage::Mapped(MappedSecret {
                    map: Some(map),
                    len,
                    locked: true,
                }),
            })
        }
        Err(error) if policy.is_required() => unpinned(policy, io_status(&error), plaintext),
        Err(error) => {
            write_secret(&mut map, &plaintext);
            Ok(PinnedBytes {
                policy,
                status: io_status(&error),
                storage: Storage::Mapped(MappedSecret {
                    map: Some(map),
                    len,
                    locked: false,
                }),
            })
        }
    }
}

#[cfg(unix)]
fn page_rounded(len: usize) -> Option<usize> {
    let page = region::page::size();
    if page == 0 {
        return None;
    }
    let remainder = len % page;
    if remainder == 0 {
        Some(len)
    } else {
        len.checked_add(page - remainder)
    }
}

#[cfg(unix)]
fn is_exclusive_page_mapping(map: &memmap2::MmapMut, bytes: usize) -> bool {
    let page = region::page::size();
    page != 0
        && map.len() == bytes
        && bytes.is_multiple_of(page)
        && map.as_ptr().addr().is_multiple_of(page)
}

#[cfg(unix)]
fn write_secret(map: &mut memmap2::MmapMut, plaintext: &[u8]) {
    map[..plaintext.len()].copy_from_slice(plaintext);
}

#[cfg(unix)]
fn io_status(error: &std::io::Error) -> MemoryPinningStatus {
    if error.kind() == std::io::ErrorKind::Unsupported {
        MemoryPinningStatus::Unavailable
    } else {
        MemoryPinningStatus::Failed
    }
}

#[cfg(unix)]
impl MappedSecret {
    fn as_slice(&self) -> &[u8] {
        self.map.as_ref().map_or(&[], |map| &map[..self.len])
    }
}

#[cfg(unix)]
impl Drop for MappedSecret {
    fn drop(&mut self) {
        if let Some(map) = self.map.as_mut() {
            map.zeroize();
        }
        // Unlock only after the overwrite. A failed `munlock` leaks the
        // still-locked mapping so it cannot be reused.
        if self.locked && self.map.as_ref().is_some_and(|map| map.unlock().is_err()) {
            let _quarantine = ManuallyDrop::new(self.map.take());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::page_rounded;

    #[test]
    fn rounds_partial_lengths_up_to_one_page() {
        let page = region::page::size();
        assert!(page > 1);
        assert_eq!(page_rounded(1), Some(page));
        assert_eq!(page_rounded(page), Some(page));
        assert_eq!(page_rounded(page + 1), page.checked_mul(2));
    }
}
