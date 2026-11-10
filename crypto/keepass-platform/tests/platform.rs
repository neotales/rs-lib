// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{MemoryPinningPolicy, MemoryPinningStatus};

#[cfg(any(feature = "memory-pin", feature = "windows-dpapi"))]
use neotales_keepass::MemoryProtectionError;
#[cfg(feature = "memory-pin")]
use neotales_keepass_platform::{MAX_PINNED_BYTES, PinnedBytes};

#[cfg(all(feature = "windows-dpapi", windows))]
use std::sync::Arc;

#[cfg(all(feature = "windows-dpapi", not(windows)))]
use neotales_keepass::MemoryProtectionProvider;
#[cfg(all(feature = "windows-dpapi", windows))]
use neotales_keepass::ProtectedValue;
#[cfg(feature = "windows-dpapi")]
use neotales_keepass_platform::{DpapiScope, WindowsDpapiProvider};

#[test]
fn platform_crate_reuses_the_core_pinning_contract() {
    assert_eq!(
        MemoryPinningPolicy::default(),
        MemoryPinningPolicy::Disabled
    );
    assert_eq!(
        MemoryPinningStatus::default(),
        MemoryPinningStatus::NotPinned
    );
    assert!(MemoryPinningPolicy::BestEffort.accepts(MemoryPinningStatus::Failed));
    assert!(!MemoryPinningPolicy::Required.accepts(MemoryPinningStatus::Unavailable));
}

#[cfg(all(feature = "windows-dpapi", not(windows)))]
#[test]
fn dpapi_provider_fails_explicitly_off_windows() {
    let provider = WindowsDpapiProvider::with_entropy(DpapiScope::User, b"context".to_vec());
    assert_eq!(provider.scope(), DpapiScope::User);
    assert!(provider.has_entropy());
    assert!(!format!("{provider:?}").contains("context"));
    assert!(matches!(
        provider.protect(b"secret"),
        Err(MemoryProtectionError::PlatformUnavailable)
    ));
    assert!(matches!(
        provider.unprotect(b"ciphertext", 6),
        Err(MemoryProtectionError::PlatformUnavailable)
    ));
}

#[cfg(feature = "memory-pin")]
#[test]
fn disabled_pin_keeps_bytes_without_an_os_lock() {
    let pinned = PinnedBytes::from_bytes(MemoryPinningPolicy::Disabled, b"secret".to_vec())
        .expect("disabled policy does not call the operating system");
    assert_eq!(pinned.as_slice(), b"secret");
    assert_eq!(pinned.policy(), MemoryPinningPolicy::Disabled);
    assert_eq!(pinned.status(), MemoryPinningStatus::NotPinned);
    assert!(!format!("{pinned:?}").contains("secret"));
}

#[cfg(feature = "memory-pin")]
#[test]
fn required_empty_input_is_unavailable() {
    let mut called = false;
    let error = PinnedBytes::with_bytes(MemoryPinningPolicy::Required, Vec::new(), |_| {
        called = true;
    })
    .expect_err("a zero-length lock is not a pin");
    assert!(!called);
    assert!(matches!(error, MemoryProtectionError::PinningUnavailable));
}

#[cfg(feature = "memory-pin")]
#[test]
fn oversized_required_pin_fails_closed() {
    let error =
        PinnedBytes::from_bytes(MemoryPinningPolicy::Required, vec![1; MAX_PINNED_BYTES + 1])
            .expect_err("the adapter refuses an unbounded pin");
    assert!(matches!(error, MemoryProtectionError::PinningFailed));
}

#[cfg(feature = "memory-pin")]
#[test]
fn best_effort_preserves_bytes_and_does_not_invent_a_pin() {
    PinnedBytes::with_bytes(
        MemoryPinningPolicy::BestEffort,
        b"secret".to_vec(),
        |bytes| {
            assert_eq!(bytes, b"secret");
        },
    )
    .expect("best effort returns a buffer");
    let pinned = PinnedBytes::from_bytes(MemoryPinningPolicy::BestEffort, b"secret".to_vec())
        .expect("best effort returns a buffer");
    assert_eq!(pinned.as_slice(), b"secret");
    assert!(pinned.policy().accepts(pinned.status()));
    assert_ne!(pinned.status(), MemoryPinningStatus::NotPinned);
}

#[cfg(feature = "memory-pin")]
#[test]
fn required_pin_either_locks_or_fails_closed() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PinnedBytes>();

    match PinnedBytes::from_bytes(MemoryPinningPolicy::Required, b"secret".to_vec()) {
        Ok(pinned) => {
            assert_eq!(pinned.status(), MemoryPinningStatus::Pinned);
            assert_eq!(pinned.as_slice(), b"secret");
            assert!(!format!("{pinned:?}").contains("secret"));
        }
        Err(error) => assert!(matches!(
            error,
            MemoryProtectionError::PinningFailed | MemoryProtectionError::PinningUnavailable
        )),
    }
}

#[cfg(all(feature = "memory-pin", not(unix)))]
#[test]
fn native_pin_is_explicitly_unavailable() {
    let error = PinnedBytes::from_bytes(MemoryPinningPolicy::Required, b"secret".to_vec())
        .expect_err("no native pinning adapter on this target");
    assert!(matches!(error, MemoryProtectionError::PinningUnavailable));
}

#[cfg(all(feature = "windows-dpapi", windows))]
#[test]
fn dpapi_provider_round_trips_user_scope_with_entropy() {
    let provider = Arc::new(WindowsDpapiProvider::with_entropy(
        DpapiScope::User,
        b"context".to_vec(),
    ));
    let value =
        ProtectedValue::from_bytes_with_protection(b"provider secret".to_vec(), provider).unwrap();
    assert_eq!(value.reveal_bytes().unwrap().as_slice(), b"provider secret");
    assert_eq!(value.pinning_policy(), MemoryPinningPolicy::Disabled);
    assert_eq!(value.pinning_status(), MemoryPinningStatus::NotPinned);
}
