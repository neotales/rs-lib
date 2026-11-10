// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::sync::Arc;

use neotales_keepass::{
    KdbxError, KdbxFailureKind, MemoryPinningPolicy, MemoryPinningStatus, MemoryProtectionError,
    MemoryProtectionProvider, ProtectedValue,
};

struct PrefixProvider;

impl MemoryProtectionProvider for PrefixProvider {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        let mut value = vec![0xA5];
        value.extend_from_slice(plaintext);
        Ok(value)
    }

    fn unprotect(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<neotales_keepass::SecretBytes, MemoryProtectionError> {
        let value = protected
            .strip_prefix(&[0xA5])
            .ok_or(MemoryProtectionError::UnprotectFailed)?;
        if value.len() != max_plaintext_len {
            return Err(MemoryProtectionError::InvalidPlaintextLength);
        }
        Ok(neotales_keepass::SecretBytes::from_vec(value.to_vec()))
    }
}

struct ReverseProvider;

impl MemoryProtectionProvider for ReverseProvider {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        Ok(plaintext.iter().rev().copied().collect())
    }

    fn unprotect(
        &self,
        protected: &[u8],
        _max_plaintext_len: usize,
    ) -> Result<neotales_keepass::SecretBytes, MemoryProtectionError> {
        Ok(neotales_keepass::SecretBytes::from_vec(
            self.protect(protected)?,
        ))
    }
}

struct PinningProvider(MemoryPinningStatus);

impl MemoryProtectionProvider for PinningProvider {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, MemoryProtectionError> {
        Ok(plaintext.to_vec())
    }

    fn unprotect(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<neotales_keepass::SecretBytes, MemoryProtectionError> {
        if protected.len() != max_plaintext_len {
            return Err(MemoryProtectionError::InvalidPlaintextLength);
        }
        Ok(neotales_keepass::SecretBytes::from_vec(protected.to_vec()))
    }

    fn pinning_policy(&self) -> MemoryPinningPolicy {
        MemoryPinningPolicy::Required
    }

    fn pinning_status(&self) -> MemoryPinningStatus {
        self.0
    }
}

#[test]
fn text_origin_is_not_additionally_memory_encrypted() {
    let value = ProtectedValue::from_text("immutable text");
    assert!(!value.is_memory_protected());
    assert_eq!(value.reveal_text().unwrap().as_str(), "immutable text");
    assert!(!format!("{value:?}").contains("immutable"));
}

#[test]
fn byte_origin_uses_default_chacha20_memory_protection() {
    let value = ProtectedValue::from_bytes_protected(b"binary secret".to_vec()).unwrap();
    assert!(value.is_memory_protected());
    assert_eq!(value.reveal_text().unwrap().as_str(), "binary secret");
    assert_eq!(
        value.with_revealed_text(str::len).unwrap(),
        "binary secret".len()
    );
    assert!(!format!("{value:?}").contains("binary secret"));
}

#[test]
fn plaintext_length_is_independent_of_protected_length() {
    let value =
        ProtectedValue::from_bytes_with_protection(Vec::new(), Arc::new(PrefixProvider)).unwrap();
    assert_eq!(value.len(), 0);
    assert!(value.is_empty());
    assert_eq!(value.reveal_bytes().unwrap().as_slice(), b"");
}

#[test]
fn external_provider_hook_round_trips() {
    let value = ProtectedValue::from_bytes_with_protection(
        b"provider secret".to_vec(),
        Arc::new(ReverseProvider),
    )
    .unwrap();
    assert!(value.is_memory_protected());
    assert_eq!(value.reveal_text().unwrap().as_str(), "provider secret");
}

#[test]
fn default_provider_reports_no_pinning() {
    let value = ProtectedValue::from_bytes_protected(b"not pinned".to_vec()).unwrap();
    assert_eq!(value.pinning_policy(), MemoryPinningPolicy::Disabled);
    assert_eq!(value.pinning_status(), MemoryPinningStatus::NotPinned);
}

#[test]
fn provider_can_report_required_pinning_without_changing_the_hook() {
    let value = ProtectedValue::from_bytes_with_protection(
        b"pinned".to_vec(),
        Arc::new(PinningProvider(MemoryPinningStatus::Pinned)),
    )
    .unwrap();
    assert_eq!(value.pinning_policy(), MemoryPinningPolicy::Required);
    assert_eq!(value.pinning_status(), MemoryPinningStatus::Pinned);
    assert!(value.pinning_policy().accepts(value.pinning_status()));
    assert_eq!(value.reveal_bytes().unwrap().as_slice(), b"pinned");
}

#[test]
fn required_pinning_failure_is_not_accepted_by_the_core() {
    let error = ProtectedValue::from_bytes_with_protection(
        b"must fail".to_vec(),
        Arc::new(PinningProvider(MemoryPinningStatus::Unavailable)),
    )
    .unwrap_err();
    assert!(matches!(error, MemoryProtectionError::PinningUnavailable));
}

#[test]
fn pinning_policy_is_explicit_about_required_and_best_effort_status() {
    assert!(MemoryPinningPolicy::BestEffort.accepts(MemoryPinningStatus::Failed));
    assert!(MemoryPinningPolicy::BestEffort.accepts(MemoryPinningStatus::Unavailable));
    assert!(!MemoryPinningPolicy::Required.accepts(MemoryPinningStatus::Failed));
    assert!(!MemoryPinningPolicy::Required.accepts(MemoryPinningStatus::Unavailable));
    assert!(MemoryPinningPolicy::Required.accepts(MemoryPinningStatus::Pinned));
}

#[test]
fn pinning_failures_are_reported_instead_of_silently_ignored() {
    let unavailable: KdbxError = MemoryProtectionError::PinningUnavailable.into();
    assert_eq!(unavailable.kind, KdbxFailureKind::Unsupported);
    assert!(!unavailable.message.contains("secret"));

    let failed: KdbxError = MemoryProtectionError::PinningFailed.into();
    assert_eq!(failed.kind, KdbxFailureKind::Authentication);
    assert_eq!(failed.message, "memory pinning failed");
}
