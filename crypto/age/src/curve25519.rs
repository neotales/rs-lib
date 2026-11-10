//! Ed25519 key material used as X25519.
//!
//! Age's SSH recipients and any other protocol that reuses an Ed25519 key for
//! Diffie-Hellman need this map. `ed25519-dalek` exposes the same operations,
//! and this module wipes the SHA-512 expansion and rejects a public key that
//! is not a valid Ed25519 point.

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// The Ed25519 public key is not a valid point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidEd25519PublicKey;

impl std::fmt::Display for InvalidEd25519PublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ed25519 public key is not a valid point")
    }
}

impl std::error::Error for InvalidEd25519PublicKey {}

/// Converts an Ed25519 verifying key to an X25519 Montgomery u-coordinate.
///
/// # Errors
///
/// Returns [`InvalidEd25519PublicKey`] when `public_key` is not a canonical
/// Ed25519 point or is a small-order point.
pub(crate) fn ed25519_public_to_x25519(
    public_key: &[u8; 32],
) -> Result<[u8; 32], InvalidEd25519PublicKey> {
    let verifying = VerifyingKey::from_bytes(public_key).map_err(|_| InvalidEd25519PublicKey)?;
    if verifying.is_weak() {
        return Err(InvalidEd25519PublicKey);
    }
    Ok(verifying.to_montgomery().to_bytes())
}

/// Expands an Ed25519 seed into the clamped X25519 scalar.
///
/// The result matches RFC 8032 clamping: the low three bits of the first byte
/// are cleared, and the high byte has its top bit cleared and its next bit
/// set. `x25519-dalek`'s `StaticSecret` accepts these bytes.
#[must_use]
pub(crate) fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let signing = SigningKey::from_bytes(seed);
    let mut hash = Sha512::digest(signing.as_bytes());
    hash[0] &= 0b1111_1000;
    hash[31] &= 0b0111_1111;
    hash[31] |= 0b0100_0000;
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    hash.as_mut_slice().zeroize();
    scalar
}

#[cfg(test)]
mod tests {
    use super::{ed25519_public_to_x25519, ed25519_seed_to_x25519};
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn seed_and_public_conversion_agree() {
        let seed = [32u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let scalar = ed25519_seed_to_x25519(&seed);
        assert_eq!(scalar[0] & 0b0000_0111, 0);
        assert_eq!(scalar[31] & 0b1100_0000, 0b0100_0000);

        let public = ed25519_public_to_x25519(&signing.verifying_key().to_bytes())
            .expect("verifying key is a valid point");
        let secret = StaticSecret::from(scalar);
        assert_eq!(PublicKey::from(&secret).to_bytes(), public);
    }

    #[test]
    fn rejects_a_non_point() {
        assert!(ed25519_public_to_x25519(&[0u8; 32]).is_err());
    }
}
