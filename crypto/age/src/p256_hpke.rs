/// P-256 and HPKE adapters shared by formats that use the NIST P-256 HPKE KEM.
///
/// The HPKE KEM serializes NIST public keys in uncompressed SEC-1 form, while
/// age's tagged P-256 recipient encoding uses the compressed form. This
/// module keeps that conversion and the generic HPKE sender setup together so
/// callers do not need to depend on a second copy of the curve or HPKE crates.
use hpke::{
    Deserializable, HpkeError, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::DhP256HkdfSha256,
};
use p256::{PublicKey as P256PublicKey, elliptic_curve::sec1::ToSec1Point};

/// The HPKE KEM used by the P-256 tagged recipient format.
pub(crate) type Kem = DhP256HkdfSha256;
/// The HPKE public-key representation used by [`Kem`].
pub(crate) type PublicKey = <Kem as KemTrait>::PublicKey;

/// The compressed SEC-1 P-256 public-key length.
pub(crate) const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 33;
/// The uncompressed SEC-1 P-256 public-key length.
pub(crate) const UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 65;

/// Parses a compressed SEC-1 P-256 public key for HPKE.
///
/// # Errors
///
/// Returns [`HpkeError::IncorrectInputLength`] or
/// [`HpkeError::ValidationError`] when the input is not a valid compressed
/// P-256 point.
pub(crate) fn public_key_from_compressed(encoded: &[u8]) -> Result<PublicKey, HpkeError> {
    if encoded.len() != COMPRESSED_PUBLIC_KEY_LENGTH {
        return Err(HpkeError::IncorrectInputLength(
            COMPRESSED_PUBLIC_KEY_LENGTH,
            encoded.len(),
        ));
    }
    let point = P256PublicKey::from_sec1_bytes(encoded).map_err(|_| HpkeError::ValidationError)?;
    // DHKEM(P-256, HKDF-SHA256) uses uncompressed SEC-1 for its public-key
    // and KEM-context encodings, even though age carries the compressed
    // recipient form in Bech32.
    <PublicKey as Deserializable>::from_bytes(point.to_sec1_point(false).as_bytes())
}

/// Serializes an HPKE P-256 public key to compressed SEC-1 form.
///
/// # Errors
///
/// Returns [`HpkeError::ValidationError`] if the HPKE value cannot be
/// converted to a canonical compressed point.
pub(crate) fn public_key_to_compressed(public_key: &PublicKey) -> Result<[u8; 33], HpkeError> {
    let encoded = public_key.to_bytes();
    let point = P256PublicKey::from_sec1_bytes(encoded.as_slice())
        .map_err(|_| HpkeError::ValidationError)?;
    point
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| HpkeError::ValidationError)
}

/// Performs a one-shot HPKE base-mode seal with HKDF-SHA-256 and
/// ChaCha20-Poly1305.
///
/// The returned pair is `(encapsulated_key, ciphertext)`. The age-specific
/// information label and stanza encoding remain the caller's concern.
///
/// # Errors
///
/// Returns an HPKE error if encapsulation or encryption fails.
pub(crate) fn seal<K>(
    public_key: &K::PublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeError>
where
    K: KemTrait,
{
    let (encapsulated_key, mut context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, K>(&OpModeS::Base, public_key, info)?;
    let ciphertext = context.seal(plaintext, &[])?;
    let encapsulated_key = encapsulated_key.to_bytes();
    Ok((encapsulated_key.as_slice().to_vec(), ciphertext))
}
