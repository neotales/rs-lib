//! age's ML-KEM-768 + X25519 hybrid recipient implementation.
//!
//! The HPKE dependency and its XWing KEM live in ``; this
//! module contains only the age-specific key encodings, domain label, and
//! stanza shape.

use {
    hpke::{
        Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
        kdf::HkdfSha256, kem::XWing,
    },
    zeroize::Zeroizing,
};

use crate::{
    codec::{decode_raw, encode_raw},
    crypto::random_array,
    error::{AgeError, Result},
    header::Stanza,
};

/// The age HPKE domain-separation label for ML-KEM-768 + X25519.
pub(crate) const HYBRID_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";
/// The serialized XWing public-key length.
pub(crate) const HYBRID_PUBLIC_KEY_LENGTH: usize = 1216;
/// The serialized XWing private-key length.
pub(crate) const HYBRID_PRIVATE_KEY_LENGTH: usize = 32;
/// The serialized XWing encapsulated-key length.
pub(crate) const HYBRID_ENCAPSULATED_KEY_LENGTH: usize = 1120;
/// The age file-key ciphertext length: 16-byte key plus a 16-byte tag.
pub(crate) const HYBRID_CIPHERTEXT_LENGTH: usize = 32;

pub(crate) type HybridKem = XWing;
pub(crate) type HybridPublicKey = <XWing as KemTrait>::PublicKey;
pub(crate) type HybridPrivateKey = <XWing as KemTrait>::PrivateKey;
pub(crate) type HybridEncapsulatedKey = <XWing as KemTrait>::EncappedKey;

pub(crate) fn generate_keypair() -> Result<(HybridPrivateKey, HybridPublicKey)> {
    // The Go age implementation feeds 32 random bytes directly to the XWing
    // private-key constructor. Do the same instead of using hpke's convenience
    // generator, which derives through the generic HPKE key-derivation step.
    let seed = Zeroizing::new(random_array::<32>()?);
    let private_key = HybridPrivateKey::from_bytes(&seed[..])
        .map_err(|_| AgeError::Crypto("MLKEM768-X25519 key generation"))?;
    let public_key = XWing::sk_to_pk(&private_key);
    Ok((private_key, public_key))
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> Result<HybridPublicKey> {
    if bytes.len() != HYBRID_PUBLIC_KEY_LENGTH {
        return Err(AgeError::InvalidKey("invalid age hybrid public key"));
    }
    HybridPublicKey::from_bytes(bytes)
        .map_err(|_| AgeError::InvalidKey("invalid age hybrid public key"))
}

pub(crate) fn private_key_from_bytes(bytes: &[u8]) -> Result<HybridPrivateKey> {
    if bytes.len() != HYBRID_PRIVATE_KEY_LENGTH {
        return Err(AgeError::InvalidKey("invalid age hybrid private key"));
    }
    HybridPrivateKey::from_bytes(bytes)
        .map_err(|_| AgeError::InvalidKey("invalid age hybrid private key"))
}

pub(crate) fn public_key_bytes(public_key: &HybridPublicKey) -> Vec<u8> {
    public_key.to_bytes().as_slice().to_vec()
}

pub(crate) fn private_key_bytes(private_key: &HybridPrivateKey) -> Zeroizing<Vec<u8>> {
    let bytes = private_key.to_bytes();
    let mut result = Zeroizing::new(Vec::with_capacity(bytes.len()));
    result.extend_from_slice(bytes.as_slice());
    result
}

pub(crate) fn wrap(public_key: &HybridPublicKey, file_key: &[u8]) -> Result<Stanza> {
    if file_key.len() != crate::crypto::FILE_KEY_LENGTH {
        return Err(AgeError::InvalidKey("age file keys are 16 bytes"));
    }

    let (encapsulated_key, mut context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            public_key,
            HYBRID_LABEL,
        )
        .map_err(|_| AgeError::Crypto("MLKEM768-X25519 HPKE sender"))?;
    let body = context
        .seal(file_key, &[])
        .map_err(|_| AgeError::Crypto("MLKEM768-X25519 encryption"))?;
    let encapsulated_key_bytes = encapsulated_key.to_bytes();
    Ok(Stanza::new(
        "mlkem768x25519",
        [encode_raw(encapsulated_key_bytes.as_slice())],
        body,
    ))
}

pub(crate) fn unwrap(
    private_key: &HybridPrivateKey,
    stanza: &Stanza,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if stanza.r#type != "mlkem768x25519" {
        return Ok(None);
    }
    if stanza.args.len() != 1 {
        return Err(AgeError::InvalidFormat(
            "invalid mlkem768x25519 recipient block",
        ));
    }
    if stanza.body.len() != HYBRID_CIPHERTEXT_LENGTH {
        return Err(AgeError::InvalidFormat(
            "invalid mlkem768x25519 recipient block",
        ));
    }

    let encapsulated_key_bytes = decode_raw(&stanza.args[0])
        .map_err(|_| AgeError::InvalidFormat("invalid mlkem768x25519 encapsulated key"))?;
    if encapsulated_key_bytes.len() != HYBRID_ENCAPSULATED_KEY_LENGTH {
        return Err(AgeError::InvalidFormat(
            "invalid mlkem768x25519 encapsulated key",
        ));
    }
    let encapsulated_key = HybridEncapsulatedKey::from_bytes(&encapsulated_key_bytes)
        .map_err(|_| AgeError::InvalidFormat("invalid mlkem768x25519 encapsulated key"))?;

    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        private_key,
        &encapsulated_key,
        HYBRID_LABEL,
    )
    .map_err(|_| AgeError::InvalidFormat("invalid mlkem768x25519 recipient"))?;

    match context.open(&stanza.body, &[]) {
        Ok(file_key) if file_key.len() == crate::crypto::FILE_KEY_LENGTH => {
            Ok(Some(Zeroizing::new(file_key)))
        }
        Ok(_) => Err(AgeError::InvalidFormat(
            "invalid mlkem768x25519 file key size",
        )),
        // A structurally valid stanza that does not authenticate is a normal
        // identity mismatch. Structural errors above remain fatal.
        Err(_) => Ok(None),
    }
}
