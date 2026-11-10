//! age's tagged P-256 and ML-KEM-768 + P-256 recipients.
//!
//! The tagged formats are encryption-only here. Their identities are expected
//! to be provided by a hardware-key integration, so this module deliberately
//! contains no identity or plugin-protocol implementation.

use {
    hkdf::Hkdf,
    hpke::{Deserializable, Kem as KemTrait, Serializable, kem::MlKem768P256},
    sha2::{Digest, Sha256},
};

use crate::{
    codec::encode_raw,
    error::{AgeError, Result},
    header::Stanza,
    p256_hpke,
};

/// The Bech32 HRP for the classic tagged recipient.
pub(crate) const CLASSIC_HRP: &str = "age1tag";
/// The Bech32 HRP for the hybrid tagged recipient.
pub(crate) const HYBRID_HRP: &str = "age1tagpq";
/// The stanza type for the classic tagged recipient.
pub(crate) const CLASSIC_STANZA_TYPE: &str = "p256tag";
/// The stanza type for the hybrid tagged recipient.
pub(crate) const HYBRID_STANZA_TYPE: &str = "mlkem768p256tag";
/// The HPKE information label for the classic tagged recipient.
pub(crate) const CLASSIC_LABEL: &[u8] = b"age-encryption.org/p256tag";
/// The HPKE information label for the hybrid tagged recipient.
pub(crate) const HYBRID_LABEL: &[u8] = b"age-encryption.org/mlkem768p256tag";

/// The compressed P-256 public-key length.
pub(crate) const CLASSIC_PUBLIC_KEY_LENGTH: usize = 33;
/// The ML-KEM-768 encapsulation-key length.
pub(crate) const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
/// The uncompressed P-256 public-key length used by the hybrid KEM.
pub(crate) const P256_UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize =
    p256_hpke::UNCOMPRESSED_PUBLIC_KEY_LENGTH;
/// The concatenated ML-KEM-768 + P-256 public-key length.
pub(crate) const HYBRID_PUBLIC_KEY_LENGTH: usize =
    MLKEM768_PUBLIC_KEY_LENGTH + P256_UNCOMPRESSED_PUBLIC_KEY_LENGTH;
/// The P-256 HPKE encapsulated-key length.
pub(crate) const CLASSIC_ENCAPSULATED_KEY_LENGTH: usize = p256_hpke::UNCOMPRESSED_PUBLIC_KEY_LENGTH;
/// The ML-KEM-768 + P-256 HPKE encapsulated-key length.
pub(crate) const HYBRID_ENCAPSULATED_KEY_LENGTH: usize = 1088 + P256_UNCOMPRESSED_PUBLIC_KEY_LENGTH;
/// The wrapped age file-key ciphertext length.
pub(crate) const TAGGED_CIPHERTEXT_LENGTH: usize = 32;

type P256Kem = p256_hpke::Kem;
type P256PublicKey = p256_hpke::PublicKey;
type HybridKem = MlKem768P256;
type HybridPublicKey = <HybridKem as KemTrait>::PublicKey;

/// Parses and canonicalizes a compressed P-256 tagged public key.
pub(crate) fn classic_public_key_from_bytes(
    bytes: &[u8],
) -> Result<[u8; CLASSIC_PUBLIC_KEY_LENGTH]> {
    if bytes.len() != CLASSIC_PUBLIC_KEY_LENGTH {
        return Err(AgeError::InvalidKey("invalid age tagged public key"));
    }
    let public_key = p256_hpke::public_key_from_compressed(bytes)
        .map_err(|_| AgeError::InvalidKey("invalid age tagged public key"))?;
    p256_hpke::public_key_to_compressed(&public_key)
        .map_err(|_| AgeError::InvalidKey("invalid age tagged public key"))
}

/// Parses and canonicalizes a concatenated ML-KEM-768 + P-256 public key.
pub(crate) fn hybrid_public_key_from_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() != HYBRID_PUBLIC_KEY_LENGTH {
        return Err(AgeError::InvalidKey("invalid age tagged hybrid public key"));
    }
    let public_key = HybridPublicKey::from_bytes(bytes)
        .map_err(|_| AgeError::InvalidKey("invalid age tagged hybrid public key"))?;
    let canonical = public_key.to_bytes();
    Ok(canonical.as_slice().to_vec())
}

/// Returns the P-256 portion used for the hybrid recipient's tag.
fn hybrid_tag_recipient(public_key: &[u8]) -> Result<&[u8]> {
    let p256 = public_key
        .get(MLKEM768_PUBLIC_KEY_LENGTH..)
        .ok_or(AgeError::InvalidKey("invalid age tagged hybrid public key"))?;
    if p256.len() != P256_UNCOMPRESSED_PUBLIC_KEY_LENGTH {
        return Err(AgeError::InvalidKey("invalid age tagged hybrid public key"));
    }
    Ok(p256)
}

/// Computes the four-byte age tag for a tagged recipient.
fn compute_tag(
    encapsulated_key: &[u8],
    recipient_material: &[u8],
    label: &[u8],
    expected_encapsulated_key_length: usize,
) -> Result<[u8; 4]> {
    if encapsulated_key.len() != expected_encapsulated_key_length {
        return Err(AgeError::InvalidFormat(
            "invalid tagged recipient encapsulated key",
        ));
    }

    let recipient_hash = Sha256::digest(recipient_material);
    let mut tag_input = Vec::with_capacity(encapsulated_key.len() + 4);
    tag_input.extend_from_slice(encapsulated_key);
    tag_input.extend_from_slice(&recipient_hash[..4]);

    // This is HKDF-Extract, not HKDF-Expand: age uses the first four bytes
    // of the pseudorandom key directly as the tag.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(label), &tag_input);
    prk[..4]
        .try_into()
        .map_err(|_| AgeError::Crypto("tagged recipient tag length"))
}

/// Computes the classic tagged recipient's four-byte tag.
pub(crate) fn classic_tag(
    public_key: &[u8; CLASSIC_PUBLIC_KEY_LENGTH],
    encapsulated_key: &[u8],
) -> Result<[u8; 4]> {
    compute_tag(
        encapsulated_key,
        public_key,
        CLASSIC_LABEL,
        CLASSIC_ENCAPSULATED_KEY_LENGTH,
    )
}

/// Computes the hybrid tagged recipient's four-byte tag.
pub(crate) fn hybrid_tag(public_key: &[u8], encapsulated_key: &[u8]) -> Result<[u8; 4]> {
    compute_tag(
        encapsulated_key,
        hybrid_tag_recipient(public_key)?,
        HYBRID_LABEL,
        HYBRID_ENCAPSULATED_KEY_LENGTH,
    )
}

fn wrap_with_kem<K: KemTrait>(
    public_key: &K::PublicKey,
    file_key: &[u8],
    stanza_type: &str,
    label: &[u8],
    tag_recipient: &[u8],
    expected_encapsulated_key_length: usize,
) -> Result<Stanza> {
    if file_key.len() != crate::crypto::FILE_KEY_LENGTH {
        return Err(AgeError::InvalidKey("age file keys are 16 bytes"));
    }

    let (encapsulated_key, body) = p256_hpke::seal::<K>(public_key, label, file_key)
        .map_err(|_| AgeError::Crypto("tagged recipient HPKE encryption"))?;
    if body.len() != TAGGED_CIPHERTEXT_LENGTH {
        return Err(AgeError::Crypto("tagged recipient ciphertext length"));
    }
    let tag = compute_tag(
        &encapsulated_key,
        tag_recipient,
        label,
        expected_encapsulated_key_length,
    )?;
    Ok(Stanza::new(
        stanza_type,
        [encode_raw(&tag), encode_raw(&encapsulated_key)],
        body,
    ))
}

/// Wraps a file key for a classic tagged P-256 recipient.
pub(crate) fn wrap_classic(
    public_key: &[u8; CLASSIC_PUBLIC_KEY_LENGTH],
    file_key: &[u8],
) -> Result<Stanza> {
    let hpke_public_key: P256PublicKey = p256_hpke::public_key_from_compressed(public_key)
        .map_err(|_| AgeError::InvalidKey("invalid age tagged public key"))?;
    wrap_with_kem::<P256Kem>(
        &hpke_public_key,
        file_key,
        CLASSIC_STANZA_TYPE,
        CLASSIC_LABEL,
        public_key,
        CLASSIC_ENCAPSULATED_KEY_LENGTH,
    )
}

/// Wraps a file key for a hybrid tagged ML-KEM-768 + P-256 recipient.
pub(crate) fn wrap_hybrid(public_key: &[u8], file_key: &[u8]) -> Result<Stanza> {
    let hpke_public_key = HybridPublicKey::from_bytes(public_key)
        .map_err(|_| AgeError::InvalidKey("invalid age tagged hybrid public key"))?;
    let tag_recipient = hybrid_tag_recipient(public_key)?;
    wrap_with_kem::<HybridKem>(
        &hpke_public_key,
        file_key,
        HYBRID_STANZA_TYPE,
        HYBRID_LABEL,
        tag_recipient,
        HYBRID_ENCAPSULATED_KEY_LENGTH,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CLASSIC_ENCAPSULATED_KEY_LENGTH, CLASSIC_PUBLIC_KEY_LENGTH, HYBRID_ENCAPSULATED_KEY_LENGTH,
        classic_tag, hybrid_tag,
    };
    use crate::{AgeRecipient, POSTQUANTUM_LABEL, codec::decode_raw, p256_hpke};
    use hpke::{Kem as KemTrait, Serializable, kem::DhP256HkdfSha256};

    fn classic_public_key() -> [u8; CLASSIC_PUBLIC_KEY_LENGTH] {
        let (private_key, public_key) = <DhP256HkdfSha256 as KemTrait>::gen_keypair();
        let compressed = p256_hpke::public_key_to_compressed(&public_key)
            .expect("HPKE public key should compress");
        // Keep the generated private key alive until the public key has been
        // derived; the recipient itself never needs it.
        drop(private_key);
        compressed
    }

    fn hybrid_public_key() -> Vec<u8> {
        let (private_key, public_key) = <super::MlKem768P256 as KemTrait>::gen_keypair();
        let bytes = public_key.to_bytes();
        let result = bytes.as_slice().to_vec();
        drop(private_key);
        result
    }

    #[test]
    fn classic_encoding_and_stanza_are_canonical() {
        let fixture = "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e";
        let fixture_recipient = AgeRecipient::from_public_key(fixture).expect("fixture recipient");
        assert_eq!(
            fixture_recipient.to_public_key().expect("fixture key"),
            fixture
        );
        let (_, fixture_bytes) = crate::bech32::decode(fixture).expect("fixture payload");
        let fixture_public_key: [u8; CLASSIC_PUBLIC_KEY_LENGTH] = fixture_bytes
            .as_slice()
            .try_into()
            .expect("fixture key length");
        assert_eq!(
            classic_tag(&fixture_public_key, &[0u8; 65]).expect("fixture tag"),
            [0x2e, 0x38, 0xce, 0x25]
        );

        let public_key = classic_public_key();
        let recipient = AgeRecipient::from_p256_tag_public_key_bytes(public_key)
            .expect("classic tagged recipient");
        let encoded = recipient.to_public_key().expect("public key");
        assert!(encoded.starts_with("age1tag1"));
        assert_eq!(
            AgeRecipient::from_public_key(&encoded)
                .expect("round trip")
                .to_public_key()
                .expect("round-trip key"),
            encoded
        );

        let stanza = recipient.wrap(&[0x42; 16]).expect("wrap");
        assert_eq!(stanza.r#type, "p256tag");
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(stanza.body.len(), 32);
        let tag = decode_raw(&stanza.args[0]).expect("tag");
        let enc = decode_raw(&stanza.args[1]).expect("encapsulated key");
        assert_eq!(tag.len(), 4);
        assert_eq!(enc.len(), CLASSIC_ENCAPSULATED_KEY_LENGTH);
        assert_eq!(tag, classic_tag(&public_key, &enc).expect("tag"));
        assert_eq!(recipient.tag(&enc).expect("public tag"), tag);
    }

    #[test]
    fn hybrid_encoding_and_stanza_are_canonical() {
        let public_key = hybrid_public_key();
        let recipient = AgeRecipient::from_tagged_hybrid_public_key_bytes(&public_key)
            .expect("hybrid tagged recipient");
        let encoded = recipient.to_public_key().expect("public key");
        assert!(encoded.starts_with("age1tagpq1"));
        assert_eq!(
            AgeRecipient::from_public_key(&encoded)
                .expect("round trip")
                .to_public_key()
                .expect("round-trip key"),
            encoded
        );

        let stanza = recipient.wrap(&[0x24; 16]).expect("wrap");
        assert_eq!(stanza.r#type, "mlkem768p256tag");
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(stanza.body.len(), 32);
        let tag = decode_raw(&stanza.args[0]).expect("tag");
        let enc = decode_raw(&stanza.args[1]).expect("encapsulated key");
        assert_eq!(tag.len(), 4);
        assert_eq!(enc.len(), HYBRID_ENCAPSULATED_KEY_LENGTH);
        assert_eq!(tag, hybrid_tag(&public_key, &enc).expect("tag"));
        assert_eq!(recipient.tag(&enc).expect("public tag"), tag);
    }

    #[test]
    fn public_key_constructors_reject_wrong_lengths_and_formats() {
        assert!(AgeRecipient::from_p256_tag_public_key_bytes([0u8; 32]).is_err());
        assert!(AgeRecipient::from_p256_tag_public_key_bytes([0u8; 33]).is_err());
        assert!(AgeRecipient::from_tagged_hybrid_public_key_bytes(vec![0u8; 1248]).is_err());
        assert!(AgeRecipient::from_public_key("age1tag1invalid").is_err());
        assert!(AgeRecipient::from_public_key("age1tagpq1invalid").is_err());
    }

    #[test]
    fn labels_keep_hybrid_tagged_recipients_separate() {
        let classic = AgeRecipient::from_p256_tag_public_key_bytes(classic_public_key())
            .expect("classic tagged recipient");
        let hybrid = AgeRecipient::from_tagged_hybrid_public_key_bytes(hybrid_public_key())
            .expect("hybrid tagged recipient");
        assert!(classic.labels().is_empty());
        assert_eq!(hybrid.labels(), &[POSTQUANTUM_LABEL]);
        assert!(!classic.compatible_with(&hybrid));
        assert!(hybrid.compatible_with(&hybrid.clone()));
        assert_eq!(hybrid.kind(), "mlkem768p256tag");

        let x25519 = AgeRecipient::from_x25519_bytes([7u8; 32]);
        assert!(AgeRecipient::validate_labels(&[classic, x25519.clone()]).is_ok());
        assert!(AgeRecipient::validate_labels(&[hybrid, x25519]).is_err());
    }
}
