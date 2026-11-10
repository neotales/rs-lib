//! Small cryptographic adapters shared by the age recipient types.

use std::fmt::Write as _;

use {
    chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    },
    hkdf::Hkdf,
    hmac::{Hmac, Mac},
    rsa::{
        self, Oaep, RsaPrivateKey, RsaPublicKey,
        rand_core::OsRng,
        traits::{PrivateKeyParts, PublicKeyParts},
    },
    sad_rsa::{self, BoxedUint, Oaep as HardenedOaep, rand_core::UnwrapErr},
    sha2::{Digest, Sha256},
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroizing,
};

use crate::error::{AgeError, Result};

pub(crate) const FILE_KEY_LENGTH: usize = 16;
pub(crate) const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";
pub(crate) const SSH_ED25519_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";
pub(crate) const SSH_RSA_LABEL: &[u8] = b"age-encryption.org/v1/ssh-rsa";
pub(crate) const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";

/// Fills a byte array with operating-system entropy.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0u8; N];
    getrandom::fill(&mut value).map_err(|_| AgeError::Random)?;
    Ok(value)
}

/// Derives 32 bytes with HKDF-SHA-256.
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| AgeError::Crypto("HKDF output length"))?;
    Ok(*output)
}

/// Computes HMAC-SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| AgeError::Crypto("HMAC key length"))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_slice());
    Ok(output)
}

/// Verifies HMAC-SHA-256 in constant time.
pub(crate) fn verify_hmac_sha256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// Encrypts a small value with the age zero nonce and empty AAD.
pub(crate) fn aead_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let nonce = Nonce::try_from(&[0u8; 12][..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 encryption"))
}

/// Decrypts a small value with the age zero nonce and empty AAD.
pub(crate) fn aead_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let nonce = Nonce::try_from(&[0u8; 12][..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| AgeError::AuthenticationFailed)
}

/// Computes the X25519 public share for a scalar.
pub(crate) fn x25519_base(secret: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    PublicKey::from(&secret).to_bytes()
}

/// Computes an X25519 shared secret and rejects the all-zero result.
pub(crate) fn x25519_shared(secret: &[u8; 32], point: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let secret = StaticSecret::from(*secret);
    let public = PublicKey::from(*point);
    let shared = secret.diffie_hellman(&public).to_bytes();
    if shared.iter().all(|value| *value == 0) {
        return None;
    }
    Some(Zeroizing::new(shared))
}

/// Derives a 32-byte scrypt key with age's label and parameters.
pub(crate) fn derive_scrypt_key(
    password: &[u8],
    salt: &[u8],
    work_factor: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    if !(1..=30).contains(&work_factor) || salt.len() != 16 {
        return Err(AgeError::InvalidWorkFactor);
    }
    let mut labeled_salt = Zeroizing::new(Vec::with_capacity(SCRYPT_LABEL.len() + salt.len()));
    labeled_salt.extend_from_slice(SCRYPT_LABEL);
    labeled_salt.extend_from_slice(salt);
    let log_n = u8::try_from(work_factor).map_err(|_| AgeError::InvalidWorkFactor)?;
    let parameters = scrypt::Params::new(log_n, 8, 1).map_err(|_| AgeError::InvalidWorkFactor)?;
    let mut output = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password, &labeled_salt, &parameters, output.as_mut_slice())
        .map_err(|_| AgeError::Crypto("scrypt derivation"))?;
    Ok(output)
}

/// Computes the four-byte SSH age fingerprint for a wire public key.
pub(crate) fn ssh_fingerprint(wire_key: &[u8]) -> String {
    let digest = Sha256::digest(wire_key);
    let mut short = [0u8; 4];
    if let Some(source) = digest.get(..short.len()) {
        short.copy_from_slice(source);
    }
    crate::codec::encode_raw(&short)
}

/// Computes a short fingerprint of public key material, for diagnostics.
///
/// A `Debug` rendering of a key has to let a caller holding the wrong key tell
/// which one they have, and it has to do that without the private half. This is
/// the first eight bytes of the SHA-256 of the public key, hex-encoded: sixteen
/// characters, no more entropy than a caller can compare by eye, and nothing in
/// it that the public key does not already publish.
pub(crate) fn public_key_fingerprint(public_key: &[u8]) -> String {
    const FINGERPRINT_BYTES: usize = 8;

    let digest = Sha256::digest(public_key);
    let mut output = String::with_capacity(FINGERPRINT_BYTES * 2);
    for byte in digest.iter().take(FINGERPRINT_BYTES) {
        // `write!` into the existing buffer rather than `push_str(&format!)`,
        // which allocates a throwaway `String` per byte.
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

/// Encrypts with RSA-OAEP-SHA-256 and the age SSH RSA label.
pub(crate) fn rsa_oaep_encrypt(key: &RsaPublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let label =
        std::str::from_utf8(SSH_RSA_LABEL).map_err(|_| AgeError::Crypto("RSA OAEP label"))?;
    let padding = Oaep::new_with_label::<rsa::sha2::Sha256, _>(label);
    key.encrypt(&mut OsRng, padding, message)
        .map_err(|_| AgeError::Crypto("RSA OAEP encryption"))
}

fn boxed_uint(bytes: &[u8], bits: usize) -> Result<BoxedUint> {
    let bits = u32::try_from(bits).map_err(|_| AgeError::AuthenticationFailed)?;
    BoxedUint::from_be_slice(bytes, bits).map_err(|_| AgeError::AuthenticationFailed)
}

fn boxed_secret(value: &rsa::BigUint) -> Result<BoxedUint> {
    let bytes = Zeroizing::new(value.to_bytes_be());
    boxed_uint(bytes.as_slice(), value.bits())
}

fn hardened_rsa_private_key(key: &RsaPrivateKey) -> Result<sad_rsa::RsaPrivateKey> {
    let n = boxed_uint(key.n().to_bytes_be().as_slice(), key.n().bits())?;
    let e = boxed_uint(key.e().to_bytes_be().as_slice(), key.e().bits())?;
    let d = boxed_secret(key.d())?;
    let primes = key
        .primes()
        .iter()
        .map(boxed_secret)
        .collect::<Result<Vec<_>>>()?;
    sad_rsa::RsaPrivateKey::from_components(n, e, d, primes)
        .map_err(|_| AgeError::AuthenticationFailed)
}

/// Decrypts with RSA-OAEP-SHA-256 and the age SSH RSA label.
///
/// The age-facing key type remains the existing `rsa` 0.9 type for API
/// compatibility. Private operations are converted to the maintained,
/// Marvin-hardened `sad-rsa` implementation and always use its blinded
/// decrypt path; no raw or variable-time private modular exponentiation is
/// performed here.
pub(crate) fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() != key.size() {
        return Err(AgeError::AuthenticationFailed);
    }
    let private_key = hardened_rsa_private_key(key)?;
    let padding = HardenedOaep::<Sha256>::new_with_label(SSH_RSA_LABEL.to_vec());
    let mut rng = UnwrapErr(getrandom_v04::SysRng);
    private_key
        .decrypt_blinded(&mut rng, padding, ciphertext)
        .map_err(|_| AgeError::AuthenticationFailed)
}
