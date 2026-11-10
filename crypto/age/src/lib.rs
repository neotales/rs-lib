#![allow(
    clippy::doc_markdown,
    reason = "algorithm and format names in this crate are proper nouns"
)]

//! A Rust implementation of the age v1 file format.
//!
//! The crate supports native X25519 and post-quantum ML-KEM-768 + X25519
//! hybrid keys, encryption-only tagged P-256 and ML-KEM-768 + P-256
//! recipients, scrypt passphrases, and SSH Ed25519 and RSA keys. It implements
//! the binary STREAM payload and strict ASCII armor directly; it does not wrap
//! another age implementation.

// The readme is this crate's front page on the registry, so its examples are
// included here and compiled as doctests. An example in a readme that nothing
// checks is an example that is wrong within a release.
#![doc = include_str!("../README.md")]

pub mod bech32;
mod codec;
mod crypto;
mod curve25519;
mod error;
mod file;
mod header;
mod identity;
mod openssh_bcrypt;
mod options;
mod p256_hpke;
mod parse;
mod plugin;
mod pq;
mod recipient;
mod ssh;
pub mod streaming;
mod tagged;
mod traits;

#[cfg(test)]
mod pq_tests;
#[cfg(test)]
mod tests;

pub use codec::{AgeArmor, maximum_armored_characters};
pub use error::{AgeError, AgeException, Error, Result};
pub use file::{
    AgeFile, decrypt, decrypt_armored, decrypt_armored_with_options, encrypt, encrypt_armored,
};

/// Encrypts bytes using dynamic recipient implementations such as plugins.
///
/// # Errors
///
/// Returns an [`AgeError`] when recipients are missing, incompatible, or
/// cryptographic operations fail.
pub fn encrypt_with_recipients(
    plaintext: &[u8],
    recipients: &[Box<dyn Recipient>],
) -> Result<Vec<u8>> {
    AgeFile::encrypt_with_recipients(plaintext, recipients)
}

/// Decrypts bytes using dynamic identity implementations such as plugins.
///
/// # Errors
///
/// Returns an [`AgeError`] for malformed input, no matching identity, or
/// authentication failure.
pub fn decrypt_with_identities(
    ciphertext: &[u8],
    identities: &[Box<dyn Identity>],
) -> Result<Vec<u8>> {
    AgeFile::decrypt_with_identities(ciphertext, identities)
}
pub use header::Stanza;
pub use identity::AgeIdentity;
pub use options::AgeReadOptions;
pub use parse::{parse_identities, parse_recipients};
// The callback aliases are re-exported rather than narrowed. Each one is the
// declared type of a `pub` field on [`ClientUi`] or a `pub fn` parameter on
// [`Plugin`], both of which are exported below. A caller that constructs a
// `ClientUi` or passes a factory to `Plugin::handle_recipient` has to name the
// type it is building, and `pub(crate)` would leave a public field whose type
// the public API cannot spell. rustdoc already renders these names in the
// signatures it publishes; exporting them makes the documentation and the
// visibility agree. `tests/plugin_surface.rs` reaches every one of them through
// the public path so a future removal fails to compile rather than silently
// narrowing the surface again.
pub use plugin::{
    ClientUi, Confirm, DisplayMessage, IdentityFactory, Plugin, PluginContext, PluginIdentity,
    PluginRecipient, RecipientFactory, RequestValue, WaitTimer, encode_identity, encode_recipient,
    parse_identity as parse_plugin_identity, parse_recipient as parse_plugin_recipient,
    valid_plugin_name,
};
pub use recipient::{
    AgeRecipient, DEFAULT_MAX_SCRYPT_WORK_FACTOR, DEFAULT_SCRYPT_WORK_FACTOR,
    MAX_SCRYPT_WORK_FACTOR, MIN_SCRYPT_WORK_FACTOR, POSTQUANTUM_LABEL, validate_work_factor,
};
pub use ssh::{SshEd25519Key, SshEd25519PublicKey, SshRsaKey, SshRsaPublicKey};
pub use streaming::{
    AgeDecryptReader, AgeDecryptReaderAt, AgeEncryptReader, AgeEncryptWriter, AgeReaderAt,
    AgeSliceReaderAt, ReaderAt, decrypt_reader, decrypt_reader_at, decrypt_reader_at_slice,
    decrypt_reader_at_slice_with_options, decrypt_reader_at_with_options, encrypt_reader,
    encrypt_writer,
};
pub use traits::{Identity, Recipient};

use zeroize::Zeroizing;

use crate::crypto::{random_array, x25519_base};

/// A generated native age key pair in its two Bech32 encodings.
///
/// [`AgeKey::generate`] creates an X25519 key. [`AgeKey::generate_hybrid`]
/// creates a post-quantum ML-KEM-768 + X25519 key.
#[derive(Clone, Eq, PartialEq)]
pub struct AgeKey {
    /// The native age Bech32 public key.
    pub public_key: String,
    /// The native age Bech32 secret key.
    pub private_key: String,
}

impl std::fmt::Debug for AgeKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeKey")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl AgeKey {
    /// Generates a fresh X25519 key pair.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Random`] when operating-system entropy is
    /// unavailable, or [`AgeError`] if Bech32 encoding fails.
    pub fn generate() -> Result<Self> {
        let secret = Zeroizing::new(random_array::<32>()?);
        let public = Zeroizing::new(x25519_base(&secret));
        let public_key = bech32::encode("age", &public[..])?;
        let private_key = bech32::encode("age-secret-key-", &secret[..])?.to_ascii_uppercase();
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Generates a fresh post-quantum ML-KEM-768 + X25519 key pair.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Random`] when operating-system entropy is
    /// unavailable, or [`AgeError`] if key encoding fails.
    pub fn generate_hybrid() -> Result<Self> {
        let identity = AgeIdentity::generate_hybrid()?;
        Ok(Self {
            public_key: identity.recipient()?.to_public_key()?,
            private_key: identity.to_private_key()?,
        })
    }

    /// Alias for [`AgeKey::generate_hybrid`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeKey::generate_hybrid`].
    pub fn generate_pq() -> Result<Self> {
        Self::generate_hybrid()
    }

    /// Alias for [`AgeKey::generate_hybrid`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeKey::generate_hybrid`].
    pub fn generate_post_quantum() -> Result<Self> {
        Self::generate_hybrid()
    }

    /// Alias for [`AgeKey::generate`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeKey::generate`].
    pub fn create() -> Result<Self> {
        Self::generate()
    }

    /// Alias for [`AgeKey::generate`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeKey::generate`].
    pub fn new() -> Result<Self> {
        Self::generate()
    }

    /// Creates a key pair from already encoded strings without validating
    /// them. Parsing the corresponding recipient and identity is still
    /// required before use.
    #[must_use]
    pub fn from_encoded(public_key: impl Into<String>, private_key: impl Into<String>) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }

    /// Returns the encoded public key.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Returns the encoded private key.
    #[must_use]
    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

/// Generates a native age X25519 identity.
///
/// # Errors
///
/// Returns [`AgeError::Random`] when operating-system entropy is unavailable.
pub fn generate_x25519_identity() -> Result<AgeIdentity> {
    let secret = Zeroizing::new(random_array::<32>()?);
    Ok(AgeIdentity::from_x25519_bytes(*secret))
}

/// Generates a post-quantum ML-KEM-768 + X25519 identity.
///
/// # Errors
///
/// Returns [`AgeError::Random`] when operating-system entropy is unavailable.
pub fn generate_hybrid_identity() -> Result<AgeIdentity> {
    AgeIdentity::generate_hybrid()
}

/// Alias for [`generate_hybrid_identity`].
///
/// # Errors
///
/// Returns the same errors as [`generate_hybrid_identity`].
pub fn generate_pq_identity() -> Result<AgeIdentity> {
    generate_hybrid_identity()
}

/// Alias for [`generate_hybrid_identity`].
///
/// # Errors
///
/// Returns the same errors as [`generate_hybrid_identity`].
pub fn generate_post_quantum_identity() -> Result<AgeIdentity> {
    generate_hybrid_identity()
}
