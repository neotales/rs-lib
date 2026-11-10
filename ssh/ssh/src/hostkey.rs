//! Ed25519 host-key blobs, signing, signature verification, and trust decisions.
//!
//! This module implements the `ssh-ed25519` wire formats defined by RFC 8709.
//! Cryptographic signature verification and application trust policy are kept
//! separate: [`verify_host_key_signature`] proves possession of a private key,
//! while [`verify_and_trust_host_key`] additionally requires an explicit
//! application callback before returning a [`VerifiedHostKey`].

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use neotales_ssh::{Error as WireError, Reader, Writer};
use zeroize::Zeroize;

/// The only host-key and signature algorithm supported by this module.
pub const SSH_ED25519: &str = "ssh-ed25519";

/// The length of an Ed25519 seed accepted by [`Ed25519Signer::from_seed`].
pub const ED25519_SEED_LENGTH: usize = 32;

/// The length of a compressed Ed25519 public point.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// A safe, non-sensitive error produced by the host-key boundary.
///
/// Error values never contain seeds, key points, signatures, exchange hashes,
/// callback errors, panic payloads, or attacker-controlled algorithm names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyError {
    /// An RFC 4251 primitive was malformed, truncated, or oversized.
    Wire(WireError),
    /// A host-key or signature algorithm was not `ssh-ed25519`.
    UnsupportedAlgorithm,
    /// A public-point or signature field did not have its exact required length.
    InvalidFieldLength,
    /// A host-key or signature blob contained bytes after its defined fields.
    TrailingData,
    /// A 32-byte value was not a usable compressed Ed25519 public point.
    InvalidPublicKey,
    /// A 64-byte signature was malformed or did not authenticate the exchange hash.
    InvalidSignature,
    /// The local Ed25519 signing operation failed.
    SigningFailed,
    /// The application trust callback explicitly rejected the verified key.
    TrustRejected,
    /// The application trust callback panicked.
    VerifierPanicked,
}

impl fmt::Display for HostKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wire(error) => return write!(formatter, "SSH host-key wire error: {error}"),
            Self::UnsupportedAlgorithm => "SSH host-key algorithm is unsupported",
            Self::InvalidFieldLength => "SSH host-key field has an invalid length",
            Self::TrailingData => "SSH host-key blob contains trailing data",
            Self::InvalidPublicKey => "SSH Ed25519 public key is invalid",
            Self::InvalidSignature => "SSH Ed25519 signature is invalid",
            Self::SigningFailed => "SSH Ed25519 signing failed",
            Self::TrustRejected => "SSH host key was rejected by application trust policy",
            Self::VerifierPanicked => "SSH host-key trust callback panicked",
        })
    }
}

impl std::error::Error for HostKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for HostKeyError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Checks a negotiated host-key algorithm name.
///
/// Only the exact `ssh-ed25519` spelling is accepted by SSH-006.
///
/// # Errors
///
/// Returns [`HostKeyError::UnsupportedAlgorithm`] for every other name.
pub fn check_host_key_algorithm(algorithm: &str) -> Result<(), HostKeyError> {
    if algorithm == SSH_ED25519 {
        Ok(())
    } else {
        Err(HostKeyError::UnsupportedAlgorithm)
    }
}

/// A validated Ed25519 public point with its `ssh-ed25519` wire format.
///
/// The type validates both the 32-byte compressed point and weak/small-order
/// points when it is constructed. It does not by itself express application
/// trust in the key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Ed25519PublicKey {
    /// Validates a raw 32-byte compressed Ed25519 point.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::InvalidPublicKey`] when the point cannot be
    /// decompressed or is weak/small-order.
    pub fn from_point(point: &[u8; ED25519_PUBLIC_KEY_LENGTH]) -> Result<Self, HostKeyError> {
        let key = VerifyingKey::from_bytes(point).map_err(|_| HostKeyError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(HostKeyError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    /// Decodes a complete `string "ssh-ed25519" || string point` public-key blob.
    ///
    /// The algorithm and point length are exact, the point is validated, and
    /// every trailing byte is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::Wire`] for truncated or oversized SSH strings,
    /// [`HostKeyError::UnsupportedAlgorithm`] for another algorithm,
    /// [`HostKeyError::InvalidFieldLength`] for a point that is not 32 bytes,
    /// [`HostKeyError::TrailingData`] for extra bytes, and
    /// [`HostKeyError::InvalidPublicKey`] for an invalid or weak point.
    pub fn from_blob(blob: &[u8]) -> Result<Self, HostKeyError> {
        let mut reader = Reader::new(blob);
        let algorithm = reader.read_string()?;
        if algorithm != SSH_ED25519.as_bytes() {
            return Err(HostKeyError::UnsupportedAlgorithm);
        }

        let point = reader.read_string()?;
        if point.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(HostKeyError::InvalidFieldLength);
        }
        if !reader.is_empty() {
            return Err(HostKeyError::TrailingData);
        }

        let point = point
            .try_into()
            .map_err(|_| HostKeyError::InvalidFieldLength)?;
        Self::from_point(&point)
    }

    /// Returns the algorithm used by this public key.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ED25519
    }

    /// Returns the validated compressed public point.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Encodes the complete SSH public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::Wire`] if the fixed-size value unexpectedly
    /// cannot be represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, HostKeyError> {
        encode_blob(self.as_bytes())
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519PublicKey")
            .field("algorithm", &Self::algorithm())
            .field("point", self.as_bytes())
            .finish()
    }
}

/// A reusable Ed25519 host signer created from a caller-supplied seed.
///
/// The signer never exposes or serializes its secret key. Its debug output is
/// redacted, and the upstream signing key is wiped on drop. Construction also
/// wipes the caller-provided working seed buffer after the upstream copy is
/// initialized.
pub struct Ed25519Signer {
    signing_key: SigningKey,
    public_key: Ed25519PublicKey,
}

impl Ed25519Signer {
    /// Creates a signer from a mutable 32-byte Ed25519 seed.
    ///
    /// The seed is copied into the upstream zeroizing signing key and is then
    /// overwritten in `seed` before this function returns. Callers that need
    /// to retain the seed must make their own protected copy first.
    #[must_use]
    pub fn from_seed(seed: &mut [u8; ED25519_SEED_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        seed.zeroize();

        let public_key = Ed25519PublicKey(signing_key.verifying_key());
        Self {
            signing_key,
            public_key,
        }
    }

    /// Returns the algorithm supported by this signer.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ED25519
    }

    /// Returns the public key corresponding to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Encodes the signer's public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::Wire`] if the fixed-size value unexpectedly
    /// cannot be represented by the SSH wire encoder.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, HostKeyError> {
        self.public_key.to_blob()
    }

    /// Signs raw exchange-hash bytes and returns a complete SSH signature blob.
    ///
    /// Ed25519 applies its internal SHA-512 operation to `exchange_hash`; this
    /// function does not wrap the hash in another SSH string. Signatures are
    /// deterministic for a fixed seed and message.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::SigningFailed`] if the upstream signer fails, or
    /// [`HostKeyError::Wire`] if the fixed-size signature cannot be encoded.
    pub fn sign_exchange_hash(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, HostKeyError> {
        let signature = self
            .signing_key
            .try_sign(exchange_hash)
            .map_err(|_| HostKeyError::SigningFailed)?;
        let signature = signature.to_bytes();
        encode_blob(&signature)
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519Signer")
            .field("algorithm", &Self::algorithm())
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Cryptographically verifies an SSH signature blob over raw exchange-hash bytes.
///
/// This function checks the public key supplied by the caller; it does **not**
/// establish application trust and never returns a [`VerifiedHostKey`]. Client
/// transports must use [`verify_and_trust_host_key`] with an explicit callback.
///
/// # Errors
///
/// Returns [`HostKeyError::UnsupportedAlgorithm`] for a wrong signature
/// algorithm, [`HostKeyError::InvalidFieldLength`] unless the detached
/// signature is exactly 64 bytes, [`HostKeyError::TrailingData`] for extra
/// bytes, and [`HostKeyError::InvalidSignature`] for malformed or incorrect
/// signatures. A bare 64-byte signature is therefore rejected.
pub fn verify_host_key_signature(
    public_key: &Ed25519PublicKey,
    signature_blob: &[u8],
    exchange_hash: &[u8],
) -> Result<(), HostKeyError> {
    let signature = decode_signature_blob(signature_blob)?;
    public_key
        .0
        .verify_strict(exchange_hash, &signature)
        .map_err(|_| HostKeyError::InvalidSignature)
}

/// Verifies a host-key signature and requires an explicit application trust decision.
///
/// Cryptographic verification always completes before `trust_callback` is
/// called. The callback receives the validated public key. `Ok(())` accepts the
/// key, any `Err` value rejects it, and a callback panic is contained and
/// returned as [`HostKeyError::VerifierPanicked`]. There is no optional
/// callback and no default accepting policy.
///
/// # Errors
///
/// Returns any malformed-blob, algorithm, public-key, or signature error from
/// strict verification; [`HostKeyError::TrustRejected`] when the callback
/// returns `Err`; or [`HostKeyError::VerifierPanicked`] when it panics.
pub fn verify_and_trust_host_key<F, E>(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    trust_callback: F,
) -> Result<VerifiedHostKey, HostKeyError>
where
    F: FnOnce(&Ed25519PublicKey) -> Result<(), E>,
{
    let public_key = Ed25519PublicKey::from_blob(host_key_blob)?;
    verify_host_key_signature(&public_key, signature_blob, exchange_hash)?;

    match catch_unwind(AssertUnwindSafe(|| trust_callback(&public_key))) {
        Ok(Ok(())) => Ok(VerifiedHostKey(public_key)),
        Ok(Err(_callback_error)) => Err(HostKeyError::TrustRejected),
        Err(_panic_payload) => Err(HostKeyError::VerifierPanicked),
    }
}

/// Proof that a host key passed both cryptographic verification and application trust policy.
///
/// Values of this type can only be produced by [`verify_and_trust_host_key`].
/// The type has no `Default` implementation and no public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedHostKey(Ed25519PublicKey);

impl VerifiedHostKey {
    /// Returns the cryptographically verified and application-trusted public key.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.0
    }

    /// Encodes the trusted public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError::Wire`] if the fixed-size value unexpectedly
    /// cannot be represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, HostKeyError> {
        self.0.to_blob()
    }
}

fn encode_blob(bytes: &[u8]) -> Result<Vec<u8>, HostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(SSH_ED25519)?;
    writer.write_string(&bytes)?;
    Ok(writer.into_bytes())
}

fn decode_signature_blob(blob: &[u8]) -> Result<Signature, HostKeyError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != SSH_ED25519.as_bytes() {
        return Err(HostKeyError::UnsupportedAlgorithm);
    }

    let signature = reader.read_string()?;
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(HostKeyError::InvalidFieldLength);
    }
    if !reader.is_empty() {
        return Err(HostKeyError::TrailingData);
    }

    let signature = signature
        .try_into()
        .map_err(|_| HostKeyError::InvalidFieldLength)?;
    Ok(Signature::from_bytes(&signature))
}
