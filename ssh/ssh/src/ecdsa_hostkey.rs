//! RFC 5656 ECDSA host-key blobs for the NIST P-256, P-384, and P-521 curves.
//!
//! This module implements `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, and
//! `ecdsa-sha2-nistp521` public-key blobs, signers, and verifiers.  Curve
//! arithmetic comes from the direct `p256`, `p384`, and `p521` dependencies.
//!
//! Cryptographic verification and application trust are separate operations:
//! [`verify_host_key_signature`] proves possession of a P-256 private key,
//! while the P-384 and P-521 verification functions provide the equivalent
//! operation for their curves.  The corresponding trust functions always
//! require an explicit callback before returning a verified key.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
    signature::hazmat::{
        PrehashSigner as P384PrehashSigner, PrehashVerifier as P384PrehashVerifier,
    },
};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
    signature::hazmat::{
        PrehashSigner as P521PrehashSigner, PrehashVerifier as P521PrehashVerifier,
    },
};
use sha2::Digest;
use zeroize::Zeroize;

use neotales_ssh::{Error as WireError, Reader, Writer};

/// The SSH host-key and signature algorithm for the NIST P-256 curve.
pub const SSH_ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";

/// The SSH host-key and signature algorithm for the NIST P-384 curve.
pub const SSH_ECDSA_SHA2_NISTP384: &str = "ecdsa-sha2-nistp384";

/// The SSH host-key and signature algorithm for the NIST P-521 curve.
pub const SSH_ECDSA_SHA2_NISTP521: &str = "ecdsa-sha2-nistp521";

/// The SSH curve name for the NIST P-256 curve.
pub const ECDSA_CURVE_NISTP256: &str = "nistp256";

/// The SSH curve name for the NIST P-384 curve.
pub const ECDSA_CURVE_NISTP384: &str = "nistp384";

/// The SSH curve name for the NIST P-521 curve.
pub const ECDSA_CURVE_NISTP521: &str = "nistp521";

/// The length of a P-256 private scalar in bytes.
pub const ECDSA_SECRET_SCALAR_LENGTH: usize = 32;

/// The length of a P-384 private scalar in bytes.
pub const ECDSA_P384_SECRET_SCALAR_LENGTH: usize = 48;

/// The length of a P-521 private scalar in bytes.
pub const ECDSA_P521_SECRET_SCALAR_LENGTH: usize = 66;

/// The length of an uncompressed SEC1 NIST P-256 point in bytes.
pub const ECDSA_PUBLIC_KEY_LENGTH: usize = 65;

/// The length of an uncompressed SEC1 NIST P-384 point in bytes.
pub const ECDSA_P384_PUBLIC_KEY_LENGTH: usize = 97;

/// The length of an uncompressed SEC1 NIST P-521 point in bytes.
pub const ECDSA_P521_PUBLIC_KEY_LENGTH: usize = 133;

/// The length of one P-256 ECDSA signature component in bytes.
pub const ECDSA_SIGNATURE_COMPONENT_LENGTH: usize = 32;

/// The length of one P-384 ECDSA signature component in bytes.
pub const ECDSA_P384_SIGNATURE_COMPONENT_LENGTH: usize = 48;

/// The length of one P-521 ECDSA signature component in bytes.
pub const ECDSA_P521_SIGNATURE_COMPONENT_LENGTH: usize = 66;

/// The length of a bare P-256 ECDSA `r || s` value in bytes.
///
/// A bare value of this length is not an SSH signature blob and is rejected by
/// [`verify_host_key_signature`].
pub const ECDSA_SIGNATURE_LENGTH: usize = ECDSA_SIGNATURE_COMPONENT_LENGTH * 2;

/// The length of a bare P-384 ECDSA `r || s` value in bytes.
///
/// A bare value of this length is not an SSH signature blob and is rejected by
/// [`verify_p384_host_key_signature`].
pub const ECDSA_P384_SIGNATURE_LENGTH: usize = ECDSA_P384_SIGNATURE_COMPONENT_LENGTH * 2;

/// The length of a bare P-521 ECDSA `r || s` value in bytes.
///
/// A bare value of this length is not an SSH signature blob and is rejected by
/// [`verify_p521_host_key_signature`].
pub const ECDSA_P521_SIGNATURE_LENGTH: usize = ECDSA_P521_SIGNATURE_COMPONENT_LENGTH * 2;

/// The required first byte of an uncompressed SEC1 elliptic-curve point.
pub const ECDSA_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// The short, unprefixed P-256 algorithm spelling used by SSH implementations.
pub const ECDSA_SHA2_NISTP256: &str = SSH_ECDSA_SHA2_NISTP256;

/// The short, unprefixed P-384 algorithm spelling used by SSH implementations.
pub const ECDSA_SHA2_NISTP384: &str = SSH_ECDSA_SHA2_NISTP384;

/// The short, unprefixed P-521 algorithm spelling used by SSH implementations.
pub const ECDSA_SHA2_NISTP521: &str = SSH_ECDSA_SHA2_NISTP521;

/// The short P-256 curve-name spelling used by SSH implementations.
pub const NISTP256: &str = ECDSA_CURVE_NISTP256;

/// The short P-384 curve-name spelling used by SSH implementations.
pub const NISTP384: &str = ECDSA_CURVE_NISTP384;

/// The short P-521 curve-name spelling used by SSH implementations.
pub const NISTP521: &str = ECDSA_CURVE_NISTP521;

/// An alias for [`ECDSA_CURVE_NISTP256`].
pub const CURVE_NISTP256: &str = ECDSA_CURVE_NISTP256;

/// An alias for [`ECDSA_CURVE_NISTP384`].
pub const CURVE_NISTP384: &str = ECDSA_CURVE_NISTP384;

/// An alias for [`ECDSA_CURVE_NISTP521`].
pub const CURVE_NISTP521: &str = ECDSA_CURVE_NISTP521;

/// A safe, non-sensitive error produced by the ECDSA host-key boundary.
///
/// Error values never contain secret scalars, public points, signatures,
/// exchange-hash bytes, callback errors, or attacker-controlled algorithm and
/// curve names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaHostKeyError {
    /// An RFC 4251 primitive was malformed, truncated, or oversized.
    Wire(WireError),
    /// A host-key or signature algorithm was not one of the supported ECDSA
    /// SHA-2 NIST algorithms.
    UnsupportedAlgorithm,
    /// A public-key curve name was not one of the supported NIST curves.
    UnsupportedCurve,
    /// A public-point or signature field did not have its required length.
    InvalidFieldLength,
    /// A host-key or signature blob contained bytes after its defined fields.
    TrailingData,
    /// An ECDSA public point was malformed or was not a usable SEC1 point.
    InvalidPublicKey,
    /// An ECDSA private scalar was zero or outside the group order.
    InvalidSecretKey,
    /// The host-key entropy source failed or produced no usable scalar.
    EntropyFailure,
    /// The nested mpint signature was malformed or did not authenticate the hash.
    InvalidSignature,
    /// The local ECDSA signing operation failed.
    SigningFailed,
    /// The application trust callback explicitly rejected the verified key.
    TrustRejected,
    /// The application trust callback panicked.
    VerifierPanicked,
}

impl fmt::Display for EcdsaHostKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wire(error) => {
                return write!(formatter, "SSH ECDSA host-key wire error: {error}");
            }
            Self::UnsupportedAlgorithm => "SSH ECDSA host-key algorithm is unsupported",
            Self::UnsupportedCurve => "SSH ECDSA host-key curve is unsupported",
            Self::InvalidFieldLength => "SSH ECDSA host-key field has an invalid length",
            Self::TrailingData => "SSH ECDSA host-key blob contains trailing data",
            Self::InvalidPublicKey => "SSH ECDSA public key is invalid",
            Self::InvalidSecretKey => "SSH ECDSA private scalar is invalid",
            Self::EntropyFailure => "SSH ECDSA entropy source failed",
            Self::InvalidSignature => "SSH ECDSA signature is invalid",
            Self::SigningFailed => "SSH ECDSA signing failed",
            Self::TrustRejected => "SSH ECDSA host key was rejected by application trust policy",
            Self::VerifierPanicked => "SSH ECDSA host-key trust callback panicked",
        })
    }
}

impl std::error::Error for EcdsaHostKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for EcdsaHostKeyError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Checks a negotiated ECDSA host-key algorithm name.
///
/// The exact `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, and
/// `ecdsa-sha2-nistp521` spellings are accepted.
///
/// # Errors
///
/// Returns [`EcdsaHostKeyError::UnsupportedAlgorithm`] for every other name.
pub fn check_host_key_algorithm(algorithm: &str) -> Result<(), EcdsaHostKeyError> {
    if matches!(
        algorithm,
        SSH_ECDSA_SHA2_NISTP256 | SSH_ECDSA_SHA2_NISTP521 | SSH_ECDSA_SHA2_NISTP384
    ) {
        Ok(())
    } else {
        Err(EcdsaHostKeyError::UnsupportedAlgorithm)
    }
}

/// Checks an ECDSA host-key curve name.
///
/// The exact `nistp256`, `nistp384`, and `nistp521` spellings are accepted.
///
/// # Errors
///
/// Returns [`EcdsaHostKeyError::UnsupportedCurve`] for every other name.
pub fn check_curve_name(curve_name: &str) -> Result<(), EcdsaHostKeyError> {
    if matches!(
        curve_name,
        ECDSA_CURVE_NISTP256 | ECDSA_CURVE_NISTP384 | ECDSA_CURVE_NISTP521
    ) {
        Ok(())
    } else {
        Err(EcdsaHostKeyError::UnsupportedCurve)
    }
}

/// A validated NIST P-256 public point with its SSH wire format.
///
/// The type validates the algorithm, curve name, exact uncompressed SEC1
/// representation, and curve membership when it is constructed.  It does not
/// by itself express application trust in the key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EcdsaPublicKey {
    verifying_key: VerifyingKey,
    point: [u8; ECDSA_PUBLIC_KEY_LENGTH],
}

impl EcdsaPublicKey {
    /// Validates a 65-byte uncompressed SEC1 NIST P-256 point.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidPublicKey`] when the point does not
    /// have the uncompressed tag or is not a valid non-identity curve point.
    pub fn from_point(point: &[u8; ECDSA_PUBLIC_KEY_LENGTH]) -> Result<Self, EcdsaHostKeyError> {
        if point.first() != Some(&ECDSA_UNCOMPRESSED_POINT_TAG) {
            return Err(EcdsaHostKeyError::InvalidPublicKey);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(point)
            .map_err(|_error| EcdsaHostKeyError::InvalidPublicKey)?;
        Self::from_verifying_key(&verifying_key)
    }

    /// Decodes a complete `ecdsa-sha2-nistp256` public-key blob.
    ///
    /// The blob is `string algorithm || string curve name || string point`.
    /// The point must be exactly 65 bytes and use the uncompressed SEC1 form.
    /// Every trailing byte is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] for truncated or oversized SSH
    /// strings, [`EcdsaHostKeyError::UnsupportedAlgorithm`] for another
    /// algorithm, [`EcdsaHostKeyError::UnsupportedCurve`] for another curve,
    /// [`EcdsaHostKeyError::InvalidFieldLength`] for a point of the wrong size,
    /// [`EcdsaHostKeyError::TrailingData`] for extra bytes, and
    /// [`EcdsaHostKeyError::InvalidPublicKey`] for an invalid point.
    pub fn from_blob(blob: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let mut reader = Reader::new(blob);
        let algorithm = reader.read_string()?;
        if algorithm != SSH_ECDSA_SHA2_NISTP256.as_bytes() {
            return Err(EcdsaHostKeyError::UnsupportedAlgorithm);
        }

        let curve_name = reader.read_string()?;
        if curve_name != ECDSA_CURVE_NISTP256.as_bytes() {
            return Err(EcdsaHostKeyError::UnsupportedCurve);
        }

        let point = reader.read_string()?;
        if point.len() != ECDSA_PUBLIC_KEY_LENGTH {
            return Err(EcdsaHostKeyError::InvalidFieldLength);
        }
        if !reader.is_empty() {
            return Err(EcdsaHostKeyError::TrailingData);
        }

        let point = point
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidFieldLength)?;
        Self::from_point(&point)
    }

    /// Returns the algorithm used by this public key.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP256
    }

    /// Returns the curve name used by this public key.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP256
    }

    /// Returns the validated uncompressed SEC1 public point.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ECDSA_PUBLIC_KEY_LENGTH] {
        &self.point
    }

    /// Encodes the complete SSH public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let mut writer = Writer::with_capacity(
            4 + SSH_ECDSA_SHA2_NISTP256.len()
                + 4
                + ECDSA_CURVE_NISTP256.len()
                + 4
                + ECDSA_PUBLIC_KEY_LENGTH,
        );
        writer.write_string(SSH_ECDSA_SHA2_NISTP256)?;
        writer.write_string(ECDSA_CURVE_NISTP256)?;
        writer.write_string(self.as_bytes().as_slice())?;
        Ok(writer.into_bytes())
    }

    fn from_verifying_key(verifying_key: &VerifyingKey) -> Result<Self, EcdsaHostKeyError> {
        let encoded = verifying_key.to_sec1_point(false);
        let point = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidPublicKey)?;
        Ok(Self {
            verifying_key: *verifying_key,
            point,
        })
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaPublicKey")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("point", &self.point)
            .finish_non_exhaustive()
    }
}

/// A reusable NIST P-256 ECDSA host signer.
///
/// The signer never exposes its secret scalar.  Its debug and display output
/// are redacted, and the upstream signing key is wiped when it is dropped.
/// Construction also wipes the caller-provided working scalar buffer.
pub struct EcdsaSigner {
    signing_key: SigningKey,
    public_key: EcdsaPublicKey,
}

impl EcdsaSigner {
    /// Creates a signer from a mutable 32-byte P-256 private scalar.
    ///
    /// The scalar is copied into the upstream zeroizing signing key and is
    /// overwritten in `secret` before this function returns, whether the input
    /// is valid or not.  Callers that need to retain the scalar must make their
    /// own protected copy first.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-256 group order.
    pub fn from_secret_scalar(
        secret: &mut [u8; ECDSA_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let signing_key_result = SigningKey::from_slice(secret.as_slice());
        secret.zeroize();
        let signing_key =
            signing_key_result.map_err(|_error| EcdsaHostKeyError::InvalidSecretKey)?;
        let public_key = EcdsaPublicKey::from_verifying_key(signing_key.verifying_key())?;
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    /// Creates a signer from a borrowed 32-byte private scalar.
    ///
    /// This copies the scalar into a temporary buffer, which is wiped during
    /// construction.  The caller's buffer is not modified.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-256 group order.
    pub fn from_secret_scalar_bytes(
        secret: &[u8; ECDSA_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let mut working_copy = *secret;
        Self::from_secret_scalar(&mut working_copy)
    }

    /// Creates a signer from a private scalar supplied by value.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-256 group order.
    pub fn from_private_bytes(
        mut secret: [u8; ECDSA_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        Self::from_secret_scalar(&mut secret)
    }

    /// Creates a signer from a scalar slice of exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] for a wrong-length or
    /// out-of-range scalar.
    pub fn from_slice(secret: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let mut secret = secret
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidSecretKey)?;
        Self::from_secret_scalar(&mut secret)
    }

    /// Generates a fresh P-256 signer from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::EntropyFailure`] if entropy is unavailable
    /// or the bounded rejection loop cannot produce a valid scalar.
    pub fn generate() -> Result<Self, EcdsaHostKeyError> {
        const MAX_GENERATION_ATTEMPTS: usize = 128;
        for _ in 0..MAX_GENERATION_ATTEMPTS {
            let mut secret = [0_u8; ECDSA_SECRET_SCALAR_LENGTH];
            if getrandom::fill(&mut secret).is_err() {
                secret.zeroize();
                return Err(EcdsaHostKeyError::EntropyFailure);
            }
            if let Ok(signer) = Self::from_secret_scalar(&mut secret) {
                return Ok(signer);
            }
        }
        Err(EcdsaHostKeyError::EntropyFailure)
    }

    /// Returns the algorithm supported by this signer.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP256
    }

    /// Returns the curve name supported by this signer.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP256
    }

    /// Returns the public key corresponding to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaPublicKey {
        &self.public_key
    }

    /// Encodes the signer's public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.public_key.to_blob()
    }

    /// Signs raw exchange-hash bytes and returns a complete SSH signature blob.
    ///
    /// P-256 ECDSA uses SHA-256 on the supplied exchange-hash bytes.  The
    /// digest is passed to the upstream RFC 6979 prehash signer; the bytes are
    /// not wrapped in another SSH string before hashing or signing.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::SigningFailed`] if the upstream signer
    /// fails, or [`EcdsaHostKeyError::Wire`] if the nested signature cannot be
    /// encoded.
    pub fn sign_exchange_hash(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let digest = sha2::Sha256::digest(exchange_hash);
        let signature: Signature = PrehashSigner::sign_prehash(&self.signing_key, &digest)
            .map_err(|_error| EcdsaHostKeyError::SigningFailed)?;
        let (r, s) = signature.split_bytes();

        let mut signature_body =
            Writer::with_capacity(2 * (4 + ECDSA_SIGNATURE_COMPONENT_LENGTH + 1));
        write_positive_mpint(&mut signature_body, r.as_slice())?;
        write_positive_mpint(&mut signature_body, s.as_slice())?;

        let mut writer =
            Writer::with_capacity(4 + SSH_ECDSA_SHA2_NISTP256.len() + 4 + signature_body.len());
        writer.write_string(SSH_ECDSA_SHA2_NISTP256)?;
        writer.write_string(signature_body.as_slice())?;
        Ok(writer.into_bytes())
    }
}

impl fmt::Debug for EcdsaSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaSigner")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EcdsaSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EcdsaSigner({}, {})",
            Self::algorithm(),
            Self::curve_name()
        )
    }
}

/// Cryptographically verifies an SSH ECDSA signature over raw exchange-hash bytes.
///
/// This function checks the public key supplied by the caller; it does not
/// establish application trust and never returns a [`VerifiedEcdsaHostKey`].
/// The signature must contain nested canonical mpints, not a bare `r || s`
/// value or an ASN.1 DER signature.
///
/// # Errors
///
/// Returns [`EcdsaHostKeyError::UnsupportedAlgorithm`] for a wrong signature
/// algorithm, [`EcdsaHostKeyError::InvalidFieldLength`] for a bare or
/// incorrectly sized detached value, [`EcdsaHostKeyError::TrailingData`] for
/// extra bytes, and [`EcdsaHostKeyError::InvalidSignature`] for malformed or
/// incorrect signatures.  Wire errors from malformed SSH framing are returned
/// as [`EcdsaHostKeyError::Wire`].
pub fn verify_host_key_signature(
    public_key: &EcdsaPublicKey,
    signature_blob: &[u8],
    exchange_hash: &[u8],
) -> Result<(), EcdsaHostKeyError> {
    let signature = decode_signature_blob(signature_blob)?;
    let digest = sha2::Sha256::digest(exchange_hash);
    PrehashVerifier::verify_prehash(&public_key.verifying_key, &digest, &signature)
        .map_err(|_error| EcdsaHostKeyError::InvalidSignature)
}

/// Verifies a host-key signature and requires an explicit application trust decision.
///
/// Cryptographic verification always completes before `trust_callback` is
/// called.  The callback receives the validated public key.  `Ok(())` accepts
/// the key, any `Err` value rejects it, and a callback panic is contained and
/// returned as [`EcdsaHostKeyError::VerifierPanicked`].  There is no optional
/// callback and no default accepting policy.
///
/// # Errors
///
/// Returns any malformed-blob, algorithm, public-key, or signature error from
/// strict verification; [`EcdsaHostKeyError::TrustRejected`] when the callback
/// returns `Err`; or [`EcdsaHostKeyError::VerifierPanicked`] when it panics.
pub fn verify_and_trust_host_key<F, E>(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    trust_callback: F,
) -> Result<VerifiedEcdsaHostKey, EcdsaHostKeyError>
where
    F: FnOnce(&EcdsaPublicKey) -> Result<(), E>,
{
    let public_key = EcdsaPublicKey::from_blob(host_key_blob)?;
    verify_host_key_signature(&public_key, signature_blob, exchange_hash)?;

    match catch_unwind(AssertUnwindSafe(|| trust_callback(&public_key))) {
        Ok(Ok(())) => Ok(VerifiedEcdsaHostKey(public_key)),
        Ok(Err(_callback_error)) => Err(EcdsaHostKeyError::TrustRejected),
        Err(_panic_payload) => Err(EcdsaHostKeyError::VerifierPanicked),
    }
}

/// Proof that a host key passed both cryptographic verification and application trust policy.
///
/// Values of this type can only be produced by [`verify_and_trust_host_key`].
/// The type has no `Default` implementation and no public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEcdsaHostKey(EcdsaPublicKey);

impl VerifiedEcdsaHostKey {
    /// Returns the cryptographically verified and application-trusted public key.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaPublicKey {
        &self.0
    }

    /// Encodes the trusted public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.0.to_blob()
    }
}

/// A compatibility name for [`EcdsaHostKeyError`].
pub type HostKeyError = EcdsaHostKeyError;

/// A compatibility name for [`EcdsaPublicKey`].
pub type P256PublicKey = EcdsaPublicKey;

/// A compatibility name for [`EcdsaSigner`].
pub type P256Signer = EcdsaSigner;

/// A compatibility name for [`VerifiedEcdsaHostKey`].
pub type VerifiedHostKey = VerifiedEcdsaHostKey;

/// A compatibility name for [`EcdsaHostKeyError`].
pub type P256HostKeyError = EcdsaHostKeyError;

/// A compatibility name for [`VerifiedEcdsaHostKey`].
pub type VerifiedP256HostKey = VerifiedEcdsaHostKey;

fn decode_signature_blob(blob: &[u8]) -> Result<Signature, EcdsaHostKeyError> {
    if blob.len() == ECDSA_SIGNATURE_LENGTH {
        return Err(EcdsaHostKeyError::InvalidFieldLength);
    }

    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != SSH_ECDSA_SHA2_NISTP256.as_bytes() {
        return Err(EcdsaHostKeyError::UnsupportedAlgorithm);
    }

    let signature_body = reader.read_string()?;
    if !reader.is_empty() {
        return Err(EcdsaHostKeyError::TrailingData);
    }

    let mut signature_reader = Reader::new(signature_body);
    let r = read_positive_scalar(&mut signature_reader)?;
    let s = read_positive_scalar(&mut signature_reader)?;
    if !signature_reader.is_empty() {
        return Err(EcdsaHostKeyError::TrailingData);
    }

    Signature::from_scalars(r, s).map_err(|_error| EcdsaHostKeyError::InvalidSignature)
}

fn write_positive_mpint(writer: &mut Writer, scalar: &[u8]) -> Result<(), WireError> {
    let mut value = Vec::with_capacity(ECDSA_SIGNATURE_COMPONENT_LENGTH + 1);
    if scalar.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(scalar);
    writer.write_mpint(value.as_slice())?;
    Ok(())
}

fn read_positive_scalar<const N: usize>(
    reader: &mut Reader<'_>,
) -> Result<[u8; N], EcdsaHostKeyError> {
    let encoded = reader.read_mpint()?;
    let Some(first) = encoded.first().copied() else {
        return Err(EcdsaHostKeyError::InvalidSignature);
    };
    if first & 0x80 != 0 {
        return Err(EcdsaHostKeyError::InvalidSignature);
    }

    let magnitude = if encoded.len() == N + 1 && encoded.first() == Some(&0) {
        encoded
            .get(1..)
            .ok_or(EcdsaHostKeyError::InvalidSignature)?
    } else {
        encoded
    };
    if magnitude.is_empty() || magnitude.len() > N {
        return Err(EcdsaHostKeyError::InvalidSignature);
    }

    let mut scalar = [0_u8; N];
    let offset = N
        .checked_sub(magnitude.len())
        .ok_or(EcdsaHostKeyError::InvalidSignature)?;
    let destination = scalar
        .get_mut(offset..)
        .ok_or(EcdsaHostKeyError::InvalidSignature)?;
    destination.copy_from_slice(magnitude);
    Ok(scalar)
}

/// A validated NIST P-384 public point with its SSH wire format.
///
/// The type validates the algorithm, curve name, exact 97-byte uncompressed
/// SEC1 representation, and curve membership when it is constructed.  It does
/// not by itself express application trust in the key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EcdsaP384PublicKey {
    verifying_key: P384VerifyingKey,
    point: [u8; ECDSA_P384_PUBLIC_KEY_LENGTH],
}

impl EcdsaP384PublicKey {
    /// Validates a 97-byte uncompressed SEC1 NIST P-384 point.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidPublicKey`] when the point does not
    /// have the uncompressed tag or is not a valid non-identity curve point.
    pub fn from_point(
        point: &[u8; ECDSA_P384_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        if point.first() != Some(&ECDSA_UNCOMPRESSED_POINT_TAG) {
            return Err(EcdsaHostKeyError::InvalidPublicKey);
        }
        let verifying_key = P384VerifyingKey::from_sec1_bytes(point)
            .map_err(|_error| EcdsaHostKeyError::InvalidPublicKey)?;
        Self::from_verifying_key(&verifying_key)
    }

    /// Decodes a complete `ecdsa-sha2-nistp384` public-key blob.
    ///
    /// The blob is `string algorithm || string curve name || string point`.
    /// The point must be exactly 97 bytes and use the uncompressed SEC1 form.
    /// Every trailing byte is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] for truncated or oversized SSH
    /// strings, [`EcdsaHostKeyError::UnsupportedAlgorithm`] for another
    /// algorithm, [`EcdsaHostKeyError::UnsupportedCurve`] for another curve,
    /// [`EcdsaHostKeyError::InvalidFieldLength`] for a point of the wrong size,
    /// [`EcdsaHostKeyError::TrailingData`] for extra bytes, and
    /// [`EcdsaHostKeyError::InvalidPublicKey`] for an invalid point.
    pub fn from_blob(blob: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let point = decode_public_key_blob::<ECDSA_P384_PUBLIC_KEY_LENGTH>(
            blob,
            SSH_ECDSA_SHA2_NISTP384,
            ECDSA_CURVE_NISTP384,
        )?;
        Self::from_point(&point)
    }

    /// Returns the algorithm used by this public key.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP384
    }

    /// Returns the curve name used by this public key.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP384
    }

    /// Returns the validated uncompressed SEC1 public point.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ECDSA_P384_PUBLIC_KEY_LENGTH] {
        &self.point
    }

    /// Encodes the complete SSH public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let mut writer = Writer::with_capacity(
            4 + SSH_ECDSA_SHA2_NISTP384.len()
                + 4
                + ECDSA_CURVE_NISTP384.len()
                + 4
                + ECDSA_P384_PUBLIC_KEY_LENGTH,
        );
        writer.write_string(SSH_ECDSA_SHA2_NISTP384)?;
        writer.write_string(ECDSA_CURVE_NISTP384)?;
        writer.write_string(self.as_bytes().as_slice())?;
        Ok(writer.into_bytes())
    }

    fn from_verifying_key(verifying_key: &P384VerifyingKey) -> Result<Self, EcdsaHostKeyError> {
        let encoded = verifying_key.to_sec1_point(false);
        let point = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidPublicKey)?;
        Ok(Self {
            verifying_key: *verifying_key,
            point,
        })
    }
}

impl fmt::Debug for EcdsaP384PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaP384PublicKey")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("point", &self.point)
            .finish_non_exhaustive()
    }
}

/// A reusable NIST P-384 ECDSA host signer.
///
/// The signer never exposes its secret scalar.  Its debug and display output
/// are redacted, and the upstream signing key is wiped when it is dropped.
/// Construction also wipes the caller-provided working scalar buffer.
pub struct EcdsaP384Signer {
    signing_key: P384SigningKey,
    public_key: EcdsaP384PublicKey,
}

impl EcdsaP384Signer {
    /// Creates a signer from a mutable 48-byte P-384 private scalar.
    ///
    /// The scalar is copied into the upstream zeroizing signing key and is
    /// overwritten in `secret` before this function returns, whether the input
    /// is valid or not.  Callers that need to retain the scalar must make their
    /// own protected copy first.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-384 group order.
    pub fn from_secret_scalar(
        secret: &mut [u8; ECDSA_P384_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let signing_key_result = P384SigningKey::from_slice(secret.as_slice());
        secret.zeroize();
        let signing_key =
            signing_key_result.map_err(|_error| EcdsaHostKeyError::InvalidSecretKey)?;
        let public_key = EcdsaP384PublicKey::from_verifying_key(signing_key.verifying_key())?;
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    /// Creates a signer from a borrowed 48-byte private scalar.
    ///
    /// This copies the scalar into a temporary buffer, which is wiped during
    /// construction.  The caller's buffer is not modified.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-384 group order.
    pub fn from_secret_scalar_bytes(
        secret: &[u8; ECDSA_P384_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let mut working_copy = *secret;
        Self::from_secret_scalar(&mut working_copy)
    }

    /// Creates a signer from a private scalar supplied by value.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-384 group order.
    pub fn from_private_bytes(
        mut secret: [u8; ECDSA_P384_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        Self::from_secret_scalar(&mut secret)
    }

    /// Creates a signer from a scalar slice of exactly 48 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] for a wrong-length or
    /// out-of-range scalar.
    pub fn from_slice(secret: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let mut secret = secret
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidSecretKey)?;
        Self::from_secret_scalar(&mut secret)
    }

    /// Generates a fresh P-384 signer from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::EntropyFailure`] if entropy is unavailable
    /// or the bounded rejection loop cannot produce a valid scalar.
    pub fn generate() -> Result<Self, EcdsaHostKeyError> {
        const MAX_GENERATION_ATTEMPTS: usize = 128;
        for _ in 0..MAX_GENERATION_ATTEMPTS {
            let mut secret = [0_u8; ECDSA_P384_SECRET_SCALAR_LENGTH];
            if getrandom::fill(&mut secret).is_err() {
                secret.zeroize();
                return Err(EcdsaHostKeyError::EntropyFailure);
            }
            if let Ok(signer) = Self::from_secret_scalar(&mut secret) {
                return Ok(signer);
            }
        }
        Err(EcdsaHostKeyError::EntropyFailure)
    }

    /// Returns the algorithm supported by this signer.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP384
    }

    /// Returns the curve name supported by this signer.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP384
    }

    /// Returns the public key corresponding to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaP384PublicKey {
        &self.public_key
    }

    /// Encodes the signer's public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.public_key.to_blob()
    }

    /// Signs raw exchange-hash bytes and returns a complete SSH signature blob.
    ///
    /// P-384 ECDSA hashes the supplied exchange-hash bytes with SHA-384 before
    /// invoking the upstream RFC 6979 prehash signer.  The bytes are not
    /// wrapped in another SSH string before hashing or signing.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::SigningFailed`] if the upstream signer
    /// fails, or [`EcdsaHostKeyError::Wire`] if the nested signature cannot be
    /// encoded.
    pub fn sign_exchange_hash(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let digest = sha2::Sha384::digest(exchange_hash);
        let signature: P384Signature = P384PrehashSigner::sign_prehash(&self.signing_key, &digest)
            .map_err(|_error| EcdsaHostKeyError::SigningFailed)?;
        let (r, s) = signature.split_bytes();
        encode_signature_blob(
            SSH_ECDSA_SHA2_NISTP384,
            r.as_slice(),
            s.as_slice(),
            ECDSA_P384_SIGNATURE_COMPONENT_LENGTH,
        )
    }
}

impl fmt::Debug for EcdsaP384Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaP384Signer")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EcdsaP384Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EcdsaP384Signer({}, {})",
            Self::algorithm(),
            Self::curve_name()
        )
    }
}

/// Cryptographically verifies an SSH P-384 signature over raw exchange-hash bytes.
///
/// This function checks the public key supplied by the caller; it does not
/// establish application trust and never returns a verified host-key proof.
/// The signature must contain nested canonical mpints, not a bare `r || s`
/// value or an ASN.1 DER signature.
///
/// # Errors
///
/// Returns [`EcdsaHostKeyError::UnsupportedAlgorithm`] for a wrong signature
/// algorithm, [`EcdsaHostKeyError::InvalidFieldLength`] for a bare or
/// incorrectly sized detached value, [`EcdsaHostKeyError::TrailingData`] for
/// extra bytes, and [`EcdsaHostKeyError::InvalidSignature`] for malformed or
/// incorrect signatures.  Wire errors from malformed SSH framing are returned
/// as [`EcdsaHostKeyError::Wire`].
pub fn verify_p384_host_key_signature(
    public_key: &EcdsaP384PublicKey,
    signature_blob: &[u8],
    exchange_hash: &[u8],
) -> Result<(), EcdsaHostKeyError> {
    let (r, s) = decode_signature_components::<ECDSA_P384_SIGNATURE_COMPONENT_LENGTH>(
        signature_blob,
        SSH_ECDSA_SHA2_NISTP384,
    )?;
    let signature =
        P384Signature::from_scalars(r, s).map_err(|_error| EcdsaHostKeyError::InvalidSignature)?;
    let digest = sha2::Sha384::digest(exchange_hash);
    P384PrehashVerifier::verify_prehash(&public_key.verifying_key, &digest, &signature)
        .map_err(|_error| EcdsaHostKeyError::InvalidSignature)
}

/// Verifies a P-384 host-key signature and requires application trust.
///
/// Cryptographic verification always completes before `trust_callback` is
/// called.  The callback receives the validated public key.  `Ok(())` accepts
/// the key, any `Err` value rejects it, and a callback panic is contained and
/// returned as [`EcdsaHostKeyError::VerifierPanicked`].  There is no optional
/// callback and no default accepting policy.
///
/// # Errors
///
/// Returns any malformed-blob, algorithm, public-key, or signature error from
/// strict verification; [`EcdsaHostKeyError::TrustRejected`] when the callback
/// returns `Err`; or [`EcdsaHostKeyError::VerifierPanicked`] when it panics.
pub fn verify_and_trust_p384_host_key<F, E>(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    trust_callback: F,
) -> Result<VerifiedEcdsaP384HostKey, EcdsaHostKeyError>
where
    F: FnOnce(&EcdsaP384PublicKey) -> Result<(), E>,
{
    let public_key = EcdsaP384PublicKey::from_blob(host_key_blob)?;
    verify_p384_host_key_signature(&public_key, signature_blob, exchange_hash)?;

    match catch_unwind(AssertUnwindSafe(|| trust_callback(&public_key))) {
        Ok(Ok(())) => Ok(VerifiedEcdsaP384HostKey(public_key)),
        Ok(Err(_callback_error)) => Err(EcdsaHostKeyError::TrustRejected),
        Err(_panic_payload) => Err(EcdsaHostKeyError::VerifierPanicked),
    }
}

/// Proof that a P-384 host key passed cryptographic verification and trust policy.
///
/// Values of this type can only be produced by
/// [`verify_and_trust_p384_host_key`].  The type has no `Default` implementation
/// and no public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEcdsaP384HostKey(EcdsaP384PublicKey);

impl VerifiedEcdsaP384HostKey {
    /// Returns the cryptographically verified and application-trusted key.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaP384PublicKey {
        &self.0
    }

    /// Encodes the trusted public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.0.to_blob()
    }
}

/// A compatibility name for [`EcdsaP384PublicKey`].
pub type P384PublicKey = EcdsaP384PublicKey;

/// A compatibility name for [`EcdsaP384Signer`].
pub type P384Signer = EcdsaP384Signer;

/// A compatibility name for [`VerifiedEcdsaP384HostKey`].
pub type VerifiedP384HostKey = VerifiedEcdsaP384HostKey;

/// A compatibility name for [`EcdsaHostKeyError`] used by P-384 APIs.
pub type P384HostKeyError = EcdsaHostKeyError;

/// A validated NIST P-521 public point with its SSH wire format.
///
/// The type validates the algorithm, curve name, exact 133-byte uncompressed
/// SEC1 representation, and curve membership when it is constructed.  It does
/// not by itself express application trust in the key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EcdsaP521PublicKey {
    verifying_key: P521VerifyingKey,
    point: [u8; ECDSA_P521_PUBLIC_KEY_LENGTH],
}

impl EcdsaP521PublicKey {
    /// Validates a 133-byte uncompressed SEC1 NIST P-521 point.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidPublicKey`] when the point does not
    /// have the uncompressed tag or is not a valid non-identity curve point.
    pub fn from_point(
        point: &[u8; ECDSA_P521_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        if point.first() != Some(&ECDSA_UNCOMPRESSED_POINT_TAG) {
            return Err(EcdsaHostKeyError::InvalidPublicKey);
        }
        let verifying_key = P521VerifyingKey::from_sec1_bytes(point)
            .map_err(|_error| EcdsaHostKeyError::InvalidPublicKey)?;
        Self::from_verifying_key(&verifying_key)
    }

    /// Decodes a complete `ecdsa-sha2-nistp521` public-key blob.
    ///
    /// The blob is `string algorithm || string curve name || string point`.
    /// The point must be exactly 133 bytes and use the uncompressed SEC1 form.
    /// Every trailing byte is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] for truncated or oversized SSH
    /// strings, [`EcdsaHostKeyError::UnsupportedAlgorithm`] for another
    /// algorithm, [`EcdsaHostKeyError::UnsupportedCurve`] for another curve,
    /// [`EcdsaHostKeyError::InvalidFieldLength`] for a point of the wrong size,
    /// [`EcdsaHostKeyError::TrailingData`] for extra bytes, and
    /// [`EcdsaHostKeyError::InvalidPublicKey`] for an invalid point.
    pub fn from_blob(blob: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let point = decode_public_key_blob::<ECDSA_P521_PUBLIC_KEY_LENGTH>(
            blob,
            SSH_ECDSA_SHA2_NISTP521,
            ECDSA_CURVE_NISTP521,
        )?;
        Self::from_point(&point)
    }

    /// Returns the algorithm used by this public key.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP521
    }

    /// Returns the curve name used by this public key.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP521
    }

    /// Returns the validated uncompressed SEC1 public point.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ECDSA_P521_PUBLIC_KEY_LENGTH] {
        &self.point
    }

    /// Encodes the complete SSH public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let mut writer = Writer::with_capacity(
            4 + SSH_ECDSA_SHA2_NISTP521.len()
                + 4
                + ECDSA_CURVE_NISTP521.len()
                + 4
                + ECDSA_P521_PUBLIC_KEY_LENGTH,
        );
        writer.write_string(SSH_ECDSA_SHA2_NISTP521)?;
        writer.write_string(ECDSA_CURVE_NISTP521)?;
        writer.write_string(self.as_bytes().as_slice())?;
        Ok(writer.into_bytes())
    }

    fn from_verifying_key(verifying_key: &P521VerifyingKey) -> Result<Self, EcdsaHostKeyError> {
        let encoded = verifying_key.to_sec1_point(false);
        let point = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidPublicKey)?;
        Ok(Self {
            verifying_key: *verifying_key,
            point,
        })
    }
}

impl fmt::Debug for EcdsaP521PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaP521PublicKey")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("point", &self.point)
            .finish_non_exhaustive()
    }
}

/// A reusable NIST P-521 ECDSA host signer.
///
/// The signer never exposes its secret scalar.  Its debug and display output
/// are redacted, and the upstream signing key is wiped when it is dropped.
/// Construction also wipes the caller-provided working scalar buffer.
pub struct EcdsaP521Signer {
    signing_key: P521SigningKey,
    public_key: EcdsaP521PublicKey,
}

impl EcdsaP521Signer {
    /// Creates a signer from a mutable 66-byte P-521 private scalar.
    ///
    /// The scalar is copied into the upstream zeroizing signing key and is
    /// overwritten in `secret` before this function returns, whether the input
    /// is valid or not.  Callers that need to retain the scalar must make their
    /// own protected copy first.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-521 group order.
    pub fn from_secret_scalar(
        secret: &mut [u8; ECDSA_P521_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let signing_key_result = P521SigningKey::from_slice(secret.as_slice());
        secret.zeroize();
        let signing_key =
            signing_key_result.map_err(|_error| EcdsaHostKeyError::InvalidSecretKey)?;
        let public_key = EcdsaP521PublicKey::from_verifying_key(signing_key.verifying_key())?;
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    /// Creates a signer from a borrowed 66-byte private scalar.
    ///
    /// This copies the scalar into a temporary buffer, which is wiped during
    /// construction.  The caller's buffer is not modified.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-521 group order.
    pub fn from_secret_scalar_bytes(
        secret: &[u8; ECDSA_P521_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        let mut working_copy = *secret;
        Self::from_secret_scalar(&mut working_copy)
    }

    /// Creates a signer from a private scalar supplied by value.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] when the scalar is zero
    /// or is not below the P-521 group order.
    pub fn from_private_bytes(
        mut secret: [u8; ECDSA_P521_SECRET_SCALAR_LENGTH],
    ) -> Result<Self, EcdsaHostKeyError> {
        Self::from_secret_scalar(&mut secret)
    }

    /// Creates a signer from a scalar slice of exactly 66 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::InvalidSecretKey`] for a wrong-length or
    /// out-of-range scalar.
    pub fn from_slice(secret: &[u8]) -> Result<Self, EcdsaHostKeyError> {
        let mut secret = secret
            .try_into()
            .map_err(|_| EcdsaHostKeyError::InvalidSecretKey)?;
        Self::from_secret_scalar(&mut secret)
    }

    /// Generates a fresh P-521 signer from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::EntropyFailure`] if entropy is unavailable
    /// or the bounded rejection loop cannot produce a valid scalar.
    pub fn generate() -> Result<Self, EcdsaHostKeyError> {
        const MAX_GENERATION_ATTEMPTS: usize = 1024;
        for _ in 0..MAX_GENERATION_ATTEMPTS {
            let mut secret = [0_u8; ECDSA_P521_SECRET_SCALAR_LENGTH];
            if getrandom::fill(&mut secret).is_err() {
                secret.zeroize();
                return Err(EcdsaHostKeyError::EntropyFailure);
            }
            if let Ok(signer) = Self::from_secret_scalar(&mut secret) {
                return Ok(signer);
            }
        }
        Err(EcdsaHostKeyError::EntropyFailure)
    }

    /// Returns the algorithm supported by this signer.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_ECDSA_SHA2_NISTP521
    }

    /// Returns the curve name supported by this signer.
    #[must_use]
    pub const fn curve_name() -> &'static str {
        ECDSA_CURVE_NISTP521
    }

    /// Returns the public key corresponding to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaP521PublicKey {
        &self.public_key
    }

    /// Encodes the signer's public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.public_key.to_blob()
    }

    /// Signs raw exchange-hash bytes and returns a complete SSH signature blob.
    ///
    /// P-521 ECDSA hashes the supplied exchange-hash bytes with SHA-512 before
    /// invoking the upstream RFC 6979 prehash signer.  The bytes are not
    /// wrapped in another SSH string before hashing or signing.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::SigningFailed`] if the upstream signer
    /// fails, or [`EcdsaHostKeyError::Wire`] if the nested signature cannot be
    /// encoded.
    pub fn sign_exchange_hash(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
        let digest = sha2::Sha512::digest(exchange_hash);
        let signature: P521Signature = P521PrehashSigner::sign_prehash(&self.signing_key, &digest)
            .map_err(|_error| EcdsaHostKeyError::SigningFailed)?;
        let (r, s) = signature.split_bytes();
        encode_signature_blob(
            SSH_ECDSA_SHA2_NISTP521,
            r.as_slice(),
            s.as_slice(),
            ECDSA_P521_SIGNATURE_COMPONENT_LENGTH,
        )
    }
}

impl fmt::Debug for EcdsaP521Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaP521Signer")
            .field("algorithm", &Self::algorithm())
            .field("curve", &Self::curve_name())
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EcdsaP521Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EcdsaP521Signer({}, {})",
            Self::algorithm(),
            Self::curve_name()
        )
    }
}

/// Cryptographically verifies an SSH P-521 signature over raw exchange-hash bytes.
///
/// This function checks the public key supplied by the caller; it does not
/// establish application trust and never returns a verified host-key proof.
/// The signature must contain nested canonical mpints, not a bare `r || s`
/// value or an ASN.1 DER signature.
///
/// # Errors
///
/// Returns [`EcdsaHostKeyError::UnsupportedAlgorithm`] for a wrong signature
/// algorithm, [`EcdsaHostKeyError::InvalidFieldLength`] for a bare or
/// incorrectly sized detached value, [`EcdsaHostKeyError::TrailingData`] for
/// extra bytes, and [`EcdsaHostKeyError::InvalidSignature`] for malformed or
/// incorrect signatures.  Wire errors from malformed SSH framing are returned
/// as [`EcdsaHostKeyError::Wire`].
pub fn verify_p521_host_key_signature(
    public_key: &EcdsaP521PublicKey,
    signature_blob: &[u8],
    exchange_hash: &[u8],
) -> Result<(), EcdsaHostKeyError> {
    let (r, s) = decode_signature_components::<ECDSA_P521_SIGNATURE_COMPONENT_LENGTH>(
        signature_blob,
        SSH_ECDSA_SHA2_NISTP521,
    )?;
    let signature =
        P521Signature::from_scalars(r, s).map_err(|_error| EcdsaHostKeyError::InvalidSignature)?;
    let digest = sha2::Sha512::digest(exchange_hash);
    P521PrehashVerifier::verify_prehash(&public_key.verifying_key, &digest, &signature)
        .map_err(|_error| EcdsaHostKeyError::InvalidSignature)
}

/// Verifies a P-521 host-key signature and requires application trust.
///
/// Cryptographic verification always completes before `trust_callback` is
/// called.  The callback receives the validated public key.  `Ok(())` accepts
/// the key, any `Err` value rejects it, and a callback panic is contained and
/// returned as [`EcdsaHostKeyError::VerifierPanicked`].  There is no optional
/// callback and no default accepting policy.
///
/// # Errors
///
/// Returns any malformed-blob, algorithm, public-key, or signature error from
/// strict verification; [`EcdsaHostKeyError::TrustRejected`] when the callback
/// returns `Err`; or [`EcdsaHostKeyError::VerifierPanicked`] when it panics.
pub fn verify_and_trust_p521_host_key<F, E>(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    trust_callback: F,
) -> Result<VerifiedEcdsaP521HostKey, EcdsaHostKeyError>
where
    F: FnOnce(&EcdsaP521PublicKey) -> Result<(), E>,
{
    let public_key = EcdsaP521PublicKey::from_blob(host_key_blob)?;
    verify_p521_host_key_signature(&public_key, signature_blob, exchange_hash)?;

    match catch_unwind(AssertUnwindSafe(|| trust_callback(&public_key))) {
        Ok(Ok(())) => Ok(VerifiedEcdsaP521HostKey(public_key)),
        Ok(Err(_callback_error)) => Err(EcdsaHostKeyError::TrustRejected),
        Err(_panic_payload) => Err(EcdsaHostKeyError::VerifierPanicked),
    }
}

/// Proof that a P-521 host key passed cryptographic verification and trust policy.
///
/// Values of this type can only be produced by
/// [`verify_and_trust_p521_host_key`].  The type has no `Default` implementation
/// and no public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEcdsaP521HostKey(EcdsaP521PublicKey);

impl VerifiedEcdsaP521HostKey {
    /// Returns the cryptographically verified and application-trusted key.
    #[must_use]
    pub const fn public_key(&self) -> &EcdsaP521PublicKey {
        &self.0
    }

    /// Encodes the trusted public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`EcdsaHostKeyError::Wire`] if the fixed-size value cannot be
    /// represented by the SSH wire encoder.
    pub fn to_blob(self) -> Result<Vec<u8>, EcdsaHostKeyError> {
        self.0.to_blob()
    }
}

/// A compatibility name for [`EcdsaP521PublicKey`].
pub type P521PublicKey = EcdsaP521PublicKey;

/// A compatibility name for [`EcdsaP521Signer`].
pub type P521Signer = EcdsaP521Signer;

/// A compatibility name for [`VerifiedEcdsaP521HostKey`].
pub type VerifiedP521HostKey = VerifiedEcdsaP521HostKey;

/// A compatibility name for [`EcdsaHostKeyError`] used by P-521 APIs.
pub type P521HostKeyError = EcdsaHostKeyError;

fn decode_public_key_blob<const N: usize>(
    blob: &[u8],
    expected_algorithm: &str,
    expected_curve: &str,
) -> Result<[u8; N], EcdsaHostKeyError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != expected_algorithm.as_bytes() {
        return Err(EcdsaHostKeyError::UnsupportedAlgorithm);
    }

    let curve_name = reader.read_string()?;
    if curve_name != expected_curve.as_bytes() {
        return Err(EcdsaHostKeyError::UnsupportedCurve);
    }

    let point = reader.read_string()?;
    if point.len() != N {
        return Err(EcdsaHostKeyError::InvalidFieldLength);
    }
    if !reader.is_empty() {
        return Err(EcdsaHostKeyError::TrailingData);
    }

    point
        .try_into()
        .map_err(|_| EcdsaHostKeyError::InvalidFieldLength)
}

fn encode_signature_blob(
    algorithm: &str,
    r: &[u8],
    s: &[u8],
    component_length: usize,
) -> Result<Vec<u8>, EcdsaHostKeyError> {
    let mut signature_body = Writer::with_capacity(2 * (4 + component_length + 1));
    write_positive_mpint(&mut signature_body, r)?;
    write_positive_mpint(&mut signature_body, s)?;

    let mut writer = Writer::with_capacity(4 + algorithm.len() + 4 + signature_body.len());
    writer.write_string(algorithm)?;
    writer.write_string(signature_body.as_slice())?;
    Ok(writer.into_bytes())
}

fn decode_signature_components<const N: usize>(
    blob: &[u8],
    expected_algorithm: &str,
) -> Result<([u8; N], [u8; N]), EcdsaHostKeyError> {
    if blob.len() == N * 2 {
        return Err(EcdsaHostKeyError::InvalidFieldLength);
    }

    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != expected_algorithm.as_bytes() {
        return Err(EcdsaHostKeyError::UnsupportedAlgorithm);
    }

    let signature_body = reader.read_string()?;
    if !reader.is_empty() {
        return Err(EcdsaHostKeyError::TrailingData);
    }

    let mut signature_reader = Reader::new(signature_body);
    let r = read_positive_scalar::<N>(&mut signature_reader)?;
    let s = read_positive_scalar::<N>(&mut signature_reader)?;
    if !signature_reader.is_empty() {
        return Err(EcdsaHostKeyError::TrailingData);
    }

    Ok((r, s))
}
