//! RSA host-key blobs and `rsa-sha2-*` signatures.
//!
//! RSA host keys use the RFC 4253 `ssh-rsa` public-key blob even when the
//! signature algorithm is `rsa-sha2-256` or `rsa-sha2-512`.  This module
//! deliberately supports only those two SHA-2 signature names and PKCS#1
//! v1.5 signatures.  The legacy `ssh-rsa` (SHA-1) name and RSA-PSS are not
//! accepted.
//!
//! Cryptographic verification and application trust are separate operations:
//! [`verify_host_key_signature`] proves possession of the private key, while
//! [`verify_and_trust_host_key`] additionally requires an explicit callback
//! before returning a [`VerifiedRsaHostKey`].

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use neotales_ssh::{Error as WireError, Reader, Writer};
use rsa::traits::PublicKeyParts as _;
use sha2::Digest;

/// The RFC 4253 RSA public-key blob type.
pub const SSH_RSA: &str = "ssh-rsa";

/// The RSA signature algorithm using SHA-256.
pub const SSH_RSA_SHA2_256: &str = "rsa-sha2-256";

/// The RSA signature algorithm using SHA-512.
pub const SSH_RSA_SHA2_512: &str = "rsa-sha2-512";

/// An unprefixed alias for [`SSH_RSA_SHA2_256`].
pub const RSA_SHA2_256: &str = SSH_RSA_SHA2_256;

/// An unprefixed alias for [`SSH_RSA_SHA2_512`].
pub const RSA_SHA2_512: &str = SSH_RSA_SHA2_512;

/// An alias for [`SSH_RSA_SHA2_256`].
pub const RSA_SHA256: &str = SSH_RSA_SHA2_256;

/// An alias for [`SSH_RSA_SHA2_512`].
pub const RSA_SHA512: &str = SSH_RSA_SHA2_512;

/// The RSA host-key signature hash selected by a signer or verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaHostKeyAlgorithm {
    /// RSA PKCS#1 v1.5 with a SHA-256 digest.
    Sha256,
    /// RSA PKCS#1 v1.5 with a SHA-512 digest.
    Sha512,
}

impl RsaHostKeyAlgorithm {
    /// Returns the SSH signature algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => SSH_RSA_SHA2_256,
            Self::Sha512 => SSH_RSA_SHA2_512,
        }
    }

    /// Parses an SSH RSA signature algorithm name.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for `ssh-rsa`,
    /// RSA-PSS, certificate names, and every other spelling.
    pub fn from_name(name: &str) -> Result<Self, RsaHostKeyError> {
        match name {
            SSH_RSA_SHA2_256 => Ok(Self::Sha256),
            SSH_RSA_SHA2_512 => Ok(Self::Sha512),
            _ => Err(RsaHostKeyError::UnsupportedAlgorithm),
        }
    }

    /// Returns the two supported signature algorithms.
    #[must_use]
    pub const fn supported() -> &'static [Self] {
        &[Self::Sha256, Self::Sha512]
    }
}

impl TryFrom<&str> for RsaHostKeyAlgorithm {
    type Error = RsaHostKeyError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::from_name(name)
    }
}

/// A descriptive alias for [`RsaHostKeyAlgorithm`].
pub type RsaSignatureAlgorithm = RsaHostKeyAlgorithm;

/// A safe, non-sensitive error produced by the RSA host-key boundary.
///
/// Error values never contain private-key material, public moduli,
/// signatures, exchange-hash bytes, callback errors, panic payloads, or
/// attacker-controlled algorithm names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaHostKeyError {
    /// An RFC 4251 primitive was malformed, truncated, or oversized.
    Wire(WireError),
    /// A public-key or signature algorithm was unsupported.
    UnsupportedAlgorithm,
    /// A signature field did not have the exact modulus-sized length.
    InvalidFieldLength,
    /// A public-key or signature blob contained bytes after its defined fields.
    TrailingData,
    /// The RSA public-key components were invalid.
    InvalidPublicKey,
    /// The signature was malformed, used the wrong hash, or did not verify.
    InvalidSignature,
    /// The local RSA signing operation failed.
    SigningFailed,
    /// The application trust callback explicitly rejected the verified key.
    TrustRejected,
    /// The application trust callback panicked.
    VerifierPanicked,
}

impl fmt::Display for RsaHostKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wire(error) => {
                return write!(formatter, "SSH RSA host-key wire error: {error}");
            }
            Self::UnsupportedAlgorithm => "SSH RSA host-key algorithm is unsupported",
            Self::InvalidFieldLength => "SSH RSA host-key field has an invalid length",
            Self::TrailingData => "SSH RSA host-key blob contains trailing data",
            Self::InvalidPublicKey => "SSH RSA public key is invalid",
            Self::InvalidSignature => "SSH RSA host-key signature is invalid",
            Self::SigningFailed => "SSH RSA host-key signing failed",
            Self::TrustRejected => "SSH RSA host key was rejected by application trust policy",
            Self::VerifierPanicked => "SSH RSA host-key trust callback panicked",
        })
    }
}

impl std::error::Error for RsaHostKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for RsaHostKeyError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Checks a negotiated RSA host-key signature algorithm name.
///
/// Only `rsa-sha2-256` and `rsa-sha2-512` are accepted.  The legacy
/// `ssh-rsa` name denotes SHA-1 and is intentionally rejected here, even
/// though `ssh-rsa` remains the public-key blob type.
#[inline]
pub fn check_host_key_algorithm(algorithm: &str) -> Result<(), RsaHostKeyError> {
    RsaHostKeyAlgorithm::from_name(algorithm).map(|_algorithm| ())
}

/// Checks the public-key blob type used by RSA host keys.
///
/// The signature algorithm and the public-key blob type are intentionally
/// separate checks: the public blob is always `ssh-rsa`, while signatures use
/// `rsa-sha2-256` or `rsa-sha2-512`.
#[inline]
pub fn check_public_key_type(algorithm: &str) -> Result<(), RsaHostKeyError> {
    if algorithm == SSH_RSA {
        Ok(())
    } else {
        Err(RsaHostKeyError::UnsupportedAlgorithm)
    }
}

/// A validated RSA public key in SSH `ssh-rsa` wire form.
///
/// The type validates the key components when it is constructed.  It does
/// not by itself establish application trust in the key.
#[derive(Clone, Eq, PartialEq)]
pub struct RsaPublicKey {
    key: rsa::RsaPublicKey,
    blob: Vec<u8>,
}

impl RsaPublicKey {
    /// Parses an exact `string "ssh-rsa" || mpint e || mpint n` blob.
    ///
    /// Both integers must be positive, canonical mpints.  Extra bytes and
    /// malformed RSA components are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for another key
    /// type, [`RsaHostKeyError::Wire`] for a truncated or non-canonical SSH
    /// primitive, [`RsaHostKeyError::TrailingData`] for extra bytes, and
    /// [`RsaHostKeyError::InvalidPublicKey`] for invalid RSA components.
    pub fn from_blob(blob: &[u8]) -> Result<Self, RsaHostKeyError> {
        let mut reader = Reader::new(blob);
        let key_type = reader.read_string()?;
        if key_type != SSH_RSA.as_bytes() {
            return Err(RsaHostKeyError::UnsupportedAlgorithm);
        }
        let exponent = reader.read_mpint()?;
        let modulus = reader.read_mpint()?;
        if !reader.is_empty() {
            return Err(RsaHostKeyError::TrailingData);
        }
        if !is_positive_mpint(exponent) || !is_positive_mpint(modulus) {
            return Err(RsaHostKeyError::InvalidPublicKey);
        }

        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(modulus),
            rsa::BigUint::from_bytes_be(exponent),
        )
        .map_err(|_error| RsaHostKeyError::InvalidPublicKey)?;
        Ok(Self {
            key,
            blob: blob.to_vec(),
        })
    }

    /// Creates a wire wrapper from an upstream RSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::InvalidPublicKey`] if the components cannot
    /// form a valid RSA public key or cannot be encoded in the SSH wire
    /// format.
    pub fn from_public_key(key: &rsa::RsaPublicKey) -> Result<Self, RsaHostKeyError> {
        let key = rsa::RsaPublicKey::new(key.n().clone(), key.e().clone())
            .map_err(|_error| RsaHostKeyError::InvalidPublicKey)?;
        let blob = encode_public_blob(&key)?;
        Ok(Self { key, blob })
    }

    /// Returns the public-key blob type, which is always `ssh-rsa`.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_RSA
    }

    /// Returns the public-key blob type, which is always `ssh-rsa`.
    #[must_use]
    pub const fn key_type() -> &'static str {
        SSH_RSA
    }

    /// Returns the exact SSH public-key blob.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }

    /// Encodes and returns the exact SSH public-key blob.
    pub fn to_blob(&self) -> Result<Vec<u8>, RsaHostKeyError> {
        encode_public_blob(&self.key)
    }

    /// Returns the validated upstream RSA public key.
    #[must_use]
    pub const fn public_key(&self) -> &rsa::RsaPublicKey {
        &self.key
    }

    /// Returns the RSA modulus.
    #[must_use]
    pub fn modulus(&self) -> &rsa::BigUint {
        self.key.n()
    }

    /// Returns the RSA public exponent.
    #[must_use]
    pub fn exponent(&self) -> &rsa::BigUint {
        self.key.e()
    }

    /// Returns the modulus size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.key.size()
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaPublicKey")
            .field("key_type", &Self::key_type())
            .finish_non_exhaustive()
    }
}

/// A reusable RSA host-key signer for one selected SHA-2 algorithm.
///
/// The private key is owned by the upstream RSA type, which wipes its secret
/// components on drop.  The signer exposes only the public blob and never
/// formats its private key.
pub struct RsaHostSigner {
    key: rsa::RsaPrivateKey,
    public_key: RsaPublicKey,
    algorithm: RsaHostKeyAlgorithm,
}

impl RsaHostSigner {
    /// Creates a signer using `rsa-sha2-256` by default.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::InvalidPublicKey`] if the corresponding
    /// public components cannot be encoded as an SSH blob.
    pub fn from_private_key(key: rsa::RsaPrivateKey) -> Result<Self, RsaHostKeyError> {
        Self::from_private_key_with_algorithm(key, RsaHostKeyAlgorithm::Sha256)
    }

    /// Creates a signer for a selected RSA host-key signature algorithm.
    ///
    /// The algorithm may be [`RsaHostKeyAlgorithm`] or its SSH string name.
    /// The name `ssh-rsa` is rejected as a SHA-1 algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for an unknown
    /// algorithm or [`RsaHostKeyError::InvalidPublicKey`] if the public key
    /// cannot be encoded.
    pub fn from_private_key_with_algorithm<A>(
        key: rsa::RsaPrivateKey,
        algorithm: A,
    ) -> Result<Self, RsaHostKeyError>
    where
        A: TryInto<RsaHostKeyAlgorithm>,
    {
        let algorithm = parse_algorithm(algorithm)?;
        let public_key = RsaPublicKey::from_public_key(&key.to_public_key())?;
        Ok(Self {
            key,
            public_key,
            algorithm,
        })
    }

    /// Creates a signer from a private key and an algorithm name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_private_key_with_algorithm`].
    pub fn new<A>(key: rsa::RsaPrivateKey, algorithm: A) -> Result<Self, RsaHostKeyError>
    where
        A: TryInto<RsaHostKeyAlgorithm>,
    {
        Self::from_private_key_with_algorithm(key, algorithm)
    }

    /// Creates a signer from two fixed primes using SHA-256 by default.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::InvalidPublicKey`] if the components do not
    /// form a valid RSA private key.
    pub fn from_p_q(
        p: rsa::BigUint,
        q: rsa::BigUint,
        exponent: rsa::BigUint,
    ) -> Result<Self, RsaHostKeyError> {
        let key = rsa::RsaPrivateKey::from_p_q(p, q, exponent)
            .map_err(|_error| RsaHostKeyError::InvalidPublicKey)?;
        Self::from_private_key(key)
    }

    /// Creates a signer from two fixed primes and a selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for an unknown
    /// algorithm or [`RsaHostKeyError::InvalidPublicKey`] for invalid RSA
    /// components.
    pub fn from_p_q_with_algorithm<A>(
        p: rsa::BigUint,
        q: rsa::BigUint,
        exponent: rsa::BigUint,
        algorithm: A,
    ) -> Result<Self, RsaHostKeyError>
    where
        A: TryInto<RsaHostKeyAlgorithm>,
    {
        let algorithm = parse_algorithm(algorithm)?;
        let key = rsa::RsaPrivateKey::from_p_q(p, q, exponent)
            .map_err(|_error| RsaHostKeyError::InvalidPublicKey)?;
        Self::from_private_key_with_algorithm(key, algorithm)
    }

    /// Returns the signature algorithm used by this signer.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm.name()
    }

    /// Returns the typed signature algorithm used by this signer.
    #[must_use]
    pub const fn signature_algorithm(&self) -> RsaHostKeyAlgorithm {
        self.algorithm
    }

    /// Returns the public-key blob type, which is always `ssh-rsa`.
    #[must_use]
    pub const fn key_type() -> &'static str {
        SSH_RSA
    }

    /// Returns the public key corresponding to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Encodes and returns the exact SSH public-key blob.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, RsaHostKeyError> {
        self.public_key.to_blob()
    }

    /// Returns a borrowed view of the exact SSH public-key blob.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Encodes and returns a copy of the SSH public-key blob.
    pub fn to_public_key_blob(&self) -> Result<Vec<u8>, RsaHostKeyError> {
        self.public_key.to_blob()
    }

    /// Signs raw exchange-hash bytes with the signer's selected algorithm.
    ///
    /// The selected SHA-256 or SHA-512 digest is calculated directly from
    /// `exchange_hash`; the bytes are not wrapped in another SSH string.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::SigningFailed`] if the upstream RSA
    /// operation fails or [`RsaHostKeyError::Wire`] if the signature cannot
    /// be encoded.
    pub fn sign_exchange_hash(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, RsaHostKeyError> {
        self.sign_with_algorithm(exchange_hash, self.algorithm)
    }

    /// Signs raw exchange-hash bytes with an explicitly selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for an unknown
    /// algorithm, [`RsaHostKeyError::SigningFailed`] for an upstream RSA
    /// failure, or [`RsaHostKeyError::Wire`] for an encoding failure.
    pub fn sign_exchange_hash_with_algorithm<A>(
        &self,
        exchange_hash: &[u8],
        algorithm: A,
    ) -> Result<Vec<u8>, RsaHostKeyError>
    where
        A: TryInto<RsaHostKeyAlgorithm>,
    {
        let algorithm = parse_algorithm(algorithm)?;
        self.sign_with_typed_algorithm(exchange_hash, algorithm)
    }

    /// Signs raw exchange-hash bytes with an explicitly selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::sign_exchange_hash_with_algorithm`].
    pub fn sign_with_algorithm<A>(
        &self,
        exchange_hash: &[u8],
        algorithm: A,
    ) -> Result<Vec<u8>, RsaHostKeyError>
    where
        A: TryInto<RsaHostKeyAlgorithm>,
    {
        self.sign_exchange_hash_with_algorithm(exchange_hash, algorithm)
    }

    /// Signs raw exchange-hash bytes with RSA PKCS#1 v1.5 and SHA-256.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::sign_exchange_hash`].
    pub fn sign_sha256(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, RsaHostKeyError> {
        self.sign_with_typed_algorithm(exchange_hash, RsaHostKeyAlgorithm::Sha256)
    }

    /// Signs raw exchange-hash bytes with RSA PKCS#1 v1.5 and SHA-512.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::sign_exchange_hash`].
    pub fn sign_sha512(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, RsaHostKeyError> {
        self.sign_with_typed_algorithm(exchange_hash, RsaHostKeyAlgorithm::Sha512)
    }

    /// Alias for [`Self::sign_exchange_hash`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::sign_exchange_hash`].
    pub fn sign(&self, exchange_hash: &[u8]) -> Result<Vec<u8>, RsaHostKeyError> {
        self.sign_exchange_hash(exchange_hash)
    }

    fn sign_with_typed_algorithm(
        &self,
        exchange_hash: &[u8],
        algorithm: RsaHostKeyAlgorithm,
    ) -> Result<Vec<u8>, RsaHostKeyError> {
        let raw_signature = match algorithm {
            RsaHostKeyAlgorithm::Sha256 => {
                let digest = sha2::Sha256::digest(exchange_hash);
                self.key
                    .sign(rsa::Pkcs1v15Sign::new_unprefixed(), digest.as_slice())
            }
            RsaHostKeyAlgorithm::Sha512 => {
                let digest = sha2::Sha512::digest(exchange_hash);
                self.key
                    .sign(rsa::Pkcs1v15Sign::new_unprefixed(), digest.as_slice())
            }
        }
        .map_err(|_error| RsaHostKeyError::SigningFailed)?;
        encode_signature_blob(algorithm, &raw_signature)
    }
}

impl fmt::Debug for RsaHostSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaHostSigner")
            .field("key_type", &Self::key_type())
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RsaHostSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RsaHostSigner({}, {})",
            Self::key_type(),
            self.algorithm()
        )
    }
}

/// Cryptographically verifies an SSH RSA signature over raw exchange-hash bytes.
///
/// This function checks the supplied public key only; it does not establish
/// application trust and never returns a [`VerifiedRsaHostKey`].  The public
/// blob remains `ssh-rsa`, while the signature algorithm must be
/// `rsa-sha2-256` or `rsa-sha2-512`.
///
/// # Errors
///
/// Returns [`RsaHostKeyError::UnsupportedAlgorithm`] for `ssh-rsa`, RSA-PSS,
/// or any other signature name; wire errors for truncated fields;
/// [`RsaHostKeyError::TrailingData`] for extra fields;
/// [`RsaHostKeyError::InvalidFieldLength`] for a signature that is not the
/// exact modulus size; and [`RsaHostKeyError::InvalidSignature`] when the
/// PKCS#1 v1.5 proof does not verify for this public key.
pub fn verify_host_key_signature(
    public_key: &RsaPublicKey,
    signature_blob: &[u8],
    exchange_hash: &[u8],
) -> Result<(), RsaHostKeyError> {
    let (algorithm, signature) = decode_signature_blob(signature_blob)?;
    if signature.len() != public_key.size() {
        return Err(RsaHostKeyError::InvalidFieldLength);
    }

    match algorithm {
        RsaHostKeyAlgorithm::Sha256 => {
            let digest = sha2::Sha256::digest(exchange_hash);
            public_key
                .public_key()
                .verify(
                    rsa::Pkcs1v15Sign::new_unprefixed(),
                    digest.as_slice(),
                    signature,
                )
                .map_err(|_error| RsaHostKeyError::InvalidSignature)
        }
        RsaHostKeyAlgorithm::Sha512 => {
            let digest = sha2::Sha512::digest(exchange_hash);
            public_key
                .public_key()
                .verify(
                    rsa::Pkcs1v15Sign::new_unprefixed(),
                    digest.as_slice(),
                    signature,
                )
                .map_err(|_error| RsaHostKeyError::InvalidSignature)
        }
    }
}

/// Verifies a host-key signature and requires an explicit application trust decision.
///
/// Cryptographic verification always completes before `trust_callback` is
/// called.  The callback receives the validated public key. `Ok(())` accepts
/// the key, any `Err` value rejects it, and a callback panic is contained and
/// returned as [`RsaHostKeyError::VerifierPanicked`].  There is no optional
/// callback and no default accepting policy.
///
/// # Errors
///
/// Returns any malformed-blob, algorithm, public-key, or signature error from
/// strict verification; [`RsaHostKeyError::TrustRejected`] when the callback
/// returns `Err`; or [`RsaHostKeyError::VerifierPanicked`] when it panics.
pub fn verify_and_trust_host_key<F, E>(
    host_key_blob: &[u8],
    signature_blob: &[u8],
    exchange_hash: &[u8],
    trust_callback: F,
) -> Result<VerifiedRsaHostKey, RsaHostKeyError>
where
    F: FnOnce(&RsaPublicKey) -> Result<(), E>,
{
    let public_key = RsaPublicKey::from_blob(host_key_blob)?;
    verify_host_key_signature(&public_key, signature_blob, exchange_hash)?;

    match catch_unwind(AssertUnwindSafe(|| trust_callback(&public_key))) {
        Ok(Ok(())) => Ok(VerifiedRsaHostKey(public_key)),
        Ok(Err(_callback_error)) => Err(RsaHostKeyError::TrustRejected),
        Err(_panic_payload) => Err(RsaHostKeyError::VerifierPanicked),
    }
}

/// Proof that an RSA host key passed both cryptographic verification and application trust policy.
///
/// Values of this type can only be produced by [`verify_and_trust_host_key`].
/// The type has no `Default` implementation and no public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRsaHostKey(RsaPublicKey);

impl VerifiedRsaHostKey {
    /// Returns the cryptographically verified and application-trusted public key.
    #[must_use]
    pub const fn public_key(&self) -> &RsaPublicKey {
        &self.0
    }

    /// Encodes the trusted public key as an SSH host-key blob.
    ///
    /// # Errors
    ///
    /// Returns a wire error if the stored key cannot be encoded.
    pub fn to_blob(&self) -> Result<Vec<u8>, RsaHostKeyError> {
        self.0.to_blob()
    }
}

/// A compatibility name for [`RsaHostKeyError`].
pub type HostKeyError = RsaHostKeyError;

/// A compatibility name for [`RsaPublicKey`].
pub type RsaHostKey = RsaPublicKey;

/// A compatibility name for [`RsaHostSigner`].
pub type RsaSigner = RsaHostSigner;

/// A compatibility name for [`RsaHostSigner`].
pub type RsaHostKeySigner = RsaHostSigner;

/// A compatibility name for [`VerifiedRsaHostKey`].
pub type VerifiedHostKey = VerifiedRsaHostKey;

fn parse_algorithm<A>(algorithm: A) -> Result<RsaHostKeyAlgorithm, RsaHostKeyError>
where
    A: TryInto<RsaHostKeyAlgorithm>,
{
    algorithm
        .try_into()
        .map_err(|_error| RsaHostKeyError::UnsupportedAlgorithm)
}

fn is_positive_mpint(value: &[u8]) -> bool {
    value.first().is_some_and(|byte| byte & 0x80 == 0)
}

fn encode_positive_mpint(writer: &mut Writer, value: &[u8]) -> Result<(), WireError> {
    if value.is_empty() {
        return Err(WireError::InvalidMpint);
    }
    let mut positive = value.to_vec();
    if positive.first().is_some_and(|byte| byte & 0x80 != 0) {
        positive.insert(0, 0);
    }
    writer.write_mpint(positive.as_slice())
}

fn encode_public_blob(key: &rsa::RsaPublicKey) -> Result<Vec<u8>, RsaHostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(SSH_RSA)?;
    encode_positive_mpint(&mut writer, &key.e().to_bytes_be())?;
    encode_positive_mpint(&mut writer, &key.n().to_bytes_be())?;
    Ok(writer.into_bytes())
}

fn encode_signature_blob(
    algorithm: RsaHostKeyAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, RsaHostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(algorithm.name())?;
    writer.write_string(signature)?;
    Ok(writer.into_bytes())
}

fn decode_signature_blob(blob: &[u8]) -> Result<(RsaHostKeyAlgorithm, &[u8]), RsaHostKeyError> {
    let mut reader = Reader::new(blob);
    let algorithm = RsaHostKeyAlgorithm::from_name(
        std::str::from_utf8(reader.read_string()?)
            .map_err(|_error| RsaHostKeyError::UnsupportedAlgorithm)?,
    )?;
    let signature = reader.read_string()?;
    if !reader.is_empty() {
        return Err(RsaHostKeyError::TrailingData);
    }
    if signature.is_empty() {
        return Err(RsaHostKeyError::InvalidFieldLength);
    }
    Ok((algorithm, signature))
}
