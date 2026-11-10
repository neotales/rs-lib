//! OpenSSH certificate parsing and verification.
//!
//! This module implements the OpenSSH certificate formats for Ed25519, RSA,
//! and the NIST P-256, P-384, and P-521 ECDSA curves. Certificate subjects
//! and signature keys are represented as normal public-key blobs; a signature
//! key must not itself be a certificate. The verification boundary accepts a
//! raw 32-byte Ed25519 point or an `ssh-ed25519` blob for an Ed25519 CA. Other
//! CAs are supplied as their normal public-key blobs. Signature checks use
//! `neotales-crypto`.
//!
//! The module does not issue certificates or sign anything. The signed bytes
//! are the raw certificate prefix through the end of the signature-key string;
//! they are not wrapped in another SSH string before verification.

use std::fmt;

use ed25519_dalek;
use p256;
use p256::ecdsa::signature::hazmat::PrehashVerifier as P256PrehashVerifier;
use p384;
use p384::ecdsa::signature::hazmat::PrehashVerifier as P384PrehashVerifier;
use p521;
use p521::ecdsa::signature::hazmat::PrehashVerifier as P521PrehashVerifier;
use rsa;
use rsa::traits::PublicKeyParts as _;
use sha2::{self, Digest};

pub use crate::ssh_wire::WireError;
use crate::ssh_wire::{Reader, Writer};

const ECDSA_UNCOMPRESSED_POINT_TAG: u8 = 0x04;
const P256_POINT_LENGTH: usize = 65;
const P384_POINT_LENGTH: usize = 97;
const P521_POINT_LENGTH: usize = 133;
const P256_SCALAR_LENGTH: usize = 32;
const P384_SCALAR_LENGTH: usize = 48;
const P521_SCALAR_LENGTH: usize = 66;
const RSA_SHA2_256: &str = "rsa-sha2-256";
const RSA_SHA2_512: &str = "rsa-sha2-512";

/// The plain Ed25519 public-key and signature algorithm.
pub const SSH_ED25519: &str = "ssh-ed25519";

/// The plain RSA public-key algorithm.
pub const SSH_RSA: &str = "ssh-rsa";

/// The plain NIST P-256 ECDSA public-key and signature algorithm.
pub const SSH_ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";

/// The plain NIST P-384 ECDSA public-key and signature algorithm.
pub const SSH_ECDSA_SHA2_NISTP384: &str = "ecdsa-sha2-nistp384";

/// The plain NIST P-521 ECDSA public-key and signature algorithm.
pub const SSH_ECDSA_SHA2_NISTP521: &str = "ecdsa-sha2-nistp521";

/// The OpenSSH Ed25519 certificate algorithm.
pub const SSH_ED25519_CERT_V01: &str = "ssh-ed25519-cert-v01@openssh.com";

/// The OpenSSH RSA certificate algorithm.
pub const SSH_RSA_CERT_V01: &str = "ssh-rsa-cert-v01@openssh.com";

/// The OpenSSH NIST P-256 ECDSA certificate algorithm.
pub const SSH_ECDSA_SHA2_NISTP256_CERT_V01: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// The OpenSSH NIST P-384 ECDSA certificate algorithm.
pub const SSH_ECDSA_SHA2_NISTP384_CERT_V01: &str = "ecdsa-sha2-nistp384-cert-v01@openssh.com";

/// The OpenSSH NIST P-521 ECDSA certificate algorithm.
pub const SSH_ECDSA_SHA2_NISTP521_CERT_V01: &str = "ecdsa-sha2-nistp521-cert-v01@openssh.com";

/// The certificate algorithms accepted by this module.
pub const SUPPORTED_CERTIFICATE_ALGORITHMS: &[&str] = &[
    SSH_ED25519_CERT_V01,
    SSH_RSA_CERT_V01,
    SSH_ECDSA_SHA2_NISTP256_CERT_V01,
    SSH_ECDSA_SHA2_NISTP384_CERT_V01,
    SSH_ECDSA_SHA2_NISTP521_CERT_V01,
];

/// The certificate type value for a user certificate.
pub const CERTIFICATE_TYPE_USER: u32 = 1;

/// The certificate type value for a host certificate.
pub const CERTIFICATE_TYPE_HOST: u32 = 2;

/// The length of an Ed25519 compressed public point.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// The name of the `source-address` critical option.
pub const CRITICAL_OPTION_SOURCE_ADDRESS: &str = "source-address";

/// The name of the `force-command` critical option.
pub const CRITICAL_OPTION_FORCE_COMMAND: &str = "force-command";

/// The role asserted by a parsed certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateType {
    /// A certificate intended for user authentication.
    User,
    /// A certificate intended for host authentication.
    Host,
}

impl CertificateType {
    /// Converts a certificate type to its OpenSSH wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::User => CERTIFICATE_TYPE_USER,
            Self::Host => CERTIFICATE_TYPE_HOST,
        }
    }

    /// Converts an OpenSSH wire value to a certificate type.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            CERTIFICATE_TYPE_USER => Some(Self::User),
            CERTIFICATE_TYPE_HOST => Some(Self::Host),
            _ => None,
        }
    }
}

/// A safe error produced while parsing or verifying an OpenSSH certificate.
///
/// Error values never contain certificate bytes, option data, public-key
/// points, or signature bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    /// An RFC 4251 primitive was malformed, truncated, or oversized.
    Wire(WireError),
    /// The certificate or embedded key algorithm is not supported.
    UnsupportedAlgorithm,
    /// A fixed-size public-key or signature field has the wrong length.
    InvalidFieldLength,
    /// An embedded public point or key is malformed or weak.
    InvalidPublicKey,
    /// The certificate role is neither user nor host.
    InvalidCertificateType,
    /// The certificate identifier is not valid UTF-8.
    InvalidIdentifier,
    /// A principal is not valid UTF-8.
    InvalidPrincipal,
    /// The validity interval is empty or otherwise malformed.
    InvalidValidityWindow,
    /// A critical option is malformed.
    InvalidCriticalOption,
    /// An extension name or value is malformed.
    InvalidExtension,
    /// An option or extension name is not valid UTF-8.
    InvalidOptionName,
    /// An option or extension name occurs more than once.
    DuplicateOption,
    /// Options or extensions are not in strict lexical name order.
    UnsortedOptions,
    /// The reserved certificate field is not empty.
    NonEmptyReserved,
    /// The signature-key field is a certificate or has another invalid shape.
    CertificateSignatureKey,
    /// The certificate's signature key differs from the trusted CA key.
    SignatureKeyMismatch,
    /// The supplied CA public key is malformed.
    InvalidCaPublicKey,
    /// A critical option was not present in the caller's allow list.
    CriticalOptionNotAllowed,
    /// The certificate role does not match the expected role.
    TypeMismatch,
    /// The expected principal is not listed by the certificate.
    PrincipalMismatch,
    /// The certificate is not valid yet at the supplied timestamp.
    NotYetValid,
    /// The certificate is expired at the supplied timestamp.
    Expired,
    /// The detached certificate signature is invalid.
    InvalidSignature,
    /// Bytes remain after a defined certificate or embedded blob.
    TrailingData,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH certificate wire error: {error}"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("SSH certificate algorithm is unsupported")
            }
            Self::InvalidFieldLength => {
                formatter.write_str("SSH certificate field has an invalid length")
            }
            Self::InvalidPublicKey => formatter.write_str("SSH certificate public key is invalid"),
            Self::InvalidCertificateType => formatter.write_str("SSH certificate type is invalid"),
            Self::InvalidIdentifier => formatter.write_str("SSH certificate identifier is invalid"),
            Self::InvalidPrincipal => formatter.write_str("SSH certificate principal is invalid"),
            Self::InvalidValidityWindow => {
                formatter.write_str("SSH certificate validity window is invalid")
            }
            Self::InvalidCriticalOption => {
                formatter.write_str("SSH certificate critical option is invalid")
            }
            Self::InvalidExtension => formatter.write_str("SSH certificate extension is invalid"),
            Self::InvalidOptionName => {
                formatter.write_str("SSH certificate option name is invalid")
            }
            Self::DuplicateOption => {
                formatter.write_str("SSH certificate option name is duplicated")
            }
            Self::UnsortedOptions => {
                formatter.write_str("SSH certificate options are not strictly sorted")
            }
            Self::NonEmptyReserved => {
                formatter.write_str("SSH certificate reserved field is not empty")
            }
            Self::CertificateSignatureKey => {
                formatter.write_str("SSH certificate signature key is invalid")
            }
            Self::SignatureKeyMismatch => {
                formatter.write_str("SSH certificate signature key does not match the CA key")
            }
            Self::InvalidCaPublicKey => {
                formatter.write_str("SSH certificate CA public key is invalid")
            }
            Self::CriticalOptionNotAllowed => formatter
                .write_str("SSH certificate contains a critical option that is not allowed"),
            Self::TypeMismatch => {
                formatter.write_str("SSH certificate type does not match the expected type")
            }
            Self::PrincipalMismatch => {
                formatter.write_str("SSH certificate does not contain the expected principal")
            }
            Self::NotYetValid => formatter.write_str("SSH certificate is not valid yet"),
            Self::Expired => formatter.write_str("SSH certificate is expired"),
            Self::InvalidSignature => formatter.write_str("SSH certificate signature is invalid"),
            Self::TrailingData => formatter.write_str("SSH certificate contains trailing data"),
        }
    }
}

impl std::error::Error for CertificateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for CertificateError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// One name/data pair from a certificate option or extension list.
///
/// The name is UTF-8 as required by the OpenSSH certificate format. Data is
/// intentionally exposed as raw bytes because option-specific encodings are
/// interpreted by the caller or by the explicitly parsed critical-option
/// accessors on [`Certificate`].
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateOption {
    name: String,
    data: Vec<u8>,
}

impl CertificateOption {
    /// Returns the option or extension name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the option or extension data bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the number of data bytes in this option.
    #[must_use]
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Debug for CertificateOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateOption")
            .field("name", &self.name)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CertificateAlgorithm {
    Ed25519,
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl CertificateAlgorithm {
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            value if value == SSH_ED25519_CERT_V01.as_bytes() => Some(Self::Ed25519),
            value if value == SSH_RSA_CERT_V01.as_bytes() => Some(Self::Rsa),
            value if value == SSH_ECDSA_SHA2_NISTP256_CERT_V01.as_bytes() => Some(Self::EcdsaP256),
            value if value == SSH_ECDSA_SHA2_NISTP384_CERT_V01.as_bytes() => Some(Self::EcdsaP384),
            value if value == SSH_ECDSA_SHA2_NISTP521_CERT_V01.as_bytes() => Some(Self::EcdsaP521),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => SSH_ED25519_CERT_V01,
            Self::Rsa => SSH_RSA_CERT_V01,
            Self::EcdsaP256 => SSH_ECDSA_SHA2_NISTP256_CERT_V01,
            Self::EcdsaP384 => SSH_ECDSA_SHA2_NISTP384_CERT_V01,
            Self::EcdsaP521 => SSH_ECDSA_SHA2_NISTP521_CERT_V01,
        }
    }

    const fn public_key_algorithm(self) -> &'static str {
        match self {
            Self::Ed25519 => SSH_ED25519,
            Self::Rsa => SSH_RSA,
            Self::EcdsaP256 => SSH_ECDSA_SHA2_NISTP256,
            Self::EcdsaP384 => SSH_ECDSA_SHA2_NISTP384,
            Self::EcdsaP521 => SSH_ECDSA_SHA2_NISTP521,
        }
    }

    const fn curve_name(self) -> Option<&'static str> {
        match self {
            Self::EcdsaP256 => Some("nistp256"),
            Self::EcdsaP384 => Some("nistp384"),
            Self::EcdsaP521 => Some("nistp521"),
            Self::Ed25519 | Self::Rsa => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SubjectPublicKey {
    blob: Vec<u8>,
    ed25519_point: Option<[u8; ED25519_PUBLIC_KEY_LENGTH]>,
}

/// A structurally parsed OpenSSH certificate.
///
/// [`parse_certificate`] validates the wire shape, fixed fields, nested
/// option encodings, and embedded key encodings, but cannot establish trust
/// without a CA key. Use [`verify_certificate`] to obtain a
/// [`VerifiedCertificate`] after signature and policy verification.
#[derive(Clone, Eq, PartialEq)]
pub struct Certificate {
    algorithm: CertificateAlgorithm,
    nonce: Vec<u8>,
    subject_public_key: SubjectPublicKey,
    serial: u64,
    role: CertificateType,
    key_id: String,
    principals: Vec<String>,
    valid_after: u64,
    valid_before: u64,
    critical_options: Vec<CertificateOption>,
    extensions: Vec<CertificateOption>,
    source_address: Option<Vec<u8>>,
    force_command: Option<Vec<u8>>,
    signature_key: Vec<u8>,
}

impl Certificate {
    /// Returns this certificate's OpenSSH certificate algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm.name()
    }

    /// Returns the certificate nonce bytes.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the Ed25519 subject point when this is an Ed25519 certificate.
    ///
    /// Use [`Self::subject_public_key_blob`] for an algorithm-independent
    /// representation.
    #[must_use]
    pub fn subject_public_key(&self) -> Option<&[u8; ED25519_PUBLIC_KEY_LENGTH]> {
        self.subject_public_key.ed25519_point.as_ref()
    }

    /// Returns the subject's normal SSH public-key blob.
    ///
    /// The blob uses `ssh-ed25519`, `ssh-rsa`, or the matching plain ECDSA
    /// algorithm rather than the certificate algorithm.
    #[must_use]
    pub fn subject_public_key_blob(&self) -> &[u8] {
        &self.subject_public_key.blob
    }

    /// Returns the certificate serial number.
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the certificate role.
    #[must_use]
    pub const fn certificate_type(&self) -> CertificateType {
        self.role
    }

    /// Returns the human-readable certificate identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the principals listed by the certificate.
    #[must_use]
    pub fn principals(&self) -> &[String] {
        &self.principals
    }

    /// Returns the inclusive start of the validity interval.
    #[must_use]
    pub const fn valid_after(&self) -> u64 {
        self.valid_after
    }

    /// Returns the exclusive end of the validity interval.
    #[must_use]
    pub const fn valid_before(&self) -> u64 {
        self.valid_before
    }

    /// Returns all critical options in their wire order.
    #[must_use]
    pub fn critical_options(&self) -> &[CertificateOption] {
        &self.critical_options
    }

    /// Returns all extensions in their wire order.
    ///
    /// Unknown extensions are retained rather than rejected.
    #[must_use]
    pub fn extensions(&self) -> &[CertificateOption] {
        &self.extensions
    }

    /// Returns the parsed `source-address` value, if that allowed option was
    /// present.
    ///
    /// The bytes are returned without address-list enforcement.
    #[must_use]
    pub fn source_address(&self) -> Option<&[u8]> {
        self.source_address.as_deref()
    }

    /// Returns the parsed `force-command` value, if that allowed option was
    /// present.
    ///
    /// The bytes are returned without command enforcement.
    #[must_use]
    pub fn force_command(&self) -> Option<&[u8]> {
        self.force_command.as_deref()
    }

    /// Returns the normal SSH public-key blob recorded as the signature key.
    #[must_use]
    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    /// Returns the normal SSH public-key blob recorded as the signature key.
    #[must_use]
    pub fn signature_key_blob(&self) -> &[u8] {
        &self.signature_key
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let critical_names: Vec<&str> = self
            .critical_options
            .iter()
            .map(CertificateOption::name)
            .collect();
        let extension_names: Vec<&str> = self
            .extensions
            .iter()
            .map(CertificateOption::name)
            .collect();
        formatter
            .debug_struct("Certificate")
            .field("algorithm", &self.algorithm())
            .field("nonce_len", &self.nonce.len())
            .field("subject_public_key", &"[redacted]")
            .field("serial", &self.serial)
            .field("certificate_type", &self.role)
            .field("key_id", &self.key_id)
            .field("principals", &self.principals)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .field("critical_options", &critical_names)
            .field("extensions", &extension_names)
            .field("source_address_present", &self.source_address.is_some())
            .field("force_command_present", &self.force_command.is_some())
            .field("signature_key", &"[redacted]")
            .finish()
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} certificate {} for {:?}",
            self.algorithm(),
            self.serial,
            self.role
        )
    }
}

/// A certificate that passed signature, type, principal, time, and
/// critical-option policy verification.
///
/// The type has no public constructor and does not retain detached signature
/// bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedCertificate {
    certificate: Certificate,
}

impl VerifiedCertificate {
    /// Borrows the structurally parsed certificate fields.
    #[must_use]
    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Consumes the verified wrapper and returns its certificate fields.
    #[must_use]
    pub fn into_certificate(self) -> Certificate {
        self.certificate
    }
}

impl std::ops::Deref for VerifiedCertificate {
    type Target = Certificate;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl AsRef<Certificate> for VerifiedCertificate {
    fn as_ref(&self) -> &Certificate {
        &self.certificate
    }
}

impl fmt::Debug for VerifiedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCertificate")
            .field("certificate", &self.certificate)
            .finish()
    }
}

impl fmt::Display for VerifiedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.certificate.fmt(formatter)
    }
}

/// Parses an OpenSSH certificate without verifying its CA signature.
///
/// The returned value is not trusted. In particular, critical-option
/// authorization is not applied by this function; use [`verify_certificate`]
/// for that fail-closed check. The final signature string is required, and
/// the Ed25519 signature shape is checked during parsing. Cryptographic
/// verification of all supported algorithms is performed by
/// [`verify_certificate`].
///
/// # Errors
///
/// Returns [`CertificateError`] for a malformed wire value, unsupported
/// algorithm, invalid field, invalid nested option encoding, invalid
/// certificate type, or trailing data.
pub fn parse_certificate(certificate: &[u8]) -> Result<Certificate, CertificateError> {
    Ok(parse_certificate_internal(certificate)?.certificate)
}

/// Parses and verifies an OpenSSH certificate.
///
/// `ca_public_key` may be either a raw 32-byte Ed25519 point or a complete
/// `ssh-ed25519` public-key blob for an Ed25519 CA. RSA and ECDSA CAs are
/// supplied as their normal public-key blobs. The certificate's signature
/// must verify strictly with the embedded signature key, which must identify
/// the same key as `ca_public_key`. `allowed_critical_options` is an explicit
/// allow list: every critical option name must occur in it, while unknown
/// extensions are retained and ignored for authorization. `now` is a Unix
/// timestamp in seconds and must satisfy `valid_after <= now < valid_before`.
///
/// The expected principal is compared byte-for-byte with one of the nested
/// principal strings. An empty principal list therefore does not match a
/// concrete principal.
///
/// # Errors
///
/// Returns [`CertificateError`] for malformed data, an unsupported
/// algorithm, an invalid CA key, an invalid signature, a mismatched expected
/// type or principal, an invalid timestamp, or a critical option that is not
/// explicitly allowed.
pub fn verify_certificate(
    certificate: &[u8],
    expected_type: CertificateType,
    expected_principal: &str,
    now: u64,
    allowed_critical_options: &[&str],
    ca_public_key: &[u8],
) -> Result<VerifiedCertificate, CertificateError> {
    let parsed = parse_certificate_internal(certificate)?;
    let ca_key = decode_ca_public_key(ca_public_key)?;

    if parsed.certificate.signature_key != ca_key.blob {
        return Err(CertificateError::SignatureKeyMismatch);
    }

    verify_public_key_signature(
        &ca_key,
        &parsed.signature_blob,
        &certificate[..parsed.signed_len],
    )?;

    verify_policy(
        &parsed.certificate,
        expected_type,
        expected_principal,
        now,
        allowed_critical_options,
    )?;

    Ok(VerifiedCertificate {
        certificate: parsed.certificate,
    })
}

struct ParsedCertificate {
    certificate: Certificate,
    signed_len: usize,
    signature_blob: Vec<u8>,
}

struct ParsedCriticalOptions {
    options: Vec<CertificateOption>,
    source_address: Option<Vec<u8>>,
    force_command: Option<Vec<u8>>,
}

enum PublicKeyKind {
    Ed25519(ed25519_dalek::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
    EcdsaP521(p521::ecdsa::VerifyingKey),
}

struct DecodedPublicKey {
    blob: Vec<u8>,
    kind: PublicKeyKind,
}

fn parse_certificate_internal(input: &[u8]) -> Result<ParsedCertificate, CertificateError> {
    let mut reader = Reader::new(input);
    let algorithm = CertificateAlgorithm::from_name(reader.read_string()?)
        .ok_or(CertificateError::UnsupportedAlgorithm)?;
    let nonce = reader.read_string_bytes()?;
    let subject_public_key = parse_subject_public_key(&mut reader, algorithm)?;

    let serial = reader.read_uint64()?;
    let certificate_type = CertificateType::from_u32(reader.read_uint32()?)
        .ok_or(CertificateError::InvalidCertificateType)?;
    let key_id = String::from_utf8(reader.read_string_bytes()?)
        .map_err(|_| CertificateError::InvalidIdentifier)?;
    let principals = parse_principals(&reader.read_string_bytes()?)?;
    let valid_after = reader.read_uint64()?;
    let valid_before = reader.read_uint64()?;
    if valid_before <= valid_after {
        return Err(CertificateError::InvalidValidityWindow);
    }

    let critical = parse_critical_options(&reader.read_string_bytes()?)?;
    let extensions = parse_extensions(&reader.read_string_bytes()?)?;
    let reserved = reader.read_string()?;
    if !reserved.is_empty() {
        return Err(CertificateError::NonEmptyReserved);
    }

    let signature_key_blob = reader.read_string_bytes()?;
    let decoded_signature_key = decode_plain_public_key_blob(&signature_key_blob)?;
    let signature_key_is_ed25519 = matches!(&decoded_signature_key.kind, PublicKeyKind::Ed25519(_));
    let signed_len = reader.position();
    let signature_blob = reader.read_string_bytes()?;
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    if signature_key_is_ed25519 {
        validate_ed25519_signature_blob(&signature_blob)?;
    }

    Ok(ParsedCertificate {
        certificate: Certificate {
            algorithm,
            nonce,
            subject_public_key,
            serial,
            role: certificate_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options: critical.options,
            extensions,
            source_address: critical.source_address,
            force_command: critical.force_command,
            signature_key: decoded_signature_key.blob,
        },
        signed_len,
        signature_blob,
    })
}

fn is_positive_mpint(value: &[u8]) -> bool {
    value.first().is_some_and(|byte| byte & 0x80 == 0)
}

fn write_positive_mpint(writer: &mut Writer, value: &[u8]) -> Result<(), WireError> {
    let mut positive = value.to_vec();
    if positive.first().is_some_and(|byte| byte & 0x80 != 0) {
        positive.insert(0, 0);
    }
    writer.write_mpint(positive.as_slice())
}

fn parse_subject_public_key(
    reader: &mut Reader<'_>,
    algorithm: CertificateAlgorithm,
) -> Result<SubjectPublicKey, CertificateError> {
    match algorithm {
        CertificateAlgorithm::Ed25519 => {
            let point = reader.read_string()?;
            if point.len() != ED25519_PUBLIC_KEY_LENGTH {
                return Err(CertificateError::InvalidFieldLength);
            }
            let point: [u8; ED25519_PUBLIC_KEY_LENGTH] = point
                .try_into()
                .map_err(|_| CertificateError::InvalidFieldLength)?;
            ed25519_verifying_key(&point)?;
            let blob = encode_ed25519_blob(&point)?;
            Ok(SubjectPublicKey {
                blob,
                ed25519_point: Some(point),
            })
        }
        CertificateAlgorithm::Rsa => {
            let exponent = reader.read_mpint()?.to_vec();
            let modulus = reader.read_mpint()?.to_vec();
            if !is_positive_mpint(&exponent) || !is_positive_mpint(&modulus) {
                return Err(CertificateError::InvalidPublicKey);
            }
            let (blob, _public_key) = decode_rsa_components(&exponent, &modulus)?;
            Ok(SubjectPublicKey {
                blob,
                ed25519_point: None,
            })
        }
        CertificateAlgorithm::EcdsaP256
        | CertificateAlgorithm::EcdsaP384
        | CertificateAlgorithm::EcdsaP521 => {
            let curve_name = reader.read_string()?.to_vec();
            let expected_curve = algorithm
                .curve_name()
                .ok_or(CertificateError::UnsupportedAlgorithm)?;
            if curve_name != expected_curve.as_bytes() {
                return Err(CertificateError::InvalidPublicKey);
            }
            let point = reader.read_string()?.to_vec();
            validate_ecdsa_point(algorithm, &point)?;
            let mut writer = Writer::new();
            writer.write_string(algorithm.public_key_algorithm())?;
            writer.write_string(curve_name.as_slice())?;
            writer.write_string(point.as_slice())?;
            Ok(SubjectPublicKey {
                blob: writer.into_bytes(),
                ed25519_point: None,
            })
        }
    }
}

fn parse_principals(encoded: &[u8]) -> Result<Vec<String>, CertificateError> {
    let mut reader = Reader::new(encoded);
    let mut principals = Vec::new();
    while !reader.is_empty() {
        let principal = String::from_utf8(reader.read_string_bytes()?)
            .map_err(|_| CertificateError::InvalidPrincipal)?;
        principals.push(principal);
    }
    Ok(principals)
}

fn parse_critical_options(encoded: &[u8]) -> Result<ParsedCriticalOptions, CertificateError> {
    let options = parse_options(encoded, true)?;
    let mut source_address = None;
    let mut force_command = None;

    for option in &options {
        if option.name == CRITICAL_OPTION_SOURCE_ADDRESS {
            source_address = Some(parse_nested_option_value(&option.data)?);
        } else if option.name == CRITICAL_OPTION_FORCE_COMMAND {
            force_command = Some(parse_nested_option_value(&option.data)?);
        }
    }

    Ok(ParsedCriticalOptions {
        options,
        source_address,
        force_command,
    })
}

fn parse_extensions(encoded: &[u8]) -> Result<Vec<CertificateOption>, CertificateError> {
    parse_options(encoded, false)
}

fn parse_options(
    encoded: &[u8],
    critical: bool,
) -> Result<Vec<CertificateOption>, CertificateError> {
    let mut reader = Reader::new(encoded);
    let mut options = Vec::new();
    let mut previous_name: Option<String> = None;

    while !reader.is_empty() {
        let name_bytes = reader.read_string_bytes().map_err(|error| {
            if critical {
                CertificateError::from(error)
            } else {
                CertificateError::InvalidExtension
            }
        })?;
        let name =
            String::from_utf8(name_bytes).map_err(|_| CertificateError::InvalidOptionName)?;
        if let Some(previous) = &previous_name {
            if name == *previous {
                return Err(CertificateError::DuplicateOption);
            }
            if name.as_bytes() < previous.as_bytes() {
                return Err(CertificateError::UnsortedOptions);
            }
        }

        let data = reader.read_string_bytes().map_err(|error| {
            if critical {
                CertificateError::from(error)
            } else {
                CertificateError::InvalidExtension
            }
        })?;
        previous_name = Some(name.clone());
        options.push(CertificateOption { name, data });
    }

    Ok(options)
}

fn parse_nested_option_value(data: &[u8]) -> Result<Vec<u8>, CertificateError> {
    let mut reader = Reader::new(data);
    let value = reader
        .read_string_bytes()
        .map_err(|_| CertificateError::InvalidCriticalOption)?;
    if !reader.is_empty() {
        return Err(CertificateError::InvalidCriticalOption);
    }
    Ok(value)
}

fn decode_plain_public_key_blob(blob: &[u8]) -> Result<DecodedPublicKey, CertificateError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if is_certificate_algorithm(algorithm) {
        return Err(CertificateError::CertificateSignatureKey);
    }

    let (canonical_blob, kind) = match algorithm {
        value if value == SSH_ED25519.as_bytes() => decode_ed25519_public_key(blob)?,
        value if value == SSH_RSA.as_bytes() => decode_rsa_public_key(blob)?,
        value if value == SSH_ECDSA_SHA2_NISTP256.as_bytes() => {
            decode_ecdsa_public_key(blob, CertificateAlgorithm::EcdsaP256)?
        }
        value if value == SSH_ECDSA_SHA2_NISTP384.as_bytes() => {
            decode_ecdsa_public_key(blob, CertificateAlgorithm::EcdsaP384)?
        }
        value if value == SSH_ECDSA_SHA2_NISTP521.as_bytes() => {
            decode_ecdsa_public_key(blob, CertificateAlgorithm::EcdsaP521)?
        }
        _ => return Err(CertificateError::UnsupportedAlgorithm),
    };

    if canonical_blob.as_slice() != blob {
        return Err(CertificateError::TrailingData);
    }
    Ok(DecodedPublicKey {
        blob: canonical_blob,
        kind,
    })
}

fn decode_ca_public_key(blob: &[u8]) -> Result<DecodedPublicKey, CertificateError> {
    if blob.len() == ED25519_PUBLIC_KEY_LENGTH {
        let point: [u8; ED25519_PUBLIC_KEY_LENGTH] = blob
            .try_into()
            .map_err(|_| CertificateError::InvalidCaPublicKey)?;
        let public_key =
            ed25519_verifying_key(&point).map_err(|_error| CertificateError::InvalidCaPublicKey)?;
        let canonical_blob =
            encode_ed25519_blob(&point).map_err(|_error| CertificateError::InvalidCaPublicKey)?;
        return Ok(DecodedPublicKey {
            blob: canonical_blob,
            kind: PublicKeyKind::Ed25519(public_key),
        });
    }

    decode_plain_public_key_blob(blob).map_err(|_error| CertificateError::InvalidCaPublicKey)
}

fn verify_public_key_signature(
    public_key: &DecodedPublicKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    match &public_key.kind {
        PublicKeyKind::Ed25519(key) => verify_ed25519(key, signature_blob, signed_bytes),
        PublicKeyKind::Rsa(key) => verify_rsa(key, signature_blob, signed_bytes),
        PublicKeyKind::EcdsaP256(key) => verify_ecdsa_p256(key, signature_blob, signed_bytes),
        PublicKeyKind::EcdsaP384(key) => verify_ecdsa_p384(key, signature_blob, signed_bytes),
        PublicKeyKind::EcdsaP521(key) => verify_ecdsa_p521(key, signature_blob, signed_bytes),
    }
}

fn validate_ed25519_signature_blob(blob: &[u8]) -> Result<(), CertificateError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != SSH_ED25519.as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let signature = reader.read_string()?;
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(CertificateError::InvalidFieldLength);
    }
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    Ok(())
}

fn is_certificate_algorithm(algorithm: &[u8]) -> bool {
    algorithm.ends_with(b"-cert-v01@openssh.com")
        || algorithm.ends_with(b"-cert")
        || algorithm.ends_with(b"-cert-v01")
}

fn ed25519_verifying_key(
    point: &[u8; ED25519_PUBLIC_KEY_LENGTH],
) -> Result<ed25519_dalek::VerifyingKey, CertificateError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(point)
        .map_err(|_| CertificateError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(CertificateError::InvalidPublicKey);
    }
    Ok(key)
}

fn encode_ed25519_blob(
    point: &[u8; ED25519_PUBLIC_KEY_LENGTH],
) -> Result<Vec<u8>, CertificateError> {
    let mut writer = Writer::new();
    writer.write_string(SSH_ED25519)?;
    writer.write_string(point)?;
    Ok(writer.into_bytes())
}

fn decode_ed25519_public_key(blob: &[u8]) -> Result<(Vec<u8>, PublicKeyKind), CertificateError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != SSH_ED25519.as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let point = reader.read_string()?;
    if point.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(CertificateError::InvalidFieldLength);
    }
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    let point: [u8; ED25519_PUBLIC_KEY_LENGTH] = point
        .try_into()
        .map_err(|_| CertificateError::InvalidFieldLength)?;
    let key = ed25519_verifying_key(&point)?;
    let canonical_blob = encode_ed25519_blob(&point)?;
    Ok((canonical_blob, PublicKeyKind::Ed25519(key)))
}

fn decode_rsa_components(
    exponent: &[u8],
    modulus: &[u8],
) -> Result<(Vec<u8>, rsa::RsaPublicKey), CertificateError> {
    if !is_positive_mpint(exponent) || !is_positive_mpint(modulus) {
        return Err(CertificateError::InvalidPublicKey);
    }
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| CertificateError::InvalidPublicKey)?;
    Ok((encode_rsa_blob(&key)?, key))
}

fn decode_rsa_public_key(blob: &[u8]) -> Result<(Vec<u8>, PublicKeyKind), CertificateError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != SSH_RSA.as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let exponent = reader.read_mpint()?.to_vec();
    let modulus = reader.read_mpint()?.to_vec();
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    let (canonical_blob, key) = decode_rsa_components(&exponent, &modulus)?;
    Ok((canonical_blob, PublicKeyKind::Rsa(key)))
}

fn encode_rsa_blob(key: &rsa::RsaPublicKey) -> Result<Vec<u8>, CertificateError> {
    let mut writer = Writer::new();
    writer.write_string(SSH_RSA)?;
    write_positive_mpint(&mut writer, &key.e().to_bytes_be())?;
    write_positive_mpint(&mut writer, &key.n().to_bytes_be())?;
    Ok(writer.into_bytes())
}

fn validate_ecdsa_point(
    algorithm: CertificateAlgorithm,
    point: &[u8],
) -> Result<(), CertificateError> {
    let expected_length = match algorithm {
        CertificateAlgorithm::EcdsaP256 => P256_POINT_LENGTH,
        CertificateAlgorithm::EcdsaP384 => P384_POINT_LENGTH,
        CertificateAlgorithm::EcdsaP521 => P521_POINT_LENGTH,
        CertificateAlgorithm::Ed25519 | CertificateAlgorithm::Rsa => {
            return Err(CertificateError::UnsupportedAlgorithm);
        }
    };
    if point.len() != expected_length {
        return Err(CertificateError::InvalidFieldLength);
    }
    if point.first() != Some(&ECDSA_UNCOMPRESSED_POINT_TAG) {
        return Err(CertificateError::InvalidPublicKey);
    }
    let valid = match algorithm {
        CertificateAlgorithm::EcdsaP256 => {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok()
        }
        CertificateAlgorithm::EcdsaP384 => {
            p384::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok()
        }
        CertificateAlgorithm::EcdsaP521 => {
            p521::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok()
        }
        CertificateAlgorithm::Ed25519 | CertificateAlgorithm::Rsa => false,
    };
    if valid {
        Ok(())
    } else {
        Err(CertificateError::InvalidPublicKey)
    }
}

fn decode_ecdsa_public_key(
    blob: &[u8],
    algorithm: CertificateAlgorithm,
) -> Result<(Vec<u8>, PublicKeyKind), CertificateError> {
    let mut reader = Reader::new(blob);
    let key_algorithm = reader.read_string()?;
    if key_algorithm != algorithm.public_key_algorithm().as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let curve_name = reader.read_string()?;
    let expected_curve = algorithm
        .curve_name()
        .ok_or(CertificateError::UnsupportedAlgorithm)?;
    if curve_name != expected_curve.as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let point = reader.read_string()?.to_vec();
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    validate_ecdsa_point(algorithm, &point)?;
    let mut writer = Writer::new();
    writer.write_string(algorithm.public_key_algorithm())?;
    writer.write_string(expected_curve)?;
    writer.write_string(point.as_slice())?;
    let canonical_blob = writer.into_bytes();
    let kind = match algorithm {
        CertificateAlgorithm::EcdsaP256 => PublicKeyKind::EcdsaP256(
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| CertificateError::InvalidPublicKey)?,
        ),
        CertificateAlgorithm::EcdsaP384 => PublicKeyKind::EcdsaP384(
            p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| CertificateError::InvalidPublicKey)?,
        ),
        CertificateAlgorithm::EcdsaP521 => PublicKeyKind::EcdsaP521(
            p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| CertificateError::InvalidPublicKey)?,
        ),
        CertificateAlgorithm::Ed25519 | CertificateAlgorithm::Rsa => {
            return Err(CertificateError::UnsupportedAlgorithm);
        }
    };
    Ok((canonical_blob, kind))
}

fn verify_ed25519(
    key: &ed25519_dalek::VerifyingKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    validate_ed25519_signature_blob(signature_blob)?;
    let mut reader = Reader::new(signature_blob);
    let _algorithm = reader.read_string()?;
    let signature = reader.read_string()?;
    let signature = ed25519_dalek::Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| CertificateError::InvalidFieldLength)?,
    );
    key.verify_strict(signed_bytes, &signature)
        .map_err(|_| CertificateError::InvalidSignature)
}

fn verify_rsa(
    key: &rsa::RsaPublicKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    let mut reader = Reader::new(signature_blob);
    let algorithm = std::str::from_utf8(reader.read_string()?)
        .map_err(|_| CertificateError::UnsupportedAlgorithm)?;
    let signature = reader.read_string()?;
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    if signature.is_empty() || signature.len() != key.size() {
        return Err(CertificateError::InvalidFieldLength);
    }
    match algorithm {
        RSA_SHA2_256 => {
            let digest = sha2::Sha256::digest(signed_bytes);
            key.verify(
                rsa::Pkcs1v15Sign::new_unprefixed(),
                digest.as_slice(),
                signature,
            )
        }
        RSA_SHA2_512 => {
            let digest = sha2::Sha512::digest(signed_bytes);
            key.verify(
                rsa::Pkcs1v15Sign::new_unprefixed(),
                digest.as_slice(),
                signature,
            )
        }
        _ => return Err(CertificateError::UnsupportedAlgorithm),
    }
    .map_err(|_| CertificateError::InvalidSignature)
}

fn verify_ecdsa_p256(
    key: &p256::ecdsa::VerifyingKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    let (r, s) =
        decode_ecdsa_scalars::<P256_SCALAR_LENGTH>(signature_blob, SSH_ECDSA_SHA2_NISTP256)?;
    let signature = p256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| CertificateError::InvalidSignature)?;
    let digest = sha2::Sha256::digest(signed_bytes);
    P256PrehashVerifier::verify_prehash(key, digest.as_slice(), &signature)
        .map_err(|_| CertificateError::InvalidSignature)
}

fn verify_ecdsa_p384(
    key: &p384::ecdsa::VerifyingKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    let (r, s) =
        decode_ecdsa_scalars::<P384_SCALAR_LENGTH>(signature_blob, SSH_ECDSA_SHA2_NISTP384)?;
    let signature = p384::ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| CertificateError::InvalidSignature)?;
    let digest = sha2::Sha384::digest(signed_bytes);
    P384PrehashVerifier::verify_prehash(key, digest.as_slice(), &signature)
        .map_err(|_| CertificateError::InvalidSignature)
}

fn verify_ecdsa_p521(
    key: &p521::ecdsa::VerifyingKey,
    signature_blob: &[u8],
    signed_bytes: &[u8],
) -> Result<(), CertificateError> {
    let (r, s) =
        decode_ecdsa_scalars::<P521_SCALAR_LENGTH>(signature_blob, SSH_ECDSA_SHA2_NISTP521)?;
    let signature = p521::ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| CertificateError::InvalidSignature)?;
    let digest = sha2::Sha512::digest(signed_bytes);
    P521PrehashVerifier::verify_prehash(key, digest.as_slice(), &signature)
        .map_err(|_| CertificateError::InvalidSignature)
}

fn decode_ecdsa_scalars<const N: usize>(
    blob: &[u8],
    expected_algorithm: &str,
) -> Result<([u8; N], [u8; N]), CertificateError> {
    if blob.len() == N * 2 {
        return Err(CertificateError::InvalidFieldLength);
    }
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string()?;
    if algorithm != expected_algorithm.as_bytes() {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    let signature_body = reader.read_string()?;
    if !reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    let mut signature_reader = Reader::new(signature_body);
    let r = read_positive_scalar::<N>(&mut signature_reader)?;
    let s = read_positive_scalar::<N>(&mut signature_reader)?;
    if !signature_reader.is_empty() {
        return Err(CertificateError::TrailingData);
    }
    Ok((r, s))
}

fn read_positive_scalar<const N: usize>(
    reader: &mut Reader<'_>,
) -> Result<[u8; N], CertificateError> {
    let encoded = reader.read_mpint()?;
    let Some(first) = encoded.first().copied() else {
        return Err(CertificateError::InvalidSignature);
    };
    if first & 0x80 != 0 {
        return Err(CertificateError::InvalidSignature);
    }
    let magnitude = if encoded.len() == N + 1 && encoded.first() == Some(&0) {
        encoded.get(1..).ok_or(CertificateError::InvalidSignature)?
    } else {
        encoded
    };
    if magnitude.is_empty() || magnitude.len() > N {
        return Err(CertificateError::InvalidSignature);
    }
    let mut scalar = [0_u8; N];
    let offset = N
        .checked_sub(magnitude.len())
        .ok_or(CertificateError::InvalidSignature)?;
    let destination = scalar
        .get_mut(offset..)
        .ok_or(CertificateError::InvalidSignature)?;
    destination.copy_from_slice(magnitude);
    Ok(scalar)
}

fn verify_policy(
    certificate: &Certificate,
    expected_type: CertificateType,
    expected_principal: &str,
    now: u64,
    allowed_critical_options: &[&str],
) -> Result<(), CertificateError> {
    for option in &certificate.critical_options {
        if !allowed_critical_options
            .iter()
            .any(|allowed| *allowed == option.name)
        {
            return Err(CertificateError::CriticalOptionNotAllowed);
        }
    }

    if certificate.role != expected_type {
        return Err(CertificateError::TypeMismatch);
    }
    if now < certificate.valid_after {
        return Err(CertificateError::NotYetValid);
    }
    if now >= certificate.valid_before {
        return Err(CertificateError::Expired);
    }
    if !certificate
        .principals
        .iter()
        .any(|principal| principal == expected_principal)
    {
        return Err(CertificateError::PrincipalMismatch);
    }
    Ok(())
}
