//! Conversion between X.509 certificates and OpenSSH v01 certificates.
//!
//! The OpenSSH certificate format is distinct from the RFC 6187 public-key
//! wire format in [`crate::ssh`]. This module supports Ed25519, RSA, and P-256
//! certified keys. Every certificate signature must be an Ed25519 signature
//! made by the certificate's Ed25519 authority key.

use core::convert::TryFrom;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::ED25519_ALGORITHM_IDENTIFIER;

const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_CURVE_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const ED25519_CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
const RSA_CERT_TYPE: &str = "ssh-rsa-cert-v01@openssh.com";
const P256_CERT_TYPE: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
const ED25519_KEY_TYPE: &str = "ssh-ed25519";
const P256_KEY_TYPE: &str = "nistp256";

const RSA_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
const P256_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_CONTEXT: u8 = 2;

const TAG_INTEGER: u32 = 2;
const TAG_BIT_STRING: u32 = 3;
const TAG_NULL: u32 = 5;
const TAG_OID: u32 = 6;
const TAG_UTC_TIME: u32 = 23;
const TAG_GENERALIZED_TIME: u32 = 24;
const TAG_SEQUENCE: u32 = 16;

const MAX_DER_DEPTH: usize = 64;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const P256_POINT_LENGTH: usize = 65;
const NONCE_MAX_LENGTH: usize = 64;

/// The user or host role encoded by an OpenSSH certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OpenSshCertKind {
    /// A user certificate (`type` 1).
    User = 1,
    /// A host certificate (`type` 2).
    Host = 2,
}

/// The long-form name for [`OpenSshCertKind`].
pub type OpenSshCertificateKind = OpenSshCertKind;

/// A public key carried by a supported OpenSSH v01 certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertifiedPublicKey {
    /// An Ed25519 public key.
    Ed25519([u8; ED25519_PUBLIC_KEY_LENGTH]),
    /// An RSA public key represented by unsigned, minimal big-endian integers.
    ///
    /// The OpenSSH wire order is exponent followed by modulus.
    Rsa {
        /// The RSA public exponent.
        exponent: Vec<u8>,
        /// The positive RSA modulus.
        modulus: Vec<u8>,
    },
    /// An uncompressed NIST P-256 point (`0x04 || X || Y`).
    EcdsaP256([u8; P256_POINT_LENGTH]),
}

/// A parsed and signature-verified OpenSSH v01 certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSshCertificate {
    /// The certified public key.
    pub certified_key: CertifiedPublicKey,
    /// The certificate nonce.
    pub nonce: Vec<u8>,
    /// The certificate serial number.
    pub serial: u64,
    /// Whether this is a user or host certificate.
    pub kind: OpenSshCertKind,
    /// The human-readable key identifier.
    pub key_id: String,
    /// The principals certified by the authority.
    pub principals: Vec<String>,
    /// The inclusive start of the validity interval, in Unix seconds.
    pub valid_after: u64,
    /// The exclusive end of the validity interval, in Unix seconds.
    pub valid_before: u64,
    /// Critical option name/value tuples.
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Non-critical extension name/value tuples.
    pub extensions: Vec<(String, Vec<u8>)>,
    /// The Ed25519 certificate authority public key.
    pub signature_key: [u8; ED25519_PUBLIC_KEY_LENGTH],
    /// The Ed25519 certificate signature.
    pub signature: [u8; ED25519_SIGNATURE_LENGTH],
}

/// Certificate metadata supplied when converting X.509 to OpenSSH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSshCertRequest {
    /// Whether to issue a user or host certificate.
    pub kind: OpenSshCertKind,
    /// The OpenSSH certificate serial number.
    pub serial: u64,
    /// The human-readable key identifier.
    pub key_id: String,
    /// The principals certified by the authority.
    pub principals: Vec<String>,
    /// A nonce between 1 and 64 bytes, inclusive.
    pub nonce: Vec<u8>,
    /// Critical option name/value tuples.
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Non-critical extension name/value tuples.
    pub extensions: Vec<(String, Vec<u8>)>,
}

/// The public identity recovered from an OpenSSH certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509Identity {
    /// A DER SubjectPublicKeyInfo for the certified key.
    pub subject_public_key_info: Vec<u8>,
    /// Whether the certificate is for a user or host.
    pub kind: OpenSshCertKind,
    /// The certificate serial number.
    pub serial: u64,
    /// The human-readable key identifier.
    pub key_id: String,
    /// The principals certified by the authority.
    pub principals: Vec<String>,
    /// The inclusive start of the validity interval, in Unix seconds.
    pub valid_after: u64,
    /// The exclusive end of the validity interval, in Unix seconds.
    pub valid_before: u64,
}

/// An error converting an X.509 or OpenSSH v01 certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenSshCertError {
    /// The certificate is malformed or structurally invalid.
    InvalidCertificate,
    /// A certificate or public-key algorithm is not supported.
    UnsupportedAlgorithm,
    /// SSH framing or encoded field content is invalid.
    InvalidSsh,
    /// An X.509 time cannot be represented as a Unix timestamp.
    ///
    /// One variant covers every way a validity field can fail: a field that is
    /// missing or is not a `UTCTime` or a `GeneralizedTime`, a field whose
    /// encoding is wrong, digits that do not name an instant, and an instant
    /// outside the `u64` seconds an OpenSSH validity field carries. Which one it
    /// was is recorded internally and is not yet published, so a caller is told
    /// that a time is the problem and not which of the two fields was.
    InvalidTime,
    /// The Ed25519 certificate signature is invalid.
    BadSignature,
}

impl std::fmt::Display for OpenSshCertError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificate => formatter.write_str("invalid X.509 or OpenSSH certificate"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("unsupported OpenSSH certificate algorithm")
            }
            Self::InvalidSsh => formatter.write_str("invalid OpenSSH certificate wire format"),
            Self::InvalidTime => formatter.write_str("invalid X.509 certificate time"),
            Self::BadSignature => formatter.write_str("invalid OpenSSH certificate signature"),
        }
    }
}

impl std::error::Error for OpenSshCertError {}

/// Converts a DER X.509 certificate into a signed OpenSSH v01 certificate.
///
/// The X.509 certificate supplies the certified public key and validity
/// window. All other OpenSSH metadata comes from `request`. The X.509
/// certificate signature is not validated.
///
/// # The validity window
///
/// Both ASN.1 time types a validity field can hold are read: a `UTCTime`,
/// whose two-digit year is expanded through the 1950 pivot, and a
/// `GeneralizedTime`, whose four-digit year RFC 5280 §4.1.2.5 requires for a
/// date on or after 2050 and which is the only one of the two that can name a
/// date before 1950. Both are Zulu time with seconds; the offsets and the
/// reduced-precision forms the RFC also permits are rejected, as is a date the
/// OpenSSH validity fields cannot carry — an OpenSSH `valid_after` and
/// `valid_before` are `u64` seconds since the Unix epoch, so a validity date
/// before 1970 has no representation and is rejected rather than wrapped. That
/// is a property of the wire format rather than of this parser, and it is why a
/// `GeneralizedTime` before 1950 is still refused after its year is read
/// correctly.
///
/// # Errors
///
/// Returns an error for malformed X.509 DER or times, unsupported public-key
/// algorithms, invalid request values, or an internal signing error.
pub fn x509_to_openssh_certificate(
    certificate_der: &[u8],
    request: &OpenSshCertRequest,
    ca_seed: &[u8; 32],
) -> Result<Vec<u8>, OpenSshCertError> {
    let parsed = parse_x509_certificate(certificate_der)?;
    let mut certificate = OpenSshCertificate {
        certified_key: parsed.certified_key,
        nonce: request.nonce.clone(),
        serial: request.serial,
        kind: request.kind,
        key_id: request.key_id.clone(),
        principals: request.principals.clone(),
        valid_after: parsed.valid_after,
        valid_before: parsed.valid_before,
        critical_options: request.critical_options.clone(),
        extensions: request.extensions.clone(),
        signature_key: [0; ED25519_PUBLIC_KEY_LENGTH],
        signature: [0; ED25519_SIGNATURE_LENGTH],
    };

    let seed_copy = Zeroizing::new(*ca_seed);
    let signing_key = SigningKey::from_bytes(&seed_copy);
    certificate.signature_key = signing_key.verifying_key().to_bytes();
    let signed_data = encode_signed_data(&certificate)?;
    let signature = signing_key
        .try_sign(&signed_data)
        .map_err(|_| OpenSshCertError::InvalidCertificate)?;
    certificate.signature = signature.to_bytes();
    to_wire(&certificate)
}

/// Parses an OpenSSH v01 certificate and verifies its Ed25519 signature.
///
/// RSA and P-256 certificates are accepted only when the certificate signature
/// and signature key use `ssh-ed25519`.
///
/// # Errors
///
/// Returns an error for malformed SSH framing or certificate fields, an
/// unsupported certificate or signature algorithm, a non-empty reserved
/// field, trailing data, an invalid public key, or a bad certificate
/// signature.
pub fn parse(blob: &[u8]) -> Result<OpenSshCertificate, OpenSshCertError> {
    let mut remaining = blob;
    let certificate_type = read_ssh_string(&mut remaining)?;
    validate_certificate_type(certificate_type)?;
    let nonce = read_ssh_string(&mut remaining)?.to_vec();
    validate_nonce(&nonce)?;
    let certified_key = parse_certificate_key(certificate_type, &mut remaining)?;

    let serial = read_u64(&mut remaining)?;
    let type_value = read_u32(&mut remaining)?;
    let kind = match type_value {
        1 => OpenSshCertKind::User,
        2 => OpenSshCertKind::Host,
        _ => return Err(OpenSshCertError::InvalidCertificate),
    };
    let key_id = read_utf8_string(&mut remaining)?;
    let principals = parse_principals(read_ssh_string(&mut remaining)?)?;
    let valid_after = read_u64(&mut remaining)?;
    let valid_before = read_u64(&mut remaining)?;
    let critical_options = parse_tuples(read_ssh_string(&mut remaining)?)?;
    let extensions = parse_tuples(read_ssh_string(&mut remaining)?)?;
    let reserved = read_ssh_string(&mut remaining)?;
    if !reserved.is_empty() {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let signature_key = parse_signature_key(read_ssh_string(&mut remaining)?)?;
    let signed_data_length = blob
        .len()
        .checked_sub(remaining.len())
        .ok_or(OpenSshCertError::InvalidSsh)?;
    let signed_data = blob
        .get(..signed_data_length)
        .ok_or(OpenSshCertError::InvalidSsh)?;
    let signature = parse_signature(read_ssh_string(&mut remaining)?)?;
    if !remaining.is_empty() {
        return Err(OpenSshCertError::InvalidSsh);
    }
    verify_signature(&signature_key, &signature, signed_data)?;

    Ok(OpenSshCertificate {
        certified_key,
        nonce,
        serial,
        kind,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        signature_key,
        signature,
    })
}

/// Encodes an OpenSSH v01 certificate after re-verifying its signature.
///
/// A certificate whose fields do not agree with its stored Ed25519 signature
/// is rejected with [`OpenSshCertError::BadSignature`]. The reserved field is
/// always encoded as empty.
///
/// # Errors
///
/// Returns an error for invalid field values, SSH fields too large to encode,
/// or a bad Ed25519 signature.
pub fn to_wire(certificate: &OpenSshCertificate) -> Result<Vec<u8>, OpenSshCertError> {
    let signed_data = encode_signed_data(certificate)?;
    verify_signature(
        &certificate.signature_key,
        &certificate.signature,
        &signed_data,
    )?;

    let signature_blob = build_signature_blob(&certificate.signature)?;
    let mut wire = signed_data;
    write_ssh_string(&mut wire, &signature_blob)?;
    Ok(wire)
}

/// Recovers the public X.509 identity carried by an OpenSSH certificate.
///
/// This function emits a DER SubjectPublicKeyInfo, not a signed X.509
/// certificate. The returned identity also contains the OpenSSH validity and
/// principal metadata.
///
/// # Errors
///
/// Returns an error for malformed or unsupported OpenSSH certificates, a bad
/// Ed25519 signature, or a certified key that cannot be represented as a DER
/// SubjectPublicKeyInfo.
pub fn openssh_certificate_to_x509_identity(blob: &[u8]) -> Result<X509Identity, OpenSshCertError> {
    let certificate = parse(blob)?;
    let subject_public_key_info = build_subject_public_key_info(&certificate.certified_key)?;
    Ok(X509Identity {
        subject_public_key_info,
        kind: certificate.kind,
        serial: certificate.serial,
        key_id: certificate.key_id,
        principals: certificate.principals,
        valid_after: certificate.valid_after,
        valid_before: certificate.valid_before,
    })
}

struct X509KeyAndValidity {
    certified_key: CertifiedPublicKey,
    valid_after: u64,
    valid_before: u64,
}

fn parse_x509_certificate(der: &[u8]) -> Result<X509KeyAndValidity, OpenSshCertError> {
    let certificate = validate_der_tree(der).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(certificate, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let mut certificate_fields = certificate.content;
    let tbs_certificate =
        next_tlv(&mut certificate_fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(tbs_certificate, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let signature_algorithm =
        next_tlv(&mut certificate_fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    parse_algorithm_identifier(signature_algorithm)
        .map_err(|()| OpenSshCertError::InvalidCertificate)?;

    let signature_value =
        next_tlv(&mut certificate_fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(signature_value, CLASS_UNIVERSAL, TAG_BIT_STRING, false) {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    if !certificate_fields.is_empty() {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    parse_tbs_certificate(tbs_certificate)
}

fn parse_tbs_certificate(tbs_certificate: Tlv<'_>) -> Result<X509KeyAndValidity, OpenSshCertError> {
    let mut fields = tbs_certificate.content;
    let first = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    let serial = if has_tag(first, CLASS_CONTEXT, 0, true) {
        parse_version(first)?;
        next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?
    } else {
        first
    };
    if !has_tag(serial, CLASS_UNIVERSAL, TAG_INTEGER, false)
        || !valid_integer_content(serial.content)
    {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let tbs_signature_algorithm =
        next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    parse_algorithm_identifier(tbs_signature_algorithm)
        .map_err(|()| OpenSshCertError::InvalidCertificate)?;

    let issuer = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(issuer, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let validity = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(validity, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    let (valid_after, valid_before) = parse_validity(validity)?;

    let subject = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(subject, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let subject_public_key_info =
        next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    let certified_key = parse_subject_public_key_info(subject_public_key_info)?;

    let mut previous_optional_tag = 0;
    while !fields.is_empty() {
        let optional = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
        if optional.class != CLASS_CONTEXT
            || optional.number == 0
            || optional.number > 3
            || optional.number <= previous_optional_tag
        {
            return Err(OpenSshCertError::InvalidCertificate);
        }
        match optional.number {
            1 | 2 if optional.constructed => return Err(OpenSshCertError::InvalidCertificate),
            3 if !optional.constructed => return Err(OpenSshCertError::InvalidCertificate),
            _ => {}
        }
        previous_optional_tag = optional.number;
    }

    Ok(X509KeyAndValidity {
        certified_key,
        valid_after,
        valid_before,
    })
}

fn parse_version(version: Tlv<'_>) -> Result<(), OpenSshCertError> {
    if !has_tag(version, CLASS_CONTEXT, 0, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    let mut fields = version.content;
    let value = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(value, CLASS_UNIVERSAL, TAG_INTEGER, false)
        || !fields.is_empty()
        || !valid_integer_content(value.content)
    {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    if value.content != [0] && value.content != [1] && value.content != [2] {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    Ok(())
}

fn parse_validity(validity: Tlv<'_>) -> Result<(u64, u64), TimeError> {
    let mut fields = validity.content;
    let not_before = next_tlv(&mut fields)
        .map_err(|()| TimeError::new(ValidityField::NotBefore, TimeFault::Missing))?;
    if !is_a_time(not_before) {
        return Err(TimeError::new(
            ValidityField::NotBefore,
            TimeFault::NotATime,
        ));
    }
    let valid_after = parse_x509_time(not_before, ValidityField::NotBefore)?;

    let not_after = next_tlv(&mut fields)
        .map_err(|()| TimeError::new(ValidityField::NotAfter, TimeFault::Missing))?;
    if !is_a_time(not_after) {
        return Err(TimeError::new(ValidityField::NotAfter, TimeFault::NotATime));
    }
    let valid_before = parse_x509_time(not_after, ValidityField::NotAfter)?;
    if !fields.is_empty() {
        return Err(TimeError::new(
            ValidityField::NotAfter,
            TimeFault::TrailingData,
        ));
    }
    Ok((valid_after, valid_before))
}

/// Reports whether a TLV is one of the two ASN.1 time types RFC 5280 allows in
/// a validity field.
fn is_a_time(tlv: Tlv<'_>) -> bool {
    has_tag(tlv, CLASS_UNIVERSAL, TAG_UTC_TIME, false)
        || has_tag(tlv, CLASS_UNIVERSAL, TAG_GENERALIZED_TIME, false)
}

fn parse_subject_public_key_info(
    subject_public_key_info: Tlv<'_>,
) -> Result<CertifiedPublicKey, OpenSshCertError> {
    if !has_tag(subject_public_key_info, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let mut fields = subject_public_key_info.content;
    let algorithm = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    let identifier =
        parse_algorithm_identifier(algorithm).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    let subject_public_key =
        next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(subject_public_key, CLASS_UNIVERSAL, TAG_BIT_STRING, false) || !fields.is_empty() {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    parse_spki_key(identifier, subject_public_key)
}

fn parse_algorithm_identifier(algorithm: Tlv<'_>) -> Result<(&[u8], Option<Tlv<'_>>), ()> {
    if !has_tag(algorithm, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(());
    }

    let mut fields = algorithm.content;
    let oid = next_tlv(&mut fields)?;
    if !has_tag(oid, CLASS_UNIVERSAL, TAG_OID, false) || !valid_oid_content(oid.content) {
        return Err(());
    }
    let parameters = if fields.is_empty() {
        None
    } else {
        let parameters = next_tlv(&mut fields)?;
        if !fields.is_empty() {
            return Err(());
        }
        Some(parameters)
    };
    Ok((oid.content, parameters))
}

fn parse_spki_key(
    algorithm: (&[u8], Option<Tlv<'_>>),
    subject_public_key: Tlv<'_>,
) -> Result<CertifiedPublicKey, OpenSshCertError> {
    let (oid, parameters) = algorithm;
    if oid == ED25519_OID {
        if parameters.is_some() {
            return Err(OpenSshCertError::InvalidCertificate);
        }
        let key = bit_string_with_unused_bits(subject_public_key, 0)?;
        return copy_array::<ED25519_PUBLIC_KEY_LENGTH>(&key)
            .map(CertifiedPublicKey::Ed25519)
            .map_err(|()| OpenSshCertError::InvalidCertificate);
    }

    if oid == RSA_OID {
        match parameters {
            None => {}
            Some(parameters)
                if has_tag(parameters, CLASS_UNIVERSAL, TAG_NULL, false)
                    && parameters.content.is_empty() => {}
            Some(_) => return Err(OpenSshCertError::InvalidCertificate),
        }
        let rsa_public_key = bit_string_with_unused_bits(subject_public_key, 0)?;
        let (exponent, modulus) = parse_rsa_public_key(&rsa_public_key)?;
        return Ok(CertifiedPublicKey::Rsa { exponent, modulus });
    }

    if oid == EC_OID {
        let Some(parameters) = parameters else {
            return Err(OpenSshCertError::InvalidCertificate);
        };
        if !has_tag(parameters, CLASS_UNIVERSAL, TAG_OID, false) {
            return Err(OpenSshCertError::InvalidCertificate);
        }
        if parameters.content != P256_CURVE_OID {
            return Err(OpenSshCertError::UnsupportedAlgorithm);
        }
        let point = bit_string_with_unused_bits(subject_public_key, 0)?;
        if point.len() != P256_POINT_LENGTH || point.first() != Some(&0x04) {
            return Err(OpenSshCertError::InvalidCertificate);
        }
        return copy_array::<P256_POINT_LENGTH>(&point)
            .map(CertifiedPublicKey::EcdsaP256)
            .map_err(|()| OpenSshCertError::InvalidCertificate);
    }

    Err(OpenSshCertError::UnsupportedAlgorithm)
}

fn bit_string_with_unused_bits(
    bit_string: Tlv<'_>,
    expected_unused_bits: u8,
) -> Result<Vec<u8>, OpenSshCertError> {
    if !has_tag(bit_string, CLASS_UNIVERSAL, TAG_BIT_STRING, false)
        || bit_string.content.first() != Some(&expected_unused_bits)
    {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    let payload = bit_string
        .content
        .get(1..)
        .ok_or(OpenSshCertError::InvalidCertificate)?;
    Ok(payload.to_vec())
}

fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OpenSshCertError> {
    let sequence = validate_der_tree(der).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !has_tag(sequence, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    let mut fields = sequence.content;
    let modulus = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    let exponent = next_tlv(&mut fields).map_err(|()| OpenSshCertError::InvalidCertificate)?;
    if !fields.is_empty() {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    let modulus = positive_der_integer(modulus)?;
    let exponent = positive_der_integer(exponent)?;
    Ok((exponent, modulus))
}

fn positive_der_integer(integer: Tlv<'_>) -> Result<Vec<u8>, OpenSshCertError> {
    if !has_tag(integer, CLASS_UNIVERSAL, TAG_INTEGER, false)
        || !valid_integer_content(integer.content)
    {
        return Err(OpenSshCertError::InvalidCertificate);
    }

    match integer.content.split_first() {
        Some((0, rest)) if rest.first().is_some_and(|byte| byte & 0x80 != 0) => Ok(rest.to_vec()),
        Some((first, _)) if first & 0x80 == 0 => Ok(integer.content.to_vec()),
        _ => Err(OpenSshCertError::InvalidCertificate),
    }
}

fn validate_certificate_type(certificate_type: &[u8]) -> Result<(), OpenSshCertError> {
    if certificate_type == ED25519_CERT_TYPE.as_bytes()
        || certificate_type == RSA_CERT_TYPE.as_bytes()
        || certificate_type == P256_CERT_TYPE.as_bytes()
    {
        Ok(())
    } else {
        Err(OpenSshCertError::UnsupportedAlgorithm)
    }
}

fn parse_certificate_key(
    certificate_type: &[u8],
    remaining: &mut &[u8],
) -> Result<CertifiedPublicKey, OpenSshCertError> {
    if certificate_type == ED25519_CERT_TYPE.as_bytes() {
        let key = read_ssh_string(remaining)?;
        return copy_array::<ED25519_PUBLIC_KEY_LENGTH>(key)
            .map(CertifiedPublicKey::Ed25519)
            .map_err(|()| OpenSshCertError::InvalidSsh);
    }

    if certificate_type == RSA_CERT_TYPE.as_bytes() {
        let mut values = *remaining;
        let exponent = read_ssh_mpint(&mut values)?;
        let modulus = read_ssh_mpint(&mut values)?;
        *remaining = values;
        return Ok(CertifiedPublicKey::Rsa {
            exponent: exponent.to_vec(),
            modulus: modulus.to_vec(),
        });
    }

    if certificate_type == P256_CERT_TYPE.as_bytes() {
        let mut values = *remaining;
        let curve = read_ssh_string(&mut values)?;
        if curve != P256_KEY_TYPE.as_bytes() {
            return Err(OpenSshCertError::UnsupportedAlgorithm);
        }
        let point = read_ssh_string(&mut values)?;
        *remaining = values;
        if point.len() != P256_POINT_LENGTH || point.first() != Some(&0x04) {
            return Err(OpenSshCertError::InvalidSsh);
        }
        return copy_array::<P256_POINT_LENGTH>(point)
            .map(CertifiedPublicKey::EcdsaP256)
            .map_err(|()| OpenSshCertError::InvalidSsh);
    }

    Err(OpenSshCertError::UnsupportedAlgorithm)
}

fn parse_principals(encoded: &[u8]) -> Result<Vec<String>, OpenSshCertError> {
    let mut remaining = encoded;
    let mut principals = Vec::new();
    while !remaining.is_empty() {
        principals.push(read_utf8_string(&mut remaining)?);
    }
    Ok(principals)
}

fn parse_tuples(encoded: &[u8]) -> Result<Vec<(String, Vec<u8>)>, OpenSshCertError> {
    let mut remaining = encoded;
    let mut tuples = Vec::new();
    while !remaining.is_empty() {
        let name = read_utf8_string(&mut remaining)?;
        let value = read_ssh_string(&mut remaining)?.to_vec();
        tuples.push((name, value));
    }
    Ok(tuples)
}

fn parse_signature_key(blob: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LENGTH], OpenSshCertError> {
    let mut remaining = blob;
    let algorithm = read_ssh_string(&mut remaining)?;
    if algorithm != ED25519_KEY_TYPE.as_bytes() {
        return Err(OpenSshCertError::UnsupportedAlgorithm);
    }
    let key = read_ssh_string(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(OpenSshCertError::InvalidSsh);
    }
    copy_array::<ED25519_PUBLIC_KEY_LENGTH>(key).map_err(|()| OpenSshCertError::InvalidSsh)
}

fn parse_signature(blob: &[u8]) -> Result<[u8; ED25519_SIGNATURE_LENGTH], OpenSshCertError> {
    let mut remaining = blob;
    let algorithm = read_ssh_string(&mut remaining)?;
    if algorithm != ED25519_KEY_TYPE.as_bytes() {
        return Err(OpenSshCertError::UnsupportedAlgorithm);
    }
    let signature = read_ssh_string(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(OpenSshCertError::InvalidSsh);
    }
    copy_array::<ED25519_SIGNATURE_LENGTH>(signature).map_err(|()| OpenSshCertError::BadSignature)
}

fn verify_signature(
    signature_key: &[u8; ED25519_PUBLIC_KEY_LENGTH],
    signature_bytes: &[u8; ED25519_SIGNATURE_LENGTH],
    signed_data: &[u8],
) -> Result<(), OpenSshCertError> {
    let verifying_key =
        VerifyingKey::from_bytes(signature_key).map_err(|_| OpenSshCertError::BadSignature)?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(signed_data, &signature)
        .map_err(|_| OpenSshCertError::BadSignature)
}

fn encode_signed_data(certificate: &OpenSshCertificate) -> Result<Vec<u8>, OpenSshCertError> {
    validate_nonce(&certificate.nonce)?;
    let certificate_type = certificate_type(&certificate.certified_key);
    let mut output = Vec::new();
    write_ssh_string(&mut output, certificate_type.as_bytes())?;
    write_ssh_string(&mut output, &certificate.nonce)?;

    match &certificate.certified_key {
        CertifiedPublicKey::Ed25519(key) => write_ssh_string(&mut output, key)?,
        CertifiedPublicKey::Rsa { exponent, modulus } => {
            write_ssh_mpint(&mut output, exponent)?;
            write_ssh_mpint(&mut output, modulus)?;
        }
        CertifiedPublicKey::EcdsaP256(point) => {
            write_ssh_string(&mut output, P256_KEY_TYPE.as_bytes())?;
            write_ssh_string(&mut output, point)?;
        }
    }
    output.extend_from_slice(&certificate.serial.to_be_bytes());
    output.extend_from_slice(&(certificate.kind as u32).to_be_bytes());
    write_ssh_string(&mut output, certificate.key_id.as_bytes())?;

    let mut principals = Vec::new();
    for principal in &certificate.principals {
        write_ssh_string(&mut principals, principal.as_bytes())?;
    }
    write_ssh_string(&mut output, &principals)?;
    output.extend_from_slice(&certificate.valid_after.to_be_bytes());
    output.extend_from_slice(&certificate.valid_before.to_be_bytes());

    let critical_options = encode_tuples(&certificate.critical_options)?;
    write_ssh_string(&mut output, &critical_options)?;
    let extensions = encode_tuples(&certificate.extensions)?;
    write_ssh_string(&mut output, &extensions)?;
    write_ssh_string(&mut output, &[])?;

    let signature_key = build_ed25519_key_blob(&certificate.signature_key)?;
    write_ssh_string(&mut output, &signature_key)?;
    Ok(output)
}

fn encode_tuples(tuples: &[(String, Vec<u8>)]) -> Result<Vec<u8>, OpenSshCertError> {
    let mut encoded = Vec::new();
    for (name, value) in tuples {
        write_ssh_string(&mut encoded, name.as_bytes())?;
        write_ssh_string(&mut encoded, value)?;
    }
    Ok(encoded)
}

fn certificate_type(key: &CertifiedPublicKey) -> &'static str {
    match key {
        CertifiedPublicKey::Ed25519(_) => ED25519_CERT_TYPE,
        CertifiedPublicKey::Rsa { .. } => RSA_CERT_TYPE,
        CertifiedPublicKey::EcdsaP256(_) => P256_CERT_TYPE,
    }
}

fn build_ed25519_key_blob(
    key: &[u8; ED25519_PUBLIC_KEY_LENGTH],
) -> Result<Vec<u8>, OpenSshCertError> {
    let mut blob = Vec::new();
    write_ssh_string(&mut blob, ED25519_KEY_TYPE.as_bytes())?;
    write_ssh_string(&mut blob, key)?;
    Ok(blob)
}

fn build_signature_blob(
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
) -> Result<Vec<u8>, OpenSshCertError> {
    let mut blob = Vec::new();
    write_ssh_string(&mut blob, ED25519_KEY_TYPE.as_bytes())?;
    write_ssh_string(&mut blob, signature)?;
    Ok(blob)
}

fn build_subject_public_key_info(key: &CertifiedPublicKey) -> Result<Vec<u8>, OpenSshCertError> {
    match key {
        CertifiedPublicKey::Ed25519(public_key) => {
            let mut content = ED25519_ALGORITHM_IDENTIFIER.to_vec();
            write_der_bit_string(&mut content, public_key)?;
            der_tlv(0x30, &content)
        }
        CertifiedPublicKey::Rsa { exponent, modulus } => {
            let mut rsa_content = Vec::new();
            write_der_positive_integer(&mut rsa_content, modulus)?;
            write_der_positive_integer(&mut rsa_content, exponent)?;
            let rsa_public_key = der_tlv(0x30, &rsa_content)?;
            let mut content = RSA_ALGORITHM_IDENTIFIER.to_vec();
            write_der_bit_string(&mut content, &rsa_public_key)?;
            der_tlv(0x30, &content)
        }
        CertifiedPublicKey::EcdsaP256(point) => {
            let mut content = P256_ALGORITHM_IDENTIFIER.to_vec();
            write_der_bit_string(&mut content, point)?;
            der_tlv(0x30, &content)
        }
    }
}

fn write_der_bit_string(output: &mut Vec<u8>, payload: &[u8]) -> Result<(), OpenSshCertError> {
    let bit_string = der_tlv(0x03, &[[0].as_slice(), payload].concat())?;
    output.extend_from_slice(&bit_string);
    Ok(())
}

fn write_der_positive_integer(output: &mut Vec<u8>, value: &[u8]) -> Result<(), OpenSshCertError> {
    if value.is_empty() || value.first() == Some(&0) {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    let encoded = if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        let mut positive = Vec::with_capacity(value.len() + 1);
        positive.push(0);
        positive.extend_from_slice(value);
        der_tlv(0x02, &positive)?
    } else {
        der_tlv(0x02, value)?
    };
    output.extend_from_slice(&encoded);
    Ok(())
}

fn der_tlv(tag: u8, content: &[u8]) -> Result<Vec<u8>, OpenSshCertError> {
    let length = content.len();
    let mut encoded_length = Vec::new();
    if length >= 128 {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .ok_or(OpenSshCertError::InvalidCertificate)?;
        let significant = bytes
            .get(first..)
            .ok_or(OpenSshCertError::InvalidCertificate)?;
        if significant.len() > 127 {
            return Err(OpenSshCertError::InvalidCertificate);
        }
        encoded_length.push(
            0x80 | u8::try_from(significant.len())
                .map_err(|_| OpenSshCertError::InvalidCertificate)?,
        );
        encoded_length.extend_from_slice(significant);
    } else {
        encoded_length
            .push(u8::try_from(length).map_err(|_| OpenSshCertError::InvalidCertificate)?);
    }

    let mut encoded = Vec::with_capacity(1 + encoded_length.len() + content.len());
    encoded.push(tag);
    encoded.extend_from_slice(&encoded_length);
    encoded.extend_from_slice(content);
    Ok(encoded)
}

fn validate_nonce(nonce: &[u8]) -> Result<(), OpenSshCertError> {
    if nonce.is_empty() || nonce.len() > NONCE_MAX_LENGTH {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    Ok(())
}

fn write_ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), OpenSshCertError> {
    let length = u32::try_from(value.len()).map_err(|_| OpenSshCertError::InvalidSsh)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn write_ssh_mpint(output: &mut Vec<u8>, value: &[u8]) -> Result<(), OpenSshCertError> {
    if value.is_empty() || value.first() == Some(&0) {
        return Err(OpenSshCertError::InvalidCertificate);
    }
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        let mut encoded = Vec::with_capacity(value.len() + 1);
        encoded.push(0);
        encoded.extend_from_slice(value);
        write_ssh_string(output, &encoded)
    } else {
        write_ssh_string(output, value)
    }
}

fn read_ssh_string<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], OpenSshCertError> {
    let input = *remaining;
    let length_bytes = input.get(..4).ok_or(OpenSshCertError::InvalidSsh)?;
    let length = u32::from_be_bytes(
        copy_array::<4>(length_bytes).map_err(|()| OpenSshCertError::InvalidSsh)?,
    );
    let length = usize::try_from(length).map_err(|_| OpenSshCertError::InvalidSsh)?;
    let end = 4usize
        .checked_add(length)
        .ok_or(OpenSshCertError::InvalidSsh)?;
    if end > input.len() {
        return Err(OpenSshCertError::InvalidSsh);
    }
    let value = input.get(4..end).ok_or(OpenSshCertError::InvalidSsh)?;
    *remaining = input.get(end..).ok_or(OpenSshCertError::InvalidSsh)?;
    Ok(value)
}

fn read_ssh_mpint<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], OpenSshCertError> {
    let encoded = read_ssh_string(remaining)?;
    let value = if encoded.first() == Some(&0) {
        encoded.get(1..).ok_or(OpenSshCertError::InvalidSsh)?
    } else {
        encoded
    };
    if value.is_empty()
        || value.first() == Some(&0)
        || value.first().is_some_and(|byte| byte & 0x80 != 0)
    {
        return Err(OpenSshCertError::InvalidSsh);
    }
    Ok(value)
}

fn read_u32(remaining: &mut &[u8]) -> Result<u32, OpenSshCertError> {
    let bytes = remaining.get(..4).ok_or(OpenSshCertError::InvalidSsh)?;
    *remaining = remaining.get(4..).ok_or(OpenSshCertError::InvalidSsh)?;
    let bytes = copy_array::<4>(bytes).map_err(|()| OpenSshCertError::InvalidSsh)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(remaining: &mut &[u8]) -> Result<u64, OpenSshCertError> {
    let bytes = remaining.get(..8).ok_or(OpenSshCertError::InvalidSsh)?;
    *remaining = remaining.get(8..).ok_or(OpenSshCertError::InvalidSsh)?;
    let bytes = copy_array::<8>(bytes).map_err(|()| OpenSshCertError::InvalidSsh)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_utf8_string(remaining: &mut &[u8]) -> Result<String, OpenSshCertError> {
    let value = read_ssh_string(remaining)?;
    let value = std::str::from_utf8(value).map_err(|_| OpenSshCertError::InvalidSsh)?;
    Ok(value.to_owned())
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ()> {
    bytes.try_into().map_err(|_| ())
}

/// The two fields of a validity sequence, in the order they are encoded.
///
/// Carried through the time parser so a rejected time says which of the two it
/// was rather than only that one of them was wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidityField {
    /// `notBefore`, the inclusive start of the validity interval.
    NotBefore,
    /// `notAfter`, the exclusive end of the validity interval.
    NotAfter,
}

impl ValidityField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotBefore => "notBefore",
            Self::NotAfter => "notAfter",
        }
    }
}

/// Why a validity field was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeFault {
    /// The validity sequence does not hold the field at all.
    Missing,
    /// The field is neither a `UTCTime` nor a `GeneralizedTime`.
    NotATime,
    /// The validity sequence holds a field after `notAfter`.
    TrailingData,
    /// The content is not `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`.
    NotADigitalTime,
    /// The content is the right length and ends in `Z`, but a digit is not one.
    NotDecimal,
    /// The digits do not name an instant: month 13, 30 February, hour 24.
    NotAnInstant,
    /// The field carries more digits than any timestamp, which the width of the
    /// accumulator still catches. Nothing a `UTCTime` or a `GeneralizedTime`
    /// encodes can reach it, because both are bounded to four digits.
    TooManyDigits,
    /// The instant is outside the `u64` seconds an OpenSSH validity field
    /// carries. Any date before 1970 is such an instant, and so is any date
    /// beyond the year 584 billion, which only a `GeneralizedTime` year at the
    /// very top of its own range could name.
    OutsideUnixRange,
}

/// A validity field that could not be read as an OpenSSH timestamp.
///
/// The published error is the single [`OpenSshCertError::InvalidTime`] variant,
/// so this does not reach a caller today: it exists so the parser can say
/// *which* field was wrong and *why*, which is what makes the difference
/// between a certificate this crate cannot represent and a certificate that is
/// malformed. Publishing it is an API change and is tracked as its own
/// question rather than smuggled in with a bug fix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimeError {
    field: ValidityField,
    fault: TimeFault,
}

impl TimeError {
    const fn new(field: ValidityField, fault: TimeFault) -> Self {
        Self { field, fault }
    }
}

impl From<TimeError> for OpenSshCertError {
    fn from(_: TimeError) -> Self {
        Self::InvalidTime
    }
}

impl std::fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self.fault {
            TimeFault::Missing => "the validity sequence does not hold the field",
            TimeFault::NotATime => "it is neither a UTCTime nor a GeneralizedTime",
            TimeFault::TrailingData => "the validity sequence holds a field after it",
            TimeFault::NotADigitalTime => "it is not YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ",
            TimeFault::NotDecimal => "it holds a byte that is not a decimal digit",
            TimeFault::NotAnInstant => "its digits do not name an instant",
            TimeFault::TooManyDigits => "it carries more digits than a timestamp",
            TimeFault::OutsideUnixRange => {
                "the instant is outside the range an OpenSSH validity field carries"
            }
        };
        write!(formatter, "{}: {reason}", self.field.as_str())
    }
}

/// Parses a `UTCTime` or `GeneralizedTime` validity field into Unix seconds.
///
/// RFC 5280 §4.1.2.5 requires a certificate-issuing application to encode a
/// validity date on or after 2050 as a `GeneralizedTime`, and a two-digit year
/// cannot name a date before 1950 at all, so both encodings have to be read: a
/// two-digit year is expanded through the 1950 pivot, and a four-digit one is
/// taken as written.
fn parse_x509_time(time: Tlv<'_>, field: ValidityField) -> Result<u64, TimeError> {
    let (year, date_time) = if has_tag(time, CLASS_UNIVERSAL, TAG_UTC_TIME, false) {
        if time.content.len() != 13 || time.content.last() != Some(&b'Z') {
            return Err(TimeError::new(field, TimeFault::NotADigitalTime));
        }
        let short_year = parse_time_number(
            time.content
                .get(..2)
                .ok_or(TimeError::new(field, TimeFault::NotADigitalTime))?,
            field,
        )?;
        let year = if short_year <= 49 {
            2000 + short_year
        } else {
            1900 + short_year
        };
        (
            year,
            time.content
                .get(2..12)
                .ok_or(TimeError::new(field, TimeFault::NotADigitalTime))?,
        )
    } else if has_tag(time, CLASS_UNIVERSAL, TAG_GENERALIZED_TIME, false) {
        if time.content.len() != 15 || time.content.last() != Some(&b'Z') {
            return Err(TimeError::new(field, TimeFault::NotADigitalTime));
        }
        let year = parse_time_number(
            time.content
                .get(..4)
                .ok_or(TimeError::new(field, TimeFault::NotADigitalTime))?,
            field,
        )?;
        (
            year,
            time.content
                .get(4..14)
                .ok_or(TimeError::new(field, TimeFault::NotADigitalTime))?,
        )
    } else {
        return Err(TimeError::new(field, TimeFault::NotATime));
    };

    if date_time.len() != 10 {
        return Err(TimeError::new(field, TimeFault::NotADigitalTime));
    }
    if date_time.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(TimeError::new(field, TimeFault::NotDecimal));
    }
    // The shape checks above make each of these five slices two bytes long, and
    // the two-digit fields are therefore at most 99 whatever the accumulator's
    // width is.
    let two_digits = |range: std::ops::Range<usize>| {
        date_time
            .get(range)
            .ok_or(TimeError::new(field, TimeFault::NotADigitalTime))
    };
    let month = parse_time_number(two_digits(0..2)?, field)?;
    let day = parse_time_number(two_digits(2..4)?, field)?;
    let hour = parse_time_number(two_digits(4..6)?, field)?;
    let minute = parse_time_number(two_digits(6..8)?, field)?;
    let second = parse_time_number(two_digits(8..10)?, field)?;
    if !valid_calendar_time(year, month, day, hour, minute, second) {
        return Err(TimeError::new(field, TimeFault::NotAnInstant));
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600))
        .and_then(|value| value.checked_add(minute * 60))
        .and_then(|value| value.checked_add(second))
        .ok_or(TimeError::new(field, TimeFault::OutsideUnixRange))?;
    u64::try_from(seconds).map_err(|_| TimeError::new(field, TimeFault::OutsideUnixRange))
}

/// Accumulates a run of ASCII decimal digits.
///
/// The accumulator is `i64` because the widest field a caller hands it is a
/// four-digit `GeneralizedTime` year, and the value is widened to `i64` a few
/// lines later anyway. An accumulator narrower than that — a `u8` held the
/// three-digit values but overflowed on the fourth digit, so no four-digit year
/// was readable at all and every certificate with a `GeneralizedTime` validity
/// was rejected.
fn parse_time_number(bytes: &[u8], field: ValidityField) -> Result<i64, TimeError> {
    let mut value = 0i64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(TimeError::new(field, TimeFault::NotDecimal));
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(byte - b'0')))
            .ok_or(TimeError::new(field, TimeFault::TooManyDigits))?;
    }
    Ok(value)
}

fn valid_calendar_time(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> bool {
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days_in_month
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_of_year = (month + 9) % 12;
    let day_of_year = (153 * month_of_year + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    class: u8,
    constructed: bool,
    number: u32,
    content: &'a [u8],
    total_len: usize,
}

fn validate_der_tree(input: &[u8]) -> Result<Tlv<'_>, ()> {
    let tlv = read_tlv(input)?;
    if tlv.total_len != input.len() {
        return Err(());
    }
    validate_der_tlv(tlv, 0)?;
    Ok(tlv)
}

fn validate_der_tlv(tlv: Tlv<'_>, depth: usize) -> Result<(), ()> {
    if depth > MAX_DER_DEPTH || !valid_tag_shape(tlv) {
        return Err(());
    }
    if !tlv.constructed {
        return validate_primitive_tlv(tlv);
    }

    let mut children = tlv.content;
    while !children.is_empty() {
        let child = read_tlv(children)?;
        let child_depth = depth.checked_add(1).ok_or(())?;
        validate_der_tlv(child, child_depth)?;
        children = children.get(child.total_len..).ok_or(())?;
    }
    Ok(())
}

fn validate_primitive_tlv(tlv: Tlv<'_>) -> Result<(), ()> {
    if tlv.class != CLASS_UNIVERSAL {
        return Ok(());
    }
    match tlv.number {
        1 => {
            if tlv.content == [0x00] || tlv.content == [0xff] {
                Ok(())
            } else {
                Err(())
            }
        }
        2 | 10 => {
            if valid_integer_content(tlv.content) {
                Ok(())
            } else {
                Err(())
            }
        }
        3 => {
            if valid_bit_string_content(tlv.content) {
                Ok(())
            } else {
                Err(())
            }
        }
        5 => {
            if tlv.content.is_empty() {
                Ok(())
            } else {
                Err(())
            }
        }
        6 | 13 => {
            if valid_oid_content(tlv.content) {
                Ok(())
            } else {
                Err(())
            }
        }
        _ => Ok(()),
    }
}

fn valid_tag_shape(tlv: Tlv<'_>) -> bool {
    if tlv.class != CLASS_UNIVERSAL {
        return true;
    }
    match tlv.number {
        0 | 15 => false,
        1..=7 | 9..=10 | 12..=14 | 18..=28 | 30..=36 => !tlv.constructed,
        8 | 11 | 16 | 17 | 29 => tlv.constructed,
        _ => true,
    }
}

fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, ()> {
    if input.is_empty() {
        return Err(());
    }
    let (tag_len, class, constructed, number) = parse_tag(input)?;
    let length_input = input.get(tag_len..).ok_or(())?;
    let (length_len, length) = parse_length(length_input)?;
    let header_len = tag_len.checked_add(length_len).ok_or(())?;
    let total_len = header_len.checked_add(length).ok_or(())?;
    if total_len > input.len() {
        return Err(());
    }
    let content = input.get(header_len..total_len).ok_or(())?;
    Ok(Tlv {
        class,
        constructed,
        number,
        content,
        total_len,
    })
}

fn next_tlv<'a>(remaining: &mut &'a [u8]) -> Result<Tlv<'a>, ()> {
    let input = *remaining;
    let tlv = read_tlv(input)?;
    *remaining = input.get(tlv.total_len..).ok_or(())?;
    Ok(tlv)
}

fn parse_tag(input: &[u8]) -> Result<(usize, u8, bool, u32), ()> {
    let first = *input.first().ok_or(())?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let first_number = first & 0x1f;
    if first_number != 0x1f {
        return Ok((1, class, constructed, u32::from(first_number)));
    }

    let mut index = 1;
    let mut number = 0u32;
    let mut first_octet = true;
    loop {
        let byte = *input.get(index).ok_or(())?;
        index += 1;
        if first_octet && (byte == 0 || byte == 0x80) {
            return Err(());
        }
        first_octet = false;
        number = number
            .checked_mul(128)
            .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
            .ok_or(())?;
        if byte & 0x80 == 0 {
            if number < 31 {
                return Err(());
            }
            return Ok((index, class, constructed, number));
        }
    }
}

fn parse_length(input: &[u8]) -> Result<(usize, usize), ()> {
    let first = *input.first().ok_or(())?;
    if first < 0x80 {
        return Ok((1, usize::from(first)));
    }
    if first == 0x80 {
        return Err(());
    }

    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > size_of::<usize>() || input.len() < 1 + octets || input[1] == 0 {
        return Err(());
    }
    let mut length = 0usize;
    for byte in &input[1..=octets] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(())?;
    }
    if length < 128 {
        return Err(());
    }
    Ok((1 + octets, length))
}

fn valid_integer_content(content: &[u8]) -> bool {
    let Some(first) = content.first() else {
        return false;
    };
    let Some(second) = content.get(1) else {
        return true;
    };
    let redundant_positive = *first == 0x00 && *second & 0x80 == 0;
    let redundant_negative = *first == 0xff && *second & 0x80 != 0;
    !redundant_positive && !redundant_negative
}

fn valid_bit_string_content(content: &[u8]) -> bool {
    let Some((unused, payload)) = content.split_first() else {
        return true;
    };
    if *unused > 7 || (payload.is_empty() && *unused != 0) {
        return false;
    }
    if *unused == 0 {
        return true;
    }
    let Some(last) = payload.last() else {
        return false;
    };
    let mask = (1_u8 << *unused) - 1;
    *last & mask == 0
}

fn valid_oid_content(content: &[u8]) -> bool {
    let Some(last) = content.last() else {
        return false;
    };
    if *last & 0x80 != 0 {
        return false;
    }

    let mut component_start = true;
    for byte in content {
        if component_start && *byte == 0x80 {
            return false;
        }
        component_start = byte & 0x80 == 0;
    }
    true
}

fn has_tag(tlv: Tlv<'_>, class: u8, number: u32, constructed: bool) -> bool {
    tlv.class == class && tlv.number == number && tlv.constructed == constructed
}

#[cfg(test)]
mod tests {
    use super::{
        CLASS_UNIVERSAL, CertifiedPublicKey, ED25519_ALGORITHM_IDENTIFIER, OpenSshCertKind,
        OpenSshCertRequest, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_SEQUENCE, TAG_UTC_TIME,
        TimeError, TimeFault, Tlv, ValidityField, openssh_certificate_to_x509_identity, parse,
        parse_time_number, parse_validity, parse_x509_time, to_wire, x509_to_openssh_certificate,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let length = u32::try_from(value.len()).expect("test SSH value is short");
        let mut encoded = length.to_be_bytes().to_vec();
        encoded.extend_from_slice(value);
        encoded
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let length = u8::try_from(content.len()).expect("test DER value is short-form");
        let mut encoded = vec![tag, length];
        encoded.extend_from_slice(content);
        encoded
    }

    fn seed_range(start: u8) -> [u8; 32] {
        std::array::from_fn(|index| start + u8::try_from(index).expect("test seed offset is small"))
    }

    fn build_host_certificate() -> Vec<u8> {
        let authority_seed = seed_range(0);
        let subject_seed = seed_range(32);
        let authority_signing_key = SigningKey::from_bytes(&authority_seed);
        let authority_key = authority_signing_key.verifying_key();
        let subject_key = SigningKey::from_bytes(&subject_seed)
            .verifying_key()
            .to_bytes();

        let mut authority_blob = Vec::new();
        authority_blob.extend_from_slice(&ssh_string(b"ssh-ed25519"));
        authority_blob.extend_from_slice(&ssh_string(authority_key.as_bytes()));

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&ssh_string(b"ssh-ed25519-cert-v01@openssh.com"));
        signed_data.extend_from_slice(&ssh_string(&[1, 2, 3]));
        signed_data.extend_from_slice(&ssh_string(&subject_key));
        signed_data.extend_from_slice(&1u64.to_be_bytes());
        signed_data.extend_from_slice(&2u32.to_be_bytes());
        signed_data.extend_from_slice(&ssh_string(b"fixture"));
        let principals = ssh_string(b"server.example");
        signed_data.extend_from_slice(&ssh_string(&principals));
        signed_data.extend_from_slice(&0u64.to_be_bytes());
        signed_data.extend_from_slice(&u64::MAX.to_be_bytes());
        signed_data.extend_from_slice(&ssh_string(&[]));
        signed_data.extend_from_slice(&ssh_string(&[]));
        signed_data.extend_from_slice(&ssh_string(&[]));
        signed_data.extend_from_slice(&ssh_string(&authority_blob));

        let signature = authority_signing_key
            .try_sign(&signed_data)
            .expect("test signature");
        let mut signature_blob = Vec::new();
        signature_blob.extend_from_slice(&ssh_string(b"ssh-ed25519"));
        signature_blob.extend_from_slice(&ssh_string(&signature.to_bytes()));
        let mut certificate = signed_data;
        certificate.extend_from_slice(&ssh_string(&signature_blob));
        certificate
    }

    fn ed25519_certificate(public_key: &[u8; 32], not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        let algorithm = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
        let mut spki_content = algorithm.clone();
        spki_content.push(0x03);
        spki_content.push(33);
        spki_content.push(0);
        spki_content.extend_from_slice(public_key);
        let spki = der(0x30, &spki_content);

        let validity = der(
            0x30,
            &[der(0x17, not_before), der(0x17, not_after)].concat(),
        );

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&der(0xa0, &der(0x02, &[2])));
        tbs_content.extend_from_slice(&der(0x02, &[1]));
        tbs_content.extend_from_slice(&algorithm);
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs_content);

        let mut certificate = tbs;
        certificate.extend_from_slice(&algorithm);
        certificate.extend_from_slice(&der(0x03, &[0]));
        der(0x30, &certificate)
    }

    #[test]
    fn parses_and_round_trips_csharp_host_certificate() {
        let blob = build_host_certificate();
        let certificate = parse(&blob).expect("the host certificate should parse");
        let subject_seed = seed_range(32);
        let subject_key = SigningKey::from_bytes(&subject_seed)
            .verifying_key()
            .to_bytes();

        assert_eq!(certificate.principals, ["server.example".to_owned()]);
        assert_eq!(certificate.serial, 1);
        assert_eq!(certificate.kind, OpenSshCertKind::Host);
        assert_eq!(certificate.valid_after, 0);
        assert_eq!(certificate.valid_before, u64::MAX);
        assert_eq!(
            certificate.certified_key,
            CertifiedPublicKey::Ed25519(subject_key)
        );
        assert_eq!(to_wire(&certificate).expect("wire round trip"), blob);
    }

    #[test]
    fn converts_x509_validity_and_identity() {
        let ca_seed = seed_range(0);
        let subject_seed = seed_range(32);
        let subject_key = SigningKey::from_bytes(&subject_seed)
            .verifying_key()
            .to_bytes();
        let der_certificate = ed25519_certificate(&subject_key, b"700101000000Z", b"700101000005Z");
        let request = OpenSshCertRequest {
            kind: OpenSshCertKind::Host,
            serial: 7,
            key_id: "host".to_owned(),
            principals: vec!["server.example".to_owned()],
            nonce: vec![9, 9],
            critical_options: Vec::new(),
            extensions: Vec::new(),
        };

        let blob = x509_to_openssh_certificate(&der_certificate, &request, &ca_seed)
            .expect("X.509 conversion");
        let certificate = parse(&blob).expect("converted certificate should parse");
        assert_eq!(
            certificate.certified_key,
            CertifiedPublicKey::Ed25519(subject_key)
        );
        assert_eq!(certificate.serial, 7);
        assert_eq!(certificate.valid_after, 0);
        assert_eq!(certificate.valid_before, 5);
        assert_eq!(certificate.principals, ["server.example".to_owned()]);

        let identity =
            openssh_certificate_to_x509_identity(&blob).expect("X.509 identity conversion");
        let mut expected_spki_content = ED25519_ALGORITHM_IDENTIFIER.to_vec();
        let mut bit_string_content = vec![0];
        bit_string_content.extend_from_slice(&subject_key);
        expected_spki_content.extend_from_slice(&der(0x03, &bit_string_content));
        let expected_spki = der(0x30, &expected_spki_content);
        assert_eq!(identity.subject_public_key_info, expected_spki);
        assert_eq!(identity.valid_after, 0);
        assert_eq!(identity.valid_before, 5);
    }

    #[test]
    fn rejects_a_flipped_signature_byte() {
        let mut blob = build_host_certificate();
        let last = blob.last_mut().expect("certificate has a signature byte");
        *last ^= 1;
        assert!(matches!(
            parse(&blob),
            Err(super::OpenSshCertError::BadSignature)
        ));
    }

    /// A `UTCTime` or a `GeneralizedTime` content, as the time parser sees it.
    fn time(number: u32, content: &[u8]) -> Tlv<'_> {
        Tlv {
            class: CLASS_UNIVERSAL,
            constructed: false,
            number,
            content,
            total_len: content.len() + 2,
        }
    }

    fn utc(content: &[u8]) -> Tlv<'_> {
        time(TAG_UTC_TIME, content)
    }

    fn generalized(content: &[u8]) -> Tlv<'_> {
        time(TAG_GENERALIZED_TIME, content)
    }

    /// Reads a content octet string, the way it appears inside a validity
    /// sequence.
    fn field(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![
            tag,
            u8::try_from(content.len()).expect("test field is short-form"),
        ];
        encoded.extend_from_slice(content);
        encoded
    }

    /// Runs the validity parser over a sequence of already-encoded fields.
    fn validity(fields: &[&[u8]]) -> Result<(u64, u64), TimeError> {
        let content: Vec<u8> = fields.iter().flat_map(|field| field.to_vec()).collect();
        parse_validity(Tlv {
            class: CLASS_UNIVERSAL,
            constructed: true,
            number: TAG_SEQUENCE,
            content: &content,
            total_len: content.len() + 2,
        })
    }

    /// Every four-digit year reads. The accumulator this parser used had a `u8`
    /// in it, which overflowed on the fourth digit of a `GeneralizedTime` year,
    /// so no four-digit year was readable and every certificate carrying one was
    /// rejected — which is every certificate whose validity date is from 2050 on,
    /// because that is the encoding RFC 5280 requires there.
    #[test]
    fn reads_a_four_digit_generalized_time_year() {
        for (content, seconds) in [
            (&b"19700101000000Z"[..], 0),
            (&b"20500228000000Z"[..], 2_529_619_200),
            (&b"20501127000000Z"[..], 2_553_120_000),
            (&b"21361127000000Z"[..], 5_267_030_400),
            (&b"99991231235959Z"[..], 253_402_300_799),
        ] {
            assert_eq!(
                parse_x509_time(generalized(content), ValidityField::NotAfter),
                Ok(seconds),
                "{content:?} should be {seconds}"
            );
        }
    }

    /// The two-digit branch, which is unchanged: a `UTCTime` year is still
    /// expanded through the 1950 pivot, so `49` is 2049 and `50` is 1950.
    #[test]
    fn reads_a_two_digit_utc_time_year_through_the_1950_pivot() {
        for (content, seconds) in [
            (&b"000101000000Z"[..], 946_684_800),
            (&b"990101000000Z"[..], 915_148_800),
            (&b"000229000000Z"[..], 951_782_400),
            (&b"480229000000Z"[..], 2_466_547_200),
            (&b"491231235959Z"[..], 2_524_607_999),
        ] {
            assert_eq!(
                parse_x509_time(utc(content), ValidityField::NotAfter),
                Ok(seconds),
                "{content:?} should be {seconds}"
            );
        }
    }

    /// A date before 1970 is refused because an OpenSSH validity field is `u64`
    /// seconds since the epoch and cannot hold it — not because its year was
    /// unreadable. Before this fix the two cases were indistinguishable, because
    /// every one of them was the same `InvalidTime`.
    #[test]
    fn a_date_before_the_epoch_is_outside_the_range_rather_than_a_bad_year() {
        for (number, content) in [
            (TAG_GENERALIZED_TIME, &b"19491231235959Z"[..]),
            (TAG_GENERALIZED_TIME, &b"00010101000000Z"[..]),
            (TAG_UTC_TIME, &b"500101000000Z"[..]),
            (TAG_UTC_TIME, &b"690101000000Z"[..]),
        ] {
            assert_eq!(
                parse_x509_time(time(number, content), ValidityField::NotBefore),
                Err(TimeError::new(
                    ValidityField::NotBefore,
                    TimeFault::OutsideUnixRange
                )),
                "{content:?} names a real instant before the epoch"
            );
        }
    }

    /// A rejected time says which of the two validity fields it came from, and
    /// which way it was wrong. Both halves used to collapse into one variant.
    #[test]
    fn a_rejected_time_names_its_field_and_its_fault() {
        for (content, fault) in [
            (&b"20x61127000000Z"[..], TimeFault::NotDecimal),
            (&b"2136112700000Z"[..], TimeFault::NotADigitalTime),
            (&b"21361127000000X"[..], TimeFault::NotADigitalTime),
            (&b"20501327000000Z"[..], TimeFault::NotAnInstant),
        ] {
            assert_eq!(
                parse_x509_time(generalized(content), ValidityField::NotBefore),
                Err(TimeError::new(ValidityField::NotBefore, fault)),
                "{content:?} is the same fault whichever field it was"
            );
            assert_eq!(
                parse_x509_time(generalized(content), ValidityField::NotAfter),
                Err(TimeError::new(ValidityField::NotAfter, fault))
            );
        }
        assert_eq!(
            TimeError::new(ValidityField::NotAfter, TimeFault::NotDecimal).to_string(),
            "notAfter: it holds a byte that is not a decimal digit"
        );
    }

    /// Every way a time's content can be wrong is a typed fault rather than a
    /// panic, an acceptance, or an undifferentiated error.
    #[test]
    fn a_malformed_time_is_rejected_with_a_typed_fault() {
        for (content, fault) in [
            (&b""[..], TimeFault::NotADigitalTime),
            (&b"2"[..], TimeFault::NotADigitalTime),
            (&b"2136112700000Z"[..], TimeFault::NotADigitalTime),
            (&b"213611270000000Z"[..], TimeFault::NotADigitalTime),
            (&b"21361127000000X"[..], TimeFault::NotADigitalTime),
            (&b"213611270000-0Z"[..], TimeFault::NotDecimal),
            (&b"20x50101000000Z"[..], TimeFault::NotDecimal),
            (&b"20x61127000000Z"[..], TimeFault::NotDecimal),
            (&b"99999999999999Z"[..], TimeFault::NotAnInstant),
            (&b"20500027000000Z"[..], TimeFault::NotAnInstant),
            (&b"20501327000000Z"[..], TimeFault::NotAnInstant),
            (&b"20500230000000Z"[..], TimeFault::NotAnInstant),
            (&b"20500229000000Z"[..], TimeFault::NotAnInstant),
            (&b"19000229000000Z"[..], TimeFault::NotAnInstant),
            (&b"20502400000000Z"[..], TimeFault::NotAnInstant),
            (&b"20501127006000Z"[..], TimeFault::NotAnInstant),
            (&b"20501127000060Z"[..], TimeFault::NotAnInstant),
        ] {
            assert_eq!(
                parse_x509_time(generalized(content), ValidityField::NotAfter),
                Err(TimeError::new(ValidityField::NotAfter, fault)),
                "{content:?} should be {fault:?}"
            );
        }
        // A field that is not a time at all, and the 30 February of a year that
        // is not a leap year, are the two ends of that list: the first is a
        // wrong ASN.1 type rather than a wrong time.
        assert_eq!(
            parse_x509_time(
                time(TAG_INTEGER, b"20501127000000Z"),
                ValidityField::NotAfter
            ),
            Err(TimeError::new(ValidityField::NotAfter, TimeFault::NotATime))
        );
    }

    /// The accumulator is wide enough for a four-digit year and still refuses a
    /// number too long for its own width. The shape checks bound every real
    /// field to four digits, so the second case is defensive rather than
    /// reachable from a certificate.
    #[test]
    fn the_digit_accumulator_is_wide_and_still_checked() {
        assert_eq!(
            parse_time_number(b"9999", ValidityField::NotAfter),
            Ok(9999)
        );
        assert_eq!(
            parse_time_number(b"99999", ValidityField::NotAfter),
            Ok(99_999)
        );
        assert_eq!(
            parse_time_number(b"99999999999999999999", ValidityField::NotAfter),
            Err(TimeError::new(
                ValidityField::NotAfter,
                TimeFault::TooManyDigits
            ))
        );
    }

    /// A validity sequence that is short, mistyped or over-long is a typed fault
    /// naming the field it belongs to, and a fault in `notBefore` is never
    /// attributed to `notAfter`.
    #[test]
    fn a_malformed_validity_sequence_names_its_field() {
        let before = field(0x18, b"20501127000000Z");
        let after = field(0x18, b"20521127000000Z");
        let before_utc = field(0x17, b"260928000000Z");
        let after_utc = field(0x17, b"451127000000Z");
        let not_a_time = field(0x02, b"\x05");
        let bad_digits = field(0x18, b"2050x127000000Z");

        assert_eq!(
            validity(&[&before, &after]),
            Ok((2_553_120_000, 2_616_278_400))
        );
        assert_eq!(
            validity(&[&before_utc, &after_utc]),
            Ok((1_790_553_600, 2_395_353_600))
        );
        let cases: [(&[&[u8]], TimeError); 7] = [
            (
                &[],
                TimeError::new(ValidityField::NotBefore, TimeFault::Missing),
            ),
            (
                &[&before],
                TimeError::new(ValidityField::NotAfter, TimeFault::Missing),
            ),
            (
                &[&after],
                TimeError::new(ValidityField::NotAfter, TimeFault::Missing),
            ),
            (
                &[&not_a_time, &after],
                TimeError::new(ValidityField::NotBefore, TimeFault::NotATime),
            ),
            (
                &[&before, &not_a_time],
                TimeError::new(ValidityField::NotAfter, TimeFault::NotATime),
            ),
            (
                &[&bad_digits, &after],
                TimeError::new(ValidityField::NotBefore, TimeFault::NotDecimal),
            ),
            (
                &[&before, &after, &after],
                TimeError::new(ValidityField::NotAfter, TimeFault::TrailingData),
            ),
        ];
        for (fields, expected) in cases {
            assert_eq!(validity(fields), Err(expected));
        }
    }
}
