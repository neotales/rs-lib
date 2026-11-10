//! Lossless X.509 certificate conversion to SSH public-key wire format.
//!
//! The wire value is the RFC 6187 representation: an SSH `string` containing
//! the key type followed by an SSH `string` containing the complete DER
//! certificate. It is not an OpenSSH `*-cert-v01@openssh.com` certificate.
//! Certificate signatures are not validated.
//!
//! RFC 6187 does not define an X.509 Ed25519 key type. This crate uses
//! `x509v3-ssh-ed25519` with the same two-string framing as the other X.509
//! key types.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_CURVE_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

const RSA_SSH_KEY_TYPE: &str = "x509v3-ssh-rsa";
const P256_SSH_KEY_TYPE: &str = "x509v3-ecdsa-sha2-nistp256";
const ED25519_SSH_KEY_TYPE: &str = "x509v3-ssh-ed25519";

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_CONTEXT: u8 = 2;

const TAG_INTEGER: u32 = 2;
const TAG_BIT_STRING: u32 = 3;
const TAG_NULL: u32 = 5;
const TAG_OID: u32 = 6;
const TAG_SEQUENCE: u32 = 16;

const MAX_DER_DEPTH: usize = 64;

/// An error converting between an X.509 certificate and SSH wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshX509Error {
    /// The DER certificate is malformed or structurally invalid.
    InvalidCertificate,
    /// The certificate's SubjectPublicKeyInfo algorithm is not supported.
    UnsupportedAlgorithm,
    /// The SSH wire or authorized-key framing is invalid.
    InvalidSsh,
}

impl std::fmt::Display for SshX509Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificate => formatter.write_str("invalid X.509 certificate DER"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("unsupported X.509 SubjectPublicKeyInfo algorithm")
            }
            Self::InvalidSsh => formatter.write_str("invalid X.509 SSH wire format"),
        }
    }
}

impl std::error::Error for SshX509Error {}

/// Converts a DER X.509 certificate to an RFC 6187 SSH public-key blob.
///
/// The complete certificate is retained as the second SSH string. The key
/// type is selected from the SubjectPublicKeyInfo algorithm identifier.
///
/// # Errors
///
/// Returns [`SshX509Error::InvalidCertificate`] for malformed or structurally
/// invalid DER, and [`SshX509Error::UnsupportedAlgorithm`] when the
/// certificate's public-key algorithm is not one of RSA, P-256 ECDSA, or
/// Ed25519.
pub fn to_ssh_wire(certificate_der: &[u8]) -> Result<Vec<u8>, SshX509Error> {
    let key_type = certificate_key_type(certificate_der)?;
    let certificate_length =
        u32::try_from(certificate_der.len()).map_err(|_| SshX509Error::InvalidCertificate)?;
    let key_type_length =
        u32::try_from(key_type.len()).map_err(|_| SshX509Error::InvalidCertificate)?;

    let mut wire = Vec::new();
    wire.extend_from_slice(&key_type_length.to_be_bytes());
    wire.extend_from_slice(key_type.as_bytes());
    wire.extend_from_slice(&certificate_length.to_be_bytes());
    wire.extend_from_slice(certificate_der);
    Ok(wire)
}

/// Converts an RFC 6187 SSH public-key blob back to its original DER bytes.
///
/// The certificate is parsed to verify that the SSH key type agrees with its
/// SubjectPublicKeyInfo algorithm. The certificate itself is not rebuilt or
/// canonicalized.
///
/// # Errors
///
/// Returns [`SshX509Error::InvalidSsh`] for malformed framing, trailing data,
/// or a key type that does not match the certificate. Certificate and
/// algorithm errors are returned from [`to_ssh_wire`] parsing as
/// [`SshX509Error::InvalidCertificate`] or
/// [`SshX509Error::UnsupportedAlgorithm`].
pub fn from_ssh_wire(ssh_wire: &[u8]) -> Result<Vec<u8>, SshX509Error> {
    let mut remaining = ssh_wire;
    let key_type = read_ssh_string(&mut remaining)?;
    let certificate_der = read_ssh_string(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(SshX509Error::InvalidSsh);
    }

    let expected_key_type = certificate_key_type(certificate_der)?;
    if key_type != expected_key_type.as_bytes() {
        return Err(SshX509Error::InvalidSsh);
    }
    Ok(certificate_der.to_vec())
}

/// Converts a DER X.509 certificate to an authorized-key line.
///
/// The line has the form `key-type base64`, uses standard base64, and has no
/// comment or trailing line ending.
///
/// # Errors
///
/// Returns [`SshX509Error::InvalidCertificate`] for malformed or structurally
/// invalid DER, and [`SshX509Error::UnsupportedAlgorithm`] when the
/// certificate's public-key algorithm is not one of RSA, P-256 ECDSA, or
/// Ed25519.
pub fn to_authorized_key(certificate_der: &[u8]) -> Result<String, SshX509Error> {
    let key_type = certificate_key_type(certificate_der)?;
    let wire = to_ssh_wire(certificate_der)?;
    Ok(format!("{key_type} {}", STANDARD.encode(wire)))
}

/// Parses an authorized-key line into its original DER certificate bytes.
///
/// Surrounding whitespace and one optional trailing comment are accepted. The
/// base64 payload uses the standard alphabet and is not URL-safe base64.
///
/// # Errors
///
/// Returns [`SshX509Error::InvalidSsh`] for invalid key framing, base64, SSH
/// wire data, or a key type that does not match the certificate. Certificate
/// and algorithm errors are returned as [`SshX509Error::InvalidCertificate`]
/// or [`SshX509Error::UnsupportedAlgorithm`].
pub fn from_authorized_key(line: &str) -> Result<Vec<u8>, SshX509Error> {
    let trimmed = line.trim();
    let mut fields = trimmed.split_whitespace();
    let key_type = fields.next().ok_or(SshX509Error::InvalidSsh)?;
    let encoded = fields.next().ok_or(SshX509Error::InvalidSsh)?;
    let wire = STANDARD
        .decode(encoded)
        .map_err(|_| SshX509Error::InvalidSsh)?;
    let certificate_der = from_ssh_wire(&wire)?;
    if key_type.as_bytes() != certificate_key_type(&certificate_der)?.as_bytes() {
        return Err(SshX509Error::InvalidSsh);
    }
    Ok(certificate_der)
}

fn certificate_key_type(certificate_der: &[u8]) -> Result<&'static str, SshX509Error> {
    let certificate =
        validate_der_tree(certificate_der).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(certificate, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let mut certificate_fields = certificate.content;
    let tbs_certificate =
        next_tlv(&mut certificate_fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(tbs_certificate, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let signature_algorithm =
        next_tlv(&mut certificate_fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(signature_algorithm, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let signature_value =
        next_tlv(&mut certificate_fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(signature_value, CLASS_UNIVERSAL, TAG_BIT_STRING, false) {
        return Err(SshX509Error::InvalidCertificate);
    }
    if !certificate_fields.is_empty() {
        return Err(SshX509Error::InvalidCertificate);
    }

    parse_tbs_key_type(tbs_certificate.content)
}

fn parse_tbs_key_type(mut fields: &[u8]) -> Result<&'static str, SshX509Error> {
    let first = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    let serial = if has_tag(first, CLASS_CONTEXT, 0, true) {
        parse_version(first)?;
        next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?
    } else {
        first
    };
    if !has_tag(serial, CLASS_UNIVERSAL, TAG_INTEGER, false)
        || !valid_integer_content(serial.content)
    {
        return Err(SshX509Error::InvalidCertificate);
    }

    let tbs_signature_algorithm =
        next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(tbs_signature_algorithm, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let issuer = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(issuer, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let validity = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(validity, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let subject = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(subject, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let subject_public_key_info =
        next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(subject_public_key_info, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }
    let key_type = parse_spki(subject_public_key_info)?;

    let mut previous_optional_tag = 0;
    while !fields.is_empty() {
        let optional = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
        if optional.class != CLASS_CONTEXT
            || optional.number == 0
            || optional.number > 3
            || optional.number <= previous_optional_tag
        {
            return Err(SshX509Error::InvalidCertificate);
        }
        match optional.number {
            1 | 2 if optional.constructed => return Err(SshX509Error::InvalidCertificate),
            3 if !optional.constructed => return Err(SshX509Error::InvalidCertificate),
            _ => {}
        }
        previous_optional_tag = optional.number;
    }

    Ok(key_type)
}

fn parse_version(version: Tlv<'_>) -> Result<(), SshX509Error> {
    if !has_tag(version, CLASS_CONTEXT, 0, true) {
        return Err(SshX509Error::InvalidCertificate);
    }
    let mut fields = version.content;
    let value = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(value, CLASS_UNIVERSAL, TAG_INTEGER, false)
        || !fields.is_empty()
        || !valid_integer_content(value.content)
    {
        return Err(SshX509Error::InvalidCertificate);
    }
    if value.content != [0] && value.content != [1] && value.content != [2] {
        return Err(SshX509Error::InvalidCertificate);
    }
    Ok(())
}

fn parse_spki(subject_public_key_info: Tlv<'_>) -> Result<&'static str, SshX509Error> {
    if !has_tag(subject_public_key_info, CLASS_UNIVERSAL, TAG_SEQUENCE, true) {
        return Err(SshX509Error::InvalidCertificate);
    }

    let mut fields = subject_public_key_info.content;
    let algorithm = next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    let (oid, parameters) =
        parse_algorithm_identifier(algorithm).map_err(|()| SshX509Error::InvalidCertificate)?;

    let subject_public_key =
        next_tlv(&mut fields).map_err(|()| SshX509Error::InvalidCertificate)?;
    if !has_tag(subject_public_key, CLASS_UNIVERSAL, TAG_BIT_STRING, false) || !fields.is_empty() {
        return Err(SshX509Error::InvalidCertificate);
    }

    key_type_for_algorithm(oid, parameters)
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

fn key_type_for_algorithm(
    oid: &[u8],
    parameters: Option<Tlv<'_>>,
) -> Result<&'static str, SshX509Error> {
    if oid == RSA_OID {
        return match parameters {
            None => Ok(RSA_SSH_KEY_TYPE),
            Some(parameters)
                if has_tag(parameters, CLASS_UNIVERSAL, TAG_NULL, false)
                    && parameters.content.is_empty() =>
            {
                Ok(RSA_SSH_KEY_TYPE)
            }
            Some(_) => Err(SshX509Error::InvalidCertificate),
        };
    }

    if oid == EC_OID {
        let Some(parameters) = parameters else {
            return Err(SshX509Error::InvalidCertificate);
        };
        if !has_tag(parameters, CLASS_UNIVERSAL, TAG_OID, false) {
            return Err(SshX509Error::InvalidCertificate);
        }
        return if parameters.content == P256_CURVE_OID {
            Ok(P256_SSH_KEY_TYPE)
        } else {
            Err(SshX509Error::UnsupportedAlgorithm)
        };
    }

    if oid == ED25519_OID {
        return if parameters.is_none() {
            Ok(ED25519_SSH_KEY_TYPE)
        } else {
            Err(SshX509Error::InvalidCertificate)
        };
    }

    Err(SshX509Error::UnsupportedAlgorithm)
}

fn read_ssh_string<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], SshX509Error> {
    let input = *remaining;
    let length_bytes = input.get(..4).ok_or(SshX509Error::InvalidSsh)?;
    let length = u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]);
    let length = usize::try_from(length).map_err(|_| SshX509Error::InvalidSsh)?;
    let end = 4usize.checked_add(length).ok_or(SshX509Error::InvalidSsh)?;
    if end > input.len() {
        return Err(SshX509Error::InvalidSsh);
    }
    let value = input.get(4..end).ok_or(SshX509Error::InvalidSsh)?;
    *remaining = input.get(end..).ok_or(SshX509Error::InvalidSsh)?;
    Ok(value)
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
        ED25519_SSH_KEY_TYPE, from_authorized_key, from_ssh_wire, read_ssh_string,
        to_authorized_key, to_ssh_wire,
    };

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let length = u8::try_from(content.len()).expect("test DER value is short-form");
        let mut value = vec![tag, length];
        value.extend_from_slice(content);
        value
    }

    fn minimal_ed25519_certificate() -> Vec<u8> {
        let algorithm = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
        let mut spki_content = algorithm;
        spki_content.extend_from_slice(&der(0x03, &[0x00]));
        let spki = der(0x30, &spki_content);

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&der(0x02, &[0x01]));
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&der(0x30, &[]));
        tbs_content.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs_content);

        let mut certificate_content = tbs;
        certificate_content.extend_from_slice(&der(0x30, &[]));
        certificate_content.extend_from_slice(&der(0x03, &[0x00]));
        der(0x30, &certificate_content)
    }

    #[test]
    fn ed25519_round_trips_wire_and_authorized_key() {
        let certificate = minimal_ed25519_certificate();
        let wire = to_ssh_wire(&certificate).expect("wire conversion");
        let mut remaining = wire.as_slice();
        let key_type = read_ssh_string(&mut remaining).expect("key type");
        assert_eq!(key_type, ED25519_SSH_KEY_TYPE.as_bytes());
        assert_eq!(from_ssh_wire(&wire).expect("wire round trip"), certificate);

        let authorized = to_authorized_key(&certificate).expect("authorized-key conversion");
        assert!(authorized.starts_with("x509v3-ssh-ed25519 "));
        assert!(!authorized.ends_with(' '));
        assert_eq!(
            from_authorized_key(&format!("  {authorized} optional comment  "))
                .expect("authorized-key round trip"),
            certificate
        );
    }

    #[test]
    fn rejects_truncated_and_trailing_certificate_der() {
        let certificate = minimal_ed25519_certificate();
        let mut truncated = certificate.clone();
        truncated.pop();
        assert!(to_ssh_wire(&truncated).is_err());

        let mut trailing = certificate;
        trailing.push(0);
        assert!(to_ssh_wire(&trailing).is_err());
    }

    #[test]
    fn rejects_authorized_key_type_mismatch() {
        let certificate = minimal_ed25519_certificate();
        let authorized = to_authorized_key(&certificate).expect("authorized-key conversion");
        let wrong_type = authorized.replacen(ED25519_SSH_KEY_TYPE, "x509v3-ssh-rsa", 1);
        assert!(from_authorized_key(&wrong_type).is_err());
    }
}
