// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::error::Error;
use std::fmt::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use neotales_ssh::cert::{
    CRITICAL_OPTION_FORCE_COMMAND, CRITICAL_OPTION_SOURCE_ADDRESS, CertificateError,
    CertificateType, ED25519_PUBLIC_KEY_LENGTH, SSH_ECDSA_SHA2_NISTP256_CERT_V01,
    SSH_ECDSA_SHA2_NISTP384_CERT_V01, SSH_ECDSA_SHA2_NISTP521_CERT_V01, SSH_ED25519,
    SSH_ED25519_CERT_V01, SSH_RSA, SSH_RSA_CERT_V01, parse_certificate, verify_certificate,
};
use neotales_ssh::{Reader, Writer, ecdsa_hostkey, rsa_hostkey};

const CA_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SUBJECT_SEED: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const VALID_AFTER: u64 = 1_700_000_000;
const VALID_BEFORE: u64 = 1_800_000_000;
const NOW: u64 = 1_750_000_000;

struct Fixture {
    certificate: Vec<u8>,
    ca_point: [u8; ED25519_PUBLIC_KEY_LENGTH],
    ca_blob: Vec<u8>,
    subject_point: [u8; ED25519_PUBLIC_KEY_LENGTH],
    signature: Vec<u8>,
}

struct SignedFixture {
    certificate: Vec<u8>,
    signed_prefix: Vec<u8>,
    signature_blob: Vec<u8>,
}

#[test]
fn valid_certificate_round_trips_fields_options_and_ca_blob() -> Result<(), Box<dyn Error>> {
    let source_address = nested_string(b"192.0.2.0/24,198.51.100.7")?;
    let force_command = nested_string(b"internal-sftp")?;
    let fixture = make_fixture(
        &["host.example", "host-alias"],
        &[
            (CRITICAL_OPTION_FORCE_COMMAND, force_command.clone()),
            (CRITICAL_OPTION_SOURCE_ADDRESS, source_address.clone()),
        ],
        &[
            ("permit-pty", Vec::new()),
            ("vendor.example/extension", b"retained".to_vec()),
        ],
        CertificateType::Host,
        VALID_AFTER,
        VALID_BEFORE,
    )?;

    let parsed = parse_certificate(&fixture.certificate)?;
    assert_eq!(parsed.algorithm(), SSH_ED25519_CERT_V01);
    assert_eq!(parsed.certificate_type(), CertificateType::Host);
    assert_eq!(parsed.serial(), 7);
    assert_eq!(parsed.key_id(), "test certificate");
    assert_eq!(
        parsed
            .principals()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["host.example", "host-alias"]
    );
    assert_eq!(parsed.nonce(), &[0xa5; 32]);
    assert_eq!(parsed.valid_after(), VALID_AFTER);
    assert_eq!(parsed.valid_before(), VALID_BEFORE);
    assert_eq!(parsed.subject_public_key(), Some(&fixture.subject_point));
    assert_eq!(parsed.signature_key(), fixture.ca_blob.as_slice());
    assert_eq!(parsed.extensions().len(), 2);
    assert_eq!(parsed.extensions()[1].data(), b"retained");
    assert_eq!(parsed.extensions()[1].data_len(), b"retained".len());

    let allowed = [
        CRITICAL_OPTION_FORCE_COMMAND,
        CRITICAL_OPTION_SOURCE_ADDRESS,
    ];
    let verified = verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &allowed,
        &fixture.ca_blob,
    )?;
    assert_eq!(verified.certificate_type(), CertificateType::Host);
    assert_eq!(verified.certificate().key_id(), "test certificate");
    assert_eq!(verified.source_address(), Some(&source_address[4..]));
    assert_eq!(verified.force_command(), Some(&force_command[4..]));
    assert_eq!(
        verified.critical_options()[0].data(),
        force_command.as_slice()
    );
    assert_eq!(
        verified.critical_options()[1].data(),
        source_address.as_slice()
    );

    let debug = format!("{verified:?}");
    let display = verified.to_string();
    assert!(!debug.contains(&hex(&fixture.signature)));
    assert!(!display.contains(&hex(&fixture.signature)));
    assert!(!debug.contains("signature_bytes"));
    let owned = verified.into_certificate();
    assert_eq!(owned.nonce(), &[0xa5; 32]);
    Ok(())
}

#[test]
fn signature_principal_type_and_time_checks_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = make_fixture(
        &["alice"],
        &[],
        &[],
        CertificateType::User,
        VALID_AFTER,
        VALID_BEFORE,
    )?;

    let verified = verify_certificate(
        &fixture.certificate,
        CertificateType::User,
        "alice",
        NOW,
        &[],
        &fixture.ca_point,
    )?;
    assert_eq!(verified.key_id(), "test certificate");

    let mut changed_signature = fixture.certificate.clone();
    let Some(last_byte) = changed_signature.last_mut() else {
        return Err("fixture unexpectedly had no signature byte".into());
    };
    *last_byte ^= 0x01;
    assert_eq!(
        verify_certificate(
            &changed_signature,
            CertificateType::User,
            "alice",
            NOW,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::InvalidSignature)
    );

    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::User,
            "bob",
            NOW,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::PrincipalMismatch)
    );
    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::Host,
            "alice",
            NOW,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::TypeMismatch)
    );
    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::User,
            "alice",
            VALID_AFTER - 1,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::NotYetValid)
    );
    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::User,
            "alice",
            VALID_BEFORE,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::Expired)
    );
    Ok(())
}

#[test]
fn unknown_critical_options_require_explicit_allowance_but_extensions_are_retained()
-> Result<(), Box<dyn Error>> {
    let unknown_data = b"opaque value".to_vec();
    let fixture = make_fixture(
        &["host.example"],
        &[("vendor.example/critical", unknown_data.clone())],
        &[("vendor.example/extension", b"ignored".to_vec())],
        CertificateType::Host,
        VALID_AFTER,
        VALID_BEFORE,
    )?;

    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::CriticalOptionNotAllowed)
    );

    let verified = verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &["vendor.example/critical"],
        &fixture.ca_point,
    )?;
    assert_eq!(
        verified.critical_options()[0].name(),
        "vendor.example/critical"
    );
    assert_eq!(verified.critical_options()[0].data(), unknown_data);
    assert_eq!(verified.extensions()[0].name(), "vendor.example/extension");
    assert_eq!(verified.extensions()[0].data(), b"ignored");
    Ok(())
}

#[test]
fn an_empty_principal_list_does_not_match_a_concrete_principal() -> Result<(), Box<dyn Error>> {
    let fixture = make_fixture(
        &[],
        &[],
        &[],
        CertificateType::Host,
        VALID_AFTER,
        VALID_BEFORE,
    )?;
    assert_eq!(
        verify_certificate(
            &fixture.certificate,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &fixture.ca_point,
        ),
        Err(CertificateError::PrincipalMismatch)
    );
    Ok(())
}

#[test]
fn parser_rejects_unsupported_algorithms_malformed_options_and_trailing_data()
-> Result<(), Box<dyn Error>> {
    assert!(neotales_ssh::cert::SUPPORTED_CERTIFICATE_ALGORITHMS.contains(&SSH_ED25519_CERT_V01));
    for algorithm in [
        "ssh-dss-cert-v01@openssh.com",
        "ecdsa-sha2-nistp999-cert-v01@openssh.com",
    ] {
        let mut writer = Writer::new();
        writer.write_string(algorithm)?;
        assert_eq!(
            parse_certificate(writer.as_bytes()),
            Err(CertificateError::UnsupportedAlgorithm)
        );
    }

    let valid = make_fixture(
        &["host.example"],
        &[],
        &[],
        CertificateType::Host,
        VALID_AFTER,
        VALID_BEFORE,
    )?;
    let mut trailing = valid.certificate.clone();
    trailing.push(0);
    assert_eq!(
        parse_certificate(&trailing),
        Err(CertificateError::TrailingData)
    );

    let short_nonce = make_fixture_with_nonce(&["host.example"], b"nonce", CertificateType::Host)?;
    assert!(parse_certificate(&short_nonce).is_ok());

    let duplicate = make_fixture(
        &["host.example"],
        &[
            ("vendor.example/option", Vec::new()),
            ("vendor.example/option", Vec::new()),
        ],
        &[],
        CertificateType::Host,
        VALID_AFTER,
        VALID_BEFORE,
    )?;
    assert_eq!(
        parse_certificate(&duplicate.certificate),
        Err(CertificateError::DuplicateOption)
    );

    Ok(())
}

#[test]
fn rsa_certificate_verifies_and_rejects_tampering_and_sha1_name() -> Result<(), Box<dyn Error>> {
    let signer = fixed_rsa_signer()?;
    let ca_blob = signer.public_key_blob()?;
    let exponent = signer.public_key().exponent().to_bytes_be();
    let modulus = signer.public_key().modulus().to_bytes_be();
    let subject_blob = ca_blob.clone();
    let fixture = make_signed_fixture(
        SSH_RSA_CERT_V01,
        &ca_blob,
        |writer| {
            write_positive_mpint(writer, exponent.as_slice())?;
            write_positive_mpint(writer, modulus.as_slice())?;
            Ok(())
        },
        |prefix| {
            signer
                .sign_sha256(prefix)
                .map_err(|error| Box::new(error) as Box<dyn Error>)
        },
    )?;

    let parsed = parse_certificate(&fixture.certificate)?;
    assert_eq!(parsed.subject_public_key_blob(), subject_blob.as_slice());
    assert_eq!(parsed.signature_key_blob(), ca_blob.as_slice());
    assert!(parsed.subject_public_key().is_none());
    verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &[],
        &ca_blob,
    )?;

    let mut changed_signature = fixture.certificate.clone();
    let Some(last_byte) = changed_signature.last_mut() else {
        return Err("fixture unexpectedly had no signature byte".into());
    };
    *last_byte ^= 0x01;
    assert_eq!(
        verify_certificate(
            &changed_signature,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &ca_blob,
        ),
        Err(CertificateError::InvalidSignature)
    );

    let sha1_named_signature = replace_signature_algorithm(&fixture.signature_blob, SSH_RSA)?;
    let sha1_named_certificate =
        certificate_with_signature(&fixture.signed_prefix, &sha1_named_signature)?;
    assert_eq!(
        verify_certificate(
            &sha1_named_certificate,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &ca_blob,
        ),
        Err(CertificateError::UnsupportedAlgorithm)
    );
    Ok(())
}

#[test]
fn p256_certificate_verifies_and_rejects_tampering() -> Result<(), Box<dyn Error>> {
    let signer = ecdsa_hostkey::EcdsaSigner::from_secret_scalar_bytes(&patterned_bytes::<32>(1))?;
    let ca_blob = signer.public_key_blob()?;
    let point = signer.public_key().as_bytes().to_vec();
    let fixture = make_signed_fixture(
        SSH_ECDSA_SHA2_NISTP256_CERT_V01,
        &ca_blob,
        |writer| {
            writer.write_string("nistp256")?;
            writer.write_string(point.as_slice())?;
            Ok(())
        },
        |prefix| {
            signer
                .sign_exchange_hash(prefix)
                .map_err(|error| Box::new(error) as Box<dyn Error>)
        },
    )?;

    let parsed = parse_certificate(&fixture.certificate)?;
    assert_eq!(parsed.algorithm(), SSH_ECDSA_SHA2_NISTP256_CERT_V01);
    assert_eq!(parsed.subject_public_key_blob(), ca_blob.as_slice());
    assert_eq!(parsed.signature_key_blob(), ca_blob.as_slice());
    assert!(parsed.subject_public_key().is_none());
    verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &[],
        &ca_blob,
    )?;

    let mut changed_signature = fixture.certificate.clone();
    let Some(last_byte) = changed_signature.last_mut() else {
        return Err("fixture unexpectedly had no signature byte".into());
    };
    *last_byte ^= 0x01;
    assert_eq!(
        verify_certificate(
            &changed_signature,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &ca_blob,
        ),
        Err(CertificateError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn p384_certificate_verifies_and_rejects_tampering() -> Result<(), Box<dyn Error>> {
    let signer =
        ecdsa_hostkey::EcdsaP384Signer::from_secret_scalar_bytes(&patterned_bytes::<48>(1))?;
    let ca_blob = signer.public_key_blob()?;
    let point = signer.public_key().as_bytes().to_vec();
    let fixture = make_signed_fixture(
        SSH_ECDSA_SHA2_NISTP384_CERT_V01,
        &ca_blob,
        |writer| {
            writer.write_string("nistp384")?;
            writer.write_string(point.as_slice())?;
            Ok(())
        },
        |prefix| {
            signer
                .sign_exchange_hash(prefix)
                .map_err(|error| Box::new(error) as Box<dyn Error>)
        },
    )?;

    let parsed = parse_certificate(&fixture.certificate)?;
    assert_eq!(parsed.algorithm(), SSH_ECDSA_SHA2_NISTP384_CERT_V01);
    assert_eq!(parsed.subject_public_key_blob(), ca_blob.as_slice());
    assert_eq!(parsed.signature_key_blob(), ca_blob.as_slice());
    assert!(parsed.subject_public_key().is_none());
    verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &[],
        &ca_blob,
    )?;

    let mut changed_signature = fixture.certificate.clone();
    let Some(last_byte) = changed_signature.last_mut() else {
        return Err("fixture unexpectedly had no signature byte".into());
    };
    *last_byte ^= 0x01;
    assert_eq!(
        verify_certificate(
            &changed_signature,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &ca_blob,
        ),
        Err(CertificateError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn p521_certificate_verifies_and_rejects_tampering() -> Result<(), Box<dyn Error>> {
    let signer =
        ecdsa_hostkey::EcdsaP521Signer::from_secret_scalar_bytes(&patterned_bytes::<66>(1))?;
    let ca_blob = signer.public_key_blob()?;
    let point = signer.public_key().as_bytes().to_vec();
    let fixture = make_signed_fixture(
        SSH_ECDSA_SHA2_NISTP521_CERT_V01,
        &ca_blob,
        |writer| {
            writer.write_string("nistp521")?;
            writer.write_string(point.as_slice())?;
            Ok(())
        },
        |prefix| {
            signer
                .sign_exchange_hash(prefix)
                .map_err(|error| Box::new(error) as Box<dyn Error>)
        },
    )?;

    let parsed = parse_certificate(&fixture.certificate)?;
    assert_eq!(parsed.algorithm(), SSH_ECDSA_SHA2_NISTP521_CERT_V01);
    assert_eq!(parsed.subject_public_key_blob(), ca_blob.as_slice());
    assert_eq!(parsed.signature_key_blob(), ca_blob.as_slice());
    assert!(parsed.subject_public_key().is_none());
    verify_certificate(
        &fixture.certificate,
        CertificateType::Host,
        "host.example",
        NOW,
        &[],
        &ca_blob,
    )?;

    let mut changed_signature = fixture.certificate.clone();
    let Some(last_byte) = changed_signature.last_mut() else {
        return Err("fixture unexpectedly had no signature byte".into());
    };
    *last_byte ^= 0x01;
    assert_eq!(
        verify_certificate(
            &changed_signature,
            CertificateType::Host,
            "host.example",
            NOW,
            &[],
            &ca_blob,
        ),
        Err(CertificateError::InvalidSignature)
    );
    Ok(())
}

fn make_signed_fixture<F, G>(
    algorithm: &str,
    ca_blob: &[u8],
    write_subject: F,
    sign: G,
) -> Result<SignedFixture, Box<dyn Error>>
where
    F: FnOnce(&mut Writer) -> Result<(), Box<dyn Error>>,
    G: FnOnce(&[u8]) -> Result<Vec<u8>, Box<dyn Error>>,
{
    let mut principal_body = Writer::new();
    principal_body.write_string("host.example")?;

    let mut prefix = Writer::new();
    prefix.write_string(algorithm)?;
    prefix.write_string(&[0xa5; 32])?;
    write_subject(&mut prefix)?;
    prefix.write_uint64(7);
    prefix.write_uint32(CertificateType::Host.as_u32());
    prefix.write_string("test certificate")?;
    prefix.write_string(principal_body.as_bytes())?;
    prefix.write_uint64(VALID_AFTER);
    prefix.write_uint64(VALID_BEFORE);
    prefix.write_string(&[])?;
    prefix.write_string(&[])?;
    prefix.write_string(&[])?;
    prefix.write_string(ca_blob)?;

    let signed_prefix = prefix.as_bytes().to_vec();
    let signature_blob = sign(&signed_prefix)?;
    let certificate = certificate_with_signature(prefix.as_bytes(), &signature_blob)?;

    Ok(SignedFixture {
        certificate,
        signed_prefix,
        signature_blob,
    })
}

fn certificate_with_signature(
    signed_prefix: &[u8],
    signature_blob: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut certificate = signed_prefix.to_vec();
    let mut signature_writer = Writer::new();
    signature_writer.write_string(signature_blob)?;
    certificate.extend(signature_writer.into_bytes());
    Ok(certificate)
}

fn replace_signature_algorithm(
    signature_blob: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut reader = Reader::new(signature_blob);
    let _old_algorithm = reader.read_string()?;
    let signature = reader.read_string_bytes()?;
    if !reader.is_empty() {
        return Err("signature fixture has trailing data".into());
    }
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_string(signature.as_slice())?;
    Ok(writer.into_bytes())
}

fn fixed_rsa_signer() -> Result<rsa_hostkey::RsaHostSigner, Box<dyn Error>> {
    let p = rsa::BigUint::from_bytes_be(&decode_hex(
        "00fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf07",
    )?);
    let q = rsa::BigUint::from_bytes_be(&decode_hex(
        "00ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be5536f71",
    )?);
    Ok(rsa_hostkey::RsaHostSigner::from_p_q(
        p,
        q,
        rsa::BigUint::from(65537_u32),
    )?)
}

fn write_positive_mpint(writer: &mut Writer, value: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut positive = value.to_vec();
    if positive.first().is_some_and(|byte| byte & 0x80 != 0) {
        positive.insert(0, 0);
    }
    writer.write_mpint(positive.as_slice())?;
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex input has odd length".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn patterned_bytes<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn make_fixture(
    principals: &[&str],
    critical_options: &[(&str, Vec<u8>)],
    extensions: &[(&str, Vec<u8>)],
    certificate_type: CertificateType,
    valid_after: u64,
    valid_before: u64,
) -> Result<Fixture, Box<dyn Error>> {
    make_fixture_with_nonce_and_options(
        principals,
        &[0xa5; 32],
        critical_options,
        extensions,
        certificate_type,
        valid_after,
        valid_before,
    )
}

fn make_fixture_with_nonce(
    principals: &[&str],
    nonce: &[u8],
    certificate_type: CertificateType,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let fixture = make_fixture_with_nonce_and_options(
        principals,
        nonce,
        &[],
        &[],
        certificate_type,
        VALID_AFTER,
        VALID_BEFORE,
    )?;
    Ok(fixture.certificate)
}

fn make_fixture_with_nonce_and_options(
    principals: &[&str],
    nonce: &[u8],
    critical_options: &[(&str, Vec<u8>)],
    extensions: &[(&str, Vec<u8>)],
    certificate_type: CertificateType,
    valid_after: u64,
    valid_before: u64,
) -> Result<Fixture, Box<dyn Error>> {
    let ca = SigningKey::from_bytes(&CA_SEED);
    let subject = SigningKey::from_bytes(&SUBJECT_SEED);
    let ca_point = ca.verifying_key().to_bytes();
    let subject_point = subject.verifying_key().to_bytes();

    let mut principal_body = Writer::new();
    for principal in principals {
        principal_body.write_string(principal)?;
    }

    let critical_body = options_body(critical_options)?;
    let extension_body = options_body(extensions)?;

    let mut ca_blob_writer = Writer::new();
    ca_blob_writer.write_string(SSH_ED25519)?;
    ca_blob_writer.write_string(&ca_point)?;
    let ca_blob = ca_blob_writer.into_bytes();

    let mut prefix = Writer::new();
    prefix.write_string(SSH_ED25519_CERT_V01)?;
    prefix.write_string(nonce)?;
    prefix.write_string(&subject_point)?;
    prefix.write_uint64(7);
    prefix.write_uint32(certificate_type.as_u32());
    prefix.write_string("test certificate")?;
    prefix.write_string(principal_body.as_bytes())?;
    prefix.write_uint64(valid_after);
    prefix.write_uint64(valid_before);
    prefix.write_string(&critical_body)?;
    prefix.write_string(&extension_body)?;
    prefix.write_string(&[])?;
    prefix.write_string(&ca_blob)?;

    let signed_prefix = prefix.as_bytes().to_vec();
    let signature = ca.sign(&signed_prefix);
    let signature_bytes = signature.to_bytes();
    let mut signature_blob = Writer::new();
    signature_blob.write_string(SSH_ED25519)?;
    signature_blob.write_string(&signature_bytes)?;
    prefix.write_string(signature_blob.as_bytes())?;

    Ok(Fixture {
        certificate: prefix.into_bytes(),
        ca_point,
        ca_blob,
        subject_point,
        signature: signature_bytes.to_vec(),
    })
}

fn options_body(options: &[(&str, Vec<u8>)]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    for (name, data) in options {
        writer.write_string(name)?;
        writer.write_string(data)?;
    }
    Ok(writer.into_bytes())
}

fn nested_string(value: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_string(value)?;
    Ok(writer.into_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}
