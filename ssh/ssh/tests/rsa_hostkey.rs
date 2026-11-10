// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/rsa_hostkey.rs"]
mod rsa_hostkey;

use std::cell::Cell;
use std::convert::Infallible;
use std::panic::catch_unwind;

use neotales_ssh::{Reader, Writer};
use rsa_hostkey::{
    HostKeyError, RSA_SHA2_256, RSA_SHA2_512, RsaHostKeyAlgorithm, RsaHostKeyError, RsaHostSigner,
    RsaPublicKey, RsaSignatureAlgorithm, SSH_RSA, SSH_RSA_SHA2_256, SSH_RSA_SHA2_512,
    VerifiedHostKey, VerifiedRsaHostKey, check_public_key_type, verify_and_trust_host_key,
    verify_host_key_signature,
};
use sha2::Digest;

const EXCHANGE_HASH: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

#[test]
fn fixed_key_signs_and_verifies_both_sha2_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let public_blob = signer.to_public_key_blob()?;
    let public_key = RsaPublicKey::from_blob(&public_blob)?;

    assert_eq!(public_blob, signer.public_key_blob()?);
    assert_eq!(public_key.to_blob()?, public_blob);
    assert_eq!(RsaPublicKey::algorithm(), SSH_RSA);
    assert_eq!(RsaPublicKey::key_type(), SSH_RSA);
    assert_eq!(public_key.size(), 128);
    assert_eq!(
        RsaPublicKey::from_public_key(public_key.public_key())?,
        public_key
    );

    let sha256_signature = signer.sign_sha256(&EXCHANGE_HASH)?;
    let sha512_signature = signer.sign_sha512(&EXCHANGE_HASH)?;
    assert_ne!(sha256_signature, sha512_signature);
    assert_eq!(signature_algorithm(&sha256_signature)?, SSH_RSA_SHA2_256);
    assert_eq!(signature_algorithm(&sha512_signature)?, SSH_RSA_SHA2_512);
    assert_eq!(signature_bytes(&sha256_signature)?.len(), public_key.size());
    assert_eq!(signature_bytes(&sha512_signature)?.len(), public_key.size());

    verify_host_key_signature(&public_key, &sha256_signature, &EXCHANGE_HASH)?;
    verify_host_key_signature(&public_key, &sha512_signature, &EXCHANGE_HASH)?;

    let mut wrapped_hash = Writer::new();
    wrapped_hash.write_string(&EXCHANGE_HASH)?;
    assert_eq!(
        verify_host_key_signature(&public_key, &sha256_signature, wrapped_hash.as_bytes()),
        Err(RsaHostKeyError::InvalidSignature)
    );

    let mut changed_hash = EXCHANGE_HASH;
    changed_hash[0] ^= 1;
    assert_eq!(
        verify_host_key_signature(&public_key, &sha512_signature, &changed_hash),
        Err(RsaHostKeyError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn public_blob_rejects_wrong_type_nonpositive_values_and_trailing_data()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let valid = signer.to_public_key_blob()?;
    let mut reader = Reader::new(&valid);
    let _key_type = reader.read_string()?;
    let exponent = reader.read_mpint()?.to_vec();
    let modulus = reader.read_mpint()?.to_vec();
    assert!(reader.is_empty());

    for algorithm in [
        "",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-rsa-cert-v01@openssh.com",
    ] {
        let blob = public_blob(algorithm, &exponent, &modulus)?;
        assert_eq!(
            RsaPublicKey::from_blob(&blob),
            Err(RsaHostKeyError::UnsupportedAlgorithm)
        );
    }
    assert_eq!(check_public_key_type(SSH_RSA), Ok(()));
    assert_eq!(
        check_public_key_type(SSH_RSA_SHA2_256),
        Err(RsaHostKeyError::UnsupportedAlgorithm)
    );

    for value in [&[0_u8][..], &[0x80][..], &[0xff][..]] {
        let blob = public_blob(SSH_RSA, value, &modulus)?;
        assert_eq!(
            RsaPublicKey::from_blob(&blob),
            Err(RsaHostKeyError::InvalidPublicKey)
        );
        let blob = public_blob(SSH_RSA, &exponent, value)?;
        assert_eq!(
            RsaPublicKey::from_blob(&blob),
            Err(RsaHostKeyError::InvalidPublicKey)
        );
    }

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        RsaPublicKey::from_blob(&trailing),
        Err(RsaHostKeyError::TrailingData)
    );
    for length in 0..valid.len() {
        assert!(
            RsaPublicKey::from_blob(&valid[..length]).is_err(),
            "accepted public-key prefix of {length} bytes"
        );
    }
    Ok(())
}

#[test]
fn signature_decoder_rejects_sha1_pss_trailing_bytes_and_truncation()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let public_key = signer.public_key();
    let valid = signer.sign_sha256(&EXCHANGE_HASH)?;
    let raw = signature_bytes(&valid)?;

    assert!(verify_host_key_signature(public_key, &raw, &EXCHANGE_HASH).is_err());
    for algorithm in [
        SSH_RSA,
        "rsa-pss-sha2-256",
        "rsa-pss-sha2-512",
        "rsa-sha2-384",
        "",
    ] {
        let blob = signature_blob(algorithm, &raw)?;
        assert_eq!(
            verify_host_key_signature(public_key, &blob, &EXCHANGE_HASH),
            Err(RsaHostKeyError::UnsupportedAlgorithm)
        );
    }

    let private = fixed_rsa_private_key()?;
    let sha1_digest = sha1::Sha1::digest(EXCHANGE_HASH);
    let sha1_raw = private.sign(rsa::Pkcs1v15Sign::new_unprefixed(), sha1_digest.as_slice())?;
    let sha1_blob = signature_blob(SSH_RSA, &sha1_raw)?;
    assert_eq!(
        verify_host_key_signature(public_key, &sha1_blob, &EXCHANGE_HASH),
        Err(RsaHostKeyError::UnsupportedAlgorithm)
    );

    let mut body_trailing = raw.clone();
    body_trailing.push(0);
    let body_trailing_blob = signature_blob(SSH_RSA_SHA2_256, &body_trailing)?;
    assert_eq!(
        verify_host_key_signature(public_key, &body_trailing_blob, &EXCHANGE_HASH),
        Err(RsaHostKeyError::InvalidFieldLength)
    );

    let mut outer_trailing = valid.clone();
    outer_trailing.push(0);
    assert_eq!(
        verify_host_key_signature(public_key, &outer_trailing, &EXCHANGE_HASH),
        Err(RsaHostKeyError::TrailingData)
    );

    for length in [0, 1, 4, 16, 255, 257] {
        let mut wrong_length = raw.clone();
        wrong_length.resize(length, 0);
        let blob = signature_blob(SSH_RSA_SHA2_256, &wrong_length)?;
        assert!(
            verify_host_key_signature(public_key, &blob, &EXCHANGE_HASH).is_err(),
            "accepted signature length {length}"
        );
    }
    for length in 0..valid.len() {
        assert!(
            verify_host_key_signature(public_key, &valid[..length], &EXCHANGE_HASH).is_err(),
            "accepted signature prefix of {length} bytes"
        );
    }
    Ok(())
}

#[test]
fn a_signature_from_a_different_modulus_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let other = alternate_signer()?;
    let signature = signer.sign_sha512(&EXCHANGE_HASH)?;

    assert_eq!(
        verify_host_key_signature(other.public_key(), &signature, &EXCHANGE_HASH),
        Err(RsaHostKeyError::InvalidSignature)
    );
    assert_ne!(signer.public_key().modulus(), other.public_key().modulus());
    Ok(())
}

#[test]
fn trust_callback_is_mandatory_and_runs_after_cryptographic_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let public_blob = signer.to_public_key_blob()?;
    let public_key = RsaPublicKey::from_blob(&public_blob)?;
    let signature = signer.sign_sha512(&EXCHANGE_HASH)?;
    let mut observed = None;

    let verified: VerifiedRsaHostKey =
        verify_and_trust_host_key(&public_blob, &signature, &EXCHANGE_HASH, |candidate| {
            observed = Some(candidate.clone());
            Ok::<(), Infallible>(())
        })?;
    assert_eq!(observed.as_ref(), Some(&public_key));
    assert_eq!(verified.public_key(), &public_key);
    assert_eq!(verified.to_blob()?, public_blob);
    let _: &VerifiedHostKey = &verified;

    assert_eq!(
        verify_and_trust_host_key(
            &public_blob,
            &signature,
            &EXCHANGE_HASH,
            |_candidate| Err::<(), _>(PolicyRejected),
        ),
        Err(RsaHostKeyError::TrustRejected)
    );

    let calls = Cell::new(0_u8);
    let mut changed_hash = EXCHANGE_HASH;
    changed_hash[31] ^= 0x80;
    let result = verify_and_trust_host_key(&public_blob, &signature, &changed_hash, |_candidate| {
        calls.set(calls.get() + 1);
        Ok::<(), Infallible>(())
    });
    assert_eq!(result, Err(RsaHostKeyError::InvalidSignature));
    assert_eq!(calls.get(), 0);

    let outcome = catch_unwind(|| {
        verify_and_trust_host_key(
            &public_blob,
            &signature,
            &EXCHANGE_HASH,
            |_candidate| -> Result<(), Infallible> {
                panic!("test trust callback panic");
            },
        )
    });
    assert!(matches!(
        outcome,
        Ok(Err(RsaHostKeyError::VerifierPanicked))
    ));
    Ok(())
}

#[test]
fn signer_and_errors_redact_private_material() -> Result<(), Box<dyn std::error::Error>> {
    let signer = fixed_signer()?;
    let debug = format!("{signer:?}");
    let display = signer.to_string();
    assert!(debug.contains("RsaHostSigner"));
    assert!(display.contains("RsaHostSigner"));
    assert!(!debug.contains("fd2e217a"));
    assert!(!display.contains("fd2e217a"));
    assert!(!debug.contains("private"));
    assert!(!display.contains("private"));

    for error in [
        RsaHostKeyError::InvalidPublicKey,
        RsaHostKeyError::InvalidSignature,
        RsaHostKeyError::SigningFailed,
        RsaHostKeyError::TrustRejected,
        RsaHostKeyError::VerifierPanicked,
    ] {
        let text = error.to_string();
        assert!(!text.contains("fd2e217a"));
        assert!(!text.contains("ccd0ae1c"));
    }
    let _: HostKeyError = RsaHostKeyError::UnsupportedAlgorithm;
    let _: RsaSignatureAlgorithm = RsaHostKeyAlgorithm::Sha512;
    assert_eq!(RsaHostKeyAlgorithm::Sha256.name(), RSA_SHA2_256);
    assert_eq!(RsaHostKeyAlgorithm::Sha512.name(), RSA_SHA2_512);
    assert_eq!(
        RsaHostSigner::new(fixed_rsa_private_key()?, SSH_RSA_SHA2_512,)?.algorithm(),
        SSH_RSA_SHA2_512
    );
    Ok(())
}

fn fixed_signer() -> Result<RsaHostSigner, Box<dyn std::error::Error>> {
    let p = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf07",
    )?);
    let q = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be5536f71",
    )?);
    Ok(RsaHostSigner::from_p_q(
        p,
        q,
        rsa::BigUint::from(65537_u32),
    )?)
}

fn fixed_rsa_private_key() -> Result<rsa::RsaPrivateKey, Box<dyn std::error::Error>> {
    let p = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf07",
    )?);
    let q = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be5536f71",
    )?);
    Ok(rsa::RsaPrivateKey::from_p_q(
        p,
        q,
        rsa::BigUint::from(65537_u32),
    )?)
}

fn alternate_signer() -> Result<RsaHostSigner, Box<dyn std::error::Error>> {
    let p = rsa::BigUint::from_bytes_be(&hex_bytes(
        "fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf2b",
    )?);
    let q = rsa::BigUint::from_bytes_be(&hex_bytes(
        "ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be553707d",
    )?);
    Ok(RsaHostSigner::from_p_q(
        p,
        q,
        rsa::BigUint::from(65537_u32),
    )?)
}

fn public_blob(
    algorithm: &str,
    exponent: &[u8],
    modulus: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_mpint(exponent)?;
    writer.write_mpint(modulus)?;
    Ok(writer.into_bytes())
}

fn signature_blob(
    algorithm: &str,
    signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_string(signature)?;
    Ok(writer.into_bytes())
}

fn signature_algorithm(blob: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.read_string_bytes()?;
    let signature = reader.read_string_bytes()?;
    if !reader.is_empty() {
        return Err("signature has trailing data".into());
    }
    if signature.is_empty() {
        return Err("signature is empty".into());
    }
    Ok(String::from_utf8(algorithm)?)
}

fn signature_bytes(blob: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut reader = Reader::new(blob);
    let _algorithm = reader.read_string()?;
    let signature = reader.read_string_bytes()?;
    if !reader.is_empty() {
        return Err("signature has trailing data".into());
    }
    Ok(signature)
}

fn hex_bytes(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("fixed hex has odd length".into());
    }
    input
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

struct PolicyRejected;
