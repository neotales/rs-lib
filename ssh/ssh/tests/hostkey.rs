// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/hostkey.rs"]
mod hostkey;

use std::cell::Cell;
use std::convert::Infallible;
use std::panic::catch_unwind;

use hostkey::{
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH, Ed25519PublicKey,
    Ed25519Signer, HostKeyError, SSH_ED25519, VerifiedHostKey, check_host_key_algorithm,
    verify_and_trust_host_key, verify_host_key_signature,
};
use neotales_ssh::Writer;
use zeroize::ZeroizeOnDrop;

const FIXED_SEED: [u8; ED25519_SEED_LENGTH] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const FIXED_HASH: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
// PROVENANCE: **computed from the primitive**. `EXPECTED_PUBLIC_BLOB` is the
// SSH wire blob for the Ed25519 public key of the seed `00 01 .. 1f`, and
// `EXPECTED_SIGNATURE_BLOB` is the blob for that key's signature over the fixed
// 32-byte hash `10 11 .. 2f`. Both were produced by running Ed25519 (RFC 8032)
// directly, not through `Ed25519Signer`, and both were then checked against this
// crate.
//
// Neither is an OpenSSH vector. `ssh-ed25519` is the algorithm name the
// specification registers (RFC 4253 section 8.1, RFC 8709 for the modern
// spelling) and it names where the encoding comes from, not who produced these
// particular bytes. RFC 8709 publishes worked examples, but not for this seed.
//
// The seed and the hash are inputs, not expected values.
const EXPECTED_PUBLIC_BLOB: &str = "0000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const EXPECTED_SIGNATURE_BLOB: &str = "0000000b7373682d6564323535313900000040d50adc7f893adacd41bebb14204d2ae34d5702a553a5bfc1d09cad6a40c91907c26ae5a3799f4f0f20b28e7d2e8d3725fd3650c8528ab08a9f1f54370af5a60a";

#[test]
fn fixed_seed_produces_exact_deterministic_ssh_blobs() -> Result<(), HostKeyError> {
    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);

    assert_eq!(seed, [0_u8; ED25519_SEED_LENGTH]);
    assert_eq!(Ed25519Signer::algorithm(), SSH_ED25519);
    assert_eq!(Ed25519PublicKey::algorithm(), SSH_ED25519);
    assert_eq!(
        signer.public_key().as_bytes().len(),
        ED25519_PUBLIC_KEY_LENGTH
    );
    assert_eq!(signer.public_key_blob()?, hex(EXPECTED_PUBLIC_BLOB));

    // PROVENANCE: **computed from the primitive** -- Ed25519 over FIXED_HASH, as
    // above. Ed25519 is deterministic by construction, so there is no nonce and
    // nothing to vary between runs.
    let signature = signer.sign_exchange_hash(&FIXED_HASH)?;
    assert_eq!(signature, hex(EXPECTED_SIGNATURE_BLOB));
    assert_eq!(signer.sign_exchange_hash(&FIXED_HASH)?, signature);
    assert_eq!(
        signature.len(),
        4 + SSH_ED25519.len() + 4 + ED25519_SIGNATURE_LENGTH
    );

    let public_key = Ed25519PublicKey::from_blob(&hex(EXPECTED_PUBLIC_BLOB))?;
    verify_host_key_signature(&public_key, &signature, &FIXED_HASH)
}

#[test]
fn valid_blobs_round_trip_and_sign_raw_exchange_hash_bytes() -> Result<(), HostKeyError> {
    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);
    let public_blob = signer.public_key_blob()?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;

    let public_key = Ed25519PublicKey::from_blob(&public_blob)?;
    assert_eq!(public_key.as_bytes().len(), ED25519_PUBLIC_KEY_LENGTH);
    assert_eq!(public_key.to_blob()?, public_blob);
    verify_host_key_signature(&public_key, &signature_blob, &FIXED_HASH)?;

    let signature_start = signature_blob
        .len()
        .checked_sub(ED25519_SIGNATURE_LENGTH)
        .ok_or(HostKeyError::InvalidFieldLength)?;
    assert_eq!(
        &signature_blob[signature_start..],
        // The bare 64-byte Ed25519 signature, the same bytes as the tail of
        // EXPECTED_SIGNATURE_BLOB above. Same provenance: computed from the
        // primitive.
        &hex(
            "d50adc7f893adacd41bebb14204d2ae34d5702a553a5bfc1d09cad6a40c91907c26ae5a3799f4f0f20b28e7d2e8d3725fd3650c8528ab08a9f1f54370af5a60a"
        )
    );
    Ok(())
}

#[test]
fn public_key_decoder_is_exact_and_rejects_every_truncation() -> Result<(), HostKeyError> {
    let blob = hex(EXPECTED_PUBLIC_BLOB);
    assert!(Ed25519PublicKey::from_blob(&blob).is_ok());
    for length in 0..blob.len() {
        assert!(
            Ed25519PublicKey::from_blob(&blob[..length]).is_err(),
            "accepted public-key prefix of {length} bytes"
        );
    }

    assert_eq!(check_host_key_algorithm(SSH_ED25519), Ok(()));
    for algorithm in [
        "",
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-rsa",
        "SSH-ED25519",
    ] {
        assert_eq!(
            check_host_key_algorithm(algorithm),
            Err(HostKeyError::UnsupportedAlgorithm)
        );
        assert_eq!(
            Ed25519PublicKey::from_blob(&wire_blob(algorithm, &blob[15..])?),
            Err(HostKeyError::UnsupportedAlgorithm)
        );
    }

    let point = &blob[19..];
    for length in [0, 31, 33, 64] {
        let mut wrong_length = point.to_vec();
        if length <= point.len() {
            wrong_length.truncate(length);
        } else {
            wrong_length.resize(length, 0);
        }
        assert_eq!(
            Ed25519PublicKey::from_blob(&wire_blob(SSH_ED25519, &wrong_length)?),
            Err(HostKeyError::InvalidFieldLength)
        );
    }

    let mut trailing = blob;
    trailing.push(0);
    assert_eq!(
        Ed25519PublicKey::from_blob(&trailing),
        Err(HostKeyError::TrailingData)
    );

    let mut malformed_point = [0_u8; 32];
    malformed_point[0] = 2;
    assert_eq!(
        Ed25519PublicKey::from_blob(&wire_blob(SSH_ED25519, &malformed_point)?),
        Err(HostKeyError::InvalidPublicKey)
    );
    assert_eq!(
        Ed25519PublicKey::from_point(&[0_u8; 32]),
        Err(HostKeyError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn signature_verification_rejects_wrong_key_hash_algorithm_and_malformed_data()
-> Result<(), HostKeyError> {
    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);
    let public_blob = signer.public_key_blob()?;
    let public_key = Ed25519PublicKey::from_blob(&public_blob)?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;
    let raw_signature = &signature_blob[signature_blob.len() - ED25519_SIGNATURE_LENGTH..];

    let mut changed_hash = FIXED_HASH;
    changed_hash[0] ^= 1;
    assert_eq!(
        verify_host_key_signature(&public_key, &signature_blob, &changed_hash),
        Err(HostKeyError::InvalidSignature)
    );

    let mut other_seed = [0x22_u8; ED25519_SEED_LENGTH];
    let other_signer = Ed25519Signer::from_seed(&mut other_seed);
    let other_key = Ed25519PublicKey::from_blob(&other_signer.public_key_blob()?)?;
    assert_eq!(
        verify_host_key_signature(&other_key, &signature_blob, &FIXED_HASH),
        Err(HostKeyError::InvalidSignature)
    );

    assert!(verify_host_key_signature(&public_key, raw_signature, &FIXED_HASH).is_err());
    for length in 0..signature_blob.len() {
        assert!(
            verify_host_key_signature(&public_key, &signature_blob[..length], &FIXED_HASH).is_err(),
            "accepted signature prefix of {length} bytes"
        );
    }

    assert_eq!(
        verify_host_key_signature(
            &public_key,
            &wire_blob("rsa-sha2-256", raw_signature)?,
            &FIXED_HASH,
        ),
        Err(HostKeyError::UnsupportedAlgorithm)
    );
    for length in [0, 63, 65, 128] {
        let mut bytes = raw_signature.to_vec();
        bytes.resize(length, 0);
        assert_eq!(
            verify_host_key_signature(&public_key, &wire_blob(SSH_ED25519, &bytes)?, &FIXED_HASH),
            Err(HostKeyError::InvalidFieldLength)
        );
    }

    let mut trailing = signature_blob.clone();
    trailing.push(0);
    assert_eq!(
        verify_host_key_signature(&public_key, &trailing, &FIXED_HASH),
        Err(HostKeyError::TrailingData)
    );
    assert_eq!(
        verify_host_key_signature(
            &public_key,
            &wire_blob(SSH_ED25519, &[0_u8; ED25519_SIGNATURE_LENGTH])?,
            &FIXED_HASH,
        ),
        Err(HostKeyError::InvalidSignature)
    );

    let wrong_key_algorithm = wire_blob("ssh-rsa", public_key.as_bytes())?;
    assert_eq!(
        Ed25519PublicKey::from_blob(&wrong_key_algorithm),
        Err(HostKeyError::UnsupportedAlgorithm)
    );
    Ok(())
}

#[test]
fn trust_callback_is_mandatory_and_runs_only_after_cryptographic_verification()
-> Result<(), HostKeyError> {
    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);
    let public_blob = signer.public_key_blob()?;
    let public_key = Ed25519PublicKey::from_blob(&public_blob)?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;

    let mut observed = None;
    let verified: VerifiedHostKey =
        verify_and_trust_host_key(&public_blob, &signature_blob, &FIXED_HASH, |candidate| {
            observed = Some(*candidate);
            Ok::<(), Infallible>(())
        })?;
    assert_eq!(observed, Some(public_key));
    assert_eq!(verified.public_key(), &public_key);
    assert_eq!(verified.to_blob()?, public_blob);

    assert_eq!(
        verify_and_trust_host_key(
            &public_blob,
            &signature_blob,
            &FIXED_HASH,
            |_candidate| Err::<(), _>(PolicyRejected),
        ),
        Err(HostKeyError::TrustRejected)
    );

    let calls = Cell::new(0_u8);
    let mut changed_hash = FIXED_HASH;
    changed_hash[31] ^= 0x80;
    let invalid_result =
        verify_and_trust_host_key(&public_blob, &signature_blob, &changed_hash, |_candidate| {
            calls.set(calls.get() + 1);
            Ok::<(), Infallible>(())
        });
    assert_eq!(invalid_result, Err(HostKeyError::InvalidSignature));
    assert_eq!(calls.get(), 0);
    Ok(())
}

#[test]
fn panicking_trust_callback_is_a_rejection_not_success() -> Result<(), HostKeyError> {
    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);
    let public_blob = signer.public_key_blob()?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;

    let outcome = catch_unwind(|| {
        verify_and_trust_host_key(
            &public_blob,
            &signature_blob,
            &FIXED_HASH,
            |_candidate| -> Result<(), Infallible> {
                panic!("test trust callback panic");
            },
        )
    });
    assert!(matches!(outcome, Ok(Err(HostKeyError::VerifierPanicked))));
    Ok(())
}

#[test]
fn signer_wipes_seed_copies_and_never_formats_secret_bytes() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();

    let mut seed = FIXED_SEED;
    let signer = Ed25519Signer::from_seed(&mut seed);
    assert_eq!(seed, [0_u8; ED25519_SEED_LENGTH]);

    let debug = format!("{signer:?}");
    assert!(debug.contains("Ed25519Signer"));
    assert!(!debug.contains("secret_key"));
    assert!(!debug.contains("signing_key"));
    assert!(!debug.contains("0001020304050607"));

    for error in [
        HostKeyError::SigningFailed,
        HostKeyError::TrustRejected,
        HostKeyError::VerifierPanicked,
        HostKeyError::UnsupportedAlgorithm,
    ] {
        let text = error.to_string();
        assert!(!text.contains("seed"));
        assert!(!text.contains("signature"));
        assert!(!text.contains("hash"));
    }
}

struct PolicyRejected;

fn wire_blob(algorithm: &str, field: &[u8]) -> Result<Vec<u8>, HostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_string(&field)?;
    Ok(writer.into_bytes())
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input must have an even length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex input must be ASCII");
            u8::from_str_radix(text, 16).expect("hex input must be hexadecimal")
        })
        .collect()
}
