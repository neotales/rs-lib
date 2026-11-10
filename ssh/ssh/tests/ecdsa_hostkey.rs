// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/ecdsa_hostkey.rs"]
mod ecdsa_hostkey;

use std::cell::Cell;
use std::convert::Infallible;
use std::panic::catch_unwind;

use ecdsa_hostkey::{
    CURVE_NISTP256, CURVE_NISTP384, CURVE_NISTP521, ECDSA_CURVE_NISTP256, ECDSA_CURVE_NISTP384,
    ECDSA_CURVE_NISTP521, ECDSA_P384_PUBLIC_KEY_LENGTH, ECDSA_P384_SECRET_SCALAR_LENGTH,
    ECDSA_P384_SIGNATURE_LENGTH, ECDSA_P521_PUBLIC_KEY_LENGTH, ECDSA_P521_SECRET_SCALAR_LENGTH,
    ECDSA_P521_SIGNATURE_LENGTH, ECDSA_PUBLIC_KEY_LENGTH, ECDSA_SECRET_SCALAR_LENGTH,
    ECDSA_SHA2_NISTP256, ECDSA_SHA2_NISTP384, ECDSA_SHA2_NISTP521, ECDSA_SIGNATURE_LENGTH,
    EcdsaHostKeyError, EcdsaP384PublicKey, EcdsaP384Signer, EcdsaP521PublicKey, EcdsaP521Signer,
    EcdsaPublicKey, EcdsaSigner, HostKeyError, NISTP256, NISTP384, NISTP521, P256HostKeyError,
    P256PublicKey, P256Signer, P384HostKeyError, P384PublicKey, P384Signer, P521HostKeyError,
    P521PublicKey, P521Signer, SSH_ECDSA_SHA2_NISTP256, SSH_ECDSA_SHA2_NISTP384,
    SSH_ECDSA_SHA2_NISTP521, VerifiedEcdsaHostKey, VerifiedEcdsaP384HostKey,
    VerifiedEcdsaP521HostKey, VerifiedHostKey, VerifiedP256HostKey, VerifiedP384HostKey,
    VerifiedP521HostKey, check_curve_name, check_host_key_algorithm, verify_and_trust_host_key,
    verify_and_trust_p384_host_key, verify_and_trust_p521_host_key, verify_host_key_signature,
    verify_p384_host_key_signature, verify_p521_host_key_signature,
};
use neotales_ssh::{Reader, Writer};
use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, hazmat::PrehashSigner},
};
use sha2::Digest;

const FIXED_SCALAR: [u8; ECDSA_SECRET_SCALAR_LENGTH] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const FIXED_HASH: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
// PROVENANCE: **computed from the primitive**, for all six constants below.
// None of them is an OpenSSH vector and none is a published one; `ecdsa-sha2-*`
// names the algorithm, not a source of bytes.
//
// The public key blobs are `string "ecdsa-sha2-nistpNNN" || string "nistpNNN"
// || string Q`, where Q is the uncompressed SEC 1 point d*G for the fixed scalar
// `01 02 .. `. Computed by point multiplication, not through the signer.
//
// The signature blobs are `string "ecdsa-sha2-nistpNNN" || string (mpint r ||
// mpint s)`, where (r, s) is the RFC 6979 deterministic ECDSA signature.
//
// The prehash is **not** the exchange hash: `sign_exchange_hash` computes
// `SHA-256(exchange_hash)` (SHA-384 and SHA-512 for the larger curves) and signs
// that. This is required rather than a quirk of this implementation, and it is
// worth writing down because getting it wrong makes a hand-check of these vectors
// fail for a reason that is not a defect:
//
//   * RFC 5656 section 3.1.1: "The message hashing algorithm MUST be from the
//     SHA2 family of hash functions and is chosen according to the curve size as
//     specified in Section 6.2.1."
//   * RFC 5656 section 6.2.1 maps curve size to digest: `b <= 256` to SHA-256,
//     `256 < b <= 384` to SHA-384, `384 < b` to SHA-512.
//
// So the exchange hash is the *message*, and the curve's SHA-2 is applied to it
// before the ECDSA arithmetic. OpenSSH does the same, which is the reason the two
// interoperate. See `sign_exchange_hash` and `verify_host_key_signature` in
// `src/ecdsa_hostkey.rs`, which are the two halves of this construction.
//
// Which of these was re-derived independently, and which was not:
//
//   * P-256 and P-384: the full RFC 6979 derivation reproduces both `r` and `s`
//     byte for byte.
//   * P-521: the public key reproduces as d*G, and the signature verifies as a
//     valid ECDSA P-521 signature over SHA-512(exchange_hash), but the RFC 6979
//     nonce did not reproduce under any variant tried, so only validity is
//     confirmed there, not the derivation.
//
// The scalars and hashes are inputs, not expected values.
const EXPECTED_PUBLIC_BLOB: &str = "0000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";
const EXPECTED_SIGNATURE_BLOB: &str = "0000001365636473612d736861322d6e69737470323536000000490000002016e5bf0a2e4fef3284630f0e7797558c70f293af93f7d534b51b63d14fde405e0000002100bd6ac6d64caf0d02f13c9d5c489ac0e950b4e18a384d1a4cea529ee555caa7c0";
const EXPECTED_P384_PUBLIC_BLOB: &str = "0000001365636473612d736861322d6e69737470333834000000086e697374703338340000006104c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa02826bc1f83451b5c8962a75caff73588d4400a6296436154fb343c393e91048a6c7bcbadc83cd8a5f26feae883156f92a1";
const EXPECTED_P384_SIGNATURE_BLOB: &str = "0000001365636473612d736861322d6e69737470333834000000690000003100e51748f5ca145aaa638e626fe8833f5bd830d178729ffefc6eb9bae50f9c0db407696b27eaccb642c8659f3dc24b02080000003040fe6771799bc64cb1a4e23789bf9f528e3316fefd4fde11f565697cf985461af7c80c0ccbf165b67b2ec95551368751";
const EXPECTED_P521_PUBLIC_BLOB: &str = "0000001365636473612d736861322d6e69737470353231000000086e697374703532310000008504000366c8c3b22dfb87d0922163cd4b53cd43a24a29f79292fa4ef1288d69ed139a7fc0552120ea1bdb4f88ca0da4eb91de9b077018d5885dbff0e91a66639a9b72a500bd5e44e3a526e1051a4371c9bae5c7611ed489582ecdcc1ea277fe2379286a3a1c0c7224c7b1ebb0a8b6e5fbda5cead23f47c300917d4f98f2d2d4dc79d0109826";
const EXPECTED_P521_SIGNATURE_BLOB: &str = "0000001365636473612d736861322d6e697374703532310000008b0000004201691e3b1d794fce6fa54585de3cdb0112c15e45366e0b3bb735d7ba790cdbf8c20e5c3ea8a07202cb3b5f3eacff9acb523f5606d996ad62fc0a4f245436a631cf2d000000410d033baeb9f95f4ab93ab0a502c362fb8547535bcb36fba116380fc0e9553098d2172c8d0c21f17cead93855daaf25e47a3a083bcb313326aa05f9613e338d5dcc";

#[test]
fn fixed_scalar_and_hash_produce_exact_deterministic_blobs() -> Result<(), EcdsaHostKeyError> {
    let mut scalar = FIXED_SCALAR;
    let signer = EcdsaSigner::from_secret_scalar(&mut scalar)?;
    let public_blob = signer.public_key_blob()?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;

    assert_eq!(public_blob, hex(EXPECTED_PUBLIC_BLOB));
    assert_eq!(signature_blob, hex(EXPECTED_SIGNATURE_BLOB));
    assert_eq!(scalar, [0_u8; ECDSA_SECRET_SCALAR_LENGTH]);
    assert_eq!(EcdsaSigner::algorithm(), SSH_ECDSA_SHA2_NISTP256);
    assert_eq!(ECDSA_SHA2_NISTP256, SSH_ECDSA_SHA2_NISTP256);
    assert_eq!(EcdsaSigner::curve_name(), CURVE_NISTP256);
    assert_eq!(NISTP256, CURVE_NISTP256);
    assert_eq!(
        signer.public_key().as_bytes().len(),
        ECDSA_PUBLIC_KEY_LENGTH
    );
    assert_eq!(signer.public_key().to_blob()?, public_blob);
    assert_eq!(signer.sign_exchange_hash(&FIXED_HASH)?, signature_blob);

    let public_key = EcdsaPublicKey::from_blob(&public_blob)?;
    verify_host_key_signature(&public_key, &signature_blob, &FIXED_HASH)?;
    assert_eq!(public_key.to_blob()?, public_blob);
    Ok(())
}

#[test]
fn p384_and_p521_fixed_vectors_are_deterministic_and_verifiable() -> Result<(), EcdsaHostKeyError> {
    let mut p384_secret = patterned_bytes::<ECDSA_P384_SECRET_SCALAR_LENGTH>(1);
    let p384 = EcdsaP384Signer::from_secret_scalar(&mut p384_secret)?;
    let p384_public_blob = p384.public_key_blob()?;
    let p384_signature_blob = p384.sign_exchange_hash(&patterned_bytes::<48>(0x10))?;

    assert_eq!(p384_secret, [0_u8; ECDSA_P384_SECRET_SCALAR_LENGTH]);
    assert_eq!(p384_public_blob, hex(EXPECTED_P384_PUBLIC_BLOB));
    assert_eq!(p384_signature_blob, hex(EXPECTED_P384_SIGNATURE_BLOB));
    assert_eq!(
        p384.sign_exchange_hash(&patterned_bytes::<48>(0x10))?,
        p384_signature_blob
    );
    assert_eq!(
        p384.public_key().as_bytes().len(),
        ECDSA_P384_PUBLIC_KEY_LENGTH
    );
    assert_eq!(EcdsaP384PublicKey::algorithm(), ECDSA_SHA2_NISTP384);
    assert_eq!(EcdsaP384PublicKey::curve_name(), CURVE_NISTP384);
    assert_eq!(NISTP384, ECDSA_CURVE_NISTP384);

    let p384_public_key = EcdsaP384PublicKey::from_blob(&p384_public_blob)?;
    verify_p384_host_key_signature(
        &p384_public_key,
        &p384_signature_blob,
        &patterned_bytes::<48>(0x10),
    )?;
    assert_eq!(p384_public_key.to_blob()?, p384_public_blob);

    let mut p521_secret = patterned_bytes::<ECDSA_P521_SECRET_SCALAR_LENGTH>(1);
    let p521 = EcdsaP521Signer::from_secret_scalar(&mut p521_secret)?;
    let p521_public_blob = p521.public_key_blob()?;
    let p521_signature_blob = p521.sign_exchange_hash(&patterned_bytes::<64>(0x20))?;

    assert_eq!(p521_secret, [0_u8; ECDSA_P521_SECRET_SCALAR_LENGTH]);
    assert_eq!(p521_public_blob, hex(EXPECTED_P521_PUBLIC_BLOB));
    assert_eq!(p521_signature_blob, hex(EXPECTED_P521_SIGNATURE_BLOB));
    assert_eq!(
        p521.sign_exchange_hash(&patterned_bytes::<64>(0x20))?,
        p521_signature_blob
    );
    assert_eq!(
        p521.public_key().as_bytes().len(),
        ECDSA_P521_PUBLIC_KEY_LENGTH
    );
    assert_eq!(EcdsaP521PublicKey::algorithm(), ECDSA_SHA2_NISTP521);
    assert_eq!(EcdsaP521PublicKey::curve_name(), CURVE_NISTP521);
    assert_eq!(NISTP521, ECDSA_CURVE_NISTP521);

    let p521_public_key = EcdsaP521PublicKey::from_blob(&p521_public_blob)?;
    verify_p521_host_key_signature(
        &p521_public_key,
        &p521_signature_blob,
        &patterned_bytes::<64>(0x20),
    )?;
    assert_eq!(p521_public_key.to_blob()?, p521_public_blob);

    let _: &P384PublicKey = p384.public_key();
    let _: &P384Signer = &p384;
    let _: &P521PublicKey = p521.public_key();
    let _: &P521Signer = &p521;
    assert_eq!(ECDSA_P384_SIGNATURE_LENGTH, 96);
    assert_eq!(ECDSA_P521_SIGNATURE_LENGTH, 132);
    Ok(())
}

#[test]
fn p384_and_p521_reject_bad_public_points_and_wire_shapes() -> Result<(), EcdsaHostKeyError> {
    let p384 = EcdsaP384Signer::from_secret_scalar_bytes(&patterned_bytes::<48>(1))?;
    let p384_blob = p384.public_key_blob()?;
    let p384_point = p384_blob
        [4 + SSH_ECDSA_SHA2_NISTP384.len() + 4 + ECDSA_CURVE_NISTP384.len() + 4..]
        .to_vec();
    for length in 0..p384_blob.len() {
        assert!(EcdsaP384PublicKey::from_blob(&p384_blob[..length]).is_err());
    }
    let mut short_point = p384_point.clone();
    short_point.pop();
    let short_blob = public_blob(SSH_ECDSA_SHA2_NISTP384, ECDSA_CURVE_NISTP384, &short_point)?;
    assert_eq!(
        EcdsaP384PublicKey::from_blob(&short_blob),
        Err(EcdsaHostKeyError::InvalidFieldLength)
    );
    let wrong_curve = public_blob(SSH_ECDSA_SHA2_NISTP384, ECDSA_CURVE_NISTP521, &p384_point)?;
    assert_eq!(
        EcdsaP384PublicKey::from_blob(&wrong_curve),
        Err(EcdsaHostKeyError::UnsupportedCurve)
    );
    let wrong_algorithm = public_blob(SSH_ECDSA_SHA2_NISTP256, ECDSA_CURVE_NISTP384, &p384_point)?;
    assert_eq!(
        EcdsaP384PublicKey::from_blob(&wrong_algorithm),
        Err(EcdsaHostKeyError::UnsupportedAlgorithm)
    );
    let mut trailing = p384_blob.clone();
    trailing.push(0);
    assert_eq!(
        EcdsaP384PublicKey::from_blob(&trailing),
        Err(EcdsaHostKeyError::TrailingData)
    );
    let mut compressed = p384_point;
    compressed[0] = 2;
    let compressed_blob = public_blob(SSH_ECDSA_SHA2_NISTP384, ECDSA_CURVE_NISTP384, &compressed)?;
    assert_eq!(
        EcdsaP384PublicKey::from_blob(&compressed_blob),
        Err(EcdsaHostKeyError::InvalidPublicKey)
    );

    let p521 = EcdsaP521Signer::from_secret_scalar_bytes(&patterned_bytes::<66>(1))?;
    let p521_blob = p521.public_key_blob()?;
    let p521_point = p521_blob
        [4 + SSH_ECDSA_SHA2_NISTP521.len() + 4 + ECDSA_CURVE_NISTP521.len() + 4..]
        .to_vec();
    for length in 0..p521_blob.len() {
        assert!(EcdsaP521PublicKey::from_blob(&p521_blob[..length]).is_err());
    }
    let mut short_point = p521_point.clone();
    short_point.pop();
    let short_blob = public_blob(SSH_ECDSA_SHA2_NISTP521, ECDSA_CURVE_NISTP521, &short_point)?;
    assert_eq!(
        EcdsaP521PublicKey::from_blob(&short_blob),
        Err(EcdsaHostKeyError::InvalidFieldLength)
    );
    let wrong_curve = public_blob(SSH_ECDSA_SHA2_NISTP521, ECDSA_CURVE_NISTP384, &p521_point)?;
    assert_eq!(
        EcdsaP521PublicKey::from_blob(&wrong_curve),
        Err(EcdsaHostKeyError::UnsupportedCurve)
    );
    let mut trailing = p521_blob;
    trailing.push(0);
    assert_eq!(
        EcdsaP521PublicKey::from_blob(&trailing),
        Err(EcdsaHostKeyError::TrailingData)
    );
    let mut compressed = p521_point;
    compressed[0] = 2;
    let compressed_blob = public_blob(SSH_ECDSA_SHA2_NISTP521, ECDSA_CURVE_NISTP521, &compressed)?;
    assert_eq!(
        EcdsaP521PublicKey::from_blob(&compressed_blob),
        Err(EcdsaHostKeyError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn public_key_decoder_rejects_wire_shape_curve_and_point_errors() -> Result<(), EcdsaHostKeyError> {
    let signer = EcdsaSigner::from_secret_scalar_bytes(&FIXED_SCALAR)?;
    let valid = signer.public_key_blob()?;
    let point =
        valid[4 + SSH_ECDSA_SHA2_NISTP256.len() + 4 + ECDSA_CURVE_NISTP256.len() + 4..].to_vec();
    let point_start = valid.len() - ECDSA_PUBLIC_KEY_LENGTH;
    assert_eq!(&valid[point_start..], point.as_slice());

    for length in 0..valid.len() {
        assert!(
            EcdsaPublicKey::from_blob(&valid[..length]).is_err(),
            "accepted public-key prefix of {length} bytes"
        );
    }

    for algorithm in ["", "ssh-ed25519", "ECDSA-SHA2-NISTP256"] {
        assert_eq!(
            check_host_key_algorithm(algorithm),
            Err(EcdsaHostKeyError::UnsupportedAlgorithm)
        );
        let wrong = public_blob(algorithm, ECDSA_CURVE_NISTP256, &point)?;
        assert_eq!(
            EcdsaPublicKey::from_blob(&wrong),
            Err(EcdsaHostKeyError::UnsupportedAlgorithm)
        );
    }
    for algorithm in [
        SSH_ECDSA_SHA2_NISTP256,
        SSH_ECDSA_SHA2_NISTP384,
        SSH_ECDSA_SHA2_NISTP521,
    ] {
        assert_eq!(check_host_key_algorithm(algorithm), Ok(()));
    }
    assert_eq!(check_curve_name(ECDSA_CURVE_NISTP256), Ok(()));

    for curve in ["", "NISTP256"] {
        assert_eq!(
            check_curve_name(curve),
            Err(EcdsaHostKeyError::UnsupportedCurve)
        );
        let wrong = public_blob(SSH_ECDSA_SHA2_NISTP256, curve, &point)?;
        assert_eq!(
            EcdsaPublicKey::from_blob(&wrong),
            Err(EcdsaHostKeyError::UnsupportedCurve)
        );
    }
    for curve in [
        ECDSA_CURVE_NISTP256,
        ECDSA_CURVE_NISTP384,
        ECDSA_CURVE_NISTP521,
    ] {
        assert_eq!(check_curve_name(curve), Ok(()));
    }

    for length in [0, 1, 33, 64, 66] {
        let mut wrong_length = point.clone();
        wrong_length.resize(length, 0);
        let blob = public_blob(SSH_ECDSA_SHA2_NISTP256, ECDSA_CURVE_NISTP256, &wrong_length)?;
        assert_eq!(
            EcdsaPublicKey::from_blob(&blob),
            Err(EcdsaHostKeyError::InvalidFieldLength)
        );
    }

    let mut compressed_tag = point.clone();
    compressed_tag[0] = 2;
    let compressed = public_blob(
        SSH_ECDSA_SHA2_NISTP256,
        ECDSA_CURVE_NISTP256,
        &compressed_tag,
    )?;
    assert_eq!(
        EcdsaPublicKey::from_blob(&compressed),
        Err(EcdsaHostKeyError::InvalidPublicKey)
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        EcdsaPublicKey::from_blob(&trailing),
        Err(EcdsaHostKeyError::TrailingData)
    );

    let mut malformed = [0_u8; ECDSA_PUBLIC_KEY_LENGTH];
    malformed[0] = 4;
    let malformed_blob = public_blob(SSH_ECDSA_SHA2_NISTP256, ECDSA_CURVE_NISTP256, &malformed)?;
    assert_eq!(
        EcdsaPublicKey::from_blob(&malformed_blob),
        Err(EcdsaHostKeyError::InvalidPublicKey)
    );
    assert_eq!(
        EcdsaPublicKey::from_point(&malformed),
        Err(EcdsaHostKeyError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn signature_decoder_requires_nested_mpints_and_rejects_der_and_trailing_data()
-> Result<(), EcdsaHostKeyError> {
    let signer = EcdsaSigner::from_secret_scalar_bytes(&FIXED_SCALAR)?;
    let public_blob = signer.public_key_blob()?;
    let public_key = EcdsaPublicKey::from_blob(&public_blob)?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;
    let body = signature_body(&signature_blob)?;

    let bare = body[4..4 + ECDSA_SIGNATURE_LENGTH].to_vec();
    assert_eq!(
        verify_host_key_signature(&public_key, &bare, &FIXED_HASH),
        Err(EcdsaHostKeyError::InvalidFieldLength)
    );

    let der =
        der_signature_from_body(&body).map_err(|_error| EcdsaHostKeyError::InvalidSignature)?;
    let der_blob = signature_blob_with_body(&der)?;
    assert!(verify_host_key_signature(&public_key, &der_blob, &FIXED_HASH).is_err());

    let wrong_algorithm = signature_blob_with_prefix("rsa-sha2-256", &body)?;
    assert_eq!(
        verify_host_key_signature(&public_key, &wrong_algorithm, &FIXED_HASH),
        Err(EcdsaHostKeyError::UnsupportedAlgorithm)
    );

    let mut body_trailing = body.clone();
    body_trailing.push(0);
    let body_trailing_blob = signature_blob_with_body(&body_trailing)?;
    assert_eq!(
        verify_host_key_signature(&public_key, &body_trailing_blob, &FIXED_HASH),
        Err(EcdsaHostKeyError::TrailingData)
    );

    let mut outer_trailing = signature_blob.clone();
    outer_trailing.push(0);
    assert_eq!(
        verify_host_key_signature(&public_key, &outer_trailing, &FIXED_HASH),
        Err(EcdsaHostKeyError::TrailingData)
    );

    for malformed in [
        wire_mpint(&[0]),
        wire_mpint(&[0x80]),
        wire_mpint(&[0x00, 0x00, 0x01]),
        wire_mpint(&[0xff, 0x01]),
    ] {
        let malformed_blob = signature_blob_with_body(&malformed)?;
        assert!(verify_host_key_signature(&public_key, &malformed_blob, &FIXED_HASH).is_err());
    }

    for length in 0..signature_blob.len() {
        assert!(
            verify_host_key_signature(&public_key, &signature_blob[..length], &FIXED_HASH).is_err(),
            "accepted signature prefix of {length} bytes"
        );
    }
    Ok(())
}

#[test]
fn p384_and_p521_reject_raw_der_wrong_algorithm_and_trailing_signatures()
-> Result<(), EcdsaHostKeyError> {
    let p384 = EcdsaP384Signer::from_secret_scalar_bytes(&patterned_bytes::<48>(1))?;
    let p384_key = p384.public_key();
    let p384_signature = p384.sign_exchange_hash(&patterned_bytes::<48>(0x10))?;
    let p384_body = signature_body(&p384_signature)?;
    let p384_raw = p384_body[4..4 + ECDSA_P384_SIGNATURE_LENGTH].to_vec();
    assert_eq!(
        verify_p384_host_key_signature(p384_key, &p384_raw, &patterned_bytes::<48>(0x10)),
        Err(EcdsaHostKeyError::InvalidFieldLength)
    );
    let p384_der = [0x30_u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let p384_der_blob = signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP384, &p384_der)?;
    assert!(
        verify_p384_host_key_signature(p384_key, &p384_der_blob, &patterned_bytes::<48>(0x10))
            .is_err()
    );
    let p384_wrong_algorithm = signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP256, &p384_body)?;
    assert_eq!(
        verify_p384_host_key_signature(
            p384_key,
            &p384_wrong_algorithm,
            &patterned_bytes::<48>(0x10)
        ),
        Err(EcdsaHostKeyError::UnsupportedAlgorithm)
    );
    let mut p384_body_trailing = p384_body;
    p384_body_trailing.push(0);
    let p384_body_trailing_blob =
        signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP384, &p384_body_trailing)?;
    assert_eq!(
        verify_p384_host_key_signature(
            p384_key,
            &p384_body_trailing_blob,
            &patterned_bytes::<48>(0x10)
        ),
        Err(EcdsaHostKeyError::TrailingData)
    );
    let mut p384_outer_trailing = p384_signature;
    p384_outer_trailing.push(0);
    assert_eq!(
        verify_p384_host_key_signature(
            p384_key,
            &p384_outer_trailing,
            &patterned_bytes::<48>(0x10)
        ),
        Err(EcdsaHostKeyError::TrailingData)
    );

    let p521 = EcdsaP521Signer::from_secret_scalar_bytes(&patterned_bytes::<66>(1))?;
    let p521_key = p521.public_key();
    let p521_signature = p521.sign_exchange_hash(&patterned_bytes::<64>(0x20))?;
    let p521_body = signature_body(&p521_signature)?;
    let p521_raw = p521_body[4..4 + ECDSA_P521_SIGNATURE_LENGTH].to_vec();
    assert_eq!(
        verify_p521_host_key_signature(p521_key, &p521_raw, &patterned_bytes::<64>(0x20)),
        Err(EcdsaHostKeyError::InvalidFieldLength)
    );
    let p521_der = [0x30_u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let p521_der_blob = signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP521, &p521_der)?;
    assert!(
        verify_p521_host_key_signature(p521_key, &p521_der_blob, &patterned_bytes::<64>(0x20))
            .is_err()
    );
    let p521_wrong_algorithm = signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP384, &p521_body)?;
    assert_eq!(
        verify_p521_host_key_signature(
            p521_key,
            &p521_wrong_algorithm,
            &patterned_bytes::<64>(0x20)
        ),
        Err(EcdsaHostKeyError::UnsupportedAlgorithm)
    );
    let mut p521_body_trailing = p521_body;
    p521_body_trailing.push(0);
    let p521_body_trailing_blob =
        signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP521, &p521_body_trailing)?;
    assert_eq!(
        verify_p521_host_key_signature(
            p521_key,
            &p521_body_trailing_blob,
            &patterned_bytes::<64>(0x20)
        ),
        Err(EcdsaHostKeyError::TrailingData)
    );
    let mut p521_outer_trailing = p521_signature;
    p521_outer_trailing.push(0);
    assert_eq!(
        verify_p521_host_key_signature(
            p521_key,
            &p521_outer_trailing,
            &patterned_bytes::<64>(0x20)
        ),
        Err(EcdsaHostKeyError::TrailingData)
    );
    Ok(())
}

#[test]
fn p384_and_p521_use_raw_exchange_hashes_and_matching_digests() -> Result<(), EcdsaHostKeyError> {
    let p384 = EcdsaP384Signer::from_secret_scalar_bytes(&patterned_bytes::<48>(1))?;
    let p384_hash = patterned_bytes::<48>(0x10);
    let p384_signature = p384.sign_exchange_hash(&p384_hash)?;
    verify_p384_host_key_signature(p384.public_key(), &p384_signature, &p384_hash)?;
    let mut wrapped = Writer::new();
    wrapped.write_string(&p384_hash)?;
    assert!(
        verify_p384_host_key_signature(p384.public_key(), &p384_signature, wrapped.as_bytes())
            .is_err()
    );
    let mut changed = p384_hash;
    changed[0] ^= 1;
    assert_eq!(
        verify_p384_host_key_signature(p384.public_key(), &p384_signature, &changed),
        Err(EcdsaHostKeyError::InvalidSignature)
    );

    let p521 = EcdsaP521Signer::from_secret_scalar_bytes(&patterned_bytes::<66>(1))?;
    let p521_hash = patterned_bytes::<64>(0x20);
    let p521_signature = p521.sign_exchange_hash(&p521_hash)?;
    verify_p521_host_key_signature(p521.public_key(), &p521_signature, &p521_hash)?;
    let mut wrapped = Writer::new();
    wrapped.write_string(&p521_hash)?;
    assert!(
        verify_p521_host_key_signature(p521.public_key(), &p521_signature, wrapped.as_bytes())
            .is_err()
    );
    let mut changed = p521_hash;
    changed[0] ^= 1;
    assert_eq!(
        verify_p521_host_key_signature(p521.public_key(), &p521_signature, &changed),
        Err(EcdsaHostKeyError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn verification_uses_raw_exchange_hash_bytes() -> Result<(), EcdsaHostKeyError> {
    let signer = EcdsaSigner::from_secret_scalar_bytes(&FIXED_SCALAR)?;
    let public_key = signer.public_key();
    let signature = signer.sign_exchange_hash(&FIXED_HASH)?;

    assert!(verify_host_key_signature(public_key, &signature, &FIXED_HASH).is_ok());
    let mut wrapped = Writer::new();
    wrapped.write_string(&FIXED_HASH)?;
    assert!(verify_host_key_signature(public_key, &signature, wrapped.as_bytes()).is_err());

    let mut changed = FIXED_HASH;
    changed[0] ^= 1;
    assert_eq!(
        verify_host_key_signature(public_key, &signature, &changed),
        Err(EcdsaHostKeyError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn trust_callback_is_mandatory_and_runs_after_cryptographic_verification()
-> Result<(), EcdsaHostKeyError> {
    let signer = EcdsaSigner::from_secret_scalar_bytes(&FIXED_SCALAR)?;
    let public_blob = signer.public_key_blob()?;
    let signature_blob = signer.sign_exchange_hash(&FIXED_HASH)?;
    let public_key = EcdsaPublicKey::from_blob(&public_blob)?;
    let mut observed = None;

    let verified: VerifiedEcdsaHostKey =
        verify_and_trust_host_key(&public_blob, &signature_blob, &FIXED_HASH, |candidate| {
            observed = Some(*candidate);
            Ok::<(), Infallible>(())
        })?;
    assert_eq!(observed.as_ref(), Some(&public_key));
    let _: &VerifiedHostKey = &verified;
    let _: &VerifiedP256HostKey = &verified;
    assert_eq!(verified.public_key(), &public_key);
    assert_eq!(verified.to_blob()?, public_blob);

    assert_eq!(
        verify_and_trust_host_key(
            &public_blob,
            &signature_blob,
            &FIXED_HASH,
            |_candidate| Err::<(), _>(PolicyRejected),
        ),
        Err(EcdsaHostKeyError::TrustRejected)
    );

    let calls = Cell::new(0_u8);
    let mut changed = FIXED_HASH;
    changed[31] ^= 0x80;
    let result = verify_and_trust_host_key(&public_blob, &signature_blob, &changed, |_candidate| {
        calls.set(calls.get() + 1);
        Ok::<(), Infallible>(())
    });
    assert_eq!(result, Err(EcdsaHostKeyError::InvalidSignature));
    assert_eq!(calls.get(), 0);

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
    assert!(matches!(
        outcome,
        Ok(Err(EcdsaHostKeyError::VerifierPanicked))
    ));
    Ok(())
}

#[test]
fn p384_and_p521_trust_callbacks_are_mandatory() -> Result<(), EcdsaHostKeyError> {
    let p384 = EcdsaP384Signer::from_secret_scalar_bytes(&patterned_bytes::<48>(1))?;
    let p384_blob = p384.public_key_blob()?;
    let p384_signature = p384.sign_exchange_hash(&patterned_bytes::<48>(0x10))?;
    let p384_hash = patterned_bytes::<48>(0x10);
    let mut observed = None;
    let verified: VerifiedEcdsaP384HostKey =
        verify_and_trust_p384_host_key(&p384_blob, &p384_signature, &p384_hash, |candidate| {
            observed = Some(*candidate);
            Ok::<(), Infallible>(())
        })?;
    assert_eq!(observed, Some(*p384.public_key()));
    let _: &VerifiedP384HostKey = &verified;
    assert_eq!(verified.public_key(), p384.public_key());
    assert_eq!(verified.to_blob()?, p384_blob);
    assert_eq!(
        verify_and_trust_p384_host_key(
            &p384_blob,
            &p384_signature,
            &p384_hash,
            |_candidate| Err::<(), _>(PolicyRejected),
        ),
        Err(EcdsaHostKeyError::TrustRejected)
    );
    let p384_calls = Cell::new(0_u8);
    let mut changed = p384_hash;
    changed[0] ^= 1;
    let p384_bad =
        verify_and_trust_p384_host_key(&p384_blob, &p384_signature, &changed, |_candidate| {
            p384_calls.set(p384_calls.get() + 1);
            Ok::<(), Infallible>(())
        });
    assert_eq!(p384_bad, Err(EcdsaHostKeyError::InvalidSignature));
    assert_eq!(p384_calls.get(), 0);
    let p384_panic = catch_unwind(|| {
        verify_and_trust_p384_host_key(
            &p384_blob,
            &p384_signature,
            &p384_hash,
            |_candidate| -> Result<(), Infallible> {
                panic!("P-384 trust callback panic");
            },
        )
    });
    assert!(matches!(
        p384_panic,
        Ok(Err(EcdsaHostKeyError::VerifierPanicked))
    ));

    let p521 = EcdsaP521Signer::from_secret_scalar_bytes(&patterned_bytes::<66>(1))?;
    let p521_blob = p521.public_key_blob()?;
    let p521_signature = p521.sign_exchange_hash(&patterned_bytes::<64>(0x20))?;
    let p521_hash = patterned_bytes::<64>(0x20);
    let verified: VerifiedEcdsaP521HostKey =
        verify_and_trust_p521_host_key(&p521_blob, &p521_signature, &p521_hash, |_candidate| {
            Ok::<(), Infallible>(())
        })?;
    let _: &VerifiedP521HostKey = &verified;
    assert_eq!(verified.public_key(), p521.public_key());
    assert_eq!(verified.to_blob()?, p521_blob);
    assert_eq!(
        verify_and_trust_p521_host_key(
            &p521_blob,
            &p521_signature,
            &p521_hash,
            |_candidate| Err::<(), _>(PolicyRejected),
        ),
        Err(EcdsaHostKeyError::TrustRejected)
    );
    let p521_calls = Cell::new(0_u8);
    let mut changed = p521_hash;
    changed[0] ^= 1;
    let p521_bad =
        verify_and_trust_p521_host_key(&p521_blob, &p521_signature, &changed, |_candidate| {
            p521_calls.set(p521_calls.get() + 1);
            Ok::<(), Infallible>(())
        });
    assert_eq!(p521_bad, Err(EcdsaHostKeyError::InvalidSignature));
    assert_eq!(p521_calls.get(), 0);
    let p521_panic = catch_unwind(|| {
        verify_and_trust_p521_host_key(
            &p521_blob,
            &p521_signature,
            &p521_hash,
            |_candidate| -> Result<(), Infallible> {
                panic!("P-521 trust callback panic");
            },
        )
    });
    assert!(matches!(
        p521_panic,
        Ok(Err(EcdsaHostKeyError::VerifierPanicked))
    ));
    Ok(())
}

#[test]
fn p384_and_p521_secret_material_is_wiped_and_redacted() -> Result<(), HostKeyError> {
    let mut p384_secret = patterned_bytes::<48>(1);
    let p384 = EcdsaP384Signer::from_secret_scalar(&mut p384_secret)?;
    assert_eq!(p384_secret, [0_u8; ECDSA_P384_SECRET_SCALAR_LENGTH]);
    let p384_debug = format!("{p384:?}");
    let p384_display = p384.to_string();
    assert!(p384_debug.contains("EcdsaP384Signer"));
    assert!(!p384_debug.contains("0102030405060708"));
    assert!(!p384_display.contains("0102030405060708"));
    assert!(EcdsaP384Signer::from_slice(&[1_u8; 47]).is_err());
    assert!(EcdsaP384Signer::from_secret_scalar_bytes(&[0_u8; 48]).is_err());
    assert!(EcdsaP384Signer::generate()?.public_key_blob()?.len() > ECDSA_P384_PUBLIC_KEY_LENGTH);

    let mut p521_secret = patterned_bytes::<66>(1);
    let p521 = EcdsaP521Signer::from_secret_scalar(&mut p521_secret)?;
    assert_eq!(p521_secret, [0_u8; ECDSA_P521_SECRET_SCALAR_LENGTH]);
    let p521_debug = format!("{p521:?}");
    let p521_display = p521.to_string();
    assert!(p521_debug.contains("EcdsaP521Signer"));
    assert!(!p521_debug.contains("0102030405060708"));
    assert!(!p521_display.contains("0102030405060708"));
    assert!(EcdsaP521Signer::from_slice(&[1_u8; 65]).is_err());
    assert!(EcdsaP521Signer::from_secret_scalar_bytes(&[0_u8; 66]).is_err());
    assert!(EcdsaP521Signer::generate()?.public_key_blob()?.len() > ECDSA_P521_PUBLIC_KEY_LENGTH);

    let _: Result<P384Signer, P384HostKeyError> =
        P384Signer::from_private_bytes(patterned_bytes::<48>(1));
    let _: Result<P521Signer, P521HostKeyError> =
        P521Signer::from_private_bytes(patterned_bytes::<66>(1));
    let _: Result<VerifiedP384HostKey, _> = Err(EcdsaHostKeyError::TrustRejected);
    let _: Result<VerifiedP521HostKey, _> = Err(EcdsaHostKeyError::TrustRejected);
    Ok(())
}

#[test]
fn secret_material_is_wiped_and_debug_is_redacted() -> Result<(), HostKeyError> {
    let mut scalar = FIXED_SCALAR;
    let signer = EcdsaSigner::from_secret_scalar(&mut scalar)?;
    assert_eq!(scalar, [0_u8; ECDSA_SECRET_SCALAR_LENGTH]);

    let debug = format!("{signer:?}");
    assert!(debug.contains("EcdsaSigner"));
    assert!(!debug.contains("signing_key"));
    assert!(!debug.contains("secret_scalar"));
    assert!(!debug.contains("0102030405060708"));
    let display = signer.to_string();
    assert!(display.contains("EcdsaSigner"));
    assert!(!display.contains("0102030405060708"));

    assert!(EcdsaSigner::from_secret_scalar_bytes(&[0_u8; 32]).is_err());
    assert!(EcdsaSigner::from_secret_scalar_bytes(&[0xff_u8; 32]).is_err());
    assert!(EcdsaSigner::from_slice(&[1_u8; 31]).is_err());

    let _: &P256PublicKey = signer.public_key();
    let _: Result<P256Signer, P256HostKeyError> = P256Signer::from_private_bytes(FIXED_SCALAR);
    let _: P256HostKeyError = EcdsaHostKeyError::EntropyFailure;
    let generated = EcdsaSigner::generate()?;
    assert!(generated.public_key_blob()?.len() > ECDSA_PUBLIC_KEY_LENGTH);
    Ok(())
}

#[test]
fn independent_p256_api_reproduces_the_fixed_signature() -> Result<(), Box<dyn std::error::Error>> {
    let signer = EcdsaSigner::from_secret_scalar_bytes(&FIXED_SCALAR)?;
    let actual = signer.sign_exchange_hash(&FIXED_HASH)?;

    let signing_key = SigningKey::from_slice(&FIXED_SCALAR)?;
    let digest = sha2::Sha256::digest(FIXED_HASH);
    let signature: Signature = PrehashSigner::sign_prehash(&signing_key, &digest)?;
    let direct_signature: Signature = signing_key.try_sign(&FIXED_HASH)?;
    assert_eq!(direct_signature, signature);
    let (r, s) = signature.split_bytes();
    let mut body = Writer::new();
    write_positive_mpint(&mut body, r.as_slice())?;
    write_positive_mpint(&mut body, s.as_slice())?;
    let mut expected = Writer::new();
    expected.write_string(SSH_ECDSA_SHA2_NISTP256)?;
    expected.write_string(body.as_slice())?;
    assert_eq!(actual, expected.into_bytes());
    Ok(())
}

struct PolicyRejected;

fn public_blob(algorithm: &str, curve: &str, point: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_string(curve)?;
    writer.write_string(point)?;
    Ok(writer.into_bytes())
}

fn signature_body(signature_blob: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
    let mut reader = Reader::new(signature_blob);
    let _algorithm = reader.read_string()?;
    let body = reader.read_string_bytes()?;
    Ok(body)
}

fn signature_blob_with_body(body: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
    signature_blob_with_prefix(SSH_ECDSA_SHA2_NISTP256, body)
}

fn signature_blob_with_prefix(algorithm: &str, body: &[u8]) -> Result<Vec<u8>, EcdsaHostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(algorithm)?;
    writer.write_string(body)?;
    Ok(writer.into_bytes())
}

fn write_positive_mpint(writer: &mut Writer, scalar: &[u8]) -> Result<(), neotales_ssh::Error> {
    let mut value = Vec::with_capacity(33);
    if scalar.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(scalar);
    writer.write_mpint(value.as_slice())?;
    Ok(())
}

fn wire_mpint(value: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_mpint(value).expect("test mpint should encode");
    writer.into_bytes()[4..].to_vec()
}

fn der_signature_from_body(body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut reader = Reader::new(body);
    let r = reader.read_mpint_magnitude()?;
    let s = reader.read_mpint_magnitude()?;
    let r: [u8; 32] = r.try_into()?;
    let s: [u8; 32] = s.try_into()?;
    let signature = Signature::from_scalars(r, s)?;
    Ok(signature.to_der().as_bytes().to_vec())
}

fn patterned_bytes<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap_or(0)))
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
