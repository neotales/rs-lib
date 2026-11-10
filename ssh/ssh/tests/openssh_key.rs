// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

// `OpenSshPrivateKey`'s accessors are public and reachable from the crate root;
// this harness compiles `openssh_key.rs` as a private module copy, so
// `unreachable_pub` on an accessor it happens not to call says nothing about
// the API.
#[allow(dead_code, unreachable_pub)]
#[path = "../src/openssh_key.rs"]
mod openssh_key;

use std::error::Error;

use ed25519_dalek::SigningKey;
use neotales_ssh::ecdsa_hostkey::EcdsaSigner;
use neotales_ssh::hostkey::Ed25519Signer;
use neotales_ssh::{Reader, Writer};
use neotales_x509::openssh_bcrypt::derive_key;
use openssh_key::{OpenSshKeyError, parse_openssh_private_key};

use aes::cipher::{KeyIvInit, StreamCipher};

const MAGIC: &[u8] = b"openssh-key-v1\0";
const NONE_BLOCK_SIZE: usize = 8;
const AES_BLOCK_SIZE: usize = 16;
const ROUNDS: u32 = 4;
const SALT: &[u8] = b"openssh-key-v1-test-salt";
const PASSPHRASE: &[u8] = b"correct-passphrase";
const COMMENT: &[u8] = b"fixture-comment";
const SEED: [u8; 32] = [0x42; 32];

#[test]
fn unencrypted_ed25519_round_trips_public_blob_and_signer() -> Result<(), Box<dyn Error>> {
    let (fixture, expected_public_blob) = plaintext_fixture(&SEED)?;
    let mut passphrase = b"unused".to_vec();
    let parsed = parse_openssh_private_key(&fixture, &mut passphrase)?;

    assert_eq!(parsed.public_blob(), expected_public_blob);
    assert_eq!(
        parsed.seed().ok_or(OpenSshKeyError::InvalidPrivateKey)?,
        SEED
    );
    assert!(passphrase.iter().all(|byte| *byte == 0));

    let parsed_seed = parsed.seed().ok_or(OpenSshKeyError::InvalidPrivateKey)?;
    let mut signer_seed = [0_u8; 32];
    signer_seed.copy_from_slice(parsed_seed);
    let signer = Ed25519Signer::from_seed(&mut signer_seed);
    assert_eq!(signer.public_key_blob()?, parsed.public_blob());
    Ok(())
}

#[test]
fn aes256_ctr_bcrypt_fixture_parses_with_the_correct_passphrase() -> Result<(), Box<dyn Error>> {
    let (fixture, expected_public_blob) = encrypted_fixture(&SEED)?;
    let mut passphrase = PASSPHRASE.to_vec();
    let parsed = parse_openssh_private_key(&fixture, &mut passphrase)?;

    assert_eq!(parsed.public_blob(), expected_public_blob);
    assert_eq!(
        parsed.seed().ok_or(OpenSshKeyError::InvalidPrivateKey)?,
        SEED
    );
    assert!(passphrase.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn wrong_passphrase_fails_without_echoing_the_passphrase() -> Result<(), Box<dyn Error>> {
    let (fixture, _) = encrypted_fixture(&SEED)?;
    let wrong_passphrase = "wrong-passphrase";
    let mut passphrase = wrong_passphrase.as_bytes().to_vec();
    let error = parse_openssh_private_key(&fixture, &mut passphrase)
        .expect_err("the encrypted fixture must reject a wrong passphrase");

    assert!(!error.to_string().contains(wrong_passphrase));
    assert!(!format!("{error:?}").contains(wrong_passphrase));
    Ok(())
}

#[test]
fn rejects_a_second_key() -> Result<(), Box<dyn Error>> {
    let public = public_point(&SEED);
    let private = pad_private_section(ed25519_private_section(&SEED, &public)?, NONE_BLOCK_SIZE);
    let public_blob = public_blob(&public)?;
    let fixture = container(b"none", b"none", &[], 2, &public_blob, &private)?;
    let mut passphrase = b"unused".to_vec();

    assert_eq!(
        parse_openssh_private_key(&fixture, &mut passphrase).err(),
        Some(OpenSshKeyError::InvalidKeyCount)
    );
    Ok(())
}

#[test]
fn rejects_an_unknown_cipher_and_an_outer_point_mismatch() -> Result<(), Box<dyn Error>> {
    let public = public_point(&SEED);
    let private = pad_private_section(ed25519_private_section(&SEED, &public)?, NONE_BLOCK_SIZE);
    let encoded_public_blob = public_blob(&public)?;
    let unknown_cipher_fixture = container(
        b"chacha20-poly1305@openssh.com",
        b"none",
        &[],
        1,
        &encoded_public_blob,
        &private,
    )?;
    let mut passphrase = b"unused".to_vec();
    assert_eq!(
        parse_openssh_private_key(&unknown_cipher_fixture, &mut passphrase).err(),
        Some(OpenSshKeyError::UnsupportedCipher)
    );

    let other_public = public_point(&[0x24; 32]);
    let mismatched_fixture = container(
        b"none",
        b"none",
        &[],
        1,
        &public_blob(&other_public)?,
        &private,
    )?;
    let mut passphrase = b"unused".to_vec();
    assert_eq!(
        parse_openssh_private_key(&mismatched_fixture, &mut passphrase).err(),
        Some(OpenSshKeyError::PublicKeyMismatch)
    );
    Ok(())
}

#[test]
fn accepts_a_valid_ecdsa_scalar_with_its_canonical_short_mpint_encoding()
-> Result<(), Box<dyn Error>> {
    let mut scalar = [0_u8; 32];
    scalar[31] = 1;
    let signer = EcdsaSigner::from_secret_scalar_bytes(&scalar)?;
    let public_blob = signer.public_key_blob()?;
    let mut public_reader = Reader::new(&public_blob);
    assert_eq!(public_reader.read_string()?, b"ecdsa-sha2-nistp256");
    assert_eq!(public_reader.read_string()?, b"nistp256");
    let point = public_reader.read_string()?.to_vec();
    assert!(public_reader.is_empty());

    let mut private = Writer::new();
    private.write_uint32(0x1357_9bdf);
    private.write_uint32(0x1357_9bdf);
    private.write_string("ecdsa-sha2-nistp256")?;
    private.write_string("nistp256")?;
    private.write_string(&point)?;
    private.write_mpint(&scalar[..])?;
    private.write_string(COMMENT)?;
    let private = private.into_bytes();
    let private_section = pad_private_section(private, NONE_BLOCK_SIZE);
    let fixture = container(b"none", b"none", &[], 1, &public_blob, &private_section)?;
    let mut passphrase = Vec::new();
    let parsed = parse_openssh_private_key(&fixture, &mut passphrase)?;

    assert_eq!(parsed.ecdsa_secret(), Some(&scalar));
    assert_eq!(parsed.public_blob(), public_blob);
    Ok(())
}

fn plaintext_fixture(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let public = public_point(seed);
    let private = pad_private_section(ed25519_private_section(seed, &public)?, NONE_BLOCK_SIZE);
    let public_blob = public_blob(&public)?;
    let fixture = container(b"none", b"none", &[], 1, &public_blob, &private)?;
    Ok((fixture, public_blob))
}

fn encrypted_fixture(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let public = public_point(seed);
    let mut private = pad_private_section(ed25519_private_section(seed, &public)?, AES_BLOCK_SIZE);
    let derived = derive_key(PASSPHRASE, SALT, ROUNDS, 48)?;
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&derived[..32], &derived[32..])?;
    cipher.apply_keystream(&mut private);

    let mut kdf_options = Vec::new();
    kdf_options.extend_from_slice(&ssh_string(SALT)?);
    kdf_options.extend_from_slice(&ROUNDS.to_be_bytes());
    let public_blob = public_blob(&public)?;
    let fixture = container(
        b"aes256-ctr",
        b"bcrypt",
        &kdf_options,
        1,
        &public_blob,
        &private,
    )?;
    Ok((fixture, public_blob))
}

fn public_point(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn public_blob(point: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_string("ssh-ed25519")?;
    writer.write_string(point)?;
    Ok(writer.into_bytes())
}

fn ed25519_private_section(seed: &[u8; 32], public: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_uint32(0x1357_9bdf);
    writer.write_uint32(0x1357_9bdf);
    writer.write_string("ssh-ed25519")?;
    writer.write_string(public)?;
    let mut private = Vec::with_capacity(64);
    private.extend_from_slice(seed);
    private.extend_from_slice(public);
    writer.write_string(&private)?;
    writer.write_string(COMMENT)?;
    Ok(writer.into_bytes())
}

fn pad_private_section(mut section: Vec<u8>, block_size: usize) -> Vec<u8> {
    let remainder = section.len() % block_size;
    let padding_length = (block_size - remainder) % block_size;
    for value in 1..=padding_length {
        section.push(u8::try_from(value).expect("fixture padding length should fit in one byte"));
    }
    section
}

fn container(
    cipher_name: &[u8],
    kdf_name: &[u8],
    kdf_options: &[u8],
    key_count: u32,
    public_blob: &[u8],
    private_section: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut fixture = Vec::new();
    fixture.extend_from_slice(MAGIC);
    fixture.extend_from_slice(&ssh_string(cipher_name)?);
    fixture.extend_from_slice(&ssh_string(kdf_name)?);
    fixture.extend_from_slice(&ssh_string(kdf_options)?);
    fixture.extend_from_slice(&key_count.to_be_bytes());
    fixture.extend_from_slice(&ssh_string(public_blob)?);
    fixture.extend_from_slice(&ssh_string(private_section)?);
    Ok(fixture)
}

fn ssh_string(value: &[u8]) -> Result<Vec<u8>, neotales_ssh::Error> {
    let mut writer = Writer::new();
    writer.write_string(value)?;
    Ok(writer.into_bytes())
}
