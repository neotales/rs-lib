//! SSH public/private key wire parsing used by age SSH recipients.

use crate::openssh_bcrypt;
use base64::{self, Engine as _};
use des::cipher::InnerIvInit as DesInnerIvInit;
use {
    aes::cipher::{BlockModeDecrypt, KeyInit, KeyIvInit, StreamCipher},
    ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey as EdDecodePrivateKey},
    md5::Md5,
    rsa::{
        self, RsaPrivateKey, RsaPublicKey,
        pkcs1::DecodeRsaPrivateKey,
        pkcs8::DecodePrivateKey,
        traits::{PrivateKeyParts, PublicKeyParts},
    },
    sha2::Digest,
    subtle::ConstantTimeEq,
    zeroize::{Zeroize, Zeroizing},
};

use crate::{
    codec::decode_standard_or_raw,
    error::{AgeError, Result},
};

const ED25519_KIND: &[u8] = b"ssh-ed25519";
const RSA_KIND: &[u8] = b"ssh-rsa";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1";
const OPENSSH_CIPHER_NONE: &[u8] = b"none";
const OPENSSH_CIPHER_AES256_CTR: &[u8] = b"aes256-ctr";
const OPENSSH_CIPHER_AES256_CBC: &[u8] = b"aes256-cbc";
const OPENSSH_KDF_NONE: &[u8] = b"none";
const OPENSSH_KDF_BCRYPT: &[u8] = b"bcrypt";
const OPENSSH_DERIVED_KEY_LENGTH: usize = 48;
const OPENSSH_AES_BLOCK_SIZE: usize = 16;
const SSH_RSA_MIN_MODULUS_BITS: usize = 2048;
const SSH_RSA_MAX_MODULUS_BITS: usize = 16_384;
const SSH_RSA_MAX_EXPONENT_BITS: usize = 24;
// OpenSSH bounds each CRT factor to 8192 bits before precomputation.
const SSH_RSA_MAX_PRIME_BITS: usize = 8192;

/// An Ed25519 SSH public key and its X25519 conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshEd25519PublicKey {
    /// The original Ed25519 public key bytes.
    pub ed25519_public_key: [u8; 32],
    /// The Montgomery X25519 public key bytes.
    pub curve25519_public_key: [u8; 32],
    /// The complete SSH wire public-key blob.
    pub wire_key: Vec<u8>,
}

/// An RSA SSH public key and its wire encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshRsaPublicKey {
    /// The parsed RSA public key.
    public_key: RsaPublicKey,
    /// The complete SSH wire public-key blob.
    pub wire_key: Vec<u8>,
}

impl SshRsaPublicKey {
    /// Returns the parsed RSA public key.
    #[must_use]
    pub fn key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

/// Helpers for Ed25519 SSH key conversions.
///
/// A unit struct: it holds no key material, and every method on it takes the
/// seed or the key it operates on as an argument. The derived
/// [`Debug`](std::fmt::Debug) therefore prints the type name and cannot leak
/// anything, and there is no per-instance key for a fingerprint to identify.
/// The parsed public key, which does hold key material, is
/// [`SshEd25519PublicKey`], and it is the public half that gets printed.
#[derive(Debug)]
pub struct SshEd25519Key;

impl SshEd25519Key {
    /// Exports an Ed25519 seed as an OpenSSH `authorized_keys` line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] when the seed cannot produce a valid
    /// Ed25519 public key.
    pub fn export_public_key(seed: &[u8; 32]) -> Result<String> {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = signing.verifying_key().to_bytes();
        let wire = build_ed25519_wire(&public);
        let encoded = base64::engine::general_purpose::STANDARD.encode(wire);
        Ok(format!("ssh-ed25519 {encoded}"))
    }

    /// Parses an Ed25519 SSH authorized-key line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for an unsupported, malformed, or non-canonical
    /// SSH public key.
    pub fn parse_public_key(line: impl AsRef<str>) -> Result<SshEd25519PublicKey> {
        let wire = parse_authorized_key(line.as_ref(), ED25519_KIND)?;
        let mut reader = SshReader::new(&wire);
        let kind = reader.read_string()?;
        if kind.as_slice() != ED25519_KIND {
            return Err(AgeError::InvalidKey("SSH key is not ssh-ed25519"));
        }
        let public = reader.read_string()?;
        if public.len() != 32 || !reader.is_complete() {
            return Err(AgeError::InvalidKey("invalid SSH Ed25519 public key"));
        }
        let ed25519_public_key: [u8; 32] = public
            .try_into()
            .map_err(|_| AgeError::InvalidKey("invalid SSH Ed25519 public key"))?;
        let curve25519_public_key =
            crate::curve25519::ed25519_public_to_x25519(&ed25519_public_key)
                .map_err(|_| AgeError::InvalidKey("invalid SSH Ed25519 public key"))?;
        Ok(SshEd25519PublicKey {
            ed25519_public_key,
            curve25519_public_key,
            wire_key: wire,
        })
    }
}

/// Helpers for RSA SSH key conversions.
///
/// A unit struct: it holds no key material, and every method on it takes the key
/// it operates on as an argument. The derived [`Debug`](std::fmt::Debug)
/// therefore prints the type name and cannot leak anything, and there is no
/// per-instance key for a fingerprint to identify. The parsed public key, which
/// does hold key material, is [`SshRsaPublicKey`], and it is the public half
/// that gets printed.
#[derive(Debug)]
pub struct SshRsaKey;

impl SshRsaKey {
    /// Exports an RSA public key as an OpenSSH `authorized_keys` line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the key cannot be encoded in SSH wire form.
    pub fn export_public_key(key: &RsaPublicKey) -> Result<String> {
        validate_ssh_rsa_key(key)?;
        let wire = build_rsa_wire(
            key.n().to_bytes_be().as_slice(),
            key.e().to_bytes_be().as_slice(),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(wire);
        Ok(format!("ssh-rsa {encoded}"))
    }

    /// Parses an RSA SSH authorized-key line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for an unsupported, malformed, undersized, or
    /// non-canonical RSA SSH public key.
    pub fn parse_public_key(line: impl AsRef<str>) -> Result<SshRsaPublicKey> {
        let wire = parse_authorized_key(line.as_ref(), RSA_KIND)?;
        let mut reader = SshReader::new(&wire);
        let kind = reader.read_string()?;
        if kind.as_slice() != RSA_KIND {
            return Err(AgeError::InvalidKey("SSH key is not ssh-rsa"));
        }
        let exponent = reader.read_mpint()?;
        let modulus = reader.read_mpint()?;
        if !reader.is_complete() {
            return Err(AgeError::InvalidKey("trailing data in SSH RSA key"));
        }
        let key = rsa_public_from_components(&modulus, &exponent)?;
        validate_ssh_rsa_key(&key)?;
        let canonical_wire = build_rsa_wire(
            key.n().to_bytes_be().as_slice(),
            key.e().to_bytes_be().as_slice(),
        );
        if canonical_wire != wire {
            return Err(AgeError::InvalidKey("non-canonical SSH RSA public key"));
        }
        Ok(SshRsaPublicKey {
            public_key: key,
            wire_key: canonical_wire,
        })
    }
}

/// Parses an unencrypted single-key OpenSSH private key blob.
pub(crate) fn parse_openssh_private(pem: &[u8]) -> Result<OpenSshPrivateKey> {
    let container = parse_openssh_container(pem)?;
    if container.cipher != OPENSSH_CIPHER_NONE || container.kdf != OPENSSH_KDF_NONE {
        return Err(passphrase_missing_error(&container.public_blob)?);
    }
    if !container.kdf_options.is_empty() {
        return Err(AgeError::InvalidKey("invalid OpenSSH private key"));
    }
    parse_openssh_private_section(
        container.private_blob.as_slice(),
        &container.public_blob,
        false,
    )
}

/// Decrypts and parses a passphrase-protected OpenSSH or legacy RSA PEM key.
pub(crate) fn parse_private_key_with_passphrase(
    pem: &[u8],
    passphrase: &[u8],
) -> Result<OpenSshPrivateKey> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| AgeError::InvalidKey("SSH private key is not UTF-8 PEM"))?;
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        return parse_openssh_private_with_passphrase(pem, passphrase);
    }
    parse_legacy_encrypted_rsa(text, passphrase)
}

/// Checks that a PEM contains a supported encrypted SSH private key.
pub(crate) fn validate_encrypted_private_key(pem: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| AgeError::InvalidKey("SSH private key is not UTF-8 PEM"))?;
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        let container = parse_openssh_container(pem)?;
        if container.cipher == OPENSSH_CIPHER_NONE && container.kdf == OPENSSH_KDF_NONE {
            return Err(AgeError::InvalidKey(
                "SSH private key is not password protected",
            ));
        }
        let _ = passphrase_missing_error(&container.public_blob)?;
        return Ok(());
    }
    let legacy = parse_legacy_pem(text)?;
    if !legacy.encrypted {
        return Err(AgeError::InvalidKey(
            "SSH private key is not password protected",
        ));
    }
    let _ = legacy.cipher()?;
    Ok(())
}

fn parse_openssh_private_with_passphrase(
    pem: &[u8],
    passphrase: &[u8],
) -> Result<OpenSshPrivateKey> {
    let container = parse_openssh_container(pem)?;
    if container.cipher == OPENSSH_CIPHER_NONE || container.kdf == OPENSSH_KDF_NONE {
        return Err(AgeError::InvalidKey(
            "SSH private key is not password protected",
        ));
    }
    if container.kdf != OPENSSH_KDF_BCRYPT {
        return Err(AgeError::Unsupported("unsupported OpenSSH KDF"));
    }
    let (salt, rounds) = parse_openssh_kdf_options(&container.kdf_options)?;
    let derived = openssh_bcrypt::derive_key(passphrase, &salt, rounds, OPENSSH_DERIVED_KEY_LENGTH)
        .map_err(|error| match error {
            openssh_bcrypt::OpenSshBcryptError::EmptyPassword => {
                AgeError::InvalidKey("SSH passphrase must not be empty")
            }
            _ => AgeError::InvalidKey("OpenSSH bcrypt key derivation failed"),
        })?;
    let derived = Zeroizing::new(derived);
    let key = derived
        .get(..32)
        .ok_or(AgeError::InvalidKey("invalid OpenSSH derived key"))?;
    let iv = derived
        .get(32..)
        .ok_or(AgeError::InvalidKey("invalid OpenSSH derived key"))?;
    let mut private = Zeroizing::new(container.private_blob.as_slice().to_vec());

    match container.cipher.as_slice() {
        value if value == OPENSSH_CIPHER_AES256_CTR => {
            let mut stream = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| AgeError::InvalidKey("invalid OpenSSH AES key or IV"))?;
            stream.apply_keystream(private.as_mut_slice());
        }
        value if value == OPENSSH_CIPHER_AES256_CBC => {
            if private.len() % OPENSSH_AES_BLOCK_SIZE != 0 {
                return Err(AgeError::InvalidKey(
                    "invalid encrypted SSH private-key length",
                ));
            }
            private = decrypt_aes256_cbc_raw(key, iv, private.as_slice())?;
        }
        _ => {
            return Err(AgeError::Unsupported(
                "unsupported encrypted OpenSSH cipher",
            ));
        }
    }
    parse_openssh_private_section(private.as_slice(), &container.public_blob, true)
}

fn parse_openssh_container(pem: &[u8]) -> Result<OpenSshContainer> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| AgeError::InvalidKey("SSH private key is not UTF-8 PEM"))?;
    let key_bytes = decode_openssh_pem(text)?;
    let mut reader = SshReader::new(key_bytes.as_slice());
    let magic = reader.read_cstring()?;
    if magic.as_slice() != OPENSSH_MAGIC {
        return Err(AgeError::InvalidKey("invalid OpenSSH private-key header"));
    }
    let cipher = reader.read_string()?;
    let kdf = reader.read_string()?;
    let kdf_options = reader.read_string()?;
    let key_count = reader.read_u32()?;
    if key_count != 1 {
        return Err(AgeError::InvalidKey(
            "multi-key OpenSSH files are not supported",
        ));
    }
    let public_blob = reader.read_string()?;
    let private_blob = Zeroizing::new(reader.read_string()?);
    if !reader.is_complete() {
        return Err(AgeError::InvalidKey("trailing data in OpenSSH private key"));
    }
    Ok(OpenSshContainer {
        cipher,
        kdf,
        kdf_options,
        public_blob,
        private_blob,
    })
}

struct OpenSshContainer {
    cipher: Vec<u8>,
    kdf: Vec<u8>,
    kdf_options: Vec<u8>,
    public_blob: Vec<u8>,
    private_blob: Zeroizing<Vec<u8>>,
}

fn parse_openssh_kdf_options(options: &[u8]) -> Result<(Vec<u8>, u32)> {
    let mut reader = SshReader::new(options);
    let salt = reader.read_string()?;
    let rounds = reader.read_u32()?;
    if !(1..=2_048).contains(&rounds) {
        return Err(AgeError::InvalidKey(
            "OpenSSH bcrypt rounds exceed the limit",
        ));
    }
    if !reader.is_complete() {
        return Err(AgeError::InvalidKey("invalid OpenSSH KDF options"));
    }
    Ok((salt, rounds))
}

fn parse_openssh_private_section(
    bytes: &[u8],
    public_blob: &[u8],
    encrypted: bool,
) -> Result<OpenSshPrivateKey> {
    let mut private = SshReader::new(bytes);
    let check_one = private
        .read_u32()
        .map_err(|_| openssh_check_error(encrypted))?;
    let check_two = private
        .read_u32()
        .map_err(|_| openssh_check_error(encrypted))?;
    if !bool::from(check_one.ct_eq(&check_two)) {
        return Err(openssh_check_error(encrypted));
    }
    let kind = private.read_string()?;
    let result = match kind.as_slice() {
        ED25519_KIND => parse_openssh_ed25519(&mut private, public_blob)?,
        RSA_KIND => parse_openssh_rsa(&mut private, public_blob)?,
        _ => return Err(AgeError::Unsupported("unsupported SSH private-key type")),
    };
    validate_openssh_padding(private.remaining())?;
    Ok(result)
}

fn openssh_check_error(encrypted: bool) -> AgeError {
    if encrypted {
        AgeError::InvalidKey("incorrect SSH passphrase")
    } else {
        AgeError::InvalidKey("OpenSSH private-key check values differ")
    }
}

/// A parsed private key used to construct an age identity.
#[allow(clippy::large_enum_variant)]
pub(crate) enum OpenSshPrivateKey {
    /// Ed25519 private-key fields.
    Ed25519 {
        /// Ed25519 seed.
        seed: Zeroizing<[u8; 32]>,
        /// Ed25519 public key.
        public_key: [u8; 32],
        /// SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
    /// RSA private key and SSH wire public-key blob.
    Rsa {
        /// Parsed RSA private key.
        private_key: RsaPrivateKey,
        /// SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
}

fn parse_openssh_ed25519(
    reader: &mut SshReader<'_>,
    public_blob: &[u8],
) -> Result<OpenSshPrivateKey> {
    let public_key = reader.read_string()?;
    let private_key = Zeroizing::new(reader.read_string()?);
    let _comment = reader.read_string()?;
    if public_key.len() != 32 || private_key.len() != 64 {
        return Err(AgeError::InvalidKey("invalid OpenSSH Ed25519 private key"));
    }
    let public_array: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AgeError::InvalidKey("invalid OpenSSH Ed25519 public key"))?;
    let public_component = private_key
        .get(32..64)
        .ok_or(AgeError::InvalidKey("invalid OpenSSH Ed25519 private key"))?;
    if !bool::from(public_array.as_slice().ct_eq(public_component)) {
        return Err(AgeError::InvalidKey(
            "OpenSSH Ed25519 public component is invalid",
        ));
    }
    let seed: [u8; 32] = private_key
        .get(..32)
        .ok_or(AgeError::InvalidKey("invalid OpenSSH Ed25519 private key"))?
        .try_into()
        .map_err(|_| AgeError::InvalidKey("invalid OpenSSH Ed25519 private key"))?;
    let expected_wire = build_ed25519_wire(&public_array);
    if expected_wire != public_blob {
        return Err(AgeError::InvalidKey(
            "OpenSSH public key does not match private key",
        ));
    }
    Ok(OpenSshPrivateKey::Ed25519 {
        seed: Zeroizing::new(seed),
        public_key: public_array,
        wire_key: expected_wire,
    })
}

fn parse_openssh_rsa(reader: &mut SshReader<'_>, public_blob: &[u8]) -> Result<OpenSshPrivateKey> {
    let modulus = reader.read_mpint()?;
    let exponent = reader.read_mpint()?;
    let private_exponent = Zeroizing::new(reader.read_mpint()?);
    let _coefficient = Zeroizing::new(reader.read_mpint()?);
    let prime_one = Zeroizing::new(reader.read_mpint()?);
    let prime_two = Zeroizing::new(reader.read_mpint()?);
    let _comment = reader.read_string()?;
    validate_ssh_rsa_components(
        &modulus,
        &exponent,
        Some((prime_one.as_slice(), prime_two.as_slice())),
    )?;
    // The private-component constructor is not limited to rsa 0.9's public
    // 4096-bit default; the SSH bounds above are checked before it performs
    // CRT precomputation.
    let private_key = RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from_bytes_be(&exponent),
        rsa::BigUint::from_bytes_be(private_exponent.as_slice()),
        vec![
            rsa::BigUint::from_bytes_be(prime_one.as_slice()),
            rsa::BigUint::from_bytes_be(prime_two.as_slice()),
        ],
    )
    .map_err(|_| AgeError::InvalidKey("invalid OpenSSH RSA private key"))?;
    validate_ssh_rsa_private_key(&private_key)?;
    let expected_wire = build_rsa_wire(
        private_key.n().to_bytes_be().as_slice(),
        private_key.e().to_bytes_be().as_slice(),
    );
    if expected_wire != public_blob {
        return Err(AgeError::InvalidKey(
            "OpenSSH public key does not match private key",
        ));
    }
    Ok(OpenSshPrivateKey::Rsa {
        private_key,
        wire_key: expected_wire,
    })
}

struct LegacyPem {
    encrypted: bool,
    cipher: Option<LegacyCipher>,
    iv: Zeroizing<Vec<u8>>,
    data: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum LegacyCipher {
    Aes128,
    Aes192,
    Aes256,
    Des,
    DesEde3,
}

impl LegacyPem {
    fn cipher(&self) -> Result<LegacyCipher> {
        self.cipher
            .ok_or(AgeError::InvalidKey("legacy PEM cipher is missing"))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "legacy PEM framing and headers are validated together"
)]
fn parse_legacy_pem(text: &str) -> Result<LegacyPem> {
    let (label, begin, end) = legacy_pem_markers(text)?;
    if label != "RSA PRIVATE KEY" {
        return Err(AgeError::Unsupported(
            "only RSA legacy SSH private keys are supported",
        ));
    }
    let start = text
        .find(begin)
        .ok_or(AgeError::InvalidKey("invalid PEM framing"))?;
    if !text
        .get(..start)
        .ok_or(AgeError::InvalidKey("invalid PEM framing"))?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(AgeError::InvalidKey("invalid PEM framing"));
    }
    let header_end = start
        .checked_add(begin.len())
        .ok_or(AgeError::InvalidKey("invalid PEM framing"))?;
    let body_start = skip_line_break(text, header_end)?;
    let end_offset = text
        .get(body_start..)
        .and_then(|tail| tail.find(end))
        .map(|offset| body_start + offset)
        .ok_or(AgeError::InvalidKey("missing PEM footer"))?;
    let body = text
        .get(body_start..end_offset)
        .ok_or(AgeError::InvalidKey("invalid PEM body"))?;
    let after_end = end_offset
        .checked_add(end.len())
        .ok_or(AgeError::InvalidKey("invalid PEM footer"))?;
    if !text
        .get(after_end..)
        .ok_or(AgeError::InvalidKey("invalid PEM footer"))?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(AgeError::InvalidKey("trailing data after PEM block"));
    }

    let mut headers = Vec::new();
    let mut data_lines = Vec::new();
    let mut in_data = false;
    for line in body.lines() {
        if !in_data && line.trim().is_empty() {
            in_data = true;
        } else if in_data {
            data_lines.push(line);
        } else if !line.trim().is_empty() {
            headers.push(line);
        }
    }
    if !in_data {
        return Err(AgeError::InvalidKey("invalid PEM headers"));
    }
    let mut proc_type = None;
    let mut dek_info = None;
    for header in headers {
        let Some((name, value)) = header.split_once(':') else {
            return Err(AgeError::InvalidKey("invalid PEM header"));
        };
        match name.trim() {
            "Proc-Type" => proc_type = Some(value.trim().to_owned()),
            "DEK-Info" => dek_info = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    let encrypted = proc_type
        .as_deref()
        .is_some_and(|value| value.contains("ENCRYPTED"));
    let encoded = Zeroizing::new(
        data_lines
            .iter()
            .flat_map(|line| line.bytes())
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect::<String>(),
    );
    let data = Zeroizing::new(
        decode_standard_or_raw(&encoded)
            .map_err(|_| AgeError::InvalidKey("invalid encrypted PEM data"))?,
    );
    if data.is_empty() || data.len() > 1024 * 1024 {
        return Err(AgeError::InvalidKey("invalid encrypted PEM data length"));
    }

    if !encrypted {
        return Ok(LegacyPem {
            encrypted: false,
            cipher: None,
            iv: Zeroizing::new(Vec::new()),
            data,
        });
    }
    let dek = dek_info.ok_or(AgeError::InvalidKey("encrypted PEM is missing DEK-Info"))?;
    let (cipher_name, iv_hex) = dek
        .split_once(',')
        .ok_or(AgeError::InvalidKey("invalid DEK-Info header"))?;
    let cipher = parse_legacy_cipher(cipher_name.trim())?;
    let iv = decode_hex(iv_hex.trim())?;
    Ok(LegacyPem {
        encrypted: true,
        cipher: Some(cipher),
        iv: Zeroizing::new(iv),
        data,
    })
}

fn legacy_pem_markers(text: &str) -> Result<(&'static str, &'static str, &'static str)> {
    if text.contains("-----BEGIN RSA PRIVATE KEY-----") {
        Ok((
            "RSA PRIVATE KEY",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        ))
    } else if text.contains("-----BEGIN EC PRIVATE KEY-----") {
        Ok((
            "EC PRIVATE KEY",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
        ))
    } else if text.contains("-----BEGIN DSA PRIVATE KEY-----") {
        Ok((
            "DSA PRIVATE KEY",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----END DSA PRIVATE KEY-----",
        ))
    } else {
        Err(AgeError::InvalidKey("invalid PEM private key"))
    }
}

fn parse_legacy_cipher(name: &str) -> Result<LegacyCipher> {
    match name {
        "AES-128-CBC" => Ok(LegacyCipher::Aes128),
        "AES-192-CBC" => Ok(LegacyCipher::Aes192),
        "AES-256-CBC" => Ok(LegacyCipher::Aes256),
        "DES-CBC" => Ok(LegacyCipher::Des),
        "DES-EDE3-CBC" => Ok(LegacyCipher::DesEde3),
        _ => Err(AgeError::Unsupported("unsupported legacy PEM cipher")),
    }
}

fn parse_legacy_encrypted_rsa(text: &str, passphrase: &[u8]) -> Result<OpenSshPrivateKey> {
    let legacy = parse_legacy_pem(text)?;
    if !legacy.encrypted {
        return Err(AgeError::InvalidKey(
            "SSH private key is not password protected",
        ));
    }
    let cipher = legacy.cipher()?;
    let (key_length, block_size) = match cipher {
        LegacyCipher::Aes128 => (16, 16),
        LegacyCipher::Aes192 => (24, 16),
        LegacyCipher::Aes256 => (32, 16),
        LegacyCipher::Des => (8, 8),
        LegacyCipher::DesEde3 => (24, 8),
    };
    if legacy.iv.len() != block_size {
        return Err(AgeError::InvalidKey("invalid legacy PEM IV length"));
    }
    let mut last_error = AgeError::InvalidKey("incorrect SSH passphrase");
    for salt in legacy_salts(legacy.iv.as_slice()) {
        let key = evp_bytes_to_key(passphrase, salt, key_length)?;
        let plaintext = match cipher {
            LegacyCipher::Aes128 => decrypt_aes_cbc_pkcs7::<aes::Aes128>(
                key.as_slice(),
                legacy.iv.as_slice(),
                legacy.data.as_slice(),
                16,
            ),
            LegacyCipher::Aes192 => decrypt_aes_cbc_pkcs7::<aes::Aes192>(
                key.as_slice(),
                legacy.iv.as_slice(),
                legacy.data.as_slice(),
                16,
            ),
            LegacyCipher::Aes256 => decrypt_aes_cbc_pkcs7::<aes::Aes256>(
                key.as_slice(),
                legacy.iv.as_slice(),
                legacy.data.as_slice(),
                16,
            ),
            LegacyCipher::Des => decrypt_des_cbc_pkcs7::<des::Des>(
                key.as_slice(),
                legacy.iv.as_slice(),
                legacy.data.as_slice(),
                8,
            ),
            LegacyCipher::DesEde3 => decrypt_des_cbc_pkcs7::<des::TdesEde3>(
                key.as_slice(),
                legacy.iv.as_slice(),
                legacy.data.as_slice(),
                8,
            ),
        };
        let plaintext = match plaintext {
            Ok(value) => value,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        let Ok(private_key) = RsaPrivateKey::from_pkcs1_der(plaintext.as_slice()) else {
            continue;
        };
        validate_ssh_rsa_private_key(&private_key)?;
        let wire_key = build_rsa_wire(
            private_key.n().to_bytes_be().as_slice(),
            private_key.e().to_bytes_be().as_slice(),
        );
        return Ok(OpenSshPrivateKey::Rsa {
            private_key,
            wire_key,
        });
    }
    Err(last_error)
}

fn legacy_salts(iv: &[u8]) -> Vec<&[u8]> {
    let mut salts = Vec::with_capacity(2);
    salts.push(iv);
    if let Some(prefix) = iv.get(..8)
        && prefix != iv
    {
        salts.push(prefix);
    }
    salts
}

fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_length: usize) -> Result<Zeroizing<Vec<u8>>> {
    if key_length == 0 || key_length > 64 {
        return Err(AgeError::InvalidKey("invalid legacy PEM key length"));
    }
    let mut key = Zeroizing::new(Vec::with_capacity(key_length));
    let mut previous = Zeroizing::new(Vec::new());
    while key.len() < key_length {
        let mut input = Zeroizing::new(Vec::with_capacity(
            previous
                .len()
                .saturating_add(password.len())
                .saturating_add(salt.len()),
        ));
        input.extend_from_slice(previous.as_slice());
        input.extend_from_slice(password);
        input.extend_from_slice(salt);
        let mut digest = Md5::digest(input.as_slice());
        let block = Zeroizing::new(digest.as_slice().to_vec());
        digest.as_mut_slice().zeroize();
        let remaining = key_length - key.len();
        let take = remaining.min(block.len());
        key.extend_from_slice(block.get(..take).ok_or(AgeError::Crypto("MD5 output"))?);
        previous = block;
    }
    Ok(key)
}

fn decrypt_aes256_cbc_raw(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(AgeError::InvalidKey("invalid CBC ciphertext length"));
    }
    let cipher = aes::Aes256::new_from_slice(key)
        .map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let decryptor = cbc::Decryptor::<aes::Aes256>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    let length = decryptor
        .decrypt_padded_b2b::<aes::cipher::block_padding::NoPadding>(
            ciphertext,
            plaintext.as_mut_slice(),
        )
        .map_err(|_| AgeError::InvalidKey("invalid CBC ciphertext"))?
        .len();
    plaintext.truncate(length);
    Ok(plaintext)
}

fn decrypt_aes_cbc_pkcs7<C>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    block_size: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    C: aes::cipher::BlockCipherDecrypt + aes::cipher::KeyInit,
{
    if !ciphertext.len().is_multiple_of(block_size) {
        return Err(AgeError::InvalidKey("incorrect SSH passphrase"));
    }
    let cipher =
        C::new_from_slice(key).map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let decryptor = cbc::Decryptor::<C>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    let length = decryptor
        .decrypt_padded_b2b::<aes::cipher::block_padding::Pkcs7>(
            ciphertext,
            plaintext.as_mut_slice(),
        )
        .map_err(|_| AgeError::InvalidKey("incorrect SSH passphrase"))?
        .len();
    plaintext.truncate(length);
    Ok(plaintext)
}

fn decrypt_des_cbc_pkcs7<C>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    block_size: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    C: des::cipher::BlockCipherDecrypt + des::cipher::KeyInit,
{
    if !ciphertext.len().is_multiple_of(block_size) {
        return Err(AgeError::InvalidKey("incorrect SSH passphrase"));
    }
    let cipher =
        C::new_from_slice(key).map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let decryptor = cbc::Decryptor::<C>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| AgeError::InvalidKey("invalid CBC key or IV"))?;
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    let length = des::cipher::BlockModeDecrypt::decrypt_padded_b2b::<
        aes::cipher::block_padding::Pkcs7,
    >(decryptor, ciphertext, plaintext.as_mut_slice())
    .map_err(|_| AgeError::InvalidKey("incorrect SSH passphrase"))?
    .len();
    plaintext.truncate(length);
    Ok(plaintext)
}

/// Parses an unencrypted Ed25519 PKCS#8 private key.
pub(crate) fn parse_ed25519_pkcs8_pem(pem: &str) -> Result<OpenSshPrivateKey> {
    let signing = <SigningKey as EdDecodePrivateKey>::from_pkcs8_pem(pem)
        .map_err(|_| AgeError::InvalidKey("invalid Ed25519 PKCS#8 private key"))?;
    let public_key = signing.verifying_key().to_bytes();
    let wire_key = build_ed25519_wire(&public_key);
    Ok(OpenSshPrivateKey::Ed25519 {
        seed: Zeroizing::new(signing.to_bytes()),
        public_key,
        wire_key,
    })
}

/// Parses a PEM RSA private key (PKCS#1 or PKCS#8).
pub(crate) fn parse_rsa_pem(pem: &str) -> Result<RsaPrivateKey> {
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem) {
        validate_ssh_rsa_private_key(&key)?;
        return Ok(key);
    }
    let key = RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|_| AgeError::InvalidKey("invalid RSA private key"))?;
    validate_ssh_rsa_private_key(&key)?;
    Ok(key)
}

fn passphrase_missing_error(public_blob: &[u8]) -> Result<AgeError> {
    let public_key = public_key_line(public_blob)?;
    Ok(AgeError::PassphraseMissing { public_key })
}

fn public_key_line(public_blob: &[u8]) -> Result<String> {
    let mut reader = SshReader::new(public_blob);
    let kind = reader.read_string()?;
    let kind_name = match kind.as_slice() {
        ED25519_KIND => "ssh-ed25519",
        RSA_KIND => "ssh-rsa",
        _ => {
            return Err(AgeError::InvalidKey(
                "unsupported embedded SSH public key type",
            ));
        }
    };
    let line = format!(
        "{kind_name} {}",
        base64::engine::general_purpose::STANDARD.encode(public_blob)
    );
    match kind.as_slice() {
        ED25519_KIND => {
            SshEd25519Key::parse_public_key(&line)?;
        }
        RSA_KIND => {
            SshRsaKey::parse_public_key(&line)?;
        }
        _ => return Err(AgeError::InvalidKey("invalid embedded SSH public key")),
    }
    Ok(line)
}

fn parse_authorized_key(line: &str, expected_kind: &[u8]) -> Result<Vec<u8>> {
    let expected = std::str::from_utf8(expected_kind)
        .map_err(|_| AgeError::InvalidKey("invalid SSH public-key type"))?;
    let mut encoded = None;
    let mut fields = line.split_whitespace().peekable();
    while let Some(field) = fields.next() {
        if field == expected {
            encoded = fields.next();
            break;
        }
    }
    let encoded = encoded.ok_or(AgeError::InvalidKey("invalid SSH public key"))?;
    let wire = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AgeError::InvalidKey("invalid SSH public-key encoding"))?;
    if base64::engine::general_purpose::STANDARD.encode(&wire) != encoded {
        return Err(AgeError::InvalidKey("non-canonical SSH public key"));
    }
    Ok(wire)
}

fn decode_openssh_pem(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";
    let start = text.find(begin).ok_or(AgeError::InvalidKey(
        "missing OpenSSH private-key PEM block",
    ))?;
    if !text
        .get(..start)
        .ok_or(AgeError::InvalidKey(
            "invalid OpenSSH private-key PEM block",
        ))?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(AgeError::InvalidKey(
            "invalid OpenSSH private-key PEM block",
        ));
    }
    let body_start = start.checked_add(begin.len()).ok_or(AgeError::InvalidKey(
        "invalid OpenSSH private-key PEM block",
    ))?;
    let body_start = skip_line_break(text, body_start)?;
    let end_offset = text
        .get(body_start..)
        .and_then(|tail| tail.find(end))
        .map(|offset| body_start + offset)
        .ok_or(AgeError::InvalidKey("missing OpenSSH private-key footer"))?;
    let encoded = Zeroizing::new(
        text.get(body_start..end_offset)
            .ok_or(AgeError::InvalidKey("invalid OpenSSH private-key PEM"))?
            .bytes()
            .filter(|value| !value.is_ascii_whitespace())
            .map(char::from)
            .collect::<String>(),
    );
    let after_end = end_offset
        .checked_add(end.len())
        .ok_or(AgeError::InvalidKey("invalid OpenSSH private-key footer"))?;
    if !text
        .get(after_end..)
        .ok_or(AgeError::InvalidKey("invalid OpenSSH private-key footer"))?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(AgeError::InvalidKey(
            "trailing data after OpenSSH private key",
        ));
    }
    let decoded = Zeroizing::new(
        decode_standard_or_raw(&encoded)
            .map_err(|_| AgeError::InvalidKey("invalid OpenSSH private-key encoding"))?,
    );
    if decoded.is_empty() || decoded.len() > 1024 * 1024 {
        return Err(AgeError::InvalidKey("invalid OpenSSH private-key length"));
    }
    Ok(decoded)
}

fn skip_line_break(text: &str, index: usize) -> Result<usize> {
    let rest = text
        .get(index..)
        .ok_or(AgeError::InvalidKey("invalid PEM line ending"))?;
    if rest.starts_with("\r\n") {
        return Ok(index + 2);
    }
    if rest.starts_with('\n') {
        return Ok(index + 1);
    }
    Err(AgeError::InvalidKey("invalid PEM line ending"))
}

pub(crate) fn validate_ssh_rsa_private_key(key: &RsaPrivateKey) -> Result<()> {
    validate_ssh_rsa_key(&key.to_public_key())?;
    for prime in key.primes() {
        let prime_bytes = prime.to_bytes_be();
        if prime_bytes.is_empty()
            || prime_bytes.last().is_none_or(|byte| byte & 1 == 0)
            || prime.bits() > SSH_RSA_MAX_PRIME_BITS
        {
            return Err(AgeError::InvalidKey(
                "SSH RSA prime factors must be odd and at most 8192 bits",
            ));
        }
    }
    Ok(())
}

fn validate_ssh_rsa_key(key: &RsaPublicKey) -> Result<()> {
    let modulus = key.n().to_bytes_be();
    let exponent = key.e().to_bytes_be();
    validate_ssh_rsa_components(&modulus, &exponent, None)
}

fn validate_ssh_rsa_components(
    modulus: &[u8],
    exponent: &[u8],
    primes: Option<(&[u8], &[u8])>,
) -> Result<()> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(AgeError::InvalidKey(
            "RSA public-key components are missing",
        ));
    }
    let modulus_bits = ssh_mpint_bit_len(modulus);
    if !(SSH_RSA_MIN_MODULUS_BITS..=SSH_RSA_MAX_MODULUS_BITS).contains(&modulus_bits) {
        return Err(AgeError::InvalidKey(
            "SSH RSA modulus must contain between 2048 and 16384 bits",
        ));
    }
    let exponent_bits = ssh_mpint_bit_len(exponent);
    if exponent_bits > SSH_RSA_MAX_EXPONENT_BITS {
        return Err(AgeError::InvalidKey("invalid SSH RSA public exponent"));
    }
    let exponent_value = rsa::BigUint::from_bytes_be(exponent);
    if exponent_value.bits() > SSH_RSA_MAX_EXPONENT_BITS
        || exponent_value < rsa::BigUint::from(3u8)
        || exponent.last().is_none_or(|byte| byte & 1 == 0)
    {
        return Err(AgeError::InvalidKey("invalid SSH RSA public exponent"));
    }
    if let Some((prime_one, prime_two)) = primes {
        for prime in [prime_one, prime_two] {
            if prime.is_empty()
                || prime.last().is_none_or(|byte| byte & 1 == 0)
                || ssh_mpint_bit_len(prime) > SSH_RSA_MAX_PRIME_BITS
            {
                return Err(AgeError::InvalidKey(
                    "SSH RSA prime factors must be odd and at most 8192 bits",
                ));
            }
        }
    }
    Ok(())
}

fn ssh_mpint_bit_len(value: &[u8]) -> usize {
    let Some(first) = value.iter().position(|byte| *byte != 0) else {
        return 0;
    };
    let significant = value.len() - first;
    significant
        .saturating_mul(8)
        .saturating_sub(value[first].leading_zeros() as usize)
}

fn rsa_public_from_components(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey> {
    validate_ssh_rsa_components(modulus, exponent, None)?;
    // rsa 0.9 defaults to a 4096-bit public-key limit. SSH's wire policy is
    // 16384 bits, so use the checked, caller-sized constructor rather than
    // bypassing validation with `new_unchecked`.
    RsaPublicKey::new_with_max_size(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
        SSH_RSA_MAX_MODULUS_BITS,
    )
    .map_err(|_| AgeError::InvalidKey("invalid RSA public key"))
}

fn build_ed25519_wire(public_key: &[u8; 32]) -> Vec<u8> {
    let mut wire = Vec::new();
    write_string(&mut wire, ED25519_KIND);
    write_string(&mut wire, public_key);
    wire
}

pub(crate) fn build_rsa_wire(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    write_string(&mut wire, RSA_KIND);
    write_mpint(&mut wire, exponent);
    write_mpint(&mut wire, modulus);
    wire
}

fn write_string(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn write_mpint(output: &mut Vec<u8>, value: &[u8]) {
    let start = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let trimmed = value.get(start..).map_or(&[][..], |slice| slice);
    if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
        write_string(output, &[&[0][..], trimmed].concat());
    } else {
        write_string(output, trimmed);
    }
}

fn validate_openssh_padding(padding: &[u8]) -> Result<()> {
    for (index, value) in padding.iter().enumerate() {
        let expected =
            u8::try_from(index + 1).map_err(|_| AgeError::InvalidKey("invalid OpenSSH padding"))?;
        if *value != expected {
            return Err(AgeError::InvalidKey("invalid OpenSSH private-key padding"));
        }
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(AgeError::InvalidKey("invalid legacy PEM IV"));
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AgeError::InvalidKey("invalid legacy PEM IV")),
    }
}

struct SshReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SshReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn is_complete(&self) -> bool {
        self.offset == self.data.len()
    }

    fn remaining(&self) -> &'a [u8] {
        self.data.get(self.offset..).unwrap_or(&[])
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self
            .data
            .get(self.offset..self.offset.saturating_add(4))
            .ok_or(AgeError::InvalidKey("truncated SSH key"))?;
        let value = u32::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| AgeError::InvalidKey("truncated SSH key"))?,
        );
        self.offset = self
            .offset
            .checked_add(4)
            .ok_or(AgeError::InvalidKey("SSH key offset overflow"))?;
        Ok(value)
    }

    fn read_string(&mut self) -> Result<Vec<u8>> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| AgeError::InvalidKey("SSH string is too large"))?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AgeError::InvalidKey("SSH string length overflow"))?;
        let value = self
            .data
            .get(self.offset..end)
            .ok_or(AgeError::InvalidKey("truncated SSH string"))?
            .to_vec();
        self.offset = end;
        Ok(value)
    }

    fn read_cstring(&mut self) -> Result<Vec<u8>> {
        let start = self.offset;
        let end = self
            .data
            .get(start..)
            .ok_or(AgeError::InvalidKey("truncated SSH key"))?
            .iter()
            .position(|value| *value == 0)
            .map(|offset| start + offset)
            .ok_or(AgeError::InvalidKey("unterminated SSH string"))?;
        let value = self
            .data
            .get(start..end)
            .ok_or(AgeError::InvalidKey("invalid SSH string"))?
            .to_vec();
        self.offset = end
            .checked_add(1)
            .ok_or(AgeError::InvalidKey("SSH key offset overflow"))?;
        Ok(value)
    }

    fn read_mpint(&mut self) -> Result<Vec<u8>> {
        let mut value = self.read_string()?;
        let had_sign_prefix = value.len() > 1 && value.first() == Some(&0);
        if value.first().is_some_and(|byte| byte & 0x80 != 0) && !had_sign_prefix {
            return Err(AgeError::InvalidKey("negative SSH mpint"));
        }
        if had_sign_prefix {
            value.remove(0);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rsa::{
        pkcs1::EncodeRsaPrivateKey as _,
        pkcs8::{EncodePrivateKey as _, LineEnding},
        traits::PublicKeyParts,
    };

    use super::{
        LegacyCipher, OpenSshPrivateKey, SshRsaKey, build_rsa_wire, parse_legacy_cipher,
        parse_openssh_private, parse_rsa_pem, rsa_public_from_components,
        validate_ssh_rsa_components,
    };

    fn authorized_rsa_line(modulus: &[u8], exponent: &[u8]) -> String {
        let wire = build_rsa_wire(modulus, exponent);
        format!("ssh-rsa {}", STANDARD.encode(wire))
    }

    #[test]
    fn dispatches_legacy_cipher_names() {
        assert!(matches!(
            parse_legacy_cipher("AES-128-CBC"),
            Ok(LegacyCipher::Aes128)
        ));
        assert!(matches!(
            parse_legacy_cipher("AES-192-CBC"),
            Ok(LegacyCipher::Aes192)
        ));
        assert!(matches!(
            parse_legacy_cipher("AES-256-CBC"),
            Ok(LegacyCipher::Aes256)
        ));
        assert!(matches!(
            parse_legacy_cipher("DES-CBC"),
            Ok(LegacyCipher::Des)
        ));
        assert!(matches!(
            parse_legacy_cipher("DES-EDE3-CBC"),
            Ok(LegacyCipher::DesEde3)
        ));
        assert!(parse_legacy_cipher("AES-128-CTR").is_err());
    }

    #[test]
    fn accepts_16384_bit_rsa_pem_private_keys() {
        let pem = include_str!("../tests/data/rsa-16384-test-vector.key");
        let parsed = parse_openssh_private(pem.as_bytes()).expect("OpenSSH RSA key");
        let OpenSshPrivateKey::Rsa { private_key, .. } = parsed else {
            panic!("expected RSA private key");
        };
        let pkcs1 = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("PKCS#1 PEM");
        assert!(parse_rsa_pem(&pkcs1).is_ok());
        let pkcs8 = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PKCS#8 PEM");
        assert!(parse_rsa_pem(&pkcs8).is_ok());
    }

    #[test]
    fn accepts_16384_bit_ssh_rsa_public_key() {
        let modulus = vec![0xff; 16_384 / 8];
        let line = authorized_rsa_line(&modulus, &[0x01, 0x00, 0x01]);
        let key = SshRsaKey::parse_public_key(line).expect("16384-bit RSA key");
        assert_eq!(key.key().size(), 16_384 / 8);
    }

    #[test]
    fn enforces_ssh_rsa_modulus_exponent_and_prime_limits() {
        let modulus = vec![0xff; 2_048 / 8];
        assert!(rsa_public_from_components(&modulus, &[0x01, 0x00, 0x01]).is_ok());
        assert!(rsa_public_from_components(&modulus, &[0x03]).is_ok());
        assert!(rsa_public_from_components(&modulus, &[0xff, 0xff, 0xff]).is_ok());
        assert!(rsa_public_from_components(&modulus, &[0x02]).is_err());
        assert!(rsa_public_from_components(&modulus, &[0x01, 0x00, 0x00]).is_err());
        assert!(rsa_public_from_components(&modulus, &[0x01, 0x00, 0x00, 0x01]).is_err());

        let oversized_modulus = vec![0xff; (16_384usize + 1).div_ceil(8)];
        assert!(
            SshRsaKey::parse_public_key(authorized_rsa_line(
                &oversized_modulus,
                &[0x01, 0x00, 0x01],
            ))
            .is_err()
        );

        let prime = vec![0xff; 8_192 / 8];
        assert!(
            validate_ssh_rsa_components(&modulus, &[0x01, 0x00, 0x01], Some((&prime, &prime)))
                .is_ok()
        );
        let oversized_prime = vec![0xff; 8_192 / 8 + 1];
        assert!(
            validate_ssh_rsa_components(
                &modulus,
                &[0x01, 0x00, 0x01],
                Some((&oversized_prime, &prime)),
            )
            .is_err()
        );
    }
}
