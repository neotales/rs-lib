//! Parser for the binary `openssh-key-v1` private-key container.
//!
//! This module handles the unencrypted container and the `bcrypt` plus
//! `aes256-ctr` encrypted container.  It deliberately accepts one Ed25519,
//! RSA, or NIST P-256 ECDSA key only.  The returned private components are held in zeroizing
//! containers so that a caller can pass them to the existing signers without
//! making another unprotected copy.

#![allow(clippy::module_name_repetitions)]

use std::fmt;

use neotales_ssh::ecdsa_hostkey::{ECDSA_SECRET_SCALAR_LENGTH, EcdsaSigner};
use neotales_ssh::{Error as WireError, Reader, Writer};
use neotales_x509::openssh_bcrypt::{self, OpenSshBcryptError};
use {
    ed25519_dalek::SigningKey,
    zeroize::{Zeroize, Zeroizing},
};

use aes::cipher::{KeyIvInit, StreamCipher};

const OPENSSH_MAGIC: &[u8; 15] = b"openssh-key-v1\0";
const CIPHER_NONE: &[u8] = b"none";
const CIPHER_AES256_CTR: &[u8] = b"aes256-ctr";
const KDF_NONE: &[u8] = b"none";
const KDF_BCRYPT: &[u8] = b"bcrypt";
const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSH_RSA: &[u8] = b"ssh-rsa";
const SSH_ECDSA_SHA2_NISTP256: &[u8] = b"ecdsa-sha2-nistp256";
const ECDSA_CURVE_NISTP256: &[u8] = b"nistp256";
const ED25519_SEED_LENGTH: usize = 32;
const ED25519_PRIVATE_LENGTH: usize = 64;
const NONE_BLOCK_SIZE: usize = 8;
const AES_BLOCK_SIZE: usize = 16;
const DERIVED_KEY_LENGTH: usize = 48;

/// A safe error produced while parsing an OpenSSH private-key file.
///
/// Error values contain no input bytes, passphrase, check integer, private
/// scalar, comment, or decrypted data.  Both formatting implementations use
/// only fixed diagnostic text.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OpenSshKeyError {
    /// The file did not begin with the exact OpenSSH v1 magic.
    InvalidMagic,
    /// An SSH wire field was truncated or malformed.
    Malformed,
    /// The private-key cipher is not supported.
    UnsupportedCipher,
    /// The private-key KDF is not supported.
    UnsupportedKdf,
    /// The KDF options were not valid for the selected KDF.
    InvalidKdfOptions,
    /// The file did not contain exactly one key.
    InvalidKeyCount,
    /// The private section did not have the required cipher block length.
    InvalidCipherBlockSize,
    /// The two OpenSSH check integers did not match.
    WrongPassphrase,
    /// The private or public key algorithm is not supported.
    UnsupportedKeyType,
    /// An SSH public-key blob was malformed.
    InvalidPublicKey,
    /// The private-key fields were malformed.
    InvalidPrivateKey,
    /// The private scalar and public key did not identify the same key.
    PublicKeyMismatch,
    /// The OpenSSH private-key padding was malformed.
    InvalidPadding,
    /// Bytes remained after a defined OpenSSH field.
    TrailingData,
}

impl OpenSshKeyError {
    /// Compatibility spelling for [`OpenSshKeyError::Malformed`].
    #[allow(non_upper_case_globals)]
    pub const InvalidFormat: Self = Self::Malformed;

    /// Compatibility spelling for [`OpenSshKeyError::WrongPassphrase`].
    #[allow(non_upper_case_globals)]
    pub const InvalidPassphrase: Self = Self::WrongPassphrase;

    /// Compatibility spelling for [`OpenSshKeyError::PublicKeyMismatch`].
    #[allow(non_upper_case_globals)]
    pub const KeyMismatch: Self = Self::PublicKeyMismatch;

    /// Compatibility spelling for [`OpenSshKeyError::UnsupportedKeyType`].
    #[allow(non_upper_case_globals)]
    pub const UnsupportedAlgorithm: Self = Self::UnsupportedKeyType;

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidMagic => "OpenSSH private-key magic is invalid",
            Self::Malformed => "OpenSSH private-key data is malformed",
            Self::UnsupportedCipher => "OpenSSH private-key cipher is unsupported",
            Self::UnsupportedKdf => "OpenSSH private-key KDF is unsupported",
            Self::InvalidKdfOptions => "OpenSSH private-key KDF options are invalid",
            Self::InvalidKeyCount => "OpenSSH private-key file must contain exactly one key",
            Self::InvalidCipherBlockSize => {
                "OpenSSH private-key section has an invalid cipher block length"
            }
            Self::WrongPassphrase => "OpenSSH private-key passphrase is incorrect",
            Self::UnsupportedKeyType => "OpenSSH private-key algorithm is unsupported",
            Self::InvalidPublicKey => "OpenSSH public-key blob is invalid",
            Self::InvalidPrivateKey => "OpenSSH private-key fields are invalid",
            Self::PublicKeyMismatch => "OpenSSH private and public key halves do not match",
            Self::InvalidPadding => "OpenSSH private-key padding is invalid",
            Self::TrailingData => "OpenSSH private-key data contains trailing bytes",
        }
    }
}

impl fmt::Debug for OpenSshKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl fmt::Display for OpenSshKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for OpenSshKeyError {}

/// Compatibility name for [`OpenSshKeyError`].
pub type Error = OpenSshKeyError;

/// Compatibility name for [`OpenSshKeyError`].
pub type ParseError = OpenSshKeyError;

/// Compatibility name for [`OpenSshKeyError`].
pub type OpenSshPrivateKeyError = OpenSshKeyError;

/// Compatibility name for [`OpenSshKeyError`].
#[allow(clippy::upper_case_acronyms)]
pub type OpenSSHKeyError = OpenSshKeyError;

/// One parsed private key from an `openssh-key-v1` file.
///
/// The `Ed25519` and `Rsa` variants expose the exact SSH public-key blob and
/// the raw comment bytes.  Private components are zeroizing values and are
/// redacted from this type's debug representation.
pub enum OpenSshPrivateKey {
    /// An Ed25519 seed and its matching SSH public-key blob.
    Ed25519 {
        /// The 32-byte Ed25519 seed.
        seed: Zeroizing<[u8; ED25519_SEED_LENGTH]>,
        /// The complete `ssh-ed25519` public-key blob.
        public_blob: Vec<u8>,
        /// The raw OpenSSH comment bytes.
        comment: Vec<u8>,
    },
    /// A NIST P-256 ECDSA secret scalar and the matching SSH public-key blob.
    ///
    /// The curve is the only one this variant covers. A key file on another
    /// NIST curve parses as [`OpenSshKeyError::UnsupportedKeyType`] rather than
    /// being reported as something this crate can sign with, because the
    /// signer it would have to hand the scalar to does not exist.
    Ecdsa {
        /// The 32-byte P-256 private scalar.
        secret: Zeroizing<[u8; ECDSA_SECRET_SCALAR_LENGTH]>,
        /// The complete `ecdsa-sha2-nistp256` public-key blob.
        public_blob: Vec<u8>,
        /// The raw OpenSSH comment bytes.
        comment: Vec<u8>,
    },
    /// RSA prime components and the matching SSH public-key blob.
    Rsa {
        /// The unsigned big-endian prime `p`, without an mpint sign byte.
        p: Zeroizing<Vec<u8>>,
        /// The unsigned big-endian prime `q`, without an mpint sign byte.
        q: Zeroizing<Vec<u8>>,
        /// The unsigned big-endian public exponent `e`, without an mpint sign
        /// byte.
        e: Zeroizing<Vec<u8>>,
        /// The complete `ssh-rsa` public-key blob.
        public_blob: Vec<u8>,
        /// The raw OpenSSH comment bytes.
        comment: Vec<u8>,
    },
}

impl OpenSshPrivateKey {
    /// Parses one private key from a binary OpenSSH v1 file.
    ///
    /// The caller-provided passphrase buffer is zeroized before this method
    /// returns, including on malformed input and decryption failure.
    ///
    /// # Errors
    ///
    /// Returns [`OpenSshKeyError`] for an invalid container, unsupported
    /// cipher or KDF, a wrong passphrase, malformed private fields, invalid
    /// padding, or mismatched public and private key components.
    pub fn parse(bytes: &[u8], passphrase: &mut [u8]) -> Result<Self, OpenSshKeyError> {
        parse_openssh_private_key(bytes, passphrase)
    }

    /// Returns the complete SSH public-key blob.
    #[must_use]
    pub fn public_key_blob(&self) -> &[u8] {
        match self {
            Self::Ed25519 { public_blob, .. }
            | Self::Ecdsa { public_blob, .. }
            | Self::Rsa { public_blob, .. } => public_blob,
        }
    }

    /// Returns the complete SSH public-key blob.
    #[must_use]
    pub fn public_blob(&self) -> &[u8] {
        self.public_key_blob()
    }

    /// Returns the raw OpenSSH comment bytes.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        match self {
            Self::Ed25519 { comment, .. }
            | Self::Ecdsa { comment, .. }
            | Self::Rsa { comment, .. } => comment,
        }
    }

    /// Returns the Ed25519 seed, or `None` for any other key type.
    #[must_use]
    pub fn seed(&self) -> Option<&[u8]> {
        match self {
            Self::Ed25519 { seed, .. } => Some(seed.as_slice()),
            Self::Ecdsa { .. } | Self::Rsa { .. } => None,
        }
    }

    /// Returns the P-256 secret scalar, or `None` for any other key type.
    #[must_use]
    pub fn ecdsa_secret(&self) -> Option<&[u8; ECDSA_SECRET_SCALAR_LENGTH]> {
        match self {
            Self::Ecdsa { secret, .. } => Some(&**secret),
            Self::Ed25519 { .. } | Self::Rsa { .. } => None,
        }
    }

    /// Returns `(p, q, e)` for RSA, or `None` for an Ed25519 key.
    #[must_use]
    pub fn rsa_components(&self) -> Option<(&[u8], &[u8], &[u8])> {
        match self {
            Self::Rsa { p, q, e, .. } => Some((p.as_slice(), q.as_slice(), e.as_slice())),
            Self::Ed25519 { .. } | Self::Ecdsa { .. } => None,
        }
    }
}

impl fmt::Debug for OpenSshPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (key_type, public_len, comment_len) = match self {
            Self::Ed25519 {
                public_blob,
                comment,
                ..
            } => ("ssh-ed25519", public_blob.len(), comment.len()),
            Self::Ecdsa {
                public_blob,
                comment,
                ..
            } => ("ecdsa-sha2-nistp256", public_blob.len(), comment.len()),
            Self::Rsa {
                public_blob,
                comment,
                ..
            } => ("ssh-rsa", public_blob.len(), comment.len()),
        };
        formatter
            .debug_struct("OpenSshPrivateKey")
            .field("key_type", &key_type)
            .field("public_blob_len", &public_len)
            .field("comment_len", &comment_len)
            .field("private_material", &"[redacted]")
            .finish()
    }
}

/// Compatibility name for [`OpenSshPrivateKey`].
pub type PrivateKey = OpenSshPrivateKey;

/// Compatibility name for [`OpenSshPrivateKey`].
pub type ParsedPrivateKey = OpenSshPrivateKey;

/// Compatibility name for [`OpenSshPrivateKey`].
pub type OpenSshKey = OpenSshPrivateKey;

/// Compatibility name for [`OpenSshPrivateKey`].
#[allow(clippy::upper_case_acronyms)]
pub type OpenSSHPrivateKey = OpenSshPrivateKey;

/// Parses one binary `openssh-key-v1` private-key file.
///
/// The input is the decoded binary container, not a PEM armor wrapper.  Only
/// one key is accepted.  `none`/`none` uses the plaintext container, while
/// `aes256-ctr`/`bcrypt` derives 48 bytes and decrypts the private section in
/// place.  The supplied passphrase buffer is always zeroized before return.
///
/// # Errors
///
/// Returns [`OpenSshKeyError`] when the container is malformed, uses an
/// unsupported cipher or KDF, has a mismatched check integer, contains an
/// unsupported key type, has invalid padding, or has inconsistent public and
/// private key components.
pub fn parse_openssh_private_key(
    bytes: &[u8],
    passphrase: &mut [u8],
) -> Result<OpenSshPrivateKey, OpenSshKeyError> {
    let passphrase_guard = PassphraseGuard::new(passphrase);

    let Some(body) = bytes.get(OPENSSH_MAGIC.len()..) else {
        return Err(OpenSshKeyError::InvalidMagic);
    };
    if bytes.get(..OPENSSH_MAGIC.len()) != Some(OPENSSH_MAGIC.as_slice()) {
        return Err(OpenSshKeyError::InvalidMagic);
    }

    let mut reader = Reader::new(body);
    let cipher_name = read_string(&mut reader)?;
    let cipher = match cipher_name {
        value if value == CIPHER_NONE => ProtectionCipher::None,
        value if value == CIPHER_AES256_CTR => ProtectionCipher::Aes256Ctr,
        _ => return Err(OpenSshKeyError::UnsupportedCipher),
    };

    let kdf_name = read_string(&mut reader)?;
    let kdf = match kdf_name {
        value if value == KDF_NONE => ProtectionKdf::None,
        value if value == KDF_BCRYPT => ProtectionKdf::Bcrypt,
        _ => return Err(OpenSshKeyError::UnsupportedKdf),
    };

    let kdf_options = read_string(&mut reader)?;
    let protection = match (cipher, kdf) {
        (ProtectionCipher::None, ProtectionKdf::None) => {
            if !kdf_options.is_empty() {
                return Err(OpenSshKeyError::InvalidKdfOptions);
            }
            Protection::None
        }
        (ProtectionCipher::Aes256Ctr, ProtectionKdf::Bcrypt) => {
            let (salt, rounds) = parse_bcrypt_options(kdf_options)?;
            Protection::Aes256Ctr { salt, rounds }
        }
        _ => return Err(OpenSshKeyError::UnsupportedCipher),
    };

    let key_count = read_uint32(&mut reader)?;
    if key_count != 1 {
        return Err(OpenSshKeyError::InvalidKeyCount);
    }
    let public_blob = read_string_bytes(&mut reader)?;
    let public_material = parse_public_blob(public_blob.as_slice())?;
    let mut private_section = Zeroizing::new(read_string_bytes(&mut reader)?);
    if !reader.is_empty() {
        return Err(OpenSshKeyError::TrailingData);
    }

    let block_size = match protection {
        Protection::None => {
            if private_section.is_empty() || private_section.len() % NONE_BLOCK_SIZE != 0 {
                return Err(OpenSshKeyError::InvalidCipherBlockSize);
            }
            NONE_BLOCK_SIZE
        }
        Protection::Aes256Ctr { salt, rounds } => {
            if private_section.is_empty() || private_section.len() % AES_BLOCK_SIZE != 0 {
                return Err(OpenSshKeyError::InvalidCipherBlockSize);
            }
            decrypt_private_section(
                private_section.as_mut_slice(),
                salt.as_slice(),
                rounds,
                passphrase_guard.bytes,
            )?;
            AES_BLOCK_SIZE
        }
    };

    parse_private_section(
        private_section.as_slice(),
        block_size,
        public_material,
        public_blob,
    )
}

/// Parses one binary OpenSSH private-key file.
///
/// This is a short compatibility spelling of
/// [`parse_openssh_private_key`].
///
/// # Errors
///
/// Returns the same errors as [`parse_openssh_private_key`].
pub fn parse_private_key(
    bytes: &[u8],
    passphrase: &mut [u8],
) -> Result<OpenSshPrivateKey, OpenSshKeyError> {
    parse_openssh_private_key(bytes, passphrase)
}

/// Parses one binary OpenSSH private-key file.
///
/// This is a short compatibility spelling of
/// [`parse_openssh_private_key`].
///
/// # Errors
///
/// Returns the same errors as [`parse_openssh_private_key`].
pub fn parse_openssh_key(
    bytes: &[u8],
    passphrase: &mut [u8],
) -> Result<OpenSshPrivateKey, OpenSshKeyError> {
    parse_openssh_private_key(bytes, passphrase)
}

/// Parses one binary OpenSSH private-key file.
///
/// This is a short compatibility spelling of
/// [`parse_openssh_private_key`].
///
/// # Errors
///
/// Returns the same errors as [`parse_openssh_private_key`].
pub fn parse(bytes: &[u8], passphrase: &mut [u8]) -> Result<OpenSshPrivateKey, OpenSshKeyError> {
    parse_openssh_private_key(bytes, passphrase)
}

#[derive(Clone, Copy)]
enum ProtectionCipher {
    None,
    Aes256Ctr,
}

#[derive(Clone, Copy)]
enum ProtectionKdf {
    None,
    Bcrypt,
}

enum Protection {
    None,
    Aes256Ctr { salt: Vec<u8>, rounds: u32 },
}

enum PublicKeyMaterial {
    Ed25519([u8; ED25519_SEED_LENGTH]),
    Ecdsa {
        point: Vec<u8>,
        secret: Option<Zeroizing<[u8; ECDSA_SECRET_SCALAR_LENGTH]>>,
    },
    Rsa {
        e: Vec<u8>,
        n: Vec<u8>,
    },
}

enum ParsedPrivate {
    Ed25519 {
        seed: Zeroizing<[u8; ED25519_SEED_LENGTH]>,
    },
    Ecdsa {
        secret: Zeroizing<[u8; ECDSA_SECRET_SCALAR_LENGTH]>,
    },
    Rsa {
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
        e: Zeroizing<Vec<u8>>,
    },
}

struct PassphraseGuard<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PassphraseGuard<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

impl Drop for PassphraseGuard<'_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn parse_bcrypt_options(options: &[u8]) -> Result<(Vec<u8>, u32), OpenSshKeyError> {
    let mut reader = Reader::new(options);
    let salt = read_string_bytes(&mut reader)?;
    let rounds = read_uint32(&mut reader)?;
    if !reader.is_empty() {
        return Err(OpenSshKeyError::InvalidKdfOptions);
    }
    Ok((salt, rounds))
}

fn decrypt_private_section(
    private_section: &mut [u8],
    salt: &[u8],
    rounds: u32,
    passphrase: &[u8],
) -> Result<(), OpenSshKeyError> {
    let passphrase_copy = Zeroizing::new(passphrase.to_vec());
    let derived = Zeroizing::new(
        openssh_bcrypt::derive_key(passphrase_copy.as_slice(), salt, rounds, DERIVED_KEY_LENGTH)
            .map_err(map_bcrypt_error)?,
    );
    let key_bytes = derived
        .get(..32)
        .ok_or(OpenSshKeyError::InvalidKdfOptions)?;
    let iv_bytes = derived
        .get(32..48)
        .ok_or(OpenSshKeyError::InvalidKdfOptions)?;
    let key = Zeroizing::new(key_bytes.to_vec());
    let iv = Zeroizing::new(iv_bytes.to_vec());

    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key.as_slice(), iv.as_slice())
        .map_err(|_error| OpenSshKeyError::InvalidCipherBlockSize)?;
    cipher.apply_keystream(private_section);
    Ok(())
}

fn map_bcrypt_error(error: OpenSshBcryptError) -> OpenSshKeyError {
    match error {
        OpenSshBcryptError::EmptyPassword => OpenSshKeyError::WrongPassphrase,
        OpenSshBcryptError::PasswordTooLong
        | OpenSshBcryptError::InvalidRounds
        | OpenSshBcryptError::InvalidSalt
        | OpenSshBcryptError::InvalidOutputLength => OpenSshKeyError::InvalidKdfOptions,
    }
}

fn parse_public_blob(blob: &[u8]) -> Result<PublicKeyMaterial, OpenSshKeyError> {
    let mut reader = Reader::new(blob);
    let key_type = read_public_string(&mut reader)?;
    let material = match key_type {
        value if value == SSH_ED25519 => {
            let point = read_public_string(&mut reader)?;
            let point = point
                .try_into()
                .map_err(|_| OpenSshKeyError::InvalidPublicKey)?;
            PublicKeyMaterial::Ed25519(point)
        }
        value if value == SSH_RSA => {
            let e = read_positive_public_mpint(&mut reader)?.to_vec();
            let n = read_positive_public_mpint(&mut reader)?.to_vec();
            PublicKeyMaterial::Rsa { e, n }
        }
        value if value == SSH_ECDSA_SHA2_NISTP256 => {
            // The curve name is a second string in an `ecdsa-sha2-*` blob. Only
            // P-256 is accepted, because it is the only curve whose signer
            // exists; a key on another curve is reported as unsupported rather
            // than parsed into something that could be handed to a signer.
            let curve = read_public_string(&mut reader)?;
            if curve != ECDSA_CURVE_NISTP256 {
                return Err(OpenSshKeyError::UnsupportedKeyType);
            }
            let point = read_public_string(&mut reader)?.to_vec();
            PublicKeyMaterial::Ecdsa {
                point,
                secret: None,
            }
        }
        _ => return Err(OpenSshKeyError::UnsupportedKeyType),
    };
    if !reader.is_empty() {
        return Err(OpenSshKeyError::InvalidPublicKey);
    }
    Ok(material)
}

fn parse_private_section(
    bytes: &[u8],
    block_size: usize,
    public_material: PublicKeyMaterial,
    public_blob: Vec<u8>,
) -> Result<OpenSshPrivateKey, OpenSshKeyError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(block_size) {
        return Err(OpenSshKeyError::InvalidCipherBlockSize);
    }

    let mut reader = Reader::new(bytes);
    let first_check = read_uint32(&mut reader)?;
    let second_check = read_uint32(&mut reader)?;
    if first_check != second_check {
        return Err(OpenSshKeyError::WrongPassphrase);
    }

    let key_type = read_string(&mut reader)?;
    let private = match key_type {
        value if value == SSH_ED25519 => match public_material {
            PublicKeyMaterial::Ed25519(outer_public) => {
                parse_ed25519_private(&mut reader, &outer_public)?
            }
            PublicKeyMaterial::Ecdsa { .. } | PublicKeyMaterial::Rsa { .. } => {
                return Err(OpenSshKeyError::PublicKeyMismatch);
            }
        },
        value if value == SSH_ECDSA_SHA2_NISTP256 => match public_material {
            PublicKeyMaterial::Ecdsa { point, .. } => {
                parse_ecdsa_private(&mut reader, &point, &public_blob)?
            }
            PublicKeyMaterial::Ed25519(_) | PublicKeyMaterial::Rsa { .. } => {
                return Err(OpenSshKeyError::PublicKeyMismatch);
            }
        },
        value if value == SSH_RSA => match public_material {
            PublicKeyMaterial::Rsa { e, n } => parse_rsa_private(&mut reader, &e, &n)?,
            PublicKeyMaterial::Ed25519(_) | PublicKeyMaterial::Ecdsa { .. } => {
                return Err(OpenSshKeyError::PublicKeyMismatch);
            }
        },
        _ => return Err(OpenSshKeyError::UnsupportedKeyType),
    };

    let comment = read_string_bytes(&mut reader)?;
    if !valid_padding(reader.remaining(), block_size) {
        return Err(OpenSshKeyError::InvalidPadding);
    }

    match private {
        ParsedPrivate::Ed25519 { seed } => Ok(OpenSshPrivateKey::Ed25519 {
            seed,
            public_blob,
            comment,
        }),
        ParsedPrivate::Ecdsa { secret } => Ok(OpenSshPrivateKey::Ecdsa {
            secret,
            public_blob,
            comment,
        }),
        ParsedPrivate::Rsa { p, q, e } => Ok(OpenSshPrivateKey::Rsa {
            p,
            q,
            e,
            public_blob,
            comment,
        }),
    }
}

fn parse_ed25519_private(
    reader: &mut Reader<'_>,
    outer_public: &[u8; ED25519_SEED_LENGTH],
) -> Result<ParsedPrivate, OpenSshKeyError> {
    let declared_public = read_string(reader)?;
    let declared_public: [u8; ED25519_SEED_LENGTH] = declared_public
        .try_into()
        .map_err(|_| OpenSshKeyError::InvalidPrivateKey)?;
    if declared_public != *outer_public {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }
    let private = read_string(reader)?;
    if private.len() != ED25519_PRIVATE_LENGTH {
        return Err(OpenSshKeyError::InvalidPrivateKey);
    }
    let private_public = private
        .get(ED25519_SEED_LENGTH..ED25519_PRIVATE_LENGTH)
        .ok_or(OpenSshKeyError::InvalidPrivateKey)?;
    if private_public != declared_public.as_slice() {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }
    let seed_bytes = private
        .get(..ED25519_SEED_LENGTH)
        .ok_or(OpenSshKeyError::InvalidPrivateKey)?;
    let mut seed = Zeroizing::new([0_u8; ED25519_SEED_LENGTH]);
    seed.copy_from_slice(seed_bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    let derived_public = signing_key.verifying_key().to_bytes();
    if derived_public != declared_public {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }
    Ok(ParsedPrivate::Ed25519 { seed })
}

/// Parses the `ecdsa-sha2-nistp256` private fields and checks them.
///
/// The private section repeats the curve name and the uncompressed public point
/// before the secret. The point is checked against the secret rather than
/// trusted, because a public key that does not match its private scalar is a
/// container that would authenticate as a different identity than the one named,
/// and the cheapest place to catch that is here. The comparison is against the
/// blob `EcdsaSigner` itself produces, so it checks the same encoder that will
/// later sign rather than a re-derivation of the point.
fn parse_ecdsa_private(
    reader: &mut Reader<'_>,
    outer_point: &[u8],
    public_blob: &[u8],
) -> Result<ParsedPrivate, OpenSshKeyError> {
    let curve = read_string(reader)?;
    if curve != ECDSA_CURVE_NISTP256 {
        return Err(OpenSshKeyError::UnsupportedKeyType);
    }
    let declared_point = read_string_bytes(reader)?;
    if declared_point != outer_point {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }
    let scalar = read_positive_mpint(reader)?;
    let mut secret = Zeroizing::new([0_u8; ECDSA_SECRET_SCALAR_LENGTH]);
    if scalar.len() > ECDSA_SECRET_SCALAR_LENGTH {
        return Err(OpenSshKeyError::InvalidPrivateKey);
    }
    let scalar_start = ECDSA_SECRET_SCALAR_LENGTH - scalar.len();
    secret[scalar_start..].copy_from_slice(scalar);
    let signer = EcdsaSigner::from_secret_scalar_bytes(&secret)
        .map_err(|_error| OpenSshKeyError::InvalidPrivateKey)?;
    let derived = signer
        .public_key_blob()
        .map_err(|_error| OpenSshKeyError::InvalidPrivateKey)?;
    if derived != public_blob {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }
    Ok(ParsedPrivate::Ecdsa { secret })
}

fn parse_rsa_private(
    reader: &mut Reader<'_>,
    outer_e: &[u8],
    outer_n: &[u8],
) -> Result<ParsedPrivate, OpenSshKeyError> {
    let n_bytes = read_positive_mpint(reader)?;
    let e_bytes = read_positive_mpint(reader)?;
    let _private_exponent = read_positive_mpint(reader)?;
    let _coefficient = read_positive_mpint(reader)?;
    let p_bytes = read_positive_mpint(reader)?;
    let q_bytes = read_positive_mpint(reader)?;

    let n = Zeroizing::new(rsa::BigUint::from_bytes_be(n_bytes));
    let e = Zeroizing::new(rsa::BigUint::from_bytes_be(e_bytes));
    let p = Zeroizing::new(rsa::BigUint::from_bytes_be(p_bytes));
    let q = Zeroizing::new(rsa::BigUint::from_bytes_be(q_bytes));
    if p == q || &*p * &*q != *n {
        return Err(OpenSshKeyError::InvalidPrivateKey);
    }

    let outer_n = rsa::BigUint::from_bytes_be(outer_n);
    let outer_e = rsa::BigUint::from_bytes_be(outer_e);
    if outer_n != *n || outer_e != *e {
        return Err(OpenSshKeyError::PublicKeyMismatch);
    }

    Ok(ParsedPrivate::Rsa {
        p: Zeroizing::new(p_bytes.to_vec()),
        q: Zeroizing::new(q_bytes.to_vec()),
        e: Zeroizing::new(e_bytes.to_vec()),
    })
}

fn read_string<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], OpenSshKeyError> {
    reader
        .read_string()
        .map_err(|_error| OpenSshKeyError::Malformed)
}

fn read_string_bytes(reader: &mut Reader<'_>) -> Result<Vec<u8>, OpenSshKeyError> {
    reader
        .read_string_bytes()
        .map_err(|_error| OpenSshKeyError::Malformed)
}

fn read_uint32(reader: &mut Reader<'_>) -> Result<u32, OpenSshKeyError> {
    reader
        .read_uint32()
        .map_err(|_error| OpenSshKeyError::Malformed)
}

fn read_public_string<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], OpenSshKeyError> {
    reader
        .read_string()
        .map_err(|_error| OpenSshKeyError::InvalidPublicKey)
}

fn read_positive_public_mpint<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], OpenSshKeyError> {
    let value = reader
        .read_mpint()
        .map_err(|_error| OpenSshKeyError::InvalidPublicKey)?;
    positive_magnitude(value).ok_or(OpenSshKeyError::InvalidPublicKey)
}

fn read_positive_mpint<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], OpenSshKeyError> {
    let value = reader
        .read_mpint()
        .map_err(|_error| OpenSshKeyError::InvalidPrivateKey)?;
    positive_magnitude(value).ok_or(OpenSshKeyError::InvalidPrivateKey)
}

fn positive_magnitude(value: &[u8]) -> Option<&[u8]> {
    let first = *value.first()?;
    if first & 0x80 != 0 {
        return None;
    }
    let magnitude = if value.len() > 1 && first == 0 {
        value.get(1..)?
    } else {
        value
    };
    if magnitude.is_empty() || magnitude.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(magnitude)
    }
}

fn valid_padding(padding: &[u8], block_size: usize) -> bool {
    // OpenSSH adds padding only while the private section is not block-aligned;
    // an already aligned section therefore has no padding bytes.
    if padding.len() > block_size {
        return false;
    }
    padding
        .iter()
        .enumerate()
        .all(|(index, byte)| u8::try_from(index + 1).is_ok_and(|expected| expected == *byte))
}

fn encode_ed25519_blob(point: &[u8; ED25519_SEED_LENGTH]) -> Result<Vec<u8>, OpenSshKeyError> {
    let mut writer = Writer::new();
    writer
        .write_string(SSH_ED25519)
        .map_err(|_error| OpenSshKeyError::InvalidPublicKey)?;
    writer
        .write_string(point)
        .map_err(|_error| OpenSshKeyError::InvalidPublicKey)?;
    Ok(writer.into_bytes())
}

fn _wire_error_type_is_static(_: Option<WireError>) {}

#[cfg(test)]
mod tests {
    use super::{
        ED25519_SEED_LENGTH, OpenSshKeyError, OpenSshPrivateKey, parse_openssh_private_key,
        valid_padding,
    };
    use ed25519_dalek::SigningKey;
    use neotales_ssh::Writer;

    #[test]
    fn rejects_bad_magic() {
        let mut passphrase = [0_u8; 4];
        assert_eq!(
            parse_openssh_private_key(b"not-an-openssh-key", &mut passphrase).err(),
            Some(OpenSshKeyError::InvalidMagic)
        );
        assert_eq!(passphrase, [0_u8; 4]);
    }

    #[test]
    fn accepts_empty_padding_and_valid_incrementing_padding() {
        assert!(valid_padding(&[], 8));
        assert!(valid_padding(&[1, 2, 3], 8));
        assert!(!valid_padding(&[1, 3], 8));
        assert!(!valid_padding(&[1; 9], 8));
    }

    #[test]
    fn accepts_a_minimal_ed25519_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let seed = [7_u8; ED25519_SEED_LENGTH];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let public_blob = {
            let mut writer = Writer::new();
            writer.write_string("ssh-ed25519")?;
            writer.write_string(&public)?;
            writer.into_bytes()
        };
        let private = {
            let mut writer = Writer::new();
            writer.write_uint32(9);
            writer.write_uint32(9);
            writer.write_string("ssh-ed25519")?;
            writer.write_string(&public)?;
            let mut secret = seed.to_vec();
            secret.extend_from_slice(&public);
            writer.write_string(&secret)?;
            // This length makes the unpadded private section block-aligned.
            writer.write_string(b"comment123456")?;
            writer.into_bytes()
        };
        let mut input = b"openssh-key-v1\0".to_vec();
        input.extend_from_slice(&ssh_string(b"none"));
        input.extend_from_slice(&ssh_string(b"none"));
        input.extend_from_slice(&ssh_string(&[]));
        input.extend_from_slice(&1_u32.to_be_bytes());
        input.extend_from_slice(&ssh_string(&public_blob));
        let mut padded = private;
        let padding_length = (8 - (padded.len() % 8)) % 8;
        for value in 1..=padding_length {
            padded.push(u8::try_from(value).expect("fixture padding should fit in a byte"));
        }
        input.extend_from_slice(&ssh_string(&padded));

        let mut passphrase = [0_u8; 3];
        let parsed = parse_openssh_private_key(&input, &mut passphrase)?;
        let OpenSshPrivateKey::Ed25519 {
            seed: parsed_seed,
            public_blob: parsed_blob,
            comment,
        } = parsed
        else {
            return Err("unexpected key type".into());
        };
        assert_eq!(parsed_seed.as_slice(), seed);
        assert_eq!(parsed_blob, public_blob);
        assert_eq!(comment, b"comment123456");
        Ok(())
    }

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let mut result = u32::try_from(value.len())
            .expect("test SSH value should fit in a uint32")
            .to_be_bytes()
            .to_vec();
        result.extend_from_slice(value);
        result
    }
}
