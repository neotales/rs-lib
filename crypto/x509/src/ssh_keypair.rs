//! Conversion of SSH key pairs into X.509 and PKCS#8 objects.

use core::convert::TryFrom;

use aes::cipher::{KeyIvInit as _, StreamCipher as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::pkcs8::{
    DecodePrivateKey as EdDecodePrivateKey, EncodePrivateKey as EdEncodePrivateKey,
    EncodePublicKey as EdEncodePublicKey,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::{openssh_bcrypt, pem};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs8::{
    DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _, PrivateKeyInfo, Version,
};
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const OPENSSH_CIPHER_NONE: &[u8] = b"none";
const OPENSSH_CIPHER_AES256_CTR: &[u8] = b"aes256-ctr";
const OPENSSH_KDF_NONE: &[u8] = b"none";
const OPENSSH_KDF_BCRYPT: &[u8] = b"bcrypt";
const OPENSSH_P256_CURVE: &[u8] = b"nistp256";

const SSH_RSA: &[u8] = b"ssh-rsa";
const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSH_ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256";

const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_CURVE_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const ED25519_SEED_LENGTH: usize = 32;
const ED25519_SECRET_LENGTH: usize = 64;
const P256_PRIVATE_SCALAR_LENGTH: usize = 32;
const P256_POINT_LENGTH: usize = 65;
const NONE_BLOCK_SIZE: usize = 8;
const AES_BLOCK_SIZE: usize = 16;
const OPENSSH_DERIVED_KEY_LENGTH: usize = 48;
const MAX_OPENSSH_ENCODED_LENGTH: usize = pem::MAXIMUM_DECODED_LENGTH.div_ceil(3) * 4;

/// The generated X.509 certificate, PKCS#8 private key, and public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509KeyPair {
    /// The self-signed X.509 certificate in DER form.
    pub certificate_der: Vec<u8>,
    /// The self-signed X.509 certificate in PEM form.
    pub certificate_pem: String,
    /// The unencrypted PKCS#8 private key in DER form.
    ///
    /// Dropping the key pair wipes this buffer.
    pub private_key_der: Zeroizing<Vec<u8>>,
    /// The unencrypted PKCS#8 private key in PEM form.
    ///
    /// Dropping the key pair wipes this string.
    pub private_key_pem: Zeroizing<String>,
    /// The SubjectPublicKeyInfo public key in DER form.
    pub public_key_der: Vec<u8>,
    /// The SubjectPublicKeyInfo public key in PEM form.
    pub public_key_pem: String,
}

/// Certificate metadata for an SSH-to-X.509 conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshKeyToX509 {
    /// The certificate subject common name.
    pub common_name: String,
    /// The inclusive certificate validity start, in Unix seconds.
    pub not_before_unix: i64,
    /// The exclusive certificate validity end, in Unix seconds.
    pub not_after_unix: i64,
}

/// An error converting an SSH key pair into X.509 and PKCS#8 objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshKeyError {
    /// The private key is malformed or internally inconsistent.
    InvalidPrivateKey,
    /// The authorized-key public line is malformed.
    InvalidPublicKey,
    /// The private and public keys do not identify the same key pair.
    KeyMismatch,
    /// The OpenSSH private key is encrypted or cannot be decrypted.
    EncryptedKey,
    /// A private-key, public-key, cipher, or KDF algorithm is unsupported.
    UnsupportedAlgorithm,
    /// The certificate subject or validity request is invalid.
    InvalidCertificateRequest,
}

impl std::fmt::Display for SshKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPrivateKey => "invalid SSH private key",
            Self::InvalidPublicKey => "invalid SSH public key",
            Self::KeyMismatch => "SSH private and public keys do not match",
            Self::EncryptedKey => "encrypted SSH private key could not be decrypted",
            Self::UnsupportedAlgorithm => "unsupported SSH key or encryption algorithm",
            Self::InvalidCertificateRequest => "invalid X.509 certificate request",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SshKeyError {}

/// Converts an SSH private key and matching authorized-key line into X.509.
///
/// The private key may use the OpenSSH v1 container, PKCS#1 RSA, or PKCS#8
/// Ed25519, RSA, or NIST P-256. OpenSSH private keys may be unencrypted or
/// encrypted with bcrypt key derivation and AES-256-CTR. The resulting
/// certificate is self-signed by the converted private key.
///
/// # Errors
///
/// Returns [`SshKeyError`] when private or public key parsing fails, an
/// encrypted key cannot be decrypted, the keys do not match, the algorithm is
/// unsupported, or the certificate request is invalid.
pub fn ssh_keypair_to_x509(
    private_key: &str,
    public_key: &str,
    request: &SshKeyToX509,
    passphrase: Option<&[u8]>,
) -> Result<X509KeyPair, SshKeyError> {
    if request.not_after_unix <= request.not_before_unix {
        return Err(SshKeyError::InvalidCertificateRequest);
    }
    let not_before = OffsetDateTime::from_unix_timestamp(request.not_before_unix)
        .map_err(|_| SshKeyError::InvalidCertificateRequest)?;
    let not_after = OffsetDateTime::from_unix_timestamp(request.not_after_unix)
        .map_err(|_| SshKeyError::InvalidCertificateRequest)?;

    let private = parse_private_key(private_key, passphrase)?;
    let public = parse_authorized_public_key(public_key)?;
    let derived_public = private.public_key()?;
    if derived_public != public {
        return Err(SshKeyError::KeyMismatch);
    }

    let (private_key_der, public_key_der) = private.encoded_key_pair()?;
    let private_key_der = Zeroizing::new(private_key_der);
    let private_key_pem = Zeroizing::new(
        pem::encode("PRIVATE KEY", &private_key_der).map_err(|_| SshKeyError::InvalidPrivateKey)?,
    );
    let public_key_pem =
        pem::encode("PUBLIC KEY", &public_key_der).map_err(|_| SshKeyError::InvalidPublicKey)?;

    let signing_key = Zeroizing::new(
        KeyPair::from_pem(&private_key_pem).map_err(|_| SshKeyError::InvalidPrivateKey)?,
    );
    let mut certificate_params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, request.common_name.clone());
    certificate_params.distinguished_name = distinguished_name;
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_after;
    let certificate = certificate_params
        .self_signed(&*signing_key)
        .map_err(|_| SshKeyError::InvalidCertificateRequest)?;
    let certificate_der = certificate.der().as_ref().to_vec();
    let certificate_pem = pem::encode("CERTIFICATE", &certificate_der)
        .map_err(|_| SshKeyError::InvalidCertificateRequest)?;

    Ok(X509KeyPair {
        certificate_der,
        certificate_pem,
        private_key_der,
        private_key_pem,
        public_key_der,
        public_key_pem,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PublicKeyMaterial {
    Ed25519([u8; ED25519_SEED_LENGTH]),
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    P256([u8; P256_POINT_LENGTH]),
}

impl PublicKeyMaterial {
    fn key_type(&self) -> &'static [u8] {
        match self {
            Self::Ed25519(_) => SSH_ED25519,
            Self::Rsa { .. } => SSH_RSA,
            Self::P256(_) => SSH_ECDSA_P256,
        }
    }
}

enum ParsedPrivateKey {
    Ed25519(SigningKey),
    Rsa(RsaPrivateKey),
    P256(P256SecretKey),
}

impl ParsedPrivateKey {
    fn public_key(&self) -> Result<PublicKeyMaterial, SshKeyError> {
        match self {
            Self::Ed25519(key) => Ok(PublicKeyMaterial::Ed25519(key.verifying_key().to_bytes())),
            Self::Rsa(key) => {
                let public = key.to_public_key();
                Ok(rsa_public_key_material(&public))
            }
            Self::P256(key) => {
                let public = key.public_key();
                p256_public_key_material(&public)
            }
        }
    }

    fn encoded_key_pair(&self) -> Result<(Vec<u8>, Vec<u8>), SshKeyError> {
        match self {
            Self::Ed25519(key) => {
                let private = key
                    .to_pkcs8_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                let public = key
                    .verifying_key()
                    .to_public_key_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                Ok((private.as_bytes().to_vec(), public.as_bytes().to_vec()))
            }
            Self::Rsa(key) => {
                let private = key
                    .to_pkcs8_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                let public = key
                    .to_public_key()
                    .to_public_key_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                Ok((private.as_bytes().to_vec(), public.as_bytes().to_vec()))
            }
            Self::P256(key) => {
                let private = key
                    .to_pkcs8_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                let public = key
                    .public_key()
                    .to_public_key_der()
                    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
                Ok((private.as_bytes().to_vec(), public.as_bytes().to_vec()))
            }
        }
    }
}

fn parse_private_key(
    private_key: &str,
    passphrase: Option<&[u8]>,
) -> Result<ParsedPrivateKey, SshKeyError> {
    if let Ok(openssh) = decode_openssh_pem(private_key) {
        return parse_openssh_private(openssh.as_slice(), passphrase);
    }

    if let Ok(pkcs1) = pem::decode_der(private_key, "RSA PRIVATE KEY") {
        return parse_pkcs1_private(&Zeroizing::new(pkcs1));
    }
    if let Ok(pkcs8) = pem::decode_der(private_key, "PRIVATE KEY") {
        return parse_pkcs8_private(&Zeroizing::new(pkcs8));
    }

    Err(SshKeyError::InvalidPrivateKey)
}

fn parse_pkcs1_private(der: &Zeroizing<Vec<u8>>) -> Result<ParsedPrivateKey, SshKeyError> {
    let key = RsaPrivateKey::from_pkcs1_der(der.as_slice())
        .map_err(|_| SshKeyError::InvalidPrivateKey)?;
    Ok(ParsedPrivateKey::Rsa(key))
}

fn parse_pkcs8_private(der: &Zeroizing<Vec<u8>>) -> Result<ParsedPrivateKey, SshKeyError> {
    let info =
        PrivateKeyInfo::try_from(der.as_slice()).map_err(|_| SshKeyError::InvalidPrivateKey)?;
    let oid = info.algorithm.oid.as_bytes();

    if oid == ED25519_OID {
        if info.version() != Version::V1 {
            return Err(SshKeyError::InvalidPrivateKey);
        }
        let key = SigningKey::from_pkcs8_der(der.as_slice())
            .map_err(|_| SshKeyError::InvalidPrivateKey)?;
        return Ok(ParsedPrivateKey::Ed25519(key));
    }

    if oid == RSA_OID {
        let key = RsaPrivateKey::from_pkcs8_der(der.as_slice())
            .map_err(|_| SshKeyError::InvalidPrivateKey)?;
        return Ok(ParsedPrivateKey::Rsa(key));
    }

    if oid == EC_OID {
        let curve = info
            .algorithm
            .parameters_oid()
            .map_err(|_| SshKeyError::InvalidPrivateKey)?;
        if curve.as_bytes() != P256_CURVE_OID {
            return Err(SshKeyError::UnsupportedAlgorithm);
        }
        let key = P256SecretKey::from_pkcs8_der(der.as_slice())
            .map_err(|_| SshKeyError::InvalidPrivateKey)?;
        return Ok(ParsedPrivateKey::P256(key));
    }

    Err(SshKeyError::UnsupportedAlgorithm)
}

#[derive(Clone, Copy)]
enum OpenSshCipher {
    None,
    Aes256Ctr,
}

#[derive(Clone, Copy)]
enum OpenSshKdf {
    None,
    Bcrypt,
}

enum OpenSshProtection {
    None,
    Aes256Ctr { salt: Vec<u8>, rounds: u32 },
}

fn parse_openssh_private(
    blob: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<ParsedPrivateKey, SshKeyError> {
    let mut reader = SshReader::new(blob);
    if reader.read_exact(OPENSSH_MAGIC.len()) != Some(OPENSSH_MAGIC) {
        return Err(SshKeyError::InvalidPrivateKey);
    }

    let cipher_name = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let cipher = match cipher_name {
        value if value == OPENSSH_CIPHER_NONE => OpenSshCipher::None,
        value if value == OPENSSH_CIPHER_AES256_CTR => OpenSshCipher::Aes256Ctr,
        _ => return Err(SshKeyError::UnsupportedAlgorithm),
    };

    let kdf_name = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let kdf = match kdf_name {
        value if value == OPENSSH_KDF_NONE => OpenSshKdf::None,
        value if value == OPENSSH_KDF_BCRYPT => OpenSshKdf::Bcrypt,
        _ => return Err(SshKeyError::UnsupportedAlgorithm),
    };

    let kdf_options = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let protection = match (cipher, kdf) {
        (OpenSshCipher::None, OpenSshKdf::None) => {
            if kdf_options.is_empty() {
                OpenSshProtection::None
            } else {
                return Err(SshKeyError::InvalidPrivateKey);
            }
        }
        (OpenSshCipher::Aes256Ctr, OpenSshKdf::Bcrypt) => {
            let mut options = SshReader::new(kdf_options);
            let salt = options
                .read_string()
                .ok_or(SshKeyError::InvalidPrivateKey)?
                .to_vec();
            let rounds = options.read_u32().ok_or(SshKeyError::InvalidPrivateKey)?;
            if !options.is_empty() {
                return Err(SshKeyError::InvalidPrivateKey);
            }
            OpenSshProtection::Aes256Ctr { salt, rounds }
        }
        _ => return Err(SshKeyError::UnsupportedAlgorithm),
    };

    let key_count = reader.read_u32().ok_or(SshKeyError::InvalidPrivateKey)?;
    if key_count != 1 {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let public_blob = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let embedded_public = parse_public_blob(public_blob).map_err(|error| match error {
        PublicBlobError::Invalid => SshKeyError::InvalidPrivateKey,
        PublicBlobError::Unsupported => SshKeyError::UnsupportedAlgorithm,
    })?;
    let private_block = Zeroizing::new(
        reader
            .read_string()
            .ok_or(SshKeyError::InvalidPrivateKey)?
            .to_vec(),
    );
    if !reader.is_empty() {
        return Err(SshKeyError::InvalidPrivateKey);
    }

    match protection {
        OpenSshProtection::None => {
            let private =
                parse_openssh_private_section(private_block.as_slice(), NONE_BLOCK_SIZE, false)?;
            if private.public_key()? != embedded_public {
                return Err(SshKeyError::KeyMismatch);
            }
            Ok(private)
        }
        OpenSshProtection::Aes256Ctr { salt, rounds } => {
            let passphrase = passphrase.ok_or(SshKeyError::EncryptedKey)?;
            let derived = Zeroizing::new(
                openssh_bcrypt::derive_key(passphrase, &salt, rounds, OPENSSH_DERIVED_KEY_LENGTH)
                    .map_err(|_| SshKeyError::EncryptedKey)?,
            );
            let key_bytes = derived.get(..32).ok_or(SshKeyError::EncryptedKey)?;
            let iv_bytes = derived.get(32..).ok_or(SshKeyError::EncryptedKey)?;
            let key = Zeroizing::new(
                copy_array::<32>(key_bytes).map_err(|()| SshKeyError::EncryptedKey)?,
            );
            let iv =
                Zeroizing::new(copy_array::<16>(iv_bytes).map_err(|()| SshKeyError::EncryptedKey)?);

            let mut decrypted = Zeroizing::new(private_block.as_slice().to_vec());
            if decrypted.len() % AES_BLOCK_SIZE != 0 {
                return Err(SshKeyError::EncryptedKey);
            }
            let mut stream = ctr::Ctr128BE::<aes::Aes256>::new((&*key).into(), (&*iv).into());
            stream.apply_keystream(decrypted.as_mut_slice());
            let private =
                parse_openssh_private_section(decrypted.as_slice(), AES_BLOCK_SIZE, true)?;
            if private.public_key()? != embedded_public {
                return Err(SshKeyError::KeyMismatch);
            }
            Ok(private)
        }
    }
}

fn parse_openssh_private_section(
    bytes: &[u8],
    block_size: usize,
    encrypted: bool,
) -> Result<ParsedPrivateKey, SshKeyError> {
    let mut reader = SshReader::new(bytes);
    let initial_error = if encrypted {
        SshKeyError::EncryptedKey
    } else {
        SshKeyError::InvalidPrivateKey
    };
    let first_check = reader.read_u32().ok_or(initial_error)?;
    let second_check = reader.read_u32().ok_or(initial_error)?;
    if !bool::from(first_check.ct_eq(&second_check)) {
        return Err(initial_error);
    }

    let key_type = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let key = match key_type {
        value if value == SSH_ED25519 => parse_openssh_ed25519(&mut reader, encrypted)?,
        value if value == SSH_RSA => parse_openssh_rsa(&mut reader)?,
        value if value == SSH_ECDSA_P256 => parse_openssh_p256(&mut reader)?,
        _ => return Err(SshKeyError::UnsupportedAlgorithm),
    };

    reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    if !valid_padding(reader.remaining(), block_size) {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    Ok(key)
}

fn parse_openssh_ed25519(
    reader: &mut SshReader<'_>,
    encrypted: bool,
) -> Result<ParsedPrivateKey, SshKeyError> {
    let declared_public =
        copy_array::<32>(reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?)
            .map_err(|()| SshKeyError::InvalidPrivateKey)?;
    let secret = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    if secret.len() != ED25519_SECRET_LENGTH {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let seed_bytes = secret
        .get(..ED25519_SEED_LENGTH)
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    let secret_public = secret
        .get(ED25519_SEED_LENGTH..)
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    if secret_public != declared_public {
        return Err(SshKeyError::KeyMismatch);
    }

    let mut seed = Zeroizing::new([0_u8; ED25519_SEED_LENGTH]);
    seed.copy_from_slice(seed_bytes);
    let key = SigningKey::from_bytes(&seed);
    let derived_public = key.verifying_key().to_bytes();
    if derived_public != declared_public {
        return Err(if encrypted {
            SshKeyError::EncryptedKey
        } else {
            SshKeyError::KeyMismatch
        });
    }
    Ok(ParsedPrivateKey::Ed25519(key))
}

fn parse_openssh_rsa(reader: &mut SshReader<'_>) -> Result<ParsedPrivateKey, SshKeyError> {
    let modulus = read_private_mpint(reader)?;
    let exponent = read_private_mpint(reader)?;
    let private_exponent = read_private_mpint(reader)?;
    let inverse_q_mod_p = read_private_mpint(reader)?;
    let prime1 = read_private_mpint(reader)?;
    let prime2 = read_private_mpint(reader)?;

    let key = RsaPrivateKey::from_components(
        (*modulus).clone(),
        (*exponent).clone(),
        (*private_exponent).clone(),
        vec![(*prime1).clone(), (*prime2).clone()],
    )
    .map_err(|_| SshKeyError::InvalidPrivateKey)?;
    let coefficient = key.qinv().ok_or(SshKeyError::InvalidPrivateKey)?;
    let coefficient = coefficient
        .to_biguint()
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    let coefficient = Zeroizing::new(coefficient);
    // The coefficient is private; use the public modulus width for a
    // fixed-size comparison.
    let modulus_len = key.n().to_bytes_be().len();
    if !big_uints_equal_constant_time(&coefficient, &inverse_q_mod_p, modulus_len) {
        return Err(SshKeyError::InvalidPrivateKey);
    }

    Ok(ParsedPrivateKey::Rsa(key))
}

fn big_uints_equal_constant_time(left: &BigUint, right: &BigUint, width: usize) -> bool {
    if width == 0 {
        return false;
    }
    let left_bytes = Zeroizing::new(left.to_bytes_be());
    let right_bytes = Zeroizing::new(right.to_bytes_be());
    let Some(left_offset) = width.checked_sub(left_bytes.len()) else {
        return false;
    };
    let Some(right_offset) = width.checked_sub(right_bytes.len()) else {
        return false;
    };

    let mut left_padded = Zeroizing::new(vec![0u8; width]);
    let mut right_padded = Zeroizing::new(vec![0u8; width]);
    let Some(left_destination) = left_padded.as_mut_slice().get_mut(left_offset..) else {
        return false;
    };
    let Some(right_destination) = right_padded.as_mut_slice().get_mut(right_offset..) else {
        return false;
    };
    left_destination.copy_from_slice(left_bytes.as_slice());
    right_destination.copy_from_slice(right_bytes.as_slice());
    bool::from(left_padded.as_slice().ct_eq(right_padded.as_slice()))
}

fn parse_openssh_p256(reader: &mut SshReader<'_>) -> Result<ParsedPrivateKey, SshKeyError> {
    let curve = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    if curve != OPENSSH_P256_CURVE {
        return Err(SshKeyError::UnsupportedAlgorithm);
    }
    let declared_point = reader.read_string().ok_or(SshKeyError::InvalidPrivateKey)?;
    let public_key = P256PublicKey::from_sec1_bytes(declared_point)
        .map_err(|_| SshKeyError::InvalidPrivateKey)?;
    if declared_point.len() != P256_POINT_LENGTH || declared_point.first() != Some(&0x04) {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let declared_public = p256_public_key_material(&public_key)?;

    let scalar = reader
        .read_positive_mpint()
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    if scalar.len() > P256_PRIVATE_SCALAR_LENGTH {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let mut scalar_bytes = Zeroizing::new([0_u8; P256_PRIVATE_SCALAR_LENGTH]);
    let offset = P256_PRIVATE_SCALAR_LENGTH
        .checked_sub(scalar.len())
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    let destination = scalar_bytes
        .get_mut(offset..)
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    destination.copy_from_slice(scalar);
    let secret_key = P256SecretKey::from_slice(scalar_bytes.as_slice())
        .map_err(|_| SshKeyError::InvalidPrivateKey)?;
    let derived_public = p256_public_key_material(&secret_key.public_key())?;
    if derived_public != declared_public {
        return Err(SshKeyError::KeyMismatch);
    }

    Ok(ParsedPrivateKey::P256(secret_key))
}

fn read_private_mpint(reader: &mut SshReader<'_>) -> Result<Zeroizing<BigUint>, SshKeyError> {
    let bytes = reader
        .read_positive_mpint()
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    Ok(Zeroizing::new(BigUint::from_bytes_be(bytes)))
}

fn parse_authorized_public_key(line: &str) -> Result<PublicKeyMaterial, SshKeyError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        return Err(SshKeyError::InvalidPublicKey);
    }
    let mut fields = trimmed.split_whitespace();
    let key_type = fields.next().ok_or(SshKeyError::InvalidPublicKey)?;
    if key_type != "ssh-rsa" && key_type != "ssh-ed25519" && key_type != "ecdsa-sha2-nistp256" {
        return Err(SshKeyError::UnsupportedAlgorithm);
    }
    let encoded = fields.next().ok_or(SshKeyError::InvalidPublicKey)?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| SshKeyError::InvalidPublicKey)?;
    if blob.is_empty() || blob.len() > pem::MAXIMUM_DECODED_LENGTH {
        return Err(SshKeyError::InvalidPublicKey);
    }
    let public = parse_public_blob(&blob).map_err(|error| match error {
        PublicBlobError::Invalid => SshKeyError::InvalidPublicKey,
        PublicBlobError::Unsupported => SshKeyError::UnsupportedAlgorithm,
    })?;
    if public.key_type() != key_type.as_bytes() {
        return Err(SshKeyError::InvalidPublicKey);
    }
    Ok(public)
}

#[derive(Clone, Copy)]
enum PublicBlobError {
    Invalid,
    Unsupported,
}

fn parse_public_blob(blob: &[u8]) -> Result<PublicKeyMaterial, PublicBlobError> {
    let mut reader = SshReader::new(blob);
    let key_type = reader.read_string().ok_or(PublicBlobError::Invalid)?;
    let public = match key_type {
        value if value == SSH_ED25519 => {
            let bytes = copy_array::<32>(reader.read_string().ok_or(PublicBlobError::Invalid)?)
                .map_err(|()| PublicBlobError::Invalid)?;
            VerifyingKey::from_bytes(&bytes).map_err(|_| PublicBlobError::Invalid)?;
            PublicKeyMaterial::Ed25519(bytes)
        }
        value if value == SSH_RSA => {
            let exponent = reader
                .read_positive_mpint()
                .ok_or(PublicBlobError::Invalid)?;
            let modulus = reader
                .read_positive_mpint()
                .ok_or(PublicBlobError::Invalid)?;
            let key = RsaPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent),
            )
            .map_err(|_| PublicBlobError::Invalid)?;
            rsa_public_key_material(&key)
        }
        value if value == SSH_ECDSA_P256 => {
            let curve = reader.read_string().ok_or(PublicBlobError::Invalid)?;
            if curve == OPENSSH_P256_CURVE {
                let point = reader.read_string().ok_or(PublicBlobError::Invalid)?;
                if point.len() != P256_POINT_LENGTH || point.first() != Some(&0x04) {
                    return Err(PublicBlobError::Invalid);
                }
                let key =
                    P256PublicKey::from_sec1_bytes(point).map_err(|_| PublicBlobError::Invalid)?;
                p256_public_key_material(&key).map_err(|_| PublicBlobError::Invalid)?
            } else {
                return Err(PublicBlobError::Unsupported);
            }
        }
        _ => return Err(PublicBlobError::Unsupported),
    };
    if !reader.is_empty() {
        return Err(PublicBlobError::Invalid);
    }
    Ok(public)
}

fn rsa_public_key_material(key: &RsaPublicKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Rsa {
        modulus: key.n().to_bytes_be(),
        exponent: key.e().to_bytes_be(),
    }
}

fn p256_public_key_material(key: &P256PublicKey) -> Result<PublicKeyMaterial, SshKeyError> {
    let encoded = key.to_sec1_point(false);
    let point = copy_array::<P256_POINT_LENGTH>(encoded.as_bytes())
        .map_err(|()| SshKeyError::InvalidPrivateKey)?;
    Ok(PublicKeyMaterial::P256(point))
}

struct SshReader<'a> {
    remaining: &'a [u8],
}

impl<'a> SshReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn read_exact(&mut self, length: usize) -> Option<&'a [u8]> {
        let value = self.remaining.get(..length)?;
        self.remaining = self.remaining.get(length..)?;
        Some(value)
    }

    fn read_string(&mut self) -> Option<&'a [u8]> {
        let length = self.read_u32()?;
        let length = usize::try_from(length).ok()?;
        let value = self.read_exact(length)?;
        Some(value)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = copy_array(self.read_exact(4)?).ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    fn read_positive_mpint(&mut self) -> Option<&'a [u8]> {
        let encoded = self.read_string()?;
        let first = *encoded.first()?;
        if first & 0x80 != 0 {
            return None;
        }
        if first == 0 {
            let value = encoded.get(1..)?;
            if value.first().is_none_or(|byte| byte & 0x80 == 0) {
                return None;
            }
            return Some(value);
        }
        Some(encoded)
    }

    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn valid_padding(padding: &[u8], block_size: usize) -> bool {
    padding.iter().enumerate().all(|(index, byte)| {
        u8::try_from(index % block_size + 1).is_ok_and(|expected| expected == *byte)
    })
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ()> {
    bytes.try_into().map_err(|_| ())
}

fn decode_openssh_pem(input: &str) -> Result<Zeroizing<Vec<u8>>, SshKeyError> {
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";
    let start = input.find(begin).ok_or(SshKeyError::InvalidPrivateKey)?;
    if !input
        .get(..start)
        .ok_or(SshKeyError::InvalidPrivateKey)?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let header_end = start
        .checked_add(begin.len())
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    let body_start = skip_line_break(input, header_end)?;
    let end_at = input
        .get(body_start..)
        .and_then(|tail| tail.find(end).map(|offset| body_start + offset))
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    let body = input
        .get(body_start..end_at)
        .ok_or(SshKeyError::InvalidPrivateKey)?;
    if !body.ends_with('\n') {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    if !input
        .get(end_at + end.len()..)
        .ok_or(SshKeyError::InvalidPrivateKey)?
        .chars()
        .all(char::is_whitespace)
    {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let body: Zeroizing<String> = Zeroizing::new(
        body.chars()
            .filter(|character| !character.is_whitespace())
            .collect(),
    );
    if body.len() > MAX_OPENSSH_ENCODED_LENGTH {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(body.as_str())
            .map_err(|_| SshKeyError::InvalidPrivateKey)?,
    );
    if decoded.is_empty() || decoded.len() > pem::MAXIMUM_DECODED_LENGTH {
        return Err(SshKeyError::InvalidPrivateKey);
    }
    Ok(decoded)
}

fn skip_line_break(input: &str, index: usize) -> Result<usize, SshKeyError> {
    let remaining = input.get(index..).ok_or(SshKeyError::InvalidPrivateKey)?;
    if let Some(stripped) = remaining.strip_prefix("\r\n") {
        Ok(index + remaining.len() - stripped.len())
    } else if let Some(stripped) = remaining.strip_prefix('\n') {
        Ok(index + remaining.len() - stripped.len())
    } else {
        Err(SshKeyError::InvalidPrivateKey)
    }
}

#[cfg(test)]
mod tests {
    use super::{OPENSSH_MAGIC, SshKeyError, SshKeyToX509, ssh_keypair_to_x509};
    use crate::pem;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{
        SigningKey, VerifyingKey,
        pkcs8::{DecodePrivateKey as _, DecodePublicKey as _},
    };

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let length = u32::try_from(value.len()).expect("test SSH value is short");
        let mut encoded = length.to_be_bytes().to_vec();
        encoded.extend_from_slice(value);
        encoded
    }

    fn seed_range(start: u8) -> [u8; 32] {
        std::array::from_fn(|index| start + u8::try_from(index).expect("test seed offset is small"))
    }

    fn ed25519_public_blob(seed: &[u8; 32]) -> Vec<u8> {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        let mut blob = ssh_string(b"ssh-ed25519");
        blob.extend_from_slice(&ssh_string(&public));
        blob
    }

    fn ed25519_private_section(seed: &[u8; 32]) -> Vec<u8> {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        let mut secret = seed.to_vec();
        secret.extend_from_slice(&public);

        let mut section = 0x1234_u32.to_be_bytes().to_vec();
        section.extend_from_slice(&0x1234_u32.to_be_bytes());
        section.extend_from_slice(&ssh_string(b"ssh-ed25519"));
        section.extend_from_slice(&ssh_string(&public));
        section.extend_from_slice(&ssh_string(&secret));
        section.extend_from_slice(&ssh_string(b"test comment"));
        add_openssh_padding(&mut section, 8);
        section
    }

    fn add_openssh_padding(value: &mut Vec<u8>, block_size: usize) {
        let remainder = value.len() % block_size;
        let padding_length = if remainder == 0 {
            0
        } else {
            block_size - remainder
        };
        for padding_value in 1..=padding_length {
            value.push(
                u8::try_from(padding_value).expect("test OpenSSH padding value fits in a byte"),
            );
        }
    }

    fn build_unencrypted_openssh(seed: &[u8; 32]) -> String {
        let public_blob = ed25519_public_blob(seed);
        let private_section = ed25519_private_section(seed);

        let mut blob = OPENSSH_MAGIC.to_vec();
        blob.extend_from_slice(&ssh_string(b"none"));
        blob.extend_from_slice(&ssh_string(b"none"));
        blob.extend_from_slice(&ssh_string(&[]));
        blob.extend_from_slice(&1_u32.to_be_bytes());
        blob.extend_from_slice(&ssh_string(&public_blob));
        blob.extend_from_slice(&ssh_string(&private_section));
        pem::encode("OPENSSH PRIVATE KEY", &blob).expect("test OpenSSH private key should encode")
    }

    fn authorized_ed25519(seed: &[u8; 32]) -> String {
        format!(
            "ssh-ed25519 {} test comment",
            STANDARD.encode(ed25519_public_blob(seed))
        )
    }

    fn request() -> SshKeyToX509 {
        SshKeyToX509 {
            common_name: "ssh.example".to_owned(),
            not_before_unix: 0,
            not_after_unix: 5,
        }
    }

    #[test]
    fn converts_unencrypted_openssh_ed25519() {
        let seed = seed_range(32);
        let private_key = build_unencrypted_openssh(&seed);
        let public_key = authorized_ed25519(&seed);
        let result = ssh_keypair_to_x509(&private_key, &public_key, &request(), None)
            .expect("OpenSSH Ed25519 key pair should convert");

        let decoded = SigningKey::from_pkcs8_pem(&result.private_key_pem)
            .expect("generated PKCS#8 Ed25519 key should decode");
        assert_eq!(decoded.to_bytes(), seed);
        let public = VerifyingKey::from_public_key_pem(&result.public_key_pem)
            .expect("generated SubjectPublicKeyInfo should decode");
        assert_eq!(
            public.to_bytes(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
        assert!(
            result
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----\n")
        );
    }

    #[test]
    fn rejects_mismatched_authorized_key() {
        let seed = seed_range(32);
        let private_key = build_unencrypted_openssh(&seed);
        let public_key = authorized_ed25519(&seed_range(64));
        assert_eq!(
            ssh_keypair_to_x509(&private_key, &public_key, &request(), None),
            Err(SshKeyError::KeyMismatch)
        );
    }

    #[test]
    fn encrypted_openssh_requires_passphrase() {
        let seed = seed_range(32);
        let public_blob = ed25519_public_blob(&seed);
        let private_section = ed25519_private_section(&seed);
        let mut kdf_options = ssh_string(b"test salt");
        kdf_options.extend_from_slice(&1_u32.to_be_bytes());

        let mut blob = OPENSSH_MAGIC.to_vec();
        blob.extend_from_slice(&ssh_string(b"aes256-ctr"));
        blob.extend_from_slice(&ssh_string(b"bcrypt"));
        blob.extend_from_slice(&ssh_string(&kdf_options));
        blob.extend_from_slice(&1_u32.to_be_bytes());
        blob.extend_from_slice(&ssh_string(&public_blob));
        blob.extend_from_slice(&ssh_string(&private_section));
        let private_key =
            pem::encode("OPENSSH PRIVATE KEY", &blob).expect("encrypted test header should encode");
        let public_key = authorized_ed25519(&seed);

        assert_eq!(
            ssh_keypair_to_x509(&private_key, &public_key, &request(), None),
            Err(SshKeyError::EncryptedKey)
        );
    }
}
