//! OpenSSH `chacha20-poly1305@openssh.com` packet protection.
//!
//! This is the SSH packet construction, not the IETF RFC 8439 AEAD.  A
//! direction key is split into a 32-byte payload key and a 32-byte length
//! key.  The sequence number is supplied for each operation and is encoded as
//! the big-endian 64-bit `ChaCha20` nonce.

use std::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::universal_hash::KeyInit;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use neotales_ssh::MAX_PACKET_CONTENT;

/// The OpenSSH name for this packet-protection construction.
///
/// This constant belongs to the standalone packet codec.  It is intentionally
/// not added to any KEXINIT proposal by this module.
pub const CHACHA20_POLY1305_OPENSSH_NAME: &str = "chacha20-poly1305@openssh.com";

/// The number of bytes in one direction key.
pub const CHACHA_KEY_SIZE: usize = 64;

/// The number of bytes in the `ChaCha20` nonce.
pub const CHACHA_NONCE_SIZE: usize = 8;

/// The number of bytes in the Poly1305 authentication tag.
pub const CHACHA_TAG_SIZE: usize = 16;

/// The `ChaCha20` block size, in bytes.
pub const CHACHA_BLOCK_SIZE: usize = 64;

const PAYLOAD_KEY_SIZE: usize = 32;
const LENGTH_KEY_SIZE: usize = 32;
const LENGTH_SIZE: usize = 4;
const MIN_BODY_SIZE: usize = 1;
const MAX_CLEAR_PACKET_SIZE: usize = MAX_PACKET_CONTENT + LENGTH_SIZE + MIN_BODY_SIZE;
const MAX_PROTECTED_PACKET_SIZE: usize = MAX_CLEAR_PACKET_SIZE + CHACHA_TAG_SIZE;

/// A safe error produced by the OpenSSH `ChaCha20` packet codec.
///
/// Error values contain no key bytes, packet bytes, plaintext, or
/// attacker-controlled input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChaChaCipherError {
    /// The direction key was not exactly 64 bytes.
    InvalidKeyMaterial,
    /// The input ended before a complete length, body, or tag was present.
    Truncated,
    /// The combined packet payload and padding exceeded
    /// [`neotales_ssh::MAX_PACKET_CONTENT`].
    LimitExceeded,
    /// The clear length field or packet body was structurally invalid.
    InvalidPacket,
    /// The Poly1305 tag did not authenticate the ciphertext.
    AuthenticationFailed,
    /// A local `ChaCha20` stream operation failed.
    EncryptionFailed,
}

impl fmt::Display for ChaChaCipherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyMaterial => "SSH ChaCha20 key material is invalid",
            Self::Truncated => "SSH ChaCha20 packet is truncated",
            Self::LimitExceeded => "SSH ChaCha20 packet exceeds the configured limit",
            Self::InvalidPacket => "SSH ChaCha20 packet is malformed",
            Self::AuthenticationFailed => "SSH ChaCha20 packet authentication failed",
            Self::EncryptionFailed => "SSH ChaCha20 packet encryption failed",
        })
    }
}

impl std::error::Error for ChaChaCipherError {}

/// Validated key material for one packet direction.
///
/// The key is copied into zeroizing storage.  The original caller buffer is
/// not modified or retained.
#[derive(Clone)]
pub struct ChaChaKeyMaterial {
    key: Zeroizing<[u8; CHACHA_KEY_SIZE]>,
}

impl fmt::Debug for ChaChaKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChaChaKeyMaterial")
            .field("key_len", &self.key.len())
            .finish()
    }
}

impl fmt::Display for ChaChaKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSH ChaCha20 direction key material")
    }
}

impl ChaChaKeyMaterial {
    /// Copies exactly 64 direction-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChaChaCipherError::InvalidKeyMaterial`] unless `key` has
    /// exactly [`CHACHA_KEY_SIZE`] bytes.
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ChaChaCipherError> {
        let key: [u8; CHACHA_KEY_SIZE] = key
            .as_ref()
            .try_into()
            .map_err(|_error| ChaChaCipherError::InvalidKeyMaterial)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }
}

/// An OpenSSH ChaCha20-Poly1305 packet protector for one direction.
///
/// The protector owns only its direction key.  It does not retain or advance
/// a sequence number: every [`Self::seal`] and [`Self::open`] call receives the
/// sequence number explicitly.  Consequently, the same protector can be used
/// for either packet direction's independent key context.
#[derive(Clone)]
pub struct ChaChaCipher {
    material: ChaChaKeyMaterial,
}

impl fmt::Debug for ChaChaCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChaChaCipher")
            .field("key_len", &self.material.key.len())
            .finish()
    }
}

impl fmt::Display for ChaChaCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSH OpenSSH ChaCha20-Poly1305 packet protector")
    }
}

impl ChaChaCipher {
    /// Creates a protector from a 64-byte direction key.
    ///
    /// # Errors
    ///
    /// Returns [`ChaChaCipherError::InvalidKeyMaterial`] when `key` does not
    /// have exactly [`CHACHA_KEY_SIZE`] bytes.
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ChaChaCipherError> {
        Ok(Self {
            material: ChaChaKeyMaterial::new(key)?,
        })
    }

    /// Creates a protector from already validated direction-key material.
    #[must_use]
    pub fn from_material(material: ChaChaKeyMaterial) -> Self {
        Self { material }
    }

    /// Encrypts a clear SSH packet and appends its Poly1305 tag.
    ///
    /// `packet` must contain a four-byte big-endian SSH length field followed
    /// by at least one body byte.  The returned bytes contain the encrypted
    /// length, encrypted body, and 16-byte tag.
    ///
    /// # Errors
    ///
    /// Returns [`ChaChaCipherError::LimitExceeded`] for an input over the SSH
    /// packet-content limit, [`ChaChaCipherError::Truncated`] when the four-byte
    /// length field is absent, and [`ChaChaCipherError::InvalidPacket`] for an
    /// empty body or an inconsistent length field.  Local stream failures are
    /// reported as [`ChaChaCipherError::EncryptionFailed`].
    pub fn seal(&self, sequence_number: u32, packet: &[u8]) -> Result<Vec<u8>, ChaChaCipherError> {
        if packet.len() > MAX_CLEAR_PACKET_SIZE {
            return Err(ChaChaCipherError::LimitExceeded);
        }

        let clear_length = packet
            .get(..LENGTH_SIZE)
            .ok_or(ChaChaCipherError::Truncated)?;
        let body_size = packet
            .get(LENGTH_SIZE..)
            .ok_or(ChaChaCipherError::Truncated)?
            .len();
        if body_size < MIN_BODY_SIZE {
            return Err(ChaChaCipherError::InvalidPacket);
        }
        validate_length(clear_length, body_size)?;

        let payload_key = self
            .material
            .key
            .get(..PAYLOAD_KEY_SIZE)
            .ok_or(ChaChaCipherError::InvalidKeyMaterial)?;
        let length_key = self
            .material
            .key
            .get(PAYLOAD_KEY_SIZE..PAYLOAD_KEY_SIZE + LENGTH_KEY_SIZE)
            .ok_or(ChaChaCipherError::InvalidKeyMaterial)?;
        let poly_key = derive_poly_key(payload_key, sequence_number)?;
        let output_size = packet
            .len()
            .checked_add(CHACHA_TAG_SIZE)
            .ok_or(ChaChaCipherError::LimitExceeded)?;
        let mut encrypted = Zeroizing::new(Vec::with_capacity(output_size));
        encrypted.extend_from_slice(packet);

        let body = encrypted
            .get_mut(LENGTH_SIZE..)
            .ok_or(ChaChaCipherError::InvalidPacket)?;
        apply_payload_stream(payload_key, sequence_number, body)?;

        let length = encrypted
            .get_mut(..LENGTH_SIZE)
            .ok_or(ChaChaCipherError::InvalidPacket)?;
        apply_length_stream(length_key, sequence_number, length)?;

        let tag = compute_tag(poly_key.as_ref(), encrypted.as_slice())?;
        encrypted.extend_from_slice(tag.as_slice());
        Ok(encrypted.as_slice().to_vec())
    }

    /// Decrypts only the four-byte OpenSSH packet length.
    ///
    /// This low-level helper is primarily used by the SSH transport. It
    /// intentionally performs no authentication. The caller must apply
    /// strict length bounds before allocating or reading the remaining packet,
    /// then authenticate the complete ciphertext with [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns [`ChaChaCipherError::Truncated`] for fewer than four bytes,
    /// [`ChaChaCipherError::InvalidPacket`] for a non-four-byte input, and
    /// [`ChaChaCipherError::InvalidKeyMaterial`] for an invalid internal key.
    #[doc(hidden)]
    pub fn decrypt_length(
        &self,
        sequence_number: u32,
        input: &[u8],
    ) -> Result<u32, ChaChaCipherError> {
        if input.len() < LENGTH_SIZE {
            return Err(ChaChaCipherError::Truncated);
        }
        if input.len() != LENGTH_SIZE {
            return Err(ChaChaCipherError::InvalidPacket);
        }
        let length_key = self
            .material
            .key
            .get(PAYLOAD_KEY_SIZE..PAYLOAD_KEY_SIZE + LENGTH_KEY_SIZE)
            .ok_or(ChaChaCipherError::InvalidKeyMaterial)?;
        let encrypted_length: [u8; LENGTH_SIZE] = input
            .try_into()
            .map_err(|_error| ChaChaCipherError::InvalidPacket)?;
        let mut clear_length = Zeroizing::new(encrypted_length);
        apply_length_stream(length_key, sequence_number, clear_length.as_mut_slice())?;
        Ok(u32::from_be_bytes(*clear_length))
    }

    /// Authenticates and opens an OpenSSH `ChaCha20` packet.
    ///
    /// The Poly1305 tag is checked over the encrypted length and body before
    /// either value is decrypted.  On authentication failure no plaintext is
    /// returned, and all temporary decrypted storage is zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`ChaChaCipherError::LimitExceeded`] for an input over the SSH
    /// packet-content limit, [`ChaChaCipherError::Truncated`] when the
    /// encrypted length, body, or 16-byte tag is incomplete, and
    /// [`ChaChaCipherError::InvalidPacket`] for an empty body or an
    /// inconsistent authenticated length field.  A bad tag returns
    /// [`ChaChaCipherError::AuthenticationFailed`].
    pub fn open(&self, sequence_number: u32, input: &[u8]) -> Result<Vec<u8>, ChaChaCipherError> {
        if input.len() > MAX_PROTECTED_PACKET_SIZE {
            return Err(ChaChaCipherError::LimitExceeded);
        }

        let minimum_size = LENGTH_SIZE
            .checked_add(MIN_BODY_SIZE)
            .and_then(|size| size.checked_add(CHACHA_TAG_SIZE))
            .ok_or(ChaChaCipherError::LimitExceeded)?;
        if input.len() < minimum_size {
            return Err(ChaChaCipherError::Truncated);
        }

        let ciphertext_size = input
            .len()
            .checked_sub(CHACHA_TAG_SIZE)
            .ok_or(ChaChaCipherError::Truncated)?;
        let ciphertext = input
            .get(..ciphertext_size)
            .ok_or(ChaChaCipherError::Truncated)?;
        let received_tag = input
            .get(ciphertext_size..)
            .ok_or(ChaChaCipherError::Truncated)?;
        if received_tag.len() != CHACHA_TAG_SIZE {
            return Err(ChaChaCipherError::Truncated);
        }

        let encrypted_body = ciphertext
            .get(LENGTH_SIZE..)
            .ok_or(ChaChaCipherError::Truncated)?;
        if encrypted_body.is_empty() {
            return Err(ChaChaCipherError::InvalidPacket);
        }

        let payload_key = self
            .material
            .key
            .get(..PAYLOAD_KEY_SIZE)
            .ok_or(ChaChaCipherError::InvalidKeyMaterial)?;
        let length_key = self
            .material
            .key
            .get(PAYLOAD_KEY_SIZE..PAYLOAD_KEY_SIZE + LENGTH_KEY_SIZE)
            .ok_or(ChaChaCipherError::InvalidKeyMaterial)?;
        let poly_key = derive_poly_key(payload_key, sequence_number)?;
        let expected_tag = compute_tag(poly_key.as_ref(), ciphertext)?;
        let tag_matches: bool = expected_tag.as_slice().ct_eq(received_tag).into();
        if !tag_matches {
            return Err(ChaChaCipherError::AuthenticationFailed);
        }

        // Do not allocate or populate a plaintext buffer until authentication
        // has succeeded.  The zeroizing guard also clears it on later errors.
        let mut clear = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        clear.extend_from_slice(ciphertext);

        let length = clear
            .get_mut(..LENGTH_SIZE)
            .ok_or(ChaChaCipherError::InvalidPacket)?;
        apply_length_stream(length_key, sequence_number, length)?;

        let body_size = {
            let body = clear
                .get_mut(LENGTH_SIZE..)
                .ok_or(ChaChaCipherError::InvalidPacket)?;
            if body.is_empty() {
                return Err(ChaChaCipherError::InvalidPacket);
            }
            apply_payload_stream(payload_key, sequence_number, body)?;
            body.len()
        };

        let clear_length = clear
            .get(..LENGTH_SIZE)
            .ok_or(ChaChaCipherError::InvalidPacket)?;
        validate_length(clear_length, body_size)?;
        Ok(clear.as_slice().to_vec())
    }
}

fn validate_length(length: &[u8], body_size: usize) -> Result<(), ChaChaCipherError> {
    let length: [u8; LENGTH_SIZE] = length
        .try_into()
        .map_err(|_error| ChaChaCipherError::InvalidPacket)?;
    let declared_size = u32::from_be_bytes(length);
    let expected_size =
        u32::try_from(body_size).map_err(|_error| ChaChaCipherError::LimitExceeded)?;
    if declared_size != expected_size {
        return Err(ChaChaCipherError::InvalidPacket);
    }
    Ok(())
}

fn derive_poly_key(
    payload_key: &[u8],
    sequence_number: u32,
) -> Result<Zeroizing<[u8; 32]>, ChaChaCipherError> {
    let mut poly_key = Zeroizing::new([0_u8; 32]);
    let mut stream = new_stream(payload_key, sequence_number)?;
    stream
        .try_apply_keystream(poly_key.as_mut_slice())
        .map_err(|_error| ChaChaCipherError::EncryptionFailed)?;
    Ok(poly_key)
}

fn apply_payload_stream(
    payload_key: &[u8],
    sequence_number: u32,
    body: &mut [u8],
) -> Result<(), ChaChaCipherError> {
    let block_offset =
        u64::try_from(CHACHA_BLOCK_SIZE).map_err(|_error| ChaChaCipherError::EncryptionFailed)?;
    let mut stream = new_stream(payload_key, sequence_number)?;
    stream
        .try_seek(block_offset)
        .map_err(|_error| ChaChaCipherError::EncryptionFailed)?;
    stream
        .try_apply_keystream(body)
        .map_err(|_error| ChaChaCipherError::EncryptionFailed)
}

fn apply_length_stream(
    length_key: &[u8],
    sequence_number: u32,
    length: &mut [u8],
) -> Result<(), ChaChaCipherError> {
    let mut stream = new_stream(length_key, sequence_number)?;
    stream
        .try_apply_keystream(length)
        .map_err(|_error| ChaChaCipherError::EncryptionFailed)
}

fn new_stream(
    key: &[u8],
    sequence_number: u32,
) -> Result<chacha20::ChaCha20Legacy, ChaChaCipherError> {
    // This is the full 64-bit integer in little-endian order, not the
    // 96-bit nonce layout used by the IETF AEAD.
    let nonce: [u8; CHACHA_NONCE_SIZE] = u64::from(sequence_number).to_be_bytes();
    chacha20::ChaCha20Legacy::new_from_slices(key, &nonce)
        .map_err(|_error| ChaChaCipherError::InvalidKeyMaterial)
}

fn compute_tag(
    poly_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; CHACHA_TAG_SIZE]>, ChaChaCipherError> {
    let mut generated = poly1305::Poly1305::new_from_slice(poly_key)
        .map_err(|_error| ChaChaCipherError::InvalidKeyMaterial)?
        .compute_unpadded(ciphertext);
    let mut tag = Zeroizing::new([0_u8; CHACHA_TAG_SIZE]);
    tag.copy_from_slice(generated.as_slice());
    generated.as_mut_slice().zeroize();
    Ok(tag)
}
