//! Authenticated SSH binary packet protection.
//!
//! This module implements the RFC 4253 encrypt-and-MAC construction, the
//! OpenSSH encrypt-then-MAC variants, and OpenSSH AES-GCM framing. Callers own
//! key derivation and sequence-number policy; a [`PacketProtector`] only
//! retains the continuous CTR byte position for its current key context.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use neotales_ssh::chacha_cipher::{ChaChaCipher, ChaChaCipherError};

use crate::MAX_PACKET_CONTENT;
use crate::kex::wipes_itself_on_drop;
use neotales_ssh::compression::{
    CompressionAlgorithm, CompressionError, compress_payload, decompress_payload,
    padding_for_payload,
};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::AeadInOut;
use hmac::Mac;

const AES128_CTR_NAME: &str = "aes128-ctr";
const AES256_CTR_NAME: &str = "aes256-ctr";
const AES128_GCM_OPENSSH_NAME: &str = "aes128-gcm@openssh.com";
const AES256_GCM_OPENSSH_NAME: &str = "aes256-gcm@openssh.com";
const CHACHA20_POLY1305_OPENSSH_NAME: &str = "chacha20-poly1305@openssh.com";
const HMAC_SHA2_256_NAME: &str = "hmac-sha2-256";
const HMAC_SHA2_512_NAME: &str = "hmac-sha2-512";
const HMAC_SHA2_256_ETM_OPENSSH_NAME: &str = "hmac-sha2-256-etm@openssh.com";
const HMAC_SHA2_512_ETM_OPENSSH_NAME: &str = "hmac-sha2-512-etm@openssh.com";

const GCM_IV_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const GCM_NONCE_SIZE: usize = 12;
/// Width of the invocation counter within an AES-GCM nonce, in octets.
///
/// Measured against OpenSSL rather than assumed: the counter is the trailing
/// *eight* octets of the 12-octet nonce, not the trailing four, so an advance
/// carries out of the last four octets and into the four before them. See
/// [`gcm_nonce`].
const COUNTER_SIZE: usize = 8;
const SHA256_KEY_SIZE: usize = 32;
const SHA512_KEY_SIZE: usize = 64;
const CHACHA_KEY_SIZE: usize = 64;
const CHACHA_IV_SIZE: usize = 8;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;
type GcmNonce = aes_gcm::Nonce<aes::cipher::consts::U12>;
type GcmTag = aes_gcm::Tag<aes::cipher::consts::U16>;

/// A safe error produced while configuring or applying SSH packet protection.
///
/// Error values never contain key material, packet bytes, sequence numbers,
/// algorithm names, or other attacker-controlled input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketProtectionError {
    /// The encryption and integrity names do not form a supported suite.
    UnsupportedSuite,
    /// The IV, encryption key, or integrity key has an invalid length or presence.
    InvalidKeyMaterial,
    /// The input ended before a complete length, body, or authentication tag.
    Truncated,
    /// The packet's combined payload and padding exceeded the configured limit.
    LimitExceeded,
    /// A clear length field or packet body was structurally inconsistent.
    InvalidPacket,
    /// Packet padding was shorter than the SSH minimum or was inconsistent.
    InvalidPadding,
    /// The packet was not aligned to the selected cipher block size.
    InvalidAlignment,
    /// The HMAC or AES-GCM authentication tag did not verify.
    AuthenticationFailed,
    /// AES-GCM could not encrypt a packet that passed all local validation.
    EncryptionFailed,
    /// A packet or GCM invocation counter cannot advance without wrapping, or
    /// the suite's processed-packet count is unavailable.
    CounterExhausted,
    /// The negotiated compression stream was malformed or exceeded its bound.
    InvalidCompression,
}

impl fmt::Display for PacketProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSuite => "SSH packet-protection suite is unsupported",
            Self::InvalidKeyMaterial => "SSH packet-protection key material is invalid",
            Self::Truncated => "SSH protected packet is truncated",
            Self::LimitExceeded => "SSH protected packet exceeds the configured limit",
            Self::InvalidPacket => "SSH protected packet is malformed",
            Self::InvalidPadding => "SSH protected packet padding is invalid",
            Self::InvalidAlignment => "SSH protected packet has invalid block alignment",
            Self::AuthenticationFailed => "SSH protected packet authentication failed",
            Self::EncryptionFailed => "SSH protected packet encryption failed",
            Self::CounterExhausted => "SSH packet-protection counter is exhausted",
            Self::InvalidCompression => "SSH compressed payload is invalid",
        })
    }
}

impl std::error::Error for PacketProtectionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CipherAlgorithm {
    Aes128Ctr,
    Aes256Ctr,
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl CipherAlgorithm {
    const fn name(self) -> &'static str {
        match self {
            Self::Aes128Ctr => AES128_CTR_NAME,
            Self::Aes256Ctr => AES256_CTR_NAME,
            Self::Aes128Gcm => AES128_GCM_OPENSSH_NAME,
            Self::Aes256Gcm => AES256_GCM_OPENSSH_NAME,
            Self::Chacha20Poly1305 => CHACHA20_POLY1305_OPENSSH_NAME,
        }
    }

    const fn key_size(self) -> usize {
        match self {
            Self::Aes128Ctr | Self::Aes128Gcm => 16,
            Self::Aes256Ctr | Self::Aes256Gcm => 32,
            Self::Chacha20Poly1305 => CHACHA_KEY_SIZE,
        }
    }

    const fn is_gcm(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm)
    }

    const fn is_chacha(self) -> bool {
        matches!(self, Self::Chacha20Poly1305)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityAlgorithm {
    HmacSha256,
    HmacSha512,
    HmacSha256Etm,
    HmacSha512Etm,
}

impl IntegrityAlgorithm {
    const fn name(self) -> &'static str {
        match self {
            Self::HmacSha256 => HMAC_SHA2_256_NAME,
            Self::HmacSha512 => HMAC_SHA2_512_NAME,
            Self::HmacSha256Etm => HMAC_SHA2_256_ETM_OPENSSH_NAME,
            Self::HmacSha512Etm => HMAC_SHA2_512_ETM_OPENSSH_NAME,
        }
    }

    const fn key_size(self) -> usize {
        match self {
            Self::HmacSha256 | Self::HmacSha256Etm => SHA256_KEY_SIZE,
            Self::HmacSha512 | Self::HmacSha512Etm => SHA512_KEY_SIZE,
        }
    }

    const fn tag_size(self) -> usize {
        match self {
            Self::HmacSha256 | Self::HmacSha256Etm => SHA256_KEY_SIZE,
            Self::HmacSha512 | Self::HmacSha512Etm => SHA512_KEY_SIZE,
        }
    }

    const fn encrypt_then_mac(self) -> bool {
        matches!(self, Self::HmacSha256Etm | Self::HmacSha512Etm)
    }
}

/// One validated packet-protection algorithm combination.
///
/// CTR suites pair `aes128-ctr` or `aes256-ctr` with one of the four supported
/// HMAC-SHA2 names. OpenSSH AES-GCM and ChaCha20-Poly1305 suites have an
/// integrity name of `None`; their authentication tags are intrinsic to the
/// cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketSuite {
    cipher: CipherAlgorithm,
    integrity: Option<IntegrityAlgorithm>,
}

impl PacketSuite {
    /// Validates an encryption name and optional HMAC name as one suite.
    ///
    /// The accepted encryption names are `aes128-ctr`, `aes256-ctr`,
    /// `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, and
    /// `chacha20-poly1305@openssh.com`. CTR requires `hmac-sha2-256`,
    /// `hmac-sha2-512`, or the corresponding OpenSSH encrypt-then-MAC name.
    /// AES-GCM and ChaCha20-Poly1305 require `integrity_name` to be `None`.
    ///
    /// # Errors
    ///
    /// Returns [`PacketProtectionError::UnsupportedSuite`] for unknown names,
    /// a missing CTR MAC, an HMAC paired with AES-GCM, or an AES-GCM name
    /// supplied as a CTR integrity algorithm.
    pub(crate) fn new(
        encryption_name: &str,
        integrity_name: Option<&str>,
    ) -> Result<Self, PacketProtectionError> {
        let cipher = match encryption_name {
            AES128_CTR_NAME => CipherAlgorithm::Aes128Ctr,
            AES256_CTR_NAME => CipherAlgorithm::Aes256Ctr,
            AES128_GCM_OPENSSH_NAME => CipherAlgorithm::Aes128Gcm,
            AES256_GCM_OPENSSH_NAME => CipherAlgorithm::Aes256Gcm,
            CHACHA20_POLY1305_OPENSSH_NAME => CipherAlgorithm::Chacha20Poly1305,
            _ => return Err(PacketProtectionError::UnsupportedSuite),
        };
        let integrity = match integrity_name {
            Some(HMAC_SHA2_256_NAME) => Some(IntegrityAlgorithm::HmacSha256),
            Some(HMAC_SHA2_512_NAME) => Some(IntegrityAlgorithm::HmacSha512),
            Some(HMAC_SHA2_256_ETM_OPENSSH_NAME) => Some(IntegrityAlgorithm::HmacSha256Etm),
            Some(HMAC_SHA2_512_ETM_OPENSSH_NAME) => Some(IntegrityAlgorithm::HmacSha512Etm),
            Some(_) => return Err(PacketProtectionError::UnsupportedSuite),
            None => None,
        };

        match (cipher.is_gcm() || cipher.is_chacha(), integrity) {
            (true, None) => Ok(Self {
                cipher,
                integrity: None,
            }),
            (false, Some(integrity)) => Ok(Self {
                cipher,
                integrity: Some(integrity),
            }),
            _ => Err(PacketProtectionError::UnsupportedSuite),
        }
    }

    /// Returns the negotiated encryption name.
    #[must_use]
    pub(crate) const fn encryption_name(self) -> &'static str {
        self.cipher.name()
    }

    /// Returns the negotiated HMAC name, or `None` for an AEAD suite.
    #[must_use]
    pub(crate) const fn integrity_name(self) -> Option<&'static str> {
        match self.integrity {
            Some(integrity) => Some(integrity.name()),
            None => None,
        }
    }

    /// Returns whether this suite uses the OpenSSH `ChaCha` packet format.
    #[must_use]
    pub(crate) const fn is_chacha(self) -> bool {
        self.cipher.is_chacha()
    }
}

/// The block size OpenSSH applies to `chacha20-poly1305@openssh.com`.
///
/// OpenSSH 10.5p1 `cipher.c` tabulates the cipher contract as
/// `static const struct sshcipher ciphers[]`, whose field order is `name,
/// block_size, key_len, iv_len, auth_len, flags` (`cipher.c` lines 66-83):
///
/// ```text
/// { "chacha20-poly1305@openssh.com",
///               8, 64, 0, 16, CFLAG_CHACHAPOLY, NULL },
/// ```
///
/// `kex.c` line 821 copies that into the direction's key context with
/// `enc->block_size = cipher_blocksize(enc->cipher);`, and `packet.c` line 1243
/// reads it back as `block_size = enc ? enc->block_size : 8;`.
pub(crate) const CHACHA_BLOCK_SIZE: usize = 8;

/// The block size OpenSSH applies to every other packet cipher this crate
/// negotiates.
///
/// From the same `cipher.c` table: `{ "aes128-ctr", 16, 16, 0, 0, 0,
/// EVP_aes_128_ctr }` and `{ "aes128-gcm@openssh.com", 16, 16, 12, 16, 0,
/// EVP_aes_128_gcm }`.
pub(crate) const AES_BLOCK_SIZE: usize = 16;

/// The smallest padding OpenSSH will accept, from `packet.c` line 1791
/// (`if (padlen < 4) {`) and the matching writer guard on line 1282.
pub(crate) const MIN_PADDING: usize = 4;

/// A failure while computing or checking a protected packet's block alignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AlignmentError {
    /// A length plus its framing header would exceed `usize` or `u8`.
    LengthOverflow,
    /// The packet does not sit on the block boundary its suite requires.
    InvalidAlignment,
    /// A padding pattern was empty, so there is nothing to pad with.
    EmptyPattern,
}

/// The block-alignment contract OpenSSH applies to one packet cipher.
///
/// This is the only place the rule lives. Sealing, opening, and stream framing
/// all ask this value rather than re-deriving an alignment from a block size,
/// because the block size and *which* length is aligned are two independent
/// decisions that a reader who has only one of them will get wrong.
///
/// # Where the rule comes from
///
/// OpenSSH computes the alignment in `ssh_packet_send2_wrapped`
/// (`packet.c` lines 1243-1244 and 1280-1283):
///
/// ```c
/// block_size = enc ? enc->block_size : 8;
/// aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;
/// ...
/// /* sizeof (packet_len + pad_len + payload) */
/// len = sshbuf_len(state->outgoing_packet);
/// len -= aadlen; /* packet length is not encrypted for EtM modes */
/// padlen = block_size - (len % block_size);
/// if (padlen < 4)
///         padlen += block_size;
/// ```
///
/// `sshbuf_len` there is the four-byte length field, the padding-length byte,
/// and the payload, so `len` is `5 + payload` before the `len -= aadlen`
/// adjustment. `authlen` is `cipher_authlen(enc->cipher)` from line 1240, which
/// the `cipher.c` table above gives as 16 for both AEAD ciphers and 0 for the
/// rest.
///
/// The same rule reappears on the receive side in `ssh_packet_read_poll2`
/// (`packet.c` lines 1702-1719), which is why the two directions agree:
///
/// ```c
/// if (aadlen) {
///         /* only the payload is encrypted */
///         need = state->packlen;
/// } else {
///         need = 4 + state->packlen - block_size;
/// }
/// ...
/// if (need % block_size != 0) {
///         logit("padding error: need %d block %d mod %d",
///             need, block_size, need % block_size);
/// ```
///
/// So `aadlen != 0` — an AEAD, or encrypt-then-MAC — aligns the four-byte
/// `packet_length` field itself, because that field is authenticated but not
/// encrypted and therefore not part of the aligned ciphertext. Encrypt-and-MAC
/// encrypts the length field along with everything else, so it aligns
/// `4 + packet_length`. `chacha20-poly1305@openssh.com` is an AEAD, so it
/// aligns `packet_length` to 8.
///
/// `packet_length` counts the padding-length byte, the payload, and the
/// padding. It does not count its own four-byte field or the authentication
/// tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketAlignment {
    block_size: usize,
    aligns_packet_length: bool,
}

impl PacketAlignment {
    /// The alignment for packets sent before `SSH_MSG_NEWKEYS`.
    ///
    /// `packet.c` line 1243 falls back to `8` when there is no key context, and
    /// line 1244 leaves `aadlen` at zero because there is neither a MAC nor an
    /// AEAD yet. The unprotected stream is therefore the same rule with
    /// `block_size == 8` and the encrypt-and-MAC branch.
    pub(crate) const UNPROTECTED: Self = Self {
        block_size: CHACHA_BLOCK_SIZE,
        aligns_packet_length: false,
    };

    /// The alignment OpenSSH applies to `suite`.
    pub(crate) fn for_suite(suite: PacketSuite) -> Self {
        // OpenSSH's `aadlen` is four when the MAC is encrypt-then-MAC or the
        // cipher is an AEAD, and zero otherwise. `integrity_name` is `None`
        // exactly for the two AEAD suites, because an AEAD carries its own
        // tag and negotiates no separate MAC.
        let aligns_packet_length = match suite.integrity_name() {
            None => true,
            Some(name) => name.contains("-etm@openssh.com"),
        };
        Self {
            block_size: if suite.is_chacha() {
                CHACHA_BLOCK_SIZE
            } else {
                AES_BLOCK_SIZE
            },
            aligns_packet_length,
        }
    }

    /// An alignment from an explicit block size and header choice, for callers
    /// that hold those two values rather than a negotiated suite.
    pub(crate) const fn new(block_size: usize, aligns_packet_length: bool) -> Self {
        Self {
            block_size,
            aligns_packet_length,
        }
    }

    /// The block size a packet of this suite is padded to.
    pub(crate) const fn block_size(self) -> usize {
        self.block_size
    }

    /// Whether `packet_length` alone is the block-aligned quantity, rather
    /// than the whole packet including the four-byte length field.
    ///
    /// This is OpenSSH's `aadlen != 0` case. An AEAD authenticates the length
    /// field without encrypting it; encrypt-then-MAC does the same; only
    /// encrypt-and-MAC encrypts the length field and so aligns it too.
    pub(crate) const fn aligns_packet_length(self) -> bool {
        self.aligns_packet_length
    }

    /// The number of framing bytes that precede the payload and take part in
    /// the alignment: the four-byte length field plus the padding-length byte,
    /// or just the padding-length byte when the length field is AAD.
    pub(crate) const fn header_length(self) -> usize {
        if self.aligns_packet_length { 1 } else { 5 }
    }

    /// The padding length OpenSSH's writer would choose for `payload_length`.
    ///
    /// This is the `padlen` arithmetic of `packet.c` lines 1281-1283, and it is
    /// the exact inverse of [`Self::validate_packet_length`].
    pub(crate) fn padding_length(self, payload_length: usize) -> Result<usize, AlignmentError> {
        let unpadded = payload_length
            .checked_add(self.header_length())
            .ok_or(AlignmentError::LengthOverflow)?;
        let mut length = self.block_size - (unpadded % self.block_size);
        if length < MIN_PADDING {
            // Unreachable overflow: `length` is at most `block_size`, so the
            // sum is at most `2 * block_size`.
            length = length
                .checked_add(self.block_size)
                .ok_or(AlignmentError::LengthOverflow)?;
        }
        Ok(length)
    }

    /// Like [`Self::padding_length`], but fills the padding from `pattern`.
    ///
    /// Compression changes the payload length after the transport has already
    /// drawn its padding, so the writer re-derives the length from the same
    /// rule while keeping the random bytes it already has.
    pub(crate) fn padding_pattern(
        self,
        payload_length: usize,
        pattern: &[u8],
    ) -> Result<Vec<u8>, AlignmentError> {
        if pattern.is_empty() {
            return Err(AlignmentError::EmptyPattern);
        }
        let length = self.padding_length(payload_length)?;
        let length =
            usize::from(u8::try_from(length).map_err(|_error| AlignmentError::LengthOverflow)?);
        let mut padding = vec![0_u8; length];
        for (index, byte) in padding.iter_mut().enumerate() {
            *byte = pattern[index % pattern.len()];
        }
        Ok(padding)
    }

    /// Rejects a received `packet_length` that is not on its block boundary.
    ///
    /// This is the receive-side `need % block_size != 0` check of `packet.c`
    /// line 1714, and it is the check that produced
    /// `padding error: need 28 block 8 mod 4` when this crate framed a
    /// `chacha20-poly1305@openssh.com` packet with `28 % 8 == 4`.
    pub(crate) fn validate_packet_length(self, packet_length: usize) -> Result<(), AlignmentError> {
        let aligned = if self.aligns_packet_length {
            packet_length
        } else {
            packet_length
                .checked_add(4)
                .ok_or(AlignmentError::LengthOverflow)?
        };
        if aligned % self.block_size != 0 {
            return Err(AlignmentError::InvalidAlignment);
        }
        Ok(())
    }
}

impl From<AlignmentError> for PacketProtectionError {
    fn from(error: AlignmentError) -> Self {
        match error {
            AlignmentError::LengthOverflow | AlignmentError::EmptyPattern => Self::LimitExceeded,
            AlignmentError::InvalidAlignment => Self::InvalidAlignment,
        }
    }
}

/// Raw, already-derived IV and key bytes supplied to a packet protector.
///
/// The constructor copies all input. The copies and their backing allocations
/// are zeroized when the material or protector is dropped.
pub(crate) struct PacketKeyMaterial {
    iv: Zeroizing<Vec<u8>>,
    encryption_key: Zeroizing<Vec<u8>>,
    integrity_key: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for PacketKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketKeyMaterial")
            .field("iv_len", &self.iv.len())
            .field("encryption_key_len", &self.encryption_key.len())
            .field(
                "integrity_key_len",
                &self.integrity_key.as_ref().map(|key| key.as_slice().len()),
            )
            .finish()
    }
}

impl PacketKeyMaterial {
    /// Copies raw IV, encryption-key, and optional integrity-key bytes.
    ///
    /// CTR suites require an integrity key. AES-GCM suites reject one during
    /// [`PacketProtector::new`] or [`PacketProtector::rekey`] validation.
    #[must_use]
    pub(crate) fn new(iv: &[u8], encryption_key: &[u8], integrity_key: Option<&[u8]>) -> Self {
        Self {
            iv: Zeroizing::new(iv.to_vec()),
            encryption_key: Zeroizing::new(encryption_key.to_vec()),
            integrity_key: integrity_key.map(|key| Zeroizing::new(key.to_vec())),
        }
    }

    /// Copies raw material for an encrypt-and-MAC or encrypt-then-MAC suite.
    #[must_use]
    pub(crate) fn hmac(iv: &[u8], encryption_key: &[u8], integrity_key: &[u8]) -> Self {
        Self::new(iv, encryption_key, Some(integrity_key))
    }

    /// Copies raw material for an AES-GCM suite without a separate MAC key.
    #[must_use]
    pub(crate) fn gcm(iv: &[u8], encryption_key: &[u8]) -> Self {
        Self::new(iv, encryption_key, None)
    }
}

struct CtrState {
    cipher: CipherAlgorithm,
    integrity: IntegrityAlgorithm,
    encryption_key: Zeroizing<Vec<u8>>,
    integrity_key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    position: u128,
}

struct GcmState {
    cipher: CipherAlgorithm,
    encryption_key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<[u8; GCM_IV_SIZE]>,
    packets_processed: Option<u64>,
}

struct ChachaState {
    cipher: ChaChaCipher,
}

enum ProtectorState {
    Ctr(CtrState),
    Gcm(GcmState),
    Chacha(ChachaState),
}

impl ProtectorState {
    fn new(suite: PacketSuite, material: PacketKeyMaterial) -> Result<Self, PacketProtectionError> {
        if material.encryption_key.len() != suite.cipher.key_size() {
            return Err(PacketProtectionError::InvalidKeyMaterial);
        }

        if suite.cipher.is_chacha() {
            if material.integrity_key.is_some()
                || material.iv.len() != CHACHA_IV_SIZE
                || material.iv.iter().any(|byte| *byte != 0)
            {
                return Err(PacketProtectionError::InvalidKeyMaterial);
            }
            let cipher =
                ChaChaCipher::new(material.encryption_key.as_slice()).map_err(map_chacha_error)?;
            return Ok(Self::Chacha(ChachaState { cipher }));
        }

        if suite.cipher.is_gcm() {
            if material.integrity_key.is_some() {
                return Err(PacketProtectionError::InvalidKeyMaterial);
            }
            let iv = material
                .iv
                .as_slice()
                .try_into()
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            Ok(Self::Gcm(GcmState {
                cipher: suite.cipher,
                encryption_key: material.encryption_key,
                iv: Zeroizing::new(iv),
                packets_processed: Some(0),
            }))
        } else {
            let integrity = suite
                .integrity
                .ok_or(PacketProtectionError::InvalidKeyMaterial)?;
            let integrity_key = material
                .integrity_key
                .ok_or(PacketProtectionError::InvalidKeyMaterial)?;
            if integrity_key.len() != integrity.key_size() {
                return Err(PacketProtectionError::InvalidKeyMaterial);
            }
            let iv = material
                .iv
                .as_slice()
                .try_into()
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            Ok(Self::Ctr(CtrState {
                cipher: suite.cipher,
                integrity,
                encryption_key: material.encryption_key,
                integrity_key,
                iv: Zeroizing::new(iv),
                position: 0,
            }))
        }
    }
}

/// Stateful SSH packet encryption and authentication for one key context.
///
/// A protector owns the continuous AES-CTR byte position, but it deliberately
/// does not own or increment the packet sequence number. Every [`Self::seal`]
/// and [`Self::open`] call receives that value explicitly. A CTR byte position
/// is committed only after the complete operation, including authentication and
/// padding validation, succeeds.
///
/// Constructing a new protector intentionally starts a fresh key context. Use
/// [`Self::rekey`] to replace an existing context's suite, keys, and IV. The
/// caller must keep AES-GCM sequence numbers unique within a key context; this
/// type intentionally does not retain or enforce sequence policy.
pub(crate) struct PacketProtector {
    suite: PacketSuite,
    compression: CompressionAlgorithm,
    state: ProtectorState,
}

impl fmt::Debug for PacketProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketProtector")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl PacketProtector {
    /// Creates a protector from a validated suite and already-derived keys.
    ///
    /// The IV must contain 16 bytes for CTR, 12 bytes for AES-GCM, or two zero
    /// words for ChaCha20-Poly1305. AES key sizes are 16 or 32 bytes; the
    /// ChaCha20-Poly1305 key is 64 bytes. HMAC-SHA2 integrity keys must contain
    /// 32 or 64 bytes as appropriate, and AEAD suites must not receive a
    /// separate key.
    ///
    /// # Errors
    ///
    /// Returns [`PacketProtectionError::InvalidKeyMaterial`] for any missing,
    /// unexpected, or incorrectly sized key component.
    pub(crate) fn new(
        suite: PacketSuite,
        key_material: PacketKeyMaterial,
    ) -> Result<Self, PacketProtectionError> {
        Self::new_with_compression(suite, key_material, CompressionAlgorithm::None)
    }

    /// Creates a protector with a negotiated packet compression mode.
    ///
    /// Compression is applied to the payload before packet framing and removed
    /// only after authenticated packet opening succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`PacketProtectionError::InvalidCompression`] for an unsupported
    /// compression name and propagates key-material validation errors.
    pub(crate) fn new_with_compression(
        suite: PacketSuite,
        key_material: PacketKeyMaterial,
        compression: CompressionAlgorithm,
    ) -> Result<Self, PacketProtectionError> {
        Ok(Self {
            state: ProtectorState::new(suite, key_material)?,
            suite,
            compression,
        })
    }

    /// Returns the negotiated compression mode.
    #[must_use]
    pub(crate) const fn compression(&self) -> CompressionAlgorithm {
        self.compression
    }

    /// Returns this protector's current packet-protection suite.
    #[must_use]
    pub(crate) const fn suite(&self) -> PacketSuite {
        self.suite
    }

    /// Decrypts only an encrypted four-byte packet length field.
    ///
    /// This performs no authentication and performs no allocation based on the
    /// decrypted value. The transport must apply its bounds and alignment
    /// checks before reading or allocating the remaining packet. AES-CTR
    /// encrypt-and-MAC packets use the same continuous CTR position as packet
    /// opening; the position is not changed by this operation.
    pub(crate) fn decrypt_length(
        &self,
        sequence_number: u32,
        input: &[u8],
    ) -> Result<u32, PacketProtectionError> {
        match &self.state {
            ProtectorState::Chacha(state) => state
                .cipher
                .decrypt_length(sequence_number, input)
                .map_err(map_chacha_error),
            ProtectorState::Ctr(state) if state.integrity.encrypt_then_mac() => {
                Err(PacketProtectionError::UnsupportedSuite)
            }
            ProtectorState::Ctr(state) => {
                if input.len() < 4 {
                    return Err(PacketProtectionError::Truncated);
                }
                if input.len() != 4 {
                    return Err(PacketProtectionError::InvalidPacket);
                }
                let mut clear = Zeroizing::new([0_u8; 4]);
                clear.copy_from_slice(input);
                let _next_position = apply_ctr(
                    state.cipher,
                    &state.encryption_key,
                    &state.iv,
                    state.position,
                    clear.as_mut_slice(),
                )?;
                Ok(u32::from_be_bytes(*clear))
            }
            ProtectorState::Gcm(_) => Err(PacketProtectionError::UnsupportedSuite),
        }
    }

    /// Replaces the suite, IV, and keys at an explicit rekey boundary.
    ///
    /// Validation completes before the old key context is replaced. CTR
    /// position and GCM nonce-key context therefore change only through this
    /// explicit operation, not because a caller reused a sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`PacketProtectionError::InvalidKeyMaterial`] if the new suite
    /// and material are incompatible. The existing context remains unchanged.
    pub(crate) fn rekey(
        &mut self,
        suite: PacketSuite,
        key_material: PacketKeyMaterial,
    ) -> Result<(), PacketProtectionError> {
        self.rekey_with_compression(suite, key_material, self.compression)
    }

    /// Replaces the suite, keys, and compression mode at a rekey boundary.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the existing context if the new
    /// material is invalid.
    pub(crate) fn rekey_with_compression(
        &mut self,
        suite: PacketSuite,
        key_material: PacketKeyMaterial,
        compression: CompressionAlgorithm,
    ) -> Result<(), PacketProtectionError> {
        let state = ProtectorState::new(suite, key_material)?;
        self.suite = suite;
        self.compression = compression;
        self.state = state;
        Ok(())
    }

    /// Seals one payload and caller-supplied padding at `sequence_number`.
    ///
    /// Padding must contain at least four bytes and must be the length
    /// [`PacketAlignment::padding_length`] returns for this suite and payload,
    /// which is what `transport::random_padding` supplies. The suite decides
    /// both the block size and whether `packet_length` or `4 + packet_length`
    /// is the aligned quantity; see [`PacketAlignment`] for the rule and for
    /// the OpenSSH source it comes from. `packet_length` counts the
    /// padding-length byte, the payload, and the padding, but not its own
    /// four-byte field or the authentication tag. Supplying padding
    /// explicitly makes framing deterministic for tests and allows a transport
    /// to use its cryptographic random source.
    ///
    /// # Errors
    ///
    /// Returns [`PacketProtectionError::InvalidPadding`],
    /// [`PacketProtectionError::InvalidAlignment`], or
    /// [`PacketProtectionError::LimitExceeded`] for invalid framing. It can
    /// also return key-state errors for an exhausted suite counter or a local
    /// AES-GCM failure.
    pub(crate) fn seal(
        &mut self,
        sequence_number: u32,
        payload: &[u8],
        padding: &[u8],
    ) -> Result<Vec<u8>, PacketProtectionError> {
        // The caller's bytes are copied so this function can hand a different
        // payload to the cipher when compression is on, and the copy is in the
        // clear, so it is a buffer that wipes itself. The padding copy is not
        // one: it is drawn from the random source rather than from the payload,
        // so it discloses nothing, and it is sealed along with the rest of the
        // packet.
        let (payload, padding) = match self.compression {
            CompressionAlgorithm::None => (
                PlaintextBytes::new(PlaintextSlot::SealInput, payload.to_vec()),
                padding.to_vec(),
            ),
            CompressionAlgorithm::Zlib => {
                // Wrapped before the fallible call below, not after it: a `?`
                // that fires there would otherwise release the compressed
                // payload — which is this caller's bytes, in the clear — as a
                // plain `Vec`.
                let compressed = PlaintextBytes::new(
                    PlaintextSlot::SealInput,
                    compress_payload(payload).map_err(map_compression_error)?,
                );
                // Compression changes the payload length after the transport
                // chose the padding, so the length has to be re-derived from
                // the same rule while keeping the random bytes already drawn.
                let alignment = PacketAlignment::for_suite(self.suite);
                let padding = padding_for_payload(
                    compressed.as_slice().len(),
                    padding,
                    alignment.block_size(),
                    alignment.header_length(),
                )
                .map_err(map_compression_error)?;
                (compressed, padding)
            }
        };
        self.seal_payload(sequence_number, payload.as_slice(), &padding)
    }

    fn seal_payload(
        &mut self,
        sequence_number: u32,
        payload: &[u8],
        padding: &[u8],
    ) -> Result<Vec<u8>, PacketProtectionError> {
        let alignment = PacketAlignment::for_suite(self.suite);
        let mut clear_packet = PlaintextBytes::new(
            PlaintextSlot::ClearPacket,
            build_clear_packet(payload, padding, alignment)?,
        );
        if let ProtectorState::Chacha(state) = &self.state {
            // The ChaCha suite seals into a buffer of its own, so this one is
            // dropped with the whole clear packet still in it. It is the one
            // *successful* path where a plain `Vec` would have released the
            // plaintext, and it is why the buffer is a type rather than a local.
            return state
                .cipher
                .seal(sequence_number, clear_packet.as_slice())
                .map_err(map_chacha_error);
        }
        match &mut self.state {
            ProtectorState::Ctr(state) => {
                if state.integrity.encrypt_then_mac() {
                    let (length, body) = clear_packet.as_mut_slice().split_at_mut(4);
                    let next_position = apply_ctr(
                        state.cipher,
                        &state.encryption_key,
                        &state.iv,
                        state.position,
                        body,
                    )?;
                    let tag = calculate_mac(
                        state.integrity,
                        &state.integrity_key,
                        sequence_number,
                        &[length, body],
                    )?;
                    clear_packet.extend(tag.as_slice());
                    state.position = next_position;
                } else {
                    let tag = calculate_mac(
                        state.integrity,
                        &state.integrity_key,
                        sequence_number,
                        &[clear_packet.as_slice()],
                    )?;
                    let next_position = apply_ctr(
                        state.cipher,
                        &state.encryption_key,
                        &state.iv,
                        state.position,
                        clear_packet.as_mut_slice(),
                    )?;
                    clear_packet.extend(tag.as_slice());
                    state.position = next_position;
                }
            }
            ProtectorState::Gcm(state) => {
                let (length, body) = clear_packet.as_mut_slice().split_at_mut(4);
                let packets_processed = state
                    .packets_processed
                    .ok_or(PacketProtectionError::CounterExhausted)?;
                let tag = encrypt_gcm(
                    state.cipher,
                    &state.encryption_key,
                    &state.iv,
                    packets_processed,
                    length,
                    body,
                )?;
                clear_packet.extend(tag.as_slice());
                state.packets_processed = packets_processed.checked_add(1);
            }
            ProtectorState::Chacha(_) => {
                return Err(PacketProtectionError::InvalidPacket);
            }
        }
        // The in-place suites have overwritten the buffer, so what it holds now
        // is the sealed packet and not a copy of the plaintext.
        Ok(clear_packet.into_ciphertext())
    }

    /// Authenticates and opens one complete protected packet.
    ///
    /// `input` must contain exactly one EAM, ETM, OpenSSH AES-GCM, or
    /// OpenSSH ChaCha20-Poly1305 packet; stream framing remains the transport
    /// layer's responsibility. Plaintext is returned only after successful
    /// authentication and padding checks. A failed open does not commit a CTR
    /// state change.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PacketProtectionError`] for truncation, malformed or
    /// oversized clear lengths, invalid alignment or padding, and invalid HMAC
    /// or GCM tags.
    pub(crate) fn open(
        &mut self,
        sequence_number: u32,
        input: &[u8],
    ) -> Result<Vec<u8>, PacketProtectionError> {
        let compression = self.compression;
        let alignment = PacketAlignment::for_suite(self.suite);
        match &mut self.state {
            ProtectorState::Ctr(state) if state.integrity.encrypt_then_mac() => {
                open_etm(state, sequence_number, input, compression, alignment)
            }
            ProtectorState::Ctr(state) => {
                open_eam(state, sequence_number, input, compression, alignment)
            }
            ProtectorState::Gcm(state) => open_gcm(state, input, compression, alignment),
            ProtectorState::Chacha(state) => {
                open_chacha(state, sequence_number, input, compression, alignment)
            }
        }
    }
}

/// The widest authentication tag any suite appends after the clear packet.
///
/// `build_clear_packet` reserves this much room, so sealing a packet appends the
/// tag without reallocating. A reallocation would copy the clear packet into a
/// second allocation and free the first one, and an allocator does not wipe
/// what it frees: the plaintext would be readable in the block the seal
/// released, on every packet rather than only on the credential ones.
const MAX_AUTH_TAG_SIZE: usize = SHA512_KEY_SIZE;

/// A heap buffer holding bytes that are in the clear.
///
/// Sealing a packet needs the plaintext in an allocation the caller owns, and
/// an ordinary `Vec<u8>` that is merely dropped leaves those bytes readable in
/// freed memory. Every plaintext buffer on the outbound path is one of these:
/// the request a caller assembles before writing it, the copy a seal works
/// from, the clear packet a cipher overwrites, and the payload a transport
/// keeps to recognise a retried write. One type for all four, because the
/// alternative is four places to forget.
///
/// # When the bytes stop being in the clear
///
/// A seal that encrypts in place turns the buffer into the ciphertext it
/// returns, and [`Self::into_ciphertext`] hands that allocation on without
/// wiping it. Every other path drops the buffer with the plaintext still in it
/// and the [`Drop`] below wipes it. That includes a *successful* seal over
/// `chacha20-poly1305`, which encrypts into a buffer of its own and would
/// otherwise release the whole clear packet in the clear on the way out.
///
/// # What this does not cover
///
/// Growing the buffer is not covered, and cannot be without a growable type
/// that wipes before every reallocation. Each site here is arranged so that
/// nothing it frees can hold the secret: the password is the last field a
/// request appends, `seal`'s input copy and a transport's retained payload are
/// exact-size allocations, and `build_clear_packet` reserves room for the tag
/// for this reason.
pub(crate) struct PlaintextBytes {
    bytes: Vec<u8>,
    slot: PlaintextSlot,
}

impl PlaintextBytes {
    /// Takes ownership of `bytes`, which are in the clear.
    pub(crate) const fn new(slot: PlaintextSlot, bytes: Vec<u8>) -> Self {
        Self { bytes, slot }
    }

    /// Returns the bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the bytes mutably, for the in-place cipher suites.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Appends bytes, for the authentication tag a seal computes last.
    pub(crate) fn extend(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Hands the allocation on, because a seal has overwritten it with the
    /// ciphertext and there is nothing left in it to wipe.
    pub(crate) fn into_ciphertext(mut self) -> Vec<u8> {
        let bytes = std::mem::take(&mut self.bytes);
        #[cfg(test)]
        record_plaintext_drop(self.slot, PlaintextDrop::HandedOn);
        bytes
    }
}

impl Zeroize for PlaintextBytes {
    fn zeroize(&mut self) {
        // The slice, not the `Vec`: zeroizing the `Vec` clears its length, and
        // a wiped buffer that has forgotten how long it was cannot be read back
        // to prove the wipe happened.
        self.bytes.as_mut_slice().zeroize();
    }
}

impl Drop for PlaintextBytes {
    fn drop(&mut self) {
        // The witness is read back in this body, and three things make that a
        // reading of the wipe rather than of freed memory. A destructor's body
        // runs to completion before the fields are dropped, so the allocation
        // is still live throughout it; the wipe above is a slice zeroize, which
        // leaves the length alone, so what is read afterwards is the same set of
        // bytes that was there before rather than a vector that has forgotten
        // how long it was; and `held_bytes` is a search for a byte that was not
        // zero, so a buffer that held nothing to destroy records nothing rather
        // than a wipe that proves nothing.
        #[cfg(test)]
        let held_bytes = self.bytes.iter().any(|byte| *byte != 0);
        self.zeroize();
        #[cfg(test)]
        if held_bytes {
            let wiped = self.bytes.iter().all(|byte| *byte == 0);
            record_plaintext_drop(
                self.slot,
                if wiped {
                    PlaintextDrop::Wiped
                } else {
                    PlaintextDrop::NotWiped
                },
            );
        }
    }
}

// The marker for the claim the `Drop` above actually makes. It is a marker, so
// the compiler checks that the claim is written down and not that it is kept:
// dropping the `Drop`, or emptying its body, leaves both this and the `const`
// item below compiling. The tests that drive each site are what check the
// second half, by emptying a real buffer through the destructor and reading
// what it left.
impl ZeroizeOnDrop for PlaintextBytes {}

const _: () = {
    wipes_itself_on_drop::<PlaintextBytes>();
};

/// Which plaintext buffer a [`PlaintextBytes`] is.
///
/// One variant per site on the outbound path. The wipe witness is recorded per
/// slot rather than in one channel, because the test scheduler reuses threads
/// and because a single password request passes through three of these buffers
/// in one call: without the slots a test could not attribute a record to the
/// site it meant, or could read another test's record on the same thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
// A test binary that includes this module without `auth.rs` has no
// `AuthRequest` to construct, and the other three are unused there the other way
// round. The slots are the witness table's shape, not any one binary's traffic.
#[allow(dead_code)]
pub(crate) enum PlaintextSlot {
    /// The encoded request a caller assembles before writing it.
    AuthRequest,
    /// The copy [`PacketProtector::seal`] works from.
    SealInput,
    /// The clear packet a seal encrypts.
    ClearPacket,
    /// The payload a transport keeps to recognise a retried write.
    PendingPayload,
}

/// The size of the wipe-witness table, taken from the last slot.
///
/// A new site needs a new variant and nothing else. A slot that is not in this
/// range is a test that panics rather than a record that overwrites another
/// site's.
#[cfg(test)]
const PLAINTEXT_SLOT_COUNT: usize = PlaintextSlot::PendingPayload as usize + 1;

/// What one [`PlaintextBytes`] destructor found.
///
/// Three answers rather than a boolean, because a boolean passes vacuously in
/// both directions. A buffer that held no non-zero byte to begin with is all
/// zeroes before a wipe as well as after one, so it records nothing at all and
/// cannot be read as [`Self::Wiped`]; and the buffer a seal hands on is all
/// zeroes for a reason that has nothing to do with the wipe, which is what
/// [`Self::HandedOn`] is for. [`Self::Wiped`] therefore also proves the buffer
/// held a byte worth destroying, and [`Self::HandedOn`] proves the seal path did
/// not wipe the bytes it returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlaintextDrop {
    /// The buffer held a byte that was not zero, and every byte was zero by the
    /// time the destructor had released nothing yet.
    Wiped,
    /// The buffer held a byte that was not zero, and some bytes were still
    /// readable at that moment.
    NotWiped,
    /// [`PlaintextBytes::into_ciphertext`] handed the allocation on; the bytes
    /// in it were ciphertext by then.
    HandedOn,
}

#[cfg(test)]
thread_local! {
    /// What the last [`PlaintextBytes`] destructor to run on this thread found,
    /// per [`PlaintextSlot`]. `None` where nothing has been recorded since the
    /// value was last taken, and that is a distinct answer from any of the three:
    /// a destructor that was deleted leaves no record at all, and so does a
    /// buffer that held no non-zero byte to destroy. A test that expects a wipe
    /// has to fail on either of those as well as on a wipe that did not happen.
    ///
    /// A thread-local is the whole of the mechanism, not a convenience, and the
    /// reason is that the crate forbids `unsafe`. A test cannot read a buffer
    /// back after it is freed, `docs/standards.md` forbids process-wide mutable
    /// state so a `static` counter is not available either, and the destructor
    /// is the only code that runs while the bytes are still readable. A
    /// thread-local cell is what is left. It is the same answer
    /// `kex::DerivedKeys` and `kex::Group16Private` already give in this crate.
    static PLAINTEXT_DROPS: [std::cell::Cell<Option<PlaintextDrop>>; PLAINTEXT_SLOT_COUNT] = const { [const { std::cell::Cell::new(None) }; PLAINTEXT_SLOT_COUNT] };
}

/// Takes the last wipe witness recorded for one slot on this thread.
///
/// Taking clears the record, so a caller reads only the destructors that ran
/// after its own setup.
///
/// # Panics
///
/// Never. `Cell::take` on a live thread-local value cannot fail.
#[cfg(test)]
#[allow(dead_code)] // Only the test binary that drives a given site calls it.
pub(crate) fn take_plaintext_drop(slot: PlaintextSlot) -> Option<PlaintextDrop> {
    PLAINTEXT_DROPS.with(|drops| drops[slot as usize].take())
}

/// Records one destructor finding for the slot it belongs to.
#[cfg(test)]
fn record_plaintext_drop(slot: PlaintextSlot, outcome: PlaintextDrop) {
    PLAINTEXT_DROPS.with(|drops| drops[slot as usize].set(Some(outcome)));
}

impl fmt::Debug for PlaintextBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The bytes are the reason this type exists, so the length and the site
        // are what a diagnostic gets.
        formatter
            .debug_struct("PlaintextBytes")
            .field("slot", &self.slot)
            .field("len", &self.bytes.len())
            .finish()
    }
}

fn build_clear_packet(
    payload: &[u8],
    padding: &[u8],
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    if !(MIN_PADDING..=u8::MAX as usize).contains(&padding.len()) {
        return Err(PacketProtectionError::InvalidPadding);
    }
    let content_size = payload
        .len()
        .checked_add(padding.len())
        .ok_or(PacketProtectionError::LimitExceeded)?;
    if content_size > MAX_PACKET_CONTENT {
        return Err(PacketProtectionError::LimitExceeded);
    }
    let packet_length = content_size
        .checked_add(1)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    let total_size = packet_length
        .checked_add(4)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    alignment.validate_packet_length(packet_length)?;
    let packet_length =
        u32::try_from(packet_length).map_err(|_error| PacketProtectionError::LimitExceeded)?;
    let padding_length =
        u8::try_from(padding.len()).map_err(|_error| PacketProtectionError::InvalidPadding)?;

    // Room for the tag, so the seal that appends it does not reallocate a
    // buffer holding the clear packet. See [`MAX_AUTH_TAG_SIZE`].
    let mut packet = Vec::with_capacity(total_size.saturating_add(MAX_AUTH_TAG_SIZE));
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(padding_length);
    packet.extend_from_slice(payload);
    packet.extend_from_slice(padding);
    Ok(packet)
}

fn open_chacha(
    state: &mut ChachaState,
    sequence_number: u32,
    input: &[u8],
    compression: CompressionAlgorithm,
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    let clear = state
        .cipher
        .open(sequence_number, input)
        .map_err(map_chacha_error)?;
    // The ChaCha layer has already consumed and verified the Poly1305 tag, so
    // what is left is exactly the clear packet with no trailing tag.
    let packet = parse_clear_packet(&clear, 0, alignment)?;
    let payload = extract_body_payload(packet.body, packet.content_size)?;
    decompress_if_selected(payload, compression)
}

fn decompress_if_selected(
    payload: Vec<u8>,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, PacketProtectionError> {
    match compression {
        CompressionAlgorithm::None => Ok(payload),
        CompressionAlgorithm::Zlib => decompress_payload(&payload).map_err(map_compression_error),
    }
}

fn map_compression_error(error: CompressionError) -> PacketProtectionError {
    match error {
        CompressionError::LimitExceeded => PacketProtectionError::LimitExceeded,
        CompressionError::InvalidStream | CompressionError::CompressionFailed => {
            PacketProtectionError::InvalidCompression
        }
    }
}

fn map_chacha_error(error: ChaChaCipherError) -> PacketProtectionError {
    match error {
        ChaChaCipherError::InvalidKeyMaterial => PacketProtectionError::InvalidKeyMaterial,
        ChaChaCipherError::Truncated => PacketProtectionError::Truncated,
        ChaChaCipherError::LimitExceeded => PacketProtectionError::LimitExceeded,
        ChaChaCipherError::InvalidPacket => PacketProtectionError::InvalidPacket,
        ChaChaCipherError::AuthenticationFailed => PacketProtectionError::AuthenticationFailed,
        ChaChaCipherError::EncryptionFailed => PacketProtectionError::EncryptionFailed,
    }
}

fn open_eam(
    state: &mut CtrState,
    sequence_number: u32,
    input: &[u8],
    compression: CompressionAlgorithm,
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    let tag_size = state.integrity.tag_size();
    let minimum_size = alignment
        .block_size()
        .checked_add(tag_size)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    if input.len() < minimum_size {
        return Err(PacketProtectionError::Truncated);
    }
    let encrypted_size = input
        .len()
        .checked_sub(tag_size)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    if encrypted_size % alignment.block_size() != 0 {
        return Err(PacketProtectionError::InvalidAlignment);
    }
    let content_size = encrypted_size
        .checked_sub(5)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    if content_size > MAX_PACKET_CONTENT {
        return Err(PacketProtectionError::LimitExceeded);
    }
    let encrypted_end = encrypted_size;
    let encrypted = input
        .get(..encrypted_end)
        .ok_or(PacketProtectionError::Truncated)?;
    let tag = input
        .get(encrypted_end..)
        .ok_or(PacketProtectionError::Truncated)?;

    let mut clear_packet = Zeroizing::new(Vec::with_capacity(encrypted_size));
    clear_packet.extend_from_slice(encrypted);
    let next_position = apply_ctr(
        state.cipher,
        &state.encryption_key,
        &state.iv,
        state.position,
        &mut clear_packet,
    )?;
    verify_mac(
        state.integrity,
        &state.integrity_key,
        sequence_number,
        &[&clear_packet],
        tag,
    )?;
    let payload = extract_eam_payload(&clear_packet, content_size, alignment)?;
    let payload = decompress_if_selected(payload, compression)?;
    state.position = next_position;
    Ok(payload)
}

fn open_etm(
    state: &mut CtrState,
    sequence_number: u32,
    input: &[u8],
    compression: CompressionAlgorithm,
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    let packet = parse_clear_packet(input, state.integrity.tag_size(), alignment)?;
    verify_mac(
        state.integrity,
        &state.integrity_key,
        sequence_number,
        &[packet.length, packet.body],
        packet.tag,
    )?;

    let mut body = Zeroizing::new(Vec::from(packet.body));
    let next_position = apply_ctr(
        state.cipher,
        &state.encryption_key,
        &state.iv,
        state.position,
        &mut body,
    )?;
    let content_size = body
        .len()
        .checked_sub(1)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    let payload = extract_body_payload(&body, content_size)?;
    let payload = decompress_if_selected(payload, compression)?;
    state.position = next_position;
    Ok(payload)
}

fn open_gcm(
    state: &mut GcmState,
    input: &[u8],
    compression: CompressionAlgorithm,
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    let packet = parse_clear_packet(input, GCM_TAG_SIZE, alignment)?;
    let packets_processed = state
        .packets_processed
        .ok_or(PacketProtectionError::CounterExhausted)?;
    let mut body = Zeroizing::new(Vec::from(packet.body));
    decrypt_gcm(
        state.cipher,
        &state.encryption_key,
        &state.iv,
        packets_processed,
        packet.length,
        &mut body,
        packet.tag,
    )?;
    let content_size = body
        .len()
        .checked_sub(1)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    let payload = extract_body_payload(&body, content_size)?;
    let payload = decompress_if_selected(payload, compression)?;
    state.packets_processed = packets_processed.checked_add(1);
    Ok(payload)
}

struct ClearPacket<'a> {
    length: &'a [u8],
    body: &'a [u8],
    tag: &'a [u8],
    content_size: usize,
}

fn parse_clear_packet(
    input: &[u8],
    tag_size: usize,
    alignment: PacketAlignment,
) -> Result<ClearPacket<'_>, PacketProtectionError> {
    let length = input.get(..4).ok_or(PacketProtectionError::Truncated)?;
    let length_bytes: [u8; 4] = length
        .try_into()
        .map_err(|_error| PacketProtectionError::Truncated)?;
    let packet_length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_error| PacketProtectionError::LimitExceeded)?;
    if packet_length == 0 {
        return Err(PacketProtectionError::InvalidPacket);
    }
    let content_size = packet_length
        .checked_sub(1)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    if content_size > MAX_PACKET_CONTENT {
        return Err(PacketProtectionError::LimitExceeded);
    }
    if content_size < MIN_PADDING {
        return Err(PacketProtectionError::InvalidPadding);
    }
    let total_size = packet_length
        .checked_add(4)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    alignment.validate_packet_length(packet_length)?;
    let expected_size = total_size
        .checked_add(tag_size)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    if input.len() < expected_size {
        return Err(PacketProtectionError::Truncated);
    }
    if input.len() != expected_size {
        return Err(PacketProtectionError::InvalidPacket);
    }
    let body_end = total_size;
    let body = input
        .get(4..body_end)
        .ok_or(PacketProtectionError::Truncated)?;
    let tag = input
        .get(body_end..expected_size)
        .ok_or(PacketProtectionError::Truncated)?;
    Ok(ClearPacket {
        length,
        body,
        tag,
        content_size,
    })
}

fn extract_eam_payload(
    packet: &[u8],
    expected_content_size: usize,
    alignment: PacketAlignment,
) -> Result<Vec<u8>, PacketProtectionError> {
    let length = packet.get(..4).ok_or(PacketProtectionError::Truncated)?;
    let length_bytes: [u8; 4] = length
        .try_into()
        .map_err(|_error| PacketProtectionError::Truncated)?;
    let packet_length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_error| PacketProtectionError::LimitExceeded)?;
    let expected_packet_size = expected_content_size
        .checked_add(1)
        .and_then(|size| size.checked_add(4))
        .ok_or(PacketProtectionError::InvalidPacket)?;
    let expected_packet_length = expected_packet_size
        .checked_sub(4)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    if packet.len() != expected_packet_size || packet_length != expected_packet_length {
        return Err(PacketProtectionError::InvalidPacket);
    }
    alignment
        .validate_packet_length(expected_packet_length)
        .map_err(|_error| PacketProtectionError::InvalidPacket)?;
    let body = packet
        .get(4..)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    extract_body_payload(body, expected_content_size)
}

fn extract_body_payload(
    body: &[u8],
    content_size: usize,
) -> Result<Vec<u8>, PacketProtectionError> {
    if content_size < MIN_PADDING || body.len() != content_size.saturating_add(1) {
        return Err(if body.len() == content_size.saturating_add(1) {
            PacketProtectionError::InvalidPadding
        } else {
            PacketProtectionError::InvalidPacket
        });
    }
    let padding_length = body
        .first()
        .copied()
        .ok_or(PacketProtectionError::Truncated)? as usize;
    if padding_length < MIN_PADDING {
        return Err(PacketProtectionError::InvalidPadding);
    }
    if padding_length > content_size {
        return Err(PacketProtectionError::InvalidPacket);
    }
    let payload_size = content_size
        .checked_sub(padding_length)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    let payload_end = 1_usize
        .checked_add(payload_size)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    body.get(1..payload_end)
        .map(<[u8]>::to_vec)
        .ok_or(PacketProtectionError::InvalidPacket)
}

fn apply_ctr(
    cipher: CipherAlgorithm,
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    position: u128,
    data: &mut [u8],
) -> Result<u128, PacketProtectionError> {
    let data_size =
        u128::try_from(data.len()).map_err(|_error| PacketProtectionError::LimitExceeded)?;
    let next_position = position
        .checked_add(data_size)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    validate_ctr_range(iv, position, data.len())?;
    if data.is_empty() {
        return Ok(next_position);
    }

    let first_block = position / AES_BLOCK_SIZE as u128;
    let byte_offset = usize::try_from(position % AES_BLOCK_SIZE as u128)
        .map_err(|_error| PacketProtectionError::CounterExhausted)?;
    let base_counter = u128::from_be_bytes(*iv);
    let counter = base_counter
        .checked_add(first_block)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    let mut stream = new_ctr_stream(cipher, key, &counter.to_be_bytes())?;

    if byte_offset == 0 {
        stream
            .try_apply_keystream(data)
            .map_err(|_error| PacketProtectionError::CounterExhausted)?;
        return Ok(next_position);
    }

    let mut block = Zeroizing::new([0_u8; AES_BLOCK_SIZE]);
    stream
        .try_apply_keystream(block.as_mut_slice())
        .map_err(|_error| PacketProtectionError::CounterExhausted)?;
    let available = AES_BLOCK_SIZE
        .checked_sub(byte_offset)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    let consumed = available.min(data.len());
    let target = data
        .get_mut(..consumed)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    let keystream = block
        .get(byte_offset..byte_offset.saturating_add(consumed))
        .ok_or(PacketProtectionError::CounterExhausted)?;
    for (byte, mask) in target.iter_mut().zip(keystream) {
        *byte ^= *mask;
    }
    stream
        .try_apply_keystream(&mut data[consumed..])
        .map_err(|_error| PacketProtectionError::CounterExhausted)?;
    Ok(next_position)
}

fn validate_ctr_range(
    iv: &[u8; AES_BLOCK_SIZE],
    position: u128,
    data_size: usize,
) -> Result<(), PacketProtectionError> {
    let first_block = position / AES_BLOCK_SIZE as u128;
    let byte_offset = position % AES_BLOCK_SIZE as u128;
    let data_size =
        u128::try_from(data_size).map_err(|_error| PacketProtectionError::LimitExceeded)?;
    let touched_size = byte_offset
        .checked_add(data_size)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    let block_count = touched_size.div_ceil(AES_BLOCK_SIZE as u128);
    if block_count == 0 {
        return Ok(());
    }
    let first_counter = u128::from_be_bytes(*iv)
        .checked_add(first_block)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    first_counter
        .checked_add(block_count - 1)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    Ok(())
}

fn new_ctr_stream(
    cipher: CipherAlgorithm,
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<CtrStream, PacketProtectionError> {
    match cipher {
        CipherAlgorithm::Aes128Ctr => Aes128Ctr::new_from_slices(key, iv)
            .map(|stream| CtrStream::Aes128(Box::new(stream)))
            .map_err(|_error| PacketProtectionError::InvalidKeyMaterial),
        CipherAlgorithm::Aes256Ctr => Aes256Ctr::new_from_slices(key, iv)
            .map(|stream| CtrStream::Aes256(Box::new(stream)))
            .map_err(|_error| PacketProtectionError::InvalidKeyMaterial),
        CipherAlgorithm::Aes128Gcm
        | CipherAlgorithm::Aes256Gcm
        | CipherAlgorithm::Chacha20Poly1305 => Err(PacketProtectionError::InvalidKeyMaterial),
    }
}

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

enum CtrStream {
    Aes128(Box<Aes128Ctr>),
    Aes256(Box<Aes256Ctr>),
}

impl StreamCipher for CtrStream {
    fn check_remaining(&self, data_len: usize) -> Result<(), aes::cipher::StreamCipherError> {
        match self {
            Self::Aes128(stream) => stream.check_remaining(data_len),
            Self::Aes256(stream) => stream.check_remaining(data_len),
        }
    }

    fn unchecked_apply_keystream_inout(&mut self, buffer: aes::cipher::InOutBuf<'_, '_, u8>) {
        match self {
            Self::Aes128(stream) => stream.unchecked_apply_keystream_inout(buffer),
            Self::Aes256(stream) => stream.unchecked_apply_keystream_inout(buffer),
        }
    }

    fn unchecked_write_keystream(&mut self, buffer: &mut [u8]) {
        match self {
            Self::Aes128(stream) => stream.unchecked_write_keystream(buffer),
            Self::Aes256(stream) => stream.unchecked_write_keystream(buffer),
        }
    }
}

enum CalculatedTag {
    Sha256(Zeroizing<[u8; SHA256_KEY_SIZE]>),
    Sha512(Zeroizing<[u8; SHA512_KEY_SIZE]>),
}

impl CalculatedTag {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(tag) => tag.as_slice(),
            Self::Sha512(tag) => tag.as_slice(),
        }
    }
}

fn calculate_mac(
    integrity: IntegrityAlgorithm,
    key: &[u8],
    sequence_number: u32,
    parts: &[&[u8]],
) -> Result<CalculatedTag, PacketProtectionError> {
    let sequence = sequence_number.to_be_bytes();
    match integrity {
        IntegrityAlgorithm::HmacSha256 | IntegrityAlgorithm::HmacSha256Etm => {
            let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            mac.update(&sequence);
            for part in parts {
                mac.update(part);
            }
            let mut output = hmac::digest::Output::<HmacSha256>::default();
            hmac::digest::FixedOutput::finalize_into(mac, &mut output);
            let mut tag = Zeroizing::new([0_u8; SHA256_KEY_SIZE]);
            tag.copy_from_slice(output.as_slice());
            output.as_mut_slice().zeroize();
            Ok(CalculatedTag::Sha256(tag))
        }
        IntegrityAlgorithm::HmacSha512 | IntegrityAlgorithm::HmacSha512Etm => {
            let mut mac = <HmacSha512 as hmac::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            mac.update(&sequence);
            for part in parts {
                mac.update(part);
            }
            let mut output = hmac::digest::Output::<HmacSha512>::default();
            hmac::digest::FixedOutput::finalize_into(mac, &mut output);
            let mut tag = Zeroizing::new([0_u8; SHA512_KEY_SIZE]);
            tag.copy_from_slice(output.as_slice());
            output.as_mut_slice().zeroize();
            Ok(CalculatedTag::Sha512(tag))
        }
    }
}

fn verify_mac(
    integrity: IntegrityAlgorithm,
    key: &[u8],
    sequence_number: u32,
    parts: &[&[u8]],
    tag: &[u8],
) -> Result<(), PacketProtectionError> {
    let sequence = sequence_number.to_be_bytes();
    match integrity {
        IntegrityAlgorithm::HmacSha256 | IntegrityAlgorithm::HmacSha256Etm => {
            let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            mac.update(&sequence);
            for part in parts {
                mac.update(part);
            }
            mac.verify_slice(tag)
                .map_err(|_error| PacketProtectionError::AuthenticationFailed)
        }
        IntegrityAlgorithm::HmacSha512 | IntegrityAlgorithm::HmacSha512Etm => {
            let mut mac = <HmacSha512 as hmac::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            mac.update(&sequence);
            for part in parts {
                mac.update(part);
            }
            mac.verify_slice(tag)
                .map_err(|_error| PacketProtectionError::AuthenticationFailed)
        }
    }
}

fn encrypt_gcm(
    cipher: CipherAlgorithm,
    key: &[u8],
    iv: &[u8; GCM_IV_SIZE],
    packets_processed: u64,
    length: &[u8],
    body: &mut [u8],
) -> Result<Zeroizing<[u8; GCM_TAG_SIZE]>, PacketProtectionError> {
    let nonce_bytes = gcm_nonce(iv, packets_processed)?;
    let nonce: &GcmNonce = (&*nonce_bytes).into();
    match cipher {
        CipherAlgorithm::Aes128Gcm => {
            let cipher = <aes_gcm::Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            let mut generated = cipher
                .encrypt_inout_detached(nonce, length, (&mut *body).into())
                .map_err(|_error| PacketProtectionError::EncryptionFailed)?;
            let mut tag = Zeroizing::new([0_u8; GCM_TAG_SIZE]);
            tag.copy_from_slice(generated.as_slice());
            generated.as_mut_slice().zeroize();
            Ok(tag)
        }
        CipherAlgorithm::Aes256Gcm => {
            let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            let mut generated = cipher
                .encrypt_inout_detached(nonce, length, (&mut *body).into())
                .map_err(|_error| PacketProtectionError::EncryptionFailed)?;
            let mut tag = Zeroizing::new([0_u8; GCM_TAG_SIZE]);
            tag.copy_from_slice(generated.as_slice());
            generated.as_mut_slice().zeroize();
            Ok(tag)
        }
        CipherAlgorithm::Aes128Ctr
        | CipherAlgorithm::Aes256Ctr
        | CipherAlgorithm::Chacha20Poly1305 => Err(PacketProtectionError::InvalidKeyMaterial),
    }
}

fn decrypt_gcm(
    cipher: CipherAlgorithm,
    key: &[u8],
    iv: &[u8; GCM_IV_SIZE],
    packets_processed: u64,
    length: &[u8],
    body: &mut [u8],
    tag_bytes: &[u8],
) -> Result<(), PacketProtectionError> {
    if tag_bytes.len() != GCM_TAG_SIZE {
        return Err(PacketProtectionError::Truncated);
    }
    let mut tag = Zeroizing::new([0_u8; GCM_TAG_SIZE]);
    tag.copy_from_slice(tag_bytes);
    let tag: &GcmTag = (&*tag).into();
    let nonce_bytes = gcm_nonce(iv, packets_processed)?;
    let nonce: &GcmNonce = (&*nonce_bytes).into();
    match cipher {
        CipherAlgorithm::Aes128Gcm => {
            let cipher = <aes_gcm::Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            cipher
                .decrypt_inout_detached(nonce, length, (&mut *body).into(), tag)
                .map_err(|_error| PacketProtectionError::AuthenticationFailed)
        }
        CipherAlgorithm::Aes256Gcm => {
            let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key)
                .map_err(|_error| PacketProtectionError::InvalidKeyMaterial)?;
            cipher
                .decrypt_inout_detached(nonce, length, (&mut *body).into(), tag)
                .map_err(|_error| PacketProtectionError::AuthenticationFailed)
        }
        CipherAlgorithm::Aes128Ctr
        | CipherAlgorithm::Aes256Ctr
        | CipherAlgorithm::Chacha20Poly1305 => Err(PacketProtectionError::InvalidKeyMaterial),
    }
}

/// Build the nonce for the AES-GCM invocation at `packets_processed` in this key
/// epoch. RFC 5647 section 7.1 divides the derived IV into a fixed four-byte
/// field and an eight-byte invocation counter. The first protected packet uses
/// the derived IV unchanged; each subsequent protected packet advances the
/// trailing counter once. This counter is independent of SSH's packet sequence
/// number, which may include packets sent before `NEWKEYS` on peers without
/// strict key exchange.
fn gcm_nonce(
    iv: &[u8; GCM_IV_SIZE],
    packets_processed: u64,
) -> Result<Zeroizing<[u8; GCM_NONCE_SIZE]>, PacketProtectionError> {
    let mut nonce = Zeroizing::new([0_u8; GCM_NONCE_SIZE]);
    let target = nonce
        .get_mut(..GCM_NONCE_SIZE)
        .ok_or(PacketProtectionError::InvalidKeyMaterial)?;
    target.copy_from_slice(
        iv.get(..GCM_NONCE_SIZE)
            .ok_or(PacketProtectionError::InvalidKeyMaterial)?,
    );
    // The counter is the trailing eight octets, added as one big-endian integer so
    // a carry propagates out of the final four octets and into the four before
    // them, instead of wrapping the low four and repeating the nonce.
    let counter = target
        .get_mut(GCM_NONCE_SIZE - COUNTER_SIZE..)
        .ok_or(PacketProtectionError::InvalidKeyMaterial)?;
    let current = u64::from_be_bytes(
        counter
            .get(..COUNTER_SIZE)
            .and_then(|slice| <[u8; COUNTER_SIZE]>::try_from(slice).ok())
            .ok_or(PacketProtectionError::InvalidKeyMaterial)?,
    );
    let advanced = current
        .checked_add(packets_processed)
        .ok_or(PacketProtectionError::CounterExhausted)?;
    counter
        .get_mut(..COUNTER_SIZE)
        .ok_or(PacketProtectionError::InvalidKeyMaterial)?
        .copy_from_slice(&advanced.to_be_bytes());
    Ok(nonce)
}
