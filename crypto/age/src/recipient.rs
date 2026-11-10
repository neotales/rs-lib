//! Age recipient construction and stanza wrapping.

#![allow(clippy::explicit_auto_deref)]

use std::fmt;

use {
    rsa::RsaPublicKey,
    zeroize::{Zeroize, Zeroizing},
};

use crate::{
    bech32,
    codec::encode_raw,
    crypto::{
        FILE_KEY_LENGTH, SSH_ED25519_LABEL, X25519_LABEL, aead_encrypt, derive_scrypt_key,
        hkdf_sha256, random_array, rsa_oaep_encrypt, ssh_fingerprint, x25519_base, x25519_shared,
    },
    error::{AgeError, Result},
    header::Stanza,
    pq,
    ssh::{SshEd25519Key, SshEd25519PublicKey, SshRsaKey, SshRsaPublicKey},
    tagged,
};

/// The default scrypt work factor used by age.
pub const DEFAULT_SCRYPT_WORK_FACTOR: u32 = 18;
/// The smallest accepted scrypt work factor.
pub const MIN_SCRYPT_WORK_FACTOR: u32 = 1;
/// The largest accepted scrypt work factor.
pub const MAX_SCRYPT_WORK_FACTOR: u32 = 30;

/// The default maximum scrypt work factor accepted by passphrase identities.
pub const DEFAULT_MAX_SCRYPT_WORK_FACTOR: u32 = 22;

/// The label used by post-quantum age recipients.
///
/// Hybrid recipients may only be combined with other recipients carrying the
/// same label. This prevents a file from accidentally being encrypted to a
/// classic recipient and thereby losing its post-quantum security.
pub const POSTQUANTUM_LABEL: &str = "postquantum";

const NO_RECIPIENT_LABELS: &[&str] = &[];
const POSTQUANTUM_RECIPIENT_LABELS: &[&str] = &[POSTQUANTUM_LABEL];

/// A recipient that can wrap an age file key.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum AgeRecipient {
    /// A native age X25519 recipient.
    X25519 {
        /// The recipient's 32-byte X25519 public key.
        public_key: [u8; 32],
    },
    /// A post-quantum ML-KEM-768 + X25519 hybrid recipient.
    Hybrid {
        /// The HPKE XWing public key.
        public_key: pq::HybridPublicKey,
    },
    /// A tagged P-256 recipient.
    P256Tag {
        /// The compressed SEC-1 P-256 public key.
        public_key: [u8; 33],
    },
    /// A tagged hybrid ML-KEM-768 + P-256 recipient.
    MlKem768P256Tag {
        /// The concatenated ML-KEM-768 and uncompressed P-256 public keys.
        public_key: Vec<u8>,
    },
    /// A passphrase recipient using scrypt.
    Scrypt {
        /// UTF-8 passphrase bytes.
        password: Vec<u8>,
        /// The base-two logarithm of the scrypt cost.
        work_factor: u32,
    },
    /// An SSH Ed25519 recipient.
    SshEd25519 {
        /// The Ed25519 key converted to X25519.
        curve25519_public_key: [u8; 32],
        /// The original SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
    /// An SSH RSA recipient.
    SshRsa {
        /// The RSA public key.
        public_key: RsaPublicKey,
        /// The original SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
}

impl fmt::Debug for AgeRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519 { .. } => formatter.write_str("X25519"),
            Self::Hybrid { .. } => formatter.write_str("mlkem768x25519"),
            Self::P256Tag { .. } => formatter.write_str("p256tag"),
            Self::MlKem768P256Tag { .. } => formatter.write_str("mlkem768p256tag"),
            Self::Scrypt { work_factor, .. } => {
                write!(formatter, "scrypt(work_factor={work_factor})")
            }
            Self::SshEd25519 { .. } => formatter.write_str("ssh-ed25519"),
            Self::SshRsa { .. } => formatter.write_str("ssh-rsa"),
        }
    }
}

impl Drop for AgeRecipient {
    fn drop(&mut self) {
        if let Self::Scrypt { password, .. } = self {
            password.zeroize();
        }
    }
}

impl crate::Recipient for AgeRecipient {
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
        AgeRecipient::wrap(self, file_key).map(|stanza| vec![stanza])
    }

    fn labels(&self) -> &'static [&'static str] {
        AgeRecipient::labels(self)
    }
}

impl AgeRecipient {
    /// Parses a native, hybrid, or tagged age Bech32 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the Bech32 value is invalid or its payload is
    /// not a supported recipient key.
    pub fn from_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let (hrp, bytes) = bech32::decode(public_key.as_ref())?;
        match hrp.as_str() {
            "age" => {
                if bytes.len() != 32 {
                    return Err(AgeError::InvalidKey("invalid age public key"));
                }
                let public_key: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| AgeError::InvalidKey("invalid age public key"))?;
                Ok(Self::X25519 { public_key })
            }
            "age1pq" => Ok(Self::Hybrid {
                public_key: pq::public_key_from_bytes(&bytes)?,
            }),
            tagged::CLASSIC_HRP => Ok(Self::P256Tag {
                public_key: tagged::classic_public_key_from_bytes(&bytes)?,
            }),
            tagged::HYBRID_HRP => Ok(Self::MlKem768P256Tag {
                public_key: tagged::hybrid_public_key_from_bytes(&bytes)?,
            }),
            _ => Err(AgeError::InvalidKey("invalid age public key")),
        }
    }

    /// Parses either tagged Bech32 recipient format.
    ///
    /// The classic format uses the `age1tag1` HRP and the hybrid format uses
    /// `age1tagpq1`.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input is a valid tagged
    /// recipient.
    pub fn from_tagged_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let recipient = Self::from_public_key(public_key)?;
        if matches!(
            &recipient,
            Self::P256Tag { .. } | Self::MlKem768P256Tag { .. }
        ) {
            Ok(recipient)
        } else {
            Err(AgeError::InvalidKey("invalid age tagged public key"))
        }
    }

    /// Parses a classic tagged P-256 Bech32 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input has the `age1tag1`
    /// HRP and contains a valid compressed P-256 public key.
    pub fn from_p256_tag_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let recipient = Self::from_public_key(public_key)?;
        if matches!(&recipient, Self::P256Tag { .. }) {
            Ok(recipient)
        } else {
            Err(AgeError::InvalidKey("invalid age tagged P-256 public key"))
        }
    }

    /// Creates a classic tagged P-256 recipient from a compressed public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input is a valid 33-byte
    /// compressed P-256 point.
    pub fn from_p256_tag_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::P256Tag {
            public_key: tagged::classic_public_key_from_bytes(public_key.as_ref())?,
        })
    }

    /// Parses a hybrid tagged ML-KEM-768 + P-256 Bech32 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input has the
    /// `age1tagpq1` HRP and contains a valid 1249-byte public key.
    pub fn from_tagged_hybrid_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let recipient = Self::from_public_key(public_key)?;
        if matches!(&recipient, Self::MlKem768P256Tag { .. }) {
            Ok(recipient)
        } else {
            Err(AgeError::InvalidKey("invalid age tagged hybrid public key"))
        }
    }

    /// Creates a hybrid tagged recipient from its concatenated raw public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input is a valid 1249-byte
    /// ML-KEM-768 + P-256 public key.
    pub fn from_tagged_hybrid_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::MlKem768P256Tag {
            public_key: tagged::hybrid_public_key_from_bytes(public_key.as_ref())?,
        })
    }

    /// Alias for [`AgeRecipient::from_tagged_public_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_tagged_public_key`].
    pub fn from_tag_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        Self::from_tagged_public_key(public_key)
    }

    /// Creates a tagged recipient from a raw public key.
    ///
    /// A 33-byte payload is interpreted as a classic P-256 key; a 1249-byte
    /// payload is interpreted as the hybrid ML-KEM-768 + P-256 format.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] for an unsupported length or invalid
    /// key material.
    pub fn from_tag_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        match public_key.as_ref().len() {
            tagged::CLASSIC_PUBLIC_KEY_LENGTH => Self::from_p256_tag_public_key_bytes(public_key),
            tagged::HYBRID_PUBLIC_KEY_LENGTH => {
                Self::from_tagged_hybrid_public_key_bytes(public_key)
            }
            _ => Err(AgeError::InvalidKey("invalid age tagged public key")),
        }
    }

    /// Alias for [`AgeRecipient::from_tag_public_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_tag_public_key_bytes`].
    pub fn from_tagged_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_tag_public_key_bytes(public_key)
    }

    /// Alias for [`AgeRecipient::from_p256_tag_public_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_p256_tag_public_key`].
    pub fn from_tagged_p256_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        Self::from_p256_tag_public_key(public_key)
    }

    /// Alias for [`AgeRecipient::from_p256_tag_public_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_p256_tag_public_key_bytes`].
    pub fn from_p256_tag(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_p256_tag_public_key_bytes(public_key)
    }

    /// Alias for [`AgeRecipient::from_p256_tag_public_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_p256_tag_public_key_bytes`].
    pub fn from_tagged_p256_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_p256_tag_public_key_bytes(public_key)
    }

    /// Alias for [`AgeRecipient::from_tagged_hybrid_public_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_tagged_hybrid_public_key`].
    pub fn from_mlkem768p256tag_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        Self::from_tagged_hybrid_public_key(public_key)
    }

    /// Alias for [`AgeRecipient::from_tagged_hybrid_public_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_tagged_hybrid_public_key_bytes`].
    pub fn from_mlkem768p256_tag(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_tagged_hybrid_public_key_bytes(public_key)
    }

    /// Alias for [`AgeRecipient::from_tagged_hybrid_public_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::from_tagged_hybrid_public_key_bytes`].
    pub fn from_mlkem768p256tag_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_tagged_hybrid_public_key_bytes(public_key)
    }

    /// Parses a post-quantum hybrid Bech32 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input has the `age1pq` HRP
    /// and contains a valid 1216-byte XWing public key.
    pub fn from_hybrid_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let recipient = Self::from_public_key(public_key)?;
        if matches!(&recipient, Self::Hybrid { .. }) {
            Ok(recipient)
        } else {
            Err(AgeError::InvalidKey("invalid age hybrid public key"))
        }
    }

    /// Creates a post-quantum recipient from raw XWing public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] when the bytes are not a valid 1216-byte
    /// XWing public key.
    pub fn from_hybrid_public_key_bytes(public_key: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::Hybrid {
            public_key: pq::public_key_from_bytes(public_key.as_ref())?,
        })
    }

    /// Returns the raw XWing public-key bytes for a hybrid recipient.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] for non-hybrid recipients.
    pub fn hybrid_public_key_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Hybrid { public_key } => Ok(pq::public_key_bytes(public_key)),
            _ => Err(AgeError::Unsupported(
                "only hybrid recipients have an XWing public key",
            )),
        }
    }

    /// Returns this native or tagged recipient's Bech32 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] for passphrase and SSH recipients.
    pub fn to_public_key(&self) -> Result<String> {
        match self {
            Self::X25519 { public_key } => bech32::encode("age", public_key),
            Self::Hybrid { public_key } => {
                bech32::encode("age1pq", &pq::public_key_bytes(public_key))
            }
            Self::P256Tag { public_key } => bech32::encode(tagged::CLASSIC_HRP, public_key),
            Self::MlKem768P256Tag { public_key } => bech32::encode(tagged::HYBRID_HRP, public_key),
            _ => Err(AgeError::Unsupported(
                "only native recipients have an age public key",
            )),
        }
    }

    /// Creates a native recipient from raw X25519 bytes.
    #[must_use]
    pub fn from_x25519_bytes(public_key: [u8; 32]) -> Self {
        Self::X25519 { public_key }
    }

    /// Alias for [`AgeRecipient::from_x25519_bytes`].
    #[must_use]
    pub fn from_x25519(public_key: [u8; 32]) -> Self {
        Self::from_x25519_bytes(public_key)
    }

    /// Creates a passphrase recipient with an explicit scrypt work factor.
    ///
    /// The work factor is `log2(N)` and must be in the inclusive range 1..=30.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::EmptyPassphrase`] for an empty passphrase and
    /// [`AgeError::InvalidWorkFactor`] for an unsupported factor.
    pub fn from_passphrase(passphrase: &str, work_factor: u32) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(AgeError::EmptyPassphrase);
        }
        validate_work_factor(work_factor)?;
        Ok(Self::Scrypt {
            password: passphrase.as_bytes().to_vec(),
            work_factor,
        })
    }

    /// Creates a passphrase recipient with age's default work factor 18.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::EmptyPassphrase`] for an empty passphrase and
    /// [`AgeError::InvalidWorkFactor`] for an unsupported factor.
    pub fn from_passphrase_default(passphrase: &str) -> Result<Self> {
        Self::from_passphrase(passphrase, DEFAULT_SCRYPT_WORK_FACTOR)
    }

    /// Alias for [`AgeRecipient::from_passphrase`].
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::EmptyPassphrase`] for an empty passphrase and
    /// [`AgeError::InvalidWorkFactor`] for an unsupported factor.
    pub fn from_passphrase_with_work_factor(passphrase: &str, work_factor: u32) -> Result<Self> {
        Self::from_passphrase(passphrase, work_factor)
    }

    /// Parses an SSH Ed25519 or RSA authorized-key line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for unsupported, malformed, undersized, or
    /// non-canonical SSH keys.
    pub fn from_ssh_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let trimmed = public_key.as_ref().trim();
        let has_kind = |kind: &str| trimmed.split_whitespace().any(|field| field == kind);
        if has_kind("ssh-ed25519") {
            let key = SshEd25519Key::parse_public_key(trimmed)?;
            return Ok(Self::from_ssh_ed25519_key(key));
        }
        if has_kind("ssh-rsa") {
            let key = SshRsaKey::parse_public_key(trimmed)?;
            return Ok(Self::from_ssh_rsa_key(key));
        }
        Err(AgeError::InvalidKey(
            "only ssh-ed25519 and ssh-rsa keys are supported",
        ))
    }

    /// Parses an SSH RSA authorized-key line.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for an unsupported, malformed, undersized, or
    /// non-canonical RSA SSH public key.
    pub fn from_ssh_rsa_public_key(public_key: impl AsRef<str>) -> Result<Self> {
        let key = SshRsaKey::parse_public_key(public_key)?;
        Ok(Self::from_ssh_rsa_key(key))
    }

    /// Creates an SSH Ed25519 recipient from parsed key material.
    #[must_use]
    pub fn from_ssh_ed25519_key(key: SshEd25519PublicKey) -> Self {
        Self::SshEd25519 {
            curve25519_public_key: key.curve25519_public_key,
            wire_key: key.wire_key,
        }
    }

    /// Creates an SSH RSA recipient from parsed key material.
    #[must_use]
    pub fn from_ssh_rsa_key(key: SshRsaPublicKey) -> Self {
        Self::SshRsa {
            public_key: key.key().clone(),
            wire_key: key.wire_key,
        }
    }

    /// Returns the age recipient type name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::X25519 { .. } => "X25519",
            Self::Hybrid { .. } => "mlkem768x25519",
            Self::P256Tag { .. } => "p256tag",
            Self::MlKem768P256Tag { .. } => "mlkem768p256tag",
            Self::Scrypt { .. } => "scrypt",
            Self::SshEd25519 { .. } => "ssh-ed25519",
            Self::SshRsa { .. } => "ssh-rsa",
        }
    }

    /// Returns whether this is a passphrase recipient.
    #[must_use]
    pub fn is_scrypt(&self) -> bool {
        matches!(self, Self::Scrypt { .. })
    }

    /// Returns whether this is a post-quantum hybrid recipient.
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::Hybrid { .. } | Self::MlKem768P256Tag { .. })
    }

    /// Returns whether this is a post-quantum hybrid recipient.
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        self.is_hybrid()
    }

    /// Returns whether this is one of the tagged recipient formats.
    #[must_use]
    pub fn is_tagged(&self) -> bool {
        matches!(self, Self::P256Tag { .. } | Self::MlKem768P256Tag { .. })
    }

    /// Returns whether this is a classic tagged P-256 recipient.
    #[must_use]
    pub fn is_p256_tag(&self) -> bool {
        matches!(self, Self::P256Tag { .. })
    }

    /// Returns whether this is a hybrid tagged ML-KEM-768 + P-256 recipient.
    #[must_use]
    pub fn is_tagged_hybrid(&self) -> bool {
        matches!(self, Self::MlKem768P256Tag { .. })
    }

    /// Returns whether this is a tagged ML-KEM-768 + P-256 recipient.
    #[must_use]
    pub fn is_mlkem768_p256_tag(&self) -> bool {
        self.is_tagged_hybrid()
    }

    /// Computes the four-byte tag for an HPKE encapsulated key.
    ///
    /// This is the low-level operation used by the tagged stanza formats. The
    /// encapsulated key must have the length required by the selected tagged
    /// recipient type.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidFormat`] for a malformed encapsulated key and
    /// [`AgeError::Unsupported`] for non-tagged recipients.
    pub fn tag(&self, encapsulated_key: &[u8]) -> Result<Vec<u8>> {
        self.tag_bytes(encapsulated_key).map(|tag| tag.to_vec())
    }

    /// Computes the four-byte tag as a fixed-size array.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::tag`].
    pub fn tag_bytes(&self, encapsulated_key: &[u8]) -> Result<[u8; 4]> {
        match self {
            Self::P256Tag { public_key } => tagged::classic_tag(public_key, encapsulated_key),
            Self::MlKem768P256Tag { public_key } => {
                tagged::hybrid_tag(public_key, encapsulated_key)
            }
            _ => Err(AgeError::Unsupported("only tagged recipients have a tag")),
        }
    }

    /// Returns the raw public-key bytes for a tagged recipient.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] for non-tagged recipients.
    pub fn tagged_public_key_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::P256Tag { public_key } => Ok(public_key.to_vec()),
            Self::MlKem768P256Tag { public_key } => Ok(public_key.clone()),
            _ => Err(AgeError::Unsupported(
                "only tagged recipients have a tagged public key",
            )),
        }
    }

    /// Returns the labels that this recipient contributes to a file header.
    ///
    /// All recipients in one encryption operation must have identical label
    /// sets. In particular, the `postquantum` label prevents a hybrid
    /// recipient from being mixed with a classic recipient.
    #[must_use]
    pub fn labels(&self) -> &'static [&'static str] {
        match self {
            Self::Hybrid { .. } | Self::MlKem768P256Tag { .. } => POSTQUANTUM_RECIPIENT_LABELS,
            _ => NO_RECIPIENT_LABELS,
        }
    }

    /// Returns whether this recipient can be combined with `other`.
    #[must_use]
    pub fn compatible_with(&self, other: &Self) -> bool {
        self.labels() == other.labels()
    }

    /// Validates that all recipients have the same compatibility labels.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] when a post-quantum recipient would be
    /// mixed with a classic recipient.
    pub fn validate_labels(recipients: &[Self]) -> Result<()> {
        let Some(first) = recipients.first() else {
            return Ok(());
        };
        if recipients
            .iter()
            .all(|recipient| recipient.labels() == first.labels())
        {
            Ok(())
        } else {
            Err(AgeError::InvalidKey(
                "can't mix post-quantum and classic recipients",
            ))
        }
    }

    /// Wraps a file key and returns the stanza with its compatibility labels.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeRecipient::wrap`].
    pub fn wrap_with_labels(&self, file_key: &[u8]) -> Result<(Stanza, Vec<&'static str>)> {
        Ok((self.wrap(file_key)?, self.labels().to_vec()))
    }

    /// Wraps a 16-byte file key in a recipient stanza.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for an invalid file-key length, failed entropy,
    /// invalid X25519 exchange, or rejected cryptographic operation.
    pub fn wrap(&self, file_key: &[u8]) -> Result<Stanza> {
        if file_key.len() != FILE_KEY_LENGTH {
            return Err(AgeError::InvalidKey("age file keys are 16 bytes"));
        }
        match self {
            Self::X25519 { public_key } => wrap_x25519(public_key, file_key),
            Self::Hybrid { public_key } => pq::wrap(public_key, file_key),
            Self::P256Tag { public_key } => tagged::wrap_classic(public_key, file_key),
            Self::MlKem768P256Tag { public_key } => tagged::wrap_hybrid(public_key, file_key),
            Self::Scrypt {
                password,
                work_factor,
            } => wrap_scrypt(password, *work_factor, file_key),
            Self::SshEd25519 {
                curve25519_public_key,
                wire_key,
            } => wrap_ssh_ed25519(curve25519_public_key, wire_key, file_key),
            Self::SshRsa {
                public_key,
                wire_key,
            } => wrap_ssh_rsa(public_key, wire_key, file_key),
        }
    }
}

/// Validates a scrypt work factor.
///
/// # Errors
///
/// Returns [`AgeError::InvalidWorkFactor`] unless `work_factor` is in 1..=30.
pub fn validate_work_factor(work_factor: u32) -> Result<()> {
    if (MIN_SCRYPT_WORK_FACTOR..=MAX_SCRYPT_WORK_FACTOR).contains(&work_factor) {
        Ok(())
    } else {
        Err(AgeError::InvalidWorkFactor)
    }
}

fn wrap_x25519(public_key: &[u8; 32], file_key: &[u8]) -> Result<Stanza> {
    let ephemeral_secret = Zeroizing::new(random_array::<32>()?);
    let ephemeral_share = Zeroizing::new(x25519_base(&*ephemeral_secret));
    let shared = x25519_shared(&*ephemeral_secret, public_key).ok_or(AgeError::Crypto(
        "X25519 produced an all-zero shared secret",
    ))?;
    let mut salt = Zeroizing::new(Vec::with_capacity(64));
    salt.extend_from_slice(&*ephemeral_share);
    salt.extend_from_slice(public_key);
    let wrap_key = Zeroizing::new(hkdf_sha256(&*shared, &salt[..], X25519_LABEL)?);
    let body = aead_encrypt(&*wrap_key, file_key)?;
    Ok(Stanza::new("X25519", [encode_raw(&*ephemeral_share)], body))
}

fn wrap_scrypt(password: &[u8], work_factor: u32, file_key: &[u8]) -> Result<Stanza> {
    validate_work_factor(work_factor)?;
    let salt = Zeroizing::new(random_array::<16>()?);
    let wrap_key = derive_scrypt_key(password, &salt[..], work_factor)?;
    let body = aead_encrypt(&*wrap_key, file_key)?;
    Ok(Stanza::new(
        "scrypt",
        [encode_raw(&salt[..]), work_factor.to_string()],
        body,
    ))
}

fn wrap_ssh_ed25519(public_key: &[u8; 32], wire_key: &[u8], file_key: &[u8]) -> Result<Stanza> {
    let ephemeral_secret = Zeroizing::new(random_array::<32>()?);
    let ephemeral_share = Zeroizing::new(x25519_base(&*ephemeral_secret));
    let shared = x25519_shared(&*ephemeral_secret, public_key).ok_or(AgeError::Crypto(
        "X25519 produced an all-zero shared secret",
    ))?;
    let tweak = Zeroizing::new(hkdf_sha256(&[], wire_key, SSH_ED25519_LABEL)?);
    let tweaked = x25519_shared(&*tweak, &*shared).ok_or(AgeError::Crypto(
        "SSH Ed25519 tweak produced an all-zero secret",
    ))?;
    let mut salt = Zeroizing::new(Vec::with_capacity(64));
    salt.extend_from_slice(&*ephemeral_share);
    salt.extend_from_slice(public_key);
    let wrap_key = Zeroizing::new(hkdf_sha256(&*tweaked, &salt[..], SSH_ED25519_LABEL)?);
    let body = aead_encrypt(&*wrap_key, file_key)?;
    let fingerprint = ssh_fingerprint(wire_key);
    Ok(Stanza::new(
        "ssh-ed25519",
        [fingerprint, encode_raw(&*ephemeral_share)],
        body,
    ))
}

fn wrap_ssh_rsa(public_key: &RsaPublicKey, wire_key: &[u8], file_key: &[u8]) -> Result<Stanza> {
    let body = rsa_oaep_encrypt(public_key, file_key)?;
    Ok(Stanza::new("ssh-rsa", [ssh_fingerprint(wire_key)], body))
}
