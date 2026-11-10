//! Age identity construction and file-key unwrapping.

#![allow(clippy::explicit_auto_deref)]

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use {
    rsa::{RsaPrivateKey, traits::PublicKeyParts},
    zeroize::{Zeroize, Zeroizing},
};

use crate::{
    bech32,
    codec::decode_raw,
    crypto::{
        FILE_KEY_LENGTH, SSH_ED25519_LABEL, X25519_LABEL, aead_decrypt, derive_scrypt_key,
        hkdf_sha256, public_key_fingerprint, rsa_oaep_decrypt, ssh_fingerprint, x25519_base,
        x25519_shared,
    },
    error::{AgeError, Result},
    header::Stanza,
    pq,
    recipient::{
        AgeRecipient, DEFAULT_MAX_SCRYPT_WORK_FACTOR, MAX_SCRYPT_WORK_FACTOR,
        MIN_SCRYPT_WORK_FACTOR,
    },
    ssh::{self, OpenSshPrivateKey},
};

/// An identity that can unwrap an age file key.
///
/// [`Debug`](fmt::Debug) is hand-written. It prints the algorithm and a
/// fingerprint of the public half, so a caller holding the wrong identity can
/// tell which one they have, and it never prints the private half: the scalar
/// for an X25519 or SSH Ed25519 identity, the RSA or XWing private key, the
/// passphrase, or the injected file key. A passphrase identity and an injected
/// file key have no public half at all, so they print the algorithm alone
/// rather than a fingerprint of a secret.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum AgeIdentity {
    /// A native age X25519 identity.
    X25519 {
        /// The 32-byte X25519 secret scalar.
        private_key: [u8; 32],
        /// The corresponding public key.
        public_key: [u8; 32],
    },
    /// A pre-unwrapped file key obtained out of band.
    InjectedFileKey(Zeroizing<Vec<u8>>),
    /// A post-quantum ML-KEM-768 + X25519 hybrid identity.
    Hybrid {
        /// The HPKE XWing private key.
        private_key: pq::HybridPrivateKey,
        /// The corresponding HPKE XWing public key.
        public_key: pq::HybridPublicKey,
    },
    /// A passphrase identity using scrypt.
    Scrypt {
        /// UTF-8 passphrase bytes.
        password: Vec<u8>,
        /// The largest work factor accepted while unwrapping.
        max_work_factor: u32,
    },
    /// An SSH Ed25519 identity converted to X25519.
    SshEd25519 {
        /// The converted X25519 scalar.
        private_key: [u8; 32],
        /// The converted X25519 public key.
        curve25519_public_key: [u8; 32],
        /// The original SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
    /// An SSH RSA identity.
    SshRsa {
        /// The RSA private key.
        private_key: RsaPrivateKey,
        /// The SSH wire public-key blob.
        wire_key: Vec<u8>,
    },
    /// A passphrase-protected SSH identity whose key is decrypted lazily.
    EncryptedSsh {
        /// The recipient derived from the supplied authorized-keys line.
        recipient: AgeRecipient,
        /// The encrypted PEM, wiped after the first successful decryption.
        pem: Arc<Mutex<Zeroizing<Vec<u8>>>>,
        /// The cached decrypted identity.
        decrypted: Arc<Mutex<Option<Box<Self>>>>,
        /// The callback used to obtain a passphrase when needed.
        passphrase_callback: Arc<dyn Fn() -> Result<Zeroizing<Vec<u8>>> + Send + Sync + 'static>,
    },
}

impl fmt::Debug for AgeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AgeIdentity");
        debug.field("kind", &self.kind());
        if let Some(fingerprint) = self.public_fingerprint() {
            debug.field("fingerprint", &fingerprint);
        }
        debug.finish()
    }
}

impl Drop for AgeIdentity {
    fn drop(&mut self) {
        match self {
            Self::X25519 { private_key, .. } | Self::SshEd25519 { private_key, .. } => {
                private_key.zeroize();
            }
            Self::Scrypt { password, .. } => password.zeroize(),
            Self::InjectedFileKey(_)
            | Self::Hybrid { .. }
            | Self::SshRsa { .. }
            | Self::EncryptedSsh { .. } => {}
        }
    }
}

impl crate::Identity for AgeIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.file_key_from_stanzas(stanzas)
    }
}

impl AgeIdentity {
    /// Parses a native age Bech32 secret key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the Bech32 value is invalid or does not
    /// contain exactly 32 secret-key bytes.
    pub fn from_private_key(private_key: impl AsRef<str>) -> Result<Self> {
        let (hrp, bytes) = bech32::decode(private_key.as_ref())?;
        let bytes = Zeroizing::new(bytes);
        match hrp.as_str() {
            "AGE-SECRET-KEY-" => {
                if bytes.len() != 32 {
                    return Err(AgeError::InvalidKey("invalid age private key"));
                }
                let private_key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AgeError::InvalidKey("invalid age private key"))?;
                Ok(Self::from_x25519_bytes(private_key))
            }
            "AGE-SECRET-KEY-PQ-" => Ok(Self::from_hybrid_private_key_bytes(&bytes)?),
            _ => Err(AgeError::InvalidKey("invalid age private key")),
        }
    }

    /// Parses a post-quantum hybrid Bech32 private key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless the input has the
    /// `AGE-SECRET-KEY-PQ-` HRP and contains a valid 32-byte XWing private key.
    pub fn from_hybrid_private_key(private_key: impl AsRef<str>) -> Result<Self> {
        let identity = Self::from_private_key(private_key)?;
        if matches!(&identity, Self::Hybrid { .. }) {
            Ok(identity)
        } else {
            Err(AgeError::InvalidKey("invalid age hybrid private key"))
        }
    }

    /// Creates a post-quantum identity from raw XWing private-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] when the bytes are not a valid 32-byte
    /// XWing private key.
    pub fn from_hybrid_private_key_bytes(private_key: impl AsRef<[u8]>) -> Result<Self> {
        let private_key = pq::private_key_from_bytes(private_key.as_ref())?;
        let public_key = <pq::HybridKem as hpke::Kem>::sk_to_pk(&private_key);
        Ok(Self::Hybrid {
            private_key,
            public_key,
        })
    }

    /// Generates a post-quantum hybrid identity.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Random`] when operating-system entropy is
    /// unavailable.
    pub fn generate_hybrid() -> Result<Self> {
        let (private_key, public_key) = pq::generate_keypair()?;
        Ok(Self::Hybrid {
            private_key,
            public_key,
        })
    }

    /// Returns this native identity's uppercase Bech32 private key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] for passphrase and SSH identities.
    pub fn to_private_key(&self) -> Result<String> {
        match self {
            Self::X25519 { private_key, .. } => {
                Ok(bech32::encode("age-secret-key-", private_key)?.to_ascii_uppercase())
            }
            Self::Hybrid { private_key, .. } => Ok(bech32::encode(
                "age-secret-key-pq-",
                &pq::private_key_bytes(private_key),
            )?
            .to_ascii_uppercase()),
            _ => Err(AgeError::Unsupported(
                "only native identities have an age private key",
            )),
        }
    }

    /// Creates an identity that supplies a file key obtained out of band.
    ///
    /// The key is still checked against the authenticated age header MAC.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] unless `file_key` is exactly 16 bytes.
    pub fn from_file_key(file_key: &[u8]) -> Result<Self> {
        if file_key.len() != crate::crypto::FILE_KEY_LENGTH {
            return Err(AgeError::InvalidKey("age file keys are 16 bytes"));
        }
        Ok(Self::InjectedFileKey(Zeroizing::new(file_key.to_vec())))
    }

    /// Creates a native identity from raw X25519 bytes.
    #[must_use]
    pub fn from_x25519_bytes(private_key: [u8; 32]) -> Self {
        let public_key = x25519_base(&private_key);
        Self::X25519 {
            private_key,
            public_key,
        }
    }

    /// Alias for [`AgeIdentity::from_private_key`].
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for an invalid Bech32 secret key.
    pub fn from_secret_key(private_key: &str) -> Result<Self> {
        Self::from_private_key(private_key)
    }

    /// Alias for [`AgeIdentity::from_x25519_bytes`].
    #[must_use]
    pub fn from_x25519(private_key: [u8; 32]) -> Self {
        Self::from_x25519_bytes(private_key)
    }

    /// Creates a passphrase identity using the age scrypt stanza.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::EmptyPassphrase`] when `passphrase` is empty.
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(AgeError::EmptyPassphrase);
        }
        Ok(Self::Scrypt {
            password: passphrase.as_bytes().to_vec(),
            max_work_factor: DEFAULT_MAX_SCRYPT_WORK_FACTOR,
        })
    }

    /// Sets the maximum scrypt work factor accepted by this identity.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] when called on a non-passphrase
    /// identity and [`AgeError::InvalidWorkFactor`] unless `log_n` is in
    /// 1..=30.
    pub fn with_max_scrypt_work_factor(mut self, log_n: u32) -> Result<Self> {
        if !(MIN_SCRYPT_WORK_FACTOR..=MAX_SCRYPT_WORK_FACTOR).contains(&log_n) {
            return Err(AgeError::InvalidWorkFactor);
        }
        match &mut self {
            Self::Scrypt {
                max_work_factor, ..
            } => *max_work_factor = log_n,
            _ => {
                return Err(AgeError::Unsupported(
                    "only passphrase identities have a scrypt maximum",
                ));
            }
        }
        Ok(self)
    }

    /// Parses an unencrypted OpenSSH private key or a PEM RSA private key.
    ///
    /// Encrypted OpenSSH keys return [`AgeError::PassphraseMissing`] with the
    /// embedded public key in `authorized_keys` format.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed, encrypted, unsupported, or
    /// undersized private keys.
    pub fn from_ssh_private_key(private_key: impl AsRef<str>) -> Result<Self> {
        let private_key = private_key.as_ref();
        if private_key.contains("OPENSSH PRIVATE KEY") {
            return Self::from_ssh_private_key_bytes(private_key.as_bytes());
        }
        if private_key.contains("BEGIN PRIVATE KEY")
            && let Ok(parsed) = ssh::parse_ed25519_pkcs8_pem(private_key)
        {
            return Self::from_openssh_private_key(parsed);
        }
        let rsa = ssh::parse_rsa_pem(private_key)?;
        Ok(Self::ssh_rsa_from_parts(rsa))
    }

    /// Creates an SSH identity that decrypts a protected private key lazily.
    ///
    /// `public_key_line` must be an `ssh-ed25519` or `ssh-rsa`
    /// `authorized_keys` line associated with `pem`. The passphrase callback
    /// is called only when a matching recipient stanza is encountered and the
    /// key has not already been decrypted successfully.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the public key or protected PEM is invalid.
    pub fn from_encrypted_ssh_private_key<F>(
        public_key_line: impl AsRef<str>,
        pem: impl AsRef<str>,
        passphrase_callback: F,
    ) -> Result<Self>
    where
        F: Fn() -> Result<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        let recipient = AgeRecipient::from_ssh_public_key(public_key_line)?;
        ssh::validate_encrypted_private_key(pem.as_ref().as_bytes())?;
        Ok(Self::EncryptedSsh {
            recipient,
            pem: Arc::new(Mutex::new(Zeroizing::new(pem.as_ref().as_bytes().to_vec()))),
            decrypted: Arc::new(Mutex::new(None)),
            passphrase_callback: Arc::new(passphrase_callback),
        })
    }

    /// Creates an SSH RSA identity from an RSA private key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidKey`] when the key is outside the SSH RSA
    /// policy (including its modulus, exponent, or prime-factor bounds) or its
    /// wire encoding cannot be represented.
    pub fn from_ssh_rsa_private_key(private_key: &RsaPrivateKey) -> Result<Self> {
        ssh::validate_ssh_rsa_private_key(private_key)?;
        let wire_key = ssh::build_rsa_wire(
            rsa::traits::PublicKeyParts::n(private_key)
                .to_bytes_be()
                .as_slice(),
            rsa::traits::PublicKeyParts::e(private_key)
                .to_bytes_be()
                .as_slice(),
        );
        Ok(Self::SshRsa {
            private_key: private_key.clone(),
            wire_key,
        })
    }

    /// Parses an unencrypted OpenSSH private key from bytes.
    ///
    /// Encrypted OpenSSH keys return [`AgeError::PassphraseMissing`] with the
    /// embedded public key in `authorized_keys` format.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed, encrypted, unsupported, or
    /// undersized private keys.
    pub fn from_ssh_private_key_bytes(private_key: &[u8]) -> Result<Self> {
        Self::from_openssh_private_key(ssh::parse_openssh_private(private_key)?)
    }

    fn from_openssh_private_key(private_key: OpenSshPrivateKey) -> Result<Self> {
        match private_key {
            OpenSshPrivateKey::Ed25519 {
                seed,
                public_key,
                wire_key,
            } => {
                let converted = crate::curve25519::ed25519_seed_to_x25519(&*seed);
                let curve25519_public_key =
                    crate::curve25519::ed25519_public_to_x25519(&public_key)
                        .map_err(|_| AgeError::InvalidKey("invalid SSH Ed25519 public key"))?;
                Ok(Self::SshEd25519 {
                    private_key: converted,
                    curve25519_public_key,
                    wire_key,
                })
            }
            OpenSshPrivateKey::Rsa {
                private_key,
                wire_key,
            } => Ok(Self::SshRsa {
                private_key,
                wire_key,
            }),
        }
    }

    fn ssh_rsa_from_parts(private_key: RsaPrivateKey) -> Self {
        let wire_key = ssh::build_rsa_wire(
            rsa::traits::PublicKeyParts::n(&private_key)
                .to_bytes_be()
                .as_slice(),
            rsa::traits::PublicKeyParts::e(&private_key)
                .to_bytes_be()
                .as_slice(),
        );
        Self::SshRsa {
            private_key,
            wire_key,
        }
    }

    fn matches_ssh_wire_key(&self, expected: &[u8]) -> bool {
        match self {
            Self::SshEd25519 { wire_key, .. } | Self::SshRsa { wire_key, .. } => {
                wire_key == expected
            }
            _ => false,
        }
    }

    /// Returns whether this is a post-quantum hybrid identity.
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::Hybrid { .. })
    }

    /// Returns whether this is a post-quantum hybrid identity.
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        self.is_hybrid()
    }

    /// Returns the age identity type name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::X25519 { .. } => "X25519",
            Self::InjectedFileKey(_) => "injected file key",
            Self::Hybrid { .. } => "mlkem768x25519",
            Self::Scrypt { .. } => "scrypt",
            Self::SshEd25519 { .. } => "ssh-ed25519",
            Self::SshRsa { .. } => "ssh-rsa",
            Self::EncryptedSsh { .. } => "encrypted SSH",
        }
    }

    /// Returns a fingerprint of the public half, or `None` when there is none.
    ///
    /// This is what [`fmt::Debug`] prints to tell two keys apart. The two
    /// variants that return `None` hold nothing but a secret: a passphrase and
    /// an unwrapped file key. Fingerprinting either would put a hash of a
    /// secret in every line that logged the value, and it would identify a
    /// passphrase by brute force.
    fn public_fingerprint(&self) -> Option<String> {
        match self {
            Self::X25519 { public_key, .. } => Some(public_key_fingerprint(&public_key[..])),
            Self::Hybrid { public_key, .. } => {
                Some(public_key_fingerprint(&pq::public_key_bytes(public_key)))
            }
            Self::SshEd25519 { wire_key, .. } | Self::SshRsa { wire_key, .. } => {
                Some(public_key_fingerprint(wire_key))
            }
            Self::EncryptedSsh { recipient, .. } => match recipient {
                AgeRecipient::SshEd25519 { wire_key, .. }
                | AgeRecipient::SshRsa { wire_key, .. } => Some(public_key_fingerprint(wire_key)),
                _ => None,
            },
            Self::InjectedFileKey(_) | Self::Scrypt { .. } => None,
        }
    }

    /// Returns the recipient corresponding to this identity, when one can be
    /// constructed without an unknown passphrase work factor.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::Unsupported`] for passphrase identities.
    pub fn recipient(&self) -> Result<AgeRecipient> {
        match self {
            Self::X25519 { public_key, .. } => Ok(AgeRecipient::from_x25519_bytes(*public_key)),
            Self::InjectedFileKey(_) => Err(AgeError::Unsupported(
                "an injected file key does not expose a recipient",
            )),
            Self::Hybrid { public_key, .. } => Ok(AgeRecipient::Hybrid {
                public_key: public_key.clone(),
            }),
            Self::SshEd25519 {
                curve25519_public_key,
                wire_key,
                ..
            } => Ok(AgeRecipient::SshEd25519 {
                curve25519_public_key: *curve25519_public_key,
                wire_key: wire_key.clone(),
            }),
            Self::SshRsa {
                private_key,
                wire_key,
            } => Ok(AgeRecipient::SshRsa {
                public_key: private_key.to_public_key(),
                wire_key: wire_key.clone(),
            }),
            Self::Scrypt { .. } => Err(AgeError::Unsupported(
                "a passphrase identity does not expose a recipient work factor",
            )),
            Self::EncryptedSsh { recipient, .. } => Ok(recipient.clone()),
        }
    }

    /// Tries to unwrap a file key from the supplied stanzas.
    pub(crate) fn file_key_from_stanzas(
        &self,
        stanzas: &[Stanza],
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self {
            Self::InjectedFileKey(file_key) => Ok(Some(Zeroizing::new(file_key.to_vec()))),
            Self::X25519 {
                private_key,
                public_key,
            } => unwrap_x25519(private_key, public_key, stanzas),
            Self::Hybrid { private_key, .. } => unwrap_hybrid(private_key, stanzas),
            Self::Scrypt {
                password,
                max_work_factor,
            } => unwrap_scrypt(password, *max_work_factor, stanzas),
            Self::SshEd25519 {
                private_key,
                curve25519_public_key,
                wire_key,
            } => unwrap_ssh_ed25519(private_key, curve25519_public_key, wire_key, stanzas),
            Self::SshRsa {
                private_key,
                wire_key,
            } => unwrap_ssh_rsa(private_key, wire_key, stanzas),
            Self::EncryptedSsh {
                recipient,
                pem,
                decrypted,
                passphrase_callback,
            } => unwrap_encrypted_ssh(recipient, pem, decrypted, passphrase_callback, stanzas),
        }
    }
}

fn unwrap_x25519(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    for stanza in stanzas {
        if stanza.r#type != "X25519" {
            continue;
        }
        if stanza.args.len() != 1 {
            return Err(AgeError::InvalidFormat("invalid X25519 recipient block"));
        }
        if stanza.body.len() != 32 {
            return Err(AgeError::InvalidFormat("invalid X25519 recipient block"));
        }
        let ephemeral_bytes = decode_raw(&stanza.args[0])
            .map_err(|_| AgeError::InvalidFormat("invalid X25519 ephemeral share"))?;
        let ephemeral_share = <[u8; 32]>::try_from(ephemeral_bytes.as_slice())
            .map_err(|_| AgeError::InvalidFormat("invalid X25519 ephemeral share"))?;
        let shared = x25519_shared(private_key, &ephemeral_share)
            .ok_or(AgeError::InvalidFormat("invalid X25519 ephemeral share"))?;
        let mut salt = Zeroizing::new(Vec::with_capacity(64));
        salt.extend_from_slice(&ephemeral_share);
        salt.extend_from_slice(public_key);
        let wrap_key = Zeroizing::new(
            hkdf_sha256(&*shared, &salt[..], X25519_LABEL)
                .map_err(|_| AgeError::Crypto("X25519 HKDF"))?,
        );
        if let Ok(file_key) = aead_decrypt(&wrap_key[..], &stanza.body)
            && file_key.len() == FILE_KEY_LENGTH
        {
            return Ok(Some(Zeroizing::new(file_key)));
        }
    }
    Ok(None)
}

fn unwrap_hybrid(
    private_key: &pq::HybridPrivateKey,
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    for stanza in stanzas {
        if stanza.r#type != "mlkem768x25519" {
            continue;
        }
        if let Some(file_key) = pq::unwrap(private_key, stanza)? {
            return Ok(Some(file_key));
        }
    }
    Ok(None)
}

fn unwrap_scrypt(
    password: &[u8],
    max_work_factor: u32,
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    for stanza in stanzas {
        if stanza.r#type != "scrypt" {
            continue;
        }
        if stanza.args.len() != 2 {
            return Err(AgeError::InvalidFormat("invalid scrypt recipient block"));
        }
        let Some(work_factor) = parse_work_factor(&stanza.args[1]) else {
            return Err(AgeError::InvalidWorkFactor);
        };
        if work_factor > max_work_factor {
            return Err(AgeError::ScryptWorkFactorTooLarge(work_factor));
        }
        if !(MIN_SCRYPT_WORK_FACTOR..=MAX_SCRYPT_WORK_FACTOR).contains(&work_factor) {
            return Err(AgeError::InvalidWorkFactor);
        }
        if stanza.body.len() != 32 {
            return Err(AgeError::InvalidFormat("invalid scrypt recipient block"));
        }
        let salt = decode_raw(&stanza.args[0])
            .map_err(|_| AgeError::InvalidFormat("invalid scrypt salt"))?;
        if salt.len() != 16 {
            return Err(AgeError::InvalidFormat("invalid scrypt salt"));
        }
        let wrap_key = derive_scrypt_key(password, &salt, work_factor)?;
        let Ok(file_key) = aead_decrypt(&wrap_key, &stanza.body) else {
            continue;
        };
        let file_key = Zeroizing::new(file_key);
        if file_key.len() == FILE_KEY_LENGTH {
            return Ok(Some(file_key));
        }
    }
    Ok(None)
}

fn unwrap_ssh_ed25519(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    wire_key: &[u8],
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let fingerprint = ssh_fingerprint(wire_key);
    for stanza in stanzas {
        if stanza.r#type != "ssh-ed25519" {
            continue;
        }
        if stanza.args.len() != 2 {
            return Err(AgeError::InvalidFormat(
                "invalid SSH Ed25519 recipient block",
            ));
        }
        if stanza.body.len() != 32 {
            return Err(AgeError::InvalidFormat(
                "invalid SSH Ed25519 recipient block",
            ));
        }
        if stanza.args[0] != fingerprint {
            continue;
        }
        let ephemeral_bytes = decode_raw(&stanza.args[1])
            .map_err(|_| AgeError::InvalidFormat("invalid SSH Ed25519 ephemeral share"))?;
        let ephemeral_share = <[u8; 32]>::try_from(ephemeral_bytes.as_slice())
            .map_err(|_| AgeError::InvalidFormat("invalid SSH Ed25519 ephemeral share"))?;
        let shared = x25519_shared(private_key, &ephemeral_share).ok_or(
            AgeError::InvalidFormat("invalid SSH Ed25519 ephemeral share"),
        )?;
        let tweak = Zeroizing::new(
            hkdf_sha256(&[], wire_key, SSH_ED25519_LABEL)
                .map_err(|_| AgeError::Crypto("SSH Ed25519 tweak HKDF"))?,
        );
        let tweaked = x25519_shared(&*tweak, &*shared).ok_or(AgeError::InvalidFormat(
            "invalid SSH Ed25519 ephemeral share",
        ))?;
        let mut salt = Zeroizing::new(Vec::with_capacity(64));
        salt.extend_from_slice(&ephemeral_share);
        salt.extend_from_slice(public_key);
        let wrap_key = Zeroizing::new(
            hkdf_sha256(&*tweaked, &salt[..], SSH_ED25519_LABEL)
                .map_err(|_| AgeError::Crypto("SSH Ed25519 wrap HKDF"))?,
        );
        if let Ok(file_key) = aead_decrypt(&wrap_key[..], &stanza.body)
            && file_key.len() == FILE_KEY_LENGTH
        {
            return Ok(Some(Zeroizing::new(file_key)));
        }
    }
    Ok(None)
}

fn unwrap_ssh_rsa(
    private_key: &RsaPrivateKey,
    wire_key: &[u8],
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let fingerprint = ssh_fingerprint(wire_key);
    for stanza in stanzas {
        if stanza.r#type != "ssh-rsa" {
            continue;
        }
        if stanza.args.len() != 1 {
            return Err(AgeError::InvalidFormat("invalid SSH RSA recipient block"));
        }
        if stanza.args[0] != fingerprint {
            continue;
        }
        if let Ok(file_key) = rsa_oaep_decrypt(private_key, &stanza.body)
            && file_key.len() == FILE_KEY_LENGTH
        {
            return Ok(Some(Zeroizing::new(file_key)));
        }
    }
    Ok(None)
}

fn unwrap_encrypted_ssh(
    recipient: &AgeRecipient,
    pem: &Arc<Mutex<Zeroizing<Vec<u8>>>>,
    decrypted: &Arc<Mutex<Option<Box<AgeIdentity>>>>,
    passphrase_callback: &Arc<dyn Fn() -> Result<Zeroizing<Vec<u8>>> + Send + Sync + 'static>,
    stanzas: &[Stanza],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut cache = lock(decrypted, "encrypted SSH identity cache lock poisoned")?;
    if let Some(identity) = cache.as_deref() {
        return identity.file_key_from_stanzas(stanzas);
    }

    let (stanza_type, wire_key) = match recipient {
        AgeRecipient::SshEd25519 { wire_key, .. } => ("ssh-ed25519", wire_key.as_slice()),
        AgeRecipient::SshRsa { wire_key, .. } => ("ssh-rsa", wire_key.as_slice()),
        _ => {
            return Err(AgeError::InvalidKey(
                "encrypted SSH identity has an invalid recipient",
            ));
        }
    };
    let fingerprint = ssh_fingerprint(wire_key);
    let expected_args = if stanza_type == "ssh-ed25519" { 2 } else { 1 };
    let mut matches = false;
    for stanza in stanzas {
        if stanza.r#type != stanza_type {
            continue;
        }
        if stanza.args.len() != expected_args {
            return Err(AgeError::InvalidFormat("invalid SSH recipient block"));
        }
        if stanza.args[0] == fingerprint {
            let expected_body = if stanza_type == "ssh-ed25519" {
                32
            } else {
                match recipient {
                    AgeRecipient::SshRsa { public_key, .. } => public_key.size(),
                    _ => unreachable!("recipient type was checked"),
                }
            };
            if stanza.body.len() != expected_body {
                return Err(AgeError::InvalidFormat("invalid SSH recipient block"));
            }
            matches = true;
            break;
        }
    }
    if !matches {
        return Ok(None);
    }

    let passphrase = passphrase_callback()?;
    let mut pem_guard = lock(pem, "encrypted SSH PEM lock poisoned")?;
    let parsed = ssh::parse_private_key_with_passphrase(pem_guard.as_slice(), &passphrase);
    drop(passphrase);
    let parsed = parsed?;
    let old_pem = std::mem::replace(&mut *pem_guard, Zeroizing::new(Vec::new()));
    drop(old_pem);
    let identity = AgeIdentity::from_openssh_private_key(parsed)?;
    if !identity.matches_ssh_wire_key(wire_key) {
        return Err(AgeError::InvalidKey(
            "mismatched private and public SSH key",
        ));
    }

    *cache = Some(Box::new(identity));
    let identity = cache
        .as_deref()
        .ok_or(AgeError::Crypto("encrypted SSH identity cache is empty"))?;
    identity.file_key_from_stanzas(stanzas)
}

fn lock<'a, T>(mutex: &'a Mutex<T>, message: &'static str) -> Result<MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| AgeError::Crypto(message))
}

fn parse_work_factor(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if value.as_bytes().first() == Some(&b'0') {
        return None;
    }
    let result = value.parse::<u32>().ok()?;
    (result > 0).then_some(result)
}
