//! Curve25519 SHA-256 ephemeral Diffie-Hellman for RFC 5656.

use neotales_ssh::{Reader, Writer};
use {
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroizing,
};

use super::{
    EphemeralKey, KexError, KexReply, KeyExchange, SSH_MSG_KEX_ECDH_INIT, SharedSecret, all_zero,
    wipes_itself_on_drop,
};
use crate::msg::kexinit::{KEX_CURVE25519_SHA256, KEX_CURVE25519_SHA256_LIBCSSH};

/// The byte length of an X25519 public key and shared secret.
pub(crate) const CURVE25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The one-shot X25519 private scalar this mechanism stores.
///
/// The upstream secret type, stored as itself rather than as the scalar bytes
/// behind it. `x25519-dalek` wipes a [`StaticSecret`] in its own [`Drop`] and
/// declares that with `ZeroizeOnDrop`; the alternative this file used to take —
/// keeping the bytes in a `Zeroizing` array and rebuilding the secret type for
/// every call — meant copying the scalar onto the stack on each public key and
/// each agreement, in a value nothing in this crate could wipe.
///
/// `x25519-dalek` gates that `Drop` body *and* the marker impl on the same
/// `zeroize` feature, so the check below also fails if a build ever turns the
/// feature off, which is the case where the destructor would silently stop
/// wiping anything.
pub(crate) type X25519Private = StaticSecret;

/// The material this mechanism stores declares that its destructor wipes it.
///
/// A marker trait is an assertion, not a proof, so this check is only half the
/// claim: it fails the build if `x25519-dalek` ever stops asserting that its own
/// secret wipes itself. The other half — that the destructor really wipes —
/// happens inside that crate, on memory this crate cannot read back, so it is
/// upstream's test suite and not this one. What this crate can check is that the
/// type it stores is the type that makes the claim, and that the scalar is
/// consumed rather than copied out; `tests/kex.rs` checks both.
const _: () = {
    wipes_itself_on_drop::<X25519Private>();
};

/// The `curve25519-sha256` mechanism, including its libssh.org name variant.
///
/// Message 30 and message 31 carry the public value as an SSH string. The
/// shared secret is the raw 32-byte X25519 output interpreted as a positive SSH
/// mpint for hashing and key derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Curve25519 {
    algorithm: &'static str,
}

impl Curve25519 {
    /// Creates the standard `curve25519-sha256` spelling.
    #[must_use]
    pub(crate) const fn standard() -> Self {
        Self {
            algorithm: KEX_CURVE25519_SHA256,
        }
    }

    /// Creates the `curve25519-sha256@libssh.org` spelling.
    #[must_use]
    pub(crate) const fn libssh() -> Self {
        Self {
            algorithm: KEX_CURVE25519_SHA256_LIBCSSH,
        }
    }

    /// Selects either supported Curve25519 SSH name.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::AlgorithmMismatch`] for every other name.
    pub(crate) fn from_name(name: &str) -> Result<Self, KexError> {
        match name {
            KEX_CURVE25519_SHA256 => Ok(Self::standard()),
            KEX_CURVE25519_SHA256_LIBCSSH => Ok(Self::libssh()),
            _ => Err(KexError::AlgorithmMismatch),
        }
    }

    /// Creates one-shot X25519 material from a fixed private scalar.
    ///
    /// This supports deterministic interoperability tests. Normal exchanges
    /// should use [`KeyExchange::generate_ephemeral`], which obtains fresh
    /// entropy from the operating system.
    ///
    /// The scalar is moved into the [`StaticSecret`] the mechanism stores, so
    /// this call is the only copy the handshake ever makes: the stored secret
    /// wipes itself in its own [`Drop`], and no scalar is left on the stack for
    /// [`EphemeralKey`] to be responsible for.
    #[must_use]
    pub(crate) fn with_private_bytes(&self, private: [u8; 32]) -> EphemeralKey {
        EphemeralKey::from_material(self.algorithm, StaticSecret::from(private))
    }
}

impl Default for Curve25519 {
    fn default() -> Self {
        Self::standard()
    }
}

impl KeyExchange for Curve25519 {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError> {
        // `x25519-dalek`'s own `StaticSecret::random` wants a `CryptoRng` this
        // crate does not depend on, so the entropy is drawn here. The scratch
        // buffer is `Zeroizing` and wipes at the end of the statement; the copy
        // handed to `StaticSecret::from` becomes the stored secret, which wipes
        // itself. Wiping the argument slot that copy passes through would take
        // `unsafe`, and this crate forbids it.
        let mut private = Zeroizing::new([0_u8; CURVE25519_PUBLIC_KEY_LENGTH]);
        getrandom::fill(&mut *private).map_err(|_error| KexError::EntropyFailure)?;
        Ok(self.with_private_bytes(*private))
    }

    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let private = ephemeral.material_ref::<X25519Private>(self.algorithm)?;
        Ok(PublicKey::from(private).to_bytes().to_vec())
    }

    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let public_key = self.public_key(ephemeral)?;
        validate_public_key(&public_key)?;
        let mut writer = Writer::with_capacity(37);
        writer.write_byte(SSH_MSG_KEX_ECDH_INIT);
        writer.write_string(&public_key)?;
        Ok(writer.into_bytes())
    }

    fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, KexError> {
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_KEX_ECDH_INIT {
            return Err(KexError::InvalidMessageType);
        }
        let public_key = reader
            .read_string_with_limit(CURVE25519_PUBLIC_KEY_LENGTH)?
            .to_vec();
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        validate_public_key(&public_key)?;
        Ok(public_key)
    }

    fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError> {
        validate_public_key(server_public_key)?;
        KexReply::new_ecdh(host_key_blob, server_public_key, signature_blob)?.encode()
    }

    fn decode_reply_message(&self, input: &[u8]) -> Result<KexReply, KexError> {
        let reply = KexReply::decode(input, true)?;
        let public_key = reply
            .server_public_key()
            .ok_or(KexError::InvalidFieldLength)?;
        validate_public_key(public_key)?;
        Ok(reply)
    }

    fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError> {
        validate_public_key(peer_public_key)?;
        let peer: [u8; CURVE25519_PUBLIC_KEY_LENGTH] = peer_public_key
            .try_into()
            .map_err(|_error| KexError::InvalidPublicKey)?;
        let private = ephemeral.into_material::<X25519Private>(self.algorithm)?;
        let shared = private.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(KexError::NonContributorySecret);
        }
        let raw = shared.to_bytes();
        if all_zero(&raw) {
            return Err(KexError::NonContributorySecret);
        }
        SharedSecret::from_raw(&raw)
    }
}

pub(super) fn validate_public_key(public_key: &[u8]) -> Result<(), KexError> {
    if public_key.len() != CURVE25519_PUBLIC_KEY_LENGTH {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}
