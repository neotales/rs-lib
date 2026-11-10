//! NIST P-256 ephemeral Diffie-Hellman for RFC 5656.

use neotales_ssh::{Reader, Writer};
use {
    p256::elliptic_curve::{point::AffineCoordinates, sec1::ToSec1Point},
    zeroize::Zeroizing,
};

use super::{
    EphemeralKey, KexError, KexReply, KeyExchange, SSH_MSG_KEX_ECDH_INIT, SharedSecret,
    wipes_itself_on_drop,
};
use crate::msg::kexinit::KEX_ECDH_SHA2_NISTP256;

/// The byte length of an uncompressed SEC1 NIST P-256 point.
pub(crate) const P256_UNCOMPRESSED_POINT_LENGTH: usize = 65;

/// The required first byte of an uncompressed SEC1 elliptic-curve point.
pub(crate) const SEC1_UNCOMPRESSED_TAG: u8 = 4;

const MAX_SECRET_GENERATION_ATTEMPTS: usize = 128;

/// The one-shot P-256 private scalar this mechanism stores.
///
/// The upstream secret type, stored as itself rather than as the scalar bytes
/// behind it, for the reason the Curve25519 material documents: `p256` wipes a
/// [`p256::SecretKey`] in its own [`Drop`] and declares that with
/// `ZeroizeOnDrop`, while the scalar bytes it was parsed from would be this
/// crate's to wipe and a re-parse on every public key and every agreement would
/// copy the scalar onto the stack each time.
pub(crate) type P256Private = p256::SecretKey;

/// The material this mechanism stores declares that its destructor wipes it.
///
/// The same assertion as the Curve25519 one, and the same half of the claim
/// this can check: the marker says `p256` claims its own secret wipes itself,
/// and a build fails here if it stops saying so. Whether the destructor keeps
/// that promise is `p256`'s suite to test, not this crate's, because the bytes
/// are released by the same destructor that wipes them.
const _: () = {
    wipes_itself_on_drop::<P256Private>();
};

/// The `ecdh-sha2-nistp256` ephemeral Diffie-Hellman mechanism.
///
/// Message 30 and message 31 carry the public value as an SSH string containing
/// a strict 65-byte uncompressed SEC1 point. The shared secret is the 32-byte
/// affine x-coordinate encoded as a positive SSH mpint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EcdhP256;

impl EcdhP256 {
    /// Creates the P-256 mechanism.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Creates one-shot P-256 material from a fixed big-endian private scalar.
    ///
    /// This supports deterministic interoperability tests. Normal exchanges
    /// should use [`KeyExchange::generate_ephemeral`], which obtains fresh
    /// entropy from the operating system.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidPublicKey`] if the scalar is zero or is not
    /// below the P-256 group order.
    pub(crate) fn from_private_bytes(private: [u8; 32]) -> Result<EphemeralKey, KexError> {
        // The parse both validates the scalar and produces the secret the
        // mechanism stores, so the validated bytes are never written down
        // anywhere this crate then has to wipe.
        let secret =
            p256::SecretKey::from_slice(&private).map_err(|_error| KexError::InvalidPublicKey)?;
        Ok(EphemeralKey::from_material(KEX_ECDH_SHA2_NISTP256, secret))
    }
}

impl KeyExchange for EcdhP256 {
    fn name(&self) -> &'static str {
        KEX_ECDH_SHA2_NISTP256
    }

    fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError> {
        for _ in 0..MAX_SECRET_GENERATION_ATTEMPTS {
            // `Zeroizing` because this is the one copy of a fresh scalar that
            // this crate owns rather than `p256`; the parse reads it by
            // reference and the resulting secret wipes itself.
            let mut private = Zeroizing::new([0_u8; 32]);
            getrandom::fill(&mut *private).map_err(|_error| KexError::EntropyFailure)?;
            if let Ok(ephemeral) = Self::from_private_bytes(*private) {
                return Ok(ephemeral);
            }
        }
        Err(KexError::EntropyFailure)
    }

    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let secret = ephemeral.material_ref::<P256Private>(KEX_ECDH_SHA2_NISTP256)?;
        Ok(encode_public_key(secret))
    }

    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let public_key = self.public_key(ephemeral)?;
        validate_public_key(&public_key)?;
        let mut writer = Writer::with_capacity(70);
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
            .read_string_with_limit(P256_UNCOMPRESSED_POINT_LENGTH)?
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
        let peer = decode_public_key(peer_public_key)?;
        let private = ephemeral.into_material::<P256Private>(KEX_ECDH_SHA2_NISTP256)?;
        // `to_nonzero_scalar` hands back a *second* copy of the scalar, and
        // unlike `SecretKey` that copy has no destructor of its own, so it is
        // wrapped here rather than left on the stack.
        let scalar = Zeroizing::new(private.to_nonzero_scalar());
        let shared = (peer.to_projective() * scalar.as_ref()).to_affine();
        if bool::from(shared.is_identity()) {
            return Err(KexError::NonContributorySecret);
        }
        SharedSecret::from_raw(shared.x().as_slice())
    }
}

pub(super) fn validate_public_key(public_key: &[u8]) -> Result<(), KexError> {
    if public_key.len() != P256_UNCOMPRESSED_POINT_LENGTH
        || public_key.first() != Some(&SEC1_UNCOMPRESSED_TAG)
    {
        return Err(KexError::InvalidPublicKey);
    }
    decode_public_key(public_key).map(|_public_key| ())
}

pub(super) fn encode_public_key(secret: &p256::SecretKey) -> Vec<u8> {
    secret.public_key().to_sec1_point(false).to_bytes().to_vec()
}

fn decode_public_key(public_key: &[u8]) -> Result<p256::PublicKey, KexError> {
    p256::PublicKey::from_sec1_bytes(public_key).map_err(|_error| KexError::InvalidPublicKey)
}
