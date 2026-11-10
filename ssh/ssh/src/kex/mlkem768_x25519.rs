//! `mlkem768x25519-sha256` hybrid key exchange.

use {
    ml_kem::{self, Decapsulate, FromSeed, KeyExport, MlKem768},
    sha2::{Digest, Sha256},
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroizing,
};

use super::{
    KEX_MLKEM768X25519_SHA256, KexContext, KexError, KexReply, SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEX_ECDH_REPLY, SharedSecret,
};
use neotales_ssh::{Reader, Writer};

/// ML-KEM-768 encapsulation-key length in bytes.
pub(crate) const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes.
pub(crate) const MLKEM768_CIPHERTEXT_LENGTH: usize = 1088;
/// X25519 public-key length in bytes.
pub(crate) const X25519_PUBLIC_KEY_LENGTH: usize = 32;
/// Complete client hybrid public value length.
pub(crate) const C_INIT_LENGTH: usize = MLKEM768_PUBLIC_KEY_LENGTH + X25519_PUBLIC_KEY_LENGTH;
/// Complete server hybrid public value length.
pub(crate) const S_REPLY_LENGTH: usize = MLKEM768_CIPHERTEXT_LENGTH + X25519_PUBLIC_KEY_LENGTH;

/// Validates the client hybrid public-value length.
pub(crate) fn validate_client_public_blob(blob: &[u8]) -> Result<(), KexError> {
    if blob.len() != C_INIT_LENGTH {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}

/// Validates the server hybrid public-value length.
pub(crate) fn validate_server_public_blob(blob: &[u8]) -> Result<(), KexError> {
    if blob.len() != S_REPLY_LENGTH {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}

fn validate_x25519(blob: &[u8]) -> Result<[u8; X25519_PUBLIC_KEY_LENGTH], KexError> {
    blob.try_into().map_err(|_error| KexError::InvalidPublicKey)
}

fn combined_secret(mlkem_secret: &[u8], x25519_secret: &[u8]) -> Result<SharedSecret, KexError> {
    if mlkem_secret.len() != 32 || x25519_secret.len() != 32 {
        return Err(KexError::NonContributorySecret);
    }
    let mut material = Zeroizing::new(Vec::with_capacity(64));
    material.extend_from_slice(mlkem_secret);
    material.extend_from_slice(x25519_secret);
    let digest: [u8; 32] = Sha256::digest(&*material).into();
    SharedSecret::from_raw_string(&digest)
}

fn exchange_hash(
    context: &KexContext,
    host_key_blob: &[u8],
    client_init: &[u8],
    server_reply: &[u8],
    secret: &SharedSecret,
) -> Result<[u8; 32], KexError> {
    let mut writer = Writer::new();
    writer.write_string(context.client_version())?;
    writer.write_string(context.server_version())?;
    writer.write_string(context.client_kexinit())?;
    writer.write_string(context.server_kexinit())?;
    writer.write_string(host_key_blob)?;
    writer.write_string(client_init)?;
    writer.write_string(server_reply)?;
    writer.write_raw(secret.as_bytes());
    let framed = Zeroizing::new(writer.into_bytes());
    Ok(Sha256::digest(&*framed).into())
}

fn client_public_value(
    ek: &ml_kem::EncapsulationKey<MlKem768>,
    x25519_secret: &StaticSecret,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(C_INIT_LENGTH);
    value.extend_from_slice(&ek.to_bytes());
    value.extend_from_slice(PublicKey::from(x25519_secret).as_bytes());
    value
}

/// Client-side one-shot state for the hybrid exchange.
pub(crate) struct ClientKex {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem768>,
    x25519_secret: StaticSecret,
    client_init: Vec<u8>,
}

impl ClientKex {
    /// Generates a fresh ML-KEM-768 and X25519 client key pair.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::EntropyFailure`] if secure random generation fails.
    pub(crate) fn generate() -> Result<Self, KexError> {
        let mut mlkem_seed = Zeroizing::new([0_u8; 64]);
        let mut x25519_seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(mlkem_seed.as_mut()).map_err(|_error| KexError::EntropyFailure)?;
        getrandom::fill(x25519_seed.as_mut()).map_err(|_error| KexError::EntropyFailure)?;
        Ok(Self::from_seeds(&mlkem_seed, &x25519_seed))
    }

    /// Builds deterministic client state for tests and known-answer vectors.
    ///
    pub(crate) fn from_seeds(mlkem_seed: &[u8; 64], x25519_seed: &[u8; 32]) -> Self {
        let seed = Zeroizing::new(ml_kem::Seed::from(*mlkem_seed));
        let (decapsulation_key, encapsulation_key) = MlKem768::from_seed(&seed);
        let x25519_secret = StaticSecret::from(*x25519_seed);
        let client_init = client_public_value(&encapsulation_key, &x25519_secret);
        Self {
            decapsulation_key,
            x25519_secret,
            client_init,
        }
    }

    /// Returns the exact client message-30 public value.
    #[must_use]
    pub(crate) fn client_init(&self) -> &[u8] {
        &self.client_init
    }

    /// Encodes the client message-30 payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed hybrid value cannot be encoded.
    pub(crate) fn init_message(&self) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_KEX_ECDH_INIT);
        writer.write_string(&self.client_init)?;
        Ok(writer.into_bytes())
    }

    /// Completes the exchange and computes the hybrid exchange hash.
    ///
    /// # Errors
    ///
    /// Returns a typed KEX error for malformed messages, invalid KEM keys, or
    /// an invalid X25519 contribution.
    pub(crate) fn complete(
        self,
        context: &KexContext,
        reply: &[u8],
    ) -> Result<HybridCompletion, KexError> {
        let parsed = KexReply::decode_with_server_limit(reply, true, Some(S_REPLY_LENGTH))?;
        let server_reply = parsed
            .server_public_key()
            .ok_or(KexError::InvalidFieldLength)?;
        if server_reply.len() != S_REPLY_LENGTH {
            return Err(KexError::InvalidFieldLength);
        }
        let ciphertext = server_reply
            .get(..MLKEM768_CIPHERTEXT_LENGTH)
            .ok_or(KexError::InvalidFieldLength)?;
        let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_error| KexError::InvalidFieldLength)?;
        let mlkem_secret = Zeroizing::new(self.decapsulation_key.decapsulate(&ciphertext));
        let server_x25519 = validate_x25519(
            server_reply
                .get(MLKEM768_CIPHERTEXT_LENGTH..)
                .ok_or(KexError::InvalidFieldLength)?,
        )?;
        let x25519_shared = self
            .x25519_secret
            .diffie_hellman(&PublicKey::from(server_x25519));
        if !x25519_shared.was_contributory() {
            return Err(KexError::NonContributorySecret);
        }
        let x25519_secret = Zeroizing::new(x25519_shared.to_bytes());
        let shared_secret = combined_secret(mlkem_secret.as_slice(), x25519_secret.as_slice())?;
        let exchange_hash = exchange_hash(
            context,
            parsed.host_key_blob(),
            &self.client_init,
            server_reply,
            &shared_secret,
        )?;
        Ok(HybridCompletion {
            exchange_hash,
            session_id: exchange_hash,
            shared_secret,
            host_key_blob: parsed.host_key_blob().to_vec(),
            signature_blob: parsed.signature_blob().to_vec(),
        })
    }
}

/// A prepared server exchange after validating the client hybrid public value.
pub(crate) struct ServerKex {
    context: KexContext,
    host_key_blob: Vec<u8>,
    used: bool,
}

impl ServerKex {
    /// Creates server state bound to the negotiated transcript and host key.
    pub(crate) fn new(context: KexContext, host_key_blob: &[u8]) -> Result<Self, KexError> {
        if context.negotiated_algorithm() != KEX_MLKEM768X25519_SHA256 {
            return Err(KexError::AlgorithmMismatch);
        }
        if host_key_blob.is_empty() {
            return Err(KexError::InvalidFieldLength);
        }
        Ok(Self {
            context,
            host_key_blob: host_key_blob.to_vec(),
            used: false,
        })
    }

    /// Accepts the client message-30 public value and prepares the reply.
    ///
    /// # Errors
    ///
    /// Returns a typed KEX error for malformed framing, invalid ML-KEM keys, or
    /// entropy failure.
    pub(crate) fn accept_init(&mut self, payload: &[u8]) -> Result<ServerPrepared, KexError> {
        if self.used {
            return Err(KexError::InvalidState);
        }
        let mut reader = Reader::new(payload);
        if reader.read_byte()? != SSH_MSG_KEX_ECDH_INIT {
            return Err(KexError::InvalidMessageType);
        }
        let client_init = reader.read_string_with_limit(C_INIT_LENGTH)?.to_vec();
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        if client_init.len() != C_INIT_LENGTH {
            return Err(KexError::InvalidFieldLength);
        }
        let ek_bytes = client_init
            .get(..MLKEM768_PUBLIC_KEY_LENGTH)
            .ok_or(KexError::InvalidFieldLength)?;
        let ek = ml_kem::EncapsulationKey::<MlKem768>::new(
            &ml_kem::Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(ek_bytes)
                .map_err(|_error| KexError::InvalidPublicKey)?,
        )
        .map_err(|_error| KexError::InvalidPublicKey)?;
        let mut x25519_seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(x25519_seed.as_mut()).map_err(|_error| KexError::EntropyFailure)?;
        let x25519_secret = StaticSecret::from(*x25519_seed);
        let mut encapsulation_randomness = Zeroizing::new([0_u8; 32]);
        getrandom::fill(encapsulation_randomness.as_mut())
            .map_err(|_error| KexError::EntropyFailure)?;
        let randomness = ml_kem::B32::from(*encapsulation_randomness);
        let (ciphertext, mlkem_secret) = ek.encapsulate_deterministic(&randomness);
        let mlkem_secret = Zeroizing::new(mlkem_secret);
        let server_x25519 = PublicKey::from(&x25519_secret);
        let mut server_reply = Vec::with_capacity(S_REPLY_LENGTH);
        server_reply.extend_from_slice(&ciphertext);
        server_reply.extend_from_slice(server_x25519.as_bytes());
        let x25519_shared = x25519_secret.diffie_hellman(&PublicKey::from(validate_x25519(
            client_init
                .get(MLKEM768_PUBLIC_KEY_LENGTH..)
                .ok_or(KexError::InvalidFieldLength)?,
        )?));
        if !x25519_shared.was_contributory() {
            return Err(KexError::NonContributorySecret);
        }
        let x25519_secret = Zeroizing::new(x25519_shared.to_bytes());
        let shared_secret = combined_secret(mlkem_secret.as_slice(), x25519_secret.as_slice())?;
        let exchange_hash = exchange_hash(
            &self.context,
            &self.host_key_blob,
            &client_init,
            &server_reply,
            &shared_secret,
        )?;
        self.used = true;
        Ok(ServerPrepared {
            host_key_blob: self.host_key_blob.clone(),
            server_reply,
            exchange_hash,
            shared_secret,
        })
    }
}

/// A server exchange ready for host-key signing and message-31 encoding.
pub(crate) struct ServerPrepared {
    host_key_blob: Vec<u8>,
    server_reply: Vec<u8>,
    exchange_hash: [u8; 32],
    shared_secret: SharedSecret,
}

impl ServerPrepared {
    /// Returns the host-key blob used in the exchange transcript.
    #[must_use]
    pub(crate) fn host_key_blob(&self) -> &[u8] {
        &self.host_key_blob
    }

    /// Returns the exchange hash to sign.
    #[must_use]
    pub(crate) const fn exchange_hash(&self) -> &[u8; 32] {
        &self.exchange_hash
    }

    /// Returns the SSH string-framed hybrid shared secret.
    #[must_use]
    pub(crate) const fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }

    /// Returns the retained session identifier (the first exchange hash).
    #[must_use]
    pub(crate) const fn session_id(&self) -> &[u8; 32] {
        &self.exchange_hash
    }

    /// Encodes the signed server message-31 reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed hybrid value cannot be encoded.
    pub(crate) fn reply_message(&self, signature_blob: &[u8]) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_KEX_ECDH_REPLY);
        writer.write_string(&self.host_key_blob)?;
        writer.write_string(&self.server_reply)?;
        writer.write_string(signature_blob)?;
        Ok(writer.into_bytes())
    }
}

/// A completed hybrid exchange.
pub(crate) struct HybridCompletion {
    /// Exchange hash H.
    pub exchange_hash: [u8; 32],
    /// Session identifier, equal to H for the initial exchange.
    pub session_id: [u8; 32],
    /// SSH string-framed K value used by key derivation.
    pub shared_secret: SharedSecret,
    /// Server host-key blob from the reply.
    pub host_key_blob: Vec<u8>,
    /// Server signature blob from the reply.
    pub signature_blob: Vec<u8>,
}
