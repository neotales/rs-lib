//! RFC 3526 group 16 ephemeral Diffie-Hellman for SSH.
//!
//! This module implements the finite-field `diffie-hellman-group16-sha512`
//! mechanism.  Its public values use the classic SSH DH message layout: the
//! client sends `SSH_MSG_KEXDH_INIT` (30) with an mpint `e`, and the server
//! replies with `SSH_MSG_KEXDH_REPLY` (31), an SSH string host key, an mpint
//! `f`, and an SSH string signature.

#![allow(
    dead_code,
    unused_imports,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    clippy::wrong_self_convention,
    clippy::too_many_arguments
)]

use neotales_ssh::{Error as WireError, Reader, Writer};
use {
    rsa::BigUint,
    sha2::{Digest, Sha512},
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
};

use super::{
    DerivationLengths, DerivationLetter, DerivedKeys, EphemeralKey, KexError, KexReply,
    KeyExchange, MAX_DERIVED_KEY_LENGTH, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY,
    SharedSecret, wipes_itself_on_drop,
};
use crate::msg::kexinit::{KEX_DIFFIE_HELLMAN_GROUP16_SHA512, KexInit};

/// The byte length of a raw group 16 prime.
pub(crate) const DH_GROUP16_PRIME_LENGTH: usize = 512;

/// The byte length of a generated group 16 private exponent.
pub(crate) const DH_GROUP16_PRIVATE_LENGTH: usize = 64;

/// The maximum encoded length of a group 16 public-value mpint.
pub(crate) const DH_GROUP16_PUBLIC_MPINT_MAX_LENGTH: usize = DH_GROUP16_PRIME_LENGTH + 1;

/// The RFC 3526 group 16 generator.
pub(crate) const DH_GROUP16_GENERATOR: u8 = 2;

/// The RFC 3526 section 5 group 16 prime in hexadecimal form.
pub(crate) const DH_GROUP16_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA",
    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED",
    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199",
    "FFFFFFFFFFFFFFFF",
);

/// An unprefixed alias for [`DH_GROUP16_PRIME_HEX`].
pub(crate) const GROUP16_PRIME_HEX: &str = DH_GROUP16_PRIME_HEX;

/// An unprefixed alias for the group 16 prime hexadecimal value.
pub(crate) const GROUP16_PRIME: &str = DH_GROUP16_PRIME_HEX;

/// An unprefixed alias for [`DH_GROUP16_PRIME_LENGTH`].
pub(crate) const GROUP16_PRIME_LENGTH: usize = DH_GROUP16_PRIME_LENGTH;

/// An unprefixed alias for [`DH_GROUP16_PRIVATE_LENGTH`].
pub(crate) const GROUP16_PRIVATE_LENGTH: usize = DH_GROUP16_PRIVATE_LENGTH;

/// An unprefixed alias for [`DH_GROUP16_GENERATOR`].
pub(crate) const GROUP16_GENERATOR: u8 = DH_GROUP16_GENERATOR;

/// The SSH message number for a finite-field DH client key-exchange init.
pub(crate) const SSH_MSG_KEX_DH_INIT: u8 = SSH_MSG_KEX_ECDH_INIT;

/// The SSH message number for a finite-field DH server key-exchange reply.
pub(crate) const SSH_MSG_KEX_DH_REPLY: u8 = SSH_MSG_KEX_ECDH_REPLY;

const MAX_PRIVATE_GENERATION_ATTEMPTS: usize = 128;
const PRIVATE_TOP_BIT: u8 = 0x80;

// This crate depends on the direct `zeroize` dependency is needed because public API types carry `Zeroizing`, so
// the `#[derive(Zeroize)]` macro — which expands to a `::zeroize::` path — is not
// available here and the impl is written out. A one-field tuple struct cannot
// grow a field without this impl being read again, which is the risk the derive
// would otherwise carry. The impl exists for the `Drop` below to call; it is
// not what makes this type wipe itself, and nothing outside this module could
// call it even if it could see the type.
pub(crate) struct Group16Private([u8; DH_GROUP16_PRIVATE_LENGTH]);

impl Zeroize for Group16Private {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Group16Private {
    fn drop(&mut self) {
        // A finite-field exponent is a plain array, so the wipe is six lines
        // away and there is nothing to delegate: this is the one mechanism in
        // the crate whose material wipes by code in this repository.
        self.0.zeroize();
        // The witness is recorded after the wipe and before the value is
        // released, which is the only moment the exponent can be read without
        // reading freed memory.
        #[cfg(test)]
        GROUP16_PRIVATE_DROP_WIPED.with(|wiped| wiped.set(Some(super::all_zero(&self.0))));
    }
}

#[cfg(test)]
thread_local! {
    /// Whether the last `Group16Private` destructor to run on this thread found
    /// the exponent already zeroed, and `None` if no destructor has reported
    /// since the value was last taken.
    ///
    /// `None` is a distinct answer from `Some(false)`: an exponent that is
    /// released without being wiped leaves no record at all, and the test that
    /// expects a wipe has to fail on that too.
    static GROUP16_PRIVATE_DROP_WIPED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Takes the last group 16 exponent destructor's wipe witness for this thread.
///
/// `Some(true)` means the destructor left a zeroed exponent behind, `Some(false)`
/// that it ran and found live key bytes, and `None` that no destructor has
/// reported since the last call.
///
/// # Panics
///
/// Never. `Cell::take` on a live thread-local value cannot fail.
#[cfg(test)]
#[allow(dead_code)] // Only `tests/kex.rs` calls it; other binaries include this module.
pub(crate) fn take_group16_private_drop_wipe() -> Option<bool> {
    GROUP16_PRIVATE_DROP_WIPED.with(std::cell::Cell::take)
}

// The marker for the claim the `Drop` above actually makes. `EphemeralKey`
// cannot check it, so it is checked twice over instead: the `const` item below
// compiles in every build, and the drop-wipe test in `tests/kex.rs` empties a
// real exponent through a destructor and reads what it left.
impl ZeroizeOnDrop for Group16Private {}

const _: () = {
    wipes_itself_on_drop::<Group16Private>();
};
/// The `diffie-hellman-group16-sha512` finite-field DH mechanism.
///
/// The public values returned by this type are canonical positive integer
/// magnitudes.  The message codecs add the SSH mpint framing when encoding
/// `e` and `f`; callers that use the generic [`KeyExchange`] interface receive
/// the same magnitude through `public_key` and `agree`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DhGroup16;

impl DhGroup16 {
    /// Creates the group 16 mechanism.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Returns the SSH algorithm name represented by this mechanism.
    #[must_use]
    pub(crate) const fn name(&self) -> &'static str {
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512
    }

    /// Returns the 512-byte RFC 3526 group 16 prime.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidProposal`] if the compiled-in constant is
    /// malformed.
    pub(crate) fn prime_bytes(&self) -> Result<Vec<u8>, KexError> {
        Ok(group16_prime()?.to_bytes_be())
    }

    /// Selects the mechanism by its exact SSH algorithm name.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::AlgorithmMismatch`] for every other name.
    pub(crate) fn from_name(name: &str) -> Result<Self, KexError> {
        if name == KEX_DIFFIE_HELLMAN_GROUP16_SHA512 {
            Ok(Self)
        } else {
            Err(KexError::AlgorithmMismatch)
        }
    }

    /// Creates one-shot private material from a fixed 512-bit big-endian value.
    ///
    /// This supports deterministic interoperability tests.  Normal exchanges
    /// should use [`KeyExchange::generate_ephemeral`], which obtains entropy
    /// from the operating system.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidPublicKey`] when the exponent is not in the
    /// valid SSH DH range `2..p-1`.
    pub(crate) fn from_private_bytes(
        &self,
        private: [u8; DH_GROUP16_PRIVATE_LENGTH],
    ) -> Result<EphemeralKey, KexError> {
        validate_private_bytes(&private)?;
        Ok(EphemeralKey::from_material(
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
            Group16Private(private),
        ))
    }

    /// Alias for [`Self::from_private_slice`] used by the other mechanisms.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidPublicKey`] for an invalid private exponent.
    pub(crate) fn with_private_bytes(
        &self,
        private: impl AsRef<[u8]>,
    ) -> Result<EphemeralKey, KexError> {
        self.from_private_slice(private.as_ref())
    }

    /// Creates one-shot private material from a big-endian value of at most 512 bits.
    ///
    /// Shorter values are left-padded with zeroes.  This is primarily useful for
    /// small deterministic test vectors; generated exchanges always use exactly
    /// 512 random bits.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidPublicKey`] when the input is empty, too long,
    /// or outside `2..p-1`.
    pub(crate) fn from_private_slice(&self, private: &[u8]) -> Result<EphemeralKey, KexError> {
        if private.is_empty() || private.len() > DH_GROUP16_PRIVATE_LENGTH {
            return Err(KexError::InvalidPublicKey);
        }
        let mut bytes = [0_u8; DH_GROUP16_PRIVATE_LENGTH];
        let offset = DH_GROUP16_PRIVATE_LENGTH - private.len();
        bytes[offset..].copy_from_slice(private);
        self.from_private_bytes(bytes)
    }

    /// Generates a fresh 512-bit private exponent.
    ///
    /// The high bit is set so the generated value has exactly 512 bits, and a
    /// bounded rejection loop forces it into the valid SSH DH range.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::EntropyFailure`] if the operating system entropy
    /// source fails or produces an unusable value after the bounded retries.
    pub(crate) fn generate_private(&self) -> Result<EphemeralKey, KexError> {
        for _ in 0..MAX_PRIVATE_GENERATION_ATTEMPTS {
            let mut bytes = [0_u8; DH_GROUP16_PRIVATE_LENGTH];
            getrandom::fill(&mut bytes).map_err(|_error| KexError::EntropyFailure)?;
            bytes[0] |= PRIVATE_TOP_BIT;
            if validate_private_bytes(&bytes).is_ok() {
                return Ok(EphemeralKey::from_material(
                    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
                    Group16Private(bytes),
                ));
            }
        }
        Err(KexError::EntropyFailure)
    }

    /// Generates fresh private material for the common KEX interface.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::EntropyFailure`] when secure entropy is unavailable.
    pub(crate) fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError> {
        self.generate_private()
    }

    /// Returns the peer's or local public value as a positive integer magnitude.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::AlgorithmMismatch`] if the material belongs to a
    /// different mechanism.
    pub(crate) fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        self.public_key_impl(ephemeral)
    }

    /// Encodes message 30 as `byte 30 || mpint e`.
    ///
    /// # Errors
    ///
    /// Returns wire, algorithm-mismatch, or invalid-state errors.
    pub(crate) fn encode_init_message(
        &self,
        ephemeral: &EphemeralKey,
    ) -> Result<Vec<u8>, KexError> {
        self.encode_init_impl(ephemeral)
    }

    /// Decodes message 30 and returns the positive magnitude of `e`.
    ///
    /// # Errors
    ///
    /// Returns wire, message-type, trailing-data, or invalid-public-value
    /// errors.
    pub(crate) fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, KexError> {
        self.decode_init_impl(input)
    }

    /// Encodes message 31 as `byte 31 || string K_S || mpint f || string sig`.
    ///
    /// # Errors
    ///
    /// Returns wire, field-length, or invalid-public-value errors.
    pub(crate) fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError> {
        self.encode_reply_impl(server_public_key, host_key_blob, signature_blob)
    }

    /// Decodes message 31 and returns the common KEX reply view.
    ///
    /// # Errors
    ///
    /// Returns wire, message-type, trailing-data, or invalid-public-value
    /// errors.
    pub(crate) fn decode_reply_message(&self, input: &[u8]) -> Result<KexReply, KexError> {
        self.decode_reply_impl(input).and_then(|reply| {
            KexReply::new(
                reply.host_key_blob(),
                Some(reply.server_public_key()),
                reply.signature_blob(),
            )
        })
    }

    /// Decodes message 31 into the group16-specific reply view.
    ///
    /// # Errors
    ///
    /// Returns wire, message-type, trailing-data, or invalid-public-value
    /// errors.
    pub(crate) fn decode_group16_reply(&self, input: &[u8]) -> Result<DhGroup16Reply, KexError> {
        self.decode_reply_impl(input)
    }

    /// Computes the shared secret using the supplied peer's `f` magnitude.
    ///
    /// # Errors
    ///
    /// Returns mechanism-mismatch, invalid-public-value, or non-contributory
    /// secret errors.
    pub(crate) fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError> {
        self.agree_impl(ephemeral, peer_public_key)
    }

    fn public_key_impl(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let private =
            ephemeral.material_ref::<Group16Private>(KEX_DIFFIE_HELLMAN_GROUP16_SHA512)?;
        let public = public_from_private(&private.0)?.to_bytes_be();
        parse_public_value(&public)?;
        Ok(public)
    }

    fn encode_init_impl(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        let public_key = self.public_key_impl(ephemeral)?;
        let mut writer = Writer::with_capacity(1 + 4 + public_key.len() + 1);
        writer.write_byte(SSH_MSG_KEX_DH_INIT);
        write_positive_mpint(&mut writer, &public_key)?;
        Ok(writer.into_bytes())
    }

    fn decode_init_impl(&self, input: &[u8]) -> Result<Vec<u8>, KexError> {
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_KEX_DH_INIT {
            return Err(KexError::InvalidMessageType);
        }
        let public_key = read_public_mpint(&mut reader)?;
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        Ok(public_key)
    }

    fn encode_reply_impl(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError> {
        DhGroup16Reply::new(host_key_blob, server_public_key, signature_blob)?.encode()
    }

    fn decode_reply_impl(&self, input: &[u8]) -> Result<DhGroup16Reply, KexError> {
        DhGroup16Reply::decode(input)
    }

    fn agree_impl(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError> {
        let peer = parse_public_value(peer_public_key)?;
        let private =
            ephemeral.into_material::<Group16Private>(KEX_DIFFIE_HELLMAN_GROUP16_SHA512)?;
        let prime = group16_prime()?;
        let private = BigUint::from_bytes_be(&private.0);
        let shared = peer.modpow(&private, &prime);
        SharedSecret::from_raw(&shared.to_bytes_be())
    }
}

impl KeyExchange for DhGroup16 {
    fn name(&self) -> &'static str {
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512
    }

    fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError> {
        self.generate_private()
    }

    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        self.public_key_impl(ephemeral)
    }

    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        self.encode_init_impl(ephemeral)
    }

    fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, KexError> {
        self.decode_init_impl(input)
    }

    fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError> {
        self.encode_reply_impl(server_public_key, host_key_blob, signature_blob)
    }

    fn decode_reply_message(&self, input: &[u8]) -> Result<KexReply, KexError> {
        let reply = self.decode_reply_impl(input)?;
        KexReply::new(
            reply.host_key_blob(),
            Some(reply.server_public_key()),
            reply.signature_blob(),
        )
    }

    fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError> {
        self.agree_impl(ephemeral, peer_public_key)
    }
}

/// A decoded group 16 message 31.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DhGroup16Reply {
    host_key_blob: Vec<u8>,
    server_public_key: Vec<u8>,
    signature_blob: Vec<u8>,
}

impl DhGroup16Reply {
    /// Builds a validated group 16 reply from positive integer magnitudes.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidFieldLength`] for an empty host key or
    /// [`KexError::InvalidPublicKey`] for an invalid `f`.
    pub(crate) fn new(
        host_key_blob: &[u8],
        server_public_key: &[u8],
        signature_blob: &[u8],
    ) -> Result<Self, KexError> {
        validate_nonempty_host_key(host_key_blob)?;
        let server_public_key = normalize_public_value(server_public_key)?;
        parse_public_value(&server_public_key)?;
        Ok(Self {
            host_key_blob: host_key_blob.to_vec(),
            server_public_key,
            signature_blob: signature_blob.to_vec(),
        })
    }

    /// Returns the SSH string containing the server host-key blob.
    #[must_use]
    pub(crate) fn host_key_blob(&self) -> &[u8] {
        &self.host_key_blob
    }

    /// Returns the positive integer magnitude of `f`.
    #[must_use]
    pub(crate) fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    /// Returns the opaque SSH signature string.
    #[must_use]
    pub(crate) fn signature_blob(&self) -> &[u8] {
        &self.signature_blob
    }

    /// Encodes this reply using the finite-field DH message layout.
    ///
    /// # Errors
    ///
    /// Returns a wire error if a field exceeds the SSH string limit.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::with_capacity(
            1 + 4
                + self.host_key_blob.len()
                + 4
                + self.server_public_key.len()
                + 4
                + self.signature_blob.len(),
        );
        writer.write_byte(SSH_MSG_KEX_DH_REPLY);
        writer.write_string(&self.host_key_blob)?;
        write_positive_mpint(&mut writer, &self.server_public_key)?;
        writer.write_string(&self.signature_blob)?;
        Ok(writer.into_bytes())
    }

    /// Decodes one complete finite-field DH reply.
    ///
    /// # Errors
    ///
    /// Returns wire, message-type, trailing-data, or invalid-public-value
    /// errors.
    pub(crate) fn decode(input: &[u8]) -> Result<Self, KexError> {
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_KEX_DH_REPLY {
            return Err(KexError::InvalidMessageType);
        }
        let host_key_blob = reader.read_string_bytes()?;
        let server_public_key = read_public_mpint(&mut reader)?;
        let signature_blob = reader.read_string_bytes()?;
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        Self::new(&host_key_blob, &server_public_key, &signature_blob)
    }
}

/// A validated group 16 exchange-hash context.
///
/// This is the SHA-512 counterpart of the baseline 32-byte KEX context.  It
/// retains the exact KEXINIT payloads because those bytes are part of the SSH
/// exchange hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Group16KexContext {
    client_version: String,
    server_version: String,
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
}

impl Group16KexContext {
    /// Binds versions, raw KEXINIT payloads, and the group 16 selection.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidIdentification`] for malformed versions,
    /// [`KexError::Wire`] for malformed KEXINIT bytes, and
    /// [`KexError::ProposalMismatch`] when the proposals do not select group 16.
    pub(crate) fn new(
        client_version: &str,
        server_version: &str,
        client_kexinit: impl Into<Vec<u8>>,
        server_kexinit: impl Into<Vec<u8>>,
    ) -> Result<Self, KexError> {
        validate_identification(client_version)?;
        validate_identification(server_version)?;
        let client_kexinit = client_kexinit.into();
        let server_kexinit = server_kexinit.into();
        if client_kexinit.len() > neotales_ssh::DEFAULT_STRING_LIMIT
            || server_kexinit.len() > neotales_ssh::DEFAULT_STRING_LIMIT
        {
            return Err(KexError::Wire(WireError::LimitExceeded));
        }
        let client = KexInit::decode(&client_kexinit).map_err(KexError::Wire)?;
        let server = KexInit::decode(&server_kexinit).map_err(KexError::Wire)?;
        let selected = client
            .negotiate(&server)
            .map_err(|_error| KexError::InvalidProposal)?
            .kex;
        if selected != KEX_DIFFIE_HELLMAN_GROUP16_SHA512 {
            return Err(KexError::ProposalMismatch);
        }
        Ok(Self {
            client_version: client_version.to_owned(),
            server_version: server_version.to_owned(),
            client_kexinit,
            server_kexinit,
        })
    }

    /// Returns the client identification without its terminating CR LF.
    #[must_use]
    pub(crate) fn client_version(&self) -> &str {
        &self.client_version
    }

    /// Returns the server identification without its terminating CR LF.
    #[must_use]
    pub(crate) fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Returns the exact client KEXINIT payload.
    #[must_use]
    pub(crate) fn client_kexinit(&self) -> &[u8] {
        &self.client_kexinit
    }

    /// Returns the exact server KEXINIT payload.
    #[must_use]
    pub(crate) fn server_kexinit(&self) -> &[u8] {
        &self.server_kexinit
    }

    /// Returns the algorithm selected by this context.
    #[must_use]
    pub(crate) const fn negotiated_algorithm(&self) -> &'static str {
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512
    }
}

/// A completed group 16 exchange with a 64-byte exchange hash and session ID.
///
/// Not [`Eq`]/[`PartialEq`], because `shared_secret` is not: a derived
/// comparison here would memcmp the secret. See [`SharedSecret`].
///
/// `Clone` is kept for the same reason it is kept on `KexCompletion` and not on
/// `ExchangeHashInput`: `Group16ClientKex::complete` returns its completion and
/// stores a copy at the same time, and the handshake reads the stored one back
/// later to install keying material, so the value must outlive the borrow that
/// produced it. See `KexCompletion` for that argument in full. The copies wipe
/// through `SharedSecret`'s destructor like every other.
#[derive(Clone, Debug)]
pub(crate) struct Group16KexCompletion {
    exchange_hash: [u8; 64],
    session_id: [u8; 64],
    shared_secret: SharedSecret,
    signature_blob: Option<Vec<u8>>,
    host_key_blob: Vec<u8>,
}

impl Group16KexCompletion {
    fn first(
        exchange_hash: [u8; 64],
        shared_secret: SharedSecret,
        host_key_blob: &[u8],
        signature_blob: Option<Vec<u8>>,
    ) -> Self {
        Self {
            session_id: exchange_hash,
            exchange_hash,
            shared_secret,
            signature_blob,
            host_key_blob: host_key_blob.to_vec(),
        }
    }

    /// Returns the negotiated group 16 algorithm name.
    #[must_use]
    pub(crate) fn algorithm(&self) -> &'static str {
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512
    }

    /// Returns the SHA-512 exchange hash `H`.
    #[must_use]
    pub(crate) fn exchange_hash(&self) -> &[u8; 64] {
        &self.exchange_hash
    }

    /// Returns the 64-byte session identifier established by this exchange.
    #[must_use]
    pub(crate) fn session_id(&self) -> &[u8; 64] {
        &self.session_id
    }

    /// Returns the positive SSH mpint shared secret.
    #[must_use]
    pub(crate) fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }

    /// Returns the host-key blob received or emitted by the role.
    #[must_use]
    pub(crate) fn host_key_blob(&self) -> &[u8] {
        &self.host_key_blob
    }

    /// Returns the opaque host-key signature, when available.
    #[must_use]
    pub(crate) fn signature_blob(&self) -> Option<&[u8]> {
        self.signature_blob.as_deref()
    }

    /// Consumes this completion and returns its shared secret.
    #[must_use]
    pub(crate) fn into_shared_secret(self) -> SharedSecret {
        self.shared_secret
    }
}

/// A compatibility alias for [`Group16KexContext`].
pub(crate) type DhGroup16KexContext = Group16KexContext;

/// A descriptive alias for [`Group16KexContext`].
pub(crate) type DhGroup16Context = Group16KexContext;

/// A descriptive alias for [`Group16KexCompletion`].
pub(crate) type DhGroup16KexCompletion = Group16KexCompletion;

/// A short alias for [`Group16KexCompletion`].
pub(crate) type Group16Completion = Group16KexCompletion;

/// The client-side one-shot group 16 exchange role.
#[derive(Debug)]
pub(crate) struct Group16ClientKex {
    mechanism: DhGroup16,
    context: Group16KexContext,
    client_public_key: Vec<u8>,
    ephemeral: Option<EphemeralKey>,
    completion: Option<Group16KexCompletion>,
}

impl Group16ClientKex {
    /// Creates a client role and a fresh 512-bit private exponent.
    ///
    /// # Errors
    ///
    /// Returns entropy or mechanism-validation errors.
    pub(crate) fn new(mechanism: DhGroup16, context: Group16KexContext) -> Result<Self, KexError> {
        let ephemeral = mechanism.generate_private()?;
        let client_public_key = mechanism.public_key(&ephemeral)?;
        Ok(Self {
            mechanism,
            context,
            client_public_key,
            ephemeral: Some(ephemeral),
            completion: None,
        })
    }

    /// Returns the client's positive public magnitude.
    #[must_use]
    pub(crate) fn client_public_key(&self) -> &[u8] {
        &self.client_public_key
    }

    /// Encodes message 30 for this role.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] after completion, plus wire errors.
    pub(crate) fn init_message(&self) -> Result<Vec<u8>, KexError> {
        let ephemeral = self.ephemeral.as_ref().ok_or(KexError::InvalidState)?;
        self.mechanism.encode_init_message(ephemeral)
    }

    /// Decodes message 31, computes the shared secret, and creates the hash.
    ///
    /// Host-key trust is intentionally left to the transport layer, matching
    /// the separation between this role and the host-key verifier.
    ///
    /// # Errors
    ///
    /// Returns malformed-message, invalid-public-value, non-contributory, and
    /// invalid-state errors.
    pub(crate) fn complete(&mut self, reply: &[u8]) -> Result<Group16KexCompletion, KexError> {
        if self.completion.is_some() {
            return Err(KexError::InvalidState);
        }
        let reply = self.mechanism.decode_group16_reply(reply)?;
        let ephemeral = self.ephemeral.take().ok_or(KexError::InvalidState)?;
        let shared_secret = self.mechanism.agree(ephemeral, reply.server_public_key())?;
        let exchange_hash = compute_group16_exchange_hash(
            self.context.client_version(),
            self.context.server_version(),
            self.context.client_kexinit(),
            self.context.server_kexinit(),
            reply.host_key_blob(),
            &self.client_public_key,
            reply.server_public_key(),
            &shared_secret,
        )?;
        let completion = Group16KexCompletion::first(
            exchange_hash,
            shared_secret,
            reply.host_key_blob(),
            Some(reply.signature_blob().to_vec()),
        );
        self.completion = Some(completion.clone());
        Ok(completion)
    }

    /// Returns the stored completion after [`Self::complete`] succeeds.
    #[must_use]
    pub(crate) fn completion(&self) -> Option<&Group16KexCompletion> {
        self.completion.as_ref()
    }

    /// Consumes the role and returns its successful completion.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] if no completion was stored.
    pub(crate) fn into_completion(self) -> Result<Group16KexCompletion, KexError> {
        self.completion.ok_or(KexError::InvalidState)
    }
}

/// The server-side one-shot group 16 exchange role.
#[derive(Debug)]
pub(crate) struct Group16ServerKex {
    mechanism: DhGroup16,
    context: Group16KexContext,
    host_key_blob: Vec<u8>,
    server_public_key: Vec<u8>,
    ephemeral: Option<EphemeralKey>,
    client_public_key: Option<Vec<u8>>,
    completion: Option<Group16KexCompletion>,
    reply_sent: bool,
}

impl Group16ServerKex {
    /// Creates a server role and a fresh 512-bit private exponent.
    ///
    /// # Errors
    ///
    /// Returns entropy, field-length, or proposal errors.
    pub(crate) fn new(
        mechanism: DhGroup16,
        context: Group16KexContext,
        host_key_blob: &[u8],
    ) -> Result<Self, KexError> {
        validate_nonempty_host_key(host_key_blob)?;
        let ephemeral = mechanism.generate_private()?;
        let server_public_key = mechanism.public_key(&ephemeral)?;
        Ok(Self {
            mechanism,
            context,
            host_key_blob: host_key_blob.to_vec(),
            server_public_key,
            ephemeral: Some(ephemeral),
            client_public_key: None,
            completion: None,
            reply_sent: false,
        })
    }

    /// Returns the server's positive public magnitude.
    #[must_use]
    pub(crate) fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    /// Decodes and validates the client's message 30.
    ///
    /// # Errors
    ///
    /// Returns malformed-message, invalid-public-value, or invalid-state errors.
    pub(crate) fn accept_init(&mut self, message: &[u8]) -> Result<(), KexError> {
        if self.client_public_key.is_some() {
            return Err(KexError::InvalidState);
        }
        self.client_public_key = Some(self.mechanism.decode_init_message(message)?);
        Ok(())
    }

    /// Computes `H`, `K`, and the 64-byte session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] before message 30 or after this
    /// transition, plus public-key and non-contributory-secret errors.
    pub(crate) fn prepare_exchange(&mut self) -> Result<&Group16KexCompletion, KexError> {
        if self.completion.is_some() {
            return Err(KexError::InvalidState);
        }
        let client_public_key = self
            .client_public_key
            .as_ref()
            .ok_or(KexError::InvalidState)?;
        let ephemeral = self.ephemeral.take().ok_or(KexError::InvalidState)?;
        let shared_secret = self.mechanism.agree(ephemeral, client_public_key)?;
        let exchange_hash = compute_group16_exchange_hash(
            self.context.client_version(),
            self.context.server_version(),
            self.context.client_kexinit(),
            self.context.server_kexinit(),
            &self.host_key_blob,
            client_public_key,
            &self.server_public_key,
            &shared_secret,
        )?;
        self.completion = Some(Group16KexCompletion::first(
            exchange_hash,
            shared_secret,
            &self.host_key_blob,
            None,
        ));
        self.completion.as_ref().ok_or(KexError::InvalidState)
    }

    /// Returns the prepared 64-byte exchange hash.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] before preparation.
    pub(crate) fn exchange_hash(&self) -> Result<&[u8; 64], KexError> {
        Ok(self
            .completion
            .as_ref()
            .ok_or(KexError::InvalidState)?
            .exchange_hash())
    }

    /// Encodes message 31 once, after the exchange hash has been prepared.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] before preparation or after a reply
    /// was emitted, plus wire and public-key errors.
    pub(crate) fn reply_message(&mut self, signature_blob: &[u8]) -> Result<Vec<u8>, KexError> {
        if self.reply_sent || self.completion.is_none() {
            return Err(KexError::InvalidState);
        }
        let message = self.mechanism.encode_reply_message(
            &self.server_public_key,
            &self.host_key_blob,
            signature_blob,
        )?;
        if let Some(completion) = self.completion.as_mut() {
            completion.signature_blob = Some(signature_blob.to_vec());
        }
        self.reply_sent = true;
        Ok(message)
    }

    /// Returns the prepared completion.
    #[must_use]
    pub(crate) fn completion(&self) -> Option<&Group16KexCompletion> {
        self.completion.as_ref()
    }

    /// Consumes the role and returns its prepared completion.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] if the exchange was not prepared.
    pub(crate) fn into_completion(self) -> Result<Group16KexCompletion, KexError> {
        self.completion.ok_or(KexError::InvalidState)
    }
}

/// Computes the RFC 4253 group 16 exchange hash using SHA-512.
///
/// The hashed sequence is exactly `string V_C || string V_S || string I_C ||
/// string I_S || string K_S || mpint e || mpint f || mpint K`.  `e` and `f`
/// are positive integer magnitudes; the function accepts either magnitudes or
/// complete canonical mpint encodings for convenience.
///
/// # Errors
///
/// Returns [`KexError::InvalidFieldLength`] for an empty host key and
/// [`KexError::InvalidPublicKey`] when `e` or `f` is outside `2..p-1`.
pub(crate) fn compute_group16_exchange_hash(
    client_version: &str,
    server_version: &str,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    host_key_blob: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    shared_secret: &SharedSecret,
) -> Result<[u8; 64], KexError> {
    validate_nonempty_host_key(host_key_blob)?;
    let client_public_key = normalize_public_value(client_public_key)?;
    let server_public_key = normalize_public_value(server_public_key)?;
    parse_public_value(&client_public_key)?;
    parse_public_value(&server_public_key)?;
    let mut writer = Writer::new();
    writer.write_string(client_version)?;
    writer.write_string(server_version)?;
    writer.write_string(client_kexinit)?;
    writer.write_string(server_kexinit)?;
    writer.write_string(host_key_blob)?;
    write_positive_mpint(&mut writer, &client_public_key)?;
    write_positive_mpint(&mut writer, &server_public_key)?;
    let mut framed = writer.into_bytes();
    framed.extend_from_slice(shared_secret.as_bytes());
    Ok(Sha512::digest(framed).into())
}

/// Alias for [`compute_group16_exchange_hash`] using the algorithm name.
pub(crate) fn compute_exchange_hash_sha512(
    client_version: &str,
    server_version: &str,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    host_key_blob: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    shared_secret: &SharedSecret,
) -> Result<[u8; 64], KexError> {
    compute_group16_exchange_hash(
        client_version,
        server_version,
        client_kexinit,
        server_kexinit,
        host_key_blob,
        client_public_key,
        server_public_key,
        shared_secret,
    )
}

/// Derives one RFC 4253 section 7.2 key using SHA-512.
///
/// # Errors
///
/// Returns [`KexError::InvalidExchangeHash`] unless the exchange hash contains
/// 64 bytes, [`KexError::InvalidSessionId`] unless the session ID contains 64
/// bytes, and [`KexError::DerivedKeyLimitExceeded`] for an oversized request.
pub(crate) fn derive_key_sha512(
    shared_secret: &SharedSecret,
    exchange_hash: &[u8],
    session_id: &[u8],
    letter: DerivationLetter,
    output_length: usize,
) -> Result<Vec<u8>, KexError> {
    validate_group16_derivation_inputs(exchange_hash, session_id, output_length)?;
    if output_length == 0 {
        return Ok(Vec::new());
    }

    let mut first = Sha512::new();
    first.update(shared_secret.as_bytes());
    first.update(exchange_hash);
    first.update([letter.as_byte()]);
    first.update(session_id);
    let mut output = Vec::with_capacity(output_length);
    output.extend_from_slice(&first.finalize());

    while output.len() < output_length {
        let mut next = Sha512::new();
        next.update(shared_secret.as_bytes());
        next.update(exchange_hash);
        next.update(&output);
        output.extend_from_slice(&next.finalize());
    }
    output.truncate(output_length);
    Ok(output)
}

/// Derives all RFC 4253 letters `A` through `F` using SHA-512.
///
/// # Errors
///
/// Returns the same validation errors as [`derive_key_sha512`].
pub(crate) fn derive_keys_sha512(
    shared_secret: &SharedSecret,
    exchange_hash: &[u8],
    session_id: &[u8],
    lengths: DerivationLengths,
) -> Result<DerivedKeys, KexError> {
    Ok(DerivedKeys {
        iv_client_to_server: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::A,
            lengths.a,
        )?),
        iv_server_to_client: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::B,
            lengths.b,
        )?),
        encryption_key_client_to_server: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::C,
            lengths.c,
        )?),
        encryption_key_server_to_client: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::D,
            lengths.d,
        )?),
        integrity_key_client_to_server: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::E,
            lengths.e,
        )?),
        integrity_key_server_to_client: Zeroizing::new(derive_key_sha512(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::F,
            lengths.f,
        )?),
    })
}

/// Alias for [`derive_keys_sha512`].
pub(crate) fn derive_group16_keys(
    shared_secret: &SharedSecret,
    exchange_hash: &[u8],
    session_id: &[u8],
    lengths: DerivationLengths,
) -> Result<DerivedKeys, KexError> {
    derive_keys_sha512(shared_secret, exchange_hash, session_id, lengths)
}

fn group16_prime() -> Result<BigUint, KexError> {
    BigUint::parse_bytes(DH_GROUP16_PRIME_HEX.as_bytes(), 16).ok_or(KexError::InvalidProposal)
}

fn one() -> BigUint {
    BigUint::from_bytes_be(&[1])
}

fn validate_private_bytes(private: &[u8; DH_GROUP16_PRIVATE_LENGTH]) -> Result<(), KexError> {
    let prime = group16_prime()?;
    let value = BigUint::from_bytes_be(private);
    let upper = &prime - one();
    if value <= one() || value >= upper {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}

fn public_from_private(private: &[u8; DH_GROUP16_PRIVATE_LENGTH]) -> Result<BigUint, KexError> {
    validate_private_bytes(private)?;
    let prime = group16_prime()?;
    Ok(BigUint::from(DH_GROUP16_GENERATOR).modpow(&BigUint::from_bytes_be(private), &prime))
}

fn parse_public_value(value: &[u8]) -> Result<BigUint, KexError> {
    let magnitude = normalize_public_value(value)?;
    let value = BigUint::from_bytes_be(&magnitude);
    let prime = group16_prime()?;
    let upper = &prime - one();
    if value <= one() || value >= upper {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(value)
}

fn normalize_public_value(value: &[u8]) -> Result<Vec<u8>, KexError> {
    if let Some(encoded) = complete_mpint_bytes(value) {
        return magnitude_from_wire(&encoded).map(<[u8]>::to_vec);
    }
    if value.is_empty() {
        return Err(KexError::InvalidPublicKey);
    }
    if value.len() > 1 && value[0] == 0 {
        if value[1] & 0x80 != 0 {
            return value
                .get(1..)
                .map(<[u8]>::to_vec)
                .ok_or(KexError::InvalidPublicKey);
        }
        return Err(KexError::InvalidPublicKey);
    }
    if value.len() > DH_GROUP16_PRIME_LENGTH {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(value.to_vec())
}

fn complete_mpint_bytes(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes(value.get(..4)?.try_into().ok()?);
    let length = usize::try_from(length).ok()?;
    if length != value.len().saturating_sub(4) {
        return None;
    }
    Some(value[4..].to_vec())
}

fn magnitude_from_wire(value: &[u8]) -> Result<&[u8], KexError> {
    let Some(first) = value.first() else {
        return Err(KexError::InvalidPublicKey);
    };
    if *first & 0x80 != 0 {
        return Err(KexError::InvalidPublicKey);
    }
    if *first == 0 && value.len() > 1 {
        if value.get(1).is_some_and(|second| *second & 0x80 == 0) {
            return Err(KexError::InvalidPublicKey);
        }
        value.get(1..).ok_or(KexError::InvalidPublicKey)
    } else {
        Ok(value)
    }
}

fn read_public_mpint(reader: &mut Reader<'_>) -> Result<Vec<u8>, KexError> {
    let wire = reader.read_mpint_with_limit(DH_GROUP16_PUBLIC_MPINT_MAX_LENGTH)?;
    let value = magnitude_from_wire(wire)?;
    let value = value.to_vec();
    parse_public_value(&value)?;
    Ok(value)
}

fn write_positive_mpint(writer: &mut Writer, value: &[u8]) -> Result<(), KexError> {
    let mut positive = Vec::with_capacity(value.len().saturating_add(1));
    if value.first().is_some_and(|byte| *byte & 0x80 != 0) {
        positive.push(0);
    }
    positive.extend_from_slice(value);
    writer.write_mpint(positive.as_slice())?;
    Ok(())
}

fn validate_identification(value: &str) -> Result<(), KexError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(KexError::InvalidIdentification);
    }
    Ok(())
}

fn validate_nonempty_host_key(value: &[u8]) -> Result<(), KexError> {
    if value.is_empty() {
        return Err(KexError::InvalidFieldLength);
    }
    Ok(())
}

fn validate_group16_derivation_inputs(
    exchange_hash: &[u8],
    session_id: &[u8],
    output_length: usize,
) -> Result<(), KexError> {
    if exchange_hash.len() != 64 {
        return Err(KexError::InvalidExchangeHash);
    }
    if session_id.len() != 64 {
        return Err(KexError::InvalidSessionId);
    }
    if output_length > MAX_DERIVED_KEY_LENGTH {
        return Err(KexError::DerivedKeyLimitExceeded);
    }
    Ok(())
}
