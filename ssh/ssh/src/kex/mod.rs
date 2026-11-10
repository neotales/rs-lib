//! SSH ephemeral Diffie-Hellman key exchange.
//!
//! This module owns the mechanism-independent transcript, exchange-hash, and
//! key-derivation rules. The concrete Curve25519 and NIST P-256 mechanisms use
//! the same small [`KeyExchange`] interface so a later finite-field DH group can
//! be added without coupling either mechanism to the transport state machine.

use std::any::Any;
use std::fmt;

use neotales_ssh::{Error as WireError, Reader, Writer, encode_mpint};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::msg::kexinit::{
    KEX_CURVE25519_SHA256, KEX_CURVE25519_SHA256_LIBCSSH, KEX_ECDH_SHA2_NISTP256,
    KEX_MLKEM768X25519_SHA256, KexInit, NegotiationError, SUPPORTED_KEX_ALGORITHMS,
};

#[path = "curve25519.rs"]
mod curve25519;
#[path = "dh_group16.rs"]
pub(crate) mod dh_group16;
#[path = "ecdh_p256.rs"]
mod ecdh_p256;
#[allow(dead_code)]
#[path = "mlkem768_x25519.rs"]
pub(crate) mod mlkem768_x25519;

pub(crate) use curve25519::{CURVE25519_PUBLIC_KEY_LENGTH, Curve25519};
#[allow(unused_imports)]
pub(crate) use dh_group16::DhGroup16;
pub(crate) use ecdh_p256::{EcdhP256, P256_UNCOMPRESSED_POINT_LENGTH, SEC1_UNCOMPRESSED_TAG};

// The material types, named where the test lane can reach them. Each is a type
// alias or a private struct inside a mechanism module, and the tests need them
// to assert that a mechanism still stores the type its own `const` item checks.
// The re-exports are compiled only for the tests, and only `tests/kex.rs` reads
// them, so the other test binaries that include this module allow the unused
// import.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use curve25519::X25519Private;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use dh_group16::{Group16Private, take_group16_private_drop_wipe};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use ecdh_p256::P256Private;

/// The SSH message number for an ECDH client key-exchange init message.
pub(crate) const SSH_MSG_KEX_ECDH_INIT: u8 = 30;

/// The SSH message number for an ECDH server key-exchange reply message.
pub(crate) const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// The maximum output length accepted by the RFC 4253 key-expansion function.
pub(crate) const MAX_DERIVED_KEY_LENGTH: usize = 1_048_576;

/// A safe error produced while preparing or completing an SSH key exchange.
///
/// Error values do not contain identification strings, transcript bytes,
/// ephemeral public keys, host-key blobs, or shared-secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KexError {
    /// An RFC 4251 primitive was malformed, truncated, or oversized.
    Wire(WireError),
    /// A key-exchange message had an unexpected SSH message number.
    InvalidMessageType,
    /// A key-exchange message contained data after its defined fields.
    TrailingData,
    /// A key-exchange field had an invalid fixed or nonzero length.
    InvalidFieldLength,
    /// An SSH identification string was empty, oversized, or non-ASCII.
    InvalidIdentification,
    /// A KEXINIT proposal could not be decoded or negotiated.
    InvalidProposal,
    /// The caller supplied a negotiated algorithm that the KEXINITs did not select.
    ProposalMismatch,
    /// A mechanism was used with a context that negotiated a different algorithm.
    AlgorithmMismatch,
    /// A server reply contained a host-key blob different from the bound blob.
    HostKeyMismatch,
    /// An X25519 or P-256 ephemeral public value was invalid.
    InvalidPublicKey,
    /// An X25519 exchange produced the all-zero or otherwise non-contributory value.
    NonContributorySecret,
    /// The operating system random-number source failed.
    EntropyFailure,
    /// A role was used before its input arrived or after its one-shot transition.
    InvalidState,
    /// An exchange hash was not 32 bytes, as required by the baseline mechanisms.
    InvalidExchangeHash,
    /// A session identifier was not 32 bytes.
    InvalidSessionId,
    /// A completion presented a session identifier different from the established one.
    SessionIdMismatch,
    /// A requested derived-key output exceeded [`MAX_DERIVED_KEY_LENGTH`].
    DerivedKeyLimitExceeded,
}

impl fmt::Display for KexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wire(error) => return write!(formatter, "SSH KEX wire error: {error}"),
            Self::InvalidMessageType => "SSH KEX message has an invalid type",
            Self::TrailingData => "SSH KEX message contains trailing data",
            Self::InvalidFieldLength => "SSH KEX field has an invalid length",
            Self::InvalidIdentification => "SSH identification string is invalid",
            Self::InvalidProposal => "SSH KEXINIT proposal is invalid",
            Self::ProposalMismatch => "SSH KEX proposal does not match the negotiated algorithm",
            Self::AlgorithmMismatch => "SSH KEX mechanism does not match the proposal",
            Self::HostKeyMismatch => "SSH KEX host-key blob does not match",
            Self::InvalidPublicKey => "SSH KEX ephemeral public key is invalid",
            Self::NonContributorySecret => "SSH KEX shared secret is non-contributory",
            Self::EntropyFailure => "secure random-number generation failed",
            Self::InvalidState => "SSH KEX role is in an invalid state",
            Self::InvalidExchangeHash => "SSH exchange hash must contain 32 bytes",
            Self::InvalidSessionId => "SSH session identifier must contain 32 bytes",
            Self::SessionIdMismatch => "SSH session identifier does not match",
            Self::DerivedKeyLimitExceeded => "SSH derived-key output exceeds the safety limit",
        })
    }
}

impl std::error::Error for KexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for KexError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Immutable proposal and identification data bound to one key exchange.
///
/// Construction decodes both KEXINIT messages and independently negotiates
/// their key-exchange lists. The caller-provided negotiated name must equal that
/// result, preventing a mechanism from being run against mismatched proposal
/// state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KexContext {
    client_version: String,
    server_version: String,
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
    negotiated_algorithm: String,
}

impl KexContext {
    /// Binds identification strings, raw KEXINIT payloads, and a negotiated name.
    ///
    /// Identification strings must be non-empty ASCII without CR, LF, or NUL and
    /// must fit the RFC 4253 limit of 255 bytes after CR LF is removed.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidIdentification`] for malformed versions,
    /// [`KexError::Wire`] for malformed or oversized KEXINIT bytes,
    /// [`KexError::InvalidProposal`] when negotiation fails, and
    /// [`KexError::ProposalMismatch`] when `negotiated_algorithm` is not the
    /// algorithm selected by those payloads.
    pub(crate) fn new(
        client_version: &str,
        server_version: &str,
        client_kexinit: impl Into<Vec<u8>>,
        server_kexinit: impl Into<Vec<u8>>,
        negotiated_algorithm: &str,
    ) -> Result<Self, KexError> {
        validate_identification(client_version)?;
        validate_identification(server_version)?;

        let client_kexinit = client_kexinit.into();
        let server_kexinit = server_kexinit.into();
        validate_kexinit_size(&client_kexinit)?;
        validate_kexinit_size(&server_kexinit)?;

        let client = KexInit::decode(&client_kexinit).map_err(KexError::Wire)?;
        let server = KexInit::decode(&server_kexinit).map_err(KexError::Wire)?;
        let selected = client
            .negotiate(&server)
            .map_err(map_negotiation_error)?
            .kex;
        if selected != negotiated_algorithm {
            return Err(KexError::ProposalMismatch);
        }
        validate_supported_algorithm(negotiated_algorithm)?;

        Ok(Self {
            client_version: client_version.to_owned(),
            server_version: server_version.to_owned(),
            client_kexinit,
            server_kexinit,
            negotiated_algorithm: negotiated_algorithm.to_owned(),
        })
    }

    /// Returns the client identification string without its terminating CR LF.
    #[must_use]
    pub(crate) fn client_version(&self) -> &str {
        &self.client_version
    }

    /// Returns the server identification string without its terminating CR LF.
    #[must_use]
    pub(crate) fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Returns the exact client KEXINIT payload, including its message byte.
    #[must_use]
    pub(crate) fn client_kexinit(&self) -> &[u8] {
        &self.client_kexinit
    }

    /// Returns the exact server KEXINIT payload, including its message byte.
    #[must_use]
    pub(crate) fn server_kexinit(&self) -> &[u8] {
        &self.server_kexinit
    }

    /// Returns the key-exchange name selected by the bound proposals.
    #[must_use]
    pub(crate) fn negotiated_algorithm(&self) -> &str {
        &self.negotiated_algorithm
    }
}

/// One-shot secret material owned by a key-exchange role.
///
/// The value has a redacted [`fmt::Debug`] implementation and is deliberately
/// neither cloneable nor serializable. A mechanism consumes it during agreement
/// so it cannot be reused accidentally.
///
/// # Where the wipe comes from, and where it is checked
///
/// The material is stored as [`Any`], so this value holds a `dyn Any` and a
/// vtable and nothing in this crate can call a method on what is inside it:
/// `EphemeralKey` has no destructor of its own and never calls [`Zeroize`] on
/// its material. A material type is therefore wiped by *its own* [`Drop`], and
/// nothing here can check that. A `Zeroize` bound on the constructor used to
/// read as if it could, which is why it is gone: implementing [`Zeroize`] says
/// a type *can* be wiped, never that anything wipes it, and a type with a
/// faithful `zeroize()` body and an empty [`Drop`] satisfies every bound this
/// module could write while leaking.
///
/// The claim is therefore made per material type, next to the mechanism that
/// stores it, where a reader is looking for it:
///
/// * `curve25519.rs` and `ecdh_p256.rs` store the upstream secret types
///   (`x25519_dalek::StaticSecret` and `p256::SecretKey`). Both wipe themselves
///   in their own [`Drop`] and both declare it with [`ZeroizeOnDrop`]; each
///   mechanism asserts that marker in a `const` item, so dropping the upstream
///   assertion is a build error here. The wipe itself happens inside those
///   crates and is not observable from here.
/// * `dh_group16.rs` stores `Group16Private`, this crate's own type, which
///   wipes in a hand-written [`Drop`]. Its destructor and the bytes it leaves
///   behind are asserted at run time in `tests/kex.rs`.
///
/// `ZeroizeOnDrop` is a marker, not a proof: the compiler checks that the claim
/// is *made*, never that it is *true*. The two types this crate owns are
/// therefore also checked by running their destructors.
pub(crate) struct EphemeralKey {
    algorithm: &'static str,
    material: Box<dyn Any + Send>,
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralKey")
            .finish_non_exhaustive()
    }
}

impl EphemeralKey {
    /// Wraps one-shot material for a mechanism without exposing its value.
    ///
    /// Mechanism implementations use this constructor so a future key-exchange
    /// module can add its own private material type without changing this
    /// module's storage representation.
    ///
    /// The material must wipe itself in its own [`Drop`]. This constructor does
    /// not wipe it and no bound on it would check that, which is why it carries
    /// only [`Any`] and [`Send`] — see the note on the type about where the
    /// property is stated and checked.
    #[must_use]
    pub(crate) fn from_material<T>(algorithm: &'static str, material: T) -> Self
    where
        T: Any + Send,
    {
        Self {
            algorithm,
            material: Box::new(material),
        }
    }

    pub(super) fn material_ref<T>(&self, algorithm: &str) -> Result<&T, KexError>
    where
        T: Any + Send,
    {
        if self.algorithm != algorithm {
            return Err(KexError::AlgorithmMismatch);
        }
        self.material
            .downcast_ref::<T>()
            .ok_or(KexError::AlgorithmMismatch)
    }

    pub(super) fn into_material<T>(self, algorithm: &str) -> Result<T, KexError>
    where
        T: Any + Send,
    {
        if self.algorithm != algorithm {
            return Err(KexError::AlgorithmMismatch);
        }
        self.material
            .downcast::<T>()
            .map(|material| *material)
            .map_err(|_material| KexError::AlgorithmMismatch)
    }
}

/// Requires a type to declare, with [`ZeroizeOnDrop`], that its [`Drop`] wipes
/// it.
///
/// This is the check a mechanism can make on the material it stores, and it is
/// worth exactly what the marker is: the compiler sees that the claim is made
/// and cannot see that it is kept. A type can satisfy this bound and leak, so
/// the two material types this crate owns are also checked by dropping them and
/// reading what they left behind.
///
/// It is a `const fn` so a mechanism can assert its material in a `const` item,
/// where the check runs in every build rather than only under `cargo test`.
pub(crate) const fn wipes_itself_on_drop<T: ZeroizeOnDrop>() {}

/// A positive ECDH shared secret in canonical SSH mpint wire form.
///
/// Construction normalizes the raw curve output with the existing wire mpint
/// encoder, adding a leading zero byte when the high bit is set.
///
/// The value is deliberately **not** [`Eq`]/[`PartialEq`].
///
/// `Vec`'s `PartialEq` is length-then-`memcmp`, so a derived comparison of this
/// type answers "are these two shared secrets equal" in time proportional to
/// their matching prefix. That is the one question about an ECDH secret whose
/// answer must not leak, and a trait derive cannot make it constant-time — the
/// derive hands every later caller the means to ask it in a timing-visible way,
/// and `assert_eq!` makes asking look like the ordinary way to write a test.
/// [`DerivedKeys`], the other type in this crate that holds session key
/// material, has the same answer for the same reason; the two are kept agreeing
/// rather than each answering separately. If a caller ever needs equality here,
/// it should compare a digest of the two values, in constant time, on purpose.
///
/// Do not add `#[derive(PartialEq)]` back to "make a test easier".
///
/// The rule a test has to follow is the one above: digest both values, then
/// compare the digests in constant time, deliberately. The derived session keys
/// are not an alternative to it. [`DerivedKeys`] holds key material of the same
/// sensitivity and refuses `Eq`/`PartialEq` for exactly this reason, so
/// comparing two of those is the same length-then-`memcmp` one level up, not a
/// way around the digest rule.
///
/// A test that wants "these two exchanges agreed" may also assert on the
/// exchange hash `H`, which is the digest rule applied to a value this crate
/// already computed. `H` is **not** a transmitted field, and it is not public
/// on the wire: RFC 4253 has each end derive it locally over the transcript it
/// just saw, and message 31 carries the host-key *signature* computed over `H`,
/// not `H` itself. So the reason comparing two `H` values is sound is that both
/// sides are local digests of a transcript that includes the secret, and two
/// peers that derived the same secret hash the same bytes — nothing about the
/// value being public to an attacker makes it safe, and the constant-time
/// digest comparison is what keeps it that way.
///
/// This is a claim about the wrappers this crate owns. [`SharedSecret`] is one
/// such wrapper, and so are [`DerivedKeys`] and [`ExchangeHashInput`]; the
/// comparison is not made where a foreign key type is merely stored, because
/// this crate neither defines those types nor chooses their derives. The
/// upstream scalars behind [`EphemeralKey`] are the standing counter-example:
/// `x25519_dalek::StaticSecret` and `p256::SecretKey` are held as-is and their
/// upstream traits are none of this crate's business, which is why the wipe
/// claimed for them is asserted from here while the comparison is not.
///
/// `Clone` is kept, unlike on [`DerivedKeys`], because the exchange roles need
/// it rather than merely tolerating it: [`ClientKex::complete`] and
/// [`ServerKex::prepare_exchange`] both build an [`ExchangeHashInput`] that
/// takes ownership of the secret, then hand a second copy to the
/// [`KexCompletion`] they store and return, because the completion outlives the
/// hash input that produced it. Every copy is a [`Drop`] that wipes, so each one
/// is protected by its own destructor rather than living unwiped beside its
/// source. Removing the clone would mean threading a reference through a
/// completion that has to survive the input's drop, and the resulting
/// borrow-checker pressure is the kind of complexity this type's callers do not
/// need.
///
/// [`Eq`]: std::cmp::Eq
/// [`PartialEq`]: std::cmp::PartialEq
#[derive(Clone)]
pub(crate) struct SharedSecret(Vec<u8>);

impl fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedSecret")
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    pub(super) fn from_raw_string(raw: &[u8]) -> Result<Self, KexError> {
        if raw.len() > MAX_DERIVED_KEY_LENGTH {
            return Err(KexError::DerivedKeyLimitExceeded);
        }
        let mut writer = Writer::new();
        writer.write_string(raw)?;
        Ok(Self(writer.into_bytes()))
    }

    pub(super) fn from_raw(raw: &[u8]) -> Result<Self, KexError> {
        if all_zero(raw) {
            return Err(KexError::NonContributorySecret);
        }
        let mut positive = Vec::with_capacity(raw.len().saturating_add(1));
        if raw.first().is_some_and(|byte| *byte & 0x80 != 0) {
            positive.push(0);
        }
        positive.extend_from_slice(raw);
        Ok(Self(encode_mpint(positive)?))
    }

    /// Returns the complete SSH mpint encoding, including its string length.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value and returns the complete SSH mpint encoding.
    #[must_use]
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The common mechanism interface used by the client and server KEX roles.
///
/// A future finite-field group can implement this trait without changing the
/// transcript, session-ID, or key-derivation code. Its init/reply codecs decide
/// whether their RFC message contains an ephemeral public value.
pub(crate) trait KeyExchange {
    /// Returns the negotiated SSH algorithm name represented by this mechanism.
    fn name(&self) -> &'static str;

    /// Generates fresh one-shot ephemeral secret material.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::EntropyFailure`] if secure random generation fails.
    fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError>;

    /// Returns the public value to place in this mechanism's ECDH messages.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::AlgorithmMismatch`] if the secret belongs to another
    /// mechanism.
    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError>;

    /// Encodes message 30 for this mechanism.
    ///
    /// # Errors
    ///
    /// Returns wire, field-length, or mechanism-mismatch errors.
    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError>;

    /// Decodes message 30 and returns the peer's ephemeral public value.
    ///
    /// # Errors
    ///
    /// Returns message, wire, field-length, or public-key validation errors.
    fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, KexError>;

    /// Encodes message 31 for this mechanism.
    ///
    /// The signature blob is an opaque SSH string produced and verified by the
    /// host-key and transport layers; this ticket does not create or check it.
    ///
    /// # Errors
    ///
    /// Returns wire, field-length, or mechanism-mismatch errors.
    fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError>;

    /// Decodes message 31 for this mechanism.
    ///
    /// # Errors
    ///
    /// Returns message, wire, field-length, or public-key validation errors.
    fn decode_reply_message(&self, input: &[u8]) -> Result<KexReply, KexError>;

    /// Consumes one-shot ephemeral material and computes the shared secret.
    ///
    /// # Errors
    ///
    /// Returns mechanism-mismatch, public-key, and non-contributory-secret
    /// errors without exposing curve input in diagnostics.
    fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError>;
}

/// The RFC 5656 message-31 fields consumed by this module.
///
/// `server_public_key` is present for the two baseline ECDH mechanisms. The
/// optional representation lets a later finite-field DH mechanism use the same
/// role interface without advertising an ephemeral value in message 31.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KexReply {
    host_key_blob: Vec<u8>,
    server_public_key: Option<Vec<u8>>,
    signature_blob: Vec<u8>,
}

impl KexReply {
    /// Returns the SSH string containing the server host-key blob.
    #[must_use]
    pub(crate) fn host_key_blob(&self) -> &[u8] {
        &self.host_key_blob
    }

    /// Returns the server ephemeral public value for an ECDH reply.
    #[must_use]
    pub(crate) fn server_public_key(&self) -> Option<&[u8]> {
        self.server_public_key.as_deref()
    }

    /// Returns the opaque SSH signature string from message 31.
    ///
    /// Host-key parsing and verification are outside this module's scope.
    #[must_use]
    pub(crate) fn signature_blob(&self) -> &[u8] {
        &self.signature_blob
    }

    pub(super) fn new(
        host_key_blob: &[u8],
        server_public_key: Option<&[u8]>,
        signature_blob: &[u8],
    ) -> Result<Self, KexError> {
        validate_nonempty_host_key(host_key_blob)?;
        Ok(Self {
            host_key_blob: host_key_blob.to_vec(),
            server_public_key: server_public_key.map(<[u8]>::to_vec),
            signature_blob: signature_blob.to_vec(),
        })
    }

    pub(super) fn new_ecdh(
        host_key_blob: &[u8],
        server_public_key: &[u8],
        signature_blob: &[u8],
    ) -> Result<Self, KexError> {
        Self::new(host_key_blob, Some(server_public_key), signature_blob)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, KexError> {
        validate_nonempty_host_key(&self.host_key_blob)?;
        let mut writer = Writer::with_capacity(64);
        writer.write_byte(SSH_MSG_KEX_ECDH_REPLY);
        writer.write_string(&self.host_key_blob)?;
        if let Some(public_key) = &self.server_public_key {
            writer.write_string(public_key)?;
        }
        writer.write_string(&self.signature_blob)?;
        Ok(writer.into_bytes())
    }

    pub(super) fn decode(input: &[u8], expects_server_public_key: bool) -> Result<Self, KexError> {
        Self::decode_with_server_limit(input, expects_server_public_key, None)
    }

    pub(super) fn decode_with_server_limit(
        input: &[u8],
        expects_server_public_key: bool,
        server_public_key_limit: Option<usize>,
    ) -> Result<Self, KexError> {
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_KEX_ECDH_REPLY {
            return Err(KexError::InvalidMessageType);
        }
        let host_key_blob = reader.read_string_bytes()?;
        validate_nonempty_host_key(&host_key_blob)?;
        let server_public_key = if expects_server_public_key {
            Some(match server_public_key_limit {
                Some(limit) => reader.read_string_bytes_with_limit(limit)?,
                None => reader.read_string_bytes()?,
            })
        } else {
            None
        };
        let signature_blob = reader.read_string_bytes()?;
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        Ok(Self {
            host_key_blob,
            server_public_key,
            signature_blob,
        })
    }
}

/// The four variable exchange-hash fields after the identification and KEXINITs.
///
/// Not [`Eq`]/[`PartialEq`], because `shared_secret` is not: a derived
/// comparison here would memcmp the secret. See [`SharedSecret`].
///
/// Not [`Clone`] either, which is the other half of the same answer. Nothing
/// clones this type — the roles build one, hash it, and drop it — so the derive
/// had no caller to justify it, and a copy of a wrapper holding an ECDH secret
/// is a second holder that has to be reasoned about rather than a convenience.
/// The secret is still [`Clone`]; it is this holder of it that is not.
#[derive(Debug)]
pub(crate) struct ExchangeHashInput {
    host_key_blob: Vec<u8>,
    client_public_key: Vec<u8>,
    server_public_key: Vec<u8>,
    shared_secret: SharedSecret,
}

impl ExchangeHashInput {
    /// Creates a validated exchange-hash input.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidFieldLength`] for an empty host-key blob.
    pub(crate) fn new(
        host_key_blob: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: SharedSecret,
    ) -> Result<Self, KexError> {
        validate_nonempty_host_key(host_key_blob)?;
        Ok(Self {
            host_key_blob: host_key_blob.to_vec(),
            client_public_key: client_public_key.to_vec(),
            server_public_key: server_public_key.to_vec(),
            shared_secret,
        })
    }

    /// Returns the server host-key blob included in the hash.
    #[must_use]
    pub(crate) fn host_key_blob(&self) -> &[u8] {
        &self.host_key_blob
    }

    /// Returns the client ephemeral public value included in the hash.
    #[must_use]
    pub(crate) fn client_public_key(&self) -> &[u8] {
        &self.client_public_key
    }

    /// Returns the server ephemeral public value included in the hash.
    #[must_use]
    pub(crate) fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    /// Returns the shared secret in complete SSH mpint wire form.
    #[must_use]
    pub(crate) fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }

    /// Returns the framed variable-field suffix `K_S || Q_C || Q_S || K`.
    ///
    /// The identification strings and KEXINIT payloads are prepended by
    /// [`compute_exchange_hash`] before hashing.
    ///
    /// # Errors
    ///
    /// Returns a wire error if a field exceeds the SSH string limit.
    pub(crate) fn framed_bytes(&self) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        writer.write_string(&self.host_key_blob)?;
        writer.write_string(&self.client_public_key)?;
        writer.write_string(&self.server_public_key)?;
        let mut bytes = writer.into_bytes();
        bytes.extend_from_slice(self.shared_secret.as_bytes());
        Ok(bytes)
    }
}

/// Computes the RFC 5656 SHA-256 exchange hash for a bound transcript.
///
/// The hashed sequence is exactly `string V_C || string V_S || string I_C ||
/// string I_S || string K_S || string Q_C || string Q_S || mpint K`.
///
/// # Errors
///
/// Returns [`KexError::AlgorithmMismatch`] if an ephemeral value does not match
/// the mechanism selected by `context`, or [`KexError::InvalidPublicKey`] for
/// an invalid X25519 length or SEC1 P-256 point.
pub(crate) fn compute_exchange_hash(
    context: &KexContext,
    input: &ExchangeHashInput,
) -> Result<[u8; 32], KexError> {
    validate_public_key_for_algorithm(
        context.negotiated_algorithm(),
        input.client_public_key(),
        true,
    )?;
    validate_public_key_for_algorithm(
        context.negotiated_algorithm(),
        input.server_public_key(),
        false,
    )?;

    let mut writer = Writer::new();
    writer.write_string(context.client_version())?;
    writer.write_string(context.server_version())?;
    writer.write_string(context.client_kexinit())?;
    writer.write_string(context.server_kexinit())?;
    writer.write_string(input.host_key_blob())?;
    writer.write_string(input.client_public_key())?;
    writer.write_string(input.server_public_key())?;
    let mut framed = writer.into_bytes();
    framed.extend_from_slice(input.shared_secret().as_bytes());
    Ok(Sha256::digest(framed).into())
}

/// A successfully completed key exchange and its retained session identifier.
///
/// Not [`Eq`]/[`PartialEq`], because `shared_secret` is not: a derived
/// comparison here would memcmp the secret. See [`SharedSecret`].
///
/// `Clone` **is** kept, unlike on [`DerivedKeys`], and unlike on
/// [`ExchangeHashInput`] which holds the same secret without it. The difference
/// is lifetime, and it is worth being explicit about because the two look like
/// the same decision:
///
/// * A completion is stored *and* returned. [`ClientKex::complete`] hands the
///   caller its value and keeps a copy in `self.completion`, because the
///   handshake later reads it back through [`ClientKex::completion`] to install
///   keying material, and the rekey path replaces it wholesale. The stored copy
///   has to outlive the borrow that produced it, so it is a value rather than a
///   reference. [`ServerKex`] and the group16 roles do the same.
/// * A hash input is built, hashed, and dropped inside one call. It never
///   escapes, so there was nothing for a copy to serve.
///
/// So the clone is load-bearing for this type and was dead weight for the other,
/// and the discriminator is whether the value outlives its producer, not how
/// sensitive the value is. Every copy here is still a [`Drop`] that wipes: the
/// clone duplicates the secret into a second wiping owner rather than a second
/// unwiped buffer, which is what makes it a different case from the
/// [`DerivedKeys`] clone that was removed.
#[derive(Clone, Debug)]
pub(crate) struct KexCompletion {
    algorithm: String,
    exchange_hash: [u8; 32],
    session_id: [u8; 32],
    shared_secret: SharedSecret,
    signature_blob: Option<Vec<u8>>,
}

impl KexCompletion {
    fn first(
        algorithm: String,
        exchange_hash: [u8; 32],
        shared_secret: SharedSecret,
        signature_blob: Option<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            session_id: exchange_hash,
            exchange_hash,
            shared_secret,
            signature_blob,
        }
    }

    /// Returns the mechanism selected by the bound KEXINIT proposals.
    #[must_use]
    pub(crate) fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the current exchange hash `H`.
    #[must_use]
    pub(crate) fn exchange_hash(&self) -> &[u8; 32] {
        &self.exchange_hash
    }

    /// Returns the connection session identifier established by this completion.
    #[must_use]
    pub(crate) fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Returns the positive shared secret in complete SSH mpint wire form.
    #[must_use]
    pub(crate) fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }

    /// Returns the opaque host-key signature string received or emitted, if available.
    ///
    /// The value is not parsed or verified here; the host-key and transport
    /// layers consume it after checking the exchange hash.
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

/// Retains the first successful exchange hash as the connection session ID.
///
/// Recording a later completion with a different session identifier returns
/// [`KexError::SessionIdMismatch`] and does not replace the established value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SessionIdTracker {
    session_id: Option<[u8; 32]>,
}

impl SessionIdTracker {
    /// Creates a tracker that has not yet observed a successful completion.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Records a completion and returns the connection session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::SessionIdMismatch`] when `completion` presents a
    /// session identifier different from the first accepted one.
    pub(crate) fn record(&mut self, completion: &KexCompletion) -> Result<[u8; 32], KexError> {
        self.record_exchange_hash(*completion.exchange_hash(), *completion.session_id())
    }

    /// Records a raw exchange hash and the session identifier presented for it.
    ///
    /// The first successful exchange must present its own hash as the session
    /// identifier. A later rekey may have a different exchange hash, but it must
    /// continue to present the identifier established by the first exchange.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::SessionIdMismatch`] when the presented identifier is
    /// different from the established one, or when the first exchange does not
    /// use its own hash as the identifier.
    pub(crate) fn record_exchange_hash(
        &mut self,
        exchange_hash: [u8; 32],
        session_id: [u8; 32],
    ) -> Result<[u8; 32], KexError> {
        match self.session_id {
            Some(established) if established != session_id => Err(KexError::SessionIdMismatch),
            Some(established) => Ok(established),
            None if exchange_hash != session_id => Err(KexError::SessionIdMismatch),
            None => {
                self.session_id = Some(exchange_hash);
                Ok(exchange_hash)
            }
        }
    }

    /// Returns the established session identifier, if a completion was recorded.
    #[must_use]
    pub(crate) fn session_id(&self) -> Option<&[u8; 32]> {
        self.session_id.as_ref()
    }
}

/// The client side of one ephemeral ECDH exchange.
#[derive(Debug)]
pub(crate) struct ClientKex<A> {
    mechanism: A,
    context: KexContext,
    expected_host_key_blob: Vec<u8>,
    client_public_key: Vec<u8>,
    ephemeral: Option<EphemeralKey>,
    completion: Option<KexCompletion>,
}

impl<A> ClientKex<A>
where
    A: KeyExchange,
{
    /// Creates a client role and a fresh one-shot ephemeral key.
    ///
    /// # Errors
    ///
    /// Returns proposal or mechanism mismatch errors, an empty host-key blob
    /// error, or [`KexError::EntropyFailure`].
    pub(crate) fn new(
        mechanism: A,
        context: KexContext,
        expected_host_key_blob: &[u8],
    ) -> Result<Self, KexError> {
        bind_mechanism(&context, mechanism.name())?;
        validate_nonempty_host_key(expected_host_key_blob)?;
        let ephemeral = mechanism.generate_ephemeral()?;
        let client_public_key = mechanism.public_key(&ephemeral)?;
        Ok(Self {
            mechanism,
            context,
            expected_host_key_blob: expected_host_key_blob.to_vec(),
            client_public_key,
            ephemeral: Some(ephemeral),
            completion: None,
        })
    }

    /// Returns the client ephemeral public value that appears in message 30.
    #[must_use]
    pub(crate) fn client_public_key(&self) -> &[u8] {
        &self.client_public_key
    }

    /// Encodes message 30 containing the client's ephemeral public value.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] after agreement has consumed the
    /// one-shot key, plus wire and mechanism errors.
    pub(crate) fn init_message(&self) -> Result<Vec<u8>, KexError> {
        let ephemeral = self.ephemeral.as_ref().ok_or(KexError::InvalidState)?;
        self.mechanism.encode_init_message(ephemeral)
    }

    /// Decodes message 31, verifies the bound host key, and completes agreement.
    ///
    /// # Errors
    ///
    /// Returns malformed-message, host-key mismatch, public-key,
    /// non-contributory-secret, and invalid-state errors. Agreement consumes
    /// the ephemeral key even if transcript hashing later fails.
    pub(crate) fn complete(&mut self, reply: &[u8]) -> Result<KexCompletion, KexError> {
        if self.completion.is_some() {
            return Err(KexError::InvalidState);
        }
        let decoded = self.mechanism.decode_reply_message(reply)?;
        if decoded.host_key_blob() != self.expected_host_key_blob {
            return Err(KexError::HostKeyMismatch);
        }
        let server_public_key = decoded
            .server_public_key()
            .ok_or(KexError::InvalidFieldLength)?;
        let signature_blob = decoded.signature_blob().to_vec();
        let ephemeral = self.ephemeral.take().ok_or(KexError::InvalidState)?;
        let shared_secret = self.mechanism.agree(ephemeral, server_public_key)?;
        let input = ExchangeHashInput::new(
            &self.expected_host_key_blob,
            &self.client_public_key,
            server_public_key,
            shared_secret,
        )?;
        let exchange_hash = compute_exchange_hash(&self.context, &input)?;
        let completion = KexCompletion::first(
            self.context.negotiated_algorithm().to_owned(),
            exchange_hash,
            input.shared_secret().clone(),
            Some(signature_blob),
        );
        self.completion = Some(completion.clone());
        Ok(completion)
    }

    /// Returns the stored completion after [`Self::complete`] succeeds.
    #[must_use]
    pub(crate) fn completion(&self) -> Option<&KexCompletion> {
        self.completion.as_ref()
    }

    /// Consumes this role and returns its successful completion.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] if no completion was stored.
    pub(crate) fn into_completion(self) -> Result<KexCompletion, KexError> {
        self.completion.ok_or(KexError::InvalidState)
    }
}

/// The server side of one ephemeral ECDH exchange.
#[derive(Debug)]
pub(crate) struct ServerKex<A> {
    mechanism: A,
    context: KexContext,
    host_key_blob: Vec<u8>,
    server_public_key: Vec<u8>,
    ephemeral: Option<EphemeralKey>,
    client_public_key: Option<Vec<u8>>,
    completion: Option<KexCompletion>,
    reply_sent: bool,
}

impl<A> ServerKex<A>
where
    A: KeyExchange,
{
    /// Creates a server role and a fresh one-shot ephemeral key.
    ///
    /// # Errors
    ///
    /// Returns proposal or mechanism mismatch errors, an empty host-key blob
    /// error, or [`KexError::EntropyFailure`].
    pub(crate) fn new(
        mechanism: A,
        context: KexContext,
        host_key_blob: &[u8],
    ) -> Result<Self, KexError> {
        bind_mechanism(&context, mechanism.name())?;
        validate_nonempty_host_key(host_key_blob)?;
        let ephemeral = mechanism.generate_ephemeral()?;
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

    /// Returns the server ephemeral public value reserved for message 31.
    #[must_use]
    pub(crate) fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    /// Decodes message 30 and binds the client's validated public value.
    ///
    /// # Errors
    ///
    /// Returns malformed-message and invalid-state errors.
    pub(crate) fn accept_init(&mut self, message: &[u8]) -> Result<(), KexError> {
        if self.client_public_key.is_some() {
            return Err(KexError::InvalidState);
        }
        self.client_public_key = Some(self.mechanism.decode_init_message(message)?);
        Ok(())
    }

    /// Consumes the one-shot key and computes `H`, `K`, and the session ID.
    ///
    /// This transition happens before host-key signing so SSH-006 and SSH-008
    /// can sign the returned exchange hash and pass an opaque signature string
    /// to [`Self::reply_message`].
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] before message 30 or after this
    /// transition, plus public-key and non-contributory-secret errors.
    pub(crate) fn prepare_exchange(&mut self) -> Result<&KexCompletion, KexError> {
        if self.completion.is_some() {
            return Err(KexError::InvalidState);
        }
        let client_public_key = self
            .client_public_key
            .as_ref()
            .ok_or(KexError::InvalidState)?;
        let ephemeral = self.ephemeral.take().ok_or(KexError::InvalidState)?;
        let shared_secret = self.mechanism.agree(ephemeral, client_public_key)?;
        let input = ExchangeHashInput::new(
            &self.host_key_blob,
            client_public_key,
            &self.server_public_key,
            shared_secret,
        )?;
        let exchange_hash = compute_exchange_hash(&self.context, &input)?;
        let completion = KexCompletion::first(
            self.context.negotiated_algorithm().to_owned(),
            exchange_hash,
            input.shared_secret().clone(),
            None,
        );
        self.completion = Some(completion);
        self.completion.as_ref().ok_or(KexError::InvalidState)
    }

    /// Returns the prepared exchange hash for host-key signing.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] before [`Self::prepare_exchange`].
    pub(crate) fn exchange_hash(&self) -> Result<&[u8; 32], KexError> {
        Ok(self
            .completion
            .as_ref()
            .ok_or(KexError::InvalidState)?
            .exchange_hash())
    }

    /// Encodes message 31 once, after the exchange hash has been prepared.
    ///
    /// `signature_blob` remains opaque here. The host-key and transport tickets
    /// are responsible for producing and verifying it.
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
    pub(crate) fn completion(&self) -> Option<&KexCompletion> {
        self.completion.as_ref()
    }

    /// Consumes this role and returns its prepared completion.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::InvalidState`] if the exchange was not prepared.
    pub(crate) fn into_completion(self) -> Result<KexCompletion, KexError> {
        self.completion.ok_or(KexError::InvalidState)
    }
}

/// An RFC 4253 section 7.2 key-expansion selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DerivationLetter {
    /// `A`: client-to-server initialization vector.
    A,
    /// `B`: server-to-client initialization vector.
    B,
    /// `C`: client-to-server encryption key.
    C,
    /// `D`: server-to-client encryption key.
    D,
    /// `E`: client-to-server integrity key.
    E,
    /// `F`: server-to-client integrity key.
    F,
}

impl DerivationLetter {
    /// Returns the one-byte selector used by the hash-key construction.
    #[must_use]
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::A => b'A',
            Self::B => b'B',
            Self::C => b'C',
            Self::D => b'D',
            Self::E => b'E',
            Self::F => b'F',
        }
    }
}

impl TryFrom<u8> for DerivationLetter {
    type Error = KexError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'A' => Ok(Self::A),
            b'B' => Ok(Self::B),
            b'C' => Ok(Self::C),
            b'D' => Ok(Self::D),
            b'E' => Ok(Self::E),
            b'F' => Ok(Self::F),
            _ => Err(KexError::InvalidFieldLength),
        }
    }
}

/// Caller-selected output lengths for key-expansion letters `A` through `F`.
///
/// The packet-protection layer chooses these from its negotiated algorithms;
/// this module intentionally makes no cipher or MAC selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DerivationLengths {
    /// Output length for letter `A`.
    pub a: usize,
    /// Output length for letter `B`.
    pub b: usize,
    /// Output length for letter `C`.
    pub c: usize,
    /// Output length for letter `D`.
    pub d: usize,
    /// Output length for letter `E`.
    pub e: usize,
    /// Output length for letter `F`.
    pub f: usize,
}

impl DerivationLengths {
    /// Returns the six requested lengths in `A` through `F` order.
    #[must_use]
    pub(crate) const fn as_array(self) -> [usize; 6] {
        [self.a, self.b, self.c, self.d, self.e, self.f]
    }
}

/// Directional IV, encryption, and integrity material for letters `A` through `F`.
///
/// This is the live session key for the life of a connection, and it is the one
/// place in this crate that holds all six letters at once. Every field is a
/// [`Zeroizing`] buffer, and [`Drop`] wipes all six before the allocations are
/// released — on the success path and on every error path, including the paths
/// where `derive_keys` has produced only some of the letters before failing.
///
/// The value is deliberately **not** [`Clone`] and **not** [`PartialEq`].
///
/// * `Clone` was used once, on the NEWKEYS path, to build the write protector
///   while keeping the read side. A second copy of a session key that nothing
///   wipes is exactly the leak this type exists to prevent, and the copy bought
///   nothing: the two protectors each want their own directional material, so
///   the caller now builds each material once, inside the borrow of the rekey
///   state, and the copy disappears.
/// * `Eq`/`PartialEq` had no caller. A derived comparison of key material is
///   also a trap: `Vec`'s `PartialEq` is length-then-`memcmp`, which is not a
///   constant-time comparison, and "compare two secrets" is a question with a
///   security answer that a trait derive cannot give. If a caller ever needs
///   equality here, it should compare digests, in constant time, on purpose.
///
/// The [`Zeroize`] impl is written out rather than derived: this crate reaches
/// the direct `zeroize` dependency is needed because public API types carry `Zeroizing`, so the derive macro —
/// which expands to a `::zeroize::` path — is not available. Each of the six
/// fields is listed, so a seventh field is a compile error here rather than an
/// unwiped buffer.
///
/// [`PartialEq`]: std::cmp::PartialEq
pub(crate) struct DerivedKeys {
    /// Client-to-server initialization vector (`A`).
    pub iv_client_to_server: Zeroizing<Vec<u8>>,
    /// Server-to-client initialization vector (`B`).
    pub iv_server_to_client: Zeroizing<Vec<u8>>,
    /// Client-to-server encryption key (`C`).
    pub encryption_key_client_to_server: Zeroizing<Vec<u8>>,
    /// Server-to-client encryption key (`D`).
    pub encryption_key_server_to_client: Zeroizing<Vec<u8>>,
    /// Client-to-server integrity key (`E`).
    pub integrity_key_client_to_server: Zeroizing<Vec<u8>>,
    /// Server-to-client integrity key (`F`).
    pub integrity_key_server_to_client: Zeroizing<Vec<u8>>,
}

impl Zeroize for DerivedKeys {
    fn zeroize(&mut self) {
        self.iv_client_to_server.zeroize();
        self.iv_server_to_client.zeroize();
        self.encryption_key_client_to_server.zeroize();
        self.encryption_key_server_to_client.zeroize();
        self.integrity_key_client_to_server.zeroize();
        self.integrity_key_server_to_client.zeroize();
    }
}

// The marker for the claim the `Drop` below actually makes. It is a marker, so
// the compiler checks that the claim is written down and not that it is kept;
// the test in `tests/kex.rs` that empties the six letters through a dropped
// value is what checks the second half.
impl ZeroizeOnDrop for DerivedKeys {}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedKeys")
            .field("a_len", &self.iv_client_to_server.len())
            .field("b_len", &self.iv_server_to_client.len())
            .field("c_len", &self.encryption_key_client_to_server.len())
            .field("d_len", &self.encryption_key_server_to_client.len())
            .field("e_len", &self.integrity_key_client_to_server.len())
            .field("f_len", &self.integrity_key_server_to_client.len())
            .finish()
    }
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        #[cfg(test)]
        DERIVED_KEYS_DROPS.with(|drops| drops.set(drops.get() + 1));
        // `Zeroize for Vec<u8>` wipes the requested length of every letter, so
        // this is the difference between the bytes being gone and the bytes
        // being merely unreachable.
        self.zeroize();
        // The witness is recorded here, after the wipe and before the fields are
        // released, because that is the only moment the letters can be read
        // without reading freed memory.
        #[cfg(test)]
        DERIVED_KEYS_DROP_WIPED.with(|wiped| wiped.set(Some(letters_are_zero(self))));
    }
}

#[cfg(test)]
thread_local! {
    /// `DerivedKeys` destructors that have run on this thread.
    ///
    /// A thread-local rather than a global, so a test can attribute a wipe to
    /// the value it built while the other tests in the same binary run in
    /// parallel.
    static DERIVED_KEYS_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Whether the last `DerivedKeys` destructor to run on this thread found
    /// all six letters already zeroed, and `None` if no destructor has reported
    /// since the value was last taken.
    ///
    /// The answer is recorded inside the destructor rather than after it,
    /// because the letters are released by the same call that wipes them:
    /// reading them once the value is gone would be reading freed memory. `None`
    /// is a distinct answer from `Some(false)` on purpose — a destructor that
    /// was deleted leaves no record at all, and a test that expected a wipe must
    /// fail on that as well as on a wipe that did not happen.
    static DERIVED_KEYS_DROP_WIPED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// How many `DerivedKeys` values have been dropped on this thread.
///
/// This exists for one assertion a trait bound cannot make: that the destructor
/// actually runs, on the success path and on the error paths where a derived
/// key was already in hand and the transport is then dropped before the
/// protectors are installed. Compiled only for this crate's tests, so it costs a
/// published library nothing.
///
/// # Panics
///
/// Never. `Cell::get` on a live thread-local value cannot fail.
#[cfg(test)]
pub(crate) fn derived_keys_drops() -> usize {
    DERIVED_KEYS_DROPS.with(std::cell::Cell::get)
}

/// Takes the last `DerivedKeys` destructor's wipe witness for this thread.
///
/// `Some(true)` means the destructor left six all-zero letters behind,
/// `Some(false)` that it ran and found live key bytes, and `None` that no
/// destructor has reported since the last call. Taking the value clears it, so
/// each caller reads only the destructors that ran after its own setup.
///
/// This is the assertion the drop counter could not make. [`Drop`] is the only
/// thing in the crate that can wipe a `DerivedKeys`, and a marker trait records
/// that it exists rather than that it works, so the test that reads this is the
/// only place the claim is checked against the bytes.
///
/// # Panics
///
/// Never. `Cell::take` on a live thread-local value cannot fail.
#[cfg(test)]
#[allow(dead_code)] // Only `tests/kex.rs` calls it; other binaries include this module.
pub(crate) fn take_derived_keys_drop_wipe() -> Option<bool> {
    DERIVED_KEYS_DROP_WIPED.with(std::cell::Cell::take)
}

/// Whether all six letters of a derived key are zero bytes.
///
/// # Panics
///
/// Never. It reads the six fields and sums their bytes.
#[cfg(test)]
fn letters_are_zero(keys: &DerivedKeys) -> bool {
    [
        keys.iv_client_to_server.as_slice(),
        keys.iv_server_to_client.as_slice(),
        keys.encryption_key_client_to_server.as_slice(),
        keys.encryption_key_server_to_client.as_slice(),
        keys.integrity_key_client_to_server.as_slice(),
        keys.integrity_key_server_to_client.as_slice(),
    ]
    .into_iter()
    .all(all_zero)
}

/// Derives one RFC 4253 section 7.2 key from `K`, `H`, a session ID, and a letter.
///
/// The first block is `HASH(K || H || letter || session_id)`. Each additional
/// block is `HASH(K || H || previous)` and is appended until `output_length` is
/// reached.
///
/// # Errors
///
/// Returns [`KexError::InvalidExchangeHash`] unless `exchange_hash` contains 32
/// bytes, [`KexError::InvalidSessionId`] unless `session_id` contains 32 bytes,
/// and [`KexError::DerivedKeyLimitExceeded`] for an oversized request.
pub(crate) fn derive_key(
    shared_secret: &SharedSecret,
    exchange_hash: &[u8],
    session_id: &[u8],
    letter: DerivationLetter,
    output_length: usize,
) -> Result<Vec<u8>, KexError> {
    validate_key_derivation_inputs(exchange_hash, session_id, output_length)?;
    if output_length == 0 {
        return Ok(Vec::new());
    }

    let mut first = Sha256::new();
    first.update(shared_secret.as_bytes());
    first.update(exchange_hash);
    first.update([letter.as_byte()]);
    first.update(session_id);
    let mut output = Vec::with_capacity(output_length);
    output.extend_from_slice(&first.finalize());

    while output.len() < output_length {
        let mut next = Sha256::new();
        next.update(shared_secret.as_bytes());
        next.update(exchange_hash);
        next.update(&output);
        output.extend_from_slice(&next.finalize());
    }
    output.truncate(output_length);
    Ok(output)
}

/// Derives all RFC 4253 letters `A` through `F` using caller-selected lengths.
///
/// # Errors
///
/// Returns the same validation errors as [`derive_key`].
pub(crate) fn derive_keys(
    shared_secret: &SharedSecret,
    exchange_hash: &[u8],
    session_id: &[u8],
    lengths: DerivationLengths,
) -> Result<DerivedKeys, KexError> {
    Ok(DerivedKeys {
        iv_client_to_server: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::A,
            lengths.a,
        )?),
        iv_server_to_client: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::B,
            lengths.b,
        )?),
        encryption_key_client_to_server: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::C,
            lengths.c,
        )?),
        encryption_key_server_to_client: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::D,
            lengths.d,
        )?),
        integrity_key_client_to_server: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::E,
            lengths.e,
        )?),
        integrity_key_server_to_client: Zeroizing::new(derive_key(
            shared_secret,
            exchange_hash,
            session_id,
            DerivationLetter::F,
            lengths.f,
        )?),
    })
}

pub(super) fn all_zero(bytes: &[u8]) -> bool {
    let mut combined = 0_u8;
    for byte in bytes {
        combined |= *byte;
    }
    combined == 0
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

fn validate_kexinit_size(value: &[u8]) -> Result<(), KexError> {
    if value.len() > neotales_ssh::DEFAULT_STRING_LIMIT {
        return Err(KexError::Wire(WireError::LimitExceeded));
    }
    Ok(())
}

fn map_negotiation_error(_error: NegotiationError) -> KexError {
    KexError::InvalidProposal
}

/// The key-exchange names routed through [`KexContext`].
///
/// A subset of [`SUPPORTED_KEX_ALGORITHMS`], and deliberately not equal to it.
/// [`KexContext`] binds the RFC 5656 transcript, the RFC 4253 exchange hash and
/// the session identifier, and the mechanisms driven through it are the ones
/// whose message layout that shared code can speak: Curve25519 and NIST P-256
/// both carry an SSH string in messages 30 and 31, and the ML-KEM hybrid is
/// driven through the same context with a codec of its own.
///
/// `diffie-hellman-group16-sha512` is supported by a handshake and therefore in
/// [`SUPPORTED_KEX_ALGORITHMS`], but it is *not* routed through this context. It
/// uses `mpint` values in messages 30 and 31, a SHA-512 exchange hash and its own
/// key-derivation chain, and both handshakes reach it through
/// `dh_group16::Group16KexContext` instead. Adding it here would let a
/// [`KexContext`] be built for a mechanism whose wire form it would then
/// mis-encode, which is a wider change to the accepted algorithms than this
/// list is for.
///
/// `tests/kexinit.rs` asserts this list is a subset of
/// [`SUPPORTED_KEX_ALGORITHMS`], so the two cannot drift apart silently.
const CONTEXT_KEX_ALGORITHMS: &[&str] = &[
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_MLKEM768X25519_SHA256,
];

// A compile-time proof that the routing allowlist is a subset of the advertised
// one, so the two cannot drift apart without a build failure rather than with a
// silently rejected proposal. Written as an explicit loop because neither
// `<[T]>::contains`, `==` on `&str`, nor a `for` loop over a slice is available
// in a `const` context.
const _: () = {
    let mut context_index = 0;
    while context_index < CONTEXT_KEX_ALGORITHMS.len() {
        let name = CONTEXT_KEX_ALGORITHMS[context_index];
        let mut supported_index = 0;
        let mut found = false;
        while supported_index < SUPPORTED_KEX_ALGORITHMS.len() {
            if same_name(SUPPORTED_KEX_ALGORITHMS[supported_index], name) {
                found = true;
            }
            supported_index += 1;
        }
        assert!(
            found,
            "CONTEXT_KEX_ALGORITHMS must be a subset of SUPPORTED_KEX_ALGORITHMS",
        );
        context_index += 1;
    }
};

/// Whether two algorithm names are the same string, in a `const` context.
///
/// `PartialEq for str` is not a `const` trait, and the check above runs at
/// compile time.
const fn same_name(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn validate_supported_algorithm(name: &str) -> Result<(), KexError> {
    if CONTEXT_KEX_ALGORITHMS.contains(&name) {
        Ok(())
    } else {
        Err(KexError::AlgorithmMismatch)
    }
}

fn validate_nonempty_host_key(value: &[u8]) -> Result<(), KexError> {
    if value.is_empty() {
        return Err(KexError::InvalidFieldLength);
    }
    Ok(())
}

fn bind_mechanism(context: &KexContext, mechanism_name: &str) -> Result<(), KexError> {
    validate_supported_algorithm(context.negotiated_algorithm())?;
    if context.negotiated_algorithm() != mechanism_name {
        return Err(KexError::AlgorithmMismatch);
    }
    Ok(())
}

fn validate_public_key_for_algorithm(
    algorithm: &str,
    public_key: &[u8],
    client_role: bool,
) -> Result<(), KexError> {
    match algorithm {
        KEX_CURVE25519_SHA256 | KEX_CURVE25519_SHA256_LIBCSSH => {
            curve25519::validate_public_key(public_key)
        }
        KEX_ECDH_SHA2_NISTP256 => ecdh_p256::validate_public_key(public_key),
        KEX_MLKEM768X25519_SHA256 if client_role => {
            mlkem768_x25519::validate_client_public_blob(public_key)
        }
        KEX_MLKEM768X25519_SHA256 => mlkem768_x25519::validate_server_public_blob(public_key),
        _ => Err(KexError::AlgorithmMismatch),
    }
}

fn validate_key_derivation_inputs(
    exchange_hash: &[u8],
    session_id: &[u8],
    output_length: usize,
) -> Result<(), KexError> {
    if exchange_hash.len() != 32 {
        return Err(KexError::InvalidExchangeHash);
    }
    if session_id.len() != 32 {
        return Err(KexError::InvalidSessionId);
    }
    if output_length > MAX_DERIVED_KEY_LENGTH {
        return Err(KexError::DerivedKeyLimitExceeded);
    }
    Ok(())
}
