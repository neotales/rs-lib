//! SSH service and user authentication over an established protected transport.
//!
//! This module deliberately contains protocol dispatch only. It reuses the
//! packet protection, sequence state, and key-exchange transcript owned by the
//! client and server transports; it never creates a second connection or a
//! second cipher. The test-local module harness includes this file until the
//! crate-surface ticket wires it into the library root.

use std::fmt;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};

use neotales_ssh::gssapi::{
    GSSAPI_WITH_MIC_METHOD, GssapiError, GssapiExchange, GssapiExchangeAction, GssapiRequest,
    GssapiTokenMechanism, GssapiTokenMechanismCallback, MAX_GSSAPI_EXCHANGES,
    gssapi_mechanism_identifier,
};
use neotales_ssh::{DEFAULT_STRING_LIMIT, Error as WireError, Reader, Writer};
use rsa::traits::PublicKeyParts as _;
use sha2::Digest;
use zeroize::Zeroizing;

use crate::agent::{AgentClient, AgentError};
use crate::cipher::{PlaintextBytes, PlaintextSlot};
use crate::client::{ClientTransport, TransportError as ClientTransportError};
use crate::ecdsa_hostkey::{EcdsaHostKeyError, EcdsaSigner, SSH_ECDSA_SHA2_NISTP256};
use crate::hostkey::{Ed25519PublicKey, Ed25519Signer, HostKeyError, verify_host_key_signature};
use crate::server::{
    ServerTransport, ServerTransportError, TransportError as ServerUnderlyingTransportError,
};

/// SSH message number for `SSH_MSG_SERVICE_REQUEST`.
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// SSH message number for `SSH_MSG_SERVICE_ACCEPT`.
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// SSH message number for `SSH_MSG_USERAUTH_REQUEST`.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// SSH message number for `SSH_MSG_USERAUTH_FAILURE`.
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// SSH message number for `SSH_MSG_USERAUTH_SUCCESS`.
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// SSH message number for `SSH_MSG_USERAUTH_BANNER`.
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
/// SSH message number for `SSH_MSG_USERAUTH_PK_OK` and, in the
/// keyboard-interactive method, `SSH_MSG_USERAUTH_INFO_REQUEST`.
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
/// SSH message number for the RFC 4256 keyboard-interactive info request.
pub const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
/// SSH message number for the RFC 4256 keyboard-interactive info response.
pub const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
/// SSH message number for the RFC 4462 GSSAPI response.
///
/// This value shares the numeric message space with the keyboard-interactive
/// info request; the active authentication state determines its meaning.
pub const SSH_MSG_USERAUTH_GSSAPI_RESPONSE: u8 =
    neotales_ssh::gssapi::SSH_MSG_USERAUTH_GSSAPI_RESPONSE;
/// SSH message number for the RFC 4462 GSSAPI token.
pub const SSH_MSG_USERAUTH_GSSAPI_TOKEN: u8 = neotales_ssh::gssapi::SSH_MSG_USERAUTH_GSSAPI_TOKEN;
/// SSH message number for the RFC 4462 GSSAPI exchange acknowledgement.
pub const SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: u8 =
    neotales_ssh::gssapi::SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE;
/// The RFC 4462 GSSAPI user-authentication method name.
pub const SSH_GSSAPI_WITH_MIC_METHOD: &str = GSSAPI_WITH_MIC_METHOD;
/// The only service name accepted by this implementation.
pub const SSH_USERAUTH_SERVICE: &str = "ssh-userauth";
/// The service name carried inside a user-authentication request.
pub const SSH_CONNECTION_SERVICE: &str = "ssh-connection";
/// The public-key user-authentication method name.
pub const SSH_PUBLICKEY_METHOD: &str = "publickey";
/// The password user-authentication method name.
pub const SSH_PASSWORD_METHOD: &str = "password";
/// The RFC 4256 keyboard-interactive user-authentication method name.
pub const SSH_KEYBOARD_INTERACTIVE_METHOD: &str = "keyboard-interactive";
/// The Ed25519 user-authentication algorithm name.
pub const SSH_ED25519: &str = "ssh-ed25519";
/// The RSA user-authentication signature algorithm name.
pub const SSH_RSA_SHA2_256: &str = "rsa-sha2-256";
/// The RSA public-key blob type name.
pub const SSH_RSA: &str = "ssh-rsa";
/// The maximum number of prompts or responses in one keyboard-interactive round.
pub const MAX_KEYBOARD_INTERACTIVE_PROMPTS: usize = 32;
/// The maximum byte length of one keyboard-interactive prompt or response.
pub const MAX_KEYBOARD_INTERACTIVE_STRING: usize = 1024;
/// Alias for [`MAX_KEYBOARD_INTERACTIVE_PROMPTS`] used for response limits.
pub const MAX_KEYBOARD_INTERACTIVE_RESPONSES: usize = MAX_KEYBOARD_INTERACTIVE_PROMPTS;
/// Alias for [`MAX_KEYBOARD_INTERACTIVE_STRING`] used for response limits.
pub const MAX_KEYBOARD_INTERACTIVE_RESPONSE_LENGTH: usize = MAX_KEYBOARD_INTERACTIVE_STRING;

const MAX_AUTH_BANNERS: usize = 8;

/// A bounded, non-sensitive authentication failure.
///
/// Values produced by this module never retain a password, private-key seed,
/// signature bytes, or callback error. Wire and transport details are
/// deliberately reduced to safe enum values before they reach this type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthError {
    /// An SSH primitive was malformed, truncated, or otherwise invalid.
    Wire(WireError),
    /// The underlying protected transport failed.
    Transport,
    /// A service or user-authentication packet had an invalid shape.
    InvalidRequest,
    /// The requested service was not `ssh-userauth`.
    UnsupportedService,
    /// A user-authentication request arrived before service negotiation.
    ServiceRequired,
    /// The peer sent a response that is not valid at this state.
    UnexpectedMessage,
    /// A public-key blob or algorithm was invalid or unsupported.
    InvalidKey,
    /// An OpenSSH agent could not produce a signature for the named key.
    ///
    /// This is what an agent-backed identity reports when the agent does not
    /// hold the key, refuses it, or is unreachable. It is deliberately a
    /// distinct error rather than a fallback: an identity that cannot be used
    /// has to say so, not authenticate as something else.
    AgentUnavailable,
    /// A signature was malformed or did not verify.
    InvalidProof,
    /// The bounded GSSAPI framing or caller mechanism failed.
    Gssapi(GssapiError),
    /// The key was not authorized by the explicit server policy.
    KeyRejected,
    /// The server's service request was rejected.
    ServiceRejected,
    /// A configured authentication callback rejected the attempt.
    CallbackRejected,
    /// A configured callback panicked; the panic payload is discarded.
    CallbackPanicked,
    /// The caller-selected attempt bound was exhausted.
    AttemptsExhausted,
    /// No configured client method remained after a failure response.
    AuthenticationFailed,
    /// The method list supplied to the client was empty.
    NoMethods,
    /// More input is needed before the nonblocking server can make progress.
    NeedMoreData,
    /// A server authenticator was used after it had already succeeded.
    AlreadyAuthenticated,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH authentication wire error: {error}"),
            Self::Transport => formatter.write_str("SSH authentication transport failed"),
            Self::InvalidRequest => formatter.write_str("SSH authentication request is invalid"),
            Self::UnsupportedService => {
                formatter.write_str("SSH authentication service is unsupported")
            }
            Self::ServiceRequired => {
                formatter.write_str("SSH user authentication requires service negotiation")
            }
            Self::UnexpectedMessage => {
                formatter.write_str("SSH authentication received an unexpected message")
            }
            Self::InvalidKey => formatter.write_str("SSH authentication key is invalid"),
            Self::AgentUnavailable => {
                formatter.write_str("SSH agent did not sign for the requested identity")
            }
            Self::InvalidProof => formatter.write_str("SSH authentication proof is invalid"),
            Self::Gssapi(error) => write!(formatter, "SSH GSSAPI authentication failed: {error}"),
            Self::KeyRejected => formatter.write_str("SSH authentication key was rejected"),
            Self::ServiceRejected => formatter.write_str("SSH authentication service was rejected"),
            Self::CallbackRejected => {
                formatter.write_str("SSH authentication callback rejected the attempt")
            }
            Self::CallbackPanicked => formatter.write_str("SSH authentication callback panicked"),
            Self::AttemptsExhausted => formatter.write_str("SSH authentication attempts exhausted"),
            Self::AuthenticationFailed => formatter.write_str("SSH authentication failed"),
            Self::NoMethods => formatter.write_str("SSH authentication has no methods to try"),
            Self::NeedMoreData => formatter.write_str("SSH authentication needs more input"),
            Self::AlreadyAuthenticated => {
                formatter.write_str("SSH authentication has already succeeded")
            }
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Gssapi(error) => Some(error),
            Self::Transport
            | Self::InvalidRequest
            | Self::AgentUnavailable
            | Self::UnsupportedService
            | Self::ServiceRequired
            | Self::UnexpectedMessage
            | Self::InvalidKey
            | Self::InvalidProof
            | Self::KeyRejected
            | Self::ServiceRejected
            | Self::CallbackRejected
            | Self::CallbackPanicked
            | Self::AttemptsExhausted
            | Self::AuthenticationFailed
            | Self::NoMethods
            | Self::NeedMoreData
            | Self::AlreadyAuthenticated => None,
        }
    }
}

impl From<WireError> for AuthError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<GssapiError> for AuthError {
    fn from(error: GssapiError) -> Self {
        Self::Gssapi(error)
    }
}

impl From<ClientTransportError> for AuthError {
    fn from(_error: ClientTransportError) -> Self {
        Self::Transport
    }
}

impl From<ServerTransportError> for AuthError {
    fn from(_error: ServerTransportError) -> Self {
        Self::Transport
    }
}

impl From<io::Error> for AuthError {
    fn from(_error: io::Error) -> Self {
        Self::Transport
    }
}

/// A descriptive alias for the shared authentication error type.
pub type ServerAuthError = AuthError;
/// A descriptive alias for the shared authentication error type.
pub type ClientAuthError = AuthError;

/// A validated RSA public key in SSH `ssh-rsa` wire form.
///
/// The request/signature algorithm is `rsa-sha2-256`, while the key blob's
/// type field remains the RFC 4253 `ssh-rsa` form.
#[derive(Clone)]
pub struct RsaPublicKey {
    key: rsa::RsaPublicKey,
    blob: Vec<u8>,
}

impl RsaPublicKey {
    /// Parses an exact `string "ssh-rsa" || mpint e || mpint n` blob.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] for a wrong type, negative or
    /// non-canonical integer, truncated/trailing data, or an invalid RSA key.
    pub fn from_blob(blob: &[u8]) -> Result<Self, AuthError> {
        let mut reader = Reader::new(blob);
        if reader.read_string()? != SSH_RSA.as_bytes() {
            return Err(AuthError::InvalidKey);
        }
        let exponent = reader.read_mpint()?;
        if exponent.is_empty() || exponent.first().is_some_and(|byte| byte & 0x80 != 0) {
            return Err(AuthError::InvalidKey);
        }
        let modulus = reader.read_mpint()?;
        if modulus.is_empty() || modulus.first().is_some_and(|byte| byte & 0x80 != 0) {
            return Err(AuthError::InvalidKey);
        }
        if !reader.is_empty() {
            return Err(AuthError::InvalidKey);
        }

        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(modulus),
            rsa::BigUint::from_bytes_be(exponent),
        )
        .map_err(|_error| AuthError::InvalidKey)?;
        Ok(Self {
            blob: blob.to_vec(),
            key,
        })
    }

    /// Creates a wire wrapper from an upstream RSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] if the key cannot be encoded.
    pub fn from_public_key(key: &rsa::RsaPublicKey) -> Result<Self, AuthError> {
        let key = rsa::RsaPublicKey::new(key.n().clone(), key.e().clone())
            .map_err(|_error| AuthError::InvalidKey)?;
        let blob = encode_rsa_blob(&key)?;
        Ok(Self { key, blob })
    }

    /// Returns the `rsa-sha2-256` request algorithm.
    #[must_use]
    pub const fn algorithm() -> &'static str {
        SSH_RSA_SHA2_256
    }

    /// Returns the `ssh-rsa` public-key blob type.
    #[must_use]
    pub const fn key_type() -> &'static str {
        SSH_RSA
    }

    /// Returns the exact SSH public-key blob.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }

    /// Returns the validated upstream RSA public key.
    #[must_use]
    pub const fn public_key(&self) -> &rsa::RsaPublicKey {
        &self.key
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaPublicKey")
            .field("algorithm", &Self::algorithm())
            .field("key_type", &Self::key_type())
            .finish_non_exhaustive()
    }
}

/// An RSA private-key signer for `rsa-sha2-256` user authentication.
///
/// The private key is kept behind a redacted debug implementation. The signer
/// uses PKCS#1 v1.5 with a SHA-256 digest; RSA-PSS and SHA-1 are not accepted
/// by the server verifier.
pub struct RsaAuthSigner {
    key: rsa::RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaAuthSigner {
    /// Creates a signer from an upstream RSA private key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] if its public component cannot be
    /// encoded as an SSH blob.
    pub fn from_private_key(key: rsa::RsaPrivateKey) -> Result<Self, AuthError> {
        let public = key.to_public_key();
        let public_key = RsaPublicKey::from_public_key(&public)?;
        Ok(Self { key, public_key })
    }

    /// Creates a signer from two fixed primes and a public exponent.
    ///
    /// This constructor is useful for embedding a test or application key
    /// without a random-number dependency.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] if the components do not form a valid
    /// RSA private key.
    pub fn from_p_q(
        p: rsa::BigUint,
        q: rsa::BigUint,
        exponent: rsa::BigUint,
    ) -> Result<Self, AuthError> {
        let key =
            rsa::RsaPrivateKey::from_p_q(p, q, exponent).map_err(|_error| AuthError::InvalidKey)?;
        Self::from_private_key(key)
    }

    /// Returns the corresponding validated public key.
    #[must_use]
    pub const fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Returns the exact SSH public-key blob.
    #[must_use]
    pub fn public_key_blob(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Signs raw authentication bytes and emits an SSH signature blob.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidProof`] if the upstream RSA operation or
    /// fixed-size signature encoding fails.
    pub fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        let digest = sha2::Sha256::digest(bytes);
        let raw_signature = self
            .key
            .sign(rsa::Pkcs1v15Sign::new_unprefixed(), digest.as_slice())
            .map_err(|_error| AuthError::InvalidProof)?;
        let mut writer = Writer::new();
        writer.write_string(SSH_RSA_SHA2_256)?;
        writer.write_string(&raw_signature)?;
        Ok(writer.into_bytes())
    }
}

impl fmt::Debug for RsaAuthSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaAuthSigner")
            .field("algorithm", &SSH_RSA_SHA2_256)
            .field("key_type", &SSH_RSA)
            .finish_non_exhaustive()
    }
}

/// A short alias for [`RsaAuthSigner`].
pub type RsaSigner = RsaAuthSigner;

/// A byte transport that an OpenSSH agent can be reached over.
///
/// This exists so [`AgentKeySigner`] can hold an agent without being generic
/// over its transport, which keeps it usable from the non-generic
/// [`PublicKeySigner`].
pub trait AgentTransport: Send + 'static {
    /// Requests one signature for `key_blob` over `data`.
    ///
    /// # Errors
    ///
    /// Returns the agent's own failure, or a transport error, unchanged.
    fn agent_sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError>;
}

impl<T> AgentTransport for AgentClient<T>
where
    T: Read + Write + Send + 'static,
{
    fn agent_sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError> {
        self.sign_with_flags(key_blob, data, flags)
    }
}

/// An identity held by an OpenSSH agent, which signs on this value's behalf.
///
/// # What this is not
///
/// This is not a wrapper that can quietly do something else. It holds the exact
/// key blob it will ask the agent about, and it reports
/// [`AuthError::AgentUnavailable`] when the agent does not answer. There is no
/// local key behind it, because a variant that authenticated with a local key
/// while claiming to be an agent identity would be worse than not offering the
/// capability at all.
///
/// # Shape
///
/// Signing an agent request means writing to a socket and reading the reply, so
/// it needs exclusive access to the client. The authentication loop borrows a
/// method in order to sign with it, so the client is held behind a mutex and
/// `sign` takes `&self`. The alternative is a `&mut` signer threaded through
/// `ClientAuthMethod`, which would make every caller's closure and every
/// `&ClientAuthMethod` borrow mutably. A mutex also keeps the value `Send`,
/// which a `RefCell` would not.
pub struct AgentKeySigner {
    client: std::sync::Mutex<Box<dyn AgentTransport>>,
    key_blob: Vec<u8>,
    algorithm: &'static str,
    flags: u32,
}

impl AgentKeySigner {
    /// Names one of the agent's identities by its public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] when the blob does not begin with an
    /// SSH string naming a key algorithm this crate can request a signature
    /// for. The error names the key rather than replacing it: there is no
    /// fallback, and a caller that wanted a different identity has to name that
    /// one.
    pub fn new<T>(client: AgentClient<T>, key_blob: &[u8]) -> Result<Self, AuthError>
    where
        T: Read + Write + Send + 'static,
    {
        let (algorithm, flags) = agent_signing_flags(key_blob)?;
        Ok(Self {
            client: std::sync::Mutex::new(Box::new(client)),
            key_blob: key_blob.to_vec(),
            algorithm,
            flags,
        })
    }

    /// Returns the exact key blob this value will ask the agent to sign with.
    #[must_use]
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    /// Returns the algorithm name the agent is asked to produce.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Returns the agent flags word implied by the key type.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Signs by asking the agent, with flags implied by the key type.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AgentUnavailable`] if the agent cannot be reached,
    /// does not hold the key, or refuses it, and [`AuthError::InvalidProof`]
    /// if it returns a signature that is not a well-formed SSH string.
    pub fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.sign_with_flags(bytes, self.flags)
    }

    /// Signs by asking the agent, with an explicit OpenSSH agent flags word.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::sign`].
    pub fn sign_with_flags(&self, bytes: &[u8], flags: u32) -> Result<Vec<u8>, AuthError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_poisoned| AuthError::AgentUnavailable)?;
        let signature = client
            .agent_sign(&self.key_blob, bytes, flags)
            .map_err(|error| map_agent_error(&error))?;
        if signature.is_empty() {
            return Err(AuthError::InvalidProof);
        }
        Ok(signature)
    }
}

impl fmt::Debug for AgentKeySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentKeySigner")
            .field("algorithm", &self.algorithm)
            .field("key_blob_len", &self.key_blob.len())
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// The key algorithm and agent flags word implied by a public-key blob.
///
/// Ed25519 and ECDSA sign with their own format identifier, so their flags word
/// is zero. RSA has no single key type, so the SHA-2 variant has to be requested
/// explicitly: OpenSSH's `agent_decode_alg` maps `SSH_AGENT_RSA_SHA2_256` to
/// `rsa-sha2-256` and returns null otherwise, which selects the SHA-1
/// signature this crate does not accept.
fn agent_signing_flags(key_blob: &[u8]) -> Result<(&'static str, u32), AuthError> {
    let mut reader = Reader::new(key_blob);
    let algorithm = reader
        .read_string()
        .map_err(|_error| AuthError::InvalidKey)?;
    if algorithm == crate::hostkey::SSH_ED25519.as_bytes() {
        return Ok((SSH_ED25519, 0));
    }
    if algorithm == SSH_RSA.as_bytes() {
        return Ok((SSH_RSA_SHA2_256, crate::agent::SSH_AGENT_RSA_SHA2_256));
    }
    if algorithm == SSH_ECDSA_SHA2_NISTP256.as_bytes() {
        return Ok((SSH_ECDSA_SHA2_NISTP256, 0));
    }
    Err(AuthError::InvalidKey)
}

fn map_agent_error(error: &AgentError) -> AuthError {
    match error {
        AgentError::Wire(error) => AuthError::Wire(*error),
        AgentError::Io(_)
        | AgentError::InvalidFrame
        | AgentError::FrameTooLarge
        | AgentError::UnexpectedMessage(_)
        | AgentError::AgentFailure
        | AgentError::UnsupportedKey
        | AgentError::UnsupportedPlatform => AuthError::AgentUnavailable,
    }
}

/// A client-side public-key signer usable by the authentication loop.
pub enum PublicKeySigner {
    /// An Ed25519 signer using raw SSH transcript bytes.
    Ed25519(Ed25519Signer),
    /// An RSA signer using `rsa-sha2-256` and PKCS#1 v1.5/SHA-256.
    Rsa(RsaAuthSigner),
    /// A NIST P-256 ECDSA signer using `ecdsa-sha2-nistp256`.
    Ecdsa(EcdsaSigner),
    /// A key held by an OpenSSH agent, which signs on this value's behalf.
    ///
    /// The variant is deliberately honest about where the key lives: it holds
    /// the exact key blob it will ask the agent to sign with, and a signature
    /// request that the agent cannot answer is
    /// [`AuthError::AgentUnavailable`]. There is no local key behind it to fall
    /// back on, because a variant that quietly authenticated with something
    /// other than the identity it names would be worse than its absence.
    Agent(AgentKeySigner),
}

impl PublicKeySigner {
    /// Creates an Ed25519 public-key signer.
    #[must_use]
    pub const fn ed25519(signer: Ed25519Signer) -> Self {
        Self::Ed25519(signer)
    }

    /// Creates an RSA public-key signer.
    #[must_use]
    pub const fn rsa(signer: RsaAuthSigner) -> Self {
        Self::Rsa(signer)
    }

    /// Creates a NIST P-256 ECDSA public-key signer.
    ///
    /// The algorithm is `ecdsa-sha2-nistp256`, the one curve this crate's
    /// [`EcdsaSigner`] implements. This is an *identity* key for client
    /// authentication and is independent of
    /// `SUPPORTED_HOST_KEY_ALGORITHMS`, which is a host-key policy.
    #[must_use]
    pub const fn ecdsa(signer: EcdsaSigner) -> Self {
        Self::Ecdsa(signer)
    }

    /// Creates a signer backed by a key held in an OpenSSH agent.
    #[must_use]
    pub const fn agent(signer: AgentKeySigner) -> Self {
        Self::Agent(signer)
    }

    /// Returns the algorithm name used in the request and signature.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => SSH_ED25519,
            Self::Rsa(_) => SSH_RSA_SHA2_256,
            Self::Ecdsa(_) => SSH_ECDSA_SHA2_NISTP256,
            Self::Agent(signer) => signer.algorithm(),
        }
    }

    /// Returns the SSH public-key blob.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] if the fixed key encoding fails.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, AuthError> {
        match self {
            Self::Ed25519(signer) => signer.public_key_blob().map_err(map_hostkey_error),
            Self::Rsa(signer) => Ok(signer.public_key_blob().to_vec()),
            Self::Ecdsa(signer) => signer.public_key_blob().map_err(map_ecdsa_error),
            Self::Agent(signer) => Ok(signer.key_blob().to_vec()),
        }
    }

    /// Returns whether signing is performed by an external key holder.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::Agent(_))
    }

    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        match self {
            Self::Ed25519(signer) => signer.sign_exchange_hash(bytes).map_err(map_hostkey_error),
            Self::Rsa(signer) => signer.sign(bytes),
            Self::Ecdsa(signer) => signer.sign_exchange_hash(bytes).map_err(map_ecdsa_error),
            Self::Agent(signer) => signer.sign(bytes),
        }
    }
}

impl fmt::Debug for PublicKeySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicKeySigner")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

/// A password policy callback.
///
/// The callback receives the password only for the duration of the policy
/// call. Its boolean result is deliberately reduced to an accept/reject bit;
/// callback error values are never retained or formatted.
pub trait PasswordVerifier {
    /// Returns `true` only when the supplied password is accepted.
    fn verify(&self, password: &str) -> bool;
}

impl<F> PasswordVerifier for F
where
    F: for<'password> Fn(&'password str) -> bool + ?Sized,
{
    fn verify(&self, password: &str) -> bool {
        self(password)
    }
}

struct PasswordCallback<F>(F);

impl<F> PasswordVerifier for PasswordCallback<F>
where
    F: for<'password> Fn(&'password str) -> bool,
{
    fn verify(&self, password: &str) -> bool {
        (self.0)(password)
    }
}

/// An additional public-key policy callback.
///
/// Cryptographic verification and authorized-key matching happen before this
/// callback is called. It is an explicit final policy decision, useful for
/// revocations, account checks, and future certificate/external-signer
/// adapters.
pub trait PublicKeyVerifier {
    /// Returns `true` when the verified key may authenticate.
    fn verify(
        &self,
        algorithm: &str,
        key_blob: &[u8],
        signed_bytes: &[u8],
        signature_blob: &[u8],
    ) -> bool;
}

impl<F> PublicKeyVerifier for F
where
    F: for<'algorithm, 'key, 'signed, 'proof> Fn(
            &'algorithm str,
            &'key [u8],
            &'signed [u8],
            &'proof [u8],
        ) -> bool
        + ?Sized,
{
    fn verify(
        &self,
        algorithm: &str,
        key_blob: &[u8],
        signed_bytes: &[u8],
        signature_blob: &[u8],
    ) -> bool {
        self(algorithm, key_blob, signed_bytes, signature_blob)
    }
}

struct PublicKeyCallback<F>(F);

impl<F> PublicKeyVerifier for PublicKeyCallback<F>
where
    F: for<'algorithm, 'key, 'signed, 'proof> Fn(
        &'algorithm str,
        &'key [u8],
        &'signed [u8],
        &'proof [u8],
    ) -> bool,
{
    fn verify(
        &self,
        algorithm: &str,
        key_blob: &[u8],
        signed_bytes: &[u8],
        signature_blob: &[u8],
    ) -> bool {
        (self.0)(algorithm, key_blob, signed_bytes, signature_blob)
    }
}

/// One server-supplied SSH user-authentication banner.
///
/// Its `Debug` implementation is deliberately redacted so untrusted banner
/// text cannot accidentally become a diagnostic sink.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthBanner {
    message: String,
    language: String,
}

impl AuthBanner {
    /// Creates a banner from its SSH message and language strings.
    #[must_use]
    pub fn new(message: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            language: language.into(),
        }
    }

    /// Returns the banner message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the banner language tag.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }
}

impl fmt::Debug for AuthBanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthBanner")
            .field("message", &"<redacted>")
            .field("language", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for AuthBanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// A password policy decision that can represent RFC 4252 partial success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordDecision {
    /// Complete authentication with message 52.
    Accept,
    /// Reject this method with message 51 and `partial_success = false`.
    Reject,
    /// Reject this method as incomplete with message 51 and
    /// `partial_success = true`.
    PartialSuccess,
}

impl PasswordDecision {
    /// Returns the accepting decision.
    #[must_use]
    pub const fn accept() -> Self {
        Self::Accept
    }

    /// Returns the rejecting decision.
    #[must_use]
    pub const fn reject() -> Self {
        Self::Reject
    }

    /// Returns the partial-success decision.
    #[must_use]
    pub const fn partial_success() -> Self {
        Self::PartialSuccess
    }

    /// Compatibility spelling for [`Self::Accept`].
    #[allow(non_upper_case_globals)]
    pub const Accepted: Self = Self::Accept;

    /// Compatibility spelling for [`Self::Reject`].
    #[allow(non_upper_case_globals)]
    pub const Rejected: Self = Self::Reject;

    /// Short compatibility spelling for [`Self::PartialSuccess`].
    #[allow(non_upper_case_globals)]
    pub const Partial: Self = Self::PartialSuccess;

    /// Returns whether this decision completes authentication.
    #[must_use]
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }

    /// Returns whether this decision is a partial-success response.
    #[must_use]
    pub const fn is_partial_success(self) -> bool {
        matches!(self, Self::PartialSuccess)
    }
}

/// A descriptive alias for [`PasswordDecision`].
pub type ServerPasswordDecision = PasswordDecision;
/// A descriptive alias for [`PasswordDecision`].
pub type PasswordAuthDecision = PasswordDecision;

/// A callback that returns a password decision.
pub trait PasswordDecisionCallback {
    /// Evaluates one password without exposing it in an error value.
    fn decide(&self, password: &str) -> PasswordDecision;
}

impl<F> PasswordDecisionCallback for F
where
    F: for<'password> Fn(&'password str) -> PasswordDecision + ?Sized,
{
    fn decide(&self, password: &str) -> PasswordDecision {
        self(password)
    }
}

struct PasswordDecisionCallbackFn<F>(F);

impl<F> PasswordDecisionCallback for PasswordDecisionCallbackFn<F>
where
    F: for<'password> Fn(&'password str) -> PasswordDecision,
{
    fn decide(&self, password: &str) -> PasswordDecision {
        (self.0)(password)
    }
}

struct PasswordDecisionResultCallback<F, E>(F, PhantomData<E>);

impl<F, E> PasswordDecisionCallback for PasswordDecisionResultCallback<F, E>
where
    F: for<'password> Fn(&'password str) -> Result<PasswordDecision, E>,
{
    fn decide(&self, password: &str) -> PasswordDecision {
        match (self.0)(password) {
            Ok(decision) => decision,
            Err(_error) => PasswordDecision::Reject,
        }
    }
}

/// One RFC 4256 keyboard-interactive prompt.
///
/// Prompt text is intentionally omitted from `Debug`; callers that need to
/// display it must explicitly use [`Self::text`].
#[derive(Clone, Eq, PartialEq)]
pub struct KeyboardInteractivePrompt {
    text_value: String,
    echo: bool,
}

impl KeyboardInteractivePrompt {
    /// Creates a prompt and its echo flag.
    #[must_use]
    pub fn new(text: impl Into<String>, echo: bool) -> Self {
        Self {
            text_value: text.into(),
            echo,
        }
    }

    /// Returns the prompt text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text_value
    }

    /// Alias for [`Self::text`].
    #[must_use]
    pub fn prompt(&self) -> &str {
        self.text()
    }

    /// Returns whether the response should be echoed by the client UI.
    #[must_use]
    pub const fn echo(&self) -> bool {
        self.echo
    }
}

impl fmt::Debug for KeyboardInteractivePrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyboardInteractivePrompt")
            .field("text", &"<redacted>")
            .field("echo", &self.echo)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for KeyboardInteractivePrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl From<(String, bool)> for KeyboardInteractivePrompt {
    fn from((text, echo): (String, bool)) -> Self {
        Self::new(text, echo)
    }
}

impl From<(&str, bool)> for KeyboardInteractivePrompt {
    fn from((text, echo): (&str, bool)) -> Self {
        Self::new(text, echo)
    }
}

/// The name, instruction, and prompt list in one RFC 4256 info request.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyboardInteractiveChallenge {
    name: String,
    instruction: String,
    language: String,
    prompts: Vec<KeyboardInteractivePrompt>,
}

impl KeyboardInteractiveChallenge {
    /// Creates one keyboard-interactive challenge.
    #[must_use]
    pub fn new<I, P>(name: impl Into<String>, instruction: impl Into<String>, prompts: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<KeyboardInteractivePrompt>,
    {
        Self {
            name: name.into(),
            instruction: instruction.into(),
            language: String::new(),
            prompts: prompts.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns the challenge name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the challenge instruction.
    #[must_use]
    pub fn instruction(&self) -> &str {
        &self.instruction
    }

    /// Returns the language tag sent in the info request.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Sets the language tag sent in the info request.
    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = language.into();
        self
    }

    /// Returns the prompts in wire order.
    #[must_use]
    pub fn prompts(&self) -> &[KeyboardInteractivePrompt] {
        &self.prompts
    }

    /// Validates the challenge count and string bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] when a challenge exceeds the
    /// keyboard-interactive limits. Prompt text is not included in the error.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.prompts.len() > MAX_KEYBOARD_INTERACTIVE_PROMPTS
            || self.name.len() > MAX_KEYBOARD_INTERACTIVE_STRING
            || self.instruction.len() > MAX_KEYBOARD_INTERACTIVE_STRING
            || self.language.len() > MAX_KEYBOARD_INTERACTIVE_STRING
            || self
                .prompts
                .iter()
                .any(|prompt| prompt.text_value.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
        {
            return Err(AuthError::InvalidRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for KeyboardInteractiveChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyboardInteractiveChallenge")
            .field("name", &"<redacted>")
            .field("instruction", &"<redacted>")
            .field("language", &"<redacted>")
            .field("prompt_count", &self.prompts.len())
            .finish()
    }
}

impl fmt::Display for KeyboardInteractiveChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// A callback result for the server keyboard-interactive exchange.
///
/// The first invocation supplies a challenge. The second invocation supplies
/// responses and must return [`Self::Accept`] or [`Self::Reject`]. The server
/// supports exactly one round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyboardInteractiveServerDecision {
    /// Send an RFC 4256 info request.
    Challenge(KeyboardInteractiveChallenge),
    /// Accept the responses and send message 52.
    Accept,
    /// Reject the responses and send message 51.
    Reject,
}

impl KeyboardInteractiveServerDecision {
    /// Constructs a challenge result.
    #[must_use]
    pub fn challenge(challenge: KeyboardInteractiveChallenge) -> Self {
        Self::Challenge(challenge)
    }

    /// Constructs an accepting result.
    #[must_use]
    pub const fn accept() -> Self {
        Self::Accept
    }

    /// Compatibility spelling for [`Self::accept`].
    #[allow(non_upper_case_globals)]
    pub const Accepted: Self = Self::Accept;

    /// Constructs a rejecting result.
    #[must_use]
    pub const fn reject() -> Self {
        Self::Reject
    }

    /// Compatibility spelling for [`Self::reject`].
    #[allow(non_upper_case_globals)]
    pub const Rejected: Self = Self::Reject;
}

/// Alias with the shorter decision name used by some callers.
pub type KeyboardInteractiveDecision = KeyboardInteractiveServerDecision;

/// A server keyboard-interactive callback.
///
/// The callback is called first with an empty response slice to obtain the
/// challenge, then once with the received responses to make the decision.
pub trait KeyboardInteractiveCallback {
    /// Supplies or evaluates one keyboard-interactive round.
    fn decide(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision;

    /// Evaluates the response phase of one round.
    ///
    /// The default keeps custom single-function callbacks convenient. The
    /// separate adapter below overrides it so a zero-prompt challenge still
    /// has an unambiguous response phase.
    fn verify(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision {
        self.decide(username, responses)
    }
}

impl<F> KeyboardInteractiveCallback for F
where
    F: for<'username> Fn(&'username str, &[String]) -> KeyboardInteractiveServerDecision + ?Sized,
{
    fn decide(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision {
        self(username, responses)
    }
}

struct KeyboardInteractiveResultResponder<F>(F);

impl<F, E> KeyboardInteractiveResponder for KeyboardInteractiveResultResponder<F>
where
    F: for<'prompts> Fn(&'prompts [KeyboardInteractivePrompt]) -> Result<Vec<String>, E>,
{
    fn respond(&self, prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError> {
        match (self.0)(prompts) {
            Ok(responses) => Ok(responses),
            Err(_error) => Err(AuthError::CallbackRejected),
        }
    }
}

struct KeyboardInteractiveCallbackFn<F>(F);

impl<F> KeyboardInteractiveCallbackFn<F> {
    fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> KeyboardInteractiveCallback for KeyboardInteractiveCallbackFn<F>
where
    F: for<'username> Fn(&'username str, &[String]) -> KeyboardInteractiveServerDecision,
{
    fn decide(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision {
        (self.0)(username, responses)
    }

    fn verify(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision {
        (self.0)(username, responses)
    }
}

/// A convenience adapter for separate challenge and response callbacks.
pub struct KeyboardInteractiveCallbacks<P, V> {
    prompts: P,
    verify: V,
}

impl<P, V> KeyboardInteractiveCallbacks<P, V> {
    /// Creates an adapter from a challenge callback and a response callback.
    pub const fn new(prompts: P, verify: V) -> Self {
        Self { prompts, verify }
    }
}

impl<P, V> fmt::Debug for KeyboardInteractiveCallbacks<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyboardInteractiveCallbacks")
            .finish_non_exhaustive()
    }
}

impl<P, V> KeyboardInteractiveCallback for KeyboardInteractiveCallbacks<P, V>
where
    P: for<'username> Fn(&'username str) -> KeyboardInteractiveChallenge,
    V: for<'username> Fn(&'username str, &[String]) -> bool,
{
    fn decide(&self, username: &str, _responses: &[String]) -> KeyboardInteractiveServerDecision {
        KeyboardInteractiveServerDecision::Challenge((self.prompts)(username))
    }

    fn verify(&self, username: &str, responses: &[String]) -> KeyboardInteractiveServerDecision {
        if (self.verify)(username, responses) {
            KeyboardInteractiveServerDecision::Accept
        } else {
            KeyboardInteractiveServerDecision::Reject
        }
    }
}

/// A bounded, redacted set of keyboard-interactive responses.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyboardInteractiveResponse {
    responses: Vec<String>,
}

impl KeyboardInteractiveResponse {
    /// Creates a response set.
    #[must_use]
    pub fn new<I, S>(responses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            responses: responses.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns the response strings.
    #[must_use]
    pub fn responses(&self) -> &[String] {
        &self.responses
    }

    /// Validates the response count and string bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] when the response set exceeds a
    /// keyboard-interactive limit. Response values are not included.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.responses.len() > MAX_KEYBOARD_INTERACTIVE_RESPONSES
            || self
                .responses
                .iter()
                .any(|response| response.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
        {
            return Err(AuthError::InvalidRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for KeyboardInteractiveResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyboardInteractiveResponse")
            .field("response_count", &self.responses.len())
            .finish()
    }
}

impl fmt::Display for KeyboardInteractiveResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl From<Vec<String>> for KeyboardInteractiveResponse {
    fn from(responses: Vec<String>) -> Self {
        Self::new(responses)
    }
}

/// A callback used by [`ClientAuthMethod::keyboard_interactive`] to answer a
/// server challenge.
pub trait KeyboardInteractiveResponder {
    /// Returns exactly one response for every prompt.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the application cannot produce a bounded
    /// response set for the supplied prompts.
    fn respond(&self, prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError>;
}

impl<F> KeyboardInteractiveResponder for F
where
    F: for<'prompts> Fn(&'prompts [KeyboardInteractivePrompt]) -> Vec<String> + ?Sized,
{
    fn respond(&self, prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError> {
        Ok(self(prompts))
    }
}

impl KeyboardInteractiveResponder for KeyboardInteractiveResponse {
    fn respond(&self, _prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError> {
        self.validate()?;
        Ok(self.responses.clone())
    }
}

impl KeyboardInteractiveResponder for Vec<String> {
    fn respond(&self, _prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError> {
        if self.len() > MAX_KEYBOARD_INTERACTIVE_RESPONSES
            || self
                .iter()
                .any(|response| response.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
        {
            return Err(AuthError::InvalidRequest);
        }
        Ok(self.clone())
    }
}

impl KeyboardInteractiveResponder for Vec<&'static str> {
    fn respond(&self, _prompts: &[KeyboardInteractivePrompt]) -> Result<Vec<String>, AuthError> {
        if self.len() > MAX_KEYBOARD_INTERACTIVE_RESPONSES
            || self
                .iter()
                .any(|response| response.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
        {
            return Err(AuthError::InvalidRequest);
        }
        Ok(self.iter().map(|response| (*response).to_owned()).collect())
    }
}

/// Encodes one bounded RFC 4256 info response.
///
/// # Errors
///
/// Returns [`AuthError::InvalidRequest`] when the count or any response string
/// exceeds the keyboard-interactive bounds. Response values are never included
/// in the returned error.
pub fn encode_keyboard_interactive_response(responses: &[String]) -> Result<Vec<u8>, AuthError> {
    if responses.len() > MAX_KEYBOARD_INTERACTIVE_RESPONSES
        || responses
            .iter()
            .any(|response| response.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
    {
        return Err(AuthError::InvalidRequest);
    }
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_USERAUTH_INFO_RESPONSE);
    writer
        .write_uint32(u32::try_from(responses.len()).map_err(|_error| AuthError::InvalidRequest)?);
    for response in responses {
        writer.write_string_with_limit(response, MAX_KEYBOARD_INTERACTIVE_STRING)?;
    }
    Ok(writer.into_bytes())
}

/// Decodes one bounded RFC 4256 info response and checks its expected count.
///
/// The count is checked before any response strings are read, so an oversized
/// count cannot cause the extra strings to be accepted or allocated.
///
/// # Errors
///
/// Returns [`AuthError`] for a malformed packet, an oversized count or string,
/// invalid UTF-8, a count mismatch, or trailing bytes.
pub fn decode_keyboard_interactive_response(
    payload: &[u8],
    expected_count: usize,
) -> Result<Vec<String>, AuthError> {
    if expected_count > MAX_KEYBOARD_INTERACTIVE_PROMPTS {
        return Err(AuthError::InvalidRequest);
    }
    let mut reader = Reader::new(payload);
    if reader.read_byte()? != SSH_MSG_USERAUTH_INFO_RESPONSE {
        return Err(AuthError::UnexpectedMessage);
    }
    let count =
        usize::try_from(reader.read_uint32()?).map_err(|_error| AuthError::InvalidRequest)?;
    if count > MAX_KEYBOARD_INTERACTIVE_RESPONSES || count != expected_count {
        return Err(AuthError::InvalidRequest);
    }
    let mut responses = Vec::with_capacity(count);
    for _ in 0..count {
        let response = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
        responses.push(
            std::str::from_utf8(response)
                .map_err(|_error| AuthError::InvalidRequest)?
                .to_owned(),
        );
    }
    if !reader.is_empty() {
        return Err(AuthError::InvalidRequest);
    }
    Ok(responses)
}

/// Explicit server authentication policy.
///
/// There is deliberately no `Default` implementation and no constructor that
/// accepts every key or password. An empty policy is valid but denies both
/// methods. `max_attempts` is checked for a value of at least one.
pub struct ServerAuthPolicy {
    authorized_keys: Vec<Vec<u8>>,
    password_verifier: Option<Box<dyn PasswordVerifier>>,
    password_decision_callback: Option<Box<dyn PasswordDecisionCallback>>,
    public_key_verifier: Option<Box<dyn PublicKeyVerifier>>,
    keyboard_interactive_callback: Option<Box<dyn KeyboardInteractiveCallback>>,
    gssapi_mechanism: Option<Box<dyn GssapiTokenMechanism>>,
    banner: Option<AuthBanner>,
    max_attempts: usize,
}

impl fmt::Debug for ServerAuthPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerAuthPolicy")
            .field("authorized_key_count", &self.authorized_keys.len())
            .field("password_verifier", &self.password_verifier.is_some())
            .field(
                "password_decision_callback",
                &self.password_decision_callback.is_some(),
            )
            .field("public_key_verifier", &self.public_key_verifier.is_some())
            .field(
                "keyboard_interactive_callback",
                &self.keyboard_interactive_callback.is_some(),
            )
            .field("gssapi_mechanism", &self.gssapi_mechanism.is_some())
            .field("banner", &self.banner.is_some())
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl ServerAuthPolicy {
    /// Creates an explicit policy with no methods enabled.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] when `max_attempts` is zero.
    pub fn new(max_attempts: usize) -> Result<Self, AuthError> {
        if max_attempts == 0 {
            return Err(AuthError::InvalidRequest);
        }
        Ok(Self {
            authorized_keys: Vec::new(),
            password_verifier: None,
            password_decision_callback: None,
            public_key_verifier: None,
            keyboard_interactive_callback: None,
            gssapi_mechanism: None,
            banner: None,
            max_attempts,
        })
    }

    /// Alias for [`Self::new`] that emphasizes the retry bound.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] when `max_attempts` is zero.
    pub fn with_max_attempts(max_attempts: usize) -> Result<Self, AuthError> {
        Self::new(max_attempts)
    }

    /// Creates a policy from an explicit authorized-key collection.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] for a zero attempt bound or
    /// [`AuthError::InvalidKey`] for any malformed supported key blob.
    pub fn from_authorized_keys<I>(keys: I, max_attempts: usize) -> Result<Self, AuthError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut policy = Self::new(max_attempts)?;
        for key in keys {
            policy.add_authorized_key(key.as_ref())?;
        }
        Ok(policy)
    }

    /// Adds one exact authorized public-key blob.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKey`] when the blob is not a supported,
    /// canonical Ed25519 or RSA public-key blob.
    pub fn add_authorized_key(&mut self, blob: &[u8]) -> Result<(), AuthError> {
        validate_authorized_blob(blob)?;
        if !self
            .authorized_keys
            .iter()
            .any(|key| key.as_slice() == blob)
        {
            self.authorized_keys.push(blob.to_vec());
        }
        Ok(())
    }

    /// Builder form of [`Self::add_authorized_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::add_authorized_key`].
    pub fn with_authorized_key(mut self, blob: &[u8]) -> Result<Self, AuthError> {
        self.add_authorized_key(blob)?;
        Ok(self)
    }

    /// Installs an explicit password callback.
    #[must_use]
    pub fn with_password_verifier<F>(mut self, verifier: F) -> Self
    where
        F: PasswordVerifier + 'static,
    {
        self.password_verifier = Some(Box::new(verifier));
        self.password_decision_callback = None;
        self
    }

    /// Alias for [`Self::with_password_verifier`] for callback-oriented code.
    #[must_use]
    pub fn with_password_callback<F>(mut self, callback: F) -> Self
    where
        F: for<'password> Fn(&'password str) -> bool + 'static,
    {
        self.password_verifier = Some(Box::new(PasswordCallback(callback)));
        self.password_decision_callback = None;
        self
    }

    /// Installs a password callback that can explicitly return partial success.
    #[must_use]
    pub fn with_password_decision_callback<F>(mut self, callback: F) -> Self
    where
        F: for<'password> Fn(&'password str) -> PasswordDecision + 'static,
    {
        self.password_decision_callback = Some(Box::new(PasswordDecisionCallbackFn(callback)));
        self
    }

    /// Alias for [`Self::with_password_decision_callback`].
    #[must_use]
    pub fn with_password_decision<F>(self, callback: F) -> Self
    where
        F: for<'password> Fn(&'password str) -> PasswordDecision + 'static,
    {
        self.with_password_decision_callback(callback)
    }

    /// Installs a custom password-decision callback implementation.
    #[must_use]
    pub fn with_password_decision_policy<F>(mut self, callback: F) -> Self
    where
        F: PasswordDecisionCallback + 'static,
    {
        self.password_decision_callback = Some(Box::new(callback));
        self
    }

    /// Installs a password callback whose result is mapped to a decision.
    #[must_use]
    pub fn with_password_decision_result_callback<F, E>(self, callback: F) -> Self
    where
        F: for<'password> Fn(&'password str) -> Result<PasswordDecision, E> + 'static,
        E: 'static,
    {
        let mut policy = self;
        policy.password_decision_callback = Some(Box::new(PasswordDecisionResultCallback::<F, E>(
            callback,
            PhantomData,
        )));
        policy
    }

    /// Installs a password callback whose error is reduced to rejection.
    #[must_use]
    pub fn with_password_result_callback<F, E>(self, callback: F) -> Self
    where
        F: for<'password> Fn(&'password str) -> Result<(), E> + 'static,
        E: 'static,
    {
        self.with_password_callback(move |password| callback(password).is_ok())
    }

    /// Sets the one banner emitted before the first authentication response.
    #[must_use]
    pub fn with_banner<M, L>(mut self, message: M, language: L) -> Self
    where
        M: Into<String>,
        L: Into<String>,
    {
        self.banner = Some(AuthBanner::new(message, language));
        self
    }

    /// Alias for [`Self::with_banner`].
    #[must_use]
    pub fn with_banner_text<M, L>(self, message: M, language: L) -> Self
    where
        M: Into<String>,
        L: Into<String>,
    {
        self.with_banner(message, language)
    }

    /// Alias for [`Self::with_banner`].
    #[must_use]
    pub fn with_banner_message<M, L>(self, message: M, language: L) -> Self
    where
        M: Into<String>,
        L: Into<String>,
    {
        self.with_banner(message, language)
    }

    /// Sets a prebuilt banner value.
    #[must_use]
    pub fn with_auth_banner(mut self, banner: AuthBanner) -> Self {
        self.banner = Some(banner);
        self
    }

    /// Installs a one-round keyboard-interactive callback.
    #[must_use]
    pub fn with_keyboard_interactive_callback<F>(mut self, callback: F) -> Self
    where
        F: for<'username> Fn(&'username str, &[String]) -> KeyboardInteractiveServerDecision
            + 'static,
    {
        self.keyboard_interactive_callback =
            Some(Box::new(KeyboardInteractiveCallbackFn::new(callback)));
        self
    }

    /// Installs a custom keyboard-interactive callback implementation.
    #[must_use]
    pub fn with_keyboard_interactive_policy<F>(mut self, callback: F) -> Self
    where
        F: KeyboardInteractiveCallback + 'static,
    {
        self.keyboard_interactive_callback = Some(Box::new(callback));
        self
    }

    /// Alias for [`Self::with_keyboard_interactive_callback`].
    #[must_use]
    pub fn with_keyboard_interactive<F>(self, callback: F) -> Self
    where
        F: for<'username> Fn(&'username str, &[String]) -> KeyboardInteractiveServerDecision
            + 'static,
    {
        self.with_keyboard_interactive_callback(callback)
    }

    /// Installs separate callbacks for challenge generation and verification.
    #[must_use]
    pub fn with_keyboard_interactive_callbacks<P, V>(mut self, prompts: P, verify: V) -> Self
    where
        P: for<'username> Fn(&'username str) -> KeyboardInteractiveChallenge + 'static,
        V: for<'username> Fn(&'username str, &[String]) -> bool + 'static,
    {
        self.keyboard_interactive_callback =
            Some(Box::new(KeyboardInteractiveCallbacks::new(prompts, verify)));
        self
    }

    /// Installs a caller-owned opaque GSSAPI token mechanism.
    ///
    /// This is a framing/callback boundary only.  It does not implement a
    /// Kerberos mechanism, create a KDC context, or cause GSSAPI to be
    /// advertised in the server's default method list.  The selected opaque
    /// mechanism and every token remain the caller's responsibility.
    #[must_use]
    pub fn with_gssapi_token_mechanism<M>(mut self, mechanism: M) -> Self
    where
        M: GssapiTokenMechanism + 'static,
    {
        self.gssapi_mechanism = Some(Box::new(mechanism));
        self
    }

    /// Installs a closure-backed opaque GSSAPI token callback.
    ///
    /// The callback receives one non-empty SSH token and returns `Continue`,
    /// `Accept`, `AcceptWithToken`, or `Fail`.  A panic is caught by the
    /// exchange state machine and is always a denial.  No Kerberos or other
    /// real mechanism is created here.
    #[must_use]
    pub fn with_gssapi_token_callback<M, F>(self, mechanism: M, callback: F) -> Self
    where
        M: AsRef<[u8]> + 'static,
        F: Fn(&[u8]) -> neotales_ssh::gssapi::GssapiMechanismResult + 'static,
    {
        self.with_gssapi_token_mechanism(GssapiTokenMechanismCallback::new(mechanism, callback))
    }

    /// Returns whether an opaque GSSAPI callback is installed.
    ///
    /// This reports configuration only; it does not mean that GSSAPI is
    /// advertised or that a real mechanism is available.
    #[must_use]
    pub fn gssapi_callback_enabled(&self) -> bool {
        self.gssapi_mechanism.is_some()
    }

    /// Installs a fixed challenge and a response verifier.
    #[must_use]
    pub fn with_keyboard_interactive_challenge<V>(
        self,
        challenge: KeyboardInteractiveChallenge,
        verify: V,
    ) -> Self
    where
        V: for<'username> Fn(&'username str, &[String]) -> bool + 'static,
    {
        self.with_keyboard_interactive_callbacks(move |_username| challenge.clone(), verify)
    }

    /// Installs a fixed challenge and a response-count-independent verifier.
    #[must_use]
    pub fn with_keyboard_interactive_verifier<V>(
        self,
        challenge: KeyboardInteractiveChallenge,
        verify: V,
    ) -> Self
    where
        V: for<'username> Fn(&'username str, &[String]) -> bool + 'static,
    {
        self.with_keyboard_interactive_challenge(challenge, verify)
    }

    /// Installs an additional public-key policy callback.
    #[must_use]
    pub fn with_public_key_verifier<F>(mut self, verifier: F) -> Self
    where
        F: for<'algorithm, 'key, 'signed, 'proof> Fn(
                &'algorithm str,
                &'key [u8],
                &'signed [u8],
                &'proof [u8],
            ) -> bool
            + 'static,
    {
        self.public_key_verifier = Some(Box::new(PublicKeyCallback(verifier)));
        self
    }

    /// Installs a public-key callback whose error is reduced to rejection.
    #[must_use]
    pub fn with_public_key_result_verifier<F, E>(self, verifier: F) -> Self
    where
        F: for<'algorithm, 'key, 'signed, 'proof> Fn(
                &'algorithm str,
                &'key [u8],
                &'signed [u8],
                &'proof [u8],
            ) -> Result<(), E>
            + 'static,
        E: 'static,
    {
        self.with_public_key_verifier(move |algorithm, key, signed, proof| {
            verifier(algorithm, key, signed, proof).is_ok()
        })
    }

    /// Returns the configured attempt bound.
    #[must_use]
    pub const fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Returns the exact authorized-key blobs.
    #[must_use]
    pub fn authorized_keys(&self) -> &[Vec<u8>] {
        &self.authorized_keys
    }

    /// Returns whether at least one public key is authorized.
    #[must_use]
    pub fn public_key_enabled(&self) -> bool {
        !self.authorized_keys.is_empty()
    }

    /// Returns whether a password callback is configured.
    #[must_use]
    pub fn password_enabled(&self) -> bool {
        self.password_verifier.is_some() || self.password_decision_callback.is_some()
    }

    /// Returns whether a keyboard-interactive callback is configured.
    #[must_use]
    pub fn keyboard_interactive_enabled(&self) -> bool {
        self.keyboard_interactive_callback.is_some()
    }

    /// Returns the optional server banner.
    #[must_use]
    pub fn banner(&self) -> Option<&AuthBanner> {
        self.banner.as_ref()
    }

    fn key_authorized(&self, blob: &[u8]) -> bool {
        self.authorized_keys
            .iter()
            .any(|authorized| authorized.as_slice() == blob)
    }

    fn available_methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::with_capacity(3);
        if self.public_key_enabled() {
            methods.push(SSH_PUBLICKEY_METHOD);
        }
        if self.password_enabled() {
            methods.push(SSH_PASSWORD_METHOD);
        }
        if self.keyboard_interactive_enabled() {
            methods.push(SSH_KEYBOARD_INTERACTIVE_METHOD);
        }
        methods
    }

    fn check_password(&self, password: &str) -> Result<PasswordDecision, AuthError> {
        if let Some(callback) = &self.password_decision_callback {
            return match catch_unwind(AssertUnwindSafe(|| callback.decide(password))) {
                Ok(decision) => Ok(decision),
                Err(_panic_payload) => Err(AuthError::CallbackPanicked),
            };
        }
        let Some(verifier) = &self.password_verifier else {
            return Ok(PasswordDecision::Reject);
        };
        match catch_unwind(AssertUnwindSafe(|| verifier.verify(password))) {
            Ok(true) => Ok(PasswordDecision::Accept),
            Ok(false) => Ok(PasswordDecision::Reject),
            Err(_panic_payload) => Err(AuthError::CallbackPanicked),
        }
    }

    fn check_public_key(
        &self,
        algorithm: &str,
        blob: &[u8],
        signed_bytes: &[u8],
        signature_blob: &[u8],
    ) -> Result<bool, AuthError> {
        let Some(verifier) = &self.public_key_verifier else {
            return Ok(true);
        };
        match catch_unwind(AssertUnwindSafe(|| {
            verifier.verify(algorithm, blob, signed_bytes, signature_blob)
        })) {
            Ok(accepted) => Ok(accepted),
            Err(_panic_payload) => Err(AuthError::CallbackPanicked),
        }
    }

    fn keyboard_interactive_decision(
        &self,
        username: &str,
        responses: &[String],
    ) -> Result<KeyboardInteractiveServerDecision, AuthError> {
        let Some(callback) = &self.keyboard_interactive_callback else {
            return Ok(KeyboardInteractiveServerDecision::Reject);
        };
        match catch_unwind(AssertUnwindSafe(|| callback.decide(username, responses))) {
            Ok(decision) => Ok(decision),
            Err(_panic_payload) => Err(AuthError::CallbackPanicked),
        }
    }

    fn keyboard_interactive_verify(
        &self,
        username: &str,
        responses: &[String],
    ) -> Result<KeyboardInteractiveServerDecision, AuthError> {
        let Some(callback) = &self.keyboard_interactive_callback else {
            return Ok(KeyboardInteractiveServerDecision::Reject);
        };
        match catch_unwind(AssertUnwindSafe(|| callback.verify(username, responses))) {
            Ok(decision) => Ok(decision),
            Err(_panic_payload) => Err(AuthError::CallbackPanicked),
        }
    }
}

/// The result of one bounded server authentication step.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ServerAuthStep {
    /// The service request was accepted.
    ServiceAccepted,
    /// A public-key query was answered with `SSH_MSG_USERAUTH_PK_OK`.
    PublicKeyQueryAccepted,
    /// A credential was rejected and a failure response was written.
    Failure,
    /// A credential was accepted and the transport was marked authenticated.
    Authenticated,
    /// A nonblocking stream has not produced another complete packet.
    NeedMoreData,
}

/// A successful server authentication result.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServerAuthSuccess {
    attempts: usize,
}

impl ServerAuthSuccess {
    /// Returns the number of user-authentication requests consumed.
    #[must_use]
    pub const fn attempts(self) -> usize {
        self.attempts
    }
}

/// Persisted protocol state for a nonblocking server authentication loop.
///
/// The state is small and contains no packet bytes or credentials. It lets a
/// caller reconstruct a short-lived [`ServerAuthenticator`] for each available
/// input chunk without replaying service negotiation or attempt accounting.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServerAuthState {
    service_accepted: bool,
    attempts: usize,
    finished: bool,
    exhausted: bool,
    banner_sent: bool,
}

impl ServerAuthState {
    /// Creates the initial unauthenticated state.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            service_accepted: false,
            attempts: 0,
            finished: false,
            exhausted: false,
            banner_sent: false,
        }
    }

    /// Returns whether service negotiation has completed.
    #[must_use]
    pub const fn service_accepted(self) -> bool {
        self.service_accepted
    }

    /// Returns the number of user-authentication requests consumed.
    #[must_use]
    pub const fn attempts(self) -> usize {
        self.attempts
    }

    /// Returns whether message 52 has been sent.
    #[must_use]
    pub const fn finished(self) -> bool {
        self.finished
    }

    /// Returns whether the retry policy has been closed.
    #[must_use]
    pub const fn exhausted(self) -> bool {
        self.exhausted
    }

    /// Returns whether the configured server banner has been written.
    #[must_use]
    pub const fn banner_sent(self) -> bool {
        self.banner_sent
    }
}

/// A bounded server authentication state machine.
///
/// The state machine reads only through `ServerTransport::read_auth_packet`
/// until it writes `SSH_MSG_USERAUTH_SUCCESS` and marks the transport. A
/// nonblocking caller can invoke [`Self::step`] whenever another complete
/// packet is available.
struct PendingKeyboardInteractive {
    username: String,
    challenge: KeyboardInteractiveChallenge,
}

struct PendingGssapi {
    username: Vec<u8>,
    exchange: GssapiExchange,
}

/// Drives the server half of the SSH authentication exchange.
///
/// The authenticator owns the sequence rather than a single message: it answers
/// `none`, `publickey` and `keyboard-interactive` attempts as they arrive, hands
/// policy decisions to a [`ServerAuthPolicy`], and only reports success once the
/// protocol says so. Holding a mechanism's own `Accept` is not enough — the
/// exchange has to reach SSH's success message.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `policy` holds authorized
/// public keys and boxed caller verifiers and callbacks, and the two `pending`
/// fields hold a `KeyboardInteractiveChallenge` and a `GssapiExchange` — the
/// challenge already has a redacting `Debug` and the exchange has a
/// metadata-only one, but the `username` beside each of them is caller
/// identity data that has no business in a log line, so neither pending value
/// is delegated to. `S` is the caller's transport; an `S: Debug` bound would tax
/// a caller for a `&mut` handle this type only reads and writes. What is
/// reported instead is the state machine's own progress: the attempt count, the
/// bounds, and whether a challenge is outstanding, which is what a server
/// diagnosing a failed handshake needs.
pub struct ServerAuthenticator<'a, S> {
    transport: &'a mut ServerTransport<S>,
    policy: &'a ServerAuthPolicy,
    state: ServerAuthState,
    pending_keyboard: Option<PendingKeyboardInteractive>,
    pending_gssapi: Option<PendingGssapi>,
}

impl<S> fmt::Debug for ServerAuthenticator<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No `S: Debug` bound, and `transport` is not printed. The pending
        // values are reported as presence only; their `username` fields are
        // caller identity data.
        formatter
            .debug_struct("ServerAuthenticator")
            .field("state", &self.state)
            .field("pending_keyboard", &self.pending_keyboard.is_some())
            .field("pending_gssapi", &self.pending_gssapi.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a, S> ServerAuthenticator<'a, S>
where
    S: Read + Write,
{
    /// Creates a server authentication state machine.
    #[must_use]
    pub const fn new(transport: &'a mut ServerTransport<S>, policy: &'a ServerAuthPolicy) -> Self {
        Self::from_state(transport, policy, ServerAuthState::initial())
    }

    /// Creates a state machine from previously persisted protocol state.
    #[must_use]
    pub const fn from_state(
        transport: &'a mut ServerTransport<S>,
        policy: &'a ServerAuthPolicy,
        state: ServerAuthState,
    ) -> Self {
        Self {
            transport,
            policy,
            state,
            pending_keyboard: None,
            pending_gssapi: None,
        }
    }

    /// Returns the current protocol state for nonblocking callers.
    #[must_use]
    pub const fn state(&self) -> ServerAuthState {
        self.state
    }

    /// Returns whether the service request has been accepted.
    #[must_use]
    pub const fn service_accepted(&self) -> bool {
        self.state.service_accepted
    }

    /// Returns the number of user-authentication requests consumed.
    #[must_use]
    pub const fn attempts(&self) -> usize {
        self.state.attempts
    }

    /// Processes one complete authentication packet.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`AuthError`] for malformed protocol data, a
    /// transport failure, a callback panic, or an exhausted attempt policy.
    /// [`ServerAuthStep::NeedMoreData`] is returned without error for a
    /// nonblocking stream that currently has no complete packet.
    pub fn step(&mut self) -> Result<ServerAuthStep, AuthError> {
        if self.state.finished {
            return Err(AuthError::AlreadyAuthenticated);
        }
        if self.state.exhausted {
            return Err(AuthError::AttemptsExhausted);
        }

        let payload = match self.transport.read_auth_packet() {
            Ok(payload) => payload,
            Err(error) => {
                if is_would_block(&error) {
                    return Ok(ServerAuthStep::NeedMoreData);
                }
                return Err(map_server_transport_error(error));
            }
        };
        self.handle_auth_packet(&payload)
    }

    /// Processes one already-read service or user-authentication packet.
    ///
    /// This is the transport-independent half of [`Self::step`] for callers
    /// that own a packet source other than [`ServerTransport::read_auth_packet`].
    /// Keyboard-interactive info responses must be passed to
    /// [`Self::handle_keyboard_interactive_response`] because the baseline
    /// pre-auth transport intentionally accepts only messages 5 and 50.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol, callback, policy, or transport error.
    pub fn handle_auth_packet(&mut self, payload: &[u8]) -> Result<ServerAuthStep, AuthError> {
        if self.state.finished {
            return Err(AuthError::AlreadyAuthenticated);
        }
        if self.state.exhausted {
            return Err(AuthError::AttemptsExhausted);
        }
        let message = payload.first().copied().ok_or(AuthError::InvalidRequest)?;
        match message {
            SSH_MSG_SERVICE_REQUEST => self.handle_service_request(payload),
            SSH_MSG_USERAUTH_REQUEST => self.handle_userauth_request(payload),
            SSH_MSG_USERAUTH_GSSAPI_RESPONSE
            | SSH_MSG_USERAUTH_GSSAPI_TOKEN
            | SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE => self.handle_gssapi_packet(payload),
            _ => Err(AuthError::UnexpectedMessage),
        }
    }

    /// Runs steps until success or until a nonblocking stream needs input.
    ///
    /// # Errors
    ///
    /// Returns the same protocol and policy errors as [`Self::step`]. A
    /// nonblocking caller should handle [`AuthError::NeedMoreData`] by
    /// invoking [`Self::step`] again later.
    pub fn run(&mut self) -> Result<ServerAuthSuccess, AuthError> {
        loop {
            match self.step()? {
                ServerAuthStep::Authenticated => {
                    return Ok(ServerAuthSuccess {
                        attempts: self.state.attempts,
                    });
                }
                ServerAuthStep::NeedMoreData => return Err(AuthError::NeedMoreData),
                ServerAuthStep::ServiceAccepted
                | ServerAuthStep::PublicKeyQueryAccepted
                | ServerAuthStep::Failure => {}
            }
        }
    }

    fn handle_service_request(&mut self, payload: &[u8]) -> Result<ServerAuthStep, AuthError> {
        let mut reader = Reader::new(payload);
        if reader.read_byte()? != SSH_MSG_SERVICE_REQUEST {
            return Err(AuthError::InvalidRequest);
        }
        let service = reader.read_string()?;
        if !reader.is_empty() {
            return Err(AuthError::InvalidRequest);
        }
        if service != SSH_USERAUTH_SERVICE.as_bytes() || self.state.service_accepted {
            return Err(AuthError::UnsupportedService);
        }
        let mut response = Writer::new();
        response.write_byte(SSH_MSG_SERVICE_ACCEPT);
        response.write_string(SSH_USERAUTH_SERVICE)?;
        self.transport
            .write_auth_packet(&response.into_bytes())
            .map_err(map_server_transport_error)?;
        self.state.service_accepted = true;
        Ok(ServerAuthStep::ServiceAccepted)
    }

    fn handle_userauth_request(&mut self, payload: &[u8]) -> Result<ServerAuthStep, AuthError> {
        if !self.state.service_accepted {
            return Err(AuthError::ServiceRequired);
        }
        // RFC 4462 requires a new userauth request to discard any in-flight
        // GSSAPI context.  The normal transport cannot deliver the follow-up
        // GSSAPI packets, but custom packet sources use the handler below.
        self.pending_gssapi = None;
        self.write_banner_if_needed()?;
        if self.state.attempts >= self.policy.max_attempts() {
            self.write_failure()?;
            self.state.exhausted = true;
            return Err(AuthError::AttemptsExhausted);
        }
        self.state.attempts += 1;

        let header = match parse_userauth_header(payload) {
            Ok(header) => header,
            Err(error) => {
                self.write_failure()?;
                return Err(error);
            }
        };
        if header.service != SSH_CONNECTION_SERVICE.as_bytes() {
            self.write_failure()?;
            return Err(AuthError::InvalidRequest);
        }

        let result = if header.method == SSH_PUBLICKEY_METHOD.as_bytes() {
            self.handle_publickey(payload, header.position)
        } else if header.method == SSH_PASSWORD_METHOD.as_bytes() {
            self.handle_password(payload, header.position)
        } else if header.method == SSH_KEYBOARD_INTERACTIVE_METHOD.as_bytes() {
            self.handle_keyboard_interactive(header.username, payload, header.position)
        } else if header.method == GSSAPI_WITH_MIC_METHOD.as_bytes() {
            self.handle_gssapi_request(header.username, payload, header.position)
        } else {
            self.write_failure()?;
            Ok(ServerAuthStep::Failure)
        };
        match result {
            Ok(step) => Ok(step),
            Err(error) => {
                self.write_failure()?;
                Err(error)
            }
        }
    }

    fn handle_publickey(
        &mut self,
        payload: &[u8],
        method_position: usize,
    ) -> Result<ServerAuthStep, AuthError> {
        let mut reader = Reader::new(&payload[method_position..]);
        let signed = reader.read_boolean()?;
        let algorithm = reader.read_string()?.to_vec();
        let key_blob = reader.read_string_bytes()?;
        let prefix_end = method_position + reader.position();
        let parsed = parse_public_key(&algorithm, &key_blob)?;

        if !signed {
            if !reader.is_empty() || !self.policy.key_authorized(&key_blob) {
                self.write_failure()?;
                return Ok(ServerAuthStep::Failure);
            }
            let mut response = Writer::new();
            response.write_byte(SSH_MSG_USERAUTH_PK_OK);
            response.write_string(&algorithm)?;
            response.write_string(&key_blob)?;
            self.transport
                .write_auth_packet(&response.into_bytes())
                .map_err(map_server_transport_error)?;
            // Parsing is intentionally repeated nowhere: the query has no
            // transcript to verify, while the authorized blob was checked.
            let _ = parsed;
            return Ok(ServerAuthStep::PublicKeyQueryAccepted);
        }

        let signature_blob = match reader.read_string_bytes() {
            Ok(signature) if reader.is_empty() => signature,
            Ok(_) | Err(_) => return Err(AuthError::InvalidRequest),
        };
        if !self.policy.key_authorized(&key_blob) {
            self.write_failure()?;
            return Ok(ServerAuthStep::Failure);
        }
        let signed_bytes =
            encode_signed_bytes(self.transport.session_id(), &payload[..prefix_end])?;
        if !verify_public_key(&parsed, &signature_blob, &signed_bytes) {
            self.write_failure()?;
            return Ok(ServerAuthStep::Failure);
        }
        let algorithm_name = match algorithm.as_slice() {
            value if value == SSH_ED25519.as_bytes() => SSH_ED25519,
            value if value == SSH_RSA_SHA2_256.as_bytes() => SSH_RSA_SHA2_256,
            _ => return Err(AuthError::InvalidKey),
        };
        if self.policy.check_public_key(
            algorithm_name,
            &key_blob,
            &signed_bytes,
            &signature_blob,
        )? {
            self.write_success()
        } else {
            self.write_failure()?;
            Ok(ServerAuthStep::Failure)
        }
    }

    fn handle_password(
        &mut self,
        payload: &[u8],
        method_position: usize,
    ) -> Result<ServerAuthStep, AuthError> {
        let mut reader = Reader::new(&payload[method_position..]);
        let change_requested = reader.read_boolean()?;
        let password = reader.read_string()?;
        if change_requested || !reader.is_empty() {
            return Err(AuthError::InvalidRequest);
        }
        let password = match std::str::from_utf8(password) {
            Ok(password) => password,
            Err(_error) => return Err(AuthError::InvalidRequest),
        };
        match self.policy.check_password(password)? {
            PasswordDecision::Accept => self.write_success(),
            PasswordDecision::Reject => {
                self.write_failure()?;
                Ok(ServerAuthStep::Failure)
            }
            PasswordDecision::PartialSuccess => {
                self.write_failure_with_partial(true)?;
                Ok(ServerAuthStep::Failure)
            }
        }
    }

    fn handle_gssapi_request(
        &mut self,
        username: &[u8],
        payload: &[u8],
        method_position: usize,
    ) -> Result<ServerAuthStep, AuthError> {
        let request = GssapiRequest::decode(&payload[method_position..])?;
        let Some(mechanism) = &self.policy.gssapi_mechanism else {
            // No real GSSAPI mechanism is bundled.  Do not acknowledge an
            // unsupported method or advertise it in the failure list.
            self.write_failure()?;
            return Ok(ServerAuthStep::Failure);
        };
        let selected = gssapi_mechanism_identifier(mechanism.as_ref())?;
        let Some(selected) = request
            .mechanisms()
            .iter()
            .find(|candidate| candidate.as_slice() == selected.as_slice())
        else {
            // Mechanism selection is exact and fail-closed.  In particular,
            // an arbitrary caller-supplied name cannot turn this into a real
            // Kerberos implementation.
            self.write_failure()?;
            return Ok(ServerAuthStep::Failure);
        };
        let mut exchange = GssapiExchange::new(MAX_GSSAPI_EXCHANGES)?;
        let response = exchange.begin(selected)?;
        self.transport
            .write_auth_packet(&response)
            .map_err(map_server_transport_error)?;
        self.pending_gssapi = Some(PendingGssapi {
            username: username.to_vec(),
            exchange,
        });
        Ok(ServerAuthStep::PublicKeyQueryAccepted)
    }

    /// Handles one already-read RFC 4462 GSSAPI packet.
    ///
    /// The baseline unauthenticated transport intentionally exposes only
    /// messages 5 and 50, so custom packet sources must pass messages 60,
    /// 61, and 63 here.  A mechanism `Accept` is not SSH success by itself:
    /// message 63 must arrive before success is written.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol, callback, policy, or transport error.  A
    /// failure response is written before the error is returned whenever the
    /// transport is still unauthenticated.
    pub fn handle_gssapi_packet(&mut self, payload: &[u8]) -> Result<ServerAuthStep, AuthError> {
        let result = self.handle_gssapi_packet_inner(payload);
        if result.is_err() {
            self.pending_gssapi = None;
            if !self.state.finished {
                let _ = self.write_failure();
            }
        }
        result
    }

    fn handle_gssapi_packet_inner(&mut self, payload: &[u8]) -> Result<ServerAuthStep, AuthError> {
        let message = payload
            .first()
            .copied()
            .ok_or(AuthError::Gssapi(GssapiError::InvalidMessage))?;
        let action = match message {
            SSH_MSG_USERAUTH_GSSAPI_TOKEN => {
                let Some(pending) = self.pending_gssapi.as_mut() else {
                    return Err(AuthError::Gssapi(GssapiError::InvalidState));
                };
                let Some(mechanism) = &self.policy.gssapi_mechanism else {
                    return Err(AuthError::Gssapi(GssapiError::CallbackRejected));
                };
                pending
                    .exchange
                    .receive_token(payload, mechanism.as_ref())
                    .map_err(AuthError::from)?
            }
            SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE => {
                let Some(pending) = self.pending_gssapi.as_mut() else {
                    return Err(AuthError::Gssapi(GssapiError::InvalidState));
                };
                pending.exchange.receive_exchange_complete(payload)?;
                GssapiExchangeAction::Complete
            }
            _ => return Err(AuthError::Gssapi(GssapiError::InvalidState)),
        };
        match action {
            GssapiExchangeAction::SendToken(token) => {
                let response = token.encode()?;
                self.transport
                    .write_auth_packet(&response)
                    .map_err(map_server_transport_error)?;
                Ok(ServerAuthStep::PublicKeyQueryAccepted)
            }
            GssapiExchangeAction::AwaitExchangeComplete | GssapiExchangeAction::AwaitToken => {
                Ok(ServerAuthStep::PublicKeyQueryAccepted)
            }
            GssapiExchangeAction::Complete => {
                self.pending_gssapi = None;
                self.write_success()
            }
        }
    }

    fn handle_keyboard_interactive(
        &mut self,
        username: &[u8],
        payload: &[u8],
        method_position: usize,
    ) -> Result<ServerAuthStep, AuthError> {
        let mut reader = Reader::new(&payload[method_position..]);
        let language = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
        let submethods = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
        if !language.is_empty() || !submethods.is_empty() || !reader.is_empty() {
            return Err(AuthError::InvalidRequest);
        }
        let username = std::str::from_utf8(username).map_err(|_error| AuthError::InvalidRequest)?;
        let decision = self.policy.keyboard_interactive_decision(username, &[])?;
        let challenge = match decision {
            KeyboardInteractiveServerDecision::Challenge(challenge) => challenge,
            KeyboardInteractiveServerDecision::Accept => {
                return self.write_success();
            }
            KeyboardInteractiveServerDecision::Reject => {
                self.write_failure()?;
                return Ok(ServerAuthStep::Failure);
            }
        };
        challenge.validate()?;
        self.pending_keyboard = Some(PendingKeyboardInteractive {
            username: username.to_owned(),
            challenge: challenge.clone(),
        });
        self.write_keyboard_interactive_request(&challenge)?;
        Ok(ServerAuthStep::PublicKeyQueryAccepted)
    }

    /// Handles one RFC 4256 info response after a challenge was written.
    ///
    /// The baseline server transport intentionally exposes only messages 5 and
    /// 50 before authentication, so callers that use a custom packet reader can
    /// pass the received message 61 here. The normal `step` path continues to
    /// handle service and request packets.
    ///
    /// # Errors
    ///
    /// Returns a bounded protocol, callback, or transport error. No message 52
    /// is written unless the response count, lengths, and callback decision are
    /// all valid.
    pub fn handle_keyboard_interactive_response(
        &mut self,
        payload: &[u8],
    ) -> Result<ServerAuthStep, AuthError> {
        let result = self.handle_keyboard_interactive_response_inner(payload);
        if result.is_err() && !self.state.finished {
            let _failure_result = self.write_failure();
        }
        result
    }

    fn handle_keyboard_interactive_response_inner(
        &mut self,
        payload: &[u8],
    ) -> Result<ServerAuthStep, AuthError> {
        let Some(pending) = self.pending_keyboard.take() else {
            return Err(AuthError::UnexpectedMessage);
        };
        let responses =
            decode_keyboard_interactive_response(payload, pending.challenge.prompts.len())?;
        match self
            .policy
            .keyboard_interactive_verify(&pending.username, &responses)?
        {
            KeyboardInteractiveServerDecision::Accept => self.write_success(),
            KeyboardInteractiveServerDecision::Reject => {
                self.write_failure()?;
                Ok(ServerAuthStep::Failure)
            }
            KeyboardInteractiveServerDecision::Challenge(_) => Err(AuthError::UnexpectedMessage),
        }
    }

    fn write_banner_if_needed(&mut self) -> Result<(), AuthError> {
        if self.state.banner_sent {
            return Ok(());
        }
        let Some(banner) = &self.policy.banner else {
            self.state.banner_sent = true;
            return Ok(());
        };
        let mut response = Writer::new();
        response.write_byte(SSH_MSG_USERAUTH_BANNER);
        response.write_string(banner.message.as_bytes())?;
        response.write_string(banner.language.as_bytes())?;
        self.transport
            .write_auth_packet(&response.into_bytes())
            .map_err(map_server_transport_error)?;
        self.state.banner_sent = true;
        Ok(())
    }

    fn write_keyboard_interactive_request(
        &mut self,
        challenge: &KeyboardInteractiveChallenge,
    ) -> Result<(), AuthError> {
        let mut response = Writer::new();
        response.write_byte(SSH_MSG_USERAUTH_INFO_REQUEST);
        response
            .write_string_with_limit(challenge.name.as_bytes(), MAX_KEYBOARD_INTERACTIVE_STRING)?;
        response.write_string_with_limit(
            challenge.instruction.as_bytes(),
            MAX_KEYBOARD_INTERACTIVE_STRING,
        )?;
        response.write_string_with_limit(
            challenge.language.as_bytes(),
            MAX_KEYBOARD_INTERACTIVE_STRING,
        )?;
        response.write_uint32(
            u32::try_from(challenge.prompts.len()).map_err(|_error| AuthError::InvalidRequest)?,
        );
        for prompt in &challenge.prompts {
            response.write_string_with_limit(
                prompt.text_value.as_bytes(),
                MAX_KEYBOARD_INTERACTIVE_STRING,
            )?;
            response.write_boolean(prompt.echo);
        }
        self.transport
            .write_auth_packet(&response.into_bytes())
            .map_err(map_server_transport_error)
    }

    fn write_failure(&mut self) -> Result<(), AuthError> {
        self.write_failure_with_partial(false)
    }

    fn write_failure_with_partial(&mut self, partial: bool) -> Result<(), AuthError> {
        let methods = self.policy.available_methods();
        let mut response = Writer::new();
        response.write_byte(SSH_MSG_USERAUTH_FAILURE);
        response.write_name_list(methods)?;
        response.write_boolean(partial);
        self.transport
            .write_auth_packet(&response.into_bytes())
            .map_err(map_server_transport_error)
    }

    fn write_success(&mut self) -> Result<ServerAuthStep, AuthError> {
        self.transport
            .write_auth_packet(&[SSH_MSG_USERAUTH_SUCCESS])
            .map_err(map_server_transport_error)?;
        self.transport.mark_authenticated();
        self.state.finished = true;
        Ok(ServerAuthStep::Authenticated)
    }
}

/// Runs a server authentication loop over an unauthenticated transport.
///
/// # Errors
///
/// Returns the same errors as [`ServerAuthenticator::run`].
pub fn authenticate_server<S>(
    transport: &mut ServerTransport<S>,
    policy: &ServerAuthPolicy,
) -> Result<ServerAuthSuccess, AuthError>
where
    S: Read + Write,
{
    let mut authenticator = ServerAuthenticator::new(transport, policy);
    authenticator.run()
}

/// The authentication method that completed on the client.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthMethodKind {
    /// Ed25519 or RSA public-key authentication.
    PublicKey,
    /// Password authentication.
    Password,
    /// RFC 4256 keyboard-interactive authentication.
    KeyboardInteractive,
}

/// A client authentication method.
///
/// The password variant deliberately has a redacted `Debug` implementation so
/// accidental diagnostics cannot disclose its value, and it holds the value in a
/// [`Zeroizing`] string so a password a caller hands over is wiped when the
/// method is dropped rather than left on the heap for the life of the process.
/// The encoded request it becomes, and the buffers the cipher and the transport
/// make of that request on the way to the socket, wipe themselves in the same
/// way.
///
/// [`Zeroizing`] is re-exported from this crate's root, so a caller can name the
/// type this variant carries without adding a dependency on a crypto crate:
/// `neotales_ssh::Zeroizing`. That matters because the variant is public —
/// building one directly, or matching on it, requires naming the payload type.
pub enum ClientAuthMethod {
    /// A public-key query followed by a signed request.
    PublicKey(Box<PublicKeySigner>),
    /// A non-changing password request, zeroized when the method is dropped.
    ///
    /// Prefer [`Self::password`], which takes anything string-shaped and wraps
    /// it. Construct the variant directly only when the value is already a
    /// `Zeroizing<String>` this crate handed back.
    Password(Zeroizing<String>),
    /// One RFC 4256 keyboard-interactive round.
    KeyboardInteractive(Box<dyn KeyboardInteractiveResponder>),
}

impl ClientAuthMethod {
    /// Creates a public-key method.
    #[must_use]
    pub fn public_key(signer: PublicKeySigner) -> Self {
        Self::PublicKey(Box::new(signer))
    }

    /// Creates a password method without exposing the value in debug output.
    ///
    /// This is the ergonomic form, and the one to reach for: it takes anything
    /// string-shaped and wraps it in a [`Zeroizing`] itself, so a caller never
    /// has to name that type to authenticate with a password. The value is wiped
    /// when the returned method is dropped, and again when the encoded request
    /// has been handed to the transport.
    #[must_use]
    pub fn password(password: impl Into<String>) -> Self {
        Self::Password(Zeroizing::new(password.into()))
    }

    /// Creates a keyboard-interactive method from a prompt responder.
    #[must_use]
    pub fn keyboard_interactive<R>(responder: R) -> Self
    where
        R: KeyboardInteractiveResponder + 'static,
    {
        Self::KeyboardInteractive(Box::new(responder))
    }

    /// Alias for [`Self::keyboard_interactive`].
    #[must_use]
    pub fn keyboard_interactive_callback<R>(responder: R) -> Self
    where
        R: KeyboardInteractiveResponder + 'static,
    {
        Self::keyboard_interactive(responder)
    }

    /// Creates a keyboard-interactive method from a fallible prompt callback.
    #[must_use]
    pub fn keyboard_interactive_result<R, E>(responder: R) -> Self
    where
        R: for<'prompts> Fn(&'prompts [KeyboardInteractivePrompt]) -> Result<Vec<String>, E>
            + 'static,
    {
        Self::KeyboardInteractive(Box::new(KeyboardInteractiveResultResponder(responder)))
    }

    /// Creates a keyboard-interactive method with a fixed response set.
    #[must_use]
    pub fn keyboard_interactive_responses<I, S>(responses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::keyboard_interactive(KeyboardInteractiveResponse::new(
            responses.into_iter().map(Into::into),
        ))
    }

    /// Alias for [`Self::keyboard_interactive_responses`].
    #[must_use]
    pub fn keyboard_interactive_with_responses<I, S>(responses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::keyboard_interactive_responses(responses)
    }

    /// Returns the method kind.
    #[must_use]
    pub const fn kind(&self) -> AuthMethodKind {
        match self {
            Self::PublicKey(_) => AuthMethodKind::PublicKey,
            Self::Password(_) => AuthMethodKind::Password,
            Self::KeyboardInteractive(_) => AuthMethodKind::KeyboardInteractive,
        }
    }
}

impl fmt::Debug for ClientAuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKey(signer) => formatter.debug_tuple("PublicKey").field(signer).finish(),
            Self::Password(_) => formatter.write_str("Password(\"<redacted>\")"),
            Self::KeyboardInteractive(_) => {
                formatter.write_str("KeyboardInteractive(\"<redacted>\")")
            }
        }
    }
}

/// A successful client authentication result.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClientAuthSuccess {
    method: AuthMethodKind,
}

impl ClientAuthSuccess {
    /// Returns the method that produced message 52.
    #[must_use]
    pub const fn method(self) -> AuthMethodKind {
        self.method
    }
}

type BannerCallback = dyn for<'message, 'language> Fn(&'message str, &'language str);

/// A bounded client authentication state machine over one transport.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `banner_callback` is a boxed
/// caller closure and is not `Debug`, so a derive would not compile; requiring
/// it would put a `Debug` bound on the caller's own closure for no reason they
/// asked for. It is also not reported as a flag, because the type has no
/// representation without one — printing a field that is `true` by construction
/// teaches a reader nothing. `username` is caller identity data and is reported
/// only as a length. `S` is the caller's transport, and an `S: Debug` bound
/// would tax a caller for a `&mut` handle this type only reads and writes. The
/// attempt counters and the service-negotiation flag are what explain a
/// handshake that failed at message 52.
pub struct ClientAuthenticator<'a, S> {
    transport: &'a mut ClientTransport<S>,
    username: Vec<u8>,
    max_attempts: usize,
    service_requested: bool,
    attempts: usize,
    banner_callback: Box<BannerCallback>,
}

impl<S> fmt::Debug for ClientAuthenticator<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No `S: Debug` bound; `transport` and `banner_callback` are not
        // printed. `username` is a length, not the value.
        formatter
            .debug_struct("ClientAuthenticator")
            .field("username_len", &self.username.len())
            .field("attempts", &self.attempts)
            .field("max_attempts", &self.max_attempts)
            .field("service_requested", &self.service_requested)
            .finish_non_exhaustive()
    }
}

impl<'a, S> ClientAuthenticator<'a, S>
where
    S: Read + Write,
{
    /// Creates a client authenticator for one username and transport.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidRequest`] for a zero attempt bound or a
    /// username that cannot be represented as an SSH string.
    pub fn new<T>(
        transport: &'a mut ClientTransport<S>,
        username: T,
        max_attempts: usize,
    ) -> Result<Self, AuthError>
    where
        T: AsRef<[u8]>,
    {
        if max_attempts == 0 {
            return Err(AuthError::InvalidRequest);
        }
        let username = username.as_ref();
        if u32::try_from(username.len()).is_err() {
            return Err(AuthError::InvalidRequest);
        }
        Ok(Self {
            transport,
            username: username.to_vec(),
            max_attempts,
            service_requested: false,
            attempts: 0,
            banner_callback: Box::new(|_message, _language| {}),
        })
    }

    /// Returns the number of user-authentication requests sent.
    #[must_use]
    pub const fn attempts(&self) -> usize {
        self.attempts
    }

    /// Installs a callback invoked for every received authentication banner.
    pub fn set_banner_callback<F>(&mut self, callback: F)
    where
        F: for<'message, 'language> Fn(&'message str, &'language str) + 'static,
    {
        self.banner_callback = Box::new(callback);
    }

    /// Builder form of [`Self::set_banner_callback`].
    #[must_use]
    pub fn with_banner_callback<F>(mut self, callback: F) -> Self
    where
        F: for<'message, 'language> Fn(&'message str, &'language str) + 'static,
    {
        self.set_banner_callback(callback);
        self
    }

    /// Alias for [`Self::set_banner_callback`].
    pub fn set_banner_handler<F>(&mut self, callback: F)
    where
        F: for<'message, 'language> Fn(&'message str, &'language str) + 'static,
    {
        self.set_banner_callback(callback);
    }

    /// Builder alias for [`Self::with_banner_callback`].
    #[must_use]
    pub fn with_banner_handler<F>(self, callback: F) -> Self
    where
        F: for<'message, 'language> Fn(&'message str, &'language str) + 'static,
    {
        self.with_banner_callback(callback)
    }

    /// Restores the default no-op banner callback.
    pub fn clear_banner_callback(&mut self) {
        self.banner_callback = Box::new(|_message, _language| {});
    }

    fn deliver_banner(&self, message: &str, language: &str) -> Result<(), AuthError> {
        match catch_unwind(AssertUnwindSafe(|| {
            (self.banner_callback)(message, language);
        })) {
            Ok(()) => Ok(()),
            Err(_panic_payload) => Err(AuthError::CallbackPanicked),
        }
    }

    /// Authenticates by trying each supplied method in order.
    ///
    /// Message 51, message 53, and a partial-success flag are never treated
    /// as success. Only message 52 completes the operation.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`AuthError`] for protocol, transport, policy, or
    /// exhausted-attempt failures.
    pub fn authenticate(
        &mut self,
        methods: &[ClientAuthMethod],
    ) -> Result<ClientAuthSuccess, AuthError> {
        if methods.is_empty() {
            return Err(AuthError::NoMethods);
        }
        self.ensure_service()?;
        for method in methods {
            if self.attempts >= self.max_attempts {
                return Err(AuthError::AttemptsExhausted);
            }
            match self.authenticate_method(method)? {
                MethodOutcome::Success => {
                    return Ok(ClientAuthSuccess {
                        method: method.kind(),
                    });
                }
                MethodOutcome::Retry => {}
                MethodOutcome::HardFailure => return Err(AuthError::AuthenticationFailed),
            }
        }
        Err(AuthError::AuthenticationFailed)
    }

    fn ensure_service(&mut self) -> Result<(), AuthError> {
        if self.service_requested {
            return Ok(());
        }
        let mut request = Writer::new();
        request.write_byte(SSH_MSG_SERVICE_REQUEST);
        request.write_string(SSH_USERAUTH_SERVICE)?;
        self.transport
            .write_payload(&request.into_bytes())
            .map_err(map_client_transport_error)?;
        self.service_requested = true;
        match self.read_response(ResponseContext::Service)? {
            ClientResponse::ServiceAccepted => Ok(()),
            ClientResponse::Failure { .. } => Err(AuthError::ServiceRejected),
            ClientResponse::Success
            | ClientResponse::PublicKeyOk { .. }
            | ClientResponse::KeyboardInteractiveRequest { .. }
            | ClientResponse::Unexpected => Err(AuthError::UnexpectedMessage),
        }
    }

    fn authenticate_method(
        &mut self,
        method: &ClientAuthMethod,
    ) -> Result<MethodOutcome, AuthError> {
        match method {
            ClientAuthMethod::PublicKey(signer) => self.authenticate_publickey(signer),
            ClientAuthMethod::Password(password) => {
                self.consume_attempt()?;
                self.authenticate_password(password.as_str())
            }
            ClientAuthMethod::KeyboardInteractive(responder) => {
                self.consume_attempt()?;
                self.authenticate_keyboard_interactive(responder.as_ref())
            }
        }
    }

    fn consume_attempt(&mut self) -> Result<(), AuthError> {
        if self.attempts >= self.max_attempts {
            return Err(AuthError::AttemptsExhausted);
        }
        self.attempts += 1;
        Ok(())
    }

    fn authenticate_publickey(
        &mut self,
        signer: &PublicKeySigner,
    ) -> Result<MethodOutcome, AuthError> {
        self.consume_attempt()?;
        let algorithm = signer.algorithm();
        let key_blob = signer.public_key_blob()?;
        let query = encode_publickey_request(&self.username, algorithm, &key_blob, false)?;
        self.transport
            .write_payload(&query)
            .map_err(map_client_transport_error)?;
        match self.read_response(ResponseContext::PublicKeyQuery)? {
            ClientResponse::PublicKeyOk {
                algorithm: response_algorithm,
                key_blob: response_key_blob,
            } => {
                if response_algorithm != algorithm.as_bytes() || response_key_blob != key_blob {
                    return Err(AuthError::UnexpectedMessage);
                }
            }
            ClientResponse::Failure {
                partial_success, ..
            } => {
                return Ok(if partial_success {
                    MethodOutcome::Retry
                } else {
                    MethodOutcome::HardFailure
                });
            }
            ClientResponse::Success => return Ok(MethodOutcome::Success),
            ClientResponse::ServiceAccepted
            | ClientResponse::KeyboardInteractiveRequest { .. }
            | ClientResponse::Unexpected => return Err(AuthError::UnexpectedMessage),
        }

        self.consume_attempt()?;
        let prefix = encode_publickey_request(&self.username, algorithm, &key_blob, true)?;
        let signed_bytes = encode_signed_bytes(self.transport.session_id(), &prefix)?;
        let signature_blob = signer.sign(&signed_bytes)?;
        let mut signature_field = Writer::new();
        signature_field.write_string(&signature_blob)?;
        let mut signed_request = prefix;
        signed_request.extend_from_slice(&signature_field.into_bytes());
        self.transport
            .write_payload(&signed_request)
            .map_err(map_client_transport_error)?;
        match self.read_response(ResponseContext::PublicKeySigned)? {
            ClientResponse::Success => Ok(MethodOutcome::Success),
            ClientResponse::Failure {
                partial_success, ..
            } => Ok(if partial_success {
                MethodOutcome::Retry
            } else {
                MethodOutcome::HardFailure
            }),
            ClientResponse::ServiceAccepted
            | ClientResponse::PublicKeyOk { .. }
            | ClientResponse::KeyboardInteractiveRequest { .. }
            | ClientResponse::Unexpected => Err(AuthError::UnexpectedMessage),
        }
    }

    // How many copies of an outbound password exist between the caller and the
    // socket, and which of them this crate wipes.
    //
    // The chain is worth writing down rather than counting on the way past it,
    // because every link is a place the plaintext can be left in freed memory:
    //
    // 1. the caller's own value, which is the caller's business;
    // 2. the [`Zeroizing`] string in [`ClientAuthMethod::Password`];
    // 3. this request, the [`Writer`] output `authenticate_password` wraps in a
    //    [`PlaintextBytes`];
    // 4. the copy `PacketProtector::seal` works from, and the clear packet it
    //    builds from that, both `PlaintextBytes`;
    // 5. the payload a transport retains while a blocked write is pending, also a
    //    [`PlaintextBytes`].
    //
    // Every buffer this crate allocates for those last four is a `PlaintextBytes`,
    // so the wipe is a property of the type rather than of each call site. The
    // gaps that remain are stated on the type: growth is not covered, and the
    // keyboard-interactive responses and the inbound side of a server's transport
    // are not on this chain.
    fn authenticate_password(&mut self, password: &str) -> Result<MethodOutcome, AuthError> {
        let mut request = Writer::new();
        request.write_byte(SSH_MSG_USERAUTH_REQUEST);
        request.write_string(&self.username)?;
        request.write_string(SSH_CONNECTION_SERVICE)?;
        request.write_string(SSH_PASSWORD_METHOD)?;
        request.write_boolean(false);
        request.write_string_with_limit(password, DEFAULT_STRING_LIMIT)?;
        let request = PlaintextBytes::new(PlaintextSlot::AuthRequest, request.into_bytes());
        self.transport
            .write_payload(request.as_slice())
            .map_err(map_client_transport_error)?;
        match self.read_response(ResponseContext::Password)? {
            ClientResponse::Success => Ok(MethodOutcome::Success),
            ClientResponse::Failure {
                partial_success, ..
            } => Ok(if partial_success {
                MethodOutcome::Retry
            } else {
                MethodOutcome::HardFailure
            }),
            ClientResponse::ServiceAccepted
            | ClientResponse::PublicKeyOk { .. }
            | ClientResponse::KeyboardInteractiveRequest { .. }
            | ClientResponse::Unexpected => Err(AuthError::UnexpectedMessage),
        }
    }

    fn authenticate_keyboard_interactive(
        &mut self,
        responder: &dyn KeyboardInteractiveResponder,
    ) -> Result<MethodOutcome, AuthError> {
        let mut request = Writer::new();
        request.write_byte(SSH_MSG_USERAUTH_REQUEST);
        request.write_string(&self.username)?;
        request.write_string(SSH_CONNECTION_SERVICE)?;
        request.write_string(SSH_KEYBOARD_INTERACTIVE_METHOD)?;
        request.write_string_with_limit(b"", MAX_KEYBOARD_INTERACTIVE_STRING)?;
        request.write_name_list_with_limit(
            std::iter::empty::<&str>(),
            MAX_KEYBOARD_INTERACTIVE_STRING,
        )?;
        self.transport
            .write_payload(&request.into_bytes())
            .map_err(map_client_transport_error)?;

        let challenge = match self.read_response(ResponseContext::KeyboardInteractive)? {
            ClientResponse::KeyboardInteractiveRequest { challenge, .. } => challenge,
            ClientResponse::Success => return Ok(MethodOutcome::Success),
            ClientResponse::Failure {
                partial_success, ..
            } => {
                return Ok(if partial_success {
                    MethodOutcome::Retry
                } else {
                    MethodOutcome::HardFailure
                });
            }
            ClientResponse::ServiceAccepted
            | ClientResponse::PublicKeyOk { .. }
            | ClientResponse::Unexpected => return Err(AuthError::UnexpectedMessage),
        };
        let responses =
            match catch_unwind(AssertUnwindSafe(|| responder.respond(&challenge.prompts))) {
                Ok(Ok(responses)) => responses,
                Ok(Err(error)) => return Err(error),
                Err(_panic_payload) => return Err(AuthError::CallbackPanicked),
            };
        let response_count = responses.len();
        if response_count > MAX_KEYBOARD_INTERACTIVE_RESPONSES
            || response_count != challenge.prompts.len()
            || responses
                .iter()
                .any(|response| response.len() > MAX_KEYBOARD_INTERACTIVE_STRING)
        {
            return Err(AuthError::InvalidRequest);
        }

        self.consume_attempt()?;
        let response = encode_keyboard_interactive_response(&responses)?;
        self.transport
            .write_payload(&response)
            .map_err(map_client_transport_error)?;
        match self.read_response(ResponseContext::KeyboardInteractiveResponse)? {
            ClientResponse::Success => Ok(MethodOutcome::Success),
            ClientResponse::Failure {
                partial_success, ..
            } => Ok(if partial_success {
                MethodOutcome::Retry
            } else {
                MethodOutcome::HardFailure
            }),
            ClientResponse::ServiceAccepted
            | ClientResponse::PublicKeyOk { .. }
            | ClientResponse::KeyboardInteractiveRequest { .. }
            | ClientResponse::Unexpected => Err(AuthError::UnexpectedMessage),
        }
    }

    fn read_response(&mut self, context: ResponseContext) -> Result<ClientResponse, AuthError> {
        for _ in 0..MAX_AUTH_BANNERS {
            let payload = self
                .transport
                .read_payload()
                .map_err(map_client_transport_error)?;
            let Some(message) = payload.first().copied() else {
                return Err(AuthError::UnexpectedMessage);
            };
            match message {
                SSH_MSG_SERVICE_ACCEPT => {
                    let mut reader = Reader::new(&payload[1..]);
                    let service = reader.read_string()?;
                    if !reader.is_empty() || service != SSH_USERAUTH_SERVICE.as_bytes() {
                        return Err(AuthError::UnexpectedMessage);
                    }
                    return Ok(ClientResponse::ServiceAccepted);
                }
                SSH_MSG_USERAUTH_FAILURE => {
                    let mut reader = Reader::new(&payload[1..]);
                    let methods = reader.read_name_list()?;
                    let partial_success = reader.read_boolean()?;
                    if !reader.is_empty() {
                        return Err(AuthError::UnexpectedMessage);
                    }
                    return Ok(ClientResponse::Failure {
                        methods,
                        partial_success,
                    });
                }
                SSH_MSG_USERAUTH_SUCCESS => {
                    if payload.len() != 1 {
                        return Err(AuthError::UnexpectedMessage);
                    }
                    return Ok(ClientResponse::Success);
                }
                SSH_MSG_USERAUTH_BANNER => {
                    let mut reader = Reader::new(&payload[1..]);
                    let message = reader.read_string_with_limit(DEFAULT_STRING_LIMIT)?;
                    let language = reader.read_string_with_limit(DEFAULT_STRING_LIMIT)?;
                    if !reader.is_empty() {
                        return Err(AuthError::UnexpectedMessage);
                    }
                    let message =
                        std::str::from_utf8(message).map_err(|_error| AuthError::InvalidRequest)?;
                    let language = std::str::from_utf8(language)
                        .map_err(|_error| AuthError::InvalidRequest)?;
                    self.deliver_banner(message, language)?;
                }
                SSH_MSG_USERAUTH_PK_OK => match context {
                    ResponseContext::PublicKeyQuery | ResponseContext::PublicKeySigned => {
                        let mut reader = Reader::new(&payload[1..]);
                        let algorithm = reader.read_string_bytes()?;
                        let key_blob = reader.read_string_bytes()?;
                        if !reader.is_empty() {
                            return Err(AuthError::UnexpectedMessage);
                        }
                        return Ok(ClientResponse::PublicKeyOk {
                            algorithm,
                            key_blob,
                        });
                    }
                    ResponseContext::KeyboardInteractive => {
                        return parse_keyboard_interactive_request(&payload[1..]);
                    }
                    ResponseContext::Service
                    | ResponseContext::Password
                    | ResponseContext::KeyboardInteractiveResponse => {
                        return Err(AuthError::UnexpectedMessage);
                    }
                },
                _ => return Ok(ClientResponse::Unexpected),
            }
        }
        Err(AuthError::AttemptsExhausted)
    }
}

/// Runs the bounded client authentication loop over one transport.
///
/// # Errors
///
/// Returns the same errors as [`ClientAuthenticator::authenticate`].
pub fn authenticate_client<S, T>(
    transport: &mut ClientTransport<S>,
    username: T,
    methods: &[ClientAuthMethod],
    max_attempts: usize,
) -> Result<ClientAuthSuccess, AuthError>
where
    S: Read + Write,
    T: AsRef<[u8]>,
{
    let mut authenticator = ClientAuthenticator::new(transport, username, max_attempts)?;
    authenticator.authenticate(methods)
}

struct RequestHeader<'a> {
    username: &'a [u8],
    service: &'a [u8],
    method: &'a [u8],
    position: usize,
}

fn parse_userauth_header(payload: &[u8]) -> Result<RequestHeader<'_>, AuthError> {
    let mut reader = Reader::new(payload);
    if reader.read_byte()? != SSH_MSG_USERAUTH_REQUEST {
        return Err(AuthError::InvalidRequest);
    }
    let username = reader.read_string()?;
    let service = reader.read_string()?;
    let method = reader.read_string()?;
    Ok(RequestHeader {
        username,
        service,
        method,
        position: reader.position(),
    })
}

enum ParsedPublicKey {
    Ed25519(Ed25519PublicKey),
    Rsa(RsaPublicKey),
}

fn parse_public_key(algorithm: &[u8], blob: &[u8]) -> Result<ParsedPublicKey, AuthError> {
    match algorithm {
        value if value == SSH_ED25519.as_bytes() => Ed25519PublicKey::from_blob(blob)
            .map(ParsedPublicKey::Ed25519)
            .map_err(map_hostkey_error),
        value if value == SSH_RSA_SHA2_256.as_bytes() => {
            RsaPublicKey::from_blob(blob).map(ParsedPublicKey::Rsa)
        }
        _ => Err(AuthError::InvalidKey),
    }
}

fn validate_authorized_blob(blob: &[u8]) -> Result<(), AuthError> {
    let mut reader = Reader::new(blob);
    let key_type = reader.read_string()?;
    if key_type == SSH_ED25519.as_bytes() {
        Ed25519PublicKey::from_blob(blob)
            .map(|_key| ())
            .map_err(map_hostkey_error)
    } else if key_type == SSH_RSA.as_bytes() {
        RsaPublicKey::from_blob(blob).map(|_key| ())
    } else {
        Err(AuthError::InvalidKey)
    }
}

fn verify_public_key(key: &ParsedPublicKey, signature_blob: &[u8], signed_bytes: &[u8]) -> bool {
    match key {
        ParsedPublicKey::Ed25519(key) => {
            verify_host_key_signature(key, signature_blob, signed_bytes).is_ok()
        }
        ParsedPublicKey::Rsa(key) => {
            let digest = sha2::Sha256::digest(signed_bytes);
            let Ok(signature) = decode_rsa_signature(signature_blob) else {
                return false;
            };
            if signature.len() != key.public_key().size() {
                return false;
            }
            key.public_key()
                .verify(
                    rsa::Pkcs1v15Sign::new_unprefixed(),
                    digest.as_slice(),
                    signature,
                )
                .is_ok()
        }
    }
}

fn decode_rsa_signature(blob: &[u8]) -> Result<&[u8], AuthError> {
    let mut reader = Reader::new(blob);
    if reader.read_string()? != SSH_RSA_SHA2_256.as_bytes() {
        return Err(AuthError::InvalidProof);
    }
    let signature = reader.read_string()?;
    if signature.is_empty() || !reader.is_empty() {
        return Err(AuthError::InvalidProof);
    }
    Ok(signature)
}

fn encode_rsa_blob(key: &rsa::RsaPublicKey) -> Result<Vec<u8>, AuthError> {
    let mut writer = Writer::new();
    writer.write_string(SSH_RSA)?;
    let exponent = positive_mpint_bytes(&key.e().to_bytes_be())?;
    let modulus = positive_mpint_bytes(&key.n().to_bytes_be())?;
    let mut blob = writer.into_bytes();
    append_positive_mpint(&mut blob, &exponent)?;
    append_positive_mpint(&mut blob, &modulus)?;
    Ok(blob)
}

fn positive_mpint_bytes(value: &[u8]) -> Result<Vec<u8>, AuthError> {
    if value.is_empty() {
        return Err(AuthError::InvalidKey);
    }
    let mut bytes = value.to_vec();
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    Ok(bytes)
}

fn append_positive_mpint(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthError> {
    let length = u32::try_from(value.len()).map_err(|_error| AuthError::InvalidKey)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn encode_signed_bytes(session_id: &[u8], request_prefix: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut writer = Writer::with_capacity(4 + session_id.len() + request_prefix.len());
    writer.write_string(session_id)?;
    let mut result = writer.into_bytes();
    result.extend_from_slice(request_prefix);
    Ok(result)
}

fn encode_publickey_request(
    username: &[u8],
    algorithm: &str,
    key_blob: &[u8],
    signed: bool,
) -> Result<Vec<u8>, AuthError> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_USERAUTH_REQUEST);
    writer.write_string(username)?;
    writer.write_string(SSH_CONNECTION_SERVICE)?;
    writer.write_string(SSH_PUBLICKEY_METHOD)?;
    writer.write_boolean(signed);
    writer.write_string(algorithm)?;
    writer.write_string(key_blob)?;
    Ok(writer.into_bytes())
}

fn parse_keyboard_interactive_request(input: &[u8]) -> Result<ClientResponse, AuthError> {
    let mut reader = Reader::new(input);
    let name = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
    let instruction = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
    let language = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
    let count =
        usize::try_from(reader.read_uint32()?).map_err(|_error| AuthError::InvalidRequest)?;
    if count > MAX_KEYBOARD_INTERACTIVE_PROMPTS {
        return Err(AuthError::InvalidRequest);
    }
    let name = std::str::from_utf8(name)
        .map_err(|_error| AuthError::InvalidRequest)?
        .to_owned();
    let instruction = std::str::from_utf8(instruction)
        .map_err(|_error| AuthError::InvalidRequest)?
        .to_owned();
    let _language = std::str::from_utf8(language).map_err(|_error| AuthError::InvalidRequest)?;
    let mut prompts = Vec::with_capacity(count);
    for _ in 0..count {
        let text = reader.read_string_with_limit(MAX_KEYBOARD_INTERACTIVE_STRING)?;
        let text = std::str::from_utf8(text)
            .map_err(|_error| AuthError::InvalidRequest)?
            .to_owned();
        let echo = reader.read_boolean()?;
        prompts.push(KeyboardInteractivePrompt::new(text, echo));
    }
    if !reader.is_empty() {
        return Err(AuthError::InvalidRequest);
    }
    let challenge = KeyboardInteractiveChallenge::new(name, instruction, prompts);
    challenge.validate()?;
    Ok(ClientResponse::KeyboardInteractiveRequest { challenge })
}

fn map_ecdsa_error(error: EcdsaHostKeyError) -> AuthError {
    match error {
        EcdsaHostKeyError::Wire(error) => AuthError::Wire(error),
        _ => AuthError::InvalidKey,
    }
}

fn map_hostkey_error(error: HostKeyError) -> AuthError {
    match error {
        HostKeyError::Wire(error) => AuthError::Wire(error),
        _ => AuthError::InvalidKey,
    }
}

fn map_client_transport_error(_error: ClientTransportError) -> AuthError {
    AuthError::Transport
}

fn map_server_transport_error(_error: ServerTransportError) -> AuthError {
    AuthError::Transport
}

fn is_would_block(error: &ServerTransportError) -> bool {
    matches!(
        error,
        ServerTransportError::Transport(ServerUnderlyingTransportError::Io(io_error))
            if io_error.kind() == io::ErrorKind::WouldBlock
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseContext {
    Service,
    PublicKeyQuery,
    PublicKeySigned,
    Password,
    KeyboardInteractive,
    KeyboardInteractiveResponse,
}

enum MethodOutcome {
    Success,
    Retry,
    HardFailure,
}

enum ClientResponse {
    ServiceAccepted,
    Failure {
        methods: Vec<String>,
        partial_success: bool,
    },
    Success,
    PublicKeyOk {
        algorithm: Vec<u8>,
        key_blob: Vec<u8>,
    },
    KeyboardInteractiveRequest {
        challenge: KeyboardInteractiveChallenge,
    },
    Unexpected,
}
