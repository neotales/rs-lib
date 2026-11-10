//! Server-side SSH identification, negotiation, and initial key exchange.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use neotales_ssh::{Error as WireError, build_packet};

use crate::cipher::{PacketKeyMaterial, PacketProtectionError, PacketProtector, PacketSuite};
use crate::hostkey::{Ed25519PublicKey, Ed25519Signer, HostKeyError};
use crate::kex::dh_group16::{Group16KexCompletion, Group16KexContext, Group16ServerKex};
use crate::kex::mlkem768_x25519::ServerKex as MlKemServerKex;
use crate::kex::{
    Curve25519, DerivationLengths, DerivedKeys, DhGroup16, EcdhP256, EphemeralKey, KexCompletion,
    KexContext, KexError, KexReply, KeyExchange, ServerKex, SharedSecret, derive_keys,
};
use crate::msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256,
    HMAC_SHA2_256, HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512, HMAC_SHA2_512_ETM_OPENSSH,
    HOST_KEY_SSH_ED25519, KEX_DIFFIE_HELLMAN_GROUP16_SHA512, KEX_MLKEM768X25519_SHA256,
    KEX_STRICT_S_V00_OPENSSH, KexInit, NegotiationError, SSH_MSG_KEXINIT,
    SUPPORTED_HOST_KEY_ALGORITHMS, SUPPORTED_MAC_ALGORITHMS, kex_guess_matches,
};
use crate::sequence::{
    Direction, PacketDisposition, PacketObservation, RekeyPhase, SSH_MSG_KEX_METHOD_FIRST,
    SSH_MSG_KEX_METHOD_LAST, SSH_MSG_NEWKEYS, SequenceError, SequenceState,
};
use crate::transport::{
    ProtectedReadBuffer, ProtectedWriteBuffer, TransportError, random_unprotected_padding,
    read_peer_identification, read_protected_packet_buffered, read_unprotected_packet,
    write_identification, write_protected_packet_buffered,
};
use neotales_ssh::compression::CompressionAlgorithm;

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
/// The SSH message number for a service request at the authentication boundary.
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// The SSH message number for a user-authentication request.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const AES128_KEY_LENGTH: usize = 16;
const AES256_KEY_LENGTH: usize = 32;
const CHACHA_KEY_LENGTH: usize = 64;
const CHACHA20_POLY1305_OPENSSH_NAME: &str =
    neotales_ssh::chacha_cipher::CHACHA20_POLY1305_OPENSSH_NAME;
const CTR_IV_LENGTH: usize = 16;
const GCM_IV_LENGTH: usize = 12;
const CHACHA_IV_LENGTH: usize = 8;
const SHA256_INTEGRITY_LENGTH: usize = 32;
const SHA512_INTEGRITY_LENGTH: usize = 64;
const PLAIN_PACKET_BLOCK_SIZE: usize = 8;

/// The default server identification written by [`ServerConfig::new`].
pub const DEFAULT_SERVER_IDENTIFICATION: &str = "SSH-2.0-neotales-ssh_0.1";

/// An alias for [`DEFAULT_SERVER_IDENTIFICATION`].
pub const SERVER_IDENTIFICATION: &str = DEFAULT_SERVER_IDENTIFICATION;

/// An alias for [`DEFAULT_SERVER_IDENTIFICATION`] using version terminology.
pub const DEFAULT_SERVER_VERSION: &str = DEFAULT_SERVER_IDENTIFICATION;

/// An alias for [`DEFAULT_SERVER_IDENTIFICATION`] using short server terminology.
pub const SERVER_VERSION: &str = DEFAULT_SERVER_IDENTIFICATION;

/// A safe failure produced by the server initial handshake.
///
/// Error values do not contain peer-controlled payloads, algorithm names,
/// identification strings, host-key material, or derived keys.
#[derive(Debug)]
pub enum HandshakeError {
    /// Identification, framing, I/O, packet protection, or sequencing failed.
    Transport(TransportError),
    /// The two proposals had no mutually supported algorithm.
    Negotiation,
    /// A selected name is not implemented by this server.
    UnsupportedAlgorithm,
    /// KEX proposal validation, message decoding, agreement, or derivation failed.
    Kex(KexError),
    /// Host-key blob creation or exchange-hash signing failed.
    HostKey(HostKeyError),
    /// A configured proposal or server version is not usable.
    InvalidConfiguration,
    /// The operating system random-number source failed.
    EntropyFailure,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "SSH server transport error: {error}"),
            Self::Negotiation => {
                formatter.write_str("SSH server proposals have no common algorithm")
            }
            Self::UnsupportedAlgorithm => {
                formatter.write_str("SSH server selected an unsupported algorithm")
            }
            Self::Kex(error) => write!(formatter, "SSH server key-exchange error: {error}"),
            Self::HostKey(error) => write!(formatter, "SSH server host-key error: {error}"),
            Self::InvalidConfiguration => {
                formatter.write_str("SSH server configuration is invalid")
            }
            Self::EntropyFailure => {
                formatter.write_str("SSH server random-number generation failed")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Kex(error) => Some(error),
            Self::HostKey(error) => Some(error),
            Self::Negotiation
            | Self::UnsupportedAlgorithm
            | Self::InvalidConfiguration
            | Self::EntropyFailure => None,
        }
    }
}

impl From<TransportError> for HandshakeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<KexError> for HandshakeError {
    fn from(error: KexError) -> Self {
        Self::Kex(error)
    }
}

impl From<HostKeyError> for HandshakeError {
    fn from(error: HostKeyError) -> Self {
        Self::HostKey(error)
    }
}

impl From<PacketProtectionError> for HandshakeError {
    fn from(error: PacketProtectionError) -> Self {
        Self::Transport(TransportError::PacketProtection(error))
    }
}

impl From<NegotiationError> for HandshakeError {
    fn from(_error: NegotiationError) -> Self {
        Self::Negotiation
    }
}

impl From<WireError> for HandshakeError {
    fn from(error: WireError) -> Self {
        Self::Transport(TransportError::Wire(error))
    }
}

impl From<SequenceError> for HandshakeError {
    fn from(error: SequenceError) -> Self {
        Self::Transport(error.into())
    }
}

impl From<io::Error> for HandshakeError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error.into())
    }
}

/// A descriptive alias for the server handshake error.
pub type ServerHandshakeError = HandshakeError;

/// A safe failure returned while reading or writing a server transport packet.
#[derive(Debug)]
pub enum ServerTransportError {
    /// Identification, framing, I/O, protection, or sequencing failed.
    Transport(TransportError),
    /// The transport has not completed NEWKEYS.
    NotEstablished,
    /// A packet was received before the SSH-009 authentication state machine.
    ///
    /// Only `SSH_MSG_SERVICE_REQUEST` and `SSH_MSG_USERAUTH_REQUEST` are
    /// accepted by [`ServerTransport::read_auth_packet`].
    UnauthenticatedMessage,
    /// A post-establishment KEX proposal or exchange failed.
    Kex(KexError),
    /// A post-establishment KEX proposal had no common algorithm.
    Negotiation,
    /// A post-establishment KEX selected an algorithm this server does not
    /// implement for rekeying.
    UnsupportedAlgorithm,
    /// A host-key operation failed during rekeying.
    HostKey(HostKeyError),
    /// An application packet was attempted while a rekey was active.
    RekeyInProgress,
}

impl fmt::Display for ServerTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "SSH server transport error: {error}"),
            Self::NotEstablished => formatter.write_str("SSH server transport is not established"),
            Self::UnauthenticatedMessage => {
                formatter.write_str("SSH server received a packet before user authentication")
            }
            Self::Kex(error) => write!(formatter, "SSH server rekey error: {error}"),
            Self::Negotiation => {
                formatter.write_str("SSH server rekey proposals have no common algorithm")
            }
            Self::UnsupportedAlgorithm => {
                formatter.write_str("SSH server rekey selected an unsupported algorithm")
            }
            Self::HostKey(error) => {
                write!(formatter, "SSH server rekey host-key error: {error}")
            }
            Self::RekeyInProgress => {
                formatter.write_str("SSH server cannot send application data during rekey")
            }
        }
    }
}

impl std::error::Error for ServerTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Kex(error) => Some(error),
            Self::HostKey(error) => Some(error),
            Self::NotEstablished
            | Self::UnauthenticatedMessage
            | Self::Negotiation
            | Self::UnsupportedAlgorithm
            | Self::RekeyInProgress => None,
        }
    }
}

impl From<TransportError> for ServerTransportError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<PacketProtectionError> for ServerTransportError {
    fn from(error: PacketProtectionError) -> Self {
        Self::Transport(error.into())
    }
}

impl From<SequenceError> for ServerTransportError {
    fn from(error: SequenceError) -> Self {
        Self::Transport(error.into())
    }
}

impl From<io::Error> for ServerTransportError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error.into())
    }
}

impl From<KexError> for ServerTransportError {
    fn from(error: KexError) -> Self {
        Self::Kex(error)
    }
}

impl From<HostKeyError> for ServerTransportError {
    fn from(error: HostKeyError) -> Self {
        Self::HostKey(error)
    }
}

impl From<NegotiationError> for ServerTransportError {
    fn from(_error: NegotiationError) -> Self {
        Self::Negotiation
    }
}

impl From<HandshakeError> for ServerTransportError {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Transport(error) => Self::Transport(error),
            HandshakeError::Negotiation => Self::Negotiation,
            HandshakeError::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            HandshakeError::Kex(error) => Self::Kex(error),
            HandshakeError::HostKey(error) => Self::HostKey(error),
            HandshakeError::InvalidConfiguration => Self::Transport(TransportError::InvalidMessage),
            HandshakeError::EntropyFailure => Self::Transport(TransportError::EntropyFailure),
        }
    }
}

/// A short alias for [`ServerTransportError`].
pub type ServerError = ServerTransportError;

/// Reusable server proposal, identification, and host-signer policy.
///
/// A server always owns an explicit [`Ed25519Signer`]. There is no `Default`
/// implementation and no constructor that can create a server without a
/// signer. The default proposal advertises only algorithms implemented by the
/// baseline SSH-008 transport and uses a fresh KEXINIT cookie per connection.
#[derive(Debug)]
pub struct ServerConfig {
    signer: Arc<Ed25519Signer>,
    server_version: String,
    kexinit: KexInit,
}

impl ServerConfig {
    /// Creates a server configuration using the supplied Ed25519 host signer.
    #[must_use]
    pub fn new(signer: Ed25519Signer) -> Self {
        Self {
            signer: Arc::new(signer),
            server_version: DEFAULT_SERVER_IDENTIFICATION.to_owned(),
            kexinit: supported_server_kexinit([0; 16]),
        }
    }

    /// Creates a server configuration from an explicit Ed25519 host signer.
    #[must_use]
    pub fn with_signer(signer: Ed25519Signer) -> Self {
        Self::new(signer)
    }

    /// Creates a server configuration from an explicit Ed25519 host signer.
    #[must_use]
    pub fn from_signer(signer: Ed25519Signer) -> Self {
        Self::new(signer)
    }

    /// Replaces the server identification software string.
    ///
    /// The value is validated when a connection starts. It must be a
    /// non-empty ASCII string without CR, LF, or NUL and fit the 255-byte
    /// identification limit including CR LF.
    #[must_use]
    pub fn with_server_version(mut self, version: impl Into<String>) -> Self {
        self.server_version = version.into();
        self
    }

    /// Replaces the server identification using the shorter version-oriented name.
    #[must_use]
    pub fn with_version(self, version: impl Into<String>) -> Self {
        self.with_server_version(version)
    }

    /// Replaces the server KEXINIT proposal while retaining the caller's cookie.
    ///
    /// Unsupported selected algorithms and invalid reserved fields are rejected
    /// when a connection starts rather than removed from the transcript. The
    /// server never advertises a guessed first KEX packet.
    #[must_use]
    pub fn with_kexinit(mut self, kexinit: KexInit) -> Self {
        self.kexinit = kexinit;
        self
    }

    /// Replaces the server proposal using an explicit policy-oriented name.
    #[must_use]
    pub fn with_proposal(self, kexinit: KexInit) -> Self {
        self.with_kexinit(kexinit)
    }

    /// Returns the configured server identification string.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Returns the configured proposal before per-connection cookie generation.
    #[must_use]
    pub const fn kexinit(&self) -> &KexInit {
        &self.kexinit
    }

    /// Returns the configured host key's public point.
    #[must_use]
    pub fn host_key(&self) -> &Ed25519PublicKey {
        self.signer.public_key()
    }

    /// Starts an incremental server handshake over `stream`.
    ///
    /// This method reads the client identification, writes the server
    /// identification, and sends the server KEXINIT. The returned handshake
    /// can be advanced by a caller that owns a nonblocking or in-memory
    /// stream; [`Self::connect`] is the blocking convenience operation.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for invalid configuration,
    /// identification, framing, or I/O failures.
    pub fn start<S>(&self, stream: S) -> Result<ServerHandshake<'_, S>, HandshakeError>
    where
        S: Read + Write,
    {
        ServerHandshake::start(self, stream)
    }

    /// Performs the complete synchronous server handshake over `stream`.
    ///
    /// The client identification is read before this method writes the server
    /// identification. The returned transport has completed packet protection
    /// but is explicitly unauthenticated; callers must use
    /// [`ServerTransport::read_auth_packet`] before installing SSH-009 policy.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for identification, I/O, proposal,
    /// KEX, host-key, derivation, protection, or sequence failures. No
    /// unauthenticated transport is returned on failure.
    pub fn connect<S>(&self, stream: S) -> Result<ServerTransport<S>, HandshakeError>
    where
        S: Read + Write,
    {
        let mut handshake = self.start(stream)?;
        loop {
            match handshake.step()? {
                AdvanceResult::Complete => return handshake.into_transport(),
                AdvanceResult::Progress => {}
                AdvanceResult::WouldBlock => {
                    return Err(HandshakeError::Transport(TransportError::Io(
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "SSH server handshake would block",
                        ),
                    )));
                }
            }
        }
    }

    /// Performs the complete synchronous server handshake over `stream`.
    ///
    /// This is an alias for [`Self::connect`] for callers that name the
    /// operation after accepting a connection.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::connect`].
    pub fn accept<S>(&self, stream: S) -> Result<ServerTransport<S>, HandshakeError>
    where
        S: Read + Write,
    {
        self.connect(stream)
    }
}

/// A staged server handshake for synchronous or caller-driven streams.
///
/// [`ServerConfig::connect`] uses this type internally for ordinary blocking
/// streams. A caller driving a nonblocking stream can call [`Self::advance`]
/// whenever input is available. `Ok(false)` means that the current read would
/// block; it is not a protocol failure and the same handshake can be advanced
/// again later.
pub struct ServerHandshake<'a, S> {
    config: &'a ServerConfig,
    stream: S,
    sequence: SequenceState,
    phase: ServerHandshakePhase,
    client_version: String,
    server_kexinit: KexInit,
    server_kexinit_payload: Vec<u8>,
    client_kexinit: Option<KexInit>,
    server_kex: Option<ServerKex<BoxedKeyExchange>>,
    group16_server_kex: Option<Group16ServerKex>,
    group16_completion: Option<Group16KexCompletion>,
    mlkem_server_kex: Option<MlKemServerKex>,
    mlkem_completion: Option<crate::kex::mlkem768_x25519::HybridCompletion>,
    negotiated_algorithm: Option<String>,
    client_guess_is_correct: bool,
    protection: Option<ProtectionPlan>,
    read_protector: Option<PacketProtector>,
    write_protector: Option<PacketProtector>,
    completion: Option<KexCompletion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerHandshakePhase {
    ClientKexInit,
    ClientKex,
    ClientNewKeys,
    Complete,
}

enum AdvanceResult {
    Progress,
    WouldBlock,
    Complete,
}

impl<S> fmt::Debug for ServerHandshake<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHandshake")
            .field("phase", &self.phase)
            .field("strict_kex", &self.sequence.strict_kex())
            .field("inbound_sequence", &self.sequence.inbound_sequence())
            .field("outbound_sequence", &self.sequence.outbound_sequence())
            .finish_non_exhaustive()
    }
}

impl<'a, S> ServerHandshake<'a, S>
where
    S: Read + Write,
{
    fn start(config: &'a ServerConfig, mut stream: S) -> Result<Self, HandshakeError> {
        validate_config(config)?;
        let client_version = read_peer_identification(&mut stream)?;
        write_identification(&mut stream, &config.server_version)?;
        let mut server_kexinit = config.kexinit.clone();
        getrandom::fill(&mut server_kexinit.cookie)
            .map_err(|_error| HandshakeError::EntropyFailure)?;
        let server_kexinit_payload = server_kexinit.encode()?;
        let mut handshake = Self {
            config,
            stream,
            sequence: SequenceState::new(),
            phase: ServerHandshakePhase::ClientKexInit,
            client_version,
            server_kexinit,
            server_kexinit_payload: server_kexinit_payload.clone(),
            client_kexinit: None,
            server_kex: None,
            group16_server_kex: None,
            group16_completion: None,
            mlkem_server_kex: None,
            mlkem_completion: None,
            negotiated_algorithm: None,
            client_guess_is_correct: false,
            protection: None,
            read_protector: None,
            write_protector: None,
            completion: None,
        };
        handshake.write_plain_packet(&server_kexinit_payload, SSH_MSG_KEXINIT)?;
        Ok(handshake)
    }

    /// Advances the handshake by one protocol phase when input is available.
    ///
    /// `Ok(true)` means that the handshake made progress, including successful
    /// completion. `Ok(false)` means that the underlying stream returned
    /// `WouldBlock`; the handshake remains usable and can be advanced again.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for any protocol, cryptographic,
    /// framing, or nonblocking-I/O failure other than `WouldBlock`.
    pub fn advance(&mut self) -> Result<bool, HandshakeError> {
        match self.step()? {
            AdvanceResult::Complete | AdvanceResult::Progress => Ok(true),
            AdvanceResult::WouldBlock => Ok(false),
        }
    }

    fn step(&mut self) -> Result<AdvanceResult, HandshakeError> {
        if self.phase == ServerHandshakePhase::Complete {
            return Ok(AdvanceResult::Complete);
        }
        let result = match self.phase {
            ServerHandshakePhase::ClientKexInit => self.accept_client_kexinit(),
            ServerHandshakePhase::ClientKex => self.accept_client_kex(),
            ServerHandshakePhase::ClientNewKeys => self.accept_client_newkeys(),
            ServerHandshakePhase::Complete => Ok(()),
        };
        match result {
            Ok(()) if self.phase == ServerHandshakePhase::Complete => Ok(AdvanceResult::Complete),
            Ok(()) => Ok(AdvanceResult::Progress),
            Err(HandshakeError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                Ok(AdvanceResult::WouldBlock)
            }
            Err(error) => Err(error),
        }
    }

    /// Returns whether NEWKEYS has completed in both directions.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, ServerHandshakePhase::Complete)
    }

    /// Returns the client identification received before the server banner.
    #[must_use]
    pub fn client_version(&self) -> &str {
        &self.client_version
    }

    /// Consumes a completed handshake and returns its unauthenticated transport.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::InvalidConfiguration`] when called before
    /// [`Self::advance`] reports completion.
    pub fn into_transport(self) -> Result<ServerTransport<S>, HandshakeError> {
        if !self.is_complete() {
            return Err(HandshakeError::InvalidConfiguration);
        }
        let session_id = if let Some(completion) = self.group16_completion.as_ref() {
            completion.exchange_hash().to_vec()
        } else if let Some(completion) = self.mlkem_completion.as_ref() {
            completion.session_id.to_vec()
        } else {
            self.completion
                .as_ref()
                .ok_or(HandshakeError::InvalidConfiguration)?
                .session_id()
                .to_vec()
        };
        let read_protector = self
            .read_protector
            .ok_or(HandshakeError::InvalidConfiguration)?;
        let write_protector = self
            .write_protector
            .ok_or(HandshakeError::InvalidConfiguration)?;
        let signer = Arc::clone(&self.config.signer);
        let host_key_blob = signer.public_key_blob()?;
        let host_key = *signer.public_key();
        let client_version = self.client_version;
        let server_version = self.config.server_version.clone();
        let rekey_proposal = self.config.kexinit.clone();
        let initial_algorithm = self
            .negotiated_algorithm
            .ok_or(HandshakeError::InvalidConfiguration)?;
        Ok(ServerTransport {
            stream: self.stream,
            sequence: self.sequence,
            session_id,
            client_version,
            server_version,
            signer,
            host_key,
            host_key_blob,
            initial_algorithm,
            rekey_proposal,
            read_protector: Some(read_protector),
            write_protector: Some(write_protector),
            read_buffer: ProtectedReadBuffer::default(),
            write_buffer: ProtectedWriteBuffer::default(),
            established: true,
            authenticated: false,
            rekey: None,
        })
    }

    fn accept_client_kexinit(&mut self) -> Result<(), HandshakeError> {
        let payload = self.read_handshake_packet(false)?;
        if payload.first() != Some(&SSH_MSG_KEXINIT) {
            return Err(TransportError::UnexpectedMessage.into());
        }
        let client_kexinit = KexInit::decode(&payload)
            .map_err(|error| HandshakeError::Kex(KexError::Wire(error)))?;
        if client_kexinit.reserved != 0 {
            return Err(HandshakeError::Kex(KexError::InvalidProposal));
        }
        let algorithms = client_kexinit.negotiate(&self.server_kexinit)?;
        let client_guess_is_correct = !client_kexinit.first_kex_packet_follows
            || kex_guess_matches(&client_kexinit, &algorithms);
        let protection = ProtectionPlan::from_algorithms(&algorithms)?;
        self.negotiated_algorithm = Some(algorithms.kex.clone());
        self.client_guess_is_correct = client_guess_is_correct;
        let strict_kex = client_kexinit.strict_kex_enabled(&self.server_kexinit);
        self.sequence.set_strict_kex(strict_kex)?;
        let host_key_blob = self.config.signer.public_key_blob()?;
        if algorithms.kex == KEX_DIFFIE_HELLMAN_GROUP16_SHA512 {
            let context = Group16KexContext::new(
                &self.client_version,
                &self.config.server_version,
                payload.clone(),
                self.server_kexinit_payload.clone(),
            )?;
            let server_kex = Group16ServerKex::new(DhGroup16::new(), context, &host_key_blob)?;
            self.group16_server_kex = Some(server_kex);
        } else if algorithms.kex == KEX_MLKEM768X25519_SHA256 {
            let context = KexContext::new(
                &self.client_version,
                &self.config.server_version,
                payload.clone(),
                self.server_kexinit_payload.clone(),
                &algorithms.kex,
            )?;
            self.mlkem_server_kex = Some(MlKemServerKex::new(context, &host_key_blob)?);
        } else {
            let context = KexContext::new(
                &self.client_version,
                &self.config.server_version,
                payload.clone(),
                self.server_kexinit_payload.clone(),
                &algorithms.kex,
            )?;
            let mechanism = mechanism_for(&algorithms.kex)?;
            let server_kex = ServerKex::new(mechanism, context, &host_key_blob)?;
            self.server_kex = Some(server_kex);
        }
        self.sequence
            .observe_kexinit(Direction::Inbound, client_kexinit.first_kex_packet_follows)?;
        self.sequence.commit_inbound()?;
        self.client_kexinit = Some(client_kexinit);
        self.protection = Some(protection);
        self.phase = ServerHandshakePhase::ClientKex;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn accept_client_kex(&mut self) -> Result<(), HandshakeError> {
        let guessed = self
            .client_kexinit
            .as_ref()
            .ok_or(HandshakeError::InvalidConfiguration)?
            .first_kex_packet_follows;
        let payload = if guessed && !self.client_guess_is_correct {
            self.read_handshake_packet(true)?;
            self.read_handshake_packet(false)?
        } else {
            self.read_handshake_packet(false)?
        };
        if payload.first() != Some(&SSH_MSG_KEX_ECDH_INIT) {
            return Err(TransportError::UnexpectedMessage.into());
        }
        if self.group16_server_kex.is_some() {
            let (reply, completion) = {
                let server_kex = self
                    .group16_server_kex
                    .as_mut()
                    .ok_or(HandshakeError::InvalidConfiguration)?;
                server_kex.accept_init(&payload)?;
                self.sequence.observe_inbound(SSH_MSG_KEX_ECDH_INIT)?;
                self.sequence.commit_inbound()?;
                let prepared = server_kex.prepare_exchange()?.clone();
                let signature = self
                    .config
                    .signer
                    .sign_exchange_hash(prepared.exchange_hash())?;
                let reply = server_kex.reply_message(&signature)?;
                let completion = server_kex
                    .completion()
                    .cloned()
                    .ok_or(HandshakeError::InvalidConfiguration)?;
                (reply, completion)
            };
            self.write_plain_packet(&reply, SSH_MSG_KEX_ECDH_REPLY)?;
            let protection = self
                .protection
                .as_ref()
                .ok_or(HandshakeError::InvalidConfiguration)?;
            let derived = crate::kex::dh_group16::derive_keys_sha512(
                completion.shared_secret(),
                completion.exchange_hash(),
                completion.session_id(),
                protection.lengths,
            )?;
            let read_protector = PacketProtector::new_with_compression(
                protection.read_suite,
                material_for(
                    protection.read_suite,
                    &derived.iv_client_to_server,
                    &derived.encryption_key_client_to_server,
                    Some(&derived.integrity_key_client_to_server),
                )?,
                protection.read_compression,
            )?;
            let write_protector = PacketProtector::new_with_compression(
                protection.write_suite,
                material_for(
                    protection.write_suite,
                    &derived.iv_server_to_client,
                    &derived.encryption_key_server_to_client,
                    Some(&derived.integrity_key_server_to_client),
                )?,
                protection.write_compression,
            )?;
            self.write_plain_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
            self.read_protector = Some(read_protector);
            self.write_protector = Some(write_protector);
            self.group16_completion = Some(completion);
            self.phase = ServerHandshakePhase::ClientNewKeys;
            return Ok(());
        }
        if self.mlkem_server_kex.is_some() {
            let prepared = {
                let server_kex = self
                    .mlkem_server_kex
                    .as_mut()
                    .ok_or(HandshakeError::InvalidConfiguration)?;
                let prepared = server_kex.accept_init(&payload)?;
                self.sequence.observe_inbound(SSH_MSG_KEX_ECDH_INIT)?;
                self.sequence.commit_inbound()?;
                prepared
            };
            let signature = self
                .config
                .signer
                .sign_exchange_hash(prepared.exchange_hash())?;
            let reply = prepared.reply_message(&signature)?;
            self.write_plain_packet(&reply, SSH_MSG_KEX_ECDH_REPLY)?;
            let protection = self
                .protection
                .as_ref()
                .ok_or(HandshakeError::InvalidConfiguration)?;
            let derived = derive_keys(
                prepared.shared_secret(),
                prepared.exchange_hash(),
                prepared.session_id(),
                protection.lengths,
            )?;
            let read_protector = PacketProtector::new_with_compression(
                protection.read_suite,
                material_for(
                    protection.read_suite,
                    &derived.iv_client_to_server,
                    &derived.encryption_key_client_to_server,
                    Some(&derived.integrity_key_client_to_server),
                )?,
                protection.read_compression,
            )?;
            let write_protector = PacketProtector::new_with_compression(
                protection.write_suite,
                material_for(
                    protection.write_suite,
                    &derived.iv_server_to_client,
                    &derived.encryption_key_server_to_client,
                    Some(&derived.integrity_key_server_to_client),
                )?,
                protection.write_compression,
            )?;
            self.write_plain_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
            self.read_protector = Some(read_protector);
            self.write_protector = Some(write_protector);
            self.mlkem_completion = Some(crate::kex::mlkem768_x25519::HybridCompletion {
                exchange_hash: *prepared.exchange_hash(),
                session_id: *prepared.session_id(),
                shared_secret: prepared.shared_secret().clone(),
                host_key_blob: prepared.host_key_blob().to_vec(),
                signature_blob: signature.clone(),
            });
            self.phase = ServerHandshakePhase::ClientNewKeys;
            return Ok(());
        }
        let server_kex = self
            .server_kex
            .as_mut()
            .ok_or(HandshakeError::InvalidConfiguration)?;
        server_kex.accept_init(&payload)?;
        self.sequence.observe_inbound(SSH_MSG_KEX_ECDH_INIT)?;
        self.sequence.commit_inbound()?;

        let completion = server_kex.prepare_exchange()?.clone();
        let signature = self
            .config
            .signer
            .sign_exchange_hash(completion.exchange_hash())?;
        let reply = server_kex.reply_message(&signature)?;
        self.write_plain_packet(&reply, SSH_MSG_KEX_ECDH_REPLY)?;

        let protection = self
            .protection
            .ok_or(HandshakeError::InvalidConfiguration)?;
        let derived = derive_keys(
            completion.shared_secret(),
            completion.exchange_hash(),
            completion.session_id(),
            protection.lengths,
        )?;
        let read_protector = PacketProtector::new_with_compression(
            protection.read_suite,
            material_for(
                protection.read_suite,
                &derived.iv_client_to_server,
                &derived.encryption_key_client_to_server,
                Some(&derived.integrity_key_client_to_server),
            )?,
            protection.read_compression,
        )?;
        let write_protector = PacketProtector::new_with_compression(
            protection.write_suite,
            material_for(
                protection.write_suite,
                &derived.iv_server_to_client,
                &derived.encryption_key_server_to_client,
                Some(&derived.integrity_key_server_to_client),
            )?,
            protection.write_compression,
        )?;
        self.write_plain_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
        self.read_protector = Some(read_protector);
        self.write_protector = Some(write_protector);
        self.completion = Some(completion);
        self.phase = ServerHandshakePhase::ClientNewKeys;
        Ok(())
    }

    fn accept_client_newkeys(&mut self) -> Result<(), HandshakeError> {
        let payload = self.read_handshake_packet(false)?;
        if payload != [SSH_MSG_NEWKEYS] {
            return Err(TransportError::InvalidMessage.into());
        }
        self.sequence.observe_inbound(SSH_MSG_NEWKEYS)?;
        self.sequence.commit_inbound()?;
        self.sequence.complete_initial_kex()?;
        self.phase = ServerHandshakePhase::Complete;
        Ok(())
    }

    fn write_plain_packet(
        &mut self,
        payload: &[u8],
        expected_type: u8,
    ) -> Result<(), HandshakeError> {
        if payload.first() != Some(&expected_type) {
            return Err(TransportError::UnexpectedMessage.into());
        }
        if self.sequence.outbound_sequence() == u32::MAX {
            return Err(SequenceError::CounterExhausted.into());
        }
        self.sequence.classify_outbound(expected_type)?;
        let padding = random_unprotected_padding(payload.len())?;
        let packet = build_packet(payload, PLAIN_PACKET_BLOCK_SIZE, |target| {
            target.copy_from_slice(&padding);
        })?;
        self.stream.write_all(&packet)?;
        self.sequence.observe_outbound(expected_type)?;
        self.sequence.commit_outbound()?;
        Ok(())
    }

    fn read_handshake_packet(&mut self, guessed: bool) -> Result<Vec<u8>, HandshakeError> {
        loop {
            if self.sequence.inbound_sequence() == u32::MAX {
                return Err(SequenceError::CounterExhausted.into());
            }
            let payload = read_unprotected_packet(&mut self.stream)?;
            let message_type = payload
                .first()
                .copied()
                .ok_or(TransportError::InvalidMessage)?;
            let disposition = if guessed {
                self.sequence.classify_guessed_inbound(message_type)?
            } else {
                self.sequence.classify_inbound(message_type)?
            };
            match disposition {
                PacketDisposition::Ignorable => {
                    if guessed {
                        self.sequence.observe_guessed_inbound(message_type)?;
                    } else {
                        self.sequence.observe_inbound(message_type)?;
                    }
                    self.sequence.commit_inbound()?;
                }
                PacketDisposition::Disconnect => {
                    return Err(TransportError::PeerDisconnected.into());
                }
                PacketDisposition::Fatal => {
                    return Err(TransportError::UnexpectedMessage.into());
                }
                PacketDisposition::KexInit
                | PacketDisposition::KexMethod
                | PacketDisposition::NewKeys => return Ok(payload),
            }
        }
    }
}

/// A protected server transport that is awaiting the user-authentication state.
///
/// The transport owns the stream and packet sequence state. Construction is
/// possible only after both NEWKEYS messages, so protected packet methods
/// cannot be used with an unestablished connection. The current type never
/// marks itself authenticated; SSH-009 must consume it through the bounded
/// authentication packet boundary. A caller can start the bounded hybrid
/// rekey API with [`Self::begin_rekey`], while peer KEXINIT packets are
/// consumed by [`Self::read_auth_packet`] and [`Self::read_payload`] before
/// application dispatch.
pub struct ServerTransport<S> {
    stream: S,
    sequence: SequenceState,
    session_id: Vec<u8>,
    client_version: String,
    server_version: String,
    signer: Arc<Ed25519Signer>,
    host_key: Ed25519PublicKey,
    host_key_blob: Vec<u8>,
    initial_algorithm: String,
    rekey_proposal: KexInit,
    read_protector: Option<PacketProtector>,
    write_protector: Option<PacketProtector>,
    read_buffer: ProtectedReadBuffer,
    write_buffer: ProtectedWriteBuffer,
    established: bool,
    authenticated: bool,
    rekey: Option<ServerRekeyState>,
}

/// An explicit name for the server state returned before SSH-009 authentication.
pub type UnauthenticatedServerTransport<S> = ServerTransport<S>;

struct ServerRekeyState {
    local_kexinit: KexInit,
    local_kexinit_payload: Vec<u8>,
    peer_kexinit: Option<KexInit>,
    peer_kexinit_payload: Option<Vec<u8>>,
    peer_guessed: bool,
    peer_guess_is_correct: bool,
    protection: Option<ProtectionPlan>,
    derived: Option<DerivedKeys>,
    server_newkeys_sent: bool,
}

impl<S> fmt::Debug for ServerTransport<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTransport")
            .field("session_id", &self.session_id)
            .field("strict_kex", &self.sequence.strict_kex())
            .field("inbound_sequence", &self.sequence.inbound_sequence())
            .field("outbound_sequence", &self.sequence.outbound_sequence())
            .field("established", &self.established)
            .field("authenticated", &self.authenticated)
            .field("host_key", &self.host_key)
            .finish_non_exhaustive()
    }
}

impl<S> ServerTransport<S>
where
    S: Read + Write,
{
    /// Returns the first exchange hash retained as the connection session ID.
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the configured and cryptographically used host public key.
    #[must_use]
    pub const fn host_key(&self) -> &Ed25519PublicKey {
        &self.host_key
    }

    /// Returns whether protected packet exchange is available.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.established
    }

    /// Returns whether the connection has completed user authentication.
    ///
    /// SSH-008 always returns `false`; the state exists to make the boundary
    /// explicit for the later authentication module.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Returns whether the transport is explicitly awaiting authentication.
    #[must_use]
    pub const fn is_unauthenticated(&self) -> bool {
        !self.authenticated
    }

    /// Marks the transport as authenticated after the server has sent
    /// `SSH_MSG_USERAUTH_SUCCESS`.
    pub(crate) fn mark_authenticated(&mut self) {
        if self.established {
            self.authenticated = true;
        }
    }

    /// Returns whether OpenSSH strict-KEX was negotiated.
    #[must_use]
    pub const fn strict_kex(&self) -> bool {
        self.sequence.strict_kex()
    }

    /// Returns the next inbound packet sequence number without consuming it.
    #[must_use]
    pub const fn inbound_sequence(&self) -> u32 {
        self.sequence.inbound_sequence()
    }

    /// Returns the next outbound packet sequence number without consuming it.
    #[must_use]
    pub const fn outbound_sequence(&self) -> u32 {
        self.sequence.outbound_sequence()
    }

    /// Returns whether the one-time initial-KEX boundary has completed.
    #[must_use]
    pub const fn initial_kex_complete(&self) -> bool {
        self.sequence.initial_kex_complete()
    }

    /// Returns whether strict KEX reset both counters at the initial boundary.
    #[must_use]
    pub const fn strict_reset_applied(&self) -> bool {
        self.sequence.strict_reset_applied()
    }

    /// Returns whether the initial-KEX policy has entered a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.sequence.is_terminal()
    }

    /// Consumes the transport and returns its underlying byte stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Returns whether a post-establishment rekey is active.
    #[must_use]
    pub const fn rekey_active(&self) -> bool {
        self.sequence.rekey_active()
    }

    /// Returns the current post-establishment rekey phase.
    #[must_use]
    pub fn rekey_phase(&self) -> RekeyPhase {
        self.sequence.rekey_phase()
    }

    /// Returns whether the post-establishment rekey policy is terminal.
    #[must_use]
    pub const fn rekey_is_terminal(&self) -> bool {
        self.sequence.rekey_is_terminal()
    }

    /// Returns whether the post-establishment rekey policy is terminal.
    #[must_use]
    pub const fn rekey_terminal(&self) -> bool {
        self.rekey_is_terminal()
    }

    /// Returns whether the most recent post-establishment rekey completed.
    #[must_use]
    pub const fn rekey_complete(&self) -> bool {
        self.sequence.rekey_is_complete()
    }

    /// Returns whether strict KEX reset the requested direction at a rekey
    /// NEWKEYS boundary.
    #[must_use]
    pub const fn rekey_reset_applied(&self, direction: Direction) -> bool {
        self.sequence.rekey_reset_applied(direction)
    }

    /// Returns whether a rekey NEWKEYS sequence commit is pending.
    #[must_use]
    pub const fn rekey_reset_pending(&self, direction: Direction) -> bool {
        self.sequence.rekey_reset_pending(direction)
    }

    /// Starts a server-initiated `mlkem768x25519-sha256` rekey.
    ///
    /// The server KEXINIT is sent with the currently installed packet keys.
    /// The caller must then drive [`Self::advance_rekey`] or use
    /// [`Self::rekey`] to complete the exchange. Only a connection whose
    /// initial KEX selected the hybrid algorithm can use this bounded API.
    ///
    /// # Errors
    ///
    /// Returns a transport, negotiation, KEX, or sequence error. A reentrant
    /// or otherwise invalid transition terminally fails the rekey policy.
    pub fn begin_rekey(&mut self) -> Result<(), ServerTransportError> {
        self.begin_rekey_internal()
    }

    /// An explicit alias for [`Self::begin_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub fn start_rekey(&mut self) -> Result<(), ServerTransportError> {
        self.begin_rekey()
    }

    /// Advances an active rekey by one protected inbound packet.
    ///
    /// `Ok(true)` means that a KEXINIT, method message, or NEWKEYS packet was
    /// consumed. `Ok(false)` means that no rekey is active. A peer-initiated
    /// rekey is normally consumed by [`Self::read_auth_packet`] or
    /// [`Self::read_payload`] instead. Protected-packet bytes are retained by
    /// the transport, so a staged caller may retry after `WouldBlock` at any
    /// packet boundary or in the middle of a packet.
    ///
    /// # Errors
    ///
    /// Returns a typed transport, KEX, host-key, or sequence error. Malformed
    /// packets and invalid transitions terminally fail closed.
    pub fn advance_rekey(&mut self) -> Result<bool, ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        if self.rekey.is_none() {
            return Ok(false);
        }
        let result = self.advance_rekey_inner();
        match result {
            Ok(progress) => Ok(progress),
            Err(error) if is_would_block_error(&error) => Err(error),
            Err(error) => Err(self.fail_rekey_closed(error)),
        }
    }

    fn advance_rekey_inner(&mut self) -> Result<bool, ServerTransportError> {
        if self.resume_pending_rekey_write()? {
            return Ok(true);
        }
        if self
            .rekey
            .as_ref()
            .is_some_and(|state| state.derived.is_some() && !state.server_newkeys_sent)
        {
            self.send_server_newkeys()?;
            return Ok(true);
        }
        let payload = self.read_protected_packet_uncommitted()?;
        self.process_rekey_payload(&payload)?;
        Ok(true)
    }

    /// Starts and synchronously completes a server-initiated rekey.
    ///
    /// This convenience method is intended for a blocking stream. A staged
    /// caller should use [`Self::begin_rekey`] and [`Self::advance_rekey`];
    /// partial protected packets are retained across `WouldBlock`.
    ///
    /// # Errors
    ///
    /// Returns the first transport, KEX, host-key, or sequence failure. The
    /// transport is not returned in a partially switched state.
    pub fn rekey(&mut self) -> Result<(), ServerTransportError> {
        self.begin_rekey()?;
        while self.rekey.is_some() {
            self.advance_rekey()?;
        }
        Ok(())
    }

    /// An explicit alias for [`Self::rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::rekey`].
    pub fn perform_rekey(&mut self) -> Result<(), ServerTransportError> {
        self.rekey()
    }

    /// Reads one protected authentication-boundary packet.
    ///
    /// The only application message numbers returned before authentication are
    /// `SSH_MSG_SERVICE_REQUEST` (5) and `SSH_MSG_USERAUTH_REQUEST` (50). A
    /// peer KEXINIT and the complete rekey exchange are consumed internally
    /// before either authentication or channel dispatch can observe a packet.
    ///
    /// # Errors
    ///
    /// Returns [`ServerTransportError::NotEstablished`] before NEWKEYS,
    /// transport/protection errors for invalid input, rekey errors for a
    /// peer-initiated exchange, and [`ServerTransportError::UnauthenticatedMessage`]
    /// for a valid protected application packet whose type is not an
    /// authentication request.
    pub fn read_auth_packet(&mut self) -> Result<Vec<u8>, ServerTransportError> {
        self.read_dispatch_payload(false)
    }

    /// Reads one packet through the authentication or post-authentication
    /// boundary.
    ///
    /// Rekey packets always take precedence over application packets. Once a
    /// peer KEXINIT is accepted, this method consumes the KEX method and both
    /// NEWKEYS boundaries before returning an application packet.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_auth_packet`] before
    /// authentication, or a transport/protection/sequence error afterwards.
    pub fn read_payload(&mut self) -> Result<Vec<u8>, ServerTransportError> {
        self.read_dispatch_payload(self.authenticated)
    }

    /// Writes one nonempty protected packet for the server-side protocol.
    ///
    /// Application packets are refused while a rekey is active. KEXINIT, KEX
    /// method, and NEWKEYS packets are written only by the rekey state machine
    /// while the old keys are still installed.
    ///
    /// # Errors
    ///
    /// Returns [`ServerTransportError::NotEstablished`] before NEWKEYS,
    /// [`ServerTransportError::RekeyInProgress`] during rekey,
    /// [`ServerTransportError::Transport`] for framing, protection, I/O, or
    /// sequence failures, and rejects an empty payload as an invalid message.
    pub fn write_payload(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        if self.rekey.is_some() {
            return Err(ServerTransportError::RekeyInProgress);
        }
        let sequence = match self.write_protected_packet(payload) {
            Ok(sequence) => sequence,
            Err(error) if is_would_block_error(&error) => return Err(error),
            Err(error) => return Err(self.fail_protected_write(error)),
        };
        let committed = match self.sequence.commit_outbound() {
            Ok(committed) => committed,
            Err(error) => return Err(self.fail_protected_write(error.into())),
        };
        if committed != sequence {
            return Err(self.fail_protected_write(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            )));
        }
        if let Err(error) = self.write_buffer.acknowledge(sequence) {
            return Err(self.fail_protected_write(error.into()));
        }
        Ok(())
    }

    fn write_protected_packet(&mut self, payload: &[u8]) -> Result<u32, ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        if payload.is_empty() {
            return Err(TransportError::InvalidMessage.into());
        }
        if self.sequence.is_terminal() {
            return Err(SequenceError::Terminal.into());
        }
        let sequence = self.sequence.outbound_sequence();
        let protector = self
            .write_protector
            .as_mut()
            .ok_or(ServerTransportError::NotEstablished)?;
        write_protected_packet_buffered(
            &mut self.stream,
            &mut self.write_buffer,
            protector,
            sequence,
            payload,
            None,
        )
        .map_err(ServerTransportError::from)
    }

    fn write_protected_rekey_packet(
        &mut self,
        payload: &[u8],
        message_type: u8,
    ) -> Result<u32, ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        if payload.is_empty() {
            return Err(TransportError::InvalidMessage.into());
        }
        let sequence = self.sequence.outbound_sequence();
        let protector = self
            .write_protector
            .as_mut()
            .ok_or(ServerTransportError::NotEstablished)?;
        write_protected_packet_buffered(
            &mut self.stream,
            &mut self.write_buffer,
            protector,
            sequence,
            payload,
            Some(message_type),
        )
        .map_err(ServerTransportError::from)
    }

    /// Writes one protected authentication-boundary packet.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::write_payload`].
    pub fn write_auth_packet(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        self.write_payload(payload)
    }

    fn begin_rekey_internal(&mut self) -> Result<(), ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        if self.rekey.is_some() {
            if self.write_buffer.pending_message_type() == Some(SSH_MSG_KEXINIT) {
                let Some(payload) = self.write_buffer.pending_payload() else {
                    return Err(self.fail_rekey_closed(ServerTransportError::Transport(
                        TransportError::InvalidMessage,
                    )));
                };
                return match self.write_rekey_packet(&payload, SSH_MSG_KEXINIT) {
                    Ok(()) => Ok(()),
                    Err(error) if is_would_block_error(&error) => Err(error),
                    Err(error) => Err(self.fail_rekey_closed(error)),
                };
            }
            return Err(self.fail_rekey_closed(ServerTransportError::RekeyInProgress));
        }
        if let Err(error) = self.ensure_rekey_supported() {
            return Err(self.fail_rekey_closed(error));
        }
        let state = match self.new_rekey_state() {
            Ok(state) => state,
            Err(error) => return Err(self.fail_rekey_closed(error)),
        };
        if let Err(error) = self.sequence.begin_rekey() {
            return Err(error.into());
        }
        self.rekey = Some(state);
        let Some(state) = self.rekey.as_ref() else {
            return Err(self.fail_rekey_closed(ServerTransportError::RekeyInProgress));
        };
        let payload = state.local_kexinit_payload.clone();
        match self.write_rekey_packet(&payload, SSH_MSG_KEXINIT) {
            Ok(()) => Ok(()),
            Err(error) if is_would_block_error(&error) => Err(error),
            Err(error) => Err(self.fail_rekey_closed(error)),
        }
    }

    fn ensure_rekey_supported(&self) -> Result<(), ServerTransportError> {
        if self.initial_algorithm != KEX_MLKEM768X25519_SHA256 {
            return Err(ServerTransportError::UnsupportedAlgorithm);
        }
        if self.session_id.len() != 32 {
            return Err(ServerTransportError::Kex(KexError::InvalidSessionId));
        }
        if self.rekey_proposal.reserved != 0 || self.rekey_proposal.first_kex_packet_follows {
            return Err(ServerTransportError::Kex(KexError::InvalidProposal));
        }
        if !self
            .rekey_proposal
            .kex_algorithms
            .iter()
            .any(|name| name == KEX_MLKEM768X25519_SHA256)
        {
            return Err(ServerTransportError::UnsupportedAlgorithm);
        }
        let current_host_key_blob = self.signer.public_key_blob()?;
        if current_host_key_blob != self.host_key_blob {
            return Err(ServerTransportError::Kex(KexError::HostKeyMismatch));
        }
        Ok(())
    }

    fn new_rekey_state(&self) -> Result<ServerRekeyState, ServerTransportError> {
        let mut local_kexinit = self.rekey_proposal.clone();
        local_kexinit.kex_algorithms = vec![KEX_MLKEM768X25519_SHA256.to_owned()];
        local_kexinit.first_kex_packet_follows = false;
        local_kexinit.reserved = 0;
        getrandom::fill(&mut local_kexinit.cookie)
            .map_err(|_error| ServerTransportError::Transport(TransportError::EntropyFailure))?;
        let local_kexinit_payload = local_kexinit
            .encode()
            .map_err(|error| ServerTransportError::Kex(KexError::Wire(error)))?;
        Ok(ServerRekeyState {
            local_kexinit,
            local_kexinit_payload,
            peer_kexinit: None,
            peer_kexinit_payload: None,
            peer_guessed: false,
            peer_guess_is_correct: true,
            protection: None,
            derived: None,
            server_newkeys_sent: false,
        })
    }

    fn read_dispatch_payload(
        &mut self,
        allow_application: bool,
    ) -> Result<Vec<u8>, ServerTransportError> {
        if !self.established {
            return Err(ServerTransportError::NotEstablished);
        }
        loop {
            if self.rekey.is_some() {
                match self.resume_pending_rekey_write() {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) if is_would_block_error(&error) => return Err(error),
                    Err(error) => return Err(self.fail_rekey_closed(error)),
                }
            }
            let payload = match self.read_protected_packet_uncommitted() {
                Ok(payload) => payload,
                Err(error) if is_would_block_error(&error) => return Err(error),
                Err(error) if self.rekey.is_some() => {
                    return Err(self.fail_rekey_closed(error));
                }
                Err(error) => return Err(error),
            };
            let Some(message_type) = payload.first().copied() else {
                let error = ServerTransportError::Transport(TransportError::InvalidMessage);
                return Err(if self.rekey.is_some() {
                    self.fail_rekey_closed(error)
                } else {
                    error
                });
            };
            if message_type == SSH_MSG_KEXINIT {
                match self.accept_rekey_kexinit(&payload) {
                    Ok(()) => {}
                    Err(error) if is_would_block_error(&error) => return Err(error),
                    Err(error) => return Err(self.fail_rekey_closed(error)),
                }
                continue;
            }
            if self.rekey.is_some() {
                match self.process_rekey_payload(&payload) {
                    Ok(()) => {}
                    Err(error) if is_would_block_error(&error) => return Err(error),
                    Err(error) => return Err(self.fail_rekey_closed(error)),
                }
                continue;
            }
            if (SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST).contains(&message_type)
                || message_type == SSH_MSG_NEWKEYS
            {
                return Err(self.fail_rekey_closed(TransportError::UnexpectedMessage.into()));
            }
            if !allow_application
                && !matches!(
                    message_type,
                    SSH_MSG_SERVICE_REQUEST | SSH_MSG_USERAUTH_REQUEST
                )
            {
                self.established = false;
                let _ = self.sequence.fail_rekey();
                return Err(ServerTransportError::UnauthenticatedMessage);
            }
            self.sequence.commit_inbound()?;
            return Ok(payload);
        }
    }

    fn process_rekey_payload(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        let message_type = payload
            .first()
            .copied()
            .ok_or(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ))?;
        match message_type {
            SSH_MSG_KEXINIT => self.accept_rekey_kexinit(payload),
            SSH_MSG_KEX_ECDH_INIT => self.accept_rekey_method(payload),
            SSH_MSG_NEWKEYS => self.accept_rekey_newkeys(payload),
            2..=4 => {
                let disposition = self.sequence.observe_rekey(message_type)?;
                if disposition != PacketDisposition::Ignorable {
                    return Err(ServerTransportError::Transport(
                        TransportError::UnexpectedMessage,
                    ));
                }
                self.sequence.commit_inbound()?;
                Ok(())
            }
            1 => {
                self.rekey = None;
                self.write_buffer.abort();
                self.established = false;
                let _ = self.sequence.fail_rekey();
                Err(ServerTransportError::Transport(
                    TransportError::PeerDisconnected,
                ))
            }
            _ => Err(ServerTransportError::Transport(
                TransportError::UnexpectedMessage,
            )),
        }
    }

    fn accept_rekey_kexinit(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        let peer_kexinit = KexInit::decode(payload)
            .map_err(|error| ServerTransportError::Kex(KexError::Wire(error)))?;
        if peer_kexinit.reserved != 0 {
            return Err(ServerTransportError::Kex(KexError::InvalidProposal));
        }
        if !peer_kexinit
            .kex_algorithms
            .iter()
            .any(|name| name == KEX_MLKEM768X25519_SHA256)
        {
            return Err(ServerTransportError::UnsupportedAlgorithm);
        }
        let peer_guessed = peer_kexinit.first_kex_packet_follows;
        let mut send_local_kexinit = false;
        if self.rekey.is_none() {
            self.ensure_rekey_supported()?;
            let state = self.new_rekey_state()?;
            self.sequence.begin_rekey()?;
            self.rekey = Some(state);
            send_local_kexinit = true;
        }
        let (algorithms, local_payload, peer_guess_is_correct) = {
            let state = self
                .rekey
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            if state.peer_kexinit.is_some() {
                return Err(ServerTransportError::Transport(
                    TransportError::UnexpectedMessage,
                ));
            }
            let algorithms = peer_kexinit.negotiate(&state.local_kexinit)?;
            if algorithms.kex != KEX_MLKEM768X25519_SHA256 {
                return Err(ServerTransportError::UnsupportedAlgorithm);
            }
            let peer_guess_is_correct =
                !peer_guessed || kex_guess_matches(&peer_kexinit, &algorithms);
            (
                algorithms,
                state.local_kexinit_payload.clone(),
                peer_guess_is_correct,
            )
        };
        let protection = ProtectionPlan::from_algorithms(&algorithms)?;
        self.sequence
            .observe_rekey_kexinit(Direction::Inbound, peer_guessed)?;
        self.sequence.commit_inbound()?;
        let state = self
            .rekey
            .as_mut()
            .ok_or(ServerTransportError::RekeyInProgress)?;
        state.peer_kexinit = Some(peer_kexinit);
        state.peer_kexinit_payload = Some(payload.to_vec());
        state.peer_guessed = peer_guessed;
        state.peer_guess_is_correct = peer_guess_is_correct;
        state.protection = Some(protection);
        if send_local_kexinit {
            self.write_rekey_packet(&local_payload, SSH_MSG_KEXINIT)?;
        }
        Ok(())
    }

    fn accept_rekey_method(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        if payload.is_empty() || payload[0] != SSH_MSG_KEX_ECDH_INIT {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        }
        let discard_guess = self
            .rekey
            .as_ref()
            .is_some_and(|state| state.peer_guessed && !state.peer_guess_is_correct);
        if discard_guess {
            let disposition = self.sequence.observe_rekey_observation(
                Direction::Inbound,
                PacketObservation::guessed(SSH_MSG_KEX_ECDH_INIT),
            )?;
            if disposition != PacketDisposition::Ignorable {
                return Err(ServerTransportError::Transport(
                    TransportError::UnexpectedMessage,
                ));
            }
            self.sequence.commit_inbound()?;
            self.rekey
                .as_mut()
                .ok_or(ServerTransportError::RekeyInProgress)?
                .peer_guessed = false;
            return Ok(());
        }
        let (client_kexinit, server_kexinit, protection, peer_guessed) = {
            let state = self
                .rekey
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            let client_kexinit = state
                .peer_kexinit_payload
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?
                .clone();
            let server_kexinit = state.local_kexinit_payload.clone();
            let protection = state
                .protection
                .ok_or(ServerTransportError::RekeyInProgress)?;
            (
                client_kexinit,
                server_kexinit,
                protection,
                state.peer_guessed && !state.peer_guess_is_correct,
            )
        };
        let context = KexContext::new(
            &self.client_version,
            &self.server_version,
            client_kexinit,
            server_kexinit,
            KEX_MLKEM768X25519_SHA256,
        )?;
        let mut server_kex = MlKemServerKex::new(context, &self.host_key_blob)?;
        let prepared = server_kex.accept_init(payload)?;
        let derived = derive_keys(
            prepared.shared_secret(),
            prepared.exchange_hash(),
            &self.session_id,
            protection.lengths,
        )?;
        let signature = self.signer.sign_exchange_hash(prepared.exchange_hash())?;
        let reply = prepared.reply_message(&signature)?;
        self.observe_inbound_rekey_method(peer_guessed)?;
        self.sequence.commit_inbound()?;
        {
            let state = self
                .rekey
                .as_mut()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            if state.derived.is_some() {
                return Err(ServerTransportError::Transport(
                    TransportError::UnexpectedMessage,
                ));
            }
            state.peer_guessed = false;
            state.derived = Some(derived);
            state.server_newkeys_sent = false;
        }
        self.write_rekey_packet(&reply, SSH_MSG_KEX_ECDH_REPLY)?;
        self.send_server_newkeys()
    }

    fn send_server_newkeys(&mut self) -> Result<(), ServerTransportError> {
        let (write_material, protection) = {
            let state = self
                .rekey
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            if state.server_newkeys_sent {
                return Ok(());
            }
            let protection = state
                .protection
                .ok_or(ServerTransportError::RekeyInProgress)?;
            let derived = state
                .derived
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            // The material is built here, inside the borrow of the rekey state,
            // so the one copy of these bytes is the `PacketKeyMaterial` the
            // protector takes. It used to be a `DerivedKeys` clone that was then
            // copied again by `material_for` and dropped unwiped.
            let write_material = material_for(
                protection.write_suite,
                &derived.iv_server_to_client,
                &derived.encryption_key_server_to_client,
                Some(&derived.integrity_key_server_to_client),
            )?;
            (write_material, protection)
        };
        self.write_rekey_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
        if self.write_buffer.is_pending() {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        }
        self.install_rekey_write_protector(write_material, protection)?;
        self.rekey
            .as_mut()
            .ok_or(ServerTransportError::RekeyInProgress)?
            .server_newkeys_sent = true;
        Ok(())
    }

    fn resume_pending_rekey_write(&mut self) -> Result<bool, ServerTransportError> {
        if !self.write_buffer.is_pending() {
            return Ok(false);
        }
        let Some(message_type) = self.write_buffer.pending_message_type() else {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        };
        // The payload is fetched inside the arm that needs it rather than
        // before the match. Only a rekey message can be resumed here, so
        // copying the entry out on the way to rejecting it would hand a
        // `Vec<u8>` of whatever was pending — an authentication request whose
        // write blocked part-way, say — to a path that drops it un-wiped.
        match message_type {
            SSH_MSG_KEXINIT => {
                let payload =
                    self.write_buffer
                        .pending_payload()
                        .ok_or(ServerTransportError::Transport(
                            TransportError::InvalidMessage,
                        ))?;
                self.write_rekey_packet(&payload, SSH_MSG_KEXINIT)?;
            }
            SSH_MSG_KEX_ECDH_REPLY => {
                let payload =
                    self.write_buffer
                        .pending_payload()
                        .ok_or(ServerTransportError::Transport(
                            TransportError::InvalidMessage,
                        ))?;
                self.write_rekey_packet(&payload, SSH_MSG_KEX_ECDH_REPLY)?;
                self.send_server_newkeys()?;
            }
            SSH_MSG_NEWKEYS => {
                self.send_server_newkeys()?;
            }
            _ => {
                return Err(ServerTransportError::Transport(
                    TransportError::InvalidMessage,
                ));
            }
        }
        Ok(true)
    }

    fn observe_inbound_rekey_method(
        &mut self,
        peer_guessed: bool,
    ) -> Result<(), ServerTransportError> {
        if peer_guessed {
            let disposition = self.sequence.observe_rekey_observation(
                Direction::Inbound,
                PacketObservation::guessed(SSH_MSG_KEX_ECDH_INIT),
            )?;
            if disposition != PacketDisposition::Ignorable {
                return Err(ServerTransportError::Transport(
                    TransportError::UnexpectedMessage,
                ));
            }
        }
        self.sequence.observe_rekey(SSH_MSG_KEX_ECDH_INIT)?;
        Ok(())
    }

    fn accept_rekey_newkeys(&mut self, payload: &[u8]) -> Result<(), ServerTransportError> {
        if payload != [SSH_MSG_NEWKEYS] {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        }
        if self.write_buffer.is_pending() {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        }
        {
            let state = self
                .rekey
                .as_ref()
                .ok_or(ServerTransportError::RekeyInProgress)?;
            if !state.server_newkeys_sent || state.derived.is_none() {
                return Err(ServerTransportError::Transport(
                    TransportError::UnexpectedMessage,
                ));
            }
        }
        self.sequence.observe_rekey(SSH_MSG_NEWKEYS)?;
        self.sequence.commit_inbound()?;
        self.sequence.complete_rekey_exchange()?;
        let state = self
            .rekey
            .take()
            .ok_or(ServerTransportError::RekeyInProgress)?;
        let derived = state.derived.ok_or(ServerTransportError::RekeyInProgress)?;
        let protection = state
            .protection
            .ok_or(ServerTransportError::RekeyInProgress)?;
        // `state` was taken out of the transport, so this is the only copy of
        // the rekeyed keys and it is wiped as this function returns. The read
        // protector gets its own directional material.
        let read_material = material_for(
            protection.read_suite,
            &derived.iv_client_to_server,
            &derived.encryption_key_client_to_server,
            Some(&derived.integrity_key_client_to_server),
        )?;
        drop(derived);
        if let Err(error) = self.install_rekey_read_protector(read_material, protection) {
            return Err(self.fail_rekey_closed(error));
        }
        Ok(())
    }

    fn install_rekey_write_protector(
        &mut self,
        write_material: PacketKeyMaterial,
        protection: ProtectionPlan,
    ) -> Result<(), ServerTransportError> {
        let write_protector = self
            .write_protector
            .as_mut()
            .ok_or(ServerTransportError::NotEstablished)?;
        write_protector.rekey_with_compression(
            protection.write_suite,
            write_material,
            protection.write_compression,
        )?;
        Ok(())
    }

    fn install_rekey_read_protector(
        &mut self,
        read_material: PacketKeyMaterial,
        protection: ProtectionPlan,
    ) -> Result<(), ServerTransportError> {
        let read_protector = self
            .read_protector
            .as_mut()
            .ok_or(ServerTransportError::NotEstablished)?;
        read_protector.rekey_with_compression(
            protection.read_suite,
            read_material,
            protection.read_compression,
        )?;
        Ok(())
    }

    fn write_rekey_packet(
        &mut self,
        payload: &[u8],
        expected_type: u8,
    ) -> Result<(), ServerTransportError> {
        if payload.first() != Some(&expected_type) {
            return Err(ServerTransportError::Transport(
                TransportError::UnexpectedMessage,
            ));
        }
        self.sequence.classify_rekey_outbound(expected_type)?;
        let sequence = self.write_protected_rekey_packet(payload, expected_type)?;
        self.sequence.observe_rekey_outbound(expected_type)?;
        let committed = self.sequence.commit_outbound()?;
        if committed != sequence {
            return Err(ServerTransportError::Transport(
                TransportError::InvalidMessage,
            ));
        }
        self.write_buffer.acknowledge(sequence)?;
        Ok(())
    }

    fn read_protected_packet_uncommitted(&mut self) -> Result<Vec<u8>, ServerTransportError> {
        if self.sequence.is_terminal() {
            return Err(SequenceError::Terminal.into());
        }
        let protector = self
            .read_protector
            .as_mut()
            .ok_or(ServerTransportError::NotEstablished)?;
        let sequence = self.sequence.inbound_sequence();
        if sequence == u32::MAX {
            return Err(SequenceError::CounterExhausted.into());
        }
        read_protected_packet_buffered(&mut self.stream, &mut self.read_buffer, protector, sequence)
            .map_err(ServerTransportError::from)
    }

    fn fail_protected_write(&mut self, error: ServerTransportError) -> ServerTransportError {
        self.write_buffer.abort();
        self.established = false;
        error
    }

    fn fail_rekey_closed(&mut self, error: ServerTransportError) -> ServerTransportError {
        self.rekey = None;
        self.write_buffer.abort();
        self.established = false;
        let _ = self.sequence.fail_rekey();
        error
    }
}

struct BoxedKeyExchange(Box<dyn KeyExchange>);

impl KeyExchange for BoxedKeyExchange {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn generate_ephemeral(&self) -> Result<EphemeralKey, KexError> {
        self.0.generate_ephemeral()
    }

    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        self.0.public_key(ephemeral)
    }

    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, KexError> {
        self.0.encode_init_message(ephemeral)
    }

    fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, KexError> {
        self.0.decode_init_message(input)
    }

    fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, KexError> {
        self.0
            .encode_reply_message(server_public_key, host_key_blob, signature_blob)
    }

    fn decode_reply_message(&self, input: &[u8]) -> Result<KexReply, KexError> {
        self.0.decode_reply_message(input)
    }

    fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, KexError> {
        self.0.agree(ephemeral, peer_public_key)
    }
}

#[derive(Clone, Copy)]
struct ProtectionPlan {
    read_suite: PacketSuite,
    write_suite: PacketSuite,
    read_compression: CompressionAlgorithm,
    write_compression: CompressionAlgorithm,
    lengths: DerivationLengths,
}

impl ProtectionPlan {
    fn from_algorithms(
        algorithms: &crate::msg::kexinit::NegotiatedAlgorithms,
    ) -> Result<Self, HandshakeError> {
        if !SUPPORTED_HOST_KEY_ALGORITHMS.contains(&algorithms.host_key.as_str()) {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let read_compression =
            CompressionAlgorithm::from_name(&algorithms.compression_client_to_server)
                .ok_or(HandshakeError::UnsupportedAlgorithm)?;
        let write_compression =
            CompressionAlgorithm::from_name(&algorithms.compression_server_to_client)
                .ok_or(HandshakeError::UnsupportedAlgorithm)?;
        if (!is_chacha_cipher(&algorithms.cipher_client_to_server)
            && !SUPPORTED_MAC_ALGORITHMS.contains(&algorithms.mac_client_to_server.as_str()))
            || (!is_chacha_cipher(&algorithms.cipher_server_to_client)
                && !SUPPORTED_MAC_ALGORITHMS.contains(&algorithms.mac_server_to_client.as_str()))
        {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let read_suite = suite_for(
            &algorithms.cipher_client_to_server,
            &algorithms.mac_client_to_server,
        )?;
        let write_suite = suite_for(
            &algorithms.cipher_server_to_client,
            &algorithms.mac_server_to_client,
        )?;
        let lengths = DerivationLengths {
            a: iv_length(read_suite),
            b: iv_length(write_suite),
            c: encryption_key_length(read_suite)?,
            d: encryption_key_length(write_suite)?,
            e: integrity_key_length(read_suite),
            f: integrity_key_length(write_suite),
        };
        Ok(Self {
            read_suite,
            write_suite,
            read_compression,
            write_compression,
            lengths,
        })
    }
}

fn supported_server_kexinit(cookie: [u8; 16]) -> KexInit {
    KexInit::from_lists(
        cookie,
        vec![
            KEX_MLKEM768X25519_SHA256.to_owned(),
            CURVE25519_SHA256.to_owned(),
            CURVE25519_SHA256_LIBSSH.to_owned(),
            ECDH_SHA2_NISTP256.to_owned(),
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512.to_owned(),
            KEX_STRICT_S_V00_OPENSSH.to_owned(),
        ],
        vec![HOST_KEY_SSH_ED25519.to_owned()],
        vec![
            CHACHA20_POLY1305_OPENSSH_NAME.to_owned(),
            AES128_CTR.to_owned(),
            AES256_CTR.to_owned(),
            AES128_GCM_OPENSSH.to_owned(),
            AES256_GCM_OPENSSH.to_owned(),
        ],
        vec![
            CHACHA20_POLY1305_OPENSSH_NAME.to_owned(),
            AES128_CTR.to_owned(),
            AES256_CTR.to_owned(),
            AES128_GCM_OPENSSH.to_owned(),
            AES256_GCM_OPENSSH.to_owned(),
        ],
        vec![
            HMAC_SHA2_256.to_owned(),
            HMAC_SHA2_512.to_owned(),
            HMAC_SHA2_256_ETM_OPENSSH.to_owned(),
            HMAC_SHA2_512_ETM_OPENSSH.to_owned(),
        ],
        vec![
            HMAC_SHA2_256.to_owned(),
            HMAC_SHA2_512.to_owned(),
            HMAC_SHA2_256_ETM_OPENSSH.to_owned(),
            HMAC_SHA2_512_ETM_OPENSSH.to_owned(),
        ],
        vec![
            COMPRESSION_NONE.to_owned(),
            COMPRESSION_ZLIB_OPENSSH.to_owned(),
        ],
        vec![
            COMPRESSION_NONE.to_owned(),
            COMPRESSION_ZLIB_OPENSSH.to_owned(),
        ],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

fn mechanism_for(name: &str) -> Result<BoxedKeyExchange, HandshakeError> {
    match name {
        CURVE25519_SHA256 => Ok(BoxedKeyExchange(Box::new(Curve25519::standard()))),
        CURVE25519_SHA256_LIBSSH => Ok(BoxedKeyExchange(Box::new(Curve25519::libssh()))),
        ECDH_SHA2_NISTP256 => Ok(BoxedKeyExchange(Box::new(EcdhP256::new()))),
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512 => Ok(BoxedKeyExchange(Box::new(DhGroup16::new()))),
        _ => Err(HandshakeError::UnsupportedAlgorithm),
    }
}

fn is_chacha_cipher(cipher: &str) -> bool {
    cipher == CHACHA20_POLY1305_OPENSSH_NAME
}

fn suite_for(cipher: &str, mac: &str) -> Result<PacketSuite, HandshakeError> {
    if matches!(
        cipher,
        AES128_GCM_OPENSSH | AES256_GCM_OPENSSH | CHACHA20_POLY1305_OPENSSH_NAME
    ) {
        return Ok(PacketSuite::new(cipher, None)?);
    }
    Ok(PacketSuite::new(cipher, Some(mac))?)
}

fn iv_length(suite: PacketSuite) -> usize {
    match suite.encryption_name() {
        // OpenSSH derives no IV for ChaCha; the protector receives two zero
        // words through the existing key-material API instead.
        CHACHA20_POLY1305_OPENSSH_NAME => 0,
        _ if suite.integrity_name().is_none() => GCM_IV_LENGTH,
        _ => CTR_IV_LENGTH,
    }
}

fn encryption_key_length(suite: PacketSuite) -> Result<usize, HandshakeError> {
    match suite.encryption_name() {
        AES128_CTR | AES128_GCM_OPENSSH => Ok(AES128_KEY_LENGTH),
        AES256_CTR | AES256_GCM_OPENSSH => Ok(AES256_KEY_LENGTH),
        CHACHA20_POLY1305_OPENSSH_NAME => Ok(CHACHA_KEY_LENGTH),
        _ => Err(HandshakeError::UnsupportedAlgorithm),
    }
}

fn integrity_key_length(suite: PacketSuite) -> usize {
    match suite.integrity_name() {
        None => 0,
        Some(name) if name.contains("sha2-512") => SHA512_INTEGRITY_LENGTH,
        Some(_) => SHA256_INTEGRITY_LENGTH,
    }
}

fn material_for(
    suite: PacketSuite,
    iv: &[u8],
    encryption_key: &[u8],
    integrity_key: Option<&[u8]>,
) -> Result<PacketKeyMaterial, HandshakeError> {
    if suite.encryption_name() == CHACHA20_POLY1305_OPENSSH_NAME {
        return Ok(PacketKeyMaterial::new(
            &[0; CHACHA_IV_LENGTH],
            encryption_key,
            None,
        ));
    }
    if suite.integrity_name().is_none() {
        return Ok(PacketKeyMaterial::gcm(iv, encryption_key));
    }
    let integrity_key = integrity_key
        .filter(|key| !key.is_empty())
        .ok_or(HandshakeError::UnsupportedAlgorithm)?;
    Ok(PacketKeyMaterial::hmac(iv, encryption_key, integrity_key))
}

fn is_would_block_error(error: &ServerTransportError) -> bool {
    matches!(
        error,
        ServerTransportError::Transport(TransportError::Io(error))
            if error.kind() == io::ErrorKind::WouldBlock
    )
}

fn validate_config(config: &ServerConfig) -> Result<(), HandshakeError> {
    let version_length = config.server_version.len().saturating_add(2);
    if !config.server_version.starts_with("SSH-2.0-")
        || config.server_version.is_empty()
        || version_length > crate::transport::MAX_IDENTIFICATION_LINE
        || !config.server_version.is_ascii()
        || config
            .server_version
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(HandshakeError::InvalidConfiguration);
    }
    if config.kexinit.reserved != 0 || config.kexinit.first_kex_packet_follows {
        return Err(HandshakeError::Kex(KexError::InvalidProposal));
    }
    Ok(())
}
