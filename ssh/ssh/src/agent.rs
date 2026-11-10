//! A bounded client for the OpenSSH agent identity and signing protocol.
//!
//! This module implements only identity enumeration and signature requests. It
//! does not select a socket from the environment, manage agent keys, or create
//! a timeout thread. Unix socket connections created by [`connect_unix`] apply
//! [`DEFAULT_TIMEOUT`] to the stream, while callers that supply another
//! [`Read`] + [`Write`] transport remain responsible for its I/O policy.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use neotales_ssh::{Error as WireError, Reader, Writer};

/// The largest accepted or emitted OpenSSH agent frame body, in bytes.
///
/// A frame body contains the message type and payload, but not its four-byte
/// length prefix.
pub const MAX_FRAME_SIZE: usize = 1_048_576;

/// The read and write timeout applied by [`connect_unix`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Message number for a generic agent failure response.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// Message number for a request to enumerate available identities.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Message number for an identity-enumeration response.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Message number for a request to sign raw data.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Message number for a signature response.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Signature flag requesting RSA with SHA-256.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;

/// An identity advertised by an SSH agent.
///
/// Both fields retain their wire representation. In particular, `comment` is
/// raw bytes and is not required to be UTF-8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    /// The SSH public-key blob identifying the key.
    pub key_blob: Vec<u8>,
    /// The caller-supplied comment associated with the key.
    pub comment: Vec<u8>,
}

impl AgentIdentity {
    /// Returns the SSH public-key blob.
    #[must_use]
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    /// Returns the raw identity comment.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }
}

/// An error produced while talking to an SSH agent.
///
/// Protocol and framing errors contain no wire payload. The generic client
/// performs no timing operation of its own; timeout failures therefore appear
/// as [`AgentError::Io`] from the caller's transport.
#[derive(Debug)]
pub enum AgentError {
    /// The underlying transport returned an I/O error.
    Io(io::Error),
    /// An SSH string or integer was malformed.
    Wire(WireError),
    /// A frame or complete response message was structurally invalid.
    InvalidFrame,
    /// A frame exceeded [`MAX_FRAME_SIZE`].
    FrameTooLarge,
    /// The agent returned a message other than the expected response.
    UnexpectedMessage(u8),
    /// The agent returned `SSH_AGENT_FAILURE`.
    AgentFailure,
    /// The default signing path does not support the key's algorithm.
    UnsupportedKey,
    /// Unix-domain agent sockets are unavailable on this platform.
    UnsupportedPlatform,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("SSH agent transport failed"),
            Self::Wire(error) => write!(formatter, "SSH agent wire error: {error}"),
            Self::InvalidFrame => formatter.write_str("SSH agent frame is malformed"),
            Self::FrameTooLarge => formatter.write_str("SSH agent frame exceeds the size limit"),
            Self::UnexpectedMessage(message) => {
                write!(formatter, "SSH agent returned unexpected message {message}")
            }
            Self::AgentFailure => formatter.write_str("SSH agent rejected the request"),
            Self::UnsupportedKey => formatter.write_str("SSH agent key algorithm is unsupported"),
            Self::UnsupportedPlatform => {
                formatter.write_str("SSH agent Unix-domain sockets are unsupported")
            }
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::InvalidFrame
            | Self::FrameTooLarge
            | Self::UnexpectedMessage(_)
            | Self::AgentFailure
            | Self::UnsupportedKey
            | Self::UnsupportedPlatform => None,
        }
    }
}

impl From<io::Error> for AgentError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for AgentError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// A sequential SSH agent protocol client over any byte transport.
///
/// Each request writes one complete frame and waits for exactly one complete
/// response frame. The client itself has no timer; callers using a generic
/// transport must enforce their own read/write budget.
#[derive(Debug)]
pub struct AgentClient<T> {
    transport: T,
}

impl<T> AgentClient<T> {
    /// Wraps an already-open byte transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns the wrapped transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T> AgentClient<T>
where
    T: Read + Write,
{
    /// Requests the identities currently available from the agent.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::FrameTooLarge`] for an invalid outbound or
    /// inbound frame size, [`AgentError::Wire`] for a malformed SSH value,
    /// [`AgentError::AgentFailure`] for message 5, and
    /// [`AgentError::UnexpectedMessage`] for any other unexpected response.
    /// Transport failures are returned as [`AgentError::Io`].
    pub fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        self.send_frame(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let payload = self.read_frame()?;
        let message = payload.first().copied().ok_or(AgentError::InvalidFrame)?;
        if message == SSH_AGENT_FAILURE {
            return Err(AgentError::AgentFailure);
        }
        if message != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(AgentError::UnexpectedMessage(message));
        }

        let mut reader = Reader::new(&payload[1..]);
        let count = reader.read_uint32()?;
        let mut identities = Vec::new();
        for _ in 0..count {
            identities.push(AgentIdentity {
                key_blob: reader.read_string_bytes()?,
                comment: reader.read_string_bytes()?,
            });
        }
        if !reader.is_empty() {
            return Err(AgentError::InvalidFrame);
        }
        Ok(identities)
    }

    /// Alias for [`Self::identities`] that emphasizes the request operation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::identities`].
    pub fn list_identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        self.identities()
    }

    /// Requests a signature using the flags implied by the key blob type.
    ///
    /// The first SSH string in `key_blob` must be exactly `ssh-ed25519`,
    /// `ssh-rsa`, or `ecdsa-sha2-nistp256`. Ed25519 and ECDSA use flag 0
    /// because their signature format identifier is the key type name; RSA
    /// requests SHA-256 with flag 2. The data is sent unchanged; this client
    /// does not hash it.
    ///
    /// The ECDSA case is not an inference about what an agent would accept. It
    /// is what OpenSSH does: `agent_decode_alg` in `ssh-agent.c` maps
    /// `SSH_AGENT_RSA_SHA2_256` to `rsa-sha2-256` and returns null for every
    /// other key type, which leaves a non-RSA key signing under its own name.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::UnsupportedKey`] for another key algorithm,
    /// [`AgentError::Wire`] for a malformed key algorithm string, or the same
    /// framing, response, and transport errors as [`Self::identities`].
    pub fn sign(&mut self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        let flags = default_signing_flags(key_blob)?;
        self.sign_with_flags(key_blob, data, flags)
    }

    /// Requests a signature with an explicit OpenSSH agent flags word.
    ///
    /// This lower-level path does not inspect the key algorithm. The caller is
    /// responsible for selecting a flag understood by the agent.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Wire`] for malformed SSH values,
    /// [`AgentError::FrameTooLarge`] when the request or response is oversized,
    /// [`AgentError::AgentFailure`] for message 5, and
    /// [`AgentError::UnexpectedMessage`] for any other unexpected response.
    /// Transport failures are returned as [`AgentError::Io`].
    pub fn sign_with_flags(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError> {
        let mut request = Writer::new();
        request.write_byte(SSH_AGENTC_SIGN_REQUEST);
        request.write_string(&key_blob)?;
        request.write_string(&data)?;
        request.write_uint32(flags);
        self.send_frame(request.as_bytes())?;

        let payload = self.read_frame()?;
        let message = payload.first().copied().ok_or(AgentError::InvalidFrame)?;
        if message == SSH_AGENT_FAILURE {
            return Err(AgentError::AgentFailure);
        }
        if message != SSH_AGENT_SIGN_RESPONSE {
            return Err(AgentError::UnexpectedMessage(message));
        }

        let mut reader = Reader::new(&payload[1..]);
        let signature = reader.read_string_bytes()?;
        if !reader.is_empty() {
            return Err(AgentError::InvalidFrame);
        }
        Ok(signature)
    }

    fn send_frame(&mut self, payload: &[u8]) -> Result<(), AgentError> {
        if payload.is_empty() {
            return Err(AgentError::InvalidFrame);
        }
        if payload.len() > MAX_FRAME_SIZE {
            return Err(AgentError::FrameTooLarge);
        }
        let length = u32::try_from(payload.len()).map_err(|_| AgentError::FrameTooLarge)?;
        self.transport.write_all(&length.to_be_bytes())?;
        self.transport.write_all(payload)?;
        Ok(())
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, AgentError> {
        let mut encoded_length = [0_u8; 4];
        self.transport.read_exact(&mut encoded_length)?;
        let length = u32::from_be_bytes(encoded_length);
        if length == 0 {
            return Err(AgentError::InvalidFrame);
        }
        let length = usize::try_from(length).map_err(|_| AgentError::FrameTooLarge)?;
        if length > MAX_FRAME_SIZE {
            return Err(AgentError::FrameTooLarge);
        }
        let mut payload = vec![0_u8; length];
        self.transport.read_exact(&mut payload)?;
        Ok(payload)
    }
}

/// Opens a Unix-domain SSH agent socket and applies the default I/O timeout.
///
/// The caller supplies the socket path explicitly. This function never reads
/// an environment-selected socket path and does not implement Windows named pipes.
///
/// # Errors
///
/// Returns [`AgentError::Io`] if the socket cannot be opened or either
/// [`DEFAULT_TIMEOUT`] cannot be configured.
#[cfg(unix)]
pub fn connect_unix(
    path: impl AsRef<Path>,
) -> Result<AgentClient<std::os::unix::net::UnixStream>, AgentError> {
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT))?;
    Ok(AgentClient::new(stream))
}

/// Reports that Unix-domain SSH agent sockets are unavailable.
///
/// # Errors
///
/// Always returns [`AgentError::UnsupportedPlatform`].
#[cfg(not(unix))]
pub fn connect_unix(path: impl AsRef<Path>) -> Result<AgentClient<io::Empty>, AgentError> {
    let _ = path;
    Err(AgentError::UnsupportedPlatform)
}

fn default_signing_flags(key_blob: &[u8]) -> Result<u32, AgentError> {
    let mut reader = Reader::new(key_blob);
    let algorithm = reader.read_string()?;
    match algorithm {
        // Zero flags: the agent signs under the key's own format identifier.
        b"ssh-ed25519" | b"ecdsa-sha2-nistp256" => Ok(0),
        b"ssh-rsa" => Ok(SSH_AGENT_RSA_SHA2_256),
        _ => Err(AgentError::UnsupportedKey),
    }
}
