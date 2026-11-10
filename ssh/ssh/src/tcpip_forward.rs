//! RFC 4254 remote TCP forwarding messages and explicit forwarding policy.
//!
//! This module carries the connection-level `tcpip-forward` and
//! `cancel-tcpip-forward` requests and the `forwarded-tcpip` channel metadata.
//! It does not allocate a port or listen on a network endpoint.  A server
//! application must explicitly authorize a binding before this endpoint records
//! it, and a forwarded channel is accepted only while an exact binding exists.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use neotales_ssh::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelOpenRequest, ChannelTransport,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
};
use neotales_ssh::{Error, MAX_PACKET_CONTENT, Reader, Writer};

/// SSH message number for a connection-level global request.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// SSH message number for a successful global-request response.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
/// SSH message number for a failed global-request response.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// The RFC 4254 name of the remote forwarding request.
pub const TCPIP_FORWARD_REQUEST: &str = "tcpip-forward";
/// The RFC 4254 name of the remote forwarding cancellation request.
pub const CANCEL_TCPIP_FORWARD_REQUEST: &str = "cancel-tcpip-forward";
/// The RFC 4254 name of a server-opened forwarded TCP channel.
pub const FORWARDED_TCPIP_CHANNEL_TYPE: &str = "forwarded-tcpip";

/// A descriptive alias for [`TCPIP_FORWARD_REQUEST`].
pub const TCPIP_FORWARD_REQUEST_NAME: &str = TCPIP_FORWARD_REQUEST;
/// A descriptive alias for [`CANCEL_TCPIP_FORWARD_REQUEST`].
pub const CANCEL_TCPIP_FORWARD_REQUEST_NAME: &str = CANCEL_TCPIP_FORWARD_REQUEST;
/// A descriptive alias for [`FORWARDED_TCPIP_CHANNEL_TYPE`].
pub const FORWARDED_TCPIP_CHANNEL_NAME: &str = FORWARDED_TCPIP_CHANNEL_TYPE;

/// The maximum byte length of a bind address in a global request.
pub const MAX_TCPIP_FORWARD_ADDRESS_LENGTH: usize = 255;
/// The largest valid requested or connected TCP port.
pub const MAX_TCPIP_FORWARD_PORT: u32 = 65_535;
/// The largest valid originator TCP port.
pub const MAX_TCPIP_FORWARD_ORIGINATOR_PORT: u32 = 65_535;
/// A descriptive alias for [`MAX_TCPIP_FORWARD_ADDRESS_LENGTH`].
pub const MAX_FORWARDED_TCPIP_ADDRESS_LENGTH: usize = MAX_TCPIP_FORWARD_ADDRESS_LENGTH;
/// A descriptive alias for [`MAX_TCPIP_FORWARD_ADDRESS_LENGTH`].
pub const MAX_TCPIP_FORWARD_HOST_LENGTH: usize = MAX_TCPIP_FORWARD_ADDRESS_LENGTH;

/// A bounded remote-forwarding protocol, policy, or transport error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpipForwardError {
    /// An SSH primitive was malformed, truncated, or could not be encoded.
    Wire(Error),
    /// The shared channel layer rejected an operation or packet.
    Channel(ChannelError),
    /// The underlying protected transport failed.
    Transport,
    /// A bind address exceeded the 255-byte protocol limit.
    BindAddressTooLong,
    /// A connected address was empty.
    EmptyConnectedAddress,
    /// A connected address exceeded the 255-byte protocol limit.
    ConnectedAddressTooLong,
    /// An originator address was empty.
    EmptyOriginatorAddress,
    /// An originator address exceeded the 255-byte protocol limit.
    OriginatorAddressTooLong,
    /// A port was outside the applicable TCP port range.
    InvalidPort,
    /// A connected port was zero or outside the TCP port range.
    InvalidConnectedPort,
    /// An originator port was outside the TCP port range.
    InvalidOriginatorPort,
    /// Type-specific data had bytes after its required fields.
    TrailingBytes,
    /// A global request or response was structurally invalid.
    InvalidRequest,
    /// A global response was not an exact RFC 4254 response.
    InvalidResponse,
    /// A forwarded channel open was structurally invalid.
    InvalidOpen,
    /// The explicit server policy rejected a request.
    PolicyDenied,
    /// The explicit server policy callback panicked.
    CallbackPanicked,
    /// No exact binding exists for a requested cancellation or channel open.
    NoBinding,
    /// A message was valid for the shared channel layer but not this endpoint.
    UnexpectedMessage,
}

impl fmt::Display for TcpipForwardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH remote-forwarding wire error: {error}"),
            Self::Channel(error) => {
                write!(formatter, "SSH remote-forwarding channel error: {error}")
            }
            Self::Transport => formatter.write_str("SSH remote-forwarding transport failed"),
            Self::BindAddressTooLong => {
                formatter.write_str("SSH remote-forwarding bind address exceeds 255 bytes")
            }
            Self::EmptyConnectedAddress => {
                formatter.write_str("SSH forwarded-tcpip connected address is empty")
            }
            Self::ConnectedAddressTooLong => {
                formatter.write_str("SSH forwarded-tcpip connected address exceeds 255 bytes")
            }
            Self::EmptyOriginatorAddress => {
                formatter.write_str("SSH forwarded-tcpip originator address is empty")
            }
            Self::OriginatorAddressTooLong => {
                formatter.write_str("SSH forwarded-tcpip originator address exceeds 255 bytes")
            }
            Self::InvalidPort => formatter.write_str("SSH remote-forwarding port is invalid"),
            Self::InvalidConnectedPort => {
                formatter.write_str("SSH forwarded-tcpip connected port is invalid")
            }
            Self::InvalidOriginatorPort => {
                formatter.write_str("SSH forwarded-tcpip originator port is invalid")
            }
            Self::TrailingBytes => {
                formatter.write_str("SSH remote-forwarding data has trailing bytes")
            }
            Self::InvalidRequest => formatter.write_str("SSH remote-forwarding request is invalid"),
            Self::InvalidResponse => {
                formatter.write_str("SSH remote-forwarding response is invalid")
            }
            Self::InvalidOpen => formatter.write_str("SSH forwarded-tcpip open is invalid"),
            Self::PolicyDenied => {
                formatter.write_str("SSH remote TCP forwarding was denied by policy")
            }
            Self::CallbackPanicked => {
                formatter.write_str("SSH remote-forwarding policy callback panicked")
            }
            Self::NoBinding => formatter.write_str("SSH remote-forwarding binding was not found"),
            Self::UnexpectedMessage => {
                formatter.write_str("SSH remote forwarding received an unexpected message")
            }
        }
    }
}

impl std::error::Error for TcpipForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Channel(error) => Some(error),
            Self::Transport
            | Self::BindAddressTooLong
            | Self::EmptyConnectedAddress
            | Self::ConnectedAddressTooLong
            | Self::EmptyOriginatorAddress
            | Self::OriginatorAddressTooLong
            | Self::InvalidPort
            | Self::InvalidConnectedPort
            | Self::InvalidOriginatorPort
            | Self::TrailingBytes
            | Self::InvalidRequest
            | Self::InvalidResponse
            | Self::InvalidOpen
            | Self::PolicyDenied
            | Self::CallbackPanicked
            | Self::NoBinding
            | Self::UnexpectedMessage => None,
        }
    }
}

impl From<Error> for TcpipForwardError {
    fn from(error: Error) -> Self {
        Self::Wire(error)
    }
}

impl From<ChannelError> for TcpipForwardError {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

/// The two-field bind address and port carried by a forwarding request.
///
/// A bind address is a byte string, not a parsed numeric address.  Empty
/// address bytes are representable because RFC 4254 assigns them a distinct
/// meaning; this type does not turn them into a wildcard permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpipForwardBinding {
    bind_address: Vec<u8>,
    port: u32,
}

impl TcpipForwardBinding {
    /// Creates a validated forwarding binding request.
    ///
    /// The port is a wire `uint32`; values above 65535 are rejected.  Port
    /// zero is retained for encoding and is rejected by the server policy when
    /// a request is handled, because this module cannot allocate a port.
    ///
    /// # Errors
    ///
    /// Returns [`TcpipForwardError::BindAddressTooLong`] or
    /// [`TcpipForwardError::InvalidPort`] for an invalid field.
    pub fn new<A, P>(bind_address: A, port: P) -> Result<Self, TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        let port = port
            .try_into()
            .map_err(|_error| TcpipForwardError::InvalidPort)?;
        Self::from_bytes(bind_address.as_ref(), port)
    }

    /// Creates a binding request from borrowed address bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TcpipForwardError::BindAddressTooLong`] or
    /// [`TcpipForwardError::InvalidPort`] for an invalid field.
    pub fn from_bytes(bind_address: &[u8], port: u32) -> Result<Self, TcpipForwardError> {
        validate_bind_address(bind_address)?;
        validate_port(port)?;
        Ok(Self {
            bind_address: bind_address.to_vec(),
            port,
        })
    }

    /// Returns the exact bind address bytes.
    #[must_use]
    pub fn bind_address(&self) -> &[u8] {
        &self.bind_address
    }

    /// Returns the exact bind address bytes.
    #[must_use]
    pub fn address(&self) -> &[u8] {
        self.bind_address()
    }

    /// Returns the requested TCP port.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }

    /// Returns this binding as a borrowed policy request.
    #[must_use]
    pub fn as_request(&self) -> TcpipForwardPolicyRequest<'_> {
        TcpipForwardPolicyRequest {
            bind_address: &self.bind_address,
            port: self.port,
        }
    }

    /// Encodes the address and port in RFC 4254 order.
    ///
    /// # Errors
    ///
    /// Returns a wire error if the fields cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, TcpipForwardError> {
        validate_bind_address(&self.bind_address)?;
        validate_port(self.port)?;
        let mut writer = Writer::new();
        writer.write_string_with_limit(&self.bind_address, MAX_TCPIP_FORWARD_ADDRESS_LENGTH)?;
        writer.write_uint32(self.port);
        let encoded = writer.into_bytes();
        ensure_packet_size(encoded.len())?;
        Ok(encoded)
    }

    /// Decodes exactly an address and port.
    ///
    /// # Errors
    ///
    /// Returns a wire, address, port, or trailing-data error for malformed
    /// request-specific data.
    pub fn decode(data: &[u8]) -> Result<Self, TcpipForwardError> {
        let mut reader = Reader::new(data);
        let bind_address = read_bind_address(&mut reader)?;
        let port = reader.read_uint32()?;
        if !reader.is_empty() {
            return Err(TcpipForwardError::TrailingBytes);
        }
        validate_bind_address(&bind_address)?;
        validate_port(port)?;
        Ok(Self { bind_address, port })
    }
}

/// A descriptive alias for [`TcpipForwardBinding`].
pub type TcpipForwardTuple = TcpipForwardBinding;
/// A descriptive alias for [`TcpipForwardBinding`].
pub type RemoteForwardBinding = TcpipForwardBinding;

/// A borrowed exact bind-address request passed to a server policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpipForwardPolicyRequest<'request> {
    /// Exact bind address bytes received from the peer.
    pub bind_address: &'request [u8],
    /// Requested TCP port received from the peer.
    pub port: u32,
}

impl TcpipForwardPolicyRequest<'_> {
    /// Returns the exact bind address bytes.
    #[must_use]
    pub const fn bind_address(&self) -> &[u8] {
        self.bind_address
    }

    /// Returns the exact bind address bytes.
    #[must_use]
    pub const fn address(&self) -> &[u8] {
        self.bind_address()
    }

    /// Returns the requested TCP port.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }
}

/// A short alias for [`TcpipForwardPolicyRequest`].
pub type TcpipForwardRequest<'request> = TcpipForwardPolicyRequest<'request>;

/// The policy shape of a decoded global request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpipForwardRequestKind {
    /// A request to create a remote binding.
    TcpipForward,
    /// A request to cancel a remote binding.
    CancelTcpipForward,
    /// A global request not handled by this module.
    Unknown,
}

/// A decoded RFC 4254 remote-forwarding global request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpipForwardGlobalRequest {
    /// A `tcpip-forward` request.
    TcpipForward {
        /// Exact bind address bytes.
        bind_address: Vec<u8>,
        /// Requested TCP port.
        port: u32,
        /// Whether the peer wants a response.
        want_reply: bool,
    },
    /// A `cancel-tcpip-forward` request.
    CancelTcpipForward {
        /// Exact bind address bytes.
        bind_address: Vec<u8>,
        /// Requested TCP port.
        port: u32,
        /// Whether the peer wants a response.
        want_reply: bool,
    },
    /// A global request whose name is not handled by this module.
    Unknown {
        /// Exact request-name bytes.
        name: Vec<u8>,
        /// Whether the peer wants a response.
        want_reply: bool,
        /// Exact request-specific bytes.
        data: Vec<u8>,
    },
}

impl TcpipForwardGlobalRequest {
    /// Creates a validated `tcpip-forward` request.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid bind address or port.
    pub fn tcpip_forward<A, P>(
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<Self, TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        let binding = TcpipForwardBinding::new(bind_address, port)?;
        Ok(Self::TcpipForward {
            bind_address: binding.bind_address,
            port: binding.port,
            want_reply,
        })
    }

    /// Creates a validated `cancel-tcpip-forward` request.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid bind address or port.
    pub fn cancel_tcpip_forward<A, P>(
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<Self, TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        let binding = TcpipForwardBinding::new(bind_address, port)?;
        Ok(Self::CancelTcpipForward {
            bind_address: binding.bind_address,
            port: binding.port,
            want_reply,
        })
    }

    /// Creates an unknown request while retaining its exact bytes.
    #[must_use]
    pub fn unknown<N, D>(name: N, want_reply: bool, data: D) -> Self
    where
        N: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        Self::Unknown {
            name: name.as_ref().to_vec(),
            want_reply,
            data: data.as_ref().to_vec(),
        }
    }

    /// Decodes one complete global-request payload.
    ///
    /// # Errors
    ///
    /// Returns a wire or request error for malformed known requests and for
    /// payloads outside the shared packet-content limit.
    pub fn decode(input: &[u8]) -> Result<Self, TcpipForwardError> {
        ensure_packet_size(input.len())?;
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_GLOBAL_REQUEST {
            return Err(TcpipForwardError::InvalidRequest);
        }
        let name = reader.read_string_with_limit(MAX_PACKET_CONTENT)?.to_vec();
        let want_reply = reader.read_boolean()?;
        match name.as_slice() {
            value if value == TCPIP_FORWARD_REQUEST.as_bytes() => {
                let bind_address = read_bind_address(&mut reader)?;
                let port = reader.read_uint32()?;
                if !reader.is_empty() {
                    return Err(TcpipForwardError::TrailingBytes);
                }
                validate_bind_address(&bind_address)?;
                validate_port(port)?;
                Ok(Self::TcpipForward {
                    bind_address,
                    port,
                    want_reply,
                })
            }
            value if value == CANCEL_TCPIP_FORWARD_REQUEST.as_bytes() => {
                let bind_address = read_bind_address(&mut reader)?;
                let port = reader.read_uint32()?;
                if !reader.is_empty() {
                    return Err(TcpipForwardError::TrailingBytes);
                }
                validate_bind_address(&bind_address)?;
                validate_port(port)?;
                Ok(Self::CancelTcpipForward {
                    bind_address,
                    port,
                    want_reply,
                })
            }
            _ => Ok(Self::Unknown {
                name,
                want_reply,
                data: reader.remaining().to_vec(),
            }),
        }
    }

    /// Decodes one global request from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, TcpipForwardError> {
        Self::decode(input)
    }

    /// Encodes this request as one complete global-request payload.
    ///
    /// # Errors
    ///
    /// Returns a wire or size error if the request cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, TcpipForwardError> {
        let (name, want_reply, binding) = match self {
            Self::TcpipForward {
                bind_address,
                port,
                want_reply,
            } => (
                TCPIP_FORWARD_REQUEST.as_bytes(),
                *want_reply,
                Some((bind_address.as_slice(), *port)),
            ),
            Self::CancelTcpipForward {
                bind_address,
                port,
                want_reply,
            } => (
                CANCEL_TCPIP_FORWARD_REQUEST.as_bytes(),
                *want_reply,
                Some((bind_address.as_slice(), *port)),
            ),
            Self::Unknown {
                name, want_reply, ..
            } => (name.as_slice(), *want_reply, None),
        };
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
        writer.write_string_with_limit(name, MAX_PACKET_CONTENT)?;
        writer.write_boolean(want_reply);
        if let Some((bind_address, port)) = binding {
            validate_bind_address(bind_address)?;
            validate_port(port)?;
            writer.write_string_with_limit(bind_address, MAX_TCPIP_FORWARD_ADDRESS_LENGTH)?;
            writer.write_uint32(port);
        }
        let mut encoded = writer.into_bytes();
        if binding.is_none()
            && let Self::Unknown { data, .. } = self
        {
            let total = encoded
                .len()
                .checked_add(data.len())
                .ok_or(TcpipForwardError::Wire(Error::LimitExceeded))?;
            ensure_packet_size(total)?;
            encoded.extend_from_slice(data);
        }
        ensure_packet_size(encoded.len())?;
        Ok(encoded)
    }

    /// Encodes this request to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, TcpipForwardError> {
        self.encode()
    }

    /// Returns the request kind.
    #[must_use]
    pub const fn kind(&self) -> TcpipForwardRequestKind {
        match self {
            Self::TcpipForward { .. } => TcpipForwardRequestKind::TcpipForward,
            Self::CancelTcpipForward { .. } => TcpipForwardRequestKind::CancelTcpipForward,
            Self::Unknown { .. } => TcpipForwardRequestKind::Unknown,
        }
    }

    /// Returns the request name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        match self {
            Self::TcpipForward { .. } => TCPIP_FORWARD_REQUEST.as_bytes(),
            Self::CancelTcpipForward { .. } => CANCEL_TCPIP_FORWARD_REQUEST.as_bytes(),
            Self::Unknown { name, .. } => name,
        }
    }

    /// Returns whether the peer requested a response.
    #[must_use]
    pub const fn want_reply(&self) -> bool {
        match self {
            Self::TcpipForward { want_reply, .. }
            | Self::CancelTcpipForward { want_reply, .. }
            | Self::Unknown { want_reply, .. } => *want_reply,
        }
    }

    /// Returns the binding fields for a known forwarding request.
    #[must_use]
    pub fn binding(&self) -> Option<TcpipForwardBinding> {
        match self {
            Self::TcpipForward {
                bind_address, port, ..
            }
            | Self::CancelTcpipForward {
                bind_address, port, ..
            } => TcpipForwardBinding::from_bytes(bind_address, *port).ok(),
            Self::Unknown { .. } => None,
        }
    }

    /// Returns whether this is a `tcpip-forward` request.
    #[must_use]
    pub const fn is_tcpip_forward(&self) -> bool {
        matches!(self, Self::TcpipForward { .. })
    }

    /// Returns whether this is a `cancel-tcpip-forward` request.
    #[must_use]
    pub const fn is_cancel_tcpip_forward(&self) -> bool {
        matches!(self, Self::CancelTcpipForward { .. })
    }

    /// Builds a response for this request.
    ///
    /// A request with `want_reply == false` produces no response.  The caller
    /// supplies the policy result; a zero-port `tcpip-forward` request is always
    /// reported as failure because this module cannot allocate a port.
    ///
    /// # Errors
    ///
    /// Returns a wire or size error if the response cannot be represented.
    pub fn reply(&self, accepted: bool) -> Result<Option<Vec<u8>>, TcpipForwardError> {
        if !self.want_reply() {
            return Ok(None);
        }
        let accepted = accepted && !matches!(self, Self::TcpipForward { port: 0, .. });
        TcpipForwardResponse::encode(if accepted {
            TcpipForwardResponse::Success
        } else {
            TcpipForwardResponse::Failure
        })
        .map(Some)
    }
}

impl TryFrom<&[u8]> for TcpipForwardGlobalRequest {
    type Error = TcpipForwardError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// A response to a global request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpipForwardResponse {
    /// The peer accepted the request.
    Success,
    /// The peer rejected the request.
    Failure,
}

impl TcpipForwardResponse {
    /// Decodes an exact one-byte global response.
    ///
    /// # Errors
    ///
    /// Returns [`TcpipForwardError::InvalidResponse`] when the payload is not
    /// exactly message 81 or 82.
    pub fn decode(input: &[u8]) -> Result<Self, TcpipForwardError> {
        match input {
            [SSH_MSG_REQUEST_SUCCESS] => Ok(Self::Success),
            [SSH_MSG_REQUEST_FAILURE] => Ok(Self::Failure),
            _ => Err(TcpipForwardError::InvalidResponse),
        }
    }

    /// Encodes this response as one byte.
    ///
    /// # Errors
    ///
    /// Returns [`TcpipForwardError::InvalidResponse`] if the shared packet
    /// limit becomes smaller than one byte.
    pub fn encode(self) -> Result<Vec<u8>, TcpipForwardError> {
        if MAX_PACKET_CONTENT == 0 {
            return Err(TcpipForwardError::InvalidResponse);
        }
        Ok(vec![match self {
            Self::Success => SSH_MSG_REQUEST_SUCCESS,
            Self::Failure => SSH_MSG_REQUEST_FAILURE,
        }])
    }

    /// Returns whether this is a success response.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Returns whether this is a failure response.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failure)
    }
}

/// A short alias for [`TcpipForwardResponse`].
pub type GlobalRequestResponse = TcpipForwardResponse;

/// A validated four-field `forwarded-tcpip` channel-open tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardedTcpipTuple {
    connected_address: Vec<u8>,
    connected_port: u32,
    originator_address: Vec<u8>,
    originator_port: u32,
}

impl ForwardedTcpipTuple {
    /// Creates a validated forwarded channel tuple.
    ///
    /// # Errors
    ///
    /// Returns an address, port, or wire error for an invalid field.
    pub fn new<C, O, P, Q>(
        connected_address: C,
        connected_port: P,
        originator_address: O,
        originator_port: Q,
    ) -> Result<Self, TcpipForwardError>
    where
        C: AsRef<[u8]>,
        O: AsRef<[u8]>,
        P: TryInto<u32>,
        Q: TryInto<u32>,
    {
        let connected_port = connected_port
            .try_into()
            .map_err(|_error| TcpipForwardError::InvalidConnectedPort)?;
        let originator_port = originator_port
            .try_into()
            .map_err(|_error| TcpipForwardError::InvalidOriginatorPort)?;
        Self::from_bytes(
            connected_address.as_ref(),
            connected_port,
            originator_address.as_ref(),
            originator_port,
        )
    }

    /// Creates a validated tuple from borrowed address bytes.
    ///
    /// # Errors
    ///
    /// Returns an address, port, or trailing-data error for invalid fields.
    pub fn from_bytes(
        connected_address: &[u8],
        connected_port: u32,
        originator_address: &[u8],
        originator_port: u32,
    ) -> Result<Self, TcpipForwardError> {
        validate_connected_address(connected_address)?;
        validate_originator_address(originator_address)?;
        validate_connected_port(connected_port)?;
        validate_originator_port(originator_port)?;
        Ok(Self {
            connected_address: connected_address.to_vec(),
            connected_port,
            originator_address: originator_address.to_vec(),
            originator_port,
        })
    }

    /// Returns the exact connected address bytes.
    #[must_use]
    pub fn connected_address(&self) -> &[u8] {
        &self.connected_address
    }

    /// Returns the connected TCP port.
    #[must_use]
    pub const fn connected_port(&self) -> u32 {
        self.connected_port
    }

    /// Returns the exact originator address bytes.
    #[must_use]
    pub fn originator_address(&self) -> &[u8] {
        &self.originator_address
    }

    /// Returns the originator TCP port.
    #[must_use]
    pub const fn originator_port(&self) -> u32 {
        self.originator_port
    }

    /// Encodes the four fields in RFC 4254 order.
    ///
    /// # Errors
    ///
    /// Returns an address, port, or wire error for an invalid field.
    pub fn encode(&self) -> Result<Vec<u8>, TcpipForwardError> {
        validate_connected_address(&self.connected_address)?;
        validate_originator_address(&self.originator_address)?;
        validate_connected_port(self.connected_port)?;
        validate_originator_port(self.originator_port)?;
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(&self.connected_address, MAX_TCPIP_FORWARD_ADDRESS_LENGTH)?;
        writer.write_uint32(self.connected_port);
        writer
            .write_string_with_limit(&self.originator_address, MAX_TCPIP_FORWARD_ADDRESS_LENGTH)?;
        writer.write_uint32(self.originator_port);
        let encoded = writer.into_bytes();
        ensure_packet_size(encoded.len())?;
        Ok(encoded)
    }

    /// Decodes exactly the four fields in RFC 4254 order.
    ///
    /// # Errors
    ///
    /// Returns a wire, address, port, or trailing-data error for malformed
    /// type-specific data.
    pub fn decode(data: &[u8]) -> Result<Self, TcpipForwardError> {
        let mut reader = Reader::new(data);
        let connected_address = read_connected_address(&mut reader)?;
        let connected_port = reader.read_uint32()?;
        let originator_address = read_originator_address(&mut reader)?;
        let originator_port = reader.read_uint32()?;
        if !reader.is_empty() {
            return Err(TcpipForwardError::TrailingBytes);
        }
        validate_connected_address(&connected_address)?;
        validate_originator_address(&originator_address)?;
        validate_connected_port(connected_port)?;
        validate_originator_port(originator_port)?;
        Ok(Self {
            connected_address,
            connected_port,
            originator_address,
            originator_port,
        })
    }

    /// Encodes this tuple as channel-open type-specific data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn encode_type_specific_data(&self) -> Result<Vec<u8>, TcpipForwardError> {
        self.encode()
    }

    /// Decodes channel-open type-specific data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn decode_type_specific_data(data: &[u8]) -> Result<Self, TcpipForwardError> {
        Self::decode(data)
    }
}

/// A descriptive alias for [`ForwardedTcpipTuple`].
pub type ForwardedTcpipOpenData = ForwardedTcpipTuple;
/// A descriptive alias for [`ForwardedTcpipTuple`].
pub type TcpipForwardOpenData = ForwardedTcpipTuple;
/// A short alias for [`ForwardedTcpipTuple`].
pub type ForwardedTcpipOpen = ForwardedTcpipTuple;
/// A short alias for [`ForwardedTcpipTuple`].
pub type TcpipForwardChannelData = ForwardedTcpipTuple;

/// The result of processing one server-side global request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerTcpipForwardRequest {
    /// The request kind.
    pub kind: TcpipForwardRequestKind,
    /// Exact bind address bytes, or an empty vector for an unknown request.
    pub bind_address: Vec<u8>,
    /// Requested port, or zero for an unknown request.
    pub port: u32,
    /// Whether the peer requested a response.
    pub want_reply: bool,
    /// Whether the request was accepted and recorded or removed.
    pub accepted: bool,
}

/// A descriptive alias for [`ServerTcpipForwardRequest`].
pub type TcpipForwardResult = ServerTcpipForwardRequest;

impl ServerTcpipForwardRequest {
    /// Returns the request kind.
    #[must_use]
    pub const fn kind(&self) -> TcpipForwardRequestKind {
        self.kind
    }

    /// Returns the exact bind address bytes.
    #[must_use]
    pub fn bind_address(&self) -> &[u8] {
        &self.bind_address
    }

    /// Returns the requested port.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }

    /// Returns whether a response was requested.
    #[must_use]
    pub const fn want_reply(&self) -> bool {
        self.want_reply
    }

    /// Returns whether the request was accepted.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.accepted
    }

    /// Returns whether the request was denied.
    #[must_use]
    pub const fn denied(&self) -> bool {
        !self.accepted
    }
}

/// A channel event routed by a remote-forwarding endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpipForwardEvent {
    /// A forwarded channel was opened or confirmed.
    Opened {
        /// Local channel identifier.
        channel: ChannelId,
        /// The validated tuple associated with the channel, when known.
        tuple: Option<ForwardedTcpipTuple>,
    },
    /// A forwarded channel open was rejected.
    OpenRejected {
        /// Local identifier for a rejected locally opened channel, or `None`
        /// for a server-side rejection before confirmation.
        channel: Option<ChannelId>,
        /// RFC 4254 numeric rejection reason.
        reason: u32,
        /// Human-readable diagnostic bytes.
        description: Vec<u8>,
        /// RFC 4250 language tag bytes.
        language: Vec<u8>,
        /// The invalid tuple when one could be decoded.
        tuple: Option<ForwardedTcpipTuple>,
    },
    /// A complete data packet arrived.
    Data {
        /// Recipient channel identifier.
        channel: ChannelId,
        /// Data bytes.
        data: Vec<u8>,
    },
    /// Extended data received on a forwarded channel.
    ExtendedData {
        /// Recipient channel identifier.
        channel: ChannelId,
        /// RFC 4254 extended-data type code.
        data_type_code: u32,
        /// Extended-data bytes.
        data: Vec<u8>,
    },
    /// The peer granted more credit for data sent on a channel.
    WindowAdjusted {
        /// Recipient channel identifier.
        channel: ChannelId,
        /// Newly available remote credit.
        available: u32,
    },
    /// The peer will send no more data on a channel.
    Eof {
        /// Recipient channel identifier.
        channel: ChannelId,
    },
    /// The peer closed a channel.
    Close {
        /// Recipient channel identifier.
        channel: ChannelId,
    },
    /// A channel request arrived with application-defined data.
    Request {
        /// Recipient channel identifier.
        channel: ChannelId,
        /// Exact request type bytes.
        request_type: Vec<u8>,
        /// Whether the peer requested a channel reply.
        want_reply: bool,
        /// Exact request-specific bytes.
        data: Vec<u8>,
    },
    /// The peer answered a channel request successfully.
    RequestSucceeded {
        /// Recipient channel identifier.
        channel: ChannelId,
    },
    /// The peer answered a channel request unsuccessfully.
    RequestFailed {
        /// Recipient channel identifier.
        channel: ChannelId,
    },
    /// The peer sent a global request, RFC 4254 §4.
    GlobalRequest {
        /// The request name, in US-ASCII, as the peer spelled it.
        request_name: Vec<u8>,
        /// Whether the peer required a reply.
        want_reply: bool,
        /// Exact request-specific bytes.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request successfully.
    GlobalRequestSucceeded {
        /// Exact response-specific bytes.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request unsuccessfully.
    GlobalRequestFailed {
        /// Exact response-specific bytes.
        data: Vec<u8>,
    },
}

/// A descriptive alias for [`TcpipForwardEvent`].
pub type ForwardedTcpipEvent = TcpipForwardEvent;

/// A boolean decision returned by a remote-forwarding policy implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpipForwardDecision(bool);

impl TcpipForwardDecision {
    /// Accepts the exact requested binding.
    #[must_use]
    pub const fn accept() -> Self {
        Self(true)
    }

    /// Rejects the exact requested binding.
    #[must_use]
    pub const fn reject() -> Self {
        Self(false)
    }

    /// Returns whether the binding was accepted.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.0
    }
}

/// An explicit authorization policy for remote TCP bindings.
pub trait TcpipForwardPolicy {
    /// Returns `true` only when the exact bind address and port are allowed.
    fn allow(&self, request: TcpipForwardPolicyRequest<'_>) -> bool;
}

impl<F> TcpipForwardPolicy for F
where
    F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> bool + ?Sized,
{
    fn allow(&self, request: TcpipForwardPolicyRequest<'_>) -> bool {
        self(request)
    }
}

struct TwoArgumentPolicy<F>(F);

impl<F> TcpipForwardPolicy for TwoArgumentPolicy<F>
where
    F: for<'request> Fn(&'request [u8], u32) -> bool,
{
    fn allow(&self, request: TcpipForwardPolicyRequest<'_>) -> bool {
        (self.0)(request.bind_address, request.port)
    }
}

struct DecisionPolicy<F>(F);

impl<F> TcpipForwardPolicy for DecisionPolicy<F>
where
    F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> TcpipForwardDecision,
{
    fn allow(&self, request: TcpipForwardPolicyRequest<'_>) -> bool {
        (self.0)(request).accepted()
    }
}

/// A client-side remote-forwarding endpoint over one authenticated connection.
#[derive(Debug)]
pub struct ClientTcpipForward<T> {
    channels: ChannelConnection<T>,
    open_tuples: BTreeMap<ChannelId, ForwardedTcpipTuple>,
}

impl<T> ClientTcpipForward<T> {
    /// Wraps one already authenticated client transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
            open_tuples: BTreeMap::new(),
        }
    }

    /// Reuses an existing shared channel connection.
    #[must_use]
    pub fn from_connection(channels: ChannelConnection<T>) -> Self {
        Self {
            channels,
            open_tuples: BTreeMap::new(),
        }
    }

    /// Returns the shared channel connection.
    #[must_use]
    pub const fn connection(&self) -> &ChannelConnection<T> {
        &self.channels
    }

    /// Returns the mutable shared channel connection.
    pub const fn connection_mut(&mut self) -> &mut ChannelConnection<T> {
        &mut self.channels
    }

    /// Consumes this endpoint and returns the shared channel connection.
    #[must_use]
    pub fn into_connection(self) -> ChannelConnection<T> {
        self.channels
    }

    /// Consumes this endpoint and returns its transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.channels.into_inner()
    }
}

impl<T> ClientTcpipForward<T>
where
    T: ChannelTransport,
{
    /// Sends a `tcpip-forward` global request.
    ///
    /// The request-specific data is written as one complete transport payload;
    /// it is not read through the channel dispatcher.
    ///
    /// # Errors
    ///
    /// Returns a validation, size, or transport error.
    pub fn request_tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        let request = TcpipForwardGlobalRequest::tcpip_forward(bind_address, port, want_reply)?;
        self.write_global_request(&request)
    }

    /// Sends a `tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_tcpip_forward`].
    pub fn request_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a `tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_tcpip_forward`].
    pub fn send_tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a `tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_tcpip_forward`].
    pub fn tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a validated forwarding request object.
    ///
    /// # Errors
    ///
    /// Returns a wire, size, or transport error.
    pub fn request(
        &mut self,
        request: &TcpipForwardGlobalRequest,
    ) -> Result<(), TcpipForwardError> {
        self.write_global_request(request)
    }

    /// Sends a validated binding as a `tcpip-forward` request.
    ///
    /// # Errors
    ///
    /// Returns a wire, size, or transport error.
    pub fn request_binding(
        &mut self,
        binding: &TcpipForwardBinding,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError> {
        self.request_tcpip_forward(binding.bind_address(), binding.port(), want_reply)
    }

    /// Sends a `cancel-tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns a validation, size, or transport error.
    pub fn request_cancel_tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        let request =
            TcpipForwardGlobalRequest::cancel_tcpip_forward(bind_address, port, want_reply)?;
        self.write_global_request(&request)
    }

    /// Sends a `cancel-tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_cancel_tcpip_forward`].
    pub fn cancel_tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_cancel_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a `cancel-tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_cancel_tcpip_forward`].
    pub fn send_cancel_tcpip_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_cancel_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a `cancel-tcpip-forward` global request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_cancel_tcpip_forward`].
    pub fn cancel_forward<A, P>(
        &mut self,
        bind_address: A,
        port: P,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError>
    where
        A: AsRef<[u8]>,
        P: TryInto<u32>,
    {
        self.request_cancel_tcpip_forward(bind_address, port, want_reply)
    }

    /// Sends a validated cancellation request object.
    ///
    /// # Errors
    ///
    /// Returns a wire, size, or transport error.
    pub fn cancel(&mut self, request: &TcpipForwardGlobalRequest) -> Result<(), TcpipForwardError> {
        self.write_global_request(request)
    }

    /// Sends a validated binding as a `cancel-tcpip-forward` request.
    ///
    /// # Errors
    ///
    /// Returns a wire, size, or transport error.
    pub fn cancel_binding(
        &mut self,
        binding: &TcpipForwardBinding,
        want_reply: bool,
    ) -> Result<(), TcpipForwardError> {
        self.request_cancel_tcpip_forward(binding.bind_address(), binding.port(), want_reply)
    }

    /// Reads one exact global-request response from the transport.
    ///
    /// Use this only when waiting directly for the response. Alternatively,
    /// [`Self::dispatch_one`] multiplexes channel traffic and returns global
    /// replies as [`TcpipForwardEvent::GlobalRequestSucceeded`] or
    /// [`TcpipForwardEvent::GlobalRequestFailed`]. Do not mix the two read paths:
    /// each consumes the next payload from the shared connection.
    ///
    /// # Errors
    ///
    /// Returns a transport or invalid-response error.
    pub fn read_global_response(&mut self) -> Result<TcpipForwardResponse, TcpipForwardError> {
        let payload = self
            .channels
            .transport_mut()
            .read_channel_payload()
            .map_err(|_error| TcpipForwardError::Transport)?;
        TcpipForwardResponse::decode(&payload)
    }

    /// Reads one exact global-request response from the transport.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_global_response`].
    pub fn read_response(&mut self) -> Result<TcpipForwardResponse, TcpipForwardError> {
        self.read_global_response()
    }

    /// Reads one exact global-request response from the transport.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_global_response`].
    pub fn read_global_reply(&mut self) -> Result<TcpipForwardResponse, TcpipForwardError> {
        self.read_global_response()
    }

    /// Reads one channel event and automatically accepts a valid inbound
    /// `forwarded-tcpip` open. Inbound global requests without a client-side
    /// policy are refused; replies to this endpoint's own global requests are
    /// surfaced as events.
    ///
    /// # Errors
    ///
    /// Returns a channel, wire, or transport error.
    pub fn dispatch_one(&mut self) -> Result<TcpipForwardEvent, TcpipForwardError> {
        loop {
            let event = self.channels.dispatch_one()?;
            match event {
                ChannelEvent::GlobalRequest { want_reply, .. } => {
                    self.channels.refuse_global_request(want_reply)?;
                }
                ChannelEvent::OpenRequest(request) => return self.handle_open_request(&request),
                event => return map_channel_event(event, &mut self.open_tuples),
            }
        }
    }

    /// Writes one bounded data packet through the shared channel window.
    ///
    /// # Errors
    ///
    /// Returns a channel-state, maximum-packet, window, or transport error.
    pub fn send_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, TcpipForwardError> {
        self.channels.write_data(channel, data).map_err(Into::into)
    }

    /// Writes one bounded data packet through the shared channel window.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::send_data`].
    pub fn write_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, TcpipForwardError> {
        self.send_data(channel, data)
    }

    /// Grants the peer more local receive credit.
    ///
    /// # Errors
    ///
    /// Returns a zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, TcpipForwardError> {
        self.channels
            .increase_local_window(channel, bytes)
            .map_err(Into::into)
    }

    /// Sends EOF through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), TcpipForwardError> {
        self.channels.send_eof(channel).map_err(Into::into)
    }

    /// Sends CLOSE through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), TcpipForwardError> {
        self.channels.send_close(channel).map_err(Into::into)
    }

    fn write_global_request(
        &mut self,
        request: &TcpipForwardGlobalRequest,
    ) -> Result<(), TcpipForwardError> {
        let payload = request.encode()?;
        self.channels
            .transport_mut()
            .write_channel_payload(&payload)
            .map_err(|_error| TcpipForwardError::Transport)
    }

    fn handle_open_request(
        &mut self,
        request: &ChannelOpenRequest,
    ) -> Result<TcpipForwardEvent, TcpipForwardError> {
        let remote_channel = request.sender_channel();
        if request.channel_type() != FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes() {
            return reject_open(
                &mut self.channels,
                remote_channel,
                SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                b"unsupported channel type",
                None,
            );
        }
        let tuple = match ForwardedTcpipTuple::decode(request.type_specific_data()) {
            Ok(tuple) => tuple,
            Err(_error) => {
                return reject_open(
                    &mut self.channels,
                    remote_channel,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    b"invalid forwarded-tcpip open data",
                    None,
                );
            }
        };
        let local_channel = self.channels.allocate_channel_id()?;
        self.channels.confirm_open(remote_channel, local_channel)?;
        self.open_tuples.insert(local_channel, tuple.clone());
        Ok(TcpipForwardEvent::Opened {
            channel: local_channel,
            tuple: Some(tuple),
        })
    }
}

/// A server-side remote-forwarding endpoint with a default-deny policy.
pub struct ServerTcpipForward<T> {
    channels: ChannelConnection<T>,
    policy: Option<Box<dyn TcpipForwardPolicy>>,
    bindings: BTreeSet<(Vec<u8>, u32)>,
    open_tuples: BTreeMap<ChannelId, ForwardedTcpipTuple>,
}

impl<T> fmt::Debug for ServerTcpipForward<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTcpipForward")
            .field("channel_count", &self.channels.channel_count())
            .field("pending_open_count", &self.channels.pending_open_count())
            .field("policy_configured", &self.policy.is_some())
            .field("binding_count", &self.bindings.len())
            .field("open_tuples", &self.open_tuples)
            .finish()
    }
}

impl<T> ServerTcpipForward<T> {
    /// Creates a default-deny server endpoint.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
            policy: None,
            bindings: BTreeSet::new(),
            open_tuples: BTreeMap::new(),
        }
    }

    /// Creates a server endpoint with an explicit policy implementation.
    #[must_use]
    pub fn with_policy<P>(transport: T, policy: P) -> Self
    where
        P: TcpipForwardPolicy + 'static,
    {
        let mut server = Self::new(transport);
        server.policy = Some(Box::new(policy));
        server
    }

    /// Creates a server endpoint with an exact two-argument allow callback.
    ///
    /// The callback receives the bind address bytes and requested port without
    /// wildcard normalization.
    #[must_use]
    pub fn with_allow_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(&'request [u8], u32) -> bool + 'static,
    {
        Self::with_policy(transport, TwoArgumentPolicy(callback))
    }

    /// Creates a server endpoint with a request-object allow callback.
    #[must_use]
    pub fn with_request_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> bool + 'static,
    {
        Self::with_policy(transport, callback)
    }

    /// Creates a server endpoint with a decision-returning request callback.
    #[must_use]
    pub fn with_decision_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> TcpipForwardDecision + 'static,
    {
        Self::with_policy(transport, DecisionPolicy(callback))
    }

    /// Creates a server endpoint with an exact two-argument allow callback.
    ///
    #[must_use]
    pub fn with_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(&'request [u8], u32) -> bool + 'static,
    {
        Self::with_allow_callback(transport, callback)
    }

    /// Creates a server endpoint with an exact two-argument allow callback.
    #[must_use]
    pub fn with_allow<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(&'request [u8], u32) -> bool + 'static,
    {
        Self::with_allow_callback(transport, callback)
    }

    /// Replaces the explicit policy implementation.
    pub fn set_policy<P>(&mut self, policy: P)
    where
        P: TcpipForwardPolicy + 'static,
    {
        self.policy = Some(Box::new(policy));
    }

    /// Replaces the policy with an exact two-argument callback.
    pub fn set_allow_callback<F>(&mut self, callback: F)
    where
        F: for<'request> Fn(&'request [u8], u32) -> bool + 'static,
    {
        self.set_policy(TwoArgumentPolicy(callback));
    }

    /// Replaces the policy with a request-object callback.
    pub fn set_request_callback<F>(&mut self, callback: F)
    where
        F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> bool + 'static,
    {
        self.set_policy(callback);
    }

    /// Replaces the policy with a decision-returning request callback.
    pub fn set_decision_callback<F>(&mut self, callback: F)
    where
        F: for<'request> Fn(TcpipForwardPolicyRequest<'request>) -> TcpipForwardDecision + 'static,
    {
        self.set_policy(DecisionPolicy(callback));
    }

    /// Removes the policy callback, restoring default-deny behavior.
    pub fn clear_policy(&mut self) {
        self.policy = None;
    }

    /// Returns whether an explicit policy is installed.
    #[must_use]
    pub fn policy_configured(&self) -> bool {
        self.policy.is_some()
    }

    /// Returns the shared channel connection.
    #[must_use]
    pub const fn connection(&self) -> &ChannelConnection<T> {
        &self.channels
    }

    /// Returns the mutable shared channel connection.
    pub const fn connection_mut(&mut self) -> &mut ChannelConnection<T> {
        &mut self.channels
    }

    /// Consumes this endpoint and returns the shared channel connection.
    #[must_use]
    pub fn into_connection(self) -> ChannelConnection<T> {
        self.channels
    }

    /// Consumes this endpoint and returns its transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.channels.into_inner()
    }

    /// Returns the number of remembered bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Returns whether an exact bind address and port is remembered.
    #[must_use]
    pub fn has_binding(&self, bind_address: &[u8], port: u32) -> bool {
        self.bindings.contains(&(bind_address.to_vec(), port))
    }

    /// Returns whether an exact bind address and port is remembered.
    #[must_use]
    pub fn is_bound(&self, bind_address: &[u8], port: u32) -> bool {
        self.has_binding(bind_address, port)
    }

    /// Returns whether an exact bind address and port is remembered.
    #[must_use]
    pub fn has_forward(&self, bind_address: &[u8], port: u32) -> bool {
        self.has_binding(bind_address, port)
    }
}

impl<T> ServerTcpipForward<T>
where
    T: ChannelTransport,
{
    /// Reads and handles one global request as one transport payload.
    ///
    /// This method intentionally reads the next transport payload directly.
    /// It must not be mixed with [`Self::dispatch_one`], which also consumes
    /// connection payloads and handles global requests while routing channels.
    ///
    /// # Errors
    ///
    /// Returns a wire, request, policy, or transport error.  A policy denial
    /// is returned as a successful [`ServerTcpipForwardRequest`] with
    /// `accepted == false`, and never as an accepted result.
    pub fn dispatch_global_request(
        &mut self,
    ) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        let payload = self
            .channels
            .transport_mut()
            .read_channel_payload()
            .map_err(|_error| TcpipForwardError::Transport)?;
        self.handle_global_request(&payload)
    }

    /// Reads and handles one global request as one transport payload.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::dispatch_global_request`].
    pub fn dispatch_request(&mut self) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        self.dispatch_global_request()
    }

    /// Reads and handles one global request as one transport payload.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::dispatch_global_request`].
    pub fn dispatch_global(&mut self) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        self.dispatch_global_request()
    }

    /// Handles one already-read global-request payload and writes its reply.
    ///
    /// # Errors
    ///
    /// Returns a wire, request, or transport error.  Policy denial is a
    /// non-error result with `accepted == false`.
    pub fn handle_global_request(
        &mut self,
        payload: &[u8],
    ) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        let request = match TcpipForwardGlobalRequest::decode(payload) {
            Ok(request) => request,
            Err(error) => {
                if global_request_wants_reply(payload) {
                    write_global_response(&mut self.channels, TcpipForwardResponse::Failure)?;
                }
                return Err(error);
            }
        };
        let (kind, bind_address, port, want_reply, accepted) = match &request {
            TcpipForwardGlobalRequest::TcpipForward {
                bind_address,
                port,
                want_reply,
            } => {
                let accepted = *port != 0 && self.authorize(bind_address, *port);
                if accepted {
                    self.bindings.insert((bind_address.clone(), *port));
                }
                (
                    TcpipForwardRequestKind::TcpipForward,
                    bind_address.clone(),
                    *port,
                    *want_reply,
                    accepted,
                )
            }
            TcpipForwardGlobalRequest::CancelTcpipForward {
                bind_address,
                port,
                want_reply,
            } => {
                let removed = self.bindings.remove(&(bind_address.clone(), *port));
                (
                    TcpipForwardRequestKind::CancelTcpipForward,
                    bind_address.clone(),
                    *port,
                    *want_reply,
                    removed,
                )
            }
            TcpipForwardGlobalRequest::Unknown { want_reply, .. } => (
                TcpipForwardRequestKind::Unknown,
                Vec::new(),
                0,
                *want_reply,
                false,
            ),
        };
        if want_reply {
            let response = if accepted {
                TcpipForwardResponse::Success
            } else {
                TcpipForwardResponse::Failure
            };
            write_global_response(&mut self.channels, response)?;
        }
        Ok(ServerTcpipForwardRequest {
            kind,
            bind_address,
            port,
            want_reply,
            accepted,
        })
    }

    /// Handles one already-read global request payload.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::handle_global_request`].
    pub fn process_global_request(
        &mut self,
        payload: &[u8],
    ) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        self.handle_global_request(payload)
    }

    /// Handles one already-read global-request payload and writes its reply.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::handle_global_request`].
    pub fn handle_global_request_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<ServerTcpipForwardRequest, TcpipForwardError> {
        self.handle_global_request(payload)
    }

    /// Opens a server-initiated `forwarded-tcpip` channel for an existing exact
    /// binding.
    ///
    /// # Errors
    ///
    /// Returns [`TcpipForwardError::NoBinding`] without opening a channel when
    /// the connected tuple does not match a remembered binding, or returns a
    /// channel, validation, or transport error.
    pub fn open_forwarded(
        &mut self,
        tuple: &ForwardedTcpipTuple,
    ) -> Result<ChannelId, TcpipForwardError> {
        let channel = self.channels.allocate_channel_id()?;
        self.open_forwarded_with_id(channel, tuple)?;
        Ok(channel)
    }

    /// Opens a server-initiated `forwarded-tcpip` channel for an existing exact
    /// binding.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_forwarded`].
    pub fn open_forwarded_channel(
        &mut self,
        tuple: &ForwardedTcpipTuple,
    ) -> Result<ChannelId, TcpipForwardError> {
        self.open_forwarded(tuple)
    }

    /// Opens a forwarded channel with a caller-selected local identifier.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_forwarded`].
    pub fn open_forwarded_with_id(
        &mut self,
        channel: ChannelId,
        tuple: &ForwardedTcpipTuple,
    ) -> Result<(), TcpipForwardError> {
        self.ensure_matching_binding(tuple)?;
        let data = tuple.encode()?;
        self.channels
            .open_channel(channel, FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes(), &data)?;
        self.open_tuples.insert(channel, tuple.clone());
        Ok(())
    }

    /// Opens a forwarded channel with explicit local receive limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_forwarded`].
    pub fn open_forwarded_with_limits(
        &mut self,
        tuple: &ForwardedTcpipTuple,
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<ChannelId, TcpipForwardError> {
        let channel = self.channels.allocate_channel_id()?;
        self.ensure_matching_binding(tuple)?;
        let data = tuple.encode()?;
        self.channels.open_channel_with_limits(
            channel,
            FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes(),
            &data,
            initial_window,
            maximum_packet_size,
        )?;
        self.open_tuples.insert(channel, tuple.clone());
        Ok(channel)
    }

    /// Reads one channel event, handles RFC 4254 port-forward requests according
    /// to the exact-binding policy, and applies that policy to inbound
    /// `forwarded-tcpip` opens.
    ///
    /// # Errors
    ///
    /// Returns a channel, wire, or transport error.
    pub fn dispatch_one(&mut self) -> Result<TcpipForwardEvent, TcpipForwardError> {
        let event = self.channels.dispatch_one()?;
        match event {
            ChannelEvent::GlobalRequest {
                request_name,
                want_reply,
                data,
            } => {
                // Re-encoding keeps the global-request decoder authoritative
                // for request-specific fields. The response is written here,
                // so report the surfaced event as already answered.
                self.handle_global_request(&reencoded_global_request(
                    &request_name,
                    want_reply,
                    &data,
                ))?;
                Ok(TcpipForwardEvent::GlobalRequest {
                    request_name,
                    want_reply: false,
                    data,
                })
            }
            ChannelEvent::OpenRequest(request) => self.handle_open_request(&request),
            event => map_channel_event(event, &mut self.open_tuples),
        }
    }

    /// Writes one bounded data packet through the shared channel window.
    ///
    /// # Errors
    ///
    /// Returns a channel-state, maximum-packet, window, or transport error.
    pub fn send_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, TcpipForwardError> {
        self.channels.write_data(channel, data).map_err(Into::into)
    }

    /// Writes one bounded data packet through the shared channel window.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::send_data`].
    pub fn write_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, TcpipForwardError> {
        self.send_data(channel, data)
    }

    /// Grants the peer more local receive credit.
    ///
    /// # Errors
    ///
    /// Returns a zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, TcpipForwardError> {
        self.channels
            .increase_local_window(channel, bytes)
            .map_err(Into::into)
    }

    /// Sends EOF through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), TcpipForwardError> {
        self.channels.send_eof(channel).map_err(Into::into)
    }

    /// Sends CLOSE through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), TcpipForwardError> {
        self.channels.send_close(channel).map_err(Into::into)
    }

    fn authorize(&self, bind_address: &[u8], port: u32) -> bool {
        let Some(policy) = &self.policy else {
            return false;
        };
        let request = TcpipForwardPolicyRequest { bind_address, port };
        matches!(
            catch_unwind(AssertUnwindSafe(|| policy.allow(request))),
            Ok(true)
        )
    }

    fn ensure_matching_binding(
        &self,
        tuple: &ForwardedTcpipTuple,
    ) -> Result<(), TcpipForwardError> {
        if self.has_binding(tuple.connected_address(), tuple.connected_port()) {
            Ok(())
        } else {
            Err(TcpipForwardError::NoBinding)
        }
    }

    fn handle_open_request(
        &mut self,
        request: &ChannelOpenRequest,
    ) -> Result<TcpipForwardEvent, TcpipForwardError> {
        let remote_channel = request.sender_channel();
        if request.channel_type() != FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes() {
            return reject_open(
                &mut self.channels,
                remote_channel,
                SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                b"unsupported channel type",
                None,
            );
        }
        let tuple = match ForwardedTcpipTuple::decode(request.type_specific_data()) {
            Ok(tuple) => tuple,
            Err(_error) => {
                return reject_open(
                    &mut self.channels,
                    remote_channel,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    b"invalid forwarded-tcpip open data",
                    None,
                );
            }
        };
        if !self.has_binding(tuple.connected_address(), tuple.connected_port()) {
            return reject_open(
                &mut self.channels,
                remote_channel,
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                b"forwarded-tcpip binding denied by policy",
                Some(tuple),
            );
        }
        let local_channel = self.channels.allocate_channel_id()?;
        self.channels.confirm_open(remote_channel, local_channel)?;
        self.open_tuples.insert(local_channel, tuple.clone());
        Ok(TcpipForwardEvent::Opened {
            channel: local_channel,
            tuple: Some(tuple),
        })
    }
}

/// Encodes a validated `tcpip-forward` global request.
///
/// # Errors
///
/// Returns a validation, wire, or packet-size error.
pub fn encode_tcpip_forward_request<A, P>(
    bind_address: A,
    port: P,
    want_reply: bool,
) -> Result<Vec<u8>, TcpipForwardError>
where
    A: AsRef<[u8]>,
    P: TryInto<u32>,
{
    TcpipForwardGlobalRequest::tcpip_forward(bind_address, port, want_reply)?.encode()
}

/// Encodes a validated `tcpip-forward` global request.
///
/// # Errors
///
/// Returns a validation, wire, or packet-size error.
pub fn encode_tcpip_forward<A, P>(
    bind_address: A,
    port: P,
    want_reply: bool,
) -> Result<Vec<u8>, TcpipForwardError>
where
    A: AsRef<[u8]>,
    P: TryInto<u32>,
{
    encode_tcpip_forward_request(bind_address, port, want_reply)
}

/// Encodes a validated `cancel-tcpip-forward` global request.
///
/// # Errors
///
/// Returns a validation, wire, or packet-size error.
pub fn encode_cancel_tcpip_forward_request<A, P>(
    bind_address: A,
    port: P,
    want_reply: bool,
) -> Result<Vec<u8>, TcpipForwardError>
where
    A: AsRef<[u8]>,
    P: TryInto<u32>,
{
    TcpipForwardGlobalRequest::cancel_tcpip_forward(bind_address, port, want_reply)?.encode()
}

/// Encodes a validated `cancel-tcpip-forward` global request.
///
/// # Errors
///
/// Returns a validation, wire, or packet-size error.
pub fn encode_cancel_tcpip_forward<A, P>(
    bind_address: A,
    port: P,
    want_reply: bool,
) -> Result<Vec<u8>, TcpipForwardError>
where
    A: AsRef<[u8]>,
    P: TryInto<u32>,
{
    encode_cancel_tcpip_forward_request(bind_address, port, want_reply)
}

/// Decodes one complete remote-forwarding global request.
///
/// # Errors
///
/// Returns a wire, request, or packet-size error.
pub fn decode_tcpip_forward_request(
    input: &[u8],
) -> Result<TcpipForwardGlobalRequest, TcpipForwardError> {
    TcpipForwardGlobalRequest::decode(input)
}

/// Decodes one complete remote-forwarding global request.
///
/// # Errors
///
/// Returns a wire, request, or packet-size error.
pub fn decode_global_request(input: &[u8]) -> Result<TcpipForwardGlobalRequest, TcpipForwardError> {
    TcpipForwardGlobalRequest::decode(input)
}

/// Encodes an exact successful global response.
///
/// # Errors
///
/// Returns [`TcpipForwardError::InvalidResponse`] if a one-byte response cannot
/// be represented.
pub fn encode_request_success() -> Result<Vec<u8>, TcpipForwardError> {
    TcpipForwardResponse::Success.encode()
}

/// Encodes an exact failed global response.
///
/// # Errors
///
/// Returns [`TcpipForwardError::InvalidResponse`] if a one-byte response cannot
/// be represented.
pub fn encode_request_failure() -> Result<Vec<u8>, TcpipForwardError> {
    TcpipForwardResponse::Failure.encode()
}

fn write_global_response<T>(
    channels: &mut ChannelConnection<T>,
    response: TcpipForwardResponse,
) -> Result<(), TcpipForwardError>
where
    T: ChannelTransport,
{
    let payload = response.encode()?;
    channels
        .transport_mut()
        .write_channel_payload(&payload)
        .map_err(|_error| TcpipForwardError::Transport)
}

fn reject_open<T>(
    channels: &mut ChannelConnection<T>,
    remote_channel: ChannelId,
    reason: u32,
    description: &[u8],
    tuple: Option<ForwardedTcpipTuple>,
) -> Result<TcpipForwardEvent, TcpipForwardError>
where
    T: ChannelTransport,
{
    channels.reject_open(remote_channel, reason, description, b"")?;
    Ok(TcpipForwardEvent::OpenRejected {
        channel: None,
        reason,
        description: description.to_vec(),
        language: Vec::new(),
        tuple,
    })
}

fn map_channel_event(
    event: ChannelEvent,
    open_tuples: &mut BTreeMap<ChannelId, ForwardedTcpipTuple>,
) -> Result<TcpipForwardEvent, TcpipForwardError> {
    match event {
        ChannelEvent::Opened(channel) => Ok(TcpipForwardEvent::Opened {
            channel,
            tuple: open_tuples.get(&channel).cloned(),
        }),
        ChannelEvent::OpenFailed {
            channel,
            reason,
            description,
            language,
        } => {
            open_tuples.remove(&channel);
            Ok(TcpipForwardEvent::OpenRejected {
                channel: Some(channel),
                reason,
                description,
                language,
                tuple: None,
            })
        }
        ChannelEvent::Data { channel, data } => Ok(TcpipForwardEvent::Data { channel, data }),
        ChannelEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        } => Ok(TcpipForwardEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        }),
        ChannelEvent::WindowAdjusted { channel, available } => {
            Ok(TcpipForwardEvent::WindowAdjusted { channel, available })
        }
        ChannelEvent::Eof { channel } => Ok(TcpipForwardEvent::Eof { channel }),
        ChannelEvent::Close { channel } => {
            open_tuples.remove(&channel);
            Ok(TcpipForwardEvent::Close { channel })
        }
        ChannelEvent::Request {
            channel,
            request_type,
            want_reply,
            data,
        } => Ok(TcpipForwardEvent::Request {
            channel,
            request_type,
            want_reply,
            data,
        }),
        ChannelEvent::RequestSucceeded { channel } => {
            Ok(TcpipForwardEvent::RequestSucceeded { channel })
        }
        ChannelEvent::RequestFailed { channel } => Ok(TcpipForwardEvent::RequestFailed { channel }),
        ChannelEvent::GlobalRequest {
            request_name,
            want_reply,
            data,
        } => Ok(TcpipForwardEvent::GlobalRequest {
            request_name,
            want_reply,
            data,
        }),
        ChannelEvent::GlobalRequestSucceeded { data } => {
            Ok(TcpipForwardEvent::GlobalRequestSucceeded { data })
        }
        ChannelEvent::GlobalRequestFailed { data } => {
            Ok(TcpipForwardEvent::GlobalRequestFailed { data })
        }
        ChannelEvent::OpenRequest(_) => Err(TcpipForwardError::UnexpectedMessage),
    }
}

fn validate_bind_address(address: &[u8]) -> Result<(), TcpipForwardError> {
    if address.len() > MAX_TCPIP_FORWARD_ADDRESS_LENGTH {
        Err(TcpipForwardError::BindAddressTooLong)
    } else {
        Ok(())
    }
}

fn validate_connected_address(address: &[u8]) -> Result<(), TcpipForwardError> {
    if address.is_empty() {
        Err(TcpipForwardError::EmptyConnectedAddress)
    } else if address.len() > MAX_TCPIP_FORWARD_ADDRESS_LENGTH {
        Err(TcpipForwardError::ConnectedAddressTooLong)
    } else {
        Ok(())
    }
}

fn validate_originator_address(address: &[u8]) -> Result<(), TcpipForwardError> {
    if address.is_empty() {
        Err(TcpipForwardError::EmptyOriginatorAddress)
    } else if address.len() > MAX_TCPIP_FORWARD_ADDRESS_LENGTH {
        Err(TcpipForwardError::OriginatorAddressTooLong)
    } else {
        Ok(())
    }
}

fn validate_port(port: u32) -> Result<(), TcpipForwardError> {
    if port > MAX_TCPIP_FORWARD_PORT {
        Err(TcpipForwardError::InvalidPort)
    } else {
        Ok(())
    }
}

fn validate_connected_port(port: u32) -> Result<(), TcpipForwardError> {
    if port == 0 || port > MAX_TCPIP_FORWARD_PORT {
        Err(TcpipForwardError::InvalidConnectedPort)
    } else {
        Ok(())
    }
}

fn validate_originator_port(port: u32) -> Result<(), TcpipForwardError> {
    if port > MAX_TCPIP_FORWARD_ORIGINATOR_PORT {
        Err(TcpipForwardError::InvalidOriginatorPort)
    } else {
        Ok(())
    }
}

fn read_bind_address(reader: &mut Reader<'_>) -> Result<Vec<u8>, TcpipForwardError> {
    reader
        .read_string_with_limit(MAX_TCPIP_FORWARD_ADDRESS_LENGTH)
        .map_err(map_bind_address_error)
        .map(ToOwned::to_owned)
}

fn read_connected_address(reader: &mut Reader<'_>) -> Result<Vec<u8>, TcpipForwardError> {
    reader
        .read_string_with_limit(MAX_TCPIP_FORWARD_ADDRESS_LENGTH)
        .map_err(map_connected_address_error)
        .map(ToOwned::to_owned)
}

fn read_originator_address(reader: &mut Reader<'_>) -> Result<Vec<u8>, TcpipForwardError> {
    reader
        .read_string_with_limit(MAX_TCPIP_FORWARD_ADDRESS_LENGTH)
        .map_err(map_originator_address_error)
        .map(ToOwned::to_owned)
}

fn map_bind_address_error(error: Error) -> TcpipForwardError {
    match error {
        Error::LimitExceeded => TcpipForwardError::BindAddressTooLong,
        other => TcpipForwardError::Wire(other),
    }
}

fn map_connected_address_error(error: Error) -> TcpipForwardError {
    match error {
        Error::LimitExceeded => TcpipForwardError::ConnectedAddressTooLong,
        other => TcpipForwardError::Wire(other),
    }
}

fn map_originator_address_error(error: Error) -> TcpipForwardError {
    match error {
        Error::LimitExceeded => TcpipForwardError::OriginatorAddressTooLong,
        other => TcpipForwardError::Wire(other),
    }
}

fn global_request_wants_reply(payload: &[u8]) -> bool {
    let mut reader = Reader::new(payload);
    if reader.read_byte().ok() != Some(SSH_MSG_GLOBAL_REQUEST) {
        return false;
    }
    if reader.read_string_with_limit(MAX_PACKET_CONTENT).is_err() {
        return false;
    }
    reader.read_boolean().is_ok_and(|value| value)
}

/// Rebuilds a global-request payload from an already-decoded channel event.
///
/// `ChannelEvent::GlobalRequest` arrives already split into its three fields,
/// while [`TcpipForwardGlobalRequest::decode`] — the one decoder that knows
/// what `tcpip-forward` and `cancel-tcpip-forward` mean — takes a payload. This
/// is the re-encoding that lets the two meet without a second decoder drifting
/// from the first.
fn reencoded_global_request(request_name: &[u8], want_reply: bool, data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
    let _ = writer.write_string_with_limit(request_name, MAX_PACKET_CONTENT);
    writer.write_boolean(want_reply);
    let mut payload = writer.into_bytes();
    payload.extend_from_slice(data);
    payload
}

fn ensure_packet_size(size: usize) -> Result<(), TcpipForwardError> {
    if size > MAX_PACKET_CONTENT {
        Err(TcpipForwardError::Wire(Error::LimitExceeded))
    } else {
        Ok(())
    }
}
