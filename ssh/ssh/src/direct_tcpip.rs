//! RFC 4254 `direct-tcpip` channel metadata and explicit forwarding policy.
//!
//! This module only carries the destination tuple and channel bytes.  It does
//! not resolve names, create a socket, or otherwise perform forwarding on
//! behalf of the application.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use neotales_ssh::{Error as WireError, Reader, Writer};

use crate::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelTransport,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
};

/// The exact RFC 4254 channel type for direct TCP/IP forwarding.
pub const DIRECT_TCPIP_CHANNEL_TYPE: &str = "direct-tcpip";
/// The maximum encoded byte length of either direct-tcpip address field.
pub const MAX_DIRECT_TCPIP_HOST_LENGTH: usize = 255;
/// The largest valid direct-tcpip TCP port.
pub const MAX_DIRECT_TCPIP_PORT: u32 = 65_535;

/// A bounded direct-tcpip protocol or channel error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectTcpipError {
    /// An SSH primitive was malformed, truncated, or could not be encoded.
    Wire(WireError),
    /// The shared channel layer rejected an operation or packet.
    Channel(ChannelError),
    /// The destination host was empty.
    EmptyDestinationHost,
    /// The destination host exceeded the bounded host limit.
    DestinationHostTooLong,
    /// The originator address was empty.
    EmptyOriginatorAddress,
    /// The originator address exceeded the bounded host limit.
    OriginatorAddressTooLong,
    /// The destination port was zero or above 65535.
    InvalidDestinationPort,
    /// The originator port was above 65535.
    InvalidOriginatorPort,
    /// Type-specific data had bytes after the fourth required field.
    TrailingBytes,
    /// A direct-tcpip open was structurally invalid.
    InvalidOpen,
    /// The server policy rejected the requested forwarding destination.
    PolicyDenied,
    /// The explicit server policy callback panicked.
    CallbackPanicked,
    /// A message was valid for the shared channel layer but not this endpoint.
    UnexpectedMessage,
}

impl fmt::Display for DirectTcpipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH direct-tcpip wire error: {error}"),
            Self::Channel(error) => write!(formatter, "SSH direct-tcpip channel error: {error}"),
            Self::EmptyDestinationHost => {
                formatter.write_str("SSH direct-tcpip destination host is empty")
            }
            Self::DestinationHostTooLong => {
                formatter.write_str("SSH direct-tcpip destination host exceeds 255 bytes")
            }
            Self::EmptyOriginatorAddress => {
                formatter.write_str("SSH direct-tcpip originator address is empty")
            }
            Self::OriginatorAddressTooLong => {
                formatter.write_str("SSH direct-tcpip originator address exceeds 255 bytes")
            }
            Self::InvalidDestinationPort => {
                formatter.write_str("SSH direct-tcpip destination port is outside the valid range")
            }
            Self::InvalidOriginatorPort => {
                formatter.write_str("SSH direct-tcpip originator port is outside the valid range")
            }
            Self::TrailingBytes => {
                formatter.write_str("SSH direct-tcpip open data has trailing bytes")
            }
            Self::InvalidOpen => formatter.write_str("SSH direct-tcpip open is invalid"),
            Self::PolicyDenied => {
                formatter.write_str("SSH direct-tcpip forwarding was denied by policy")
            }
            Self::CallbackPanicked => {
                formatter.write_str("SSH direct-tcpip policy callback panicked")
            }
            Self::UnexpectedMessage => {
                formatter.write_str("SSH direct-tcpip received an unexpected message")
            }
        }
    }
}

impl std::error::Error for DirectTcpipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Channel(error) => Some(error),
            Self::EmptyDestinationHost
            | Self::DestinationHostTooLong
            | Self::EmptyOriginatorAddress
            | Self::OriginatorAddressTooLong
            | Self::InvalidDestinationPort
            | Self::InvalidOriginatorPort
            | Self::TrailingBytes
            | Self::InvalidOpen
            | Self::PolicyDenied
            | Self::CallbackPanicked
            | Self::UnexpectedMessage => None,
        }
    }
}

impl From<WireError> for DirectTcpipError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<ChannelError> for DirectTcpipError {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

/// The validated RFC 4254 type-specific data for a direct-tcpip open.
///
/// The two address fields are deliberately byte strings.  They are not parsed
/// as numeric addresses and names are never resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectTcpipTuple {
    destination_host: Vec<u8>,
    destination_port: u32,
    originator_address: Vec<u8>,
    originator_port: u32,
}

impl DirectTcpipTuple {
    /// Creates a validated destination/originator tuple.
    ///
    /// `destination_port` must be nonzero and both ports must fit in the RFC
    /// TCP port range.  Originator port zero is valid.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty or overlong address, an invalid
    /// destination port, or an originator port above 65535.
    pub fn new<H, O, P, Q>(
        destination_host: H,
        destination_port: P,
        originator_address: O,
        originator_port: Q,
    ) -> Result<Self, DirectTcpipError>
    where
        H: AsRef<[u8]>,
        O: AsRef<[u8]>,
        P: TryInto<u32>,
        Q: TryInto<u32>,
    {
        let destination_port = destination_port
            .try_into()
            .map_err(|_error| DirectTcpipError::InvalidDestinationPort)?;
        let originator_port = originator_port
            .try_into()
            .map_err(|_error| DirectTcpipError::InvalidOriginatorPort)?;
        Self::from_bytes(
            destination_host.as_ref(),
            destination_port,
            originator_address.as_ref(),
            originator_port,
        )
    }

    /// Creates a validated tuple from borrowed address bytes.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn from_bytes(
        destination_host: &[u8],
        destination_port: u32,
        originator_address: &[u8],
        originator_port: u32,
    ) -> Result<Self, DirectTcpipError> {
        validate_address(destination_host, false)?;
        validate_address(originator_address, true)?;
        validate_ports(destination_port, originator_port)?;
        Ok(Self {
            destination_host: destination_host.to_vec(),
            destination_port,
            originator_address: originator_address.to_vec(),
            originator_port,
        })
    }

    /// Returns the exact destination host bytes.
    #[must_use]
    pub fn destination_host(&self) -> &[u8] {
        &self.destination_host
    }

    /// Returns the destination TCP port.
    #[must_use]
    pub const fn destination_port(&self) -> u32 {
        self.destination_port
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

    /// Returns this tuple as a borrowed policy request.
    #[must_use]
    pub fn as_request(&self) -> DirectTcpipRequest<'_> {
        DirectTcpipRequest {
            destination_host: &self.destination_host,
            destination_port: self.destination_port,
            originator_address: &self.originator_address,
            originator_port: self.originator_port,
        }
    }

    /// Encodes the four RFC 4254 fields in their required wire order.
    ///
    /// # Errors
    ///
    /// Returns a wire error if a bounded field cannot be represented as an SSH
    /// string.
    pub fn encode(&self) -> Result<Vec<u8>, DirectTcpipError> {
        validate_address(&self.destination_host, false)?;
        validate_address(&self.originator_address, true)?;
        validate_ports(self.destination_port, self.originator_port)?;
        let mut writer = Writer::new();
        writer.write_string_with_limit(&self.destination_host, MAX_DIRECT_TCPIP_HOST_LENGTH)?;
        writer.write_uint32(self.destination_port);
        writer.write_string_with_limit(&self.originator_address, MAX_DIRECT_TCPIP_HOST_LENGTH)?;
        writer.write_uint32(self.originator_port);
        Ok(writer.into_bytes())
    }

    /// Decodes exactly the four RFC 4254 fields in their required wire order.
    ///
    /// # Errors
    ///
    /// Returns a wire, address, port, or trailing-data error for malformed
    /// type-specific data.
    pub fn decode(data: &[u8]) -> Result<Self, DirectTcpipError> {
        let mut reader = Reader::new(data);
        let destination_host = read_address(&mut reader, false)?.to_vec();
        let destination_port = reader.read_uint32()?;
        let originator_address = read_address(&mut reader, true)?.to_vec();
        let originator_port = reader.read_uint32()?;
        if !reader.is_empty() {
            return Err(DirectTcpipError::TrailingBytes);
        }
        validate_address(&destination_host, false)?;
        validate_address(&originator_address, true)?;
        validate_ports(destination_port, originator_port)?;
        Ok(Self {
            destination_host,
            destination_port,
            originator_address,
            originator_port,
        })
    }

    /// Encodes this tuple as channel-open type-specific data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn encode_type_specific_data(&self) -> Result<Vec<u8>, DirectTcpipError> {
        self.encode()
    }

    /// Decodes channel-open type-specific data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn decode_type_specific_data(data: &[u8]) -> Result<Self, DirectTcpipError> {
        Self::decode(data)
    }
}

/// A descriptive alias for the direct-tcpip open tuple.
pub type DirectTcpipOpenData = DirectTcpipTuple;

/// A borrowed exact tuple passed to an explicit server policy callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectTcpipRequest<'request> {
    /// Exact destination host bytes received from the peer.
    pub destination_host: &'request [u8],
    /// Destination TCP port received from the peer.
    pub destination_port: u32,
    /// Exact originator address bytes received from the peer.
    pub originator_address: &'request [u8],
    /// Originator TCP port received from the peer.
    pub originator_port: u32,
}

impl<'request> DirectTcpipRequest<'request> {
    /// Returns the exact destination host bytes.
    #[must_use]
    pub const fn destination_host(&self) -> &'request [u8] {
        self.destination_host
    }

    /// Returns the destination TCP port.
    #[must_use]
    pub const fn destination_port(&self) -> u32 {
        self.destination_port
    }

    /// Returns the exact originator address bytes.
    #[must_use]
    pub const fn originator_address(&self) -> &'request [u8] {
        self.originator_address
    }

    /// Returns the originator TCP port.
    #[must_use]
    pub const fn originator_port(&self) -> u32 {
        self.originator_port
    }
}

/// A boolean decision returned by a direct-tcpip policy implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectTcpipDecision(bool);

impl DirectTcpipDecision {
    /// Accepts the exact requested tuple.
    #[must_use]
    pub const fn accept() -> Self {
        Self(true)
    }

    /// Rejects the exact requested tuple.
    #[must_use]
    pub const fn reject() -> Self {
        Self(false)
    }

    /// Returns whether the tuple was accepted.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.0
    }
}

/// Explicit authorization policy for inbound direct-tcpip opens.
///
/// There is no accepting default implementation.  A server constructed
/// without a policy rejects every open.
pub trait DirectTcpipPolicy {
    /// Returns `true` only for a tuple that the application authorizes.
    fn allow(&self, request: DirectTcpipRequest<'_>) -> bool;
}

impl<F> DirectTcpipPolicy for F
where
    F: for<'request> Fn(DirectTcpipRequest<'request>) -> bool + ?Sized,
{
    fn allow(&self, request: DirectTcpipRequest<'_>) -> bool {
        self(request)
    }
}

struct FourArgumentPolicy<F>(F);

impl<F> DirectTcpipPolicy for FourArgumentPolicy<F>
where
    F: for<'request> Fn(&'request [u8], u32, &'request [u8], u32) -> bool,
{
    fn allow(&self, request: DirectTcpipRequest<'_>) -> bool {
        (self.0)(
            request.destination_host,
            request.destination_port,
            request.originator_address,
            request.originator_port,
        )
    }
}

struct DecisionPolicy<F>(F);

impl<F> DirectTcpipPolicy for DecisionPolicy<F>
where
    F: for<'request> Fn(DirectTcpipRequest<'request>) -> DirectTcpipDecision,
{
    fn allow(&self, request: DirectTcpipRequest<'_>) -> bool {
        (self.0)(request).accepted()
    }
}

/// One routed client/server direct-tcpip event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectTcpipEvent {
    /// A locally opened channel was confirmed by the peer.
    Opened {
        /// The local recipient channel identifier.
        channel: ChannelId,
    },
    /// A local open was rejected by the peer or an explicit policy.
    OpenRejected {
        /// The rejected local sender identifier, or `None` for a server-side
        /// rejection before confirmation.
        channel: Option<ChannelId>,
        /// RFC 4254 numeric rejection reason.
        reason: u32,
        /// Human-readable diagnostic bytes.
        description: Vec<u8>,
        /// RFC 4250 language tag bytes.
        language: Vec<u8>,
    },
    /// The peer granted more credit for data sent on this channel.
    WindowAdjusted {
        /// The recipient channel identifier.
        channel: ChannelId,
        /// Newly available remote credit.
        available: u32,
    },
    /// A complete bounded data packet arrived.
    Data {
        /// The recipient channel identifier.
        channel: ChannelId,
        /// The data bytes.
        data: Vec<u8>,
    },
    /// Extended data received on this channel.
    ExtendedData {
        /// The recipient channel identifier.
        channel: ChannelId,
        /// RFC 4254 extended-data type code.
        data_type_code: u32,
        /// The extended-data bytes.
        data: Vec<u8>,
    },
    /// The peer will send no more data on this channel.
    Eof {
        /// The recipient channel identifier.
        channel: ChannelId,
    },
    /// The peer closed this channel.
    Close {
        /// The recipient channel identifier.
        channel: ChannelId,
    },
}

/// A client-side direct-tcpip endpoint over one authenticated connection.
#[derive(Debug)]
pub struct ClientDirectTcpip<T> {
    channels: ChannelConnection<T>,
}

impl<T> ClientDirectTcpip<T> {
    /// Wraps one already authenticated client transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
        }
    }

    /// Reuses an existing shared channel connection.
    #[must_use]
    pub const fn from_connection(channels: ChannelConnection<T>) -> Self {
        Self { channels }
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

impl<T> ClientDirectTcpip<T>
where
    T: ChannelTransport,
{
    /// Allocates a local channel and sends a validated direct-tcpip open.
    ///
    /// The returned identifier is pending until [`Self::dispatch_one`] returns
    /// [`DirectTcpipEvent::Opened`].
    ///
    /// # Errors
    ///
    /// Returns a validation, channel-allocation, or transport error.  A tuple
    /// is encoded before the shared channel manager is called, so invalid data
    /// cannot register a local channel.
    pub fn open(&mut self, tuple: &DirectTcpipTuple) -> Result<ChannelId, DirectTcpipError> {
        let channel = self.channels.allocate_channel_id()?;
        self.open_with_id(channel, tuple)?;
        Ok(channel)
    }

    /// Sends a validated direct-tcpip open with a caller-selected local id.
    ///
    /// # Errors
    ///
    /// Returns a validation, duplicate-id, limit, or transport error.
    pub fn open_with_id(
        &mut self,
        channel: ChannelId,
        tuple: &DirectTcpipTuple,
    ) -> Result<(), DirectTcpipError> {
        let data = tuple.encode()?;
        self.channels
            .open_channel(channel, DIRECT_TCPIP_CHANNEL_TYPE.as_bytes(), &data)?;
        Ok(())
    }

    /// Allocates a local channel with explicit receive limits.
    ///
    /// # Errors
    ///
    /// Returns a validation, channel-allocation, limit, or transport error.
    pub fn open_with_limits(
        &mut self,
        tuple: &DirectTcpipTuple,
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<ChannelId, DirectTcpipError> {
        let channel = self.channels.allocate_channel_id()?;
        self.open_with_id_and_limits(channel, tuple, initial_window, maximum_packet_size)?;
        Ok(channel)
    }

    /// Sends a direct-tcpip open with a selected id and explicit receive limits.
    ///
    /// # Errors
    ///
    /// Returns a validation, duplicate-id, limit, or transport error.
    pub fn open_with_id_and_limits(
        &mut self,
        channel: ChannelId,
        tuple: &DirectTcpipTuple,
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<(), DirectTcpipError> {
        let data = tuple.encode()?;
        self.channels.open_channel_with_limits(
            channel,
            DIRECT_TCPIP_CHANNEL_TYPE.as_bytes(),
            &data,
            initial_window,
            maximum_packet_size,
        )?;
        Ok(())
    }

    /// Alias for [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_direct_tcpip(
        &mut self,
        tuple: &DirectTcpipTuple,
    ) -> Result<ChannelId, DirectTcpipError> {
        self.open(tuple)
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
    ) -> Result<usize, DirectTcpipError> {
        self.channels.write_data(channel, data)?;
        Ok(data.len())
    }

    /// Alias for [`Self::send_data`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::send_data`].
    pub fn write_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, DirectTcpipError> {
        self.send_data(channel, data)
    }

    /// Grants the peer more local receive credit through the shared window path.
    ///
    /// # Errors
    ///
    /// Returns a zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, DirectTcpipError> {
        self.channels
            .increase_local_window(channel, bytes)
            .map_err(Into::into)
    }

    /// Sends EOF through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), DirectTcpipError> {
        self.channels.send_eof(channel)?;
        Ok(())
    }

    /// Sends CLOSE through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), DirectTcpipError> {
        self.channels.send_close(channel)?;
        Ok(())
    }

    /// Reads and routes one complete direct-tcpip channel event.
    ///
    /// # Errors
    ///
    /// Returns a transport, wire, channel, or unexpected-message error.
    pub fn dispatch_one(&mut self) -> Result<DirectTcpipEvent, DirectTcpipError> {
        map_client_event(require_event(self.channels.dispatch_channel_event()?)?)
    }
}

/// A server-side direct-tcpip endpoint with a default-deny policy boundary.
pub struct ServerDirectTcpip<T> {
    channels: ChannelConnection<T>,
    policy: Option<Box<dyn DirectTcpipPolicy>>,
}

impl<T> fmt::Debug for ServerDirectTcpip<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerDirectTcpip")
            .field("channel_count", &self.channels.channel_count())
            .field("pending_open_count", &self.channels.pending_open_count())
            .field("policy_configured", &self.policy.is_some())
            .finish()
    }
}

impl<T> ServerDirectTcpip<T> {
    /// Creates a default-deny server endpoint.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
            policy: None,
        }
    }

    /// Creates a server endpoint with one explicit policy implementation.
    #[must_use]
    pub fn with_policy<P>(transport: T, policy: P) -> Self
    where
        P: DirectTcpipPolicy + 'static,
    {
        let mut server = Self::new(transport);
        server.policy = Some(Box::new(policy));
        server
    }

    /// Creates a server endpoint with a four-argument allow callback.
    ///
    /// The callback receives the exact destination host and port followed by
    /// the exact originator address and port.
    #[must_use]
    pub fn with_allow_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(&'request [u8], u32, &'request [u8], u32) -> bool + 'static,
    {
        Self::with_policy(transport, FourArgumentPolicy(callback))
    }

    /// Creates a server endpoint with a decision-returning request callback.
    #[must_use]
    pub fn with_decision_callback<F>(transport: T, callback: F) -> Self
    where
        F: for<'request> Fn(DirectTcpipRequest<'request>) -> DirectTcpipDecision + 'static,
    {
        Self::with_policy(transport, DecisionPolicy(callback))
    }

    /// Replaces the explicit policy implementation.
    pub fn set_policy<P>(&mut self, policy: P)
    where
        P: DirectTcpipPolicy + 'static,
    {
        self.policy = Some(Box::new(policy));
    }

    /// Replaces the policy with a four-argument allow callback.
    pub fn set_allow_callback<F>(&mut self, callback: F)
    where
        F: for<'request> Fn(&'request [u8], u32, &'request [u8], u32) -> bool + 'static,
    {
        self.set_policy(FourArgumentPolicy(callback));
    }

    /// Removes all policy callbacks, restoring default-deny behavior.
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
}

impl<T> ServerDirectTcpip<T>
where
    T: ChannelTransport,
{
    /// Reads one channel packet and applies the explicit direct-tcpip policy.
    ///
    /// # Errors
    ///
    /// Returns a channel, transport, callback, or unexpected-message error.
    /// An open is confirmed only after its tuple validates and the installed
    /// policy returns `true`.
    pub fn dispatch_one(&mut self) -> Result<DirectTcpipEvent, DirectTcpipError> {
        let event = require_event(self.channels.dispatch_channel_event()?)?;
        match event {
            ChannelEvent::OpenRequest(request) => self.handle_open(&request),
            ChannelEvent::Opened(_)
            | ChannelEvent::OpenFailed { .. }
            | ChannelEvent::Request { .. }
            | ChannelEvent::RequestSucceeded { .. }
            | ChannelEvent::RequestFailed { .. } => Err(DirectTcpipError::UnexpectedMessage),
            other => map_established_event(other),
        }
    }

    /// Writes one bounded data packet after an accepted open.
    ///
    /// # Errors
    ///
    /// Returns a channel-state, maximum-packet, window, or transport error.
    pub fn send_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, DirectTcpipError> {
        self.channels.write_data(channel, data)?;
        Ok(data.len())
    }

    /// Alias for [`Self::send_data`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::send_data`].
    pub fn write_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<usize, DirectTcpipError> {
        self.send_data(channel, data)
    }

    /// Grants the peer more local receive credit through the shared window path.
    ///
    /// # Errors
    ///
    /// Returns a zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, DirectTcpipError> {
        self.channels
            .increase_local_window(channel, bytes)
            .map_err(Into::into)
    }

    /// Sends EOF through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), DirectTcpipError> {
        self.channels.send_eof(channel)?;
        Ok(())
    }

    /// Sends CLOSE through the shared channel lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), DirectTcpipError> {
        self.channels.send_close(channel)?;
        Ok(())
    }

    fn handle_open(
        &mut self,
        request: &crate::channel::ChannelOpenRequest,
    ) -> Result<DirectTcpipEvent, DirectTcpipError> {
        let remote_channel = request.sender_channel();
        if request.channel_type() != DIRECT_TCPIP_CHANNEL_TYPE.as_bytes() {
            return self.reject_open(
                remote_channel,
                SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                b"unsupported channel type",
            );
        }
        let tuple = match DirectTcpipTuple::decode(request.type_specific_data()) {
            Ok(tuple) => tuple,
            Err(_error) => {
                return self.reject_open(
                    remote_channel,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    b"invalid direct-tcpip open data",
                );
            }
        };
        let accepted = match &self.policy {
            Some(policy) => {
                match catch_unwind(AssertUnwindSafe(|| policy.allow(tuple.as_request()))) {
                    Ok(accepted) => accepted,
                    Err(_panic_payload) => {
                        self.reject_open(
                            remote_channel,
                            SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                            b"direct-tcpip policy callback failed",
                        )?;
                        return Err(DirectTcpipError::CallbackPanicked);
                    }
                }
            }
            None => false,
        };
        if !accepted {
            return self.reject_open(
                remote_channel,
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                b"direct-tcpip denied by policy",
            );
        }
        let local_channel = self.channels.allocate_channel_id()?;
        self.channels.confirm_open(remote_channel, local_channel)?;
        Ok(DirectTcpipEvent::Opened {
            channel: local_channel,
        })
    }

    fn reject_open(
        &mut self,
        remote_channel: ChannelId,
        reason: u32,
        description: &[u8],
    ) -> Result<DirectTcpipEvent, DirectTcpipError> {
        self.channels
            .reject_open(remote_channel, reason, description, b"")?;
        Ok(DirectTcpipEvent::OpenRejected {
            channel: None,
            reason,
            description: description.to_vec(),
            language: Vec::new(),
        })
    }
}

fn map_client_event(event: ChannelEvent) -> Result<DirectTcpipEvent, DirectTcpipError> {
    match event {
        ChannelEvent::Opened(channel) => Ok(DirectTcpipEvent::Opened { channel }),
        ChannelEvent::OpenFailed {
            channel,
            reason,
            description,
            language,
        } => Ok(DirectTcpipEvent::OpenRejected {
            channel: Some(channel),
            reason,
            description,
            language,
        }),
        ChannelEvent::OpenRequest(_)
        | ChannelEvent::Request { .. }
        | ChannelEvent::RequestSucceeded { .. }
        | ChannelEvent::RequestFailed { .. } => Err(DirectTcpipError::UnexpectedMessage),
        other => map_established_event(other),
    }
}

fn map_established_event(event: ChannelEvent) -> Result<DirectTcpipEvent, DirectTcpipError> {
    match event {
        ChannelEvent::WindowAdjusted { channel, available } => {
            Ok(DirectTcpipEvent::WindowAdjusted { channel, available })
        }
        ChannelEvent::Data { channel, data } => Ok(DirectTcpipEvent::Data { channel, data }),
        ChannelEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        } => Ok(DirectTcpipEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        }),
        ChannelEvent::Eof { channel } => Ok(DirectTcpipEvent::Eof { channel }),
        ChannelEvent::Close { channel } => Ok(DirectTcpipEvent::Close { channel }),
        ChannelEvent::Opened(_)
        | ChannelEvent::OpenFailed { .. }
        | ChannelEvent::OpenRequest(_)
        | ChannelEvent::Request { .. }
        | ChannelEvent::RequestSucceeded { .. }
        | ChannelEvent::RequestFailed { .. }
        | ChannelEvent::GlobalRequest { .. }
        | ChannelEvent::GlobalRequestSucceeded { .. }
        | ChannelEvent::GlobalRequestFailed { .. } => Err(DirectTcpipError::UnexpectedMessage),
    }
}

fn validate_address(address: &[u8], originator: bool) -> Result<(), DirectTcpipError> {
    if address.is_empty() {
        if originator {
            Err(DirectTcpipError::EmptyOriginatorAddress)
        } else {
            Err(DirectTcpipError::EmptyDestinationHost)
        }
    } else if address.len() > MAX_DIRECT_TCPIP_HOST_LENGTH {
        if originator {
            Err(DirectTcpipError::OriginatorAddressTooLong)
        } else {
            Err(DirectTcpipError::DestinationHostTooLong)
        }
    } else {
        Ok(())
    }
}

fn read_address<'a>(
    reader: &mut Reader<'a>,
    originator: bool,
) -> Result<&'a [u8], DirectTcpipError> {
    reader
        .read_string_with_limit(MAX_DIRECT_TCPIP_HOST_LENGTH)
        .map_err(|error| match error {
            WireError::LimitExceeded if originator => DirectTcpipError::OriginatorAddressTooLong,
            WireError::LimitExceeded => DirectTcpipError::DestinationHostTooLong,
            other => DirectTcpipError::Wire(other),
        })
}

fn validate_ports(destination_port: u32, originator_port: u32) -> Result<(), DirectTcpipError> {
    if destination_port == 0 || destination_port > MAX_DIRECT_TCPIP_PORT {
        Err(DirectTcpipError::InvalidDestinationPort)
    } else if originator_port > MAX_DIRECT_TCPIP_PORT {
        Err(DirectTcpipError::InvalidOriginatorPort)
    } else {
        Ok(())
    }
}

/// Unwraps one channel event, rejecting a payload that carried none.
///
/// [`ChannelConnection::dispatch_channel_event`] returns `None` when the
/// transport produced no channel event, which after a successful read means
/// the peer sent only connection-level messages this endpoint does not act on.
/// That is not a reason to fail a direct-tcpip call that is otherwise fine.
fn require_event(event: Option<ChannelEvent>) -> Result<ChannelEvent, DirectTcpipError> {
    event.ok_or(DirectTcpipError::UnexpectedMessage)
}
