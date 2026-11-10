//! RFC 4254 connection-level channel multiplexing and flow control.
//!
//! [`ChannelConnection`] owns exactly one authenticated packet transport and
//! serializes every channel write through that value. It does not buffer
//! channel data: each call to [`ChannelConnection::dispatch_one`] reads one
//! transport payload, validates it completely, accounts any received window
//! credit, and returns one bounded event to the caller.
//!
//! # Connection-level messages
//!
//! A channel multiplexer is not the only thing on an authenticated
//! connection, and RFC 4254 §4 says so of global requests: "both the client
//! and server MAY send global requests at any time, and the receiver MUST
//! respond appropriately". [`ChannelConnection::dispatch_one`] therefore
//! tolerates the message numbers that are legal at any time on an
//! established connection and routes each one to the treatment RFC 4253 §11
//! and RFC 4254 §4 give it. See [`ChannelConnection::dispatch_one`] for the
//! exact split, because which of the three it is — handled, dropped, or
//! surfaced — is a contract and not an implementation detail.
//!
//! A current OpenSSH server sends `SSH_MSG_GLOBAL_REQUEST`
//! `hostkeys-00@openssh.com` as the very first payload after
//! `SSH_MSG_USERAUTH_SUCCESS`, ahead of anything the client asked for. A
//! multiplexer that treats that as fatal cannot open a channel against a
//! current OpenSSH at all.

use std::fmt;
use std::io::{Read, Write};

use neotales_ssh::{Error as WireError, MAX_PACKET_CONTENT, MIN_PADDING, Reader, Writer};

use crate::cipher::AES_BLOCK_SIZE;
use crate::client::ClientTransport;
use crate::server::ServerTransport;

/// SSH message number for `SSH_MSG_CHANNEL_OPEN`.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// SSH message number for `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// SSH message number for `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// SSH message number for `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// SSH message number for `SSH_MSG_CHANNEL_DATA`.
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// SSH message number for `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// SSH message number for `SSH_MSG_CHANNEL_EOF`.
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
/// SSH message number for `SSH_MSG_CHANNEL_CLOSE`.
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
/// SSH message number for `SSH_MSG_CHANNEL_REQUEST`.
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// SSH message number for `SSH_MSG_CHANNEL_SUCCESS`.
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// SSH message number for `SSH_MSG_CHANNEL_FAILURE`.
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

// The transport-layer and connection-layer message numbers below are the ones
// RFC 4253 §12 and RFC 4254 §9 assign. They are declared here rather than
// imported so that a multiplexer built on this type does not have to reach
// through the handshake's private sequence layer for values this file has to
// recognise on every packet.

/// `SSH_MSG_IGNORE`, RFC 4253 §11.2.
pub const SSH_MSG_IGNORE: u8 = 2;
/// `SSH_MSG_UNIMPLEMENTED`, RFC 4253 §11.4.
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
/// `SSH_MSG_DEBUG`, RFC 4253 §11.3.
pub const SSH_MSG_DEBUG: u8 = 4;
/// `SSH_MSG_GLOBAL_REQUEST`, RFC 4254 §4.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// `SSH_MSG_REQUEST_SUCCESS`, RFC 4254 §4.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
/// `SSH_MSG_REQUEST_FAILURE`, RFC 4254 §4.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// The local receive window advertised by default for every channel.
pub const INITIAL_CHANNEL_WINDOW: u32 = 65_536;
/// The largest channel-data payload advertised by default.
pub const MAX_CHANNEL_PACKET_SIZE: u32 = 32_768;
const MAX_CHANNEL_PADDING_SIZE: usize = AES_BLOCK_SIZE + MIN_PADDING - 1;
const MAX_DEFLATE_OVERHEAD: usize =
    MAX_PACKET_CONTENT / 4_096 + MAX_PACKET_CONTENT / 16_384 + MAX_PACKET_CONTENT / 33_554_432 + 13;
const MAX_CHANNEL_MESSAGE_SIZE: usize =
    MAX_PACKET_CONTENT - MAX_CHANNEL_PADDING_SIZE - MAX_DEFLATE_OVERHEAD;
/// The largest channel-data payload this implementation can safely frame.
///
/// The bound leaves room for extended-data message fields, the largest padding
/// used by supported packet ciphers, and zlib's worst-case expansion at the
/// transport payload limit. The compression allowance is calculated at the
/// full transport limit, leaving two bytes of additional headroom at this cap.
pub const MAX_CHANNEL_DATA_SIZE: usize = MAX_CHANNEL_MESSAGE_SIZE - 13;
/// The maximum number of live or pending channels retained by one connection.
pub const MAX_CHANNELS_PER_CONNECTION: usize = 1_024;
/// The maximum encoded length accepted for a channel type or request name.
pub const MAX_CHANNEL_NAME_LENGTH: usize = 256;

/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `SSH_OPEN_CONNECT_FAILED`.
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
/// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
/// `SSH_OPEN_RESOURCE_SHORTAGE`.
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

/// An RFC 4254 channel identifier local to one side of a connection.
pub type ChannelId = u32;

/// A bounded channel-window failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowError {
    /// A complete data write did not fit in the peer's remaining credit.
    Insufficient {
        /// Credit still available to the sender.
        available: u32,
        /// Number of data bytes the caller attempted to write.
        requested: usize,
    },
    /// A window adjustment would exceed the RFC 4254 `uint32` range.
    AdjustmentOverflow {
        /// Current local or remote window before the rejected adjustment.
        current: u32,
        /// Increment in the rejected adjustment.
        increment: u32,
    },
}

impl fmt::Display for WindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient {
                available,
                requested,
            } => write!(
                formatter,
                "channel data requires {requested} bytes but only {available} bytes of window remain"
            ),
            Self::AdjustmentOverflow { current, increment } => write!(
                formatter,
                "channel window adjustment {current} + {increment} overflows u32"
            ),
        }
    }
}

impl std::error::Error for WindowError {}

/// A bounded channel protocol or transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// An SSH primitive was malformed or truncated.
    Wire(WireError),
    /// The underlying protected transport failed.
    Transport,
    /// A channel packet was structurally invalid for an open channel.
    InvalidMessage,
    /// A channel-open advertisement was invalid.
    InvalidOpen,
    /// A zero window adjustment was supplied.
    InvalidWindowAdjustment,
    /// The requested recipient channel is unknown.
    UnknownChannel,
    /// A local or remote channel identifier is already active.
    DuplicateChannel,
    /// The bounded per-connection channel count was exhausted.
    TooManyChannels,
    /// No unused local channel identifier remains.
    ChannelIdExhausted,
    /// A message type is not valid at this layer or channel state.
    UnexpectedMessage(u8),
    /// Data was received after the peer's EOF.
    DataAfterEof,
    /// Flow-control accounting failed.
    Window(WindowError),
    /// Received data exceeded the recipient's advertised local window.
    WindowExceeded {
        /// Local credit available before this packet.
        available: u32,
        /// Data bytes carried by the rejected packet.
        received: usize,
    },
    /// A data write exceeded the effective maximum data size for that channel.
    PacketTooLarge {
        /// Maximum data bytes permitted in this channel packet.
        maximum: u32,
        /// Data bytes the caller attempted to write.
        requested: usize,
    },
    /// A complete encoded channel message exceeded the transport bound.
    MessageTooLarge,
    /// A channel message named a channel that both sides had already closed.
    ///
    /// RFC 4254 §5.3: "The channel is considered closed for a party when it
    /// has both sent and received `SSH_MSG_CHANNEL_CLOSE`". Once that is true
    /// the channel is gone from the table, and OpenSSH disconnects on a
    /// message for a channel it no longer has — `channel_from_packet_id`
    /// calls `ssh_packet_disconnect(ssh, "%s packet referred to nonexistent
    /// channel %d")`. This error is that condition, reported without the
    /// disconnect so a caller can decide.
    ClosedChannel(ChannelId),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH channel wire error: {error}"),
            Self::Transport => formatter.write_str("SSH channel transport failed"),
            Self::InvalidMessage => formatter.write_str("SSH channel message is invalid"),
            Self::InvalidOpen => formatter.write_str("SSH channel-open message is invalid"),
            Self::InvalidWindowAdjustment => {
                formatter.write_str("SSH channel window adjustment must be nonzero")
            }
            Self::UnknownChannel => formatter.write_str("SSH channel identifier is unknown"),
            Self::DuplicateChannel => {
                formatter.write_str("SSH channel identifier is already active")
            }
            Self::TooManyChannels => {
                formatter.write_str("SSH connection channel limit was exhausted")
            }
            Self::ChannelIdExhausted => {
                formatter.write_str("SSH local channel identifiers were exhausted")
            }
            Self::UnexpectedMessage(message) => {
                write!(
                    formatter,
                    "SSH channel received unexpected message {message}"
                )
            }
            Self::DataAfterEof => formatter.write_str("SSH channel data arrived after peer EOF"),
            Self::Window(error) => write!(formatter, "SSH channel window error: {error}"),
            Self::WindowExceeded {
                available,
                received,
            } => write!(
                formatter,
                "SSH channel received {received} bytes with only {available} bytes of local window"
            ),
            Self::PacketTooLarge { maximum, requested } => write!(
                formatter,
                "SSH channel data requires {requested} bytes but the peer maximum is {maximum}"
            ),
            Self::MessageTooLarge => {
                formatter.write_str("SSH channel message exceeds the transport limit")
            }
            Self::ClosedChannel(channel) => write!(
                formatter,
                "SSH channel {channel} was addressed after both sides closed it"
            ),
        }
    }
}

impl std::error::Error for ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Transport
            | Self::InvalidMessage
            | Self::InvalidOpen
            | Self::InvalidWindowAdjustment
            | Self::UnknownChannel
            | Self::DuplicateChannel
            | Self::TooManyChannels
            | Self::ChannelIdExhausted
            | Self::UnexpectedMessage(_)
            | Self::DataAfterEof
            | Self::Window(_)
            | Self::WindowExceeded { .. }
            | Self::PacketTooLarge { .. }
            | Self::MessageTooLarge
            | Self::ClosedChannel(_) => None,
        }
    }
}

impl From<WireError> for ChannelError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// The minimal packet boundary required by a channel multiplexer.
///
/// Client and server protected transports implement this trait. Applications
/// and later channel types can also provide another single serialized writer.
pub trait ChannelTransport {
    /// Writes one complete nonempty SSH payload.
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()>;

    /// Reads and consumes one complete SSH payload.
    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()>;
}

impl<S> ChannelTransport for ClientTransport<S>
where
    S: Read + Write,
{
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.write_payload(payload).map_err(|_error| ())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.read_payload().map_err(|_error| ())
    }
}

impl<S> ChannelTransport for ServerTransport<S>
where
    S: Read + Write,
{
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.write_payload(payload).map_err(|_error| ())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.read_payload().map_err(|_error| ())
    }
}

/// A validated inbound `SSH_MSG_CHANNEL_OPEN` request.
///
/// Type-specific bytes are kept opaque by the shared channel layer. Session
/// rejects all bytes after the four standard open fields, while a later channel
/// type can decode its own bounded payload without changing packet or window
/// handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpenRequest {
    channel_type: Vec<u8>,
    sender_channel: ChannelId,
    initial_window: u32,
    maximum_packet_size: u32,
    type_specific_data: Vec<u8>,
}

impl ChannelOpenRequest {
    /// Returns the requested channel type.
    #[must_use]
    pub fn channel_type(&self) -> &[u8] {
        &self.channel_type
    }

    /// Returns the sender-selected channel identifier.
    #[must_use]
    pub const fn sender_channel(&self) -> ChannelId {
        self.sender_channel
    }

    /// Returns the peer's advertised receive window.
    #[must_use]
    pub const fn initial_window(&self) -> u32 {
        self.initial_window
    }

    /// Returns the peer's advertised maximum channel-data packet size.
    #[must_use]
    pub const fn maximum_packet_size(&self) -> u32 {
        self.maximum_packet_size
    }

    /// Returns the bounded type-specific open bytes.
    #[must_use]
    pub fn type_specific_data(&self) -> &[u8] {
        &self.type_specific_data
    }
}

/// One completely parsed and routed channel event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    /// A peer requested a new channel.
    OpenRequest(ChannelOpenRequest),
    /// The peer confirmed a locally opened channel.
    Opened(ChannelId),
    /// The peer rejected a locally opened channel.
    OpenFailed {
        /// The local sender channel that was rejected.
        channel: ChannelId,
        /// RFC 4254 numeric rejection reason.
        reason: u32,
        /// Human-readable diagnostic supplied by the peer.
        description: Vec<u8>,
        /// RFC 4250 language tag supplied by the peer.
        language: Vec<u8>,
    },
    /// The peer granted additional credit for data sent to its channel.
    WindowAdjusted {
        /// The recipient channel receiving the adjustment.
        channel: ChannelId,
        /// Newly available remote credit after the adjustment.
        available: u32,
    },
    /// A complete data packet was charged to the local receive window.
    Data {
        /// The recipient channel.
        channel: ChannelId,
        /// The bounded data bytes.
        data: Vec<u8>,
    },
    /// A complete extended-data packet was charged to the local receive window.
    ExtendedData {
        /// The recipient channel.
        channel: ChannelId,
        /// RFC 4254 extended-data type code (1 is `SSH_EXTENDED_DATA_STDERR`).
        data_type_code: u32,
        /// The bounded extended-data bytes.
        data: Vec<u8>,
    },
    /// The peer will send no more data on this channel.
    Eof {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer closed this channel.
    Close {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// A channel request whose type-specific bytes remain application-defined.
    Request {
        /// The recipient channel.
        channel: ChannelId,
        /// SSH request type.
        request_type: Vec<u8>,
        /// Whether the requester asked for SUCCESS or FAILURE.
        want_reply: bool,
        /// Bounded request-specific bytes.
        data: Vec<u8>,
    },
    /// The peer answered a request with `SSH_MSG_CHANNEL_SUCCESS`.
    RequestSucceeded {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer answered a request with `SSH_MSG_CHANNEL_FAILURE`.
    RequestFailed {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer sent an `SSH_MSG_GLOBAL_REQUEST`, RFC 4254 §4.
    ///
    /// A global request is not addressed to a channel and RFC 4254 §4 allows
    /// one "at any time". Which requests are honoured is policy, not channel
    /// multiplexing, so this value is surfaced rather than answered here; see
    /// [`ChannelConnection::send_global_request_success`] and
    /// [`ChannelConnection::send_global_request_failure`] for the reply the
    /// same section requires when `want_reply` is set.
    GlobalRequest {
        /// The request name, in US-ASCII, as the peer spelled it.
        request_name: Vec<u8>,
        /// Whether the peer requires a `SSH_MSG_REQUEST_SUCCESS` or
        /// `SSH_MSG_REQUEST_FAILURE` answer.
        want_reply: bool,
        /// Bounded request-specific data.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request with success.
    ///
    /// RFC 4254 §4 requires replies to global requests to arrive in the order
    /// the requests were sent, so the caller pairs these with its own
    /// outstanding-request queue.
    GlobalRequestSucceeded {
        /// Bounded response-specific data, empty when the reply carried none.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request with failure.
    GlobalRequestFailed {
        /// Bounded response-specific data, empty when the reply carried none.
        data: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelDirection {
    OpenedLocally,
    AcceptedLocally,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Channel {
    local_id: ChannelId,
    remote_id: Option<ChannelId>,
    direction: ChannelDirection,
    local_window: u32,
    remote_window: u32,
    local_maximum_packet_size: u32,
    remote_maximum_packet_size: u32,
    local_eof_sent: bool,
    remote_eof_received: bool,
    local_close_sent: bool,
    remote_close_received: bool,
    failed: bool,
}

impl Channel {
    fn writable(&self) -> Result<(), ChannelError> {
        if self.failed {
            return Err(ChannelError::InvalidMessage);
        }
        if self.local_eof_sent {
            return Err(ChannelError::DataAfterEof);
        }
        if self.local_close_sent {
            return Err(ChannelError::InvalidMessage);
        }
        Ok(())
    }

    fn active(&self) -> Result<(), ChannelError> {
        if self.failed || self.remote_close_received {
            return Err(ChannelError::InvalidMessage);
        }
        Ok(())
    }
}

/// A public, read-only view of one open channel's flow-control state.
///
/// The view does not own a queue. Incoming data exists only in the
/// [`ChannelEvent`] returned by one dispatcher call.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelState {
    local_id: ChannelId,
    remote_id: Option<ChannelId>,
    local_window: u32,
    remote_window: u32,
    local_maximum_packet_size: u32,
    remote_maximum_packet_size: u32,
    local_eof_sent: bool,
    remote_eof_received: bool,
    local_close_sent: bool,
    remote_close_received: bool,
    failed: bool,
}

impl ChannelState {
    /// Returns the local sender channel identifier.
    #[must_use]
    pub const fn local_id(&self) -> ChannelId {
        self.local_id
    }

    /// Returns the peer sender channel identifier for an established channel.
    #[must_use]
    pub const fn remote_id(&self) -> Option<ChannelId> {
        self.remote_id
    }

    /// Returns the remaining local receive window.
    #[must_use]
    pub const fn local_window(&self) -> u32 {
        self.local_window
    }

    /// Returns the remaining remote receive window.
    #[must_use]
    pub const fn remote_window(&self) -> u32 {
        self.remote_window
    }

    /// Returns the locally advertised maximum data size.
    #[must_use]
    pub const fn local_maximum_packet_size(&self) -> u32 {
        self.local_maximum_packet_size
    }

    /// Returns the peer-advertised maximum data size, capped to this
    /// implementation's transport-safe limit.
    #[must_use]
    pub const fn remote_maximum_packet_size(&self) -> u32 {
        self.remote_maximum_packet_size
    }

    /// Returns whether this side has sent EOF.
    #[must_use]
    pub const fn local_eof_sent(&self) -> bool {
        self.local_eof_sent
    }

    /// Returns whether the peer has sent EOF.
    #[must_use]
    pub const fn remote_eof_received(&self) -> bool {
        self.remote_eof_received
    }

    /// Returns whether this side has sent CLOSE.
    #[must_use]
    pub const fn local_close_sent(&self) -> bool {
        self.local_close_sent
    }

    /// Returns whether the peer has sent CLOSE.
    #[must_use]
    pub const fn remote_close_received(&self) -> bool {
        self.remote_close_received
    }

    /// Returns whether a channel-specific protocol error made the channel unusable.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

/// A bounded, single-reader and serialized-writer channel multiplexer.
///
/// All channel operations borrow the connection mutably. The connection does
/// not run background readers, spawn threads, or buffer data between calls.
#[derive(Debug)]
pub struct ChannelConnection<T> {
    transport: T,
    channels: std::collections::BTreeMap<ChannelId, Channel>,
    incoming: std::collections::BTreeMap<ChannelId, ChannelOpenRequest>,
    /// Bounded tombstones for channels both sides have closed.
    ///
    /// RFC 4254 §5.3 lets a party reuse a channel number once it has both sent
    /// and received `SSH_MSG_CHANNEL_CLOSE`, and OpenSSH reuses the lowest free
    /// slot (`channel_new`: "Try to find a free slot where to put the new
    /// channel"). A peer is therefore entitled to name a number we have just
    /// retired. Remembering the retirement lets the multiplexer say
    /// [`ChannelError::ClosedChannel`] instead of silently routing a straggler
    /// onto whatever channel took the number next; the bound keeps a
    /// misbehaving peer from growing the table without limit.
    closed: std::collections::BTreeMap<ChannelId, u64>,
    /// Monotonic retirement counter used to bound the tombstone map.
    reap_clock: u64,
}

/// How many retired local channel identifiers are remembered.
///
/// Far above any legitimate multiplexing depth, and small enough that the
/// tombstone map is not a growth vector.
pub const MAX_REMEMBERED_CLOSED_CHANNELS: usize = 1_024;

impl<T> ChannelConnection<T> {
    /// Wraps one already authenticated transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            channels: std::collections::BTreeMap::new(),
            incoming: std::collections::BTreeMap::new(),
            closed: std::collections::BTreeMap::new(),
            reap_clock: 0,
        }
    }

    /// Returns a read-only reference to the owned transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the sole mutable transport reference.
    ///
    /// Normal channel users should prefer the typed methods on this value. This
    /// accessor remains available to channel-type extensions that need to
    /// exchange a bounded protocol packet on the same serialized transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns one open channel's current state.
    #[must_use]
    pub fn channel(&self, channel: ChannelId) -> Option<ChannelState> {
        self.channels.get(&channel).map(Channel::state)
    }

    /// Iterates over copies of all locally addressed channel states in identifier order.
    pub fn channels(&self) -> impl Iterator<Item = ChannelState> {
        self.channels.values().map(Channel::state)
    }

    /// Returns the number of locally addressed open channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Returns the number of received opens awaiting confirmation or rejection.
    #[must_use]
    pub fn pending_open_count(&self) -> usize {
        self.incoming.len()
    }

    /// Returns the number of retired channel identifiers still remembered.
    ///
    /// A non-zero value means at least one channel on this connection has
    /// reached the point RFC 4254 §5.3 calls closed and been dropped from
    /// [`Self::channel`]. It is the observable half of "a closed channel is
    /// dropped", which is otherwise only visible as a freed identifier.
    #[must_use]
    pub fn closed_channel_count(&self) -> usize {
        self.closed.len()
    }

    /// Returns whether one local identifier was retired and not yet reused.
    #[must_use]
    pub fn is_retired_channel(&self, channel: ChannelId) -> bool {
        self.closed.contains_key(&channel)
    }

    /// Returns the always-zero number of buffered data bytes.
    ///
    /// This explicit invariant makes backpressure behavior observable without
    /// retaining payload copies between dispatch calls.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn buffered_data_bytes(&self) -> usize {
        0
    }

    /// Consumes the multiplexer and returns its transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T> ChannelConnection<T>
where
    T: ChannelTransport,
{
    /// Allocates the lowest local channel identifier that is free to use.
    ///
    /// An identifier is free when no live channel holds it *and* it is not
    /// still remembered as closed. Skipping the second case is what keeps a
    /// straggler distinguishable: a peer that sends `SSH_MSG_CHANNEL_DATA` for
    /// a channel it has already closed would otherwise have that data delivered
    /// into whichever channel was given the number next. RFC 4254 §5.3 permits
    /// reuse — "the party may then reuse the channel number" — but permits it,
    /// it does not require it, and skipping a bounded window of retired
    /// identifiers costs at most [`MAX_REMEMBERED_CLOSED_CHANNELS`] extra
    /// identifiers while removing the only way a dropped channel's bytes can be
    /// misrouted. OpenSSH does reuse freely, which is why it relies on
    /// `ssh_packet_disconnect` for a message it cannot attribute; this
    /// multiplexer reports the condition instead.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelIdExhausted`] after every `u32` identifier
    /// has been used.
    pub fn allocate_channel_id(&self) -> Result<ChannelId, ChannelError> {
        for candidate in 0..=u32::MAX {
            if !self.channels.contains_key(&candidate) && !self.closed.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(ChannelError::ChannelIdExhausted)
    }

    /// Sends a channel open with this implementation's standard local limits.
    ///
    /// `type_specific_data` is appended as raw SSH channel-open type-specific
    /// data; it is not wrapped in another string.
    ///
    /// # Errors
    ///
    /// Returns a validation or transport error without registering a channel
    /// when the open cannot be written completely.
    pub fn open_channel(
        &mut self,
        sender_channel: ChannelId,
        channel_type: &[u8],
        type_specific_data: &[u8],
    ) -> Result<(), ChannelError> {
        self.open_channel_with_limits(
            sender_channel,
            channel_type,
            type_specific_data,
            INITIAL_CHANNEL_WINDOW,
            MAX_CHANNEL_PACKET_SIZE,
        )
    }

    /// Sends a channel open with explicit local receive limits.
    ///
    /// `maximum_packet_size` must not exceed [`MAX_CHANNEL_DATA_SIZE`], which
    /// reserves space for channel framing, packet padding, and compression.
    ///
    /// # Errors
    ///
    /// Returns a validation, limit, or transport error. No channel is
    /// registered unless the complete open packet is written.
    pub fn open_channel_with_limits(
        &mut self,
        sender_channel: ChannelId,
        channel_type: &[u8],
        type_specific_data: &[u8],
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<(), ChannelError> {
        validate_channel_name(channel_type)?;
        validate_local_limits(initial_window, maximum_packet_size)?;
        validate_type_specific_size(type_specific_data, maximum_packet_size)?;
        self.ensure_capacity(sender_channel, None)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN);
        writer.write_string(channel_type)?;
        writer.write_uint32(sender_channel);
        writer.write_uint32(initial_window);
        writer.write_uint32(maximum_packet_size);
        let mut payload = writer.into_bytes();
        payload.extend_from_slice(type_specific_data);
        if payload.len() > MAX_CHANNEL_MESSAGE_SIZE {
            return Err(ChannelError::MessageTooLarge);
        }
        self.transport
            .write_channel_payload(&payload)
            .map_err(|_error| ChannelError::Transport)?;
        self.channels.insert(
            sender_channel,
            Channel {
                local_id: sender_channel,
                remote_id: None,
                direction: ChannelDirection::OpenedLocally,
                local_window: initial_window,
                remote_window: 0,
                local_maximum_packet_size: maximum_packet_size,
                remote_maximum_packet_size: 0,
                local_eof_sent: false,
                remote_eof_received: false,
                local_close_sent: false,
                remote_close_received: false,
                failed: false,
            },
        );
        Ok(())
    }

    /// Confirms a pending peer open with this implementation's standard limits.
    ///
    /// # Errors
    ///
    /// Returns an unknown, duplicate, invalid-limit, or transport error. The
    /// pending request remains reserved when packet writing fails.
    pub fn confirm_open(
        &mut self,
        remote_channel: ChannelId,
        local_channel: ChannelId,
    ) -> Result<(), ChannelError> {
        self.confirm_open_with_limits(
            remote_channel,
            local_channel,
            INITIAL_CHANNEL_WINDOW,
            MAX_CHANNEL_PACKET_SIZE,
        )
    }

    /// Confirms a pending peer open with explicit local receive limits.
    ///
    /// `maximum_packet_size` must not exceed [`MAX_CHANNEL_DATA_SIZE`], which
    /// reserves space for channel framing, packet padding, and compression.
    ///
    /// # Errors
    ///
    /// Returns an unknown, duplicate, invalid-limit, or transport error. The
    /// pending request remains reserved when packet writing fails.
    pub fn confirm_open_with_limits(
        &mut self,
        remote_channel: ChannelId,
        local_channel: ChannelId,
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<(), ChannelError> {
        validate_local_limits(initial_window, maximum_packet_size)?;
        self.incoming
            .get(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        self.ensure_capacity(local_channel, Some(remote_channel))?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        writer.write_uint32(remote_channel);
        writer.write_uint32(local_channel);
        writer.write_uint32(initial_window);
        writer.write_uint32(maximum_packet_size);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        let pending = self
            .incoming
            .remove(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        self.channels.insert(
            local_channel,
            Channel {
                local_id: local_channel,
                remote_id: Some(remote_channel),
                direction: ChannelDirection::AcceptedLocally,
                local_window: initial_window,
                remote_window: pending.initial_window,
                local_maximum_packet_size: maximum_packet_size,
                remote_maximum_packet_size: effective_remote_maximum_packet_size(
                    pending.maximum_packet_size,
                ),
                local_eof_sent: false,
                remote_eof_received: false,
                local_close_sent: false,
                remote_close_received: false,
                failed: false,
            },
        );
        Ok(())
    }

    /// Rejects and removes one pending peer channel open.
    ///
    /// # Errors
    ///
    /// Returns an unknown request, invalid description, or transport error. A
    /// transport failure leaves the request pending.
    pub fn reject_open(
        &mut self,
        remote_channel: ChannelId,
        reason: u32,
        description: &[u8],
        language: &[u8],
    ) -> Result<(), ChannelError> {
        if !self.incoming.contains_key(&remote_channel) {
            return Err(ChannelError::UnknownChannel);
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
        writer.write_uint32(remote_channel);
        writer.write_uint32(reason);
        writer.write_string_with_limit(description, MAX_CHANNEL_PACKET_SIZE as usize)?;
        writer.write_string_with_limit(language, MAX_CHANNEL_PACKET_SIZE as usize)?;
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        self.incoming
            .remove(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        Ok(())
    }

    /// Reads and routes exactly one complete SSH payload.
    ///
    /// Channel payloads are parsed completely before any window or lifecycle
    /// field is changed. No event is returned for malformed or unknown-channel
    /// input.
    ///
    /// # What this layer tolerates
    ///
    /// An authenticated connection carries more than channels, and the
    /// multiplexing layer has to be the place that knows the difference. The
    /// message numbers treated as connection-level rather than as a defect are
    /// exactly the six that are legal at any time on an established
    /// connection, and each gets the treatment its own section requires:
    ///
    /// * `SSH_MSG_IGNORE` (2), `SSH_MSG_DEBUG` (4) and `SSH_MSG_UNIMPLEMENTED`
    ///   (3) are parsed, bounded, and dropped without producing an event.
    ///   RFC 4253 §11.2 says implementations "MUST understand (and ignore)"
    ///   the first at any time, §11.3 allows them to ignore the second, and
    ///   §11.4 says the third "MUST be otherwise ignored". A caller never
    ///   sees them, so no caller's `match` has to carry a variant the RFC
    ///   permits it to ignore. Malformed framing is still an error, because
    ///   "ignore" describes the message, not a licence to skip validation.
    /// * `SSH_MSG_GLOBAL_REQUEST` (80), `SSH_MSG_REQUEST_SUCCESS` (81) and
    ///   `SSH_MSG_REQUEST_FAILURE` (82) are surfaced as
    ///   [`ChannelEvent::GlobalRequest`], and the two replies as
    ///   [`ChannelEvent::GlobalRequestSucceeded`] or
    ///   [`ChannelEvent::GlobalRequestFailed`]. They are surfaced rather than
    ///   dropped because RFC 4254 §4 requires an answer when "want reply" is
    ///   true, and because whether a request is honoured is a policy decision
    ///   that belongs above the multiplexer — which is also why they are not
    ///   answered here. Use [`Self::send_global_request_success`] and
    ///   [`Self::send_global_request_failure`] to reply.
    ///
    /// Every other message number is still
    /// [`ChannelError::UnexpectedMessage`], and that includes message numbers
    /// this layer *does* own. A `SSH_MSG_CHANNEL_*` it failed to honour, a
    /// transport-layer number, and a user-authentication number are all
    /// errors. Silently discarding a channel message would be a worse defect
    /// than the one this replaces: a client that drops `SSH_MSG_CHANNEL_DATA`
    /// loses data with no signal, where a client that fails says so.
    ///
    /// This is not hypothetical for the tolerated set. A current OpenSSH
    /// server sends `hostkeys-00@openssh.com` as a global request as the first
    /// payload after `SSH_MSG_USERAUTH_SUCCESS` — `sshd` calls
    /// `notify_hostkeys(ssh)` from `do_authenticated`'s caller, immediately
    /// before the session starts — and follows it with `SSH_MSG_DEBUG`.
    /// Neither is a channel message, and both arrive before any channel
    /// exists.
    ///
    /// # Errors
    ///
    /// Returns a transport, wire, unknown-channel, state, flow-control, or
    /// unexpected-message error. A channel-specific violation marks that
    /// channel failed without delivering an event.
    pub fn dispatch_one(&mut self) -> Result<ChannelEvent, ChannelError> {
        // A discarded connection-level message produces no event, so the loop
        // continues to the next payload rather than returning early. This is
        // what makes `SSH_MSG_IGNORE` transparent to every caller instead of a
        // variant each of them has to handle.
        loop {
            if let Some(event) = self.dispatch_payload()? {
                return Ok(event);
            }
        }
    }

    /// Reads one payload and returns its event, or `None` when it carried none.
    fn dispatch_payload(&mut self) -> Result<Option<ChannelEvent>, ChannelError> {
        let payload = self
            .transport
            .read_channel_payload()
            .map_err(|_error| ChannelError::Transport)?;
        let message = parse_message(&payload)?;
        let event = match message {
            ParsedMessage::Open(request) => self.apply_open(request),
            ParsedMessage::Confirmation {
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            } => self.apply_confirmation(
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            ),
            ParsedMessage::OpenFailure {
                channel,
                reason,
                description,
                language,
            } => self.apply_open_failure(channel, reason, description, language),
            ParsedMessage::WindowAdjustment { channel, bytes } => {
                self.apply_window_adjustment(channel, bytes)
            }
            ParsedMessage::Data { channel, data } => self.apply_data(channel, data),
            ParsedMessage::ExtendedData {
                channel,
                data_type_code,
                data,
            } => self.apply_extended_data(channel, data_type_code, data),
            ParsedMessage::Eof { channel } => self.apply_eof(channel),
            ParsedMessage::Close { channel } => self.apply_close(channel),
            ParsedMessage::Request {
                channel,
                request_type,
                want_reply,
                data,
            } => self.apply_request(channel, request_type, want_reply, data),
            ParsedMessage::Reply { channel, success } => {
                let invalid = self
                    .channels
                    .get(&channel)
                    .ok_or_else(|| self.unknown_channel(channel))?
                    .active()
                    .is_err();
                if invalid {
                    return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
                }
                Ok(if success {
                    ChannelEvent::RequestSucceeded { channel }
                } else {
                    ChannelEvent::RequestFailed { channel }
                })
            }
            ParsedMessage::GlobalRequest {
                request_name,
                want_reply,
                data,
            } => Ok(ChannelEvent::GlobalRequest {
                request_name,
                want_reply,
                data,
            }),
            ParsedMessage::GlobalReply { success, data } => Ok(if success {
                ChannelEvent::GlobalRequestSucceeded { data }
            } else {
                ChannelEvent::GlobalRequestFailed { data }
            }),
            // No event: `dispatch_one` reads the next payload instead.
            ParsedMessage::Discarded => return Ok(None),
        }?;
        Ok(Some(event))
    }

    /// Sends `SSH_MSG_REQUEST_SUCCESS` for an earlier global request.
    ///
    /// RFC 4254 §4 requires this whenever the peer set "want reply", and
    /// requires replies to be sent in the order their requests were.
    ///
    /// # Errors
    ///
    /// Returns a wire or transport error.
    pub fn send_global_request_success(&mut self) -> Result<(), ChannelError> {
        self.write_global_reply(SSH_MSG_REQUEST_SUCCESS)
    }

    /// Sends `SSH_MSG_REQUEST_FAILURE` for an earlier global request.
    ///
    /// RFC 4254 §4: "If the recipient does not recognize or support the
    /// request, it simply responds with `SSH_MSG_REQUEST_FAILURE`."
    ///
    /// # Errors
    ///
    /// Returns a wire or transport error.
    pub fn send_global_request_failure(&mut self) -> Result<(), ChannelError> {
        self.write_global_reply(SSH_MSG_REQUEST_FAILURE)
    }

    /// Answers a global request this connection has no policy for.
    ///
    /// RFC 4254 §4 requires an answer whenever the peer set "want reply", and
    /// names the answer for a request the recipient does not support:
    /// `SSH_MSG_REQUEST_FAILURE`. OpenSSH does the same for every request type
    /// it does not recognise — `client_input_global_request` leaves `success`
    /// at zero and replies failure when `want_reply` is set, and its
    /// `server_input_global_request` does the same.
    ///
    /// A request with `want_reply` clear is answered with nothing, because the
    /// RFC only obliges a reply when one was asked for.
    ///
    /// # Errors
    ///
    /// Returns a transport error.
    pub fn refuse_global_request(&mut self, want_reply: bool) -> Result<(), ChannelError> {
        if want_reply {
            self.send_global_request_failure()?;
        }
        Ok(())
    }

    /// Reads payloads until one yields a channel event, or none is left.
    ///
    /// This is the dispatch loop for a layer built on this multiplexer that
    /// has no global-request policy of its own — a session or direct-tcpip
    /// endpoint, say. Such a layer has nothing to do with a connection-level
    /// request, so it cannot surface one in a channel-scoped event, and it must
    /// not fail on one either: a current OpenSSH server sends
    /// `hostkeys-00@openssh.com` before any channel exists. So the request is
    /// answered per RFC 4254 §4 and reading continues.
    ///
    /// `None` means the next call has to read from the transport again, which
    /// is also what happens when only ignorable messages arrived.
    ///
    /// # Errors
    ///
    /// Returns a transport, wire, channel-state, flow-control, or
    /// unexpected-message error.
    pub fn dispatch_channel_event(&mut self) -> Result<Option<ChannelEvent>, ChannelError> {
        loop {
            match self.dispatch_payload()? {
                Some(ChannelEvent::GlobalRequest { want_reply, .. }) => {
                    self.refuse_global_request(want_reply)?;
                }
                // An ignorable RFC 4253 §11 message carries no event, so keep
                // reading rather than reporting an empty dispatch.
                Some(
                    ChannelEvent::GlobalRequestSucceeded { .. }
                    | ChannelEvent::GlobalRequestFailed { .. },
                )
                | None => {}
                other => return Ok(other),
            }
        }
    }

    fn write_global_reply(&mut self, message: u8) -> Result<(), ChannelError> {
        if message != SSH_MSG_REQUEST_SUCCESS && message != SSH_MSG_REQUEST_FAILURE {
            return Err(ChannelError::InvalidMessage);
        }
        self.transport
            .write_channel_payload(&[message])
            .map_err(|_error| ChannelError::Transport)
    }

    /// Writes one complete channel-data packet without buffering it.
    ///
    /// The remote window and maximum packet are validated before any write.
    /// Remote credit is committed only after the transport accepts the packet.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::PacketTooLarge`] or
    /// [`WindowError::Insufficient`] without sending anything when the payload
    /// does not fit. State and transport errors are returned unchanged.
    pub fn write_data(&mut self, channel: ChannelId, data: &[u8]) -> Result<usize, ChannelError> {
        self.write_data_packet(channel, None, data)
    }

    /// Writes one complete extended-data packet without buffering it.
    ///
    /// Extended data shares the channel's receive window and packet-size limits
    /// with ordinary data; the type code is metadata and is not charged as
    /// payload bytes.
    ///
    /// # Errors
    ///
    /// Returns the same channel, state, packet-size, window, or transport
    /// errors as [`Self::write_data`].
    pub fn write_extended_data(
        &mut self,
        channel: ChannelId,
        data_type_code: u32,
        data: &[u8],
    ) -> Result<usize, ChannelError> {
        self.write_data_packet(channel, Some(data_type_code), data)
    }

    fn write_data_packet(
        &mut self,
        channel: ChannelId,
        data_type_code: Option<u32>,
        data: &[u8],
    ) -> Result<usize, ChannelError> {
        let (remote_channel, remote_maximum, remote_window) = {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
            (
                state.remote_id.ok_or(ChannelError::InvalidMessage)?,
                state.remote_maximum_packet_size,
                state.remote_window,
            )
        };
        let requested = data.len();
        let maximum = usize::try_from(remote_maximum)
            .unwrap_or(usize::MAX)
            .min(MAX_CHANNEL_DATA_SIZE);
        if requested > maximum {
            return Err(ChannelError::PacketTooLarge {
                maximum: u32::try_from(maximum).map_err(|_error| ChannelError::MessageTooLarge)?,
                requested,
            });
        }
        let data_length =
            u32::try_from(requested).map_err(|_error| ChannelError::MessageTooLarge)?;
        if data_length > remote_window {
            return Err(ChannelError::Window(WindowError::Insufficient {
                available: remote_window,
                requested,
            }));
        }
        let mut writer = Writer::new();
        writer.write_byte(if data_type_code.is_some() {
            SSH_MSG_CHANNEL_EXTENDED_DATA
        } else {
            SSH_MSG_CHANNEL_DATA
        });
        writer.write_uint32(remote_channel);
        if let Some(data_type_code) = data_type_code {
            writer.write_uint32(data_type_code);
        }
        writer.write_string(data)?;
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_window -= data_length;
        }
        Ok(requested)
    }

    /// Sends a bounded channel request with type-specific bytes appended raw.
    ///
    /// # Errors
    ///
    /// Returns a name, channel-state, packet-size, wire, or transport error.
    pub fn send_request(
        &mut self,
        channel: ChannelId,
        request_type: &[u8],
        want_reply: bool,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        validate_channel_name(request_type)?;
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_REQUEST);
        writer.write_uint32(remote_channel);
        writer.write_string(request_type)?;
        writer.write_boolean(want_reply);
        let mut payload = writer.into_bytes();
        payload.extend_from_slice(data);
        self.write_control(channel, &payload)
    }

    /// Sends `SSH_MSG_CHANNEL_SUCCESS` for an earlier request.
    ///
    /// # Errors
    ///
    /// Returns an unknown, closed, or transport error.
    pub fn send_request_success(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_SUCCESS);
        writer.write_uint32(remote_channel);
        self.write_control(channel, &writer.into_bytes())
    }

    /// Sends `SSH_MSG_CHANNEL_FAILURE` for an earlier request.
    ///
    /// # Errors
    ///
    /// Returns an unknown, closed, or transport error.
    pub fn send_request_failure(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_FAILURE);
        writer.write_uint32(remote_channel);
        self.write_control(channel, &writer.into_bytes())
    }

    /// Grants the peer more local receive credit with `WINDOW_ADJUST`.
    ///
    /// Local credit changes only after the complete packet is written.
    ///
    /// # Errors
    ///
    /// Returns a zero increment, [`WindowError::AdjustmentOverflow`], channel
    /// state, or transport error without changing the local window.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, ChannelError> {
        if bytes == 0 {
            return Err(ChannelError::InvalidWindowAdjustment);
        }
        let (remote_channel, updated) = {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.active()?;
            if state.local_close_sent {
                return Err(ChannelError::InvalidMessage);
            }
            let remote_channel = state.remote_id.ok_or(ChannelError::InvalidMessage)?;
            let updated = state
                .local_window
                .checked_add(bytes)
                .ok_or(ChannelError::Window(WindowError::AdjustmentOverflow {
                    current: state.local_window,
                    increment: bytes,
                }))?;
            (remote_channel, updated)
        };
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        writer.write_uint32(remote_channel);
        writer.write_uint32(bytes);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_window = updated;
        }
        Ok(updated)
    }

    /// Sends one half-close EOF marker.
    ///
    /// # Errors
    ///
    /// Returns an unknown channel, repeated EOF, data-after-EOF state, or
    /// transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_EOF);
        writer.write_uint32(remote_channel);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_eof_sent = true;
        }
        Ok(())
    }

    /// Sends one channel CLOSE marker.
    ///
    /// A channel marked failed by a protocol error can still be closed, but
    /// cannot send any further data, request, EOF, or window adjustment.
    ///
    /// When the peer has already closed its side, this call completes the
    /// RFC 4254 §5.3 handshake and the channel is dropped from the connection
    /// before this method returns. Re-issuing any per-channel method for it
    /// afterwards returns [`ChannelError::UnknownChannel`]; querying
    /// [`Self::channel`] returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an unknown channel, repeated CLOSE, or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.local_close_sent {
                return Err(ChannelError::InvalidMessage);
            }
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_CLOSE);
        writer.write_uint32(remote_channel);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_close_sent = true;
        }
        self.reap_if_fully_closed(channel);
        Ok(())
    }

    fn remote_channel(&self, channel: ChannelId) -> Result<ChannelId, ChannelError> {
        self.channels
            .get(&channel)
            .ok_or(ChannelError::UnknownChannel)?
            .remote_id
            .ok_or(ChannelError::InvalidMessage)
    }

    /// Records a channel both sides have closed, RFC 4254 §5.3.
    ///
    /// The channel leaves `channels` — that is the whole of the fix — and its
    /// identifier is remembered in `closed` so that a straggler naming it is
    /// reported as [`ChannelError::ClosedChannel`] instead of being routed onto
    /// whichever channel is allocated the number next.
    fn retire_channel(&mut self, channel: ChannelId) {
        self.channels.remove(&channel);
        self.closed.insert(channel, self.reap_clock);
        self.reap_clock = self.reap_clock.wrapping_add(1);
        while self.closed.len() > MAX_REMEMBERED_CLOSED_CHANNELS {
            let Some(oldest) = self
                .closed
                .iter()
                .min_by_key(|(_identifier, retired_at)| *retired_at)
                .map(|(identifier, _retired_at)| *identifier)
            else {
                break;
            };
            self.closed.remove(&oldest);
        }
    }

    /// Reaps one channel if it has crossed the RFC 4254 §5.3 close boundary.
    ///
    /// The boundary is *both* directions, not either. A peer may send
    /// `SSH_MSG_CHANNEL_CLOSE` without having sent or received
    /// `SSH_MSG_CHANNEL_EOF` — the same section says so explicitly — and
    /// `SSH_MSG_CHANNEL_DATA` for a channel can still be in flight when the
    /// local `CLOSE` goes out. Reaping on the local close alone would drop
    /// that data on the floor; RFC 4254 §5.3 asks the opposite, that "all data
    /// sent before this message be delivered to the actual destination".
    fn reap_if_fully_closed(&mut self, channel: ChannelId) {
        let fully_closed = self
            .channels
            .get(&channel)
            .is_some_and(|state| state.local_close_sent && state.remote_close_received);
        if fully_closed {
            self.retire_channel(channel);
        }
    }

    /// Distinguishes a never-seen channel from one both sides have closed.
    fn unknown_channel(&self, channel: ChannelId) -> ChannelError {
        if self.closed.contains_key(&channel) {
            ChannelError::ClosedChannel(channel)
        } else {
            ChannelError::UnknownChannel
        }
    }

    /// Fails before a mutable borrow is taken, for the `get_mut` apply paths.
    fn require_live(&self, channel: ChannelId) -> Result<(), ChannelError> {
        if self.channels.contains_key(&channel) {
            Ok(())
        } else {
            Err(self.unknown_channel(channel))
        }
    }

    fn ensure_capacity(
        &self,
        local_channel: ChannelId,
        remote_channel: Option<ChannelId>,
    ) -> Result<(), ChannelError> {
        if self.channels.contains_key(&local_channel) {
            return Err(ChannelError::DuplicateChannel);
        }
        if self.closed.contains_key(&local_channel) {
            return Err(ChannelError::ClosedChannel(local_channel));
        }
        let replacing_pending =
            remote_channel.is_some_and(|remote| self.incoming.contains_key(&remote));
        let occupied_after = self
            .channels
            .len()
            .saturating_add(self.incoming.len())
            .saturating_sub(usize::from(replacing_pending));
        if occupied_after >= MAX_CHANNELS_PER_CONNECTION {
            return Err(ChannelError::TooManyChannels);
        }
        if let Some(remote) = remote_channel {
            let open_channel_uses_remote = self
                .channels
                .values()
                .any(|channel| channel.remote_id == Some(remote));
            if open_channel_uses_remote {
                return Err(ChannelError::DuplicateChannel);
            }
        }
        Ok(())
    }

    fn remote_channel_in_use(&self, remote: ChannelId) -> bool {
        self.incoming.contains_key(&remote)
            || self
                .channels
                .values()
                .any(|channel| channel.remote_id == Some(remote))
    }

    fn write_control(&mut self, channel: ChannelId, payload: &[u8]) -> Result<(), ChannelError> {
        if payload.len() > MAX_CHANNEL_MESSAGE_SIZE {
            return Err(ChannelError::MessageTooLarge);
        }
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
        }
        self.transport
            .write_channel_payload(payload)
            .map_err(|_error| ChannelError::Transport)
    }

    fn apply_open(&mut self, request: ChannelOpenRequest) -> Result<ChannelEvent, ChannelError> {
        if self.channels.len().saturating_add(self.incoming.len()) >= MAX_CHANNELS_PER_CONNECTION {
            return Err(ChannelError::TooManyChannels);
        }
        if self.remote_channel_in_use(request.sender_channel) {
            return Err(ChannelError::DuplicateChannel);
        }
        self.incoming
            .insert(request.sender_channel, request.clone());
        Ok(ChannelEvent::OpenRequest(request))
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
    ///
    /// The duplicate-remote-identifier guard is scoped to *live* channels and
    /// to opens this side is still holding, which is what makes identifier
    /// reuse work. RFC 4254 §5.3 allows reuse once a party has both sent and
    /// received `SSH_MSG_CHANNEL_CLOSE`, and OpenSSH allocates the lowest free
    /// slot on the connection, so the second session on a connection is
    /// confirmed with the same remote identifier the first one used. A refusal
    /// here is a real protocol error only while the identifier is genuinely
    /// held by another open channel.
    fn apply_confirmation(
        &mut self,
        channel: ChannelId,
        remote_channel: ChannelId,
        remote_window: u32,
        remote_maximum_packet_size: u32,
    ) -> Result<ChannelEvent, ChannelError> {
        if remote_maximum_packet_size == 0
            || remote_maximum_packet_size as usize > MAX_PACKET_CONTENT
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidOpen));
        }
        if self.remote_channel_in_use(remote_channel) {
            return Err(self.fail_channel(channel, ChannelError::DuplicateChannel));
        }
        self.require_live(channel)?;
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or(ChannelError::UnknownChannel)?;
        if state.direction != ChannelDirection::OpenedLocally
            || state.remote_id.is_some()
            || state.failed
            || state.local_close_sent
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        state.remote_id = Some(remote_channel);
        state.remote_window = remote_window;
        state.remote_maximum_packet_size =
            effective_remote_maximum_packet_size(remote_maximum_packet_size);
        Ok(ChannelEvent::Opened(channel))
    }

    fn apply_open_failure(
        &mut self,
        channel: ChannelId,
        reason: u32,
        description: Vec<u8>,
        language: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        let state = self
            .channels
            .get(&channel)
            .ok_or_else(|| self.unknown_channel(channel))?;
        if state.direction != ChannelDirection::OpenedLocally
            || state.remote_id.is_some()
            || state.failed
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        self.channels.remove(&channel);
        Ok(ChannelEvent::OpenFailed {
            channel,
            reason,
            description,
            language,
        })
    }

    fn apply_window_adjustment(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<ChannelEvent, ChannelError> {
        if bytes == 0 {
            return Err(self.fail_channel(channel, ChannelError::InvalidWindowAdjustment));
        }
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err() {
                Err(ChannelError::InvalidMessage)
            } else {
                let current = state.remote_window;
                match current.checked_add(bytes) {
                    Some(available) => {
                        state.remote_window = available;
                        Ok(available)
                    }
                    None => Err(ChannelError::Window(WindowError::AdjustmentOverflow {
                        current,
                        increment: bytes,
                    })),
                }
            }
        };
        let available = result.map_err(|error| self.fail_channel(channel, error))?;
        Ok(ChannelEvent::WindowAdjusted { channel, available })
    }

    fn apply_data(
        &mut self,
        channel: ChannelId,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.account_received_data(channel, &data)?;
        Ok(ChannelEvent::Data { channel, data })
    }

    fn apply_extended_data(
        &mut self,
        channel: ChannelId,
        data_type_code: u32,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.account_received_data(channel, &data)?;
        Ok(ChannelEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        })
    }

    fn account_received_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        self.require_live(channel)?;
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err() {
                Err(ChannelError::InvalidMessage)
            } else if state.remote_eof_received {
                Err(ChannelError::DataAfterEof)
            } else if data.len() > state.local_maximum_packet_size as usize {
                Err(ChannelError::PacketTooLarge {
                    maximum: state.local_maximum_packet_size,
                    requested: data.len(),
                })
            } else {
                let length =
                    u32::try_from(data.len()).map_err(|_error| ChannelError::MessageTooLarge)?;
                if length > state.local_window {
                    Err(ChannelError::WindowExceeded {
                        available: state.local_window,
                        received: data.len(),
                    })
                } else {
                    state.local_window -= length;
                    Ok(())
                }
            }
        };
        result.map_err(|error| self.fail_channel(channel, error))
    }

    fn apply_eof(&mut self, channel: ChannelId) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let invalid = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.active().is_err() || state.remote_eof_received
        };
        if invalid {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_eof_received = true;
        }
        Ok(ChannelEvent::Eof { channel })
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_CLOSE`.
    ///
    /// RFC 4254 §5.3: "Upon receiving this message, a party MUST send back an
    /// `SSH_MSG_CHANNEL_CLOSE` unless it has already sent this message for the
    /// channel." Reaching the local close earlier is the case where that
    /// MUST does not apply, and it is also the case where the channel crosses
    /// the section's closed boundary and is dropped.
    fn apply_close(&mut self, channel: ChannelId) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let invalid = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.failed || state.remote_close_received
        };
        if invalid {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_close_received = true;
        }
        // The event is built from values captured before the reap, so a caller
        // still learns that the channel closed even though the entry is gone
        // by the time this returns.
        self.reap_if_fully_closed(channel);
        Ok(ChannelEvent::Close { channel })
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_REQUEST`.
    ///
    /// RFC 4254 §6.10 defines exactly two channel requests that a peer sends
    /// after its `SSH_MSG_CHANNEL_EOF`: `exit-status` and `exit-signal`.
    /// `exit-signal` optionally carries a core dump as part of its payload.
    /// Every other request is refused once `remote_eof_received` is set.
    fn apply_request(
        &mut self,
        channel: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err()
                || (state.remote_eof_received && !is_request_allowed_after_eof(&request_type))
            {
                Err(ChannelError::InvalidMessage)
            } else if data.len() > state.local_maximum_packet_size as usize {
                Err(ChannelError::PacketTooLarge {
                    maximum: state.local_maximum_packet_size,
                    requested: data.len(),
                })
            } else {
                Ok(())
            }
        };
        result.map_err(|error| self.fail_channel(channel, error))?;
        Ok(ChannelEvent::Request {
            channel,
            request_type,
            want_reply,
            data,
        })
    }

    fn fail_channel(&mut self, channel: ChannelId, error: ChannelError) -> ChannelError {
        if let Some(state) = self.channels.get_mut(&channel) {
            state.failed = true;
        }
        error
    }
}

impl Channel {
    fn state(&self) -> ChannelState {
        ChannelState {
            local_id: self.local_id,
            remote_id: self.remote_id,
            local_window: self.local_window,
            remote_window: self.remote_window,
            local_maximum_packet_size: self.local_maximum_packet_size,
            remote_maximum_packet_size: self.remote_maximum_packet_size,
            local_eof_sent: self.local_eof_sent,
            remote_eof_received: self.remote_eof_received,
            local_close_sent: self.local_close_sent,
            remote_close_received: self.remote_close_received,
            failed: self.failed,
        }
    }
}

enum ParsedMessage {
    Open(ChannelOpenRequest),
    Confirmation {
        channel: ChannelId,
        remote_channel: ChannelId,
        remote_window: u32,
        remote_maximum_packet_size: u32,
    },
    OpenFailure {
        channel: ChannelId,
        reason: u32,
        description: Vec<u8>,
        language: Vec<u8>,
    },
    WindowAdjustment {
        channel: ChannelId,
        bytes: u32,
    },
    Data {
        channel: ChannelId,
        data: Vec<u8>,
    },
    ExtendedData {
        channel: ChannelId,
        data_type_code: u32,
        data: Vec<u8>,
    },
    Eof {
        channel: ChannelId,
    },
    Close {
        channel: ChannelId,
    },
    Request {
        channel: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: Vec<u8>,
    },
    Reply {
        channel: ChannelId,
        success: bool,
    },
    /// A connection-level message with no channel event to deliver.
    ///
    /// RFC 4253 §11.2, §11.3 and §11.4 all say the same thing about
    /// `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG` and `SSH_MSG_UNIMPLEMENTED`: the
    /// receiver must understand them and must otherwise ignore them. The
    /// payload was still parsed and bounded, so a malformed one is an error
    /// and a well-formed one is dropped without a caller ever seeing it.
    Discarded,
    /// A global request, RFC 4254 §4.
    GlobalRequest {
        /// The request name, in US-ASCII, as the peer spelled it.
        request_name: Vec<u8>,
        /// Whether the peer requires a reply.
        want_reply: bool,
        /// Bounded request-specific data.
        data: Vec<u8>,
    },
    /// A global-request reply, RFC 4254 §4.
    GlobalReply {
        /// Whether the reply was success or failure.
        success: bool,
        /// Bounded response-specific data.
        data: Vec<u8>,
    },
}

#[allow(clippy::too_many_lines)]
fn parse_message(payload: &[u8]) -> Result<ParsedMessage, ChannelError> {
    let message = payload
        .first()
        .copied()
        .ok_or(ChannelError::InvalidMessage)?;
    let mut reader = Reader::new(&payload[1..]);
    match message {
        SSH_MSG_CHANNEL_OPEN => {
            let channel_type = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            if channel_type.is_empty() {
                return Err(ChannelError::InvalidOpen);
            }
            let sender_channel = reader.read_uint32()?;
            let initial_window = reader.read_uint32()?;
            let maximum_packet_size = reader.read_uint32()?;
            if maximum_packet_size == 0 || maximum_packet_size as usize > MAX_PACKET_CONTENT {
                return Err(ChannelError::InvalidOpen);
            }
            validate_type_specific_size(reader.remaining(), maximum_packet_size)?;
            Ok(ParsedMessage::Open(ChannelOpenRequest {
                channel_type,
                sender_channel,
                initial_window,
                maximum_packet_size,
                type_specific_data: reader.remaining().to_vec(),
            }))
        }
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            let channel = reader.read_uint32()?;
            let remote_channel = reader.read_uint32()?;
            let remote_window = reader.read_uint32()?;
            let remote_maximum_packet_size = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Confirmation {
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            })
        }
        SSH_MSG_CHANNEL_OPEN_FAILURE => {
            let channel = reader.read_uint32()?;
            let reason = reader.read_uint32()?;
            let description = reader
                .read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?
                .to_vec();
            let language = reader
                .read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?
                .to_vec();
            ensure_finished(&reader)?;
            Ok(ParsedMessage::OpenFailure {
                channel,
                reason,
                description,
                language,
            })
        }
        SSH_MSG_CHANNEL_WINDOW_ADJUST => {
            let channel = reader.read_uint32()?;
            let bytes = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::WindowAdjustment { channel, bytes })
        }
        SSH_MSG_CHANNEL_DATA => {
            let channel = reader.read_uint32()?;
            let data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Data {
                channel,
                data: data.to_vec(),
            })
        }
        SSH_MSG_CHANNEL_EXTENDED_DATA => {
            let channel = reader.read_uint32()?;
            let data_type_code = reader.read_uint32()?;
            let data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::ExtendedData {
                channel,
                data_type_code,
                data: data.to_vec(),
            })
        }
        SSH_MSG_CHANNEL_EOF => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Eof { channel })
        }
        SSH_MSG_CHANNEL_CLOSE => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Close { channel })
        }
        SSH_MSG_CHANNEL_REQUEST => {
            let channel = reader.read_uint32()?;
            let request_type = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            if request_type.is_empty() {
                return Err(ChannelError::InvalidMessage);
            }
            let want_reply = reader.read_boolean()?;
            if reader.remaining().len() > MAX_PACKET_CONTENT {
                return Err(ChannelError::MessageTooLarge);
            }
            Ok(ParsedMessage::Request {
                channel,
                request_type,
                want_reply,
                data: reader.remaining().to_vec(),
            })
        }
        SSH_MSG_CHANNEL_SUCCESS | SSH_MSG_CHANNEL_FAILURE => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Reply {
                channel,
                success: message == SSH_MSG_CHANNEL_SUCCESS,
            })
        }
        _ => parse_connection_level(message, &mut reader),
    }
}

/// Parses every message that is legal on an established connection but is not
/// addressed to a channel.
///
/// The three RFC 4253 §11 messages are validated for framing and then
/// discarded, and the three RFC 4254 §4 messages are decoded into variants
/// the caller can match. Anything outside those six numbers is
/// [`ChannelError::UnexpectedMessage`], which keeps a message this layer
/// exists to route — a `SSH_MSG_CHANNEL_*` it did not honour, or a transport
/// or user-authentication number that has no business here — an error rather
/// than something silently swallowed.
fn parse_connection_level(
    message: u8,
    reader: &mut Reader<'_>,
) -> Result<ParsedMessage, ChannelError> {
    match message {
        // RFC 4253 §11.2: "All implementations MUST understand (and ignore)
        // this message at any time (after receiving the identification
        // string)." It is padding a peer sends for traffic-analysis reasons, so
        // it is the one message here that must not reach a caller's match.
        SSH_MSG_IGNORE => {
            let _data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4253 §11.4: "Such messages MUST be otherwise ignored." The
        // reference is to a message number we sent, which a channel layer
        // cannot act on; the sequence number is read to prove the framing and
        // then discarded, because the transport owns the sequence space.
        SSH_MSG_UNIMPLEMENTED => {
            let _sequence = reader.read_uint32()?;
            ensure_finished(reader)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4253 §11.3: "All implementations MUST understand this message,
        // but they are allowed to ignore it." The payload is bounded and
        // dropped; surfacing it would add a variant every caller's match has
        // to carry for a message the RFC explicitly permits ignoring.
        SSH_MSG_DEBUG => {
            let _always_display = reader.read_boolean()?;
            let _message = reader.read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?;
            let _language = reader.read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4254 §4: a global request affects the whole connection and
        // "both the client and server MAY send global requests at any time".
        // Whether to honour it is policy, so it is surfaced rather than
        // answered here.
        SSH_MSG_GLOBAL_REQUEST => {
            // The name is bounded but not otherwise constrained here. OpenSSH
            // reads a cstring, compares it against the requests it knows, and
            // reports "unsupported request" for anything else including the
            // empty name; refusing an empty name here would be stricter than
            // the peer this layer has to interoperate with, and a peer is
            // entitled to ask about a request that does not exist.
            let request_name = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            let want_reply = reader.read_boolean()?;
            Ok(ParsedMessage::GlobalRequest {
                request_name,
                want_reply,
                data: reader.remaining().to_vec(),
            })
        }
        // RFC 4254 §4: "byte SSH_MSG_REQUEST_SUCCESS .... response specific
        // data". The data is opaque and bounded; callers pair the reply with
        // their own outstanding-request queue, which §4 requires to be
        // in-order.
        SSH_MSG_REQUEST_SUCCESS => Ok(ParsedMessage::GlobalReply {
            success: true,
            data: reader.remaining().to_vec(),
        }),
        SSH_MSG_REQUEST_FAILURE => Ok(ParsedMessage::GlobalReply {
            success: false,
            data: reader.remaining().to_vec(),
        }),
        _ => Err(ChannelError::UnexpectedMessage(message)),
    }
}

fn ensure_finished(reader: &Reader<'_>) -> Result<(), ChannelError> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(ChannelError::InvalidMessage)
    }
}

fn validate_channel_name(name: &[u8]) -> Result<(), ChannelError> {
    if name.is_empty() || name.len() > MAX_CHANNEL_NAME_LENGTH {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

fn effective_remote_maximum_packet_size(advertised: u32) -> u32 {
    advertised.min(u32::try_from(MAX_CHANNEL_DATA_SIZE).unwrap_or(u32::MAX))
}

fn validate_local_limits(
    initial_window: u32,
    maximum_packet_size: u32,
) -> Result<(), ChannelError> {
    if initial_window == 0
        || maximum_packet_size == 0
        || maximum_packet_size as usize > MAX_CHANNEL_DATA_SIZE
    {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

fn validate_type_specific_size(data: &[u8], maximum_packet_size: u32) -> Result<(), ChannelError> {
    if data.len() > maximum_packet_size as usize || data.len() > MAX_PACKET_CONTENT {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

/// The RFC 4254 §6.10 `exit-status` channel request name.
const EXIT_STATUS_REQUEST: &[u8] = b"exit-status";
/// The RFC 4254 §6.10 `exit-signal` channel request name.
const EXIT_SIGNAL_REQUEST: &[u8] = b"exit-signal";

/// Returns whether RFC 4254 §6.10 defines this channel request as arriving
/// after the peer's `SSH_MSG_CHANNEL_EOF`.
///
/// `exit-status` and `exit-signal` are the only two. `exit-signal` optionally
/// carries a core dump, which is part of its payload rather than a separate
/// request.
fn is_request_allowed_after_eof(request_type: &[u8]) -> bool {
    request_type == EXIT_STATUS_REQUEST || request_type == EXIT_SIGNAL_REQUEST
}
