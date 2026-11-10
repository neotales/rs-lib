//! OpenSSH global ping and keepalive requests.
//!
//! This module encodes and decodes the `SSH_MSG_GLOBAL_REQUEST` messages used
//! for `ping@openssh.com` and `keepalive@openssh.com`.  It deliberately does
//! not schedule a keepalive or send anything on a transport: callers choose
//! when to encode a request and when to write a returned response.

#![allow(clippy::module_name_repetitions)]

use neotales_ssh::{Error, MAX_PACKET_CONTENT, Reader, StringBytes, Writer};

/// SSH message number for a connection-level global request.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;

/// SSH message number for a successful global-request response.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;

/// SSH message number for a failed global-request response.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// The OpenSSH keepalive request name.
pub const KEEPALIVE_REQUEST: &str = "keepalive@openssh.com";

/// The OpenSSH ping request name.
pub const PING_REQUEST: &str = "ping@openssh.com";

/// A descriptive alias for [`KEEPALIVE_REQUEST`].
pub const KEEPALIVE_REQUEST_NAME: &str = KEEPALIVE_REQUEST;

/// A descriptive alias for [`PING_REQUEST`].
pub const PING_REQUEST_NAME: &str = PING_REQUEST;

/// A short alias for [`KEEPALIVE_REQUEST`].
pub const KEEPALIVE_NAME: &str = KEEPALIVE_REQUEST;

/// A short alias for [`PING_REQUEST`].
pub const PING_NAME: &str = PING_REQUEST;

/// The protocol shape of a decoded global request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalRequestKind {
    /// The known `keepalive@openssh.com` request, which has no request data.
    Keepalive,
    /// The known `ping@openssh.com` request, which carries one SSH string.
    Ping,
    /// A request name this module does not recognize.
    Unknown,
}

/// A decoded OpenSSH global request.
///
/// `Keepalive` and `Ping` retain the boolean received on the wire, including
/// the less usual `want_reply: true` keepalive.  The dedicated constructors
/// and encoders use the canonical OpenSSH defaults (`false` for keepalive and
/// `true` for ping).  An `Unknown` request retains its name and every byte
/// after `want_reply` without interpreting that data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalRequest {
    /// A `keepalive@openssh.com` request with no request-specific data.
    Keepalive {
        /// Whether the peer requested a success or failure response.
        want_reply: bool,
    },
    /// A `ping@openssh.com` request carrying the decoded string value.
    Ping {
        /// Whether the peer requested a success response.
        want_reply: bool,
        /// The exact bytes carried by the ping's SSH string.
        payload: Vec<u8>,
    },
    /// A global request whose name is not handled by this module.
    Unknown {
        /// The exact request-name bytes, which need not be UTF-8.
        name: Vec<u8>,
        /// Whether the peer requested a response.
        want_reply: bool,
        /// The exact opaque bytes following `want_reply`.
        data: Vec<u8>,
    },
}

impl GlobalRequest {
    /// Creates a canonical keepalive request with `want_reply` set to false.
    #[must_use]
    pub fn keepalive() -> Self {
        Self::Keepalive { want_reply: false }
    }

    /// Creates a canonical ping request with `want_reply` set to true.
    #[must_use]
    pub fn ping<P>(payload: P) -> Self
    where
        P: StringBytes,
    {
        Self::Ping {
            want_reply: true,
            payload: payload.as_ssh_bytes().to_vec(),
        }
    }

    /// Creates an unknown request while retaining its opaque data.
    #[must_use]
    pub fn unknown<N, D>(name: N, want_reply: bool, data: D) -> Self
    where
        N: StringBytes,
        D: StringBytes,
    {
        Self::Unknown {
            name: name.as_ssh_bytes().to_vec(),
            want_reply,
            data: data.as_ssh_bytes().to_vec(),
        }
    }

    /// Decodes one complete `SSH_MSG_GLOBAL_REQUEST` payload.
    ///
    /// The request name and request data are not sent through packet framing;
    /// `input` is the payload written to or read from an SSH transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when `input` exceeds
    /// [`MAX_PACKET_CONTENT`], [`Error::Truncated`] for an incomplete type,
    /// name, boolean, or ping string, [`Error::InvalidBoolean`] for a
    /// `want_reply` byte other than zero or one, and [`Error::InvalidPacket`]
    /// for a wrong type or trailing bytes in a fully defined keepalive or
    /// ping request.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }

        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_GLOBAL_REQUEST {
            return Err(Error::InvalidPacket);
        }
        let name = reader.read_string_with_limit(MAX_PACKET_CONTENT)?.to_vec();
        let want_reply = reader.read_boolean()?;

        match name.as_slice() {
            value if value == KEEPALIVE_REQUEST.as_bytes() => {
                if !reader.is_empty() {
                    return Err(Error::InvalidPacket);
                }
                Ok(Self::Keepalive { want_reply })
            }
            value if value == PING_REQUEST.as_bytes() => {
                let payload = reader.read_string_with_limit(MAX_PACKET_CONTENT)?.to_vec();
                if !reader.is_empty() {
                    return Err(Error::InvalidPacket);
                }
                Ok(Self::Ping {
                    want_reply,
                    payload,
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
    /// Returns the same errors as [`GlobalRequest::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        Self::decode(input)
    }

    /// Encodes this request as one complete global-request payload.
    ///
    /// The canonical constructors choose the OpenSSH defaults, while an
    /// explicitly constructed or decoded variant preserves its `want_reply`
    /// value.  Unknown request data is appended without interpretation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the complete encoded payload
    /// exceeds [`MAX_PACKET_CONTENT`] or a field cannot be represented as an
    /// SSH string.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (name, want_reply, data, data_is_string) = match self {
            Self::Keepalive { want_reply } => {
                (KEEPALIVE_REQUEST.as_bytes(), *want_reply, None, false)
            }
            Self::Ping {
                want_reply,
                payload,
            } => (
                PING_REQUEST.as_bytes(),
                *want_reply,
                Some(payload.as_slice()),
                true,
            ),
            Self::Unknown {
                name,
                want_reply,
                data,
            } => (name.as_slice(), *want_reply, Some(data.as_slice()), false),
        };

        let data_length = data.map_or(0, <[u8]>::len);
        ensure_request_size(name.len(), data_length, data_is_string)?;

        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
        writer.write_string_with_limit(name, MAX_PACKET_CONTENT)?;
        writer.write_boolean(want_reply);
        if data_is_string {
            // The length was checked above, so the string encoder cannot make
            // the complete payload exceed the packet-content limit.
            writer
                .write_string_with_limit(data.ok_or(Error::LimitExceeded)?, MAX_PACKET_CONTENT)?;
        }
        let mut encoded = writer.into_bytes();
        if !data_is_string && let Some(data) = data {
            encoded.extend_from_slice(data);
        }
        if encoded.len() > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }
        Ok(encoded)
    }

    /// Encodes this request to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`GlobalRequest::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }

    /// Returns the protocol shape of this request.
    #[must_use]
    pub const fn kind(&self) -> GlobalRequestKind {
        match self {
            Self::Keepalive { .. } => GlobalRequestKind::Keepalive,
            Self::Ping { .. } => GlobalRequestKind::Ping,
            Self::Unknown { .. } => GlobalRequestKind::Unknown,
        }
    }

    /// Returns whether this request is one of the two names handled here.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. })
    }

    /// Returns whether this is a keepalive request.
    #[must_use]
    pub const fn is_keepalive(&self) -> bool {
        matches!(self, Self::Keepalive { .. })
    }

    /// Returns whether this is a ping request.
    #[must_use]
    pub const fn is_ping(&self) -> bool {
        matches!(self, Self::Ping { .. })
    }

    /// Returns whether the peer asked for a response.
    #[must_use]
    pub const fn want_reply(&self) -> bool {
        match self {
            Self::Keepalive { want_reply }
            | Self::Ping { want_reply, .. }
            | Self::Unknown { want_reply, .. } => *want_reply,
        }
    }

    /// Returns the request name bytes.
    ///
    /// Unknown names are returned exactly as received, including bytes that
    /// are not valid UTF-8.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        match self {
            Self::Keepalive { .. } => KEEPALIVE_REQUEST.as_bytes(),
            Self::Ping { .. } => PING_REQUEST.as_bytes(),
            Self::Unknown { name, .. } => name,
        }
    }

    /// Returns the semantic request data.
    ///
    /// A ping returns its decoded string value, an unknown request returns its
    /// opaque bytes, and a keepalive returns an empty slice.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Keepalive { .. } => &[],
            Self::Ping { payload, .. } => payload,
            Self::Unknown { data, .. } => data,
        }
    }

    /// Returns the ping payload, or `None` for other request kinds.
    #[must_use]
    pub fn ping_payload(&self) -> Option<&[u8]> {
        match self {
            Self::Ping { payload, .. } => Some(payload),
            Self::Keepalive { .. } | Self::Unknown { .. } => None,
        }
    }

    /// Builds the response for this request.
    ///
    /// A request with `want_reply == false` produces no response.  Known
    /// keepalive and ping requests produce success, with a ping echoing its
    /// SSH string.  An unknown request produces only `SSH_MSG_REQUEST_FAILURE`
    /// and never `SSH_MSG_REQUEST_SUCCESS`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when echoing a ping would make the
    /// complete response exceed [`MAX_PACKET_CONTENT`].
    pub fn reply(&self) -> Result<Option<Vec<u8>>, Error> {
        if !self.want_reply() {
            return Ok(None);
        }
        match self {
            Self::Keepalive { .. } => encode_request_success().map(Some),
            Self::Ping { payload, .. } => encode_request_success_with_string(payload).map(Some),
            Self::Unknown { .. } => encode_request_failure().map(Some),
        }
    }

    /// Builds the response for this request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`GlobalRequest::reply`].
    pub fn response(&self) -> Result<Option<Vec<u8>>, Error> {
        self.reply()
    }

    /// Builds the response for this request.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`GlobalRequest::reply`].
    pub fn build_reply(&self) -> Result<Option<Vec<u8>>, Error> {
        self.reply()
    }
}

impl TryFrom<&[u8]> for GlobalRequest {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// Encodes the canonical `keepalive@openssh.com` request.
///
/// The emitted `want_reply` byte is zero, as required by the OpenSSH request
/// used by this crate.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] if the complete request cannot fit within
/// [`MAX_PACKET_CONTENT`], although the canonical request is bounded and small.
pub fn encode_keepalive() -> Result<Vec<u8>, Error> {
    GlobalRequest::keepalive().encode()
}

/// Encodes the canonical `ping@openssh.com` request.
///
/// The emitted `want_reply` byte is one, and `payload` is encoded as one SSH
/// string after the request boolean.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] when the complete encoded request exceeds
/// [`MAX_PACKET_CONTENT`].
pub fn encode_ping<P>(payload: P) -> Result<Vec<u8>, Error>
where
    P: StringBytes,
{
    GlobalRequest::ping(payload).encode()
}

/// Decodes one complete global-request payload.
///
/// # Errors
///
/// Returns the same errors as [`GlobalRequest::decode`].
pub fn decode_global_request(input: &[u8]) -> Result<GlobalRequest, Error> {
    GlobalRequest::decode(input)
}

/// Encodes an empty `SSH_MSG_REQUEST_SUCCESS` response.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] only if the shared response limit changes
/// to a value smaller than one byte.
pub fn encode_request_success() -> Result<Vec<u8>, Error> {
    if 1 > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(vec![SSH_MSG_REQUEST_SUCCESS])
}

/// Encodes an `SSH_MSG_REQUEST_SUCCESS` response containing one SSH string.
///
/// This is the response form used by `ping@openssh.com`.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] when the complete response exceeds
/// [`MAX_PACKET_CONTENT`].
pub fn encode_request_success_with_string<P>(payload: P) -> Result<Vec<u8>, Error>
where
    P: StringBytes,
{
    let payload = payload.as_ssh_bytes();
    ensure_response_string_size(payload.len())?;
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_REQUEST_SUCCESS);
    writer.write_string_with_limit(payload, MAX_PACKET_CONTENT)?;
    let encoded = writer.into_bytes();
    if encoded.len() > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(encoded)
}

/// Encodes an empty `SSH_MSG_REQUEST_FAILURE` response.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] only if the shared response limit changes
/// to a value smaller than one byte.
pub fn encode_request_failure() -> Result<Vec<u8>, Error> {
    if 1 > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(vec![SSH_MSG_REQUEST_FAILURE])
}

fn ensure_request_size(
    name_length: usize,
    data_length: usize,
    data_is_string: bool,
) -> Result<(), Error> {
    let data_overhead = if data_is_string { 4 } else { 0 };
    let total = 1_usize
        .checked_add(4)
        .and_then(|size| size.checked_add(name_length))
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add(data_overhead))
        .and_then(|size| size.checked_add(data_length))
        .ok_or(Error::LimitExceeded)?;
    if total > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}

fn ensure_response_string_size(payload_length: usize) -> Result<(), Error> {
    let total = 1_usize
        .checked_add(4)
        .and_then(|size| size.checked_add(payload_length))
        .ok_or(Error::LimitExceeded)?;
    if total > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}
