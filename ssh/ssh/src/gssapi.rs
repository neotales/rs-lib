//! RFC 4462 GSSAPI user-authentication framing.
//!
//! This module implements the SSH message layer for the `gssapi-with-mic`
//! method.  It deliberately does not implement Kerberos, a GSSAPI mechanism,
//! a KDC client, or a security context.  A caller can provide an opaque
//! token-exchange callback through [`GssapiTokenMechanism`]; the callback is
//! responsible for whatever mechanism-specific state it owns.  The types in
//! this module only move bounded, opaque bytes and enforce protocol ordering.

#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::error::Error as WireError;
use crate::packet::MAX_PACKET_CONTENT;
use crate::wire::{Reader, Writer};

/// SSH message number for the initial server GSSAPI response.
pub const SSH_MSG_USERAUTH_GSSAPI_RESPONSE: u8 = 60;
/// SSH message number for one opaque GSSAPI token.
pub const SSH_MSG_USERAUTH_GSSAPI_TOKEN: u8 = 61;
/// SSH message number for the client's GSSAPI exchange acknowledgement.
pub const SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: u8 = 63;
/// SSH message number for an optional RFC 4462 GSSAPI error status.
pub const SSH_MSG_USERAUTH_GSSAPI_ERROR: u8 = 64;
/// SSH message number for an optional RFC 4462 GSSAPI error token.
pub const SSH_MSG_USERAUTH_GSSAPI_ERRTOK: u8 = 65;
/// SSH message number for the RFC 4462 GSSAPI MIC message.
pub const SSH_MSG_USERAUTH_GSSAPI_MIC: u8 = 66;
/// SSH user-authentication message number used by a GSSAPI request.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// The RFC 4462 `gssapi-with-mic` authentication method name.
pub const GSSAPI_WITH_MIC_METHOD: &str = "gssapi-with-mic";
/// The RFC 4462 `gssapi-keyex` authentication method name.
pub const GSSAPI_KEYEX_METHOD: &str = "gssapi-keyex";
/// The SSH service name used while negotiating user authentication.
pub const SSH_USERAUTH_SERVICE: &str = "ssh-userauth";
/// The SSH connection service name used in a user-authentication request.
pub const SSH_CONNECTION_SERVICE: &str = "ssh-connection";

/// Maximum number of mechanism OIDs in one GSSAPI authentication request.
pub const MAX_GSSAPI_MECHANISMS: usize = 64;
/// Maximum byte length of one opaque mechanism identifier or DER OID.
pub const MAX_GSSAPI_MECHANISM_LENGTH: usize = 4_096;
/// Maximum byte length of one user name in the RFC 4462 request shape.
pub const MAX_GSSAPI_USERNAME_LENGTH: usize = 4_096;
/// Maximum byte length of one opaque GSSAPI token.
pub const MAX_GSSAPI_TOKEN_LENGTH: usize = 64 * 1_024;
/// Maximum number of caller-driven token exchanges in one attempt.
pub const MAX_GSSAPI_EXCHANGES: usize = 32;

/// Alias for [`MAX_GSSAPI_MECHANISMS`].
pub const MAX_GSSAPI_MECHANISM_COUNT: usize = MAX_GSSAPI_MECHANISMS;
/// Alias for [`MAX_GSSAPI_EXCHANGES`].
pub const MAX_GSSAPI_TOKEN_EXCHANGES: usize = MAX_GSSAPI_EXCHANGES;

/// A bounded, non-sensitive error from the GSSAPI framing or state machine.
///
/// Error values never contain mechanism identifiers, token bytes, callback
/// errors, or panic payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GssapiError {
    /// The primitive SSH wire value was truncated or otherwise malformed.
    Wire(WireError),
    /// The packet type, field shape, or trailing data was invalid.
    InvalidMessage,
    /// A field that RFC 4462 requires to be non-empty was empty.
    EmptyField,
    /// A mechanism, token, packet, or configuration bound was exceeded.
    LimitExceeded,
    /// The operation is not valid in the current exchange state.
    InvalidState,
    /// The caller-provided mechanism is not the selected mechanism.
    UnsupportedMechanism,
    /// The configured token-exchange limit was exhausted.
    TooManyExchanges,
    /// A caller callback panicked.  The panic payload is discarded.
    CallbackPanicked,
    /// A caller mechanism reported authentication failure.
    CallbackRejected,
    /// The exchange is already complete or terminally failed.
    Terminal,
    /// A state-machine limit was zero or outside the supported range.
    InvalidConfiguration,
}

impl fmt::Display for GssapiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH GSSAPI wire error: {error}"),
            Self::InvalidMessage => formatter.write_str("SSH GSSAPI message is invalid"),
            Self::EmptyField => formatter.write_str("SSH GSSAPI field must not be empty"),
            Self::LimitExceeded => {
                formatter.write_str("SSH GSSAPI value exceeds the configured limit")
            }
            Self::InvalidState => formatter.write_str("SSH GSSAPI message is out of order"),
            Self::UnsupportedMechanism => {
                formatter.write_str("SSH GSSAPI mechanism is unsupported")
            }
            Self::TooManyExchanges => {
                formatter.write_str("SSH GSSAPI token exchange limit was exhausted")
            }
            Self::CallbackPanicked => formatter.write_str("SSH GSSAPI callback panicked"),
            Self::CallbackRejected => {
                formatter.write_str("SSH GSSAPI mechanism rejected the exchange")
            }
            Self::Terminal => formatter.write_str("SSH GSSAPI exchange is already terminal"),
            Self::InvalidConfiguration => {
                formatter.write_str("SSH GSSAPI configuration is invalid")
            }
        }
    }
}

impl std::error::Error for GssapiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::InvalidMessage
            | Self::EmptyField
            | Self::LimitExceeded
            | Self::InvalidState
            | Self::UnsupportedMechanism
            | Self::TooManyExchanges
            | Self::CallbackPanicked
            | Self::CallbackRejected
            | Self::Terminal
            | Self::InvalidConfiguration => None,
        }
    }
}

impl From<WireError> for GssapiError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::LimitExceeded => Self::LimitExceeded,
            other => Self::Wire(other),
        }
    }
}

fn check_packet_size(input: &[u8]) -> Result<(), GssapiError> {
    if input.len() > MAX_PACKET_CONTENT {
        return Err(GssapiError::LimitExceeded);
    }
    Ok(())
}

fn validate_mechanism(mechanism: &[u8]) -> Result<(), GssapiError> {
    if mechanism.is_empty() {
        return Err(GssapiError::EmptyField);
    }
    if mechanism.len() > MAX_GSSAPI_MECHANISM_LENGTH {
        return Err(GssapiError::LimitExceeded);
    }
    Ok(())
}

fn validate_token(token: &[u8]) -> Result<(), GssapiError> {
    if token.is_empty() {
        return Err(GssapiError::EmptyField);
    }
    if token.len() > MAX_GSSAPI_TOKEN_LENGTH {
        return Err(GssapiError::LimitExceeded);
    }
    Ok(())
}

fn ensure_packet_finished(reader: &Reader<'_>) -> Result<(), GssapiError> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(GssapiError::InvalidMessage)
    }
}

/// The RFC 4462 server response selecting one mechanism.
///
/// The mechanism is retained as opaque bytes because this module does not
/// implement ASN.1 or a GSSAPI mechanism registry.  A callback must validate
/// and authorize the selected identifier before accepting tokens.
#[derive(Clone, Eq, PartialEq)]
pub struct GssapiResponse {
    mechanism: Vec<u8>,
}

impl GssapiResponse {
    /// Creates a response value without validating the mechanism length.
    ///
    /// Validation is performed by [`Self::encode`] and [`Self::try_new`].
    #[must_use]
    pub fn new<M>(mechanism: M) -> Self
    where
        M: AsRef<[u8]>,
    {
        Self {
            mechanism: mechanism.as_ref().to_vec(),
        }
    }

    /// Creates a response after checking the mechanism bound and non-empty
    /// requirement.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::EmptyField`] or [`GssapiError::LimitExceeded`]
    /// for an invalid mechanism.
    pub fn try_new<M>(mechanism: M) -> Result<Self, GssapiError>
    where
        M: AsRef<[u8]>,
    {
        let mechanism = mechanism.as_ref();
        validate_mechanism(mechanism)?;
        Ok(Self {
            mechanism: mechanism.to_vec(),
        })
    }

    /// Returns the selected opaque mechanism identifier.
    #[must_use]
    pub fn mechanism(&self) -> &[u8] {
        &self.mechanism
    }

    /// Encodes the complete SSH message.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an empty or oversized mechanism, an
    /// unrepresentable string, or a packet larger than the SSH content limit.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        validate_mechanism(&self.mechanism)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_USERAUTH_GSSAPI_RESPONSE);
        writer.write_string_with_limit(&self.mechanism, MAX_GSSAPI_MECHANISM_LENGTH)?;
        let encoded = writer.into_bytes();
        check_packet_size(&encoded)?;
        Ok(encoded)
    }

    /// Decodes one complete response message and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for a wrong type, truncated field, empty
    /// mechanism, oversized mechanism, or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_USERAUTH_GSSAPI_RESPONSE {
            return Err(GssapiError::InvalidMessage);
        }
        let mechanism = reader.read_string_with_limit(MAX_GSSAPI_MECHANISM_LENGTH)?;
        validate_mechanism(mechanism)?;
        ensure_packet_finished(&reader)?;
        Ok(Self {
            mechanism: mechanism.to_vec(),
        })
    }

    /// Alias for [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, GssapiError> {
        self.encode()
    }

    /// Alias for [`Self::decode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, GssapiError> {
        Self::decode(input)
    }
}

impl fmt::Debug for GssapiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiResponse")
            .field("mechanism_length", &self.mechanism.len())
            .finish()
    }
}

impl TryFrom<&[u8]> for GssapiResponse {
    type Error = GssapiError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// The RFC 4462 message carrying one non-empty opaque mechanism token.
#[derive(Clone, Eq, PartialEq)]
pub struct GssapiToken {
    token: Vec<u8>,
}

impl GssapiToken {
    /// Creates a token value without validating its length.
    ///
    /// Validation is performed by [`Self::encode`] and [`Self::try_new`].
    #[must_use]
    pub fn new<T>(token: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            token: token.as_ref().to_vec(),
        }
    }

    /// Creates a token after checking the non-empty and length requirements.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::EmptyField`] or [`GssapiError::LimitExceeded`]
    /// for an invalid token.
    pub fn try_new<T>(token: T) -> Result<Self, GssapiError>
    where
        T: AsRef<[u8]>,
    {
        let token = token.as_ref();
        validate_token(token)?;
        Ok(Self {
            token: token.to_vec(),
        })
    }

    /// Returns the opaque token bytes.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Encodes the complete SSH message.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an empty or oversized token, an
    /// unrepresentable string, or a packet larger than the SSH content limit.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        validate_token(&self.token)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_USERAUTH_GSSAPI_TOKEN);
        writer.write_string_with_limit(&self.token, MAX_GSSAPI_TOKEN_LENGTH)?;
        let encoded = writer.into_bytes();
        check_packet_size(&encoded)?;
        Ok(encoded)
    }

    /// Decodes one complete token message and rejects empty/trailing fields.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for a wrong type, truncated field, empty token,
    /// oversized token, or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_USERAUTH_GSSAPI_TOKEN {
            return Err(GssapiError::InvalidMessage);
        }
        let token = reader.read_string_with_limit(MAX_GSSAPI_TOKEN_LENGTH)?;
        validate_token(token)?;
        ensure_packet_finished(&reader)?;
        Ok(Self {
            token: token.to_vec(),
        })
    }

    /// Alias for [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, GssapiError> {
        self.encode()
    }

    /// Alias for [`Self::decode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, GssapiError> {
        Self::decode(input)
    }
}

impl fmt::Debug for GssapiToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiToken")
            .field("token_length", &self.token.len())
            .finish()
    }
}

impl TryFrom<&[u8]> for GssapiToken {
    type Error = GssapiError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// The RFC 4462 client acknowledgement that the token exchange is complete.
///
/// RFC 4462 defines this as a message number with no fields.  In particular,
/// this type intentionally has no boolean or other synthetic payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GssapiExchangeComplete;

impl GssapiExchangeComplete {
    /// Creates the empty acknowledgement value.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encodes the complete SSH message.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::LimitExceeded`] only if the shared packet limit
    /// is ever reduced below one byte.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        if MAX_PACKET_CONTENT < 1 {
            return Err(GssapiError::LimitExceeded);
        }
        Ok(vec![SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE])
    }

    /// Decodes one complete acknowledgement message.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::InvalidMessage`] for a missing type byte, a
    /// wrong type, or any trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        if input.len() != 1
            || input.first().copied() != Some(SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)
        {
            return Err(GssapiError::InvalidMessage);
        }
        Ok(Self)
    }

    /// Alias for [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, GssapiError> {
        self.encode()
    }

    /// Alias for [`Self::decode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, GssapiError> {
        Self::decode(input)
    }
}

impl Default for GssapiExchangeComplete {
    fn default() -> Self {
        Self
    }
}

impl fmt::Debug for GssapiExchangeComplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GssapiExchangeComplete")
    }
}

impl TryFrom<&[u8]> for GssapiExchangeComplete {
    type Error = GssapiError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// The three RFC 4462 messages handled by this module.
#[derive(Clone, Eq, PartialEq)]
pub enum GssapiMessage {
    /// The server's selected mechanism response.
    Response(GssapiResponse),
    /// One opaque token in either direction.
    Token(GssapiToken),
    /// The client's acknowledgement.
    ExchangeComplete(GssapiExchangeComplete),
}

impl GssapiMessage {
    /// Encodes this message as one complete SSH payload.
    ///
    /// # Errors
    ///
    /// Returns the same bounded errors as the selected message encoder.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        match self {
            Self::Response(message) => message.encode(),
            Self::Token(message) => message.encode(),
            Self::ExchangeComplete(message) => message.encode(),
        }
    }

    /// Decodes one of the three supported message types.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an unknown type, malformed primitive, an
    /// empty required field, an oversized field, or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        match input.first().copied() {
            Some(SSH_MSG_USERAUTH_GSSAPI_RESPONSE) => {
                GssapiResponse::decode(input).map(Self::Response)
            }
            Some(SSH_MSG_USERAUTH_GSSAPI_TOKEN) => GssapiToken::decode(input).map(Self::Token),
            Some(SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE) => {
                GssapiExchangeComplete::decode(input).map(Self::ExchangeComplete)
            }
            Some(_) | None => Err(GssapiError::InvalidMessage),
        }
    }

    /// Returns the SSH message number for this value.
    #[must_use]
    pub const fn message_number(&self) -> u8 {
        match self {
            Self::Response(_) => SSH_MSG_USERAUTH_GSSAPI_RESPONSE,
            Self::Token(_) => SSH_MSG_USERAUTH_GSSAPI_TOKEN,
            Self::ExchangeComplete(_) => SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
        }
    }

    /// Alias for [`Self::message_number`].
    #[must_use]
    pub const fn message_type(&self) -> u8 {
        self.message_number()
    }
}

impl fmt::Debug for GssapiMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(message) => formatter.debug_tuple("Response").field(message).finish(),
            Self::Token(message) => formatter.debug_tuple("Token").field(message).finish(),
            Self::ExchangeComplete(message) => formatter
                .debug_tuple("ExchangeComplete")
                .field(message)
                .finish(),
        }
    }
}

impl TryFrom<&[u8]> for GssapiMessage {
    type Error = GssapiError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// The method-specific `uint32 n, string[n] mechanism OIDs` portion of an
/// RFC 4462 `SSH_MSG_USERAUTH_REQUEST`.
///
/// Mechanism OIDs are kept opaque here.  A caller-supplied mechanism owns
/// their interpretation and support decision; this module does not pretend to
/// implement DER or Kerberos.
#[derive(Clone, Eq, PartialEq)]
pub struct GssapiRequest {
    mechanisms: Vec<Vec<u8>>,
}

impl GssapiRequest {
    /// Creates a method-specific request without validating its fields.
    #[must_use]
    pub fn new<I, M>(mechanisms: I) -> Self
    where
        I: IntoIterator<Item = M>,
        M: AsRef<[u8]>,
    {
        Self {
            mechanisms: mechanisms
                .into_iter()
                .map(|mechanism| mechanism.as_ref().to_vec())
                .collect(),
        }
    }

    /// Creates a method-specific request after validating every field.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an empty list, too many mechanisms, an
    /// empty mechanism, or an oversized mechanism.
    pub fn try_new<I, M>(mechanisms: I) -> Result<Self, GssapiError>
    where
        I: IntoIterator<Item = M>,
        M: AsRef<[u8]>,
    {
        let request = Self::new(mechanisms);
        request.validate()?;
        Ok(request)
    }

    /// Returns the requested opaque mechanism identifiers in wire order.
    #[must_use]
    pub fn mechanisms(&self) -> &[Vec<u8>] {
        &self.mechanisms
    }

    /// Validates the request count and each mechanism field.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an empty list, too many mechanisms, an
    /// empty mechanism, or an oversized mechanism.
    pub fn validate(&self) -> Result<(), GssapiError> {
        if self.mechanisms.is_empty() || self.mechanisms.len() > MAX_GSSAPI_MECHANISMS {
            return Err(if self.mechanisms.is_empty() {
                GssapiError::EmptyField
            } else {
                GssapiError::LimitExceeded
            });
        }
        for mechanism in &self.mechanisms {
            validate_mechanism(mechanism)?;
        }
        Ok(())
    }

    /// Encodes only the method-specific fields, without the user-auth request
    /// message number or the user/service/method header.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid counts/fields or a packet larger
    /// than the SSH content limit.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        self.validate()?;
        let count =
            u32::try_from(self.mechanisms.len()).map_err(|_error| GssapiError::LimitExceeded)?;
        let mut writer = Writer::new();
        writer.write_uint32(count);
        for mechanism in &self.mechanisms {
            writer.write_string_with_limit(mechanism, MAX_GSSAPI_MECHANISM_LENGTH)?;
        }
        let encoded = writer.into_bytes();
        check_packet_size(&encoded)?;
        Ok(encoded)
    }

    /// Decodes only the method-specific fields and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for truncation, an invalid count, an empty or
    /// oversized mechanism, or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        let mut reader = Reader::new(input);
        let count =
            usize::try_from(reader.read_uint32()?).map_err(|_error| GssapiError::LimitExceeded)?;
        if count == 0 {
            return Err(GssapiError::EmptyField);
        }
        if count > MAX_GSSAPI_MECHANISMS {
            return Err(GssapiError::LimitExceeded);
        }
        if count > reader.len() / 4 {
            return Err(GssapiError::InvalidMessage);
        }
        let mut mechanisms = Vec::with_capacity(count);
        for _ in 0..count {
            let mechanism = reader.read_string_with_limit(MAX_GSSAPI_MECHANISM_LENGTH)?;
            validate_mechanism(mechanism)?;
            mechanisms.push(mechanism.to_vec());
        }
        ensure_packet_finished(&reader)?;
        Ok(Self { mechanisms })
    }

    /// Returns the method-specific bytes used after the common request header.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, GssapiError> {
        self.encode()
    }

    /// Decodes method-specific request bytes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, GssapiError> {
        Self::decode(input)
    }
}

impl fmt::Debug for GssapiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiRequest")
            .field("mechanism_count", &self.mechanisms.len())
            .field(
                "mechanism_lengths",
                &self.mechanisms.iter().map(Vec::len).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// A complete RFC 4462 `gssapi-with-mic` user-authentication request.
///
/// This is a framing convenience for callers that need to construct the
/// common request header.  It does not initiate a GSSAPI context.
#[derive(Clone, Eq, PartialEq)]
pub struct GssapiUserAuthRequest {
    username: Vec<u8>,
    mechanisms: GssapiRequest,
}

impl GssapiUserAuthRequest {
    /// Creates a complete request value without validating its fields.
    #[must_use]
    pub fn new<I, M>(username: impl AsRef<[u8]>, mechanisms: I) -> Self
    where
        I: IntoIterator<Item = M>,
        M: AsRef<[u8]>,
    {
        Self {
            username: username.as_ref().to_vec(),
            mechanisms: GssapiRequest::new(mechanisms),
        }
    }

    /// Creates a complete request after validating all fields.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an invalid username, list, or mechanism.
    pub fn try_new<I, M>(username: impl AsRef<[u8]>, mechanisms: I) -> Result<Self, GssapiError>
    where
        I: IntoIterator<Item = M>,
        M: AsRef<[u8]>,
    {
        let username = username.as_ref();
        if username.len() > MAX_GSSAPI_USERNAME_LENGTH {
            return Err(GssapiError::LimitExceeded);
        }
        std::str::from_utf8(username).map_err(|_error| GssapiError::InvalidMessage)?;
        let mechanisms = GssapiRequest::try_new(mechanisms)?;
        Ok(Self {
            username: username.to_vec(),
            mechanisms,
        })
    }

    /// Returns the UTF-8 user-name bytes.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// Returns the requested mechanism values.
    #[must_use]
    pub fn mechanisms(&self) -> &[Vec<u8>] {
        self.mechanisms.mechanisms()
    }

    /// Encodes a complete `SSH_MSG_USERAUTH_REQUEST` payload.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an invalid field or an oversized packet.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        self.mechanisms.validate()?;
        if self.username.len() > MAX_GSSAPI_USERNAME_LENGTH {
            return Err(GssapiError::LimitExceeded);
        }
        std::str::from_utf8(&self.username).map_err(|_error| GssapiError::InvalidMessage)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_USERAUTH_REQUEST);
        writer.write_string_with_limit(&self.username, MAX_GSSAPI_USERNAME_LENGTH)?;
        writer.write_string(SSH_CONNECTION_SERVICE)?;
        writer.write_string(GSSAPI_WITH_MIC_METHOD)?;
        writer.write_uint32(
            u32::try_from(self.mechanisms.mechanisms().len())
                .map_err(|_error| GssapiError::LimitExceeded)?,
        );
        for mechanism in self.mechanisms.mechanisms() {
            writer.write_string_with_limit(mechanism, MAX_GSSAPI_MECHANISM_LENGTH)?;
        }
        let encoded = writer.into_bytes();
        check_packet_size(&encoded)?;
        Ok(encoded)
    }

    /// Decodes a complete `SSH_MSG_USERAUTH_REQUEST` payload.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for a wrong type/service/method, invalid UTF-8
    /// user name, malformed mechanism list, or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, GssapiError> {
        check_packet_size(input)?;
        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_USERAUTH_REQUEST {
            return Err(GssapiError::InvalidMessage);
        }
        let username = reader.read_string_with_limit(MAX_GSSAPI_USERNAME_LENGTH)?;
        std::str::from_utf8(username).map_err(|_error| GssapiError::InvalidMessage)?;
        let service = reader.read_string_with_limit(MAX_GSSAPI_MECHANISM_LENGTH)?;
        if service != SSH_CONNECTION_SERVICE.as_bytes() {
            return Err(GssapiError::InvalidMessage);
        }
        let method = reader.read_string_with_limit(MAX_GSSAPI_MECHANISM_LENGTH)?;
        if method != GSSAPI_WITH_MIC_METHOD.as_bytes() {
            return Err(GssapiError::InvalidMessage);
        }
        let mechanisms = GssapiRequest::decode(reader.remaining())?;
        Ok(Self {
            username: username.to_vec(),
            mechanisms,
        })
    }
}

impl fmt::Debug for GssapiUserAuthRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiUserAuthRequest")
            .field("username_length", &self.username.len())
            .field("mechanism_count", &self.mechanisms.mechanisms().len())
            .finish()
    }
}

/// The result returned by a caller-owned opaque token mechanism.
///
/// `Continue` and `AcceptWithToken` carry a non-empty output token.  `Accept`
/// means that the mechanism has accepted the latest input but still requires
/// the RFC 4462 client acknowledgement before the SSH authentication boundary
/// may complete.  `Fail` is terminal.
#[derive(Clone, Eq, PartialEq)]
pub enum GssapiMechanismResult {
    /// The mechanism needs another token exchange.
    Continue(Vec<u8>),
    /// The mechanism accepts the exchange; the acknowledgement is still
    /// required before authentication can succeed.
    Accept,
    /// The mechanism accepts the exchange and has a final token to send before
    /// the acknowledgement.
    AcceptWithToken(Vec<u8>),
    /// The mechanism rejects the exchange.
    Fail,
}

impl GssapiMechanismResult {
    /// Constructs a continuation result.
    #[must_use]
    pub fn continue_with<T>(token: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self::Continue(token.as_ref().to_vec())
    }

    /// Constructs an accepting result without an output token.
    #[must_use]
    pub const fn accept() -> Self {
        Self::Accept
    }

    /// Constructs an accepting result with a final output token.
    #[must_use]
    pub fn accept_with_token<T>(token: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self::AcceptWithToken(token.as_ref().to_vec())
    }

    /// Constructs a terminal rejecting result.
    #[must_use]
    pub const fn fail() -> Self {
        Self::Fail
    }
}

impl fmt::Debug for GssapiMechanismResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(_) => formatter.write_str("Continue(\"<redacted>\")"),
            Self::Accept => formatter.write_str("Accept"),
            Self::AcceptWithToken(_) => formatter.write_str("AcceptWithToken(\"<redacted>\")"),
            Self::Fail => formatter.write_str("Fail"),
        }
    }
}

/// A caller-supplied, mechanism-independent token exchange boundary.
///
/// The trait is intentionally small.  It has no Kerberos credentials, KDC
/// lookup, ASN.1 implementation, or security-context claim.  The implementor
/// owns the opaque mechanism state and must return a non-empty token for
/// continuation.  Calls made by [`GssapiExchange`] are caught so a panic is a
/// denial, never authentication success.
pub trait GssapiTokenMechanism {
    /// Returns the opaque mechanism identifier selected by the server.
    ///
    /// The default is empty.  Implementations may instead override
    /// [`Self::name`]; the state machine accepts either spelling.  A returned
    /// identifier is still subject to the module's non-empty and size bounds.
    fn mechanism(&self) -> &[u8] {
        &[]
    }

    /// Compatibility spelling for [`Self::mechanism`].
    fn name(&self) -> &[u8] {
        self.mechanism()
    }

    /// Processes one received opaque token and reports the next action.
    fn exchange(&self, token: &[u8]) -> GssapiMechanismResult;
}

/// A short alias for [`GssapiTokenMechanism`].
pub use GssapiTokenMechanism as GssapiMechanism;

/// A closure-backed opaque token mechanism.
///
/// The callback receives only the current token and returns a result.  It can
/// keep context in a caller-owned `RefCell`, mutex, or other synchronization
/// primitive appropriate for the application.
type GssapiCallback = dyn for<'a> Fn(&'a [u8]) -> GssapiMechanismResult;

/// Adapts a caller-supplied closure into a GSSAPI token mechanism.
///
/// GSSAPI token exchange is a loop whose mechanics differ per mechanism, and most
/// implementations delegate the token step to something outside the crate. This
/// is the seam for that: the callback receives the current token and returns the
/// result, and the type parameter carries the caller's own mechanism marker so
/// several can be registered at once.
pub struct GssapiTokenMechanismCallback<M> {
    mechanism: Vec<u8>,
    callback: Box<GssapiCallback>,
    _marker: std::marker::PhantomData<M>,
}

impl<M> GssapiTokenMechanismCallback<M> {
    /// Creates a callback adapter.  Validation occurs when it is installed or
    /// when the exchange selects it.
    #[must_use]
    pub fn new<F>(mechanism: M, callback: F) -> Self
    where
        M: AsRef<[u8]>,
        F: for<'a> Fn(&'a [u8]) -> GssapiMechanismResult + 'static,
    {
        Self {
            mechanism: mechanism.as_ref().to_vec(),
            callback: Box::new(callback),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<M> fmt::Debug for GssapiTokenMechanismCallback<M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiTokenMechanismCallback")
            .field("mechanism_length", &self.mechanism.len())
            .finish_non_exhaustive()
    }
}

impl<M> GssapiTokenMechanism for GssapiTokenMechanismCallback<M>
where
    M: AsRef<[u8]> + 'static,
{
    fn mechanism(&self) -> &[u8] {
        &self.mechanism
    }

    fn exchange(&self, token: &[u8]) -> GssapiMechanismResult {
        (self.callback)(token)
    }
}

/// A short alias for [`GssapiTokenMechanismCallback`].
pub type GssapiMechanismCallback<M> = GssapiTokenMechanismCallback<M>;

/// The protocol state of one strict RFC 4462 token exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GssapiExchangeState {
    /// The initial response has not been selected or received.
    AwaitingResponse,
    /// A response has been established and the next token is expected.
    AwaitingToken,
    /// The mechanism accepted its input and the client acknowledgement is
    /// expected.
    AwaitingExchangeComplete,
    /// The acknowledgement was received and the exchange is complete.
    Complete,
    /// A protocol, callback, or resource failure made the exchange terminal.
    Failed,
}

/// The next action produced by [`GssapiExchange`].
#[derive(Clone, Eq, PartialEq)]
pub enum GssapiExchangeAction {
    /// The initial response was selected and a token is expected next.
    AwaitToken,
    /// Send this opaque token to the peer.
    SendToken(GssapiToken),
    /// The callback accepted the input; wait for the acknowledgement.
    AwaitExchangeComplete,
    /// The acknowledgement was accepted; the caller may now cross its own
    /// authentication success boundary.
    Complete,
}

impl GssapiExchangeAction {
    /// Encodes an action that has a wire message.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::InvalidState`] for an action that is a local
    /// state marker rather than a token message.
    pub fn encode(&self) -> Result<Vec<u8>, GssapiError> {
        match self {
            Self::SendToken(token) => token.encode(),
            Self::AwaitToken | Self::AwaitExchangeComplete | Self::Complete => {
                Err(GssapiError::InvalidState)
            }
        }
    }
}

impl fmt::Debug for GssapiExchangeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitToken => formatter.write_str("AwaitToken"),
            Self::SendToken(_) => formatter.write_str("SendToken(\"<redacted>\")"),
            Self::AwaitExchangeComplete => formatter.write_str("AwaitExchangeComplete"),
            Self::Complete => formatter.write_str("Complete"),
        }
    }
}

/// A bounded, callback-driven server-side RFC 4462 exchange state machine.
///
/// The state machine owns no mechanism context.  It passes opaque tokens to a
/// caller-owned [`GssapiTokenMechanism`] and validates the selected mechanism,
/// message order, token sizes, exchange count, and terminal state.  A
/// successful callback intentionally stops at
/// [`GssapiExchangeState::AwaitingExchangeComplete`]; callers must receive the
/// client acknowledgement and cross their existing SSH authentication success
/// boundary themselves.
#[derive(Clone, Eq, PartialEq)]
pub struct GssapiExchange {
    state: GssapiExchangeState,
    selected_mechanism: Vec<u8>,
    token_exchanges: usize,
    max_exchanges: usize,
}

impl GssapiExchange {
    /// Creates an exchange with an explicit positive, bounded exchange limit.
    ///
    /// # Errors
    ///
    /// Returns [`GssapiError::InvalidConfiguration`] when the limit is zero or
    /// greater than [`MAX_GSSAPI_EXCHANGES`].
    pub fn new(max_exchanges: usize) -> Result<Self, GssapiError> {
        if max_exchanges == 0 || max_exchanges > MAX_GSSAPI_EXCHANGES {
            return Err(GssapiError::InvalidConfiguration);
        }
        Ok(Self {
            state: GssapiExchangeState::AwaitingResponse,
            selected_mechanism: Vec::new(),
            token_exchanges: 0,
            max_exchanges,
        })
    }

    /// Creates an exchange using [`MAX_GSSAPI_EXCHANGES`].
    ///
    /// # Errors
    ///
    /// Returns an error only if the shared maximum is invalid.
    pub fn with_default_limit() -> Result<Self, GssapiError> {
        Self::new(MAX_GSSAPI_EXCHANGES)
    }

    /// Returns the current protocol state.
    #[must_use]
    pub const fn state(&self) -> GssapiExchangeState {
        self.state
    }

    /// Returns the number of token callbacks already invoked.
    #[must_use]
    pub const fn token_exchanges(&self) -> usize {
        self.token_exchanges
    }

    /// Returns the configured maximum number of token exchanges.
    #[must_use]
    pub const fn max_exchanges(&self) -> usize {
        self.max_exchanges
    }

    /// Returns whether this exchange is complete or terminally failed.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            GssapiExchangeState::Complete | GssapiExchangeState::Failed
        )
    }

    /// Returns whether the acknowledgement has been accepted.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, GssapiExchangeState::Complete)
    }

    /// Returns the selected opaque mechanism identifier, if one exists.
    #[must_use]
    pub fn selected_mechanism(&self) -> &[u8] {
        &self.selected_mechanism
    }

    /// Starts a server exchange and encodes the initial response.
    ///
    /// The response is selected locally and is deliberately not sent by this
    /// method.  A caller must write the returned payload through its own
    /// transport.
    ///
    /// # Errors
    ///
    /// Returns an error and enters the failed state for a duplicate start,
    /// invalid mechanism, or encoding failure.
    pub fn begin(&mut self, mechanism: &[u8]) -> Result<Vec<u8>, GssapiError> {
        if self.is_terminal() {
            return Err(GssapiError::Terminal);
        }
        if self.state != GssapiExchangeState::AwaitingResponse {
            return self.fail_with(GssapiError::InvalidState);
        }
        if let Err(error) = validate_mechanism(mechanism) {
            return self.fail_with(error);
        }
        self.selected_mechanism = mechanism.to_vec();
        let response = match GssapiResponse::new(&self.selected_mechanism).encode() {
            Ok(response) => response,
            Err(error) => return self.fail_with(error),
        };
        self.state = GssapiExchangeState::AwaitingToken;
        Ok(response)
    }

    /// Alias for [`Self::begin`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin`].
    pub fn start(&mut self, mechanism: &[u8]) -> Result<Vec<u8>, GssapiError> {
        self.begin(mechanism)
    }

    /// Alias for [`Self::begin`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin`].
    pub fn start_response(&mut self, mechanism: &[u8]) -> Result<Vec<u8>, GssapiError> {
        self.begin(mechanism)
    }

    /// Receives and validates a server response on the client side.
    ///
    /// # Errors
    ///
    /// Returns an error and enters the failed state for an out-of-order,
    /// malformed, duplicate, or unsupported response.
    pub fn receive_response(
        &mut self,
        payload: &[u8],
        mechanism: &dyn GssapiTokenMechanism,
    ) -> Result<(), GssapiError> {
        if self.is_terminal() {
            return Err(GssapiError::Terminal);
        }
        if self.state != GssapiExchangeState::AwaitingResponse {
            return self.fail_with(GssapiError::InvalidState);
        }
        let response = match GssapiResponse::decode(payload) {
            Ok(response) => response,
            Err(error) => return self.fail_with(error),
        };
        let expected = match gssapi_mechanism_identifier(mechanism) {
            Ok(expected) => expected,
            Err(error) => return self.fail_with(error),
        };
        if response.mechanism() != expected.as_slice() {
            return self.fail_with(GssapiError::UnsupportedMechanism);
        }
        self.selected_mechanism = expected;
        self.state = GssapiExchangeState::AwaitingToken;
        Ok(())
    }

    /// Receives one token and invokes the caller-owned mechanism.
    ///
    /// # Errors
    ///
    /// Returns a bounded, terminal error for malformed/out-of-order input,
    /// unsupported mechanism, callback panic/failure, an empty/oversized
    /// output, or an exhausted exchange limit.
    pub fn receive_token(
        &mut self,
        payload: &[u8],
        mechanism: &dyn GssapiTokenMechanism,
    ) -> Result<GssapiExchangeAction, GssapiError> {
        if self.is_terminal() {
            return Err(GssapiError::Terminal);
        }
        if self.state != GssapiExchangeState::AwaitingToken {
            return self.fail_with(GssapiError::InvalidState);
        }
        let token = match GssapiToken::decode(payload) {
            Ok(token) => token,
            Err(error) => return self.fail_with(error),
        };
        let expected = match gssapi_mechanism_identifier(mechanism) {
            Ok(expected) => expected,
            Err(error) => return self.fail_with(error),
        };
        if self.selected_mechanism != expected {
            return self.fail_with(GssapiError::UnsupportedMechanism);
        }
        if self.token_exchanges >= self.max_exchanges {
            return self.fail_with(GssapiError::TooManyExchanges);
        }
        self.token_exchanges += 1;
        let result = match catch_unwind(AssertUnwindSafe(|| mechanism.exchange(token.token()))) {
            Ok(result) => result,
            Err(_panic_payload) => return self.fail_with(GssapiError::CallbackPanicked),
        };
        match result {
            GssapiMechanismResult::Continue(output) => {
                if self.token_exchanges >= self.max_exchanges {
                    return self.fail_with(GssapiError::TooManyExchanges);
                }
                if let Err(error) = validate_token(&output) {
                    return self.fail_with(error);
                }
                Ok(GssapiExchangeAction::SendToken(GssapiToken::new(output)))
            }
            GssapiMechanismResult::Accept => {
                self.state = GssapiExchangeState::AwaitingExchangeComplete;
                Ok(GssapiExchangeAction::AwaitExchangeComplete)
            }
            GssapiMechanismResult::AcceptWithToken(output) => {
                if let Err(error) = validate_token(&output) {
                    return self.fail_with(error);
                }
                self.state = GssapiExchangeState::AwaitingExchangeComplete;
                Ok(GssapiExchangeAction::SendToken(GssapiToken::new(output)))
            }
            GssapiMechanismResult::Fail => self.fail_with(GssapiError::CallbackRejected),
        }
    }

    /// Receives the client acknowledgement and marks the exchange complete.
    ///
    /// # Errors
    ///
    /// Returns a terminal error for a duplicate, early, malformed, or
    /// trailing-field acknowledgement.
    pub fn receive_exchange_complete(&mut self, payload: &[u8]) -> Result<(), GssapiError> {
        if self.is_terminal() {
            return Err(GssapiError::Terminal);
        }
        if self.state != GssapiExchangeState::AwaitingExchangeComplete {
            return self.fail_with(GssapiError::InvalidState);
        }
        if let Err(error) = GssapiExchangeComplete::decode(payload) {
            return self.fail_with(error);
        }
        self.state = GssapiExchangeState::Complete;
        Ok(())
    }

    /// Receives and dispatches one of the three supported wire messages.
    ///
    /// # Errors
    ///
    /// Returns the same terminal errors as the corresponding typed method.
    pub fn receive_message(
        &mut self,
        message: &GssapiMessage,
        mechanism: &dyn GssapiTokenMechanism,
    ) -> Result<GssapiExchangeAction, GssapiError> {
        match message {
            GssapiMessage::Response(response) => {
                let payload = match response.encode() {
                    Ok(payload) => payload,
                    Err(error) => return self.fail_with(error),
                };
                self.receive_response(&payload, mechanism)?;
                Ok(GssapiExchangeAction::AwaitToken)
            }
            GssapiMessage::Token(token) => {
                let payload = match token.encode() {
                    Ok(payload) => payload,
                    Err(error) => return self.fail_with(error),
                };
                self.receive_token(&payload, mechanism)
            }
            GssapiMessage::ExchangeComplete(complete) => {
                let payload = match complete.encode() {
                    Ok(payload) => payload,
                    Err(error) => return self.fail_with(error),
                };
                self.receive_exchange_complete(&payload)?;
                Ok(GssapiExchangeAction::Complete)
            }
        }
    }

    /// Decodes and dispatches one complete wire payload.
    ///
    /// # Errors
    ///
    /// Returns the same terminal errors as [`Self::receive_message`].
    pub fn receive_packet(
        &mut self,
        payload: &[u8],
        mechanism: &dyn GssapiTokenMechanism,
    ) -> Result<GssapiExchangeAction, GssapiError> {
        let message = match GssapiMessage::decode(payload) {
            Ok(message) => message,
            Err(error) => return self.fail_with(error),
        };
        self.receive_message(&message, mechanism)
    }

    /// Explicitly marks the exchange terminally failed.
    pub fn fail(&mut self) {
        self.state = GssapiExchangeState::Failed;
    }

    fn fail_with<T>(&mut self, error: GssapiError) -> Result<T, GssapiError> {
        self.state = GssapiExchangeState::Failed;
        Err(error)
    }
}

impl fmt::Debug for GssapiExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GssapiExchange")
            .field("state", &self.state)
            .field("token_exchanges", &self.token_exchanges)
            .field("max_exchanges", &self.max_exchanges)
            .field("mechanism_length", &self.selected_mechanism.len())
            .finish()
    }
}

/// Returns and validates a caller mechanism's opaque identifier.
///
/// The callback is panic-contained.  This helper is useful to dispatchers
/// that must select a mechanism before starting [`GssapiExchange`].
///
/// # Errors
///
/// Returns a bounded error for an empty or oversized identifier or a callback
/// panic.
pub fn gssapi_mechanism_identifier(
    mechanism: &dyn GssapiTokenMechanism,
) -> Result<Vec<u8>, GssapiError> {
    let primary = match catch_unwind(AssertUnwindSafe(|| mechanism.mechanism())) {
        Ok(identifier) => identifier,
        Err(_panic_payload) => return Err(GssapiError::CallbackPanicked),
    };
    let identifier = if primary.is_empty() {
        match catch_unwind(AssertUnwindSafe(|| mechanism.name())) {
            Ok(identifier) => identifier,
            Err(_panic_payload) => return Err(GssapiError::CallbackPanicked),
        }
    } else {
        primary
    };
    validate_mechanism(identifier)?;
    Ok(identifier.to_vec())
}

/// Encodes one RFC 4462 response message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiResponse::encode`].
pub fn encode_gssapi_response<M>(mechanism: M) -> Result<Vec<u8>, GssapiError>
where
    M: AsRef<[u8]>,
{
    GssapiResponse::new(mechanism).encode()
}

/// Decodes one RFC 4462 response message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiResponse::decode`].
pub fn decode_gssapi_response(input: &[u8]) -> Result<GssapiResponse, GssapiError> {
    GssapiResponse::decode(input)
}

/// Encodes one RFC 4462 token message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiToken::encode`].
pub fn encode_gssapi_token<T>(token: T) -> Result<Vec<u8>, GssapiError>
where
    T: AsRef<[u8]>,
{
    GssapiToken::new(token).encode()
}

/// Decodes one RFC 4462 token message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiToken::decode`].
pub fn decode_gssapi_token(input: &[u8]) -> Result<GssapiToken, GssapiError> {
    GssapiToken::decode(input)
}

/// Encodes the empty RFC 4462 exchange-complete message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiExchangeComplete::encode`].
pub fn encode_gssapi_exchange_complete() -> Result<Vec<u8>, GssapiError> {
    GssapiExchangeComplete.encode()
}

/// Decodes the empty RFC 4462 exchange-complete message.
///
/// # Errors
///
/// Returns the same errors as [`GssapiExchangeComplete::decode`].
pub fn decode_gssapi_exchange_complete(
    input: &[u8],
) -> Result<GssapiExchangeComplete, GssapiError> {
    GssapiExchangeComplete::decode(input)
}

/// Decodes any of the three supported RFC 4462 messages.
///
/// # Errors
///
/// Returns the same errors as [`GssapiMessage::decode`].
pub fn decode_gssapi_message(input: &[u8]) -> Result<GssapiMessage, GssapiError> {
    GssapiMessage::decode(input)
}
