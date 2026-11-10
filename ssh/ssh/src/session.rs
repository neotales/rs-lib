//! SSH session channels for client `exec`/`shell` requests and explicit server policy.
//!
//! This module never starts a process and never translates an `exec` command
//! into a platform shell invocation. A server application receives the exact
//! command bytes, makes its own accept/reject decision, writes any response
//! bytes through [`ServerSessions`], and asks this module to send the callback's
//! exit status followed by EOF and CLOSE. When a structured forced command is
//! configured, it is applied only after that callback accepts; the callback
//! still observes the exact peer request and a rejection remains final. An
//! accepted shell is represented as an effective exec request when that
//! forced command is configured; this module still does not execute it.
//!
//! [`ServerSessions`] has two deliberately separate policy layers. The public
//! [`SessionPolicy`] callback remains the base decision for `exec` and `shell`.
//! An optional structured [`ServerPolicy`] is a mandatory gate for PTY,
//! environment, and forwarding-related decisions and supplies the exact
//! forced-command bytes. If both are configured, the callback is evaluated
//! once and a rejection is final; structured policy never upgrades a rejection
//! to success. An endpoint with neither layer remains default-deny.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use neotales_ssh::server_policy::ServerPolicy;
use neotales_ssh::{Reader, Writer};

use crate::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelTransport,
    MAX_CHANNEL_PACKET_SIZE, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
};

/// The RFC 4254 channel type used for interactive and command sessions.
pub const SESSION_CHANNEL_TYPE: &str = "session";
/// The RFC 4254 `exec` channel request name.
pub const SESSION_REQUEST_EXEC: &str = "exec";
/// The RFC 4254 `shell` channel request name.
pub const SESSION_REQUEST_SHELL: &str = "shell";
/// The RFC 4254 `pty-req` channel request name.
pub const SESSION_REQUEST_PTY: &str = "pty-req";
/// The RFC 4254 `env` channel request name.
pub const SESSION_REQUEST_ENV: &str = "env";
/// The RFC 4254 `exit-status` channel request name.
pub const SESSION_REQUEST_EXIT_STATUS: &str = "exit-status";
/// The RFC 4254 `exit-signal` channel request name.
pub const SESSION_REQUEST_EXIT_SIGNAL: &str = "exit-signal";

/// The RFC 4254 terminal-mode opcode that terminates a PTY mode list.
pub const TTY_OP_END: u8 = 0;

/// The maximum number of non-terminal terminal modes in one PTY request.
pub const MAX_PTY_MODES: usize = 256;

/// The maximum byte length of an RFC 4254 exit-signal name.
pub const MAX_EXIT_SIGNAL_NAME_LENGTH: usize = 32;

/// A bounded session protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The shared channel layer rejected an operation or packet.
    Channel(ChannelError),
    /// A session request or reply had an invalid shape or state.
    InvalidRequest,
    /// A message valid for the shared layer was not valid for a session.
    UnexpectedMessage,
    /// The server has not yet accepted an exec or shell request.
    RequestRequired,
    /// The server policy rejected the session request.
    RequestRejected,
    /// Exit status must be sent before EOF on an accepted server session.
    ExitStatusRequired,
    /// EOF must be sent before CLOSE on an accepted server session.
    EofRequired,
    /// The exit status was already sent for this session.
    ExitStatusAlreadySent,
    /// The explicit session policy callback panicked; its payload was discarded.
    CallbackPanicked,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(error) => write!(formatter, "SSH session channel error: {error}"),
            Self::InvalidRequest => formatter.write_str("SSH session request is invalid"),
            Self::UnexpectedMessage => {
                formatter.write_str("SSH session received an unexpected message")
            }
            Self::RequestRequired => {
                formatter.write_str("SSH session requires an accepted exec or shell request")
            }
            Self::RequestRejected => {
                formatter.write_str("SSH session request was rejected by server policy")
            }
            Self::ExitStatusRequired => {
                formatter.write_str("SSH accepted session must send exit status before EOF")
            }
            Self::EofRequired => {
                formatter.write_str("SSH accepted session must send EOF before CLOSE")
            }
            Self::ExitStatusAlreadySent => {
                formatter.write_str("SSH session exit status was already sent")
            }
            Self::CallbackPanicked => {
                formatter.write_str("SSH server session policy callback panicked")
            }
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Channel(error) => Some(error),
            Self::InvalidRequest
            | Self::UnexpectedMessage
            | Self::RequestRequired
            | Self::RequestRejected
            | Self::ExitStatusRequired
            | Self::EofRequired
            | Self::ExitStatusAlreadySent
            | Self::CallbackPanicked => None,
        }
    }
}

impl From<ChannelError> for SessionError {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

/// A borrowed session request passed to an explicit server policy callback.
///
/// `Exec` contains the exact SSH string bytes received from the peer. A
/// structured forced command is applied to the owned result only after this
/// callback accepts; it never changes the bytes observed here. `Shell` has no
/// command field, so no empty or fabricated command is supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRequest<'request> {
    /// An opaque RFC 4254 `exec` command.
    Exec {
        /// Exact command bytes, excluding the SSH string length prefix.
        command: &'request [u8],
    },
    /// An RFC 4254 interactive shell request with no command bytes.
    Shell,
}

/// An owned session request returned in a [`SessionEvent`].
///
/// For an accepted request, an opaque `exec` command contains the effective
/// forced-command bytes when one is configured. An accepted shell request is
/// likewise represented as an effective `exec` request when a forced command
/// exists. Rejected requests retain the exact peer request that the callback
/// evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedSessionRequest {
    /// An opaque `exec` command.
    Exec(Vec<u8>),
    /// A shell request without a command, unless a forced command transformed
    /// the accepted result into [`OwnedSessionRequest::Exec`].
    Shell,
}

/// The result returned by an explicit server session policy callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionDecision {
    accepted: bool,
    exit_status: u32,
}

impl SessionDecision {
    /// Accepts a request and selects the exit status the server will later send.
    #[must_use]
    pub const fn accept(exit_status: u32) -> Self {
        Self {
            accepted: true,
            exit_status,
        }
    }

    /// Rejects a request without fabricating an exit-status request.
    #[must_use]
    pub const fn reject() -> Self {
        Self {
            accepted: false,
            exit_status: 0,
        }
    }

    /// Returns whether the request was accepted.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.accepted
    }

    /// Returns the exit status selected for an accepted request.
    #[must_use]
    pub const fn exit_status(self) -> u32 {
        self.exit_status
    }
}

/// Explicit authorization policy for server session requests.
///
/// A type implementing this trait is itself the required allow callback. Merely
/// constructing [`ServerSessions`] without installing one leaves session opens
/// denied; this trait deliberately has no accepting default implementation.
pub trait SessionPolicy {
    /// Evaluates one exact `exec` or command-free `shell` request.
    fn authorize(&self, request: SessionRequest<'_>) -> SessionDecision;
}

impl<F> SessionPolicy for F
where
    F: for<'request> Fn(SessionRequest<'request>) -> SessionDecision + ?Sized,
{
    fn authorize(&self, request: SessionRequest<'_>) -> SessionDecision {
        self(request)
    }
}

impl SessionPolicy for Box<dyn SessionPolicy> {
    fn authorize(&self, request: SessionRequest<'_>) -> SessionDecision {
        (**self).authorize(request)
    }
}

/// A strict terminal-mode codec failure.
///
/// The decoder does not retain input bytes in this error.  A missing
/// terminator, a truncated value, trailing data, and excessive mode count are
/// kept distinct so callers can diagnose a malformed PTY request without
/// treating its opaque mode string as a shell command or terminal setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtyModesError {
    /// The mode list ended without a `TTY_OP_END` opcode.
    MissingTerminator,
    /// A nonzero opcode was not followed by a complete big-endian `uint32`.
    TruncatedValue,
    /// Bytes remained after the terminating opcode.
    TrailingBytes,
    /// The list contained more than [`MAX_PTY_MODES`] nonzero modes.
    TooManyModes,
    /// Opcode zero was supplied as a mode to the encoder.
    ReservedOpcode,
}

impl fmt::Display for PtyModesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingTerminator => "PTY terminal modes have no terminator",
            Self::TruncatedValue => "PTY terminal mode value is truncated",
            Self::TrailingBytes => "PTY terminal modes contain trailing bytes",
            Self::TooManyModes => "PTY terminal mode list is too long",
            Self::ReservedOpcode => "PTY terminal mode opcode zero is reserved",
        })
    }
}

impl std::error::Error for PtyModesError {}

/// A singular-name alias for [`PtyModesError`].
pub type PtyModeError = PtyModesError;

impl From<PtyModesError> for SessionError {
    fn from(_error: PtyModesError) -> Self {
        Self::InvalidRequest
    }
}

/// One RFC 4254 terminal mode opcode and its 32-bit value.
///
/// The opcode is deliberately not interpreted: values unknown to this crate
/// remain available to callers.  Opcode zero is reserved for the list
/// terminator and is rejected by [`PtyModes::new`] and [`PtyModes::encode`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PtyMode {
    /// The terminal-mode opcode byte.
    pub opcode: u8,
    /// The big-endian `uint32` value associated with the opcode.
    pub value: u32,
}

impl PtyMode {
    /// Creates an unvalidated mode pair.
    ///
    /// Use [`PtyModes::new`] or [`PtyModes::encode`] when the pair will be
    /// emitted; those operations reject opcode zero.
    #[must_use]
    pub const fn new(opcode: u8, value: u32) -> Self {
        Self { opcode, value }
    }

    /// Creates a mode pair after checking that its opcode is nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`PtyModesError::ReservedOpcode`] for opcode zero.
    pub const fn try_new(opcode: u8, value: u32) -> Result<Self, PtyModesError> {
        if opcode == TTY_OP_END {
            Err(PtyModesError::ReservedOpcode)
        } else {
            Ok(Self { opcode, value })
        }
    }

    /// Returns the terminal-mode opcode.
    #[must_use]
    pub const fn opcode(self) -> u8 {
        self.opcode
    }

    /// Returns the terminal-mode value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Returns the opcode/value pair.
    #[must_use]
    pub const fn pair(self) -> (u8, u32) {
        (self.opcode, self.value)
    }
}

impl From<(u8, u32)> for PtyMode {
    fn from((opcode, value): (u8, u32)) -> Self {
        Self::new(opcode, value)
    }
}

impl From<&(u8, u32)> for PtyMode {
    fn from((opcode, value): &(u8, u32)) -> Self {
        Self::new(*opcode, *value)
    }
}

impl From<PtyMode> for (u8, u32) {
    fn from(mode: PtyMode) -> Self {
        mode.pair()
    }
}

impl From<&PtyMode> for (u8, u32) {
    fn from(mode: &PtyMode) -> Self {
        mode.pair()
    }
}

/// A strict, bounded RFC 4254 terminal-mode list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtyModes {
    modes: Vec<PtyMode>,
}

impl PtyModes {
    /// Creates a validated list of nonzero terminal modes.
    ///
    /// # Errors
    ///
    /// Returns [`PtyModesError::ReservedOpcode`] for a zero opcode and
    /// [`PtyModesError::TooManyModes`] when the list exceeds
    /// [`MAX_PTY_MODES`].
    pub fn new<M>(modes: M) -> Result<Self, PtyModesError>
    where
        M: IntoIterator,
        M::Item: Into<PtyMode>,
    {
        let mut bounded = Vec::with_capacity(MAX_PTY_MODES);
        for mode in modes {
            if bounded.len() == MAX_PTY_MODES {
                return Err(PtyModesError::TooManyModes);
            }
            bounded.push(mode.into());
        }
        validate_pty_modes(&bounded)?;
        Ok(Self { modes: bounded })
    }

    /// Decodes one complete terminal-mode string.
    ///
    /// Each nonzero opcode is followed by a big-endian `uint32`.  Opcode zero
    /// ends the list and must be the final byte.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PtyModesError`] for a missing terminator, truncated
    /// value, trailing bytes, or a list longer than [`MAX_PTY_MODES`].
    pub fn decode(input: &[u8]) -> Result<Self, PtyModesError> {
        let mut reader = Reader::new(input);
        let mut modes = Vec::new();
        loop {
            let opcode = reader
                .read_byte()
                .map_err(|_error| PtyModesError::MissingTerminator)?;
            if opcode == TTY_OP_END {
                if !reader.is_empty() {
                    return Err(PtyModesError::TrailingBytes);
                }
                return Ok(Self { modes });
            }
            if modes.len() == MAX_PTY_MODES {
                return Err(PtyModesError::TooManyModes);
            }
            let value = reader
                .read_uint32()
                .map_err(|_error| PtyModesError::TruncatedValue)?;
            modes.push(PtyMode::new(opcode, value));
        }
    }

    /// Decodes one complete terminal-mode string.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, PtyModesError> {
        Self::decode(input)
    }

    /// Encodes the list followed by exactly one terminator byte.
    ///
    /// # Errors
    ///
    /// Returns [`PtyModesError::ReservedOpcode`] if a caller-constructed list
    /// contains opcode zero, or [`PtyModesError::TooManyModes`] if it exceeds
    /// the bounded list size.
    pub fn encode(&self) -> Result<Vec<u8>, PtyModesError> {
        validate_pty_modes(&self.modes)?;
        let mut encoded = Vec::with_capacity(1 + self.modes.len() * 5);
        for mode in &self.modes {
            encoded.push(mode.opcode);
            encoded.extend_from_slice(&mode.value.to_be_bytes());
        }
        encoded.push(TTY_OP_END);
        Ok(encoded)
    }

    /// Encodes the list to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, PtyModesError> {
        self.encode()
    }

    /// Returns the retained modes in wire order.
    #[must_use]
    pub fn as_slice(&self) -> &[PtyMode] {
        &self.modes
    }

    /// Returns the number of nonzero modes before the terminator.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modes.len()
    }

    /// Returns whether the list contains no modes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modes.is_empty()
    }

    /// Iterates over the retained modes in wire order.
    pub fn iter(&self) -> impl Iterator<Item = &PtyMode> {
        self.modes.iter()
    }

    /// Iterates over opcode/value pairs in wire order.
    pub fn pairs(&self) -> impl Iterator<Item = (u8, u32)> + '_ {
        self.modes.iter().map(|mode| mode.pair())
    }

    /// Returns the opcode/value pairs as an owned vector.
    #[must_use]
    pub fn as_pairs(&self) -> Vec<(u8, u32)> {
        self.pairs().collect()
    }
}

impl AsRef<[PtyMode]> for PtyModes {
    fn as_ref(&self) -> &[PtyMode] {
        self.as_slice()
    }
}

impl From<PtyModes> for Vec<PtyMode> {
    fn from(modes: PtyModes) -> Self {
        modes.modes
    }
}

impl TryFrom<&[u8]> for PtyModes {
    type Error = PtyModesError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// The result of applying the strict terminal-mode decoder to a [`PtyRequest`].
///
/// The original mode bytes remain available through [`PtyRequest::modes`].
/// `NotParsed` is intentionally distinct from a protocol failure: legacy
/// callers may send opaque PTY mode strings, and those requests remain
/// accepted without pretending that their bytes have terminal semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PtyModesView {
    /// The opaque bytes decoded successfully into a bounded mode list.
    Parsed(PtyModes),
    /// The opaque bytes did not satisfy the strict terminal-mode decoder.
    NotParsed,
}

impl PtyModesView {
    /// Returns whether the opaque bytes were parsed.
    #[must_use]
    pub const fn is_parsed(&self) -> bool {
        matches!(self, Self::Parsed(_))
    }

    /// Returns whether the opaque bytes were not parsed.
    #[must_use]
    pub const fn is_not_parsed(&self) -> bool {
        matches!(self, Self::NotParsed)
    }

    /// Returns the opcode/value pairs, if the opaque bytes parsed.
    #[must_use]
    pub fn pairs(&self) -> Option<Vec<(u8, u32)>> {
        self.parsed().map(PtyModes::as_pairs)
    }

    /// Returns the parsed list, if any.
    #[must_use]
    pub const fn parsed(&self) -> Option<&PtyModes> {
        match self {
            Self::Parsed(modes) => Some(modes),
            Self::NotParsed => None,
        }
    }

    /// Consumes this view and returns the parsed list, if any.
    #[must_use]
    pub fn into_parsed(self) -> Option<PtyModes> {
        match self {
            Self::Parsed(modes) => Some(modes),
            Self::NotParsed => None,
        }
    }
}

/// A descriptive alias for [`PtyMode`].
pub type TerminalMode = PtyMode;
/// A descriptive alias for [`PtyModes`].
pub type TerminalModes = PtyModes;
/// A descriptive alias for [`PtyModesView`].
pub type ParsedPtyModes = PtyModesView;

/// Decodes one strict RFC 4254 terminal-mode string.
///
/// # Errors
///
/// Returns a typed [`PtyModesError`] for malformed or oversized mode data.
pub fn decode_pty_modes(input: &[u8]) -> Result<PtyModes, PtyModesError> {
    PtyModes::decode(input)
}

/// Encodes a strict RFC 4254 terminal-mode list.
///
/// # Errors
///
/// Returns a typed [`PtyModesError`] for an invalid opcode or an oversized
/// list.
pub fn encode_pty_modes<M>(modes: M) -> Result<Vec<u8>, PtyModesError>
where
    M: IntoIterator,
    M::Item: Into<PtyMode>,
{
    PtyModes::new(modes)?.encode()
}

/// Decodes one strict RFC 4254 terminal-mode string into opcode/value pairs.
///
/// # Errors
///
/// Returns a typed [`PtyModesError`] for malformed or oversized mode data.
pub fn decode_pty_mode_pairs(input: &[u8]) -> Result<Vec<(u8, u32)>, PtyModesError> {
    PtyModes::decode(input).map(|modes| modes.as_pairs())
}

/// Encodes opcode/value pairs as a strict RFC 4254 terminal-mode list.
///
/// # Errors
///
/// Returns a typed [`PtyModesError`] for an invalid opcode or an oversized
/// list.
pub fn encode_pty_mode_pairs<M>(modes: M) -> Result<Vec<u8>, PtyModesError>
where
    M: IntoIterator,
    M::Item: Into<PtyMode>,
{
    encode_pty_modes(modes)
}

/// Decodes one strict RFC 4254 terminal-mode string.
///
/// # Errors
///
/// Returns the same errors as [`decode_pty_modes`].
pub fn decode_terminal_modes(input: &[u8]) -> Result<PtyModes, PtyModesError> {
    decode_pty_modes(input)
}

/// Encodes one strict RFC 4254 terminal-mode list.
///
/// # Errors
///
/// Returns the same errors as [`encode_pty_modes`].
pub fn encode_terminal_modes<M>(modes: M) -> Result<Vec<u8>, PtyModesError>
where
    M: IntoIterator,
    M::Item: Into<PtyMode>,
{
    encode_pty_modes(modes)
}

/// Parsed RFC 4254 PTY dimensions and opaque terminal-mode bytes.
///
/// The library validates and bounds these fields but does not interpret,
/// normalize, or emulate terminal modes.  [`Self::parsed_modes`] provides an
/// optional strict view without changing the opaque wire representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtyRequest {
    term: Vec<u8>,
    character_width: u32,
    character_height: u32,
    pixel_width: u32,
    pixel_height: u32,
    modes: Vec<u8>,
}

impl PtyRequest {
    /// Creates a PTY request value without interpreting its mode bytes.
    #[must_use]
    pub fn new(
        term: &[u8],
        character_width: u32,
        character_height: u32,
        pixel_width: u32,
        pixel_height: u32,
        modes: &[u8],
    ) -> Self {
        Self {
            term: term.to_vec(),
            character_width,
            character_height,
            pixel_width,
            pixel_height,
            modes: modes.to_vec(),
        }
    }

    /// Returns the opaque terminal type bytes.
    #[must_use]
    pub fn term(&self) -> &[u8] {
        &self.term
    }

    /// Returns the character width in columns.
    #[must_use]
    pub const fn character_width(&self) -> u32 {
        self.character_width
    }

    /// Returns the character height in rows.
    #[must_use]
    pub const fn character_height(&self) -> u32 {
        self.character_height
    }

    /// Returns the pixel width.
    #[must_use]
    pub const fn pixel_width(&self) -> u32 {
        self.pixel_width
    }

    /// Returns the pixel height.
    #[must_use]
    pub const fn pixel_height(&self) -> u32 {
        self.pixel_height
    }

    /// Returns the exact opaque mode string.
    #[must_use]
    pub fn modes(&self) -> &[u8] {
        &self.modes
    }

    /// Applies the strict terminal-mode decoder to the opaque mode string.
    ///
    /// A valid list is returned as [`PtyModesView::Parsed`].  Malformed,
    /// truncated, trailing, or oversized data is represented by
    /// [`PtyModesView::NotParsed`]; it is not turned into a PTY request
    /// failure.
    #[must_use]
    pub fn parsed_modes(&self) -> PtyModesView {
        match PtyModes::decode(&self.modes) {
            Ok(modes) => PtyModesView::Parsed(modes),
            Err(_error) => PtyModesView::NotParsed,
        }
    }

    /// Returns the strict terminal-mode view under a descriptive alias.
    #[must_use]
    pub fn modes_view(&self) -> PtyModesView {
        self.parsed_modes()
    }

    /// Parses the opaque mode string and preserves the strict decoder error.
    ///
    /// Unlike [`Self::parsed_modes`], this method is useful when a caller
    /// needs to distinguish a missing terminator from truncation or trailing
    /// bytes.  It does not mutate or reinterpret [`Self::modes`].
    ///
    /// # Errors
    ///
    /// Returns a typed [`PtyModesError`] when the opaque string is not a
    /// strict RFC 4254 terminal-mode list.
    pub fn parse_modes(&self) -> Result<PtyModes, PtyModesError> {
        PtyModes::decode(&self.modes)
    }

    /// Parses the mode string into opcode/value pairs.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PtyModesError`] when the opaque string is malformed.
    pub fn parsed_mode_pairs(&self) -> Result<Vec<(u8, u32)>, PtyModesError> {
        self.parse_modes().map(|modes| modes.as_pairs())
    }

    fn parse(data: &[u8], maximum_string_length: usize) -> Result<Self, SessionError> {
        let mut reader = Reader::new(data);
        let term = reader
            .read_string_with_limit(maximum_string_length)
            .map_err(map_wire_error)?
            .to_vec();
        if term.is_empty() {
            return Err(SessionError::InvalidRequest);
        }
        let character_width = reader.read_uint32().map_err(map_wire_error)?;
        let character_height = reader.read_uint32().map_err(map_wire_error)?;
        let pixel_width = reader.read_uint32().map_err(map_wire_error)?;
        let pixel_height = reader.read_uint32().map_err(map_wire_error)?;
        let modes = reader
            .read_string_with_limit(maximum_string_length)
            .map_err(map_wire_error)?
            .to_vec();
        if !reader.is_empty() {
            return Err(SessionError::InvalidRequest);
        }
        Ok(Self {
            term,
            character_width,
            character_height,
            pixel_width,
            pixel_height,
            modes,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, SessionError> {
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(&self.term, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        writer.write_uint32(self.character_width);
        writer.write_uint32(self.character_height);
        writer.write_uint32(self.pixel_width);
        writer.write_uint32(self.pixel_height);
        writer
            .write_string_with_limit(&self.modes, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        Ok(writer.into_bytes())
    }
}

/// A validated RFC 4254 `env` request payload.
///
/// Both fields remain exact SSH string bytes. The structured server policy
/// decides whether the pair is accepted; this value does not parse, normalize,
/// interpolate, or otherwise interpret environment data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentRequest {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl EnvironmentRequest {
    /// Creates an environment request value while preserving both byte strings
    /// exactly.
    #[must_use]
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
            value: value.to_vec(),
        }
    }

    /// Returns the exact environment-variable name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the exact environment-variable value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Encodes the two request-specific SSH strings.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] when either field cannot fit
    /// within the bounded channel packet.
    pub fn encode(&self) -> Result<Vec<u8>, SessionError> {
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(&self.name, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        writer
            .write_string_with_limit(&self.value, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        let encoded = writer.into_bytes();
        if encoded.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        Ok(encoded)
    }

    /// Encodes the environment request to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, SessionError> {
        self.encode()
    }

    /// Decodes exactly two SSH strings.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] for truncated, oversized, or
    /// trailing request data.
    pub fn decode(data: &[u8]) -> Result<Self, SessionError> {
        Self::decode_with_limit(data, MAX_CHANNEL_PACKET_SIZE as usize)
    }

    /// Decodes two SSH strings with a caller-supplied field limit.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] for malformed or oversized
    /// request data.
    pub fn decode_with_limit(data: &[u8], limit: usize) -> Result<Self, SessionError> {
        if data.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        let limit = limit.min(MAX_CHANNEL_PACKET_SIZE as usize);
        let mut reader = Reader::new(data);
        let name = reader
            .read_string_with_limit(limit)
            .map_err(map_wire_error)?
            .to_vec();
        let value = reader
            .read_string_with_limit(limit)
            .map_err(map_wire_error)?
            .to_vec();
        if !reader.is_empty() {
            return Err(SessionError::InvalidRequest);
        }
        Ok(Self { name, value })
    }

    /// Builds the request name, want-reply byte, and request-specific data.
    ///
    /// # Errors
    ///
    /// Returns the same encoding errors as [`Self::encode`].
    pub fn encode_request_data(&self, want_reply: bool) -> Result<Vec<u8>, SessionError> {
        let request_data = self.encode()?;
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(
                SESSION_REQUEST_ENV.as_bytes(),
                MAX_CHANNEL_PACKET_SIZE as usize,
            )
            .map_err(map_wire_error)?;
        writer.write_boolean(want_reply);
        let mut encoded = writer.into_bytes();
        encoded.extend_from_slice(&request_data);
        if encoded.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        Ok(encoded)
    }
}

impl TryFrom<&[u8]> for EnvironmentRequest {
    type Error = SessionError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(data)
    }
}

/// A validated RFC 4254 `exit-signal` request payload.
///
/// The signal name is an opaque SSH string without an added `SIG` prefix.  The
/// module does not turn it into a host signal, allocate a process, or interpret
/// the diagnostic text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitSignal {
    signal_name: Vec<u8>,
    core_dumped: bool,
    error_message: Vec<u8>,
    language: Vec<u8>,
}

impl ExitSignal {
    /// Creates a validated exit-signal payload.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] when the signal name is empty,
    /// longer than [`MAX_EXIT_SIGNAL_NAME_LENGTH`] bytes, or contains
    /// whitespace or NUL.
    pub fn new(
        signal_name: &[u8],
        core_dumped: bool,
        error_message: &[u8],
        language: &[u8],
    ) -> Result<Self, SessionError> {
        validate_signal_name(signal_name)?;
        Ok(Self {
            signal_name: signal_name.to_vec(),
            core_dumped,
            error_message: error_message.to_vec(),
            language: language.to_vec(),
        })
    }

    /// Decodes one complete exit-signal payload under a byte-slice alias.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, SessionError> {
        Self::decode(data)
    }

    /// Creates a validated exit-signal payload from its four fields.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::new`].
    pub fn from_fields(
        signal_name: &[u8],
        core_dumped: bool,
        error_message: &[u8],
        language: &[u8],
    ) -> Result<Self, SessionError> {
        Self::new(signal_name, core_dumped, error_message, language)
    }

    /// Returns the exact signal-name bytes, without an added prefix.
    #[must_use]
    pub fn signal_name(&self) -> &[u8] {
        &self.signal_name
    }

    /// Returns the exact signal-name bytes under a short alias.
    #[must_use]
    pub fn signal(&self) -> &[u8] {
        self.signal_name()
    }

    /// Returns whether the peer reported that a core was dumped.
    #[must_use]
    pub const fn core_dumped(&self) -> bool {
        self.core_dumped
    }

    /// Returns the exact diagnostic error-message bytes.
    #[must_use]
    pub fn error_message(&self) -> &[u8] {
        &self.error_message
    }

    /// Returns the exact diagnostic message bytes under a short alias.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.error_message()
    }

    /// Returns the exact language-tag bytes.
    #[must_use]
    pub fn language(&self) -> &[u8] {
        &self.language
    }

    /// Returns the exact language-tag bytes under the RFC field-name alias.
    #[must_use]
    pub fn language_tag(&self) -> &[u8] {
        self.language()
    }

    /// Returns the request name used on the wire.
    #[must_use]
    pub const fn request_type() -> &'static str {
        SESSION_REQUEST_EXIT_SIGNAL
    }

    /// Returns the fixed RFC 4254 request's want-reply value.
    #[must_use]
    pub const fn want_reply() -> bool {
        false
    }

    /// Encodes the four request-specific SSH fields in RFC order.
    ///
    /// The channel request name and want-reply boolean are added by
    /// [`crate::channel::ChannelConnection::send_request`] when this payload is
    /// sent as a session request.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] for an invalid signal name or
    /// a field too large for the shared channel packet bound.
    pub fn encode(&self) -> Result<Vec<u8>, SessionError> {
        validate_signal_name(&self.signal_name)?;
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(&self.signal_name, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        writer.write_boolean(self.core_dumped);
        writer
            .write_string_with_limit(&self.error_message, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        writer
            .write_string_with_limit(&self.language, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        let encoded = writer.into_bytes();
        if encoded.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        Ok(encoded)
    }

    /// Encodes the request-specific fields to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, SessionError> {
        self.encode()
    }

    /// Decodes exactly the four RFC 4254 request-specific fields.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] for a truncated field, invalid
    /// boolean, invalid signal name, or trailing bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SessionError> {
        Self::decode_with_limit(data, MAX_CHANNEL_PACKET_SIZE as usize)
    }

    /// Decodes request-specific fields with a caller-supplied string limit.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidRequest`] for malformed, oversized, or
    /// trailing request data.
    pub fn decode_with_limit(data: &[u8], limit: usize) -> Result<Self, SessionError> {
        if data.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        let limit = limit.min(MAX_CHANNEL_PACKET_SIZE as usize);
        let mut reader = Reader::new(data);
        let signal_name = reader
            .read_string_with_limit(limit)
            .map_err(map_wire_error)?
            .to_vec();
        let core_dumped = reader.read_boolean().map_err(map_wire_error)?;
        let error_message = reader
            .read_string_with_limit(limit)
            .map_err(map_wire_error)?
            .to_vec();
        let language = reader
            .read_string_with_limit(limit)
            .map_err(map_wire_error)?
            .to_vec();
        if !reader.is_empty() {
            return Err(SessionError::InvalidRequest);
        }
        Self::new(&signal_name, core_dumped, &error_message, &language)
    }

    /// Builds the request name, fixed want-reply byte, and request data.
    ///
    /// This is the request-specific portion passed after the channel
    /// identifier in an `SSH_MSG_CHANNEL_REQUEST`; the shared channel layer
    /// supplies the message number and recipient channel identifier.
    ///
    /// # Errors
    ///
    /// Returns the same encoding errors as [`Self::encode`].
    pub fn encode_request_data(&self) -> Result<Vec<u8>, SessionError> {
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(
                SESSION_REQUEST_EXIT_SIGNAL.as_bytes(),
                MAX_CHANNEL_PACKET_SIZE as usize,
            )
            .map_err(map_wire_error)?;
        writer.write_boolean(false);
        let mut encoded = writer.into_bytes();
        encoded.extend_from_slice(&self.encode()?);
        if encoded.len() > MAX_CHANNEL_PACKET_SIZE as usize {
            return Err(SessionError::InvalidRequest);
        }
        Ok(encoded)
    }

    /// Returns the request-specific data under a channel-codec alias.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn encode_type_specific_data(&self) -> Result<Vec<u8>, SessionError> {
        self.encode()
    }

    /// Encodes the request name, fixed want-reply byte, and request data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode_request_data`].
    pub fn encode_request(&self) -> Result<Vec<u8>, SessionError> {
        self.encode_request_data()
    }
}

/// A descriptive alias for [`ExitSignal`].
pub type ExitSignalRequest = ExitSignal;

impl TryFrom<&[u8]> for ExitSignal {
    type Error = SessionError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(data)
    }
}

/// One routed client/server session event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// A session channel was confirmed locally.
    Opened {
        /// The local recipient channel identifier.
        session: ChannelId,
    },
    /// A session open was rejected locally or by the peer.
    OpenRejected {
        /// The rejected local sender identifier, or `None` for a server-side rejection.
        session: Option<ChannelId>,
        /// RFC 4254 numeric reason.
        reason: u32,
        /// Peer- or policy-supplied diagnostic bytes.
        description: Vec<u8>,
        /// Peer- or policy-supplied language tag.
        language: Vec<u8>,
    },
    /// The peer granted more room to send data to this session.
    WindowAdjusted {
        /// The recipient session identifier.
        session: ChannelId,
        /// Newly available remote window.
        available: u32,
    },
    /// A complete data packet was delivered to exactly this session.
    Data {
        /// The recipient session identifier.
        session: ChannelId,
        /// The bounded response or input bytes.
        data: Vec<u8>,
    },
    /// Extended data, such as SSH stderr, delivered to exactly this session.
    ExtendedData {
        /// The recipient session identifier.
        session: ChannelId,
        /// RFC 4254 extended-data type code (1 is `SSH_EXTENDED_DATA_STDERR`).
        data_type_code: u32,
        /// The bounded extended-data bytes.
        data: Vec<u8>,
    },
    /// The peer will send no more input on this session.
    Eof {
        /// The recipient session identifier.
        session: ChannelId,
    },
    /// The peer closed this session.
    Close {
        /// The recipient session identifier.
        session: ChannelId,
    },
    /// The server evaluated an exec or shell request.
    Request {
        /// The request's recipient session.
        session: ChannelId,
        /// The owned request value after the structured forced-command layer.
        /// An accepted shell can appear as an effective exec when forced.
        request: OwnedSessionRequest,
        /// Whether SUCCESS or FAILURE was written.
        want_reply: bool,
        /// Whether the explicit callback accepted the request.
        accepted: bool,
        /// The callback-selected status for an accepted request.
        exit_status: Option<u32>,
    },
    /// A valid PTY request arrived, potentially before `shell`.
    PtyRequested {
        /// The request's recipient session.
        session: ChannelId,
        /// Parsed dimensions and opaque modes.
        request: PtyRequest,
        /// Whether SUCCESS was written.
        want_reply: bool,
    },
    /// A valid PTY request was denied by the structured server policy.
    PtyRejected {
        /// The request's recipient session.
        session: ChannelId,
        /// Whether FAILURE was written.
        want_reply: bool,
    },
    /// A valid environment request arrived and was evaluated by policy.
    EnvironmentRequested {
        /// The request's recipient session.
        session: ChannelId,
        /// The exact environment-variable name bytes.
        name: Vec<u8>,
        /// The exact environment-variable value bytes.
        value: Vec<u8>,
        /// Whether SUCCESS or FAILURE was written.
        want_reply: bool,
        /// Whether the structured policy accepted the request.
        accepted: bool,
    },
    /// An unsupported request was rejected when a reply was requested.
    UnsupportedRequest {
        /// The request's recipient session.
        session: ChannelId,
        /// Exact unsupported request type.
        request_type: Vec<u8>,
    },
    /// The peer answered a request with SUCCESS.
    RequestSucceeded {
        /// The recipient session.
        session: ChannelId,
    },
    /// The peer answered a request with FAILURE.
    RequestFailed {
        /// The recipient session.
        session: ChannelId,
    },
    /// The server sent the callback-selected `exit-status` request.
    ExitStatus {
        /// The recipient session.
        session: ChannelId,
        /// Exact process-style status selected by the server callback.
        status: u32,
    },
    /// A server-originated RFC 4254 `exit-signal` request arrived.
    ExitSignal {
        /// The recipient session.
        session: ChannelId,
        /// Exact signal-name bytes, without an added `SIG` prefix.
        signal_name: Vec<u8>,
        /// Whether the peer reported that a core was dumped.
        core_dumped: bool,
        /// Exact diagnostic error-message bytes.
        error_message: Vec<u8>,
        /// Exact language-tag bytes.
        language: Vec<u8>,
    },
}

impl SessionEvent {
    /// Returns the validated exit-signal payload carried by this event.
    #[must_use]
    pub fn exit_signal(&self) -> Option<ExitSignal> {
        match self {
            Self::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                language,
                ..
            } => Some(ExitSignal {
                signal_name: signal_name.clone(),
                core_dumped: *core_dumped,
                error_message: error_message.clone(),
                language: language.clone(),
            }),
            _ => None,
        }
    }
}

/// A client-side session-channel endpoint over one authenticated connection.
#[derive(Debug)]
pub struct ClientSessions<T> {
    channels: ChannelConnection<T>,
}

impl<T> ClientSessions<T> {
    /// Wraps one authenticated client transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
        }
    }

    /// Reuses an existing generic channel connection.
    #[must_use]
    pub const fn from_connection(channels: ChannelConnection<T>) -> Self {
        Self { channels }
    }

    /// Returns the shared channel endpoint.
    #[must_use]
    pub const fn connection(&self) -> &ChannelConnection<T> {
        &self.channels
    }

    /// Returns the mutable shared channel endpoint.
    pub const fn connection_mut(&mut self) -> &mut ChannelConnection<T> {
        &mut self.channels
    }

    /// Consumes this endpoint and returns the generic channel connection.
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

impl<T> ClientSessions<T>
where
    T: ChannelTransport,
{
    /// Allocates a local identifier and opens a standard-limit session.
    ///
    /// The returned identifier is pending until [`Self::dispatch_one`] returns
    /// [`SessionEvent::Opened`].
    ///
    /// # Errors
    ///
    /// Returns a channel allocation, validation, or transport error.
    pub fn open_session(&mut self) -> Result<ChannelId, SessionError> {
        let session = self.channels.allocate_channel_id()?;
        self.open_session_with_id(session)?;
        Ok(session)
    }

    /// Opens a standard-limit session with a caller-selected local identifier.
    ///
    /// # Errors
    ///
    /// Returns a duplicate-id, validation, or transport error.
    pub fn open_session_with_id(&mut self, session: ChannelId) -> Result<(), SessionError> {
        self.channels
            .open_channel(session, SESSION_CHANNEL_TYPE.as_bytes(), &[])?;
        Ok(())
    }

    /// Sends an `exec` request with the command's exact opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns a channel-state, size, wire, or transport error.
    pub fn request_exec(
        &mut self,
        session: ChannelId,
        command: &[u8],
        want_reply: bool,
    ) -> Result<(), SessionError> {
        let mut writer = Writer::new();
        writer
            .write_string_with_limit(command, MAX_CHANNEL_PACKET_SIZE as usize)
            .map_err(map_wire_error)?;
        self.channels.send_request(
            session,
            SESSION_REQUEST_EXEC.as_bytes(),
            want_reply,
            &writer.into_bytes(),
        )?;
        Ok(())
    }

    /// Sends a command-free interactive `shell` request.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn request_shell(
        &mut self,
        session: ChannelId,
        want_reply: bool,
    ) -> Result<(), SessionError> {
        self.channels
            .send_request(session, SESSION_REQUEST_SHELL.as_bytes(), want_reply, &[])?;
        Ok(())
    }

    /// Sends a PTY request whose mode string remains opaque.
    ///
    /// # Errors
    ///
    /// Returns a size, channel-state, or transport error.
    pub fn request_pty(
        &mut self,
        session: ChannelId,
        request: &PtyRequest,
        want_reply: bool,
    ) -> Result<(), SessionError> {
        let data = request.encode()?;
        self.channels
            .send_request(session, SESSION_REQUEST_PTY.as_bytes(), want_reply, &data)?;
        Ok(())
    }

    /// Sends an RFC 4254 environment request without interpreting either
    /// string. The server-side structured policy validates the name and value
    /// when the request is dispatched.
    ///
    /// # Errors
    ///
    /// Returns a size, channel-state, or transport error.
    pub fn request_env(
        &mut self,
        session: ChannelId,
        name: &[u8],
        value: &[u8],
        want_reply: bool,
    ) -> Result<(), SessionError> {
        let request = EnvironmentRequest::new(name, value);
        let data = request.encode()?;
        self.channels
            .send_request(session, SESSION_REQUEST_ENV.as_bytes(), want_reply, &data)?;
        Ok(())
    }

    /// Writes bounded response bytes to an open session.
    ///
    /// # Errors
    ///
    /// Returns a channel-state, maximum-packet, window, or transport error.
    pub fn send_data(&mut self, session: ChannelId, data: &[u8]) -> Result<usize, SessionError> {
        self.channels.write_data(session, data).map_err(Into::into)
    }

    /// Writes typed extended-response bytes to an open session.
    ///
    /// # Errors
    ///
    /// Returns the same channel-state, maximum-packet, window, or transport
    /// errors as [`Self::send_data`].
    pub fn send_extended_data(
        &mut self,
        session: ChannelId,
        data_type_code: u32,
        data: &[u8],
    ) -> Result<usize, SessionError> {
        self.channels
            .write_extended_data(session, data_type_code, data)
            .map_err(Into::into)
    }

    /// Grants the server more room to send session data.
    ///
    /// # Errors
    ///
    /// Returns a zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        session: ChannelId,
        bytes: u32,
    ) -> Result<u32, SessionError> {
        self.channels
            .increase_local_window(session, bytes)
            .map_err(Into::into)
    }

    /// Sends session EOF.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_eof(&mut self, session: ChannelId) -> Result<(), SessionError> {
        self.channels.send_eof(session)?;
        Ok(())
    }

    /// Sends session CLOSE.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_close(&mut self, session: ChannelId) -> Result<(), SessionError> {
        self.channels.send_close(session)?;
        Ok(())
    }

    /// Reads and routes one payload from the single connection reader.
    ///
    /// # Errors
    ///
    /// Returns a channel, malformed session request, or unexpected-message error.
    pub fn dispatch_one(&mut self) -> Result<SessionEvent, SessionError> {
        let event = self
            .channels
            .dispatch_channel_event()?
            .ok_or(SessionError::UnexpectedMessage)?;
        match event {
            ChannelEvent::Opened(session) => Ok(SessionEvent::Opened { session }),
            ChannelEvent::OpenFailed {
                channel,
                reason,
                description,
                language,
            } => Ok(SessionEvent::OpenRejected {
                session: Some(channel),
                reason,
                description,
                language,
            }),
            ChannelEvent::Data {
                channel: session,
                data,
            } => Ok(SessionEvent::Data { session, data }),
            ChannelEvent::ExtendedData {
                channel: session,
                data_type_code,
                data,
            } => Ok(SessionEvent::ExtendedData {
                session,
                data_type_code,
                data,
            }),
            ChannelEvent::Eof { channel: session } => Ok(SessionEvent::Eof { session }),
            ChannelEvent::Close { channel: session } => Ok(SessionEvent::Close { session }),
            ChannelEvent::Request {
                channel: session,
                request_type,
                want_reply,
                data,
            } => self.handle_request(session, request_type, want_reply, &data),
            ChannelEvent::RequestSucceeded { channel: session } => {
                Ok(SessionEvent::RequestSucceeded { session })
            }
            ChannelEvent::RequestFailed { channel: session } => {
                Ok(SessionEvent::RequestFailed { session })
            }
            ChannelEvent::WindowAdjusted { channel, available } => {
                Ok(SessionEvent::WindowAdjusted {
                    session: channel,
                    available,
                })
            }
            ChannelEvent::OpenRequest(_)
            | ChannelEvent::GlobalRequest { .. }
            | ChannelEvent::GlobalRequestSucceeded { .. }
            | ChannelEvent::GlobalRequestFailed { .. } => Err(SessionError::UnexpectedMessage),
        }
    }

    fn handle_request(
        &mut self,
        session: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: &[u8],
    ) -> Result<SessionEvent, SessionError> {
        if request_type == SESSION_REQUEST_EXIT_SIGNAL.as_bytes() {
            let maximum = self
                .channels
                .channel(session)
                .ok_or(SessionError::InvalidRequest)?
                .local_maximum_packet_size() as usize;
            return decode_exit_signal_event(session, want_reply, data, maximum);
        }
        if request_type == SESSION_REQUEST_EXIT_STATUS.as_bytes() {
            let mut reader = Reader::new(data);
            let status = reader.read_uint32().map_err(map_wire_error)?;
            if !reader.is_empty() {
                return Err(SessionError::InvalidRequest);
            }
            return Ok(SessionEvent::ExitStatus { session, status });
        }
        if want_reply {
            self.channels.send_request_failure(session)?;
        }
        Ok(SessionEvent::UnsupportedRequest {
            session,
            request_type,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerRequestState {
    Pending,
    Accepted { exit_status: u32, status_sent: bool },
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServerSessionState {
    request: ServerRequestState,
}

impl ServerSessionState {
    const fn accepted(self) -> bool {
        matches!(self.request, ServerRequestState::Accepted { .. })
    }

    const fn status_sent(self) -> bool {
        matches!(
            self.request,
            ServerRequestState::Accepted {
                status_sent: true,
                ..
            }
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ServerOptionalState {
    pty: bool,
    environment: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A server-side, default-deny session endpoint.
///
/// [`Self::new`] intentionally has no accepting policy. Use
/// [`Self::with_policy`] to install the explicit callback that receives exact
/// exec bytes or a command-free shell request.
pub struct ServerSessions<T> {
    channels: ChannelConnection<T>,
    policy: Option<Box<dyn SessionPolicy>>,
    server_policy: Option<ServerPolicy>,
    allow_channel_open: bool,
    sessions: std::collections::BTreeMap<ChannelId, ServerSessionState>,
    optional: std::collections::BTreeMap<ChannelId, ServerOptionalState>,
}

impl<T> fmt::Debug for ServerSessions<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerSessions")
            .field("channel_count", &self.channels.channel_count())
            .field("policy_configured", &self.policy.is_some())
            .field("server_policy_configured", &self.server_policy.is_some())
            .field("allow_channel_open", &self.allow_channel_open)
            .field("session_count", &self.sessions.len())
            .field("optional_state_count", &self.optional.len())
            .finish()
    }
}

impl<T> ServerSessions<T> {
    /// Creates a default-deny server endpoint over an authenticated transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            channels: ChannelConnection::new(transport),
            policy: None,
            server_policy: None,
            allow_channel_open: false,
            sessions: std::collections::BTreeMap::new(),
            optional: std::collections::BTreeMap::new(),
        }
    }

    /// Creates a server endpoint with one explicit request-policy callback.
    #[must_use]
    pub fn with_policy<F>(transport: T, policy: F) -> Self
    where
        F: for<'request> Fn(SessionRequest<'request>) -> SessionDecision + 'static,
    {
        let mut sessions = Self::new(transport);
        sessions.policy = Some(Box::new(policy));
        sessions.allow_channel_open = true;
        sessions
    }

    /// Creates a server endpoint from a named [`SessionPolicy`] implementation.
    #[must_use]
    pub fn with_session_policy(transport: T, policy: impl SessionPolicy + 'static) -> Self {
        let mut sessions = Self::new(transport);
        sessions.policy = Some(Box::new(policy));
        sessions.allow_channel_open = true;
        sessions
    }

    /// Creates a server endpoint with a structured [`ServerPolicy`].
    ///
    /// The structured policy supplies PTY, environment, forced-command, and
    /// forwarding decisions. It does not replace the required
    /// [`SessionPolicy`] callback for authorizing `exec` or `shell`; install
    /// that callback with [`Self::set_policy`] or use
    /// [`Self::with_policies`]. Consequently, a structured policy alone never
    /// turns a default-deny endpoint into an accepting one.
    #[must_use]
    pub fn with_server_policy(transport: T, policy: ServerPolicy) -> Self {
        let mut sessions = Self::new(transport);
        sessions.server_policy = Some(policy);
        sessions
    }

    /// Creates a server endpoint with both policy layers installed.
    ///
    /// The callback is the base decision for `exec` and `shell`. The structured
    /// policy is then applied as a mandatory constraint for the operations it
    /// owns. A callback rejection is final; structured policy can never turn a
    /// rejected callback decision into success.
    #[must_use]
    pub fn with_policies<F>(transport: T, callback: F, policy: ServerPolicy) -> Self
    where
        F: for<'request> Fn(SessionRequest<'request>) -> SessionDecision + 'static,
    {
        let mut sessions = Self::with_server_policy(transport, policy);
        sessions.policy = Some(Box::new(callback));
        sessions.allow_channel_open = true;
        sessions
    }

    /// Creates a server endpoint with a named callback and structured policy.
    #[must_use]
    pub fn with_session_and_server_policy<P>(
        transport: T,
        callback: P,
        policy: ServerPolicy,
    ) -> Self
    where
        P: SessionPolicy + 'static,
    {
        let mut sessions = Self::with_server_policy(transport, policy);
        sessions.policy = Some(Box::new(callback));
        sessions.allow_channel_open = true;
        sessions
    }

    /// Alias for [`Self::with_session_and_server_policy`].
    #[must_use]
    pub fn with_server_and_session_policy<P>(
        transport: T,
        policy: ServerPolicy,
        callback: P,
    ) -> Self
    where
        P: SessionPolicy + 'static,
    {
        Self::with_session_and_server_policy(transport, callback, policy)
    }

    /// Replaces the explicit request-policy callback and enables session opens.
    pub fn set_policy<F>(&mut self, policy: F)
    where
        F: for<'request> Fn(SessionRequest<'request>) -> SessionDecision + 'static,
    {
        self.policy = Some(Box::new(policy));
        self.allow_channel_open = true;
    }

    /// Replaces policy with a named [`SessionPolicy`] implementation.
    pub fn set_session_policy(&mut self, policy: impl SessionPolicy + 'static) {
        self.policy = Some(Box::new(policy));
        self.allow_channel_open = true;
    }

    /// Installs or replaces the structured policy without changing the
    /// callback layer.
    pub fn set_server_policy(&mut self, policy: ServerPolicy) {
        self.server_policy = Some(policy);
    }

    /// Removes the structured policy. The callback layer is unchanged.
    pub fn clear_server_policy(&mut self) {
        self.server_policy = None;
    }

    /// Returns the installed structured policy, if any.
    #[must_use]
    pub fn server_policy(&self) -> Option<&ServerPolicy> {
        self.server_policy.as_ref()
    }

    /// Returns whether a structured policy is installed.
    #[must_use]
    pub fn server_policy_configured(&self) -> bool {
        self.server_policy.is_some()
    }

    /// Returns whether either policy layer is installed.
    #[must_use]
    pub fn policy_configured(&self) -> bool {
        self.policy.is_some() || self.server_policy.is_some()
    }

    /// Returns whether a forwarding destination is permitted by the installed
    /// structured policy. An absent policy is always deny.
    #[must_use]
    pub fn destination_allowed(&self, host: &[u8], port: u32) -> bool {
        self.server_policy
            .as_ref()
            .is_some_and(|policy| policy.open_allowed_bytes(host, port))
    }

    /// Explicitly enables or disables confirmation of inbound session opens.
    pub const fn set_allow_channel_open(&mut self, allow: bool) {
        self.allow_channel_open = allow;
    }

    /// Returns whether inbound session opens are currently eligible for confirmation.
    #[must_use]
    pub const fn allows_channel_open(&self) -> bool {
        self.allow_channel_open
    }

    /// Returns the shared channel endpoint.
    #[must_use]
    pub const fn connection(&self) -> &ChannelConnection<T> {
        &self.channels
    }

    /// Returns the mutable shared channel endpoint.
    pub const fn connection_mut(&mut self) -> &mut ChannelConnection<T> {
        &mut self.channels
    }

    /// Consumes this endpoint and returns the generic channel connection.
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

impl<T> ServerSessions<T>
where
    T: ChannelTransport,
{
    /// Reads and routes one payload, applying explicit session policy.
    ///
    /// # Errors
    ///
    /// Returns a channel, malformed request, callback-panic, or session-state
    /// error. Rejected open/request replies are returned as successful events.
    pub fn dispatch_one(&mut self) -> Result<SessionEvent, SessionError> {
        let event = self
            .channels
            .dispatch_channel_event()?
            .ok_or(SessionError::UnexpectedMessage)?;
        match event {
            ChannelEvent::OpenRequest(request) => self.handle_open(&request),
            ChannelEvent::Data {
                channel: session,
                data,
            } => {
                self.require_accepted(session)?;
                Ok(SessionEvent::Data { session, data })
            }
            ChannelEvent::ExtendedData {
                channel: session,
                data_type_code,
                data,
            } => {
                self.require_accepted(session)?;
                Ok(SessionEvent::ExtendedData {
                    session,
                    data_type_code,
                    data,
                })
            }
            ChannelEvent::Eof { channel: session } => {
                self.require_accepted(session)?;
                Ok(SessionEvent::Eof { session })
            }
            ChannelEvent::Close { channel: session } => {
                self.sessions.remove(&session);
                self.optional.remove(&session);
                Ok(SessionEvent::Close { session })
            }
            ChannelEvent::Request {
                channel: session,
                request_type,
                want_reply,
                data,
            } => self.handle_request(session, request_type, want_reply, &data),
            ChannelEvent::RequestSucceeded { channel: session } => {
                Ok(SessionEvent::RequestSucceeded { session })
            }
            ChannelEvent::RequestFailed { channel: session } => {
                Ok(SessionEvent::RequestFailed { session })
            }
            ChannelEvent::WindowAdjusted { channel, available } => {
                Ok(SessionEvent::WindowAdjusted {
                    session: channel,
                    available,
                })
            }
            ChannelEvent::Opened(_)
            | ChannelEvent::OpenFailed { .. }
            | ChannelEvent::GlobalRequest { .. }
            | ChannelEvent::GlobalRequestSucceeded { .. }
            | ChannelEvent::GlobalRequestFailed { .. } => Err(SessionError::UnexpectedMessage),
        }
    }

    /// Writes application-selected response bytes after policy acceptance.
    ///
    /// # Errors
    ///
    /// Returns a request-state, channel-state, window, maximum-packet, or
    /// transport error.
    pub fn send_data(&mut self, session: ChannelId, data: &[u8]) -> Result<usize, SessionError> {
        self.require_accepted(session)?;
        if self
            .session_state(session)
            .is_some_and(ServerSessionState::status_sent)
        {
            return Err(SessionError::ExitStatusAlreadySent);
        }
        self.channels.write_data(session, data).map_err(Into::into)
    }

    /// Writes typed extended-response bytes after policy acceptance.
    ///
    /// # Errors
    ///
    /// Returns the same request-state, channel-state, window, maximum-packet,
    /// or transport errors as [`Self::send_data`].
    pub fn send_extended_data(
        &mut self,
        session: ChannelId,
        data_type_code: u32,
        data: &[u8],
    ) -> Result<usize, SessionError> {
        self.require_accepted(session)?;
        if self
            .session_state(session)
            .is_some_and(ServerSessionState::status_sent)
        {
            return Err(SessionError::ExitStatusAlreadySent);
        }
        self.channels
            .write_extended_data(session, data_type_code, data)
            .map_err(Into::into)
    }

    /// Sends the callback-selected `exit-status` exactly once.
    ///
    /// # Errors
    ///
    /// Returns a request-state, already-sent, channel-state, or transport error.
    pub fn send_exit_status(&mut self, session: ChannelId) -> Result<u32, SessionError> {
        let state = self.require_accepted(session)?;
        let ServerRequestState::Accepted {
            exit_status,
            status_sent,
        } = state
        else {
            return Err(SessionError::InvalidRequest);
        };
        if status_sent {
            return Err(SessionError::ExitStatusAlreadySent);
        }
        self.channels.send_request(
            session,
            SESSION_REQUEST_EXIT_STATUS.as_bytes(),
            false,
            &exit_status.to_be_bytes(),
        )?;
        self.set_session_state(
            session,
            ServerSessionState {
                request: ServerRequestState::Accepted {
                    exit_status,
                    status_sent: true,
                },
            },
        );
        Ok(exit_status)
    }

    /// Sends an RFC 4254 `exit-signal` request for an accepted session.
    ///
    /// This method only serializes and writes the request.  It does not create
    /// a process, convert the signal name into a host signal, send an
    /// `exit-status`, or mark the status as sent.  The existing EOF rule
    /// therefore still requires [`Self::send_exit_status`] first.
    ///
    /// # Errors
    ///
    /// Returns a request-state, invalid-signal, channel-state, or transport
    /// error.
    pub fn send_exit_signal(
        &mut self,
        session: ChannelId,
        signal_name: &[u8],
        core_dumped: bool,
        error_message: &[u8],
        language: &[u8],
    ) -> Result<(), SessionError> {
        self.require_accepted(session)?;
        let signal = ExitSignal::new(signal_name, core_dumped, error_message, language)?;
        let data = signal.encode()?;
        self.channels.send_request(
            session,
            SESSION_REQUEST_EXIT_SIGNAL.as_bytes(),
            false,
            &data,
        )?;
        Ok(())
    }

    /// Sends a previously validated RFC 4254 `exit-signal` request.
    ///
    /// # Errors
    ///
    /// Returns a request-state, channel-state, or transport error.
    pub fn send_exit_signal_request(
        &mut self,
        session: ChannelId,
        signal: &ExitSignal,
    ) -> Result<(), SessionError> {
        self.require_accepted(session)?;
        let data = signal.encode()?;
        self.channels.send_request(
            session,
            SESSION_REQUEST_EXIT_SIGNAL.as_bytes(),
            false,
            &data,
        )?;
        Ok(())
    }

    /// Sends EOF after the callback-selected exit status.
    ///
    /// Rejected requests may be closed without an exit status.
    ///
    /// # Errors
    ///
    /// Returns a request-state, missing-status, channel-state, or transport error.
    pub fn send_eof(&mut self, session: ChannelId) -> Result<(), SessionError> {
        let state = self
            .session_state(session)
            .ok_or(SessionError::RequestRequired)?;
        if state.accepted() && !state.status_sent() {
            return Err(SessionError::ExitStatusRequired);
        }
        self.channels.send_eof(session)?;
        Ok(())
    }

    /// Sends CLOSE after EOF for an accepted request.
    ///
    /// # Errors
    ///
    /// Returns a request-state, missing-status, missing-EOF, channel-state, or
    /// transport error.
    pub fn send_close(&mut self, session: ChannelId) -> Result<(), SessionError> {
        let state = self
            .session_state(session)
            .ok_or(SessionError::RequestRequired)?;
        if state.accepted() {
            if !state.status_sent() {
                return Err(SessionError::ExitStatusRequired);
            }
            if !self
                .channels
                .channel(session)
                .is_some_and(|channel| channel.local_eof_sent())
            {
                return Err(SessionError::EofRequired);
            }
        }
        self.channels.send_close(session)?;
        Ok(())
    }

    /// Grants a client more local receive credit after it sends response bytes.
    ///
    /// # Errors
    ///
    /// Returns a request-state, zero, overflow, channel-state, or transport error.
    pub fn increase_local_window(
        &mut self,
        session: ChannelId,
        bytes: u32,
    ) -> Result<u32, SessionError> {
        self.require_accepted(session)?;
        self.channels
            .increase_local_window(session, bytes)
            .map_err(Into::into)
    }

    /// Sends SUCCESS for a server-originated session request.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_request_success(&mut self, session: ChannelId) -> Result<(), SessionError> {
        self.channels.send_request_success(session)?;
        Ok(())
    }

    /// Sends FAILURE for a server-originated session request.
    ///
    /// # Errors
    ///
    /// Returns a channel-state or transport error.
    pub fn send_request_failure(&mut self, session: ChannelId) -> Result<(), SessionError> {
        self.channels.send_request_failure(session)?;
        Ok(())
    }

    fn handle_open(
        &mut self,
        request: &crate::channel::ChannelOpenRequest,
    ) -> Result<SessionEvent, SessionError> {
        if request.channel_type() != SESSION_CHANNEL_TYPE.as_bytes()
            || !request.type_specific_data().is_empty()
        {
            self.channels.reject_open(
                request.sender_channel(),
                SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                b"unsupported channel type",
                b"",
            )?;
            return Ok(SessionEvent::OpenRejected {
                session: None,
                reason: SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                description: b"unsupported channel type".to_vec(),
                language: Vec::new(),
            });
        }
        if self.policy.is_none() || !self.allow_channel_open {
            self.channels.reject_open(
                request.sender_channel(),
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                b"session denied by policy",
                b"",
            )?;
            return Ok(SessionEvent::OpenRejected {
                session: None,
                reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                description: b"session denied by policy".to_vec(),
                language: Vec::new(),
            });
        }
        let local = self.channels.allocate_channel_id()?;
        self.channels
            .confirm_open(request.sender_channel(), local)?;
        self.sessions.insert(
            local,
            ServerSessionState {
                request: ServerRequestState::Pending,
            },
        );
        self.optional.insert(local, ServerOptionalState::default());
        Ok(SessionEvent::Opened { session: local })
    }

    #[allow(clippy::too_many_lines)]
    fn handle_request(
        &mut self,
        session: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: &[u8],
    ) -> Result<SessionEvent, SessionError> {
        let maximum = self
            .channels
            .channel(session)
            .ok_or(SessionError::InvalidRequest)?
            .local_maximum_packet_size() as usize;
        if request_type == SESSION_REQUEST_PTY.as_bytes() {
            let request = PtyRequest::parse(data, maximum)?;
            if !self.tty_allowed() {
                if want_reply {
                    self.channels.send_request_failure(session)?;
                }
                return Ok(SessionEvent::PtyRejected {
                    session,
                    want_reply,
                });
            }
            if want_reply {
                self.channels.send_request_success(session)?;
            }
            let Some(optional) = self.optional.get_mut(&session) else {
                return Err(SessionError::InvalidRequest);
            };
            optional.pty = true;
            return Ok(SessionEvent::PtyRequested {
                session,
                request,
                want_reply,
            });
        }
        if request_type == SESSION_REQUEST_ENV.as_bytes() {
            let request = EnvironmentRequest::decode_with_limit(data, maximum)?;
            let current = self
                .session_state(session)
                .ok_or(SessionError::InvalidRequest)?;
            if current
                != (ServerSessionState {
                    request: ServerRequestState::Pending,
                })
            {
                if want_reply {
                    self.channels.send_request_failure(session)?;
                }
                return Ok(SessionEvent::UnsupportedRequest {
                    session,
                    request_type,
                });
            }
            let accepted = self.environment_allowed(session, &request);
            if accepted {
                if want_reply {
                    self.channels.send_request_success(session)?;
                }
                let Some(optional) = self.optional.get_mut(&session) else {
                    return Err(SessionError::InvalidRequest);
                };
                optional
                    .environment
                    .push((request.name.clone(), request.value.clone()));
            } else if want_reply {
                self.channels.send_request_failure(session)?;
            }
            return Ok(SessionEvent::EnvironmentRequested {
                session,
                name: request.name,
                value: request.value,
                want_reply,
                accepted,
            });
        }
        if request_type == SESSION_REQUEST_EXIT_SIGNAL.as_bytes() {
            return decode_exit_signal_event(session, want_reply, data, maximum);
        }
        if request_type == SESSION_REQUEST_EXIT_STATUS.as_bytes() {
            return Err(SessionError::InvalidRequest);
        }

        let current = self
            .session_state(session)
            .ok_or(SessionError::InvalidRequest)?;
        if current
            != (ServerSessionState {
                request: ServerRequestState::Pending,
            })
        {
            if want_reply {
                self.channels.send_request_failure(session)?;
            }
            return Ok(SessionEvent::UnsupportedRequest {
                session,
                request_type,
            });
        }

        let owned_request = if request_type == SESSION_REQUEST_EXEC.as_bytes() {
            let mut reader = Reader::new(data);
            let command = reader
                .read_string_with_limit(maximum)
                .map_err(map_wire_error)?;
            if !reader.is_empty() {
                return Err(SessionError::InvalidRequest);
            }
            OwnedSessionRequest::Exec(command.to_vec())
        } else if request_type == SESSION_REQUEST_SHELL.as_bytes() {
            if !data.is_empty() {
                return Err(SessionError::InvalidRequest);
            }
            OwnedSessionRequest::Shell
        } else {
            if want_reply {
                self.channels.send_request_failure(session)?;
            }
            return Ok(SessionEvent::UnsupportedRequest {
                session,
                request_type,
            });
        };

        let borrowed = match &owned_request {
            OwnedSessionRequest::Exec(command) => SessionRequest::Exec { command },
            OwnedSessionRequest::Shell => SessionRequest::Shell,
        };
        let forced_command = self
            .server_policy
            .as_ref()
            .and_then(ServerPolicy::forced_command)
            .map(<[u8]>::to_vec);
        let decision = self.authorize(borrowed)?;
        let event_request = if decision.accepted() {
            Self::apply_forced_command(owned_request, forced_command.as_deref())
        } else {
            owned_request
        };
        if decision.accepted() {
            if want_reply {
                self.channels.send_request_success(session)?;
            }
            self.set_session_state(
                session,
                ServerSessionState {
                    request: ServerRequestState::Accepted {
                        exit_status: decision.exit_status(),
                        status_sent: false,
                    },
                },
            );
        } else {
            if want_reply {
                self.channels.send_request_failure(session)?;
            }
            self.set_session_state(
                session,
                ServerSessionState {
                    request: ServerRequestState::Rejected,
                },
            );
        }
        Ok(SessionEvent::Request {
            session,
            request: event_request,
            want_reply,
            accepted: decision.accepted(),
            exit_status: decision.accepted().then_some(decision.exit_status()),
        })
    }

    fn apply_forced_command(
        request: OwnedSessionRequest,
        forced_command: Option<&[u8]>,
    ) -> OwnedSessionRequest {
        match request {
            OwnedSessionRequest::Exec(command) => {
                let effective = forced_command.map_or_else(|| command.clone(), <[u8]>::to_vec);
                OwnedSessionRequest::Exec(effective)
            }
            OwnedSessionRequest::Shell => match forced_command {
                Some(command) => OwnedSessionRequest::Exec(command.to_vec()),
                None => OwnedSessionRequest::Shell,
            },
        }
    }

    fn tty_allowed(&self) -> bool {
        match &self.server_policy {
            Some(policy) => policy.tty_allowed(),
            // A callback-only endpoint predates structured policy and keeps its
            // historical PTY behavior. A completely unconfigured endpoint
            // remains default-deny.
            None => self.policy.is_some(),
        }
    }

    fn environment_allowed(&self, session: ChannelId, request: &EnvironmentRequest) -> bool {
        let Some(policy) = &self.server_policy else {
            return false;
        };
        let Ok(name) = std::str::from_utf8(request.name()) else {
            return false;
        };
        if !policy.env_request_allowed(name, request.value()) {
            return false;
        }
        self.optional.get(&session).is_some_and(|optional| {
            !optional
                .environment
                .iter()
                .any(|(accepted, _)| accepted == request.name())
        })
    }

    fn authorize(&self, request: SessionRequest<'_>) -> Result<SessionDecision, SessionError> {
        let Some(policy) = &self.policy else {
            return Ok(SessionDecision::reject());
        };
        match catch_unwind(AssertUnwindSafe(|| policy.authorize(request))) {
            Ok(decision) => Ok(decision),
            Err(_panic_payload) => Err(SessionError::CallbackPanicked),
        }
    }

    fn require_accepted(&self, session: ChannelId) -> Result<ServerRequestState, SessionError> {
        let state = self
            .session_state(session)
            .ok_or(SessionError::RequestRequired)?;
        if state.accepted() {
            Ok(state.request)
        } else {
            Err(SessionError::RequestRejected)
        }
    }

    fn session_state(&self, session: ChannelId) -> Option<ServerSessionState> {
        self.sessions.get(&session).copied()
    }

    fn set_session_state(&mut self, session: ChannelId, state: ServerSessionState) {
        self.sessions.insert(session, state);
    }
}

fn decode_exit_signal_event(
    session: ChannelId,
    want_reply: bool,
    data: &[u8],
    maximum: usize,
) -> Result<SessionEvent, SessionError> {
    if want_reply {
        return Err(SessionError::InvalidRequest);
    }
    let signal = ExitSignal::decode_with_limit(data, maximum)?;
    Ok(SessionEvent::ExitSignal {
        session,
        signal_name: signal.signal_name,
        core_dumped: signal.core_dumped,
        error_message: signal.error_message,
        language: signal.language,
    })
}

fn validate_pty_modes(modes: &[PtyMode]) -> Result<(), PtyModesError> {
    if modes.len() > MAX_PTY_MODES {
        return Err(PtyModesError::TooManyModes);
    }
    if modes.iter().any(|mode| mode.opcode == TTY_OP_END) {
        return Err(PtyModesError::ReservedOpcode);
    }
    Ok(())
}

fn validate_signal_name(signal_name: &[u8]) -> Result<(), SessionError> {
    if signal_name.is_empty()
        || signal_name.len() > MAX_EXIT_SIGNAL_NAME_LENGTH
        || signal_name
            .iter()
            .any(|byte| *byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(SessionError::InvalidRequest);
    }
    Ok(())
}

fn map_wire_error(_error: neotales_ssh::Error) -> SessionError {
    SessionError::InvalidRequest
}
