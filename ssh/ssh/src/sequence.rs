//! SSH packet sequence numbers and the OpenSSH strict-KEX policy.
//!
//! This module is deliberately independent of packet framing, ciphers, and the
//! message codec.  A transport validates and decrypts a packet first, asks this
//! module to classify its message number, and commits the corresponding
//! sequence number only after the packet has been accepted.  That separation is
//! important: classification and observation never consume a sequence number.

use std::fmt;

/// The client OpenSSH strict-KEX marker.
pub(crate) const KEX_STRICT_C_V00_OPENSSH: &str = "kex-strict-c-v00@openssh.com";

/// The server OpenSSH strict-KEX marker.
pub(crate) const KEX_STRICT_S_V00_OPENSSH: &str = "kex-strict-s-v00@openssh.com";

/// A short alias for [`KEX_STRICT_C_V00_OPENSSH`].
pub(crate) const KEX_STRICT_C_V00: &str = KEX_STRICT_C_V00_OPENSSH;

/// A short alias for [`KEX_STRICT_S_V00_OPENSSH`].
pub(crate) const KEX_STRICT_S_V00: &str = KEX_STRICT_S_V00_OPENSSH;

/// The client marker under a name that emphasizes its protocol role.
pub(crate) const STRICT_KEX_CLIENT_MARKER: &str = KEX_STRICT_C_V00_OPENSSH;

/// The server marker under a name that emphasizes its protocol role.
pub(crate) const STRICT_KEX_SERVER_MARKER: &str = KEX_STRICT_S_V00_OPENSSH;

/// The SSH message number for `SSH_MSG_DISCONNECT`.
pub(crate) const SSH_MSG_DISCONNECT: u8 = 1;

/// The SSH message number for `SSH_MSG_IGNORE`.
pub(crate) const SSH_MSG_IGNORE: u8 = 2;

/// The SSH message number for `SSH_MSG_DEBUG`.
pub(crate) const SSH_MSG_DEBUG: u8 = 3;

/// The SSH message number for `SSH_MSG_UNIMPLEMENTED`.
pub(crate) const SSH_MSG_UNIMPLEMENTED: u8 = 4;

/// The SSH message number for `SSH_MSG_KEXINIT`.
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;

/// The SSH message number for `SSH_MSG_NEWKEYS`.
pub(crate) const SSH_MSG_NEWKEYS: u8 = 21;

/// The first RFC 4253 key-exchange method message number.
pub(crate) const SSH_MSG_KEX_METHOD_FIRST: u8 = 30;

/// The last RFC 4253 key-exchange method message number.
pub(crate) const SSH_MSG_KEX_METHOD_LAST: u8 = 49;

/// A packet direction for the independent SSH sequence counters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    /// Packets received from the peer.
    Inbound,
    /// Packets sent to the peer.
    Outbound,
}

impl Direction {
    /// Returns whether this direction receives packets.
    #[must_use]
    pub const fn is_inbound(self) -> bool {
        matches!(self, Self::Inbound)
    }

    /// Returns whether this direction sends packets.
    #[must_use]
    pub const fn is_outbound(self) -> bool {
        matches!(self, Self::Outbound)
    }
}

/// A compatibility alias for callers that use the longer direction name.
pub(crate) type SequenceDirection = Direction;

/// A compatibility alias for callers that use packet-oriented naming.
pub(crate) type PacketDirection = Direction;

/// A typed failure from sequence or initial-KEX state management.
///
/// Errors contain no packet bytes, algorithm names, or other attacker-
/// controlled values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceError {
    /// A sequence commit would wrap the 32-bit packet counter.
    CounterExhausted,
    /// The requested operation is not valid in the current state.
    InvalidState,
    /// The initial-KEX policy has already entered its terminal state.
    Terminal,
    /// A packet arrived before the phase in which it is permitted.
    OutOfOrder,
    /// A packet type is not permitted by the initial-KEX policy.
    UnexpectedPacket,
    /// Strict mode rejected a normally ignorable or guessed packet.
    StrictViolation,
    /// NEWKEYS has not been observed in both directions.
    Incomplete,
    /// The initial-KEX completion/reset boundary was already applied.
    ResetAlreadyPerformed,
    /// The initial-KEX classifier was used after the handshake became established.
    AfterEstablished,
    /// No non-marker key-exchange algorithm occurs in both proposals.
    NoCommonKexAlgorithm,
}

#[allow(non_upper_case_globals)]
impl SequenceError {
    /// An alias for [`SequenceError::CounterExhausted`].
    pub const Exhausted: Self = Self::CounterExhausted;

    /// An alias for [`SequenceError::InvalidState`].
    pub const InvalidTransition: Self = Self::InvalidState;

    /// An alias for [`SequenceError::Terminal`].
    pub const TerminalState: Self = Self::Terminal;

    /// An alias for [`SequenceError::Incomplete`].
    pub const NotComplete: Self = Self::Incomplete;

    /// An alias for [`SequenceError::ResetAlreadyPerformed`].
    pub const AlreadyReset: Self = Self::ResetAlreadyPerformed;

    /// An alias for [`SequenceError::CounterExhausted`].
    pub const RekeyRequired: Self = Self::CounterExhausted;
}

impl fmt::Display for SequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CounterExhausted => "SSH packet sequence counter is exhausted",
            Self::InvalidState => "SSH sequence state does not allow this operation",
            Self::Terminal => "SSH initial-KEX state is terminal",
            Self::OutOfOrder => "SSH initial-KEX packet arrived out of order",
            Self::UnexpectedPacket => "SSH packet is not permitted during initial KEX",
            Self::StrictViolation => "SSH strict-KEX policy rejected a packet",
            Self::Incomplete => "SSH initial KEX has not received both NEWKEYS messages",
            Self::ResetAlreadyPerformed => "SSH initial-KEX sequence boundary was already applied",
            Self::AfterEstablished => "SSH initial-KEX policy is no longer active",
            Self::NoCommonKexAlgorithm => "SSH proposals have no common key-exchange algorithm",
        })
    }
}

impl std::error::Error for SequenceError {}

/// A short alias for [`SequenceError`].
pub(crate) type StateError = SequenceError;

/// A state-specific alias for [`SequenceError`].
pub(crate) type SequenceStateError = SequenceError;

/// The phase of one initial-KEX direction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum KexPhase {
    /// The direction is waiting for `SSH_MSG_KEXINIT` (20).
    KexInit,
    /// The direction is waiting for one method-specific message (30–49).
    KexMethod,
    /// The direction is waiting for `SSH_MSG_NEWKEYS` (21).
    NewKeys,
    /// The initial KEX has been completed for both directions.
    Established,
    /// The initial-KEX policy has terminated.
    Terminal,
    /// The two directions are in different pre-completion phases.
    Diverged,
}

#[allow(non_upper_case_globals)]
impl KexPhase {
    /// An awaiting-KEXINIT alias for [`KexPhase::KexInit`].
    pub(crate) const AwaitingKexInit: Self = Self::KexInit;

    /// An awaiting-method alias for [`KexPhase::KexMethod`].
    pub(crate) const AwaitingKexMethod: Self = Self::KexMethod;

    /// An awaiting-NEWKEYS alias for [`KexPhase::NewKeys`].
    pub(crate) const AwaitingNewKeys: Self = Self::NewKeys;

    /// Returns whether this is a terminal phase.
    #[must_use]
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }

    /// Returns whether the initial KEX has completed.
    #[must_use]
    pub(crate) const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
}

/// A compatibility alias for code that names the phase explicitly.
pub(crate) type InitialKexPhase = KexPhase;

/// The phase of one direction during a post-establishment rekey.
///
/// A rekey has the same packet skeleton as the initial key exchange, but it
/// starts from an idle connection and must not be confused with the initial
/// KEX policy.  The two directions are tracked independently so that one side
/// may send NEWKEYS before the other side has finished its key-exchange
/// method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RekeyPhase {
    /// No rekey exchange is active.
    Idle,
    /// The direction is waiting for its KEXINIT.
    KexInit,
    /// KEXINIT was observed and the direction is waiting for a KEX method.
    KexMethod,
    /// The KEX method was observed and the direction is waiting for NEWKEYS.
    NewKeys,
    /// Both directional NEWKEYS messages completed the rekey.
    Complete,
    /// The rekey policy has entered a terminal state.
    Terminal,
    /// The two directions are in different active phases.
    Diverged,
}

#[allow(non_upper_case_globals)]
impl RekeyPhase {
    /// An awaiting-KEXINIT alias for [`RekeyPhase::KexInit`].
    pub const AwaitingKexInit: Self = Self::KexInit;

    /// An awaiting-method alias for [`RekeyPhase::KexMethod`].
    pub const AwaitingKexMethod: Self = Self::KexMethod;

    /// An awaiting-NEWKEYS alias for [`RekeyPhase::NewKeys`].
    pub const AwaitingNewKeys: Self = Self::NewKeys;

    /// An established/idle alias for callers that use the connection-oriented
    /// name for the post-establishment ready state.
    pub const Established: Self = Self::Idle;

    /// Returns whether the phase is the ready/idle phase.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Returns whether the phase is one of the active KEX phases.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::KexInit | Self::KexMethod | Self::NewKeys)
    }

    /// Returns whether the rekey has completed.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Returns whether the phase is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

/// A compatibility alias for code that calls the post-establishment phase a
/// KEX phase.
pub(crate) type PostKexPhase = RekeyPhase;

/// The result of classifying one message number during initial KEX.
///
/// A successful result identifies the expected phase transition.  `Ignorable`
/// and `Disconnect` are successful classifications because the caller still
/// needs to decide how to finish the connection; an invalid packet is returned
/// as a [`SequenceError`] by the state methods.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PacketDisposition {
    /// `SSH_MSG_KEXINIT` was expected and advances the direction.
    KexInit,
    /// A method-specific KEX message was expected and advances the direction.
    KexMethod,
    /// `SSH_MSG_NEWKEYS` was expected and completes that direction.
    NewKeys,
    /// The packet is ignorable in a non-strict initial KEX.
    Ignorable,
    /// The peer sent `SSH_MSG_DISCONNECT`; the handshake ends cleanly.
    Disconnect,
    /// A non-successful classification useful to callers that do not use
    /// [`Result`] for classification.
    Fatal,
}

impl PacketDisposition {
    /// Returns whether the disposition advances the initial-KEX phase.
    #[must_use]
    pub(crate) const fn is_expected(self) -> bool {
        matches!(self, Self::KexInit | Self::KexMethod | Self::NewKeys)
    }

    /// Returns whether the packet can be ignored without advancing the phase.
    #[must_use]
    pub(crate) const fn is_ignorable(self) -> bool {
        matches!(self, Self::Ignorable)
    }

    /// Returns whether the disposition represents a fatal classification.
    #[must_use]
    pub(crate) const fn is_fatal(self) -> bool {
        matches!(self, Self::Fatal)
    }
}

/// A compatibility alias for the classification terminology used by transports.
pub(crate) type PacketClass = PacketDisposition;

/// The maximum number of outbound packets required by one hybrid rekey.
pub(crate) const REKEY_OUTBOUND_PACKET_SLOTS: u32 = 3;
/// The maximum number of inbound packets required by one hybrid rekey,
/// including one possible wrong first-KEX guess that must be discarded.
pub(crate) const REKEY_INBOUND_PACKET_SLOTS: u32 = 4;

/// A message observation that can carry the guessed-packet marker from a
/// KEXINIT without coupling this module to the KEXINIT codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketObservation {
    /// The SSH message number at the start of the packet payload.
    pub message_type: u8,
    /// Whether this observation is the guessed packet announced by
    /// `first_kex_packet_follows`.
    pub first_kex_packet_follows: bool,
}

impl PacketObservation {
    /// Creates an ordinary, non-guessed observation.
    #[must_use]
    pub(crate) const fn new(message_type: u8) -> Self {
        Self {
            message_type,
            first_kex_packet_follows: false,
        }
    }

    /// Creates a guessed first-KEX-packet observation.
    #[must_use]
    pub(crate) const fn guessed(message_type: u8) -> Self {
        Self {
            message_type,
            first_kex_packet_follows: true,
        }
    }

    /// Creates an observation with an explicit guessed-packet flag.
    #[must_use]
    pub(crate) const fn with_first_kex_packet_follows(
        message_type: u8,
        first_kex_packet_follows: bool,
    ) -> Self {
        Self {
            message_type,
            first_kex_packet_follows,
        }
    }
}

impl From<u8> for PacketObservation {
    fn from(message_type: u8) -> Self {
        Self::new(message_type)
    }
}

/// The strict-marker predicate used by the proposal filter.
#[must_use]
pub(crate) fn is_strict_kex_marker(name: &str) -> bool {
    name == KEX_STRICT_C_V00_OPENSSH || name == KEX_STRICT_S_V00_OPENSSH
}

/// Removes both strict-KEX marker strings from a KEX name-list.
///
/// The order, duplicates, and ownership of all non-marker names are preserved.
/// The returned names can therefore be passed to the ordinary key-exchange
/// selector without a marker being selected as an algorithm.
#[must_use]
pub(crate) fn filter_kex_algorithms<I, N>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = N>,
    N: AsRef<str>,
{
    names
        .into_iter()
        .filter(|name| !is_strict_kex_marker(name.as_ref()))
        .map(|name| name.as_ref().to_owned())
        .collect()
}

/// An alias for [`filter_kex_algorithms`].
#[must_use]
pub(crate) fn filter_strict_kex_markers<I, N>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = N>,
    N: AsRef<str>,
{
    filter_kex_algorithms(names)
}

/// An alias for [`filter_kex_algorithms`] using removal terminology.
#[must_use]
pub(crate) fn remove_strict_kex_markers<I, N>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = N>,
    N: AsRef<str>,
{
    filter_kex_algorithms(names)
}

/// Reports strict mode only when the client and server markers are present in
/// their respective KEX name-lists.
#[must_use]
pub(crate) fn strict_kex_negotiated<C, CI, S, SI>(client: C, server: S) -> bool
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    client
        .into_iter()
        .any(|name| name.as_ref() == KEX_STRICT_C_V00_OPENSSH)
        && server
            .into_iter()
            .any(|name| name.as_ref() == KEX_STRICT_S_V00_OPENSSH)
}

/// An alias for [`strict_kex_negotiated`].
#[must_use]
pub(crate) fn strict_kex_enabled<C, CI, S, SI>(client: C, server: S) -> bool
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    strict_kex_negotiated(client, server)
}

/// Selects the first client KEX name that is also offered by the server, after
/// removing both strict markers from both lists.
#[must_use]
pub(crate) fn negotiate_kex_algorithm<C, CI, S, SI>(client: C, server: S) -> Option<String>
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    let server: Vec<String> = filter_kex_algorithms(server);
    client
        .into_iter()
        .map(|name| name.as_ref().to_owned())
        .filter(|name| !is_strict_kex_marker(name))
        .find(|candidate| server.iter().any(|server_name| server_name == candidate))
}

/// Selects a non-marker KEX algorithm and reports a typed absence error.
///
/// # Errors
///
/// Returns [`SequenceError::NoCommonKexAlgorithm`] when the filtered proposals
/// have no mutually supported key-exchange name.
pub(crate) fn select_kex_algorithm<C, CI, S, SI>(
    client: C,
    server: S,
) -> Result<String, SequenceError>
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    negotiate_kex_algorithm(client, server).ok_or(SequenceError::NoCommonKexAlgorithm)
}

/// A separate alias for the error returned by [`select_kex_algorithm`].
pub(crate) type KexNegotiationError = SequenceError;

/// The ordered classifier for one connection's initial KEX.
///
/// Inbound and outbound phases are tracked independently because each side
/// sends its own KEXINIT, method-specific message, and NEWKEYS.  The state is
/// still a single policy: completion requires NEWKEYS in both directions.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InitialKexPolicy {
    strict_kex: bool,
    inbound_phase: KexPhase,
    outbound_phase: KexPhase,
    inbound_newkeys: bool,
    outbound_newkeys: bool,
    terminal: bool,
    established: bool,
}

impl Default for InitialKexPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl InitialKexPolicy {
    /// Creates a non-strict initial-KEX policy awaiting KEXINIT in both directions.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_strict_kex(false)
    }

    /// Creates a policy with the supplied strict-mode decision.
    #[must_use]
    pub(crate) fn with_strict_kex(strict_kex: bool) -> Self {
        Self {
            strict_kex,
            inbound_phase: KexPhase::KexInit,
            outbound_phase: KexPhase::KexInit,
            inbound_newkeys: false,
            outbound_newkeys: false,
            terminal: false,
            established: false,
        }
    }

    /// Creates a policy from two KEX name-lists.
    #[must_use]
    pub(crate) fn from_kex_lists<C, CI, S, SI>(client: C, server: S) -> Self
    where
        C: IntoIterator<Item = CI>,
        CI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
    {
        Self::with_strict_kex(strict_kex_negotiated(client, server))
    }

    /// Returns whether strict mode is active for this policy.
    #[must_use]
    pub(crate) const fn strict_kex(&self) -> bool {
        self.strict_kex
    }

    /// Changes the strict-mode decision before the initial KEX completes.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] after a terminal transition and
    /// [`SequenceError::InvalidState`] after the initial KEX is established.
    pub(crate) fn set_strict_kex(&mut self, strict_kex: bool) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.established {
            return Err(SequenceError::InvalidState);
        }
        self.strict_kex = strict_kex;
        Ok(())
    }

    /// Configures strict mode from the two KEX name-lists.
    ///
    /// Returns the resulting strict-mode decision.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::set_strict_kex`].
    pub(crate) fn configure_strict_kex<C, CI, S, SI>(
        &mut self,
        client: C,
        server: S,
    ) -> Result<bool, SequenceError>
    where
        C: IntoIterator<Item = CI>,
        CI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
    {
        let strict = strict_kex_negotiated(client, server);
        self.set_strict_kex(strict)?;
        Ok(strict)
    }

    /// Returns the combined policy phase.
    ///
    /// A state with different directional phases is reported as
    /// [`KexPhase::Diverged`] until both directions reach NEWKEYS.
    #[must_use]
    pub(crate) fn phase(&self) -> KexPhase {
        if self.terminal || self.inbound_phase == KexPhase::Terminal {
            return KexPhase::Terminal;
        }
        if self.established || self.inbound_phase == KexPhase::Established {
            return KexPhase::Established;
        }
        if self.inbound_phase == self.outbound_phase {
            self.inbound_phase
        } else {
            KexPhase::Diverged
        }
    }

    /// Returns the inbound initial-KEX phase.
    #[must_use]
    pub(crate) const fn inbound_phase(&self) -> KexPhase {
        self.inbound_phase
    }

    /// Returns the outbound initial-KEX phase.
    #[must_use]
    pub(crate) const fn outbound_phase(&self) -> KexPhase {
        self.outbound_phase
    }

    /// Returns whether this policy has entered a terminal state.
    #[must_use]
    pub(crate) const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns whether the initial KEX has been explicitly completed.
    #[must_use]
    pub(crate) const fn is_established(&self) -> bool {
        self.established
    }

    /// Returns whether inbound NEWKEYS has been observed.
    #[must_use]
    pub(crate) const fn inbound_newkeys_received(&self) -> bool {
        self.inbound_newkeys
    }

    /// Returns whether outbound NEWKEYS has been observed.
    #[must_use]
    pub(crate) const fn outbound_newkeys_sent(&self) -> bool {
        self.outbound_newkeys
    }

    /// Classifies an inbound message without changing policy or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify(&self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Inbound, message_type)
    }

    /// Classifies an inbound message without changing policy or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Inbound, message_type)
    }

    /// Classifies an outbound message without changing policy or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Outbound, message_type)
    }

    /// Classifies a message in an explicit direction without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_direction(
        &self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(direction, PacketObservation::new(message_type))
    }

    /// Classifies an observation carrying the guessed-packet marker.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_observation(
        &self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        let phase = self.phase_for_direction(direction);
        if phase == KexPhase::NewKeys
            && observation.message_type == SSH_MSG_NEWKEYS
            && match direction {
                Direction::Inbound => self.inbound_newkeys,
                Direction::Outbound => self.outbound_newkeys,
            }
        {
            return Err(SequenceError::OutOfOrder);
        }
        classify_phase(self.strict_kex, phase, observation)
    }

    /// Classifies an inbound guessed packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(Direction::Inbound, PacketObservation::guessed(message_type))
    }

    /// Classifies an outbound guessed packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(
            Direction::Outbound,
            PacketObservation::guessed(message_type),
        )
    }

    /// Observes an inbound message and advances only the policy phase.
    ///
    /// This method never commits the inbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe(&mut self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.observe_inbound(message_type)
    }

    /// Observes a message in an explicit direction and advances only policy.
    ///
    /// This method never commits a sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe_direction(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_observation(direction, PacketObservation::new(message_type))
    }

    /// Observes an inbound message and advances only the policy phase.
    ///
    /// This method never commits the inbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_observation(Direction::Inbound, PacketObservation::new(message_type))
    }

    /// Observes an outbound message and advances only the policy phase.
    ///
    /// This method never commits the outbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_observation(Direction::Outbound, PacketObservation::new(message_type))
    }

    /// Observes a message with an explicit guessed-packet flag.
    ///
    /// This method never commits a sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe_with_guess(
        &mut self,
        direction: Direction,
        message_type: u8,
        guessed: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_observation(
            direction,
            PacketObservation::with_first_kex_packet_follows(message_type, guessed),
        )
    }

    /// Observes a message with its guessed-packet metadata.
    ///
    /// This method never commits a sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  An invalid transition
    /// places the policy in its terminal state.
    pub(crate) fn observe_observation(
        &mut self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        let disposition = match self.classify_observation(direction, observation) {
            Ok(disposition) => disposition,
            Err(error) => {
                if should_terminate(error) {
                    self.mark_terminal();
                }
                return Err(error);
            }
        };

        match disposition {
            PacketDisposition::KexInit => {
                self.set_direction_phase(direction, KexPhase::KexMethod);
            }
            PacketDisposition::KexMethod => {
                self.set_direction_phase(direction, KexPhase::NewKeys);
            }
            PacketDisposition::NewKeys => {
                self.mark_newkeys(direction);
            }
            PacketDisposition::Ignorable => {}
            PacketDisposition::Disconnect => {
                self.mark_terminal();
            }
            PacketDisposition::Fatal => {
                self.mark_terminal();
                return Err(SequenceError::UnexpectedPacket);
            }
        }
        Ok(disposition)
    }

    /// Observes a guessed inbound packet without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_guessed_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_with_guess(Direction::Inbound, message_type, true)
    }

    /// Observes a guessed outbound packet without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_guessed_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_with_guess(Direction::Outbound, message_type, true)
    }

    /// Records a KEXINIT observation, including its guessed-packet flag.
    ///
    /// The flag is retained as protocol metadata; strict mode still permits
    /// the KEX method packet that may follow a correct guess.
    ///
    /// # Errors
    ///
    /// Returns the ordinary state-policy errors for an invalid observation.
    pub(crate) fn observe_kexinit(
        &mut self,
        direction: Direction,
        first_kex_packet_follows: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.established {
            return Err(SequenceError::AfterEstablished);
        }
        let _ = first_kex_packet_follows;
        self.observe_observation(direction, PacketObservation::new(SSH_MSG_KEXINIT))
    }

    /// Completes the initial KEX after both directions have sent NEWKEYS.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Incomplete`] before both NEWKEYS messages have
    /// been observed, [`SequenceError::ResetAlreadyPerformed`] on a repeated
    /// completion, and terminal-state errors after an invalid transition.
    pub(crate) fn complete_initial_kex(&mut self) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.established {
            self.mark_terminal();
            return Err(SequenceError::ResetAlreadyPerformed);
        }
        if !self.inbound_newkeys || !self.outbound_newkeys {
            self.mark_terminal();
            return Err(SequenceError::Incomplete);
        }
        self.established = true;
        self.inbound_phase = KexPhase::Established;
        self.outbound_phase = KexPhase::Established;
        Ok(())
    }

    /// Records completion of a later rekey without changing initial-KEX state.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::InvalidState`] before the initial KEX is
    /// established and terminal-state errors after a failed initial KEX.
    pub(crate) fn complete_rekey(&mut self) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if !self.established {
            self.mark_terminal();
            return Err(SequenceError::InvalidState);
        }
        Ok(())
    }

    fn phase_for_direction(&self, direction: Direction) -> KexPhase {
        if self.terminal {
            return KexPhase::Terminal;
        }
        if self.established {
            return KexPhase::Established;
        }
        match direction {
            Direction::Inbound => self.inbound_phase,
            Direction::Outbound => self.outbound_phase,
        }
    }

    fn set_direction_phase(&mut self, direction: Direction, phase: KexPhase) {
        match direction {
            Direction::Inbound => self.inbound_phase = phase,
            Direction::Outbound => self.outbound_phase = phase,
        }
    }

    fn mark_newkeys(&mut self, direction: Direction) {
        match direction {
            Direction::Inbound => self.inbound_newkeys = true,
            Direction::Outbound => self.outbound_newkeys = true,
        }
    }

    fn mark_terminal(&mut self) {
        self.terminal = true;
        self.inbound_phase = KexPhase::Terminal;
        self.outbound_phase = KexPhase::Terminal;
    }
}

/// The ordered policy for one post-establishment rekey exchange.
///
/// The policy is deliberately separate from [`InitialKexPolicy`].  The
/// initial policy is retired once the connection is established, while this
/// policy can be started again after each successful rekey.  A KEXINIT is
/// accepted once per direction, followed by exactly one method-specific KEX
/// message and NEWKEYS.  Any invalid observation or attempted completion
/// before both NEWKEYS messages makes the policy terminal; a terminal policy
/// can never become complete.
///
/// This type does not own packet sequence counters.  [`SequenceState`] uses it
/// to apply the strict-KEX counter boundary at each directional NEWKEYS.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RekeyPolicy {
    strict_kex: bool,
    inbound_phase: RekeyPhase,
    outbound_phase: RekeyPhase,
    inbound_kexinit: bool,
    outbound_kexinit: bool,
    inbound_kex_method: bool,
    outbound_kex_method: bool,
    inbound_newkeys: bool,
    outbound_newkeys: bool,
    active: bool,
    complete: bool,
    terminal: bool,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RekeyPolicy {
    /// Creates a non-strict policy ready to start a post-establishment rekey.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_strict_kex(false)
    }

    /// Creates a policy with the supplied strict-mode decision.
    #[must_use]
    pub(crate) fn with_strict_kex(strict_kex: bool) -> Self {
        Self {
            strict_kex,
            inbound_phase: RekeyPhase::Idle,
            outbound_phase: RekeyPhase::Idle,
            inbound_kexinit: false,
            outbound_kexinit: false,
            inbound_kex_method: false,
            outbound_kex_method: false,
            inbound_newkeys: false,
            outbound_newkeys: false,
            active: false,
            complete: false,
            terminal: false,
        }
    }

    /// Creates a post-establishment policy from two KEX name-lists.
    #[must_use]
    pub(crate) fn from_kex_lists<C, CI, S, SI>(client: C, server: S) -> Self
    where
        C: IntoIterator<Item = CI>,
        CI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
    {
        Self::with_strict_kex(strict_kex_negotiated(client, server))
    }

    /// Returns whether strict mode is active for rekeys.
    #[must_use]
    pub(crate) const fn strict_kex(&self) -> bool {
        self.strict_kex
    }

    /// Changes strict mode while no rekey is active.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] after a failed rekey and
    /// [`SequenceError::InvalidState`] while a rekey is active or complete.
    pub(crate) fn set_strict_kex(&mut self, strict_kex: bool) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.active || self.complete {
            return Err(SequenceError::InvalidState);
        }
        self.strict_kex = strict_kex;
        Ok(())
    }

    /// Starts a rekey cycle and waits for one KEXINIT in each direction.
    ///
    /// Calling this while a cycle is active is a reentrant transition and
    /// terminally fails the policy.  A new cycle may be started after a prior
    /// cycle has been completed.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] after a failed cycle and
    /// [`SequenceError::InvalidState`] for a reentrant start.
    pub(crate) fn begin_rekey(&mut self) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.active {
            self.mark_terminal();
            return Err(SequenceError::InvalidState);
        }
        self.prepare_cycle();
        Ok(())
    }

    /// Starts a cycle and records KEXINIT for one direction.
    ///
    /// This is useful when the caller has already sent or received that
    /// direction's KEXINIT.  The other direction still has to supply its own
    /// KEXINIT.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub(crate) fn begin_rekey_direction(
        &mut self,
        direction: Direction,
    ) -> Result<(), SequenceError> {
        self.begin_rekey()?;
        self.mark_kexinit(direction);
        Ok(())
    }

    /// An explicit-name alias for [`Self::begin_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub(crate) fn start_rekey(&mut self) -> Result<(), SequenceError> {
        self.begin_rekey()
    }

    /// An alias for [`Self::begin_rekey_direction`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey_direction`].
    pub(crate) fn start_rekey_direction(
        &mut self,
        direction: Direction,
    ) -> Result<(), SequenceError> {
        self.begin_rekey_direction(direction)
    }

    /// Returns the combined rekey phase.
    #[must_use]
    pub(crate) fn phase(&self) -> RekeyPhase {
        if self.terminal {
            return RekeyPhase::Terminal;
        }
        if self.complete {
            return RekeyPhase::Complete;
        }
        if !self.active {
            return RekeyPhase::Idle;
        }
        if self.inbound_phase == self.outbound_phase {
            self.inbound_phase
        } else {
            RekeyPhase::Diverged
        }
    }

    /// Returns the inbound rekey phase.
    #[must_use]
    pub(crate) const fn inbound_phase(&self) -> RekeyPhase {
        self.inbound_phase
    }

    /// Returns the outbound rekey phase.
    #[must_use]
    pub(crate) const fn outbound_phase(&self) -> RekeyPhase {
        self.outbound_phase
    }

    /// Returns whether a rekey cycle is currently active.
    #[must_use]
    pub(crate) const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns whether a rekey cycle is in progress.
    #[must_use]
    pub(crate) const fn is_in_progress(&self) -> bool {
        self.active
    }

    /// Returns whether this policy has entered a terminal state.
    #[must_use]
    pub(crate) const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns whether a rekey has been explicitly completed.
    #[must_use]
    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the policy is ready for a new rekey.
    #[must_use]
    pub(crate) const fn is_established(&self) -> bool {
        !self.terminal && !self.active
    }

    /// Returns whether both directional NEWKEYS messages have been observed.
    #[must_use]
    pub(crate) const fn both_newkeys_received(&self) -> bool {
        self.inbound_newkeys && self.outbound_newkeys
    }

    /// Returns whether the active cycle can be completed.
    #[must_use]
    pub(crate) const fn is_ready_to_complete(&self) -> bool {
        self.active && self.both_newkeys_received()
    }

    /// Returns whether inbound KEXINIT was observed.
    #[must_use]
    pub(crate) const fn inbound_kexinit_received(&self) -> bool {
        self.inbound_kexinit
    }

    /// Returns whether outbound KEXINIT was observed.
    #[must_use]
    pub(crate) const fn outbound_kexinit_sent(&self) -> bool {
        self.outbound_kexinit
    }

    /// Returns whether inbound KEXINIT was observed.
    #[must_use]
    pub(crate) const fn inbound_kexinit_observed(&self) -> bool {
        self.inbound_kexinit
    }

    /// Returns whether outbound KEXINIT was observed.
    #[must_use]
    pub(crate) const fn outbound_kexinit_observed(&self) -> bool {
        self.outbound_kexinit
    }

    /// Returns whether an inbound KEX method was observed.
    #[must_use]
    pub(crate) const fn inbound_kex_method_received(&self) -> bool {
        self.inbound_kex_method
    }

    /// Returns whether an outbound KEX method was observed.
    #[must_use]
    pub(crate) const fn outbound_kex_method_sent(&self) -> bool {
        self.outbound_kex_method
    }

    /// Returns whether inbound NEWKEYS was observed.
    #[must_use]
    pub(crate) const fn inbound_newkeys_received(&self) -> bool {
        self.inbound_newkeys
    }

    /// Returns whether outbound NEWKEYS was observed.
    #[must_use]
    pub(crate) const fn outbound_newkeys_sent(&self) -> bool {
        self.outbound_newkeys
    }

    /// Classifies an inbound message without changing policy state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify(&self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Inbound, message_type)
    }

    /// Classifies an inbound message without changing policy state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Inbound, message_type)
    }

    /// Classifies an outbound message without changing policy state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_direction(Direction::Outbound, message_type)
    }

    /// Classifies a message in an explicit direction without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_direction(
        &self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(direction, PacketObservation::new(message_type))
    }

    /// Classifies an observation without changing policy state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_observation(
        &self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if observation.message_type == SSH_MSG_DISCONNECT {
            return Ok(PacketDisposition::Disconnect);
        }
        if observation.first_kex_packet_follows {
            if self.active
                && self.phase_for_direction(direction) == RekeyPhase::KexMethod
                && is_kex_method_message(observation.message_type)
            {
                return Ok(PacketDisposition::Ignorable);
            }
            return Err(SequenceError::OutOfOrder);
        }

        match observation.message_type {
            SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED if !self.strict_kex => {
                Ok(PacketDisposition::Ignorable)
            }
            SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED => {
                Err(SequenceError::StrictViolation)
            }
            SSH_MSG_KEXINIT => {
                let phase = self.phase_for_direction(direction);
                if (!self.active && !self.complete && phase == RekeyPhase::Idle)
                    || (self.active && phase == RekeyPhase::KexInit)
                {
                    Ok(PacketDisposition::KexInit)
                } else {
                    Err(SequenceError::OutOfOrder)
                }
            }
            SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST => {
                if self.active && self.phase_for_direction(direction) == RekeyPhase::KexMethod {
                    Ok(PacketDisposition::KexMethod)
                } else {
                    Err(SequenceError::OutOfOrder)
                }
            }
            SSH_MSG_NEWKEYS => {
                let phase = self.phase_for_direction(direction);
                let already_received = match direction {
                    Direction::Inbound => self.inbound_newkeys,
                    Direction::Outbound => self.outbound_newkeys,
                };
                if self.active && phase == RekeyPhase::NewKeys && !already_received {
                    Ok(PacketDisposition::NewKeys)
                } else {
                    Err(SequenceError::OutOfOrder)
                }
            }
            _ => Err(SequenceError::UnexpectedPacket),
        }
    }

    /// Classifies an inbound guessed packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(Direction::Inbound, PacketObservation::guessed(message_type))
    }

    /// Classifies an outbound guessed packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_observation(
            Direction::Outbound,
            PacketObservation::guessed(message_type),
        )
    }

    /// Observes an inbound message and advances the rekey policy.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the policy.
    pub(crate) fn observe(&mut self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.observe_inbound(message_type)
    }

    /// Observes an inbound message and advances the rekey policy.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the policy.
    pub(crate) fn observe_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_direction(Direction::Inbound, message_type)
    }

    /// Observes an outbound message and advances the rekey policy.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the policy.
    pub(crate) fn observe_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_direction(Direction::Outbound, message_type)
    }

    /// Observes a message in an explicit direction.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the policy.
    pub(crate) fn observe_direction(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_observation(direction, PacketObservation::new(message_type))
    }

    /// Observes an observation carrying guessed-packet metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the policy.
    pub(crate) fn observe_observation(
        &mut self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        let disposition = match self.classify_observation(direction, observation) {
            Ok(disposition) => disposition,
            Err(error) => {
                if should_terminate_rekey(error) {
                    self.mark_terminal();
                }
                return Err(error);
            }
        };

        match disposition {
            PacketDisposition::KexInit => {
                if !self.active {
                    self.prepare_cycle();
                }
                self.mark_kexinit(direction);
            }
            PacketDisposition::KexMethod => self.mark_kex_method(direction),
            PacketDisposition::NewKeys => self.mark_newkeys(direction),
            PacketDisposition::Ignorable => {}
            PacketDisposition::Disconnect => self.mark_terminal(),
            PacketDisposition::Fatal => {
                self.mark_terminal();
                return Err(SequenceError::UnexpectedPacket);
            }
        }
        Ok(disposition)
    }

    /// Records a KEXINIT and its guessed-packet flag.
    ///
    /// The flag is retained as protocol metadata; strict mode still permits
    /// the KEX method packet that may follow a correct guess.
    ///
    /// # Errors
    ///
    /// Returns an ordinary rekey state-policy error.
    pub(crate) fn observe_kexinit(
        &mut self,
        direction: Direction,
        first_kex_packet_follows: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        let _ = first_kex_packet_follows;
        self.observe_observation(direction, PacketObservation::new(SSH_MSG_KEXINIT))
    }

    /// Records a method-specific KEX message in one direction.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::OutOfOrder`] before that direction's KEXINIT
    /// and [`SequenceError::UnexpectedPacket`] for a non-KEX method number.
    pub(crate) fn observe_kex_method(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if !is_kex_method_message(message_type) {
            self.mark_terminal();
            return Err(SequenceError::UnexpectedPacket);
        }
        if !self.active || self.phase_for_direction(direction) != RekeyPhase::KexMethod {
            self.mark_terminal();
            return Err(SequenceError::OutOfOrder);
        }
        self.mark_kex_method(direction);
        Ok(PacketDisposition::KexMethod)
    }

    /// Records NEWKEYS in one direction.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::OutOfOrder`] before that direction's KEX
    /// method or when NEWKEYS was already recorded.
    pub(crate) fn observe_newkeys(
        &mut self,
        direction: Direction,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        let already_received = match direction {
            Direction::Inbound => self.inbound_newkeys,
            Direction::Outbound => self.outbound_newkeys,
        };
        if !self.active
            || already_received
            || self.phase_for_direction(direction) != RekeyPhase::NewKeys
        {
            self.mark_terminal();
            return Err(SequenceError::OutOfOrder);
        }
        self.mark_newkeys(direction);
        Ok(PacketDisposition::NewKeys)
    }

    /// Completes the active rekey after both directional NEWKEYS messages.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Incomplete`] before both NEWKEYS messages,
    /// [`SequenceError::InvalidState`] without an active cycle, and
    /// [`SequenceError::ResetAlreadyPerformed`] on repeated completion.
    /// Every failed completion is terminal and never becomes complete.
    pub(crate) fn complete_rekey(&mut self) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        if self.complete {
            self.mark_terminal();
            return Err(SequenceError::ResetAlreadyPerformed);
        }
        if !self.active {
            self.mark_terminal();
            return Err(SequenceError::InvalidState);
        }
        if !self.both_newkeys_received() {
            self.mark_terminal();
            return Err(SequenceError::Incomplete);
        }
        self.active = false;
        self.complete = true;
        self.inbound_phase = RekeyPhase::Complete;
        self.outbound_phase = RekeyPhase::Complete;
        Ok(())
    }

    /// An explicit-name alias for [`Self::complete_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::complete_rekey`].
    pub(crate) fn complete(&mut self) -> Result<(), SequenceError> {
        self.complete_rekey()
    }

    /// Explicitly fails the current rekey and makes it terminal.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] if the policy was already failed.
    pub(crate) fn fail_rekey(&mut self) -> Result<(), SequenceError> {
        if self.terminal {
            return Err(SequenceError::Terminal);
        }
        self.mark_terminal();
        Ok(())
    }

    /// An alias for [`Self::fail_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::fail_rekey`].
    pub(crate) fn abort(&mut self) -> Result<(), SequenceError> {
        self.fail_rekey()
    }

    fn prepare_cycle(&mut self) {
        self.inbound_phase = RekeyPhase::KexInit;
        self.outbound_phase = RekeyPhase::KexInit;
        self.inbound_kexinit = false;
        self.outbound_kexinit = false;
        self.inbound_kex_method = false;
        self.outbound_kex_method = false;
        self.inbound_newkeys = false;
        self.outbound_newkeys = false;
        self.active = true;
        self.complete = false;
    }

    fn phase_for_direction(&self, direction: Direction) -> RekeyPhase {
        if self.terminal {
            return RekeyPhase::Terminal;
        }
        if self.complete {
            return RekeyPhase::Complete;
        }
        if !self.active {
            return RekeyPhase::Idle;
        }
        match direction {
            Direction::Inbound => self.inbound_phase,
            Direction::Outbound => self.outbound_phase,
        }
    }

    fn mark_kexinit(&mut self, direction: Direction) {
        match direction {
            Direction::Inbound => {
                self.inbound_kexinit = true;
                self.inbound_phase = RekeyPhase::KexMethod;
            }
            Direction::Outbound => {
                self.outbound_kexinit = true;
                self.outbound_phase = RekeyPhase::KexMethod;
            }
        }
    }

    fn mark_kex_method(&mut self, direction: Direction) {
        match direction {
            Direction::Inbound => {
                self.inbound_kex_method = true;
                self.inbound_phase = RekeyPhase::NewKeys;
            }
            Direction::Outbound => {
                self.outbound_kex_method = true;
                self.outbound_phase = RekeyPhase::NewKeys;
            }
        }
    }

    fn mark_newkeys(&mut self, direction: Direction) {
        match direction {
            Direction::Inbound => self.inbound_newkeys = true,
            Direction::Outbound => self.outbound_newkeys = true,
        }
    }

    fn mark_terminal(&mut self) {
        self.active = false;
        self.complete = false;
        self.terminal = true;
        self.inbound_phase = RekeyPhase::Terminal;
        self.outbound_phase = RekeyPhase::Terminal;
    }
}

/// Compatibility aliases for the post-establishment rekey policy.
pub(crate) type RekeyState = RekeyPolicy;
/// Compatibility alias emphasizing that the policy starts after establishment.
pub(crate) type PostEstablishmentRekeyPolicy = RekeyPolicy;
/// Compatibility alias emphasizing the post-establishment state boundary.
pub(crate) type PostEstablishmentRekeyState = RekeyPolicy;
/// Compatibility alias for code that calls this a key-rekey policy.
pub(crate) type KeyRekeyPolicy = RekeyPolicy;

/// The connection-level sequence and initial-KEX state.
///
/// The two counters represent the next sequence number to use in each
/// direction.  They start at zero after identification.  A caller obtains the
/// current value for packet protection, validates the packet, and then calls
/// [`Self::commit_inbound`] or [`Self::commit_outbound`] exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SequenceState {
    inbound: u32,
    outbound: u32,
    policy: InitialKexPolicy,
    initial_boundary_applied: bool,
    rekey_policy: RekeyPolicy,
    rekey_inbound_newkeys_pending: Option<u32>,
    rekey_outbound_newkeys_pending: Option<u32>,
    rekey_inbound_reset_applied: bool,
    rekey_outbound_reset_applied: bool,
}

impl Default for SequenceState {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceState {
    /// Creates a fresh non-strict connection state with both counters at zero.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_strict_kex(false)
    }

    /// Creates a fresh state with the supplied strict-mode decision.
    #[must_use]
    pub(crate) fn with_strict_kex(strict_kex: bool) -> Self {
        Self {
            inbound: 0,
            outbound: 0,
            policy: InitialKexPolicy::with_strict_kex(strict_kex),
            initial_boundary_applied: false,
            rekey_policy: RekeyPolicy::with_strict_kex(strict_kex),
            rekey_inbound_newkeys_pending: None,
            rekey_outbound_newkeys_pending: None,
            rekey_inbound_reset_applied: false,
            rekey_outbound_reset_applied: false,
        }
    }

    /// An explicit-name alias for [`Self::with_strict_kex`].
    #[must_use]
    pub(crate) fn new_with_strict_kex(strict_kex: bool) -> Self {
        Self::with_strict_kex(strict_kex)
    }

    /// Creates a state whose strict decision is derived from both KEX lists.
    #[must_use]
    pub(crate) fn from_kex_lists<C, CI, S, SI>(client: C, server: S) -> Self
    where
        C: IntoIterator<Item = CI>,
        CI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
    {
        Self::with_strict_kex(strict_kex_negotiated(client, server))
    }

    /// Creates a state at explicit counters.
    ///
    /// This is useful when resuming a connection whose counters are already
    /// known.  Normal new connections should use [`Self::new`].
    #[must_use]
    pub(crate) fn with_counters(inbound: u32, outbound: u32) -> Self {
        Self::with_counters_and_strict(inbound, outbound, false)
    }

    /// Creates a state at explicit counters and with an explicit strict decision.
    #[must_use]
    pub(crate) fn with_counters_and_strict(inbound: u32, outbound: u32, strict_kex: bool) -> Self {
        Self {
            inbound,
            outbound,
            policy: InitialKexPolicy::with_strict_kex(strict_kex),
            initial_boundary_applied: false,
            rekey_policy: RekeyPolicy::with_strict_kex(strict_kex),
            rekey_inbound_newkeys_pending: None,
            rekey_outbound_newkeys_pending: None,
            rekey_inbound_reset_applied: false,
            rekey_outbound_reset_applied: false,
        }
    }

    /// An alias for [`Self::with_counters`].
    #[must_use]
    pub(crate) fn from_counters(inbound: u32, outbound: u32) -> Self {
        Self::with_counters(inbound, outbound)
    }

    /// Returns the current inbound sequence number without consuming it.
    #[must_use]
    pub(crate) const fn inbound_sequence(&self) -> u32 {
        self.inbound
    }

    /// Returns the current outbound sequence number without consuming it.
    #[must_use]
    pub(crate) const fn outbound_sequence(&self) -> u32 {
        self.outbound
    }

    /// Returns the current inbound sequence number without consuming it.
    #[must_use]
    pub(crate) const fn inbound(&self) -> u32 {
        self.inbound
    }

    /// Returns the current outbound sequence number without consuming it.
    #[must_use]
    pub(crate) const fn outbound(&self) -> u32 {
        self.outbound
    }

    /// Returns the current sequence number for a direction without consuming it.
    #[must_use]
    pub(crate) const fn sequence(&self, direction: Direction) -> u32 {
        match direction {
            Direction::Inbound => self.inbound,
            Direction::Outbound => self.outbound,
        }
    }

    /// Returns whether a rekey can reserve enough sequence numbers in one
    /// direction without reaching the exhausted counter.
    #[must_use]
    pub(crate) const fn rekey_headroom_available_for(&self, direction: Direction) -> bool {
        let required = match direction {
            Direction::Inbound => REKEY_INBOUND_PACKET_SLOTS,
            Direction::Outbound => REKEY_OUTBOUND_PACKET_SLOTS,
        };
        self.sequence(direction) <= u32::MAX - required
    }

    /// Returns whether both directions have enough sequence headroom for a
    /// complete hybrid rekey.
    #[must_use]
    pub(crate) const fn rekey_headroom_available(&self) -> bool {
        self.rekey_headroom_available_for(Direction::Inbound)
            && self.rekey_headroom_available_for(Direction::Outbound)
    }

    /// Returns whether the next commit should trigger a rekey.
    ///
    /// The signal becomes true once a successful commit would advance the
    /// counter to `u32::MAX`; it remains true at exhaustion.  A commit at the
    /// exhausted value fails without changing the counter.
    #[must_use]
    pub(crate) const fn needs_rekey(&self, direction: Direction) -> bool {
        self.sequence(direction) >= u32::MAX - 1
    }

    /// An alias for [`Self::needs_rekey`].
    #[must_use]
    pub(crate) const fn requires_rekey(&self, direction: Direction) -> bool {
        self.needs_rekey(direction)
    }

    /// Commits and returns the current inbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::CounterExhausted`] without changing the
    /// counter when the next increment would wrap, and
    /// [`SequenceError::Terminal`] after an initial-KEX terminal transition.
    pub(crate) fn commit_inbound(&mut self) -> Result<u32, SequenceError> {
        self.commit(Direction::Inbound)
    }

    /// Commits and returns the current outbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::CounterExhausted`] without changing the
    /// counter when the next increment would wrap, and
    /// [`SequenceError::Terminal`] after an initial-KEX terminal transition.
    pub(crate) fn commit_outbound(&mut self) -> Result<u32, SequenceError> {
        self.commit(Direction::Outbound)
    }

    /// Commits and returns the current sequence number in a direction.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::CounterExhausted`] without changing the
    /// counter when the next increment would wrap, and
    /// [`SequenceError::Terminal`] after an initial-KEX terminal transition.
    pub(crate) fn commit(&mut self, direction: Direction) -> Result<u32, SequenceError> {
        if self.policy.is_terminal() || self.rekey_policy.is_terminal() {
            return Err(SequenceError::Terminal);
        }
        if let Some(current) = match direction {
            Direction::Inbound => self.rekey_inbound_newkeys_pending.take(),
            Direction::Outbound => self.rekey_outbound_newkeys_pending.take(),
        } {
            return Ok(current);
        }
        let next = match direction {
            Direction::Inbound => self.inbound.checked_add(1),
            Direction::Outbound => self.outbound.checked_add(1),
        };
        let next = next.ok_or(SequenceError::CounterExhausted)?;
        let current = self.sequence(direction);
        match direction {
            Direction::Inbound => self.inbound = next,
            Direction::Outbound => self.outbound = next,
        }
        Ok(current)
    }

    /// Returns whether a commit can currently succeed in a direction.
    #[must_use]
    pub(crate) const fn can_commit(&self, direction: Direction) -> bool {
        !self.policy.is_terminal()
            && !self.rekey_policy.is_terminal()
            && match direction {
                Direction::Inbound => {
                    self.rekey_inbound_newkeys_pending.is_some() || self.inbound != u32::MAX
                }
                Direction::Outbound => {
                    self.rekey_outbound_newkeys_pending.is_some() || self.outbound != u32::MAX
                }
            }
    }

    /// Returns the initial-KEX policy used by this state.
    #[must_use]
    pub(crate) const fn policy(&self) -> &InitialKexPolicy {
        &self.policy
    }

    /// Returns the post-establishment rekey policy used by this state.
    #[must_use]
    pub(crate) const fn rekey_policy(&self) -> &RekeyPolicy {
        &self.rekey_policy
    }

    /// Returns the current combined rekey phase.
    #[must_use]
    pub(crate) fn rekey_phase(&self) -> RekeyPhase {
        self.rekey_policy.phase()
    }

    /// Returns the inbound post-establishment rekey phase.
    #[must_use]
    pub(crate) const fn rekey_inbound_phase(&self) -> RekeyPhase {
        self.rekey_policy.inbound_phase()
    }

    /// Returns the outbound post-establishment rekey phase.
    #[must_use]
    pub(crate) const fn rekey_outbound_phase(&self) -> RekeyPhase {
        self.rekey_policy.outbound_phase()
    }

    /// Returns whether a post-establishment rekey is active.
    #[must_use]
    pub(crate) const fn rekey_active(&self) -> bool {
        self.rekey_policy.is_active()
    }

    /// Returns whether the post-establishment rekey policy is terminal.
    #[must_use]
    pub(crate) const fn rekey_is_terminal(&self) -> bool {
        self.rekey_policy.is_terminal()
    }

    /// Returns whether a post-establishment rekey is complete.
    #[must_use]
    pub(crate) const fn rekey_is_complete(&self) -> bool {
        self.rekey_policy.is_complete()
    }

    /// Returns an explicit-name alias for [`Self::rekey_is_complete`].
    #[must_use]
    pub(crate) const fn rekey_complete(&self) -> bool {
        self.rekey_is_complete()
    }

    /// Returns whether a strict counter reset was applied at a rekey NEWKEYS
    /// boundary in the requested direction.
    #[must_use]
    pub(crate) const fn rekey_reset_applied(&self, direction: Direction) -> bool {
        match direction {
            Direction::Inbound => self.rekey_inbound_reset_applied,
            Direction::Outbound => self.rekey_outbound_reset_applied,
        }
    }

    /// Returns whether the NEWKEYS packet is awaiting its sequence commit.
    #[must_use]
    pub(crate) const fn rekey_reset_pending(&self, direction: Direction) -> bool {
        match direction {
            Direction::Inbound => self.rekey_inbound_newkeys_pending.is_some(),
            Direction::Outbound => self.rekey_outbound_newkeys_pending.is_some(),
        }
    }

    /// Returns the post-establishment rekey policy state name.
    #[must_use]
    pub(crate) const fn rekey_state(&self) -> &RekeyPolicy {
        self.rekey_policy()
    }

    /// Returns the current combined initial-KEX phase.
    #[must_use]
    pub(crate) fn phase(&self) -> KexPhase {
        self.policy.phase()
    }

    /// Returns the inbound initial-KEX phase.
    #[must_use]
    pub(crate) const fn inbound_phase(&self) -> KexPhase {
        self.policy.inbound_phase()
    }

    /// Returns the outbound initial-KEX phase.
    #[must_use]
    pub(crate) const fn outbound_phase(&self) -> KexPhase {
        self.policy.outbound_phase()
    }

    /// Returns whether strict mode is active.
    #[must_use]
    pub(crate) const fn strict_kex(&self) -> bool {
        self.policy.strict_kex()
    }

    /// Changes the strict-mode decision before the initial KEX completes.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] after a terminal transition and
    /// [`SequenceError::InvalidState`] after the initial KEX is established.
    pub(crate) fn set_strict_kex(&mut self, strict_kex: bool) -> Result<(), SequenceError> {
        if self.policy.is_terminal() || self.rekey_policy.is_terminal() {
            return Err(SequenceError::Terminal);
        }
        if self.policy.is_established() {
            return Err(SequenceError::InvalidState);
        }
        self.rekey_policy.set_strict_kex(strict_kex)?;
        self.policy.set_strict_kex(strict_kex)
    }

    /// Configures strict mode from the two KEX name-lists.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Terminal`] after a terminal transition and
    /// [`SequenceError::InvalidState`] after the initial KEX is established.
    pub(crate) fn configure_strict_kex<C, CI, S, SI>(
        &mut self,
        client: C,
        server: S,
    ) -> Result<bool, SequenceError>
    where
        C: IntoIterator<Item = CI>,
        CI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
    {
        let strict = strict_kex_negotiated(client, server);
        self.set_strict_kex(strict)?;
        Ok(strict)
    }

    /// Classifies an inbound message without changing state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify(&self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify(message_type)
    }

    /// Classifies an inbound message without changing state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_inbound(message_type)
    }

    /// Classifies an outbound message without changing state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_outbound(message_type)
    }

    /// Classifies a message in an explicit direction without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_direction(
        &self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_direction(direction, message_type)
    }

    /// Classifies a guessed inbound packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_guessed_inbound(message_type)
    }

    /// Classifies a guessed outbound packet without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_guessed_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_guessed_outbound(message_type)
    }

    /// Classifies an explicit observation without changing state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_observation(
        &self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.classify_observation(direction, observation)
    }

    /// Returns a fatal classification instead of a typed error.
    ///
    /// This helper is useful to dispatchers that first want a total
    /// classification.  State-changing callers should use [`Self::observe`].
    #[must_use]
    pub(crate) fn classify_packet(&self, message_type: u8) -> PacketDisposition {
        match self.classify(message_type) {
            Ok(disposition) => disposition,
            Err(_) => PacketDisposition::Fatal,
        }
    }

    /// Observes an inbound message without committing its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe(&mut self, message_type: u8) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe(message_type)
    }

    /// Observes a message in an explicit direction without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe_direction(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_direction(direction, message_type)
    }

    /// Observes an inbound message without committing its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_inbound(message_type)
    }

    /// Observes an outbound message without committing its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_outbound(message_type)
    }

    /// Observes a message with explicit guessed-packet metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe_with_guess(
        &mut self,
        direction: Direction,
        message_type: u8,
        guessed: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy
            .observe_with_guess(direction, message_type, guessed)
    }

    /// Observes a guessed inbound packet without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_guessed_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_guessed_inbound(message_type)
    }

    /// Observes a guessed outbound packet without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_guessed_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_guessed_outbound(message_type)
    }

    /// Observes an observation without committing a sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// leave the policy terminal.
    pub(crate) fn observe_observation(
        &mut self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy.observe_observation(direction, observation)
    }

    /// Records KEXINIT and its guessed-packet flag without committing a counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_kexinit(
        &mut self,
        direction: Direction,
        first_kex_packet_follows: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        self.policy
            .observe_kexinit(direction, first_kex_packet_follows)
    }

    /// Starts a post-establishment rekey and waits for directional KEXINITs.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::InvalidState`] before the initial KEX is
    /// established or for a reentrant start, and [`SequenceError::Terminal`]
    /// after a failed rekey.
    pub(crate) fn begin_rekey(&mut self) -> Result<(), SequenceError> {
        self.begin_rekey_internal(None)
    }

    /// Starts a rekey and records KEXINIT for one direction.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub(crate) fn begin_rekey_direction(
        &mut self,
        direction: Direction,
    ) -> Result<(), SequenceError> {
        self.begin_rekey_internal(Some(direction))
    }

    /// An alias for [`Self::begin_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub(crate) fn start_rekey(&mut self) -> Result<(), SequenceError> {
        self.begin_rekey()
    }

    /// An alias for [`Self::begin_rekey_direction`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey_direction`].
    pub(crate) fn start_rekey_direction(
        &mut self,
        direction: Direction,
    ) -> Result<(), SequenceError> {
        self.begin_rekey_direction(direction)
    }

    /// Classifies an inbound post-establishment rekey message without changing
    /// state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_rekey(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_rekey_direction(Direction::Inbound, message_type)
    }

    /// Classifies an inbound post-establishment rekey message without changing
    /// state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_rekey_inbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_rekey_direction(Direction::Inbound, message_type)
    }

    /// Classifies an outbound post-establishment rekey message without changing
    /// state or counters.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_rekey_outbound(
        &self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_rekey_direction(Direction::Outbound, message_type)
    }

    /// Classifies a post-establishment rekey message in an explicit direction.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_rekey_direction(
        &self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.classify_rekey_observation(direction, PacketObservation::new(message_type))
    }

    /// Classifies a post-establishment rekey observation without changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn classify_rekey_observation(
        &self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        if self.rekey_policy.is_terminal() || self.policy.is_terminal() {
            return Err(SequenceError::Terminal);
        }
        if !self.policy.is_established() {
            return Err(SequenceError::InvalidState);
        }
        self.rekey_policy
            .classify_observation(direction, observation)
    }

    /// Returns a fatal classification for a post-establishment rekey message.
    #[must_use]
    pub(crate) fn classify_rekey_packet(&self, message_type: u8) -> PacketDisposition {
        match self.classify_rekey(message_type) {
            Ok(disposition) => disposition,
            Err(_) => PacketDisposition::Fatal,
        }
    }

    /// Observes an inbound post-establishment rekey message without committing
    /// its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_inbound(message_type)
    }

    /// Observes an inbound post-establishment rekey message without committing
    /// its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_direction(Direction::Inbound, message_type)
    }

    /// Observes an outbound post-establishment rekey message without committing
    /// its sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_direction(Direction::Outbound, message_type)
    }

    /// Observes a post-establishment rekey message in an explicit direction.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_direction(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_observation(direction, PacketObservation::new(message_type))
    }

    /// Observes a post-establishment rekey observation.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_observation(
        &mut self,
        direction: Direction,
        observation: PacketObservation,
    ) -> Result<PacketDisposition, SequenceError> {
        self.require_rekey_established()?;
        let disposition = self
            .rekey_policy
            .observe_observation(direction, observation)?;
        if disposition == PacketDisposition::NewKeys {
            self.apply_rekey_newkeys_boundary(direction);
        }
        Ok(disposition)
    }

    /// Records KEXINIT for a post-establishment rekey.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_kexinit(
        &mut self,
        direction: Direction,
        first_kex_packet_follows: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        self.require_rekey_established()?;
        let disposition = self
            .rekey_policy
            .observe_kexinit(direction, first_kex_packet_follows)?;
        Ok(disposition)
    }

    /// Records a method-specific KEX message for a post-establishment rekey.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_kex_method(
        &mut self,
        direction: Direction,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.require_rekey_established()?;
        let disposition = self
            .rekey_policy
            .observe_kex_method(direction, message_type)?;
        Ok(disposition)
    }

    /// Records NEWKEYS for one direction and applies its strict sequence
    /// boundary when applicable.
    ///
    /// The returned packet still uses the sequence number that was current
    /// before this observation.  In strict mode the next packet in that
    /// direction starts at zero; [`Self::commit`] consumes the saved NEWKEYS
    /// sequence exactly once without incrementing the reset counter.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_newkeys(
        &mut self,
        direction: Direction,
    ) -> Result<PacketDisposition, SequenceError> {
        self.require_rekey_established()?;
        let disposition = self.rekey_policy.observe_newkeys(direction)?;
        self.apply_rekey_newkeys_boundary(direction);
        Ok(disposition)
    }

    /// Observes a rekey packet with explicit guessed-packet metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.  Invalid transitions
    /// terminally fail the rekey.
    pub(crate) fn observe_rekey_with_guess(
        &mut self,
        direction: Direction,
        message_type: u8,
        guessed: bool,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_observation(
            direction,
            PacketObservation::with_first_kex_packet_follows(message_type, guessed),
        )
    }

    /// Observes a guessed inbound rekey packet.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_rekey_guessed_inbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_with_guess(Direction::Inbound, message_type, true)
    }

    /// Observes a guessed outbound rekey packet.
    ///
    /// # Errors
    ///
    /// Returns a typed state or packet-policy error.
    pub(crate) fn observe_rekey_guessed_outbound(
        &mut self,
        message_type: u8,
    ) -> Result<PacketDisposition, SequenceError> {
        self.observe_rekey_with_guess(Direction::Outbound, message_type, true)
    }

    /// Completes an active post-establishment rekey.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Incomplete`] before both directional NEWKEYS
    /// messages or while a strict directional NEWKEYS sequence commit is still
    /// pending, and terminal errors after a failed or repeated completion.
    pub(crate) fn complete_rekey_exchange(&mut self) -> Result<(), SequenceError> {
        self.require_rekey_established()?;
        if self.rekey_inbound_newkeys_pending.is_some()
            || self.rekey_outbound_newkeys_pending.is_some()
        {
            self.rekey_policy.fail_rekey()?;
            return Err(SequenceError::Incomplete);
        }
        self.rekey_policy.complete_rekey()
    }

    /// An explicit-name alias for [`Self::complete_rekey_exchange`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::complete_rekey_exchange`].
    pub(crate) fn finish_rekey(&mut self) -> Result<(), SequenceError> {
        self.complete_rekey_exchange()
    }

    /// Explicitly fails the current post-establishment rekey.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::InvalidState`] before establishment and
    /// [`SequenceError::Terminal`] after a previous failure.
    pub(crate) fn fail_rekey(&mut self) -> Result<(), SequenceError> {
        if self.policy.is_terminal() {
            return Err(SequenceError::Terminal);
        }
        if !self.policy.is_established() {
            self.rekey_policy.fail_rekey()?;
            return Err(SequenceError::InvalidState);
        }
        self.rekey_inbound_newkeys_pending = None;
        self.rekey_outbound_newkeys_pending = None;
        self.rekey_policy.fail_rekey()
    }

    /// An alias for [`Self::fail_rekey`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::fail_rekey`].
    pub(crate) fn abort_rekey(&mut self) -> Result<(), SequenceError> {
        self.fail_rekey()
    }

    /// Completes the initial KEX and applies its one-time sequence boundary.
    ///
    /// Strict mode resets both counters to zero.  Non-strict mode leaves both
    /// counters unchanged.  In either mode, a second call returns
    /// [`SequenceError::ResetAlreadyPerformed`].
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::Incomplete`] before both NEWKEYS messages have
    /// been observed and terminal-state errors after an invalid transition.
    pub(crate) fn complete_initial_kex(&mut self) -> Result<(), SequenceError> {
        if self.initial_boundary_applied {
            self.policy.mark_terminal();
            return Err(SequenceError::ResetAlreadyPerformed);
        }
        self.policy.complete_initial_kex()?;
        self.initial_boundary_applied = true;
        if self.policy.strict_kex() {
            self.inbound = 0;
            self.outbound = 0;
        }
        Ok(())
    }

    /// An explicit reset-oriented alias for [`Self::complete_initial_kex`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::complete_initial_kex`].
    pub(crate) fn reset_sequences(&mut self) -> Result<(), SequenceError> {
        self.complete_initial_kex()
    }

    /// An alias for [`Self::reset_sequences`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::complete_initial_kex`].
    pub(crate) fn reset_after_initial_kex(&mut self) -> Result<(), SequenceError> {
        self.complete_initial_kex()
    }

    /// Configures strict mode and completes the initial KEX in one operation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::set_strict_kex`] and
    /// [`Self::complete_initial_kex`].
    pub(crate) fn complete_initial_kex_with_strict(
        &mut self,
        strict_kex: bool,
    ) -> Result<(), SequenceError> {
        self.set_strict_kex(strict_kex)?;
        self.complete_initial_kex()
    }

    /// Records completion of a later rekey.
    ///
    /// When no post-establishment rekey has been started, this retains the
    /// original API behavior and only verifies that the initial KEX is
    /// established.  Once a rekey cycle is active, completion is delegated to
    /// the explicit rekey policy and therefore requires both NEWKEYS messages.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::InvalidState`] before the initial KEX is
    /// established, [`SequenceError::Incomplete`] for an unfinished rekey, and
    /// terminal-state errors after a failed rekey.
    pub(crate) fn complete_rekey(&mut self) -> Result<(), SequenceError> {
        if self.rekey_policy.is_active()
            || self.rekey_policy.is_terminal()
            || self.rekey_policy.is_complete()
        {
            self.complete_rekey_exchange()
        } else {
            self.policy.complete_rekey()
        }
    }

    /// Returns whether the one-time initial-KEX boundary was applied.
    #[must_use]
    pub(crate) const fn initial_boundary_applied(&self) -> bool {
        self.initial_boundary_applied
    }

    /// Returns whether the initial KEX is established.
    #[must_use]
    pub(crate) const fn initial_kex_complete(&self) -> bool {
        self.policy.is_established()
    }

    /// Returns whether strict mode reset both counters at the initial boundary.
    #[must_use]
    pub(crate) const fn strict_reset_applied(&self) -> bool {
        self.initial_boundary_applied && self.policy.strict_kex()
    }

    /// Returns whether the initial-KEX or post-establishment rekey policy is
    /// terminal.
    #[must_use]
    pub(crate) const fn is_terminal(&self) -> bool {
        self.policy.is_terminal() || self.rekey_policy.is_terminal()
    }

    fn begin_rekey_internal(&mut self, direction: Option<Direction>) -> Result<(), SequenceError> {
        self.require_rekey_established()?;
        if self.rekey_inbound_newkeys_pending.is_some()
            || self.rekey_outbound_newkeys_pending.is_some()
        {
            self.rekey_policy.fail_rekey()?;
            return Err(SequenceError::Incomplete);
        }
        if self.rekey_policy.is_active() {
            return match direction {
                Some(direction) => self.rekey_policy.begin_rekey_direction(direction),
                None => self.rekey_policy.begin_rekey(),
            };
        }
        if !self.rekey_headroom_available() {
            return Err(SequenceError::CounterExhausted);
        }
        match direction {
            Some(direction) => self.rekey_policy.begin_rekey_direction(direction)?,
            None => self.rekey_policy.begin_rekey()?,
        }
        self.rekey_inbound_reset_applied = false;
        self.rekey_outbound_reset_applied = false;
        Ok(())
    }

    fn require_rekey_established(&mut self) -> Result<(), SequenceError> {
        if self.policy.is_terminal() || self.rekey_policy.is_terminal() {
            return Err(SequenceError::Terminal);
        }
        if !self.policy.is_established() {
            self.rekey_policy.fail_rekey()?;
            return Err(SequenceError::InvalidState);
        }
        Ok(())
    }

    fn apply_rekey_newkeys_boundary(&mut self, direction: Direction) {
        if !self.policy.strict_kex() {
            return;
        }
        match direction {
            Direction::Inbound => {
                if self.rekey_inbound_newkeys_pending.is_none() {
                    self.rekey_inbound_newkeys_pending = Some(self.inbound);
                    self.inbound = 0;
                }
                self.rekey_inbound_reset_applied = true;
            }
            Direction::Outbound => {
                if self.rekey_outbound_newkeys_pending.is_none() {
                    self.rekey_outbound_newkeys_pending = Some(self.outbound);
                    self.outbound = 0;
                }
                self.rekey_outbound_reset_applied = true;
            }
        }
    }
}

/// An alias for the initial-KEX policy state.
pub(crate) type InitialKexState = InitialKexPolicy;

/// An alias for the connection-level KEX and sequence state.
pub(crate) type KexSequenceState = SequenceState;

/// A compatibility alias for code that names the state after packet sequence numbers.
pub(crate) type SequenceNumbers = SequenceState;

/// A compatibility alias for transport-facing sequence state.
pub(crate) type PacketSequenceState = SequenceState;

/// A compatibility alias for the SSH-specific state name.
pub(crate) type SshSequenceState = SequenceState;

fn classify_phase(
    strict_kex: bool,
    phase: KexPhase,
    observation: PacketObservation,
) -> Result<PacketDisposition, SequenceError> {
    if phase == KexPhase::Terminal {
        return Err(SequenceError::Terminal);
    }
    if phase == KexPhase::Established {
        return Err(SequenceError::AfterEstablished);
    }

    if observation.message_type == SSH_MSG_DISCONNECT {
        return Ok(PacketDisposition::Disconnect);
    }
    if observation.first_kex_packet_follows {
        if phase == KexPhase::KexMethod
            && (SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST)
                .contains(&observation.message_type)
        {
            return Ok(PacketDisposition::Ignorable);
        }
        return Err(SequenceError::OutOfOrder);
    }

    match observation.message_type {
        SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED if !strict_kex => {
            Ok(PacketDisposition::Ignorable)
        }
        SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED => {
            Err(SequenceError::StrictViolation)
        }
        SSH_MSG_KEXINIT if phase == KexPhase::KexInit => Ok(PacketDisposition::KexInit),
        SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST if phase == KexPhase::KexMethod => {
            Ok(PacketDisposition::KexMethod)
        }
        SSH_MSG_NEWKEYS if phase == KexPhase::NewKeys => Ok(PacketDisposition::NewKeys),
        SSH_MSG_KEXINIT | SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST | SSH_MSG_NEWKEYS => {
            Err(SequenceError::OutOfOrder)
        }
        _ => Err(SequenceError::UnexpectedPacket),
    }
}

fn should_terminate(error: SequenceError) -> bool {
    matches!(
        error,
        SequenceError::OutOfOrder
            | SequenceError::UnexpectedPacket
            | SequenceError::StrictViolation
    )
}

fn is_kex_method_message(message_type: u8) -> bool {
    (SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST).contains(&message_type)
}

fn should_terminate_rekey(error: SequenceError) -> bool {
    matches!(
        error,
        SequenceError::InvalidState
            | SequenceError::OutOfOrder
            | SequenceError::UnexpectedPacket
            | SequenceError::StrictViolation
    )
}
