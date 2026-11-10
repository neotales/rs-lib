//! Synchronous SSH packet transport state for the client role.
//!
//! This module is the sole owner of the byte stream after construction. It
//! writes identification lines and packets, dispatches inbound handshake
//! packets, and installs packet protection after `SSH_MSG_NEWKEYS`. The client
//! handshake in the sibling module supplies protocol decisions while this
//! module enforces framing, authentication, and sequence-number boundaries.

use std::fmt;
use std::io::{self, Read, Write};

use neotales_ssh::{Error, MAX_PACKET_CONTENT, build_packet, decode_packet};

use crate::cipher::{
    AES_BLOCK_SIZE, AlignmentError, PacketAlignment, PacketProtectionError, PacketProtector,
    PacketSuite, PlaintextBytes, PlaintextSlot,
};
use crate::hostkey::VerifiedHostKey;
use crate::kex::mlkem768_x25519::ClientKex as MlKemClientKex;
use crate::kex::{DerivationLengths, DerivedKeys};
use crate::msg::kexinit::KexInit;
pub use crate::sequence::RekeyPhase;
use crate::sequence::{Direction, SequenceError, SequenceState};
use neotales_ssh::compression::CompressionAlgorithm;

/// The maximum RFC 4253 identification line length, including CR LF.
pub const MAX_IDENTIFICATION_LINE: usize = 255;

/// The maximum number of bytes accepted in lines preceding the peer version.
pub const MAX_PRE_BANNER_BYTES: usize = 8_192;

const PLAIN_PACKET_BLOCK_SIZE: usize = PacketAlignment::UNPROTECTED.block_size();
const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;
const CHACHA_TAG_LENGTH: usize = 16;
const SHA256_KEY_LENGTH: usize = 32;
const SHA512_KEY_LENGTH: usize = 64;
const VERSION_PREFIX: &[u8] = b"SSH-2.0-";
const SSH_LINE_PREFIX: &[u8] = b"SSH-";

/// A bounded failure while exchanging an SSH identification line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentificationError {
    /// A line would exceed 255 bytes when CR LF is included.
    LineTooLong,
    /// Lines before the version exceed the 8192-byte pre-banner limit.
    PreBannerTooLong,
    /// The stream ended before an SSH version line arrived.
    MissingVersion,
    /// A line began with `SSH-` but was not an SSH 2.0 version.
    InvalidVersion,
}

impl fmt::Display for IdentificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LineTooLong => "SSH identification line exceeds 255 bytes",
            Self::PreBannerTooLong => "SSH identification pre-banner exceeds 8192 bytes",
            Self::MissingVersion => "SSH peer did not send an identification version",
            Self::InvalidVersion => "SSH peer identification is not SSH-2.0",
        })
    }
}

impl std::error::Error for IdentificationError {}

/// A safe transport, framing, protection, or sequence failure.
///
/// Values do not contain stream bytes, version strings, packet payloads,
/// negotiated algorithm names, or cryptographic material.
#[derive(Debug)]
pub enum TransportError {
    /// The underlying byte stream reported an I/O failure.
    Io(io::Error),
    /// An SSH primitive or unencrypted packet was malformed.
    Wire(Error),
    /// Identification exchange exceeded a configured bound or was invalid.
    Identification(IdentificationError),
    /// Packet protection rejected protected input or key material.
    PacketProtection(PacketProtectionError),
    /// Initial-KEX ordering or sequence state rejected an operation.
    Sequence(SequenceError),
    /// The stream ended within a required framed value.
    Truncated,
    /// A packet did not begin with the message number required by its state.
    UnexpectedMessage,
    /// A packet was empty, had trailing bytes, or otherwise had an invalid shape.
    InvalidMessage,
    /// A caller requested protected I/O before NEWKEYS completed.
    NotEstablished,
    /// Application or ordinary payload I/O was attempted during a rekey.
    RekeyInProgress,
    /// The peer sent `SSH_MSG_DISCONNECT` during the initial handshake.
    PeerDisconnected,
    /// The operating system random-number source failed.
    EntropyFailure,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "SSH transport I/O error: {error}"),
            Self::Wire(error) => write!(formatter, "SSH transport wire error: {error}"),
            Self::Identification(error) => {
                write!(formatter, "SSH identification error: {error}")
            }
            Self::PacketProtection(error) => {
                write!(formatter, "SSH packet-protection error: {error}")
            }
            Self::Sequence(error) => write!(formatter, "SSH sequence error: {error}"),
            Self::Truncated => formatter.write_str("SSH transport input is truncated"),
            Self::UnexpectedMessage => {
                formatter.write_str("SSH transport received an unexpected message")
            }
            Self::InvalidMessage => formatter.write_str("SSH transport message is invalid"),
            Self::NotEstablished => {
                formatter.write_str("SSH transport is not established for protected I/O")
            }
            Self::RekeyInProgress => {
                formatter.write_str("SSH transport cannot exchange application data during rekey")
            }
            Self::PeerDisconnected => formatter.write_str("SSH peer disconnected during handshake"),
            Self::EntropyFailure => {
                formatter.write_str("SSH transport random-number generation failed")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Identification(error) => Some(error),
            Self::PacketProtection(error) => Some(error),
            Self::Sequence(error) => Some(error),
            Self::Truncated
            | Self::UnexpectedMessage
            | Self::InvalidMessage
            | Self::NotEstablished
            | Self::RekeyInProgress
            | Self::PeerDisconnected
            | Self::EntropyFailure => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Error> for TransportError {
    fn from(error: Error) -> Self {
        Self::Wire(error)
    }
}

impl From<IdentificationError> for TransportError {
    fn from(error: IdentificationError) -> Self {
        Self::Identification(error)
    }
}

impl From<PacketProtectionError> for TransportError {
    fn from(error: PacketProtectionError) -> Self {
        Self::PacketProtection(error)
    }
}

impl From<AlignmentError> for TransportError {
    fn from(error: AlignmentError) -> Self {
        Self::from(PacketProtectionError::from(error))
    }
}

impl From<SequenceError> for TransportError {
    fn from(error: SequenceError) -> Self {
        Self::Sequence(error)
    }
}

/// The negotiated packet algorithms and compression for one client rekey.
///
/// This crate-private state lives in the transport so a staged rekey can be
/// resumed without exposing packet protectors or key material to callers.
#[derive(Clone, Copy)]
pub(crate) struct RekeyProtection {
    pub(crate) write_suite: PacketSuite,
    pub(crate) read_suite: PacketSuite,
    pub(crate) write_compression: CompressionAlgorithm,
    pub(crate) read_compression: CompressionAlgorithm,
    pub(crate) lengths: DerivationLengths,
}

/// Client-side state retained between staged rekey steps.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ClientRekeyState {
    pub(crate) local_kexinit: KexInit,
    pub(crate) local_kexinit_payload: Vec<u8>,
    pub(crate) peer_kexinit: Option<KexInit>,
    pub(crate) peer_kexinit_payload: Option<Vec<u8>>,
    pub(crate) peer_guessed: bool,
    pub(crate) peer_guess_is_correct: bool,
    pub(crate) protection: Option<RekeyProtection>,
    pub(crate) client_kex: Option<MlKemClientKex>,
    pub(crate) derived: Option<DerivedKeys>,
    pub(crate) client_method_sent: bool,
    pub(crate) write_newkeys_sent: bool,
}

/// Bytes retained while a protected packet is being read from a stream.
///
/// The buffer is deliberately owned by a transport rather than by one read
/// operation. A nonblocking stream can return `WouldBlock` after any prefix of
/// a packet; retaining both the bytes and the context used to parse them makes
/// the next call resume the same packet without advancing its sequence number.
#[derive(Default)]
pub(crate) struct ProtectedReadBuffer {
    bytes: Vec<u8>,
    filled: usize,
    expected_length: Option<usize>,
    suite: Option<PacketSuite>,
    sequence: Option<u32>,
}

/// A sealed protected packet retained while its stream write is incomplete.
///
/// The bytes and the context used to produce them are owned by the transport,
/// rather than by one call to `Write::write`. A caller may therefore retry a
/// protected operation after `WouldBlock` without sealing a second packet or
/// consuming another sequence number. The entry remains present after the last
/// byte is written until the caller acknowledges the sequence commit.
#[derive(Default)]
pub(crate) struct ProtectedWriteBuffer {
    pending: Option<PendingProtectedWrite>,
    poisoned: bool,
}

struct PendingProtectedWrite {
    bytes: Vec<u8>,
    written: usize,
    /// The plaintext this packet was sealed from, kept so a retry after
    /// `WouldBlock` can be recognised as the same packet.
    ///
    /// A [`PlaintextBytes`] because the entry outlives the call that filled it:
    /// a write that blocks part-way leaves the packet here, plaintext, until a
    /// later retry or an abort, so a password written through this transport
    /// sits in this buffer for as long as the peer declines to read it.
    payload: PlaintextBytes,
    sequence: u32,
    suite: PacketSuite,
    compression: CompressionAlgorithm,
    message_type: Option<u8>,
    flushed: bool,
}

impl ProtectedWriteBuffer {
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn pending_message_type(&self) -> Option<u8> {
        self.pending
            .as_ref()
            .and_then(|pending| pending.message_type)
    }

    pub(crate) fn pending_payload(&self) -> Option<Vec<u8>> {
        self.pending
            .as_ref()
            .map(|pending| pending.payload.as_slice().to_vec())
    }

    fn prepare(
        &mut self,
        protector: &mut PacketProtector,
        sequence: u32,
        payload: &[u8],
        message_type: Option<u8>,
    ) -> Result<(), TransportError> {
        if self.poisoned {
            return Err(TransportError::InvalidMessage);
        }
        if let Some(pending) = self.pending.as_ref() {
            let matches = pending.sequence == sequence
                && pending.suite == protector.suite()
                && pending.compression == protector.compression()
                && pending.payload.as_slice() == payload
                && pending.message_type == message_type;
            if !matches {
                self.poisoned = true;
                return Err(TransportError::InvalidMessage);
            }
            return Ok(());
        }
        if message_type.is_some_and(|message_type| payload.first() != Some(&message_type)) {
            return Err(TransportError::InvalidMessage);
        }
        if payload.is_empty() {
            return Err(TransportError::InvalidMessage);
        }
        let padding = random_padding(payload.len(), protector.suite())?;
        let bytes = protector.seal(sequence, payload, &padding)?;
        self.pending = Some(PendingProtectedWrite {
            bytes,
            written: 0,
            payload: PlaintextBytes::new(PlaintextSlot::PendingPayload, payload.to_vec()),
            sequence,
            suite: protector.suite(),
            compression: protector.compression(),
            message_type,
            flushed: false,
        });
        Ok(())
    }

    fn flush(&mut self, stream: &mut impl Write) -> Result<(), TransportError> {
        if self.poisoned {
            return Err(TransportError::InvalidMessage);
        }
        let Some(pending) = self.pending.as_mut() else {
            self.poisoned = true;
            return Err(TransportError::InvalidMessage);
        };
        let (result, retryable) =
            if pending.bytes.is_empty() || pending.written > pending.bytes.len() {
                (Err(TransportError::InvalidMessage), false)
            } else if pending.flushed {
                (Ok(()), true)
            } else {
                loop {
                    if pending.written >= pending.bytes.len() {
                        pending.flushed = true;
                        break (Ok(()), true);
                    }
                    let start = pending.written;
                    let Some(remaining) = pending.bytes.len().checked_sub(start) else {
                        break (Err(TransportError::InvalidMessage), false);
                    };
                    match stream.write(&pending.bytes[start..]) {
                        Ok(0) => {
                            break (
                                Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "SSH protected packet write made no progress",
                                )
                                .into()),
                                false,
                            );
                        }
                        Ok(count) if count > remaining => {
                            break (Err(TransportError::InvalidMessage), false);
                        }
                        Ok(count) => {
                            pending.written = match pending.written.checked_add(count) {
                                Some(written) => written,
                                None => break (Err(TransportError::InvalidMessage), false),
                            };
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            break (Err(error.into()), true);
                        }
                        Err(error) => break (Err(error.into()), false),
                    }
                }
            };
        if !retryable {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn acknowledge(&mut self, sequence: u32) -> Result<(), TransportError> {
        let valid = !self.poisoned
            && self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.sequence == sequence && pending.flushed);
        if !valid {
            self.poisoned = true;
            return Err(TransportError::InvalidMessage);
        }
        self.pending = None;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn abort(&mut self) {
        self.pending = None;
        self.poisoned = true;
    }
}

/// Queues or resumes one protected packet and returns its sequence number.
///
/// The returned sequence number is not committed by this helper. The caller
/// must observe and commit it after this function reports that the complete
/// packet is flushed, then acknowledge the buffer.
pub(crate) fn write_protected_packet_buffered(
    stream: &mut impl Write,
    buffer: &mut ProtectedWriteBuffer,
    protector: &mut PacketProtector,
    sequence: u32,
    payload: &[u8],
    message_type: Option<u8>,
) -> Result<u32, TransportError> {
    if sequence == u32::MAX {
        return Err(SequenceError::CounterExhausted.into());
    }
    buffer.prepare(protector, sequence, payload, message_type)?;
    buffer.flush(stream)?;
    Ok(sequence)
}

impl ProtectedReadBuffer {
    fn prepare_context(
        &mut self,
        protector: &PacketProtector,
        sequence: u32,
    ) -> Result<(), TransportError> {
        let suite = protector.suite();
        match (self.suite, self.sequence) {
            (None, None) => {
                if self.filled != 0 {
                    return Err(TransportError::InvalidMessage);
                }
                self.suite = Some(suite);
                self.sequence = Some(sequence);
                Ok(())
            }
            (Some(current_suite), Some(current_sequence))
                if current_suite == suite && current_sequence == sequence =>
            {
                Ok(())
            }
            _ => Err(TransportError::InvalidMessage),
        }
    }

    fn resize_for(&mut self, target: usize) -> Result<(), TransportError> {
        if target < self.filled || self.filled > self.bytes.len() {
            return Err(TransportError::InvalidMessage);
        }
        if self.bytes.len() < target {
            self.bytes.resize(target, 0);
        }
        Ok(())
    }

    fn fill_to(&mut self, stream: &mut impl Read, target: usize) -> Result<(), TransportError> {
        self.resize_for(target)?;
        while self.filled < target {
            match stream.read(&mut self.bytes[self.filled..target]) {
                Ok(0) => return Err(TransportError::Truncated),
                Ok(count) => {
                    self.filled = self
                        .filled
                        .checked_add(count)
                        .ok_or(TransportError::InvalidMessage)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.filled = 0;
        self.expected_length = None;
        self.suite = None;
        self.sequence = None;
    }

    fn take_payload(&mut self, payload: Vec<u8>) -> Vec<u8> {
        self.clear();
        payload
    }

    fn open_packet(
        &mut self,
        protector: &mut PacketProtector,
        sequence: u32,
    ) -> Result<Vec<u8>, TransportError> {
        let packet = self
            .bytes
            .get(..self.filled)
            .ok_or(TransportError::Truncated)?;
        match protector.open(sequence, packet) {
            Ok(payload) => Ok(self.take_payload(payload)),
            Err(error) => {
                self.clear();
                Err(error.into())
            }
        }
    }

    fn set_expected(&mut self, expected_length: usize) -> Result<(), TransportError> {
        if let Some(previous) = self.expected_length {
            if previous != expected_length {
                self.clear();
                return Err(TransportError::InvalidMessage);
            }
        } else {
            self.expected_length = Some(expected_length);
        }
        Ok(())
    }

    fn set_expected_from(
        &mut self,
        expected: Result<usize, TransportError>,
    ) -> Result<(), TransportError> {
        match expected {
            Ok(expected_length) => self.set_expected(expected_length),
            Err(error) => {
                self.clear();
                Err(error)
            }
        }
    }
}

/// Reads and authenticates one protected packet using transport-owned state.
///
/// The stream may return `WouldBlock` after any prefix. In that case the
/// current buffer, suite, and sequence remain in place and the caller can
/// retry the same operation. No sequence state is touched by this function.
pub(crate) fn read_protected_packet_buffered(
    stream: &mut impl Read,
    buffer: &mut ProtectedReadBuffer,
    protector: &mut PacketProtector,
    sequence: u32,
) -> Result<Vec<u8>, TransportError> {
    buffer.prepare_context(protector, sequence)?;
    let suite = protector.suite();
    if suite.is_chacha() {
        read_chacha_packet_buffered(stream, buffer, protector, sequence)
    } else if PacketAlignment::for_suite(suite).aligns_packet_length() {
        read_framed_packet_buffered(stream, buffer, protector, sequence)
    } else {
        read_eam_packet_buffered(stream, buffer, protector, sequence)
    }
}

fn read_framed_packet_buffered(
    stream: &mut impl Read,
    buffer: &mut ProtectedReadBuffer,
    protector: &mut PacketProtector,
    sequence: u32,
) -> Result<Vec<u8>, TransportError> {
    if buffer.filled < 4 {
        buffer.fill_to(stream, 4)?;
    }
    if buffer.expected_length.is_none() {
        let expected = buffer
            .bytes
            .get(..4)
            .ok_or(TransportError::Truncated)
            .and_then(|prefix| protected_packet_wire_length(protector.suite(), prefix));
        buffer.set_expected_from(expected)?;
    }
    let expected_length = buffer
        .expected_length
        .ok_or(TransportError::InvalidMessage)?;
    buffer.fill_to(stream, expected_length)?;
    buffer.open_packet(protector, sequence)
}

fn read_chacha_packet_buffered(
    stream: &mut impl Read,
    buffer: &mut ProtectedReadBuffer,
    protector: &mut PacketProtector,
    sequence: u32,
) -> Result<Vec<u8>, TransportError> {
    if buffer.filled < 4 {
        buffer.fill_to(stream, 4)?;
    }
    if buffer.expected_length.is_none() {
        let expected = (|| {
            let encrypted_length = buffer.bytes.get(..4).ok_or(TransportError::Truncated)?;
            let packet_length =
                usize::try_from(protector.decrypt_length(sequence, encrypted_length)?)
                    .map_err(|_error| PacketProtectionError::LimitExceeded)?;
            let (_clear_length, total_length) = validate_chacha_packet_length(
                PacketAlignment::for_suite(protector.suite()),
                packet_length,
            )?;
            Ok(total_length)
        })();
        buffer.set_expected_from(expected)?;
    }
    let expected_length = buffer
        .expected_length
        .ok_or(TransportError::InvalidMessage)?;
    buffer.fill_to(stream, expected_length)?;
    buffer.open_packet(protector, sequence)
}

fn read_eam_packet_buffered(
    stream: &mut impl Read,
    buffer: &mut ProtectedReadBuffer,
    protector: &mut PacketProtector,
    sequence: u32,
) -> Result<Vec<u8>, TransportError> {
    if buffer.filled < 4 {
        buffer.fill_to(stream, 4)?;
    }
    if buffer.expected_length.is_none() {
        let expected = (|| {
            let encrypted_length = buffer.bytes.get(..4).ok_or(TransportError::Truncated)?;
            let packet_length =
                usize::try_from(protector.decrypt_length(sequence, encrypted_length)?)
                    .map_err(|_error| PacketProtectionError::LimitExceeded)?;
            validate_eam_packet_length(protector.suite(), packet_length)
        })();
        buffer.set_expected_from(expected)?;
    }
    let expected_length = buffer
        .expected_length
        .ok_or(TransportError::InvalidMessage)?;
    buffer.fill_to(stream, expected_length)?;
    buffer.open_packet(protector, sequence)
}

fn protected_packet_wire_length(
    suite: PacketSuite,
    prefix: &[u8],
) -> Result<usize, TransportError> {
    let alignment = PacketAlignment::for_suite(suite);
    let packet_length = packet_length(prefix)?;
    let total_length = packet_length.checked_add(4).ok_or(Error::LimitExceeded)?;
    alignment.validate_packet_length(packet_length)?;
    if total_length < alignment.block_size() {
        return Err(PacketProtectionError::Truncated.into());
    }
    total_length
        .checked_add(tag_length(suite))
        .ok_or(Error::LimitExceeded.into())
}

fn validate_eam_packet_length(
    suite: PacketSuite,
    packet_length: usize,
) -> Result<usize, TransportError> {
    let alignment = PacketAlignment::for_suite(suite);
    let content_length = packet_length
        .checked_sub(1)
        .ok_or(PacketProtectionError::InvalidPacket)?;
    if content_length > MAX_PACKET_CONTENT {
        return Err(PacketProtectionError::LimitExceeded.into());
    }
    let total_length = packet_length
        .checked_add(4)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    if total_length < alignment.block_size() {
        return Err(PacketProtectionError::Truncated.into());
    }
    alignment.validate_packet_length(packet_length)?;
    total_length
        .checked_add(tag_length(suite))
        .ok_or(PacketProtectionError::LimitExceeded.into())
}

/// A synchronous client transport with authenticated packet exchange.
///
/// Values of this type are created only after identification, key exchange,
/// mandatory host-key trust, NEWKEYS, and the initial-KEX sequence boundary
/// have all succeeded. Every read and write requires mutable access, so one
/// caller owns packet dispatch and stream mutation at a time.
pub struct ClientTransport<S> {
    pub(crate) stream: S,
    pub(crate) sequence: SequenceState,
    pub(crate) session_id: Vec<u8>,
    pub(crate) verified_host_key: Option<VerifiedHostKey>,
    pub(crate) write_protector: Option<PacketProtector>,
    pub(crate) read_protector: Option<PacketProtector>,
    pub(crate) read_buffer: ProtectedReadBuffer,
    pub(crate) write_buffer: ProtectedWriteBuffer,
    pub(crate) established: bool,
    pub(crate) client_version: String,
    pub(crate) peer_version: String,
    pub(crate) initial_algorithm: Option<String>,
    pub(crate) rekey_proposal: Option<KexInit>,
    pub(crate) rekey: Option<ClientRekeyState>,
}

impl<S> fmt::Debug for ClientTransport<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientTransport")
            .field("session_id", &self.session_id)
            .field("strict_kex", &self.sequence.strict_kex())
            .field("inbound_sequence", &self.sequence.inbound_sequence())
            .field("outbound_sequence", &self.sequence.outbound_sequence())
            .field("established", &self.established)
            .field("host_key_verified", &self.verified_host_key.is_some())
            .finish_non_exhaustive()
    }
}

impl<S> ClientTransport<S>
where
    S: Read + Write,
{
    /// Writes the local identification and reads the bounded peer version.
    pub(crate) fn start(
        mut stream: S,
        local_version: &str,
    ) -> Result<(Self, String), TransportError> {
        write_identification(&mut stream, local_version)?;
        let peer_version = read_peer_identification(&mut stream)?;
        Ok((
            Self {
                stream,
                sequence: SequenceState::new(),
                session_id: Vec::new(),
                verified_host_key: None,
                write_protector: None,
                read_protector: None,
                read_buffer: ProtectedReadBuffer::default(),
                write_buffer: ProtectedWriteBuffer::default(),
                established: false,
                client_version: local_version.to_owned(),
                peer_version: peer_version.clone(),
                initial_algorithm: None,
                rekey_proposal: None,
                rekey: None,
            },
            peer_version,
        ))
    }

    /// Returns the first exchange hash retained as the connection session ID.
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the cryptographically verified and application-trusted host key.
    #[must_use]
    pub fn verified_host_key(&self) -> Option<&VerifiedHostKey> {
        self.verified_host_key.as_ref()
    }

    /// Returns whether protected payload exchange is available.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.established
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

    /// Returns whether a post-establishment rekey is currently active.
    #[must_use]
    pub fn rekey_active(&self) -> bool {
        self.rekey.is_some() || self.sequence.rekey_active()
    }

    /// Returns the current post-establishment rekey phase.
    #[must_use]
    pub fn rekey_phase(&self) -> RekeyPhase {
        self.sequence.rekey_phase()
    }

    /// Returns whether the current post-establishment rekey has completed.
    #[must_use]
    pub const fn rekey_complete(&self) -> bool {
        self.sequence.rekey_is_complete()
    }

    /// Returns whether the most recent post-establishment rekey completed.
    #[must_use]
    pub const fn rekey_is_complete(&self) -> bool {
        self.rekey_complete()
    }

    /// Returns whether the post-establishment rekey policy is terminal.
    #[must_use]
    pub const fn rekey_terminal(&self) -> bool {
        self.sequence.rekey_is_terminal()
    }

    /// Returns whether the post-establishment rekey policy is terminal.
    #[must_use]
    pub const fn rekey_is_terminal(&self) -> bool {
        self.rekey_terminal()
    }

    /// Writes one protected payload and commits its outbound sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotEstablished`] before NEWKEYS, protection or
    /// framing errors for an invalid payload, and an I/O error if the complete
    /// packet cannot be written. The sequence number is committed only after
    /// `write_all` succeeds.
    pub fn write_payload(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if self.rekey.is_some() {
            return Err(TransportError::RekeyInProgress);
        }
        let sequence = match self.write_protected_packet(payload) {
            Ok(sequence) => sequence,
            Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(TransportError::Io(error));
            }
            Err(error) => return Err(self.fail_protected_write(error)),
        };
        let committed = match self.sequence.commit_outbound() {
            Ok(committed) => committed,
            Err(error) => return Err(self.fail_protected_write(error.into())),
        };
        if committed != sequence {
            return Err(self.fail_protected_write(TransportError::InvalidMessage));
        }
        if let Err(error) = self.write_buffer.acknowledge(sequence) {
            return Err(self.fail_protected_write(error));
        }
        Ok(())
    }

    /// Opens and returns one protected payload.
    ///
    /// Authentication and padding validation complete before a sequence number
    /// is committed or plaintext is returned. A peer-originated KEXINIT is
    /// consumed transparently: the transport performs the bounded hybrid
    /// rekey before reading the next application payload.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotEstablished`] before NEWKEYS and a typed
    /// framing, protection, I/O, sequence, or rekey error for an invalid
    /// packet. Once a peer rekey has started, callers using a nonblocking
    /// stream should resume it with [`ClientTransport::advance_rekey`].
    pub fn read_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.rekey.is_some() {
            return Err(TransportError::RekeyInProgress);
        }
        loop {
            let (payload, sequence) = self.read_protected_packet()?;
            if payload.first() == Some(&crate::msg::kexinit::SSH_MSG_KEXINIT) {
                self.dispatch_peer_rekey(&payload, sequence)?;
                while self.rekey.is_some() {
                    self.advance_rekey()?;
                }
                continue;
            }
            self.sequence.commit_inbound()?;
            return Ok(payload);
        }
    }

    /// Writes one protected packet without committing its sequence number.
    ///
    /// This is used by the post-establishment rekey state machine so it can
    /// record the rekey observation at the exact packet boundary before the
    /// normal sequence commit. The current protector is intentionally retained
    /// until the caller changes it with [`PacketProtector::rekey`].
    pub(crate) fn write_protected_packet(&mut self, payload: &[u8]) -> Result<u32, TransportError> {
        self.write_protected_packet_inner(payload, None)
    }

    pub(crate) fn write_protected_rekey_packet(
        &mut self,
        payload: &[u8],
        message_type: u8,
    ) -> Result<u32, TransportError> {
        self.write_protected_packet_inner(payload, Some(message_type))
    }

    fn write_protected_packet_inner(
        &mut self,
        payload: &[u8],
        message_type: Option<u8>,
    ) -> Result<u32, TransportError> {
        if !self.established {
            return Err(TransportError::NotEstablished);
        }
        if payload.is_empty() {
            return Err(TransportError::InvalidMessage);
        }
        let sequence = self.sequence.outbound_sequence();
        let protector = self
            .write_protector
            .as_mut()
            .ok_or(TransportError::NotEstablished)?;
        write_protected_packet_buffered(
            &mut self.stream,
            &mut self.write_buffer,
            protector,
            sequence,
            payload,
            message_type,
        )
    }

    /// Reads and authenticates one protected packet without committing its
    /// sequence number.
    ///
    /// The returned sequence number is the one used to authenticate the packet;
    /// the caller must observe and commit it exactly once after accepting the
    /// protocol message.
    pub(crate) fn read_protected_packet(&mut self) -> Result<(Vec<u8>, u32), TransportError> {
        if !self.established {
            return Err(TransportError::NotEstablished);
        }
        let protector = self
            .read_protector
            .as_mut()
            .ok_or(TransportError::NotEstablished)?;
        let sequence = self.sequence.inbound_sequence();
        if sequence == u32::MAX {
            return Err(SequenceError::CounterExhausted.into());
        }
        let payload = read_protected_packet_buffered(
            &mut self.stream,
            &mut self.read_buffer,
            protector,
            sequence,
        )?;
        Ok((payload, sequence))
    }

    /// Writes and then reads one protected payload in stream order.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::write_payload`] or [`Self::read_payload`].
    pub fn exchange_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.write_payload(payload)?;
        self.read_payload()
    }

    /// Consumes the transport and returns its underlying byte stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    pub(crate) fn configure_strict_kex(&mut self, strict: bool) -> Result<(), TransportError> {
        self.sequence.set_strict_kex(strict)?;
        Ok(())
    }

    pub(crate) fn configure_rekey_proposal(&mut self, proposal: KexInit) {
        self.rekey_proposal = Some(proposal);
    }

    pub(crate) fn configure_initial_algorithm(&mut self, algorithm: String) {
        self.initial_algorithm = Some(algorithm);
    }

    pub(crate) fn write_handshake_packet(
        &mut self,
        payload: &[u8],
        expected_type: u8,
    ) -> Result<(), TransportError> {
        if self.established || payload.first() != Some(&expected_type) {
            return Err(TransportError::UnexpectedMessage);
        }
        self.sequence.classify_outbound(expected_type)?;
        ensure_can_commit(&self.sequence, Direction::Outbound)?;
        let padding = random_unprotected_padding(payload.len())?;
        let packet = build_packet(payload, PLAIN_PACKET_BLOCK_SIZE, |target| {
            target.copy_from_slice(&padding);
        })?;
        self.stream.write_all(&packet)?;
        self.sequence.observe_outbound(expected_type)?;
        self.sequence.commit_outbound()?;
        Ok(())
    }

    pub(crate) fn receive_handshake_packet(
        &mut self,
    ) -> Result<PendingHandshakePacket, TransportError> {
        loop {
            let payload = read_unprotected_packet(&mut self.stream)?;
            let message_type = payload
                .first()
                .copied()
                .ok_or(TransportError::InvalidMessage)?;
            match self.sequence.classify_inbound(message_type)? {
                crate::sequence::PacketDisposition::Ignorable => {
                    ensure_can_commit(&self.sequence, Direction::Inbound)?;
                    self.sequence.observe_inbound(message_type)?;
                    self.sequence.commit_inbound()?;
                }
                crate::sequence::PacketDisposition::Disconnect => {
                    return Err(TransportError::PeerDisconnected);
                }
                _ => {
                    return Ok(PendingHandshakePacket {
                        payload,
                        message_type,
                    });
                }
            }
        }
    }

    pub(crate) fn accept_handshake_packet(
        &mut self,
        packet: &PendingHandshakePacket,
        expected_type: u8,
        guessed_kexinit: Option<bool>,
    ) -> Result<(), TransportError> {
        if self.established || packet.message_type != expected_type {
            return Err(TransportError::UnexpectedMessage);
        }
        ensure_can_commit(&self.sequence, Direction::Inbound)?;
        match guessed_kexinit {
            Some(guessed) => {
                self.sequence.observe_kexinit(Direction::Inbound, guessed)?;
            }
            None => {
                self.sequence.observe_inbound(expected_type)?;
            }
        }
        self.sequence.commit_inbound()?;
        Ok(())
    }

    pub(crate) fn discard_guessed_handshake_packet(
        &mut self,
        _packet: &PendingHandshakePacket,
    ) -> Result<(), TransportError> {
        if self.established {
            return Err(TransportError::UnexpectedMessage);
        }
        ensure_can_commit(&self.sequence, Direction::Inbound)?;
        self.sequence.commit_inbound()?;
        Ok(())
    }

    pub(crate) fn finish_handshake(
        &mut self,
        session_id: Vec<u8>,
        verified_host_key: VerifiedHostKey,
        write_protector: PacketProtector,
        read_protector: PacketProtector,
    ) -> Result<(), TransportError> {
        self.sequence.complete_initial_kex()?;
        self.session_id = session_id;
        self.verified_host_key = Some(verified_host_key);
        self.write_protector = Some(write_protector);
        self.read_protector = Some(read_protector);
        self.established = true;
        Ok(())
    }

    fn fail_protected_write(&mut self, error: TransportError) -> TransportError {
        self.write_buffer.abort();
        self.established = false;
        error
    }
}

pub(crate) struct PendingHandshakePacket {
    pub(crate) payload: Vec<u8>,
    message_type: u8,
}

fn ensure_can_commit(state: &SequenceState, direction: Direction) -> Result<(), TransportError> {
    if state.sequence(direction) == u32::MAX {
        return Err(SequenceError::CounterExhausted.into());
    }
    Ok(())
}

pub(crate) fn write_identification(
    stream: &mut impl Write,
    version: &str,
) -> Result<(), TransportError> {
    let length = version
        .len()
        .checked_add(2)
        .ok_or(TransportError::Identification(
            IdentificationError::LineTooLong,
        ))?;
    if version.is_empty()
        || length > MAX_IDENTIFICATION_LINE
        || !version.is_ascii()
        || version
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(TransportError::Identification(
            IdentificationError::InvalidVersion,
        ));
    }
    stream.write_all(version.as_bytes())?;
    stream.write_all(b"\r\n")?;
    Ok(())
}

pub(crate) fn read_peer_identification(stream: &mut impl Read) -> Result<String, TransportError> {
    let mut line = Vec::new();
    let mut pre_banner_bytes = 0_usize;

    loop {
        let byte = match read_byte(stream) {
            Ok(byte) => byte,
            Err(TransportError::Truncated) if line.is_empty() => {
                return Err(TransportError::Identification(
                    IdentificationError::MissingVersion,
                ));
            }
            Err(error) => return Err(error),
        };
        let is_version_candidate = line.first() == VERSION_PREFIX.first();
        if !line.is_empty() && !is_version_candidate {
            let projected = pre_banner_bytes
                .checked_add(line.len())
                .and_then(|length| length.checked_add(1))
                .ok_or(TransportError::Identification(
                    IdentificationError::PreBannerTooLong,
                ))?;
            if projected > MAX_PRE_BANNER_BYTES {
                return Err(TransportError::Identification(
                    IdentificationError::PreBannerTooLong,
                ));
            }
        }

        if line.len() >= MAX_IDENTIFICATION_LINE - 2 && byte != b'\r' {
            return Err(TransportError::Identification(
                IdentificationError::LineTooLong,
            ));
        }
        line.push(byte);
        if line.first() != VERSION_PREFIX.first() {
            let projected =
                pre_banner_bytes
                    .checked_add(line.len())
                    .ok_or(TransportError::Identification(
                        IdentificationError::PreBannerTooLong,
                    ))?;
            if projected > MAX_PRE_BANNER_BYTES {
                return Err(TransportError::Identification(
                    IdentificationError::PreBannerTooLong,
                ));
            }
        }

        if byte != b'\r' {
            if line.len() >= MAX_IDENTIFICATION_LINE {
                return Err(TransportError::Identification(
                    IdentificationError::LineTooLong,
                ));
            }
            continue;
        }

        let terminator = read_byte(stream)?;
        if terminator != b'\n' {
            return Err(TransportError::Identification(
                IdentificationError::LineTooLong,
            ));
        }
        line.push(terminator);

        if line.starts_with(VERSION_PREFIX) {
            let version =
                line.get(..line.len().saturating_sub(2))
                    .ok_or(TransportError::Identification(
                        IdentificationError::InvalidVersion,
                    ))?;
            let version = std::str::from_utf8(version).map_err(|_error| {
                TransportError::Identification(IdentificationError::InvalidVersion)
            })?;
            if !version.is_ascii() || version.bytes().any(|byte| byte == 0) {
                return Err(TransportError::Identification(
                    IdentificationError::InvalidVersion,
                ));
            }
            return Ok(version.to_owned());
        }
        if line.starts_with(SSH_LINE_PREFIX) {
            return Err(TransportError::Identification(
                IdentificationError::InvalidVersion,
            ));
        }

        pre_banner_bytes =
            pre_banner_bytes
                .checked_add(line.len())
                .ok_or(TransportError::Identification(
                    IdentificationError::PreBannerTooLong,
                ))?;
        if pre_banner_bytes > MAX_PRE_BANNER_BYTES {
            return Err(TransportError::Identification(
                IdentificationError::PreBannerTooLong,
            ));
        }
        line.clear();
    }
}

fn read_byte(stream: &mut impl Read) -> Result<u8, TransportError> {
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Err(TransportError::Truncated),
            Ok(_) => return Ok(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn read_unprotected_packet(stream: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut encoded = vec![0_u8; 4];
    read_exact(stream, &mut encoded, 4)?;
    let packet_length = packet_length(&encoded)?;
    let total_length = packet_length.checked_add(4).ok_or(Error::LimitExceeded)?;
    encoded.resize(total_length, 0);
    read_exact(stream, &mut encoded[4..], total_length.saturating_sub(4))?;
    let packet = decode_packet(&encoded, PLAIN_PACKET_BLOCK_SIZE)?;
    Ok(packet.payload)
}

pub(crate) fn read_protected_packet(
    stream: &mut impl Read,
    suite: PacketSuite,
) -> Result<Vec<u8>, TransportError> {
    let alignment = PacketAlignment::for_suite(suite);
    // Only a block cipher reaches this reader: the ChaCha length field is
    // encrypted with the header key and has its own reader, and the AEADs
    // authenticate the length in clear, so `AES_BLOCK_SIZE` here is a genuine
    // first-block read rather than a stand-in for the suite's block size.
    let mut encoded = [0_u8; AES_BLOCK_SIZE];
    read_exact(stream, &mut encoded, AES_BLOCK_SIZE)?;
    let packet_length = packet_length(&encoded)?;
    let total_length = packet_length.checked_add(4).ok_or(Error::LimitExceeded)?;
    if total_length < AES_BLOCK_SIZE {
        return Err(PacketProtectionError::Truncated.into());
    }
    alignment.validate_packet_length(packet_length)?;

    let tag_length = tag_length(suite);
    let remaining = total_length
        .saturating_sub(AES_BLOCK_SIZE)
        .checked_add(tag_length)
        .ok_or(Error::LimitExceeded)?;
    let mut packet = encoded.to_vec();
    packet.resize(total_length.saturating_add(tag_length), 0);
    read_exact(stream, &mut packet[AES_BLOCK_SIZE..], remaining)?;
    Ok(packet)
}

pub(crate) fn validate_chacha_packet_length(
    alignment: PacketAlignment,
    packet_length: usize,
) -> Result<(usize, usize), PacketProtectionError> {
    if packet_length < 5 {
        return Err(PacketProtectionError::InvalidPacket);
    }
    let maximum_packet_length = MAX_PACKET_CONTENT
        .checked_add(1)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    if packet_length > maximum_packet_length {
        return Err(PacketProtectionError::LimitExceeded);
    }
    alignment.validate_packet_length(packet_length)?;
    let clear_length = packet_length
        .checked_add(4)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    let total_length = clear_length
        .checked_add(CHACHA_TAG_LENGTH)
        .ok_or(PacketProtectionError::LimitExceeded)?;
    Ok((clear_length, total_length))
}

pub(crate) fn read_chacha_payload(
    stream: &mut impl Read,
    protector: &mut PacketProtector,
    sequence_number: u32,
) -> Result<Vec<u8>, TransportError> {
    let mut encrypted_length = [0_u8; 4];
    read_exact(stream, &mut encrypted_length, 4)?;
    let packet_length =
        usize::try_from(protector.decrypt_length(sequence_number, &encrypted_length)?)
            .map_err(|_error| PacketProtectionError::LimitExceeded)?;
    let (_clear_length, total_length) = validate_chacha_packet_length(
        PacketAlignment::for_suite(protector.suite()),
        packet_length,
    )?;
    let mut packet = Vec::with_capacity(total_length);
    packet.extend_from_slice(&encrypted_length);
    packet.resize(total_length, 0);
    read_exact(
        stream,
        packet
            .get_mut(4..)
            .ok_or(PacketProtectionError::InvalidPacket)?,
        total_length - 4,
    )?;
    Ok(protector.open(sequence_number, &packet)?)
}

pub(crate) fn read_eam_payload(
    stream: &mut impl Read,
    protector: &mut PacketProtector,
    sequence_number: u32,
) -> Result<Vec<u8>, TransportError> {
    let mut packet = vec![0_u8; AES_BLOCK_SIZE];
    read_exact(stream, &mut packet, AES_BLOCK_SIZE)?;
    let tag_length = tag_length(protector.suite());
    let maximum_packet_length = MAX_PACKET_CONTENT
        .checked_add(1)
        .and_then(|length| length.checked_add(AES_BLOCK_SIZE - 1))
        .map(|length| length / AES_BLOCK_SIZE * AES_BLOCK_SIZE)
        .and_then(|length| length.checked_add(tag_length))
        .ok_or(Error::LimitExceeded)?;
    loop {
        let error = match protector.open(sequence_number, &packet) {
            Ok(payload) => return Ok(payload),
            Err(PacketProtectionError::CounterExhausted) => {
                return Err(PacketProtectionError::CounterExhausted.into());
            }
            Err(error) => error,
        };

        if packet.len() >= maximum_packet_length {
            return Err(error.into());
        }
        let start = packet.len();
        let next_length = AES_BLOCK_SIZE.min(maximum_packet_length.saturating_sub(start));
        packet.resize(start.saturating_add(next_length), 0);
        if let Err(read_error) = read_exact(stream, &mut packet[start..], next_length) {
            if error == PacketProtectionError::AuthenticationFailed {
                return Err(error.into());
            }
            return Err(read_error);
        }
    }
}

fn packet_length(prefix: &[u8]) -> Result<usize, TransportError> {
    let length_bytes: [u8; 4] = prefix
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(TransportError::Truncated)?;
    let packet_length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_error| Error::LimitExceeded)?;
    let content_length = packet_length.checked_sub(1).ok_or(Error::InvalidPacket)?;
    if content_length > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded.into());
    }
    Ok(packet_length)
}

fn read_exact(
    stream: &mut impl Read,
    target: &mut [u8],
    expected_length: usize,
) -> Result<(), TransportError> {
    if target.len() != expected_length {
        return Err(TransportError::InvalidMessage);
    }
    let mut read = 0_usize;
    while read < target.len() {
        match stream.read(&mut target[read..]) {
            Ok(0) => return Err(TransportError::Truncated),
            Ok(count) => {
                read = read
                    .checked_add(count)
                    .ok_or(TransportError::InvalidMessage)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn tag_length(suite: PacketSuite) -> usize {
    match suite.integrity_name() {
        None => GCM_TAG_LENGTH,
        Some(name) if name.contains("sha2-512") => SHA512_KEY_LENGTH,
        Some(_) => SHA256_KEY_LENGTH,
    }
}

pub(crate) fn random_unprotected_padding(payload_length: usize) -> Result<Vec<u8>, TransportError> {
    random_padding_of(PacketAlignment::UNPROTECTED, payload_length)
}

pub(crate) fn random_padding(
    payload_length: usize,
    suite: PacketSuite,
) -> Result<Vec<u8>, TransportError> {
    random_padding_of(PacketAlignment::for_suite(suite), payload_length)
}

fn random_padding_of(
    alignment: PacketAlignment,
    payload_length: usize,
) -> Result<Vec<u8>, TransportError> {
    let length = alignment.padding_length(payload_length)?;
    let mut padding = vec![0_u8; length];
    getrandom::fill(&mut padding).map_err(|_error| TransportError::EntropyFailure)?;
    Ok(padding)
}
