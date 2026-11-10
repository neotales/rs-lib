//! Errors produced while decoding and validating SSH wire data.

use std::fmt;

/// A safe, non-sensitive error reported by the SSH wire codec.
///
/// Error values intentionally contain no input bytes, names, payloads, or
/// other material from a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The input ended before a complete wire value could be read.
    Truncated,
    /// A length or packet body exceeded the configured safety limit.
    LimitExceeded,
    /// A boolean contained a value other than `0` or `1`.
    InvalidBoolean,
    /// An mpint was non-canonical or otherwise invalid.
    InvalidMpint,
    /// A name-list contained an invalid or empty name.
    InvalidName,
    /// A packet length, alignment, or body was inconsistent.
    InvalidPacket,
    /// Packet padding was shorter than the SSH minimum.
    InvalidPadding,
    /// A packet block size was zero or could not represent a valid padding byte.
    InvalidBlockSize,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "SSH input is truncated",
            Self::LimitExceeded => "SSH value exceeds the configured limit",
            Self::InvalidBoolean => "SSH boolean is neither zero nor one",
            Self::InvalidMpint => "SSH mpint is invalid",
            Self::InvalidName => "SSH name-list contains an invalid name",
            Self::InvalidPacket => "SSH packet is malformed",
            Self::InvalidPadding => "SSH packet padding is too short",
            Self::InvalidBlockSize => "SSH packet block size is invalid",
        })
    }
}

impl std::error::Error for Error {}
