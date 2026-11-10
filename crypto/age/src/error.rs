//! Errors returned by the age implementation.

use std::{fmt, io};

/// An error raised while parsing, encrypting, or decrypting an age file.
#[derive(Debug)]
pub enum AgeError {
    /// A key, passphrase, or SSH input is not valid.
    InvalidKey(&'static str),
    /// A textual or binary format value is not valid.
    InvalidFormat(&'static str),
    /// An operation is not supported by this implementation.
    Unsupported(&'static str),
    /// The input ended before a required value was available.
    Truncated,
    /// The age header is malformed or has an unsupported version.
    InvalidHeader(&'static str),
    /// The header authentication tag is invalid.
    InvalidMac,
    /// A payload authentication tag is invalid.
    AuthenticationFailed,
    /// No supplied identity matched a recipient stanza.
    NoMatchingIdentity,
    /// A configured size or count limit was exceeded.
    LimitExceeded(&'static str),
    /// A passphrase recipient was mixed with another recipient.
    MixedScrypt,
    /// The requested work factor is outside the accepted range.
    InvalidWorkFactor,
    /// A scrypt stanza used a work factor above the identity's configured maximum.
    ScryptWorkFactorTooLarge(u32),
    /// An operating-system entropy source failed.
    Random,
    /// A cryptographic primitive rejected valid-looking input.
    Crypto(&'static str),
    /// An SSH private key needs a passphrase and contains its public key.
    PassphraseMissing {
        /// The embedded public key in `authorized_keys` format.
        public_key: String,
    },
    /// A passphrase was empty.
    EmptyPassphrase,
    /// No secret keys were found in an identity file.
    NoSecretKeys,
    /// No recipients were found in a recipient file.
    NoRecipients,
    /// A secret-key file line was invalid.
    InvalidIdentityLine {
        /// The one-based line number.
        line: usize,
        /// A description that does not include the line contents.
        reason: String,
    },
    /// A recipient-file line was malformed.
    MalformedRecipientLine {
        /// The one-based line number.
        line: usize,
    },
    /// An underlying I/O operation failed.
    Io(io::Error),
}

impl fmt::Display for AgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(message) => write!(formatter, "invalid age key: {message}"),
            Self::InvalidFormat(message) => write!(formatter, "invalid age format: {message}"),
            Self::Unsupported(message) => write!(formatter, "unsupported age feature: {message}"),
            Self::Truncated => formatter.write_str("the age file is truncated"),
            Self::InvalidHeader(message) => write!(formatter, "invalid age header: {message}"),
            Self::InvalidMac => formatter.write_str("the age header MAC is invalid"),
            Self::AuthenticationFailed => {
                formatter.write_str("the age payload authentication failed")
            }
            Self::NoMatchingIdentity => {
                formatter.write_str("no identity matched the age file recipients")
            }
            Self::LimitExceeded(message) => write!(formatter, "age limit exceeded: {message}"),
            Self::MixedScrypt => {
                formatter.write_str("a passphrase recipient must be the only recipient")
            }
            Self::InvalidWorkFactor => {
                formatter.write_str("the scrypt work factor must be between 1 and 30")
            }
            Self::ScryptWorkFactorTooLarge(work_factor) => {
                write!(formatter, "scrypt work factor too large: {work_factor}")
            }
            Self::Random => formatter.write_str("operating-system entropy is unavailable"),
            Self::Crypto(message) => {
                write!(formatter, "age cryptographic operation failed: {message}")
            }
            Self::PassphraseMissing { .. } => {
                formatter.write_str("SSH private key is passphrase protected")
            }
            Self::EmptyPassphrase => formatter.write_str("passphrase can't be empty"),
            Self::NoSecretKeys => formatter.write_str("no secret keys found"),
            Self::NoRecipients => formatter.write_str("no recipients found"),
            Self::InvalidIdentityLine { line, reason } => {
                write!(formatter, "error at line {line}: {reason}")
            }
            Self::MalformedRecipientLine { line } => {
                write!(formatter, "malformed recipient at line {line}")
            }
            Self::Io(error) => write!(formatter, "age I/O operation failed: {error}"),
        }
    }
}

impl std::error::Error for AgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AgeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, AgeError>;

/// A short alias for [`AgeError`].
pub type Error = AgeError;

/// A compatibility alias matching the exception-oriented API of the reference library.
pub type AgeException = AgeError;
