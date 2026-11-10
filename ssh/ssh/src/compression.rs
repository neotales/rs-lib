//! Bounded SSH transport compression primitives.
//!
//! Compression is applied to the SSH packet payload before packet framing and
//! removed after authenticated packet opening. The implementation uses the
//! pure-Rust `miniz_oxide` backend selected by this crate's `flate2` feature.

use std::fmt;
use std::io::Write;

use flate2::{Compression, Decompress, FlushDecompress, Status, write::ZlibEncoder};

use neotales_ssh::MAX_PACKET_CONTENT;

use crate::cipher::{AlignmentError, PacketAlignment};

/// The SSH compression name that performs no compression.
pub const COMPRESSION_NONE: &str = "none";
/// The OpenSSH zlib compression name.
pub const COMPRESSION_ZLIB_OPENSSH: &str = "zlib@openssh.com";

/// Maximum compressed or decompressed payload accepted by this module.
pub const MAX_COMPRESSED_PAYLOAD: usize = MAX_PACKET_CONTENT;

/// A bounded compression error with no payload bytes attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionError {
    /// The input or output exceeded the SSH payload limit.
    LimitExceeded,
    /// The compressed stream was malformed or had trailing data.
    InvalidStream,
    /// The local compressor failed.
    CompressionFailed,
}

impl fmt::Display for CompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "SSH compressed payload exceeds the configured limit",
            Self::InvalidStream => "SSH compressed payload is malformed",
            Self::CompressionFailed => "SSH compression operation failed",
        })
    }
}

impl std::error::Error for CompressionError {}

/// The internal packet compression mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionAlgorithm {
    /// No compression.
    None,
    /// OpenSSH zlib compression.
    Zlib,
}

impl CompressionAlgorithm {
    /// Parses a negotiated compression name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            COMPRESSION_NONE => Some(Self::None),
            COMPRESSION_ZLIB_OPENSSH => Some(Self::Zlib),
            _ => None,
        }
    }

    /// Returns the negotiated compression name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => COMPRESSION_NONE,
            Self::Zlib => COMPRESSION_ZLIB_OPENSSH,
        }
    }
}

/// Compresses one bounded payload with the OpenSSH zlib stream.
///
/// # Errors
///
/// Returns [`CompressionError`] for an oversized payload or a local encoder
/// failure.
pub fn compress_payload(payload: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if payload.len() > MAX_COMPRESSED_PAYLOAD {
        return Err(CompressionError::LimitExceeded);
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .map_err(|_error| CompressionError::CompressionFailed)?;
    let compressed = encoder
        .finish()
        .map_err(|_error| CompressionError::CompressionFailed)?;
    if compressed.len() > MAX_COMPRESSED_PAYLOAD {
        return Err(CompressionError::LimitExceeded);
    }
    Ok(compressed)
}

/// Decompresses one bounded OpenSSH zlib stream.
///
/// # Errors
///
/// Returns [`CompressionError`] for an oversized, malformed, truncated, or
/// trailing-data stream.
pub fn decompress_payload(payload: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if payload.is_empty() || payload.len() > MAX_COMPRESSED_PAYLOAD {
        return Err(if payload.is_empty() {
            CompressionError::InvalidStream
        } else {
            CompressionError::LimitExceeded
        });
    }

    let initial_capacity = payload.len().min(8 * 1_024);
    let mut output = Vec::new();
    output
        .try_reserve(initial_capacity)
        .map_err(|_error| CompressionError::LimitExceeded)?;
    let mut decompressor = Decompress::new(true);
    let mut previous_in = 0_u64;
    let mut previous_out = 0_u64;

    loop {
        let offset = usize::try_from(decompressor.total_in())
            .map_err(|_error| CompressionError::InvalidStream)?;
        if offset > payload.len() {
            return Err(CompressionError::InvalidStream);
        }
        if output.len() >= MAX_COMPRESSED_PAYLOAD {
            return Err(CompressionError::LimitExceeded);
        }
        let target = output
            .len()
            .saturating_add(8 * 1_024)
            .min(MAX_COMPRESSED_PAYLOAD);
        let additional = target.saturating_sub(output.len());
        output
            .try_reserve(additional)
            .map_err(|_error| CompressionError::LimitExceeded)?;

        let status = decompressor
            .decompress_vec(&payload[offset..], &mut output, FlushDecompress::Finish)
            .map_err(|_error| CompressionError::InvalidStream)?;
        if status == Status::StreamEnd {
            let consumed = usize::try_from(decompressor.total_in())
                .map_err(|_error| CompressionError::InvalidStream)?;
            if consumed != payload.len() || output.len() > MAX_COMPRESSED_PAYLOAD {
                return Err(CompressionError::InvalidStream);
            }
            return Ok(output);
        }
        let current_in = decompressor.total_in();
        let current_out = decompressor.total_out();
        if current_in == previous_in && current_out == previous_out && status == Status::BufError {
            return Err(CompressionError::InvalidStream);
        }
        previous_in = current_in;
        previous_out = current_out;
    }
}

/// Creates alignment padding for a compressed payload from a byte pattern.
///
/// `block_size` and `header_length` are the two halves of the protected
/// packet's framing contract, and the arithmetic that turns them into a padding
/// length lives in one place so this function and the packet layer cannot
/// disagree. `header_length` is `1` when the four-byte `packet_length` field is
/// authenticated but not encrypted — the AEAD and encrypt-then-MAC cases — and
/// `5` when it is encrypted along with the payload.
///
/// # Errors
///
/// Returns [`CompressionError`] for an empty pattern, an unsupported block size
/// or header length, or an unrepresentable padding length.
pub fn padding_for_payload(
    payload_length: usize,
    pattern: &[u8],
    block_size: usize,
    header_length: usize,
) -> Result<Vec<u8>, CompressionError> {
    if !matches!(block_size, 8 | 16) || !matches!(header_length, 1 | 5) {
        return Err(CompressionError::CompressionFailed);
    }
    let alignment = PacketAlignment::new(block_size, header_length == 1);
    alignment
        .padding_pattern(payload_length, pattern)
        .map_err(|error| match error {
            AlignmentError::EmptyPattern => CompressionError::CompressionFailed,
            AlignmentError::LengthOverflow | AlignmentError::InvalidAlignment => {
                CompressionError::LimitExceeded
            }
        })
}
