//! Unencrypted SSH binary packet framing from RFC 4253 section 6.

pub use crate::error::Error;

/// The default SSH cipher block size before key exchange.
pub const DEFAULT_BLOCK_SIZE: usize = 8;

/// The minimum permitted SSH packet padding length.
pub const MIN_PADDING: usize = 4;

/// The maximum combined payload and padding size accepted by this slice.
pub const MAX_PACKET_CONTENT: usize = 1_048_576;

/// An alias for the maximum packet content limit.
pub const MAX_PACKET_BODY: usize = MAX_PACKET_CONTENT;

/// A source used to fill the padding bytes of a new packet.
///
/// A closure accepting `&mut [u8]` implements this trait automatically, so
/// callers can use deterministic padding in tests without adding a random
/// number dependency.
pub trait PaddingSource {
    /// Fills every byte in `padding`.
    fn fill(&mut self, padding: &mut [u8]);
}

impl<F> PaddingSource for F
where
    F: FnMut(&mut [u8]),
{
    fn fill(&mut self, padding: &mut [u8]) {
        self(padding);
    }
}

/// An alias for [`PaddingSource`] that emphasizes the fill operation.
pub use PaddingSource as PaddingFill;

/// A deterministic padding source that repeats its supplied bytes.
///
/// An empty source fills with zeroes.  A non-empty source is cycled as needed
/// to cover the exact padding length selected by the packet builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedPadding {
    bytes: Vec<u8>,
}

impl FixedPadding {
    /// Creates a repeating padding source.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Returns the source bytes without consuming it.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl PaddingSource for FixedPadding {
    fn fill(&mut self, padding: &mut [u8]) {
        if self.bytes.is_empty() {
            padding.fill(0);
            return;
        }
        for (index, byte) in padding.iter_mut().enumerate() {
            *byte = self.bytes[index % self.bytes.len()];
        }
    }
}

/// A decoded unencrypted SSH packet body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    /// The packet payload, excluding the padding-length byte and padding.
    pub payload: Vec<u8>,
    /// The padding bytes, which may be arbitrary caller-selected bytes.
    pub padding: Vec<u8>,
}

impl Packet {
    /// Creates a packet from already separated payload and padding bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPadding`] when padding cannot be represented by
    /// the one-byte padding-length field and [`Error::LimitExceeded`] when
    /// payload plus padding is too large.
    pub fn from_parts(
        payload: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        let payload = payload.into();
        let padding = padding.into();
        if padding.len() < MIN_PADDING || u8::try_from(padding.len()).is_err() {
            return Err(Error::InvalidPadding);
        }
        let content_length = payload
            .len()
            .checked_add(padding.len())
            .ok_or(Error::LimitExceeded)?;
        if content_length > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }
        Ok(Self { payload, padding })
    }

    /// Returns the packet payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the packet padding.
    #[must_use]
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Consumes the packet and returns its payload and padding.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.payload, self.padding)
    }

    /// Checks packet-size and padding invariants for a selected block size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBlockSize`], [`Error::InvalidPadding`],
    /// [`Error::LimitExceeded`], or [`Error::InvalidPacket`] when an invariant
    /// is not satisfied.
    pub fn validate(&self, block_size: usize) -> Result<(), Error> {
        validate_block_size(block_size)?;
        if self.padding.len() < MIN_PADDING {
            return Err(Error::InvalidPadding);
        }
        let content_length = self
            .payload
            .len()
            .checked_add(self.padding.len())
            .ok_or(Error::LimitExceeded)?;
        if content_length > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }
        let total_length = 4_usize
            .checked_add(1)
            .and_then(|length| length.checked_add(content_length))
            .ok_or(Error::LimitExceeded)?;
        if total_length % block_size != 0 {
            return Err(Error::InvalidPacket);
        }
        if u8::try_from(self.padding.len()).is_err() {
            return Err(Error::InvalidPadding);
        }
        Ok(())
    }
}

/// Builds an unencrypted SSH packet with an explicit block size and a closure.
///
/// The source is called once with exactly the padding slice selected for the
/// payload.  The resulting bytes contain the four-byte packet length followed
/// by the padding-length byte, payload, and padding.
///
/// # Errors
///
/// Returns [`Error::InvalidBlockSize`] for a zero or unrepresentable block
/// size and [`Error::LimitExceeded`] when payload plus padding exceeds
/// [`MAX_PACKET_CONTENT`].
pub fn build_packet<F>(
    payload: &[u8],
    block_size: usize,
    padding_source: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&mut [u8]),
{
    build_packet_with_source(payload, block_size, padding_source)
}

/// Builds an unencrypted SSH packet with an explicit block size and a
/// [`PaddingSource`] implementation.
///
/// # Errors
///
/// Returns [`Error::InvalidBlockSize`] for a zero or unrepresentable block
/// size and [`Error::LimitExceeded`] when payload plus padding exceeds
/// [`MAX_PACKET_CONTENT`].
pub fn build_packet_with_source(
    payload: &[u8],
    block_size: usize,
    mut padding_source: impl PaddingSource,
) -> Result<Vec<u8>, Error> {
    let padding_length = padding_length_for(payload.len(), block_size)?;
    let packet_length = payload
        .len()
        .checked_add(padding_length)
        .and_then(|length| length.checked_add(1))
        .ok_or(Error::LimitExceeded)?;
    let total_length = packet_length.checked_add(4).ok_or(Error::LimitExceeded)?;
    if total_length % block_size != 0 {
        return Err(Error::InvalidPacket);
    }
    let packet_length = u32::try_from(packet_length).map_err(|_| Error::LimitExceeded)?;
    let padding_length_byte = u8::try_from(padding_length).map_err(|_| Error::InvalidBlockSize)?;
    let mut output = Vec::with_capacity(total_length);
    output.extend_from_slice(&packet_length.to_be_bytes());
    output.push(padding_length_byte);
    output.extend_from_slice(payload);
    let padding_start = output.len();
    output.resize(
        output
            .len()
            .checked_add(padding_length)
            .ok_or(Error::LimitExceeded)?,
        0,
    );
    let padding = output
        .get_mut(padding_start..)
        .ok_or(Error::InvalidPacket)?;
    padding_source.fill(padding);
    Ok(output)
}

/// Builds an unencrypted packet using [`DEFAULT_BLOCK_SIZE`].
///
/// # Errors
///
/// Returns the same errors as [`build_packet`].
pub fn build_packet_default<F>(payload: &[u8], padding_source: F) -> Result<Vec<u8>, Error>
where
    F: FnMut(&mut [u8]),
{
    build_packet(payload, DEFAULT_BLOCK_SIZE, padding_source)
}

/// Builds a packet using the default block size and a [`PaddingSource`].
///
/// # Errors
///
/// Returns the same errors as [`build_packet_with_source`].
pub fn build_packet_with_source_default(
    payload: &[u8],
    padding_source: impl PaddingSource,
) -> Result<Vec<u8>, Error> {
    build_packet_with_source(payload, DEFAULT_BLOCK_SIZE, padding_source)
}

/// Builds an unencrypted packet using [`DEFAULT_BLOCK_SIZE`].
///
/// This longer name is provided for callers that prefer an explicit
/// default-block-size operation.
///
/// # Errors
///
/// Returns the same errors as [`build_packet`].
pub fn build_packet_with_default_block_size<F>(
    payload: &[u8],
    padding_source: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&mut [u8]),
{
    build_packet_default(payload, padding_source)
}

/// Alias for [`build_packet`] using the explicit-block-size signature.
///
/// # Errors
///
/// Returns the same errors as [`build_packet`].
pub fn encode_packet<F>(
    payload: &[u8],
    block_size: usize,
    padding_source: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&mut [u8]),
{
    build_packet(payload, block_size, padding_source)
}

/// Encodes a packet with an explicit block size and a [`PaddingSource`].
///
/// # Errors
///
/// Returns the same errors as [`build_packet_with_source`].
pub fn encode_packet_with_source(
    payload: &[u8],
    block_size: usize,
    padding_source: impl PaddingSource,
) -> Result<Vec<u8>, Error> {
    build_packet_with_source(payload, block_size, padding_source)
}

/// Builds and decodes one exact packet, primarily useful for validating a
/// newly constructed packet body.
///
/// # Errors
///
/// Returns any error returned by packet construction or decoding.
pub fn round_trip_packet<F>(
    payload: &[u8],
    block_size: usize,
    padding_source: F,
) -> Result<Packet, Error>
where
    F: FnMut(&mut [u8]),
{
    let encoded = build_packet(payload, block_size, padding_source)?;
    decode_packet(&encoded, block_size)
}

/// Decodes one exact unencrypted SSH packet from `input`.
///
/// The input must contain the four-byte packet length and exactly one packet
/// body.  Use [`decode_packet_prefix`] when reading from a larger stream.
///
/// # Errors
///
/// Returns [`Error::Truncated`] for an incomplete packet, [`Error::LimitExceeded`]
/// for an oversized content body, and [`Error::InvalidPacket`],
/// [`Error::InvalidPadding`], or [`Error::InvalidBlockSize`] for malformed
/// framing.
pub fn decode_packet(input: &[u8], block_size: usize) -> Result<Packet, Error> {
    let (packet, consumed) = decode_packet_prefix(input, block_size)?;
    if consumed != input.len() {
        return Err(Error::InvalidPacket);
    }
    Ok(packet)
}

/// Decodes one packet and returns the number of input bytes consumed.
///
/// This permits a caller to process several packets from one contiguous buffer
/// while still requiring each individual packet to be self-consistent.
///
/// # Errors
///
/// Returns the same framing errors as [`decode_packet`].
pub fn decode_packet_prefix(input: &[u8], block_size: usize) -> Result<(Packet, usize), Error> {
    validate_block_size(block_size)?;
    let mut reader = crate::wire::Reader::new(input);
    let packet_length = reader.read_uint32()?;
    let packet_length = usize::try_from(packet_length).map_err(|_| Error::LimitExceeded)?;
    if packet_length == 0 {
        return Err(Error::InvalidPacket);
    }
    let content_length = packet_length.checked_sub(1).ok_or(Error::InvalidPacket)?;
    if content_length > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    let total_length = packet_length.checked_add(4).ok_or(Error::LimitExceeded)?;
    if input.len() < total_length {
        return Err(Error::Truncated);
    }
    if total_length % block_size != 0 {
        return Err(Error::InvalidPacket);
    }
    let body = input.get(4..total_length).ok_or(Error::Truncated)?;
    let padding_length = body.first().copied().ok_or(Error::Truncated)? as usize;
    if padding_length < MIN_PADDING {
        return Err(Error::InvalidPadding);
    }
    if padding_length > content_length {
        return Err(Error::InvalidPacket);
    }
    let payload_length = content_length - padding_length;
    let payload_end = 1_usize
        .checked_add(payload_length)
        .ok_or(Error::InvalidPacket)?;
    let payload = body.get(1..payload_end).ok_or(Error::Truncated)?.to_vec();
    let padding = body
        .get(payload_end..total_length - 4)
        .ok_or(Error::Truncated)?
        .to_vec();
    Ok((Packet { payload, padding }, total_length))
}

/// Decodes one exact packet using [`DEFAULT_BLOCK_SIZE`].
///
/// # Errors
///
/// Returns the same errors as [`decode_packet`].
pub fn decode_packet_default(input: &[u8]) -> Result<Packet, Error> {
    decode_packet(input, DEFAULT_BLOCK_SIZE)
}

/// Decodes one packet using the default block size and returns its consumed length.
///
/// # Errors
///
/// Returns the same errors as [`decode_packet_prefix`].
pub fn decode_packet_prefix_default(input: &[u8]) -> Result<(Packet, usize), Error> {
    decode_packet_prefix(input, DEFAULT_BLOCK_SIZE)
}

/// Alias for [`decode_packet`].
///
/// # Errors
///
/// Returns the same errors as [`decode_packet`].
pub fn parse_packet(input: &[u8], block_size: usize) -> Result<Packet, Error> {
    decode_packet(input, block_size)
}

fn validate_block_size(block_size: usize) -> Result<(), Error> {
    if block_size == 0 || block_size > u8::MAX as usize + 1 {
        return Err(Error::InvalidBlockSize);
    }
    Ok(())
}

fn padding_length_for(payload_length: usize, block_size: usize) -> Result<usize, Error> {
    validate_block_size(block_size)?;
    let unpadded_length = 4_usize
        .checked_add(1)
        .and_then(|length| length.checked_add(payload_length))
        .ok_or(Error::LimitExceeded)?;
    let mut padding_length = block_size - (unpadded_length % block_size);
    while padding_length < MIN_PADDING {
        padding_length = padding_length
            .checked_add(block_size)
            .ok_or(Error::InvalidBlockSize)?;
    }
    if u8::try_from(padding_length).is_err() {
        return Err(Error::InvalidBlockSize);
    }
    let content_length = payload_length
        .checked_add(padding_length)
        .ok_or(Error::LimitExceeded)?;
    if content_length > MAX_PACKET_CONTENT {
        return Err(Error::LimitExceeded);
    }
    Ok(padding_length)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_BLOCK_SIZE, Error, FixedPadding, MAX_PACKET_CONTENT, Packet, build_packet,
        build_packet_default, build_packet_with_source, decode_packet, decode_packet_prefix,
    };

    #[test]
    fn round_trips_empty_and_several_payload_lengths() -> Result<(), Error> {
        for block_size in [8, 16] {
            for payload_length in [0, 1, 3, 4, 7, 8, 15, 16, 31] {
                let payload = vec![0xa5; payload_length];
                let encoded = build_packet(&payload, block_size, |padding| {
                    padding.fill(0x5a);
                })?;
                let packet = decode_packet(&encoded, block_size)?;
                assert_eq!(packet.payload(), payload);
                assert!(packet.padding().len() >= 4);
                let expected_packet_length = packet.payload().len() + packet.padding().len() + 1;
                assert!(u32::try_from(expected_packet_length).is_ok_and(|expected| {
                    encoded.get(0..4).is_some_and(|length| {
                        u32::from_be_bytes([length[0], length[1], length[2], length[3]]) == expected
                    })
                }));
            }
        }
        Ok(())
    }

    #[test]
    fn uses_the_default_block_size() -> Result<(), Error> {
        let encoded = build_packet_default(b"payload", |padding| padding.fill(7))?;
        assert_eq!(encoded.len() % DEFAULT_BLOCK_SIZE, 0);
        let packet = decode_packet(&encoded, DEFAULT_BLOCK_SIZE)?;
        assert_eq!(packet.payload(), b"payload");
        assert!(packet.padding().iter().all(|byte| *byte == 7));
        Ok(())
    }

    #[test]
    fn fixed_padding_repeats_caller_bytes() -> Result<(), Error> {
        let encoded = build_packet_with_source(b"x", 16, FixedPadding::new([0xaa, 0xbb]))?;
        let packet = decode_packet(&encoded, 16)?;
        assert_eq!(
            packet.padding(),
            [0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb]
        );
        Ok(())
    }

    #[test]
    fn rejects_short_padding_and_inconsistent_lengths() -> Result<(), Error> {
        let malformed = [0, 0, 0, 4, 3, 0, 0, 0];
        assert_eq!(decode_packet(&malformed, 8), Err(Error::InvalidPadding));

        let zero_length = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_packet(&zero_length, 8), Err(Error::InvalidPacket));

        let valid = build_packet(b"", 8, |padding| padding.fill(0))?;
        assert_eq!(
            decode_packet(&valid, 8)?,
            Packet::from_parts(Vec::new(), vec![0; 11])?
        );
        let mut with_extra = valid;
        with_extra.push(0);
        assert_eq!(decode_packet(&with_extra, 8), Err(Error::InvalidPacket));
        Ok(())
    }

    #[test]
    fn rejects_invalid_block_sizes_and_oversized_content() {
        assert_eq!(
            build_packet(b"payload", 0, |padding| padding.fill(0)),
            Err(Error::InvalidBlockSize)
        );
        assert_eq!(
            build_packet(&vec![0; MAX_PACKET_CONTENT], 8, |padding| padding.fill(0)),
            Err(Error::LimitExceeded)
        );
        assert_eq!(
            Packet::from_parts(vec![0; MAX_PACKET_CONTENT], vec![0; 4]),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn prefix_decoder_reports_consumed_length() -> Result<(), Error> {
        let mut first = build_packet(b"one", 8, |padding| padding.fill(1))?;
        let second = build_packet(b"two", 8, |padding| padding.fill(2))?;
        first.extend_from_slice(&second);
        let (packet, consumed) = decode_packet_prefix(&first, 8)?;
        assert_eq!(packet.payload(), b"one");
        assert_eq!(consumed, 16);
        let (packet, consumed) = decode_packet_prefix(&first[consumed..], 8)?;
        assert_eq!(packet.payload(), b"two");
        assert_eq!(consumed, first.len() - 16);
        Ok(())
    }
}
