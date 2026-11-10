//! Strict single-block PEM.
//!
//! `pem-rfc7468` accepts more framing than the established PEM framing. This
//! codec matches that policy: one block, an exact label, whitespace only
//! outside the block, a decoded payload from 1 byte through 1 MiB, and DER
//! that is exactly one distinguished-encoding value.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

/// Largest DER payload this codec accepts.
pub const MAXIMUM_DECODED_LENGTH: usize = 1024 * 1024;

const MAX_DEPTH: usize = 64;

const MAX_ENCODED_LENGTH: usize = MAXIMUM_DECODED_LENGTH.div_ceil(3) * 4;

/// PEM encode or decode failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PemError {
    /// The label is empty or contains a line break.
    Label,
    /// The input is not one PEM block with the expected label.
    Framing,
    /// The base64 payload is invalid.
    Base64,
    /// The decoded length is outside 1 byte through [`MAXIMUM_DECODED_LENGTH`].
    Length,
    /// The bytes are not one DER value.
    Der,
}

impl std::fmt::Display for PemError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Label => "PEM label must be a non-empty single line",
            Self::Framing => "PEM input must contain exactly one block",
            Self::Base64 => "PEM payload is not valid base64",
            Self::Length => "PEM decoded data must be between 1 byte and 1 MiB",
            Self::Der => "DER input must contain exactly one valid DER value",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PemError {}

/// Encodes one DER payload with `label`.
///
/// # Errors
///
/// Returns [`PemError::Label`] or [`PemError::Length`] when the inputs are outside the codec policy.
pub fn encode(label: &str, der: &[u8]) -> Result<String, PemError> {
    validate_label(label)?;
    validate_length(der.len())?;
    let body = Zeroizing::new(STANDARD.encode(der));
    let mut pem = Zeroizing::new(String::with_capacity(body.len() + label.len() * 2 + 64));
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        let Ok(line) = std::str::from_utf8(chunk) else {
            return Err(PemError::Base64);
        };
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    Ok(std::mem::take(&mut *pem))
}

/// Decodes exactly one PEM block with `expected_label`.
///
/// # Errors
///
/// Returns [`PemError`] when the framing, label, base64, or length check fails.
pub fn decode(pem: &str, expected_label: &str) -> Result<Vec<u8>, PemError> {
    validate_label(expected_label)?;
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");
    let start = pem.find(&begin).ok_or(PemError::Framing)?;
    if !pem[..start].chars().all(char::is_whitespace) {
        return Err(PemError::Framing);
    }
    let header_end = start + begin.len();
    let body_start = skip_line_break(pem, header_end)?;
    let end_at = pem[body_start..]
        .find(&end)
        .map(|offset| body_start + offset)
        .ok_or(PemError::Framing)?;
    if end_at < body_start || !line_starts_footer(&pem[body_start..end_at]) {
        return Err(PemError::Framing);
    }
    let after_end = end_at + end.len();
    if !pem[after_end..].chars().all(char::is_whitespace) {
        return Err(PemError::Framing);
    }
    let body: Zeroizing<String> = Zeroizing::new(
        pem[body_start..end_at]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect(),
    );
    if body.len() > MAX_ENCODED_LENGTH {
        return Err(PemError::Length);
    }
    let decoded = STANDARD
        .decode(body.as_str())
        .map_err(|_| PemError::Base64)?;
    validate_length(decoded.len())?;
    Ok(decoded)
}

/// Decodes one PEM block and requires the payload to be one DER value.
///
/// # Errors
///
/// Returns [`PemError`] from [`decode`], or [`PemError::Der`] when the payload is not one DER value.
pub fn decode_der(pem: &str, expected_label: &str) -> Result<Vec<u8>, PemError> {
    let mut der = Zeroizing::new(decode(pem, expected_label)?);
    validate_der(&der)?;
    Ok(std::mem::take(&mut *der))
}

/// Checks that `der` is one bounded distinguished-encoding value.
///
/// # Errors
///
/// Returns [`PemError::Length`] or [`PemError::Der`].
pub fn validate_der(der: &[u8]) -> Result<(), PemError> {
    validate_length(der.len())?;
    let consumed = parse_value(der, 0).map_err(|()| PemError::Der)?;
    if consumed != der.len() {
        return Err(PemError::Der);
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), PemError> {
    if label.is_empty() || label.contains(['\r', '\n']) {
        Err(PemError::Label)
    } else {
        Ok(())
    }
}

fn validate_length(length: usize) -> Result<(), PemError> {
    if (1..=MAXIMUM_DECODED_LENGTH).contains(&length) {
        Ok(())
    } else {
        Err(PemError::Length)
    }
}

fn skip_line_break(pem: &str, index: usize) -> Result<usize, PemError> {
    let rest = pem.get(index..).ok_or(PemError::Framing)?;
    if let Some(stripped) = rest.strip_prefix("\r\n") {
        Ok(pem.len() - stripped.len())
    } else if let Some(stripped) = rest.strip_prefix('\n') {
        Ok(pem.len() - stripped.len())
    } else {
        Err(PemError::Framing)
    }
}

fn line_starts_footer(body: &str) -> bool {
    body.ends_with('\n')
}

fn parse_value(input: &[u8], depth: usize) -> Result<usize, ()> {
    if depth > MAX_DEPTH || input.is_empty() {
        return Err(());
    }
    let (tag_len, class, constructed, number) = parse_tag(input)?;
    let (length_len, length) = parse_length(&input[tag_len..])?;
    let header = tag_len.checked_add(length_len).ok_or(())?;
    let total = header.checked_add(length).ok_or(())?;
    if total > input.len() {
        return Err(());
    }
    let content = &input[header..total];
    if constructed {
        if class == 0 && primitive_only(number) {
            return Err(());
        }
        parse_constructed(content, depth, class, number)?;
    } else {
        if class == 0 && constructed_only(number) {
            return Err(());
        }
        validate_primitive(class, number, content)?;
    }
    Ok(total)
}

fn parse_constructed(content: &[u8], depth: usize, class: u8, number: u32) -> Result<(), ()> {
    let mut offset = 0;
    let mut children = Vec::new();
    while offset < content.len() {
        let child_len = parse_value(&content[offset..], depth + 1)?;
        children.push(&content[offset..offset + child_len]);
        offset += child_len;
    }
    if class == 0 && number == 17 {
        for pair in children.windows(2) {
            if pair[0] > pair[1] {
                return Err(());
            }
        }
    }
    Ok(())
}

fn parse_tag(input: &[u8]) -> Result<(usize, u8, bool, u32), ()> {
    let first = *input.first().ok_or(())?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    if first & 0x1f != 0x1f {
        return Ok((1, class, constructed, u32::from(first & 0x1f)));
    }
    let mut number: u32 = 0;
    let mut index = 1;
    let mut saw = false;
    while index < input.len() {
        let byte = input[index];
        index += 1;
        saw = true;
        if number > (u32::MAX >> 7) {
            return Err(());
        }
        number = (number << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if number < 31 {
                return Err(());
            }
            return Ok((index, class, constructed, number));
        }
    }
    let _ = saw;
    Err(())
}

fn parse_length(input: &[u8]) -> Result<(usize, usize), ()> {
    let first = *input.first().ok_or(())?;
    if first < 0x80 {
        return Ok((1, usize::from(first)));
    }
    if first == 0x80 {
        return Err(());
    }
    let nbytes = usize::from(first & 0x7f);
    if nbytes == 0 || nbytes > 4 || input.len() < 1 + nbytes {
        return Err(());
    }
    if input[1] == 0 {
        return Err(());
    }
    let mut length = 0usize;
    for byte in &input[1..=nbytes] {
        length = length
            .checked_shl(8)
            .ok_or(())?
            .checked_add(usize::from(*byte))
            .ok_or(())?;
    }
    if length < 128 {
        return Err(());
    }
    Ok((1 + nbytes, length))
}

fn primitive_only(number: u32) -> bool {
    matches!(
        number,
        1 | 2
            | 3
            | 4
            | 5
            | 6
            | 7
            | 9
            | 10
            | 12
            | 13
            | 18
            | 19
            | 20
            | 21
            | 22
            | 23
            | 24
            | 25
            | 26
            | 27
            | 28
            | 30
    )
}

fn constructed_only(number: u32) -> bool {
    matches!(number, 8 | 11 | 16 | 17)
}

fn validate_primitive(class: u8, number: u32, content: &[u8]) -> Result<(), ()> {
    if class != 0 {
        return Ok(());
    }
    match number {
        1 => {
            if content == [0x00] || content == [0xff] {
                Ok(())
            } else {
                Err(())
            }
        }
        2 | 10 => validate_integer(content),
        3 => validate_bit_string(content),
        5 => {
            if content.is_empty() {
                Ok(())
            } else {
                Err(())
            }
        }
        6 | 13 => validate_oid(content),
        _ => Ok(()),
    }
}

fn validate_integer(content: &[u8]) -> Result<(), ()> {
    let [first, second, ..] = content else {
        return if content.is_empty() { Err(()) } else { Ok(()) };
    };
    let redundant_positive = *first == 0x00 && second & 0x80 == 0;
    let redundant_negative = *first == 0xff && second & 0x80 != 0;
    if redundant_positive || redundant_negative {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_bit_string(content: &[u8]) -> Result<(), ()> {
    let Some((unused, payload)) = content.split_first() else {
        return Err(());
    };
    if *unused > 7 || (payload.is_empty() && *unused != 0) {
        return Err(());
    }
    if *unused > 0 {
        let mask = (1_u8 << unused) - 1;
        if payload.last().ok_or(())? & mask != 0 {
            return Err(());
        }
    }
    Ok(())
}

fn validate_oid(content: &[u8]) -> Result<(), ()> {
    if content.is_empty() || content.last().ok_or(())? & 0x80 != 0 {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PemError, decode, decode_der, encode, validate_der};

    #[test]
    fn round_trips_one_block() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x01];
        let pem = encode("TEST DATA", &der).expect("encode");
        assert_eq!(
            pem,
            "-----BEGIN TEST DATA-----\nMAMCAQE=\n-----END TEST DATA-----\n"
        );
        assert_eq!(decode_der(&pem, "TEST DATA").expect("decode"), der);
    }

    #[test]
    fn rejects_extra_text_wrong_label_and_bad_der() {
        let pem = encode("TEST DATA", &[1, 2, 3]).expect("encode");
        assert_eq!(decode(&pem, "OTHER DATA"), Err(PemError::Framing));
        assert_eq!(
            decode(&format!("{pem}text"), "TEST DATA"),
            Err(PemError::Framing)
        );
        assert_eq!(
            decode(&format!("{pem}{pem}"), "TEST DATA"),
            Err(PemError::Framing)
        );
        assert_eq!(decode_der(&pem, "TEST DATA"), Err(PemError::Der));
        assert_eq!(validate_der(&[0x30, 0x03, 0x02, 0x01]), Err(PemError::Der));
    }
}
