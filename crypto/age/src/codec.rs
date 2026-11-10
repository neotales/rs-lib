//! Strict base64 and ASCII-armor codecs used by age.

use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::STANDARD_NO_PAD,
};

use crate::{
    AgeReadOptions,
    error::{AgeError, Result},
};

/// The age version line.
pub(crate) const VERSION_LINE: &[u8] = b"age-encryption.org/v1\n";

/// The STREAM plaintext chunk size.
pub(crate) const STREAM_CHUNK_SIZE: usize = 64 * 1024;
/// The STREAM payload nonce size.
pub(crate) const STREAM_NONCE_SIZE: usize = 16;
/// The STREAM authentication tag size.
pub(crate) const STREAM_TAG_LENGTH: usize = 16;

const ARMOR_LINE_LENGTH: usize = 64;
const ARMOR_MAX_WHITESPACE: usize = 1024;

/// Returns the canonical, unpadded age base64 representation.
pub(crate) fn encode_raw(bytes: &[u8]) -> String {
    STANDARD.encode(bytes).trim_end_matches('=').to_owned()
}

/// Decodes canonical, unpadded age base64.
pub(crate) fn decode_raw(value: &str) -> Result<Vec<u8>> {
    if value.contains('=') {
        return Err(AgeError::InvalidFormat("padded age base64"));
    }
    if value.len() % 4 == 1 {
        return Err(AgeError::InvalidFormat("invalid age base64 length"));
    }
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| AgeError::InvalidFormat("invalid age base64"))?;
    if encode_raw(&decoded) != value {
        return Err(AgeError::InvalidFormat("non-canonical age base64"));
    }
    Ok(decoded)
}

/// Decodes standard base64, accepting either the padded or unpadded form.
///
/// Padding, when present, must be the canonical trailing padding. This is
/// retained for the SSH wire formats, which are separate from the age header
/// grammar. Header MACs use [`decode_raw`] instead.
pub(crate) fn decode_standard_or_raw(value: &str) -> Result<Vec<u8>> {
    if value.contains('=') {
        if !value.len().is_multiple_of(4) || !value.ends_with('=') {
            return Err(AgeError::InvalidFormat("invalid padded base64"));
        }
        let first_padding = value.find('=').unwrap_or(value.len());
        if value[first_padding..]
            .bytes()
            .any(|character| character != b'=')
        {
            return Err(AgeError::InvalidFormat("invalid padded base64"));
        }
        let decoded = STANDARD
            .decode(value)
            .map_err(|_| AgeError::InvalidFormat("invalid base64"))?;
        if STANDARD.encode(&decoded) != value {
            return Err(AgeError::InvalidFormat("non-canonical base64"));
        }
        return Ok(decoded);
    }
    decode_raw(value)
}

/// Strict ASCII armor for an age file.
///
/// A unit struct holding no state, so its [`Debug`](std::fmt::Debug) output is
/// the type name. Armor is a set of associated functions rather than a value
/// with settings, so there is no per-instance state a caller could want to see.
#[derive(Debug)]
pub struct AgeArmor;

impl AgeArmor {
    /// The opening armor marker.
    pub const BEGIN: &'static str = "-----BEGIN AGE ENCRYPTED FILE-----";
    /// The closing armor marker.
    pub const END: &'static str = "-----END AGE ENCRYPTED FILE-----";

    /// Encodes binary age data using strict 64-column armor.
    #[must_use]
    pub fn encode(binary: &[u8]) -> String {
        let body = STANDARD.encode(binary);
        let mut result =
            String::with_capacity(Self::BEGIN.len() + Self::END.len() + body.len() + 8);
        result.push_str(Self::BEGIN);
        result.push('\n');
        for chunk in body.as_bytes().chunks(64) {
            if let Ok(line) = std::str::from_utf8(chunk) {
                result.push_str(line);
            }
            result.push('\n');
        }
        result.push_str(Self::END);
        result.push('\n');
        result
    }

    /// Decodes age armor with the default limits.
    ///
    /// # Errors
    ///
    /// Returns an [`AgeError`] for malformed framing, line lengths,
    /// whitespace, base64, or configured size-limit violations.
    pub fn decode(armored: impl AsRef<str>) -> Result<Vec<u8>> {
        Self::decode_with_options(armored, AgeReadOptions::default())
    }

    /// Decodes age armor with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns an [`AgeError`] for malformed framing, line lengths,
    /// whitespace, base64, or configured size-limit violations.
    pub fn decode_with_options(
        armored: impl AsRef<str>,
        options: AgeReadOptions,
    ) -> Result<Vec<u8>> {
        let armored = armored.as_ref();
        let options = options.validate()?;
        if armored.len() > maximum_armored_characters(options) {
            return Err(AgeError::LimitExceeded("armored input is too large"));
        }

        // Go's armor reader accepts CRLF and removes one trailing carriage
        // return from a line, including a final line without LF. Keep the raw
        // segments so trailing-whitespace limits count CRLF bytes as Go does.
        let mut lines = armored.split_inclusive('\n');
        let mut leading_whitespace = 0usize;
        loop {
            let Some(segment) = lines.next() else {
                return Err(AgeError::InvalidFormat("missing armor begin marker"));
            };
            let line = armor_line(segment)?;
            if line == Self::BEGIN {
                break;
            }
            if !is_ascii_whitespace_line(line) {
                return Err(AgeError::InvalidFormat("invalid armor begin marker"));
            }
            leading_whitespace = leading_whitespace
                .checked_add(line.len())
                .and_then(|value| value.checked_add(1))
                .ok_or(AgeError::LimitExceeded("too much leading armor whitespace"))?;
            if leading_whitespace > ARMOR_MAX_WHITESPACE {
                return Err(AgeError::LimitExceeded("too much leading armor whitespace"));
            }
        }

        let mut binary = Vec::new();
        let mut last_line_was_short = false;
        loop {
            let Some(segment) = lines.next() else {
                return Err(AgeError::InvalidFormat("missing armor end marker"));
            };
            let line = armor_line(segment)?;
            if line == Self::END {
                break;
            }
            if last_line_was_short {
                return Err(AgeError::InvalidFormat("data after final armor line"));
            }
            if line.is_empty()
                || line.len() > ARMOR_LINE_LENGTH
                || line.bytes().any(|byte| byte.is_ascii_whitespace())
            {
                return Err(AgeError::InvalidFormat("invalid armor line"));
            }

            let decoded = STANDARD
                .decode(line.as_bytes())
                .map_err(|_| AgeError::InvalidFormat("invalid armor base64"))?;
            if STANDARD.encode(&decoded) != line || decoded.len() > ARMOR_LINE_LENGTH / 4 * 3 {
                return Err(AgeError::InvalidFormat("non-canonical armor base64"));
            }
            binary.extend_from_slice(&decoded);
            last_line_was_short = decoded.len() < ARMOR_LINE_LENGTH / 4 * 3;
        }

        let trailer = lines.collect::<String>();
        validate_trailing_whitespace(&trailer)?;
        if binary.len() > maximum_binary_bytes(options) {
            return Err(AgeError::LimitExceeded("armored binary is too large"));
        }
        Ok(binary)
    }
}

fn armor_line(segment: &str) -> Result<&str> {
    let line = segment.strip_suffix('\n').unwrap_or(segment);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains('\r') {
        return Err(AgeError::InvalidFormat("invalid armor line endings"));
    }
    Ok(line)
}

fn is_ascii_whitespace_line(line: &str) -> bool {
    line.bytes().all(|byte| byte.is_ascii_whitespace())
}

fn validate_trailing_whitespace(trailer: &str) -> Result<()> {
    let bytes = trailer.as_bytes();
    let inspected = bytes.len().min(ARMOR_MAX_WHITESPACE);
    if bytes
        .get(..inspected)
        .unwrap_or_default()
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err(AgeError::InvalidFormat("trailing data after armor"));
    }
    if bytes.len() >= ARMOR_MAX_WHITESPACE {
        return Err(AgeError::LimitExceeded(
            "too much trailing armor whitespace",
        ));
    }
    Ok(())
}

/// Returns whether bytes begin an age armor block, allowing the same bounded
/// leading whitespace as the Go armor reader.
pub(crate) fn starts_with_begin_marker(bytes: &[u8]) -> bool {
    let begin = AgeArmor::BEGIN.as_bytes();
    let mut offset = 0usize;
    let mut removed = 0usize;
    while offset < bytes.len() {
        let Some(relative_end) = bytes[offset..].iter().position(|byte| *byte == b'\n') else {
            let mut line_end = bytes.len();
            if line_end > offset && bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            return bytes.get(offset..line_end) == Some(begin);
        };
        let end = offset.saturating_add(relative_end);
        let mut line_end = end;
        if line_end > offset && bytes[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        let line = bytes.get(offset..line_end).unwrap_or_default();
        if line == begin {
            return true;
        }
        if !line.iter().all(u8::is_ascii_whitespace) {
            return false;
        }
        removed = removed
            .checked_add(line.len())
            .and_then(|value| value.checked_add(1))
            .unwrap_or(usize::MAX);
        if removed > ARMOR_MAX_WHITESPACE {
            return false;
        }
        offset = end.saturating_add(1);
    }
    false
}

/// Computes the largest binary age file permitted by the configured limits.
pub(crate) fn maximum_binary_bytes(options: AgeReadOptions) -> usize {
    if options.max_payload_bytes == usize::MAX {
        return usize::MAX;
    }

    let payload = options.max_payload_bytes;
    let chunks = if payload == 0 {
        1usize
    } else {
        payload / STREAM_CHUNK_SIZE + usize::from(!payload.is_multiple_of(STREAM_CHUNK_SIZE))
    };
    let stream_size = STREAM_NONCE_SIZE
        .checked_add(payload)
        .and_then(|value| {
            chunks
                .checked_mul(STREAM_TAG_LENGTH)
                .and_then(|tags| value.checked_add(tags))
        })
        .unwrap_or(usize::MAX);
    options.max_header_bytes.saturating_add(stream_size)
}

/// Computes the maximum accepted armor character count.
///
/// The calculation includes the complete binary STREAM bound, armor framing,
/// bounded leading and trailing whitespace, and the possible extra carriage
/// return in CRLF line endings.
#[must_use]
pub fn maximum_armored_characters(options: AgeReadOptions) -> usize {
    let binary = maximum_binary_bytes(options);
    if binary == usize::MAX {
        return usize::MAX;
    }

    let binary = binary as u128;
    let encoded = (binary.saturating_add(2) / 3).saturating_mul(4);
    let lines = encoded.saturating_add(ARMOR_LINE_LENGTH as u128 - 1) / ARMOR_LINE_LENGTH as u128;
    let framing = AgeArmor::BEGIN.len() as u128
        + AgeArmor::END.len() as u128
        + 2 // LF after each marker.
        + 2 // CR in CRLF marker endings.
        + 2 * lines // LF and CR in body line endings.
        + 4 * ARMOR_MAX_WHITESPACE as u128; // bounded surrounding whitespace.
    let total = encoded.saturating_add(framing);
    usize::try_from(total).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::{AgeArmor, starts_with_begin_marker};

    #[test]
    fn armor_round_trips() {
        let binary = b"age-encryption.org/v1\nsome binary\0data";
        let armored = AgeArmor::encode(binary);
        assert_eq!(AgeArmor::decode(&armored).expect("decode"), binary);
    }

    #[test]
    fn armor_accepts_empty_body_and_bounded_surrounding_whitespace() {
        let armored = format!(" \t\r\n{}\r\n{}\r\n \t", AgeArmor::BEGIN, AgeArmor::END);
        assert_eq!(
            AgeArmor::decode(&armored).expect("decode"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn armor_accepts_crlf_and_full_final_lines() {
        let binary = vec![0x5a; 48];
        let armored = AgeArmor::encode(&binary).replace('\n', "\r\n");
        assert_eq!(AgeArmor::decode(&armored).expect("decode"), binary);
    }

    #[test]
    fn armor_whitespace_is_bounded_at_1024_bytes() {
        let leading = format!("{}\n{}\n", " ".repeat(1023), AgeArmor::BEGIN);
        let armored = format!("{leading}{}\n", AgeArmor::END);
        assert!(AgeArmor::decode(&armored).is_ok());

        let too_much = format!("{}\n{}\n", " ".repeat(1024), AgeArmor::BEGIN);
        let armored = format!("{too_much}{}\n", AgeArmor::END);
        assert!(AgeArmor::decode(&armored).is_err());
    }

    #[test]
    fn armor_requires_canonical_padded_base64() {
        let unpadded = format!("{}\nYQ\n{}\n", AgeArmor::BEGIN, AgeArmor::END);
        assert!(AgeArmor::decode(&unpadded).is_err());
        let noncanonical = format!("{}\nYR==\n{}\n", AgeArmor::BEGIN, AgeArmor::END);
        assert!(AgeArmor::decode(&noncanonical).is_err());
        assert_eq!(STANDARD.decode("YQ==").expect("base64"), b"a");
    }

    #[test]
    fn armor_counts_crlf_bytes_in_trailing_whitespace() {
        let accepted = format!(
            "{}\r\n{}\r\n{}\r\n",
            AgeArmor::BEGIN,
            AgeArmor::END,
            " ".repeat(1021)
        );
        assert!(AgeArmor::decode(&accepted).is_ok());
        let rejected = format!(
            "{}\r\n{}\r\n{}\r\n",
            AgeArmor::BEGIN,
            AgeArmor::END,
            " ".repeat(1022)
        );
        assert!(AgeArmor::decode(&rejected).is_err());
    }

    #[test]
    fn auto_detection_accepts_bounded_leading_whitespace() {
        let armored = format!(" \n{}\n", AgeArmor::BEGIN);
        assert!(starts_with_begin_marker(armored.as_bytes()));
    }

    #[test]
    fn rejects_trailing_data() {
        let armored = format!("{}junk", AgeArmor::encode(b"payload"));
        assert!(AgeArmor::decode(&armored).is_err());
    }
}
