//! The small Bech32 codec used by age key encodings.

use crate::error::{AgeError, Result};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Encodes bytes with a lower-case Bech32 human-readable part.
///
/// # Errors
///
/// Returns [`AgeError::InvalidFormat`] when `hrp` is not a single-line ASCII
/// string suitable for Bech32.
pub fn encode(hrp: &str, bytes: &[u8]) -> Result<String> {
    let lower = hrp.to_ascii_lowercase();
    if lower.is_empty() || !lower.bytes().all(|value| (33..=126).contains(&value)) {
        return Err(AgeError::InvalidFormat(
            "invalid Bech32 human-readable part",
        ));
    }

    let data = convert_bits(bytes, 8, 5, true)?;
    let checksum = create_checksum(&lower, &data);
    let mut result = String::new();
    result.push_str(&lower);
    result.push('1');
    for value in data {
        let index = usize::from(value);
        let character = CHARSET
            .get(index)
            .copied()
            .ok_or(AgeError::InvalidFormat("invalid Bech32 data value"))?;
        result.push(char::from(character));
    }
    for value in checksum {
        let index = usize::from(value);
        let character = CHARSET
            .get(index)
            .copied()
            .ok_or(AgeError::InvalidFormat("invalid Bech32 checksum value"))?;
        result.push(char::from(character));
    }
    Ok(result)
}

/// Decodes a Bech32 string into its original-case HRP and payload bytes.
///
/// Both all-lower-case and all-upper-case encodings are accepted. The HRP's
/// case is preserved so callers can enforce age's exact human-readable parts.
/// Mixed case, whitespace, malformed padding, and checksum failures are
/// rejected.
///
/// # Errors
///
/// Returns [`AgeError::InvalidFormat`] for any malformed Bech32 input.
pub fn decode(value: &str) -> Result<(String, Vec<u8>)> {
    if value.is_empty() {
        return Err(AgeError::InvalidFormat("empty Bech32 value"));
    }

    let mut has_lower = false;
    let mut has_upper = false;
    for character in value.chars() {
        if character.is_whitespace() || !character.is_ascii() {
            return Err(AgeError::InvalidFormat("non-ASCII Bech32 value"));
        }
        has_lower |= character.is_ascii_lowercase();
        has_upper |= character.is_ascii_uppercase();
    }
    if has_lower && has_upper {
        return Err(AgeError::InvalidFormat("Bech32 value mixes casing"));
    }

    let lower = value.to_ascii_lowercase();
    let separator = lower
        .rfind('1')
        .ok_or(AgeError::InvalidFormat("missing Bech32 separator"))?;
    if separator < 1 || separator + 7 > lower.len() {
        return Err(AgeError::InvalidFormat("invalid Bech32 separator"));
    }

    let checksum_hrp = lower
        .get(..separator)
        .ok_or(AgeError::InvalidFormat("invalid Bech32 HRP"))?
        .to_owned();
    if !checksum_hrp
        .bytes()
        .all(|character| (33..=126).contains(&character))
    {
        return Err(AgeError::InvalidFormat("invalid Bech32 HRP"));
    }
    let original_hrp = value
        .get(..separator)
        .ok_or(AgeError::InvalidFormat("invalid Bech32 HRP"))?
        .to_owned();
    let data_length = lower.len() - separator - 1;
    let mut data = Vec::with_capacity(data_length);
    for character in lower
        .get(separator + 1..)
        .ok_or(AgeError::InvalidFormat("invalid Bech32 data"))?
        .bytes()
    {
        let value =
            decode_charset(character).ok_or(AgeError::InvalidFormat("invalid Bech32 character"))?;
        data.push(value);
    }

    if !verify_checksum(&checksum_hrp, &data) {
        return Err(AgeError::InvalidFormat("invalid Bech32 checksum"));
    }
    let payload = convert_bits(
        data.get(..data_length.saturating_sub(6))
            .ok_or(AgeError::InvalidFormat("missing Bech32 checksum"))?,
        5,
        8,
        false,
    )?;
    Ok((original_hrp, payload))
}

fn decode_charset(value: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|character| *character == value)
        .and_then(|index| u8::try_from(index).ok())
}

fn convert_bits(data: &[u8], from_bits: u8, to_bits: u8, pad: bool) -> Result<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let mut result = Vec::new();
    let max_value = (1u32 << to_bits) - 1;
    let source_mask = (1u32 << from_bits) - 1;

    for value in data {
        let source = u32::from(*value);
        if source > source_mask {
            return Err(AgeError::InvalidFormat("invalid Bech32 data value"));
        }
        accumulator = (accumulator << from_bits) | source;
        bits = bits
            .checked_add(from_bits)
            .ok_or(AgeError::InvalidFormat("Bech32 data is too long"))?;
        while bits >= to_bits {
            let shift = bits - to_bits;
            let value = (accumulator >> shift) & max_value;
            result.push(
                u8::try_from(value)
                    .map_err(|_| AgeError::InvalidFormat("invalid Bech32 data value"))?,
            );
            bits -= to_bits;
            accumulator &= (1u32 << shift) - 1;
        }
    }

    if pad {
        if bits > 0 {
            let value = (accumulator << (to_bits - bits)) & max_value;
            result.push(
                u8::try_from(value)
                    .map_err(|_| AgeError::InvalidFormat("invalid Bech32 padding"))?,
            );
        }
    } else if bits >= from_bits || (accumulator << (to_bits - bits)) & max_value != 0 {
        return Err(AgeError::InvalidFormat("invalid Bech32 padding"));
    }
    Ok(result)
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut expanded = Vec::with_capacity(bytes.len() * 2 + 1);
    expanded.extend(bytes.iter().map(|value| value >> 5));
    expanded.push(0);
    expanded.extend(bytes.iter().map(|value| value & 31));
    expanded
}

fn polymod(hrp: &[u8], data: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1u32;
    for value in hrp.iter().copied().chain(data.iter().copied()) {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if ((top >> index) & 1) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    polymod(&hrp_expand(hrp), data) == 1
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = Vec::with_capacity(data.len() + 6);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let checksum = polymod(&hrp_expand(hrp), &values) ^ 1;
    let mut result = [0u8; 6];
    for (index, value) in result.iter_mut().enumerate() {
        let shift = 5 * (5 - index);
        *value = u8::try_from((checksum >> shift) & 31).unwrap_or(0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trips_and_preserves_hrp_case() {
        let bytes: Vec<u8> = (0..32).collect();
        let encoded = encode("AGE", &bytes).expect("encode");
        let (hrp, decoded) = decode(&encoded.to_ascii_uppercase()).expect("decode");
        assert!(encoded.starts_with("age1"));
        assert_eq!(hrp, "AGE");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn rejects_invalid_forms() {
        assert!(decode("").is_err());
        assert!(decode("Age1mixedcase").is_err());
        assert!(decode("age1invalid!").is_err());
    }
}
