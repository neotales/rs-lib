use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// A KeePass UUID represented by its exact 16 wire bytes.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KdbxUuid([u8; 16]);

impl KdbxUuid {
    /// The all-zero UUID.
    pub const ZERO: Self = Self([0; 16]);

    /// Creates a random UUID using operating-system entropy.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide entropy. This preserves
    /// the infallible model-constructor boundary; callers that must handle an
    /// unavailable entropy source can construct a value from explicit bytes
    /// with [`Self::from_bytes`].
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("operating-system entropy is unavailable");
        Self(bytes)
    }

    /// Creates a UUID from exactly 16 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns whether this is the all-zero UUID.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }

    /// Encodes the UUID using KeePass XML's standard Base64 representation.
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Decodes a KeePass standard-Base64 UUID.
    ///
    /// # Errors
    ///
    /// Returns a malformed-input error when the text is not exactly 16 decoded
    /// bytes.
    pub fn from_base64(value: &str) -> Result<Self, crate::KdbxError> {
        let bytes = STANDARD
            .decode(value)
            .map_err(|_| crate::KdbxError::malformed("invalid UUID Base64"))?;
        let bytes = <[u8; 16]>::try_from(bytes.as_slice())
            .map_err(|_| crate::KdbxError::malformed("UUID must decode to 16 bytes"))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for KdbxUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KdbxUuid(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl fmt::Display for KdbxUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_base64())
    }
}

/// KDBX 4.1 date value: seconds since 0001-01-01, as specified by KDBX.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct KdbxTimestamp(pub i64);

impl KdbxTimestamp {
    /// Converts the KDBX value to a Unix timestamp.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        // the 100-nanosecond tick count begin at 0001-01-01; Unix epoch is 62135596800
        // seconds later.
        self.0 - 62_135_596_800
    }

    /// Creates a KDBX value from a Unix timestamp.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds + 62_135_596_800)
    }
}

/// A KeePass color, represented as optional 24-bit RGB.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KdbxColor {
    /// RGB components, or `None` for an empty color.
    pub rgb: Option<[u8; 3]>,
}

impl KdbxColor {
    /// Returns an empty color.
    #[must_use]
    pub const fn empty() -> Self {
        Self { rgb: None }
    }

    /// Parses KeePass `#RRGGBB` syntax.
    #[must_use]
    pub fn parse(value: &str) -> Result<Self, crate::KdbxError> {
        if value.is_empty() {
            return Ok(Self::empty());
        }
        let hex = value
            .strip_prefix('#')
            .ok_or_else(|| crate::KdbxError::malformed("color must be #RRGGBB"))?;
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(crate::KdbxError::malformed("color must be #RRGGBB"));
        }
        let red = u8::from_str_radix(&hex[0..2], 16).expect("validated hex");
        let green = u8::from_str_radix(&hex[2..4], 16).expect("validated hex");
        let blue = u8::from_str_radix(&hex[4..6], 16).expect("validated hex");
        Ok(Self {
            rgb: Some([red, green, blue]),
        })
    }
}

impl fmt::Display for KdbxColor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some([red, green, blue]) = self.rgb {
            write!(formatter, "#{red:02X}{green:02X}{blue:02X}")
        } else {
            formatter.write_str("")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KdbxColor, KdbxTimestamp, KdbxUuid};

    #[test]
    fn uuid_base64_round_trips() {
        let uuid = KdbxUuid::from_bytes([7; 16]);
        assert_eq!(KdbxUuid::from_base64(&uuid.to_base64()).unwrap(), uuid);
    }

    #[test]
    fn color_requires_six_hex_digits() {
        assert_eq!(KdbxColor::parse("").unwrap().rgb, None);
        assert_eq!(KdbxColor::parse("#00AAff").unwrap().to_string(), "#00AAFF");
        assert!(KdbxColor::parse("00AAff").is_err());
    }

    #[test]
    fn timestamp_converts_epoch() {
        assert_eq!(KdbxTimestamp::from_unix_seconds(0).unix_seconds(), 0);
    }
}
