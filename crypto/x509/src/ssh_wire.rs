//! The RFC 4251 primitives used by OpenSSH certificate parsing.
//!
//! This is the small reader and writer the certificate module needs. The SSH
//! crate keeps the full packet codec.

use std::fmt;

/// A wire-format failure that contains no certificate bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The input ended before a complete value could be read.
    Truncated,
    /// A length exceeded the one-megabyte safety cap.
    LimitExceeded,
    /// An mpint was empty of its required form or was not minimal.
    InvalidMpint,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "SSH input is truncated",
            Self::LimitExceeded => "SSH value exceeds the configured limit",
            Self::InvalidMpint => "SSH mpint is invalid",
        })
    }
}

impl std::error::Error for WireError {}

const STRING_LIMIT: usize = 1_048_576;

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.position >= self.input.len()
    }

    pub(crate) fn read_uint32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(crate) fn read_uint64(&mut self) -> Result<u64, WireError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn read_string(&mut self) -> Result<&'a [u8], WireError> {
        let length = self.read_uint32()?;
        let length = usize::try_from(length).map_err(|_| WireError::LimitExceeded)?;
        if length > STRING_LIMIT {
            return Err(WireError::LimitExceeded);
        }
        self.take(length)
    }

    pub(crate) fn read_string_bytes(&mut self) -> Result<Vec<u8>, WireError> {
        Ok(self.read_string()?.to_vec())
    }

    pub(crate) fn read_mpint(&mut self) -> Result<&'a [u8], WireError> {
        let value = self.read_string()?;
        validate_mpint(value)?;
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WireError::Truncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(WireError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
}

pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(crate) const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn write_string(&mut self, value: impl AsRef<[u8]>) -> Result<(), WireError> {
        let bytes = value.as_ref();
        if bytes.len() > STRING_LIMIT {
            return Err(WireError::LimitExceeded);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| WireError::LimitExceeded)?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn write_mpint(&mut self, value: &[u8]) -> Result<(), WireError> {
        if value.len() > STRING_LIMIT {
            return Err(WireError::LimitExceeded);
        }
        self.write_string(canonical_mpint(value))
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn canonical_mpint(value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        return vec![0];
    }

    let mut start = 0;
    if value[0] & 0x80 == 0 {
        while start + 1 < value.len() && value[start] == 0 && value[start + 1] & 0x80 == 0 {
            start += 1;
        }
    } else {
        while start + 1 < value.len() && value[start] == 0xff && value[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }

    let mut canonical = match value.get(start..) {
        Some(bytes) => bytes.to_vec(),
        None => vec![0],
    };
    if canonical.is_empty() {
        canonical.push(0);
    }
    canonical
}

fn validate_mpint(value: &[u8]) -> Result<(), WireError> {
    let Some(first) = value.first().copied() else {
        return Ok(());
    };
    let Some(second) = value.get(1).copied() else {
        return Ok(());
    };
    if (first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) {
        return Err(WireError::InvalidMpint);
    }
    Ok(())
}
