//! RFC 4251 section 5 primitive wire values.
//!
//! SSH integers are encoded in network byte order.  Strings are length-prefixed
//! byte sequences, while name-lists are length-prefixed comma-separated ASCII
//! names.  The reader never allocates for a primitive string or mpint and
//! enforces a default one-megabyte string limit before taking a slice.

use std::str;

pub use crate::error::Error;

/// The default maximum byte length accepted for a string, mpint, or name-list.
pub const DEFAULT_STRING_LIMIT: usize = 1_048_576;

/// A byte-oriented value accepted by the SSH string encoder.
///
/// The trait lets callers pass either binary byte slices or UTF-8 text without
/// making the wire string type itself impose a text restriction.
pub trait StringBytes {
    /// Returns the bytes to place in an SSH string.
    fn as_ssh_bytes(&self) -> &[u8];
}

impl StringBytes for [u8] {
    fn as_ssh_bytes(&self) -> &[u8] {
        self
    }
}

impl StringBytes for str {
    fn as_ssh_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl StringBytes for String {
    fn as_ssh_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl StringBytes for Vec<u8> {
    fn as_ssh_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<T> StringBytes for &T
where
    T: StringBytes + ?Sized,
{
    fn as_ssh_bytes(&self) -> &[u8] {
        (*self).as_ssh_bytes()
    }
}

impl<const N: usize> StringBytes for [u8; N] {
    fn as_ssh_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A value that can be represented as an SSH two's-complement mpint.
///
/// Byte-slice implementations interpret their input as a signed two's-
/// complement value and normalize it to the shortest representation.  The
/// integer implementations are conveniences for values that fit in a Rust
/// primitive integer.
pub trait IntoMpint {
    /// Converts the value to a big-endian two's-complement byte sequence.
    fn into_mpint_bytes(self) -> Vec<u8>;
}

impl IntoMpint for &[u8] {
    fn into_mpint_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl IntoMpint for Vec<u8> {
    fn into_mpint_bytes(self) -> Vec<u8> {
        self
    }
}

impl IntoMpint for &Vec<u8> {
    fn into_mpint_bytes(self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl<const N: usize> IntoMpint for &[u8; N] {
    fn into_mpint_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl<const N: usize> IntoMpint for [u8; N] {
    fn into_mpint_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

macro_rules! impl_signed_mpint {
    ($($type:ty),+ $(,)?) => {
        $(
            impl IntoMpint for $type {
                fn into_mpint_bytes(self) -> Vec<u8> {
                    self.to_be_bytes().to_vec()
                }
            }
        )+
    };
}

macro_rules! impl_unsigned_mpint {
    ($($type:ty),+ $(,)?) => {
        $(
            impl IntoMpint for $type {
                fn into_mpint_bytes(self) -> Vec<u8> {
                    let bytes = self.to_be_bytes();
                    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
                        let mut value = Vec::with_capacity(bytes.len() + 1);
                        value.push(0);
                        value.extend_from_slice(&bytes);
                        value
                    } else {
                        bytes.to_vec()
                    }
                }
            }
        )+
    };
}

impl_signed_mpint!(i8, i16, i32, i64, i128, isize);
impl_unsigned_mpint!(u8, u16, u32, u64, u128, usize);

/// A forward-only reader for RFC 4251 wire values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `input` without copying it.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    /// Returns whether no bytes remain to be read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the unread portion of the input.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.input.get(self.position..).unwrap_or_default()
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when no byte remains.
    pub fn read_byte(&mut self) -> Result<u8, Error> {
        Ok(*self.take(1)?.first().ok_or(Error::Truncated)?)
    }

    /// Reads one byte using the short name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_byte`].
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        self.read_byte()
    }

    /// Reads a strict SSH boolean.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when no byte remains and
    /// [`Error::InvalidBoolean`] for values other than `0` and `1`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBoolean),
        }
    }

    /// Reads a strict SSH boolean; this is an alias for [`Self::read_boolean`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_boolean`].
    pub fn read_bool(&mut self) -> Result<bool, Error> {
        self.read_boolean()
    }

    /// Reads a network-order unsigned 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than four bytes remain.
    pub fn read_uint32(&mut self) -> Result<u32, Error> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads a network-order unsigned 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than eight bytes remain.
    pub fn read_uint64(&mut self) -> Result<u64, Error> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads a network-order unsigned 32-bit integer using the short name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_uint32`].
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        self.read_uint32()
    }

    /// Reads a network-order unsigned 64-bit integer using the short name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_uint64`].
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        self.read_uint64()
    }

    /// Reads a length-prefixed SSH string using the default one-megabyte cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] for an incomplete length or body and
    /// [`Error::LimitExceeded`] when the declared length exceeds the cap.
    pub fn read_string(&mut self) -> Result<&'a [u8], Error> {
        self.read_string_with_limit(DEFAULT_STRING_LIMIT)
    }

    /// Reads a length-prefixed SSH string with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] for an incomplete length or body and
    /// [`Error::LimitExceeded`] when the declared length exceeds `limit`.
    pub fn read_string_with_limit(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let length = self.read_uint32()?;
        let length = usize::try_from(length).map_err(|_| Error::LimitExceeded)?;
        if length > limit {
            return Err(Error::LimitExceeded);
        }
        self.take(length)
    }

    /// Reads a length-prefixed SSH string and returns an owned copy.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_string`].
    pub fn read_string_bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.read_string()?.to_vec())
    }

    /// Reads a length-prefixed SSH string with a cap and returns an owned copy.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_string_with_limit`].
    pub fn read_string_bytes_with_limit(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        Ok(self.read_string_with_limit(limit)?.to_vec())
    }

    /// Reads a canonical RFC 4251 mpint as its two's-complement bytes.
    ///
    /// The returned slice is borrowed from the reader input and includes the
    /// sign byte when the positive value would otherwise have its high bit set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] for an incomplete value,
    /// [`Error::LimitExceeded`] for a value over the default cap, and
    /// [`Error::InvalidMpint`] for a non-minimal representation.
    pub fn read_mpint(&mut self) -> Result<&'a [u8], Error> {
        self.read_mpint_with_limit(DEFAULT_STRING_LIMIT)
    }

    /// Reads a canonical mpint with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
    /// [`Error::InvalidMpint`] for incomplete, oversized, or non-canonical data.
    pub fn read_mpint_with_limit(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let value = self.read_string_with_limit(limit)?;
        validate_mpint(value)?;
        Ok(value)
    }

    /// Reads a canonical mpint and returns an owned copy.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_mpint`].
    pub fn read_mpint_bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.read_mpint()?.to_vec())
    }

    /// Reads a canonical mpint and returns a positive sign byte without the
    /// redundant positive sign-extension byte.
    ///
    /// Negative values retain their complete two's-complement bytes.  Zero is
    /// returned as the single byte `0x00`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_mpint`].
    pub fn read_mpint_magnitude(&mut self) -> Result<&'a [u8], Error> {
        let value = self.read_mpint()?;
        match value.first() {
            Some(0) if value.len() > 1 => Ok(value.get(1..).ok_or(Error::InvalidMpint)?),
            _ => Ok(value),
        }
    }

    /// Reads a name-list using the default one-megabyte cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
    /// [`Error::InvalidName`] for malformed wire data.
    pub fn read_name_list(&mut self) -> Result<Vec<String>, Error> {
        Ok(self
            .read_name_list_borrowed()?
            .into_iter()
            .map(str::to_owned)
            .collect())
    }

    /// Reads a name-list with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
    /// [`Error::InvalidName`] for malformed wire data.
    pub fn read_name_list_with_limit(&mut self, limit: usize) -> Result<Vec<String>, Error> {
        Ok(self
            .read_name_list_borrowed_with_limit(limit)?
            .into_iter()
            .map(str::to_owned)
            .collect())
    }

    /// Reads a name-list as borrowed ASCII strings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
    /// [`Error::InvalidName`] for malformed wire data.
    pub fn read_name_list_borrowed(&mut self) -> Result<Vec<&'a str>, Error> {
        self.read_name_list_borrowed_with_limit(DEFAULT_STRING_LIMIT)
    }

    /// Reads a name-list as borrowed ASCII strings with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
    /// [`Error::InvalidName`] for malformed wire data.
    pub fn read_name_list_borrowed_with_limit(
        &mut self,
        limit: usize,
    ) -> Result<Vec<&'a str>, Error> {
        let encoded = self.read_string_with_limit(limit)?;
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        encoded
            .split(|byte| *byte == b',')
            .map(decode_name)
            .collect()
    }

    /// Returns all unread bytes without consuming them.
    #[must_use]
    pub fn remaining_bytes(&self) -> &'a [u8] {
        self.remaining()
    }

    /// Returns an error unless the reader has consumed its entire input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when unread bytes remain.  The name is
    /// retained for callers that use this method as a completeness check.
    pub fn ensure_finished(&self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Truncated)?;
        let bytes = self.input.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
}

/// A growable writer for RFC 4251 wire values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Creates an empty writer with reserved capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Appends one byte.
    pub fn write_byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends already-framed bytes without adding another length prefix.
    pub fn write_raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// Appends one byte using the short name.
    pub fn write_u8(&mut self, value: u8) {
        self.write_byte(value);
    }

    /// Appends a boolean using the strict SSH representation.
    pub fn write_boolean(&mut self, value: bool) {
        self.write_byte(u8::from(value));
    }

    /// Appends a boolean using the short method name.
    pub fn write_bool(&mut self, value: bool) {
        self.write_boolean(value);
    }

    /// Appends a network-order unsigned 32-bit integer.
    pub fn write_uint32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a network-order unsigned 64-bit integer.
    pub fn write_uint64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a network-order unsigned 32-bit integer using the short name.
    pub fn write_u32(&mut self, value: u32) {
        self.write_uint32(value);
    }

    /// Appends a network-order unsigned 64-bit integer using the short name.
    pub fn write_u64(&mut self, value: u64) {
        self.write_uint64(value);
    }

    /// Appends a length-prefixed SSH string using the default cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the value is too long to encode.
    pub fn write_string<B>(&mut self, value: &B) -> Result<(), Error>
    where
        B: StringBytes + ?Sized,
    {
        self.write_string_with_limit(value, DEFAULT_STRING_LIMIT)
    }

    /// Appends a length-prefixed SSH string with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the value exceeds `limit` or its
    /// length cannot be represented by an SSH `uint32`.
    pub fn write_string_with_limit<B>(&mut self, value: &B, limit: usize) -> Result<(), Error>
    where
        B: StringBytes + ?Sized,
    {
        let bytes = value.as_ssh_bytes();
        if bytes.len() > limit {
            return Err(Error::LimitExceeded);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| Error::LimitExceeded)?;
        self.write_uint32(length);
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends a length-prefixed SSH string containing UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::write_string`].
    pub fn write_utf8_string(&mut self, value: &str) -> Result<(), Error> {
        self.write_string(&value)
    }

    /// Appends a canonical RFC 4251 mpint.
    ///
    /// Byte inputs are interpreted as signed two's-complement values and
    /// normalized to their shortest representation.  Integer inputs are
    /// supported through [`IntoMpint`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the canonical representation is
    /// larger than the default string cap.
    pub fn write_mpint<M>(&mut self, value: M) -> Result<(), Error>
    where
        M: IntoMpint,
    {
        self.write_mpint_with_limit(value, DEFAULT_STRING_LIMIT)
    }

    /// Appends a canonical mpint with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the canonical representation is
    /// larger than `limit` or cannot be represented by an SSH `uint32`.
    pub fn write_mpint_with_limit<M>(&mut self, value: M, limit: usize) -> Result<(), Error>
    where
        M: IntoMpint,
    {
        let input = value.into_mpint_bytes();
        if input.len() > limit {
            return Err(Error::LimitExceeded);
        }
        let value = canonical_mpint(&input);
        self.write_string_with_limit(&value, limit)
    }

    /// Appends a comma-separated name-list using the default cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidName`] for an empty, non-ASCII, comma-containing,
    /// or whitespace-containing name and [`Error::LimitExceeded`] for an
    /// oversized list.
    pub fn write_name_list<S>(&mut self, names: impl IntoIterator<Item = S>) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        self.write_name_list_with_limit(names, DEFAULT_STRING_LIMIT)
    }

    /// Appends a comma-separated name-list with a caller-supplied cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidName`] for an invalid name and
    /// [`Error::LimitExceeded`] for an oversized list.
    pub fn write_name_list_with_limit<S>(
        &mut self,
        names: impl IntoIterator<Item = S>,
        limit: usize,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        let names: Vec<S> = names.into_iter().collect();
        let mut length = 0_usize;
        for name in &names {
            let name = name.as_ref();
            validate_name(name.as_bytes())?;
            length = length.checked_add(name.len()).ok_or(Error::LimitExceeded)?;
            if length > limit {
                return Err(Error::LimitExceeded);
            }
        }
        if names.len() > 1 {
            length = length
                .checked_add(names.len().saturating_sub(1))
                .ok_or(Error::LimitExceeded)?;
            if length > limit {
                return Err(Error::LimitExceeded);
            }
        }
        let length = u32::try_from(length).map_err(|_| Error::LimitExceeded)?;
        self.write_uint32(length);
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                self.write_byte(b',');
            }
            self.bytes.extend_from_slice(name.as_ref().as_bytes());
        }
        Ok(())
    }

    /// Returns the encoded bytes without consuming the writer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the encoded bytes without consuming the writer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /// Returns the number of encoded bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the writer and returns its encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for Writer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Writer> for Vec<u8> {
    fn from(writer: Writer) -> Self {
        writer.into_bytes()
    }
}

/// Encodes one byte as a one-byte vector.
#[must_use]
pub fn encode_byte(value: u8) -> Vec<u8> {
    vec![value]
}

/// Encodes a strict SSH boolean as a one-byte vector.
#[must_use]
pub fn encode_boolean(value: bool) -> Vec<u8> {
    vec![u8::from(value)]
}

/// Decodes a strict SSH boolean from the first input byte.
///
/// # Errors
///
/// Returns [`Error::Truncated`] for empty input and [`Error::InvalidBoolean`]
/// for any value other than `0` or `1`.
pub fn decode_boolean(input: &[u8]) -> Result<bool, Error> {
    Reader::new(input).read_boolean()
}

/// Encodes a network-order unsigned 32-bit integer.
#[must_use]
pub fn encode_uint32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decodes a network-order unsigned 32-bit integer from the first four bytes.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than four bytes are available.
pub fn decode_uint32(input: &[u8]) -> Result<u32, Error> {
    Reader::new(input).read_uint32()
}

/// Encodes a network-order unsigned 64-bit integer.
#[must_use]
pub fn encode_uint64(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decodes a network-order unsigned 64-bit integer from the first eight bytes.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than eight bytes are available.
pub fn decode_uint64(input: &[u8]) -> Result<u64, Error> {
    Reader::new(input).read_uint64()
}

/// Encodes a length-prefixed SSH string using the default cap.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] when the value is too long to encode.
pub fn encode_string<B>(value: &B) -> Result<Vec<u8>, Error>
where
    B: StringBytes + ?Sized,
{
    let mut writer = Writer::new();
    writer.write_string(value)?;
    Ok(writer.into_bytes())
}

/// Decodes a length-prefixed SSH string and returns an owned copy.
///
/// # Errors
///
/// Returns [`Error::Truncated`] or [`Error::LimitExceeded`] for malformed or
/// oversized string data.
pub fn decode_string(input: &[u8]) -> Result<Vec<u8>, Error> {
    Reader::new(input).read_string_bytes()
}

/// Encodes a canonical RFC 4251 mpint using the default cap.
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] when the canonical value is too long.
pub fn encode_mpint<M>(value: M) -> Result<Vec<u8>, Error>
where
    M: IntoMpint,
{
    let mut writer = Writer::new();
    writer.write_mpint(value)?;
    Ok(writer.into_bytes())
}

/// Decodes a canonical mpint and returns an owned copy.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
/// [`Error::InvalidMpint`] for malformed mpint data.
pub fn decode_mpint(input: &[u8]) -> Result<Vec<u8>, Error> {
    Reader::new(input).read_mpint_bytes()
}

/// Encodes a comma-separated name-list using the default cap.
///
/// # Errors
///
/// Returns [`Error::InvalidName`] or [`Error::LimitExceeded`] for invalid input.
pub fn encode_name_list<S>(names: impl IntoIterator<Item = S>) -> Result<Vec<u8>, Error>
where
    S: AsRef<str>,
{
    let mut writer = Writer::new();
    writer.write_name_list(names)?;
    Ok(writer.into_bytes())
}

/// Decodes a comma-separated name-list using the default cap.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::LimitExceeded`], or
/// [`Error::InvalidName`] for malformed name-list data.
pub fn decode_name_list(input: &[u8]) -> Result<Vec<String>, Error> {
    Reader::new(input).read_name_list()
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

fn validate_mpint(value: &[u8]) -> Result<(), Error> {
    let Some(first) = value.first().copied() else {
        return Ok(());
    };
    let Some(second) = value.get(1).copied() else {
        return Ok(());
    };
    if (first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) {
        return Err(Error::InvalidMpint);
    }
    Ok(())
}

fn validate_name(value: &[u8]) -> Result<(), Error> {
    if value.is_empty()
        || value
            .iter()
            .any(|byte| !byte.is_ascii() || *byte == b',' || byte.is_ascii_whitespace())
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn decode_name(value: &[u8]) -> Result<&str, Error> {
    validate_name(value)?;
    str::from_utf8(value).map_err(|_| Error::InvalidName)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_STRING_LIMIT, Error, IntoMpint, Reader, Writer, decode_name_list, encode_mpint,
        encode_name_list, encode_string,
    };

    #[test]
    fn round_trips_primitive_values() -> Result<(), Error> {
        let mut writer = Writer::new();
        writer.write_byte(0x7f);
        writer.write_boolean(true);
        writer.write_uint32(0x0102_0304);
        writer.write_uint64(0x0102_0304_0506_0708);
        writer.write_string(b"binary\0bytes")?;

        let bytes = writer.into_bytes();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_byte()?, 0x7f);
        assert!(reader.read_boolean()?);
        assert_eq!(reader.read_uint32()?, 0x0102_0304);
        assert_eq!(reader.read_uint64()?, 0x0102_0304_0506_0708);
        assert_eq!(reader.read_string()?, b"binary\0bytes");
        reader.ensure_finished()
    }

    #[test]
    fn rejects_non_strict_booleans() {
        let mut reader = Reader::new(&[2]);
        assert_eq!(reader.read_boolean(), Err(Error::InvalidBoolean));
    }

    #[test]
    fn truncates_primitives_and_sized_values() {
        let mut reader = Reader::new(&[0, 0, 0]);
        assert_eq!(reader.read_uint32(), Err(Error::Truncated));

        let mut reader = Reader::new(&[0, 0, 0, 4, 1, 2]);
        assert_eq!(reader.read_string(), Err(Error::Truncated));
    }

    #[test]
    fn enforces_string_limits_before_taking_a_body() -> Result<(), Error> {
        let mut reader = Reader::new(&[0, 0, 0, 4, 1, 2]);
        assert_eq!(reader.read_string_with_limit(3), Err(Error::LimitExceeded));

        let too_long = (DEFAULT_STRING_LIMIT as u64) + 1;
        let length = u32::try_from(too_long).map_err(|_| Error::LimitExceeded)?;
        let mut input = Vec::from(length.to_be_bytes());
        input.push(0);
        assert_eq!(Reader::new(&input).read_string(), Err(Error::LimitExceeded));
        Ok(())
    }

    #[test]
    fn round_trips_name_lists_and_empty_lists() -> Result<(), Error> {
        let encoded = encode_name_list(["ssh-ed25519", "rsa-sha2-256"])?;
        assert_eq!(decode_name_list(&encoded)?, ["ssh-ed25519", "rsa-sha2-256"]);
        assert_eq!(encode_name_list(Vec::<String>::new())?, [0, 0, 0, 0]);
        assert_eq!(decode_name_list(&[0, 0, 0, 0])?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn rejects_invalid_name_list_members() {
        for encoded in [
            vec![0, 0, 0, 2, b'a', b','],
            vec![0, 0, 0, 3, b'a', b' ', b'b'],
            vec![0, 0, 0, 1, 0x80],
        ] {
            assert_eq!(decode_name_list(&encoded), Err(Error::InvalidName));
        }
        let mut writer = Writer::new();
        assert_eq!(writer.write_name_list([""]), Err(Error::InvalidName));
    }

    #[test]
    fn encodes_canonical_signed_mpints() -> Result<(), Error> {
        let cases: [(i128, &[u8]); 7] = [
            (0, &[0]),
            (1, &[1]),
            (127, &[127]),
            (128, &[0, 128]),
            (-1, &[255]),
            (-128, &[128]),
            (-129, &[255, 127]),
        ];
        for (value, expected) in cases {
            let encoded = encode_mpint(value)?;
            let mut reader = Reader::new(&encoded);
            assert_eq!(reader.read_mpint()?, expected);
        }
        Ok(())
    }

    #[test]
    fn normalizes_nonminimal_mpints_when_encoding() -> Result<(), Error> {
        let encoded = encode_mpint([0, 0, 1].as_slice())?;
        assert_eq!(encoded, [0, 0, 0, 1, 1]);
        let encoded = encode_mpint([255, 255, 127].as_slice())?;
        assert_eq!(encoded, [0, 0, 0, 2, 255, 127]);
        Ok(())
    }

    #[test]
    fn accepts_rfc_zero_and_rejects_nonminimal_mpints() -> Result<(), Error> {
        assert_eq!(Reader::new(&[0, 0, 0, 0]).read_mpint()?, []);
        for encoded in [vec![0, 0, 0, 2, 0, 1], vec![0, 0, 0, 2, 255, 128]] {
            assert_eq!(Reader::new(&encoded).read_mpint(), Err(Error::InvalidMpint));
        }
        Ok(())
    }

    #[test]
    fn limits_mpints_to_the_default_string_cap() -> Result<(), Error> {
        let length = u32::try_from(DEFAULT_STRING_LIMIT + 1).map_err(|_| Error::LimitExceeded)?;
        let input = length.to_be_bytes().to_vec();
        assert_eq!(Reader::new(&input).read_mpint(), Err(Error::LimitExceeded));
        Ok(())
    }

    #[test]
    fn accepts_binary_strings_and_text() -> Result<(), Error> {
        let mut writer = Writer::new();
        writer.write_string("hello")?;
        writer.write_string(&[0_u8, 255][..])?;
        assert_eq!(
            writer.as_slice(),
            [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0, 0, 0, 2, 0, 255]
        );
        assert_eq!(encode_string("text")?, [0, 0, 0, 4, b't', b'e', b'x', b't']);
        Ok(())
    }

    #[test]
    fn custom_integer_types_are_mpint_inputs() -> Result<(), Error> {
        let value: u8 = 128;
        let mut writer = Writer::new();
        writer.write_mpint(value)?;
        assert_eq!(writer.as_slice(), [0, 0, 0, 2, 0, 128]);
        let value: u8 = 255;
        writer.write_mpint(value)?;
        assert_eq!(writer.as_slice(), [0, 0, 0, 2, 0, 128, 0, 0, 0, 2, 0, 255]);
        let value: i8 = -1;
        writer.write_mpint(value)?;
        assert_eq!(
            writer.as_slice(),
            [0, 0, 0, 2, 0, 128, 0, 0, 0, 2, 0, 255, 0, 0, 0, 1, 255]
        );
        let _: &[u8] = [1_u8].as_slice().into_mpint_bytes().as_slice();
        Ok(())
    }
}
