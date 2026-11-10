//! RFC 8308 `SSH_MSG_EXT_INFO` encoding and extension parsing.
//!
//! This module handles the message wire format and the RFC 8308
//! `server-sig-algs` extension. It does not send the message or alter a
//! handshake's negotiated algorithms.

use std::collections::HashSet;

use neotales_ssh::{Error, MAX_PACKET_CONTENT, Reader, Writer, decode_name_list, encode_name_list};

/// The SSH message number for `SSH_MSG_EXT_INFO`.
pub const SSH_MSG_EXT_INFO: u8 = 7;

/// The extension name carrying the server's accepted public-key algorithms.
pub const SERVER_SIG_ALGS: &str = "server-sig-algs";

/// A descriptive alias for [`SERVER_SIG_ALGS`].
pub const EXTENSION_SERVER_SIG_ALGS: &str = SERVER_SIG_ALGS;

/// The RSA SHA-512 public-key algorithm name.
pub const RSA_SHA2_512: &str = "rsa-sha2-512";

/// The RSA SHA-256 public-key algorithm name.
pub const RSA_SHA2_256: &str = "rsa-sha2-256";

/// The legacy SHA-1 RSA public-key algorithm name.
pub const SSH_RSA: &str = "ssh-rsa";

const EXT_INFO_HEADER_SIZE: usize = 1 + 4;
const MIN_EXTENSION_PAIR_SIZE: usize = 4 + 1 + 4;

/// The largest extension count whose minimum valid wire form fits one packet.
///
/// Every extension needs two SSH string length prefixes, a non-empty
/// one-byte-or-longer name, and may have an empty value.
pub const MAX_EXT_INFO_EXTENSIONS: usize =
    (MAX_PACKET_CONTENT - EXT_INFO_HEADER_SIZE) / MIN_EXTENSION_PAIR_SIZE;

/// One name/value pair from an `SSH_MSG_EXT_INFO` message.
///
/// Unknown extensions retain their exact wire value. The recognized
/// `server-sig-algs` value is validated and decoded when the extension is
/// constructed, while [`Extension::value`] continues to return its original
/// encoded SSH name-list bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extension {
    name: String,
    value: Vec<u8>,
    server_sig_algs: Option<Vec<String>>,
}

impl Extension {
    /// Creates one extension from its wire name and raw value bytes.
    ///
    /// The name must be a non-empty RFC 4251 name. If it is
    /// [`SERVER_SIG_ALGS`], `value` must contain exactly one complete SSH
    /// name-list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidName`] for an invalid extension name or a
    /// malformed `server-sig-algs` name-list, and [`Error::Truncated`] or
    /// [`Error::LimitExceeded`] for an incomplete or oversized name-list.
    pub fn new(name: impl Into<String>, value: &[u8]) -> Result<Self, Error> {
        let name = name.into();
        validate_extension_name(&name)?;
        let server_sig_algs = if name == SERVER_SIG_ALGS {
            Some(decode_complete_name_list(value)?)
        } else {
            None
        };

        Ok(Self {
            name,
            value: value.to_vec(),
            server_sig_algs,
        })
    }

    /// Creates a `server-sig-algs` extension from ordered algorithm names.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Extension::new`].
    pub fn from_server_sig_algs<S, N>(names: S) -> Result<Self, Error>
    where
        S: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        let value = encode_name_list(names)?;
        Self::new(SERVER_SIG_ALGS, &value)
    }

    /// Returns the extension name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact encoded value bytes supplied by the peer.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the decoded `server-sig-algs` names in wire order.
    ///
    /// Unknown extensions return [`None`].
    #[must_use]
    pub fn server_sig_algs(&self) -> Option<&[String]> {
        self.server_sig_algs.as_deref()
    }
}

/// A complete RFC 8308 `SSH_MSG_EXT_INFO` message.
///
/// Extension order and unknown values are retained. Extension names must be
/// unique, and the optional `server-sig-algs` names are available in wire
/// order through [`ExtInfo::server_sig_algs`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtInfo {
    extensions: Vec<Extension>,
}

impl ExtInfo {
    /// Creates a message from an ordered collection of extensions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPacket`] when an extension name occurs more
    /// than once.
    pub fn new(extensions: Vec<Extension>) -> Result<Self, Error> {
        ensure_unique_names(&extensions)?;
        Ok(Self { extensions })
    }

    /// Returns all extensions in their original wire order.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Finds an extension by its exact name.
    #[must_use]
    pub fn extension(&self, name: &str) -> Option<&Extension> {
        self.extensions
            .iter()
            .find(|extension| extension.name == name)
    }

    /// Returns the decoded `server-sig-algs` names in wire order.
    #[must_use]
    pub fn server_sig_algs(&self) -> Option<&[String]> {
        self.extension(SERVER_SIG_ALGS)
            .and_then(Extension::server_sig_algs)
    }

    /// Selects the preferred RSA SHA-2 algorithm advertised by this message.
    ///
    /// This method ignores unknown extensions and never selects `ssh-rsa`.
    #[must_use]
    pub fn preferred_rsa_signature(&self) -> Option<&'static str> {
        preferred_rsa_signature(self.server_sig_algs()?)
    }

    /// Encodes this complete message, including its SSH message type byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the extension count or encoded
    /// message cannot fit within [`MAX_PACKET_CONTENT`], [`Error::InvalidName`]
    /// for an invalid extension name, and [`Error::InvalidPacket`] for a
    /// duplicate name.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let encoded_size = encoded_size(&self.extensions)?;
        let mut writer = Writer::with_capacity(encoded_size);
        writer.write_byte(SSH_MSG_EXT_INFO);
        let count = u32::try_from(self.extensions.len()).map_err(|_| Error::LimitExceeded)?;
        writer.write_uint32(count);
        for extension in &self.extensions {
            writer.write_string(&extension.name)?;
            writer.write_string(&extension.value)?;
        }
        Ok(writer.into_bytes())
    }

    /// Decodes one complete message, including its SSH message type byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] for an oversized input or extension
    /// count, [`Error::Truncated`] for an incomplete count or pair,
    /// [`Error::InvalidName`] for an empty/invalid extension name or malformed
    /// `server-sig-algs` value, and [`Error::InvalidPacket`] for a wrong type,
    /// duplicate extension name, or trailing bytes.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }

        let mut reader = Reader::new(input);
        if reader.read_byte()? != SSH_MSG_EXT_INFO {
            return Err(Error::InvalidPacket);
        }
        let count = usize::try_from(reader.read_uint32()?).map_err(|_| Error::LimitExceeded)?;
        ensure_count_fits(count)?;
        let minimum_pair_bytes = count
            .checked_mul(MIN_EXTENSION_PAIR_SIZE)
            .ok_or(Error::LimitExceeded)?;
        if minimum_pair_bytes > reader.len() {
            return Err(Error::Truncated);
        }

        let mut extensions = Vec::with_capacity(count);
        for _ in 0..count {
            let name =
                String::from_utf8(reader.read_string_bytes()?).map_err(|_| Error::InvalidName)?;
            let value = reader.read_string_bytes()?;
            extensions.push(Extension::new(name, &value)?);
        }
        if !reader.is_empty() {
            return Err(Error::InvalidPacket);
        }
        Self::new(extensions)
    }

    /// Decodes one `SSH_MSG_EXT_INFO` message from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ExtInfo::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        Self::decode(input)
    }

    /// Encodes this `SSH_MSG_EXT_INFO` message to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ExtInfo::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }
}

impl TryFrom<&[u8]> for ExtInfo {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// Encodes an `SSH_MSG_EXT_INFO` message using the shared wire writer.
///
/// # Errors
///
/// Returns the same errors as [`ExtInfo::encode`].
pub fn encode(message: &ExtInfo) -> Result<Vec<u8>, Error> {
    message.encode()
}

/// Decodes an `SSH_MSG_EXT_INFO` message using the shared wire reader.
///
/// # Errors
///
/// Returns the same errors as [`ExtInfo::decode`].
pub fn decode(input: &[u8]) -> Result<ExtInfo, Error> {
    ExtInfo::decode(input)
}

/// Selects the preferred RSA SHA-2 name from an algorithm name-list.
///
/// `rsa-sha2-512` wins whenever it is present. Otherwise,
/// `rsa-sha2-256` is selected when present. The legacy `ssh-rsa` name and all
/// other names are ignored.
#[must_use]
pub fn preferred_rsa_signature<S, N>(names: S) -> Option<&'static str>
where
    S: IntoIterator<Item = N>,
    N: AsRef<str>,
{
    let mut has_sha2_256 = false;
    for name in names {
        match name.as_ref() {
            RSA_SHA2_512 => return Some(RSA_SHA2_512),
            RSA_SHA2_256 => has_sha2_256 = true,
            _ => {}
        }
    }
    has_sha2_256.then_some(RSA_SHA2_256)
}

fn validate_extension_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| !byte.is_ascii() || byte == b',' || byte.is_ascii_whitespace())
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn decode_complete_name_list(input: &[u8]) -> Result<Vec<String>, Error> {
    let mut reader = Reader::new(input);
    let length = reader.read_uint32()?;
    let expected = usize::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(4))
        .ok_or(Error::InvalidName)?;
    if expected != input.len() {
        decode_name_list(input)?;
        return Err(Error::InvalidName);
    }
    decode_name_list(input)
}

fn ensure_unique_names(extensions: &[Extension]) -> Result<(), Error> {
    let mut names = HashSet::with_capacity(extensions.len());
    for extension in extensions {
        if !names.insert(extension.name.as_str()) {
            return Err(Error::InvalidPacket);
        }
    }
    Ok(())
}

fn ensure_count_fits(count: usize) -> Result<(), Error> {
    if count > MAX_EXT_INFO_EXTENSIONS {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}

fn encoded_size(extensions: &[Extension]) -> Result<usize, Error> {
    ensure_count_fits(extensions.len())?;
    ensure_unique_names(extensions)?;

    let mut size = EXT_INFO_HEADER_SIZE;
    for extension in extensions {
        validate_extension_name(&extension.name)?;
        size = size
            .checked_add(4)
            .and_then(|size| size.checked_add(extension.name.len()))
            .and_then(|size| size.checked_add(4))
            .and_then(|size| size.checked_add(extension.value.len()))
            .ok_or(Error::LimitExceeded)?;
        if size > MAX_PACKET_CONTENT {
            return Err(Error::LimitExceeded);
        }
    }
    Ok(size)
}
