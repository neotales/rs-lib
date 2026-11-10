//! age v1 header construction and strict parsing.

use zeroize::Zeroizing;

use crate::{
    AgeReadOptions,
    codec::{VERSION_LINE, decode_raw, encode_raw},
    crypto::{hkdf_sha256, hmac_sha256, verify_hmac_sha256},
    error::{AgeError, Result},
};

/// A recipient stanza from an age header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stanza {
    /// The recipient type, such as `X25519` or `scrypt`.
    pub r#type: String,
    /// Type-specific arguments after the recipient type.
    pub args: Vec<String>,
    /// The decoded stanza body.
    pub body: Vec<u8>,
}

impl Stanza {
    /// Creates a stanza without imposing recipient-specific validation.
    #[must_use]
    pub fn new<T, I>(r#type: T, args: I, body: impl Into<Vec<u8>>) -> Self
    where
        T: Into<String>,
        I: IntoIterator,
        I::Item: Into<String>,
    {
        Self {
            r#type: r#type.into(),
            args: args.into_iter().map(Into::into).collect(),
            body: body.into(),
        }
    }

    /// Returns the recipient type.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.r#type
    }
}

const MAX_STANZA_ARGS: usize = 128;

fn is_valid_field(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (33..=126).contains(&byte))
}

fn validate_stanza(stanza: &Stanza) -> Result<()> {
    if !is_valid_field(&stanza.r#type)
        || stanza.args.len() > MAX_STANZA_ARGS
        || stanza.args.iter().any(|argument| !is_valid_field(argument))
    {
        return Err(AgeError::InvalidHeader("invalid recipient stanza fields"));
    }
    Ok(())
}

/// A parsed age header and the unconsumed payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedHeader {
    pub(crate) stanzas: Vec<Stanza>,
    pub(crate) header_prefix: Vec<u8>,
    pub(crate) mac: Vec<u8>,
}

/// Builds a complete age header from recipient stanzas and a file key.
pub(crate) fn build_header(stanzas: &[Stanza], file_key: &[u8]) -> Result<Vec<u8>> {
    if stanzas.is_empty() || file_key.len() != 16 {
        return Err(AgeError::InvalidHeader(
            "a recipient and 16-byte file key are required",
        ));
    }
    let mut prefix = Vec::new();
    prefix.extend_from_slice(VERSION_LINE);
    for stanza in stanzas {
        validate_stanza(stanza)?;
        prefix.extend_from_slice(b"-> ");
        prefix.extend_from_slice(stanza.r#type.as_bytes());
        for argument in &stanza.args {
            prefix.push(b' ');
            prefix.extend_from_slice(argument.as_bytes());
        }
        prefix.push(b'\n');
        append_wrapped_body(&mut prefix, &stanza.body);
    }
    prefix.extend_from_slice(b"---");
    let mac_key = Zeroizing::new(hkdf_sha256(file_key, &[], b"header")?);
    let mac = hmac_sha256(&mac_key[..], &prefix)?;
    let mac_text = encode_raw(&mac);
    prefix.extend_from_slice(b" ");
    prefix.extend_from_slice(mac_text.as_bytes());
    prefix.push(b'\n');
    Ok(prefix)
}

/// Parses an age header and returns the payload offset in `input`.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_header(input: &[u8], options: AgeReadOptions) -> Result<(ParsedHeader, usize)> {
    let mut cursor = Cursor::new(input, options.max_header_bytes);
    let version = cursor
        .read_line()?
        .ok_or(AgeError::InvalidHeader("empty header"))?;
    if version.as_slice() != b"age-encryption.org/v1" {
        return Err(AgeError::InvalidHeader("unsupported version"));
    }
    let mut prefix = Vec::new();
    append_bounded(&mut prefix, &version, b'\n', options.max_header_bytes)?;
    let mut stanzas = Vec::new();

    loop {
        let line = cursor
            .read_line()?
            .ok_or(AgeError::InvalidHeader("truncated header"))?;
        if line.starts_with(b"--- ") {
            if stanzas.is_empty() {
                return Err(AgeError::InvalidHeader("header has no recipient stanza"));
            }
            let footer_length = line
                .len()
                .checked_add(1)
                .ok_or(AgeError::LimitExceeded("header is too large"))?;
            let complete_header_length = prefix
                .len()
                .checked_add(footer_length)
                .ok_or(AgeError::LimitExceeded("header is too large"))?;
            if complete_header_length > options.max_header_bytes {
                return Err(AgeError::LimitExceeded("header is too large"));
            }
            prefix.extend_from_slice(b"---");
            let encoded_mac = line
                .get(4..)
                .ok_or(AgeError::InvalidHeader("missing header MAC"))?;
            let mac = decode_raw(
                std::str::from_utf8(encoded_mac)
                    .map_err(|_| AgeError::InvalidHeader("header MAC is not ASCII"))?,
            )?;
            if mac.len() != 32 {
                return Err(AgeError::InvalidHeader("header MAC has the wrong length"));
            }
            return Ok((
                ParsedHeader {
                    stanzas,
                    header_prefix: prefix,
                    mac,
                },
                cursor.offset,
            ));
        }
        if !line.starts_with(b"-> ") {
            return Err(AgeError::InvalidHeader("invalid recipient stanza"));
        }
        if stanzas.len() >= options.max_stanzas {
            return Err(AgeError::LimitExceeded("too many recipient stanzas"));
        }
        append_bounded(&mut prefix, &line, b'\n', options.max_header_bytes)?;
        let text = std::str::from_utf8(&line)
            .map_err(|_| AgeError::InvalidHeader("recipient stanza is not ASCII"))?;
        let stanza_text = text
            .get(3..)
            .ok_or(AgeError::InvalidHeader("invalid recipient stanza"))?;
        let mut fields = stanza_text.split(' ');
        let kind = fields
            .next()
            .ok_or(AgeError::InvalidHeader("missing recipient type"))?;
        if !is_valid_field(kind) {
            return Err(AgeError::InvalidHeader("invalid recipient type"));
        }
        let mut args = Vec::new();
        for argument in fields {
            if args.len() >= MAX_STANZA_ARGS {
                return Err(AgeError::LimitExceeded("too many recipient arguments"));
            }
            if !is_valid_field(argument) {
                return Err(AgeError::InvalidHeader("invalid recipient argument"));
            }
            args.push(argument.to_owned());
        }

        let mut encoded_body = String::new();
        loop {
            let body_line = cursor
                .read_line()?
                .ok_or(AgeError::InvalidHeader("truncated recipient body"))?;
            if body_line.len() > 64 {
                return Err(AgeError::InvalidHeader("recipient body line is too long"));
            }
            append_bounded(&mut prefix, &body_line, b'\n', options.max_header_bytes)?;
            let body_text = std::str::from_utf8(&body_line)
                .map_err(|_| AgeError::InvalidHeader("recipient body is not ASCII"))?;
            encoded_body.push_str(body_text);
            if body_line.len() < 64 {
                break;
            }
        }
        let body = decode_raw(&encoded_body)?;
        if body.len() > options.max_stanza_body_bytes {
            return Err(AgeError::LimitExceeded("recipient body is too large"));
        }
        stanzas.push(Stanza {
            r#type: kind.to_owned(),
            args,
            body,
        });
    }
}

/// Verifies a parsed header MAC in constant time.
pub(crate) fn verify_header_mac(header_prefix: &[u8], mac: &[u8], file_key: &[u8]) -> Result<()> {
    let key = Zeroizing::new(hkdf_sha256(file_key, &[], b"header")?);
    if !verify_hmac_sha256(&key[..], header_prefix, mac) {
        return Err(AgeError::InvalidMac);
    }
    Ok(())
}

fn append_wrapped_body(output: &mut Vec<u8>, body: &[u8]) {
    let encoded = encode_raw(body);
    for chunk in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(chunk);
        output.push(b'\n');
    }
    if encoded.len().is_multiple_of(64) {
        output.push(b'\n');
    }
}

fn append_bounded(output: &mut Vec<u8>, line: &[u8], newline: u8, limit: usize) -> Result<()> {
    let new_length = output
        .len()
        .checked_add(line.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(AgeError::LimitExceeded("header is too large"))?;
    if new_length > limit {
        return Err(AgeError::LimitExceeded("header is too large"));
    }
    output.extend_from_slice(line);
    output.push(newline);
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
    max_line_length: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8], max_line_length: usize) -> Self {
        Self {
            input,
            offset: 0,
            max_line_length,
        }
    }

    fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        let start = self.offset;
        let relative_end = self
            .input
            .get(start..)
            .ok_or(AgeError::InvalidHeader("invalid header cursor"))?
            .iter()
            .position(|value| *value == b'\n');
        let Some(relative_end) = relative_end else {
            if start == self.input.len() {
                return Ok(None);
            }
            return Err(AgeError::Truncated);
        };
        let end = start
            .checked_add(relative_end)
            .ok_or(AgeError::InvalidHeader("header line is too long"))?;
        let line = self
            .input
            .get(start..end)
            .ok_or(AgeError::InvalidHeader("header line is out of range"))?;
        if line.len() >= self.max_line_length {
            return Err(AgeError::LimitExceeded("header line is too long"));
        }
        if line.contains(&b'\r') {
            return Err(AgeError::InvalidHeader("header must use LF line endings"));
        }
        self.offset = end
            .checked_add(1)
            .ok_or(AgeError::InvalidHeader("header offset overflow"))?;
        Ok(Some(line.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::{Stanza, build_header, parse_header};
    use crate::AgeReadOptions;

    fn header(args: Vec<String>) -> Vec<u8> {
        build_header(&[Stanza::new("test", args, Vec::new())], &[7u8; 16]).expect("build header")
    }

    #[test]
    fn stanza_arguments_are_capped_at_128() {
        let valid = header(vec!["a".to_owned(); 128]);
        assert!(parse_header(&valid, AgeReadOptions::default()).is_ok());
        assert!(
            build_header(
                &[Stanza::new("test", vec!["a".to_owned(); 129], Vec::new())],
                &[7u8; 16],
            )
            .is_err()
        );
    }

    #[test]
    fn stanza_syntax_rejects_noncanonical_fields() {
        for opening in [
            "-> test  arg",
            "-> test arg ",
            "-> test\targ",
            "-> test\u{0000}",
            "-> test café",
        ] {
            let input = format!(
                "age-encryption.org/v1\n{opening}\n\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            );
            assert!(
                parse_header(input.as_bytes(), AgeReadOptions::default()).is_err(),
                "accepted {opening:?}"
            );
        }
    }

    #[test]
    fn default_header_limits_accept_large_bodies_and_many_stanzas() {
        let body = vec![0x5a; 16 * 1024];
        let stanza = Stanza::new("test", Vec::<String>::new(), body);
        let one_large = build_header(&[stanza], &[7u8; 16]).expect("large header");
        assert!(parse_header(&one_large, AgeReadOptions::default()).is_ok());

        let stanzas = (0..33)
            .map(|_| Stanza::new("test", Vec::<String>::new(), Vec::new()))
            .collect::<Vec<_>>();
        let many = build_header(&stanzas, &[7u8; 16]).expect("many stanzas");
        assert!(parse_header(&many, AgeReadOptions::default()).is_ok());
    }

    #[test]
    fn header_footer_is_included_in_the_byte_limit() {
        let valid = header(Vec::new());
        assert!(
            parse_header(
                &valid,
                AgeReadOptions::default().with_max_header_bytes(valid.len()),
            )
            .is_ok()
        );
        assert!(
            parse_header(
                &valid,
                AgeReadOptions::default().with_max_header_bytes(valid.len() - 1),
            )
            .is_err()
        );
    }

    #[test]
    fn header_mac_must_use_canonical_raw_base64() {
        let valid = header(Vec::new());
        let footer = valid
            .windows(4)
            .position(|window| window == b"--- ")
            .expect("footer");
        let line_end = valid[footer..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| footer + offset)
            .expect("footer newline");
        let raw = &valid[footer + 4..line_end];
        let mut padded = valid[..footer].to_vec();
        padded.extend_from_slice(b"--- ");
        padded.extend_from_slice(STANDARD.encode(raw).as_bytes());
        padded.push(b'\n');
        padded.extend_from_slice(&valid[line_end + 1..]);
        assert!(parse_header(&padded, AgeReadOptions::default()).is_err());
    }
}
