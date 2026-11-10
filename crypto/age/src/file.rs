//! Binary and armored age v1 file encryption/decryption.

use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use {
    chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    },
    zeroize::{Zeroize, Zeroizing},
};

use crate::{
    AgeArmor, AgeIdentity, AgeReadOptions, AgeRecipient,
    codec::{
        STREAM_CHUNK_SIZE, STREAM_NONCE_SIZE, STREAM_TAG_LENGTH, maximum_armored_characters,
        maximum_binary_bytes, starts_with_begin_marker,
    },
    crypto::{hkdf_sha256, random_array},
    error::{AgeError, Result},
    header::{build_header, parse_header, verify_header_mac},
};

const CHUNK_SIZE: usize = STREAM_CHUNK_SIZE;
const TAG_LENGTH: usize = STREAM_TAG_LENGTH;
const PAYLOAD_NONCE_LENGTH: usize = STREAM_NONCE_SIZE;
const ARMOR_BINARY_LINE_LENGTH: usize = 48;

/// Encryption and decryption entry points for age files.
///
/// A unit struct holding no state, so its [`Debug`](std::fmt::Debug) output is
/// the type name and nothing else. A caller debugging a failed `encrypt` or
/// `decrypt` holds the returned `Vec<u8>` or [`AgeError`], not one of these.
#[derive(Debug)]
pub struct AgeFile;

impl AgeFile {
    /// Encrypts bytes to one or more recipients.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when no recipient is supplied, a passphrase
    /// recipient is mixed with another recipient, entropy is unavailable, or
    /// a recipient wrapping operation fails.
    pub fn encrypt(plaintext: &[u8], recipients: &[AgeRecipient]) -> Result<Vec<u8>> {
        validate_recipients(recipients)?;
        let file_key = Zeroizing::new(random_array::<16>()?);
        let stanzas = recipients
            .iter()
            .map(|recipient| recipient.wrap(&file_key[..]))
            .collect::<Result<Vec<_>>>()?;
        let header = build_header(&stanzas, &file_key[..])?;
        let mut output = Vec::new();
        output.write_all(&header).map_err(AgeError::from)?;
        encrypt_payload(&mut io::Cursor::new(plaintext), &mut output, &file_key[..])?;
        Ok(output)
    }

    /// Encrypts bytes using dynamic recipient implementations.
    ///
    /// This is the extension-point equivalent of [`Self::encrypt`] and is
    /// useful for plugin recipients and other protocol adapters.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when no recipients are supplied, labels are
    /// incompatible, entropy is unavailable, or a recipient fails.
    pub fn encrypt_with_recipients(
        plaintext: &[u8],
        recipients: &[Box<dyn crate::Recipient>],
    ) -> Result<Vec<u8>> {
        if recipients.is_empty() {
            return Err(AgeError::InvalidKey("at least one recipient is required"));
        }
        let file_key = Zeroizing::new(random_array::<16>()?);
        let mut stanzas = Vec::new();
        let mut expected_labels: Option<Vec<String>> = None;
        for recipient in recipients {
            let (mut wrapped, mut labels) = recipient.wrap_with_labels(&file_key[..])?;
            labels.sort();
            if let Some(expected) = &expected_labels
                && expected != &labels
            {
                return Err(AgeError::InvalidKey("incompatible age recipient labels"));
            }
            expected_labels.get_or_insert(labels);
            stanzas.append(&mut wrapped);
        }
        let header = build_header(&stanzas, &file_key[..])?;
        let mut output = Vec::new();
        output.write_all(&header).map_err(AgeError::from)?;
        encrypt_payload(&mut io::Cursor::new(plaintext), &mut output, &file_key[..])?;
        Ok(output)
    }

    /// Encrypts a file into a binary age file.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for path/I/O failures, invalid recipients, or
    /// recipient wrapping failures.
    pub fn encrypt_file(
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        recipients: &[AgeRecipient],
    ) -> Result<()> {
        validate_recipients(recipients)?;
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();
        ensure_distinct_paths(input_path, output_path)?;
        let mut input = File::open(input_path).map_err(AgeError::from)?;
        let (temporary_path, mut output) = create_temporary_output(output_path)?;
        let result = Self::encrypt_reader(&mut input, &mut output, recipients).and_then(|()| {
            output.sync_all().map_err(AgeError::from)?;
            std::fs::rename(&temporary_path, output_path).map_err(AgeError::from)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }

    /// Decrypts a binary or armored age file into a file.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for path/I/O failures, malformed input, no
    /// matching identity, or authentication failure.
    pub fn decrypt_file(
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        identities: &[AgeIdentity],
    ) -> Result<()> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();
        ensure_distinct_paths(input_path, output_path)?;
        let mut input = File::open(input_path).map_err(AgeError::from)?;
        let (temporary_path, mut output) = create_temporary_output(output_path)?;
        let result = Self::decrypt_reader(&mut input, &mut output, identities).and_then(|()| {
            output.sync_all().map_err(AgeError::from)?;
            std::fs::rename(&temporary_path, output_path).map_err(AgeError::from)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }

    /// Extracts and validates the complete binary age header.
    ///
    /// The returned bytes can be passed to [`Self::decrypt_header`] without
    /// retaining the encrypted payload.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed headers or configured limit
    /// violations.
    pub fn extract_header(ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (_header, payload_offset) = parse_header(ciphertext, AgeReadOptions::default())?;
        ciphertext
            .get(..payload_offset)
            .map(<[u8]>::to_vec)
            .ok_or(AgeError::InvalidHeader("header offset is out of range"))
    }

    /// Decrypts a detached age header and returns its authenticated file key.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed headers, no matching identity, or an
    /// invalid header MAC.
    pub fn decrypt_header(
        header: &[u8],
        identities: &[AgeIdentity],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if identities.is_empty() {
            return Err(AgeError::InvalidKey("at least one identity is required"));
        }
        let (parsed, _) = parse_header(header, AgeReadOptions::default())?;
        reject_mixed_scrypt(&parsed.stanzas)?;
        let mut file_key = None;
        for identity in identities {
            if let Some(candidate) = identity.file_key_from_stanzas(&parsed.stanzas)? {
                file_key = Some(candidate);
                break;
            }
        }
        let file_key = file_key.ok_or(AgeError::NoMatchingIdentity)?;
        verify_header_mac(&parsed.header_prefix, &parsed.mac, &file_key[..])?;
        Ok(file_key)
    }

    /// Encrypts bytes and returns the strict ASCII-armored representation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeFile::encrypt`].
    pub fn encrypt_armored(plaintext: &[u8], recipients: &[AgeRecipient]) -> Result<String> {
        Ok(AgeArmor::encode(&Self::encrypt(plaintext, recipients)?))
    }

    /// Decrypts binary or automatically detected ASCII-armored bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed input, no matching identity, an
    /// invalid header MAC, or payload authentication failure.
    pub fn decrypt(ciphertext: &[u8], identities: &[AgeIdentity]) -> Result<Vec<u8>> {
        Self::decrypt_with_options(ciphertext, identities, AgeReadOptions::default())
    }

    /// Decrypts with explicit resource limits.
    ///
    /// The default policy leaves payload and per-stanza body sizes unbounded;
    /// set [`AgeReadOptions::max_payload_bytes`] and
    /// [`AgeReadOptions::max_stanza_body_bytes`] when a resource cap is needed.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed input, no matching identity, an
    /// invalid header MAC, payload authentication failure, or a limit
    /// violation.
    pub fn decrypt_with_options(
        ciphertext: &[u8],
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<Vec<u8>> {
        let options = options.validate()?;
        if identities.is_empty() {
            return Err(AgeError::InvalidKey("at least one identity is required"));
        }
        let binary = if starts_with_begin_marker(ciphertext) {
            let armored = std::str::from_utf8(ciphertext)
                .map_err(|_| AgeError::InvalidFormat("armor is not UTF-8"))?;
            Cow::Owned(AgeArmor::decode_with_options(armored, options)?)
        } else {
            Cow::Borrowed(ciphertext)
        };
        decrypt_binary(binary.as_ref(), identities, options)
    }

    /// Decrypts binary age bytes using dynamic identity implementations.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed input, no matching identity, an
    /// invalid header MAC, or payload authentication failure.
    pub fn decrypt_with_identities(
        ciphertext: &[u8],
        identities: &[Box<dyn crate::Identity>],
    ) -> Result<Vec<u8>> {
        Self::decrypt_with_identities_with_options(
            ciphertext,
            identities,
            AgeReadOptions::default(),
        )
    }

    /// Decrypts binary age bytes using dynamic identities and explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed input, no matching identity, an
    /// invalid header MAC, payload authentication failure, or a limit
    /// violation.
    pub fn decrypt_with_identities_with_options(
        ciphertext: &[u8],
        identities: &[Box<dyn crate::Identity>],
        options: AgeReadOptions,
    ) -> Result<Vec<u8>> {
        if identities.is_empty() {
            return Err(AgeError::InvalidKey("at least one identity is required"));
        }
        decrypt_binary_with_identities(ciphertext, identities, options)
    }

    /// Decrypts a strict ASCII-armored string.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed armor, no matching identity, an
    /// invalid header MAC, or payload authentication failure.
    pub fn decrypt_armored(armored: &str, identities: &[AgeIdentity]) -> Result<Vec<u8>> {
        Self::decrypt_with_options(armored.as_bytes(), identities, AgeReadOptions::default())
    }

    /// Decrypts strict ASCII armor with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for malformed armor, no matching identity, an
    /// invalid header MAC, authentication failure, or a limit violation.
    pub fn decrypt_armored_with_options(
        armored: &str,
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<Vec<u8>> {
        Self::decrypt_with_options(armored.as_bytes(), identities, options)
    }

    /// Encrypts a reader into a binary writer without buffering plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for invalid recipients, entropy failures, or
    /// reader/writer errors.
    pub fn encrypt_reader<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        recipients: &[AgeRecipient],
    ) -> Result<()> {
        validate_recipients(recipients)?;
        let file_key = Zeroizing::new(random_array::<16>()?);
        let stanzas = recipients
            .iter()
            .map(|recipient| recipient.wrap(&file_key[..]))
            .collect::<Result<Vec<_>>>()?;
        let header = build_header(&stanzas, &file_key[..])?;
        output.write_all(&header).map_err(AgeError::from)?;
        encrypt_payload(input, output, &file_key[..])
    }

    /// Encrypts a reader into a strict ASCII-armored writer.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for invalid recipients, entropy failures, or
    /// reader/writer errors.
    pub fn encrypt_reader_armored<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        recipients: &[AgeRecipient],
    ) -> Result<()> {
        validate_recipients(recipients)?;
        let file_key = Zeroizing::new(random_array::<16>()?);
        let stanzas = recipients
            .iter()
            .map(|recipient| recipient.wrap(&file_key[..]))
            .collect::<Result<Vec<_>>>()?;
        let header = build_header(&stanzas, &file_key[..])?;
        let mut armor = ArmorWriter::new(output);
        armor.write_all(&header).map_err(AgeError::from)?;
        encrypt_payload(input, &mut armor, &file_key[..])?;
        armor.finish()
    }

    /// Decrypts a bounded binary reader into a writer.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for I/O errors, malformed input, no matching
    /// identity, or authentication failure.
    pub fn decrypt_reader<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        identities: &[AgeIdentity],
    ) -> Result<()> {
        Self::decrypt_reader_with_options(input, output, identities, AgeReadOptions::default())
    }

    /// Decrypts a bounded reader with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for I/O errors, malformed input, no matching
    /// identity, authentication failure, or a limit violation.
    pub fn decrypt_reader_with_options<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<()> {
        let options = options.validate()?;
        let maximum = maximum_binary_input(options)?;
        let bytes = read_bounded(input, maximum)?;
        let plaintext = Self::decrypt_with_options(&bytes, identities, options)?;
        output.write_all(&plaintext).map_err(AgeError::from)
    }

    /// Decrypts a bounded armored reader into a writer.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for I/O errors, malformed armor, no matching
    /// identity, or authentication failure.
    pub fn decrypt_reader_armored<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        identities: &[AgeIdentity],
    ) -> Result<()> {
        Self::decrypt_reader_armored_with_options(
            input,
            output,
            identities,
            AgeReadOptions::default(),
        )
    }

    /// Decrypts a bounded armored reader with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for I/O errors, malformed armor, no matching
    /// identity, authentication failure, or a limit violation.
    pub fn decrypt_reader_armored_with_options<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<()> {
        let options = options.validate()?;
        let maximum = maximum_armored_characters(options);
        let bytes = read_bounded(input, maximum)?;
        let armored = std::str::from_utf8(&bytes)
            .map_err(|_| AgeError::InvalidFormat("armor is not UTF-8"))?;
        let binary = AgeArmor::decode_with_options(armored, options)?;
        let plaintext = Self::decrypt_with_options(&binary, identities, options)?;
        output.write_all(&plaintext).map_err(AgeError::from)
    }
}

/// Encrypts bytes with the supplied recipients.
///
/// # Errors
///
/// Returns [`AgeError`] when recipient validation, entropy, or recipient
/// wrapping fails.
pub fn encrypt(plaintext: &[u8], recipients: &[AgeRecipient]) -> Result<Vec<u8>> {
    AgeFile::encrypt(plaintext, recipients)
}

/// Decrypts bytes with the supplied identities.
///
/// # Errors
///
/// Returns [`AgeError`] for malformed input, no matching identity, or
/// authentication failure.
pub fn decrypt(ciphertext: &[u8], identities: &[AgeIdentity]) -> Result<Vec<u8>> {
    AgeFile::decrypt(ciphertext, identities)
}

/// Encrypts bytes to strict ASCII armor.
///
/// # Errors
///
/// Returns the same errors as [`encrypt`].
pub fn encrypt_armored(plaintext: &[u8], recipients: &[AgeRecipient]) -> Result<String> {
    AgeFile::encrypt_armored(plaintext, recipients)
}

/// Decrypts strict ASCII armor.
///
/// # Errors
///
/// Returns the same errors as [`decrypt`].
pub fn decrypt_armored(armored: &str, identities: &[AgeIdentity]) -> Result<Vec<u8>> {
    AgeFile::decrypt_armored(armored, identities)
}

/// Decrypts strict ASCII armor with explicit resource limits.
///
/// # Errors
///
/// Returns the same errors as [`AgeFile::decrypt_with_options`].
pub fn decrypt_armored_with_options(
    armored: &str,
    identities: &[AgeIdentity],
    options: AgeReadOptions,
) -> Result<Vec<u8>> {
    AgeFile::decrypt_armored_with_options(armored, identities, options)
}

fn ensure_distinct_paths(input_path: &Path, output_path: &Path) -> Result<()> {
    let input_canonical = input_path.canonicalize().map_err(AgeError::Io)?;
    if output_path.exists()
        && output_path
            .canonicalize()
            .map_err(AgeError::from)
            .is_ok_and(|output_canonical| output_canonical == input_canonical)
    {
        return Err(AgeError::InvalidKey(
            "age input and output must be different files",
        ));
    }
    Ok(())
}

fn create_temporary_output(output_path: &Path) -> Result<(std::path::PathBuf, File)> {
    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("age-output");
    for _ in 0..16 {
        let suffix = u64::from_be_bytes(random_array::<8>()?);
        let temporary_path = parent.join(format!(".{file_name}.neotales-age-{suffix:016x}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(output) => return Ok((temporary_path, output)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(AgeError::Io(error)),
        }
    }
    Err(AgeError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary age output",
    )))
}

fn validate_recipients(recipients: &[AgeRecipient]) -> Result<()> {
    if recipients.is_empty() {
        return Err(AgeError::InvalidKey("at least one recipient is required"));
    }
    if recipients.iter().any(AgeRecipient::is_scrypt) && recipients.len() != 1 {
        return Err(AgeError::MixedScrypt);
    }
    AgeRecipient::validate_labels(recipients)
}

fn decrypt_binary_with_identities(
    binary: &[u8],
    identities: &[Box<dyn crate::Identity>],
    options: AgeReadOptions,
) -> Result<Vec<u8>> {
    let (header, payload_offset) = parse_header(binary, options)?;
    reject_mixed_scrypt(&header.stanzas)?;
    let mut file_key = None;
    for identity in identities {
        if let Some(candidate) = identity.unwrap(&header.stanzas)? {
            file_key = Some(candidate);
            break;
        }
    }
    let file_key = file_key.ok_or(AgeError::NoMatchingIdentity)?;
    verify_header_mac(&header.header_prefix, &header.mac, &file_key[..])?;
    let mut plaintext = Vec::new();
    let payload = binary
        .get(payload_offset..)
        .ok_or(AgeError::InvalidHeader("payload offset is out of range"))?;
    decrypt_payload(
        &mut io::Cursor::new(payload),
        &mut plaintext,
        &file_key[..],
        options,
    )?;
    Ok(plaintext)
}

fn decrypt_binary(
    binary: &[u8],
    identities: &[AgeIdentity],
    options: AgeReadOptions,
) -> Result<Vec<u8>> {
    let (header, payload_offset) = parse_header(binary, options)?;
    reject_mixed_scrypt(&header.stanzas)?;
    let mut file_key = None;
    let mut ordered_identities: Vec<&AgeIdentity> = identities.iter().collect();
    ordered_identities.sort_by_key(|identity| {
        !matches!(
            identity,
            AgeIdentity::X25519 { .. } | AgeIdentity::Hybrid { .. } | AgeIdentity::Scrypt { .. }
        )
    });
    for identity in ordered_identities {
        if let Some(candidate) = identity.file_key_from_stanzas(&header.stanzas)? {
            file_key = Some(candidate);
            break;
        }
    }
    let file_key = file_key.ok_or(AgeError::NoMatchingIdentity)?;
    verify_header_mac(&header.header_prefix, &header.mac, &file_key[..])?;
    let mut plaintext = Vec::new();
    let payload = binary
        .get(payload_offset..)
        .ok_or(AgeError::InvalidHeader("payload offset is out of range"))?;
    let mut payload_reader = io::Cursor::new(payload);
    decrypt_payload(&mut payload_reader, &mut plaintext, &file_key[..], options)?;
    Ok(plaintext)
}

fn reject_mixed_scrypt(stanzas: &[crate::Stanza]) -> Result<()> {
    if stanzas.iter().any(|stanza| stanza.r#type == "scrypt") && stanzas.len() != 1 {
        return Err(AgeError::MixedScrypt);
    }
    Ok(())
}

fn encrypt_payload<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    file_key: &[u8],
) -> Result<()> {
    let nonce = Zeroizing::new(random_array::<PAYLOAD_NONCE_LENGTH>()?);
    output.write_all(&nonce[..]).map_err(AgeError::from)?;
    let payload_key = Zeroizing::new(hkdf_sha256(file_key, &nonce[..], b"payload")?);
    let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let mut plaintext = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut chunk_nonce = Zeroizing::new([0u8; 12]);
    let mut pending = None;
    let mut counter = 0u64;
    loop {
        let read = if let Some(first) = pending.take() {
            let buffer = plaintext.as_mut_slice();
            buffer[0] = first;
            1usize
                .checked_add(read_chunk(input, &mut buffer[1..])?)
                .ok_or(AgeError::LimitExceeded("input is too large"))?
        } else {
            read_chunk(input, plaintext.as_mut_slice())?
        };
        let is_final = if read < CHUNK_SIZE {
            true
        } else {
            match read_one(input)? {
                Some(byte) => {
                    pending = Some(byte);
                    false
                }
                None => true,
            }
        };

        build_chunk_nonce(counter, is_final, &mut chunk_nonce);
        let next_counter = counter
            .checked_add(1)
            .ok_or(AgeError::Crypto("payload counter overflow"))?;
        let nonce = Nonce::try_from(&chunk_nonce[..])
            .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
        let plaintext_chunk = plaintext
            .get(..read)
            .ok_or(AgeError::InvalidFormat("payload chunk is out of range"))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext_chunk)
            .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 encryption"))?;
        output.write_all(&ciphertext).map_err(AgeError::from)?;
        if is_final {
            return Ok(());
        }
        counter = next_counter;
    }
}

fn decrypt_payload<R: Read>(
    input: &mut R,
    output: &mut impl Write,
    file_key: &[u8],
    options: AgeReadOptions,
) -> Result<()> {
    let mut nonce = Zeroizing::new([0u8; PAYLOAD_NONCE_LENGTH]);
    read_exact(input, nonce.as_mut_slice())?;
    let payload_key = Zeroizing::new(hkdf_sha256(file_key, &nonce[..], b"payload")?);
    let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))?;
    let mut encrypted = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LENGTH]);
    let mut chunk_nonce = Zeroizing::new([0u8; 12]);
    let mut counter = 0u64;
    let mut total = 0usize;
    loop {
        let read = read_at_most(input, encrypted.as_mut_slice())?;
        if read == 0 {
            return Err(AgeError::Truncated);
        }
        if read < TAG_LENGTH {
            return Err(AgeError::InvalidFormat("payload chunk is truncated"));
        }
        let plaintext_length = read - TAG_LENGTH;
        if plaintext_length == 0 && counter != 0 {
            return Err(AgeError::InvalidFormat(
                "payload contains an empty non-final chunk",
            ));
        }

        let ciphertext = encrypted
            .get(..read)
            .ok_or(AgeError::InvalidFormat("payload chunk is out of range"))?;
        let is_short = read < encrypted.len();
        let (decrypted, is_final) = if is_short {
            (
                decrypt_chunk(&cipher, ciphertext, counter, true, &mut chunk_nonce)?
                    .ok_or(AgeError::AuthenticationFailed)?,
                true,
            )
        } else if let Some(decrypted) =
            decrypt_chunk(&cipher, ciphertext, counter, false, &mut chunk_nonce)?
        {
            (decrypted, false)
        } else if let Some(decrypted) =
            decrypt_chunk(&cipher, ciphertext, counter, true, &mut chunk_nonce)?
        {
            (decrypted, true)
        } else {
            return Err(AgeError::AuthenticationFailed);
        };

        if decrypted.len() != plaintext_length {
            return Err(AgeError::AuthenticationFailed);
        }
        total = total
            .checked_add(plaintext_length)
            .ok_or(AgeError::LimitExceeded("payload is too large"))?;
        if total > options.max_payload_bytes {
            return Err(AgeError::LimitExceeded("payload is too large"));
        }
        if is_final {
            reject_trailing_data(input)?;
        }
        output.write_all(&decrypted).map_err(AgeError::from)?;
        if is_final {
            return Ok(());
        }
        counter = counter
            .checked_add(1)
            .ok_or(AgeError::Crypto("payload counter overflow"))?;
    }
}

fn decrypt_chunk(
    cipher: &ChaCha20Poly1305,
    ciphertext: &[u8],
    counter: u64,
    is_final: bool,
    chunk_nonce: &mut [u8; 12],
) -> Result<Option<Vec<u8>>> {
    build_chunk_nonce(counter, is_final, chunk_nonce);
    let nonce = Nonce::try_from(&chunk_nonce[..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    Ok(cipher.decrypt(&nonce, ciphertext).ok())
}

fn reject_trailing_data(input: &mut impl Read) -> Result<()> {
    if read_one(input)?.is_some() {
        return Err(AgeError::InvalidFormat("trailing data after payload"));
    }
    Ok(())
}

fn read_one(input: &mut impl Read) -> Result<Option<u8>> {
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(1) => return Ok(Some(byte[0])),
            Ok(_) => return Err(AgeError::InvalidFormat("reader returned too much data")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(AgeError::Io(error)),
        }
    }
}

fn build_chunk_nonce(counter: u64, is_final: bool, nonce: &mut [u8; 12]) {
    nonce.fill(0);
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(is_final);
}

fn read_chunk(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        match input.read(&mut buffer[offset..]) {
            Ok(0) => break,
            Ok(read) => {
                if read > buffer.len().saturating_sub(offset) {
                    return Err(AgeError::InvalidFormat("reader returned too much data"));
                }
                offset = offset
                    .checked_add(read)
                    .ok_or(AgeError::LimitExceeded("input is too large"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(AgeError::Io(error)),
        }
    }
    Ok(offset)
}

fn read_at_most(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        match input.read(&mut buffer[offset..]) {
            Ok(0) => break,
            Ok(read) => {
                if read > buffer.len().saturating_sub(offset) {
                    return Err(AgeError::InvalidFormat("reader returned too much data"));
                }
                offset = offset
                    .checked_add(read)
                    .ok_or(AgeError::LimitExceeded("input is too large"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(AgeError::Io(error)),
        }
    }
    Ok(offset)
}

fn read_exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    if read_at_most(input, buffer)? == buffer.len() {
        Ok(())
    } else {
        Err(AgeError::Truncated)
    }
}

#[allow(clippy::unnecessary_wraps)]
fn maximum_binary_input(options: AgeReadOptions) -> Result<usize> {
    Ok(maximum_binary_bytes(options))
}

fn read_bounded(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    let mut limited = input.take(maximum_u64.saturating_add(1));
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes).map_err(AgeError::from)?;
    if bytes.len() > maximum {
        return Err(AgeError::LimitExceeded("input is too large"));
    }
    Ok(bytes)
}

struct ArmorWriter<'a, W: Write> {
    inner: &'a mut W,
    pending: [u8; ARMOR_BINARY_LINE_LENGTH],
    pending_length: usize,
    started: bool,
    completed: bool,
}

impl<'a, W: Write> ArmorWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            pending: [0u8; ARMOR_BINARY_LINE_LENGTH],
            pending_length: 0,
            started: false,
            completed: false,
        }
    }

    fn finish(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        if !self.started {
            self.inner
                .write_all(format!("{}\n", AgeArmor::BEGIN).as_bytes())
                .map_err(AgeError::from)?;
            self.started = true;
        }
        self.flush_pending()?;
        self.inner
            .write_all(format!("{}\n", AgeArmor::END).as_bytes())
            .map_err(AgeError::from)?;
        self.completed = true;
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<()> {
        if self.pending_length == 0 {
            return Ok(());
        }
        let pending = self
            .pending
            .get(..self.pending_length)
            .ok_or(AgeError::Crypto("armor line is out of range"))?;
        let line = STANDARD.encode(pending);
        self.inner
            .write_all(line.as_bytes())
            .map_err(AgeError::from)?;
        self.inner.write_all(b"\n").map_err(AgeError::from)?;
        if let Some(pending) = self.pending.get_mut(..self.pending_length) {
            pending.zeroize();
        }
        self.pending_length = 0;
        Ok(())
    }
}

impl<W: Write> Write for ArmorWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.completed {
            return Err(io::Error::other("armor writer is closed"));
        }
        if !self.started {
            self.inner
                .write_all(format!("{}\n", AgeArmor::BEGIN).as_bytes())?;
            self.started = true;
        }
        let mut offset = 0usize;
        while offset < bytes.len() {
            let available = ARMOR_BINARY_LINE_LENGTH
                .checked_sub(self.pending_length)
                .ok_or_else(|| io::Error::other("armor line length overflow"))?;
            let copied = available.min(bytes.len() - offset);
            let destination_start = self.pending_length;
            let destination_end = destination_start
                .checked_add(copied)
                .ok_or_else(|| io::Error::other("armor line length overflow"))?;
            let destination = self
                .pending
                .get_mut(destination_start..destination_end)
                .ok_or_else(|| io::Error::other("armor line is out of range"))?;
            let source = bytes
                .get(offset..offset + copied)
                .ok_or_else(|| io::Error::other("armor input is out of range"))?;
            destination.copy_from_slice(source);
            self.pending_length = destination_end;
            offset = offset
                .checked_add(copied)
                .ok_or_else(|| io::Error::other("armor input length overflow"))?;
            if self.pending_length == ARMOR_BINARY_LINE_LENGTH {
                self.flush_pending()
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use {
        chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit},
        },
        zeroize::Zeroizing,
    };

    use super::*;
    use crate::crypto::hkdf_sha256;

    fn encrypt_test_payload(plaintext: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        encrypt_payload(&mut Cursor::new(plaintext), &mut output, &[0x42; 16])
            .expect("encrypt payload");
        output
    }

    #[test]
    fn stream_nonce_is_three_zeroes_big_endian_counter_and_final_flag() {
        let mut nonce = [0xff; 12];
        build_chunk_nonce(0x0102_0304_0506_0708, false, &mut nonce);
        assert_eq!(nonce, [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        build_chunk_nonce(0x0102_0304_0506_0708, true, &mut nonce);
        assert_eq!(nonce, [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1]);
    }

    #[test]
    fn stream_chunk_boundaries_match_go() {
        for size in [
            0,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 2,
        ] {
            let plaintext = vec![0x6d; size];
            let encrypted = encrypt_test_payload(&plaintext);
            let chunks = if size == 0 {
                1usize
            } else {
                size.div_ceil(CHUNK_SIZE)
            };
            assert_eq!(
                encrypted.len(),
                PAYLOAD_NONCE_LENGTH + size + chunks * TAG_LENGTH
            );

            let mut decrypted = Vec::new();
            decrypt_payload(
                &mut Cursor::new(encrypted.as_slice()),
                &mut decrypted,
                &[0x42; 16],
                AgeReadOptions::default(),
            )
            .expect("decrypt payload");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn stream_rejects_trailing_and_empty_nonfinal_chunks() {
        let mut with_trailing = encrypt_test_payload(&[]);
        with_trailing.push(0x42);
        let mut output = Vec::new();
        assert!(
            decrypt_payload(
                &mut Cursor::new(with_trailing.as_slice()),
                &mut output,
                &[0x42; 16],
                AgeReadOptions::default(),
            )
            .is_err()
        );

        let source = vec![0x6d; CHUNK_SIZE + 1];
        let encrypted = encrypt_test_payload(&source);
        let first_chunk_end = PAYLOAD_NONCE_LENGTH + CHUNK_SIZE + TAG_LENGTH;
        let payload_key = Zeroizing::new(
            hkdf_sha256(&[0x42; 16], &encrypted[..PAYLOAD_NONCE_LENGTH], b"payload")
                .expect("payload key"),
        );
        let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).expect("cipher");
        let mut chunk_nonce = [0u8; 12];
        build_chunk_nonce(1, true, &mut chunk_nonce);
        let nonce = Nonce::try_from(&chunk_nonce[..]).expect("chunk nonce");
        let empty_final = cipher.encrypt(&nonce, &[] as &[u8]).expect("empty final");
        let mut malformed = encrypted[..first_chunk_end].to_vec();
        malformed.extend_from_slice(&empty_final);
        let mut output = Vec::new();
        assert!(
            decrypt_payload(
                &mut Cursor::new(malformed.as_slice()),
                &mut output,
                &[0x42; 16],
                AgeReadOptions::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn stream_rejects_a_full_chunk_without_a_final_marker() {
        let plaintext = vec![0x6d; CHUNK_SIZE];
        let encrypted = encrypt_test_payload(&plaintext);
        let payload_key = Zeroizing::new(
            hkdf_sha256(&[0x42; 16], &encrypted[..PAYLOAD_NONCE_LENGTH], b"payload")
                .expect("payload key"),
        );
        let cipher = ChaCha20Poly1305::new_from_slice(&payload_key[..]).expect("cipher");
        let mut chunk_nonce = [0u8; 12];
        build_chunk_nonce(0, false, &mut chunk_nonce);
        let nonce = Nonce::try_from(&chunk_nonce[..]).expect("chunk nonce");
        let nonfinal = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .expect("non-final chunk");
        let mut malformed = encrypted[..PAYLOAD_NONCE_LENGTH].to_vec();
        malformed.extend_from_slice(&nonfinal);
        let mut output = Vec::new();
        assert!(
            decrypt_payload(
                &mut Cursor::new(malformed.as_slice()),
                &mut output,
                &[0x42; 16],
                AgeReadOptions::default(),
            )
            .is_err()
        );
    }
}
