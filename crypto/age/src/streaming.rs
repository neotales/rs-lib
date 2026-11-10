//! Non-buffering age v1 streaming primitives.
//!
//! The types in this module keep the age header separate from the STREAM
//! payload. [`AgeEncryptWriter`] and [`AgeEncryptReader`] produce a complete
//! binary age file, while [`AgeDecryptReader`] authenticates and decrypts one
//! payload chunk at a time. [`AgeDecryptReaderAt`] provides random access over
//! an encrypted [`ReaderAt`] source and authenticates the final chunk
//! before it is returned to the caller.
//!
//! These APIs operate on binary age files. ASCII armor remains available
//! through [`crate::AgeArmor`] and the higher-level file helpers.

use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::Mutex,
};

use {
    chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    },
    zeroize::Zeroizing,
};

use crate::{
    AgeFile, AgeIdentity, AgeReadOptions, AgeRecipient, Result,
    codec::{STREAM_CHUNK_SIZE, STREAM_NONCE_SIZE, STREAM_TAG_LENGTH},
    crypto::{hkdf_sha256, random_array},
    error::AgeError,
    header::{ParsedHeader, build_header, parse_header, verify_header_mac},
};

const CHUNK_SIZE: usize = STREAM_CHUNK_SIZE;
const TAG_LENGTH: usize = STREAM_TAG_LENGTH;
const PAYLOAD_NONCE_LENGTH: usize = STREAM_NONCE_SIZE;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LENGTH;
const CHUNK_SIZE_U64: u64 = CHUNK_SIZE as u64;
const ENCRYPTED_CHUNK_SIZE_U64: u64 = ENCRYPTED_CHUNK_SIZE as u64;
const TAG_LENGTH_U64: u64 = TAG_LENGTH as u64;
const PAYLOAD_NONCE_LENGTH_U64: u64 = PAYLOAD_NONCE_LENGTH as u64;

/// A minimal random-access byte source used by [`AgeDecryptReaderAt`].
///
/// Rust's standard library does not currently provide a `ReadAt` trait. This
/// trait supplies the same offset-based operation and has a blanket
/// implementation for every [`Read`] + [`Seek`] source, including
/// [`std::fs::File`] and [`std::io::Cursor`]. As with the conventional
/// `ReadAt` operation, the source's current seek position is ignored. The
/// implementation seeks before each request, so callers that share a source
/// between threads must provide their own synchronization; the decrypted
/// chunk cache is synchronized independently. A request leaves the source's
/// seek position at the end of the requested range.
pub trait ReaderAt {
    /// Reads exactly `buffer.len()` bytes at `offset`, or returns an error if
    /// the source ends first.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the source cannot be seeked/read or when the
    /// requested range is outside the source.
    fn read_at(&mut self, buffer: &mut [u8], offset: u64) -> io::Result<usize>;
}

impl<T> ReaderAt for T
where
    T: Read + Seek,
{
    fn read_at(&mut self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.seek(SeekFrom::Start(offset))?;
        let mut position = 0usize;
        while position < buffer.len() {
            match self.read(&mut buffer[position..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "random-access source ended before the requested range",
                    ));
                }
                Ok(read) => {
                    if read > buffer.len() - position {
                        return Err(io::Error::other(
                            "random-access source returned too much data",
                        ));
                    }
                    position += read;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(position)
    }
}

/// A slice-backed random-access source for [`AgeDecryptReaderAt`].
///
/// This is useful when the encrypted file is already in memory. It performs
/// bounds-checked offset reads without copying the encrypted input.
///
/// [`Debug`](std::fmt::Debug) prints the length of the viewed bytes rather than
/// the bytes. The bytes are ciphertext, so printing them would not leak a
/// secret, but a container can be megabytes and a derived implementation would
/// put all of it into a log line or a test failure message.
#[derive(Clone, Copy)]
pub struct AgeSliceReaderAt<'a> {
    bytes: &'a [u8],
}

impl std::fmt::Debug for AgeSliceReaderAt<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeSliceReaderAt")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl<'a> AgeSliceReaderAt<'a> {
    /// Creates a random-access view over `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the viewed bytes.
    #[must_use]
    pub fn as_slice(&self) -> &'a [u8] {
        self.bytes
    }
}

impl ReaderAt for AgeSliceReaderAt<'_> {
    fn read_at(&mut self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let offset = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "age source offset is too large",
            )
        })?;
        let end = offset.checked_add(buffer.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "age source range overflow")
        })?;
        let source = self.bytes.get(offset..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "age source range is out of range",
            )
        })?;
        buffer.copy_from_slice(source);
        Ok(buffer.len())
    }
}

/// A streaming age encryptor that implements [`Write`].
///
/// The age header and payload nonce are written when the writer is created.
/// Call [`AgeEncryptWriter::finish`] after the last call to [`Write::write`]
/// (or [`Write::write_all`]); finishing emits the authenticated final STREAM
/// chunk, including an empty final chunk for an empty input. The underlying
/// writer is owned by this value and is not closed by `finish`.
///
/// [`Debug`](std::fmt::Debug) is hand-written and prints the progress counters
/// and the number of plaintext bytes currently buffered, never the bytes
/// themselves. `buffer` holds plaintext that has been handed to `write` and not
/// yet encrypted, and a derived implementation would print it. The
/// implementation also does not require `W: Debug`, so a caller is not asked to
/// implement `Debug` on their own writer type to be able to log this value.
pub struct AgeEncryptWriter<W: Write> {
    output: Option<W>,
    cipher: ChaCha20Poly1305,
    counter: u64,
    buffer: Vec<u8>,
    finished: bool,
    failure: Option<io::Error>,
}

impl<W: Write> std::fmt::Debug for AgeEncryptWriter<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeEncryptWriter")
            .field("counter", &self.counter)
            .field("buffered", &self.buffer.len())
            .field("finished", &self.finished)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl<W: Write> AgeEncryptWriter<W> {
    /// Creates an age encryptor and writes its header and payload nonce to
    /// `output`.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when recipients are invalid, entropy is
    /// unavailable, or writing the age header or nonce fails.
    pub fn new(mut output: W, recipients: &[AgeRecipient]) -> Result<Self> {
        let (prefix, cipher) = encryption_material(recipients)?;
        output.write_all(&prefix).map_err(AgeError::from)?;
        Ok(Self::with_cipher(output, cipher))
    }

    /// Alias for [`AgeEncryptWriter::new`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::new`].
    pub fn with_recipients(output: W, recipients: &[AgeRecipient]) -> Result<Self> {
        Self::new(output, recipients)
    }

    /// Creates a low-level STREAM encryptor from a 32-byte payload key.
    ///
    /// This constructor does not add an age header or payload nonce. Most
    /// callers should use [`AgeEncryptWriter::new`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when `payload_key` is not a valid ChaCha20-Poly1305
    /// key length.
    pub fn from_payload_key(output: W, payload_key: &[u8]) -> Result<Self> {
        let cipher = cipher_from_key(payload_key)?;
        Ok(Self::with_cipher(output, cipher))
    }

    /// Alias for [`AgeEncryptWriter::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::from_payload_key`].
    pub fn from_key(output: W, payload_key: &[u8]) -> Result<Self> {
        Self::from_payload_key(output, payload_key)
    }

    /// Alias for [`AgeEncryptWriter::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::from_payload_key`].
    pub fn new_with_payload_key(output: W, payload_key: &[u8]) -> Result<Self> {
        Self::from_payload_key(output, payload_key)
    }

    fn with_cipher(output: W, cipher: ChaCha20Poly1305) -> Self {
        // The prefix has already been written by the public constructors.
        Self {
            output: Some(output),
            cipher,
            counter: 0,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            finished: false,
            failure: None,
        }
    }

    /// Emits the final authenticated STREAM chunk.
    ///
    /// This method is idempotent after a successful finish. A writer that has
    /// already returned an I/O error remains failed.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when encrypting the final chunk or writing it to
    /// the underlying writer fails.
    pub fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if let Some(error) = self.failure.as_ref() {
            return Err(AgeError::Io(clone_io_error(error)));
        }
        if let Err(error) = self.flush_chunk(true) {
            self.failure = Some(age_error_as_io(&error));
            return Err(error);
        }
        self.finished = true;
        Ok(())
    }

    /// Alias for [`AgeEncryptWriter::finish`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::finish`].
    pub fn close(&mut self) -> Result<()> {
        self.finish()
    }

    /// Finishes encryption and returns the underlying writer.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::finish`].
    pub fn finish_and_get(mut self) -> Result<W> {
        self.finish()?;
        Ok(self.into_inner())
    }

    /// Returns whether the final chunk has been emitted.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Returns a shared reference to the underlying writer.
    ///
    /// # Panics
    ///
    /// Panics only if the writer's internal output has already been taken,
    /// which cannot happen through the public API.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        self.output
            .as_ref()
            .expect("age encryption output is present")
    }

    /// Returns a mutable reference to the underlying writer.
    ///
    /// # Panics
    ///
    /// Panics only if the writer's internal output has already been taken,
    /// which cannot happen through the public API.
    pub fn get_mut(&mut self) -> &mut W {
        self.output
            .as_mut()
            .expect("age encryption output is present")
    }

    /// Consumes the encryptor and returns the underlying writer.
    ///
    /// The caller should call [`AgeEncryptWriter::finish`] before consuming the
    /// value when a complete age file is required.
    ///
    /// # Panics
    ///
    /// Panics only if the writer's internal output has already been taken,
    /// which cannot happen through the public API.
    #[must_use]
    pub fn into_inner(mut self) -> W {
        self.output
            .take()
            .expect("age encryption output is present")
    }

    fn flush_chunk(&mut self, is_final: bool) -> Result<()> {
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(AgeError::Crypto("payload counter overflow"))?;
        let ciphertext = encrypt_chunk(&self.cipher, self.counter, is_final, &self.buffer)?;
        if let Err(error) = self
            .output
            .as_mut()
            .expect("age encryption output is present")
            .write_all(&ciphertext)
        {
            self.buffer.fill(0);
            self.buffer.clear();
            return Err(AgeError::Io(error));
        }
        self.buffer.fill(0);
        self.buffer.clear();
        if !is_final {
            self.counter = next_counter;
        }
        Ok(())
    }

    fn failed_io_error(&self) -> Option<io::Error> {
        self.failure.as_ref().map(clone_io_error)
    }
}

impl<W: Write> Write for AgeEncryptWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(error) = self.failed_io_error() {
            return Err(error);
        }
        if self.finished {
            return Err(io::Error::other("age encryption writer is closed"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }

        let total = bytes.len();
        let mut offset = 0usize;
        while offset < bytes.len() {
            if self.buffer.len() == CHUNK_SIZE
                && let Err(error) = self.flush_chunk(false)
            {
                let io_error = age_error_as_io(&error);
                self.failure = Some(clone_io_error(&io_error));
                return Err(io_error);
            }
            let available = CHUNK_SIZE.saturating_sub(self.buffer.len());
            let copied = available.min(bytes.len() - offset);
            self.buffer.extend_from_slice(
                bytes
                    .get(offset..offset + copied)
                    .ok_or_else(|| io::Error::other("age encryption input is out of range"))?,
            );
            offset += copied;
            if self.buffer.len() == CHUNK_SIZE
                && offset < bytes.len()
                && let Err(error) = self.flush_chunk(false)
            {
                let io_error = age_error_as_io(&error);
                self.failure = Some(clone_io_error(&io_error));
                return Err(io_error);
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(error) = self.failed_io_error() {
            return Err(error);
        }
        self.output
            .as_mut()
            .expect("age encryption output is present")
            .flush()
            .map_err(|error| {
                let io_error = io::Error::new(error.kind(), error.to_string());
                self.failure = Some(clone_io_error(&io_error));
                io_error
            })
    }
}

impl<W: Write> Drop for AgeEncryptWriter<W> {
    fn drop(&mut self) {
        self.buffer.fill(0);
    }
}

/// A streaming age encryptor that implements [`Read`].
///
/// The returned bytes are a complete binary age file: the header and payload
/// nonce are emitted first, followed by authenticated STREAM chunks. Input is
/// read at most one chunk ahead so that the final-chunk flag is exact.
///
/// [`Debug`](std::fmt::Debug) is hand-written and prints how far through the
/// header and the payload this value is, never the caller's plaintext and never
/// the ciphertext. It does not require `R: Debug`, so a caller is not asked to
/// implement `Debug` on their own reader type to be able to log this value.
pub struct AgeEncryptReader<R> {
    input: R,
    prefix: Vec<u8>,
    prefix_offset: usize,
    cipher: ChaCha20Poly1305,
    encrypted: Vec<u8>,
    encrypted_offset: usize,
    pending: Option<u8>,
    counter: u64,
    done: bool,
    failure: Option<AgeError>,
}

impl<R> std::fmt::Debug for AgeEncryptReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeEncryptReader")
            .field("prefix_offset", &self.prefix_offset)
            .field("prefix_len", &self.prefix.len())
            .field("counter", &self.counter)
            .field("encrypted_len", &self.encrypted.len())
            .field("done", &self.done)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl<R: Read> AgeEncryptReader<R> {
    /// Creates an encrypting reader for `input` and the supplied recipients.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when recipients are invalid or entropy is
    /// unavailable.
    pub fn new(input: R, recipients: &[AgeRecipient]) -> Result<Self> {
        let (prefix, cipher) = encryption_material(recipients)?;
        Ok(Self::with_cipher(input, prefix, cipher))
    }

    /// Alias for [`AgeEncryptReader::new`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptReader::new`].
    pub fn with_recipients(input: R, recipients: &[AgeRecipient]) -> Result<Self> {
        Self::new(input, recipients)
    }

    /// Creates a low-level STREAM encrypting reader from a 32-byte payload
    /// key. No age header or payload nonce is emitted.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when `payload_key` is not a valid ChaCha20-Poly1305
    /// key length.
    pub fn from_payload_key(input: R, payload_key: &[u8]) -> Result<Self> {
        let cipher = cipher_from_key(payload_key)?;
        Ok(Self::with_cipher(input, Vec::new(), cipher))
    }

    /// Alias for [`AgeEncryptReader::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptReader::from_payload_key`].
    pub fn from_key(input: R, payload_key: &[u8]) -> Result<Self> {
        Self::from_payload_key(input, payload_key)
    }

    /// Alias for [`AgeEncryptReader::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptReader::from_payload_key`].
    pub fn new_with_payload_key(input: R, payload_key: &[u8]) -> Result<Self> {
        Self::from_payload_key(input, payload_key)
    }

    fn with_cipher(input: R, prefix: Vec<u8>, cipher: ChaCha20Poly1305) -> Self {
        Self {
            input,
            prefix,
            prefix_offset: 0,
            cipher,
            encrypted: Vec::with_capacity(ENCRYPTED_CHUNK_SIZE),
            encrypted_offset: 0,
            pending: None,
            counter: 0,
            done: false,
            failure: None,
        }
    }

    /// Consumes the encryptor and returns the plaintext source.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.input
    }

    /// Returns a shared reference to the plaintext source.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.input
    }

    /// Returns a mutable reference to the plaintext source.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.input
    }

    fn fill_next_chunk(&mut self) -> Result<()> {
        let mut plaintext = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
        let read = if let Some(first) = self.pending.take() {
            plaintext[0] = first;
            1usize
                .checked_add(read_at_most(
                    &mut self.input,
                    &mut plaintext.as_mut_slice()[1..],
                )?)
                .ok_or(AgeError::LimitExceeded("input is too large"))?
        } else {
            read_at_most(&mut self.input, &mut plaintext)?
        };
        let is_final = if read < CHUNK_SIZE {
            true
        } else {
            match read_one(&mut self.input)? {
                Some(byte) => {
                    self.pending = Some(byte);
                    false
                }
                None => true,
            }
        };
        let plaintext = plaintext
            .get(..read)
            .ok_or(AgeError::InvalidFormat("payload chunk is out of range"))?;
        let ciphertext = encrypt_chunk(&self.cipher, self.counter, is_final, plaintext)?;
        self.encrypted.clear();
        self.encrypted.extend_from_slice(&ciphertext);
        self.encrypted_offset = 0;
        if is_final {
            self.done = true;
        } else {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(AgeError::Crypto("payload counter overflow"))?;
        }
        Ok(())
    }

    fn read_encrypted(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.failure.as_ref() {
            return Err(age_error_as_io(error));
        }
        if self.prefix_offset < self.prefix.len() {
            let count = (self.prefix.len() - self.prefix_offset).min(output.len());
            let source = self
                .prefix
                .get(self.prefix_offset..self.prefix_offset + count)
                .ok_or_else(|| io::Error::other("age encryption prefix is out of range"))?;
            output[..count].copy_from_slice(source);
            self.prefix_offset += count;
            return Ok(count);
        }
        if self.encrypted_offset >= self.encrypted.len() {
            if self.done {
                return Ok(0);
            }
            if let Err(error) = self.fill_next_chunk() {
                self.failure = Some(error);
                return Err(age_error_as_io(
                    self.failure.as_ref().expect("stored failure"),
                ));
            }
        }
        if self.encrypted_offset >= self.encrypted.len() {
            return Ok(0);
        }
        let count = (self.encrypted.len() - self.encrypted_offset).min(output.len());
        let source = self
            .encrypted
            .get(self.encrypted_offset..self.encrypted_offset + count)
            .ok_or_else(|| io::Error::other("age encrypted chunk is out of range"))?;
        output[..count].copy_from_slice(source);
        self.encrypted_offset += count;
        if self.encrypted_offset == self.encrypted.len() {
            self.encrypted.fill(0);
            self.encrypted.clear();
            self.encrypted_offset = 0;
        }
        Ok(count)
    }
}

impl<R: Read> Read for AgeEncryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.read_encrypted(output)
    }
}

/// A streaming age decryptor that implements [`Read`].
///
/// Construction parses and authenticates the age header and payload nonce. A
/// payload chunk is authenticated in full before any of its plaintext is
/// returned. A full-sized final chunk is accepted, and bytes after it are
/// rejected just as they are by [`crate::AgeFile::decrypt_reader`].
///
/// [`Debug`](std::fmt::Debug) is hand-written, and this is the one type in the
/// crate where a derive would have leaked. `pending` is a
/// `Zeroizing<Vec<u8>>` holding an already-authenticated plaintext chunk, and
/// `zeroize` derives `Debug` for `Zeroizing` by printing the wrapped value. A
/// derived implementation would therefore have put decrypted plaintext into any
/// log line or test failure that touched this value, which is the opposite of
/// what the `Zeroizing` wrapper is there to guarantee. The implementation
/// below prints the progress counters and the number of plaintext bytes waiting
/// to be handed out, and nothing else. It also does not require `R: Debug`, so
/// a caller is not asked to implement `Debug` on their own reader type to be
/// able to log this value.
pub struct AgeDecryptReader<R> {
    input: R,
    cipher: ChaCha20Poly1305,
    encrypted: Zeroizing<Vec<u8>>,
    pending: Zeroizing<Vec<u8>>,
    pending_offset: usize,
    counter: u64,
    total: usize,
    options: AgeReadOptions,
    done: bool,
    failure: Option<AgeError>,
}

impl<R> std::fmt::Debug for AgeDecryptReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeDecryptReader")
            .field("counter", &self.counter)
            .field("total", &self.total)
            .field(
                "pending",
                &self.pending.len().saturating_sub(self.pending_offset),
            )
            .field("done", &self.done)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl<R: Read> AgeDecryptReader<R> {
    /// Creates a decrypting reader for a binary age file.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for I/O errors, malformed input, no matching
    /// identity, an invalid header MAC, or a truncated payload nonce.
    pub fn new(input: R, identities: &[AgeIdentity]) -> Result<Self> {
        Self::new_with_options(input, identities, AgeReadOptions::default())
    }

    /// Creates a decrypting reader with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for invalid limits, I/O errors, malformed input,
    /// no matching identity, an invalid header MAC, or a truncated payload
    /// nonce.
    pub fn new_with_options(
        mut input: R,
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        if identities.is_empty() {
            return Err(AgeError::InvalidKey("at least one identity is required"));
        }
        let header = read_stream_header(&mut input, options)?;
        let file_key = unwrap_file_key(&header, identities)?;
        let mut nonce = Zeroizing::new([0u8; PAYLOAD_NONCE_LENGTH]);
        read_exact(&mut input, nonce.as_mut_slice())?;
        let payload_key = Zeroizing::new(hkdf_sha256(&file_key[..], &nonce[..], b"payload")?);
        let cipher = cipher_from_key(&payload_key[..])?;
        Ok(Self {
            input,
            cipher,
            encrypted: Zeroizing::new(vec![0u8; ENCRYPTED_CHUNK_SIZE]),
            pending: Zeroizing::new(Vec::new()),
            pending_offset: 0,
            counter: 0,
            total: 0,
            options,
            done: false,
            failure: None,
        })
    }

    /// Creates a low-level payload decrypting reader from a 32-byte payload
    /// key. `input` must begin at the first encrypted STREAM chunk, not at the
    /// age header or payload nonce.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when `payload_key` is not a valid ChaCha20-Poly1305
    /// key length or when `options` is invalid.
    pub fn from_payload_key(input: R, payload_key: &[u8], options: AgeReadOptions) -> Result<Self> {
        let options = options.validate()?;
        let cipher = cipher_from_key(payload_key)?;
        Ok(Self {
            input,
            cipher,
            encrypted: Zeroizing::new(vec![0u8; ENCRYPTED_CHUNK_SIZE]),
            pending: Zeroizing::new(Vec::new()),
            pending_offset: 0,
            counter: 0,
            total: 0,
            options,
            done: false,
            failure: None,
        })
    }

    /// Creates a low-level payload decrypting reader with default limits.
    ///
    /// # Errors
    ///
    /// Returns the same key errors as [`AgeDecryptReader::from_payload_key`].
    pub fn from_key(input: R, payload_key: &[u8]) -> Result<Self> {
        Self::from_payload_key(input, payload_key, AgeReadOptions::default())
    }

    /// Alias for [`AgeDecryptReader::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same key and option errors as
    /// [`AgeDecryptReader::from_payload_key`].
    pub fn new_with_payload_key(
        input: R,
        payload_key: &[u8],
        options: AgeReadOptions,
    ) -> Result<Self> {
        Self::from_payload_key(input, payload_key, options)
    }

    /// Consumes the decryptor and returns the encrypted source.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.input
    }

    /// Returns a shared reference to the encrypted source.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.input
    }

    /// Returns a mutable reference to the encrypted source.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.input
    }

    fn load_next_chunk(&mut self) -> Result<()> {
        let read = read_at_most(&mut self.input, self.encrypted.as_mut_slice())?;
        if read == 0 {
            return Err(AgeError::Truncated);
        }
        if read < TAG_LENGTH {
            return Err(AgeError::InvalidFormat("payload chunk is truncated"));
        }
        let plaintext_length = read - TAG_LENGTH;
        if plaintext_length == 0 && self.counter != 0 {
            return Err(AgeError::InvalidFormat(
                "payload contains an empty non-final chunk",
            ));
        }
        let ciphertext = self
            .encrypted
            .get(..read)
            .ok_or(AgeError::InvalidFormat("payload chunk is out of range"))?;
        let (decrypted, is_final) = if read < ENCRYPTED_CHUNK_SIZE {
            (
                decrypt_chunk(&self.cipher, ciphertext, self.counter, true)?
                    .ok_or(AgeError::AuthenticationFailed)?,
                true,
            )
        } else if let Some(decrypted) =
            decrypt_chunk(&self.cipher, ciphertext, self.counter, false)?
        {
            (decrypted, false)
        } else if let Some(decrypted) = decrypt_chunk(&self.cipher, ciphertext, self.counter, true)?
        {
            (decrypted, true)
        } else {
            return Err(AgeError::AuthenticationFailed);
        };
        if decrypted.len() != plaintext_length {
            return Err(AgeError::AuthenticationFailed);
        }
        self.total = self
            .total
            .checked_add(plaintext_length)
            .ok_or(AgeError::LimitExceeded("payload is too large"))?;
        if self.total > self.options.max_payload_bytes {
            return Err(AgeError::LimitExceeded("payload is too large"));
        }
        if is_final {
            reject_trailing_data(&mut self.input)?;
            self.done = true;
        } else {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(AgeError::Crypto("payload counter overflow"))?;
        }
        self.pending = Zeroizing::new(decrypted);
        self.pending_offset = 0;
        Ok(())
    }

    fn read_plaintext(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.failure.as_ref() {
            return Err(age_error_as_io(error));
        }
        if self.pending_offset >= self.pending.len() {
            if self.done {
                return Ok(0);
            }
            if let Err(error) = self.load_next_chunk() {
                self.failure = Some(error);
                return Err(age_error_as_io(
                    self.failure.as_ref().expect("stored failure"),
                ));
            }
        }
        if self.pending_offset >= self.pending.len() {
            return Ok(0);
        }
        let count = (self.pending.len() - self.pending_offset).min(output.len());
        let source = self
            .pending
            .get(self.pending_offset..self.pending_offset + count)
            .ok_or_else(|| io::Error::other("age plaintext chunk is out of range"))?;
        output[..count].copy_from_slice(source);
        self.pending_offset += count;
        if self.pending_offset == self.pending.len() {
            self.pending.as_mut_slice().fill(0);
            self.pending.clear();
            self.pending_offset = 0;
        }
        Ok(count)
    }
}

impl<R: Read> Read for AgeDecryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.read_plaintext(output)
    }
}

/// One decrypted STREAM chunk cached by [`AgeDecryptReaderAt`].
struct CachedChunk {
    index: u64,
    data: Vec<u8>,
}

impl Drop for CachedChunk {
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

/// Random access to the authenticated plaintext of a binary age file.
///
/// The constructor authenticates the final STREAM chunk before returning. At
/// most one decrypted chunk is cached, so opening a file does not buffer the
/// complete plaintext. [`ReaderAt`] can be used to request arbitrary
/// plaintext ranges; each requested chunk is authenticated before its bytes
/// are copied to the caller's buffer.
///
/// [`Debug`](std::fmt::Debug) is hand-written and prints the sizes and chunk
/// count, which is what identifies a failing random-access read. `cache` holds
/// an already-decrypted plaintext chunk behind a lock, and a derived
/// implementation would have printed it; the lock is also not taken here, so
/// formatting this value cannot block behind or panic on a poisoned one. It
/// does not require `R: Debug`, so a caller is not asked to implement `Debug`
/// on their own source type to be able to log this value.
pub struct AgeDecryptReaderAt<R> {
    source: R,
    cipher: ChaCha20Poly1305,
    encrypted_size: u64,
    payload_offset: u64,
    payload_size: u64,
    chunks: u64,
    plaintext_size: u64,
    cache: Mutex<Option<CachedChunk>>,
}

impl<R> std::fmt::Debug for AgeDecryptReaderAt<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgeDecryptReaderAt")
            .field("encrypted_size", &self.encrypted_size)
            .field("payload_offset", &self.payload_offset)
            .field("payload_size", &self.payload_size)
            .field("chunks", &self.chunks)
            .field("plaintext_size", &self.plaintext_size)
            .finish_non_exhaustive()
    }
}

impl<R: ReaderAt> AgeDecryptReaderAt<R> {
    /// Opens a random-access age file and returns its plaintext length through
    /// [`AgeDecryptReaderAt::plaintext_size`].
    ///
    /// `encrypted_size` may be supplied as either a `u64` or a platform-sized
    /// integer. The declared size must include exactly the encrypted payload;
    /// bytes outside that range are not inspected.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for invalid identities, malformed or unauthenticated
    /// headers, invalid encrypted sizes, truncated sources, or failure to
    /// authenticate the final chunk.
    pub fn new<S>(source: R, encrypted_size: S, identities: &[AgeIdentity]) -> Result<Self>
    where
        S: TryInto<u64>,
    {
        Self::new_with_options(
            source,
            encrypted_size,
            identities,
            AgeReadOptions::default(),
        )
    }

    /// Opens a random-access age file and returns the reader with its
    /// authenticated plaintext length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::new`].
    pub fn open<S>(source: R, encrypted_size: S, identities: &[AgeIdentity]) -> Result<(Self, u64)>
    where
        S: TryInto<u64>,
    {
        let reader = Self::new(source, encrypted_size, identities)?;
        let plaintext_size = reader.plaintext_size();
        Ok((reader, plaintext_size))
    }

    /// Opens a random-access age file with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::new`], plus invalid
    /// configured limits or a plaintext size above the configured limit.
    pub fn new_with_options<S>(
        mut source: R,
        encrypted_size: S,
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<Self>
    where
        S: TryInto<u64>,
    {
        let options = options.validate()?;
        if identities.is_empty() {
            return Err(AgeError::InvalidKey("at least one identity is required"));
        }
        let encrypted_size = encrypted_size
            .try_into()
            .map_err(|_| AgeError::InvalidFormat("invalid encrypted size"))?;
        let (header, header_size) = read_header_at(&mut source, encrypted_size, options)?;
        let file_key = unwrap_file_key(&header, identities)?;
        let payload_offset = header_size
            .checked_add(PAYLOAD_NONCE_LENGTH_U64)
            .ok_or(AgeError::LimitExceeded("encrypted file is too large"))?;
        if payload_offset > encrypted_size {
            return Err(AgeError::Truncated);
        }
        let mut nonce = Zeroizing::new([0u8; PAYLOAD_NONCE_LENGTH]);
        read_full_at(
            &mut source,
            nonce.as_mut_slice(),
            payload_offset - PAYLOAD_NONCE_LENGTH_U64,
        )?;
        let payload_size = encrypted_size - payload_offset;
        let chunks = encrypted_chunk_count(payload_size)?;
        let plaintext_size = plaintext_size(payload_size, chunks)?;
        let maximum_plaintext = u64::try_from(options.max_payload_bytes).unwrap_or(u64::MAX);
        if plaintext_size > maximum_plaintext {
            return Err(AgeError::LimitExceeded("payload is too large"));
        }
        let payload_key = Zeroizing::new(hkdf_sha256(&file_key[..], &nonce[..], b"payload")?);
        let cipher = cipher_from_key(&payload_key[..])?;
        let final_index = chunks - 1;
        let final_offset = final_index
            .checked_mul(ENCRYPTED_CHUNK_SIZE_U64)
            .ok_or(AgeError::LimitExceeded("encrypted file is too large"))?;
        let final_size = payload_size
            .checked_sub(final_offset)
            .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
        let final_size_usize = usize::try_from(final_size)
            .map_err(|_| AgeError::InvalidFormat("encrypted payload chunk is too large"))?;
        let mut final_chunk = Zeroizing::new(vec![0u8; final_size_usize]);
        read_full_at(
            &mut source,
            final_chunk.as_mut_slice(),
            payload_offset
                .checked_add(final_offset)
                .ok_or(AgeError::LimitExceeded("encrypted file is too large"))?,
        )?;
        let final_plaintext = decrypt_chunk(&cipher, &final_chunk, final_index, true)?
            .ok_or(AgeError::AuthenticationFailed)?;
        let expected_final_length = final_size
            .checked_sub(TAG_LENGTH_U64)
            .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
        if final_plaintext.len() as u64 != expected_final_length {
            return Err(AgeError::AuthenticationFailed);
        }
        Ok(Self {
            source,
            cipher,
            encrypted_size,
            payload_offset,
            payload_size,
            chunks,
            plaintext_size,
            cache: Mutex::new(Some(CachedChunk {
                index: final_index,
                data: final_plaintext,
            })),
        })
    }

    /// Creates a low-level payload random-access reader from a 32-byte
    /// payload key. `source` must contain the encrypted STREAM payload and
    /// `encrypted_size` must be exactly its length.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] for invalid sizes, invalid keys, or final-chunk
    /// authentication failure.
    pub fn from_payload_key<S>(source: R, payload_key: &[u8], payload_size: S) -> Result<Self>
    where
        S: TryInto<u64>,
    {
        Self::from_payload_key_with_options(
            source,
            payload_key,
            payload_size,
            AgeReadOptions::default(),
        )
    }

    /// Alias for [`AgeDecryptReaderAt::from_payload_key`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::from_payload_key`].
    pub fn new_with_payload_key<S>(source: R, payload_key: &[u8], payload_size: S) -> Result<Self>
    where
        S: TryInto<u64>,
    {
        Self::from_payload_key(source, payload_key, payload_size)
    }

    /// Creates a low-level payload random-access reader with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::from_payload_key`],
    /// plus invalid limits or a payload above the configured limit.
    pub fn from_payload_key_with_options<S>(
        mut source: R,
        payload_key: &[u8],
        payload_size: S,
        options: AgeReadOptions,
    ) -> Result<Self>
    where
        S: TryInto<u64>,
    {
        let options = options.validate()?;
        let payload_size = payload_size
            .try_into()
            .map_err(|_| AgeError::InvalidFormat("invalid encrypted size"))?;
        let chunks = encrypted_chunk_count(payload_size)?;
        let plaintext_size = plaintext_size(payload_size, chunks)?;
        let maximum_plaintext = u64::try_from(options.max_payload_bytes).unwrap_or(u64::MAX);
        if plaintext_size > maximum_plaintext {
            return Err(AgeError::LimitExceeded("payload is too large"));
        }
        let cipher = cipher_from_key(payload_key)?;
        let final_index = chunks - 1;
        let final_offset = final_index
            .checked_mul(ENCRYPTED_CHUNK_SIZE_U64)
            .ok_or(AgeError::LimitExceeded("encrypted file is too large"))?;
        let final_size = payload_size
            .checked_sub(final_offset)
            .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
        let final_size_usize = usize::try_from(final_size)
            .map_err(|_| AgeError::InvalidFormat("encrypted payload chunk is too large"))?;
        let mut final_chunk = Zeroizing::new(vec![0u8; final_size_usize]);
        read_full_at(&mut source, final_chunk.as_mut_slice(), final_offset)?;
        let final_plaintext = decrypt_chunk(&cipher, &final_chunk, final_index, true)?
            .ok_or(AgeError::AuthenticationFailed)?;
        let expected_final_length = final_size
            .checked_sub(TAG_LENGTH_U64)
            .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
        if final_plaintext.len() as u64 != expected_final_length {
            return Err(AgeError::AuthenticationFailed);
        }
        Ok(Self {
            source,
            cipher,
            encrypted_size: payload_size,
            payload_offset: 0,
            payload_size,
            chunks,
            plaintext_size,
            cache: Mutex::new(Some(CachedChunk {
                index: final_index,
                data: final_plaintext,
            })),
        })
    }

    /// Returns the authenticated plaintext length in bytes.
    #[must_use]
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    /// Returns the plaintext length as a platform-sized integer.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] if the authenticated length does
    /// not fit in `usize`.
    pub fn plaintext_size_usize(&self) -> io::Result<usize> {
        usize::try_from(self.plaintext_size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "age plaintext length does not fit in usize",
            )
        })
    }

    /// Alias for [`AgeDecryptReaderAt::plaintext_size`].
    #[must_use]
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_size()
    }

    /// Alias for [`AgeDecryptReaderAt::plaintext_size`].
    #[must_use]
    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_size()
    }

    /// Returns the plaintext length as `usize` when it fits.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] if the length does not fit in
    /// `usize`.
    pub fn len(&self) -> io::Result<usize> {
        self.plaintext_size_usize()
    }

    /// Returns the encrypted file size supplied to the constructor.
    #[must_use]
    pub fn encrypted_size(&self) -> u64 {
        self.encrypted_size
    }

    /// Returns whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plaintext_size == 0
    }

    /// Returns a shared reference to the encrypted random-access source.
    #[must_use]
    pub fn source(&self) -> &R {
        &self.source
    }

    /// Returns a mutable reference to the encrypted random-access source.
    pub fn source_mut(&mut self) -> &mut R {
        &mut self.source
    }

    /// Consumes the reader and returns the encrypted random-access source.
    #[must_use]
    pub fn into_source(self) -> R {
        self.source
    }

    /// Performs a random-access read and returns the number of bytes copied.
    ///
    /// This inherent method mirrors [`ReaderAt::read_at`] and is
    /// provided so callers do not need to import the trait explicitly. A
    /// short read returns an [`io::ErrorKind::UnexpectedEof`] error; no
    /// unauthenticated bytes are copied.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an out-of-range offset,
    /// [`io::ErrorKind::UnexpectedEof`] for a short range, and an I/O or
    /// authentication error when a source chunk cannot be read or verified.
    pub fn read_at<O>(&mut self, output: &mut [u8], offset: O) -> io::Result<usize>
    where
        O: TryInto<u64>,
    {
        let offset = offset.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "age plaintext offset is invalid",
            )
        })?;
        if offset > self.plaintext_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "age plaintext offset is out of range",
            ));
        }
        if output.is_empty() {
            return Ok(0);
        }
        if offset == self.plaintext_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "age plaintext offset is at end of file",
            ));
        }

        let mut copied = 0usize;
        let mut current = offset;
        while current < self.plaintext_size && copied < output.len() {
            let chunk_index = current / CHUNK_SIZE_U64;
            let plaintext_chunk_offset = current % CHUNK_SIZE_U64;
            let plaintext = self.chunk(chunk_index)?;
            let available = plaintext
                .len()
                .checked_sub(usize::try_from(plaintext_chunk_offset).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "age plaintext offset is too large",
                    )
                })?)
                .ok_or_else(|| io::Error::other("age plaintext chunk is out of range"))?;
            let count = available.min(output.len() - copied);
            let source_offset = usize::try_from(plaintext_chunk_offset).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "age offset is too large")
            })?;
            let source = plaintext
                .get(source_offset..source_offset + count)
                .ok_or_else(|| io::Error::other("age plaintext chunk is out of range"))?;
            output[copied..copied + count].copy_from_slice(source);
            copied += count;
            current = current
                .checked_add(u64::try_from(count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "age read length is too large")
                })?)
                .ok_or_else(|| io::Error::other("age plaintext offset overflow"))?;
        }
        if copied < output.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "age plaintext ended before the requested range",
            ))
        } else {
            Ok(copied)
        }
    }

    fn chunk(&mut self, index: u64) -> io::Result<Vec<u8>> {
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("age random-access cache lock poisoned"))?
            .as_ref()
            .filter(|cached| cached.index == index)
        {
            return Ok(cached.data.clone());
        }
        let encrypted_offset = index
            .checked_mul(ENCRYPTED_CHUNK_SIZE_U64)
            .ok_or_else(|| io::Error::other("age encrypted chunk offset overflow"))?;
        let encrypted_size = self
            .payload_size
            .checked_sub(encrypted_offset)
            .ok_or_else(|| io::Error::other("age encrypted chunk is out of range"))?;
        let encrypted_size = encrypted_size.min(ENCRYPTED_CHUNK_SIZE_U64);
        let encrypted_size = usize::try_from(encrypted_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "age chunk is too large"))?;
        let mut encrypted = Zeroizing::new(vec![0u8; encrypted_size]);
        read_full_at(
            &mut self.source,
            encrypted.as_mut_slice(),
            self.payload_offset
                .checked_add(encrypted_offset)
                .ok_or_else(|| io::Error::other("age encrypted offset overflow"))?,
        )
        .map_err(|error| age_error_as_io(&error))?;
        let plaintext = decrypt_chunk(&self.cipher, &encrypted, index, index + 1 == self.chunks)
            .map_err(|error| age_error_as_io(&error))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "age payload authentication failed",
                )
            })?;
        let expected_length = if index + 1 == self.chunks {
            encrypted_size - TAG_LENGTH
        } else {
            CHUNK_SIZE
        };
        if plaintext.len() != expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "age payload chunk length is invalid",
            ));
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("age random-access cache lock poisoned"))?;
        *cache = Some(CachedChunk {
            index,
            data: plaintext.clone(),
        });
        Ok(plaintext)
    }
}

impl<'a> AgeDecryptReaderAt<AgeSliceReaderAt<'a>> {
    /// Creates a random-access decrypting reader over an in-memory binary age
    /// file.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::new`].
    pub fn from_slice(ciphertext: &'a [u8], identities: &[AgeIdentity]) -> Result<Self> {
        Self::new(
            AgeSliceReaderAt::new(ciphertext),
            ciphertext.len(),
            identities,
        )
    }

    /// Creates a slice-backed random-access decrypting reader with explicit
    /// resource limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::new_with_options`].
    pub fn from_slice_with_options(
        ciphertext: &'a [u8],
        identities: &[AgeIdentity],
        options: AgeReadOptions,
    ) -> Result<Self> {
        Self::new_with_options(
            AgeSliceReaderAt::new(ciphertext),
            ciphertext.len(),
            identities,
            options,
        )
    }
}

impl<R: ReaderAt> ReaderAt for AgeDecryptReaderAt<R> {
    fn read_at(&mut self, output: &mut [u8], offset: u64) -> io::Result<usize> {
        AgeDecryptReaderAt::read_at(self, output, offset)
    }
}

/// A short alias for [`AgeDecryptReaderAt`].
pub type AgeReaderAt<R> = AgeDecryptReaderAt<R>;

/// Creates an [`AgeEncryptWriter`] using the supplied recipients.
///
/// # Errors
///
/// Returns the same errors as [`AgeEncryptWriter::new`].
pub fn encrypt_writer<W: Write>(
    output: W,
    recipients: &[AgeRecipient],
) -> Result<AgeEncryptWriter<W>> {
    AgeEncryptWriter::new(output, recipients)
}

/// Creates an [`AgeEncryptReader`] using the supplied recipients.
///
/// # Errors
///
/// Returns the same errors as [`AgeEncryptReader::new`].
pub fn encrypt_reader<R: Read>(
    input: R,
    recipients: &[AgeRecipient],
) -> Result<AgeEncryptReader<R>> {
    AgeEncryptReader::new(input, recipients)
}

/// Creates an [`AgeDecryptReader`] using the supplied identities.
///
/// # Errors
///
/// Returns the same errors as [`AgeDecryptReader::new`].
pub fn decrypt_reader<R: Read>(
    input: R,
    identities: &[AgeIdentity],
) -> Result<AgeDecryptReader<R>> {
    AgeDecryptReader::new(input, identities)
}

/// Creates an [`AgeDecryptReaderAt`] and returns it with its authenticated
/// plaintext length.
///
/// # Errors
///
/// Returns the same errors as [`AgeDecryptReaderAt::new`].
pub fn decrypt_reader_at<R, S>(
    source: R,
    encrypted_size: S,
    identities: &[AgeIdentity],
) -> Result<(AgeDecryptReaderAt<R>, u64)>
where
    R: ReaderAt,
    S: TryInto<u64>,
{
    let reader = AgeDecryptReaderAt::new(source, encrypted_size, identities)?;
    let plaintext_size = reader.plaintext_size();
    Ok((reader, plaintext_size))
}

/// Creates an [`AgeDecryptReaderAt`] with explicit resource limits and returns
/// it with its authenticated plaintext length.
///
/// # Errors
///
/// Returns the same errors as [`AgeDecryptReaderAt::new_with_options`].
pub fn decrypt_reader_at_with_options<R, S>(
    source: R,
    encrypted_size: S,
    identities: &[AgeIdentity],
    options: AgeReadOptions,
) -> Result<(AgeDecryptReaderAt<R>, u64)>
where
    R: ReaderAt,
    S: TryInto<u64>,
{
    let reader = AgeDecryptReaderAt::new_with_options(source, encrypted_size, identities, options)?;
    let plaintext_size = reader.plaintext_size();
    Ok((reader, plaintext_size))
}

/// Creates a random-access reader over an in-memory binary age file.
///
/// This convenience function uses a bounds-checked slice view and still
/// authenticates chunks lazily; it does not construct a second plaintext copy
/// of the file.
///
/// # Errors
///
/// Returns the same errors as [`AgeDecryptReaderAt::new`].
pub fn decrypt_reader_at_slice<'a>(
    ciphertext: &'a [u8],
    identities: &[AgeIdentity],
) -> Result<(AgeDecryptReaderAt<AgeSliceReaderAt<'a>>, u64)> {
    AgeDecryptReaderAt::from_slice(ciphertext, identities).map(|reader| {
        let plaintext_size = reader.plaintext_size();
        (reader, plaintext_size)
    })
}

/// Creates a slice-backed random-access decrypting reader with explicit
/// resource limits.
///
/// # Errors
///
/// Returns the same errors as [`AgeDecryptReaderAt::from_slice_with_options`].
pub fn decrypt_reader_at_slice_with_options<'a>(
    ciphertext: &'a [u8],
    identities: &[AgeIdentity],
    options: AgeReadOptions,
) -> Result<(AgeDecryptReaderAt<AgeSliceReaderAt<'a>>, u64)> {
    AgeDecryptReaderAt::from_slice_with_options(ciphertext, identities, options).map(|reader| {
        let plaintext_size = reader.plaintext_size();
        (reader, plaintext_size)
    })
}

impl AgeFile {
    /// Creates a streaming age encryptor.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptWriter::new`].
    pub fn encrypt_writer<W: Write>(
        output: W,
        recipients: &[AgeRecipient],
    ) -> Result<AgeEncryptWriter<W>> {
        AgeEncryptWriter::new(output, recipients)
    }

    /// Creates a streaming encrypting reader.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptReader::new`].
    pub fn encrypt_stream_reader<R: Read>(
        input: R,
        recipients: &[AgeRecipient],
    ) -> Result<AgeEncryptReader<R>> {
        AgeEncryptReader::new(input, recipients)
    }

    /// Alias for [`AgeFile::encrypt_stream_reader`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeEncryptReader::new`].
    pub fn encrypt_reader_stream<R: Read>(
        input: R,
        recipients: &[AgeRecipient],
    ) -> Result<AgeEncryptReader<R>> {
        Self::encrypt_stream_reader(input, recipients)
    }

    /// Creates a streaming decrypting reader.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReader::new`].
    pub fn decrypt_stream_reader<R: Read>(
        input: R,
        identities: &[AgeIdentity],
    ) -> Result<AgeDecryptReader<R>> {
        AgeDecryptReader::new(input, identities)
    }

    /// Alias for [`AgeFile::decrypt_stream_reader`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReader::new`].
    pub fn decrypt_reader_stream<R: Read>(
        input: R,
        identities: &[AgeIdentity],
    ) -> Result<AgeDecryptReader<R>> {
        Self::decrypt_stream_reader(input, identities)
    }

    /// Creates a random-access decrypting reader and returns its plaintext
    /// length.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AgeDecryptReaderAt::new`].
    pub fn decrypt_reader_at<R, S>(
        source: R,
        encrypted_size: S,
        identities: &[AgeIdentity],
    ) -> Result<(AgeDecryptReaderAt<R>, u64)>
    where
        R: ReaderAt,
        S: TryInto<u64>,
    {
        decrypt_reader_at(source, encrypted_size, identities)
    }
}

fn encryption_material(recipients: &[AgeRecipient]) -> Result<(Vec<u8>, ChaCha20Poly1305)> {
    validate_recipients(recipients)?;
    let file_key = Zeroizing::new(random_array::<16>()?);
    let stanzas = recipients
        .iter()
        .map(|recipient| recipient.wrap(&file_key[..]))
        .collect::<Result<Vec<_>>>()?;
    let mut prefix = build_header(&stanzas, &file_key[..])?;
    let nonce = Zeroizing::new(random_array::<PAYLOAD_NONCE_LENGTH>()?);
    prefix.extend_from_slice(&nonce[..]);
    let payload_key = Zeroizing::new(hkdf_sha256(&file_key[..], &nonce[..], b"payload")?);
    let cipher = cipher_from_key(&payload_key[..])?;
    Ok((prefix, cipher))
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

fn cipher_from_key(key: &[u8]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 key length"))
}

fn encrypt_chunk(
    cipher: &ChaCha20Poly1305,
    counter: u64,
    is_final: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    build_chunk_nonce(counter, is_final, &mut nonce);
    let nonce = Nonce::try_from(&nonce[..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 encryption"))
}

fn decrypt_chunk(
    cipher: &ChaCha20Poly1305,
    ciphertext: &[u8],
    counter: u64,
    is_final: bool,
) -> Result<Option<Vec<u8>>> {
    let mut nonce = [0u8; 12];
    build_chunk_nonce(counter, is_final, &mut nonce);
    let nonce = Nonce::try_from(&nonce[..])
        .map_err(|_| AgeError::Crypto("ChaCha20-Poly1305 nonce length"))?;
    Ok(cipher.decrypt(&nonce, ciphertext).ok())
}

fn build_chunk_nonce(counter: u64, is_final: bool, nonce: &mut [u8; 12]) {
    nonce.fill(0);
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(is_final);
}

fn read_stream_header(input: &mut impl Read, options: AgeReadOptions) -> Result<ParsedHeader> {
    let mut bytes = Vec::new();
    let mut line_start = 0usize;
    loop {
        if bytes.len() >= options.max_header_bytes {
            return Err(AgeError::LimitExceeded("header is too large"));
        }
        let Some(byte) = read_one(input)? else {
            return match parse_header(&bytes, options) {
                Ok(_) => Err(AgeError::Truncated),
                Err(error) => Err(error),
            };
        };
        bytes.push(byte);
        if byte != b'\n' {
            continue;
        }
        let line = bytes
            .get(line_start..bytes.len().saturating_sub(1))
            .ok_or(AgeError::InvalidHeader("invalid header cursor"))?;
        if line.starts_with(b"--- ") {
            let (header, _) = parse_header(&bytes, options)?;
            return Ok(header);
        }
        line_start = bytes.len();
    }
}

fn read_header_at<R: ReaderAt>(
    source: &mut R,
    encrypted_size: u64,
    options: AgeReadOptions,
) -> Result<(ParsedHeader, u64)> {
    let mut bytes = Vec::new();
    let mut line_start = 0usize;
    loop {
        if bytes.len() >= options.max_header_bytes {
            return Err(AgeError::LimitExceeded("header is too large"));
        }
        let offset = u64::try_from(bytes.len())
            .map_err(|_| AgeError::LimitExceeded("header is too large"))?;
        if offset >= encrypted_size {
            return match parse_header(&bytes, options) {
                Ok(_) => Err(AgeError::Truncated),
                Err(error) => Err(error),
            };
        }
        let mut byte = [0u8; 1];
        read_full_at(source, &mut byte, offset)?;
        bytes.push(byte[0]);
        if byte[0] != b'\n' {
            continue;
        }
        let line = bytes
            .get(line_start..bytes.len().saturating_sub(1))
            .ok_or(AgeError::InvalidHeader("invalid header cursor"))?;
        if line.starts_with(b"--- ") {
            let (header, _) = parse_header(&bytes, options)?;
            let header_size = u64::try_from(bytes.len())
                .map_err(|_| AgeError::LimitExceeded("header is too large"))?;
            return Ok((header, header_size));
        }
        line_start = bytes.len();
    }
}

fn unwrap_file_key(
    header: &ParsedHeader,
    identities: &[AgeIdentity],
) -> Result<Zeroizing<Vec<u8>>> {
    if identities.is_empty() {
        return Err(AgeError::InvalidKey("at least one identity is required"));
    }
    if header
        .stanzas
        .iter()
        .any(|stanza| stanza.r#type == "scrypt")
        && header.stanzas.len() != 1
    {
        return Err(AgeError::MixedScrypt);
    }
    let mut ordered_identities: Vec<&AgeIdentity> = identities.iter().collect();
    ordered_identities.sort_by_key(|identity| {
        !matches!(
            identity,
            AgeIdentity::X25519 { .. } | AgeIdentity::Hybrid { .. } | AgeIdentity::Scrypt { .. }
        )
    });
    let mut file_key = None;
    for identity in ordered_identities {
        if let Some(candidate) = identity.file_key_from_stanzas(&header.stanzas)? {
            file_key = Some(candidate);
            break;
        }
    }
    let file_key = file_key.ok_or(AgeError::NoMatchingIdentity)?;
    verify_header_mac(&header.header_prefix, &header.mac, &file_key[..])?;
    Ok(file_key)
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

fn read_exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    if read_at_most(input, buffer)? == buffer.len() {
        Ok(())
    } else {
        Err(AgeError::Truncated)
    }
}

fn reject_trailing_data(input: &mut impl Read) -> Result<()> {
    if read_one(input)?.is_some() {
        return Err(AgeError::InvalidFormat("trailing data after payload"));
    }
    Ok(())
}

fn read_full_at<R: ReaderAt>(source: &mut R, buffer: &mut [u8], offset: u64) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    let read = match source.read_at(buffer, offset) {
        Ok(read) => read,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(AgeError::Truncated);
        }
        Err(error) => return Err(AgeError::Io(error)),
    };
    if read == buffer.len() {
        return Ok(());
    }
    if read < buffer.len() {
        return Err(AgeError::Truncated);
    }
    Err(AgeError::InvalidFormat("reader returned too much data"))
}

fn encrypted_chunk_count(encrypted_size: u64) -> Result<u64> {
    if encrypted_size == 0 {
        return Err(AgeError::InvalidFormat("invalid encrypted payload size"));
    }
    let addition = ENCRYPTED_CHUNK_SIZE_U64
        .checked_sub(1)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
    let count = encrypted_size
        .checked_add(addition)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?
        / ENCRYPTED_CHUNK_SIZE_U64;
    let tag_bytes = count
        .checked_mul(TAG_LENGTH_U64)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
    let plaintext_size = encrypted_size
        .checked_sub(tag_bytes)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
    let expected = if plaintext_size == 0 {
        1
    } else {
        plaintext_size
            .checked_add(CHUNK_SIZE_U64 - 1)
            .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?
            / CHUNK_SIZE_U64
    };
    if count != expected {
        return Err(AgeError::InvalidFormat("invalid encrypted payload size"));
    }
    Ok(count)
}

fn plaintext_size(encrypted_size: u64, chunks: u64) -> Result<u64> {
    let tags = chunks
        .checked_mul(TAG_LENGTH_U64)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))?;
    encrypted_size
        .checked_sub(tags)
        .ok_or(AgeError::InvalidFormat("invalid encrypted payload size"))
}

fn age_error_as_io(error: &AgeError) -> io::Error {
    let kind = match error {
        AgeError::Io(io_error) => io_error.kind(),
        AgeError::Truncated => io::ErrorKind::UnexpectedEof,
        AgeError::InvalidKey(_)
        | AgeError::InvalidFormat(_)
        | AgeError::Unsupported(_)
        | AgeError::InvalidHeader(_)
        | AgeError::InvalidMac
        | AgeError::AuthenticationFailed
        | AgeError::NoMatchingIdentity
        | AgeError::LimitExceeded(_)
        | AgeError::MixedScrypt
        | AgeError::InvalidWorkFactor
        | AgeError::ScryptWorkFactorTooLarge(_)
        | AgeError::Random
        | AgeError::Crypto(_)
        | AgeError::EmptyPassphrase
        | AgeError::NoSecretKeys
        | AgeError::NoRecipients
        | AgeError::InvalidIdentityLine { .. }
        | AgeError::MalformedRecipientLine { .. } => io::ErrorKind::InvalidData,
        AgeError::PassphraseMissing { .. } => io::ErrorKind::InvalidInput,
    };
    io::Error::new(kind, error.to_string())
}

fn clone_io_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}
