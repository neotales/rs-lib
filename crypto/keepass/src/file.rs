use std::{
    fmt,
    io::{Cursor, Read, Write},
};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use zeroize::Zeroize;

use crate::async_api::{KdbxAsyncRead, KdbxAsyncWrite, KdbxLoadFuture, KdbxSaveFuture};
use crate::cancellation::KdbxCancellation;
use crate::credentials::KdbxCredentials;
use crate::crypto;
use crate::error::{KdbxError, KdbxFailureKind};
use crate::limits::KdbxReadLimits;
use crate::model::{KeePassDatabase, VariantDictionary, VariantValue};
use crate::wire::{self, Compression as WireCompression, OuterCipher};

/// Outer encryption used when writing a KDBX 4.1 file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdbxOuterCipher {
    /// AES-256-CBC with PKCS#7 padding.
    Aes,
    /// ChaCha20 with a 12-byte nonce.
    ChaCha20,
}

/// Compression used when writing a KDBX file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdbxCompression {
    /// Store the inner header and XML without compression.
    None,
    /// Compress the inner header and XML with GZip.
    GZip,
}

/// KDF selected for a KDBX 4.1 write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdbxKdf {
    /// AES-KDF using `KdbxWriteOptions::aes_kdf_rounds`.
    Aes,
    /// Argon2d using the Argon2 fields in [`KdbxWriteOptions`].
    Argon2d,
    /// Argon2id using the Argon2 fields in [`KdbxWriteOptions`].
    Argon2id,
}

/// KDBX 4.1 writer settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdbxWriteOptions {
    /// Outer cipher.
    pub cipher: KdbxOuterCipher,
    /// Compression algorithm.
    pub compression: KdbxCompression,
    /// KDF algorithm.
    pub kdf: KdbxKdf,
    /// AES-KDF transform rounds. Used only when `kdf` is [`KdbxKdf::Aes`].
    pub aes_kdf_rounds: u64,
    /// Argon2 memory cost in kibibytes. Used only for Argon2 KDFs.
    pub argon2_memory_kib: u32,
    /// Argon2 time cost. Used only for Argon2 KDFs.
    pub argon2_time: u32,
    /// Argon2 lanes. Used only for Argon2 KDFs.
    pub argon2_lanes: u32,
    /// Maximum authenticated block size.
    pub hmac_block_bytes: usize,
}

/// KDBX 3.1 writer settings.
///
/// KDBX 3 has no Argon2 or ChaCha20 outer-cipher mode; this deliberately
/// writes only the format's AES-KDF/AES-CBC path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kdbx3WriteOptions {
    /// Compression algorithm.
    pub compression: KdbxCompression,
    /// AES-KDF transform rounds.
    pub aes_kdf_rounds: u64,
    /// Maximum hashed block size.
    pub block_bytes: usize,
}

impl Default for Kdbx3WriteOptions {
    fn default() -> Self {
        Self {
            compression: KdbxCompression::None,
            aes_kdf_rounds: 600_000,
            block_bytes: 1024 * 1024,
        }
    }
}

impl Default for KdbxWriteOptions {
    fn default() -> Self {
        Self {
            cipher: KdbxOuterCipher::Aes,
            compression: KdbxCompression::None,
            kdf: KdbxKdf::Aes,
            aes_kdf_rounds: 600_000,
            argon2_memory_kib: 64 * 1024,
            argon2_time: 10,
            argon2_lanes: 1,
            hmac_block_bytes: 1024 * 1024,
        }
    }
}

/// An incremental, block-authenticated KDBX 4 payload reader.
///
/// This type authenticates one KDBX 4 HMAC block at a time and returns only
/// after that block's HMAC has passed. It never concatenates the encrypted
/// payload and retains at most one caller-configured block plus small framing
/// state. A returned block is authenticated, but the complete file is not
/// authenticated until [`Self::finish`] succeeds (which also consumes the
/// terminal block and checks for trailing bytes).
///
/// This is deliberately a framing/authentication primitive, not a selected
/// entry API. It does not decrypt, decompress, parse XML, or retain a pending
/// result that could be mistaken for a fully validated entry.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `base_hmac` is the SHA-512
/// derived HMAC key that authenticates every block, so a derived `Debug` would
/// print 64 bytes of key material. `source` is the caller's own `R`, and
/// requiring `R: Debug` here would force a `Debug` bound onto a generic the
/// caller chose for their own reasons — the same trap
/// [`crate::async_api::KdbxLoadFuture`] avoids. What a caller debugging a
/// stalled or mis-framed stream actually needs is the block accounting: how far
/// the reader has got, and whether the terminal block has been authenticated.
/// The reader holds no decrypted bytes at all, so that accounting is the whole
/// of what is there to report.
pub struct Kdbx4AuthenticatedBlockReader<'a, R> {
    source: R,
    cancellation: KdbxCancellation<'a>,
    limits: KdbxReadLimits,
    input_bytes: u64,
    base_hmac: [u8; 64],
    next_index: u64,
    data_blocks: u64,
    terminal_authenticated: bool,
}

impl<R> fmt::Debug for Kdbx4AuthenticatedBlockReader<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note there is no `R: Debug` bound here. `source` is the caller's
        // type and is not printed; `base_hmac` is key material and is not
        // printed. Everything below is a counter or a flag.
        formatter
            .debug_struct("Kdbx4AuthenticatedBlockReader")
            .field("input_bytes", &self.input_bytes)
            .field("next_index", &self.next_index)
            .field("data_blocks", &self.data_blocks)
            .field("terminal_authenticated", &self.terminal_authenticated)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Read> Kdbx4AuthenticatedBlockReader<'a, R> {
    /// Opens a KDBX 4 stream and authenticates its outer header.
    ///
    /// The reader accepts only KDBX 4.0/4.1. KDBX 3 has a different
    /// stream-start and per-block checksum format and is intentionally not
    /// accepted by this primitive.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed or unsupported input, failed
    /// header hash/HMAC authentication, invalid credentials or KDF
    /// parameters, cancellation, or a resource-limit violation.
    pub fn open(
        mut source: R,
        credentials: &mut KdbxCredentials,
        limits: &KdbxReadLimits,
        cancellation: KdbxCancellation<'a>,
    ) -> Result<Self, KdbxError> {
        limits.validate()?;
        cancellation.checkpoint()?;
        let mut input_bytes = 0;
        let header = read_kdbx4_header(&mut source, limits, cancellation, &mut input_bytes)?;
        if (header.version >> 16) != 4 {
            return Err(KdbxError::unsupported(
                "KDBX 4 block streaming requires a KDBX 4 file",
            ));
        }

        let mut header_hash = [0u8; 32];
        read_exact_budgeted(
            &mut source,
            &mut header_hash,
            limits,
            cancellation,
            &mut input_bytes,
        )?;
        if !constant_time_equal(&header_hash, &crypto::sha256(&header.raw)) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX header hash validation failed",
            ));
        }

        let mut composite = credentials.composite_key()?;
        let (_cipher_key, base_hmac) = wire::derive_key(&header, &composite, limits)?;
        composite.zeroize();
        cancellation.checkpoint()?;

        let mut header_hmac = [0u8; 32];
        read_exact_budgeted(
            &mut source,
            &mut header_hmac,
            limits,
            cancellation,
            &mut input_bytes,
        )?;
        let expected_header_hmac = wire::header_hmac(&header.raw, &base_hmac)?;
        if !constant_time_equal(&header_hmac, &expected_header_hmac) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX header HMAC validation failed",
            ));
        }

        Ok(Self {
            source,
            cancellation,
            limits: *limits,
            input_bytes,
            base_hmac,
            next_index: 0,
            data_blocks: 0,
            terminal_authenticated: false,
        })
    }

    /// Authenticates and returns the next non-terminal ciphertext block.
    ///
    /// The returned vector is the current KDBX block only. A caller may
    /// process it before the rest of the file is authenticated, but must not
    /// treat a selected result as valid until [`Self::finish`] succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a truncated frame, failed block HMAC,
    /// cancellation, or a configured block/input/count limit.
    pub fn next_block(&mut self) -> Result<Option<Vec<u8>>, KdbxError> {
        self.cancellation.checkpoint()?;
        if self.terminal_authenticated {
            return Ok(None);
        }

        let mut frame = [0u8; 36];
        read_exact_budgeted(
            &mut self.source,
            &mut frame,
            &self.limits,
            self.cancellation,
            &mut self.input_bytes,
        )?;
        let length = u32::from_le_bytes(frame[32..36].try_into().expect("checked")) as usize;
        if length > self.limits.max_block_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX block exceeds the configured limit",
            ));
        }
        if length != 0 && self.data_blocks >= self.limits.max_blocks {
            return Err(KdbxError::resource_limit(
                "KDBX block count exceeds the configured limit",
            ));
        }
        let mut block = vec![0u8; length];
        read_exact_budgeted(
            &mut self.source,
            &mut block,
            &self.limits,
            self.cancellation,
            &mut self.input_bytes,
        )?;
        let expected = wire::block_tag(self.next_index, length, &block, &self.base_hmac)?;
        if !constant_time_equal(&frame[..32], &expected) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX payload HMAC validation failed",
            ));
        }
        self.cancellation.checkpoint()?;

        if length == 0 {
            self.ensure_eof()?;
            self.terminal_authenticated = true;
            return Ok(None);
        }
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| KdbxError::malformed("KDBX block index overflow"))?;
        self.data_blocks = self
            .data_blocks
            .checked_add(1)
            .ok_or_else(|| KdbxError::malformed("KDBX block count overflow"))?;
        Ok(Some(block))
    }

    /// Drains and authenticates all remaining blocks, including the terminal
    /// block, and verifies that no bytes follow it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::next_block`]. On success, the
    /// complete encrypted KDBX 4 file has passed outer-header and payload
    /// authentication and terminal framing checks.
    pub fn finish(&mut self) -> Result<(), KdbxError> {
        while self.next_block()?.is_some() {}
        Ok(())
    }

    /// Returns whether the authenticated terminal block and EOF have been
    /// consumed successfully.
    #[must_use]
    pub const fn is_fully_authenticated(&self) -> bool {
        self.terminal_authenticated
    }

    fn ensure_eof(&mut self) -> Result<(), KdbxError> {
        self.cancellation.checkpoint()?;
        let mut byte = [0u8; 1];
        let count = self
            .source
            .read(&mut byte)
            .map_err(|_| KdbxError::truncated())?;
        self.cancellation.checkpoint()?;
        if count == 0 {
            return Ok(());
        }
        if count != 1 {
            return Err(KdbxError::malformed("invalid KDBX input read"));
        }
        self.input_bytes = self
            .input_bytes
            .checked_add(1)
            .ok_or_else(|| KdbxError::resource_limit("KDBX input size overflow"))?;
        if self.input_bytes > self.limits.max_input_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX input exceeds the configured limit",
            ));
        }
        Err(KdbxError::malformed("trailing KDBX block data"))
    }
}

/// Synchronous KDBX file operations.
///
/// [`Debug`](std::fmt::Debug) is derived, and this is provably safe rather
/// than a shortcut: `KdbxFile` is a unit struct. Every operation is an
/// associated function taking its arguments, so there is no field, no buffer,
/// and no key material for a derive to print. The output is the type name.
#[derive(Debug)]
pub struct KdbxFile;

impl KdbxFile {
    /// Loads a KDBX 3.0/3.1 or 4.0/4.1 stream with bounded resources.
    ///
    /// The input stream is read into a bounded buffer before parsing. KDBX 4
    /// header and block authentication is completed before payload
    /// decryption; KDBX 3 remains a read-only compatibility path with its
    /// stream-start and checksum checks. The caller retains ownership of the
    /// stream and credentials.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, unsupported, unauthenticated, or
    /// over-limit input. Error text is safe diagnostic text and must not be
    /// treated as a secret-bearing authentication oracle.
    pub fn load(
        source: impl Read,
        credentials: &mut KdbxCredentials,
        limits: &KdbxReadLimits,
    ) -> Result<KeePassDatabase, KdbxError> {
        Self::load_with_cancellation(source, credentials, limits, KdbxCancellation::never())
    }

    /// Loads a bounded KDBX stream with cooperative cancellation checkpoints.
    ///
    /// Cancellation is checked before reading, between input chunks, and at
    /// major decoding stages. KDF, cryptography, and XML parsing are still
    /// synchronous and may finish before a pending request is observed.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::load`], or a cancelled error at a
    /// checkpoint. No database is returned on cancellation.
    pub fn load_with_cancellation(
        mut source: impl Read,
        credentials: &mut KdbxCredentials,
        limits: &KdbxReadLimits,
        cancellation: KdbxCancellation<'_>,
    ) -> Result<KeePassDatabase, KdbxError> {
        cancellation.checkpoint()?;
        limits.validate()?;
        let mut input = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            cancellation.checkpoint()?;
            let remaining = limits.max_input_bytes.saturating_sub(input.len() as u64);
            let read_len = (chunk.len() as u64).min(remaining.saturating_add(1)) as usize;
            let count = source.read(&mut chunk[..read_len]).map_err(io_error)?;
            cancellation.checkpoint()?;
            if count == 0 {
                break;
            }
            if count as u64 > remaining {
                return Err(KdbxError::resource_limit(
                    "KDBX input exceeds the configured limit",
                ));
            }
            input.extend_from_slice(&chunk[..count]);
        }
        let (header, consumed) = wire::parse_header(&input, limits)?;
        cancellation.checkpoint()?;
        let _version = header.version;
        if (header.version >> 16) == 3 {
            let mut composite = credentials.composite_key()?;
            let (cipher_key, _) = wire::derive_key(&header, &composite, limits)?;
            composite.zeroize();
            cancellation.checkpoint()?;
            let decrypted = match header.cipher {
                OuterCipher::Aes => {
                    crypto::aes_cbc_decrypt(&cipher_key, &header.iv, &input[consumed..])?
                }
                OuterCipher::ChaCha20 => {
                    return Err(KdbxError::unsupported("KDBX 3 ChaCha20 is not supported"));
                }
            };
            let expected_start = header
                .stream_start
                .as_deref()
                .ok_or_else(|| KdbxError::malformed("missing KDBX 3 stream-start bytes"))?;
            if decrypted.len() < 32 || !constant_time_equal(&decrypted[..32], expected_start) {
                return Err(KdbxError::new(
                    KdbxFailureKind::Authentication,
                    "KDBX 3 stream-start verification failed",
                ));
            }
            let hashed = wire::read_hashed_blocks(&decrypted[32..], limits)?;
            let payload = match header.compression {
                WireCompression::None => hashed,
                WireCompression::GZip => decompress(&hashed, limits)?,
            };
            cancellation.checkpoint()?;
            let inner = wire::InnerHeader {
                stream_id: header
                    .inner_stream_id
                    .ok_or_else(|| KdbxError::malformed("missing KDBX 3 inner stream ID"))?,
                stream_key: header
                    .inner_stream_key
                    .clone()
                    .ok_or_else(|| KdbxError::malformed("missing KDBX 3 inner stream key"))?,
                binaries: Vec::new(),
                consumed: 0,
            };
            let expected_header_hash = crypto::sha256(&header.raw);
            let mut database = crate::xml::parse_database(
                &payload,
                &inner,
                &[],
                0,
                true,
                Some(&expected_header_hash),
                limits,
            )?;
            apply_public_custom_data(&mut database, header.public_custom_data.as_ref());
            database.can_save_losslessly &= !header.has_unknown_fields;
            cancellation.checkpoint()?;
            return Ok(database);
        }
        let hash_end = consumed + 32;
        let hmac_end = hash_end + 32;
        if hmac_end > input.len() {
            return Err(KdbxError::truncated());
        }
        let expected_hash = crypto::sha256(&header.raw);
        if !constant_time_equal(&input[consumed..hash_end], &expected_hash) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX header hash validation failed",
            ));
        }
        let mut composite = credentials.composite_key()?;
        let (cipher_key, base_hmac) = wire::derive_key(&header, &composite, limits)?;
        composite.zeroize();
        cancellation.checkpoint()?;
        let expected_header_hmac = wire::header_hmac(&header.raw, &base_hmac)?;
        if !constant_time_equal(&input[hash_end..hmac_end], &expected_header_hmac) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX header HMAC validation failed",
            ));
        }
        let authenticated = wire::read_hmac_blocks(&input[hmac_end..], &base_hmac, limits)?;
        let decrypted = match header.cipher {
            OuterCipher::Aes => crypto::aes_cbc_decrypt(&cipher_key, &header.iv, &authenticated)?,
            OuterCipher::ChaCha20 => {
                let mut value = authenticated;
                crypto::chacha20_transform(&cipher_key, &header.iv, &mut value)?;
                value
            }
        };
        let payload = match header.compression {
            WireCompression::None => decrypted,
            WireCompression::GZip => decompress(&decrypted, limits)?,
        };
        cancellation.checkpoint()?;
        let inner = wire::InnerHeader::parse(&payload, limits)?;
        let (binaries, inner_stream_offset) =
            wire::parse_xml_payload(&payload[inner.consumed..], &inner, limits)?;
        let mut database = crate::xml::parse_database(
            &payload[inner.consumed..],
            &inner,
            &binaries,
            inner_stream_offset,
            false,
            None,
            limits,
        )?;
        apply_public_custom_data(&mut database, header.public_custom_data.as_ref());
        database.can_save_losslessly &= !header.has_unknown_fields;
        cancellation.checkpoint()?;
        Ok(database)
    }

    /// Saves a database as KDBX 4.1.
    ///
    /// A save uses fresh operating-system entropy for the master seed, IV,
    /// transform seed, and inner-stream key. Unsupported model state fails
    /// rather than silently dropping fields. The destination stream remains
    /// caller-owned and is not replaced or rewound.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid writer settings, unsupported model
    /// state, entropy failure, or I/O failure.
    pub fn save(
        database: &KeePassDatabase,
        destination: impl Write,
        credentials: &mut KdbxCredentials,
        options: KdbxWriteOptions,
        limits: &KdbxReadLimits,
    ) -> Result<(), KdbxError> {
        Self::save_with_cancellation(
            database,
            destination,
            credentials,
            options,
            limits,
            KdbxCancellation::never(),
        )
    }

    /// Saves a database as KDBX 4.1 with cooperative cancellation checkpoints.
    pub fn save_with_cancellation(
        database: &KeePassDatabase,
        destination: impl Write,
        credentials: &mut KdbxCredentials,
        options: KdbxWriteOptions,
        limits: &KdbxReadLimits,
        cancellation: KdbxCancellation<'_>,
    ) -> Result<(), KdbxError> {
        cancellation.checkpoint()?;
        limits.validate()?;
        validate_write_options(options, limits)?;
        if !database.can_save_losslessly {
            return Err(KdbxError::unsupported(
                "document cannot be saved losslessly",
            ));
        }
        let mut master_seed = [0; 32];
        let mut transform_seed = [0; 32];
        let mut kdf_salt = [0; 32];
        let mut iv = [0; 16];
        let mut inner_stream_key = [0; 64];
        fill_random(&mut master_seed)?;
        fill_random(&mut transform_seed)?;
        if options.kdf != KdbxKdf::Aes {
            fill_random(&mut kdf_salt)?;
        }
        fill_random(&mut iv)?;
        fill_random(&mut inner_stream_key)?;
        cancellation.checkpoint()?;
        let mut composite = credentials.composite_key()?;
        let transformed =
            derive_transformed_key(&composite, &transform_seed, &kdf_salt, options, limits)?;
        composite.zeroize();
        cancellation.checkpoint()?;
        let public_custom_data = effective_public_custom_data(database);
        let header = create_header(
            &master_seed,
            &transform_seed,
            &kdf_salt,
            &iv,
            &public_custom_data,
            options,
        )?;
        if header.len() > limits.max_header_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX outer header exceeds the configured limit",
            ));
        }
        let mut cipher_input = master_seed.to_vec();
        cipher_input.extend_from_slice(&transformed);
        let cipher_key = crypto::sha256(&cipher_input);
        cipher_input.zeroize();
        let mut hmac_input = master_seed.to_vec();
        hmac_input.extend_from_slice(&transformed);
        hmac_input.push(1);
        let base_hmac = crypto::sha512(&hmac_input);
        hmac_input.zeroize();
        let mut stream = crypto::InnerCipher::new(2, &inner_stream_key)?;
        let binaries: Vec<_> = if database.binary_pool.is_empty() {
            database
                .meta
                .legacy_binaries
                .iter()
                .map(|data| (data.clone(), false))
                .collect()
        } else {
            database
                .binary_pool
                .records()
                .iter()
                .map(|record| (record.data.clone(), record.protected))
                .collect()
        };
        let mut payload =
            crate::xml::write_inner_header(2, &inner_stream_key, &binaries, &mut stream);
        cancellation.checkpoint()?;
        let xml = crate::xml::write_database(
            database,
            &mut stream,
            crate::xml::BinaryStorage::InnerHeader,
        )?;
        if xml.len() as u64 > limits.max_xml_chars {
            return Err(KdbxError::resource_limit(
                "KDBX XML exceeds the configured limit",
            ));
        }
        payload.extend_from_slice(&xml);
        cancellation.checkpoint()?;
        if payload.len() as u64 > limits.max_decompressed_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX payload exceeds the decompression limit",
            ));
        }
        if options.compression == KdbxCompression::GZip {
            payload = compress(&payload, limits)?;
        }
        cancellation.checkpoint()?;
        let ciphertext = match options.cipher {
            KdbxOuterCipher::Aes => crypto::aes_cbc_encrypt(&cipher_key, &iv, &payload)?,
            KdbxOuterCipher::ChaCha20 => {
                let mut value = payload;
                crypto::chacha20_transform(&cipher_key, &iv[..12], &mut value)?;
                value
            }
        };
        let blocks =
            wire::write_hmac_blocks(&ciphertext, &base_hmac, options.hmac_block_bytes, limits)?;
        cancellation.checkpoint()?;
        let header_hash = crypto::sha256(&header);
        let header_hmac = wire::header_hmac(&header, &base_hmac)?;
        let output_size = (header.len() as u64)
            .saturating_add(header_hash.len() as u64)
            .saturating_add(header_hmac.len() as u64)
            .saturating_add(blocks.len() as u64);
        if output_size > limits.max_input_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX output exceeds the configured input limit",
            ));
        }
        let mut output = destination;
        cancellation.checkpoint()?;
        output.write_all(&header).map_err(io_error)?;
        cancellation.checkpoint()?;
        output.write_all(&header_hash).map_err(io_error)?;
        cancellation.checkpoint()?;
        output.write_all(&header_hmac).map_err(io_error)?;
        cancellation.checkpoint()?;
        output.write_all(&blocks).map_err(io_error)?;
        cancellation.checkpoint()?;
        Ok(())
    }

    /// Saves a database as a bounded KDBX 3.1 stream.
    ///
    /// KDBX 3 writing is intentionally limited to its defined AES-KDF/AES-CBC
    /// outer path. The XML is emitted in the legacy `Meta/Binaries` form, and
    /// the authenticated SHA-256 block framing plus the KDBX 3 stream-start
    /// marker are written explicitly. Public KDBX 4 header custom data and
    /// opaque XML extensions are rejected rather than dropped.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid options, unsupported model state,
    /// entropy failure, or I/O failure.
    pub fn save_kdbx3(
        database: &KeePassDatabase,
        destination: impl Write,
        credentials: &mut KdbxCredentials,
        options: Kdbx3WriteOptions,
        limits: &KdbxReadLimits,
    ) -> Result<(), KdbxError> {
        limits.validate()?;
        if options.aes_kdf_rounds == 0
            || options.aes_kdf_rounds > limits.max_aes_kdf_rounds
            || options.block_bytes == 0
            || options.block_bytes > limits.max_block_bytes
        {
            return Err(KdbxError::new(
                KdbxFailureKind::InvalidArgument,
                "invalid KDBX 3 writer options",
            ));
        }
        if !database.can_save_losslessly
            || !database.public_custom_data.items().is_empty()
            || !database.typed_public_custom_data.is_empty()
            || !kdbx3_xml_state_is_supported(database)
        {
            return Err(KdbxError::unsupported(
                "document cannot be saved losslessly as KDBX 3",
            ));
        }

        let mut master_seed = [0; 32];
        let mut transform_seed = [0; 32];
        let mut iv = [0; 16];
        let mut inner_stream_key = [0; 32];
        let mut stream_start = [0; 32];
        fill_random(&mut master_seed)?;
        fill_random(&mut transform_seed)?;
        fill_random(&mut iv)?;
        fill_random(&mut inner_stream_key)?;
        fill_random(&mut stream_start)?;

        let header = create_kdbx3_header(
            &master_seed,
            &transform_seed,
            &iv,
            &inner_stream_key,
            &stream_start,
            options,
        );
        if header.len() > limits.max_header_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX 3 outer header exceeds the configured limit",
            ));
        }
        let header_hash = crypto::sha256(&header);
        let mut composite = credentials.composite_key()?;
        let transformed =
            crypto::aes_kdf(&composite, &transform_seed, options.aes_kdf_rounds, limits)?;
        composite.zeroize();
        let mut stream = crypto::InnerCipher::new(2, &inner_stream_key)?;
        let xml = crate::xml::write_database_with_header_hash(
            database,
            &mut stream,
            crate::xml::BinaryStorage::LegacyXml,
            &header_hash,
        )?;
        if xml.len() as u64 > limits.max_xml_chars {
            return Err(KdbxError::resource_limit(
                "KDBX XML exceeds the configured limit",
            ));
        }
        let payload = match options.compression {
            KdbxCompression::None => xml,
            KdbxCompression::GZip => compress(&xml, limits)?,
        };
        let blocks = wire::write_hashed_blocks(&payload, options.block_bytes, limits)?;
        let mut plaintext = Vec::with_capacity(stream_start.len() + blocks.len());
        plaintext.extend_from_slice(&stream_start);
        plaintext.extend_from_slice(&blocks);
        let cipher_key = kdbx_outer_key(&master_seed, &transformed);
        let encrypted = crypto::aes_cbc_encrypt(&cipher_key, &iv, &plaintext)?;
        let output_size = (header.len() as u64).saturating_add(encrypted.len() as u64);
        if output_size > limits.max_input_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX 3 output exceeds the configured input limit",
            ));
        }
        let mut output = destination;
        output.write_all(&header).map_err(io_error)?;
        output.write_all(&encrypted).map_err(io_error)?;
        Ok(())
    }

    /// Creates a runtime-neutral future that loads a KDBX stream.
    ///
    /// The future polls the caller-owned asynchronous reader and applies the
    /// same bounded authentication and decoding rules as [`Self::load`].
    pub fn load_async<'a, R>(
        source: &'a mut R,
        credentials: &'a mut KdbxCredentials,
        limits: &'a KdbxReadLimits,
        cancellation: KdbxCancellation<'a>,
    ) -> KdbxLoadFuture<'a, R>
    where
        R: KdbxAsyncRead + ?Sized,
    {
        KdbxLoadFuture::new(source, credentials, limits, cancellation)
    }

    /// Creates a runtime-neutral future that saves a KDBX 4.1 stream.
    ///
    /// Encoding is completed before destination writes begin. The future then
    /// uses only `poll_write` and `poll_flush` for the asynchronous transport.
    pub fn save_async<'a, W>(
        database: &'a KeePassDatabase,
        destination: &'a mut W,
        credentials: &'a mut KdbxCredentials,
        options: KdbxWriteOptions,
        limits: &'a KdbxReadLimits,
        cancellation: KdbxCancellation<'a>,
    ) -> KdbxSaveFuture<'a, W>
    where
        W: KdbxAsyncWrite + ?Sized,
    {
        KdbxSaveFuture::new(
            database,
            destination,
            credentials,
            options,
            limits,
            cancellation,
        )
    }

    /// Opens a password-protected KDBX stream with the standard library limits.
    ///
    /// This is the concise form of [`Self::load_password`] for callers that do
    /// not need a custom resource policy. It reads all currently supported KDBX
    /// versions; the convenience method does not imply KDBX 4-only input.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::load`], including malformed,
    /// unauthenticated, unsupported, or over-limit input.
    pub fn open(
        source: impl Read,
        password: impl AsRef<[u8]>,
    ) -> Result<KeePassDatabase, KdbxError> {
        Self::load_password(source, password, &KdbxReadLimits::default())
    }

    /// Opens a KDBX stream with caller-supplied credentials and the standard
    /// library limits.
    ///
    /// This is useful when the vault uses a key file or an application-owned
    /// credential provider and the caller only needs to omit a custom limits
    /// value.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::load`].
    pub fn open_with_credentials(
        source: impl Read,
        credentials: &mut KdbxCredentials,
    ) -> Result<KeePassDatabase, KdbxError> {
        Self::load(source, credentials, &KdbxReadLimits::default())
    }

    /// Saves a database as KDBX 4.1 with the standard writer defaults.
    ///
    /// The convenience form uses [`KdbxWriteOptions::default`] and
    /// [`KdbxReadLimits::default`], creates password-only credentials for the
    /// duration of the operation, and leaves the destination stream owned by
    /// the caller. Use [`Self::save`] when selecting KDF, cipher, compression,
    /// block size, or resource limits.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::save`], plus invalid or empty
    /// password input.
    pub fn save_default(
        database: &KeePassDatabase,
        destination: impl Write,
        password: impl AsRef<[u8]>,
    ) -> Result<(), KdbxError> {
        let mut credentials = KdbxCredentials::password(password)?;
        Self::save(
            database,
            destination,
            &mut credentials,
            KdbxWriteOptions::default(),
            &KdbxReadLimits::default(),
        )
    }

    /// Saves a database as KDBX 4.1 with caller-supplied credentials and the
    /// standard writer defaults.
    ///
    /// This is the concise form for key-file and custom-provider credentials;
    /// use [`Self::save`] for fine-grained format and resource control.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::save`].
    pub fn save_default_with_credentials(
        database: &KeePassDatabase,
        destination: impl Write,
        credentials: &mut KdbxCredentials,
    ) -> Result<(), KdbxError> {
        Self::save(
            database,
            destination,
            credentials,
            KdbxWriteOptions::default(),
            &KdbxReadLimits::default(),
        )
    }

    /// Loads password-only credentials without exposing a long-lived password API.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::load`].
    pub fn load_password(
        source: impl Read,
        password: impl AsRef<[u8]>,
        limits: &KdbxReadLimits,
    ) -> Result<KeePassDatabase, KdbxError> {
        let mut credentials = KdbxCredentials::password(password)?;
        Self::load(source, &mut credentials, limits)
    }
}

fn validate_write_options(
    options: KdbxWriteOptions,
    limits: &KdbxReadLimits,
) -> Result<(), KdbxError> {
    let kdf_valid = match options.kdf {
        KdbxKdf::Aes => {
            options.aes_kdf_rounds > 0 && options.aes_kdf_rounds <= limits.max_aes_kdf_rounds
        }
        KdbxKdf::Argon2d | KdbxKdf::Argon2id => {
            let valid = options.argon2_memory_kib > 0
                && options.argon2_time > 0
                && options.argon2_lanes > 0;
            if valid {
                crypto::validate_argon2_limits(
                    options.argon2_memory_kib,
                    options.argon2_time,
                    options.argon2_lanes,
                    limits,
                )
                .map_err(KdbxError::argon2_limit)?;
            }
            valid
        }
    };
    if !kdf_valid
        || options.hmac_block_bytes == 0
        || options.hmac_block_bytes > limits.max_block_bytes
    {
        return Err(KdbxError::new(
            KdbxFailureKind::InvalidArgument,
            "invalid KDBX writer options",
        ));
    }
    Ok(())
}

fn derive_transformed_key(
    composite: &[u8],
    transform_seed: &[u8; 32],
    kdf_salt: &[u8; 32],
    options: KdbxWriteOptions,
    limits: &KdbxReadLimits,
) -> Result<[u8; 32], KdbxError> {
    match options.kdf {
        KdbxKdf::Aes => crypto::aes_kdf(composite, transform_seed, options.aes_kdf_rounds, limits),
        KdbxKdf::Argon2d => crypto::argon2(
            composite,
            kdf_salt,
            options.argon2_memory_kib,
            options.argon2_time,
            options.argon2_lanes,
            false,
            limits,
        ),
        KdbxKdf::Argon2id => crypto::argon2(
            composite,
            kdf_salt,
            options.argon2_memory_kib,
            options.argon2_time,
            options.argon2_lanes,
            true,
            limits,
        ),
    }
}

fn kdbx_outer_key(master_seed: &[u8; 32], transformed: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(master_seed);
    input.extend_from_slice(transformed);
    let key = crypto::sha256(&input);
    input.zeroize();
    key
}

fn compress(input: &[u8], limits: &KdbxReadLimits) -> Result<Vec<u8>, KdbxError> {
    if input.len() as u64 > limits.max_decompressed_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX payload exceeds the decompression limit",
        ));
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(input).map_err(io_error)?;
    let output = encoder.finish().map_err(io_error)?;
    if output.len() as u64 > limits.max_decompressed_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX payload exceeds the compression limit",
        ));
    }
    Ok(output)
}

fn kdbx3_xml_state_is_supported(database: &KeePassDatabase) -> bool {
    fn group_is_supported(group: &crate::model::Group) -> bool {
        group.entries.iter().all(entry_is_supported) && group.groups.iter().all(group_is_supported)
    }
    fn entry_is_supported(entry: &crate::model::Entry) -> bool {
        entry.quality_check.is_none() && entry.history.iter().all(entry_is_supported)
    }
    group_is_supported(&database.root)
}

fn read_kdbx4_header<R: Read>(
    source: &mut R,
    limits: &KdbxReadLimits,
    cancellation: KdbxCancellation<'_>,
    input_bytes: &mut u64,
) -> Result<wire::OuterHeader, KdbxError> {
    let mut header = Vec::with_capacity(limits.max_header_bytes.min(64 * 1024));
    let mut prefix = [0u8; 12];
    read_exact_budgeted(source, &mut prefix, limits, cancellation, input_bytes)?;
    header.extend_from_slice(&prefix);
    let version = u32::from_le_bytes(prefix[8..12].try_into().expect("checked"));
    if (version >> 16) != 4 {
        return Err(KdbxError::unsupported(
            "KDBX 4 block streaming requires a KDBX 4 file",
        ));
    }

    loop {
        if header.len() >= limits.max_header_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX header exceeds the configured limit",
            ));
        }
        let mut id = [0u8; 1];
        read_exact_budgeted(source, &mut id, limits, cancellation, input_bytes)?;
        header.extend_from_slice(&id);

        let mut length_bytes = [0u8; 4];
        read_exact_budgeted(source, &mut length_bytes, limits, cancellation, input_bytes)?;
        header.extend_from_slice(&length_bytes);
        let length = i32::from_le_bytes(length_bytes);
        if length < 0 {
            return Err(KdbxError::resource_limit(
                "KDBX outer header field exceeds the configured limit",
            ));
        }
        let length = length as usize;
        let value_end = header
            .len()
            .checked_add(length)
            .ok_or_else(|| KdbxError::resource_limit("KDBX header size overflow"))?;
        if value_end > limits.max_header_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX outer header field exceeds the configured limit",
            ));
        }
        let value_start = header.len();
        header.resize(value_end, 0);
        read_exact_budgeted(
            source,
            &mut header[value_start..],
            limits,
            cancellation,
            input_bytes,
        )?;
        if id[0] == 0 {
            break;
        }
    }
    wire::parse_header(&header, limits).map(|(header, _)| header)
}

fn read_exact_budgeted<R: Read>(
    source: &mut R,
    output: &mut [u8],
    limits: &KdbxReadLimits,
    cancellation: KdbxCancellation<'_>,
    input_bytes: &mut u64,
) -> Result<(), KdbxError> {
    let mut offset = 0;
    while offset < output.len() {
        cancellation.checkpoint()?;
        let remaining = limits.max_input_bytes.saturating_sub(*input_bytes);
        let requested = if remaining >= (output.len() - offset) as u64 {
            output.len() - offset
        } else {
            remaining as usize + 1
        };
        let count = source
            .read(&mut output[offset..offset + requested])
            .map_err(io_error)?;
        if count == 0 {
            return Err(KdbxError::truncated());
        }
        if count > requested {
            return Err(KdbxError::malformed("invalid KDBX input read"));
        }
        *input_bytes = input_bytes
            .checked_add(count as u64)
            .ok_or_else(|| KdbxError::resource_limit("KDBX input size overflow"))?;
        if *input_bytes > limits.max_input_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX input exceeds the configured limit",
            ));
        }
        offset += count;
    }
    cancellation.checkpoint()?;
    Ok(())
}

fn effective_public_custom_data(database: &KeePassDatabase) -> VariantDictionary {
    if !database.typed_public_custom_data.is_empty() {
        return database.typed_public_custom_data.clone();
    }
    let mut output = VariantDictionary::default();
    for item in database.public_custom_data.items() {
        output.set(item.key.clone(), item.value.clone());
    }
    output
}

fn apply_public_custom_data(database: &mut KeePassDatabase, data: Option<&VariantDictionary>) {
    database.public_custom_data = crate::model::CustomData::default();
    database.typed_public_custom_data = data.cloned().unwrap_or_default();
    if let Some(data) = data {
        for item in data.items() {
            if let VariantValue::String(value) = &item.value {
                database
                    .public_custom_data
                    .set(item.key.clone(), value.clone(), None);
            }
        }
    }
}

fn create_header(
    master_seed: &[u8; 32],
    transform_seed: &[u8; 32],
    kdf_salt: &[u8; 32],
    iv: &[u8; 16],
    public_custom_data: &VariantDictionary,
    options: KdbxWriteOptions,
) -> Result<Vec<u8>, KdbxError> {
    let mut output = Vec::new();
    output.extend_from_slice(&0x9aa2_d903u32.to_le_bytes());
    output.extend_from_slice(&0xb54b_fb67u32.to_le_bytes());
    output.extend_from_slice(&0x0004_0001u32.to_le_bytes());
    let cipher = if options.cipher == KdbxOuterCipher::Aes {
        [
            0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc,
            0x5a, 0xff,
        ]
    } else {
        [
            0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
            0xb5, 0x9a,
        ]
    };
    write_field(&mut output, 2, &cipher);
    let compression = if options.compression == KdbxCompression::GZip {
        1u32
    } else {
        0
    };
    write_field(&mut output, 3, &compression.to_le_bytes());
    write_field(&mut output, 4, master_seed);
    let nonce: &[u8] = if options.cipher == KdbxOuterCipher::Aes {
        iv
    } else {
        &iv[..12]
    };
    write_field(&mut output, 7, nonce);
    let kdf = match options.kdf {
        KdbxKdf::Aes => wire::aes_kdf_dictionary(transform_seed, options.aes_kdf_rounds),
        KdbxKdf::Argon2d => wire::argon2_kdf_dictionary(
            false,
            kdf_salt,
            options.argon2_memory_kib,
            options.argon2_time,
            options.argon2_lanes,
        ),
        KdbxKdf::Argon2id => wire::argon2_kdf_dictionary(
            true,
            kdf_salt,
            options.argon2_memory_kib,
            options.argon2_time,
            options.argon2_lanes,
        ),
    };
    write_field(&mut output, 11, &kdf);
    if !public_custom_data.is_empty() {
        write_field(
            &mut output,
            12,
            &wire::serialize_variant_dictionary(public_custom_data),
        );
    }
    write_field(&mut output, 0, &[13, 10, 13, 10]);
    Ok(output)
}

fn create_kdbx3_header(
    master_seed: &[u8; 32],
    transform_seed: &[u8; 32],
    iv: &[u8; 16],
    inner_stream_key: &[u8; 32],
    stream_start: &[u8; 32],
    options: Kdbx3WriteOptions,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&0x9aa2_d903u32.to_le_bytes());
    output.extend_from_slice(&0xb54b_fb67u32.to_le_bytes());
    output.extend_from_slice(&0x0003_0001u32.to_le_bytes());
    write_field_3(
        &mut output,
        2,
        &[
            0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc,
            0x5a, 0xff,
        ],
    );
    write_field_3(
        &mut output,
        3,
        &(if options.compression == KdbxCompression::GZip {
            1u32
        } else {
            0u32
        })
        .to_le_bytes(),
    );
    write_field_3(&mut output, 4, master_seed);
    write_field_3(&mut output, 5, transform_seed);
    write_field_3(&mut output, 6, &options.aes_kdf_rounds.to_le_bytes());
    write_field_3(&mut output, 7, iv);
    write_field_3(&mut output, 8, inner_stream_key);
    write_field_3(&mut output, 9, stream_start);
    write_field_3(&mut output, 10, &2u32.to_le_bytes());
    write_field_3(&mut output, 0, &[]);
    output
}

fn write_field_3(output: &mut Vec<u8>, id: u8, value: &[u8]) {
    output.push(id);
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("KDBX 3 header field length is bounded by the format")
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
}

fn write_field(output: &mut Vec<u8>, id: u8, value: &[u8]) {
    output.push(id);
    output.extend_from_slice(&(value.len() as i32).to_le_bytes());
    output.extend_from_slice(value);
}
fn fill_random(buffer: &mut [u8]) -> Result<(), KdbxError> {
    getrandom::fill(buffer).map_err(|_| {
        KdbxError::new(
            KdbxFailureKind::Authentication,
            "operating-system entropy is unavailable",
        )
    })
}
fn io_error(_: std::io::Error) -> KdbxError {
    KdbxError::new(KdbxFailureKind::Io, "KDBX stream I/O failed")
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}
fn decompress(input: &[u8], limits: &KdbxReadLimits) -> Result<Vec<u8>, KdbxError> {
    let decoder = GzDecoder::new(Cursor::new(input));
    let mut output = Vec::new();
    decoder
        .take(limits.max_decompressed_bytes.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|_| KdbxError::malformed("invalid KDBX GZip payload"))?;
    if output.len() as u64 > limits.max_decompressed_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX payload exceeds the decompression limit",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use flate2::{Compression, write::GzEncoder};

    use super::*;
    use crate::crypto::InnerCipher;

    const AES_CIPHER: [u8; 16] = [
        0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
        0xff,
    ];

    fn header_field(output: &mut Vec<u8>, id: u8, value: &[u8]) {
        output.push(id);
        output.extend_from_slice(&(value.len() as u16).to_le_bytes());
        output.extend_from_slice(value);
    }

    fn hashed_block(index: u32, data: &[u8]) -> Vec<u8> {
        let mut block = Vec::with_capacity(40 + data.len());
        block.extend_from_slice(&index.to_le_bytes());
        if data.is_empty() {
            block.extend_from_slice(&[0; 32]);
        } else {
            block.extend_from_slice(&crypto::sha256(data));
        }
        block.extend_from_slice(&(data.len() as i32).to_le_bytes());
        block.extend_from_slice(data);
        block
    }

    #[test]
    fn unknown_kdbx4_header_fields_block_lossless_save() {
        let limits = KdbxReadLimits::default();
        let mut bytes = Vec::new();
        KdbxFile::save(
            &KeePassDatabase::default(),
            &mut bytes,
            &mut KdbxCredentials::password("pw").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &limits,
        )
        .unwrap();
        let (header, consumed) = crate::wire::parse_header(&bytes, &limits).unwrap();
        let terminator = &header.raw[consumed - 9..];
        assert_eq!(terminator, [0, 4, 0, 0, 0, 13, 10, 13, 10]);
        let mut extended = header.raw[..consumed - 9].to_vec();
        extended.extend_from_slice(&[99, 4, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd]);
        extended.extend_from_slice(terminator);

        let mut credentials = KdbxCredentials::password("pw").unwrap();
        let composite = credentials.composite_key().unwrap();
        let (_, base_hmac) = crate::wire::derive_key(&header, &composite, &limits).unwrap();
        let hash = crypto::sha256(&extended);
        let hmac = crate::wire::header_hmac(&extended, &base_hmac).unwrap();
        let blocks = bytes[consumed + 64..].to_vec();
        bytes.clear();
        bytes.extend_from_slice(&extended);
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&hmac);
        bytes.extend_from_slice(&blocks);

        let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
        assert!(!loaded.can_save_losslessly);
        let error = KdbxFile::save(
            &loaded,
            &mut Vec::new(),
            &mut KdbxCredentials::password("pw").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &limits,
        )
        .unwrap_err();
        assert_eq!(error.kind, KdbxFailureKind::Unsupported);
    }

    #[test]
    fn opens_kdbx3_protected_legacy_binaries_and_shared_attachments() {
        let limits = KdbxReadLimits::default();
        let master_seed = [0x11; 32];
        let transform_seed = [0x22; 32];
        let iv = [0x33; 16];
        let inner_key = [0x44; 32];
        let stream_start = [0x55; 32];
        let rounds = 16_u64;

        let mut header = Vec::new();
        header.extend_from_slice(&0x9aa2_d903_u32.to_le_bytes());
        header.extend_from_slice(&0xb54b_fb67_u32.to_le_bytes());
        header.extend_from_slice(&0x0003_0001_u32.to_le_bytes());
        header_field(&mut header, 2, &AES_CIPHER);
        header_field(&mut header, 3, &0_u32.to_le_bytes());
        header_field(&mut header, 4, &master_seed);
        header_field(&mut header, 5, &transform_seed);
        header_field(&mut header, 6, &rounds.to_le_bytes());
        header_field(&mut header, 7, &iv);
        header_field(&mut header, 8, &inner_key);
        header_field(&mut header, 9, &stream_start);
        header_field(&mut header, 10, &2_u32.to_le_bytes());
        header_field(&mut header, 0, &[13, 10, 13, 10]);
        let header_hash = crypto::sha256(&header);

        let password_component = crypto::sha256(b"fixture-password");
        let composite = crypto::sha256(&password_component);
        let transformed = crypto::aes_kdf(&composite, &transform_seed, rounds, &limits).unwrap();
        let mut cipher_input = master_seed.to_vec();
        cipher_input.extend_from_slice(&transformed);
        let cipher_key = crypto::sha256(&cipher_input);

        let mut inner = InnerCipher::new(2, &inner_key).unwrap();
        let secret = b"legacy protected attachment".to_vec();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&secret).unwrap();
        let mut protected_compressed = encoder.finish().unwrap();
        inner.transform(&mut protected_compressed);
        let second = b"second legacy binary".to_vec();

        let mut password = b"password after binaries".to_vec();
        inner.transform(&mut password);
        let entry_uuid = crate::primitives::KdbxUuid::from_bytes([2; 16]).to_base64();
        let xml = format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<KeePassFile><Meta><Generator>KDBX3 fixture</Generator>",
                "<HeaderHash>{}</HeaderHash><Binaries>",
                "<Binary ID=\"7\" Compressed=\"True\" Protected=\"True\">{}</Binary>",
                "<Binary ID=\"2\">{}</Binary>",
                "</Binaries></Meta><Root><Group>",
                "<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>",
                "<Entry><UUID>{}</UUID><Name>legacy</Name>",
                "<String><Key>Password</Key><Value Protected=\"True\">{}</Value></String>",
                "<Binary><Key>shared-a.txt</Key><Value Ref=\"7\"/></Binary>",
                "<Binary><Key>shared-b.txt</Key><Value Ref=\"7\"/></Binary>",
                "<Binary><Key>second.txt</Key><Value Ref=\"2\"/></Binary>",
                "</Entry></Group></Root></KeePassFile>"
            ),
            STANDARD.encode(header_hash),
            STANDARD.encode(&protected_compressed),
            STANDARD.encode(&second),
            entry_uuid,
            STANDARD.encode(password),
        );
        let mut plaintext = stream_start.to_vec();
        plaintext.extend_from_slice(&hashed_block(0, xml.as_bytes()));
        plaintext.extend_from_slice(&hashed_block(1, &[]));
        let encrypted = crypto::aes_cbc_encrypt(&cipher_key, &iv, &plaintext).unwrap();

        let mut file = header;
        file.extend_from_slice(&encrypted);
        let loaded = KdbxFile::load_password(file.as_slice(), "fixture-password", &limits).unwrap();
        assert_eq!(loaded.meta.legacy_binaries[0], secret);
        assert_eq!(loaded.meta.legacy_binaries[1], second);
        assert_eq!(loaded.binary_pool.records()[0].data, second);
        assert_eq!(loaded.binary_pool.records()[1].data, secret);
        assert!(loaded.binary_pool.records()[1].protected);

        let entry = &loaded.root.entries[0];
        assert_eq!(entry.attachments[0].reference, 1);
        assert_eq!(entry.attachments[1].reference, 1);
        assert_eq!(entry.attachments[2].reference, 0);
        assert_eq!(
            entry
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "password after binaries"
        );
    }
}
