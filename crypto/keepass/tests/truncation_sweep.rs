//! An exhaustive truncation sweep over the KDBX parsers.
//!
//! The two sweeps already in this area — `crypto/crypto/tests/truncation_sweep.rs`
//! and `crypto/x509/tests/truncation_sweep.rs` — exist because every format
//! there puts a *caller-supplied* length in front of the bytes it governs: a
//! salt length, a metadata length, an SSH string length, a DER length. A parser
//! that reads one and slices without checking walks off the end of a buffer at a
//! length nobody picked in advance.
//!
//! KDBX is that, several times over, inside one file. A KDBX 4 container is a
//! twelve-byte signature and version, a sequence of header fields that each
//! carry their own little-endian length, a 32-byte header hash, a 32-byte header
//! HMAC, and then a chain of HMAC blocks each with a 36-byte frame whose last
//! four bytes are the length of the block that follows. Inside the authenticated
//! payload there is a second header of the same shape, an XML document with its
//! own limits, and a KDBX 3 variant that swaps the four-byte header lengths for
//! two-byte ones, replaces the HMAC block chain with a per-block SHA-256
//! index/hash chain, and hands the whole ciphertext to AES-CBC in one piece.
//! There is no single "the KDBX parser": there are several, and they do not
//! agree with each other about what a short input is.
//!
//! So this file enumerates, for every entry point a caller can hand bytes to:
//!
//! | entry point | input | what a cut can break |
//! |---|---|---|
//! | `KdbxFile::load` on KDBX 4.1 | a KDBX 4 file | header field lengths, header hash and HMAC, HMAC block frames |
//! | `KdbxFile::load` on KDBX 3.1 | a KDBX 3 file | two-byte header field lengths, AES-CBC block alignment, hashed block frames |
//! | `KdbxFile::load` on the committed `KeePassXC` file | a real KDBX 3.0.1 file | the same two-byte header walk, on bytes this crate did not write |
//! | `Kdbx4AuthenticatedBlockReader` | a KDBX 4 stream | an incrementally read header, and block frames read rather than sliced |
//! | `KdbxXml::import` | a KDBX XML document | element nesting, attribute parsing, and the value decoders behind them |
//! | `KdbxKeyFile::parse` and `read_key_file` | a key file | four formats, two of which are discriminated by length |
//! | `OtpUri::parse` | an `otpauth://` URI | query parameters and a Base32 secret |
//! | `KdbxUuid::from_base64`, `KdbxColor::parse`, `OtpSecret::from_base32` | XML attribute encodings | Base64 groups, `#RRGGBB` length, Base32 trailing bits |
//!
//! Every one of them asserts a typed error whose *kind and message* match the
//! offset the cut landed at: never a panic, never a hang, and never a read past
//! the end of the buffer. Asserting only `is_err()` would pass on any failure
//! at all; the crate's own `malformed.rs` does that for a KDBX 4 prefix, and
//! this file is the version that says *which* failure.
//!
//! # The property of a prefix, and the three ways a parser can be wrong about it
//!
//! A prefix of a well-formed container is *short*, never *malformed*. Every
//! field the cut did reach still has its correct length and its correct value;
//! every field it did not reach is missing. So a correct parser reports a
//! framing failure at every offset, and the sweep's real content is the
//! negative claim: a cut may never produce a *content* failure — an
//! `Authentication` failure, an `Unsupported` failure, or a `ResourceLimit`
//! failure that is not about the cut.
//!
//! KDBX makes that claim sharper than the other two sweeps, because the three
//! container parsers in this crate disagree about it, and the disagreements are
//! the interesting content:
//!
//! - A cut inside a KDBX 4 or KDBX 3 **header field value** is reported as
//!   `ResourceLimit` ("KDBX outer header field exceeds the configured limit"),
//!   because the length is read out of the bytes and the check that catches the
//!   over-read is the limit check. A cut inside the field's **id or length
//!   bytes** is `Truncated`. The two are one byte apart and mean different
//!   things.
//! - A cut inside a KDBX 4 **block body** is `Malformed` ("truncated KDBX
//!   block"), because `read_hmac_blocks` slices. The *same cut* through
//!   `Kdbx4AuthenticatedBlockReader` is `Truncated`, because that reader reads.
//!   One wire format, two implementations, two different typed answers, both
//!   correct.
//! - A cut in a KDBX 3 **ciphertext** that is not on a 16-byte boundary is
//!   `Malformed` ("invalid AES-CBC input"). At a boundary, PKCS#7 usually
//!   rejects the short buffer with an `Authentication` error; because the
//!   fixture is randomized, a valid padding suffix can occur by chance and move
//!   the failure downstream to stream-start verification or a typed truncation.
//!
//! # No cut of a KDBX 4 file is ever an authentication failure
//!
//! This is a property of prefixes, not of the parser, and it is worth stating
//! because it is counter-intuitive. The header hash covers the header bytes and
//! the header HMAC covers the same bytes: both authenticate a region that lies
//! entirely *before* the cut. A prefix therefore always contains both in full
//! and both always verify, and the only failures left are framing ones. The
//! `Authentication` classification is real and reachable — from a full-length
//! file with one byte changed, and from the wrong password — and the sweep
//! asserts those as controls, so that the absence is a claim about prefixes
//! rather than a claim that the parser never authenticates.
//!
//! # What a cut cannot reach, and why that is a fact about the format
//!
//! Four parsers inside this crate are *not* covered here, and the reason is not
//! that they were overlooked: no prefix of any KDBX file reaches them, because
//! the outer authentication stands in front of them. That is worth writing down
//! rather than leaving to be discovered, because it is the difference between
//! "this parser has no truncation bugs" and "no truncation can get here".
//!
//! - **The inner header.** KDBX 4's payload is a second header of five-byte
//!   fields with four-byte lengths, carrying the inner stream ID, the inner
//!   stream key, and the binary pool. It exists only after every HMAC block has
//!   verified, and every block verifies only for a complete file, so
//!   `InnerHeader::parse` is reached at exactly one length. Injecting an
//!   off-by-one into its five-byte field check, or deleting its bounds check
//!   altogether, leaves this file green.
//! - **The KDF dictionary and the public custom-data dictionary.** The KDF
//!   parameters are a header *field value*, so the header's own field-length
//!   check rejects every cut inside them before `parse_kdf` runs, and
//!   `read_value` — the four-byte length reader both dictionaries share — is
//!   never handed a short buffer. The variant dictionary is behind the inner
//!   header's gate as well.
//! - **The protected XML payload.** The inner stream's `Salsa20` or `ChaCha20`
//!   transform, the Base64 decode of a protected value, and the legacy binary
//!   references all run on the authenticated payload, so they are reached at one
//!   length. `KdbxXml::import` cannot reach them either: it refuses a document
//!   with a protected payload outright, which is a control in this file.
//! - **The KDBX 3 hashed block bodies.** Nearly so. KDBX 3 decrypts and unpads
//!   the whole ciphertext *before* it reads a single hashed block, so a cut that
//!   is not a whole number of blocks never gets there, and a cut that is only
//!   gets there when the decrypted padding happens to verify — about one aligned
//!   cut in 256, which is a coin toss per file rather than a guarantee. The
//!   bounds check in `read_hashed_blocks` is load-bearing — delete it and the cut
//!   that would have reached it panics on the slice instead — but no truncation
//!   sweep of a KDBX 3 file can prove that, because it needs a ciphertext that
//!   decrypts *and* unpads *and* stops mid-block, and the writer will not produce
//!   one. The unit test in `wire.rs` is the right home for that check, and this
//!   file does not pretend to cover it.
//!
//! The first three of those are properties of the format: an authenticated
//! container cannot hand its payload to a parser until the whole container has
//! been authenticated, so there is no prefix that reaches them. The fourth is a
//! gap, and it is the one to close if this area grows a fuzz target.
//!
//! # Truncation coverage is not validity coverage
//!
//! Everything in this file is a *short* input. A sweep that only truncates can
//! never find a defect where well-formed input is rejected, because it never
//! presents the parser with a complete, valid document except at exactly one
//! length. Issue #41 is that defect: `parse_time_number` in the X.509
//! OpenSSH-certificate converter accumulated a decimal year into a `u8`, so no
//! four-digit year could be parsed, and every certificate with a `GeneralizedTime`
//! validity — which RFC 5280 requires for any date on or after 2050 — was
//! rejected. A truncation sweep of that parser would have been green, because
//! truncation never produces a four-digit year. So a green run of this file
//! means "no cut of these fixtures is mis-parsed, over-read, or accepted". It
//! does not mean "these parsers accept every valid input", and it should not be
//! cited as evidence that they do.
//!
//! # Cost, and where the fixture sizes come from
//!
//! The fixtures are the smallest real ones each format allows: an empty
//! `KeePassDatabase`, written once per test with the crate's own writer. That is
//! 2123 bytes for KDBX 4.1, 2106 for KDBX 3.1, and 1652 of XML, and those sizes
//! are asserted rather than assumed, so a change to the writer's output fails
//! here instead of silently changing what is swept.
//!
//! A KDBX file cannot be made much smaller: the writer emits a fixed
//! `KeePassFile` schema, so an empty database is already close to the floor. A
//! full sweep of a KDBX 4 container is therefore 2123 parses, and a KDBX 4 parse
//! that gets past the header runs the KDF and four SHA-2 and HMAC constructions
//! over the 207-byte header. `cargo test` builds unoptimised, and unoptimised
//! SHA-256 is roughly two orders of magnitude slower than the hardware it is
//! written for, so the per-parse cost is dominated by hashes this crate cannot
//! make cheaper. Measured, one test at a time on a twelve-core machine that other
//! agents were also using: 0.58 s for the KDBX 4 container, 0.23 s for KDBX 3.1,
//! 0.12 s for the XML document, 0.60 s for the streaming reader, and under 10 ms
//! for the three small text sweeps. The file runs its eight tests in parallel for
//! about 0.6 s. That is the price of the exhaustive version of this file, and it
//! is paid in the default suite on purpose. The two sweeps next door take 0.02 s
//! and 0.10 s because their fixtures are 56 to 416 bytes; this one is slower
//! because a KDBX container cannot be under two kilobytes.
//!
//! The KDF cost is pinned to one AES-KDF round for the same reason the crypto
//! area pinned its PBKDF2 count to one: the iteration count lives in the *file*,
//! not in the settings struct, so a one-round fixture exercises the identical
//! `derive_key` path a real vault's file takes, at a cost the default suite can
//! afford. `KdbxFile::save` has no injectable seed, so the master seed, IV, and
//! inner-stream key of these two fixtures are fresh operating-system entropy on
//! every run. Their *bytes* differ run to run; their *layout* does not, and the
//! layout is what a truncation sweep enumerates, so the same offsets are covered
//! every time. The pinned lengths and field offsets are what make that claim
//! checkable.
//!
//! The one fixture that is *not* generated is the committed `KeePassXC` file, and
//! the reason it cannot be swept exhaustively is the same KDF cost in its worst
//! form: that file's header asks for 7,142,857 AES-KDF rounds, one parse of it
//! costs about 3.3 s unoptimised, and a sweep of its 1,566 lengths would take the
//! best part of half an hour. Every cut that stops *before* the header is complete fails
//! inside the header parser and never derives a key, so those 222 lengths — the
//! whole KDF-free prefix, and every offset the two-byte-length header walk has —
//! are swept exhaustively on the real bytes, and the offsets past it are covered
//! by the generated KDBX 3.1 fixture, whose header has the identical field
//! layout. That split is a cost decision and it is the reason the real fixture
//! appears in this file at all.
//!
//! # Determinism
//!
//! Every fixture is either a literal or written once from a fixed database and
//! fixed options. Nothing here generates a key per iteration, reads entropy per
//! iteration, or samples: each sweep enumerates every length from zero to the
//! full length, and the expected classification is *derived from the fixture's
//! own bytes* — the header field boundaries, the block framing, the key file's
//! element offsets, and the URI's parameter offsets are all read out of the
//! fixture and asserted — rather than from a table of offsets that could drift
//! away from the file they describe.
//!
//! # `neotales-keepass-platform`
//!
//! Nothing is swept there, and the reason is that neither of its two public
//! surfaces parses untrusted structured bytes. `PinnedBytes::from_bytes` takes a
//! caller-supplied *length* and pins a buffer of that size; it never reads a
//! length out of the data, and its length handling (page rounding, the pinning
//! ceiling) is unit-tested where it lives. `WindowsDpapiProvider::unprotect`
//! hands the caller's ciphertext to the operating system and compares the
//! *returned* plaintext length against the length the value was created with; it
//! contains no arithmetic on the input, and on a non-Windows target both
//! operations are stubs that report `PlatformUnavailable` for every input, so a
//! sweep over it would assert that a constant is a constant.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::fmt::Debug;
use std::ops::Range;

use neotales_keepass::{
    CredentialProvider, Kdbx3WriteOptions, Kdbx4AuthenticatedBlockReader, KdbxCancellation,
    KdbxColor, KdbxCompression, KdbxCredentials, KdbxError, KdbxFailureKind, KdbxFile, KdbxKdf,
    KdbxKeyFile, KdbxOuterCipher, KdbxReadLimits, KdbxUuid, KdbxWriteOptions, KdbxXml,
    KeePassDatabase, OtpSecret, OtpUri, read_key_file,
};

/// The password every generated fixture is written and opened with.
const PASSWORD: &[u8] = b"truncation sweep";

/// The password the committed `KeePassXC` fixture is written with.
const KEEPASSXC_PASSWORD: &[u8] = b"fixture-password";

/// The `hmac_block_bytes` the generated KDBX fixtures are written with.
///
/// Chosen so the payload is two data blocks and a terminal block rather than one
/// enormous block, because the interesting cuts are the ones that land inside a
/// frame and the ones that land inside a body, and a fixture with a single
/// 1,816-byte body has only one of each.
const HMAC_BLOCK_BYTES: usize = 1024;

/// The pinned KDBX 4.1 fixture length, in bytes.
///
/// Written from an empty `KeePassDatabase`: a 207-byte header, a 32-byte header
/// hash, a 32-byte header HMAC, a 1,024-byte data block in a 36-byte frame, a
/// 720-byte data block, and a terminal frame.
const KDBX4_LENGTH: usize = 2123;

/// The pinned KDBX 4.1 header length, in bytes.
const KDBX4_HEADER_END: usize = 207;

/// The KDBX 4.1 header hash and header HMAC lengths.
const KDBX4_HEADER_TRAILER: usize = 64;

/// The KDBX 4 HMAC block frame length: a 32-byte tag and a four-byte length.
const KDBX4_FRAME: usize = 36;

/// The pinned KDBX 3.1 fixture length, in bytes.
const KDBX3_LENGTH: usize = 2106;

/// The pinned KDBX 3.1 header length, in bytes.
///
/// Eleven bytes longer than the KDBX 4 one, because the KDBX 3 header carries
/// the three inner-stream fields (8, 9, and 10) that KDBX 4 moved into the
/// payload, and those three fields are exactly the ones whose *two-byte* length
/// encoding is a separate branch in the parser.
const KDBX3_HEADER_END: usize = 218;

/// The committed `KeePassXC` KDBX 3.0.1 fixture, 1,566 bytes.
const KEEPASSXC_FIXTURE: &[u8] = include_bytes!("fixtures/keepassxc-minimal.kdbx");

/// The AES-KDF rounds the committed `KeePassXC` fixture asks for, asserted against
/// its own header field 6 rather than quoted.
///
/// This is the number that makes an exhaustive sweep of that file impossible in
/// the default suite, so it is a constant here rather than a sentence in a
/// comment. Measured at roughly 3.3 s for one parse of that file, unoptimised.
const KEEPASSXC_AES_KDF_ROUNDS: u64 = 7_142_857;

/// The pinned header length of the committed `KeePassXC` fixture, in bytes.
const KEEPASSXC_HEADER_END: usize = 222;

/// A real `KeePass` XML key file, version 1.00, with a 32-byte Base64 key.
///
/// The key is the Base64 of the bytes `00 01 .. 1f`, which is what makes the v2
/// fixture's hash below reproducible.
const KEY_FILE_V1: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
    "<KeyFile>\n",
    "\t<Meta>\n",
    "\t\t<Version>1.00</Version>\n",
    "\t</Meta>\n",
    "\t<Key>\n",
    "\t\t<Data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</Data>\n",
    "\t</Key>\n",
    "</KeyFile>\n",
);

/// A real `KeePass` XML key file, version 2.0, with a 32-byte hex key and a hash.
///
/// `Hash` is the first four bytes of the SHA-256 of the key, upper-case hex, as
/// the format requires: `630DCD29`. The full-length parse succeeding in the
/// sweep below is what proves the hash is right, so the fixture does not depend
/// on this comment being correct.
const KEY_FILE_V2: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
    "<KeyFile>\n",
    "\t<Meta>\n",
    "\t\t<Version>2.0</Version>\n",
    "\t</Meta>\n",
    "\t<Key>\n",
    "\t\t<Data Hash=\"630DCD29\">",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "</Data>\n",
    "\t</Key>\n",
    "</KeyFile>\n",
);

/// A real `otpauth://` TOTP URI: a label, a Base32 secret, and five query
/// parameters in the order a URI library emits them.
const OTP_URI: &str = "otpauth://totp/example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\
                       &algorithm=SHA256&digits=8&period=30";

/// A strict, unpadded Base32 OTP secret.
const OTP_BASE32: &str = "JBSWY3DPEHPK3PXP";

/// The `KeePass` `#RRGGBB` colour syntax.
const COLOUR: &str = "#00AAff";

/// The generator string the crate's own XML writer puts in a document's `Meta`.
const GENERATOR: &str = "Neotales KeePass Rust";

/// The pinned KDBX 4.1 fixture's ciphertext length: two data blocks.
///
/// Pinned separately from the file length because it is the number that has to
/// add up: the file is the header, the authenticated trailer, three 36-byte
/// frames, and this many ciphertext bytes.
const KDBX4_CIPHERTEXT: usize = 1744;

/// The one-iteration writer options for the generated KDBX 4.1 fixture.
///
/// `aes_kdf_rounds: 1` is the whole point: the round count is read out of the
/// written file, so a one-round file is opened by the identical `derive_key`
/// path a real vault's file takes, and the sweep can afford the 1,852 parses
/// that reach it.
/// Everything else is the default shape, so the fixture is a file a real KDBX
/// reader would accept.
fn kdbx4_options() -> KdbxWriteOptions {
    KdbxWriteOptions {
        cipher: KdbxOuterCipher::Aes,
        compression: KdbxCompression::None,
        kdf: KdbxKdf::Aes,
        aes_kdf_rounds: 1,
        argon2_memory_kib: 8,
        argon2_time: 1,
        argon2_lanes: 1,
        hmac_block_bytes: HMAC_BLOCK_BYTES,
    }
}

/// Writes an empty database as a KDBX 4.1 file, once per call.
///
/// The call is made once per test and never once per iteration: the sweeps below
/// truncate a single buffer, so a per-iteration write would be a quadratic
/// number of key derivations on top of a quadratic number of parses.
fn kdbx4_fixture() -> Vec<u8> {
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut KdbxCredentials::password(PASSWORD).expect("fixture credentials"),
        kdbx4_options(),
        &KdbxReadLimits::default(),
    )
    .expect("fixture KDBX 4 file");
    bytes
}

/// Writes an empty database as a KDBX 3.1 file, once per call.
fn kdbx3_fixture() -> Vec<u8> {
    let mut bytes = Vec::new();
    KdbxFile::save_kdbx3(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut KdbxCredentials::password(PASSWORD).expect("fixture credentials"),
        Kdbx3WriteOptions {
            compression: KdbxCompression::None,
            aes_kdf_rounds: 1,
            block_bytes: HMAC_BLOCK_BYTES,
        },
        &KdbxReadLimits::default(),
    )
    .expect("fixture KDBX 3 file");
    bytes
}

/// Unwraps a typed failure, or panics with the context that was cut.
fn failure<T: Debug>(result: Result<T, KdbxError>, what: &str) -> KdbxError {
    match result {
        Ok(_) => panic!("{what} was accepted"),
        Err(error) => error,
    }
}

/// Asserts that an input failed in exactly one way.
fn assert_failure<T: Debug>(
    result: Result<T, KdbxError>,
    kind: KdbxFailureKind,
    message: &str,
    what: &str,
) {
    let error = failure(result, what);
    assert_eq!(
        error.kind, kind,
        "{what} should fail as {kind:?}, got {error}"
    );
    assert_eq!(error.message, message, "{what} should fail as {message:?}");
}

/// One outer-header field, and where its value lies.
struct HeaderField {
    /// Offset of the one-byte field id.
    start: usize,
    /// Offset of the first value byte.
    value: usize,
    /// Offset one past the last value byte.
    end: usize,
}

/// Walks a KDBX outer header and returns each field's boundaries.
///
/// This is a test-side reader, not a second copy of the parser: it reads the id
/// and the length and reports where the value lies, which is the minimum needed
/// to say *which* field a cut landed in. `width` is the length-field width,
/// four bytes for KDBX 4 and two for KDBX 3 — the branch the parser takes on the
/// version, and the reason one sweep of each version is not redundant.
fn header_fields(data: &[u8], width: usize) -> Vec<HeaderField> {
    let mut fields = Vec::new();
    let mut offset = 12;
    loop {
        let id = data[offset];
        let length = read_length(data, offset + 1, width);
        let value = offset + 1 + width;
        fields.push(HeaderField {
            start: offset,
            value,
            end: value + length,
        });
        offset = value + length;
        if id == 0 {
            return fields;
        }
    }
}

/// The offset one past the last field of a walked header.
fn header_end(fields: &[HeaderField]) -> usize {
    fields
        .last()
        .expect("a KDBX header ends with a terminator field")
        .end
}

/// Reads one little-endian header field length of the given width.
fn read_length(data: &[u8], offset: usize, width: usize) -> usize {
    let bytes = &data[offset..offset + width];
    if width == 2 {
        usize::from(u16::from_le_bytes(
            bytes.try_into().expect("two-byte length"),
        ))
    } else {
        usize::try_from(i32::from_le_bytes(
            bytes.try_into().expect("four-byte length"),
        ))
        .expect("a non-negative four-byte length")
    }
}

/// One HMAC block frame: where it starts, where it ends, and the block length
/// declared inside it.
struct Block {
    /// Offset of the 32-byte tag.
    start: usize,
    /// Offset one past the last ciphertext byte.
    end: usize,
    /// The block length read out of the frame.
    length: usize,
}

/// Walks a KDBX 4 HMAC block chain from the first frame to the terminal one.
///
/// The lengths come out of the frames themselves, so the regions this returns
/// are the regions the parser sees rather than a hard-coded offset list.
fn hmac_blocks(data: &[u8], first_frame: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut offset = first_frame;
    loop {
        let length = usize::try_from(u32::from_le_bytes(
            data[offset + 32..offset + 36]
                .try_into()
                .expect("four-byte block length"),
        ))
        .expect("a block length that fits in a usize");
        blocks.push(Block {
            start: offset,
            end: offset + KDBX4_FRAME + length,
            length,
        });
        offset += KDBX4_FRAME + length;
        if length == 0 {
            assert_eq!(offset, data.len(), "the terminal frame ends the file");
            return blocks;
        }
    }
}

/// The classification a KDBX 4 container must produce for a cut at `length`,
/// derived from the fixture's own header and block layout.
///
/// The two interleaved regions inside the header are the ones worth reading
/// twice: a cut inside a field's id or length bytes is a truncation, and a cut
/// inside the value that the length points at is a *resource limit*, because the
/// check that catches it is the limit check.
fn kdbx4_classification(bytes: &[u8], length: usize) -> (KdbxFailureKind, &'static str) {
    if length < 12 {
        return (KdbxFailureKind::Malformed, "invalid KDBX signatures");
    }
    let fields = header_fields(bytes, 4);
    for field in &fields {
        if length < field.value {
            return (KdbxFailureKind::Truncated, "input ended unexpectedly");
        }
        if length < field.end {
            return (
                KdbxFailureKind::ResourceLimit,
                "KDBX outer header field exceeds the configured limit",
            );
        }
    }
    let first_frame = header_end(&fields) + KDBX4_HEADER_TRAILER;
    if length < first_frame {
        return (KdbxFailureKind::Truncated, "input ended unexpectedly");
    }
    for block in hmac_blocks(bytes, first_frame) {
        if length < block.start + KDBX4_FRAME {
            return (KdbxFailureKind::Truncated, "input ended unexpectedly");
        }
        if length < block.end {
            return (KdbxFailureKind::Malformed, "truncated KDBX block");
        }
    }
    (KdbxFailureKind::Truncated, "input ended unexpectedly")
}

/// The classification a KDBX 3 container must produce for a cut at `length`.
///
/// The header regions are KDBX 4's with two-byte lengths. Past the header there
/// is no framing at all: KDBX 3 decrypts the whole ciphertext in one AES-CBC
/// call, so a non-block-aligned cut is rejected by the block-size check. For an
/// aligned cut, PKCS#7 can occasionally accept the random final plaintext byte;
/// the parser then reaches a later, typed truncation or stream-start failure.
fn kdbx3_classification(bytes: &[u8], length: usize) -> (KdbxFailureKind, &'static str) {
    if length < 12 {
        return (KdbxFailureKind::Malformed, "invalid KDBX signatures");
    }
    let fields = header_fields(bytes, 2);
    for field in &fields {
        if length < field.value {
            return (KdbxFailureKind::Truncated, "input ended unexpectedly");
        }
        if length < field.end {
            return (
                KdbxFailureKind::ResourceLimit,
                "KDBX outer header field exceeds the configured limit",
            );
        }
    }
    (KdbxFailureKind::Malformed, "invalid AES-CBC input")
}

/// The outcome of one prefix.
#[derive(Debug, Eq, PartialEq)]
enum Outcome {
    /// The prefix was accepted, which for a sweep is itself a result worth
    /// asserting rather than a hole in the coverage.
    Accepted,
    /// The prefix was rejected, with the kind and message it was rejected as.
    Rejected(KdbxFailureKind, String),
}

impl Outcome {
    /// The outcome a cut at `length` should produce.
    fn of(kind: KdbxFailureKind, message: &str) -> Self {
        Self::Rejected(kind, message.to_owned())
    }
}

/// Runs `parse` over every prefix of `bytes` and returns the outcome of each.
///
/// The returned vector is indexed by length, so index *n* is the outcome for the
/// first *n* bytes.
fn sweep<T: Debug>(
    bytes: &[u8],
    mut parse: impl FnMut(&[u8]) -> Result<T, KdbxError>,
) -> Vec<Outcome> {
    (0..=bytes.len())
        .map(|length| match parse(&bytes[..length]) {
            Ok(_) => Outcome::Accepted,
            Err(error) => Outcome::Rejected(error.kind, error.message),
        })
        .collect()
}

/// The lengths in `outcomes` that were accepted.
fn accepted(outcomes: &[Outcome]) -> Vec<usize> {
    outcomes
        .iter()
        .enumerate()
        .filter(|(_, outcome)| **outcome == Outcome::Accepted)
        .map(|(length, _)| length)
        .collect()
}

/// The message each rejected length reported, for comparison against a table.
fn messages(outcomes: &[Outcome]) -> Vec<Option<&str>> {
    outcomes
        .iter()
        .map(|outcome| match outcome {
            Outcome::Accepted => None,
            Outcome::Rejected(_, message) => Some(message.as_str()),
        })
        .collect()
}

/// Asserts that no length produced one of `kinds`, which is the negative claim a
/// prefix cannot make a content error.
fn assert_never(outcomes: &[Outcome], kinds: &[KdbxFailureKind], what: &str) {
    for (length, outcome) in outcomes.iter().enumerate() {
        if let Outcome::Rejected(kind, _) = outcome {
            assert!(
                !kinds.contains(kind),
                "{what} at length {length} produced {kind:?}, which a cut cannot mean"
            );
        }
    }
}

/// Asserts that every rejected length failed as `kind`.
fn assert_all_malformed(outcomes: &[Outcome], what: &str) {
    for (length, outcome) in outcomes.iter().enumerate() {
        if let Outcome::Rejected(kind, _) = outcome {
            assert_eq!(*kind, KdbxFailureKind::Malformed, "{what} length {length}");
        }
    }
}

/// Finds a byte substring, so a fixture's offsets are asserted against its own
/// bytes rather than against a number in a comment.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Whether a prefix ends inside a tag, an attribute, or a processing
/// instruction, as the KDBX XML reader sees it.
///
/// A prefix whose last `<` has no `>` after it is in the middle of a construct
/// the reader cannot finish, and that is the only way a cut of a KDBX XML
/// document — or of an XML key file — can be a *malformed* input rather than a
/// short one. A prefix of exactly `<` counts, and so does a prefix of a complete
/// XML declaration plus a lone `<`; both readers agree on that, and both were
/// checked against a prefix of every length to be sure.
fn ends_inside_a_tag(prefix: &[u8]) -> bool {
    prefix
        .iter()
        .rposition(|byte| *byte == b'<')
        .is_some_and(|start| !prefix[start..].contains(&b'>'))
}

/// Every length of a real KDBX 4.1 container, through `KdbxFile::load`.
///
/// This is the sweep the container format exists for: a header that is a chain
/// of self-declared lengths, a 64-byte authenticated trailer, then a chain of
/// blocks whose lengths are also read out of the bytes. The expected
/// classification is derived from the fixture's own layout, so this asserts
/// where the parser's checks fire rather than that it fails.
#[test]
fn every_truncation_of_a_kdbx4_container_is_a_typed_error() {
    let bytes = kdbx4_fixture();
    assert_eq!(bytes.len(), KDBX4_LENGTH, "the KDBX 4 fixture is pinned");
    let fields = header_fields(&bytes, 4);
    assert_eq!(
        header_end(&fields),
        KDBX4_HEADER_END,
        "the header is pinned"
    );
    assert_eq!(
        fields
            .iter()
            .map(|field| bytes[field.start])
            .collect::<Vec<_>>(),
        vec![2, 3, 4, 7, 11, 0],
        "cipher, compression, seed, IV, KDF, terminator"
    );
    let first_frame = KDBX4_HEADER_END + KDBX4_HEADER_TRAILER;
    let blocks = hmac_blocks(&bytes, first_frame);
    assert_eq!(
        blocks.iter().map(|block| block.length).collect::<Vec<_>>(),
        vec![1024, 720, 0],
        "the block framing is pinned"
    );
    assert_eq!(
        bytes.len() - first_frame,
        3 * KDBX4_FRAME + KDBX4_CIPHERTEXT,
        "the three frames and the ciphertext account for the whole file"
    );

    // The whole file opens, and the one thing it proves that no cut can: the
    // protected inner stream and the XML behind it are reachable, so the
    // failures below are the framing checks and not a parser that never gets
    // past them.
    let database = KdbxFile::load_password(bytes.as_slice(), PASSWORD, &KdbxReadLimits::default())
        .expect("the fixture opens");
    assert!(database.root.entries.is_empty());

    let outcomes = sweep(&bytes, |prefix| {
        KdbxFile::load_password(prefix, PASSWORD, &KdbxReadLimits::default())
    });
    assert_eq!(
        accepted(&outcomes),
        vec![KDBX4_LENGTH],
        "no proper prefix of a KDBX 4 file is a valid KDBX 4 file"
    );
    for (length, outcome) in outcomes.iter().enumerate().take(bytes.len()) {
        let (kind, message) = kdbx4_classification(&bytes, length);
        assert_eq!(
            *outcome,
            Outcome::of(kind, message),
            "KDBX 4 length {length} should be {kind:?} {message:?}"
        );
    }

    // The negative claim, stated on its own so a reader does not have to infer
    // it: no cut of a KDBX 4 file is an authentication failure, because the two
    // values that authenticate it both cover a region that lies entirely before
    // the cut. The controls below show the classification is reachable at full
    // length.
    assert_never(
        &outcomes,
        &[KdbxFailureKind::Authentication],
        "a KDBX 4 cut",
    );

    // The first length at which the KDF runs: the header and its hash are both
    // complete, so the parse gets as far as deriving a key and checking the
    // header HMAC, and both of those *pass*, because they cover bytes the cut did
    // not touch. The failure is the missing block frame.
    assert_eq!(
        outcomes[first_frame],
        Outcome::of(KdbxFailureKind::Truncated, "input ended unexpectedly"),
        "a complete header, hash, and HMAC with no block frame at all"
    );

    assert_kdbx4_named_offsets(&bytes, &outcomes, &fields, &blocks);
    assert_kdbx4_controls(&bytes, &fields, &blocks);
}

/// Re-asserts the KDBX 4 classification at the offsets worth naming.
///
/// The sweep above already covers every one of them; this is the claim about
/// *which* offsets are the interesting ones, written down rather than left to a
/// reader who has to diff a loop against a format. One byte either side of the
/// header's authenticated trailer is in the list because that is the boundary a
/// parser gets wrong by checking the hash and forgetting the HMAC.
fn assert_kdbx4_named_offsets(
    bytes: &[u8],
    outcomes: &[Outcome],
    fields: &[HeaderField],
    blocks: &[Block],
) {
    let first_frame = KDBX4_HEADER_END + KDBX4_HEADER_TRAILER;
    let mut named: Vec<usize> = vec![0, 1, 4, 8, 11, 12, 16];
    for field in fields {
        named.extend([field.start, field.value, field.end - 1, field.end]);
    }
    named.extend([
        first_frame - 1,
        KDBX4_HEADER_END + 31,
        KDBX4_HEADER_END + 32,
        KDBX4_HEADER_END + KDBX4_HEADER_TRAILER - 1,
        first_frame,
    ]);
    for block in blocks {
        named.extend([
            block.start,
            block.start + KDBX4_FRAME - 1,
            block.start + KDBX4_FRAME,
            block.end - 1,
        ]);
    }
    named.push(bytes.len() - 1);
    for length in named.into_iter().filter(|length| *length < bytes.len()) {
        let (kind, message) = kdbx4_classification(bytes, length);
        assert_eq!(
            outcomes[length],
            Outcome::of(kind, message),
            "KDBX 4 length {length} should be {kind:?} {message:?}"
        );
    }
}

/// Asserts the KDBX 4 failures a truncation cannot produce.
///
/// Each of these is a full-length input with one thing wrong, and together they
/// are the negative claim of the sweep above: the `Authentication`
/// classification is reachable, so its absence from every cut is a property of
/// prefixes and not of a parser that never authenticates.
fn assert_kdbx4_controls(bytes: &[u8], fields: &[HeaderField], blocks: &[Block]) {
    let first_frame = KDBX4_HEADER_END + KDBX4_HEADER_TRAILER;
    for (offset, message) in [
        (fields[2].value, "KDBX header hash validation failed"),
        (KDBX4_HEADER_END, "KDBX header hash validation failed"),
        (KDBX4_HEADER_END + 32, "KDBX header HMAC validation failed"),
        (blocks[0].start, "KDBX payload HMAC validation failed"),
        (
            blocks[0].start + KDBX4_FRAME,
            "KDBX payload HMAC validation failed",
        ),
        (blocks[2].start, "KDBX payload HMAC validation failed"),
    ] {
        let mut tampered = bytes.to_vec();
        tampered[offset] ^= 1;
        assert_failure(
            KdbxFile::load_password(tampered.as_slice(), PASSWORD, &KdbxReadLimits::default()),
            KdbxFailureKind::Authentication,
            message,
            &format!("one changed byte at {offset}"),
        );
    }
    // The wrong password is an authentication failure too, and it is the one a
    // caller actually meets.
    assert_failure(
        KdbxFile::load_password(bytes, b"wrong", &KdbxReadLimits::default()),
        KdbxFailureKind::Authentication,
        "KDBX header HMAC validation failed",
        "the fixture opened with the wrong password",
    );
    // Trailing data after the terminal block is rejected, which no truncation can
    // reach: a prefix has nothing after it.
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_failure(
        KdbxFile::load_password(trailing.as_slice(), PASSWORD, &KdbxReadLimits::default()),
        KdbxFailureKind::Malformed,
        "trailing KDBX block data",
        "one byte after the terminal block",
    );
    // And a declared block length past the end of the input, which is the
    // resource-limit check a truncation reaches *through the length field* rather
    // than through a short buffer.
    let mut oversized = bytes.to_vec();
    oversized[first_frame + 32..first_frame + 36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_failure(
        KdbxFile::load_password(oversized.as_slice(), PASSWORD, &KdbxReadLimits::default()),
        KdbxFailureKind::ResourceLimit,
        "KDBX block exceeds the configured limit",
        "a block length of u32::MAX",
    );
}

/// Every length of a real KDBX 3.1 container, through `KdbxFile::load`.
///
/// The second container format, and not a variant of the first: the header
/// lengths are two bytes rather than four, the authenticated trailer is gone,
/// and the block chain is a per-block SHA-256 index and hash chain read out of
/// a single AES-CBC decryption. Non-aligned cuts have a stable classification;
/// aligned cuts can reach later typed failures if random padding happens to pass.
#[test]
fn every_truncation_of_a_kdbx3_container_is_a_typed_error() {
    let bytes = kdbx3_fixture();
    assert_eq!(bytes.len(), KDBX3_LENGTH, "the KDBX 3 fixture is pinned");
    let fields = header_fields(&bytes, 2);
    assert_eq!(
        header_end(&fields),
        KDBX3_HEADER_END,
        "the header is pinned"
    );
    // The KDBX 3 field ids: the KDBX 4 set plus the three inner-stream fields
    // that KDBX 4 moved into the payload. This is the branch the two-byte length
    // encoding exists for, and it is why this sweep is not the KDBX 4 one with
    // a different constant.
    assert_eq!(
        fields
            .iter()
            .map(|field| bytes[field.start])
            .collect::<Vec<_>>(),
        vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 0],
        "the KDBX 3 field ids"
    );
    for (id, length) in [(5, 32), (6, 8), (8, 32), (9, 32), (10, 4)] {
        let field = fields
            .iter()
            .find(|field| bytes[field.start] == id)
            .expect("a KDBX 3 header field");
        assert_eq!(field.end - field.value, length, "field {id}'s length");
    }

    KdbxFile::load_password(bytes.as_slice(), PASSWORD, &KdbxReadLimits::default())
        .expect("the fixture opens");

    let outcomes = sweep(&bytes, |prefix| {
        KdbxFile::load_password(prefix, PASSWORD, &KdbxReadLimits::default())
    });
    assert_eq!(
        accepted(&outcomes),
        vec![KDBX3_LENGTH],
        "no proper prefix of a KDBX 3 file is a valid KDBX 3 file"
    );
    for (length, outcome) in outcomes.iter().enumerate().take(bytes.len()) {
        let ciphertext_len = length.saturating_sub(header_end(&fields));
        if length >= header_end(&fields) && ciphertext_len > 0 && ciphertext_len.is_multiple_of(16)
        {
            // A valid PKCS#7 suffix occurs with probability 1/255 for a random
            // block. The randomized fixture can therefore reach a later typed
            // failure instead of the padding error at any aligned truncation.
            assert_kdbx3_aligned_truncation(outcome, length);
            continue;
        }
        let (kind, message) = kdbx3_classification(&bytes, length);
        assert_eq!(
            *outcome,
            Outcome::of(kind, message),
            "KDBX 3 length {length} should be {kind:?} {message:?}"
        );
    }

    assert_kdbx3_named_offsets(&bytes, &outcomes, &fields);
    assert_kdbx3_controls(&bytes);
}

/// Re-asserts the KDBX 3 classification at the offsets worth naming.
///
/// The sweep above covers all of them. Two lists are here because the two
/// regions of this format are different in kind: the header has field
/// boundaries, and the ciphertext past it has *block* boundaries and nothing
/// else, so the second list is the arithmetic of the AES block size rather than
/// a walk of declared lengths.
fn assert_kdbx3_named_offsets(bytes: &[u8], outcomes: &[Outcome], fields: &[HeaderField]) {
    let mut named: Vec<usize> = vec![0, 11, 12];
    for field in fields {
        named.extend([
            field.start,
            field.start + 2,
            field.value,
            field.end - 1,
            field.end,
        ]);
    }
    named.extend([KDBX3_HEADER_END + 1, bytes.len() - 1]);
    for length in named.into_iter().filter(|length| *length < bytes.len()) {
        let (kind, message) = kdbx3_classification(bytes, length);
        assert_eq!(
            outcomes[length],
            Outcome::of(kind, message),
            "KDBX 3 length {length} should be {kind:?} {message:?}"
        );
    }

    // The block-size checks are deterministic away from block boundaries. At
    // aligned cuts, only rejection is stable: valid PKCS#7 padding can occur by
    // chance in the randomized fixture and advance parsing to a later failure.
    for (length, kind, message, what) in [
        (
            KDBX3_HEADER_END,
            KdbxFailureKind::Malformed,
            "invalid AES-CBC input",
            "an empty ciphertext is not a whole number of blocks",
        ),
        (
            KDBX3_HEADER_END + 15,
            KdbxFailureKind::Malformed,
            "invalid AES-CBC input",
            "one byte short of a whole block",
        ),
        (
            KDBX3_LENGTH - 1,
            KdbxFailureKind::Malformed,
            "invalid AES-CBC input",
            "one byte short of the fixture is not a whole number of blocks",
        ),
    ] {
        assert_eq!(outcomes[length], Outcome::of(kind, message), "{what}");
    }
    for length in [
        KDBX3_HEADER_END + 16,
        KDBX3_HEADER_END + 32,
        KDBX3_LENGTH - 16,
    ] {
        assert_kdbx3_aligned_truncation(&outcomes[length], length);
    }
}

/// Checks the bounded set of failures possible after an aligned truncation.
///
/// The writer's random ciphertext can make PKCS#7 reject immediately, or accept
/// by chance. In the latter case parsing can only fail authentication of the
/// short stream-start value or discover the incomplete hashed-block stream.
fn assert_kdbx3_aligned_truncation(outcome: &Outcome, length: usize) {
    match outcome {
        Outcome::Rejected(KdbxFailureKind::Authentication, message)
            if matches!(
                message.as_str(),
                "AES-CBC padding is invalid" | "KDBX 3 stream-start verification failed"
            ) => {}
        Outcome::Rejected(KdbxFailureKind::Truncated, message)
            if message == "input ended unexpectedly" => {}
        _ => panic!("unexpected KDBX 3 aligned-truncation outcome at length {length}: {outcome:?}"),
    }
}

/// Asserts the KDBX 3 failures a truncation cannot produce.
///
/// A wrong password, and data after the terminal hashed block. Neither is
/// reachable by truncation: a prefix keeps the stream-start marker intact and
/// has nothing after it.
fn assert_kdbx3_controls(bytes: &[u8]) {
    let wrong = failure(
        KdbxFile::load_password(bytes, b"wrong", &KdbxReadLimits::default()),
        "the fixture opened with the wrong password",
    );
    assert_eq!(
        wrong.kind,
        KdbxFailureKind::Authentication,
        "a wrong KDBX 3 password is an authentication failure"
    );
    assert!(
        matches!(
            wrong.message.as_str(),
            "AES-CBC padding is invalid" | "KDBX 3 stream-start verification failed"
        ),
        "a wrong KDBX 3 password fails as one of its two authentication checks, got {}",
        wrong.message
    );
    // Trailing data, which no truncation can produce: a prefix has nothing after
    // it. One byte is enough to make the ciphertext a non-multiple of the block
    // size, and the block-size check runs before the cipher does, so the failure
    // is a parameter one rather than the trailing-block one further in.
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_failure(
        KdbxFile::load_password(trailing.as_slice(), PASSWORD, &KdbxReadLimits::default()),
        KdbxFailureKind::Malformed,
        "invalid AES-CBC input",
        "one byte after the terminal hashed block",
    );
    // A whole extra block keeps the alignment, so the file gets past the
    // block-size check and fails on the ciphertext it now decrypts to instead.
    // Which check that is depends on the plaintext, so the assertion here is the
    // weaker one that a tampered KDBX 3 file does not load.
    let mut trailing_block = bytes.to_vec();
    trailing_block.extend_from_slice(&[0; 16]);
    assert!(
        KdbxFile::load_password(
            trailing_block.as_slice(),
            PASSWORD,
            &KdbxReadLimits::default()
        )
        .is_err(),
        "a KDBX 3 file with 16 bytes appended loaded"
    );
}

/// Every cut of the committed `KeePassXC` file that does not reach its KDF.
///
/// That file is a real `KeePassXC` 3.0.1 KDBX, and it is the only fixture here
/// this crate did not write, which is worth something a generated fixture cannot
/// be: the classification below is not an artefact of this crate's own writer.
/// Its header asks for 7,142,857 AES-KDF rounds, so every cut at or past the end
/// of the header costs about 3.3 s unoptimised and a sweep of its 1566 lengths
/// would take the best part of half an hour. Every cut *before* the header is
/// complete fails inside the header parser and never derives a key, so the whole
/// KDF-free prefix is swept here, and the offsets past it are covered by the
/// generated KDBX 3.1 fixture, whose header has the identical field layout.
#[test]
fn every_truncation_of_a_keepassxc_header_is_a_typed_error() {
    let bytes = KEEPASSXC_FIXTURE;
    assert_eq!(bytes.len(), 1566, "the committed fixture is pinned");
    assert_eq!(
        u32::from_le_bytes(bytes[8..12].try_into().expect("version")),
        0x0003_0001,
        "the committed fixture is KDBX 3.0.1"
    );
    let fields = header_fields(bytes, 2);
    assert_eq!(
        header_end(&fields),
        KEEPASSXC_HEADER_END,
        "the committed header length is pinned"
    );
    assert_eq!(
        fields
            .iter()
            .map(|field| bytes[field.start])
            .collect::<Vec<_>>(),
        vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 0],
        "the same field ids the generated KDBX 3 header has"
    );
    // The round count that makes the rest of this file unsweepable, read out of
    // the bytes rather than quoted.
    let rounds = fields
        .iter()
        .find(|field| bytes[field.start] == 6)
        .expect("the AES-KDF round field");
    assert_eq!(
        u64::from_le_bytes(
            bytes[rounds.value..rounds.end]
                .try_into()
                .expect("eight-byte round count")
        ),
        KEEPASSXC_AES_KDF_ROUNDS
    );

    // Swept over `0..KEEPASSXC_HEADER_END` exactly: the slice is one byte shorter
    // than the header, so the loop's inclusive range is every cut from nothing to
    // one byte short of a complete header, and the first cut that would reach the
    // KDF is the one this test does not make.
    let outcomes = sweep(&bytes[..KEEPASSXC_HEADER_END - 1], |prefix| {
        KdbxFile::load_password(prefix, KEEPASSXC_PASSWORD, &KdbxReadLimits::default())
    });
    assert_eq!(
        accepted(&outcomes),
        Vec::<usize>::new(),
        "no prefix is a file"
    );
    for (length, outcome) in outcomes.iter().enumerate() {
        let (kind, message) = kdbx3_classification(bytes, length);
        assert_eq!(
            *outcome,
            Outcome::of(kind, message),
            "`KeePassXC` length {length} should be {kind:?} {message:?}"
        );
    }
    // The same alternation the generated fixture has, on different bytes: three
    // bytes of id and two-byte length per field, so the truncation regions are
    // three wide where the KDBX 4 ones are five.
    for (length, kind, message, what) in [
        (
            14,
            KdbxFailureKind::Truncated,
            "input ended unexpectedly",
            "one byte short of the first field's length",
        ),
        (
            15,
            KdbxFailureKind::ResourceLimit,
            "KDBX outer header field exceeds the configured limit",
            "the first byte of the cipher field's value",
        ),
        (
            KEEPASSXC_HEADER_END - 1,
            KdbxFailureKind::ResourceLimit,
            "KDBX outer header field exceeds the configured limit",
            "one byte short of the terminator's value",
        ),
        (
            KEEPASSXC_HEADER_END - 5,
            KdbxFailureKind::Truncated,
            "input ended unexpectedly",
            "one byte of the terminator's two-byte length",
        ),
    ] {
        assert_eq!(outcomes[length], Outcome::of(kind, message), "{what}");
    }
    // The boundary the cost stops at, named so the gap is a number rather than an
    // omission: length 222 is the first cut that reaches the KDF, and this sweep
    // deliberately stops at 221.
    assert_eq!(
        outcomes.len(),
        KEEPASSXC_HEADER_END,
        "the sweep covers 0 to one byte short of the first KDF-bound cut"
    );
}

/// Every length of a real KDBX 4 stream, through the streaming block reader.
///
/// `Kdbx4AuthenticatedBlockReader` is a second, independent implementation of
/// the KDBX 4 framing — it reads the header incrementally from the stream
/// instead of slicing it out of a buffer, and it reads each block frame instead
/// of walking a length chain — so a fix to one would not be a fix to the other.
/// The comparison with the container sweep is the point of this test, and it is
/// not a small one: `KdbxFile::load` reports a cut inside a block body as
/// `Malformed` ("truncated KDBX block") because it slices, and this reader
/// reports the *same cut* as `Truncated` because it reads. Same bytes, same wire
/// format, two different typed answers, both of them correct.
#[test]
fn every_truncation_of_a_kdbx4_stream_is_a_typed_error() {
    let bytes = kdbx4_fixture();
    assert_eq!(bytes.len(), KDBX4_LENGTH, "the KDBX 4 fixture is pinned");
    let first_frame = KDBX4_HEADER_END + KDBX4_HEADER_TRAILER;

    // The complete operation, one loop over every length. `open` followed by
    // `finish` is the whole authenticated read, and this reader reads rather than
    // slices, so every cut short of the terminal frame is a truncation and nothing
    // else. That there is no region here where the classification changes is a
    // *result*, not a gap: the reader's per-length answer is uniform because a
    // short read is caught by the same check wherever it happens.
    //
    // The loop also carries the reader's documented contract, which is worth
    // pinning because it is the one place this crate's API accepts a short KDBX 4
    // file on purpose: `open` authenticates the header and stops, so it succeeds
    // for every length from the first complete frame onwards and the payload is
    // not its business — but it never claims the file is fully authenticated,
    // because it has not read the terminal block. `finish` is what makes that
    // claim, and every cut here fails before it can.
    for length in 0..bytes.len() {
        let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
        let what = format!("stream length {length}");
        let opened = open_stream(&bytes[..length], &mut credentials);
        if length < first_frame {
            // Short of the first complete frame the reader never opens, and the
            // truncated header is what it says.
            assert_failure(
                opened.map(|_| ()),
                KdbxFailureKind::Truncated,
                "input ended unexpectedly",
                &format!("{what} in open"),
            );
            continue;
        }
        let mut reader = opened
            .unwrap_or_else(|error| panic!("{what} failed in open, not in a block read: {error}"));
        assert!(
            !reader.is_fully_authenticated(),
            "{what} claims full authentication before the terminal block is read"
        );
        assert_failure(
            reader.finish(),
            KdbxFailureKind::Truncated,
            "input ended unexpectedly",
            &what,
        );
    }
    // The named boundaries, and the contrast with the container sweep spelled out
    // at four offsets: a complete header with no frame at all, a partial frame, a
    // frame with no body, and a body one byte short. All four are
    // `Truncated` here and the middle two are `Malformed` in
    // `every_truncation_of_a_kdbx4_container_is_a_typed_error`.
    for (length, note) in [
        (
            first_frame,
            "a complete header, hash, and HMAC with no block frame",
        ),
        (first_frame + 1, "one byte of the first block tag"),
        (
            first_frame + KDBX4_FRAME - 1,
            "one byte short of the first frame",
        ),
        (
            first_frame + KDBX4_FRAME,
            "a complete frame and no block body",
        ),
        (bytes.len() - 1, "one byte short of the terminal frame"),
    ] {
        let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
        let what = format!("{note} at {length}");
        let mut reader = open_stream(&bytes[..length], &mut credentials)
            .unwrap_or_else(|error| panic!("{what} failed in open: {error}"));
        assert_failure(
            reader.finish(),
            KdbxFailureKind::Truncated,
            "input ended unexpectedly",
            &what,
        );
    }

    // And the full stream, which is the only length at which `finish` succeeds.
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let mut reader = open_stream(&bytes, &mut credentials).expect("the fixture opens");
    let mut blocks = 0;
    while reader.next_block().expect("a block").is_some() {
        blocks += 1;
    }
    assert_eq!(blocks, 2, "the fixture's two data blocks");
    assert!(reader.is_fully_authenticated());
    reader.finish().expect("the terminal frame is consumed");

    assert_stream_controls(&bytes, first_frame);
}

/// Opens a prefix of a KDBX 4 stream with this crate's default limits and no
/// cancellation, which is every call the sweep makes.
///
/// The `never()` policy holds nothing, so the reader's cancellation lifetime is
/// `'static` and the helper hands one back without borrowing the prefix for it.
fn open_stream<'a>(
    prefix: &'a [u8],
    credentials: &'a mut KdbxCredentials,
) -> Result<Kdbx4AuthenticatedBlockReader<'static, &'a [u8]>, KdbxError> {
    Kdbx4AuthenticatedBlockReader::open(
        prefix,
        credentials,
        &KdbxReadLimits::default(),
        KdbxCancellation::never(),
    )
}

/// Asserts the streaming reader's failures a truncation cannot produce.
///
/// A changed byte in a block body authenticates as a *failed* block rather than a
/// short one, and that is the only authentication failure this reader can
/// report; trailing data after the terminal frame is a framing failure that a
/// prefix cannot reach either.
fn assert_stream_controls(bytes: &[u8], first_frame: usize) {
    let mut tampered = bytes.to_vec();
    tampered[first_frame + KDBX4_FRAME] ^= 1;
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let mut reader =
        open_stream(&tampered, &mut credentials).expect("the header still authenticates");
    assert_failure(
        reader.next_block(),
        KdbxFailureKind::Authentication,
        "KDBX payload HMAC validation failed",
        "one changed byte in the first block body",
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let mut reader =
        open_stream(&trailing, &mut credentials).expect("the header still authenticates");
    assert_failure(
        reader.finish(),
        KdbxFailureKind::Malformed,
        "trailing KDBX block data",
        "one byte after the terminal frame",
    );
    // The block-size limit, which is a policy check rather than a truncation one:
    // a cut cannot produce a block length over the limit, because the lengths in a
    // truncated file are the file's own. The reader has to be handed one.
    let mut oversized = bytes.to_vec();
    oversized[first_frame + 32..first_frame + 36].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let mut reader =
        open_stream(&oversized, &mut credentials).expect("the header still authenticates");
    assert_failure(
        reader.next_block(),
        KdbxFailureKind::ResourceLimit,
        "KDBX block exceeds the configured limit",
        "a block length of u32::MAX",
    );
}

/// Every length of a real KDBX XML document, through `KdbxXml::import`.
///
/// The container sweeps above stop at the header and the block framing, and the
/// one length at which they reach the XML is the one length at which it is
/// complete. So the XML parser — the element walker, the attribute parser, the
/// Base64 UUID and timestamp decoders, and the element-shape checks behind them
/// — is swept here on its own, against a document this crate's own writer
/// produced from an empty database.
///
/// The classification has three regions, and the split between the first two is
/// not the crate's: a cut inside a tag, an attribute, or the XML declaration is
/// a reader *error*, and a cut at a tag boundary with the tree still open is the
/// crate's own "unterminated" check. The test derives the first from the bytes,
/// so it is asserting where the two checks fire rather than which of them
/// exists.
#[test]
fn every_truncation_of_a_kdbx_xml_document_is_a_typed_error() {
    let bytes = KdbxXml::export(&KeePassDatabase::default()).expect("fixture XML document");
    assert_eq!(bytes.len(), 1652, "the XML fixture is pinned");
    let limits = KdbxReadLimits::default();

    // The whole document imports, so the one length that is not a truncation is
    // a real database and not an empty success.
    let database = KdbxXml::import(bytes.as_slice(), &limits).expect("the fixture imports");
    assert_eq!(database.meta.generator, GENERATOR);
    assert!(database.can_save_losslessly);
    assert!(
        database.root.entries.is_empty() && database.root.groups.is_empty(),
        "an empty database has an empty root group"
    );
    assert_eq!(
        KdbxXml::export(&database).expect("re-export"),
        bytes,
        "the fixture round-trips"
    );

    // The offset at which the root start tag closes. Below it a prefix has
    // produced no document element at all; from it onwards the tree is open and
    // every cut is a truncation of a document in progress.
    let root = find(&bytes, b"<KeePassFile").expect("the fixture has a root element");
    let root_end = root
        + bytes[root..]
            .iter()
            .position(|byte| *byte == b'>')
            .expect("the root start tag closes")
        + 1;
    assert_eq!(root_end, 51, "the root element offset is pinned");

    let outcomes = sweep(&bytes, |prefix| KdbxXml::import(prefix, &limits));
    assert_eq!(
        accepted(&outcomes),
        vec![bytes.len()],
        "only the whole document"
    );
    for (length, outcome) in outcomes.iter().enumerate().take(bytes.len()) {
        let expected = xml_classification(&bytes[..length], root_end);
        assert_eq!(
            *outcome,
            Outcome::of(KdbxFailureKind::Malformed, expected),
            "XML length {length} should be Malformed {expected:?}"
        );
    }
    // The negative claim, on its own: a cut cannot produce a `Unsupported` or a
    // `ResourceLimit` failure, which is what a DTD, an external entity, a
    // protected payload, or an over-limit document produces. A cut that reached
    // one of those checks would mean the walker had accepted a document it had
    // not finished reading.
    assert_never(
        &outcomes,
        &[KdbxFailureKind::Unsupported, KdbxFailureKind::ResourceLimit],
        "a KDBX XML cut",
    );
    // The two lengths that report "no document element", named. The naive minimum
    // — the shortest prefix that is not a truncation — is 0, and the interesting
    // boundary is 38, which is a *complete* XML declaration and still has no
    // element in it.
    for length in [0, 38] {
        assert_failure::<()>(
            KdbxXml::import(&bytes[..length], &limits).map(|_| ()),
            KdbxFailureKind::Malformed,
            "KDBX XML has no document element",
            &format!("XML length {length}"),
        );
    }
    // And the ends of the first region, to show the boundary is where the byte
    // arithmetic says it is: one byte into the declaration is a malformed
    // declaration, the declaration's last byte is still no element, and the root
    // start tag on its own is an unterminated document.
    for (length, message, what) in [
        (1, "invalid KDBX XML", "one byte of the XML declaration"),
        (37, "invalid KDBX XML", "one byte short of the declaration"),
        (
            50,
            "invalid KDBX XML",
            "one byte short of the root start tag",
        ),
        (
            root_end,
            "unterminated KDBX XML",
            "the root start tag and nothing else",
        ),
    ] {
        assert_failure::<()>(
            KdbxXml::import(&bytes[..length], &limits).map(|_| ()),
            KdbxFailureKind::Malformed,
            message,
            what,
        );
    }

    assert_xml_controls(&bytes, root_end, &limits);
}

/// The failure a cut of a KDBX XML document must produce.
///
/// Two checks can fire and the split between them is the reader's, not the
/// crate's. A cut inside a tag, an attribute, or the XML declaration is a
/// *reader* error, which the crate reports as one message whatever the reader
/// said. A cut at a tag boundary is a document the reader accepted and the crate
/// then found wanting: no element at all below the root start tag's `>`, and an
/// unterminated tree above it.
fn xml_classification(prefix: &[u8], root_end: usize) -> &'static str {
    if ends_inside_a_tag(prefix) {
        "invalid KDBX XML"
    } else if prefix.len() < root_end {
        "KDBX XML has no document element"
    } else {
        "unterminated KDBX XML"
    }
}

/// Asserts the KDBX XML failures a truncation cannot produce.
///
/// Every one of these is a *complete* document with something in it that a prefix
/// can never contain: a DTD, an external entity, a protected payload, or a size
/// over the limit. A cut that reached one of these checks would mean the walker
/// had accepted a document it had not finished reading.
fn assert_xml_controls(bytes: &[u8], root_end: usize, limits: &KdbxReadLimits) {
    for (document, kind, message) in [
        (
            &b"<!DOCTYPE KeePassFile><KeePassFile><Meta/></KeePassFile>"[..],
            KdbxFailureKind::Unsupported,
            "DTDs are not permitted in KDBX XML",
        ),
        (
            &b"<KeePassFile><Root><Group><Name>&external;</Name></Group></Root></KeePassFile>"[..],
            KdbxFailureKind::Unsupported,
            "external entities are not permitted in KDBX XML",
        ),
        (
            &b"<KeePassFile><Root><Group><String><Key>Password</Key><Value \
               Protected=\"True\">dGVzdA==</Value></String></Group></Root></KeePassFile>"[..],
            KdbxFailureKind::Unsupported,
            "plain XML cannot import protected values",
        ),
    ] {
        assert_failure(
            KdbxXml::import(document, limits),
            kind,
            message,
            "a complete document with a construct no cut can produce",
        );
    }
    // A prefix is always shorter than a limit, so it can never be the input that
    // trips one. The control is a *complete* document under an eight-byte limit.
    assert_failure(
        KdbxXml::import(
            &bytes[..root_end],
            &KdbxReadLimits {
                max_xml_chars: 8,
                ..*limits
            },
        ),
        KdbxFailureKind::ResourceLimit,
        "KDBX XML exceeds the configured limit",
        "a complete root element under an eight-byte XML limit",
    );
}

/// The offsets that decide how a cut of an XML key file is classified.
struct KeyFileShape {
    /// Where the `Data` element's text starts, and one past its last byte.
    data: Range<usize>,
    /// Where the root element's start tag closes.
    root_end: usize,
}

/// Reads a key file's own layout out of its bytes and checks it against the
/// pinned offsets.
///
/// The three anchors are the `Data` start tag, the first byte of its text, and
/// the `Data` end tag. Everything the classification below does with a cut point
/// is arithmetic on those, so they are asserted rather than assumed, and a
/// fixture edit that moved one would fail here instead of quietly changing which
/// lengths are accepted.
fn key_file_shape(
    bytes: &[u8],
    data_tag: usize,
    data_start: usize,
    data_end: usize,
) -> KeyFileShape {
    assert_eq!(
        find(bytes, b"<Data").expect("a Data element"),
        data_tag,
        "the Data start tag offset is pinned"
    );
    assert_eq!(
        bytes[data_start - 1],
        b'>',
        "the Data text starts after its start tag's closing '>'"
    );
    assert!(
        data_tag + 6 <= data_start,
        "the v1 start tag is six bytes and the v2 one also carries a Hash attribute"
    );
    assert_eq!(
        find(bytes, b"</Data>").expect("a Data end tag"),
        data_end,
        "the Data end tag offset is pinned"
    );
    let root_end = find(bytes, b"<KeyFile>").expect("a root element") + "<KeyFile>".len();
    assert_eq!(root_end, 48, "the root element offset is pinned");
    KeyFileShape {
        data: data_start..data_end,
        root_end,
    }
}

/// The classification a cut of an XML key file must produce, or `None` when the
/// cut is accepted.
///
/// The interesting part of this function is what it does *not* say. A key file
/// has no trailer to be short of: the reader takes events until end of input and
/// then checks that it saw a `KeyFile` root and a `Data` value, and a prefix that
/// stops at a tag boundary *after* the value has been read satisfies both. So
/// nine of the lengths in a 178-byte v1 key file are accepted, and the first of
/// them — 32 — is not an XML prefix at all: 32 bytes is the raw form, and the raw
/// form is checked before the `<` that would identify the file as XML.
fn key_file_classification(
    bytes: &[u8],
    shape: &KeyFileShape,
    version_two: bool,
    length: usize,
) -> Option<&'static str> {
    match length {
        0 => return Some("key-file must not be empty"),
        // 32 bytes is the raw form, whatever the file was. 64 is the hex form,
        // and these fixtures are not hex, so it is refused.
        32 => return None,
        64 => return Some("invalid key-file hex"),
        _ => {}
    }
    if ends_inside_a_tag(&bytes[..length]) {
        return Some("invalid key-file XML");
    }
    if length < shape.root_end {
        return Some("key-file XML root must be KeyFile");
    }
    if length <= shape.data.start {
        // The reader has not produced a `Data` text event yet: either the element
        // has not been reached, or the cut stopped inside it, or the cut left the
        // single byte of text that end-of-input will not turn into an event.
        return Some("key-file data is required");
    }
    if length < shape.data.end {
        // A cut inside the value. The v1 form is Base64, so a whole group decodes
        // and is then refused for its length and a partial group will not decode
        // at all. The v2 form is hex, so an odd length is refused before it is
        // decoded and an even one decodes and is refused for its length.
        let taken = length - shape.data.start;
        return Some(if version_two {
            if taken.is_multiple_of(2) {
                "key-file data must contain 32 bytes"
            } else {
                "XML v2 key must contain complete hex bytes"
            }
        } else if taken.is_multiple_of(4) {
            "key-file data must contain 32 bytes"
        } else {
            "invalid XML v1 key data"
        });
    }
    None
}

/// Every length of four real key files, through both key-file entry points.
///
/// The key file is the one place in this crate where a length is not read out of
/// a header but *is* the discriminator: 32 bytes is a raw key, 64 is hex, a
/// leading `<` is XML, and anything else non-empty is hashed. So the sweep's
/// first result is that two of the four forms have no truncation failures at all
/// — the fallback swallows every proper prefix — and the accepted sets below are
/// the whole finding. A sweep that asserted "every truncation is an error" would
/// be asserting something false about this parser, and one that asserted only
/// `is_err` would panic on the first accepted prefix.
#[test]
fn every_truncation_of_a_key_file_is_a_typed_error() {
    // A raw 32-byte key. Its first byte is `0x01`, not `<`, so no prefix of it can
    // be mistaken for the XML form.
    let raw: Vec<u8> = (0u8..32).map(|value| value + 1).collect();
    // 64 hex characters, the second form. Every proper prefix of it is a
    // *different length*, so every proper prefix falls through to the hash
    // fallback — except the 32-byte prefix, which is the raw form instead, and
    // produces a key that is the first half of the hex text read as bytes.
    let hex: Vec<u8> = (0u8..32)
        .flat_map(|value| format!("{value:02X}").into_bytes())
        .collect();
    assert_eq!(raw.len(), 32);
    assert_eq!(hex.len(), 64);

    for (label, bytes) in [("raw", raw.as_slice()), ("hex", hex.as_slice())] {
        let outcomes = sweep(bytes, KdbxKeyFile::parse);
        assert_eq!(
            accepted(&outcomes),
            (1..=bytes.len()).collect::<Vec<_>>(),
            "the {label} form's every non-empty prefix is hashed, not rejected"
        );
        assert_eq!(
            outcomes[0],
            Outcome::of(KdbxFailureKind::Malformed, "key-file must not be empty"),
            "the {label} form's empty prefix"
        );
    }
    // The 32-byte prefix of the hex form is the sharpest edge in this parser: it
    // is the raw form, so the key it produces is the first 32 *characters* of the
    // hex text read as bytes, and the key is 32 bytes long, and the open that
    // follows fails on authentication rather than on the truncated file. A caller
    // cannot tell a truncated key file from a wrong one.
    let mut provider = KdbxKeyFile::parse(&hex[..32]).expect("the raw form accepts 32 bytes");
    assert_eq!(
        provider.key_component().expect("a key component"),
        <[u8; 32]>::try_from(&hex[..32]).expect("32 bytes"),
        "a 32-byte cut of a hex key file is read as a raw key"
    );

    // The XML forms, where the length arithmetic lives.
    for (label, fixture, version_two, data_tag, data_start, data_end, accepted_lengths) in [
        (
            "v1",
            KEY_FILE_V1,
            false,
            101,
            107,
            151,
            vec![32, 151, 158, 159, 160, 166, 167, 177, 178],
        ),
        (
            "v2",
            KEY_FILE_V2,
            true,
            100,
            122,
            186,
            vec![32, 186, 193, 194, 195, 201, 202, 212, 213],
        ),
    ] {
        let bytes = fixture.as_bytes();
        let shape = key_file_shape(bytes, data_tag, data_start, data_end);
        let outcomes = sweep(bytes, KdbxKeyFile::parse);
        let expected: Vec<Outcome> = (0..=bytes.len())
            .map(|length| {
                key_file_classification(bytes, &shape, version_two, length)
                    .map_or(Outcome::Accepted, |message| {
                        Outcome::of(KdbxFailureKind::Malformed, message)
                    })
            })
            .collect();
        assert_eq!(outcomes, expected, "the {label} key file");
        assert_eq!(
            accepted(&outcomes),
            accepted_lengths,
            "the {label} key file's accepted cuts"
        );
        assert_all_malformed(&outcomes, &format!("key file {label}"));
        // The full-length parse is the control: it is what proves the fixture is a
        // real key file and that the accepted set above is about truncation rather
        // than about a fixture that never parsed.
        assert!(
            KdbxKeyFile::parse(bytes).is_ok(),
            "the {label} fixture is a valid key file"
        );
        // The reading entry point must agree with the parsing one at every
        // length, including the accepted ones: it is the same parser with a
        // 64 KiB cap in front of it.
        for length in 0..=bytes.len() {
            assert_eq!(
                read_key_file(&bytes[..length]).is_ok(),
                KdbxKeyFile::parse(&bytes[..length]).is_ok(),
                "read_key_file and KdbxKeyFile::parse disagree at length {length}"
            );
        }
    }

    // The 32-byte cut of an XML key file is worth naming on its own, because it
    // is the same 32 bytes that make the two forms above interesting: the raw
    // form is checked before the `<`, so the first 32 bytes of a key file are a
    // valid key and the key is the XML declaration read as bytes.
    let v1 = KEY_FILE_V1.as_bytes();
    assert_eq!(v1[0], b'<', "the v1 fixture is XML");
    let mut raw_cut = KdbxKeyFile::parse(&v1[..32]).expect("the raw form accepts 32 bytes");
    assert_eq!(
        raw_cut.key_component().expect("a key component"),
        <[u8; 32]>::try_from(&v1[..32]).expect("32 bytes"),
        "a 32-byte cut of an XML key file is read as a raw key"
    );
    // The v2 form's XML is a different shape — an odd-length hex string and a
    // `Hash` attribute — and it fails differently at the same offsets, which is
    // why both are swept rather than one standing in for the other.
    assert_eq!(KEY_FILE_V2.as_bytes()[0], b'<', "the v2 fixture is XML");
    assert_failure(
        KdbxKeyFile::parse(b"<!DOCTYPE KeyFile><KeyFile><Key><Data>AA==</Data></Key></KeyFile>"),
        KdbxFailureKind::Unsupported,
        "DTD and external entities are not permitted in key-file XML",
        "a complete key file with a DTD",
    );
    assert_failure(
        KdbxKeyFile::parse(&vec![b'x'; 64 * 1024 + 1]),
        KdbxFailureKind::ResourceLimit,
        "key file exceeds the configured limit",
        "a key file one byte over the cap",
    );
}

/// Every length of a real `otpauth://` URI, through `OtpUri::parse`.
///
/// The URI is the one text format here whose *cut point* decides which parameter
/// check fires, so the classification is a region table keyed on the fixture's
/// own parameter offsets. Two of its regions are worth reading. A cut inside the
/// Base32 secret is a Base32 failure unless the cut lands on a whole number of
/// Base32 characters, and two of them do — at 41 and 44 — in which case the
/// secret parses and the failure moves on to the missing period. And the
/// shortest accepted URI is one byte *shorter* than the whole thing, because
/// `period=3` is as good a period as `period=30`.
#[test]
fn every_truncation_of_an_otp_uri_is_a_typed_error() {
    let bytes = OTP_URI.as_bytes();
    assert_eq!(bytes.len(), 103, "the URI fixture is pinned");
    for (needle, offset) in [
        ("otpauth://", 0),
        ("totp", 10),
        ("?secret=", 28),
        (OTP_BASE32, 36),
        ("&issuer=Example", 52),
        ("&algorithm=SHA256", 67),
        ("&digits=", 84),
        ("&period=", 93),
        ("30", 101),
    ] {
        assert_eq!(
            find(bytes, needle.as_bytes()),
            Some(offset),
            "the {needle} offset is pinned"
        );
    }

    let uri = OtpUri::parse(OTP_URI).expect("the fixture parses");
    assert_eq!(uri.account, "example:alice");
    assert_eq!(uri.issuer.as_deref(), Some("Example"));
    assert_eq!(uri.secret, OTP_BASE32);
    assert_eq!(uri.period, Some(30));
    // The shortest accepted prefix: one byte short of the whole URI, because the
    // period's last digit is not load-bearing. This is the same shape as the PEM
    // minimum in the crypto area's sweep, which is one byte short because the
    // trailing newline is optional.
    let shorter = OtpUri::parse(&OTP_URI[..102]).expect("one byte short is still a TOTP URI");
    assert_eq!(shorter.period, Some(3));
    assert_eq!(shorter.secret, OTP_BASE32);

    let outcomes = sweep(bytes, |prefix| {
        OtpUri::parse(std::str::from_utf8(prefix).expect("the fixture is ASCII"))
    });
    assert_eq!(
        accepted(&outcomes),
        vec![102, 103],
        "only a whole or a one-byte-short period parses"
    );
    // The region table. Each row is a range of cut points and the check that
    // fires there; the ranges are the fixture's own parameter boundaries, which
    // are asserted above, so this is where the checks fire rather than a list of
    // offsets that could drift.
    let table: &[(Range<usize>, &str)] = &[
        (0..10, "OTP URI must use otpauth"),
        (10..14, "unsupported OTP URI type"),
        (14..36, "OTP URI secret is required"),
        (36..37, "invalid OTP Base32"),
        (37..41, "OTP Base32 has non-zero trailing bits"),
        (41..42, "TOTP URI period must be positive"),
        (42..44, "OTP Base32 has non-zero trailing bits"),
        (44..45, "TOTP URI period must be positive"),
        (45..52, "OTP Base32 has non-zero trailing bits"),
        (52..78, "TOTP URI period must be positive"),
        (78..84, "unsupported OTP algorithm"),
        (84..92, "TOTP URI period must be positive"),
        (92..93, "unsupported OTP digits"),
        (93..101, "TOTP URI period must be positive"),
        (101..102, "invalid OTP period"),
    ];
    let mut expected = vec![None; bytes.len() + 1];
    for (range, message) in table {
        for slot in &mut expected[range.clone()] {
            *slot = Some(*message);
        }
    }
    assert_eq!(messages(&outcomes), expected, "the otpauth URI");
    assert_all_malformed(&outcomes, "otpauth URI");

    // The two secret cuts that land on a whole number of Base32 characters,
    // named rather than left inside a range, because they are the only two
    // offsets in this sweep where the reported failure is *not* about the bytes
    // that were cut: the secret is complete and valid, and the URI is still
    // missing its period.
    for length in [41, 44] {
        let taken = length - 36;
        assert_eq!(
            OtpSecret::from_base32(&OTP_BASE32[..taken])
                .expect("a whole number of Base32 characters")
                .len(),
            taken * 5 / 8,
            "the cut secret is {taken} Base32 characters"
        );
        assert_eq!(
            outcomes[length],
            Outcome::of(
                KdbxFailureKind::Malformed,
                "TOTP URI period must be positive"
            ),
            "a valid secret and no period, at length {length}"
        );
    }
    // The controls, which no cut produces: a duplicate parameter, an unknown
    // one, and a HOTP URI with no counter.
    for (uri, message) in [
        (
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=30&period=60",
            "duplicate OTP URI parameter",
        ),
        (
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=30&extra=1",
            "unknown OTP URI parameter",
        ),
        (
            "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP",
            "HOTP URI counter is required",
        ),
    ] {
        assert_failure(OtpUri::parse(uri), KdbxFailureKind::Malformed, message, uri);
    }
}

/// Every length of the three small text encodings the KDBX XML attributes use.
///
/// Grouped because each is under thirty bytes and the per-test cost is the
/// fixture, not the assertions. They are three parsers of caller-supplied text
/// with three different length rules, and all three have the property that
/// matters here: *some* proper prefixes are accepted.
///
/// - Base64: only a whole number of four-character groups decodes at all, and a
///   whole group that is not the whole value decodes to too few bytes, so the
///   accepted set is exactly one length.
/// - `#RRGGBB`: the empty string is a valid empty colour, so the shortest prefix
///   is accepted and the six lengths in between are not.
/// - Base32: a cut that lands on a whole number of eight characters decodes to
///   fewer bytes and is accepted; every other cut has non-zero trailing bits.
#[test]
fn every_truncation_of_a_protected_value_encoding_is_a_typed_error() {
    // Base64. `KdbxUuid::from_base64` is the decoder behind every `UUID` element
    // in a KDBX document, so this is the XML parser's own attribute decoder at
    // its smallest.
    let uuid = KdbxUuid::from_bytes([7; 16]);
    let encoded = uuid.to_base64();
    assert_eq!(encoded.len(), 24, "16 bytes is 24 Base64 characters");
    assert_eq!(
        KdbxUuid::from_base64(&encoded).expect("the fixture decodes"),
        uuid
    );
    let outcomes = sweep(encoded.as_bytes(), |prefix| {
        KdbxUuid::from_base64(std::str::from_utf8(prefix).expect("the fixture is ASCII"))
    });
    assert_eq!(outcomes.len(), 25);
    assert_eq!(accepted(&outcomes), vec![24], "only a whole UUID decodes");
    for length in 0usize..24 {
        let expected = if length.is_multiple_of(4) {
            // A whole group decodes to a short buffer, which is then refused for
            // its length. This is the case a decoder that trusted the encoding's
            // length rather than the decoded one would get wrong.
            "UUID must decode to 16 bytes"
        } else {
            // A partial group. The engine requires canonical padding, so a group
            // that is not a whole multiple of four is refused rather than
            // completed.
            "invalid UUID Base64"
        };
        assert_failure(
            KdbxUuid::from_base64(&encoded[..length]),
            KdbxFailureKind::Malformed,
            expected,
            &format!("UUID Base64 length {length}"),
        );
    }

    // `#RRGGBB`.
    assert_eq!(
        KdbxColor::parse(COLOUR)
            .expect("the fixture parses")
            .to_string(),
        "#00AAFF"
    );
    let outcomes = sweep(COLOUR.as_bytes(), |prefix| {
        KdbxColor::parse(std::str::from_utf8(prefix).expect("the fixture is ASCII"))
    });
    assert_eq!(
        accepted(&outcomes),
        vec![0, 7],
        "the empty string is a valid empty colour, and the whole string is a colour"
    );
    for length in 1..7 {
        assert_failure(
            KdbxColor::parse(&COLOUR[..length]),
            KdbxFailureKind::Malformed,
            "color must be #RRGGBB",
            &format!("colour length {length}"),
        );
    }
    assert_eq!(
        KdbxColor::parse("").expect("an empty colour is valid").rgb,
        None,
        "the empty prefix is an empty colour, not an error"
    );
    // The length check's other half, which no cut of a seven-character colour can
    // reach: a *longer* string is as wrong as a shorter one, and a parser that
    // checked only for "too short" would quietly use the first six digits.
    assert_failure(
        KdbxColor::parse("#00AAffAA"),
        KdbxFailureKind::Malformed,
        "color must be #RRGGBB",
        "an eight-character colour",
    );

    // Base32.
    let secret = OtpSecret::from_base32(OTP_BASE32).expect("the fixture decodes");
    assert_eq!(secret.len(), 10, "16 Base32 characters are 10 bytes");
    let outcomes = sweep(OTP_BASE32.as_bytes(), |prefix| {
        OtpSecret::from_base32(std::str::from_utf8(prefix).expect("the fixture is ASCII"))
    });
    assert_eq!(
        accepted(&outcomes),
        vec![5, 8, 16],
        "a whole number of Base32 characters decodes to a shorter secret"
    );
    for length in 0..OTP_BASE32.len() {
        if outcomes[length] == Outcome::Accepted {
            continue;
        }
        let expected = if length == 0 {
            "invalid OTP Base32"
        } else {
            "OTP Base32 has non-zero trailing bits"
        };
        assert_failure(
            OtpSecret::from_base32(&OTP_BASE32[..length]),
            KdbxFailureKind::Malformed,
            expected,
            &format!("Base32 length {length}"),
        );
    }
    // The decoder's own two checks, named, because no cut produces either: a
    // padded secret is refused rather than trimmed, and a character outside the
    // alphabet is refused rather than skipped.
    assert_failure(
        OtpSecret::from_base32("JBSWY3DPEHPK3PX="),
        KdbxFailureKind::Malformed,
        "invalid OTP Base32",
        "a padded secret",
    );
    assert_failure(
        OtpSecret::from_base32("JBSWY3DPEHPK3PX1"),
        KdbxFailureKind::Malformed,
        "invalid OTP Base32 character",
        "a character outside the alphabet",
    );
}
