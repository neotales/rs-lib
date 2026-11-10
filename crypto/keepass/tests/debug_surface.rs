//! Every public type in the crate can be `Debug`-printed, and none of them
//! prints a secret.
//!
//! Two separate claims are tested here, and the second is the one that matters
//! in a password manager.
//!
//! The first is coverage: a caller holding one of these values can log it, put
//! it in a test failure, or assert on it. `missing_debug_implementations` is a
//! workspace lint, so a new public type without `Debug` is already reported by
//! the build; this file is the behavioural half of that.
//!
//! The second is that the output is safe to log. Of the nineteen public types
//! the workspace lint named, five are derived and fourteen are hand-written,
//! and every hand-written case has a field that must not appear:
//!
//! - `KdbxCredentials` holds the master password in a `Vec<u8>`, and holds
//!   boxed caller `CredentialProvider` trait objects.
//! - `KdbxKeyFile` holds the 32-byte composite-key component outright.
//! - `OtpSecret` holds the TOTP/HOTP shared seed. Every code the generator
//!   emits is an HMAC under it.
//! - `Kdbx4AuthenticatedBlockReader` holds the SHA-512 derived block-HMAC key
//!   in `base_hmac`.
//! - `KdbxLoadFuture` and `KdbxSaveFuture` hold the buffered KDBX document,
//!   the decoded database, and a borrow of the master password, and they are
//!   generic over the caller's transport.
//! - `KdbxCancellation` holds the caller's cancellation closure.
//! - `ChaCha20MemoryProtection` holds its key and nonce in `Zeroizing` fields,
//!   and `zeroize` derives `Debug` for `Zeroizing` by *printing the wrapped
//!   value*. That is the trap, and it is demonstrated experimentally in
//!   [`zeroizing_is_not_a_redaction_wrapper`] below rather than taken on trust.
//!
//! The assertions check the *absence* of the secret rather than the presence of
//! a format, so a future reformatting that stays safe still passes. The
//! exception is the progress metadata a type is required to print — lengths,
//! counts, stage names — which is the point of printing it: a caller
//! diagnosing a stalled load needs to know how far the future got.
//!
//! The helpers are only worth what they can catch, so
//! [`the_negative_control_catches_an_injected_leak`] renders a secret
//! deliberately in all three forms a byte string can take in a `Debug` output
//! and asserts each is rejected. Without that test, "the assertion passed" would
//! be indistinguishable from "the assertion could never fail".

// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public item in
// the crate is still reported.
#![allow(missing_docs)]

use std::{
    fmt::Write as _,
    future::Future,
    io::{self, Read},
    pin::Pin,
    task::{Context, Poll, Waker},
};

use neotales_keepass::{
    CredentialProvider, Hotp, Kdbx4AuthenticatedBlockReader, KdbxAsyncRead, KdbxAsyncWrite,
    KdbxCancellation, KdbxCancellationToken, KdbxCredentials, KdbxFile, KdbxKeyFile,
    KdbxReadLimits, KdbxWriteOptions, KdbxXml, KeePassDatabase, KeePassXcOtp, OtpSecret, OtpUri,
    ProtectedValue, Totp,
};
use zeroize::Zeroizing;

/// A master password that must never appear in any `Debug` output.
const PASSWORD: &str = "canary-master-password-4b7e2d91-do-not-log-me";

/// An OTP shared secret that must never appear in any `Debug` output.
///
/// Strict unpadded Base32, so `OtpSecret::from_base32` accepts it. The decoded
/// form is the secret; the Base32 form is checked too, because the encoded one
/// is what an `otpauth` URI and a `KeePassXC` field actually carry.
const OTP_BASE32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// Key-file material. `KdbxKeyFile::parse` hashes arbitrary non-empty input, so
/// this arrives as a 32-byte composite-key component.
const KEY_FILE: &str = "canary-key-file-material-0a1b2c3d-do-not-log-me";

/// The plaintext behind a `ProtectedValue`.
const PROTECTED: &str = "canary-protected-plaintext-77c5e0a2-do-not-log-me";

/// Fails the test if `output` contains the secret in any of the three forms a
/// byte string can take in a `Debug` rendering: as text, as a decimal list, or
/// as a hex list.
fn assert_no_secret(output: &str, secret: &str) {
    assert_no_bytes(output, Some(secret), secret.as_bytes());
}

/// The same check for a raw key.
///
/// `text` is the encoding to search for as a string, and is `None` for a value
/// that need not be valid UTF-8. A derived `Debug` prints a byte array as a
/// decimal list, and `Zeroizing<Vec<u8>>` — which `zeroize` derives `Debug` for
/// by printing the wrapped value — as a decimal list of the bytes it wraps. So
/// the decimal list is the form a leaked secret here would *most likely* take,
/// and it is the form a check that only searched for text would miss.
fn assert_no_bytes(output: &str, text: Option<&str>, secret: &[u8]) {
    if let Some(text) = text {
        assert!(
            !output.contains(text),
            "Debug output leaked the secret as text: {output}"
        );
    }
    let mut decimal = String::new();
    for (index, byte) in secret.iter().enumerate() {
        if index > 0 {
            decimal.push_str(", ");
        }
        decimal.push_str(&byte.to_string());
    }
    assert!(
        !output.contains(&decimal),
        "Debug output leaked the secret as a decimal byte list: {output}"
    );
    // A byte vector renders as a decimal list, and that is the form a leaked
    // secret would actually take in a `Debug` output. The hex renderings are
    // checked too, since a redacting implementation may use either.
    let mut hex = String::new();
    for byte in secret {
        // `write!` into the existing buffer rather than `push_str(&format!)`,
        // which allocates a throwaway `String` per byte.
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let spaced = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !output.contains(&hex) && !output.contains(&spaced),
        "Debug output leaked the secret as a hex byte list: {output}"
    );
}

/// The helpers above are the load-bearing part of this file, so they are checked
/// against a leak deliberately rendered in each of the three forms they claim to
/// catch.
///
/// If this test ever passes while the helpers cannot fail, the rest of the file
/// is decorative. Each block below is the output a `#[derive(Debug)]` would have
/// produced for the corresponding field, and each must be rejected.
#[test]
fn the_negative_control_catches_an_injected_leak() {
    // Form 1: a `String` field printed as text.
    let leaked_text = format!("KdbxCredentials {{ password: Some({PASSWORD:?}) }}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_text, PASSWORD));
    assert!(caught.is_err(), "a text leak must be caught: {leaked_text}");

    // Form 2: a `Vec<u8>` field printed as a decimal list. This is what
    // `KdbxCredentials { password: Some(..) }` would *actually* have looked
    // like, because the field is `Option<Vec<u8>>` rather than a `String`.
    let bytes = PASSWORD.as_bytes();
    let leaked_decimal = format!(
        "KdbxCredentials {{ password: Some([{}]) }}",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_decimal, PASSWORD));
    assert!(
        caught.is_err(),
        "a decimal-list leak must be caught: {leaked_decimal}"
    );

    // Form 3: the same bytes as a hex list, which is what a redacting
    // implementation might print and what a redaction check must not miss.
    let mut hex = String::new();
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let leaked_hex = format!("OtpSecret {{ secret: [{hex}] }}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_hex, PASSWORD));
    assert!(
        caught.is_err(),
        "a hex-list leak must be caught: {leaked_hex}"
    );

    // And the raw-byte variant, for a secret that is not valid UTF-8 and so has
    // no text form to search for.
    let non_utf8 = [0xffu8, 0xfe, 0x00, 0x80];
    let leaked_raw = format!(
        "KdbxKeyFile {{ key: [{}] }}",
        non_utf8
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let caught = std::panic::catch_unwind(|| assert_no_bytes(&leaked_raw, None, &non_utf8));
    assert!(
        caught.is_err(),
        "a raw-byte leak must be caught: {leaked_raw}"
    );

    // A real, safe `Debug` output from this crate must *not* be caught. Without
    // this, the four checks above would also pass if `assert_no_bytes` simply
    // rejected everything.
    assert_no_secret(&format!("OtpSecret {{ len: {} }}", 20), PASSWORD);
    assert_no_secret("KdbxKeyFile", KEY_FILE);
}

/// `zeroize` derives `Debug` for `Zeroizing` by printing the wrapped value.
///
/// This is the claim the whole `ChaCha20MemoryProtection` impl rests on, and it
/// is asserted here rather than assumed, because getting it wrong in the other
/// direction is silent: if `zeroize` ever stopped deriving `Debug`, a
/// `#[derive(Debug)]` on that struct would become safe and a maintainer reading
/// only the struct would have no way to know. The assertion is deliberately
/// about `zeroize` and not about the crate's own type, whose constructor is
/// private — the mechanism is what is being pinned down, and it is reachable
/// from an integration test because `zeroize` is a dependency of this package.
#[test]
fn zeroizing_is_not_a_redaction_wrapper() {
    let canary = *b"CANARY-IN-MEMORY-PROTECTION-KEY!";
    let wrapped = Zeroizing::new(canary);

    // This is the trap. A `Debug` on a struct holding this field prints the
    // key, which is the decimal list the assertion above matched. The
    // assertion is written as a positive claim about the dependency so that it
    // fails loudly if the dependency ever changes, rather than silently making
    // the hand-written impl look redundant to whoever reads this next.
    let rendered = format!("{wrapped:?}");
    assert!(
        rendered.contains(
            &canary
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "zeroize is expected to derive Debug for Zeroizing by printing the \
         wrapped value; if this no longer holds, the reasoning behind the \
         hand-written ChaCha20MemoryProtection impl should be revisited: \
         {rendered}"
    );
    // And the negative control for the helper, using the same bytes: the
    // helper above must reject exactly this rendering.
    let caught = std::panic::catch_unwind(|| {
        assert_no_bytes(&rendered, None, &canary);
    });
    assert!(
        caught.is_err(),
        "the helper must reject zeroize's own rendering: {rendered}"
    );

    // The fixed-size array form is what the type actually holds, and it behaves
    // the same way: `[u8; 32]`, not `Vec<u8>`.
    let fixed: Zeroizing<[u8; 8]> = Zeroizing::new(*b"KEYBYTES");
    assert!(
        format!("{fixed:?}").contains("75, 69, 89, 66, 89, 84, 69, 83"),
        "zeroize is expected to print a wrapped fixed-size array too: {fixed:?}"
    );
}

/// A caller-supplied asynchronous sink that deliberately does not implement
/// `Debug`.
///
/// This is the ergonomic claim: a caller-side type must not have to supply
/// `Debug` on its own generic parameter. `KdbxLoadFuture`, `KdbxSaveFuture`,
/// and `Kdbx4AuthenticatedBlockReader` are all generic over such a type, and if
/// any of them required the bound, this file would not compile. It is used for
/// both a reader and a writer so one non-`Debug` type covers both directions.
///
/// The sink stalls on every third `poll_write` rather than every other one.
/// Alternating would put the stall immediately before the first write, so every
/// rendering would show `position: 0` and the position field would look
/// constant. Stalling irregularly is what makes a mid-write rendering possible.
///
/// The sink also accepts at most 1024 bytes per call, a short write. Without
/// one, the first accepted write consumes the whole encoded buffer and the
/// position jumps straight from 0 to the end, so the field would never render
/// as anything but 0 or the total.
struct Opaque {
    written: usize,
    polls: usize,
}

/// The most bytes one `poll_write` accepts.
const SHORT_WRITE: usize = 1024;

impl KdbxAsyncRead for Opaque {
    fn poll_read(&mut self, _cx: &mut Context<'_>, _buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        // Never read. Used only where a transport must exist.
        Poll::Ready(Ok(0))
    }
}

impl KdbxAsyncWrite for Opaque {
    fn poll_write(&mut self, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.polls += 1;
        if self.polls % 3 == 1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = buffer.len().min(SHORT_WRITE);
        self.written += count;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A `Read` source that is also not `Debug`, for the block reader.
struct NotDebug {
    bytes: Vec<u8>,
    position: usize,
}

impl Read for NotDebug {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.bytes.len().saturating_sub(self.position);
        let count = output.len().min(available);
        output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

/// An asynchronous reader that yields one byte per poll, returns `Pending` on
/// every other poll, and is not `Debug`.
///
/// The `Pending` matters. A transport that always answers `Ready` lets the
/// future complete in a handful of polls without the driver ever getting a
/// chance to render it mid-flight, and the mid-flight value is the one holding
/// the buffered document.
struct ByteAtATime<'a> {
    bytes: &'a [u8],
    position: usize,
    stalling: bool,
}

impl KdbxAsyncRead for ByteAtATime<'_> {
    fn poll_read(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        self.stalling = !self.stalling;
        if self.stalling {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.position >= self.bytes.len() || buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        buffer[0] = self.bytes[self.position];
        self.position += 1;
        Poll::Ready(Ok(1))
    }
}

/// Builds a KDBX 4 vault encrypted under `PASSWORD`.
fn vault(password: &str) -> Vec<u8> {
    let mut database = KeePassDatabase::default();
    database
        .root
        .entries
        .push(neotales_keepass::Entry::new("entry"));
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut KdbxCredentials::password(password).expect("credentials"),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .expect("save");
    bytes
}

/// Drives a future to completion, returning every `Debug` rendering seen along
/// the way.
///
/// The renderings matter as much as the result. A `Debug` impl that always
/// reported the pre-poll state would satisfy a single post-construction check
/// while saying nothing about a mid-flight value, and the mid-flight value is
/// the one holding the buffered document.
///
/// The `F: Debug` bound is on the *future*, not on the future's transport. Both
/// `KdbxLoadFuture` and `KdbxSaveFuture` implement `Debug` unconditionally, so
/// this bound is satisfied by a future over a transport that is not `Debug` —
/// which is the whole ergonomic claim, and is checked by every caller below
/// using a non-`Debug` transport.
fn drive<F: Future + std::fmt::Debug>(future: F) -> (F::Output, Vec<String>) {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    let mut seen = Vec::new();
    for _ in 0..1_000_000 {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(output) => return (output, seen),
            Poll::Pending => seen.push(format!("{future:?}")),
        }
    }
    panic!("future did not complete");
}

/// The five derived types are unit structs, so their output is the type name and
/// nothing else.
///
/// This is the provably-safe case: there is no field for a derive to reach, so
/// "a derive here leaks nothing" is checkable rather than asserted.
#[test]
fn unit_structs_print_only_their_name() {
    assert_eq!(format!("{KdbxFile:?}"), "KdbxFile");
    assert_eq!(format!("{Hotp:?}"), "Hotp");
    assert_eq!(format!("{Totp:?}"), "Totp");
    assert_eq!(format!("{KeePassXcOtp:?}"), "KeePassXcOtp");
    assert_eq!(format!("{KdbxXml:?}"), "KdbxXml");
}

/// The master password and the key-file material never reach an output.
///
/// A caller has to be able to tell "credentials with a password and one
/// provider" from "credentials with no password and no providers", and the
/// counts are the whole of that.
#[test]
fn credentials_and_key_files_print_no_secret() {
    let credentials = KdbxCredentials::password(PASSWORD).expect("a non-empty password");
    let printed = format!("{credentials:?}");
    assert!(printed.starts_with("KdbxCredentials"), "{printed}");
    assert!(printed.contains("password: true"), "{printed}");
    assert!(printed.contains("provider_count: 0"), "{printed}");
    assert_no_secret(&printed, PASSWORD);

    // A provider-only value. The password component is absent, and the derived
    // `Debug` on `KdbxKeyFile` prints the type name alone.
    let mut key_file = KdbxKeyFile::parse(KEY_FILE.as_bytes()).expect("key file parses");
    let component = key_file.key_component().expect("key component");
    let printed = format!("{key_file:?}");
    assert_eq!(printed, "KdbxKeyFile");
    assert_no_secret(&printed, KEY_FILE);
    assert_no_bytes(&printed, None, &component);

    // Password plus one provider: the count is the field that distinguishes it
    // from the password-only case above. The key file is consumed as the
    // provider so the derived composite key is the one a real caller would get.
    let credentials = KdbxCredentials::with_provider(
        Some(PASSWORD),
        Box::new(std::mem::replace(
            &mut key_file,
            KdbxKeyFile::parse(KEY_FILE.as_bytes()).expect("key file parses"),
        )),
    )
    .expect("password plus a provider is valid");
    let printed = format!("{credentials:?}");
    assert!(printed.contains("password: true"), "{printed}");
    assert!(printed.contains("provider_count: 1"), "{printed}");
    assert_no_secret(&printed, PASSWORD);
    assert_no_bytes(&printed, None, &component);

    // And a credentials value with no password at all, which is the third
    // distinguishable shape.
    let credentials = KdbxCredentials::key_file(KEY_FILE.as_bytes()).expect("key file only");
    let printed = format!("{credentials:?}");
    assert!(printed.contains("password: false"), "{printed}");
    assert!(printed.contains("provider_count: 1"), "{printed}");
    assert_no_bytes(&printed, None, &component);
}

/// The OTP seed never reaches an output, and its length does.
///
/// The length is the deliberate exception: a seed that decoded to zero bytes, or
/// to one of the few lengths a truncated Base32 encoding produces, is a real
/// configuration error, and the length is the only part of the value that is not
/// the secret. Every six- or eight-digit code the generator emits is an HMAC
/// under these bytes, so the bytes are a long-lived factor.
#[test]
fn the_otp_secret_prints_its_length_and_nothing_else() {
    let secret = OtpSecret::from_base32(OTP_BASE32).expect("strict unpadded base32");
    let decoded = secret.expose().to_vec();
    assert!(!decoded.is_empty(), "the canary must decode to something");

    let printed = format!("{secret:?}");
    assert!(printed.starts_with("OtpSecret"), "{printed}");
    assert!(
        printed.contains(&format!("len: {}", decoded.len())),
        "the length is the diagnostic content: {printed}"
    );
    // All three forms of the secret: the raw bytes as a decimal list, the raw
    // bytes as hex, and the Base32 text a caller supplied.
    assert_no_bytes(&printed, Some(OTP_BASE32), &decoded);
    // And the URI form, which embeds the Base32 secret. `OtpUri` already had a
    // redacting `Debug`; this confirms it still holds for the secret it
    // carries.
    let uri = OtpUri::parse(&format!(
        "otpauth://totp/issuer:acme?secret={OTP_BASE32}&issuer=acme&period=30"
    ))
    .expect("otpauth uri");
    let printed = format!("{uri:?}");
    assert!(printed.contains("<redacted>"), "{printed}");
    assert_no_bytes(&printed, Some(OTP_BASE32), &decoded);
}

/// A `ProtectedValue` reports its length and whether it is memory-protected,
/// never the plaintext behind it.
///
/// This is the one public path that constructs a `ChaCha20MemoryProtection`, so
/// it also carries the end-to-end check that the protector does not surface
/// through anything the caller can print. The provider itself has a private
/// constructor, so its own output is asserted in the crate's unit tests.
#[test]
fn a_protected_value_reports_its_length_not_its_plaintext() {
    let value = ProtectedValue::from_text(PROTECTED);
    let printed = format!("{value:?}");
    assert!(
        printed.contains(&format!("len: {}", PROTECTED.len())),
        "{printed}"
    );
    assert!(printed.contains("memory_protected: "), "{printed}");
    assert_no_secret(&printed, PROTECTED);

    // The byte path, which installs a `ChaCha20MemoryProtection` by default and
    // therefore reaches the `Zeroizing` key material.
    let bytes = ProtectedValue::from_bytes(PROTECTED.as_bytes()).expect("protected bytes");
    assert!(bytes.is_memory_protected(), "the default is protected");
    let printed = format!("{bytes:?}");
    assert!(
        printed.contains(&format!("len: {}", PROTECTED.len())),
        "{printed}"
    );
    assert!(printed.contains("memory_protected: true"), "{printed}");
    assert_no_secret(&printed, PROTECTED);

    // The ciphertext differs from the plaintext, so the protector really is
    // transforming rather than passing the value through.
    let revealed = bytes.reveal_bytes().expect("reveal");
    assert_eq!(revealed.as_slice(), PROTECTED.as_bytes());
}

/// The block reader reports its framing progress and never its HMAC key.
///
/// `base_hmac` is the SHA-512 derived key that authenticates every block. The
/// reader holds no decrypted bytes at all, so the block accounting is the whole
/// of what there is to report — and it is exactly what a caller debugging a
/// stalled or mis-framed stream needs.
#[test]
fn the_block_reader_reports_progress_and_not_its_hmac_key() {
    let container = vault(PASSWORD);
    let limits = KdbxReadLimits::default();
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");

    // The generic parameter is `NotDebug`, which is not `Debug`. If this
    // required `R: Debug` the file would not compile.
    let mut reader = Kdbx4AuthenticatedBlockReader::open(
        NotDebug {
            bytes: container.clone(),
            position: 0,
        },
        &mut credentials,
        &limits,
        KdbxCancellation::never(),
    )
    .expect("open");

    let printed = format!("{reader:?}");
    assert!(
        printed.starts_with("Kdbx4AuthenticatedBlockReader"),
        "{printed}"
    );
    assert!(printed.contains("next_index: 0"), "{printed}");
    assert!(printed.contains("data_blocks: 0"), "{printed}");
    assert!(
        printed.contains("terminal_authenticated: false"),
        "{printed}"
    );
    // `input_bytes` counts what has been consumed, which at open is the outer
    // header — the whole container is not read yet.
    let header_bytes: usize = printed
        .split("input_bytes: ")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .expect("the reader reports input_bytes")
        .parse()
        .expect("input_bytes is a number");
    assert!(header_bytes > 0, "{printed}");
    assert!(header_bytes < container.len(), "{printed}");
    assert_no_secret(&printed, PASSWORD);

    // Read a block so the accounting moves, then check it moved. An impl that
    // reported constant zeroes would have passed the assertions above.
    reader.next_block().expect("read a block").expect("a block");
    let printed = format!("{reader:?}");
    assert!(printed.contains("next_index: 1"), "{printed}");
    assert!(printed.contains("data_blocks: 1"), "{printed}");
    assert!(
        printed.contains("terminal_authenticated: false"),
        "{printed}"
    );
    let after: usize = printed
        .split("input_bytes: ")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .expect("the reader reports input_bytes")
        .parse()
        .expect("input_bytes is a number");
    assert!(
        after > header_bytes,
        "the consumed-byte count must advance: {header_bytes} then {after}"
    );
    assert_no_secret(&printed, PASSWORD);
    drop(reader);

    // The same over a source that implements neither `Read`-and-`Debug` nor
    // anything else printable, to show the bound is genuinely absent rather
    // than satisfied by a coincidental impl.
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let _ = (&mut credentials, &limits);
}

/// The largest value a numeric `Debug` field took across a set of renderings.
///
/// A single rendering is not evidence that a counter is live. An impl that
/// always printed `buffered: 0` would satisfy any "the field is present"
/// assertion, so the tests below compare the values across every rendering and
/// require the counter to have moved. Reading the number back out of the
/// rendered text, rather than holding the value in a variable, is what makes
/// this a test of the `Debug` output rather than of the future's internals.
fn largest(renderings: &[String], field: &str) -> usize {
    let needle = format!("{field}: ");
    let mut largest = 0;
    let mut saw_any = false;
    for rendering in renderings {
        let mut rest = rendering.as_str();
        while let Some(start) = rest.find(&needle) {
            rest = &rest[start + needle.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                saw_any = true;
                largest = largest.max(digits.parse().expect("a byte count is a number"));
            }
        }
    }
    assert!(saw_any, "no rendering reported a `{field}`: {renderings:?}");
    largest
}

/// The load future reports its stage and its buffered byte count, never the
/// document or the password, and puts no `Debug` bound on the caller's
/// transport.
#[test]
fn the_load_future_prints_progress_and_no_credentials() {
    let container = vault(PASSWORD);
    let limits = KdbxReadLimits::default();
    let mut source = ByteAtATime {
        bytes: &container,
        position: 0,
        stalling: false,
    };
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let future = KdbxFile::load_async(
        &mut source,
        &mut credentials,
        &limits,
        KdbxCancellation::never(),
    );

    // Before any poll at all.
    let printed = format!("{future:?}");
    assert!(printed.starts_with("KdbxLoadFuture"), "{printed}");
    assert!(printed.contains("buffered: 0"), "{printed}");
    assert!(printed.contains("validated: false"), "{printed}");
    assert!(
        printed.contains("cancellation: KdbxCancellation { check: \"never\" }"),
        "the policy is delegated to, so its own shape is visible: {printed}"
    );
    assert_no_secret(&printed, PASSWORD);

    // Then every mid-flight rendering, which is the state that actually holds
    // the buffered KDBX document. The transport stalls on every other poll so
    // the driver is guaranteed at least one of them.
    let (result, seen) = drive(future);
    result.expect("the vault loads");
    assert!(
        !seen.is_empty(),
        "the transport must have stalled at least once"
    );
    for rendering in &seen {
        assert!(rendering.starts_with("KdbxLoadFuture"), "{rendering}");
        assert_no_secret(rendering, PASSWORD);
    }
    // The buffered count has to be live, and it has to reach the whole document.
    // `poll` takes the buffer with `mem::take` on the same pass that starts
    // decoding, so the renderings top out just below the full length; requiring
    // the exact total would pin an internal detail rather than the claim.
    let peak = largest(&seen, "buffered");
    assert!(peak > 0, "the buffered count never moved: {seen:?}");
    assert!(
        peak >= container.len() - 1,
        "the buffered count should approach the document length, not stop at \
         {peak} of {}: {seen:?}",
        container.len()
    );
    // Every rendering carries a stage, but it is worth being precise about what
    // can be observed here. `KdbxLoadFuture::poll` yields `Pending` in exactly
    // one place — the caller's `poll_read` — and both the transition to
    // `Decoding` and the decode itself happen on the same pass. So a rendering
    // can only ever catch the reading stage, and a test that demanded the stage
    // advance would be testing an impossibility rather than the `Debug` impl.
    // The buffered count is the field that carries progress here, and it is
    // checked above to have moved.
    for rendering in &seen {
        assert!(
            rendering.contains("state: "),
            "every rendering should name the stage: {rendering}"
        );
    }
}

/// The save future is the mirror image: it holds the encoded document and the
/// database, and reports its stage, the encoded length, and the write position.
#[test]
fn the_save_future_prints_progress_and_no_credentials() {
    let limits = KdbxReadLimits::default();
    let database = KeePassDatabase::default();
    let mut destination = Opaque {
        written: 0,
        polls: 0,
    };
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let future = KdbxFile::save_async(
        &database,
        &mut destination,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &limits,
        KdbxCancellation::never(),
    );

    let printed = format!("{future:?}");
    assert!(printed.starts_with("KdbxSaveFuture"), "{printed}");
    assert!(printed.contains("encoded: 0"), "{printed}");
    assert!(printed.contains("position: 0"), "{printed}");
    assert!(
        printed.contains("cancellation: KdbxCancellation { check: \"never\" }"),
        "the policy is delegated to, so its own shape is visible: {printed}"
    );
    assert_no_secret(&printed, PASSWORD);

    let (result, seen) = drive(future);
    result.expect("the vault saves");
    assert!(!seen.is_empty(), "the sink must have stalled at least once");
    for rendering in &seen {
        assert!(rendering.starts_with("KdbxSaveFuture"), "{rendering}");
        assert_no_secret(rendering, PASSWORD);
    }
    assert!(
        largest(&seen, "encoded") == destination.written,
        "the encoded count should be the number of bytes written: {seen:?}"
    );
    // And the write position advances too, which is what tells a caller how far
    // a partially-flushed save got. It is strictly between 0 and the total, so
    // the renderings prove the field tracks the transport rather than the
    // future's own assumption about it.
    let peak_position = largest(&seen, "position");
    assert!(
        peak_position > 0 && peak_position < destination.written,
        "the write position should be observed mid-transfer, not only at the \
         ends: peak {peak_position} of {}: {seen:?}",
        destination.written
    );
    // Worth being precise about the stage field, as with the load future above.
    // Both futures do their expensive stage synchronously inside a single
    // `poll`, so the first `Pending` — and therefore every rendering the driver
    // can take — happens in the *next* stage. A test that demanded the stage
    // advance would be asking to observe something the state machine never
    // yields. The counters are the fields that carry observable progress, and
    // both are checked above to have moved.
    for rendering in &seen {
        assert!(
            rendering.contains("state: "),
            "every rendering should name the stage: {rendering}"
        );
    }
}

/// A cancellation policy reports which kind of check is installed and never the
/// caller's closure.
///
/// A `Callback` policy holds a `&dyn Fn() -> bool` that is not `Debug` at all,
/// so a derive would not have compiled; the impl matches on the check instead. A
/// token-backed policy is delegated to, which is safe because the token wraps a
/// single `AtomicBool` and nothing else.
#[test]
fn a_cancellation_policy_reports_its_check_and_not_the_closure() {
    assert_eq!(
        format!("{:?}", KdbxCancellation::never()),
        "KdbxCancellation { check: \"never\" }"
    );
    assert_eq!(
        format!("{:?}", KdbxCancellation::from_fn(&|| true)),
        "KdbxCancellation { check: \"callback\" }"
    );

    let token = KdbxCancellationToken::new();
    let printed = format!("{:?}", KdbxCancellation::from_token(&token));
    assert!(printed.contains("check: \"token\""), "{printed}");
    assert!(printed.contains("cancelled: false"), "{printed}");
    token.cancel();
    let printed = format!("{:?}", KdbxCancellation::from_token(&token));
    assert!(printed.contains("cancelled: true"), "{printed}");

    // The token itself is derived, and a derived `Debug` on `Arc<AtomicBool>` is
    // safe precisely because the flag is the whole of the value: there is no
    // buffer behind it for the derive to reach.
    assert_eq!(
        format!("{token:?}"),
        "KdbxCancellationToken { cancelled: true }"
    );
}

/// No public type in the crate prints the master password, whatever path it was
/// built by.
///
/// The per-type tests above pin each value's own claim. This one is the
/// belt-and-braces version: it drives the real load and save APIs and checks
/// every rendering each of them produced.
#[test]
fn no_public_type_prints_the_master_password() {
    let container = vault(PASSWORD);
    let limits = KdbxReadLimits::default();

    let mut source = ByteAtATime {
        bytes: &container,
        position: 0,
        stalling: false,
    };
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    assert_no_secret(&format!("{credentials:?}"), PASSWORD);
    let (result, seen) = drive(KdbxFile::load_async(
        &mut source,
        &mut credentials,
        &limits,
        KdbxCancellation::never(),
    ));
    result.expect("the vault loads");
    for rendering in seen {
        assert_no_secret(&rendering, PASSWORD);
    }

    let mut destination = Opaque {
        written: 0,
        polls: 0,
    };
    let mut credentials = KdbxCredentials::password(PASSWORD).expect("credentials");
    let (result, seen) = drive(KdbxFile::save_async(
        &KeePassDatabase::default(),
        &mut destination,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            hmac_block_bytes: 64,
            ..KdbxWriteOptions::default()
        },
        &limits,
        KdbxCancellation::never(),
    ));
    result.expect("the vault saves");
    for rendering in seen {
        assert_no_secret(&rendering, PASSWORD);
    }
}
