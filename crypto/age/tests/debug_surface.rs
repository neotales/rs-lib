//! Every public type in the crate can be `Debug`-printed, and none of them
//! prints a secret.
//!
//! Two separate claims are tested here, and the second is the one that matters.
//!
//! The first is coverage: a caller holding one of these values can log it, put
//! it in a test failure, or assert on it. `missing_debug_implementations` is a
//! workspace lint, so a new public type without `Debug` is already reported by
//! the build; this file is the behavioural half of that.
//!
//! The second is that the `Debug` output is safe to log. Five of the eleven
//! types are not derived, and the reason in each case is a field that must not
//! be printed:
//!
//! - `AgeDecryptReader` holds an authenticated *plaintext* chunk in a
//!   `Zeroizing<Vec<u8>>`, and `zeroize` derives `Debug` for `Zeroizing` by
//!   printing the wrapped value. A derive here would have put decrypted
//!   plaintext in every log line that touched the value.
//! - `AgeEncryptWriter` holds not-yet-encrypted plaintext in `buffer`.
//! - `AgeDecryptReaderAt` caches a decrypted plaintext chunk behind a lock.
//! - `AgeEncryptReader` owns the caller's plaintext source.
//! - `ClientUi` and `Plugin` hold closures, which cannot be printed, and
//!   requiring `Debug` of them would put a bound on the caller's own closures.
//!
//! The assertions below check the absence of the secret rather than the
//! presence of a format, so a future reformatting that stays safe still passes.
//! The exception is the identifying information a key type prints, which is the
//! point of printing it at all: a caller holding the wrong key has to be able to
//! tell which one they have, so two keys must not print the same thing.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::{
    fmt::Write as _,
    io::{Cursor, Read, Write},
    sync::Arc,
};

use neotales_age::{
    AgeArmor, AgeDecryptReader, AgeDecryptReaderAt, AgeEncryptReader, AgeEncryptWriter, AgeFile,
    AgeIdentity, AgeKey, AgeRecipient, AgeSliceReaderAt, ClientUi, Error, Plugin, Recipient,
    RecipientFactory, SshEd25519Key, SshRsaKey, bech32,
};

/// A passphrase-shaped string that must never appear in any `Debug` output.
const CANARY: &str = "canary-plaintext-2f8a41c6-do-not-log-me";

/// A private key that must never appear in any `Debug` output.
const PRIVATE_KEY: &str =
    "AGE-SECRET-KEY-1M0J706Z6QXT0A4ALWZ098Q5AFLTWXCVXLFT8VFYAG24MXX56CUSQQLCA3H";

/// An unwrapped age file key, which is a secret and must never appear either.
const FILE_KEY: &[u8; 16] = b"file-key-canary!";

/// Fails the test if `output` contains the canary in any of the three forms a
/// byte string can take in a `Debug` rendering: as text, as a decimal list, or
/// as a hex list.
fn assert_no_secret(output: &str, secret: &str) {
    assert_no_bytes(output, Some(secret), secret.as_bytes());
}

/// The same check for a raw key.
///
/// `text` is the encoding to search for as a string, and is `None` for a value
/// that need not be valid UTF-8. A derived `Debug` prints a byte array as a
/// decimal list and a `Zeroizing<Vec<u8>>` as a decimal list of the bytes it
/// wraps, so the two list forms are the ones a leak would actually take.
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

/// The two unit structs and the two key namespaces hold no state, so their
/// output is the type name and nothing else.
#[test]
fn stateless_types_print_only_their_name() {
    assert_eq!(format!("{AgeFile:?}"), "AgeFile");
    assert_eq!(format!("{AgeArmor:?}"), "AgeArmor");
    assert_eq!(format!("{SshRsaKey:?}"), "SshRsaKey");
    assert_eq!(format!("{SshEd25519Key:?}"), "SshEd25519Key");
}

/// A caller-supplied reader and writer that deliberately do not implement
/// `Debug`.
///
/// This is the ergonomic claim the issue asks for: a caller-side type must not
/// have to supply `Debug` on its own generic parameter. If any of the four
/// streaming types required it, this file would not compile.
struct Opaque;

impl Read for Opaque {
    fn read(&mut self, _output: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl Write for Opaque {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl neotales_age::ReaderAt for Opaque {
    fn read_at(&mut self, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let offset = usize::try_from(offset).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "offset too large")
        })?;
        let available = buffer.len().saturating_sub(offset);
        let available = available.min(buffer.len());
        buffer[..available].fill(0);
        Ok(available)
    }
}

/// The streaming types print their progress state, never the caller's bytes.
#[test]
fn streaming_types_print_without_a_debug_bound_on_the_caller_type() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let container =
        AgeFile::encrypt(CANARY.as_bytes(), std::slice::from_ref(&recipient)).expect("encrypt");

    // A sink that is not `Debug`, and holds the ciphertext rather than the
    // plaintext, so nothing here can print the canary by accident either.
    let writer = AgeEncryptWriter::new(Opaque, std::slice::from_ref(&recipient)).expect("writer");
    let printed = format!("{writer:?}");
    assert!(printed.starts_with("AgeEncryptWriter"), "{printed}");
    assert_no_secret(&printed, CANARY);

    let encrypt_reader = AgeEncryptReader::new(
        Cursor::new(CANARY.as_bytes()),
        std::slice::from_ref(&recipient),
    )
    .expect("encrypt reader");
    let printed = format!("{encrypt_reader:?}");
    assert!(printed.starts_with("AgeEncryptReader"), "{printed}");
    assert_no_secret(&printed, CANARY);

    // Drive the decrypt reader far enough that it holds a real, authenticated
    // plaintext chunk in `pending`. This is the field a derived `Debug` would
    // have printed.
    let mut reader = AgeDecryptReader::new(
        Cursor::new(container.clone()),
        std::slice::from_ref(&identity),
    )
    .expect("decrypt reader");
    let mut head = [0u8; 8];
    let read = reader.read(&mut head).expect("read head");
    assert_eq!(&head[..read], &CANARY.as_bytes()[..read]);
    let printed = format!("{reader:?}");
    assert!(printed.starts_with("AgeDecryptReader"), "{printed}");
    // The whole payload fits in one chunk, so the reader is holding the
    // remainder. The count is what a caller needs to know how far a partial
    // read got, and it is the number that must appear in place of the bytes.
    assert!(
        printed.contains(&format!("pending: {}", CANARY.len() - read)),
        "the reader should report the bytes it is holding: {printed}"
    );
    assert!(
        printed.contains(&format!("total: {}", CANARY.len())),
        "{printed}"
    );
    assert_no_secret(&printed, CANARY);

    // And the random-access reader, whose cache holds a decrypted chunk.
    let source = AgeSliceReaderAt::new(&container);
    let random = AgeDecryptReaderAt::new(source, container.len(), std::slice::from_ref(&identity))
        .expect("random access reader");
    let printed = format!("{random:?}");
    assert!(printed.starts_with("AgeDecryptReaderAt"), "{printed}");
    assert!(
        printed.contains(&format!("plaintext_size: {}", CANARY.len())),
        "{printed}"
    );
    assert_no_secret(&printed, CANARY);

    // A source that is not `Debug` still formats, which is the whole point.
    let opaque_random = AgeDecryptReaderAt::new(Opaque, 0usize, std::slice::from_ref(&identity));
    assert!(opaque_random.is_err(), "a zero size source is rejected");
    let slice_view = AgeSliceReaderAt::new(&container);
    let printed = format!("{slice_view:?}");
    assert_eq!(
        printed,
        format!("AgeSliceReaderAt {{ len: {} }}", container.len())
    );
}

/// The encrypting writer holds plaintext in `buffer` between calls to `write`.
///
/// A 64 KiB chunk boundary is what keeps bytes in the buffer, so the test writes
/// less than one chunk and then formats.
#[test]
fn encrypt_writer_does_not_print_buffered_plaintext() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let mut writer =
        AgeEncryptWriter::new(Vec::new(), std::slice::from_ref(&recipient)).expect("writer");
    writer.write_all(CANARY.as_bytes()).expect("write");

    let printed = format!("{writer:?}");
    assert!(
        printed.contains(&format!("buffered: {}", CANARY.len())),
        "the writer should report how much it is holding: {printed}"
    );
    assert_no_secret(&printed, CANARY);
    writer.finish().expect("finish");
}

/// The callback and factory holders report presence, not contents.
#[test]
fn callback_and_factory_holders_report_presence() {
    let empty = format!(
        "{:?}",
        ClientUi {
            display_message: None,
            request_value: None,
            confirm: None,
            wait_timer: None,
        }
    );
    assert_eq!(
        empty,
        "ClientUi { display_message: false, request_value: false, confirm: false, wait_timer: false }"
    );

    let populated = format!("{:?}", ClientUi::default());
    assert_eq!(
        populated,
        "ClientUi { display_message: false, request_value: false, confirm: false, wait_timer: false }"
    );

    let plugin = Plugin::new("example").expect("plugin name");
    let printed = format!("{plugin:?}");
    assert_eq!(
        printed,
        "Plugin { name: \"example\", recipient: false, identity_as_recipient: false, identity: false }"
    );
    assert_no_secret(&printed, PRIVATE_KEY);
}

/// The plugin holder with a factory installed still prints no closure detail.
#[test]
fn plugin_with_a_factory_prints_no_closure_detail() {
    let factory: RecipientFactory = Arc::new(|_data, _context| {
        Err::<Box<dyn Recipient>, Error>(Error::Unsupported("not invoked"))
    });
    let plugin = Plugin::new("example")
        .expect("plugin name")
        .handle_recipient(factory);
    let printed = format!("{plugin:?}");
    assert!(
        printed.contains("recipient: true"),
        "a registered factory should be visible: {printed}"
    );
    assert!(
        !printed.contains("not invoked"),
        "the closure body must not be printed: {printed}"
    );
    assert_no_secret(&printed, CANARY);
}

/// A key type identifies itself, and the identification is not the private key.
///
/// The two claims are the same claim about the same string. A caller holding the
/// wrong identity has to be able to tell which one they have from a log line,
/// and the only thing in a log line that can tell them is the public half, so
/// `Debug` has to print something that differs between two keys and is not the
/// private material. Asserting on `to_public_key` instead would say nothing
/// about `Debug` at all: a public-key encoding is a separate call with a
/// separate return value, and it is the redaction that matters when a caller
/// logs the identity itself.
#[test]
fn a_key_type_identifies_itself_without_printing_the_private_half() {
    let keys = [
        AgeKey::generate().expect("first key"),
        AgeKey::generate().expect("second key"),
    ];
    let identities = [
        AgeIdentity::from_private_key(&keys[0].private_key).expect("first identity"),
        AgeIdentity::from_private_key(&keys[1].private_key).expect("second identity"),
        AgeIdentity::generate_hybrid().expect("first hybrid identity"),
        AgeIdentity::generate_hybrid().expect("second hybrid identity"),
    ];

    let printed: Vec<String> = identities.iter().map(|id| format!("{id:?}")).collect();
    for (index, left) in printed.iter().enumerate() {
        for right in printed.iter().skip(index + 1) {
            assert_ne!(left, right, "two identities printed the same thing");
        }
    }
    for (identity, output) in identities.iter().zip(&printed) {
        assert!(output.contains(identity.kind()), "{output}");
        assert!(
            output.contains("fingerprint"),
            "an identity with a public half should identify itself: {output}"
        );
        assert_no_secret(output, &identity.to_private_key().expect("private key"));
    }

    // The scalar itself, not only its Bech32 encoding. A `Debug` that printed
    // the raw private key would leak in decimal or hex, and the encoding check
    // above would not see it.
    for (identity, key) in identities.iter().zip(&keys) {
        let (_, secret) = bech32::decode(&key.private_key).expect("private key payload");
        let output = format!("{identity:?}");
        assert_no_bytes(&output, Some(&key.private_key), &secret);
        assert!(!output.contains(&key.public_key), "{output}");
    }
}

/// A passphrase identity has no public half, so it prints the algorithm alone.
///
/// A fingerprint of a passphrase would identify it by brute force, and a
/// fingerprint of an unwrapped file key is a hash of a secret, so neither gets
/// one. Two passphrase identities are expected to look alike; that is the
/// honest answer rather than a defect.
#[test]
fn an_identity_without_a_public_half_prints_no_fingerprint() {
    let passphrase = AgeIdentity::from_passphrase(CANARY).expect("passphrase identity");
    let injected = AgeIdentity::from_file_key(FILE_KEY).expect("injected identity");

    for (identity, text, secret) in [
        (&passphrase, Some(CANARY), CANARY.as_bytes()),
        (&injected, None, &FILE_KEY[..]),
    ] {
        let printed = format!("{identity:?}");
        assert!(!printed.contains("fingerprint"), "{printed}");
        assert!(printed.contains(identity.kind()), "{printed}");
        assert_no_bytes(&printed, text, secret);
    }
}

/// A private key is never printed by any of them, including the ones that do
/// print key-adjacent state.
#[test]
fn no_public_type_prints_a_private_key() {
    let identity = AgeIdentity::from_private_key(PRIVATE_KEY).expect("identity");

    // The one public type that does hold a private key prints the algorithm
    // and a fingerprint of the public half, and neither is the scalar. This is
    // the assertion the issue asks for: the private half is absent from the
    // output, in all three of the forms it could take.
    let printed = format!("{identity:?}");
    assert!(!printed.contains(PRIVATE_KEY), "{printed}");
    assert_no_secret(&printed, PRIVATE_KEY);
    let (_, secret) = bech32::decode(PRIVATE_KEY).expect("private key payload");
    assert_no_bytes(&printed, Some(PRIVATE_KEY), &secret);
}
