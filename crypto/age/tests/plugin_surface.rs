//! The plugin callback types are reachable from outside the crate.
//!
//! These six aliases were `pub` inside a private module while every item that
//! uses them was re-exported, so a caller could read `ClientUi::display_message:
//! Option<DisplayMessage>` in the published documentation and still have no way
//! to name the type they were being asked to build. `unreachable_pub` is what
//! found it.
//!
//! This file is the guard. It is an integration test, so it can only see the
//! public API: every name below has to resolve through `neotales_age::`. If a
//! future change narrows one of the aliases back to `pub(crate)`, or drops it
//! from the re-export list, this stops compiling rather than quietly taking the
//! name away from a caller who was already using it.
//!
//! An alias that resolves is also not the same as an alias that is usable. The
//! factories hand back `Box<dyn Recipient>` and `Box<dyn Identity>`, so a caller
//! cannot register one without implementing the trait it returns. Every factory
//! below therefore returns a real value, and the recipient factories are driven
//! through the plugin state machine to prove the value wraps a real file key.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::{
    io::{self, Cursor, Write},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use neotales_age::{
    AgeIdentity, AgeKey, AgeRecipient, ClientUi, Confirm, DisplayMessage, Error, Identity,
    IdentityFactory, Plugin, PluginContext, Recipient, RecipientFactory, RequestValue, Result,
    Stanza, WaitTimer, bech32, decrypt, encode_identity, encode_recipient, encrypt_with_recipients,
    parse_plugin_identity, parse_plugin_recipient,
};
// `Recipient::wrap` returns `Result<Vec<Stanza>>`, and the crate exports both,
// so the recipient below needs no other name. `Identity` asks for
// `Option<Zeroizing<Vec<u8>>>` in its return type, so an identity implementation
// has to name `Zeroizing`; this crate reaches it through ``, its
// own published dependency, rather than re-exporting it.
use zeroize::Zeroizing;

/// Real file data for the factories to be pointed at.
const PLAINTEXT: &[u8] = b"a plugin recipient has to wrap a real file key";

/// Builds each of the four client callbacks as a named value.
///
/// The point is not the closures. It is that a caller can hold a
/// `DisplayMessage` in a variable with a name of its own, rather than writing
/// the whole `Arc<dyn Fn(&str, &str) -> Result<()> + Send + Sync>` out again at
/// every use. That is the capability the aliases exist to provide.
#[test]
fn client_callback_types_are_nameable() {
    let display_message: DisplayMessage = Arc::new(|_name, message| {
        assert!(!message.is_empty());
        Ok(())
    });
    let request_value: RequestValue = Arc::new(|_name, prompt, _secret| Ok(prompt.to_owned()));
    let confirm: Confirm = Arc::new(|_name, _message, _yes, _no| Ok(true));
    let wait_timer: WaitTimer = Arc::new(|_reason| {});

    let ui = ClientUi {
        display_message: Some(display_message),
        request_value: Some(request_value),
        confirm: Some(confirm),
        wait_timer: Some(wait_timer),
    };

    // Invoked through the public surface rather than only constructed, so an
    // alias that resolves but names the wrong shape would fail here too.
    ui.display_message.as_ref().expect("callback present")("plugin", "a message")
        .expect("display message");
    assert_eq!(
        ui.request_value.as_ref().expect("callback present")("plugin", "a prompt", false)
            .expect("request value"),
        "a prompt"
    );
    assert!(
        ui.confirm.as_ref().expect("callback present")("plugin", "message", "yes", "no")
            .expect("confirm")
    );
    ui.wait_timer.as_ref().expect("callback present")("waiting");

    // `ClientUi` is `Default`, so a caller that wants only some of the four
    // does not have to name the ones it is leaving unset.
    assert!(ClientUi::default().display_message.is_none());
}

/// A recipient implemented here, by the caller, out of the crate.
///
/// `Recipient` is what a `RecipientFactory` has to return, so this is not an
/// optional extra: a caller who cannot write it cannot use the factory at all.
/// The signature needs `Result` and `Stanza`, and the crate exports both.
#[derive(Clone)]
struct CallerRecipient {
    key: AgeRecipient,
}

impl Recipient for CallerRecipient {
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
        AgeRecipient::wrap(&self.key, file_key).map(|stanza| vec![stanza])
    }
}

/// An identity implemented here, by the caller, out of the crate.
struct CallerIdentity {
    key: AgeIdentity,
}

impl Identity for CallerIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.key.unwrap(stanzas)
    }
}

/// Decodes the 32-byte X25519 public key a plugin recipient encoding carries.
fn recipient_from(data: &[u8]) -> Result<CallerRecipient> {
    let public_key: [u8; 32] = data
        .try_into()
        .map_err(|_| Error::InvalidKey("a plugin recipient key is 32 bytes"))?;
    Ok(CallerRecipient {
        key: AgeRecipient::from_x25519_bytes(public_key),
    })
}

/// Decodes the 32-byte X25519 secret key a plugin identity encoding carries.
fn identity_from(data: &[u8]) -> Result<CallerIdentity> {
    let private_key: [u8; 32] = data
        .try_into()
        .map_err(|_| Error::InvalidKey("a plugin identity key is 32 bytes"))?;
    Ok(CallerIdentity {
        key: AgeIdentity::from_x25519_bytes(private_key),
    })
}

/// A factory can be built as a named value, handed to a public builder, and
/// asked for the value it advertises.
///
/// Both factories return a real recipient and a real identity rather than an
/// error. A factory closure that only ever returns `Err` still satisfies its
/// alias, which is why nameability on its own is not the claim worth making.
#[test]
fn plugin_factory_types_are_nameable() {
    let recipient_factory: RecipientFactory = Arc::new(move |data, _context: &PluginContext| {
        Ok(Box::new(recipient_from(data)?) as Box<dyn Recipient>)
    });
    let identity_factory: IdentityFactory = Arc::new(move |data, _context: &PluginContext| {
        Ok(Box::new(identity_from(data)?) as Box<dyn Identity>)
    });

    let plugin = Plugin::new("example")
        .expect("valid plugin name")
        .handle_recipient(Arc::clone(&recipient_factory))
        .handle_identity_as_recipient(recipient_factory)
        .handle_identity(identity_factory);

    assert_eq!(plugin.name(), "example");
}

/// A recipient the caller implements really wraps a file key.
///
/// The trait compiling and the trait working are different claims. This one is
/// about working: the container is built through `encrypt_with_recipients` with
/// a `Box<dyn Recipient>` this file wrote, and read back with the identity that
/// matches it, so a `wrap` that returned an empty stanza list or a body of the
/// wrong length would fail here.
#[test]
fn a_caller_implemented_recipient_round_trips_real_data() {
    let key = AgeKey::generate().expect("key");
    let recipient = CallerRecipient {
        key: AgeRecipient::from_public_key(&key.public_key).expect("recipient"),
    };
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");

    let recipients: Vec<Box<dyn Recipient>> = vec![Box::new(recipient)];
    let container = encrypt_with_recipients(PLAINTEXT, &recipients).expect("encrypt");
    assert!(
        container.starts_with(b"age-encryption.org/v1\n"),
        "{:?}",
        String::from_utf8_lossy(&container[..32])
    );
    assert_eq!(
        decrypt(&container, &[identity]).expect("decrypt"),
        PLAINTEXT
    );
}

/// Writes whatever the plugin sends into a buffer the test can read back.
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads the plugin's first stanza of `kind` back out of its own output.
///
/// Parsed rather than substring-matched, so the assertions below are about the
/// stanza the plugin actually wrote and not about text near it.
fn first_stanza(output: &str, kind: &str) -> (Vec<String>, Vec<u8>) {
    let mut lines = output
        .lines()
        .skip_while(|line| !line.starts_with(&format!("-> {kind} ")));
    let header = lines.next().expect("a plugin stanza");
    let mut encoded = String::new();
    for line in lines {
        // The protocol ends a body with an empty line or the next stanza line,
        // so anything that is one of those is not body.
        if line.is_empty() || line.len() > 64 || line.starts_with("-> ") {
            break;
        }
        encoded.push_str(line);
    }
    let fields = header
        .split_whitespace()
        .skip(2)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (
        fields,
        STANDARD_NO_PAD.decode(encoded).expect("stanza body"),
    )
}

/// A registered recipient factory, reached through the plugin's public entry
/// point, wraps a real file key into a real age stanza.
///
/// `Plugin::run_with_io` is the entire server-side plugin surface: it parses the
/// `age1<name>1...` encoding, calls the registered factory with the decoded
/// payload, and hands the stanzas the factory's recipient produced back over the
/// protocol. This drives that path with the client half of the age plugin
/// protocol, so an alias that resolves to a signature the state machine cannot
/// call fails here instead of passing a type check.
#[test]
fn plugin_recipient_factory_wraps_a_real_file_key() {
    let key = AgeKey::generate().expect("key");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let (_, public_key) = bech32::decode(&key.public_key).expect("public key payload");
    let encoding = encode_recipient("example", &public_key).expect("plugin recipient encoding");
    assert_eq!(
        parse_plugin_recipient(&encoding).expect("parse").0,
        "example"
    );

    // The factory is reached only by the state machine, so the recipient it
    // built is captured on the way out to be exercised on its own below.
    let built = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&built);
    let factory: RecipientFactory = Arc::new(move |data, _context: &PluginContext| {
        let recipient = recipient_from(data)?;
        *sink.lock().expect("factory lock") = Some(recipient.clone());
        Ok(Box::new(recipient) as Box<dyn Recipient>)
    });
    let plugin = Plugin::new("example")
        .expect("plugin name")
        .handle_recipient(factory);

    // Add the recipient, offer it a 16-byte file key to wrap, then acknowledge
    // the stanza the plugin writes back.
    let input = format!(
        "-> add-recipient {encoding}\n\n-> wrap-file-key\n{}\n\n-> done\n\n-> ok\n\n",
        STANDARD_NO_PAD.encode([0x5au8; 16])
    );
    let output = Arc::new(Mutex::new(Vec::new()));
    let code = plugin
        .run_with_io(
            &["--age-plugin=recipient-v1".to_owned()],
            Cursor::new(input),
            Buffer(Arc::clone(&output)),
            Vec::new(),
        )
        .expect("recipient state machine");
    assert_eq!(code, 0);

    let output =
        String::from_utf8(output.lock().expect("output lock").clone()).expect("UTF-8 output");
    assert!(output.ends_with("-> done\n\n"), "{output}");
    let (fields, body) = first_stanza(&output, "recipient-stanza");
    // File key index, stanza type, and the ephemeral share.
    assert_eq!(fields.len(), 3, "{output}");
    assert_eq!(fields[0], "0", "{output}");
    assert_eq!(fields[1], "X25519", "{output}");
    assert_eq!(
        STANDARD_NO_PAD
            .decode(&fields[2])
            .expect("ephemeral share")
            .len(),
        32,
        "{output}"
    );
    // A 16-byte file key plus a ChaCha20-Poly1305 tag.
    assert_eq!(body.len(), 32, "{output}");

    // And the recipient the factory returned, used the way a caller would use
    // it, on file data of its own.
    let recipient = built
        .lock()
        .expect("factory lock")
        .clone()
        .expect("the factory ran");
    let recipients: Vec<Box<dyn Recipient>> = vec![Box::new(recipient)];
    let container = encrypt_with_recipients(PLAINTEXT, &recipients).expect("encrypt");
    assert_eq!(
        decrypt(&container, &[identity]).expect("decrypt"),
        PLAINTEXT
    );
}

/// The registered identity factory, reached the same way, unwraps a real file
/// key.
///
/// The counterpart to the test above, and the only way the `Identity`
/// implementation in this file is exercised rather than merely compiled. The
/// stanza offered here was produced by wrapping a real file key to the matching
/// real recipient, so the 16 bytes that come back are the ones that went in.
#[test]
fn plugin_identity_factory_unwraps_a_real_file_key() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let (_, private_key) = bech32::decode(&key.private_key).expect("private key payload");
    let encoding = encode_identity("example", &private_key).expect("plugin identity encoding");
    assert_eq!(
        parse_plugin_identity(&encoding).expect("parse").0,
        "example"
    );

    let factory: IdentityFactory = Arc::new(move |data, _context: &PluginContext| {
        Ok(Box::new(identity_from(data)?) as Box<dyn Identity>)
    });
    let plugin = Plugin::new("example")
        .expect("plugin name")
        .handle_identity(factory);

    let file_key = [0x5au8; 16];
    let stanza = recipient.wrap(&file_key).expect("wrap");
    let input = format!(
        "-> add-identity {encoding}\n\n-> recipient-stanza 0 {kind} {share}\n{body}\n\n-> done\n\n-> ok\n\n",
        kind = stanza.r#type,
        share = stanza.args[0],
        body = STANDARD_NO_PAD.encode(&stanza.body),
    );
    let output = Arc::new(Mutex::new(Vec::new()));
    let code = plugin
        .run_with_io(
            &["--age-plugin=identity-v1".to_owned()],
            Cursor::new(input),
            Buffer(Arc::clone(&output)),
            Vec::new(),
        )
        .expect("identity state machine");
    assert_eq!(code, 0);

    let output =
        String::from_utf8(output.lock().expect("output lock").clone()).expect("UTF-8 output");
    assert!(output.ends_with("-> done\n\n"), "{output}");
    let (fields, key) = first_stanza(&output, "file-key");
    assert_eq!(fields, ["0"], "{output}");
    assert_eq!(key, file_key, "{output}");
}

/// The factory aliases are the parameter types of the public builders, and the
/// name a plugin registers under is what its recipient encodings carry.
#[test]
fn plugin_name_reaches_the_public_recipient_encoding() {
    let key = AgeKey::generate().expect("key");
    let (_, public_key) = bech32::decode(&key.public_key).expect("public key payload");
    let factory: RecipientFactory = Arc::new(move |data, _context: &PluginContext| {
        Ok(Box::new(recipient_from(data)?) as Box<dyn Recipient>)
    });
    let plugin = Plugin::new("Example")
        .expect("plugin name")
        .handle_recipient(factory);

    // The name comes from the plugin, not from the string written here: a
    // registered name is normalized, and the encoding carries what the plugin
    // says it is called.
    let encoding = encode_recipient(plugin.name(), &public_key).expect("plugin recipient encoding");
    assert!(encoding.starts_with("age1example1"), "{encoding}");
    assert_eq!(
        parse_plugin_recipient(&encoding).expect("parse").0,
        plugin.name()
    );
}
