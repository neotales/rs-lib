// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

pub use neotales_ssh::MAX_PACKET_CONTENT;

#[path = "../src/msg/mod.rs"]
mod msg;

#[allow(dead_code, unused_imports)]
#[path = "../src/kex/mod.rs"]
mod kex;

#[allow(dead_code, unused_imports)]
#[path = "../src/cipher.rs"]
mod cipher;

#[allow(dead_code, unused_imports)]
#[path = "../src/sequence.rs"]
mod sequence;

#[allow(dead_code, unused_imports)]
#[path = "../src/hostkey.rs"]
mod hostkey;

#[allow(dead_code, unused_imports)]
#[path = "../src/transport.rs"]
mod transport;

#[allow(dead_code, unused_imports)]
#[path = "../src/client/mod.rs"]
mod client;

#[allow(dead_code, unused_imports)]
#[path = "../src/server/mod.rs"]
mod server;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::rc::Rc;

use client::ClientConfig;
use hostkey::Ed25519Signer;
use kex::DerivationLengths;
use kex::dh_group16::{
    DH_GROUP16_PRIME_HEX, DhGroup16, Group16ClientKex, Group16KexCompletion, Group16KexContext,
    Group16ServerKex, compute_group16_exchange_hash, derive_keys_sha512,
};
use msg::kexinit::{
    AES128_CTR, COMPRESSION_NONE, HMAC_SHA2_256, HOST_KEY_SSH_ED25519,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512, KexInit,
};
use neotales_ssh::{Reader, Writer, decode_mpint, encode_mpint};
use rsa::BigUint;
use server::ServerConfig;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A compile-time assertion that a type does **not** implement a trait.
///
/// The resolution trick: the method is called on `Type as Ambiguous<_>` with an
/// inferred argument. There is one implementation for every `?Sized` type whose
/// argument is `()`, and one for every type that implements the trait whose
/// argument is `PhantomData<()>` — two different argument types, so the `_` is
/// pinned to `()` and the trait implementation becomes a candidate only when the
/// bound is actually satisfied. With exactly one candidate the call compiles.
/// With two, it does not, so putting the trait back breaks this file at compile
/// time rather than passing quietly.
///
/// One trait per invocation, because two trait-bound implementations of the same
/// generic type would conflict with each other rather than with the assertion.
///
/// This is the shape `static_assertions::assert_not_impl_any!` uses, written out
/// rather than depended on, because this crate takes no dependency it does not
/// need. It is a deliberate copy of the macro in `tests/kex.rs` instead of a
/// shared one: a `macro_rules!` macro is private to the crate that defines it
/// and every integration test binary is its own crate, so sharing it would need
/// an include path that buys nothing. The two copies have to stay in step, and
/// the assertions below are what make the copy in this binary worth having.
macro_rules! assert_not_impl {
    ($trait:ident for $ty:ty) => {
        const _: () = {
            use std::marker::PhantomData;

            trait AmbiguousIfImpl<Marker> {
                fn marker() {}
            }

            impl<T: ?Sized> AmbiguousIfImpl<()> for T {
                fn marker() {}
            }

            impl<T: ?Sized + $trait> AmbiguousIfImpl<PhantomData<()>> for T {
                fn marker() {}
            }

            let _ = <$ty as AmbiguousIfImpl<_>>::marker;
        };
    };
}

// A completed group 16 exchange holds the shared secret, so `==` on two of them
// would be `Vec`'s length-then-`memcmp` over that secret and over nothing else:
// the one question about an ECDH secret whose answer must not be visible in
// timing, asked through the most ordinary-looking expression there is. The
// traits are absent by design, which is what these two lines enforce — this file
// writes the `assert_secrets_agree` below precisely because `assert_eq!` is not
// available to it. `Clone` is present and deliberately not asserted against,
// because the completion is both returned and stored and each copy wipes; its
// own doc says so, and the same reasoning is what keeps `Clone` off
// `kex::ExchangeHashInput`.
assert_not_impl!(PartialEq for Group16KexCompletion);
assert_not_impl!(Eq for Group16KexCompletion);

// The secret underneath that completion, enforced at this binary's own boundary
// as well as in `tests/kex.rs`. The helper below documents that the comparison
// is not on offer; a claim that is only checked in one of the two test binaries
// that rely on it is a claim one deletion away from being wrong.
assert_not_impl!(PartialEq for kex::SharedSecret);
assert_not_impl!(Eq for kex::SharedSecret);

const CLIENT_VERSION: &str = "SSH-2.0-dh-group16-client";
const SERVER_VERSION: &str = "SSH-2.0-dh-group16-server";
const HOST_KEY_BLOB: &[u8] = b"group16-host-key";
const SIGNATURE_BLOB: &[u8] = b"group16-signature";

/// Asserts that two shared secrets are the same value, on purpose.
///
/// `kex::SharedSecret` is not `PartialEq`, and that is the point: `Vec`'s
/// comparison is length-then-`memcmp`, so `assert_eq!` on two of them would
/// answer "are these ECDH secrets equal" in time proportional to their matching
/// prefix. This is the form the rustdoc on the type asks a caller to use —
/// digest each value, compare the digests in constant time — written out here
/// so the group16 exchange asserts agreement the way the crate intends rather
/// than skipping the assertion.
///
/// The group16 secret is bigger and slower to derive than curve25519's, so the
/// digest is cheap next to recomputing either side.
fn assert_secrets_agree(left: &kex::SharedSecret, right: &kex::SharedSecret) {
    let left_digest = Sha256::digest(left.as_bytes());
    let right_digest = Sha256::digest(right.as_bytes());
    assert!(
        bool::from(left_digest.as_slice().ct_eq(right_digest.as_slice())),
        "the two shared secrets differ"
    );
}

#[test]
fn fixed_private_exponents_match_independent_modexp_and_mpint()
-> Result<(), Box<dyn std::error::Error>> {
    let mechanism = DhGroup16::new();
    let mut alice_private = [0_u8; 64];
    let mut bob_private = [0_u8; 64];
    alice_private[63] = 2;
    bob_private[63] = 3;
    let alice = mechanism.from_private_bytes(alice_private)?;
    let bob = mechanism.from_private_bytes(bob_private)?;
    let alice_public = mechanism.public_key(&alice)?;
    let bob_public = mechanism.public_key(&bob)?;

    let alice_shared = mechanism.agree(alice, &bob_public)?;
    let bob_shared = mechanism.agree(bob, &alice_public)?;
    assert_secrets_agree(&alice_shared, &bob_shared);

    let prime = BigUint::parse_bytes(DH_GROUP16_PRIME_HEX.as_bytes(), 16)
        .ok_or("group16 prime did not parse")?;
    let exponent = BigUint::from_bytes_be(&alice_private) * BigUint::from_bytes_be(&bob_private);
    let expected = BigUint::from(2_u8).modpow(&exponent, &prime);
    assert_eq!(
        alice_shared.as_bytes(),
        &encode_mpint(expected.to_bytes_be())?
    );
    assert_eq!(
        decode_mpint(alice_shared.as_bytes())?,
        expected.to_bytes_be()
    );
    Ok(())
}

#[test]
fn public_values_one_and_p_minus_one_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mechanism = DhGroup16::new();
    let mut private = [0_u8; 64];
    private[63] = 2;
    let ephemeral = mechanism.from_private_bytes(private)?;
    let prime = BigUint::parse_bytes(DH_GROUP16_PRIME_HEX.as_bytes(), 16)
        .ok_or("group16 prime did not parse")?;
    let p_minus_one = (&prime - BigUint::from(1_u8)).to_bytes_be();
    // `.err()` rather than comparing the whole `Result`: the `Ok` arm carries a
    // `SharedSecret`, and this file does not compare two of those with `==`.
    assert_eq!(
        mechanism
            .agree(mechanism.from_private_bytes(private)?, &[1],)
            .err(),
        Some(kex::KexError::InvalidPublicKey)
    );
    assert_eq!(
        mechanism
            .agree(mechanism.from_private_bytes(private)?, &p_minus_one)
            .err(),
        Some(kex::KexError::InvalidPublicKey)
    );
    let client = proposal([7; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let server = proposal([8; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let context = Group16KexContext::new(
        CLIENT_VERSION,
        SERVER_VERSION,
        client.encode()?,
        server.encode()?,
    )?;
    let shared = mechanism.agree(ephemeral, &[3])?;
    assert_eq!(
        compute_group16_exchange_hash(
            context.client_version(),
            context.server_version(),
            context.client_kexinit(),
            context.server_kexinit(),
            HOST_KEY_BLOB,
            &[1],
            &[3],
            &shared,
        ),
        Err(kex::KexError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn group16_messages_and_sha512_hash_have_exact_framing() -> Result<(), Box<dyn std::error::Error>> {
    let mechanism = DhGroup16::new();
    let mut private = [0_u8; 64];
    private[63] = 2;
    let ephemeral = mechanism.from_private_bytes(private)?;
    let public = mechanism.public_key(&ephemeral)?;
    let message = mechanism.encode_init_message(&ephemeral)?;
    let mut reader = Reader::new(&message);
    assert_eq!(reader.read_byte()?, 30);
    assert_eq!(reader.read_mpint()?, {
        let mut framed = Writer::new();
        framed.write_mpint(public.as_slice())?;
        let mut result = Reader::new(framed.as_bytes());
        result.read_mpint()?.to_vec()
    });
    reader.ensure_finished()?;

    let shared = mechanism.agree(ephemeral, &[3])?;
    let client = proposal([1; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let server = proposal([2; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let context = Group16KexContext::new(
        CLIENT_VERSION,
        SERVER_VERSION,
        client.encode()?,
        server.encode()?,
    )?;
    let hash = compute_group16_exchange_hash(
        context.client_version(),
        context.server_version(),
        context.client_kexinit(),
        context.server_kexinit(),
        HOST_KEY_BLOB,
        &public,
        &[3],
        &shared,
    )?;
    assert_eq!(hash.len(), 64);
    let lengths = DerivationLengths {
        a: 16,
        b: 16,
        c: 16,
        d: 16,
        e: 32,
        f: 32,
    };
    let keys = derive_keys_sha512(&shared, &hash, &hash, lengths)?;
    assert_eq!(keys.iv_client_to_server.len(), 16);
    assert_eq!(keys.integrity_key_server_to_client.len(), 32);
    Ok(())
}

#[test]
fn group16_roles_agree_on_a_64_byte_session_id() -> Result<(), Box<dyn std::error::Error>> {
    let client = proposal([3; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let server = proposal([4; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512);
    let context = Group16KexContext::new(
        CLIENT_VERSION,
        SERVER_VERSION,
        client.encode()?,
        server.encode()?,
    )?;
    let mut client_role = Group16ClientKex::new(DhGroup16::new(), context.clone())?;
    let mut server_role = Group16ServerKex::new(DhGroup16::new(), context, HOST_KEY_BLOB)?;
    let init = client_role.init_message()?;
    server_role.accept_init(&init)?;
    let server_completion = server_role.prepare_exchange()?.clone();
    let reply = server_role.reply_message(SIGNATURE_BLOB)?;
    let client_completion = client_role.complete(&reply)?;
    assert_eq!(
        client_completion.exchange_hash(),
        server_completion.exchange_hash()
    );
    assert_eq!(
        client_completion.session_id(),
        client_completion.exchange_hash()
    );
    assert_eq!(client_completion.session_id().len(), 64);
    assert_secrets_agree(
        client_completion.shared_secret(),
        server_completion.shared_secret(),
    );
    assert_eq!(client_completion.signature_blob(), Some(SIGNATURE_BLOB));
    Ok(())
}

#[test]
fn client_and_server_configs_complete_group16_in_memory_handshake()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_seed(&mut [91; 32]);
    let expected_key = *signer.public_key();
    let client_config =
        ClientConfig::with_kexinit(proposal([5; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512));
    let server_config = ServerConfig::new(signer)
        .with_kexinit(proposal([6; 16], KEX_DIFFIE_HELLMAN_GROUP16_SHA512));
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let server_handshake = Rc::new(RefCell::new(None));
    let server_error = Rc::new(RefCell::new(None));
    let driver = {
        let server_stream = server_stream.clone();
        let server_handshake = Rc::clone(&server_handshake);
        let server_error = Rc::clone(&server_error);
        let client_to_server = Rc::clone(&client_to_server);
        let server_config = &server_config;
        Rc::new(RefCell::new(move || {
            advance_server(
                server_config,
                server_stream.clone(),
                &server_handshake,
                &server_error,
                &client_to_server,
            );
        })) as Driver<'_>
    };
    client_stream.set_driver(driver);

    let mut client = client_config.connect(client_stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    let mut server = server_handshake
        .borrow_mut()
        .take()
        .ok_or("server handshake did not complete")?
        .into_transport()?;
    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(client.session_id(), server.session_id());
    assert_eq!(client.session_id().len(), 64);
    assert_eq!(server.session_id().len(), 64);
    let payload = [5, 0, 0, 0, 4, b'g', b'1', b'6'];
    client.write_payload(&payload)?;
    assert_eq!(server.read_auth_packet()?, payload);
    if let Some(error) = server_error.borrow_mut().take() {
        return Err(Box::new(error));
    }
    Ok(())
}

fn proposal(cookie: [u8; 16], kex: &str) -> KexInit {
    KexInit::from_lists(
        cookie,
        vec![kex.to_owned()],
        vec![HOST_KEY_SSH_ED25519.to_owned()],
        vec![AES128_CTR.to_owned()],
        vec![AES128_CTR.to_owned()],
        vec![HMAC_SHA2_256.to_owned()],
        vec![HMAC_SHA2_256.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

fn advance_server<'a, S>(
    config: &'a ServerConfig,
    server_stream: S,
    handshake: &Rc<RefCell<Option<server::ServerHandshake<'a, S>>>>,
    error: &Rc<RefCell<Option<server::HandshakeError>>>,
    client_to_server: &Rc<RefCell<VecDeque<u8>>>,
) where
    S: Read + Write,
{
    let mut handshake = handshake.borrow_mut();
    if handshake.is_none() {
        if !has_client_identification(client_to_server) {
            return;
        }
        match config.start(server_stream) {
            Ok(started) => *handshake = Some(started),
            Err(start_error) => {
                *error.borrow_mut() = Some(start_error);
                return;
            }
        }
    }
    let Some(started) = handshake.as_mut() else {
        return;
    };
    if let Err(advance_error) = started.advance() {
        *error.borrow_mut() = Some(advance_error);
    }
}

fn has_client_identification(bytes: &Rc<RefCell<VecDeque<u8>>>) -> bool {
    let bytes: Vec<u8> = bytes.borrow().iter().copied().collect();
    let mut line_start = 0_usize;
    while let Some(relative_end) = bytes[line_start..]
        .windows(2)
        .position(|window| window == b"\r\n")
    {
        let end = line_start + relative_end;
        if bytes
            .get(line_start..end)
            .is_some_and(|line| line.starts_with(b"SSH-"))
        {
            return true;
        }
        line_start = end + 2;
    }
    false
}

fn duplex_pair<'a>() -> (Stream<'a>, Stream<'a>, Rc<RefCell<VecDeque<u8>>>) {
    let client_to_server = Rc::new(RefCell::new(VecDeque::new()));
    let server_to_client = Rc::new(RefCell::new(VecDeque::new()));
    let client = Stream {
        input: Rc::clone(&server_to_client),
        output: Rc::clone(&client_to_server),
        driver: None,
    };
    let server = Stream {
        input: Rc::clone(&client_to_server),
        output: server_to_client,
        driver: None,
    };
    (client, server, client_to_server)
}

type Driver<'a> = Rc<RefCell<dyn FnMut() + 'a>>;

#[derive(Clone)]
struct Stream<'a> {
    input: Rc<RefCell<VecDeque<u8>>>,
    output: Rc<RefCell<VecDeque<u8>>>,
    driver: Option<Driver<'a>>,
}

impl<'a> Stream<'a> {
    fn set_driver(&mut self, driver: Driver<'a>) {
        self.driver = Some(driver);
    }

    fn drive(&mut self) {
        let Some(driver) = self.driver.clone() else {
            return;
        };
        driver.borrow_mut()();
    }
}

impl Read for Stream<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        if self.input.borrow().is_empty() {
            self.drive();
        }
        let mut input = self.input.borrow_mut();
        if input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory client stream is waiting for the server",
            ));
        }
        let count = target.len().min(input.len());
        for byte in &mut target[..count] {
            *byte = input.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "in-memory queue truncated")
            })?;
        }
        Ok(count)
    }
}

impl Write for Stream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.borrow_mut().extend(bytes.iter().copied());
        self.drive();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
