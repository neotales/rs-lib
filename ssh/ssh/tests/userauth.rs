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

// `agent.rs` and `ecdsa_hostkey.rs` are pulled in because `auth.rs` now names
// `AgentClient` and `EcdsaSigner`; they are compiled the same way as every other
// module this harness borrows.
#[allow(dead_code, unused_imports)]
#[path = "../src/agent.rs"]
mod agent;

#[allow(dead_code, unused_imports)]
#[path = "../src/ecdsa_hostkey.rs"]
mod ecdsa_hostkey;

// `auth.rs` gets the same treatment as every other module this harness borrows:
// it is a private copy of a library module, so a `pub` item in it that this
// harness does not exercise is not dead library code, it is a harness that
// borrows more than it uses. Without the allow, adding anything to `auth.rs`
// turns every unrelated unused item in it into a warning here.
#[allow(dead_code, unused_imports, unreachable_pub)]
#[path = "../src/auth.rs"]
mod auth;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use crate::client::{ClientConfig, ClientTransport};
use auth::{
    AuthError, AuthMethodKind, ClientAuthMethod, ClientAuthenticator, KeyboardInteractivePrompt,
    PasswordDecision, PublicKeySigner, RsaAuthSigner, ServerAuthPolicy, ServerAuthState,
    ServerAuthStep,
};
use cipher::{PlaintextDrop, PlaintextSlot, take_plaintext_drop};
use hostkey::{Ed25519PublicKey, Ed25519Signer};
use kex::{Curve25519, KeyExchange};
use msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256,
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH, HMAC_SHA2_256, HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512,
    HMAC_SHA2_512_ETM_OPENSSH, HOST_KEY_SSH_ED25519, KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_STRICT_C_V00_OPENSSH, KexInit,
};
// `Zeroizing` is named here through `neotales_ssh`'s own root, the way a
// consumer names it. It used to be reached through
// `zeroize`, which meant a downstream crate matching
// on `ClientAuthMethod::Password` had to depend on the crypto area *and* know
// that re-export in order to use a variant of ours.
use neotales_ssh::Zeroizing;
use neotales_ssh::{Writer, build_packet_default};
use server::{
    HandshakeError, IdentificationError, ServerConfig, ServerHandshake, ServerTransport,
    ServerTransportError, TransportError,
};
use sha2::Digest;

const CLIENT_PAYLOAD: &[u8] = &[5, 0, 0, 0, 4, b'a', b'u', b't', b'h'];
const SERVER_PAYLOAD: &[u8] = &[52];

#[test]
fn client_and_server_complete_a_strict_handshake_and_exchange_auth_packets()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(11);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer).with_server_version("SSH-2.0-neotales-ssh_test");
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let server_stream_for_handshake = server_stream.clone();
    let server_handshake = Rc::new(RefCell::new(None));
    let server_error = Rc::new(RefCell::new(None));
    let server_handshake_for_callback = Rc::clone(&server_handshake);
    let server_error_for_callback = Rc::clone(&server_error);
    let client_to_server_for_callback = Rc::clone(&client_to_server);
    let config_for_callback = &config;
    let driver: Driver<'_> = Rc::new(RefCell::new(move || {
        advance_server(
            config_for_callback,
            server_stream_for_handshake.clone(),
            &server_handshake_for_callback,
            &server_error_for_callback,
            &client_to_server_for_callback,
        );
    }));
    client_stream.set_driver(driver);

    let mut client = ClientConfig::new().connect(client_stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    let mut server = server_handshake
        .borrow_mut()
        .take()
        .ok_or("server handshake did not complete")?
        .into_transport()?;

    assert!(!server.is_authenticated());
    assert!(server.is_unauthenticated());
    assert!(client.is_established());
    assert!(server.is_established());
    assert!(client.strict_kex());
    assert!(server.strict_kex());
    assert_eq!(client.session_id(), server.session_id());
    assert_eq!(client.inbound_sequence(), 0);
    assert_eq!(client.outbound_sequence(), 0);
    assert_eq!(server.inbound_sequence(), 0);
    assert_eq!(server.outbound_sequence(), 0);

    client.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(server.read_auth_packet()?, CLIENT_PAYLOAD);
    server.write_payload(SERVER_PAYLOAD)?;
    assert_eq!(client.read_payload()?, SERVER_PAYLOAD);
    assert_eq!(client.inbound_sequence(), 1);
    assert_eq!(client.outbound_sequence(), 1);
    assert_eq!(server.inbound_sequence(), 1);
    assert_eq!(server.outbound_sequence(), 1);

    if let Some(error) = server_error.borrow_mut().take() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn blocking_server_config_runs_every_handshake_phase() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(17));
    let mut client_kexinit = ClientConfig::new().kexinit().clone();
    client_kexinit.kex_algorithms = vec![
        CURVE25519_SHA256.to_owned(),
        KEX_STRICT_C_V00_OPENSSH.to_owned(),
    ];
    client_kexinit.cookie = [17; 16];
    let mechanism = Curve25519::standard();
    let ephemeral = mechanism.generate_ephemeral()?;
    let init = mechanism.encode_init_message(&ephemeral)?;
    let mut input = Vec::new();
    input.extend_from_slice(b"SSH-2.0-neotales-ssh_0.1\r\n");
    let payloads = vec![client_kexinit.encode()?, init, vec![21]];
    for payload in payloads {
        input.extend_from_slice(&build_packet_default(&payload, |padding| {
            padding.fill(0xa5);
        })?);
    }
    let mut stream = BlockingStream {
        input: Cursor::new(input),
        output: Vec::new(),
    };
    let transport = config.connect(&mut stream)?;
    assert!(transport.is_established());
    assert_eq!(transport.inbound_sequence(), 0);
    assert_eq!(transport.outbound_sequence(), 0);
    drop(transport);
    assert!(stream.output.starts_with(b"SSH-2.0-neotales-ssh_0.1\r\n"));
    Ok(())
}

#[test]
fn server_identification_is_bounded_and_sent_after_the_client_banner()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(18));
    let mut legal_input = b"legal pre-banner\r\n".to_vec();
    legal_input.extend_from_slice(b"SSH-2.0-neotales-ssh_0.1\r\n");
    let mut legal_stream = BlockingStream {
        input: Cursor::new(legal_input),
        output: Vec::new(),
    };
    let handshake = config.start(&mut legal_stream)?;
    assert!(!handshake.is_complete());
    drop(handshake);
    assert!(
        legal_stream
            .output
            .starts_with(b"SSH-2.0-neotales-ssh_0.1\r\n")
    );

    let mut oversized = Vec::new();
    for _ in 0..34 {
        oversized.extend(std::iter::repeat_n(b'x', 250));
        oversized.extend_from_slice(b"\r\n");
    }
    let mut oversized_stream = BlockingStream {
        input: Cursor::new(oversized),
        output: Vec::new(),
    };
    assert!(matches!(
        config.start(&mut oversized_stream),
        Err(HandshakeError::Transport(TransportError::Identification(
            IdentificationError::PreBannerTooLong
        )))
    ));
    Ok(())
}

#[test]
fn default_server_proposal_matches_the_supported_client_lists() {
    let config = ServerConfig::new(signer(13));
    let proposal = config.kexinit();
    assert_eq!(
        proposal.kex_algorithms,
        [
            "mlkem768x25519-sha256",
            CURVE25519_SHA256,
            CURVE25519_SHA256_LIBSSH,
            ECDH_SHA2_NISTP256,
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
            "kex-strict-s-v00@openssh.com",
        ]
        .map(str::to_owned)
    );
    assert_eq!(
        proposal.server_host_key_algorithms,
        [HOST_KEY_SSH_ED25519.to_owned()]
    );
    for names in [
        &proposal.encryption_algorithms_client_to_server,
        &proposal.encryption_algorithms_server_to_client,
    ] {
        assert_eq!(
            names,
            &[
                ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
                AES128_CTR,
                AES256_CTR,
                AES128_GCM_OPENSSH,
                AES256_GCM_OPENSSH,
            ]
            .map(str::to_owned)
        );
        assert!(!names.iter().any(|name| name == "zlib"));
    }
    for names in [
        &proposal.mac_algorithms_client_to_server,
        &proposal.mac_algorithms_server_to_client,
    ] {
        assert_eq!(
            names,
            &[
                HMAC_SHA2_256,
                HMAC_SHA2_512,
                HMAC_SHA2_256_ETM_OPENSSH,
                HMAC_SHA2_512_ETM_OPENSSH,
            ]
            .map(str::to_owned)
        );
    }
    assert_eq!(
        proposal.compression_algorithms_client_to_server,
        [
            COMPRESSION_NONE.to_owned(),
            COMPRESSION_ZLIB_OPENSSH.to_owned()
        ]
    );
    assert_eq!(
        proposal.compression_algorithms_server_to_client,
        [
            COMPRESSION_NONE.to_owned(),
            COMPRESSION_ZLIB_OPENSSH.to_owned()
        ]
    );
}

#[test]
fn one_strict_marker_does_not_reset_server_sequences() -> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(14);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let client_config = ClientConfig::with_kexinit(proposal(
        CURVE25519_SHA256,
        AES128_CTR,
        HMAC_SHA2_256,
        false,
    ));
    run_echo(&config, &client_config, &expected_key, false)
}

#[test]
fn directional_server_keys_use_the_opposite_client_and_server_suites()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(15);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let mut client_proposal = proposal(CURVE25519_SHA256, AES128_CTR, HMAC_SHA2_256, true);
    client_proposal.encryption_algorithms_server_to_client = vec![AES256_GCM_OPENSSH.to_owned()];
    client_proposal.mac_algorithms_server_to_client = vec![HMAC_SHA2_512.to_owned()];
    let client_config = ClientConfig::with_kexinit(client_proposal);
    run_echo(&config, &client_config, &expected_key, true)
}

#[test]
fn all_supported_kex_and_packet_suites_round_trip_through_the_server()
-> Result<(), Box<dyn std::error::Error>> {
    let kexes = [
        CURVE25519_SHA256,
        CURVE25519_SHA256_LIBSSH,
        ECDH_SHA2_NISTP256,
    ];
    let suites = [
        (AES128_CTR, HMAC_SHA2_256),
        (AES256_CTR, HMAC_SHA2_512),
        (AES128_GCM_OPENSSH, HMAC_SHA2_256),
        (AES256_GCM_OPENSSH, HMAC_SHA2_512),
    ];
    let mut seed = 20_u8;
    for kex in kexes {
        for (cipher, mac) in suites {
            seed = seed.wrapping_add(1);
            let signer = signer(seed);
            let expected_key = *signer.public_key();
            let config = ServerConfig::new(signer);
            let client_config = ClientConfig::with_kexinit(proposal(kex, cipher, mac, true));
            run_echo(&config, &client_config, &expected_key, true)?;
        }
    }
    Ok(())
}

fn run_echo(
    config: &ServerConfig,
    client_config: &ClientConfig,
    expected_key: &Ed25519PublicKey,
    expected_strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let server_handshake = Rc::new(RefCell::new(None));
    let server_error = Rc::new(RefCell::new(None));
    let driver = {
        let server_stream = server_stream.clone();
        let server_handshake = Rc::clone(&server_handshake);
        let server_error = Rc::clone(&server_error);
        let client_to_server = Rc::clone(&client_to_server);
        let config = &config;
        Rc::new(RefCell::new(move || {
            advance_server(
                config,
                server_stream.clone(),
                &server_handshake,
                &server_error,
                &client_to_server,
            );
        })) as Driver<'_>
    };
    client_stream.set_driver(driver);
    let mut client = client_config.connect(client_stream, |key| {
        assert_eq!(key, expected_key);
        Ok::<(), Infallible>(())
    })?;
    let mut server = server_handshake
        .borrow_mut()
        .take()
        .ok_or("server handshake did not complete")?
        .into_transport()?;
    assert_eq!(client.strict_kex(), expected_strict);
    assert_eq!(server.strict_kex(), expected_strict);
    assert_eq!(client.session_id(), server.session_id());
    assert_eq!(
        server.inbound_sequence(),
        if expected_strict { 0 } else { 3 }
    );
    assert_eq!(
        server.outbound_sequence(),
        if expected_strict { 0 } else { 3 }
    );
    client.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(server.read_auth_packet()?, CLIENT_PAYLOAD);
    server.write_payload(SERVER_PAYLOAD)?;
    assert_eq!(client.read_payload()?, SERVER_PAYLOAD);
    if let Some(error) = server_error.borrow_mut().take() {
        return Err(Box::new(error));
    }
    Ok(())
}

fn proposal(kex: &str, cipher: &str, mac: &str, strict: bool) -> KexInit {
    let mut kex_names = vec![kex.to_owned()];
    if strict {
        kex_names.push(KEX_STRICT_C_V00_OPENSSH.to_owned());
    }
    KexInit::from_lists(
        [0; 16],
        kex_names,
        vec![HOST_KEY_SSH_ED25519.to_owned()],
        vec![cipher.to_owned()],
        vec![cipher.to_owned()],
        vec![mac.to_owned()],
        vec![mac.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

#[test]
fn unauthenticated_server_rejects_non_auth_packets_without_advancing_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(12);
    let config = ServerConfig::new(signer);
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let server_handshake = Rc::new(RefCell::new(None));
    let server_error = Rc::new(RefCell::new(None));
    let driver = {
        let server_stream = server_stream.clone();
        let server_handshake = Rc::clone(&server_handshake);
        let server_error = Rc::clone(&server_error);
        let client_to_server = Rc::clone(&client_to_server);
        let config = &config;
        Rc::new(RefCell::new(move || {
            advance_server(
                config,
                server_stream.clone(),
                &server_handshake,
                &server_error,
                &client_to_server,
            );
        })) as Driver<'_>
    };
    client_stream.set_driver(driver);
    let mut client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    let mut server = server_handshake
        .borrow_mut()
        .take()
        .ok_or("server handshake did not complete")?
        .into_transport()?;
    client.write_payload(&[80, b'n', b'o'])?;
    assert!(matches!(
        server.read_auth_packet(),
        Err(ServerTransportError::UnauthenticatedMessage)
    ));
    assert_eq!(server.inbound_sequence(), 0);
    Ok(())
}

fn advance_server<'a, S>(
    config: &'a ServerConfig,
    server_stream: S,
    handshake: &Rc<RefCell<Option<ServerHandshake<'a, S>>>>,
    error: &Rc<RefCell<Option<HandshakeError>>>,
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

struct BlockingStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for BlockingStream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.input.read(target)
    }
}

impl Write for BlockingStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&mut [seed; 32])
}

#[derive(Clone, Copy)]
enum KeyboardScript {
    Success,
    PromptCount(usize),
}

struct AuthDriver<'a> {
    config: &'a ServerConfig,
    server_stream: Stream<'a>,
    client_to_server: Rc<RefCell<VecDeque<u8>>>,
    handshake: RefCell<Option<ServerHandshake<'a, Stream<'a>>>>,
    handshake_started: Cell<bool>,
    transport: RefCell<Option<ServerTransport<Stream<'a>>>>,
    policy: ServerAuthPolicy,
    state: Cell<ServerAuthState>,
    error: RefCell<Option<AuthError>>,
    authenticated: Cell<bool>,
    scripted: bool,
    keyboard_script: Option<KeyboardScript>,
    script_step: Cell<u8>,
    paused: bool,
}

impl<'a> AuthDriver<'a> {
    fn drive(&self) {
        if !self.handshake_started.get() {
            if !has_client_identification(&self.client_to_server) {
                return;
            }
            match self.config.start(self.server_stream.clone()) {
                Ok(started) => {
                    self.handshake_started.set(true);
                    *self.handshake.borrow_mut() = Some(started);
                }
                Err(_error) => {
                    self.set_error(AuthError::Transport);
                    return;
                }
            }
        }

        let mut handshake_failed = false;
        let mut handshake_complete = false;
        {
            let mut handshake = self.handshake.borrow_mut();
            if let Some(started) = handshake.as_mut() {
                match started.advance() {
                    Ok(_) => handshake_complete = started.is_complete(),
                    Err(_error) => handshake_failed = true,
                }
            }
        }
        if handshake_failed {
            self.set_error(AuthError::Transport);
            return;
        }
        if handshake_complete {
            let started = self.handshake.borrow_mut().take();
            if let Some(started) = started {
                match started.into_transport() {
                    Ok(transport) => {
                        *self.transport.borrow_mut() = Some(transport);
                        return;
                    }
                    Err(_error) => {
                        self.set_error(AuthError::Transport);
                        return;
                    }
                }
            }
        }
        if self.authenticated.get() {
            return;
        }
        if self.paused {
            return;
        }
        if self.scripted {
            self.drive_scripted();
            return;
        }
        let Some(mut transport) = self.transport.borrow_mut().take() else {
            return;
        };
        let result = {
            let mut authenticator = auth::ServerAuthenticator::from_state(
                &mut transport,
                &self.policy,
                self.state.get(),
            );
            let result = authenticator.step();
            self.state.set(authenticator.state());
            result
        };
        match result {
            Ok(ServerAuthStep::Authenticated) => self.authenticated.set(true),
            Ok(
                ServerAuthStep::NeedMoreData
                | ServerAuthStep::ServiceAccepted
                | ServerAuthStep::PublicKeyQueryAccepted
                | ServerAuthStep::Failure,
            )
            | Err(AuthError::NeedMoreData) => {}
            Err(error) => self.set_error(error),
        }
        *self.transport.borrow_mut() = Some(transport);
    }

    fn drive_scripted(&self) {
        let Some(mut transport) = self.transport.borrow_mut().take() else {
            return;
        };
        if self.keyboard_script.is_some() && self.script_step.get() >= 2 {
            let result = transport
                .write_payload(&[auth::SSH_MSG_USERAUTH_SUCCESS])
                .map_err(AuthError::from);
            if result.is_ok() {
                self.script_step.set(3);
            }
            if let Err(error) = result {
                self.set_error(error);
            }
            *self.transport.borrow_mut() = Some(transport);
            return;
        }
        let payload = match transport.read_auth_packet() {
            Ok(payload) => payload,
            Err(ServerTransportError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                *self.transport.borrow_mut() = Some(transport);
                return;
            }
            Err(_error) => {
                *self.transport.borrow_mut() = Some(transport);
                self.set_error(AuthError::Transport);
                return;
            }
        };
        let result = (|| -> Result<(), AuthError> {
            match payload.first().copied() {
                Some(auth::SSH_MSG_SERVICE_REQUEST) => {
                    let mut response = Writer::new();
                    response.write_byte(auth::SSH_MSG_SERVICE_ACCEPT);
                    response.write_string(auth::SSH_USERAUTH_SERVICE)?;
                    transport
                        .write_payload(&response.into_bytes())
                        .map_err(AuthError::from)?;
                    if self.keyboard_script.is_some() {
                        self.script_step.set(1);
                    }
                    Ok(())
                }
                Some(auth::SSH_MSG_USERAUTH_REQUEST) => {
                    if let Some(script) = self.keyboard_script {
                        let count = match script {
                            KeyboardScript::Success => 1,
                            KeyboardScript::PromptCount(count) => count,
                        };
                        let request = keyboard_info_request(count)?;
                        transport.write_payload(&request).map_err(AuthError::from)?;
                        self.script_step.set(2);
                        return Ok(());
                    }
                    let mut banner = Writer::new();
                    banner.write_byte(auth::SSH_MSG_USERAUTH_BANNER);
                    banner.write_string("scripted banner")?;
                    banner.write_string("en")?;
                    transport
                        .write_payload(&banner.into_bytes())
                        .map_err(AuthError::from)?;
                    let mut failure = Writer::new();
                    failure.write_byte(auth::SSH_MSG_USERAUTH_FAILURE);
                    failure.write_name_list(["password"])?;
                    failure.write_boolean(true);
                    transport
                        .write_payload(&failure.into_bytes())
                        .map_err(AuthError::from)
                }
                _ => Err(AuthError::UnexpectedMessage),
            }
        })();
        if let Err(error) = result {
            self.set_error(error);
        }
        *self.transport.borrow_mut() = Some(transport);
    }

    fn set_error(&self, error: AuthError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn take_error(&self) -> Option<AuthError> {
        self.error.borrow_mut().take()
    }

    fn take_server(&self) -> Option<ServerTransport<Stream<'a>>> {
        self.transport.borrow_mut().take()
    }
}

fn connect_auth_pair<'a>(
    config: &'a ServerConfig,
    policy: ServerAuthPolicy,
) -> Result<(ClientTransport<Stream<'a>>, Rc<AuthDriver<'a>>), Box<dyn std::error::Error>> {
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let driver = Rc::new(AuthDriver {
        config,
        server_stream,
        client_to_server,
        handshake: RefCell::new(None),
        handshake_started: Cell::new(false),
        transport: RefCell::new(None),
        policy,
        state: Cell::new(ServerAuthState::initial()),
        error: RefCell::new(None),
        authenticated: Cell::new(false),
        scripted: false,
        keyboard_script: None,
        script_step: Cell::new(0),
        paused: false,
    });
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'a> = Rc::new(RefCell::new(move || callback_driver.drive()));
    client_stream.set_driver(callback);

    let client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    Ok((client, driver))
}

fn connect_paused_auth_pair<'a>(
    config: &'a ServerConfig,
) -> Result<(ClientTransport<Stream<'a>>, Rc<AuthDriver<'a>>), Box<dyn std::error::Error>> {
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let driver = Rc::new(AuthDriver {
        config,
        server_stream,
        client_to_server,
        handshake: RefCell::new(None),
        handshake_started: Cell::new(false),
        transport: RefCell::new(None),
        policy: ServerAuthPolicy::new(1)?,
        state: Cell::new(ServerAuthState::initial()),
        error: RefCell::new(None),
        authenticated: Cell::new(false),
        scripted: false,
        keyboard_script: None,
        script_step: Cell::new(0),
        paused: true,
    });
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'a> = Rc::new(RefCell::new(move || callback_driver.drive()));
    client_stream.set_driver(callback);
    let client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    Ok((client, driver))
}

fn connect_scripted_pair<'a>(
    config: &'a ServerConfig,
) -> Result<(ClientTransport<Stream<'a>>, Rc<AuthDriver<'a>>), Box<dyn std::error::Error>> {
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let driver = Rc::new(AuthDriver {
        config,
        server_stream,
        client_to_server,
        handshake: RefCell::new(None),
        handshake_started: Cell::new(false),
        transport: RefCell::new(None),
        policy: ServerAuthPolicy::new(1)?,
        state: Cell::new(ServerAuthState::initial()),
        error: RefCell::new(None),
        authenticated: Cell::new(false),
        scripted: true,
        keyboard_script: None,
        script_step: Cell::new(0),
        paused: false,
    });
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'a> = Rc::new(RefCell::new(move || callback_driver.drive()));
    client_stream.set_driver(callback);
    let client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    Ok((client, driver))
}

fn connect_keyboard_scripted_pair<'a>(
    config: &'a ServerConfig,
    script: KeyboardScript,
) -> Result<(ClientTransport<Stream<'a>>, Rc<AuthDriver<'a>>), Box<dyn std::error::Error>> {
    let (mut client_stream, server_stream, client_to_server) = duplex_pair();
    let driver = Rc::new(AuthDriver {
        config,
        server_stream,
        client_to_server,
        handshake: RefCell::new(None),
        handshake_started: Cell::new(false),
        transport: RefCell::new(None),
        policy: ServerAuthPolicy::new(1)?,
        state: Cell::new(ServerAuthState::initial()),
        error: RefCell::new(None),
        authenticated: Cell::new(false),
        scripted: true,
        keyboard_script: Some(script),
        script_step: Cell::new(0),
        paused: false,
    });
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'a> = Rc::new(RefCell::new(move || callback_driver.drive()));
    client_stream.set_driver(callback);
    let client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    Ok((client, driver))
}

fn connect_keyboard_success_pair(
    config: &ServerConfig,
) -> Result<(ClientTransport<Stream<'_>>, Rc<AuthDriver<'_>>), Box<dyn std::error::Error>> {
    connect_keyboard_scripted_pair(config, KeyboardScript::Success)
}

fn connect_keyboard_prompt_count_pair(
    config: &ServerConfig,
    count: usize,
) -> Result<(ClientTransport<Stream<'_>>, Rc<AuthDriver<'_>>), Box<dyn std::error::Error>> {
    connect_keyboard_scripted_pair(config, KeyboardScript::PromptCount(count))
}

fn keyboard_info_request(count: usize) -> Result<Vec<u8>, AuthError> {
    let mut writer = Writer::new();
    writer.write_byte(auth::SSH_MSG_USERAUTH_INFO_REQUEST);
    writer.write_string("scripted challenge")?;
    writer.write_string("enter the response")?;
    writer.write_string("en")?;
    writer.write_uint32(u32::try_from(count).map_err(|_error| AuthError::InvalidRequest)?);
    for _ in 0..count {
        writer.write_string("token")?;
        writer.write_boolean(false);
    }
    Ok(writer.into_bytes())
}

#[test]
fn ed25519_authentication_reuses_the_transport_for_application_data()
-> Result<(), Box<dyn std::error::Error>> {
    let auth_signer = signer(201);
    let auth_blob = auth_signer.public_key_blob()?;
    let config = ServerConfig::new(signer(202));
    let policy = ServerAuthPolicy::new(3)?.with_authorized_key(&auth_blob)?;
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let client_in_before = client.inbound_sequence();
    let client_out_before = client.outbound_sequence();

    let mut authenticator = ClientAuthenticator::new(&mut client, "alice", 3)?;
    let methods = [ClientAuthMethod::public_key(PublicKeySigner::ed25519(
        auth_signer,
    ))];
    let result = authenticator.authenticate(&methods)?;
    let mut server = driver.take_server().ok_or("server transport was lost")?;
    let server_in_before = 0;
    let server_out_before = 0;
    assert_eq!(result.method(), AuthMethodKind::PublicKey);
    assert!(server.is_authenticated());
    assert!(!server.is_unauthenticated());
    assert_eq!(client.inbound_sequence() - client_in_before, 3);
    assert_eq!(client.outbound_sequence() - client_out_before, 3);
    assert_eq!(server.inbound_sequence() - server_in_before, 3);
    assert_eq!(server.outbound_sequence() - server_out_before, 3);

    client.write_payload(b"channel-data")?;
    assert_eq!(server.read_payload()?, b"channel-data");
    server.write_payload(b"channel-reply")?;
    assert_eq!(client.read_payload()?, b"channel-reply");
    assert_eq!(client.inbound_sequence() - client_in_before, 4);
    assert_eq!(client.outbound_sequence() - client_out_before, 4);
    assert_eq!(server.inbound_sequence() - server_in_before, 4);
    assert_eq!(server.outbound_sequence() - server_out_before, 4);
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn rsa_sha256_publickey_authentication_uses_pkcs1_sha256() -> Result<(), Box<dyn std::error::Error>>
{
    let auth_signer = fixed_rsa_signer()?;
    let auth_blob = auth_signer.public_key_blob().to_vec();
    let config = ServerConfig::new(signer(203));
    let policy = ServerAuthPolicy::new(3)?.with_authorized_key(&auth_blob)?;
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "rsa-user", 3)?;
    let methods = [ClientAuthMethod::public_key(PublicKeySigner::rsa(
        auth_signer,
    ))];
    let result = authenticator.authenticate(&methods)?;
    assert_eq!(result.method(), AuthMethodKind::PublicKey);
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn password_authentication_retries_and_redacts_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    const PASSWORD: &str = "correct horse battery staple";
    const DISTINCTIVE: &str = "password-that-must-never-appear";
    let config = ServerConfig::new(signer(204));
    let policy =
        ServerAuthPolicy::new(3)?.with_password_callback(|candidate| candidate == PASSWORD);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "password-user", 3)?;
    let wrong = ClientAuthMethod::password(DISTINCTIVE);
    let error = authenticator
        .authenticate(&[wrong])
        .expect_err("wrong password must not authenticate");
    assert!(matches!(error, AuthError::AuthenticationFailed));
    assert!(!format!("{error:?}").contains(DISTINCTIVE));
    assert!(!format!("{error}").contains(DISTINCTIVE));
    assert!(!format!("{:?}", ClientAuthMethod::password(DISTINCTIVE)).contains(DISTINCTIVE));
    assert!(!driver.state.get().finished());

    let result = authenticator.authenticate(&[ClientAuthMethod::password(PASSWORD)])?;
    assert_eq!(result.method(), AuthMethodKind::Password);
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn a_password_method_holds_its_password_in_a_zeroizing_string() {
    // The claim here is the type of the variant's payload, so it is checked by
    // naming that type: putting a plain `String` back into the variant stops
    // this file from compiling, rather than leaving a test that passes against
    // a copy nothing wipes.
    let method = ClientAuthMethod::password("hunter2");
    let ClientAuthMethod::Password(password) = &method else {
        panic!("a password method must carry its password");
    };
    let _: &Zeroizing<String> = password;

    // A live method still has to carry a readable password, because a retry
    // after a partial success sends the same method again, and a wipe that ran
    // early would authenticate with an empty one.
    assert_eq!(password.as_str(), "hunter2");
    assert!(!format!("{method:?}").contains("hunter2"));
}

/// The payload type of `ClientAuthMethod::Password` is nameable by a consumer
/// of `neotales-ssh` and of nothing else.
///
/// `ClientAuthMethod::Password` is a public variant, so building one and
/// matching on one both require naming its payload. The type used to be
/// reachable only as `zeroize::Zeroizing`, which put
/// a dependency on a sibling crypto crate and knowledge of its re-export
/// between a caller and a variant of this crate's API. It is re-exported from
/// the crate root now, and this test is the proof: it names the type *only*
/// through `neotales_ssh`, and constructs the variant directly rather than
/// through the convenience constructor, which is the case that needs the name.
///
/// The type identity is the point, so it is asserted as an identity and not as
/// an assignability: a re-export of a *different* `Zeroizing` would satisfy a
/// `let _: &Zeroizing<String>` and would not wipe the caller's password.
#[test]
fn the_password_payload_type_is_reachable_from_the_crate_root_and_identical() {
    let method: ClientAuthMethod =
        ClientAuthMethod::Password(Zeroizing::new(String::from("hunter2")));
    let ClientAuthMethod::Password(password) = &method else {
        panic!("a password method must carry its password");
    };

    // The type this crate's own signature promises, written as a fully
    // qualified path through `neotales_ssh`, so the two spellings have to be one
    // type and not merely two types that happen to convert.
    let same: &neotales_ssh::Zeroizing<String> = password;
    assert_eq!(same.as_str(), "hunter2");

    // And it is the same type the crypto area uses, so a value handed across
    // that boundary is one value and is wiped once.
    let across: &zeroize::Zeroizing<String> = same;
    assert_eq!(across.as_str(), "hunter2");

    // The direct-construction path still gets the redaction the constructor
    // gets; otherwise the ergonomic form would be the safe one and the public
    // variant the leaky one.
    assert!(!format!("{method:?}").contains("hunter2"));
}

#[test]
fn the_encoded_password_request_is_wiped_once_the_transport_has_taken_it()
-> Result<(), Box<dyn std::error::Error>> {
    const PASSWORD: &str = "wipe-this-password";
    let config = ServerConfig::new(signer(225));
    let policy =
        ServerAuthPolicy::new(1)?.with_password_callback(|candidate| candidate == PASSWORD);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "wipe-user", 1)?;

    // A witness left on this thread by an earlier test is cleared rather than
    // asserted absent: the scheduler reuses threads, and only the one recorded
    // below can be this request's.
    let _ = take_plaintext_drop(PlaintextSlot::AuthRequest);

    let result = authenticator.authenticate(&[ClientAuthMethod::password(PASSWORD)])?;
    assert_eq!(result.method(), AuthMethodKind::Password);
    assert_eq!(
        take_plaintext_drop(PlaintextSlot::AuthRequest),
        Some(PlaintextDrop::Wiped),
        "the request buffer must hold the password before the wipe and every byte \
         of it must be zero after"
    );
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn explicit_empty_policy_and_rejecting_callbacks_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let auth_signer = signer(205);
    let auth_blob = auth_signer.public_key_blob()?;
    let config = ServerConfig::new(signer(206));
    let policy = ServerAuthPolicy::new(2)?
        .with_authorized_key(&auth_blob)?
        .with_public_key_verifier(|_algorithm, _blob, _signed, _signature| false);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "callback-user", 2)?;
    let methods = [ClientAuthMethod::public_key(PublicKeySigner::ed25519(
        auth_signer,
    ))];
    let error = authenticator
        .authenticate(&methods)
        .expect_err("rejecting verifier must not authenticate");
    assert!(matches!(error, AuthError::AuthenticationFailed));
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }

    let empty_config = ServerConfig::new(signer(207));
    let empty_policy = ServerAuthPolicy::new(1)?;
    let (mut empty_client, empty_driver) = connect_auth_pair(&empty_config, empty_policy)?;
    let mut empty_auth = ClientAuthenticator::new(&mut empty_client, "empty-user", 1)?;
    let empty_methods = [ClientAuthMethod::public_key(PublicKeySigner::ed25519(
        signer(208),
    ))];
    assert!(matches!(
        empty_auth.authenticate(&empty_methods),
        Err(AuthError::AuthenticationFailed)
    ));
    let empty_server = empty_driver
        .take_server()
        .ok_or("empty-policy server transport was lost")?;
    assert!(!empty_server.is_authenticated());
    if let Some(error) = empty_driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn changed_session_id_and_mutated_request_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let auth_signer = signer(209);
    let auth_blob = auth_signer.public_key_blob()?;
    let config = ServerConfig::new(signer(210));
    let policy = ServerAuthPolicy::new(4)?.with_authorized_key(&auth_blob)?;
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    request_service(&mut client)?;
    request_publickey_query(
        &mut client,
        auth::SSH_ED25519,
        auth_signer.public_key_blob()?.as_slice(),
    )?;

    let prefix = publickey_request(
        b"alice",
        auth::SSH_ED25519,
        true,
        auth_signer.public_key_blob()?.as_slice(),
    )?;
    let mut signed_bytes = Vec::new();
    let mut session_writer = Writer::new();
    session_writer.write_string(&[0x5a; 32])?;
    signed_bytes.extend_from_slice(session_writer.as_bytes());
    signed_bytes.extend_from_slice(&prefix);
    let signature = auth_signer.sign_exchange_hash(&signed_bytes)?;
    let mut wrong_session = prefix;
    let mut signature_writer = Writer::new();
    signature_writer.write_string(&signature)?;
    wrong_session.extend_from_slice(signature_writer.as_bytes());
    client.write_payload(&wrong_session)?;
    assert_eq!(
        client.read_payload()?.first(),
        Some(&auth::SSH_MSG_USERAUTH_FAILURE)
    );

    let valid_prefix = publickey_request(
        b"alice",
        auth::SSH_ED25519,
        true,
        auth_signer.public_key_blob()?.as_slice(),
    )?;
    let mut valid_signed_bytes = Writer::new();
    valid_signed_bytes.write_string(client.session_id())?;
    let mut valid_data = valid_signed_bytes.into_bytes();
    valid_data.extend_from_slice(&valid_prefix);
    let valid_signature = auth_signer.sign_exchange_hash(&valid_data)?;
    let mut mutated = valid_prefix;
    let mut valid_signature_writer = Writer::new();
    valid_signature_writer.write_string(&valid_signature)?;
    mutated.extend_from_slice(valid_signature_writer.as_bytes());
    mutated[5] = b'x';
    client.write_payload(&mutated)?;
    assert_eq!(
        client.read_payload()?.first(),
        Some(&auth::SSH_MSG_USERAUTH_FAILURE)
    );
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn truncated_and_malformed_auth_messages_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(211));
    let policy =
        ServerAuthPolicy::new(3)?.with_password_callback(|candidate| candidate == "accepted");
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    request_service(&mut client)?;
    client.write_payload(&[auth::SSH_MSG_USERAUTH_REQUEST])?;
    assert_eq!(
        client.read_payload()?.first(),
        Some(&auth::SSH_MSG_USERAUTH_FAILURE)
    );
    assert!(matches!(
        driver.take_error(),
        Some(AuthError::Wire(_) | AuthError::InvalidRequest)
    ));
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    Ok(())
}

#[test]
fn rsa_pss_and_sha1_signatures_are_rejected_for_sha256() -> Result<(), Box<dyn std::error::Error>> {
    for use_sha1 in [false, true] {
        let auth_signer = fixed_rsa_signer()?;
        let auth_blob = auth_signer.public_key_blob().to_vec();
        let config = ServerConfig::new(signer(212));
        let policy = ServerAuthPolicy::new(3)?.with_authorized_key(&auth_blob)?;
        let (mut client, driver) = connect_auth_pair(&config, policy)?;
        request_service(&mut client)?;
        request_publickey_query(&mut client, auth::SSH_RSA_SHA2_256, &auth_blob)?;
        let prefix = publickey_request(b"rsa-user", auth::SSH_RSA_SHA2_256, true, &auth_blob)?;
        let mut signed_writer = Writer::new();
        signed_writer.write_string(client.session_id())?;
        let mut signed_bytes = signed_writer.into_bytes();
        signed_bytes.extend_from_slice(&prefix);
        let signature = if use_sha1 {
            let private = fixed_rsa_private_key()?;
            let digest = sha1::Sha1::digest(&signed_bytes);
            let raw = private.sign(rsa::Pkcs1v15Sign::new_unprefixed(), digest.as_slice())?;
            let mut writer = Writer::new();
            writer.write_string(auth::SSH_RSA_SHA2_256)?;
            writer.write_string(&raw)?;
            writer.into_bytes()
        } else {
            let valid = auth_signer.sign(&signed_bytes)?;
            let mut reader = neotales_ssh::Reader::new(&valid);
            let _algorithm = reader.read_string()?;
            let raw = reader.read_string_bytes()?;
            let mut writer = Writer::new();
            writer.write_string("rsa-pss-sha2-256")?;
            writer.write_string(&raw)?;
            writer.into_bytes()
        };
        let mut request = prefix;
        let mut signature_writer = Writer::new();
        signature_writer.write_string(&signature)?;
        request.extend_from_slice(signature_writer.as_bytes());
        client.write_payload(&request)?;
        assert_eq!(
            client.read_payload()?.first(),
            Some(&auth::SSH_MSG_USERAUTH_FAILURE)
        );
        let server = driver.take_server().ok_or("server transport was lost")?;
        assert!(!server.is_authenticated());
        if let Some(error) = driver.take_error() {
            return Err(Box::new(error));
        }
    }
    Ok(())
}

#[test]
fn password_attempt_limit_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(213));
    let policy = ServerAuthPolicy::new(1)?.with_password_callback(|candidate| candidate == "right");
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "limited-user", 2)?;
    assert!(matches!(
        authenticator.authenticate(&[ClientAuthMethod::password("wrong")]),
        Err(AuthError::AuthenticationFailed)
    ));
    assert!(matches!(
        authenticator.authenticate(&[ClientAuthMethod::password("right")]),
        Err(AuthError::AuthenticationFailed)
    ));
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    assert!(matches!(
        driver.take_error(),
        Some(AuthError::AttemptsExhausted)
    ));
    Ok(())
}

#[test]
fn invalid_service_and_boolean_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(214));
    let policy = ServerAuthPolicy::new(2)?.with_password_callback(|_| true);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut wrong_service = Writer::new();
    wrong_service.write_byte(auth::SSH_MSG_SERVICE_REQUEST);
    wrong_service.write_string("ssh-not-userauth")?;
    client.write_payload(&wrong_service.into_bytes())?;
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    assert!(matches!(
        driver.take_error(),
        Some(AuthError::UnsupportedService)
    ));

    let config = ServerConfig::new(signer(215));
    let policy = ServerAuthPolicy::new(2)?.with_password_callback(|_| true);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    request_service(&mut client)?;
    let mut bad_password = Writer::new();
    bad_password.write_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    bad_password.write_string("alice")?;
    bad_password.write_string(auth::SSH_CONNECTION_SERVICE)?;
    bad_password.write_string(auth::SSH_PASSWORD_METHOD)?;
    bad_password.write_byte(2);
    bad_password.write_string("secret")?;
    client.write_payload(&bad_password.into_bytes())?;
    assert_eq!(
        client.read_payload()?.first(),
        Some(&auth::SSH_MSG_USERAUTH_FAILURE)
    );
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    assert!(matches!(driver.take_error(), Some(AuthError::Wire(_))));
    Ok(())
}

#[test]
fn client_does_not_treat_banner_or_partial_failure_as_success()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(216));
    let (mut client, driver) = connect_scripted_pair(&config)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "alice", 2)?;
    let error = authenticator
        .authenticate(&[ClientAuthMethod::password("password")])
        .expect_err("partial failure must not authenticate");
    assert!(matches!(error, AuthError::AuthenticationFailed));
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn banner_before_success_is_delivered_and_is_not_the_result()
-> Result<(), Box<dyn std::error::Error>> {
    const PASSWORD: &str = "banner-password";
    let banners = Rc::new(RefCell::new(Vec::new()));
    let banners_for_callback = Rc::clone(&banners);
    let config = ServerConfig::new(signer(217));
    let policy = ServerAuthPolicy::new(2)?
        .with_banner("server notice", "en")
        .with_password_callback(move |candidate| candidate == PASSWORD);
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "banner-user", 2)?
        .with_banner_callback(move |message, language| {
            banners_for_callback
                .borrow_mut()
                .push((message.to_owned(), language.to_owned()));
        });
    let result = authenticator.authenticate(&[ClientAuthMethod::password(PASSWORD)])?;
    assert_eq!(result.method(), AuthMethodKind::Password);
    assert_eq!(
        banners.borrow().as_slice(),
        [("server notice".to_owned(), "en".to_owned())]
    );
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn partial_success_false_stops_before_the_second_method() -> Result<(), Box<dyn std::error::Error>>
{
    let auth_signer = signer(218);
    let auth_blob = auth_signer.public_key_blob()?;
    let config = ServerConfig::new(signer(219));
    let policy = ServerAuthPolicy::new(4)?
        .with_password_callback(|_candidate| false)
        .with_authorized_key(&auth_blob)?;
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let before = client.outbound_sequence();
    let mut authenticator = ClientAuthenticator::new(&mut client, "partial-user", 4)?;
    let error = authenticator
        .authenticate(&[
            ClientAuthMethod::password("wrong"),
            ClientAuthMethod::public_key(PublicKeySigner::ed25519(auth_signer)),
        ])
        .expect_err("a hard failure must not fall through");
    assert!(matches!(error, AuthError::AuthenticationFailed));
    assert_eq!(authenticator.attempts(), 1);
    assert_eq!(client.outbound_sequence() - before, 2);
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn partial_success_true_allows_the_second_method_to_succeed()
-> Result<(), Box<dyn std::error::Error>> {
    let auth_signer = signer(220);
    let auth_blob = auth_signer.public_key_blob()?;
    let config = ServerConfig::new(signer(221));
    let policy = ServerAuthPolicy::new(4)?
        .with_password_decision_callback(|_password| PasswordDecision::PartialSuccess)
        .with_authorized_key(&auth_blob)?;
    let (mut client, driver) = connect_auth_pair(&config, policy)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "partial-user", 4)?;
    let result = authenticator.authenticate(&[
        ClientAuthMethod::password("first-factor"),
        ClientAuthMethod::public_key(PublicKeySigner::ed25519(auth_signer)),
    ])?;
    assert_eq!(result.method(), AuthMethodKind::PublicKey);
    assert_eq!(authenticator.attempts(), 3);
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn server_keyboard_callback_completes_one_matching_round() -> Result<(), Box<dyn std::error::Error>>
{
    let config = ServerConfig::new(signer(224));
    let (mut client, driver) = connect_paused_auth_pair(&config)?;
    let mut server = driver.take_server().ok_or("server transport was lost")?;
    let challenge = auth::KeyboardInteractiveChallenge::new(
        "login",
        "enter token",
        [KeyboardInteractivePrompt::new("token", false)],
    );
    let policy = ServerAuthPolicy::new(2)?.with_keyboard_interactive_callbacks(
        move |_username: &str| challenge.clone(),
        |_username: &str, responses: &[String]| responses == ["correct response".to_owned()],
    );
    let mut authenticator = auth::ServerAuthenticator::new(&mut server, &policy);

    let mut service = Writer::new();
    service.write_byte(auth::SSH_MSG_SERVICE_REQUEST);
    service.write_string(auth::SSH_USERAUTH_SERVICE)?;
    let service_payload = service.into_bytes();
    client.write_payload(&service_payload)?;
    assert_eq!(
        authenticator.handle_auth_packet(&service_payload)?,
        ServerAuthStep::ServiceAccepted
    );

    let mut request = Writer::new();
    request.write_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    request.write_string("keyboard-user")?;
    request.write_string(auth::SSH_CONNECTION_SERVICE)?;
    request.write_string(auth::SSH_KEYBOARD_INTERACTIVE_METHOD)?;
    request.write_string("")?;
    request.write_string("")?;
    client.write_payload(&request.clone().into_bytes())?;
    assert_eq!(
        authenticator.handle_auth_packet(&request.into_bytes())?,
        ServerAuthStep::PublicKeyQueryAccepted
    );

    let response = auth::encode_keyboard_interactive_response(&["correct response".to_owned()])?;
    assert_eq!(
        authenticator.handle_keyboard_interactive_response(&response)?,
        ServerAuthStep::Authenticated
    );
    assert!(server.is_authenticated());
    Ok(())
}

#[test]
fn server_keyboard_callback_supplies_prompts_and_checks_responses() {
    let challenge = auth::KeyboardInteractiveChallenge::new(
        "login",
        "enter token",
        [KeyboardInteractivePrompt::new("token", false)],
    );
    let callback = auth::KeyboardInteractiveCallbacks::new(
        move |_username: &str| challenge.clone(),
        |_username: &str, responses: &[String]| responses == ["correct response".to_owned()],
    );
    let first = auth::KeyboardInteractiveCallback::decide(&callback, "alice", &[]);
    assert!(matches!(
        first,
        auth::KeyboardInteractiveServerDecision::Challenge(_)
    ));
    let accepted = auth::KeyboardInteractiveCallback::verify(
        &callback,
        "alice",
        &["correct response".to_owned()],
    );
    assert_eq!(accepted, auth::KeyboardInteractiveServerDecision::Accept);
    let rejected = auth::KeyboardInteractiveCallback::verify(
        &callback,
        "alice",
        &["wrong response".to_owned()],
    );
    assert_eq!(rejected, auth::KeyboardInteractiveServerDecision::Reject);
    let policy = ServerAuthPolicy::new(1)
        .expect("one attempt is valid")
        .with_keyboard_interactive_policy(callback);
    assert!(policy.keyboard_interactive_enabled());
}

#[test]
fn keyboard_interactive_sends_one_matching_response() -> Result<(), Box<dyn std::error::Error>> {
    let seen_prompt = Rc::new(Cell::new(false));
    let seen_prompt_for_callback = Rc::clone(&seen_prompt);
    let config = ServerConfig::new(signer(222));
    let (mut client, driver) = connect_keyboard_success_pair(&config)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "keyboard-user", 2)?;
    let result = authenticator.authenticate(&[ClientAuthMethod::keyboard_interactive(
        move |prompts: &[KeyboardInteractivePrompt]| {
            if prompts.len() == 1 && prompts[0].text() == "token" {
                seen_prompt_for_callback.set(true);
            }
            vec!["correct response".to_owned()]
        },
    )])?;
    assert_eq!(result.method(), AuthMethodKind::KeyboardInteractive);
    assert!(seen_prompt.get());
    assert_eq!(authenticator.attempts(), 2);
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

#[test]
fn keyboard_interactive_rejects_an_info_request_with_33_prompts()
-> Result<(), Box<dyn std::error::Error>> {
    let responder_called = Rc::new(Cell::new(false));
    let responder_called_for_callback = Rc::clone(&responder_called);
    let config = ServerConfig::new(signer(223));
    let (mut client, driver) = connect_keyboard_prompt_count_pair(&config, 33)?;
    let mut authenticator = ClientAuthenticator::new(&mut client, "keyboard-user", 2)?;
    let error = authenticator
        .authenticate(&[ClientAuthMethod::keyboard_interactive(
            move |_prompts: &[KeyboardInteractivePrompt]| {
                responder_called_for_callback.set(true);
                vec!["unused".to_owned()]
            },
        )])
        .expect_err("an oversized prompt count must fail");
    assert!(matches!(error, AuthError::InvalidRequest));
    assert!(!responder_called.get());
    let server = driver.take_server().ok_or("server transport was lost")?;
    assert!(!server.is_authenticated());
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok(())
}

fn request_service<S>(client: &mut ClientTransport<S>) -> Result<(), Box<dyn std::error::Error>>
where
    S: Read + Write,
{
    let mut request = Writer::new();
    request.write_byte(auth::SSH_MSG_SERVICE_REQUEST);
    request.write_string(auth::SSH_USERAUTH_SERVICE)?;
    client.write_payload(&request.into_bytes())?;
    let response = client.read_payload()?;
    assert_eq!(response.first(), Some(&auth::SSH_MSG_SERVICE_ACCEPT));
    Ok(())
}

fn request_publickey_query<S>(
    client: &mut ClientTransport<S>,
    algorithm: &str,
    key_blob: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: Read + Write,
{
    let request = publickey_request(b"alice", algorithm, false, key_blob)?;
    client.write_payload(&request)?;
    let response = client.read_payload()?;
    assert_eq!(response.first(), Some(&auth::SSH_MSG_USERAUTH_PK_OK));
    Ok(response)
}

fn publickey_request(
    username: &[u8],
    algorithm: &str,
    signed: bool,
    key_blob: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut writer = Writer::new();
    writer.write_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    writer.write_string(username)?;
    writer.write_string(auth::SSH_CONNECTION_SERVICE)?;
    writer.write_string(auth::SSH_PUBLICKEY_METHOD)?;
    writer.write_boolean(signed);
    writer.write_string(algorithm)?;
    writer.write_string(key_blob)?;
    Ok(writer.into_bytes())
}

fn fixed_rsa_signer() -> Result<RsaAuthSigner, Box<dyn std::error::Error>> {
    Ok(RsaAuthSigner::from_private_key(fixed_rsa_private_key()?)?)
}

fn fixed_rsa_private_key() -> Result<rsa::RsaPrivateKey, Box<dyn std::error::Error>> {
    let p = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf07",
    )?);
    let q = rsa::BigUint::from_bytes_be(&hex_bytes(
        "00ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be5536f71",
    )?);
    Ok(rsa::RsaPrivateKey::from_p_q(
        p,
        q,
        rsa::BigUint::from(65537_u32),
    )?)
}

fn hex_bytes(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("fixed hex has odd length".into());
    }
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
