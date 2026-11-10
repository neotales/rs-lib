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

// `ChannelConnection`'s channel-level API is public and reachable from the
// crate root, but this harness compiles `channel.rs` as a private module copy, so
// `unreachable_pub` fires on every public item in it. That is an artefact of the
// harness, not a finding about the API, and the lint is silenced for the module
// rather than by hiding anything that is genuinely public.
#[allow(dead_code, unused_imports, unreachable_pub)]
#[path = "../src/channel.rs"]
mod channel;

#[allow(dead_code, unused_imports)]
#[path = "../src/session.rs"]
mod session;

#[allow(dead_code, unused_imports)]
#[path = "../src/direct_tcpip.rs"]
mod direct_tcpip;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use crate::channel::{
    ChannelError, ChannelEvent, INITIAL_CHANNEL_WINDOW, MAX_CHANNEL_PACKET_SIZE,
    SSH_MSG_CHANNEL_DATA, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, WindowError,
};
use crate::client::{ClientConfig, ClientTransport};
use auth::{
    AuthError, AuthMethodKind, ClientAuthMethod, ClientAuthenticator, PublicKeySigner,
    RsaAuthSigner, ServerAuthPolicy, ServerAuthState, ServerAuthStep,
};
use direct_tcpip::{
    ClientDirectTcpip, DIRECT_TCPIP_CHANNEL_TYPE, DirectTcpipError, DirectTcpipEvent,
    DirectTcpipTuple, MAX_DIRECT_TCPIP_HOST_LENGTH, ServerDirectTcpip,
};
use hostkey::{Ed25519PublicKey, Ed25519Signer};
use kex::{Curve25519, KeyExchange};
use msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256,
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH, HMAC_SHA2_256, HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512,
    HMAC_SHA2_512_ETM_OPENSSH, HOST_KEY_SSH_ED25519, KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_STRICT_C_V00_OPENSSH, KexInit,
};
use neotales_ssh::{Writer, build_packet_default};
use server::{
    HandshakeError, IdentificationError, ServerConfig, ServerHandshake, ServerTransport,
    ServerTransportError, TransportError,
};
use session::{
    ClientSessions, OwnedSessionRequest, PtyRequest, ServerSessions, SessionDecision, SessionError,
    SessionEvent, SessionRequest,
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
                        .map_err(AuthError::from)
                }
                Some(auth::SSH_MSG_USERAUTH_REQUEST) => {
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
    });
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'a> = Rc::new(RefCell::new(move || callback_driver.drive()));
    client_stream.set_driver(callback);
    let client = ClientConfig::new().connect(client_stream, |_key| Ok::<(), Infallible>(()))?;
    Ok((client, driver))
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

fn authenticated_pair(
    config: &ServerConfig,
    _seed: u8,
) -> Result<(ClientTransport<Stream<'_>>, ServerTransport<Stream<'_>>), Box<dyn std::error::Error>>
{
    let auth_policy = ServerAuthPolicy::new(1)?.with_password_callback(|_password| true);
    let (mut client, driver) = connect_auth_pair(config, auth_policy)?;
    let methods = [ClientAuthMethod::password("integration-test")];
    auth::authenticate_client(&mut client, "session-user", &methods, 1)?;
    let server = driver
        .take_server()
        .ok_or("authenticated server was lost")?;
    if let Some(error) = driver.take_error() {
        return Err(Box::new(error));
    }
    Ok((client, server))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SeenRequest {
    Exec(Vec<u8>),
    Shell,
}

#[allow(clippy::too_many_lines)]
#[test]
fn exec_uses_exact_command_bytes_and_delivers_status_eof_close_in_order()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(21));
    let (client, server) = authenticated_pair(&config, 22)?;
    let seen = Rc::new(RefCell::new(Vec::new()));
    let seen_by_policy = Rc::clone(&seen);
    let mut client = ClientSessions::new(client);
    let mut server = ServerSessions::with_policy(server, move |request| {
        let observed = match request {
            SessionRequest::Exec { command } => SeenRequest::Exec(command.to_vec()),
            SessionRequest::Shell => SeenRequest::Shell,
        };
        seen_by_policy.borrow_mut().push(observed);
        SessionDecision::accept(23)
    });

    let client_session = client.open_session()?;
    let SessionEvent::Opened {
        session: server_session,
    } = server.dispatch_one()?
    else {
        return Err("server did not confirm session".into());
    };
    assert_eq!(server_session, client_session);
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));

    let command = b"opaque\0command | not/a/real/shell".as_slice();
    client.request_exec(client_session, command, true)?;
    let SessionEvent::Request {
        session,
        request: OwnedSessionRequest::Exec(received),
        want_reply: true,
        accepted: true,
        exit_status: Some(23),
    } = server.dispatch_one()?
    else {
        return Err("server did not evaluate exec".into());
    };
    assert_eq!(session, server_session);
    assert_eq!(received, command);
    assert_eq!(
        seen.borrow().as_slice(),
        &[SeenRequest::Exec(command.to_vec())]
    );
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::RequestSucceeded { .. }
    ));

    client.send_data(client_session, b"stdin bytes")?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::Data { data, .. } if data == b"stdin bytes"
    ));
    server.send_data(server_session, b"stdout bytes")?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Data { data, .. } if data == b"stdout bytes"
    ));

    assert_eq!(server.send_exit_status(server_session)?, 23);
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::ExitStatus { status: 23, .. }
    ));
    server.send_eof(server_session)?;
    assert!(matches!(client.dispatch_one()?, SessionEvent::Eof { .. }));
    client.send_eof(client_session)?;
    assert!(matches!(server.dispatch_one()?, SessionEvent::Eof { .. }));
    server.send_close(server_session)?;
    assert!(matches!(client.dispatch_one()?, SessionEvent::Close { .. }));
    client.send_close(client_session)?;
    assert!(matches!(server.dispatch_one()?, SessionEvent::Close { .. }));
    Ok(())
}

#[test]
fn shell_accepts_pty_without_interpreting_modes_or_fabricating_a_command()
-> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../src/session.rs");
    assert!(!source.contains("std::process"));
    assert!(!source.contains("Command::new"));
    assert!(!source.contains("/bin/sh -c"));
    assert!(!source.contains("cmd.exe /c"));

    let config = ServerConfig::new(signer(23));
    let (client, server) = authenticated_pair(&config, 24)?;
    let seen = Rc::new(RefCell::new(Vec::new()));
    let seen_by_policy = Rc::clone(&seen);
    let mut client = ClientSessions::new(client);
    let mut server = ServerSessions::with_policy(server, move |request| {
        seen_by_policy.borrow_mut().push(match request {
            SessionRequest::Exec { command } => SeenRequest::Exec(command.to_vec()),
            SessionRequest::Shell => SeenRequest::Shell,
        });
        SessionDecision::accept(0)
    });
    let session = client.open_session()?;
    let SessionEvent::Opened { .. } = server.dispatch_one()? else {
        return Err("server did not confirm shell session".into());
    };
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));

    let modes = b"\x80\x00opaque-modes";
    let pty = PtyRequest::new(b"xterm-256color", 132, 43, 1_320, 860, modes);
    client.request_pty(session, &pty, true)?;
    let SessionEvent::PtyRequested {
        request: received,
        want_reply: true,
        ..
    } = server.dispatch_one()?
    else {
        return Err("server did not parse PTY request".into());
    };
    assert_eq!(received, pty);
    assert_eq!(received.modes(), modes);
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::RequestSucceeded { .. }
    ));

    client.request_shell(session, true)?;
    let SessionEvent::Request {
        request: OwnedSessionRequest::Shell,
        accepted: true,
        exit_status: Some(0),
        ..
    } = server.dispatch_one()?
    else {
        return Err("server did not evaluate shell request".into());
    };
    assert_eq!(seen.borrow().as_slice(), &[SeenRequest::Shell]);
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::RequestSucceeded { .. }
    ));
    server.send_data(session, b"shell output")?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Data { data, .. } if data == b"shell output"
    ));
    Ok(())
}

#[test]
fn pty_modes_are_bounded_and_truncated_pty_fields_never_reach_the_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(33));
    let (client, server) = authenticated_pair(&config, 34)?;
    let callback_calls = Rc::new(Cell::new(0_usize));
    let calls_by_policy = Rc::clone(&callback_calls);
    let mut client = ClientSessions::new(client);
    let mut server = ServerSessions::with_policy(server, move |_request| {
        calls_by_policy.set(calls_by_policy.get() + 1);
        SessionDecision::accept(0)
    });

    let oversized = client.open_session()?;
    let SessionEvent::Opened { .. } = server.dispatch_one()? else {
        return Err("server did not confirm PTY test session".into());
    };
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    let mut request = Writer::new();
    request.write_byte(channel::SSH_MSG_CHANNEL_REQUEST);
    request.write_uint32(oversized);
    request.write_string(session::SESSION_REQUEST_PTY)?;
    request.write_boolean(true);
    request.write_string("xterm")?;
    request.write_uint32(80);
    request.write_uint32(24);
    request.write_uint32(0);
    request.write_uint32(0);
    request.write_string(&vec![b'x'; MAX_CHANNEL_PACKET_SIZE as usize + 1])?;
    client
        .connection_mut()
        .transport_mut()
        .write_payload(&request.into_bytes())?;
    let oversized_result = server.dispatch_one();
    assert!(
        matches!(
            oversized_result,
            Err(SessionError::Channel(ChannelError::PacketTooLarge { .. }))
        ),
        "{oversized_result:?}"
    );

    let truncated = client.open_session()?;
    let SessionEvent::Opened { .. } = server.dispatch_one()? else {
        return Err("server did not confirm truncated PTY session".into());
    };
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    let mut request = Writer::new();
    request.write_byte(channel::SSH_MSG_CHANNEL_REQUEST);
    request.write_uint32(truncated);
    request.write_string(session::SESSION_REQUEST_PTY)?;
    request.write_boolean(false);
    request.write_string("xterm")?;
    client
        .connection_mut()
        .transport_mut()
        .write_payload(&request.into_bytes())?;
    assert!(matches!(
        server.dispatch_one(),
        Err(SessionError::InvalidRequest)
    ));
    assert_eq!(callback_calls.get(), 0);
    Ok(())
}

#[test]
fn server_session_open_is_default_deny_without_an_explicit_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(25));
    let (client, server) = authenticated_pair(&config, 26)?;
    let mut client = ClientSessions::new(client);
    let mut server = ServerSessions::new(server);
    let session = client.open_session()?;
    let SessionEvent::OpenRejected {
        session: None,
        reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
        ref description,
        ..
    } = server.dispatch_one()?
    else {
        return Err("default server accepted a session".into());
    };
    assert_eq!(description, b"session denied by policy");
    let SessionEvent::OpenRejected {
        session: Some(rejected),
        reason,
        ..
    } = client.dispatch_one()?
    else {
        return Err("client did not receive open failure".into());
    };
    assert_eq!(rejected, session);
    assert_eq!(reason, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
    Ok(())
}

#[test]
fn one_dispatcher_routes_interleaved_channels_to_the_exact_recipient()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(27));
    let (client, server) = authenticated_pair(&config, 28)?;
    let mut client = ClientSessions::new(client);
    let mut server = ServerSessions::with_policy(server, |_request| SessionDecision::accept(0));
    let first = client.open_session()?;
    let second = client.open_session()?;
    let first_server = opened_session(&mut server)?;
    let second_server = opened_session(&mut server)?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));

    client.request_exec(second, b"two", false)?;
    client.request_exec(first, b"one", false)?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::Request { .. }
    ));
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::Request { .. }
    ));

    client.send_data(second, b"channel-two")?;
    client.send_data(first, b"channel-one")?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::Data { session, data }
            if session == second_server && data == b"channel-two"
    ));
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::Data { session, data }
            if session == first_server && data == b"channel-one"
    ));
    server.send_data(first_server, b"reply-one")?;
    server.send_data(second_server, b"reply-two")?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Data { session, data }
            if session == first && data == b"reply-one"
    ));
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Data { session, data }
            if session == second && data == b"reply-two"
    ));
    Ok(())
}

fn opened_session<T>(server: &mut ServerSessions<T>) -> Result<u32, Box<dyn std::error::Error>>
where
    T: channel::ChannelTransport,
{
    let SessionEvent::Opened { session } = server.dispatch_one()? else {
        return Err("expected channel confirmation".into());
    };
    Ok(session)
}

#[allow(clippy::too_many_lines)]
#[test]
fn window_limits_are_exact_typed_and_never_buffer_uncredited_data()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(29));
    let (client, server) = authenticated_pair(&config, 30)?;
    let mut client = ClientSessions::new(client);
    let mut server = channel::ChannelConnection::new(server);

    client.open_session_with_id(7)?;
    let request = open_request(&mut server)?;
    server.confirm_open_with_limits(request.sender_channel(), 11, 4, 4)?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    assert_eq!(client.connection().channel(7).unwrap().remote_window(), 4);
    assert_eq!(client.connection_mut().write_data(7, b"abcd")?, 4);
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 11, data } if data == b"abcd"
    ));
    assert_eq!(client.connection().channel(7).unwrap().remote_window(), 0);
    assert_eq!(
        client.connection_mut().write_data(7, b"x"),
        Err(ChannelError::Window(WindowError::Insufficient {
            available: 0,
            requested: 1
        }))
    );
    assert_eq!(client.connection().buffered_data_bytes(), 0);

    assert_eq!(server.increase_local_window(11, 2)?, 2);
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::WindowAdjusted {
            session: 7,
            available: 2
        }
    ));
    assert_eq!(client.connection_mut().write_data(7, b"xy")?, 2);
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 11, data } if data == b"xy"
    ));
    assert_eq!(client.connection().channel(7).unwrap().remote_window(), 0);

    client.open_session_with_id(8)?;
    let request = open_request(&mut server)?;
    server.confirm_open_with_limits(request.sender_channel(), 12, 3, 3)?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    assert_eq!(
        client.connection_mut().write_data(8, b"four"),
        Err(ChannelError::PacketTooLarge {
            maximum: 3,
            requested: 4
        })
    );

    client
        .connection_mut()
        .open_channel_with_limits(9, b"session", &[], 2, 8)?;
    let request = open_request(&mut server)?;
    server.confirm_open_with_limits(request.sender_channel(), 13, 8, 8)?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    server
        .transport_mut()
        .write_payload(&data_payload(9, b"abc"))?;
    let receive_result = client.connection_mut().dispatch_one();
    assert!(
        matches!(
            receive_result,
            Err(ChannelError::WindowExceeded {
                available: 2,
                received: 3
            })
        ),
        "{receive_result:?}"
    );

    client.open_session_with_id(10)?;
    let request = open_request(&mut server)?;
    server.confirm_open_with_limits(
        request.sender_channel(),
        14,
        u32::MAX - 1,
        MAX_CHANNEL_PACKET_SIZE,
    )?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::Opened { .. }
    ));
    assert_eq!(server.increase_local_window(14, 1)?, u32::MAX);
    assert!(matches!(
        client.connection_mut().dispatch_one()?,
        ChannelEvent::WindowAdjusted {
            channel: 10,
            available: u32::MAX
        }
    ));
    let mut adjustment = Writer::new();
    adjustment.write_byte(channel::SSH_MSG_CHANNEL_WINDOW_ADJUST);
    adjustment.write_uint32(10);
    adjustment.write_uint32(1);
    server
        .transport_mut()
        .write_payload(&adjustment.into_bytes())?;
    assert!(matches!(
        client.connection_mut().dispatch_one(),
        Err(ChannelError::Window(WindowError::AdjustmentOverflow {
            current: u32::MAX,
            increment: 1
        }))
    ));
    assert_eq!(INITIAL_CHANNEL_WINDOW, 65_536);
    assert_eq!(MAX_CHANNEL_PACKET_SIZE, 32_768);
    Ok(())
}

fn open_request<T>(
    server: &mut channel::ChannelConnection<T>,
) -> Result<channel::ChannelOpenRequest, Box<dyn std::error::Error>>
where
    T: channel::ChannelTransport,
{
    let ChannelEvent::OpenRequest(request) = server.dispatch_one()? else {
        return Err("expected channel open request".into());
    };
    Ok(request)
}

#[test]
fn unknown_ids_truncation_unexpected_types_and_data_after_eof_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(31));
    let (client, server) = authenticated_pair(&config, 32)?;
    let mut client = channel::ChannelConnection::new(client);
    let mut server = channel::ChannelConnection::new(server);
    client.open_channel(0, b"session", &[])?;
    let request = open_request(&mut server)?;
    server.confirm_open(request.sender_channel(), 0)?;
    assert!(matches!(
        client.dispatch_one()?,
        ChannelEvent::Opened { .. }
    ));

    client
        .transport_mut()
        .write_payload(&data_payload(999, b"wrong-channel"))?;
    assert!(matches!(
        server.dispatch_one(),
        Err(ChannelError::UnknownChannel)
    ));
    client.write_data(0, b"right-channel")?;
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 0, data } if data == b"right-channel"
    ));

    client.send_eof(0)?;
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Eof { channel: 0 }
    ));
    client
        .transport_mut()
        .write_payload(&data_payload(0, b"after-eof"))?;
    assert!(matches!(
        server.dispatch_one(),
        Err(ChannelError::DataAfterEof)
    ));

    client.open_channel(1, b"session", &[])?;
    let request = open_request(&mut server)?;
    server.confirm_open(request.sender_channel(), 1)?;
    assert!(matches!(
        client.dispatch_one()?,
        ChannelEvent::Opened { .. }
    ));
    client
        .transport_mut()
        .write_payload(&[SSH_MSG_CHANNEL_DATA, 0, 0])?;
    assert!(matches!(
        server.dispatch_one(),
        Err(ChannelError::Wire(neotales_ssh::Error::Truncated))
    ));
    // 50 is SSH_MSG_USERAUTH_REQUEST. It is not a channel message and not a
    // connection-level one, so the multiplexer must still refuse it: the
    // tolerated set is the six numbers RFC 4253 §11 and RFC 4254 §4 name, not
    // "anything that is not a channel message".
    client
        .transport_mut()
        .write_payload(&[auth::SSH_MSG_USERAUTH_REQUEST, 0, 0, 0, 0])?;
    assert!(matches!(
        server.dispatch_one(),
        Err(ChannelError::UnexpectedMessage(
            auth::SSH_MSG_USERAUTH_REQUEST
        ))
    ));
    // 80 is SSH_MSG_GLOBAL_REQUEST, which RFC 4254 §4 allows at any time. It is
    // surfaced rather than fatal, and it is the exact name a current OpenSSH
    // server sends as the first payload after SSH_MSG_USERAUTH_SUCCESS.
    let mut request = Writer::new();
    request.write_byte(channel::SSH_MSG_GLOBAL_REQUEST);
    let _ = request.write_string(b"hostkeys-00@openssh.com");
    request.write_boolean(false);
    client.transport_mut().write_payload(request.as_bytes())?;
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::GlobalRequest {
            request_name,
            want_reply: false,
            ..
        } if request_name == b"hostkeys-00@openssh.com"
    ));
    // The connection is still routed: the next payload is ordinary data.
    client.write_data(1, b"still-routed")?;
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 1, data } if data == b"still-routed"
    ));
    client
        .transport_mut()
        .write_payload(&[channel::SSH_MSG_CHANNEL_EOF, 0, 0, 0, 1, 0])?;
    assert!(matches!(
        server.dispatch_one(),
        Err(ChannelError::InvalidMessage)
    ));
    Ok(())
}

fn data_payload(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_DATA);
    writer.write_uint32(recipient);
    writer.write_string(data).unwrap_or_default();
    writer.into_bytes()
}

#[test]
fn direct_tcpip_tuple_round_trips_ipv4_ipv6_and_boundary_ports()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("127.0.0.1", 1_u32, "127.0.0.1", 0_u32),
        ("2001:db8::1", 80, "2001:db8::2", 65_535),
        ("example.invalid", 65_535, "::ffff:127.0.0.1", 1),
    ];
    for (host, destination_port, originator, originator_port) in cases {
        let tuple = DirectTcpipTuple::new(host, destination_port, originator, originator_port)?;
        let encoded = tuple.encode()?;
        let mut expected = Writer::new();
        expected.write_string(&host)?;
        expected.write_uint32(destination_port);
        expected.write_string(&originator)?;
        expected.write_uint32(originator_port);
        assert_eq!(encoded, expected.into_bytes());
        assert_eq!(DirectTcpipTuple::decode(&encoded)?, tuple);
    }
    let boundary_host = vec![b'b'; MAX_DIRECT_TCPIP_HOST_LENGTH];
    let boundary = DirectTcpipTuple::new(&boundary_host, 1, &boundary_host, 0)?;
    assert_eq!(DirectTcpipTuple::decode(&boundary.encode()?)?, boundary);
    Ok(())
}

#[test]
fn direct_tcpip_validation_rejects_invalid_fields_and_trailing_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(DirectTcpipTuple::new("", 80, "127.0.0.1", 0).is_err());
    assert!(DirectTcpipTuple::new("127.0.0.1", 80, "", 0).is_err());
    assert!(DirectTcpipTuple::new("127.0.0.1", 0, "127.0.0.1", 0).is_err());
    assert!(DirectTcpipTuple::new("127.0.0.1", 65_536, "127.0.0.1", 0).is_err());
    assert!(DirectTcpipTuple::new("127.0.0.1", 80, "127.0.0.1", 65_536).is_err());

    let overlong = vec![b'x'; MAX_DIRECT_TCPIP_HOST_LENGTH + 1];
    assert!(DirectTcpipTuple::new(&overlong, 80, "127.0.0.1", 0).is_err());
    assert!(DirectTcpipTuple::new("127.0.0.1", 80, &overlong, 0).is_err());
    let mut overlong_wire = Writer::new();
    overlong_wire.write_string(&overlong)?;
    overlong_wire.write_uint32(80);
    overlong_wire.write_string("127.0.0.1")?;
    overlong_wire.write_uint32(0);
    assert!(matches!(
        DirectTcpipTuple::decode(&overlong_wire.into_bytes()),
        Err(DirectTcpipError::DestinationHostTooLong)
    ));

    let mut invalid_destination_port = Writer::new();
    invalid_destination_port.write_string("127.0.0.1")?;
    invalid_destination_port.write_uint32(65_536);
    invalid_destination_port.write_string("127.0.0.1")?;
    invalid_destination_port.write_uint32(0);
    assert!(matches!(
        DirectTcpipTuple::decode(&invalid_destination_port.into_bytes()),
        Err(DirectTcpipError::InvalidDestinationPort)
    ));
    let mut invalid_originator_port = Writer::new();
    invalid_originator_port.write_string("127.0.0.1")?;
    invalid_originator_port.write_uint32(80);
    invalid_originator_port.write_string("127.0.0.1")?;
    invalid_originator_port.write_uint32(65_536);
    assert!(matches!(
        DirectTcpipTuple::decode(&invalid_originator_port.into_bytes()),
        Err(DirectTcpipError::InvalidOriginatorPort)
    ));

    let valid = DirectTcpipTuple::new("127.0.0.1", 80, "127.0.0.1", 0)?.encode()?;
    assert!(DirectTcpipTuple::decode(&valid[..valid.len() - 1]).is_err());
    let mut trailing = valid;
    trailing.push(0);
    assert!(matches!(
        DirectTcpipTuple::decode(&trailing),
        Err(DirectTcpipError::TrailingBytes)
    ));
    let mut missing = Writer::new();
    missing.write_string("127.0.0.1")?;
    missing.write_uint32(80);
    assert!(DirectTcpipTuple::decode(&missing.into_bytes()).is_err());
    Ok(())
}

#[test]
fn direct_tcpip_invalid_open_is_rejected_without_confirming_a_data_path()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(41));
    let (client, server) = authenticated_pair(&config, 42)?;
    let mut client = channel::ChannelConnection::new(client);
    let mut server = ServerDirectTcpip::new(server);
    let mut open = Writer::new();
    open.write_byte(channel::SSH_MSG_CHANNEL_OPEN);
    open.write_string(DIRECT_TCPIP_CHANNEL_TYPE)?;
    open.write_uint32(0);
    open.write_uint32(INITIAL_CHANNEL_WINDOW);
    open.write_uint32(MAX_CHANNEL_PACKET_SIZE);
    open.write_string("127.0.0.1")?;
    open.write_uint32(0);
    open.write_string("127.0.0.1")?;
    open.write_uint32(0);
    client.transport_mut().write_payload(&open.into_bytes())?;
    let DirectTcpipEvent::OpenRejected {
        channel: None,
        reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
        ..
    } = server.dispatch_one()?
    else {
        return Err("invalid direct-tcpip open was not rejected".into());
    };
    assert_eq!(server.connection().channel_count(), 0);
    assert_eq!(server.connection().pending_open_count(), 0);
    assert_eq!(server.connection().buffered_data_bytes(), 0);
    Ok(())
}

#[test]
fn direct_tcpip_default_deny_and_explicit_allow_receive_exact_tuple()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(43));
    let (client, server) = authenticated_pair(&config, 44)?;
    let tuple = DirectTcpipTuple::new("2001:db8::1", 443, "127.0.0.1", 0)?;
    let seen = Rc::new(RefCell::new(Vec::new()));
    let seen_by_policy = Rc::clone(&seen);
    let mut client = ClientDirectTcpip::new(client);
    let mut server = ServerDirectTcpip::new(server);

    let denied = client.open(&tuple)?;
    assert!(matches!(
        server.dispatch_one()?,
        DirectTcpipEvent::OpenRejected {
            channel: None,
            reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
            ..
        }
    ));
    assert_eq!(server.connection().channel_count(), 0);
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::OpenRejected {
            channel: Some(channel),
            reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
            ..
        } if channel == denied
    ));

    server.set_allow_callback(move |host, destination_port, originator, originator_port| {
        seen_by_policy.borrow_mut().push((
            host.to_vec(),
            destination_port,
            originator.to_vec(),
            originator_port,
        ));
        true
    });
    let opened = client.open(&tuple)?;
    let DirectTcpipEvent::Opened { channel } = server.dispatch_one()? else {
        return Err("allow callback did not confirm direct-tcpip".into());
    };
    assert_eq!(channel, opened);
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Opened { channel } if channel == opened
    ));
    assert_eq!(
        seen.borrow().as_slice(),
        &[(b"2001:db8::1".to_vec(), 443, b"127.0.0.1".to_vec(), 0,)]
    );
    Ok(())
}

#[test]
fn direct_tcpip_uses_shared_data_window_eof_and_close_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(45));
    let (client, server) = authenticated_pair(&config, 46)?;
    let tuple = DirectTcpipTuple::new("127.0.0.1", 8080, "127.0.0.1", 12345)?;
    let mut client = ClientDirectTcpip::new(client);
    let mut server =
        ServerDirectTcpip::with_allow_callback(server, |_host, _port, _origin, _origin_port| true);
    let client_channel = client.open(&tuple)?;
    let DirectTcpipEvent::Opened {
        channel: server_channel,
    } = server.dispatch_one()?
    else {
        return Err("server did not confirm direct-tcpip".into());
    };
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Opened { channel } if channel == client_channel
    ));
    assert_eq!(
        client
            .connection()
            .channel(client_channel)
            .unwrap()
            .remote_window(),
        INITIAL_CHANNEL_WINDOW
    );
    assert_eq!(
        server
            .connection()
            .channel(server_channel)
            .unwrap()
            .remote_window(),
        INITIAL_CHANNEL_WINDOW
    );
    assert_eq!(client.send_data(client_channel, b"client-to-server")?, 16);
    assert!(matches!(
        server.dispatch_one()?,
        DirectTcpipEvent::Data { channel, data }
            if channel == server_channel && data == b"client-to-server"
    ));
    assert_eq!(
        server
            .connection_mut()
            .write_data(server_channel, b"server-to-client")?,
        16
    );
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Data { channel, data }
            if channel == client_channel && data == b"server-to-client"
    ));
    assert_eq!(
        server
            .connection_mut()
            .write_extended_data(server_channel, 0xfeed, b"not-stream-data")?,
        15
    );
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::ExtendedData {
            channel,
            data_type_code: 0xfeed,
            data
        } if channel == client_channel && data == b"not-stream-data"
    ));
    assert!(matches!(
        client.send_data(
            client_channel,
            &vec![0; MAX_CHANNEL_PACKET_SIZE as usize + 1]
        ),
        Err(DirectTcpipError::Channel(
            ChannelError::PacketTooLarge { .. }
        ))
    ));
    client.send_eof(client_channel)?;
    assert!(matches!(
        server.dispatch_one()?,
        DirectTcpipEvent::Eof { channel } if channel == server_channel
    ));
    server.send_eof(server_channel)?;
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Eof { channel } if channel == client_channel
    ));
    client.send_close(client_channel)?;
    assert!(matches!(
        server.dispatch_one()?,
        DirectTcpipEvent::Close { channel } if channel == server_channel
    ));
    server.send_close(server_channel)?;
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Close { channel } if channel == client_channel
    ));
    Ok(())
}

#[test]
fn direct_tcpip_window_credit_and_channel_type_use_the_shared_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(47));
    let (client, server) = authenticated_pair(&config, 48)?;
    let tuple = DirectTcpipTuple::new("127.0.0.1", 22, "127.0.0.1", 0)?;
    let mut client = channel::ChannelConnection::new(client);
    let mut server = channel::ChannelConnection::new(server);
    assert_eq!(DIRECT_TCPIP_CHANNEL_TYPE, "direct-tcpip");
    assert_ne!(DIRECT_TCPIP_CHANNEL_TYPE, "direct-tcpip@openssh.com");
    client.open_channel_with_limits(
        7,
        DIRECT_TCPIP_CHANNEL_TYPE.as_bytes(),
        &tuple.encode()?,
        4,
        64,
    )?;
    let request = open_request(&mut server)?;
    assert_eq!(request.channel_type(), DIRECT_TCPIP_CHANNEL_TYPE.as_bytes());
    assert_eq!(
        DirectTcpipTuple::decode(request.type_specific_data())?,
        tuple
    );
    server.confirm_open_with_limits(request.sender_channel(), 11, 4, 64)?;
    assert!(matches!(
        client.dispatch_one()?,
        ChannelEvent::Opened { .. }
    ));
    assert_eq!(client.channel(7).unwrap().remote_window(), 4);
    assert_eq!(client.write_data(7, b"abcd")?, 4);
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 11, data } if data == b"abcd"
    ));
    assert!(matches!(
        client.write_data(7, b"x"),
        Err(ChannelError::Window(WindowError::Insufficient {
            available: 0,
            requested: 1
        }))
    ));
    assert_eq!(server.increase_local_window(11, 2)?, 2);
    assert!(matches!(
        client.dispatch_one()?,
        ChannelEvent::WindowAdjusted {
            channel: 7,
            available: 2
        }
    ));
    assert_eq!(client.write_data(7, b"xy")?, 2);
    assert!(matches!(
        server.dispatch_one()?,
        ChannelEvent::Data { channel: 11, data } if data == b"xy"
    ));
    assert_eq!(client.buffered_data_bytes(), 0);
    Ok(())
}

#[test]
fn direct_tcpip_peer_close_is_a_bounded_transport_error() -> Result<(), Box<dyn std::error::Error>>
{
    let config = ServerConfig::new(signer(49));
    let (client, server) = authenticated_pair(&config, 50)?;
    let tuple = DirectTcpipTuple::new("127.0.0.1", 443, "127.0.0.1", 0)?;
    let mut client = ClientDirectTcpip::new(client);
    let mut server =
        ServerDirectTcpip::with_allow_callback(server, |_host, _port, _origin, _origin_port| true);
    let channel = client.open(&tuple)?;
    let DirectTcpipEvent::Opened { .. } = server.dispatch_one()? else {
        return Err("server did not confirm direct-tcpip".into());
    };
    assert!(matches!(
        client.dispatch_one()?,
        DirectTcpipEvent::Opened { .. }
    ));
    drop(server);
    assert!(matches!(
        client.dispatch_one(),
        Err(DirectTcpipError::Channel(ChannelError::Transport))
    ));
    assert!(client.connection().channel(channel).is_some());
    Ok(())
}

#[test]
fn direct_tcpip_module_contains_no_socket_or_process_api() {
    let source = include_str!("../src/direct_tcpip.rs");
    assert!(!source.contains("std::net"));
    assert!(!source.contains("std::process"));
    assert!(!source.contains("TcpStream"));
}
