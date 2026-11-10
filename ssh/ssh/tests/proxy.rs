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
#[path = "../src/direct_tcpip.rs"]
mod direct_tcpip;

#[allow(dead_code)]
#[path = "../src/proxy.rs"]
mod proxy;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::rc::Rc;

use auth::{ServerAuthPolicy, ServerAuthState, ServerAuthStep, ServerAuthenticator};
use channel::MAX_CHANNEL_PACKET_SIZE;
use direct_tcpip::{DirectTcpipEvent, ServerDirectTcpip};
use hostkey::Ed25519Signer;
use proxy::{ProxyError, ProxyTarget};
use server::{ServerConfig, ServerHandshake, ServerTransport};

const DESTINATION_PASSWORD: &str = "destination-password-must-remain-at-destination";
const JUMP_HOST: &str = "jump.internal";
const DESTINATION_HOST: &str = "database.internal";

#[test]
fn jump_list_parser_accepts_documented_forms_and_rejects_unsafe_items()
-> Result<(), Box<dyn std::error::Error>> {
    let parsed = proxy::parse_jump_list(concat!(
        "first,",
        "second:2200,",
        "alice@third,",
        "bob@fourth:2022,",
        "[2001:db8::1],",
        "[2001:db8::2]:2222,",
        "carol@[2001:db8::3],",
        "dave@[2001:db8::4]:2022"
    ))?;
    let actual: Vec<(Option<&str>, &str, u16)> = parsed
        .iter()
        .map(|hop| (hop.user(), hop.host(), hop.port()))
        .collect();
    assert_eq!(
        actual,
        [
            (None, "first", 22),
            (None, "second", 2200),
            (Some("alice"), "third", 22),
            (Some("bob"), "fourth", 2022),
            (None, "2001:db8::1", 22),
            (None, "2001:db8::2", 2222),
            (Some("carol"), "2001:db8::3", 22),
            (Some("dave"), "2001:db8::4", 2022),
        ]
    );

    for invalid in [
        "",
        "host,",
        ",host",
        "host,,next",
        "user@",
        "@host",
        "user@@host",
        "host:",
        "host:0",
        "host:65536",
        "host:-1",
        "host:+22",
        "host: 22",
        "[2001:db8::1",
        "2001:db8::1",
        "[::1]:",
        "[::1]suffix",
        "[::1]:22:33",
        "[]",
        "user name@host",
        "user@host name",
        "user\0@host",
        "user@ho\0st",
    ] {
        assert!(
            proxy::parse_jump_list(invalid).is_err(),
            "invalid jump item was accepted: {invalid:?}"
        );
    }
    Ok(())
}

#[test]
fn proxy_command_expansion_is_single_pass_and_limited() {
    assert_eq!(
        proxy::expand_proxy_command("helper %r@%h:%p %% %q %h%", "2001:db8::5", 2222, "alice",),
        "helper alice@2001:db8::5:2222 % %q 2001:db8::5%"
    );
    assert_eq!(
        proxy::expand_proxy_command("literal", "host", 22, "user"),
        "literal"
    );
}

#[allow(clippy::too_many_lines)]
#[test]
fn two_hops_keep_credentials_separate_and_jump_transport_owned()
-> Result<(), Box<dyn std::error::Error>> {
    let jump_config: &'static ServerConfig = Box::leak(Box::new(
        ServerConfig::new(signer(201)).with_server_version("SSH-2.0-neotales-ssh_proxy-jump"),
    ));
    let destination_config: &'static ServerConfig = Box::leak(Box::new(
        ServerConfig::new(signer(202))
            .with_server_version("SSH-2.0-neotales-ssh_proxy-destination"),
    ));
    let password_seen = Rc::new(Cell::new(false));
    let password_seen_by_policy = Rc::clone(&password_seen);
    let policy = ServerAuthPolicy::new(1)?.with_password_callback(move |candidate| {
        if candidate == DESTINATION_PASSWORD {
            password_seen_by_policy.set(true);
            true
        } else {
            false
        }
    });
    let driver = two_hop_driver(
        jump_config,
        destination_config,
        policy,
        password_seen.clone(),
    );
    let client_stream = driver
        .take_client_stream()
        .ok_or("two-hop test client stream was not installed")?;
    let dial_count = Rc::new(Cell::new(0_usize));
    let dial_count_by_callback = Rc::clone(&dial_count);
    let jump_auth_calls = Rc::new(Cell::new(0_usize));
    let jump_auth_calls_by_callback = Rc::clone(&jump_auth_calls);
    let trusted_hosts = Rc::new(Cell::new(0_usize));
    let trusted_hosts_by_callback = Rc::clone(&trusted_hosts);
    let dial_stream = RefCell::new(Some(client_stream));
    let dial = move |host: &str, port: u16| -> io::Result<Stream<'static>> {
        assert_eq!(host, JUMP_HOST);
        assert_eq!(port, 22);
        dial_count_by_callback.set(dial_count_by_callback.get() + 1);
        dial_stream
            .borrow_mut()
            .take()
            .ok_or_else(|| io::Error::other("test dial stream was consumed"))
    };
    let mut jump_auth = |hop: &proxy::JumpHost| {
        assert_eq!(hop.host(), JUMP_HOST);
        jump_auth_calls_by_callback.set(jump_auth_calls_by_callback.get() + 1);
        None::<Vec<neotales_ssh::ClientAuthMethod>>
    };
    let trust = move |_key: &neotales_ssh::hostkey::Ed25519PublicKey| {
        trusted_hosts_by_callback.set(trusted_hosts_by_callback.get() + 1);
        Ok::<(), Infallible>(())
    };
    let no_opener: Option<&mut proxy::ProxyCommandOpener<'_, Stream<'static>>> = None;
    let target = ProxyTarget::new(
        DESTINATION_HOST,
        2222,
        "alice",
        Some("jumpuser@jump.internal"),
        None,
    );
    let connection = proxy::connect(
        &neotales_ssh::ClientConfig::new(),
        &target,
        &[neotales_ssh::ClientAuthMethod::password(
            DESTINATION_PASSWORD,
        )],
        dial,
        no_opener,
        &mut jump_auth,
        trust,
    );
    let client = match connection {
        Ok(client) => client,
        Err(error) => {
            if let Some(driver_error) = driver.take_error() {
                return Err(driver_error);
            }
            return Err(Box::new(error));
        }
    };

    assert_eq!(dial_count.get(), 1);
    assert_eq!(jump_auth_calls.get(), 1);
    assert_eq!(trusted_hosts.get(), 2);
    assert!(password_seen.get());
    assert!(driver.destination_authenticated());
    let nested_packets = driver.channel_data();
    assert!(
        nested_packets
            .windows(DESTINATION_PASSWORD.len())
            .all(|window| window != DESTINATION_PASSWORD.as_bytes()),
        "the destination password appeared in decrypted jump channel data"
    );
    assert!(
        nested_packets.starts_with(b"SSH-2.0-neotales-ssh_0.1\r\n"),
        "the direct-tcpip payload was not the destination SSH stream"
    );
    assert!(!driver.jump_dropped());
    drop(client);
    assert!(driver.jump_dropped());
    if let Some(error) = driver.take_error() {
        return Err(error);
    }
    Ok(())
}

#[test]
fn proxy_command_precedence_requires_callback_and_never_dials_or_executes() {
    let dial_count = Rc::new(Cell::new(0_usize));
    let dial_count_by_callback = Rc::clone(&dial_count);
    let dial = move |_host: &str, _port: u16| -> io::Result<Stream<'static>> {
        dial_count_by_callback.set(dial_count_by_callback.get() + 1);
        Err(io::Error::other("dial must not run"))
    };
    let mut jump_auth = |_hop: &proxy::JumpHost| None::<Vec<neotales_ssh::ClientAuthMethod>>;
    let trust = |_key: &neotales_ssh::hostkey::Ed25519PublicKey| Ok::<(), Infallible>(());
    let target = ProxyTarget::new(
        "destination.internal",
        2022,
        "alice",
        Some(","),
        Some("caller helper %r@%h:%p"),
    );
    let no_opener: Option<&mut proxy::ProxyCommandOpener<'_, Stream<'static>>> = None;
    let unsupported = proxy::connect::<Stream<'static>, _, _, _, Infallible>(
        &neotales_ssh::ClientConfig::new(),
        &target,
        &[],
        dial,
        no_opener,
        &mut jump_auth,
        trust,
    );
    assert!(matches!(
        unsupported,
        Err(ProxyError::ProxyCommandUnsupported)
    ));
    assert_eq!(dial_count.get(), 0);

    let second_dial_count = Rc::new(Cell::new(0_usize));
    let second_dial_count_by_callback = Rc::clone(&second_dial_count);
    let second_dial = move |_host: &str, _port: u16| -> io::Result<Stream<'static>> {
        second_dial_count_by_callback.set(second_dial_count_by_callback.get() + 1);
        Err(io::Error::other("jump must not dial"))
    };
    let expanded_command = Rc::new(RefCell::new(String::new()));
    let expanded_by_callback = Rc::clone(&expanded_command);
    let mut opener = |command: &str| -> io::Result<Stream<'static>> {
        *expanded_by_callback.borrow_mut() = command.to_owned();
        Err(io::Error::other("test opener stopped"))
    };
    let result = proxy::connect::<Stream<'static>, _, _, _, Infallible>(
        &neotales_ssh::ClientConfig::new(),
        &target,
        &[],
        second_dial,
        Some(&mut opener),
        &mut jump_auth,
        |_key| Ok::<(), Infallible>(()),
    );
    assert!(matches!(result, Err(ProxyError::ProxyCommandOpenFailed)));
    assert_eq!(second_dial_count.get(), 0);
    assert_eq!(
        expanded_command.borrow().as_str(),
        "caller helper alice@destination.internal:2022"
    );

    let source = include_str!("../src/proxy.rs");
    assert!(!source.contains("std::process"));
    assert!(!source.contains("std::net"));
    assert!(!source.contains("Command::new"));
    assert!(!source.contains("TcpStream"));
}

type Driver<'a> = Rc<RefCell<dyn FnMut() + 'a>>;

#[derive(Default)]
struct Queues {
    client_to_server: Rc<RefCell<VecDeque<u8>>>,
    server_to_client: Rc<RefCell<VecDeque<u8>>>,
}

struct Stream<'a> {
    input: Rc<RefCell<VecDeque<u8>>>,
    output: Rc<RefCell<VecDeque<u8>>>,
    driver: Option<Driver<'a>>,
    dropped: Option<Rc<Cell<bool>>>,
}

impl Clone for Stream<'_> {
    fn clone(&self) -> Self {
        Self {
            input: Rc::clone(&self.input),
            output: Rc::clone(&self.output),
            driver: self.driver.clone(),
            dropped: None,
        }
    }
}

impl<'a> Stream<'a> {
    fn new(
        input: Rc<RefCell<VecDeque<u8>>>,
        output: Rc<RefCell<VecDeque<u8>>>,
        driver: Option<Driver<'a>>,
        dropped: Option<Rc<Cell<bool>>>,
    ) -> Self {
        Self {
            input,
            output,
            driver,
            dropped,
        }
    }

    fn drive(&mut self) {
        let Some(driver) = self.driver.clone() else {
            return;
        };
        driver.borrow_mut()();
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            dropped.set(true);
        }
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
        if self.input.borrow().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory SSH peer has not produced another packet",
            ));
        }
        let count = target.len().min(self.input.borrow().len());
        let mut input = self.input.borrow_mut();
        let destination = target
            .get_mut(..count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid read target"))?;
        for byte in destination {
            *byte = input
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty SSH queue"))?;
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

struct TwoHopDriver<'config> {
    jump_config: &'config ServerConfig,
    destination_config: &'config ServerConfig,
    jump_stream: Stream<'config>,
    destination_stream: Stream<'config>,
    client_stream: RefCell<Option<Stream<'config>>>,
    jump_handshake: RefCell<Option<ServerHandshake<'config, Stream<'config>>>>,
    jump_channels: RefCell<Option<ServerDirectTcpip<ServerTransport<Stream<'config>>>>>,
    jump_channel: Cell<Option<u32>>,
    destination_handshake: RefCell<Option<ServerHandshake<'config, Stream<'config>>>>,
    destination_transport: RefCell<Option<ServerTransport<Stream<'config>>>>,
    destination_policy: ServerAuthPolicy,
    destination_auth_state: Cell<ServerAuthState>,
    destination_authenticated: Cell<bool>,
    destination_password_seen: Rc<Cell<bool>>,
    nested_client_to_server: Rc<RefCell<VecDeque<u8>>>,
    nested_server_to_client: Rc<RefCell<VecDeque<u8>>>,
    channel_data: RefCell<Vec<u8>>,
    jump_dropped: Rc<Cell<bool>>,
    error: RefCell<Option<Box<dyn std::error::Error>>>,
}

impl<'config> TwoHopDriver<'config> {
    fn new(
        jump_config: &'config ServerConfig,
        destination_config: &'config ServerConfig,
        destination_policy: ServerAuthPolicy,
        destination_password_seen: Rc<Cell<bool>>,
    ) -> Self {
        let jump_queues = Queues::default();
        let destination_queues = Queues::default();
        Self {
            jump_config,
            destination_config,
            jump_stream: Stream::new(
                Rc::clone(&jump_queues.client_to_server),
                Rc::clone(&jump_queues.server_to_client),
                None,
                None,
            ),
            destination_stream: Stream::new(
                Rc::clone(&destination_queues.client_to_server),
                Rc::clone(&destination_queues.server_to_client),
                None,
                None,
            ),
            client_stream: RefCell::new(None),
            jump_handshake: RefCell::new(None),
            jump_channels: RefCell::new(None),
            jump_channel: Cell::new(None),
            destination_handshake: RefCell::new(None),
            destination_transport: RefCell::new(None),
            destination_policy,
            destination_auth_state: Cell::new(ServerAuthState::initial()),
            destination_authenticated: Cell::new(false),
            destination_password_seen,
            nested_client_to_server: destination_queues.client_to_server,
            nested_server_to_client: destination_queues.server_to_client,
            channel_data: RefCell::new(Vec::new()),
            jump_dropped: Rc::new(Cell::new(false)),
            error: RefCell::new(None),
        }
    }

    fn take_client_stream(&self) -> Option<Stream<'config>> {
        self.client_stream.borrow_mut().take()
    }

    fn drive(&self) {
        if self.error.borrow().is_some() {
            return;
        }
        self.drive_jump();
        if self.error.borrow().is_some() {
            return;
        }
        self.drive_destination();
        self.route_destination_output();
    }

    fn drive_jump(&self) {
        if self.jump_handshake.borrow().is_none()
            && self.jump_channels.borrow().is_none()
            && has_client_identification(&self.jump_stream.input)
        {
            match self.jump_config.start(self.jump_stream.clone()) {
                Ok(started) => *self.jump_handshake.borrow_mut() = Some(started),
                Err(_error) => self.set_error("jump test server could not start"),
            }
        }

        let mut complete = false;
        if self.jump_handshake.borrow().is_some() {
            let result = self
                .jump_handshake
                .borrow_mut()
                .as_mut()
                .map(|started| started.advance().map(|_success| started.is_complete()));
            if let Some(Ok(is_complete)) = result {
                complete = is_complete;
            } else {
                self.set_error("jump test handshake failed");
                return;
            }
        }
        if complete {
            let started = self.jump_handshake.borrow_mut().take();
            if let Some(started) = started {
                match started.into_transport() {
                    Ok(mut transport) => {
                        transport.mark_authenticated();
                        *self.jump_channels.borrow_mut() =
                            Some(ServerDirectTcpip::with_allow_callback(
                                transport,
                                |_host, _port, _origin, _origin_port| true,
                            ));
                    }
                    Err(_error) => self.set_error("jump test transport could not be created"),
                }
            }
        }

        if self.jump_stream.input.borrow().is_empty() {
            return;
        }
        let Some(mut channels) = self.jump_channels.borrow_mut().take() else {
            return;
        };
        let event = channels.dispatch_one();
        *self.jump_channels.borrow_mut() = Some(channels);
        match event {
            Ok(DirectTcpipEvent::Opened { channel }) => self.jump_channel.set(Some(channel)),
            Ok(
                DirectTcpipEvent::Data { channel, data }
                | DirectTcpipEvent::ExtendedData { channel, data, .. },
            ) => {
                if self
                    .jump_channel
                    .get()
                    .is_some_and(|opened| opened != channel)
                {
                    self.set_error("jump test received data for an unknown channel");
                    return;
                }
                self.nested_client_to_server
                    .borrow_mut()
                    .extend(data.iter().copied());
                self.channel_data.borrow_mut().extend(data);
            }
            Ok(DirectTcpipEvent::WindowAdjusted { channel, .. })
                if self.jump_channel.get() == Some(channel) => {}
            Ok(
                DirectTcpipEvent::OpenRejected { .. }
                | DirectTcpipEvent::WindowAdjusted { .. }
                | DirectTcpipEvent::Eof { .. }
                | DirectTcpipEvent::Close { .. },
            ) => self.set_error("jump test received an unexpected direct-tcpip event"),
            Err(_error) => self.set_error("jump test direct-tcpip dispatch failed"),
        }
    }

    fn drive_destination(&self) {
        if self.destination_handshake.borrow().is_none()
            && self.destination_transport.borrow().is_none()
            && !self.destination_authenticated.get()
            && has_client_identification(&self.nested_client_to_server)
        {
            match self
                .destination_config
                .start(self.destination_stream.clone())
            {
                Ok(started) => *self.destination_handshake.borrow_mut() = Some(started),
                Err(_error) => {
                    self.set_error("destination test server could not start");
                    return;
                }
            }
        }

        let mut complete = false;
        if self.destination_handshake.borrow().is_some()
            && !self.nested_client_to_server.borrow().is_empty()
        {
            let result = self
                .destination_handshake
                .borrow_mut()
                .as_mut()
                .map(|started| started.advance().map(|_success| started.is_complete()));
            if let Some(Ok(is_complete)) = result {
                complete = is_complete;
            } else {
                self.set_error("destination test handshake failed");
                return;
            }
        }
        if complete {
            let started = self.destination_handshake.borrow_mut().take();
            if let Some(started) = started {
                match started.into_transport() {
                    Ok(transport) => *self.destination_transport.borrow_mut() = Some(transport),
                    Err(_error) => {
                        self.set_error("destination test transport could not be created");
                        return;
                    }
                }
            }
        }

        if self.destination_authenticated.get() || self.nested_client_to_server.borrow().is_empty()
        {
            return;
        }
        let Some(mut transport) = self.destination_transport.borrow_mut().take() else {
            return;
        };
        let result = {
            let mut authenticator = ServerAuthenticator::from_state(
                &mut transport,
                &self.destination_policy,
                self.destination_auth_state.get(),
            );
            let result = authenticator.step();
            self.destination_auth_state.set(authenticator.state());
            result
        };
        *self.destination_transport.borrow_mut() = Some(transport);
        match result {
            Ok(ServerAuthStep::Authenticated) => self.destination_authenticated.set(true),
            Ok(
                ServerAuthStep::NeedMoreData
                | ServerAuthStep::ServiceAccepted
                | ServerAuthStep::PublicKeyQueryAccepted
                | ServerAuthStep::Failure,
            ) => {}
            Err(_error) => self.set_error("destination test authentication failed"),
        }
    }

    fn route_destination_output(&self) {
        if self.nested_server_to_client.borrow().is_empty() {
            return;
        }
        let output: Vec<u8> = self
            .nested_server_to_client
            .borrow_mut()
            .drain(..)
            .collect();
        let Some(channel) = self.jump_channel.get() else {
            self.set_error("destination produced output before the jump channel opened");
            return;
        };
        let Some(mut channels) = self.jump_channels.borrow_mut().take() else {
            self.set_error("jump channel endpoint disappeared");
            return;
        };
        let mut failed = false;
        for chunk in output.chunks(MAX_CHANNEL_PACKET_SIZE as usize) {
            if channels.send_data(channel, chunk).is_err() {
                failed = true;
                break;
            }
        }
        *self.jump_channels.borrow_mut() = Some(channels);
        if failed {
            self.set_error("jump test could not forward destination output");
        }
    }

    fn destination_authenticated(&self) -> bool {
        self.destination_authenticated.get() && self.destination_password_seen.get()
    }

    fn channel_data(&self) -> Vec<u8> {
        self.channel_data.borrow().clone()
    }

    fn jump_dropped(&self) -> bool {
        self.jump_dropped.get()
    }

    fn take_error(&self) -> Option<Box<dyn std::error::Error>> {
        self.error.borrow_mut().take()
    }

    fn set_error(&self, message: &'static str) {
        let mut error = self.error.borrow_mut();
        if error.is_none() {
            *error = Some(message.into());
        }
    }
}

fn two_hop_driver<'config>(
    jump_config: &'config ServerConfig,
    destination_config: &'config ServerConfig,
    destination_policy: ServerAuthPolicy,
    destination_password_seen: Rc<Cell<bool>>,
) -> Rc<TwoHopDriver<'config>> {
    let driver = Rc::new(TwoHopDriver::new(
        jump_config,
        destination_config,
        destination_policy,
        destination_password_seen,
    ));
    let callback_driver = Rc::clone(&driver);
    let callback: Driver<'config> = Rc::new(RefCell::new(move || {
        callback_driver.drive();
    }));
    let client = Stream::new(
        Rc::clone(&driver.jump_stream.output),
        Rc::clone(&driver.jump_stream.input),
        Some(callback),
        Some(Rc::clone(&driver.jump_dropped)),
    );
    *driver.client_stream.borrow_mut() = Some(client);
    driver
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
        line_start = end.saturating_add(2);
    }
    false
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&mut [seed; 32])
}
