// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]
#![allow(dead_code, unused_imports, clippy::struct_excessive_bools)]

pub use neotales_ssh::MAX_PACKET_CONTENT;

#[path = "../src/msg/mod.rs"]
mod msg;

#[path = "../src/kex/mod.rs"]
mod kex;

#[path = "../src/cipher.rs"]
mod cipher;

#[path = "../src/sequence.rs"]
mod sequence;

#[path = "../src/hostkey.rs"]
mod hostkey;

#[path = "../src/transport.rs"]
mod transport;

#[path = "../src/client/mod.rs"]
mod client;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::rc::Rc;

use cipher::{PacketAlignment, PacketKeyMaterial, PacketProtector, PacketSuite};
use client::{ClientConfig, HandshakeError};
use hostkey::Ed25519Signer;
use kex::mlkem768_x25519::ServerKex as HybridServerKex;
use kex::{DerivationLengths, DerivedKeys, KexContext, derive_keys};
use msg::kexinit::{
    AES128_CTR, COMPRESSION_NONE, HMAC_SHA2_256, HOST_KEY_SSH_ED25519, KEX_MLKEM768X25519_SHA256,
    KEX_STRICT_C_V00_OPENSSH, KEX_STRICT_S_V00_OPENSSH, KexInit, SSH_MSG_KEXINIT,
    SUPPORTED_HOST_KEY_ALGORITHMS, SUPPORTED_KEX_ALGORITHMS,
};
use neotales_ssh::build_packet_default;
use sequence::{Direction, PacketDisposition, SSH_MSG_NEWKEYS, SequenceState};
use transport::{TransportError, read_eam_payload, read_protected_packet};

const SERVER_VERSION: &str = "SSH-2.0-neotales-ssh-rekey-peer";
const CLIENT_PAYLOAD: &[u8] = b"client-after-rekey";
const PEER_PAYLOAD: &[u8] = b"peer-after-rekey";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerPhase {
    AwaitClientKexInit,
    AwaitClientKex,
    AwaitClientNewKeys,
    Established,
    AwaitRekeyKex,
    AwaitRekeyKexMethod,
    AwaitRekeyNewKeys,
}

struct ByteQueue {
    bytes: VecDeque<u8>,
}

impl ByteQueue {
    fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Read for ByteQueue {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        let count = target.len().min(self.bytes.len());
        for byte in &mut target[..count] {
            *byte = self
                .bytes
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "test queue"))?;
        }
        Ok(count)
    }
}

impl Write for ByteQueue {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend(bytes.iter().copied());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct Stream {
    input: Rc<RefCell<ByteQueue>>,
    output: Rc<RefCell<ByteQueue>>,
    peer: Rc<RefCell<Peer>>,
}

impl Read for Stream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        if self.input.borrow().is_empty() {
            self.peer.borrow_mut().drive();
        }
        self.input.borrow_mut().read(target)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.borrow_mut().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct WriteGate {
    active: bool,
    remaining: usize,
}

impl WriteGate {
    fn arm(&mut self, length: usize) {
        self.active = true;
        self.remaining = length;
    }

    fn open(&mut self) {
        self.active = false;
        self.remaining = 0;
    }
}

struct GatedStream {
    inner: Stream,
    gate: Rc<RefCell<WriteGate>>,
}

impl GatedStream {
    fn new(inner: Stream, gate: Rc<RefCell<WriteGate>>) -> Self {
        Self { inner, gate }
    }
}

impl Read for GatedStream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.inner.read(target)
    }
}

impl Write for GatedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let allowed = {
            let gate = self.gate.borrow_mut();
            if !gate.active {
                bytes.len()
            } else if gate.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "test client write is waiting for the next chunk",
                ));
            } else {
                bytes.len().min(gate.remaining)
            }
        };
        let count = self.inner.write(&bytes[..allowed])?;
        let mut gate = self.gate.borrow_mut();
        gate.remaining = gate.remaining.saturating_sub(count);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Peer {
    client_bytes: Rc<RefCell<ByteQueue>>,
    server_bytes: Rc<RefCell<ByteQueue>>,
    phase: PeerPhase,
    sequence: SequenceState,
    signer: Ed25519Signer,
    host_key_blob: Vec<u8>,
    server_kexinit: KexInit,
    server_kexinit_payload: Vec<u8>,
    client_version: String,
    active_server_kex: Option<HybridServerKex>,
    session_id: Vec<u8>,
    write_suite: PacketSuite,
    read_suite: PacketSuite,
    write_protector: Option<PacketProtector>,
    read_protector: Option<PacketProtector>,
    pending_derived: Option<DerivedKeys>,
    pending_read_suite: Option<PacketSuite>,
    pending_write_suite: Option<PacketSuite>,
    received_application: VecDeque<Vec<u8>>,
    rekey_algorithms: Vec<String>,
    malformed_rekey_kexinit: bool,
    saw_rekey: bool,
    server_rekey_kexinit_sent: bool,
    server_rekey_kexinit_payload: Option<Vec<u8>>,
    send_application_after_rekey: bool,
}

impl Peer {
    fn new() -> Result<(Rc<RefCell<Self>>, Stream), String> {
        let signer = Ed25519Signer::from_seed(&mut [0x42; 32]);
        let host_key_blob = signer
            .public_key_blob()
            .map_err(|error| error.to_string())?;
        let server_kexinit = proposal([0x22; 16], false);
        let server_kexinit_payload = server_kexinit.encode().map_err(|error| error.to_string())?;
        let client_bytes = Rc::new(RefCell::new(ByteQueue::new()));
        let server_bytes = Rc::new(RefCell::new(ByteQueue::new()));
        let mut server_queue = server_bytes.borrow_mut();
        server_queue
            .write_all(SERVER_VERSION.as_bytes())
            .and_then(|()| server_queue.write_all(b"\r\n"))
            .map_err(|error| error.to_string())?;
        drop(server_queue);
        let peer = Rc::new(RefCell::new(Self {
            client_bytes: Rc::clone(&client_bytes),
            server_bytes: Rc::clone(&server_bytes),
            phase: PeerPhase::AwaitClientKexInit,
            sequence: SequenceState::new(),
            signer,
            host_key_blob,
            server_kexinit,
            server_kexinit_payload,
            client_version: String::new(),
            active_server_kex: None,
            session_id: Vec::new(),
            write_suite: PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))
                .map_err(|error| error.to_string())?,
            read_suite: PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))
                .map_err(|error| error.to_string())?,
            write_protector: None,
            read_protector: None,
            pending_derived: None,
            pending_read_suite: None,
            pending_write_suite: None,
            received_application: VecDeque::new(),
            rekey_algorithms: vec![KEX_MLKEM768X25519_SHA256.to_owned()],
            malformed_rekey_kexinit: false,
            saw_rekey: false,
            server_rekey_kexinit_sent: false,
            server_rekey_kexinit_payload: None,
            send_application_after_rekey: false,
        }));
        let stream = Stream {
            input: server_bytes,
            output: client_bytes,
            peer: Rc::clone(&peer),
        };
        Ok((peer, stream))
    }

    fn drive(&mut self) {
        let result = match self.phase {
            PeerPhase::AwaitClientKexInit => self.drive_initial_kexinit(),
            PeerPhase::AwaitClientKex => self.drive_initial_kex(),
            PeerPhase::AwaitClientNewKeys => self.drive_initial_newkeys(),
            PeerPhase::Established => self.drive_established(),
            PeerPhase::AwaitRekeyKex => self.drive_rekey_kexinit(),
            PeerPhase::AwaitRekeyKexMethod => self.drive_rekey_kex(),
            PeerPhase::AwaitRekeyNewKeys => self.drive_rekey_newkeys(),
        };
        if let Err(error) = result {
            panic!("test peer failed in {:?}: {error}", self.phase);
        }
    }

    fn drive_initial_kexinit(&mut self) -> Result<(), String> {
        let version = take_identification(&mut self.client_bytes.borrow_mut())?;
        if version != client::CLIENT_IDENTIFICATION {
            return Err(format!("unexpected client version {version}"));
        }
        self.client_version = version;
        let payload = read_plain_packet(&mut self.client_bytes.borrow_mut())
            .map_err(|error| format!("read client KEXINIT: {error}"))?;
        if payload.first() != Some(&SSH_MSG_KEXINIT) {
            return Err("initial client packet was not KEXINIT".to_owned());
        }
        let client_kexinit = KexInit::decode(&payload).map_err(|error| error.to_string())?;
        let algorithms = client_kexinit
            .negotiate(&self.server_kexinit)
            .map_err(|error| error.to_string())?;
        if algorithms.kex != KEX_MLKEM768X25519_SHA256 {
            return Err("initial test exchange was not hybrid".to_owned());
        }
        self.sequence
            .set_strict_kex(client_kexinit.strict_kex_enabled(&self.server_kexinit))
            .map_err(|error| error.to_string())?;
        self.sequence
            .observe_kexinit(Direction::Inbound, client_kexinit.first_kex_packet_follows)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        let context = KexContext::new(
            &self.client_version,
            SERVER_VERSION,
            payload.clone(),
            self.server_kexinit_payload.clone(),
            &algorithms.kex,
        )
        .map_err(|error| error.to_string())?;
        self.active_server_kex = Some(
            HybridServerKex::new(context, &self.host_key_blob)
                .map_err(|error| error.to_string())?,
        );
        self.send_plain_packet(&self.server_kexinit_payload.clone())?;
        self.phase = PeerPhase::AwaitClientKex;
        Ok(())
    }

    fn drive_initial_kex(&mut self) -> Result<(), String> {
        let payload = read_plain_packet(&mut self.client_bytes.borrow_mut())?;
        if payload.first() != Some(&30) {
            return Err("initial client KEX method had the wrong type".to_owned());
        }
        self.sequence
            .observe_inbound(30)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        let completion = self.complete_server_kex(&payload, true)?;
        self.send_plain_packet(&completion.reply)?;
        self.send_plain_packet(&[SSH_MSG_NEWKEYS])?;
        self.session_id = completion.exchange_hash.to_vec();
        self.install_write_protector(&completion.derived, completion.write_suite)?;
        self.pending_derived = Some(completion.derived);
        self.pending_read_suite = Some(completion.read_suite);
        self.phase = PeerPhase::AwaitClientNewKeys;
        Ok(())
    }

    fn drive_initial_newkeys(&mut self) -> Result<(), String> {
        let payload = read_plain_packet(&mut self.client_bytes.borrow_mut())?;
        if payload != [SSH_MSG_NEWKEYS] {
            return Err("initial client NEWKEYS was malformed".to_owned());
        }
        self.sequence
            .observe_inbound(SSH_MSG_NEWKEYS)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        self.sequence
            .complete_initial_kex()
            .map_err(|error| error.to_string())?;
        let derived = self
            .pending_derived
            .take()
            .ok_or_else(|| "missing pending initial keys".to_owned())?;
        let suite = self
            .pending_read_suite
            .take()
            .ok_or_else(|| "missing pending read suite".to_owned())?;
        self.install_read_protector(&derived, suite)?;
        self.phase = PeerPhase::Established;
        Ok(())
    }

    fn drive_established(&mut self) -> Result<(), String> {
        if self.client_bytes.borrow().is_empty() {
            return Ok(());
        }
        let (payload, sequence) = self.read_protected_client()?;
        if payload.first() == Some(&SSH_MSG_KEXINIT) {
            self.saw_rekey = true;
            self.sequence
                .begin_rekey()
                .map_err(|error| error.to_string())?;
            self.phase = PeerPhase::AwaitRekeyKexMethod;
            self.process_rekey_kexinit(&payload, sequence)?;
            return Ok(());
        }
        self.sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        self.received_application.push_back(payload);
        Ok(())
    }

    fn initiate_rekey(&mut self) -> Result<(), String> {
        let mut server_kexinit = self.server_kexinit.clone();
        server_kexinit
            .kex_algorithms
            .clone_from(&self.rekey_algorithms);
        getrandom::fill(&mut server_kexinit.cookie).map_err(|error| error.to_string())?;
        let payload = server_kexinit.encode().map_err(|error| error.to_string())?;
        self.sequence
            .begin_rekey()
            .map_err(|error| error.to_string())?;
        self.phase = PeerPhase::AwaitRekeyKex;
        self.saw_rekey = true;
        self.server_rekey_kexinit_sent = true;
        self.server_rekey_kexinit_payload = Some(payload.clone());
        self.send_protected_packet(&payload, SSH_MSG_KEXINIT)
    }

    fn drive_rekey_kexinit(&mut self) -> Result<(), String> {
        let (payload, sequence) = self.read_protected_client()?;
        if payload.first() != Some(&SSH_MSG_KEXINIT) {
            return Err("rekey client KEXINIT had the wrong type".to_owned());
        }
        self.phase = PeerPhase::AwaitRekeyKexMethod;
        self.process_rekey_kexinit(&payload, sequence)?;
        if self.server_rekey_kexinit_sent {
            self.drive_rekey_kex()?;
        }
        Ok(())
    }

    fn drive_rekey_kex(&mut self) -> Result<(), String> {
        let (payload, sequence) = self.read_protected_client()?;
        if payload.first() != Some(&30) {
            return Err("rekey client KEX method had the wrong type".to_owned());
        }
        self.sequence
            .observe_rekey_inbound(30)
            .map_err(|error| error.to_string())?;
        self.commit_inbound(sequence)?;
        let completion = self.complete_server_kex(&payload, false)?;
        self.send_protected_packet(&completion.reply, 31)?;
        self.send_protected_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
        self.install_write_protector(&completion.derived, completion.write_suite)?;
        self.pending_derived = Some(completion.derived);
        self.pending_read_suite = Some(completion.read_suite);
        self.phase = PeerPhase::AwaitRekeyNewKeys;
        Ok(())
    }

    fn drive_rekey_newkeys(&mut self) -> Result<(), String> {
        let (payload, sequence) = self.read_protected_client()?;
        if payload != [SSH_MSG_NEWKEYS] {
            return Err("rekey client NEWKEYS was malformed".to_owned());
        }
        self.sequence
            .observe_rekey_newkeys(Direction::Inbound)
            .map_err(|error| error.to_string())?;
        self.commit_inbound(sequence)?;
        let derived = self
            .pending_derived
            .take()
            .ok_or_else(|| "missing pending rekey keys".to_owned())?;
        let suite = self
            .pending_read_suite
            .take()
            .ok_or_else(|| "missing pending rekey read suite".to_owned())?;
        self.install_read_protector(&derived, suite)?;
        self.sequence
            .complete_rekey_exchange()
            .map_err(|error| error.to_string())?;
        self.phase = PeerPhase::Established;
        if self.send_application_after_rekey {
            self.send_application(PEER_PAYLOAD)?;
        }
        Ok(())
    }

    fn process_rekey_kexinit(&mut self, payload: &[u8], sequence: u32) -> Result<(), String> {
        let client_kexinit = KexInit::decode(payload).map_err(|error| error.to_string())?;
        if client_kexinit.reserved != 0 || client_kexinit.first_kex_packet_follows {
            return Err("rekey client KEXINIT flags were invalid".to_owned());
        }
        let mut server_kexinit = self.server_kexinit.clone();
        server_kexinit
            .kex_algorithms
            .clone_from(&self.rekey_algorithms);
        getrandom::fill(&mut server_kexinit.cookie).map_err(|error| error.to_string())?;
        let server_payload = server_kexinit.encode().map_err(|error| error.to_string())?;
        let context_server_payload = if self.server_rekey_kexinit_sent {
            self.server_rekey_kexinit_payload
                .clone()
                .ok_or_else(|| "missing server rekey KEXINIT payload".to_owned())?
        } else {
            server_payload.clone()
        };
        let algorithms = client_kexinit.negotiate(&server_kexinit);
        if let Ok(algorithms) = algorithms
            && algorithms.kex == KEX_MLKEM768X25519_SHA256
        {
            let context = KexContext::new(
                &self.client_version,
                SERVER_VERSION,
                payload.to_vec(),
                context_server_payload,
                &algorithms.kex,
            )
            .map_err(|error| error.to_string())?;
            self.active_server_kex = Some(
                HybridServerKex::new(context, &self.host_key_blob)
                    .map_err(|error| error.to_string())?,
            );
        }
        self.sequence
            .observe_rekey_inbound(SSH_MSG_KEXINIT)
            .map_err(|error| error.to_string())?;
        self.commit_inbound(sequence)?;
        if self.malformed_rekey_kexinit {
            self.send_protected_packet(&[SSH_MSG_KEXINIT], SSH_MSG_KEXINIT)?;
        } else if !self.server_rekey_kexinit_sent {
            self.send_protected_packet(&server_payload, SSH_MSG_KEXINIT)?;
            self.server_rekey_kexinit_sent = true;
            self.server_rekey_kexinit_payload = Some(server_payload);
        }
        Ok(())
    }

    fn complete_server_kex(
        &mut self,
        init_payload: &[u8],
        initial: bool,
    ) -> Result<ServerCompletion, String> {
        let server_kex = self
            .active_server_kex
            .as_mut()
            .ok_or_else(|| "missing active server KEX".to_owned())?;
        let prepared = server_kex
            .accept_init(init_payload)
            .map_err(|error| error.to_string())?;
        let signature = self
            .signer
            .sign_exchange_hash(prepared.exchange_hash())
            .map_err(|error| error.to_string())?;
        let reply = prepared
            .reply_message(&signature)
            .map_err(|error| error.to_string())?;
        let derived = derive_keys(
            prepared.shared_secret(),
            prepared.exchange_hash(),
            if initial {
                prepared.exchange_hash()
            } else {
                self.session_id.as_slice()
            },
            DerivationLengths {
                a: 16,
                b: 16,
                c: 16,
                d: 16,
                e: 32,
                f: 32,
            },
        )
        .map_err(|error| error.to_string())?;
        Ok(ServerCompletion {
            reply,
            derived,
            exchange_hash: *prepared.exchange_hash(),
            read_suite: PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))
                .map_err(|error| error.to_string())?,
            write_suite: PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))
                .map_err(|error| error.to_string())?,
        })
    }

    fn send_plain_packet(&mut self, payload: &[u8]) -> Result<(), String> {
        let packet = build_packet_default(payload, |padding| padding.fill(0xa5))
            .map_err(|error| error.to_string())?;
        let message_type = payload
            .first()
            .copied()
            .ok_or_else(|| "test peer cannot send an empty packet".to_owned())?;
        self.server_bytes
            .borrow_mut()
            .write_all(&packet)
            .map_err(|error| error.to_string())?;
        self.sequence
            .observe_outbound(message_type)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_outbound()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn send_protected_packet(&mut self, payload: &[u8], message_type: u8) -> Result<(), String> {
        let sequence = self.sequence.outbound_sequence();
        let protector = self
            .write_protector
            .as_mut()
            .ok_or_else(|| "test peer has no write protector".to_owned())?;
        let padding = protection_padding(payload.len(), protector.suite());
        let packet = protector
            .seal(sequence, payload, &padding)
            .map_err(|error| error.to_string())?;
        self.server_bytes
            .borrow_mut()
            .write_all(&packet)
            .map_err(|error| error.to_string())?;
        if self.phase == PeerPhase::AwaitRekeyKex
            || self.phase == PeerPhase::AwaitRekeyKexMethod
            || self.phase == PeerPhase::AwaitRekeyNewKeys
        {
            self.sequence
                .observe_rekey_outbound(message_type)
                .map_err(|error| error.to_string())?;
        } else {
            self.sequence
                .observe_outbound(message_type)
                .map_err(|error| error.to_string())?;
        }
        self.sequence
            .commit_outbound()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn read_protected_client(&mut self) -> Result<(Vec<u8>, u32), String> {
        let sequence = self.sequence.inbound_sequence();
        let protector = self
            .read_protector
            .as_mut()
            .ok_or_else(|| "test peer has no read protector".to_owned())?;
        let mut input = self.client_bytes.borrow_mut();
        let payload = if PacketAlignment::for_suite(protector.suite()).aligns_packet_length() {
            let packet = read_protected_packet(&mut *input, protector.suite())
                .map_err(|error| error.to_string())?;
            protector
                .open(sequence, &packet)
                .map_err(|error| error.to_string())?
        } else {
            read_eam_payload(&mut *input, protector, sequence).map_err(|error| error.to_string())?
        };
        Ok((payload, sequence))
    }

    fn commit_inbound(&mut self, expected: u32) -> Result<(), String> {
        let actual = self
            .sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        if actual != expected {
            return Err(format!("inbound sequence mismatch: {actual} != {expected}"));
        }
        Ok(())
    }

    fn install_write_protector(
        &mut self,
        derived: &DerivedKeys,
        suite: PacketSuite,
    ) -> Result<(), String> {
        let material = material_for_server_write(suite, derived);
        if let Some(protector) = self.write_protector.as_mut() {
            protector
                .rekey(suite, material)
                .map_err(|error| error.to_string())?;
        } else {
            self.write_protector =
                Some(PacketProtector::new(suite, material).map_err(|error| error.to_string())?);
        }
        self.write_suite = suite;
        Ok(())
    }

    fn install_read_protector(
        &mut self,
        derived: &DerivedKeys,
        suite: PacketSuite,
    ) -> Result<(), String> {
        let material = material_for_server_read(suite, derived);
        if let Some(protector) = self.read_protector.as_mut() {
            protector
                .rekey(suite, material)
                .map_err(|error| error.to_string())?;
        } else {
            self.read_protector =
                Some(PacketProtector::new(suite, material).map_err(|error| error.to_string())?);
        }
        self.read_suite = suite;
        Ok(())
    }

    fn send_application(&mut self, payload: &[u8]) -> Result<(), String> {
        let sequence = self.sequence.outbound_sequence();
        let protector = self
            .write_protector
            .as_mut()
            .ok_or_else(|| "test peer has no write protector".to_owned())?;
        let padding = protection_padding(payload.len(), protector.suite());
        let packet = protector
            .seal(sequence, payload, &padding)
            .map_err(|error| error.to_string())?;
        self.server_bytes
            .borrow_mut()
            .write_all(&packet)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_outbound()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

struct ServerCompletion {
    reply: Vec<u8>,
    derived: DerivedKeys,
    exchange_hash: [u8; 32],
    read_suite: PacketSuite,
    write_suite: PacketSuite,
}

fn proposal(cookie: [u8; 16], _strict: bool) -> KexInit {
    KexInit::from_lists(
        cookie,
        vec![KEX_MLKEM768X25519_SHA256.to_owned()],
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

fn material_for_server_read(_suite: PacketSuite, keys: &DerivedKeys) -> PacketKeyMaterial {
    PacketKeyMaterial::hmac(
        &keys.iv_client_to_server,
        &keys.encryption_key_client_to_server,
        &keys.integrity_key_client_to_server,
    )
}

fn material_for_server_write(_suite: PacketSuite, keys: &DerivedKeys) -> PacketKeyMaterial {
    PacketKeyMaterial::hmac(
        &keys.iv_server_to_client,
        &keys.encryption_key_server_to_client,
        &keys.integrity_key_server_to_client,
    )
}

/// Padding for one payload, taken from the crate's own alignment rule.
///
/// This used to be a copy of the arithmetic with a hard-coded block size of 16
/// and a `payload + 5` header, which meant it agreed with itself and could
/// disagree with the code under test. Deriving it from `PacketAlignment` is the
/// point: a test that reimplements the rule it is checking cannot fail when the
/// rule changes.
fn protection_padding(payload_length: usize, suite: PacketSuite) -> Vec<u8> {
    let length = PacketAlignment::for_suite(suite)
        .padding_length(payload_length)
        .expect("alignment rule must produce a padding length");
    vec![0xa5; length]
}

fn read_plain_packet(input: &mut ByteQueue) -> Result<Vec<u8>, String> {
    transport::read_unprotected_packet(input).map_err(|error| error.to_string())
}

fn take_identification(input: &mut ByteQueue) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        input
            .read_exact(&mut byte)
            .map_err(|error| error.to_string())?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n") {
            return String::from_utf8(bytes[..bytes.len() - 2].to_vec())
                .map_err(|error| error.to_string());
        }
        if bytes.len() > 255 {
            return Err("test client identification is too long".to_owned());
        }
    }
}

#[test]
fn client_rekey_uses_hybrid_old_keys_until_newkeys_and_preserves_session_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let client_proposal = proposal([0x11; 16], false);
    let config = ClientConfig::with_kexinit(client_proposal);
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    let original_session_id = transport.session_id().to_vec();
    assert!(!peer.borrow().saw_rekey);
    peer.borrow_mut().drive();

    transport.rekey()?;

    assert!(transport.is_established());
    assert!(transport.rekey_complete());
    assert!(!transport.rekey_active());
    assert_eq!(transport.session_id(), original_session_id.as_slice());
    assert!(peer.borrow().saw_rekey);

    transport.write_payload(CLIENT_PAYLOAD)?;
    peer.borrow_mut().drive();
    peer.borrow_mut().drive();
    assert_eq!(
        peer.borrow_mut().received_application.pop_front(),
        Some(CLIENT_PAYLOAD.to_vec())
    );

    peer.borrow_mut().send_application(PEER_PAYLOAD)?;
    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    Ok(())
}

#[test]
fn client_partial_protected_write_resumes_the_same_packet() -> Result<(), Box<dyn std::error::Error>>
{
    let (peer, stream) = Peer::new()?;
    let gate = Rc::new(RefCell::new(WriteGate::default()));
    let stream = GatedStream::new(stream, Rc::clone(&gate));
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |_key| Ok::<(), Infallible>(()))?;
    peer.borrow_mut().drive();
    let initial_sequence = transport.outbound_sequence();

    gate.borrow_mut().arm(3);
    assert!(matches!(
        transport.write_payload(CLIENT_PAYLOAD),
        Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(transport.outbound_sequence(), initial_sequence);

    gate.borrow_mut().open();
    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(transport.outbound_sequence(), initial_sequence + 1);
    peer.borrow_mut().drive();
    assert_eq!(
        peer.borrow_mut().received_application.pop_front(),
        Some(CLIENT_PAYLOAD.to_vec())
    );
    Ok(())
}

#[test]
fn client_rekey_resumes_split_kexinit_method_and_newkeys() -> Result<(), Box<dyn std::error::Error>>
{
    let (peer, stream) = Peer::new()?;
    let gate = Rc::new(RefCell::new(WriteGate::default()));
    let stream = GatedStream::new(stream, Rc::clone(&gate));
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |_key| Ok::<(), Infallible>(()))?;
    peer.borrow_mut().drive();
    let initial_sequence = transport.outbound_sequence();

    gate.borrow_mut().arm(3);
    assert!(matches!(
        transport.begin_rekey(),
        Err(HandshakeError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(transport.rekey_active());
    assert_eq!(transport.outbound_sequence(), initial_sequence);
    gate.borrow_mut().open();
    transport.begin_rekey()?;
    assert_eq!(transport.outbound_sequence(), initial_sequence + 1);

    gate.borrow_mut().arm(3);
    assert!(matches!(
        transport.advance_rekey(),
        Err(HandshakeError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(transport.outbound_sequence(), initial_sequence + 1);
    gate.borrow_mut().open();
    assert!(transport.advance_rekey()?);
    assert_eq!(transport.outbound_sequence(), initial_sequence + 2);

    assert!(transport.advance_rekey()?);
    assert_eq!(transport.outbound_sequence(), initial_sequence + 2);
    gate.borrow_mut().arm(3);
    assert!(matches!(
        transport.advance_rekey(),
        Err(HandshakeError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(transport.outbound_sequence(), initial_sequence + 2);
    gate.borrow_mut().open();
    assert!(transport.advance_rekey()?);
    assert_eq!(transport.outbound_sequence(), initial_sequence + 3);

    while transport.rekey_active() {
        transport.advance_rekey()?;
    }
    assert!(transport.rekey_complete());
    peer.borrow_mut().drive();
    Ok(())
}

#[test]
fn client_staged_rekey_can_be_advanced_without_blocking() -> Result<(), Box<dyn std::error::Error>>
{
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();

    transport.start_rekey()?;
    assert!(transport.rekey_active());
    assert!(matches!(
        transport.write_payload(b"blocked during rekey"),
        Err(TransportError::RekeyInProgress)
    ));
    assert!(transport.advance_rekey()?);
    assert!(transport.advance_rekey()?);
    assert!(transport.advance_rekey()?);
    assert!(transport.advance_rekey()?);
    assert!(!transport.rekey_active());
    assert!(transport.rekey_complete());
    peer.borrow_mut().drive();
    Ok(())
}

#[test]
fn strict_staged_rekey_resets_each_sequence_at_newkeys() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    {
        let mut state = peer.borrow_mut();
        state
            .server_kexinit
            .kex_algorithms
            .push(KEX_STRICT_S_V00_OPENSSH.to_owned());
        state.server_kexinit_payload = state.server_kexinit.encode()?;
    }
    let mut client_proposal = proposal([0x11; 16], false);
    client_proposal
        .kex_algorithms
        .push(KEX_STRICT_C_V00_OPENSSH.to_owned());
    let config = ClientConfig::with_kexinit(client_proposal);
    let expected_key = *peer.borrow().signer.public_key();
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();

    transport.begin_rekey()?;
    for _ in 0..4 {
        assert!(transport.advance_rekey()?);
    }
    assert_eq!(transport.inbound_sequence(), 0);
    assert_eq!(transport.outbound_sequence(), 0);
    assert!(transport.rekey_complete());
    peer.borrow_mut().drive();
    Ok(())
}

#[test]
fn client_rekey_rejects_reentrant_begin_and_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();

    transport.begin_rekey()?;
    assert!(matches!(
        transport.begin_rekey(),
        Err(HandshakeError::Transport(TransportError::Sequence(_)))
    ));
    assert!(!transport.is_established());
    assert!(transport.rekey_is_terminal());
    Ok(())
}

#[test]
fn client_rekey_rejects_a_non_hybrid_peer_and_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();
    peer.borrow_mut().rekey_algorithms = vec!["curve25519-sha256".to_owned()];

    let result = transport.rekey();
    assert!(matches!(
        result,
        Err(HandshakeError::Negotiation | HandshakeError::UnsupportedAlgorithm)
    ));
    assert!(!transport.is_established());
    assert!(transport.rekey_terminal());
    assert!(matches!(
        transport.write_payload(b"must not be sent"),
        Err(TransportError::NotEstablished)
    ));
    Ok(())
}

#[test]
fn client_peer_initiated_rekey_resumes_split_local_kexinit()
-> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    let gate = Rc::new(RefCell::new(WriteGate::default()));
    let stream = GatedStream::new(stream, Rc::clone(&gate));
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |_key| Ok::<(), Infallible>(()))?;
    peer.borrow_mut().drive();
    peer.borrow_mut().send_application_after_rekey = true;
    peer.borrow_mut().initiate_rekey()?;

    gate.borrow_mut().arm(3);
    assert!(matches!(
        transport.read_payload(),
        Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(transport.rekey_active());
    gate.borrow_mut().open();
    for _ in 0..8 {
        if !transport.rekey_active() {
            break;
        }
        transport.advance_rekey()?;
    }
    assert!(!transport.rekey_active());
    assert!(transport.rekey_complete());
    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    Ok(())
}

#[test]
fn client_read_payload_consumes_peer_initiated_rekey() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();
    let original_session_id = transport.session_id().to_vec();

    peer.borrow_mut().send_application_after_rekey = true;
    peer.borrow_mut().initiate_rekey()?;

    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    assert!(transport.is_established());
    assert!(transport.rekey_complete());
    assert_eq!(transport.session_id(), original_session_id.as_slice());
    assert!(peer.borrow().saw_rekey);
    Ok(())
}

#[test]
fn client_rekey_rejects_malformed_kexinit_and_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(proposal([0x11; 16], false));
    let mut transport = config.connect(stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    })?;
    peer.borrow_mut().drive();
    peer.borrow_mut().malformed_rekey_kexinit = true;

    assert!(matches!(transport.rekey(), Err(HandshakeError::Kex(_))));
    assert!(!transport.is_established());
    assert!(transport.rekey_terminal());
    Ok(())
}

type KexInitConstructor = (&'static str, fn([u8; 16]) -> KexInit);

#[test]
fn the_default_kexinit_constructors_complete_a_handshake() -> Result<(), Box<dyn std::error::Error>>
{
    // The public entry point is `ClientConfig::with_kexinit`, and the obvious
    // thing to hand it is one of `KexInit`'s own default constructors. Before the
    // algorithm catalogs were corrected those proposals named `rsa-sha2-512` and
    // `ecdh-sha2-nistp384`, and both handshakes refused them with
    // `UnsupportedAlgorithm`. This runs the whole exchange with each, so a
    // default that regresses to naming a mechanism this crate cannot negotiate
    // fails here rather than in a caller's handshake.
    let constructors: [KexInitConstructor; 3] = [
        ("KexInit::new", KexInit::new),
        ("KexInit::client_defaults", KexInit::client_defaults),
        ("KexInit::server_defaults", KexInit::server_defaults),
    ];
    for (label, construct) in constructors {
        let (peer, stream) = Peer::new()?;
        let expected_key = *peer.borrow().signer.public_key();
        let config = ClientConfig::with_kexinit(construct([0x11; 16]));
        let mut transport = config
            .connect(stream, |key| {
                assert_eq!(key, &expected_key);
                Ok::<(), Infallible>(())
            })
            .map_err(|error| format!("{label} could not complete a handshake: {error:?}"))?;
        peer.borrow_mut().drive();
        assert!(transport.is_established(), "{label} did not establish");

        transport.write_payload(CLIENT_PAYLOAD)?;
        peer.borrow_mut().drive();
        peer.borrow_mut().drive();
        assert_eq!(
            peer.borrow_mut().received_application.pop_front(),
            Some(CLIENT_PAYLOAD.to_vec()),
            "{label} could not carry a protected payload",
        );
    }

    // `Default` is a fourth constructor and takes no cookie argument. It builds
    // the same lists as `KexInit::new`, so it gets its own exchange to prove it.
    let (peer, stream) = Peer::new()?;
    let expected_key = *peer.borrow().signer.public_key();
    let config = ClientConfig::with_kexinit(KexInit::default());
    let mut transport = config
        .connect(stream, |key| {
            assert_eq!(key, &expected_key);
            Ok::<(), Infallible>(())
        })
        .map_err(|error| format!("KexInit::default could not complete a handshake: {error:?}"))?;
    peer.borrow_mut().drive();
    assert!(
        transport.is_established(),
        "KexInit::default did not establish"
    );
    transport.write_payload(CLIENT_PAYLOAD)?;
    peer.borrow_mut().drive();
    peer.borrow_mut().drive();
    assert_eq!(
        peer.borrow_mut().received_application.pop_front(),
        Some(CLIENT_PAYLOAD.to_vec()),
        "KexInit::default could not carry a protected payload",
    );
    Ok(())
}

#[test]
fn a_server_config_defaulted_from_kexinit_new_accepts_a_client()
-> Result<(), Box<dyn std::error::Error>> {
    // The proposal half of the same hazard, checked on its own. The full
    // client-against-server exchange for these constructors is in
    // `tests/server_transport.rs`, which can reach `ServerConfig`.
    let server = KexInit::new([0x33; 16]);
    let client = KexInit::client_defaults([0x44; 16]);
    let negotiated = client.negotiate(&server).map_err(|error| {
        format!("KexInit::new and a client default share no algorithm: {error}")
    })?;
    assert!(
        SUPPORTED_KEX_ALGORITHMS.contains(&negotiated.kex.as_str()),
        "negotiated the unsupported key exchange {}",
        negotiated.kex,
    );
    assert!(
        SUPPORTED_HOST_KEY_ALGORITHMS.contains(&negotiated.host_key.as_str()),
        "negotiated the unsupported host key {}",
        negotiated.host_key,
    );
    Ok(())
}
