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

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use cipher::{
    PacketAlignment, PacketKeyMaterial, PacketProtectionError, PacketProtector, PacketSuite,
    PlaintextDrop, PlaintextSlot, take_plaintext_drop,
};
use client::{
    CLIENT_IDENTIFICATION, ClientConfig, HandshakeError, IdentificationError, TransportError,
};
use hostkey::{Ed25519Signer, HostKeyError};
use kex::{
    Curve25519, DerivationLengths, EcdhP256, EphemeralKey, KexContext, KeyExchange, ServerKex,
    SharedSecret, derive_keys,
};
use msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256,
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH, EXT_INFO_S, HMAC_SHA2_256, HMAC_SHA2_512,
    HOST_KEY_RSA_SHA2_256, HOST_KEY_SSH_ED25519, KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_STRICT_S_V00_OPENSSH, KexInit, NegotiatedAlgorithms, SSH_MSG_KEXINIT,
};
use neotales_ssh::{build_packet_default, decode_packet};
use sequence::SequenceState;

const SERVER_VERSION: &str = "SSH-2.0-neotales-ssh-test-peer";
const PRE_BANNER: &[u8] = b"legal pre-banner\r\n\r\n";
const CLIENT_PAYLOAD: &[u8] = &[80, b'c', b'l', b'i', b'e', b'n', b't'];
const PEER_PAYLOAD: &[u8] = &[81, b'p', b'e', b'e', b'r'];
const SSH_MSG_DEBUG: u8 = 3;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEX_ECDH_INIT: u8 = 30;

#[test]
fn strict_handshake_retains_session_id_and_exchanges_protected_payloads()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        7,
        PRE_BANNER,
        None,
    )?;
    let expected_public = *peer.signer().public_key();
    let mut transport = config.connect(peer.client_stream.clone(), |key| {
        assert_eq!(key, &expected_public);
        Ok::<(), Infallible>(())
    })?;
    peer.accept_client_newkeys()?;

    assert!(transport.is_established());
    assert!(transport.initial_kex_complete());
    assert!(transport.strict_kex());
    assert_eq!(transport.inbound_sequence(), 0);
    assert_eq!(transport.outbound_sequence(), 0);
    assert_eq!(transport.session_id(), peer.exchange_hash().as_ref());
    assert_eq!(
        transport
            .verified_host_key()
            .map(|verified| *verified.public_key()),
        Some(expected_public)
    );

    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    peer.write_client_payload(PEER_PAYLOAD, false)?;
    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    assert_eq!(transport.inbound_sequence(), 1);
    assert_eq!(transport.outbound_sequence(), 1);
    Ok(())
}

#[test]
fn every_supported_kex_and_packet_suite_derives_valid_directional_material()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        (ENCRYPTION_CHACHA20_POLY1305_OPENSSH, HMAC_SHA2_256),
        (AES128_CTR, HMAC_SHA2_256),
        (AES256_CTR, HMAC_SHA2_512),
        (AES128_GCM_OPENSSH, HMAC_SHA2_256),
        (AES256_GCM_OPENSSH, HMAC_SHA2_512),
    ];
    let mechanisms = [
        CURVE25519_SHA256,
        CURVE25519_SHA256_LIBSSH,
        ECDH_SHA2_NISTP256,
    ];
    let mut seed = 20_u8;

    for kex in mechanisms {
        for (cipher, mac) in variants {
            seed = seed.wrapping_add(1);
            let (mut peer, config) =
                peer_and_config(kex, cipher, cipher, mac, mac, true, seed, PRE_BANNER, None)?;
            let mut transport =
                config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
            peer.accept_client_newkeys()?;
            assert_eq!(transport.session_id(), peer.exchange_hash().as_ref());
            assert_protection_lengths(cipher, mac);
            transport.write_payload(CLIENT_PAYLOAD)?;
            assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
            peer.write_client_payload(PEER_PAYLOAD, false)?;
            assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
        }
    }
    Ok(())
}

#[test]
fn non_strict_initial_kex_preserves_both_counters() -> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        false,
        41,
        PRE_BANNER,
        None,
    )?;
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;

    assert!(!transport.strict_kex());
    assert_eq!(transport.inbound_sequence(), 3);
    assert_eq!(transport.outbound_sequence(), 3);
    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    peer.write_client_payload(PEER_PAYLOAD, false)?;
    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    assert_eq!(transport.inbound_sequence(), 4);
    assert_eq!(transport.outbound_sequence(), 4);
    Ok(())
}

#[test]
fn bounded_identification_accepts_legal_banner_and_rejects_oversize_or_missing()
-> Result<(), Box<dyn std::error::Error>> {
    {
        let (mut peer, config) = peer_and_config(
            CURVE25519_SHA256,
            AES128_CTR,
            AES128_CTR,
            HMAC_SHA2_256,
            HMAC_SHA2_256,
            true,
            51,
            &maximum_pre_banner(),
            None,
        )?;
        let result = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()));
        assert!(
            result.is_ok(),
            "maximum legal pre-banner was not accepted: {result:?}"
        );
        peer.accept_client_newkeys()?;
    }
    {
        let (client, mut server, _queues) = duplex_pair();
        server
            .write_all(&oversized_pre_banner())
            .expect("test stream is writable");
        let result = ClientConfig::new().connect(client, |_key| Ok::<(), Infallible>(()));
        assert!(
            matches!(
                result,
                Err(HandshakeError::Transport(TransportError::Identification(
                    IdentificationError::PreBannerTooLong
                )))
            ),
            "oversized pre-banner produced unexpected error: {result:?}"
        );
    }
    {
        let (client, _server, _queues) = duplex_pair();
        let result = ClientConfig::new().connect(client, |_key| Ok::<(), Infallible>(()));
        assert!(matches!(
            result,
            Err(HandshakeError::Transport(TransportError::Identification(
                IdentificationError::MissingVersion
            )))
        ));
    }
    Ok(())
}

#[test]
fn overlong_identification_line_is_rejected_before_packet_io() {
    let (client, mut server, _queues) = duplex_pair();
    server
        .write_all(&vec![b'x'; 255])
        .expect("in-memory stream accepts the fixed banner");
    let result = ClientConfig::new().connect(client, |_key| Ok::<(), Infallible>(()));
    assert!(matches!(
        result,
        Err(HandshakeError::Transport(TransportError::Identification(
            IdentificationError::LineTooLong
        )))
    ));
}

#[test]
fn malformed_and_incompatible_kexinit_fail_without_starting_kex()
-> Result<(), Box<dyn std::error::Error>> {
    {
        let (peer, config) = peer_and_config(
            CURVE25519_SHA256,
            AES128_CTR,
            AES128_CTR,
            HMAC_SHA2_256,
            HMAC_SHA2_256,
            true,
            61,
            PRE_BANNER,
            Some(&[SSH_MSG_KEXINIT]),
        )?;
        let result = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()));
        assert!(
            matches!(
                result,
                Err(HandshakeError::Kex(kex::KexError::Wire(
                    neotales_ssh::Error::Truncated
                )))
            ),
            "malformed KEXINIT produced unexpected error: {result:?}"
        );
        assert_eq!(peer.client_packet_types(), [SSH_MSG_KEXINIT]);
    }
    {
        let mut proposal = proposal(
            CURVE25519_SHA256,
            AES128_CTR,
            AES128_CTR,
            HMAC_SHA2_256,
            HMAC_SHA2_256,
            true,
        );
        proposal.encryption_algorithms_client_to_server = vec!["aes192-ctr".to_owned()];
        proposal.encryption_algorithms_server_to_client = vec!["aes192-ctr".to_owned()];
        let (peer, config) =
            custom_peer_and_config(proposal, CURVE25519_SHA256, 62, PRE_BANNER, None)?;
        let result = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()));
        assert!(matches!(result, Err(HandshakeError::Negotiation)));
        assert_eq!(peer.client_packet_types(), [SSH_MSG_KEXINIT]);
    }
    {
        let mut proposal = proposal(
            CURVE25519_SHA256,
            AES128_CTR,
            AES128_CTR,
            HMAC_SHA2_256,
            HMAC_SHA2_256,
            true,
        );
        proposal.server_host_key_algorithms = vec![HOST_KEY_RSA_SHA2_256.to_owned()];
        let (peer, config) =
            custom_peer_and_config(proposal, CURVE25519_SHA256, 63, PRE_BANNER, None)?;
        let result = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()));
        assert!(matches!(result, Err(HandshakeError::Negotiation)));
    }
    Ok(())
}

#[test]
fn host_key_rejection_and_bad_signature_never_send_client_newkeys()
-> Result<(), Box<dyn std::error::Error>> {
    let expected_signer = signer(71);
    let expected_key = *expected_signer.public_key();
    let (peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        72,
        PRE_BANNER,
        None,
    )?;
    let result = config.connect(peer.client_stream.clone(), |key| {
        if key == &expected_key {
            Ok(())
        } else {
            Err(PolicyRejected)
        }
    });
    assert!(matches!(
        result,
        Err(HandshakeError::HostKey(HostKeyError::TrustRejected))
    ));
    assert_eq!(
        peer.client_packet_types(),
        [SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT]
    );

    let (peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        73,
        PRE_BANNER,
        None,
    )?;
    peer.state.borrow_mut().corrupted_signature = true;
    let result = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()));
    assert!(matches!(
        result,
        Err(HandshakeError::HostKey(HostKeyError::InvalidSignature))
    ));
    assert_eq!(
        peer.client_packet_types(),
        [SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT]
    );
    Ok(())
}

#[test]
fn strict_guessed_kexinit_and_ignorable_packet_obey_initial_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let mut guessed = proposal(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
    );
    guessed.first_kex_packet_follows = true;
    let (peer, config) = custom_peer_and_config(guessed, CURVE25519_SHA256, 81, PRE_BANNER, None)?;
    let transport = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    assert!(transport.strict_kex());

    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        false,
        82,
        PRE_BANNER,
        None,
    )?;
    peer.insert_server_ignorable()?;
    let transport = config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;
    assert!(!transport.strict_kex());
    assert_eq!(transport.inbound_sequence(), 4);
    assert_eq!(transport.outbound_sequence(), 3);
    Ok(())
}

#[test]
fn tampered_first_protected_packet_returns_no_plaintext_and_does_not_commit_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        AES128_CTR,
        AES128_CTR,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        91,
        PRE_BANNER,
        None,
    )?;
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;

    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    peer.write_client_payload(PEER_PAYLOAD, true)?;
    assert!(matches!(
        transport.read_payload(),
        Err(TransportError::PacketProtection(
            PacketProtectionError::AuthenticationFailed
        ))
    ));
    assert_eq!(transport.inbound_sequence(), 0);
    Ok(())
}

#[test]
fn chacha_handshake_protects_application_data_and_fails_closed_on_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        92,
        PRE_BANNER,
        None,
    )?;
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;

    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    peer.write_client_payload(PEER_PAYLOAD, true)?;
    assert!(matches!(
        transport.read_payload(),
        Err(TransportError::PacketProtection(
            PacketProtectionError::AuthenticationFailed
        ))
    ));
    assert_eq!(transport.inbound_sequence(), 0);
    Ok(())
}

#[test]
fn chacha_handshake_allows_empty_mac_lists() -> Result<(), Box<dyn std::error::Error>> {
    let mut client_proposal = proposal(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
    );
    client_proposal.mac_algorithms_client_to_server.clear();
    client_proposal.mac_algorithms_server_to_client.clear();
    let (mut peer, _default_config) = custom_peer_and_config(
        client_proposal.clone(),
        CURVE25519_SHA256,
        95,
        PRE_BANNER,
        None,
    )?;
    let config = ClientConfig::with_kexinit(client_proposal);
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;

    let negotiated = peer.state.borrow().negotiated.clone();
    assert!(negotiated.mac_client_to_server.is_empty());
    assert!(negotiated.mac_server_to_client.is_empty());
    assert_eq!(
        PacketSuite::new(ENCRYPTION_CHACHA20_POLY1305_OPENSSH, None)?.integrity_name(),
        None
    );
    transport.write_payload(CLIENT_PAYLOAD)?;
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    peer.write_client_payload(PEER_PAYLOAD, false)?;
    assert_eq!(transport.read_payload()?, PEER_PAYLOAD);
    Ok(())
}

#[test]
fn chacha_corrupted_length_does_not_commit_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        94,
        PRE_BANNER,
        None,
    )?;
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;
    peer.write_client_payload_with_length_tamper(PEER_PAYLOAD)?;
    assert!(transport.read_payload().is_err());
    assert_eq!(transport.inbound_sequence(), 0);
    Ok(())
}

#[test]
fn partial_aes_ctr_and_chacha_reads_resume_without_advancing_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    for (cipher, seed) in [
        (AES128_CTR, 101_u8),
        (ENCRYPTION_CHACHA20_POLY1305_OPENSSH, 102_u8),
        (AES128_GCM_OPENSSH, 103_u8),
    ] {
        let (mut peer, config) = peer_and_config(
            CURVE25519_SHA256,
            cipher,
            cipher,
            HMAC_SHA2_256,
            HMAC_SHA2_256,
            true,
            seed,
            PRE_BANNER,
            None,
        )?;
        let gate = Rc::new(RefCell::new(ChunkGate::default()));
        let stream = ChunkedStream::new(peer.client_stream.clone(), Rc::clone(&gate));
        let mut transport = config.connect(stream, |_key| Ok::<(), Infallible>(()))?;
        peer.accept_client_newkeys()?;
        peer.write_client_payload(PEER_PAYLOAD, false)?;
        peer.write_client_payload(CLIENT_PAYLOAD, false)?;

        gate.borrow_mut().arm(3);
        let payload = finish_split_read(&mut transport, &gate, 0)?;
        assert_eq!(payload, PEER_PAYLOAD);
        assert_eq!(transport.inbound_sequence(), 1);
        gate.borrow_mut().release(3);
        let payload = finish_split_read(&mut transport, &gate, 1)?;
        assert_eq!(payload, CLIENT_PAYLOAD);
        assert_eq!(transport.inbound_sequence(), 2);
    }
    Ok(())
}

fn finish_split_read<S>(
    transport: &mut client::ClientTransport<S>,
    gate: &Rc<RefCell<ChunkGate>>,
    expected_sequence: u32,
) -> Result<Vec<u8>, TransportError>
where
    S: Read + Write,
{
    for _ in 0..64 {
        match transport.read_payload() {
            Ok(payload) => return Ok(payload),
            Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                assert_eq!(transport.inbound_sequence(), expected_sequence);
                gate.borrow_mut().release(3);
            }
            Err(error) => return Err(error),
        }
    }
    Err(TransportError::InvalidMessage)
}

#[derive(Default)]
struct ChunkGate {
    active: bool,
    remaining: usize,
}

impl ChunkGate {
    fn arm(&mut self, length: usize) {
        self.active = true;
        self.remaining = length;
    }

    fn release(&mut self, length: usize) {
        self.remaining = length;
    }
}

struct ChunkedStream<S> {
    inner: S,
    gate: Rc<RefCell<ChunkGate>>,
}

impl<S> ChunkedStream<S> {
    fn new(inner: S, gate: Rc<RefCell<ChunkGate>>) -> Self {
        Self { inner, gate }
    }
}

impl<S> Read for ChunkedStream<S>
where
    S: Read,
{
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        let allowed = {
            let gate = self.gate.borrow();
            if !gate.active {
                None
            } else if gate.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "test packet chunk is waiting for release",
                ));
            } else {
                Some(gate.remaining)
            }
        };
        let Some(allowed) = allowed else {
            return self.inner.read(target);
        };
        let length = allowed.min(target.len());
        let count = self.inner.read(&mut target[..length])?;
        if count != 0 {
            self.gate.borrow_mut().remaining -= count;
        }
        Ok(count)
    }
}

impl<S> Write for ChunkedStream<S>
where
    S: Write,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn chacha_live_wire_has_only_encrypted_length_body_and_tag()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = peer_and_config(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        HMAC_SHA2_256,
        true,
        93,
        PRE_BANNER,
        None,
    )?;
    let mut transport =
        config.connect(peer.client_stream.clone(), |_key| Ok::<(), Infallible>(()))?;
    peer.accept_client_newkeys()?;
    transport.write_payload(CLIENT_PAYLOAD)?;

    let raw: Vec<u8> = peer.client_to_server.borrow().iter().copied().collect();
    let packet_length = {
        let state = peer.state.borrow();
        let protector = state
            .read_protector
            .as_ref()
            .ok_or("test peer has no read protector")?;
        protector.decrypt_length(0, raw.get(..4).ok_or("missing encrypted length")?)?
    };
    let packet_length = usize::try_from(packet_length)?;
    let clear_length_bytes = u32::try_from(packet_length)?.to_be_bytes();
    assert_eq!(raw.len(), 4 + packet_length + 16);
    // `packet_length` is the aligned quantity under an AEAD; the four-byte
    // length field is authenticated but not encrypted, so it is not part of
    // the ciphertext. This used to assert `(4 + packet_length) % 8 == 0`.
    assert_eq!(packet_length % 8, 0);
    assert_eq!((4 + packet_length) % 8, 4);
    assert_ne!(raw.get(..4), Some(clear_length_bytes.as_slice()));
    assert_eq!(peer.read_client_payload()?, CLIENT_PAYLOAD);
    Ok(())
}

#[test]
fn chacha_length_bounds_and_corrupt_lengths_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let chacha = PacketSuite::new(ENCRYPTION_CHACHA20_POLY1305_OPENSSH, None)?;
    let alignment = PacketAlignment::for_suite(chacha);
    assert!(matches!(
        transport::validate_chacha_packet_length(alignment, 4),
        Err(PacketProtectionError::InvalidPacket)
    ));
    // `packet_length` itself must sit on the eight-byte boundary. The
    // four-byte length field is authenticated but not encrypted under an AEAD,
    // so it is not part of the aligned ciphertext. Accepting 12 here is what
    // made a real OpenSSH server answer `padding error: need 28 block 8 mod 4`.
    assert!(matches!(
        transport::validate_chacha_packet_length(alignment, 12),
        Err(PacketProtectionError::InvalidAlignment)
    ));
    assert!(matches!(
        transport::validate_chacha_packet_length(alignment, MAX_PACKET_CONTENT + 2),
        Err(PacketProtectionError::LimitExceeded)
    ));
    assert_eq!(
        transport::validate_chacha_packet_length(alignment, 16)?,
        (20, 36)
    );

    let suite = chacha;
    let key = vec![0x44_u8; 64];
    let iv = [0_u8; 8];
    let mut sender = PacketProtector::new(suite, PacketKeyMaterial::new(&iv, &key, None))?;
    let mut receiver = PacketProtector::new(suite, PacketKeyMaterial::new(&iv, &key, None))?;
    let padding = protection_padding(CLIENT_PAYLOAD.len(), suite);
    let packet = sender.seal(7, CLIENT_PAYLOAD, &padding)?;
    let mut damaged_length = packet.clone();
    damaged_length[0] ^= 1;
    let mut damaged_stream = Cursor::new(damaged_length);
    assert!(
        transport::read_chacha_payload(&mut damaged_stream, &mut receiver, 7).is_err(),
        "a corrupted encrypted length must fail closed"
    );

    let small_clear_length = u32::try_from(CLIENT_PAYLOAD.len() + padding.len() + 1)?.to_be_bytes();
    let small_encrypted_length: [u8; 4] = packet
        .get(..4)
        .ok_or(PacketProtectionError::InvalidPacket)?
        .try_into()?;
    let length_keystream: [u8; 4] =
        std::array::from_fn(|index| small_clear_length[index] ^ small_encrypted_length[index]);
    let excessive_clear_length = u32::try_from(MAX_PACKET_CONTENT + 2)?.to_be_bytes();
    let excessive_encrypted_length: [u8; 4] =
        std::array::from_fn(|index| excessive_clear_length[index] ^ length_keystream[index]);
    let mut excessive_stream = Cursor::new(excessive_encrypted_length.to_vec());
    assert!(matches!(
        transport::read_chacha_payload(&mut excessive_stream, &mut receiver, 7),
        Err(TransportError::PacketProtection(
            PacketProtectionError::LimitExceeded
        ))
    ));
    assert_eq!(excessive_stream.position(), 4);

    // A clear packet that is correctly aligned but declares a padding-length
    // byte of zero, so the padding check is what rejects it. The body has to
    // stay on the eight-byte boundary or the alignment check fires first.
    let mut malformed_clear = Vec::new();
    let malformed_body_size = CLIENT_PAYLOAD.len() + 9;
    malformed_clear.extend_from_slice(&u32::try_from(malformed_body_size)?.to_be_bytes());
    malformed_clear.push(0);
    malformed_clear.extend_from_slice(CLIENT_PAYLOAD);
    malformed_clear.extend_from_slice(&[0xa5; 8]);
    let malformed =
        neotales_ssh::chacha_cipher::ChaChaCipher::new(&key)?.seal(7, &malformed_clear)?;
    assert!(matches!(
        receiver.open(7, &malformed),
        Err(PacketProtectionError::InvalidPadding)
    ));

    // A clear packet that is not on the eight-byte boundary is rejected before
    // the padding is even looked at. This is the shape that made a real
    // OpenSSH server answer `padding error: need 28 block 8 mod 4`.
    let mut misaligned_clear = Vec::new();
    misaligned_clear.extend_from_slice(&u32::try_from(CLIENT_PAYLOAD.len() + 4 + 1)?.to_be_bytes());
    misaligned_clear.push(4);
    misaligned_clear.extend_from_slice(CLIENT_PAYLOAD);
    misaligned_clear.extend_from_slice(&[0xa5; 4]);
    let misaligned =
        neotales_ssh::chacha_cipher::ChaChaCipher::new(&key)?.seal(7, &misaligned_clear)?;
    assert!(matches!(
        receiver.open(7, &misaligned),
        Err(PacketProtectionError::InvalidAlignment)
    ));

    let mut extra = packet;
    extra.push(0);
    assert!(receiver.open(7, &extra).is_err());
    Ok(())
}

#[test]
fn direct_chacha_protector_checks_key_length_sequence_and_rekey()
-> Result<(), Box<dyn std::error::Error>> {
    let suite = PacketSuite::new(ENCRYPTION_CHACHA20_POLY1305_OPENSSH, None)?;
    let key = vec![0x11_u8; 64];
    let iv = [0_u8; 8];
    let mut sender = PacketProtector::new(suite, PacketKeyMaterial::new(&iv, &key, None))?;
    let mut receiver = PacketProtector::new(suite, PacketKeyMaterial::new(&iv, &key, None))?;
    let padding = vec![0x5a_u8; protection_padding(CLIENT_PAYLOAD.len(), suite).len()];
    let packet = sender.seal(3, CLIENT_PAYLOAD, &padding)?;
    let mut clear = Vec::new();
    clear
        .extend_from_slice(&u32::try_from(CLIENT_PAYLOAD.len() + padding.len() + 1)?.to_be_bytes());
    clear.push(u8::try_from(padding.len())?);
    clear.extend_from_slice(CLIENT_PAYLOAD);
    clear.extend_from_slice(&padding);
    let expected = neotales_ssh::chacha_cipher::ChaChaCipher::new(&key)?.seal(3, &clear)?;
    assert_eq!(packet, expected);
    assert_eq!(receiver.open(3, &packet)?, CLIENT_PAYLOAD);
    assert!(matches!(
        receiver.open(4, &packet),
        Err(PacketProtectionError::AuthenticationFailed)
    ));
    assert_eq!(
        PacketProtector::new(suite, PacketKeyMaterial::new(&[0; 7], &key, None)).err(),
        Some(PacketProtectionError::InvalidKeyMaterial)
    );
    assert_eq!(
        PacketProtector::new(suite, PacketKeyMaterial::new(&iv, &key[..63], None)).err(),
        Some(PacketProtectionError::InvalidKeyMaterial)
    );

    let new_key = vec![0x22_u8; 64];
    sender.rekey(suite, PacketKeyMaterial::new(&iv, &new_key, None))?;
    receiver.rekey(suite, PacketKeyMaterial::new(&iv, &new_key, None))?;
    let replacement = sender.seal(4, CLIENT_PAYLOAD, &padding)?;
    assert_eq!(receiver.open(4, &replacement)?, CLIENT_PAYLOAD);
    let debug = format!("{sender:?}");
    assert!(!debug.contains("1111111111111111"));
    Ok(())
}

#[test]
fn default_proposal_advertises_only_implemented_mechanisms_and_required_categories() {
    let proposal = ClientConfig::new();
    let kexinit = proposal.kexinit();
    assert_eq!(
        kexinit.kex_algorithms,
        [
            "mlkem768x25519-sha256",
            CURVE25519_SHA256,
            CURVE25519_SHA256_LIBSSH,
            ECDH_SHA2_NISTP256,
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
            sequence::KEX_STRICT_C_V00_OPENSSH,
        ]
        .map(str::to_owned)
    );
    assert_eq!(kexinit.server_host_key_algorithms, [HOST_KEY_SSH_ED25519]);
    assert_eq!(
        kexinit.compression_algorithms_client_to_server,
        [COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH]
    );
    assert_eq!(
        kexinit.compression_algorithms_server_to_client,
        [COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH]
    );
    assert!(
        kexinit
            .encryption_algorithms_client_to_server
            .contains(&ENCRYPTION_CHACHA20_POLY1305_OPENSSH.to_owned())
    );
    assert!(
        kexinit
            .encryption_algorithms_server_to_client
            .contains(&ENCRYPTION_CHACHA20_POLY1305_OPENSSH.to_owned())
    );
    assert!(
        kexinit
            .encryption_algorithms_client_to_server
            .contains(&AES128_CTR.to_owned())
    );
    assert!(
        kexinit
            .encryption_algorithms_server_to_client
            .contains(&AES128_CTR.to_owned())
    );
    assert!(
        kexinit
            .mac_algorithms_client_to_server
            .contains(&HMAC_SHA2_256.to_owned())
    );
    assert!(
        kexinit
            .mac_algorithms_server_to_client
            .contains(&HMAC_SHA2_256.to_owned())
    );
}

struct PolicyRejected;

impl KeyExchange for Box<dyn KeyExchange> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn generate_ephemeral(&self) -> Result<EphemeralKey, kex::KexError> {
        (**self).generate_ephemeral()
    }

    fn public_key(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, kex::KexError> {
        (**self).public_key(ephemeral)
    }

    fn encode_init_message(&self, ephemeral: &EphemeralKey) -> Result<Vec<u8>, kex::KexError> {
        (**self).encode_init_message(ephemeral)
    }

    fn decode_init_message(&self, input: &[u8]) -> Result<Vec<u8>, kex::KexError> {
        (**self).decode_init_message(input)
    }

    fn encode_reply_message(
        &self,
        server_public_key: &[u8],
        host_key_blob: &[u8],
        signature_blob: &[u8],
    ) -> Result<Vec<u8>, kex::KexError> {
        (**self).encode_reply_message(server_public_key, host_key_blob, signature_blob)
    }

    fn decode_reply_message(&self, input: &[u8]) -> Result<kex::KexReply, kex::KexError> {
        (**self).decode_reply_message(input)
    }

    fn agree(
        &self,
        ephemeral: EphemeralKey,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, kex::KexError> {
        (**self).agree(ephemeral, peer_public_key)
    }
}

type Responder = Rc<RefCell<dyn FnMut(Vec<u8>) -> Vec<u8>>>;

#[derive(Clone)]
struct Stream {
    input: Rc<RefCell<VecDeque<u8>>>,
    output: Rc<RefCell<VecDeque<u8>>>,
    responder: Option<Responder>,
}

impl Read for Stream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        if self.input.borrow().is_empty() {
            if self.responder.is_none() {
                return Ok(0);
            }
            self.generate_response();
        }
        let mut input = self.input.borrow_mut();
        if input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory peer has not produced the next byte",
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

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.borrow_mut().extend(bytes.iter().copied());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream {
    fn generate_response(&mut self) {
        let Some(responder) = &self.responder else {
            return;
        };
        let client_bytes: Vec<u8> = self.output.borrow().iter().copied().collect();
        let response = responder.borrow_mut()(client_bytes);
        self.input.borrow_mut().extend(response);
    }
}

struct TestPeer {
    client_stream: Stream,
    stream: Stream,
    state: Rc<RefCell<PeerState>>,
    client_to_server: Rc<RefCell<VecDeque<u8>>>,
}

impl TestPeer {
    fn signer(&self) -> std::cell::Ref<'_, Ed25519Signer> {
        std::cell::Ref::map(self.state.borrow(), |state| &state.signer)
    }

    fn exchange_hash(&self) -> [u8; 32] {
        self.state.borrow().exchange_hash
    }

    fn accept_client_newkeys(&mut self) -> Result<(), String> {
        self.discard_client_identification()?;
        let kexinit = read_plain_packet(&mut self.stream)
            .map_err(|error| format!("failed to read client KEXINIT: {error}"))?;
        assert_eq!(kexinit.first(), Some(&SSH_MSG_KEXINIT));
        let init = read_plain_packet(&mut self.stream)
            .map_err(|error| format!("failed to read client KEX method: {error}"))?;
        assert_eq!(init.first(), Some(&SSH_MSG_KEX_ECDH_INIT));
        let payload = read_plain_packet(&mut self.stream)
            .map_err(|error| format!("failed to read client NEWKEYS: {error}"))?;
        if payload != [SSH_MSG_NEWKEYS] {
            return Err("test peer expected client NEWKEYS".to_owned());
        }
        let mut state = self.state.borrow_mut();
        state.accept_inbound(SSH_MSG_NEWKEYS)?;
        state
            .sequence
            .complete_initial_kex()
            .map_err(|error| error.to_string())
    }

    fn insert_server_ignorable(&mut self) -> Result<(), String> {
        let packet =
            self.state
                .borrow_mut()
                .record_plain_outbound(&[SSH_MSG_DEBUG, 0, 0, 0, 0, 0, 0, 0])?;
        self.stream
            .write_all(&packet)
            .map_err(|error| error.to_string())
    }

    fn read_client_payload(&mut self) -> Result<Vec<u8>, String> {
        let mut state = self.state.borrow_mut();
        let sequence = state.sequence.inbound_sequence();
        let suite = state.read_suite;
        let protector = state
            .read_protector
            .as_mut()
            .ok_or_else(|| "test peer has no read protector".to_owned())?;
        let payload = if suite.is_chacha() {
            transport::read_chacha_payload(&mut self.stream, protector, sequence)
                .map_err(|error| format!("failed to read protected client payload: {error}"))?
        } else if PacketAlignment::for_suite(suite).aligns_packet_length() {
            let packet = read_protected_packet(&mut self.stream, suite)
                .map_err(|error| format!("failed to read protected client payload: {error}"))?;
            protector
                .open(sequence, &packet)
                .map_err(|error| error.to_string())?
        } else {
            read_eam_test_payload(&mut self.stream, protector, sequence)?
        };
        state
            .sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        Ok(payload)
    }

    fn write_client_payload(&mut self, payload: &[u8], tamper: bool) -> Result<(), String> {
        self.write_client_payload_inner(payload, tamper, false)
    }

    fn write_client_payload_with_length_tamper(&mut self, payload: &[u8]) -> Result<(), String> {
        self.write_client_payload_inner(payload, false, true)
    }

    fn write_client_payload_inner(
        &mut self,
        payload: &[u8],
        tamper: bool,
        length_tamper: bool,
    ) -> Result<(), String> {
        let mut state = self.state.borrow_mut();
        let sequence = state.sequence.outbound_sequence();
        let padding = protection_padding(payload.len(), state.write_suite);
        let protector = state
            .write_protector
            .as_mut()
            .ok_or_else(|| "test peer has no write protector".to_owned())?;
        let mut packet = protector
            .seal(sequence, payload, &padding)
            .map_err(|error| error.to_string())?;
        if length_tamper {
            let first = packet
                .first_mut()
                .ok_or_else(|| "protected packet has no encrypted length".to_owned())?;
            *first ^= 1;
        } else if tamper {
            let last = packet
                .len()
                .checked_sub(1)
                .ok_or_else(|| "protected packet has no authentication tag".to_owned())?;
            packet[last] ^= 1;
        }
        self.stream
            .write_all(&packet)
            .map_err(|error| error.to_string())?;
        state
            .sequence
            .commit_outbound()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn discard_client_identification(&mut self) -> Result<(), String> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            read_exact(&mut self.stream, &mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                assert_eq!(
                    line.get(..line.len().saturating_sub(2)),
                    Some(CLIENT_IDENTIFICATION.as_bytes())
                );
                return Ok(());
            }
            if line.len() > 255 {
                return Err("test client sent an overlong identification".to_owned());
            }
        }
    }

    fn client_packet_types(&self) -> Vec<u8> {
        let bytes: Vec<u8> = self.client_to_server.borrow().iter().copied().collect();
        let mut remaining = bytes.as_slice();
        let _version =
            take_identification(&mut remaining).expect("test client sent an identification");
        let mut types = Vec::new();
        while !remaining.is_empty() {
            let payload =
                take_plain_payload(&mut remaining).expect("test client sent whole packets");
            types.push(payload[0]);
        }
        types
    }
}

struct PeerState {
    proposal: KexInit,
    mechanism: Option<Box<dyn KeyExchange>>,
    server_kex: Option<ServerKex<Box<dyn KeyExchange>>>,
    sequence: SequenceState,
    signer: Ed25519Signer,
    host_key_blob: Vec<u8>,
    negotiated: NegotiatedAlgorithms,
    exchange_hash: [u8; 32],
    write_suite: PacketSuite,
    read_suite: PacketSuite,
    write_protector: Option<PacketProtector>,
    read_protector: Option<PacketProtector>,
    corrupted_signature: bool,
    response_sent: bool,
}

impl PeerState {
    fn new(
        proposal: KexInit,
        mechanism: Box<dyn KeyExchange>,
        seed: u8,
        corrupted_signature: bool,
    ) -> Result<Self, String> {
        let signer = signer(seed);
        let host_key_blob = signer
            .public_key_blob()
            .map_err(|error| error.to_string())?;
        let write_suite =
            PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256)).map_err(|error| error.to_string())?;
        let read_suite = write_suite;
        Ok(Self {
            proposal,
            mechanism: Some(mechanism),
            server_kex: None,
            sequence: SequenceState::new(),
            signer,
            host_key_blob,
            negotiated: NegotiatedAlgorithms::new("", "", "", "", "", "", "", ""),
            exchange_hash: [0; 32],
            write_suite,
            read_suite,
            write_protector: None,
            read_protector: None,
            corrupted_signature,
            response_sent: false,
        })
    }

    fn initial_server_bytes(
        &mut self,
        pre_banner: &[u8],
        raw_kexinit: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        let mut bytes = pre_banner.to_vec();
        bytes.extend_from_slice(SERVER_VERSION.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        let payload = match raw_kexinit {
            Some(payload) => payload.to_vec(),
            None => self.proposal.encode().map_err(|error| error.to_string())?,
        };
        bytes.extend_from_slice(&self.record_plain_outbound(&payload)?);
        Ok(bytes)
    }

    fn drive(&mut self, client_bytes: &[u8]) -> Vec<u8> {
        if self.response_sent {
            return Vec::new();
        }
        self.response_sent = true;
        let mut remaining = client_bytes;
        let version =
            take_identification(&mut remaining).expect("client identification is complete");
        assert_eq!(version, CLIENT_IDENTIFICATION);
        let client_kexinit =
            take_plain_payload(&mut remaining).expect("client KEXINIT is complete");
        self.accept_client_kexinit(&client_kexinit)
            .expect("test client KEXINIT is valid");
        let init =
            take_plain_payload(&mut remaining).expect("client KEX method message is complete");
        assert_eq!(init.first(), Some(&SSH_MSG_KEX_ECDH_INIT));
        self.accept_inbound(SSH_MSG_KEX_ECDH_INIT)
            .expect("client KEX method message is ordered");
        let completion = {
            let server = self
                .server_kex
                .as_mut()
                .expect("server KEX role was initialized");
            server
                .accept_init(&init)
                .expect("test server accepts client KEX");
            server
                .prepare_exchange()
                .expect("test server computes its exchange")
                .clone()
        };
        let signature = self
            .signer
            .sign_exchange_hash(completion.exchange_hash())
            .expect("test signer produces a signature");
        let mut reply = self
            .server_kex
            .as_mut()
            .expect("server KEX role remains available")
            .reply_message(&signature)
            .expect("test server encodes its reply");
        if self.corrupted_signature {
            let last = reply.len() - 1;
            reply[last] ^= 1;
        }
        self.install_protection(&completion)
            .expect("test peer derives packet protection");
        self.exchange_hash = *completion.exchange_hash();
        let reply_packet = self
            .record_plain_outbound(&reply)
            .expect("server reply is ordered");
        let newkeys_packet = self
            .record_plain_outbound(&[SSH_MSG_NEWKEYS])
            .expect("server NEWKEYS is ordered");
        let mut response = reply_packet;
        response.extend_from_slice(&newkeys_packet);
        response
    }

    fn accept_client_kexinit(&mut self, payload: &[u8]) -> Result<(), String> {
        let client = KexInit::decode(payload).map_err(|error| error.to_string())?;
        self.negotiated = client
            .negotiate(&self.proposal)
            .map_err(|error| error.to_string())?;
        self.sequence
            .set_strict_kex(client.strict_kex_enabled(&self.proposal))
            .map_err(|error| error.to_string())?;
        self.accept_inbound(SSH_MSG_KEXINIT)?;
        let context = KexContext::new(
            CLIENT_IDENTIFICATION,
            SERVER_VERSION,
            client.encode().map_err(|error| error.to_string())?,
            self.proposal.encode().map_err(|error| error.to_string())?,
            &self.negotiated.kex,
        )
        .map_err(|error| error.to_string())?;
        let mechanism = self
            .mechanism
            .take()
            .ok_or_else(|| "test mechanism was already consumed".to_owned())?;
        self.server_kex = Some(
            ServerKex::new(mechanism, context, &self.host_key_blob)
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    fn install_protection(&mut self, completion: &kex::KexCompletion) -> Result<(), String> {
        self.write_suite = suite_for(
            &self.negotiated.cipher_client_to_server,
            &self.negotiated.mac_client_to_server,
        )?;
        self.read_suite = suite_for(
            &self.negotiated.cipher_server_to_client,
            &self.negotiated.mac_server_to_client,
        )?;
        let lengths = DerivationLengths {
            a: iv_length(self.read_suite),
            b: iv_length(self.write_suite),
            c: encryption_key_length(self.read_suite)?,
            d: encryption_key_length(self.write_suite)?,
            e: integrity_key_length(self.read_suite),
            f: integrity_key_length(self.write_suite),
        };
        let derived = derive_keys(
            completion.shared_secret(),
            completion.exchange_hash(),
            completion.session_id(),
            lengths,
        )
        .map_err(|error| error.to_string())?;
        self.write_protector = Some(new_test_protector(
            self.write_suite,
            material_for(
                self.write_suite,
                &derived.iv_server_to_client,
                &derived.encryption_key_server_to_client,
                &derived.integrity_key_server_to_client,
            ),
        )?);
        self.read_protector = Some(new_test_protector(
            self.read_suite,
            material_for(
                self.read_suite,
                &derived.iv_client_to_server,
                &derived.encryption_key_client_to_server,
                &derived.integrity_key_client_to_server,
            ),
        )?);
        Ok(())
    }

    fn record_plain_outbound(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let message_type = payload
            .first()
            .copied()
            .ok_or_else(|| "test peer cannot send an empty packet".to_owned())?;
        self.sequence
            .classify_outbound(message_type)
            .map_err(|error| error.to_string())?;
        let packet = build_plain_packet(payload)?;
        self.sequence
            .observe_outbound(message_type)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_outbound()
            .map_err(|error| error.to_string())?;
        Ok(packet)
    }

    fn accept_inbound(&mut self, expected: u8) -> Result<(), String> {
        self.sequence
            .observe_inbound(expected)
            .map_err(|error| error.to_string())?;
        self.sequence
            .commit_inbound()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn peer_and_config(
    kex: &str,
    client_to_server_cipher: &str,
    server_to_client_cipher: &str,
    client_to_server_mac: &str,
    server_to_client_mac: &str,
    strict: bool,
    seed: u8,
    pre_banner: &[u8],
    raw_kexinit: Option<&[u8]>,
) -> Result<(TestPeer, ClientConfig), String> {
    let proposal = proposal(
        kex,
        client_to_server_cipher,
        server_to_client_cipher,
        client_to_server_mac,
        server_to_client_mac,
        strict,
    );
    custom_peer_and_config(proposal, kex, seed, pre_banner, raw_kexinit)
}

fn custom_peer_and_config(
    proposal: KexInit,
    kex: &str,
    seed: u8,
    pre_banner: &[u8],
    raw_kexinit: Option<&[u8]>,
) -> Result<(TestPeer, ClientConfig), String> {
    let (_initial_client_stream, stream, client_to_server, server_to_client) =
        duplex_pair_with_queues();
    let mechanism: Box<dyn KeyExchange> = match kex {
        CURVE25519_SHA256 => Box::new(Curve25519::standard()),
        CURVE25519_SHA256_LIBSSH => Box::new(Curve25519::libssh()),
        ECDH_SHA2_NISTP256 => Box::new(EcdhP256::new()),
        _ => return Err("test requested an unsupported KEX mechanism".to_owned()),
    };
    let state = Rc::new(RefCell::new(PeerState::new(
        proposal, mechanism, seed, false,
    )?));
    let initial = state
        .borrow_mut()
        .initial_server_bytes(pre_banner, raw_kexinit)?;
    server_to_client.borrow_mut().extend(initial);

    let responder_state = Rc::clone(&state);
    let responder: Responder = Rc::new(RefCell::new(move |client_bytes: Vec<u8>| {
        responder_state.borrow_mut().drive(&client_bytes)
    }));
    let client_stream = Stream {
        input: server_to_client,
        output: Rc::clone(&client_to_server),
        responder: Some(responder),
    };
    let peer = TestPeer {
        client_stream,
        stream,
        state,
        client_to_server,
    };
    Ok((peer, ClientConfig::new()))
}

fn proposal(
    kex: &str,
    client_to_server_cipher: &str,
    server_to_client_cipher: &str,
    client_to_server_mac: &str,
    server_to_client_mac: &str,
    strict: bool,
) -> KexInit {
    let mut kex_names = vec![kex.to_owned()];
    if strict {
        kex_names.push(KEX_STRICT_S_V00_OPENSSH.to_owned());
    }
    KexInit::from_lists(
        [1; 16],
        kex_names,
        vec![HOST_KEY_SSH_ED25519.to_owned(), EXT_INFO_S.to_owned()],
        vec![client_to_server_cipher.to_owned()],
        vec![server_to_client_cipher.to_owned()],
        vec![client_to_server_mac.to_owned()],
        vec![server_to_client_mac.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&mut [seed; 32])
}

fn assert_protection_lengths(cipher: &str, mac: &str) {
    let suite = PacketSuite::new(
        cipher,
        (!cipher.contains("-gcm@") && cipher != ENCRYPTION_CHACHA20_POLY1305_OPENSSH)
            .then_some(mac),
    )
    .expect("test packet suite is supported");
    let iv = if cipher == ENCRYPTION_CHACHA20_POLY1305_OPENSSH {
        0
    } else if suite.integrity_name().is_none() {
        12
    } else {
        16
    };
    let key = match cipher {
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH => 64,
        _ if cipher.contains("256") => 32,
        _ => 16,
    };
    let integrity = if suite.integrity_name().is_none() {
        0
    } else if mac.contains("sha2-512") {
        64
    } else {
        32
    };
    assert!(iv == 0 || iv == 12 || iv == 16);
    assert!(key == 16 || key == 32 || key == 64);
    assert!(integrity == 0 || integrity == 32 || integrity == 64);
}

fn suite_for(cipher: &str, mac: &str) -> Result<PacketSuite, String> {
    let integrity = if cipher.contains("-gcm@") || cipher == ENCRYPTION_CHACHA20_POLY1305_OPENSSH {
        None
    } else {
        Some(mac)
    };
    PacketSuite::new(cipher, integrity).map_err(|error| error.to_string())
}

fn new_test_protector(
    suite: PacketSuite,
    material: PacketKeyMaterial,
) -> Result<PacketProtector, String> {
    PacketProtector::new(suite, material).map_err(|error| error.to_string())
}

fn material_for(
    suite: PacketSuite,
    iv: &[u8],
    encryption_key: &[u8],
    integrity_key: &[u8],
) -> PacketKeyMaterial {
    if suite.encryption_name() == ENCRYPTION_CHACHA20_POLY1305_OPENSSH {
        PacketKeyMaterial::new(&[0; 8], encryption_key, None)
    } else if suite.integrity_name().is_none() {
        PacketKeyMaterial::gcm(iv, encryption_key)
    } else {
        PacketKeyMaterial::hmac(iv, encryption_key, integrity_key)
    }
}

fn iv_length(suite: PacketSuite) -> usize {
    match suite.encryption_name() {
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH => 0,
        _ if suite.integrity_name().is_none() => 12,
        _ => 16,
    }
}

fn encryption_key_length(suite: PacketSuite) -> Result<usize, String> {
    match suite.encryption_name() {
        AES128_CTR | AES128_GCM_OPENSSH => Ok(16),
        AES256_CTR | AES256_GCM_OPENSSH => Ok(32),
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH => Ok(64),
        _ => Err("test selected an unknown cipher".to_owned()),
    }
}

fn integrity_key_length(suite: PacketSuite) -> usize {
    match suite.integrity_name() {
        None => 0,
        Some(name) if name.contains("sha2-512") => 64,
        Some(_) => 32,
    }
}

fn build_plain_packet(payload: &[u8]) -> Result<Vec<u8>, String> {
    build_packet_default(payload, |padding| padding.fill(0xa5)).map_err(|error| error.to_string())
}

fn read_plain_packet(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut prefix = [0_u8; 4];
    read_exact(stream, &mut prefix)?;
    let packet_length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_error| "test packet length does not fit usize".to_owned())?;
    let total = packet_length
        .checked_add(4)
        .ok_or_else(|| "test packet length overflow".to_owned())?;
    let mut packet = prefix.to_vec();
    packet.resize(total, 0);
    read_exact(stream, &mut packet[4..])?;
    let decoded = decode_packet(&packet, 8).map_err(|error| error.to_string())?;
    Ok(decoded.payload().to_vec())
}

fn take_plain_payload(input: &mut &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 4 {
        return Err("test packet prefix is truncated".to_owned());
    }
    let packet_length = usize::try_from(u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_error| "test packet prefix is truncated".to_owned())?,
    ))
    .map_err(|_error| "test packet length does not fit usize".to_owned())?;
    let total = packet_length
        .checked_add(4)
        .ok_or_else(|| "test packet length overflow".to_owned())?;
    let packet = input
        .get(..total)
        .ok_or_else(|| "test packet body is truncated".to_owned())?;
    let decoded = decode_packet(packet, 8).map_err(|error| error.to_string())?;
    *input = input.get(total..).unwrap_or_default();
    Ok(decoded.payload().to_vec())
}

fn take_identification(input: &mut &[u8]) -> Result<String, String> {
    let end = input
        .windows(2)
        .position(|window| window == b"\r\n")
        .and_then(|position| position.checked_add(2))
        .ok_or_else(|| "test identification is truncated".to_owned())?;
    let line = input
        .get(..end)
        .ok_or_else(|| "test identification is truncated".to_owned())?;
    let version = std::str::from_utf8(
        line.get(..end.saturating_sub(2))
            .ok_or_else(|| "test identification is truncated".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    *input = input.get(end..).unwrap_or_default();
    Ok(version.to_owned())
}

fn read_protected_packet(stream: &mut impl Read, suite: PacketSuite) -> Result<Vec<u8>, String> {
    let mut prefix = [0_u8; 16];
    read_exact(stream, &mut prefix)?;
    let packet_length = usize::try_from(u32::from_be_bytes(
        prefix
            .get(..4)
            .ok_or_else(|| "test protected prefix is truncated".to_owned())?
            .try_into()
            .map_err(|_error| "test protected prefix is truncated".to_owned())?,
    ))
    .map_err(|_error| "test protected length does not fit usize".to_owned())?;
    let total = packet_length
        .checked_add(4)
        .ok_or_else(|| "test protected length overflow".to_owned())?;
    let tag_length = if suite.integrity_name().is_none() {
        16
    } else if suite
        .integrity_name()
        .is_some_and(|name| name.contains("sha2-512"))
    {
        64
    } else {
        32
    };
    let mut packet = prefix.to_vec();
    packet.resize(total.saturating_add(tag_length), 0);
    read_exact(stream, &mut packet[16..])?;
    Ok(packet)
}

fn read_eam_test_payload(
    stream: &mut impl Read,
    protector: &mut PacketProtector,
    sequence: u32,
) -> Result<Vec<u8>, String> {
    let mut packet = vec![0_u8; 16];
    read_exact(stream, &mut packet)?;
    let maximum = (MAX_PACKET_CONTENT + 1).div_ceil(16) * 16 + 32;
    loop {
        let error = match protector.open(sequence, &packet) {
            Ok(payload) => return Ok(payload),
            Err(error) => error,
        };
        if packet.len() >= maximum {
            return Err(error.to_string());
        }
        let start = packet.len();
        let count = 16_usize.min(maximum.saturating_sub(start));
        packet.resize(start + count, 0);
        if let Err(read_error) = read_exact(stream, &mut packet[start..]) {
            return Err(if error == PacketProtectionError::AuthenticationFailed {
                error.to_string()
            } else {
                read_error
            });
        }
    }
}

fn read_exact(stream: &mut impl Read, target: &mut [u8]) -> Result<(), String> {
    let mut read = 0;
    while read < target.len() {
        match stream.read(&mut target[read..]) {
            Ok(0) => return Err("in-memory stream ended early".to_owned()),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

/// A pending write keeps the payload it was sealed from, and that payload is
/// plaintext.
///
/// The entry outlives the call that filled it: a write that blocks part-way
/// leaves the packet here until a later retry, so for as long as the peer
/// declines to read it the transport is holding a copy of whatever was sent —
/// including an SSH password. This drives the entry through both ways out and
/// checks each one wiped it.
#[test]
fn a_pending_write_wipes_the_plaintext_payload_it_retained()
-> Result<(), Box<dyn std::error::Error>> {
    const SECRET: &[u8] = b"\x50\x00\x00\x00\x0chunter2";
    let suite = PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))?;
    let key = vec![0x31_u8; 16];
    let integrity_key = vec![0x32_u8; 32];
    let iv = [0x07_u8; 16];
    let mut protector = PacketProtector::new(
        suite,
        PacketKeyMaterial::new(&iv, &key, Some(&integrity_key)),
    )?;
    let (_, mut stream, _) = duplex_pair();
    let mut buffer = transport::ProtectedWriteBuffer::default();

    let sequence = transport::write_protected_packet_buffered(
        &mut stream,
        &mut buffer,
        &mut protector,
        0,
        SECRET,
        None,
    )?;
    assert!(buffer.is_pending());
    // The retry check reads this buffer, so it has to still be intact here.
    assert_eq!(
        transport::write_protected_packet_buffered(
            &mut stream,
            &mut buffer,
            &mut protector,
            0,
            SECRET,
            None
        )?,
        sequence,
        "a retry of the same packet must not reseal it"
    );

    // A record left by an earlier test on this thread would make the two
    // assertions below unfalsifiable, so the lane starts from none.
    assert_eq!(take_plaintext_drop(PlaintextSlot::PendingPayload), None);
    buffer.acknowledge(sequence)?;
    assert_eq!(
        take_plaintext_drop(PlaintextSlot::PendingPayload),
        Some(PlaintextDrop::Wiped),
        "acknowledging a write must wipe the payload it retained"
    );

    transport::write_protected_packet_buffered(
        &mut stream,
        &mut buffer,
        &mut protector,
        1,
        SECRET,
        None,
    )?;
    assert_eq!(take_plaintext_drop(PlaintextSlot::PendingPayload), None);
    buffer.abort();
    assert_eq!(
        take_plaintext_drop(PlaintextSlot::PendingPayload),
        Some(PlaintextDrop::Wiped),
        "aborting a blocked write must wipe the payload it retained"
    );
    Ok(())
}

/// Padding for one payload, taken from the crate's own alignment rule.
///
/// The test used to carry its own copy of the arithmetic, including a local
/// `body_is_aligned`. That is a copy, not a derivation, so it would have
/// agreed with itself and disagreed with the code under test.
fn protection_padding(payload_length: usize, suite: PacketSuite) -> Vec<u8> {
    let length = PacketAlignment::for_suite(suite)
        .padding_length(payload_length)
        .expect("alignment rule must produce a padding length");
    vec![0x5a; length]
}

fn maximum_pre_banner() -> Vec<u8> {
    let mut output = Vec::new();
    for _ in 0..32 {
        output.extend(std::iter::repeat_n(b'b', 250));
        output.extend_from_slice(b"\r\n");
    }
    output.extend(std::iter::repeat_n(b'c', 126));
    output.extend_from_slice(b"\r\n");
    assert_eq!(output.len(), 8_192);
    output
}

fn oversized_pre_banner() -> Vec<u8> {
    let mut output = Vec::new();
    for _ in 0..34 {
        output.extend(std::iter::repeat_n(b'x', 250));
        output.extend_from_slice(b"\r\n");
    }
    output
}

fn duplex_pair() -> (Stream, Stream, Rc<RefCell<VecDeque<u8>>>) {
    let (client, server, client_to_server, _server_to_client) = duplex_pair_with_queues();
    (client, server, client_to_server)
}

type ByteQueue = Rc<RefCell<VecDeque<u8>>>;
type DuplexQueues = (Stream, Stream, ByteQueue, ByteQueue);

fn duplex_pair_with_queues() -> DuplexQueues {
    let client_to_server = Rc::new(RefCell::new(VecDeque::new()));
    let server_to_client = Rc::new(RefCell::new(VecDeque::new()));
    let client = Stream {
        input: Rc::clone(&server_to_client),
        output: Rc::clone(&client_to_server),
        responder: None,
    };
    let server = Stream {
        input: Rc::clone(&client_to_server),
        output: Rc::clone(&server_to_client),
        responder: None,
    };
    (client, server, client_to_server, server_to_client)
}
