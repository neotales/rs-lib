// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

pub use neotales_ssh::MAX_PACKET_CONTENT;

type KexInitConstructor = (&'static str, fn([u8; 16]) -> KexInit);

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
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use crate::client::{ClientConfig, HandshakeError as ClientHandshakeError};
use cipher::{PacketKeyMaterial, PacketProtector, PacketSuite};
use hostkey::{Ed25519PublicKey, Ed25519Signer, verify_host_key_signature};
use kex::mlkem768_x25519::ClientKex as MlKemClientKex;
use kex::{Curve25519, DerivationLengths, DerivedKeys, KexContext, KeyExchange, derive_keys};
use msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256,
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH, HMAC_SHA2_256, HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512,
    HMAC_SHA2_512_ETM_OPENSSH, HOST_KEY_SSH_ED25519, KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_MLKEM768X25519_SHA256, KEX_STRICT_C_V00_OPENSSH, KexInit,
};
use neotales_ssh::build_packet_default;
use neotales_ssh::compression::CompressionAlgorithm;
use sequence::SequenceState;
use server::{
    HandshakeError, IdentificationError, ServerConfig, ServerHandshake, ServerTransport,
    ServerTransportError, TransportError,
};

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
fn server_rekeys_hybrid_with_old_keys_until_newkeys_and_keeps_session_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(41);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let (mut server, mut peer) = complete_raw_initial(&config, expected_key, true)?;
    let original_session_id = server.session_id().to_vec();

    server.begin_rekey()?;
    peer.begin_rekey()?;
    let server_kexinit = peer.receive_protected()?;
    assert_eq!(server_kexinit.first(), Some(&20));
    let server_kexinit_message = KexInit::decode(&server_kexinit)?;
    let mut client_kexinit = proposal(KEX_MLKEM768X25519_SHA256, AES128_CTR, HMAC_SHA2_256, false);
    client_kexinit.cookie = [0x72; 16];
    let client_kexinit_payload = client_kexinit.encode()?;
    peer.send_rekey(&client_kexinit_payload, 20)?;

    server.advance_rekey()?;
    assert!(server.rekey_active());
    let context = KexContext::new(
        &peer.client_version,
        &peer.server_version,
        client_kexinit_payload.as_slice(),
        server_kexinit.as_slice(),
        KEX_MLKEM768X25519_SHA256,
    )?;
    let client_kex = MlKemClientKex::from_seeds(&[0x81; 64], &[0x82; 32]);
    peer.send_rekey(&client_kex.init_message()?, 30)?;
    server.advance_rekey()?;
    let reply = peer.receive_protected()?;
    assert_eq!(reply.first(), Some(&31));
    let completion = client_kex.complete(&context, &reply)?;
    verify_host_key_signature(
        &expected_key,
        &completion.signature_blob,
        &completion.exchange_hash,
    )?;
    let derived = derive_keys(
        &completion.shared_secret,
        &completion.exchange_hash,
        &original_session_id,
        raw_derivation_lengths(),
    )?;
    let server_newkeys = peer.receive_protected()?;
    assert_eq!(server_newkeys, [21]);
    peer.send_rekey(&[21], 21)?;
    peer.complete_rekey()?;

    server.advance_rekey()?;
    assert!(!server.rekey_active());
    assert_eq!(server.inbound_sequence(), 0);
    assert_eq!(server.outbound_sequence(), 0);
    assert!(server.rekey_reset_applied(sequence::Direction::Inbound));
    assert!(server.rekey_reset_applied(sequence::Direction::Outbound));
    assert_eq!(server.session_id(), original_session_id.as_slice());
    assert_eq!(server.host_key(), &expected_key);
    peer.install_rekey_protectors(&derived)?;
    peer.send_application(&[50, 1, 2, 3])?;
    assert_eq!(server.read_auth_packet()?, [50, 1, 2, 3]);
    server.write_payload(&[94, 9, 8, 7])?;
    assert_eq!(peer.receive_protected()?, [94, 9, 8, 7]);
    assert_eq!(
        server_kexinit_message.kex_algorithms,
        vec![KEX_MLKEM768X25519_SHA256.to_owned()]
    );
    Ok(())
}

#[test]
fn peer_kexinit_is_consumed_before_authentication_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(42);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let (mut server, mut peer) = complete_raw_initial(&config, expected_key, false)?;
    let mut client_kexinit = proposal(KEX_MLKEM768X25519_SHA256, AES128_CTR, HMAC_SHA2_256, false);
    client_kexinit.cookie = [0x91; 16];
    peer.begin_rekey()?;
    peer.send_rekey(&client_kexinit.encode()?, 20)?;

    assert!(matches!(
        server.read_auth_packet(),
        Err(ServerTransportError::Transport(TransportError::Io(_)))
    ));
    assert!(server.rekey_active());
    assert_eq!(server.inbound_sequence(), 4);

    let server_kexinit = peer.receive_protected()?;
    assert_eq!(server_kexinit.first(), Some(&20));
    Ok(())
}

#[test]
fn rekey_rejects_non_hybrid_and_reentrant_transitions_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(43);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let (mut server, peer) = complete_raw_initial(&config, expected_key, false)?;
    server.begin_rekey()?;
    assert!(matches!(
        server.begin_rekey(),
        Err(ServerTransportError::RekeyInProgress)
    ));
    assert!(server.rekey_is_terminal());
    drop(server);
    drop(peer);

    let (mut server, mut peer) = complete_raw_initial(&config, expected_key, false)?;
    let mut non_hybrid = proposal(CURVE25519_SHA256, AES128_CTR, HMAC_SHA2_256, false);
    non_hybrid.cookie = [0xb1; 16];
    peer.begin_rekey()?;
    peer.send_rekey(&non_hybrid.encode()?, 20)?;
    assert!(matches!(
        server.read_auth_packet(),
        Err(ServerTransportError::UnsupportedAlgorithm)
    ));
    assert!(server.rekey_is_terminal());
    assert!(server.write_payload(&[50, 0]).is_err());
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
fn one_sided_chacha_offer_fails_closed() {
    let signer = signer(19);
    let expected_key = *signer.public_key();
    let server_proposal = proposal(CURVE25519_SHA256, AES128_CTR, HMAC_SHA2_256, true);
    let config = ServerConfig::new(signer).with_kexinit(server_proposal);
    let client_config = ClientConfig::with_kexinit(proposal(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        true,
    ));
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

    let result = client_config.connect(client_stream, |key| {
        assert_eq!(key, &expected_key);
        Ok::<(), Infallible>(())
    });
    assert!(matches!(result, Err(ClientHandshakeError::Negotiation)));
    assert!(matches!(
        server_error.borrow_mut().take(),
        Some(HandshakeError::Negotiation)
    ));
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
fn chacha_and_aes_directional_keys_use_opposite_material() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = signer(16);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let mut client_proposal = proposal(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        true,
    );
    client_proposal.encryption_algorithms_server_to_client = vec![AES256_GCM_OPENSSH.to_owned()];
    client_proposal.mac_algorithms_server_to_client = vec![HMAC_SHA2_512.to_owned()];
    let client_config = ClientConfig::with_kexinit(client_proposal);
    run_echo(&config, &client_config, &expected_key, true)
}

#[test]
fn chacha_handshake_allows_disjoint_mac_lists() -> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(17);
    let expected_key = *signer.public_key();
    let server_config = ServerConfig::new(signer);
    let mut server_proposal = server_config.kexinit().clone();
    server_proposal.mac_algorithms_client_to_server = vec![HMAC_SHA2_512.to_owned()];
    server_proposal.mac_algorithms_server_to_client = vec![HMAC_SHA2_512.to_owned()];
    let config = server_config.with_kexinit(server_proposal.clone());

    let mut client_proposal = proposal(
        CURVE25519_SHA256,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        HMAC_SHA2_256,
        true,
    );
    client_proposal.mac_algorithms_client_to_server = vec![HMAC_SHA2_256.to_owned()];
    client_proposal.mac_algorithms_server_to_client = vec![HMAC_SHA2_256.to_owned()];
    let negotiated = client_proposal
        .negotiate(&server_proposal)
        .expect("ChaCha ignores disjoint MAC lists");
    assert!(negotiated.mac_client_to_server.is_empty());
    assert!(negotiated.mac_server_to_client.is_empty());
    assert_eq!(
        PacketSuite::new(ENCRYPTION_CHACHA20_POLY1305_OPENSSH, None)?.integrity_name(),
        None
    );

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
        (ENCRYPTION_CHACHA20_POLY1305_OPENSSH, HMAC_SHA2_256),
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

#[test]
fn the_default_kexinit_constructors_complete_a_server_handshake()
-> Result<(), Box<dyn std::error::Error>> {
    // The server half of the hazard the client half covers in
    // `tests/client_rekey.rs`: `ServerConfig::with_kexinit(KexInit::new())` is
    // the documented construction, and before the algorithm catalogs were
    // corrected it proposed `rsa-sha2-512` first, which this server's own
    // `ProtectionPlan::from_algorithms` then refused with
    // `UnsupportedAlgorithm`. Each constructor is run against a real client over
    // a duplex stream, exchange to exchange.
    let expected_key = *signer(41).public_key();
    let constructors: [KexInitConstructor; 4] = [
        ("KexInit::new", KexInit::new),
        ("KexInit::client_defaults", KexInit::client_defaults),
        ("KexInit::server_defaults", KexInit::server_defaults),
        ("|_| KexInit::default()", |_| KexInit::default()),
    ];
    for (label, construct) in constructors {
        let config = ServerConfig::new(signer(41)).with_kexinit(construct([0x55; 16]));
        let client_config = ClientConfig::new();
        run_echo(
            &config,
            &client_config,
            &expected_key,
            client_config.kexinit().strict_kex_enabled(config.kexinit()),
        )
        .map_err(|error| format!("{label} could not complete a server handshake: {error}"))?;
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

fn raw_derivation_lengths() -> DerivationLengths {
    DerivationLengths {
        a: 16,
        b: 16,
        c: 16,
        d: 16,
        e: 32,
        f: 32,
    }
}

fn raw_protector(
    iv: &[u8],
    encryption_key: &[u8],
    integrity_key: &[u8],
) -> Result<PacketProtector, Box<dyn std::error::Error>> {
    Ok(PacketProtector::new_with_compression(
        PacketSuite::new(AES128_CTR, Some(HMAC_SHA2_256))?,
        PacketKeyMaterial::hmac(iv, encryption_key, integrity_key),
        CompressionAlgorithm::None,
    )?)
}

struct RawPeer<S> {
    stream: S,
    sequence: SequenceState,
    session_id: Vec<u8>,
    client_version: String,
    server_version: String,
    read_protector: Option<PacketProtector>,
    write_protector: Option<PacketProtector>,
}

impl<S> RawPeer<S>
where
    S: Read + Write,
{
    fn send_plain(
        &mut self,
        payload: &[u8],
        message_type: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.sequence.classify_outbound(message_type)?;
        let padding = transport::random_unprotected_padding(payload.len())?;
        let packet = build_packet_default(payload, |target| {
            target.copy_from_slice(&padding);
        })?;
        self.stream.write_all(&packet)?;
        self.sequence.observe_outbound(message_type)?;
        self.sequence.commit_outbound()?;
        Ok(())
    }

    fn receive_plain(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let payload = transport::read_unprotected_packet(&mut self.stream)?;
        let message_type = payload.first().copied().unwrap_or_default();
        self.sequence.observe_inbound(message_type)?;
        self.sequence.commit_inbound()?;
        Ok(payload)
    }

    fn begin_rekey(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.sequence.begin_rekey()?;
        Ok(())
    }

    fn send_rekey(
        &mut self,
        payload: &[u8],
        message_type: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.sequence.classify_rekey_outbound(message_type)?;
        let protector = self
            .write_protector
            .as_mut()
            .ok_or("raw peer has no write protector")?;
        let sequence = self.sequence.outbound_sequence();
        let padding = transport::random_padding(payload.len(), protector.suite())?;
        let packet = protector.seal(sequence, payload, &padding)?;
        self.stream.write_all(&packet)?;
        self.sequence.observe_rekey_outbound(message_type)?;
        self.sequence.commit_outbound()?;
        Ok(())
    }

    fn receive_protected(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let protector = self
            .read_protector
            .as_mut()
            .ok_or("raw peer has no read protector")?;
        let sequence = self.sequence.inbound_sequence();
        let payload = transport::read_eam_payload(&mut self.stream, protector, sequence)?;
        let message_type = payload.first().copied().unwrap_or_default();
        if self.sequence.rekey_active() {
            self.sequence.observe_rekey_inbound(message_type)?;
        }
        self.sequence.commit_inbound()?;
        Ok(payload)
    }

    fn complete_rekey(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.sequence.complete_rekey_exchange()?;
        Ok(())
    }

    fn install_rekey_protectors(
        &mut self,
        derived: &DerivedKeys,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.read_protector = Some(raw_protector(
            &derived.iv_server_to_client,
            &derived.encryption_key_server_to_client,
            &derived.integrity_key_server_to_client,
        )?);
        self.write_protector = Some(raw_protector(
            &derived.iv_client_to_server,
            &derived.encryption_key_client_to_server,
            &derived.integrity_key_client_to_server,
        )?);
        Ok(())
    }

    fn send_application(&mut self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let protector = self
            .write_protector
            .as_mut()
            .ok_or("raw peer has no write protector")?;
        let sequence = self.sequence.outbound_sequence();
        let padding = transport::random_padding(payload.len(), protector.suite())?;
        let packet = protector.seal(sequence, payload, &padding)?;
        self.stream.write_all(&packet)?;
        self.sequence.commit_outbound()?;
        Ok(())
    }
}

fn complete_raw_initial(
    config: &ServerConfig,
    expected_key: Ed25519PublicKey,
    strict: bool,
) -> Result<(ServerTransport<Stream<'_>>, RawPeer<Stream<'_>>), Box<dyn std::error::Error>> {
    complete_raw_initial_with_gate(config, expected_key, strict, None)
}

fn complete_raw_initial_with_gate(
    config: &ServerConfig,
    expected_key: Ed25519PublicKey,
    strict: bool,
    read_gate: Option<Rc<RefCell<ReadGate>>>,
) -> Result<(ServerTransport<Stream<'_>>, RawPeer<Stream<'_>>), Box<dyn std::error::Error>> {
    complete_raw_initial_with_gates(config, expected_key, strict, read_gate, None)
}

fn complete_raw_initial_with_write_gate(
    config: &ServerConfig,
    expected_key: Ed25519PublicKey,
    strict: bool,
    write_gate: Rc<RefCell<WriteGate>>,
) -> Result<(ServerTransport<Stream<'_>>, RawPeer<Stream<'_>>), Box<dyn std::error::Error>> {
    complete_raw_initial_with_gates(config, expected_key, strict, None, Some(write_gate))
}

fn complete_raw_initial_with_gates<'a>(
    config: &'a ServerConfig,
    expected_key: Ed25519PublicKey,
    strict: bool,
    read_gate: Option<Rc<RefCell<ReadGate>>>,
    write_gate: Option<Rc<RefCell<WriteGate>>>,
) -> Result<(ServerTransport<Stream<'a>>, RawPeer<Stream<'a>>), Box<dyn std::error::Error>> {
    let (mut client_stream, mut server_stream, client_to_server) = duplex_pair();
    server_stream.read_gate = read_gate;
    server_stream.write_gate = write_gate;
    let server_stream_for_handshake = server_stream.clone();
    let server_handshake = Rc::new(RefCell::new(None));
    let server_error = Rc::new(RefCell::new(None));
    let driver = {
        let server_stream = server_stream_for_handshake.clone();
        let server_handshake = Rc::clone(&server_handshake);
        let server_error = Rc::clone(&server_error);
        let client_to_server = Rc::clone(&client_to_server);
        let config_for_callback = config;
        Rc::new(RefCell::new(move || {
            advance_server(
                config_for_callback,
                server_stream.clone(),
                &server_handshake,
                &server_error,
                &client_to_server,
            );
        })) as Driver<'a>
    };
    client_stream.set_driver(driver);
    client_stream.write_all(b"SSH-2.0-neotales-ssh_0.1\r\n")?;
    let server_version = transport::read_peer_identification(&mut client_stream)?;
    let client_version = "SSH-2.0-neotales-ssh_0.1".to_owned();
    let mut peer = RawPeer {
        stream: client_stream,
        sequence: SequenceState::new(),
        session_id: Vec::new(),
        client_version: client_version.clone(),
        server_version: server_version.clone(),
        read_protector: None,
        write_protector: None,
    };
    let client_kexinit = proposal(KEX_MLKEM768X25519_SHA256, AES128_CTR, HMAC_SHA2_256, strict);
    let client_kexinit_payload = client_kexinit.encode()?;
    peer.send_plain(&client_kexinit_payload, 20)?;
    let server_kexinit_payload = peer.receive_plain()?;
    let server_kexinit = KexInit::decode(&server_kexinit_payload)?;
    assert!(
        server_kexinit
            .kex_algorithms
            .contains(&KEX_MLKEM768X25519_SHA256.to_owned())
    );
    peer.sequence.set_strict_kex(strict)?;
    let context = KexContext::new(
        &client_version,
        &server_version,
        client_kexinit_payload.as_slice(),
        server_kexinit_payload.as_slice(),
        KEX_MLKEM768X25519_SHA256,
    )?;
    let client_kex = MlKemClientKex::from_seeds(&[0x31; 64], &[0x32; 32]);
    peer.send_plain(&client_kex.init_message()?, 30)?;
    let reply = peer.receive_plain()?;
    let completion = client_kex.complete(&context, &reply)?;
    verify_host_key_signature(
        &expected_key,
        &completion.signature_blob,
        &completion.exchange_hash,
    )?;
    let derived = derive_keys(
        &completion.shared_secret,
        &completion.exchange_hash,
        &completion.session_id,
        raw_derivation_lengths(),
    )?;
    peer.session_id = completion.session_id.to_vec();
    peer.send_plain(&[21], 21)?;
    let server_newkeys = peer.receive_plain()?;
    assert_eq!(server_newkeys, [21]);
    peer.sequence.complete_initial_kex()?;
    peer.read_protector = Some(raw_protector(
        &derived.iv_server_to_client,
        &derived.encryption_key_server_to_client,
        &derived.integrity_key_server_to_client,
    )?);
    peer.write_protector = Some(raw_protector(
        &derived.iv_client_to_server,
        &derived.encryption_key_client_to_server,
        &derived.integrity_key_client_to_server,
    )?);
    let server = server_handshake
        .borrow_mut()
        .take()
        .ok_or("server handshake did not complete")?
        .into_transport()?;
    if let Some(error) = server_error.borrow_mut().take() {
        return Err(Box::new(error));
    }
    Ok((server, peer))
}

#[test]
fn server_partial_protected_read_resumes_without_advancing_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(44);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let gate = Rc::new(RefCell::new(ReadGate::default()));
    let (mut server, mut peer) =
        complete_raw_initial_with_gate(&config, expected_key, true, Some(Rc::clone(&gate)))?;
    peer.send_application(&[50, 1, 2])?;
    peer.send_application(&[50, 3, 4])?;

    gate.borrow_mut().arm(3);
    for (expected_sequence, expected_payload) in [(0_u32, &[50, 1, 2][..]), (1, &[50, 3, 4][..])] {
        loop {
            match server.read_auth_packet() {
                Ok(payload) => {
                    assert_eq!(payload, expected_payload);
                    break;
                }
                Err(ServerTransportError::Transport(TransportError::Io(error)))
                    if error.kind() == io::ErrorKind::WouldBlock =>
                {
                    assert_eq!(server.inbound_sequence(), expected_sequence);
                    gate.borrow_mut().release(3);
                }
                Err(error) => return Err(Box::new(error)),
            }
        }
    }
    assert_eq!(server.inbound_sequence(), 2);
    Ok(())
}

#[test]
fn server_partial_protected_write_resumes_without_advancing_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(45);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let gate = Rc::new(RefCell::new(WriteGate::default()));
    let (mut server, mut peer) =
        complete_raw_initial_with_write_gate(&config, expected_key, true, Rc::clone(&gate))?;
    let initial_sequence = server.outbound_sequence();

    gate.borrow_mut().arm(3);
    assert!(matches!(
        server.write_payload(SERVER_PAYLOAD),
        Err(ServerTransportError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(server.outbound_sequence(), initial_sequence);

    gate.borrow_mut().open();
    server.write_payload(SERVER_PAYLOAD)?;
    assert_eq!(server.outbound_sequence(), initial_sequence + 1);
    assert_eq!(peer.receive_protected()?, SERVER_PAYLOAD);
    Ok(())
}

#[test]
fn server_rekey_resumes_split_kexinit_and_reply() -> Result<(), Box<dyn std::error::Error>> {
    let signer = signer(46);
    let expected_key = *signer.public_key();
    let config = ServerConfig::new(signer);
    let gate = Rc::new(RefCell::new(WriteGate::default()));
    let (mut server, mut peer) =
        complete_raw_initial_with_write_gate(&config, expected_key, true, Rc::clone(&gate))?;
    let initial_sequence = server.outbound_sequence();
    let session_id = server.session_id().to_vec();

    gate.borrow_mut().arm(3);
    assert!(matches!(
        server.begin_rekey(),
        Err(ServerTransportError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(server.rekey_active());
    assert_eq!(server.outbound_sequence(), initial_sequence);
    gate.borrow_mut().open();
    server.begin_rekey()?;
    assert_eq!(server.outbound_sequence(), initial_sequence + 1);

    peer.begin_rekey()?;
    let server_kexinit = peer.receive_protected()?;
    assert_eq!(server_kexinit.first(), Some(&20));
    let mut client_kexinit = proposal(KEX_MLKEM768X25519_SHA256, AES128_CTR, HMAC_SHA2_256, false);
    client_kexinit.cookie = [0x72; 16];
    let client_kexinit_payload = client_kexinit.encode()?;
    peer.send_rekey(&client_kexinit_payload, 20)?;
    server.advance_rekey()?;

    let context = KexContext::new(
        &peer.client_version,
        &peer.server_version,
        client_kexinit_payload.as_slice(),
        server_kexinit.as_slice(),
        KEX_MLKEM768X25519_SHA256,
    )?;
    let client_kex = MlKemClientKex::from_seeds(&[0x81; 64], &[0x82; 32]);
    peer.send_rekey(&client_kex.init_message()?, 30)?;

    gate.borrow_mut().arm(3);
    assert!(matches!(
        server.advance_rekey(),
        Err(ServerTransportError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(server.outbound_sequence(), initial_sequence + 1);
    gate.borrow_mut().open();
    assert!(server.advance_rekey()?);
    assert_eq!(server.outbound_sequence(), 0);
    assert!(server.rekey_reset_applied(sequence::Direction::Outbound));

    let reply = peer.receive_protected()?;
    let completion = client_kex.complete(&context, &reply)?;
    let server_newkeys = peer.receive_protected()?;
    assert_eq!(server_newkeys, [21]);
    let derived = derive_keys(
        &completion.shared_secret,
        &completion.exchange_hash,
        &session_id,
        raw_derivation_lengths(),
    )?;
    peer.send_rekey(&[21], 21)?;
    peer.complete_rekey()?;
    peer.install_rekey_protectors(&derived)?;
    server.advance_rekey()?;
    assert!(!server.rekey_active());
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
    assert!(!server.is_established());
    assert!(server.rekey_is_terminal());
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
        read_gate: None,
        write_gate: None,
    };
    let server = Stream {
        input: Rc::clone(&client_to_server),
        output: server_to_client,
        driver: None,
        read_gate: None,
        write_gate: None,
    };
    (client, server, client_to_server)
}

type Driver<'a> = Rc<RefCell<dyn FnMut() + 'a>>;

#[derive(Default)]
struct ReadGate {
    active: bool,
    remaining: usize,
}

impl ReadGate {
    fn arm(&mut self, length: usize) {
        self.active = true;
        self.remaining = length;
    }

    fn release(&mut self, length: usize) {
        self.remaining = length;
    }

    fn limit(&self, requested: usize) -> usize {
        if self.active {
            requested.min(self.remaining)
        } else {
            requested
        }
    }

    fn consume(&mut self, count: usize) {
        self.remaining = self.remaining.saturating_sub(count);
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

    fn limit(&self, requested: usize) -> usize {
        if self.active {
            requested.min(self.remaining)
        } else {
            requested
        }
    }

    fn consume(&mut self, count: usize) {
        self.remaining = self.remaining.saturating_sub(count);
    }
}

#[derive(Clone)]
struct Stream<'a> {
    input: Rc<RefCell<VecDeque<u8>>>,
    output: Rc<RefCell<VecDeque<u8>>>,
    driver: Option<Driver<'a>>,
    read_gate: Option<Rc<RefCell<ReadGate>>>,
    write_gate: Option<Rc<RefCell<WriteGate>>>,
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
        let limit = self
            .read_gate
            .as_ref()
            .map_or(target.len(), |gate| gate.borrow().limit(target.len()));
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory server stream is waiting for the next chunk",
            ));
        }
        let mut input = self.input.borrow_mut();
        if input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory client stream is waiting for the server",
            ));
        }
        let count = target.len().min(input.len()).min(limit);
        for byte in &mut target[..count] {
            *byte = input.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "in-memory queue truncated")
            })?;
        }
        if let Some(gate) = &self.read_gate {
            gate.borrow_mut().consume(count);
        }
        Ok(count)
    }
}

impl Write for Stream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let allowed = self
            .write_gate
            .as_ref()
            .map_or(bytes.len(), |gate| gate.borrow().limit(bytes.len()));
        if allowed == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory server write is waiting for the next chunk",
            ));
        }
        let count = allowed.min(bytes.len());
        self.output
            .borrow_mut()
            .extend(bytes[..count].iter().copied());
        if let Some(gate) = &self.write_gate {
            gate.borrow_mut().consume(count);
        }
        if count == bytes.len() {
            self.drive();
        }
        Ok(count)
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
