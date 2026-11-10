//! Pinned cross-implementation vector for `mlkem768x25519-sha256`.
//!
//! # Provenance
//!
//! **From a live peer.** The source fixture is a captured Go client / OpenSSH
//! 9.9 server transcript, so the shared secret and exchange hash below are bytes
//! two independent implementations produced in a real session. That is the
//! strongest provenance available in this crate, and it is the only test here
//! that has it.
//!
//! Two things support the claim rather than just asserting it. The fixture's own
//! server identification line is `SSH-2.0-OpenSSH_9.9`, so the peer is named in
//! the bytes, and the fixture's SHA-256 is
//! `700e87e980ae43c972dae155ea9ba2b77d6a8332067677c5f532ac4f9d30a7da`, which
//! matches the value recorded in `data/README.md`.
//!
//! What was *not* re-derived here: the ML-KEM-768 encapsulation and the X25519
//! exchange were not recomputed step by step to confirm these two values, so they
//! rest on the fixture's integrity rather than on a second independent
//! calculation. The two 32-byte seeds are inputs, pinned so the exchange is
//! reproducible at all.
//!
//! It pins the client public value, the SSH transcript framing, the combined
//! shared secret, and the exchange hash without relying on a live OpenSSH process.

#![allow(dead_code, unreachable_pub, unused_imports)]

#[path = "../src/msg/mod.rs"]
mod msg;

#[path = "../src/kex/mod.rs"]
mod kex;

use std::collections::BTreeMap;

use kex::KexContext;
use kex::mlkem768_x25519::ClientKex;
use neotales_ssh::Reader;

const FIXTURE: &[u8] = include_bytes!("data/Client-KEX-mlkem768x25519-sha256");

fn from_hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn parse_flows(input: &[u8]) -> BTreeMap<u32, Vec<u8>> {
    let text = std::str::from_utf8(input).expect("fixture is ASCII");
    let mut flows = BTreeMap::new();
    let mut current = None;

    for line in text.lines() {
        if let Some(number) = line.strip_prefix(">>> Flow ") {
            let number = number
                .split_whitespace()
                .next()
                .expect("flow number")
                .parse::<u32>()
                .expect("numeric flow number");
            current = Some(number);
            flows.insert(number, Vec::new());
            continue;
        }

        let Some(number) = current else {
            continue;
        };
        let Some((hex_bytes, _ascii)) = line.get(10..).and_then(|line| line.split_once('|')) else {
            continue;
        };
        for token in hex_bytes.split_whitespace() {
            flows
                .get_mut(&number)
                .expect("flow data follows its header")
                .push(u8::from_str_radix(token, 16).expect("fixture hex byte"));
        }
    }

    flows
}

fn packet_payload(flow: &[u8]) -> &[u8] {
    let packet_length = u32::from_be_bytes(flow[..4].try_into().unwrap()) as usize;
    let padding_length = usize::from(flow[4]);
    assert!(padding_length >= 4);
    &flow[5..4 + packet_length - padding_length]
}

#[test]
fn pinned_go_openssh_hybrid_transcript_matches() -> Result<(), Box<dyn std::error::Error>> {
    let flows = parse_flows(FIXTURE);
    let client_kexinit = packet_payload(&flows[&3]);
    let server_kexinit = packet_payload(&flows[&4]);
    let client_message = packet_payload(&flows[&5]);
    let server_message = packet_payload(&flows[&6]);

    assert_eq!(client_kexinit[0], 20);
    assert_eq!(server_kexinit[0], 20);
    assert_eq!(client_message[0], 30);
    assert_eq!(server_message[0], 31);

    let context = KexContext::new(
        "SSH-2.0-Go",
        "SSH-2.0-OpenSSH_9.9",
        client_kexinit,
        server_kexinit,
        "mlkem768x25519-sha256",
    )?;
    let client = ClientKex::from_seeds(
        // PROVENANCE: **from a live peer** -- the Go client's own ML-KEM-768
        // seed and X25519 seed, taken from the captured transcript so the
        // exchange is reproducible. Inputs, not expected values.
        &from_hex(
            "ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a",
        ),
        &from_hex("66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9"),
    );

    let mut client_reader = Reader::new(client_message);
    assert_eq!(client_reader.read_byte()?, 30);
    assert_eq!(client_reader.read_string()?, client.client_init());
    assert!(client_reader.is_empty());

    let completion = client.complete(&context, server_message)?;
    assert_eq!(
        completion.shared_secret.as_bytes(),
        // PROVENANCE: **from a live peer** -- the Go client and the OpenSSH 9.9
        // server in the captured transcript. See the module comment.
        from_hex::<36>("0000002067701b91802f907a39e1f9031afa57b9fb84e1ff42322d76e8063584891d65fe")
    );
    assert_eq!(
        completion.exchange_hash,
        // PROVENANCE: **from a live peer** -- same transcript.
        from_hex("01bf822b312734a0641694c5772abd98244a94679883708c7f72f8f6b3d39a39")
    );
    assert_eq!(completion.session_id, completion.exchange_hash);
    Ok(())
}
