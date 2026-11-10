// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/chacha_cipher.rs"]
mod chacha_cipher;

use chacha_cipher::{
    CHACHA_KEY_SIZE, CHACHA20_POLY1305_OPENSSH_NAME, ChaChaCipher, ChaChaCipherError,
    ChaChaKeyMaterial,
};
use neotales_ssh::MAX_PACKET_CONTENT;

const SEQUENCE: u32 = 7;
const BODY: &[u8] = b"neotales-ssh";

fn test_key() -> Vec<u8> {
    (0..CHACHA_KEY_SIZE)
        .map(|value| u8::try_from(value).expect("test key byte fits"))
        .collect()
}

fn clear_packet(body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + body.len());
    packet.extend_from_slice(
        &u32::try_from(body.len())
            .expect("test body length fits")
            .to_be_bytes(),
    );
    packet.extend_from_slice(body);
    packet
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    result
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pair is UTF-8");
            u8::from_str_radix(text, 16).expect("hex pair is valid")
        })
        .collect()
}

// Canonical draft-ietf-sshm-chacha20-poly1305-04 Appendix A bytes,
// including the six clear padding bytes in the input packet.
//
// PROVENANCE: **from the specification** -- the Appendix A worked example of
// draft-ietf-sshm-chacha20-poly1305-04, which is the specification that defines
// `chacha20-poly1305@openssh.com`. All three constants were read out of that
// appendix and checked against it:
//
//   DRAFT_04_CLEAR_PACKET is Figure 4, "Input packet encoded as hex bytes,
//   before encryption":
//
//        00 00 00 48  06 5e 00 00  00 00 00 00  00 38 4c 6f
//        72 65 6d 20  69 70 73 75  6d 20 64 6f  6c 6f 72 20
//        73 69 74 20  61 6d 65 74  2c 20 63 6f  6e 73 65 63
//        74 65 74 75  72 20 61 64  69 70 69  73 69 63 69 6e
//        67 20 65 6c  69 74 4e 43  e8 04 dc 6c
//
//   DRAFT_04_KEY is Figure 5, "Key material output from the key exchange",
//   which the draft introduces with:
//
//        The encryption key for the client-to-server direction of the
//        connection, derived as specified in RFC4253 section 7.2, is 64 bytes
//        long and consists of the following bytes:
//
//        8b bf f6 85  5f c1 02 33  8c 37 3e 73  aa c0 c9 14
//        f0 76 a9 05  b2 44 4a 32  ee ca ff ea  e2 2b ec c5
//        e9 b7 a7 a5  82 5a 82 49  34 6e c1 c2  83 01 cf 39
//        45 43 fc 75  69 88 7d 76  e1 68 f3 75  62 ac 07 40
//
//   DRAFT_04_WIRE is the concatenation the draft calls "The full encrypted and
//   authenticated data of this packet": its Figure 12 ciphertext
//
//        2c 3e cc e4  a5 bc 05 89  5b f0 7a 7b  a9 56 b6 c6
//        88 29 ac 7c  83 b7 80 b7  00 0e cd e7  45 af c7 05
//        bb c3 78 ce  03 a2 80 23  6b 87 b5 3b  ed 58 39 66
//        23 02 b1 64  b6 28 6a 48  cd 1e 09 71  38 e3 cb 90
//        9b 8b 2b 82  9d d1 8d 2a  35 ff 82 d9
//
//   followed by its Figure 17 tag
//
//        95 34 9e 85  5b f0 2c 29  8e f7 75 f2  d1 a7 e8 b8
//
// This is the strongest kind of vector a test in this crate can have short of a
// live peer: the specification's own worked example, byte for byte. It is worth
// keeping that contrast in mind, because the packet-protection tests either side
// of it in this repository have no such anchor.
const DRAFT_04_KEY: &str = "8bbff6855fc102338c373e73aac0c914f076a905b2444a32eecaffeae22becc5e9b7a7a5825a8249346ec1c28301cf394543fc7569887d76e168f37562ac0740";
const DRAFT_04_CLEAR_PACKET: &str = "00000048065e00000000000000384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c69744e43e804dc6c";
const DRAFT_04_WIRE: &str = "2c3ecce4a5bc05895bf07a7ba956b6c68829ac7c83b780b7000ecde745afc705bbc378ce03a280236b87b53bed5839662302b164b6286a48cd1e097138e3cb909b8b2b829dd18d2a35ff82d995349e855bf02c298ef775f2d1a7e8b8";

#[test]
fn draft_04_appendix_a_vector_is_pinned() {
    let cipher = ChaChaCipher::new(decode_hex(DRAFT_04_KEY)).expect("valid direction key");
    let clear = decode_hex(DRAFT_04_CLEAR_PACKET);
    let sealed = cipher.seal(SEQUENCE, &clear).expect("packet seals");

    assert_eq!(
        cipher
            .decrypt_length(SEQUENCE, sealed.get(..4).expect("encrypted length"))
            .expect("length decrypts"),
        0x48
    );
    assert_eq!(hex(&sealed), DRAFT_04_WIRE);
    assert_eq!(cipher.open(SEQUENCE, &sealed).expect("packet opens"), clear);
}

#[test]
fn a_one_bit_tag_change_fails() {
    let cipher = ChaChaCipher::new(test_key()).expect("valid direction key");
    let sealed = cipher
        .seal(SEQUENCE, &clear_packet(BODY))
        .expect("packet seals");
    let mut damaged = sealed;
    let last = damaged.len().saturating_sub(1);
    damaged[last] ^= 1;

    assert_eq!(
        cipher.open(SEQUENCE, &damaged),
        Err(ChaChaCipherError::AuthenticationFailed)
    );
}

#[test]
fn malformed_inputs_and_keys_are_rejected() {
    let cipher = ChaChaCipher::new(test_key()).expect("valid direction key");

    assert_eq!(
        cipher.seal(SEQUENCE, &[0, 0, 0, 0]),
        Err(ChaChaCipherError::InvalidPacket)
    );
    let sealed = cipher
        .seal(SEQUENCE, &clear_packet(BODY))
        .expect("packet seals");
    assert!(cipher.open(SEQUENCE, &sealed[..sealed.len() - 1]).is_err());
    assert!(cipher.open(SEQUENCE, &[0_u8; 21]).is_err());
    assert!(matches!(
        ChaChaCipher::new([0_u8; 63]),
        Err(ChaChaCipherError::InvalidKeyMaterial)
    ));
}

#[test]
fn content_limit_is_applied_before_wire_overhead() {
    let cipher = ChaChaCipher::new(test_key()).expect("valid direction key");
    let mut body = vec![0_u8; MAX_PACKET_CONTENT + 1];
    body[0] = 4;
    let clear = clear_packet(&body);
    assert_eq!(clear.len(), MAX_PACKET_CONTENT + 5);

    let wire = cipher.seal(SEQUENCE, &clear).expect("maximum packet seals");
    assert_eq!(wire.len(), MAX_PACKET_CONTENT + 21);
    assert_eq!(
        cipher.open(SEQUENCE, &wire).expect("maximum packet opens"),
        clear
    );

    let mut over_clear = clear;
    over_clear.push(0);
    assert_eq!(
        cipher.seal(SEQUENCE, &over_clear),
        Err(ChaChaCipherError::LimitExceeded)
    );

    let mut over_wire = wire;
    over_wire.push(0);
    assert_eq!(
        cipher.open(SEQUENCE, &over_wire),
        Err(ChaChaCipherError::LimitExceeded)
    );
}

#[test]
fn the_sequence_number_is_explicit_and_key_debug_output_is_redacted() {
    let cipher = ChaChaCipher::new(test_key()).expect("valid direction key");
    let packet = clear_packet(BODY);
    let at_seven = cipher.seal(7, &packet).expect("packet seals");
    let at_eight = cipher.seal(8, &packet).expect("packet seals");
    assert_ne!(at_seven, at_eight);
    assert_eq!(cipher.open(7, &at_seven).expect("packet opens"), packet);

    let material = ChaChaKeyMaterial::new(test_key()).expect("valid key");
    let cipher_from_material = ChaChaCipher::from_material(material);
    assert_eq!(
        cipher_from_material
            .open(7, &at_seven)
            .expect("packet opens"),
        packet
    );
    assert_eq!(
        CHACHA20_POLY1305_OPENSSH_NAME,
        "chacha20-poly1305@openssh.com"
    );

    let debug = format!("{cipher:?}");
    let display = format!("{cipher}");
    let material_debug = format!(
        "{:?}",
        ChaChaKeyMaterial::new(test_key()).expect("valid key")
    );
    assert!(!debug.contains("0001020304050607"));
    assert!(!display.contains("0001020304050607"));
    assert!(!material_debug.contains("0001020304050607"));
}
