// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/keepalive.rs"]
mod keepalive;

use std::error::Error;

use keepalive::{
    GlobalRequest, GlobalRequestKind, KEEPALIVE_REQUEST, PING_REQUEST, SSH_MSG_GLOBAL_REQUEST,
    SSH_MSG_REQUEST_FAILURE, SSH_MSG_REQUEST_SUCCESS, decode_global_request, encode_keepalive,
    encode_ping,
};
use neotales_ssh::{Error as WireError, MAX_PACKET_CONTENT, Reader, Writer};

#[test]
fn ping_round_trips_and_success_reply_echoes_the_string() -> Result<(), Box<dyn Error>> {
    let payload = b"opaque\0ping-payload";
    let encoded = encode_ping(payload)?;
    assert_eq!(encoded.first(), Some(&SSH_MSG_GLOBAL_REQUEST));

    let decoded = decode_global_request(&encoded)?;
    assert_eq!(decoded.kind(), GlobalRequestKind::Ping);
    assert_eq!(decoded.name(), PING_REQUEST.as_bytes());
    assert!(decoded.want_reply());
    assert_eq!(decoded.ping_payload(), Some(payload.as_slice()));

    let reply = decoded.reply()?.ok_or(WireError::InvalidPacket)?;
    assert_eq!(reply.first(), Some(&SSH_MSG_REQUEST_SUCCESS));
    let mut reader = Reader::new(reply.get(1..).ok_or(WireError::Truncated)?);
    assert_eq!(reader.read_string()?, payload.as_slice());
    assert!(reader.is_empty());
    Ok(())
}

#[test]
fn keepalive_is_encoded_without_a_reply_request() -> Result<(), Box<dyn Error>> {
    let encoded = encode_keepalive()?;
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.read_byte()?, SSH_MSG_GLOBAL_REQUEST);
    assert_eq!(reader.read_string()?, KEEPALIVE_REQUEST.as_bytes());
    assert!(!reader.read_boolean()?);
    assert!(reader.is_empty());

    let decoded = GlobalRequest::decode(&encoded)?;
    assert_eq!(decoded.kind(), GlobalRequestKind::Keepalive);
    assert!(!decoded.want_reply());
    assert_eq!(decoded.reply()?, None);
    Ok(())
}

#[test]
fn unknown_request_with_want_reply_produces_failure_only() -> Result<(), Box<dyn Error>> {
    let name = b"future@example.test";
    let data = [0x00, 0xff, 0x80, b'r', b'a', b'w'];
    let encoded = wire_request(name, true, &data)?;
    let decoded = decode_global_request(&encoded)?;

    assert_eq!(decoded.kind(), GlobalRequestKind::Unknown);
    assert_eq!(decoded.name(), name);
    assert_eq!(decoded.data(), data);
    assert_eq!(decoded.encode()?, encoded);
    let reply = decoded.reply()?.ok_or(WireError::InvalidPacket)?;
    assert_eq!(reply, [SSH_MSG_REQUEST_FAILURE]);
    assert_eq!(reply.first(), Some(&SSH_MSG_REQUEST_FAILURE));
    assert_ne!(reply.first(), Some(&SSH_MSG_REQUEST_SUCCESS));
    Ok(())
}

#[test]
fn known_keepalive_with_want_reply_produces_success_without_data() -> Result<(), Box<dyn Error>> {
    let decoded = GlobalRequest::Keepalive { want_reply: true };
    let reply = decoded.reply()?.ok_or(WireError::InvalidPacket)?;
    assert_eq!(reply, [SSH_MSG_REQUEST_SUCCESS]);

    let encoded = wire_request(KEEPALIVE_REQUEST.as_bytes(), true, &[])?;
    assert_eq!(GlobalRequest::decode(&encoded)?, decoded);
    Ok(())
}

#[test]
fn ping_with_want_reply_false_decodes_but_has_no_response() -> Result<(), Box<dyn Error>> {
    let payload = b"quiet";
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
    writer.write_string(PING_REQUEST.as_bytes())?;
    writer.write_boolean(false);
    writer.write_string(payload)?;

    let decoded = decode_global_request(writer.as_bytes())?;
    assert_eq!(decoded.kind(), GlobalRequestKind::Ping);
    assert!(!decoded.want_reply());
    assert_eq!(decoded.ping_payload(), Some(payload.as_slice()));
    assert_eq!(decoded.reply()?, None);
    Ok(())
}

#[test]
fn unknown_request_without_want_reply_is_ignored() -> Result<(), Box<dyn Error>> {
    let encoded = wire_request(b"opaque", false, b"\x00\x01\x02")?;
    let decoded = decode_global_request(&encoded)?;
    assert_eq!(decoded.kind(), GlobalRequestKind::Unknown);
    assert!(!decoded.want_reply());
    assert_eq!(decoded.reply()?, None);
    Ok(())
}

#[test]
fn decoder_rejects_truncation_wrong_type_and_invalid_boolean() -> Result<(), Box<dyn Error>> {
    let encoded = encode_ping(b"payload")?;
    for length in 0..encoded.len() {
        assert!(
            decode_global_request(&encoded[..length]).is_err(),
            "accepted a {length}-byte prefix"
        );
    }
    assert_eq!(decode_global_request(&[]).err(), Some(WireError::Truncated));

    let mut wrong_type = encoded.clone();
    wrong_type[0] = SSH_MSG_GLOBAL_REQUEST + 1;
    assert_eq!(
        decode_global_request(&wrong_type).err(),
        Some(WireError::InvalidPacket)
    );

    let mut invalid_boolean = wire_ping(true, b"payload")?;
    let boolean_offset = 1 + 4 + PING_REQUEST.len();
    let invalid_byte = invalid_boolean
        .get_mut(boolean_offset)
        .ok_or(WireError::InvalidPacket)?;
    *invalid_byte = 2;
    assert_eq!(
        decode_global_request(&invalid_boolean).err(),
        Some(WireError::InvalidBoolean)
    );
    Ok(())
}

#[test]
fn decoder_rejects_trailing_data_for_defined_requests() -> Result<(), Box<dyn Error>> {
    let mut keepalive = wire_request(KEEPALIVE_REQUEST.as_bytes(), false, &[])?;
    keepalive.push(0);
    assert_eq!(
        decode_global_request(&keepalive).err(),
        Some(WireError::InvalidPacket)
    );

    let mut ping = wire_ping(false, b"payload")?;
    ping.push(0);
    assert_eq!(
        decode_global_request(&ping).err(),
        Some(WireError::InvalidPacket)
    );
    Ok(())
}

#[test]
fn decoder_rejects_payloads_over_the_shared_limit() {
    let oversized = vec![SSH_MSG_GLOBAL_REQUEST; MAX_PACKET_CONTENT + 1];
    assert_eq!(
        decode_global_request(&oversized).err(),
        Some(WireError::LimitExceeded)
    );
}

#[test]
fn ping_encoder_enforces_the_complete_payload_limit() {
    let fixed_overhead = 1 + 4 + PING_REQUEST.len() + 1 + 4;
    let maximum_payload = MAX_PACKET_CONTENT - fixed_overhead;
    assert!(encode_ping(vec![0_u8; maximum_payload]).is_ok());
    assert_eq!(
        encode_ping(vec![0_u8; maximum_payload + 1]).err(),
        Some(WireError::LimitExceeded)
    );
}

fn wire_request(name: &[u8], want_reply: bool, data: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
    writer.write_string(name)?;
    writer.write_boolean(want_reply);
    let mut encoded = writer.into_bytes();
    encoded.extend_from_slice(data);
    Ok(encoded)
}

fn wire_ping(want_reply: bool, payload: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
    writer.write_string(PING_REQUEST.as_bytes())?;
    writer.write_boolean(want_reply);
    writer.write_string(payload)?;
    Ok(writer.into_bytes())
}
