// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/agent.rs"]
mod agent;

use std::error::Error;
use std::io::{self, Cursor, Read, Write};

use agent::{
    AgentClient, AgentError, MAX_FRAME_SIZE, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_RSA_SHA2_256, SSH_AGENT_SIGN_RESPONSE, SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
};
use neotales_ssh::{Reader, Writer};

struct ScriptedAgent {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl ScriptedAgent {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }
}

impl Read for ScriptedAgent {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedAgent {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn lists_one_ed25519_identity_and_signs_rsa_with_sha256_flag() -> Result<(), Box<dyn Error>> {
    let ed25519_key = key_blob(b"ssh-ed25519", &[0x11; 32])?;
    let rsa_key = key_blob(b"ssh-rsa", &[0x22; 4])?;
    let mut identities_answer = Writer::new();
    identities_answer.write_byte(SSH_AGENT_IDENTITIES_ANSWER);
    identities_answer.write_uint32(1);
    identities_answer.write_string(&ed25519_key)?;
    identities_answer.write_string(&[0xff, 0x00, 0x80][..])?;

    let signature_blob = [0x30, 0x44, 0x02, 0x20];
    let mut responses = frame(&identities_answer.into_bytes())?;
    responses.extend(sign_response(&signature_blob)?);
    let mut client = AgentClient::new(ScriptedAgent::new(responses));

    let identities = client.identities()?;
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].key_blob(), ed25519_key);
    assert_eq!(identities[0].comment(), [0xff, 0x00, 0x80]);

    let signature = client.sign(&rsa_key, b"raw transcript")?;
    assert_eq!(signature, signature_blob);

    let transport = client.into_inner();
    let mut offset = 0;
    let (message, payload) = next_request(&transport.output, &mut offset)?;
    assert_eq!(message, SSH_AGENTC_REQUEST_IDENTITIES);
    assert_eq!(payload, [SSH_AGENTC_REQUEST_IDENTITIES]);

    let (message, payload) = next_request(&transport.output, &mut offset)?;
    assert_eq!(message, SSH_AGENTC_SIGN_REQUEST);
    let mut request = Reader::new(&payload);
    assert_eq!(request.read_byte()?, SSH_AGENTC_SIGN_REQUEST);
    assert_eq!(request.read_string_bytes()?, rsa_key);
    assert_eq!(request.read_string_bytes()?, b"raw transcript");
    assert_eq!(request.read_uint32()?, SSH_AGENT_RSA_SHA2_256);
    assert!(request.is_empty());
    Ok(())
}

#[test]
fn ed25519_sign_request_uses_flag_zero_and_preserves_data() -> Result<(), Box<dyn Error>> {
    let key = key_blob(b"ssh-ed25519", &[0x33; 32])?;
    let raw_data = [0x00, 0xff, 0x10, 0x80];
    let signature_blob = [0xde, 0xad, 0xbe, 0xef];
    let mut client = AgentClient::new(ScriptedAgent::new(sign_response(&signature_blob)?));

    let signature = client.sign(&key, &raw_data)?;
    assert_eq!(signature, signature_blob);

    let transport = client.into_inner();
    let (_, payload) = next_request(&transport.output, &mut 0)?;
    let mut request = Reader::new(&payload);
    assert_eq!(request.read_byte()?, SSH_AGENTC_SIGN_REQUEST);
    assert_eq!(request.read_string_bytes()?, key);
    assert_eq!(request.read_string_bytes()?, raw_data);
    assert_eq!(request.read_uint32()?, 0);
    assert!(request.is_empty());
    Ok(())
}

#[test]
fn explicit_sign_flags_are_forwarded_without_algorithm_selection() -> Result<(), Box<dyn Error>> {
    let key = key_blob(b"an-unknown-algorithm", &[0x44])?;
    let signature_blob = [0x55];
    let mut client = AgentClient::new(ScriptedAgent::new(sign_response(&signature_blob)?));

    let signature = client.sign_with_flags(&key, b"caller-selected", 7)?;
    assert_eq!(signature, signature_blob);

    let transport = client.into_inner();
    let (_, payload) = next_request(&transport.output, &mut 0)?;
    let mut request = Reader::new(&payload);
    assert_eq!(request.read_byte()?, SSH_AGENTC_SIGN_REQUEST);
    assert_eq!(request.read_string_bytes()?, key);
    assert_eq!(request.read_string_bytes()?, b"caller-selected");
    assert_eq!(request.read_uint32()?, 7);
    assert!(request.is_empty());
    Ok(())
}

#[test]
fn rejects_oversized_frame_before_reading_or_allocating_its_body() -> Result<(), Box<dyn Error>> {
    let length = u32::try_from(MAX_FRAME_SIZE + 1)?;
    let mut client = AgentClient::new(ScriptedAgent::new(length.to_be_bytes().to_vec()));

    let result = client.identities();
    assert!(matches!(result, Err(AgentError::FrameTooLarge)));

    let transport = client.into_inner();
    assert_eq!(transport.input.position(), 4);
    assert_eq!(transport.input.get_ref().len(), 4);
    assert_eq!(
        transport.output,
        [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]
    );
    Ok(())
}

#[test]
fn rejects_zero_length_frames_and_agent_failure() -> Result<(), Box<dyn Error>> {
    let mut zero_client = AgentClient::new(ScriptedAgent::new(0_u32.to_be_bytes().to_vec()));
    assert!(matches!(
        zero_client.identities(),
        Err(AgentError::InvalidFrame)
    ));

    let mut failure_client = AgentClient::new(ScriptedAgent::new(frame(&[SSH_AGENT_FAILURE])?));
    assert!(matches!(
        failure_client.identities(),
        Err(AgentError::AgentFailure)
    ));
    Ok(())
}

#[test]
fn rejects_trailing_bytes_after_a_complete_sign_response() -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_AGENT_SIGN_RESPONSE);
    writer.write_string(&[0x01, 0x02][..])?;
    writer.write_byte(0);
    let mut client = AgentClient::new(ScriptedAgent::new(frame(&writer.into_bytes())?));

    assert!(matches!(
        client.sign(&key_blob(b"ssh-ed25519", &[0x66])?, b"data"),
        Err(AgentError::InvalidFrame)
    ));
    Ok(())
}

#[test]
fn rejects_an_unexpected_success_message() -> Result<(), Box<dyn Error>> {
    let mut client = AgentClient::new(ScriptedAgent::new(frame(&[0xff])?));

    assert!(matches!(
        client.identities(),
        Err(AgentError::UnexpectedMessage(0xff))
    ));
    Ok(())
}

fn key_blob(algorithm: &[u8], body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_string(&algorithm)?;
    writer.write_string(&body)?;
    Ok(writer.into_bytes())
}

fn sign_response(signature: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_AGENT_SIGN_RESPONSE);
    writer.write_string(&signature)?;
    frame(&writer.into_bytes())
}

fn frame(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = u32::try_from(payload.len())?;
    let mut encoded = length.to_be_bytes().to_vec();
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn next_request(encoded: &[u8], offset: &mut usize) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
    let header_end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_data("request offset overflow"))?;
    let header = encoded
        .get(*offset..header_end)
        .ok_or_else(|| invalid_data("missing request length"))?;
    let length = u32::from_be_bytes(header.try_into()?);
    let frame_end = header_end
        .checked_add(
            usize::try_from(length)
                .map_err(|_| invalid_data("request length does not fit usize"))?,
        )
        .ok_or_else(|| invalid_data("request length overflow"))?;
    let request = encoded
        .get(header_end..frame_end)
        .ok_or_else(|| invalid_data("truncated request"))?;
    let message = *request
        .first()
        .ok_or_else(|| invalid_data("request has no message"))?;
    let payload = request.to_vec();
    *offset = frame_end;
    Ok((message, payload))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
