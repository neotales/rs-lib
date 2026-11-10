//! Client identity keys beyond Ed25519 and RSA.
//!
//! # What this file is for
//!
//! `PublicKeySigner` and `OpenSshPrivateKey` were closed enums carrying
//! `Ed25519` and `Rsa` and nothing else, so a downstream crate could not
//! express an ECDSA identity or an agent-held key at all. There was no
//! constructor to call, and `cargo build` said so:
//!
//! ```text
//! error[E0599]: no variant, associated function, or constant named `agent` found
//!               for enum `PublicKeySigner` in the current scope
//! ```
//!
//! No cryptography was missing. `EcdsaSigner` could already sign and produce a
//! public-key blob, and `AgentClient` could already list identities and sign.
//! What was missing was a variant on each enum and the plumbing to fill it, and
//! that is the whole of this change.
//!
//! # What the agent variant deliberately is not
//!
//! `AgentKeySigner` holds the exact key blob it will ask the agent about and
//! reports `AuthError::AgentUnavailable` when the agent will not answer. There
//! is no local key behind it. A variant that quietly authenticated with a local
//! key while claiming to be an agent identity would be worse than its absence,
//! so `an_agent_key_never_falls_back_to_a_local_key` pins the failure instead.
//!
//! # Live lanes
//!
//! `openssh_identities.rs` drives both against a real `sshd` and a real
//! `ssh-agent`.

#![allow(missing_docs)]

use neotales_ssh::agent::{AgentClient, AgentError};
use neotales_ssh::auth::{AgentKeySigner, ClientAuthMethod, PublicKeySigner, RsaAuthSigner};
use neotales_ssh::ecdsa_hostkey::{ECDSA_SECRET_SCALAR_LENGTH, EcdsaSigner};
use neotales_ssh::hostkey::Ed25519Signer;

/// A scalar that is inside the P-256 group order, for constructing a signer.
fn valid_scalar() -> [u8; ECDSA_SECRET_SCALAR_LENGTH] {
    let mut scalar = [0_u8; ECDSA_SECRET_SCALAR_LENGTH];
    scalar[31] = 0x42;
    scalar
}

/// The public-key blob `ssh-keygen`-style algorithms are named by: the first SSH
/// string is the key type, which is what an agent is asked to sign with.
fn blob_algorithm(blob: &[u8]) -> String {
    let length = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    String::from_utf8_lossy(&blob[4..4 + length]).into_owned()
}

#[test]
fn an_ecdsa_identity_names_its_own_algorithm_and_blob() -> Result<(), Box<dyn std::error::Error>> {
    let signer = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let blob = signer.public_key_blob()?;

    let identity = PublicKeySigner::ecdsa(signer);
    assert_eq!(identity.algorithm(), "ecdsa-sha2-nistp256");
    assert_eq!(identity.public_key_blob()?, blob);
    assert_eq!(blob_algorithm(&blob), "ecdsa-sha2-nistp256");
    // It is an identity key, not a host key: this says nothing about
    // `SUPPORTED_HOST_KEY_ALGORITHMS`, which is a separate and deliberate
    // Ed25519-only policy.
    assert!(!identity.is_external());
    Ok(())
}

#[test]
fn an_ecdsa_signature_is_a_well_formed_ssh_signature_blob() -> Result<(), Box<dyn std::error::Error>>
{
    use neotales_ssh::Reader;
    let signer = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let signature = signer.sign_exchange_hash(b"the session id and request prefix")?;
    let mut reader = Reader::new(&signature);
    let algorithm = reader.read_string()?;
    assert_eq!(algorithm, b"ecdsa-sha2-nistp256");
    let body = reader.read_string()?;
    assert!(reader.is_empty(), "the signature has trailing bytes");
    // The body is two mpints, r and s, and both are 32 bytes for P-256.
    let mut body_reader = Reader::new(body);
    let r = body_reader.read_mpint()?;
    let s = body_reader.read_mpint()?;
    assert!(body_reader.is_empty());
    assert!(r.len() <= 33 && s.len() <= 33);
    Ok(())
}

#[test]
fn an_agent_key_names_its_key_type_and_the_flags_that_key_needs()
-> Result<(), Box<dyn std::error::Error>> {
    // An Ed25519 agent key: flag 0, because the format identifier is the key
    // type name.
    let ed25519 = Ed25519Signer::from_seed(&mut [7_u8; 32]);
    let ed25519_blob = ed25519.public_key_blob()?;
    let agent = AgentKeySigner::new(AgentClient::new(std::io::empty()), &ed25519_blob)?;
    assert_eq!(agent.algorithm(), "ssh-ed25519");
    assert_eq!(agent.flags(), 0);
    assert_eq!(agent.key_blob(), ed25519_blob.as_slice());
    assert!(PublicKeySigner::agent(agent).is_external());

    // An RSA agent key: the SHA-2 variant has to be requested, or OpenSSH's
    // `agent_decode_alg` returns null and the agent produces the SHA-1
    // signature this crate will not accept.
    let rsa_blob = vec![0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a'];
    let rsa = AgentKeySigner::new(AgentClient::new(std::io::empty()), &rsa_blob)?;
    assert_eq!(rsa.algorithm(), "rsa-sha2-256");
    assert_eq!(rsa.flags(), neotales_ssh::agent::SSH_AGENT_RSA_SHA2_256);

    // An ECDSA agent key: flag 0, and `AgentClient` now accepts the type.
    let ecdsa = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let ecdsa_blob = ecdsa.public_key_blob()?;
    let agent = AgentKeySigner::new(AgentClient::new(std::io::empty()), &ecdsa_blob)?;
    assert_eq!(agent.algorithm(), "ecdsa-sha2-nistp256");
    assert_eq!(agent.flags(), 0);
    Ok(())
}

#[test]
fn an_agent_key_never_falls_back_to_a_local_key() -> Result<(), Box<dyn std::error::Error>> {
    // A key type this crate cannot ask an agent about is rejected at
    // construction, not quietly replaced with something else.
    let unsupported = vec![0, 0, 0, 9, b's', b's', b'h', b'-', b'd', b's', b's'];
    let error = AgentKeySigner::new(AgentClient::new(std::io::empty()), &unsupported)
        .expect_err("an unsupported key type must be refused");
    assert_eq!(error, neotales_ssh::auth::AuthError::InvalidKey);

    // A blob that is not even a string is refused the same way.
    let malformed = [0xff_u8, 0xff, 0xff, 0xff];
    assert!(AgentKeySigner::new(AgentClient::new(std::io::empty()), &malformed).is_err());

    // And an agent that cannot answer reports that, rather than authenticating
    // as something it is not: there is no local key to fall back on, so an
    // unreachable agent is the end of the attempt.
    let ecdsa = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let blob = ecdsa.public_key_blob()?;
    let agent = AgentKeySigner::new(AgentClient::new(std::io::empty()), &blob)?;
    assert_eq!(
        agent.sign(b"anything"),
        Err(neotales_ssh::auth::AuthError::AgentUnavailable)
    );
    Ok(())
}

/// An agent that holds nothing answers with `SSH_AGENT_FAILURE`, and the signer
/// reports that as an unavailable identity rather than as a transport error.
#[test]
fn an_agent_without_the_key_reports_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    /// A scripted agent transport: one response frame, then silence.
    #[derive(Default)]
    struct ScriptedAgent {
        response: Option<Vec<u8>>,
        request: Vec<u8>,
    }

    impl Read for ScriptedAgent {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(response) = self.response.as_mut() else {
                return Ok(0);
            };
            let count = buffer.len().min(response.len());
            for slot in buffer.iter_mut().take(count) {
                *slot = response.remove(0);
            }
            Ok(count)
        }
    }

    impl Write for ScriptedAgent {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.request.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // A four-byte length prefix and message 5, which is `SSH_AGENT_FAILURE`.
    let mut failure = 1_u32.to_be_bytes().to_vec();
    failure.push(5);
    let agent = ScriptedAgent {
        response: Some(failure),
        request: Vec::new(),
    };
    let ecdsa = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let blob = ecdsa.public_key_blob()?;
    let signer = AgentKeySigner::new(AgentClient::new(agent), &blob)?;
    assert_eq!(
        signer.sign(b"the signed bytes"),
        Err(neotales_ssh::auth::AuthError::AgentUnavailable)
    );
    Ok(())
}

#[test]
fn the_agent_client_accepts_an_ecdsa_key_type() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    /// Records the request the client made and replays one signature response.
    #[derive(Default)]
    struct Recorder {
        request: Vec<u8>,
        response: Vec<u8>,
    }

    impl Read for Recorder {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = buffer.len().min(self.response.len());
            for slot in buffer.iter_mut().take(count) {
                *slot = self.response.remove(0);
            }
            Ok(count)
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.request.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // The response body is one SSH string, so the signature needs its own
    // length prefix. A hand-written blob without one would be a fixture that
    // fails for the wrong reason.
    let signature_body = b"a-signature";
    let mut signature = u32::try_from(signature_body.len())?.to_be_bytes().to_vec();
    signature.extend_from_slice(signature_body);
    // The frame length covers the message byte as well as the string, because
    // `read_frame` reads exactly that many bytes after the prefix.
    let frame = 1_usize + signature.len();
    let mut response = u32::try_from(frame)?.to_be_bytes().to_vec();
    response.push(14); // SSH2_AGENT_SIGN_RESPONSE
    response.extend_from_slice(&signature);
    let mut recorder = Recorder {
        request: Vec::new(),
        response,
    };
    let ecdsa = EcdsaSigner::from_secret_scalar(&mut valid_scalar())?;
    let blob = ecdsa.public_key_blob()?;
    let (produced, request) = {
        let mut client = AgentClient::new(&mut recorder);
        let produced = client.sign(&blob, b"data to sign")?;
        (produced, recorder.request.clone())
    };
    // The client returns the string's bytes, not the enclosing frame.
    assert_eq!(produced, signature_body.to_vec());
    // The flags word is the last four bytes of the request, and for an ECDSA key
    // it must be zero.
    let flags = u32::from_be_bytes(
        request
            .get(request.len() - 4..)
            .ok_or("the agent request is truncated")?
            .try_into()
            .map_err(|_| "the flags word is four bytes")?,
    );
    assert_eq!(flags, 0, "an ECDSA agent key needs no SHA-2 flags word");

    // A key blob whose string length runs past the frame is refused, so the
    // extension above is a specific one rather than "anything goes".
    let refused = AgentClient::new(std::io::empty()).sign(&[0xff, 0xff, 0xff, 0x7f], b"data");
    assert!(
        matches!(refused, Err(AgentError::Wire(_))),
        "got {refused:?}"
    );
    Ok(())
}

#[test]
fn the_existing_signer_variants_are_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    // A guard on the two variants that already existed, because the ECDSA and
    // agent arms were added to the same match.
    let ed25519 = Ed25519Signer::from_seed(&mut [9_u8; 32]);
    let identity = PublicKeySigner::ed25519(ed25519);
    assert_eq!(identity.algorithm(), "ssh-ed25519");
    assert_eq!(blob_algorithm(&identity.public_key_blob()?), "ssh-ed25519");

    // The RSA constructor keeps its existing spelling and type.
    let rsa = RsaAuthSigner::from_p_q(
        rsa::BigUint::from_bytes_be(&hex(
            "fd2e217a58d0fda766b6ae4f3a088b0a081c18e7a5b5035466a87c5926a8b90\
             c2d8b18e3eecb91b4bb4f749dc528599446b26df51910cb43917234486a28cf07",
        )?),
        rsa::BigUint::from_bytes_be(&hex(
            "ccd0ae1cdb32ec05fe6e7a3704f8661e301147571d4fffedf49f676f47bfab1\
             aa197f8fe01bee547c2aee05775b708c5c2dfad737d294571068e126be5536f71",
        )?),
        rsa::BigUint::from(65537_u32),
    )?;
    let identity = PublicKeySigner::rsa(rsa);
    assert_eq!(identity.algorithm(), "rsa-sha2-256");
    assert_eq!(blob_algorithm(&identity.public_key_blob()?), "ssh-rsa");

    // The method wrapper is what a caller reaches for.
    let method = ClientAuthMethod::public_key(PublicKeySigner::ecdsa(
        EcdsaSigner::from_secret_scalar(&mut valid_scalar())?,
    ));
    assert!(!format!("{method:?}").is_empty());
    Ok(())
}

/// Decodes a fixed hex literal, ignoring the line breaks in this file's source.
fn hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        return Err("the fixed hex has an odd length".into());
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
