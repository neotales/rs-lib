//! Round trip against a 16384-bit OpenSSH RSA key.
//!
//! The key is deliberately enormous. age supports SSH RSA recipients, and a
//! realistic key is 3072 or 4096 bits, which exercises the happy path far too
//! quickly to notice a performance or allocation problem. This one is slow on
//! purpose, which is also why it is committed rather than generated: generating
//! a key this size takes long enough to dominate the test run.
//!
//! It is a generated test vector, not a credential. See the fixture ticket for
//! where that is recorded.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_age::{AgeFile, AgeIdentity, AgeRecipient, SshRsaKey};

const RSA_16384_PUBLIC: &str = include_str!("data/rsa-16384-test-vector.pub");
const RSA_16384_PRIVATE: &str = include_str!("data/rsa-16384-test-vector.key");

// The slow lane, and why it is slow. 7.8s measured on this machine at
// `bb91e6e`; it is marked rather than weakened because the cost is a property of
// the *fixture* -- 16384-bit RSA key generation is 30-40 s of it and is inherent to the size -- and a cheaper fixture would be a different test.
// The long lane in `.gitea/workflows/ci.yml` runs it with `--include-ignored`.
#[ignore = "slow lane: run by the CI long lane, see eng/README.md"]
#[test]
fn rsa_16384_openssh_key_round_trips() {
    let public = SshRsaKey::parse_public_key(RSA_16384_PUBLIC).expect("public RSA key");
    let recipient = AgeRecipient::from_ssh_rsa_key(public);
    let identity = AgeIdentity::from_ssh_private_key(RSA_16384_PRIVATE).expect("private RSA key");

    let encrypted = AgeFile::encrypt(b"16384-bit SSH RSA", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"16384-bit SSH RSA"
    );
}
