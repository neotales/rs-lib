//! An exhaustive truncation sweep over the X.509 and SSH parsers.
//!
//! The age sweep exists because a container has length fields and a parser that
//! trusts one without checking walks off the end of a buffer at a length nobody
//! picked in advance. Every parser in this crate is a worse case than that,
//! because the length is not merely in the bytes, it is *read out of the bytes*
//! and used to slice. [`ssh::from_ssh_wire`] takes a four-byte big-endian length
//! and returns the next `length` bytes; [`openssh_cert::parse`] and
//! [`ssh_cert::parse_certificate`] do the same a dozen times over, for the nonce,
//! the certified key, each principal, each option, and the signature. The DER
//! walkers behind [`ssh::to_ssh_wire`] and
//! [`openssh_cert::x509_to_openssh_certificate`] do the same recursively.
//!
//! So this file enumerates, for every parser in `neotales-x509` a caller can
//! hand bytes to:
//!
//! | entry point | input | what a cut can break |
//! |---|---|---|
//! | [`ssh::to_ssh_wire`] | certificate DER | the recursive DER length walk |
//! | [`openssh_cert::x509_to_openssh_certificate`] | certificate DER | the same walk, plus the ASN.1 times |
//! | [`ssh::from_ssh_wire`] | RFC 6187 blob | two SSH string lengths |
//! | [`ssh::from_authorized_key`] | authorized-key line | base-64, then the blob |
//! | [`openssh_cert::parse`] | OpenSSH v01 certificate | a dozen SSH string lengths |
//! | [`ssh_cert::parse_certificate`] | OpenSSH certificate | the same, in a second implementation |
//!
//! Every one of them asserts a typed error whose classification matches the
//! offset the cut landed at, never a panic, and never a hang.
//!
//! # The interesting property of a prefix
//!
//! A prefix of a well-formed blob is *short*, never *malformed*. Every field
//! that the cut did reach still has its correct length, and every field it did
//! not reach is missing. So a correct parser reports the framing failure at
//! every offset, and the sweep's real content is the negative claim: no offset
//! may produce a *content* error. A cut that reported `UnsupportedAlgorithm`,
//! `InvalidFieldLength`, `InvalidPrincipal`, `Expired`, or
//! `PrincipalMismatch` would mean the reader ran past the end of the buffer and
//! made an assertion about bytes it never received. That is why these sweeps
//! assert the *specific* variant rather than `is_err()`, and why the places a
//! content error can legitimately appear — a full-length input with a flipped
//! byte, or a verifier asked a question the certificate does not answer — are
//! asserted separately as controls.
//!
//! # Cost
//!
//! The fixtures are 265 bytes of DER, a 291-byte SSH blob, a 348-byte
//! certificate, and a 407-character line, so the whole file is about four
//! thousand parses of inputs a few hundred bytes long. The OpenSSH certificate
//! is built from fixed 32-byte seeds and signed with deterministic Ed25519, so
//! every run sweeps exactly the same bytes; the sizes are asserted rather than
//! assumed. `verify_certificate` and `openssh_cert::parse` each do one
//! signature verification per cut, which is the expensive part and still lands
//! the file in the default suite at a tenth of a second.
//!
//! # The DER fixture's validity window
//!
//! The pinned certificate expires in 2045, which is deliberate. RFC 5280
//! requires `GeneralizedTime` for a validity date on or after 2050, so a
//! certificate inside the `UTCTime` window exercises the two-digit-year branch
//! of `parse_x509_time` in `openssh_cert`, and the four-digit-year branch is
//! covered by the boundary fixtures in the `validity_times` sweep instead.
//! Keeping the
//! two sweeps on different fixtures means neither is the only evidence for the
//! branch it does not cover, and it means a change to either one does not
//! silently move the other's date.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
//! still reported.
#![allow(missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use neotales_x509::{
    OpenSshCertError, SshX509Error,
    openssh_cert::{self, OpenSshCertKind, OpenSshCertRequest},
    ssh,
    ssh_cert::{self, CertificateError, CertificateType, WireError},
};

/// A real Ed25519 certificate, issued once and pinned here.
///
/// Generated with `openssl req -new -x509 -key <ed25519> -days 7000 -subj
/// /CN=truncation.sweep -set_serial 7`, then pasted. 265 bytes of DER: small
/// enough that a full sweep is a few hundred parses, and real enough that the
/// DER walker sees a genuine certificate rather than a hand-written
/// approximation. It carries a subject key identifier extension, so the walk
/// descends into a context-specific constructed tag as well as the universal
/// ones.
const CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBBTCBuKADAgECAgEHMAUGAytlcDAbMRkwFwYDVQQDDBB0cnVuY2F0aW9uLnN3\n\
ZWVwMB4XDTI2MDkyODAwNTQyN1oXDTQ1MTEyNzAwNTQyN1owGzEZMBcGA1UEAwwQ\n\
dHJ1bmNhdGlvbi5zd2VlcDAqMAUGAytlcAMhAPtuTCye/ZeaFXZzWSCPOM6nQTXD\n\
/TFbwnV+OuQ7VfeVoyEwHzAdBgNVHQ4EFgQURw+KWE5Z6Ic3k0D8klYhP/0U1Ykw\n\
BQYDK2VwA0EAVNm99sc2Utwny0DJgAoFAdfHUYkYTqyb4OvCmWxKuqHvIsOaa7fm\n\
tefWRHSuW78QYE6usOyCWHGKUieMeypqBg==\n\
-----END CERTIFICATE-----\n";

/// The principal every certificate fixture certifies.
const PRINCIPAL: &str = "server.example";
/// The key identifier every certificate fixture carries.
const KEY_ID: &str = "sweep";
/// The SSH key type length, which is the length of `x509v3-ssh-ed25519`.
const KEY_TYPE: usize = 18;
/// The certificate algorithm name the OpenSSH fixtures carry, which is
/// `ssh-ed25519-cert-v01@openssh.com`.
const ALGORITHM_LENGTH: usize = 32;
/// The outer SSH string that carries the detached signature: a four-byte
/// length, the signature blob's algorithm string, and the signature itself.
/// 4 + (4 + 11) + (4 + 64).
const SIGNATURE_STRING: usize = 4 + (4 + 11) + (4 + 64);
/// The offset of that string's length field, counted back from the end.
const fn signature_at(total: usize) -> usize {
    total - SIGNATURE_STRING
}

/// The offsets worth naming in an OpenSSH certificate fixture, on top of the
/// exhaustive sweep.
///
/// The loop below already covers every length, so this list is not extra
/// coverage — it is the claim about *which* offsets are the interesting ones,
/// written down. Both certificate parsers are swept against it, so a reader
/// that is only checked at the offsets one of them happens to have in front of
/// it is not the situation.
fn named_offsets(total: usize) -> Vec<usize> {
    let signature = signature_at(total);
    vec![
        // Inside the algorithm string's four-byte length, and inside its name.
        1,
        4,
        5,
        24,
        31,
        // Either side of the nonce's length field, and its last byte.
        4 + ALGORITHM_LENGTH,
        5 + ALGORITHM_LENGTH,
        8 + ALGORITHM_LENGTH,
        // The certified key, the serial, and the type.
        4 + ALGORITHM_LENGTH + 7,
        4 + ALGORITHM_LENGTH + 39,
        4 + ALGORITHM_LENGTH + 47,
        // Either side of the signature's outer length field, and the first four
        // bytes of the signature blob.
        signature,
        signature + 1,
        signature + 4,
        // The last byte of the whole certificate.
        total - 1,
    ]
}

fn ssh_string(value: &[u8]) -> Vec<u8> {
    let length = u32::try_from(value.len()).expect("fixture SSH value is short");
    let mut encoded = length.to_be_bytes().to_vec();
    encoded.extend_from_slice(value);
    encoded
}

/// A fixed 32-byte seed, so every fixture is byte-for-byte reproducible.
fn seed_range(start: u8) -> [u8; 32] {
    std::array::from_fn(|index| start + u8::try_from(index).expect("fixture seed offset is small"))
}

fn certificate_der() -> Vec<u8> {
    neotales_x509::pem::decode(CERTIFICATE_PEM, "CERTIFICATE").expect("fixture certificate")
}

fn signing_key(start: u8) -> SigningKey {
    SigningKey::from_bytes(&seed_range(start))
}

/// Assembles a signed OpenSSH certificate from its signed part.
///
/// The fixture carries a nonce, a certified key, a key identifier, one
/// principal, one critical option with a nested value, and one extension, so a
/// truncation sweep over it crosses six nested string boundaries rather than
/// only the outer ones.
///
/// `openssh_cert` and `ssh_cert` are two independent implementations of the
/// same wire format. The two builders are the same code because the bytes are
/// the same bytes, but the *parsers* they feed are not, and that is what is
/// worth sweeping: a fix to one parser's reader would not be a fix to the
/// other's.
fn signed_certificate() -> (Vec<u8>, [u8; 32]) {
    let authority = signing_key(0);
    let subject = signing_key(32).verifying_key().to_bytes();
    let authority_point = authority.verifying_key().to_bytes();

    let mut authority_blob = Vec::new();
    authority_blob.extend_from_slice(&ssh_string(b"ssh-ed25519"));
    authority_blob.extend_from_slice(&ssh_string(&authority_point));

    let mut principals = Vec::new();
    principals.extend_from_slice(&ssh_string(PRINCIPAL.as_bytes()));

    let mut critical = Vec::new();
    critical.extend_from_slice(&ssh_string(b"force-command"));
    critical.extend_from_slice(&ssh_string(&ssh_string(b"/usr/bin/true")));

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&ssh_string(b"permit-pty"));
    extensions.extend_from_slice(&ssh_string(&[]));

    let mut signed = Vec::new();
    signed.extend_from_slice(&ssh_string(b"ssh-ed25519-cert-v01@openssh.com"));
    signed.extend_from_slice(&ssh_string(&[1, 2, 3]));
    signed.extend_from_slice(&ssh_string(&subject));
    signed.extend_from_slice(&1_u64.to_be_bytes());
    signed.extend_from_slice(&1_u32.to_be_bytes());
    signed.extend_from_slice(&ssh_string(KEY_ID.as_bytes()));
    signed.extend_from_slice(&ssh_string(&principals));
    signed.extend_from_slice(&0_u64.to_be_bytes());
    signed.extend_from_slice(&u64::MAX.to_be_bytes());
    signed.extend_from_slice(&ssh_string(&critical));
    signed.extend_from_slice(&ssh_string(&extensions));
    signed.extend_from_slice(&ssh_string(&[]));
    signed.extend_from_slice(&ssh_string(&authority_blob));

    let signature = authority.sign(&signed);
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&ssh_string(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&ssh_string(&signature.to_bytes()));

    let mut blob = signed;
    blob.extend_from_slice(&ssh_string(&signature_blob));
    (blob, authority_point)
}

/// Every length of a real certificate, through the DER walker in
/// [`ssh::to_ssh_wire`].
///
/// `to_ssh_wire` is the only entry point in the crate whose whole job is
/// "parse this DER and tell me the SSH key type", so it is the direct way to
/// reach the recursive length walk. The certificate has a three-byte outer
/// length, so the very first cut already points the walk past the end of the
/// buffer, and every subsequent cut lands somewhere inside a TLV that the walk
/// has already accepted.
#[test]
fn every_truncation_of_a_certificate_is_a_typed_error() {
    let der = certificate_der();
    assert_eq!(der.len(), 265, "the DER fixture is pinned");

    // The full certificate converts, and the key type it reports is the one a
    // truncation must never be able to report.
    let wire = ssh::to_ssh_wire(&der).expect("fixture conversion");
    assert_eq!(wire.len(), 4 + KEY_TYPE + 4 + der.len());
    assert_eq!(&wire[..4], &[0, 0, 0, 18]);
    assert_eq!(&wire[4..4 + KEY_TYPE], b"x509v3-ssh-ed25519");
    assert_eq!(ssh::from_ssh_wire(&wire).expect("round trip"), der);

    for length in 0..der.len() {
        assert_eq!(
            ssh::to_ssh_wire(&der[..length]),
            Err(SshX509Error::InvalidCertificate),
            "DER length {length} should be rejected as an invalid certificate"
        );
    }

    // And the offsets that matter: the outer length field, each nesting level's
    // header, and the last byte of the signature bit string. A cut at any of
    // them is a different walk state and none of them may be accepted.
    for length in [
        1usize, 2, 3, 4, 5, 7, 12, 15, 17, 22, 51, 68, 83, 114, 158, 193, 264,
    ] {
        assert_eq!(
            ssh::to_ssh_wire(&der[..length]),
            Err(SshX509Error::InvalidCertificate),
            "DER length {length} should be rejected as an invalid certificate"
        );
    }
}

/// Every length of a real certificate, through
/// [`openssh_cert::x509_to_openssh_certificate`].
///
/// This is the second copy of the DER walk, in a different module, and it is
/// worth sweeping separately: a fix to one copy would not be a fix to the
/// other, and the two disagree about more than names. This one also reads the
/// two ASN.1 times, which is the only place in the crate where a two-character
/// number is parsed out of a string.
///
/// Note on the fixture: the certificate's validity is inside the `UTCTime`
/// window on purpose, so the sweep drives the two-digit-year branch of
/// `parse_x509_time`. The four-digit-year branch RFC 5280 requires for a
/// validity date before 1950 or on or after 2050 is covered by the boundary
/// fixtures in `validity_times`, including the years 2049 and 2050 either side
/// of the change. Both files convert a complete certificate before sweeping it,
/// so a full-length conversion that stopped working would fail here first.
#[test]
fn every_truncation_of_a_certificate_for_openssh_is_a_typed_error() {
    let der = certificate_der();
    let request = OpenSshCertRequest {
        kind: OpenSshCertKind::Host,
        serial: 7,
        key_id: KEY_ID.to_owned(),
        principals: vec![PRINCIPAL.to_owned()],
        nonce: vec![9, 9],
        critical_options: Vec::new(),
        extensions: Vec::new(),
    };

    let blob = openssh_cert::x509_to_openssh_certificate(&der, &request, &seed_range(0))
        .expect("fixture conversion");
    assert_eq!(
        openssh_cert::parse(&blob).expect("fixture parses").key_id,
        KEY_ID
    );

    for length in 0..der.len() {
        assert_eq!(
            openssh_cert::x509_to_openssh_certificate(&der[..length], &request, &seed_range(0))
                .map(|_| ()),
            Err(OpenSshCertError::InvalidCertificate),
            "DER length {length} should be rejected before any time is read"
        );
    }
}

/// Every length of a real RFC 6187 SSH public-key blob.
///
/// The blob is two SSH strings, so a cut has to be classified by which of the
/// two it lands in. Both are `InvalidSsh`, which is correct, but the assertion
/// is that the *content* errors — `InvalidCertificate` and
/// `UnsupportedAlgorithm`, both of which are reachable from a complete blob with
/// the wrong bytes — never appear, because a cut cannot have produced a
/// certificate to mis-parse.
#[test]
fn every_truncation_of_an_ssh_wire_blob_is_a_typed_error() {
    let der = certificate_der();
    let wire = ssh::to_ssh_wire(&der).expect("fixture conversion");
    assert_eq!(wire.len(), 4 + KEY_TYPE + 4 + der.len());

    // The two offsets worth naming: the end of the first string, which is where
    // the second string's length field begins, and the last byte of the
    // certificate inside the second string.
    let second_length_at = 4 + KEY_TYPE;
    let certificate_at = second_length_at + 4;

    for length in 0..wire.len() {
        assert_eq!(
            ssh::from_ssh_wire(&wire[..length]).map(|_| ()),
            Err(SshX509Error::InvalidSsh),
            "wire length {length} should be rejected as invalid SSH framing"
        );
    }
    for length in [
        1usize,
        3,
        4,
        second_length_at - 1,
        second_length_at,
        second_length_at + 1,
        second_length_at + 3,
        certificate_at,
        certificate_at + 1,
        wire.len() - 1,
    ] {
        assert_eq!(
            ssh::from_ssh_wire(&wire[..length]).map(|_| ()),
            Err(SshX509Error::InvalidSsh),
            "wire length {length} should be rejected as invalid SSH framing"
        );
    }

    // The control: a complete blob with the key type altered is a *content*
    // failure, not a framing one. This is what proves the sweep is not just
    // accepting any error at all.
    let mut wrong_type = wire.clone();
    wrong_type[4] = b'X';
    assert_eq!(
        ssh::from_ssh_wire(&wrong_type).map(|_| ()),
        Err(SshX509Error::InvalidSsh),
        "a mismatched key type is a framing failure here"
    );
    let mut zero_length = wire.clone();
    zero_length[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        ssh::from_ssh_wire(&zero_length).map(|_| ()),
        Err(SshX509Error::InvalidSsh)
    );
    // Trailing data after the second string is rejected rather than ignored.
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_eq!(
        ssh::from_ssh_wire(&trailing).map(|_| ()),
        Err(SshX509Error::InvalidSsh)
    );
}

/// Every length of a real authorized-key line.
///
/// The line is text, so the truncation is a cut in the base-64, and the
/// interesting boundary is the one at the end of the alphabet: base-64 with
/// canonical padding has three lengths, 72, 73, and 74, at the tail where a
/// final group carries two bytes, one byte, or none. Every one of them has to
/// be rejected, and a decoder that completed the partial group rather than
/// rejecting it would produce a short certificate here rather than an error.
///
/// A cut that lands between the key type and the alphabet is the other
/// boundary: there is a space there, and a parser that reached for the second
/// field without checking would have nothing to hand to the base-64 decoder.
#[test]
fn every_truncation_of_an_authorized_key_line_is_a_typed_error() {
    let der = certificate_der();
    let line = ssh::to_authorized_key(&der).expect("fixture conversion");
    let alphabet_at = KEY_TYPE + 1;
    assert_eq!(&line[..KEY_TYPE], "x509v3-ssh-ed25519");
    assert_eq!(
        line.as_bytes()[KEY_TYPE],
        b' ',
        "the key type and the alphabet are separated by one space"
    );
    assert_eq!(
        line.len(),
        alphabet_at + 4 * ssh::to_ssh_wire(&der).expect("fixture").len().div_ceil(3),
        "the line is the key type, a space, and the padded blob"
    );

    assert_eq!(ssh::from_authorized_key(&line).expect("full"), der);

    for length in 0..line.len() {
        let cut = &line[..length];
        let error = ssh::from_authorized_key(cut)
            .err()
            .unwrap_or_else(|| panic!("authorized-key length {length} was accepted"));
        assert_eq!(
            error,
            SshX509Error::InvalidSsh,
            "authorized-key length {length} should be rejected as invalid SSH"
        );
    }

    // The space between the key type and the alphabet, both ways round.
    for length in [alphabet_at - 1, alphabet_at] {
        assert_eq!(
            ssh::from_authorized_key(&line[..length]),
            Err(SshX509Error::InvalidSsh),
            "a line with no alphabet at all must be rejected"
        );
    }
    // The three canonical final-group lengths.
    for length in [line.len() - 3, line.len() - 2, line.len() - 1] {
        assert_eq!(
            ssh::from_authorized_key(&line[..length]),
            Err(SshX509Error::InvalidSsh),
            "a partial final base-64 group must be rejected"
        );
    }
    // Trailing text is a comment and is allowed; trailing *whitespace* is too.
    assert_eq!(
        ssh::from_authorized_key(&format!("  {line} a comment  ")).expect("comment"),
        der
    );
}

/// Every length of a real OpenSSH v01 certificate.
///
/// The fixture has a nonce, a certified key, a key identifier, one principal,
/// one critical option with a nested value, and one extension, so the sweep
/// crosses six nested string boundaries and not only the outer ones. A cut
/// inside the nested option value has to be caught by the inner reader rather
/// than being handed to the outer one as a short option.
///
/// [`openssh_cert::openssh_certificate_to_x509_identity`] takes the same bytes
/// and delegates the entire wire format to [`openssh_cert::parse`], so it is
/// swept here alongside its caller and asserted to agree at every offset. A
/// divergence between the two is itself a finding.
#[test]
fn every_truncation_of_an_openssh_v01_certificate_is_a_typed_error() {
    let (blob, _) = signed_certificate();
    assert_eq!(blob.len(), 348, "the OpenSSH certificate fixture is pinned");

    let certificate = openssh_cert::parse(&blob).expect("fixture parses");
    assert_eq!(certificate.key_id, KEY_ID);
    assert_eq!(certificate.principals, [PRINCIPAL.to_owned()]);
    assert_eq!(certificate.critical_options.len(), 1);
    assert_eq!(certificate.extensions.len(), 1);
    assert_eq!(
        openssh_cert::to_wire(&certificate).expect("wire round trip"),
        blob
    );

    // Every offset below the full length is a framing failure. Content errors
    // are not reachable from a prefix, and asserting the exact variant is what
    // says so.
    for length in 0..blob.len() {
        assert_eq!(
            openssh_cert::parse(&blob[..length]).map(|_| ()),
            Err(OpenSshCertError::InvalidSsh),
            "v01 length {length} should be rejected as invalid SSH framing"
        );
        assert_eq!(
            openssh_cert::openssh_certificate_to_x509_identity(&blob[..length]).map(|_| ()),
            Err(OpenSshCertError::InvalidSsh),
            "identity length {length} should agree with the parser it delegates to"
        );
    }

    // The named offsets, defined once and shared with the other certificate
    // parser's sweep.
    for length in named_offsets(blob.len()) {
        assert_eq!(
            openssh_cert::parse(&blob[..length]).map(|_| ()),
            Err(OpenSshCertError::InvalidSsh),
            "v01 length {length} should be rejected as invalid SSH framing"
        );
    }

    // The controls that prove the sweep is not accepting any error at all: a
    // full-length blob with a flipped signature byte is a signature failure, and
    // a full-length blob with a flipped algorithm byte is a content failure.
    // Neither is the framing failure a truncation produces.
    let mut bad_signature = blob.clone();
    *bad_signature
        .last_mut()
        .expect("the fixture has a signature byte") ^= 1;
    assert_eq!(
        openssh_cert::parse(&bad_signature).map(|_| ()),
        Err(OpenSshCertError::BadSignature)
    );
    let mut bad_algorithm = blob.clone();
    bad_algorithm[4] = b'X';
    assert_eq!(
        openssh_cert::parse(&bad_algorithm).map(|_| ()),
        Err(OpenSshCertError::UnsupportedAlgorithm)
    );
    // And an empty nonce at full length, which is a content failure the cut
    // offsets can never produce. The nonce's length field follows the algorithm
    // string, whose own length is asserted rather than assumed.
    assert_eq!(
        &blob[4..4 + ALGORITHM_LENGTH],
        b"ssh-ed25519-cert-v01@openssh.com"
    );
    let mut empty_nonce = blob.clone();
    empty_nonce[4 + ALGORITHM_LENGTH..8 + ALGORITHM_LENGTH].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        openssh_cert::parse(&empty_nonce).map(|_| ()),
        Err(OpenSshCertError::InvalidCertificate)
    );
}

/// Every length of a real OpenSSH certificate, through both of
/// `neotales-x509`'s certificate parsers.
///
/// This is a second, independent implementation of the same wire format, with
/// its own reader, its own `CertificateError` taxonomy, and its own CA
/// verification. It is swept together with [`ssh_cert::verify_certificate`]
/// because the verifier's first act is to call the parser: a prefix that
/// reached the policy checks at all would mean the parser accepted a short
/// blob, and the policy errors — `PrincipalMismatch`, `Expired`,
/// `CriticalOptionNotAllowed` — are exactly what would be reported next. So the
/// sweep asserts the failure is always `Wire(Truncated)` and never a policy
/// error, which is the same negative claim the module doc makes.
#[test]
fn every_truncation_of_an_ssh_certificate_is_a_typed_error() {
    let (blob, ca) = signed_certificate();
    assert_eq!(blob.len(), 348, "the OpenSSH certificate fixture is pinned");

    // The full certificate parses, and the verifier accepts it with the right
    // role, principal, and authority key.
    let certificate = ssh_cert::parse_certificate(&blob).expect("fixture parses");
    assert_eq!(certificate.key_id(), KEY_ID);
    assert_eq!(certificate.principals(), &[PRINCIPAL.to_owned()]);
    assert_eq!(certificate.extensions().len(), 1);
    assert_eq!(
        ssh_cert::verify_certificate(
            &blob,
            CertificateType::User,
            PRINCIPAL,
            1,
            &["force-command"],
            &ca,
        )
        .expect("fixture verifies")
        .algorithm(),
        "ssh-ed25519-cert-v01@openssh.com"
    );

    for length in 0..blob.len() {
        assert_eq!(
            ssh_cert::parse_certificate(&blob[..length]).map(|_| ()),
            Err(CertificateError::Wire(WireError::Truncated)),
            "ssh_cert length {length} should be a wire truncation"
        );
        assert_eq!(
            ssh_cert::verify_certificate(
                &blob[..length],
                CertificateType::User,
                PRINCIPAL,
                1,
                &["force-command"],
                &ca,
            )
            .map(|_| ()),
            Err(CertificateError::Wire(WireError::Truncated)),
            "verify length {length} should be a wire truncation, not a policy failure"
        );
    }

    // The named offsets, defined once and shared with the other certificate
    // parser's sweep.
    for length in named_offsets(blob.len()) {
        assert_eq!(
            ssh_cert::parse_certificate(&blob[..length]).map(|_| ()),
            Err(CertificateError::Wire(WireError::Truncated)),
            "ssh_cert length {length} should be a wire truncation"
        );
    }

    // The controls: a full-length blob with a flipped signature byte parses
    // cleanly and is rejected by verification, and a full-length blob with a
    // flipped algorithm byte is a content failure. Neither may be mistaken for
    // the framing failure a truncation produces.
    let mut bad_signature = blob.clone();
    *bad_signature
        .last_mut()
        .expect("the fixture has a signature byte") ^= 1;
    assert!(
        ssh_cert::parse_certificate(&bad_signature).is_ok(),
        "parsing does not verify the signature"
    );
    assert_eq!(
        ssh_cert::verify_certificate(
            &bad_signature,
            CertificateType::User,
            PRINCIPAL,
            1,
            &["force-command"],
            &ca,
        )
        .map(|_| ()),
        Err(CertificateError::InvalidSignature)
    );
    let mut bad_algorithm = blob.clone();
    bad_algorithm[4] = b'X';
    assert_eq!(
        ssh_cert::parse_certificate(&bad_algorithm).map(|_| ()),
        Err(CertificateError::UnsupportedAlgorithm)
    );

    // And the policy errors the sweep says a truncation may not produce, on the
    // full-length blob. A cut that reached any of these would mean the reader
    // ran past the end of the buffer and started making assertions about bytes
    // it never received.
    let force_command: &[&str] = &["force-command"];
    for (role, principal, allowed, expected) in [
        (
            CertificateType::Host,
            PRINCIPAL,
            force_command,
            CertificateError::TypeMismatch,
        ),
        (
            CertificateType::User,
            "other.example",
            force_command,
            CertificateError::PrincipalMismatch,
        ),
        (
            CertificateType::User,
            PRINCIPAL,
            &[] as &[&str],
            CertificateError::CriticalOptionNotAllowed,
        ),
    ] {
        assert_eq!(
            ssh_cert::verify_certificate(&blob, role, principal, 1, allowed, &ca).map(|_| ()),
            Err(expected),
            "{expected:?} is reachable at full length, so a cut must not reach it"
        );
    }
}
