//! An exhaustive truncation sweep over a real age container.
//!
//! The crate already covers malformed input well, and by kind: a cut header, a
//! bad MAC, tampered ciphertext, oversized limits, a padded header MAC. Those
//! are chosen offsets, and chosen offsets encode what the person who wrote the
//! test thought to try. A binary format has length fields, and a parser that
//! trusts one without checking walks off the end of a buffer at a length nobody
//! picked in advance. Enumerating every length removes the question.
//!
//! So this file enumerates. It takes a container from [`AgeFile::encrypt`]
//! rather than a hand-written blob, and asserts three things at every length:
//!
//! 1. The call is a typed `Err` and not a panic. A sweep that only checked "did
//!    not panic" would pass on an unspecified failure and hide which of the
//!    three truncation classes is being reported, so each error is classified
//!    into the class its offset implies.
//! 2. The full container is still accepted, so the sweep proves the boundary
//!    rather than only the interior.
//! 3. The minimum valid length is accepted, and one byte below it is not.
//!
//! # Cost
//!
//! The sweep is a few hundred iterations over a few hundred bytes, which runs in
//! well under a tenth of a second, so it can live in the default suite rather
//! than behind a flag. That is the point of doing it here: a sweep nobody runs
//! is worth less than the offsets it replaces.
//!
//! # Determinism
//!
//! The identity is a fixed X25519 secret from the crate's own fixtures rather
//! than a generated key. RSA key generation at 16384 bits takes tens of seconds
//! and a 16384-bit round trip takes about nine, so a per-iteration generated key
//! would make this suite unusable, and a sweep that only sometimes exercises a
//! length is worse than no sweep. An X25519 container is also fixed-size, so
//! every run sweeps exactly the same set of lengths, which the length assertion
//! below pins down.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_age::{AgeArmor, AgeError, AgeFile, AgeIdentity, AgeRecipient};

/// An X25519 identity from the crate's own fixture set. Fixed, so the sweep is
/// deterministic and costs nothing to set up.
const IDENTITY: &str = "AGE-SECRET-KEY-1M0J706Z6QXT0A4ALWZ098Q5AFLTWXCVXLFT8VFYAG24MXX56CUSQQLCA3H";

/// The STREAM chunk size the crate uses.
const CHUNK: usize = 64 * 1024;
/// The STREAM payload nonce length.
const NONCE: usize = 16;
/// The per-chunk Poly1305 tag length.
const TAG: usize = 16;

/// The ways a truncated binary container can fail, so an assertion can name
/// which one it saw rather than only that something failed. The armored sweep
/// has its own framing assertion, because every armored failure is about
/// framing and there is nothing to tell apart.
#[derive(Debug, PartialEq, Eq)]
enum Truncation {
    /// The cut leaves no payload bytes at all.
    Header,
    /// The cut lands inside the payload, before the final chunk is complete.
    Payload,
    /// The payload is structurally complete but fails authentication, which is
    /// what a cut in the last chunk's tag looks like.
    Authentication,
}

fn identity() -> AgeIdentity {
    AgeIdentity::from_private_key(IDENTITY).expect("fixture identity")
}

fn recipient() -> AgeRecipient {
    identity().recipient().expect("fixture recipient")
}

/// Classifies a binary-container error. A length that does not fit any class is
/// a finding rather than something to fold into a catch-all.
///
/// One variant is genuinely ambiguous: a bare [`AgeError::Truncated`] is what
/// every exact read in the crate returns when the input ends inside it, so it
/// appears inside the header, inside the sixteen-byte payload nonce, and inside
/// a STREAM chunk. The variant alone does not say which, so `offset` says it:
/// `offset` is the number of payload bytes the cut left, and zero means the cut
/// landed in the header. That is the honest classification, and it is why the
/// tests assert the class against the offset rather than the other way round.
fn classify_binary(error: &AgeError, offset: usize) -> Truncation {
    match error {
        AgeError::Truncated if offset == 0 => Truncation::Header,
        AgeError::InvalidFormat(
            "empty header" | "missing armor begin marker" | "invalid armor begin marker",
        )
        | AgeError::InvalidHeader(_) => Truncation::Header,
        AgeError::Truncated
        | AgeError::InvalidFormat(
            "payload chunk is truncated" | "payload contains an empty non-final chunk",
        ) => Truncation::Payload,
        AgeError::AuthenticationFailed | AgeError::InvalidMac => Truncation::Authentication,
        other => panic!("unexpected error for a truncated container: {other:?}"),
    }
}

/// Every length of a real binary container, from zero to the full size.
///
/// The container is the one the crate itself produces for a single X25519
/// recipient, so the header is a real parsed header with a real stanza and a
/// real MAC rather than a hand-written approximation.
#[test]
fn every_truncation_of_a_binary_container_is_a_typed_error() {
    let identity = identity();
    let container =
        AgeFile::encrypt(b"truncation sweep", std::slice::from_ref(&recipient())).expect("encrypt");
    let header = AgeFile::extract_header(&container).expect("header").len();

    // Pinned so a change to the container's size is a visible diff rather than
    // a silently different sweep.
    assert!(
        container.len() > 100 && container.len() < 1024,
        "the sweep assumes a small container, got {}",
        container.len()
    );
    assert!(
        header < container.len(),
        "a container with no payload would not exercise the payload classes"
    );

    // The full container is accepted, so the sweep proves the top of the range.
    assert_eq!(
        AgeFile::decrypt(&container, std::slice::from_ref(&identity)).expect("full decrypt"),
        b"truncation sweep"
    );

    // The minimum valid length, which needs a container whose payload is empty.
    // A container with plaintext cannot have bytes dropped and still decrypt:
    // the dropped bytes land in the final chunk's ciphertext, so the chunk is
    // the right length but fails authentication. An empty payload has no
    // ciphertext to drop, so its shortest valid form is exactly the header, the
    // nonce, and a final chunk that is nothing but its tag.
    let empty = AgeFile::encrypt(b"", std::slice::from_ref(&recipient())).expect("encrypt empty");
    let empty_header = AgeFile::extract_header(&empty).expect("empty header").len();
    let minimum = empty_header + NONCE + TAG;
    assert_eq!(
        minimum,
        empty.len(),
        "an empty payload is header + nonce + tag"
    );
    assert_eq!(
        AgeFile::decrypt(&empty[..minimum], std::slice::from_ref(&identity)).expect("minimum"),
        b""
    );
    let error = AgeFile::decrypt(&empty[..minimum - 1], std::slice::from_ref(&identity))
        .expect_err("one byte below the minimum valid length must be rejected");
    assert_eq!(
        classify_binary(&error, TAG),
        Truncation::Payload,
        "a cut inside the final chunk is a payload failure: {error:?}"
    );

    // And for the non-empty container, the shortest prefix that still decrypts
    // is the whole thing: its final chunk carries real ciphertext, so every
    // proper prefix fails. The range is inclusive of the full length, because
    // that is where the answer is.
    let shortest = (0..=container.len())
        .find(|length| {
            AgeFile::decrypt(&container[..*length], std::slice::from_ref(&identity)).is_ok()
        })
        .expect("the full container decrypts");
    assert_eq!(
        shortest,
        container.len(),
        "no proper prefix of a non-empty container should decrypt"
    );

    // Every length from zero to the full size, exclusive of the full size.
    for length in 0..container.len() {
        let result = AgeFile::decrypt(&container[..length], std::slice::from_ref(&identity));
        let error = result.expect_err(&format!("length {length} was accepted"));
        let offset = length.saturating_sub(header);
        let class = classify_binary(&error, offset);

        // The assertion that catches a parser trusting a length field: a cut
        // that left no payload bytes at all can only be a header failure, and a
        // cut that left some can only be a payload or authentication failure.
        if offset == 0 {
            assert_eq!(
                class,
                Truncation::Header,
                "length {length} leaves no payload bytes (header is {header}) but reported {class:?}: {error:?}"
            );
        } else {
            assert_ne!(
                class,
                Truncation::Header,
                "length {length} leaves {offset} payload bytes but reported {class:?}: {error:?}"
            );
        }
    }
}

/// The same sweep through the armored path.
///
/// Armor length and binary length are related by a base-64 transform rather
/// than a stored field, so the arithmetic has its own edge cases at the line
/// boundaries: a cut can lose a whole line, half a line, or the end marker.
#[test]
fn every_truncation_of_an_armored_container_is_a_typed_error() {
    let identity = identity();
    // One `encrypt` call, armored from the result, because age encryption is
    // randomised: a second call would produce a different container with a
    // different ephemeral share, and the two would not be the same bytes.
    let binary =
        AgeFile::encrypt(b"armor sweep", std::slice::from_ref(&recipient())).expect("encrypt");
    let armored = AgeArmor::encode(&binary);

    assert!(
        armored.starts_with(AgeArmor::BEGIN),
        "the armored form should carry the begin marker"
    );
    assert!(
        armored.len() > binary.len(),
        "armor is longer than the binary it wraps"
    );
    assert_eq!(AgeArmor::decode(&armored).expect("full decode"), binary);

    // The full armored container decrypts.
    assert_eq!(
        AgeFile::decrypt_armored(&armored, std::slice::from_ref(&identity)).expect("full"),
        b"armor sweep"
    );
    // And the auto-detecting entry point accepts the same bytes.
    assert_eq!(
        AgeFile::decrypt(armored.as_bytes(), std::slice::from_ref(&identity)).expect("auto"),
        b"armor sweep"
    );

    // The minimum valid armored length. The trailing newline after the end
    // marker is optional, matching the reference reader, so the minimum is one
    // below the full length rather than the full length.
    let minimum = armored.len() - 1;
    assert_eq!(
        AgeArmor::decode(&armored[..minimum]).expect("minimum armored"),
        binary
    );
    assert_eq!(
        AgeFile::decrypt_armored(&armored[..minimum], std::slice::from_ref(&identity))
            .expect("minimum armored decrypt"),
        b"armor sweep"
    );
    assert!(
        AgeArmor::decode(&armored[..minimum - 1]).is_err(),
        "one byte below the minimum valid armored length must be rejected"
    );

    for length in 0..minimum {
        let error = AgeFile::decrypt_armored(&armored[..length], std::slice::from_ref(&identity))
            .expect_err(&format!("armored length {length} was accepted"));
        // A cut short of a complete begin marker never produces a payload to
        // fail authentication, so the failure has to be about framing. The
        // framing checks are reached in two different ways, so two shapes of
        // error are correct here:
        //
        //  - the empty input has no marker to be missing, so the armor decoder
        //    produces no bytes and the binary decoder reports the empty header;
        //  - a cut inside the marker itself is read as base-64 and hits the
        //    exact-read helper, which reports `Truncated`.
        //
        // Anything else means a cut got past the framing and failed on content,
        // which would be a different bug.
        let is_framing = match error {
            AgeError::InvalidFormat(_) => true,
            AgeError::InvalidHeader("empty header") => length == 0,
            AgeError::Truncated => length < AgeArmor::BEGIN.len(),
            _ => false,
        };
        assert!(
            is_framing,
            "armored length {length} failed on content rather than framing: {error:?}"
        );
    }
}

/// The same sweep through `extract_header`, the function a caller reaches for
/// first on a container of unknown provenance.
///
/// This one has a different and correct boundary: `extract_header` reads only
/// the header, so every length at or past the header offset is a valid header
/// and must succeed, and everything below it must be rejected. Asserting that
/// is what makes it a boundary test rather than a length check.
#[test]
fn every_truncation_of_a_header_is_a_typed_error() {
    let container =
        AgeFile::encrypt(b"header sweep", std::slice::from_ref(&recipient())).expect("encrypt");
    let full = AgeFile::extract_header(&container).expect("header");

    // Every length below the header is rejected as a header truncation.
    for length in 0..full.len() {
        let error = AgeFile::extract_header(&container[..length])
            .expect_err(&format!("header length {length} was accepted"));
        assert_eq!(
            classify_binary(&error, 0),
            Truncation::Header,
            "header length {length} reported the wrong class: {error:?}"
        );
    }

    // The header itself and anything longer is a complete header. This is the
    // minimum valid length for this function, and it succeeds.
    assert_eq!(
        AgeFile::extract_header(&container[..full.len()]).expect("exact"),
        full
    );
    assert_eq!(AgeFile::extract_header(&container).expect("full"), full);
    // A container with no header at all is rejected, which is the other side of
    // the boundary.
    assert!(
        AgeFile::extract_header(&container[full.len()..]).is_err(),
        "a payload with no header in front of it is not a header"
    );

    // And the extracted header still authenticates, which is the point of
    // extracting it rather than just slicing.
    let key = AgeFile::decrypt_header(&full, std::slice::from_ref(&identity())).expect("file key");
    assert_eq!(key.len(), 16, "an age file key is 16 bytes");
}

/// The payload chunk arithmetic at a chunk boundary.
///
/// A container whose payload spans more than one STREAM chunk has a length
/// field per chunk, and this walks the interesting offsets around the first
/// boundary: the last byte of a chunk's ciphertext, the last byte of its tag,
/// and the point where the final chunk would begin.
#[test]
fn truncation_at_a_chunk_boundary_is_a_typed_error() {
    let identity = identity();
    // One byte past a single chunk, so there is a full chunk and a final chunk.
    let plaintext = vec![b'x'; CHUNK + 1];
    let container =
        AgeFile::encrypt(&plaintext, std::slice::from_ref(&recipient())).expect("encrypt");
    let header = AgeFile::extract_header(&container).expect("header").len();
    let payload = container.len() - header;

    // Sanity: the payload is a nonce, one full chunk, and a short final chunk.
    assert_eq!(payload, NONCE + (CHUNK + TAG) + (1 + TAG));

    assert_eq!(
        AgeFile::decrypt(&container, std::slice::from_ref(&identity)).expect("full"),
        plaintext
    );

    // The minimum for this container is everything but the final chunk's
    // plaintext byte, which cannot be dropped without failing authentication
    // rather than failing structurally. So the structural minimum is the length
    // that leaves a final chunk of exactly a tag, and one below it is rejected.
    let structural_minimum = header + NONCE + (CHUNK + TAG) + TAG;
    assert!(
        AgeFile::decrypt(
            &container[..structural_minimum],
            std::slice::from_ref(&identity)
        )
        .is_err(),
        "a container missing the final chunk's plaintext must not authenticate"
    );

    // Each of the chunk-boundary offsets is a typed error, not a panic and not
    // an unspecified failure.
    for dropped in [1usize, TAG, TAG + 1, 17, 20, CHUNK, CHUNK + TAG] {
        let length = container.len() - dropped;
        let error = AgeFile::decrypt(&container[..length], std::slice::from_ref(&identity))
            .expect_err(&format!("dropping {dropped} bytes was accepted"));
        let offset = length.saturating_sub(header);
        let class = classify_binary(&error, offset);
        assert_ne!(
            class,
            Truncation::Header,
            "dropping {dropped} bytes left {offset} payload bytes but reported {class:?}: {error:?}"
        );
    }
}
