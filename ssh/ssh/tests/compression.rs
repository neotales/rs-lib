// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_ssh::compression::{
    COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH, CompressionAlgorithm, CompressionError,
    compress_payload, decompress_payload, padding_for_payload,
};

#[test]
fn names_and_algorithms_are_explicit() {
    assert_eq!(
        CompressionAlgorithm::from_name(COMPRESSION_NONE),
        Some(CompressionAlgorithm::None)
    );
    assert_eq!(
        CompressionAlgorithm::from_name(COMPRESSION_ZLIB_OPENSSH),
        Some(CompressionAlgorithm::Zlib)
    );
    assert_eq!(CompressionAlgorithm::from_name("zlib"), None);
}

#[test]
fn zlib_round_trips_and_rejects_trailing_data() {
    let payload = b"neotales ssh compression payload".repeat(32);
    let compressed = compress_payload(&payload).expect("payload compresses");
    assert!(compressed.len() < payload.len());
    assert_eq!(
        decompress_payload(&compressed).expect("payload decompresses"),
        payload
    );

    let mut trailing = compressed;
    trailing.push(0);
    assert_eq!(
        decompress_payload(&trailing),
        Err(CompressionError::InvalidStream)
    );
}

#[test]
fn malformed_and_empty_streams_fail_closed() {
    assert_eq!(
        decompress_payload(&[]),
        Err(CompressionError::InvalidStream)
    );
    assert_eq!(
        decompress_payload(b"not zlib"),
        Err(CompressionError::InvalidStream)
    );
}

#[test]
fn padding_uses_the_selected_alignment_and_preserves_the_pattern() {
    // Header length 1 is the AEAD and encrypt-then-MAC case, where the
    // four-byte length field is authenticated but not encrypted and so is not
    // part of the aligned ciphertext.
    let padding = padding_for_payload(3, &[0xa5], 16, 1).expect("padding");
    assert_eq!(padding.len(), 12);
    assert!(padding.iter().all(|byte| *byte == 0xa5));
    // Header length 5 is encrypt-and-MAC, which encrypts the length field and
    // therefore aligns `4 + packet_length`. `1 + 3 + 12 == 16`, so this one
    // needs three fewer bytes of padding.
    let encrypt_and_mac = padding_for_payload(3, &[0xa5], 16, 5).expect("padding");
    assert_eq!(encrypt_and_mac.len(), 8);
    assert_eq!(encrypt_and_mac.len() % 16, 8);
    // An eight-byte block with a one-byte header.
    assert_eq!(
        padding_for_payload(3, &[0xa5], 8, 1)
            .expect("padding")
            .len(),
        4
    );
    assert_eq!(
        padding_for_payload(3, &[], 16, 1),
        Err(CompressionError::CompressionFailed)
    );
    assert_eq!(
        padding_for_payload(3, &[0xa5], 7, 1),
        Err(CompressionError::CompressionFailed)
    );
    assert_eq!(
        padding_for_payload(3, &[0xa5], 16, 4),
        Err(CompressionError::CompressionFailed)
    );
}
