// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Entry, KdbxCompression, KdbxFailureKind, KdbxFile, KdbxKeyFile, KdbxOuterCipher,
    KdbxReadLimits, KdbxWriteOptions, KdbxXml, KeePassDatabase, ProtectedValue,
};

const AES_CIPHER: &[u8] = &[
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];

#[test]
fn malformed_outer_headers_fail_before_key_derivation() {
    let iv = [0u8; 16];
    let compression = [0u8; 4];
    let seed = [0u8; 32];
    let invalid_kdf = [0u8, 1];

    let cases = [
        (
            "signature".to_owned(),
            vec![0u8; 12],
            KdbxFailureKind::Malformed,
        ),
        (
            "version".to_owned(),
            outer_prefix(0x0005_0001, &[]),
            KdbxFailureKind::Unsupported,
        ),
        (
            "missing terminator".to_owned(),
            outer_prefix(0x0004_0001, &[(2, AES_CIPHER)]),
            KdbxFailureKind::Truncated,
        ),
        (
            "bad terminator".to_owned(),
            outer_header(0x0004_0001, &[(2, AES_CIPHER)], &[0, 0, 0, 0]),
            KdbxFailureKind::Malformed,
        ),
        (
            "duplicate field".to_owned(),
            outer_header(
                0x0004_0001,
                &[(2, AES_CIPHER), (2, AES_CIPHER)],
                &[13, 10, 13, 10],
            ),
            KdbxFailureKind::Malformed,
        ),
        (
            "unsupported cipher".to_owned(),
            outer_header(
                0x0004_0001,
                &[(2, &[0; 16]), (3, &compression)],
                &[13, 10, 13, 10],
            ),
            KdbxFailureKind::Unsupported,
        ),
        (
            "missing master seed".to_owned(),
            outer_header(
                0x0004_0001,
                &[(2, AES_CIPHER), (3, &compression), (7, &iv)],
                &[13, 10, 13, 10],
            ),
            KdbxFailureKind::Malformed,
        ),
        (
            "invalid kdf".to_owned(),
            outer_header(
                0x0004_0001,
                &[
                    (2, AES_CIPHER),
                    (3, &compression),
                    (4, &seed),
                    (7, &iv),
                    (11, &invalid_kdf),
                ],
                &[13, 10, 13, 10],
            ),
            KdbxFailureKind::Malformed,
        ),
    ];

    for (name, bytes, expected) in cases {
        let error = KdbxFile::load_password(bytes.as_slice(), b"pw", &KdbxReadLimits::default())
            .unwrap_err();
        assert_eq!(error.kind, expected, "{name}: {error}");
    }

    let mut negative_length = outer_prefix(0x0004_0001, &[]);
    negative_length.push(2);
    negative_length.extend_from_slice(&(-1i32).to_le_bytes());
    negative_length.extend_from_slice(AES_CIPHER);
    assert_eq!(
        KdbxFile::load_password(
            negative_length.as_slice(),
            b"pw",
            &KdbxReadLimits::default()
        )
        .unwrap_err()
        .kind,
        KdbxFailureKind::ResourceLimit
    );
}

// The slow lane, and why it is slow. 11.7s measured on this machine at
// `bb91e6e`; it is marked rather than weakened because the cost is a property of
// the *fixture* -- every one of ~4,000 prefixes goes through a full authenticated load -- and a cheaper fixture would be a different test.
// The long lane in `.gitea/workflows/ci.yml` runs it with `--include-ignored`.
#[ignore = "slow lane: run by the CI long lane, see eng/README.md"]
#[test]
fn every_proper_kdbx4_prefix_is_rejected() {
    let bytes = valid_kdbx4();
    for cut in 0..bytes.len() {
        let result = KdbxFile::load_password(&bytes[..cut], b"pw", &KdbxReadLimits::default());
        assert!(result.is_err(), "accepted truncated prefix of {cut} bytes");
    }

    let limits = KdbxReadLimits {
        max_input_bytes: bytes.len() as u64 - 1,
        ..KdbxReadLimits::default()
    };
    assert_eq!(
        KdbxFile::load_password(bytes.as_slice(), b"pw", &limits)
            .unwrap_err()
            .kind,
        KdbxFailureKind::ResourceLimit
    );
}

#[test]
fn kdbx4_authentication_boundaries_are_tamper_evident() {
    let bytes = valid_kdbx4();
    let header_end = kdbx4_header_end(&bytes);
    let hash_start = header_end;
    let hmac_start = hash_start + 32;
    let block_start = hmac_start + 32;
    let blocks = kdbx4_block_ranges(&bytes, block_start);
    assert!(
        blocks.len() >= 3,
        "fixture should have data and terminal blocks"
    );

    let mut header = bytes.clone();
    let seed_offset = kdbx4_field_value_offset(&bytes, 4);
    flip(&mut header, seed_offset);
    assert_eq!(load_error_kind(&header), KdbxFailureKind::Authentication);

    let mut header_hash = bytes.clone();
    flip(&mut header_hash, hash_start);
    assert_eq!(
        load_error_kind(&header_hash),
        KdbxFailureKind::Authentication
    );

    let mut header_hmac = bytes.clone();
    flip(&mut header_hmac, hmac_start);
    assert_eq!(
        load_error_kind(&header_hmac),
        KdbxFailureKind::Authentication
    );

    for &(start, _, _length) in blocks.iter().filter(|(_, _, length)| *length > 0) {
        let mut tag_tamper = bytes.clone();
        flip(&mut tag_tamper, start);
        assert_eq!(
            load_error_kind(&tag_tamper),
            KdbxFailureKind::Authentication
        );

        let mut data_tamper = bytes.clone();
        flip(&mut data_tamper, start + 36);
        assert_eq!(
            load_error_kind(&data_tamper),
            KdbxFailureKind::Authentication
        );
    }

    let (terminal_start, _, terminal_length) = *blocks.last().expect("terminal block");
    assert_eq!(terminal_length, 0);
    let mut terminal_tamper = bytes.clone();
    flip(&mut terminal_tamper, terminal_start);
    assert_eq!(
        load_error_kind(&terminal_tamper),
        KdbxFailureKind::Authentication
    );

    let mut oversized_block = bytes.clone();
    oversized_block[blocks[0].0 + 32..blocks[0].0 + 36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        load_error_kind(&oversized_block),
        KdbxFailureKind::ResourceLimit
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(load_error_kind(&trailing), KdbxFailureKind::Malformed);

    let mut missing_terminal = bytes;
    missing_terminal.truncate(terminal_start);
    assert!(
        KdbxFile::load_password(
            missing_terminal.as_slice(),
            b"pw",
            &KdbxReadLimits::default()
        )
        .is_err()
    );
}

// The slow lane, and why it is slow. 22.0s measured on this machine at
// `bb91e6e`; it is marked rather than weakened because the cost is a property of
// the *fixture* -- each of its loads pays the real KDF in a committed KeePassXC fixture -- and a cheaper fixture would be a different test.
// The long lane in `.gitea/workflows/ci.yml` runs it with `--include-ignored`.
#[ignore = "slow lane: run by the CI long lane, see eng/README.md"]
#[test]
fn kdbx3_stream_start_and_framing_are_checked() {
    let bytes = include_bytes!("fixtures/keepassxc-minimal.kdbx");
    let header_end = kdbx3_header_end(bytes);
    for cut in [0, header_end - 1, header_end, bytes.len() - 1] {
        assert!(
            KdbxFile::load_password(
                &bytes[..cut],
                b"fixture-password",
                &KdbxReadLimits::default()
            )
            .is_err(),
            "accepted KDBX3 prefix of {cut} bytes"
        );
    }

    let mut stream_start_tamper = bytes.to_vec();
    flip(&mut stream_start_tamper, header_end + 4);
    assert_eq!(
        load_error_kind_with_password(&stream_start_tamper, b"fixture-password"),
        KdbxFailureKind::Authentication
    );

    let mut block_tamper = bytes.to_vec();
    flip(&mut block_tamper, header_end + 40);
    assert!(
        KdbxFile::load_password(
            block_tamper.as_slice(),
            b"fixture-password",
            &KdbxReadLimits::default()
        )
        .is_err()
    );

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(
        KdbxFile::load_password(
            trailing.as_slice(),
            b"fixture-password",
            &KdbxReadLimits::default()
        )
        .is_err()
    );

    let limits = KdbxReadLimits {
        max_input_bytes: bytes.len() as u64 - 1,
        ..KdbxReadLimits::default()
    };
    assert_eq!(
        KdbxFile::load_password(bytes.as_slice(), b"fixture-password", &limits)
            .unwrap_err()
            .kind,
        KdbxFailureKind::ResourceLimit
    );
}

#[test]
fn xml_parser_rejects_malformed_and_protected_documents() {
    let valid = br"<KeePassFile><Root><Group><Name>Root</Name></Group></Root></KeePassFile>";
    assert!(KdbxXml::import(valid, &KdbxReadLimits::default()).is_ok());
    let explicitly_unprotected = br"<KeePassFile><Root><Group><Entry><String><Key>Note</Key><Value Protected='False'>plain</Value></String></Entry></Group></Root></KeePassFile>";
    assert!(KdbxXml::import(explicitly_unprotected, &KdbxReadLimits::default()).is_ok());

    let cases = [
        ("empty", Vec::new(), KdbxFailureKind::Malformed),
        (
            "wrong root",
            b"<NotKeePassFile/>".to_vec(),
            KdbxFailureKind::Malformed,
        ),
        (
            "missing root",
            b"<KeePassFile/>".to_vec(),
            KdbxFailureKind::Malformed,
        ),
        (
            "missing group",
            b"<KeePassFile><Root/></KeePassFile>".to_vec(),
            KdbxFailureKind::Malformed,
        ),
        (
            "unbalanced",
            b"<KeePassFile><Root><Group></KeePassFile>".to_vec(),
            KdbxFailureKind::Malformed,
        ),
        (
            "doctype",
            b"<!DOCTYPE KeePassFile><KeePassFile><Root><Group/></Root></KeePassFile>".to_vec(),
            KdbxFailureKind::Unsupported,
        ),
        (
            "external entity",
            b"<KeePassFile><Root><Group><Name>&xxe;</Name></Group></Root></KeePassFile>"
                .to_vec(),
            KdbxFailureKind::Unsupported,
        ),
        (
            "invalid uuid",
            b"<KeePassFile><Root><Group><UUID>not-base64</UUID></Group></Root></KeePassFile>"
                .to_vec(),
            KdbxFailureKind::Malformed,
        ),
        (
            "protected single quote",
            b"<KeePassFile><Root><Group><String><Key>Password</Key><Value Protected='true'>dGVzdA==</Value></String></Group></Root></KeePassFile>"
                .to_vec(),
            KdbxFailureKind::Unsupported,
        ),
    ];
    for (name, data, expected) in cases {
        let error = KdbxXml::import(&data, &KdbxReadLimits::default()).unwrap_err();
        assert_eq!(error.kind, expected, "{name}: {error}");
    }
    let unknown = b"<KeePassFile><Root><Group><Bogus/></Group></Root></KeePassFile>";
    let unknown_database = KdbxXml::import(unknown, &KdbxReadLimits::default()).unwrap();
    assert!(!unknown_database.can_save_losslessly);

    let invalid_utf8 = [0xff, b'<', b'>'];
    assert_eq!(
        KdbxXml::import(&invalid_utf8, &KdbxReadLimits::default())
            .unwrap_err()
            .kind,
        KdbxFailureKind::Malformed
    );

    let depth_limits = KdbxReadLimits {
        max_xml_depth: 2,
        ..KdbxReadLimits::default()
    };
    assert_eq!(
        KdbxXml::import(valid, &depth_limits).unwrap_err().kind,
        KdbxFailureKind::ResourceLimit
    );
    let size_limits = KdbxReadLimits {
        max_xml_chars: 8,
        ..KdbxReadLimits::default()
    };
    assert_eq!(
        KdbxXml::import(valid, &size_limits).unwrap_err().kind,
        KdbxFailureKind::ResourceLimit
    );

    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("secret");
    entry.password = ProtectedValue::from_text("must not enter plain XML");
    database.root.entries.push(entry);
    assert_eq!(
        KdbxXml::export(&database).unwrap_err().kind,
        KdbxFailureKind::Unsupported
    );
}

#[test]
fn key_file_parser_rejects_malformed_forms() {
    assert!(KdbxKeyFile::parse(&[0x42; 32]).is_ok());
    assert!(KdbxKeyFile::parse(b"arbitrary non-empty key-file data").is_ok());
    assert_eq!(key_file_error_kind(b""), KdbxFailureKind::Malformed);
    assert_eq!(
        key_file_error_kind(&vec![b'x'; 64 * 1024 + 1]),
        KdbxFailureKind::ResourceLimit
    );
    assert_eq!(
        key_file_error_kind(b"<NotKeyFile><Key/></NotKeyFile>"),
        KdbxFailureKind::Malformed
    );
    assert_eq!(
        key_file_error_kind(b"<!DOCTYPE KeyFile><KeyFile><Key/></KeyFile>"),
        KdbxFailureKind::Unsupported
    );
    assert_eq!(
        key_file_error_kind(b"<KeyFile><Key><Data>not-base64</Data></Key></KeyFile>"),
        KdbxFailureKind::Malformed
    );
    let unicode_64 = format!("{}a", "€".repeat(21)).into_bytes();
    assert_eq!(unicode_64.len(), 64);
    assert!(KdbxKeyFile::parse(&unicode_64).is_err());

    let valid_v2 = b"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"630DCD29\">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data></Key></KeyFile>";
    assert!(KdbxKeyFile::parse(valid_v2).is_ok());
    let non_ascii_v2 = format!(
        "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
        "€".repeat(22)
    );
    assert!(KdbxKeyFile::parse(non_ascii_v2.as_bytes()).is_err());

    let invalid_hash = b"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"00000000\">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data></Key></KeyFile>";
    assert!(KdbxKeyFile::parse(invalid_hash).is_err());
    let odd_hex = b"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"630DCD29\">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F0</Data></Key></KeyFile>";
    assert!(KdbxKeyFile::parse(odd_hex).is_err());
}

#[test]
fn invalid_resource_limits_are_rejected_before_io() {
    let limits = KdbxReadLimits {
        max_input_bytes: 0,
        ..KdbxReadLimits::default()
    };
    let error = KdbxFile::load_password(b"".as_slice(), b"pw", &limits).unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::InvalidArgument);

    let limits = KdbxReadLimits {
        max_xml_depth: 0,
        ..KdbxReadLimits::default()
    };
    assert!(KdbxXml::import(b"<KeePassFile/>", &limits).is_err());
}

#[test]
fn bounded_mutation_smoke_corpus_never_panics() {
    let seed = valid_kdbx4();
    for index in [0, 7, 12, 31, seed.len() / 2, seed.len() - 1] {
        let mut data = seed.clone();
        flip(&mut data, index);
        let _ = KdbxFile::load_password(data.as_slice(), b"pw", &KdbxReadLimits::default());
    }

    let xml_cases: &[&[u8]] = &[
        b"",
        b"<KeePassFile>",
        b"<!DOCTYPE x><x/>",
        b"<KeePassFile><Root><Group><UUID>***</UUID></Group></Root></KeePassFile>",
    ];
    for data in xml_cases {
        let _ = KdbxXml::import(data, &KdbxReadLimits::default());
        let _ = KdbxKeyFile::parse(data);
    }
}

fn valid_kdbx4() -> Vec<u8> {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("tamper corpus");
    entry.notes = "bounded payload".repeat(32);
    database.root.entries.push(entry);
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").expect("password"),
        KdbxWriteOptions {
            cipher: KdbxOuterCipher::Aes,
            compression: KdbxCompression::None,
            kdf: neotales_keepass::KdbxKdf::Aes,
            aes_kdf_rounds: 8,
            argon2_memory_kib: 64,
            argon2_time: 1,
            argon2_lanes: 1,
            hmac_block_bytes: 32,
        },
        &KdbxReadLimits::default(),
    )
    .expect("valid KDBX4 fixture");
    bytes
}

fn load_error_kind(data: &[u8]) -> KdbxFailureKind {
    load_error_kind_with_password(data, b"pw")
}

fn key_file_error_kind(data: &[u8]) -> KdbxFailureKind {
    KdbxKeyFile::parse(data)
        .expect_err("key-file input should be rejected")
        .kind
}

fn load_error_kind_with_password(data: &[u8], password: &[u8]) -> KdbxFailureKind {
    KdbxFile::load_password(data, password, &KdbxReadLimits::default())
        .unwrap_err()
        .kind
}

fn flip(data: &mut [u8], index: usize) {
    data[index] ^= 1;
}

fn outer_prefix(version: u32, fields: &[(u8, &[u8])]) -> Vec<u8> {
    let width = if version >> 16 == 3 { 2 } else { 4 };
    let mut output = Vec::new();
    output.extend_from_slice(&0x9aa2_d903u32.to_le_bytes());
    output.extend_from_slice(&0xb54b_fb67u32.to_le_bytes());
    output.extend_from_slice(&version.to_le_bytes());
    for (id, value) in fields {
        output.push(*id);
        if width == 2 {
            output.extend_from_slice(
                &u16::try_from(value.len())
                    .expect("field length")
                    .to_le_bytes(),
            );
        } else {
            output.extend_from_slice(
                &i32::try_from(value.len())
                    .expect("field length")
                    .to_le_bytes(),
            );
        }
        output.extend_from_slice(value);
    }
    output
}

fn outer_header(version: u32, fields: &[(u8, &[u8])], terminator: &[u8]) -> Vec<u8> {
    let mut output = outer_prefix(version, fields);
    let width = if version >> 16 == 3 { 2 } else { 4 };
    output.push(0);
    if width == 2 {
        output.extend_from_slice(
            &u16::try_from(terminator.len())
                .expect("terminator length")
                .to_le_bytes(),
        );
    } else {
        output.extend_from_slice(
            &i32::try_from(terminator.len())
                .expect("terminator length")
                .to_le_bytes(),
        );
    }
    output.extend_from_slice(terminator);
    output
}

fn kdbx4_header_end(data: &[u8]) -> usize {
    header_end(data, 4)
}

fn kdbx3_header_end(data: &[u8]) -> usize {
    header_end(data, 2)
}

fn header_end(data: &[u8], width: usize) -> usize {
    let mut offset = 12;
    loop {
        let id = data[offset];
        let length = if width == 2 {
            u16::from_le_bytes(data[offset + 1..offset + 3].try_into().expect("length")) as usize
        } else {
            u32::from_le_bytes(data[offset + 1..offset + 5].try_into().expect("length")) as usize
        };
        offset += 1 + width;
        if id == 0 {
            return offset + length;
        }
        offset += length;
    }
}

fn kdbx4_field_value_offset(data: &[u8], wanted: u8) -> usize {
    let mut offset = 12;
    loop {
        let id = data[offset];
        let length =
            u32::from_le_bytes(data[offset + 1..offset + 5].try_into().expect("length")) as usize;
        let value_offset = offset + 5;
        if id == wanted {
            return value_offset;
        }
        assert_ne!(id, 0, "field {wanted} not found");
        offset = value_offset + length;
    }
}

fn kdbx4_block_ranges(data: &[u8], mut offset: usize) -> Vec<(usize, usize, usize)> {
    let mut ranges = Vec::new();
    loop {
        let length =
            u32::from_le_bytes(data[offset + 32..offset + 36].try_into().expect("length")) as usize;
        let end = offset + 36 + length;
        ranges.push((offset, end, length));
        offset = end;
        if length == 0 {
            assert_eq!(offset, data.len());
            return ranges;
        }
    }
}
