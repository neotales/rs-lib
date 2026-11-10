// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Attachment, CredentialProvider, Entry, Field, Kdbx3WriteOptions, KdbxCompression,
    KdbxCredentials, KdbxError, KdbxFile, KdbxKdf, KdbxKeyFile, KdbxOuterCipher, KdbxReadLimits,
    KdbxWriteOptions, KdbxXml, KeePassDatabase, ProtectedValue,
};

struct StaticCredential([u8; 32]);

impl CredentialProvider for StaticCredential {
    fn key_component(&mut self) -> Result<[u8; 32], KdbxError> {
        Ok(self.0)
    }
}

// The slow lane, and why it is slow. 4.3s measured on this machine at
// `bb91e6e`; it is marked rather than weakened because the cost is a property of
// the *fixture* -- one load per external KDBX 4.1 fixture, each paying a real KDF -- and a cheaper fixture would be a different test.
// The long lane in `.gitea/workflows/ci.yml` runs it with `--include-ignored`.
#[ignore = "slow lane: run by the CI long lane, see eng/README.md"]
#[test]
fn opens_external_kdbx4_fixtures() {
    let limits = KdbxReadLimits::default();
    for (name, bytes) in [
        (
            "aes-kdf",
            include_bytes!("fixtures/keepass-rs-kdbx4-aes-kdf.kdbx").as_slice(),
        ),
        (
            "argon2d",
            include_bytes!("fixtures/keepass-rs-kdbx4-argon2d.kdbx").as_slice(),
        ),
        (
            "argon2id",
            include_bytes!("fixtures/keepass-rs-kdbx4-argon2id.kdbx").as_slice(),
        ),
        (
            "argon2d-chacha20",
            include_bytes!("fixtures/keepass-rs-kdbx4-argon2d-chacha20.kdbx").as_slice(),
        ),
    ] {
        let loaded = KdbxFile::load_password(bytes, "demopass", &limits)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(
            !loaded.root.entries.is_empty(),
            "{name} should contain an entry"
        );
    }
}

#[test]
fn bounded_limits_and_terminal_framing_fail_closed() {
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let small = KdbxReadLimits {
        max_input_bytes: 1,
        ..KdbxReadLimits::default()
    };
    assert!(KdbxFile::load_password(bytes.as_slice(), "pw", &small).is_err());
    bytes.push(0);
    assert!(KdbxFile::load_password(bytes.as_slice(), "pw", &KdbxReadLimits::default()).is_err());
}

#[test]
fn parses_key_file_xml_v2_with_integrity_prefix() {
    let xml = br#"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="630DCD29">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data></Key></KeyFile>"#;
    KdbxKeyFile::parse(xml).unwrap_or_else(|error| panic!("{error:?}"));
    let invalid = br#"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="00000000">000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data></Key></KeyFile>"#;
    assert!(KdbxKeyFile::parse(invalid).is_err());
}

#[test]
fn wrong_password_and_tampering_are_rejected() {
    let limits = KdbxReadLimits::default();
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("right").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    assert!(KdbxFile::load_password(bytes.as_slice(), "wrong", &limits).is_err());
    let mut tampered = bytes.clone();
    tampered[20] ^= 1;
    assert!(KdbxFile::load_password(tampered.as_slice(), "right", &limits).is_err());
}

#[test]
fn key_file_credentials_round_trip() {
    let limits = KdbxReadLimits::default();
    let database = KeePassDatabase::default();
    let mut bytes = Vec::new();
    let options = KdbxWriteOptions {
        aes_kdf_rounds: 8,
        ..KdbxWriteOptions::default()
    };
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::key_file([0x42; 32]).unwrap(),
        options,
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load(
        bytes.as_slice(),
        &mut neotales_keepass::KdbxCredentials::key_file([0x42; 32]).unwrap(),
        &limits,
    )
    .unwrap();
    assert!(loaded.root.entries.is_empty());
}

#[test]
fn custom_credential_provider_remains_an_explicit_component_seam() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("provider"));
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut KdbxCredentials::from_parts(None, vec![Box::new(StaticCredential([0x31; 32]))])
            .unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let mut credentials =
        KdbxCredentials::from_parts(None, vec![Box::new(StaticCredential([0x31; 32]))]).unwrap();
    let loaded = KdbxFile::load(bytes.as_slice(), &mut credentials, &limits).unwrap();
    assert_eq!(loaded.root.entries[0].title, "provider");
}

#[test]
fn plain_xml_round_trips_unprotected_entries() {
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("plain"));
    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.root.entries[0].title, "plain");
}

#[test]
fn writer_supports_outer_cipher_and_compression_matrix() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("matrix"));
    for cipher in [KdbxOuterCipher::Aes, KdbxOuterCipher::ChaCha20] {
        for compression in [KdbxCompression::None, KdbxCompression::GZip] {
            let mut bytes = Vec::new();
            let options = KdbxWriteOptions {
                cipher,
                compression,
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            };
            KdbxFile::save(
                &database,
                &mut bytes,
                &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
                options,
                &limits,
            )
            .unwrap();
            let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
            assert_eq!(loaded.root.entries[0].title, "matrix");
        }
    }
}

// The slow lane, and why it is slow. 10.0s measured on this machine at
// `bb91e6e`; it is marked rather than weakened because the cost is a property of
// the *fixture* -- same fixture, same real KDF; this is the interop test and it is the point -- and a cheaper fixture would be a different test.
// The long lane in `.gitea/workflows/ci.yml` runs it with `--include-ignored`.
#[ignore = "slow lane: run by the CI long lane, see eng/README.md"]
#[test]
fn opens_kdbx3_fixture() {
    let limits = KdbxReadLimits::default();
    let loaded = KdbxFile::load_password(
        include_bytes!("fixtures/keepassxc-minimal.kdbx").as_slice(),
        "fixture-password",
        &limits,
    )
    .unwrap();
    assert!(loaded.root.entries.is_empty());
}

#[test]
fn kdbx3_writer_round_trips_protected_values_and_legacy_binaries() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    let protected_binary = database
        .binary_pool
        .add(b"kdbx3 protected binary".to_vec(), true);
    let plain_binary = database
        .binary_pool
        .add(b"kdbx3 plain binary".to_vec(), false);
    let mut entry = Entry::new("legacy");
    entry.set_field(Field {
        key: "Password".into(),
        value: ProtectedValue::from_text("kdbx3 password"),
        protected: true,
        protect_in_memory: true,
    });
    entry.attachments.push(Attachment {
        name: "protected.bin".into(),
        reference: protected_binary,
    });
    entry.attachments.push(Attachment {
        name: "plain.bin".into(),
        reference: plain_binary,
    });
    database.root.entries.push(entry);

    for compression in [KdbxCompression::None, KdbxCompression::GZip] {
        let mut bytes = Vec::new();
        KdbxFile::save_kdbx3(
            &database,
            &mut bytes,
            &mut neotales_keepass::KdbxCredentials::password("kdbx3-password").unwrap(),
            Kdbx3WriteOptions {
                compression,
                aes_kdf_rounds: 8,
                block_bytes: 32,
            },
            &limits,
        )
        .unwrap();
        assert_eq!(&bytes[8..12], &0x0003_0001u32.to_le_bytes());
        let loaded = KdbxFile::load_password(bytes.as_slice(), "kdbx3-password", &limits).unwrap();
        let loaded_entry = &loaded.root.entries[0];
        assert_eq!(loaded_entry.title, "legacy");
        assert_eq!(
            loaded_entry
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "kdbx3 password"
        );
        assert!(loaded_entry.field("Password").unwrap().protected);
        assert_eq!(
            loaded.binary_pool.get(protected_binary).unwrap().data,
            b"kdbx3 protected binary"
        );
        assert!(loaded.binary_pool.get(protected_binary).unwrap().protected);
        assert_eq!(
            loaded.binary_pool.get(plain_binary).unwrap().data,
            b"kdbx3 plain binary"
        );
        assert!(!loaded.binary_pool.get(plain_binary).unwrap().protected);
    }
}

#[test]
fn kdbx4_writer_supports_argon2d_and_argon2id() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("argon2"));
    for kdf in [KdbxKdf::Argon2d, KdbxKdf::Argon2id] {
        let mut bytes = Vec::new();
        KdbxFile::save(
            &database,
            &mut bytes,
            &mut neotales_keepass::KdbxCredentials::password("argon2-password").unwrap(),
            KdbxWriteOptions {
                kdf,
                argon2_memory_kib: 32,
                argon2_time: 1,
                argon2_lanes: 1,
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &limits,
        )
        .unwrap();
        let loaded = KdbxFile::load_password(bytes.as_slice(), "argon2-password", &limits).unwrap();
        assert_eq!(loaded.root.entries[0].title, "argon2");
    }
}

#[test]
fn aes_kdf_aes_cbc_round_trips_protected_fields() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("payments");
    entry.set_field(Field {
        key: "Password".into(),
        value: ProtectedValue::from_text("correct horse battery staple"),
        protected: true,
        protect_in_memory: true,
    });
    entry.set_field(Field::new("URL", "https://example.test"));
    database.root.entries.push(entry);

    let limits = KdbxReadLimits::default();
    let options = KdbxWriteOptions {
        aes_kdf_rounds: 32,
        ..KdbxWriteOptions::default()
    };
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
        options,
        &limits,
    )
    .unwrap();

    let loaded = KdbxFile::load_password(bytes.as_slice(), "password", &limits).unwrap();
    let loaded_entry = &loaded.root.entries[0];
    assert_eq!(loaded_entry.title, "payments");
    assert_eq!(
        loaded_entry
            .field("Password")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "correct horse battery staple"
    );
    assert!(loaded_entry.field("Password").unwrap().protected);
    assert!(
        loaded_entry
            .field("Password")
            .unwrap()
            .value
            .is_memory_protected()
    );
    assert_eq!(
        loaded_entry
            .field("URL")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "https://example.test"
    );
}

/// Regression: the KDBX 4 inner protected stream is consumed in document
/// order, so a document that mixes entries and child groups under one parent
/// must round-trip every protected value. A reader that grouped `Entry` and
/// `Group` children by name desynchronized the inner cipher here.
#[test]
fn round_trips_protected_values_across_mixed_entry_and_group_layouts() {
    fn entry(title: &str, secret: &str) -> Entry {
        let mut entry = Entry::new(title);
        entry.password = ProtectedValue::from_text(secret);
        entry.set_field(Field {
            key: "Private".into(),
            value: ProtectedValue::from_text(secret),
            protected: true,
            protect_in_memory: true,
        });
        entry
    }

    let mut database = KeePassDatabase::default();
    database.root.add_entry(entry("root-entry", "root-secret"));
    let mut depth_one = neotales_keepass::Group::new("one");
    depth_one.add_entry(entry("one-entry", "one-secret"));
    let mut depth_two = neotales_keepass::Group::new("two");
    depth_two.add_entry(entry("two-entry", "two-secret"));
    depth_two.add_entry(entry("two-second", "two-second-secret"));
    depth_one.add_group(depth_two);
    database.root.add_group(depth_one);

    let mut bytes = Vec::new();
    KdbxFile::save_default(&database, &mut bytes, "pw").expect("save mixed layout");
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &KdbxReadLimits::default())
        .expect("load mixed layout");

    let root_entry = loaded
        .find_entry_by_path(
            "root-entry",
            neotales_keepass::PathOptions {
                delimiter: '/',
                comparison: neotales_keepass::Comparison::CaseInsensitive,
            },
        )
        .expect("root entry path")
        .expect("root entry");
    assert_eq!(
        root_entry
            .password
            .reveal_text()
            .expect("root password")
            .as_str(),
        "root-secret"
    );

    for (path, expected) in [
        ("one/one-entry", "one-secret"),
        ("one/two/two-entry", "two-secret"),
        ("one/two/two-second", "two-second-secret"),
    ] {
        let options = neotales_keepass::PathOptions {
            delimiter: '/',
            comparison: neotales_keepass::Comparison::CaseInsensitive,
        };
        let found = loaded
            .find_entry_by_path(path, options)
            .unwrap_or_else(|error| panic!("{path}: {error}"))
            .unwrap_or_else(|| panic!("{path} exists"));
        assert_eq!(
            found
                .password
                .reveal_text()
                .unwrap_or_else(|error| panic!("{path} password: {error}"))
                .as_str(),
            expected,
            "{path}"
        );
        let field = found
            .field("Private")
            .unwrap_or_else(|| panic!("{path} custom field"))
            .value
            .reveal_text()
            .unwrap_or_else(|error| panic!("{path} custom field: {error}"));
        assert_eq!(field.as_str(), expected, "{path} custom field");
    }
}
