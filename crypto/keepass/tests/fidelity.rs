// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Attachment, CustomIcon, Entry, Field, KdbxFile, KdbxReadLimits, KdbxTimestamp, KdbxUuid,
    KdbxWriteOptions, KdbxXml, KeePassDatabase, ProtectedValue, VariantValue,
};

fn timestamp(seconds: i64) -> KdbxTimestamp {
    KdbxTimestamp::from_unix_seconds(seconds)
}

#[test]
fn metadata_custom_icons_and_custom_data_round_trip_through_xml() {
    let icon_id = KdbxUuid::from_bytes([0x11; 16]);
    let mut database = KeePassDatabase::default();
    database.root.id = KdbxUuid::from_bytes([0x01; 16]);
    database.meta.generator = "KeePassXC".into();
    database.meta.name = "Metadata".into();
    database.meta.description = "Preserved <metadata>".into();
    database.meta.default_username = "keeper".into();
    database.meta.settings_changed = Some(timestamp(1_700_000_000));
    database.meta.database_name_changed = Some(timestamp(1_700_000_001));
    database.meta.database_description_changed = Some(timestamp(1_700_000_002));
    database.meta.default_username_changed = Some(timestamp(1_700_000_003));
    database.meta.master_key_changed = Some(timestamp(1_700_000_004));
    database
        .meta
        .custom_data
        .set("Plugin_Mode", "fidelity", Some(timestamp(1_700_000_005)));
    database
        .meta
        .custom_data
        .set("Plugin_Count", "7", Some(timestamp(1_700_000_006)));
    database.meta.custom_icons.push(CustomIcon {
        uuid: icon_id,
        data: vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        name: Some("custom & icon".into()),
        last_modification: Some(timestamp(1_700_000_007)),
    });

    let mut entry = Entry::new("icon user");
    entry.id = KdbxUuid::from_bytes([0x02; 16]);
    entry.custom_icon_id = icon_id;
    entry.icon_id = 17;
    entry.custom_data.set("Entry_Plugin", "value", None);
    database.root.entries.push(entry);

    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.meta, database.meta);
    assert_eq!(loaded.root.id, database.root.id);
    assert_eq!(loaded.root.entries[0].id, database.root.entries[0].id);
    assert_eq!(loaded.root.entries[0].icon_id, 17);
    assert_eq!(loaded.root.entries[0].custom_icon_id, icon_id);
    assert_eq!(
        loaded.root.entries[0].custom_data,
        database.root.entries[0].custom_data
    );
}

#[test]
fn public_header_custom_data_preserves_all_variant_types() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.typed_public_custom_data.set("u32", 7_u32);
    database.typed_public_custom_data.set("u64", 8_u64);
    database.typed_public_custom_data.set("bool", true);
    database.typed_public_custom_data.set("i32", -9_i32);
    database.typed_public_custom_data.set("i64", -10_i64);
    database
        .typed_public_custom_data
        .set("string", "header plugin");
    database
        .typed_public_custom_data
        .set("bytes", vec![0x00, 0xff, 0x42]);
    database.typed_public_custom_data.set("u32", 11_u32);

    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(
        loaded.typed_public_custom_data,
        database.typed_public_custom_data
    );
    assert_eq!(
        loaded.public_custom_data.get("string"),
        Some("header plugin")
    );
    assert_eq!(
        loaded.typed_public_custom_data.items()[0].value,
        VariantValue::UInt32(11)
    );
    assert!(KdbxXml::export(&loaded).is_err());
}

#[test]
fn string_public_header_custom_data_preserves_existing_api() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .public_custom_data
        .set("Plugin_Key", "plugin value", None);
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(loaded.public_custom_data, database.public_custom_data);
    assert!(matches!(
        loaded.typed_public_custom_data.get("Plugin_Key"),
        Some(VariantValue::String(value)) if value == "plugin value"
    ));
}

#[test]
fn protected_empty_and_shared_attachments_round_trip_in_order() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    let shared = database
        .binary_pool
        .add(b"shared protected attachment".to_vec(), true);
    let empty = database.binary_pool.add(Vec::new(), true);
    let plain = database.binary_pool.add(b"plain".to_vec(), false);

    let mut entry = Entry::new("attachments");
    entry.set_field(Field {
        key: "Password".into(),
        value: ProtectedValue::from_text("first protected field"),
        protected: true,
        protect_in_memory: true,
    });
    entry.attachments.push(Attachment {
        name: "shared.txt".into(),
        reference: shared,
    });
    entry.attachments.push(Attachment {
        name: "empty.bin".into(),
        reference: empty,
    });
    entry.attachments.push(Attachment {
        name: "plain.bin".into(),
        reference: plain,
    });

    let mut snapshot = Entry::new("attachments");
    snapshot.id = entry.id;
    snapshot.attachments.push(Attachment {
        name: "history-shared.txt".into(),
        reference: shared,
    });
    entry.history.push(snapshot);
    database.root.entries.push(entry);

    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            compression: neotales_keepass::KdbxCompression::GZip,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(loaded.binary_pool.records().len(), 3);
    assert!(loaded.binary_pool.records()[0].protected);
    assert_eq!(
        loaded.binary_pool.records()[0].data,
        b"shared protected attachment"
    );
    assert!(loaded.binary_pool.records()[1].protected);
    assert!(loaded.binary_pool.records()[1].data.is_empty());
    assert!(!loaded.binary_pool.records()[2].protected);
    assert_eq!(loaded.binary_pool.records()[2].data, b"plain");

    let entry = &loaded.root.entries[0];
    assert_eq!(entry.attachments[0].reference, shared);
    assert_eq!(entry.attachments[1].reference, empty);
    assert_eq!(entry.history[0].attachments[0].reference, shared);
    assert_eq!(
        entry
            .field("Password")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "first protected field"
    );
}

#[test]
fn shared_legacy_xml_attachments_round_trip() {
    let mut database = KeePassDatabase::default();
    let shared = database.binary_pool.add(b"one shared pool".to_vec(), false);
    database.binary_pool.add(Vec::new(), false);
    let mut first = Entry::new("first");
    first.attachments.push(Attachment {
        name: "first.bin".into(),
        reference: shared,
    });
    first.attachments.push(Attachment {
        name: "first-alias.bin".into(),
        reference: shared,
    });
    let mut second = Entry::new("second");
    second.attachments.push(Attachment {
        name: "second.bin".into(),
        reference: shared,
    });
    database.root.entries.push(first);
    database.root.entries.push(second);

    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.meta.legacy_binaries.len(), 2);
    assert_eq!(loaded.binary_pool.records()[0].data, b"one shared pool");
    assert_eq!(loaded.root.entries[0].attachments[0].reference, 0);
    assert_eq!(loaded.root.entries[0].attachments[1].reference, 0);
    assert_eq!(loaded.root.entries[1].attachments[0].reference, 0);
}

#[test]
fn unknown_xml_extensions_load_but_block_lossless_save() {
    let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Generator>test</Generator><Plugin><Payload>keep</Payload></Plugin></Meta>
<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#;
    let database = KdbxXml::import(xml, &KdbxReadLimits::default()).unwrap();
    assert!(!database.can_save_losslessly);
    assert!(KdbxXml::export(&database).is_err());

    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}

#[test]
fn writer_rejects_disagreeing_binary_pools_and_converts_legacy_only_data() {
    let mut database = KeePassDatabase::default();
    database.binary_pool.add(b"inner".to_vec(), false);
    database.meta.legacy_binaries.push(b"different".to_vec());
    let error = KdbxFile::save(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);

    let mut database = KeePassDatabase::default();
    database.meta.legacy_binaries.push(b"legacy only".to_vec());
    let mut entry = Entry::new("legacy attachment");
    entry.attachments.push(Attachment {
        name: "data.bin".into(),
        reference: 0,
    });
    database.root.entries.push(entry);
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let loaded =
        KdbxFile::load_password(bytes.as_slice(), "pw", &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.binary_pool.get(0).unwrap().data, b"legacy only");
}

#[test]
fn writer_rejects_invalid_unprotected_field_bytes_instead_of_replacing_them() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("invalid utf8");
    entry.set_field(Field {
        key: "Note".into(),
        value: ProtectedValue::from_bytes_unprotected(vec![0xff]),
        protected: false,
        protect_in_memory: false,
    });
    database.root.entries.push(entry);
    let error = KdbxFile::save(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Malformed);
}

#[test]
fn kdbx3_writer_rejects_kdbx4_only_public_data_and_fields() {
    let mut database = KeePassDatabase::default();
    database
        .typed_public_custom_data
        .set("plugin", "must not be dropped");
    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);

    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("quality"));
    database.root.entries[0].quality_check = Some(true);
    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}

#[test]
fn plain_xml_rejects_a_protected_password_in_history() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("current");
    let mut snapshot = Entry::new("historical password");
    snapshot.password = ProtectedValue::from_text("history secret");
    entry.history.push(snapshot);
    database.root.entries.push(entry);

    let error = KdbxXml::export(&database).unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}
