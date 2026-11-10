// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::io::{self, Cursor, Read, Write};

use neotales_keepass::{
    Attachment, Entry, Group, KdbxCancellation, KdbxCancellationToken, KdbxCredentials,
    KdbxFailureKind, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase, MergeStrategy,
    ProtectedValue, read_key_file,
};

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture reader failure"))
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture writer failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn caller_owned_stream_failures_have_a_distinct_io_contract() {
    let limits = KdbxReadLimits::default();
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = KdbxFile::load(FailingReader, &mut credentials, &limits).unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Io);
    assert!(!error.message.contains("fixture reader failure"));

    let Err(error) = read_key_file(FailingReader) else {
        panic!("failing key-file reader unexpectedly succeeded");
    };
    assert_eq!(error.kind, KdbxFailureKind::Io);
    assert!(!error.message.contains("fixture reader failure"));

    let error = KdbxFile::save(
        &KeePassDatabase::default(),
        FailingWriter,
        &mut credentials,
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Io);
    assert!(!error.message.contains("fixture writer failure"));
}

#[test]
fn simple_open_and_save_defaults_round_trip() {
    let database = KeePassDatabase::default();
    let mut bytes = Vec::new();
    KdbxFile::save_default(&database, &mut bytes, "pw").unwrap();
    let loaded = KdbxFile::open(Cursor::new(bytes), "pw").unwrap();
    assert_eq!(loaded.root.id, database.root.id);
}

#[test]
fn simple_credential_forms_round_trip() {
    let database = KeePassDatabase::default();
    let mut bytes = Vec::new();
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    KdbxFile::save_default_with_credentials(&database, &mut bytes, &mut credentials).unwrap();
    let loaded = KdbxFile::open_with_credentials(Cursor::new(bytes), &mut credentials).unwrap();
    assert_eq!(loaded.root.id, database.root.id);
}

#[test]
fn merge_remaps_attachments_in_new_nested_groups() {
    let mut target = KeePassDatabase::default();
    target.binary_pool.add(b"target".to_vec(), false);

    let mut source = KeePassDatabase::default();
    let source_binary = source.binary_pool.add(b"source".to_vec(), true);
    let mut entry = Entry::new("nested attachment");
    entry.attachments.push(Attachment {
        name: "source.bin".into(),
        reference: source_binary,
    });
    let mut history = Entry::new("history attachment");
    history.id = entry.id;
    history.attachments.push(Attachment {
        name: "history.bin".into(),
        reference: source_binary,
    });
    entry.history.push(history);
    let mut group = Group::new("new group");
    group.add_entry(entry);
    source.root.add_group(group);

    target
        .merge_from(&source, MergeStrategy::PreferSource)
        .unwrap();

    let copied = &target.root.groups[0].entries[0];
    let copied_reference = copied.attachments[0].reference;
    assert_ne!(copied_reference, source_binary);
    assert_eq!(copied.history[0].attachments[0].reference, copied_reference);
    assert_eq!(
        target.binary_pool.records()[copied_reference].data,
        b"source"
    );
    assert!(target.binary_pool.records()[copied_reference].protected);
}

#[test]
fn merge_rejects_invalid_source_references_before_mutation() {
    let mut target = KeePassDatabase::default();
    let mut source = KeePassDatabase::default();
    let mut entry = Entry::new("invalid");
    entry.attachments.push(Attachment {
        name: "missing.bin".into(),
        reference: 9,
    });
    source.root.add_entry(entry);

    let error = target
        .merge_from(&source, MergeStrategy::PreferSource)
        .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::InvalidArgument);
    assert!(target.root.entries.is_empty());
    assert!(target.binary_pool.is_empty());
}

#[test]
fn public_cancellation_stream_and_reveal_forms_compile() {
    let token = KdbxCancellationToken::new();
    token.cancel();
    let cancellation = KdbxCancellation::from_token(&token);
    let mut credentials = KdbxCredentials::password("pw").unwrap();
    let error = KdbxFile::load_with_cancellation(
        Cursor::new(Vec::<u8>::new()),
        &mut credentials,
        &KdbxReadLimits::default(),
        cancellation,
    )
    .unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::Cancelled);

    let value = ProtectedValue::from_text("compile-time callback contract");
    let observed = value.with_revealed_text(str::len).unwrap();
    assert_eq!(observed, "compile-time callback contract".len());
}
