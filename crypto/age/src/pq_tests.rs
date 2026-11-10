use super::*;

#[test]
fn hybrid_keys_and_file_keys_round_trip() {
    let key = AgeKey::generate_hybrid().expect("hybrid key");
    assert!(key.public_key.starts_with("age1pq1"));
    assert!(key.private_key.starts_with("AGE-SECRET-KEY-PQ-1"));

    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    assert!(matches!(recipient, AgeRecipient::Hybrid { .. }));
    assert!(matches!(identity, AgeIdentity::Hybrid { .. }));
    assert_eq!(
        recipient.to_public_key().expect("public key"),
        key.public_key
    );
    assert_eq!(
        identity.to_private_key().expect("private key"),
        key.private_key
    );
    assert_eq!(
        identity
            .recipient()
            .expect("recipient")
            .to_public_key()
            .expect("public key"),
        key.public_key
    );

    let file_key = [0x42u8; 16];
    let stanza = recipient.wrap(&file_key).expect("stanza");
    assert_eq!(stanza.r#type, "mlkem768x25519");
    assert_eq!(stanza.args.len(), 1);
    assert_eq!(stanza.body.len(), 32);
    let unwrapped = identity
        .file_key_from_stanzas(std::slice::from_ref(&stanza))
        .expect("unwrap result")
        .expect("matching identity");
    assert_eq!(unwrapped.as_slice(), file_key);

    let encrypted = AgeFile::encrypt(b"hybrid payload", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"hybrid payload"
    );
}

#[test]
fn hybrid_parse_helpers_dispatch_without_exposing_secrets() {
    let identity = generate_hybrid_identity().expect("identity");
    let encoded = identity.to_private_key().expect("private key");
    let recipient = identity.recipient().expect("recipient");
    let encoded_public = recipient.to_public_key().expect("public key");

    let parsed_identity = parse_identities(&encoded).expect("identities");
    let parsed_recipient = parse_recipients(&encoded_public).expect("recipients");
    assert!(matches!(
        parsed_identity.as_slice(),
        [AgeIdentity::Hybrid { .. }]
    ));
    assert!(matches!(
        parsed_recipient.as_slice(),
        [AgeRecipient::Hybrid { .. }]
    ));
    assert!(parse_identities(&encoded.to_ascii_lowercase()).is_err());
    assert!(parse_recipients(&encoded_public.to_ascii_uppercase()).is_err());
    assert!(!format!("{identity:?}").contains(&encoded));
    assert!(!format!("{recipient:?}").contains(&encoded_public));
}

#[test]
fn hybrid_identity_mismatch_is_not_a_format_error() {
    let identity = generate_hybrid_identity().expect("identity");
    let other = generate_hybrid_identity().expect("other identity");
    let stanza = identity
        .recipient()
        .expect("recipient")
        .wrap(&[7u8; 16])
        .expect("stanza");

    assert!(matches!(
        other.file_key_from_stanzas(std::slice::from_ref(&stanza)),
        Ok(None)
    ));

    let mut malformed_args = stanza.clone();
    malformed_args.args.push("extra".to_owned());
    assert!(identity.file_key_from_stanzas(&[malformed_args]).is_err());

    let mut malformed_body = stanza;
    malformed_body.body.pop();
    assert!(identity.file_key_from_stanzas(&[malformed_body]).is_err());
}

#[test]
fn hybrid_labels_separate_post_quantum_and_classic_recipients() {
    let hybrid = generate_hybrid_identity()
        .expect("hybrid identity")
        .recipient()
        .expect("hybrid recipient");
    let classic = generate_x25519_identity()
        .expect("classic identity")
        .recipient()
        .expect("classic recipient");
    let hybrid_again = generate_hybrid_identity()
        .expect("second hybrid identity")
        .recipient()
        .expect("second hybrid recipient");

    assert!(hybrid.is_hybrid());
    assert!(!classic.is_hybrid());
    assert!(hybrid.compatible_with(&hybrid_again));
    assert!(!hybrid.compatible_with(&classic));
    assert_eq!(hybrid.labels(), &[POSTQUANTUM_LABEL]);
    assert!(classic.labels().is_empty());
    assert!(AgeFile::encrypt(b"mixed", &[hybrid, classic]).is_err());
    assert!(AgeFile::encrypt(b"hybrid", &[hybrid_again]).is_ok());
}
