// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/msg/mod.rs"]
mod msg;

use msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH, CURVE25519_SHA256, DEFAULT_CLIENT_KEX_ALGORITHMS,
    DEFAULT_COMPRESSION_ALGORITHMS, DEFAULT_SERVER_KEX_ALGORITHMS, ECDH_SHA2_NISTP256,
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH, EXT_INFO_C, EXT_INFO_S, HMAC_SHA2_256,
    HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512, HMAC_SHA2_512_ETM_OPENSSH, HOST_KEY_SSH_ED25519,
    KEX_STRICT_C_V00_OPENSSH, KEX_STRICT_S_V00_OPENSSH, KNOWN_HOST_KEY_ALGORITHMS,
    KNOWN_KEX_ALGORITHMS, KexInit, NegotiationError, RSA_SHA2_256, RSA_SHA2_512, SSH_MSG_KEXINIT,
    SUPPORTED_ALGORITHMS, SUPPORTED_COMPRESSION_ALGORITHMS, SUPPORTED_ENCRYPTION_ALGORITHMS,
    SUPPORTED_EXTENSIONS, SUPPORTED_HOST_KEY_ALGORITHMS, SUPPORTED_KEX_ALGORITHMS,
    SUPPORTED_MAC_ALGORITHMS, is_kex_marker, negotiate_algorithm,
};
use neotales_ssh::{Error, Reader, Writer, encode_name_list};

/// How many times `name` appears in `names`.
fn occurrences(names: &[&str], name: &str) -> usize {
    names.iter().filter(|candidate| **candidate == name).count()
}

/// Asserts that a name-list has no repeated entry.
///
/// A duplicate does not change what negotiation selects, so this is not a
/// correctness check — it is a check that the constant says what it means to say
/// when a peer reads it off the wire.
fn assert_no_duplicates(names: &[&str], label: &str) {
    for (index, name) in names.iter().enumerate() {
        assert_eq!(
            occurrences(names, name),
            1,
            "{label} lists {name} more than once, first at index {index}",
        );
    }
}

/// Asserts that every name in a proposal is in the set a handshake accepts.
///
/// This is the assertion that would have caught the original defect: a
/// `SUPPORTED_*` list naming mechanisms the handshake refuses, and a `DEFAULT_*`
/// list proposing them.
fn assert_within_supported(proposal: &[&str], supported: &[&str], label: &str) {
    for name in proposal {
        assert!(
            supported.contains(name),
            "{label} proposes {name}, which no handshake in this crate accepts",
        );
    }
}

/// Asserts that every name in a key-exchange list is either a supported
/// mechanism or an OpenSSH marker.
///
/// The strict-key-exchange and extension-information markers share the
/// key-exchange name-list on the wire and are skipped by negotiation, so a list
/// containing one is not proposing a mechanism this crate cannot run.
fn assert_kex_list_within_supported(proposal: &[&str], label: &str) {
    for name in proposal {
        assert!(
            SUPPORTED_KEX_ALGORITHMS.contains(name) || is_kex_marker(name),
            "{label} proposes {name}, which is neither a supported mechanism nor a marker",
        );
    }
}

#[test]
fn every_default_proposal_is_drawn_from_the_supported_set() {
    assert_kex_list_within_supported(
        msg::kexinit::DEFAULT_KEX_ALGORITHMS,
        "DEFAULT_KEX_ALGORITHMS",
    );
    assert_kex_list_within_supported(
        DEFAULT_CLIENT_KEX_ALGORITHMS,
        "DEFAULT_CLIENT_KEX_ALGORITHMS",
    );
    assert_kex_list_within_supported(
        DEFAULT_SERVER_KEX_ALGORITHMS,
        "DEFAULT_SERVER_KEX_ALGORITHMS",
    );
    // The strict markers are the one name in a default key-exchange list that is
    // not a mechanism, and there is exactly one of the correct half in each.
    assert_eq!(
        DEFAULT_CLIENT_KEX_ALGORITHMS
            .iter()
            .filter(|name| is_kex_marker(name))
            .copied()
            .collect::<Vec<_>>(),
        [KEX_STRICT_C_V00_OPENSSH],
    );
    assert_eq!(
        DEFAULT_SERVER_KEX_ALGORITHMS
            .iter()
            .filter(|name| is_kex_marker(name))
            .copied()
            .collect::<Vec<_>>(),
        [KEX_STRICT_S_V00_OPENSSH],
    );
    assert_within_supported(
        msg::kexinit::DEFAULT_HOST_KEY_ALGORITHMS,
        SUPPORTED_HOST_KEY_ALGORITHMS,
        "DEFAULT_HOST_KEY_ALGORITHMS",
    );
    assert_within_supported(
        msg::kexinit::DEFAULT_ENCRYPTION_ALGORITHMS,
        SUPPORTED_ENCRYPTION_ALGORITHMS,
        "DEFAULT_ENCRYPTION_ALGORITHMS",
    );
    assert_within_supported(
        msg::kexinit::DEFAULT_MAC_ALGORITHMS,
        SUPPORTED_MAC_ALGORITHMS,
        "DEFAULT_MAC_ALGORITHMS",
    );
    assert_within_supported(
        DEFAULT_COMPRESSION_ALGORITHMS,
        SUPPORTED_COMPRESSION_ALGORITHMS,
        "DEFAULT_COMPRESSION_ALGORITHMS",
    );
}

#[test]
fn no_algorithm_list_contains_a_duplicate_entry() {
    assert_no_duplicates(SUPPORTED_KEX_ALGORITHMS, "SUPPORTED_KEX_ALGORITHMS");
    assert_no_duplicates(
        SUPPORTED_HOST_KEY_ALGORITHMS,
        "SUPPORTED_HOST_KEY_ALGORITHMS",
    );
    assert_no_duplicates(KNOWN_KEX_ALGORITHMS, "KNOWN_KEX_ALGORITHMS");
    assert_no_duplicates(KNOWN_HOST_KEY_ALGORITHMS, "KNOWN_HOST_KEY_ALGORITHMS");
    assert_no_duplicates(
        SUPPORTED_ENCRYPTION_ALGORITHMS,
        "SUPPORTED_ENCRYPTION_ALGORITHMS",
    );
    assert_no_duplicates(SUPPORTED_MAC_ALGORITHMS, "SUPPORTED_MAC_ALGORITHMS");
    assert_no_duplicates(
        SUPPORTED_COMPRESSION_ALGORITHMS,
        "SUPPORTED_COMPRESSION_ALGORITHMS",
    );
    assert_no_duplicates(SUPPORTED_EXTENSIONS, "SUPPORTED_EXTENSIONS");
    assert_no_duplicates(SUPPORTED_ALGORITHMS, "SUPPORTED_ALGORITHMS");
    assert_no_duplicates(
        msg::kexinit::DEFAULT_KEX_ALGORITHMS,
        "DEFAULT_KEX_ALGORITHMS",
    );
    assert_no_duplicates(
        DEFAULT_CLIENT_KEX_ALGORITHMS,
        "DEFAULT_CLIENT_KEX_ALGORITHMS",
    );
    assert_no_duplicates(
        DEFAULT_SERVER_KEX_ALGORITHMS,
        "DEFAULT_SERVER_KEX_ALGORITHMS",
    );
    assert_no_duplicates(
        msg::kexinit::DEFAULT_HOST_KEY_ALGORITHMS,
        "DEFAULT_HOST_KEY_ALGORITHMS",
    );
}

#[test]
fn the_known_catalogs_are_strict_supersets_of_the_supported_ones() {
    // `KNOWN_*` exists to be larger. If it stops being larger, one of the two
    // constants is misnamed and one of the two documentation claims is a lie.
    assert!(KNOWN_KEX_ALGORITHMS.len() > SUPPORTED_KEX_ALGORITHMS.len());
    assert!(KNOWN_HOST_KEY_ALGORITHMS.len() > SUPPORTED_HOST_KEY_ALGORITHMS.len());
    for name in SUPPORTED_KEX_ALGORITHMS {
        assert!(
            KNOWN_KEX_ALGORITHMS.contains(name),
            "{name} is accepted by a handshake but not in the known catalogue",
        );
    }
    for name in SUPPORTED_HOST_KEY_ALGORITHMS {
        assert!(
            KNOWN_HOST_KEY_ALGORITHMS.contains(name),
            "{name} is accepted by a handshake but not in the known catalogue",
        );
    }
    // The names that are recognised but never negotiated, named explicitly so
    // that adding a mechanism to either handshake has to delete a line here.
    for name in [
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
    ] {
        assert!(KNOWN_KEX_ALGORITHMS.contains(&name));
        assert!(
            !SUPPORTED_KEX_ALGORITHMS.contains(&name),
            "{name} has no mechanism in kex/, so no handshake can accept it",
        );
    }
    for name in ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256"] {
        assert!(KNOWN_HOST_KEY_ALGORITHMS.contains(&name));
        assert!(
            !SUPPORTED_HOST_KEY_ALGORITHMS.contains(&name),
            "{name} has an implementation but no handshake path to it",
        );
    }
}

#[test]
fn the_unlabelled_catalog_is_exactly_the_union_of_the_supported_ones() {
    let mut expected: Vec<&str> = Vec::new();
    for category in [
        SUPPORTED_KEX_ALGORITHMS,
        SUPPORTED_HOST_KEY_ALGORITHMS,
        SUPPORTED_ENCRYPTION_ALGORITHMS,
        SUPPORTED_MAC_ALGORITHMS,
        SUPPORTED_COMPRESSION_ALGORITHMS,
        SUPPORTED_EXTENSIONS,
    ] {
        for name in category {
            assert!(
                !expected.contains(name),
                "{name} is in two category lists, so the union is not a set",
            );
            expected.push(name);
        }
    }
    assert_eq!(SUPPORTED_ALGORITHMS.len(), expected.len());
    for name in expected {
        assert!(
            SUPPORTED_ALGORITHMS.contains(&name),
            "{name} is in a category list but not in SUPPORTED_ALGORITHMS",
        );
    }
}

#[test]
fn the_default_constructors_propose_only_names_a_handshake_accepts() {
    for message in [
        KexInit::new([0x01; 16]),
        KexInit::default(),
        KexInit::client_defaults([0x02; 16]),
        KexInit::server_defaults([0x03; 16]),
    ] {
        for name in &message.kex_algorithms {
            assert!(
                SUPPORTED_KEX_ALGORITHMS.contains(&name.as_str()) || is_kex_marker(name),
                "a default KEXINIT proposes the key exchange {name}",
            );
        }
        for name in &message.server_host_key_algorithms {
            assert!(
                SUPPORTED_HOST_KEY_ALGORITHMS.contains(&name.as_str()),
                "a default KEXINIT proposes the host key {name}",
            );
        }
        for name in message
            .encryption_algorithms_client_to_server
            .iter()
            .chain(&message.encryption_algorithms_server_to_client)
        {
            assert!(
                SUPPORTED_ENCRYPTION_ALGORITHMS.contains(&name.as_str()),
                "a default KEXINIT proposes the encryption {name}",
            );
        }
        for name in message
            .mac_algorithms_client_to_server
            .iter()
            .chain(&message.mac_algorithms_server_to_client)
        {
            assert!(
                SUPPORTED_MAC_ALGORITHMS.contains(&name.as_str()),
                "a default KEXINIT proposes the integrity algorithm {name}",
            );
        }
        for name in message
            .compression_algorithms_client_to_server
            .iter()
            .chain(&message.compression_algorithms_server_to_client)
        {
            assert!(
                SUPPORTED_COMPRESSION_ALGORITHMS.contains(&name.as_str()),
                "a default KEXINIT proposes the compression {name}",
            );
        }
    }
}

#[test]
fn a_name_this_crate_cannot_run_is_never_selected_rather_than_refused_later() {
    // The failure this correction is about, stated as a property rather than as a
    // constant comparison. For each name the crate recognises but cannot
    // negotiate, a peer that offers only that name must fail *at negotiation*,
    // with `NoCommonAlgorithm`, and a default proposal of ours must not contain
    // it at all.
    //
    // The second half is the one that matters. If a default proposal did offer an
    // unrunnable name and a peer preferred it, the exchange would negotiate
    // successfully and then fail inside the handshake with
    // `UnsupportedAlgorithm` — which is the shape of the original defect. A
    // client and a server that both default will not notice either, because the
    // first entry in both lists is one that works.
    let unrunnable_kex: Vec<&str> = KNOWN_KEX_ALGORITHMS
        .iter()
        .copied()
        .filter(|name| !SUPPORTED_KEX_ALGORITHMS.contains(name))
        .collect();
    assert!(
        !unrunnable_kex.is_empty(),
        "the known catalogue has to be a strict superset for this test to mean anything",
    );
    for name in unrunnable_kex {
        for proposal in [
            KexInit::new([0x07; 16]),
            KexInit::default(),
            KexInit::client_defaults([0x08; 16]),
            KexInit::server_defaults([0x09; 16]),
        ] {
            assert!(
                !proposal
                    .kex_algorithms
                    .iter()
                    .any(|offered| offered == name),
                "a default proposal offers the unrunnable key exchange {name}",
            );
        }

        // A peer that offers only the unrunnable name has nothing in common with
        // a default proposal of ours, so negotiation fails cleanly.
        let peer = KexInit::from_lists(
            [0x0a; 16],
            vec![name.to_owned()],
            vec![HOST_KEY_SSH_ED25519.to_owned()],
            vec![AES128_CTR.to_owned()],
            vec![AES128_CTR.to_owned()],
            vec![HMAC_SHA2_256.to_owned()],
            vec![HMAC_SHA2_256.to_owned()],
            vec![COMPRESSION_NONE.to_owned()],
            vec![COMPRESSION_NONE.to_owned()],
            Vec::new(),
            Vec::new(),
            false,
            0,
        );
        assert_eq!(
            KexInit::new([0x0b; 16]).negotiate(&peer),
            Err(NegotiationError::NoCommonAlgorithm),
            "a default proposal negotiated the unrunnable key exchange {name}",
        );
    }

    // The same for host keys. A peer offering only `rsa-sha2-512` has to fail at
    // negotiation, not be selected and then refused by the host-key check.
    for name in KNOWN_HOST_KEY_ALGORITHMS
        .iter()
        .copied()
        .filter(|name| !SUPPORTED_HOST_KEY_ALGORITHMS.contains(name))
    {
        let peer = KexInit::from_lists(
            [0x0c; 16],
            vec![CURVE25519_SHA256.to_owned()],
            vec![name.to_owned()],
            vec![AES128_CTR.to_owned()],
            vec![AES128_CTR.to_owned()],
            vec![HMAC_SHA2_256.to_owned()],
            vec![HMAC_SHA2_256.to_owned()],
            vec![COMPRESSION_NONE.to_owned()],
            vec![COMPRESSION_NONE.to_owned()],
            Vec::new(),
            Vec::new(),
            false,
            0,
        );
        assert_eq!(
            KexInit::new([0x0d; 16]).negotiate(&peer),
            Err(NegotiationError::NoCommonAlgorithm),
            "a default proposal negotiated the unreachable host key {name}",
        );
    }
}

fn sample_message() -> KexInit {
    KexInit::from_lists(
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        vec![
            CURVE25519_SHA256.to_owned(),
            CURVE25519_SHA256.to_owned(),
            ECDH_SHA2_NISTP256.to_owned(),
        ],
        vec![
            HOST_KEY_SSH_ED25519.to_owned(),
            HOST_KEY_SSH_ED25519.to_owned(),
        ],
        vec![AES256_GCM_OPENSSH.to_owned(), AES128_GCM_OPENSSH.to_owned()],
        vec![AES256_CTR.to_owned(), AES128_CTR.to_owned()],
        vec![
            HMAC_SHA2_512_ETM_OPENSSH.to_owned(),
            HMAC_SHA2_256_ETM_OPENSSH.to_owned(),
        ],
        vec![HMAC_SHA2_512.to_owned(), HMAC_SHA2_256.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        vec!["en-US".to_owned()],
        true,
        0x0102_0304,
    )
}

fn expected_wire(message: &KexInit) -> Result<Vec<u8>, Error> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_KEXINIT);
    for byte in message.cookie {
        writer.write_byte(byte);
    }
    for names in message.name_lists() {
        writer.write_name_list(names)?;
    }
    writer.write_boolean(message.first_kex_packet_follows);
    writer.write_uint32(message.reserved);
    Ok(writer.into_bytes())
}

#[test]
fn fixed_kexinit_vector_round_trips_without_normalization() -> Result<(), Error> {
    let message = sample_message();
    let encoded = message.encode()?;

    assert_eq!(encoded, expected_wire(&message)?);
    assert_eq!(encoded[0], SSH_MSG_KEXINIT);
    assert_eq!(&encoded[1..17], &message.cookie);

    let decoded = KexInit::decode(&encoded)?;
    assert_eq!(decoded, message);
    assert_eq!(decoded.kex_algorithms[1], CURVE25519_SHA256);
    assert!(decoded.languages_client_to_server.is_empty());
    assert_eq!(decoded.languages_server_to_client, ["en-US"]);
    assert!(decoded.first_kex_packet_follows);
    assert_eq!(decoded.reserved, 0x0102_0304);
    Ok(())
}

#[test]
fn encoding_and_decoding_use_ssh_name_list_encoding() -> Result<(), Error> {
    let names = ["first", "first", "second"];
    let encoded_list = encode_name_list(names)?;
    assert_eq!(
        // PROVENANCE: **from the specification**. RFC 4251 section 5 defines the
        // `name-list` type this is an instance of:
        //
        //    A string containing a comma-separated list of names.  A name-list
        //    is represented as a uint32 containing its length (number of bytes
        //    that follow) followed by a comma-separated list of zero or more
        //    names.  A name MUST have a non-zero length, and it MUST NOT
        //    contain a comma (",").  As this is a list of names, all of the
        //    elements contained are names and MUST be in US-ASCII.
        //
        // and RFC 4253 section 7.1 says of the KEXINIT name-lists:
        //
        //    Each of the algorithm name-lists MUST be a comma-separated list of
        //    algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
        //    information in [SSH-NUMBERS]).  Each supported (allowed) algorithm
        //    MUST be listed in order of preference, from most to least.
        //
        // The bytes are ours -- computed by applying those two definitions --
        // but the encoding they encode is fixed by the RFCs. Note what the
        // definition is specific about and that this vector pins: no trailing
        // comma after "second", and a length of 18 covering exactly the 18
        // characters of "first,first,second". What is *not* pinned here is
        // compression: `first` appears twice in the input and is written twice,
        // because a sender does not deduplicate. The name of this test says
        // "without normalization", and that is the property being checked.
        encoded_list,
        [
            0, 0, 0, 18, b'f', b'i', b'r', b's', b't', b',', b'f', b'i', b'r', b's', b't', b',',
            b's', b'e', b'c', b'o', b'n', b'd',
        ]
    );

    let message = KexInit {
        kex_algorithms: names.iter().map(|name| (*name).to_owned()).collect(),
        ..KexInit::default()
    };
    let encoded = message.encode()?;
    let decoded = KexInit::decode(&encoded)?;

    assert_eq!(
        decoded.kex_algorithms,
        vec!["first".to_owned(), "first".to_owned(), "second".to_owned()]
    );
    assert_eq!(
        decoded.compression_algorithms_client_to_server,
        [COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH]
    );
    assert_eq!(
        decoded.compression_algorithms_server_to_client,
        [COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH]
    );
    Ok(())
}

#[test]
fn every_truncation_is_rejected() -> Result<(), Error> {
    let encoded = sample_message().encode()?;
    for length in 0..encoded.len() {
        assert!(
            KexInit::decode(&encoded[..length]).is_err(),
            "accepted {length} bytes"
        );
    }
    assert!(KexInit::decode(&[]).is_err());
    Ok(())
}

#[test]
fn decode_rejects_wrong_type_and_trailing_data() -> Result<(), Error> {
    let mut wrong_type = sample_message().encode()?;
    wrong_type[0] = SSH_MSG_KEXINIT + 1;
    assert_eq!(KexInit::decode(&wrong_type), Err(Error::InvalidPacket));

    let mut trailing = sample_message().encode()?;
    trailing.push(0);
    assert_eq!(KexInit::decode(&trailing), Err(Error::InvalidPacket));
    Ok(())
}

#[test]
fn decode_rejects_invalid_boolean_and_non_utf8_name() {
    let mut invalid_boolean = Writer::new();
    invalid_boolean.write_byte(SSH_MSG_KEXINIT);
    for byte in 0u8..16 {
        invalid_boolean.write_byte(byte);
    }
    for _ in 0..10 {
        invalid_boolean.write_uint32(0);
    }
    invalid_boolean.write_byte(2);
    invalid_boolean.write_uint32(0);
    assert_eq!(
        KexInit::decode(invalid_boolean.as_bytes()),
        Err(Error::InvalidBoolean)
    );

    let mut invalid_name = Writer::new();
    invalid_name.write_byte(SSH_MSG_KEXINIT);
    for byte in 0u8..16 {
        invalid_name.write_byte(byte);
    }
    invalid_name.write_uint32(1);
    invalid_name.write_byte(0xff);
    for _ in 0..9 {
        invalid_name.write_uint32(0);
    }
    invalid_name.write_byte(0);
    invalid_name.write_uint32(0);
    assert_eq!(
        KexInit::decode(invalid_name.as_bytes()),
        Err(Error::InvalidName)
    );
}

#[test]
fn negotiation_follows_client_order_and_deduplicates_only_by_selection() {
    assert_eq!(
        negotiate_algorithm(
            ["client-first", "server-only", "client-first"],
            ["server-only", "client-first"]
        ),
        Ok("client-first".to_owned())
    );
    assert_eq!(
        negotiate_algorithm(["client-first", "server-only"], ["server-only"]),
        Ok("server-only".to_owned())
    );
    assert_eq!(
        negotiate_algorithm(["client-only"], ["server-only"]),
        Err(NegotiationError::NoCommonAlgorithm)
    );
}

#[test]
fn negotiation_error_is_typed_and_does_not_echo_names() {
    let error = negotiate_algorithm(["client-secret"], ["server-secret"]).unwrap_err();
    assert_eq!(error, NegotiationError::NoCommonAlgorithm);
    let text = error.to_string();
    assert!(!text.contains("client-secret"));
    assert!(!text.contains("server-secret"));
}

#[test]
fn whole_message_negotiation_selects_each_category() {
    let client = KexInit::from_lists(
        [0; 16],
        vec![CURVE25519_SHA256.to_owned()],
        vec![HOST_KEY_SSH_ED25519.to_owned()],
        vec![AES128_CTR.to_owned()],
        vec![AES256_CTR.to_owned()],
        vec![HMAC_SHA2_256.to_owned()],
        vec![HMAC_SHA2_512.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    );
    let server = KexInit::from_lists(
        [1; 16],
        vec![ECDH_SHA2_NISTP256.to_owned(), CURVE25519_SHA256.to_owned()],
        vec![RSA_SHA2_256.to_owned(), HOST_KEY_SSH_ED25519.to_owned()],
        vec![AES256_CTR.to_owned(), AES128_CTR.to_owned()],
        vec![AES128_CTR.to_owned(), AES256_CTR.to_owned()],
        vec![HMAC_SHA2_512.to_owned(), HMAC_SHA2_256.to_owned()],
        vec![HMAC_SHA2_256.to_owned(), HMAC_SHA2_512.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    );

    let negotiated = client.negotiate(&server).unwrap();
    assert_eq!(negotiated.kex, CURVE25519_SHA256);
    assert_eq!(negotiated.host_key, HOST_KEY_SSH_ED25519);
    assert_eq!(negotiated.cipher_client_to_server, AES128_CTR);
    assert_eq!(negotiated.cipher_server_to_client, AES256_CTR);
    assert_eq!(negotiated.mac_client_to_server, HMAC_SHA2_256);
    assert_eq!(negotiated.mac_server_to_client, HMAC_SHA2_512);
}

#[test]
fn p0_names_are_present_once_and_compression_is_only_none() {
    let encryption = [
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
        AES128_CTR,
        AES256_CTR,
        AES128_GCM_OPENSSH,
        AES256_GCM_OPENSSH,
    ];
    for name in encryption {
        assert_eq!(
            msg::kexinit::DEFAULT_ENCRYPTION_ALGORITHMS
                .iter()
                .filter(|candidate| **candidate == name)
                .count(),
            1
        );
    }
    let macs = [
        HMAC_SHA2_256,
        HMAC_SHA2_512,
        HMAC_SHA2_256_ETM_OPENSSH,
        HMAC_SHA2_512_ETM_OPENSSH,
    ];
    for name in macs {
        assert_eq!(
            msg::kexinit::DEFAULT_MAC_ALGORITHMS
                .iter()
                .filter(|candidate| **candidate == name)
                .count(),
            1
        );
    }
    assert!(SUPPORTED_KEX_ALGORITHMS.contains(&"mlkem768x25519-sha256"));
    assert_eq!(
        DEFAULT_COMPRESSION_ALGORITHMS,
        [COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH]
    );
    assert_eq!(
        DEFAULT_CLIENT_KEX_ALGORITHMS
            .iter()
            .filter(|name| **name == KEX_STRICT_C_V00_OPENSSH)
            .count(),
        1
    );
    assert_eq!(
        DEFAULT_SERVER_KEX_ALGORITHMS
            .iter()
            .filter(|name| **name == KEX_STRICT_S_V00_OPENSSH)
            .count(),
        1
    );
    assert_eq!(EXT_INFO_C, "ext-info-c");
    assert_eq!(EXT_INFO_S, "ext-info-s");
    assert_eq!(RSA_SHA2_256, "rsa-sha2-256");
    assert_eq!(RSA_SHA2_512, "rsa-sha2-512");
}

#[test]
fn chacha_is_advertised_once_and_requires_an_exact_mutual_name() {
    for names in [
        msg::kexinit::SUPPORTED_ENCRYPTION_ALGORITHMS,
        msg::kexinit::DEFAULT_ENCRYPTION_ALGORITHMS,
    ] {
        assert_eq!(
            names
                .iter()
                .filter(|name| **name == ENCRYPTION_CHACHA20_POLY1305_OPENSSH)
                .count(),
            1
        );
        assert!(names.contains(&ENCRYPTION_CHACHA20_POLY1305_OPENSSH));
    }

    let client = KexInit::client_defaults([1; 16]);
    let server = KexInit::server_defaults([2; 16]);
    let negotiated = client.negotiate(&server).expect("defaults share ChaCha");
    assert_eq!(
        negotiated.cipher_client_to_server,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );
    assert_eq!(
        negotiated.cipher_server_to_client,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );

    let mut aes_server = server.clone();
    for names in [
        &mut aes_server.encryption_algorithms_client_to_server,
        &mut aes_server.encryption_algorithms_server_to_client,
    ] {
        names.retain(|name| name != ENCRYPTION_CHACHA20_POLY1305_OPENSSH);
    }
    let negotiated = client
        .negotiate(&aes_server)
        .expect("the remaining exact AES names still negotiate");
    assert_ne!(
        negotiated.cipher_client_to_server,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );
    assert_ne!(
        negotiated.cipher_server_to_client,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );

    let mut chacha_client = client;
    for names in [
        &mut chacha_client.encryption_algorithms_client_to_server,
        &mut chacha_client.encryption_algorithms_server_to_client,
    ] {
        names.retain(|name| name == ENCRYPTION_CHACHA20_POLY1305_OPENSSH);
    }
    assert_eq!(
        chacha_client.negotiate(&aes_server),
        Err(NegotiationError::NoCommonAlgorithm)
    );
}

#[test]
fn chacha_negotiation_does_not_require_mac_algorithms() {
    let mut client = KexInit::client_defaults([1; 16]);
    let mut server = KexInit::server_defaults([2; 16]);
    client.mac_algorithms_client_to_server.clear();
    client.mac_algorithms_server_to_client.clear();
    server.mac_algorithms_client_to_server.clear();
    server.mac_algorithms_server_to_client.clear();

    let negotiated = client
        .negotiate(&server)
        .expect("ChaCha does not require MAC lists");
    assert_eq!(
        negotiated.cipher_client_to_server,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );
    assert_eq!(
        negotiated.cipher_server_to_client,
        ENCRYPTION_CHACHA20_POLY1305_OPENSSH
    );
    assert!(negotiated.mac_client_to_server.is_empty());
    assert!(negotiated.mac_server_to_client.is_empty());

    let mut disjoint_client = client;
    let mut disjoint_server = server;
    disjoint_client.mac_algorithms_client_to_server = vec![HMAC_SHA2_256.to_owned()];
    disjoint_client.mac_algorithms_server_to_client = vec![HMAC_SHA2_256.to_owned()];
    disjoint_server.mac_algorithms_client_to_server = vec![HMAC_SHA2_512.to_owned()];
    disjoint_server.mac_algorithms_server_to_client = vec![HMAC_SHA2_512.to_owned()];
    let negotiated = disjoint_client
        .negotiate(&disjoint_server)
        .expect("disjoint MAC lists are ignored for ChaCha");
    assert!(negotiated.mac_client_to_server.is_empty());
    assert!(negotiated.mac_server_to_client.is_empty());

    disjoint_client.encryption_algorithms_client_to_server = vec![AES128_CTR.to_owned()];
    disjoint_client.encryption_algorithms_server_to_client = vec![AES128_CTR.to_owned()];
    disjoint_server.encryption_algorithms_client_to_server = vec![AES128_CTR.to_owned()];
    disjoint_server.encryption_algorithms_server_to_client = vec![AES128_CTR.to_owned()];
    assert_eq!(
        disjoint_client.negotiate(&disjoint_server),
        Err(NegotiationError::NoCommonAlgorithm)
    );
}

#[test]
fn reader_sees_exactly_the_encoded_message() -> Result<(), Error> {
    let encoded = sample_message().encode()?;
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.read_byte()?, SSH_MSG_KEXINIT);
    for expected in sample_message().cookie {
        assert_eq!(reader.read_byte()?, expected);
    }
    assert_eq!(reader.read_name_list()?, sample_message().kex_algorithms);
    assert!(!reader.is_empty());
    Ok(())
}
