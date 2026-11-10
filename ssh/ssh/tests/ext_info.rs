// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/msg/ext_info.rs"]
mod ext_info;

use ext_info::{
    ExtInfo, Extension, RSA_SHA2_256, RSA_SHA2_512, SERVER_SIG_ALGS, SSH_MSG_EXT_INFO, SSH_RSA,
    preferred_rsa_signature,
};
use neotales_ssh::{Error, MAX_PACKET_CONTENT, Writer, decode_name_list, encode_name_list};

fn wire_extensions(extensions: &[(&[u8], &[u8])]) -> Result<Vec<u8>, Error> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_EXT_INFO);
    let count = u32::try_from(extensions.len()).map_err(|_| Error::LimitExceeded)?;
    writer.write_uint32(count);
    for (name, value) in extensions {
        writer.write_string(name)?;
        writer.write_string(value)?;
    }
    Ok(writer.into_bytes())
}

#[test]
fn server_sig_algs_round_trips_in_order_and_selects_sha2_512() -> Result<(), Error> {
    let names = vec![RSA_SHA2_512.to_owned(), RSA_SHA2_256.to_owned()];
    let message = ExtInfo::new(vec![Extension::from_server_sig_algs(&names)?])?;

    let encoded = message.encode()?;
    assert_eq!(encoded[0], SSH_MSG_EXT_INFO);
    let decoded = ExtInfo::decode(&encoded)?;

    assert_eq!(decoded.server_sig_algs(), Some(names.as_slice()));
    assert_eq!(
        decoded.extension(SERVER_SIG_ALGS).map(Extension::value),
        Some(encode_name_list(&names)?.as_slice())
    );
    assert_eq!(decoded.preferred_rsa_signature(), Some(RSA_SHA2_512));
    assert_eq!(preferred_rsa_signature(&names), Some(RSA_SHA2_512));
    Ok(())
}

#[test]
fn rsa_preference_never_selects_ssh_rsa() {
    assert_eq!(
        preferred_rsa_signature(["ssh-rsa", RSA_SHA2_256]),
        Some(RSA_SHA2_256)
    );
    assert_eq!(preferred_rsa_signature(["ssh-rsa"]), None);
}

#[test]
fn unknown_extension_is_retained_without_affecting_signature_selection() -> Result<(), Error> {
    let unknown_name = "future-extension";
    let unknown_value = vec![0_u8, 0xff, b'x'];
    let message = ExtInfo::new(vec![
        Extension::from_server_sig_algs([RSA_SHA2_256])?,
        Extension::new(unknown_name, &unknown_value)?,
    ])?;

    let encoded = message.encode()?;
    let decoded = ExtInfo::decode(&encoded)?;
    let unknown = decoded
        .extension(unknown_name)
        .ok_or(Error::InvalidPacket)?;

    assert_eq!(decoded.extensions().len(), 2);
    assert_eq!(unknown.name(), unknown_name);
    assert_eq!(unknown.value(), unknown_value);
    assert_eq!(
        decoded.server_sig_algs(),
        Some([RSA_SHA2_256.to_owned()].as_slice())
    );
    assert_eq!(decoded.preferred_rsa_signature(), Some(RSA_SHA2_256));
    Ok(())
}

#[test]
fn truncation_before_the_uint32_count_is_rejected() {
    for input in [
        vec![],
        vec![SSH_MSG_EXT_INFO],
        vec![SSH_MSG_EXT_INFO, 0],
        vec![SSH_MSG_EXT_INFO, 0, 0],
    ] {
        assert_eq!(ExtInfo::decode(&input).err(), Some(Error::Truncated));
    }
}

#[test]
fn truncated_pairs_and_all_other_prefixes_are_rejected() -> Result<(), Error> {
    let message = ExtInfo::new(vec![Extension::from_server_sig_algs([
        RSA_SHA2_256,
        SSH_RSA,
    ])?])?;
    let encoded = message.encode()?;

    for length in 0..encoded.len() {
        assert!(
            ExtInfo::decode(&encoded[..length]).is_err(),
            "accepted {length} encoded bytes"
        );
    }
    assert_eq!(ExtInfo::decode(&encoded[..5]).err(), Some(Error::Truncated));
    Ok(())
}

#[test]
fn duplicate_and_empty_extension_names_are_rejected() -> Result<(), Error> {
    let extension = Extension::new("known", b"value")?;
    assert_eq!(
        ExtInfo::new(vec![extension.clone(), extension]).err(),
        Some(Error::InvalidPacket)
    );
    assert_eq!(Extension::new("", b"value").err(), Some(Error::InvalidName));

    let duplicate = wire_extensions(&[(b"known", b"one"), (b"known", b"two")])?;
    assert_eq!(
        ExtInfo::decode(&duplicate).err(),
        Some(Error::InvalidPacket)
    );

    let empty_name = wire_extensions(&[(b"", b"value")])?;
    assert_eq!(ExtInfo::decode(&empty_name).err(), Some(Error::InvalidName));
    Ok(())
}

#[test]
fn malformed_server_sig_algs_name_lists_are_rejected() -> Result<(), Error> {
    let mut malformed_name_list = Writer::new();
    malformed_name_list.write_uint32(4);
    malformed_name_list.write_string(b"rsa,")?;
    let malformed_name_list = malformed_name_list.into_bytes();
    let malformed =
        wire_extensions(&[(SERVER_SIG_ALGS.as_bytes(), malformed_name_list.as_slice())])?;
    assert_eq!(ExtInfo::decode(&malformed).err(), Some(Error::InvalidName));

    let mut trailing_name_list = encode_name_list([RSA_SHA2_256])?;
    trailing_name_list.push(0);
    assert_eq!(
        decode_name_list(&trailing_name_list).map(|names| names.len()),
        Ok(1)
    );
    let trailing = wire_extensions(&[(SERVER_SIG_ALGS.as_bytes(), trailing_name_list.as_slice())])?;
    assert_eq!(ExtInfo::decode(&trailing).err(), Some(Error::InvalidName));
    Ok(())
}

#[test]
fn wrong_message_type_and_outer_trailing_bytes_are_rejected() -> Result<(), Error> {
    let encoded = ExtInfo::new(vec![Extension::from_server_sig_algs([RSA_SHA2_256])?])?.encode()?;

    let mut wrong_type = encoded.clone();
    wrong_type[0] = SSH_MSG_EXT_INFO + 1;
    assert_eq!(
        ExtInfo::decode(&wrong_type).err(),
        Some(Error::InvalidPacket)
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(ExtInfo::decode(&trailing).err(), Some(Error::InvalidPacket));
    Ok(())
}

#[test]
fn payload_and_extension_count_limits_are_enforced() -> Result<(), Error> {
    let oversized = vec![SSH_MSG_EXT_INFO; MAX_PACKET_CONTENT + 1];
    assert_eq!(
        ExtInfo::decode(&oversized).err(),
        Some(Error::LimitExceeded)
    );

    let mut excessive_count = vec![SSH_MSG_EXT_INFO];
    excessive_count.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ExtInfo::decode(&excessive_count).err(),
        Some(Error::LimitExceeded)
    );
    let too_large = ExtInfo::new(vec![Extension::new(
        "oversized",
        &vec![0_u8; MAX_PACKET_CONTENT],
    )?])?;
    assert_eq!(too_large.encode().err(), Some(Error::LimitExceeded));
    Ok(())
}
