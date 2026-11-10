// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/known_hosts.rs"]
mod known_hosts;

use std::error::Error;

use known_hosts::{
    AppendEntry, KnownHosts, KnownHostsMarker, KnownHostsStatus, append_certificate_authority,
    append_hashed, append_plain, append_revoked, base64_decode, encode_base64, fingerprint,
    format_append_entry_with_salt, hash_host_token_with_salt, try_host_token,
};
use neotales_ssh::Writer;

const ALGORITHM: &str = "ssh-ed25519";

#[test]
fn parses_comments_plain_patterns_and_nondefault_ports() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x11)?;
    let encoded = encode_base64(&key);
    let text = format!(
        "\n  # ignored comment\napi*.example,!bastion.example {ALGORITHM} {encoded}\n\
         api?.example {ALGORITHM} {encoded}\n\
         [db.example]:2200 {ALGORITHM} {encoded}\n"
    );
    let hosts = KnownHosts::parse(&text)?;

    assert_eq!(
        hosts.check("api.example", 22, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("bastion.example", 22, &key),
        KnownHostsStatus::NotFound
    );
    assert_eq!(
        hosts.check("API.EXAMPLE", 22, &key),
        KnownHostsStatus::NotFound
    );
    assert_eq!(
        hosts.check("apx.example", 22, &key),
        KnownHostsStatus::NotFound
    );
    assert_eq!(
        hosts.check("db.example", 2200, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("db.example", 22, &key),
        KnownHostsStatus::NotFound
    );
    assert_eq!(hosts.len(), 3);
    Ok(())
}

#[test]
fn matches_hashed_entries_and_pins_the_encoding() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x22)?;
    let salt = [0x33_u8; 20];
    let host_token = try_host_token("hashed.example", 22)?;
    let hashed = hash_host_token_with_salt(&host_token, &salt)?;
    let line = format!("{hashed} {ALGORITHM} {}", encode_base64(&key));
    let port_token = try_host_token("hashed.example", 2200)?;
    let hashed_port = hash_host_token_with_salt(&port_token, &salt)?;
    let port_line = format!("{hashed_port} {ALGORITHM} {}", encode_base64(&key));
    let hosts = KnownHosts::parse(&format!("{line}\n{port_line}\n"))?;

    assert_eq!(
        hashed,
        "|1|MzMzMzMzMzMzMzMzMzMzMzMzMzM=|ZwTv6WWoDbmNa7vP5hekfHBLS20="
    );
    assert_eq!(
        hosts.check("hashed.example", 22, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("hashed.example", 2200, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("other.example", 22, &key),
        KnownHostsStatus::NotFound
    );
    Ok(())
}

#[test]
fn applies_decision_order_and_never_accepts_a_revoked_key() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x44)?;
    let changed = key_blob(0x55)?;
    let line = format!(
        "server.example {ALGORITHM} {}\n@revoked server.example {ALGORITHM} {}\n",
        encode_base64(&key),
        encode_base64(&key)
    );
    let hosts = KnownHosts::parse(&line)?;

    assert_eq!(
        hosts.check("server.example", 22, &key),
        KnownHostsStatus::Revoked
    );
    assert_eq!(
        hosts.check("server.example", 22, &changed),
        KnownHostsStatus::Changed
    );

    let revoked_only = KnownHosts::parse(&format!(
        "@revoked revoked.example {ALGORITHM} {}\n",
        encode_base64(&key)
    ))?;
    assert_eq!(
        revoked_only.check("revoked.example", 22, &key),
        KnownHostsStatus::Revoked
    );
    assert_eq!(
        revoked_only.check("revoked.example", 22, &changed),
        KnownHostsStatus::NotFound
    );
    Ok(())
}

#[test]
fn a_certificate_authority_line_does_not_trust_a_raw_host_key() -> Result<(), Box<dyn Error>> {
    let authority = key_blob(0x66)?;
    let other = key_blob(0x77)?;
    let hosts = KnownHosts::parse(&format!(
        "@cert-authority ca.example {ALGORITHM} {}\n",
        encode_base64(&authority)
    ))?;

    let status = hosts.check("ca.example", 22, &authority);
    assert_eq!(status, KnownHostsStatus::CertificateAuthority);
    assert!(!status.is_trusted());
    assert_eq!(
        hosts.check("ca.example", 22, &other),
        KnownHostsStatus::NotFound
    );

    let with_changed_plain = KnownHosts::parse(&format!(
        "ca.example {ALGORITHM} {}\n@cert-authority ca.example {ALGORITHM} {}\n",
        encode_base64(&other),
        encode_base64(&authority)
    ))?;
    assert_eq!(
        with_changed_plain.check("ca.example", 22, &authority),
        KnownHostsStatus::Changed
    );
    Ok(())
}

#[test]
fn append_writes_plain_hashed_and_marked_lines() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x88)?;
    let mut plain = Vec::new();
    append_plain(&mut plain, "plain.example", 22, &key)?;
    append_hashed(&mut plain, "hashed.example", 2200, &key)?;
    append_revoked(&mut plain, "revoked.example", 22, &key)?;
    append_certificate_authority(&mut plain, "ca.example", 22, &key)?;

    assert!(plain.ends_with(b"\n"));
    let text = std::str::from_utf8(&plain)?;
    let hosts = KnownHosts::parse(text)?;
    assert_eq!(
        hosts.check("plain.example", 22, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("hashed.example", 2200, &key),
        KnownHostsStatus::Trusted
    );
    assert_eq!(
        hosts.check("revoked.example", 22, &key),
        KnownHostsStatus::Revoked
    );
    assert_eq!(
        hosts.check("ca.example", 22, &key),
        KnownHostsStatus::CertificateAuthority
    );

    let entry = AppendEntry::new(["fixed.example"], &key, KnownHostsMarker::None, true)?;
    let fixed = format_append_entry_with_salt(&entry, &[0x5a; 20])?;
    let expected = hash_host_token_with_salt("fixed.example", &[0x5a; 20])?;
    assert!(fixed.starts_with(&format!("{expected} ")));
    assert!(fixed.ends_with('\n'));
    Ok(())
}

#[test]
fn fingerprint_is_stable_and_unpadded() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x42)?;
    assert_eq!(
        fingerprint(&key),
        "SHA256:LgZpRzWEAbVvBimxTv69/UB88PD8jyOSDqfozr+iNX0"
    );
    assert!(!fingerprint(&key).contains('='));
    Ok(())
}

#[test]
fn malformed_markers_and_base64_reject_the_whole_document() -> Result<(), Box<dyn Error>> {
    let key = key_blob(0x99)?;
    let valid = format!("server.example {ALGORITHM} {}", encode_base64(&key));
    let text = format!(
        "{valid}\n@unknown server.example {ALGORITHM} {}\n",
        encode_base64(&key)
    );
    assert!(KnownHosts::parse(&text).is_err());
    assert!(KnownHosts::parse(&format!("{valid} @unknown")).is_err());
    assert!(KnownHosts::parse("server.example ssh-ed25564 !!!").is_err());
    assert_eq!(base64_decode("aGVsbG8=")?, b"hello");
    assert!(base64_decode("aGVsbG8").is_err());
    assert!(base64_decode("aGVsbG8===").is_err());
    Ok(())
}

#[test]
fn a_changed_key_is_rejected_by_an_existing_plain_line() -> Result<(), Box<dyn Error>> {
    let trusted = key_blob(0xaa)?;
    let replacement = key_blob(0xbb)?;
    let hosts = KnownHosts::parse(&format!(
        "server.example {ALGORITHM} {}",
        encode_base64(&trusted)
    ))?;

    assert_eq!(
        hosts.check("server.example", 22, &replacement),
        KnownHostsStatus::Changed
    );
    assert!(!hosts.check("server.example", 22, &replacement).is_trusted());

    let mismatched_algorithm = KnownHosts::parse(&format!(
        "server.example ssh-rsa {}",
        encode_base64(&trusted)
    ))?;
    assert_eq!(
        mismatched_algorithm.check("server.example", 22, &trusted),
        KnownHostsStatus::Changed
    );
    Ok(())
}

fn key_blob(fill: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_string(ALGORITHM)?;
    let point = [fill; 32];
    writer.write_string(&point)?;
    Ok(writer.into_bytes())
}
