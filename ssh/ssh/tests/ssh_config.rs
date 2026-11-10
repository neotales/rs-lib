// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/ssh_config.rs"]
mod ssh_config;

use std::error::Error;

use ssh_config::{SshConfigError, parse};

#[test]
fn host_wildcards_and_negation_apply_only_to_the_original_host() -> Result<(), Box<dyn Error>> {
    let config = parse("Host api?.example,!skip.example\n  User deploy\n")?;
    let selected = config.resolve("api1.example", "default")?;
    let negated = config.resolve("skip.example", "default")?;
    let miss = config.resolve("api12.example", "default")?;

    assert_eq!(selected.user, "deploy");
    assert_eq!(negated.user, "default");
    assert_eq!(miss.user, "default");
    Ok(())
}

#[test]
fn first_hostname_wins_and_h_n_have_distinct_expansion_meanings() -> Result<(), Box<dyn Error>> {
    let config = parse(
        "Host app\n  HostName backend.example\n  IdentityFile keys/%h-%n\n\
         Host *\n  HostName later.example\n  IdentityFile keys/later\n",
    )?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.hostname, "backend.example");
    assert_eq!(
        resolved.identity_files,
        ["keys/backend.example-app", "keys/later"]
    );
    assert_eq!(
        config.resolve("other", "default")?.hostname,
        "later.example"
    );
    Ok(())
}

#[test]
fn identity_file_expands_port_user_and_literal_percent() -> Result<(), Box<dyn Error>> {
    let config = parse("Host app\n  User deploy\n  Port 2200\n  IdentityFile keys/%p-%r-%%\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 2200);
    assert_eq!(resolved.identity_files, ["keys/2200-deploy-%"]);
    Ok(())
}

#[test]
fn match_exec_does_not_select_its_stanza() -> Result<(), Box<dyn Error>> {
    let config = parse("Host *\n  User selected\nMatch exec true\n  User ignored\n  Port 2200\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.user, "selected");
    assert_eq!(resolved.port, 22);
    Ok(())
}

#[test]
fn include_is_rejected_without_being_read() {
    assert!(matches!(
        parse("Host app\n  Include /path/that/must/not/be/read\n"),
        Err(SshConfigError::Include)
    ));
}

#[test]
fn unknown_keywords_are_retained_without_changing_typed_values() -> Result<(), Box<dyn Error>> {
    let config = parse("Host app\n  VendorFlag enabled\n  Port=2200\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 2200);
    assert_eq!(
        resolved.unknown_keywords,
        [("VendorFlag".to_owned(), "enabled".to_owned())]
    );
    Ok(())
}

#[test]
fn proxy_command_is_returned_as_text_and_quoted_spaces_are_preserved() -> Result<(), Box<dyn Error>>
{
    let config =
        parse("Host app\n  ProxyCommand \"helper --name value\" # retained command text\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(
        resolved.proxy_command.as_deref(),
        Some("helper --name value")
    );
    Ok(())
}

#[test]
fn match_host_uses_an_earlier_hostname_and_supports_case_insensitivity()
-> Result<(), Box<dyn Error>> {
    let config =
        parse("Host alias\n  HostName REMOTE.example\nMatch host remote.*\n  Port 2222\n")?;
    let resolved = config.resolve("alias", "default")?;

    assert_eq!(resolved.port, 2222);
    Ok(())
}

#[test]
fn scalar_and_accumulative_keywords_keep_the_required_order() -> Result<(), Box<dyn Error>> {
    let config = parse(
        "Host *\n  IdentityFile one two\n  CertificateFile cert-a cert-b\n\
         SendEnv LANG LC_*\n  SetEnv MODE=test\n  Port 22\n\
         Host app\n  IdentityFile three\n  Port 2200\n",
    )?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 22);
    assert_eq!(resolved.identity_files, ["one", "two", "three"]);
    assert_eq!(resolved.certificate_files, ["cert-a", "cert-b"]);
    assert_eq!(resolved.send_env, ["LANG", "LC_*"]);
    assert_eq!(resolved.set_env, ["MODE=test"]);
    Ok(())
}
