// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/server_policy.rs"]
mod server_policy;

use std::error::Error;

use neotales_ssh::direct_tcpip::{DirectTcpipPolicy, DirectTcpipRequest};
use neotales_ssh::tcpip_forward::{TcpipForwardPolicy, TcpipForwardPolicyRequest};
use server_policy::{
    MAX_ENVIRONMENT_NAME_LENGTH, MAX_ENVIRONMENT_NAMES, MAX_ENVIRONMENT_VALUE_LENGTH,
    MAX_FORCE_COMMAND_LENGTH, MAX_PERMIT_OPEN_PATTERN_LENGTH, MAX_PERMIT_OPEN_PATTERNS,
    ServerPolicy, ServerPolicyError,
};

#[test]
fn a_new_policy_denies_all_optional_requests() {
    let policy = ServerPolicy::new();

    assert!(!policy.tty_allowed());
    assert!(!policy.env_allowed("LANG"));
    assert_eq!(policy.forced_command(), None);
    assert!(!policy.open_allowed("host", 22));
}

#[test]
fn exact_environment_and_destination_allow_lists_are_enforced() {
    let mut policy = ServerPolicy::new();
    policy.permit_tty(true);
    policy.accept_env("LANG").expect("LANG is valid");
    policy.permit_open("host:22").expect("pattern is valid");

    assert!(policy.env_allowed("LANG"));
    assert!(!policy.env_allowed("PATH"));
    assert!(!policy.env_allowed("LANGX"));
    assert!(!policy.env_allowed("lan"));
    assert!(policy.tty_allowed());
    assert!(policy.open_allowed("host", 22));
    assert!(!policy.open_allowed("host", 80));
}

#[test]
fn forced_command_preserves_exact_bytes_and_distinguishes_empty() -> Result<(), Box<dyn Error>> {
    let mut policy = ServerPolicy::new();
    let command = [0_u8, b'e', b'c', b'h', 0, 0xff];

    policy.force_command(Some(&command))?;
    assert_eq!(policy.forced_command(), Some(command.as_slice()));

    policy.force_command(Some(&[]))?;
    assert_eq!(policy.forced_command(), Some(&[][..]));

    policy.force_command(None)?;
    assert_eq!(policy.forced_command(), None);
    Ok(())
}

#[test]
fn environment_entries_reject_invalid_names_and_enforce_the_list_bound() {
    let mut policy = ServerPolicy::new();
    let too_long = "x".repeat(MAX_ENVIRONMENT_NAME_LENGTH + 1);

    assert_eq!(
        policy.accept_env(""),
        Err(ServerPolicyError::EmptyEnvironmentName)
    );
    assert_eq!(
        policy.accept_env("NAME=value"),
        Err(ServerPolicyError::InvalidEnvironmentName)
    );
    assert_eq!(
        policy.accept_env("NAME\0value"),
        Err(ServerPolicyError::InvalidEnvironmentName)
    );
    assert_eq!(
        policy.accept_env(&too_long),
        Err(ServerPolicyError::EnvironmentNameTooLong)
    );

    for index in 0..MAX_ENVIRONMENT_NAMES {
        policy
            .accept_env(&format!("NAME_{index}"))
            .expect("bounded name is valid");
    }
    assert_eq!(
        policy.accept_env("ONE_TOO_MANY"),
        Err(ServerPolicyError::TooManyEnvironmentNames)
    );
    assert!(!policy.env_allowed("ONE_TOO_MANY"));

    let exact_length = "x".repeat(MAX_ENVIRONMENT_NAME_LENGTH);
    let mut duplicate_policy = ServerPolicy::new();
    duplicate_policy
        .accept_env(&exact_length)
        .expect("255-byte name is valid");
    assert!(duplicate_policy.env_allowed(&exact_length));
}

#[test]
fn command_and_pattern_entries_enforce_their_independent_byte_limits() {
    let mut command_policy = ServerPolicy::new();
    command_policy
        .force_command(Some(b"kept"))
        .expect("small command is valid");
    let oversized_command = vec![0_u8; MAX_FORCE_COMMAND_LENGTH + 1];
    assert_eq!(
        command_policy.force_command(Some(&oversized_command)),
        Err(ServerPolicyError::ForceCommandTooLong)
    );
    assert_eq!(command_policy.forced_command(), Some(&b"kept"[..]));

    let mut pattern_policy = ServerPolicy::new();
    assert_eq!(
        pattern_policy.permit_open(""),
        Err(ServerPolicyError::EmptyPermitOpenPattern)
    );
    let too_long = "x".repeat(MAX_PERMIT_OPEN_PATTERN_LENGTH + 1);
    assert_eq!(
        pattern_policy.permit_open(&too_long),
        Err(ServerPolicyError::PermitOpenPatternTooLong)
    );
    for index in 0..MAX_PERMIT_OPEN_PATTERNS {
        pattern_policy
            .permit_open(&format!("host-{index}:22"))
            .expect("bounded pattern is valid");
    }
    assert_eq!(
        pattern_policy.permit_open("one-too-many:22"),
        Err(ServerPolicyError::TooManyPermitOpenPatterns)
    );
}

#[test]
fn permit_open_uses_only_star_and_question_marks_as_wildcards() {
    let mut star_policy = ServerPolicy::new();
    star_policy.permit_open("h*:22").expect("pattern is valid");
    assert!(star_policy.open_allowed("host", 22));
    assert!(star_policy.open_allowed("h-other", 22));
    assert!(!star_policy.open_allowed("host", 80));

    let mut question_policy = ServerPolicy::new();
    question_policy
        .permit_open("h?st:22")
        .expect("pattern is valid");
    assert!(question_policy.open_allowed("host", 22));
    assert!(question_policy.open_allowed("hXst", 22));
    assert!(!question_policy.open_allowed("hst", 22));
    assert!(!question_policy.open_allowed("hxxst", 22));

    let mut literal_policy = ServerPolicy::new();
    literal_policy
        .permit_open("!host:22")
        .expect("literal pattern is valid");
    assert!(literal_policy.open_allowed("!host", 22));
    assert!(!literal_policy.open_allowed("other", 22));

    let mut port_pattern_policy = ServerPolicy::new();
    port_pattern_policy
        .permit_open("host:2?0")
        .expect("port pattern is valid");
    assert!(port_pattern_policy.open_allowed("host", 220));
    assert!(port_pattern_policy.open_allowed("host", 200));
    assert!(!port_pattern_policy.open_allowed("host", 202));

    assert!(!star_policy.open_allowed("HOST", 22));
}

#[test]
fn open_allowed_rejects_empty_hosts_and_invalid_ports() {
    let mut policy = ServerPolicy::new();
    policy.permit_open("*").expect("pattern is valid");

    assert!(!policy.open_allowed("", 22));
    assert!(!policy.open_allowed("host", 0));
    assert!(!policy.open_allowed("host", 65_536));
    assert!(policy.open_allowed("host", 1));
    assert!(policy.open_allowed("host", 65_535));
}

#[test]
fn duplicate_allow_list_entries_do_not_consume_capacity() -> Result<(), Box<dyn Error>> {
    let mut policy = ServerPolicy::new();
    for _ in 0..MAX_ENVIRONMENT_NAMES {
        policy.accept_env("LANG")?;
    }
    for _ in 0..MAX_PERMIT_OPEN_PATTERNS {
        policy.permit_open("host:22")?;
    }

    assert!(policy.env_allowed("LANG"));
    assert!(policy.open_allowed("host", 22));
    Ok(())
}

#[test]
fn environment_requests_validate_names_values_without_exposing_payloads()
-> Result<(), Box<dyn Error>> {
    let mut policy = ServerPolicy::new();
    policy.accept_env("LANG")?;

    assert!(policy.environment_allowed("LANG", b"en_US"));
    assert!(policy.env_request_allowed("LANG", b"en_US"));
    assert!(!policy.environment_allowed("LANG", b"bad\0value"));
    assert_eq!(
        ServerPolicy::validate_environment_value(b"bad\0value"),
        Err(ServerPolicyError::InvalidEnvironmentValue)
    );
    assert!(!policy.environment_allowed("LANG", &[0xff]));
    assert!(!policy.environment_allowed("PATH", b"/bin"));
    assert!(policy.environment_value_allowed(b""));
    assert!(!policy.environment_value_allowed(&vec![b'x'; MAX_ENVIRONMENT_VALUE_LENGTH + 1]));

    let mut redacted = ServerPolicy::new();
    redacted.accept_env("SECRET_NAME")?;
    redacted.force_command(Some(b"SECRET_COMMAND"))?;
    redacted.permit_open("secret.example:22")?;
    let debug = format!("{redacted:?}");
    assert!(!debug.contains("SECRET_NAME"));
    assert!(!debug.contains("SECRET_COMMAND"));
    assert!(!debug.contains("secret.example"));
    Ok(())
}

#[test]
fn structured_policy_drives_existing_forwarding_policy_endpoints() -> Result<(), Box<dyn Error>> {
    let mut policy = ServerPolicy::new();
    policy.permit_open("db.example:5432")?;

    let direct = DirectTcpipRequest {
        destination_host: b"db.example",
        destination_port: 5432,
        originator_address: b"client",
        originator_port: 1234,
    };
    assert!(DirectTcpipPolicy::allow(&policy, direct));
    assert!(!DirectTcpipPolicy::allow(
        &policy,
        DirectTcpipRequest {
            destination_host: b"db.example",
            destination_port: 5433,
            originator_address: b"client",
            originator_port: 1234,
        },
    ));

    let forward = TcpipForwardPolicyRequest {
        bind_address: b"db.example",
        port: 5432,
    };
    assert!(TcpipForwardPolicy::allow(&policy, forward));
    assert!(!policy.open_allowed_bytes(&[0xff], 5432));
    Ok(())
}
