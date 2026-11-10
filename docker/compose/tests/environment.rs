//! Integration tests for explicit Compose environment values and dotenv precedence.

use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};

use neotales_docker_compose::{
    ComposeDocument, ComposePolicy, ComposeResolver, DotenvOptions, DotenvPolicy, DotenvPrecedence,
    DotenvSource, InterpolationPolicy, InterpolationValues, Platform, load_dotenv,
    load_dotenv_path, load_dotenv_sources,
};

const QUOTING: &str = include_str!("../../../fixtures/compose/v1/dotenv-quoting-order.env");
const INVALID: &str = include_str!("../../../fixtures/compose/v1/dotenv-invalid.env");
const PRECEDENCE_BASE: &str =
    include_str!("../../../fixtures/compose/v1/dotenv-precedence-base.env");
const PRECEDENCE_OVERLAY: &str =
    include_str!("../../../fixtures/compose/v1/dotenv-precedence-overlay.env");

#[test]
fn dotenv_preserves_quotes_order_and_interpolates_only_explicit_values() {
    let policy = DotenvPolicy::default()
        .with_platform(Platform::Unix)
        .with_precedence(DotenvPrecedence::LastWins);
    let loaded = load_dotenv(
        QUOTING,
        "dotenv-quoting-order.env",
        DotenvOptions::default().with_policy(policy),
    )
    .expect("valid dotenv fixture");
    let values = loaded.values();
    let default_precedence = load_dotenv(QUOTING, "default.env", DotenvOptions::default())
        .expect("default injected precedence still uses the last dotenv assignment");
    assert_eq!(default_precedence.values().get("ORDER"), Some("second"));

    assert_eq!(loaded.source(), QUOTING);
    assert_eq!(values.get("ROOT"), Some("compose"));
    assert_eq!(values.get("ORDER"), Some("second"));
    assert_eq!(values.get("SINGLE"), Some("literal $ROOT"));
    assert_eq!(values.get("DOUBLE"), Some("expanded compose"));
    assert_eq!(values.get("RAW"), Some("raw $ROOT"));
    assert_eq!(values.get("PLAIN"), Some("compose"));
    assert_eq!(
        values.iter().map(|(key, _)| key).collect::<Vec<_>>(),
        [
            "ROOT", "ORDER", "SINGLE", "DOUBLE", "RAW", "PLAIN", "Path", "PATH"
        ]
    );

    let document = ComposeDocument::parse_yaml(
        "services:\n  app:\n    image: alpine:3.22\n    environment:\n      ROOT_COPY: ${ROOT}\n",
        "compose.yaml",
    )
    .expect("valid Compose source");
    let resolved = ComposeResolver::resolve(&[document], values, ComposePolicy::default())
        .expect("explicit dotenv values resolve Compose interpolation");
    assert_eq!(
        resolved.service("app").expect("app").environment["ROOT_COPY"],
        "compose"
    );
}

#[test]
fn invalid_node_and_key_policies_are_explicit() {
    let default_error = load_dotenv(INVALID, "invalid.env", DotenvOptions::default())
        .expect_err("invalid node is rejected by default");
    assert_eq!(default_error.code(), "compose_invalid_dotenv_node");

    let key_policy = DotenvPolicy {
        invalid_nodes: neotales_docker_compose::InvalidDotenvNodePolicy::Ignore,
        ..DotenvPolicy::default()
    };
    let key_error = load_dotenv(
        INVALID,
        "invalid.env",
        DotenvOptions::default().with_policy(key_policy),
    )
    .expect_err("invalid key is rejected by the selected policy");
    assert_eq!(key_error.code(), "compose_invalid_environment_name");

    let ignore_policy = DotenvPolicy {
        invalid_nodes: neotales_docker_compose::InvalidDotenvNodePolicy::Ignore,
        invalid_keys: neotales_docker_compose::InvalidEnvironmentKeyPolicy::Ignore,
        ..DotenvPolicy::default()
    };
    let loaded = load_dotenv(
        INVALID,
        "invalid.env",
        DotenvOptions::default().with_policy(ignore_policy),
    )
    .expect("selected policy ignores invalid nodes and keys");
    assert_eq!(loaded.values().get("GOOD"), Some("value"));
    assert_eq!(
        loaded.document().first_invalid().map(|(_, span)| span.line),
        Some(2)
    );
}

#[test]
fn precedence_is_explicit_for_injected_values_and_multiple_sources() {
    let sources = [
        DotenvSource::new("base.env", PRECEDENCE_BASE),
        DotenvSource::new("overlay.env", PRECEDENCE_OVERLAY),
    ];
    let injected = InterpolationValues::from_pairs([("SHARED", "injected")]);

    let injected_wins = load_dotenv_sources(
        &sources,
        &injected,
        DotenvOptions::default()
            .with_policy(DotenvPolicy::default().with_precedence(DotenvPrecedence::InjectedWins)),
    )
    .expect("injected precedence");
    assert_eq!(injected_wins.get("SHARED"), Some("injected"));
    assert_eq!(injected_wins.get("ORDER"), Some("overlay"));

    let dotenv_wins = load_dotenv_sources(
        &sources,
        &injected,
        DotenvOptions::default()
            .with_policy(DotenvPolicy::default().with_precedence(DotenvPrecedence::LastWins)),
    )
    .expect("dotenv precedence");
    assert_eq!(dotenv_wins.get("SHARED"), Some("overlay"));
    assert_eq!(dotenv_wins.get("ORDER"), Some("overlay"));
}

#[test]
fn windows_key_rules_preserve_first_spelling_and_last_value() {
    let policy = DotenvPolicy::default()
        .with_platform(Platform::Windows)
        .with_precedence(DotenvPrecedence::LastWins);
    let values = load_dotenv(
        QUOTING,
        "windows.env",
        DotenvOptions::default().with_policy(policy),
    )
    .expect("Windows dotenv fixture")
    .into_parts()
    .1;

    assert_eq!(values.environment().as_map().len(), 7);
    assert_eq!(
        values
            .environment()
            .as_map()
            .keys()
            .next()
            .map(String::as_str),
        Some("ROOT")
    );
    assert_eq!(values.get("path"), Some("second"));
    assert!(!values.environment().as_map().contains_key("PATH"));
    assert_eq!(
        values
            .environment()
            .as_map()
            .keys()
            .find(|key| key.eq_ignore_ascii_case("PATH"))
            .map(String::as_str),
        Some("Path")
    );
}

#[test]
fn windows_interpolation_lookup_is_case_insensitive() {
    let document = ComposeDocument::parse_yaml(
        "services:\n  app:\n    image: example/app:${TAG}\n",
        "windows-compose.yaml",
    )
    .expect("valid Compose source");
    let values =
        InterpolationValues::from_pairs_with_platform([("tag", "windows")], Platform::Windows);

    let resolved = ComposeResolver::resolve(&[document], &values, ComposePolicy::default())
        .expect("case-insensitive interpolation");
    assert_eq!(
        resolved.service("app").expect("app").image.as_str(),
        "example/app:windows"
    );
}

#[test]
fn dotenv_loading_observes_cooperative_cancellation() {
    let calls = AtomicUsize::new(0);
    let cancelled = || calls.fetch_add(1, Ordering::Relaxed) >= 2;
    let error = load_dotenv(
        QUOTING,
        "cancelled.env",
        DotenvOptions::default().with_cancellation(&cancelled),
    )
    .expect_err("cancellation stops dotenv loading");
    assert_eq!(error.code(), "compose_cancelled");
    assert!(calls.load(Ordering::Relaxed) >= 3);
}

#[test]
fn disabled_interpolation_does_not_consult_values() {
    let policy = DotenvPolicy {
        interpolation: InterpolationPolicy::disabled(),
        ..DotenvPolicy::default()
    };
    let error = load_dotenv(
        "VALUE=$OTHER\n",
        "literal.env",
        DotenvOptions::default().with_policy(policy),
    )
    .expect_err("disabled interpolation rejects the token");
    assert_eq!(error.code(), "compose_interpolation_disabled");
}

#[test]
fn a_dotenv_path_is_opened_only_when_explicitly_selected() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("explicit.env");
    fs::write(&path, "FROM_FILE=selected\n").expect("write fixture");

    let loaded = load_dotenv_path(&path, DotenvOptions::default()).expect("explicit path");
    assert_eq!(loaded.values().get("FROM_FILE"), Some("selected"));
    assert!(loaded.source().contains("FROM_FILE=selected"));
}
