//! Integration tests for Compose parsing, interpolation, merging, and resolution.

use std::collections::BTreeMap;

use neotales_docker_compose::{
    ComposeDocument, ComposePolicy, ComposeResolver, ComposeValidationMode, IncludePolicy,
    InterpolationMode, InterpolationPolicy, InterpolationValues, MergePolicy,
    MissingVariablePolicy, ParseOptions, interpolate,
};

fn values() -> InterpolationValues {
    InterpolationValues::from_pairs([("TAG", "2026.09"), ("RELEASE", "stable"), ("CI", "fixture")])
}

fn resolve(source: &str, path: &str) -> neotales_docker_compose::ResolvedComposeDocument {
    let document = ComposeDocument::parse_yaml(source, path).expect("fixture is valid");
    ComposeResolver::resolve(&[document], &values(), ComposePolicy::default())
        .expect("fixture resolves")
}

#[test]
fn yaml_and_json_fixtures_normalize_to_the_same_deterministic_result() {
    let yaml = resolve(
        include_str!("../../../fixtures/compose/v1/service-image-environment.yaml"),
        "service-image-environment.yaml",
    );
    let json_document = ComposeDocument::parse_json(
        include_str!("../../../fixtures/compose/v1/service-image-environment.json"),
        "service-image-environment.json",
    )
    .expect("JSON fixture is valid");
    let json = ComposeResolver::resolve(&[json_document], &values(), ComposePolicy::default())
        .expect("JSON fixture resolves");

    let expected_text =
        include_str!("../../../fixtures/compose/v1/service-image-environment.expected.json");
    let expected: serde_json::Value =
        serde_json::from_str(expected_text).expect("expected fixture is valid JSON");
    let yaml_json: serde_json::Value =
        serde_json::from_str(&yaml.to_json().expect("YAML result serializes")).expect("valid JSON");
    let json_json: serde_json::Value =
        serde_json::from_str(&json.to_json().expect("JSON result serializes")).expect("valid JSON");

    assert_eq!(yaml_json, expected);
    assert_eq!(json_json, expected);
    assert_eq!(yaml, json);
    let yaml_text = yaml.to_json().expect("serializes");
    assert_eq!(yaml_text, expected_text.trim_end());
}

#[test]
fn explicit_normalized_model_is_accepted_without_a_source_parser() {
    let mut service = neotales_docker_compose::ComposeService::new(
        neotales_docker_compose::ImageReference::new("alpine:3.20").expect("valid image"),
    );
    service
        .environment
        .insert("MODE".to_owned(), Some("test".to_owned()));
    let mut services = BTreeMap::new();
    services.insert("app".to_owned(), service);
    let document = neotales_docker_compose::ComposeDocument {
        name: Some("explicit".to_owned()),
        services,
        ..ComposeDocument::default()
    };

    let resolved = ComposeResolver::resolve(
        std::slice::from_ref(&document),
        &InterpolationValues::new(),
        ComposePolicy::default(),
    )
    .expect("explicit model resolves");
    assert_eq!(
        resolved.service("app").expect("app").image.as_str(),
        "alpine:3.20"
    );
    assert_eq!(
        resolved
            .service("app")
            .expect("app")
            .environment
            .get("MODE")
            .map(String::as_str),
        Some("test")
    );
}

#[test]
fn interpolation_uses_only_injected_values_and_preserves_empty_versus_pass_through() {
    let document = ComposeDocument::parse_yaml(
        include_str!("../../../fixtures/compose/v1/service-image-environment.yaml"),
        "compose.yaml",
    )
    .expect("fixture is valid");
    let web = document.service("web").expect("web service");
    assert_eq!(web.environment.get("EMPTY"), Some(&None));
    assert_eq!(
        web.environment.get("LOG_LEVEL"),
        Some(&Some("info".to_owned()))
    );

    let resolved = ComposeResolver::resolve(&[document], &values(), ComposePolicy::default())
        .expect("fixture resolves");
    assert_eq!(
        resolved
            .service("web")
            .expect("web service")
            .environment
            .get("EMPTY")
            .map(String::as_str),
        Some("")
    );
    assert_eq!(
        resolved
            .service("worker")
            .expect("worker service")
            .environment
            .get("CI")
            .map(String::as_str),
        Some("fixture")
    );
}

#[test]
fn interpolation_policy_handles_empty_values_and_rejects_unsafe_forms() {
    let values = InterpolationValues::from_pairs([("SET", "set"), ("EMPTY", "")]);
    let policy = InterpolationPolicy {
        mode: InterpolationMode::ExplicitValues,
        missing: MissingVariablePolicy::Error,
    };
    assert_eq!(
        interpolate("$SET/${EMPTY:-fallback}", &values, policy).expect("safe interpolation"),
        "set/fallback"
    );

    let disabled = InterpolationPolicy::disabled();
    let error =
        interpolate("${SET}", &values, disabled).expect_err("disabled policy rejects tokens");
    assert_eq!(error.code(), "compose_interpolation_disabled");

    let command_error =
        interpolate("$(id)", &values, policy).expect_err("command substitution is rejected");
    assert_eq!(
        command_error.code(),
        "compose_command_substitution_rejected"
    );

    let template_error = interpolate("{{ .Values.image }}", &values, policy)
        .expect_err("template syntax requires the explicit renderer");
    assert_eq!(template_error.code(), "compose_template_rejected");
}

#[test]
fn merge_and_include_policies_are_explicit() {
    let base = ComposeDocument::parse_yaml(
        "services:\n  app:\n    image: alpine:3.20\n    environment:\n      BASE: one\n",
        "base.yaml",
    )
    .expect("base is valid");
    let over = ComposeDocument::parse_yaml(
        "services:\n  app:\n    image: alpine:3.21\n    environment:\n      EXTRA: two\n",
        "override.yaml",
    )
    .expect("override is valid");

    let default_error = ComposeResolver::resolve(
        &[base.clone(), over.clone()],
        &InterpolationValues::new(),
        ComposePolicy::default(),
    )
    .expect_err("default policy rejects multiple documents");
    assert_eq!(default_error.code(), "compose_merge_rejected");

    let policy = ComposePolicy {
        merge: MergePolicy::MergeServices,
        ..ComposePolicy::default()
    };
    let merged = ComposeResolver::resolve(&[base, over], &InterpolationValues::new(), policy)
        .expect("explicit merge succeeds");
    assert_eq!(
        merged
            .service("app")
            .expect("app service")
            .environment
            .get("BASE")
            .map(String::as_str),
        Some("one")
    );
    assert_eq!(
        merged
            .service("app")
            .expect("app service")
            .environment
            .get("EXTRA")
            .map(String::as_str),
        Some("two")
    );

    let main = ComposeDocument::parse_yaml(
        include_str!("../../../fixtures/compose/v1/include-main.yaml"),
        "include-main.yaml",
    )
    .expect("include fixture is valid");
    let shared = ComposeDocument::parse_yaml(
        include_str!("../../../fixtures/compose/v1/include-shared.yaml"),
        "include-shared.yaml",
    )
    .expect("shared fixture is valid");
    let include_error = ComposeResolver::resolve(
        std::slice::from_ref(&main),
        &InterpolationValues::new(),
        ComposePolicy::default(),
    )
    .expect_err("default include policy rejects includes");
    assert_eq!(include_error.code(), "compose_include_rejected");

    let policy = ComposePolicy {
        merge: MergePolicy::MergeServices,
        include: IncludePolicy::CallerSupplied,
        ..ComposePolicy::default()
    };
    let mut includes = BTreeMap::new();
    includes.insert("shared.yaml".to_owned(), shared);
    let resolved = ComposeResolver::resolve_with_includes(
        &[main],
        &InterpolationValues::new(),
        policy,
        &includes,
    )
    .expect("caller-supplied include resolves");
    assert!(resolved.service("shared").is_some());
    assert!(resolved.service("app").is_some());
}

#[test]
fn validation_modes_do_not_silently_apply_unsupported_service_fields() {
    let source = include_str!("../../../fixtures/compose/v1/unsupported-service.yaml");
    let strict = ComposeDocument::parse_yaml_with_options(
        source,
        "unsupported-service.yaml",
        ParseOptions {
            validation: ComposeValidationMode::Strict,
        },
    )
    .expect_err("strict mode rejects build");
    assert_eq!(strict.code(), "compose_unsupported_field");

    let loose = ComposeDocument::parse_yaml_with_options(
        source,
        "unsupported-service.yaml",
        ParseOptions {
            validation: ComposeValidationMode::Loose,
        },
    )
    .expect("loose mode ignores build");
    assert_eq!(
        loose.service("api").expect("api service").image.as_str(),
        "alpine:3.20"
    );
}
