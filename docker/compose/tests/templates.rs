//! Integration tests for safe template rendering into resolved Compose documents.

#![cfg(feature = "templates")]

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use neotales_docker_compose::{
    ComposeDocument, ComposePolicy, ComposeResolver, DotenvOptions, InterpolationValues,
    TemplateError, TemplateOptions, TemplateParseOptions, TemplateRenderOptions, Value,
    load_dotenv, render_template,
};

const SAFE_HELPERS: &str = include_str!("fixtures/templates/safe-helpers.gotmpl");
const UNSUPPORTED_ENV: &str = include_str!("fixtures/templates/unsupported-env.gotmpl");
const DOTENV: &str = include_str!("../../../fixtures/compose/v1/dotenv-quoting-order.env");

fn values() -> InterpolationValues {
    InterpolationValues::from_pairs([
        ("repository", "REGISTRY.EXAMPLE/Team"),
        ("release", "candidate"),
        ("component", ""),
    ])
}

#[test]
fn safe_helpers_feed_the_existing_normalized_compose_path() {
    let rendered = render_template(SAFE_HELPERS, &values(), &TemplateOptions::default())
        .expect("safe helper fixture renders");
    let document = ComposeDocument::parse_yaml(&rendered, "safe-helpers.gotmpl")
        .expect("rendered source is normalized Compose YAML");
    let resolved = ComposeResolver::resolve(
        &[document],
        &InterpolationValues::from_pairs([("CHANNEL", "nightly")]),
        ComposePolicy::default(),
    )
    .expect("Compose interpolation uses explicit values");

    let service = resolved.service("app").expect("app service");
    assert_eq!(service.image.as_str(), "registry.example/team:nightly");
    assert_eq!(
        service.environment["REPOSITORY"],
        "\"registry.example/team\""
    );
    assert_eq!(service.environment["RELEASE"], "CANDIDATE");
    assert_eq!(service.environment["COMPONENT"], "app");
}

/// A template must not read the *host* environment.
///
/// `env` exists, because the reference registers it and a template written
/// against the reference would otherwise fail on a name that is genuinely there.
/// What it does not do is read the process environment: it reads the
/// environment handed to the render, so a rendered Compose file is the same on a
/// laptop and in a pipeline. That is the property worth asserting, and the
/// earlier form of this test asserted it by refusing the name outright.
#[test]
fn a_template_cannot_reach_the_host_environment() {
    // With no environment supplied, `env` yields the empty string rather than
    // the caller's own `HOME`. Go's sprig `env` behaves this way for a name that
    // is not set, and a template that probes for an optional value must not fail
    // because the value is absent.
    let rendered = render_template(
        UNSUPPORTED_ENV,
        &InterpolationValues::new(),
        &TemplateOptions::default(),
    )
    .expect("a template with no environment renders");
    assert_eq!(
        rendered.trim(),
        "services:\n  app:\n    image: ''",
        "env read the host environment instead of the empty one supplied"
    );
}

/// A name no helper claims is still an error.
///
/// This is the other half of the safety property: refusing a host-reaching
/// helper is only meaningful if an unknown name is refused rather than rendered
/// as nothing, which would let a typo pass silently.
#[test]
fn an_unknown_helper_is_rejected() {
    let error = render_template(
        "image: '{{ notAHelper \"x\" }}'",
        &InterpolationValues::new(),
        &TemplateOptions::default(),
    )
    .expect_err("an unknown helper is an error");
    assert!(
        error.to_string().contains("notAHelper"),
        "the error should name the helper: {error}"
    );
}

#[test]
fn parse_render_limits_and_cancellation_are_enforced() {
    let values = InterpolationValues::from_pairs([("value", "value")]);

    let source_limit = TemplateOptions::default()
        .with_parse_options(TemplateParseOptions::default().with_max_source_length(1));
    assert_eq!(
        render_template("{{ .value }}", &values, &source_limit),
        Err(TemplateError::ResourceLimitExceeded)
    );

    let output_limit = TemplateOptions::default()
        .with_render_options(TemplateRenderOptions::default().with_max_output_length(1));
    assert_eq!(
        render_template("{{ .value }}", &values, &output_limit),
        Err(TemplateError::ResourceLimitExceeded)
    );

    let cancelled = || true;
    let options = TemplateOptions::default().with_cancellation(&cancelled);
    assert_eq!(
        render_template("{{ .value }}", &values, &options),
        Err(TemplateError::Cancelled)
    );
}

#[test]
fn normalized_non_template_source_preserves_the_original_parse_path() {
    let source = "services:\n  app:\n    image: alpine:3.22\n";
    let callbacks = AtomicUsize::new(0);
    let cancellation = || {
        callbacks.fetch_add(1, Ordering::Relaxed);
        true
    };
    let options = TemplateOptions::default().with_cancellation(&cancellation);

    assert_eq!(
        render_template(source, &InterpolationValues::new(), &options)
            .expect("non-template source remains available"),
        source
    );
    assert_eq!(callbacks.load(Ordering::Relaxed), 0);
    ComposeDocument::parse_yaml(source, "compose.yaml")
        .expect("the normalized parser remains available");
}

#[test]
fn loaded_dotenv_values_feed_templates_without_host_state() {
    let loaded = load_dotenv(DOTENV, "template.env", DotenvOptions::default())
        .expect("dotenv fixture for template values");
    assert_eq!(
        render_template("{{ .ROOT }}", loaded.values(), &TemplateOptions::default()),
        Ok("compose".to_owned())
    );
}

#[test]
fn legacy_typed_template_values_remain_source_compatible() {
    let values = BTreeMap::from([("value".to_owned(), Value::String("legacy".to_owned()))]);
    assert_eq!(
        render_template("{{ .value }}", &values, &TemplateOptions::default()),
        Ok("legacy".to_owned())
    );
}

/// A template with an unset variable renders a supplied default, and the
/// option that allows it is off by default.
///
/// This is the whole reason the option exists. `{{ .env.OPTIONAL | default "x" }}`
/// is how anyone writes a fallback in a Compose template, and under the default
/// the render stopped at the field access before `default` was reached. The
/// default is unchanged on purpose: a typo in a configuration file should stop
/// the render, not become an empty value a container is started with.
#[test]
fn a_missing_variable_is_an_error_by_default_and_a_null_on_request() {
    let source = "image: alpine:{{ .TAG | default \"3.20\" }}";

    let error = render_template(source, &values(), &TemplateOptions::default())
        .expect_err("the default must stop on a value that is not there");
    assert!(
        matches!(error, TemplateError::MissingValue(ref path) if path.contains("TAG")),
        "{error}"
    );

    let lenient = TemplateOptions {
        render: TemplateRenderOptions {
            missing_value: neotales_docker_compose::MissingValueBehavior::Null,
            ..TemplateRenderOptions::default()
        },
        ..TemplateOptions::default()
    };
    let rendered = render_template(source, &values(), &lenient)
        .expect("a helper can answer for a value that is not there");
    assert_eq!(rendered.trim(), "image: alpine:3.20");
}

/// A value that is set is the same either way.
///
/// The option must not become a way to ignore values that *are* present, and the
/// default helper only takes over for an empty value, so a real value wins.
#[test]
fn a_present_value_is_unaffected_by_the_missing_value_behavior() {
    let source = "image: alpine:{{ .TAG | default \"3.20\" }}";
    let values = InterpolationValues::from_pairs([("TAG", "3.21")]);
    for missing_value in [
        neotales_docker_compose::MissingValueBehavior::Error,
        neotales_docker_compose::MissingValueBehavior::Null,
    ] {
        let options = TemplateOptions {
            render: TemplateRenderOptions {
                missing_value,
                ..TemplateRenderOptions::default()
            },
            ..TemplateOptions::default()
        };
        let rendered = render_template(source, &values, &options).expect("a set value renders");
        assert_eq!(rendered.trim(), "image: alpine:3.21", "{missing_value:?}");
    }
}

/// The option forgives a missing leaf, not a missing step on the way to one.
///
/// `{{ .env.MISSING.TAG }}` has nothing to walk into and nothing to hand to a
/// helper, so forgiving it would turn a typo into a silently empty field.
#[test]
fn null_does_not_forgive_walking_through_a_missing_variable() {
    let source = "image: alpine:{{ .MISSING.TAG }}";
    let options = TemplateOptions {
        render: TemplateRenderOptions {
            missing_value: neotales_docker_compose::MissingValueBehavior::Null,
            ..TemplateRenderOptions::default()
        },
        ..TemplateOptions::default()
    };
    assert!(
        render_template(source, &values(), &options).is_err(),
        "walking through a variable that is not there is a mistake either way"
    );
}
