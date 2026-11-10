//! Integration tests for safe template rendering into normalized bake documents.

#![cfg(feature = "templates")]

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use neotales_docker_bake::{
    DotenvOptions, TemplateError, TemplateOptions, TemplateParseOptions, TemplateRenderOptions,
    Value, VariableValues, load_dotenv, parse_normalized_json, render_template,
};

const SAFE_HELPERS: &str = include_str!("fixtures/templates/safe-helpers.gotmpl");
const UNSUPPORTED_NETWORK: &str =
    include_str!("fixtures/templates/unsupported-network-helper.gotmpl");
const DOTENV: &str = include_str!("../../../fixtures/compose/v1/dotenv-quoting-order.env");

fn values() -> VariableValues {
    VariableValues::from_pairs([("repository", "REGISTRY.EXAMPLE/Team")])
}

#[test]
fn safe_helpers_feed_the_existing_normalized_bake_path() {
    let rendered = render_template(SAFE_HELPERS, &values(), &TemplateOptions::default())
        .expect("safe helper fixture renders");
    let normalized =
        parse_normalized_json(&rendered).expect("rendered source is normalized Bake JSON");
    let app = normalized.target("app").expect("app target");

    assert_eq!(app.tags, ["registry.example/team:latest"]);
}

#[test]
fn unsupported_network_helpers_are_rejected_without_side_effects() {
    let error = render_template(
        UNSUPPORTED_NETWORK,
        &VariableValues::new(),
        &TemplateOptions::default(),
    )
    .expect_err("network access is not a safe helper");
    assert_eq!(
        error.to_string(),
        "unsupported safe Sprig helper: getHostByName"
    );
}

#[test]
fn parse_render_limits_and_cancellation_are_enforced() {
    let values = VariableValues::from_pairs([("value", "value")]);

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
    let source = r#"{"target":{"app":{"context":"."}}}"#;
    let callbacks = AtomicUsize::new(0);
    let cancellation = || {
        callbacks.fetch_add(1, Ordering::Relaxed);
        true
    };
    let options = TemplateOptions::default().with_cancellation(&cancellation);

    assert_eq!(
        render_template(source, &VariableValues::new(), &options)
            .expect("non-template source remains available"),
        source
    );
    assert_eq!(callbacks.load(Ordering::Relaxed), 0);
    parse_normalized_json(source).expect("the normalized parser remains available");
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
