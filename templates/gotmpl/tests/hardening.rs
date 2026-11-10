//! Tests for the resource limits and the escape hatches around them.
//!
//! These are the cases where a template is deliberately too large, too deep
//! or self-referential, and the parser or renderer has to refuse it rather
//! than allocate until the machine gives up.

// `missing_docs` is a workspace lint aimed at the published API. A test
// binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public
// item in the crate is still reported.
#![allow(missing_docs)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use neotales_gotmpl::{Error, ParseOptions, RenderOptions, Template, Value};

fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

#[test]
fn rejects_duplicate_and_mutually_recursive_definitions() {
    assert_eq!(
        Template::parse("{{ define \"line\" }}one{{ end }}{{ define \"line\" }}two{{ end }}"),
        Err(Error::DuplicateTemplate("line".into()))
    );
    assert_eq!(
        Template::parse(
            "{{ define \"a\" }}{{ template \"b\" . }}{{ end }}{{ define \"b\" }}{{ template \"a\" . }}{{ end }}"
        ),
        Err(Error::RecursiveTemplate("a".into()))
    );
}

#[test]
fn bounds_source_and_parse_nesting() {
    let source_error =
        Template::parse_with_options("hello", ParseOptions::default().with_max_source_length(4))
            .expect_err("source limit should be enforced");
    assert_eq!(source_error, Error::ResourceLimitExceeded);

    let depth_error = Template::parse_with_options(
        "{{ if true }}{{ if true }}{{ if true }}x{{ end }}{{ end }}{{ end }}",
        ParseOptions::default().with_max_nesting_depth(2),
    )
    .expect_err("parse nesting limit should be enforced");
    assert_eq!(depth_error, Error::ResourceLimitExceeded);
}

#[test]
fn bounds_output_iterations_and_function_calls() {
    let output = Template::parse("value={{ .value }}")
        .unwrap()
        .render_typed_with_options(
            &map([("value", Value::String("too long".into()))]),
            RenderOptions::default().with_max_output_length(8),
        )
        .expect_err("output limit should be enforced");
    assert_eq!(output, Error::ResourceLimitExceeded);

    let iterations = Template::parse("{{ range .items }}{{ . }}{{ end }}")
        .unwrap()
        .render_typed_with_options(
            &map([(
                "items",
                Value::List(vec![Value::String("a".into()), Value::String("b".into())]),
            )]),
            RenderOptions::default().with_max_iterations(1),
        );
    assert_eq!(iterations, Err(Error::ResourceLimitExceeded));

    let calls = Template::parse("{{ upper .value }}{{ upper .value }}")
        .unwrap()
        .render_typed_with_options(
            &map([("value", Value::String("x".into()))]),
            RenderOptions::default().with_max_function_calls(1),
        );
    assert_eq!(calls, Err(Error::ResourceLimitExceeded));

    let evaluations = Template::parse("{{ .items }}")
        .unwrap()
        .render_typed_with_options(
            &map([(
                "items",
                Value::List(vec![Value::String("a".into()), Value::String("b".into())]),
            )]),
            RenderOptions::default().with_max_node_evaluations(2),
        );
    assert_eq!(evaluations, Err(Error::ResourceLimitExceeded));
}

#[test]
fn bounds_acyclic_named_template_fanout() {
    let template = Template::parse(
        "{{ template \"root\" . }}{{ define \"root\" }}{{ template \"branch\" . }}{{ template \"branch\" . }}{{ end }}{{ define \"branch\" }}branch{{ end }}",
    )
    .unwrap();
    let result = template.render_typed_with_options(
        &BTreeMap::new(),
        RenderOptions::default().with_max_template_expansions(1),
    );
    assert_eq!(result, Err(Error::ResourceLimitExceeded));
}

#[test]
fn cancellation_is_observed_at_parse_and_render_boundaries() {
    let cancelled = || true;
    assert_eq!(
        Template::parse_with_cancellation("hello", ParseOptions::default(), &cancelled),
        Err(Error::Cancelled)
    );

    let template = Template::parse("hello").unwrap();
    let values = BTreeMap::new();
    let options = RenderOptions::default().with_cancellation(&cancelled);
    assert_eq!(
        template.render_typed_with_options(&values, options),
        Err(Error::Cancelled)
    );
}

#[test]
fn branch_variables_are_lexical_and_shadowing_is_restored() {
    let template = Template::parse(
        "{{ $value := \"outer\" }}{{ if .enabled }}{{ $value := \"if\" }}{{ $value }}{{ end }}|{{ $value }}|{{ with .child }}{{ $value := \"with\" }}{{ $value }}{{ end }}|{{ $value }}|{{ range .items }}{{ $value := \"range\" }}{{ $value }}{{ end }}|{{ $value }}",
    )
    .unwrap();
    let values = map([
        ("enabled", Value::Bool(true)),
        (
            "child",
            Value::Map(BTreeMap::from([(
                "name".into(),
                Value::String("child".into()),
            )])),
        ),
        (
            "items",
            Value::List(vec![Value::String("a".into()), Value::String("b".into())]),
        ),
    ]);
    assert_eq!(
        template.render_typed(&values).unwrap(),
        "if|outer|with|outer|rangerange|outer"
    );
}

#[test]
fn else_and_empty_branches_restore_the_outer_scope() {
    let template = Template::parse(
        "{{ $value := \"outer\" }}{{ if .enabled }}{{ $value := \"then\" }}{{ else }}{{ $value := \"else\" }}{{ $value }}{{ end }}|{{ $value }}|{{ with .empty }}{{ $value := \"bad\" }}{{ else }}{{ $value := \"empty\" }}{{ $value }}{{ end }}|{{ $value }}|{{ range .emptyItems }}{{ $value := \"bad\" }}{{ else }}{{ $value := \"empty-range\" }}{{ $value }}{{ end }}|{{ $value }}",
    )
    .unwrap();
    let values = map([
        ("enabled", Value::Bool(false)),
        ("empty", Value::String(String::new())),
        ("emptyItems", Value::List(Vec::new())),
    ]);
    assert_eq!(
        template.render_typed(&values).unwrap(),
        "else|outer|empty|outer|empty-range|outer"
    );
}

#[test]
fn root_scope_survives_nested_dot_changes() {
    let template = Template::parse(
        "{{ with .child }}{{ range .items }}{{ $.name }}={{ . }}{{ end }}{{ end }}",
    )
    .unwrap();
    let values = map([
        ("name", Value::String("root".into())),
        (
            "child",
            Value::Map(BTreeMap::from([(
                "items".into(),
                Value::List(vec![
                    Value::String("one".into()),
                    Value::String("two".into()),
                ]),
            )])),
        ),
    ]);
    assert_eq!(template.render_typed(&values).unwrap(), "root=oneroot=two");
}

#[test]
fn named_templates_isolate_variables_and_use_the_invocation_root() {
    let template = Template::parse(
        "{{ $caller := \"caller\" }}{{ template \"show\" .child }}{{ $caller }}{{ define \"show\" }}{{ $local := \"local\" }}{{ $local }}={{ $.name }}{{ end }}",
    )
    .unwrap();
    let values = map([
        ("name", Value::String("root".into())),
        (
            "child",
            Value::Map(BTreeMap::from([(
                "name".into(),
                Value::String("child".into()),
            )])),
        ),
    ]);
    assert_eq!(template.render_typed(&values).unwrap(), "local=childcaller");

    let isolated = Template::parse(
        "{{ $caller := \"caller\" }}{{ template \"show\" . }}{{ define \"show\" }}{{ $caller }}{{ end }}",
    )
    .unwrap();
    assert_eq!(
        isolated.render_typed(&BTreeMap::new()),
        Err(Error::MissingVariable("caller".into()))
    );
}

#[test]
fn compound_values_and_render_depth_are_bounded_without_recursive_rendering() {
    let mut value = Value::String("leaf".into());
    for _ in 0..128 {
        value = Value::List(vec![value]);
    }
    let result = Template::parse("{{ . }}")
        .unwrap()
        .render_typed_with_options(
            &map([("value", value)]),
            RenderOptions::default().with_max_nesting_depth(8),
        );
    assert_eq!(result, Err(Error::ResourceLimitExceeded));
}

#[test]
fn parsed_templates_can_be_rendered_concurrently_with_independent_options() {
    let template = Arc::new(Template::parse("{{ .value }}").unwrap());
    let handles = (0..8)
        .map(|index| {
            let template = Arc::clone(&template);
            thread::spawn(move || {
                let values = map([("value", Value::String(index.to_string()))]);
                template.render_typed(&values).unwrap()
            })
        })
        .collect::<Vec<_>>();
    for (index, handle) in handles.into_iter().enumerate() {
        assert_eq!(handle.join().unwrap(), index.to_string());
    }
}

#[test]
fn cancellation_can_be_requested_after_render_starts() {
    let calls = AtomicUsize::new(0);
    let cancelled = || calls.fetch_add(1, Ordering::Relaxed) > 3;
    let template = Template::parse("{{ range . }}{{ . }}{{ end }}").unwrap();
    let values = map([(
        "value",
        Value::List(
            (0..32)
                .map(|index| Value::String(index.to_string()))
                .collect(),
        ),
    )]);
    let options = RenderOptions::default().with_cancellation(&cancelled);
    assert_eq!(
        template.render_typed_with_options(&values, options),
        Err(Error::Cancelled)
    );
}
