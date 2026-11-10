//! Conformance tests driven by the shared JSON fixture set.
//!
//! Every case in `fixtures/gotmpl/v1.json` is rendered and compared, so
//! adding a case to the fixture is the way to add a test here.

// `missing_docs` is a workspace lint aimed at the published API. A test
// binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public
// item in the crate is still reported.
#![allow(missing_docs)]

use std::collections::BTreeMap;

use neotales_gotmpl::{Template, Value};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureSet {
    version: u8,
    cases: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    template: String,
    data: serde_json::Value,
    output: Option<String>,
    error: Option<String>,
    diagnostic: Option<String>,
}

#[test]
fn renders_every_v1_conformance_fixture() {
    let fixtures: FixtureSet =
        serde_json::from_str(include_str!("../../../fixtures/gotmpl/v1.json"))
            .expect("checked-in fixture JSON must be valid");
    assert_eq!(fixtures.version, 1, "unsupported fixture format version");

    for fixture in fixtures.cases {
        let Fixture {
            name,
            template,
            data,
            output,
            error,
            diagnostic,
        } = fixture;
        assert!(
            output.is_some() ^ error.is_some(),
            "fixture {name} must specify exactly one result"
        );
        assert!(
            output.is_none() || diagnostic.is_none(),
            "fixture {name} must not specify a diagnostic for a successful result"
        );
        if let Some(expected) = error.as_deref() {
            assert!(
                !expected.trim().is_empty(),
                "fixture {name} must specify a meaningful expected error"
            );
        }
        if let Some(expected) = diagnostic.as_deref() {
            assert!(
                !expected.trim().is_empty(),
                "fixture {name} must specify a meaningful diagnostic"
            );
        }

        let expected_diagnostic = diagnostic.as_deref();
        let rendered = Template::parse(&template)
            .and_then(|template| template.render_typed(&fixture_data(data)));
        match (output, error, expected_diagnostic, rendered) {
            (Some(expected), None, None, Ok(actual)) => {
                assert_eq!(actual, expected, "fixture {name}");
            }
            (None, Some(expected), expected_diagnostic, Err(actual)) => {
                assert_eq!(actual.to_string(), expected, "fixture {name}");
                if let Some(expected_diagnostic) = expected_diagnostic {
                    assert_eq!(
                        diagnostic_for_error(&actual),
                        expected_diagnostic,
                        "fixture {name} diagnostic"
                    );
                }
            }
            (Some(expected), None, _, Err(actual)) => {
                panic!("fixture {name} rendered error instead of {expected:?}: {actual}")
            }
            (None, Some(expected), _, Ok(actual)) => {
                panic!("fixture {name} rendered {actual:?} instead of error {expected:?}")
            }
            (Some(_), None, Some(_), Ok(_)) => {
                panic!("fixture {name} specifies both output and diagnostic")
            }
            _ => panic!("fixture {name} must specify exactly one result"),
        }
    }
}

fn diagnostic_for_error(error: &neotales_gotmpl::Error) -> &'static str {
    match error {
        neotales_gotmpl::Error::MissingValue(_) => "missing_value",
        neotales_gotmpl::Error::MissingVariable(_) => "missing_variable",
        neotales_gotmpl::Error::MissingTemplate(_) => "missing_template",
        neotales_gotmpl::Error::Helper(_) => "unsupported_function",
        neotales_gotmpl::Error::UnterminatedAction
        | neotales_gotmpl::Error::UnterminatedComment
        | neotales_gotmpl::Error::EmptyAction
        | neotales_gotmpl::Error::MalformedTrimMarker
        | neotales_gotmpl::Error::InvalidQuotedString
        | neotales_gotmpl::Error::CharacterLiteral
        | neotales_gotmpl::Error::UnsupportedAction(_)
        | neotales_gotmpl::Error::UnexpectedControl(_)
        | neotales_gotmpl::Error::DuplicateTemplate(_)
        | neotales_gotmpl::Error::RecursiveTemplate(_) => "parse_error",
        neotales_gotmpl::Error::ResourceLimitExceeded => "resource_limit",
        neotales_gotmpl::Error::Cancelled => "cancelled",
    }
}

fn fixture_data(value: serde_json::Value) -> BTreeMap<String, Value> {
    let Value::Map(data) = fixture_value(value) else {
        panic!("fixture data must be a JSON object");
    };
    data
}

fn fixture_value(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::String(value) => Value::String(value),
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => {
            Value::Number(value.as_f64().expect("a JSON number fits in f64"))
        }
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Array(values) => {
            Value::List(values.into_iter().map(fixture_value).collect())
        }
        serde_json::Value::Object(values) => Value::Map(
            values
                .into_iter()
                .map(|(key, value)| (key, fixture_value(value)))
                .collect(),
        ),
    }
}
