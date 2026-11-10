//! Structured values files for Compose Go templates.
//!
//! A Compose template is only useful if it has something to be parameterized
//! with, and a flat string map cannot express it: a values file routinely holds
//! nested maps, lists, numbers, and booleans, and
//! `{{ range $name, $cfg := .values.services }}` needs the structure. This
//! module reads such a file and merges several of them, following the reference
//! implementation's `ComposeGotmpl.ParseValues` and `ComposeGotmpl.Merge`.
//!
//! The format is chosen by extension, and otherwise sniffed, so a file named
//! `values` still works:
//!
//! | Extension | Format |
//! | --- | --- |
//! | `.json` | JSON |
//! | `.yml`, `.yaml` | YAML |
//! | anything else | Sniffed: a leading `{` or `[` means JSON, otherwise YAML. |
//!
//! Only a mapping at the top level is accepted. A values file that is a list or a
//! bare scalar has no key to merge under, and accepting one would mean inventing
//! a root key that the template author never wrote.

use std::collections::BTreeMap;

use neotales_sprig::Value;
use serde::Deserialize;

use crate::error::ComposeError;

/// The decoded contents of one values file.
pub type TemplateValueMap = BTreeMap<String, Value>;

/// Decodes a values file into the structured map a template ranges over.
///
/// A top-level list or scalar is rejected: the values are merged into a single
/// `.values` map, and a list has no key to merge under.
///
/// # Errors
///
/// Returns `compose_values_invalid` when the document cannot be decoded by the
/// format its extension selects, naming the file, and
/// `compose_values_not_a_mapping` when it decodes to anything but a mapping.
pub fn parse_values(content: &str, path: &str) -> Result<TemplateValueMap, ComposeError> {
    if content.trim().is_empty() {
        return Ok(TemplateValueMap::new());
    }
    let document: serde_json::Value = if is_json(content, path) {
        serde_json::from_str(content).map_err(|error| values_error(path, error))?
    } else {
        // YAML is a superset of JSON, so one parser reads both once the format
        // is known. `serde_yaml` keeps numbers and booleans distinct, which is
        // what a template's `if` and number rendering depend on.
        serde_yaml::from_str(content).map_err(|error| values_error(path, error))?
    };
    match document {
        serde_json::Value::Object(entries) => Ok(entries
            .into_iter()
            .map(|(key, value)| (key, json_to_value(value)))
            .collect()),
        other => Err(ComposeError::new(
            "compose_values_not_a_mapping",
            format!(
                "a Compose values file must be a mapping at the top level, found {}",
                json_kind(&other)
            ),
            Some(path.to_owned()),
            "$",
        )),
    }
}

/// Merges `incoming` into `target`, recursing into nested maps.
///
/// This is the reference's `ComposeGotmpl.Merge`. A nested mapping present in
/// both files merges key by key, so an override file can change one leaf of a
/// service without restating the service. Everything else — scalars, lists, a
/// map replacing a non-map — is replaced outright, because there is nothing to
/// merge item by item.
pub fn merge_values(target: &mut TemplateValueMap, incoming: TemplateValueMap) {
    for (key, value) in incoming {
        match (&mut target.get_mut(&key), value) {
            (Some(Value::Map(existing)), Value::Map(child)) => merge_values(existing, child),
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

/// Reports whether a values file should be read as JSON.
fn is_json(content: &str, path: &str) -> bool {
    // The extension decides, case-insensitively, so `VALUES.JSON` and
    // `values.json` are the same file to a reader. Both parsers agree on a
    // mapping, so this only matters for a document one can read and the other
    // cannot.
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str);
    if let Some(extension) = extension {
        if extension.eq_ignore_ascii_case("json") {
            return true;
        }
        if extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml") {
            return false;
        }
    }
    // No usable extension, so the first non-whitespace character decides, as the
    // reference does.
    content
        .chars()
        .find(|character| !character.is_whitespace())
        .is_some_and(|character| character == '{' || character == '[')
}

/// Names the JSON kind of a value for a diagnostic.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "a list",
        serde_json::Value::Object(_) => "a mapping",
    }
}

/// Converts a decoded document into the template value model.
///
/// Numbers become `Value::Number` and null becomes `Value::Null` so a template
/// distinguishes them from the string `"3"` and from an absent member. Every
/// JSON number round-trips through `f64`, which is what `serde_json` decodes and
/// what Go's `text/template` then prints.
fn json_to_value(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => Value::Number(value.as_f64().unwrap_or_default()),
        serde_json::Value::String(value) => Value::String(value),
        serde_json::Value::Array(values) => {
            Value::List(values.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key, json_to_value(value)))
                .collect(),
        ),
    }
}

/// Wraps a decode failure with the file it came from.
fn values_error(path: &str, error: impl std::fmt::Display) -> ComposeError {
    ComposeError::new(
        "compose_values_invalid",
        format!("failed to read Compose values file '{path}': {error}"),
        Some(path.to_owned()),
        "$",
    )
}

/// Builds the root value a Compose template is rendered against.
///
/// The shape matches the reference exactly: `.values` is the merged values map
/// and `.env` is the environment. Both namespaces are always present, so a
/// template that reads `.env` does not have to guard against an absent member
/// when no environment was supplied.
#[must_use]
pub fn template_root(
    values: TemplateValueMap,
    environment: &BTreeMap<String, String>,
) -> BTreeMap<String, Value> {
    let mut root = BTreeMap::new();
    root.insert("values".to_owned(), Value::Map(values));
    root.insert(
        "env".to_owned(),
        Value::Map(
            environment
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect(),
        ),
    );
    root
}

/// Decodes a values document from a string, for callers that already have the
/// bytes.
///
/// This exists so a caller with a JSON document in hand does not have to
/// re-serialize it to satisfy [`parse_values`].
///
/// # Errors
///
/// Returns `compose_values_invalid` when the document cannot be decoded by the
/// format its extension selects.
pub fn parse_values_document<T>(content: &str, path: &str) -> Result<T, ComposeError>
where
    T: for<'de> Deserialize<'de>,
{
    if is_json(content, path) {
        serde_json::from_str(content).map_err(|error| values_error(path, error))
    } else {
        serde_yaml::from_str(content).map_err(|error| values_error(path, error))
    }
}
