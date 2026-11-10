#![warn(missing_docs)]

//! Repository-native Docker Bake parsing and target planning.
//!
//! This crate accepts Docker Bake's JSON document shape, normalizes
//! declarations, resolves target inheritance, validates group and named-context
//! graphs, and produces an owned target selection. It deliberately does not
//! contact `BuildKit` or inject a solver. The optional `templates` feature adds
//! bounded, caller-driven source rendering while the normalized JSON path stays
//! available by default.
#![doc = include_str!("../README.md")]

mod document;
mod dotenv;
mod error;
mod plan;
#[cfg(feature = "templates")]
mod template;

pub use neotales_env::{Environment as PlatformEnvironment, Platform};

pub use document::{
    BakeDocument, DEFAULT_CONTEXT, DEFAULT_DOCKERFILE, DEFAULT_NAME, Group, MAX_DOCUMENT_BYTES,
    ResolvedTarget, TargetDefinition, Variable, VariableValues, parse_json, parse_path,
    parse_reader,
};
pub use dotenv::{
    DotenvInterpolationPolicy, DotenvOptions, DotenvPolicy, DotenvPrecedence, DotenvSource,
    InvalidDotenvNodePolicy, InvalidEnvironmentKeyPolicy, LoadedDotenv, MAX_DOTENV_BYTES,
    load_dotenv, load_dotenv_path, load_dotenv_sources, load_dotenv_with_values,
};
pub use error::{BakeError, BakeResult};
pub use plan::{NormalizedDocument, TargetGraph, normalize, normalize_with_values};
#[cfg(feature = "templates")]
pub use template::{
    ParseOptions as TemplateParseOptions, RenderOptions as TemplateRenderOptions, TemplateError,
    TemplateOptions, TemplateValues, Value, render_template,
};

/// Parses and normalizes a Bake JSON document.
///
/// # Errors
///
/// Returns the same parsing and inheritance errors as [`parse_json`] and
/// [`normalize`].
pub fn parse_normalized_json(input: &str) -> BakeResult<NormalizedDocument> {
    normalize(&parse_json(input)?)
}

/// Parses a Bake JSON document, normalizes it, and selects a target graph.
///
/// # Errors
///
/// Returns parsing, inheritance, graph-validation, or selection errors.
pub fn parse_and_plan(input: &str, requested: &[&str]) -> BakeResult<TargetGraph> {
    parse_normalized_json(input)?.plan(requested)
}
