//! Parsed and normalized Docker Bake document values.

use std::{fs, io::Read, path::Path};

use indexmap::IndexMap;
use neotales_env::{Environment, Platform};
use serde::Deserialize;

use crate::error::{BakeError, BakeResult, from_json_error};

/// Default context used when a target does not specify one.
pub const DEFAULT_CONTEXT: &str = ".";
/// Default Dockerfile used when a target does not specify one.
pub const DEFAULT_DOCKERFILE: &str = "Dockerfile";
/// Conventional name used for the default Bake target or group.
pub const DEFAULT_NAME: &str = "default";
/// Maximum size accepted by the bounded JSON document reader.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// A parsed Bake document, retaining declaration order.
///
/// The first slice intentionally models only normalized, non-template Bake
/// JSON. It owns all values and can be normalized without contacting a Docker
/// daemon or `BuildKit` builder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BakeDocument {
    /// Declared Bake variables in declaration order.
    pub variables: IndexMap<String, Variable>,
    /// Declared groups in declaration order.
    pub groups: IndexMap<String, Group>,
    /// Declared targets in declaration order.
    pub targets: IndexMap<String, TargetDefinition>,
}

/// A declared Bake variable.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Variable {
    /// Declared default value. `None` represents a null or absent default.
    pub default: Option<String>,
    /// Optional declared type name, such as `string` or `bool`.
    pub type_name: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// A named collection of target selectors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Group {
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Target or nested-group names in declaration order.
    pub targets: Vec<String>,
}

/// An unmerged target declaration.
///
/// `Option` fields are significant during inheritance: an absent field inherits
/// the base value, while a present field replaces it. Map fields merge by key;
/// list fields replace the inherited list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetDefinition {
    /// Targets whose values are inherited, in precedence order.
    pub inherits: Vec<String>,
    /// Build context.
    pub context: Option<String>,
    /// Dockerfile path.
    pub dockerfile: Option<String>,
    /// Build arguments. A `None` value intentionally asks the builder to use
    /// the Dockerfile default when this document is eventually solved.
    pub args: Option<IndexMap<String, Option<String>>>,
    /// Image labels. A `None` value has the same Dockerfile-default meaning as
    /// a null build argument.
    pub labels: Option<IndexMap<String, Option<String>>>,
    /// Named build contexts, including `target:<name>` references.
    pub contexts: Option<IndexMap<String, String>>,
    /// Image tags.
    pub tags: Option<Vec<String>>,
    /// Target platforms.
    pub platforms: Option<Vec<String>>,
    /// Dockerfile stage to build.
    pub target: Option<String>,
    /// Whether to disable the build cache.
    pub no_cache: Option<bool>,
    /// Whether to pull referenced images.
    pub pull: Option<bool>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// A fully merged target with normalized defaults.
///
/// This is an owned planning value. It does not borrow the parsed document and
/// contains no builder, session, or template-rendering state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTarget {
    /// Target name.
    pub name: String,
    /// Direct bases used to produce this target, in declaration order.
    pub inherits: Vec<String>,
    /// Normalized build context.
    pub context: String,
    /// Normalized Dockerfile path.
    pub dockerfile: String,
    /// Merged build arguments.
    pub args: IndexMap<String, Option<String>>,
    /// Merged image labels.
    pub labels: IndexMap<String, Option<String>>,
    /// Merged named contexts.
    pub contexts: IndexMap<String, String>,
    /// Normalized image tags.
    pub tags: Vec<String>,
    /// Normalized target platforms.
    pub platforms: Vec<String>,
    /// Dockerfile stage to build.
    pub target: Option<String>,
    /// Normalized cache setting.
    pub no_cache: bool,
    /// Normalized pull setting.
    pub pull: bool,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Ordered, platform-aware values supplied for Bake normalization.
///
/// The backing store is `neotales_env::Environment`. No constructor reads the
/// process environment. On Windows, variable lookup is ASCII case-insensitive
/// and the first selected key spelling is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariableValues {
    environment: Environment,
}

impl VariableValues {
    /// Creates an empty value set using host platform key rules.
    #[must_use]
    pub fn new() -> Self {
        Self::with_platform(Platform::host())
    }

    /// Creates an empty value set with explicit platform key rules.
    #[must_use]
    pub fn with_platform(platform: Platform) -> Self {
        Self {
            environment: Environment::new(platform),
        }
    }

    /// Creates values from caller-owned pairs using host platform key rules.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self::from_pairs_with_platform(pairs, Platform::host())
    }

    /// Creates values from caller-owned pairs with explicit platform key rules.
    #[must_use]
    pub fn from_pairs_with_platform<I, K, V>(pairs: I, platform: Platform) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut values = Self::with_platform(platform);
        for (name, value) in pairs {
            values.insert(name, value);
        }
        values
    }

    /// Adopts an ordered environment without copying it.
    #[must_use]
    pub const fn from_environment(environment: Environment) -> Self {
        Self { environment }
    }

    /// Returns the platform rules used for key identity.
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.environment.platform()
    }

    /// Returns the backing ordered environment.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Consumes this wrapper and returns the backing ordered environment.
    #[must_use]
    pub fn into_environment(self) -> Environment {
        self.environment
    }

    /// Adds or replaces a variable value.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.environment.insert(name, value);
    }

    /// Returns a value by platform-aware name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.environment.get(name)
    }

    /// Returns whether a name is explicitly present, including an empty value.
    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.environment.get(name).is_some()
    }

    /// Returns values in first-selected insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.environment
            .as_map()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Returns the number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.environment.as_map().len()
    }

    /// Returns whether no values are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.environment.as_map().is_empty()
    }
}

impl Default for VariableValues {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Environment> for VariableValues {
    fn from(environment: Environment) -> Self {
        Self::from_environment(environment)
    }
}

impl FromIterator<(String, String)> for VariableValues {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self::from_pairs(iter)
    }
}

/// Parses a bounded Bake JSON document.
///
/// The accepted top-level shape is Docker Bake's normalized JSON shape with
/// `variable`, `group`, and `target` properties. HCL, Compose conversion, Go
/// templates, and `BuildKit` solving are deliberately not handled here.
///
/// # Errors
///
/// Returns [`BakeError::DocumentTooLarge`] for oversized input and a JSON or
/// document error for malformed or unsupported input.
pub fn parse_json(input: &str) -> BakeResult<BakeDocument> {
    if input.len() > MAX_DOCUMENT_BYTES {
        return Err(BakeError::DocumentTooLarge {
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    let raw: RawDocument = serde_json::from_str(input).map_err(|error| from_json_error(&error))?;
    raw.into_document()
}

/// Parses a bounded Bake JSON document from a reader.
///
/// # Errors
///
/// Returns an I/O, size, JSON, or document error.
pub fn parse_reader<R: Read>(mut reader: R) -> BakeResult<BakeDocument> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_DOCUMENT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BakeError::Io(error.to_string()))?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(BakeError::DocumentTooLarge {
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    let input =
        std::str::from_utf8(&bytes).map_err(|error| BakeError::InvalidJson(error.to_string()))?;
    parse_json(input)
}

/// Reads and parses a bounded Bake JSON file.
///
/// # Errors
///
/// Returns an I/O, size, JSON, or document error.
pub fn parse_path(path: impl AsRef<Path>) -> BakeResult<BakeDocument> {
    let file = fs::File::open(path).map_err(|error| BakeError::Io(error.to_string()))?;
    parse_reader(file)
}

impl BakeDocument {
    /// Parses a JSON document and returns the declaration model.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`parse_json`].
    pub fn from_json(input: &str) -> BakeResult<Self> {
        parse_json(input)
    }

    /// Returns the names of declared targets in declaration order.
    pub fn target_names(&self) -> impl Iterator<Item = &str> {
        self.targets.keys().map(String::as_str)
    }

    /// Returns the names of declared groups in declaration order.
    pub fn group_names(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    #[serde(default)]
    variable: IndexMap<String, RawVariableDefinition>,
    /// Groups, under Docker's own spelling.
    ///
    /// Both spellings are accepted because Docker accepts both. Measured against
    /// `docker buildx bake --print` on v0.37.1: a document with `"groups"` and one
    /// with `"group"` produce identical output. The reference implementation reads only the
    /// singular (`BakePlanParser.cs:133` — `root.TryGetProperty("group", …)`), so
    /// accepting the plural is strictly more compatible than the reference and
    /// loses nothing the reference accepts.
    #[serde(default, alias = "group")]
    groups: IndexMap<String, RawGroup>,
    #[serde(default)]
    target: IndexMap<String, RawTarget>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVariableDefinition {
    #[serde(default)]
    default: Option<String>,
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    targets: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    #[serde(default)]
    inherits: Vec<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    dockerfile: Option<String>,
    #[serde(default)]
    args: Option<IndexMap<String, Option<String>>>,
    #[serde(default)]
    labels: Option<IndexMap<String, Option<String>>>,
    #[serde(default)]
    contexts: Option<IndexMap<String, String>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default, rename = "no-cache")]
    no_cache: Option<bool>,
    #[serde(default)]
    pull: Option<bool>,
    #[serde(default)]
    description: Option<String>,
}

impl RawDocument {
    fn into_document(self) -> BakeResult<BakeDocument> {
        let mut variables = IndexMap::with_capacity(self.variable.len());
        for (name, variable) in self.variable {
            validate_name("variable", &name)?;
            variables.insert(
                name,
                Variable {
                    default: variable.default,
                    type_name: variable.type_name,
                    description: variable.description,
                },
            );
        }

        let mut groups = IndexMap::with_capacity(self.groups.len());
        for (name, group) in self.groups {
            validate_name("group", &name)?;
            groups.insert(
                name,
                Group {
                    description: group.description,
                    targets: group.targets,
                },
            );
        }

        let mut targets = IndexMap::with_capacity(self.target.len());
        for (name, target) in self.target {
            validate_name("target", &name)?;
            targets.insert(
                name,
                TargetDefinition {
                    inherits: target.inherits,
                    context: target.context,
                    dockerfile: target.dockerfile,
                    args: target.args,
                    labels: target.labels,
                    contexts: target.contexts,
                    tags: target.tags,
                    platforms: target.platforms,
                    target: target.target,
                    no_cache: target.no_cache,
                    pull: target.pull,
                    description: target.description,
                },
            );
        }

        Ok(BakeDocument {
            variables,
            groups,
            targets,
        })
    }
}

pub(crate) fn validate_name(kind: &'static str, name: &str) -> BakeResult<()> {
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(BakeError::InvalidName {
            kind,
            name: name.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{BakeDocument, MAX_DOCUMENT_BYTES, parse_json, parse_reader};
    use crate::BakeError;

    #[test]
    fn parses_canonical_json_and_preserves_declaration_order() {
        let document = parse_json(
            r#"{
                "target": {
                    "z": {"tags": ["z:latest"]},
                    "a": {"tags": ["a:latest"]}
                },
                "group": {"default": {"targets": ["z", "a"]}},
                "variable": {"TAG": {"default": "latest", "type": "string"}}
            }"#,
        )
        .expect("valid Bake JSON");
        assert_eq!(document.target_names().collect::<Vec<_>>(), vec!["z", "a"]);
        assert_eq!(document.groups["default"].targets, vec!["z", "a"]);
        assert_eq!(document.variables["TAG"].default.as_deref(), Some("latest"));
        assert_eq!(
            document.variables["TAG"].type_name.as_deref(),
            Some("string")
        );
    }

    #[test]
    fn reads_a_reader_and_rejects_oversized_documents() {
        let document =
            parse_reader(Cursor::new(br#"{"target": {}}"#.as_slice())).expect("reader input");
        assert!(document.targets.is_empty());

        let oversized = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert_eq!(
            parse_reader(Cursor::new(oversized)),
            Err(BakeError::DocumentTooLarge {
                limit: MAX_DOCUMENT_BYTES
            })
        );
        let oversized_text = " ".repeat(MAX_DOCUMENT_BYTES + 1);
        assert_eq!(
            super::parse_json(&oversized_text),
            Err(BakeError::DocumentTooLarge {
                limit: MAX_DOCUMENT_BYTES
            })
        );
    }

    /// Docker accepts both `group` and `groups`.
    ///
    /// Measured against `docker buildx bake --print` on buildx v0.37.1: a
    /// document with `"groups"` and the same document with `"group"` produce
    /// identical output. The reference implementation reads only the singular
    /// (`BakePlanParser.cs:133`), so this parser accepted `"group"` and rejected
    /// `"groups"` — and every test in the workspace used the singular, so the
    /// rejection was not caught by any of them.
    #[test]
    fn both_group_spellings_parse_to_the_same_document() {
        let singular = parse_json(
            r#"{
                "group": {"all": {"targets": ["a", "b"]}},
                "target": {
                    "a": {"tags": ["a:latest"]},
                    "b": {"tags": ["b:latest"]}
                }
            }"#,
        )
        .expect("the singular spelling is valid");
        let plural = parse_json(
            r#"{
                "groups": {"all": {"targets": ["a", "b"]}},
                "target": {
                    "a": {"tags": ["a:latest"]},
                    "b": {"tags": ["b:latest"]}
                }
            }"#,
        )
        .expect("the plural spelling is valid too");
        assert_eq!(singular, plural);
        assert_eq!(plural.groups["all"].targets, vec!["a", "b"]);
    }

    #[test]
    fn rejects_unknown_target_fields() {
        let error = parse_json(r#"{"target":{"app":{"future": true}}}"#)
            .expect_err("unknown fields must be rejected");
        assert!(matches!(error, BakeError::UnsupportedField { .. }));
    }

    #[test]
    fn constructs_an_empty_document() {
        let document = BakeDocument::default();
        assert!(document.targets.is_empty());
        assert!(document.groups.is_empty());
    }
}
