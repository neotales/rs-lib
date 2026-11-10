//! Explicit dotenv loading through the repository-native parser.

use std::{fmt, fs::File, io::Read, path::Path};

use neotales_dotenv::{Document, Node, QuoteStyle};
use neotales_env::{Platform, interpolate};

use crate::{BakeError, BakeResult, VariableValues};

/// Maximum size accepted for one explicit dotenv source.
pub const MAX_DOTENV_BYTES: usize = 1024 * 1024;

/// Controls interpolation in unquoted and double-quoted dotenv values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DotenvInterpolationPolicy {
    /// Preserve interpolation-looking text without consulting values.
    Disabled,
    /// Expand only names present in the ordered explicit environment.
    #[default]
    ExplicitValues,
}

/// Controls malformed nodes retained by `neotales-dotenv`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InvalidDotenvNodePolicy {
    /// Reject the first invalid node with its source line.
    #[default]
    Reject,
    /// Preserve the node in the source document but omit it from values.
    Ignore,
}

/// Controls assignments whose names are not environment variable names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InvalidEnvironmentKeyPolicy {
    /// Reject the assignment with its source line and key.
    #[default]
    Reject,
    /// Preserve the assignment in the source document but omit it from values.
    Ignore,
}

/// Controls conflicts between injected values and explicitly loaded dotenvs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DotenvPrecedence {
    /// Injected values are protected; later dotenv values win among themselves.
    #[default]
    InjectedWins,
    /// Later dotenv assignments and sources win, including over injected values.
    LastWins,
}

/// Repository-owned policy for converting dotenv documents to Bake values.
///
/// `neotales-dotenv` remains the only assignment parser. This policy owns key
/// validation, malformed-node behavior, interpolation, and precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DotenvPolicy {
    /// Platform rules for key identity. The default uses the host platform.
    pub platform: Platform,
    /// Treatment of nodes that are not comments, blanks, or assignments.
    pub invalid_nodes: InvalidDotenvNodePolicy,
    /// Treatment of assignments with invalid environment names.
    pub invalid_keys: InvalidEnvironmentKeyPolicy,
    /// Conflict precedence between injected values and dotenv assignments.
    pub precedence: DotenvPrecedence,
    /// Interpolation policy for unquoted and double-quoted values.
    pub interpolation: DotenvInterpolationPolicy,
}

impl DotenvPolicy {
    /// Returns this policy with different platform-aware key rules.
    #[must_use]
    pub const fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    /// Returns this policy with a different precedence rule.
    #[must_use]
    pub const fn with_precedence(mut self, precedence: DotenvPrecedence) -> Self {
        self.precedence = precedence;
        self
    }

    /// Returns this policy with different malformed-node handling.
    #[must_use]
    pub const fn with_invalid_nodes(mut self, invalid_nodes: InvalidDotenvNodePolicy) -> Self {
        self.invalid_nodes = invalid_nodes;
        self
    }

    /// Returns this policy with different invalid-key handling.
    #[must_use]
    pub const fn with_invalid_keys(mut self, invalid_keys: InvalidEnvironmentKeyPolicy) -> Self {
        self.invalid_keys = invalid_keys;
        self
    }

    /// Returns this policy with different explicit interpolation behavior.
    #[must_use]
    pub const fn with_interpolation(mut self, interpolation: DotenvInterpolationPolicy) -> Self {
        self.interpolation = interpolation;
        self
    }
}

impl Default for DotenvPolicy {
    fn default() -> Self {
        Self {
            platform: Platform::host(),
            invalid_nodes: InvalidDotenvNodePolicy::Reject,
            invalid_keys: InvalidEnvironmentKeyPolicy::Reject,
            precedence: DotenvPrecedence::InjectedWins,
            interpolation: DotenvInterpolationPolicy::default(),
        }
    }
}

/// One caller-supplied dotenv document and its diagnostic name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotenvSource {
    path: String,
    source: String,
}

impl DotenvSource {
    /// Creates one named in-memory dotenv source.
    #[must_use]
    pub fn new(path: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
        }
    }

    /// Returns the caller-supplied source name.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact source text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Policy and cooperative cancellation for explicit dotenv loading.
#[derive(Clone, Copy, Default)]
pub struct DotenvOptions<'a> {
    /// Repository-owned parsing and precedence policy.
    pub policy: DotenvPolicy,
    /// Optional callback checked before and between document nodes.
    pub is_cancelled: Option<&'a dyn Fn() -> bool>,
}

impl<'a> DotenvOptions<'a> {
    /// Creates default rejection and injected-value precedence policies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns these options with a different dotenv policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: DotenvPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Returns these options with one cooperative cancellation callback.
    #[must_use]
    pub const fn with_cancellation(mut self, callback: &'a dyn Fn() -> bool) -> Self {
        self.is_cancelled = Some(callback);
        self
    }
}

impl fmt::Debug for DotenvOptions<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DotenvOptions")
            .field("policy", &self.policy)
            .field("has_cancellation", &self.is_cancelled.is_some())
            .finish()
    }
}

/// A parsed source document and the ordered values selected from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedDotenv {
    document: Document,
    values: VariableValues,
}

impl LoadedDotenv {
    /// Returns the source-preserving parser document, including invalid nodes.
    #[must_use]
    pub const fn document(&self) -> &Document {
        &self.document
    }

    /// Returns the exact dotenv source text.
    #[must_use]
    pub fn source(&self) -> &str {
        self.document.source()
    }

    /// Returns ordered, platform-aware values selected by policy.
    #[must_use]
    pub const fn values(&self) -> &VariableValues {
        &self.values
    }

    /// Consumes the result into its source document and selected values.
    #[must_use]
    pub fn into_parts(self) -> (Document, VariableValues) {
        (self.document, self.values)
    }
}

/// Parses one explicit dotenv source into ordered Bake variable values.
///
/// The source-retaining document is parsed by `neotales-dotenv`. This function
/// only applies Bake-owned key, invalid-node, interpolation, and precedence
/// policy. It never opens a path or reads process state.
///
/// # Examples
///
/// ```
/// use neotales_docker_bake::{DotenvOptions, load_dotenv};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let loaded = load_dotenv("ROOT=compose\n", "example.env", DotenvOptions::default())?;
/// assert_eq!(loaded.values().get("ROOT"), Some("compose"));
///
/// let rejected = load_dotenv("not-an-assignment\n", "bad.env", DotenvOptions::default());
/// assert!(rejected.is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a repository-owned error for an oversized source, cancellation,
/// malformed nodes, or invalid keys.
pub fn load_dotenv(
    source: &str,
    path: &str,
    options: DotenvOptions<'_>,
) -> BakeResult<LoadedDotenv> {
    let values = VariableValues::with_platform(options.policy.platform);
    load_dotenv_with_values(source, path, &values, options)
}

/// Parses one explicit dotenv source over caller-owned ordered values.
///
/// The supplied values retain their own platform rules;
/// [`DotenvPolicy::platform`] is used by [`load_dotenv`] when no base is given.
/// Later assignments and sources use [`DotenvPrecedence::LastWins`]. With
/// [`DotenvPrecedence::InjectedWins`], existing caller values are protected while
/// later dotenv assignments and sources still replace earlier dotenv values.
///
/// # Errors
///
/// Returns a repository-owned error for an oversized source, cancellation,
/// malformed nodes, or invalid keys.
pub fn load_dotenv_with_values(
    source: &str,
    path: &str,
    values: &VariableValues,
    options: DotenvOptions<'_>,
) -> BakeResult<LoadedDotenv> {
    parse_dotenv_source(source, path, values, values, options)
}

/// Combines named in-memory dotenv sources in caller-provided precedence order.
///
/// # Errors
///
/// Returns the first invalid source, key, size, or cancellation error. No source
/// path is opened by this function.
pub fn load_dotenv_sources(
    sources: &[DotenvSource],
    values: &VariableValues,
    options: DotenvOptions<'_>,
) -> BakeResult<VariableValues> {
    check_cancelled(options.is_cancelled, "$")?;
    let mut selected = values.clone();
    for source in sources {
        let loaded =
            parse_dotenv_source(source.source(), source.path(), &selected, values, options)?;
        selected = loaded.into_parts().1;
    }
    Ok(selected)
}

/// Reads and parses one caller-selected dotenv path.
///
/// This is the only dotenv file operation in this crate. There is no implicit
/// `.env` lookup and no process-environment fallback.
///
/// # Errors
///
/// Returns a repository-owned I/O, UTF-8, size, parse-policy, key, or
/// cancellation error.
pub fn load_dotenv_path(
    path: impl AsRef<Path>,
    options: DotenvOptions<'_>,
) -> BakeResult<LoadedDotenv> {
    let path = path.as_ref();
    let display_path = path.display().to_string();
    check_cancelled(options.is_cancelled, &display_path)?;
    let mut file = File::open(path).map_err(|error| BakeError::DotenvIo {
        path: display_path.clone(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_DOTENV_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BakeError::DotenvIo {
            path: display_path.clone(),
            message: error.to_string(),
        })?;
    if bytes.len() > MAX_DOTENV_BYTES {
        return Err(BakeError::DotenvTooLarge {
            path: display_path,
            limit: MAX_DOTENV_BYTES,
        });
    }
    check_cancelled(options.is_cancelled, &display_path)?;
    let source = std::str::from_utf8(&bytes).map_err(|error| BakeError::DotenvEncoding {
        path: display_path.clone(),
        message: error.to_string(),
    })?;
    load_dotenv(source, &display_path, options)
}

fn parse_dotenv_source(
    source: &str,
    path: &str,
    values: &VariableValues,
    protected: &VariableValues,
    options: DotenvOptions<'_>,
) -> BakeResult<LoadedDotenv> {
    check_cancelled(options.is_cancelled, path)?;
    if source.len() > MAX_DOTENV_BYTES {
        return Err(BakeError::DotenvTooLarge {
            path: path.to_owned(),
            limit: MAX_DOTENV_BYTES,
        });
    }

    let document = neotales_dotenv::parse(source);
    let mut selected = values.clone();
    materialize_document(&document, path, &mut selected, protected, options)?;
    Ok(LoadedDotenv {
        document,
        values: selected,
    })
}

fn materialize_document(
    document: &Document,
    path: &str,
    values: &mut VariableValues,
    protected: &VariableValues,
    options: DotenvOptions<'_>,
) -> BakeResult<()> {
    for node in document.nodes() {
        check_cancelled(options.is_cancelled, path)?;
        let Node::Assignment(assignment) = node else {
            if matches!(node, Node::Invalid { .. })
                && options.policy.invalid_nodes == InvalidDotenvNodePolicy::Reject
            {
                let Node::Invalid { message, span, .. } = node else {
                    unreachable!("matched invalid node")
                };
                return Err(BakeError::InvalidDotenvNode {
                    path: path.to_owned(),
                    line: span.line,
                    message: message.clone(),
                });
            }
            continue;
        };

        if !valid_environment_key(&assignment.key) {
            if options.policy.invalid_keys == InvalidEnvironmentKeyPolicy::Reject {
                return Err(BakeError::InvalidEnvironmentKey {
                    path: path.to_owned(),
                    line: assignment.span.line,
                    key: assignment.key.clone(),
                });
            }
            continue;
        }

        if options.policy.precedence == DotenvPrecedence::InjectedWins
            && protected.get(&assignment.key).is_some()
        {
            continue;
        }

        let value = match assignment.quote {
            QuoteStyle::Single | QuoteStyle::Raw => assignment.value.clone(),
            QuoteStyle::Unquoted => match options.policy.interpolation {
                DotenvInterpolationPolicy::Disabled => {
                    strip_unquoted_comment(&assignment.value).to_owned()
                }
                DotenvInterpolationPolicy::ExplicitValues => interpolate(
                    strip_unquoted_comment(&assignment.value),
                    values.environment(),
                ),
            },
            QuoteStyle::Double => match options.policy.interpolation {
                DotenvInterpolationPolicy::Disabled => assignment.value.clone(),
                DotenvInterpolationPolicy::ExplicitValues => {
                    interpolate(&assignment.value, values.environment())
                }
            },
        };
        values.insert(assignment.key.clone(), value);
    }
    Ok(())
}

fn strip_unquoted_comment(value: &str) -> &str {
    let comment = value.char_indices().find_map(|(index, character)| {
        (character == '#'
            && value[..index]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace))
        .then_some(index)
    });
    value
        .get(..comment.unwrap_or(value.len()))
        .unwrap_or(value)
        .trim_end()
}

fn valid_environment_key(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn check_cancelled(is_cancelled: Option<&dyn Fn() -> bool>, path: &str) -> BakeResult<()> {
    if is_cancelled.is_some_and(|is_cancelled| is_cancelled()) {
        return Err(BakeError::DotenvCancelled {
            path: path.to_owned(),
        });
    }
    Ok(())
}
