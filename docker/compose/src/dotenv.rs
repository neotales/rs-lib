//! Explicit dotenv loading through the repository-native parser.

use std::{fmt, fs::File, io::Read, path::Path};

use neotales_dotenv::{Document, Node, QuoteStyle};

use crate::{
    ComposeError,
    model::is_valid_environment_key,
    policy::{
        DotenvPolicy, DotenvPrecedence, InterpolationValues, InvalidDotenvNodePolicy,
        InvalidEnvironmentKeyPolicy,
    },
    resolver,
};

/// Maximum size accepted for one explicit dotenv source.
pub const MAX_DOTENV_BYTES: usize = 1024 * 1024;

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
    values: InterpolationValues,
}

impl LoadedDotenv {
    /// Returns the source-preserving parser document, including invalid nodes.
    #[must_use]
    pub const fn document(&self) -> &Document {
        &self.document
    }

    /// Returns the exact dotenv source text.
    ///
    /// A leading UTF-8 byte-order mark is not part of it: one is removed before
    /// parsing, so the text returned here is the text that was parsed.
    #[must_use]
    pub fn source(&self) -> &str {
        self.document.source()
    }

    /// Returns ordered, platform-aware values selected by policy.
    #[must_use]
    pub const fn values(&self) -> &InterpolationValues {
        &self.values
    }

    /// Consumes the result into its source document and selected values.
    #[must_use]
    pub fn into_parts(self) -> (Document, InterpolationValues) {
        (self.document, self.values)
    }
}

/// Parses one explicit dotenv source into ordered Compose interpolation values.
///
/// The source-retaining document is parsed by `neotales-dotenv`. This function
/// only applies Compose-owned key, invalid-node, interpolation, and precedence
/// policy. It never opens a path or reads process state. A leading UTF-8
/// byte-order mark is removed first, because the file a Windows editor saves
/// carries one and it is an encoding signature rather than part of the first
/// key.
///
/// # Examples
///
/// ```
/// use neotales_docker_compose::{DotenvOptions, load_dotenv};
///
/// let loaded = load_dotenv("ROOT=compose\n", "example.env", DotenvOptions::default())?;
/// assert_eq!(loaded.values().get("ROOT"), Some("compose"));
///
/// let rejected = load_dotenv("not-an-assignment\n", "bad.env", DotenvOptions::default());
/// assert!(rejected.is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// Returns a repository-owned error for an oversized source, cancellation,
/// malformed nodes, invalid keys, or rejected interpolation.
pub fn load_dotenv(
    source: &str,
    path: &str,
    options: DotenvOptions<'_>,
) -> Result<LoadedDotenv, ComposeError> {
    let values = InterpolationValues::with_platform(options.policy.platform);
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
/// malformed nodes, invalid keys, or rejected interpolation.
pub fn load_dotenv_with_values(
    source: &str,
    path: &str,
    values: &InterpolationValues,
    options: DotenvOptions<'_>,
) -> Result<LoadedDotenv, ComposeError> {
    parse_dotenv_source(source, path, values, values, options)
}

/// Combines named in-memory dotenv sources in caller-provided precedence order.
///
/// # Errors
///
/// Returns the first invalid source, key, interpolation, size, or cancellation
/// error. No source path is opened by this function.
pub fn load_dotenv_sources(
    sources: &[DotenvSource],
    values: &InterpolationValues,
    options: DotenvOptions<'_>,
) -> Result<InterpolationValues, ComposeError> {
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
/// `.env` lookup and no process-environment fallback. A UTF-8 byte-order mark is
/// removed, because the file this most often reads was last saved by an editor
/// on the same Windows host that runs the daemon, and Notepad has written one
/// by default since Windows 10 1903.
///
/// # Errors
///
/// Returns a repository-owned I/O, UTF-8, size, parse-policy, key,
/// interpolation, or cancellation error.
pub fn load_dotenv_path(
    path: impl AsRef<Path>,
    options: DotenvOptions<'_>,
) -> Result<LoadedDotenv, ComposeError> {
    let path = path.as_ref();
    let display_path = path.display().to_string();
    check_cancelled(options.is_cancelled, &display_path)?;
    let mut file = File::open(path).map_err(|error| {
        ComposeError::new(
            "compose_dotenv_io",
            format!("could not open dotenv source: {error}"),
            Some(display_path.clone()),
            "$.dotenv",
        )
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_DOTENV_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ComposeError::new(
                "compose_dotenv_io",
                format!("could not read dotenv source: {error}"),
                Some(display_path.clone()),
                "$.dotenv",
            )
        })?;
    if bytes.len() > MAX_DOTENV_BYTES {
        return Err(ComposeError::new(
            "compose_dotenv_too_large",
            format!("dotenv source exceeds the {MAX_DOTENV_BYTES}-byte limit"),
            Some(display_path),
            "$.dotenv",
        ));
    }
    check_cancelled(options.is_cancelled, &display_path)?;
    let source = std::str::from_utf8(&bytes).map_err(|error| {
        ComposeError::new(
            "compose_dotenv_encoding",
            format!("dotenv source is not UTF-8: {error}"),
            Some(display_path.clone()),
            "$.dotenv",
        )
    })?;
    load_dotenv(source, &display_path, options)
}

fn parse_dotenv_source(
    source: &str,
    path: &str,
    values: &InterpolationValues,
    protected: &InterpolationValues,
    options: DotenvOptions<'_>,
) -> Result<LoadedDotenv, ComposeError> {
    check_cancelled(options.is_cancelled, path)?;
    if source.len() > MAX_DOTENV_BYTES {
        return Err(ComposeError::new(
            "compose_dotenv_too_large",
            format!("dotenv source exceeds the {MAX_DOTENV_BYTES}-byte limit"),
            Some(path.to_owned()),
            "$.dotenv",
        ));
    }

    // A leading byte-order mark is an encoding signature, not content.
    // `str::from_utf8` accepts EF BB BF as the ordinary character U+FEFF and
    // neither this crate nor `neotales-dotenv` treats it as whitespace, so it
    // became the first character of the first key and
    // `is_valid_environment_key` rejected the whole file with
    // `compose_invalid_environment_name` — measured: a `.env` beginning
    // `U+FEFFKEY=value` reported "invalid environment key 'U+FEFFKEY'". UTF-8
    // with a BOM has been the Notepad default since Windows 10 1903, so that is
    // what a `.env` saved on a Windows host arrives with, and it has to load.
    // A *Compose* document with the same prefix already works, because libyaml
    // skips it; the dotenv path is the only one that did not.
    //
    // Exactly one mark is dropped. A second one is a character in the first
    // key's name, and quietly eating characters a key spells is how a
    // `PASSWORD` becomes `ASSWORD` without a word.
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
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
    values: &mut InterpolationValues,
    protected: &InterpolationValues,
    options: DotenvOptions<'_>,
) -> Result<(), ComposeError> {
    for node in document.nodes() {
        check_cancelled(options.is_cancelled, path)?;
        let Node::Assignment(assignment) = node else {
            if matches!(node, Node::Invalid { .. })
                && options.policy.invalid_nodes == InvalidDotenvNodePolicy::Reject
            {
                let Node::Invalid { message, span, .. } = node else {
                    unreachable!("matched invalid node")
                };
                return Err(ComposeError::new(
                    "compose_invalid_dotenv_node",
                    message.clone(),
                    Some(path.to_owned()),
                    format!("$.dotenv[{}]", span.line),
                ));
            }
            continue;
        };

        if !is_valid_environment_key(&assignment.key) {
            if options.policy.invalid_keys == InvalidEnvironmentKeyPolicy::Reject {
                return Err(ComposeError::new(
                    "compose_invalid_environment_name",
                    format!(
                        "invalid environment key '{}' in dotenv source",
                        assignment.key
                    ),
                    Some(path.to_owned()),
                    format!("$.dotenv[{}].key", assignment.span.line),
                ));
            }
            continue;
        }

        if options.policy.precedence == DotenvPrecedence::InjectedWins
            && protected.get(&assignment.key).is_some()
        {
            continue;
        }

        let source_value = match assignment.quote {
            QuoteStyle::Single | QuoteStyle::Raw | QuoteStyle::Double => assignment.value.clone(),
            QuoteStyle::Unquoted => strip_unquoted_comment(&assignment.value).to_owned(),
        };
        let value = if matches!(assignment.quote, QuoteStyle::Unquoted | QuoteStyle::Double) {
            resolver::interpolate(&source_value, values, options.policy.interpolation).map_err(
                |error| {
                    ComposeError::new(
                        error.code(),
                        error.message(),
                        Some(path.to_owned()),
                        format!("$.dotenv[{}].value", assignment.span.line),
                    )
                },
            )?
        } else {
            source_value
        };
        let _ = values.insert(assignment.key.clone(), value);
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

fn check_cancelled(
    is_cancelled: Option<&dyn Fn() -> bool>,
    path: &str,
) -> Result<(), ComposeError> {
    if is_cancelled.is_some_and(|is_cancelled| is_cancelled()) {
        return Err(ComposeError::new(
            "compose_cancelled",
            "dotenv loading was cancelled",
            Some(path.to_owned()),
            "$.dotenv",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{DotenvOptions, load_dotenv, load_dotenv_path};

    /// A file a Windows editor saved loads.
    ///
    /// Measured before the fix, on Linux, with the very same bytes: the document
    /// parsed and then `compose_invalid_environment_name` rejected the file for
    /// "invalid environment key 'U+FEFFKEY'". Nothing about that failure is
    /// platform-specific, which is why this is a plain test here rather than a
    /// gated one — the host only decides how likely the file is to be written,
    /// not whether the bytes parse.
    #[test]
    fn a_utf8_byte_order_mark_is_not_the_first_character_of_the_first_key() {
        let loaded = load_dotenv(
            "\u{feff}KEY=value\nSECOND=2\n",
            "app.env",
            DotenvOptions::default(),
        )
        .expect("a BOM-prefixed .env loads");
        assert_eq!(loaded.values().get("KEY"), Some("value"));
        assert_eq!(loaded.values().get("SECOND"), Some("2"));
        // The mark is an encoding signature, so it is not part of the retained
        // source text either.
        assert_eq!(loaded.source(), "KEY=value\nSECOND=2\n");
    }

    /// The same file read from disk, which is where the bytes actually arrive.
    ///
    /// The path is the only file operation in this crate, so this is the case
    /// that has to work; the in-memory test above is the same code with the
    /// bytes handed over directly.
    #[test]
    fn a_saved_file_with_a_byte_order_mark_loads_from_disk() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("app.env");
        std::fs::write(&path, "\u{feff}KEY=value\n").expect("the file is written");
        let loaded = load_dotenv_path(&path, DotenvOptions::default())
            .expect("a BOM-prefixed file on disk loads");
        assert_eq!(loaded.values().get("KEY"), Some("value"));
    }

    /// Exactly one mark is dropped, and a second one is still an invalid key.
    ///
    /// The alternative — stripping every leading mark — would quietly rename a
    /// key, and a renamed key is a missing secret rather than an error.
    #[test]
    fn a_second_byte_order_mark_is_content_and_still_fails() {
        let error = load_dotenv(
            "\u{feff}\u{feff}KEY=value\n",
            "app.env",
            DotenvOptions::default(),
        )
        .expect_err("only the encoding mark is dropped");
        assert_eq!(error.code(), "compose_invalid_environment_name");
    }

    /// A file with no mark is untouched.
    #[test]
    fn a_source_without_a_byte_order_mark_is_returned_exactly() {
        let source = "KEY=value\n# a comment\n";
        let loaded =
            load_dotenv(source, "app.env", DotenvOptions::default()).expect("a plain .env loads");
        assert_eq!(loaded.source(), source);
    }
}
