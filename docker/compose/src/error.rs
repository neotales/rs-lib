use std::fmt;

use serde::Serialize;

/// Severity attached to a Compose diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    /// A non-fatal policy or normalization observation.
    Warning,
    /// A condition that prevents normalization or resolution.
    Error,
}

/// A stable, source-independent description of a normalization problem.
///
/// The first slice intentionally does not retain YAML spans.  `source` is
/// the caller-supplied document path and `path` is the normalized model path,
/// for example `$.services.web.image`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComposeDiagnostic {
    /// Stable machine-readable diagnostic code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Caller-supplied source document path, when one is available.
    pub source: Option<String>,
    /// Path within the normalized Compose model.
    pub path: String,
    /// Diagnostic severity.
    pub severity: DiagnosticSeverity,
}

/// An error raised while parsing, validating, merging, or resolving Compose
/// input.
///
/// Errors contain model paths and variable names, never the value of an
/// interpolated variable.  This keeps diagnostics safe to log when a caller
/// injects credentials or other secret-like values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeError {
    code: String,
    message: String,
    source: Option<String>,
    path: String,
}

impl ComposeError {
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        source: Option<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            source,
            path: path.into(),
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the human-readable explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the caller-supplied source document path, if one was supplied.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Returns the path within the Compose model.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Converts this error into a serializable diagnostic.
    #[must_use]
    pub fn diagnostic(&self) -> ComposeDiagnostic {
        ComposeDiagnostic {
            code: self.code.clone(),
            message: self.message.clone(),
            source: self.source.clone(),
            path: self.path.clone(),
            severity: DiagnosticSeverity::Error,
        }
    }
}

impl fmt::Display for ComposeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            write!(
                formatter,
                "{source}{}: {} [{}]",
                self.path, self.message, self.code
            )
        } else {
            write!(formatter, "{}: {} [{}]", self.path, self.message, self.code)
        }
    }
}

impl std::error::Error for ComposeError {}
