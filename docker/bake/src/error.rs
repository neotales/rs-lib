//! Errors produced while parsing and planning Bake documents.

use std::fmt;

/// Result type used by the Bake parser and planner.
pub type BakeResult<T> = Result<T, BakeError>;

/// Errors produced by the bounded Bake document and explicit dotenv layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BakeError {
    /// The input could not be read.
    Io(String),
    /// The input exceeded the bounded document size.
    DocumentTooLarge {
        /// Maximum accepted input size in bytes.
        limit: usize,
    },
    /// The input was not valid JSON.
    InvalidJson(String),
    /// The JSON shape was not a supported Bake document.
    InvalidDocument(String),
    /// A field was explicitly rejected by this bounded slice.
    UnsupportedField {
        /// Dotted path to the containing object.
        path: String,
        /// Unsupported field name.
        field: String,
    },
    /// A target, group, or variable name was not a valid Bake identifier.
    InvalidName {
        /// Kind of identifier being validated.
        kind: &'static str,
        /// Invalid identifier.
        name: String,
    },
    /// A target reference did not resolve.
    MissingTarget(String),
    /// A group reference did not resolve.
    MissingGroup(String),
    /// A target inherited from a target that is not declared.
    MissingInheritance {
        /// Target containing the inheritance declaration.
        target: String,
        /// Unresolved base target.
        base: String,
    },
    /// Target inheritance contains a cycle.
    InheritanceCycle {
        /// Cycle path, with the repeated node at both ends.
        trace: Vec<String>,
    },
    /// Group expansion contains a cycle.
    GroupCycle {
        /// Cycle path, with the repeated node at both ends.
        trace: Vec<String>,
    },
    /// Named target contexts contain a dependency cycle.
    DependencyCycle {
        /// Cycle path, with the repeated node at both ends.
        trace: Vec<String>,
    },
    /// A requested target or group selector matched nothing.
    UnknownSelection(String),
    /// A `target:` context reference was empty or malformed.
    InvalidTargetReference {
        /// Target containing the reference.
        target: String,
        /// Invalid reference value.
        reference: String,
    },
    /// A string used a Bake variable that was not declared or had no value.
    UnresolvedVariable(String),
    /// An explicit dotenv source could not be read.
    DotenvIo {
        /// Caller-selected source path.
        path: String,
        /// Operating-system error text.
        message: String,
    },
    /// An explicit dotenv source exceeded the bounded input size.
    DotenvTooLarge {
        /// Caller-selected source path.
        path: String,
        /// Maximum accepted source size in bytes.
        limit: usize,
    },
    /// An explicit dotenv source was not UTF-8.
    DotenvEncoding {
        /// Caller-selected source path.
        path: String,
        /// UTF-8 error text.
        message: String,
    },
    /// `neotales-dotenv` retained a node that policy rejected.
    InvalidDotenvNode {
        /// Caller-selected source path.
        path: String,
        /// One-based source line.
        line: u32,
        /// Parser explanation without the source value.
        message: String,
    },
    /// A dotenv assignment did not use a valid environment variable name.
    InvalidEnvironmentKey {
        /// Caller-selected source path.
        path: String,
        /// One-based source line.
        line: u32,
        /// Invalid key text.
        key: String,
    },
    /// Dotenv loading observed cooperative cancellation.
    DotenvCancelled {
        /// Caller-selected source path.
        path: String,
    },
}

impl fmt::Display for BakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "Bake document I/O failed: {message}"),
            Self::DocumentTooLarge { limit } => {
                write!(formatter, "Bake document exceeds the {limit}-byte limit")
            }
            Self::InvalidJson(message) => {
                write!(formatter, "Bake document JSON is invalid: {message}")
            }
            Self::InvalidDocument(message) => {
                write!(formatter, "Bake document is invalid: {message}")
            }
            Self::UnsupportedField { path, field } => {
                write!(formatter, "unsupported Bake field {path}.{field}")
            }
            Self::InvalidName { kind, name } => {
                write!(formatter, "invalid Bake {kind} name: {name}")
            }
            Self::MissingTarget(name) => write!(formatter, "Bake target does not exist: {name}"),
            Self::MissingGroup(name) => write!(formatter, "Bake group does not exist: {name}"),
            Self::MissingInheritance { target, base } => {
                write!(
                    formatter,
                    "Bake target {target} inherits missing target {base}"
                )
            }
            Self::InheritanceCycle { trace } => {
                write!(
                    formatter,
                    "Bake target inheritance cycle: {}",
                    trace.join(" -> ")
                )
            }
            Self::GroupCycle { trace } => {
                write!(formatter, "Bake group cycle: {}", trace.join(" -> "))
            }
            Self::DependencyCycle { trace } => {
                write!(
                    formatter,
                    "Bake target dependency cycle: {}",
                    trace.join(" -> ")
                )
            }
            Self::UnknownSelection(selector) => {
                write!(
                    formatter,
                    "Bake selection did not match a target or group: {selector}"
                )
            }
            Self::InvalidTargetReference { target, reference } => write!(
                formatter,
                "Bake target {target} has invalid target reference: {reference}"
            ),
            Self::UnresolvedVariable(name) => {
                write!(formatter, "Bake variable has no value: {name}")
            }
            Self::DotenvIo { path, message } => {
                write!(
                    formatter,
                    "could not read Bake dotenv source {path}: {message}"
                )
            }
            Self::DotenvTooLarge { path, limit } => write!(
                formatter,
                "Bake dotenv source {path} exceeds the {limit}-byte limit"
            ),
            Self::DotenvEncoding { path, message } => {
                write!(
                    formatter,
                    "Bake dotenv source {path} is not UTF-8: {message}"
                )
            }
            Self::InvalidDotenvNode {
                path,
                line,
                message,
            } => write!(
                formatter,
                "Bake dotenv source {path}:{line} is invalid: {message}"
            ),
            Self::InvalidEnvironmentKey { path, line, key } => write!(
                formatter,
                "Bake dotenv source {path}:{line} has invalid environment key {key}"
            ),
            Self::DotenvCancelled { path } => {
                write!(formatter, "Bake dotenv loading was cancelled for {path}")
            }
        }
    }
}

impl std::error::Error for BakeError {}

pub(crate) fn from_json_error(error: &serde_json::Error) -> BakeError {
    let message = error.to_string();
    if let Some(field) = unknown_field(&message) {
        return BakeError::UnsupportedField {
            path: "document".to_owned(),
            field,
        };
    }
    BakeError::InvalidJson(message)
}

fn unknown_field(message: &str) -> Option<String> {
    let remainder = message
        .strip_prefix("unknown field `")
        .or_else(|| message.strip_prefix("unknown field '"))?;
    let end = remainder.find('`').or_else(|| remainder.find('\''))?;
    let field = &remainder[..end];
    (!field.is_empty()).then(|| field.to_owned())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{BakeError, from_json_error};

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictDocument {
        #[serde(default)]
        _known: bool,
    }

    #[test]
    fn maps_unknown_serde_fields_to_the_public_error() {
        let error = serde_json::from_str::<StrictDocument>(r#"{"future":true}"#)
            .expect_err("unknown field");
        assert_eq!(
            from_json_error(&error),
            BakeError::UnsupportedField {
                path: "document".to_owned(),
                field: "future".to_owned(),
            }
        );

        let malformed = serde_json::from_str::<StrictDocument>("{").expect_err("malformed JSON");
        assert!(matches!(
            from_json_error(&malformed),
            BakeError::InvalidJson(_)
        ));
    }
}
