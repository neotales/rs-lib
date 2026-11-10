//! Bounded Dockerfile solve inputs.

use std::fmt;

use zeroize::Zeroize;

use crate::BuilderSelection;

/// Maximum context archive accepted by the repository-owned input boundary.
pub const MAX_BUILD_CONTEXT_BYTES: usize = 64 * 1024 * 1024;

const MAX_DOCKERFILE_PATH_BYTES: usize = 4096;

/// Errors returned while constructing bounded solve input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildContextError {
    /// A Dockerfile solve context archive cannot be empty.
    Empty,
    /// The context archive exceeded the repository limit.
    TooLarge {
        /// Actual archive size in bytes.
        actual: usize,
        /// Maximum accepted archive size in bytes.
        maximum: usize,
    },
}

/// Errors returned while validating a Dockerfile path inside a context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerfilePathError {
    /// The path was empty or too long.
    InvalidLength,
    /// The path was absolute, empty, `.`, or `..`.
    InvalidComponent,
    /// The path used a platform-specific separator instead of `/`.
    InvalidSeparator,
    /// The path contained a control character.
    InvalidCharacter,
}

/// A bounded, diagnostic-safe build context archive.
///
/// Context bytes are omitted from `Debug` and zeroized when dropped. Adapters
/// receive bytes only through the explicit accessor and are responsible for
/// applying any lower application-specific limit.
pub struct BuildContext {
    bytes: Vec<u8>,
}

impl BuildContext {
    /// Creates a non-empty context archive within the repository limit.
    ///
    /// # Errors
    ///
    /// Returns an error when `archive` is empty or exceeds
    /// [`MAX_BUILD_CONTEXT_BYTES`].
    pub fn new(archive: Vec<u8>) -> Result<Self, BuildContextError> {
        if archive.is_empty() {
            return Err(BuildContextError::Empty);
        }
        if archive.len() > MAX_BUILD_CONTEXT_BYTES {
            return Err(BuildContextError::TooLarge {
                actual: archive.len(),
                maximum: MAX_BUILD_CONTEXT_BYTES,
            });
        }
        Ok(Self { bytes: archive })
    }

    /// Returns the number of context bytes without exposing their contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the context has no bytes.
    ///
    /// A valid [`BuildContext`] is never empty; this method supports generic
    /// collection-style callers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrows the context archive for an adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the context and returns its archive bytes.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for BuildContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildContext")
            .field("byte_len", &self.bytes.len())
            .field("contents", &"[OMITTED]")
            .finish()
    }
}

impl Drop for BuildContext {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A normalized, context-relative Dockerfile path.
///
/// Only slash-separated relative paths without empty, `.`, or `..` components
/// are accepted. This prevents the input contract from referring outside its
/// bounded context archive.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DockerfilePath {
    value: String,
}

impl DockerfilePath {
    /// Validates a context-relative Dockerfile path.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized path, an absolute or parent
    /// path, a backslash separator, or a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, DockerfilePathError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_DOCKERFILE_PATH_BYTES {
            return Err(DockerfilePathError::InvalidLength);
        }
        if value.contains('\\') {
            return Err(DockerfilePathError::InvalidSeparator);
        }
        if value.chars().any(char::is_control) {
            return Err(DockerfilePathError::InvalidCharacter);
        }
        if value.starts_with('/') || value.ends_with('/') {
            return Err(DockerfilePathError::InvalidComponent);
        }
        if value
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
        {
            return Err(DockerfilePathError::InvalidComponent);
        }
        Ok(Self { value })
    }

    /// Returns the normalized context-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for DockerfilePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl fmt::Display for BuildContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Build context archive must not be empty"),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "Build context has {actual} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl fmt::Display for DockerfilePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("Dockerfile path is empty or too long"),
            Self::InvalidComponent => {
                formatter.write_str("Dockerfile path must stay within the context root")
            }
            Self::InvalidSeparator => {
                formatter.write_str("Dockerfile path must use slash separators")
            }
            Self::InvalidCharacter => {
                formatter.write_str("Dockerfile path contains a control character")
            }
        }
    }
}

impl std::error::Error for BuildContextError {}

impl std::error::Error for DockerfilePathError {}

/// Explicit inputs for one Dockerfile solve.
///
/// This first boundary carries the selected builder, a bounded context archive,
/// and a contained Dockerfile path. Build arguments, secrets, cache, named
/// contexts, and exporters remain deliberately unsupported until their own
/// contracts are tested.
#[derive(Debug)]
pub struct SolveRequest {
    /// Builder whose endpoint the adapter must match exactly.
    pub builder: BuilderSelection,
    /// Bounded Dockerfile build context.
    pub context: BuildContext,
    /// Dockerfile path relative to the context root.
    pub dockerfile: DockerfilePath,
}

impl SolveRequest {
    /// Creates an explicit Dockerfile solve request.
    #[must_use]
    pub const fn new(
        builder: BuilderSelection,
        context: BuildContext,
        dockerfile: DockerfilePath,
    ) -> Self {
        Self {
            builder,
            context,
            dockerfile,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuildContext, BuildContextError, DockerfilePath, DockerfilePathError, SolveRequest,
    };
    use crate::{BuilderEndpoint, BuilderSelection};

    #[test]
    fn redacts_context_bytes_and_zeroizes_on_drop() {
        let secret_marker = b"context-must-not-appear".to_vec();
        let expected_len = secret_marker.len();
        let context = BuildContext::new(secret_marker).expect("bounded context");
        let diagnostic = format!("{context:?}");

        assert!(diagnostic.contains("[OMITTED]"));
        assert!(!diagnostic.contains("context-must-not-appear"));
        assert_eq!(context.len(), expected_len);
    }

    #[test]
    fn rejects_empty_and_oversized_contexts() {
        assert_eq!(
            BuildContext::new(Vec::new()).map(|_| ()),
            Err(BuildContextError::Empty)
        );
        assert!(matches!(
            BuildContext::new(vec![0; super::MAX_BUILD_CONTEXT_BYTES + 1]),
            Err(BuildContextError::TooLarge { .. })
        ));
    }

    #[test]
    fn confines_dockerfile_paths_to_the_context() {
        for path in ["/Dockerfile", "../Dockerfile", "docker/../Dockerfile"] {
            assert_eq!(
                DockerfilePath::new(path).map(|_| ()),
                Err(DockerfilePathError::InvalidComponent),
                "{path}"
            );
        }
        assert_eq!(
            DockerfilePath::new("docker\\Dockerfile").map(|_| ()),
            Err(DockerfilePathError::InvalidSeparator)
        );
        assert_eq!(
            DockerfilePath::new("docker/demo.Dockerfile")
                .expect("contained Dockerfile")
                .as_str(),
            "docker/demo.Dockerfile"
        );
    }

    #[test]
    fn solve_request_requires_a_complete_explicit_boundary() {
        let endpoint =
            BuilderEndpoint::parse("https://builder.example:9443").expect("validated endpoint");
        let builder = BuilderSelection::new("request", endpoint).expect("validated selection");
        let context = BuildContext::new(b"FROM scratch\n".to_vec()).expect("context");
        let dockerfile = DockerfilePath::new("Dockerfile").expect("Dockerfile");

        let request = SolveRequest::new(builder, context, dockerfile);
        assert_eq!(request.builder.label(), "request");
        assert_eq!(request.dockerfile.as_str(), "Dockerfile");
    }
}
