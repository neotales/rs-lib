//! Explicit BuildKit builder selection without environment or Buildx discovery.

use std::{fmt, str::FromStr};

use url::Url;

const MAX_BUILDER_LABEL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BuilderTransport {
    CleartextTcp,
    TlsTcp,
    UnixSocket,
}

/// Errors returned while parsing or naming an explicit BuildKit builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuilderError {
    /// The endpoint was empty or surrounded by whitespace.
    InvalidEndpointText,
    /// The endpoint was not a valid URL.
    InvalidEndpointUrl,
    /// The endpoint URL used an unsupported scheme.
    UnsupportedScheme,
    /// A TCP endpoint did not contain a host.
    MissingHost,
    /// A cleartext TCP endpoint did not contain an explicit port.
    MissingPort,
    /// A Unix endpoint did not contain an absolute socket path.
    MissingUnixPath,
    /// A network endpoint contained a path other than `/`.
    UnexpectedPath,
    /// Endpoint user information is forbidden.
    EndpointCredentials,
    /// Endpoint query parameters are forbidden.
    EndpointQuery,
    /// Endpoint fragments are forbidden.
    EndpointFragment,
    /// The diagnostic builder label was empty or too long.
    InvalidLabel,
    /// The diagnostic builder label contained a control character.
    InvalidLabelCharacter,
}

/// A validated BuildKit gRPC endpoint.
///
/// The type accepts explicit cleartext TCP, TLS TCP, and Unix socket endpoint
/// forms. It only records the selection; this crate does not establish a
/// transport connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BuilderEndpoint {
    address: String,
    transport: BuilderTransport,
}

impl BuilderEndpoint {
    /// Parses an explicit BuildKit endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, ambiguous, credential-bearing, or
    /// unsupported endpoint values. No environment or configuration fallback is
    /// attempted.
    pub fn parse(value: &str) -> Result<Self, BuilderError> {
        if value.is_empty() || value.trim() != value {
            return Err(BuilderError::InvalidEndpointText);
        }
        let url = Url::parse(value).map_err(|_| BuilderError::InvalidEndpointUrl)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(BuilderError::EndpointCredentials);
        }
        if url.query().is_some() {
            return Err(BuilderError::EndpointQuery);
        }
        if url.fragment().is_some() {
            return Err(BuilderError::EndpointFragment);
        }

        let transport = match url.scheme() {
            "tcp" | "http" => {
                if url.host_str().is_none_or(str::is_empty) {
                    return Err(BuilderError::MissingHost);
                }
                if !matches!(url.path(), "" | "/") {
                    return Err(BuilderError::UnexpectedPath);
                }
                if url.scheme() == "tcp" && url.port().is_none() {
                    return Err(BuilderError::MissingPort);
                }
                BuilderTransport::CleartextTcp
            }
            "https" => {
                if url.host_str().is_none_or(str::is_empty) {
                    return Err(BuilderError::MissingHost);
                }
                if !matches!(url.path(), "" | "/") {
                    return Err(BuilderError::UnexpectedPath);
                }
                BuilderTransport::TlsTcp
            }
            "unix" => {
                if url.host_str().is_some_and(|host| !host.is_empty()) || url.port().is_some() {
                    return Err(BuilderError::MissingUnixPath);
                }
                if url.path().len() <= 1 {
                    return Err(BuilderError::MissingUnixPath);
                }
                BuilderTransport::UnixSocket
            }
            _ => return Err(BuilderError::UnsupportedScheme),
        };

        Ok(Self {
            address: url.into(),
            transport,
        })
    }

    /// Returns the normalized endpoint value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// Returns whether selecting this endpoint requires cleartext HTTP/2.
    ///
    /// The fixture adapter never performs this transport. A future adapter must
    /// report h2c support before selecting a cleartext endpoint.
    #[must_use]
    pub const fn requires_h2c(&self) -> bool {
        !matches!(self.transport, BuilderTransport::TlsTcp)
    }
}

impl fmt::Display for BuilderEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.address)
    }
}

impl FromStr for BuilderEndpoint {
    type Err = BuilderError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// An explicitly selected BuildKit builder.
///
/// `label` is diagnostic metadata only. It is never interpreted as a Buildx
/// builder name, Docker context, or endpoint fallback key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BuilderSelection {
    label: String,
    endpoint: BuilderEndpoint,
}

impl fmt::Display for BuilderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpointText => {
                formatter.write_str("BuildKit endpoint text is empty or padded")
            }
            Self::InvalidEndpointUrl => formatter.write_str("BuildKit endpoint is not a valid URL"),
            Self::UnsupportedScheme => {
                formatter.write_str("BuildKit endpoint scheme is unsupported")
            }
            Self::MissingHost => formatter.write_str("BuildKit endpoint has no host"),
            Self::MissingPort => {
                formatter.write_str("cleartext BuildKit TCP endpoint has no explicit port")
            }
            Self::MissingUnixPath => {
                formatter.write_str("BuildKit Unix endpoint has no absolute socket path")
            }
            Self::UnexpectedPath => {
                formatter.write_str("BuildKit network endpoint must not contain a path")
            }
            Self::EndpointCredentials => {
                formatter.write_str("BuildKit endpoint must not contain credentials")
            }
            Self::EndpointQuery => {
                formatter.write_str("BuildKit endpoint must not contain a query")
            }
            Self::EndpointFragment => {
                formatter.write_str("BuildKit endpoint must not contain a fragment")
            }
            Self::InvalidLabel => {
                formatter.write_str("BuildKit builder label is empty or too long")
            }
            Self::InvalidLabelCharacter => {
                formatter.write_str("BuildKit builder label contains a control character")
            }
        }
    }
}

impl BuilderSelection {
    /// Creates an explicit builder selection.
    ///
    /// # Errors
    ///
    /// Returns an error when the diagnostic label is empty, too long, or
    /// contains a control character.
    pub fn new(label: impl Into<String>, endpoint: BuilderEndpoint) -> Result<Self, BuilderError> {
        let label = label.into();
        if label.is_empty() || label.len() > MAX_BUILDER_LABEL_BYTES {
            return Err(BuilderError::InvalidLabel);
        }
        if label.chars().any(char::is_control) {
            return Err(BuilderError::InvalidLabelCharacter);
        }
        Ok(Self { label, endpoint })
    }

    /// Returns the non-routing diagnostic label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the endpoint that the adapter must match exactly.
    #[must_use]
    pub const fn endpoint(&self) -> &BuilderEndpoint {
        &self.endpoint
    }
}

impl fmt::Display for BuilderSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.label, self.endpoint)
    }
}

impl std::error::Error for BuilderError {}

#[cfg(test)]
mod tests {
    use super::{BuilderEndpoint, BuilderError, BuilderSelection};

    #[test]
    fn parses_explicit_network_and_unix_endpoints() {
        let tcp = BuilderEndpoint::parse("tcp://builder.example:1234").expect("TCP endpoint");
        let tls = BuilderEndpoint::parse("https://builder.example:9443").expect("TLS endpoint");
        let unix =
            BuilderEndpoint::parse("unix:///run/buildkit/buildkitd.sock").expect("Unix endpoint");

        assert!(tcp.requires_h2c());
        assert!(!tls.requires_h2c());
        assert!(unix.requires_h2c());
    }

    #[test]
    fn rejects_ambiguous_or_credential_bearing_endpoints() {
        assert_eq!(
            BuilderEndpoint::parse("builder.example:1234"),
            Err(BuilderError::UnsupportedScheme)
        );
        assert_eq!(
            BuilderEndpoint::parse("tcp://builder.example"),
            Err(BuilderError::MissingPort)
        );
        assert_eq!(
            BuilderEndpoint::parse("tcp://user:password@builder.example:1234"),
            Err(BuilderError::EndpointCredentials)
        );
        assert_eq!(
            BuilderEndpoint::parse("https://builder.example:9443?token=secret"),
            Err(BuilderError::EndpointQuery)
        );
    }

    #[test]
    fn selection_has_no_environment_or_buildx_fallback() {
        let endpoint =
            BuilderEndpoint::parse("https://builder.example:9443").expect("validated endpoint");
        let selection =
            BuilderSelection::new("contract-fixture", endpoint).expect("validated selection");

        assert_eq!(selection.label(), "contract-fixture");
        assert_eq!(
            selection.endpoint().as_str(),
            "https://builder.example:9443/"
        );
    }
}
