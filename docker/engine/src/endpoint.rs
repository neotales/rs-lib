//! Docker endpoint parsing and typed endpoint values.

use std::path::PathBuf;

use url::Url;

/// TLS material associated with a Docker context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsMaterial {
    /// Path to the certificate authority bundle.
    pub ca_path: PathBuf,
    /// Path to the client certificate.
    pub cert_path: PathBuf,
    /// Path to the client private key.
    pub key_path: PathBuf,
}

/// A Docker Engine endpoint selected by a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// Unix domain socket.
    Unix(PathBuf),
    /// Windows named pipe.
    NamedPipe(String),
    /// Plain HTTP or TCP endpoint.
    Http(String),
    /// HTTPS endpoint with optional context-local TLS material.
    Https {
        /// Docker endpoint URL.
        address: String,
        /// Optional Docker context TLS material.
        material: Option<TlsMaterial>,
    },
    /// Native OpenSSH endpoint.
    Ssh {
        /// SSH endpoint URL.
        address: String,
        /// Optional identity file.
        identity_path: Option<PathBuf>,
    },
}

/// Errors returned while parsing a Docker endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    /// The endpoint was not a valid URL.
    InvalidUrl,
    /// The endpoint used an unsupported URL scheme.
    UnsupportedScheme,
    /// A Unix endpoint did not contain a socket path.
    MissingUnixPath,
    /// A named-pipe endpoint did not contain a pipe name.
    MissingNamedPipe,
    /// SSH endpoints must not contain passwords.
    PasswordInSshEndpoint,
    /// SSH endpoints must not contain path components.
    SshPath,
    /// Docker endpoints must not contain query or fragment components.
    QueryOrFragment,
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => write!(formatter, "Docker endpoint is not a valid URL"),
            Self::UnsupportedScheme => write!(formatter, "Docker endpoint scheme is unsupported"),
            Self::MissingUnixPath => write!(formatter, "Unix Docker endpoint has no socket path"),
            Self::MissingNamedPipe => {
                write!(formatter, "Named-pipe Docker endpoint has no pipe name")
            }
            Self::PasswordInSshEndpoint => {
                write!(formatter, "Docker SSH endpoint must not contain a password")
            }
            Self::SshPath => write!(formatter, "Docker SSH endpoint must not contain a path"),
            Self::QueryOrFragment => {
                write!(
                    formatter,
                    "Docker endpoint must not contain a query or fragment"
                )
            }
        }
    }
}

impl std::error::Error for EndpointError {}

impl Endpoint {
    /// Parses a Docker endpoint URL into a typed endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid URLs, unsupported schemes, malformed
    /// socket/pipe values, or passwords in SSH URLs.
    pub fn parse(value: &str) -> Result<Self, EndpointError> {
        let url = Url::parse(value).map_err(|_| EndpointError::InvalidUrl)?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(EndpointError::QueryOrFragment);
        }
        match url.scheme() {
            "unix" => {
                let path = url.path();
                if path.is_empty() {
                    return Err(EndpointError::MissingUnixPath);
                }
                Ok(Self::Unix(PathBuf::from(path)))
            }
            "npipe" => {
                let pipe = value.strip_prefix("npipe://").unwrap_or_default();
                if pipe.is_empty() {
                    return Err(EndpointError::MissingNamedPipe);
                }
                Ok(Self::NamedPipe(pipe.to_owned()))
            }
            "tcp" | "http" => Ok(Self::Http(value.to_owned())),
            "https" => Ok(Self::Https {
                address: value.to_owned(),
                material: None,
            }),
            "ssh" => {
                if url.password().is_some() {
                    return Err(EndpointError::PasswordInSshEndpoint);
                }
                if !url.path().is_empty() && url.path() != "/" {
                    return Err(EndpointError::SshPath);
                }
                Ok(Self::Ssh {
                    address: value.to_owned(),
                    identity_path: None,
                })
            }
            _ => Err(EndpointError::UnsupportedScheme),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Endpoint, EndpointError};

    #[test]
    fn parses_supported_endpoints() {
        assert_eq!(
            Endpoint::parse("unix:///var/run/docker.sock").unwrap(),
            Endpoint::Unix(PathBuf::from("/var/run/docker.sock"))
        );
        assert_eq!(
            Endpoint::parse("tcp://127.0.0.1:2375").unwrap(),
            Endpoint::Http("tcp://127.0.0.1:2375".to_owned())
        );
        assert!(matches!(
            Endpoint::parse("https://docker.example:2376").unwrap(),
            Endpoint::Https { .. }
        ));
        assert!(matches!(
            Endpoint::parse("ssh://deploy@example.com").unwrap(),
            Endpoint::Ssh { .. }
        ));
    }

    #[test]
    fn rejects_password_in_ssh_endpoint() {
        assert_eq!(
            Endpoint::parse("ssh://user:password@example.com"),
            Err(EndpointError::PasswordInSshEndpoint)
        );
    }

    #[test]
    fn rejects_ssh_paths_and_query_components() {
        assert_eq!(
            Endpoint::parse("ssh://user@example.com/path"),
            Err(EndpointError::SshPath)
        );
        assert_eq!(
            Endpoint::parse("ssh://user@example.com?check=true"),
            Err(EndpointError::QueryOrFragment)
        );
    }

    #[test]
    fn rejects_unsupported_endpoint() {
        assert_eq!(
            Endpoint::parse("ftp://example.com"),
            Err(EndpointError::UnsupportedScheme)
        );
    }
}
