//! Engine registry authentication without exposing transport credentials.

use http::{Method, header};
use serde::Serialize;

use crate::{DockerClient, Error, RegistryCredentials};

/// Result of authenticating with a registry through `POST /auth`.
///
/// The daemon status is safe to display. The stored credentials retain the
/// facade's redacted `Debug` implementation and zeroization behavior.
#[derive(Clone, Debug)]
pub struct RegistryAuthenticationResult {
    /// Registry authentication status returned by Docker.
    pub status: String,
    /// Credentials to persist after successful login.
    pub credentials: RegistryCredentials,
}

impl RegistryAuthenticationResult {
    /// Returns whether Docker reported a successful login.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status.contains("Login Succeeded")
    }
}

#[derive(Serialize)]
struct AuthRequest<'a> {
    username: &'a str,
    password: &'a str,
    serveraddress: &'a str,
}

impl DockerClient {
    /// Authenticates a registry through the Docker Engine API.
    ///
    /// Bollard 0.21.1 does not publish a generated `/auth` method. The facade
    /// reuses Bollard's transport and raw-response decoder through its public
    /// request modifier while keeping the generated auth model private.
    ///
    /// # Errors
    ///
    /// Returns a credential, transport, daemon, or response-decoding error.
    pub async fn authenticate_registry(
        &self,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<RegistryAuthenticationResult, Error> {
        credentials.validate_for(registry)?;
        let (username, secret, configured_server) = credentials.into_auth_parts();
        let server_address = if configured_server.is_empty() {
            registry.to_owned()
        } else {
            configured_server
        };
        let payload = serde_json::to_vec(&AuthRequest {
            username: &username,
            password: &secret,
            serveraddress: &server_address,
        })
        .map_err(Error::serialization)?;
        let content_length = payload.len();
        let docker = self
            .inner
            .clone()
            .with_request_modifier(move |mut request| {
                *request.method_mut() = Method::POST;
                if let Ok(path_and_query) = "/auth".parse::<http::uri::PathAndQuery>() {
                    let mut parts = request.uri().clone().into_parts();
                    parts.path_and_query = Some(path_and_query);
                    if let Ok(uri) = http::Uri::from_parts(parts) {
                        *request.uri_mut() = uri;
                    }
                }
                request.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static("application/json"),
                );
                request.headers_mut().insert(
                    header::CONTENT_LENGTH,
                    header::HeaderValue::from(content_length),
                );
                *request.body_mut() = bollard::body_full(payload.clone().into());
                request
            });

        let body = docker.ping().await?;
        let document: serde_json::Value =
            serde_json::from_str(&body).map_err(Error::serialization)?;
        let status = document
            .get("Status")
            .and_then(serde_json::Value::as_str)
            .filter(|status| !status.trim().is_empty())
            .ok_or_else(|| {
                Error::serialization(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "registry authentication response has no Status",
                )))
            })?
            .to_owned();
        let credentials = document
            .get("IdentityToken")
            .and_then(serde_json::Value::as_str)
            .filter(|token| !token.is_empty())
            .map_or_else(
                || RegistryCredentials::new(username, secret),
                RegistryCredentials::from_identity_token,
            )
            .with_server_address(server_address);
        Ok(RegistryAuthenticationResult {
            status,
            credentials,
        })
    }
}
