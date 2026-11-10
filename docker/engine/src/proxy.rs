//! Explicit HTTP forward-proxy policy and Hyper 1 transport support.
//!
//! Proxy routing is deliberately opt-in. This module never reads
//! `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, or container/build
//! environment variables. The only supported proxy URL is an explicit HTTP
//! proxy. Plain HTTP Engine requests use absolute-form forwarding; HTTPS
//! Engine endpoints use an HTTP `CONNECT` tunnel before TLS is negotiated.
//!
//! Bollard 0.21.1 exposes `Docker::connect_with_custom_transport`. Hyper's
//! legacy client can carry an HTTP/1 `101` response's `OnUpgrade` extension,
//! but Bollard's separate `attach_container_websocket` path opens its own
//! socket and does not call the custom transport. This module therefore
//! covers the facade's ordinary HTTP/1 Engine calls and does not claim that
//! Bollard's WebSocket convenience path is proxied. A future WebSocket or
//! h2c API must account for that bypass rather than assuming this transport
//! covers it.

use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bollard::{BollardRequest, ClientVersion, Docker};
use hyper::{
    Uri,
    header::{HeaderValue, PROXY_AUTHORIZATION},
    rt::{Read, ReadBufCursor, Write},
};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection, HttpConnector},
    },
    rt::TokioExecutor,
};
use tower_service::Service;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "tls")]
use hyper_rustls::HttpsConnector;
#[cfg(feature = "tls")]
use hyper_util::client::legacy::connect::proxy::Tunnel;
#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
#[cfg(feature = "tls")]
use std::fs::File;

use crate::DEFAULT_TIMEOUT_SECONDS;
#[cfg(feature = "tls")]
use crate::TlsMaterial;

/// Maximum accepted length of an explicit proxy URL, in bytes.
pub const MAX_PROXY_URL_BYTES: usize = 2048;
/// Maximum accepted length of a Basic proxy username, in bytes.
pub const MAX_PROXY_USERNAME_BYTES: usize = 256;
/// Maximum accepted length of a Basic proxy password, in bytes.
pub const MAX_PROXY_PASSWORD_BYTES: usize = 4096;
/// Maximum accepted length of the generated Proxy-Authorization header.
pub const MAX_PROXY_AUTHORIZATION_BYTES: usize = 8192;

/// Errors returned while validating or applying explicit proxy policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyError {
    /// The proxy URL was not a valid absolute URL.
    InvalidUrl,
    /// The Docker TCP endpoint was not a valid absolute URL.
    InvalidEndpointUrl,
    /// Only `http://` proxy URLs are supported.
    UnsupportedScheme,
    /// Proxy credentials must not be embedded in a URL.
    CredentialsInUrl,
    /// A proxy URL must address the proxy root and contain no path.
    UrlPathNotAllowed,
    /// A proxy URL must not contain a query or fragment.
    QueryOrFragment,
    /// The proxy URL exceeded its bounded input size.
    UrlTooLong {
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The proxy URL did not contain a host.
    MissingHost,
    /// The Docker endpoint was not an HTTP or HTTPS TCP endpoint.
    EndpointNotProxyable,
    /// The Docker endpoint scheme is not valid for the selected HTTP policy.
    UnsupportedEndpointScheme,
    /// The Docker endpoint contained a path that is not valid for a daemon
    /// origin.
    EndpointPathNotAllowed,
    /// A proxy username was empty or contained the Basic separator colon.
    InvalidUsername,
    /// Proxy authentication contained a control character.
    CredentialControlCharacter,
    /// One proxy authentication component exceeded its bound.
    CredentialComponentTooLong {
        /// Component name (`username` or `password`).
        component: &'static str,
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The generated proxy authorization header exceeded its bound.
    AuthorizationHeaderTooLong {
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The generated proxy authorization header was not a valid HTTP header.
    AuthorizationHeaderInvalid,
    /// TLS material could not be loaded into a verifying rustls client.
    TlsConfiguration,
    /// Bollard could not initialize the custom transport.
    TransportInitialization,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => write!(formatter, "Docker proxy URL is not a valid URL"),
            Self::InvalidEndpointUrl => {
                write!(formatter, "Docker TCP endpoint is not a valid URL")
            }
            Self::UnsupportedScheme => {
                write!(formatter, "Docker proxy URL must use the http scheme")
            }
            Self::CredentialsInUrl => {
                write!(formatter, "Docker proxy URL must not contain credentials")
            }
            Self::UrlPathNotAllowed => {
                write!(formatter, "Docker proxy URL must not contain a path")
            }
            Self::QueryOrFragment => {
                write!(
                    formatter,
                    "Docker proxy URL must not contain a query or fragment"
                )
            }
            Self::UrlTooLong { max } => {
                write!(formatter, "Docker proxy URL exceeds {max} bytes")
            }
            Self::MissingHost => write!(formatter, "Docker proxy URL has no host"),
            Self::EndpointNotProxyable => {
                write!(
                    formatter,
                    "HTTP proxy policy applies only to TCP Docker endpoints"
                )
            }
            Self::UnsupportedEndpointScheme => write!(
                formatter,
                "Docker endpoint scheme is not valid for the selected HTTP policy"
            ),
            Self::EndpointPathNotAllowed => {
                write!(formatter, "Docker TCP endpoint must not contain a path")
            }
            Self::InvalidUsername => {
                write!(
                    formatter,
                    "Docker proxy username is empty or contains a colon"
                )
            }
            Self::CredentialControlCharacter => {
                write!(
                    formatter,
                    "Docker proxy authentication contains a control character"
                )
            }
            Self::CredentialComponentTooLong { component, max } => {
                write!(formatter, "Docker proxy {component} exceeds {max} bytes")
            }
            Self::AuthorizationHeaderTooLong { max } => write!(
                formatter,
                "Docker proxy authorization header exceeds {max} bytes"
            ),
            Self::AuthorizationHeaderInvalid => {
                write!(formatter, "Docker proxy authorization header is invalid")
            }
            Self::TlsConfiguration => {
                write!(
                    formatter,
                    "Docker proxy TLS material could not be configured"
                )
            }
            Self::TransportInitialization => {
                write!(formatter, "Docker proxy transport could not be initialized")
            }
        }
    }
}

impl std::error::Error for ProxyError {}

/// A bounded, redacted Basic-auth value for an HTTP proxy.
///
/// Only Basic authentication is accepted by this small explicit policy. The
/// password is zeroized when the value is dropped, and both fields are
/// redacted from `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyCredentials {
    username: String,
    password: SecretString,
}

impl ProxyCredentials {
    /// Creates bounded Basic proxy credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or colon-containing username, control
    /// characters, or a component larger than its documented bound.
    pub fn basic(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let username = username.into();
        let password = password.into();

        if username.is_empty() || username.contains(':') {
            return Err(ProxyError::InvalidUsername);
        }
        validate_credential_component("username", &username, MAX_PROXY_USERNAME_BYTES)?;
        validate_credential_component("password", &password, MAX_PROXY_PASSWORD_BYTES)?;

        Ok(Self {
            username,
            password: SecretString(password),
        })
    }

    fn authorization(&self) -> Result<HeaderValue, ProxyError> {
        let raw = Zeroizing::new(format!("{}:{}", self.username, self.password.0));
        let encoded = STANDARD.encode(raw.as_bytes());
        let value = format!("Basic {encoded}");
        if value.len() > MAX_PROXY_AUTHORIZATION_BYTES {
            return Err(ProxyError::AuthorizationHeaderTooLong {
                max: MAX_PROXY_AUTHORIZATION_BYTES,
            });
        }

        let mut header =
            HeaderValue::from_str(&value).map_err(|_| ProxyError::AuthorizationHeaderInvalid)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SecretString(String);

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn validate_credential_component(
    component: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ProxyError> {
    if value.len() > max {
        return Err(ProxyError::CredentialComponentTooLong { component, max });
    }
    if value.chars().any(char::is_control) {
        return Err(ProxyError::CredentialControlCharacter);
    }
    Ok(())
}

/// An explicitly configured HTTP forward proxy.
///
/// The URL is normalized and validated at construction. Proxy authentication
/// is optional and is never represented in the URL.
#[derive(Clone, Eq, PartialEq)]
pub struct ForwardProxy {
    address: String,
    credentials: Option<ProxyCredentials>,
}

impl ForwardProxy {
    /// Creates an explicit HTTP proxy without authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HTTP URL, embedded credentials, a path,
    /// query/fragment, missing host, or an overlong URL.
    pub fn new(address: impl Into<String>) -> Result<Self, ProxyError> {
        let address = normalize_proxy_url(&address.into())?;
        Ok(Self {
            address,
            credentials: None,
        })
    }

    /// Creates an explicit HTTP proxy with bounded Basic authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid proxy URL or invalid credentials.
    pub fn with_basic_auth(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let credentials = ProxyCredentials::basic(username, password)?;
        Self::new(address)?.with_credentials(credentials)
    }

    /// Adds bounded Basic authentication to this proxy.
    ///
    /// # Errors
    ///
    /// Returns an error only when the proxy has not passed URL validation.
    pub fn with_credentials(mut self, credentials: ProxyCredentials) -> Result<Self, ProxyError> {
        // `new` is the only public constructor, but retaining this check makes
        // the invariant explicit if another constructor is added later.
        let _ = normalize_proxy_url(&self.address)?;
        self.credentials = Some(credentials);
        Ok(self)
    }

    /// Returns the validated, credential-free proxy URL.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns whether Basic proxy authentication is configured.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    fn uri(&self) -> Result<Uri, ProxyError> {
        self.address.parse().map_err(|_| ProxyError::InvalidUrl)
    }

    fn authorization(&self) -> Result<Option<HeaderValue>, ProxyError> {
        self.credentials
            .as_ref()
            .map(ProxyCredentials::authorization)
            .transpose()
    }
}

impl fmt::Debug for ForwardProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardProxy")
            .field("address", &self.address)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Explicit proxy selection for a Docker client.
///
/// `Direct` is the default and does not consult process proxy variables. The
/// `Http` variant is the only supported forward-proxy route. It is valid only
/// for `Endpoint::Http` and `Endpoint::Https`; callers receive a validation
/// error for Unix sockets, named pipes, and SSH rather than silently routing
/// those transports through an HTTP proxy.
#[derive(Clone, Default, Eq, PartialEq)]
pub enum ProxyPolicy {
    /// Connect directly to the selected Docker endpoint.
    #[default]
    Direct,
    /// Connect to a TCP Docker endpoint through the explicit HTTP proxy.
    Http(ForwardProxy),
}

impl ProxyPolicy {
    /// Creates a direct policy.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Creates a policy for an explicit HTTP proxy.
    #[must_use]
    pub const fn http(proxy: ForwardProxy) -> Self {
        Self::Http(proxy)
    }

    /// Creates an HTTP proxy policy from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not a supported explicit HTTP proxy.
    pub fn from_http_url(address: impl Into<String>) -> Result<Self, ProxyError> {
        ForwardProxy::new(address).map(Self::Http)
    }

    /// Creates an authenticated HTTP proxy policy from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL or Basic credentials are invalid.
    pub fn with_basic_auth(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        ForwardProxy::with_basic_auth(address, username, password).map(Self::Http)
    }

    /// Returns whether this policy selects a direct connection.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    /// Returns the configured forward proxy, if any.
    #[must_use]
    pub const fn forward_proxy(&self) -> Option<&ForwardProxy> {
        match self {
            Self::Direct => None,
            Self::Http(proxy) => Some(proxy),
        }
    }
}

impl fmt::Debug for ProxyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::Http(proxy) => formatter.debug_tuple("Http").field(proxy).finish(),
        }
    }
}

fn authority_contains_userinfo(address: &str) -> bool {
    address
        .split_once("://")
        .map(|(_, remainder)| remainder.split('/').next().unwrap_or_default())
        .unwrap_or_default()
        .contains('@')
}

fn normalize_proxy_url(address: &str) -> Result<String, ProxyError> {
    if address.is_empty() {
        return Err(ProxyError::InvalidUrl);
    }
    if address.len() > MAX_PROXY_URL_BYTES {
        return Err(ProxyError::UrlTooLong {
            max: MAX_PROXY_URL_BYTES,
        });
    }

    let url = Url::parse(address).map_err(|_| ProxyError::InvalidUrl)?;
    if url.scheme() != "http" {
        return Err(ProxyError::UnsupportedScheme);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::QueryOrFragment);
    }
    if url.path() != "/" {
        return Err(ProxyError::UrlPathNotAllowed);
    }
    if url.host_str().is_none() {
        return Err(ProxyError::MissingHost);
    }

    // `Url::username()` is empty both for no user-info and an explicitly
    // empty user. Inspect the authority as well so `http://@host` is not
    // accepted as a surprising credential-bearing form.
    if authority_contains_userinfo(address)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProxyError::CredentialsInUrl);
    }

    let normalized = url.to_string();
    if normalized.len() > MAX_PROXY_URL_BYTES {
        return Err(ProxyError::UrlTooLong {
            max: MAX_PROXY_URL_BYTES,
        });
    }
    Ok(normalized)
}

fn target_origin(address: &str, secure: bool) -> Result<String, ProxyError> {
    let mut url = Url::parse(address).map_err(|_| ProxyError::InvalidEndpointUrl)?;
    let original_scheme = url.scheme();
    let expected_schemes = if secure {
        ["https", "tcp"]
    } else {
        ["http", "tcp"]
    };
    if !expected_schemes.contains(&original_scheme) {
        return Err(ProxyError::UnsupportedEndpointScheme);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::QueryOrFragment);
    }
    if authority_contains_userinfo(address)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProxyError::CredentialsInUrl);
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(ProxyError::EndpointPathNotAllowed);
    }
    if url.host_str().is_none() {
        return Err(ProxyError::MissingHost);
    }

    let scheme = if secure { "https" } else { "http" };
    url.set_scheme(scheme)
        .map_err(|()| ProxyError::UnsupportedScheme)?;
    let port = url.port_or_known_default().ok_or(ProxyError::MissingHost)?;
    let host = url.host_str().ok_or(ProxyError::MissingHost)?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Builds a plain-HTTP custom transport using absolute-form forwarding.
pub(crate) fn connect_http(
    address: &str,
    proxy: &ForwardProxy,
    client_version: &ClientVersion,
) -> Result<Docker, ProxyError> {
    let target = target_origin(address, false)?;
    let proxy_uri = proxy.uri()?;
    let connector = ForwardProxyConnector::new(proxy_uri, HttpConnector::new());
    build_docker(target, connector, proxy.authorization()?, client_version)
}

/// Builds an HTTPS custom transport using HTTP CONNECT and rustls.
#[cfg(feature = "tls")]
pub(crate) fn connect_https(
    address: &str,
    material: &TlsMaterial,
    proxy: &ForwardProxy,
    client_version: &ClientVersion,
) -> Result<Docker, ProxyError> {
    let target = target_origin(address, true)?;
    let proxy_uri = proxy.uri()?;
    let tunnel = Tunnel::new(proxy_uri, HttpConnector::new());
    let tunnel = match proxy.authorization()? {
        Some(authorization) => tunnel.with_auth(authorization),
        None => tunnel,
    };
    let connector = HttpsConnector::from((tunnel, tls_config(material)?));
    build_docker(target, connector, None, client_version)
}

fn build_docker<C>(
    target: String,
    connector: C,
    authorization: Option<HeaderValue>,
    client_version: &ClientVersion,
) -> Result<Docker, ProxyError>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: Read + Write + Connection + Send + Unpin + 'static,
    C::Future: Send + Unpin + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder.pool_max_idle_per_host(0);
    let client = Arc::new(client_builder.build(connector));

    let transport = move |mut request: BollardRequest| {
        let client = Arc::clone(&client);
        let authorization = authorization.clone();
        Box::pin(async move {
            if let Some(authorization) = authorization {
                request
                    .headers_mut()
                    .insert(PROXY_AUTHORIZATION, authorization);
            }
            client
                .request(request)
                .await
                .map_err(bollard::errors::Error::from)
        })
    };

    Docker::connect_with_custom_transport(
        transport,
        Some(target),
        DEFAULT_TIMEOUT_SECONDS,
        client_version,
    )
    .map_err(|_| ProxyError::TransportInitialization)
}

#[cfg(feature = "tls")]
fn tls_config(material: &TlsMaterial) -> Result<Arc<rustls::ClientConfig>, ProxyError> {
    let mut roots = rustls::RootCertStore::empty();

    // Platform roots are added, and a store that only partly loads is tolerated
    // rather than fatal.
    //
    // `TlsMaterial` makes `ca_path` mandatory, so a caller always pins the
    // authority for the endpoint it is dialling. The platform store is therefore
    // additional reach, not a requirement -- and treating any error in reading it
    // as fatal meant a host whose keychain returns one unreadable store could not
    // talk to a server whose CA it had already pinned, on three platforms, with
    // an error naming neither the cause nor the step.
    //
    // Tolerating a partial load cannot weaken anything: it adds *fewer* platform
    // roots, so the trusted set shrinks. The pinned CA is still required to be
    // present and usable, which is the condition that actually matters and is
    // checked immediately below.
    // `load_native_certs` returns a result struct rather than a `Result`, so
    // partial failure arrives as a non-empty `errors` list beside the roots that
    // did load. Read both and ignore the former, for the reason above.
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        // A single unusable platform root is the same case again, and skipping it
        // keeps the remaining ones.
        let _ = roots.add(certificate);
    }

    let ca_file = File::open(&material.ca_path).map_err(|_| ProxyError::TlsConfiguration)?;
    let ca_certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(ca_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProxyError::TlsConfiguration)?;
    let (valid, invalid) = roots.add_parsable_certificates(ca_certificates);
    if valid == 0 || invalid != 0 {
        return Err(ProxyError::TlsConfiguration);
    }

    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&material.cert_path)
            .map_err(|_| ProxyError::TlsConfiguration)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProxyError::TlsConfiguration)?;
    if certificates.is_empty() {
        return Err(ProxyError::TlsConfiguration);
    }
    let key_file = File::open(&material.key_path).map_err(|_| ProxyError::TlsConfiguration)?;
    let mut keys = PrivateKeyDer::pem_reader_iter(key_file);
    let key: PrivateKeyDer<'static> = keys
        .next()
        .ok_or(ProxyError::TlsConfiguration)?
        .map_err(|_| ProxyError::TlsConfiguration)?;
    if keys.next().is_some() {
        return Err(ProxyError::TlsConfiguration);
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ProxyError::TlsConfiguration)?;
    let config = builder
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .map_err(|_| ProxyError::TlsConfiguration)?;
    Ok(Arc::new(config))
}

#[derive(Clone)]
struct ForwardProxyConnector<C> {
    inner: C,
    proxy: Uri,
}

impl<C> ForwardProxyConnector<C> {
    const fn new(proxy: Uri, inner: C) -> Self {
        Self { inner, proxy }
    }
}

impl<C> Service<Uri> for ForwardProxyConnector<C>
where
    C: Service<Uri> + Clone,
    C::Response: Send + 'static,
    C::Future: Send + 'static,
{
    type Response = ProxiedConnection<C::Response>;
    type Error = C::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<ProxiedConnection<C::Response>, C::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, _destination: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy.clone());
        Box::pin(async move { connecting.await.map(ProxiedConnection) })
    }
}

struct ProxiedConnection<T>(T);

impl<T> Connection for ProxiedConnection<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        self.0.connected().proxy(true)
    }
}

impl<T> Read for ProxiedConnection<T>
where
    T: Read + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
    }
}

impl<T> Write for ProxiedConnection<T>
where
    T: Write + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "tls")]
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };

    use super::{
        ForwardProxy, HttpConnector, MAX_PROXY_PASSWORD_BYTES, ProxyCredentials, ProxyError,
        ProxyPolicy,
    };
    use crate::{DockerClient, Endpoint, ErrorKind};

    async fn read_headers<S>(stream: &mut S) -> std::io::Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "proxy fixture closed before headers",
                ));
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(request)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
            if request.len() > 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy fixture headers exceeded the test bound",
                ));
            }
        }
    }

    async fn start_proxy(
        response: &'static [u8],
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_headers(&mut stream).await?;
            let _ = request_sender.send(request);
            stream.write_all(response).await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[test]
    fn rejects_ambiguous_proxy_urls_without_echoing_them() {
        let error = ForwardProxy::new("https://user:password@proxy.example:8443")
            .expect_err("HTTPS proxy URLs are not accepted");
        assert_eq!(error, ProxyError::UnsupportedScheme);

        let error = ForwardProxy::new("http://user:password@proxy.example:8080")
            .expect_err("URL credentials are not accepted");
        assert_eq!(error, ProxyError::CredentialsInUrl);
        assert!(!error.to_string().contains("password"));
    }

    #[test]
    fn rejects_proxy_routes_for_wrong_endpoint_scheme() {
        let proxy = ForwardProxy::new("http://proxy.example:8080").expect("proxy");
        let error = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("ftp://docker.example:2375".to_owned()),
            ProxyPolicy::Http(proxy),
        )
        .expect_err("only HTTP/TCP endpoints may be forwarded");
        assert_eq!(error.kind(), ErrorKind::Proxy);
    }

    #[test]
    fn bounds_and_redacts_proxy_authentication() {
        let credentials =
            ProxyCredentials::basic("proxy-user", "proxy-password").expect("bounded credentials");
        let output = format!("{credentials:?}");
        assert!(output.contains("<redacted>"));
        assert!(!output.contains("proxy-user"));
        assert!(!output.contains("proxy-password"));
        let proxy = ForwardProxy::with_basic_auth(
            "http://proxy.example:8080",
            "proxy-user",
            "proxy-password",
        )
        .expect("proxy");
        let policy = format!("{:?}", ProxyPolicy::Http(proxy));
        assert!(!policy.contains("proxy-user"));
        assert!(!policy.contains("proxy-password"));

        let too_long = "x".repeat(MAX_PROXY_PASSWORD_BYTES + 1);
        assert!(matches!(
            ProxyCredentials::basic("user", too_long),
            Err(ProxyError::CredentialComponentTooLong {
                component: "password",
                ..
            })
        ));
        assert_eq!(
            ProxyCredentials::basic("user\n", "password"),
            Err(ProxyError::CredentialControlCharacter)
        );
        assert_eq!(
            ProxyCredentials::basic("user", "password\r\n"),
            Err(ProxyError::CredentialControlCharacter)
        );
    }

    #[cfg(feature = "tls")]
    async fn start_tls_target(
        config: Arc<rustls::ServerConfig>,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let acceptor = TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = acceptor.accept(stream).await?;
            let request = read_headers(&mut stream).await?;
            let _ = request_sender.send(request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[cfg(feature = "tls")]
    async fn start_tls_proxy(
        target: std::net::SocketAddr,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await?;
            let request = read_headers(&mut client).await?;
            let _ = request_sender.send(request);
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let mut upstream = TcpStream::connect(target).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[cfg(feature = "tls")]
    fn tls_fixture_material(
        directory: &std::path::Path,
    ) -> Result<(crate::TlsMaterial, Arc<rustls::ServerConfig>), Box<dyn std::error::Error>> {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        use rustls::{RootCertStore, pki_types::PrivateKeyDer};
        use std::fs;

        let ca_key = KeyPair::generate()?;
        let mut ca_parameters = CertificateParams::new(Vec::new())?;
        ca_parameters
            .distinguished_name
            .push(DnType::CommonName, "neotales docker test CA");
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_certificate = ca_parameters.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_parameters, ca_key);

        let server_key = KeyPair::generate()?;
        let mut server_parameters = CertificateParams::new(vec!["localhost".to_owned()])?;
        server_parameters
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_certificate = server_parameters.signed_by(&server_key, &issuer)?;

        let client_key = KeyPair::generate()?;
        let mut client_parameters = CertificateParams::new(Vec::new())?;
        client_parameters
            .distinguished_name
            .push(DnType::CommonName, "docker test client");
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_certificate = client_parameters.signed_by(&client_key, &issuer)?;

        let ca_path = directory.join("ca.pem");
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        fs::write(&ca_path, ca_certificate.pem())?;
        fs::write(&cert_path, client_certificate.pem())?;
        fs::write(&key_path, client_key.serialize_pem())?;

        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate.der().clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()?;
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_certificate.der().clone()],
                PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )?;

        Ok((
            crate::TlsMaterial {
                ca_path,
                cert_path,
                key_path,
            },
            Arc::new(server_config),
        ))
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn sends_https_docker_ping_through_connect_proxy()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use tempfile::tempdir;

        let directory = tempdir()?;
        let (material, server_config) = tls_fixture_material(directory.path())?;
        let (target_address, target_request, target_server) =
            start_tls_target(server_config).await?;
        let (proxy_address, proxy_request, proxy_server) = start_tls_proxy(target_address).await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{proxy_address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Https {
                address: format!("https://localhost:{}", target_address.port()),
                material: Some(material),
            },
            ProxyPolicy::Http(proxy),
        )?;

        let result = tokio::time::timeout(Duration::from_secs(5), client.ping()).await??;
        assert_eq!(result, "OK");
        let connect_request = proxy_request
            .await
            .map_err(|_| "TLS proxy fixture did not report a CONNECT request")?;
        let request = target_request
            .await
            .map_err(|_| "TLS target fixture did not report a request")?;
        proxy_server.await??;
        target_server.await??;
        assert!(
            connect_request.starts_with(&format!(
                "CONNECT localhost:{} HTTP/1.1\r\n",
                target_address.port()
            )),
            "{connect_request}"
        );
        assert!(
            connect_request
                .contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==\r\n"),
            "{connect_request}"
        );
        assert!(request.starts_with("GET /_ping HTTP/1.1\r\n"), "{request}");
        assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
        Ok(())
    }

    #[tokio::test]
    async fn forwards_plain_http_in_absolute_form_with_explicit_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        let (address, request_receiver, server) = start_proxy(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
        )
        .await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://docker.example:2375".to_owned()),
            ProxyPolicy::Http(proxy),
        )?;

        let result = tokio::time::timeout(Duration::from_secs(5), client.ping()).await??;
        assert_eq!(result, "OK");
        let request = request_receiver
            .await
            .map_err(|_| "proxy fixture did not report a request")?;
        server.await??;
        assert!(
            request.starts_with("GET http://docker.example:2375/_ping HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic chjvehktdxnlcjpwcm94es1wyxnzd29yza==\r\n"),
            "{request}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn constructs_hyper_connect_tunnel_with_explicit_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        use hyper_util::client::legacy::connect::proxy::Tunnel;
        use tower_service::Service;

        let (address, request_receiver, server) =
            start_proxy(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let mut tunnel = Tunnel::new(proxy.uri()?, HttpConnector::new())
            .with_auth(proxy.authorization()?.expect("proxy auth"));
        let connection = tunnel.call("https://docker.example:2376".parse()?).await?;
        drop(connection);

        let request = request_receiver
            .await
            .map_err(|_| "proxy fixture did not report a CONNECT request")?;
        server.await??;
        assert!(
            request.starts_with("CONNECT docker.example:2376 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("Host: docker.example:2376\r\n"));
        assert!(
            request.contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==\r\n")
        );
        Ok(())
    }

    #[test]
    fn rejects_proxy_policy_for_local_and_ssh_endpoints() {
        let proxy = ForwardProxy::new("http://proxy.example:8080").expect("proxy");
        let policy = ProxyPolicy::Http(proxy);

        for endpoint in [
            Endpoint::Unix("/var/run/docker.sock".into()),
            Endpoint::NamedPipe(r"\\.\pipe\docker_engine".to_owned()),
            Endpoint::Ssh {
                address: "ssh://docker.example".to_owned(),
                identity_path: None,
            },
        ] {
            let error = DockerClient::connect_endpoint_with_policy(&endpoint, policy.clone())
                .expect_err("proxy must not be applied to a non-TCP endpoint");
            assert_eq!(error.kind(), ErrorKind::Proxy);
        }
    }
}
