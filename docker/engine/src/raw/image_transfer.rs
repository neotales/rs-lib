//! Authenticated, streaming image transfer on the repository-owned Engine
//! backend.
//!
//! This is the streaming half of step 3 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. It covers the six operations
//! that cannot be a single buffered document — `pull_stream`, `push_stream`,
//! `load`, `save`, `import`, and `build` — and it is the first slice in the
//! owned backend to send a [`RawBody::Stream`] request body and to read an
//! answer as newline-delimited JSON.
//!
//! Everything here reuses the existing plumbing: [`RawEngine`] for the
//! connection, [`engine_result`] for the status mapping, [`Query`] and
//! [`with_query`](super::containers::with_query) for the query string,
//! [`escape_path_segment`](super::containers::escape_path_segment) for a
//! reference in a path, and [`FrameStream::next_json`] for the progress
//! records. There is no second HTTP client, no second error type, and no
//! second streaming decoder in the crate.
//!
//! # Why these are streams and the rest of the image surface is not
//!
//! A pull, a push, a load, an import, and a build all write one JSON value per
//! line for as long as the transfer takes. Measured against Docker Engine
//! 29.8.0, an already-current pull is three records and a `save` is 3 731 968
//! bytes of `application/x-tar` with `Transfer-Encoding: chunked` and no
//! length. Buffering either would be buffering a transfer whose size the client
//! cannot know in advance, so each operation here returns the live
//! [`FrameStream`] and the caller reads a record — or, for `save`, a byte
//! chunk — at a time. Dropping the stream closes the connection, which is the
//! cancellation mechanism; there is no separate cancel protocol to get wrong.
//!
//! [`raw::images`](super::images) is the other half of the step: the
//! document-shaped operations, plus the *collected* form of a pull and a push
//! for a caller that wants a bounded answer rather than a live one.
//!
//! # The registry-auth header, and the one thing that is easy to get wrong
//!
//! The Engine reads a pull and a push credential from **`X-Registry-Auth`**, and
//! a build credential from **`X-Registry-Config`**. They are different headers
//! with different shapes: `X-Registry-Auth` carries one registry's auth object,
//! `X-Registry-Config` carries a map of registry to auth object. Both are
//! base64-encoded JSON.
//!
//! **The base64 alphabet is URL-safe, and the pinned dependency sends the
//! standard alphabet under a function named `base64_url_encode`.** Measured
//! against Docker Engine 29.8.0, the same pull of
//! `ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz:latest` answers:
//!
//! | Header | Answer |
//! | --- | --- |
//! | absent | `500` `error from registry: denied\ndenied` |
//! | standard base64 of `{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}` | `500` `error from registry: denied\ndenied` |
//! | URL-safe base64 of the same value | `403` `error from registry: denied` |
//!
//! The middle row is the defect. The daemon decodes the header with
//! `base64.URLEncoding`; when that fails it does not reject the request, it
//! **proceeds with an empty auth configuration**, so the answer is byte for
//! byte the answer to a request that carried no credentials at all. The
//! standard and URL-safe alphabets differ only in `+` and `/`, which the
//! encoding of ASCII JSON can only produce when a credential field ends in `>`
//! or `~` at a 3-byte-aligned offset — uncommon, and a real password, and a
//! password that is silently not sent.
//!
//! So [`RegistryAuth`] encodes with `general_purpose::URL_SAFE` and this module
//! says so at the point of encoding. A credential this client cannot encode is
//! an error, never an empty header: an `X-Registry-Auth` that decodes to nothing
//! is indistinguishable from anonymous, which is the worse of the two failures.
//!
//! A header is also *omitted* rather than sent empty when the caller has no
//! credential. `RegistryAuth::none` sends no header, and a caller can tell that
//! apart from a header that was sent — the difference between "no credentials
//! were sent" and "credentials were sent and the registry refused".
//!
//! # A `200` is not a result
//!
//! Measured against Docker Engine 29.8.0:
//!
//! - A **pull** that the registry refuses answers a non-2xx status with a JSON
//!   error body — `403` or `500` — so [`engine_result`] turns it into an error
//!   with the daemon's own words.
//! - A **push** that the registry refuses answers **`200`** and puts the failure
//!   in the stream:
//!
//!   ```text
//!   {"status":"The push refers to repository [docker.io/library/alpine]"}
//!   {"status":"Layer already exists","progressDetail":{},"id":"25f1d6b1951a"}
//!   {"error":"failed commit on ref \"manifest-sha256:c64c…\": server message: insufficient_scope: authorization failed",
//!    "errorDetail":{"message":"…insufficient_scope: authorization failed"}}
//!   HTTP 200
//!   ```
//!
//! - A **load** whose requested platform is missing answers `200` and puts
//!   `{"error":"image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])"}`
//!   in the stream.
//! - A **build** that never starts answers `500` with a JSON error body, so the
//!   failure is still a status.
//!
//! The status therefore decides only whether the stream *starts*. A caller of
//! [`push_stream`], [`load`], or [`build`] must read its records and pass them
//! to [`progress_error`] to learn the outcome; that is stated on each function
//! and is what [`raw::images::image_push_document`](super::images::image_push_document)
//! does for the collected form.
//!
//! # Where the request differs from the current facade
//!
//! | Member | Facade | Owned backend | Why |
//! | --- | --- | --- | --- |
//! | `X-Registry-Auth` / `X-Registry-Config` encoding | standard base64, through a function named `base64_url_encode` | URL-safe base64 | Measured above. The standard spelling is silently decoded as *no credential*. |
//! | `POST /images/create` `platform` | always sent, defaulting to `platform=` | sent only when the caller set one | The generated option is a non-optional `String`, so the recorded request carries a parameter nobody asked for. An omitted parameter is the same request without the noise. |
//! | `POST /build` `platform`, `target` | always sent, defaulting to empty | sent only when the caller set one | Same reason, same measurement family as the container slice's `platform`. |
//! | `POST /build` `t` | sent through a request modifier, one pair per tag | sent as one `t=` pair per tag, from the builder | The generated option holds a single tag, so a multi-tag build needed a modifier to be expressible at all. |
//! | `POST /images/load` `platform` | one repeated pair per entry | one repeated pair per entry | Both spellings were measured: a JSON *object* repeated once per entry is accepted, and a JSON *array* is refused with `400 failed to parse platform: json: cannot unmarshal array into Go value of type v1.Platform`. Each entry is therefore its own `platform=` pair. |
//! | `POST /build` `buildargs`, `labels` | JSON object in one query value, from a `HashMap` | JSON object in one query value, from the ordered `BTreeMap` | Same gain the container slice records: a recorded request is reproducible, because the key order of the facade's `HashMap` varies between runs. |
//! | `POST /build` `version` / BuildKit parameters | `version=1` and the BuildKit-only parameters are sent by the generated option | never sent | There is no BuildKit session transport in this crate. `ImageBuildBackend::BuildKit` and any named `buildkit_options` are refused here rather than silently downgraded to a classic build, which is the failure the option type already documents. |
//! | `POST /images/load` and `/import` request bodies | a bounded caller-owned stream | a bounded caller-owned stream | Same shape. The bound is [`MAX_UPLOAD_BYTES`] here. |

use std::borrow::Cow;
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use hyper::Method;
use hyper::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;

use super::containers::{Query, escape_path_segment, with_query};
use super::transport::{RawEngine, RawRequest, engine_result};
use crate::raw::body::{FrameStream, RawBody};
use crate::{
    Error, ImageBuildBackend, ImageBuildOptions, ImageImportOptions, ImageLoadOptions,
    ImagePullOptions, ImagePushOptions, ImageSaveOptions, RegistryCredentials, normalize_registry,
};

/// The `X-Registry-Auth` header the Engine reads a pull and a push credential
/// from.
///
/// The Engine's header names are not standard HTTP names, so they are spelled
/// once here rather than as string literals at each use.
static X_REGISTRY_AUTH: HeaderName = HeaderName::from_static("x-registry-auth");
/// The `X-Registry-Config` header the Engine reads a build credential from.
static X_REGISTRY_CONFIG: HeaderName = HeaderName::from_static("x-registry-config");

/// The largest upload body this slice will stream to the daemon.
///
/// `load`, `import`, and `build` all send a caller-owned archive as a
/// [`RawBody::Stream`], and none of them is bounded by a `Content-Length` this
/// client can check afterwards. The bound is therefore enforced *while* the
/// chunks are produced, and exceeding it fails the transfer rather than
/// streaming an unbounded body to a socket.
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// The registry credential one Engine transfer request carries.
///
/// This is a borrow of the repository-owned
/// [`RegistryCredentials`]; nothing here is discovered, read from a
/// configuration file, or persisted. A caller that has no credential says so
/// with [`RegistryAuth::none`], and the difference between "no header" and "a
/// header the registry refused" is preserved rather than blurred.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryAuth<'a> {
    username: Option<&'a str>,
    secret: Option<&'a str>,
    identity_token: bool,
    /// Borrowed when the caller named a normalized authority, owned when this
    /// module normalized the spelling itself. A caller that already holds a
    /// normalized authority pays no allocation; a caller that does not still
    /// gets a validated one.
    server_address: Cow<'a, str>,
}

impl std::fmt::Debug for RegistryAuth<'_> {
    /// Names the registry and whether a secret is present, and nothing else.
    ///
    /// A registry credential is a password. Rendering one into a log line, an
    /// error message, or a test failure is how it ends up in a build log, so
    /// this implementation never formats a username or a secret.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryAuth")
            .field("server_address", &self.server_address)
            .field("has_secret", &self.secret.is_some())
            .field("identity_token", &self.identity_token)
            .finish()
    }
}

impl<'a> RegistryAuth<'a> {
    /// No credential: no `X-Registry-Auth` header is sent at all.
    ///
    /// An absent header is the honest spelling of "no credentials were sent",
    /// and it is deliberately *not* the same as a header carrying an empty auth
    /// object. Measured against Docker Engine 29.8.0, a registry refusal with
    /// no header answers `500 error from registry: denied\ndenied` and with
    /// credentials answers `403 error from registry: denied`; a request whose
    /// header the daemon could not decode answers the first one.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            username: None,
            secret: None,
            identity_token: false,
            server_address: Cow::Borrowed(""),
        }
    }

    /// A credential for one registry, taken from the caller's own value.
    ///
    /// The credential is validated through the repository's own
    /// [`RegistryCredentials::validate_for`](crate::RegistryCredentials), so an
    /// incomplete secret, an oversized field, or a server address that does not
    /// match the registry is refused before a connection is opened — the same
    /// refusal the current facade makes, through the same code.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not a usable authority, or when
    /// the credentials are empty, oversized, or addressed to a different
    /// registry.
    pub fn credentials(
        registry: &str,
        credentials: &'a RegistryCredentials,
    ) -> Result<Self, Error> {
        let normalized = normalize_registry(registry)?;
        credentials.validate_for(&normalized)?;
        // A token-only credential has no username; the repository spells that
        // case as the `<token>` placeholder, and the Engine's `AuthConfig` has a
        // separate `IdentityToken` member for it, so both are sent.
        let (username, secret) = credentials.secret_parts().ok_or_else(|| {
            Error::invalid_input(format!(
                "the registry credential for {normalized} carries no secret"
            ))
        })?;
        Ok(Self {
            identity_token: credentials.username().is_none(),
            username: Some(username),
            secret: Some(secret),
            server_address: match credentials.server_address() {
                // `validate_for` has already checked this against the registry,
                // so the borrow is safe and no normalization is repeated.
                Some(named) => Cow::Borrowed(named),
                None => Cow::Owned(normalized),
            },
        })
    }

    /// A bearer credential for one registry, with no username.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not a usable authority.
    pub fn identity_token(registry: &str, token: &'a str) -> Result<Self, Error> {
        if token.is_empty() {
            return Err(Error::invalid_input(
                "an identity-token registry credential must not be empty",
            ));
        }
        Ok(Self {
            username: Some(TOKEN_USERNAME),
            secret: Some(token),
            identity_token: true,
            server_address: Cow::Owned(normalize_registry(registry)?),
        })
    }

    /// Returns whether a credential will actually be sent.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.secret.is_some() && self.username.is_some()
    }

    /// Returns the registry authority the credential is addressed to.
    #[must_use]
    pub fn server_address(&self) -> &str {
        &self.server_address
    }
}

/// The placeholder account name the Engine expects beside a bearer token.
///
/// The repository's own credential handling spells a token-only credential this
/// way — `RegistryCredentials::into_auth_parts` substitutes it — and the
/// Engine's `AuthConfig` still wants a `username` beside the token, so the
/// placeholder is sent rather than an empty account name.
const TOKEN_USERNAME: &str = "<token>";

/// The Engine's registry auth object, in the spelling its Go struct expects.
///
/// Every member is lower-case: `registrytypes.AuthConfig` declares `username`,
/// `password`, `auth`, `email`, `serveraddress`, `identitytoken`, and
/// `registrytoken`, and this is a `#[derive(Serialize)]` projection rather than
/// the dependency's own struct.
#[derive(Debug, Serialize)]
struct EngineAuthConfig<'a> {
    /// The account name, or the `<token>` placeholder for a bearer credential.
    username: &'a str,
    /// The password, or the token.
    password: &'a str,
    /// The registry the credential is addressed to.
    ///
    /// Owned rather than borrowed: it is a normalized authority this module may
    /// have produced itself, and it outlives the `RegistryAuth` a build's
    /// credential map is built from.
    serveraddress: String,
    /// Set only for a bearer credential, alongside `password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    identitytoken: Option<&'a str>,
}

impl<'a> EngineAuthConfig<'a> {
    /// Projects a borrowed [`RegistryAuth`] onto the Engine's auth object.
    ///
    /// Returns `None` for [`RegistryAuth::none`], which is what makes "no
    /// header" and "an empty header" different requests.
    fn new(auth: &RegistryAuth<'a>) -> Option<Self> {
        if !auth.is_present() {
            return None;
        }
        let secret = auth.secret?;
        Some(Self {
            username: auth.username?,
            password: secret,
            serveraddress: auth.server_address().to_owned(),
            identitytoken: auth.identity_token.then_some(secret),
        })
    }
}

/// Encodes an auth value into the header the Engine reads it from.
///
/// The alphabet is [`AUTH_ALPHABET`] rather than the standard one, for the
/// reason the module documentation gives: the daemon decodes with the URL-safe
/// alphabet and silently treats anything it cannot decode as *no credential*.
pub(super) fn encoded_auth_header<T>(value: &T) -> Result<HeaderValue, Error>
where
    T: Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(value).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine registry auth configuration: {error}"
        ))
    })?;
    let text = URL_SAFE.encode(encoded);
    HeaderValue::from_str(&text).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine registry auth header: {error}"
        ))
    })
}

/// Sets `X-Registry-Auth` on a request, or leaves the header off.
///
/// # Errors
///
/// Returns an error when the credential cannot be encoded or does not fit an
/// HTTP header. There is deliberately no fallback that sends an empty auth
/// object: a header the daemon cannot read is the same as no header, and
/// reporting it as success would hide the difference.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn with_registry_auth(
    mut request: RawRequest,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    let Some(config) = EngineAuthConfig::new(&auth) else {
        return Ok(request);
    };
    let value = encoded_auth_header(&config)?;
    request.headers.insert(X_REGISTRY_AUTH.clone(), value);
    Ok(request)
}

/// Sets `X-Registry-Config` on a build request, or leaves the header off.
///
/// The build endpoint reads a *map* of registry to auth object, not the single
/// object `X-Registry-Auth` carries, and the two headers are not
/// interchangeable: a build with an `X-Registry-Auth` header has no
/// credentials, and one with an `X-Registry-Config` header has them.
///
/// # Errors
///
/// Returns an error when the credential map cannot be encoded or does not fit an
/// HTTP header.
pub(super) fn with_registry_config(
    mut request: RawRequest,
    credentials: &BTreeMap<String, RegistryCredentials>,
) -> Result<RawRequest, Error> {
    if credentials.is_empty() {
        return Ok(request);
    }
    let mut canonical: BTreeMap<String, EngineAuthConfig<'_>> = BTreeMap::new();
    for (registry, credential) in credentials {
        let auth = RegistryAuth::credentials(registry, credential)?;
        if let Some(config) = EngineAuthConfig::new(&auth) {
            canonical.insert(auth.server_address().to_owned(), config);
        }
    }
    if canonical.is_empty() {
        return Ok(request);
    }
    let value = encoded_auth_header(&canonical)?;
    request.headers.insert(X_REGISTRY_CONFIG.clone(), value);
    Ok(request)
}

/// Reads the failure a daemon embeds in an otherwise successful stream.
///
/// Measured against Docker Engine 29.8.0, a refused push, a load whose platform
/// is missing, and a build step that fails all answer `200` and carry the
/// failure in a record, so a caller that only looks at the status reports a
/// failed transfer as a successful one. Pass every record to this and treat a
/// returned message as the result.
///
/// The daemon spells the failure twice — a bare `error` string and an
/// `errorDetail.message` — and this reads the bare `error` first, because that
/// is the one the current facade's own projection prefers. An empty message is
/// reported as no message, for the same reason the shared status mapping falls
/// back to the status rather than printing an empty string: an `error` member the
/// daemon wrote and did not fill in is not a failure to report.
#[must_use]
pub fn progress_error(frame: &serde_json::Value) -> Option<String> {
    frame
        .get("error")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            frame
                .get("errorDetail")
                .and_then(|detail| detail.get("message"))
                .and_then(serde_json::Value::as_str)
        })
        .filter(|message| !message.is_empty())
        .map(ToOwned::to_owned)
}

/// Opens an image pull and returns the daemon's progress stream.
///
/// `POST /images/create` with `fromImage` is the pull, and the same path with
/// `fromSrc` is the import; the two are separate functions here because the
/// request bodies and the query values are different, and because a caller that
/// means one of them should not be able to spell the other by accident.
///
/// The answer is a [`FrameStream`], not a buffered document: the daemon writes
/// one JSON value per line and does not declare a length. Read it with
/// [`FrameStream::next_json`] and pass each record to [`progress_error`]. A
/// pull the registry refuses is *not* in-band — measured against Docker Engine
/// 29.8.0, it is a `403` or a `500` with a JSON error body — so the status is
/// checked before the stream is handed out, and a refused pull is an error
/// carrying the daemon's own words rather than a stream of progress records.
///
/// Dropping the stream closes the connection, which is how a caller stops a
/// pull early.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — including a registry refusal, measured at `403` and `500` — or
/// when the credential cannot be encoded.
pub async fn pull_stream(
    engine: &RawEngine,
    image: &str,
    options: &ImagePullOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error> {
    let response = engine.send(pull_request(image, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/create` request for a pull.
///
/// `platform` is sent only when the caller set one. The generated option in the
/// current dependency is a non-optional `String`, so the recorded facade request
/// always carries `platform=` — even for the pull that asked for nothing.
pub(super) fn pull_request(
    image: &str,
    options: &ImagePullOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    if image.is_empty() {
        return Err(Error::invalid_input(
            "the Engine image reference to pull must not be empty",
        ));
    }
    let mut query = Query::default();
    query.value("fromImage", image);
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    let request = with_query(
        RawRequest::new(Method::POST, "/images/create"),
        query.finish(),
    );
    with_registry_auth(request, auth)
}

/// Opens an image push and returns the daemon's progress stream.
///
/// The answer is a [`FrameStream`]. **A `200` here is not a result.** Measured
/// against Docker Engine 29.8.0, a push the registry refuses answers `200` and
/// carries the refusal in a record:
///
/// ```text
/// {"error":"failed commit on ref \"manifest-sha256:c64c…\": server message: insufficient_scope: authorization failed", …}
/// HTTP 200
/// ```
///
/// Read the records and pass each to [`progress_error`], or use
/// [`raw::images::image_push_document`](super::images::image_push_document),
/// which does that for a caller that wants a bounded answer.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request before the stream starts, or when the credential cannot be encoded.
pub async fn push_stream(
    engine: &RawEngine,
    image: &str,
    options: &ImagePushOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error> {
    let response = engine.send(push_request(image, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/{name}/push` request.
pub(super) fn push_request(
    image: &str,
    options: &ImagePushOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    if image.is_empty() {
        return Err(Error::invalid_input(
            "the Engine image reference to push must not be empty",
        ));
    }
    let mut query = Query::default();
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    let request = with_query(
        RawRequest::new(
            Method::POST,
            format!("/images/{}/push", escape_path_segment(image)),
        ),
        query.finish(),
    );
    with_registry_auth(request, auth)
}

/// Streams a Docker image archive into the daemon and returns its progress.
///
/// The archive is the caller's own stream of bytes, sent as a
/// [`RawBody::Stream`] so it reaches the socket incrementally rather than being
/// buffered whole; [`MAX_UPLOAD_BYTES`] bounds it while it is produced. The
/// request therefore carries `Transfer-Encoding: chunked` and no
/// `Content-Length`, which is what the Engine accepts for this endpoint.
///
/// The answer is a [`FrameStream`], and again **a `200` is not a result**:
/// measured, a load whose requested platform is missing answers `200` and
/// carries `{"error":"image alpine:3.20 was loaded, but doesn't provide the
/// requested platform ([plan9/amd64])"}` in the stream.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request before the stream starts, or when the credential cannot be encoded.
pub async fn load<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageLoadOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let response = engine.send(load_request(source, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/load` request.
fn load_request<S>(
    source: S,
    options: &ImageLoadOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let mut query = Query::default();
    query.flag("quiet", options.quiet);
    // `platform` is one JSON object, and the Engine wants it repeated once per
    // requested platform. An array in one value is not an alternative: measured,
    // `platform=["{…}"]` is refused with `400 failed to parse platform: json:
    // cannot unmarshal array into Go value of type v1.Platform`.
    for platform in &options.platforms {
        query.value("platform", platform);
    }
    let request = with_query(
        RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(
            bounded_upload(source, MAX_UPLOAD_BYTES),
        )),
        query.finish(),
    );
    with_registry_auth(request.with_header(CONTENT_TYPE, "application/x-tar"), auth)
}

/// Downloads one or more images as a Docker archive.
///
/// The answer here is **bytes, not JSON**: measured against Docker Engine
/// 29.8.0, `GET /images/{name}/get` answers `200` with
/// `Content-Type: application/x-tar`, `Transfer-Encoding: chunked`, and no
/// length, and a three-megabyte archive arrived in many chunks. So the returned
/// [`FrameStream`] is read with [`FrameStream::next_data`], and reading it with
/// [`FrameStream::next_json`](crate::raw::FrameStream::next_json) would fail on
/// the first TAR header rather than yield anything.
///
/// A single name goes to `/images/{name}/get` and more than one to
/// `/images/get` with one repeated `names=` pair each, which is the spelling the
/// Engine declares.
///
/// # Errors
///
/// Returns an error when no image name was given, when the daemon cannot be
/// reached, or when it rejects the request.
pub async fn save(engine: &RawEngine, options: &ImageSaveOptions) -> Result<FrameStream, Error> {
    let response = engine.send(save_request(options)?).await?;
    started(response).await
}

/// Builds the `GET /images/{name}/get` or `GET /images/get` request.
fn save_request(options: &ImageSaveOptions) -> Result<RawRequest, Error> {
    if options.names.is_empty() {
        return Err(Error::invalid_input(
            "saving an image archive needs at least one image name",
        ));
    }
    let mut query = Query::default();
    for name in &options.names {
        query.value("names", name);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    let path = match options.names.as_slice() {
        [only] => format!("/images/{}/get", escape_path_segment(only)),
        _ => "/images/get".to_owned(),
    };
    Ok(with_query(
        RawRequest::new(Method::GET, path),
        query.finish(),
    ))
}

/// Streams a root-filesystem archive into the daemon as a new image.
///
/// This is the `fromSrc` half of `POST /images/create`: the same path as a pull
/// with a different query, which is exactly why it is a separate function.
///
/// `changes` is sent as one newline-joined value rather than as repeated pairs,
/// which is the form the Engine declares and the form the current dependency
/// sends. The body is a [`RawBody::Stream`] bounded by [`MAX_UPLOAD_BYTES`].
///
/// The answer is a [`FrameStream`], and **a `200` is not a result**: an import
/// that fails reports it in a record.
///
/// # Errors
///
/// Returns an error when the source is empty, when the daemon cannot be reached
/// or rejects the request, or when the credential cannot be encoded.
pub async fn import<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let response = engine.send(import_request(source, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/create` request for an import.
fn import_request<S>(
    source: S,
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    if options.source.is_empty() {
        return Err(Error::invalid_input(
            "importing an image needs a source URL or '-'",
        ));
    }
    let mut query = Query::default();
    query.value("fromSrc", &options.source);
    if let Some(repository) = options.repository.as_deref() {
        query.value("repo", repository);
    }
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(message) = options.message.as_deref() {
        query.value("message", message);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    if !options.changes.is_empty() {
        query.value("changes", &options.changes.join("\n"));
    }
    let request = with_query(
        RawRequest::new(Method::POST, "/images/create").with_body(RawBody::from_stream(
            bounded_upload(source, MAX_UPLOAD_BYTES),
        )),
        query.finish(),
    );
    with_registry_auth(request.with_header(CONTENT_TYPE, "application/x-tar"), auth)
}

/// Builds an image from a caller's build context and returns the daemon's build
/// stream.
///
/// The context is the caller's own stream of bytes, sent as a
/// [`RawBody::Stream`] bounded by [`MAX_UPLOAD_BYTES`]; it is never buffered
/// here. The credentials go out in `X-Registry-Config`, which is a **map** of
/// registry to auth object — the header a pull does not read and the one a
/// build does.
///
/// `t` is sent as one `t=` pair per tag. The generated option in the current
/// dependency holds a single tag, so a multi-tag build is only expressible there
/// through a request modifier, and the owned request spells the tags out.
///
/// The answer is a [`FrameStream`], and **a `200` is not a result**: a build
/// step that fails reports it in a record. A build that never starts — a
/// `dockerfile` the context does not contain, measured as `500 Cannot locate
/// specified Dockerfile: Nopefile` — is a status, and is reported as an error
/// before the stream is handed out.
///
/// # Errors
///
/// Returns an error when the `BuildKit` backend or a named `BuildKit` option was
/// asked for — there is no `BuildKit` session transport in this crate, and a
/// silent downgrade to a classic build is the failure the option type already
/// documents — when a remote context was named and would have to be downloaded,
/// when the daemon cannot be reached or rejects the request, or when a
/// credential cannot be encoded.
pub async fn build<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageBuildOptions,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let response = engine.send(build_request(source, options)?).await?;
    started(response).await
}

/// Builds the `POST /build` request.
fn build_request<S>(source: S, options: &ImageBuildOptions) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    if options.backend == ImageBuildBackend::BuildKit {
        return Err(Error::invalid_input(
            "the Engine /build endpoint is the classic builder; BuildKit needs a session transport this crate does not have",
        ));
    }
    if let Some(option) = options.buildkit_options.first().copied() {
        return Err(Error::invalid_input(format!(
            "BuildKit image option {option} is not available on the classic Engine /build endpoint"
        )));
    }
    if options.remote.is_some() {
        return Err(Error::invalid_input(
            "a remote build context would have to be downloaded, and this operation builds from a caller-owned stream",
        ));
    }

    let mut query = Query::default();
    if !options.dockerfile.is_empty() {
        query.value("dockerfile", &options.dockerfile);
    }
    for tag in &options.tags {
        query.value("t", tag);
    }
    query.flag("q", options.quiet);
    query.flag("nocache", options.no_cache);
    query.flag("rm", options.remove_intermediate);
    query.flag("forcerm", options.force_remove_intermediate);
    if let Some(pull) = options.pull {
        query.flag("pull", pull);
    }
    if let Some(target) = options.target.as_deref() {
        query.value("target", target);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    if let Some(extra_hosts) = options.extra_hosts.as_deref() {
        query.value("extrahosts", extra_hosts);
    }
    if let Some(network_mode) = options.network_mode.as_deref() {
        query.value("networkmode", network_mode);
    }
    if let Some(memory) = options.memory {
        query.value("memory", &memory.to_string());
    }
    if let Some(memswap) = options.memswap {
        query.value("memswap", &memswap.to_string());
    }
    if let Some(cpu_shares) = options.cpu_shares {
        query.value("cpushares", &cpu_shares.to_string());
    }
    if let Some(cpu_period) = options.cpu_period {
        query.value("cpuperiod", &cpu_period.to_string());
    }
    if let Some(cpu_quota) = options.cpu_quota {
        query.value("cpuquota", &cpu_quota.to_string());
    }
    if let Some(cpuset_cpus) = options.cpuset_cpus.as_deref() {
        query.value("cpusetcpus", cpuset_cpus);
    }
    if let Some(shm_size) = options.shm_size {
        query.value("shmsize", &shm_size.to_string());
    }
    if let Some(squash) = options.squash {
        query.flag("squash", squash);
    }
    if !options.build_args.is_empty() {
        query.value("buildargs", &json_query_value(&options.build_args)?);
    }
    if !options.labels.is_empty() {
        query.value("labels", &json_query_value(&options.labels)?);
    }
    if !options.cache_from.is_empty() {
        // The Engine declares `cachefrom` as an array of strings, and the
        // current dependency sends it as a JSON array in one value; that form is
        // what is sent here, from an ordered list rather than a `HashMap`.
        query.value("cachefrom", &json_query_value(&options.cache_from)?);
    }

    let request = with_query(
        RawRequest::new(Method::POST, "/build")
            .with_body(RawBody::from_stream(bounded_upload(
                source,
                MAX_UPLOAD_BYTES,
            )))
            .with_header(CONTENT_TYPE, "application/x-tar"),
        query.finish(),
    );
    with_registry_config(request, &options.registry_credentials)
}

/// Hands out a response's frame stream once the status says it is one.
///
/// The status is interpreted *before* the body is handed out. An Engine error
/// body is a JSON object, and a `404` whose body happened to parse as a
/// progress record would otherwise arrive as a stream of errors — the same
/// reason `stats_stream` checks the status first.
async fn started(response: super::RawResponse) -> Result<FrameStream, Error> {
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(response.into_frames())
}

/// Encodes a value for a query parameter the Engine declares as JSON.
fn json_query_value<T>(value: &T) -> Result<String, Error>
where
    T: Serialize + ?Sized,
{
    serde_json::to_string(value).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode an Engine build query value: {error}"
        ))
    })
}

/// Wraps a caller-owned upload in a byte bound.
///
/// The bound is checked on every chunk rather than once at the end, so an
/// oversized archive fails while it is still small instead of after the whole
/// body has been written to a socket. The stream is left finished after the
/// first failure: retrying past a limit that has already been exceeded would
/// just exceed it again.
fn bounded_upload<S>(
    source: S,
    limit: u64,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let source = Box::pin(source);
    futures_util::stream::unfold(
        (source, 0_u64, limit, false),
        |(mut source, total, limit, failed)| async move {
            if failed {
                return None;
            }
            let item = source.as_mut().next().await?;
            match item {
                Ok(chunk) => {
                    let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    let Some(next_total) = total.checked_add(length) else {
                        return Some((
                            Err(std::io::Error::other("image upload size overflow")),
                            (source, total, limit, true),
                        ));
                    };
                    if next_total > limit {
                        return Some((
                            Err(std::io::Error::other(format!(
                                "image upload exceeds the {limit}-byte limit"
                            ))),
                            (source, next_total, limit, true),
                        ));
                    }
                    Some((Ok(chunk), (source, next_total, limit, false)))
                }
                Err(error) => Some((
                    Err(std::io::Error::other(error)),
                    (source, total, limit, true),
                )),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use futures_util::stream;
    use hyper::Method;

    use super::{
        MAX_UPLOAD_BYTES, RegistryAuth, build_request, import_request, load_request,
        progress_error, pull_request, push_request, save_request,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawRequest, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, ImageBuildBackend, ImageBuildOptions, ImageImportOptions,
        ImageLoadOptions, ImagePullOptions, ImagePushOptions, ImageSaveOptions,
        RegistryCredentials,
    };

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    fn upload() -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static
    {
        stream::iter(vec![Ok(Bytes::from_static(b"archive"))])
    }

    fn auth() -> RegistryAuth<'static> {
        RegistryAuth {
            username: Some("nobody"),
            secret: Some("aa>"),
            identity_token: false,
            server_address: std::borrow::Cow::Borrowed("ghcr.io"),
        }
    }

    #[test]
    fn the_auth_header_is_url_safe_base64_because_the_daemon_decodes_that() {
        // The value below is the one measured against Docker Engine 29.8.0: a
        // standard-base64 header decodes to nothing on the daemon's side, the
        // pull proceeds with no credential, and the answer is byte for byte the
        // answer to a request with no header at all (`500 error from registry:
        // denied`). The URL-safe spelling of the same value is the one the
        // daemon reads (`403 error from registry: denied`).
        let request = pull_request(
            "ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz",
            &ImagePullOptions {
                tag: Some("latest".to_owned()),
                platform: None,
            },
            auth(),
        )
        .expect("request");
        let header = request
            .headers
            .get("x-registry-auth")
            .expect("an X-Registry-Auth header")
            .to_str()
            .expect("a header value");
        assert_eq!(
            header,
            "eyJ1c2VybmFtZSI6Im5vYm9keSIsInBhc3N3b3JkIjoiYWE-Iiwic2VydmVyYWRkcmVzcyI6ImdoY3IuaW8ifQ=="
        );
        assert!(
            !header.contains('+'),
            "the standard alphabet is the defect: {header}"
        );
        assert!(
            !header.contains('/'),
            "the standard alphabet is the defect: {header}"
        );
        assert!(header.ends_with('='), "URL_SAFE is padded: {header}");
    }

    #[test]
    fn the_measured_standard_alphabet_spelling_really_is_different() {
        // The other half of the measurement: the two alphabets agree on almost
        // every credential and differ on this one, so a test that only checked
        // "the header is base64" would have passed against the defect.
        let standard = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            br#"{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}"#,
        );
        let url_safe = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE,
            br#"{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}"#,
        );
        assert_ne!(standard, url_safe, "the alphabets must differ here");
        assert!(standard.contains('+'), "{standard}");
    }

    #[test]
    fn a_request_with_no_credential_carries_no_auth_header() {
        // An absent header and a header holding an empty auth object are
        // different requests, and only the first one can say "no credentials
        // were sent".
        let request = pull_request("alpine", &ImagePullOptions::default(), RegistryAuth::none())
            .expect("request");
        assert!(request.headers.get("x-registry-auth").is_none());
        let push = push_request("alpine", &ImagePushOptions::default(), RegistryAuth::none())
            .expect("request");
        assert!(push.headers.get("x-registry-auth").is_none());
    }

    #[test]
    fn a_credential_is_only_sent_when_it_carries_a_secret() {
        assert!(!RegistryAuth::none().is_present());
        assert!(auth().is_present());
        assert_eq!(auth().server_address(), "ghcr.io");
    }

    #[test]
    fn a_registry_credential_is_validated_before_a_connection_is_opened() {
        let credentials = RegistryCredentials::new("nobody", "aa>");
        let valid = RegistryAuth::credentials("ghcr.io", &credentials).expect("a credential");
        assert!(valid.is_present());
        assert_eq!(valid.server_address(), "ghcr.io");
        assert!(!valid.identity_token);

        // Credentials addressed to a different registry are refused here, not
        // sent to the wrong one. The repository's own validation classifies it as
        // a credential problem rather than invalid input, and that is the more
        // useful of the two for a caller deciding whether to re-read a store.
        let elsewhere = credentials.clone().with_server_address("registry.example");
        assert_eq!(
            RegistryAuth::credentials("ghcr.io", &elsewhere)
                .expect_err("a mismatched registry")
                .kind(),
            ErrorKind::Credentials
        );
        // A credential with no secret is refused rather than sent empty.
        assert_eq!(
            RegistryAuth::credentials("ghcr.io", &RegistryCredentials::default())
                .expect_err("no secret")
                .kind(),
            ErrorKind::Credentials
        );
        // A registry that is not an authority is refused, and refused by the
        // repository's own normalizer rather than by a private rule here.
        assert_eq!(
            RegistryAuth::credentials("not a registry", &credentials)
                .expect_err("a bad registry")
                .kind(),
            ErrorKind::Credentials
        );
    }

    #[test]
    fn a_token_credential_sends_the_identity_token_member_too() {
        let credentials = RegistryCredentials::from_identity_token("a-token");
        let token = RegistryAuth::credentials("ghcr.io", &credentials).expect("a credential");
        assert!(token.is_present());
        assert!(
            token.identity_token,
            "a token-only credential is an identity token"
        );
        assert_eq!(token.server_address(), "ghcr.io");
    }

    #[test]
    fn the_debug_rendering_of_a_credential_never_prints_the_secret() {
        // A registry credential is a password. Rendering one into a log line or
        // a test failure is how it ends up in a build log.
        let rendered = format!("{:?}", auth());
        assert!(!rendered.contains("aa>"), "{rendered}");
        assert!(rendered.contains("has_secret: true"), "{rendered}");
        assert!(rendered.contains("ghcr.io"), "{rendered}");
    }

    #[test]
    fn a_pull_sends_the_image_the_tag_and_nothing_else() {
        let request = pull_request(
            "ghcr.io/owner/app",
            &ImagePullOptions {
                tag: Some("1.2.3".to_owned()),
                platform: Some("linux/arm64".to_owned()),
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/create?fromImage=ghcr.io%2Fowner%2Fapp&tag=1.2.3&platform=linux%2Farm64 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_pull_without_a_platform_sends_no_platform() {
        // The generated option is a non-optional `String`, so the facade's
        // recorded request always carries `platform=`; an omitted parameter is
        // the same request without the noise.
        let request = pull_request("alpine", &ImagePullOptions::default(), RegistryAuth::none())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/create?fromImage=alpine HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_image_reference_is_refused_before_a_connection_is_opened() {
        assert_eq!(
            pull_request("", &ImagePullOptions::default(), RegistryAuth::none())
                .expect_err("an empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            push_request("", &ImagePushOptions::default(), RegistryAuth::none())
                .expect_err("an empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_push_escapes_its_reference_into_one_segment() {
        let request = push_request(
            "owner/app",
            &ImagePushOptions {
                tag: Some("v1".to_owned()),
                platform: None,
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/owner%2Fapp/push?tag=v1 HTTP/1.1")
        );
    }

    #[test]
    fn a_load_streams_its_body_and_repeats_one_platform_pair_per_entry() {
        // Measured: `platform=["{…}"]` is refused with `400 failed to parse
        // platform: json: cannot unmarshal array into Go value of type
        // v1.Platform`, and the repeated form is what the Engine reads.
        let request = load_request(
            upload(),
            &ImageLoadOptions {
                quiet: true,
                platforms: vec![
                    r#"{"os":"linux","architecture":"amd64"}"#.to_owned(),
                    r#"{"os":"linux","architecture":"arm64"}"#.to_owned(),
                ],
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/load?quiet=true&platform=%7B%22os%22%3A%22linux%22%2C%22architecture%22%3A%22amd64%22%7D&platform=%7B%22os%22%3A%22linux%22%2C%22architecture%22%3A%22arm64%22%7D HTTP/1.1"
            )
        );
        assert_eq!(
            request.body.known_len(),
            None,
            "a streamed body has no length"
        );
    }

    #[test]
    fn a_load_sends_its_archive_as_a_tar_content_type() {
        let request = load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none())
            .expect("request");
        assert_eq!(
            request.headers.get("content-type").expect("a content type"),
            "application/x-tar"
        );
    }

    #[test]
    fn an_import_sends_from_src_and_joins_its_changes_with_newlines() {
        let request = import_request(
            upload(),
            &ImageImportOptions {
                source: "-".to_owned(),
                repository: Some("imported".to_owned()),
                tag: Some("v1".to_owned()),
                message: Some("a message".to_owned()),
                changes: vec!["ENV A=1".to_owned(), "ENV B=2".to_owned()],
                platform: Some("linux/amd64".to_owned()),
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/create?fromSrc=-&repo=imported&tag=v1&message=a+message&platform=linux%2Famd64&changes=ENV+A%3D1%0AENV+B%3D2 HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_import_without_a_source_is_refused() {
        assert_eq!(
            import_request(
                upload(),
                &ImageImportOptions {
                    source: String::new(),
                    ..ImageImportOptions::default()
                },
                RegistryAuth::none(),
            )
            .expect_err("no source")
            .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_spells_every_tag_and_leaves_out_what_was_not_asked_for() {
        let request = build_request(
            upload(),
            &ImageBuildOptions {
                dockerfile: "docker/Dockerfile".to_owned(),
                tags: vec!["probe/a".to_owned(), "probe/b".to_owned()],
                build_args: BTreeMap::from([("V".to_owned(), "1".to_owned())]),
                labels: BTreeMap::from([("L".to_owned(), "x".to_owned())]),
                cache_from: vec!["probe/a".to_owned()],
                ..ImageBuildOptions::default()
            },
        )
        .expect("request");
        let line = request_line(&request);
        assert!(
            line.starts_with(&crate::raw::at_api_version(
                "POST /v1.API/build?dockerfile=docker%2FDockerfile&"
            )),
            "{line}"
        );
        assert!(
            line.contains("&t=probe%2Fa&t=probe%2Fb"),
            "one pair per tag: {line}"
        );
        assert!(
            line.contains("&buildargs=%7B%22V%22%3A%221%22%7D"),
            "{line}"
        );
        assert!(line.contains("&labels=%7B%22L%22%3A%22x%22%7D"), "{line}");
        assert!(line.contains("&cachefrom=%5B%22probe%2Fa%22%5D"), "{line}");
        assert!(line.contains("&rm=true"), "{line}");
        // `platform` and `target` are non-optional `String`s in the generated
        // option, so the facade's recorded request always carries them empty.
        assert!(
            !line.contains("platform"),
            "an unset platform is not sent: {line}"
        );
        assert!(
            !line.contains("target"),
            "an unset target is not sent: {line}"
        );
        // The BuildKit-only `version` parameter is never sent.
        assert!(
            !line.contains("version="),
            "there is no BuildKit session: {line}"
        );
    }

    #[test]
    fn a_build_refuses_buildkit_rather_than_downgrading_it_silently() {
        let options = ImageBuildOptions {
            backend: ImageBuildBackend::BuildKit,
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &options)
                .expect_err("BuildKit")
                .kind(),
            ErrorKind::InvalidInput
        );
        let named = ImageBuildOptions {
            buildkit_options: vec![crate::ImageBuildKitOption::CacheTo],
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &named)
                .expect_err("a named BuildKit option")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_refuses_a_remote_context_it_would_have_to_download() {
        let options = ImageBuildOptions {
            remote: Some("https://example.invalid/context.git".to_owned()),
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &options)
                .expect_err("a remote context")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_with_credentials_sends_the_config_map_and_not_the_single_auth() {
        // The two headers are not interchangeable: `/build` reads
        // `X-Registry-Config`, a map of registry to auth object.
        let options = ImageBuildOptions {
            registry_credentials: BTreeMap::from([(
                "ghcr.io".to_owned(),
                RegistryCredentials::new("nobody", "aa>"),
            )]),
            ..ImageBuildOptions::default()
        };
        let request = build_request(upload(), &options).expect("request");
        assert!(request.headers.get("x-registry-auth").is_none());
        let header = request
            .headers
            .get("x-registry-config")
            .expect("an X-Registry-Config header")
            .to_str()
            .expect("a header value");
        assert!(!header.contains('+'), "{header}");
        assert!(!header.contains('/'), "{header}");
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, header)
            .expect("the daemon's own alphabet decodes it");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("a JSON auth map");
        let entry = &value["ghcr.io"];
        assert_eq!(entry["username"], "nobody");
        assert_eq!(entry["password"], "aa>");
        assert_eq!(entry["serveraddress"], "ghcr.io");
    }

    #[test]
    fn a_build_without_credentials_sends_no_config_header() {
        let request = build_request(upload(), &ImageBuildOptions::default()).expect("request");
        assert!(request.headers.get("x-registry-config").is_none());
    }

    #[test]
    fn a_save_of_one_name_uses_the_single_image_path() {
        let request = save_request(&ImageSaveOptions::new(["alpine:3.20"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/alpine%3A3.20/get?names=alpine%3A3.20 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_save_of_several_names_repeats_the_names_pair() {
        let request =
            save_request(&ImageSaveOptions::new(["alpine:3.20", "busybox:1.36"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/get?names=alpine%3A3.20&names=busybox%3A1.36 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_save_of_a_reference_with_a_slash_keeps_it_in_one_segment() {
        let request = save_request(&ImageSaveOptions::new(["owner/app:v1"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/owner%2Fapp%3Av1/get?names=owner%2Fapp%3Av1 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_save_with_no_names_is_refused() {
        // `POST /images/{name}/tag` with no repository answers `200` and changes
        // nothing, and a save with no name has nothing to save; both are refused
        // here rather than sent for the daemon to accept silently.
        assert_eq!(
            save_request(&ImageSaveOptions::default())
                .expect_err("no names")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn the_daemon_writes_a_push_failure_into_a_two_hundred() {
        // The measured record, and the reason `progress_error` exists: a refused
        // push is `HTTP 200` with the refusal in the body.
        let frame = serde_json::json!({
            "status": "Layer already exists",
            "progressDetail": {},
            "id": "25f1d6b1951a",
        });
        assert_eq!(progress_error(&frame), None);

        let failure = serde_json::json!({
            "error": "failed commit on ref \"manifest-sha256:c64c\": server message: insufficient_scope: authorization failed",
            "errorDetail": {"message": "failed commit on ref \"manifest-sha256:c64c\": server message: insufficient_scope: authorization failed"},
        });
        assert!(
            progress_error(&failure)
                .expect("the daemon's own words")
                .contains("insufficient_scope")
        );

        // A load failure arrives the same way, and its bare `error` is the
        // spelling this reads first.
        let load_failure = serde_json::json!({
            "error": "image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])",
        });
        assert_eq!(
            progress_error(&load_failure).expect("a load failure"),
            "image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])"
        );
    }

    #[test]
    fn an_empty_error_member_is_not_a_failure() {
        // A record that carries an empty `error` is not a failure, and reporting
        // one as a failure would fail a transfer that worked.
        assert_eq!(progress_error(&serde_json::json!({"error": ""})), None);
        assert_eq!(progress_error(&serde_json::json!({"error": null})), None);
    }

    #[tokio::test]
    async fn a_streamed_upload_is_capped_while_it_is_produced() {
        // The bound is checked per chunk, not once at the end, and the stream is
        // left finished after the first failure.
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            (0..4).map(|_| Ok(Bytes::from(vec![b'x'; 8]))).collect();
        let mut upload = Box::pin(super::bounded_upload(stream::iter(chunks), 20));
        let mut sent = 0_u64;
        let mut failure = None;
        while let Some(item) = futures_util::StreamExt::next(&mut upload).await {
            match item {
                Ok(chunk) => sent += u64::try_from(chunk.len()).unwrap_or(0),
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        assert_eq!(sent, 16, "two 8-byte chunks fit under the 20-byte bound");
        assert!(failure.expect("the limit is refused").contains("20-byte"));
    }

    #[tokio::test]
    async fn an_upload_under_the_bound_is_passed_through_whole() {
        let mut upload = Box::pin(super::bounded_upload(
            stream::iter(vec![
                Ok(Bytes::from_static(b"one")),
                Ok(Bytes::from_static(b"two")),
            ]),
            MAX_UPLOAD_BYTES,
        ));
        let mut whole = Vec::new();
        while let Some(item) = futures_util::StreamExt::next(&mut upload).await {
            whole.extend_from_slice(&item.expect("a chunk"));
        }
        assert_eq!(whole, b"onetwo");
    }

    #[test]
    fn a_stream_request_declares_no_length_and_uses_the_documented_method() {
        for request in [
            load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none()).expect("load"),
            import_request(
                upload(),
                &ImageImportOptions::new("https://example.invalid/i.tar"),
                RegistryAuth::none(),
            )
            .expect("import"),
            build_request(upload(), &ImageBuildOptions::default()).expect("build"),
        ] {
            assert!(matches!(request.body, RawBody::Stream(_)), "{request:?}");
            assert_eq!(request.body.known_len(), None);
        }
        assert_eq!(
            load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none())
                .expect("load")
                .method,
            Method::POST
        );
    }

    #[test]
    fn the_document_bound_is_still_the_one_the_rest_of_the_backend_uses() {
        // The collected pull and push forms in `raw::images` bound their answer
        // by the same constant as every other document here, so a stream that
        // never ends cannot be turned into an unbounded buffer by going through
        // the document form.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        assert_eq!(MAX_DOCUMENT_BYTES, 16 * 1024 * 1024);
    }
}
