//! What the Engine's registry-credential headers look like on the wire.
//!
//! Every other claim about these headers is a claim about *which bytes go into a
//! header this crate builds*, and those bytes are invisible to a unit test that
//! only calls the encoder. This suite stands a local HTTP fixture in for the
//! daemon, drives the two public operations that carry a registry credential,
//! and reads the request the client actually sent.
//!
//! That matters because the failure is silent in both directions. The Engine
//! decodes `X-Registry-Auth` and `X-Registry-Config` with Go's
//! `base64.URLEncoding` and treats a value it cannot decode as *no credential*,
//! and it reads `POST /images/load`'s credential from `X-Registry-Auth` while
//! `X-Registry-Config` is the map header `POST /build` reads. A wrong alphabet
//! or a wrong header name therefore produces a request that is answered exactly
//! as an anonymous one, with no error anywhere.
//!
//! The measurement of what the daemon does with each spelling is in
//! `docker/engine/src/image_transfer.rs`'s module documentation; it was taken
//! against Docker Engine 29.7.2 and is not reproduced here.
//!
//! ## The measure
//!
//! Copy `docker/engine/src/image_transfer.rs` aside, revert it, and run this
//! file: every test that sends a credential fails, because every one of them
//! asserts a header this crate composes. That is the point of putting them at
//! the wire rather than beside the encoder — a test that only called
//! `load_registry_header` would have been reverted along with the code it
//! covers.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use neotales_docker::{
    DockerClient, ImageBuildContext, ImageBuildOptions, ImageImportOptions, ImageTransferError,
    ImageTransferLimits, RegistryCredentials,
};

/// How long a fixture waits for the request it was started for.
///
/// A fixture that never receives its request has to fail rather than hang: every
/// hung test run this repository has had traces back to a fixture that waited
/// for a request the client had stopped making.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

/// A recorded request head: the request line and the headers that followed it.
struct Recorded {
    request_line: String,
    headers: Vec<(String, String)>,
}

impl Recorded {
    /// Returns a header's value, matched case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Starts a fixture daemon on loopback and returns its address and a receiver for
/// the requests it records.
///
/// The fixture reads until the request head is complete and then answers `200`
/// with an empty JSON stream, a shape both a build and a load accept. It does not
/// read the request body: the assertions here are about the head, and both
/// operations send a body small enough to have been written already.
fn fixture() -> Result<(String, Receiver<Recorded>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = channel();
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut head_bytes: Vec<u8> = Vec::new();
            let mut chunk = [0; 4096];
            // A head can arrive over several reads, so keep going until the blank
            // line that ends it. Bounded, so a client that sends nothing ends
            // this connection rather than spinning.
            for _ in 0..64 {
                let Ok(read) = stream.read(&mut chunk) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                head_bytes.extend_from_slice(&chunk[..read]);
                if head_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let Ok(text) = String::from_utf8(head_bytes) else {
                continue;
            };
            let mut lines = text.split("\r\n");
            let Some(request_line) = lines.next().map(str::to_owned) else {
                continue;
            };
            let headers = lines
                .take_while(|line| !line.is_empty())
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
                .collect();
            let _written = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            );
            if sender
                .send(Recorded {
                    request_line,
                    headers,
                })
                .is_err()
            {
                return;
            }
        }
    });
    Ok((format!("http://{address}"), receiver))
}

/// Waits for the fixture's request, or fails with the timeout named.
fn await_request(receiver: &Receiver<Recorded>) -> Recorded {
    match receiver.recv_timeout(FIXTURE_TIMEOUT) {
        Ok(recorded) => recorded,
        Err(RecvTimeoutError::Timeout) => {
            panic!("the fixture received no request within {FIXTURE_TIMEOUT:?}")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the fixture thread stopped early"),
    }
}

/// Candidate secrets, in the order the searches try them.
///
/// The two alphabets differ only in `+`/`-` and `/`/`_`, and an encoded JSON
/// document only reaches those characters when a credential byte lands on a
/// six-bit group of 62 or 63 — which for ASCII means `>`, `?` or `~` at a
/// particular alignment. Almost every short alphanumeric password encodes
/// identically in both, and a test holding one of those passes whichever way the
/// code is wrong. So the tests *search* for a secret and refuse to pass without
/// one that discriminates.
const CANDIDATE_SECRETS: &[&str] = &[
    "a?b", "aa~bb", "p>ss", "s?cret", ">>", "~~", "?>", "~?", "z~>", "0?1", "x>y~z?w",
];

/// The document `POST /build` carries for one registry.
///
/// Compared as an exact string rather than field by field, because the member
/// order and the `null`s are part of the claim: the value is a *map* keyed by the
/// normalized authority, and the generated credential struct contributes every
/// member whether or not this crate set it.
fn expected_config_document(registry: &str, secret: &str) -> String {
    format!(
        r#"{{"{registry}":{{"username":"probeuser","password":"{secret}","auth":null,"email":null,"serveraddress":"{registry}","identitytoken":null,"registrytoken":null}}}}"#
    )
}

/// The document `POST /images/load` carries for one registry.
///
/// One auth object, not a map keyed by registry: the Engine decodes a single
/// object out of `X-Registry-Auth` and wraps it in a one-entry map itself.
fn expected_auth_document(registry: &str, secret: &str) -> String {
    format!(
        r#"{{"username":"probeuser","password":"{secret}","auth":null,"email":null,"serveraddress":"{registry}","identitytoken":null,"registrytoken":null}}"#
    )
}

/// Reports whether a header value tells the two base64 alphabets apart.
///
/// `true` means the URL-safe spelling contains at least one `-` or `_` and no
/// `+` or `/`, which is exactly the condition under which the standard alphabet
/// cannot read the value the Engine would be handed.
fn discriminates_the_alphabets(header: &str) -> bool {
    (header.contains('-') || header.contains('_'))
        && !(header.contains('+') || header.contains('/'))
}

/// Asserts a header is readable by the Engine's alphabet and not by the other.
///
/// The first two assertions are the guard: this exact value is one the two
/// alphabets disagree about, and the URL-safe encoding of it contains no
/// standard-alphabet character. Without them the third would pass for any
/// header base64 happens to accept in both.
fn assert_engine_alphabet(header: &str) {
    assert!(
        discriminates_the_alphabets(header),
        "this header must tell the two base64 alphabets apart, or the next \
         assertion proves nothing: {header}"
    );
    assert!(
        base64::engine::general_purpose::STANDARD
            .decode(header)
            .is_err(),
        "the standard alphabet must not be able to read the Engine's header: {header}"
    );
    assert!(
        base64::engine::general_purpose::URL_SAFE
            .decode(header)
            .is_ok(),
        "the Engine decodes this header with the URL-safe alphabet: {header}"
    );
}

/// Decodes a header the Engine would read, and asserts the alphabet first.
fn decode_as_the_engine_does(header: &str) -> String {
    assert_engine_alphabet(header);
    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(header)
        .expect("the Engine's alphabet reads its own header");
    String::from_utf8(decoded).expect("the header carries a JSON document")
}

/// Builds a one-file build context in a fresh directory.
///
/// The context owns the archive bytes, so the directory is removed before the
/// context is returned rather than left to accumulate one per test run.
fn build_context(tag: &str) -> Result<ImageBuildContext, Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("neotales-docker-wire-{}-{tag}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory)?;
    std::fs::write(directory.join("Dockerfile"), "FROM scratch\n")?;
    let context = ImageBuildContext::from_directory(&directory);
    let _removed = std::fs::remove_dir_all(&directory);
    Ok(context?)
}

/// Sends a build for one of the candidate secrets and returns the recorded head
/// for the first that discriminates the two alphabets.
///
/// Searching here rather than in a literal is deliberate: a hard-coded password
/// stops testing the alphabet the moment somebody changes it, and this way the
/// test says so instead of passing.
fn build_with_a_discriminating_secret(
    client: &DockerClient,
    requests: &Receiver<Recorded>,
) -> Result<(Recorded, String), Box<dyn std::error::Error>> {
    let mut last: Option<Recorded> = None;
    for secret in CANDIDATE_SECRETS {
        let options = ImageBuildOptions::new()
            .with_dockerfile("Dockerfile")
            .with_registry_credentials("ghcr.io", RegistryCredentials::new("probeuser", *secret));
        let _stream = client.build_image(build_context("build")?, Some(options))?;
        let recorded = await_request(requests);
        if let Some(header) = recorded.header("x-registry-config")
            && discriminates_the_alphabets(header)
        {
            return Ok((recorded, (*secret).to_owned()));
        }
        last = Some(recorded);
    }
    Err(search_exhausted("x-registry-config", last).into())
}

/// The error a finished search produces.
///
/// It names the header that was expected and reports what the last request
/// actually carried, because the two ways this can end — the wrong alphabet and
/// the wrong header *name* — look identical from inside the search.
fn search_exhausted(expected: &str, last: Option<Recorded>) -> String {
    let seen = last.map_or_else(
        || "no request at all".to_owned(),
        |recorded| {
            let names: Vec<&str> = recorded
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            if names.is_empty() {
                "a request with no headers".to_owned()
            } else {
                format!("headers {}", names.join(", "))
            }
        },
    );
    format!(
        "none of the {} candidate secrets produced a `{expected}` value that \
         tells the two base64 alphabets apart, and the test cannot assert the \
         alphabet until one does. The last request carried {seen}",
        CANDIDATE_SECRETS.len()
    )
}

/// Sends a load for one of the candidate secrets and returns the recorded head
/// for the first that discriminates the two alphabets.
fn load_with_a_discriminating_secret(
    client: &DockerClient,
    requests: &Receiver<Recorded>,
) -> Result<(Recorded, String), Box<dyn std::error::Error>> {
    let mut last: Option<Recorded> = None;
    for secret in CANDIDATE_SECRETS {
        let mut credentials = BTreeMap::new();
        credentials.insert(
            "ghcr.io".to_owned(),
            RegistryCredentials::new("probeuser", *secret),
        );
        let source = futures_util::stream::iter([Ok::<_, std::io::Error>(Vec::new())]);
        let _stream = client.load_image_with_credentials(
            source,
            None,
            ImageTransferLimits::default(),
            credentials,
        )?;
        let recorded = await_request(requests);
        if let Some(header) = recorded.header("x-registry-auth")
            && discriminates_the_alphabets(header)
        {
            return Ok((recorded, (*secret).to_owned()));
        }
        last = Some(recorded);
    }
    Err(search_exhausted("x-registry-auth", last).into())
}

/// A build sends its credential in `X-Registry-Config`, as a map, URL-safe.
///
/// The Engine's `POST /build` reads a *map* of registry to auth object from
/// `X-Registry-Config`. `X-Registry-Auth` is the single-object header, and a
/// build carrying only that one has no credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_build_carries_its_credentials_in_the_url_safe_config_map()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let (recorded, secret) = build_with_a_discriminating_secret(&client, &requests)?;

    assert!(
        recorded.request_line.starts_with("POST "),
        "{}",
        recorded.request_line
    );
    assert!(
        recorded.request_line.contains("/build"),
        "{}",
        recorded.request_line
    );
    assert_eq!(
        recorded.header("x-registry-auth"),
        None,
        "POST /build reads the map header; a single-object header carries nothing"
    );
    let header = recorded
        .header("x-registry-config")
        .expect("the build sends its credential");
    assert_eq!(
        decode_as_the_engine_does(header),
        expected_config_document("ghcr.io", &secret)
    );
    Ok(())
}

/// A load sends its credential in `X-Registry-Auth`, as one object, URL-safe.
///
/// This is the assertion the defect made impossible to make. `POST /images/load`
/// reads one auth object out of `X-Registry-Auth`; `X-Registry-Config` is the
/// map header `POST /build` reads, and a load request carrying it is answered as
/// though no credential had been sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_load_carries_its_credentials_in_the_url_safe_auth_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let (recorded, secret) = load_with_a_discriminating_secret(&client, &requests)?;

    assert!(
        recorded.request_line.starts_with("POST "),
        "{}",
        recorded.request_line
    );
    assert!(
        recorded.request_line.contains("/images/load"),
        "{}",
        recorded.request_line
    );
    assert_eq!(
        recorded.header("x-registry-config"),
        None,
        "POST /images/load does not read the map header POST /build reads"
    );
    let header = recorded
        .header("x-registry-auth")
        .expect("the load sends its credential");
    assert_eq!(
        decode_as_the_engine_does(header),
        expected_auth_document("ghcr.io", &secret)
    );
    Ok(())
}

/// A load of two or more registries is refused, naming both header names.
///
/// The Engine decodes one auth object out of `X-Registry-Auth`, so a map of
/// registries has no faithful spelling for `POST /images/load`. Sending the
/// nearest available thing instead is what made the credential unreadable in the
/// first place, so this is an error that says which endpoint a multi-registry
/// credential belongs to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_load_of_more_than_one_registry_is_refused_with_both_header_names()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, _requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let mut credentials = BTreeMap::new();
    credentials.insert(
        "ghcr.io".to_owned(),
        RegistryCredentials::new("probeuser", "one"),
    );
    credentials.insert(
        "quay.io".to_owned(),
        RegistryCredentials::new("probeuser", "two"),
    );
    let source = futures_util::stream::iter([Ok::<_, std::io::Error>(Vec::new())]);

    let error = client
        .load_image_with_credentials(source, None, ImageTransferLimits::default(), credentials)
        .err()
        .ok_or("two registries must be refused before a request is opened")?;
    let ImageTransferError::InvalidOption { name, detail } = &error else {
        return Err(format!("unexpected error: {error}").into());
    };
    assert_eq!(*name, "registry-credentials");
    assert!(detail.contains("X-Registry-Auth"), "{detail}");
    assert!(detail.contains("X-Registry-Config"), "{detail}");
    assert!(detail.contains("ghcr.io"), "{detail}");
    assert!(detail.contains("quay.io"), "{detail}");
    Ok(())
}

/// An import sends its credential in `X-Registry-Auth`, URL-safe, one object.
///
/// `POST /images/create?fromSrc=` reads its credential from `X-Registry-Auth` and
/// nowhere else, so the header *name* was already right. The *alphabet* was
/// not: the credential was handed to the generated client, which encodes it with
/// `general_purpose::STANDARD` under a function named `base64_url_encode`, and
/// the Engine decodes with the URL-safe one and treats a failure as no
/// credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_carries_its_credentials_in_the_url_safe_auth_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let mut last: Option<Recorded> = None;
    for secret in CANDIDATE_SECRETS {
        let options = ImageImportOptions::new("https://example.invalid/image.tar");
        let _stream = client.import_image_with_credentials_for_registry(
            options,
            "example.invalid",
            RegistryCredentials::new("probeuser", *secret),
        )?;
        let recorded = await_request(&requests);
        if let Some(header) = recorded.header("x-registry-auth")
            && discriminates_the_alphabets(header)
        {
            assert!(
                recorded.request_line.contains("/images/create"),
                "{}",
                recorded.request_line
            );
            assert_eq!(
                recorded.header("x-registry-config"),
                None,
                "POST /images/create reads the single-object header"
            );
            assert_eq!(
                decode_as_the_engine_does(header),
                expected_auth_document("example.invalid", secret)
            );
            return Ok(());
        }
        last = Some(recorded);
    }
    Err(search_exhausted("x-registry-auth", last).into())
}

/// An import with no credentials sends no registry header at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_with_no_credentials_sends_no_registry_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let options = ImageImportOptions::new("https://example.invalid/image.tar");
    let _stream = client.import_image(options)?;
    let recorded = await_request(&requests);

    assert!(
        recorded.request_line.contains("/images/create"),
        "{}",
        recorded.request_line
    );
    assert_eq!(recorded.header("x-registry-auth"), None);
    assert_eq!(recorded.header("x-registry-config"), None);
    Ok(())
}

/// A load with no credentials sends no registry header at all.
///
/// "No credentials were sent" and "credentials were sent and the registry
/// refused" are different answers, and an empty header is how the second gets
/// reported when nothing was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_load_with_no_credentials_sends_no_registry_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, requests) = fixture()?;
    let client = DockerClient::connect_http(&address)?;
    let source = futures_util::stream::iter([Ok::<_, std::io::Error>(Vec::new())]);
    let _stream = client.load_image(source, None, ImageTransferLimits::default())?;
    let recorded = await_request(&requests);

    assert!(
        recorded.request_line.contains("/images/load"),
        "{}",
        recorded.request_line
    );
    assert_eq!(recorded.header("x-registry-auth"), None);
    assert_eq!(recorded.header("x-registry-config"), None);
    Ok(())
}
