//! `RawTarget::Stream`: a duplex the transport cannot dial, opened per request.
//!
//! The SSH slice has its own file (`ssh_dial_stdio.rs`), which drives a real
//! `sshd` and a real `docker system dial-stdio`. This file covers the part that
//! is about the *target* rather than about SSH, and it needs no peer at all
//! beyond a loopback HTTP fixture: the factory contract, the authority, the one
//! frame reader, and what a refused duplex reports.
//!
//! # Why a loopback server and not an in-memory duplex
//!
//! An in-process duplex is the obvious fixture and it is the wrong one here. Its
//! read side and its write side are the same object, so "the request has been
//! written" and "the response is available" are the same event, and a peer has
//! to arrange for a read that is pending to be woken by its own write. Get that
//! wrong and the connection parks: hyper's client polls the read side before it
//! writes, so the first `poll_read` returns `Pending`, the task sleeps, and the
//! request is never written. That is not a hypothetical — it is what the first
//! version of this file did, and every test in it hung.
//!
//! A loopback socket has a kernel that makes both directions ready
//! independently, which is the property the transport actually relies on and the
//! one an in-memory pair cannot reproduce honestly.
//!
//! ## The measure
//!
//! Copy `docker/engine/src/raw/transport.rs` aside, revert it, and run this
//! file: every test that sends a request fails, because the `Stream` variant and
//! the arm in `connect` are what carry it. A test that passes both before and
//! after a rewire is not a test.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use neotales_docker::Error;
use neotales_docker::raw::{
    Duplex, RawEngine, RawRequest, RawTarget, StreamFactory, collect_json_frames, engine_result,
};
use neotales_docker::{ApiVersion, ErrorKind};

/// The version the owned transport is pinned to, matching the crate's ceiling.
const VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 53,
};

/// How long one request may take end to end.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A loopback HTTP fixture that answers each request with its own connection
/// number.
///
/// The number is the point. It is written by the *server*, so a client that
/// opened one duplex and reused it for two requests would be answered twice by
/// the same connection and see the same number — and a client that opened a
/// duplex per request sees two different ones. The distinction is only visible
/// if the peer is a real socket with a real connection identity, which is why
/// this is a server and not a pair of buffers.
struct Fixture {
    address: String,
    /// Connections the server has accepted, which is the number of duplexes the
    /// client asked for.
    connections: Arc<AtomicUsize>,
    /// Requests the server has read, in order.
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The accept loop owns the listener and ends when the process does, so
        // there is nothing to unwind here beyond dropping the shared counters.
    }
}

/// Starts the fixture and returns it once it is listening.
fn start(body: &str) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    // `host:port`, not a URL: the factory below dials it, and a scheme is not
    // part of a socket address. The scheme belongs on `RawTarget`, and it is not
    // part of `RawTarget` because a `Stream` target's authority is the value
    // the `Host` header carries, which is a different thing.
    let address = listener
        .local_addr()
        .expect("read the bound address")
        .to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counted = Arc::clone(&connections);
    let recorded = Arc::clone(&requests);
    let template = body.to_owned();
    thread::spawn(move || {
        // One thread per connection, and one response per connection. A request
        // that arrives in pieces is read until the head is complete; a client
        // that sends nothing ends its own connection rather than this loop.
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let number = counted.fetch_add(1, Ordering::SeqCst) + 1;
            let response = template.replace("{n}", &number.to_string());
            let handler = Arc::clone(&recorded);
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut chunk = [0_u8; 4096];
                for _ in 0..64 {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            head.extend_from_slice(&chunk[..read]);
                            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                if head.is_empty() {
                    return;
                }
                handler
                    .lock()
                    .expect("the recorded requests")
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _written = stream.write_all(response.as_bytes());
                let _flushed = stream.flush();
            });
        }
    });
    Fixture {
        address,
        connections,
        requests,
    }
}

impl Fixture {
    /// A factory that opens one real TCP duplex per request.
    ///
    /// This is the whole point of the file in nine lines: a `StreamFactory` is a
    /// closure, and the only thing it has to do is hand back a duplex. The
    /// authority is not a socket property, which is why `RawTarget::Stream`
    /// carries one separately.
    fn factory(&self) -> StreamFactory {
        let address = self.address.clone();
        StreamFactory::from_fn(move || {
            let address = address.clone();
            async move {
                let stream = tokio::net::TcpStream::connect(&address)
                    .await
                    .map_err(|error| Error::transport(format!("connect to {address}: {error}")))?;
                Ok(Box::new(stream) as Box<dyn Duplex>)
            }
        })
    }

    /// A target over this fixture.
    fn target(&self) -> RawTarget {
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: self.factory(),
        }
    }

    /// The requests the server has read.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the recorded requests").clone()
    }

    /// The connections the server has accepted.
    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// The factory is called once per request, and a target that cached fails.
///
/// The duplex in this case is a real socket to a real server that answers with
/// the connection number, so the second request seeing `1` means the same
/// connection served it. The count of connections is asserted too, and the two
/// assertions fail differently: a repeated number is a cached duplex, a count of
/// one is a factory called in the wrong place.
#[tokio::test]
async fn a_stream_target_opens_a_fresh_duplex_for_every_request() {
    let fixture = start(&numbered());
    let engine = RawEngine::new(fixture.target(), VERSION);

    let first = send(&engine, "/info").await;
    let second = send(&engine, "/info").await;

    assert_eq!(
        fixture.connections(),
        2,
        "the factory was not called once per request"
    );
    assert_eq!(
        first, br#"{"n":1}"#,
        "the first request did not get the first duplex"
    );
    assert_eq!(
        second, br#"{"n":2}"#,
        "the second request was served a cached duplex"
    );
}

/// Three requests over one target, with each duplex dropped before the next.
///
/// This is the factory contract from the other side. `RawEngine::send` drops the
/// duplex with the response, so a target that held one would serve the first
/// request and then fail on the second — with a protocol error from `hyper` that
/// says nothing about exhaustion, which is the hard version of this bug to
/// diagnose. Each round asserts the connection number it was given, so a reused
/// duplex is caught at the round it happened rather than as a later flake.
#[tokio::test]
async fn a_second_request_succeeds_after_the_first_duplex_is_dropped() {
    let fixture = start(&numbered());
    let engine = RawEngine::new(fixture.target(), VERSION);

    for round in 1..=3 {
        let document = send(&engine, "/version").await;
        assert_eq!(
            document,
            format!("{{\"n\":{round}}}").into_bytes(),
            "round {round} was not served by a fresh duplex"
        );
    }
    assert_eq!(fixture.connections(), 3);
}

/// The request the client wrote is a versioned Engine request, and the
/// `authority` is the one the target was given.
///
/// The daemon ignores the `Host` value, so this cannot be asserted against a
/// status. It is asserted against the bytes on the wire. `RawTarget::Stream`
/// makes the authority a caller's choice rather than a constant, so the claim has
/// to be that the choice is honoured — otherwise the field is decoration.
#[tokio::test]
async fn a_stream_target_sends_a_versioned_request_with_the_given_authority() {
    let fixture =
        start("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "deploy.example.test:2222".to_owned(),
            open: fixture.factory(),
        },
        VERSION,
    );

    let _document = send(&engine, "/version").await;

    let requests = fixture.requests();
    let request = requests.first().expect("a request was recorded");
    assert!(
        request.starts_with("GET /v1.53/version "),
        "the request was not versioned:\n{request}"
    );
    // Case-insensitively: hyper writes header names in the canonical lowercase
    // form, and an assertion that required the title case would be asserting
    // about hyper's spelling rather than about this crate.
    assert!(
        header(request, "host").as_deref() == Some("deploy.example.test:2222"),
        "the authority was not the one the target was given:\n{request}"
    );
}

/// A duplex that cannot be opened is reported as a transport failure that names
/// the target and carries the factory's own reason.
///
/// A factory outside the crate is handed an `Error` to build, and
/// `Error::transport` is public for that reason — a `pub(crate)` constructor
/// would leave a factory with no way to answer. The message naming the endpoint
/// is the property escape criterion 6 is about: "connection refused" on its own
/// does not say which endpoint was tried.
///
/// The assertions read the **source chain**, not `Display`. `ErrorKind::Transport`
/// currently renders as the bare string `"Docker transport error"` and puts the
/// composed message in its source, so `to_string()` alone does not name the
/// target. That is a pre-existing defect in the same area, recorded in
/// `~/work/memory/projects/pvtlab/rust-docker/owned-raw-engine-backend.md` as
/// escape criterion 6 and still open at this commit; it is reported rather than
/// fixed here, because changing what every caller prints is not this slice's
/// decision. The chain is what a caller has today.
#[tokio::test]
async fn a_duplex_that_cannot_be_opened_names_the_target_and_the_reason() {
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "deploy.example.test:2222".to_owned(),
            open: StreamFactory::new(|| {
                Box::pin(async { Err(Error::transport("the fixture refused to open a duplex")) })
            }),
        },
        VERSION,
    );

    let error = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(hyper::Method::GET, "/version")),
    )
    .await
    .expect("the request did not finish in time")
    .expect_err("a factory that refuses must fail the request");

    assert_eq!(error.kind(), ErrorKind::Transport);
    let chain = source_chain(&error);
    assert!(
        chain
            .iter()
            .any(|link| link.contains("deploy.example.test:2222")),
        "no link in the chain named the target: {chain:?}"
    );
    assert!(
        chain
            .iter()
            .any(|link| link.contains("the fixture refused to open a duplex")),
        "no link in the chain carried the factory's reason: {chain:?}"
    );
}

/// The refusal reaches a caller through `source()`, so a caller that formats the
/// chain is not left with only the category.
///
/// This is the half of the claim that holds today. The composed message — the
/// endpoint and the factory's own words — is in the chain, so a caller walking
/// it sees both. See the note on the test above for why the assertions read the
/// chain and not `Display`.
#[tokio::test]
async fn the_refused_duplex_carries_its_reason_in_the_source_chain() {
    let engine = RawEngine::new(
        RawTarget::Stream {
            authority: "docker".to_owned(),
            open: StreamFactory::new(|| {
                Box::pin(async { Err(Error::transport("a very specific refusal")) })
            }),
        },
        VERSION,
    );

    let error = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(hyper::Method::GET, "/version")),
    )
    .await
    .expect("the request did not finish in time")
    .expect_err("a refused duplex must fail the request");

    let chain = source_chain(&error);
    assert!(
        chain
            .iter()
            .any(|link| link.contains("a very specific refusal")),
        "no link in the chain carried the reason: {chain:?}"
    );
}

/// The one frame reader, reached through a duplex this crate did not dial.
///
/// `collect_json_frames` is `FrameStream::next_json` in its bounded form, and it
/// is the decoder every Engine stream goes through. A transport that delivered
/// only one complete short response would pass every test above and fail here,
/// so this is the test that says the path is not only a request/response path.
#[tokio::test]
async fn a_multiline_stream_decodes_through_the_one_frame_reader() {
    let body = concat!(
        "{\"status\":\"Pulling\",\"id\":\"alpine\"}\r\n",
        "{\"status\":\"Downloading\",\"progressDetail\":{}}\r\n",
        "{\"status\":\"Download complete\"}\n"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let fixture = start(&response);
    let engine = RawEngine::new(fixture.target(), VERSION);

    let response = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(hyper::Method::POST, "/images/create")),
    )
    .await
    .expect("the pull did not finish in time")
    .expect("the pull was sent");
    let frames = tokio::time::timeout(REQUEST_TIMEOUT, collect_json_frames(response))
        .await
        .expect("the frame reader did not finish in time")
        .expect("three frames were decoded");

    assert_eq!(frames.len(), 3, "a record was lost or merged");
    assert_eq!(frames[0]["status"], "Pulling");
    assert_eq!(frames[1]["status"], "Downloading");
    // The last record has no trailing newline. It used to be parsed and
    // discarded; returning it is what `FrameStream::next_json` documents, and
    // this asserts it.
    assert_eq!(frames[2]["status"], "Download complete");
}

/// An Engine error status crosses the same path and is read by the one status
/// mapping.
///
/// The message is the daemon's own word, carried through unchanged. Asserting
/// the *text* rather than merely that an error came back is the point: a
/// transport error that renders as a bare string reaches nobody, and a status
/// mapping that replaced the daemon's words would be a second mapping.
#[tokio::test]
async fn an_engine_error_over_a_stream_target_carries_the_daemons_own_message() {
    let message = r#"{"message":"No such container: ndocker-stream-missing"}"#;
    let fixture = start(&format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{message}",
        message.len()
    ));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let response = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(
            hyper::Method::GET,
            "/containers/ndocker-stream-missing/json",
        )),
    )
    .await
    .expect("the inspect did not finish in time")
    .expect("the inspect was sent");
    let error = engine_result(response)
        .await
        .expect_err("inspecting a container that does not exist must fail");

    let api = error
        .api_error()
        .expect("an Engine rejection is reported as an API error");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, "No such container: ndocker-stream-missing");
}

/// A request body is written to the duplex, not just a head.
///
/// Every test above sends a bodyless request, so none of them would notice a
/// transport that dropped the body. The fixture is asked to record the request,
/// and the assertion is on the bytes: `Content-Length` must agree with what
/// actually arrived. A body that is declared and not written is a `hyper`
/// protocol error against a real daemon, and it is invisible to a head-only
/// fixture.
#[tokio::test]
async fn a_request_body_reaches_the_duplex() {
    let fixture = start(
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    );
    let engine = RawEngine::new(fixture.target(), VERSION);
    let document = r#"{"query":"a value with spaces"}"#;

    let response = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(
            RawRequest::new(hyper::Method::POST, "/containers/create").with_body(
                neotales_docker::raw::RawBody::from_bytes(bytes::Bytes::from(document)),
            ),
        ),
    )
    .await
    .expect("the create did not finish in time")
    .expect("the create was sent");
    let _unused = engine_result(response).await.expect("a document");

    let requests = fixture.requests();
    let request = requests.first().expect("a request was recorded");
    assert_eq!(
        header(request, "content-length").as_deref(),
        Some(document.len().to_string().as_str()),
        "the body length was not declared correctly:\n{request}"
    );
    assert!(
        request.ends_with(document),
        "the body did not reach the duplex:\n{request}"
    );
}

/// A record larger than the bound is refused, and the stream recovers at the
/// next one.
///
/// This is the ticket's finding over a real connection rather than over a
/// buffer: a loopback fixture writes an oversized record, a small one, and then
/// ends. The oversized record is refused with a message naming the limit, and
/// the record after it is still read — a daemon that emitted one line this
/// client will not accept did not break the stream, and ending the transfer
/// would lose every later record on a long-lived `/events` or `/stats`.
///
/// The bound is set small on purpose. The default is 8 MiB, and a test that
/// wrote 8 MiB to prove a 4 KiB bound works would be slow for the same
/// coverage; the arithmetic under the default is asserted against the constant
/// in the unit tests, where it is cheap.
#[tokio::test]
async fn an_oversized_record_is_refused_and_the_stream_recovers_after_it() {
    let limit = 64;
    let oversized = record_of(limit + 1);
    let ordinary = record_of(16);
    let body = format!(
        "{}\n{}\n",
        String::from_utf8(oversized).expect("the fixture is utf-8"),
        String::from_utf8(ordinary.clone()).expect("the fixture is utf-8")
    );
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let mut frames = frames.with_record_limit(limit);

    let error = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect_err("a record over the bound must be refused");
    assert!(
        error
            .to_string()
            .contains(&format!("{limit}-byte record limit")),
        "the refusal does not name the limit: {error}"
    );

    // The next record is read, so a caller that keeps polling after the refusal
    // is not left with a dead stream.
    let recovered = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect("the stream recovered at the next record")
        .expect("the record after the refused one is returned");
    assert_eq!(
        recovered["k"].as_str(),
        Some("x".repeat(padding_of(ordinary.len())).as_str()),
        "the record after the refused one is intact, not a tail of the refused one"
    );

    assert!(
        frames.next_json().await.expect("a clean end").is_none(),
        "the stream ends after the last record"
    );
}

/// A refused record's tail is dropped, and the stream resumes after it.
///
/// The wire-level half of the case the length sweep found: a record refused
/// *mid-arrival* is still arriving, so the bytes that follow are its tail rather
/// than a new record. The fixture writes an oversized record in three pieces, so
/// the refusal lands on the piece that crossed the line and two more pieces of
/// the same record are still to come.
///
/// A decoder that resumed on the next read would hand the caller the middle of
/// the record it had just refused, as a record in its own right. This asserts the
/// caller gets the record *after* the refused one, whole, and nothing in between.
#[tokio::test]
async fn a_refused_records_tail_is_dropped_and_the_stream_resumes_after_it() {
    let limit = 64;
    let oversized = record_of(limit * 3);
    // Split the record across three writes, and put the next record in the same
    // write as the record's terminator, which is what a real transport read does
    // whenever the two land in one buffer.
    let mut body = String::new();
    body.push_str(&String::from_utf8_lossy(&oversized[..limit]));
    body.push_str(&String::from_utf8_lossy(&oversized[limit..limit * 2]));
    body.push_str(&String::from_utf8_lossy(&oversized[limit * 2..]));
    body.push('\n');
    let mut following = record_of(16);
    following.push(b'\n');
    body.push_str(&String::from_utf8_lossy(&following));
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let mut frames = frames.with_record_limit(limit);

    // The first refusal lands when the accumulated length crosses the bound. The
    // transport may coalesce the three writes into fewer reads, so the assertion
    // is that *some* read refuses rather than that a particular one does.
    let mut refusals = 0_usize;
    let mut recovered = None;
    for _ in 0..8 {
        match tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
            .await
            .expect("the read did not finish in time")
        {
            Ok(Some(value)) => {
                recovered = Some(value);
                break;
            }
            Ok(None) => break,
            Err(error) => {
                assert!(
                    error
                        .to_string()
                        .contains(&format!("{limit}-byte record limit")),
                    "the failure is not the record bound: {error}"
                );
                refusals += 1;
            }
        }
    }

    assert!(refusals > 0, "the oversized record was not refused");
    let recovered = recovered.expect("the stream never recovered");
    assert_eq!(
        recovered["k"].as_str(),
        Some("x".repeat(padding_of(16)).as_str()),
        "the record after the refused one is intact and is not a tail of the refused one"
    );
    assert!(
        frames.next_json().await.expect("a clean end").is_none(),
        "the stream ends after the last record"
    );
}

/// A record of exactly `len` bytes with its terminator, as the transport would
/// deliver it.
fn terminated(len: usize) -> Vec<u8> {
    let mut record = record_of(len);
    record.push(b'\n');
    record
}

/// A bound cannot be set on a stream that has already delivered a record.
///
/// The public `with_record_limit` replaced the whole reader, so calling it after
/// a read dropped the records the transport had already delivered and reset the
/// refusal state — silently, with the stream still working. On `/events` that is
/// an event a caller is waiting for that simply never arrives, which is the worst
/// shape of failure: no error, no log line, and a subscription that looks healthy.
///
/// The fixture delivers two records. The first is read, which is what fixes the
/// bound. Reconfiguring is then refused, and *every* record is still delivered —
/// which is the part a fix that merely errored would miss, since an error
/// returned after the state had already been replaced would lose the second
/// record just as quietly.
#[tokio::test]
async fn a_bound_cannot_be_set_once_a_record_has_been_delivered() {
    let body = format!(
        "{}\n{}\n",
        String::from_utf8(terminated(8)).expect("the fixture is utf-8"),
        String::from_utf8(terminated(12)).expect("the fixture is utf-8")
    );
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");

    // Before any read, the bound is the caller's to set.
    let mut frames = frames;
    frames
        .try_with_record_limit(64)
        .expect("an unread stream takes a bound");

    let first = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect("the first record is within the bound")
        .expect("the first record is returned");
    assert_eq!(first["k"].as_str().map(str::len), Some(padding_of(8)));

    // After it, the attempt is refused and says why.
    let error = frames
        .try_with_record_limit(64)
        .expect_err("a read stream must refuse a new bound");
    // The call is refused, not applied, and the stream is still the caller's.
    assert_eq!(
        error,
        neotales_docker::raw::RecordLimitError::AlreadyReading
    );
    assert!(
        error.to_string().contains("before the stream is read"),
        "the refusal does not say what to do instead: {error}"
    );

    // The refused call changed nothing: the record after the first is still
    // delivered, and the stream still ends cleanly.
    let second = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect("the second record is within the bound")
        .expect("the second record was not lost by the refused call");
    assert_eq!(second["k"].as_str().map(str::len), Some(padding_of(12)));
    assert!(
        frames.next_json().await.expect("a clean end").is_none(),
        "the stream ends after the last record"
    );
}

/// `with_record_limit` refuses loudly on a read stream rather than replacing it.
///
/// The fallible call is the one to reach for, but the panicking one has to be
/// *safe* rather than merely loud: the version before this fix replaced the whole
/// reader, so calling it after a record had been delivered dropped that record
/// and reset the refusal state, and the stream carried on looking healthy. A
/// silent data loss is worse than a panic, and this is the assertion that says
/// the panic is what a caller now gets instead.
#[tokio::test]
#[should_panic(expected = "before the stream is read")]
async fn the_panicking_bound_refuses_a_read_stream_rather_than_replacing_it() {
    let body = format!(
        "{}\n{}\n",
        String::from_utf8(terminated(8)).expect("the fixture is utf-8"),
        String::from_utf8(terminated(12)).expect("the fixture is utf-8")
    );
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let mut frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let first = frames
        .next_json()
        .await
        .expect("a clean read")
        .expect("the first record is returned");
    assert_eq!(first["k"].as_str().map(str::len), Some(padding_of(8)));

    // Consuming builder, called on a stream that has already read. This is the
    // call that used to replace the reader.
    let _unused = frames.with_record_limit(64);
}

/// A bound of zero is refused rather than applied or panicked on.
///
/// Zero would refuse every record including the empty one, and a caller that
/// computed it — an underflowed subtraction, an empty config field — should find
/// out at the call rather than on the first record of every later stream.
#[tokio::test]
async fn a_zero_bound_is_refused_before_the_stream_is_read() {
    let fixture = start(&ndjson(&String::from_utf8(terminated(8)).expect("utf-8")));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let mut frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let error = frames
        .try_with_record_limit(0)
        .expect_err("a zero bound must be refused");
    assert_eq!(error, neotales_docker::raw::RecordLimitError::ZeroLimit);
    // The refused call left the default in place, so the record is still read
    // rather than every record on the stream being refused in turn.
    let record = frames
        .next_json()
        .await
        .expect("a clean read")
        .expect("the record is returned");
    assert_eq!(record["k"].as_str().map(str::len), Some(padding_of(8)));
}

/// A record of exactly the bound is read over a real connection.
///
/// The same boundary as above from the other side, and the reason it is a
/// separate test: a bound that refused a maximal record would pass the refusal
/// test and fail every real daemon, because the refusal test only ever proves
/// that something is rejected.
#[tokio::test]
async fn a_record_of_exactly_the_bound_is_read_over_the_wire() {
    let limit = 64;
    let exact = record_of(limit);
    let body = format!(
        "{}\n",
        String::from_utf8(exact.clone()).expect("the fixture is utf-8")
    );
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let mut frames = frames.with_record_limit(limit);

    let record = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect("a record at the bound is not refused")
        .expect("the record is returned");
    assert_eq!(
        record["k"].as_str().map(str::len),
        Some(padding_of(exact.len())),
        "the whole record was read, not a prefix of it"
    );
    assert_eq!(
        record["k"].as_str(),
        Some("x".repeat(padding_of(exact.len())).as_str())
    );
    assert!(frames.next_json().await.expect("a clean end").is_none());
}

/// A peer that never terminates a record is refused, not buffered.
///
/// The reachable remote condition the ticket is really about: on `/events` and
/// `/stats` the daemon decides when a record ends, so a stream that sends bytes
/// forever without a terminator is a condition a peer can reach, not malformed
/// input. The fixture writes several times the bound and never writes a newline,
/// and the read must fail rather than grow.
///
/// The assertion is on the error, not on the memory: what matters is that the
/// failure arrives without the record having been assembled, and the bound in
/// the message is what says the buffer stopped where it was told to.
#[tokio::test]
async fn a_record_that_is_never_terminated_is_refused() {
    let limit = 64;
    // No newline anywhere, and eight times the bound. The transport delivers
    // this in several reads, so the refusal has to come from the accumulated
    // length rather than from one oversized chunk.
    let body = "x".repeat(limit * 8);
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let mut frames = frames.with_record_limit(limit);

    let error = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
        .await
        .expect("the read did not finish in time")
        .expect_err("an unterminated record over the bound must be refused");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!("{limit}-byte record limit")),
        "the refusal does not name the limit: {rendered}"
    );
    assert!(
        !rendered.contains('x'),
        "the refusal must not carry the record's bytes: {rendered}"
    );
}

/// A whole stream of small records is read, in order, over a real connection.
///
/// The regression guard for the bound itself. A decoder that charged a whole
/// read to the record it happened to be assembling would refuse this stream once
/// a read carried more than `limit` bytes, so a bound added carelessly breaks
/// the case that matters most: a normal `/events` or `/stats` subscription.
#[tokio::test]
async fn a_stream_of_small_records_is_read_in_order_over_the_wire() {
    let limit = 64;
    let records: Vec<String> = (0..40)
        .map(|index| {
            let record = record_of(16);
            let mut value: serde_json::Value =
                serde_json::from_slice(&record).expect("the fixture is JSON");
            value["n"] = serde_json::Value::from(index);
            value.to_string()
        })
        .collect();
    let body = format!("{}\n", records.join("\n"));
    let fixture = start(&ndjson(&body));
    let engine = RawEngine::new(fixture.target(), VERSION);

    let frames = tokio::time::timeout(REQUEST_TIMEOUT, open_stream(&engine))
        .await
        .expect("the stream did not open in time");
    let mut frames = frames.with_record_limit(limit);

    for index in 0..records.len() {
        let value = tokio::time::timeout(REQUEST_TIMEOUT, frames.next_json())
            .await
            .unwrap_or_else(|_| panic!("record {index} did not arrive in time"))
            .unwrap_or_else(|error| panic!("record {index} failed: {error}"))
            .unwrap_or_else(|| panic!("record {index} was lost"));
        assert_eq!(
            value["n"].as_u64(),
            Some(index as u64),
            "record {index} is out of order, merged, or duplicated"
        );
        assert_eq!(
            value["k"].as_str().map(str::len),
            Some(padding_of(16)),
            "record {index} was truncated"
        );
    }
    assert!(
        frames.next_json().await.expect("a clean end").is_none(),
        "every record was read and the stream then ended"
    );
}

/// Builds a JSON record of exactly `len` bytes.
///
/// The shape is `{"k":"xxxx…"}`: a six-byte opening, a two-byte close, and
/// `len - 8` bytes of padding. A boundary test has to use bytes the daemon could
/// really send, and a bare run of `x` is not a record — the first version of
/// this helper got the envelope wrong and every test that used it failed in
/// `serde_json` rather than at the bound.
fn record_of(len: usize) -> Vec<u8> {
    const OPEN: &[u8] = b"{\"k\":\"";
    const CLOSE: &[u8] = b"\"}";
    let envelope = OPEN.len() + CLOSE.len();
    assert!(len >= envelope, "the envelope alone is eight bytes");
    let mut record = OPEN.to_vec();
    record.extend(std::iter::repeat_n(b'x', len - envelope));
    record.extend_from_slice(CLOSE);
    assert_eq!(record.len(), len, "the padding is what makes the length");
    record
}

/// The length of the padding inside a record [`record_of`] built.
fn padding_of(len: usize) -> usize {
    len - 8
}

/// A `200` answer whose body is `body`, framed as a stream rather than a
/// document.
///
/// No `Content-Length`: the Engine's streaming endpoints do not declare one, and
/// a fixture that declared it would be answering a shape the streamed operations
/// never see.
fn ndjson(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n{body}")
}

/// Opens a stream over the fixture and hands back the frame stream.
async fn open_stream(engine: &RawEngine) -> neotales_docker::raw::FrameStream {
    let response = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(hyper::Method::GET, "/events")),
    )
    .await
    .expect("the request did not finish in time")
    .expect("the request was sent");
    response.into_frames()
}

/// Two targets that name the same authority compare equal, and that is pinned.
///
/// The consequence is a property of the design rather than an accident: a
/// closure is not a value, so `RawTarget` cannot compare factories. Nothing in
/// the crate decides anything with the comparison — a target is built once and
/// then used — so the honest thing is to state it and test it rather than imply
/// the comparison is finer than it is.
#[test]
fn two_stream_targets_with_one_authority_compare_equal() {
    let first = start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let second = start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let third = start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let left = first.target();
    let right = second.target();
    let other = RawTarget::Stream {
        authority: "other".to_owned(),
        open: third.factory(),
    };

    assert_eq!(left, right, "one authority is one target");
    assert_ne!(left, other, "a different authority is a different target");
    assert_ne!(left, RawTarget::Unix("/var/run/docker.sock".into()));
    assert_ne!(left, RawTarget::NamedPipe(r"\\.\pipe\docker_engine".into()));
    assert_ne!(
        left,
        RawTarget::Tcp {
            host: "127.0.0.1".to_owned(),
            port: 2375
        }
    );
    let rendered = format!("{left:?}");
    assert!(
        rendered.contains("docker"),
        "the debug form names the authority: {rendered}"
    );
}

/// `Debug` does not print the factory, and that is pinned too.
///
/// The factory is an opaque closure, so the only thing a `Debug` could show is
/// an address, which tells a reader nothing and changes every run. A derived
/// impl would also put a `Debug` bound on a caller's own closure for no reason
/// they asked for.
#[test]
fn the_debug_form_of_a_stream_target_omits_the_factory() {
    let fixture = start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let rendered = format!("{:?}", fixture.target());

    assert_eq!(
        rendered,
        "Stream { authority: \"docker\", open: StreamFactory(<opaque>) }"
    );
}

/// A JSON answer whose body is `{"n":<the connection number>}`.
///
/// The length is written out rather than computed so a reader can check it by
/// eye, and it is 7 because every number this fixture produces is one digit for
/// the first nine connections — which is more than the tests need. A tenth
/// connection would need 8, and the fixture would then answer a body one byte
/// short of what it declared, which `hyper` reports as a truncated body rather
/// than as a fixture fault. The count is asserted per test and stays well under.
fn numbered() -> String {
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"n\":{n}}"
        .to_owned()
}

/// Returns one header's value from a recorded request, matched case-insensitively.
fn header(request: &str, name: &str) -> Option<String> {
    request
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
}

/// Every message in an error's source chain, starting with its own summary.
fn source_chain(error: &Error) -> Vec<String> {
    let mut chain = vec![error.to_string()];
    let mut current = std::error::Error::source(error);
    while let Some(source) = current {
        chain.push(source.to_string());
        current = source.source();
    }
    chain
}

/// Sends one bodyless request and returns the document it was answered with.
async fn send(engine: &RawEngine, path: &str) -> Vec<u8> {
    let response = tokio::time::timeout(
        REQUEST_TIMEOUT,
        engine.send(RawRequest::new(hyper::Method::GET, path)),
    )
    .await
    .unwrap_or_else(|_| panic!("{path} did not finish in {REQUEST_TIMEOUT:?}"))
    .unwrap_or_else(|error| panic!("{path} could not be sent: {error}"));
    engine_result(response)
        .await
        .unwrap_or_else(|error| panic!("{path} had no document: {error:?}"))
        .to_vec()
}
