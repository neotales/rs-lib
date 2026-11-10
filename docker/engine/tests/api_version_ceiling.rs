//! The raised ceiling, checked against a real Engine daemon.
//!
//! Every other test in this crate that mentions an API version either builds a
//! client without connecting, or asserts a string. This file is the only place
//! that asks the question the whole change turns on: **does a daemon actually
//! accept the version this crate now claims to target?**
//!
//! # Why a live daemon and not a recorded fixture
//!
//! A recorded `GET /v1.55/_ping` response proves only that someone once saw a
//! 200. The claim this crate makes is about the *daemon's* gate — the rule that
//! rejects a version above its maximum — and a gate is a property of the running
//! daemon, not of a file in this repository. So the test asks the daemon two
//! questions and requires both answers:
//!
//! 1. Does it accept the prefix this crate sends?
//! 2. Does it reject the very next version up, and does it *say* what its own
//!    maximum is?
//!
//! Question 2 is the one that gives the first its meaning. A daemon that answers
//! 200 to everything would pass question 1 alone, and so would a client that sent
//! no version at all — which is exactly the Bollard defect documented in
//! `README.md`. Pairing them means the test fails if the prefix is absent, if it
//! is the wrong one, or if the ceiling is not actually the daemon's.
//!
//! # Why it parses the rejection message
//!
//! The daemon names its own maximum in the 400 body: `Maximum supported API
//! version is 1.55`. That number is compared against this crate's constant. A
//! test that only asserted "the daemon rejected 1.56" would keep passing on a
//! daemon that had moved to 1.60, at which point the crate would be claiming
//! 1.55 while the daemon was offering more — not wrong, but no longer the
//! statement the constant is supposed to be. Reading the number makes the test
//! say which daemon it is talking to.
//!
//! # Running it
//!
//! These tests are `#[ignore]`d by default and run with:
//!
//! ```text
//! cargo test -p neotales-docker --test api_version_ceiling -- --ignored
//! ```
//!
//! They are ignored rather than skipped-by-environment because "no daemon" and
//! "a daemon that refused" are different outcomes, and a test that quietly
//! returns early on the first while reporting the second as a pass is a test
//! that cannot fail. The endpoint and message-parsing tests need no daemon and
//! run with the ordinary suite, on every platform.
//!
//! # Where the daemon is, per platform
//!
//! `NEOTALES_DOCKER_SOCKET` overrides **only the raw probe** in this file. The
//! separate `DockerClient::connect_defaults()` check uses the crate's normal
//! `DOCKER_HOST` / `DOCKER_CONTEXT` resolution. For that live comparison, point
//! both mechanisms at the same daemon: set `NEOTALES_DOCKER_SOCKET` to the
//! selected local socket when `DOCKER_HOST` or a named context selects a
//! different endpoint. With no such overrides, the raw probe selects the local
//! default socket (including Docker Desktop's `~/.docker/run/docker.sock` on
//! macOS) or the Windows named pipe. Both `//./pipe/docker_engine` and
//! `\\.\pipe\docker_engine` spell the same pipe; input is normalized to
//! Windows' canonical `\\.\pipe\...` spelling before opening it. The bytes
//! written and parsed are otherwise identical on both transports.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
/// How long to wait on the daemon. Generous, because a loaded host can stall a
/// socket write for a while, and a timeout here would be a flake rather than a
/// finding.
const TIMEOUT: Duration = Duration::from_secs(20);

/// The Windows named-pipe probe must not buffer an unbounded response head
/// while it waits for framing.
const MAX_RESPONSE_HEADER_SIZE: usize = 64 * 1024;
/// Keep a broken or hostile Windows daemon from growing the framed probe's body
/// buffer without limit. This caps the complete wire response, including chunk
/// syntax.
const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// The endpoint a local daemon listens on when nothing overrides it.
///
/// A constant rather than a `cfg!` so that a target this file has no transport
/// for is a missing-constant compile error naming the platform's own endpoint,
/// not a silent fall back to a Unix path.
#[cfg(unix)]
const DEFAULT_ENDPOINT: &str = "/var/run/docker.sock";
#[cfg(windows)]
const DEFAULT_ENDPOINT: &str = r"\\.\pipe\docker_engine";

/// The endpoint this process should probe, honouring the environment override.
///
/// Reading the environment is confined to [`endpoint`] so the resolution itself
/// is testable without mutating a process-wide variable out from under the tests
/// running beside it.
fn endpoint() -> PathBuf {
    endpoint_from(std::env::var_os("NEOTALES_DOCKER_SOCKET"))
}

/// The resolution [`endpoint`] performs, given what the environment said.
fn endpoint_from(overridden: Option<OsString>) -> PathBuf {
    #[cfg(unix)]
    {
        overridden.map_or_else(default_unix_endpoint, PathBuf::from)
    }
    #[cfg(windows)]
    {
        let endpoint = overridden.unwrap_or_else(|| OsString::from(DEFAULT_ENDPOINT));
        PathBuf::from(normalize_windows_endpoint(&endpoint))
    }
}

/// Selects the same socket candidates as the crate's non-Windows default.
#[cfg(unix)]
fn default_unix_endpoint() -> PathBuf {
    let home = std::env::var_os("HOME").filter(|home| !home.is_empty());
    select_unix_endpoint(home.as_deref().map(Path::new), Path::exists)
}

#[cfg(unix)]
fn select_unix_endpoint(home: Option<&Path>, exists: impl Fn(&Path) -> bool) -> PathBuf {
    let mut candidates = vec![PathBuf::from(DEFAULT_ENDPOINT)];
    if let Some(home) = home {
        candidates.push(home.join(".docker/run/docker.sock"));
    }
    candidates.push(PathBuf::from("/run/docker.sock"));
    candidates
        .iter()
        .find(|candidate| exists(candidate))
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

/// Replaces either spelling of a Windows pipe separator with a backslash.
///
/// Operating on UTF-16 code units preserves non-ASCII pipe names and even
/// unpaired surrogates in an environment-provided `OsString`.
fn normalize_pipe_separators(units: impl IntoIterator<Item = u16>) -> Vec<u16> {
    units
        .into_iter()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect()
}

#[cfg(windows)]
fn normalize_windows_endpoint(endpoint: &OsStr) -> OsString {
    let units = normalize_pipe_separators(endpoint.encode_wide());
    OsString::from_wide(&units)
}

/// The one request this probe ever sends.
///
/// Both transports send this and nothing else, so it is built here rather than
/// inside either of them: a request the Unix path builds and the Windows path
/// does not would be two probes, and the point of the file is that there is one.
fn build_request(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: api-version-ceiling-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    )
}

/// Splits a response into its status line and its body.
///
/// The terminator is searched for once, at the first `\r\n\r\n`, because a body
/// is free to contain one — an Engine error is JSON on a single line, but a
/// `Connection: close` probe is not the place to assume that.
fn parse_response(response: &[u8]) -> Result<(String, String), String> {
    let text = String::from_utf8_lossy(response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| {
        format!(
            "no header terminator in a {len}-byte response",
            len = response.len()
        )
    })?;
    let status = head
        .lines()
        .next()
        .ok_or_else(|| "empty response head".to_owned())?
        .to_owned();
    Ok((status, body.to_owned()))
}

/// A raw `GET` over the Engine socket, returning `(status_line, body)`.
///
/// Deliberately not the crate's own transport. This is the floor the crate's
/// request building stands on, so using the crate to test the crate would be
/// circular: a bug in the prefix rendering would produce a 400 and a test
/// failure, but so would a bug that stopped the request being sent at all, and
/// the two would be indistinguishable.
///
/// Two implementations, one per platform, behind this one name: a Unix domain
/// socket on Unix, a named pipe on Windows. Both send [`build_request`]'s bytes;
/// Unix reads to EOF and Windows stops at the framed HTTP response, so the live
/// tests below are the same assertions on both rather than a Unix suite with a
/// Windows `cfg` around it.
#[cfg(unix)]
fn get(path: &str) -> Result<(String, String), String> {
    let target = endpoint();
    let mut stream = std::os::unix::net::UnixStream::connect(&target)
        .map_err(|error| format!("connecting to {}: {error}", target.display()))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|error| format!("setting timeouts: {error}"))?;

    stream
        .write_all(build_request(path).as_bytes())
        .map_err(|error| format!("writing: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flushing: {error}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("reading: {error}"))?;
    parse_response(&response)
}

#[cfg(windows)]
fn get(path: &str) -> Result<(String, String), String> {
    // The pipe client is `tokio`'s, because `std` has no blocking named-pipe
    // client, so the probe drives one. A runtime per request rather than one
    // shared: each invocation owns its runtime and pipe connection, so test
    // threads remain independent even when ignored tests run concurrently.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("building a runtime: {error}"))?
        .block_on(get_over_pipe(path))
}

/// The Windows half of [`get`]: one request over the daemon's named pipe.
#[cfg(windows)]
async fn get_over_pipe(path: &str) -> Result<(String, String), String> {
    use tokio::io::AsyncWriteExt as _;

    let mut client = open_pipe(&endpoint()).await?;

    // Both directions are bounded by the same [`TIMEOUT`] the Unix path bounds
    // its reads and writes with. A pipe write cannot stall the way a socket's
    // can, but a daemon that accepts the connection and then says nothing would
    // otherwise hang the suite forever, which is the one outcome a probe must
    // not have.
    tokio::time::timeout(TIMEOUT, client.write_all(build_request(path).as_bytes()))
        .await
        .map_err(|_elapsed| format!("writing to the daemon: no progress in {TIMEOUT:?}"))?
        .map_err(|error| format!("writing: {error}"))?;
    // No-op on a pipe -- there is no userspace buffer to push -- but kept so the
    // two transports issue the same sequence of calls.
    tokio::time::timeout(TIMEOUT, client.flush())
        .await
        .map_err(|_elapsed| format!("flushing to the daemon: no progress in {TIMEOUT:?}"))?
        .map_err(|error| format!("flushing: {error}"))?;

    tokio::time::timeout(TIMEOUT, read_framed_response(&mut client))
        .await
        .map_err(|_elapsed| format!("reading: no complete HTTP response in {TIMEOUT:?}"))?
}

/// Read a framed response without relying on the daemon closing its pipe.
#[cfg(windows)]
async fn read_framed_response<R>(reader: &mut R) -> Result<(String, String), String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(parsed) = parse_framed_response(&response)? {
            return Ok(parsed);
        }
        let read_len = (MAX_RESPONSE_SIZE + 1 - response.len()).min(chunk.len());
        let count = reader
            .read(&mut chunk[..read_len])
            .await
            .map_err(|error| format!("reading: {error}"))?;
        if count == 0 {
            return Err("reading: pipe closed before the HTTP response was complete".to_owned());
        }
        response.extend_from_slice(&chunk[..count]);
    }
}

/// Return a response once its HTTP framing is complete; `None` means read more.
/// Bytes already buffered beyond the framed response are rejected rather than
/// silently parsed as part of its body. The reader intentionally does not wait
/// for EOF to rule out bytes that might arrive later: doing so would make a
/// named-pipe probe hang on daemons that keep the connection open.
fn parse_framed_response(response: &[u8]) -> Result<Option<(String, String)>, String> {
    if response.len() > MAX_RESPONSE_SIZE {
        return Err(format!("HTTP response exceeds {MAX_RESPONSE_SIZE} bytes"));
    }
    let Some(head_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        if response.len() > MAX_RESPONSE_HEADER_SIZE {
            return Err(format!(
                "HTTP response headers exceed {MAX_RESPONSE_HEADER_SIZE} bytes"
            ));
        }
        return Ok(None);
    };
    let header_end = head_end + 4;
    if header_end > MAX_RESPONSE_HEADER_SIZE {
        return Err(format!(
            "HTTP response headers exceed {MAX_RESPONSE_HEADER_SIZE} bytes"
        ));
    }

    let ResponseHead {
        status,
        content_length,
        transfer_encoding,
    } = parse_framed_head(&response[..head_end + 2])?;
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err("conflicting Content-Length and Transfer-Encoding".to_owned());
    }
    let (body_end, is_chunked) = match (content_length, transfer_encoding.as_deref()) {
        (Some(length), None) => {
            if length > MAX_RESPONSE_SIZE.saturating_sub(header_end) {
                return Err(format!("HTTP response exceeds {MAX_RESPONSE_SIZE} bytes"));
            }
            let end = header_end
                .checked_add(length)
                .ok_or_else(|| "Content-Length overflows response size".to_owned())?;
            if response.len() < end {
                return Ok(None);
            }
            (end, false)
        }
        (None, Some(encoding)) if encoding == b"chunked" => {
            let Some(end) = chunked_body_end(&response[header_end..])? else {
                return Ok(None);
            };
            (header_end + end, true)
        }
        (None, Some(_)) => return Err("unsupported Transfer-Encoding".to_owned()),
        (None, None) => return Err("HTTP response has no supported body framing".to_owned()),
        (Some(_), Some(_)) => {
            return Err("conflicting Content-Length and Transfer-Encoding".to_owned());
        }
    };
    if response.len() != body_end {
        return Err("trailing data after the framed HTTP response".to_owned());
    }
    if body_end > MAX_RESPONSE_SIZE {
        return Err(format!("HTTP response exceeds {MAX_RESPONSE_SIZE} bytes"));
    }
    let body_bytes = if is_chunked {
        decode_chunked_body(&response[header_end..body_end])
    } else {
        response[header_end..body_end].to_vec()
    };
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    Ok(Some((status, body)))
}

struct ResponseHead {
    status: String,
    content_length: Option<usize>,
    transfer_encoding: Option<Vec<u8>>,
}

fn parse_framed_head(head: &[u8]) -> Result<ResponseHead, String> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines
        .next()
        .ok_or_else(|| "empty response head".to_owned())?;
    let status_line = status_line
        .strip_suffix(b"\r")
        .ok_or_else(|| "malformed HTTP status line".to_owned())?;
    if !valid_status_line(status_line) {
        return Err("malformed HTTP status line".to_owned());
    }
    let status = String::from_utf8_lossy(status_line).into_owned();

    let mut content_length = None;
    let mut transfer_encoding = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line = line
            .strip_suffix(b"\r")
            .ok_or_else(|| "malformed HTTP header line".to_owned())?;
        let (name, value) = parse_header_field(line)?;
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit)
            {
                return Err("invalid or duplicate Content-Length".to_owned());
            }
            let value = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| "invalid Content-Length".to_owned())?;
            content_length = Some(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if transfer_encoding.is_some() || value.is_empty() {
                return Err("invalid or duplicate Transfer-Encoding".to_owned());
            }
            transfer_encoding = Some(value.to_ascii_lowercase());
        }
    }

    Ok(ResponseHead {
        status,
        content_length,
        transfer_encoding,
    })
}

fn parse_header_field(line: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| "malformed HTTP header without colon".to_owned())?;
    let name = &line[..colon];
    if name.is_empty()
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
    {
        return Err("malformed HTTP header name".to_owned());
    }
    let raw_value = &line[colon + 1..];
    if raw_value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err("invalid control byte in HTTP header".to_owned());
    }
    Ok((name, trim_ascii(raw_value)))
}

fn valid_status_line(line: &[u8]) -> bool {
    let Some(separator) = line.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let protocol = &line[..separator];
    let code_start = separator + 1;
    if line.len() < code_start + 3 {
        return false;
    }
    let code = &line[code_start..code_start + 3];
    let reason = match line.get(code_start + 3..) {
        Some([]) => &[][..],
        Some([b' ', rest @ ..]) => rest,
        _ => return false,
    };
    (protocol == b"HTTP/1.0" || protocol == b"HTTP/1.1")
        && code.iter().all(u8::is_ascii_digit)
        && reason.iter().all(|byte| *byte == b'\t' || *byte >= 0x20)
        && !reason.contains(&0x7f)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// Find the end of a chunked body, including the final empty trailer line.
fn chunked_body_end(mut bytes: &[u8]) -> Result<Option<usize>, String> {
    let mut consumed = 0;
    let mut decoded_body_size = 0_usize;
    loop {
        let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n") else {
            return Ok(None);
        };
        let size_text = bytes[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        if size_text.is_empty() || !size_text.iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid chunk size".to_owned());
        }
        let extension = &bytes[..line_end][size_text.len()..];
        if extension.iter().any(|byte| *byte < 0x21 || *byte > 0x7e) {
            return Err("invalid chunk extension".to_owned());
        }
        let size_text = std::str::from_utf8(size_text).expect("hex digits are ASCII");
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| "invalid chunk size".to_owned())?;
        decoded_body_size = decoded_body_size
            .checked_add(size)
            .ok_or_else(|| "chunked body size overflows".to_owned())?;
        if decoded_body_size > MAX_RESPONSE_SIZE {
            return Err(format!(
                "HTTP response body exceeds {MAX_RESPONSE_SIZE} bytes"
            ));
        }
        let chunk_start = line_end + 2;
        consumed += chunk_start;
        bytes = &bytes[chunk_start..];
        if size == 0 {
            loop {
                let Some(trailer_end) = bytes.windows(2).position(|window| window == b"\r\n")
                else {
                    return Ok(None);
                };
                consumed += trailer_end + 2;
                if trailer_end == 0 {
                    return Ok(Some(consumed));
                }
                let trailer = &bytes[..trailer_end];
                let (name, _) = parse_header_field(trailer)
                    .map_err(|_| "malformed chunked trailer".to_owned())?;
                if name.eq_ignore_ascii_case(b"content-length")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
                {
                    return Err("framing header in chunked trailer".to_owned());
                }
                bytes = &bytes[trailer_end + 2..];
            }
        }
        let Some(end) = size.checked_add(2) else {
            return Err("chunk size overflows response".to_owned());
        };
        if bytes.len() < end {
            return Ok(None);
        }
        if &bytes[size..end] != b"\r\n" {
            return Err("chunk data is not followed by CRLF".to_owned());
        }
        consumed = consumed
            .checked_add(end)
            .ok_or_else(|| "chunked response size overflows".to_owned())?;
        bytes = &bytes[end..];
    }
}

fn decode_chunked_body(mut bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("validated chunk line");
        let size_text = bytes[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let size =
            usize::from_str_radix(std::str::from_utf8(size_text).expect("validated hex"), 16)
                .expect("validated chunk size");
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

/// The pipe client this crate's probes use, named once for the signatures below.
#[cfg(windows)]
type PipeClient = tokio::net::windows::named_pipe::NamedPipeClient;

/// Opens the daemon's pipe, waiting at most [`TIMEOUT`] for a free instance.
///
/// `CreateFileW` reports a busy pipe rather than blocking for the next instance,
/// and the Engine's daemon recreates instances in a loop, so the retry `tokio`
/// documents for its own `open` is bounded here rather than left open-ended: a
/// probe that cannot get an instance fails with the reason instead of hanging.
/// The Unix stream's connect itself is blocking; its read and write timeouts are
/// installed immediately after the connection succeeds.
#[cfg(windows)]
async fn open_pipe(target: &Path) -> Result<PipeClient, String> {
    /// `ERROR_PIPE_BUSY`, spelled out because `windows-sys` is not a dependency
    /// of this test target and this is the only code it is needed for.
    const BUSY: i32 = 231;
    const RETRY_DELAY: Duration = Duration::from_millis(50);

    let give_up_at = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let opened = tokio::net::windows::named_pipe::ClientOptions::new()
            .read(true)
            .write(true)
            .open(target);
        match opened {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(BUSY) => {
                if tokio::time::Instant::now() >= give_up_at {
                    return Err(format!(
                        "connecting to {}: every instance stayed busy for {TIMEOUT:?}: {error}",
                        target.display()
                    ));
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(error) => return Err(format!("connecting to {}: {error}", target.display())),
        }
    }
}

/// The daemon's maximum API version, read out of its own rejection message.
///
/// The Engine answers a too-new prefix with `400` and a body of the form
/// `{"message":"client version 1.56 is too new. Maximum supported API version is
/// 1.55"}`. Probe well above the crate's v1.55 cap so a newer daemon remains a
/// valid test target; the crate's compatibility limit and the daemon's own
/// maximum are independent facts.
fn daemon_maximum_api_version() -> Result<usize, String> {
    const PROBE_MINOR: usize = 999;
    let probe = PROBE_MINOR;
    let (status, body) = get(&format!("/v1.{probe}/_ping"))?;
    if !status.contains(" 400 ") {
        return Err(format!(
            "expected the daemon to reject /v1.{probe}/_ping with 400, got {status:?}"
        ));
    }
    if !body.contains("is too new") {
        return Err(format!(
            "the daemon's {status:?} for /v1.{probe}/_ping was not a too-new rejection: {body:?}"
        ));
    }
    let maximum = parse_reported_maximum(&body)?;
    if maximum >= probe {
        return Err(format!(
            "the daemon reported maximum v1.{maximum}, not below the v1.{probe} probe"
        ));
    }
    Ok(maximum)
}

/// Extracts the maximum from `Maximum supported API version is <n>`.
fn parse_reported_maximum(body: &str) -> Result<usize, String> {
    parse_after(body, "Maximum supported API version is ")
}

/// Extracts the minimum from `Minimum supported API version is <n>`.
///
/// Needed because the daemon's *minimum* is not the crate's concern and is not
/// 1.24, which is what `moby/api/common.go` said at the last tag that had the
/// file. The Engine 29.x daemon on the development host answers `1.40`. A test
/// that walked "from 1.24" would fail against the minimum rather than against
/// anything the ceiling does, which is the failure mode this function removes:
/// the range walked is read back from the daemon instead of assumed.
fn parse_reported_minimum(body: &str) -> Result<usize, String> {
    parse_after(body, "Minimum supported API version is ")
}

/// Reads a dotted `major.minor` that follows `marker`.
fn parse_after(body: &str, marker: &str) -> Result<usize, String> {
    let (_, rest) = body
        .split_once(marker)
        .ok_or_else(|| format!("no {marker:?} in the daemon's message: {body:?}"))?;
    // The value is `1.55` and then the closing quote of the JSON string, so the
    // digits and the dot between them are what is being read -- not a run of
    // digits, which would stop at the dot and yield the major version.
    let mut seen_dot = false;
    let version: String = rest
        .chars()
        .take_while(|character| {
            if *character == '.' {
                seen_dot = true;
                return true;
            }
            character.is_ascii_digit()
        })
        .collect();
    if !seen_dot {
        return Err(format!(
            "{marker:?} is not followed by a dotted version: {body:?}"
        ));
    }
    let minor = version
        .split_once('.')
        .map(|(_, minor)| minor)
        .unwrap_or_default();
    minor
        .parse()
        .map_err(|error| format!("parsing the minor of {version:?} from {body:?}: {error}"))
}

/// The daemon accepts the version prefix this crate targets.
///
/// This is the claim the bump makes, asked of a real daemon. It goes through
/// the crate's own owned transport, so a regression in how the prefix is built
/// fails here rather than only in production.
#[test]
#[ignore = "needs a live Engine daemon; run with -- --ignored"]
fn the_daemon_accepts_the_prefix_this_crate_sends() {
    let client = neotales_docker::DockerClient::connect_defaults()
        .expect("connecting with the repository's own defaults");
    let engine = client
        .raw_engine()
        .expect("the owned transport should reach the default endpoint");

    let path = format!(
        "/v{}.{}/_ping",
        neotales_docker::API_VERSION.major,
        neotales_docker::API_VERSION.minor
    );
    let (status, body) = get(&path).expect("a ping");
    assert!(
        status.contains(" 200 "),
        "the daemon refused the version prefix this crate targets (v{major}.{minor}): \
         {status:?} {body:?}",
        major = neotales_docker::API_VERSION.major,
        minor = neotales_docker::API_VERSION.minor,
    );

    // The crate's own transport must be configured for the version that was
    // just accepted. Reading `version()` rather than trusting the constant is
    // the point: if a constructor handed the owned transport a different
    // version than the crate claims -- which is exactly what happened when
    // `raw_version` was derived from the version passed to Bollard -- this
    // compares the two and fails.
    let owned = engine.version();
    assert_eq!(
        owned,
        neotales_docker::API_VERSION,
        "the owned transport speaks v{owned_major}.{owned_minor} while the crate claims \
         v{claimed_major}.{claimed_minor}",
        owned_major = owned.major,
        owned_minor = owned.minor,
        claimed_major = neotales_docker::API_VERSION.major,
        claimed_minor = neotales_docker::API_VERSION.minor,
    );
}

/// The crate's ceiling is within this daemon's supported range.
///
/// The daemon may support a newer API than this crate claims. The crate cap
/// stays at v1.55 until the newer API additions are implemented and reviewed;
/// this check requires only that the daemon's maximum is not below the crate's
/// supported version.
#[test]
#[ignore = "needs a live Engine daemon; run with -- --ignored"]
fn the_crates_ceiling_is_supported_by_the_daemon() {
    let maximum = daemon_maximum_api_version().expect("reading the daemon's maximum");
    assert!(
        maximum >= neotales_docker::API_VERSION.minor,
        "the crate targets v{major}.{minor} but the daemon's own maximum is v1.{maximum}",
        major = neotales_docker::API_VERSION.major,
        minor = neotales_docker::API_VERSION.minor,
    );
}

/// The daemon's own minimum, read out of its own rejection message.
///
/// Probing below the minimum gets `400 ... too old. Minimum supported API
/// version is <n>`, which is the only place the daemon states it.
fn daemon_minimum_api_version() -> Result<usize, String> {
    let (status, body) = get("/v1.0/_ping")?;
    if !status.contains(" 400 ") {
        return Err(format!(
            "expected the daemon to reject /v1.0 with 400, got {status:?}"
        ));
    }
    parse_reported_minimum(&body)
}

/// Every version in the daemon's reported range is accepted, and the next is
/// rejected.
///
/// The daemon's bounds are discovered at runtime rather than assuming they
/// exactly match the crate's deliberately lower compatibility cap.
#[test]
#[ignore = "needs a live Engine daemon; run with -- --ignored"]
fn the_daemon_accepts_its_reported_range_and_rejects_the_next() {
    let minimum = daemon_minimum_api_version().expect("reading the daemon's minimum");
    let maximum = daemon_maximum_api_version().expect("reading the daemon's maximum");
    assert!(
        minimum <= maximum,
        "daemon range v1.{minimum}..=v1.{maximum} is inverted"
    );
    assert!(
        minimum <= neotales_docker::API_VERSION.minor
            && neotales_docker::API_VERSION.minor <= maximum,
        "the daemon's supported range v1.{minimum}..=v1.{maximum} does not include the \
         crate's ceiling v1.{}",
        neotales_docker::API_VERSION.minor
    );

    for minor in minimum..=maximum {
        let (status, body) = get(&format!("/v1.{minor}/_ping")).expect("a ping");
        assert!(
            status.contains(" 200 "),
            "the daemon refused v1.{minor}, which is in its reported range \
             v1.{minimum}..=v1.{maximum}: {status:?} {body:?}"
        );
    }

    let above = maximum + 1;
    let (status, body) = get(&format!("/v1.{above}/_ping")).expect("a ping");
    assert!(
        status.contains(" 400 "),
        "the daemon accepted v1.{above}, one above its reported maximum: {status:?} {body:?}"
    );
    assert!(
        body.contains("is too new"),
        "the rejection did not say the version was too new, so this is some other 400: {body:?}"
    );
    assert_eq!(
        parse_reported_maximum(&body).expect("the rejection reports the daemon maximum"),
        maximum,
        "the rejection's stated maximum must match the discovered maximum"
    );
}

/// A version outside v1 is refused, and the refusal is the version gate's.
///
/// Worth separating from the cases above: a `2.0` prefix could be rejected by a
/// router that only understands single-digit majors, which would make the suite
/// look like it had checked the ceiling when it had checked string parsing.
#[test]
#[ignore = "needs a live Engine daemon; run with -- --ignored"]
fn a_major_version_above_one_is_refused_by_the_daemon() {
    let (status, body) = get("/v2.0/_ping").expect("a ping");
    assert!(
        status.contains(" 400 "),
        "the daemon accepted a v2.0 prefix: {status:?} {body:?}"
    );
}

/// The parser reads the Engine's message for both bounds.
///
/// No daemon needed — the two strings are the ones the Engine writes, quoted
/// from its own responses — so this runs with the ordinary suite rather than
/// under `--ignored`, which is what makes the coverage on every platform: the
/// parsing is the same everywhere, and only the transport above it is not. It is
/// kept here rather than in a unit test inside `src/` because it is the parsing
/// that makes the live tests above work, and a parser that silently reads the
/// major version as the minor would turn every one of them into an opaque
/// failure at the first `expect`.
#[test]
fn the_rejection_message_parses() {
    let too_new =
        r#"{"message":"client version 1.56 is too new. Maximum supported API version is 1.55"}"#;
    assert_eq!(parse_reported_maximum(too_new).expect("parses"), 55);

    let too_old = r#"{"message":"client version 1.24 is too old. Minimum supported API version is 1.40, please upgrade your client to a newer version"}"#;
    assert_eq!(parse_reported_minimum(too_old).expect("parses"), 40);

    // A body with neither marker is an error, not a zero. Returning 0 would
    // make a daemon that changed its wording look like a daemon whose minimum
    // is 0.0, and every range check built on it would then pass vacuously.
    assert!(parse_reported_maximum("{}").is_err());
    assert!(parse_reported_minimum("{}").is_err());
}

/// The daemon accepts the crate cap; versions just around it follow the
/// daemon's independently reported range.
///
/// The crate's local tests enforce its own cap. This live check establishes that
/// the daemon can accept the crate's version without assuming the daemon rejects
/// the next version too.
#[test]
#[ignore = "needs a live Engine daemon; run with -- --ignored"]
fn the_ceiling_boundary_agrees_with_the_daemon() {
    let ceiling = neotales_docker::API_VERSION.minor;
    let minimum = daemon_minimum_api_version().expect("reading the daemon's minimum");
    let maximum = daemon_maximum_api_version().expect("reading the daemon's maximum");
    for version in [ceiling - 1, ceiling, ceiling + 1] {
        let should_be_accepted = (minimum..=maximum).contains(&version);
        let (status, body) = get(&format!("/v1.{version}/_ping")).expect("a ping");
        assert_eq!(
            status.contains(" 200 "),
            should_be_accepted,
            "v1.{version}: the crate says accepted={should_be_accepted} but the daemon \
             said {status:?} {body:?}"
        );
    }
}

/// The default endpoint is this platform's own local daemon, and only that.
///
/// The literal is written out per platform rather than read back from
/// [`DEFAULT_ENDPOINT`] alone, because a default that quietly became the Unix
/// path on every target is the exact regression this file is being fixed for:
/// it compiles, and then every live test fails against a real Windows daemon
/// because nothing listens at `/var/run/docker.sock` there.
#[test]
fn the_default_endpoint_is_the_local_daemons_own() {
    #[cfg(unix)]
    {
        assert_eq!(DEFAULT_ENDPOINT, "/var/run/docker.sock");
        let home = Path::new("/home/test-user");
        let candidates = [
            PathBuf::from("/var/run/docker.sock"),
            home.join(".docker/run/docker.sock"),
            PathBuf::from("/run/docker.sock"),
        ];
        assert_eq!(
            select_unix_endpoint(Some(home), |path| path == candidates[1].as_path()),
            candidates[1],
            "the Docker Desktop socket is selected when it is the existing candidate"
        );
        assert_eq!(
            select_unix_endpoint(Some(home), |path| path == candidates[2].as_path()),
            candidates[2],
            "the final fallback is selected when earlier candidates do not exist"
        );
        assert_eq!(
            select_unix_endpoint(Some(home), |_| false),
            candidates[0],
            "the first candidate remains the fallback when no socket exists"
        );
        let selected = default_unix_endpoint();
        assert!(
            selected.as_path() == Path::new("/var/run/docker.sock")
                || selected.as_path() == Path::new("/run/docker.sock")
                || selected.ends_with(".docker/run/docker.sock"),
            "unexpected Unix default endpoint: {}",
            selected.display()
        );
        assert_eq!(endpoint_from(None), selected);
    }
    #[cfg(windows)]
    {
        assert_eq!(DEFAULT_ENDPOINT, r"\\.\pipe\docker_engine");
        assert_eq!(endpoint_from(None), PathBuf::from(DEFAULT_ENDPOINT));
    }
}

/// Either slash direction for a named pipe normalizes to the canonical Windows form.
#[test]
fn windows_pipe_endpoint_spellings_normalize_to_backslashes() {
    for input in [
        r"\\.\pipe/docker_engine",
        "//./pipe/docker_engine",
        r"\\./pipe/docker_engine",
        r"\\.\pipe/docker_engine",
    ] {
        let units = normalize_pipe_separators(input.encode_utf16());
        let normalized = String::from_utf16(&units).expect("valid UTF-16 input stays valid");
        assert_eq!(normalized, r"\\.\pipe\docker_engine", "input: {input:?}");
    }
}

/// `NEOTALES_DOCKER_SOCKET` decides the endpoint when it is set.
///
/// Pinned per platform rather than only checked against [`DEFAULT_ENDPOINT`],
/// for the same reason: an override that resolved to the default would leave
/// every live test pointed at the wrong daemon with nothing failing.
#[test]
fn the_environment_override_decides_the_endpoint() {
    let overridden = OsString::from(if cfg!(windows) {
        r"\\.\pipe\neotales_test_override"
    } else {
        "/tmp/neotales-test-override.sock"
    });
    assert_eq!(
        endpoint_from(Some(overridden.clone())),
        PathBuf::from(&overridden),
        "an override must be used verbatim, not merged with or replaced by the default"
    );
    assert_ne!(
        endpoint_from(Some(overridden)),
        endpoint_from(None),
        "an override must not resolve to the default"
    );
    #[cfg(windows)]
    assert_eq!(
        endpoint_from(Some(OsString::from("//./pipe/neotales_override"))),
        PathBuf::from(r"\\.\pipe\neotales_override"),
        "forward slashes from an override normalize to native Windows separators"
    );
}

/// The probe sends one `GET`, and the version prefix travels in the path.
///
/// This is the request both transports now send, and it is the request whose
/// version prefix is the subject of the file: if the prefix moved out of the
/// path and into a header, or if a transport added its own line, the daemon
/// would stop gating this client and the live tests would start passing for the
/// wrong reason.
#[test]
fn the_request_carries_the_version_prefix_in_its_path() {
    let request = build_request("/v1.55/_ping");
    assert_eq!(
        request,
        concat!(
            "GET /v1.55/_ping HTTP/1.1\r\n",
            "Host: docker\r\n",
            "User-Agent: api-version-ceiling-probe\r\n",
            "Accept: */*\r\n",
            "Connection: close\r\n",
            "\r\n",
        ),
        "the exact bytes both transports write"
    );
    assert!(
        !request.to_ascii_lowercase().contains("api-version:"),
        "the version belongs in the path; a header would not be gated: {request:?}"
    );
    assert_eq!(
        request.matches("\r\n").count(),
        6,
        "the request line and four headers, then the blank line: {request:?}"
    );
}

/// The Unix response helper splits at its first terminator. A truncated head is
/// an error; a body may itself contain another terminator.
#[test]
fn a_response_is_split_at_its_first_header_terminator() {
    let (status, body) = parse_response(b"HTTP/1.1 400 Bad Request\r\nApi-Version: 1.55\r\n\r\n")
        .expect("a complete response");
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
    assert_eq!(body, "", "nothing follows the terminator");

    // A body is free to contain the terminator, so the split is at the *first*
    // one and not at the last.
    let (status, body) =
        parse_response(b"HTTP/1.1 200 OK\r\n\r\n\r\na second part\r\n\r\n").expect("a body");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(body, "\r\na second part\r\n\r\n");

    // Not UTF-8, because the split happens on bytes and must not depend on the
    // daemon's charset for the ASCII status line above it.
    let (status, _) =
        parse_response(b"HTTP/1.1 200 OK\r\nX-Note: \xff\xfe\r\n\r\n").expect("a non-UTF-8 header");
    assert_eq!(status, "HTTP/1.1 200 OK");

    // No terminator at all. Reported with the size rather than silently read as
    // an empty body, which would read as a 0-byte 200 to the callers above.
    let incomplete = b"HTTP/1.1 200 OK\r\n";
    let error = parse_response(incomplete).expect_err("an unterminated response");
    assert!(
        error.contains("no header terminator"),
        "an unterminated response must say so: {error}"
    );
    assert!(
        error.contains(&format!("{}-byte", incomplete.len())),
        "an unterminated response must report how much arrived: {error}"
    );

    // Nothing at all, and a terminator with no status line: both errors, never
    // an empty status that every `status.contains(" 200 ")` would call a miss.
    assert!(parse_response(b"").is_err());
    assert!(parse_response(b"\r\n\r\n").is_err());
}

#[test]
fn framed_content_length_response_completes_without_pipe_eof() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    assert_eq!(
        parse_framed_response(response).expect("valid framing"),
        Some(("HTTP/1.1 200 OK".to_owned(), "hello".to_owned()))
    );
    assert_eq!(
        parse_framed_response(&response[..response.len() - 1]).unwrap(),
        None
    );
    assert!(
        parse_framed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .unwrap()
            .is_none()
    );
}

#[test]
fn framed_chunked_response_decodes_chunks_and_trailers() {
    let response = b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-Final: yes\r\n\r\n";
    assert_eq!(
        parse_framed_response(response).expect("valid framing"),
        Some(("HTTP/1.1 400 Bad Request".to_owned(), "body".to_owned()))
    );
    assert!(
        parse_framed_response(&response[..response.len() - 2])
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_ambiguous_truncated_and_trailing_responses_fail_closed() {
    let cases: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 nope\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nq\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-trailer\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxextra",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
        b"HTTP/1.1 200 OK\r\nBad Header\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Note: bad\x01value\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 184467440737095516160\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n",
    ];
    for response in cases {
        assert!(
            parse_framed_response(response).is_err(),
            "accepted {response:?}"
        );
    }
}

#[test]
fn response_header_and_body_sizes_are_bounded() {
    let mut oversized_header = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    oversized_header.resize(MAX_RESPONSE_HEADER_SIZE + 1, b'a');
    assert!(parse_framed_response(&oversized_header).is_err());

    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_RESPONSE_SIZE}\r\n\r\n");
    assert!(parse_framed_response(response.as_bytes()).is_err());
}
