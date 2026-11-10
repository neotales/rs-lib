//! Live interoperability lanes against the system OpenSSH server, for the
//! channel multiplexer.
//!
//! Run explicitly with:
//!
//! ```text
//! cargo test -p neotales-ssh --test openssh_channels -- --ignored --test-threads=1
//! ```
//!
//! # Why this file exists
//!
//! `openssh_interop.rs` covers negotiation and the packet cipher, and stops at
//! the point where a channel could be opened. Everything below that point is
//! what a real `sshd` does that no in-crate test can assert, and two things it
//! does broke `ChannelConnection` outright:
//!
//! * The first payload after `SSH_MSG_USERAUTH_SUCCESS` is a global request,
//!   `hostkeys-00@openssh.com`, message byte 80. `sshd` sends it from
//!   `notify_hostkeys`, which `sshd-session.c` calls immediately before
//!   `do_authenticated`. A multiplexer whose parser has only `SSH_MSG_CHANNEL_*`
//!   arms cannot open a channel against a current OpenSSH at all.
//! * `sshd` allocates session channels by reusing the lowest free identifier on
//!   the connection, so the *second* channel on a connection is confirmed with
//!   the remote identifier the first one used. A multiplexer that refuses a
//!   remote identifier another channel holds can therefore carry exactly one
//!   channel for the life of a connection.
//!
//! Every lane authenticates for real against a throwaway loopback `sshd` using
//! a generated Ed25519 key and drives the crate's own client authentication and
//! channel multiplexer. Nothing below the TCP socket is stubbed.
//!
//! # Why these lanes drive `ChannelConnection` and not `ClientSessions`
//!
//! The channel multiplexer is the layer under test, so most lanes drive it
//! directly. The one lane that needs `exit-status` —
//! `exit_status_after_peer_eof_is_delivered`, at the bottom of this file —
//! goes through `ClientSessions` because that is the API a caller actually
//! uses to run a command and learn its exit code.
//!
//! # Where the programs come from
//!
//! `sshd` and `ssh-keygen` are resolved at run time by `openssh_tools`, not
//! named by absolute path. This file used to hardcode `/usr/bin/sshd`, which
//! does not exist on macOS — the server there is `/usr/sbin/sshd` — so on macOS
//! these lanes failed on the spawn with `No such file or directory (os error
//! 2)`, before any channel code ran. `openssh_identities.rs` named the same
//! server `/usr/sbin/sshd`, so one area carried two spellings of one binary.
//!
//! **A missing prerequisite is a failure, not a skip.** The error names the
//! program, every location that was searched, and the package that provides it.
//! These lanes are evidence for the interoperability claim in
//! `docs/support-matrix.md`, so a lane that turned itself green because it never
//! started a peer would make that claim unfalsifiable.
//!
//! These live lanes run on Linux, macOS, and Windows. The OS-specific tool
//! discovery itself is covered separately by `openssh_discovery.rs`.

#![allow(missing_docs, unreachable_pub)]

mod openssh_tools;

use std::fs;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use neotales_ssh::ClientConfig;
use neotales_ssh::auth::{AuthMethodKind, ClientAuthMethod, PublicKeySigner, authenticate_client};
use neotales_ssh::channel::{ChannelConnection, ChannelEvent, ChannelId, ChannelTransport};
use neotales_ssh::hostkey::{Ed25519PublicKey, Ed25519Signer};
use neotales_ssh::openssh_key::OpenSshPrivateKey;
use neotales_ssh::transport::ClientTransport;

struct OpenSshServer {
    #[cfg(not(target_os = "linux"))]
    _child: openssh_tools::temp_dir::ChildGuard,
    #[cfg(target_os = "linux")]
    _docker: DockerFixture,
    _directory: openssh_tools::temp_dir::TempDir,
}

#[cfg(target_os = "linux")]
struct DockerFixture {
    container: String,
    image: String,
    owner: String,
    container_id: Option<String>,
    image_id: Option<String>,
}

#[cfg(target_os = "linux")]
impl Drop for DockerFixture {
    fn drop(&mut self) {
        let failures = self.cleanup();
        if failures.is_empty() {
            return;
        }
        let message = format!("Docker fixture cleanup failed: {}", failures.join("; "));
        if std::thread::panicking() {
            eprintln!("{message}");
        } else {
            panic!("{message}");
        }
    }
}

#[cfg(target_os = "linux")]
impl DockerFixture {
    fn cleanup(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        let artifacts = [
            (
                "container",
                self.container.as_str(),
                self.container_id.as_ref(),
                false,
            ),
            ("image", self.image.as_str(), self.image_id.as_ref(), true),
        ];
        for (kind, name, expected_id, is_image) in artifacts {
            match inspect_owned_id(kind, name, &self.owner) {
                Ok(None) => {}
                Ok(Some(id)) => {
                    if expected_id.is_some_and(|expected| expected != &id) {
                        failures.push(format!(
                            "refusing to remove {kind} {name}: inspected ID changed"
                        ));
                        continue;
                    }
                    let mut args = if is_image {
                        vec!["image".to_owned(), "rm".to_owned()]
                    } else {
                        vec!["rm".to_owned(), "--force".to_owned()]
                    };
                    args.push(id);
                    match docker(&args) {
                        Ok(output) if output.status.success() => {}
                        Ok(output) => failures.push(format!(
                            "docker {} failed: {}",
                            args.first().map_or("command", String::as_str),
                            String::from_utf8_lossy(&output.stderr).trim()
                        )),
                        Err(error) => failures.push(error.to_string()),
                    }
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        failures
    }
}

#[cfg(target_os = "linux")]
const DOCKER_OWNER_LABEL: &str = "io.neotales.openssh-channel.owner";

#[cfg(target_os = "linux")]
fn docker(args: &[String]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    Ok(Command::new("docker").args(args).output()?)
}

#[cfg(target_os = "linux")]
fn parse_inspected_owned_id(
    kind: &str,
    owner: &str,
    inspected: &str,
) -> Result<String, &'static str> {
    let expected_id = match kind {
        "container" => (64, false),
        "image" => (64, true),
        _ => return Err("unsupported Docker object type"),
    };
    let record = inspected
        .strip_suffix('\n')
        .ok_or("Docker inspect record must end with exactly one newline")?;
    if record.contains(['\n', '\r']) {
        return Err("Docker inspect returned multiple or malformed records");
    }
    let mut fields = record.split('\t');
    let id = fields.next().ok_or("Docker inspect record has no ID")?;
    let label = fields
        .next()
        .ok_or("Docker inspect record has no owner label")?;
    if fields.next().is_some() {
        return Err("Docker inspect record has extra fields");
    }

    let id_hex = if expected_id.1 {
        id.strip_prefix("sha256:")
            .ok_or("Docker image ID is not a sha256 digest")?
    } else {
        id
    };
    if id_hex.len() != expected_id.0 || !id_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Docker inspect returned a malformed ID");
    }
    if label != owner {
        return Err("Docker ownership label mismatch or missing label");
    }
    Ok(id.to_owned())
}

#[cfg(all(test, target_os = "linux"))]
mod docker_inspect_parser_tests {
    use super::parse_inspected_owned_id;

    const OWNER: &str = "0123456789abcdef0123456789abcdef";
    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const IMAGE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_valid_container_and_image_records() {
        assert_eq!(
            parse_inspected_owned_id("container", OWNER, &format!("{CONTAINER_ID}\t{OWNER}\n")),
            Ok(CONTAINER_ID.to_owned())
        );
        assert_eq!(
            parse_inspected_owned_id("image", OWNER, &format!("{IMAGE_ID}\t{OWNER}\n")),
            Ok(IMAGE_ID.to_owned())
        );
    }

    #[test]
    fn rejects_mismatched_and_missing_labels() {
        assert!(
            parse_inspected_owned_id(
                "container",
                OWNER,
                &format!("{CONTAINER_ID}\tother-owner\n")
            )
            .is_err()
        );
        assert!(
            parse_inspected_owned_id("container", OWNER, &format!("{CONTAINER_ID}\t\n")).is_err()
        );
    }

    #[test]
    fn rejects_malformed_ids() {
        assert!(
            parse_inspected_owned_id("container", OWNER, &format!("short\t{OWNER}\n")).is_err()
        );
        assert!(
            parse_inspected_owned_id(
                "container",
                OWNER,
                &format!("{}g\t{OWNER}\n", &CONTAINER_ID[..63])
            )
            .is_err()
        );
        assert!(
            parse_inspected_owned_id("image", OWNER, &format!("{}\t{OWNER}\n", &IMAGE_ID[7..]))
                .is_err()
        );
    }

    #[test]
    fn rejects_multiple_or_malformed_records_and_extra_fields() {
        assert!(
            parse_inspected_owned_id(
                "container",
                OWNER,
                &format!("{CONTAINER_ID}\t{OWNER}\n{CONTAINER_ID}\t{OWNER}\n")
            )
            .is_err()
        );
        assert!(
            parse_inspected_owned_id("container", OWNER, &format!("{CONTAINER_ID}\t{OWNER}\n\n"))
                .is_err()
        );
        assert!(
            parse_inspected_owned_id(
                "container",
                OWNER,
                &format!("{CONTAINER_ID}\t{OWNER}\textra\n")
            )
            .is_err()
        );
        assert!(
            parse_inspected_owned_id("container", OWNER, &format!("{CONTAINER_ID}\t{OWNER}\r\n"))
                .is_err()
        );
    }
}

#[cfg(target_os = "linux")]
fn random_owner_token() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(32);
    for byte in bytes {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

#[cfg(target_os = "linux")]
fn inspect_owned_id(
    kind: &str,
    name: &str,
    owner: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let output = docker(&[
        "inspect".to_owned(),
        "--type".to_owned(),
        kind.to_owned(),
        format!(
            "--format={{{{.Id}}}}{{{{\"\\t\"}}}}{{{{index .Config.Labels \"{DOCKER_OWNER_LABEL}\"}}}}"
        ),
        name.to_owned(),
    ])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let missing = match kind {
            "image" => stderr.contains("No such image:") || stderr.contains("No such object:"),
            "container" => {
                stderr.contains("No such container:") || stderr.contains("No such object:")
            }
            _ => false,
        };
        if missing {
            return Ok(None);
        }
        return Err(format!("could not inspect Docker {kind} {name}: {stderr}").into());
    }
    let inspected = String::from_utf8(output.stdout)?;
    parse_inspected_owned_id(kind, owner, &inspected)
        .map(Some)
        .map_err(|error| {
            format!("Docker returned invalid ID/owner data for {kind} {name}: {error}").into()
        })
}

#[cfg(target_os = "linux")]
fn ensure_absent(kind: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = docker(&[
        "inspect".to_owned(),
        "--type".to_owned(),
        kind.to_owned(),
        name.to_owned(),
    ])?;
    if output.status.success() {
        return Err(format!("refusing pre-existing Docker {kind} collision: {name}").into());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let missing = match kind {
        "image" => stderr.contains("No such image:") || stderr.contains("No such object:"),
        "container" => stderr.contains("No such container:") || stderr.contains("No such object:"),
        _ => false,
    };
    if !missing {
        return Err(format!("could not check Docker {kind} collision for {name}: {stderr}").into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn checked_docker(args: &[String]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let output = docker(args)?;
    if !output.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            args.first().map_or("command", String::as_str),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn mapped_loopback_port(container: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let output = checked_docker(&["port".to_owned(), container.to_owned(), "22/tcp".to_owned()])?;
    let mapping = String::from_utf8(output.stdout)?;
    let address: SocketAddr = mapping
        .trim()
        .parse()
        .map_err(|error| format!("invalid Docker SSH port mapping {mapping:?}: {error}"))?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(format!("Docker SSH port is not a nonzero loopback mapping: {address}").into());
    }
    Ok(address.port())
}

#[cfg(target_os = "linux")]
fn fixture_directory() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if !manifest.is_absolute() {
        return Err("CARGO_MANIFEST_DIR must be absolute for the Docker bind mount".into());
    }
    let workspace = manifest.join("workspace");
    fs::create_dir_all(&workspace)?;
    if !workspace.is_dir() {
        return Err("CARGO_MANIFEST_DIR/workspace is not a directory".into());
    }
    Ok(workspace)
}

#[cfg(target_os = "linux")]
fn docker_fixture(
    public_key: &Path,
) -> Result<(DockerFixture, u16, Ed25519PublicKey), Box<dyn std::error::Error>> {
    let owner = random_owner_token()?;
    let image = format!("neotales-ssh-channel-fixture-debian:test-{owner}");
    let container = format!("neotales-ssh-channel-{owner}");
    ensure_absent("image", &image)?;
    ensure_absent("container", &container)?;
    let mut fixture = DockerFixture {
        container,
        image,
        owner,
        container_id: None,
        image_id: None,
    };

    build_and_run_fixture(&mut fixture, public_key)?;
    let port = mapped_loopback_port(&fixture.container)?;
    let host_key = fixture_host_key(&fixture.container)?;
    await_pinned_handshake(port, host_key)?;
    Ok((fixture, port, host_key))
}

#[cfg(target_os = "linux")]
fn build_and_run_fixture(
    fixture: &mut DockerFixture,
    public_key: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eng/ci/openssh-channel-fixture-debian")
        .canonicalize()?;
    if public_key.to_string_lossy().contains(',') {
        return Err("Docker bind-mount source path cannot contain a comma".into());
    }
    checked_docker(&[
        "build".to_owned(),
        "--label".to_owned(),
        format!("{DOCKER_OWNER_LABEL}={}", fixture.owner),
        "--tag".to_owned(),
        fixture.image.clone(),
        fixture_path.to_string_lossy().into_owned(),
    ])?;
    fixture.image_id = inspect_owned_id("image", &fixture.image, &fixture.owner)?;
    if fixture.image_id.is_none() {
        return Err("Docker build succeeded but the owned image could not be inspected".into());
    }
    checked_docker(&[
        "run".to_owned(),
        "--detach".to_owned(),
        "--name".to_owned(),
        fixture.container.clone(),
        "--label".to_owned(),
        format!("{DOCKER_OWNER_LABEL}={}", fixture.owner),
        "--publish".to_owned(),
        "127.0.0.1::22/tcp".to_owned(),
        "--mount".to_owned(),
        format!(
            "type=bind,src={},dst=/run/openssh-channel-fixture/authorized_keys,readonly",
            public_key.display()
        ),
        fixture.image.clone(),
    ])?;
    fixture.container_id = inspect_owned_id("container", &fixture.container, &fixture.owner)?;
    if fixture.container_id.is_none() {
        return Err("Docker run succeeded but the owned container could not be inspected".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fixture_host_key(container: &str) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let key_args = [
        "exec".to_owned(),
        container.to_owned(),
        "ssh-keygen".to_owned(),
        "-y".to_owned(),
        "-f".to_owned(),
        "/etc/ssh/ssh_host_ed25519_key".to_owned(),
    ];
    loop {
        let output = docker(&key_args)?;
        if output.status.success() {
            return ed25519_public_key(std::str::from_utf8(&output.stdout)?);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Docker OpenSSH fixture host key was unavailable within 15 seconds: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
fn await_pinned_handshake(
    port: u16,
    host_key: Ed25519PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_readiness_error = String::from("connection was refused");
    loop {
        let probe =
            TcpStream::connect_timeout(&address, Duration::from_millis(250)).and_then(|stream| {
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                Ok(stream)
            });
        if let Ok(stream) = probe {
            let mut mismatched_key = false;
            match ClientConfig::new().connect(stream, |key| {
                if *key == host_key {
                    Ok(())
                } else {
                    mismatched_key = true;
                    Err("server Ed25519 host key did not match the Docker-pinned key")
                }
            }) {
                Ok(_transport) => break,
                Err(error) if mismatched_key => return Err(error.into()),
                Err(error) => last_readiness_error = error.to_string(),
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Docker OpenSSH fixture did not complete a pinned SSH handshake within 15 seconds: {last_readiness_error}"
                )
                .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn ed25519_public_key(text: &str) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
    let mut fields = text.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return Err("expected an ssh-ed25519 public key".into());
    }
    let encoded = fields.next().ok_or("public key has no base64 blob")?;
    let blob = base64_decode(encoded)?;
    Ok(Ed25519PublicKey::from_blob(&blob)?)
}

/// Decodes one layer of standard base64, which is all `ssh-keygen` emits.
fn base64_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = TABLE
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("invalid base64 in the generated key")?;
        let value = u32::try_from(value).expect("a base64 index fits a u32");
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Reads the 32-byte Ed25519 seed out of a generated private key.
///
/// This parses the key with the crate's own `openssh-key-v1` reader rather than
/// duplicating the format, so a regression in that reader shows up here as a
/// failure to reach the server rather than as a silent divergence.
fn ed25519_seed(key: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let text = fs::read_to_string(key)?;
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.starts_with("Private-key"))
        .collect();
    let decoded = base64_decode(body.trim())?;
    let mut passphrase: [u8; 0] = [];
    match OpenSshPrivateKey::parse(&decoded, &mut passphrase)? {
        OpenSshPrivateKey::Ed25519 { seed, .. } => Ok(*seed),
        OpenSshPrivateKey::Ecdsa { .. } | OpenSshPrivateKey::Rsa { .. } => {
            Err("the generated key is not Ed25519".into())
        }
    }
}

/// How long a lane waits for a peer that has gone quiet before failing.
const LANE_DEADLINE: Duration = Duration::from_secs(30);

/// Start a throwaway `sshd` and complete a real public-key authentication.
#[cfg(not(target_os = "linux"))]
fn start_authenticated_server()
-> Result<(OpenSshServer, ClientTransport<TcpStream>), Box<dyn std::error::Error>> {
    let directory = openssh_tools::temp_dir::TempDir::new("neotales-channels")
        .map_err(|error| format!("could not create OpenSSH channel test directory: {error}"))?;
    let host_key = directory.join("host_ed25519");
    let user_key = directory.join("id_ed25519");
    for key in [&host_key, &user_key] {
        let generated = Command::new(openssh_tools::ssh_keygen()?)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !generated.status.success() {
            return Err("ssh-keygen could not create a temporary key".into());
        }
    }
    let authorized = directory.join("authorized_keys");
    fs::copy(user_key.with_extension("pub"), &authorized)?;
    let expected_host_key =
        ed25519_public_key(&fs::read_to_string(host_key.with_extension("pub"))?)?;

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let config = directory.join("sshd_config");
    fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {}\n\
             PidFile {}\n\
             UsePAM no\n\
             UseDNS no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             PubkeyAuthentication yes\n\
             AuthorizedKeysFile {}\n\
             PermitRootLogin no\n\
             StrictModes no\n\
             MaxAuthTries 100\n\
             LoginGraceTime 60\n\
             LogLevel VERBOSE\n",
            host_key.display(),
            directory.join("sshd.pid").display(),
            authorized.display(),
        ),
    )?;
    let mut command = Command::new(openssh_tools::sshd()?);
    command
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = openssh_tools::temp_dir::ChildGuard::spawn_tree(&mut command)?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.set_read_timeout(Some(LANE_DEADLINE))?;
            stream.set_write_timeout(Some(LANE_DEADLINE))?;
            let transport = authenticated_transport(
                stream,
                &user_key,
                openssh_tools::current_user()?,
                expected_host_key,
            )?;
            return Ok((
                OpenSshServer {
                    _child: child,
                    _directory: directory,
                },
                transport,
            ));
        }
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("the throwaway sshd exited before becoming reachable: {status}").into(),
            );
        }
        if Instant::now() > deadline {
            return Err("the throwaway sshd did not become reachable".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Linux uses the repository's disposable Docker OpenSSH fixture; other hosts
/// retain their existing locally spawned `sshd` setup above.
#[cfg(target_os = "linux")]
fn start_authenticated_server()
-> Result<(OpenSshServer, ClientTransport<TcpStream>), Box<dyn std::error::Error>> {
    let directory =
        openssh_tools::temp_dir::TempDir::new_in(&fixture_directory()?, "neotales-channels")
            .map_err(|error| format!("could not create OpenSSH channel test directory: {error}"))?;
    let user_key = directory.join("id_ed25519");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&user_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create a temporary key".into());
    }
    let (docker, port, host_key) = docker_fixture(&user_key.with_extension("pub"))?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(LANE_DEADLINE))?;
    stream.set_write_timeout(Some(LANE_DEADLINE))?;
    let transport = authenticated_transport(stream, &user_key, "channeltest", host_key)?;
    Ok((
        OpenSshServer {
            _docker: docker,
            _directory: directory,
        },
        transport,
    ))
}

fn authenticated_transport(
    stream: TcpStream,
    user_key: &Path,
    username: impl AsRef<str>,
    expected_host_key: Ed25519PublicKey,
) -> Result<ClientTransport<TcpStream>, Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(LANE_DEADLINE))?;
    stream.set_write_timeout(Some(LANE_DEADLINE))?;
    let mut transport = ClientConfig::new().connect(stream, |key| {
        if *key == expected_host_key {
            Ok(())
        } else {
            Err("server Ed25519 host key did not match the pinned key")
        }
    })?;
    let mut seed = ed25519_seed(user_key)?;
    let signer = PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut seed));
    let success = authenticate_client(
        &mut transport,
        username.as_ref(),
        &[ClientAuthMethod::public_key(signer)],
        4,
    )?;
    assert_eq!(success.method(), AuthMethodKind::PublicKey);
    Ok(transport)
}

/// Dispatches until the given session is confirmed, failing on a budget.
fn await_open(
    channels: &mut ChannelConnection<ClientTransport<TcpStream>>,
    session: ChannelId,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + LANE_DEADLINE;
    loop {
        if Instant::now() > deadline {
            return Err("the session was never confirmed".into());
        }
        match channels.dispatch_one()? {
            ChannelEvent::Opened(id) if id == session => return Ok(()),
            // A global request is surfaced by the multiplexer; this lane has no
            // policy for one, so it is answered the way RFC 4254 §4 requires
            // and reading continues.
            ChannelEvent::GlobalRequest { want_reply, .. } => {
                channels.refuse_global_request(want_reply)?;
            }
            other => return Err(format!("unexpected event before Opened: {other:?}").into()),
        }
    }
}

/// Runs the close handshake for one session and reports its final state.
fn close_session(
    channels: &mut ChannelConnection<ClientTransport<TcpStream>>,
    session: ChannelId,
) -> Result<(), Box<dyn std::error::Error>> {
    channels.send_close(session)?;
    let deadline = Instant::now() + LANE_DEADLINE;
    loop {
        if Instant::now() > deadline {
            return Err("the server never closed the session".into());
        }
        match channels.dispatch_one()? {
            ChannelEvent::Close { channel } if channel == session => return Ok(()),
            ChannelEvent::GlobalRequest { want_reply, .. } => {
                channels.refuse_global_request(want_reply)?;
            }
            // A session that was never asked to do anything produces no data,
            // but `SSH_MSG_CHANNEL_EOF` and an early close are both legal here.
            ChannelEvent::Eof { .. } | ChannelEvent::Data { .. } => {}
            other => return Err(format!("unexpected event while closing: {other:?}").into()),
        }
    }
}

/// **Wall 1, measured.** The first payload after authentication is byte 80
/// carrying `hostkeys-00@openssh.com`.
///
/// This is the raw measurement the tolerance contract is built on. The bytes
/// are decoded by hand rather than by this crate's parser, so the assertion is
/// about the wire and not about the implementation under test.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn the_first_payload_after_authentication_is_the_hostkeys_global_request()
-> Result<(), Box<dyn std::error::Error>> {
    let (_server, transport) = start_authenticated_server()?;
    let mut channels = ChannelConnection::new(transport);
    let raw = channels
        .transport_mut()
        .read_channel_payload()
        .map_err(|()| "the first post-authentication payload could not be read")?;
    assert_eq!(
        raw.first().copied(),
        Some(80),
        "the first payload after authentication is not SSH_MSG_GLOBAL_REQUEST: {raw:?}"
    );
    let name_length = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    let name = raw
        .get(5..5 + name_length)
        .ok_or("the global request name is truncated")?;
    assert_eq!(name, b"hostkeys-00@openssh.com");
    assert_eq!(
        raw.get(5 + name_length).copied(),
        Some(0),
        "sshd sets want reply to zero for hostkeys-00"
    );

    // The same connection still opens and confirms a channel, which is what
    // could not happen before: `parse_message` had nine `SSH_MSG_CHANNEL_*`
    // arms and a fallback of `UnexpectedMessage`, so message 80 killed it.
    channels.open_channel(0, b"session", &[])?;
    await_open(&mut channels, 0)?;
    close_session(&mut channels, 0)?;
    Ok(())
}

/// **Wall 1, end to end.** The global request is answered and a session opens.
///
/// A current `sshd` sends the global request as the first payload and follows
/// it with `SSH_MSG_DEBUG` traffic about the authorized-keys file it just read.
/// All of it is connection-level and has to be tolerated, or no channel can be
/// opened at all.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn a_session_channel_opens_against_a_current_openssh_server()
-> Result<(), Box<dyn std::error::Error>> {
    let (_server, transport) = start_authenticated_server()?;
    let mut channels = ChannelConnection::new(transport);
    channels.open_channel(0, b"session", &[])?;
    await_open(&mut channels, 0)?;
    let state = channels.channel(0).ok_or("the session is missing")?;
    assert!(state.remote_id().is_some());
    // Whether the closed channel is *dropped* is the other claim this file
    // covers, and it is asserted by the lanes below rather than here.
    close_session(&mut channels, 0)?;
    Ok(())
}

/// **Wall 1, tolerating `SSH_MSG_IGNORE` from a real server.** RFC 4253 §11.2:
/// "All implementations MUST understand (and ignore) this message at any time."
///
/// A real `sshd` has to decrypt and discard each one, so this lane is also a
/// packet-cipher exercise in the client-to-server direction, and it interleaves
/// them with a real channel open so the mid-stream case is covered.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn ignored_packets_around_a_real_channel_open_are_tolerated()
-> Result<(), Box<dyn std::error::Error>> {
    let (_server, mut transport) = start_authenticated_server()?;
    // `SSH_MSG_IGNORE` with no data, RFC 4253 §11.2. 256 of them, which is also
    // more than enough to cross a packet-nonce boundary in one direction.
    for _ in 0..256 {
        transport.write_payload(&[2])?;
    }
    let mut channels = ChannelConnection::new(transport);
    channels.open_channel(0, b"session", &[])?;
    await_open(&mut channels, 0)?;
    close_session(&mut channels, 0)?;
    Ok(())
}

/// **Wall 2, end to end.** Three sequential channels on one connection, and a
/// fourth after a `CLOSE`.
///
/// This is the case that failed with
/// `SSH session channel error: SSH channel identifier is already active` on the
/// second request, because OpenSSH reuses the lowest free session identifier on
/// a connection and the multiplexer refused a remote identifier it had already
/// recorded. The remote identifier is asserted to be the same on every round:
/// that is what makes this a parity check rather than a change detector, since a
/// multiplexer that minted its own remote numbers would pass a weaker form.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn three_sequential_channels_and_a_fourth_after_a_close_all_work()
-> Result<(), Box<dyn std::error::Error>> {
    const ROUNDS: usize = 4;
    let (_server, transport) = start_authenticated_server()?;
    let mut channels = ChannelConnection::new(transport);
    let mut remote_identifiers = Vec::new();
    let mut retired_after = Vec::new();
    for round in 0..ROUNDS {
        let session = channels.allocate_channel_id()?;
        channels.open_channel(session, b"session", &[])?;
        await_open(&mut channels, session)?;
        remote_identifiers.push(
            channels
                .channel(session)
                .and_then(|state| state.remote_id()),
        );
        close_session(&mut channels, session)?;
        assert!(
            channels.channel(session).is_none(),
            "round {round} left the session in the table"
        );
        retired_after.push(channels.closed_channel_count());
        assert_eq!(
            channels.channel_count(),
            0,
            "round {round} left a live channel behind"
        );
    }
    // One retirement per round, none forgotten.
    assert_eq!(retired_after, vec![1, 2, 3, 4]);
    // The server reuses the lowest free session identifier, so all four were
    // confirmed with the same remote identifier. This is the specific reuse
    // that used to be refused.
    let first = remote_identifiers[0];
    assert!(first.is_some(), "no remote identifier was recorded");
    for (round, identifier) in remote_identifiers.iter().enumerate() {
        assert_eq!(
            *identifier, first,
            "round {round} came back with a different remote identifier"
        );
    }
    Ok(())
}

/// A channel that is dropped is not dropped early, against a real server.
///
/// The lane asks a real `sshd` to produce a long stream of output, waits for the
/// first data packet, and only then sends its own `SSH_MSG_CHANNEL_CLOSE`,
/// without ever sending `SSH_MSG_CHANNEL_EOF` first — which RFC 4254 §5.3
/// explicitly allows: "A party MAY send `SSH_MSG_CHANNEL_CLOSE` without having
/// sent or received `SSH_MSG_CHANNEL_EOF`." The server is still producing output
/// at that moment, so its `SSH_MSG_CHANNEL_DATA` genuinely arrives after our
/// `CLOSE` and before its own.
///
/// Reaping on the local close alone would discard that data. RFC 4254 §5.3 asks
/// for the opposite: "It is RECOMMENDED that all data sent before this message
/// be delivered to the actual destination." A `CLOSE` we sent says nothing about
/// what the peer may still send us, and conflating the two is the mistake this
/// lane exists to catch.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn a_channel_survives_our_close_until_the_peers_close_arrives()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::session::{ClientSessions, SessionEvent};
    let (_server, transport) = start_authenticated_server()?;
    let mut sessions = ClientSessions::new(transport);
    let session = sessions.open_session()?;
    let deadline = Instant::now() + LANE_DEADLINE;
    while !matches!(sessions.dispatch_one()?, SessionEvent::Opened { .. }) {
        if Instant::now() > deadline {
            return Err("the session was never confirmed".into());
        }
    }
    // A command with more output than one window, so the server has packets in
    // flight when our CLOSE lands.
    // Emit more than 4 MiB even on Windows' `cmd.exe`, whose per-line output
    // is comparatively small. This exceeds the commonly advertised 2 MiB SSH
    // channel window so data remains queued when our first local CLOSE arrives.
    #[cfg(windows)]
    let command = b"cmd.exe /d /c \"for /L %i in (1,1,100000) do @echo 0123456789012345678901234567890123456789\"".as_slice();
    #[cfg(not(windows))]
    let command = b"yes channel-data".as_slice();
    sessions.request_exec(session, command, true)?;

    // Wait for the first data packet, then close our side immediately, with no
    // EOF first.
    let deadline = Instant::now() + LANE_DEADLINE;
    loop {
        if Instant::now() > deadline {
            return Err("the command produced no output".into());
        }
        match sessions.dispatch_one()? {
            SessionEvent::Data { session: id, data } if id == session => {
                assert!(!data.is_empty());
                break;
            }
            SessionEvent::Close { .. } => return Err("the command finished too fast".into()),
            _ => {}
        }
    }
    sessions.connection_mut().send_close(session)?;
    {
        let connection = sessions.connection();
        assert!(
            connection
                .channel(session)
                .is_some_and(|state| state.local_close_sent()),
            "the channel is not addressable after our own close"
        );
        assert_eq!(
            connection.channel_count(),
            1,
            "one side has not closed, so the channel must be retained"
        );
    }

    // Keep reading. Every further data packet is one the server sent *after* our
    // CLOSE and before its own, and it must be delivered rather than dropped.
    let mut data_after_our_close = 0_usize;
    let mut closed = false;
    let deadline = Instant::now() + LANE_DEADLINE;
    while !closed {
        if Instant::now() > deadline {
            return Err("the server never closed the session".into());
        }
        match sessions.dispatch_one()? {
            SessionEvent::Data { session: id, data } if id == session => {
                data_after_our_close += data.len();
            }
            SessionEvent::Close { session: id } if id == session => closed = true,
            // The exit-status request after the server's EOF is delivered; see
            // `exit_status_after_peer_eof_is_delivered`. It arrives after the
            // close handshake, so it cannot affect what this lane measures.
            _ => {}
        }
    }
    assert!(
        data_after_our_close > 0,
        "the server sent nothing after our close, so the in-flight case was not \
         actually exercised"
    );
    {
        let connection = sessions.connection();
        assert_eq!(connection.channel_count(), 0, "both sides closed");
        assert!(connection.channel(session).is_none());
        assert!(connection.is_retired_channel(session));
        // The retired identifier is not handed straight back out, so a
        // straggler naming it can be told apart from the next channel.
        assert_ne!(connection.allocate_channel_id()?, session);
    }

    // A straggler for a retired channel is not demonstrated here. A conforming
    // server does not send one, so producing it needs an injection rather than a
    // real peer, and an injected packet after the server has closed the
    // connection races the server's own `SSH_MSG_DISCONNECT` on a blocking read.
    // `channel_lifetime::a_data_message_for_a_dropped_channel_is_reported_not_
    // rerouted` does that injection deterministically.

    Ok(())
}

/// The same, with the ignorable packets *between* two real channels rather than
/// before the first. A peer is entitled to send them at any point, and a client
/// that treats one as fatal is one a server can break.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn ignored_packets_between_two_channels_do_not_break_the_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (_server, transport) = start_authenticated_server()?;
    // `ChannelConnection` owns the transport, so the ignorable packets go on
    // the multiplexer itself. It exposes the serialized transport for exactly
    // this: a bounded packet on the same connection between two channel uses.
    let mut channels = ChannelConnection::new(transport);
    for _ in 0..128 {
        channels
            .transport_mut()
            .write_channel_payload(&[2])
            .map_err(|()| "an ignorable packet could not be written")?;
    }
    channels.open_channel(0, b"session", &[])?;
    await_open(&mut channels, 0)?;
    close_session(&mut channels, 0)?;

    // The connection is still live after the first channel closed, which is
    // itself the Wall 2 property: before the fix, a second channel on this
    // connection was refused with "SSH channel identifier is already active".
    for _ in 0..128 {
        channels
            .transport_mut()
            .write_channel_payload(&[2])
            .map_err(|()| "an ignorable packet could not be written")?;
    }
    let second = channels.allocate_channel_id()?;
    channels.open_channel(second, b"session", &[])?;
    await_open(&mut channels, second)?;
    close_session(&mut channels, second)?;
    assert_eq!(channels.channel_count(), 0);
    Ok(())
}

/// **The fix for the ticketed defect.** OpenSSH sends
/// `SSH_MSG_CHANNEL_EOF` and *then* the `exit-status` channel request on a
/// finished command; RFC 4254 §6.10 says the status is sent that way, and §5.3
/// says "the channel remains open after this message".
///
/// Before the fix, `apply_request` refused a channel request once
/// `remote_eof_received` was set, so the request was rejected and the command's
/// exit status was lost. Now `exit-status` and `exit-signal` are the two
/// requests RFC 4254 §6.10 defines as arriving after EOF, and both are
/// delivered to the caller.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn exit_status_after_peer_eof_is_delivered() -> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::session::{ClientSessions, SessionEvent};
    let (_server, transport) = start_authenticated_server()?;
    let mut sessions = ClientSessions::new(transport);

    for expected_status in [3, 0] {
        let session = sessions.open_session()?;
        let deadline = Instant::now() + LANE_DEADLINE;
        while !matches!(sessions.dispatch_one()?, SessionEvent::Opened { .. }) {
            if Instant::now() > deadline {
                return Err("the session was never confirmed".into());
            }
        }
        // `sshd` invokes the account's shell with `-c`; a nested shell adds a
        // quoting layer whose exit status can differ by shell. This is native
        // syntax in both the POSIX test shell and Windows' cmd/PowerShell shells.
        let command = format!("exit {expected_status}");
        sessions.request_exec(session, command.as_bytes(), true)?;
        let mut saw_eof = false;
        let mut exit_status = None;
        let deadline = Instant::now() + LANE_DEADLINE;
        loop {
            if Instant::now() > deadline {
                return Err("the command never produced a status".into());
            }
            match sessions.dispatch_one()? {
                SessionEvent::Eof { .. } => saw_eof = true,
                SessionEvent::ExitStatus { status, .. } => {
                    exit_status = Some(status);
                    break;
                }
                SessionEvent::Close { .. } => break,
                _ => {}
            }
        }
        assert!(saw_eof, "the server's EOF should come before exit-status");
        assert_eq!(
            exit_status,
            Some(expected_status),
            "the caller should see exit code {expected_status}"
        );
    }
    Ok(())
}
