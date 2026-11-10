//! Live identity-key lanes: ECDSA and agent authentication against the real
//! pieces.
//!
//! Run explicitly with:
//!
//! ```text
//! cargo test -p neotales-ssh --test openssh_identities -- --ignored --test-threads=1
//! ```
//!
//! # Why this file exists
//!
//! `PublicKeySigner` and `OpenSshPrivateKey` were closed enums carrying
//! `Ed25519` and `Rsa` and nothing else, so a downstream crate could not name an
//! ECDSA identity or an agent-held key:
//!
//! ```text
//! error[E0599]: no variant, associated function, or constant named `agent` found
//!               for enum `PublicKeySigner` in the current scope
//! ```
//!
//! A unit test can prove the variants exist and that the wire encodings are
//! right. Only a real peer can prove the thing that matters, which is that a
//! server *accepts* the result. So this file runs:
//!
//! * a real `sshd`, with a real `ecdsa-sha2-nistp256` key in its
//!   `AuthorizedKeysFile`, and the key parsed by this crate's own
//!   `openssh-key-v1` reader and signed by this crate's own `EcdsaSigner`;
//! * a real `ssh-agent`, holding a real key, asked for a real signature, and
//!   the result authenticated against that same `sshd`.
//!
//! Nothing below the key files and the two sockets is stubbed. The private
//! scalar really does come out of the container this crate parses, and the
//! signature really is produced by whichever key holder the test names.
//!
//! # Where the programs come from
//!
//! `sshd`, `ssh-keygen`, `ssh-agent` and `ssh-add` are resolved at run time by
//! `openssh_tools`, not named by absolute path. This file used to hardcode
//! `/usr/sbin/sshd`, `/usr/bin/ssh-agent` and `/usr/bin/ssh-add`, which is a
//! list of where those files happen to be on a Linux box with a merged `/usr`
//! and not a statement about any platform. `openssh_interop.rs` and
//! `openssh_channels.rs` named the same server `/usr/bin/sshd`, so one area
//! carried two spellings of one binary.
//!
//! **A missing prerequisite is a failure, not a skip.** The error names the
//! program, every location that was searched, and the package that provides it.
//! These lanes are evidence for the interoperability claim in
//! `docs/support-matrix.md`, so a lane that turned itself green because it never
//! started a peer would make that claim unfalsifiable.
//!
//! The direct ECDSA lane runs on Windows, Linux, and macOS. Agent-backed lanes
//! are Unix-only because this crate exposes Unix-domain agent sockets and does
//! not implement Windows' named-pipe agent protocol.

#![allow(missing_docs)]

mod openssh_tools;

use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use neotales_ssh::ClientConfig;
#[cfg(unix)]
use neotales_ssh::agent;

#[cfg(unix)]
use neotales_ssh::auth::AgentKeySigner;
use neotales_ssh::auth::{AuthMethodKind, ClientAuthMethod, PublicKeySigner, authenticate_client};
use neotales_ssh::ecdsa_hostkey::EcdsaSigner;
use neotales_ssh::openssh_key::OpenSshPrivateKey;
use neotales_ssh::transport::ClientTransport;

/// How long a lane waits for a peer before failing.
const LANE_DEADLINE: Duration = Duration::from_secs(30);

struct OpenSshServer {
    _child: openssh_tools::temp_dir::ChildGuard,
    directory: openssh_tools::temp_dir::TempDir,
}

fn temporary_directory() -> io::Result<openssh_tools::temp_dir::TempDir> {
    openssh_tools::temp_dir::TempDir::new("neotales-identities")
}

/// A short temporary directory for an `ssh-agent` Unix socket.
///
/// Darwin limits `sockaddr_un.sun_path` to 104 bytes. `TMPDIR` can be deeply
/// nested on macOS, so use `/tmp` there to keep the socket path portable.
#[cfg(unix)]
fn agent_directory() -> io::Result<openssh_tools::temp_dir::TempDir> {
    let root = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    openssh_tools::temp_dir::TempDir::new_in(&root, "na")
}

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

/// Parses a `ssh-keygen` private key with this crate's own container reader.
fn parse_key(path: &Path) -> Result<OpenSshPrivateKey, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.starts_with("Private-key"))
        .collect();
    let decoded = base64_decode(body.trim())?;
    let mut passphrase: [u8; 0] = [];
    Ok(OpenSshPrivateKey::parse(&decoded, &mut passphrase)?)
}

/// The key type an SSH public-key blob names, which is its first SSH string.
fn key_type(blob: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let length = u32::from_be_bytes(
        blob.get(..4)
            .ok_or("the key blob has no length prefix")?
            .try_into()
            .map_err(|_| "the length prefix is four bytes")?,
    );
    let length = usize::try_from(length)?;
    let name = blob
        .get(4..4 + length)
        .ok_or("the key type string is truncated")?;
    Ok(String::from_utf8_lossy(name).into_owned())
}

/// A throwaway `sshd` that will accept the named public key.
fn start_server(authorized_key: &Path) -> Result<OpenSshServer, Box<dyn std::error::Error>> {
    let directory = temporary_directory()
        .map_err(|error| format!("could not create OpenSSH identity test directory: {error}"))?;
    let host_key = directory.join("host_ed25519");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create the host key".into());
    }
    let authorized = directory.join("authorized_keys");
    fs::copy(authorized_key, &authorized)?;

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

    // Wait for the listener rather than returning a server nobody can reach.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(OpenSshServer {
                _child: child,
                directory,
            });
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

/// Connects and handshakes, returning a transport ready for authentication.
fn connect(port: u16) -> Result<ClientTransport<TcpStream>, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(LANE_DEADLINE))?;
    stream.set_write_timeout(Some(LANE_DEADLINE))?;
    Ok(ClientConfig::new().connect(stream, |_key| Ok::<(), ()>(()))?)
}

/// The port the running server is listening on, read back from its config.
fn server_port(server: &OpenSshServer) -> Result<u16, Box<dyn std::error::Error>> {
    let config = fs::read_to_string(server.directory.join("sshd_config"))?;
    let line = config
        .lines()
        .find_map(|line| line.strip_prefix("Port "))
        .ok_or("the generated config has no Port")?;
    Ok(line.trim().parse()?)
}

/// A real `ssh-agent` holding one key, and the socket it listens on.
#[cfg(unix)]
struct TestAgent {
    _child: openssh_tools::temp_dir::ChildGuard,
    socket: PathBuf,
    _directory: openssh_tools::temp_dir::TempDir,
}

#[cfg(unix)]
fn start_agent(key: Option<&Path>) -> Result<TestAgent, Box<dyn std::error::Error>> {
    const SOCKET_PATH_BUDGET: usize = 100;
    let directory = agent_directory()?;
    let socket = directory.join("agent.sock");
    let socket_bytes = socket.as_os_str().as_encoded_bytes().len();
    if socket_bytes >= SOCKET_PATH_BUDGET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "agent socket path is too long ({socket_bytes} bytes; limit is below {SOCKET_PATH_BUDGET}): {}",
                socket.display()
            ),
        )
        .into());
    }
    let agent_program = openssh_tools::ssh_agent()?;
    let add_program = key.map(|_| openssh_tools::ssh_add()).transpose()?;
    let socket_arg = socket.to_str().ok_or("the socket path is not UTF-8")?;
    let mut command = Command::new(agent_program);
    command
        // Keep the agent in this child process. Without `-D`, ssh-agent forks
        // into the background, so killing/waiting for this `Child` would leave
        // the actual signing agent running after the test unlinked its socket.
        .args([
            "-D",
            "-a",
            socket_arg,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = openssh_tools::temp_dir::ChildGuard::new(command.spawn()?);

    // `ssh-agent -a` prints its environment; the socket is the one it was told
    // to bind, so waiting on the path is enough and avoids parsing the banner.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !socket.exists() {
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("the test ssh-agent exited before creating its socket: {status}").into(),
            );
        }
        if Instant::now() > deadline {
            return Err("the test ssh-agent never created its socket".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if let Some(status) = child.try_wait()? {
        return Err(
            format!("the test ssh-agent exited before ssh-add could use it: {status}").into(),
        );
    }
    if let (Some(key), Some(add_program)) = (key, add_program) {
        let added = Command::new(add_program)
            .arg(key)
            .env("SSH_AUTH_SOCK", &socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match added {
            Ok(status) if status.success() => {}
            Ok(_) => {
                if let Some(status) = child.try_wait()? {
                    return Err(format!(
                        "the test ssh-agent exited while loading the key: {status}"
                    )
                    .into());
                }
                return Err("ssh-add refused the key".into());
            }
            Err(error) => {
                if let Some(status) = child.try_wait()? {
                    return Err(format!(
                        "the test ssh-agent exited while loading the key: {status}"
                    )
                    .into());
                }
                return Err(error.into());
            }
        }
    }
    Ok(TestAgent {
        _child: child,
        socket,
        _directory: directory,
    })
}

/// **ECDSA, end to end.** A real `sshd` accepts a signature this crate made with
/// a key this crate parsed.
///
/// The key is generated by `ssh-keygen -t ecdsa`, put in the server's
/// `AuthorizedKeysFile`, read back through `OpenSshPrivateKey::parse`, and
/// signed by `PublicKeySigner::ecdsa`. Every step in between is this crate's
/// own, so a defect in the container reader, the scalar hand-off, or the
/// signature encoding shows up as a refusal by the server rather than as a unit
/// test asserting this crate against itself.
#[test]
#[ignore = "live OpenSSH lane: needs sshd, ssh-keygen, ssh-agent and ssh-add, resolved by openssh_tools; a missing one fails rather than skips"]
fn an_ecdsa_identity_authenticates_against_a_real_sshd() -> Result<(), Box<dyn std::error::Error>> {
    let directory = temporary_directory()?;
    let key = directory.join("id_ecdsa");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ecdsa", "-N", "", "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create an ECDSA key".into());
    }

    // The container this crate has to read.
    let parsed = parse_key(&key)?;
    assert_eq!(key_type(parsed.public_key_blob())?, "ecdsa-sha2-nistp256");
    let secret = parsed
        .ecdsa_secret()
        .ok_or("the parsed key has no ECDSA scalar")?;
    assert_eq!(secret.len(), 32);

    // The server's authorized key and this crate's view of it must agree, or the
    // signature will be made with an identity the server never authorized.
    let authorized = key.with_extension("pub");
    let authorized_blob = base64_decode(
        fs::read_to_string(&authorized)?
            .split_whitespace()
            .nth(1)
            .ok_or("the public key line has no key material")?,
    )?;
    assert_eq!(
        parsed.public_key_blob(),
        authorized_blob.as_slice(),
        "the parsed public key is not the one the server will check"
    );

    let server = start_server(&authorized)?;
    let mut transport = connect(server_port(&server)?)?;
    let signer = EcdsaSigner::from_secret_scalar_bytes(secret)?;
    assert_eq!(signer.public_key_blob()?, parsed.public_key_blob());
    let success = authenticate_client(
        &mut transport,
        openssh_tools::current_user()?,
        &[ClientAuthMethod::public_key(PublicKeySigner::ecdsa(signer))],
        4,
    )?;
    assert_eq!(success.method(), AuthMethodKind::PublicKey);
    Ok(())
}

/// **An agent identity, end to end.** A real `ssh-agent` signs, and a real
/// `sshd` accepts the result.
///
/// This is the case that had no constructor at all. The agent socket is a real
/// `ssh-agent` holding a real key, and the key blob named to
/// [`AgentKeySigner`] is the one the agent advertises, so the lane fails if the
/// signer asks about a different identity or with the wrong flags.
#[test]
#[ignore = "live OpenSSH lane: needs sshd, ssh-keygen, ssh-agent and ssh-add, resolved by openssh_tools; a missing one fails rather than skips"]
#[cfg(unix)]
fn an_agent_identity_authenticates_against_a_real_sshd() -> Result<(), Box<dyn std::error::Error>> {
    let directory = temporary_directory()?;
    let key = directory.join("id_ed25519");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create an Ed25519 key".into());
    }
    let authorized = key.with_extension("pub");
    let agent = start_agent(Some(&key))?;

    // The identity the agent advertises, asked for over the real socket.
    let advertised = {
        let mut client = agent::connect_unix(&agent.socket)?;
        client.identities()?
    };
    assert_eq!(advertised.len(), 1, "the agent holds exactly one key");
    let identity = advertised.first().ok_or("the agent advertised no key")?;
    assert_eq!(key_type(identity.key_blob())?, "ssh-ed25519");

    let server = start_server(&authorized)?;
    let mut transport = connect(server_port(&server)?)?;
    let signer = AgentKeySigner::new(agent::connect_unix(&agent.socket)?, identity.key_blob())?;
    assert_eq!(signer.algorithm(), "ssh-ed25519");
    assert_eq!(signer.flags(), 0);
    let success = authenticate_client(
        &mut transport,
        openssh_tools::current_user()?,
        &[ClientAuthMethod::public_key(PublicKeySigner::agent(signer))],
        4,
    )?;
    assert_eq!(success.method(), AuthMethodKind::PublicKey);
    Ok(())
}

/// **An ECDSA key held by the agent, end to end.** The one combination that
/// needs the agent flag extension as well as the signer variant.
///
/// `AgentClient::sign` used to accept only `ssh-ed25519` and `ssh-rsa`, so an
/// ECDSA identity in an agent was not requestable at all. OpenSSH's
/// `agent_decode_alg` in `ssh-agent.c` maps `SSH_AGENT_RSA_SHA2_256` to
/// `rsa-sha2-256` and returns null for every other key type, which leaves a
/// non-RSA key signing under its own name — so the flags word for ECDSA is
/// zero, and this lane checks that against a real agent and a real server.
#[test]
#[ignore = "live OpenSSH lane: needs sshd, ssh-keygen, ssh-agent and ssh-add, resolved by openssh_tools; a missing one fails rather than skips"]
#[cfg(unix)]
fn an_ecdsa_identity_held_by_an_agent_authenticates_against_a_real_sshd()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = temporary_directory()?;
    let key = directory.join("id_ecdsa");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ecdsa", "-N", "", "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create an ECDSA key".into());
    }
    let authorized = key.with_extension("pub");
    let agent = start_agent(Some(&key))?;

    let advertised = {
        let mut client = agent::connect_unix(&agent.socket)?;
        client.identities()?
    };
    let identity = advertised.first().ok_or("the agent advertised no key")?;
    assert_eq!(key_type(identity.key_blob())?, "ecdsa-sha2-nistp256");

    let signer = AgentKeySigner::new(agent::connect_unix(&agent.socket)?, identity.key_blob())?;
    assert_eq!(signer.algorithm(), "ecdsa-sha2-nistp256");
    assert_eq!(signer.flags(), 0, "a non-RSA agent key needs no SHA-2 flag");

    let server = start_server(&authorized)?;
    let mut transport = connect(server_port(&server)?)?;
    let success = authenticate_client(
        &mut transport,
        openssh_tools::current_user()?,
        &[ClientAuthMethod::public_key(PublicKeySigner::agent(signer))],
        4,
    )?;
    assert_eq!(success.method(), AuthMethodKind::PublicKey);
    Ok(())
}

/// The guard the whole agent variant rests on: an agent that does not hold the
/// key is a failed authentication, not a silent success.
///
/// A variant that fell back to a local key would make this lane pass, which is
/// exactly why it is here: the failure is the property, and a real agent
/// answering `SSH_AGENT_FAILURE` is the cheapest honest demonstration of it.
#[test]
#[ignore = "live OpenSSH lane: needs sshd, ssh-keygen, ssh-agent and ssh-add, resolved by openssh_tools; a missing one fails rather than skips"]
#[cfg(unix)]
fn an_agent_without_the_key_fails_rather_than_falling_back()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = temporary_directory()?;
    let key = directory.join("id_ed25519");
    let generated = Command::new(openssh_tools::ssh_keygen()?)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create an Ed25519 key".into());
    }
    let authorized = key.with_extension("pub");
    // An agent with no keys at all.
    let agent = start_agent(None)?;

    // A key blob for the identity we want, which the agent does not hold.
    let wanted = base64_decode(
        fs::read_to_string(&authorized)?
            .split_whitespace()
            .nth(1)
            .ok_or("the public key line has no key material")?,
    )?;

    let server = start_server(&authorized)?;
    let mut transport = connect(server_port(&server)?)?;
    let signer = AgentKeySigner::new(agent::connect_unix(&agent.socket)?, &wanted)?;
    let outcome = authenticate_client(
        &mut transport,
        openssh_tools::current_user()?,
        &[ClientAuthMethod::public_key(PublicKeySigner::agent(signer))],
        4,
    );
    // Whether this surfaces as the agent refusing or as the server refusing
    // depends on which side gives up first, and both are honest failures. What
    // must not happen is a success, because there is no key anywhere in this
    // process that could have made one.
    assert!(
        outcome.is_err(),
        "an agent holding no key authenticated the client"
    );
    Ok(())
}
