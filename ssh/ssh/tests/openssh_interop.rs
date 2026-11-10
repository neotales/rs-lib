//! Opt-in live interoperability smoke test against the system OpenSSH server.
//!
//! Run explicitly with:
//!
//! ```text
//! cargo test -p neotales-ssh --test openssh_interop -- --ignored --test-threads=1
//! ```
//!
//! The tests start a temporary, loopback-only `sshd` with an Ed25519 host key
//! and complete the real client handshake. They do not authenticate or open a
//! channel. What they do cover is negotiation -- and, in the second test, a long
//! run of protected packets in each direction, which is the only way to reach
//! the packet cipher at all.
//!
//! That distinction was the gap. A handshake proves a key exchange agreed; it
//! proves nothing about the nonce a protected packet is sealed with, and a
//! non-conformant AES-GCM nonce survives a handshake perfectly. It did: the
//! construction this crate used produced `IV[0..4] || zeros || sequence_number`
//! instead of the counter OpenSSH actually uses, and a handshake-only lane could
//! not have found it.
//!
//! The run length matters just as much. A one-octet GCM counter repeats the nonce
//! every 256 packets, so a lane that stops at the second packet is structurally
//! blind to that. The lane below sends several hundred.
//!
//! # Where the programs come from
//!
//! `sshd` and `ssh-keygen` are resolved at run time by `openssh_tools`, not
//! named by absolute path. This file used to hardcode `/usr/bin/sshd`, which
//! does not exist on macOS — the server there is `/usr/sbin/sshd` — so on macOS
//! these lanes failed on the spawn with `No such file or directory (os error
//! 2)`, before any protocol code ran.
//!
//! **A missing prerequisite is a failure, not a skip.** The error names the
//! program, every location that was searched, and the package that provides it.
//! These lanes are the evidence behind the interoperability claim in
//! `docs/support-matrix.md`, so a lane that turned itself green because it never
//! started a peer would make that claim unfalsifiable.
//!
//! These live lanes run on Linux, macOS, and Windows. The OS-specific tool
//! discovery itself is covered separately by `openssh_discovery.rs`.

mod openssh_tools;

use std::fmt::Write as _;
use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use neotales_ssh::ClientConfig;

struct OpenSshServer {
    _child: openssh_tools::temp_dir::ChildGuard,
    _directory: openssh_tools::temp_dir::TempDir,
}

/// Write an `sshd_config` for a throwaway server.
///
/// `ciphers` restricts what the server will negotiate, which is how a test forces
/// a particular packet cipher rather than accepting whatever the client prefers.
/// `banner` makes the server send a message of its own accord once the keys are
/// established, which is what gives a test a protected packet to decrypt.
fn write_config(
    directory: &Path,
    port: u16,
    host_key: &Path,
    ciphers: &str,
    banner: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let config = directory.join("sshd_config");
    let mut text = format!(
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
         AuthorizedKeysFile none\n\
         PermitRootLogin no\n\
         StrictModes no\n\
         MaxAuthTries 100000\n\
         LoginGraceTime 60\n\
         LogLevel VERBOSE\n",
        host_key.display(),
        directory.join("sshd.pid").display(),
    );
    if !ciphers.is_empty() {
        let _ = writeln!(text, "Ciphers {ciphers}");
    }
    if let Some(path) = banner {
        let _ = writeln!(text, "Banner {}", path.display());
    }
    fs::write(&config, text)?;
    Ok(config)
}

/// Start a server and complete a handshake against it, returning the live
/// transport so a test can go on to exchange protected packets.
fn start_server_with(
    ciphers: &str,
    banner_text: Option<&str>,
) -> Result<
    (
        OpenSshServer,
        neotales_ssh::transport::ClientTransport<TcpStream>,
    ),
    Box<dyn std::error::Error>,
> {
    let directory = openssh_tools::temp_dir::TempDir::new("neotales-openssh")
        .map_err(|error| format!("could not create OpenSSH test directory: {error}"))?;
    let banner_path = if let Some(text) = banner_text {
        let path = directory.join("banner");
        fs::write(&path, text)?;
        Some(path)
    } else {
        None
    };
    let host_key = directory.join("host_ed25519");
    let keygen = openssh_tools::ssh_keygen()?;
    let generated = Command::new(&keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run ssh-keygen at {}: {error}", keygen.display()))?;
    if !generated.status.success() {
        return Err("ssh-keygen could not create the temporary host key".into());
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let config = write_config(&directory, port, &host_key, ciphers, banner_path.as_deref())
        .map_err(|error| {
            format!(
                "could not write sshd config under {}: {error}",
                directory.display()
            )
        })?;
    // stderr is inherited rather than discarded: an `sshd` that refuses a
    // packet writes the reason there, and the reason is the whole diagnosis.
    let sshd = openssh_tools::sshd()?;
    let mut command = Command::new(&sshd);
    command
        .args(["-D", "-e", "-f"])
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = openssh_tools::temp_dir::ChildGuard::spawn_tree(&mut command)
        .map_err(|error| format!("failed to run sshd at {}: {error}", sshd.display()))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("the throwaway sshd exited before becoming reachable: {status}").into(),
            );
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                let config = ClientConfig::new();
                let transport =
                    config
                        .connect(stream, |_key| Ok::<(), ()>(()))
                        .map_err(|error| {
                            format!("SSH handshake with the local sshd failed: {error}")
                        })?;
                return Ok((
                    OpenSshServer {
                        _child: child,
                        _directory: directory,
                    },
                    transport,
                ));
            }
            Err(error) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
                let _ = error;
            }
            Err(error) => {
                return Err(error.into());
            }
        }
    }
}

/// A handshake with whatever the client prefers. The original lane, unchanged.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn live_openssh_server_completes_mlkem_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let (_server, _transport) = start_server_with("", None)?;
    Ok(())
}

/// `SSH_MSG_USERAUTH_BANNER`, RFC 4252 section 5.4.
const SSH_MSG_USERAUTH_BANNER: u8 = 53;

/// SSH message numbers, RFC 4253 section 7.1 and RFC 4252 section 5.
const SSH_MSG_IGNORE: u8 = 2;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;

/// An `SSH_MSG_IGNORE` with no data, RFC 4253 section 11.2.
///
/// The peer must silently discard it, and it is the cheapest packet that still
/// forces the packet cipher: the receiver has to decrypt it and verify its tag
/// before it can know to discard it. A nonce that repeats is caught here.
///
/// `SSH_MSG_USERAUTH_REQUEST` would do the same cryptographic work, and this lane
/// used a run of those, but each one is an authentication attempt and OpenSSH
/// penalises repeated attempts against an invalid user. The penalty is seconds
/// per attempt, so a run long enough to cross the 256-packet boundary does not
/// finish before `LoginGraceTime` expires and the server hangs up. An ignored
/// packet carries the same proof without the rate limit.
fn ignore() -> Vec<u8> {
    vec![SSH_MSG_IGNORE]
}

/// Prepend an RFC 4251 SSH string: a four-byte big-endian length, then the bytes.
fn ssh_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    let length = u32::try_from(value.len()).expect("test SSH string length fits in u32");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// `SSH_MSG_SERVICE_REQUEST` asking for `ssh-userauth`, RFC 4253 section 7.1.
fn service_request() -> Vec<u8> {
    let mut out = vec![SSH_MSG_SERVICE_REQUEST];
    out.extend(ssh_string(b"ssh-userauth"));
    out
}

/// `SSH_MSG_USERAUTH_REQUEST` for the `none` method, RFC 4252 section 7.2.
///
/// The request stops after the method name. RFC 4252 shows a `boolean FALSE`
/// following the method name, but OpenSSH's `userauth_none` reads the three
/// strings and then requires the packet to be exhausted, so the boolean is
/// reported to it as `SSH_ERR_UNEXPECTED_TRAILING_DATA` and the connection is
/// torn down with
///
///     userauth_none: parse packet: unexpected bytes remain after decoding
///
/// That is worth recording, because it was previously read as a fault in this
/// crate's packet framing. The framing was correct throughout: the server
/// decrypts the packet and verifies its tag, and then rejects the *payload* this
/// test built. The cipher here is the evidence -- with the boolean included the
/// server dies on the payload, and without it the same server accepts hundreds
/// of consecutive requests.
fn userauth_request_none(user: &str) -> Vec<u8> {
    let mut out = vec![SSH_MSG_USERAUTH_REQUEST];
    out.extend(ssh_string(user.as_bytes()));
    out.extend(ssh_string(b"ssh-connection"));
    out.extend(ssh_string(b"none"));
    out
}

/// Read until a packet of `wanted` type arrives, or the peer stops talking.
///
/// A server is free to send `SSH_MSG_EXT_INFO` or a banner in any order around the
/// reply it owes us, so a single read is not enough to conclude anything.
fn read_until<F>(
    transport: &mut neotales_ssh::transport::ClientTransport<TcpStream>,
    wanted: u8,
    mut inspect: F,
) -> Result<bool, Box<dyn std::error::Error>>
where
    F: FnMut(&[u8]),
{
    for _ in 0..8 {
        let payload = transport.read_payload()?;
        if payload.first() == Some(&wanted) {
            inspect(&payload);
            return Ok(true);
        }
    }
    Ok(false)
}

/// A protected exchange with a conformant peer, in both directions, carried far
/// enough past the 256-packet boundary to matter.
///
/// The handshake agrees keys and stops. The nonce lives only in a sealed packet,
/// so a non-conformant nonce passes every handshake test there is -- and this
/// crate's had one, producing `IV[0..4] || zeros || sequence_number`. Two
/// opposite-direction assertions are what make a fix real rather than merely
/// spec-shaped:
///
///   * the client seals a service request, a run of `SSH_MSG_IGNORE`, and then a
///     `none` auth request, and the server answers `SSH_MSG_USERAUTH_FAILURE` to
///     the last one -- which only a server that correctly decrypted and
///     tag-verified every packet before it can produce, since SSH is one ordered
///     stream per direction and it cannot reach the last packet past one it
///     could not read;
///   * the client opens the banner the server sent of its own accord, and finds
///     the text there byte for byte.
///
/// Break the nonce and the first assertion fails, because the server cannot read
/// the packets. Break the write path and the second does.
///
/// ## Why this lane is long, which is the point of it
///
/// The GCM nonce construction this crate used read the counter as one octet wide,
/// so a nonce repeated every 256 packets in a direction. Reusing a nonce under
/// AES-GCM leaks the GHASH authentication key and permits tag forgery, so that is
/// a security defect and not only an interoperation one.
///
/// A lane that stops at the second packet cannot see it. The divergence begins at
/// `256 - IV[11]`, and `IV[11]` is whatever the key exchange happened to produce,
/// so a one-octet counter can agree with a correct one for anywhere from a handful
/// of packets to nearly 256. Only a lane carrying more than 256 protected packets
/// in one direction crosses the boundary on every run, and
/// [`PROTECTED_PACKET_RUN`] is well past it.
///
/// The ignored packets are what carry the count, and they are cheap: a receiver
/// must decrypt a packet and verify its tag before it can know to discard it, so
/// each one is a full test of the packet cipher, and none of them is an
/// authentication attempt for the server to rate-limit.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn live_openssh_exchanges_protected_packets_with_aes128_gcm()
-> Result<(), Box<dyn std::error::Error>> {
    protected_exchange_over("aes128-gcm@openssh.com")
}

/// The thirty-two-bit key does not change the packet framing, so this is a
/// control: a change to the shared rule that broke the 128-bit lane should not
/// pass here silently.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn live_openssh_exchanges_protected_packets_with_aes256_gcm()
-> Result<(), Box<dyn std::error::Error>> {
    protected_exchange_over("aes256-gcm@openssh.com")
}

/// `chacha20-poly1305@openssh.com` is the **eight**-byte-block AEAD, and it is the
/// lane that exposed the alignment defect this commit fixes. Its 4-byte
/// `packet_length` is AAD, so it is authenticated but not encrypted and does not
/// count toward block alignment; this crate aligned the whole packet, so
/// everything it sent sat at `mod 4` on an eight-byte block and the peer answered
///
///     padding error: need 28 block 8 mod 4
///
/// Two packets would have been enough to see that, and they were not used,
/// because the same lane also has to cross the 256-packet nonce boundary.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn live_openssh_exchanges_protected_packets_with_chacha20_poly1305()
-> Result<(), Box<dyn std::error::Error>> {
    protected_exchange_over("chacha20-poly1305@openssh.com")
}

/// The sixteen-byte-block encrypt-then-MAC suite, the other alignment branch:
/// `4 + packet_length` is aligned here, not `packet_length` alone. It is the lane
/// that would notice a change to the shared rule breaking a suite that worked.
#[test]
#[ignore = "live OpenSSH lane: needs sshd and ssh-keygen, resolved by openssh_tools; a missing one fails rather than skips"]
fn live_openssh_exchanges_protected_packets_with_aes128_ctr_etm()
-> Result<(), Box<dyn std::error::Error>> {
    protected_exchange_over("aes128-ctr")
}

fn protected_exchange_over(cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected = format!("neotales banner, read through {cipher}");
    let (_server, mut transport) = start_server_with(cipher, Some(&expected))?;

    // Client to server: a sealed packet the server has to read to make progress.
    transport.write_payload(&service_request())?;
    let accepted = read_until(&mut transport, SSH_MSG_SERVICE_ACCEPT, |_| {})?;
    assert!(
        accepted,
        "the server never accepted ssh-userauth over {cipher}"
    );

    // The first authentication request. A server sends its banner only once
    // authentication is under way, so this is the packet that provokes it, and
    // the banner is a server-to-client packet this client has to decrypt.
    transport.write_payload(&userauth_request_none("nobody"))?;
    let saw_banner = read_until(&mut transport, SSH_MSG_USERAUTH_BANNER, |payload| {
        let text = String::from_utf8_lossy(&payload[1..]);
        assert!(
            text.contains(&expected),
            "the banner decrypted to something else: {text:?}"
        );
    })?;
    assert!(
        saw_banner,
        "no banner arrived; the server-to-client nonce is unproven"
    );
    let refused = read_until(&mut transport, SSH_MSG_USERAUTH_FAILURE, |_| {})?;
    assert!(
        refused,
        "the server never rejected the `none` method; it did not read our request"
    );

    // Client to server: PROTECTED_PACKET_RUN protected packets that the server
    // must decrypt and tag-verify, carrying the run past the 256-packet boundary
    // where a one-octet counter would repeat a nonce.
    for _ in 0..PROTECTED_PACKET_RUN {
        transport.write_payload(&ignore())?;
    }

    // One more, and the server answers it. Reaching this answer at all is the
    // proof: the request sits past the whole run, and SSH is one ordered stream
    // per direction, so the server decrypted and tag-verified every packet of the
    // run to get here.
    transport.write_payload(&userauth_request_none("nobody"))?;
    let refused = read_until(&mut transport, SSH_MSG_USERAUTH_FAILURE, |_| {})?;
    assert!(
        refused,
        "the server never answered the request that follows {PROTECTED_PACKET_RUN} \
         protected packets, so it stopped reading somewhere inside the run"
    );
    Ok(())
}

/// How many protected packets the live lane sends past the 256-packet boundary.
///
/// A one-octet GCM counter repeats its nonce every 256 packets in a direction, so
/// the run has to exceed 256 to be sure of crossing the boundary whatever the
/// key exchange produced for `IV[11]`. 400 leaves room and stays well inside the
/// packet limits a server applies before a rekey.
const PROTECTED_PACKET_RUN: usize = 400;
