//! `docker system dial-stdio` over a session opened by `neotales-ssh`.
//!
//! This is the same mechanism as [`super::ssh_dial_stdio`] — run
//! `docker system dial-stdio` on the far end and speak Engine HTTP over its
//! standard streams — with the local end implemented by this repository's own
//! SSH crate rather than by the `ssh` binary.
//!
//! # Why this is the same transport and not a second one
//!
//! The output of this module is a [`StreamFactory`], exactly like the native
//! `ssh` binary's. Everything above it — the versioned URI, the request head,
//! `engine_result`, `FrameStream`, `escape_path_segment` — is the one
//! implementation in [`crate::raw::transport`]. There is no SSH-shaped status
//! mapping and no SSH-shaped stream decoder here, because a byte stream that
//! carries HTTP is not a different protocol once it is carrying HTTP.
//!
//! # The blocking part, and why it is only the blocking part
//!
//! `neotales-ssh` is a synchronous implementation. Connecting, the SSH
//! handshake, user authentication, opening a session channel, and the `exec`
//! request all block, and all of them happen on a blocking thread.
//!
//! Once the `exec` is accepted the shared socket is switched to non-blocking
//! mode and the transport is driven from the async task. That is not a
//! convenience: `neotales-ssh`'s packet layer documents that a stream "may
//! return `WouldBlock` after any prefix. In that case the current buffer,
//! suite, and sequence remain in place and the caller can retry the same
//! operation" (`neotales_ssh::transport`, on
//! `read_protected_packet_buffered`). That is what makes a non-blocking socket
//! usable at all, and it is why the loops below retry *the same operation*
//! rather than starting a fresh read.
//!
//! Three consequences follow, and all three are load-bearing:
//!
//! * A `WouldBlock` from the channel layer arrives as an undifferentiated
//!   `ChannelError::Transport`, which is indistinguishable from a dead
//!   connection. [`WouldBlock`] records the last `WouldBlock` the socket
//!   produced, and the duplex classifies on the record rather than on the error
//!   value. Guessing would turn every retryable stall into a dead connection.
//! * A write refused for a *window* is not a transport failure either. The
//!   remote window is SSH flow control and the answer arrives later as a
//!   `WindowAdjusted` event on the same session, so a write that cannot proceed
//!   pumps inbound events until it can, exactly as a read does.
//! * SSH windows are finite. The duplex grants the remote more room as bytes are
//!   handed to the caller, because granting on arrival instead would stall any
//!   response larger than one window at exactly the window boundary — which for
//!   a `docker build` or a long `pull` is every response of interest.
//!
//! # The credential is the caller's, and is not asked for
//!
//! This client speaks a transport, not a console, so an SSH password and the
//! passphrase on an encrypted identity file are both **values the caller
//! supplies**, wrapped in [`SshSecret`]. A library that blocked on a terminal
//! prompt inside a request would hang in exactly the situation a caller cannot
//! interrupt — a daemon, a CI job, a server — and the secret belongs to whoever
//! is driving the program, not to a request already in flight on someone else's
//! task.
//!
//! # What is not here, and why
//!
//! **Connection reuse.** Each request gets a whole connection, handshake,
//! authentication, session, and `exec`, which is heavier per request than the
//! native `ssh` binary reusing OpenSSH multiplexing. Reusing the *connection*
//! and opening a fresh channel per request is the shape that fits a
//! `StreamFactory` — which is called once per request and hands back a duplex no
//! other request holds — and it is not offered because
//! `neotales_ssh::channel::ChannelConnection` cannot support it:
//!
//! * It never reclaims a closed channel. `send_close` marks one closed and
//!   leaves it in the table; the only removal anywhere in that type is on an
//!   *open failure*. So `MAX_CHANNELS_PER_CONNECTION` (1024) is a hard
//!   per-connection ceiling, and a reused connection would eventually fail a
//!   request with a `ChannelError::TooManyChannels` naming neither the cause nor
//!   the reuse.
//! * Worse, it is the **second** request that fails. `apply_confirmation` refuses
//!   a confirmation whose remote identifier is already recorded on another
//!   channel, and OpenSSH allocates session channels by reusing the lowest free
//!   identifier on the connection — so a second channel's remote identifier is
//!   the first one's, and the request is refused with
//!   `ChannelError::DuplicateChannel`, "SSH channel identifier is already
//!   active". Measured against OpenSSH 10.5p1 with a pooled target over this
//!   module: three sequential requests, the first answered, the second refused
//!   with exactly that error.
//!
//! Both are properties of the channel layer's channel table, and the fix belongs
//! beside it: a `ChannelConnection` that dropped a channel once both sides have
//! closed it would make connection-level reuse work, and would also make a
//! long-lived multiplexing client possible. Reported rather than worked around
//! here, because `neotales-ssh` is not this change's to modify.
//!
//! **Agent and ECDSA identity keys.** `PublicKeySigner` and `OpenSshPrivateKey`
//! are closed enums carrying `Ed25519` and `Rsa` and nothing else, so an
//! agent-held identity and an `ecdsa-sha2-nistp256` key file are both
//! inexpressible from here — there is no constructor to call, and a
//! `cargo build` says so. `neotales_ssh::agent::AgentClient` can already list
//! identities and sign, and `neotales_ssh::ecdsa_hostkey::EcdsaSigner` can
//! already sign, so neither needs new cryptography: a variant on each enum and
//! the plumbing to fill it is the whole of it. Also reported rather than worked
//! around.
//!
//! **A second stream decoder.** Nothing here decodes the Engine's frames. The
//! `FrameStream` in [`crate::raw`] is the only one, and a multiplexed scheme
//! carrying several requests over one channel would have needed a second.

use std::future::Future as _;
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use neotales_ssh::GlobalRequest;
use neotales_ssh::auth::{ClientAuthMethod, ClientAuthenticator, PublicKeySigner, RsaAuthSigner};
use neotales_ssh::channel::{
    ChannelConnection, ChannelId, ChannelTransport, INITIAL_CHANNEL_WINDOW, MAX_CHANNEL_PACKET_SIZE,
};
use neotales_ssh::client::ClientConfig;
use neotales_ssh::ecdsa_hostkey::EcdsaSigner;
use neotales_ssh::hostkey::{Ed25519PublicKey, Ed25519Signer};
use neotales_ssh::known_hosts::{AppendEntry, KnownHosts, KnownHostsMarker, KnownHostsStatus};
use neotales_ssh::openssh_key::{OpenSshKeyError, OpenSshPrivateKey};
use neotales_ssh::session::{ClientSessions, SESSION_CHANNEL_TYPE, SessionEvent};
use neotales_ssh::transport::ClientTransport;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::ssh_auth::{SshIdentity, SshSecret};
use super::ssh_dial_stdio::{DIAL_STDIO, DIAL_STDIO_AUTHORITY, SshDestination};
use crate::Error;
use crate::raw::{Duplex, RawTarget, StreamFactory};

/// Waits for one readiness direction inside a `poll_fn` loop.
///
/// This is `ready!(wait_ready(…))` with the error case handled, which the
/// `ready!` macro cannot express in one expression. The three arms are the three
/// things a readiness wait can do, and every call site in this module wants all
/// three: keep going when the edge arrived, propagate a registration failure,
/// and yield when the edge has not.
macro_rules! await_ready {
    ($context:expr, $this:expr, $interest:expr) => {
        match wait_ready($context, &mut $this.readiness, $interest) {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

/// How the managed SSH client opens its session.
///
/// A struct, not a parameter list: this is the shape a caller has to describe
/// an `ssh://` endpoint, and it is the shape that grows when an agent or a
/// password provider is wired to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedSshOptions {
    /// The host to connect to.
    pub(crate) host: String,
    /// The TCP port to connect to.
    pub(crate) port: u16,
    /// The login name to authenticate as.
    pub(crate) user: String,
    /// The OpenSSH known-hosts token for `host` and `port`.
    pub(crate) host_token: String,
    /// The credential to authenticate with.
    pub(crate) identity: SshIdentity,
    /// The known-hosts file the host key is checked against, and an unseen key
    /// is added to.
    pub(crate) known_hosts_path: std::path::PathBuf,
}

impl ManagedSshOptions {
    /// Reads the managed options out of an `ssh://` address, a credential, and
    /// a known-hosts path.
    ///
    /// # Errors
    ///
    /// Returns an error naming the missing part when the address is not an
    /// `ssh://` endpoint or names no host, when it names no login name, and when
    /// no known-hosts file is given. Each of the two is refused with its own
    /// reason rather than as one "incomplete", because a caller who supplied one
    /// of them needs to know which is absent.
    ///
    /// A credential is not defaulted here, but it is also not *required*: a
    /// caller who named none is refused by the builder before this is reached,
    /// with a message naming the three ways to set one. Refusing it here as
    /// "incomplete" would report a missing password as a malformed endpoint.
    pub(crate) fn from_endpoint(
        address: &str,
        identity: SshIdentity,
        known_hosts_path: Option<&Path>,
    ) -> Result<Self, Error> {
        let destination = SshDestination::parse(address)?;
        let user = destination.user.ok_or_else(|| {
            Error::invalid_input(format!(
                "the managed Engine SSH client authenticates as a named user and \
                 '{address}' names none"
            ))
        })?;
        let known_hosts_path = known_hosts_path.ok_or_else(|| {
            Error::invalid_input(format!(
                "the managed Engine SSH client checks the host key against a known-hosts \
                 file and '{address}' names none"
            ))
        })?;
        Ok(Self {
            host: destination.host,
            port: destination.port,
            user,
            host_token: destination.host_token,
            identity,
            known_hosts_path: known_hosts_path.to_path_buf(),
        })
    }
}

/// Builds the owned `RawTarget` for the managed SSH client.
///
/// The factory opens a whole new TCP connection, handshake, authentication,
/// session, and `exec` for every request. That is heavier per request than the
/// native `ssh` binary, which at least reuses the user's connection
/// multiplexing, and it is also the property that makes the target stateless —
/// and statelessness is what lets two requests share one
/// [`RawEngine`](crate::raw::RawEngine) with no coordination between them.
///
/// A connect, handshake, authentication, or `exec` failure is reported by the
/// first request that needed it, which is where a user sees it against the
/// request they made.
pub(crate) fn managed_ssh_target(options: ManagedSshOptions) -> RawTarget {
    let authority = DIAL_STDIO_AUTHORITY.to_owned();
    let factory = StreamFactory::from_fn(move || {
        let options = options.clone();
        async move { open(&options).await }
    });
    RawTarget::Stream {
        authority,
        open: factory,
    }
}

/// Opens one SSH session running `docker system dial-stdio`.
async fn open(options: &ManagedSshOptions) -> Result<Box<dyn Duplex>, Error> {
    // The synchronous prologue — connect, handshake, authenticate, open the
    // channel, exec — runs on a blocking thread, because every step of it blocks
    // and none of it is `async` in `neotales-ssh`. The duplex it returns is
    // driven by the caller's task, not by that one.
    let established = {
        let options = options.clone();
        tokio::task::spawn_blocking(move || establish(&options))
            .await
            .map_err(|error| {
                Error::transport(format!(
                    "the managed Engine SSH task did not finish: {error}"
                ))
            })?
    }?;
    let Established {
        sessions,
        session,
        readiness,
        would_block,
    } = established;
    // Registered with the reactor here rather than in `establish`, because
    // `TcpStream::from_std` needs a reactor and `establish` runs on a blocking
    // thread.
    let readiness = TcpStream::from_std(readiness)
        .map_err(|error| Error::transport(format!("register the Engine SSH socket: {error}")))?;
    Ok(Box::new(SessionDuplex {
        sessions,
        session,
        readiness,
        would_block: WouldBlock(would_block),
        inbound: Vec::new(),
        drained: 0,
        pending_grant: 0,
        at_eof: false,
    }))
}

/// A connected SSH session whose `exec` has been accepted.
struct Established {
    /// The session channel, with the SSH transport inside it.
    sessions: ClientSessions<ConnectionOnly<ClientTransport<Socket>>>,
    /// The local channel identifier, which the channel layer allocated.
    session: ChannelId,
    /// A second handle on the same socket, used only for readiness.
    ///
    /// `try_clone` shares the socket's file description, so the non-blocking
    /// flag applies to both and the reactor watches the same bytes the SSH
    /// transport reads. It is never read from or written to: the SSH packet
    /// layer needs both directions through one object, because the sequence
    /// numbers, the cipher state, and a rekey are one state machine.
    readiness: StdTcpStream,
    /// Shared with the socket, so the duplex can classify a `WouldBlock` the
    /// channel layer has already erased.
    would_block: Arc<AtomicBool>,
}

/// Runs the synchronous prologue of one request's SSH session.
fn establish(options: &ManagedSshOptions) -> Result<Established, Error> {
    let host = options.host.clone();
    let port = options.port;
    let user = options.user.clone();
    let host_token = options.host_token.clone();
    let known_hosts_path = options.known_hosts_path.clone();
    let known_hosts = load_known_hosts(&known_hosts_path)?;
    let methods = auth_methods(&options.identity)?;

    let socket = connect(&host, port)?;
    let would_block = Arc::new(AtomicBool::new(false));
    let transport_socket = socket
        .try_clone()
        .map_err(|error| transport_error("clone the SSH socket", error))?;
    let mut transport = ClientConfig::new()
        .connect(
            Socket {
                inner: transport_socket,
                would_block: Arc::clone(&would_block),
            },
            move |host_key| {
                check_host_key(&known_hosts, &known_hosts_path, &host_token, port, host_key)
            },
        )
        .map_err(|error| transport_error(format!("the SSH handshake with {host}:{port}"), error))?;

    let mut authenticator = ClientAuthenticator::new(&mut transport, &user, 4)
        .map_err(|error| transport_error("prepare SSH authentication", error))?;
    authenticator.authenticate(&methods).map_err(|error| {
        transport_error(
            format!(
                "authenticate to {host}:{port} as '{user}' with {}",
                options.identity.mechanism()
            ),
            error,
        )
    })?;

    // The connection-level demultiplexer goes in *under* the channel layer, not
    // around it: the channel layer reads one payload at a time and treats
    // anything that is not a channel message as a protocol failure, and a real
    // OpenSSH server sends connection-level messages routinely.
    //
    // It is installed *after* authentication because that is the order the
    // messages arrive in — measured against OpenSSH 10.5p1, the
    // `hostkeys-00@openssh.com` global request is the first payload after
    // message 52, and the authenticator's own reader is a message-numbered
    // state machine that would have to learn about message 80 as well.
    let transport = ConnectionOnly::new(transport);
    // The channel is opened through `ChannelConnection` rather than through
    // `ClientSessions::open_session`, so the same object the duplex will later
    // drive is the one the `exec` request is issued on.
    let mut channels = ChannelConnection::new(transport);
    let session = channels
        .allocate_channel_id()
        .map_err(|error| transport_error("allocate an SSH channel identifier", error))?;
    channels
        .open_channel_with_limits(
            session,
            SESSION_CHANNEL_TYPE.as_bytes(),
            &[],
            INITIAL_CHANNEL_WINDOW,
            MAX_CHANNEL_PACKET_SIZE,
        )
        .map_err(|error| transport_error("open an SSH session channel", error))?;
    let mut sessions = ClientSessions::from_connection(channels);
    // The channel has to be confirmed before an `exec` can name it. An exec
    // request carries the *remote* channel identifier, which the peer only
    // supplies in its confirmation, so asking before that arrives fails inside
    // the channel layer with a message about a missing remote identifier — a
    // failure that reads like a protocol fault and is really an ordering one.
    await_confirmation(&mut sessions, session)?;
    sessions
        .request_exec(session, &exec_request(), true)
        .map_err(|error| transport_error("request 'docker system dial-stdio' over SSH", error))?;
    await_exec(&mut sessions, session)?;

    // The exec is accepted, so the far end of this socket is now an HTTP peer
    // and has to be driven by readiness. Both handles share the file
    // description, so one flag switch covers both.
    socket
        .set_nonblocking(true)
        .map_err(|error| transport_error("switch the SSH socket to non-blocking", error))?;
    let readiness = socket
        .try_clone()
        .map_err(|error| transport_error("clone the SSH socket for readiness", error))?;
    Ok(Established {
        sessions,
        session,
        readiness,
        would_block,
    })
}

/// The exact bytes of the `exec` request: one command string, no shell.
///
/// `sshd` hands the command to the login shell, so the words are spelled the way
/// a user would type them. The .NET reference sends the identical command string
/// (`session.StartAsync("docker system dial-stdio", …)`), and so does `docker`.
fn exec_request() -> Vec<u8> {
    DIAL_STDIO.join(" ").into_bytes()
}

/// Consumes events until the peer has confirmed the session channel.
///
/// A channel is not usable the moment it is opened: the `exec` request has to
/// name the *remote* identifier the confirmation carries, and asking for it
/// earlier is refused by the channel layer for a reason that names neither the
/// ordering nor the fix.
fn await_confirmation<T>(sessions: &mut ClientSessions<T>, session: ChannelId) -> Result<(), Error>
where
    T: neotales_ssh::channel::ChannelTransport,
{
    loop {
        match sessions
            .dispatch_one()
            .map_err(|error| transport_error("await the SSH channel confirmation", error))?
        {
            SessionEvent::Opened { session: opened } if opened == session => return Ok(()),
            SessionEvent::OpenRejected {
                reason,
                description,
                ..
            } => {
                return Err(Error::transport(format!(
                    "the remote host refused to open an SSH session channel: reason {reason}, {}",
                    String::from_utf8_lossy(&description)
                )));
            }
            // Informational while the peer is still deciding: a `global request`
            // or an `env` reply carries nothing about this channel.
            _ => {}
        }
    }
}

/// Consumes events until the `exec` request is accepted.
fn await_exec<T>(sessions: &mut ClientSessions<T>, session: ChannelId) -> Result<(), Error>
where
    T: neotales_ssh::channel::ChannelTransport,
{
    let mut executed = false;
    while !executed {
        match sessions
            .dispatch_one()
            .map_err(|error| transport_error("await the SSH exec reply", error))?
        {
            SessionEvent::RequestSucceeded { session: ok } => executed = ok == session,
            SessionEvent::RequestFailed { session: refused } if refused == session => {
                return Err(Error::transport(
                    "the remote host refused 'docker system dial-stdio'; check that the login \
                     user can reach the Docker socket and that the docker CLI is on that \
                     account's PATH"
                        .to_owned(),
                ));
            }
            // A second channel on the same connection, or a `close` for one this
            // duplex did not open, is not something this request can act on and
            // the session is the only channel it has.
            SessionEvent::OpenRejected {
                reason,
                description,
                ..
            } => {
                return Err(Error::transport(format!(
                    "the remote host refused an SSH session channel: reason {reason}, {}",
                    String::from_utf8_lossy(&description)
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Decides whether an offered host key is accepted.
///
/// An unrecognised key is *added*, which is OpenSSH's
/// `StrictHostKeyChecking accept-new` and the same policy the OpenSSH-backed
/// transport in `ssh_transport` uses (`KnownHosts::Add`). A key that is present
/// and different is refused, and so is one marked revoked: a changed key is the
/// signal that matters most, and accepting it is the failure this check exists
/// to prevent.
fn check_host_key(
    known_hosts: &KnownHosts,
    known_hosts_path: &Path,
    host_token: &str,
    port: u16,
    host_key: &Ed25519PublicKey,
) -> Result<(), Error> {
    let blob = host_key.to_blob().map_err(|error| {
        Error::transport(format!("encode the SSH host key for {host_token}: {error}"))
    })?;
    match known_hosts.check(host_token, port, &blob) {
        KnownHostsStatus::Trusted => Ok(()),
        KnownHostsStatus::NotFound => {
            let entry = AppendEntry::new(
                [host_token.to_owned()],
                &blob,
                KnownHostsMarker::None,
                false,
            )
            .map_err(|error| host_key_error(known_hosts_path, host_token, error))?;
            neotales_ssh::known_hosts::append_to_path(known_hosts_path, &entry)
                .map_err(|error| host_key_error(known_hosts_path, host_token, error))
        }
        KnownHostsStatus::Changed => Err(Error::transport(format!(
            "the SSH host key for {host_token} does not match {}; the host may have been \
             rebuilt, or the connection may not be to the host it claims to be",
            known_hosts_path.display()
        ))),
        KnownHostsStatus::Revoked => Err(Error::transport(format!(
            "the SSH host key for {host_token} is marked revoked in {}",
            known_hosts_path.display()
        ))),
        KnownHostsStatus::CertificateAuthority => Err(Error::transport(format!(
            "the SSH host key for {host_token} matches a certificate-authority entry in {}, \
             which this client does not accept as a host key",
            known_hosts_path.display()
        ))),
    }
}

/// Reports a known-hosts failure against the file it happened to.
fn host_key_error(
    known_hosts_path: &Path,
    host_token: &str,
    error: impl std::fmt::Display,
) -> Error {
    Error::transport(format!(
        "record the SSH host key for {host_token} in {}: {error}",
        known_hosts_path.display()
    ))
}

/// Connects the TCP socket the SSH session runs over.
///
/// Every resolved address is tried, because a host with both an AAAA and an A
/// record that refuses IPv6 should not fail the connection.
fn connect(host: &str, port: u16) -> Result<StdTcpStream, Error> {
    let mut last = None;
    for address in (host, port)
        .to_socket_addrs()
        .map_err(|error| transport_error(format!("resolve the SSH host {host}:{port}"), error))?
    {
        match StdTcpStream::connect(address) {
            Ok(socket) => {
                // The Engine's request/response pairs are small and latency
                // sensitive, which is exactly what Nagle delays.
                let _ignored = socket.set_nodelay(true);
                return Ok(socket);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(transport_error(
        format!("connect to {host}:{port}"),
        last.unwrap_or_else(|| std::io::Error::other("the host resolved to no addresses")),
    ))
}

/// Loads the known-hosts file, treating an absent file as empty.
///
/// An absent file is the first-run case, and OpenSSH treats it the same way: no
/// entry matches, and the key is added. A file that exists and cannot be read is
/// an error rather than an empty set, because "no known hosts" and "cannot read
/// the known hosts" have opposite trust consequences.
fn load_known_hosts(path: &Path) -> Result<KnownHosts, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => KnownHosts::parse(&text).map_err(|error| {
            Error::invalid_input(format!(
                "the known-hosts file {} could not be parsed: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(KnownHosts::default()),
        Err(error) => Err(Error::transport(format!(
            "read the known-hosts file {}: {error}",
            path.display()
        ))),
    }
}

/// The authentication methods to try, in order, for one connection.
///
/// One method per connection, because the caller named exactly one credential
/// and offering the server a choice would let it steer which one is used. The
/// vector rather than a single value because `ClientAuthenticator::authenticate`
/// takes a slice, and a one-element slice is not a special case worth a branch.
fn auth_methods(identity: &SshIdentity) -> Result<Vec<ClientAuthMethod>, Error> {
    let method = match identity {
        SshIdentity::KeyFile(path) => {
            ClientAuthMethod::PublicKey(Box::new(public_key_signer(path, None)?))
        }
        SshIdentity::EncryptedKeyFile { path, passphrase } => {
            ClientAuthMethod::PublicKey(Box::new(public_key_signer(path, Some(passphrase))?))
        }
        // The constructor rather than the variant, because the variant holds a
        // `Zeroizing` string: the copy made here is wiped with the method, and
        // naming the constructor is what makes that the case.
        SshIdentity::Password(password) => ClientAuthMethod::password(password.expose()),
    };
    Ok(vec![method])
}

/// Loads an OpenSSH private key as a public-key signer.
///
/// An encrypted key needs the caller's passphrase. A library that blocked on a
/// terminal prompt inside a request would hang, so the passphrase is a
/// caller-supplied [`SshSecret`], and a key that needs one and was given none is
/// refused with a message naming the call that would work rather than with
/// whatever the container parser happens to report for an empty passphrase.
fn public_key_signer(
    path: &Path,
    passphrase: Option<&SshSecret>,
) -> Result<PublicKeySigner, Error> {
    let bytes = std::fs::read(path).map_err(|error| {
        Error::transport(format!("read the SSH identity {}: {error}", path.display()))
    })?;
    // `ssh-keygen` writes the new format inside a PEM armor, and the file every
    // user has on disk is armored. `OpenSshPrivateKey::parse` takes the decoded
    // container — its own documentation says so — so the armor is removed here
    // rather than in `neotales-ssh`, which is a protocol crate and not a file
    // format reader for OpenSSH's armor.
    let bytes = match decode_openssh_armor(&bytes) {
        Some(decoded) => decoded,
        // Not armored: the caller handed the raw container, which the parser
        // accepts, and its own error message is the better one.
        None => bytes,
    };
    // The passphrase is a throwaway buffer rather than the secret's own storage,
    // because `OpenSshPrivateKey::parse` zeroizes what it is given and that
    // promise is only worth something about a copy.
    let passphrase_was_given = passphrase.is_some();
    let mut passphrase =
        passphrase.map_or_else(|| Zeroizing::new(Vec::new()), SshSecret::expose_throwaway);
    match OpenSshPrivateKey::parse(&bytes, &mut passphrase) {
        Ok(OpenSshPrivateKey::Ed25519 { seed, .. }) => {
            let mut bytes = [0_u8; 32];
            let seed = seed.as_slice();
            if seed.len() != bytes.len() {
                return Err(Error::invalid_input(format!(
                    "the Ed25519 SSH identity {} carries a {}-byte seed",
                    path.display(),
                    seed.len()
                )));
            }
            bytes.copy_from_slice(seed);
            Ok(PublicKeySigner::ed25519(Ed25519Signer::from_seed(
                &mut bytes,
            )))
        }
        Ok(OpenSshPrivateKey::Ecdsa { secret, .. }) => {
            let signer = EcdsaSigner::from_secret_scalar_bytes(&secret).map_err(|error| {
                Error::invalid_input(format!(
                    "the ECDSA SSH identity {} could not be used: {error}",
                    path.display()
                ))
            })?;
            Ok(PublicKeySigner::ecdsa(signer))
        }
        Ok(OpenSshPrivateKey::Rsa { p, q, e, .. }) => {
            let signer = RsaAuthSigner::from_p_q(
                rsa::BigUint::from_bytes_be(&p),
                rsa::BigUint::from_bytes_be(&q),
                rsa::BigUint::from_bytes_be(&e),
            )
            .map_err(|error| {
                Error::invalid_input(format!(
                    "the RSA SSH identity {} could not be used: {error}",
                    path.display()
                ))
            })?;
            Ok(PublicKeySigner::rsa(signer))
        }
        // An encrypted key with no passphrase is a caller's mistake, and the
        // container parser's own words for it are about an unsupported algorithm
        // — true, and useless. `WrongPassphrase` reaches the same place, because
        // with an empty passphrase the derived key is wrong rather than absent,
        // so the parser cannot tell the two apart either.
        // One arm for the three errors that all mean "this key wanted a
        // passphrase and did not get one". Nested rather than three `Err(..)`
        // alternatives, which is the same pattern written three times.
        Err(
            OpenSshKeyError::WrongPassphrase
            | OpenSshKeyError::UnsupportedCipher
            | OpenSshKeyError::UnsupportedKdf,
        ) if !passphrase_was_given => Err(Error::invalid_input(format!(
            "the SSH identity {} is encrypted and no passphrase was given; an encrypted \
                 identity is authenticated with SshIdentity::EncryptedKeyFile",
            path.display()
        ))),
        Err(OpenSshKeyError::WrongPassphrase) => Err(Error::invalid_input(format!(
            "the passphrase for the SSH identity {} is incorrect",
            path.display()
        ))),
        Err(error @ (OpenSshKeyError::UnsupportedCipher | OpenSshKeyError::UnsupportedKdf)) => {
            // A passphrase *was* given, so the key is asking for a cipher or a
            // key derivation this parser does not implement. Which one is the
            // useful half, so it is named rather than flattened.
            Err(Error::invalid_input(format!(
                "the SSH identity {} is encrypted with a cipher or key derivation this client \
                 does not implement: {error}",
                path.display()
            )))
        }
        Err(error) => Err(Error::invalid_input(format!(
            "the SSH identity {} could not be read: {error}",
            path.display()
        ))),
    }
}

/// The `-----BEGIN OPENSSH PRIVATE KEY-----` armor lines.
const OPENSSH_ARMOR_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// The `-----END OPENSSH PRIVATE KEY-----` armor line.
const OPENSSH_ARMOR_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// Decodes the base64 body of an armored OpenSSH private key.
///
/// Returns `None` when the bytes are not that armor, so the caller can hand
/// them to the container parser unchanged and let it report the shape it
/// actually saw. The armor is a line-oriented format and this reads it that
/// way: everything between the two markers, with the whitespace a text editor
/// or a line wrap introduced removed before decoding.
fn decode_openssh_armor(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;

    let text = std::str::from_utf8(bytes).ok()?;
    let (_, after_begin) = text.split_once(OPENSSH_ARMOR_BEGIN)?;
    let (body, _) = after_begin.split_once(OPENSSH_ARMOR_END)?;
    let encoded: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
}

/// The connection-level messages that arrive on a session's one connection and
/// are not channel messages.
///
/// RFC 4253 section 7.1 numbers them, and the numbers are quoted here because a
/// magic byte with no citation is exactly the kind of thing that gets
/// "simplified" later.
mod connection_message {
    /// `SSH_MSG_IGNORE` (5). The peer is telling the client to ignore a packet.
    pub(super) const IGNORE: u8 = 5;
    /// `SSH_MSG_DEBUG` (4). A diagnostic the client may display.
    pub(super) const DEBUG: u8 = 4;
    /// `SSH_MSG_UNIMPLEMENTED` (7). A reply to something the peer could not do.
    pub(super) const UNIMPLEMENTED: u8 = 7;
    /// `SSH_MSG_GLOBAL_REQUEST` (80).
    pub(super) const GLOBAL_REQUEST: u8 = 80;
    /// `SSH_MSG_REQUEST_SUCCESS` (81), the answer to a global request.
    pub(super) const REQUEST_SUCCESS: u8 = 81;
    /// `SSH_MSG_REQUEST_FAILURE` (82), the answer to a global request.
    pub(super) const REQUEST_FAILURE: u8 = 82;
}

/// A demultiplexer that answers connection-level messages before the channel
/// layer sees them.
///
/// # Why this exists, and what it is not
///
/// `neotales_ssh::channel::ChannelConnection` reads one payload per
/// `dispatch_one` and treats anything that is not a channel message as
/// `ChannelError::UnexpectedMessage`. A real OpenSSH server does not send only
/// channel messages. Measured against OpenSSH 10.5p1, immediately after a
/// successful public-key authentication and before any channel is opened, it
/// sends:
///
/// ```text
/// ROUND 0: len=84 first=80 head="P\0\0\0\u{17}hostkeys-00@openssh.com\0\0\0\0..."
/// ```
///
/// Message 80 is `SSH_MSG_GLOBAL_REQUEST`, and `hostkeys-00@openssh.com` is
/// OpenSSH's post-authentication host-key advertisement. A client that treats it
/// as a channel message cannot open a channel against a current OpenSSH server
/// at all — the failure surfaces as "unexpected message 80" and names neither
/// the message nor the fix.
///
/// This wrapper reads a payload, answers it if it is a connection-level message,
/// and returns the next one that is not. It adds **no channel behaviour**: no
/// window accounting, no identifier, no framing. Every channel message passes
/// through untouched, and the channel layer above still owns all of that.
///
/// # The defect this is working around
///
/// The right home for this is inside `neotales-ssh`, where `ChannelConnection`
/// lives and where `neotales_ssh::GlobalRequest` already knows how to decode and
/// answer one. That is outside this change's scope, so it is reported rather
/// than fixed, and this wrapper stands in for it. When the channel layer grows
/// the handling, this type and its `ChannelTransport` impl go away, and nothing
/// above them changes.
///
/// # What is answered, and what is not
///
/// * `SSH_MSG_GLOBAL_REQUEST` is decoded and answered by
///   [`GlobalRequest`], which sends `REQUEST_FAILURE` for a name it does not
///   know — including `hostkeys-00@openssh.com`. RFC 4253 section 7.1 requires
///   exactly that: a client must not silently ignore a global request that asked
///   for a reply, and must answer one it does not support with a failure.
/// * `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, and `SSH_MSG_UNIMPLEMENTED` are
///   discarded. They carry nothing this client acts on, and RFC 4253 says a
///   recipient "MUST ignore" a debug or ignore message.
/// * `SSH_MSG_REQUEST_SUCCESS` and `SSH_MSG_REQUEST_FAILURE` are discarded
///   because this client sends no global requests, so there is nothing for them
///   to answer. Discarding rather than erroring is what keeps a *server*-side
///   client (a future `direct-tcpip` use) working against a peer that does send
///   them.
struct ConnectionOnly<T> {
    transport: T,
}

impl<T> ConnectionOnly<T> {
    const fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T> ChannelTransport for ConnectionOnly<T>
where
    T: neotales_ssh::channel::ChannelTransport,
{
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.transport.write_channel_payload(payload)
    }

    /// Reads payloads until one belongs to a channel.
    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        loop {
            let payload = self.transport.read_channel_payload()?;
            match payload.first().copied() {
                Some(connection_message::GLOBAL_REQUEST) => {
                    // A payload that does not decode is still not a channel
                    // message, and RFC 4253's obligation is to answer rather
                    // than to fail: a global request whose shape this client
                    // cannot read cannot be honoured and must not be a fatal
                    // error. A `want_reply` request answered with a failure is
                    // the conformant response.
                    if let Ok(request) = GlobalRequest::decode(&payload)
                        && let Some(reply) = request.reply().ok().flatten()
                    {
                        let _answered = self.transport.write_channel_payload(&reply);
                    }
                }
                Some(
                    connection_message::DEBUG
                    | connection_message::IGNORE
                    | connection_message::UNIMPLEMENTED
                    | connection_message::REQUEST_SUCCESS
                    | connection_message::REQUEST_FAILURE,
                ) => {}
                // A channel message, or an empty payload the channel layer is
                // better placed to report on than this loop is.
                _ => return Ok(payload),
            }
        }
    }
}

/// Whether the socket last could not make progress.
///
/// The channel layer maps every transport failure onto one
/// `ChannelError::Transport`, so a retryable `WouldBlock` and a dead connection
/// arrive as the same value. The socket is the only place that still knows which
/// happened, so the flag it sets is what the duplex classifies on.
#[derive(Clone, Debug, Default)]
struct WouldBlock(Arc<AtomicBool>);

impl WouldBlock {
    /// Clears the record so the next classification is about one operation.
    fn arm(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Returns and clears the record.
    fn take(&self) -> bool {
        self.0.swap(false, Ordering::AcqRel)
    }
}

/// A socket that records when it could not make progress.
struct Socket {
    inner: StdTcpStream,
    would_block: Arc<AtomicBool>,
}

impl Read for Socket {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.would_block.store(true, Ordering::Release);
                Err(error)
            }
            other => other,
        }
    }
}

impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.inner.write(bytes) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.would_block.store(true, Ordering::Release);
                Err(error)
            }
            other => other,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// What one attempt to move bytes in or out achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Progress {
    /// Something changed; try again.
    Moved,
    /// Nothing is available right now.
    Blocked,
    /// The remote closed its side.
    Closed,
}

/// One `docker system dial-stdio` exec request, as a byte duplex.
struct SessionDuplex {
    sessions: ClientSessions<ConnectionOnly<ClientTransport<Socket>>>,
    session: ChannelId,
    /// Readable/writable interest for the socket behind the transport.
    readiness: TcpStream,
    /// The shared `WouldBlock` record.
    would_block: WouldBlock,
    /// Decoded `SSH_MSG_CHANNEL_DATA` not yet handed to the caller.
    inbound: Vec<u8>,
    /// How far into `inbound` the caller has read, so granted bytes are counted
    /// once.
    drained: usize,
    /// Inbound bytes consumed but not yet credited back to the remote.
    pending_grant: u32,
    /// Whether the remote has signalled end of input.
    at_eof: bool,
}

impl SessionDuplex {
    /// Dispatches one inbound event, classifying a `WouldBlock` as `Blocked`.
    fn dispatch(&mut self) -> Result<Progress, Error> {
        self.would_block.arm();
        match self.sessions.dispatch_one() {
            Ok(SessionEvent::Data { data, .. }) => {
                self.inbound.extend_from_slice(&data);
                Ok(Progress::Moved)
            }
            // The channel was already confirmed before the `exec` was sent, so a
            // rejection here means the remote took it back. It is a failure of
            // the connection rather than something to retry.
            Ok(SessionEvent::OpenRejected {
                reason,
                description,
                ..
            }) => Err(Error::transport(format!(
                "the remote host rejected the SSH session channel: reason {reason}, {}",
                String::from_utf8_lossy(&description)
            ))),
            Ok(SessionEvent::Eof { .. } | SessionEvent::Close { .. }) => {
                self.at_eof = true;
                Ok(Progress::Closed)
            }
            // Everything else the peer sends on a session channel is
            // informational for this duplex: a `WindowAdjusted` (which a write
            // is waiting for), a `global request`, an `env` reply, or the
            // `exit-status` the `dial-stdio` process sends as it ends. None of
            // them carries Engine bytes and none of them is an error here.
            Ok(_) => Ok(Progress::Moved),
            Err(_) if self.would_block.take() => Ok(Progress::Blocked),
            Err(error) => Err(Error::transport(format!(
                "the SSH session channel failed: {error}"
            ))),
        }
    }

    /// Writes at most one channel data packet.
    fn write(&mut self, bytes: &[u8]) -> Result<Progress, Error> {
        self.would_block.arm();
        let session = self.session;
        match self.sessions.send_data(session, bytes) {
            Ok(_) => Ok(Progress::Moved),
            Err(_) if self.would_block.take() => Ok(Progress::Blocked),
            Err(error) => Err(Error::transport(format!(
                "writing the Engine request over SSH failed: {error}"
            ))),
        }
    }

    /// The remote's remaining receive window and maximum packet size.
    fn limits(&self) -> (u32, u32) {
        self.sessions
            .connection()
            .channel(self.session)
            .map_or((0, 0), |state| {
                (state.remote_window(), state.remote_maximum_packet_size())
            })
    }

    /// Credits the remote with room for bytes already handed to the caller.
    ///
    /// The credit is remembered rather than dropped when the socket cannot take
    /// it: `increase_local_window` only counts a window it actually sent, so
    /// retrying with the same byte count is correct, and dropping the amount
    /// would stall the stream at the window boundary with nothing to show for
    /// it.
    fn credit(&mut self, bytes: u32) {
        self.pending_grant = self.pending_grant.saturating_add(bytes);
    }

    /// Sends as much of the pending credit as the socket will take.
    ///
    /// Returns `false` when the credit could not be sent, which is not an
    /// error: it means the socket is not writable yet.
    fn flush_credit(&mut self) -> Result<bool, Error> {
        if self.pending_grant == 0 {
            return Ok(true);
        }
        self.would_block.arm();
        let bytes = self.pending_grant;
        match self.sessions.increase_local_window(self.session, bytes) {
            Ok(_) => {
                self.pending_grant = 0;
                Ok(true)
            }
            Err(_) if self.would_block.take() => Ok(false),
            Err(error) => Err(Error::transport(format!(
                "the SSH session window could not be extended: {error}"
            ))),
        }
    }
}

impl AsyncRead for SessionDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut future = std::pin::pin!(poll_fn(|context| {
            loop {
                if this.drained < this.inbound.len() {
                    let count = buffer.remaining().min(this.inbound.len() - this.drained);
                    let start = this.drained;
                    buffer.put_slice(&this.inbound[start..start + count]);
                    this.drained += count;
                    // Credited as the bytes leave the buffer rather than as they
                    // arrive: the remote may not send its next packet until the
                    // window allows it, so crediting on arrival would stall any
                    // response larger than one window at exactly that boundary.
                    this.credit(u32::try_from(count).unwrap_or(u32::MAX));
                    return Poll::Ready(Ok(()));
                }
                if this.at_eof {
                    return Poll::Ready(Ok(()));
                }
                // The credit is sent before anything is read, because a remote
                // that is waiting for it is a remote that will send nothing.
                match this.flush_credit() {
                    Ok(true) => {}
                    Ok(false) => {
                        await_ready!(context, this, Interest::WRITABLE);
                        continue;
                    }
                    Err(error) => return Poll::Ready(Err(io_error(&error))),
                }
                match this.dispatch() {
                    Ok(Progress::Moved | Progress::Closed) => {}
                    Ok(Progress::Blocked) => {
                        await_ready!(context, this, Interest::READABLE);
                    }
                    Err(error) => return Poll::Ready(Err(io_error(&error))),
                }
            }
        }));
        future.as_mut().poll(context)
    }
}

impl AsyncWrite for SessionDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut future = std::pin::pin!(poll_fn(|context| {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            loop {
                if this.at_eof {
                    return Poll::Ready(Err(closed("before the request was written")));
                }
                // One channel data packet carries at most the remote's maximum
                // packet size, and writing less than the caller offered is
                // permitted, so a large buffer is chunked rather than refused.
                let (window, maximum) = this.limits();
                let maximum = usize::try_from(maximum).unwrap_or(0);
                if maximum == 0 {
                    return Poll::Ready(Err(closed("the session has no open channel")));
                }
                let wanted = bytes.len().min(maximum);
                if wanted <= usize::try_from(window).unwrap_or(0) {
                    match this.write(&bytes[..wanted]) {
                        Ok(Progress::Moved) => return Poll::Ready(Ok(wanted)),
                        Ok(Progress::Blocked) => {
                            await_ready!(context, this, Interest::WRITABLE);
                        }
                        Ok(Progress::Closed) => {
                            return Poll::Ready(Err(closed("while writing the request")));
                        }
                        Err(error) => return Poll::Ready(Err(io_error(&error))),
                    }
                    continue;
                }
                // The remote window is exhausted, or the pending credit could
                // not be sent. Both are answered by a later event or a writable
                // socket, so inbound events are pumped rather than waited on
                // separately.
                match this.flush_credit() {
                    Ok(true) => {}
                    Ok(false) => {
                        await_ready!(context, this, Interest::WRITABLE);
                        continue;
                    }
                    Err(error) => return Poll::Ready(Err(io_error(&error))),
                }
                match this.dispatch() {
                    Ok(Progress::Moved | Progress::Closed) => {}
                    Ok(Progress::Blocked) => {
                        await_ready!(context, this, Interest::WRITABLE);
                    }
                    Err(error) => return Poll::Ready(Err(io_error(&error))),
                }
            }
        }));
        future.as_mut().poll(context)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // A channel data packet is written whole or not at all, so there is
        // nothing half-written here to flush. That is why this can answer
        // without touching the transport.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Closing the local socket *is* the cancellation, and it happens when
        // the transport drops this duplex: the `Socket` inside the SSH transport
        // is a `std::net::TcpStream`, and dropping it closes the descriptor. The
        // remote `docker system dial-stdio` then sees its standard input close
        // and exits, which is the disconnect the daemon observes. There is no
        // message to send for that, so there is nothing to do here.
        Poll::Ready(Ok(()))
    }
}

/// Waits for one readiness direction and consumes the edge.
///
/// The edge has to be consumed. Leaving it set makes every later poll return
/// immediately, so the loop that called this would spin for the rest of the
/// request. The consumption happens through `try_io` with an infallible body,
/// which is tokio's own way of saying "I have taken the readiness edge"; if the
/// socket turned out not to be ready after all, `try_io` leaves the edge set and
/// the next readiness event re-arms this wait instead of spinning on it.
fn wait_ready(
    context: &mut Context<'_>,
    readiness: &mut TcpStream,
    interest: Interest,
) -> Poll<std::io::Result<()>> {
    match readiness.poll_read_ready(context) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => {
            let _cleared = readiness.try_io(interest, || Ok(()));
            Poll::Ready(Ok(()))
        }
    }
}

/// The I/O error for a session the remote has closed.
fn closed(when: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        format!("the Engine closed the SSH session {when}"),
    )
}

/// Converts a crate error into the I/O error the async traits speak.
fn io_error(error: &Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

/// Wraps a connect, handshake, or session failure with the target it happened
/// against.
fn transport_error(what: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::transport(format!("failed to {what}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::Ordering;

    use super::{ManagedSshOptions, WouldBlock, managed_ssh_target};
    use crate::SshIdentity;
    use crate::raw::RawTarget;

    /// A complete endpoint, as the starting point for the cases below.
    fn options(identity: SshIdentity) -> Result<ManagedSshOptions, crate::Error> {
        ManagedSshOptions::from_endpoint(
            "ssh://deploy@example.test:2222",
            identity,
            Some(Path::new("/keys/known_hosts")),
        )
    }

    fn key() -> SshIdentity {
        SshIdentity::KeyFile(Path::new("/keys/id_ed25519").to_path_buf())
    }

    /// A missing login name and a missing known-hosts file are each refused with
    /// their own reason, because a caller who supplied one of the two needs to
    /// be told which is absent.
    ///
    /// A credential is not among them any more: a password is a credential, and
    /// refusing the description without one would report a missing password as a
    /// malformed endpoint.
    #[test]
    fn a_managed_endpoint_needs_a_user_and_a_known_hosts_file() {
        assert!(
            ManagedSshOptions::from_endpoint("ssh://example.test", key(), Some(Path::new("/h")))
                .is_err_and(|error| error.to_string().contains("named user")),
            "an endpoint naming no login user was accepted"
        );
        assert!(
            ManagedSshOptions::from_endpoint("ssh://deploy@example.test", key(), None)
                .is_err_and(|error| error.to_string().contains("known-hosts")),
            "an endpoint with no known-hosts file was accepted"
        );
        assert!(
            options(SshIdentity::Password(crate::SshSecret::new("x"))).is_ok(),
            "a password credential did not build a description"
        );
    }

    #[test]
    fn a_managed_endpoint_becomes_a_stream_target() {
        let options = options(key()).expect("a complete managed endpoint");

        assert_eq!(options.host, "example.test");
        assert_eq!(options.port, 2222);
        assert_eq!(options.user, "deploy");
        // The known-hosts token, not the bare host: a `host:port` spelling is a
        // hostname with a colon in it, which no known-hosts line contains.
        assert_eq!(options.host_token, "[example.test]:2222");

        let target = managed_ssh_target(options);
        assert!(matches!(target, RawTarget::Stream { .. }));
    }

    /// The flag is the only thing that tells a retryable stall from a dead
    /// connection, because the channel layer erases the difference.
    #[test]
    fn a_would_block_is_recorded_once_and_taken_once() {
        let record = WouldBlock::default();
        assert!(!record.take(), "nothing was recorded yet");

        record.0.store(true, Ordering::Release);
        assert!(record.take(), "a recorded stall is taken");
        assert!(!record.take(), "and it is not taken twice");

        record.0.store(true, Ordering::Release);
        record.arm();
        assert!(
            !record.take(),
            "arming clears the previous operation's stall"
        );
    }
}
