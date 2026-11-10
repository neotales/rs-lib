//! The `docker system dial-stdio` command, and the native `ssh` binary that
//! carries it.
//!
//! A remote Docker daemon has no socket to dial. Docker's answer, documented in
//! its own CLI and reproduced by every implementation, is to run a command on
//! the far end whose standard streams *are* an Engine HTTP connection:
//! `docker system dial-stdio`. The local end then speaks HTTP/1.1 over that
//! pair and never learns it is not a socket.
//!
//! Two mechanisms open that pair here, and both hand the same bytes to the same
//! owned transport:
//!
//! * this module, which spawns the system `ssh` binary;
//! * [`super::ssh_neotales`], which opens an SSH session with the
//!   repository's own `neotales-ssh` crate.
//!
//! Neither one has its own status mapping, stream decoder, or path escaping.
//! Both produce a [`StreamFactory`], and the transport above them is
//! unchanged — which is the point. The two mechanisms differ in *how* the bytes
//! arrive and in nothing else.
//!
//! # Why the factory is per request
//!
//! `docker system dial-stdio` is a one-request-per-process shape. Docker's CLI
//! and the .NET reference both queue concurrent requests behind a single
//! connection for the native backend, and the reason is the same one the owned
//! transport has: it opens a connection per request. So a factory here opens a
//! *new* `ssh` process, or a *new* SSH session, for every request, and the
//! duplex is dropped with the response. Holding one and handing it out again
//! would serve exactly one request and then fail on the second.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio as ProcessStdio;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, Command};

use crate::Error;
use crate::raw::{Duplex, RawTarget, StreamFactory};

/// The remote command whose standard streams are an Engine HTTP connection.
///
/// The three arguments are passed separately rather than as one string so no
/// shell is involved on either end: the remote `sshd` hands the bytes to the
/// user's login shell, and Docker's own CLI does the same, so the command is
/// spelled the way a user would type it.
pub(crate) const DIAL_STDIO: [&str; 3] = ["docker", "system", "dial-stdio"];

/// The `Host` header value sent to a `dial-stdio` peer.
///
/// A socket target sends `localhost` and a TCP target sends its own authority,
/// because those have an authority. A `dial-stdio` peer has none: it is a
/// process attached to a channel, and the Engine ignores the value. `localhost`
/// is therefore the consistent choice with the rest of [`RawTarget`], and it is
/// a value a caller can override by naming its own
/// [`RawTarget::Stream`] rather than taking this one.
///
/// The .NET reference sends `http://docker/` for a `unix`, `npipe`, or `ssh`
/// endpoint, so its `Host` value differs here. That difference is stated rather
/// than reconciled: the Engine does not read the header, and matching it would
/// mean this crate's own two targets disagree with each other.
pub(crate) const DIAL_STDIO_AUTHORITY: &str = "localhost";

/// The parts of an `ssh://` endpoint an SSH mechanism needs.
///
/// `Endpoint::Ssh` keeps the address as the URL a caller wrote, so the pieces
/// have to be recovered from it. `url::Url` is already a dependency for the
/// `Host` header, and parsing the same string with a second hand-rolled parser
/// is the kind of thing that disagrees about percent-encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SshDestination {
    /// The login name, when the endpoint named one.
    pub(crate) user: Option<String>,
    /// The host to connect to.
    pub(crate) host: String,
    /// The TCP port, defaulting to 22.
    pub(crate) port: u16,
    /// The host token OpenSSH and `neotales-ssh` both use for a known-hosts
    /// lookup, spelled the OpenSSH way.
    pub(crate) host_token: String,
}

impl SshDestination {
    /// Reads the destination out of an `ssh://` address.
    ///
    /// # Errors
    ///
    /// Returns an error when the address does not parse or does not name a
    /// host. The port falls back to 22, which is the IANA-assigned SSH port and
    /// what every other implementation in this repository assumes.
    pub(crate) fn parse(address: &str) -> Result<Self, Error> {
        let url = url::Url::parse(address).map_err(|error| {
            Error::invalid_input(format!("invalid SSH endpoint '{address}': {error}"))
        })?;
        if url.scheme() != "ssh" {
            return Err(Error::invalid_input(format!(
                "endpoint '{address}' is not an ssh:// endpoint"
            )));
        }
        let Some(host) = url.host_str() else {
            return Err(Error::invalid_input(format!(
                "SSH endpoint '{address}' names no host"
            )));
        };
        let port = url.port().unwrap_or(22);
        Ok(Self {
            user: non_empty(url.username()),
            host: host.to_owned(),
            port,
            // The known-hosts token is `[host]:port` for a non-default port and
            // a bare `host` otherwise, which is OpenSSH's own spelling and the
            // one `neotales_ssh::known_hosts` implements.
            host_token: if port == 22 {
                host.to_owned()
            } else {
                format!("[{host}]:{port}")
            },
        })
    }

    /// The OpenSSH destination argument: `[user@]host`.
    #[must_use]
    pub(crate) fn argument(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.host.clone(),
            |user| format!("{user}@{host}", host = self.host),
        )
    }
}

/// Returns `Some` for a non-empty slice, and `None` for an empty one.
fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

/// How the native `ssh` binary should be invoked.
///
/// A struct rather than a parameter list, because this is the shape most likely
/// to grow: OpenSSH itself has a dozen options a caller may need, and adding
/// the seventh positional parameter is what makes a call unreadable. Every
/// field has a defined absence — `None` means "do not pass the flag", never
/// "pass a default" — because passing `-p 22` and omitting `-p` are
/// observably different to `ssh_config` and to a user's `~/.ssh/config`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeSshOptions {
    /// The `ssh` executable to run.
    pub(crate) program: String,
    /// The already-assembled `[user@]host` destination.
    pub(crate) destination: String,
    /// An explicit port. Omitted when the endpoint used the default.
    pub(crate) port: Option<u16>,
    /// An identity file passed as `-i`.
    pub(crate) identity_path: Option<PathBuf>,
    /// An OpenSSH configuration file passed as `-F`.
    ///
    /// This is how a caller keeps OpenSSH's own host-key, identity, proxy, and
    /// multiplexing behaviour without putting any of it in an endpoint URI.
    /// It is the same idea as the .NET reference's
    /// `DockerClientOptions.NativeSshConfigurationFile`.
    pub(crate) config_file: Option<PathBuf>,
}

impl NativeSshOptions {
    /// Returns the full argument vector, program excluded.
    ///
    /// The order is fixed and matches the .NET reference's
    /// `CreateNativeSshStartInfo`: `-T`, then `-F`, then `-p`, then `--`, then
    /// the destination, then the command.
    ///
    /// `-T` is not optional. Without it `ssh` asks for a pseudo-terminal when
    /// stdin is not one, and a pty translates every `\n` the daemon writes into
    /// `\r\n` and mangles anything that looks like a line editor key. The
    /// Engine's HTTP responses are binary — an 8-byte frame header precedes
    /// every multiplexed stream — so a pty does not merely reformat the
    /// stream, it corrupts it. `docker` itself passes `-T`.
    #[must_use]
    pub(crate) fn arguments(&self) -> Vec<String> {
        let mut arguments = vec!["-T".to_owned()];
        if let Some(config) = &self.config_file {
            arguments.push("-F".to_owned());
            arguments.push(path_argument(config));
        }
        if let Some(identity) = &self.identity_path {
            arguments.push("-i".to_owned());
            arguments.push(path_argument(identity));
        }
        // The default port is left to `ssh_config` and to the user's own
        // configuration, exactly as it is for every other `ssh` invocation.
        if let Some(port) = self.port {
            arguments.push("-p".to_owned());
            arguments.push(port.to_string());
        }
        // `--` ends option parsing, so a destination that begins with a dash
        // is a host name rather than a flag.
        arguments.push("--".to_owned());
        arguments.push(self.destination.clone());
        arguments.extend(DIAL_STDIO.iter().map(|argument| (*argument).to_owned()));
        arguments
    }
}

/// Renders a path for an `ssh` argument.
///
/// A path that is not valid UTF-8 cannot go on a command line as text, and
/// silently dropping it would leave `ssh` reading its own configuration for an
/// identity the caller asked for. `ssh` takes the path as a plain argument, so
/// a lossy rendering is the only option available; it is still better than
/// omitting the flag, and the failure surfaces as `ssh`'s own error naming the
/// path it tried.
fn path_argument(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Builds the owned `RawTarget` for the native `ssh` binary.
///
/// The returned factory spawns one `ssh` process per request. Each duplex owns
/// its child, and dropping the duplex kills the child, so an abandoned request
/// cannot leave an `ssh` process holding a channel to a daemon.
///
/// Everything after the spawn — host key rejection, authentication failure, a
/// remote without Docker — is reported on first use, by the first request,
/// which is where a user sees it against the request they made.
pub(crate) fn native_ssh_target(options: NativeSshOptions) -> RawTarget {
    let authority = DIAL_STDIO_AUTHORITY.to_owned();
    let factory = StreamFactory::new(move || {
        let options = options.clone();
        // Not `async`: a spawn does not wait, and nothing about this duplex
        // becomes usable before the first write reaches the process. Making it
        // a future rather than a value keeps the factory's signature the same
        // as the managed client's, which does have a blocking prologue to wait
        // for, so a caller can swap one for the other without noticing.
        Box::pin(std::future::ready(open(&options)))
    });
    RawTarget::Stream {
        authority,
        open: factory,
    }
}

/// Spawns one `ssh … docker system dial-stdio` and returns its streams.
fn open(options: &NativeSshOptions) -> Result<Box<dyn Duplex>, Error> {
    let mut child = Command::new(&options.program);
    child
        .args(options.arguments())
        .stdin(ProcessStdio::piped())
        .stdout(ProcessStdio::piped())
        // Standard error is inherited rather than piped. `ssh` reports host key
        // rejection, authentication failure, and a missing remote `docker` on
        // standard error, and a piped stream nobody reads is a second deadlock
        // on the same connection. Inheriting puts those words where a user can
        // see them, which is where Docker puts them.
        .stderr(ProcessStdio::inherit())
        // A duplex that is dropped mid-request must not leave the process
        // running. Without this, every cancelled or failed request would leak
        // one `ssh` process holding an SSH channel to the remote daemon.
        .kill_on_drop(true);
    let mut child = child.spawn().map_err(|error| {
        Error::transport(format!(
            "failed to start '{}' for the Engine SSH target: {error}",
            options.program
        ))
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        Error::transport("the 'ssh' process was started without a standard input pipe".to_owned())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        Error::transport("the 'ssh' process was started without a standard output pipe".to_owned())
    })?;
    Ok(Box::new(NativeSshStream {
        stdin,
        stdout,
        _child: child,
    }))
}

/// The standard streams of a running `ssh … docker system dial-stdio`.
struct NativeSshStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    /// Held for the duplex's lifetime and never read.
    ///
    /// It is the ownership of the process, and it is what makes dropping the
    /// duplex cancel the request: `kill_on_drop` was set on the spawn, so
    /// dropping this handle terminates the local `ssh`. Waiting on it would say
    /// nothing the request had not already reported — the Engine's own answer
    /// arrives as bytes on `stdout` — and a duplex that could block on a
    /// process exit would make `poll_shutdown` a place a request hangs.
    _child: Child,
}

impl AsyncRead for NativeSshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stdout).poll_read(context, buffer)
    }
}

impl AsyncWrite for NativeSshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stdin).poll_write(context, bytes)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stdin).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stdin).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::{DIAL_STDIO_AUTHORITY, NativeSshOptions, SshDestination, native_ssh_target};
    use crate::raw::RawTarget;

    #[test]
    fn an_ssh_endpoint_yields_a_user_a_host_and_the_default_port() {
        assert_eq!(
            SshDestination::parse("ssh://deploy@example.test").expect("an ssh endpoint"),
            SshDestination {
                user: Some("deploy".to_owned()),
                host: "example.test".to_owned(),
                port: 22,
                host_token: "example.test".to_owned(),
            }
        );
    }

    #[test]
    fn a_non_default_port_survives_into_the_known_hosts_token() {
        let destination = SshDestination::parse("ssh://deploy@example.test:2222")
            .expect("an ssh endpoint with a port");

        assert_eq!(destination.port, 2222);
        // This is the spelling OpenSSH writes, and the one
        // `neotales_ssh::known_hosts` looks up. A bare `host:port` would be a
        // hostname with a colon in it, which no known-hosts line ever contains.
        assert_eq!(destination.host_token, "[example.test]:2222");
        assert_eq!(destination.argument(), "deploy@example.test");
    }

    #[test]
    fn an_endpoint_without_a_user_connects_as_the_local_user() {
        let destination =
            SshDestination::parse("ssh://example.test").expect("an ssh endpoint without a user");

        assert_eq!(destination.user, None);
        assert_eq!(destination.argument(), "example.test");
    }

    #[test]
    fn an_address_that_is_not_an_ssh_endpoint_is_refused() {
        assert!(SshDestination::parse("tcp://example.test:2375").is_err());
        assert!(SshDestination::parse("not a url").is_err());
    }

    #[test]
    fn the_ssh_arguments_match_dockers_own_invocation() {
        let options = NativeSshOptions {
            program: "ssh".to_owned(),
            destination: "deploy@example.test".to_owned(),
            port: Some(2222),
            identity_path: Some("/keys/id_ed25519".into()),
            config_file: None,
        };

        // `-T` first, then the flags, then `--`, the destination, and the
        // three command words. Anything else and the argument after the
        // destination stops being the command.
        assert_eq!(
            options.arguments(),
            vec![
                "-T",
                "-i",
                "/keys/id_ed25519",
                "-p",
                "2222",
                "--",
                "deploy@example.test",
                "docker",
                "system",
                "dial-stdio",
            ]
        );
    }

    #[test]
    fn the_default_port_is_left_to_ssh_rather_than_passed() {
        let options = NativeSshOptions {
            program: "ssh".to_owned(),
            destination: "deploy@example.test".to_owned(),
            port: None,
            identity_path: None,
            config_file: Some("/etc/ssh/ssh_config".into()),
        };

        // Passing `-p 22` here would override a `Port` in the user's own
        // configuration, which is a behaviour change the caller did not ask
        // for. The port is omitted and `ssh_config` decides.
        assert_eq!(
            options.arguments(),
            vec![
                "-T",
                "-F",
                "/etc/ssh/ssh_config",
                "--",
                "deploy@example.test",
                "docker",
                "system",
                "dial-stdio",
            ]
        );
    }

    #[test]
    fn the_native_target_is_a_stream_target_naming_one_authority() {
        let target = native_ssh_target(NativeSshOptions {
            program: "ssh".to_owned(),
            destination: "deploy@example.test".to_owned(),
            port: None,
            identity_path: None,
            config_file: None,
        });

        assert!(
            matches!(&target, RawTarget::Stream { authority, .. } if authority == DIAL_STDIO_AUTHORITY)
        );
    }
}
