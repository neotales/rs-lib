//! Repository-owned Hyper/OpenSSH transport for Docker SSH endpoints.
//!
//! Bollard 0.21.1 exposes a custom transport hook, but its built-in SSH
//! connector removes the `ssh://` scheme before calling `openssh`. The
//! `openssh` destination parser only extracts a user and port while the
//! scheme is present. This connector deliberately restores the scheme before
//! resolving the destination so an endpoint such as
//! `ssh://deploy@example.test:2222` becomes an explicit `-p 2222` argument.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bollard::{BollardRequest, ClientVersion, Docker};
use hyper::Uri;
use hyper::rt::{Read, Write};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openssh::{Child, ChildStdin, ChildStdout, KnownHosts, Session, SessionBuilder, Stdio};
use tower_service::Service;

const SSH_SCHEME: &str = "ssh";

/// The connector used by the repository-owned SSH transport.
#[derive(Clone, Debug)]
pub(crate) struct SshConnector {
    identity_path: Option<String>,
    known_hosts_path: Option<String>,
}

impl SshConnector {
    pub(crate) fn new(identity_path: Option<String>, known_hosts_path: Option<String>) -> Self {
        Self {
            identity_path,
            known_hosts_path,
        }
    }
}

/// An SSH-backed HTTP connection whose bytes are the remote Docker
/// `dial-stdio` process.
pub(crate) struct SshStream {
    // Keeping the child alive owns the local OpenSSH process. Its Drop
    // implementation terminates that local process when the Hyper connection
    // is cancelled or dropped. It intentionally does not claim to terminate
    // the remote process.
    _child: Child<Arc<Session>>,
    stdin: Option<TokioIo<ChildStdin>>,
    stdout: TokioIo<ChildStdout>,
}

impl SshStream {
    fn stdin(self: Pin<&mut Self>) -> io::Result<Pin<&mut TokioIo<ChildStdin>>> {
        self.get_mut()
            .stdin
            .as_mut()
            .map(Pin::new)
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    fn stdout(self: Pin<&mut Self>) -> Pin<&mut TokioIo<ChildStdout>> {
        Pin::new(&mut self.get_mut().stdout)
    }
}

impl Read for SshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.stdout().poll_read(cx, buffer)
    }
}

impl Write for SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stdin()?.poll_write(cx, buffer)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.stdin()?.poll_write_vectored(cx, buffers)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stdin()?.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().stdin()?.poll_shutdown(cx))?;
        drop(self.get_mut().stdin.take());
        Poll::Ready(Ok(()))
    }
}

impl Connection for SshStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

fn ssh_destination(destination: &Uri) -> Result<String, openssh::Error> {
    let authority = match destination.scheme() {
        Some(scheme) if scheme == SSH_SCHEME => destination
            .authority()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing SSH authority")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid SSH scheme {:?}", destination.scheme()),
        )),
    }
    .map_err(openssh::Error::Connect)?;

    // Hyper supplies only the authority to a connector in the built-in
    // Bollard path. Reconstruct the URI before resolving it:
    // `openssh::SessionBuilder::resolve` recognizes `user` and `port` only
    // for an `ssh://...` destination.
    Ok(format!("{SSH_SCHEME}://{authority}"))
}

impl Service<Uri> for SshConnector {
    type Response = SshStream;
    type Error = openssh::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let identity_path = self.identity_path.clone();
        let known_hosts_path = self.known_hosts_path.clone();

        Box::pin(async move {
            let ssh_destination = ssh_destination(&destination)?;
            let mut builder = SessionBuilder::default();
            builder.known_hosts_check(KnownHosts::Add);
            if let Some(path) = identity_path {
                builder.keyfile(path);
            }
            if let Some(path) = known_hosts_path {
                builder.user_known_hosts_file(path);
            }

            let (builder, destination) = builder.resolve(&ssh_destination);
            let tempdir = builder.launch_master(destination).await?;
            let session = Arc::new(Session::new_process_mux(tempdir));
            let mut child = session
                .arc_command("docker")
                .arg("system")
                .arg("dial-stdio")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .await?;

            let stdin = child.stdin().take().ok_or_else(|| {
                openssh::Error::Connect(io::Error::other("OpenSSH child has no stdin"))
            })?;
            let stdout = child.stdout().take().ok_or_else(|| {
                openssh::Error::Connect(io::Error::other("OpenSSH child has no stdout"))
            })?;

            Ok(SshStream {
                stdin: Some(TokioIo::new(stdin)),
                stdout: TokioIo::new(stdout),
                _child: child,
            })
        })
    }
}

/// Builds a Bollard client backed by the corrected SSH connector.
pub(crate) fn connect(
    endpoint: &str,
    timeout_seconds: u64,
    identity_path: Option<String>,
    known_hosts_path: Option<String>,
    client_version: &ClientVersion,
) -> Result<Docker, bollard::errors::Error> {
    let connector = SshConnector::new(identity_path, known_hosts_path);
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let client = Arc::new(client);

    let transport = move |request: BollardRequest| {
        let client = Arc::clone(&client);
        Box::pin(async move {
            client
                .request(request)
                .await
                .map_err(bollard::errors::Error::from)
        }) as Pin<Box<dyn Future<Output = _> + Send>>
    };

    Docker::connect_with_custom_transport(
        transport,
        Some(endpoint.to_owned()),
        timeout_seconds,
        client_version,
    )
}

#[cfg(test)]
mod tests {
    use hyper::Uri;

    use super::ssh_destination;

    #[test]
    fn preserves_ssh_authority_for_openssh_resolution() {
        let destination = Uri::from_static("ssh://deploy@example.test:2222/v1.53/_ping");

        assert_eq!(
            ssh_destination(&destination).expect("valid SSH destination"),
            "ssh://deploy@example.test:2222"
        );
    }
}
