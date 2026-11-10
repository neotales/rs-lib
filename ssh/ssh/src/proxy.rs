//! SSH `ProxyJump` and caller-supplied `ProxyCommand` transport routing.
//!
//! This module never resolves names, opens a socket, or starts a process. The
//! caller supplies every initial stream and every jump dial operation. Once a
//! jump transport is established, later hops are carried by owned
//! `direct-tcpip` channel streams.

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
use std::io::{self, Read, Write};

use neotales_ssh::ClientDirectTcpip;
use neotales_ssh::channel::{ChannelId, ChannelState, ChannelTransport};
use neotales_ssh::direct_tcpip::{DirectTcpipEvent, DirectTcpipTuple};
use neotales_ssh::hostkey::Ed25519PublicKey;
use neotales_ssh::{ClientAuthMethod, ClientConfig, ClientTransport};

/// The default TCP port for a jump or destination host.
pub const DEFAULT_SSH_PORT: u16 = 22;
/// The RFC 4254 direct-tcpip originator address used for proxy channels.
pub const PROXY_ORIGINATOR_ADDRESS: &str = "127.0.0.1";
/// The RFC 4254 direct-tcpip originator port used for proxy channels.
pub const PROXY_ORIGINATOR_PORT: u16 = 0;
/// The maximum encoded byte length accepted for one jump or destination host.
pub const MAX_PROXY_HOST_LENGTH: usize = 255;

/// A caller callback that opens a transport for an expanded `ProxyCommand`.
///
/// This trait object performs only the caller-provided operation. The proxy
/// module never interprets the command as a process or launches it.
pub type ProxyCommandOpener<'stream, S> = dyn FnMut(&str) -> io::Result<S> + 'stream;

/// A bounded proxy-routing failure whose values contain no supplied secret.
///
/// Stream, authentication, and callback errors are deliberately reduced to
/// fixed variants. In particular, this type never retains a password, private
/// key, expanded command, destination user, or host from the failed route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyError {
    /// A comma-separated jump-list item was empty.
    EmptyJumpItem,
    /// A jump username was empty or contained whitespace, NUL, or `@`.
    InvalidJumpUser,
    /// A jump host was empty or contained whitespace, NUL, or invalid brackets.
    InvalidJumpHost,
    /// A colon-containing IPv6 host was not enclosed in brackets.
    MissingIpv6Bracket,
    /// A jump port was empty, non-decimal, zero, or above 65535.
    InvalidJumpPort,
    /// The destination host, user, or port was not valid for this transport.
    InvalidDestination,
    /// `ProxyCommand` was configured but no caller stream-opening callback was supplied.
    ProxyCommandUnsupported,
    /// The caller dial callback did not provide a stream.
    DialFailed,
    /// The caller `ProxyCommand` callback did not provide a stream.
    ProxyCommandOpenFailed,
    /// A client handshake failed on a jump or the destination.
    HandshakeFailed,
    /// User authentication failed on a jump or the destination.
    AuthenticationFailed,
    /// A jump server rejected a direct-tcpip open.
    ChannelOpenRejected,
    /// A direct-tcpip stream received an invalid or out-of-order event.
    ChannelProtocol,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyJumpItem => "SSH proxy jump list contains an empty item",
            Self::InvalidJumpUser => "SSH proxy jump username is invalid",
            Self::InvalidJumpHost => "SSH proxy jump host is invalid",
            Self::MissingIpv6Bracket => "SSH proxy IPv6 host must use brackets",
            Self::InvalidJumpPort => "SSH proxy jump port is invalid",
            Self::InvalidDestination => "SSH proxy destination is invalid",
            Self::ProxyCommandUnsupported => {
                "SSH ProxyCommand requires a caller-provided stream opener"
            }
            Self::DialFailed => "SSH proxy dial callback failed",
            Self::ProxyCommandOpenFailed => "SSH proxy command stream callback failed",
            Self::HandshakeFailed => "SSH proxy client handshake failed",
            Self::AuthenticationFailed => "SSH proxy user authentication failed",
            Self::ChannelOpenRejected => "SSH proxy direct-tcpip open was rejected",
            Self::ChannelProtocol => "SSH proxy direct-tcpip channel protocol failed",
        })
    }
}

impl std::error::Error for ProxyError {}

/// One validated entry in a comma-separated `ProxyJump` list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpHost {
    user: Option<String>,
    host: String,
    port: u16,
}

impl JumpHost {
    /// Creates one validated jump endpoint.
    ///
    /// A missing username remains `None`; the connection falls back to the
    /// destination username only if the caller supplies jump authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::InvalidJumpUser`] for an empty username or one
    /// containing whitespace, NUL, or `@`, and [`ProxyError::InvalidJumpHost`]
    /// for an empty, oversized, whitespace-containing, or NUL-containing host.
    pub fn new(user: Option<&str>, host: &str, port: u16) -> Result<Self, ProxyError> {
        if port == 0 {
            return Err(ProxyError::InvalidJumpPort);
        }
        validate_user(user, ProxyError::InvalidJumpUser)?;
        validate_host(host, ProxyError::InvalidJumpHost)?;
        Ok(Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        })
    }

    /// Returns the explicit jump username, if one was present.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns the exact jump host text without IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the jump TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// The destination and optional `ProxyJump` or `ProxyCommand` configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyTarget<'target> {
    host: &'target str,
    port: u16,
    user: &'target str,
    proxy_jump: Option<&'target str>,
    proxy_command: Option<&'target str>,
}

impl<'target> ProxyTarget<'target> {
    /// Creates a destination route.
    ///
    /// `proxy_command` takes precedence over `proxy_jump` when both are
    /// present. The command is only expanded and passed to a caller callback;
    /// this module never executes it.
    #[must_use]
    pub const fn new(
        host: &'target str,
        port: u16,
        user: &'target str,
        proxy_jump: Option<&'target str>,
        proxy_command: Option<&'target str>,
    ) -> Self {
        Self {
            host,
            port,
            user,
            proxy_jump,
            proxy_command,
        }
    }

    /// Returns the destination host.
    #[must_use]
    pub const fn host(&self) -> &'target str {
        self.host
    }

    /// Returns the destination TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the destination username.
    #[must_use]
    pub const fn user(&self) -> &'target str {
        self.user
    }

    /// Returns the configured comma-separated `ProxyJump` value.
    #[must_use]
    pub const fn proxy_jump(&self) -> Option<&'target str> {
        self.proxy_jump
    }

    /// Returns the configured `ProxyCommand` text.
    #[must_use]
    pub const fn proxy_command(&self) -> Option<&'target str> {
        self.proxy_command
    }
}

/// Expands only `%h`, `%p`, `%r`, and `%%` in a `ProxyCommand` string.
///
/// Expansion is a single left-to-right pass. Unknown escapes such as `%q` are
/// preserved literally, and replacement text is never expanded recursively.
#[must_use]
pub fn expand_proxy_command(command: &str, host: &str, port: u16, user: &str) -> String {
    let mut expanded = String::with_capacity(command.len());
    let mut characters = command.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '%' {
            expanded.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            expanded.push('%');
            break;
        };
        match escaped {
            'h' => expanded.push_str(host),
            'p' => {
                let _ = write!(expanded, "{port}");
            }
            'r' => expanded.push_str(user),
            '%' => expanded.push('%'),
            other => {
                expanded.push('%');
                expanded.push(other);
            }
        }
    }
    expanded
}

/// Parses a comma-separated `ProxyJump` list.
///
/// Accepted entries are `host`, `host:port`, `user@host`, `user@host:port`,
/// `[ipv6]`, `[ipv6]:port`, `user@[ipv6]`, and `user@[ipv6]:port`. The default
/// port is 22. Empty items, missing IPv6 brackets, whitespace or NUL in a user
/// or host, and ports outside `1..=65535` are rejected.
///
/// # Errors
///
/// Returns a bounded [`ProxyError`] for any malformed list item.
pub fn parse_jump_list(value: &str) -> Result<Vec<JumpHost>, ProxyError> {
    let mut hosts = Vec::new();
    for item in value.split(',') {
        if item.is_empty() {
            return Err(ProxyError::EmptyJumpItem);
        }
        let (user, endpoint) = match item.split_once('@') {
            Some((user, endpoint)) => {
                if endpoint.contains('@') {
                    return Err(ProxyError::InvalidJumpUser);
                }
                (Some(user), endpoint)
            }
            None => (None, item),
        };
        let (host, port) = parse_endpoint(endpoint)?;
        hosts.push(JumpHost::new(user, host, port)?);
    }
    Ok(hosts)
}

/// A connected destination client that owns its complete proxy route.
///
/// Dropping this value drops the destination transport and every preceding
/// jump transport. No hop is detached to a background thread.
pub struct ProxyClient<'stream> {
    transport: ClientTransport<ProxyStream<'stream>>,
}

impl<'stream> ProxyClient<'stream> {
    /// Returns the destination SSH transport.
    #[must_use]
    pub const fn transport(&self) -> &ClientTransport<ProxyStream<'stream>> {
        &self.transport
    }

    /// Returns the mutable destination SSH transport.
    pub const fn transport_mut(&mut self) -> &mut ClientTransport<ProxyStream<'stream>> {
        &mut self.transport
    }

    /// Consumes the client and returns its destination transport.
    ///
    /// The returned transport still owns the full direct-tcpip chain.
    #[must_use]
    pub fn into_inner(self) -> ClientTransport<ProxyStream<'stream>> {
        self.transport
    }

    /// Returns whether the destination handshake completed.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.transport.is_established()
    }
}

impl fmt::Debug for ProxyClient<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyClient")
            .field("is_established", &self.is_established())
            .finish_non_exhaustive()
    }
}

/// An owned byte stream for a proxied destination transport.
///
/// Values are created only by [`connect`]. A direct value owns the caller's
/// dial or `ProxyCommand` stream; a channel value owns all preceding SSH hop
/// transports through nested `ClientDirectTcpip` endpoints.
pub struct ProxyStream<'stream> {
    inner: ProxyStreamInner<'stream>,
}

impl<'stream> ProxyStream<'stream> {
    fn direct(stream: impl Read + Write + 'stream) -> Self {
        Self {
            inner: ProxyStreamInner::Direct(Box::new(stream)),
        }
    }

    fn channel(stream: DirectTcpipStream<'stream>) -> Self {
        Self {
            inner: ProxyStreamInner::Channel(stream),
        }
    }
}

impl fmt::Debug for ProxyStream<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let route = match &self.inner {
            ProxyStreamInner::Direct(_) => "direct",
            ProxyStreamInner::Channel(_) => "direct-tcpip",
        };
        formatter
            .debug_struct("ProxyStream")
            .field("route", &route)
            .finish_non_exhaustive()
    }
}

impl Read for ProxyStream<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            ProxyStreamInner::Direct(stream) => stream.read(target),
            ProxyStreamInner::Channel(stream) => stream.read(target),
        }
    }
}

impl Write for ProxyStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            ProxyStreamInner::Direct(stream) => stream.write(bytes),
            ProxyStreamInner::Channel(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            ProxyStreamInner::Direct(stream) => stream.flush(),
            ProxyStreamInner::Channel(stream) => stream.flush(),
        }
    }
}

enum ProxyStreamInner<'stream> {
    Direct(Box<dyn ReadWrite + 'stream>),
    Channel(DirectTcpipStream<'stream>),
}

trait ReadWrite: Read + Write {}

impl<T> ReadWrite for T where T: Read + Write + ?Sized {}

struct OwnedChannelTransport<'stream> {
    inner: Box<dyn ChannelTransport + 'stream>,
}

impl<'stream> OwnedChannelTransport<'stream> {
    fn new<T>(transport: T) -> Self
    where
        T: ChannelTransport + 'stream,
    {
        Self {
            inner: Box::new(transport),
        }
    }
}

impl ChannelTransport for OwnedChannelTransport<'_> {
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.inner.write_channel_payload(payload)
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.inner.read_channel_payload()
    }
}

type HopChannels<'stream> = ClientDirectTcpip<OwnedChannelTransport<'stream>>;

struct DirectTcpipStream<'stream> {
    channels: HopChannels<'stream>,
    channel: ChannelId,
    incoming: VecDeque<u8>,
    eof: bool,
    closed: bool,
}

impl<'stream> DirectTcpipStream<'stream> {
    fn open<T>(transport: T, host: &str, port: u16) -> Result<Self, ProxyError>
    where
        T: ChannelTransport + 'stream,
    {
        let mut channels = ClientDirectTcpip::new(OwnedChannelTransport::new(transport));
        let tuple =
            DirectTcpipTuple::new(host, port, PROXY_ORIGINATOR_ADDRESS, PROXY_ORIGINATOR_PORT)
                .map_err(|_error| ProxyError::InvalidJumpHost)?;
        let channel = channels
            .open(&tuple)
            .map_err(|_error| ProxyError::ChannelProtocol)?;
        match channels
            .dispatch_one()
            .map_err(|_error| ProxyError::ChannelProtocol)?
        {
            DirectTcpipEvent::Opened { channel: opened } if opened == channel => Ok(Self {
                channels,
                channel,
                incoming: VecDeque::new(),
                eof: false,
                closed: false,
            }),
            DirectTcpipEvent::OpenRejected { .. } => Err(ProxyError::ChannelOpenRejected),
            DirectTcpipEvent::Opened { .. }
            | DirectTcpipEvent::WindowAdjusted { .. }
            | DirectTcpipEvent::Data { .. }
            | DirectTcpipEvent::ExtendedData { .. }
            | DirectTcpipEvent::Eof { .. }
            | DirectTcpipEvent::Close { .. } => Err(ProxyError::ChannelProtocol),
        }
    }

    fn state(&self) -> Result<ChannelState, ProxyError> {
        self.channels
            .connection()
            .channel(self.channel)
            .ok_or(ProxyError::ChannelProtocol)
    }

    fn dispatch_read_event(&mut self) -> io::Result<()> {
        match self
            .channels
            .dispatch_one()
            .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?
        {
            DirectTcpipEvent::Data { channel, data } if channel == self.channel => {
                self.incoming.extend(data);
                Ok(())
            }
            DirectTcpipEvent::ExtendedData { channel, data, .. } if channel == self.channel => {
                // A direct-tcpip stream is one byte stream. SSH extended data
                // (normally session stderr) is not part of that stream, so
                // discard it and immediately return the consumed channel credit.
                if !data.is_empty() {
                    let credit = u32::try_from(data.len())
                        .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
                    self.channels
                        .increase_local_window(self.channel, credit)
                        .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
                }
                Ok(())
            }
            DirectTcpipEvent::WindowAdjusted { channel, .. } if channel == self.channel => Ok(()),
            DirectTcpipEvent::Eof { channel } if channel == self.channel => {
                self.eof = true;
                Ok(())
            }
            DirectTcpipEvent::Close { channel } if channel == self.channel => {
                self.closed = true;
                Ok(())
            }
            DirectTcpipEvent::Opened { .. }
            | DirectTcpipEvent::OpenRejected { .. }
            | DirectTcpipEvent::WindowAdjusted { .. }
            | DirectTcpipEvent::Data { .. }
            | DirectTcpipEvent::ExtendedData { .. }
            | DirectTcpipEvent::Eof { .. }
            | DirectTcpipEvent::Close { .. } => Err(io::Error::other(ProxyError::ChannelProtocol)),
        }
    }

    fn dispatch_write_event(&mut self) -> io::Result<()> {
        match self
            .channels
            .dispatch_one()
            .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?
        {
            DirectTcpipEvent::WindowAdjusted { channel, .. } if channel == self.channel => Ok(()),
            DirectTcpipEvent::Data { channel, data } if channel == self.channel => {
                self.incoming.extend(data);
                Ok(())
            }
            DirectTcpipEvent::ExtendedData { channel, data, .. } if channel == self.channel => {
                if !data.is_empty() {
                    let credit = u32::try_from(data.len())
                        .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
                    self.channels
                        .increase_local_window(self.channel, credit)
                        .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
                }
                Ok(())
            }
            DirectTcpipEvent::Opened { .. }
            | DirectTcpipEvent::OpenRejected { .. }
            | DirectTcpipEvent::WindowAdjusted { .. }
            | DirectTcpipEvent::Data { .. }
            | DirectTcpipEvent::ExtendedData { .. }
            | DirectTcpipEvent::Eof { .. }
            | DirectTcpipEvent::Close { .. } => Err(io::Error::other(ProxyError::ChannelProtocol)),
        }
    }
}

impl Read for DirectTcpipStream<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        while self.incoming.is_empty() {
            if self.eof || self.closed {
                return Ok(0);
            }
            self.dispatch_read_event()?;
        }

        let count = target.len().min(self.incoming.len());
        let adjustment =
            u32::try_from(count).map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
        self.channels
            .increase_local_window(self.channel, adjustment)
            .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
        let destination = target
            .get_mut(..count)
            .ok_or_else(|| io::Error::other(ProxyError::ChannelProtocol))?;
        for byte in destination {
            *byte = self
                .incoming
                .pop_front()
                .ok_or_else(|| io::Error::other(ProxyError::ChannelProtocol))?;
        }
        Ok(count)
    }
}

impl Write for DirectTcpipStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut written = 0_usize;
        while written < bytes.len() {
            let state = self.state().map_err(io::Error::other)?;
            let remote_window = usize::try_from(state.remote_window())
                .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
            let remote_maximum = usize::try_from(state.remote_maximum_packet_size())
                .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
            if remote_maximum == 0 {
                return Err(io::Error::other(ProxyError::ChannelProtocol));
            }
            let available = bytes.len() - written;
            let count = available.min(remote_maximum).min(remote_window);
            if count == 0 {
                self.dispatch_write_event()?;
                continue;
            }
            let end = written
                .checked_add(count)
                .ok_or_else(|| io::Error::other(ProxyError::ChannelProtocol))?;
            let payload = bytes
                .get(written..end)
                .ok_or_else(|| io::Error::other(ProxyError::ChannelProtocol))?;
            let sent = self
                .channels
                .send_data(self.channel, payload)
                .map_err(|_error| io::Error::other(ProxyError::ChannelProtocol))?;
            if sent != count {
                return Err(io::Error::other(ProxyError::ChannelProtocol));
            }
            written = end;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Connects a destination through `ProxyCommand` or a `ProxyJump` route.
///
/// `dial` is called only for the first jump, or for the destination when no
/// proxy is configured. `jump_auth` is called only after that jump's handshake;
/// returning `None` or an empty method list skips user authentication. Its
/// methods are separate from `destination_auth`, which is used only after the
/// destination handshake. `trust_host_key` is cloned for every hop, including
/// the destination. A configured `ProxyCommand` wins over `ProxyJump` and is
/// passed only to `open_proxy_command`; it is never executed by this module.
///
/// # Errors
///
/// Returns a bounded [`ProxyError`] for invalid route data, unavailable
/// `ProxyCommand` support, caller stream failures, channel-open failure, or a
/// jump or destination handshake/authentication failure. The returned error
/// never includes supplied credentials, commands, users, or hosts.
#[allow(clippy::too_many_lines)]
pub fn connect<'stream, S, D, A, T, E>(
    client_config: &ClientConfig,
    target: &ProxyTarget<'_>,
    destination_auth: &[ClientAuthMethod],
    mut dial: D,
    open_proxy_command: Option<&mut ProxyCommandOpener<'_, S>>,
    mut jump_auth: A,
    trust_host_key: T,
) -> Result<ProxyClient<'stream>, ProxyError>
where
    S: Read + Write + 'stream,
    D: FnMut(&str, u16) -> io::Result<S>,
    A: FnMut(&JumpHost) -> Option<Vec<ClientAuthMethod>>,
    T: Fn(&Ed25519PublicKey) -> Result<(), E> + Clone,
{
    validate_destination(target)?;

    if let Some(command) = target.proxy_command() {
        let Some(opener) = open_proxy_command else {
            return Err(ProxyError::ProxyCommandUnsupported);
        };
        let expanded = expand_proxy_command(command, target.host(), target.port(), target.user());
        let stream = opener(&expanded).map_err(|_error| ProxyError::ProxyCommandOpenFailed)?;
        return connect_destination(
            client_config,
            target,
            destination_auth,
            ProxyStream::direct(stream),
            trust_host_key,
        );
    }

    let jumps = match target.proxy_jump() {
        Some(value) => parse_jump_list(value)?,
        None => Vec::new(),
    };
    if jumps.is_empty() {
        let stream = dial(target.host(), target.port()).map_err(|_error| ProxyError::DialFailed)?;
        return connect_destination(
            client_config,
            target,
            destination_auth,
            ProxyStream::direct(stream),
            trust_host_key,
        );
    }

    let first = jumps.first().ok_or(ProxyError::EmptyJumpItem)?;
    let first_stream = dial(first.host(), first.port()).map_err(|_error| ProxyError::DialFailed)?;
    let mut current = connect_hop(
        client_config,
        ProxyStream::direct(first_stream),
        trust_host_key.clone(),
    )?;
    authenticate_jump(&mut current, first, target.user(), &mut jump_auth)?;

    for hop in jumps.iter().skip(1) {
        let stream =
            DirectTcpipStream::open(OwnedChannelTransport::new(current), hop.host(), hop.port())?;
        current = connect_hop(
            client_config,
            ProxyStream::channel(stream),
            trust_host_key.clone(),
        )?;
        authenticate_jump(&mut current, hop, target.user(), &mut jump_auth)?;
    }

    let destination_stream = DirectTcpipStream::open(
        OwnedChannelTransport::new(current),
        target.host(),
        target.port(),
    )?;
    connect_destination(
        client_config,
        target,
        destination_auth,
        ProxyStream::channel(destination_stream),
        trust_host_key,
    )
}

fn connect_hop<'stream, T, E>(
    client_config: &ClientConfig,
    stream: ProxyStream<'stream>,
    trust_host_key: T,
) -> Result<ClientTransport<ProxyStream<'stream>>, ProxyError>
where
    T: Fn(&Ed25519PublicKey) -> Result<(), E>,
{
    neotales_ssh::ClientConfig::connect(client_config, stream, trust_host_key)
        .map_err(|_error| ProxyError::HandshakeFailed)
}

fn connect_destination<'stream, T, E>(
    client_config: &ClientConfig,
    target: &ProxyTarget<'_>,
    methods: &[ClientAuthMethod],
    stream: ProxyStream<'stream>,
    trust_host_key: T,
) -> Result<ProxyClient<'stream>, ProxyError>
where
    T: Fn(&Ed25519PublicKey) -> Result<(), E>,
{
    let mut transport = connect_hop(client_config, stream, trust_host_key)?;
    authenticate_methods(&mut transport, target.user(), methods)?;
    Ok(ProxyClient { transport })
}

fn authenticate_jump<A>(
    transport: &mut ClientTransport<ProxyStream<'_>>,
    hop: &JumpHost,
    destination_user: &str,
    jump_auth: &mut A,
) -> Result<(), ProxyError>
where
    A: FnMut(&JumpHost) -> Option<Vec<ClientAuthMethod>>,
{
    let Some(methods) = jump_auth(hop) else {
        return Ok(());
    };
    let username = match hop.user() {
        Some(user) => user,
        None => destination_user,
    };
    authenticate_methods(transport, username, &methods)
}

fn authenticate_methods<S>(
    transport: &mut ClientTransport<S>,
    username: &str,
    methods: &[ClientAuthMethod],
) -> Result<(), ProxyError>
where
    S: Read + Write,
{
    if methods.is_empty() {
        return Ok(());
    }
    let attempts = methods.len().saturating_mul(2).max(1);
    neotales_ssh::authenticate_client(transport, username, methods, attempts)
        .map(|_success| ())
        .map_err(|_error| ProxyError::AuthenticationFailed)
}

fn parse_endpoint(endpoint: &str) -> Result<(&str, u16), ProxyError> {
    if endpoint.starts_with('[') {
        return parse_bracketed_endpoint(endpoint);
    }
    if endpoint.contains(':') {
        if endpoint.matches(':').count() > 1 {
            return Err(ProxyError::MissingIpv6Bracket);
        }
        let (host, port) = endpoint
            .split_once(':')
            .ok_or(ProxyError::InvalidJumpHost)?;
        return Ok((host, parse_port(port)?));
    }
    Ok((endpoint, DEFAULT_SSH_PORT))
}

fn parse_bracketed_endpoint(endpoint: &str) -> Result<(&str, u16), ProxyError> {
    let inner = endpoint.get(1..).ok_or(ProxyError::MissingIpv6Bracket)?;
    let close = inner.find(']').ok_or(ProxyError::MissingIpv6Bracket)?;
    let host = inner.get(..close).ok_or(ProxyError::InvalidJumpHost)?;
    if host.contains('[') || host.contains(']') {
        return Err(ProxyError::InvalidJumpHost);
    }
    let tail = inner
        .get(close.saturating_add(1)..)
        .ok_or(ProxyError::InvalidJumpHost)?;
    if tail.is_empty() {
        Ok((host, DEFAULT_SSH_PORT))
    } else {
        let port = tail.strip_prefix(':').ok_or(ProxyError::InvalidJumpHost)?;
        Ok((host, parse_port(port)?))
    }
}

fn parse_port(value: &str) -> Result<u16, ProxyError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProxyError::InvalidJumpPort);
    }
    let port = value
        .parse::<u32>()
        .map_err(|_error| ProxyError::InvalidJumpPort)?;
    if !(1..=u32::from(u16::MAX)).contains(&port) {
        return Err(ProxyError::InvalidJumpPort);
    }
    u16::try_from(port).map_err(|_error| ProxyError::InvalidJumpPort)
}

fn validate_user(user: Option<&str>, error: ProxyError) -> Result<(), ProxyError> {
    let Some(user) = user else {
        return Ok(());
    };
    if user.is_empty() || user.contains('@') || contains_forbidden(user) {
        return Err(error);
    }
    Ok(())
}

fn validate_host(host: &str, error: ProxyError) -> Result<(), ProxyError> {
    if host.is_empty() || host.len() > MAX_PROXY_HOST_LENGTH || contains_forbidden(host) {
        return Err(error);
    }
    Ok(())
}

fn contains_forbidden(value: &str) -> bool {
    value
        .chars()
        .any(|character| character == '\0' || character.is_whitespace())
}

fn validate_destination(target: &ProxyTarget<'_>) -> Result<(), ProxyError> {
    if target.port() == 0 {
        return Err(ProxyError::InvalidDestination);
    }
    validate_host(target.host(), ProxyError::InvalidDestination)?;
    if target.user().is_empty() || contains_forbidden(target.user()) {
        return Err(ProxyError::InvalidDestination);
    }
    Ok(())
}
