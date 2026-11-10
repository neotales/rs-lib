//! Explicit, default-deny policy decisions for an SSH server.
//!
//! This module only records and evaluates policy.  It does not resolve host
//! names, open sockets, parse commands, or make any other network or process
//! call. An application can use the decisions while handling a session, and
//! the policy implements the existing direct-tcpip and remote-forwarding
//! policy traits for forwarding dispatchers.

use std::fmt;

/// The maximum byte length of one accepted environment-variable name.
pub const MAX_ENVIRONMENT_NAME_LENGTH: usize = 255;

/// The maximum byte length of one environment-variable value.
///
/// Environment values are kept as opaque bytes by the policy, but they must
/// be valid UTF-8 text without NUL bytes before a request can be accepted.
pub const MAX_ENVIRONMENT_VALUE_LENGTH: usize = 64 * 1024;

/// The maximum number of accepted environment-variable names.
pub const MAX_ENVIRONMENT_NAMES: usize = 64;

/// The maximum byte length of an opaque forced command.
pub const MAX_FORCE_COMMAND_LENGTH: usize = 64 * 1024;

/// The maximum byte length of one forwarding destination pattern.
pub const MAX_PERMIT_OPEN_PATTERN_LENGTH: usize = 255;

/// The maximum number of forwarding destination patterns.
pub const MAX_PERMIT_OPEN_PATTERNS: usize = 64;

/// A validation failure while adding a server-policy entry.
///
/// Errors never contain environment names, command bytes, or patterns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerPolicyError {
    /// An environment-variable name was empty.
    EmptyEnvironmentName,
    /// An environment-variable name exceeded [`MAX_ENVIRONMENT_NAME_LENGTH`].
    EnvironmentNameTooLong,
    /// An environment-variable name contained `=` or NUL.
    InvalidEnvironmentName,
    /// An environment-variable value exceeded
    /// [`MAX_ENVIRONMENT_VALUE_LENGTH`].
    EnvironmentValueTooLong,
    /// An environment-variable value was not valid NUL-free UTF-8 text.
    InvalidEnvironmentValue,
    /// The environment-variable allow list was already full.
    TooManyEnvironmentNames,
    /// A forced command exceeded [`MAX_FORCE_COMMAND_LENGTH`].
    ForceCommandTooLong,
    /// A forwarding destination pattern was empty.
    EmptyPermitOpenPattern,
    /// A forwarding destination pattern exceeded
    /// [`MAX_PERMIT_OPEN_PATTERN_LENGTH`].
    PermitOpenPatternTooLong,
    /// The forwarding destination pattern list was already full.
    TooManyPermitOpenPatterns,
}

impl fmt::Display for ServerPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyEnvironmentName => "SSH server environment name is empty",
            Self::EnvironmentNameTooLong => {
                "SSH server environment name exceeds the 255-byte limit"
            }
            Self::InvalidEnvironmentName => "SSH server environment name contains an invalid byte",
            Self::EnvironmentValueTooLong => {
                "SSH server environment value exceeds the 64 KiB limit"
            }
            Self::InvalidEnvironmentValue => "SSH server environment value contains invalid bytes",
            Self::TooManyEnvironmentNames => "SSH server environment allow list is full",
            Self::ForceCommandTooLong => "SSH server forced command exceeds the 64 KiB limit",
            Self::EmptyPermitOpenPattern => "SSH server forwarding pattern is empty",
            Self::PermitOpenPatternTooLong => {
                "SSH server forwarding pattern exceeds the 255-byte limit"
            }
            Self::TooManyPermitOpenPatterns => "SSH server forwarding pattern list is full",
        })
    }
}

impl std::error::Error for ServerPolicyError {}

/// Explicit policy decisions for server-side SSH requests.
///
/// A newly constructed policy denies TTY allocation, accepts no environment
/// names, has no forced command, and permits no forwarding destinations. The
/// session dispatcher consults it for the operations it owns, while the
/// callback-based `SessionPolicy` remains the separate base decision for
/// `exec` and `shell`.
///
/// The [`fmt::Debug`] implementation intentionally reports only configuration
/// counts and flags. It never formats names, values, command bytes, or
/// forwarding patterns, which may contain sensitive material.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerPolicy {
    tty_allowed: bool,
    environment_names: Vec<String>,
    forced_command: Option<Vec<u8>>,
    open_patterns: Vec<String>,
}

impl fmt::Debug for ServerPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerPolicy")
            .field("tty_allowed", &self.tty_allowed)
            .field("environment_name_count", &self.environment_names.len())
            .field("forced_command_configured", &self.forced_command.is_some())
            .field("open_pattern_count", &self.open_patterns.len())
            .finish()
    }
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerPolicy {
    /// Creates a policy that denies every optional server request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tty_allowed: false,
            environment_names: Vec::new(),
            forced_command: None,
            open_patterns: Vec::new(),
        }
    }

    /// Sets whether a TTY may be allocated.
    ///
    /// This changes only the TTY decision; it does not change any other
    /// policy entry.
    pub fn permit_tty(&mut self, allowed: bool) {
        self.tty_allowed = allowed;
    }

    /// Adds one exact environment-variable name to the allow list.
    ///
    /// Matching is case-sensitive and compares the complete name.  Wildcard
    /// characters have no special meaning.  Empty names, names containing `=`
    /// or NUL, names longer than [`MAX_ENVIRONMENT_NAME_LENGTH`] bytes, and
    /// additions beyond [`MAX_ENVIRONMENT_NAMES`] are rejected.
    ///
    /// Adding a name that is already present is a successful no-op and does
    /// not consume another list slot.
    ///
    /// # Errors
    ///
    /// Returns [`ServerPolicyError`] when the name is invalid or the list is
    /// full.  The policy is unchanged on an error.
    pub fn accept_env(&mut self, name: &str) -> Result<(), ServerPolicyError> {
        validate_environment_name(name)?;
        if self
            .environment_names
            .iter()
            .any(|accepted| accepted == name)
        {
            return Ok(());
        }
        if self.environment_names.len() >= MAX_ENVIRONMENT_NAMES {
            return Err(ServerPolicyError::TooManyEnvironmentNames);
        }
        self.environment_names.push(name.to_owned());
        Ok(())
    }

    /// Sets or clears the opaque forced-command bytes.
    ///
    /// `None` removes the forced command.  `Some(&[])` is distinct from
    /// `None` and records an explicitly empty command.  Bytes are copied
    /// exactly and are never parsed or executed.
    ///
    /// # Errors
    ///
    /// Returns [`ServerPolicyError::ForceCommandTooLong`] when the supplied
    /// command exceeds [`MAX_FORCE_COMMAND_LENGTH`] bytes.  The previously
    /// configured command is left unchanged on an error.
    pub fn force_command(&mut self, command: Option<&[u8]>) -> Result<(), ServerPolicyError> {
        let Some(command) = command else {
            self.forced_command = None;
            return Ok(());
        };
        if command.len() > MAX_FORCE_COMMAND_LENGTH {
            return Err(ServerPolicyError::ForceCommandTooLong);
        }
        self.forced_command = Some(command.to_vec());
        Ok(())
    }

    /// Adds one forwarding destination pattern to the allow list.
    ///
    /// Each pattern is matched against the string `host:port`, where `port`
    /// is rendered in decimal without leading zeroes.  `*` matches any run
    /// of characters and `?` matches exactly one character.  All other
    /// characters, including `!`, `[` and `]`, are literals; there is no
    /// character-class or negation syntax.  Empty patterns, patterns longer
    /// than [`MAX_PERMIT_OPEN_PATTERN_LENGTH`] bytes, and additions beyond
    /// [`MAX_PERMIT_OPEN_PATTERNS`] are rejected.
    ///
    /// Adding an identical pattern is a successful no-op and does not consume
    /// another list slot.
    ///
    /// # Errors
    ///
    /// Returns [`ServerPolicyError`] when the pattern is invalid or the list
    /// is full.  The policy is unchanged on an error.
    pub fn permit_open(&mut self, pattern: &str) -> Result<(), ServerPolicyError> {
        validate_open_pattern(pattern)?;
        if self.open_patterns.iter().any(|allowed| allowed == pattern) {
            return Ok(());
        }
        if self.open_patterns.len() >= MAX_PERMIT_OPEN_PATTERNS {
            return Err(ServerPolicyError::TooManyPermitOpenPatterns);
        }
        self.open_patterns.push(pattern.to_owned());
        Ok(())
    }

    /// Returns whether TTY allocation is permitted.
    #[must_use]
    pub const fn tty_allowed(&self) -> bool {
        self.tty_allowed
    }

    /// Returns whether one environment-variable name is accepted exactly.
    #[must_use]
    pub fn env_allowed(&self, name: &str) -> bool {
        self.environment_names
            .iter()
            .any(|accepted| accepted == name)
    }

    /// Returns whether one complete environment request is permitted.
    ///
    /// Matching is the exact, case-sensitive name allow-list configured by
    /// [`Self::accept_env`]. The value is checked for the same bounded,
    /// NUL-free UTF-8 shape used by the session dispatcher. The value is never
    /// parsed, normalized, or included in an error.
    #[must_use]
    pub fn environment_allowed(&self, name: &str, value: &[u8]) -> bool {
        validate_environment_name(name).is_ok()
            && Self::validate_environment_value(value).is_ok()
            && self.env_allowed(name)
    }

    /// Validates one environment-variable value without retaining or formatting
    /// its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ServerPolicyError::EnvironmentValueTooLong`] or
    /// [`ServerPolicyError::InvalidEnvironmentValue`] for an unsafe value.
    pub fn validate_environment_value(value: &[u8]) -> Result<(), ServerPolicyError> {
        if value.len() > MAX_ENVIRONMENT_VALUE_LENGTH {
            return Err(ServerPolicyError::EnvironmentValueTooLong);
        }
        if std::str::from_utf8(value).is_err() || value.contains(&0) {
            return Err(ServerPolicyError::InvalidEnvironmentValue);
        }
        Ok(())
    }

    /// Alias for [`Self::environment_allowed`] using the wire-request name.
    #[must_use]
    pub fn env_request_allowed(&self, name: &str, value: &[u8]) -> bool {
        self.environment_allowed(name, value)
    }

    /// Returns whether one environment value has the bounded wire-safe shape.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn environment_value_allowed(&self, value: &[u8]) -> bool {
        Self::validate_environment_value(value).is_ok()
    }

    /// Returns the exact forced-command bytes, or `None` when none is set.
    #[must_use]
    pub fn forced_command(&self) -> Option<&[u8]> {
        self.forced_command.as_deref()
    }

    /// Returns whether one forwarding destination is permitted.
    ///
    /// The port must be in `1..=65535`, and the host must be non-empty.  The
    /// destination is tested against each configured pattern; one match is
    /// sufficient.  No name resolution or socket operation is performed.
    #[must_use]
    pub fn open_allowed(&self, host: &str, port: u32) -> bool {
        if host.is_empty() || !(1..=65_535).contains(&port) {
            return false;
        }
        let destination = format!("{host}:{port}");
        self.open_patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, &destination))
    }

    /// Returns whether a byte-oriented forwarding destination is permitted.
    ///
    /// Forwarding endpoints carry addresses as SSH strings rather than parsed
    /// host names. Invalid UTF-8 is denied rather than being lossily decoded.
    #[must_use]
    pub fn open_allowed_bytes(&self, host: &[u8], port: u32) -> bool {
        let Ok(host) = std::str::from_utf8(host) else {
            return false;
        };
        self.open_allowed(host, port)
    }
}

impl neotales_ssh::direct_tcpip::DirectTcpipPolicy for ServerPolicy {
    fn allow(&self, request: neotales_ssh::direct_tcpip::DirectTcpipRequest<'_>) -> bool {
        self.open_allowed_bytes(request.destination_host(), request.destination_port())
    }
}

impl neotales_ssh::tcpip_forward::TcpipForwardPolicy for ServerPolicy {
    fn allow(&self, request: neotales_ssh::tcpip_forward::TcpipForwardPolicyRequest<'_>) -> bool {
        self.open_allowed_bytes(request.bind_address(), request.port())
    }
}

fn validate_environment_name(name: &str) -> Result<(), ServerPolicyError> {
    if name.is_empty() {
        return Err(ServerPolicyError::EmptyEnvironmentName);
    }
    if name.len() > MAX_ENVIRONMENT_NAME_LENGTH {
        return Err(ServerPolicyError::EnvironmentNameTooLong);
    }
    if name.bytes().any(|byte| byte == b'=' || byte == 0) {
        return Err(ServerPolicyError::InvalidEnvironmentName);
    }
    Ok(())
}

fn validate_open_pattern(pattern: &str) -> Result<(), ServerPolicyError> {
    if pattern.is_empty() {
        return Err(ServerPolicyError::EmptyPermitOpenPattern);
    }
    if pattern.len() > MAX_PERMIT_OPEN_PATTERN_LENGTH {
        return Err(ServerPolicyError::PermitOpenPatternTooLong);
    }
    Ok(())
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut pattern_index = 0_usize;
    let mut value_index = 0_usize;
    let mut star_index = None;
    let mut star_value_index = 0_usize;

    while value_index < value.len() {
        match pattern.get(pattern_index).copied() {
            Some('*') => {
                star_index = Some(pattern_index);
                star_value_index = value_index;
                pattern_index += 1;
            }
            Some('?') => {
                pattern_index += 1;
                value_index += 1;
            }
            Some(expected) if value.get(value_index).copied() == Some(expected) => {
                pattern_index += 1;
                value_index += 1;
            }
            _ => {
                let Some(star) = star_index else {
                    return false;
                };
                star_value_index += 1;
                value_index = star_value_index;
                pattern_index = star + 1;
            }
        }
    }

    while pattern.get(pattern_index) == Some(&'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}
