//! A small, side-effect-free parser and resolver for OpenSSH client configuration.
//!
//! This module deliberately treats configuration as text.  It does not open
//! files, inspect the environment, expand home-directory shortcuts, or run a
//! proxy command.  [`SshConfig::resolve`] only performs the token substitutions
//! documented for the selected values and returns the resulting text to the
//! caller.

#![allow(clippy::module_name_repetitions, dead_code)]

use std::fmt;
use std::str::FromStr;

/// An error produced while parsing or resolving an SSH client configuration.
///
/// Error values intentionally do not contain configuration text.  This keeps
/// diagnostics bounded even when a caller parses an untrusted document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshConfigError {
    /// A non-empty line could not be separated into a keyword and value.
    MalformedLine,
    /// A double-quoted value was not closed before the end of the line.
    UnterminatedQuote,
    /// A known keyword was written without a value.
    MissingValue,
    /// A `Host` or `Match host` pattern was empty or malformed.
    InvalidHostPattern,
    /// A `Match` directive did not contain a usable criterion.
    InvalidMatch,
    /// A yes/no option contained something other than `yes` or `no`.
    InvalidBoolean,
    /// An integer option was negative, empty, or outside the supported range.
    InvalidInteger,
    /// A port was outside the range 1 through 65535.
    InvalidPort,
    /// `StrictHostKeyChecking` was not one of the four supported values.
    InvalidStrictHostKeyChecking,
    /// A token-expanded keyword contained an unsupported percent sequence.
    InvalidToken,
    /// `Include` is deliberately unsupported by this text-only module.
    Include,
}

impl fmt::Display for SshConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedLine => formatter.write_str("SSH configuration line is malformed"),
            Self::UnterminatedQuote => {
                formatter.write_str("SSH configuration contains an unterminated quote")
            }
            Self::MissingValue => formatter.write_str("SSH configuration keyword has no value"),
            Self::InvalidHostPattern => {
                formatter.write_str("SSH configuration contains an invalid host pattern")
            }
            Self::InvalidMatch => {
                formatter.write_str("SSH configuration contains an invalid Match")
            }
            Self::InvalidBoolean => {
                formatter.write_str("SSH configuration boolean must be yes or no")
            }
            Self::InvalidInteger => formatter.write_str("SSH configuration integer is invalid"),
            Self::InvalidPort => formatter.write_str("SSH configuration port is invalid"),
            Self::InvalidStrictHostKeyChecking => {
                formatter.write_str("SSH StrictHostKeyChecking must be yes, no, ask, or accept-new")
            }
            Self::InvalidToken => {
                formatter.write_str("SSH configuration contains an unsupported token")
            }
            Self::Include => {
                formatter.write_str("SSH configuration Include directives are unsupported")
            }
        }
    }
}

impl std::error::Error for SshConfigError {}

/// A compatibility name for [`SshConfigError`].
pub type Error = SshConfigError;

/// A compatibility name for [`SshConfigError`].
pub type ParseError = SshConfigError;

/// A parsed SSH client configuration document.
///
/// The document retains stanzas in source order.  Scalar options use the first
/// value obtained from an applicable stanza, while the designated list options
/// retain every value in source order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SshConfig {
    stanzas: Vec<Stanza>,
}

impl SshConfig {
    /// Parses an SSH client configuration from text.
    ///
    /// `Host` and `Match` directives start new stanzas.  Lines before the first
    /// stanza are treated as an implicit `Host *` stanza.  `Include` is rejected
    /// without inspecting its path.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError`] for malformed syntax, invalid known values,
    /// unsupported `Include`, or malformed host and match patterns.
    pub fn parse(text: &str) -> Result<Self, SshConfigError> {
        parse_document(text)
    }

    /// Resolves this document for one original command-line host.
    ///
    /// Resolution walks stanzas from top to bottom.  `Host` patterns always
    /// compare against `original_host`; `Match host` compares against the
    /// `HostName` obtained by an earlier applicable stanza, or the original
    /// host when no such value has been obtained.  Token expansion is performed
    /// only after that scan.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError::InvalidToken`] when a selected token-expanded
    /// keyword contains an unsupported percent sequence.
    pub fn resolve(
        &self,
        original_host: &str,
        default_user: &str,
    ) -> Result<ResolvedConfig, SshConfigError> {
        let mut values = Accumulator::default();
        for stanza in &self.stanzas {
            let current_remote_host = match values.hostname.as_deref() {
                Some(hostname) => hostname,
                None => original_host,
            };
            if stanza.applies(original_host, current_remote_host) {
                for entry in &stanza.entries {
                    values.apply(entry)?;
                }
            }
        }
        values.into_resolved(original_host, default_user)
    }

    /// Returns whether the parsed document contains no stanzas.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stanzas.is_empty()
    }
}

impl FromStr for SshConfig {
    type Err = SshConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Parses an SSH client configuration from text.
///
/// This is the free-function form of [`SshConfig::parse`].
///
/// # Errors
///
/// Returns [`SshConfigError`] for malformed syntax, invalid known values,
/// unsupported `Include`, or malformed host and match patterns.
pub fn parse(text: &str) -> Result<SshConfig, SshConfigError> {
    SshConfig::parse(text)
}

/// The effective configuration for one original command-line host.
///
/// Unset scalar options are represented by `None`.  `hostname`, `user`, and
/// `port` always have values: the original host, the caller-supplied default
/// user, and port 22 respectively are used when no earlier value was obtained.
/// Paths remain literal text except for the explicitly supported percent
/// tokens; in particular, a leading `~` is not expanded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConfig {
    /// The original host supplied to [`SshConfig::resolve`].
    pub original_host: String,
    /// The expanded `HostName`, or the original host when `HostName` is unset.
    pub hostname: String,
    /// The obtained `User`, or the default user supplied to the resolver.
    pub user: String,
    /// The obtained `Port`, or 22 when `Port` is unset.
    pub port: u16,
    /// All selected `IdentityFile` values in file order.
    pub identity_files: Vec<String>,
    /// The first selected `IdentitiesOnly` value.
    pub identities_only: Option<bool>,
    /// The first selected, token-expanded `IdentityAgent` value.
    pub identity_agent: Option<String>,
    /// All selected `CertificateFile` values in file order.
    pub certificate_files: Vec<String>,
    /// The first selected, token-expanded `ProxyJump` value.
    pub proxy_jump: Option<String>,
    /// The first selected, token-expanded `ProxyCommand` text.
    ///
    /// This value is never interpreted or executed by this module.
    pub proxy_command: Option<String>,
    /// All selected `SendEnv` tokens in file order.
    pub send_env: Vec<String>,
    /// All selected `SetEnv` tokens in file order.
    pub set_env: Vec<String>,
    /// All selected `UserKnownHostsFile` values in file order.
    pub user_known_hosts_files: Vec<String>,
    /// All selected `GlobalKnownHostsFile` values in file order.
    pub global_known_hosts_files: Vec<String>,
    /// The first selected `StrictHostKeyChecking` value.
    pub strict_host_key_checking: Option<String>,
    /// The first selected `HashKnownHosts` value.
    pub hash_known_hosts: Option<bool>,
    /// The first selected `KexAlgorithms` value.
    pub kex_algorithms: Option<String>,
    /// The first selected `Ciphers` value.
    pub ciphers: Option<String>,
    /// The first selected `MACs` value.
    pub macs: Option<String>,
    /// The first selected `HostKeyAlgorithms` value.
    pub host_key_algorithms: Option<String>,
    /// The first selected `PubkeyAcceptedAlgorithms` value.
    pub pubkey_accepted_algorithms: Option<String>,
    /// The first selected `PreferredAuthentications` value.
    pub preferred_authentications: Option<String>,
    /// The first selected `ConnectTimeout` value.
    pub connect_timeout: Option<u64>,
    /// The first selected `ServerAliveInterval` value.
    pub server_alive_interval: Option<u64>,
    /// The first selected `ServerAliveCountMax` value.
    pub server_alive_count_max: Option<u64>,
    /// Unknown keywords from applicable stanzas, in source order.
    pub unknown_keywords: Vec<(String, String)>,
}

impl ResolvedConfig {
    /// Returns the original command-line host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.original_host
    }

    /// Returns the accumulated identity file values.
    #[must_use]
    pub fn identity_file(&self) -> &[String] {
        &self.identity_files
    }

    /// Returns the accumulated certificate file values.
    #[must_use]
    pub fn certificate_file(&self) -> &[String] {
        &self.certificate_files
    }

    /// Returns the accumulated user known-hosts file values.
    #[must_use]
    pub fn user_known_hosts_file(&self) -> &[String] {
        &self.user_known_hosts_files
    }

    /// Returns the accumulated global known-hosts file values.
    #[must_use]
    pub fn global_known_hosts_file(&self) -> &[String] {
        &self.global_known_hosts_files
    }

    /// Returns unknown keyword/value pairs from applicable stanzas.
    #[must_use]
    pub fn unknown(&self) -> &[(String, String)] {
        &self.unknown_keywords
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StanzaKind {
    Host,
    Match,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Pattern {
    negated: bool,
    text: String,
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, SshConfigError> {
        if text.is_empty() {
            return Err(SshConfigError::InvalidHostPattern);
        }
        let (negated, body) = match text.strip_prefix('!') {
            Some(body) => (true, body),
            None => (false, text),
        };
        if body.is_empty() {
            return Err(SshConfigError::InvalidHostPattern);
        }
        Ok(Self {
            negated,
            text: body.to_owned(),
        })
    }

    fn matches(&self, host: &str) -> bool {
        wildcard_match(&self.text, host)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MatchCriterion {
    All,
    Host(Vec<Pattern>),
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Stanza {
    kind: StanzaKind,
    patterns: Vec<Pattern>,
    criteria: Vec<MatchCriterion>,
    entries: Vec<Entry>,
}

impl Stanza {
    fn implicit() -> Self {
        Self {
            kind: StanzaKind::Host,
            patterns: vec![Pattern {
                negated: false,
                text: "*".to_owned(),
            }],
            criteria: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn host(patterns: Vec<Pattern>) -> Self {
        Self {
            kind: StanzaKind::Host,
            patterns,
            criteria: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn matching(criteria: Vec<MatchCriterion>) -> Self {
        Self {
            kind: StanzaKind::Match,
            patterns: Vec::new(),
            criteria,
            entries: Vec::new(),
        }
    }

    fn applies(&self, original_host: &str, current_remote_host: &str) -> bool {
        match self.kind {
            StanzaKind::Host => patterns_match(&self.patterns, original_host),
            StanzaKind::Match => {
                if self
                    .criteria
                    .iter()
                    .any(|criterion| matches!(criterion, MatchCriterion::Unsupported))
                {
                    return false;
                }
                self.criteria.iter().all(|criterion| match criterion {
                    MatchCriterion::All => true,
                    MatchCriterion::Host(patterns) => patterns_match(patterns, current_remote_host),
                    MatchCriterion::Unsupported => false,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    keyword: String,
    original_keyword: String,
    value: String,
    values: Vec<String>,
}

#[derive(Default)]
struct Accumulator {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_files: Vec<String>,
    identities_only: Option<bool>,
    identity_agent: Option<String>,
    certificate_files: Vec<String>,
    proxy_jump: Option<String>,
    proxy_command: Option<String>,
    send_env: Vec<String>,
    set_env: Vec<String>,
    user_known_hosts_files: Vec<String>,
    global_known_hosts_files: Vec<String>,
    strict_host_key_checking: Option<String>,
    hash_known_hosts: Option<bool>,
    kex_algorithms: Option<String>,
    ciphers: Option<String>,
    macs: Option<String>,
    host_key_algorithms: Option<String>,
    pubkey_accepted_algorithms: Option<String>,
    preferred_authentications: Option<String>,
    connect_timeout: Option<u64>,
    server_alive_interval: Option<u64>,
    server_alive_count_max: Option<u64>,
    unknown_keywords: Vec<(String, String)>,
}

impl Accumulator {
    fn apply(&mut self, entry: &Entry) -> Result<(), SshConfigError> {
        match entry.keyword.as_str() {
            "hostname" => set_once(&mut self.hostname, entry.value.clone()),
            "user" => set_once(&mut self.user, entry.value.clone()),
            "port" => set_once(&mut self.port, parse_port(&entry.value)?),
            "identityfile" => self.identity_files.extend(entry.values.iter().cloned()),
            "identitiesonly" => {
                set_once(&mut self.identities_only, parse_boolean(&entry.value)?);
            }
            "identityagent" => set_once(&mut self.identity_agent, entry.value.clone()),
            "certificatefile" => self.certificate_files.extend(entry.values.iter().cloned()),
            "proxyjump" => set_once(&mut self.proxy_jump, entry.value.clone()),
            "proxycommand" => set_once(&mut self.proxy_command, entry.value.clone()),
            "sendenv" => self.send_env.extend(entry.values.iter().cloned()),
            "setenv" => self.set_env.extend(entry.values.iter().cloned()),
            "userknownhostsfile" => self
                .user_known_hosts_files
                .extend(entry.values.iter().cloned()),
            "globalknownhostsfile" => self
                .global_known_hosts_files
                .extend(entry.values.iter().cloned()),
            "stricthostkeychecking" => {
                set_once(
                    &mut self.strict_host_key_checking,
                    parse_strict_host_key_checking(&entry.value)?.to_owned(),
                );
            }
            "hashknownhosts" => {
                set_once(&mut self.hash_known_hosts, parse_boolean(&entry.value)?);
            }
            "kexalgorithms" => set_once(&mut self.kex_algorithms, entry.value.clone()),
            "ciphers" => set_once(&mut self.ciphers, entry.value.clone()),
            "macs" => set_once(&mut self.macs, entry.value.clone()),
            "hostkeyalgorithms" => {
                set_once(&mut self.host_key_algorithms, entry.value.clone());
            }
            "pubkeyacceptedalgorithms" => {
                set_once(&mut self.pubkey_accepted_algorithms, entry.value.clone());
            }
            "preferredauthentications" => {
                set_once(&mut self.preferred_authentications, entry.value.clone());
            }
            "connecttimeout" => {
                set_once(&mut self.connect_timeout, parse_integer(&entry.value)?);
            }
            "serveraliveinterval" => {
                set_once(
                    &mut self.server_alive_interval,
                    parse_integer(&entry.value)?,
                );
            }
            "serveralivecountmax" => {
                set_once(
                    &mut self.server_alive_count_max,
                    parse_integer(&entry.value)?,
                );
            }
            _ => self
                .unknown_keywords
                .push((entry.original_keyword.clone(), entry.value.clone())),
        }
        Ok(())
    }

    fn into_resolved(
        self,
        original_host: &str,
        default_user: &str,
    ) -> Result<ResolvedConfig, SshConfigError> {
        let hostname = match self.hostname {
            Some(value) => expand_hostname(&value, original_host)?,
            None => original_host.to_owned(),
        };
        let user = match self.user {
            Some(value) => value,
            None => default_user.to_owned(),
        };
        let port = self.port.as_ref().map_or(22, |value| *value);
        let context = ExpansionContext {
            original_host,
            hostname: &hostname,
            port,
            user: &user,
        };

        let identity_files = expand_values(self.identity_files, &context)?;
        let identity_agent = expand_optional(self.identity_agent, &context)?;
        let certificate_files = expand_values(self.certificate_files, &context)?;
        let proxy_jump = expand_optional(self.proxy_jump, &context)?;
        let proxy_command = expand_optional(self.proxy_command, &context)?;
        let user_known_hosts_files = expand_values(self.user_known_hosts_files, &context)?;
        let global_known_hosts_files = expand_values(self.global_known_hosts_files, &context)?;

        Ok(ResolvedConfig {
            original_host: original_host.to_owned(),
            hostname,
            user,
            port,
            identity_files,
            identities_only: self.identities_only,
            identity_agent,
            certificate_files,
            proxy_jump,
            proxy_command,
            send_env: self.send_env,
            set_env: self.set_env,
            user_known_hosts_files,
            global_known_hosts_files,
            strict_host_key_checking: self.strict_host_key_checking,
            hash_known_hosts: self.hash_known_hosts,
            kex_algorithms: self.kex_algorithms,
            ciphers: self.ciphers,
            macs: self.macs,
            host_key_algorithms: self.host_key_algorithms,
            pubkey_accepted_algorithms: self.pubkey_accepted_algorithms,
            preferred_authentications: self.preferred_authentications,
            connect_timeout: self.connect_timeout,
            server_alive_interval: self.server_alive_interval,
            server_alive_count_max: self.server_alive_count_max,
            unknown_keywords: self.unknown_keywords,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn parse_document(text: &str) -> Result<SshConfig, SshConfigError> {
    let mut stanzas = Vec::new();
    let mut current = Stanza::implicit();
    let mut has_current = false;

    for raw_line in text.lines() {
        let tokens = lex_line(raw_line)?;
        if tokens.is_empty() {
            continue;
        }
        let (original_keyword, values) = split_keyword(&tokens)?;
        let keyword = original_keyword.to_ascii_lowercase();
        match keyword.as_str() {
            "host" => {
                let patterns = parse_patterns(&values)?;
                if has_current {
                    stanzas.push(current);
                }
                current = Stanza::host(patterns);
                has_current = true;
            }
            "match" => {
                let criteria = parse_match_criteria(&values)?;
                if has_current {
                    stanzas.push(current);
                }
                current = Stanza::matching(criteria);
                has_current = true;
            }
            "include" => return Err(SshConfigError::Include),
            _ => {
                let entry = make_entry(original_keyword, keyword, values)?;
                current.entries.push(entry);
                has_current = true;
            }
        }
    }

    if has_current {
        stanzas.push(current);
    }
    Ok(SshConfig { stanzas })
}

fn make_entry(
    original_keyword: String,
    keyword: String,
    values: Vec<String>,
) -> Result<Entry, SshConfigError> {
    let value = values.join(" ");
    if is_known_keyword(&keyword) {
        validate_known_entry(&keyword, &values, &value)?;
    }
    Ok(Entry {
        keyword,
        original_keyword,
        value,
        values,
    })
}

fn is_known_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "hostname"
            | "user"
            | "port"
            | "identityfile"
            | "identitiesonly"
            | "identityagent"
            | "certificatefile"
            | "proxyjump"
            | "proxycommand"
            | "sendenv"
            | "setenv"
            | "userknownhostsfile"
            | "globalknownhostsfile"
            | "stricthostkeychecking"
            | "hashknownhosts"
            | "kexalgorithms"
            | "ciphers"
            | "macs"
            | "hostkeyalgorithms"
            | "pubkeyacceptedalgorithms"
            | "preferredauthentications"
            | "connecttimeout"
            | "serveraliveinterval"
            | "serveralivecountmax"
    )
}

fn validate_known_entry(
    keyword: &str,
    values: &[String],
    value: &str,
) -> Result<(), SshConfigError> {
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err(SshConfigError::MissingValue);
    }
    match keyword {
        "identitiesonly" | "hashknownhosts" => {
            parse_boolean(value)?;
        }
        "stricthostkeychecking" => {
            parse_strict_host_key_checking(value)?;
        }
        "port" => {
            parse_port(value)?;
        }
        "connecttimeout" | "serveraliveinterval" | "serveralivecountmax" => {
            parse_integer(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn parse_boolean(value: &str) -> Result<bool, SshConfigError> {
    if value.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        Err(SshConfigError::InvalidBoolean)
    }
}

fn parse_integer(value: &str) -> Result<u64, SshConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| SshConfigError::InvalidInteger)
}

fn parse_port(value: &str) -> Result<u16, SshConfigError> {
    let port = parse_integer(value)?;
    if port == 0 {
        return Err(SshConfigError::InvalidPort);
    }
    u16::try_from(port).map_err(|_| SshConfigError::InvalidPort)
}

fn parse_strict_host_key_checking(value: &str) -> Result<&str, SshConfigError> {
    if value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("ask")
        || value.eq_ignore_ascii_case("accept-new")
    {
        Ok(value)
    } else {
        Err(SshConfigError::InvalidStrictHostKeyChecking)
    }
}

fn parse_patterns(values: &[String]) -> Result<Vec<Pattern>, SshConfigError> {
    let mut patterns = Vec::new();
    for value in values {
        for part in value.split(',') {
            patterns.push(Pattern::parse(part)?);
        }
    }
    if patterns.is_empty() {
        return Err(SshConfigError::InvalidHostPattern);
    }
    Ok(patterns)
}

fn parse_match_criteria(values: &[String]) -> Result<Vec<MatchCriterion>, SshConfigError> {
    if values.is_empty() {
        return Err(SshConfigError::InvalidMatch);
    }

    let mut criteria = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let criterion = values[index].to_ascii_lowercase();
        match criterion.as_str() {
            "all" => {
                criteria.push(MatchCriterion::All);
                index += 1;
            }
            "host" => {
                index += 1;
                let start = index;
                while index < values.len() && !is_match_criterion_word(&values[index]) {
                    index += 1;
                }
                if start == index {
                    return Err(SshConfigError::InvalidMatch);
                }
                criteria.push(MatchCriterion::Host(parse_patterns(&values[start..index])?));
            }
            _ => {
                criteria.push(MatchCriterion::Unsupported);
                break;
            }
        }
    }
    Ok(criteria)
}

fn is_match_criterion_word(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let name = match lower.split_once('=') {
        Some((name, _)) => name,
        None => lower.as_str(),
    };
    matches!(
        name,
        "address"
            | "all"
            | "ca"
            | "canonical"
            | "cert"
            | "environment"
            | "exec"
            | "final"
            | "host"
            | "inaddr"
            | "key"
            | "laddr"
            | "localnetwork"
            | "localuser"
            | "lport"
            | "luser"
            | "originalhost"
            | "principals"
            | "rdomain"
            | "user"
            | "version"
    )
}

fn patterns_match(patterns: &[Pattern], host: &str) -> bool {
    let mut has_positive = false;
    let mut has_negative = false;
    for pattern in patterns {
        if pattern.matches(host) {
            if pattern.negated {
                has_negative = true;
            } else {
                has_positive = true;
            }
        }
    }
    has_positive && !has_negative
}

fn wildcard_match(pattern: &str, host: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let host: Vec<char> = host.chars().collect();
    let mut pattern_index = 0;
    let mut host_index = 0;
    let mut star_index = None;
    let mut star_host_index = 0;

    while host_index < host.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?'
                || chars_equal(pattern[pattern_index], host[host_index]))
        {
            pattern_index += 1;
            host_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            star_host_index = host_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_host_index += 1;
            host_index = star_host_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn chars_equal(left: char, right: char) -> bool {
    left == right || left.eq_ignore_ascii_case(&right)
}

fn lex_line(line: &str) -> Result<Vec<String>, SshConfigError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut token_started = false;
    let mut quote = None;
    let mut escaped = false;

    for character in line.chars() {
        if escaped {
            current.push(character);
            token_started = true;
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            token_started = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '"' | '\'' => {
                quote = Some(character);
                token_started = true;
            }
            '#' => break,
            value if value.is_whitespace() => {
                if token_started {
                    tokens.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            value => {
                current.push(value);
                token_started = true;
            }
        }
    }

    if escaped || quote.is_some() {
        return Err(SshConfigError::UnterminatedQuote);
    }
    if token_started {
        tokens.push(current);
    }
    Ok(tokens)
}

fn split_keyword(tokens: &[String]) -> Result<(String, Vec<String>), SshConfigError> {
    let first = tokens
        .first()
        .ok_or(SshConfigError::MalformedLine)?
        .as_str();
    if first.is_empty() {
        return Err(SshConfigError::MalformedLine);
    }

    if let Some(separator) = first.find('=') {
        let keyword = first[..separator].to_owned();
        if keyword.is_empty() {
            return Err(SshConfigError::MalformedLine);
        }
        let mut values = Vec::new();
        let first_value = &first[separator + 1..];
        if !first_value.is_empty() {
            values.push(first_value.to_owned());
        }
        values.extend(tokens[1..].iter().cloned());
        return Ok((keyword, values));
    }

    if tokens.len() > 1 {
        if tokens[1] == "=" {
            return Ok((first.to_owned(), tokens[2..].to_vec()));
        }
        if let Some(value) = tokens[1].strip_prefix('=') {
            let mut values = Vec::new();
            if !value.is_empty() {
                values.push(value.to_owned());
            }
            values.extend(tokens[2..].iter().cloned());
            return Ok((first.to_owned(), values));
        }
    }

    Ok((first.to_owned(), tokens[1..].to_vec()))
}

#[derive(Clone, Copy)]
enum ExpansionMode {
    HostName,
    General,
}

struct ExpansionContext<'a> {
    original_host: &'a str,
    hostname: &'a str,
    port: u16,
    user: &'a str,
}

fn expand_hostname(value: &str, original_host: &str) -> Result<String, SshConfigError> {
    let context = ExpansionContext {
        original_host,
        hostname: original_host,
        port: 22,
        user: "",
    };
    expand_tokens(value, &context, ExpansionMode::HostName)
}

fn expand_optional(
    value: Option<String>,
    context: &ExpansionContext<'_>,
) -> Result<Option<String>, SshConfigError> {
    match value {
        Some(value) => expand_tokens(&value, context, ExpansionMode::General).map(Some),
        None => Ok(None),
    }
}

fn expand_values(
    values: Vec<String>,
    context: &ExpansionContext<'_>,
) -> Result<Vec<String>, SshConfigError> {
    values
        .into_iter()
        .map(|value| expand_tokens(&value, context, ExpansionMode::General))
        .collect()
}

fn expand_tokens(
    value: &str,
    context: &ExpansionContext<'_>,
    mode: ExpansionMode,
) -> Result<String, SshConfigError> {
    let mut expanded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            expanded.push(character);
            continue;
        }
        let token = characters.next().ok_or(SshConfigError::InvalidToken)?;
        match (mode, token) {
            (_, '%') => expanded.push('%'),
            (ExpansionMode::HostName, 'h') | (ExpansionMode::General, 'n') => {
                expanded.push_str(context.original_host);
            }
            (ExpansionMode::General, 'h') => expanded.push_str(context.hostname),
            (ExpansionMode::General, 'p') => expanded.push_str(&context.port.to_string()),
            (ExpansionMode::General, 'r') => expanded.push_str(context.user),
            _ => return Err(SshConfigError::InvalidToken),
        }
    }
    Ok(expanded)
}
