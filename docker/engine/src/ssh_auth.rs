//! How the managed Engine SSH client proves who it is, and what it must never
//! print while doing it.
//!
//! The managed client in [`super::ssh_neotales`] speaks a transport, not a
//! console. That is the whole reason a password and a key passphrase are
//! **caller-supplied values** rather than something this crate asks for: a
//! library that blocked on a terminal prompt inside a request would hang in
//! exactly the situation a caller cannot interrupt — a daemon, a CI job, a
//! server. So the answer to "where does the secret come from" is the caller, and
//! this module is the boundary that keeps it the caller's.
//!
//! Three rules hold here, and each is asserted in
//! `tests/debug_surface.rs` rather than argued for in a comment:
//!
//! * a secret is redacted from `Debug` *and* from `Display`. `Debug` is the one
//!   that leaks — it is a panic message, a test failure, and a log line — but a
//!   credential that renders in `format!("{credential}")` is one `{}` away from
//!   a log line, and this crate has already leaked a credential three times.
//! * a secret is zeroized when the value is dropped.
//! * a secret never becomes a `RawRequest`. It goes into the SSH
//!   authenticator and nowhere else, so there is no query, no header, and
//!   nothing for `RawRequest`'s own redaction to have to catch. That is why no
//!   entry was added to `raw::transport`'s credential-header list: this secret
//!   is not an Engine credential and never goes near the wire the Engine sees.
//!
//! The two private secret holders in `credentials.rs` and `proxy.rs` are
//! different things and this is not a third of either. Those wrap a value the
//! crate discovered and uses internally; [`SshSecret`] is a value the *caller*
//! hands in, holds, and is responsible for. It has to be nameable in a public
//! signature for that to work, which is why it is public and those are not.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::Error;

/// What `Debug` and `Display` print in place of a secret.
///
/// Named rather than written inline so the redaction in the `Debug` surface
/// suite has a literal to search for: a test that asserts "the output does not
/// contain the secret" passes just as happily against a `Debug` that prints
/// nothing at all, and one that asserts the marker *is* present cannot.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// A secret the caller supplies to the managed Engine SSH client.
///
/// Used for an SSH password and for the passphrase on an encrypted identity
/// file. `Debug` and `Display` both print `[REDACTED]`, the value is zeroized
/// when the value is dropped, and nothing in this crate ever puts it in a
/// `RawRequest`.
///
/// `Clone` is implemented and is not a mistake: the options struct is cloned
/// once per request, and refusing to clone would mean either a
/// reference-counted secret or a factory that cannot be `Send`. The copies are
/// zeroized the same way the original is.
///
/// The secret is exposed through [`SshSecret::expose`], which is named for what
/// it does. There is no `Deref`, no `AsRef<str>`, and no accessor that returns
/// a `&String`, so a value cannot reach a format argument or a log by accident
/// through a trait that reads as ordinary data.
#[derive(Clone, Eq, PartialEq)]
pub struct SshSecret(Zeroizing<String>);

impl SshSecret {
    /// Wraps a value the caller already has.
    ///
    /// The caller keeps ownership of whatever produced the value; this is a
    /// copy that is zeroized on drop, and the caller's own copy is its own
    /// business.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Returns the secret.
    ///
    /// Every call site is the transport handing the value to
    /// `neotales-ssh`. There is no other reason to call this, and it is public
    /// only because a caller building its own [`SshIdentity`] may need it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns a copy of the secret in the mutable buffer `OpenSshPrivateKey`
    /// zeroizes in place.
    ///
    /// `neotales-ssh`'s key parser takes `&mut [u8]` and promises to zeroize it
    /// before returning, so a passphrase is passed as a throwaway buffer rather
    /// than as the secret's own storage. Reusing `SshSecret`'s storage would
    /// hand the parser a slice of a value that is still live afterwards, and the
    /// promise would be about a copy rather than the secret.
    pub(crate) fn expose_throwaway(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_bytes().to_vec())
    }
}

impl fmt::Debug for SshSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for SshSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl From<&str> for SshSecret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SshSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// The credential the managed Engine SSH client authenticates with.
///
/// One enum rather than a field per mechanism on the options struct, because the
/// mechanisms are *alternatives* and a struct with four `Option`s has sixteen
/// states of which three are meaningful. A caller names exactly one.
///
/// An encrypted identity file is a separate variant rather than a flag on
/// [`SshIdentity::KeyFile`] because a passphrase is a secret and a
/// `Option<SshSecret>` in a public field is a secret a caller can forget to
/// redact in their own `Debug`. Naming it in the variant means the type system
/// says the difference out loud.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshIdentity {
    /// A private key file, unencrypted.
    KeyFile(PathBuf),
    /// A private key file and the passphrase that decrypts it.
    EncryptedKeyFile {
        /// The private key file to read.
        path: PathBuf,
        /// The passphrase for the key file.
        passphrase: SshSecret,
    },
    /// An SSH password, sent with the `password` method.
    ///
    /// Up front, by design. The alternative — a callback this crate invokes
    /// when the server answers `SSH_MSG_USERAUTH_FAILURE` — is what OpenSSH
    /// does, and it is refused here for the reason in this module's
    /// documentation: the prompt belongs to whoever is driving the program, not
    /// to a request already in flight on someone else's task.
    Password(SshSecret),
}

impl SshIdentity {
    /// Returns the identity file, when this credential has one.
    pub(crate) fn key_file(&self) -> Option<&Path> {
        match self {
            Self::KeyFile(path) | Self::EncryptedKeyFile { path, .. } => Some(path),
            Self::Password(_) => None,
        }
    }

    /// Names the mechanism, for a diagnostic. Never the value.
    pub(crate) fn mechanism(&self) -> &'static str {
        match self {
            Self::KeyFile(_) => "an identity file",
            Self::EncryptedKeyFile { .. } => "an encrypted identity file",
            Self::Password(_) => "a password",
        }
    }
}

/// A managed `neotales-ssh` connection to a remote Engine, under construction.
///
/// Built by [`crate::DockerClient::connect_ssh_managed`]. Every setting has a
/// defined default and every one of them is a method rather than a positional
/// parameter: the set of things a caller may need to say about an `ssh://`
/// endpoint — who, which key or password, which known-hosts file, how long to
/// wait, and whether to reuse connections — is five settings, and a
/// five-argument constructor whose fifth argument is a password is a signature
/// nobody reads correctly. There is deliberately no connection-reuse setting on
/// it: see the `ssh_neotales` module's own documentation for the two
/// mechanisms that were considered and the one reason neither is offered.
///
/// # What is not a default
///
/// The credential. There is no `identity_file` default and no reading of the
/// invoking user's `~/.ssh`, because the reason this mechanism exists is to be
/// explicit about host keys and about who is authenticating. A client built
/// without a credential is refused on first use, with a message naming what to
/// set — see [`SshIdentity`] for the three that exist.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct ManagedSshClient {
    endpoint: String,
    known_hosts_path: PathBuf,
    timeout: Duration,
    identity: Option<SshIdentity>,
}

impl ManagedSshClient {
    /// Starts from an endpoint and the known-hosts file to check it against.
    ///
    /// The timeout defaults to thirty seconds and the connection policy to one
    /// connection per request, so the two settings a caller almost always wants
    /// are the two that are already right.
    pub(crate) fn new(endpoint: &str, known_hosts_path: &Path) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            known_hosts_path: known_hosts_path.to_path_buf(),
            timeout: Duration::from_secs(30),
            identity: None,
        }
    }

    /// Sets how long a request may take before it is abandoned.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Authenticates with an unencrypted private key file.
    pub fn identity_file(self, path: &Path) -> Self {
        self.identity(SshIdentity::KeyFile(path.to_path_buf()))
    }

    /// Authenticates with an encrypted private key file and its passphrase.
    ///
    /// The passphrase is a value, not a prompt. See this module's documentation
    /// for why: the managed client speaks a transport and not a console.
    pub fn identity_file_with_passphrase(self, path: &Path, passphrase: SshSecret) -> Self {
        self.identity(SshIdentity::EncryptedKeyFile {
            path: path.to_path_buf(),
            passphrase,
        })
    }

    /// Authenticates with an SSH password.
    pub fn password(self, password: SshSecret) -> Self {
        self.identity(SshIdentity::Password(password))
    }

    /// Replaces the credential, which is what each of the three above does.
    pub fn identity(mut self, identity: SshIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The endpoint this client was pointed at.
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// How long a request may take before it is abandoned.
    pub(crate) const fn request_timeout(&self) -> Duration {
        self.timeout
    }

    /// The credential, when one was named.
    pub(crate) fn credential(&self) -> Option<&SshIdentity> {
        self.identity.as_ref()
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns an error when no credential was named, when the endpoint is not
    /// an `ssh://` address or names no login user, when the timeout is zero, and
    /// when a path is not valid UTF-8. Each of those is reported separately
    /// rather than as one "incomplete configuration", because a caller who set
    /// three of the four needs to be told which one is wrong.
    pub fn connect(self) -> Result<crate::DockerClient, Error> {
        let identity = self.identity.clone().ok_or_else(|| {
            Error::invalid_input(
                "the managed Engine SSH client was given no credential; set one with \
                 identity_file, identity_file_with_passphrase, or password",
            )
        })?;
        let options = crate::ssh_neotales::ManagedSshOptions::from_endpoint(
            &self.endpoint,
            identity,
            Some(&self.known_hosts_path),
        )?;
        crate::DockerClient::connect_ssh_managed_inner(&self, options)
    }
}

#[cfg(test)]
mod tests {
    use super::{SshIdentity, SshSecret};

    /// The canary is what a leak would carry, and the assertion is that neither
    /// rendering contains it. Both are checked because a secret that is redacted
    /// in `Debug` and printed by `Display` is one `{}` away from a log line.
    #[test]
    fn a_secret_renders_as_a_redaction_and_nothing_else() {
        const CANARY: &str = "canary-ssh-secret-2b7f41c9-do-not-log-me";
        let secret = SshSecret::new(CANARY);

        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        for rendered in [&debug, &display] {
            assert!(
                !rendered.contains(CANARY),
                "a secret rendered in {rendered:?}"
            );
            assert!(
                rendered.contains("[REDACTED]"),
                "the redaction has to be visible rather than an omission: {rendered:?}"
            );
        }
    }

    /// The secret is the caller's to read back, so `expose` has to work — and
    /// this is the check that it is the *only* way out. A `Deref<Target = str>`
    /// or an `AsRef<str>` here would put the value back within reach of a
    /// `{}`.
    #[test]
    fn a_secret_is_readable_only_by_asking_for_it_explicitly() {
        let secret = SshSecret::from("hunter2");
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(SshSecret::from(String::from("hunter2")), secret);
    }

    /// Every variant has to name a mechanism, because the mechanism is what a
    /// failed authentication has to say. The value is never in it.
    #[test]
    fn an_identity_names_its_mechanism_and_never_its_secret() {
        const CANARY: &str = "canary-ssh-passphrase-6d0a5e13-do-not-log-me";
        let identity = SshIdentity::EncryptedKeyFile {
            path: "/keys/id_ed25519".into(),
            passphrase: SshSecret::new(CANARY),
        };
        let rendered = format!("{identity:?}");

        assert!(
            !rendered.contains(CANARY),
            "the passphrase leaked: {rendered}"
        );
        assert_eq!(identity.mechanism(), "an encrypted identity file");
        assert_eq!(
            identity.key_file(),
            Some(std::path::Path::new("/keys/id_ed25519"))
        );
        assert_eq!(
            SshIdentity::Password(SshSecret::new("x")).mechanism(),
            "a password"
        );
        assert!(
            SshIdentity::Password(SshSecret::new("x"))
                .key_file()
                .is_none()
        );
    }

    /// A builder with nothing set is refused when it is built, not when it is
    /// first used, and the message names the three calls that would work — a
    /// caller who forgot one setting should not have to make a request to find
    /// out which.
    #[test]
    fn a_managed_client_with_no_credential_names_the_three_ways_to_set_one() {
        let error = crate::DockerClient::connect_ssh_managed(
            "ssh://deploy@example.test",
            std::path::Path::new("/keys/known_hosts"),
        )
        .connect()
        .expect_err("a client with no credential must be refused");
        let rendered = error.to_string();
        for setting in ["identity_file", "identity_file_with_passphrase", "password"] {
            assert!(
                rendered.contains(setting),
                "the refusal must name {setting}: {rendered}"
            );
        }
    }
}
