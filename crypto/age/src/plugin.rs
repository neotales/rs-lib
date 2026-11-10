//! age plugin protocol v1.
//!
//! This module provides both sides of the age plugin protocol: clients for
//! plugin recipients and identities, and a small framework for exposing age
//! recipients and identities as plugin executables.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use zeroize::Zeroizing;

use crate::{
    AgeError, Result, Stanza, bech32,
    codec::{decode_raw, encode_raw},
    traits::{Identity, Recipient},
};

/// A callback used by a plugin client to display a message.
pub type DisplayMessage = Arc<dyn Fn(&str, &str) -> Result<()> + Send + Sync>;
/// A callback used by a plugin client to request a public or secret value.
pub type RequestValue = Arc<dyn Fn(&str, &str, bool) -> Result<String> + Send + Sync>;
/// A callback used by a plugin client to request confirmation.
pub type Confirm = Arc<dyn Fn(&str, &str, &str, &str) -> Result<bool> + Send + Sync>;
/// A callback invoked when a plugin operation may be waiting for a user.
pub type WaitTimer = Arc<dyn Fn(&str) + Send + Sync>;

/// Callbacks used by a plugin client for interactive plugin requests.
///
/// [`Debug`](std::fmt::Debug) is hand-written and reports which callbacks are
/// installed, as `Some` or `None`. A closure cannot be printed, and demanding
/// `Debug` of the caller's closures would make the trait bound on this struct
/// depend on every closure a caller might write. Which callbacks are present is
/// what a caller debugging an unexpected plugin prompt needs to see: a plugin
/// that asks for confirmation and gets no handler is a different bug from one
/// that has all four installed.
#[derive(Clone, Default)]
pub struct ClientUi {
    /// Handles `msg` stanzas.
    pub display_message: Option<DisplayMessage>,
    /// Handles `request-public` and `request-secret` stanzas.
    pub request_value: Option<RequestValue>,
    /// Handles `confirm` stanzas.
    pub confirm: Option<Confirm>,
    /// Called when a plugin may be waiting for external user interaction.
    pub wait_timer: Option<WaitTimer>,
}

impl std::fmt::Debug for ClientUi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientUi")
            .field("display_message", &self.display_message.is_some())
            .field("request_value", &self.request_value.is_some())
            .field("confirm", &self.confirm.is_some())
            .field("wait_timer", &self.wait_timer.is_some())
            .finish()
    }
}

/// Returns whether a plugin name is valid under the age protocol.
#[must_use]
pub fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || b"+-._".contains(&value))
}

/// Encodes a plugin recipient string.
#[must_use]
pub fn encode_recipient(name: &str, data: &[u8]) -> Option<String> {
    if !valid_plugin_name(name) {
        return None;
    }
    bech32::encode(&format!("age1{}", name.to_ascii_lowercase()), data).ok()
}

/// Parses a plugin recipient string into its plugin name and payload.
///
/// # Errors
///
/// Returns [`AgeError`] for malformed Bech32, an invalid plugin prefix, or an
/// invalid plugin name.
pub fn parse_recipient(encoding: &str) -> Result<(String, Vec<u8>)> {
    let (hrp, data) = bech32::decode(encoding)
        .map_err(|_| AgeError::InvalidFormat("invalid plugin recipient encoding"))?;
    let Some(name) = hrp.strip_prefix("age1") else {
        return Err(AgeError::InvalidFormat("not a plugin recipient"));
    };
    if !valid_plugin_name(name) {
        return Err(AgeError::InvalidFormat("invalid plugin name"));
    }
    Ok((name.to_owned(), data))
}

/// Encodes a plugin identity string.
#[must_use]
pub fn encode_identity(name: &str, data: &[u8]) -> Option<String> {
    if !valid_plugin_name(name) {
        return None;
    }
    bech32::encode(&format!("AGE-PLUGIN-{}-", name.to_ascii_uppercase()), data)
        .ok()
        .map(|value| value.to_ascii_uppercase())
}

/// Parses a plugin identity string into its plugin name and payload.
///
/// # Errors
///
/// Returns [`AgeError`] for malformed Bech32, an invalid plugin prefix, or an
/// invalid plugin name.
pub fn parse_identity(encoding: &str) -> Result<(String, Vec<u8>)> {
    let (hrp, data) = bech32::decode(encoding)
        .map_err(|_| AgeError::InvalidFormat("invalid plugin identity encoding"))?;
    let Some(name) = hrp
        .strip_prefix("AGE-PLUGIN-")
        .and_then(|value| value.strip_suffix('-'))
    else {
        return Err(AgeError::InvalidFormat("not a plugin identity"));
    };
    if !valid_plugin_name(name) {
        return Err(AgeError::InvalidFormat("invalid plugin name"));
    }
    Ok((name.to_ascii_lowercase(), data))
}

/// A client-side plugin recipient.
#[derive(Clone)]
pub struct PluginRecipient {
    name: String,
    encoding: String,
    identity: bool,
    ui: ClientUi,
    labels: Arc<Mutex<Vec<String>>>,
}

impl std::fmt::Debug for PluginRecipient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginRecipient")
            .field("name", &self.name)
            .field("encoding", &self.encoding)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PluginRecipient {
    /// Creates a plugin recipient client.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the recipient encoding is invalid.
    pub fn new(encoding: impl AsRef<str>, ui: ClientUi) -> Result<Self> {
        let (name, _) = parse_recipient(encoding.as_ref())?;
        Ok(Self {
            name,
            encoding: encoding.as_ref().to_owned(),
            identity: false,
            ui,
            labels: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Creates a recipient client that asks a plugin to wrap a file key for an
    /// identity encoding.
    #[must_use]
    pub fn from_identity(identity: &PluginIdentity) -> Self {
        Self {
            name: identity.name.clone(),
            encoding: identity.encoding.clone(),
            identity: true,
            ui: identity.ui.clone(),
            labels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns the plugin name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the recipient or identity encoding.
    #[must_use]
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    fn wrap_inner(&self, file_key: &[u8]) -> Result<(Vec<Stanza>, Vec<String>)> {
        if file_key.len() != 16 {
            return Err(AgeError::InvalidKey("age file keys are 16 bytes"));
        }
        let mut connection = open_client_connection(&self.name, "recipient-v1")?;
        let add_type = if self.identity {
            "add-identity"
        } else {
            "add-recipient"
        };
        write_stanza(
            &mut connection.output,
            add_type,
            std::slice::from_ref(&self.encoding),
        )?;
        write_stanza_with_body(&mut connection.output, "wrap-file-key", file_key)?;
        write_stanza(&mut connection.output, "extension-labels", &[])?;
        write_stanza(&mut connection.output, "done", &[])?;

        let mut stanzas = Vec::new();
        let mut labels = None;
        loop {
            let response = read_client_stanza(&mut connection, &self.ui, &self.name)?;
            match response.r#type.as_str() {
                "recipient-stanza" => {
                    if response.args.len() < 2 || response.args[0] != "0" {
                        return Err(plugin_protocol_error("malformed recipient stanza"));
                    }
                    stanzas.push(Stanza::new(
                        response.args[1].clone(),
                        response.args[2..].to_vec(),
                        response.body,
                    ));
                    write_stanza(&mut connection.output, "ok", &[])?;
                }
                "labels" => {
                    if labels.is_some() {
                        return Err(plugin_protocol_error("repeated labels stanza"));
                    }
                    labels = Some(response.args);
                    write_stanza(&mut connection.output, "ok", &[])?;
                }
                "error" => {
                    write_stanza(&mut connection.output, "ok", &[])?;
                    return Err(plugin_response_error(&response.body));
                }
                "done" => break,
                _ if handle_client_interaction(
                    &mut connection,
                    &self.ui,
                    &self.name,
                    &response,
                )? => {}
                _ => write_stanza(&mut connection.output, "unsupported", &[])?,
            }
        }
        connection.close();
        if stanzas.is_empty() {
            return Err(plugin_protocol_error(
                "plugin returned zero recipient stanzas",
            ));
        }
        let labels = labels.unwrap_or_default();
        self.labels
            .lock()
            .map_err(|_| plugin_protocol_error("plugin label lock poisoned"))?
            .clone_from(&labels);
        Ok((stanzas, labels))
    }
}

impl Recipient for PluginRecipient {
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
        self.wrap_inner(file_key).map(|(stanzas, _)| stanzas)
    }

    fn wrap_with_labels(&self, file_key: &[u8]) -> Result<(Vec<Stanza>, Vec<String>)> {
        self.wrap_inner(file_key)
    }
}

/// A client-side plugin identity.
#[derive(Clone)]
pub struct PluginIdentity {
    name: String,
    encoding: String,
    ui: ClientUi,
}

impl std::fmt::Debug for PluginIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginIdentity")
            .field("name", &self.name)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl PluginIdentity {
    /// Creates a plugin identity client.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the identity encoding is invalid.
    pub fn new(encoding: impl AsRef<str>, ui: ClientUi) -> Result<Self> {
        let (name, _) = parse_identity(encoding.as_ref())?;
        Ok(Self {
            name,
            encoding: encoding.as_ref().to_owned(),
            ui,
        })
    }

    /// Creates a plugin identity client without an encoded payload.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the plugin name is invalid.
    pub fn without_data(name: &str, ui: ClientUi) -> Result<Self> {
        let encoding =
            encode_identity(name, &[]).ok_or(AgeError::InvalidKey("invalid plugin name"))?;
        Self::new(encoding, ui)
    }

    /// Returns the plugin name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the identity encoding.
    #[must_use]
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    /// Returns an identity-derived recipient client.
    #[must_use]
    pub fn recipient(&self) -> PluginRecipient {
        PluginRecipient::from_identity(self)
    }
}

impl Identity for PluginIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut connection = open_client_connection(&self.name, "identity-v1")?;
        write_stanza(
            &mut connection.output,
            "add-identity",
            std::slice::from_ref(&self.encoding),
        )?;
        for stanza in stanzas {
            let mut args = vec!["0".to_owned(), stanza.r#type.clone()];
            args.extend(stanza.args.iter().cloned());
            write_stanza_with_body_args(
                &mut connection.output,
                "recipient-stanza",
                &args,
                &stanza.body,
            )?;
        }
        write_stanza(&mut connection.output, "done", &[])?;

        let mut file_key = None;
        loop {
            let response = read_client_stanza(&mut connection, &self.ui, &self.name)?;
            match response.r#type.as_str() {
                "file-key" => {
                    if response.args.len() != 1 || response.args[0] != "0" || file_key.is_some() {
                        return Err(plugin_protocol_error("malformed file-key stanza"));
                    }
                    if response.body.len() != 16 {
                        return Err(plugin_protocol_error("invalid plugin file key"));
                    }
                    file_key = Some(Zeroizing::new(response.body));
                    write_stanza(&mut connection.output, "ok", &[])?;
                }
                "error" => {
                    write_stanza(&mut connection.output, "ok", &[])?;
                    return Err(plugin_response_error(&response.body));
                }
                "done" => break,
                _ if handle_client_interaction(
                    &mut connection,
                    &self.ui,
                    &self.name,
                    &response,
                )? => {}
                _ => write_stanza(&mut connection.output, "unsupported", &[])?,
            }
        }
        connection.close();
        Ok(file_key)
    }
}

/// A callback that constructs a recipient from decoded plugin data.
pub type RecipientFactory =
    Arc<dyn Fn(&[u8], &PluginContext) -> Result<Box<dyn Recipient>> + Send + Sync>;
/// A callback that constructs an identity from decoded plugin data.
pub type IdentityFactory =
    Arc<dyn Fn(&[u8], &PluginContext) -> Result<Box<dyn Identity>> + Send + Sync>;

/// A server-side age plugin implementation.
///
/// [`Debug`](std::fmt::Debug) is hand-written and prints the normalized plugin
/// name and which factories are registered. A factory is a closure and cannot
/// be printed; requiring `Debug` of the caller's closures would put a trait
/// bound on this type that the caller has to satisfy for their own reasons.
/// Which factories are registered is what identifies a plugin that returns
/// "recipient-v1 not supported" or "identity-v1 not supported" at runtime.
pub struct Plugin {
    name: String,
    recipient: Option<RecipientFactory>,
    identity_as_recipient: Option<RecipientFactory>,
    identity: Option<IdentityFactory>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Plugin")
            .field("name", &self.name)
            .field("recipient", &self.recipient.is_some())
            .field(
                "identity_as_recipient",
                &self.identity_as_recipient.is_some(),
            )
            .field("identity", &self.identity.is_some())
            .finish()
    }
}

impl Plugin {
    /// Creates a plugin with a case-insensitive name.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] when the name is invalid.
    pub fn new(name: &str) -> Result<Self> {
        if !valid_plugin_name(name) {
            return Err(AgeError::InvalidKey("invalid plugin name"));
        }
        Ok(Self {
            name: name.to_ascii_lowercase(),
            recipient: None,
            identity_as_recipient: None,
            identity: None,
        })
    }

    /// Registers recipient construction for `age1<name>1...` values.
    #[must_use]
    pub fn handle_recipient(mut self, factory: RecipientFactory) -> Self {
        self.recipient = Some(factory);
        self
    }

    /// Registers identity-as-recipient construction for plugin identities.
    #[must_use]
    pub fn handle_identity_as_recipient(mut self, factory: RecipientFactory) -> Self {
        self.identity_as_recipient = Some(factory);
        self
    }

    /// Registers identity construction for `AGE-PLUGIN-<NAME>-1...` values.
    #[must_use]
    pub fn handle_identity(mut self, factory: IdentityFactory) -> Self {
        self.identity = Some(factory);
        self
    }

    /// Returns the normalized plugin name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runs the plugin and converts protocol errors into a process-style exit
    /// code.
    #[must_use]
    pub fn main(&self) -> i32 {
        self.run().unwrap_or(1)
    }

    /// Runs the plugin using the process arguments and standard streams.
    ///
    /// # Errors
    ///
    /// Returns protocol, I/O, or callback errors.
    pub fn run(&self) -> Result<i32> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        self.run_with_io(&args, stdin, stdout, stderr)
    }

    /// Runs the plugin state machine with explicit streams and arguments.
    ///
    /// # Errors
    ///
    /// Returns protocol, I/O, or callback errors.
    pub fn run_with_io<
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        E: Write + Send + 'static,
    >(
        &self,
        args: &[String],
        input: R,
        output: W,
        _error: E,
    ) -> Result<i32> {
        let state = args
            .iter()
            .find_map(|arg| arg.strip_prefix("--age-plugin="))
            .ok_or_else(|| plugin_protocol_error("missing plugin state machine"))?;
        let connection = Arc::new(Mutex::new(ProtocolConnection {
            input: Box::new(BufReader::new(input)),
            output: Box::new(output),
        }));
        let context = PluginContext {
            connection: Arc::clone(&connection),
        };
        match state {
            "recipient-v1" => self.recipient_v1(&context),
            "identity-v1" => self.identity_v1(&context),
            _ => Ok(4),
        }
    }

    fn recipient_v1(&self, context: &PluginContext) -> Result<i32> {
        if self.recipient.is_none() && self.identity_as_recipient.is_none() {
            return Err(plugin_protocol_error("recipient-v1 not supported"));
        }
        let mut recipients = Vec::new();
        let mut file_keys = Vec::new();
        let mut supports_labels = false;
        loop {
            let stanza = context.read()?;
            match stanza.r#type.as_str() {
                "add-recipient" => recipients.push((
                    stanza
                        .args
                        .first()
                        .cloned()
                        .ok_or_else(|| plugin_protocol_error("missing plugin recipient"))?,
                    false,
                )),
                "add-identity" => recipients.push((
                    stanza
                        .args
                        .first()
                        .cloned()
                        .ok_or_else(|| plugin_protocol_error("missing plugin identity"))?,
                    true,
                )),
                "extension-labels" => supports_labels = true,
                "wrap-file-key" => file_keys.push(stanza.body),
                "done" => break,
                _ => {}
            }
        }
        if recipients.is_empty() || file_keys.is_empty() {
            return Err(plugin_protocol_error(
                "plugin recipient request is incomplete",
            ));
        }
        let mut parsed = Vec::new();
        for (encoding, identity) in recipients {
            let (name, recipient) = if identity {
                let (name, data) = parse_identity(&encoding)?;
                let factory = self
                    .identity_as_recipient
                    .as_ref()
                    .ok_or_else(|| plugin_protocol_error("identity encodings not supported"))?;
                (name, factory(&data, context)?)
            } else {
                let (name, data) = parse_recipient(&encoding)?;
                let factory = self
                    .recipient
                    .as_ref()
                    .ok_or_else(|| plugin_protocol_error("recipient encodings not supported"))?;
                (name, factory(&data, context)?)
            };
            if name != self.name {
                return Err(plugin_protocol_error("unsupported plugin name"));
            }
            parsed.push(recipient);
        }
        let mut all_stanzas = Vec::new();
        let mut expected_labels = None;
        for (index, file_key) in file_keys.iter().enumerate() {
            for recipient in &parsed {
                let (stanzas, mut labels) = recipient.wrap_with_labels(file_key)?;
                labels.sort();
                if let Some(expected) = &expected_labels
                    && expected != &labels
                {
                    return Err(plugin_protocol_error("recipient labels do not match"));
                }
                if expected_labels.is_none() {
                    expected_labels = Some(labels);
                }
                all_stanzas.push((index, stanzas.clone()));
            }
        }
        if supports_labels {
            let labels = expected_labels.unwrap_or_default();
            context.write("labels", &labels, &[])?;
            context.expect_ok()?;
        }
        for (index, stanzas) in all_stanzas {
            for stanza in stanzas {
                let mut args = vec![index.to_string(), stanza.r#type];
                args.extend(stanza.args);
                context.write("recipient-stanza", &args, &stanza.body)?;
                context.expect_ok()?;
            }
        }
        context.write("done", &[], &[])?;
        Ok(0)
    }

    fn identity_v1(&self, context: &PluginContext) -> Result<i32> {
        let factory = self
            .identity
            .as_ref()
            .ok_or_else(|| plugin_protocol_error("identity-v1 not supported"))?;
        let mut encodings = Vec::new();
        let mut files: Vec<Vec<Stanza>> = Vec::new();
        loop {
            let stanza = context.read()?;
            match stanza.r#type.as_str() {
                "add-identity" => encodings.push(
                    stanza
                        .args
                        .first()
                        .cloned()
                        .ok_or_else(|| plugin_protocol_error("missing plugin identity"))?,
                ),
                "recipient-stanza" => {
                    if stanza.args.len() < 2 || stanza.args[0] != "0" {
                        return Err(plugin_protocol_error("invalid recipient stanza index"));
                    }
                    let recipient_stanza = Stanza::new(
                        stanza.args[1].clone(),
                        stanza.args[2..].to_vec(),
                        stanza.body,
                    );
                    if let Some(file) = files.last_mut() {
                        file.push(recipient_stanza);
                    } else {
                        files.push(vec![recipient_stanza]);
                    }
                }
                "done" => break,
                _ => {}
            }
        }
        if encodings.is_empty() || files.is_empty() {
            return Err(plugin_protocol_error(
                "plugin identity request is incomplete",
            ));
        }
        let mut identities = Vec::new();
        for encoding in encodings {
            let (name, data) = parse_identity(&encoding)?;
            if name != self.name {
                return Err(plugin_protocol_error("unsupported plugin name"));
            }
            identities.push(factory(&data, context)?);
        }
        for (index, stanzas) in files.iter().enumerate() {
            for identity in &identities {
                if let Some(file_key) = identity.unwrap(stanzas)? {
                    context.write("file-key", &[index.to_string()], &file_key)?;
                    context.expect_ok()?;
                    break;
                }
            }
        }
        context.write("done", &[], &[])?;
        Ok(0)
    }
}

/// A context passed to plugin recipient and identity factories.
///
/// The context can be cloned and retained by a recipient or identity to issue
/// interactive protocol requests while its `wrap` or `unwrap` method runs.
#[derive(Clone)]
pub struct PluginContext {
    connection: Arc<Mutex<ProtocolConnection>>,
}

impl std::fmt::Debug for PluginContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PluginContext")
    }
}

impl PluginContext {
    fn read(&self) -> Result<Stanza> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| plugin_protocol_error("plugin connection lock poisoned"))?;
        read_stanza(&mut *connection.input)
    }

    fn write(&self, kind: &str, args: &[String], body: &[u8]) -> Result<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| plugin_protocol_error("plugin connection lock poisoned"))?;
        write_stanza_with_body_args(&mut *connection.output, kind, args, body)
    }

    fn expect_ok(&self) -> Result<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| plugin_protocol_error("plugin connection lock poisoned"))?;
        expect_ok(&mut *connection.input)
    }

    /// Sends a message to the client and waits for its response.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] if the client rejects the request or the protocol
    /// is malformed.
    pub fn display_message(&self, message: &str) -> Result<()> {
        self.write("msg", &[], message.as_bytes())?;
        let response = self.read()?;
        if response.r#type == "fail" {
            return Err(plugin_protocol_error("client rejected message"));
        }
        expect_response_ok(&response)
    }

    /// Requests a public or secret value from the client.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] if the client rejects the request or the protocol
    /// is malformed.
    pub fn request_value(&self, prompt: &str, secret: bool) -> Result<Zeroizing<Vec<u8>>> {
        self.write(
            if secret {
                "request-secret"
            } else {
                "request-public"
            },
            &[],
            prompt.as_bytes(),
        )?;
        let response = self.read()?;
        if response.r#type == "fail" {
            return Err(plugin_protocol_error("client rejected value request"));
        }
        if response.r#type != "ok" {
            return Err(plugin_protocol_error("invalid value response"));
        }
        Ok(Zeroizing::new(response.body))
    }

    /// Requests confirmation from the client.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError`] if the client rejects the request or the protocol
    /// is malformed.
    pub fn confirm(&self, prompt: &str, yes: &str, no: &str) -> Result<bool> {
        let mut args = vec![encode_raw(yes.as_bytes())];
        if !no.is_empty() {
            args.push(encode_raw(no.as_bytes()));
        }
        self.write("confirm", &args, prompt.as_bytes())?;
        let response = self.read()?;
        if response.r#type == "fail" {
            return Err(plugin_protocol_error("client rejected confirmation"));
        }
        if response.r#type != "ok"
            || response.args.len() != 1
            || (response.args[0] != "yes" && response.args[0] != "no")
        {
            return Err(plugin_protocol_error("invalid confirmation response"));
        }
        Ok(response.args[0] == "yes")
    }
}

struct ProtocolConnection {
    input: Box<dyn BufRead + Send>,
    output: Box<dyn Write + Send>,
}

struct ClientConnection {
    child: Child,
    input: BufReader<ChildStdout>,
    output: ChildStdin,
}

impl ClientConnection {
    fn close(self) {
        let Self {
            mut child,
            input,
            output,
        } = self;
        drop(output);
        drop(input);
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn open_client_connection(name: &str, protocol: &str) -> Result<ClientConnection> {
    if !valid_plugin_name(name) || name.contains(std::path::MAIN_SEPARATOR) {
        return Err(AgeError::InvalidKey("invalid plugin name"));
    }
    let mut child = Command::new(format!("age-plugin-{name}"))
        .arg(format!("--age-plugin={protocol}"))
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                AgeError::InvalidKey("age plugin executable not found")
            } else {
                AgeError::Io(error)
            }
        })?;
    let output = child
        .stdin
        .take()
        .ok_or_else(|| plugin_protocol_error("plugin stdin unavailable"))?;
    let input = child
        .stdout
        .take()
        .ok_or_else(|| plugin_protocol_error("plugin stdout unavailable"))?;
    Ok(ClientConnection {
        child,
        input: BufReader::new(input),
        output,
    })
}

fn read_client_stanza(
    connection: &mut ClientConnection,
    ui: &ClientUi,
    name: &str,
) -> Result<Stanza> {
    let cancel = ui.wait_timer.as_ref().map(|timer| {
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let timer = Arc::clone(timer);
        let name = name.to_owned();
        let worker = thread::spawn(move || {
            if cancel_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                timer(&name);
            }
        });
        (cancel_tx, worker)
    });
    let result = read_stanza(&mut connection.input);
    drop(cancel);
    result
}

fn handle_client_interaction(
    connection: &mut ClientConnection,
    ui: &ClientUi,
    name: &str,
    stanza: &Stanza,
) -> Result<bool> {
    if let Some(timer) = &ui.wait_timer {
        timer(name);
    }
    match stanza.r#type.as_str() {
        "msg" => {
            if let Some(callback) = &ui.display_message {
                if callback(name, &String::from_utf8_lossy(&stanza.body)).is_ok() {
                    write_stanza(&mut connection.output, "ok", &[])?;
                } else {
                    write_stanza(&mut connection.output, "fail", &[])?;
                }
            } else {
                write_stanza(&mut connection.output, "fail", &[])?;
            }
        }
        "request-public" | "request-secret" => {
            let secret = stanza.r#type == "request-secret";
            if let Some(callback) = &ui.request_value {
                if let Ok(value) = callback(name, &String::from_utf8_lossy(&stanza.body), secret) {
                    write_stanza_with_body(&mut connection.output, "ok", value.as_bytes())?;
                } else {
                    write_stanza(&mut connection.output, "fail", &[])?;
                }
            } else {
                write_stanza(&mut connection.output, "fail", &[])?;
            }
        }
        "confirm" => {
            if stanza.args.is_empty() || stanza.args.len() > 2 {
                return Err(plugin_protocol_error("invalid confirm arguments"));
            }
            let yes = decode_raw(&stanza.args[0])
                .map_err(|_| plugin_protocol_error("invalid confirm yes option"))?;
            let no = if let Some(value) = stanza.args.get(1) {
                decode_raw(value).map_err(|_| plugin_protocol_error("invalid confirm no option"))?
            } else {
                Vec::new()
            };
            if let Some(callback) = &ui.confirm {
                if let Ok(chosen) = callback(
                    name,
                    &String::from_utf8_lossy(&stanza.body),
                    &String::from_utf8_lossy(&yes),
                    &String::from_utf8_lossy(&no),
                ) {
                    write_stanza(
                        &mut connection.output,
                        "ok",
                        &[if chosen { "yes" } else { "no" }.to_owned()],
                    )?;
                } else {
                    write_stanza(&mut connection.output, "fail", &[])?;
                }
            } else {
                write_stanza(&mut connection.output, "fail", &[])?;
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn read_stanza(input: &mut (impl BufRead + ?Sized)) -> Result<Stanza> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(AgeError::Truncated);
    }
    let line = line
        .strip_suffix('\n')
        .ok_or_else(|| plugin_protocol_error("unterminated plugin stanza"))?;
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.len() > 16 * 1024 || !line.starts_with("-> ") {
        return Err(plugin_protocol_error("invalid plugin stanza"));
    }
    let fields = line[3..].split(' ').collect::<Vec<_>>();
    if fields.is_empty()
        || fields.iter().any(|field| {
            field.is_empty() || !field.bytes().all(|value| (33..=126).contains(&value))
        })
    {
        return Err(plugin_protocol_error("invalid plugin stanza fields"));
    }
    let mut encoded = String::new();
    loop {
        let mut body_line = String::new();
        if input.read_line(&mut body_line)? == 0 {
            return Err(AgeError::Truncated);
        }
        let body_line = body_line
            .strip_suffix('\n')
            .ok_or_else(|| plugin_protocol_error("unterminated plugin body"))?;
        let body_line = body_line.strip_suffix('\r').unwrap_or(body_line);
        if body_line.len() > 64 || body_line.is_empty() {
            break;
        }
        if !body_line.bytes().all(|value| (33..=126).contains(&value)) {
            return Err(plugin_protocol_error("invalid plugin body"));
        }
        encoded.push_str(body_line);
    }
    let body = decode_raw(&encoded)?;
    Ok(Stanza::new(
        fields[0],
        fields[1..].iter().map(|field| (*field).to_owned()),
        body,
    ))
}

fn write_stanza<W: Write + ?Sized>(output: &mut W, kind: &str, args: &[String]) -> Result<()> {
    write_stanza_with_body_args(output, kind, args, &[])
}

fn write_stanza_with_body<W: Write + ?Sized>(
    output: &mut W,
    kind: &str,
    body: &[u8],
) -> Result<()> {
    write_stanza_with_body_args(output, kind, &[], body)
}

fn write_stanza_with_body_args<W: Write + ?Sized>(
    output: &mut W,
    kind: &str,
    args: &[String],
    body: &[u8],
) -> Result<()> {
    if kind.is_empty()
        || !kind.bytes().all(|value| (33..=126).contains(&value))
        || args
            .iter()
            .any(|arg| arg.is_empty() || !arg.bytes().all(|value| (33..=126).contains(&value)))
    {
        return Err(AgeError::InvalidFormat("invalid plugin stanza"));
    }
    let mut line = format!("-> {kind}");
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    writeln!(output, "{line}").map_err(AgeError::from)?;
    let encoded = encode_raw(body);
    for chunk in encoded.as_bytes().chunks(64) {
        output.write_all(chunk).map_err(AgeError::from)?;
        output.write_all(b"\n").map_err(AgeError::from)?;
    }
    if encoded.len().is_multiple_of(64) {
        output.write_all(b"\n").map_err(AgeError::from)?;
    }
    Ok(())
}

fn expect_ok(input: &mut (impl BufRead + ?Sized)) -> Result<()> {
    let response = read_stanza(input)?;
    if response.r#type != "ok" || !response.args.is_empty() || !response.body.is_empty() {
        return Err(plugin_protocol_error("expected plugin ok"));
    }
    Ok(())
}

fn expect_response_ok(stanza: &Stanza) -> Result<()> {
    if stanza.r#type != "ok" || !stanza.args.is_empty() || !stanza.body.is_empty() {
        return Err(plugin_protocol_error("expected plugin ok"));
    }
    Ok(())
}

fn plugin_protocol_error(_message: &'static str) -> AgeError {
    AgeError::InvalidFormat("invalid age plugin protocol")
}

fn plugin_response_error(body: &[u8]) -> AgeError {
    AgeError::Io(io::Error::other(String::from_utf8_lossy(body).into_owned()))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use zeroize::Zeroizing;

    use super::{
        encode_identity, encode_recipient, parse_identity, parse_recipient, valid_plugin_name,
    };
    use crate::{Identity, Plugin, Recipient, Result, Stanza};

    #[test]
    fn plugin_names_and_encodings_match_protocol() {
        assert!(valid_plugin_name("vendor_1+x"));
        assert!(!valid_plugin_name(""));
        assert!(!valid_plugin_name("../vendor"));
        let recipient = encode_recipient("Vendor", &[1, 2, 3]).expect("recipient");
        let (name, data) = parse_recipient(&recipient).expect("parse recipient");
        assert_eq!(name, "vendor");
        assert_eq!(data, [1, 2, 3]);
        let identity = encode_identity("Vendor", &[4, 5]).expect("identity");
        let (name, data) = parse_identity(&identity).expect("parse identity");
        assert_eq!(name, "vendor");
        assert_eq!(data, [4, 5]);
    }

    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct TestRecipient;

    impl Recipient for TestRecipient {
        fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
            Ok(vec![Stanza::new(
                "test",
                std::iter::empty::<String>(),
                file_key.to_vec(),
            )])
        }
    }

    struct TestIdentity;

    impl Identity for TestIdentity {
        fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(stanzas
                .first()
                .map(|stanza| Zeroizing::new(stanza.body.clone())))
        }
    }

    #[test]
    fn recipient_state_machine_writes_stanzas_and_labels() {
        let plugin = Plugin::new("test")
            .expect("plugin")
            .handle_recipient(Arc::new(|_, _| {
                Ok(Box::new(TestRecipient) as Box<dyn Recipient>)
            }));
        let recipient = encode_recipient("test", &[]).expect("recipient encoding");
        let input = format!(
            "-> add-recipient {recipient}\n\n-> wrap-file-key\n{}\n\n-> extension-labels\n\n-> done\n\n-> ok\n\n-> ok\n\n",
            crate::codec::encode_raw(&[0u8; 16])
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let code = plugin
            .run_with_io(
                &["--age-plugin=recipient-v1".to_owned()],
                io::Cursor::new(input),
                Buffer(Arc::clone(&output)),
                Vec::new(),
            )
            .expect("recipient state machine");
        assert_eq!(code, 0);
        let output =
            String::from_utf8(output.lock().expect("buffer lock").clone()).expect("UTF-8 output");
        assert!(output.contains("-> labels\n\n"));
        assert!(output.contains("-> recipient-stanza 0 test\n"));
        assert!(output.ends_with("-> done\n\n"));
    }

    #[test]
    fn identity_state_machine_writes_file_key() {
        let plugin = Plugin::new("test")
            .expect("plugin")
            .handle_identity(Arc::new(|_, _| {
                Ok(Box::new(TestIdentity) as Box<dyn Identity>)
            }));
        let identity = encode_identity("test", &[]).expect("identity encoding");
        let input = format!(
            "-> add-identity {identity}\n\n-> recipient-stanza 0 test\n{}\n\n-> done\n\n-> ok\n\n",
            crate::codec::encode_raw(&[0u8; 16])
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let code = plugin
            .run_with_io(
                &["--age-plugin=identity-v1".to_owned()],
                io::Cursor::new(input),
                Buffer(Arc::clone(&output)),
                Vec::new(),
            )
            .expect("identity state machine");
        assert_eq!(code, 0);
        let output =
            String::from_utf8(output.lock().expect("buffer lock").clone()).expect("UTF-8 output");
        assert!(output.contains("-> file-key 0\n"));
        assert!(output.ends_with("-> done\n\n"));
    }

    #[test]
    fn plugin_encodings_reject_wrong_prefixes() {
        assert!(parse_recipient("age1not-a-valid-name!").is_err());
        assert!(parse_identity("AGE-SECRET-KEY-1abc").is_err());
    }
}
