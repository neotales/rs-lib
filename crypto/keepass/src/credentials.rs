use std::{fmt, io::Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use quick_xml::Reader;
use quick_xml::events::Event;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KdbxError, KdbxFailureKind};

/// Supplies a hashed 32-byte KeePass credential component.
///
/// This is also the integration seam for an application-owned challenge-response
/// or platform credential adapter. The core cannot validate a challenge or
/// authenticate a hardware response; those responsibilities belong to the
/// implementation behind this trait.
pub trait CredentialProvider {
    /// Returns exactly one 32-byte key component.
    ///
    /// # Errors
    ///
    /// Implementations may return a format or I/O error. The returned bytes
    /// are copied into the composite-key buffer and wiped by the caller.
    fn key_component(&mut self) -> Result<[u8; 32], KdbxError>;
}

/// Password and optional credential components used to open a KDBX file.
///
/// The crate supplies password and key-file components. A hardware or
/// challenge-response integration can implement [`CredentialProvider`] and
/// return its independently derived 32-byte component, but this crate does
/// not provide a built-in challenge-response protocol, authenticator, or
/// platform key store. A provider must own challenge lifetime, replay and
/// timeout policy, secret storage, and device/platform I/O.
///
/// [`Debug`](std::fmt::Debug) is hand-written. `password` is the master
/// password, held as a plain `Vec<u8>` that is zeroed on drop, and a derived
/// `Debug` would print it in full in every log line and test failure that
/// touches a credentials value. The `providers` vector holds boxed caller
/// trait objects, which are not `Debug` either, and requiring that of the
/// caller's implementation would put a bound on this type that has nothing to
/// do with this crate. What remains printable is the shape: whether a password
/// component is present at all, and how many provider components will
/// contribute to the composite key. A credentials value with no password and
/// one provider is a different misconfiguration from one with a password and
/// three providers, and the counts are what distinguishes them.
pub struct KdbxCredentials {
    password: Option<Vec<u8>>,
    providers: Vec<Box<dyn CredentialProvider + Send>>,
}

impl KdbxCredentials {
    /// Creates password-only credentials. Empty passwords are rejected.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty password.
    pub fn password(password: impl AsRef<[u8]>) -> Result<Self, KdbxError> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(invalid("password must not be empty"));
        }
        Ok(Self {
            password: Some(password.to_vec()),
            providers: Vec::new(),
        })
    }

    /// Creates password-plus-provider credentials.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when no component was supplied.
    pub fn from_parts(
        password: Option<&[u8]>,
        providers: Vec<Box<dyn CredentialProvider + Send>>,
    ) -> Result<Self, KdbxError> {
        let password = match password {
            Some(value) if !value.is_empty() => Some(value.to_vec()),
            Some(_) => return Err(invalid("password must not be empty")),
            None => None,
        };
        if password.is_none() && providers.is_empty() {
            return Err(invalid("at least one credential component is required"));
        }
        Ok(Self {
            password,
            providers,
        })
    }

    /// Creates password-plus-one-provider credentials.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the password is present but empty.
    pub fn with_provider(
        password: Option<&str>,
        provider: Box<dyn CredentialProvider + Send>,
    ) -> Result<Self, KdbxError> {
        Self::from_parts(password.map(str::as_bytes), vec![provider])
    }

    /// Creates credentials from an in-memory key file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not a supported key-file form.
    pub fn key_file(data: impl AsRef<[u8]>) -> Result<Self, KdbxError> {
        Self::from_parts(None, vec![Box::new(KdbxKeyFile::parse(data.as_ref())?)])
    }

    /// Derives the KeePass composite key.
    ///
    /// The returned 32-byte key is caller-owned. Wrap it in
    /// [`zeroize::Zeroizing`] (or explicitly zeroize it) if it must remain
    /// outside the immediate load/save operation.
    ///
    /// # Errors
    ///
    /// Returns provider errors or a malformed credential error. Components
    /// already obtained from providers are zeroized even when a later provider
    /// returns an error.
    pub fn composite_key(&mut self) -> Result<[u8; 32], KdbxError> {
        let mut components = Zeroizing::new(Vec::with_capacity(1 + self.providers.len()));
        if let Some(password) = &self.password {
            components.push(Sha256::digest(password).into());
        }
        for provider in &mut self.providers {
            components.push(provider.key_component()?);
        }
        if components.is_empty() {
            return Err(invalid("at least one credential component is required"));
        }
        let mut input = Zeroizing::new(Vec::with_capacity(components.len() * 32));
        for component in &*components {
            input.extend_from_slice(component);
        }
        Ok(Sha256::digest(&*input).into())
    }
}

impl Drop for KdbxCredentials {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
    }
}

impl fmt::Debug for KdbxCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `password.is_some()` and `providers.len()` only. The password bytes
        // and the boxed providers are both deliberately unrepresented; see the
        // type documentation for why.
        formatter
            .debug_struct("KdbxCredentials")
            .field("password", &self.password.is_some())
            .field("provider_count", &self.providers.len())
            .finish()
    }
}

fn invalid(message: &'static str) -> KdbxError {
    KdbxError::new(KdbxFailureKind::InvalidArgument, message)
}

/// KeePass key-file formats supported by the crate.
///
/// [`Debug`](std::fmt::Debug) is hand-written and prints the type name and
/// nothing else. The only field is the 32-byte composite-key contribution
/// hashed or decoded out of the key file, which is key material: a caller
/// holding the wrong key file has to be able to tell which one they have from a
/// log line, and the only thing that could tell them is the bytes themselves,
/// which is exactly what must not be printed. A fingerprint would not help
/// either — the key file is user-chosen, and its hash is a hash of a secret.
/// There is also no length to report: the field is a fixed 32 bytes, so its
/// length carries no information about which key file this is.
pub struct KdbxKeyFile {
    key: [u8; 32],
}

impl KdbxKeyFile {
    /// Parses raw 32 bytes, 64-character hex, XML v1/v2, or arbitrary-file fallback.
    ///
    /// # Errors
    ///
    /// Returns malformed-input for an invalid explicit format. Arbitrary
    /// non-empty data is hashed according to KeePass's fallback rule.
    pub fn parse(data: &[u8]) -> Result<Self, KdbxError> {
        if data.len() > 64 * 1024 {
            return Err(KdbxError::resource_limit(
                "key file exceeds the configured limit",
            ));
        }
        if data.len() == 32 {
            return Ok(Self {
                key: data.try_into().expect("length checked"),
            });
        }
        if data.len() == 64 {
            if !data.iter().all(u8::is_ascii_hexdigit) {
                return Err(KdbxError::malformed("invalid key-file hex"));
            }
            let mut key = [0; 32];
            for (index, byte) in key.iter_mut().enumerate() {
                let pair = &data[index * 2..index * 2 + 2];
                let text = std::str::from_utf8(pair)
                    .map_err(|_| KdbxError::malformed("invalid key-file hex"))?;
                *byte = u8::from_str_radix(text, 16)
                    .map_err(|_| KdbxError::malformed("invalid key-file hex"))?;
            }
            return Ok(Self { key });
        }
        if data.starts_with(b"<") {
            return Self::parse_xml(data);
        }
        if data.is_empty() {
            return Err(KdbxError::malformed("key-file must not be empty"));
        }
        Ok(Self {
            key: Sha256::digest(data).into(),
        })
    }

    fn parse_xml(data: &[u8]) -> Result<Self, KdbxError> {
        if data.len() > 64 * 1024 {
            return Err(KdbxError::resource_limit(
                "key-file XML exceeds the configured limit",
            ));
        }
        let mut reader = Reader::from_reader(data);
        reader.config_mut().trim_text(true);
        reader.config_mut().enable_all_checks(true);
        let mut version = None;
        let mut key_data = None;
        let mut key_hash = None;
        let mut current = String::new();
        let mut depth = 0usize;
        let mut root_seen = false;
        loop {
            match reader
                .read_event()
                .map_err(|_| KdbxError::malformed("invalid key-file XML"))?
            {
                Event::Start(element) => {
                    let name = element.name().as_ref().to_owned();
                    if depth == 0 {
                        root_seen = name == "KeyFile";
                    }
                    depth += 1;
                    if name == "Data" {
                        for attribute in element.attributes().with_checks(true) {
                            let attribute = attribute.map_err(|_| {
                                KdbxError::malformed("invalid key-file XML attribute")
                            })?;
                            if attribute.key.as_ref() == "Hash" {
                                key_hash = Some(attribute.value.to_string());
                            }
                        }
                    }
                    current = name;
                }
                Event::Text(text) => {
                    // quick-xml 0.42 validates UTF-8 when it constructs the event,
                    // so `as_ref()` is already `&str` and the explicit
                    // `from_utf8` re-check this used to do is gone: the error it
                    // raised cannot be reached any more.
                    let value = text.as_ref().to_owned();
                    match current.as_str() {
                        "Version" => version = Some(value),
                        "Data" => key_data = Some(value),
                        _ => {}
                    }
                }
                Event::DocType(_) | Event::GeneralRef(_) => {
                    return Err(KdbxError::unsupported(
                        "DTD and external entities are not permitted in key-file XML",
                    ));
                }
                Event::End(_element) => {
                    current.clear();
                    depth = depth.saturating_sub(1);
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !root_seen {
            return Err(KdbxError::malformed("key-file XML root must be KeyFile"));
        }
        let value = key_data.ok_or_else(|| KdbxError::malformed("key-file data is required"))?;
        let bytes = if version.as_deref() == Some("2.0") {
            let compact: Vec<u8> = value
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            if compact.len() % 2 != 0 {
                return Err(KdbxError::malformed(
                    "XML v2 key must contain complete hex bytes",
                ));
            }
            if !compact.iter().all(u8::is_ascii_hexdigit) {
                return Err(KdbxError::malformed("invalid XML v2 key"));
            }
            let bytes = compact
                .chunks_exact(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair)
                        .map_err(|_| KdbxError::malformed("invalid XML v2 key"))?;
                    u8::from_str_radix(text, 16)
                        .map_err(|_| KdbxError::malformed("invalid XML v2 key"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if bytes.len() != 32 {
                return Err(KdbxError::malformed("key-file data must contain 32 bytes"));
            }
            let expected = hex_prefix(&Sha256::digest(&bytes));
            if !key_hash
                .as_deref()
                .is_some_and(|hash| hash.eq_ignore_ascii_case(&expected))
            {
                return Err(KdbxError::malformed("key-file v2 hash validation failed"));
            }
            bytes
        } else {
            STANDARD
                .decode(&value)
                .map_err(|_| KdbxError::malformed("invalid XML v1 key data"))?
        };
        if bytes.len() != 32 {
            return Err(KdbxError::malformed("key-file data must contain 32 bytes"));
        }
        Ok(Self {
            key: bytes.try_into().expect("length checked"),
        })
    }
}

fn hex_prefix(data: &[u8]) -> String {
    data.iter()
        .take(4)
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

impl CredentialProvider for KdbxKeyFile {
    fn key_component(&mut self) -> Result<[u8; 32], KdbxError> {
        Ok(self.key)
    }
}

impl fmt::Debug for KdbxKeyFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Nothing to report but the type. `key` is the composite-key component
        // and is never printed; see the type documentation.
        formatter.write_str("KdbxKeyFile")
    }
}

impl Drop for KdbxKeyFile {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Reads a key file from a caller-managed stream.
pub fn read_key_file(source: impl Read) -> Result<KdbxKeyFile, KdbxError> {
    let mut data = Vec::new();
    source
        .take(64 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| KdbxError::new(KdbxFailureKind::Io, "unable to read key file"))?;
    if data.len() > 64 * 1024 {
        data.zeroize();
        return Err(KdbxError::resource_limit(
            "key file exceeds the configured limit",
        ));
    }
    let result = KdbxKeyFile::parse(&data);
    data.zeroize();
    result
}
