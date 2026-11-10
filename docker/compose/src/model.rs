use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use crate::error::ComposeError;
use crate::policy::ComposeValidationMode;

/// A normalized Compose environment map.
///
/// `Some(value)` is an explicit value, including an explicit empty string.
/// `None` is the normalized representation of a pass-through entry such as
/// `environment: [TOKEN]`.  It is resolved only from injected values; this
/// crate never reads the host process environment.
pub type Environment = BTreeMap<String, Option<String>>;

/// An error returned when a value is not a usable image reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidImageReference;

impl fmt::Display for InvalidImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("image reference must be non-empty and contain no whitespace")
    }
}

impl std::error::Error for InvalidImageReference {}

/// A structurally validated Docker image reference.
///
/// Interpolation tokens are allowed in this pre-resolution model.  The
/// resolver validates the expanded value again before producing a resolved
/// service.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ImageReference(String);

impl ImageReference {
    /// Creates a structurally validated image reference.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty value, leading/trailing whitespace, or
    /// embedded whitespace/control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidImageReference> {
        let value = value.into();
        let invalid = value.is_empty()
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control());
        if invalid {
            return Err(InvalidImageReference);
        }
        Ok(Self(value))
    }

    /// Returns the image reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the reference and returns its text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ImageReference {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for ImageReference {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl TryFrom<String> for ImageReference {
    type Error = InvalidImageReference;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ImageReference {
    type Error = InvalidImageReference;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ImageReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ImageReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// One explicit, caller-supplied Compose include path.
///
/// The path is never opened by this crate.  A resolver receives a separate
/// path-to-document map when `IncludePolicy::CallerSupplied` is selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeInclude {
    /// Include path as written in the normalized document.
    pub path: String,
}

impl ComposeInclude {
    /// Creates an include entry.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

/// A normalized, image-based Compose service.
///
/// The first slice intentionally contains only the service/image/environment
/// surface needed by the deterministic fixtures.  Other Compose fields are
/// diagnosed or handled by the selected validation mode rather than silently
/// discarded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeService {
    /// Image used to run the service.
    pub image: ImageReference,
    /// Explicit and pass-through environment entries.
    #[serde(default)]
    pub environment: Environment,
}

impl ComposeService {
    /// Creates a service with an empty environment.
    #[must_use]
    pub fn new(image: ImageReference) -> Self {
        Self {
            image,
            environment: Environment::new(),
        }
    }

    /// Returns the value associated with an environment key.
    ///
    /// The outer option distinguishes an absent key from a present pass-through
    /// entry; the inner option distinguishes pass-through from an explicit
    /// value.
    #[must_use]
    pub fn environment_value(&self, key: &str) -> Option<Option<&str>> {
        self.environment.get(key).map(|value| value.as_deref())
    }
}

/// Options controlling source parsing and bounded validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseOptions {
    /// Treatment of fields outside the bounded normalized schema.
    pub validation: ComposeValidationMode,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            validation: ComposeValidationMode::Strict,
        }
    }
}

/// A normalized Compose document.
///
/// The document is data-only and contains no source spans or Docker client
/// handles.  Service and environment maps use `BTreeMap`, so serialization
/// and iteration are deterministic.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeDocument {
    /// Optional Compose project name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional legacy Compose format version, retained for compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Normalized services keyed by service name.
    #[serde(default)]
    pub services: BTreeMap<String, ComposeService>,
    /// Caller-supplied include paths, if the source contains includes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<ComposeInclude>,
}

impl ComposeDocument {
    /// Parses a YAML Compose source using strict bounded validation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed YAML, an invalid document shape, or a
    /// field rejected by [`ComposeValidationMode::Strict`].
    pub fn parse_yaml(source: &str, path: &str) -> Result<Self, ComposeError> {
        Self::parse_yaml_with_options(source, path, ParseOptions::default())
    }

    /// Parses a YAML Compose source with explicit validation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot be normalized under `options`.
    pub fn parse_yaml_with_options(
        source: &str,
        path: &str,
        options: ParseOptions,
    ) -> Result<Self, ComposeError> {
        let value: Value = serde_yaml::from_str(source).map_err(|error| {
            ComposeError::new(
                "compose_parse",
                format!("could not parse Compose YAML: {error}"),
                Some(path.to_owned()),
                "$",
            )
        })?;
        Self::from_yaml_value(&value, path, options.validation)
    }

    /// Parses a JSON Compose source using strict bounded validation.
    ///
    /// JSON is validated as JSON before it is passed through the same bounded
    /// normalizer used for YAML.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON or a rejected normalized field.
    pub fn parse_json(source: &str, path: &str) -> Result<Self, ComposeError> {
        Self::parse_json_with_options(source, path, ParseOptions::default())
    }

    /// Parses a JSON Compose source with explicit validation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot be normalized under `options`.
    pub fn parse_json_with_options(
        source: &str,
        path: &str,
        options: ParseOptions,
    ) -> Result<Self, ComposeError> {
        serde_json::from_str::<serde_json::Value>(source).map_err(|error| {
            ComposeError::new(
                "compose_parse",
                format!("could not parse Compose JSON: {error}"),
                Some(path.to_owned()),
                "$",
            )
        })?;
        Self::parse_yaml_with_options(source, path, options)
    }

    /// Parses a source that may be either YAML or JSON with explicit policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot be normalized under `options`.
    pub fn from_str_with_options(
        source: &str,
        path: &str,
        options: ParseOptions,
    ) -> Result<Self, ComposeError> {
        Self::parse_yaml_with_options(source, path, options)
    }

    /// Serializes the normalized document as deterministic pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be represented by `serde_json`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serializes the normalized document as YAML.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be represented by `serde_yaml`.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Returns a service by name.
    #[must_use]
    pub fn service(&self, name: &str) -> Option<&ComposeService> {
        self.services.get(name)
    }

    /// Validates invariants that can be bypassed by a manually constructed
    /// normalized model.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid project name, service name, include
    /// path, or environment key.
    pub fn validate(&self) -> Result<(), ComposeError> {
        validate_document(self, None)
    }

    fn from_yaml_value(
        value: &Value,
        path: &str,
        validation: ComposeValidationMode,
    ) -> Result<Self, ComposeError> {
        let root = mapping(value, path, "$")?;
        reject_duplicate_keys(root, path, "$")?;
        let mut document = Self::default();

        for (key, value) in root {
            let key = scalar_key(key, path, "$")?;
            match key.as_str() {
                "name" => {
                    document.name = Some(optional_scalar(value, path, "$.name")?);
                }
                "version" => {
                    document.version = Some(optional_scalar(value, path, "$.version")?);
                }
                "services" => {
                    document.services = parse_services(value, path, validation)?;
                }
                "include" => document.include = parse_includes(value, path)?,
                _ if key.starts_with("x-") => {}
                _ if validation == ComposeValidationMode::Loose => {}
                _ => {
                    return Err(ComposeError::new(
                        "compose_unknown_field",
                        format!("top-level field '{key}' is outside the bounded Compose schema"),
                        Some(path.to_owned()),
                        format!("$.{key}"),
                    ));
                }
            }
        }

        validate_document(&document, Some(path))?;
        Ok(document)
    }
}

impl FromStr for ComposeDocument {
    type Err = ComposeError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse_yaml(source, "compose.yaml")
    }
}

fn parse_services(
    value: &Value,
    source: &str,
    validation: ComposeValidationMode,
) -> Result<BTreeMap<String, ComposeService>, ComposeError> {
    let services_value = mapping(value, source, "$.services")?;
    reject_duplicate_keys(services_value, source, "$.services")?;
    let mut services = BTreeMap::new();
    for (name, service_value) in services_value {
        let name = scalar_key(name, source, "$.services")?;
        validate_service_name(&name, source, &format!("$.services.{name}"))?;
        let service = parse_service(service_value, source, validation, &name)?;
        if services.insert(name.clone(), service).is_some() {
            return Err(ComposeError::new(
                "compose_duplicate_service",
                "service names must be unique",
                Some(source.to_owned()),
                format!("$.services.{name}"),
            ));
        }
    }
    Ok(services)
}

fn parse_service(
    value: &Value,
    source: &str,
    validation: ComposeValidationMode,
    service_name: &str,
) -> Result<ComposeService, ComposeError> {
    let service_path = format!("$.services.{service_name}");
    let service = mapping(value, source, &service_path)?;
    reject_duplicate_keys(service, source, &service_path)?;
    let mut image = None;
    let mut environment = Environment::new();

    for (key, value) in service {
        let key = scalar_key(key, source, &service_path)?;
        match key.as_str() {
            "image" => {
                let text = scalar(value, source, &format!("{service_path}.image"))?;
                image = Some(ImageReference::new(text).map_err(|_| {
                    ComposeError::new(
                        "compose_invalid_image",
                        "image must be a non-empty reference without whitespace",
                        Some(source.to_owned()),
                        format!("{service_path}.image"),
                    )
                })?);
            }
            "environment" => {
                environment = parse_environment(value, source, &service_path)?;
            }
            _ if key.starts_with("x-") => {}
            _ if validation == ComposeValidationMode::Loose => {}
            _ => {
                return Err(ComposeError::new(
                    "compose_unsupported_field",
                    format!("service field '{key}' is not part of the bounded Compose model"),
                    Some(source.to_owned()),
                    format!("{service_path}.{key}"),
                ));
            }
        }
    }

    let image = image.ok_or_else(|| {
        ComposeError::new(
            "compose_service_requires_image",
            "the bounded Compose model requires an image for every service",
            Some(source.to_owned()),
            service_path,
        )
    })?;
    Ok(ComposeService { image, environment })
}

fn parse_environment(
    value: &Value,
    source: &str,
    service_path: &str,
) -> Result<Environment, ComposeError> {
    let environment_path = format!("{service_path}.environment");
    match value {
        Value::Mapping(mapping) => {
            reject_duplicate_keys(mapping, source, &environment_path)?;
            let mut environment = Environment::new();
            for (key, value) in mapping {
                let key = scalar_key(key, source, &environment_path)?;
                validate_environment_key(&key, source, &format!("{environment_path}.{key}"))?;
                let value =
                    environment_scalar(value, source, &format!("{environment_path}.{key}"))?;
                if environment.insert(key, value).is_some() {
                    return Err(ComposeError::new(
                        "compose_duplicate_environment",
                        "environment names must be unique",
                        Some(source.to_owned()),
                        environment_path.clone(),
                    ));
                }
            }
            Ok(environment)
        }
        Value::Sequence(sequence) => {
            let mut environment = Environment::new();
            for (index, value) in sequence.iter().enumerate() {
                let item_path = format!("{environment_path}[{index}]");
                let text = scalar(value, source, &item_path)?;
                let (key, value) = if let Some((key, value)) = text.split_once('=') {
                    (key, Some(value.to_owned()))
                } else {
                    (text.as_str(), None)
                };
                validate_environment_key(key, source, &item_path)?;
                if environment.insert(key.to_owned(), value).is_some() {
                    return Err(ComposeError::new(
                        "compose_duplicate_environment",
                        "environment names must be unique",
                        Some(source.to_owned()),
                        environment_path.clone(),
                    ));
                }
            }
            Ok(environment)
        }
        _ => Err(ComposeError::new(
            "compose_invalid_environment",
            "environment must be a mapping or a sequence",
            Some(source.to_owned()),
            environment_path,
        )),
    }
}

fn parse_includes(value: &Value, source: &str) -> Result<Vec<ComposeInclude>, ComposeError> {
    let sequence = sequence(value, source, "$.include")?;
    let mut includes = Vec::new();
    for (index, value) in sequence.iter().enumerate() {
        let include_path = format!("$.include[{index}]");
        let path = match value {
            Value::String(path) => path.clone(),
            Value::Mapping(mapping) => {
                reject_duplicate_keys(mapping, source, &include_path)?;
                let Some(path) = mapping.get(Value::String("path".to_owned())) else {
                    return Err(ComposeError::new(
                        "compose_invalid_include",
                        "include mapping requires a path",
                        Some(source.to_owned()),
                        include_path,
                    ));
                };
                scalar(path, source, &format!("{include_path}.path"))?
            }
            _ => {
                return Err(ComposeError::new(
                    "compose_invalid_include",
                    "include entries must be paths or mappings with a path",
                    Some(source.to_owned()),
                    include_path,
                ));
            }
        };
        if path.trim().is_empty() {
            return Err(ComposeError::new(
                "compose_invalid_include",
                "include path must not be empty",
                Some(source.to_owned()),
                include_path,
            ));
        }
        includes.push(ComposeInclude::new(path));
    }
    Ok(includes)
}

fn validate_document(document: &ComposeDocument, source: Option<&str>) -> Result<(), ComposeError> {
    if let Some(name) = &document.name
        && !is_valid_project_name(name)
        && !has_interpolation_syntax(name)
    {
        return Err(ComposeError::new(
            "compose_invalid_project_name",
            "project name must use lowercase letters, digits, hyphens, or underscores",
            source.map(str::to_owned),
            "$.name",
        ));
    }
    for (name, service) in &document.services {
        validate_service_name(
            name,
            source.unwrap_or("normalized"),
            &format!("$.services.{name}"),
        )?;
        for key in service.environment.keys() {
            validate_environment_key(
                key,
                source.unwrap_or("normalized"),
                &format!("$.services.{name}.environment.{key}"),
            )?;
        }
    }
    for include in &document.include {
        if include.path.trim().is_empty() {
            return Err(ComposeError::new(
                "compose_invalid_include",
                "include path must not be empty",
                source.map(str::to_owned),
                "$.include",
            ));
        }
    }
    Ok(())
}

fn validate_service_name(value: &str, source: &str, path: &str) -> Result<(), ComposeError> {
    if is_service_name(value) {
        return Ok(());
    }
    Err(ComposeError::new(
        "compose_invalid_service_name",
        "service name must contain only letters, digits, '.', '_' or '-'",
        Some(source.to_owned()),
        path.to_owned(),
    ))
}

fn validate_environment_key(value: &str, source: &str, path: &str) -> Result<(), ComposeError> {
    if is_environment_key(value) || (value.contains('$') && !value.contains(char::is_whitespace)) {
        return Ok(());
    }
    Err(ComposeError::new(
        "compose_invalid_environment_name",
        "environment name must start with a letter or underscore and contain only letters, digits, or '_'",
        Some(source.to_owned()),
        path.to_owned(),
    ))
}

pub(crate) fn is_valid_project_name(value: &str) -> bool {
    is_project_name(value)
}

fn is_project_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        })
}

fn is_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

fn is_environment_key(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(crate) fn is_valid_environment_key(value: &str) -> bool {
    is_environment_key(value)
}

pub(crate) fn has_interpolation_syntax(value: &str) -> bool {
    let characters: Vec<char> = value.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '$' {
            index += 1;
            continue;
        }
        let Some(next) = characters.get(index + 1).copied() else {
            break;
        };
        if matches!(next, '$' | '{' | '(') {
            return true;
        }
        if next.is_ascii_alphabetic() || next == '_' {
            return true;
        }
        index += 1;
    }
    false
}

fn optional_scalar(value: &Value, source: &str, path: &str) -> Result<String, ComposeError> {
    scalar(value, source, path)
}

fn environment_scalar(
    value: &Value,
    source: &str,
    path: &str,
) -> Result<Option<String>, ComposeError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        Value::Number(value) => Ok(Some(value.to_string())),
        Value::Bool(value) => Ok(Some(value.to_string())),
        _ => Err(ComposeError::new(
            "compose_invalid_environment",
            "environment values must be scalars or null",
            Some(source.to_owned()),
            path.to_owned(),
        )),
    }
}

fn scalar(value: &Value, source: &str, path: &str) -> Result<String, ComposeError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(ComposeError::new(
            "compose_invalid_scalar",
            "expected a scalar value",
            Some(source.to_owned()),
            path.to_owned(),
        )),
    }
}

fn scalar_key(value: &Value, source: &str, path: &str) -> Result<String, ComposeError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        _ => Err(ComposeError::new(
            "compose_invalid_key",
            "mapping keys must be strings",
            Some(source.to_owned()),
            path.to_owned(),
        )),
    }
}

fn mapping<'a>(value: &'a Value, source: &str, path: &str) -> Result<&'a Mapping, ComposeError> {
    match value {
        Value::Mapping(mapping) => Ok(mapping),
        _ => Err(ComposeError::new(
            "compose_expected_mapping",
            "expected a mapping",
            Some(source.to_owned()),
            path.to_owned(),
        )),
    }
}

fn sequence<'a>(
    value: &'a Value,
    source: &str,
    path: &str,
) -> Result<&'a Vec<Value>, ComposeError> {
    match value {
        Value::Sequence(sequence) => Ok(sequence),
        _ => Err(ComposeError::new(
            "compose_expected_sequence",
            "expected a sequence",
            Some(source.to_owned()),
            path.to_owned(),
        )),
    }
}

fn reject_duplicate_keys(mapping: &Mapping, source: &str, path: &str) -> Result<(), ComposeError> {
    let mut keys = BTreeSet::new();
    for key in mapping.keys() {
        let key = scalar_key(key, source, path)?;
        if !keys.insert(key.clone()) {
            return Err(ComposeError::new(
                "compose_duplicate_key",
                format!("duplicate mapping key '{key}'"),
                Some(source.to_owned()),
                path.to_owned(),
            ));
        }
    }
    Ok(())
}
