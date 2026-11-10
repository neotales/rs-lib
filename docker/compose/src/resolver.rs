use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ComposeError;
use crate::model::{
    ComposeDocument, ComposeInclude, ImageReference, has_interpolation_syntax,
    is_valid_environment_key, is_valid_project_name,
};
use crate::policy::{
    ComposePolicy, IncludePolicy, InterpolationMode, InterpolationPolicy, InterpolationValues,
    MergePolicy, MissingVariablePolicy,
};

const MAX_EXPANSION_DEPTH: usize = 32;

/// A fully expanded, daemon-free Compose document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolvedComposeDocument {
    /// Optional project name from the merged source documents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional legacy format version from the merged source documents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Resolved services in deterministic name order.
    #[serde(default)]
    pub services: BTreeMap<String, ResolvedComposeService>,
}

/// A fully expanded image-based Compose service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolvedComposeService {
    /// Expanded image reference.
    pub image: ImageReference,
    /// Expanded environment values in deterministic name order.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

impl ResolvedComposeDocument {
    /// Returns a resolved service by name.
    #[must_use]
    pub fn service(&self, name: &str) -> Option<&ResolvedComposeService> {
        self.services.get(name)
    }

    /// Serializes the resolved document as deterministic pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be represented by `serde_json`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serializes the resolved document as YAML.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be represented by `serde_yaml`.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

/// Daemon-free Compose normalization and interpolation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComposeResolver;

impl ComposeResolver {
    /// Resolves one or more normalized documents using only explicit values.
    ///
    /// `include` is rejected under the default policy.  Use
    /// [`Self::resolve_with_includes`] when the caller has already loaded
    /// include documents and has selected [`IncludePolicy::CallerSupplied`].
    ///
    /// # Errors
    ///
    /// Returns an error for an empty input, a policy rejection, malformed
    /// interpolation, an unresolved required value, or an invalid normalized
    /// model.
    pub fn resolve(
        documents: &[ComposeDocument],
        values: &InterpolationValues,
        policy: ComposePolicy,
    ) -> Result<ResolvedComposeDocument, ComposeError> {
        Self::resolve_with_includes(documents, values, policy, &BTreeMap::new())
    }

    /// Resolves documents and caller-supplied include documents.
    ///
    /// The include map is an explicit authority boundary.  This method never
    /// opens a path, reads a `.env` file, or consults process state.  Include
    /// paths must match the map keys exactly after scalar interpolation.
    ///
    /// # Errors
    ///
    /// Returns an error when policy rejects a merge/include, an include is
    /// missing or cyclic, or scalar/model validation fails.
    pub fn resolve_with_includes(
        documents: &[ComposeDocument],
        values: &InterpolationValues,
        policy: ComposePolicy,
        included_documents: &BTreeMap<String, ComposeDocument>,
    ) -> Result<ResolvedComposeDocument, ComposeError> {
        if documents.is_empty() {
            return Err(ComposeError::new(
                "compose_empty_input",
                "at least one Compose document is required",
                None,
                "$",
            ));
        }

        let mut merged = None;
        let mut ancestors = Vec::new();
        for document in documents {
            let expanded =
                resolve_document(document, values, policy, included_documents, &mut ancestors)?;
            merged = Some(merge_documents(merged, expanded, policy.merge)?);
        }
        let document = merged.ok_or_else(|| {
            ComposeError::new(
                "compose_empty_input",
                "at least one Compose document is required",
                None,
                "$",
            )
        })?;

        resolve_model(document, values, policy)
    }
}

/// Expands one scalar using the explicit interpolation policy.
///
/// This function implements only Compose-style `$NAME`, `${NAME}`, and `$$`
/// escapes plus the `:-`, `-`, `:?`, `?`, `:+`, and `+` operators.  It rejects
/// Go-template markers and never evaluates command substitutions.
///
/// # Errors
///
/// Returns an error when interpolation is disabled, a token is malformed,
/// command substitution is present, a required value is absent, or expansion
/// exceeds the bounded nesting depth.
pub fn interpolate(
    value: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
) -> Result<String, ComposeError> {
    let path = "$";
    if value.contains("{{") || value.contains("}}") {
        return Err(ComposeError::new(
            "compose_template_rejected",
            "Go-template syntax must be rendered before Compose interpolation",
            None,
            path,
        ));
    }
    if policy.mode == InterpolationMode::Disabled {
        if has_interpolation_syntax(value) {
            return Err(ComposeError::new(
                "compose_interpolation_disabled",
                "interpolation syntax is not allowed by the selected policy",
                None,
                path,
            ));
        }
        return Ok(value.to_owned());
    }
    expand_explicit(value, values, policy, path, 0)
}

fn resolve_document(
    document: &ComposeDocument,
    values: &InterpolationValues,
    policy: ComposePolicy,
    included_documents: &BTreeMap<String, ComposeDocument>,
    ancestors: &mut Vec<String>,
) -> Result<ComposeDocument, ComposeError> {
    document.validate()?;

    if !document.include.is_empty() && policy.include == IncludePolicy::Reject {
        return Err(ComposeError::new(
            "compose_include_rejected",
            "include entries require the caller-supplied include policy",
            None,
            "$.include",
        ));
    }

    let mut merged = None;
    for include in &document.include {
        let include_path = include_path(include, values, policy)?;
        if ancestors.iter().any(|ancestor| ancestor == &include_path) {
            return Err(ComposeError::new(
                "compose_include_cycle",
                format!("include cycle detected at '{include_path}'"),
                None,
                "$.include",
            ));
        }
        let Some(included) = included_documents.get(&include_path) else {
            return Err(ComposeError::new(
                "compose_include_missing",
                format!("caller did not supply include '{include_path}'"),
                None,
                "$.include",
            ));
        };
        ancestors.push(include_path);
        let expanded = resolve_document(included, values, policy, included_documents, ancestors);
        ancestors.pop();
        merged = Some(merge_documents(merged, expanded?, policy.merge)?);
    }

    let mut own = document.clone();
    own.include.clear();
    merged = Some(merge_documents(merged, own, policy.merge)?);
    Ok(merged.unwrap_or_else(|| ComposeDocument {
        name: None,
        version: None,
        services: BTreeMap::new(),
        include: Vec::new(),
    }))
}

fn include_path(
    include: &ComposeInclude,
    values: &InterpolationValues,
    policy: ComposePolicy,
) -> Result<String, ComposeError> {
    let path = interpolate(include.path.as_str(), values, policy.interpolation).map_err(|_| {
        ComposeError::new(
            "compose_invalid_include",
            "include path contains invalid interpolation",
            None,
            "$.include",
        )
    })?;
    if path.trim().is_empty() {
        return Err(ComposeError::new(
            "compose_invalid_include",
            "include path must not be empty",
            None,
            "$.include",
        ));
    }
    Ok(path)
}

fn merge_documents(
    left: Option<ComposeDocument>,
    right: ComposeDocument,
    policy: MergePolicy,
) -> Result<ComposeDocument, ComposeError> {
    let Some(mut left) = left else {
        return Ok(right);
    };
    if policy == MergePolicy::Reject {
        return Err(ComposeError::new(
            "compose_merge_rejected",
            "multiple Compose documents require an explicit merge policy",
            None,
            "$",
        ));
    }

    if right.name.is_some() {
        left.name = right.name;
    }
    if right.version.is_some() {
        left.version = right.version;
    }
    for (name, service) in right.services {
        if policy == MergePolicy::MergeServices {
            if let Some(previous) = left.services.get_mut(&name) {
                previous.environment.extend(service.environment);
                previous.image = service.image;
            } else {
                left.services.insert(name, service);
            }
        } else {
            left.services.insert(name, service);
        }
    }
    Ok(left)
}

fn resolve_model(
    document: ComposeDocument,
    values: &InterpolationValues,
    policy: ComposePolicy,
) -> Result<ResolvedComposeDocument, ComposeError> {
    let name = document
        .name
        .as_deref()
        .map(|value| interpolate(value, values, policy.interpolation))
        .transpose()
        .map_err(|error| rebase_error(&error, "$.name"))?;
    if name
        .as_deref()
        .is_some_and(|value| !is_valid_project_name(value))
    {
        return Err(ComposeError::new(
            "compose_invalid_project_name",
            "expanded project name is invalid",
            None,
            "$.name",
        ));
    }
    let version = document
        .version
        .as_deref()
        .map(|value| interpolate(value, values, policy.interpolation))
        .transpose()
        .map_err(|error| rebase_error(&error, "$.version"))?;

    let mut services = BTreeMap::new();
    for (service_name, service) in document.services {
        let service_path = format!("$.services.{service_name}");
        let image_text = interpolate(service.image.as_str(), values, policy.interpolation)
            .map_err(|error| rebase_error(&error, &format!("{service_path}.image")))?;
        let image = ImageReference::new(image_text).map_err(|_| {
            ComposeError::new(
                "compose_invalid_image",
                "expanded image must be a non-empty reference without whitespace",
                None,
                format!("{service_path}.image"),
            )
        })?;

        let mut environment = BTreeMap::new();
        for (key, value) in service.environment {
            let resolved_key =
                interpolate(key.as_str(), values, policy.interpolation).map_err(|error| {
                    rebase_error(&error, &format!("{service_path}.environment.{key}"))
                })?;
            if !is_valid_environment_key(&resolved_key) {
                return Err(ComposeError::new(
                    "compose_invalid_environment_name",
                    "expanded environment name is not a valid environment variable",
                    None,
                    format!("{service_path}.environment.{key}"),
                ));
            }
            let resolved_value = match value {
                Some(value) => {
                    interpolate(value.as_str(), values, policy.interpolation).map_err(|error| {
                        rebase_error(&error, &format!("{service_path}.environment.{key}"))
                    })?
                }
                None if policy.interpolation.mode == InterpolationMode::Disabled => {
                    return Err(ComposeError::new(
                        "compose_interpolation_disabled",
                        "pass-through environment values require explicit interpolation",
                        None,
                        format!("{service_path}.environment.{key}"),
                    ));
                }
                None => match values.get(&resolved_key) {
                    Some(value) => value.to_owned(),
                    None if policy.interpolation.missing == MissingVariablePolicy::Error => {
                        return Err(ComposeError::new(
                            "compose_missing_interpolation",
                            format!(
                                "required environment variable '{resolved_key}' is not injected"
                            ),
                            None,
                            format!("{service_path}.environment.{key}"),
                        ));
                    }
                    None => String::new(),
                },
            };
            if environment
                .insert(resolved_key.clone(), resolved_value)
                .is_some()
            {
                return Err(ComposeError::new(
                    "compose_duplicate_environment",
                    "interpolation produced duplicate environment names",
                    None,
                    format!("{service_path}.environment"),
                ));
            }
        }
        services.insert(service_name, ResolvedComposeService { image, environment });
    }

    Ok(ResolvedComposeDocument {
        name,
        version,
        services,
    })
}

fn rebase_error(error: &ComposeError, path: &str) -> ComposeError {
    ComposeError::new(
        error.code(),
        error.message(),
        error.source().map(str::to_owned),
        path,
    )
}

fn expand_explicit(
    value: &str,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
    path: &str,
    depth: usize,
) -> Result<String, ComposeError> {
    if depth > MAX_EXPANSION_DEPTH {
        return Err(ComposeError::new(
            "compose_interpolation_depth",
            "interpolation fallback nesting is too deep",
            None,
            path,
        ));
    }

    let characters: Vec<char> = value.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '$' {
            output.push(characters[index]);
            index += 1;
            continue;
        }

        let Some(next) = characters.get(index + 1).copied() else {
            output.push('$');
            break;
        };
        if next == '$' {
            output.push('$');
            index += 2;
            continue;
        }
        if next == '(' {
            return Err(ComposeError::new(
                "compose_command_substitution_rejected",
                "command substitution is not supported",
                None,
                path,
            ));
        }
        if next == '{' {
            let Some(relative_end) = characters[index + 2..]
                .iter()
                .position(|character| *character == '}')
            else {
                return Err(ComposeError::new(
                    "compose_invalid_interpolation",
                    "interpolation expression is missing a closing brace",
                    None,
                    path,
                ));
            };
            let end = index + 2 + relative_end;
            let expression: String = characters[index + 2..end].iter().collect();
            let (name, operator, fallback) = parse_expression(&expression).map_err(|message| {
                ComposeError::new("compose_invalid_interpolation", message, None, path)
            })?;
            let replacement = resolve_expression(
                &name,
                &operator,
                fallback.as_deref(),
                values,
                policy,
                path,
                depth,
            )?;
            output.push_str(&replacement);
            index = end + 1;
            continue;
        }

        if next.is_ascii_alphabetic() || next == '_' {
            let start = index + 1;
            let mut end = start;
            while end < characters.len()
                && (characters[end].is_ascii_alphanumeric() || characters[end] == '_')
            {
                end += 1;
            }
            let name: String = characters[start..end].iter().collect();
            let replacement = resolve_expression(&name, "", None, values, policy, path, depth)?;
            output.push_str(&replacement);
            index = end;
        } else {
            output.push('$');
            index += 1;
        }
    }
    Ok(output)
}

fn parse_expression(expression: &str) -> Result<(String, String, Option<String>), String> {
    if expression.is_empty() {
        return Err("interpolation expression must contain a variable name".to_owned());
    }
    let characters: Vec<char> = expression.chars().collect();
    let mut end = 0;
    let first = characters[0];
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err("interpolation variable name is invalid".to_owned());
    }
    while end < characters.len()
        && (characters[end].is_ascii_alphanumeric() || characters[end] == '_')
    {
        end += 1;
    }
    let name: String = characters[..end].iter().collect();
    if end == characters.len() {
        return Ok((name, String::new(), None));
    }

    let operator_start = end;
    let operator = if characters.get(end) == Some(&':')
        && matches!(characters.get(end + 1), Some('-' | '?' | '+'))
    {
        end += 2;
        characters[operator_start..end].iter().collect::<String>()
    } else if matches!(characters.get(end), Some('-' | '?' | '+')) {
        end += 1;
        characters[operator_start..end].iter().collect::<String>()
    } else {
        return Err("interpolation operator is invalid".to_owned());
    };
    let fallback = if end == characters.len() {
        None
    } else {
        Some(characters[end..].iter().collect::<String>())
    };
    Ok((name, operator, fallback))
}

fn resolve_expression(
    name: &str,
    operator: &str,
    fallback: Option<&str>,
    values: &InterpolationValues,
    policy: InterpolationPolicy,
    path: &str,
    depth: usize,
) -> Result<String, ComposeError> {
    let value = values.get(name);
    let is_set = value.is_some();
    let is_nonempty = value.is_some_and(|value| !value.is_empty());
    let use_fallback = || -> Result<String, ComposeError> {
        fallback.map_or_else(
            || Ok(String::new()),
            |value| expand_explicit(value, values, policy, path, depth + 1),
        )
    };

    match operator {
        "" => value.map_or_else(
            || {
                if policy.missing == MissingVariablePolicy::Error {
                    Err(ComposeError::new(
                        "compose_missing_interpolation",
                        format!("required variable '{name}' is not injected"),
                        None,
                        path,
                    ))
                } else {
                    Ok(String::new())
                }
            },
            |value| Ok(value.to_owned()),
        ),
        "-" if !is_set => use_fallback(),
        ":-" if !is_nonempty => use_fallback(),
        "?" if !is_set => Err(ComposeError::new(
            "compose_missing_interpolation",
            format!("required variable '{name}' is not injected"),
            None,
            path,
        )),
        ":?" if !is_nonempty => Err(ComposeError::new(
            "compose_missing_interpolation",
            format!("required variable '{name}' is empty"),
            None,
            path,
        )),
        "+" if is_set => use_fallback(),
        ":+" if is_nonempty => use_fallback(),
        _ => value.map_or_else(|| Ok(String::new()), |value| Ok(value.to_owned())),
    }
}
