//! Inheritance resolution, target selection, and dependency-first planning.

use std::collections::HashMap;

use indexmap::IndexMap;
use neotales_env::Platform;

use crate::{
    BakeError, BakeResult,
    document::{
        BakeDocument, DEFAULT_CONTEXT, DEFAULT_DOCKERFILE, DEFAULT_NAME, Group, ResolvedTarget,
        TargetDefinition, Variable, VariableValues, validate_name,
    },
};

/// A normalized document with every target inheritance chain resolved.
///
/// Normalization validates all declared targets, groups, and named target
/// contexts, even when a later selection uses only a subset. This keeps a
/// document from acquiring different validity depending on which target a
/// caller happens to request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NormalizedDocument {
    /// Declared variables, copied without mutation.
    pub variables: IndexMap<String, Variable>,
    /// Declared groups, copied without mutation.
    pub groups: IndexMap<String, Group>,
    /// Fully resolved targets in declaration order.
    pub targets: IndexMap<String, ResolvedTarget>,
}

impl NormalizedDocument {
    /// Returns a normalized target by name.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&ResolvedTarget> {
        self.targets.get(name)
    }

    /// Returns a declared group by name.
    #[must_use]
    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    /// Returns target names in declaration order.
    pub fn target_names(&self) -> impl Iterator<Item = &str> {
        self.targets.keys().map(String::as_str)
    }

    /// Returns group names in declaration order.
    pub fn group_names(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    /// Selects targets and returns an owned dependency graph.
    ///
    /// Group names take precedence over target names, matching Docker Bake.
    /// An empty selection chooses the `default` group or target when present;
    /// otherwise it chooses all declared targets. Named `target:` contexts are
    /// added to the graph as dependencies, but inheritance bases are not added
    /// because they are merged into their consuming target rather than solved
    /// independently.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown selector, a malformed group reference,
    /// or a dependency cycle. Normalization normally catches the latter before
    /// this method is called.
    pub fn plan(&self, requested: &[&str]) -> BakeResult<TargetGraph> {
        self.plan_names(requested.iter().copied())
    }

    /// Selects targets using any iterator of string-like selectors.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::plan`].
    pub fn plan_names<I, S>(&self, requested: I) -> BakeResult<TargetGraph>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let requested = requested
            .into_iter()
            .map(|selector| selector.as_ref().to_owned())
            .collect();
        self.plan_owned(requested)
    }

    /// Selects targets from an owned selector collection.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::plan`].
    pub fn plan_owned(&self, requested: Vec<String>) -> BakeResult<TargetGraph> {
        let mut selectors = if requested.is_empty() {
            self.default_selectors()
        } else {
            requested
        };
        deduplicate(&mut selectors);

        let mut selected = Vec::new();
        for selector in &selectors {
            self.expand_selector(selector, &mut selected)?;
        }
        deduplicate(&mut selected);

        let mut targets = IndexMap::with_capacity(selected.len());
        let mut edges = IndexMap::with_capacity(selected.len());
        let mut inheritance = IndexMap::with_capacity(selected.len());
        let mut dependency_stack = Vec::new();
        for name in selected {
            self.add_target_closure(
                &name,
                &mut targets,
                &mut edges,
                &mut inheritance,
                &mut dependency_stack,
            )?;
        }

        Ok(TargetGraph {
            requested: selectors,
            targets,
            edges,
            inheritance,
        })
    }

    fn default_selectors(&self) -> Vec<String> {
        if self.groups.contains_key(DEFAULT_NAME) || self.targets.contains_key(DEFAULT_NAME) {
            vec![DEFAULT_NAME.to_owned()]
        } else {
            self.targets.keys().cloned().collect()
        }
    }

    fn expand_selector(&self, selector: &str, selected: &mut Vec<String>) -> BakeResult<()> {
        if !selector.contains(['*', '?', '[']) {
            if self.groups.contains_key(selector) {
                self.expand_group(selector, selected, &mut Vec::new())?;
            } else if self.targets.contains_key(selector) {
                selected.push(selector.to_owned());
            } else {
                return Err(BakeError::UnknownSelection(selector.to_owned()));
            }
            return Ok(());
        }

        let mut matches = Vec::new();
        for name in self.groups.keys() {
            if glob_matches(selector, name) {
                matches.push(name.clone());
            }
        }
        for name in self.targets.keys() {
            if glob_matches(selector, name) {
                matches.push(name.clone());
            }
        }
        matches.dedup();
        if matches.is_empty() {
            return Err(BakeError::UnknownSelection(selector.to_owned()));
        }
        for name in matches {
            if self.groups.contains_key(&name) {
                self.expand_group(&name, selected, &mut Vec::new())?;
            } else {
                selected.push(name);
            }
        }
        Ok(())
    }

    fn expand_group(
        &self,
        name: &str,
        selected: &mut Vec<String>,
        stack: &mut Vec<String>,
    ) -> BakeResult<()> {
        if let Some(position) = stack.iter().position(|item| item == name) {
            let mut trace = stack[position..].to_vec();
            trace.push(name.to_owned());
            return Err(BakeError::GroupCycle { trace });
        }
        let Some(group) = self.groups.get(name) else {
            return Err(BakeError::MissingGroup(name.to_owned()));
        };
        stack.push(name.to_owned());
        for target in &group.targets {
            if self.groups.contains_key(target) {
                self.expand_group(target, selected, stack)?;
            } else if self.targets.contains_key(target) {
                selected.push(target.clone());
            } else {
                return Err(BakeError::MissingTarget(target.clone()));
            }
        }
        stack.pop();
        Ok(())
    }

    fn add_target_closure(
        &self,
        name: &str,
        targets: &mut IndexMap<String, ResolvedTarget>,
        edges: &mut IndexMap<String, Vec<String>>,
        inheritance: &mut IndexMap<String, Vec<String>>,
        stack: &mut Vec<String>,
    ) -> BakeResult<()> {
        if targets.contains_key(name) {
            return Ok(());
        }
        if let Some(position) = stack.iter().position(|item| item == name) {
            let mut trace = stack[position..].to_vec();
            trace.push(name.to_owned());
            return Err(BakeError::DependencyCycle { trace });
        }
        let Some(target) = self.targets.get(name) else {
            return Err(BakeError::MissingTarget(name.to_owned()));
        };

        stack.push(name.to_owned());
        targets.insert(name.to_owned(), target.clone());
        let dependencies = target_dependencies(name, target)?;
        for dependency in &dependencies {
            self.add_target_closure(dependency, targets, edges, inheritance, stack)?;
        }
        stack.pop();
        edges.insert(name.to_owned(), dependencies);
        inheritance.insert(name.to_owned(), target.inherits.clone());
        Ok(())
    }
}

/// A selected, owned Bake target graph.
///
/// `edges` contains execution dependencies from named `target:` contexts.
/// `inheritance` records the direct bases used to produce each node. The graph
/// owns its targets, so it can outlive the parsed document without exposing
/// mutable parser state or builder internals.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetGraph {
    /// Selectors supplied by the caller, or the implicit default selection.
    pub requested: Vec<String>,
    /// Selected target nodes and their normalized configurations.
    pub targets: IndexMap<String, ResolvedTarget>,
    /// Named-context execution edges, in deterministic declaration order.
    pub edges: IndexMap<String, Vec<String>>,
    /// Direct inheritance edges for selected target nodes.
    pub inheritance: IndexMap<String, Vec<String>>,
}

impl TargetGraph {
    /// Returns a selected target by name.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&ResolvedTarget> {
        self.targets.get(name)
    }

    /// Returns the dependency-first execution order.
    #[must_use]
    pub fn execution_order(&self) -> Vec<String> {
        let mut visited = vec![false; self.targets.len()];
        let mut order = Vec::with_capacity(self.targets.len());
        for name in self.targets.keys() {
            self.visit_for_order(name, &mut visited, &mut order);
        }
        order
    }

    /// Returns the target names in graph insertion order.
    pub fn target_names(&self) -> impl Iterator<Item = &str> {
        self.targets.keys().map(String::as_str)
    }

    fn visit_for_order(&self, name: &str, visited: &mut [bool], order: &mut Vec<String>) {
        let Some(index) = self.targets.get_index_of(name) else {
            return;
        };
        if visited[index] {
            return;
        }
        visited[index] = true;
        if let Some(dependencies) = self.edges.get(name) {
            for dependency in dependencies {
                self.visit_for_order(dependency, visited, order);
            }
        }
        order.push(name.to_owned());
    }
}

/// Normalizes all target inheritance and validates all document graphs.
///
/// # Errors
///
/// Returns an inheritance, group, named-context, or variable error.
pub fn normalize(document: &BakeDocument) -> BakeResult<NormalizedDocument> {
    let values = document
        .variables
        .iter()
        .filter_map(|(name, variable)| variable.default.clone().map(|value| (name.clone(), value)))
        .collect::<VariableValues>();
    normalize_with_values(document, &values)
}

/// Normalizes a document with explicit variable values.
///
/// Values supplied by the caller replace declared defaults. Supplying a value
/// for an undeclared variable is rejected so typos do not silently disappear.
///
/// # Errors
///
/// Returns an inheritance, group, named-context, or variable error.
pub fn normalize_with_values(
    document: &BakeDocument,
    values: &VariableValues,
) -> BakeResult<NormalizedDocument> {
    validate_document_names(document)?;
    validate_variable_names(document, values)?;

    let mut effective_values = VariableValues::with_platform(values.platform());
    for (name, variable) in &document.variables {
        if let Some(default) = &variable.default {
            effective_values.insert(name.clone(), default.clone());
        }
    }
    for (name, value) in values.iter() {
        effective_values.insert(name, value);
    }

    let mut resolved = IndexMap::with_capacity(document.targets.len());
    let mut states = HashMap::with_capacity(document.targets.len());
    let mut stack = Vec::new();
    for name in document.targets.keys() {
        resolve_target(name, document, &mut resolved, &mut states, &mut stack)?;
    }

    let mut normalized_targets = IndexMap::with_capacity(resolved.len());
    for (name, definition) in &resolved {
        let direct_inherits = document
            .targets
            .get(name)
            .map(|target| target.inherits.clone())
            .unwrap_or_default();
        normalized_targets.insert(
            name.clone(),
            materialize_target(name, &direct_inherits, definition, &effective_values)?,
        );
    }

    let normalized = NormalizedDocument {
        variables: document.variables.clone(),
        groups: document.groups.clone(),
        targets: normalized_targets,
    };
    validate_groups(&normalized)?;
    validate_context_graph(&normalized)?;
    Ok(normalized)
}

impl BakeDocument {
    /// Resolves inheritance and validates groups and named target contexts.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`normalize`].
    pub fn normalize(&self) -> BakeResult<NormalizedDocument> {
        normalize(self)
    }

    /// Normalizes and plans this document without a separate parse step.
    ///
    /// # Errors
    ///
    /// Returns normalization or selection errors.
    pub fn plan(&self, requested: &[&str]) -> BakeResult<TargetGraph> {
        self.normalize()?.plan(requested)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResolveState {
    Visiting,
    Resolved,
}

fn resolve_target(
    name: &str,
    document: &BakeDocument,
    resolved: &mut IndexMap<String, TargetDefinition>,
    states: &mut HashMap<String, ResolveState>,
    stack: &mut Vec<String>,
) -> BakeResult<TargetDefinition> {
    if let Some(state) = states.get(name) {
        if *state == ResolveState::Resolved {
            return resolved
                .get(name)
                .cloned()
                .ok_or_else(|| BakeError::MissingTarget(name.to_owned()));
        }
        let position = stack
            .iter()
            .position(|item| item == name)
            .unwrap_or_default();
        let mut trace = stack[position..].to_vec();
        trace.push(name.to_owned());
        return Err(BakeError::InheritanceCycle { trace });
    }
    let declaration = document
        .targets
        .get(name)
        .cloned()
        .ok_or_else(|| BakeError::MissingTarget(name.to_owned()))?;

    states.insert(name.to_owned(), ResolveState::Visiting);
    stack.push(name.to_owned());
    let mut merged = TargetDefinition::default();
    for base in &declaration.inherits {
        if !document.targets.contains_key(base) {
            return Err(BakeError::MissingInheritance {
                target: name.to_owned(),
                base: base.clone(),
            });
        }
        let base_definition = match resolved.get(base).cloned() {
            Some(base_definition) => base_definition,
            None => resolve_target(base, document, resolved, states, stack)?,
        };
        merge_definition(&mut merged, &base_definition);
    }
    merge_definition(&mut merged, &declaration);
    stack.pop();
    states.insert(name.to_owned(), ResolveState::Resolved);
    resolved.insert(name.to_owned(), merged.clone());
    Ok(merged)
}

fn merge_definition(base: &mut TargetDefinition, overlay: &TargetDefinition) {
    if let Some(context) = &overlay.context {
        base.context = Some(context.clone());
    }
    if let Some(dockerfile) = &overlay.dockerfile {
        base.dockerfile = Some(dockerfile.clone());
    }
    if let Some(args) = &overlay.args {
        let destination = base.args.get_or_insert_with(IndexMap::new);
        for (name, value) in args {
            destination.insert(name.clone(), value.clone());
        }
    }
    if let Some(labels) = &overlay.labels {
        let destination = base.labels.get_or_insert_with(IndexMap::new);
        for (name, value) in labels {
            destination.insert(name.clone(), value.clone());
        }
    }
    if let Some(contexts) = &overlay.contexts {
        let destination = base.contexts.get_or_insert_with(IndexMap::new);
        for (name, value) in contexts {
            destination.insert(name.clone(), value.clone());
        }
    }
    if let Some(tags) = &overlay.tags {
        base.tags = Some(tags.clone());
    }
    if let Some(platforms) = &overlay.platforms {
        base.platforms = Some(platforms.clone());
    }
    if let Some(target) = &overlay.target {
        base.target = Some(target.clone());
    }
    if let Some(no_cache) = overlay.no_cache {
        base.no_cache = Some(no_cache);
    }
    if let Some(pull) = overlay.pull {
        base.pull = Some(pull);
    }
    if let Some(description) = &overlay.description {
        base.description = Some(description.clone());
    }
}

fn validate_document_names(document: &BakeDocument) -> BakeResult<()> {
    for name in document.variables.keys() {
        validate_name("variable", name)?;
    }
    for name in document.groups.keys() {
        validate_name("group", name)?;
    }
    for name in document.targets.keys() {
        validate_name("target", name)?;
    }
    Ok(())
}

fn validate_variable_names(document: &BakeDocument, values: &VariableValues) -> BakeResult<()> {
    for (name, _) in values.iter() {
        let declared = if values.platform() == Platform::Windows {
            document
                .variables
                .keys()
                .any(|declared| declared.eq_ignore_ascii_case(name))
        } else {
            document.variables.contains_key(name)
        };
        if !declared {
            return Err(BakeError::UnresolvedVariable(name.to_owned()));
        }
    }
    Ok(())
}

fn validate_groups(document: &NormalizedDocument) -> BakeResult<()> {
    let mut states = HashMap::with_capacity(document.groups.len());
    let mut stack = Vec::new();
    for name in document.groups.keys() {
        validate_group(name, document, &mut states, &mut stack)?;
    }
    Ok(())
}

fn validate_group(
    name: &str,
    document: &NormalizedDocument,
    states: &mut HashMap<String, ResolveState>,
    stack: &mut Vec<String>,
) -> BakeResult<()> {
    if let Some(state) = states.get(name) {
        if *state == ResolveState::Resolved {
            return Ok(());
        }
        let position = stack
            .iter()
            .position(|item| item == name)
            .unwrap_or_default();
        let mut trace = stack[position..].to_vec();
        trace.push(name.to_owned());
        return Err(BakeError::GroupCycle { trace });
    }
    let group = document
        .groups
        .get(name)
        .ok_or_else(|| BakeError::MissingGroup(name.to_owned()))?;
    states.insert(name.to_owned(), ResolveState::Visiting);
    stack.push(name.to_owned());
    for target in &group.targets {
        if document.groups.contains_key(target) {
            validate_group(target, document, states, stack)?;
        } else if !document.targets.contains_key(target) {
            return Err(BakeError::MissingTarget(target.clone()));
        }
    }
    stack.pop();
    states.insert(name.to_owned(), ResolveState::Resolved);
    Ok(())
}

fn validate_context_graph(document: &NormalizedDocument) -> BakeResult<()> {
    let mut states = HashMap::with_capacity(document.targets.len());
    let mut stack = Vec::new();
    for name in document.targets.keys() {
        validate_context_target(name, document, &mut states, &mut stack)?;
    }
    Ok(())
}

fn validate_context_target(
    name: &str,
    document: &NormalizedDocument,
    states: &mut HashMap<String, ResolveState>,
    stack: &mut Vec<String>,
) -> BakeResult<()> {
    if let Some(state) = states.get(name) {
        if *state == ResolveState::Resolved {
            return Ok(());
        }
        let position = stack
            .iter()
            .position(|item| item == name)
            .unwrap_or_default();
        let mut trace = stack[position..].to_vec();
        trace.push(name.to_owned());
        return Err(BakeError::DependencyCycle { trace });
    }
    let target = document
        .targets
        .get(name)
        .ok_or_else(|| BakeError::MissingTarget(name.to_owned()))?;
    states.insert(name.to_owned(), ResolveState::Visiting);
    stack.push(name.to_owned());
    for dependency in target_dependencies(name, target)? {
        validate_context_target(&dependency, document, states, stack)?;
    }
    stack.pop();
    states.insert(name.to_owned(), ResolveState::Resolved);
    Ok(())
}

fn target_dependencies(target_name: &str, target: &ResolvedTarget) -> BakeResult<Vec<String>> {
    let mut dependencies = Vec::new();
    for reference in target.contexts.values() {
        let Some(dependency) = reference.strip_prefix("target:") else {
            continue;
        };
        if validate_name("target", dependency).is_err() {
            return Err(BakeError::InvalidTargetReference {
                target: target_name.to_owned(),
                reference: reference.clone(),
            });
        }
        if !dependencies.iter().any(|item| item == dependency) {
            dependencies.push(dependency.to_owned());
        }
    }
    Ok(dependencies)
}

fn materialize_target(
    name: &str,
    direct_inherits: &[String],
    definition: &TargetDefinition,
    values: &VariableValues,
) -> BakeResult<ResolvedTarget> {
    let context = definition
        .context
        .as_deref()
        .filter(|value| !value.is_empty())
        .map_or(Ok(DEFAULT_CONTEXT.to_owned()), |value| {
            expand_string(value, values)
        })?;
    let dockerfile = definition
        .dockerfile
        .as_deref()
        .filter(|value| !value.is_empty())
        .map_or(Ok(DEFAULT_DOCKERFILE.to_owned()), |value| {
            expand_string(value, values)
        })?;
    Ok(ResolvedTarget {
        name: name.to_owned(),
        inherits: direct_inherits.to_vec(),
        context,
        dockerfile,
        args: expand_optional_map(definition.args.clone(), values)?,
        labels: expand_optional_map(definition.labels.clone(), values)?,
        contexts: expand_map(definition.contexts.clone(), values)?,
        tags: expand_list(definition.tags.clone(), values)?,
        platforms: expand_list(definition.platforms.clone(), values)?,
        target: expand_optional(definition.target.clone(), values)?,
        no_cache: definition.no_cache.unwrap_or(false),
        pull: definition.pull.unwrap_or(false),
        description: definition.description.clone(),
    })
}

fn deduplicate(values: &mut Vec<String>) {
    let mut seen = Vec::new();
    values.retain(|value| {
        if seen.iter().any(|item| item == value) {
            false
        } else {
            seen.push(value.clone());
            true
        }
    });
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    fn visit(
        pattern: &[char],
        pattern_index: usize,
        value: &[char],
        value_index: usize,
        memo: &mut [Vec<Option<bool>>],
    ) -> bool {
        if let Some(result) = memo[pattern_index][value_index] {
            return result;
        }
        let result = if pattern_index == pattern.len() {
            value_index == value.len()
        } else {
            match pattern[pattern_index] {
                '*' => {
                    visit(pattern, pattern_index + 1, value, value_index, memo)
                        || (value_index < value.len()
                            && visit(pattern, pattern_index, value, value_index + 1, memo))
                }
                '?' => {
                    value_index < value.len()
                        && visit(pattern, pattern_index + 1, value, value_index + 1, memo)
                }
                '[' => value
                    .get(value_index)
                    .copied()
                    .and_then(|value| character_class(pattern, pattern_index, value))
                    .is_some_and(|(class_length, matches_character)| {
                        matches_character
                            && visit(
                                pattern,
                                pattern_index + class_length,
                                value,
                                value_index + 1,
                                memo,
                            )
                    }),
                character => {
                    value.get(value_index).copied() == Some(character)
                        && visit(pattern, pattern_index + 1, value, value_index + 1, memo)
                }
            }
        };
        memo[pattern_index][value_index] = Some(result);
        result
    }

    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut memo = vec![vec![None; value.len() + 1]; pattern.len() + 1];
    visit(&pattern, 0, &value, 0, &mut memo)
}

fn character_class(pattern: &[char], start: usize, value: char) -> Option<(usize, bool)> {
    if pattern.get(start) != Some(&'[') {
        return None;
    }
    let mut index = start + 1;
    let negated = matches!(pattern.get(index), Some('!' | '^'));
    if negated {
        index += 1;
    }
    let class_start = index;
    while index < pattern.len() && pattern[index] != ']' {
        index += 1;
    }
    if index == class_start || index >= pattern.len() {
        return None;
    }

    let mut matches_character = false;
    let mut item_start = class_start;
    while item_start < index {
        let item_end = if item_start + 2 < index && pattern[item_start + 1] == '-' {
            item_start + 2
        } else {
            item_start
        };
        let first = pattern[item_start];
        let last = pattern[item_end];
        if item_end > item_start + 1 {
            matches_character |= first <= value && value <= last;
        } else {
            matches_character |= first == value;
        }
        item_start = item_end + 1;
    }
    Some((index - start + 1, matches_character != negated))
}

fn expand_string(value: &str, values: &VariableValues) -> BakeResult<String> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            output.push_str(&rest[start..]);
            return Ok(output);
        };
        let name = &after_start[..end];
        if name.is_empty() {
            output.push_str(&rest[start..=(start + 2 + end)]);
        } else if let Some(replacement) = values.get(name) {
            output.push_str(replacement);
        } else {
            return Err(BakeError::UnresolvedVariable(name.to_owned()));
        }
        rest = &after_start[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn expand_optional(value: Option<String>, values: &VariableValues) -> BakeResult<Option<String>> {
    value.map(|value| expand_string(&value, values)).transpose()
}

fn expand_map(
    values: Option<IndexMap<String, String>>,
    variables: &VariableValues,
) -> BakeResult<IndexMap<String, String>> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| expand_string(&value, variables).map(|value| (name, value)))
        .collect()
}

fn expand_optional_map(
    values: Option<IndexMap<String, Option<String>>>,
    variables: &VariableValues,
) -> BakeResult<IndexMap<String, Option<String>>> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| {
            value
                .map_or(Ok(None), |value| expand_string(&value, variables).map(Some))
                .map(|value| (name, value))
        })
        .collect()
}

fn expand_list(values: Option<Vec<String>>, variables: &VariableValues) -> BakeResult<Vec<String>> {
    let values = values.unwrap_or_default();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = expand_string(&value, variables)?;
        if value.is_empty() || normalized.iter().any(|item| item == &value) {
            continue;
        }
        normalized.push(value);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;

    use super::{VariableValues, glob_matches, normalize_with_values};
    use crate::{BakeError, parse_json};

    #[test]
    fn resolves_multiple_bases_from_left_to_right() {
        let document = parse_json(
            r#"{
                "target": {
                    "first": {"args": {"VALUE": "first", "KEEP": "yes"}},
                    "second": {"args": {"VALUE": "second"}},
                    "result": {"inherits": ["first", "second"]}
                }
            }"#,
        )
        .expect("valid document");
        let normalized = document.normalize().expect("normalization");
        let target = &normalized.targets["result"];
        assert_eq!(target.args["VALUE"], Some("second".to_owned()));
        assert_eq!(target.args["KEEP"], Some("yes".to_owned()));
    }

    #[test]
    fn reports_missing_inheritance_bases() {
        let document =
            parse_json(r#"{"target":{"app":{"inherits":["missing"]}}}"#).expect("valid JSON shape");
        assert_eq!(
            document.normalize(),
            Err(BakeError::MissingInheritance {
                target: "app".to_owned(),
                base: "missing".to_owned(),
            })
        );
    }

    #[test]
    fn expands_declared_bake_variables_after_parsing() {
        let document = parse_json(
            r#"{
                "variable": {"TAG": {"default": "latest"}},
                "target": {"app": {"tags": ["example/app:${TAG}"]}}
            }"#,
        )
        .expect("valid document");
        let normalized = document.normalize().expect("normalization");
        assert_eq!(normalized.targets["app"].tags, ["example/app:latest"]);
    }

    #[test]
    fn rejects_unresolved_variables() {
        let document =
            parse_json(r#"{"target":{"app":{"tags":["${MISSING}"]}}}"#).expect("valid JSON shape");
        assert!(matches!(
            document.normalize(),
            Err(BakeError::UnresolvedVariable(name)) if name == "MISSING"
        ));
    }

    #[test]
    fn explicit_variable_values_override_only_the_selected_defaults() {
        let document = parse_json(
            r#"{
                "variable": {
                    "REGISTRY": {"default": "registry.example"},
                    "TAG": {"default": "latest"}
                },
                "target": {"app": {"tags": ["${REGISTRY}/app:${TAG}"]}}
            }"#,
        )
        .expect("valid document");
        let mut values = VariableValues::new();
        values.insert("TAG", "dev");
        let normalized = normalize_with_values(&document, &values).expect("normalization");
        assert_eq!(normalized.targets["app"].tags, ["registry.example/app:dev"]);
    }

    #[test]
    fn rejects_extra_variable_values() {
        let document = parse_json(r#"{"target":{"app":{}}}"#).expect("valid document");
        let mut values = VariableValues::new();
        values.insert("UNKNOWN", "value");
        assert!(matches!(
            normalize_with_values(&document, &values),
            Err(BakeError::UnresolvedVariable(name)) if name == "UNKNOWN"
        ));
    }

    #[test]
    fn expands_null_argument_values_without_dropping_the_key() {
        let document =
            parse_json(r#"{"target":{"app":{"args":{"PRESENT":"value","DEFAULT":null}}}}"#)
                .expect("valid document");
        let normalized = document.normalize().expect("normalization");
        let args = indexmap! {
            "PRESENT".to_owned() => Some("value".to_owned()),
            "DEFAULT".to_owned() => None,
        };
        assert_eq!(normalized.targets["app"].args, args);
    }

    #[test]
    fn glob_matching_handles_stars_question_marks_and_classes() {
        assert!(glob_matches("web-*", "web-api"));
        assert!(glob_matches("web-?", "web-a"));
        assert!(!glob_matches("web-?", "web-api"));
        assert!(glob_matches("web-[ab]", "web-a"));
        assert!(!glob_matches("web-[ab]", "web-c"));
        assert!(glob_matches("web-[!a]", "web-b"));
    }
}
