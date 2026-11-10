use crate::model::{Entry, Group, KeePassDatabase};

/// Options for root-relative path queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathOptions {
    /// Segment delimiter.
    pub delimiter: char,
    /// Segment comparison mode.
    pub comparison: Comparison,
}

impl Default for PathOptions {
    fn default() -> Self {
        Self {
            delimiter: '/',
            comparison: Comparison::CaseInsensitive,
        }
    }
}

/// Path comparison mode without exposing platform-specific string comparison APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    /// Compare Unicode scalar values.
    Ordinal,
    /// Compare ASCII case-insensitively.
    CaseInsensitive,
}

impl Comparison {
    fn equal(self, left: &str, right: &str) -> bool {
        match self {
            Self::Ordinal => left == right,
            Self::CaseInsensitive => left.eq_ignore_ascii_case(right),
        }
    }
}

/// A path query error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// A path contained an empty segment.
    EmptySegment,
    /// A tree name was empty or contained the delimiter.
    InvalidName,
    /// An entry path did not include a title.
    MissingEntry,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptySegment => "path cannot contain an empty segment",
            Self::InvalidName => "tree name cannot be empty or contain the delimiter",
            Self::MissingEntry => "entry path must include an entry title",
        })
    }
}

impl std::error::Error for PathError {}

fn parse(path: &str, options: PathOptions) -> Result<Vec<&str>, PathError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let segments: Vec<_> = path.split(options.delimiter).collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(PathError::EmptySegment);
    }
    Ok(segments)
}

fn validate_name(name: &str, options: PathOptions) -> Result<(), PathError> {
    if name.is_empty() || name.contains(options.delimiter) {
        return Err(PathError::InvalidName);
    }
    Ok(())
}

fn child_group<'a>(
    parent: &'a Group,
    name: &str,
    options: PathOptions,
) -> Result<Option<&'a Group>, PathError> {
    for child in &parent.groups {
        validate_name(&child.name, options)?;
        if options.comparison.equal(&child.name, name) {
            return Ok(Some(child));
        }
    }
    Ok(None)
}

impl KeePassDatabase {
    /// Finds a group relative to the root. An empty path returns the root.
    ///
    /// # Errors
    ///
    /// Returns a path error for empty segments or ambiguous tree names.
    pub fn find_group_by_path(
        &self,
        path: &str,
        options: PathOptions,
    ) -> Result<Option<&Group>, PathError> {
        let segments = parse(path, options)?;
        let mut group = &self.root;
        let start =
            usize::from(!segments.is_empty() && options.comparison.equal(segments[0], &group.name));
        for segment in &segments[start..] {
            group = match child_group(group, segment, options)? {
                Some(child) => child,
                None => return Ok(None),
            };
        }
        Ok(Some(group))
    }

    /// Finds an entry by title and parent-group path.
    ///
    /// # Errors
    ///
    /// Returns a path error for empty segments, ambiguous names, or an empty
    /// entry path.
    pub fn find_entry_by_path(
        &self,
        path: &str,
        options: PathOptions,
    ) -> Result<Option<&Entry>, PathError> {
        let segments = parse(path, options)?;
        if segments.is_empty() {
            return Err(PathError::MissingEntry);
        }
        let mut group = &self.root;
        let start = usize::from(options.comparison.equal(segments[0], &group.name));
        if start == segments.len() {
            return Err(PathError::MissingEntry);
        }
        for segment in &segments[start..segments.len() - 1] {
            group = match child_group(group, segment, options)? {
                Some(child) => child,
                None => return Ok(None),
            };
        }
        let title = segments[segments.len() - 1];
        for entry in &group.entries {
            validate_name(&entry.title, options)?;
            if options.comparison.equal(&entry.title, title) {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    /// Returns entries in a group and all descendants in pre-order.
    ///
    /// # Errors
    ///
    /// Returns a path error when the prefix or a traversed name is invalid.
    pub fn entries_by_path_prefix(
        &self,
        path: &str,
        options: PathOptions,
    ) -> Result<Vec<&Entry>, PathError> {
        let Some(group) = self.find_group_by_path(path, options)? else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        fn visit<'a>(
            group: &'a Group,
            entries: &mut Vec<&'a Entry>,
            options: PathOptions,
        ) -> Result<(), PathError> {
            for entry in &group.entries {
                validate_name(&entry.title, options)?;
                entries.push(entry);
            }
            for child in &group.groups {
                visit(child, entries, options)?;
            }
            Ok(())
        }
        visit(group, &mut entries, options)?;
        Ok(entries)
    }
}
