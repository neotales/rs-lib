//! The semantic version helpers.
//!
//! `semver` parses a version and `semverCompare` tests one against a
//! constraint. Both are ports of the reference's own `Neotales.Versioning`
//! types — `SemanticVersion` for the version and `VersionConstraint` for the
//! range — rather than of the `SemVer` 2.0.0 specification, because the reference
//! is where the behaviour has to match. The two differ in places that matter:
//! a constraint accepts one, two, or three version components where a version
//! needs exactly three, and a range like `1.2` is a wildcard rather than a
//! truncated version.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::support;
use crate::{Context, Error, Value};

/// Dispatches a semantic version helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let _ = context;
    let result = match name {
        "semver" => semver(arguments),
        "semverCompare" => semver_compare(arguments),
        // Reached only through a `Value::Method`, never by name from a
        // template: a template calls `.Compare` on a version object.
        "semver.Compare" => semver_compare_method(arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// False for both. `semver` returns a map, which the caller reads fields from,
/// and a rendered map would be a single string.
///
/// The answer is kept per module because that is where the contract for it
/// lives: a module that later grows a helper which does want its arguments
/// rendered has one place to say so. `lib.rs` currently folds the answer for
/// this module to a constant `false`, so nothing outside the module's own tests
/// calls this; the lint is allowed rather than the function dropped so that the
/// two cannot drift apart.
#[allow(dead_code)]
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// Parses a version and returns its parts as a map.
///
/// This is the reference's `SemVer`, which returns an object with the five
/// members `Major`, `Minor`, `Patch`, `Prerelease`, and `Metadata` and a
/// `Compare` method. `Value` has no method values, so `Compare` is not part of
/// what this returns; the five members are, and the numbers are returned as
/// numbers so `{{ (semver "1.2.3").Major }}` prints `1` rather than a rendered
/// map.
fn semver(arguments: &[Value]) -> Result<Value, Error> {
    crate::arity("semver", arguments.len(), 1, Some(1))?;
    let text = support::text("semver", &arguments[0])?;
    let version = parse_version(&text)
        .ok_or_else(|| crate::invalid("semver", format!("cannot read {text:?} as a version")))?;
    // The reference returns a `TemplateValue.Object`: a display string, the five
    // members, and the `Compare` method. The display is the canonical version,
    // which is what lets a version be piped into another version's method and
    // rendered rather than re-read as a map.
    Ok(Value::Object {
        display: canonical(&version),
        members: BTreeMap::from([
            ("Major".to_owned(), Value::Number(f64::from(version.major))),
            ("Minor".to_owned(), Value::Number(f64::from(version.minor))),
            ("Patch".to_owned(), Value::Number(f64::from(version.patch))),
            (
                "Prerelease".to_owned(),
                Value::String(version.prerelease.clone()),
            ),
            ("Metadata".to_owned(), Value::String(version.build.clone())),
            // The reference returns an *object* here, not a plain map: `Compare` is
            // a method, so `{{ semver "1.2.3" | (semver "1.3.3").Compare }}` reads the
            // member off one version and calls it with the other. A method value
            // carries the version it was reached through, because that is the
            // receiver the comparison is against.
            (
                "Compare".to_owned(),
                Value::Method {
                    helper: "semver.Compare".to_owned(),
                    receiver: Box::new(Value::String(canonical(&version))),
                },
            ),
        ]),
    })
}

/// Renders a version in the canonical `major.minor.patch[-pre][+build]` form.
///
/// The reference keys its object on `SemanticVersion.ToString()`, and the method
/// re-parses that string, so the receiver has to be a version the parser reads
/// back identically. Prerelease and build metadata are appended only when
/// present, because a trailing `-` is not a version the parser accepts.
fn canonical(version: &Version) -> String {
    let mut out = format!("{}.{}.{}", version.major, version.minor, version.patch);
    if !version.prerelease.is_empty() {
        out.push('-');
        out.push_str(&version.prerelease);
    }
    if !version.build.is_empty() {
        out.push('+');
        out.push_str(&version.build);
    }
    out
}

/// Implements the `Compare` method the `semver` object carries.
///
/// The receiver is the version the member was read from and the argument is the
/// version being compared against it, so `{{ semver "1.2.3" | (semver
/// "1.3.3").Compare }}` is one-point-three compared to one-point-two and is `1`.
/// That is the reference's own `CompareTo(ParseVersion(arguments[0]))`.
fn semver_compare_method(arguments: &[Value]) -> Result<Value, Error> {
    crate::arity("semver.Compare", arguments.len(), 2, Some(2))?;
    // The reference renders its argument before parsing it, so a version
    // *object* is a valid argument and not only a string. That is what makes
    // `{{ semver "1.2.3" | (semver "1.3.3").Compare }}` work: the piped value is
    // itself the result of `semver`.
    let left = support::any_text(&arguments[0]);
    let right = support::any_text(&arguments[1]);
    let left = parse_version(&left).ok_or_else(|| {
        crate::invalid(
            "semver.Compare",
            format!("cannot read {left:?} as a version"),
        )
    })?;
    let right = parse_version(&right).ok_or_else(|| {
        crate::invalid(
            "semver.Compare",
            format!("cannot read {right:?} as a version"),
        )
    })?;
    // The reference's `CompareTo` returns -1, 0, or 1, and the fixture for this
    // method expects `1`, so the ordering is mapped rather than rendered.
    let sign = match left.compare(&right) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    Ok(Value::Number(f64::from(sign)))
}

/// Reports whether a version satisfies a constraint.
///
/// This is the reference's `SemVerCompare`, whose first argument is the
/// constraint and whose second is the version — the reverse of what the name
/// suggests, and the order the reference's own `semverCompare` fixtures use.
fn semver_compare(arguments: &[Value]) -> Result<Value, Error> {
    crate::arity("semverCompare", arguments.len(), 2, Some(2))?;
    let range = support::text("semverCompare", &arguments[0])?;
    let text = support::text("semverCompare", &arguments[1])?;
    let constraint = parse_constraint(&range).ok_or_else(|| {
        crate::invalid(
            "semverCompare",
            format!("cannot read {range:?} as a version constraint"),
        )
    })?;
    let version = parse_version(&text).ok_or_else(|| {
        crate::invalid(
            "semverCompare",
            format!("cannot read {text:?} as a version"),
        )
    })?;
    Ok(Value::Bool(constraint.is_satisfied_by(&version)))
}

/// A Semantic Versioning 2.0.0 value.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Version {
    major: i32,
    minor: i32,
    patch: i32,
    /// The prerelease identifiers, or the empty string.
    prerelease: String,
    /// The build metadata, or the empty string.
    build: String,
}

impl Version {
    /// Compares two versions, which is `SemanticVersion.CompareTo`.
    ///
    /// The three numbers come first. A version with a prerelease then sorts
    /// *below* the same version without one, and two prereleases are compared
    /// identifier by identifier.
    fn compare(&self, other: &Self) -> Ordering {
        let numbers = self
            .major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch));
        if numbers != Ordering::Equal || self.prerelease == other.prerelease {
            return numbers;
        }
        if self.prerelease.is_empty() {
            return Ordering::Greater;
        }
        if other.prerelease.is_empty() {
            return Ordering::Less;
        }
        compare_prerelease(&self.prerelease, &other.prerelease)
    }
}

/// Compares two prerelease strings, which is `SemanticVersion.ComparePrerelease`.
///
/// A numeric identifier compares as a number and sorts *below* an alphanumeric
/// one, so `1.0.0-alpha.1` is below `1.0.0-alpha.beta`. A shorter run of
/// identifiers is the lower one, so `alpha` is below `alpha.1`.
fn compare_prerelease(left: &str, right: &str) -> Ordering {
    let left_parts: Vec<&str> = left.split('.').collect();
    let right_parts: Vec<&str> = right.split('.').collect();
    for (left_part, right_part) in left_parts.iter().zip(&right_parts) {
        let comparison = match (number(left_part), number(right_part)) {
            (Some(left_number), Some(right_number)) => left_number.cmp(&right_number),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => left_part.cmp(right_part),
        };
        if comparison != Ordering::Equal {
            return comparison;
        }
    }
    left_parts.len().cmp(&right_parts.len())
}

/// Reads an identifier as a number, rejecting a leading zero.
///
/// This is the reference's `int.TryParse` with `NumberStyles.None`, which
/// accepts a bare run of digits and nothing else.
fn number(value: &str) -> Option<i32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    value.parse::<i32>().ok()
}

/// Parses a strict version, which is `SemanticVersion.TryParse`.
///
/// A version needs exactly three numeric components with no leading zeros. An
/// optional prerelease follows a `-` and optional build metadata follows a `+`;
/// both are dot-separated runs of ASCII alphanumerics and hyphens, and a
/// prerelease identifier that is a number may not have a leading zero while a
/// build identifier may.
fn parse_version(value: &str) -> Option<Version> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    // `TryParse` strips one leading `v`, while the reference's `ParseVersion`
    // strips every one it finds with `TrimStart`. The single strip is the one
    // that matters, because `vv1.2.3` is not a version either way.
    let value = value.strip_prefix(['v', 'V']).unwrap_or(value);

    let (core_and_prerelease, build) = match value.find('+') {
        Some(index) => (&value[..index], Some(value.get(index + 1..)?)),
        None => (value, None),
    };
    if build.is_some_and(|build| build.is_empty() || build.contains('+')) {
        return None;
    }

    let (core, prerelease) = match core_and_prerelease.find('-') {
        Some(index) => (
            &core_and_prerelease[..index],
            Some(core_and_prerelease.get(index + 1..)?),
        ),
        None => (core_and_prerelease, None),
    };
    if prerelease.is_some_and(str::is_empty) {
        return None;
    }

    let fields: Vec<&str> = core.split('.').collect();
    if fields.len() != 3 {
        return None;
    }
    let major = number(fields[0])?;
    let minor = number(fields[1])?;
    let patch = number(fields[2])?;
    if major < 0 || minor < 0 || patch < 0 {
        return None;
    }
    // The reference's constructor validates the two identifier lists and throws
    // when one is malformed, which `TryParse` turns into a parse failure.
    let prerelease_text = prerelease.unwrap_or("");
    let build_text = build.unwrap_or("");
    if !valid_identifiers(prerelease_text, true) || !valid_identifiers(build_text, false) {
        return None;
    }
    Some(Version {
        major,
        minor,
        patch,
        prerelease: prerelease_text.to_owned(),
        build: build_text.to_owned(),
    })
}

/// A version constraint, which is the reference's `VersionConstraint`.
///
/// A constraint is a disjunction of comparator sets: `a || b` holds when either
/// side holds, and within a set every comparator must hold.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Constraint {
    sets: Vec<ComparatorSet>,
}

impl Constraint {
    /// Reports whether a version satisfies any of the sets.
    fn is_satisfied_by(&self, version: &Version) -> bool {
        self.sets.iter().any(|set| set.is_satisfied_by(version))
    }
}

/// One conjunction of comparators, which is the reference's `ComparatorSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ComparatorSet {
    comparators: Vec<Comparator>,
}

impl ComparatorSet {
    /// Reports whether a version satisfies every comparator in the set.
    ///
    /// A prerelease version is rejected outright unless the set names a
    /// prerelease of the same three numbers. That is the `SemVer` rule that stops
    /// `>=1.2.3` from matching `2.0.0-rc.1`, and it is why a range written for
    /// release versions does not accidentally accept a release candidate.
    fn is_satisfied_by(&self, version: &Version) -> bool {
        if !version.prerelease.is_empty()
            && !self.comparators.iter().any(|comparator| {
                !comparator.version.prerelease.is_empty()
                    && comparator.version.major == version.major
                    && comparator.version.minor == version.minor
                    && comparator.version.patch == version.patch
            })
        {
            return false;
        }
        self.comparators
            .iter()
            .all(|comparator| comparator.is_satisfied_by(version))
    }
}

/// The six comparisons a comparator can make.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Comparison {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

/// One comparison, which is the reference's `Comparator`.
///
/// A `wildcard_part` of `-1` is an exact comparator. Otherwise it is the index
/// of the first component the range left open: `1.2.x` is `2`, `1.x` is `1`, and
/// `*` is `0`. A wildcard is not a single comparison but a family of them,
/// which is why the satisfied-by logic below switches on it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Comparator {
    operation: Comparison,
    version: Version,
    wildcard_part: i32,
}

impl Comparator {
    /// Reports whether a version satisfies this comparator.
    fn is_satisfied_by(&self, version: &Version) -> bool {
        if self.wildcard_part >= 0 {
            return self.is_wildcard_satisfied_by(version);
        }
        let comparison = version.compare(&self.version);
        match self.operation {
            Comparison::Equal => comparison.is_eq(),
            Comparison::NotEqual => comparison.is_ne(),
            Comparison::Greater => comparison.is_gt(),
            Comparison::GreaterOrEqual => comparison.is_ge(),
            Comparison::Less => comparison.is_lt(),
            Comparison::LessOrEqual => comparison.is_le(),
        }
    }

    /// The wildcard forms, which is `Comparator.IsWildcardSatisfiedBy`.
    fn is_wildcard_satisfied_by(&self, version: &Version) -> bool {
        if self.wildcard_part == 0 {
            // A bare `*` matches everything, and only the comparisons that ask
            // for a bound are meaningless against it.
            return matches!(
                self.operation,
                Comparison::Equal | Comparison::GreaterOrEqual | Comparison::LessOrEqual
            );
        }
        let comparison = version.compare(&self.version);
        match self.operation {
            Comparison::Equal => self.is_tilde_range(version),
            Comparison::NotEqual => self.is_not_equal_wildcard(version),
            Comparison::Greater => self.is_greater_wildcard(version),
            Comparison::GreaterOrEqual => comparison.is_ge(),
            Comparison::Less => comparison.is_lt(),
            Comparison::LessOrEqual => self.is_less_or_equal_wildcard(version),
        }
    }

    /// `1.2.x` as an equality: at or above `1.2.0` within `1.2`.
    fn is_tilde_range(&self, version: &Version) -> bool {
        if version.compare(&self.version).is_lt() {
            return false;
        }
        if self.version.major == 0
            && self.version.minor == 0
            && self.version.patch == 0
            && self.wildcard_part == 0
        {
            return true;
        }
        version.major == self.version.major
            && (self.wildcard_part == 1 || version.minor == self.version.minor)
    }

    /// `!=1.2.x`: outside `1.2`, and inside it only a different prerelease.
    fn is_not_equal_wildcard(&self, version: &Version) -> bool {
        if self.wildcard_part == 1 {
            return version.major != self.version.major;
        }
        if version.major != self.version.major || version.minor != self.version.minor {
            return true;
        }
        if !version.prerelease.is_empty() || !self.version.prerelease.is_empty() {
            return compare_prerelease(&version.prerelease, &self.version.prerelease).is_ne();
        }
        false
    }

    /// `>1.2.x`: a later minor within the same major.
    fn is_greater_wildcard(&self, version: &Version) -> bool {
        if version.major != self.version.major {
            return version.major > self.version.major;
        }
        if self.wildcard_part == 1 {
            return false;
        }
        if self.wildcard_part == 2 && version.minor == self.version.minor {
            return false;
        }
        if self.wildcard_part == 0 {
            version.compare(&self.version).is_gt()
        } else {
            version.minor > self.version.minor
        }
    }

    /// `<=1.2.x`: this major, and within it this minor or lower.
    fn is_less_or_equal_wildcard(&self, version: &Version) -> bool {
        version.major <= self.version.major
            && (version.major != self.version.major
                || self.wildcard_part == 1
                || version.minor <= self.version.minor)
    }
}

/// Parses a constraint, which is `VersionConstraint.TryParse`.
fn parse_constraint(value: &str) -> Option<Constraint> {
    if value.trim().is_empty() {
        return None;
    }
    let sets = value
        .split("||")
        .map(parse_set)
        .collect::<Option<Vec<_>>>()?;
    Some(Constraint { sets })
}

/// Parses one side of a `||`, which is `VersionConstraint.TryParseSet`.
fn parse_set(value: &str) -> Option<ComparatorSet> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(set) = parse_hyphen_range(value) {
        return Some(set);
    }

    // A comma is a space to the reference, so it separates comparators the same
    // way whitespace does.
    let text = value.replace(',', " ");
    let tokens: Vec<&str> = text.split(' ').filter(|token| !token.is_empty()).collect();
    let mut comparators: Vec<Comparator> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        // A bare operator is its own token, and the version is the next one, so
        // the two are rejoined before being parsed. A comparison with nothing
        // after it is not a range.
        let token = if is_operator(tokens[index]) {
            let version = tokens.get(index + 1)?;
            let operator = tokens[index];
            index += 2;
            format!("{operator}{version}")
        } else {
            let token = tokens[index].to_owned();
            index += 1;
            token
        };
        comparators.extend(parse_comparator(&token)?);
    }

    // A set with no comparators is only meaningful if it was a bare wildcard,
    // which `parse_comparator` turns into a comparator anyway; anything else
    // that parsed to nothing was not a range.
    if comparators.is_empty() && (tokens.len() != 1 || !is_wildcard(tokens[0])) {
        return None;
    }
    Some(ComparatorSet { comparators })
}

/// Parses a `1.2.3 - 2.3.4` range, which is `TryParseHyphenRange`.
///
/// The upper bound's component count decides the bound: one component is
/// exclusive at the next major, two at the next minor, and three is inclusive
/// of the version itself. The separator is ` - ` with single spaces, and
/// exactly one of them, because a range of ranges is not a range.
fn parse_hyphen_range(value: &str) -> Option<ComparatorSet> {
    let separator = value.find(" - ")?;
    if value[separator + 3..].contains(" - ") {
        return None;
    }
    // The lower bound only needs the version; the upper also needs to know how
    // many components it wrote, which is what decides the exclusive bound.
    let lower = parse_partial(&value[..separator])?.version;
    let upper = parse_partial(value.get(separator + 3..)?)?;

    let mut comparators = vec![Comparator {
        operation: Comparison::GreaterOrEqual,
        version: lower,
        wildcard_part: -1,
    }];
    let (operation, version) = match upper.parts {
        1 => (Comparison::Less, increment_major(&upper.version)?),
        2 => (Comparison::Less, increment_minor(&upper.version)?),
        _ => (Comparison::LessOrEqual, upper.version),
    };
    comparators.push(Comparator {
        operation,
        version,
        wildcard_part: -1,
    });
    Some(ComparatorSet { comparators })
}

/// Parses one comparator, which is `VersionConstraint.TryParseComparator`.
///
/// The operators are tested longest-first so `>=` is not read as `>` followed
/// by a version starting with `=`. A leading `^` or `~` expands into a pair of
/// comparators.
fn parse_comparator(token: &str) -> Option<Vec<Comparator>> {
    let (operation, rest) = if let Some(rest) = token.strip_prefix("!=") {
        (Comparison::NotEqual, rest)
    } else if let Some(rest) = token.strip_prefix(">=") {
        (Comparison::GreaterOrEqual, rest)
    } else if let Some(rest) = token.strip_prefix("<=") {
        (Comparison::LessOrEqual, rest)
    } else if let Some(rest) = token.strip_prefix('>') {
        (Comparison::Greater, rest)
    } else if let Some(rest) = token.strip_prefix('<') {
        (Comparison::Less, rest)
    } else if let Some(rest) = token.strip_prefix('=') {
        (Comparison::Equal, rest)
    } else {
        (Comparison::Equal, token)
    };

    if let Some(rest) = rest.strip_prefix('^') {
        return parse_caret(rest);
    }
    if let Some(rest) = rest.strip_prefix('~') {
        return parse_tilde(rest);
    }

    let partial = parse_partial(rest)?;
    Some(vec![Comparator {
        operation,
        version: partial.version,
        wildcard_part: partial.wildcard_part,
    }])
}

/// Expands a caret range, which is `VersionConstraint.TryParseCaret`.
///
/// `^1.2.3` allows `1.x`; `^0.2.3` allows only `0.2.x`; `^0.0.3` only `0.0.3`
/// itself, because a leading zero pins every component. How many components the
/// range wrote also matters: `^0` allows `0.x` and `^0.0` allows `0.0.x`.
fn parse_caret(value: &str) -> Option<Vec<Comparator>> {
    let partial = parse_partial(value)?;
    if partial.wildcard_part == 0 {
        return Some(vec![Comparator {
            operation: Comparison::GreaterOrEqual,
            version: partial.version,
            wildcard_part: partial.wildcard_part,
        }]);
    }
    // A leading zero pins every component before it, and how many components
    // the range wrote decides the rest: `^0` allows `0.x` because it wrote only
    // the major, and `^0.0` allows `0.0.x` for the same reason one level down.
    let pinned_by_major = partial.version.major > 0 || partial.parts == 1;
    let pinned_by_minor = partial.version.minor > 0 || partial.parts == 2;
    let maximum = if pinned_by_major {
        increment_major(&partial.version)?
    } else if pinned_by_minor {
        increment_minor(&partial.version)?
    } else {
        increment_patch(&partial.version)?
    };
    Some(vec![
        Comparator {
            operation: Comparison::GreaterOrEqual,
            version: partial.version,
            wildcard_part: -1,
        },
        Comparator {
            operation: Comparison::Less,
            version: maximum,
            wildcard_part: -1,
        },
    ])
}

/// Expands a tilde range, which is `VersionConstraint.TryParseTilde`.
///
/// `~1.2.3` allows `1.2.x`; a tilde always allows a change to the minor unless
/// the range named only the major, in which case it allows `1.x`.
fn parse_tilde(value: &str) -> Option<Vec<Comparator>> {
    let partial = parse_partial(value)?;
    if partial.wildcard_part == 0 {
        return Some(vec![Comparator {
            operation: Comparison::GreaterOrEqual,
            version: partial.version,
            wildcard_part: partial.wildcard_part,
        }]);
    }
    let maximum = if partial.parts == 1 {
        increment_major(&partial.version)?
    } else {
        increment_minor(&partial.version)?
    };
    Some(vec![
        Comparator {
            operation: Comparison::GreaterOrEqual,
            version: partial.version,
            wildcard_part: -1,
        },
        Comparator {
            operation: Comparison::Less,
            version: maximum,
            wildcard_part: -1,
        },
    ])
}

/// A version a range wrote, which is the reference's `TryParsePartial`.
///
/// A range may name one, two, or three components, or use `*`, `x`, or `X` in
/// the tail. The component count is kept because it decides a range's bound, and
/// a range with fewer than three components and no wildcard still behaves like
/// one.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Partial {
    version: Version,
    parts: usize,
    wildcard_part: i32,
}

/// Parses one version as a range wrote it.
fn parse_partial(value: &str) -> Option<Partial> {
    let value = value.trim();
    let value = value.strip_prefix(['v', 'V']).unwrap_or(value);

    let suffix = value.find(['-', '+']);
    let core = suffix.map_or(value, |index| &value[..index]);
    let mut identifiers: Vec<&str> = core.split('.').collect();
    if identifiers.is_empty() || identifiers.len() > 3 {
        return None;
    }

    let mut wildcard_part: i32 = -1;
    if let Some(wildcard) = identifiers
        .iter()
        .position(|identifier| is_wildcard(identifier))
    {
        // A wildcard ends the version: `1.2.x` is a range and `1.x.3` is not.
        if identifiers[wildcard..]
            .iter()
            .any(|part| !is_wildcard(part))
        {
            return None;
        }
        identifiers.truncate(wildcard);
        wildcard_part = i32::try_from(wildcard).unwrap_or(i32::MAX);
    }

    let parts = identifiers.len();
    if wildcard_part < 0 && parts < 3 {
        wildcard_part = i32::try_from(parts).unwrap_or(i32::MAX);
    }
    if parts == 0 && wildcard_part != 0 {
        return None;
    }

    let major = range_number(&identifiers, 0)?;
    let minor = range_number(&identifiers, 1)?;
    let patch = range_number(&identifiers, 2)?;
    let prerelease = match suffix {
        Some(index) if value.as_bytes()[index] == b'-' => {
            // The prerelease stops at a `+`, so `1.2.3-beta+build` is a
            // prerelease of `beta` with build metadata.
            let rest = &value[index + 1..];
            rest.split('+').next().unwrap_or("")
        }
        _ => "",
    };
    let build = match suffix {
        Some(index) if value.as_bytes()[index] == b'+' => &value[index + 1..],
        _ => "",
    };
    if !valid_identifiers(prerelease, true) || !valid_identifiers(build, false) {
        return None;
    }
    Some(Partial {
        version: Version {
            major,
            minor,
            patch,
            prerelease: prerelease.to_owned(),
            build: build.to_owned(),
        },
        parts,
        wildcard_part,
    })
}

/// Reads a component of a range, which is `VersionConstraint.TryNumber`.
///
/// A component past the end of what the range wrote is zero, so `1` is `1.0.0`.
/// Unlike a version's own number this one accepts a leading zero, because
/// `int.TryParse` is used here rather than the stricter version parser.
fn range_number(identifiers: &[&str], index: usize) -> Option<i32> {
    let Some(identifier) = identifiers.get(index) else {
        return Some(0);
    };
    if identifier.is_empty() || !identifier.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    identifier.parse::<i32>().ok()
}

/// Reports whether every dot-separated identifier is well formed.
///
/// An identifier is ASCII alphanumerics and hyphens, and a numeric identifier
/// with a leading zero is only a problem in a prerelease. This is the
/// reference's `ValidateIdentifiers`.
fn valid_identifiers(value: &str, numeric_no_leading_zero: bool) -> bool {
    if value.is_empty() {
        return true;
    }
    value.split('.').all(|identifier| {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        !(numeric_no_leading_zero
            && identifier.len() > 1
            && identifier.starts_with('0')
            && identifier.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Reports whether a component is a wildcard, which is `IsWildcard`.
fn is_wildcard(value: &str) -> bool {
    matches!(value, "*" | "x" | "X")
}

/// Reports whether a token is a bare comparison operator.
fn is_operator(value: &str) -> bool {
    matches!(value, ">" | ">=" | "<" | "<=" | "=" | "!=")
}

/// The next major, which is the reference's `IncrementMajor`.
///
/// A version whose major is already `i32::MAX` cannot be incremented, and the
/// reference's `checked` throws there, so the range is rejected rather than
/// wrapping to a negative bound.
fn increment_major(version: &Version) -> Option<Version> {
    Some(Version {
        major: version.major.checked_add(1)?,
        minor: 0,
        patch: 0,
        prerelease: String::new(),
        build: String::new(),
    })
}

/// The next minor, which is the reference's `IncrementMinor`.
fn increment_minor(version: &Version) -> Option<Version> {
    Some(Version {
        major: version.major,
        minor: version.minor.checked_add(1)?,
        patch: 0,
        prerelease: String::new(),
        build: String::new(),
    })
}

/// The next patch, which is the reference's `IncrementPatch`.
fn increment_patch(version: &Version) -> Option<Version> {
    Some(Version {
        major: version.major,
        minor: version.minor,
        patch: version.patch.checked_add(1)?,
        prerelease: String::new(),
        build: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::{
        Comparator, ComparatorSet, Comparison, DISPATCH, Version, parse_constraint, parse_version,
        takes_rendered_strings,
    };
    use crate::{Context, Error, Value};

    /// Calls the dispatch table the way `lib.rs` does, unwrapping `Some`.
    fn call(name: &str, arguments: &[Value]) -> Result<Value, Error> {
        let context = Context::default();
        DISPATCH(name, arguments, &context).expect("the module claims the name")
    }

    /// Renders `semverCompare "RANGE" "VERSION"` as the reference's fixtures do.
    fn compare(range: &str, version: &str) -> String {
        call(
            "semverCompare",
            &[
                Value::String(range.to_owned()),
                Value::String(version.to_owned()),
            ],
        )
        .expect("semverCompare succeeds")
        .render()
    }

    /// Renders one field of `semver "VERSION"`, as `$version.FIELD` does.
    fn field(version: &str, name: &str) -> String {
        let value = call("semver", &[Value::String(version.to_owned())]).expect("semver succeeds");
        // The reference returns an *object* — a display string plus members plus
        // the `Compare` method — so the members are reached through that.
        let Value::Object {
            members: entries, ..
        } = value
        else {
            panic!("semver returns an object");
        };
        entries
            .get(name)
            .unwrap_or_else(|| panic!("semver has no {name}"))
            .render()
    }

    #[test]
    fn the_module_claims_only_its_own_helpers() {
        let context = Context::default();
        assert!(DISPATCH("semverCompare", &[], &context).is_some());
        assert!(DISPATCH("semver", &[], &context).is_some());
        assert!(DISPATCH("date", &[], &context).is_none());
        assert!(DISPATCH("urlParse", &[], &context).is_none());
    }

    #[test]
    fn no_helper_wants_rendered_arguments() {
        assert!(!takes_rendered_strings("semver"));
        assert!(!takes_rendered_strings("semverCompare"));
    }

    #[test]
    fn the_reference_semver_compare_cases_match() {
        // The reference's own `semverCompare` fixtures, copied from
        // SprigUpstreamParityTests.
        for (range, version, expected) in [
            ("^1.2.0", "1.2.3", "true"),
            ("^1.2.0", "2.2.3", "false"),
            ("^0.2.3", "0.3.0", "false"),
            ("1.2.x", "1.2.9", "true"),
            ("1.2.3 - 2.3.4", "2.3.4", "true"),
            (">=1.2.3 <2.0.0 || >=3.0.0", "3.1.0", "true"),
            (">=1.2.0", "1.3.0", "true"),
            ("~1.2.0", "1.2.9", "true"),
            ("~1.2.0", "1.3.0", "false"),
            ("1.2.x", "1.3.0", "false"),
        ] {
            assert_eq!(compare(range, version), expected, "{range} {version}");
        }
    }

    #[test]
    fn the_reference_semver_fields_match() {
        // `{{ $version := semver "1.2.3-beta.1+c0ff33" }}{{ $version.Prerelease }}`
        // renders `beta.1` and `{{ $version.Major }}` renders `1`.
        assert_eq!(field("1.2.3-beta.1+c0ff33", "Prerelease"), "beta.1");
        assert_eq!(field("1.2.3-beta.1+c0ff33", "Major"), "1");
        assert_eq!(field("1.2.3-beta.1+c0ff33", "Minor"), "2");
        assert_eq!(field("1.2.3-beta.1+c0ff33", "Patch"), "3");
        assert_eq!(field("1.2.3-beta.1+c0ff33", "Metadata"), "c0ff33");
    }

    #[test]
    fn a_prerelease_sorts_below_the_release_it_precedes() {
        // The reference's `CompareTo`: the numbers decide first, and only then
        // does a nonempty prerelease sort below an empty one.
        let version = |value: &str| parse_version(value).expect("a version");
        assert_eq!(version("1.2.3").compare(&version("1.2.3")), Ordering::Equal);
        assert_eq!(version("1.2.3").compare(&version("1.2.4")), Ordering::Less);
        assert_eq!(
            version("1.3.0").compare(&version("1.2.9")),
            Ordering::Greater
        );
        assert_eq!(
            version("1.0.0-alpha").compare(&version("1.0.0")),
            Ordering::Less
        );
        // A numeric identifier is below an alphanumeric one, and `alpha` is
        // below `alpha.1` because a shorter run of identifiers is lower.
        assert_eq!(
            version("1.0.0-alpha.1").compare(&version("1.0.0-alpha.beta")),
            Ordering::Less
        );
        assert_eq!(
            version("1.0.0-alpha").compare(&version("1.0.0-alpha.1")),
            Ordering::Less
        );
        assert_eq!(
            version("1.0.0-alpha.10").compare(&version("1.0.0-alpha.9")),
            Ordering::Greater
        );
    }

    #[test]
    fn a_caret_range_pins_every_leading_zero() {
        // The reference's `TryParseCaret`: a leading zero pins the component
        // before it, so `^0.2.3` stops at 0.3.0 and `^0.0.3` stops at 0.0.4.
        for (range, version, expected) in [
            ("^0.0.3", "0.0.3", "true"),
            ("^0.0.3", "0.0.4", "false"),
            ("^0.0.3", "0.1.0", "false"),
            ("^0.2.3", "0.2.9", "true"),
            ("^1.2", "1.9.0", "true"),
            ("^1.2", "2.0.0", "false"),
            ("^1", "1.5.0", "true"),
            ("^1", "2.0.0", "false"),
        ] {
            assert_eq!(compare(range, version), expected, "{range} {version}");
        }
    }

    #[test]
    fn a_tilde_range_allows_the_minor_to_move() {
        for (range, version, expected) in [
            ("~1.2.0", "1.2.0", "true"),
            ("~1.2.0", "1.2.99", "true"),
            ("~1.2.0", "1.3.0", "false"),
            ("~1.2.0", "0.9.9", "false"),
            ("~1", "1.5.0", "true"),
            ("~1", "2.0.0", "false"),
        ] {
            assert_eq!(compare(range, version), expected, "{range} {version}");
        }
    }

    #[test]
    fn a_hyphen_range_is_inclusive_at_both_ends() {
        // The reference's `TryParseHyphenRange`: the upper bound's component
        // count decides whether the bound is exclusive and at what.
        for (range, version, expected) in [
            ("1.2.3 - 2.3.4", "1.2.3", "true"),
            ("1.2.3 - 2.3.4", "2.3.4", "true"),
            ("1.2.3 - 2.3.4", "1.2.2", "false"),
            ("1.2.3 - 2.3.4", "2.3.5", "false"),
            ("1.2.3 - 2.3", "2.3.9", "true"),
            ("1.2.3 - 2.3", "2.4.0", "false"),
            ("1.2.3 - 2", "2.9.9", "true"),
            ("1.2.3 - 2", "3.0.0", "false"),
        ] {
            assert_eq!(compare(range, version), expected, "{range} {version}");
        }
    }

    #[test]
    fn a_wildcard_compares_the_way_each_operator_asks() {
        // `1.2.x` as an equality is the `1.2` tilde range; the operators around
        // a wildcard each have their own rule in the reference.
        for (range, version, expected) in [
            ("1.2.x", "1.2.0", "true"),
            ("1.2.x", "1.2.99", "true"),
            ("1.2.x", "1.1.99", "false"),
            ("1.x", "1.9.9", "true"),
            ("1.x", "2.0.0", "false"),
            ("*", "9.9.9", "true"),
            (">1.2.x", "1.3.0", "true"),
            (">1.2.x", "1.2.9", "false"),
            ("<=1.2.x", "1.2.9", "true"),
            ("<=1.2.x", "1.3.0", "false"),
            ("!=1.2.x", "1.3.0", "true"),
            ("!=1.2.x", "1.2.0", "false"),
            (">=1.2", "1.2.0", "true"),
        ] {
            assert_eq!(compare(range, version), expected, "{range} {version}");
        }
    }

    #[test]
    fn a_bare_wildcard_only_answers_the_comparisons_that_have_a_meaning() {
        // The reference's `IsWildcardSatisfiedBy` returns true for `=`, `>=`,
        // and `<=` against `*` and false for the strict ones, which have no
        // bound to compare against.
        let wildcard = |operation| Comparator {
            operation,
            version: Version {
                major: 0,
                minor: 0,
                patch: 0,
                prerelease: String::new(),
                build: String::new(),
            },
            wildcard_part: 0,
        };
        let version = parse_version("5.6.7").expect("a version");
        assert!(wildcard(Comparison::Equal).is_satisfied_by(&version));
        assert!(wildcard(Comparison::GreaterOrEqual).is_satisfied_by(&version));
        assert!(wildcard(Comparison::LessOrEqual).is_satisfied_by(&version));
        assert!(!wildcard(Comparison::Greater).is_satisfied_by(&version));
        assert!(!wildcard(Comparison::Less).is_satisfied_by(&version));
        assert!(!wildcard(Comparison::NotEqual).is_satisfied_by(&version));
    }

    #[test]
    fn a_prerelease_version_needs_a_prerelease_in_the_range() {
        // The reference's `ComparatorSet.IsSatisfiedBy`: `>=1.2.3` is about
        // release versions, so it does not accept `2.0.0-rc.1` even though
        // that version is numerically above it.
        assert_eq!(compare(">=1.2.3", "2.0.0-rc.1"), "false");
        assert_eq!(compare(">=2.0.0-rc.1", "2.0.0-rc.1"), "true");
        // A range naming a different triple of numbers does not unlock it.
        assert_eq!(compare(">=1.2.3-rc.1", "2.0.0-rc.1"), "false");
    }

    #[test]
    fn either_side_of_an_or_can_satisfy() {
        assert_eq!(compare("1.2.3 || 2.0.0", "2.0.0"), "true");
        assert_eq!(compare("1.2.3 || 2.0.0", "1.2.3"), "true");
        assert_eq!(compare("1.2.3 || 2.0.0", "1.5.0"), "false");
        // A comma is a space to the reference, so it separates comparators the
        // same way.
        assert_eq!(compare(">=1.2.3, <2.0.0", "1.5.0"), "true");
        assert_eq!(compare(">=1.2.3, <2.0.0", "2.0.0"), "false");
    }

    #[test]
    fn a_version_needs_exactly_three_components() {
        // `SemanticVersion.TryParse` splits on `.` and requires three fields,
        // so a two-component version is a range, not a version.
        assert!(parse_version("1.2").is_none());
        assert!(parse_version("1").is_none());
        assert!(parse_version("1.2.3.4").is_none());
        // A leading zero is not a number, either in a version or in a range's
        // strict reading.
        assert!(parse_version("01.2.3").is_none());
        // A leading `v` is accepted, exactly one of them.
        assert!(parse_version("v1.2.3").is_some());
        assert!(parse_version("vv1.2.3").is_none());
        // A prerelease identifier that is a number may not have a leading zero.
        assert!(parse_version("1.2.3-01").is_none());
        assert!(parse_version("1.2.3-0").is_some());
        // Build metadata may, and does not affect precedence.
        assert!(parse_version("1.2.3+01").is_some());
        // An empty prerelease, an empty build, and whitespace are all refused.
        assert!(parse_version("1.2.3-").is_none());
        assert!(parse_version("1.2.3+").is_none());
        assert!(parse_version(" 1.2.3").is_none());
        assert!(parse_version("1.2.3 ").is_none());
    }

    #[test]
    fn an_invalid_version_or_range_is_an_error() {
        for text in ["", "not a version", "1.2", "1.2.3-", "vv1.2.3"] {
            let result = call("semver", &[Value::String(text.to_owned())]);
            assert!(
                matches!(result, Err(Error::InvalidArgument { .. })),
                "semver {text:?} should be an error"
            );
        }
        for range in ["", "   ", ">=", "1.2.x.3", "^"] {
            let result = call(
                "semverCompare",
                &[
                    Value::String(range.to_owned()),
                    Value::String("1.2.3".to_owned()),
                ],
            );
            assert!(
                matches!(result, Err(Error::InvalidArgument { .. })),
                "semverCompare {range:?} should be an error"
            );
        }
        let result = call(
            "semverCompare",
            &[
                Value::String("^1.2.0".to_owned()),
                Value::String("not a version".to_owned()),
            ],
        );
        assert!(matches!(result, Err(Error::InvalidArgument { .. })));
    }

    #[test]
    fn the_argument_count_is_checked() {
        assert!(matches!(
            call("semver", &[]),
            Err(Error::WrongArgumentCount { .. })
        ));
        assert!(matches!(
            call(
                "semver",
                &[
                    Value::String("1.2.3".to_owned()),
                    Value::String("x".to_owned())
                ]
            ),
            Err(Error::WrongArgumentCount { .. })
        ));
        assert!(matches!(
            call("semverCompare", &[Value::String("^1.2.0".to_owned())]),
            Err(Error::WrongArgumentCount { .. })
        ));
    }

    #[test]
    fn a_scalar_argument_is_read_as_its_rendered_form() {
        // The reference's `S` renders a scalar rather than insisting on a
        // string, so a number arriving from a values file is read rather than
        // refused. `1.0` renders as `1`, which is one component, so it is not
        // a version — the coercion happened, and the parse then said no.
        assert!(matches!(
            call("semver", &[Value::Number(1.0)]),
            Err(Error::InvalidArgument { .. })
        ));
        // A collection has no sensible rendered form, so `support::text`
        // refuses it.
        assert!(matches!(
            call(
                "semver",
                &[Value::List(vec![Value::String("1.2.3".to_owned())])]
            ),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn the_constraint_and_set_types_are_what_the_reference_expects() {
        // A direct check that a parsed constraint is the shape the reference's
        // `IsSatisfiedBy` walks: one set per `||` side, each a list of
        // comparators.
        let constraint = parse_constraint(">=1.2.3 <2.0.0 || >=3.0.0").expect("a constraint");
        assert_eq!(constraint.sets.len(), 2);
        let ComparatorSet { comparators } = &constraint.sets[0];
        assert_eq!(comparators.len(), 2);
        assert_eq!(comparators[0].operation, Comparison::GreaterOrEqual);
        assert_eq!(comparators[1].operation, Comparison::Less);
        assert_eq!(
            constraint.sets[1].comparators[0].operation,
            Comparison::GreaterOrEqual
        );
        // And a version the reference's own fixture calls true.
        assert!(constraint.is_satisfied_by(&parse_version("3.1.0").expect("a version")));
    }
}
