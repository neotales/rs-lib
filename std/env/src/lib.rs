//! Pure, ordered environment values and transformations.
#![doc = include_str!("../README.md")]

use std::fmt;

use indexmap::IndexMap;

/// Platform rules used for environment-key and PATH handling.
///
/// The same environment variable is spelled with different capitalisation on the
/// two platforms, and a comparison that ignores that treats `Path` and `PATH` as
/// two different variables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    /// Linux, macOS and the other systems using a colon-separated `PATH`.
    Unix,
    /// Windows, where environment names are case-insensitive and `PATH` entries are separated by semicolons.
    Windows,
}

impl Platform {
    /// Returns the rules for the platform this build is running on.
    ///
    /// Right for rendering a file that will be consumed elsewhere. For anything
    /// acting on the current process, read the real environment rather than
    /// assuming this one.
    #[must_use]
    pub const fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }

    /// Returns the character that separates entries in a `PATH`-style value.
    #[must_use]
    pub const fn path_separator(self) -> char {
        match self {
            Self::Unix => ':',
            Self::Windows => ';',
        }
    }

    /// Compares two environment keys under this platform's rules.
    fn keys_equal(self, left: &str, right: &str) -> bool {
        match self {
            Self::Unix => left == right,
            Self::Windows => left.eq_ignore_ascii_case(right),
        }
    }
}

/// An insertion-ordered environment which preserves the first selected key spelling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Environment {
    platform: Platform,
    values: IndexMap<String, String>,
}

impl Environment {
    /// Creates an empty environment using the given platform's rules.
    #[must_use]
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            values: IndexMap::new(),
        }
    }

    /// Returns the platform rules used for key comparison and PATH handling.
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Returns the value stored under `key`, or `None` when it is not set.
    ///
    /// The lookup follows the platform's case rules, so on Windows `path` finds
    /// an entry stored as `Path`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(existing, _)| self.platform.keys_equal(existing, key))
            .map(|(_, value)| value.as_str())
    }

    /// Sets `key` to `value`, returning whatever it held before.
    ///
    /// An existing entry keeps the spelling it was first inserted with, so this
    /// updates in place rather than adding a second entry under a differently
    /// capitalised name.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let key = key.into();
        let value = value.into();
        if let Some(existing) = self
            .values
            .keys()
            .find(|existing| self.platform.keys_equal(existing, &key))
            .cloned()
        {
            return self.values.insert(existing, value);
        }
        self.values.insert(key, value)
    }

    /// Removes `key`, returning its value when it was set.
    ///
    /// This is `shift_remove` rather than `swap_remove`, so the order of the
    /// remaining entries is preserved.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        let existing = self
            .values
            .keys()
            .find(|existing| self.platform.keys_equal(existing, key))
            .cloned()?;
        self.values.shift_remove(&existing)
    }

    /// Returns the entries in the order they were first inserted.
    #[must_use]
    pub fn as_map(&self) -> &IndexMap<String, String> {
        &self.values
    }
}

/// Expands `$NAME` and `${NAME}` using explicitly supplied values. Unset names are empty.
#[must_use]
pub fn interpolate(value: &str, environment: &Environment) -> String {
    interpolate_with(value, |name| environment.get(name))
}

/// Expands `$NAME` and `${NAME}` using an explicit lookup function.
///
/// A name is a run of ASCII letters, digits and underscores, and the character
/// that ends it is not part of it. The unbraced form therefore keeps the `/` in
/// `$HOME/bin` rather than swallowing it into the name:
///
/// ```
/// use neotales_env::interpolate_with;
///
/// let home = interpolate_with("$HOME/bin", |name| (name == "HOME").then_some("/home/dev"));
/// assert_eq!(home, "/home/dev/bin");
/// ```
#[must_use]
pub fn interpolate_with<'a>(
    value: &str,
    mut lookup: impl FnMut(&str) -> Option<&'a str>,
) -> String {
    let mut output = String::with_capacity(value.len());
    // `rest` is the part of `value` not yet copied, and it is always sliced
    // rather than iterated, so the character that ends a name is still at the
    // front of `rest` when the next iteration looks at it.
    let mut rest = value;
    while let Some(dollar) = rest.find('$') {
        output.push_str(&rest[..dollar]);
        rest = &rest[dollar + 1..];
        if let Some(braced) = rest.strip_prefix('{') {
            // A `${NAME` with no closing brace takes the rest of the value as
            // its name, which is what the braced form has always done.
            let end = braced.find('}').unwrap_or(braced.len());
            output.push_str(lookup(&braced[..end]).unwrap_or(""));
            // The closing brace is consumed here rather than by a `take_while`
            // that had to eat it to stop. `braced[end]` is the brace, so
            // `end + 1` is the next character boundary.
            rest = if end < braced.len() {
                &braced[end + 1..]
            } else {
                ""
            };
            continue;
        }
        let end = name_end(rest);
        if end == 0 {
            // A `$` with no name after it is literal, and whatever follows it
            // has not been looked at yet.
            output.push('$');
        } else {
            output.push_str(lookup(&rest[..end]).unwrap_or(""));
            rest = &rest[end..];
        }
    }
    output.push_str(rest);
    output
}

/// Returns the byte length of the variable name at the start of `value`.
///
/// Zero means there is no name there, so the caller emits a literal `$` rather
/// than a lookup. The name characters are the set the unbraced form has always
/// accepted; only the handling of the character after them has changed.
fn name_end(value: &str) -> usize {
    value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(value.len())
}

/// Prepends entries in declaration order, preserving an empty existing value as absent.
#[must_use]
pub fn path_prepend(existing: Option<&str>, entries: &[String], platform: Platform) -> String {
    join_path(
        entries
            .iter()
            .map(String::as_str)
            .chain(existing.filter(|value| !value.is_empty())),
        platform,
    )
}

/// Appends entries in declaration order, preserving an empty existing value as absent.
#[must_use]
pub fn path_append(existing: Option<&str>, entries: &[String], platform: Platform) -> String {
    join_path(
        existing
            .filter(|value| !value.is_empty())
            .into_iter()
            .chain(entries.iter().map(String::as_str)),
        platform,
    )
}

fn join_path<'a>(entries: impl Iterator<Item = &'a str>, platform: Platform) -> String {
    entries
        .collect::<Vec<_>>()
        .join(&platform.path_separator().to_string())
}

/// Something the environment helpers could not accept.
///
/// This is the crate's only error, and it is returned where the bad value
/// arrives rather than where it would later be noticed. There is nothing to
/// recover from at the point of reporting, so it carries the offending value
/// and nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvError {
    /// A key is not a name that a shell or an operating system will accept.
    ///
    /// A name starts with an ASCII letter or an underscore and continues with
    /// ASCII letters, digits or underscores, so `PATH` and `_INTERNAL2` are
    /// names while `1INVALID`, `MY-VAR`, `MY VAR` and the empty string are not.
    InvalidKey {
        /// The rejected key, exactly as it was given.
        key: String,
    },
}

impl fmt::Display for EnvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey { key } => write!(
                formatter,
                "{key:?} is not an environment variable name: a name starts with an ASCII letter \
                 or an underscore and continues with ASCII letters, digits or underscores"
            ),
        }
    }
}

impl std::error::Error for EnvError {}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, EnvError>;

/// An ordered sequence of changes to apply to an environment.
///
/// A diff is a plan, not an action. Building one changes nothing, which is what
/// makes it reviewable and renderable into a script before anything is applied.
///
/// Every key is checked as it is added, so a diff built through the public API
/// always renders. A key that is not a name costs a `?` where it was written
/// rather than a panic where it was rendered.
///
/// ```
/// use neotales_env::{EnvDiff, Shell};
///
/// # fn main() -> Result<(), neotales_env::EnvError> {
/// let mut diff = EnvDiff::new();
/// diff.set("MODE", "release")?;
/// diff.path_prepend("PATH", "/opt/bin")?;
///
/// assert_eq!(diff.affected_keys(), ["MODE", "PATH"]);
/// assert!(diff.render(Shell::Bash).contains("export MODE='release'"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvDiff {
    changes: Vec<EnvChange>,
}

/// A single change within an [`EnvDiff`].
///
/// A caller can build one of these, but there is no way to put one into a diff:
/// [`EnvDiff::set`] and its three siblings check the key and record the change
/// themselves, which is what keeps every key in a diff a name that renders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvChange {
    /// Sets a variable to an exact value.
    Set {
        /// The variable name.
        key: String,
        /// The value to set it to.
        value: String,
    },
    /// Removes a variable.
    Unset {
        /// The variable name.
        key: String,
    },
    /// Puts an entry at the front of a `PATH`-style variable.
    PathPrepend {
        /// The variable name, normally `PATH`.
        key: String,
        /// The entry to add.
        value: String,
    },
    /// Puts an entry at the end of a `PATH`-style variable.
    PathAppend {
        /// The variable name, normally `PATH`.
        key: String,
        /// The entry to add.
        value: String,
    },
}

/// A shell a diff can be rendered for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shell {
    /// GNU Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish, whose quoting differs from the POSIX shells.
    Fish,
    /// Windows PowerShell and PowerShell Core.
    PowerShell,
    /// Nushell, which is not a POSIX shell and takes list syntax.
    Nushell,
}

impl Shell {
    /// Parses a shell name, accepting the common aliases.
    ///
    /// Returns `None` for anything unrecognised, so a caller can report the value
    /// it was given rather than silently rendering for the wrong shell.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "powershell" | "pwsh" => Some(Self::PowerShell),
            "nu" | "nushell" => Some(Self::Nushell),
            _ => None,
        }
    }
}

impl EnvDiff {
    /// Creates an empty diff.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a change setting `key` to an exact value.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::InvalidKey`] if `key` is not a valid environment
    /// variable name, and records nothing.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> Result<&mut Self> {
        let key = key.into();
        validate_key(&key)?;
        self.changes.push(EnvChange::Set {
            key,
            value: value.into(),
        });
        Ok(self)
    }

    /// Appends a change removing `key`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::InvalidKey`] if `key` is not a valid environment
    /// variable name, and records nothing.
    pub fn unset(&mut self, key: impl Into<String>) -> Result<&mut Self> {
        let key = key.into();
        validate_key(&key)?;
        self.changes.push(EnvChange::Unset { key });
        Ok(self)
    }

    /// Appends a change putting `value` at the front of the `key` list.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::InvalidKey`] if `key` is not a valid environment
    /// variable name, and records nothing.
    pub fn path_prepend(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<&mut Self> {
        let key = key.into();
        validate_key(&key)?;
        self.changes.push(EnvChange::PathPrepend {
            key,
            value: value.into(),
        });
        Ok(self)
    }

    /// Appends a change putting `value` at the end of the `key` list.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::InvalidKey`] if `key` is not a valid environment
    /// variable name, and records nothing.
    pub fn path_append(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<&mut Self> {
        let key = key.into();
        validate_key(&key)?;
        self.changes.push(EnvChange::PathAppend {
            key,
            value: value.into(),
        });
        Ok(self)
    }

    /// Returns the changes in the order they were added.
    ///
    /// Order is significant: a later change to the same key overrides an earlier
    /// one, so applying the same set in a different order is a different result.
    #[must_use]
    pub fn changes(&self) -> &[EnvChange] {
        &self.changes
    }

    /// Returns each affected key once, in the order it was first changed.
    #[must_use]
    pub fn affected_keys(&self) -> Vec<&str> {
        let mut keys = Vec::new();
        for change in &self.changes {
            if !keys.contains(&change.key()) {
                keys.push(change.key());
            }
        }
        keys
    }

    /// Returns `environment` with every change applied, leaving the input alone.
    #[must_use]
    pub fn apply(&self, environment: &IndexMap<String, String>) -> IndexMap<String, String> {
        let mut result = environment.clone();
        for change in &self.changes {
            apply_change(&mut result, change);
        }
        result
    }

    /// Returns the diff that undoes this one against `environment`.
    ///
    /// Composing `reverse` with `apply` returns the original environment, which
    /// is what makes a change reviewable before it is applied and reversible
    /// after it has been.
    #[must_use]
    pub fn reverse(&self, environment: &IndexMap<String, String>) -> Self {
        let mut current = environment.clone();
        let mut reverse = Vec::with_capacity(self.changes.len());
        for change in &self.changes {
            let key = change.key();
            reverse.push(match current.get(key) {
                Some(value) => EnvChange::Set {
                    key: key.to_owned(),
                    value: value.clone(),
                },
                None => EnvChange::Unset {
                    key: key.to_owned(),
                },
            });
            apply_change(&mut current, change);
        }
        reverse.reverse();
        Self { changes: reverse }
    }

    /// Renders the diff as shell commands, one per line.
    ///
    /// Values are quoted for the target shell, and that quoting is tested against
    /// embedded quotes and command substitution.
    ///
    /// This cannot fail. A key was checked by the method that recorded its
    /// change, and those methods are the only way to put a change in a diff, so
    /// no caller can reach a key this cannot render.
    #[must_use]
    pub fn render(&self, shell: Shell) -> String {
        self.changes
            .iter()
            .map(|change| render_change(change, shell))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl EnvChange {
    fn key(&self) -> &str {
        match self {
            Self::Set { key, .. }
            | Self::Unset { key }
            | Self::PathPrepend { key, .. }
            | Self::PathAppend { key, .. } => key,
        }
    }
}

fn apply_change(environment: &mut IndexMap<String, String>, change: &EnvChange) {
    match change {
        EnvChange::Set { key, value } => {
            environment.insert(key.clone(), value.clone());
        }
        EnvChange::Unset { key } => {
            environment.shift_remove(key);
        }
        EnvChange::PathPrepend { key, value } => {
            let value = path_prepend(
                environment.get(key).map(String::as_str),
                std::slice::from_ref(value),
                Platform::host(),
            );
            environment.insert(key.clone(), value);
        }
        EnvChange::PathAppend { key, value } => {
            let value = path_append(
                environment.get(key).map(String::as_str),
                std::slice::from_ref(value),
                Platform::host(),
            );
            environment.insert(key.clone(), value);
        }
    }
}

fn render_change(change: &EnvChange, shell: Shell) -> String {
    let key = change.key();
    match shell {
        Shell::Bash | Shell::Zsh => match change {
            EnvChange::Set { value, .. } => format!("export {key}={}", quote_posix(value)),
            EnvChange::Unset { .. } => format!("unset {key}"),
            EnvChange::PathPrepend { value, .. } => {
                format!("export {key}={}:\"${{{key}:-}}\"", quote_posix(value))
            }
            EnvChange::PathAppend { value, .. } => format!(
                "export {key}=\"${{{key}:+${{{key}}}:}}\"{}",
                quote_posix(value)
            ),
        },
        Shell::Fish => match change {
            EnvChange::Set { value, .. } => format!("set -gx {key} {}", quote_posix(value)),
            EnvChange::Unset { .. } => format!("set -e {key}"),
            EnvChange::PathPrepend { value, .. } => {
                format!("set -gx {key} {} ${key}", quote_posix(value))
            }
            EnvChange::PathAppend { value, .. } => {
                format!("set -gx {key} ${key} {}", quote_posix(value))
            }
        },
        Shell::PowerShell => match change {
            EnvChange::Set { value, .. } => format!("$env:{key} = {}", quote_single(value)),
            EnvChange::Unset { .. } => {
                format!("Remove-Item Env:{key} -ErrorAction SilentlyContinue")
            }
            EnvChange::PathPrepend { value, .. } => format!(
                "$env:{key} = {} + [IO.Path]::PathSeparator + $env:{key}",
                quote_single(value)
            ),
            EnvChange::PathAppend { value, .. } => format!(
                "$env:{key} = $env:{key} + [IO.Path]::PathSeparator + {}",
                quote_single(value)
            ),
        },
        Shell::Nushell => match change {
            EnvChange::Set { value, .. } => format!("$env.{key} = {}", quote_single(value)),
            EnvChange::Unset { .. } => format!("hide-env {key}"),
            EnvChange::PathPrepend { value, .. } => format!(
                "$env.{key} = [{}] ++ ($env.{key}? | default [])",
                quote_single(value)
            ),
            EnvChange::PathAppend { value, .. } => format!(
                "$env.{key} = ($env.{key}? | default []) ++ [{}]",
                quote_single(value)
            ),
        },
    }
}
/// Checks a key against the name rules, reporting the key itself on failure.
fn validate_key(key: &str) -> Result<()> {
    if valid_key(key) {
        return Ok(());
    }
    Err(EnvError::InvalidKey {
        key: key.to_owned(),
    })
}
/// Reports whether `key` is a name a shell and an operating system accept.
///
/// The first character is a letter or an underscore, and the rest are letters,
/// digits or underscores, which is what a POSIX name is and what the shells
/// this crate renders for all accept.
fn valid_key(key: &str) -> bool {
    let mut chars = key.bytes();
    matches!(chars.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
fn quote_posix(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn quote_single(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::{
        EnvDiff, EnvError, Environment, Platform, Result, Shell, interpolate, interpolate_with,
        path_append, path_prepend,
    };
    use indexmap::indexmap;
    #[test]
    fn fixture_interpolation_matches_config_behavior() {
        let mut environment = Environment::new(Platform::Unix);
        environment.insert("NAME", "acme");
        // Both separators are kept: the one after the unbraced `$NAME` and the
        // one after the braced `${MISSING}`, which expands to nothing.
        assert_eq!(interpolate("$NAME/${MISSING}/$", &environment), "acme//$");
    }
    /// Expands against a fixed set of values, so a test says what it expects
    /// rather than which variable it happened to look up.
    fn expand(value: &str) -> String {
        interpolate_with(value, |name| match name {
            "HOME" => Some("/home/dev"),
            "PATH" => Some("/usr/bin"),
            _ => None,
        })
    }
    #[test]
    fn unbraced_name_keeps_the_character_that_ends_it() {
        assert_eq!(expand("$HOME/bin"), "/home/dev/bin");
        assert_eq!(expand("$HOME"), "/home/dev");
        assert_eq!(expand("$PATH:/opt/bin"), "/usr/bin:/opt/bin");
        assert_eq!(expand("$HOME/bin:$PATH/x"), "/home/dev/bin:/usr/bin/x");
        assert_eq!(expand("/opt/$HOME"), "/opt//home/dev");
    }
    #[test]
    fn unbraced_name_ends_at_any_character_a_value_can_contain() {
        // The last one is two bytes in UTF-8, so the list also says the name is
        // delimited on a character boundary rather than a byte.
        for terminator in [':', '/', '-', '.', ' ', '=', '\n', '\u{e9}'] {
            let value = format!("$HOME{terminator}bin");
            assert_eq!(
                expand(&value),
                format!("/home/dev{terminator}bin"),
                "terminator {terminator:?} was swallowed"
            );
        }
    }
    #[test]
    fn a_missing_name_expands_to_nothing_and_keeps_its_neighbours() {
        assert_eq!(expand("$MISSING/bin"), "/bin");
        assert_eq!(expand("x${MISSING}y"), "xy");
    }
    #[test]
    fn a_dollar_with_no_name_is_literal() {
        assert_eq!(expand("$"), "$");
        assert_eq!(expand("a$/b"), "a$/b");
        assert_eq!(expand("$$"), "$$");
    }
    #[test]
    fn a_braced_name_is_unchanged_by_the_terminator_fix() {
        assert_eq!(expand("${HOME}/bin"), "/home/dev/bin");
        assert_eq!(expand("${HOME}"), "/home/dev");
        assert_eq!(expand("${MISSING}/bin"), "/bin");
        // No closing brace: the rest of the value is the name, and it is not
        // set, so the whole remainder expands to nothing.
        assert_eq!(expand("${HOME/bin"), "");
    }
    #[test]
    fn fixture_path_operations_preserve_declaration_order() {
        let entries = vec!["first".into(), "second".into()];
        assert_eq!(
            path_prepend(Some("system"), &entries, Platform::Unix),
            "first:second:system"
        );
        assert_eq!(
            path_append(Some("system"), &entries, Platform::Windows),
            "system;first;second"
        );
    }
    #[test]
    fn windows_keys_are_case_insensitive_with_stable_spelling() {
        let mut environment = Environment::new(Platform::Windows);
        environment.insert("Path", "one");
        environment.insert("PATH", "two");
        environment.insert("pAtH", "three");
        assert_eq!(
            environment.as_map(),
            &indexmap! { String::from("Path") => String::from("three") }
        );
        assert_eq!(environment.get("PATH"), Some("three"));
        assert_eq!(environment.remove("path"), Some("three".into()));
        assert!(environment.as_map().is_empty());
    }
    #[test]
    fn fixture_diff_reverses_exactly() -> Result<()> {
        let original =
            indexmap! { "PATH".into() => "/usr/bin".into(), "OLD".into() => "old".into() };
        let mut diff = EnvDiff::new();
        diff.set("NEW", "value")?
            .unset("OLD")?
            .path_prepend("PATH", "/tool/bin")?;
        assert_eq!(
            diff.reverse(&original).apply(&diff.apply(&original)),
            original
        );
        Ok(())
    }
    #[test]
    fn shell_rendering_remains_escaped() -> Result<()> {
        let mut diff = EnvDiff::new();
        diff.set("VALUE", "a'$(unsafe)")?
            .path_prepend("PATH", "/opt tool")?;
        assert!(diff.render(Shell::Bash).contains("'a'\"'\"'$(unsafe)'"));
        assert!(diff.render(Shell::Zsh).contains("'a'\"'\"'$(unsafe)'"));
        assert!(diff.render(Shell::Fish).contains("'a'\"'\"'$(unsafe)'"));
        assert!(diff.render(Shell::PowerShell).contains("'a''$(unsafe)'"));
        assert!(diff.render(Shell::Nushell).contains("'a''$(unsafe)'"));
        Ok(())
    }

    #[test]
    fn diff_reports_each_affected_key_once_in_first_change_order() -> Result<()> {
        let mut diff = EnvDiff::new();
        diff.set("FIRST", "one")?
            .path_prepend("PATH", "/tools")?
            .unset("FIRST")?
            .path_append("PATH", "/more")?
            .set("LAST", "three")?;
        assert_eq!(diff.affected_keys(), ["FIRST", "PATH", "LAST"]);
        Ok(())
    }
    /// The exact bytes this crate produced before the key check moved to the
    /// builders, so a change about not panicking cannot quietly become a change
    /// about what is rendered.
    #[test]
    fn rendered_output_is_unchanged_for_every_shell() -> Result<()> {
        let mut diff = EnvDiff::new();
        diff.set("MODE", "release")?
            .unset("OLD")?
            .path_prepend("PATH", "/opt/bin")?
            .path_append("LD_LIBRARY_PATH", "/opt/lib")?
            .set("QUOTED", "a'$(unsafe) \"x\"")?;
        let bash = "export MODE='release'\n\
                    unset OLD\n\
                    export PATH='/opt/bin':\"${PATH:-}\"\n\
                    export LD_LIBRARY_PATH=\"${LD_LIBRARY_PATH:+${LD_LIBRARY_PATH}:}\"'/opt/lib'\n\
                    export QUOTED='a'\"'\"'$(unsafe) \"x\"'";
        let fish = "set -gx MODE 'release'\n\
                    set -e OLD\n\
                    set -gx PATH '/opt/bin' $PATH\n\
                    set -gx LD_LIBRARY_PATH $LD_LIBRARY_PATH '/opt/lib'\n\
                    set -gx QUOTED 'a'\"'\"'$(unsafe) \"x\"'";
        let powershell = "$env:MODE = 'release'\n\
                         Remove-Item Env:OLD -ErrorAction SilentlyContinue\n\
                         $env:PATH = '/opt/bin' + [IO.Path]::PathSeparator + $env:PATH\n\
                         $env:LD_LIBRARY_PATH = $env:LD_LIBRARY_PATH + [IO.Path]::PathSeparator + '/opt/lib'\n\
                         $env:QUOTED = 'a''$(unsafe) \"x\"'";
        let nushell = "$env.MODE = 'release'\n\
                       hide-env OLD\n\
                       $env.PATH = ['/opt/bin'] ++ ($env.PATH? | default [])\n\
                       $env.LD_LIBRARY_PATH = ($env.LD_LIBRARY_PATH? | default []) ++ ['/opt/lib']\n\
                       $env.QUOTED = 'a''$(unsafe) \"x\"'";
        assert_eq!(diff.render(Shell::Bash), bash);
        assert_eq!(diff.render(Shell::Zsh), bash);
        assert_eq!(diff.render(Shell::Fish), fish);
        assert_eq!(diff.render(Shell::PowerShell), powershell);
        assert_eq!(diff.render(Shell::Nushell), nushell);
        Ok(())
    }
    /// The reported case: a key that is not a name comes back as a value, from
    /// the call that introduced it, and is not recorded.
    #[test]
    fn an_invalid_key_is_a_typed_error_rather_than_a_panic() {
        let mut diff = EnvDiff::new();
        assert_eq!(
            diff.set("1INVALID", "value").unwrap_err(),
            EnvError::InvalidKey {
                key: "1INVALID".into()
            }
        );
        // Nothing half-recorded, so the diff is still renderable.
        assert!(diff.changes().is_empty());
        assert_eq!(diff.render(Shell::Bash), "");
    }
    #[test]
    fn every_builder_refuses_a_key_that_is_not_a_name() {
        for key in [
            "", "1INVALID", "MY-VAR", "MY VAR", "PATH=", "\u{c9}NV", "MODE.",
        ] {
            let mut diff = EnvDiff::new();
            for error in [
                diff.set(key, "value").unwrap_err(),
                diff.unset(key).unwrap_err(),
                diff.path_prepend(key, "value").unwrap_err(),
                diff.path_append(key, "value").unwrap_err(),
            ] {
                assert_eq!(error, EnvError::InvalidKey { key: key.into() });
            }
            assert!(diff.changes().is_empty(), "{key:?} was recorded anyway");
        }
    }
    #[test]
    fn a_key_that_is_a_name_is_accepted_by_every_builder() -> Result<()> {
        let mut diff = EnvDiff::new();
        diff.set("PATH", "value")?
            .set("_INTERNAL2", "value")?
            .set("a", "value")?
            .unset("PATH")?
            .path_prepend("PATH", "value")?
            .path_append("PATH", "value")?;
        assert_eq!(diff.changes().len(), 6);
        Ok(())
    }
    #[test]
    fn the_error_says_which_key_was_rejected() {
        let error = EnvError::InvalidKey {
            key: "MY-VAR".into(),
        };
        let message = error.to_string();
        assert!(message.contains("MY-VAR"), "{message}");
        assert!(
            message.contains("not an environment variable name"),
            "{message}"
        );
        // A `std::error::Error`, so it composes with the caller's own reporting.
        let _: &dyn std::error::Error = &error;
    }
}
