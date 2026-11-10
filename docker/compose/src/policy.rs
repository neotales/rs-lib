use neotales_env::{Environment, Platform};

/// Controls which fields are accepted while parsing a Compose document.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ComposeValidationMode {
    /// Reject every field outside the bounded normalized schema.
    #[default]
    Strict,
    /// Reject fields outside the bounded schema; extension keys are ignored.
    Default,
    /// Ignore fields outside the bounded schema after structural validation.
    Loose,
}

/// Controls scalar interpolation performed by the resolver.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InterpolationMode {
    /// Reject interpolation syntax; no values are consulted.
    Disabled,
    /// Expand only variables present in the caller-owned environment model.
    #[default]
    ExplicitValues,
}

/// Controls an unset bare variable such as `$NAME` or `${NAME}`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MissingVariablePolicy {
    /// Replace an unset variable with an empty string.
    #[default]
    Empty,
    /// Reject an unset variable.
    Error,
}

/// Explicit interpolation policy.
///
/// Interpolation never falls back to the process environment, implicit `.env`
/// files, `env_file`, command substitution, or Go-template evaluation. The `?`
/// and `:?` operators are always errors when their required variable is absent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterpolationPolicy {
    /// Whether scalar interpolation is enabled.
    pub mode: InterpolationMode,
    /// How an ordinary unset variable is handled.
    pub missing: MissingVariablePolicy,
}

impl InterpolationPolicy {
    /// Creates the default explicit-value policy.
    #[must_use]
    pub const fn explicit_values() -> Self {
        Self {
            mode: InterpolationMode::ExplicitValues,
            missing: MissingVariablePolicy::Empty,
        }
    }

    /// Creates a policy that rejects interpolation syntax.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            mode: InterpolationMode::Disabled,
            missing: MissingVariablePolicy::Error,
        }
    }

    /// Returns this policy with a different missing-variable behavior.
    #[must_use]
    pub const fn with_missing(mut self, missing: MissingVariablePolicy) -> Self {
        self.missing = missing;
        self
    }
}

/// Controls how multiple normalized documents are combined.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MergePolicy {
    /// Accept exactly one document and reject all source merges.
    #[default]
    Reject,
    /// Later documents replace an earlier service as a whole.
    LastWins,
    /// Later documents replace scalar service values and merge environment maps.
    MergeServices,
}

/// Controls how a service's `env_file` and `label_file` are read.
///
/// Compose declares these paths inside the document, so honoring them means
/// reading a file the document named. This repository does not read a
/// document-named file implicitly: the library resolves the declared path
/// against the directory of the Compose file and looks the result up in a
/// caller-supplied map, so the bytes always come from the caller that chose to
/// supply them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EnvFilePolicy {
    /// Reject every `env_file` and `label_file` entry.
    #[default]
    Reject,
    /// Resolve entries against a caller-supplied map of file contents.
    CallerSupplied,
}

/// Controls include handling without granting implicit filesystem access.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IncludePolicy {
    /// Reject every `include` entry.
    #[default]
    Reject,
    /// Resolve only entries supplied by the caller in an explicit path map.
    CallerSupplied,
}

/// Controls malformed nodes retained by `neotales-dotenv`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InvalidDotenvNodePolicy {
    /// Reject the first invalid node with its source line.
    #[default]
    Reject,
    /// Preserve the node in the source document but omit it from values.
    Ignore,
}

/// Controls assignments whose names are not environment variable names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InvalidEnvironmentKeyPolicy {
    /// Reject the assignment with its source line and key.
    #[default]
    Reject,
    /// Preserve the assignment in the source document but omit it from values.
    Ignore,
}

/// Controls conflicts between injected values and explicitly loaded dotenvs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DotenvPrecedence {
    /// Injected values are protected; later dotenv values win among themselves.
    #[default]
    InjectedWins,
    /// Later dotenv assignments and sources win, including over injected values.
    LastWins,
}

/// Repository-owned policy for converting one or more dotenv documents.
///
/// A dotenv document is parsed only by `neotales-dotenv`. This policy validates
/// its unvalidated assignment names, controls malformed nodes, and defines
/// conflicts without consulting process-global state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DotenvPolicy {
    /// Platform rules for key identity. The default uses the host platform.
    pub platform: Platform,
    /// Treatment of nodes that are not comments, blanks, or assignments.
    pub invalid_nodes: InvalidDotenvNodePolicy,
    /// Treatment of assignments with invalid environment names.
    pub invalid_keys: InvalidEnvironmentKeyPolicy,
    /// Conflict precedence between injected values and dotenv assignments.
    pub precedence: DotenvPrecedence,
    /// Interpolation policy for unquoted and double-quoted values.
    pub interpolation: InterpolationPolicy,
}

impl DotenvPolicy {
    /// Returns this policy with different platform-aware key rules.
    #[must_use]
    pub const fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    /// Returns this policy with a different precedence rule.
    #[must_use]
    pub const fn with_precedence(mut self, precedence: DotenvPrecedence) -> Self {
        self.precedence = precedence;
        self
    }

    /// Returns this policy with different malformed-node handling.
    #[must_use]
    pub const fn with_invalid_nodes(mut self, invalid_nodes: InvalidDotenvNodePolicy) -> Self {
        self.invalid_nodes = invalid_nodes;
        self
    }

    /// Returns this policy with different invalid-key handling.
    #[must_use]
    pub const fn with_invalid_keys(mut self, invalid_keys: InvalidEnvironmentKeyPolicy) -> Self {
        self.invalid_keys = invalid_keys;
        self
    }

    /// Returns this policy with different explicit interpolation behavior.
    #[must_use]
    pub const fn with_interpolation(mut self, interpolation: InterpolationPolicy) -> Self {
        self.interpolation = interpolation;
        self
    }
}

impl Default for DotenvPolicy {
    fn default() -> Self {
        Self {
            platform: Platform::host(),
            invalid_nodes: InvalidDotenvNodePolicy::Reject,
            invalid_keys: InvalidEnvironmentKeyPolicy::Reject,
            precedence: DotenvPrecedence::InjectedWins,
            interpolation: InterpolationPolicy::default(),
        }
    }
}

/// All policy switches used by the daemon-free resolver.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComposePolicy {
    /// Field validation policy used while parsing source input.
    pub validation: ComposeValidationMode,
    /// Scalar interpolation policy.
    pub interpolation: InterpolationPolicy,
    /// Multi-document merge policy.
    pub merge: MergePolicy,
    /// Include policy.
    pub include: IncludePolicy,
}

/// Ordered, platform-aware values injected into Compose interpolation.
///
/// The backing store is `neotales_env::Environment`. On Windows, key identity
/// is ASCII case-insensitive and the first selected spelling is retained. No
/// constructor reads the process environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpolationValues {
    environment: Environment,
}

impl InterpolationValues {
    /// Creates an empty value set using host platform key rules.
    #[must_use]
    pub fn new() -> Self {
        Self::with_platform(Platform::host())
    }

    /// Creates an empty value set with explicit platform key rules.
    #[must_use]
    pub fn with_platform(platform: Platform) -> Self {
        Self {
            environment: Environment::new(platform),
        }
    }

    /// Creates a value set from caller-owned pairs using host platform rules.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self::from_pairs_with_platform(pairs, Platform::host())
    }

    /// Creates a value set from caller-owned pairs with explicit platform rules.
    #[must_use]
    pub fn from_pairs_with_platform<I, K, V>(pairs: I, platform: Platform) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut values = Self::with_platform(platform);
        for (key, value) in pairs {
            let _ = values.insert(key, value);
        }
        values
    }

    /// Adopts an ordered environment without copying it.
    #[must_use]
    pub const fn from_environment(environment: Environment) -> Self {
        Self { environment }
    }

    /// Returns the platform rules used for key identity.
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.environment.platform()
    }

    /// Returns the backing ordered environment.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Consumes this wrapper and returns the backing ordered environment.
    #[must_use]
    pub fn into_environment(self) -> Environment {
        self.environment
    }

    /// Inserts or replaces one explicit value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.environment.insert(key, value)
    }

    /// Returns an injected value using platform-aware key identity.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.environment.get(key)
    }

    /// Returns whether a key is explicitly present, including an empty value.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.environment.get(key).is_some()
    }

    /// Returns values in first-selected insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.environment
            .as_map()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Returns the number of injected values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.environment.as_map().len()
    }

    /// Returns whether no values were injected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.environment.as_map().is_empty()
    }
}

impl Default for InterpolationValues {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Environment> for InterpolationValues {
    fn from(environment: Environment) -> Self {
        Self::from_environment(environment)
    }
}

impl FromIterator<(String, String)> for InterpolationValues {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self::from_pairs(iter)
    }
}
