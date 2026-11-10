//! What a helper can see about the call site beyond its arguments.

use std::collections::BTreeMap;

/// The call-site facts a helper may need.
///
/// Two of Sprig's helpers read the environment, which is not a property of their
/// arguments. Rather than have the template engine know which helpers those are,
/// the caller hands over the environment and the helper crate decides. That
/// keeps the knowledge in one place: adding a helper that needs the environment
/// does not mean editing the engine.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context<'a> {
    /// The environment `env` and `expandenv` read.
    ///
    /// This is the template's own environment, not the process environment. A
    /// template that read the process environment would produce different output
    /// on a developer machine and in a pipeline for the same inputs, which makes
    /// a rendered Compose file unreproducible.
    pub environment: Option<&'a BTreeMap<String, String>>,
}

impl<'a> Context<'a> {
    /// Builds a context over an environment map.
    #[must_use]
    pub const fn with_environment(environment: &'a BTreeMap<String, String>) -> Self {
        Self {
            environment: Some(environment),
        }
    }

    /// Looks up a name, treating an absent environment as an absent value.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&'a str> {
        self.environment
            .and_then(|environment| environment.get(name))
            .map(String::as_str)
    }
}
