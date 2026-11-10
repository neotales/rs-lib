//! Opt-in, bounded Go-template rendering for explicit Bake sources.

use std::{collections::BTreeMap, fmt};

use neotales_env::Environment;
use neotales_gotmpl::Template;
pub use neotales_gotmpl::{Error as TemplateError, ParseOptions, RenderOptions};
pub use neotales_sprig::Value;

use crate::VariableValues;

/// Bounds and cooperative cancellation for one Bake template render.
///
/// The parse and render limits are the stable public contracts from
/// `neotales-gotmpl`. A cancellation callback is observed during both parsing
/// and rendering.
#[derive(Clone, Copy, Default)]
pub struct TemplateOptions<'a> {
    /// Bounds applied while parsing the template source.
    pub parse: ParseOptions,
    /// Bounds and cancellation applied while rendering explicit values.
    pub render: RenderOptions<'a>,
}

impl<'a> TemplateOptions<'a> {
    /// Creates the default finite parse and render limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns these options with different parse limits.
    #[must_use]
    pub fn with_parse_options(mut self, options: ParseOptions) -> Self {
        self.parse = options;
        self
    }

    /// Returns these options with different render limits and cancellation.
    #[must_use]
    pub fn with_render_options(mut self, options: RenderOptions<'a>) -> Self {
        self.render = options;
        self
    }

    /// Returns these options with one cancellation callback for both phases.
    #[must_use]
    pub fn with_cancellation(mut self, callback: &'a dyn Fn() -> bool) -> Self {
        self.render.is_cancelled = Some(callback);
        self
    }
}

impl fmt::Debug for TemplateOptions<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateOptions")
            .field("parse", &self.parse)
            .field("render", &self.render)
            .finish()
    }
}

/// Explicit values accepted by the Bake template adapter.
///
/// The environment implementations are the preferred path because they retain
/// order and platform-aware key identity. The typed-map implementation keeps
/// the pre-RD-009 template API source-compatible for callers that need helper
/// values which are not environment strings.
pub trait TemplateValues {
    /// Converts this value set into the deterministic typed template context.
    fn template_values(&self) -> BTreeMap<String, Value>;
}

impl TemplateValues for VariableValues {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.iter()
            .map(|(name, value)| (name.to_owned(), Value::String(value.to_owned())))
            .collect()
    }
}

impl TemplateValues for Environment {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.as_map()
            .iter()
            .map(|(name, value)| (name.to_owned(), Value::String(value.to_owned())))
            .collect()
    }
}

impl TemplateValues for BTreeMap<String, Value> {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.clone()
    }
}

/// Renders one explicit Bake source with the ordered variable model.
///
/// The same [`VariableValues`] instance can be passed to
/// [`crate::normalize_with_values`] or produced by the explicit dotenv loader.
/// Sources without a Go-template opening delimiter are returned unchanged and
/// do not invoke parsing, rendering, cancellation, or value conversion.
/// Template errors are returned directly from `neotales-gotmpl`; rendered
/// values are never added to diagnostics.
///
/// # Errors
///
/// Returns a parse, safe-helper, cancellation, or resource-limit error.
pub fn render_template<V>(
    source: &str,
    values: &V,
    options: &TemplateOptions<'_>,
) -> Result<String, TemplateError>
where
    V: TemplateValues + ?Sized,
{
    if source.len() > options.parse.max_source_length {
        return Err(TemplateError::ResourceLimitExceeded);
    }
    if !source.contains("{{") {
        return Ok(source.to_owned());
    }

    let template = if let Some(is_cancelled) = options.render.is_cancelled {
        Template::parse_with_cancellation(source, options.parse, is_cancelled)?
    } else {
        Template::parse_with_options(source, options.parse)?
    };
    let values = values.template_values();
    template.render_typed_with_options(&values, options.render)
}
