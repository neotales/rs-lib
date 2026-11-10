//! Explicit, daemon-free Compose document primitives.
//!
//! This crate is deliberately independent from `neotales-docker`. It
//! normalizes the small, commonly useful part of a Compose document (service
//! names, image references, and environment entries), then resolves it using
//! values supplied by the caller. It does not contact a Docker daemon or read
//! the process environment. Dotenv files are loaded only when explicitly
//! selected by the caller. The optional `templates` feature adds a bounded,
//! caller-driven source renderer without changing the normalized parse and
//! resolution paths.
#![doc = include_str!("../README.md")]
#![cfg_attr(
    feature = "templates",
    doc = r##"# Values files

A Compose Go template is only useful with something to be parameterized by, and
a flat string map cannot express a nested service map. With the `templates`
feature, `parse_values` decodes a JSON or YAML values file into the structured
map a template ranges over, and `merge_values` layers one file over another so
an override changes the leaves it names and leaves the rest.

```
use neotales_docker_compose::{merge_values, parse_values};
use neotales_sprig::Value;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut values =
    parse_values(r#"{"services":{"api":{"image":"api:1","replicas":3}}}"#, "values.json")?;
merge_values(
    &mut values,
    parse_values(r#"{"services":{"api":{"image":"api:2"}}}"#, "override.json")?,
);

// The override changed the image and left `replicas` alone, because the merge
// recurses into nested mappings instead of replacing them.
let services = values.get("services").expect("services");
let Value::Map(services) = services else { unreachable!() };
let Value::Map(api) = services.get("api").expect("api") else { unreachable!() };
assert_eq!(api.get("image"), Some(&Value::String("api:2".into())));
assert_eq!(api.get("replicas"), Some(&Value::Number(3.0)));
# Ok(())
# }
```
"##
)]

mod bridge;
mod dotenv;
mod error;
mod executor;
mod model;
mod plan;
mod plan_yaml;
mod policy;
mod project;
mod resolver;
mod runtime;
#[cfg(feature = "templates")]
mod template;
#[cfg(feature = "templates")]
mod values;

pub use neotales_env::{Environment as PlatformEnvironment, Platform};

pub use bridge::{
    COMPOSE_BRIDGE_API_VERSION, COMPOSE_BRIDGE_KIND, ComposeBridgeDocument, ComposeBridgeNetwork,
    ComposeBridgePort, ComposeBridgeService, ComposeBridgeVolume,
};
pub use dotenv::{
    DotenvOptions, DotenvSource, LoadedDotenv, MAX_DOTENV_BYTES, load_dotenv, load_dotenv_path,
    load_dotenv_sources, load_dotenv_with_values,
};
pub use error::{ComposeDiagnostic, ComposeError, DiagnosticSeverity};
pub use executor::{
    ComposeExecutionError, ComposeExecutionOptions, ComposeExecutor, ComposeOperationFuture,
    ComposeOperationResult, ComposeOperationSink,
};
pub use model::{
    ComposeDocument, ComposeInclude, ComposeService, Environment, ImageReference,
    InvalidImageReference, ParseOptions,
};
pub use plan::{
    COMPOSE_CONFIG_DIGEST_LABEL, COMPOSE_CONTAINER_NUMBER_LABEL, COMPOSE_DEFAULT_NETWORK_KEY,
    COMPOSE_DEPENDS_ON_LABEL, COMPOSE_NETWORK_LABEL, COMPOSE_ONEOFF_LABEL, COMPOSE_ONEOFF_VALUE,
    COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, COMPOSE_VERSION_LABEL, COMPOSE_VERSION_VALUE,
    ComposeConfigRenderer, ComposePlan, ComposePlanOperation, ComposePlanOperationKind,
    ComposePlanOptions, ComposePlanPolicy, ComposePlanner, ComposePolicyViolation,
    ComposeRenderOptions,
};
pub use plan_yaml::{OrderedMap, OrderedValue, to_yaml as render_yaml_value};
pub use policy::{
    ComposePolicy, ComposeValidationMode, DotenvPolicy, DotenvPrecedence, EnvFilePolicy,
    IncludePolicy, InterpolationMode, InterpolationPolicy, InterpolationValues,
    InvalidDotenvNodePolicy, InvalidEnvironmentKeyPolicy, MergePolicy, MissingVariablePolicy,
};
pub use project::{
    ComposeBindOptions, ComposeBuild, ComposeBuildKitField, ComposeDependency, ComposeDeploy,
    ComposeDeployMode, ComposeHealthcheck, ComposeLogging, ComposeMount, ComposeMountKind,
    ComposeMountSubtree, ComposePlacement, ComposePort, ComposePortProtocol, ComposeProject,
    ComposeProjectConfig, ComposeProjectOptions, ComposeProjectResource, ComposeProjectSecret,
    ComposeProjectService, ComposeRestart, ComposeServiceConfig, ComposeServiceNetwork,
    ComposeServiceSecret, ComposeTmpfsOptions, ComposeUlimit, ComposeUpdateConfig,
    ComposeVolumeOptions, MAX_COMPOSE_SOURCE_BYTES, normalized_project_name, parse_duration_nanos,
    parse_size_bytes,
};
pub use resolver::{ComposeResolver, ResolvedComposeDocument, ResolvedComposeService, interpolate};
pub use runtime::{
    ComposeContainerSpec, ComposeNetworkAttachment, ComposeNetworkSpec, ComposePortPublication,
    ComposePortSpec, ComposeRuntime, ComposeSecretDelivery, ComposeSecretSource, ComposeVolumeSpec,
    container_operation_id, network_operation_id, volume_operation_id,
};
#[cfg(feature = "templates")]
pub use values::{
    TemplateValueMap, merge_values, parse_values, parse_values_document, template_root,
};

#[cfg(feature = "templates")]
pub use template::{
    MissingValueBehavior, ParseOptions as TemplateParseOptions,
    RenderOptions as TemplateRenderOptions, TemplateError, TemplateOptions, TemplateValues, Value,
    render_template,
};
