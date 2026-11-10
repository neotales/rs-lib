# neotales-docker-compose

Explicit, daemon-free Compose document primitives for the Rust Docker work
stream. This crate is a separate higher-level boundary: it does not depend
on `neotales-docker`, contact a Docker daemon, shell out to `docker compose`, or
read the process environment. It can load a dotenv file only when the caller
selects its path or supplies its source. Its opt-in `templates` feature renders
only explicit source with explicit values.

## Bounded first slice

The initial model covers the fields needed for deterministic service/image/
environment fixtures:

- `name`, legacy `version`, and `services` keys;
- one image reference per service; and
- environment mappings and sequences, preserving the distinction between an
  explicit empty value (`KEY=`) and a pass-through entry (`KEY`).

Source YAML/JSON is normalized into ordered maps before resolution. Unsupported
fields are diagnosed according to the selected `ComposeValidationMode` rather
than silently applied.

## Policy boundary

`ComposePolicy` makes the non-default behaviors explicit:

- `MergePolicy::Reject` (the default) accepts one document only. `LastWins`
  replaces services; `MergeServices` merges service environment maps.
- `IncludePolicy::Reject` (the default) rejects `include`. `CallerSupplied`
  accepts only documents explicitly supplied by the caller; the crate never
  opens an include path.
- `InterpolationMode::ExplicitValues` reads only an `InterpolationValues` map.
  There is no process-environment fallback. `$$` and Compose's `:-`, `-`,
  `:?`, `?`, `:+`, and `+` operators are handled without command substitution.
- `InterpolationMode::Disabled` rejects interpolation syntax.
- `ComposeValidationMode::Strict` is the safe default and rejects fields
  outside the bounded schema; `Default` also rejects those fields while
  ignoring `x-` extensions, and `Loose` ignores them after structural checks.

Go-template syntax remains invalid in the scalar interpolator. The optional
`templates` feature exposes `render_template`, which accepts the same ordered
`InterpolationValues` model used by the resolver (and the legacy typed-map
shape for helper-only callers). It uses only the public `neotales-gotmpl` and
safe `neotales-sprig` contracts, applies finite parse and render limits plus
cooperative cancellation, returns non-template source unchanged, and never
reads files, environment variables, credentials, or process state. Pass its
output to the existing normalized parser; the default feature set has no
template dependency.

## Dotenv boundary

`load_dotenv`, `load_dotenv_path`, and `load_dotenv_sources` delegate assignment
parsing to the source-preserving `neotales-dotenv` crate. They return a
`LoadedDotenv` document together with `InterpolationValues`, whose backing
store is the ordered, platform-aware `neotales-env::Environment`. `DotenvPolicy`
makes invalid-node handling, invalid-key handling, interpolation, and
`DotenvPrecedence` explicit. `InjectedWins` protects caller values;
`LastWins` lets later assignments and sources replace them. Single-quoted and
raw values remain literal, while unquoted and double-quoted values use the
selected explicit interpolation policy. `load_dotenv_path` is explicit I/O;
there is no implicit `.env` discovery and no process-global fallback. A leading
UTF-8 byte-order mark is removed, because that is what a `.env` last saved by a
Windows editor carries and it is an encoding signature rather than content.

`ComposeProjectOptions::env_files` supplies the bytes a service's `env_file` and
`label_file` name, and nothing here opens a file. Its key is the declared path
resolved against the declaring document's directory, spelled with `/` on every
platform; a key spelled with the running host's own separator is normalized the
same way, so one entry is found either way. On Unix a backslash is left alone,
because there it is an ordinary character in a filename.

## Values files

`parse_values` decodes a JSON or YAML values file into the structured map a
template is parameterized with, and `merge_values` layers one over another. Both
are behind the `templates` feature, which is off by default, so the example below is
not compiled as a doctest: a doctest cannot enable a feature of the crate it is
testing. It compiles and passes under `--all-features`.

```rust,ignore
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

Numbers, booleans, and nulls stay distinct from strings, so a template can tell
`3` from `"3"` and `{{ if .enabled }}` means a true boolean. A file whose top
level is not a mapping is rejected rather than merged under an invented key.

`template_root` builds the root a Compose template is rendered against: `.values`
is the merged values and `.env` is the environment, matching the reference's
`ComposeGotmpl.Render`. Both namespaces are always present.

## Example

```rust,no_run
use neotales_docker_compose::{
    ComposeDocument, ComposePolicy, ComposeResolver, InterpolationValues,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let document = ComposeDocument::parse_yaml(
    "services:\n  web:\n    image: ghcr.io/example/web:${TAG:-dev}\n    environment:\n      MODE: test\n",
    "compose.yaml",
)?;
let values = InterpolationValues::from_pairs([("TAG", "2026.09")]);
let resolved = ComposeResolver::resolve(&[document], &values, ComposePolicy::default())?;
println!("{}", resolved.to_json()?);
# Ok(())
# }
```

The checked-in fixtures under `rust/fixtures/compose/v1` exercise equivalent
YAML and JSON inputs, interpolation, pass-through environment entries, and
stable canonical output. Template integration tests cover safe helpers,
explicit Compose interpolation, limits/cancellation, the unchanged normalized
path, and rejection of environment access. No fixture contains a real secret.

## Lifecycle model, planner, and executor

The normalized `ComposeProject` adds the bounded local lifecycle fields needed
by a Compose adapter: services, dependency order, replicas, image pull/build intent,
ports, bind/volume/tmpfs mounts, networks, labels, and typed project name. The
source parser records bind paths but never opens them. `ComposePlanner` emits a
canonical, SHA-256-addressed plan with explicit pull/build/resource/container/
start/teardown operations, ownership labels, destructive markers, and
redaction-safe intent. `ComposeConfigRenderer` and `ComposeBridgeDocument` are
daemon-free projections; neither is a Kubernetes manifest or an Engine request.

`ComposeExecutor` is an operation-sink boundary rather than a second Docker
client. It checks cooperative cancellation before each operation and rolls back
only resources reported as created by the current invocation. The deterministic
`planner_executor` fixture records the exact operation order; callers can adapt
the sink to the public `neotales-docker` facade without exposing Bollard models.

## Applied runtime binding

`ComposeRuntime` is the inverse of the planner. A plan is redacted and
serializable, so it is the right artifact to print and diff but not the right
artifact to send: environment values, bind sources, and user labels are
`<redacted>` in a plan. `ComposeRuntime::bind` produces the concrete typed
values an Engine request needs — container image, argv, `NAME=value`
environment, exposed ports and publications, bind and tmpfs mounts, network
attachments with aliases, and unredacted labels — while staying free of any
daemon client. A caller maps these specs onto its own Engine facade.

Binding is where unsupported input is rejected, so no request is issued for a
service that cannot be created:

| Code | Rejected because |
| --- | --- |
| `compose_runtime_project_mismatch` | The plan and project describe different projects. |
| `compose_undeclared_network` | A service attaches to a network the project does not declare. |
| `compose_undeclared_volume` | A service mounts a volume the project does not declare. |
| `compose_external_volume_not_attached` | The attached slice does not create or mount external volumes. |
| `compose_bind_mount_requires_source` | A `type: bind` mount has no source. |
| `compose_runtime_unbound_operation` | A plan create operation has no request specification. |
| `compose_runtime_unplanned_network` | A container attaches to a network the plan does not create. |
| `compose_runtime_missing_image` | A service has no image. |

Every spec carries the Compose ownership labels
(`com.docker.compose.project`, `com.docker.compose.version`,
`com.neotales.compose.config-digest`); containers add the service,
container-number, oneoff, depends-on, and network labels. The exported label
key constants are `COMPOSE_PROJECT_LABEL`, `COMPOSE_SERVICE_LABEL`,
`COMPOSE_VERSION_LABEL`, `COMPOSE_CONFIG_DIGEST_LABEL`,
`COMPOSE_CONTAINER_NUMBER_LABEL`, `COMPOSE_ONEOFF_LABEL`, `COMPOSE_ONEOFF_VALUE`,
`COMPOSE_NETWORK_LABEL`, `COMPOSE_DEPENDS_ON_LABEL`, and
`COMPOSE_DEFAULT_NETWORK_KEY`.

`ComposePlanOptions::default_network` makes the planner create the implicit
`<project>_default` network that Compose attaches services without a declared
network to. The library default is `false`, so an explicitly modeled project is
planned exactly as written; a caller that executes containers against a daemon
enables it. `ComposePlanOptions::applied_create` and `applied_up` set it together
with the matching start behavior, and also apply the same flag in teardown plans
so `down` removes the default network.

`ComposeProject::select_services_with_dependencies` selects services together
with everything they require, in dependency order.
`ComposeProject::narrow` returns a project limited to those services and the
networks and volumes they reference, so an applied plan never creates an orphan.
Neither changes the project name, so ownership labels, Engine names, and the
configuration digest are unaffected.

`depends_on` conditions are normalized here, and a condition outside
`service_started`, `service_healthy`, and `service_completed_successfully` is
rejected with `compose_invalid_dependency_condition` at parse time rather than
normalized to something a caller would have to second-guess. The crate stays
daemon-free: it carries the condition on `ComposeDependency` and does not decide
when it is satisfied. A Compose adapter evaluates it by polling
`DockerClient::container_details` and gates the dependent container's create on
the result; see the Compose adapter's own documentation for the bounded-wait policy.

`ComposeExecutionError` carries a stable code, a safe message, and an optional
`raw` string for lower-layer text a caller may print in raw-error mode. The raw
text is never used to build the message.

## Bounded specification areas

The project intentionally diagnoses rather than silently applies areas outside
this local slice:

- profiles and profile-based service selection;
- attaching external networks or external volumes;
- build execution, so a `build` declaration only ever becomes plan intent here.
  The declaration is normalized in full (`context`, `dockerfile`, `target`,
  `platform`, `no_cache`, `pull`, `args`, `labels`, `cache_from`), and any
  BuildKit-only field it declares is recorded by name in
  `ComposeBuild::buildkit` rather than dropped, so an executor can refuse it
  explicitly instead of quietly building something else;
- filesystem or remote `include` expansion beyond caller-supplied documents;
- Swarm `deploy`/task semantics;
- configs, secrets, and credential-spec materialization;
- classic image-build request bodies and `BuildKit` session/negotiation, which
  belong to the `neotales-docker` image facade rather than to this model;
- develop/watch, extensions with engine semantics, and cross-project
  composition providers; and
- the full runtime host configuration surface (devices, capabilities, resource
  limits, health/readiness polling, and lifecycle hooks).

The small supported subset still has deterministic policy gates for host
paths, devices, privileged services, published ports, pulls, builds, and Docker
socket mounts. Callers must opt in to the corresponding gate before planning a
plan that contains that intent.
