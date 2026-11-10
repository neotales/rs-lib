# neotales-docker-bake

Repository-native Docker Bake document parsing and target planning.

The default crate remains a bounded RD-006 slice. It provides:

- bounded, JSON-only Bake document parsing with strict unsupported-field
  rejection;
- ordered target and group declarations;
- target inheritance with deterministic map/list precedence;
- normalized context/Dockerfile defaults and simple declared Bake-variable
  substitution;
- group and named `target:` context graph validation; and
- an owned, dependency-first target selection graph.

The default crate intentionally does **not** depend on `neotales-docker` or
`neotales-docker-buildkit`. It does not contact a builder, inject a solver,
parse HCL, or convert Compose files. It can parse an explicitly selected dotenv
file through the repository-native input boundary, but never discovers a file
or reads the process environment implicitly. The opt-in `templates` feature
adds only the public `neotales-gotmpl` and safe `neotales-sprig` contracts; it
does not make the normalized JSON parser or planner require rendering.

## Supported JSON shape

The parser accepts Docker Bake's canonical JSON blocks. Variable objects may
carry a string `default`, `type` metadata, and `description`; complex variable
values and typed evaluation are deferred; simple string defaults are expanded
during normalization.

```json
{
  "variable": {
    "TAG": { "default": "latest" }
  },
  "group": {
    "default": { "targets": ["app"] }
  },
  "target": {
    "app": {
      "tags": ["example/app:${TAG}"],
      "platforms": ["linux/amd64"],
      "target": "runtime",
      "no-cache": true,
      "pull": true
    }
  }
}
```

The bounded target fields are `inherits`, `context`, `dockerfile`, `args`,
`labels`, `contexts`, `tags`, `platforms`, `target`, `no-cache`, `pull`, and
`description`. Other Bake fields are rejected rather than silently ignored.
`null` values in `args` and `labels` are retained as explicit Dockerfile-default
arguments.

## Opt-in templates

With the `templates` feature, `render_template` accepts a bounded explicit
source and typed caller values before the existing `parse_json` or
`parse_normalized_json` path. It returns source without a `{{` delimiter
unchanged, applies finite parse/render limits, and observes one cooperative
cancellation callback. Only deterministic safe helpers are available; process,
environment, filesystem, network, and credential helpers remain unsupported.

## Example

```rust
use neotales_docker_bake::{BakeError, parse_normalized_json};

fn example() -> Result<(), BakeError> {
    let document = parse_normalized_json(
        r#"{
            "target": {
                "base": {"context": ".", "dockerfile": "Dockerfile"},
                "app": {"inherits": ["base"], "tags": ["example/app:latest"]}
            },
            "group": {"default": {"targets": ["app"]}}
        }"#,
    )?;
    let graph = document.plan(&["default"])?;
    assert_eq!(graph.target("app").unwrap().dockerfile, "Dockerfile");
    Ok(())
}
```

`parse_and_plan` is a compact equivalent for callers that do not need to retain
an intermediate normalized document. The graph owns all resolved values and
contains no builder or session state.

## Dotenv boundary

`load_dotenv`, `load_dotenv_path`, and `load_dotenv_sources` use
`neotales-dotenv` for source-preserving assignment parsing and produce
`VariableValues` backed by the ordered, platform-aware
`neotales-env::Environment`. `DotenvPolicy` explicitly controls invalid nodes,
invalid environment keys, quote interpolation, and `DotenvPrecedence`:
`InjectedWins` protects caller values, while `LastWins` lets later assignments
and sources replace them. `load_dotenv_path` is explicit I/O; there is no
implicit `.env` lookup or process-global fallback. The same `VariableValues`
model is accepted by `normalize_with_values` and the opt-in template adapter.

Deterministic fixtures under `tests/fixtures` cover defaults, inheritance,
group/target selection, and inheritance, group, and named-context cycles. The
shared Compose dotenv fixtures additionally cover quoting, ordering,
precedence, interpolation, Windows key rules, invalid assignments, and
cancellation. Opt-in template tests additionally cover safe helpers, Bake
interpolation, bounded/cancelled rendering, unsupported network helpers, and
the unchanged non-template parser path.
