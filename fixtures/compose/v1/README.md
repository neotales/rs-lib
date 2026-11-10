# Compose v1 bounded fixtures

These fixtures are deliberately small and daemon-free. `service-image-environment`
has equivalent YAML and JSON inputs; the test injects `TAG=2026.09`,
`RELEASE=stable`, and `CI=fixture`, then compares the canonical resolved JSON
with `service-image-environment.expected.json`.

The environment fixture covers both mapping and sequence syntax, an explicit
empty value, a pass-through entry, Compose fallback interpolation, and the
`$$` escape. No process environment is consulted.

`unsupported-service.yaml` is used to verify that the bounded schema diagnoses
unsupported service fields. `include-main.yaml` and `include-shared.yaml` are
used only with an explicit caller-supplied include map; the resolver never opens
these paths itself.

Opt-in template integration tests under the Compose crate cover safe
`neotales-gotmpl`/`neotales-sprig` helpers followed by explicit Compose
interpolation, as well as rejection of the unsupported `env` helper. The
`dotenv-quoting-order.env` fixture covers outer quotes, inline comments,
ordering, and Windows key spelling; `dotenv-invalid.env` covers malformed nodes
and invalid keys; and the two `dotenv-precedence-*.env` files cover explicit
layering. `lifecycle-plan.yaml` and `executor-calls.expected.json` exercise the normalized
local project, deterministic resource/service ordering, and the operation-sink
executor boundary without a daemon. They contain no credentials or secret
values.
