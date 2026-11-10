# neotales-docker-buildkit

Repository-owned BuildKit builder, solve, status, and cancellation boundaries.
The crate is separate from `neotales-docker`; this slice does not call Docker
Engine `POST /build` and does not depend on either `neotales-docker` or Bollard.

## First bounded slice

`BuildKitAdapterFixture` is a deterministic, checked-in-fixture-backed adapter.
It validates a solve's context bounds and replays versioned status JSON for one
exact builder endpoint. A solve cannot fall back to another builder when its
explicit endpoint does not match the adapter.

The public boundary includes:

- `BuilderSelection` with an explicit endpoint and no environment, Docker
  context, Buildx, or local Engine discovery;
- `SolveRequest` with a size-bounded, diagnostic-redacted context and a
  context-contained Dockerfile path;
- `SolveStatus` updates with one terminal completion, failure, or cancellation
  state; and
- `SolveCancellation`, where the caller requests cancellation and the adapter
  owns remote session cleanup and status delivery.

Dropping a `SolveHandle` requests cancellation. Cancellation is cooperative and
idempotent; a caller must not assume that requesting it synchronously tears
down a remote BuildKit session.

## Unsupported in this slice

The fixture adapter does not implement or claim support for:

- remote BuildKit sessions or session lifetime;
- cache import/export;
- cleartext HTTP/2 (h2c) transport;
- local context file walking or Dockerfile transfer;
- build arguments, secrets, credentials, SSH forwarding, named contexts, cache
  selectors, exporters, multi-platform solves, or Buildx behavior; or
- direct Engine `POST /build`.

Bollard 0.21.1's optional BuildKit support is intentionally not enabled yet.
Its current high-level driver consumes a solve and returns only a final result;
it does not expose a repository-owned status stream or cancellation handle, and
its session server task is detached from the solve result. Those limitations
do not compose into the cancellation ownership required here. A future adapter
must enable Bollard's BuildKit features only after fixture and disposable
BuildKit tests prove progress, session teardown, and cancellation semantics.

## Fixture use

```rust,no_run
use neotales_docker_buildkit::{
    BuildContext, BuildKitAdapter, BuildKitAdapterFixture, BuilderEndpoint, BuilderSelection,
    DockerfilePath, SolveRequest,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let builder = BuilderSelection::new(
    "contract-fixture",
    BuilderEndpoint::parse("https://builder.fixture:9443")?,
)?;
// `CARGO_MANIFEST_DIR` rather than a relative path, because this file is both the
// crate's front page and the crate's doctests, and those resolve `include_str!`
// against different directories.
let fixture = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/solve-success.json"));
let adapter = BuildKitAdapterFixture::from_json(builder.clone(), fixture)?;
let request = SolveRequest::new(
    builder,
    BuildContext::new(b"FROM scratch\n".to_vec())?,
    DockerfilePath::new("Dockerfile")?,
);
let mut solve = adapter.start_solve(request).await?;
while let Some(status) = solve.next_status().await {
    println!("{status:?}");
}
# Ok(())
# }
```
