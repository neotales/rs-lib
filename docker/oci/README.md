# `neotales-oci-distribution`

A small, transport-neutral OCI Distribution boundary for the Rust workspace.

The crate is deliberately separate from `neotales-docker`:

- registry references and upload locations are normalized without accepting
  URL user information or cross-origin upload locations;
- SHA-256/SHA-512 content digests and `Docker-Content-Digest` headers are
  verified fail-closed;
- manifest media types and `Accept` values are explicit and response bodies
  are bounded;
- basic and bearer credentials have their own provider and lifetime, with
  redacted `Debug`/`Display` implementations and zeroized secret storage;
- `LocalRegistryFixture` provides deterministic blob and manifest round trips
  without a daemon, network, Engine socket, or ambient Docker configuration.

The current slice is policy plus a local fixture.  HTTP transport, retry
policy, resumable uploads, mirroring, and Buildx/imagetools behavior are
intentionally separate follow-up work.  The crate must not reuse Engine
`X-Registry-Auth` state when that transport is added.

Run its local checks from `rust/`:

```sh
cargo fmt --all -- --check
cargo check -p neotales-oci-distribution
cargo test -p neotales-oci-distribution
cargo clippy -p neotales-oci-distribution --all-targets -- -D warnings
```
