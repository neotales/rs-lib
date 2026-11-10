# neotales-docker

Repository-native Docker Engine API access over Bollard 0.21.1. The
compatibility target is Docker Engine API v1.55.

That target has two halves, and they are not the same number:

| What | Version | Why that one |
| --- | --- | --- |
| The repository-owned transport in `raw` | **v1.55** | It encodes its own requests, so this is the version it can actually put on the wire. |
| Bollard 0.21.1's generated client | **v1.53** | Its models are generated against 1.53. Handing it 1.55 would claim model coverage of two versions' worth of new fields that the crate does not have. |

The two used to be one constant, derived from the other, which meant no call
site could say which it meant. They are separate now, and a test fails if they
are made equal again or if Bollard's is raised without a dependency upgrade.

## Conformance boundary for 1.54 and 1.55

Targeting 1.55 is a claim, and this is the other side of it: what 1.54 and 1.55
added that this crate does **not** implement. The list is not a caveat on the
ceiling, it is the ceiling's boundary. Nothing in it is a regression against
1.53, because moby's `v1.53.yaml` and `v1.55.yaml` differ only by addition — no
path, definition, field, or required member was removed across the two
versions, checked by diffing both documents key-by-key at every depth.

| Version | Added | This crate |
| --- | --- | --- |
| 1.54 | `GET /images/json` gains an `identity` query parameter, and each manifest summary gains an `Identity` member | not implemented: the owned list request does not send `identity` and no repository-owned model carries `Identity` |
| 1.54 | `POST /networks/{id}/connect` now applies the `MacAddress` in `EndpointSettings`, which the daemon had accepted and ignored since 1.44 | implemented by not needing to be: the owned connect body has always sent `MacAddress`, so the field becomes live rather than inert |
| 1.55 | `GET /images/{name}/attestations`, a new endpoint returning in-toto attestation statements filtered by `platform`, `type`, and `statement` | not implemented: no owned function reaches the endpoint and no model describes an `AttestationStatement` |
| 1.55 | `POST /containers/{id}/update` honours the per-device blkio members it had always accepted and ignored | not implemented and not reachable: `ContainerUpdateOptions` carries only `cpu_shares` and `memory` |

Two further 1.55 changes are documentation-only: a `StopTimeout` description
that now names the `default-stop-timeout` setting, and clarifications to the
`/secrets` and `/configs` filter documentation.

**The `MacAddress` row is a behaviour change, not a gap.** A caller who set
`mac_address` on a network connect and watched the daemon ignore it will, at
1.55, watch the daemon apply it. That is the daemon correcting a bug, and code
that measured "I asked for this MAC and got whatever the pool handed out" should
not be relying on it.

**Raising the path version does not raise the models.** Everything that goes
through Bollard is still converted from Bollard's 1.53 generated types, so a
1.54 or 1.55 response member has no typed home in this crate unless a
repository-owned *document* function returns it verbatim — for example
`raw::image_list_documents`, which hands back the daemon's own JSON. Reaching a
1.54/1.55 addition today means calling the endpoint yourself, not that this
crate offers it.

The crate exposes bounded Engine resource, stream, system, and context-archive
slices over the foundation: typed image list/inspect/history/tag/search/prune
values, network and volume operations, Swarm services/nodes/configs/secrets/tasks,
container and Swarm log streams, stats, daemon events, authenticated image
pull/push progress, image archive downloads, and safe Docker context TAR/ZIP
import/export. Bollard request, response, stream, and credential models are not
part of the public contract. `BuildKit`, `Compose`, `Bake`, `OCI`
Distribution, and environment policy remain separate concerns.

## Usage

```rust,no_run
use neotales_docker::DockerClient;

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
client.ping().await?;
let containers = client.list_containers().await?;
println!("{} containers", containers.len());
# Ok(())
# }
```

## Image resource slice

`DockerClient` exposes the repository-owned image operations
`list_images`, `inspect_image` (plus `inspect_image_with_options`),
`image_history` (plus `image_history_with_options`), `tag_image`,
`search_images`, `prune_images`, and `remove_image`. Results use
`ImageSummary`, `ImageInspect`, `ImageHistory`, `ImageSearchResult`, and
`ImagePruneResult`; their request/response conversions and all nested values
are private to the facade. Search and prune filters are ordered `BTreeMap`
values and are encoded as Docker's JSON filter query deterministically.
`ImageInspectOptions` and `ImageHistoryOptions` carry the v1.55 JSON-encoded
platform selector without exposing a Bollard OCI model. `ImageTagOptions` also
preserves the Engine `force` query flag, which is absent from Bollard 0.21.1's
generated tag option type; these omitted query fields are added through a
narrow request modifier.

Image inspection includes stable configuration, root-filesystem, storage-driver,
and local-metadata projections. Experimental OCI descriptors, manifest
summaries, and identity records remain outside the typed models — `Identity`
is a 1.54 addition, so it is named in the
[conformance table](#conformance-boundary-for-154-and-155) above rather than
carried here. The client's API ceiling is v1.55. That is a statement about the
path prefix the owned transport sends and about the request shapes it encodes;
it is **not** a claim that every field 1.54 or 1.55 defined is reachable through
a type in this crate, and it is not a claim about v1.56.

Build, load, and import request-body streams are not exposed by this slice.
The existing `export_image`/`export_images` methods provide bounded byte-stream
downloads used by save/archive clients, but the higher-level save/archive
writer contract remains open. Platform-specific image deletion is also still
unsupported: Bollard 0.21.1's generated nested `platforms` sequence is rejected
by its URL-form serializer and needs a documented transport/query extension or
fork decision.

`tests/engine_resources.rs` and `tests/image_operations.rs`, together with the
JSON files under `rust/fixtures/docker/engine/images/`, provide deterministic
local HTTP fixtures for response mapping, request paths, query encoding, and
Docker API errors. API failures are available as `Error::api_error()` with a
repository-owned status/message pair.

## Container list projection

`list_containers` and `list_containers_with_options` return repository-owned
`ContainerSummary` values. The projection carries container id, names, image and
image id, command, creation time, ports, daemon state, human-readable status,
and the container's `labels`. Bollard already decodes the daemon's `Labels`
object, so labels are projected into an ordered `BTreeMap<String, String>`
rather than a hash map: a caller that compares, hashes, or prints them gets the
same ordering every call, and a container with no labels projects to an empty
map. No existing field or behavior changes with the addition.

## Container readiness projection

`container_details` returns repository-owned `ContainerDetails`. Alongside the
existing `tty`, `exit_code`, `status`, and `ports`, the projection carries the
two fields a readiness decision needs, both read from the same daemon state so
one request answers the whole question:

- `health: Option<String>` is the daemon's health status, lowercased:
  `healthy`, `unhealthy`, `starting`, or `none`. It is `None` when the container
  has no health state at all, which is how a container without a healthcheck
  appears. That distinction is the point: a caller can tell "no healthcheck
  configured" apart from "the healthcheck has not reported yet" and refuse the
  first instead of waiting for a status that can never appear. An empty daemon
  spelling also projects to `None` so the value is never a bare empty string.
- `running: Option<bool>` is `State.Running`, or `None` when the daemon omits it.

Bollard's `ContainerState`, `Health`, and `HealthStatusEnum` models stay
private to this adapter, exactly like every other generated model. No existing
field or behavior changes with the addition. The Compose adapter in this repository is the
current consumer: it polls this projection to honor `depends_on`
`service_healthy` and `service_completed_successfully`.

## Network and volume resource slice

`DockerClient` exposes repository-owned `list_networks`, `inspect_network`,
`create_network`, `remove_network`, `connect_network`, `disconnect_network`, and
`prune_networks` operations. Network filters are ordered `BTreeMap` values and
are encoded as Docker's JSON filter query deterministically. IPAM, endpoint,
creation, label, and driver values are projected into repository-owned types;
daemon-specific service, peer, status, and cluster-volume objects are outside
this bounded slice.

`list_volumes`, `inspect_volume`, `create_volume`, `remove_volume`, and
`prune_volumes` provide the corresponding typed volume boundary, including
volume warnings, usage data, labels, driver options, and forced removal. The
conversion to Bollard request/response models is private, and API failures are
mapped through the same `Error::api_error()` status/message projection as the
image boundary. `tests/engine_resources_networks_volumes.rs` and the JSON files
under `rust/fixtures/docker/engine/networks/` and
`rust/fixtures/docker/engine/volumes/` cover request paths, deterministic
filter encoding, payload/response mapping, and daemon errors.

## Swarm and task slice

`DockerClient` owns repository-owned Swarm operations for initialization,
join/leave/unlock, inspection, metadata updates, service create/list/inspect/
update/rollback/remove, node list/inspect/update/remove, config and secret
CRUD, and task list/inspect. Service and task log methods return the same
caller-owned `DockerStream<ContainerLogFrame>` used by container logs. Filters
are `BTreeMap` values and are encoded in stable key order, so request fixtures
do not depend on Bollard's unordered filter maps.

Swarm, service, node, config, secret, and task response values use explicit
repository models. Flexible Engine specification members are represented as
ordered JSON values and are converted privately to Bollard's v1.53 models.
That conversion is a real limit, not a parenthetical: the Swarm path reaches
the daemon through Bollard, so it is pinned at 1.53 regardless of the crate's
1.55 ceiling, and a Swarm response member added in 1.54 or 1.55 would arrive as
an unmodelled JSON value rather than as a typed field. No Swarm change landed
in either version — the 1.54 and 1.55 additions are all image, network, and
container resource concerns — so nothing is lost here today, and the
[conformance table](#conformance-boundary-for-154-and-155) is where that would
be recorded if that stopped being true.
Secret creation accepts a redacted, zeroizing `SwarmSecretData`; secret bytes
are not retained in list or inspect responses. Update methods require the
version read by the caller and preserve a daemon `409 Conflict` as an API
error. Callers must inspect again and decide whether to retry; the facade does
not perform an implicit write/retry loop.

The client is capped at Engine API v1.55. The request fixtures assert the paths
and query encodings the owned transport produces at that version; they do not
assert anything about v1.56, and the fields that 1.54 and 1.55 added are
enumerated in the conformance table rather than implied. The `unlock` request
uses a narrow Bollard request modifier because
Bollard 0.21.1 does not publish a dedicated method; no independent Engine HTTP
client or shell fallback is used. `GET /swarm/unlockkey` is parsed by the CLI
but is explicitly rejected by this facade because Bollard 0.21.1 exposes no
public response-decoding method for that endpoint. It remains a documented
follow-up rather than a claim about an API version this crate does not target.

**v1.56 support is backlog work, after the alpha packages are shipped.** A daemon
may advertise a maximum above v1.55 (Docker Engine 29.8 advertises v1.56); that
does not raise this crate's ceiling. Before changing `API_VERSION`, audit the
v1.56 schema and behavior, implement the additions this facade claims to expose,
update the conformance table and fixtures, and verify against a daemon that
supports v1.56. The live ceiling tests deliberately distinguish the crate's cap
from a daemon's independently reported maximum.

Deterministic fixtures live in `rust/fixtures/docker/engine/swarm/`, and
`tests/swarm.rs` covers request paths, ordered filters, payloads, response
projection, streams, cancellation ownership, and version conflicts.

## Resource and registry slice

The facade exposes repository-owned plugin, registry-auth, local context, and
Docker-config credential boundaries in addition to network/volume and system
operations. Plugin list/inspect/enable/disable/remove/set, archive creation,
privilege lookup, install progress, upgrade, and push keep Bollard models
private. Registry authentication uses Engine v1.55 `POST /auth`; credentials
are bounded, redacted, and zeroized. `RegistryConfigStore` honors
`credHelpers` before `credsStore`, preserves unrelated config keys, and invokes
only validated `docker-credential-*` helpers directly. `ContextStore` handles
named context list/create/update/remove/use and delegates archive operations to
the bounded `ContextArchiveStore`.

The CLI resource parser covers network, volume, system, plugin, context, builder,
resource-specific prune, and registry login/logout. Non-interactive prune calls
require `--force`; interactive calls require an affirmative `y`. The explicit
`system prune` policy is confirmed but never composed into resource calls
because no Engine API version through v1.55 defines a daemon-wide
`/system/prune` endpoint.

## Streams

`logs`, `stats`, and `events` return a `DockerStream<T>` rather than a Bollard
stream. The handle owns the response body, implements the standard
`futures_core::Stream` trait, and also provides an inherent async `next`
method. It does not buffer: each poll yields at most one decoded item.

```rust,no_run
use neotales_docker::{ContainerLogsOptions, DockerClient};

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
let mut logs = client.logs(
    "demo",
    Some(ContainerLogsOptions {
        follow: true,
        stdout: true,
        stderr: true,
        ..Default::default()
    }),
);
while let Some(frame) = logs.next().await {
    let frame = frame?;
    println!("{:?}: {:?}", frame.stream, frame.payload);
}
# Ok(())
# }
```

Docker's multiplexed log frames remain separate and retain their source
(`Stdout` or `Stderr`); the eight-byte transport header is not exposed. Raw
TTY output is represented as `ContainerLogStream::Console` rather than being
misclassified as multiplexed stdout. Image pull/push progress is exposed as
`ImageStreamEvent`, and image archive downloads yield caller-owned byte chunks.

The response handle is independent of `DockerClient`: callers may drop the
client after creating it. Call `cancel()` or `close()` when a response is no
longer needed; dropping the handle has the same ownership behavior. Cancelling
drops the underlying response body, with immediate socket closure dependent on
the selected Hyper/Bollard transport. Transport and decode errors are returned
by `next()` rather than exposed as Bollard models.

The current facade exposes typed container attach and exec session boundaries
with caller-owned input/output handles. WebSocket and h2c upgrades remain
explicitly outside this slice and require their own transport/ownership
fixtures. Build/load request-body streams are implemented by the separate
bounded image-transfer boundary below. Bollard's decoder also owns the raw
multiplexed parsing, so malformed-frame handling is not reimplemented in this
facade.

## Registry-authenticated image streams

Registry credentials are never read from Docker configuration implicitly. A
caller can supply an owned `RegistryCredentials` value, use the synchronous
`RegistryCredentialProvider` boundary, or explicitly select the bounded
`DockerCredentialHelper` adapter:

```rust,no_run
use neotales_docker::{
    DockerClient, DockerCredentialHelper, ImagePullOptions,
    InMemoryRegistryCredentialProvider, RegistryCredentials,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = DockerClient::connect_local()?;
let mut provider = InMemoryRegistryCredentialProvider::new();
provider.insert(
    "registry.example",
    RegistryCredentials::new("alice", "password-from-caller-owned-storage"),
);
let mut pull = client.pull_image_with_provider(
    "registry.example/team/app",
    Some(ImagePullOptions {
        tag: Some("stable".to_owned()),
        ..Default::default()
    }),
    &provider,
)?;
while let Some(event) = pull.next().await {
    println!("{:?}", event?);
}
# let _ = DockerCredentialHelper::new("docker-credential-example", std::time::Duration::from_secs(1));
# Ok(())
# }
```

`pull_image_with_provider` and `push_image_with_provider` resolve the registry
from the image reference before constructing the stream. Explicit
`*_for_registry` variants are available when a local image name needs a
registry selected by the caller. The `*_with_credentials` methods provide the
same path for an already-owned value. `*_with_credential_helper` resolves the
helper asynchronously before opening the response; the helper receives its
action as a direct argument and registry/payload over stdin, with a validated
executable name, no shell, a timeout, bounded stdout, and redacted errors. None
of these methods stores credentials in the client or edits `config.json`.

The conversion to Bollard's registry-auth request type is private. Values
owned by this facade are zeroized when dropped, and secret values are never
placed in `Debug`, `Display`, or facade errors. Bollard receives only the
request-scoped serialized copy needed for `X-Registry-Auth`; the client does
not retain that copy. The returned value is still a
`DockerStream<ImageStreamEvent>`: it owns the response body, does not buffer
progress, and can be cancelled or dropped independently of `DockerClient`.

Bollard 0.21.1's public `create_image` and `push_image` methods accept an
optional registry credential and return an owned decoded stream, so this
authenticated path does not require a custom transport or fork. Bollard does
not expose a public hook for attaching credentials after a stream has been
constructed; consequently the facade resolves and validates credentials before
calling Bollard. That is the documented composition boundary, not an
additional credential store.


Network operations cover list, inspect, create, remove, connect/disconnect,
and resource-specific prune; volume operations cover list, inspect, create,
remove, and resource-specific prune. Image build, load, import, high-level
save/archive writing, and platform-specific delete are exposed by the bounded
image-transfer and image-operation boundaries. Cluster-volume objects and other
daemon-specific nested fields remain outside this slice. Attach and exec
sessions are typed and caller-owned; `resize_exec` resizes an exec pseudo-TTY
through repository-owned `ExecResizeOptions`. Container creation serializes
`ContainerHostConfig::umask` as the Engine `HostConfig.Umask` value through a
request modifier, because Bollard 0.21.1's generated host-config model has no
such field. The repository type carries the octal spelling a person writes
(`0022`) while the Engine declares a `uint32`, so the modifier sends a JSON
**number** (`18`); sending the string is rejected outright by Docker Engine
29.8.0, and a non-octal value is refused locally rather than becoming a `400`
about JSON types. WebSocket and h2c ownership are not claimed by this slice and
still require their own fixtures or a narrow extension/fork decision.

Bollard 0.21.1 is still configured with the v1.53 ceiling, and that is the whole
of what it is configured with: the 1.54 and 1.55 additions its models do not
carry are named in the
[conformance table](#conformance-boundary-for-154-and-155) above. The v1.55
ceiling on the owned transport does not reach Bollard's models, so nothing about
1.54 or 1.55 is implied by this crate's types — and nothing about v1.56 is
implied by its paths either.

Enable transport features as needed:

```toml
[dependencies]
neotales-docker = { path = "../lib/neotales-docker", features = ["ssh", "tls"] }
```

`connect_defaults` resolves `DOCKER_CONTEXT`, the Docker config current
context, `DOCKER_HOST`, and platform defaults through the repository-owned
resolver. Context-local TLS material is used when present, and contexts that
request `SkipTLSVerify` are rejected.

## Engine profiles

`EngineKind` and `EngineProfile` select which engine's Docker-compatible
endpoint is addressed. The selection is always explicit, from a caller option
or from `NDOCKER_ENGINE`; it is never inferred from which socket exists,
because Docker, Podman, and nerdctl are routinely installed side by side and
silently talking to the wrong engine is worse than failing.

```rust,no_run
use std::collections::BTreeMap;

use neotales_docker::{ContextResolver, EngineKind, EngineProfile};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let environment = BTreeMap::from([("NDOCKER_ENGINE".to_owned(), "nerdctl".to_owned())]);
let resolver = ContextResolver::new("/tmp/docker-config", environment);
let selection = resolver.resolve_for(EngineProfile::explicit(EngineKind::Nerdctl))?;
println!("{} {:?} {:?}", selection.profile.kind, selection.profile.source, selection.source);
# Ok(())
# }
```

`ContextResolver::resolve` uses the environment-selected profile, and
`ContextResolver::resolve_for` takes one explicitly. `ResolvedEndpoint` carries
the `profile` alongside the `source`, so a caller can always report both the
engine and the endpoint provenance.

Docker profile order, unchanged: `DOCKER_CONTEXT`, the current Docker context,
`DOCKER_HOST`, then the platform default. The two Docker-compatible service
profiles share one shape — an explicit `CONTAINER_HOST`, then an explicit
`DOCKER_HOST`, then the first declared service socket that exists:

| Order | Source | Podman | nerdctl |
| --- | --- | --- | --- |
| 1 | `CONTAINER_HOST` | The variable Podman itself honors. | An explicit override only: `nerdctl` itself addresses containerd through `CONTAINERD_ADDRESS`. |
| 2 | `DOCKER_HOST` | An explicit user override under every profile; this is how a Docker client is pointed at a Podman service socket. | The same explicit override; this is how a Docker client reaches a `nerdctl.sock`. |
| 3 | rootful socket | `/run/podman/podman.sock` | `/run/nerdctl/nerdctl.sock` |
| 4 | `$XDG_RUNTIME_DIR` socket | `$XDG_RUNTIME_DIR/podman/podman.sock` | `$XDG_RUNTIME_DIR/nerdctl/nerdctl.sock` |
| 5 | `UID` socket | `/run/user/<uid>/podman/podman.sock`; omitted when `UID` is not numeric. | `/run/user/<uid>/nerdctl/nerdctl.sock`; omitted when `UID` is not numeric. |

`podman_socket_candidates`/`podman_socket_sources` and
`nerdctl_socket_candidates`/`nerdctl_socket_sources` expose those orders without
probing anything. When no candidate exists, resolution fails with
`ContextError::PodmanSocketNotFound` or `ContextError::NerdctlSocketNotFound`
listing the probed paths. Neither ever falls back to a Docker socket, and a
non-Docker profile with a non-default `DOCKER_CONTEXT` fails instead of silently
using Docker context metadata.

`PathProbe` is the existence seam for platform discovery. The default probes
the real filesystem; `PathProbe::declared` treats an explicit set of paths as
existing, which is how `ContextResolver::new_with_probe` makes the Docker
platform default and both service candidate orders testable without `/run`
access, a daemon, or process-global state.

### What the Podman profile does not provide

Podman's Docker compatibility layer is a different conformance surface. The
repository rejects these Docker-only capabilities up front through
`EngineKind::unsupported_reason`, `EngineProfile::require`, and
`EngineProfile::rejection` instead of forwarding a request that can only fail
with a confusing daemon error:

| Capability | Why it is rejected |
| --- | --- |
| `EngineCapability::Swarm` | Services, nodes, tasks, configs, and secrets have no compatibility endpoints. |
| `EngineCapability::Stack` | `stack` deployment requires Swarm mode. |
| `EngineCapability::Plugin` | The Docker plugin manager endpoints are not implemented. |
| `EngineCapability::Checkpoint` | Container checkpoint endpoints are Docker-specific. |
| `EngineCapability::DockerContext` | Contexts are Docker CLI metadata under `DOCKER_CONFIG`. |
| `EngineCapability::DockerCredentialStore` | Docker keeps credentials in `config.json`, Podman in `auth.json`. |

Nothing else is claimed. Build, prune, system, and event behavior under the
Podman profile is unverified by this repository, and the v1.55 API ceiling,
TLS, SSH, proxy, and credential rules are identical for every profile. There is
no Libpod client here: this crate speaks the Docker-compatible API only.

### What the nerdctl profile does not provide

nerdctl's conformance surface rejects **fewer** capabilities than Podman's, and
the difference is grounded in nerdctl's own published documentation rather than
guessed. nerdctl's `docs/command-reference.md` has an "Unimplemented Docker
commands" section, and this profile rejects exactly what it lists:

| Capability | Verdict | Grounding |
| --- | --- | --- |
| `EngineCapability::Swarm` | rejected | "Swarm commands are unimplemented and will not be implemented: `docker swarm\|node\|service\|config\|secret\|stack *`." `task` is a Swarm-mode object with no `nerdctl` command. |
| `EngineCapability::Stack` | rejected | The same sentence includes `stack *`. |
| `EngineCapability::Plugin` | rejected | "Plugin commands are unimplemented and will not be implemented: `docker plugin *`." |
| `EngineCapability::DockerContext` | rejected | `docker context` is listed under "Others". A nerdctl endpoint is selected with an address or socket, not with context metadata. |
| `EngineCapability::Checkpoint` | **allowed** | nerdctl ships `nerdctl checkpoint create\|list\|remove`. |
| `EngineCapability::DockerCredentialStore` | **allowed** | nerdctl `docs/registry.md`: "nerdctl uses `${DOCKER_CONFIG}/config.json` for the authentication with image registries. `$DOCKER_CONFIG` defaults to `$HOME/.docker`." That is the same store this crate's caller writes. |

Nothing beyond that table is claimed. Whether a given `nerdctl.sock` provider
exposes `/build`, checkpoint, or system endpoints is unverified by this
repository, and the classic `POST /build` endpoint is not gated by this profile
at all. Also note that upstream `nerdctl` is a CLI for containerd and does not
ship a Docker-compatible API server: `/run/nerdctl/nerdctl.sock` and
`$XDG_RUNTIME_DIR/nerdctl/nerdctl.sock` are the locations documented by the
separate daemons that do, and this crate treats them as the profile's candidate
paths without verifying any one of those daemons.

The SSH path uses a repository-owned Hyper/OpenSSH transport and the remote
Docker CLI's `docker system dial-stdio` command. The connector restores the
`ssh://` scheme before `openssh` resolves the destination, so explicit ports
such as `ssh://deploy@example.test:2222` reach OpenSSH as `-p 2222`; it retains
identity-file handling and `StrictHostKeyChecking=accept-new` (normal OpenSSH
host-key acceptance, never `StrictHostKeyChecking=no`). Bollard 0.21.1's
built-in `Docker::connect_with_ssh` remains unsupported for non-default ports
because it strips that scheme before resolution; callers should use
`DockerClient::connect_ssh` for this facade.

Dropping or cancelling the stream terminates the local OpenSSH child, but the
public OpenSSH/Bollard API does not guarantee termination of the remote
`docker system dial-stdio` process. The hermetic port/argument fixture is in
`tests/ssh_port_characterization.rs`; the opt-in lifecycle tests are in
`tests/ssh_lifecycle.rs` and require disposable `NEOTALES_DOCKER_SSH_*` fixture
environment variables.

Registry credentials are supplied through a caller-owned
`RegistryCredentialProvider` or an explicit `RegistryCredentials` value; the
client does not read or persist Docker credential configuration implicitly.
Secret values are redacted and zeroized when owned by this facade. The
optional `DockerCredentialHelper` adapter executes only validated
`docker-credential-*` names without a shell and bounds its output and
lifetime.

The system facade exposes `info`, `disk_usage`, `events`, and the native
`prune_build_cache` operation. `DiskUsageOptions` and `EventOptions` preserve
the Engine query shape, including repeated `type` parameters and JSON-encoded
filters. `EventStream` owns the response body; call `next()` while consuming it
and call `cancel()` (or drop the handle) to release/cancel the response.

No Engine API version through v1.55 defines a daemon-wide `/system/prune`
endpoint, and
Bollard 0.21.1 does not expose one. This crate deliberately does not compose
container, image, network, and volume prune calls under a misleading system
method. Those resource-specific operations remain part of RD-003d, while
`prune_build_cache` maps only to Docker's `/build/prune` endpoint. Verbose
disk-usage entries are projected into repository-owned types; daemon-specific
nested fields are intentionally omitted.

`ContextArchiveStore` imports and exports Docker's root-level `meta.json` and
`tls/<endpoint>/<file>` archive layout. TAR export is deterministic; TAR and
ZIP import are both supported. The default limits bound entry count, individual
and total uncompressed size, physical container size, path length, and ZIP
compression ratio. `ContextArchiveLimits` can tighten those bounds for an
application.

```rust,no_run
use std::fs::File;
use neotales_docker::ContextArchiveStore;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let store = ContextArchiveStore::from_environment()?;
let mut archive = File::open("remote.dockercontext")?;
store.import("copied", &mut archive)?;
# Ok(())
# }
```

Import validates the complete entry table before extraction, rejects unsafe
paths, duplicates, links, and special entries, stages below the Docker
configuration root, and publishes metadata last. Existing unrelated Docker
configuration is untouched, TLS private keys are mode `0600` on Unix, and
path-based export uses a synced sibling temporary file followed by an atomic
rename. Proxy routing remains tracked as later RD-002 work.

## The owned raw backend (`raw`)

`neotales-docker::raw` is a second, repository-owned Engine client living behind
the same public facade. It exists because a concrete defect was identified in the
current dependency, not a hypothetical one:
Bollard `0.21.1` builds `"{scheme}://{host}/v{major}.{minor}{path}"` and then
calls `url::Url::join(path)`, which discards the version prefix it just added.
Every Engine path is rooted, so **no request ever carries the API version**, and
the facade's validated v1.55 ceiling does not reach the daemon.

The `raw` module is not wired into `DockerClient` and nothing in this repository uses it
yet. The production path is unchanged.

```rust,no_run
use neotales_docker::raw::{
    RawEngine, RawTarget, container_create, container_list, container_start, info, ping, version,
};
use neotales_docker::{ContainerCreateOptions, ContainerListOptions, ContainerStartOptions};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let engine = RawEngine::new(
    RawTarget::Unix("/var/run/docker.sock".into()),
    neotales_docker::API_VERSION,
);

// `/_ping` carries its answer in headers, so the owned client returns them
// typed instead of collapsing five capabilities into one string.
let capabilities = ping(&engine).await?;
println!("daemon API {:?}, swarm {:?}", capabilities.api_version, capabilities.swarm);

// Versioned paths: the daemon receives `/v1.55/info`, not `/info` -- the
// version is `API_VERSION`, so this line moves when the ceiling does.
let daemon = info(&engine).await?;
let _version = version(&engine).await?;

// The container lifecycle speaks the same versioned paths and decodes into the
// repository-owned models rather than generated ones.
let containers =
    container_list(&engine, &ContainerListOptions { all: true, ..Default::default() }).await?;
println!("{} containers", containers.len());
let created = container_create(&engine, &ContainerCreateOptions {
    image: "alpine:3.19".into(),
    name: Some("slice".into()),
    ..Default::default()
}).await?;
container_start(&engine, &created.id, &ContainerStartOptions::default()).await?;
# Ok(())
# }
```

## What the backend covers

Two vertical slices, matching the first two steps of the migration order in the
decision record:

| Operation | Request |
| --- | --- |
| `ping` | `GET /v{major}.{minor}/_ping`, answer read from the capability headers |
| `version` | `GET /v{major}.{minor}/version` |
| `info` | `GET /v{major}.{minor}/info` |
| `list` | `GET /v{major}.{minor}/containers/json?all=…&size=…&filters=…` |
| `create` | `POST /v{major}.{minor}/containers/create?name=…` with a JSON body |
| `start` | `POST /v{major}.{minor}/containers/{id}/start` |
| `stop` | `POST /v{major}.{minor}/containers/{id}/stop?signal=…&t=…` |
| `remove` | `DELETE /v{major}.{minor}/containers/{id}?v=…&force=…&link=…` |
| `wait` | `POST /v{major}.{minor}/containers/{id}/wait?condition=…` |

The container slice was verified end to end against Docker Engine 29.8.0 over a
Unix socket — create, start, list, stop, wait, remove, a `404` carrying the
daemon's message, and an escaped reference — not only against the fixtures in
`tests/raw_backend_containers.rs`.
Those results were recorded in rust-libraries at 765e715; this pipeline does not start a daemon or re-run that check.

What the slices guarantee, and how each is tested in
`tests/raw_backend_differential.rs` and `tests/raw_backend_containers.rs`:

- **Versioned paths.** `RawEngine::request_uri` prefixes the negotiated version
  and refuses a path that is not absolute rather than guessing at a target.
- **Bounded documents.** `RawResponse::document` refuses to buffer past
  `MAX_DOCUMENT_BYTES`, enforced per chunk rather than from `Content-Length`,
  since a streaming or dishonest response does not carry an accurate one.
- **Bounded records and multiplexed log frames.** `FrameStream::next_json` caps
  each assembled record at `MAX_RECORD_BYTES`; container and Swarm multiplexed
  log decoders refuse a declared payload over `MAX_FRAME_BYTES` before buffering
  it. Both defaults are 8 MiB. The log-frame bound applies only to multiplexed
  framing: TTY output has no declared frame length, and the decoder yields it by
  transport read rather than buffering the complete stream.
- **Unbounded streams are never buffered.** `RawResponse::into_frames` yields
  frames as they arrive.
- **Cancellation is ownership.** Dropping the response drops the body, which
  closes the socket so the daemon observes a disconnect, and aborts the driver
  task. No cancel message exists for the two ends to disagree about.
- **Engine errors keep the daemon's words.** A non-2xx status becomes
  `ErrorKind::Docker` with the status and message in `Error::api_error`, so
  `--raw-error` still prints what the daemon said. An unparsable error body falls
  back to the status rather than replacing the daemon's answer with a parsing
  complaint.
- **Reaching the daemon is a distinct failure.** `ErrorKind::Transport` separates
  "the request was valid and the daemon was never reached" from
  `ErrorKind::InvalidInput`.
- **No silent truncation.** `version` and `info` return the document as sent
  rather than a generated struct, so members this client does not know about are
  not dropped. The container operations project onto the existing
  repository-owned models, which are `snake_case` CLI output types rather than wire
  types; the wire spelling is confined to private `*Document` projections, and
  each is a separate rename because `ImageID`, `DeviceIDs`, `Type`, and
  `StatusCode` are not what a casing rule produces.
- **The container name is a query value.** Docker reads it from `?name=` and
  *silently ignores* a `Name` member in the create body: a create request
  carrying `"Name":"probey"` in the body answers
  `{"Id":...,"Warnings":[]}` for a container under a generated name, verified
  against Docker Engine 29.8.0. A name in the body is a container the caller
  cannot find again.
- **A `204` is a success, not an empty document.** `start`, `stop`, and `remove`
  answer `204` with no body. The body is read and discarded and never handed to
  a JSON decoder, so a successful lifecycle call is not reported as a parse
  failure.
- **A container reference stays inside one path segment.** `/` is a path
  separator, so an unescaped reference would silently address a different
  resource: `POST /containers/a/b/start` is a four-segment path. Every reference
  is percent-encoded into exactly one segment, `%` included, so a reference
  cannot smuggle an escape sequence either. An empty reference is refused before
  a connection is opened. This is a difference from Bollard `0.21.1`, which
  formats the path with `format!("/containers/{id}/start")` and escapes nothing.
- **The recorded request is reproducible.** `filters` is built from the ordered
  `BTreeMap` the repository model already uses, so the key order of the encoded
  JSON is the same on every run. The current dependency converts that map into a
  `HashMap` before serializing it, so its `filters` key order varies between
  runs of the same command.
- **A create member is validated, not forwarded.** A restart-policy name outside
  the Engine's `""`/`no`/`always`/`unless-stopped`/`on-failure` set, and a umask
  that is not octal, are refused as `ErrorKind::InvalidInput` rather than
  forwarded for the daemon to reject with a `400`.

One constraint is load-bearing and documented on `RawEngine::send`: **the
response body must be read on the runtime that made the call**, or on a task of
it. hyper's HTTP/1 client only reads the socket while its connection future is
being polled, and that future runs as a task on the calling runtime. An earlier
revision tried to own the connection inline to avoid this; it deadlocked on
`send_request` and then raced hyper's internals. The constraint is documented
rather than hidden.

## Where the container slice disagrees with the current facade

Recorded here rather than in a comment, because the two paths differ on the wire
for three members and a difference that is not written down reads as a bug:

| Member | Facade | Owned backend | Why |
| --- | --- | --- | --- |
| `HostConfig.Umask` | `"Umask": 18` (a number) | `"Umask": 18` (a number) | The Engine declares `uint32`, and `ContainerHostConfig::umask` carries the octal spelling a person writes (`0022`), so both paths convert it. The facade used to install a JSON string, which Docker Engine 29.8.0 rejects with `400 invalid JSON: json: cannot unmarshal string into Go struct field HostConfig.HostConfig.Umask of type uint32` — a create carrying a umask could not succeed. Found by running the real code against a real daemon and **fixed**; a non-octal umask is now rejected locally as `InvalidInput` instead of becoming a `400` about JSON types. |
| `platform` | always sent, defaulting to `platform=` | sent only when the caller set one | An unrequested parameter on every create request. The recorded create line is `POST /containers/create?name=web&platform=` through the facade and `POST /v1.55/containers/create?name=web` through the owned backend. |
| Container reference | interpolated into the path unescaped | percent-encoded into one segment | A reference containing `/` addresses a different path shape through the facade. |

Not implemented, and not claimed: TLS, SSH, and forward-proxy connections
(`RawTarget::Tcp` is plain TCP); streaming request bodies; any operation beyond
the table above (in particular `inspect`, `logs`, `stats`, `attach`, `exec`,
`prune`, `rename`, `kill`, `pause`, and `update` are not implemented, though
`wait` does block on the daemon's own connection rather than a stream). See the
decision record for the full list and the migration order.

## Open requirement: a per-request duplex factory

A caller that reaches a remote daemon over SSH and runs
`docker system dial-stdio` to do it. There is no way to express that today:
`RawTarget` has `Unix`, `NamedPipe` and `Tcp`, none of which can name a duplex
obtained out of band.

**The ask is a factory, not a stream, and the distinction is load-bearing.**
`RawEngine::send` calls `connect()` and then `exchange()`, and `exchange` runs a
fresh `hyper` HTTP/1.1 handshake per request and drops the stream. So a variant
holding one duplex would serve exactly one request and fail on the second.

What would unblock it is additive and small — a `RawTarget` variant carrying
something like

```text
Stream(fn() -> BoxFuture<'static, Result<Box<dyn Duplex>, Error>>)
```

That is a fragment of a variant rather than a compilable item, so it is marked
`text` and not run as a doctest. It describes an API that does not exist yet.

so `connect()` has something to call. It does not touch `exchange`, because
`exchange` is already correct for a per-request connection. The caller pays a
`dial-stdio` process per request, which is expensive and is an accepted cost on
the caller's side; connection pooling would be the larger change and is not being
asked for here.

Raised by the SSH client that drives this crate, which documents the
full contract. Not implemented here: this crate has another owner, and a
speculative patch to someone else's transport is worse than a written-down ask.
