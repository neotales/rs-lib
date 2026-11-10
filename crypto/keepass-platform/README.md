# neotales-keepass-platform

Optional, target-specific adapters for [`neotales-keepass`](../keepass).
The core `neotales-keepass` crate remains portable and contains no operating-system
FFI or `unsafe_code`.

## Windows DPAPI adapter

Enable the `windows-dpapi` feature to expose `WindowsDpapiProvider`:

```toml
[dependencies]
neotales-keepass-platform = { path = "...", features = ["windows-dpapi"] }
```

The provider implements the existing `MemoryProtectionProvider` hook:

```rust,ignore
use std::sync::Arc;

use neotales_keepass::ProtectedValue;
use neotales_keepass_platform::{DpapiScope, WindowsDpapiProvider};

let provider = Arc::new(WindowsDpapiProvider::with_entropy(
    DpapiScope::User,
    b"application-and-database-context".to_vec(),
));
let value = ProtectedValue::from_bytes_with_protection(
    b"secret".to_vec(),
    provider,
)?;
assert_eq!(value.reveal_bytes()?.as_slice(), b"secret");
# Ok::<(), neotales_keepass::KdbxError>(())
```

The revealed `SecretBytes` owns a zeroizing buffer; prefer a short-lived
`with_revealed_bytes` callback where possible. Neither reveal form pins the
plaintext. The provider's pinning policy/status are `Disabled`/`NotPinned`.

`DpapiScope::User` binds ciphertext to the current Windows account.
`DpapiScope::Machine` allows any local user to decrypt it and must be selected
intentionally. Entropy is optional, stable configuration context; it is not a
secret key and must be available when the value is unprotected. The provider
zeroizes its entropy copy on drop and does not expose entropy in `Debug` output.

On Windows, the adapter delegates to the `windows-dpapi` safe wrapper, which
calls `CryptProtectData`/`CryptUnprotectData` and releases the native output
allocation. The adapter bounds the input to DPAPI's 32-bit blob length and
keeps the decrypted temporary in a zeroizing buffer while ownership moves to
`SecretBytes`. On non-Windows targets, enabling the feature is useful for
configuration code but protection operations return the explicit
`MemoryProtectionError::PlatformUnavailable` error; they never fall back to a
different cipher.

The optional dependency is deliberately not enabled by default. Before using
it in a release, audit the pinned dependency and decide whether the
application requires additional native flags such as
`CRYPTPROTECT_UI_FORBIDDEN`; this adapter does not claim to enforce policy that
is not exposed by the selected safe wrapper.

## Pinning policy and integration plan

DPAPI protects a representation at rest. It does not make a revealed buffer
resident in RAM. The core exposes the portable
`MemoryPinningPolicy`/`MemoryPinningStatus` contract so a platform adapter can
report the distinction without changing the `protect`/`unprotect` hook.

## Memory pinning

Enable the `memory-pin` feature for `PinnedBytes`:

```toml
[dependencies]
neotales-keepass-platform = { path = "...", features = ["memory-pin"] }
```

On Unix, the feature calls `mlock`/`munlock` through `memmap2`'s safe wrapper
and uses `region` to determine the page size. On Windows and other non-Unix
targets, `Required` returns `PinningUnavailable` and `BestEffort` reports
`Unavailable`; no native pin is claimed. This crate still
has `forbid(unsafe_code)`, and the workspace `unsafe_code = "forbid"` lint is
unchanged. `nix` 0.31's `mlock` is an unsafe function, so it is not used.

`PinnedBytes` is not a `MemoryProtectionProvider`. The core hook returns
`SecretBytes`, which is a separately allocated `Vec`. Reporting that buffer as
pinned would be false. Callers that need a lock use `PinnedBytes::from_bytes`
or `PinnedBytes::with_bytes` and read the slice only while that value is alive.

The adapter follows the platform-owned lifecycle:

1. Allocate a page-aligned anonymous mapping owned by this crate. An ordinary
   `Vec` is never passed to `mlock`.
2. Round the length up to a whole page, refuse a mapping that is not
   exclusively page-aligned, and lock it before copying plaintext.
3. For `BestEffort`, report `Unavailable` or `Failed` and continue with a
   zeroizing unpinned buffer. For `Required`, return
   `MemoryProtectionError::PinningUnavailable` or `PinningFailed` and do not
   reveal plaintext.
4. `with_bytes` keeps the lock alive for the callback. On drop, the mapping is
   overwritten while the lock is still held, then unlocked. A failed Unix
   `munlock` leaks that mapping so it cannot be reused.
5. Pin requests above 64 MiB are rejected. `RLIMIT_MEMLOCK` and page rounding can
   still make a smaller request fail. Pinning is
   best effort against swap, not protection from a debugger, administrator,
   crash dump, or root-level process. An empty buffer is not locked, because
   `mlock` rejects a zero length.

Audit `memmap2` 0.9.11 and `region` 4.0.1 before enabling the feature in a
release. Windows requires a separately reviewed safe `VirtualLock` lifecycle
with observable unlock failure before it can claim native pinning; the
`region` 4.0.1 `LockGuard` only checks unlock failure with `debug_assert!`.

## Development

From the repository's `rust` directory:

```sh
cargo test -p neotales-keepass-platform
cargo test -p neotales-keepass-platform --features windows-dpapi
cargo test -p neotales-keepass-platform --features memory-pin
cargo clippy -p neotales-keepass-platform --all-targets --features memory-pin -- -D warnings
```
