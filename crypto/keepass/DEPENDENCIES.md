# `neotales-keepass` dependency notes

The production crate is MIT-licensed and has no UI, network, filesystem, or
platform-crypto dependency. Direct dependencies are deliberately small,
permissively licensed building blocks; the KDBX framing and resource policy
remain in this crate.

| Dependency | Declared version | Role | Upstream license expression |
| --- | --- | --- | --- |
| `aes` | `0.9.2` | AES-256 and KDBX AES-KDF transforms | MIT OR Apache-2.0 |
| `argon2` | `0.6.0` | Argon2d/Argon2id KDFs | MIT OR Apache-2.0 |
| `base64` | `0.22` | KDBX XML UUIDs, protected values, and key files | MIT OR Apache-2.0 |
| `cbc` | `0.2.1` | AES-CBC with PKCS#7 padding | MIT OR Apache-2.0 |
| `chacha20` | `0.10.2` | Outer ChaCha20 and in-memory protection | MIT OR Apache-2.0 |
| `digest` | `0.11` | Hash/HMAC traits | MIT OR Apache-2.0 |
| `flate2` | `1.1` | GZip payload compression | MIT OR Apache-2.0 |
| `getrandom` | `0.3` | Operating-system entropy | MIT OR Apache-2.0 |
| `hmac` | `0.13.0` | KDBX block and header authentication | MIT OR Apache-2.0 |
| `quick-xml` | `0.42` | Bounded XML and key-file parsing | MIT |
| `salsa20` | `0.11` | KDBX inner protected stream | MIT OR Apache-2.0 |
| `sha1` | `0.11` | HMAC-SHA-1 for HOTP compatibility | MIT OR Apache-2.0 |
| `sha2` | `0.11` | SHA-256/SHA-512 KDBX primitives | MIT OR Apache-2.0 |
| `thiserror` | `2.0` | Typed, non-secret error categories | MIT OR Apache-2.0 |
| `time` | `0.3` | RFC3339 fallback for XML timestamps | MIT OR Apache-2.0 |
| `zeroize` | `1.9` | Best-effort cleanup of temporary key/secret buffers | MIT OR Apache-2.0 |

The optional `neotales-keepass-platform` crate additionally uses `zeroize`,
`memmap2 = 0.9.11` (MIT OR Apache-2.0; declared Rust 1.65), and
`region = 4.0.1` (MIT; declared Rust 1.98) for `memory-pin`. With
`windows-dpapi` on Windows it uses `windows-dpapi = 0.2.0` (MIT OR
Apache-2.0; no declared Rust version), which resolves `winapi = 0.3.9`
(MIT/Apache-2.0; undeclared), `anyhow = 1.0.104` (MIT OR Apache-2.0), and
`log = 0.4.34` (MIT OR Apache-2.0). The CLI interoperability test uses
workspace `tempfile = 3.27.0` as a dev dependency; it is not linked into the
published library.

These are direct-dependency notes, not a substitute for a transitive license
inventory. The workspace `Cargo.lock` is the release input and must be
reviewed whenever a dependency is updated. Run `cargo tree -p
neotales-keepass` and the organization's license/advisory scanner (for
example, `cargo deny` when installed) before publishing. No GPL KeePass
implementation is linked or vendored; interoperability fixtures are covered
separately by their provenance records.

## MSRV and lockfiles

The library inherits the workspace declaration of Rust 1.98 and edition 2024.
Keep the 1.85 build in the release gate, not only a newer stable build. A
fresh fuzz package has its own lockfile because it is intentionally outside the
workspace; its `libfuzzer-sys` dependency is test tooling and does not change
the production crate's MSRV. If a semver-compatible update raises a dependency
MSRV, pin it in the appropriate lockfile or update the declared MSRV and test
matrix together. The 1.85 check is also a language-feature gate: the public
model keeps a cached binary-pool length so its `const` accessors do not depend
on newer `const` `Vec` methods.

## Local audit (2026-09-24)

- `cargo tree -p neotales-keepass --edges normal` and the optional Windows
  graph (`cargo tree -p neotales-keepass-platform --features windows-dpapi
  --target x86_64-pc-windows-gnu --edges normal`) were inspected against the
  checked-in lockfile. The Windows-only branch includes `windows-dpapi 0.2.0`,
  `winapi 0.3.9`, `anyhow 1.0.104`, and `log 0.4.34`.
- Offline `cargo metadata --locked` license/MSRV inspection found no declared
  Rust version above 1.85 among the resolved KeePass/platform dependency
  closure. `adler2`, `miniz_oxide`, and `simd-adler32` do not declare
  `rust-version`, so the 1.85 build is still necessary. Available license
  expressions offer permissive choices; `unicode-ident` also requires
  Unicode-3.0, and some target-specific dependencies offer LGPL as an
  **alternative** to MIT/Apache-2.0. These are metadata observations, not a
  complete source-level license audit. The exact graph sizes, direct resolved
  versions, and the public API and MSRV review are maintained with the crate's
  internal review record, which is not part of the published package.
- `cargo-audit`, `cargo-deny`, and `cargo-license` were unavailable locally;
  no advisory database scan or automated transitive license policy check was
  performed. Run the organization's scanner before publication.
