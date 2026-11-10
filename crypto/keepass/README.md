# neotales-keepass

Headless KeePass KDBX support for Neotales. The crate is intentionally free
of UI, clipboard, platform prompts, and configuration-provider concerns.

## Current status

The crate is under active development. It currently provides:

- bounded KDBX 3.0/3.1 and KDBX 4.0/4.1 reading, with strict header/hash/HMAC/checksum validation;
- bounded KDBX 3.1 writing with the format's AES-KDF/AES-CBC path and hashed blocks;
- KDBX 4.1 writing with AES-KDF, Argon2d, or Argon2id, AES-CBC or ChaCha20, and GZip or no compression;
- Argon2d/Argon2id reading, password and key-file credentials, and protected inner streams;
- ordered metadata/tree/attachment models, typed public-header custom data, XML import/export, path queries, merge strategies, and lossless-save blocking;
- HOTP/TOTP and the headless KeePassXC `otp` field adapter.

KDBX 3.1 writing is available through [`KdbxFile::save_kdbx3`]; KDBX 3.0 and KDBX 3 Argon2/ChaCha20 writing remain unsupported because they are not part of the selected KDBX 3 writer path. Argon2d/Argon2id writing is available for KDBX 4.1. Configuration-framework adapters and UI/platform integrations are intentionally outside this crate.

## Security

All untrusted lengths are bounded before allocation. KDBX4 authentication
happens before decryption, terminal framing is mandatory, and temporary
password/key material is zeroized. Errors contain only safe diagnostic
categories and never include secret values.

### Argon2 read and save limits

The default Argon2 ceilings are 1,048,576 KiB of total memory, 4096 passes,
and 64 lanes. The combined work ceiling is 16,777,216 KiB-passes.
Work is total memory in KiB multiplied by passes. Lanes do not multiply work.
Equality with each ceiling is allowed. Read and save check memory, time,
lanes, then work before Argon2 parameter construction or hashing.
`KdbxError::limit_detail()` returns `KdbxLimitDetail`, with a
`KdbxLimitParameter`, `actual`, and `maximum`. Other errors return `None`.

**Breaking-ish behavior change:** This changes the security policy for callers
that use defaults. The previous scalar ceilings were 65,536 KiB, 10 passes,
and 16 lanes. The new defaults
allow more memory and work per operation so ordinary vaults can open.
Services that process hostile input must select explicit, lower limits.
`KdbxWriteOptions` defaults are unchanged.

`ProtectedValue` follows the KeePass distinction between text-origin and
byte-origin values:

- `from_text` takes ownership of text and keeps it as a zeroizing `String`; it
  does not add another in-memory encryption layer.
- `from_bytes` is the safe default for byte-origin values and encrypts them
  with per-value ChaCha20 key/nonce material. `from_bytes_unprotected` is the
  explicit opt-out.
- `reveal_bytes` and `reveal_text` return crate-owned `SecretBytes` and
  `SecretString` values whose buffers are zeroized on drop. The
  `with_revealed_text`/`with_revealed_bytes` callback forms make that lifetime
  explicit.
- `SecretBytes::as_slice` and `SecretString::as_str` borrow the owned plaintext;
  callers should keep reveals short-lived and avoid copying them into ordinary
  strings or buffers. `with_revealed_bytes` supplies a mutable, temporary slice;
  `with_revealed_text` supplies a temporary `&str`. Neither is a pinning guard.
- `from_bytes_with_protection` accepts a `MemoryProtectionProvider`, allowing a
  Windows DPAPI implementation to be supplied without making this crate
  Windows-specific. The optional `neotales-keepass-platform` crate provides a
  feature-gated safe adapter for the native Windows API.

The core crate does not pin memory. `MemoryPinningPolicy` and
`MemoryPinningStatus` describe the contract for an optional platform provider:
`BestEffort` can report an unavailable/failed pin, while `Required` must fail
explicitly. The core never silently claims that a value is pinned. Optional
`mlock`/`VirtualLock` integration belongs in a platform-owned allocation and
must zeroize before unlocking; see the [platform integration
plan](../keepass-platform/README.md). `ProtectedValue` debug output is
redacted.

### Windows DPAPI provider boundary

The optional [`neotales-keepass-platform`](../keepass-platform/README.md)
crate supplies `WindowsDpapiProvider` behind `windows-dpapi`; on non-Windows
hosts its protect/unprotect calls return `PlatformUnavailable`. It protects the
stored byte representation, not revealed plaintext, and reports pinning as
disabled/not pinned. The safe wrapper does not promise
`CRYPTPROTECT_UI_FORBIDDEN`; applications needing that flag must review the
native dependency boundary before deployment.

## Development

From the repository's `rust` directory:

```sh
mise exec rust@stable -- cargo fmt --all -- --check
mise exec rust@stable -- cargo check -p neotales-keepass
mise exec rust@stable -- cargo test -p neotales-keepass
```

## API contract

`KdbxFile::load` and `KdbxFile::save` accept caller-owned `Read`/`Write`
streams; they do not open paths, prompt for credentials, access a key store,
or make assumptions about a UI. `KdbxCredentials` owns the password and
optional key-file/provider components for the duration of an operation. For
ordinary local files, `KdbxFile::open`/`save_default` provide concise forms
using the standard library limits and the selected KDBX 4.1 writer defaults.
Use the explicit `load`/`save` forms when selecting resource limits, KDF,
cipher, compression, or block sizes. `KdbxFile::open_with_credentials` and
`save_default_with_credentials` are the concise forms for key-file and custom
provider credentials.

```rust
use std::io::Cursor;
use neotales_keepass::{
    KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

let database = KeePassDatabase::default();
let limits = KdbxReadLimits::default();
let mut credentials = KdbxCredentials::password("password")?;

let mut bytes = Vec::new();
KdbxFile::save(
    &database,
    &mut bytes,
    &mut credentials,
    KdbxWriteOptions::default(),
    &limits,
)?;
let loaded = KdbxFile::load(Cursor::new(bytes), &mut credentials, &limits)?;
assert_eq!(loaded.root.id, database.root.id);
# Ok::<(), neotales_keepass::KdbxError>(())
```

The shortest password-only round trip is:

```rust
use std::io::Cursor;
use neotales_keepass::{KdbxFile, KeePassDatabase};

let database = KeePassDatabase::default();
let mut bytes = Vec::new();
KdbxFile::save_default(&database, &mut bytes, "password")?;
let loaded = KdbxFile::open(Cursor::new(bytes), "password")?;
assert_eq!(loaded.root.id, database.root.id);
# Ok::<(), neotales_keepass::KdbxError>(())
```

The synchronous API remains the canonical full-document API. It accepts
caller-owned `Read`/`Write` streams and `KdbxFile::load_with_cancellation`
checks before I/O, between bounded input chunks, and between decoding stages.
Blocking `Read`, KDF, cryptography, and XML parsing cannot be interrupted
mid-call; applications requiring responsive cancellation should run the
operation on a worker. The loader still buffers one bounded input document and
its decoded payload. The streaming/allocator work is tracked separately in
`../../../agents/work/keepass/009-streaming-and-interoperability.md`.

### Runtime-neutral async transport

`KdbxFile::load_async` and `KdbxFile::save_async` return ordinary
`std::future::Future` values and add no executor or async-runtime dependency.
The caller supplies a small `KdbxAsyncRead` or `KdbxAsyncWrite` transport
whose `poll_*` methods are genuinely non-blocking and arrange wakeups when
returning `Poll::Pending`. There is deliberately no blanket implementation
for `std::io::Read`/`Write`: the crate does not disguise a blocking transport
as an asynchronous one. The load future reads bounded input chunks through
`poll_read`, requires an observed EOF, and then applies the same truncation,
authentication, terminal-framing, cancellation, and resource-limit rules as the
synchronous loader. The save future encodes before submitting bytes, handles
partial `poll_write` results, and completes only after `poll_flush` succeeds.
A save is not transactional if its destination has accepted bytes before an
error or cancellation.

The future is runtime-neutral, not fully non-blocking CPU work: the existing
KDF, codec, decompression, and XML stages are synchronous and operate on the
complete bounded document. Moving those stages to an interruptible/incremental
pipeline requires the prerequisites already listed for selected-entry
streaming: incremental authenticated KDBX 4 block processing, incremental
ciphertext decryption, bounded decompression/XML consumption, and a
cancellation-aware KDF/credential boundary. Until that exists, applications
that need an executor thread to remain responsive during CPU work should
schedule the future on an application-owned worker; the transport itself is
never moved to a hidden runtime.

### Bounded streaming and selected-entry blocker (KDBX-801/802)

There is no selected-entry scan yet. `Kdbx4AuthenticatedBlockReader` now
provides the first bounded KDBX 4 primitive: it authenticates and releases one
block at a time, requires the terminal block, checks trailing bytes, and
enforces cancellation and resource limits. It intentionally does not decrypt,
decompress, parse XML, or retain a pending result. `find_entry_by_path` still
works only after `KdbxFile::load` has materialized the full database; limits
bound input and decoded payload size, not peak memory to a single entry. A
selected scan must advance the protected inner stream through skipped fields
and binaries, consume the terminal block and trailing bytes before returning
any result, and apply XML, decompression, attachment, and per-block limits
throughout the scan. KDBX 3 needs a separate checksum-aware path. The earlier
whole-pipeline streaming prototype was removed because it referenced a
nonexistent incremental AES-CBC decryptor and cancellation-aware KDF/credential
methods; the authenticated block reader is the bounded replacement.

The remaining async prerequisite is not a transport dependency. It is an
incremental, cancellation-aware KDF/credential and authenticated codec
pipeline that can suspend without retaining the complete document. The current
transport futures intentionally expose only the transport boundary; they do
not claim selected-entry memory bounds. Until the incremental pipeline is
implemented and tested, callers can use the async transport with an
application-owned worker for CPU work, or use `load_with_cancellation` on a
worker with application-owned limits and use `find_entry_by_path` on the
resulting document.

The blocking allocation chain is concrete: `file::load_with_cancellation`
reads the complete encrypted input into `input`; `wire::read_hmac_blocks`
concatenates every authenticated ciphertext block; `crypto::aes_cbc_decrypt`
(or the ChaCha20 branch) produces the complete plaintext; GZip expands into
another whole-payload buffer; `xml::parse_tree` retains every XML node and
text value before `parse_database` constructs every entry and attachment.
`max_input_bytes` and `max_decompressed_bytes` cap total documents, not peak
selected-entry memory. Returning an entry found by searching this model would
still scale memory with the entire database.

The smallest safe selected-entry path requires, in order:

1. A bounded header reader and KDBX 4 block reader that verifies each HMAC
   before releasing that block, checks block count/length and aggregate input,
   authenticates the empty terminal block, and rejects bytes after it. A
   separate KDBX 3 stream-start/hashed-block path is needed for KDBX 3 support.
2. Stateful incremental AES-CBC (including final padding validation) and
   ChaCha20 decryption, followed by bounded incremental GZip decoding and an
   inner-header/binary-pool reader. A new XML reader must consume skipped
   entries and protected fields in wire order so the inner stream stays aligned;
   a selected entry may reference an earlier binary in the pool. It must reject
   unsupported XML and enforce depth, text, binary, and decoded-byte limits
   even in skipped branches.
3. A pending result held until the *entire* file passes authentication, XML
   validation, terminal framing, and cancellation checkpoints. A selected
   entry requires a new per-entry size limit; the current `max_binary_bytes`
   permits the entire binary pool to be retained, so binary references
   additionally need a bounded spool or an explicit restriction.

`tests/selected_scan_prerequisites.rs` pins the current full-input/EOF,
terminal-HMAC, trailing-byte, and EOF-cancellation behavior on a multi-block
vault containing a matching entry. These are regression requirements for an
incremental implementation, **not** evidence that the current loader streams.

`KdbxFailureKind` is the stable classification to branch on. Error messages
are safe diagnostics; callers must not use them as a substitute for explicit
credential or integrity handling. Lower `KdbxReadLimits` values for services
processing attacker-controlled vaults and keep the defaults for local files.

## Security and compatibility boundary

- KDBX 4 header SHA-256, header HMAC, and every payload block are verified
  before decryption. A terminal empty block is mandatory, and trailing bytes
  are rejected.
- KDBX 3.0/3.1 reading uses the legacy stream-start and per-block SHA-256
  checks. KDBX 3.1 writing emits those same checks; it does not add KDBX 4
  header/payload HMACs to a KDBX 3 file.
- Header, KDF, decompression, block, XML-depth, XML-size, and binary-pool
  limits are checked before attacker-controlled allocations. DTDs and external
  entities are rejected.
- Password, composite, inner-stream, and protected-value buffers are zeroized
  on a best-effort basis. `ProtectedValue` intentionally does not claim that
  text is pinned or that an operating system can guarantee swapping behavior.
- Plain `KdbxXml` import/export is for unprotected values only. Protected KDBX
  values require a real KDBX inner stream; there is no plaintext fallback.
- This is not a full-fidelity KeePass implementation. KDBX 3.0 writing,
  challenge-response credentials, platform key stores, unknown extension
  preservation, and several schema fields remain unsupported or fail closed.
  The exact blockers and the bounded credential-provider seam are tracked
  against the crate rather than described here, because they move and a readme
  that lists them goes stale the first time one is closed.

### Support matrix (0.1.0)

| Capability | Read | Write |
| --- | --- | --- |
| KDBX 3.0/3.1 | Yes, bounded | 3.1 only |
| KDBX 4.0/4.1 | Yes, bounded | 4.1 only |
| AES-KDF | Yes | Yes |
| Argon2d / Argon2id | Yes | Yes, KDBX 4.1 |
| AES-CBC / ChaCha20 outer cipher | Yes | KDBX 4.1: yes; KDBX 3: AES only |
| GZip / no compression | Yes | Yes |
| Password / key-file credentials | Yes | Yes |
| Custom 32-byte credential providers | Yes, as a composite component | Yes, as a composite component |
| Challenge-response credentials | No built-in provider | No built-in provider |
| Unknown extensions | May load, if parseable | Lossless save blocked |

The checked-in external fixtures run on every test invocation.
`tests/cli_interop.rs` additionally opens the four KDBX 4.1
cipher/compression combinations, both KDBX 4.1 Argon2 variants, and both KDBX
3.1 compression variants, using a real `keepassxc-cli`.

Those three tests are `#[ignore]`d, so an ordinary `cargo test` does not require a
KeePass CLI to be installed — a consumer of this crate should not have to install
one. When the lane *is* invoked it fails rather than skips if the tool is missing.
There is deliberately no skip path: a lane that returns quietly when it cannot run
reports a pass it did not earn, and a green run that means "nothing was checked" is
worse than a red one that says why.

The lane is currently verified on Linux and Windows. It does not run on macOS,
where `keepassxc-cli` is not installable, and the support matrix records that
rather than rounding two platforms up to three.

See [`DEPENDENCIES.md`](DEPENDENCIES.md) for the direct dependency inventory,
license notes, and lockfile policy.

## Fuzzing and release gate

There is no fuzz package in this repository. The parsers are bounded and the
malformed-input corpus is covered by tests, but bounded is not the same as fuzzed,
and the area README records the fuzzing lane as one that does not run.

The gate is run from the repository root rather than from a per-crate release
record, so it is the same gate the rest of the workspace is held to:

```sh
cargo fmt --all -- --check
cargo test -p neotales-keepass
cargo clippy -p neotales-keepass --all-targets -- -D warnings
```

No toolchain is named in the command, which is deliberate: the version is pinned by
`rust-toolchain.toml` and enforced by `rust-version` in the workspace manifest, and a
copy of that number in a readme is a number that goes stale.
