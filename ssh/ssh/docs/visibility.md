# Public surface of `neotales-ssh`

This is the record the visibility ticket asked for: what the crate's public
surface is, why each module is in the state it is, and what was probably meant
to be public but is not.

## The measurement, and why the first one was wrong

Count it with:

```sh
export PATH="$HOME/.local/share/mise/installs/rust/1.98.1:$PATH"
ssh/ssh/tools/unreachable-pub.py --per-file
```

The tool exits non-zero if the library target is not zero, so it is usable as a
gate. It needs the pinned toolchain in `PATH`: the repository's
`rust-version` is 1.98 and the system cargo is older.

The measurement this note replaces was one number taken with
`cargo clippy --all-targets --all-features`, and it mixed two populations that
have nothing to do with each other.

**The library target** is the published surface. A `pub` there that nothing
outside the crate can reach is a claim about the API that is not true. That
count was **524** before this change and is **0** after it.

**The integration test targets** are not a published surface at all. Twenty-eight
of the files in `tests/` reach into the library with
`#[path = "../src/<file>.rs"] mod <name>;`, which recompiles those sources as
modules of the *test* crate under a private root. Every `pub` item in a file
included that way is genuinely unreachable — `pub` under a `mod`, not under
`pub mod` — and it says nothing about what a consumer can call. That population
was **2,004** items in a `--all-targets` run, and it is larger than the real one.

This is not a small correction. `sftp.rs`, `auth.rs`, `tcpip_forward.rs` and
`session.rs` were four of the five largest entries in the original per-file
table, at 257, 173, 157 and 129 items. None of them has a private submodule, so
all four contribute **zero** to the library count. The table that made this look
like a statement about which parts of the SSH implementation are finished was
mostly a statement about the test harness.

The test-target count cannot be driven to zero without replacing the `#[path]`
harness with something that cannot see private items, which would mean giving up
the white-box tests. That is a different change with a different trade-off, and
it is not a defect to fix. The tool reports it so it stays visible, and never
fails on it.

## What was changed, and why it cannot have changed the API

Every one of the 524 items rustc reported as `unreachable_pub` had its `pub`
rewritten to `pub(crate)`. Nothing else was touched.

`unreachable_pub` fires only when *every* path from the crate root to the item
is private. Narrowing an item the lint reported therefore cannot change what is
reachable from outside the crate: by the lint's own definition nothing reached
it. The list came from the compiler rather than from a judgement about each
line, which is what makes this a mechanical sweep that is also a no-op for
consumers.

| Module | Items | Why it is `pub(crate)` |
| --- | ---: | --- |
| `sequence` | 224 | Two items are public and re-exported at the crate root: `Direction` and `SequenceError`. The other 224 back the sequence state machine, which is driven by the transports and has no caller-facing surface. |
| `kex` | 176 | The key-exchange mechanisms, the transcript, the key derivation and `DerivedKeys`. None is nameable outside the crate today, and the ticket for the live session key already describes `kex` as internal. |
| `msg` | 107 | The KEXINIT codec and the algorithm catalogs. See "the one thing that is not a narrowing" below. |
| `cipher` | 17 | Packet protection. `PacketProtector` is reached through the transports, not by name. |
| `kex::dh_group16` | (in `kex`) | Included above. |
| `cipher` and the four `kex` mechanism modules | (in the above) | Included above. |

Grouping by module rather than by file: `kex` is 176 items across `mod.rs`,
`dh_group16.rs`, `mlkem768_x25519.rs`, `curve25519.rs` and `ecdh_p256.rs`, and
`msg` is 107 across `kexinit.rs` and `mod.rs`.

## Was anything here probably meant to be public?

Per module, honestly:

- **`sequence`** — no. `Direction` and `SequenceError` are the two the public
  rekey and transport-error APIs need, and they are already re-exported. The
  rest is state-machine internals. Nothing in this module looks like a type a
  consumer of an SSH-2 crate would name.
- **`cipher`** — no. It was already `pub(crate)` at the module root, so the
  `pub` on the items inside it was a lie about a module nobody could see. The
  crate's packet-protection story is "the transport protects packets", not "here
  is a protector you can construct".
- **`kex`** — no, and this is the clearest of the three. It is already
  `pub(crate)`, and the security review of the live session key reached the same
  conclusion independently. The KEXINIT proposal is the caller-facing part, and
  it lives in `msg`.
- **`msg`** — **this one is different, and the honest answer is "some of it,
  and it is already exposed".** See below.

Nothing was deleted to make a number look better. No item was moved, renamed, or
given a new signature, and no reachable item was narrowed.

## The one thing that is not a narrowing: `KexInit` is public and unnameable

`msg` is `pub(crate) mod msg`, and its own module documentation says the module
is "kept separate from the crate root until the crate-surface integration
ticket wires it into the public library API". That recorded intent is the reason
this module is treated differently from the other three, and it is still
accurate.

`KexInit` is already in the published API. `ClientConfig::with_kexinit` takes
one, `ClientConfig::kexinit` returns one, and `ServerConfig::with_kexinit` takes
one. So the crate hands a consumer a type it will not let them name, and the
constants that describe its fields are unreachable.

Two consequences, both measured rather than asserted:

- rustc **does not** report `pub struct KexInit` as `unreachable_pub`. Its
  reachability analysis counts an item used in the signature of a reachable item
  as reachable, so `KexInit` — and `NegotiatedAlgorithms` and `NegotiationError`,
  which appear in `KexInit::negotiate`'s signature — are part of the effective
  public API even though no module path names them. That is why the library
  count reaches zero without any widening, and it is also why a count taken from
  the lint alone would have understated the surface.
- Narrowing `KexInit` to `pub(crate)` — which the sweep would otherwise have
  done — fires `private_interfaces`:
  `type KexInit is more private than the item ClientConfig::kexinit`. It is
  therefore **not** a pure visibility change, and doing it would have turned a
  naming problem into a real API defect.

What this needs is the widening decision, which the visibility ticket puts out
of scope: re-export `KexInit`, `NegotiatedAlgorithms` and `NegotiationError`
from the crate root, so the type the API already hands out can be written down.
That is one type and its two collaborators, not the 107 items in `msg`. It has
not been done here, and the note exists so the next person does not have to
rediscover that the two are the same problem.

### The relationship to the algorithm-catalog ticket

The algorithm catalogs in `msg/kexinit.rs` were corrected in a separate change:
`SUPPORTED_*` is now what a handshake will accept and `KNOWN_*` is what the
codec recognises. Narrowing them to `pub(crate)` does not regress that, and the
argument there does not depend on them being public.

They are not meant to be public, and that is the decision, not an accident:

- A caller of an SSH-2 crate chooses between transports and ciphers through
  `ClientConfig` and `ServerConfig`. It does not choose algorithms by indexing
  a name catalog, and a public `SUPPORTED_*` slice would be an invitation to
  build a proposal the crate then refuses — which is exactly the defect that
  ticket corrected.
- The lists are the *internal* single source for the negotiation allowlist:
  `KexContext` and both `ProtectionPlan::from_algorithms` test against them.
  Publishing them would make a private invariant look like a supported
  configuration surface.

So the two tickets are one finding seen from two sides. The catalogs were wrong
whether or not a caller could read them, because `KexInit::new()` fed them
straight into a public constructor; that is fixed. They are unreachable now, and
that is correct rather than a leftover. The part of `msg` that *should* be
reachable is `KexInit`, and rustc agrees — it is the one item in the module the
narrowing sweep deliberately left alone.

## Warnings, before and after

| | Library target |
| --- | ---: |
| Before | 526 |
| After | 3 |

The 3 are pre-existing `missing_debug_implementations` on `ServerAuthenticator`,
`ClientAuthenticator` and `ScpClient`, which are in reachable modules and are
unrelated to visibility. No `private_interfaces` warning was introduced: that is
the check that the sweep did not narrow anything a public signature mentions.

## See also

- [`../README.md`](../README.md) — what the crate is.
- `tools/unreachable-pub.py` — the measurement, and the gate.
