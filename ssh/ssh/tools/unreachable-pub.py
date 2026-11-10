#!/usr/bin/env python3
"""Count `unreachable_pub` items in `neotales-ssh`, separated by target.

Why this script exists
----------------------

The original measurement for this ticket was one number, taken with
`cargo clippy --all-targets --all-features`, and it was wrong in a way that
mattered. It mixed two completely different populations:

* the **library** target, where `pub` on an item nothing outside the crate can
  reach is a claim about the published API, and
* the **integration test** targets. Twenty-eight of the tests in `tests/` reach
  into the library with `#[path = "../src/<file>.rs"] mod <name>;`, which
  recompiles those source files as modules of the *test* crate, under a private
  root. Every `pub` item in a file included that way is genuinely unreachable —
  it is `pub` under a `mod`, not under `pub mod` — and it says nothing at all
  about the published surface. `sftp.rs`, `auth.rs`, `tcpip_forward.rs` and
  `session.rs` have no private submodules and contribute **zero** to the library
  count, yet each of them dominates the `--all-targets` number.

The two populations are reported separately here, because only the first is a
number anybody can act on. The second cannot be driven to zero without changing
the test harness, and it is not a defect.

What it measures
----------------

Distinct `file:line` of the primary span of each `unreachable_pub` diagnostic,
deduplicated across the lib and lib-test compilations of the same file. A raw
diagnostic count is roughly double, because every item is reported once for the
lib and once for the lib test.

Usage
-----

    tools/unreachable-pub.py [--manifest-dir DIR] [--json] [--per-file]

Exits non-zero if the library target is not zero, so it can be used as a gate.
The test-target count is reported but never fails the run: see above.

Toolchain: the repository pins `rust-version = 1.98`, and the system cargo is
older. `PATH` must contain the pinned toolchain.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import posixpath
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_CRATE = HERE.parent

# A diagnostic is only about this crate's own source. The workspace's other
# crates are compiled as dependencies and produce their own `unreachable_pub`
# warnings; counting those would put another area's debt in this crate's total.
# The path cargo emits is **workspace-relative and unnormalised**, and for a
# `#[path]`-included source file that is the *re-include* spelling rather than the
# file's real one: `ssh/ssh/tests/../src/auth.rs`, 28 distinct spellings across
# the test targets, none of which contains `neotales-ssh/src/`.
#
# This filter used to require that substring, so it matched nothing, collected
# nothing, and **exited 0 for every state of the repository** while clippy was
# emitting 3,643 diagnostics across those targets. `Cargo.toml` documented the
# tool as "not a working gate" because of exactly this. It matches on the
# normalised path now, so both spellings of one file are the file they are.
OWN_DIRECTORY = "/src/"


def is_own_source(file_name, crate):
    """True when `file_name` names a source file of `crate`, in any spelling.

    Normalises first, so `ssh/ssh/tests/../src/auth.rs` and `ssh/ssh/src/auth.rs`
    are one file. A `/src/` somewhere in the path is not enough on its own: the
    crate's own directory has to be in the path, or another crate's `src/` would
    be counted as this crate's.
    """
    normalised = posixpath.normpath(str(file_name).replace("\\", "/"))
    if OWN_DIRECTORY not in normalised:
        return False
    parts = normalised.split("/")
    if crate.name not in parts:
        return False
    return parts.index(crate.name) < len(parts) - 1


def cargo_clippy(crate: pathlib.Path) -> str:
    """Run clippy for the library target and return its JSON diagnostics."""
    env = dict(os.environ)
    # `cargo clippy` needs a writable target directory and will not accept a
    # second one through an env var, so the caller's tree is used as-is.
    result = subprocess.run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            str(crate / "Cargo.toml"),
            "--lib",
            "--all-features",
            "--message-format=json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if result.returncode != 0 and not result.stdout:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"cargo clippy failed: exit {result.returncode}")
    return result.stdout


def collect(crate: pathlib.Path) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Return (library-target items, lib-test items) as (file, line) pairs."""
    lib: set[tuple[str, int]] = set()
    lib_test: set[tuple[str, int]] = set()
    for line in cargo_clippy(crate).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line).get("message") or {}
        except json.JSONDecodeError:
            continue
        if (message.get("code") or {}).get("code") != "unreachable_pub":
            continue
        target = json.loads(line).get("target") or {}
        kind = target.get("kind")
        kind = kind[0] if isinstance(kind, list) and kind else kind
        for span in message.get("spans", []):
            if not span.get("is_primary"):
                continue
            name = span.get("file_name", "")
            if not is_own_source(name, crate):
                continue
            item = (name, span["line_start"])
            # `lib-test` is the same file compiled with the test harness; it
            # carries the same items as `lib` and is not a separate population.
            if kind == "lib-test":
                lib.add(item)
            else:
                lib.add(item)
    return sorted(lib), sorted(lib_test)


def collect_tests(crate: pathlib.Path) -> set[tuple[str, int]]:
    """Return the items that only exist in an integration test target."""
    env = dict(os.environ)
    result = subprocess.run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            str(crate / "Cargo.toml"),
            "--tests",
            "--all-features",
            "--message-format=json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if result.returncode != 0 and not result.stdout:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"cargo clippy --tests failed: exit {result.returncode}")
    found: set[tuple[str, int]] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = record.get("message") or {}
        if (message.get("code") or {}).get("code") != "unreachable_pub":
            continue
        target = record.get("target") or {}
        name = target.get("name")
        name = name[0] if isinstance(name, list) and name else name
        if name == crate.name.replace("-", "_"):
            continue
        for span in message.get("spans", []):
            if not span.get("is_primary"):
                continue
            file_name = span.get("file_name", "")
            if not is_own_source(file_name, crate):
                continue
            found.add((file_name, span["line_start"]))
    return found


def by_file(items: list[tuple[str, int]]) -> list[tuple[str, int]]:
    counts: collections.Counter[str] = collections.Counter(name for name, _ in items)
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-dir", type=pathlib.Path, default=DEFAULT_CRATE)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--per-file", action="store_true", help="list files and counts")
    parser.add_argument(
        "--skip-test-targets",
        action="store_true",
        help="only measure the library target, which is the fast path",
    )
    arguments = parser.parse_args()

    crate = arguments.manifest_dir.resolve()
    library, _ = collect(crate)
    test_only: set[tuple[str, int]] = set()
    if not arguments.skip_test_targets:
        test_only = collect_tests(crate) - set(library)

    report = {
        "library": len(library),
        "test_targets_only": len(test_only),
        "library_by_file": dict(by_file(library)),
        "test_targets_by_file": dict(by_file(sorted(test_only))),
    }

    if arguments.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"library target (the published surface): {report['library']}")
        print(f"test targets only (harness artefact):    {report['test_targets_only']}")
        if arguments.per_file:
            for name, count in report["library_by_file"].items():
                print(f"  {count:5d}  {name}")
            for name, count in report["test_targets_by_file"].items():
                print(f"  {count:5d}  {name}  (test targets only)")

    if library:
        print(
            "library target is not zero; see docs/visibility.md for the one item"
            " that is expected to remain and why",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
