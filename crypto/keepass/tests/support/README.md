# CLI integration-test support

`cli_support.rs` is a shared, test-only fixture module. A downstream command-line
front end includes it from its own `tests/` directory and maps every `Scenario`
to its real executable. The core-crate
`../cli_fixture_harness.rs` separately verifies that the disposable KDBX4 fixture
and byte-level scanner work without coupling the library tests to the app.

No sentinel vault is checked in. `CliFixture` creates a temporary vault with
distinct markers for the master password, entry password, username, notes,
protected custom field, OTP URI/seed, attachment bytes, key-file material, and
a missing-entry request. `find_leak` checks stdout and stderr as raw bytes and
also rejects generic `otpauth://` and `secret=` fragments. Failure assertions
identify only the channel and marker category, never the marker value.

When adding an app adapter:

1. Use `command(binary, fixture)` so the working directory and environment are
   isolated, then restore only required non-secret variables such as an absolute
   `XDG_CONFIG_HOME`.
2. Authenticate shared public-surface cases with `--password-stdin` or an
   explicit password environment name, never a real credential literal in argv.
   A focused compatibility test may use a disposable fixture password with
   `--password` to verify that scripting mode while scanning its output for
   disclosure.
3. Map every `Scenario` arm to a real command. The public suite requires help,
   list, context, and alias to succeed, and missing-entry, wrong-password, and
   corrupt-vault commands to fail.
4. Keep reveal commands out of `assert_public_surfaces`. For deliberate reveal
   tests, compare stdout only to the selected value and scan stderr separately;
   never include raw `Output` in panic messages because it may contain secrets.
5. Add `CliFixture::new(true)` coverage only when the CLI exposes a key-file
   credential source. The current CLI accepts password credentials only.

The app adapter intentionally does not set `HOME` after `env_clear`; it supplies
an absolute `XDG_CONFIG_HOME` so configuration behavior is deterministic and
cannot fall back to the test runner's home directory.
