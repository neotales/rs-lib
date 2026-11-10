# SSH compatibility

This document describes interoperability evidence for `neotales-ssh`. A crate
test passing against its own fixtures is not evidence that another SSH
implementation accepts its output.

## Verified interoperability

These results were recorded in rust-libraries at 765e715; this repository's pipeline does not run those ignored lanes.

The live OpenSSH tests start the platform's system `sshd` and exercise this
crate as the SSH client. They cover protected packet exchange, channel behavior,
and public-key authentication. The current recorded results are:

| Platform | OpenSSH peer | Live lanes |
| --- | --- | ---: |
| Linux x86_64 | OpenSSH 10.5p1 | 16 |
| macOS 13.7.8 x86_64 | OpenSSH 9.0p1 | 16 |
| Windows Server 2025 x86_64 | Windows OpenSSH | 13 applicable |

The Windows count excludes three Unix-agent lanes. The crate's agent client uses
Unix-domain sockets; Windows named-pipe agent support is not implemented or
claimed. Windows identity coverage includes direct ECDSA-key authentication.
Current Windows discovery checks the in-box `%SystemRoot%\System32\OpenSSH`
location and the Win32-OpenSSH `%ProgramFiles%\OpenSSH` installation. Native
Windows tests confirm discovery and pass the 13 applicable live lanes.

An intermittent macOS identity failure was traced to a valid ECDSA scalar
encoded as a canonical short positive mpint. The parser now left-pads it to the
fixed scalar width, and a deterministic regression fixture covers the encoding.
After the fix, the full macOS live suite passed and 20/20 parallel identity
stress runs passed.

The five packet/handshake lanes include AES-GCM, AES-CTR with encrypt-then-MAC,
ChaCha20-Poly1305, and the ML-KEM hybrid key exchange. Seven live channel lanes
exercise real channel traffic. Identity lanes exercise ECDSA and Ed25519 keys,
and on Unix, real `ssh-agent` authentication.

## Not verified or not claimed

- **Reverse interoperability is not verified.** There is no current live test
  demonstrating a system OpenSSH client connecting to this crate's server.
- The Windows Unix-agent lanes are not applicable: Windows named-pipe agent
  transport is outside the crate's current implementation.
- These results are hand-verified on the listed machines, not a passing current
  Gitea three-platform CI matrix. See the repository's
  [`support matrix`](../../docs/support-matrix.md) for CI status and provenance.
- Other SSH implementations and versions are not implied by these OpenSSH runs.

## Running the live tests

The ordinary package test run keeps external-tool tests ignored. With `sshd`,
`ssh-keygen`, and (on Unix) `ssh-agent` and `ssh-add` installed, run:

```sh
cargo test -p neotales-ssh --all-features -- --include-ignored
```

The tool-discovery integration tests run without OpenSSH installed and report
which executable is missing when a live lane is explicitly run.
