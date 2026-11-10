# `neotales-age`

An implementation of the [age](https://age-encryption.org) v1 file encryption
format for Rust, in pure safe Rust with no external age binary.

age is designed to be hard to misuse. A file is encrypted to *recipients* and
decrypted by *identities*, the two are asymmetric, and the format has no way to
express "encrypt with this password" without also being explicit about how the
password is stretched.

## What it supports

- **X25519** native keys, the format's default.
- **Post-quantum hybrid recipients**, ML-KEM-768 with X25519, for data that has to
  stay confidential for longer than a discrete logarithm is assumed to hold.
- **Encryption-only tagged recipients** on P-256 and on the same hybrid, for a
  curve with different hardware support.
- **scrypt passphrases.**
- **SSH keys**, Ed25519 and RSA, so an existing `~/.ssh` identity works.
- **The binary STREAM payload and strict ASCII armor**, both implemented directly.
- **Plugins**, as the format specifies them.

It implements the format itself rather than wrapping another implementation, so
there is no second age process to agree with and no subprocess to sandbox.

## Example

```rust
use neotales_age::{AgeFile, AgeIdentity, AgeKey, AgeRecipient};

let key = AgeKey::generate()?;
let recipient = AgeRecipient::from_public_key(&key.public_key)?;
let identity = AgeIdentity::from_private_key(&key.private_key)?;

let encrypted = AgeFile::encrypt(b"a message", &[recipient])?;
assert_eq!(AgeFile::decrypt(&encrypted, &[identity])?, b"a message");
# Ok::<(), neotales_age::Error>(())
```

The identity is what decrypts and the recipient is what encrypts, which is the
point of the format: give somebody the public half and they can write to you
without being able to read what you wrote.

## What it does not do

- **It does not wrap another age implementation.** There is no subprocess, so
  there is also no interoperability layer to be surprised by.
- **It does not do streaming to a file path.** There are streaming reader and
  writer types, and opening the file is the caller's decision, because where a
  decrypted file lands is a decision with consequences.
- **It has no keyring integration.** An identity is something the caller supplies.
  Where it came from is not this crate's business.
- **It does not implement age plugins beyond loading and invoking them.**

## What is verified, and what is not

Round trips are covered by the crate's own tests on Linux, Windows and macOS:
native and hybrid keys, SSH keys, passphrases, the binary payload and the ASCII
armor, plus parser limits and the identity and recipient syntax the reference
tool's own test cases cover.

**Interoperation with a reference implementation is tested, in both directions.**
A container written here is decrypted by `rage`, and a container written by
`rage` is decrypted here, for both the binary form and the ASCII armor, on all
three platforms. The tool version is pinned in the area README.

**Fuzzing does not run.** The area README names a fuzzing lane over every parser
and there is no fuzz target in this repository. The parsers are bounded — they
enforce size limits and reject rather than allocate without bound — but bounded
is not the same as fuzzed, and the distinction is worth keeping.

## Licence

MIT. See [LICENSE](../../LICENSE.md).
