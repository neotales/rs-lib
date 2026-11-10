# Test data

Everything in this directory is a **test vector**. None of it is a secret, and
none of it protects anything.

## `rsa-16384-test-vector.key` and `rsa-16384-test-vector.pub`

A 16384-bit RSA key pair, generated solely for this crate's test suite.

**This private key is not a secret and must never be treated as one.** It was
generated for the tests, it is not used by any system, and the corresponding
public key is committed beside it in plain text. Anyone who reads this directory
already has the whole key pair, so there is nothing to steal.

They are committed rather than generated during the test run because 16384-bit
RSA key generation takes around 30 to 40 seconds. Paying that on every test run
to avoid committing a key that is already published beside its public half would
be a bad trade.

They are regenerated whenever the committed pair is rotated. The old pair is not
removed from git history, which is the point: a private key that has been in a
published repository's history is burned, and pretending otherwise by quietly
replacing the file would be worse than saying so.

### Why the size

16384 bits is not arbitrary. `neotales-age` supports an RSA recipient, and a key
that large exercises a slow legacy path that a normal 2048- or 4096-bit test key
would never reach. A test that used a small key would pass while the path a user
is most likely to hit slowly stayed untested.

### What uses it

- `tests/rsa_16384.rs` — an encrypt-then-decrypt round trip. It asserts the
  plaintext comes back, and deliberately does not pin any expected ciphertext, so
  the pair can be rotated without touching the test.
- `src/ssh.rs`, in the unit test `accepts_16384_bit_rsa_pem_private_keys` — parses
  the OpenSSH private key form and checks the derived PKCS#1 and PKCS#8 PEMs both
  parse back.

If you need a key of this size for something else, generate your own. Do not
reuse this one, and do not add a real key to this directory.
