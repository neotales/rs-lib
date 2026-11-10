# `neotales-x509`

X.509 certificate identifiers, parsing and generation, and the SSH wire
conversions for certificates and keys.

X.509 is a large and much-misunderstood format, and most of the difficulty is not
cryptographic: it is the identifier encoding, the wire format, and the several
places where a certificate is not quite DER. This crate is the certificate
surface built on `neotales-crypto`, which is where the algorithms live.

## What it covers

- **Certificate identifiers and names**, including the parsing that distinguishes
  a distinguished name from a string that merely looks like one.
- **Certificate parsing and generation**, with a bounded parser.
- **Public and private key encoding** for Ed25519, ECDSA on P-256, and RSA, in
  PKCS#8 and the OpenSSH encodings.
- **SSH wire conversions**, so a certificate or key can be carried in the format
  an SSH client expects rather than in DER.
- **The object identifiers** the format needs, exported as named constants and
  as an `oids` module, so a caller is not embedding `1.3.101.112` as a literal.

## What it does not do

- **No validation against a trust store.** It parses and generates; deciding
  whether to trust a certificate is a policy decision that belongs to the caller
  and to whatever policy library they already use.
- **No revocation.** Same reason. A CRL or an OCSP response is fetched by
  something that knows the network.
- **No I/O beyond reading a file the caller names.** Parsing takes bytes.
- **No algorithm implementation.** The algorithms are in `neotales-crypto`.

## What is verified, and what is not

Encoding and decoding of the supported key and certificate forms, including the
OpenSSH wire conversions, is covered by the crate's own tests on Linux, Windows
and macOS, with round trips and bounded parsing.

**Two things the area README names as gates are not running.** No test in this
repository invokes `ssh-keygen` or `ssh`, so the OpenSSH encodings have not been
demonstrated to interoperate with the tool that defines them, and no fuzzing runs
anywhere in this repository. The support matrix records the interoperation lane
as an exclusion. Because this crate exists to interoperate with other software,
that gap is worth more here than it would be elsewhere.

## Licence

MIT. See [LICENSE](../../LICENSE.md).
