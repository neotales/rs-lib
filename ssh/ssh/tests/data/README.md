# ML-KEM interoperability fixture

`Client-KEX-mlkem768x25519-sha256` is copied from the Go `x/crypto` SSH
regression fixture at commit `c96bba2ced58241e913463bed27fdb1f43ef21f4`:

<https://github.com/golang/crypto/blob/c96bba2ced58241e913463bed27fdb1f43ef21f4/ssh/testdata/Client-KEX-mlkem768x25519-sha256>

The fixture is a Go client/OpenSSH 9.9 server transcript. Its SHA-256 is
`700e87e980ae43c972dae155ea9ba2b77d6a8332067677c5f532ac4f9d30a7da`.

The Go x/crypto repository is distributed under the BSD 3-Clause license.
The fixture is retained here only as a regression vector for the SSH wire
format and hybrid exchange hash.

The `nist-mlkem768-*.bin` files are selected records from the NIST ACVP-Server
FIPS-203 corpus at commit
[`65370b861b96efd30dfe0daae607bde26a78a5c8`](https://github.com/usnistgov/ACVP-Server/tree/65370b861b96efd30dfe0daae607bde26a78a5c8/gen-val/json-files).
They are used only as known-answer primitive vectors: key generation `tgId=2,
tcId=26`; encapsulation `tgId=2, tcId=26`; and decapsulation `tgId=5`,
`tcId=88` (valid) and `tcId=86` (implicit rejection). The source JSON files
and their SHA-256 values are:

- `ML-KEM-keyGen-FIPS203/internalProjection.json`:
  `0fdca41ed30f49c828af80c73a6424ece3accc1e3430ae14492363aaadeb0e48`
- `ML-KEM-encapDecap-FIPS203/prompt.json`:
  `d4a2b990f08c3459f258f4d089e6de9eeaa0b6b7d2f6d9035afdff81dfc43b36`
- `ML-KEM-encapDecap-FIPS203/expectedResults.json`:
  `e1b498e941ba877c27d2a452c275b1832d461e5426a73f103da27e03b97e0542`

These are NIST ACVP-Server records, not CAVP response files. The decap
`tcId=86` record intentionally exercises FIPS 203 implicit rejection and must
return a shared secret rather than an error.

## License notice for the copied Go SSH transcript

The following notice applies only to `Client-KEX-mlkem768x25519-sha256`,
copied from Go `x/crypto`; it does not apply to Neotales code or the NIST vectors.
It is reproduced verbatim from the upstream
[LICENSE at the pinned commit](https://go.googlesource.com/crypto/+/c96bba2ced58241e913463bed27fdb1f43ef21f4/LICENSE).

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
