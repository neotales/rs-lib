# neotales-ssh

An SSH-2 protocol implementation with key exchange, packet protection,
authentication, host-key handling, channels, and forwarding metadata. See the
crate documentation for its API and the shipped
[`docs/compatibility.md`](docs/compatibility.md) for the exact interoperability
claims and exclusions. The live OpenSSH lanes are ignored, this pipeline does not start sshd, and
reverse interoperability is not claimed.
