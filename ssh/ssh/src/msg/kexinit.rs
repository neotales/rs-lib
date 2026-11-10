//! Algorithm names and the SSH `SSH_MSG_KEXINIT` message codec.
//!
//! `SSH_MSG_KEXINIT` is the first algorithm-negotiation message in an SSH
//! connection.  This module deliberately deals only with its RFC 4251 wire
//! representation and client-preference negotiation.  It does not perform key
//! exchange, packet protection, or host-key verification.
//!
//! It also owns the algorithm-name catalogs, and it is deliberate that they live
//! here rather than beside the mechanisms that consume them. A name-list has to
//! be encodable and decodable long before a mechanism exists to run it, so this
//! module distinguishes three different claims and names each one:
//!
//! | Constant | Claim |
//! | --- | --- |
//! | `SUPPORTED_*` | A KEXINIT built from these names completes a handshake. |
//! | `DEFAULT_*` | The order this crate proposes, drawn from the supported set. |
//! | `KNOWN_*` | Names this crate can encode, decode and recognise. |
//!
//! `KNOWN_*` being larger than `SUPPORTED_*` is the point, not an oversight: it
//! is what a peer may legitimately offer, and what a reader should consult before
//! assuming a name will be negotiated. An earlier version of this module used
//! `SUPPORTED_*` for the larger list, which made the public constants promise
//! mechanisms that both handshakes refuse.

use std::fmt;

use neotales_ssh::{Error, Reader, Writer};

/// The SSH message number for `SSH_MSG_KEXINIT`.
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;

/// The number of bytes in an SSH KEXINIT cookie.
pub(crate) const KEXINIT_COOKIE_LENGTH: usize = 16;

/// The number of name-list fields in an SSH KEXINIT message.
pub(crate) const KEXINIT_NAME_LIST_COUNT: usize = 10;

/// A short alias for [`KEXINIT_COOKIE_LENGTH`].
pub(crate) const COOKIE_LENGTH: usize = KEXINIT_COOKIE_LENGTH;

/// The Curve25519 SHA-256 key-exchange algorithm name.
pub(crate) const KEX_CURVE25519_SHA256: &str = "curve25519-sha256";

/// The libssh.org spelling of the Curve25519 SHA-256 key-exchange name.
pub(crate) const KEX_CURVE25519_SHA256_LIBCSSH: &str = "curve25519-sha256@libssh.org";

/// The NIST P-256 ECDH key-exchange algorithm name.
pub(crate) const KEX_ECDH_SHA2_NISTP256: &str = "ecdh-sha2-nistp256";

/// The NIST P-384 ECDH key-exchange algorithm name.
pub(crate) const KEX_ECDH_SHA2_NISTP384: &str = "ecdh-sha2-nistp384";

/// The NIST P-521 ECDH key-exchange algorithm name.
pub(crate) const KEX_ECDH_SHA2_NISTP521: &str = "ecdh-sha2-nistp521";

/// The 2048-bit Diffie-Hellman group 14 SHA-256 algorithm name.
pub(crate) const KEX_DIFFIE_HELLMAN_GROUP14_SHA256: &str = "diffie-hellman-group14-sha256";

/// The 4096-bit Diffie-Hellman group 16 SHA-512 algorithm name.
pub(crate) const KEX_DIFFIE_HELLMAN_GROUP16_SHA512: &str = "diffie-hellman-group16-sha512";

/// The ML-KEM-768 and X25519 hybrid key-exchange name.
pub(crate) const KEX_MLKEM768X25519_SHA256: &str = "mlkem768x25519-sha256";

/// The Ed25519 host-key algorithm name.
pub(crate) const HOST_KEY_SSH_ED25519: &str = "ssh-ed25519";

/// The RSA SHA-256 host-key algorithm name.
pub(crate) const HOST_KEY_RSA_SHA2_256: &str = "rsa-sha2-256";

/// The RSA SHA-512 host-key algorithm name.
pub(crate) const HOST_KEY_RSA_SHA2_512: &str = "rsa-sha2-512";

/// The ECDSA NIST P-256 host-key algorithm name.
pub(crate) const HOST_KEY_ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";

/// The AES-128 CTR packet-encryption algorithm name.
pub(crate) const ENCRYPTION_AES128_CTR: &str = "aes128-ctr";

/// The AES-256 CTR packet-encryption algorithm name.
pub(crate) const ENCRYPTION_AES256_CTR: &str = "aes256-ctr";

/// The AES-128 GCM packet-encryption algorithm name.
pub(crate) const ENCRYPTION_AES128_GCM_OPENSSH: &str = "aes128-gcm@openssh.com";

/// The AES-256 GCM packet-encryption algorithm name.
pub(crate) const ENCRYPTION_AES256_GCM_OPENSSH: &str = "aes256-gcm@openssh.com";

/// The OpenSSH ChaCha20-Poly1305 packet-encryption algorithm name.
pub(crate) const ENCRYPTION_CHACHA20_POLY1305_OPENSSH: &str = "chacha20-poly1305@openssh.com";

/// An alias for the OpenSSH ChaCha20-Poly1305 packet-encryption name.
pub(crate) const CHACHA20_POLY1305_OPENSSH: &str = ENCRYPTION_CHACHA20_POLY1305_OPENSSH;

/// An alias using the packet codec's `NAME` suffix convention.
pub(crate) const CHACHA20_POLY1305_OPENSSH_NAME: &str = ENCRYPTION_CHACHA20_POLY1305_OPENSSH;

/// The HMAC-SHA2-256 packet-integrity algorithm name.
pub(crate) const MAC_HMAC_SHA2_256: &str = "hmac-sha2-256";

/// The HMAC-SHA2-512 packet-integrity algorithm name.
pub(crate) const MAC_HMAC_SHA2_512: &str = "hmac-sha2-512";

/// The HMAC-SHA2-256 encrypt-then-MAC algorithm name.
pub(crate) const MAC_HMAC_SHA2_256_ETM_OPENSSH: &str = "hmac-sha2-256-etm@openssh.com";

/// The HMAC-SHA2-512 encrypt-then-MAC algorithm name.
pub(crate) const MAC_HMAC_SHA2_512_ETM_OPENSSH: &str = "hmac-sha2-512-etm@openssh.com";

/// The no-compression algorithm name.
pub(crate) const COMPRESSION_NONE: &str = "none";

/// The OpenSSH zlib compression algorithm name.
pub(crate) const COMPRESSION_ZLIB_OPENSSH: &str = "zlib@openssh.com";

/// The client OpenSSH extension-information marker.
pub(crate) const EXT_INFO_C: &str = "ext-info-c";

/// The server OpenSSH extension-information marker.
pub(crate) const EXT_INFO_S: &str = "ext-info-s";

/// The client strict-KEX marker.
pub(crate) const KEX_STRICT_C_V00_OPENSSH: &str = "kex-strict-c-v00@openssh.com";

/// The server strict-KEX marker.
pub(crate) const KEX_STRICT_S_V00_OPENSSH: &str = "kex-strict-s-v00@openssh.com";

/// An unprefixed alias for [`KEX_CURVE25519_SHA256`].
pub(crate) const CURVE25519_SHA256: &str = KEX_CURVE25519_SHA256;

/// An unprefixed alias for [`KEX_CURVE25519_SHA256_LIBCSSH`].
pub(crate) const CURVE25519_SHA256_LIBSSH: &str = KEX_CURVE25519_SHA256_LIBCSSH;

/// An unprefixed alias for [`KEX_ECDH_SHA2_NISTP256`].
pub(crate) const ECDH_SHA2_NISTP256: &str = KEX_ECDH_SHA2_NISTP256;

/// An unprefixed alias for [`KEX_ECDH_SHA2_NISTP384`].
pub(crate) const ECDH_SHA2_NISTP384: &str = KEX_ECDH_SHA2_NISTP384;

/// An unprefixed alias for [`KEX_ECDH_SHA2_NISTP521`].
pub(crate) const ECDH_SHA2_NISTP521: &str = KEX_ECDH_SHA2_NISTP521;

/// An unprefixed alias for [`KEX_DIFFIE_HELLMAN_GROUP14_SHA256`].
pub(crate) const DIFFIE_HELLMAN_GROUP14_SHA256: &str = KEX_DIFFIE_HELLMAN_GROUP14_SHA256;

/// An unprefixed alias for [`KEX_DIFFIE_HELLMAN_GROUP16_SHA512`].
pub(crate) const DIFFIE_HELLMAN_GROUP16_SHA512: &str = KEX_DIFFIE_HELLMAN_GROUP16_SHA512;

/// An alias for [`KEX_MLKEM768X25519_SHA256`].
pub(crate) const MLKEM768X25519_SHA256: &str = KEX_MLKEM768X25519_SHA256;

/// An unprefixed alias for [`HOST_KEY_SSH_ED25519`].
pub(crate) const SSH_ED25519: &str = HOST_KEY_SSH_ED25519;

/// An unprefixed alias for [`HOST_KEY_RSA_SHA2_256`].
pub(crate) const RSA_SHA2_256: &str = HOST_KEY_RSA_SHA2_256;

/// An unprefixed alias for [`HOST_KEY_RSA_SHA2_512`].
pub(crate) const RSA_SHA2_512: &str = HOST_KEY_RSA_SHA2_512;

/// An unprefixed alias for [`HOST_KEY_ECDSA_SHA2_NISTP256`].
pub(crate) const ECDSA_SHA2_NISTP256: &str = HOST_KEY_ECDSA_SHA2_NISTP256;

/// An unprefixed alias for [`ENCRYPTION_AES128_CTR`].
pub(crate) const AES128_CTR: &str = ENCRYPTION_AES128_CTR;

/// An unprefixed alias for [`ENCRYPTION_AES256_CTR`].
pub(crate) const AES256_CTR: &str = ENCRYPTION_AES256_CTR;

/// An unprefixed alias for [`ENCRYPTION_AES128_GCM_OPENSSH`].
pub(crate) const AES128_GCM_OPENSSH: &str = ENCRYPTION_AES128_GCM_OPENSSH;

/// An unprefixed alias for [`ENCRYPTION_AES256_GCM_OPENSSH`].
pub(crate) const AES256_GCM_OPENSSH: &str = ENCRYPTION_AES256_GCM_OPENSSH;

/// An unprefixed alias for [`ENCRYPTION_CHACHA20_POLY1305_OPENSSH`].
pub(crate) const CHACHA20_POLY1305: &str = ENCRYPTION_CHACHA20_POLY1305_OPENSSH;

/// An alias using the `cipher` category prefix.
pub(crate) const CIPHER_CHACHA20_POLY1305_OPENSSH: &str = ENCRYPTION_CHACHA20_POLY1305_OPENSSH;

/// An unprefixed alias for [`MAC_HMAC_SHA2_256`].
pub(crate) const HMAC_SHA2_256: &str = MAC_HMAC_SHA2_256;

/// An unprefixed alias for [`MAC_HMAC_SHA2_512`].
pub(crate) const HMAC_SHA2_512: &str = MAC_HMAC_SHA2_512;

/// An unprefixed alias for [`MAC_HMAC_SHA2_256_ETM_OPENSSH`].
pub(crate) const HMAC_SHA2_256_ETM_OPENSSH: &str = MAC_HMAC_SHA2_256_ETM_OPENSSH;

/// An unprefixed alias for [`MAC_HMAC_SHA2_512_ETM_OPENSSH`].
pub(crate) const HMAC_SHA2_512_ETM_OPENSSH: &str = MAC_HMAC_SHA2_512_ETM_OPENSSH;

/// An unprefixed alias for [`COMPRESSION_NONE`].
pub(crate) const NONE: &str = COMPRESSION_NONE;

/// An alias for [`COMPRESSION_ZLIB_OPENSSH`].
pub(crate) const ZLIB_OPENSSH: &str = COMPRESSION_ZLIB_OPENSSH;

/// An alias using the packet codec's `NAME` suffix convention.
pub(crate) const COMPRESSION_ZLIB_OPENSSH_NAME: &str = COMPRESSION_ZLIB_OPENSSH;

/// A short alias for [`KEX_CURVE25519_SHA256_LIBCSSH`].
pub(crate) const KEX_CURVE25519_SHA256_LIBSSH_ORG: &str = KEX_CURVE25519_SHA256_LIBCSSH;

/// An alternate identifier for the libssh.org Curve25519 name.
pub(crate) const KEX_CURVE25519_SHA256_LIBSSH: &str = KEX_CURVE25519_SHA256_LIBCSSH;

/// An alternate identifier that retains the libssh.org domain in its name.
pub(crate) const KEX_CURVE25519_SHA256_LIBCSSH_ORG: &str = KEX_CURVE25519_SHA256_LIBCSSH;

/// An alternate short identifier for the client strict-KEX marker.
pub(crate) const KEX_STRICT_C_V00: &str = KEX_STRICT_C_V00_OPENSSH;

/// An alternate short identifier for the server strict-KEX marker.
pub(crate) const KEX_STRICT_S_V00: &str = KEX_STRICT_S_V00_OPENSSH;

/// An alias using the OpenSSH `hostkey` spelling.
pub(crate) const HOSTKEY_SSH_ED25519: &str = HOST_KEY_SSH_ED25519;

/// An alias using the OpenSSH `hostkey` spelling.
pub(crate) const HOSTKEY_RSA_SHA2_256: &str = HOST_KEY_RSA_SHA2_256;

/// An alias using the OpenSSH `hostkey` spelling.
pub(crate) const HOSTKEY_RSA_SHA2_512: &str = HOST_KEY_RSA_SHA2_512;

/// An alias using the OpenSSH `hostkey` spelling.
pub(crate) const HOSTKEY_ECDSA_SHA2_NISTP256: &str = HOST_KEY_ECDSA_SHA2_NISTP256;

/// An alias using the `cipher` category prefix.
pub(crate) const CIPHER_AES128_CTR: &str = ENCRYPTION_AES128_CTR;

/// An alias using the `cipher` category prefix.
pub(crate) const CIPHER_AES256_CTR: &str = ENCRYPTION_AES256_CTR;

/// An alias using the `cipher` category prefix.
pub(crate) const CIPHER_AES128_GCM_OPENSSH: &str = ENCRYPTION_AES128_GCM_OPENSSH;

/// An alias using the `cipher` category prefix.
pub(crate) const CIPHER_AES256_GCM_OPENSSH: &str = ENCRYPTION_AES256_GCM_OPENSSH;

/// An alias using the `mac` category prefix.
pub(crate) const MAC_SHA2_256: &str = MAC_HMAC_SHA2_256;

/// An alias using the `mac` category prefix.
pub(crate) const MAC_SHA2_512: &str = MAC_HMAC_SHA2_512;

/// An alias using the `mac` category prefix.
pub(crate) const MAC_SHA2_256_ETM_OPENSSH: &str = MAC_HMAC_SHA2_256_ETM_OPENSSH;

/// An alias using the `mac` category prefix.
pub(crate) const MAC_SHA2_512_ETM_OPENSSH: &str = MAC_HMAC_SHA2_512_ETM_OPENSSH;

/// The key-exchange names a handshake in this crate will accept.
///
/// This is the single source of truth for that set. `kex::KexContext` validates a
/// negotiated name against the [`SUPPORTED_KEX_ALGORITHMS`] subset it is
/// routed through, the client and server handshakes build their proposals from
/// the same names, and `tests/kexinit.rs` fails if any of those drift from this
/// list.
///
/// It is deliberately *not* every name this crate recognises. A KEXINIT whose
/// key-exchange list is [`KNOWN_KEX_ALGORITHMS`] but not this one can be encoded,
/// decoded and negotiated, and will then be refused — which is why the two
/// constants have different names and different documentation.
///
/// The list is a proposal, not a ranking: preference order lives in
/// [`DEFAULT_KEX_ALGORITHMS`].
pub(crate) const SUPPORTED_KEX_ALGORITHMS: &[&str] = &[
    KEX_MLKEM768X25519_SHA256,
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
];

/// The host-key names a handshake in this crate will accept.
///
/// As with [`SUPPORTED_KEX_ALGORITHMS`], this is the single source of truth: both
/// handshakes test the negotiated name against it in
/// `ProtectionPlan::from_algorithms`, rather than comparing against one
/// hard-coded name.
///
/// `ssh-ed25519` is the only entry, and that is a deliberate statement rather
/// than an omission. `rsa_hostkey.rs` and `ecdsa_hostkey.rs` are complete,
/// tested RSA and ECDSA P-256 implementations, and
/// [`KNOWN_HOST_KEY_ALGORITHMS`] records that they exist. Neither handshake can
/// reach them, because both are hard-wired to Ed25519 for host-key signing and
/// verification. Adding RSA or ECDSA to this list would advertise a mechanism
/// that is then refused, which is the exact failure this list was corrected to
/// stop; widening what a handshake accepts is a security-posture decision that
/// belongs with the host-key work, not with this correction. See the `ssh`
/// host-key reachability ticket.
pub(crate) const SUPPORTED_HOST_KEY_ALGORITHMS: &[&str] = &[HOST_KEY_SSH_ED25519];

/// Every key-exchange name this crate recognises.
///
/// A strict superset of [`SUPPORTED_KEX_ALGORITHMS`]. These are the names of the
/// SSH algorithm series that the KEXINIT codec can encode, decode and negotiate;
/// proposing one of them does not mean a handshake can complete with it.
///
/// `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521` and
/// `diffie-hellman-group14-sha256` have no mechanism in `kex/` at all, and the
/// hybrid `mlkem768x25519-sha256` mechanism is driven by a codec of its own.
/// The list is kept because the RFC names are part of the wire vocabulary this
/// crate has to understand, and because it is what makes the gap between
/// "recognised" and "accepted" visible instead of invisible.
pub(crate) const KNOWN_KEX_ALGORITHMS: &[&str] = &[
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_ECDH_SHA2_NISTP384,
    KEX_ECDH_SHA2_NISTP521,
    KEX_DIFFIE_HELLMAN_GROUP14_SHA256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_MLKEM768X25519_SHA256,
];

/// Every host-key name this crate recognises and can sign with or verify.
///
/// A strict superset of [`SUPPORTED_HOST_KEY_ALGORITHMS`], and unlike
/// [`KNOWN_KEX_ALGORITHMS`] every entry here has a complete implementation
/// behind it: `rsa-sha2-512` and `rsa-sha2-256` in `rsa_hostkey.rs`, and
/// `ecdsa-sha2-nistp256` in `ecdsa_hostkey.rs`. What none of them has is a
/// handshake that can select it — see [`SUPPORTED_HOST_KEY_ALGORITHMS`].
///
/// The P-384 and P-521 ECDSA curves are *not* here: they are recognised by name
/// in [`KNOWN_KEX_ALGORITHMS`]'s sibling `ecdsa_hostkey.rs` type surface but are
/// outside the host-key algorithm names this crate advertises or accepts.
pub(crate) const KNOWN_HOST_KEY_ALGORITHMS: &[&str] = &[
    HOST_KEY_SSH_ED25519,
    HOST_KEY_RSA_SHA2_512,
    HOST_KEY_RSA_SHA2_256,
    HOST_KEY_ECDSA_SHA2_NISTP256,
];

/// The complete packet-encryption catalog supported by the SSH algorithm
/// series.
pub(crate) const SUPPORTED_ENCRYPTION_ALGORITHMS: &[&str] = &[
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
    ENCRYPTION_AES128_GCM_OPENSSH,
    ENCRYPTION_AES256_GCM_OPENSSH,
    ENCRYPTION_AES256_CTR,
    ENCRYPTION_AES128_CTR,
];

/// The complete packet-integrity catalog supported by the SSH algorithm
/// series.
pub(crate) const SUPPORTED_MAC_ALGORITHMS: &[&str] = &[
    MAC_HMAC_SHA2_256,
    MAC_HMAC_SHA2_512,
    MAC_HMAC_SHA2_256_ETM_OPENSSH,
    MAC_HMAC_SHA2_512_ETM_OPENSSH,
];

/// The complete compression catalog supported by the SSH algorithm series.
pub(crate) const SUPPORTED_COMPRESSION_ALGORITHMS: &[&str] =
    &[COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH];

/// The OpenSSH extension and strict-KEX marker catalog.
pub(crate) const SUPPORTED_EXTENSIONS: &[&str] = &[
    EXT_INFO_C,
    EXT_INFO_S,
    KEX_STRICT_C_V00_OPENSSH,
    KEX_STRICT_S_V00_OPENSSH,
];

/// Every algorithm name a handshake in this crate will accept, without category
/// labels.
///
/// The union of [`SUPPORTED_KEX_ALGORITHMS`], [`SUPPORTED_HOST_KEY_ALGORITHMS`],
/// [`SUPPORTED_ENCRYPTION_ALGORITHMS`], [`SUPPORTED_MAC_ALGORITHMS`],
/// [`SUPPORTED_COMPRESSION_ALGORITHMS`] and [`SUPPORTED_EXTENSIONS`]. It is
/// written out rather than assembled, because a `const` cannot concatenate
/// slices; `tests/kexinit.rs` asserts it *is* that union, so a name added to a
/// category list without being added here fails the build rather than
/// under-reporting.
///
/// For the names this crate recognises but will not negotiate, see
/// [`KNOWN_KEX_ALGORITHMS`] and [`KNOWN_HOST_KEY_ALGORITHMS`].
pub(crate) const SUPPORTED_ALGORITHMS: &[&str] = &[
    // SUPPORTED_KEX_ALGORITHMS
    KEX_MLKEM768X25519_SHA256,
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    // SUPPORTED_HOST_KEY_ALGORITHMS
    HOST_KEY_SSH_ED25519,
    // SUPPORTED_ENCRYPTION_ALGORITHMS
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
    ENCRYPTION_AES128_GCM_OPENSSH,
    ENCRYPTION_AES256_GCM_OPENSSH,
    ENCRYPTION_AES256_CTR,
    ENCRYPTION_AES128_CTR,
    // SUPPORTED_MAC_ALGORITHMS
    MAC_HMAC_SHA2_256,
    MAC_HMAC_SHA2_512,
    MAC_HMAC_SHA2_256_ETM_OPENSSH,
    MAC_HMAC_SHA2_512_ETM_OPENSSH,
    // SUPPORTED_COMPRESSION_ALGORITHMS
    COMPRESSION_NONE,
    COMPRESSION_ZLIB_OPENSSH,
    // SUPPORTED_EXTENSIONS
    EXT_INFO_C,
    EXT_INFO_S,
    KEX_STRICT_C_V00_OPENSSH,
    KEX_STRICT_S_V00_OPENSSH,
];

/// The default client key-exchange proposal, excluding strict-KEX markers.
///
/// The list is ordered by preference. Every entry is in
/// [`SUPPORTED_KEX_ALGORITHMS`], so a KEXINIT built from it by
/// [`KexInit::new`] completes a handshake with either transport. A peer can
/// negotiate a different order by supplying its own proposal.
///
/// Each name appears exactly once. A duplicated entry does not change what is
/// selected — negotiation takes the first client-preferred name the server also
/// offers — but it does put a lie in the encoded name-list, so
/// `tests/kexinit.rs` asserts there are none.
pub(crate) const DEFAULT_KEX_ALGORITHMS: &[&str] = &[
    KEX_MLKEM768X25519_SHA256,
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
];

/// The default host-key proposal, ordered by preference.
///
/// Every entry is in [`SUPPORTED_HOST_KEY_ALGORITHMS`], so there is exactly one
/// and it is the one both handshakes will accept.
pub(crate) const DEFAULT_HOST_KEY_ALGORITHMS: &[&str] = SUPPORTED_HOST_KEY_ALGORITHMS;

/// The default packet-encryption proposal, ordered by preference.
pub(crate) const DEFAULT_ENCRYPTION_ALGORITHMS: &[&str] = &[
    ENCRYPTION_CHACHA20_POLY1305_OPENSSH,
    ENCRYPTION_AES256_GCM_OPENSSH,
    ENCRYPTION_AES128_GCM_OPENSSH,
    ENCRYPTION_AES256_CTR,
    ENCRYPTION_AES128_CTR,
];

/// The default packet-integrity proposal, ordered by preference.
pub(crate) const DEFAULT_MAC_ALGORITHMS: &[&str] = &[
    MAC_HMAC_SHA2_512_ETM_OPENSSH,
    MAC_HMAC_SHA2_256_ETM_OPENSSH,
    MAC_HMAC_SHA2_512,
    MAC_HMAC_SHA2_256,
];

/// The default compression algorithms, ordered by preference.
pub(crate) const DEFAULT_COMPRESSION_ALGORITHMS: &[&str] =
    &[COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH];

/// An alias for [`DEFAULT_COMPRESSION_ALGORITHMS`].
pub(crate) const DEFAULT_COMPRESSION_PROPOSAL: &[&str] = DEFAULT_COMPRESSION_ALGORITHMS;

/// An alias for [`DEFAULT_COMPRESSION_ALGORITHMS`].
pub(crate) const DEFAULT_COMPRESSION: &[&str] = DEFAULT_COMPRESSION_ALGORITHMS;

/// Returns the default compression proposal.
///
/// # Examples
///
/// ```
/// assert_eq!(default_compression_proposal(), ["none", "zlib@openssh.com"]);
/// ```
#[must_use]
pub(crate) fn default_compression_proposal() -> &'static [&'static str] {
    DEFAULT_COMPRESSION_PROPOSAL
}

/// The default client key-exchange proposal including its strict-KEX marker.
///
/// [`DEFAULT_KEX_ALGORITHMS`] plus [`KEX_STRICT_C_V00_OPENSSH`], which
/// [`KexInit::strict_kex_enabled`] looks for rather than treating as a
/// key-exchange algorithm. A peer that does not also offer
/// [`KEX_STRICT_S_V00_OPENSSH`] simply does not get strict key exchange, so the
/// marker is safe to propose unconditionally.
pub(crate) const DEFAULT_CLIENT_KEX_ALGORITHMS: &[&str] = &[
    KEX_MLKEM768X25519_SHA256,
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_STRICT_C_V00_OPENSSH,
];

/// The default server key-exchange proposal including its strict-KEX marker.
///
/// [`DEFAULT_KEX_ALGORITHMS`] plus [`KEX_STRICT_S_V00_OPENSSH`], the server half
/// of the strict-key-exchange pair.
pub(crate) const DEFAULT_SERVER_KEX_ALGORITHMS: &[&str] = &[
    KEX_MLKEM768X25519_SHA256,
    KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBCSSH,
    KEX_ECDH_SHA2_NISTP256,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
    KEX_STRICT_S_V00_OPENSSH,
];

/// An error returned when two algorithm proposals have no common member.
///
/// The error intentionally carries no algorithm names, packet bytes, or key
/// material.  It is therefore safe to expose in protocol diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationError {
    /// The client and server proposals have no mutually supported name.
    NoCommonAlgorithm,
}

impl NegotiationError {
    /// A named constant for [`NegotiationError::NoCommonAlgorithm`].
    pub const NO_COMMON_ALGORITHM: Self = Self::NoCommonAlgorithm;
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSH proposals have no mutually supported algorithm")
    }
}

impl std::error::Error for NegotiationError {}

/// The eight algorithm choices negotiated from a pair of KEXINIT messages.
///
/// Language lists are not algorithm choices and are therefore not represented
/// in this result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedAlgorithms {
    /// The selected key-exchange algorithm.
    pub kex: String,
    /// The selected server host-key algorithm.
    pub host_key: String,
    /// The selected client-to-server cipher.
    pub cipher_client_to_server: String,
    /// The selected server-to-client cipher.
    pub cipher_server_to_client: String,
    /// The selected client-to-server MAC, or an empty string when `ChaCha`
    /// selected the direction and MAC negotiation is not applicable.
    pub mac_client_to_server: String,
    /// The selected server-to-client MAC, or an empty string when `ChaCha`
    /// selected the direction and MAC negotiation is not applicable.
    pub mac_server_to_client: String,
    /// The selected client-to-server compression algorithm.
    pub compression_client_to_server: String,
    /// The selected server-to-client compression algorithm.
    pub compression_server_to_client: String,
}

impl NegotiatedAlgorithms {
    /// Creates a complete negotiated-algorithm result.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kex: impl Into<String>,
        host_key: impl Into<String>,
        cipher_client_to_server: impl Into<String>,
        cipher_server_to_client: impl Into<String>,
        mac_client_to_server: impl Into<String>,
        mac_server_to_client: impl Into<String>,
        compression_client_to_server: impl Into<String>,
        compression_server_to_client: impl Into<String>,
    ) -> Self {
        Self {
            kex: kex.into(),
            host_key: host_key.into(),
            cipher_client_to_server: cipher_client_to_server.into(),
            cipher_server_to_client: cipher_server_to_client.into(),
            mac_client_to_server: mac_client_to_server.into(),
            mac_server_to_client: mac_server_to_client.into(),
            compression_client_to_server: compression_client_to_server.into(),
            compression_server_to_client: compression_server_to_client.into(),
        }
    }

    /// Returns the selected client-to-server encryption name.
    #[must_use]
    pub fn encryption_client_to_server(&self) -> &str {
        &self.cipher_client_to_server
    }

    /// Returns the selected server-to-client encryption name.
    #[must_use]
    pub fn encryption_server_to_client(&self) -> &str {
        &self.cipher_server_to_client
    }
}

/// Returns whether a peer's first-KEX packet guess matches the negotiation.
///
/// RFC 4253 permits a peer to send the first KEX method immediately after
/// KEXINIT when the sender's first KEX and host-key choices are the selected
/// choices. The caller still validates the guessed packet before using it.
pub(crate) fn kex_guess_matches(proposal: &KexInit, negotiated: &NegotiatedAlgorithms) -> bool {
    proposal
        .kex_algorithms
        .first()
        .is_some_and(|algorithm| algorithm == &negotiated.kex)
        && proposal
            .server_host_key_algorithms
            .first()
            .is_some_and(|algorithm| algorithm == &negotiated.host_key)
}

/// A lossless SSH KEXINIT message.
///
/// The ten vector fields are stored in wire order after the cookie.  Their
/// order and duplicate entries are retained when the message is encoded and
/// decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KexInit {
    /// The 16-byte random cookie sent by the peer.
    pub cookie: [u8; KEXINIT_COOKIE_LENGTH],
    /// The key-exchange name-list.
    pub kex_algorithms: Vec<String>,
    /// The server host-key name-list.
    pub server_host_key_algorithms: Vec<String>,
    /// The client-to-server encryption name-list.
    pub encryption_algorithms_client_to_server: Vec<String>,
    /// The server-to-client encryption name-list.
    pub encryption_algorithms_server_to_client: Vec<String>,
    /// The client-to-server MAC name-list.
    pub mac_algorithms_client_to_server: Vec<String>,
    /// The server-to-client MAC name-list.
    pub mac_algorithms_server_to_client: Vec<String>,
    /// The client-to-server compression name-list.
    pub compression_algorithms_client_to_server: Vec<String>,
    /// The server-to-client compression name-list.
    pub compression_algorithms_server_to_client: Vec<String>,
    /// The client-to-server language name-list.
    pub languages_client_to_server: Vec<String>,
    /// The server-to-client language name-list.
    pub languages_server_to_client: Vec<String>,
    /// Whether the sender has a guessed first KEX packet to follow.
    pub first_kex_packet_follows: bool,
    /// The reserved wire word, preserved without normalization.
    pub reserved: u32,
}

/// A descriptive alias for [`KexInit`].
pub(crate) type KexInitMessage = KexInit;

/// An alternate capitalization alias for [`KexInit`].
pub(crate) type Kexinit = KexInit;

/// A descriptive alternate alias for [`KexInit`].
pub(crate) type KexinitMessage = KexInit;

impl Default for KexInit {
    fn default() -> Self {
        Self::with_default_algorithms([0; KEXINIT_COOKIE_LENGTH])
    }
}

impl KexInit {
    /// Creates a KEXINIT message with the default algorithm proposals.
    #[must_use]
    pub fn new(cookie: [u8; KEXINIT_COOKIE_LENGTH]) -> Self {
        Self::with_default_algorithms(cookie)
    }

    /// Creates a KEXINIT message with the default algorithm proposals.
    #[must_use]
    pub fn with_default_algorithms(cookie: [u8; KEXINIT_COOKIE_LENGTH]) -> Self {
        Self::from_lists(
            cookie,
            owned_names(DEFAULT_KEX_ALGORITHMS),
            owned_names(DEFAULT_HOST_KEY_ALGORITHMS),
            owned_names(DEFAULT_ENCRYPTION_ALGORITHMS),
            owned_names(DEFAULT_ENCRYPTION_ALGORITHMS),
            owned_names(DEFAULT_MAC_ALGORITHMS),
            owned_names(DEFAULT_MAC_ALGORITHMS),
            owned_names(DEFAULT_COMPRESSION_ALGORITHMS),
            owned_names(DEFAULT_COMPRESSION_ALGORITHMS),
            Vec::new(),
            Vec::new(),
            false,
            0,
        )
    }

    /// Creates a client proposal with the default algorithms and strict-KEX
    /// marker.
    #[must_use]
    pub fn client_defaults(cookie: [u8; KEXINIT_COOKIE_LENGTH]) -> Self {
        Self::with_kex_proposal(cookie, DEFAULT_CLIENT_KEX_ALGORITHMS, false, 0)
    }

    /// Creates a server proposal with the default algorithms and strict-KEX
    /// marker.
    #[must_use]
    pub fn server_defaults(cookie: [u8; KEXINIT_COOKIE_LENGTH]) -> Self {
        Self::with_kex_proposal(cookie, DEFAULT_SERVER_KEX_ALGORITHMS, false, 0)
    }

    fn with_kex_proposal(
        cookie: [u8; KEXINIT_COOKIE_LENGTH],
        kex_algorithms: &[&str],
        first_kex_packet_follows: bool,
        reserved: u32,
    ) -> Self {
        Self {
            cookie,
            kex_algorithms: owned_names(kex_algorithms),
            ..Self::with_default_algorithms(cookie)
        }
        .with_flags(first_kex_packet_follows, reserved)
    }

    fn with_flags(mut self, first_kex_packet_follows: bool, reserved: u32) -> Self {
        self.first_kex_packet_follows = first_kex_packet_follows;
        self.reserved = reserved;
        self
    }

    /// Creates a KEXINIT message from all ten name-lists and its scalar
    /// fields.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_lists(
        cookie: [u8; KEXINIT_COOKIE_LENGTH],
        kex_algorithms: Vec<String>,
        server_host_key_algorithms: Vec<String>,
        encryption_algorithms_client_to_server: Vec<String>,
        encryption_algorithms_server_to_client: Vec<String>,
        mac_algorithms_client_to_server: Vec<String>,
        mac_algorithms_server_to_client: Vec<String>,
        compression_algorithms_client_to_server: Vec<String>,
        compression_algorithms_server_to_client: Vec<String>,
        languages_client_to_server: Vec<String>,
        languages_server_to_client: Vec<String>,
        first_kex_packet_follows: bool,
        reserved: u32,
    ) -> Self {
        Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved,
        }
    }

    /// Returns all ten name-lists in their wire order.
    #[must_use]
    pub fn name_lists(&self) -> [&[String]; KEXINIT_NAME_LIST_COUNT] {
        [
            &self.kex_algorithms,
            &self.server_host_key_algorithms,
            &self.encryption_algorithms_client_to_server,
            &self.encryption_algorithms_server_to_client,
            &self.mac_algorithms_client_to_server,
            &self.mac_algorithms_server_to_client,
            &self.compression_algorithms_client_to_server,
            &self.compression_algorithms_server_to_client,
            &self.languages_client_to_server,
            &self.languages_server_to_client,
        ]
    }

    /// Encodes this message, including its SSH message type byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidName`] when a list member is not a valid SSH
    /// name and returns [`Error::LimitExceeded`] when a list is too large for
    /// the wire string limit.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_KEXINIT);
        for byte in self.cookie {
            writer.write_byte(byte);
        }
        for names in self.name_lists() {
            writer.write_name_list(names)?;
        }
        writer.write_boolean(self.first_kex_packet_follows);
        writer.write_uint32(self.reserved);
        Ok(writer.into_bytes())
    }

    /// Decodes one complete KEXINIT message, including its type byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when a required field is incomplete,
    /// [`Error::InvalidPacket`] for a different message type or trailing data,
    /// and the existing wire errors for invalid booleans or name-lists.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(input);
        let message_type = reader.read_byte()?;
        if message_type != SSH_MSG_KEXINIT {
            return Err(Error::InvalidPacket);
        }

        let mut cookie = [0_u8; KEXINIT_COOKIE_LENGTH];
        for byte in &mut cookie {
            *byte = reader.read_byte()?;
        }

        let kex_algorithms = reader.read_name_list()?;
        let server_host_key_algorithms = reader.read_name_list()?;
        let encryption_algorithms_client_to_server = reader.read_name_list()?;
        let encryption_algorithms_server_to_client = reader.read_name_list()?;
        let mac_algorithms_client_to_server = reader.read_name_list()?;
        let mac_algorithms_server_to_client = reader.read_name_list()?;
        let compression_algorithms_client_to_server = reader.read_name_list()?;
        let compression_algorithms_server_to_client = reader.read_name_list()?;
        let languages_client_to_server = reader.read_name_list()?;
        let languages_server_to_client = reader.read_name_list()?;
        let first_kex_packet_follows = reader.read_boolean()?;
        let reserved = reader.read_uint32()?;

        if !reader.is_empty() {
            return Err(Error::InvalidPacket);
        }

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved,
        })
    }

    /// Decodes one KEXINIT message from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`KexInit::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        Self::decode(input)
    }

    /// Encodes this KEXINIT message to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`KexInit::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }

    /// Negotiates all algorithm fields against a server proposal.
    ///
    /// Selection follows the client's order independently for every field.
    /// Strict-KEX markers are not treated as key-exchange algorithms.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::NoCommonAlgorithm`] when any required
    /// algorithm category has no mutually supported name. MAC lists are not
    /// required for a direction that selects `chacha20-poly1305@openssh.com`.
    pub fn negotiate(&self, server: &Self) -> Result<NegotiatedAlgorithms, NegotiationError> {
        self.negotiate_with(server)
    }

    /// Negotiates all algorithm fields against a server proposal.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError::NoCommonAlgorithm`] when any required
    /// algorithm category has no mutually supported name. MAC lists are not
    /// required for a direction that selects `chacha20-poly1305@openssh.com`.
    pub fn negotiate_with(&self, server: &Self) -> Result<NegotiatedAlgorithms, NegotiationError> {
        let kex = negotiate_kex_algorithm(&self.kex_algorithms, &server.kex_algorithms)?;
        let host_key = negotiate_algorithm(
            &self.server_host_key_algorithms,
            &server.server_host_key_algorithms,
        )?;
        let cipher_client_to_server = negotiate_algorithm(
            &self.encryption_algorithms_client_to_server,
            &server.encryption_algorithms_client_to_server,
        )?;
        let cipher_server_to_client = negotiate_algorithm(
            &self.encryption_algorithms_server_to_client,
            &server.encryption_algorithms_server_to_client,
        )?;
        let mac_client_to_server = negotiate_mac_for_cipher(
            &cipher_client_to_server,
            &self.mac_algorithms_client_to_server,
            &server.mac_algorithms_client_to_server,
        )?;
        let mac_server_to_client = negotiate_mac_for_cipher(
            &cipher_server_to_client,
            &self.mac_algorithms_server_to_client,
            &server.mac_algorithms_server_to_client,
        )?;
        let compression_client_to_server = negotiate_algorithm(
            &self.compression_algorithms_client_to_server,
            &server.compression_algorithms_client_to_server,
        )?;
        let compression_server_to_client = negotiate_algorithm(
            &self.compression_algorithms_server_to_client,
            &server.compression_algorithms_server_to_client,
        )?;

        Ok(NegotiatedAlgorithms::new(
            kex,
            host_key,
            cipher_client_to_server,
            cipher_server_to_client,
            mac_client_to_server,
            mac_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
        ))
    }

    /// Reports whether both OpenSSH strict-KEX markers are present.
    #[must_use]
    pub fn strict_kex_enabled(&self, server: &Self) -> bool {
        self.kex_algorithms
            .iter()
            .any(|name| name == KEX_STRICT_C_V00_OPENSSH)
            && server
                .kex_algorithms
                .iter()
                .any(|name| name == KEX_STRICT_S_V00_OPENSSH)
    }
}

impl TryFrom<&[u8]> for KexInit {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(input)
    }
}

/// Encodes a KEXINIT message using the shared wire writer.
///
/// # Errors
///
/// Returns the same errors as [`KexInit::encode`].
pub(crate) fn encode(message: &KexInit) -> Result<Vec<u8>, Error> {
    message.encode()
}

/// Decodes a KEXINIT message using the shared wire reader.
///
/// # Errors
///
/// Returns the same errors as [`KexInit::decode`].
pub(crate) fn decode(input: &[u8]) -> Result<KexInit, Error> {
    KexInit::decode(input)
}

/// Encodes a KEXINIT message.
///
/// # Errors
///
/// Returns the same errors as [`KexInit::encode`].
pub(crate) fn encode_kexinit(message: &KexInit) -> Result<Vec<u8>, Error> {
    message.encode()
}

/// Decodes a KEXINIT message.
///
/// # Errors
///
/// Returns the same errors as [`KexInit::decode`].
pub(crate) fn decode_kexinit(input: &[u8]) -> Result<KexInit, Error> {
    KexInit::decode(input)
}

fn negotiate_mac_for_cipher(
    cipher: &str,
    client: &[String],
    server: &[String],
) -> Result<String, NegotiationError> {
    if cipher == ENCRYPTION_CHACHA20_POLY1305_OPENSSH {
        return Ok(String::new());
    }
    negotiate_algorithm(client, server)
}

/// Selects the first client algorithm that also occurs in the server list.
///
/// The returned string preserves the spelling and first-occurrence order of
/// the client proposal.  Duplicate entries do not change the selected value.
/// Both arguments may be owned or borrowed iterables of names.
///
/// # Errors
///
/// Returns [`NegotiationError::NoCommonAlgorithm`] when the lists are
/// disjoint.  The error contains no proposal or key material.
pub(crate) fn negotiate_algorithm<C, S, CI, SI>(
    client: C,
    server: S,
) -> Result<String, NegotiationError>
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    let server: Vec<SI> = server.into_iter().collect();
    client
        .into_iter()
        .find(|candidate| {
            server
                .iter()
                .any(|server_name| server_name.as_ref() == candidate.as_ref())
        })
        .map(|candidate| candidate.as_ref().to_owned())
        .ok_or(NegotiationError::NoCommonAlgorithm)
}

/// An alias for [`negotiate_algorithm`].
///
/// # Errors
///
/// Returns the same errors as [`negotiate_algorithm`].
pub(crate) fn negotiate<C, S, CI, SI>(client: C, server: S) -> Result<String, NegotiationError>
where
    C: IntoIterator<Item = CI>,
    CI: AsRef<str>,
    S: IntoIterator<Item = SI>,
    SI: AsRef<str>,
{
    negotiate_algorithm(client, server)
}

/// Whether a name in a key-exchange list is an OpenSSH marker rather than a
/// key-exchange algorithm.
///
/// The strict-key-exchange and extension-information markers share the
/// key-exchange name-list on the wire, and [`KexInit::negotiate`] skips them. A
/// caller checking a proposal against `SUPPORTED_KEX_ALGORITHMS` has to skip them
/// too, or it will conclude that every strict-key-exchange proposal names an
/// unsupported mechanism.
#[must_use]
pub(crate) fn is_kex_marker(name: &str) -> bool {
    name == EXT_INFO_C
        || name == EXT_INFO_S
        || name == KEX_STRICT_C_V00_OPENSSH
        || name == KEX_STRICT_S_V00_OPENSSH
}

fn negotiate_kex_algorithm<C, S>(client: &[C], server: &[S]) -> Result<String, NegotiationError>
where
    C: AsRef<str>,
    S: AsRef<str>,
{
    for candidate in client {
        if is_kex_marker(candidate.as_ref()) {
            continue;
        }
        if server
            .iter()
            .any(|server_name| server_name.as_ref() == candidate.as_ref())
        {
            return Ok(candidate.as_ref().to_owned());
        }
    }
    Err(NegotiationError::NoCommonAlgorithm)
}

fn owned_names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}
