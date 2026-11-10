//! SSH-2 protocol implementation for Neotales.
//!
//! This crate combines RFC 4251 wire values and packet framing with key
//! exchange, packet protection, host-key handling, client and server
//! handshakes, user authentication, session channels, and direct-tcpip
//! forwarding metadata. Client and server are modules of this single library
//! and share the same transport boundary.
//!
//! The supported entry points are re-exported at the crate root. The
//! sequence-facing types used by the public rekey and transport-error APIs,
//! [`Direction`] and [`SequenceError`], are re-exported there as well so
//! downstream callers can name them without reaching into private modules. The
//! lower level protocol modules remain available for applications that need to
//! work directly with the SSH codecs and state machines.
//!
//! # Public surface
//!
//! `KexInit` is the one type to be aware of here. It is the argument to
//! [`ClientConfig::with_kexinit`] and the result of [`ClientConfig::kexinit`],
//! so it is part of this crate's API, but it lives in a private module and
//! cannot yet be named by a downstream caller. `docs/visibility.md` records
//! that, the reasoning behind the rest of the surface, and the measurement that
//! keeps it honest.
//!
//! The blocker is not the export. `pub use msg::kexinit::KexInit;` is a one-line
//! change and it compiles — but the *real* `msg` module and the hand-maintained
//! `#[cfg(doctest)]` mirror that shadows it are two different declarations of the
//! same name, and the export has to be gated to match. A consumer names one name;
//! rustdoc resolves it in whichever module it is building. Gating the export
//! correctly turns out to need the mirror to agree on visibility for
//! `NegotiatedAlgorithms` and `NegotiationError` as well, and the mirror's
//! `NegotiationError` variant is `pub(crate)`, so `negotiate`'s own doc link to
//! `NegotiationError::NoCommonAlgorithm` then resolves to a private item and
//! `RUSTDOCFLAGS="-D warnings" cargo doc` fails with three errors that do not
//! exist at HEAD. That is the whole reason this is still open: it is a
//! visibility-mirroring problem, not a missing `pub use`.

extern crate self as neotales_ssh;

#[cfg(not(doctest))]
#[allow(dead_code, unused_imports)]
pub(crate) mod msg;

#[cfg(doctest)]
#[doc(hidden)]
#[allow(dead_code, unused_imports)]
pub(crate) mod msg {
    //! Minimal doctest-only KEXINIT declarations used while documenting the
    //! public transport modules. The real message codec is compiled for normal
    //! library and test builds from `msg/mod.rs`.
    //!
    //! This is a hand-maintained *mirror*, and the rule for it is narrow: it has
    //! to declare every `msg::kexinit` item the rest of the library body
    //! references, and nothing else. A library source file that reaches for a new
    //! constant from `msg::kexinit` therefore fails to build under `cfg(doctest)`
    //! until it is added here, which is a louder failure than the constant going
    //! quietly missing. `cargo test` catches it; `cargo build` does not.

    pub mod kexinit {
        use std::fmt;

        pub const SSH_MSG_KEXINIT: u8 = 20;
        pub const KEX_CURVE25519_SHA256: &str = "curve25519-sha256";
        pub const KEX_CURVE25519_SHA256_LIBCSSH: &str = "curve25519-sha256@libssh.org";
        pub const KEX_ECDH_SHA2_NISTP256: &str = "ecdh-sha2-nistp256";
        pub const KEX_DIFFIE_HELLMAN_GROUP16_SHA512: &str = "diffie-hellman-group16-sha512";
        pub const KEX_MLKEM768X25519_SHA256: &str = "mlkem768x25519-sha256";
        pub const CURVE25519_SHA256: &str = KEX_CURVE25519_SHA256;
        pub const CURVE25519_SHA256_LIBSSH: &str = KEX_CURVE25519_SHA256_LIBCSSH;
        pub const ECDH_SHA2_NISTP256: &str = KEX_ECDH_SHA2_NISTP256;
        pub const HOST_KEY_SSH_ED25519: &str = "ssh-ed25519";
        pub const AES128_CTR: &str = "aes128-ctr";
        pub const AES256_CTR: &str = "aes256-ctr";
        pub const AES128_GCM_OPENSSH: &str = "aes128-gcm@openssh.com";
        pub const AES256_GCM_OPENSSH: &str = "aes256-gcm@openssh.com";
        pub const HMAC_SHA2_256: &str = "hmac-sha2-256";
        pub const HMAC_SHA2_512: &str = "hmac-sha2-512";
        pub const HMAC_SHA2_256_ETM_OPENSSH: &str = "hmac-sha2-256-etm@openssh.com";
        pub const HMAC_SHA2_512_ETM_OPENSSH: &str = "hmac-sha2-512-etm@openssh.com";
        pub const COMPRESSION_NONE: &str = "none";
        pub const COMPRESSION_ZLIB_OPENSSH: &str = "zlib@openssh.com";
        pub const KEX_STRICT_C_V00_OPENSSH: &str = "kex-strict-c-v00@openssh.com";
        pub const KEX_STRICT_S_V00_OPENSSH: &str = "kex-strict-s-v00@openssh.com";
        pub const SUPPORTED_MAC_ALGORITHMS: &[&str] = &[
            HMAC_SHA2_256,
            HMAC_SHA2_512,
            HMAC_SHA2_256_ETM_OPENSSH,
            HMAC_SHA2_512_ETM_OPENSSH,
        ];
        // The accepted-algorithm catalogs. `kex` checks the negotiated name
        // against `SUPPORTED_KEX_ALGORITHMS` rather than against its own list,
        // and both handshakes check the negotiated host key against
        // `SUPPORTED_HOST_KEY_ALGORITHMS`, so the mirror needs both. Keep the
        // contents in step with `msg/kexinit.rs`: the test lane in
        // `tests/kexinit.rs` pins the real lists, and a disagreement between the
        // mirror and the real module would only show up as a doctest that
        // documents a proposal this crate would refuse.
        pub const SUPPORTED_KEX_ALGORITHMS: &[&str] = &[
            KEX_MLKEM768X25519_SHA256,
            CURVE25519_SHA256,
            CURVE25519_SHA256_LIBSSH,
            ECDH_SHA2_NISTP256,
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512,
        ];
        pub const SUPPORTED_HOST_KEY_ALGORITHMS: &[&str] = &[HOST_KEY_SSH_ED25519];

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum NegotiationError {
            NoCommonAlgorithm,
        }

        impl fmt::Display for NegotiationError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("SSH proposals have no common algorithm")
            }
        }

        impl std::error::Error for NegotiationError {}

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct NegotiatedAlgorithms {
            pub kex: String,
            pub host_key: String,
            pub cipher_client_to_server: String,
            pub cipher_server_to_client: String,
            pub mac_client_to_server: String,
            pub mac_server_to_client: String,
            pub compression_client_to_server: String,
            pub compression_server_to_client: String,
        }

        impl NegotiatedAlgorithms {
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
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct KexInit {
            pub cookie: [u8; 16],
            pub kex_algorithms: Vec<String>,
            pub server_host_key_algorithms: Vec<String>,
            pub encryption_algorithms_client_to_server: Vec<String>,
            pub encryption_algorithms_server_to_client: Vec<String>,
            pub mac_algorithms_client_to_server: Vec<String>,
            pub mac_algorithms_server_to_client: Vec<String>,
            pub compression_algorithms_client_to_server: Vec<String>,
            pub compression_algorithms_server_to_client: Vec<String>,
            pub languages_client_to_server: Vec<String>,
            pub languages_server_to_client: Vec<String>,
            pub first_kex_packet_follows: bool,
            pub reserved: u32,
        }

        impl KexInit {
            #[must_use]
            #[allow(clippy::too_many_arguments)]
            pub fn from_lists(
                cookie: [u8; 16],
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

            pub fn encode(&self) -> Result<Vec<u8>, crate::Error> {
                Err(crate::Error::InvalidPacket)
            }

            pub fn decode(_input: &[u8]) -> Result<Self, crate::Error> {
                Err(crate::Error::InvalidPacket)
            }

            pub fn negotiate(
                &self,
                _server: &Self,
            ) -> Result<NegotiatedAlgorithms, NegotiationError> {
                Ok(NegotiatedAlgorithms::new(
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ))
            }

            pub fn strict_kex_enabled(&self, _server: &Self) -> bool {
                false
            }
        }

        pub(crate) fn kex_guess_matches(
            _proposal: &KexInit,
            _negotiated: &NegotiatedAlgorithms,
        ) -> bool {
            false
        }
    }
}

#[allow(dead_code)]
pub mod auth;
#[allow(clippy::missing_errors_doc, clippy::result_unit_err)]
pub mod channel;
#[allow(dead_code)]
pub(crate) mod cipher;
#[allow(unused_imports)]
pub mod client;
pub mod direct_tcpip;
pub mod error;
pub mod hostkey;
#[allow(dead_code, unused_imports)]
pub(crate) mod kex;
pub mod packet;
#[allow(dead_code)]
pub(crate) mod sequence;
pub mod server;
pub mod session;
#[allow(dead_code)]
pub mod transport;
pub mod wire;

pub mod agent;
pub mod cert;
pub mod chacha_cipher;
pub mod compression;
pub mod ecdsa_hostkey;
#[path = "msg/ext_info.rs"]
pub mod ext_info;
pub mod gssapi;
pub mod keepalive;
#[allow(clippy::missing_errors_doc, clippy::must_use_candidate)]
pub mod known_hosts;
#[allow(dead_code)]
pub mod openssh_key;
pub mod proxy;
#[allow(clippy::missing_errors_doc)]
pub mod rsa_hostkey;
pub mod scp;
pub mod server_policy;
pub mod sftp;
pub mod ssh_config;
pub mod tcpip_forward;

pub use agent::AgentClient;
pub use cert::Certificate;
pub use chacha_cipher::ChaChaCipher;
pub use ecdsa_hostkey::EcdsaPublicKey;
pub use ext_info::ExtInfo;
pub use gssapi::{
    GSSAPI_WITH_MIC_METHOD, GssapiError, GssapiExchange, GssapiExchangeAction,
    GssapiExchangeComplete, GssapiExchangeState, GssapiMechanismResult, GssapiMessage,
    GssapiRequest, GssapiResponse, GssapiToken, GssapiTokenMechanism,
};
pub use keepalive::GlobalRequest;
pub use known_hosts::KnownHosts;
pub use openssh_key::OpenSshPrivateKey;
pub use proxy::ProxyClient;
pub use rsa_hostkey::RsaHostKey;
pub use scp::ScpClient;
pub use server_policy::ServerPolicy;
pub use sftp::SftpClient;
pub use ssh_config::SshConfig;
pub use tcpip_forward::ServerTcpipForward;

pub use auth::{
    AgentKeySigner, AgentTransport, ClientAuthMethod, ServerAuthPolicy, authenticate_client,
    authenticate_server,
};
pub use client::{
    CLIENT_IDENTIFICATION, ClientConfig, ClientTransport, HandshakeError as ClientHandshakeError,
    connect,
};
pub use direct_tcpip::{ClientDirectTcpip, DirectTcpipPolicy, ServerDirectTcpip};
pub use sequence::{Direction, SequenceError};
pub use server::{DEFAULT_SERVER_IDENTIFICATION, ServerConfig, ServerTransport};
pub use session::{ClientSessions, ServerSessions, SessionPolicy};

/// A string that wipes itself when it is dropped.
///
/// Re-exported because [`ClientAuthMethod::Password`] carries one. That variant
/// is public, so a consumer that wants to construct or match it has to name the
/// type, and a name is only usable if the crate it comes from is a dependency of
/// the consumer. `neotales-ssh` depends on `zeroize` directly for exactly that
/// reason; without this re-export the only route to the type was
/// `zeroize::Zeroizing`, which would have made this
/// crate's public API depend on a path inside a different crate's API.
///
/// It is the same `zeroize` the crypto area resolves, so a value of this type is
/// one type and the zeroization semantics are the same ones the crypto crates
/// document.
pub use zeroize::Zeroizing;

pub use error::Error;
pub use packet::{
    DEFAULT_BLOCK_SIZE, FixedPadding, MAX_PACKET_BODY, MAX_PACKET_CONTENT, MIN_PADDING, Packet,
    PaddingFill, PaddingSource, build_packet, build_packet_default,
    build_packet_with_default_block_size, build_packet_with_source,
    build_packet_with_source_default, decode_packet, decode_packet_default, decode_packet_prefix,
    decode_packet_prefix_default, encode_packet, encode_packet_with_source, parse_packet,
    round_trip_packet,
};
pub use wire::{
    DEFAULT_STRING_LIMIT, IntoMpint, Reader, StringBytes, Writer, decode_boolean, decode_mpint,
    decode_name_list, decode_string, decode_uint32, decode_uint64, encode_boolean, encode_byte,
    encode_mpint, encode_name_list, encode_string, encode_uint32, encode_uint64,
};
