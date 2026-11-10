//! Server-side SSH transport and initial-handshake API.
//!
//! The server completes identification, negotiation, ephemeral key exchange,
//! host-key signing, and NEWKEYS before returning an explicitly unauthenticated
//! transport. User authentication and channel policy are intentionally left to
//! later modules.

mod handshake;

pub use crate::transport::{
    IdentificationError, MAX_IDENTIFICATION_LINE, MAX_PRE_BANNER_BYTES, TransportError,
};
pub use handshake::{
    DEFAULT_SERVER_IDENTIFICATION, DEFAULT_SERVER_VERSION, HandshakeError, SERVER_IDENTIFICATION,
    SERVER_VERSION, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_REQUEST, ServerConfig, ServerError,
    ServerHandshake, ServerHandshakeError, ServerTransport, ServerTransportError,
    UnauthenticatedServerTransport,
};
