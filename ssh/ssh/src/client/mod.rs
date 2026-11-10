//! SSH client transport and initial-handshake API.
//!
//! The client completes identification, algorithm negotiation, ephemeral key
//! exchange, mandatory host-key trust, and NEWKEYS before returning a protected
//! synchronous transport. User authentication and channels intentionally remain
//! outside this module.

mod handshake;

pub use crate::transport::{
    ClientTransport, IdentificationError, MAX_IDENTIFICATION_LINE, MAX_PRE_BANNER_BYTES,
    TransportError,
};
pub use handshake::{CLIENT_IDENTIFICATION, ClientConfig, HandshakeError, connect};
