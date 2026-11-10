// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::io::Cursor;

use neotales_ssh::direct_tcpip::DirectTcpipRequest;
use neotales_ssh::hostkey::Ed25519PublicKey;
use neotales_ssh::session::{SessionDecision, SessionRequest};
use neotales_ssh::{
    AgentClient, CLIENT_IDENTIFICATION, Certificate, ChaChaCipher, ClientAuthMethod, ClientConfig,
    ClientDirectTcpip, ClientHandshakeError, ClientSessions, ClientTransport,
    DEFAULT_SERVER_IDENTIFICATION, DirectTcpipPolicy, Direction, EcdsaPublicKey, ExtInfo,
    GlobalRequest, KnownHosts, OpenSshPrivateKey, ProxyClient, RsaHostKey, ScpClient,
    SequenceError, ServerAuthPolicy, ServerConfig, ServerDirectTcpip, ServerPolicy, ServerSessions,
    ServerTcpipForward, ServerTransport, SessionPolicy, SftpClient, SshConfig, Zeroizing,
    authenticate_client, authenticate_server, connect,
};

struct DenySession;

impl SessionPolicy for DenySession {
    fn authorize(&self, _request: SessionRequest<'_>) -> SessionDecision {
        SessionDecision::reject()
    }
}

struct DenyDirectTcpip;

impl DirectTcpipPolicy for DenyDirectTcpip {
    fn allow(&self, _request: DirectTcpipRequest<'_>) -> bool {
        false
    }
}

fn assert_public_type<T>() {
    assert!(std::mem::size_of::<T>() > 0);
}

fn assert_public_function<F>(function: &F) {
    assert!(!std::any::type_name_of_val(function).is_empty());
}

#[test]
fn public_crate_surface_is_available_without_io() {
    let client_config = ClientConfig::new();
    assert!(!client_config.kexinit().kex_algorithms.is_empty());
    assert!(CLIENT_IDENTIFICATION.starts_with("SSH-2.0-"));
    assert!(DEFAULT_SERVER_IDENTIFICATION.starts_with("SSH-2.0-"));

    assert_public_type::<Option<ClientTransport<Cursor<Vec<u8>>>>>();
    assert_public_type::<Option<ServerTransport<Cursor<Vec<u8>>>>>();
    assert_public_type::<Option<ServerConfig>>();
    assert_public_type::<Option<ClientHandshakeError>>();
    assert_public_type::<EcdsaPublicKey>();
    assert_public_type::<RsaHostKey>();
    assert_public_type::<Certificate>();
    assert_public_type::<KnownHosts>();
    assert_public_type::<SshConfig>();
    assert_public_type::<AgentClient<Cursor<Vec<u8>>>>();
    assert_public_type::<OpenSshPrivateKey>();
    assert_public_type::<ExtInfo>();
    assert_public_type::<GlobalRequest>();
    assert_public_type::<ServerTcpipForward<Cursor<Vec<u8>>>>();
    assert_public_type::<SftpClient<Cursor<Vec<u8>>>>();
    assert_public_type::<ScpClient<Cursor<Vec<u8>>>>();
    assert_public_type::<ProxyClient<'static>>();
    assert_public_type::<ServerPolicy>();
    assert_public_type::<ChaChaCipher>();
    assert_public_type::<Direction>();
    assert_public_type::<SequenceError>();
    // `ClientAuthMethod::Password` carries one, so the crate root re-exports it
    // rather than leaving a consumer to reach into a sibling crate for a type
    // our own public variant is named in terms of. `userauth.rs` covers the
    // identity; this covers the fact that the name is on the root at all.
    assert_public_type::<Zeroizing<String>>();
    assert_public_function(
        &connect::<Cursor<Vec<u8>>, fn(&Ed25519PublicKey) -> Result<(), ()>, ()>,
    );

    assert_public_function(&authenticate_client::<Cursor<Vec<u8>>, &str>);
    assert_public_function(&authenticate_server::<Cursor<Vec<u8>>>);
    assert!(ServerAuthPolicy::new(1).is_ok());
    assert!(matches!(
        ClientAuthMethod::password("smoke").kind(),
        neotales_ssh::auth::AuthMethodKind::Password
    ));

    let client_sessions = ClientSessions::new(());
    assert_eq!(client_sessions.connection().channel_count(), 0);
    let server_sessions = ServerSessions::new(());
    assert!(!server_sessions.allows_channel_open());
    let client_direct_tcpip = ClientDirectTcpip::new(());
    assert_eq!(client_direct_tcpip.connection().channel_count(), 0);
    let server_direct_tcpip = ServerDirectTcpip::new(());
    assert!(!server_direct_tcpip.policy_configured());

    let session_policy: Box<dyn SessionPolicy> = Box::new(DenySession);
    assert!(!session_policy.authorize(SessionRequest::Shell).accepted());
    let direct_tcpip_policy: Box<dyn DirectTcpipPolicy> = Box::new(DenyDirectTcpip);
    assert!(!direct_tcpip_policy.allow(DirectTcpipRequest {
        destination_host: b"localhost",
        destination_port: 22,
        originator_address: b"127.0.0.1",
        originator_port: 0,
    }));
}
