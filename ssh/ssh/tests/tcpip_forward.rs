// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::error::Error as StdError;
use std::rc::Rc;

use neotales_ssh::channel::{ChannelConnection, ChannelEvent, ChannelId, ChannelTransport};
use neotales_ssh::{Error, Reader, Writer};
use tcpip_forward::{
    CANCEL_TCPIP_FORWARD_REQUEST, ClientTcpipForward, FORWARDED_TCPIP_CHANNEL_TYPE,
    ForwardedTcpipTuple, ServerTcpipForward, TCPIP_FORWARD_REQUEST, TcpipForwardError,
    TcpipForwardGlobalRequest, TcpipForwardRequestKind, TcpipForwardResponse,
};

#[allow(dead_code)]
#[path = "../src/tcpip_forward.rs"]
mod tcpip_forward;

#[derive(Clone, Debug)]
struct MemoryTransport {
    incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl MemoryTransport {
    fn pair() -> (Self, Self) {
        let client_to_server = Rc::new(RefCell::new(VecDeque::new()));
        let server_to_client = Rc::new(RefCell::new(VecDeque::new()));
        (
            Self {
                incoming: Rc::clone(&server_to_client),
                outgoing: Rc::clone(&client_to_server),
            },
            Self {
                incoming: Rc::clone(&client_to_server),
                outgoing: Rc::clone(&server_to_client),
            },
        )
    }

    fn outgoing_len(&self) -> usize {
        self.outgoing.borrow().len()
    }
}

impl ChannelTransport for MemoryTransport {
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.outgoing.borrow_mut().push_back(payload.to_vec());
        Ok(())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.incoming.borrow_mut().pop_front().ok_or(())
    }
}

#[test]
fn default_deny_writes_failure_without_creating_a_channel() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server = ServerTcpipForward::new(server_transport);

    client.request_tcpip_forward(b"127.0.0.1", 8080, true)?;
    let result = server.dispatch_global_request()?;

    assert!(!result.accepted());
    assert_eq!(result.kind(), TcpipForwardRequestKind::TcpipForward);
    assert_eq!(server.connection().channel_count(), 0);
    assert_eq!(server.connection().pending_open_count(), 0);
    assert_eq!(
        client.read_global_response()?,
        TcpipForwardResponse::Failure
    );
    Ok(())
}

#[test]
fn dispatch_routes_global_forward_requests_and_replies_once() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server = ServerTcpipForward::with_allow_callback(server_transport, |address, port| {
        address == b"127.0.0.1" && port == 8080
    });

    client.request_tcpip_forward(b"127.0.0.1", 8080, true)?;
    assert!(matches!(
        server.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::GlobalRequest {
            request_name,
            want_reply: false,
            ..
        } if request_name == TCPIP_FORWARD_REQUEST.as_bytes()
    ));
    assert!(server.has_binding(b"127.0.0.1", 8080));
    assert!(matches!(
        client.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::GlobalRequestSucceeded { data } if data.is_empty()
    ));
    assert_eq!(server.connection().transport().outgoing_len(), 0);

    client.request_cancel_tcpip_forward(b"127.0.0.1", 8080, false)?;
    assert!(matches!(
        server.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::GlobalRequest {
            request_name,
            want_reply: false,
            ..
        } if request_name == CANCEL_TCPIP_FORWARD_REQUEST.as_bytes()
    ));
    assert!(!server.has_binding(b"127.0.0.1", 8080));
    assert_eq!(server.connection().transport().outgoing_len(), 0);
    Ok(())
}

#[test]
fn policy_matches_exact_bind_bytes_and_does_not_widen_wildcards() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server = ServerTcpipForward::with_allow_callback(server_transport, |address, port| {
        address == b"127.0.0.1" && port == 8080
    });

    for (address, expected) in [
        (b"127.0.0.1".as_slice(), true),
        (b"0.0.0.0".as_slice(), false),
        (b"".as_slice(), false),
    ] {
        client.request_tcpip_forward(address, 8080, true)?;
        let result = server.dispatch_global_request()?;
        assert_eq!(result.accepted(), expected);
        assert_eq!(
            client.read_global_response()?,
            if expected {
                TcpipForwardResponse::Success
            } else {
                TcpipForwardResponse::Failure
            }
        );
    }

    assert_eq!(server.binding_count(), 1);
    assert!(server.has_binding(b"127.0.0.1", 8080));
    assert!(!server.has_binding(b"0.0.0.0", 8080));
    assert!(!server.has_binding(b"", 8080));
    Ok(())
}

#[test]
fn allowed_forward_opens_forwarded_channel_moves_data_and_cancels_exactly()
-> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server = ServerTcpipForward::with_allow_callback(server_transport, |address, port| {
        address == b"127.0.0.1" && port == 8080
    });

    client.request_tcpip_forward(b"127.0.0.1", 8080, true)?;
    let request = server.dispatch_global_request()?;
    assert!(request.accepted());
    assert_eq!(
        client.read_global_response()?,
        TcpipForwardResponse::Success
    );

    let tuple = ForwardedTcpipTuple::new(b"127.0.0.1", 8080, b"192.0.2.10", 43210)?;
    let server_channel = server.open_forwarded(&tuple)?;
    let client_event = client.dispatch_one()?;
    let client_channel = match client_event {
        tcpip_forward::TcpipForwardEvent::Opened {
            channel,
            tuple: Some(received),
        } => {
            assert_eq!(received, tuple);
            channel
        }
        other => return Err(format!("unexpected client event: {other:?}").into()),
    };
    assert!(matches!(
        server.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::Opened {
            channel,
            tuple: Some(ref received),
        } if channel == server_channel && received == &tuple
    ));

    assert_eq!(client.send_data(client_channel, b"one payload")?, 11);
    assert!(matches!(
        server.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::Data { data, .. } if data == b"one payload"
    ));

    client.request_cancel_tcpip_forward(b"127.0.0.1", 8080, true)?;
    let cancelled = server.dispatch_global_request()?;
    assert!(cancelled.accepted());
    assert_eq!(
        client.read_global_response()?,
        TcpipForwardResponse::Success
    );
    assert_eq!(server.binding_count(), 0);

    let before = server.connection().channel_count();
    assert!(matches!(
        server.open_forwarded(&tuple),
        Err(TcpipForwardError::NoBinding)
    ));
    assert_eq!(server.connection().channel_count(), before);
    Ok(())
}

#[test]
fn want_reply_false_changes_binding_without_writing_a_response() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server =
        ServerTcpipForward::with_allow_callback(server_transport, |_address, _port| true);

    client.request_tcpip_forward(b"127.0.0.1", 9000, false)?;
    let result = server.dispatch_global_request()?;
    assert!(result.accepted());
    assert_eq!(server.connection().transport().outgoing_len(), 0);
    assert!(server.has_binding(b"127.0.0.1", 9000));

    client.request_cancel_tcpip_forward(b"127.0.0.1", 9000, false)?;
    let cancelled = server.dispatch_global_request()?;
    assert!(cancelled.accepted());
    assert!(!server.has_binding(b"127.0.0.1", 9000));
    assert_eq!(server.connection().transport().outgoing_len(), 0);
    Ok(())
}

#[test]
fn port_zero_and_callback_panic_are_denials() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server =
        ServerTcpipForward::with_allow_callback(server_transport, |_address, _port| true);

    client.request_tcpip_forward(b"127.0.0.1", 0, true)?;
    let result = server.dispatch_global_request()?;
    assert!(!result.accepted());
    assert_eq!(
        client.read_global_response()?,
        TcpipForwardResponse::Failure
    );
    assert_eq!(server.binding_count(), 0);

    server.set_allow_callback(|_address, _port| panic!("policy must fail closed"));
    client.request_tcpip_forward(b"127.0.0.1", 8080, true)?;
    let result = server.dispatch_global_request()?;
    assert!(!result.accepted());
    assert_eq!(
        client.read_global_response()?,
        TcpipForwardResponse::Failure
    );
    assert_eq!(server.binding_count(), 0);
    Ok(())
}

#[test]
fn forwarded_open_requires_an_exact_live_binding() -> Result<(), Box<dyn StdError>> {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let mut client = ClientTcpipForward::new(client_transport);
    let mut server =
        ServerTcpipForward::with_allow_callback(server_transport, |_address, _port| true);
    let tuple = ForwardedTcpipTuple::new(b"127.0.0.1", 8080, b"192.0.2.1", 1)?;

    client.connection_mut().open_channel(
        9,
        FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes(),
        &tuple.encode()?,
    )?;
    let rejected = server.dispatch_one()?;
    assert!(matches!(
        rejected,
        tcpip_forward::TcpipForwardEvent::OpenRejected {
            reason: 1,
            tuple: Some(received),
            ..
        } if received == tuple
    ));
    assert_eq!(server.connection().channel_count(), 0);
    assert_eq!(server.connection().pending_open_count(), 0);
    assert!(matches!(
        client.dispatch_one()?,
        tcpip_forward::TcpipForwardEvent::OpenRejected {
            channel: Some(9),
            ..
        }
    ));
    Ok(())
}

#[test]
fn global_and_forwarded_wire_shapes_are_exact_and_bounded() -> Result<(), Box<dyn StdError>> {
    let request = TcpipForwardGlobalRequest::tcpip_forward(b"127.0.0.1", 8080, true)?;
    let encoded = request.encode()?;
    assert_eq!(encoded.first(), Some(&80));
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.read_byte()?, 80);
    assert_eq!(reader.read_string()?, TCPIP_FORWARD_REQUEST.as_bytes());
    assert!(reader.read_boolean()?);
    assert_eq!(reader.read_string()?, b"127.0.0.1");
    assert_eq!(reader.read_uint32()?, 8080);
    assert!(reader.is_empty());
    assert_eq!(TcpipForwardGlobalRequest::decode(&encoded)?, request);

    let mut trailing_request = Writer::new();
    trailing_request.write_byte(80);
    trailing_request.write_string(TCPIP_FORWARD_REQUEST)?;
    trailing_request.write_boolean(true);
    trailing_request.write_string("127.0.0.1")?;
    trailing_request.write_uint32(8080);
    trailing_request.write_byte(0);
    assert!(matches!(
        TcpipForwardGlobalRequest::decode(trailing_request.as_bytes()),
        Err(TcpipForwardError::TrailingBytes)
    ));

    let cancel = TcpipForwardGlobalRequest::cancel_tcpip_forward(b"", 8080, false)?;
    let cancel_bytes = cancel.encode()?;
    let mut cancel_reader = Reader::new(&cancel_bytes);
    assert_eq!(cancel_reader.read_byte()?, 80);
    assert_eq!(
        cancel_reader.read_string()?,
        CANCEL_TCPIP_FORWARD_REQUEST.as_bytes()
    );
    assert!(!cancel_reader.read_boolean()?);
    assert_eq!(cancel_reader.read_string()?, b"");
    assert_eq!(cancel_reader.read_uint32()?, 8080);
    assert!(cancel_reader.is_empty());

    let tuple = ForwardedTcpipTuple::new(b"::1", 443, b"127.0.0.1", 0)?;
    let tuple_bytes = tuple.encode()?;
    assert_eq!(ForwardedTcpipTuple::decode(&tuple_bytes)?, tuple);
    let mut trailing = tuple_bytes;
    trailing.push(0);
    assert!(matches!(
        ForwardedTcpipTuple::decode(&trailing),
        Err(TcpipForwardError::TrailingBytes)
    ));
    assert!(ForwardedTcpipTuple::new(b"", 443, b"127.0.0.1", 0).is_err());
    assert!(ForwardedTcpipTuple::new(b"::1", 0, b"127.0.0.1", 0).is_err());
    assert!(ForwardedTcpipTuple::new(b"::1", 443, b"127.0.0.1", 65_536).is_err());

    assert_eq!(
        TcpipForwardResponse::decode(&[81])?,
        TcpipForwardResponse::Success
    );
    assert_eq!(
        TcpipForwardResponse::decode(&[82])?,
        TcpipForwardResponse::Failure
    );
    assert!(TcpipForwardResponse::decode(&[81, 0]).is_err());
    Ok(())
}

#[test]
fn channel_helpers_use_the_published_connection_without_reimplementing_windowing() {
    let (client_transport, server_transport) = MemoryTransport::pair();
    let client = ClientTcpipForward::new(client_transport);
    let server = ServerTcpipForward::new(server_transport);
    let _: &ChannelConnection<_> = client.connection();
    let _: &ChannelConnection<_> = server.connection();
    let _ = std::mem::size_of::<ChannelId>();
    assert_eq!(client.connection().channel_count(), 0);
    assert_eq!(server.connection().pending_open_count(), 0);
    let _ = ChannelEvent::Data {
        channel: 0,
        data: Vec::new(),
    };
    let _: Option<Error> = None;
}

#[test]
fn module_has_no_external_forwarding_runtime() {
    let source = include_str!("../src/tcpip_forward.rs");
    assert!(!source.contains("std::net"));
    assert!(!source.contains("std::process"));
    assert!(!source.contains("std::thread"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("unwrap()"));
    assert!(!source.contains("expect("));
}
