//! Connection-level tolerance for the channel multiplexer.
//!
//! # What this file is for
//!
//! A current `sshd` sends `SSH_MSG_GLOBAL_REQUEST hostkeys-00@openssh.com` as
//! the first payload after `SSH_MSG_USERAUTH_SUCCESS`, ahead of anything the
//! client asked for, and follows it with `SSH_MSG_DEBUG` traffic. A multiplexer
//! whose parser has only `SSH_MSG_CHANNEL_*` arms cannot open a channel against
//! a current OpenSSH at all. These tests pin the contract that fixes that, and
//! — just as importantly — pin what stays an error.
//!
//! `ChannelConnection` is generic over [`ChannelTransport`] and buffers no
//! channel data, so these tests drive it through an in-memory transport and
//! assert on payloads rather than on a socket. That is the layer's own contract:
//! the packet *routing* is what is under test, not the transport underneath it.
//!
//! ## The contract
//!
//! Six message numbers are legal at any time on an established connection, and
//! each gets the treatment its own section requires:
//!
//! * `SSH_MSG_IGNORE` (2), `SSH_MSG_DEBUG` (4) and `SSH_MSG_UNIMPLEMENTED` (3)
//!   are parsed, bounded, and dropped with no event. RFC 4253 §11.2 says
//!   implementations "MUST understand (and ignore)" the first at any time, §11.3
//!   allows them to ignore the second, and §11.4 says the third "MUST be
//!   otherwise ignored". A caller never sees them, so no caller's `match` has
//!   to carry a variant the RFC permits it to ignore.
//! * `SSH_MSG_GLOBAL_REQUEST` (80), `SSH_MSG_REQUEST_SUCCESS` (81) and
//!   `SSH_MSG_REQUEST_FAILURE` (82) are surfaced as events a caller can match,
//!   because RFC 4254 §4 requires an answer when "want reply" is true and
//!   because whether a request is honoured is a policy decision that belongs
//!   above the multiplexer.
//!
//! Everything else is still [`ChannelError::UnexpectedMessage`], and that
//! includes message numbers this layer *does* own. Over-tolerating is its own
//! defect: a stream that silently discards an `SSH_MSG_CHANNEL_*` it should have
//! honoured loses data with no signal, which is worse than one that fails.
//!
//! The live counterpart is `openssh_channels.rs`.

#![allow(missing_docs)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use neotales_ssh::MAX_PACKET_CONTENT;
use neotales_ssh::Writer;
use neotales_ssh::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelTransport,
    MAX_CHANNEL_DATA_SIZE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
    SSH_MSG_CHANNEL_WINDOW_ADJUST, SSH_MSG_DEBUG, SSH_MSG_GLOBAL_REQUEST, SSH_MSG_IGNORE,
    SSH_MSG_REQUEST_FAILURE, SSH_MSG_REQUEST_SUCCESS, SSH_MSG_UNIMPLEMENTED,
};

/// `SSH_MSG_USERAUTH_REQUEST`. Neither a channel message nor a connection-level
/// one, so it is a control for "still an error".
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// `SSH_MSG_SERVICE_ACCEPT`. Also fatal at this layer.
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// `SSH_MSG_KEXINIT`. A transport message, not a connection one.
const SSH_MSG_KEXINIT: u8 = 20;
/// `SSH_MSG_USERAUTH_PK_OK`. A user-authentication message.
const SSH_MSG_USERAUTH_PK_OK: u8 = 60;

/// One channel endpoint over a queue of payloads a test fills by hand.
///
/// Nothing is buffered between calls except the payloads the test queued, which
/// is what makes "the peer sent this between those two messages" expressible
/// without a cooperating server.
#[derive(Debug, Default)]
struct End {
    inner: Rc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    inbound: RefCell<VecDeque<Vec<u8>>>,
    sent: RefCell<Vec<Vec<u8>>>,
}

impl End {
    fn new() -> Self {
        Self {
            inner: Rc::default(),
        }
    }

    /// Queues one payload for the next `dispatch_one` on this endpoint.
    fn feed(&self, payload: &[u8]) {
        self.inner.inbound.borrow_mut().push_back(payload.to_vec());
    }

    /// The payloads this endpoint has written, oldest first.
    fn written(&self) -> Vec<Vec<u8>> {
        self.inner.sent.borrow().clone()
    }
}

impl ChannelTransport for End {
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.inner.sent.borrow_mut().push(payload.to_vec());
        Ok(())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        // An empty queue means the test asked for a payload that was never
        // queued. Fabricating one would hide a dispatch bug, so this is a
        // distinct failure the assertions below cannot mistake for data.
        self.inner.inbound.borrow_mut().pop_front().ok_or(())
    }
}

/// One client endpoint, fed by the test in the server-to-client direction.
///
/// The tolerated set is the same in both directions — it is a property of the
/// message number — so every lane here drives the client side and the live lanes
/// in `openssh_channels.rs` cover the same contract against a real `sshd`.
struct Pair {
    client: ChannelConnection<End>,
    client_end: End,
}

impl Pair {
    fn new() -> Self {
        let client_end = End::new();
        Self {
            client: ChannelConnection::new(End {
                inner: Rc::clone(&client_end.inner),
            }),
            client_end,
        }
    }

    /// Feeds the client endpoint, i.e. the server-to-client direction.
    fn to_client(&self, payload: &[u8]) {
        self.client_end.feed(payload);
    }

    /// The payloads the endpoint has written, oldest first.
    fn client_sent(&self) -> Vec<Vec<u8>> {
        self.client_end.written()
    }
}

// -- payload builders -------------------------------------------------------

fn channel_confirmation(recipient: ChannelId, sender: ChannelId) -> Vec<u8> {
    channel_confirmation_with_max(recipient, sender, 32_768)
}

fn channel_confirmation_with_max(
    recipient: ChannelId,
    sender: ChannelId,
    maximum_packet_size: u32,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    writer.write_uint32(recipient);
    writer.write_uint32(sender);
    writer.write_uint32(65_536);
    writer.write_uint32(maximum_packet_size);
    writer.into_bytes()
}

fn channel_data(recipient: ChannelId, data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_DATA);
    writer.write_uint32(recipient);
    writer.write_string(data).expect("in-memory string fits");
    writer.into_bytes()
}

fn global_request(name: &[u8], want_reply: bool) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_GLOBAL_REQUEST);
    writer.write_string(name).expect("in-memory string fits");
    writer.write_boolean(want_reply);
    writer.into_bytes()
}

fn global_request_with_data(name: &[u8], want_reply: bool, data: &[u8]) -> Vec<u8> {
    let mut payload = global_request(name, want_reply);
    payload.extend_from_slice(data);
    payload
}

fn request_success(data: &[u8]) -> Vec<u8> {
    let mut payload = vec![SSH_MSG_REQUEST_SUCCESS];
    payload.extend_from_slice(data);
    payload
}

fn request_failure(data: &[u8]) -> Vec<u8> {
    let mut payload = vec![SSH_MSG_REQUEST_FAILURE];
    payload.extend_from_slice(data);
    payload
}

fn ignore_message(data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_IGNORE);
    writer.write_string(data).expect("in-memory string fits");
    writer.into_bytes()
}

fn debug_message(always_display: bool, message: &[u8], language: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_DEBUG);
    writer.write_boolean(always_display);
    writer.write_string(message).expect("in-memory string fits");
    writer
        .write_string(language)
        .expect("in-memory string fits");
    writer.into_bytes()
}

fn unimplemented_message(sequence: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_UNIMPLEMENTED);
    writer.write_uint32(sequence);
    writer.into_bytes()
}

/// Opens local channel 0 and confirms it with remote identifier 7.
fn open_and_confirm(pair: &mut Pair) -> Result<ChannelId, Box<dyn std::error::Error>> {
    pair.client.open_channel(0, b"session", &[])?;
    pair.to_client(&channel_confirmation(0, 7));
    match pair.client.dispatch_one()? {
        ChannelEvent::Opened(id) => Ok(id),
        other => Err(format!("open_and_confirm: expected Opened, got {other:?}").into()),
    }
}

// -- Wall 1: what must be tolerated at the multiplexing layer ----------------

/// A current OpenSSH `sshd` sends `hostkeys-00@openssh.com` as the first
/// payload after `SSH_MSG_USERAUTH_SUCCESS`, ahead of any channel. RFC 4254 §4
/// makes a global request legal at any time, so it must be surfaced rather than
/// being fatal.
///
/// The name and the `want_reply` flag are exactly what the real daemon sends:
/// `sshd`'s `notify_hostkeys` writes `hostkeys-00@openssh.com` with
/// `sshpkt_put_u8(ssh, 0)` for want-reply, and `sshd-session.c` calls it
/// immediately before `do_authenticated`. This was measured against OpenSSH
/// 10.5p1, where it is byte 80 and the first payload after message 52.
#[test]
fn a_global_request_is_surfaced_rather_than_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    pair.to_client(&global_request_with_data(
        b"hostkeys-00@openssh.com",
        false,
        b"key-blob",
    ));
    match pair.client.dispatch_one()? {
        ChannelEvent::GlobalRequest {
            request_name,
            want_reply,
            data,
        } => {
            assert_eq!(request_name, b"hostkeys-00@openssh.com");
            assert!(!want_reply, "sshd sets want reply to zero for hostkeys");
            assert_eq!(data, b"key-blob");
        }
        other => return Err(format!("expected a global request, got {other:?}").into()),
    }
    Ok(())
}

/// The three global-request replies are connection-level and in-order, RFC 4254
/// §4, and a caller pairing them with its own outstanding-request queue has to
/// be able to tell success from failure and read the response data.
#[test]
fn global_request_replies_are_surfaced_with_their_response_data()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    // `tcpip-forward` with port 0 answers with the bound port, which RFC 4254
    // §7.1 defines as the one place a global-request reply carries data.
    pair.to_client(&request_success(&22_u16.to_be_bytes()));
    match pair.client.dispatch_one()? {
        ChannelEvent::GlobalRequestSucceeded { data } => {
            assert_eq!(data, 22_u16.to_be_bytes());
        }
        other => return Err(format!("expected success, got {other:?}").into()),
    }
    pair.to_client(&request_failure(b""));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::GlobalRequestFailed { data } if data.is_empty()
    ));
    Ok(())
}

#[test]
fn peer_packet_limit_is_capped_to_the_transport_safe_channel_size() {
    let mut pair = Pair::new();
    pair.client
        .open_channel(7, b"session", &[])
        .expect("the test channel opens");
    pair.to_client(&channel_confirmation_with_max(
        7,
        11,
        u32::try_from(MAX_PACKET_CONTENT).expect("the transport limit fits u32"),
    ));
    assert!(matches!(
        pair.client.dispatch_one(),
        Ok(ChannelEvent::Opened(7))
    ));
    assert_eq!(
        pair.client
            .channel(7)
            .expect("the channel remains open")
            .remote_maximum_packet_size(),
        u32::try_from(MAX_CHANNEL_DATA_SIZE).expect("the channel limit fits u32")
    );
}

/// A layer with no global-request policy still has to answer when the peer asked
/// for an answer, and then keep reading. This is the loop a session or
/// direct-tcpip endpoint runs, and it is what makes the tolerance invisible to a
/// caller that only cares about channels.
#[test]
fn a_policy_free_layer_answers_an_unhandled_global_request_and_keeps_reading()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    let before = pair.client_sent().len();
    // `no-more-sessions@openssh.com` is a real OpenSSH global request that a
    // session endpoint has no policy for, and it arrives with want-reply set.
    pair.to_client(&global_request(b"no-more-sessions@openssh.com", true));
    // The next channel payload must still be delivered, which is only possible
    // if the global request was consumed rather than turned into an error.
    pair.to_client(&channel_data(0, b"payload-after-global-request"));
    match pair.client.dispatch_channel_event()? {
        Some(ChannelEvent::Data { channel, data }) => {
            assert_eq!(channel, 0);
            assert_eq!(data, b"payload-after-global-request");
        }
        other => return Err(format!("expected the channel data, got {other:?}").into()),
    }
    // RFC 4254 §4 obliges an answer, and FAILURE is the answer for a request the
    // recipient does not support: "If the recipient does not recognize or
    // support the request, it simply responds with SSH_MSG_REQUEST_FAILURE."
    // OpenSSH's `client_input_global_request` does the same for a request type
    // it does not recognise.
    let written = pair.client_sent();
    assert_eq!(written.len(), before + 1);
    assert_eq!(
        written.last().map(Vec::as_slice),
        Some([SSH_MSG_REQUEST_FAILURE].as_slice())
    );
    Ok(())
}

/// The same, for a request that asks for no reply: RFC 4254 §4 only obliges an
/// answer when one was asked for, so nothing is written and reading continues.
#[test]
fn a_global_request_without_want_reply_is_answered_with_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    let before = pair.client_sent().len();
    pair.to_client(&global_request(b"hostkeys-00@openssh.com", false));
    pair.to_client(&channel_data(0, b"after"));
    assert!(matches!(
        pair.client.dispatch_channel_event()?,
        Some(ChannelEvent::Data { channel: 0, .. })
    ));
    assert_eq!(pair.client_sent().len(), before, "no reply was owed");
    Ok(())
}

/// The RFC 4253 §11 trio. All three must be understood and otherwise ignored,
/// which means they produce no event and cost the caller nothing: a peer is
/// entitled to send them between any two channel messages.
#[test]
fn ignore_debug_and_unimplemented_are_dropped_between_channel_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    // Interleaved with real traffic, in the order a peer may send it. This is
    // the mid-packet-stream case: the ignorable messages sit between two
    // payloads the caller does care about.
    let before = channel_data(0, b"before");
    let after = channel_data(0, b"after");
    let empty_ignore = ignore_message(b"");
    let padded_ignore = ignore_message(&[0_u8; 64]);
    let displayed = debug_message(true, b"debug1: ready", b"en");
    let hidden = debug_message(false, b"debug2: noise", b"");
    pair.to_client(&empty_ignore);
    pair.to_client(&displayed);
    pair.to_client(&before);
    pair.to_client(&padded_ignore);
    pair.to_client(&unimplemented_message(41));
    pair.to_client(&hidden);
    pair.to_client(&after);

    let mut received = Vec::new();
    for _ in 0..2 {
        match pair.client.dispatch_one()? {
            ChannelEvent::Data { channel, data } => {
                assert_eq!(channel, 0);
                received.push(data);
            }
            other => {
                return Err(format!(
                    "a message RFC 4253 §11 requires be ignored reached the caller: {other:?}"
                )
                .into());
            }
        }
    }
    assert_eq!(received, vec![b"before".to_vec(), b"after".to_vec()]);
    Ok(())
}

/// Being tolerant is a property of the *message number*, not a licence to skip
/// validation. A malformed `SSH_MSG_IGNORE` is still a wire error, because the
/// payload framing is what bounds it and a bad length is what a receiver has to
/// defend against.
#[test]
fn a_malformed_tolerated_message_is_still_an_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    // SSH_MSG_IGNORE claiming a u32::MAX string with no body behind it.
    let mut truncated = vec![SSH_MSG_IGNORE];
    truncated.extend_from_slice(&u32::MAX.to_be_bytes());
    pair.to_client(&truncated);
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::Wire(_))
    ));
    // SSH_MSG_DEBUG truncated before its message string.
    pair.to_client(&[SSH_MSG_DEBUG, 0]);
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::Wire(_))
    ));
    // SSH_MSG_UNIMPLEMENTED missing its sequence number.
    pair.to_client(&[SSH_MSG_UNIMPLEMENTED, 0, 0]);
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::Wire(_))
    ));
    // The channel survived all three: the errors were wire-level, not
    // channel-level, and did not mark it failed.
    assert!(pair.client.channel(0).is_some_and(|state| !state.failed()));
    Ok(())
}

/// Over-tolerating is its own defect. The tolerated set is the six numbers RFC
/// 4253 §11 and RFC 4254 §4 name, and a message outside it stays fatal.
#[test]
fn messages_outside_the_tolerated_set_remain_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    for number in [
        SSH_MSG_USERAUTH_REQUEST,
        1, // SSH_MSG_DISCONNECT
        SSH_MSG_SERVICE_ACCEPT,
        SSH_MSG_KEXINIT,
        21, // SSH_MSG_NEWKEYS
        30, // a key-exchange method message
        60,
        SSH_MSG_USERAUTH_PK_OK,
        79, // last unassigned user-authentication number
        83, // first unassigned connection-protocol number
        101,
        200,
        255,
    ] {
        pair.to_client(&[number, 0, 0, 0, 0]);
        assert!(
            matches!(
                pair.client.dispatch_one(),
                Err(ChannelError::UnexpectedMessage(found)) if found == number
            ),
            "message {number} should not be tolerated"
        );
    }
    // The connection is still usable, so a failure above did not corrupt state.
    pair.to_client(&channel_data(0, b"after-fatal-messages"));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Data { channel: 0, .. }
    ));
    Ok(())
}

/// A `SSH_MSG_CHANNEL_*` this layer could not honour is an error, and the
/// tolerance above does not absorb it. Silently discarding a channel message
/// would be worse than the defect this work replaced: a client that drops
/// `SSH_MSG_CHANNEL_DATA` loses data with no signal, where one that fails says
/// so.
#[test]
fn unhonourable_channel_messages_still_fail_the_channel() -> Result<(), Box<dyn std::error::Error>>
{
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    // A zero window adjustment, which RFC 4254 §5.2 rules out and the layer
    // rejects explicitly.
    let mut zero = Writer::new();
    zero.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    zero.write_uint32(0);
    zero.write_uint32(0);
    pair.to_client(zero.as_bytes());
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::InvalidWindowAdjustment)
    ));
    // The channel is marked failed rather than silently left usable, and it
    // stays failed: a second defect on a failed channel is still an error, not a
    // silently dropped payload.
    assert!(pair.client.channel(0).is_some_and(|state| state.failed()));
    pair.to_client(&channel_data(0, b"still-dropped"));
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::InvalidMessage)
    ));
    Ok(())
}

/// A payload over the transport bound is rejected before anything is routed, so
/// the tolerance for connection-level messages does not extend to unbounded
/// ones.
#[test]
fn an_oversized_global_request_data_field_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    // The multiplexer itself bounds the request name; the data field is what
    // remains, and it is checked against the transport limit.
    let mut payload = global_request(&vec![b'a'; 257], false);
    let oversized = u32::try_from(MAX_PACKET_CONTENT + 1).expect("the limit fits a u32");
    payload.extend_from_slice(&oversized.to_be_bytes());
    pair.to_client(&payload);
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::Wire(_))
    ));
    Ok(())
}
