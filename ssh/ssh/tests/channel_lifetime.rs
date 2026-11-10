//! Channel lifetime for the channel multiplexer.
//!
//! # What this file is for
//!
//! RFC 4254 §5.3: "The channel is considered closed for a party when it has
//! both sent and received `SSH_MSG_CHANNEL_CLOSE`, and the party may then reuse
//! the channel number." A multiplexer that never drops a closed channel can
//! therefore carry exactly one channel for the life of a connection, and one
//! that refuses a remote identifier another channel holds cannot even carry two:
//! OpenSSH's `channel_new` takes "a free slot" in the connection's table, so
//! every sequential session on a connection is confirmed with the same remote
//! identifier. Measured against OpenSSH 10.5p1, three sequential requests gave
//! one answer and then `SSH channel identifier is already active`.
//!
//! `ChannelConnection` is generic over [`ChannelTransport`] and buffers no
//! channel data, so these tests drive it through an in-memory transport and
//! assert on payloads rather than on a socket. That is the layer's own contract:
//! the packet *routing* is what is under test, not the transport underneath it.
//!
//! # The half-close ordering, which is the whole difficulty
//!
//! `SSH_MSG_CHANNEL_EOF` and `SSH_MSG_CHANNEL_CLOSE` are separate messages. A
//! peer may send `CLOSE` without ever sending `EOF` — the same section says so —
//! and `CHANNEL_DATA` for a channel can still be in flight when our own `CLOSE`
//! goes out. Reaping on the local close alone would discard exactly that data,
//! where RFC 4254 §5.3 asks the opposite: "It is RECOMMENDED that all data sent
//! before this message be delivered to the actual destination." A `CLOSE` we
//! sent says nothing about what the peer may still send us, and conflating the
//! two is the mistake these tests exist to catch.
//!
//! The tolerance contract — which connection-level messages this layer tolerates
//! — is in `channel_connection_level.rs`. The live counterpart is
//! `openssh_channels.rs`.

#![allow(missing_docs)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use neotales_ssh::Writer;
use neotales_ssh::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelTransport,
    SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_OPEN,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
};

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

/// A client endpoint and the server endpoint it is talking to.
struct Pair {
    client: ChannelConnection<End>,
    server: ChannelConnection<End>,
    client_end: End,
    server_end: End,
}

impl Pair {
    fn new() -> Self {
        let client_end = End::new();
        let server_end = End::new();
        Self {
            client: ChannelConnection::new(End {
                inner: Rc::clone(&client_end.inner),
            }),
            server: ChannelConnection::new(End {
                inner: Rc::clone(&server_end.inner),
            }),
            client_end,
            server_end,
        }
    }

    /// Feeds the client endpoint, i.e. the server-to-client direction.
    fn to_client(&self, payload: &[u8]) {
        self.client_end.feed(payload);
    }

    /// Feeds the server endpoint, i.e. the client-to-server direction.
    fn to_server(&self, payload: &[u8]) {
        self.server_end.feed(payload);
    }
}

// -- payload builders -------------------------------------------------------

fn channel_open(sender: ChannelId) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_OPEN);
    writer
        .write_string(b"session")
        .expect("in-memory string fits");
    writer.write_uint32(sender);
    writer.write_uint32(65_536);
    writer.write_uint32(32_768);
    writer.into_bytes()
}

fn channel_confirmation(recipient: ChannelId, sender: ChannelId) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    writer.write_uint32(recipient);
    writer.write_uint32(sender);
    writer.write_uint32(65_536);
    writer.write_uint32(32_768);
    writer.into_bytes()
}

fn channel_data(recipient: ChannelId, data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_DATA);
    writer.write_uint32(recipient);
    writer.write_string(data).expect("in-memory string fits");
    writer.into_bytes()
}

fn channel_eof(recipient: ChannelId) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_EOF);
    writer.write_uint32(recipient);
    writer.into_bytes()
}

fn channel_close(recipient: ChannelId) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_CHANNEL_CLOSE);
    writer.write_uint32(recipient);
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

// -- A closed channel is dropped, and a reused remote id is accepted -----

/// The behaviour the whole wall is about: three sequential channels on one
/// connection, and a fourth after a close. OpenSSH allocates the lowest free
/// session identifier on a connection, so every one of these is confirmed with
/// the *same* remote identifier — measured against OpenSSH 10.5p1, where
/// channels one through four all came back as remote identifier 1.
#[test]
fn sequential_channels_reuse_a_remote_identifier_after_a_close()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    // The *remote* identifier is the part that is reused, and reusing it is what
    // used to be refused. The local one advances past a retired identifier so a
    // straggler stays attributable; see `a_data_message_for_a_dropped_channel_is
    // _reported_not_rerouted`.
    for round in 0..4_u32 {
        let local = pair.client.allocate_channel_id()?;
        let _ = round;
        assert_eq!(local, round, "identifiers advance past the retired one");
        pair.client.open_channel(local, b"session", &[])?;
        // The same remote identifier every round, which is what a real server
        // does and what RFC 4254 §5.3 permits once the channel is closed for
        // both sides.
        let remote = 3;
        pair.to_client(&channel_confirmation(local, remote));
        match pair.client.dispatch_one()? {
            ChannelEvent::Opened(confirmed) => assert_eq!(confirmed, local),
            other => return Err(format!("round {round}: expected Opened, got {other:?}").into()),
        }
        let state = pair
            .client
            .channel(local)
            .ok_or("the confirmed channel should be present")?;
        assert_eq!(state.remote_id(), Some(remote));

        pair.client.send_close(local)?;
        pair.to_client(&channel_close(local));
        assert!(matches!(
            pair.client.dispatch_one()?,
            ChannelEvent::Close { channel } if channel == local
        ));
        // Dropped: the channel is gone, and its identifier is remembered as
        // retired rather than handed straight back out.
        assert!(pair.client.channel(local).is_none());
        assert_eq!(pair.client.channel_count(), 0);
        assert_eq!(
            pair.client.closed_channel_count(),
            (round + 1) as usize,
            "one retirement per round, still remembered"
        );
    }
    Ok(())
}

/// A channel crosses the RFC 4254 §5.3 close boundary only when *both* sides
/// have sent `SSH_MSG_CHANNEL_CLOSE`. Reaping on the local close alone would drop
/// `SSH_MSG_CHANNEL_DATA` the RFC asks to be delivered, because a peer may send
/// `CLOSE` without ever sending `EOF` and data can still be in flight.
#[test]
fn a_channel_survives_our_close_until_the_peers_close_arrives()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    // No EOF: RFC 4254 §5.3 says "A party MAY send SSH_MSG_CHANNEL_CLOSE without
    // having sent or received SSH_MSG_CHANNEL_EOF."
    pair.client.send_close(0)?;
    // Still present, still addressable, after our own close.
    assert_eq!(pair.client.channel_count(), 1);
    let state = pair.client.channel(0).ok_or("channel dropped early")?;
    assert!(state.local_close_sent());
    assert!(!state.remote_close_received());

    // Data sent before the peer's CLOSE must still be delivered. RFC 4254 §5.3:
    // "It is RECOMMENDED that all data sent before this message be delivered to
    // the actual destination." Dropping it here is the failure mode the boundary
    // exists to prevent, and this is the assertion that would catch it.
    pair.to_client(&channel_data(0, b"in-flight"));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Data { channel: 0, data } if data == b"in-flight"
    ));
    assert_eq!(pair.client.channel_count(), 1, "still not both-closed");

    // Only the peer's CLOSE completes the boundary.
    pair.to_client(&channel_close(0));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Close { channel: 0 }
    ));
    assert_eq!(pair.client.channel_count(), 0);
    Ok(())
}

/// The other ordering: the peer's `CLOSE` arrives first, so *our* `CLOSE` is
/// what completes the boundary, and the channel must be gone by the time
/// `send_close` returns.
#[test]
fn a_peer_close_completed_by_our_close_drops_the_channel() -> Result<(), Box<dyn std::error::Error>>
{
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    pair.to_client(&channel_close(0));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Close { channel: 0 }
    ));
    // Only one side has closed, so the channel is retained.
    assert_eq!(pair.client.channel_count(), 1);
    let state = pair
        .client
        .channel(0)
        .ok_or("retained after one-sided close")?;
    assert!(state.remote_close_received());
    assert!(!state.local_close_sent());

    pair.client.send_close(0)?;
    assert_eq!(pair.client.channel_count(), 0, "both sides closed");
    assert!(pair.client.channel(0).is_none());
    Ok(())
}

/// The risk the wall is really about: a late `SSH_MSG_CHANNEL_DATA` for a
/// channel that has already been dropped must not panic, must not hang, and must
/// not be silently routed onto whatever channel took the number next.
#[test]
fn a_data_message_for_a_dropped_channel_is_reported_not_rerouted()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    pair.client.send_close(0)?;
    pair.to_client(&channel_close(0));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Close { channel: 0 }
    ));
    assert_eq!(pair.client.channel_count(), 0);

    // Explicit-id APIs must honor the same retirement guard as the allocator.
    // Otherwise a late packet for channel 0 could land on this new channel.
    assert!(matches!(
        pair.client.open_channel(0, b"session", &[]),
        Err(ChannelError::ClosedChannel(0))
    ));

    // The identifier is still remembered, so a new channel does not take it.
    // That is what makes the straggler below attributable: the alternative is
    // delivering the previous channel's bytes into a new channel, which would
    // be silent corruption with no signal at all.
    let reused = pair.client.allocate_channel_id()?;
    assert_ne!(reused, 0, "a retired identifier is not handed out again");
    pair.client.open_channel(reused, b"session", &[])?;
    pair.to_client(&channel_confirmation(reused, 9));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Opened(id) if id == reused
    ));

    // The straggler names the retired identifier, which no live channel holds.
    pair.to_client(&channel_data(0, b"straggler"));
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::ClosedChannel(0))
    ));
    // The new channel is untouched: not failed, and the straggler was not
    // delivered to it.
    let state = pair
        .client
        .channel(reused)
        .ok_or("the new channel survived")?;
    assert!(!state.failed());
    Ok(())
}

/// A straggler for a channel dropped long ago is still reported rather than
/// routed, and the tombstone map that makes it possible is bounded so a
/// misbehaving peer cannot grow the connection's state without limit.
#[test]
fn the_tombstone_map_is_bounded_and_still_reports_old_retirements()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    let limit = neotales_ssh::channel::MAX_REMEMBERED_CLOSED_CHANNELS;
    // Retire more channels than the tombstone map holds.
    for round in 0..(limit + 32) {
        let local = ChannelId::try_from(round).expect("the loop bound fits a channel id");
        pair.client.open_channel(local, b"session", &[])?;
        pair.to_client(&channel_confirmation(local, local));
        let opened = pair.client.dispatch_one()?;
        assert!(matches!(opened, ChannelEvent::Opened(id) if id == local));
        pair.client.send_close(local)?;
        pair.to_client(&channel_close(local));
        assert!(matches!(
            pair.client.dispatch_one()?,
            ChannelEvent::Close { channel } if channel == local
        ));
        assert!(pair.client.channel(local).is_none());
    }
    assert_eq!(pair.client.closed_channel_count(), limit);
    assert_eq!(pair.client.channel_count(), 0);
    // The most recent retirement is still remembered; the oldest is not, which
    // is the bound doing its job.
    let newest = ChannelId::try_from(limit + 31).expect("the bound fits a channel id");
    assert!(pair.client.is_retired_channel(newest));
    assert!(!pair.client.is_retired_channel(0));
    // The first retirement fell out of the bound, so its identifier is free
    // again. That is the documented limit of the guarantee.
    assert_eq!(pair.client.allocate_channel_id()?, 0);
    Ok(())
}

/// `MAX_CHANNELS_PER_CONNECTION` was a per-connection *lifetime* ceiling before
/// a closed channel was dropped, so a connection could carry exactly one
/// channel for its whole life. It is a concurrency bound now, and a connection
/// that opens and closes more channels than the ceiling still works.
#[test]
fn the_channel_ceiling_bounds_concurrency_not_a_connections_lifetime()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    let ceiling = neotales_ssh::channel::MAX_CHANNELS_PER_CONNECTION;
    for _ in 0..(ceiling + 8) {
        let local = pair.client.allocate_channel_id()?;
        pair.client.open_channel(local, b"session", &[])?;
        pair.to_client(&channel_confirmation(local, local));
        let opened = pair.client.dispatch_one()?;
        assert!(matches!(opened, ChannelEvent::Opened(id) if id == local));
        pair.client.send_close(local)?;
        pair.to_client(&channel_close(local));
        assert!(matches!(
            pair.client.dispatch_one()?,
            ChannelEvent::Close { channel } if channel == local
        ));
    }
    assert_eq!(pair.client.channel_count(), 0);
    Ok(())
}

/// A duplicate *live* remote identifier is still a protocol error. Reuse is legal
/// only after a close, so the guard is scoped to what is actually held.
#[test]
fn a_remote_identifier_still_held_by_a_live_channel_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    let second = pair.client.allocate_channel_id()?;
    assert_eq!(second, 1);
    pair.client.open_channel(second, b"session", &[])?;
    // Confirmed with a remote identifier the open channel already holds.
    pair.to_client(&channel_confirmation(second, 7));
    assert!(matches!(
        pair.client.dispatch_one(),
        Err(ChannelError::DuplicateChannel)
    ));
    Ok(())
}

/// Our own EOF and CLOSE are both half-close signals until the peer closes too.
/// In particular, EOF forbids further sends in our direction, but RFC 4254
/// permits the peer to finish sending data in its direction.
#[test]
fn data_after_our_eof_or_close_is_delivered_until_remote_close()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    pair.client.send_eof(0)?;
    pair.to_client(&channel_data(0, b"after-our-eof"));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Data { channel: 0, data } if data == b"after-our-eof"
    ));

    let mut pair = Pair::new();
    open_and_confirm(&mut pair)?;
    pair.client.send_close(0)?;
    pair.to_client(&channel_data(0, b"after-our-close"));
    assert!(matches!(
        pair.client.dispatch_one()?,
        ChannelEvent::Data { channel: 0, data } if data == b"after-our-close"
    ));
    assert_eq!(
        pair.client.increase_local_window(0, 1),
        Err(ChannelError::InvalidMessage)
    );
    Ok(())
}

/// The server side of the same state machine, which is the direction a Docker
/// Engine connection does not use but which shares the multiplexer. A
/// server-accepted channel is dropped on the same boundary.
#[test]
fn an_accepted_channel_is_dropped_on_the_same_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair = Pair::new();
    pair.to_server(&channel_open(4));
    let ChannelEvent::OpenRequest(request) = pair.server.dispatch_one()? else {
        return Err("expected an open request".into());
    };
    assert_eq!(request.sender_channel(), 4);
    pair.server.confirm_open(4, 6)?;
    pair.to_server(&channel_eof(6));
    assert!(matches!(
        pair.server.dispatch_one()?,
        ChannelEvent::Eof { channel: 6 }
    ));
    pair.server.send_close(6)?;
    assert_eq!(pair.server.channel_count(), 1, "one side has not closed");
    pair.to_server(&channel_close(6));
    assert!(matches!(
        pair.server.dispatch_one()?,
        ChannelEvent::Close { channel: 6 }
    ));
    assert_eq!(pair.server.channel_count(), 0);
    // The identifiers are free again, so the peer may reuse them.
    assert_eq!(pair.server.allocate_channel_id()?, 0);
    Ok(())
}
