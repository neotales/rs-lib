// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/sequence.rs"]
mod sequence;

use sequence::{
    Direction, InitialKexPolicy, KEX_STRICT_C_V00_OPENSSH, KEX_STRICT_S_V00_OPENSSH,
    PacketDisposition, REKEY_INBOUND_PACKET_SLOTS, REKEY_OUTBOUND_PACKET_SLOTS, RekeyPhase,
    RekeyPolicy, SSH_MSG_DEBUG, SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_KEX_METHOD_FIRST,
    SSH_MSG_KEX_METHOD_LAST, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS, SSH_MSG_UNIMPLEMENTED,
    SequenceError, SequenceState, filter_kex_algorithms, negotiate_kex_algorithm,
    strict_kex_negotiated,
};

const KEX_ALGORITHM: &str = "curve25519-sha256";

#[test]
fn strict_markers_require_both_roles_and_are_filtered_before_selection() {
    let client = [
        KEX_ALGORITHM,
        KEX_STRICT_C_V00_OPENSSH,
        KEX_STRICT_S_V00_OPENSSH,
    ];
    let server = [KEX_STRICT_S_V00_OPENSSH, KEX_ALGORITHM];

    assert!(strict_kex_negotiated(client, server));
    assert!(!strict_kex_negotiated([KEX_ALGORITHM], server));
    assert!(!strict_kex_negotiated(client, [KEX_STRICT_C_V00_OPENSSH]));
    assert_eq!(filter_kex_algorithms(client), [KEX_ALGORITHM.to_owned()]);
    assert_eq!(
        negotiate_kex_algorithm(client, server),
        Some(KEX_ALGORITHM.to_owned())
    );
    assert_eq!(
        negotiate_kex_algorithm(
            [KEX_STRICT_C_V00_OPENSSH, KEX_STRICT_S_V00_OPENSSH],
            [KEX_STRICT_C_V00_OPENSSH, KEX_STRICT_S_V00_OPENSSH]
        ),
        None
    );
    assert_eq!(
        negotiate_kex_algorithm([KEX_ALGORITHM], [KEX_STRICT_C_V00_OPENSSH, KEX_ALGORITHM]),
        Some(KEX_ALGORITHM.to_owned())
    );
}

#[test]
fn counters_start_at_zero_and_observation_does_not_consume_them() {
    let mut state = SequenceState::new();

    assert_eq!(state.inbound_sequence(), 0);
    assert_eq!(state.outbound_sequence(), 0);
    assert_eq!(
        state.classify_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(state.inbound_sequence(), 0);
    assert_eq!(state.outbound_sequence(), 0);

    assert_eq!(state.commit_inbound(), Ok(0));
    assert_eq!(state.inbound_sequence(), 1);
    assert_eq!(state.commit_inbound(), Ok(1));
    assert_eq!(state.commit_outbound(), Ok(0));
    assert_eq!(state.inbound_sequence(), 2);
    assert_eq!(state.outbound_sequence(), 1);
}

#[test]
fn exhaustion_is_reported_before_wrap_without_changing_the_counter() {
    let mut state = SequenceState::with_counters(u32::MAX - 2, 4);

    assert!(!state.needs_rekey(Direction::Inbound));
    assert_eq!(state.commit_inbound(), Ok(u32::MAX - 2));
    assert!(state.needs_rekey(Direction::Inbound));
    assert_eq!(state.commit_inbound(), Ok(u32::MAX - 1));
    assert_eq!(state.inbound_sequence(), u32::MAX);
    assert_eq!(state.commit_inbound(), Err(SequenceError::CounterExhausted));
    assert_eq!(state.inbound_sequence(), u32::MAX);
}

#[test]
fn rekey_requires_sequence_headroom_before_it_starts() {
    let mut state = SequenceState::with_counters_and_strict(
        u32::MAX - REKEY_INBOUND_PACKET_SLOTS + 1,
        u32::MAX - REKEY_OUTBOUND_PACKET_SLOTS + 1,
        false,
    );
    complete_initial_kex(&mut state);
    assert!(!state.rekey_headroom_available());
    assert_eq!(state.begin_rekey(), Err(SequenceError::CounterExhausted));
    assert!(!state.rekey_active());

    let mut available = SequenceState::with_counters_and_strict(
        u32::MAX - REKEY_INBOUND_PACKET_SLOTS,
        u32::MAX - REKEY_OUTBOUND_PACKET_SLOTS,
        false,
    );
    complete_initial_kex(&mut available);
    assert!(available.rekey_headroom_available());
    assert_eq!(available.begin_rekey(), Ok(()));
}

#[test]
fn strict_initial_kex_has_the_required_order_and_resets_once() {
    let mut state = SequenceState::with_strict_kex(true);

    assert_eq!(
        state.observe_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_KEX_METHOD_FIRST),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEX_METHOD_LAST),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(state.commit_inbound(), Ok(0));
    assert_eq!(state.commit_outbound(), Ok(0));
    assert_eq!(
        state.observe_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.inbound_sequence(), 1);
    assert_eq!(state.outbound_sequence(), 1);
    assert_eq!(state.complete_initial_kex(), Ok(()));
    assert_eq!(state.inbound_sequence(), 0);
    assert_eq!(state.outbound_sequence(), 0);
    assert!(state.strict_reset_applied());
    assert_eq!(
        state.complete_initial_kex(),
        Err(SequenceError::ResetAlreadyPerformed)
    );
    assert!(state.is_terminal());
}

#[test]
fn non_strict_initial_kex_preserves_counters_and_rekey_does_not_reset() {
    let mut state = SequenceState::new();
    assert_eq!(state.commit_inbound(), Ok(0));
    assert_eq!(state.commit_outbound(), Ok(0));

    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(state.observe_inbound(30), Ok(PacketDisposition::KexMethod));
    assert_eq!(state.observe_outbound(31), Ok(PacketDisposition::KexMethod));
    assert_eq!(
        state.observe_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.complete_initial_kex(), Ok(()));
    assert_eq!(state.inbound_sequence(), 1);
    assert_eq!(state.outbound_sequence(), 1);

    assert_eq!(state.complete_rekey(), Ok(()));
    assert_eq!(state.inbound_sequence(), 1);
    assert_eq!(state.outbound_sequence(), 1);
    assert_eq!(state.commit_inbound(), Ok(1));
    assert_eq!(state.commit_outbound(), Ok(1));
    assert_eq!(state.inbound_sequence(), 2);
    assert_eq!(state.outbound_sequence(), 2);
}

#[test]
fn strict_mode_rejects_ignorable_packets_and_becomes_terminal() {
    let mut state = SequenceState::with_strict_kex(true);

    assert_eq!(
        state.observe_inbound(SSH_MSG_IGNORE),
        Err(SequenceError::StrictViolation)
    );
    assert!(state.is_terminal());
    assert_eq!(state.phase(), sequence::KexPhase::Terminal);
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::Terminal)
    );
    assert_eq!(state.commit_inbound(), Err(SequenceError::Terminal));
}

#[test]
fn non_strict_ignore_debug_and_unimplemented_do_not_advance_the_phase() {
    let mut state = SequenceState::new();

    for message_type in [SSH_MSG_IGNORE, SSH_MSG_DEBUG, SSH_MSG_UNIMPLEMENTED] {
        assert_eq!(
            state.classify(message_type),
            Ok(PacketDisposition::Ignorable)
        );
        assert_eq!(
            state.observe(message_type),
            Ok(PacketDisposition::Ignorable)
        );
        assert_eq!(state.phase(), sequence::KexPhase::KexInit);
    }
    assert_eq!(state.inbound_sequence(), 0);
    assert_eq!(state.outbound_sequence(), 0);
}

#[test]
fn disconnect_is_a_clean_terminal_disposition() {
    let mut state = SequenceState::new();

    assert_eq!(
        state.observe_inbound(SSH_MSG_DISCONNECT),
        Ok(PacketDisposition::Disconnect)
    );
    assert!(state.is_terminal());
    assert_eq!(
        state.observe_outbound(SSH_MSG_KEXINIT),
        Err(SequenceError::Terminal)
    );
    assert_eq!(state.outbound_sequence(), 0);
}

#[test]
fn out_of_order_and_repeated_transitions_are_terminal() {
    let mut early_method = SequenceState::new();
    assert_eq!(
        early_method.observe_inbound(30),
        Err(SequenceError::OutOfOrder)
    );
    assert!(early_method.is_terminal());

    let mut repeated_init = SequenceState::new();
    assert_eq!(
        repeated_init.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        repeated_init.observe_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::OutOfOrder)
    );
    assert!(repeated_init.is_terminal());

    let mut repeated_newkeys = SequenceState::new();
    assert_eq!(
        repeated_newkeys.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        repeated_newkeys.observe_inbound(30),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(
        repeated_newkeys.observe_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(
        repeated_newkeys.observe_inbound(SSH_MSG_NEWKEYS),
        Err(SequenceError::OutOfOrder)
    );
    assert!(repeated_newkeys.is_terminal());
}

#[test]
fn guessed_first_kex_packets_follow_strict_policy() {
    let mut strict = SequenceState::with_strict_kex(true);
    assert_eq!(
        strict.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        strict.observe_guessed_inbound(30),
        Ok(PacketDisposition::Ignorable)
    );
    assert!(!strict.is_terminal());

    let mut early_non_strict = SequenceState::new();
    assert_eq!(
        early_non_strict.observe_guessed_inbound(30),
        Err(SequenceError::OutOfOrder)
    );
    assert!(early_non_strict.is_terminal());

    let mut non_strict = SequenceState::new();
    assert_eq!(
        non_strict.observe_kexinit(Direction::Inbound, true),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        non_strict.observe_guessed_inbound(30),
        Ok(PacketDisposition::Ignorable)
    );
    assert_eq!(non_strict.inbound_phase(), sequence::KexPhase::KexMethod);

    let mut rekey = SequenceState::with_strict_kex(true);
    complete_initial_kex(&mut rekey);
    rekey.begin_rekey().unwrap();
    assert_eq!(
        rekey.observe_rekey_kexinit(Direction::Inbound, true),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        rekey.observe_rekey_guessed_inbound(30),
        Ok(PacketDisposition::Ignorable)
    );
    assert!(!rekey.is_terminal());
}

#[test]
fn the_initial_policy_rejects_packets_after_established_but_counters_continue() {
    let mut state = SequenceState::with_strict_kex(true);
    complete_initial_kex(&mut state);

    assert_eq!(
        state.classify_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::AfterEstablished)
    );
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::AfterEstablished)
    );
    assert!(!state.is_terminal());
    assert_eq!(state.commit_inbound(), Ok(0));
    assert_eq!(state.inbound_sequence(), 1);
    assert_eq!(state.complete_rekey(), Ok(()));
    assert_eq!(state.inbound_sequence(), 1);
}

#[test]
fn a_policy_can_be_used_without_sequence_counters() {
    let mut policy = InitialKexPolicy::with_strict_kex(true);
    assert_eq!(
        policy.classify_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        policy.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(policy.observe_inbound(30), Ok(PacketDisposition::KexMethod));
    assert_eq!(
        policy.observe_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert!(policy.inbound_newkeys_received());
    assert!(!policy.outbound_newkeys_sent());
    assert_eq!(
        policy.complete_initial_kex(),
        Err(SequenceError::Incomplete)
    );
    assert!(policy.is_terminal());
}

#[test]
fn post_establishment_rekey_requires_kexinit_before_method_and_newkeys() {
    let mut state = SequenceState::new();
    complete_initial_kex(&mut state);

    assert_eq!(state.begin_rekey(), Ok(()));
    assert_eq!(state.rekey_phase(), RekeyPhase::KexInit);
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEX_METHOD_FIRST),
        Err(SequenceError::OutOfOrder)
    );
    assert!(state.rekey_is_terminal());
    assert!(!state.rekey_is_complete());
    assert_eq!(state.commit_inbound(), Err(SequenceError::Terminal));
}

#[test]
fn rekey_rejects_duplicate_reentrant_and_incomplete_transitions() {
    let mut duplicate = RekeyPolicy::new();
    assert_eq!(duplicate.begin_rekey(), Ok(()));
    assert_eq!(
        duplicate.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        duplicate.observe_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::OutOfOrder)
    );
    assert!(duplicate.is_terminal());
    assert!(!duplicate.is_complete());

    let mut reentrant = RekeyPolicy::new();
    assert_eq!(reentrant.begin_rekey(), Ok(()));
    assert_eq!(reentrant.begin_rekey(), Err(SequenceError::InvalidState));
    assert!(reentrant.is_terminal());
    assert!(!reentrant.is_complete());

    let mut incomplete = RekeyPolicy::new();
    assert_eq!(incomplete.begin_rekey(), Ok(()));
    assert_eq!(
        incomplete.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        incomplete.observe_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(incomplete.complete_rekey(), Err(SequenceError::Incomplete));
    assert!(incomplete.is_terminal());
    assert!(!incomplete.is_complete());
}

#[test]
fn strict_rekey_resets_each_counter_at_its_newkeys_boundary() {
    let mut state = SequenceState::with_strict_kex(true);
    complete_initial_kex(&mut state);
    for _ in 0..4 {
        assert!(state.commit_inbound().is_ok());
        assert!(state.commit_outbound().is_ok());
    }
    let (inbound_before, outbound_before) = (state.inbound_sequence(), state.outbound_sequence());
    assert_eq!(state.begin_rekey(), Ok(()));
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(state.commit_inbound(), Ok(inbound_before));
    assert_eq!(state.commit_outbound(), Ok(outbound_before));
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEX_METHOD_FIRST),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_KEX_METHOD_LAST),
        Ok(PacketDisposition::KexMethod)
    );
    let inbound_method = state.commit_inbound().expect("inbound method commits");
    let outbound_method = state.commit_outbound().expect("outbound method commits");
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.inbound_sequence(), 0);
    assert_eq!(state.outbound_sequence(), outbound_method + 1);
    assert!(state.rekey_reset_applied(Direction::Inbound));
    assert!(!state.rekey_reset_applied(Direction::Outbound));
    assert!(state.rekey_reset_pending(Direction::Inbound));
    assert_eq!(state.commit_inbound(), Ok(inbound_method + 1));

    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.outbound_sequence(), 0);
    assert!(state.rekey_reset_applied(Direction::Outbound));
    assert_eq!(state.commit_outbound(), Ok(outbound_method + 1));
    assert_eq!(state.complete_rekey_exchange(), Ok(()));
    assert!(state.rekey_is_complete());
    assert!(!state.rekey_reset_pending(Direction::Inbound));
    assert!(!state.rekey_reset_pending(Direction::Outbound));
}

#[test]
fn strict_rekey_completion_rejects_pending_directional_newkeys_commits() {
    for pending_direction in [Direction::Inbound, Direction::Outbound] {
        let mut state = SequenceState::with_strict_kex(true);
        complete_initial_kex(&mut state);
        assert_eq!(state.begin_rekey(), Ok(()));
        assert_eq!(
            state.observe_rekey_inbound(SSH_MSG_KEXINIT),
            Ok(PacketDisposition::KexInit)
        );
        assert_eq!(
            state.observe_rekey_outbound(SSH_MSG_KEXINIT),
            Ok(PacketDisposition::KexInit)
        );
        assert_eq!(state.commit_inbound(), Ok(0));
        assert_eq!(state.commit_outbound(), Ok(0));
        assert_eq!(
            state.observe_rekey_inbound(SSH_MSG_KEX_METHOD_FIRST),
            Ok(PacketDisposition::KexMethod)
        );
        assert_eq!(
            state.observe_rekey_outbound(SSH_MSG_KEX_METHOD_LAST),
            Ok(PacketDisposition::KexMethod)
        );
        assert_eq!(state.commit_inbound(), Ok(1));
        assert_eq!(state.commit_outbound(), Ok(1));
        assert_eq!(
            state.observe_rekey_inbound(SSH_MSG_NEWKEYS),
            Ok(PacketDisposition::NewKeys)
        );
        assert_eq!(
            state.observe_rekey_outbound(SSH_MSG_NEWKEYS),
            Ok(PacketDisposition::NewKeys)
        );

        let other_direction = match pending_direction {
            Direction::Inbound => Direction::Outbound,
            Direction::Outbound => Direction::Inbound,
        };
        assert!(state.commit(other_direction).is_ok());
        assert!(state.rekey_reset_pending(pending_direction));
        assert!(!state.rekey_reset_pending(other_direction));
        assert_eq!(
            state.complete_rekey_exchange(),
            Err(SequenceError::Incomplete)
        );
        assert!(state.rekey_is_terminal());
        assert!(!state.rekey_is_complete());
        assert_eq!(
            state.commit(pending_direction),
            Err(SequenceError::Terminal)
        );
    }
}

#[test]
fn non_strict_rekey_preserves_both_counters() {
    let mut state = SequenceState::new();
    complete_initial_kex(&mut state);
    assert_eq!(state.commit_inbound(), Ok(0));
    assert_eq!(state.commit_outbound(), Ok(0));
    let (inbound_before, outbound_before) = (state.inbound_sequence(), state.outbound_sequence());

    assert_eq!(state.begin_rekey(), Ok(()));
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(state.commit_inbound(), Ok(inbound_before));
    assert_eq!(state.commit_outbound(), Ok(outbound_before));
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEX_METHOD_FIRST),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_KEX_METHOD_FIRST),
        Ok(PacketDisposition::KexMethod)
    );
    assert_eq!(state.commit_inbound(), Ok(inbound_before + 1));
    assert_eq!(state.commit_outbound(), Ok(outbound_before + 1));
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(
        state.observe_rekey_outbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.inbound_sequence(), inbound_before + 2);
    assert_eq!(state.outbound_sequence(), outbound_before + 2);
    assert_eq!(state.commit_inbound(), Ok(inbound_before + 2));
    assert_eq!(state.commit_outbound(), Ok(outbound_before + 2));
    assert_eq!(state.complete_rekey_exchange(), Ok(()));
    assert!(state.rekey_is_complete());
}

#[test]
fn a_rekey_cannot_start_before_initial_establishment_and_failure_is_terminal() {
    let mut early = SequenceState::new();
    assert_eq!(
        early.observe_rekey_inbound(SSH_MSG_KEXINIT),
        Err(SequenceError::InvalidState)
    );
    assert!(early.rekey_is_terminal());
    assert!(!early.rekey_is_complete());

    let mut state = SequenceState::new();
    complete_initial_kex(&mut state);
    assert_eq!(
        state.observe_rekey_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert!(state.rekey_active());
    assert_eq!(state.begin_rekey(), Err(SequenceError::InvalidState));
    assert!(state.rekey_is_terminal());
    assert!(!state.rekey_is_complete());
}

fn complete_initial_kex(state: &mut SequenceState) {
    assert_eq!(
        state.observe_inbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_KEXINIT),
        Ok(PacketDisposition::KexInit)
    );
    assert_eq!(state.observe_inbound(30), Ok(PacketDisposition::KexMethod));
    assert_eq!(state.observe_outbound(31), Ok(PacketDisposition::KexMethod));
    assert_eq!(
        state.observe_inbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(
        state.observe_outbound(SSH_MSG_NEWKEYS),
        Ok(PacketDisposition::NewKeys)
    );
    assert_eq!(state.complete_initial_kex(), Ok(()));
}
