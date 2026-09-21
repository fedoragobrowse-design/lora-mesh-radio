use mesh_core::frame::{decode_frame, encode_frame};
use mesh_node::{
    encode_persist, BlockOutcome, Engine, EngineError, IncomingKind, NodeEvent, OutgoingFrame,
    PersistContact, PersistView, MAX_CONTACTS,
};

const HOUR: u64 = 500_000;

fn fixture(uid: u8, peer: u8, role: u8) -> Vec<u8> {
    let mut contacts = [PersistContact::empty(); MAX_CONTACTS];
    contacts[0].present = true;
    contacts[0].peer_identity = [peer; 8];
    contacts[0].ed_peer = [peer; 32];
    contacts[0].root = [42; 32];
    contacts[0].role = role;
    let view = PersistView::new(true, uid, [uid; 8], true, 0, 0, [uid; 32], true, contacts);
    encode_persist(&view).0.to_vec()
}

fn restore(bytes: &[u8]) -> Engine {
    let mut e = Engine::new(true);
    e.restore(bytes).unwrap();
    e
}

fn commit(e: &mut Engine) -> Vec<u8> {
    let bytes = e.pending_persist().unwrap().to_vec();
    e.commit_ok();
    bytes
}

fn peers() -> (Engine, Engine) {
    let mut a = restore(&fixture(1, 2, 0));
    let mut b = restore(&fixture(2, 1, 1));
    for e in [&mut a, &mut b] {
        e.set_time(HOUR * 3600).unwrap();
        commit(e);
    }
    (a, b)
}

fn send(e: &mut Engine, id: u32, text: &[u8]) -> OutgoingFrame {
    e.send_begin(1, text, id).unwrap();
    commit(e);
    let f = e.send_emit().unwrap();
    commit(e);
    f
}

#[test]
fn committed_reservation_survives_reset_before_first_transmission() {
    let (mut a, _) = peers();
    let first = a.send_begin(1, b"never aired", 1).unwrap();
    assert!(matches!(a.send_emit(), Err(EngineError::Busy)));
    let reserved = commit(&mut a);
    let mut rebooted = restore(&reserved);
    assert!(matches!(
        rebooted.send_begin(1, b"later", 2),
        Err(EngineError::TimeUnset)
    ));
    rebooted.set_time(HOUR * 3600).unwrap();
    commit(&mut rebooted);
    let f = send(&mut rebooted, 2, b"later");
    assert!(decode_frame(f.as_slice()).unwrap().0.sequence > first.sequence);
}

#[test]
fn ack_ids_are_supplied_and_reception_survives_reboot() {
    let (mut a, mut b) = peers();
    let data = send(&mut a, 7, b"durable receive");
    let (kind, ack, event) = b.on_frame(data.as_slice(), 100, 0x12345678);
    assert!(matches!(kind, IncomingKind::Deliver { contact_id: 1, .. }));
    assert!(matches!(
        event,
        Some(NodeEvent::Received { text_len: 15, .. })
    ));
    let saved = commit(&mut b);
    let ack = ack.unwrap();
    let ack_header = decode_frame(ack.as_slice()).unwrap().0;
    assert_eq!(ack_header.packet_id, 0x12345678);
    assert!(matches!(
        a.on_frame(ack.as_slice(), 200, 0).0,
        IncomingKind::Ack { contact_id: 1 }
    ));
    commit(&mut a);

    let mut rebooted = restore(&saved);
    rebooted.set_time(HOUR * 3600).unwrap();
    commit(&mut rebooted);
    let (kind, ack2, event2) = rebooted.on_frame(data.as_slice(), 12_000, 0x87654321);
    assert_eq!(kind, IncomingKind::ReAck { contact_id: 1 });
    assert!(event2.is_none());
    let saved2 = commit(&mut rebooted);
    let h2 = decode_frame(ack2.unwrap().as_slice()).unwrap().0;
    assert_eq!(h2.packet_id, 0x87654321);
    assert!(h2.sequence > ack_header.sequence);
    // The second reservation/replay snapshot itself remains restorable.
    let mut again = restore(&saved2);
    again.set_time(HOUR * 3600).unwrap();
    commit(&mut again);
    assert_eq!(
        again.on_frame(data.as_slice(), 24_000, 9).0,
        IncomingKind::ReAck { contact_id: 1 }
    );
}

#[test]
fn time_advances_without_usb_and_old_hour_retry_is_identical() {
    let (mut a, mut b) = peers();
    for e in [&mut a, &mut b] {
        e.set_mono_s(100);
        e.set_time(HOUR * 3600 + 3599).unwrap();
        commit(e);
    }
    let original = send(&mut a, 5, b"boundary");
    a.advance_time(101).unwrap();
    let saved = commit(&mut a);
    assert_eq!(a.epoch(), HOUR as u32 + 1);
    assert_eq!(a.send_retry_echo().unwrap().as_slice(), original.as_slice());
    a.advance_time(102).unwrap();
    assert!(a.pending_persist().is_none(), "no per-second flash writes");
    b.advance_time(101).unwrap();
    commit(&mut b);
    let (_, ack, _) = b.on_frame(original.as_slice(), 101_000, 6);
    commit(&mut b);
    let ack = ack.unwrap();
    assert_eq!(
        decode_frame(ack.as_slice()).unwrap().0.epoch,
        HOUR as u32 + 1
    );
    assert_eq!(
        a.on_frame(ack.as_slice(), 102_000, 0).0,
        IncomingKind::Ack { contact_id: 1 }
    );
    let mut rebooted = restore(&saved);
    assert_eq!(
        rebooted.set_time(HOUR * 3600),
        Err(EngineError::TimeRollback)
    );
}

#[test]
fn version_one_pair_state_migrates_and_arm_is_consumed_once() {
    // Genuine V1 record: 2-slot length with version byte 1.
    let full = fixture(1, 2, 0);
    let mut old = full[..mesh_node::PERSIST_V2_LEN].to_vec();
    old[4] = 1;
    let mut a = restore(&old);
    assert!(!a.armed_next_boot());
    a.arm_next_boot().unwrap();
    assert!(!a.radio_on(), "arming must not enable current RF");
    let armed = commit(&mut a);
    let mut first_boot = restore(&armed);
    assert!(first_boot.consume_boot_arm().unwrap());
    assert!(!first_boot.radio_on(), "commit must precede driver enable");
    let consumed = commit(&mut first_boot);
    let mut second_boot = restore(&consumed);
    assert!(!second_boot.consume_boot_arm().unwrap());
    second_boot.set_time(HOUR * 3600).unwrap();
    commit(&mut second_boot);
    let mut b = restore(&fixture(2, 1, 1));
    b.set_time(HOUR * 3600).unwrap();
    commit(&mut b);
    let data = send(&mut second_boot, 99, b"preserved pair");
    assert!(matches!(
        b.on_frame(data.as_slice(), 0, 7).0,
        IncomingKind::Deliver { .. }
    ));
    second_boot.arm_next_boot().unwrap();
    commit(&mut second_boot);
    second_boot.set_radio(false).unwrap();
    let off = commit(&mut second_boot);
    assert!(!restore(&off).armed_next_boot());
}

#[test]
fn blocking_another_contact_does_not_cancel_the_pending_send() {
    let mut bytes = fixture(1, 2, 0);
    let mut view = mesh_node::decode_persist(&bytes).unwrap();
    let mut contact = view.contacts[0];
    contact.peer_identity = [3; 8];
    contact.ed_peer = [3; 32];
    contact.root = [43; 32];
    view.contacts[1] = contact;
    bytes = encode_persist(&PersistView::new(
        true,
        1,
        [1; 8],
        true,
        0,
        0,
        [1; 32],
        true,
        view.contacts,
    ))
    .0
    .to_vec();
    let mut a = restore(&bytes);
    a.set_time(HOUR * 3600).unwrap();
    commit(&mut a);
    let data = send(&mut a, 20, b"still pending");
    assert_eq!(a.set_blocked(2, true), Ok(BlockOutcome::Blocked));
    commit(&mut a);
    assert_eq!(a.send_retry_echo().unwrap().as_slice(), data.as_slice());
    assert!(matches!(
        a.set_blocked(1, true),
        Ok(BlockOutcome::CancelledSend(_))
    ));
    commit(&mut a);
    a.set_blocked(1, false).unwrap();
    commit(&mut a);
    assert!(!a.send_inflight());
    assert!(a.send_retry_echo().is_err());
}

#[test]
fn unsynced_endpoint_only_forwards_and_bad_tags_do_not_poison_replay() {
    let (mut a, mut b) = peers();
    let data = send(&mut a, 15, b"auth first");
    let mut cold = restore(&fixture(2, 1, 1));
    let (kind, forward, event) = cold.on_frame(data.as_slice(), 0, 2);
    assert_eq!(kind, IncomingKind::Forward);
    assert_eq!(decode_frame(forward.unwrap().as_slice()).unwrap().0.hops, 0);
    assert!(event.is_none());

    let (header, body) = decode_frame(data.as_slice()).unwrap();
    let mut bad_body = body.to_vec();
    bad_body[0] ^= 1;
    let mut bad = [0u8; 255];
    let len = encode_frame(&header, &bad_body, &mut bad).unwrap();
    assert!(b.on_frame(&bad[..len], 0, 3).2.is_none());
    assert_eq!(b.auth_failures(), 1);
    assert!(matches!(
        b.on_frame(data.as_slice(), 1, 4).0,
        IncomingKind::Deliver { .. }
    ));
    commit(&mut b);
    assert_eq!(
        b.on_frame(data.as_slice(), 2, 5).0,
        IncomingKind::ReAck { contact_id: 1 }
    );
    assert_eq!(b.replay_drops(), 1);

    a.note_origin(data.as_slice(), 10);
    assert_eq!(a.on_frame(data.as_slice(), 11, 0).0, IncomingKind::Ignore);
}

#[test]
fn v2_record_migrates_to_v3_and_pair_survives() {
    use mesh_node::{decode_persist, migrate_to_v3, PERSIST_V2_LEN};
    // Build a V3 record with one pair, then truncate to V2 length (2 slots).
    let full = fixture(1, 2, 0);
    assert_eq!(full.len(), mesh_node::PERSIST_LEN);
    // V2 layout = header + 2 slots; take prefix and stamp version 2.
    let mut v2 = full[..PERSIST_V2_LEN].to_vec();
    v2[4] = 2;
    // Canonical migrate must succeed where zero-padding would Fault.
    let v3 = migrate_to_v3(&v2).expect("v2 migrates");
    assert_eq!(v3.len(), mesh_node::PERSIST_LEN);
    let mut a = restore(&v3);
    // Pair state survived: contact 1 present, restores cleanly again.
    assert!(a.contact_present(1));
    assert!(!a.contact_present(3));
    let owned = decode_persist(&v3).unwrap();
    assert!(owned.contacts[0].present);
    assert!(!owned.contacts[2].present);
}

#[test]
fn mismatched_version_and_length_rejected() {
    use mesh_node::{decode_view, PERSIST_V2_LEN};
    // V3 version byte in a 2-slot record must fail.
    let full = fixture(1, 2, 0);
    let mut short_v3 = full[..PERSIST_V2_LEN].to_vec();
    short_v3[4] = 3;
    assert!(decode_view(&short_v3).is_err());
    // V1 version byte in a full-length record must fail.
    let mut long_v1 = full.clone();
    long_v1[4] = 1;
    assert!(decode_view(&long_v1).is_err());
}
