//! Transport-independent secure node engine: pairing ceremony, encrypted
//! DATA/ACK processing, durable sequence reservation, persisted inbound
//! replay windows, hourly aliases, blocking/cancel, and RF-independent
//! relay decisions. `no_std`, fixed buffers, zeroizing secrets.
//!
//! Durability contract: every state mutation that gates a visible effect
//! (nonce use, delivery, ACK send, contact activation) is staged into a
//! caller-persisted snapshot FIRST. The caller commits
//! [`Engine::pending_persist`] bytes via [`crate::persist`] encoding, then
//! calls [`Engine::commit_ok`]; only then does the engine emit the frame or
//! event. Restart/inerrupted writes can therefore never reuse a nonce,
//! clear a replay window, or resurrect a retired epoch slot.

use ed25519_dalek::Signer as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use mesh_core::clock::{derive_address, epoch_of_unix, in_accept_window, AliasCache};
use mesh_core::frame::{
    self, Header, BODY_ACK, BODY_DATA, FLAG_WANT_ACK, MAX_FRAME_LEN, MAX_TEXT_LEN, TAG_LEN,
    VERSION_SECURE,
};
use mesh_core::pairing::{
    self, Confirmation, Offer, Proof, CONFIRM_RECORD_LEN, OFFER_PAYLOAD_LEN, OFFER_RECORD_LEN,
    PROOF_CT_LEN, PROOF_RECORD_LEN, ROLE_L, T_LEN,
};
use mesh_core::relay::{self, RelayCache};
use mesh_core::security::{
    self, AnchorHours, ReplayWindow, Secret32, LABEL_ADDRESS, LABEL_CONFIRM, LABEL_SETUP_LR,
    LABEL_SETUP_RL, LABEL_TRAFFIC_LR, LABEL_TRAFFIC_RL,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Max paired contacts. 16 slots: persist ~3.5 KiB (fits one 4 KiB flash page),
/// worst-case RX auth 16 x 3 epoch windows. `contact_id` is 1..=16.
pub const MAX_CONTACTS: usize = 16;
/// Transmit sequence numbers are reserved in blocks of 32; the whole block
/// is committed to durable storage before any number in it is used. After
/// reboot the engine skips the entire last reserved block.
pub const SEQ_RESERVE_BLOCK: u64 = 32;
/// Proof transcript preimage domain.
const DOMAIN_PROOF: &[u8] = b"LMESH-proof-v1";
/// Confirmation transcript preimage domain.
const DOMAIN_CONFIRM_MSG: &[u8] = b"LMESH-confirm-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    BadRequest,
    Unprovisioned,
    StorageFault,
    TimeUnset,
    TimeRollback,
    Busy,
    ContactBlocked,
    RadioMustBeOff,
    RadioUnavailable,
    UnknownOp,
    PairingAbsent,
    PairingExpired,
    NoSlot,
    /// Confirmation import without the aloud SAS comparison.
    SasMismatch,
    /// Forward time jump over one hour without operator confirmation.
    TimeJumpNeedsConfirm,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairStep {
    NeedProof,
    NeedConfirm,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairImportOutcome {
    pub step: PairStep,
    pub fingerprint: [u8; 16],
    pub contact_id: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckReference {
    pub epoch: u32,
    pub sequence: u64,
    pub packet_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSend {
    pub contact_id: u8,
    pub epoch: u32,
    pub sequence: u64,
    pub packet_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    Blocked,
    Unblocked,
    /// A pending send was cancelled by the block transition.
    CancelledSend(PendingSend),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingKind {
    /// Authenticated DATA for us; deliver once (caller emits `received`).
    Deliver { contact_id: u8, text_len: u8 },
    /// Authenticated duplicate DATA; re-ACK via `out_ack`, no display.
    ReAck { contact_id: u8 },
    /// ACK matching our pending send.
    Ack { contact_id: u8 },
    /// Opaque transit frame: forward bytes unchanged (hops decremented).
    Forward,
    /// Frame consumed/ignored (wrong address, blocked, stale, bad tag).
    Ignore,
}

/// A frame the engine wants transmitted (DATA, ACK, or relay forward).
/// Bytes are fully encoded with CRC; `is_retry_echo` marks identical
/// retransmissions of the same nonce/ciphertext.
#[derive(Clone, Copy)]
pub struct OutgoingFrame {
    pub len: usize,
    pub bytes: [u8; MAX_FRAME_LEN],
    pub contact_id: Option<u8>,
    pub is_ack: bool,
    pub is_retry_echo: bool,
}

impl OutgoingFrame {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// UI-visible event staging: delivery text or ACK completion. Emitted only
/// after the corresponding durable commit (see module docs).
#[derive(Clone, Copy)]
pub enum NodeEvent {
    Received {
        contact_id: u8,
        epoch: u32,
        sequence: u64,
        text: [u8; MAX_TEXT_LEN],
        text_len: u8,
    },
    SendAcked {
        contact_id: u8,
        epoch: u32,
        sequence: u64,
        packet_id: u32,
    },
}

/// One paired contact: all secrets zeroize on drop via [`Secret32`].
#[derive(Clone)]
struct Contact {
    present: bool,
    blocked: bool,
    label_hint: [u8; 8],
    label_len: u8,
    ed_peer: [u8; 32],
    peer_identity: [u8; 8],
    root: Secret32,
    traffic_lr: Secret32,
    traffic_rl: Secret32,
    addr_secret: Secret32,
    /// Our role in this pair (L=0/R=1).
    role: u8,
    /// Next transmit sequence (durable: skip whole reserved block on boot).
    tx_next: u64,
    /// Durably reserved high-water mark (exclusive upper bound).
    tx_reserved: u64,
    /// Highest transmit epoch ever used (never decreases).
    tx_epoch_max: u32,
    anchor: AnchorHours,
    /// Persisted receive windows: 3 epoch slots x (DATA, ACK).
    win_data: [ReplayWindow; 3],
    win_ack: [ReplayWindow; 3],
    win_epochs: [u32; 3],
    aliases: AliasCache,
    cached_epoch: u32,
}

impl Contact {
    fn empty() -> Self {
        Self {
            present: false,
            blocked: false,
            label_hint: [0u8; 8],
            label_len: 0,
            ed_peer: [0u8; 32],
            peer_identity: [0u8; 8],
            root: Secret32::new([0u8; 32]),
            traffic_lr: Secret32::new([0u8; 32]),
            traffic_rl: Secret32::new([0u8; 32]),
            addr_secret: Secret32::new([0u8; 32]),
            role: ROLE_L,
            tx_next: 0,
            tx_reserved: 0,
            tx_epoch_max: 0,
            anchor: AnchorHours::new(0),
            win_data: [ReplayWindow::new(); 3],
            win_ack: [ReplayWindow::new(); 3],
            win_epochs: [0u32; 3],
            aliases: AliasCache::new(),
            cached_epoch: u32::MAX,
        }
    }
}

/// Pending in-person pairing attempt (volatile except persisted seeds).
struct PendingPair {
    own_offer: [u8; OFFER_PAYLOAD_LEN],
    own_eph_priv: [u8; 32],
    peer_offer: Option<[u8; OFFER_PAYLOAD_LEN]>,
    peer_identity: Option<[u8; 8]>,
    transcript: Option<[u8; T_LEN]>,
    own_role: u8,
    own_proof: Option<[u8; PROOF_RECORD_LEN]>,
    peer_proof: Option<[u8; PROOF_RECORD_LEN]>,
    own_confirm: Option<[u8; CONFIRM_RECORD_LEN]>,
    start_mono_s: u64,
    slot: usize,
    replace: bool,
}

/// Transport-independent node state. The `radio_on` flag gates pairing
/// (RADIO_MUST_BE_OFF) only; actual airtime lives outside this engine.
pub struct Engine {
    provisioned: bool,
    label: u8,
    uid: [u8; 8],
    uid_set: bool,
    /// Trusted local UTC seconds; `time_valid` is RAM-only and always
    /// starts false at boot (cold boot = TIME_UNSET even with stored time).
    unix_seconds: u64,
    time_valid: bool,
    persisted_tx_epoch: u32,
    radio_on: bool,
    armed_next_boot: bool,
    /// Radio hardware present. `false` in the default radio-free image:
    /// every RF send/ping/on returns RADIO_UNAVAILABLE.
    radio_available: bool,
    sign_priv: [u8; 32],
    sign_set: bool,
    contacts: [Contact; MAX_CONTACTS],
    pending: Option<PendingPair>,
    pending_send: Option<PendingSend>,
    pending_text: [u8; MAX_TEXT_LEN],
    pending_text_len: u8,
    relay_cache: RelayCache,
    fault: bool,
    /// Bytes staged for durable commit; `commit_ok` applies them.
    staged: Option<StagedCommit>,
    persist_scratch: [u8; crate::persist::PERSIST_LEN],
    persist_len: usize,
    persist_dirty: bool,
    mono_s: u64,
    utc_mono_s: u64,
    auth_failures: u32,
    replay_drops: u32,
}

#[derive(Clone, Copy)]
enum StagedCommit {
    None,
    Provision,
    Time(u64),
    PairActivate { slot: usize },
    TxReserve { slot: usize, new_reserved: u64 },
    RxAccept,
    AnchorAdvance,
}

impl Engine {
    pub fn new(radio_available: bool) -> Self {
        Self {
            provisioned: false,
            label: 0,
            uid: [0u8; 8],
            uid_set: false,
            unix_seconds: 0,
            time_valid: false,
            persisted_tx_epoch: 0,
            radio_on: false,
            armed_next_boot: false,
            radio_available,
            sign_priv: [0u8; 32],
            sign_set: false,
            contacts: core::array::from_fn(|_| Contact::empty()),
            pending: None,
            pending_send: None,
            pending_text: [0u8; MAX_TEXT_LEN],
            pending_text_len: 0,
            relay_cache: RelayCache::new(),
            fault: false,
            staged: None,
            persist_scratch: [0u8; crate::persist::PERSIST_LEN],
            persist_len: 0,
            persist_dirty: false,
            mono_s: 0,
            utc_mono_s: 0,
            auth_failures: 0,
            replay_drops: 0,
        }
    }

    pub fn set_mono_s(&mut self, now: u64) {
        self.mono_s = now;
    }

    /// Advance trusted UTC without host traffic. Commit a staged hour
    /// transition before processing another operation or emitting a frame.
    pub fn advance_time(&mut self, now_mono_s: u64) -> Result<(), EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        self.mono_s = now_mono_s;
        if !self.time_valid {
            return Ok(());
        }
        let Some(elapsed) = now_mono_s.checked_sub(self.utc_mono_s) else {
            self.time_valid = false;
            return Err(EngineError::TimeRollback);
        };
        let next = self
            .unix_seconds
            .checked_add(elapsed)
            .filter(|seconds| epoch_of_unix(*seconds).is_some());
        let Some(next) = next else {
            self.time_valid = false;
            return Err(EngineError::BadRequest);
        };
        if epoch_of_unix(next) != Some(self.epoch()) {
            self.set_time(next)?;
        } else {
            self.unix_seconds = next;
            self.utc_mono_s = now_mono_s;
        }
        Ok(())
    }

    fn check_usable(&self) -> Result<(), EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        if !self.provisioned {
            return Err(EngineError::Unprovisioned);
        }
        Ok(())
    }

    pub fn mark_fault(&mut self) {
        self.fault = true;
    }

    pub fn provisioned(&self) -> bool {
        !self.fault && self.provisioned
    }

    pub fn label(&self) -> u8 {
        self.label
    }

    pub fn radio_on(&self) -> bool {
        self.radio_on
    }

    pub fn radio_available(&self) -> bool {
        self.radio_available
    }

    /// Correct the hardware flag after full radio init without touching
    /// restored identity/pair state. RF stays off until explicitly enabled.
    pub fn set_radio_available(&mut self, available: bool) {
        self.radio_available = available;
        if !available {
            self.radio_on = false;
            self.pending_send = None;
            self.armed_next_boot = false;
        }
    }

    pub fn time_valid(&self) -> bool {
        !self.fault && self.time_valid
    }

    pub fn unix_seconds(&self) -> u64 {
        self.unix_seconds
    }

    pub fn epoch(&self) -> u32 {
        if self.time_valid {
            epoch_of_unix(self.unix_seconds).unwrap_or(0)
        } else {
            0
        }
    }

    pub fn set_identity(&mut self, uid: [u8; 8]) {
        if self.uid_set && self.uid == uid {
            return;
        }
        self.uid = uid;
        self.uid_set = true;
        self.stage_persist(StagedCommit::None);
    }

    pub fn identity(&self) -> Option<[u8; 8]> {
        self.uid_set.then_some(self.uid)
    }

    /// Explicit provisioning. Second call fails closed (ALREADY_PROVISIONED
    /// at the wire layer).
    pub fn provision(&mut self, label: u8, sign_priv: [u8; 32]) -> Result<(), EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        if self.provisioned {
            return Err(EngineError::Busy);
        }
        if label == 0 || label > 3 {
            return Err(EngineError::BadRequest);
        }
        self.label = label;
        self.sign_priv = sign_priv;
        self.sign_set = true;
        self.provisioned = true;
        self.stage_persist(StagedCommit::Provision);
        Ok(())
    }

    pub fn ed_pubkey(&self) -> Result<[u8; 32], EngineError> {
        if !self.sign_set {
            return Err(EngineError::Unprovisioned);
        }
        Ok(SigningKey::from_bytes(&self.sign_priv)
            .verifying_key()
            .to_bytes())
    }

    /// Monotonic trusted UTC set. Within-hour corrections pass; any move
    /// below the persisted transmit epoch or any receive anchor fails with
    /// TIME_ROLLBACK. Commits before returning.
    pub fn set_time(&mut self, unix_seconds: u64) -> Result<u32, EngineError> {
        self.set_time_confirmed(unix_seconds, false)
    }

    /// B4: like `set_time` but `confirmed=true` permits forward jumps over
    /// one hour (operator-confirmed via `--confirm-jump`). Gradual slew
    /// stays accepted without confirmation.
    pub fn set_time_confirmed(
        &mut self,
        unix_seconds: u64,
        confirmed: bool,
    ) -> Result<u32, EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        let new_epoch = epoch_of_unix(unix_seconds).ok_or(EngineError::BadRequest)?;
        let mut floor: u32 = 0;
        floor = floor.max(self.persisted_tx_epoch);
        for c in self.contacts.iter() {
            if c.present {
                floor = floor.max(c.anchor.anchor());
            }
        }
        if new_epoch < floor {
            return Err(EngineError::TimeRollback);
        }
        // B4/X1: ceiling against jumps. A single step forward of more than
        // one hour past the current epoch needs operator confirmation
        // (host re-issues with confirm); gradual slew stays accepted.
        if !confirmed && self.time_valid {
            let cur = self.epoch();
            if new_epoch > cur.saturating_add(1) {
                return Err(EngineError::TimeJumpNeedsConfirm);
            }
        }
        // Atomically advance every present contact's anchor + windows.
        for c in self.contacts.iter_mut() {
            if c.present {
                let fresh = c.anchor.trusted_advance(new_epoch);
                match fresh {
                    Ok(init) => {
                        let old = c.win_epochs;
                        let mut nd = c.win_data;
                        let mut na = c.win_ack;
                        let mut ne = c.win_epochs;
                        for (slot_i, e) in [
                            new_epoch.saturating_sub(1),
                            new_epoch,
                            new_epoch.saturating_add(1),
                        ]
                        .iter()
                        .enumerate()
                        {
                            if let Some(old_i) = old.iter().position(|o| o == e) {
                                nd[slot_i] = c.win_data[old_i];
                                na[slot_i] = c.win_ack[old_i];
                            } else if init.contains(e) || !old.contains(e) {
                                nd[slot_i] = ReplayWindow::new();
                                na[slot_i] = ReplayWindow::new();
                            }
                            ne[slot_i] = *e;
                        }
                        c.win_data = nd;
                        c.win_ack = na;
                        c.win_epochs = ne;
                        c.cached_epoch = u32::MAX;
                    }
                    Err(_) => return Err(EngineError::TimeRollback),
                }
            }
        }
        self.unix_seconds = unix_seconds;
        self.time_valid = true;
        self.utc_mono_s = self.mono_s;
        self.stage_persist(StagedCommit::Time(unix_seconds));
        Ok(new_epoch)
    }

    pub fn set_radio(&mut self, enabled: bool) -> Result<(), EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        if enabled && !self.radio_available {
            return Err(EngineError::RadioUnavailable);
        }
        self.radio_on = enabled;
        if !enabled {
            self.pending_send = None;
            self.armed_next_boot = false;
        }
        self.stage_persist(StagedCommit::None);
        Ok(())
    }

    pub fn send_inflight(&self) -> bool {
        self.pending_send.is_some()
    }

    pub fn armed_next_boot(&self) -> bool {
        self.armed_next_boot
    }

    /// Stages a one-shot arm without changing current RF state.
    pub fn arm_next_boot(&mut self) -> Result<(), EngineError> {
        self.check_usable()?;
        if !self.radio_available {
            return Err(EngineError::RadioUnavailable);
        }
        self.armed_next_boot = true;
        self.stage_persist(StagedCommit::None);
        Ok(())
    }

    /// Only enable hardware after successfully committing the cleared flag.
    pub fn consume_boot_arm(&mut self) -> Result<bool, EngineError> {
        if self.fault {
            return Err(EngineError::StorageFault);
        }
        let armed = self.armed_next_boot;
        if armed {
            self.armed_next_boot = false;
            self.stage_persist(StagedCommit::None);
        }
        Ok(armed && self.radio_available)
    }

    fn require_radio_off(&self) -> Result<(), EngineError> {
        if self.radio_on {
            return Err(EngineError::RadioMustBeOff);
        }
        Ok(())
    }

    // ---------- pairing ceremony ----------

    /// Start (or re-emit) our offer. `eph_priv`/`eph_pub`/`challenge` come
    /// from the caller's TRNG; repeated calls re-emit the same offer until
    /// expiry/cancel. Radio must be off.
    pub fn pair_offer(
        &mut self,
        eph_priv: [u8; 32],
        eph_pub: [u8; 32],
        challenge: [u8; 32],
    ) -> Result<[u8; OFFER_RECORD_LEN], EngineError> {
        self.check_usable()?;
        self.require_radio_off()?;
        if let Some(p) = self.pending.as_ref() {
            if !pairing::is_expired(p.start_mono_s, self.mono_s) {
                let mut rec = [0u8; OFFER_RECORD_LEN];
                rec[0] = pairing::RECORD_OFFER;
                rec[1..].copy_from_slice(&p.own_offer);
                return Ok(rec);
            }
        }
        if !self.sign_set {
            return Err(EngineError::Unprovisioned);
        }
        let ed = self.ed_pubkey()?;
        // Reject degenerate ephemeral keys early (all-zero contributes nothing).
        if eph_pub == [0u8; 32] {
            return Err(EngineError::BadRequest);
        }
        let offer = Offer {
            ed_pub: ed,
            eph_pub,
            challenge,
        };
        let mut payload = [0u8; OFFER_PAYLOAD_LEN];
        pairing::encode_offer_payload(&offer, &mut payload).map_err(|_| EngineError::BadRequest)?;
        // Find a free slot now (fail before creating pending state).
        let slot = self.free_slot().ok_or(EngineError::NoSlot)?;
        self.pending = Some(PendingPair {
            own_offer: payload,
            own_eph_priv: eph_priv,
            peer_offer: None,
            peer_identity: None,
            transcript: None,
            own_role: ROLE_L,
            own_proof: None,
            peer_proof: None,
            own_confirm: None,
            start_mono_s: self.mono_s,
            slot,
            replace: false,
        });
        let mut rec = [0u8; OFFER_RECORD_LEN];
        rec[0] = pairing::RECORD_OFFER;
        rec[1..].copy_from_slice(&payload);
        Ok(rec)
    }

    pub fn pair_cancel(&mut self) {
        if let Some(p) = self.pending.take() {
            let mut priv_copy = p.own_eph_priv;
            priv_copy.zeroize();
        }
        self.pending_send = None;
    }

    fn free_slot(&self) -> Option<usize> {
        self.contacts.iter().position(|c| !c.present)
    }

    /// Import a peer record (offer/proof/confirmation transport-decoded by
    /// the caller). `record` is the raw binary record (type byte first).
    pub fn pair_import(
        &mut self,
        record: &[u8],
        replace: bool,
    ) -> Result<PairImportOutcome, EngineError> {
        self.pair_import_sas(record, replace, false)
    }

    /// SAS-gated import: confirmation records (which activate trust)
    /// require `sas_match` (operator compared the transcript aloud on both
    /// sides). Offer/proof imports are unaffected.
    pub fn pair_import_sas(
        &mut self,
        record: &[u8],
        replace: bool,
        sas_match: bool,
    ) -> Result<PairImportOutcome, EngineError> {
        self.check_usable()?;
        self.require_radio_off()?;
        let p = self.pending.as_mut().ok_or(EngineError::PairingAbsent)?;
        if pairing::is_expired(p.start_mono_s, self.mono_s) {
            return Err(EngineError::PairingExpired);
        }
        if record.is_empty() {
            return Err(EngineError::BadRequest);
        }
        // C4: trust activates on confirmation import; require the aloud
        // SAS comparison BEFORE flash mutation, not after.
        if record[0] == pairing::RECORD_CONFIRM && !sas_match {
            return Err(EngineError::SasMismatch);
        }
        match record[0] {
            pairing::RECORD_OFFER => self.import_offer(record, replace),
            pairing::RECORD_PROOF => self.import_proof(record),
            pairing::RECORD_CONFIRM => self.import_confirm(record),
            _ => Err(EngineError::BadRequest),
        }
    }

    fn import_offer(
        &mut self,
        record: &[u8],
        replace: bool,
    ) -> Result<PairImportOutcome, EngineError> {
        let offer = pairing::decode_offer_record(record).map_err(|_| EngineError::BadRequest)?;
        let free_slot = self.free_slot();
        let p = self.pending.as_mut().ok_or(EngineError::PairingAbsent)?;
        let own_ed = {
            let o = pairing::decode_offer_payload(&p.own_offer)
                .map_err(|_| EngineError::StorageFault)?;
            o.ed_pub
        };
        pairing::check_not_self(&own_ed, &offer.ed_pub).map_err(|_| EngineError::BadRequest)?;
        // Duplicate signing identity against existing contacts. `replace`
        // cannot currently renew the same peer in place: this fails closed
        // before slot selection even when `replace` is true. Repair a stale
        // slot with contact_delete, then a fresh offer with replace=false.
        for c in self.contacts.iter() {
            if c.present && c.ed_peer == offer.ed_pub {
                return Err(EngineError::BadRequest);
            }
        }
        let mut peer_payload = [0u8; OFFER_PAYLOAD_LEN];
        pairing::encode_offer_payload(&offer, &mut peer_payload)
            .map_err(|_| EngineError::BadRequest)?;
        // Transcript over ordered payloads (lexicographic by Ed25519 key,
        // bytes 1..33 of each 97-byte payload).
        let own_copy: [u8; OFFER_PAYLOAD_LEN] = p.own_offer;
        let (l, r) = if own_copy[1..33] <= peer_payload[1..33] {
            (&own_copy, &peer_payload)
        } else {
            (&peer_payload, &own_copy)
        };
        let t = security::transcript_t(l, r);
        let role = pairing::role_for(&own_ed, &offer.ed_pub);
        // Slot selection: explicit replace may target an occupied slot.
        let slot = if replace {
            // Replace requires at least one present contact; reuse slot 0
            // when free, else fail closed (caller picks contact to replace
            // by blocking/unblocking is out of scope: keep slot of peer).
            p.slot
        } else {
            free_slot.ok_or(EngineError::NoSlot)?
        };
        p.peer_offer = Some(peer_payload);
        p.transcript = Some(t);
        p.own_role = role;
        p.slot = slot;
        p.replace = replace;
        Ok(PairImportOutcome {
            step: PairStep::NeedProof,
            fingerprint: pairing::transcript_fingerprint(&t),
            contact_id: None,
        })
    }

    fn setup_keys(&self, t: &[u8; T_LEN], role: u8) -> Result<([u8; 32], [u8; 32]), EngineError> {
        let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
        let peer_payload = p.peer_offer.as_ref().ok_or(EngineError::BadRequest)?;
        let peer_offer =
            pairing::decode_offer_payload(peer_payload).map_err(|_| EngineError::BadRequest)?;
        // X25519 with contributory check.
        let priv_key = x25519_dalek::StaticSecret::from(p.own_eph_priv);
        let peer_pub = x25519_dalek::PublicKey::from(peer_offer.eph_pub);
        let dh = priv_key.diffie_hellman(&peer_pub);
        let dh_bytes: [u8; 32] = *dh.as_bytes();
        if dh_bytes == [0u8; 32] {
            return Err(EngineError::BadRequest);
        }
        let root = security::derive_root(&dh_bytes, t);
        let k_lr = security::derive_label(&root, LABEL_SETUP_LR);
        let k_rl = security::derive_label(&root, LABEL_SETUP_RL);
        let _ = role;
        Ok((k_lr, k_rl))
    }

    /// Export our proof (deterministic under the fresh directional setup
    /// key; repeat exports return the identical bytes).
    pub fn pair_proof(&mut self) -> Result<[u8; PROOF_RECORD_LEN], EngineError> {
        self.check_usable()?;
        self.require_radio_off()?;
        let (t, role) = {
            let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
            if pairing::is_expired(p.start_mono_s, self.mono_s) {
                return Err(EngineError::PairingExpired);
            }
            (p.transcript.ok_or(EngineError::BadRequest)?, p.own_role)
        };
        {
            let p = self.pending.as_ref().unwrap();
            if let Some(saved) = p.own_proof {
                return Ok(saved);
            }
        }
        let (k_lr, k_rl) = self.setup_keys(&t, role)?;
        let out_key = if role == ROLE_L { k_lr } else { k_rl };
        // Encrypt our 8-byte private identity/flash serial.
        if !self.uid_set {
            return Err(EngineError::Unprovisioned);
        }
        let mut aad = [0u8; 33];
        aad[..32].copy_from_slice(&t);
        aad[32] = role;
        let mut ct = [0u8; PROOF_CT_LEN];
        security::encrypt_data(&out_key, &[0u8; 12], &aad, &self.uid, &mut ct)
            .map_err(|_| EngineError::StorageFault)?;
        // Sign "LMESH-proof-v1" || T || role || ct (14-byte domain).
        let mut msg = [0u8; 14 + 32 + 1 + PROOF_CT_LEN];
        msg[..14].copy_from_slice(DOMAIN_PROOF);
        msg[14..46].copy_from_slice(&t);
        msg[46] = role;
        msg[47..].copy_from_slice(&ct);
        let sig = SigningKey::from_bytes(&self.sign_priv).sign(&msg);
        let proof = Proof {
            t,
            role,
            ct,
            sig: sig.to_bytes(),
        };
        let mut rec = [0u8; PROOF_RECORD_LEN];
        pairing::encode_proof(&proof, &mut rec).map_err(|_| EngineError::BadRequest)?;
        self.pending.as_mut().unwrap().own_proof = Some(rec);
        Ok(rec)
    }

    fn import_proof(&mut self, record: &[u8]) -> Result<PairImportOutcome, EngineError> {
        let proof = pairing::decode_proof(record).map_err(|_| EngineError::BadRequest)?;
        let (t, role) = {
            let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
            (p.transcript.ok_or(EngineError::BadRequest)?, p.own_role)
        };
        if proof.t != t {
            return Err(EngineError::BadRequest);
        }
        // Role must be the peer's role, not ours.
        if proof.role == role {
            return Err(EngineError::BadRequest);
        }
        // Verify Ed25519 strictly with the peer offer key.
        let peer_ed = {
            let p = self.pending.as_ref().unwrap();
            let po = pairing::decode_offer_payload(p.peer_offer.as_ref().unwrap())
                .map_err(|_| EngineError::BadRequest)?;
            po.ed_pub
        };
        let vk = VerifyingKey::from_bytes(&peer_ed).map_err(|_| EngineError::BadRequest)?;
        let mut msg = [0u8; 14 + 32 + 1 + PROOF_CT_LEN];
        msg[..14].copy_from_slice(DOMAIN_PROOF);
        msg[14..46].copy_from_slice(&proof.t);
        msg[46] = proof.role;
        msg[47..].copy_from_slice(&proof.ct);
        vk.verify_strict(&msg, &Signature::from_bytes(&proof.sig))
            .map_err(|_| EngineError::BadRequest)?;
        // Decrypt peer identity under the peer's outgoing setup key.
        let (k_lr, k_rl) = self.setup_keys(&t, role)?;
        let peer_key = if proof.role == ROLE_L { k_lr } else { k_rl };
        let mut aad = [0u8; 33];
        aad[..32].copy_from_slice(&t);
        aad[32] = proof.role;
        let mut pt = [0u8; 8];
        security::decrypt_data(&peer_key, &[0u8; 12], &aad, &proof.ct, &mut pt)
            .map_err(|_| EngineError::BadRequest)?;
        // Stash peer proof + decrypted identity for activation.
        let p = self.pending.as_mut().unwrap();
        let mut raw = [0u8; PROOF_RECORD_LEN];
        raw.copy_from_slice(record);
        p.peer_proof = Some(raw);
        p.peer_identity = Some(pt);
        Ok(PairImportOutcome {
            step: PairStep::NeedConfirm,
            fingerprint: pairing::transcript_fingerprint(&t),
            contact_id: None,
        })
    }

    /// Export our confirmation (HMAC over proof transcript).
    pub fn pair_confirm(&mut self) -> Result<[u8; CONFIRM_RECORD_LEN], EngineError> {
        self.check_usable()?;
        self.require_radio_off()?;
        let (t, role) = {
            let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
            if pairing::is_expired(p.start_mono_s, self.mono_s) {
                return Err(EngineError::PairingExpired);
            }
            (p.transcript.ok_or(EngineError::BadRequest)?, p.own_role)
        };
        if self.pending.as_ref().unwrap().peer_proof.is_none() {
            return Err(EngineError::BadRequest);
        }
        if let Some(saved) = self.pending.as_ref().unwrap().own_confirm {
            return Ok(saved);
        }
        let p = self.pending.as_ref().unwrap();
        let own_proof = p.own_proof.ok_or(EngineError::BadRequest)?;
        let peer_proof = p.peer_proof.ok_or(EngineError::BadRequest)?;
        // Order proofs canonically: L proof first.
        let (pl, pr) = if role == ROLE_L {
            (own_proof, peer_proof)
        } else {
            (peer_proof, own_proof)
        };
        let mut h = Sha256::new();
        h.update(&pl);
        h.update(&pr);
        let digest: [u8; 32] = h.finalize().into();
        // Confirm key from pair root.
        let root = self.pair_root(&t)?;
        let ck = security::derive_label(&root, LABEL_CONFIRM);
        let mut mac = Hmac::<Sha256>::new_from_slice(&ck).map_err(|_| EngineError::StorageFault)?;
        mac.update(DOMAIN_CONFIRM_MSG);
        mac.update(&t);
        mac.update(&[role]);
        mac.update(&digest);
        let tag = mac.finalize().into_bytes();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&tag);
        let conf = Confirmation {
            t,
            role,
            mac: mac_bytes,
        };
        let mut rec = [0u8; CONFIRM_RECORD_LEN];
        pairing::encode_confirmation(&conf, &mut rec).map_err(|_| EngineError::BadRequest)?;
        self.pending.as_mut().unwrap().own_confirm = Some(rec);
        Ok(rec)
    }

    fn pair_root(&self, t: &[u8; T_LEN]) -> Result<[u8; 32], EngineError> {
        let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
        let peer_payload = p.peer_offer.as_ref().ok_or(EngineError::BadRequest)?;
        let peer_offer =
            pairing::decode_offer_payload(peer_payload).map_err(|_| EngineError::BadRequest)?;
        let priv_key = x25519_dalek::StaticSecret::from(p.own_eph_priv);
        let peer_pub = x25519_dalek::PublicKey::from(peer_offer.eph_pub);
        let dh = priv_key.diffie_hellman(&peer_pub);
        let dh_bytes: [u8; 32] = *dh.as_bytes();
        if dh_bytes == [0u8; 32] {
            return Err(EngineError::BadRequest);
        }
        Ok(security::derive_root(&dh_bytes, t))
    }

    fn import_confirm(&mut self, record: &[u8]) -> Result<PairImportOutcome, EngineError> {
        let conf = pairing::decode_confirmation(record).map_err(|_| EngineError::BadRequest)?;
        let (t, role, slot) = {
            let p = self.pending.as_ref().ok_or(EngineError::PairingAbsent)?;
            (
                p.transcript.ok_or(EngineError::BadRequest)?,
                p.own_role,
                p.slot,
            )
        };
        if conf.t != t || conf.role == role {
            return Err(EngineError::BadRequest);
        }
        let p = self.pending.as_ref().unwrap();
        let own_proof = p.own_proof.ok_or(EngineError::BadRequest)?;
        let peer_proof = p.peer_proof.ok_or(EngineError::BadRequest)?;
        let (pl, pr) = if role == ROLE_L {
            (own_proof, peer_proof)
        } else {
            (peer_proof, own_proof)
        };
        let mut h = Sha256::new();
        h.update(&pl);
        h.update(&pr);
        let digest: [u8; 32] = h.finalize().into();
        let root = self.pair_root(&t)?;
        let ck = security::derive_label(&root, LABEL_CONFIRM);
        let mut mac = Hmac::<Sha256>::new_from_slice(&ck).map_err(|_| EngineError::StorageFault)?;
        mac.update(DOMAIN_CONFIRM_MSG);
        mac.update(&t);
        mac.update(&[conf.role]);
        mac.update(&digest);
        let expect = mac.finalize().into_bytes();
        if expect.as_slice() != conf.mac.as_slice() {
            return Err(EngineError::BadRequest);
        }
        // Use the peer identity verified at proof import (AEAD + strict
        // signature); re-check it matches a fresh decrypt of the stored
        // peer proof so a torn pending state cannot activate.
        let peer_id_cached = self
            .pending
            .as_ref()
            .unwrap()
            .peer_identity
            .ok_or(EngineError::BadRequest)?;
        let peer_proof_d =
            pairing::decode_proof(&peer_proof).map_err(|_| EngineError::BadRequest)?;
        let (k_lr, k_rl) = self.setup_keys(&t, role)?;
        let peer_key = if conf.role == ROLE_L { k_lr } else { k_rl };
        let mut aad = [0u8; 33];
        aad[..32].copy_from_slice(&t);
        aad[32] = conf.role;
        let mut peer_id = [0u8; 8];
        security::decrypt_data(&peer_key, &[0u8; 12], &aad, &peer_proof_d.ct, &mut peer_id)
            .map_err(|_| EngineError::BadRequest)?;
        if peer_id != peer_id_cached {
            return Err(EngineError::BadRequest);
        }
        let peer_ed = {
            let po = pairing::decode_offer_payload(
                self.pending.as_ref().unwrap().peer_offer.as_ref().unwrap(),
            )
            .map_err(|_| EngineError::BadRequest)?;
            po.ed_pub
        };
        // Activate: durable save BEFORE reporting contact_id. Stage persist;
        // caller commits, then commit_ok() finalizes.
        self.activate_contact(slot, &peer_ed, &peer_id, &root, role, t)?;
        self.stage_persist(StagedCommit::PairActivate { slot });
        Ok(PairImportOutcome {
            step: PairStep::Active,
            fingerprint: pairing::transcript_fingerprint(&t),
            contact_id: Some((slot + 1) as u8),
        })
    }

    fn activate_contact(
        &mut self,
        slot: usize,
        peer_ed: &[u8; 32],
        peer_id: &[u8; 8],
        root: &[u8; 32],
        role: u8,
        t: [u8; T_LEN],
    ) -> Result<(), EngineError> {
        if slot >= MAX_CONTACTS {
            return Err(EngineError::NoSlot);
        }
        let epoch = self.epoch();
        let c = &mut self.contacts[slot];
        *c = Contact::empty();
        c.present = true;
        c.ed_peer = *peer_ed;
        c.peer_identity = *peer_id;
        c.root = Secret32::new(*root);
        let (lr, rl) = if role == ROLE_L {
            (
                security::derive_label(root, LABEL_TRAFFIC_LR),
                security::derive_label(root, LABEL_TRAFFIC_RL),
            )
        } else {
            (
                security::derive_label(root, LABEL_TRAFFIC_LR),
                security::derive_label(root, LABEL_TRAFFIC_RL),
            )
        };
        c.traffic_lr = Secret32::new(lr);
        c.traffic_rl = Secret32::new(rl);
        c.addr_secret = Secret32::new(security::derive_label(root, LABEL_ADDRESS));
        c.role = role;
        c.anchor = AnchorHours::new(epoch);
        c.win_epochs = [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)];
        c.cached_epoch = u32::MAX;
        let _ = t;
        Ok(())
    }

    // ---------- transmit path ----------

    fn dir_roots(&self, slot: usize) -> Result<([u8; 32], [u8; 32]), EngineError> {
        let c = self.contacts.get(slot).ok_or(EngineError::BadRequest)?;
        if !c.present {
            return Err(EngineError::BadRequest);
        }
        Ok((*c.traffic_lr.as_bytes(), *c.traffic_rl.as_bytes()))
    }

    fn outgoing_key(&self, slot: usize, epoch: u32) -> Result<[u8; 32], EngineError> {
        let (lr, rl) = self.dir_roots(slot)?;
        let role = self.contacts[slot].role;
        let dir = if role == ROLE_L { lr } else { rl };
        Ok(security::hourly_key(&dir, epoch))
    }

    fn incoming_key(&self, slot: usize, epoch: u32) -> Result<[u8; 32], EngineError> {
        let (lr, rl) = self.dir_roots(slot)?;
        let role = self.contacts[slot].role;
        let dir = if role == ROLE_L { rl } else { lr };
        Ok(security::hourly_key(&dir, epoch))
    }

    fn refresh_aliases(&mut self, slot: usize) {
        let epoch = self.epoch();
        let c = &mut self.contacts[slot];
        if !c.present || c.cached_epoch == epoch {
            return;
        }
        let own = self.uid;
        let peer = c.peer_identity;
        let secret = *c.addr_secret.as_bytes();
        c.aliases.refresh(&secret, &own, &peer, epoch);
        c.cached_epoch = epoch;
    }

    /// Reserve the next transmit sequence (durable block of 32). Stages the
    /// persist; the caller commits, then calls `send_stage2` to encrypt.
    pub fn send_begin(
        &mut self,
        contact_id: u8,
        text: &[u8],
        packet_id: u32,
    ) -> Result<PendingSend, EngineError> {
        self.check_usable()?;
        if !self.time_valid {
            return Err(EngineError::TimeUnset);
        }
        // Virtual-transport sends do not need a radio driver: the exerciser
        // shuttles `__frame` bytes between processes. Only the
        // `radio_available` check is relaxed here; provisioned/fault and
        // TIME_UNSET guards above still apply. Real firmware airtime stays
        // gated at the USB layer.
        let slot = self.slot_of(contact_id)?;
        if self.contacts[slot].blocked {
            return Err(EngineError::ContactBlocked);
        }
        if self.pending_send.is_some() {
            return Err(EngineError::Busy);
        }
        if text.is_empty() || text.len() > MAX_TEXT_LEN || core::str::from_utf8(text).is_err() {
            return Err(EngineError::BadRequest);
        }
        let epoch = self.epoch();
        // Never decrease highest transmit epoch.
        if epoch < self.contacts[slot].tx_epoch_max {
            return Err(EngineError::TimeRollback);
        }
        // Reserve block if exhausted.
        let c = &mut self.contacts[slot];
        if c.tx_next >= c.tx_reserved {
            let new_reserved = c
                .tx_next
                .checked_add(SEQ_RESERVE_BLOCK)
                .ok_or(EngineError::StorageFault)?;
            self.stage_persist(StagedCommit::TxReserve { slot, new_reserved });
        } else {
            self.stage_persist(StagedCommit::None);
        }
        self.pending_text[..text.len()].copy_from_slice(text);
        self.pending_text_len = text.len() as u8;
        let seq = self.contacts[slot].tx_next;
        let ps = PendingSend {
            contact_id,
            epoch,
            sequence: seq,
            packet_id,
        };
        self.pending_send = Some(ps);
        Ok(ps)
    }

    /// Encrypt the staged send AFTER the reservation commit. Returns the
    /// encoded frame (hops=1 mesh). Consumes the reservation.
    pub fn send_emit(&mut self) -> Result<OutgoingFrame, EngineError> {
        if self.persist_dirty {
            return Err(EngineError::Busy);
        }
        let ps = self.pending_send.ok_or(EngineError::BadRequest)?;
        let slot = self.slot_of(ps.contact_id)?;
        let epoch = ps.epoch;
        // Preserve the reserved envelope across an hour boundary.
        if self.contacts[slot].tx_next != ps.sequence
            || ps.sequence >= self.contacts[slot].tx_reserved
        {
            return Err(EngineError::StorageFault);
        }
        if epoch < self.contacts[slot].tx_epoch_max {
            return Err(EngineError::TimeRollback);
        }
        let key = self.outgoing_key(slot, epoch)?;
        let nonce = security::nonce(epoch, ps.sequence);
        self.refresh_aliases(slot);
        let (dst, src) = {
            let c = &self.contacts[slot];
            let e = epoch;
            (
                derive_address(c.addr_secret.as_bytes(), &c.peer_identity, e),
                derive_address(c.addr_secret.as_bytes(), &self.uid, e),
            )
        };
        let mut pt = [0u8; 1 + MAX_TEXT_LEN];
        pt[0] = BODY_DATA;
        pt[1..1 + self.pending_text_len as usize]
            .copy_from_slice(&self.pending_text[..self.pending_text_len as usize]);
        let pt_len = 1 + self.pending_text_len as usize;
        let h = Header {
            version: VERSION_SECURE,
            flags: FLAG_WANT_ACK,
            dst: u32::from_be_bytes(dst),
            src: u32::from_be_bytes(src),
            packet_id: ps.packet_id,
            hops: 1,
            epoch,
            sequence: ps.sequence,
        };
        let aad = security::frame_aad(&h, (pt_len + TAG_LEN) as u8);
        let mut body = [0u8; 1 + MAX_TEXT_LEN + TAG_LEN];
        let ct_len = security::encrypt_data(&key, &nonce, &aad, &pt[..pt_len], &mut body)
            .map_err(|_| EngineError::StorageFault)?;
        let mut bytes = [0u8; MAX_FRAME_LEN];
        let len = frame::encode_frame(&h, &body[..ct_len], &mut bytes)
            .map_err(|_| EngineError::BadRequest)?;
        // Consume reservation + record epoch max (persist staged alongside).
        {
            let c = &mut self.contacts[slot];
            c.tx_next = ps.sequence + 1;
            c.tx_epoch_max = c.tx_epoch_max.max(epoch);
        }
        self.persisted_tx_epoch = self.persisted_tx_epoch.max(epoch);
        self.stage_persist(StagedCommit::None);
        let mut ps2 = ps;
        ps2.epoch = epoch;
        self.pending_send = Some(ps2);
        Ok(OutgoingFrame {
            len,
            bytes,
            contact_id: Some(ps.contact_id),
            is_ack: false,
            is_retry_echo: false,
        })
    }

    /// Identical retry bytes for the in-flight send (never re-encrypts).
    pub fn send_retry_echo(&mut self) -> Result<OutgoingFrame, EngineError> {
        let ps = self.pending_send.ok_or(EngineError::BadRequest)?;
        let slot = self.slot_of(ps.contact_id)?;
        let key = self.outgoing_key(slot, ps.epoch)?;
        let nonce = security::nonce(ps.epoch, ps.sequence);
        let (dst, src) = {
            let c = &self.contacts[slot];
            (
                derive_address(c.addr_secret.as_bytes(), &c.peer_identity, ps.epoch),
                derive_address(c.addr_secret.as_bytes(), &self.uid, ps.epoch),
            )
        };
        let mut pt = [0u8; 1 + MAX_TEXT_LEN];
        pt[0] = BODY_DATA;
        pt[1..1 + self.pending_text_len as usize]
            .copy_from_slice(&self.pending_text[..self.pending_text_len as usize]);
        let pt_len = 1 + self.pending_text_len as usize;
        let h = Header {
            version: VERSION_SECURE,
            flags: FLAG_WANT_ACK,
            dst: u32::from_be_bytes(dst),
            src: u32::from_be_bytes(src),
            packet_id: ps.packet_id,
            hops: 1,
            epoch: ps.epoch,
            sequence: ps.sequence,
        };
        let aad = security::frame_aad(&h, (pt_len + TAG_LEN) as u8);
        let mut body = [0u8; 1 + MAX_TEXT_LEN + TAG_LEN];
        let ct_len = security::encrypt_data(&key, &nonce, &aad, &pt[..pt_len], &mut body)
            .map_err(|_| EngineError::StorageFault)?;
        let mut bytes = [0u8; MAX_FRAME_LEN];
        let len = frame::encode_frame(&h, &body[..ct_len], &mut bytes)
            .map_err(|_| EngineError::BadRequest)?;
        Ok(OutgoingFrame {
            len,
            bytes,
            contact_id: Some(ps.contact_id),
            is_ack: false,
            is_retry_echo: true,
        })
    }

    pub fn send_complete(&mut self, acked: bool) {
        let _ = acked;
        self.pending_send = None;
    }

    fn slot_of(&self, contact_id: u8) -> Result<usize, EngineError> {
        if contact_id < 1 || contact_id as usize > MAX_CONTACTS {
            return Err(EngineError::BadRequest);
        }
        let slot = (contact_id - 1) as usize;
        if !self.contacts[slot].present {
            return Err(EngineError::BadRequest);
        }
        Ok(slot)
    }

    // ---------- receive path ----------

    /// Process one received frame. Pure + staged-persist: on
    /// `Deliver`/`ReAck`/`Ack` the caller must commit `pending_persist()`
    /// then call `commit_ok()` before emitting `out_ack` or the event.
    pub fn on_frame(
        &mut self,
        frame_bytes: &[u8],
        now_ms: u64,
        ack_packet_id: u32,
    ) -> (IncomingKind, Option<OutgoingFrame>, Option<NodeEvent>) {
        // Structural checks first (relay-compatible, keyless).
        let (h, body) = match frame::decode_frame(frame_bytes) {
            Ok(v) => v,
            Err(_) => return (IncomingKind::Ignore, None, None),
        };
        if h.version != VERSION_SECURE {
            return (IncomingKind::Ignore, None, None);
        }
        if h.hops > 1 {
            return (IncomingKind::Ignore, None, None);
        }
        if !self.provisioned || self.fault {
            // Unprovisioned/faulted nodes still forward opaquely.
            return self.transit(frame_bytes, &h, now_ms, true);
        }
        if !self.time_valid {
            return self.transit(frame_bytes, &h, now_ms, true);
        }
        // Try endpoint authentication for every present, unblocked contact
        // across the 3 retained epochs x alias collisions.
        let local_epoch = self.epoch();
        if self.time_valid && !in_accept_window(h.epoch, local_epoch) {
            return self.transit(frame_bytes, &h, now_ms, false);
        }
        let mut authentication_failed = false;
        for slot in 0..MAX_CONTACTS {
            if !self.contacts[slot].present {
                continue;
            }
            let win_idx = match self.contacts[slot]
                .win_epochs
                .iter()
                .position(|e| *e == h.epoch)
            {
                Some(i) => i,
                None => continue,
            };
            // Alias candidate selection: a match only selects which
            // directional key to TRY; AEAD success decides delivery.
            self.refresh_aliases(slot);
            let se = *self.contacts[slot].addr_secret.as_bytes();
            let own_a = derive_address(&se, &self.uid, h.epoch);
            let peer_a = derive_address(&se, &self.contacts[slot].peer_identity, h.epoch);
            let dst_b = h.dst.to_be_bytes();
            let src_b = h.src.to_be_bytes();
            if dst_b != own_a || src_b != peer_a {
                continue;
            }
            let key = match self.incoming_key(slot, h.epoch) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let nonce = security::nonce(h.epoch, h.sequence);
            let aad = security::frame_aad(&h, body.len() as u8);
            let mut pt = [0u8; 1 + MAX_TEXT_LEN];
            let pt_len = match security::decrypt_data(&key, &nonce, &aad, body, &mut pt) {
                Ok(n) => n,
                Err(_) => {
                    authentication_failed = true;
                    continue;
                }
            };
            // Validate decrypted body + flags agreement.
            if frame::validate_body(h.flags, &pt[..pt_len]).is_err() {
                continue;
            }
            let contact_id = (slot + 1) as u8;
            if self.contacts[slot].blocked {
                return (IncomingKind::Ignore, None, None);
            }
            if pt[0] == BODY_DATA {
                let is_ack_frame = false;
                let verdict = {
                    let c = &mut self.contacts[slot];
                    let w = &mut c.win_data[win_idx];
                    w.accept(h.sequence)
                };
                match verdict {
                    security::Verdict::Accepted => {
                        // Commit reception BEFORE event/ACK.
                        self.stage_persist(StagedCommit::RxAccept);
                        let text = &pt[1..pt_len];
                        let mut tb = [0u8; MAX_TEXT_LEN];
                        tb[..text.len()].copy_from_slice(text);
                        let ev = NodeEvent::Received {
                            contact_id,
                            epoch: h.epoch,
                            sequence: h.sequence,
                            text: tb,
                            text_len: text.len() as u8,
                        };
                        let ack = self.build_ack(slot, &h, ack_packet_id);
                        let _ = is_ack_frame;
                        return (
                            IncomingKind::Deliver {
                                contact_id,
                                text_len: text.len() as u8,
                            },
                            ack,
                            Some(ev),
                        );
                    }
                    security::Verdict::Duplicate => {
                        self.replay_drops = self.replay_drops.saturating_add(1);
                        self.stage_persist(StagedCommit::None);
                        let ack = self.build_ack(slot, &h, ack_packet_id);
                        return (IncomingKind::ReAck { contact_id }, ack, None);
                    }
                    security::Verdict::Stale => {
                        self.replay_drops = self.replay_drops.saturating_add(1);
                        return (IncomingKind::Ignore, None, None);
                    }
                }
            } else {
                // ACK body: check replay window, then match pending send.
                let ref_epoch = u32::from_be_bytes([pt[1], pt[2], pt[3], pt[4]]);
                let ref_seq =
                    u64::from_be_bytes([pt[5], pt[6], pt[7], pt[8], pt[9], pt[10], pt[11], pt[12]]);
                let ref_pid = u32::from_be_bytes([pt[13], pt[14], pt[15], pt[16]]);
                let verdict = {
                    let c = &mut self.contacts[slot];
                    // ACK windows are keyed by the ACK's own envelope
                    // sequence, not the referenced DATA sequence.
                    let own_idx = match c.win_epochs.iter().position(|e| *e == h.epoch) {
                        Some(i) => i,
                        None => return (IncomingKind::Ignore, None, None),
                    };
                    c.win_ack[own_idx].accept(h.sequence)
                };
                match verdict {
                    security::Verdict::Stale | security::Verdict::Duplicate => {
                        self.replay_drops = self.replay_drops.saturating_add(1);
                        return (IncomingKind::Ignore, None, None);
                    }
                    security::Verdict::Accepted => {}
                }
                self.stage_persist(StagedCommit::RxAccept);
                match self.pending_send {
                    Some(ps)
                        if ps.contact_id == contact_id
                            && ps.epoch == ref_epoch
                            && ps.sequence == ref_seq
                            && ps.packet_id == ref_pid =>
                    {
                        let ev = NodeEvent::SendAcked {
                            contact_id,
                            epoch: ref_epoch,
                            sequence: ref_seq,
                            packet_id: ref_pid,
                        };
                        return (IncomingKind::Ack { contact_id }, None, Some(ev));
                    }
                    _ => return (IncomingKind::Ignore, None, None),
                }
            }
        }
        if authentication_failed {
            self.auth_failures = self.auth_failures.saturating_add(1);
        }
        // No contact authenticated: opaque transit.
        self.transit(frame_bytes, &h, now_ms, false)
    }

    /// Mark local DATA/ACK frames so an over-air echo is not forwarded.
    pub fn note_origin(&mut self, bytes: &[u8], now_ms: u64) {
        if let Ok((_, body)) = frame::decode_frame(bytes) {
            if let Some(key) = relay::cache_key_of_frame(bytes, body) {
                self.relay_cache.observe(&key, now_ms);
            }
        }
    }

    fn transit(
        &mut self,
        frame_bytes: &[u8],
        h: &Header,
        now_ms: u64,
        _unauth: bool,
    ) -> (IncomingKind, Option<OutgoingFrame>, Option<NodeEvent>) {
        let mut hb = [0u8; 28];
        hb.copy_from_slice(&frame_bytes[..28]);
        let body = &frame_bytes[28..frame_bytes.len() - 2];
        let hb_arr: [u8; 28] = hb;
        let key = relay::cache_key(&hb_arr, body);
        match self.relay_cache.observe(&key, now_ms) {
            relay::Observe::Duplicate => (IncomingKind::Ignore, None, None),
            relay::Observe::New => {
                if !relay::should_forward(h.hops, false, false) {
                    return (IncomingKind::Ignore, None, None);
                }
                let mut out = [0u8; MAX_FRAME_LEN];
                match relay::prepare_forward(frame_bytes, &mut out) {
                    Ok(len) => (
                        IncomingKind::Forward,
                        Some(OutgoingFrame {
                            len,
                            bytes: out,
                            contact_id: None,
                            is_ack: false,
                            is_retry_echo: false,
                        }),
                        None,
                    ),
                    Err(_) => (IncomingKind::Ignore, None, None),
                }
            }
        }
    }

    /// Build a fresh ACK under our current epoch/sequence/key. The
    /// reservation is staged; caller commits before transmitting.
    fn build_ack(&mut self, slot: usize, data_h: &Header, packet_id: u32) -> Option<OutgoingFrame> {
        if !self.time_valid {
            return None;
        }
        let epoch = self.epoch();
        let c = &mut self.contacts[slot];
        if c.tx_next >= c.tx_reserved {
            let new_reserved = c.tx_next.checked_add(SEQ_RESERVE_BLOCK)?;
            self.stage_persist(StagedCommit::TxReserve { slot, new_reserved });
        } else {
            self.stage_persist(StagedCommit::RxAccept);
        }
        let seq = self.contacts[slot].tx_next;
        let key = self.outgoing_key(slot, epoch).ok()?;
        let nonce = security::nonce(epoch, seq);
        let mut ref_pt = [0u8; 17];
        ref_pt[0] = BODY_ACK;
        ref_pt[1..5].copy_from_slice(&data_h.epoch.to_be_bytes());
        ref_pt[5..13].copy_from_slice(&data_h.sequence.to_be_bytes());
        ref_pt[13..17].copy_from_slice(&data_h.packet_id.to_be_bytes());
        let (dst, src) = {
            let c = &self.contacts[slot];
            (
                derive_address(c.addr_secret.as_bytes(), &c.peer_identity, epoch),
                derive_address(c.addr_secret.as_bytes(), &self.uid, epoch),
            )
        };
        let h = Header {
            version: VERSION_SECURE,
            flags: 0,
            dst: u32::from_be_bytes(dst),
            src: u32::from_be_bytes(src),
            packet_id,
            hops: 1,
            epoch,
            sequence: seq,
        };
        let aad = security::frame_aad(&h, (17 + TAG_LEN) as u8);
        let mut body = [0u8; 17 + TAG_LEN];
        let ct_len = security::encrypt_data(&key, &nonce, &aad, &ref_pt, &mut body).ok()?;
        let mut bytes = [0u8; MAX_FRAME_LEN];
        let len = frame::encode_frame(&h, &body[..ct_len], &mut bytes).ok()?;
        {
            let c = &mut self.contacts[slot];
            c.tx_next = seq + 1;
            c.tx_epoch_max = c.tx_epoch_max.max(epoch);
        }
        self.persisted_tx_epoch = self.persisted_tx_epoch.max(epoch);
        // Include consumed sequence and highest epoch in the same snapshot
        // as reception and any newly reserved nonce block.
        self.stage_persist(self.staged.unwrap_or(StagedCommit::RxAccept));
        Some(OutgoingFrame {
            len,
            bytes,
            contact_id: Some((slot + 1) as u8),
            is_ack: true,
            is_retry_echo: false,
        })
    }

    // ---------- contact removal ----------

    /// Delete a paired contact, freeing its slot. Secrets zeroize via
    /// `Secret32` drop. Staged for durable commit like every mutation.
    pub fn delete_contact(&mut self, contact_id: u8) -> Result<(), EngineError> {
        self.check_usable()?;
        let slot = self.slot_of(contact_id)?;
        self.contacts[slot] = Contact::empty();
        if let Some(ps) = self.pending_send {
            if ps.contact_id == contact_id {
                self.pending_send = None;
            }
        }
        self.stage_persist(StagedCommit::None);
        Ok(())
    }

    // ---------- blocking ----------

    pub fn set_blocked(
        &mut self,
        contact_id: u8,
        blocked: bool,
    ) -> Result<BlockOutcome, EngineError> {
        self.check_usable()?;
        let slot = self.slot_of(contact_id)?;
        self.contacts[slot].blocked = blocked;
        self.stage_persist(StagedCommit::None);
        if blocked {
            if let Some(ps) = self.pending_send {
                if ps.contact_id == contact_id {
                    self.pending_send = None;
                    return Ok(BlockOutcome::CancelledSend(ps));
                }
            }
            Ok(BlockOutcome::Blocked)
        } else {
            Ok(BlockOutcome::Unblocked)
        }
    }

    pub fn contact_present(&self, contact_id: u8) -> bool {
        (contact_id as usize) >= 1
            && (contact_id as usize) <= MAX_CONTACTS
            && self.contacts[(contact_id - 1) as usize].present
    }

    pub fn contact_blocked(&self, contact_id: u8) -> bool {
        self.contact_present(contact_id) && self.contacts[(contact_id - 1) as usize].blocked
    }

    pub fn contact_fingerprint(&self, contact_id: u8) -> Option<[u8; 32]> {
        if !self.contact_present(contact_id) {
            return None;
        }
        let c = &self.contacts[(contact_id - 1) as usize];
        let mut h = Sha256::new();
        h.update(c.ed_peer);
        let d: [u8; 32] = h.finalize().into();
        Some(d)
    }

    // ---------- persistence staging ----------

    fn stage_persist(&mut self, op: StagedCommit) {
        self.staged = Some(op);
        let bytes = crate::persist::encode_into(&self.persist_view(), &mut self.persist_scratch);
        self.persist_len = bytes;
        self.persist_dirty = true;
    }

    /// Bytes the caller must durably commit before using any staged effect.
    pub fn pending_persist(&self) -> Option<&[u8]> {
        if self.persist_dirty {
            Some(&self.persist_scratch[..self.persist_len])
        } else {
            None
        }
    }

    /// Apply the staged mutation after a successful durable commit.
    /// `TxReserve` applies the reservation; `PairActivate` clears pending
    /// secrets; reboot-skip is enforced at restore time.
    pub fn commit_ok(&mut self) {
        match self.staged.take() {
            Some(StagedCommit::TxReserve { slot, new_reserved }) => {
                if let Some(c) = self.contacts.get_mut(slot) {
                    c.tx_reserved = new_reserved;
                }
            }
            Some(StagedCommit::PairActivate { .. }) => {
                if let Some(p) = self.pending.take() {
                    let mut priv_copy = p.own_eph_priv;
                    priv_copy.zeroize();
                }
            }
            _ => {}
        }
        self.persist_dirty = false;
    }

    pub fn discard_staged(&mut self) {
        let _ = self.staged.take();
        self.persist_dirty = false;
        self.pending_send = None;
    }

    fn persist_view(&self) -> crate::persist::PersistView {
        let mut contacts = [crate::persist::PersistContact::empty(); MAX_CONTACTS];
        for (i, c) in self.contacts.iter().enumerate() {
            contacts[i] = crate::persist::PersistContact {
                present: c.present,
                blocked: c.blocked,
                ed_peer: c.ed_peer,
                peer_identity: c.peer_identity,
                root: *c.root.as_bytes(),
                role: c.role,
                tx_next: c.tx_next,
                tx_reserved: c.tx_reserved,
                tx_epoch_max: c.tx_epoch_max,
                anchor: c.anchor.anchor(),
                win_epochs: c.win_epochs,
                win_data: c
                    .win_data
                    .map(|w| (w.highest().unwrap_or(0), w.bitmap_bits(), w.is_empty())),
                win_ack: c
                    .win_ack
                    .map(|w| (w.highest().unwrap_or(0), w.bitmap_bits(), w.is_empty())),
            };
        }
        if let Some(StagedCommit::TxReserve { slot, new_reserved }) = self.staged {
            contacts[slot].tx_reserved = new_reserved;
        }
        let mut view = crate::persist::PersistView::new(
            self.provisioned,
            self.label,
            self.uid,
            self.uid_set,
            self.unix_seconds,
            self.persisted_tx_epoch,
            self.sign_priv,
            self.sign_set,
            contacts,
        );
        view.armed_next_boot = self.armed_next_boot;
        view
    }

    /// Restore from persisted bytes. Enforces reboot-skip of the last
    /// reserved transmit block and leaves `time_valid` false (boot = unset).
    pub fn restore(&mut self, bytes: &[u8]) -> Result<(), EngineError> {
        let view = crate::persist::decode_view(bytes).map_err(|_| EngineError::StorageFault)?;
        self.provisioned = view.provisioned;
        self.label = view.label;
        self.uid = view.uid;
        self.uid_set = view.uid_set;
        self.unix_seconds = view.unix_seconds;
        self.time_valid = false;
        self.persisted_tx_epoch = view.persisted_tx_epoch;
        self.radio_on = false;
        self.armed_next_boot = view.armed_next_boot;
        self.sign_priv = view.sign_priv;
        self.sign_set = view.sign_set;
        for (i, pc) in view.contacts.iter().enumerate() {
            let c = &mut self.contacts[i];
            *c = Contact::empty();
            if !pc.present {
                continue;
            }
            c.present = true;
            c.blocked = pc.blocked;
            c.ed_peer = pc.ed_peer;
            c.peer_identity = pc.peer_identity;
            c.root = Secret32::new(pc.root);
            c.traffic_lr = Secret32::new(security::derive_label(&pc.root, LABEL_TRAFFIC_LR));
            c.traffic_rl = Secret32::new(security::derive_label(&pc.root, LABEL_TRAFFIC_RL));
            c.addr_secret = Secret32::new(security::derive_label(&pc.root, LABEL_ADDRESS));
            c.role = pc.role;
            // Skip the whole last reserved block: never reuse a nonce.
            let skip_to = pc.tx_reserved.max(pc.tx_next);
            c.tx_next = skip_to;
            c.tx_reserved = pc.tx_reserved.max(skip_to);
            c.tx_epoch_max = pc.tx_epoch_max;
            c.anchor = AnchorHours::new(pc.anchor);
            c.win_epochs = pc.win_epochs;
            for s in 0..3 {
                c.win_data[s] =
                    ReplayWindow::restore(pc.win_data[s].0, pc.win_data[s].1, pc.win_data[s].2);
                c.win_ack[s] =
                    ReplayWindow::restore(pc.win_ack[s].0, pc.win_ack[s].1, pc.win_ack[s].2);
            }
            c.cached_epoch = u32::MAX;
        }
        self.pending = None;
        self.pending_send = None;
        self.persist_dirty = false;
        self.staged = None;
        Ok(())
    }

    // ---------- USB-facing helpers ----------

    pub fn present_count(&self) -> u8 {
        self.contacts.iter().filter(|c| c.present).count() as u8
    }

    pub fn auth_failures(&self) -> u32 {
        self.auth_failures
    }

    pub fn replay_drops(&self) -> u32 {
        self.replay_drops
    }

    pub fn blocked_count(&self) -> u8 {
        self.contacts
            .iter()
            .filter(|c| c.present && c.blocked)
            .count() as u8
    }

    pub fn mono_s(&self) -> u64 {
        self.mono_s
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.sign_priv.zeroize();
        self.pending_text.zeroize();
    }
}

// Re-export for persist module use.
pub(crate) fn contact_count() -> usize {
    MAX_CONTACTS
}
