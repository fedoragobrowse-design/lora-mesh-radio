//! Secure radio runtime: engine-owned send/ACK/retry/relay coordination.
//!
//! The radio task owns LoRa/SPI exclusively; this module owns the engine,
//! TRNG-derived packet IDs, awaited storage commits, policy gating, and USB
//! replies/events. Every engine mutation with a visible effect is committed
//! before the corresponding TX or delivery event. Full radio queues report
//! `BUSY`; terminal radio events are correlated by internal command IDs that
//! are distinct from USB request IDs.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};
use mesh_node::{BlockOutcome, Engine, EngineError, IncomingKind, NodeEvent, OutgoingFrame};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::radio::{AirFrame, RadioCmd, RadioEvt, TxFault, RADIO_BUF_LEN, RADIO_CMD, RADIO_EVT};
use crate::storage::{StorageReq, StorageResp, StoreHealth};
use crate::usb::{self, Counters, PendingOp, TxDoneSummary, UsbState, REPLY_LEN};

/// Bounded USB reply/event transport. Full => drop async events, never block
/// engine/radio progress. Replies are written by the USB writer task only.
pub static USB_TX: Channel<CriticalSectionRawMutex, UsbOut, 8> = Channel::new();

/// One bounded USB output record.
#[derive(Clone, Copy)]
pub struct UsbOut {
    pub len: u16,
    pub bytes: [u8; REPLY_LEN],
}

impl UsbOut {
    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > REPLY_LEN {
            return None;
        }
        let mut out = Self {
            len: bytes.len() as u16,
            bytes: [0u8; REPLY_LEN],
        };
        out.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Storage owner channels (main passes the existing statics).
pub struct StorageChannels {
    pub req: &'static Channel<CriticalSectionRawMutex, StorageReq, 2>,
    pub resp: &'static Channel<CriticalSectionRawMutex, StorageResp, 4>,
}

/// TRNG word source owned by main.
pub trait Entropy {
    async fn word(&mut self) -> u32;
    async fn fill(&mut self, out: &mut [u8]);
}

const MAX_TX: u8 = 3;
const ACK_WAIT: Duration = Duration::from_secs(12);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_DELAY_MIN_MS: u64 = 100;
const RELAY_DELAY_MAX_MS: u64 = 300;
const SEND_QUEUE_TIMEOUT_MS: u64 = 5_000;

/// Deferred secure send tracked across TX completions, ACK waits, retries.
struct InFlight {
    reply_id: u64,
    contact_id: u8,
    tx_count: u8,
    deadline: Instant,
    cmd_id: u64,
}

/// Deferred CAD-only ping.
struct PingInFlight {
    reply_id: u64,
    remaining: u8,
    clear: u8,
    cmd_id: u64,
}

/// Queued relay forward awaiting its listen delay.
struct PendingForward {
    frame: AirFrame,
    at: Instant,
    cmd_id: Option<u64>,
}

pub struct Runtime<'a, E: Entropy> {
    pub usb: UsbState,
    entropy: &'a mut E,
    storage: StorageChannels,
    next_cmd: u64,
    send: Option<InFlight>,
    ping: Option<PingInFlight>,
    forward: Option<PendingForward>,
    scratch: [u8; REPLY_LEN],
    last_policy: Option<(bool, u32)>,
    hw_present: bool,
}

impl<'a, E: Entropy> Runtime<'a, E> {
    pub fn new(usb: UsbState, entropy: &'a mut E, storage: StorageChannels) -> Self {
        Self {
            usb,
            entropy,
            storage,
            next_cmd: 1,
            send: None,
            ping: None,
            forward: None,
            scratch: [0u8; REPLY_LEN],
            last_policy: None,
            hw_present: false,
        }
    }

    /// Record whether real radio hardware initialized. Skips barrier waits
    /// when absent (no radio task drains commands); RF stays unavailable.
    pub fn set_hw_present(&mut self, present: bool) {
        self.hw_present = present;
    }

    /// Advance trusted UTC and durably rotate hour windows before I/O.
    pub async fn advance_time(&mut self) {
        if self
            .usb
            .engine
            .advance_time(Instant::now().as_secs())
            .is_err()
        {
            self.fail_radio_closed().await;
        } else if self.usb.engine.pending_persist().is_some() {
            let _ = self.commit().await;
        }
    }

    /// Scratch for USB pump dispatch; caller must not hold across awaits
    /// that let `on_usb_outcome` run (it reuses the same buffer).
    pub fn scratch(&mut self) -> &mut [u8; REPLY_LEN] {
        &mut self.scratch
    }

    /// Pump one CDC byte into the line buffer (no borrow of `self` fields
    /// beyond the call; scratch buffer is internal).
    pub fn pump_byte(
        &mut self,
        lines: &mut usb::LineBuffer,
        byte: u8,
        parse: &mut [u8],
    ) -> Option<usb::Outcome> {
        let (usb, scratch) = (&mut self.usb, &mut self.scratch);
        usb::pump_byte(usb, lines, byte, scratch, parse)
    }

    fn alloc_cmd(&mut self) -> u64 {
        let id = self.next_cmd;
        self.next_cmd = self.next_cmd.wrapping_add(1).max(1);
        id
    }

    async fn commit(&mut self) -> bool {
        // USB dispatch stages snapshots itself; radio-originated send/RX
        // operations stage only in the engine. Both must reach flash before
        // commit_ok permits TX, ACK, or delivery.
        if self.usb.staged.is_none() {
            usb::stage_for_commit(&mut self.usb);
        }
        if let Some((bytes, len)) = self.usb.staged.take() {
            self.storage
                .req
                .send(StorageReq::Commit { bytes, len })
                .await;
            let ok = loop {
                match self.storage.resp.receive().await {
                    StorageResp::Committed(r) => break r.is_ok(),
                    _ => continue,
                }
            };
            if ok {
                self.usb.engine.commit_ok();
                return true;
            }
            self.usb.engine.discard_staged();
            self.usb.engine.mark_fault();
            self.usb.health = StoreHealth::Fault;
            self.fail_radio_closed().await;
            return false;
        }
        true
    }
    /// Commit the staged `LSET` settings record under `KEY_SETTINGS`.
    /// No engine mutation, no policy sync, no barrier: on storage fault,
    /// revert to defaults live (the stored copy is authoritative) and report
    /// false so the caller emits `STORAGE_FAULT` without replying success.
    async fn commit_settings(&mut self) -> bool {
        let bytes = self.usb.settings.encode();
        self.storage
            .req
            .send(StorageReq::CommitSettings { bytes })
            .await;
        let ok = loop {
            match self.storage.resp.receive().await {
                StorageResp::Committed(r) => break r.is_ok(),
                // L9: a mid-run storage Fault must fail closed, never hang.
                StorageResp::Fault => break false,
                _ => continue,
            }
        };
        if ok {
            return true;
        }
        self.usb.settings = mesh_node::settings::Settings::default();
        self.usb.settings_tx_pending = false;
        false
    }

    /// Commit the staged WiFi credential under `KEY_WIFI`, then publish to
    /// `WIFI_CRED` so the radio task joins. `wifi_forget` commits a zeroed
    /// record; the commit path clears `wifi_configured` via commit_reply.
    /// On fault, restore the prior flag and fail the reply honestly.
    async fn commit_wifi(&mut self) -> bool {
        // Encode under KEY_WIFI via the radio codec when available; the
        // radio-free image has no wifi module, so it commits the zeroed
        // shape (forget path never runs there — wifi ops need the radio
        // image — but the arm must still typecheck).
        #[cfg(feature = "radio")]
        let bytes = match self.usb.staged_wifi {
            Some((ssid, sl, pass, pl)) => {
                let mut c = crate::wifi::WifiCred::empty();
                c.ssid = ssid;
                c.ssid_len = sl;
                c.pass = pass;
                c.pass_len = pl;
                c.encode()
            }
            None => crate::wifi::WifiCred::empty().encode(),
        };
        #[cfg(not(feature = "radio"))]
        let bytes = [0u8; 102];
        self.storage
            .req
            .send(StorageReq::CommitWifi { bytes })
            .await;
        let ok = loop {
            match self.storage.resp.receive().await {
                StorageResp::Committed(r) => break r.is_ok(),
                // L9: a mid-run storage Fault must fail closed, never hang.
                StorageResp::Fault => break false,
                _ => continue,
            }
        };
        if !ok {
            return false;
        }
        // Publish live (radio image only) so the WiFi task joins without a
        // reboot. Newer credential overwrites via drain + send, never blocks.
        // Forget commits zeros and skips publish; commit_reply clears the
        // flag. Staged secrets are scrubbed once published.
        #[cfg(feature = "radio")]
        {
            let is_forget = matches!(
                self.usb.staged_reply,
                Some(usb::StagedReply::WifiForget { .. })
            );
            if !is_forget {
                if let Some((ssid, sl, pass, pl)) = self.usb.staged_wifi {
                    let mut c = crate::wifi::WifiCred::empty();
                    c.ssid = ssid;
                    c.ssid_len = sl;
                    c.pass = pass;
                    c.pass_len = pl;
                    while crate::wifi::WIFI_CRED.try_receive().is_ok() {}
                    let _ = crate::wifi::WIFI_CRED.try_send(c);
                }
            }
            self.usb.staged_wifi = Some(([0u8; 32], 0, [0u8; 63], 0));
            self.usb.staged_wifi = None;
        }
        true
    }
    fn blocked_mask(&self) -> u32 {
        let mut mask = 0u32;
        for id in 1..=(mesh_node::MAX_CONTACTS as u8) {
            if self.usb.engine.contact_blocked(id) {
                mask |= 1 << (id - 1);
            }
        }
        mask
    }

    fn reply(&mut self, bytes: &[u8]) {
        if let Some(out) = UsbOut::new(bytes) {
            let _ = USB_TX.try_send(out);
        }
    }

    fn reply_outcome(&mut self, outcome: usb::Outcome) {
        if let usb::Outcome::Inline(len) = outcome {
            let mut owned = [0u8; REPLY_LEN];
            owned[..len].copy_from_slice(&self.scratch[..len]);
            self.reply(&owned[..len]);
        }
    }

    /// Radio-free safety: disable RF, clear pending work, fail deferred ops.
    async fn fail_radio_closed(&mut self) {
        let mask = self.blocked_mask();
        crate::radio::set_policy(false, mask);
        // Mirror the direct gate write so the next sync_policy diff compares
        // against reality: without this the cache still claims the old
        // (enabled) tuple and never re-syncs the forced-off gate.
        self.last_policy = Some((false, mask));
        let cmd = self.alloc_cmd();
        let _ = RADIO_CMD.try_send(RadioCmd::SetEnabled {
            id: cmd,
            enabled: false,
        });
        if let Some(send) = self.send.take() {
            self.usb.engine.send_complete(false);
            self.emit_err(send.reply_id, usb::err::STORAGE_FAULT);
        }
        self.ping = None;
        self.forward = None;
    }

    fn emit_err(&mut self, id: u64, code: &str) {
        let outcome = self.render_err(id, code);
        self.reply_outcome(outcome);
    }

    fn render_err(&mut self, id: u64, code: &str) -> usb::Outcome {
        let mut tmp = [0u8; 64];
        let mut len = 0usize;
        let push = |buf: &mut [u8], len: &mut usize, s: &[u8]| {
            if *len + s.len() <= buf.len() {
                buf[*len..*len + s.len()].copy_from_slice(s);
                *len += s.len();
            }
        };
        push(&mut tmp, &mut len, b"{\"id\":");
        let mut num = [0u8; 20];
        let n = format_u64(id, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(&mut tmp, &mut len, b",\"ok\":false,\"error\":\"");
        push(&mut tmp, &mut len, code.as_bytes());
        push(&mut tmp, &mut len, b"\"}");
        self.scratch[..len].copy_from_slice(&tmp[..len]);
        usb::Outcome::Inline(len)
    }

    /// USB parser entry: called for every pump outcome with TRNG available.
    /// `NeedsCommit` for radio/block routes through barrier-gated controls;
    /// all other commits reply inline after durable commit.
    pub async fn on_usb_outcome(&mut self, mut outcome: usb::Outcome) {
        if outcome == usb::Outcome::NeedsTrng {
            outcome = self.drive_trng_op().await;
        }
        if outcome == usb::Outcome::NeedsSendPrep {
            outcome = self.drive_send_prep().await;
        }
        if outcome == usb::Outcome::NeedsPingPrep {
            outcome = self.drive_ping_prep().await;
        }
        if matches!(outcome, usb::Outcome::NeedsCommit(_)) {
            // Radio/block dispatches already mutated the engine and staged
            // persist bytes; route those through barrier-gated controls.
            // Detect kind without consuming staged_reply (controls reply).
            enum Deferred {
                Radio {
                    id: u64,
                    enabled: bool,
                },
                Block {
                    id: u64,
                    contact_id: u8,
                    blocked: bool,
                },
            }
            let deferred = match self.usb.staged_reply {
                Some(usb::StagedReply::RadioSet { id, enabled }) => {
                    Some(Deferred::Radio { id, enabled })
                }
                Some(usb::StagedReply::Block {
                    id,
                    contact_id,
                    blocked,
                }) => Some(Deferred::Block {
                    id,
                    contact_id,
                    blocked,
                }),
                // Delete mutated + staged like block: same commit, policy
                // sync, and barrier. A deleted-while-blocked slot must clear
                // its policy bit or re-pair mints dead tokens.
                Some(usb::StagedReply::Simple { id, .. }) => {
                    if !self.commit().await {
                        self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
                        return;
                    }
                    self.sync_policy();
                    // Cancel in-flight TX bound for the freed slot.
                    // The slot is empty now, so the engine blocked flag is
                    // clear: report BUSY (stale binding), never CONTACT_BLOCKED
                    // (wire contract: flag still set). Host must re-resolve.
                    let pending = self.send.take();
                    if let Some(send) = pending {
                        self.usb.engine.send_complete(false);
                        self.emit_err(send.reply_id, usb::err::BUSY);
                    }
                    if self.hw_present {
                        let barrier = self.alloc_cmd();
                        if RADIO_CMD
                            .try_send(RadioCmd::Barrier { id: barrier })
                            .is_err()
                        {
                            self.emit_err(id, usb::err::BUSY);
                            return;
                        }
                        let ok = self.wait_control(barrier).await;
                        if !ok {
                            self.emit_err(id, usb::err::STORAGE_FAULT);
                            return;
                        }
                    }
                    None
                }
                // Settings carry no engine mutation: commit the 13-byte LSET
                // record under KEY_SETTINGS, then fall through to the shared
                // commit_reply render (no barrier, no policy sync).
                Some(usb::StagedReply::SettingsSet { .. }) => {
                    if !self.commit_settings().await {
                        self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
                        return;
                    }
                    None
                }
                // WiFi credential: commit the 102-byte WSET record under
                // KEY_WIFI, publish to WIFI_CRED (radio task joins on next
                // loop), then fall through to commit_reply render.
                Some(usb::StagedReply::WifiSet { .. })
                | Some(usb::StagedReply::WifiForget { .. }) => {
                    if !self.commit_wifi().await {
                        self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
                        return;
                    }
                    None
                }
                _ => None,
            };
            match deferred {
                Some(Deferred::Radio { id, enabled }) => {
                    // control path commits the already-staged bytes once,
                    // gates policy, waits the barrier, then replies.
                    self.control_set_radio_already_staged(id, enabled).await;
                    return;
                }
                Some(Deferred::Block {
                    id,
                    contact_id,
                    blocked,
                }) => {
                    self.control_set_blocked_already_staged(id, contact_id, blocked)
                        .await;
                    return;
                }
                None => {
                    if !self.commit().await {
                        self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
                        return;
                    }
                }
            }
        }
        match outcome {
            usb::Outcome::Inline(len) => {
                let mut owned = [0u8; REPLY_LEN];
                owned[..len].copy_from_slice(&self.scratch[..len]);
                self.reply(&owned[..len]);
            }
            usb::Outcome::NeedsCommit(_) => {
                if let Some(len) = usb::commit_reply(&mut self.usb, &mut self.scratch) {
                    let mut owned = [0u8; REPLY_LEN];
                    owned[..len].copy_from_slice(&self.scratch[..len]);
                    self.reply(&owned[..len]);
                }
            }
            // Reboot is driven by main's USB loop (needs the class handle
            // for TX flush + the ROM call); the runtime only parks it.
            usb::Outcome::NeedsRebootBootsel => {
                // Re-park so main's USB loop can observe it after the reply
                // flushes through USB_TX below.
                self.usb.pending_op = Some(usb::PendingOp::RebootBootsel {
                    id: self.usb.reply_id,
                });
                if let Some(len) = usb::reply_rebooting(&mut self.usb, &mut self.scratch) {
                    let mut owned = [0u8; REPLY_LEN];
                    owned[..len].copy_from_slice(&self.scratch[..len]);
                    self.reply(&owned[..len]);
                }
            }
            _ => {}
        }
    }

    fn reply_bytes(&mut self, bytes: &[u8]) {
        self.reply(bytes);
    }

    async fn drive_trng_op(&mut self) -> usb::Outcome {
        match self.usb.pending_op.take() {
            Some(PendingOp::Provision { id, label }) => {
                let mut key = [0u8; 32];
                self.entropy.fill(&mut key).await;
                let result =
                    usb::complete_provision(&mut self.usb, id, label, key, &mut self.scratch);
                key.zeroize();
                result
            }
            Some(PendingOp::PairOffer { id }) => {
                let mut eph_priv = [0u8; 32];
                let mut challenge = [0u8; 32];
                self.entropy.fill(&mut eph_priv).await;
                self.entropy.fill(&mut challenge).await;
                let eph_pub = PublicKey::from(&StaticSecret::from(eph_priv)).to_bytes();
                let result = usb::complete_pair_offer(
                    &mut self.usb,
                    id,
                    eph_priv,
                    eph_pub,
                    challenge,
                    &mut self.scratch,
                );
                eph_priv.zeroize();
                result
            }
            _ => usb::Outcome::Silent,
        }
    }

    /// Stage + commit a validated send, queue the first TX, defer the reply.
    async fn drive_send_prep(&mut self) -> usb::Outcome {
        let (id, contact) = match self.usb.pending_op.take() {
            Some(PendingOp::SendPrep { id, contact_id }) => (id, contact_id),
            _ => return usb::Outcome::Silent,
        };
        // M2: fail fast when the radio is off — never burn a seq
        // reservation + flash commit for a TX the policy gate will cancel.
        if !self.usb.engine.radio_on() {
            self.usb.send_len = 0;
            return self.render_err(id, usb::err::RADIO_UNAVAILABLE);
        }
        if self.send.is_some() {
            self.usb.send_len = 0;
            return self.render_err(id, usb::err::BUSY);
        }
        let len = self.usb.send_len as usize;
        let mut text = [0u8; 160];
        text[..len].copy_from_slice(&self.usb.send_text[..len]);
        let packet_id = self.usb.next_packet_id(self.entropy.word().await);
        let begin_code = match self.usb.engine.send_begin(contact, &text[..len], packet_id) {
            Ok(_) => None,
            Err(e) => Some(engine_code(e)),
        };
        if let Some(code) = begin_code {
            self.usb.send_len = 0;
            return self.render_err(id, code);
        }
        if !self.commit().await {
            self.usb.send_len = 0;
            return self.render_err(id, usb::err::STORAGE_FAULT);
        }
        let frame = match self.usb.engine.send_emit() {
            Ok(f) => f,
            Err(e) => {
                self.usb.engine.send_complete(false);
                self.usb.send_len = 0;
                return self.render_err(id, engine_code(e));
            }
        };
        if !self.commit().await {
            self.usb.send_len = 0;
            return self.render_err(id, usb::err::STORAGE_FAULT);
        }
        self.usb.send_len = 0;
        self.queue_tx(id, Some(contact), &frame, false).await;
        usb::Outcome::Silent
    }

    async fn queue_tx(
        &mut self,
        reply_id: u64,
        contact: Option<u8>,
        frame: &OutgoingFrame,
        is_retry: bool,
    ) {
        let jitter = (self.entropy.word().await % 81 + 20) as u64;
        // Sync the gate before minting: committed engine bits must be
        // visible to the radio before the token snapshots generations.
        self.sync_policy();
        let token = crate::radio::tx_token(contact);
        let cmd_id = self.alloc_cmd();
        let air = air_from_outgoing(frame);
        match RADIO_CMD.try_send(RadioCmd::Tx {
            id: cmd_id,
            frame: air,
            jitter_ms: jitter,
            contact_id: contact,
            token,
        }) {
            Ok(()) => {
                if !is_retry {
                    if contact.is_some() {
                        self.send = Some(InFlight {
                            reply_id,
                            contact_id: contact.unwrap(),
                            tx_count: 1,
                            deadline: Instant::now() + ACK_WAIT,
                            cmd_id,
                        });
                    } else {
                        self.forward = Some(PendingForward {
                            frame: air,
                            at: Instant::now(),
                            cmd_id: Some(cmd_id),
                        });
                        self.usb.counters.report_forward();
                    }
                }
            }
            Err(_) => {
                if contact.is_some() {
                    self.usb.engine.send_complete(false);
                    self.emit_err(reply_id, usb::err::BUSY);
                }
            }
        }
        let _ = is_retry;
    }

    async fn drive_ping_prep(&mut self) -> usb::Outcome {
        let (id, count) = match self.usb.pending_op.take() {
            Some(PendingOp::PingPrep { id, count }) => (id, count),
            _ => return usb::Outcome::Silent,
        };
        if self.ping.is_some() {
            return self.render_err(id, usb::err::BUSY);
        }
        let cmd_id = self.alloc_cmd();
        match RADIO_CMD.try_send(RadioCmd::CadProbe { id: cmd_id }) {
            Ok(()) => {
                self.ping = Some(PingInFlight {
                    reply_id: id,
                    remaining: count,
                    clear: 0,
                    cmd_id,
                });
            }
            Err(_) => return self.render_err(id, usb::err::BUSY),
        }
        usb::Outcome::Silent
    }

    /// Correlated radio events. ACK/forward completions never touch the DATA wait.
    pub async fn on_radio_evt(&mut self, evt: RadioEvt) {
        match evt {
            RadioEvt::ControlDone { id: _, ok: _ } => {}
            RadioEvt::TxDone {
                id,
                result,
                attempted,
            } => self.on_tx_done(id, result, attempted).await,
            RadioEvt::CadDone { id, result } => self.on_cad_done(id, result).await,
            RadioEvt::RxFrame(frame) => self.on_rx(frame).await,
            RadioEvt::RxCrcError => self.usb.counters.report_rx_crc(),
            RadioEvt::Fault => self.fail_radio_closed().await,
        }
    }

    async fn on_tx_done(&mut self, id: u64, result: Result<(), TxFault>, attempted: bool) {
        if attempted {
            self.usb.counters.report_tx_attempted();
        }
        let summary = match result {
            Ok(()) => TxDoneSummary::Success,
            Err(TxFault::ChannelBusy) => TxDoneSummary::Busy,
            Err(TxFault::Cancelled) => TxDoneSummary::Cancelled,
            Err(TxFault::Radio) => TxDoneSummary::Radio,
        };
        self.usb.counters.report_tx_done(summary);
        // DATA completion?
        if let Some(send) = self.send.take() {
            if send.cmd_id == id {
                match result {
                    Ok(()) => {
                        self.send = Some(InFlight {
                            reply_id: send.reply_id,
                            contact_id: send.contact_id,
                            tx_count: send.tx_count,
                            deadline: Instant::now() + ACK_WAIT,
                            cmd_id: id,
                        });
                    }
                    Err(TxFault::ChannelBusy) => {
                        self.usb.engine.send_complete(false);
                        self.emit_err(send.reply_id, usb::err::CHANNEL_BUSY);
                    }
                    Err(TxFault::Cancelled) => {
                        // Cancelled conflates radio-off, still-blocked, and
                        // stale-token (policy generation moved under an
                        // already-authorized send, e.g. an unblock or radio
                        // cycle between token mint and pre-TX check). Report
                        // honestly: only claim CONTACT_BLOCKED when the
                        // engine flag is still set; otherwise BUSY so the
                        // host retries with a fresh token instead of
                        // concluding the contact is blocked.
                        self.usb.engine.send_complete(false);
                        if self.usb.engine.contact_blocked(send.contact_id) {
                            self.emit_err(send.reply_id, usb::err::CONTACT_BLOCKED);
                        } else {
                            self.emit_err(send.reply_id, usb::err::BUSY);
                        }
                    }
                    Err(TxFault::Radio) => {
                        self.usb.engine.send_complete(false);
                        self.emit_err(send.reply_id, "RADIO");
                    }
                }
                return;
            } else {
                self.send = Some(send);
            }
        }
        // Forward/ACK completions are accounting only; never complete DATA.
        if let Some(fwd) = self.forward.take() {
            if fwd.cmd_id != Some(id) {
                self.forward = Some(fwd);
            }
        }
    }

    async fn on_cad_done(&mut self, id: u64, result: Result<bool, TxFault>) {
        let mut ping = match self.ping.take() {
            Some(p) if p.cmd_id == id => p,
            other => {
                self.ping = other;
                return;
            }
        };
        match result {
            Ok(clear) => {
                if clear {
                    ping.clear += 1;
                }
                ping.remaining -= 1;
                if ping.remaining == 0 {
                    let total = self.usb.ping_count;
                    self.emit_ping(ping.reply_id, total, ping.clear);
                    self.usb.ping_count = 0;
                } else {
                    let cmd_id = self.alloc_cmd();
                    match RADIO_CMD.try_send(RadioCmd::CadProbe { id: cmd_id }) {
                        Ok(()) => {
                            ping.cmd_id = cmd_id;
                            self.ping = Some(ping);
                        }
                        Err(_) => self.emit_err(ping.reply_id, usb::err::BUSY),
                    }
                }
            }
            Err(TxFault::Cancelled) => {
                // CAD probes carry no contact: Cancelled means the RF gate
                // was closed, never a blocked contact. Report the live
                // engine flag honestly, like the DATA path does.
                if self.usb.engine.radio_on() {
                    self.emit_err(ping.reply_id, usb::err::BUSY);
                } else {
                    self.emit_err(ping.reply_id, usb::err::RADIO_UNAVAILABLE);
                }
            }
            Err(_) => self.emit_err(ping.reply_id, "RADIO"),
        }
    }

    fn emit_ping(&mut self, id: u64, probes: u8, clear: u8) {
        let mut tmp = [0u8; 96];
        let mut len = 0usize;
        let push = |buf: &mut [u8], len: &mut usize, s: &[u8]| {
            if *len + s.len() <= buf.len() {
                buf[*len..*len + s.len()].copy_from_slice(s);
                *len += s.len();
            }
        };
        push(&mut tmp, &mut len, b"{\"id\":");
        let mut num = [0u8; 20];
        let n = format_u64(id, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(&mut tmp, &mut len, b",\"ok\":true,\"result\":{\"probes\":");
        let n = format_u64(probes as u64, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(&mut tmp, &mut len, b",\"clear\":");
        let n = format_u64(clear as u64, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(&mut tmp, &mut len, b"}}");
        self.scratch[..len].copy_from_slice(&tmp[..len]);
        self.reply_outcome(usb::Outcome::Inline(len));
    }

    async fn on_rx(&mut self, frame: AirFrame) {
        let now_ms = Instant::now().as_millis();
        let bytes = &frame.bytes[..frame.len as usize];
        let ack_id = self.entropy.word().await;
        let (kind, out_ack, event) = self.usb.engine.on_frame(bytes, now_ms, ack_id);
        self.usb.counters.mirror_reception(&self.usb.engine);
        match kind {
            IncomingKind::Deliver { contact_id, .. } => {
                self.usb.counters.report_rx_frame();
                if !self.commit().await {
                    return;
                }
                if let Some(ack) = out_ack {
                    self.send_ack_frame(ack).await;
                }
                if let Some(NodeEvent::Received {
                    contact_id,
                    epoch,
                    sequence,
                    text,
                    text_len,
                }) = event
                {
                    self.emit_received(contact_id, epoch, sequence, &text[..text_len as usize]);
                }
                let _ = contact_id;
            }
            IncomingKind::ReAck { .. } => {
                if !self.commit().await {
                    return;
                }
                if let Some(ack) = out_ack {
                    self.send_ack_frame(ack).await;
                }
            }
            IncomingKind::Ack { contact_id } => {
                if !self.commit().await {
                    return;
                }
                if let Some(send) = self.send.take() {
                    if send.contact_id == contact_id {
                        self.usb.engine.send_complete(true);
                        self.emit_acknowledged(send.reply_id);
                    } else {
                        self.send = Some(send);
                    }
                }
                let _ = event;
            }
            IncomingKind::Forward => {
                if let Some(fwd) = out_ack {
                    self.schedule_forward(fwd).await;
                }
            }
            IncomingKind::Ignore => {
                if self.usb.engine.pending_persist().is_some() {
                    let _ = self.commit().await;
                }
            }
        }
    }

    async fn send_ack_frame(&mut self, ack: OutgoingFrame) {
        let contact = ack.contact_id;
        let jitter = (self.entropy.word().await % 81 + 20) as u64;
        // Sync before mint so a just-committed block bit is visible here.
        self.sync_policy();
        let token = crate::radio::tx_token(contact);
        let cmd_id = self.alloc_cmd();
        let air = air_from_outgoing(&ack);
        self.usb
            .engine
            .note_origin(ack.as_slice(), Instant::now().as_millis());
        if RADIO_CMD
            .try_send(RadioCmd::Tx {
                id: cmd_id,
                frame: air,
                jitter_ms: jitter,
                contact_id: contact,
                token,
            })
            .is_err()
        {
            // Bounded queue full: drop this ACK rather than block; endpoint
            // retries will re-solicit it.
        }
    }

    async fn schedule_forward(&mut self, fwd: OutgoingFrame) {
        let jitter = RELAY_DELAY_MIN_MS
            + (self.entropy.word().await as u64 % (RELAY_DELAY_MAX_MS - RELAY_DELAY_MIN_MS + 1));
        let air = air_from_outgoing(&fwd);
        self.forward = Some(PendingForward {
            frame: air,
            at: Instant::now() + Duration::from_millis(jitter),
            cmd_id: None,
        });
        self.usb.counters.report_forward();
    }

    fn emit_received(&mut self, contact_id: u8, epoch: u32, sequence: u64, text: &[u8]) {
        if let Some(len) = usb::reply_received(contact_id, epoch, sequence, text, &mut self.scratch)
        {
            let mut owned = [0u8; REPLY_LEN];
            owned[..len].copy_from_slice(&self.scratch[..len]);
            self.reply(&owned[..len]);
        }
    }

    fn emit_acknowledged(&mut self, id: u64) {
        let mut tmp = [0u8; 64];
        let mut len = 0usize;
        let push = |buf: &mut [u8], len: &mut usize, s: &[u8]| {
            if *len + s.len() <= buf.len() {
                buf[*len..*len + s.len()].copy_from_slice(s);
                *len += s.len();
            }
        };
        push(&mut tmp, &mut len, b"{\"id\":");
        let mut num = [0u8; 20];
        let n = format_u64(id, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(
            &mut tmp,
            &mut len,
            b",\"ok\":true,\"result\":{\"status\":\"ACKNOWLEDGED\"}}",
        );
        self.scratch[..len].copy_from_slice(&tmp[..len]);
        self.reply_outcome(usb::Outcome::Inline(len));
    }

    /// Deadline driver: call regularly; performs retries or UNCONFIRMED.
    pub async fn poll_timeouts(&mut self) {
        if let Some(send) = self.send.take() {
            if Instant::now() >= send.deadline {
                if send.tx_count < MAX_TX {
                    match self.usb.engine.send_retry_echo() {
                        Ok(frame) => {
                            let jitter = (self.entropy.word().await % 81 + 20) as u64;
                            let contact = Some(send.contact_id);
                            // Re-sync: the gate may have moved while awaiting the deadline.
                            self.sync_policy();
                            let token = crate::radio::tx_token(contact);
                            let cmd_id = self.alloc_cmd();
                            let air = air_from_outgoing(&frame);
                            match RADIO_CMD.try_send(RadioCmd::Tx {
                                id: cmd_id,
                                frame: air,
                                jitter_ms: jitter,
                                contact_id: contact,
                                token,
                            }) {
                                Ok(()) => {
                                    self.send = Some(InFlight {
                                        reply_id: send.reply_id,
                                        contact_id: send.contact_id,
                                        tx_count: send.tx_count + 1,
                                        deadline: Instant::now() + ACK_WAIT,
                                        cmd_id,
                                    });
                                }
                                Err(_) => {
                                    self.usb.engine.send_complete(false);
                                    self.emit_err(send.reply_id, usb::err::BUSY);
                                }
                            }
                        }
                        Err(e) => {
                            self.usb.engine.send_complete(false);
                            self.emit_err(send.reply_id, engine_code(e));
                        }
                    }
                } else {
                    self.usb.engine.send_complete(false);
                    self.emit_unconfirmed(send.reply_id);
                }
            } else {
                self.send = Some(send);
            }
        }
        if let Some(fwd) = self.forward.take() {
            if fwd.cmd_id.is_none() && Instant::now() >= fwd.at {
                let jitter = (self.entropy.word().await % 81 + 20) as u64;
                self.sync_policy();
                let token = crate::radio::tx_token(None);
                let cmd_id = self.alloc_cmd();
                match RADIO_CMD.try_send(RadioCmd::Tx {
                    id: cmd_id,
                    frame: fwd.frame,
                    jitter_ms: jitter,
                    contact_id: None,
                    token,
                }) {
                    Ok(()) => {
                        self.forward = Some(PendingForward {
                            frame: fwd.frame,
                            at: fwd.at,
                            cmd_id: Some(cmd_id),
                        });
                    }
                    Err(_) => {
                        // Queue full: keep the forward for the next poll.
                        self.forward = Some(fwd);
                    }
                }
            } else {
                self.forward = Some(fwd);
            }
        }
    }

    fn emit_unconfirmed(&mut self, id: u64) {
        let mut tmp = [0u8; 64];
        let mut len = 0usize;
        let push = |buf: &mut [u8], len: &mut usize, s: &[u8]| {
            if *len + s.len() <= buf.len() {
                buf[*len..*len + s.len()].copy_from_slice(s);
                *len += s.len();
            }
        };
        push(&mut tmp, &mut len, b"{\"id\":");
        let mut num = [0u8; 20];
        let n = format_u64(id, &mut num);
        push(&mut tmp, &mut len, &num[..n]);
        push(
            &mut tmp,
            &mut len,
            b",\"ok\":true,\"result\":{\"status\":\"UNCONFIRMED\"}}",
        );
        self.scratch[..len].copy_from_slice(&tmp[..len]);
        self.reply_outcome(usb::Outcome::Inline(len));
    }

    /// Wait for one `ControlDone` with `want`, forwarding other radio events.
    /// Bounded: 2s total even if the radio task is dead (each `receive` has
    /// its own timeout; the deadline is re-checked after every wake).
    async fn wait_control(&mut self, want: u64) -> bool {
        if !self.hw_present {
            return false;
        }
        let deadline = Instant::now() + Duration::from_millis(2000);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remain = deadline - now;
            match embassy_time::with_timeout(remain, RADIO_EVT.receive()).await {
                Err(_) => return false,
                Ok(RadioEvt::ControlDone { id, ok }) if id == want => return ok,
                Ok(other) => self.on_radio_evt(other).await,
            }
        }
    }

    /// Sync policy atom only when it changed; cheap critical-section write.
    fn sync_policy(&mut self) {
        let cur = (self.usb.engine.radio_on(), self.blocked_mask());
        if self.last_policy != Some(cur) {
            crate::radio::set_policy(cur.0, cur.1);
            self.last_policy = Some(cur);
        }
    }

    /// Already-staged radio transition: dispatch mutated the engine and
    /// staged persist bytes; commit once, gate policy, barrier, reply.
    async fn control_set_radio_already_staged(&mut self, id: u64, enabled: bool) {
        if !self.commit().await {
            self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
            return;
        }
        // M4: radio (re-)enable latches RF tunables; clear the pending flag.
        if enabled {
            self.usb.settings_tx_pending = false;
        }
        self.sync_policy();
        // No radio task drains commands when hardware is absent: skip the
        // SetEnabled/Barrier sends (`.send().await` would fill cap-8 and
        // hang the USB loop forever). Reply from the committed state.
        if self.hw_present {
            let cmd = self.alloc_cmd();
            // Bounded: never block the USB loop when the queue is full;
            // report BUSY-equivalent instead (STORAGE_FAULT keeps the
            // fail-closed reply path; queue-full is transient).
            if RADIO_CMD
                .try_send(RadioCmd::SetEnabled { id: cmd, enabled })
                .is_err()
            {
                self.emit_err(id, usb::err::BUSY);
                return;
            }
            // Barrier ensures the physical transition finished before reply.
            let barrier = self.alloc_cmd();
            if RADIO_CMD
                .try_send(RadioCmd::Barrier { id: barrier })
                .is_err()
            {
                self.emit_err(id, usb::err::BUSY);
                return;
            }
            let ok = self.wait_control(barrier).await;
            if !enabled {
                self.send = None;
                self.forward = None;
            }
            if !ok {
                // L5: commit already succeeded; a barrier timeout is a
                // transient radio stall, not a storage failure.
                self.emit_err(id, usb::err::BUSY);
                return;
            }
        } else if !enabled {
            self.send = None;
            self.forward = None;
        }
        if let Some(len) = usb::commit_reply(&mut self.usb, &mut self.scratch) {
            let mut owned = [0u8; REPLY_LEN];
            owned[..len].copy_from_slice(&self.scratch[..len]);
            self.reply(&owned[..len]);
        }
    }

    /// Direct control entry (unused by USB dispatch; kept for tests).
    pub async fn control_set_radio(&mut self, id: u64, enabled: bool) {
        if self.usb.engine.set_radio(enabled).is_err() {
            return;
        }
        // Stage persist bytes the way dispatch does, then shared path.
        if self.usb.staged.is_none() {
            // Engine mutated without staging (should not happen); fail closed.
            self.usb.engine.discard_staged();
            return;
        }
        self.control_set_radio_already_staged(id, enabled).await;
    }

    pub async fn control_set_blocked(&mut self, id: u64, contact_id: u8, blocked: bool) {
        match self.usb.engine.set_blocked(contact_id, blocked) {
            Ok(outcome) => {
                // Matches dispatch staging: commit once via shared path.
                if self.usb.staged.is_none() {
                    self.usb.engine.discard_staged();
                    return;
                }
                self.apply_block_commit(id, outcome).await;
            }
            Err(_) => {}
        }
    }

    /// Already-staged block transition: dispatch mutated the engine and
    /// staged persist bytes; commit once, barrier-gate, then reply.
    async fn control_set_blocked_already_staged(&mut self, id: u64, contact_id: u8, blocked: bool) {
        let _ = (contact_id, blocked);
        if !self.commit().await {
            self.emit_err(self.usb.reply_id, usb::err::STORAGE_FAULT);
            return;
        }
        self.sync_policy();
        if self.hw_present {
            let barrier = self.alloc_cmd();
            if RADIO_CMD
                .try_send(RadioCmd::Barrier { id: barrier })
                .is_err()
            {
                self.emit_err(id, usb::err::BUSY);
                return;
            }
            let ok = self.wait_control(barrier).await;
            if !ok {
                // L5: commit already succeeded; barrier timeout is BUSY.
                self.emit_err(id, usb::err::BUSY);
                return;
            }
        }
        if let Some(len) = usb::commit_reply(&mut self.usb, &mut self.scratch) {
            let mut owned = [0u8; REPLY_LEN];
            owned[..len].copy_from_slice(&self.scratch[..len]);
            self.reply(&owned[..len]);
        }
    }

    /// Shared block commit after engine mutation + staging.
    async fn apply_block_commit(&mut self, id: u64, outcome: BlockOutcome) {
        match outcome {
            BlockOutcome::CancelledSend(_) => {
                let pending = self.send.take();
                if !self.commit().await {
                    return;
                }
                self.sync_policy();
                if self.hw_present {
                    let barrier = self.alloc_cmd();
                    if RADIO_CMD
                        .try_send(RadioCmd::Barrier { id: barrier })
                        .is_err()
                    {
                        self.emit_err(id, usb::err::BUSY);
                        return;
                    }
                    let _ = self.wait_control(barrier).await;
                }
                if let Some(send) = pending {
                    self.emit_err(send.reply_id, usb::err::CONTACT_BLOCKED);
                }
                if let Some(len) = usb::commit_reply(&mut self.usb, &mut self.scratch) {
                    let mut owned = [0u8; REPLY_LEN];
                    owned[..len].copy_from_slice(&self.scratch[..len]);
                    self.reply(&owned[..len]);
                }
                let _ = id;
            }
            _ => {
                if !self.commit().await {
                    return;
                }
                self.sync_policy();
                if self.hw_present {
                    // Barrier-gate the deferred block reply the same way.
                    let barrier = self.alloc_cmd();
                    if RADIO_CMD
                        .try_send(RadioCmd::Barrier { id: barrier })
                        .is_err()
                    {
                        self.emit_err(id, usb::err::BUSY);
                        return;
                    }
                    let ok = self.wait_control(barrier).await;
                    if !ok {
                        self.emit_err(id, usb::err::STORAGE_FAULT);
                        return;
                    }
                }
                if let Some(len) = usb::commit_reply(&mut self.usb, &mut self.scratch) {
                    let mut owned = [0u8; REPLY_LEN];
                    owned[..len].copy_from_slice(&self.scratch[..len]);
                    self.reply(&owned[..len]);
                }
            }
        }
    }

    /// Queue-full watchdog for synchronous TX enqueue paths.
    pub async fn await_queue_space(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(SEND_QUEUE_TIMEOUT_MS);
        while RADIO_CMD.len() >= 8 && Instant::now() < deadline {
            Timer::after(Duration::from_millis(10)).await;
        }
    }
}

fn air_from_outgoing(frame: &OutgoingFrame) -> AirFrame {
    let mut air = AirFrame {
        len: frame.len.min(RADIO_BUF_LEN) as u8,
        bytes: [0u8; RADIO_BUF_LEN],
    };
    air.bytes[..air.len as usize].copy_from_slice(&frame.as_slice()[..air.len as usize]);
    air
}

fn engine_code(e: EngineError) -> &'static str {
    match e {
        EngineError::BadRequest => usb::err::BAD_REQUEST,
        EngineError::Unprovisioned => usb::err::UNPROVISIONED,
        EngineError::StorageFault => usb::err::STORAGE_FAULT,
        EngineError::TimeUnset => usb::err::TIME_UNSET,
        EngineError::TimeRollback => usb::err::TIME_ROLLBACK,
        EngineError::Busy => usb::err::BUSY,
        EngineError::ContactBlocked => usb::err::CONTACT_BLOCKED,
        EngineError::RadioMustBeOff => usb::err::RADIO_MUST_BE_OFF,
        EngineError::RadioUnavailable => usb::err::RADIO_UNAVAILABLE,
        _ => usb::err::BAD_REQUEST,
    }
}

fn format_u64(mut v: u64, out: &mut [u8; 20]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut i = 20;
    while v > 0 && i > 0 {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let len = 20 - i;
    out.copy_within(i..20, 0);
    len
}

pub struct TrngEntropy<'a, T> {
    trng: &'a mut T,
}

impl<'a, T> TrngEntropy<'a, T> {
    pub fn new(trng: &'a mut T) -> Self {
        Self { trng }
    }
}

impl<'a, T: embassy_rp::trng::Instance> Entropy for TrngEntropy<'a, embassy_rp::trng::Trng<'a, T>> {
    async fn word(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.trng.fill_bytes(&mut b).await;
        u32::from_le_bytes(b)
    }
    async fn fill(&mut self, out: &mut [u8]) {
        self.trng.fill_bytes(out).await;
    }
}

#[allow(dead_code)]
fn _counters_shape(_c: &mut Counters) {}
