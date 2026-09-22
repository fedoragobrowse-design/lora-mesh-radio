//! USB CDC contract: newline-delimited UTF-8 JSON, max 1024 bytes/command.
//!
//! Every request carries integer `id` and string `op`; replies echo `id`
//! with `ok` and either `result` or `error`. Asynchronous records use
//! `event`. An overlong line is discarded through its newline, reports
//! `LINE_TOO_LONG`, and the parser resumes on the next line.
//!
//! Radio-free image contract (matches the native exerciser byte-for-byte):
//! `image` is `"radio-free"`, `radio_available` is always false, and there
//! is NO `radio_version` field (no SPI read has happened; never fabricate
//! `0x12`). `radio_set enabled=true`, `send`, and `ping` return
//! `RADIO_UNAVAILABLE` — never a fake ACK. Pairing is allowed while the
//! radio flag is off and rejected with `RADIO_MUST_BE_OFF` when on.
//!
//! This module is transport-agnostic: the Embassy USB CDC task (wired in
//! `main.rs`) feeds received bytes into [`LineBuffer`] and calls
//! [`dispatch_line`] for each complete line. Replies render into a
//! caller-provided fixed buffer; no heap. All secure state lives in the
//! `mesh-node` [`Engine`]; USB only stages `pending_persist()` bytes to the
//! single storage owner and calls `commit_ok()` after the awaited commit.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use mesh_node::persist::PERSIST_LEN;
use mesh_node::{BlockOutcome, Engine, EngineError, PairStep};
use serde::Deserialize;

use crate::storage::{label_to_str, StoreHealth};

/// Max bytes per USB command line.
pub const MAX_LINE_LEN: usize = 1024;

/// Reply/event scratch size. Status replies are ~400 bytes; `received`
/// events carry up to 160 text bytes which can expand under JSON escaping,
/// and the `contacts` reply lists 16 slots (~90 bytes each worst case);
/// so this is deliberately larger than [`MAX_LINE_LEN`] (the 1024-byte cap
/// applies to inbound command lines, not outbound replies).
pub const REPLY_LEN: usize = 4096;

/// Scratch for string unescaping during request parse.
pub const PARSE_SCRATCH_LEN: usize = 256;

/// Run image name.
#[cfg(feature = "radio")]
pub const IMAGE: &str = "radio-secure";
#[cfg(not(feature = "radio"))]
/// Image string for the default radio-free secure build.
pub const IMAGE: &str = "radio-free";
/// Board string reported on USB.
pub const BOARD: &str = "pico2w";
/// Firmware version reported on USB.
pub const FIRMWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Historical note: the radio-free image used to send this banner once per
/// connection. That caused dropped-banner parse failures because normal
/// hosts clear their receive buffer at open; no image should emit it now.
#[allow(dead_code)]
pub const STARTUP_BANNER_HISTORICAL: &[u8] =
    b"radio-free image: hardware unavailable, radio not initialized; pairing allowed while radio off\r\n";

/// Exact firmware error strings.
pub mod err {
    pub const BUSY: &str = "BUSY";
    pub const CHANNEL_BUSY: &str = "CHANNEL_BUSY";
    pub const CONTACT_BLOCKED: &str = "CONTACT_BLOCKED";
    pub const TIME_UNSET: &str = "TIME_UNSET";
    pub const TIME_ROLLBACK: &str = "TIME_ROLLBACK";
    pub const TIME_JUMP_NEEDS_CONFIRM: &str = "TIME_JUMP_NEEDS_CONFIRM";
    pub const STORAGE_FAULT: &str = "STORAGE_FAULT";
    pub const RADIO_MUST_BE_OFF: &str = "RADIO_MUST_BE_OFF";
    pub const RADIO_UNAVAILABLE: &str = "RADIO_UNAVAILABLE";
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    pub const UNKNOWN_OP: &str = "UNKNOWN_OP";
    pub const UNPROVISIONED: &str = "UNPROVISIONED";
    pub const LINE_TOO_LONG: &str = "LINE_TOO_LONG";
    pub const ALREADY_PROVISIONED: &str = "ALREADY_PROVISIONED";
    pub const SAS_MISMATCH: &str = "SAS_MISMATCH";
}

/// Bounded USB channels; full surfaces `BUSY`, never blocks.
pub const QUEUE_DEPTH: usize = 8;

/// Fixed RF constants reported honestly (no measurement claimed).
pub const TX_POWER_DBM: u32 = 2;
pub const RF_PROFILE: &str = "915000000/SF7/BW500/CR4-5/pre8/CRC/sync12";
/// Runtime-visible counters with an internal owner mirror. The engine
/// keeps actual auth/replay reception statistics; the USB state mirrors
/// transmit/forward/CRC outcomes only. Callers MUST use
/// `report_tx_done/rx_frame/rx_crc/tx_attempted/forward/mirror_reception`
/// rather than hand-bumping fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub tx_attempts: u32,
    pub tx_ok: u32,
    pub rx_ok: u32,
    pub rx_crc_bad: u32,
    pub auth_fail: u32,
    pub replay_drop: u32,
    pub forwards: u32,
}

/// Terminal radio outcome classes collapsed for counter accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDoneSummary {
    Success,
    Busy,
    Cancelled,
    Radio,
}

impl Counters {
    pub fn report_tx_done(&mut self, result: TxDoneSummary) {
        if result == TxDoneSummary::Success {
            self.tx_ok = self.tx_ok.saturating_add(1);
        }
    }

    pub fn report_rx_frame(&mut self) {
        self.rx_ok = self.rx_ok.saturating_add(1);
    }

    pub fn report_rx_crc(&mut self) {
        self.rx_crc_bad = self.rx_crc_bad.saturating_add(1);
    }

    pub fn report_tx_attempted(&mut self) {
        self.tx_attempts = self.tx_attempts.saturating_add(1);
    }

    pub fn report_forward(&mut self) {
        self.forwards = self.forwards.saturating_add(1);
    }

    pub fn mirror_reception(&mut self, engine: &Engine) {
        self.auth_fail = engine.auth_failures();
        self.replay_drop = engine.replay_drops();
    }
}

/// What dispatch did with one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Inline(usize),
    /// Caller must persist staged bytes, then re-emit via `commit_reply`.
    NeedsCommit(usize),
    /// Caller must draw TRNG bytes and call the matching `complete_*`
    /// helper (provision / pair-offer); USB never carries key material.
    NeedsTrng,
    /// Caller must draw one TRNG word and drive the staged secure send.
    NeedsSendPrep,
    /// Caller must draw one TRNG word and drive the staged CAD-only ping.
    NeedsPingPrep,
    /// Caller must flush USB TX, reply `{rebooting:true}`, then invoke the
    /// RP235x ROM `reset_to_usb_boot` (never returns).
    NeedsRebootBootsel,
    Silent,
}

type EStr<'a> = serde_json_core::str::EscapedStr<'a>;

/// Request envelope.
#[derive(Debug, Deserialize)]
struct Request<'a> {
    id: u64,
    #[serde(borrow)]
    op: EStr<'a>,
    #[serde(borrow, default)]
    label: Option<EStr<'a>>,
    #[serde(default)]
    unix_seconds: Option<u64>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    count: Option<u8>,
    #[serde(default)]
    contact_id: Option<u8>,
    #[serde(borrow, default)]
    text: Option<EStr<'a>>,
    #[serde(borrow, default)]
    record_b64: Option<EStr<'a>>,
    #[serde(default)]
    replace: Option<bool>,
    /// Settings op key name (`settings_get` optional filter, `settings_set` required).
    #[serde(borrow, default)]
    key: Option<EStr<'a>>,
    /// New value (`settings_set` required; signed so negatives clamp, never wrap).
    #[serde(default)]
    value: Option<i64>,
    /// WiFi SSID (`wifi_set` required; 1-32 UTF-8 bytes, never logged).
    #[serde(borrow, default)]
    ssid: Option<EStr<'a>>,
    /// WiFi passphrase (`wifi_set` required; 0-63 UTF-8 bytes, never logged).
    #[serde(borrow, default)]
    pass: Option<EStr<'a>>,
    /// Reboot confirmation (`reboot_bootsel` required true; guards pocket-dial).
    #[serde(default)]
    confirm: Option<bool>,
    /// SAS comparison confirmation (`pair_import` confirmation records
    /// require true; operator compared the transcript aloud on both sides).
    #[serde(default)]
    sas_match: Option<bool>,
}
/// Mutable USB-side state: the secure engine plus volatile counters and a
/// TRNG-backed packet-ID allocator.
pub struct UsbState {
    pub engine: Engine,
    pub health: StoreHealth,
    pub counters: Counters,
    pkt_next: u32,
    /// Chip-detect result: raw RegVersion byte, or None on SPI error.
    /// Reported honestly; never fabricated. RF stays unavailable.
    pub radio_version: Option<u8>,
    /// Staged persist bytes awaiting the storage owner commit.
    pub staged: Option<([u8; PERSIST_LEN], usize)>,
    /// Reply to emit after the staged commit completes.
    pub staged_reply: Option<StagedReply>,
    /// TRNG-backed op awaiting key bytes (provision / pair-offer).
    pub pending_op: Option<PendingOp>,
    pub reply_id: u64,
    /// Usability-tunable parameters (separate flash key `KEY_SETTINGS`;
    /// RF field `tx_power` latches at next radio-on, rest read live).
    pub settings: mesh_node::settings::Settings,
    /// True once a customized `tx_power` is stored while the radio is on:
    /// `settings_get` reports it as `applied:false` (latches next radio-on).
    pub settings_tx_pending: bool,
    /// Staged WiFi credential for the `KEY_WIFI` commit (`wifi_set` builds
    /// it, `wifi_forget` clears it). Published to `WIFI_CRED` (radio image)
    /// only after durable commit; never logged, never in replies.
    pub staged_wifi: Option<([u8; 32], u8, [u8; 63], u8)>,
    /// Whether a WiFi credential is durably stored (loaded at boot or
    /// committed this session). `wifi_status` reports this, never secrets.
    pub wifi_configured: bool,
    /// Stored SSID length for `wifi_status` display (never the SSID itself).
    pub wifi_ssid_len: u8,
    /// Deferred secure-send assembly with validated UTF-8 text. Stashed
    /// during dispatch; main draws TRNG words and drives begin/emit.
    pub send_text: [u8; 160],
    pub send_len: u8,
    /// Deferred ping count (CAD-only when the radio feature is enabled).
    pub ping_count: u8,
}

#[derive(Debug, Clone)]
pub enum StagedReply {
    Status {
        id: u64,
    },
    Simple {
        id: u64,
        body: heapless::String<128>,
    },
    Block {
        id: u64,
        contact_id: u8,
        blocked: bool,
    },
    RadioSet {
        id: u64,
        enabled: bool,
    },
    /// `settings_set`: reply data staged alongside the settings commit.
    SettingsSet {
        id: u64,
        key: heapless::String<24>,
        value: u32,
        clamped: bool,
    },
    /// `wifi_set`/`wifi_forget`: credential staged for the KEY_WIFI commit.
    /// Reply renders only after durable commit; the passphrase never enters
    /// the reply (only `ssid_len` + `configured:true`).
    WifiSet {
        id: u64,
    },
    WifiForget {
        id: u64,
    },
}

impl UsbState {
    pub fn new(engine: Engine, health: StoreHealth) -> Self {
        Self {
            engine,
            health,
            counters: Counters::default(),
            pkt_next: 0x243F_6A88,
            radio_version: None,
            staged: None,
            staged_reply: None,
            pending_op: None,
            reply_id: 0,
            settings: mesh_node::settings::Settings::default(),
            settings_tx_pending: false,
            staged_wifi: None,
            wifi_configured: false,
            wifi_ssid_len: 0,
            send_text: [0u8; 160],
            send_len: 0,
            ping_count: 0,
        }
    }
    pub fn next_packet_id(&mut self, trng_word: u32) -> u32 {
        let mut x = self.pkt_next | 1;
        x ^= trng_word;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        if x == 0 {
            x = 1;
        }
        self.pkt_next = x;
        x
    }

    /// Validate one deferred secure send and stash its exact bytes. The
    /// caller draws TRNG, then drives begin/emit; deferred replies only.
    pub fn stash_send(&mut self, contact_id: u8, text: &[u8]) -> Result<(), EngineError> {
        if contact_id < 1 || contact_id as usize > crate::storage::MAX_CONTACTS {
            return Err(EngineError::BadRequest);
        }
        if text.is_empty() || text.len() > self.send_text.len() {
            return Err(EngineError::BadRequest);
        }
        self.send_text[..text.len()].copy_from_slice(text);
        self.send_len = text.len() as u8;
        Ok(())
    }
}

/// Byte-fed line assembler.
pub struct LineBuffer {
    buf: [u8; MAX_LINE_LEN],
    len: usize,
    discarding: bool,
}

impl LineBuffer {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_LINE_LEN],
            len: 0,
            discarding: false,
        }
    }

    pub fn push(&mut self, byte: u8) -> Option<LineEvent<'_>> {
        if self.discarding {
            if byte == b'\n' {
                self.discarding = false;
                return Some(LineEvent::TooLong);
            }
            return None;
        }
        if byte == b'\n' {
            let line = &self.buf[..self.len];
            self.len = 0;
            return Some(LineEvent::Line(line));
        }
        if byte == b'\r' {
            return None;
        }
        if self.len >= MAX_LINE_LEN {
            self.discarding = true;
            self.len = 0;
            return None;
        }
        self.buf[self.len] = byte;
        self.len += 1;
        None
    }
}

/// Result of feeding one byte into [`LineBuffer`].
pub enum LineEvent<'a> {
    /// Complete line, newline stripped. Borrow lives until the next `push`.
    Line(&'a [u8]),
    /// An overlong line just ended; caller reports `LINE_TOO_LONG`.
    TooLong,
}

/// Minimal JSON writer over a fixed buffer.
struct JsonWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> JsonWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn raw(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.len.checked_add(bytes.len())?;
        self.buf.get_mut(self.len..end)?.copy_from_slice(bytes);
        self.len = end;
        Some(())
    }

    fn num(&mut self, v: u64) -> Option<()> {
        let mut tmp = [0u8; 20];
        let mut n = v;
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        } else {
            while n > 0 {
                i -= 1;
                tmp[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        self.raw(&tmp[i..])
    }

    fn comma(&mut self, first: &mut bool) -> Option<()> {
        if !*first {
            self.raw(b",")?;
        }
        *first = false;
        Some(())
    }

    fn key(&mut self, first: &mut bool, name: &str) -> Option<()> {
        self.comma(first)?;
        self.raw(b"\"")?;
        self.raw(name.as_bytes())?;
        self.raw(b"\":")
    }

    fn num_field(&mut self, first: &mut bool, name: &str, v: u64) -> Option<()> {
        self.key(first, name)?;
        self.num(v)
    }

    fn bool_field(&mut self, first: &mut bool, name: &str, v: bool) -> Option<()> {
        self.key(first, name)?;
        self.raw(if v { b"true" } else { b"false" })
    }

    fn lit_field(&mut self, first: &mut bool, name: &str, v: &str) -> Option<()> {
        self.key(first, name)?;
        self.raw(b"\"")?;
        self.raw(v.as_bytes())?;
        self.raw(b"\"")
    }

    /// Emit `bytes` (validated UTF-8 message text) as a JSON string.
    /// Passes printable ASCII and all multi-byte UTF-8 sequences through
    /// verbatim; only the JSON metacharacters (`"`, `\`, controls) are
    /// escaped. The old `\u00XX`-per-byte form shredded every non-ASCII
    /// character into Latin-1 mojibake (`é` -> `Ã©`); callers MUST validate
    /// UTF-8 before calling (engine `send_begin` + `validate_body` do).
    fn quoted_escaped(&mut self, bytes: &[u8]) -> Option<()> {
        self.raw(b"\"")?;
        let mut i = 0usize;
        while i < bytes.len() {
            let b = bytes[i];
            match b {
                b'"' => self.raw(b"\\\"")?,
                b'\\' => self.raw(b"\\\\")?,
                b'\n' => self.raw(b"\\n")?,
                b'\r' => self.raw(b"\\r")?,
                b'\t' => self.raw(b"\\t")?,
                0x08 => self.raw(b"\\b")?,
                0x0C => self.raw(b"\\f")?,
                0x20..=0x7E => self.raw(&[b])?,
                0xC2..=0xF4 => {
                    // Multi-byte UTF-8 lead: pass the whole sequence through
                    // (length set by the lead byte; validated upstream).
                    let len = if b >= 0xF0 {
                        4
                    } else if b >= 0xE0 {
                        3
                    } else {
                        2
                    };
                    let end = i.checked_add(len)?;
                    self.raw(bytes.get(i..end)?)?;
                    i = end;
                    continue;
                }
                _ => {
                    // ASCII controls (incl. 0x7F) and lone continuation bytes:
                    // engine-validated UTF-8 never contains the latter here,
                    // but emit \u00XX rather than dropping the event.
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.raw(b"\\u00")?;
                    self.raw(&[HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]])?;
                }
            }
            i += 1;
        }
        self.raw(b"\"")
    }
}

/// Decode an [`EStr`] into `out`. Returns the decoded length, or `None`
/// when the value does not fit or is malformed.
fn unescape_into(s: EStr<'_>, out: &mut [u8]) -> Option<usize> {
    let mut pos = 0usize;
    for frag in s.fragments() {
        let frag = frag.ok()?;
        match frag {
            serde_json_core::str::EscapedStringFragment::NotEscaped(part) => {
                let bytes = part.as_bytes();
                let end = pos.checked_add(bytes.len())?;
                out.get_mut(pos..end)?.copy_from_slice(bytes);
                pos = end;
            }
            serde_json_core::str::EscapedStringFragment::Escaped(c) => {
                let mut tmp = [0u8; 4];
                let bytes = c.encode_utf8(&mut tmp).as_bytes();
                let end = pos.checked_add(bytes.len())?;
                out.get_mut(pos..end)?.copy_from_slice(bytes);
                pos = end;
            }
        }
    }
    Some(pos)
}

fn reply_err(id: u64, code: &str, out: &mut [u8]) -> Outcome {
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":false,\"error\":\"")?;
        w.raw(code.as_bytes())?;
        w.raw(b"\"}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

fn engine_err(e: EngineError) -> &'static str {
    match e {
        EngineError::BadRequest => err::BAD_REQUEST,
        EngineError::Unprovisioned => err::UNPROVISIONED,
        EngineError::StorageFault => err::STORAGE_FAULT,
        EngineError::TimeUnset => err::TIME_UNSET,
        EngineError::TimeRollback => err::TIME_ROLLBACK,
        // B4: jumps need a second confirmed step with a distinct code so
        // hosts prompt instead of misdiagnosing rollback.
        EngineError::TimeJumpNeedsConfirm => err::TIME_JUMP_NEEDS_CONFIRM,
        EngineError::Busy => err::BUSY,
        EngineError::ContactBlocked => err::CONTACT_BLOCKED,
        EngineError::RadioMustBeOff => err::RADIO_MUST_BE_OFF,
        EngineError::RadioUnavailable => err::RADIO_UNAVAILABLE,
        EngineError::UnknownOp => err::UNKNOWN_OP,
        EngineError::PairingAbsent => err::BAD_REQUEST,
        EngineError::PairingExpired => err::BAD_REQUEST,
        EngineError::NoSlot => err::BAD_REQUEST,
        EngineError::SasMismatch => err::SAS_MISMATCH,
    }
}

/// Dispatch one complete line (newline already stripped). Replies render
/// into `out`; `scratch` backs string unescaping during request parse.
/// TRNG-backed ops (provision/pair_offer) return `NeedsTrng`; main.rs draws
/// the bytes and calls the matching `complete_*` helper.
pub fn dispatch_line(
    state: &mut UsbState,
    line: &[u8],
    out: &mut [u8],
    scratch: &mut [u8],
) -> Outcome {
    if line.is_empty() {
        return Outcome::Silent;
    }
    let (req, _): (Request<'_>, usize) = match serde_json_core::from_slice_escaped(line, scratch) {
        Ok(v) => v,
        Err(_) => {
            return reply_err(0, err::BAD_REQUEST, out);
        }
    };
    state.reply_id = req.id;
    dispatch(state, &req, out)
}

fn dispatch(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    if state.health == StoreHealth::Fault {
        match req.op.0 {
            "status" => return reply_status(state, req.id, out),
            _ => return reply_err(req.id, err::STORAGE_FAULT, out),
        }
    }
    match req.op.0 {
        "status" => reply_status(state, req.id, out),
        "contacts" => reply_contacts(state, req.id, out),
        "provision" => op_provision(state, req, out),
        "time_set" => op_time_set(state, req, out),
        "time_status" => reply_time_status(state, req.id, out),
        "radio_set" => op_radio_set(state, req, out),
        "radio_arm_next_boot" => op_arm(state, req, out),
        // Radio-free image: explicit unavailable, never fake RF.
        #[cfg(not(feature = "radio"))]
        "ping" => reply_err(req.id, err::RADIO_UNAVAILABLE, out),
        #[cfg(feature = "radio")]
        "ping" => op_ping(state, req, out),
        #[cfg(not(feature = "radio"))]
        "send" => op_send_radio_free(state, req, out),
        #[cfg(feature = "radio")]
        "send" => op_send(state, req, out),
        "block" => op_block(state, req, true, out),
        "unblock" => op_block(state, req, false, out),
        "contact_delete" => op_delete(state, req, out),
        "pair_offer" => op_pair_offer(state, req, out),
        "pair_proof" => op_pair_proof(state, req, out),
        "pair_confirm" => op_pair_confirm(state, req, out),
        "pair_import" => op_pair_import(state, req, out),
        "settings_get" => op_settings_get(state, req, out),
        "settings_set" => op_settings_set(state, req, out),
        "wifi_status" => op_wifi_status(state, req, out),
        "wifi_set" => op_wifi_set(state, req, out),
        "wifi_forget" => op_wifi_forget(state, req, out),
        "reboot_bootsel" => op_reboot_bootsel(state, req, out),
        _ => reply_err(req.id, err::UNKNOWN_OP, out),
    }
}

fn reply_status(state: &UsbState, id: u64, out: &mut [u8]) -> Outcome {
    let e = &state.engine;
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{")?;
        let mut f = true;
        w.lit_field(&mut f, "board", BOARD)?;
        w.lit_field(&mut f, "firmware_version", FIRMWARE_VERSION)?;
        w.lit_field(&mut f, "image", IMAGE)?;
        w.bool_field(&mut f, "provisioned", e.provisioned())?;
        w.lit_field(&mut f, "label", label_to_str(e.label()))?;
        w.bool_field(&mut f, "radio_enabled", e.radio_on())?;
        w.bool_field(&mut f, "radio_available", e.radio_available())?;
        w.lit_field(
            &mut f,
            "hardware",
            if e.radio_available() {
                "sx1276"
            } else {
                "unavailable"
            },
        )?;
        if let Some(v) = state.radio_version {
            w.num_field(&mut f, "radio_version", v as u64)?;
        }
        w.bool_field(&mut f, "armed_next_boot", e.armed_next_boot())?;
        w.num_field(&mut f, "tx_power_dbm", TX_POWER_DBM as u64)?;
        w.lit_field(&mut f, "rf_profile", RF_PROFILE)?;
        w.bool_field(&mut f, "time_valid", e.time_valid())?;
        w.num_field(&mut f, "epoch", e.epoch() as u64)?;
        w.raw(b",\"contacts\":{\"count\":")?;
        w.num(e.present_count() as u64)?;
        w.raw(b",\"blocked\":")?;
        w.num(e.blocked_count() as u64)?;
        w.raw(b"}")?;
        w.raw(b",\"counters\":{")?;
        let mut c = true;
        let k = &state.counters;
        w.num_field(&mut c, "tx_attempts", k.tx_attempts as u64)?;
        w.num_field(&mut c, "tx_ok", k.tx_ok as u64)?;
        w.num_field(&mut c, "rx_ok", k.rx_ok as u64)?;
        w.num_field(&mut c, "rx_crc_bad", k.rx_crc_bad as u64)?;
        w.num_field(&mut c, "auth_fail", k.auth_fail as u64)?;
        w.num_field(&mut c, "replay_drop", k.replay_drop as u64)?;
        w.num_field(&mut c, "forwards", k.forwards as u64)?;
        w.raw(b"}}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

fn reply_contacts(state: &UsbState, id: u64, out: &mut [u8]) -> Outcome {
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{\"contacts\":[")?;
        for i in 0..crate::storage::MAX_CONTACTS {
            let cid = (i + 1) as u8;
            if i > 0 {
                w.raw(b",")?;
            }
            w.raw(b"{\"contact_id\":")?;
            w.num(cid as u64)?;
            w.raw(b",\"present\":")?;
            w.raw(if state.engine.contact_present(cid) {
                b"true"
            } else {
                b"false"
            })?;
            w.raw(b",\"blocked\":")?;
            w.raw(if state.engine.contact_blocked(cid) {
                b"true"
            } else {
                b"false"
            })?;
            w.raw(b",\"fingerprint\":\"")?;
            if let Some(fp) = state.engine.contact_fingerprint(cid) {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for b in fp.iter().take(8) {
                    w.raw(&[HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]])?;
                }
            }
            w.raw(b"\"}")?;
        }
        w.raw(b"]}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

fn reply_time_status(state: &UsbState, id: u64, out: &mut [u8]) -> Outcome {
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{")?;
        let mut f = true;
        w.bool_field(&mut f, "time_valid", state.engine.time_valid())?;
        w.num_field(&mut f, "unix_seconds", state.engine.unix_seconds())?;
        w.num_field(&mut f, "epoch", state.engine.epoch() as u64)?;
        w.raw(b"}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

pub(crate) fn stage_for_commit(state: &mut UsbState) {
    if let Some(bytes) = state.engine.pending_persist() {
        let mut arr = [0u8; PERSIST_LEN];
        arr.copy_from_slice(bytes);
        state.staged = Some((arr, bytes.len()));
    }
}

/// Staged settings bytes for the separate `KEY_SETTINGS` map key.
/// `None` when settings are clean (no commit needed).
pub(crate) fn stage_settings_for_commit(state: &mut UsbState) -> Option<[u8; 13]> {
    // Caller stages only after mutating `state.settings`; always emits.
    Some(state.settings.encode())
}

fn reply_ok_simple(id: u64, body: &str, out: &mut [u8]) -> Outcome {
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":")?;
        w.raw(body.as_bytes())?;
        w.raw(b"}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

/// Pending TRNG-backed operation the transport-agnostic dispatch cannot
/// complete alone. `main.rs` draws TRNG bytes, calls the matching
/// `complete_*` helper, awaits the storage commit, then emits the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOp {
    Provision {
        id: u64,
        label: u8,
    },
    PairOffer {
        id: u64,
    },
    SendPrep {
        id: u64,
        contact_id: u8,
    },
    PingPrep {
        id: u64,
        count: u8,
    },
    /// Confirmed BOOTSEL reboot awaiting TX flush + ROM call.
    RebootBootsel {
        id: u64,
    },
}

fn op_provision(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    if state.engine.provisioned() {
        return reply_err(req.id, err::ALREADY_PROVISIONED, out);
    }
    let raw = match req.label {
        Some(l) => l,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let mut lb = [0u8; 8];
    let label = match unescape_into(raw, &mut lb) {
        Some(n) => match &lb[..n] {
            b"A" => crate::storage::LABEL_A,
            b"B" => crate::storage::LABEL_B,
            b"C" => crate::storage::LABEL_C,
            _ => return reply_err(req.id, err::BAD_REQUEST, out),
        },
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    // Signing key bytes come from main.rs TRNG (USB never carries secrets,
    // and there is no private-key export op). Signal the owner loop.
    state.pending_op = Some(PendingOp::Provision { id: req.id, label });
    let _ = out;
    Outcome::NeedsTrng
}

/// Complete provisioning with TRNG-supplied key bytes (called by main.rs,
/// which owns the TRNG — USB never carries secrets).
pub fn complete_provision(
    state: &mut UsbState,
    id: u64,
    label: u8,
    key: [u8; 32],
    out: &mut [u8],
) -> Outcome {
    match state.engine.provision(label, key) {
        Ok(()) => {
            stage_for_commit(state);
            let mut w = JsonWriter::new(out);
            let n = (|| {
                w.raw(b"{\"id\":")?;
                w.num(id)?;
                w.raw(b",\"ok\":true,\"result\":{")?;
                let mut f = true;
                w.bool_field(&mut f, "provisioned", true)?;
                w.lit_field(&mut f, "label", label_to_str(label))?;
                w.raw(b"}}")?;
                Some(w.len())
            })();
            match n {
                Some(len) => Outcome::Inline(len),
                None => Outcome::Silent,
            }
        }
        Err(e) => reply_err(id, engine_err(e), out),
    }
}

fn op_time_set(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let secs = match req.unix_seconds {
        Some(v) => v,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    // B4: forward jumps over one hour need explicit confirmation.
    let confirmed = req.confirm == Some(true);
    match state.engine.set_time_confirmed(secs, confirmed) {
        Ok(_) => {
            stage_for_commit(state);
            state.staged_reply = Some(StagedReply::Status { id: req.id });
            Outcome::NeedsCommit(0)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn op_block(state: &mut UsbState, req: &Request<'_>, blocked: bool, out: &mut [u8]) -> Outcome {
    let Some(contact_id) = req.contact_id else {
        return reply_err(req.id, err::BAD_REQUEST, out);
    };
    match state.engine.set_blocked(contact_id, blocked) {
        Ok(_) => {
            stage_for_commit(state);
            state.staged_reply = Some(StagedReply::Block {
                id: req.id,
                contact_id,
                blocked,
            });
            Outcome::NeedsCommit(0)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn op_delete(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let Some(contact_id) = req.contact_id else {
        return reply_err(req.id, err::BAD_REQUEST, out);
    };
    match state.engine.delete_contact(contact_id) {
        Ok(()) => {
            stage_for_commit(state);
            state.staged_reply = Some(StagedReply::Simple {
                id: req.id,
                body: heapless::String::try_from("{\"deleted\":true}").unwrap_or_default(),
            });
            Outcome::NeedsCommit(0)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

pub fn storage_failure(state: &mut UsbState, out: &mut [u8]) -> Outcome {
    state.staged_reply = None;
    reply_err(state.reply_id, err::STORAGE_FAULT, out)
}

fn op_radio_set(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let enabled = match req.enabled {
        Some(v) => v,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    #[cfg(not(feature = "radio"))]
    if enabled {
        // Radio-free image: explicit unavailable, never fake on.
        return reply_err(req.id, err::RADIO_UNAVAILABLE, out);
    }
    match state.engine.set_radio(enabled) {
        Ok(()) => {
            stage_for_commit(state);
            state.staged_reply = Some(StagedReply::RadioSet {
                id: req.id,
                enabled,
            });
            Outcome::NeedsCommit(0)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn op_arm(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    match state.engine.arm_next_boot() {
        Ok(()) => {
            stage_for_commit(state);
            reply_ok_simple(req.id, "{\"armed_next_boot\":true}", out)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}
/// `settings_get`: report every entry as `{key,min,max,readonly,applied}`
/// plus the stored `value`. Optional `key` narrows to one entry; unknown
/// keys are `BAD_REQUEST`. `applied` is false only for `tx_power` when a
/// new value was stored while the radio is already on (it latches at the
/// next radio-on; every other field is read live).
fn op_settings_get(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    use mesh_node::settings::Settings;
    let id = req.id;
    let mut keybuf = [0u8; 32];
    let filter: Option<&[u8]> = match req.key {
        Some(k) => match unescape_into(k, &mut keybuf) {
            Some(n) => Some(&keybuf[..n]),
            None => return reply_err(id, err::BAD_REQUEST, out),
        },
        None => None,
    };
    if let Some(f) = filter {
        if Settings::meta(core::str::from_utf8(f).unwrap_or("")).is_none() {
            return reply_err(id, err::BAD_REQUEST, out);
        }
    }
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{\"settings\":[")?;
        let mut first = true;
        for m in mesh_node::settings::KEYS.iter() {
            if let Some(f) = filter {
                if f != m.key.as_bytes() {
                    continue;
                }
            }
            let value = state.settings.value(m.key).unwrap_or(m.min);
            let applied = !(m.rf && m.key == "tx_power" && state.settings_tx_pending);
            if !first {
                w.raw(b",")?;
            }
            first = false;
            let mut f = true;
            w.raw(b"{")?;
            w.lit_field(&mut f, "key", m.key)?;
            w.num_field(&mut f, "value", value as u64)?;
            w.num_field(&mut f, "min", m.min as u64)?;
            w.num_field(&mut f, "max", m.max as u64)?;
            w.bool_field(&mut f, "readonly", m.readonly)?;
            w.bool_field(&mut f, "applied", applied)?;
            w.raw(b"}")?;
        }
        w.raw(b"]}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}
/// `settings_set`: clamp `value` into range, store it, reply
/// `{\"key\",\"value\",\"clamped\"}`. Unknown/readonly keys are
/// `BAD_REQUEST`; `tx_power` stored while the radio is on is marked
/// pending (`applied:false`) and takes effect at the next radio-on.
/// Persistence is Main's storage-owner half (separate `KEY_SETTINGS` map
/// key): the handler mutates `state.settings` only, never touch node bytes.
fn op_settings_set(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    use mesh_node::settings::Settings;
    let id = req.id;
    let raw = match req.key {
        Some(k) => k,
        None => return reply_err(id, err::BAD_REQUEST, out),
    };
    let value = match req.value {
        Some(v) => v,
        None => return reply_err(id, err::BAD_REQUEST, out),
    };
    let mut keybuf = [0u8; 32];
    let n = match unescape_into(raw, &mut keybuf) {
        Some(n) => n,
        None => return reply_err(id, err::BAD_REQUEST, out),
    };
    let key = match core::str::from_utf8(&keybuf[..n]) {
        Ok(k) => k,
        Err(_) => return reply_err(id, err::BAD_REQUEST, out),
    };
    if Settings::meta(key).is_none() {
        return reply_err(id, err::BAD_REQUEST, out);
    }
    // Validate through a scratch copy first so a readonly/unknown key never
    // mutates live state. Then apply to live state and stage the commit;
    // the reply renders only after the storage owner durably commits.
    let mut probe = state.settings;
    let clamped = match probe.set(key, value) {
        Ok(c) => c,
        Err(()) => return reply_err(id, err::BAD_REQUEST, out),
    };
    let stored = state.settings.set(key, value).unwrap_or(true);
    debug_assert_eq!(stored, clamped);
    if key == "tx_power" && state.engine.radio_on() {
        state.settings_tx_pending = true;
    }
    let mut ks = heapless::String::<24>::new();
    let _ = ks.push_str(key);
    let got = state.settings.value(key).unwrap_or(0);
    state.staged_reply = Some(StagedReply::SettingsSet {
        id,
        key: ks,
        value: got,
        clamped,
    });
    let _ = out;
    Outcome::NeedsCommit(0)
}

/// `wifi_status`: report `{configured, ssid_len}` — never secrets. `ssid_len`
/// is only the length (so the operator can confirm which network without
/// dumping it); the passphrase length is never reported either.
fn op_wifi_status(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let id = req.id;
    let (ssid_len, configured) = match state.staged_wifi {
        Some((_, sl, _, _)) => (sl as u64, true),
        None => (state.wifi_ssid_len as u64, state.wifi_configured),
    };
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{")?;
        let mut f = true;
        w.bool_field(
            &mut f,
            "configured",
            configured || state.staged_wifi.is_some(),
        )?;
        w.num_field(&mut f, "ssid_len", ssid_len)?;
        w.raw(b"}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

/// `wifi_set`: validate `{ssid, pass}` (1-32 / 0-63 UTF-8 bytes), stage the
/// credential, and commit under `KEY_WIFI`. The passphrase never enters
/// logs or replies; the reply is only `{configured:true, ssid_len}` after
/// durable commit. Publishing to `WIFI_CRED` happens in the commit path.
fn op_wifi_set(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let id = req.id;
    let raw_ssid = match req.ssid {
        Some(s) => s,
        None => return reply_err(id, err::BAD_REQUEST, out),
    };
    let raw_pass = match req.pass {
        Some(p) => p,
        None => return reply_err(id, err::BAD_REQUEST, out),
    };
    let mut ssid = [0u8; 32];
    let mut pass = [0u8; 63];
    let sn = match unescape_into(raw_ssid, &mut ssid) {
        Some(n) if n >= 1 && n <= 32 => n,
        _ => return reply_err(id, err::BAD_REQUEST, out),
    };
    let pn = match unescape_into(raw_pass, &mut pass) {
        Some(n) if n <= 63 => n,
        _ => return reply_err(id, err::BAD_REQUEST, out),
    };
    if core::str::from_utf8(&ssid[..sn]).is_err() || core::str::from_utf8(&pass[..pn]).is_err() {
        return reply_err(id, err::BAD_REQUEST, out);
    }
    // Scrub scratch buffers holding secrets before any further use; stage
    // only the validated prefix (never stale tail bytes beyond sn/pn).
    let mut sb = [0u8; 32];
    sb[..sn].copy_from_slice(&ssid[..sn]);
    let mut pb = [0u8; 63];
    pb[..pn].copy_from_slice(&pass[..pn]);
    ssid.fill(0);
    pass.fill(0);
    state.staged_wifi = Some((sb, sn as u8, pb, pn as u8));
    state.staged_reply = Some(StagedReply::WifiSet { id });
    let _ = out;
    Outcome::NeedsCommit(0)
}

/// `reboot_bootsel`: confirm-gated reboot into the BOOTSEL mass-storage
/// volume via the RP235x ROM (`reset_to_usb_boot`). No state mutation,
/// works with radio on or off. The reply transmits before the ROM call;
/// callers must flush USB TX (~100ms) before invoking.
fn op_reboot_bootsel(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    if req.confirm != Some(true) {
        return reply_err(req.id, err::BAD_REQUEST, out);
    }
    state.pending_op = Some(PendingOp::RebootBootsel { id: req.id });
    let _ = out;
    Outcome::NeedsRebootBootsel
}

/// Render the `{rebooting:true}` reply for a parked BOOTSEL reboot; the
/// caller flushes USB TX then invokes the ROM.
pub fn reply_rebooting(state: &mut UsbState, out: &mut [u8]) -> Option<usize> {
    let id = match state.pending_op {
        Some(PendingOp::RebootBootsel { id }) => id,
        _ => return None,
    };
    match reply_ok_simple(id, "{\"rebooting\":true}", out) {
        Outcome::Inline(n) => Some(n),
        _ => None,
    }
}

/// `wifi_forget`: clear the stored credential (commit zeroed record under
/// `KEY_WIFI`). Reply `{configured:false}` after durable commit.
fn op_wifi_forget(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    state.staged_wifi = None;
    state.staged_reply = Some(StagedReply::WifiForget { id: req.id });
    let _ = out;
    Outcome::NeedsCommit(0)
}

fn op_send(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let cid = match req.contact_id {
        Some(c) if c >= 1 && (c as usize) <= crate::storage::MAX_CONTACTS => c,
        _ => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    if state.engine.contact_blocked(cid) {
        return reply_err(req.id, err::CONTACT_BLOCKED, out);
    }
    // Validate text shape honestly first (BAD_REQUEST vs unavailable).
    let raw = match req.text {
        Some(t) => t,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let mut text = [0u8; 160];
    let n = match unescape_into(raw, &mut text) {
        Some(n) if n >= 1 && n <= 160 => n,
        _ => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    if core::str::from_utf8(&text[..n]).is_err() {
        return reply_err(req.id, err::BAD_REQUEST, out);
    }
    // M2: radio-off send must not reserve seq or commit flash; checked
    // after shape validation so BAD_REQUEST keeps precedence.
    #[cfg(feature = "radio")]
    if !state.engine.radio_on() {
        return reply_err(req.id, err::RADIO_UNAVAILABLE, out);
    }
    if state.stash_send(cid, &text[..n]).is_err() {
        return reply_err(req.id, err::BAD_REQUEST, out);
    }
    state.pending_op = Some(PendingOp::SendPrep {
        id: req.id,
        contact_id: cid,
    });
    let _ = out;
    Outcome::NeedsSendPrep
}

#[cfg(feature = "radio")]
fn op_ping(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let count = match req.count {
        Some(c) if (1..=3).contains(&c) => c,
        _ => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    state.ping_count = count;
    state.pending_op = Some(PendingOp::PingPrep { id: req.id, count });
    let _ = out;
    Outcome::NeedsPingPrep
}
#[cfg(not(feature = "radio"))]
fn op_send_radio_free(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let cid = match req.contact_id {
        Some(c) if c >= 1 && (c as usize) <= crate::storage::MAX_CONTACTS => c,
        _ => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    if state.engine.contact_blocked(cid) {
        return reply_err(req.id, err::CONTACT_BLOCKED, out);
    }
    let raw = match req.text {
        Some(t) => t,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let mut text = [0u8; 160];
    let n = match unescape_into(raw, &mut text) {
        Some(n) if n >= 1 && n <= 160 => n,
        _ => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    if core::str::from_utf8(&text[..n]).is_err() {
        return reply_err(req.id, err::BAD_REQUEST, out);
    }
    reply_err(req.id, err::RADIO_UNAVAILABLE, out)
}
fn op_pair_offer(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let _ = out;
    // Fresh ephemeral key + challenge are drawn by main.rs TRNG.
    state.pending_op = Some(PendingOp::PairOffer { id: req.id });
    Outcome::NeedsTrng
}

pub fn complete_pair_offer(
    state: &mut UsbState,
    id: u64,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    challenge: [u8; 32],
    out: &mut [u8],
) -> Outcome {
    match state.engine.pair_offer(eph_priv, eph_pub, challenge) {
        Ok(rec) => {
            stage_for_commit(state);
            reply_record(id, &rec, out)
        }
        Err(e) => reply_err(id, engine_err(e), out),
    }
}

fn op_pair_proof(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    match state.engine.pair_proof() {
        Ok(rec) => {
            stage_for_commit(state);
            reply_record(req.id, &rec, out)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn op_pair_confirm(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    match state.engine.pair_confirm() {
        Ok(rec) => {
            stage_for_commit(state);
            reply_record(req.id, &rec, out)
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn op_pair_import(state: &mut UsbState, req: &Request<'_>, out: &mut [u8]) -> Outcome {
    let raw = match req.record_b64 {
        Some(r) => r,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let mut rb = [0u8; 256];
    let rn = match unescape_into(raw, &mut rb) {
        Some(n) => n,
        None => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let replace = req.replace.unwrap_or(false);
    // Strict LMESH1:/base64url decode via mesh-core pairing transport.
    let mut bin = [0u8; 160];
    let rec_len = match mesh_core::pairing::decode_transport(&rb[..rn], &mut bin) {
        Ok(n) => n,
        Err(_) => return reply_err(req.id, err::BAD_REQUEST, out),
    };
    let sas_match = req.sas_match == Some(true);
    match state
        .engine
        .pair_import_sas(&bin[..rec_len], replace, sas_match)
    {
        Ok(o) => {
            stage_for_commit(state);
            let mut w = JsonWriter::new(out);
            let n = (|| {
                w.raw(b"{\"id\":")?;
                w.num(req.id)?;
                w.raw(b",\"ok\":true,\"result\":{\"fingerprint\":\"")?;
                w.raw(&o.fingerprint)?;
                w.raw(b"\"")?;
                if let Some(c) = o.contact_id {
                    debug_assert!(matches!(o.step, PairStep::Active));
                    w.raw(b",\"contact_id\":")?;
                    w.num(c as u64)?;
                }
                w.raw(b"}}")?;
                Some(w.len())
            })();
            match n {
                Some(len) => Outcome::Inline(len),
                None => Outcome::Silent,
            }
        }
        Err(e) => reply_err(req.id, engine_err(e), out),
    }
}

fn reply_record(id: u64, rec: &[u8], out: &mut [u8]) -> Outcome {
    // LMESH1: + base64url(no pad) into the reply buffer.
    let mut w = JsonWriter::new(out);
    let n = (|| {
        w.raw(b"{\"id\":")?;
        w.num(id)?;
        w.raw(b",\"ok\":true,\"result\":{\"record_b64\":\"LMESH1:")?;
        let need = mesh_core::pairing::b64_encoded_len(rec.len());
        // Encode in chunks to avoid a second large buffer.
        let mut tmp = [0u8; 256];
        mesh_core::pairing::transport_encode(rec, &mut tmp).ok()?;
        let body = tmp.get(b"LMESH1:".len()..b"LMESH1:".len() + need)?;
        w.raw(body)?;
        w.raw(b"\"}}")?;
        Some(w.len())
    })();
    match n {
        Some(len) => Outcome::Inline(len),
        None => Outcome::Silent,
    }
}

/// Render a `received` event for one delivered DATA into `out`.
pub fn reply_received(
    contact_id: u8,
    epoch: u32,
    sequence: u64,
    text: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut w = JsonWriter::new(out);
    w.raw(b"{\"event\":\"received\",\"contact_id\":")?;
    w.num(contact_id as u64)?;
    w.raw(b",\"epoch\":")?;
    w.num(epoch as u64)?;
    w.raw(b",\"sequence\":")?;
    w.num(sequence)?;
    w.raw(b",\"text\":")?;
    if core::str::from_utf8(text).is_err() {
        return None;
    }
    w.quoted_escaped(text)?;
    w.raw(b"}")?;
    Some(w.len())
}

/// Report an overlong line against id 0.
pub fn reply_line_too_long(out: &mut [u8]) -> Option<usize> {
    let mut w = JsonWriter::new(out);
    w.raw(b"{\"id\":0,\"ok\":false,\"error\":\"LINE_TOO_LONG\"}")?;
    Some(w.len())
}

/// Feed one byte from CDC into `lines`, dispatching complete lines.
pub fn pump_byte(
    state: &mut UsbState,
    lines: &mut LineBuffer,
    byte: u8,
    out: &mut [u8],
    scratch: &mut [u8],
) -> Option<Outcome> {
    match lines.push(byte)? {
        LineEvent::Line(line) => Some(dispatch_line(state, line, out, scratch)),
        LineEvent::TooLong => match reply_line_too_long(out) {
            Some(len) => Some(Outcome::Inline(len)),
            None => Some(Outcome::Silent),
        },
    }
}

/// Radio-free safety net: send/ping prep must never reach the TRNG owner
/// without RF. Clears stale prep state and fails closed under reply id.
pub fn reply_unexpected_prep(state: &mut UsbState, out: &mut [u8]) -> Outcome {
    state.pending_op = None;
    state.send_len = 0;
    state.ping_count = 0;
    reply_err(state.reply_id, err::RADIO_UNAVAILABLE, out)
}

/// Emit the deferred reply after the storage owner commits staged bytes.
/// Call `engine.commit_ok()` first, then this renders the owed reply.
pub fn commit_reply(state: &mut UsbState, out: &mut [u8]) -> Option<usize> {
    match state.staged_reply.take() {
        Some(StagedReply::Status { id }) => match reply_status(state, id, out) {
            Outcome::Inline(n) => Some(n),
            _ => None,
        },
        Some(StagedReply::Simple { id, body }) => {
            let mut s = heapless::String::<160>::new();
            let _ = s.push_str("{\"id\":");
            let _ = core::fmt::write(&mut s, format_args!("{id}"));
            let _ = s.push_str(",\"ok\":true,\"result\":");
            let _ = s.push_str(body.as_str());
            let _ = s.push('}');
            let b = s.as_bytes();
            out.get_mut(..b.len())?.copy_from_slice(b);
            Some(b.len())
        }
        Some(StagedReply::Block {
            id,
            contact_id: _,
            blocked,
        }) => {
            let body = if blocked {
                "{\"blocked\":true}"
            } else {
                "{\"blocked\":false}"
            };
            match reply_ok_simple(id, body, out) {
                Outcome::Inline(n) => Some(n),
                _ => None,
            }
        }
        Some(StagedReply::RadioSet { id, enabled }) => {
            let body = if enabled {
                "{\"radio_enabled\":true}"
            } else {
                "{\"radio_enabled\":false}"
            };
            match reply_ok_simple(id, body, out) {
                Outcome::Inline(n) => Some(n),
                _ => None,
            }
        }
        Some(StagedReply::SettingsSet {
            id,
            key,
            value,
            clamped,
        }) => {
            let mut w = JsonWriter::new(out);
            let n = (|| {
                w.raw(b"{\"id\":")?;
                w.num(id)?;
                w.raw(b",\"ok\":true,\"result\":{")?;
                let mut f = true;
                w.lit_field(&mut f, "key", key.as_str())?;
                w.num_field(&mut f, "value", value as u64)?;
                w.bool_field(&mut f, "clamped", clamped)?;
                w.raw(b"}}")?;
                Some(w.len())
            })();
            n
        }
        Some(StagedReply::WifiSet { id }) => {
            // Credential committed; report shape only, never secrets.
            // Keep the length in RAM so later `wifi_status` reports it.
            let ssid_len = state
                .staged_wifi
                .map(|(_, sl, _, _)| sl as u64)
                .unwrap_or(0);
            state.staged_wifi = None;
            state.wifi_configured = true;
            state.wifi_ssid_len = ssid_len as u8;
            let mut w = JsonWriter::new(out);
            let n = (|| {
                w.raw(b"{\"id\":")?;
                w.num(id)?;
                w.raw(b",\"ok\":true,\"result\":{")?;
                let mut f = true;
                w.bool_field(&mut f, "configured", true)?;
                w.num_field(&mut f, "ssid_len", ssid_len)?;
                w.raw(b"}}")?;
                Some(w.len())
            })();
            n
        }
        Some(StagedReply::WifiForget { id }) => {
            state.staged_wifi = None;
            state.wifi_configured = false;
            state.wifi_ssid_len = 0;
            match reply_ok_simple(id, "{\"configured\":false}", out) {
                Outcome::Inline(n) => Some(n),
                _ => None,
            }
        }
        None => None,
    }
}

pub type UsbChannel = Channel<CriticalSectionRawMutex, UsbEvent, QUEUE_DEPTH>;

/// USB-side events (no radio queues in the radio-free image).
#[derive(Debug, Clone, Copy)]
pub enum UsbEvent {
    Committed(Result<(), StoreErrorKind>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    Fault,
}

use crate::storage::StoreError;
