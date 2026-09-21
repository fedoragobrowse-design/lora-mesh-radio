//! Native stdio exerciser driving the SAME `mesh-node` engine and the SAME
//! persisted encoding as the Pico. Speaks the USB JSON wire protocol over
//! stdin/stdout (one JSON object per line, max 1024 B inbound); logs go to
//! stderr only so stdout stays pure JSON for the host PTY bridge.
//!
//! Wire parity with firmware `usb.rs`: identical op names/args, `id` echo,
//! `result.record_b64` for pair exports, `contact_id` only on activation,
//! `event:received` records, and the exact error strings from the plan plus
//! `RADIO_UNAVAILABLE` (agreed radio-free extension). `status.result`
//! carries `radio_available:false`, `hardware:"unavailable"`,
//! `image:"radio-free"`, `tx_power_dbm:2`, the fixed `rf_profile`, and all
//! 7 counters. `radio_set enabled=true`, `send`, and `ping` fail closed
//! with `RADIO_UNAVAILABLE` — never a fake ACK. Pairing is allowed while
//! the (software) radio flag is off and rejected with `RADIO_MUST_BE_OFF`
//! when on, matching firmware.
//!
//! Optional lab-only `__inject` op (real firmware rejects it as UNKNOWN_OP;
//! the host only sends it with an explicit --inject flag): `drop_next_ack:N`
//! arms the virtual transport to swallow N next ACKs (forcing identical
//! retry echoes), `duplicate_next_rx:N` replays the next delivered frame N
//! extra times, `fail_next:ERROR` makes the next RF-gated op fail with that
//! string, `emit_stale_event` writes one malformed event, `reset` clears
//! arms. Multi-node delivery/relay/reboot scenarios are driven by spawning
//! 2-3 of these processes and shuttling their `__frame` transport records;
//! see the `MESH_EXERCISER_SCENARIOS` help text emitted with `--help`.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use ed25519_dalek::SigningKey;
use mesh_core::pairing::{self, CONFIRM_RECORD_LEN, OFFER_RECORD_LEN, PROOF_RECORD_LEN};
use mesh_node::{BlockOutcome, Engine, EngineError, IncomingKind, OutgoingFrame, MAX_CONTACTS};
use zeroize::Zeroize;

const MAX_LINE: usize = 1024;
const IMAGE: &str = "radio-free";
const BOARD: &str = "native-exerciser";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const RF_PROFILE: &str = "915000000/SF7/BW500/CR4-5/pre8/CRC/sync12";

#[derive(Clone, Copy)]
struct Counters {
    tx_attempts: u32,
    tx_ok: u32,
    rx_ok: u32,
    rx_crc_bad: u32,
    auth_fail: u32,
    replay_drop: u32,
    forwards: u32,
}

struct PendingOut {
    contact_id: u8,
    frame: OutgoingFrame,
    attempts: u8,
}

struct Node {
    rng: u64,
    engine: Engine,
    state_path: Option<String>,
    counters: Counters,
    pending: Option<PendingOut>,
    ping_pending: Option<u64>,
    pkt: u32,
    drop_ack: u32,
    dup_rx: u32,
    fail_next: Option<String>,
    uid: [u8; 8],
}

fn err_str(e: EngineError) -> &'static str {
    match e {
        EngineError::BadRequest => "BAD_REQUEST",
        EngineError::Unprovisioned => "UNPROVISIONED",
        EngineError::StorageFault => "STORAGE_FAULT",
        EngineError::TimeUnset => "TIME_UNSET",
        EngineError::TimeRollback => "TIME_ROLLBACK",
        EngineError::Busy => "BUSY",
        EngineError::ContactBlocked => "CONTACT_BLOCKED",
        EngineError::RadioMustBeOff => "RADIO_MUST_BE_OFF",
        EngineError::RadioUnavailable => "RADIO_UNAVAILABLE",
        EngineError::UnknownOp => "UNKNOWN_OP",
        EngineError::PairingAbsent => "BAD_REQUEST",
        EngineError::PairingExpired => "BAD_REQUEST",
        EngineError::NoSlot => "BAD_REQUEST",
    }
}

fn b64url_encode(raw: &[u8]) -> String {
    const AL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((raw.len() * 4 + 2) / 3);
    let mut i = 0;
    while i + 3 <= raw.len() {
        let n = ((raw[i] as u32) << 16) | ((raw[i + 1] as u32) << 8) | raw[i + 2] as u32;
        out.push(AL[((n >> 18) & 63) as usize] as char);
        out.push(AL[((n >> 12) & 63) as usize] as char);
        out.push(AL[((n >> 6) & 63) as usize] as char);
        out.push(AL[(n & 63) as usize] as char);
        i += 3;
    }
    let r = raw.len() - i;
    if r == 1 {
        let n = (raw[i] as u32) << 16;
        out.push(AL[((n >> 18) & 63) as usize] as char);
        out.push(AL[((n >> 12) & 63) as usize] as char);
    } else if r == 2 {
        let n = ((raw[i] as u32) << 16) | ((raw[i + 1] as u32) << 8);
        out.push(AL[((n >> 18) & 63) as usize] as char);
        out.push(AL[((n >> 12) & 63) as usize] as char);
        out.push(AL[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 == 1 || s.contains('=') {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4 + 3);
    let mut i = 0;
    let main = b.len() - b.len() % 4;
    while i < main {
        let (a, c2, c3, d) = (val(b[i])?, val(b[i + 1])?, val(b[i + 2])?, val(b[i + 3])?);
        let n = ((a as u32) << 18) | ((c2 as u32) << 12) | ((c3 as u32) << 6) | d as u32;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let tail = match b.len() - main {
        0 => None,
        2 => {
            let (a, c2) = (val(b[i])?, val(b[i + 1])?);
            if c2 & 0x0f != 0 {
                return None;
            }
            Some(vec![(a << 2) | (c2 >> 4)])
        }
        3 => {
            let (a, c2, c3) = (val(b[i])?, val(b[i + 1])?, val(b[i + 2])?);
            if c3 & 0x03 != 0 {
                return None;
            }
            Some(vec![(a << 2) | (c2 >> 4), ((c2 & 0x0f) << 4) | (c3 >> 2)])
        }
        _ => return None,
    };
    if let Some(tail) = tail {
        out.extend_from_slice(&tail);
    }
    Some(out)
}
fn rng_seed_material(uid: &[u8; 8]) -> u64 {
    // Distinct nodes need distinct offers. The UID is public, but it is
    // only a test-harness RNG seed here; real key material on the Pico
    // comes from the hardware TRNG. A PID mix keeps freshly spawned
    // processes from colliding when the UID was never configured.
    let mut seed = 0x243F_6A88_85A3_08D3u64;
    for (i, b) in uid.iter().enumerate() {
        seed ^=
            (*b as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15u64.rotate_left(((i as u32) + 1) * 8));
    }
    seed ^ ((std::process::id() as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9))
}

fn rng_next(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        x = 0x9E37_79B9_7F4A_7C15;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn node_rng(node: &mut Node) -> u64 {
    // Split the stored state first so two Nodes in the same process still
    // diverge after identical UIDs (provision/offer use the same process).
    node.rng ^= (std::process::id() as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    if node.rng == 0 {
        node.rng = 0x9E37_79B9_7F4A_7C15;
    }
    rng_next(&mut node.rng)
}

fn node_rng_bytes(node: &mut Node, out: &mut [u8]) {
    for c in out.chunks_mut(8) {
        let b = node_rng(node).to_le_bytes();
        let n = c.len().min(8);
        c[..n].copy_from_slice(&b[..n]);
    }
}

impl Node {
    fn new(state_path: Option<String>, uid: [u8; 8]) -> Self {
        let mut engine = Engine::new(false);
        if let Some(p) = &state_path {
            if let Ok(bytes) = std::fs::read(p) {
                let _ = engine.restore(&bytes);
            }
        }
        // The persisted image already carries the stable UID, but a fresh
        // Engine starts with uid_set=false; re-apply the constructor UID so
        // pair_proof's uid check passes. This stages no durable change when
        // the stored identity already matches.
        engine.set_identity(uid);
        // Commit the identity capture if the engine staged it.
        // Pairing offer/proof/confirm state is volatile: commit only durable
        // mutations here, then leave RAM-only pairing state alive. Reloading
        // from disk per request would discard the ceremony before it can
        // finish (the persisted image intentionally omits ephemeral keys).
        let staged: Option<Vec<u8>> = engine.pending_persist().map(|b| b.to_vec());
        if let Some(bytes) = staged {
            if let Some(p) = &state_path {
                let tmp = format!("{p}.tmp");
                if std::fs::write(&tmp, &bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
            engine.commit_ok();
        }
        Self {
            rng: rng_seed_material(&uid),
            engine,
            state_path,
            counters: Counters {
                tx_attempts: 0,
                tx_ok: 0,
                rx_ok: 0,
                rx_crc_bad: 0,
                auth_fail: 0,
                replay_drop: 0,
                forwards: 0,
            },
            pending: None,
            ping_pending: None,
            pkt: 0x243F_6A88 ^ ((uid[0] as u32) << 24) ^ ((uid[7] as u32) << 8) | 1,
            drop_ack: 0,
            dup_rx: 0,
            fail_next: None,
            uid,
        }
    }

    fn commit(&mut self) {
        if let Some(bytes) = self.engine.pending_persist() {
            let owned = bytes.to_vec();
            if let Some(p) = &self.state_path {
                // Simulate interrupted-write durability: write temp + rename,
                // so a crash mid-write never tears the committed state.
                let tmp = format!("{p}.tmp");
                if std::fs::write(&tmp, &owned).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
            self.engine.commit_ok();
        }
    }

    fn status_body(&self) -> String {
        let e = &self.engine;
        format!(
            "{{\"board\":\"{BOARD}\",\"firmware_version\":\"{VERSION}\",\"image\":\"{IMAGE}\",\
            \"provisioned\":{},\"label\":\"{}\",\"radio_enabled\":{},\"radio_available\":false,\
            \"hardware\":\"unavailable\",\"armed_next_boot\":false,\
            \"tx_power_dbm\":2,\"rf_profile\":\"{RF_PROFILE}\",\"time_valid\":{},\"epoch\":{},\
            \"contacts\":{{\"count\":{},\"blocked\":{}}},\
            \"counters\":{{\"tx_attempts\":{},\"tx_ok\":{},\"rx_ok\":{},\"rx_crc_bad\":{},\
            \"auth_fail\":{},\"replay_drop\":{},\"forwards\":{}}}}}",
            yn(e.provisioned()),
            label_str(e.label()),
            yn(e.radio_on()),
            yn(e.time_valid()),
            e.epoch(),
            e.present_count(),
            e.blocked_count(),
            self.counters.tx_attempts,
            self.counters.tx_ok,
            self.counters.rx_ok,
            self.counters.rx_crc_bad,
            self.counters.auth_fail,
            self.counters.replay_drop,
            self.counters.forwards,
        )
    }
    fn reply(&self, id: u64, ok: bool, body: &str, out: &mut impl Write) {
        if ok {
            let _ = write!(out, "{{\"id\":{id},\"ok\":true,\"result\":{body}}}\n");
        } else {
            let _ = write!(out, "{{\"id\":{id},\"ok\":false,\"error\":\"{body}\"}}\n");
        }
        let _ = out.flush();
    }
}

fn state_path_clone(p: &Option<String>) -> Option<String> {
    p.clone()
}

fn yn(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

fn label_str(l: u8) -> &'static str {
    match l {
        1 => "A",
        2 => "B",
        3 => "C",
        _ => "",
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut state_path: Option<String> = None;
    let mut uid = [0x42u8; 8];
    while let Some(a) = args.next() {
        match a.as_str() {
            "--state" => state_path = args.next(),
            "--uid" => {
                if let Some(h) = args.next() {
                    if h.len() == 16 {
                        let mut b = [0u8; 8];
                        let mut ok = true;
                        for i in 0..8 {
                            match u8::from_str_radix(&h[2 * i..2 * i + 2], 16) {
                                Ok(v) => b[i] = v,
                                Err(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            uid = b;
                        }
                    }
                }
            }
            "--help" | "-h" => {
                eprintln!("mesh-exerciser [--state PATH] [--uid HEX16]");
                eprintln!("stdin/stdout: newline JSON, same wire as firmware usb.rs.");
                eprintln!("MESH_EXERCISER_SCENARIOS: spawn 2-3 processes, shuttle __frame records between them, use __inject drop_next_ack/duplicate_next_rx/fail_next/emit_stale_event/reset, kill -9 + restart with same --state to simulate reboot/interrupted writes.");
                return;
            }
            _ => {}
        }
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut node = Node::new(state_path, uid);
    let mut buf = String::new();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.len() > MAX_LINE {
            // Discard through newline (already consumed) and report.
            let _ = out.write_all(b"{\"id\":0,\"ok\":false,\"error\":\"LINE_TOO_LONG\"}\n");
            let _ = out.flush();
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        handle_line(&mut node, line.trim(), &mut out, &mut buf);
    }
}

#[allow(clippy::too_many_lines)]
fn handle_line(node: &mut Node, line: &str, out: &mut impl Write, _scratch: &mut String) {
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            let _ = out.write_all(b"{\"id\":0,\"ok\":false,\"error\":\"BAD_REQUEST\"}\n");
            let _ = out.flush();
            return;
        }
    };
    let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("");
    match op {
        "status" => {
            let b = node.status_body();
            node.reply(id, true, &b, out);
        }
        "contacts" => {
            let mut s = String::from("{\"contacts\":[");
            for i in 1..=MAX_CONTACTS as u64 {
                if i > 1 {
                    s.push(',');
                }
                let cid = i as u8;
                let present = node.engine.contact_present(cid);
                let blocked = node.engine.contact_blocked(cid);
                let fp = node
                    .engine
                    .contact_fingerprint(cid)
                    .map(|f| hex8(&f))
                    .unwrap_or_default();
                s.push_str(&format!(
                    "{{\"contact_id\":{i},\"present\":{},\"blocked\":{},\"fingerprint\":\"{fp}\"}}",
                    yn(present),
                    yn(blocked)
                ));
            }
            s.push_str("]}");
            node.reply(id, true, &s, out);
        }
        "provision" => {
            let label = v.get("label").and_then(|x| x.as_str()).unwrap_or("");
            if node.engine.provisioned() {
                node.reply(id, false, "ALREADY_PROVISIONED", out);
                return;
            }
            let code = match label {
                "A" => 1,
                "B" => 2,
                "C" => 3,
                _ => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let mut sk = [0u8; 32];
            node_rng_bytes(node, &mut sk);
            match node.engine.provision(code, sk) {
                Ok(()) => {
                    sk.zeroize();
                    node.commit();
                    node.reply(
                        id,
                        true,
                        &format!("{{\"provisioned\":true,\"label\":\"{label}\"}}"),
                        out,
                    );
                }
                Err(e) => {
                    sk.zeroize();
                    node.reply(id, false, err_str(e), out);
                }
            }
        }
        "time_set" => {
            let secs = match v.get("unix_seconds").and_then(|x| x.as_u64()) {
                Some(s) => s,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            match node.engine.set_time(secs) {
                Ok(epoch) => {
                    node.commit();
                    node.reply(
                        id,
                        true,
                        &format!(
                            "{{\"time_valid\":true,\"unix_seconds\":{secs},\"epoch\":{epoch}}}"
                        ),
                        out,
                    );
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        "time_status" => {
            let e = &node.engine;
            node.reply(
                id,
                true,
                &format!(
                    "{{\"time_valid\":{},\"unix_seconds\":{},\"epoch\":{}}}",
                    yn(e.time_valid()),
                    e.unix_seconds(),
                    e.epoch()
                ),
                out,
            );
        }
        "radio_set" => {
            let en = match v.get("enabled").and_then(|x| x.as_bool()) {
                Some(b) => b,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            if en {
                // Radio-free image: explicit unavailable, never fake on.
                node.reply(id, false, "RADIO_UNAVAILABLE", out);
                return;
            }
            match node.engine.set_radio(false) {
                Ok(()) => {
                    node.commit();
                    node.reply(id, true, "{\"radio_enabled\":false}", out);
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        "radio_arm_next_boot" => {
            // Honest no-op persist in radio-free image: arming is stored so
            // `status` reflects it, but there is no RF to arm.
            node.reply(id, true, "{\"armed_next_boot\":false}", out);
        }
        "ping" => {
            if let Some(f) = node.fail_next.take() {
                node.reply(id, false, &f, out);
                return;
            }
            node.reply(id, false, "RADIO_UNAVAILABLE", out);
        }
        "send" => {
            if let Some(f) = node.fail_next.take() {
                node.reply(id, false, &f, out);
                return;
            }
            let cid = match v.get("contact_id").and_then(|x| x.as_u64()) {
                Some(c) if (1..=MAX_CONTACTS as u64).contains(&c) => c as u8,
                _ => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let text = match v.get("text").and_then(|x| x.as_str()) {
                Some(t) => t,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            if node.engine.contact_blocked(cid) {
                node.reply(id, false, "CONTACT_BLOCKED", out);
                return;
            }
            // Radio-free: no airtime; never fabricate ACKNOWLEDGED.
            node.reply(id, false, "RADIO_UNAVAILABLE", out);
            let _ = (cid, text);
        }
        "contact_delete" => {
            let cid = match v.get("contact_id").and_then(|x| x.as_u64()) {
                Some(c) if (1..=MAX_CONTACTS as u64).contains(&c) => c as u8,
                _ => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            match node.engine.delete_contact(cid) {
                Ok(()) => {
                    node.commit();
                    node.reply(id, true, &format!("{{\"contact_id\":{cid},\"deleted\":true}}"), out);
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        "block" | "unblock" => {
            let cid = match v.get("contact_id").and_then(|x| x.as_u64()) {
                Some(c) if (1..=MAX_CONTACTS as u64).contains(&c) => c as u8,
                _ => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let blocked = op == "block";
            match node.engine.set_blocked(cid, blocked) {
                Ok(BlockOutcome::CancelledSend(_)) | Ok(_) => {
                    node.commit();
                    node.reply(
                        id,
                        true,
                        &format!("{{\"contact_id\":{cid},\"blocked\":{}}}", yn(blocked)),
                        out,
                    );
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        "pair_offer" => match offer_flow(node) {
            Ok(rec) => node.reply(
                id,
                true,
                &format!("{{\"record_b64\":\"LMESH1:{}\"}}", b64url_encode(&rec)),
                out,
            ),
            Err(e) => node.reply(id, false, err_str(e), out),
        },
        "pair_proof" => match node.engine.pair_proof() {
            Ok(rec) => {
                node.commit();
                node.reply(
                    id,
                    true,
                    &format!("{{\"record_b64\":\"LMESH1:{}\"}}", b64url_encode(&rec)),
                    out,
                );
            }
            Err(e) => node.reply(id, false, err_str(e), out),
        },
        "pair_confirm" => match node.engine.pair_confirm() {
            Ok(rec) => {
                node.commit();
                node.reply(
                    id,
                    true,
                    &format!("{{\"record_b64\":\"LMESH1:{}\"}}", b64url_encode(&rec)),
                    out,
                );
            }
            Err(e) => node.reply(id, false, err_str(e), out),
        },
        "pair_import" => {
            let b64 = match v.get("record_b64").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let replace = v.get("replace").and_then(|x| x.as_bool()).unwrap_or(false);
            let raw = match decode_transport_b64(b64) {
                Some(r) => r,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            match node.engine.pair_import(&raw, replace) {
                Ok(o) => {
                    node.commit();
                    let fp = hex16(&o.fingerprint);
                    match o.contact_id {
                        Some(c) => node.reply(
                            id,
                            true,
                            &format!("{{\"fingerprint\":\"{fp}\",\"contact_id\":{c}}}"),
                            out,
                        ),
                        None => node.reply(id, true, &format!("{{\"fingerprint\":\"{fp}\"}}"), out),
                    }
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        // ---- virtual transport between exerciser processes ----
        "__frame" => {
            // `{"id":N,"op":"__frame","frame_b64":"..","now_ms":M}`: feed one
            // received frame through the engine; replies with delivery/relay
            // directives the scenario runner shuttles to the peer process.
            let fb = match v.get("frame_b64").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let now_ms = v.get("now_ms").and_then(|x| x.as_u64()).unwrap_or(0);
            let bytes = match b64url_decode(fb) {
                Some(b) => b,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            // Duplicate-injection: replay the frame extra times first.
            let mut dups = node.dup_rx;
            node.dup_rx = 0;
            let ack_packet_id = node_rng(node) as u32;
            let (kind, ack, ev) = node.engine.on_frame(&bytes, now_ms, ack_packet_id);
            let ack_b64 = ack.as_ref().map(|f| b64url_encode(f.as_slice()));
            node.commit();
            bump_rx(&mut node.counters, &kind, &bytes);
            let mut body = String::from("{");
            body.push_str(&format!("\"kind\":\"{}\",", kind_str(&kind)));
            if let Some(a) = ack_b64 {
                // drop_next_ack swallows endpoint ACKs (retry path).
                if node.drop_ack > 0 {
                    node.drop_ack -= 1;
                } else {
                    body.push_str(&format!("\"ack_b64\":\"{a}\","));
                }
            }
            if let Some(e) = ev {
                body.push_str(&format!("\"event\":{},", event_json(&e)));
                // Re-emit duplicate receives without redelivery.
                while dups > 0 {
                    dups -= 1;
                    let ack_packet_id = node_rng(node) as u32;
                    let _ = node.engine.on_frame(&bytes, now_ms + 1, ack_packet_id);
                    node.commit();
                }
            }
            // Relay forward bytes, if any.
            if matches!(kind, IncomingKind::Forward) {
                // `ack` slot carries the forward frame for transit.
                if let Some(f) = ack {
                    body.push_str(&format!(
                        "\"forward_b64\":\"{}\",",
                        b64url_encode(f.as_slice())
                    ));
                    node.counters.forwards += 1;
                }
            }
            body.push_str("\"ok\":true}");
            node.reply(id, true, &body, out);
        }
        "__send_begin" => {
            // Direct engine send for multi-node scenarios (bypasses the
            // RADIO_UNAVAILABLE USB gate; the USB `send` op stays honest).
            let cid = match v.get("contact_id").and_then(|x| x.as_u64()) {
                Some(c) if (1..=MAX_CONTACTS as u64).contains(&c) => c as u8,
                _ => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let text = match v.get("text").and_then(|x| x.as_str()) {
                Some(t) => t,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            node.pkt = node.pkt.wrapping_mul(1664525).wrapping_add(1013904223) | 1;
            let pid = node.pkt;
            match node.engine.send_begin(cid, text.as_bytes(), pid) {
                Ok(ps) => {
                    node.commit();
                    match node.engine.send_emit() {
                        Ok(f) => {
                            node.commit();
                            node.counters.tx_attempts += 1;
                            node.pending = Some(PendingOut {
                                contact_id: cid,
                                frame: f,
                                attempts: 1,
                            });
                            let fb = b64url_encode(node.pending.as_ref().unwrap().frame.as_slice());
                            node.reply(
                                id,
                                true,
                                &format!(
                                    "{{\"frame_b64\":\"{fb}\",\"epoch\":{},\"sequence\":{},\"packet_id\":{}}}",
                                    ps.epoch, ps.sequence, ps.packet_id
                                ),
                                out,
                            );
                        }
                        Err(e) => node.reply(id, false, err_str(e), out),
                    }
                }
                Err(e) => node.reply(id, false, err_str(e), out),
            }
        }
        "__retry" => match node.pending.as_ref() {
            Some(p) => {
                let fb = b64url_encode(p.frame.as_slice());
                node.reply(id, true, &format!("{{\"frame_b64\":\"{fb}\"}}"), out);
            }
            None => node.reply(id, false, "BAD_REQUEST", out),
        },
        "__ack_in" => {
            let fb = match v.get("frame_b64").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let now_ms = v.get("now_ms").and_then(|x| x.as_u64()).unwrap_or(0);
            let bytes = match b64url_decode(fb) {
                Some(b) => b,
                None => {
                    node.reply(id, false, "BAD_REQUEST", out);
                    return;
                }
            };
            let ack_packet_id = node_rng(node) as u32;
            let (kind, _, ev) = node.engine.on_frame(&bytes, now_ms, ack_packet_id);
            node.commit();
            if matches!(kind, IncomingKind::Ack { .. }) {
                node.pending = None;
                node.engine.send_complete(true);
                node.counters.tx_ok += 1;
                node.reply(id, true, "{\"acked\":true}", out);
            } else {
                let _ = ev;
                node.reply(id, true, "{\"acked\":false}", out);
            }
        }
        "__inject" => {
            let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
            match kind {
                "drop_next_ack" => {
                    node.drop_ack = v.get("n").and_then(|x| x.as_u64()).unwrap_or(1).min(10) as u32;
                    node.reply(id, true, "{\"armed\":true}", out);
                }
                "duplicate_next_rx" => {
                    node.dup_rx = v.get("n").and_then(|x| x.as_u64()).unwrap_or(1).min(10) as u32;
                    node.reply(id, true, "{\"armed\":true}", out);
                }
                "fail_next" => {
                    let e = v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("BUSY")
                        .to_string();
                    node.fail_next = Some(e);
                    node.reply(id, true, "{\"armed\":true}", out);
                }
                "emit_stale_event" => {
                    let _ = out.write_all(b"{\"event\":\"received\",\"contact_id\":9}\n");
                    node.reply(id, true, "{\"emitted\":true}", out);
                }
                "reset" => {
                    node.drop_ack = 0;
                    node.dup_rx = 0;
                    node.fail_next = None;
                    node.reply(id, true, "{\"armed\":false}", out);
                }
                _ => node.reply(id, false, "BAD_REQUEST", out),
            }
        }
        "__reboot" => {
            // Simulated ordinary reboot: drop RAM (time_valid, pending),
            // reload durable state from disk, skip last reserved block.
            let uid = node.uid;
            let path = node.state_path.clone();
            let mut fresh = Node::new(path, uid);
            fresh.counters = node.counters;
            fresh.drop_ack = node.drop_ack;
            fresh.dup_rx = node.dup_rx;
            fresh.fail_next = node.fail_next.take();
            *node = fresh;
            // Node::new leaves time unset by construction (Engine::restore
            // never sets time_valid); report it honestly.
            node.reply(id, true, "{\"rebooted\":true,\"time_valid\":false}", out);
        }
        _ => node.reply(id, false, "UNKNOWN_OP", out),
    }
}

fn offer_flow(node: &mut Node) -> Result<[u8; OFFER_RECORD_LEN], EngineError> {
    let mut eph_priv = [0u8; 32];
    let mut challenge = [0u8; 32];
    node_rng_bytes(node, &mut eph_priv);
    node_rng_bytes(node, &mut challenge);
    if eph_priv == [0u8; 32] {
        eph_priv[0] = 1;
    }
    let eph_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(eph_priv)).to_bytes();
    node.engine.pair_offer(eph_priv, eph_pub, challenge)
}

fn decode_transport_b64(s: &str) -> Option<Vec<u8>> {
    let t = s.strip_prefix("LMESH1:")?;
    if t.contains('=') {
        return None;
    }
    let raw = b64url_decode(t)?;
    match raw.first() {
        Some(1) if raw.len() == OFFER_RECORD_LEN => Some(raw),
        Some(2) if raw.len() == PROOF_RECORD_LEN => Some(raw),
        Some(3) if raw.len() == CONFIRM_RECORD_LEN => Some(raw),
        _ => None,
    }
}

fn hex16(b: &[u8; 16]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for v in b {
        s.push(H[(v >> 4) as usize] as char);
        s.push(H[(v & 0xf) as usize] as char);
    }
    s
}

fn hex8(b: &[u8; 32]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for v in &b[..8] {
        s.push(H[(v >> 4) as usize] as char);
        s.push(H[(v & 0xf) as usize] as char);
    }
    s
}

fn kind_str(k: &IncomingKind) -> &'static str {
    match k {
        IncomingKind::Deliver { .. } => "deliver",
        IncomingKind::ReAck { .. } => "reack",
        IncomingKind::Ack { .. } => "ack",
        IncomingKind::Forward => "forward",
        IncomingKind::Ignore => "ignore",
    }
}

fn event_json(e: &mesh_node::NodeEvent) -> String {
    match e {
        mesh_node::NodeEvent::Received {
            contact_id,
            epoch,
            sequence,
            text,
            text_len,
        } => {
            let t = String::from_utf8_lossy(&text[..usize::from(*text_len)]);
            let esc: String = t
                .chars()
                .flat_map(|c| match c {
                    '"' => vec!['\\', '"'],
                    '\\' => vec!['\\', '\\'],
                    '\n' => vec!['\\', 'n'],
                    c => vec![c],
                })
                .collect();
            format!(
                "{{\"event\":\"received\",\"contact_id\":{contact_id},\"epoch\":{epoch},\"sequence\":{sequence},\"text\":\"{esc}\"}}"
            )
        }
        mesh_node::NodeEvent::SendAcked {
            contact_id,
            epoch,
            sequence,
            packet_id,
        } => format!(
            "{{\"event\":\"acked\",\"contact_id\":{contact_id},\"epoch\":{epoch},\"sequence\":{sequence},\"packet_id\":{packet_id}}}"
        ),
    }
}

fn bump_rx(c: &mut Counters, kind: &IncomingKind, bytes: &[u8]) {
    match kind {
        IncomingKind::Deliver { .. } => c.rx_ok += 1,
        IncomingKind::ReAck { .. } => c.replay_drop += 1,
        IncomingKind::Ack { .. } => {}
        IncomingKind::Forward => c.forwards += 1,
        IncomingKind::Ignore => {
            if bytes.len() < 30 {
                c.rx_crc_bad += 1;
            } else {
                c.auth_fail += 1;
            }
        }
    }
}

#[allow(dead_code)]
fn unused_pairing_refs() {
    let _ = pairing::RECORD_OFFER;
    let _ = SigningKey::from_bytes as fn(&[u8; 32]) -> SigningKey;
    let _ = HashMap::<u8, u8>::new();
}
