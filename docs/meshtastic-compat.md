# Meshtastic compatibility — PROPOSAL ONLY (no protocol changes)

Status: **proposal** (host receive-only parser + `mesh-core` decode-only
helpers landed: see §5). This document authorizes **no changes** to the
secure mesh: no frame, crypto, RF, firmware dispatch, or
secure-host/script changes. It adds a display-only decode path for
public Meshtastic frames; it adds no TX, no PSK handling, and no bridging.

Baseline (2026-09-21, from Main): A→C and B→A RF links are ACK-proven at
+2 dBm SF7/BW500/CR4-5/sync `0x12` on radio-secure image `1ba682e7`; all
three boards live with radios on. TCP is parked (router MAC-filters new
devices). Constraint: **any compat MUST ride the existing encrypted
frame path, never bypass it.** Compat bytes travel INSIDE an authenticated
LMESH secure DATA body and are handed to the decode helpers only after
endpoint decryption. This doc does not re-prove RF and assumes TCP is down.

## 0. Decision: dual image, secure stays default

The private mesh stays the default and only recommended image:

- Pairwise X25519 + Ed25519 pairing, per-hour ChaCha20-Poly1305 traffic
  keys, forward secrecy, authenticated seq/epoch replay windows.
- Fixed RF: 915 MHz, SF7, BW500, CR4/5, pre8, CRC on, private sync `0x12`,
  **+2 dBm fixed** (`firmware/src/radio.rs::TX_POWER_DBM`), 1-hop managed
  flood (`crates/mesh-core/src/relay.rs`: only `hops == 1` forwarded,
  64-entry 8 s cache, 100–300 ms jitter).
- Max secure DATA frame 207 B, text ≤ 160 B (`crates/mesh-core/src/frame.rs`).

The Meshtastic-compat image is a **separate, opt-in build** for
interoperation only. Everywhere it appears — USB `status.image`,
USB strings, host UI, docs, boot banner — it MUST be labeled
**`INSECURE`**, e.g. `image: "meshtastic-compat-INSECURE"`. Reason,
repeated verbatim in UI/docs/USB:

> INSECURE: shared channel PSK decrypts all traffic, no forward secrecy,
> 7-hop flood, MQTT bridge leaks.

Default-flash, pairing, and docs flows MUST NOT offer the compat image
unless the operator explicitly selects it. Cross-flashing a secure node
to compat MUST wipe secure contact keys (same `wipe` path as today).

Proposed build (not implemented):

- `firmware --features meshtastic-compat` → `IMAGE =
  "meshtastic-compat-INSECURE"`; `--features radio` stays the only
  RF-enabled secure image; default (no features) stays radio-free.
- Compat and secure images NEVER share airtime: different modem + sync
  + framing (see §2). One radio = one mesh at a time. Simultaneous
  participation needs a second radio (§5).

## 1a. Physics verdict: same-radio interop is impossible (standing decision)

| Axis | Secure private mesh (this repo, fixed) | Meshtastic US MediumFast/LongFast default RX path |
|---|---|---|
| Frequency | 915.0 MHz fixed | 906.875 MHz (default LongFast/MediumFast slot center; channel-name hash picks other 902–928 MHz slots) |
| Spreading factor | SF7 | SF11 |
| Bandwidth | BW500 | BW250 |
| Preamble | 8 symbols | 16 symbols |
| Sync word | `0x12` (private) | `0x2B1B` (Meshtastic SX126x-family sync; SX1276-compat public path uses `0x34` — still not `0x12`) |
| Framing / crypto | `LMESH` ver/flags/dst/src/pkt/hops/epoch/seq + pairwise X25519 ECDH → HKDF → hourly ChaCha20-Poly1305, Ed25519 pairing | Meshtastic MeshPacket + protobuf Data portnums + shared channel AES-PSK (0/16/32 B, default `0x01` well-known), up to 7 hops, MQTT bridge |

Why one SX1276 cannot hear both: LoRa demodulation requires matching
frequency AND SF AND bandwidth AND preamble/sync within the same RX
window. Every one of those differs here (915.0 vs 906.875 MHz, SF7 vs
SF11, BW500 vs BW250, pre8 vs pre16, sync `0x12` vs `0x2B1B`). A single
radio parked on our profile hears Meshtastic as noise and vice versa;
no firmware re-tune, preamble tweak, or "promiscuous mode" fixes this
without leaving our mesh. The crypto/identity stacks then differ on
top (pairwise X25519 + rotating addresses vs shared PSK + persistent
NodeIds), so even a captured bitstream would not decode into our mesh.

What a bridge would need (explicit non-goal, second radio required):

- A **second, dedicated Meshtastic-tuned radio** (own antenna path or
  RF switch) parked at 906.875 MHz / SF11 / BW250 / preamble 16 /
  Meshtastic sync, running the Meshtastic stack or the
  `host/meshctl/compat.py` receive-only parser for display.
- Host-side policy only: display decoded public text as `INSECURE`
  (see `compat.py` docstring); never forward secure traffic to the
  public channel and never import a shared channel PSK into the secure
  path. Any decrypt-both-sides relay is a designed plaintext point and
  is NOT built here.
- Legal/power note: bridge RX is passive; any Meshtastic TX from our
  bench stays under the project +2 dBm hard constraint with short
  bench range — range parity via 22–30 dBm is NOT proposed.

## 1. Why the two meshes cannot merge

## 2. RF / legal mapping (RP2350 + SX1276)

Meshtastic US LongFast reference (docs 2026-09-21,
meshtastic.org/docs/configuration/radio/lora,
…/radio/channels): region `US` 902–928 MHz, 100 % duty, 30 dBm limit;
modem presets ShortTurbo…VeryLongSlow, default LongFast; `hop_limit`
max 7 default 3; channel name hash → frequency slot unless
`frequency_slot` is pinned; TX power 0 = legal max.

| Item | Fits single SX1276 @ +2 dBm? | Notes |
|---|---|---|
| SF7/BW500 compat-only presets (ShortTurbo-class) | Fits, legal | Same chip capability as secure profile; only sync/freq-hopping/framing change. |
| LongFast SF11/BW125 RX/TX | Fits technically (SX127x supports SF7–12) | ~2 s airtime per hop; 7-hop flood × MQTT = congestion + battery cost. pico `RADIO_QUEUE_CAP = 8` and 255-B buffers already bound this; compat MUST add duty/airtime caps (proposal: drop rather than queue). |
| Frequency-slot hopping (channel-name hash) | Fits with driver work | `lora-phy` SX127x path programs one frequency per TX; slot table + CAD per hop is new code, no protocol change to secure image. |
| Public sync word `0x34` | Fits | Compile-time per-image constant; NEVER runtime-switchable (avoids secure/compat cross-talk). |
| +2 dBm TX (project hard constraint) | **Legal** (≪ 30 dBm US limit), short range | Compat at +2 dBm hears only nearby Meshtastic nodes; this is expected and MUST be documented, not "fixed" by raising power. |
| Raising power to 22–30 dBm for parity | **Breaks project constraint; NOT proposed** | Would need PA/duty/thermal work and violates the user's lowest-power rule. Any such request is a new explicit user decision, not part of this proposal. |
| EU 10 % duty regions | Needs duty tracker | US-only bench today; compat image MUST refuse TX until `lora.region` is set (mirrors Meshtastic `UNSET` = no-TX gate). |

## 3. Feature map: Meshtastic → RP2350 limits

### 3.1 Channels / PSK

- 8 slots (index 0 PRIMARY + SECONDARYs, consecutive, no gaps);
  per-channel name (<12 B), PSK 0/16/32 B, uplink/downlink/mute flags,
  `position_precision` 0–32.
- Shim maps **one** active Meshtastic channel at a time (RAM: one 32-B
  PSK + name; full 8-channel table does not fit comfortably beside
  Embassy USB + relay cache on RP2350 — proposal caps at 1 active +
  1 staged).
- Default PSK `0x01` and all-zeros (no crypto) MUST surface as
  `INSECURE-DEFAULT-KEY` in UI; `ok_to_mqtt` is a polite flag only,
  not cryptographic — document as such.
- Fits: AES-128/256 decrypt + channel-hash (`SHA256(name)` → slot)
  in the shim crate (host-computed today via `prost`; firmware port
  needs `nanopb`-equivalent budget — see §4).

### 3.2 NodeInfo / identity

- Meshtastic broadcasts persistent NodeId, long/short names, HW model,
  battery/role. This directly contradicts the secure mesh's rotating
  addresses and no-serial-on-air rule.
- Compat image MUST isolate identity stores: separate flash namespace,
  separate USB `contacts` view, explicit `INSECURE node-id broadcast
  ON` indicator. NEVER reuse secure addresses/keys for NodeInfo.

### 3.3 Text / telemetry / position

- Portnums: `TEXT_MESSAGE_APP`, `TELEMETRY_APP` (battery/sensor),
  `POSITION_APP` (lat/lon/alt + precision), `NODEINFO_APP`,
  `ROUTING_APP` (ACK/nak/traceroute), `ADMIN_APP`, `MAP_REPORT_APP`.
- Protobuf decode on RP2350 is the tightest fit: full `protobuf`
  runtime is rejected (flash/RAM); proposal allows `nanopb`-style
  generated structs for these 7 portnums only, drop unknown portnums.
- 160-B secure text vs Meshtastic ~200-B+ protobuf payloads: shim
  MUST enforce 255-B `RADIO_BUF_LEN` ceiling and drop oversize with a
  counter (no fragmentation proposed).
- Position: honor `position_precision` (0 = never send); default MUST
  be 0/off in the compat image until the operator opts in.

### 3.4 Routing / hop_limit

- Secure: 1-hop, opaque, endpoints authenticate. Compat: `hop_limit`
  ≤ 7, each relay decrements + rebroadcasts, wants ACK via routing
  module, traceroute exposes path.
- Shim relay policy (proposal): cap effective forwarded hops at the
  configured `hop_limit`, enforce per-packet dedup cache (reuse the
  64-entry/8 s pattern, separate instance), and count floods toward
  duty caps. 7-hop floods at SF11 will saturate the channel — document
  default 3, operator-tunable down, never up past 7.
- Secure `RELAY_CACHE` logic MUST NOT be shared: different mutable
  fields and trust model.

### 3.5 MQTT

- Meshtastic MQTT uplinks mesh packets to a public broker and
  downlinks back to RF. This **publishes INSECURE-channel plaintext
  (decryptable by PSK holders) to the internet**.
- RP2350 firmware leaves Pico 2 W Wi-Fi/Bluetooth uninitialized; the
  compat **firmware MUST NOT add Wi-Fi**. MQTT bridging is host-side
  only (`meshctl`-adjacent proposal), explicit opt-in per channel
  (`uplink_enabled`/`downlink_enabled` default false), with the leak
  warning in the enable prompt. `ignore_mqtt` default true in shim.

### 3.6 Admin / remote menos

- `ADMIN_APP` (remote config, shutdown, channel edit) + legacy `admin`
  channel + Remote-Admin are powerful and remotely exploitable.
- Proposal: compat image answers **no** remote admin by default
  (drop `ADMIN_APP` on RX; no TX). Local USB admin only. Any future
  remote-admin support needs a separate threat review — out of scope.

## 4. Proposed `crates/mesh-meshtastic-shim/` (plan only, not created)

Pure `no_std` translation crate, zero secure-mesh imports (prevents
key/frame confusion). Sketched layout:

```text
crates/mesh-meshtastic-shim/
  Cargo.toml        # no_std, deps: sha2, chacha20poly1305(AES-CTR only via aes crate), heapless, serde(nostd)
  src/lib.rs        # error types, INSECURE markers
  src/channel.rs    # name→slot hash, PSK store (1 active + 1 staged), uplink/downlink/mute/precision flags
  src/modem.rs      # LongFast-equivalent params, sync 0x34 const, region gate (UNSET=no-TX), duty-cap counters
  src/packet.rs     # MeshPacket encode/decode, hop_limit clamp ≤7, 255-B ceiling, portnum filter (7 known, drop rest)
  src/proto_min.rs  # nanopb-style structs for text/telemetry/position/nodeinfo/routing/admin(map-report dropped)
  src/relay.rs      # separate flood cache (64×8 s pattern), decrement-and-rebroadcast, traceroute answer=drop
  src/usb_text.rs   # exact INSECURE strings (below) — single source for firmware + host
```

Skipped (needs second radio or violates constraints): simultaneous
dual-mesh, firmware Wi-Fi/MQTT, power > +2 dBm, full 8-channel table,
full protobuf runtime, remote admin, position-on-by-default,
`SHORT_TURBO` in non-US-legal regions.

Flash/RAM budget (estimate, must be measured at implementation):
~20–40 KB flash for minimal protobuf structs + AES; relay cache
64×32 B = 2 KB; channel store < 1 KB. Requires `opt-level="s" + LTO`
(release profile already set) and MUST report `cargo size` in the
implementation ticket.

## 5. What fits vs needs second radio vs breaks legal/+2 dBm

Physics verdict restated: with SF7/BW500/pre8/sync `0x12` @ 915.0 MHz on
our side vs SF11/BW250/pre16/sync `0x2B1B` @ 906.875 MHz on the
Meshtastic default RX path, same-radio "listen to both" is physically
impossible. All compat RX below assumes a second, Meshtastic-tuned
radio feeding raw payloads to the host parser.

- **Fits (single RP2350+SX1276, +2 dBm, proposal scope):** 1 active
  channel, LongFast-class RX/TX at low power, hop_limit ≤ 7 with duty
  caps, text/telemetry/position-RX + text-TX, NodeInfo with isolated
- **Landed (host-only, receive-parse ONLY):** `host/meshctl/compat.py`
  decodes captured public (`decoded`) MeshPacket/Data frames to
  display text. No encode/send/encrypt path exists; channel-encrypted
  (`encrypted`) packets are reported as undecodable-by-design; no PSK
  API exists and no PSK is ever imported into the secure path. Every
  entry point is labeled INSECURE in its docstring; `format_packet`
  output carries the `INSECURE ... (shared channel; unauthenticated)`
  marker for any UI that displays it.
- **Landed (`mesh-core`, decode-only, feature-gated):**
  `crates/mesh-core/src/compat.rs` behind non-default cargo feature
  `meshtastic` mirrors the host parser in `no_std` Rust: fixed-capacity
  (512-B ceiling, borrowed slices, zero allocation), `parse_packet` /
  `try_parse_packet` / `portnum_name` only. No encode/send/encrypt path,
  no PSK API, no secure-module imports, no frame-path or dispatch
  changes. Encrypted-path-only: callers MUST hand it bytes already
  decrypted from an LMESH secure DATA body; it never sees raw RF and
  never retunes the modem.
- **Needs second radio (explicit non-goal):** staying on the secure
  mesh AND Meshtastic at once; any "bridge" box between the two meshes
  (would decrypt both — a designed plaintext point, NEVER implicit).
  Both parsers take caller-supplied payload bytes as input; RF
  capture/transport lives outside them and is NOT built here.

## 5a. Staged plan (sniff/decode first, TX last, never auto-enabled)

1. **Stage 0 — this ticket (landed):** host parser + `mesh-core`
   decode-only helpers. No RF, no TX, no PSK, no dispatch changes.
2. **Stage 1 — sniff/decode over the encrypted path (next):** a
   Meshtastic-tuned second radio feeds captures to the host; the host
   ferries raw captures INSIDE secure LMESH DATA to a paired node whose
   firmware calls `compat::try_parse_packet` post-decryption for local
   display only. Needs real RF captures to prove field coverage; the
   current vectors are hand-built, not air-proven.
3. **Stage 2 — display plumbing (proposal):** USB/host surfaces show
   decoded text with the §6 INSECURE strings; drop + count oversize /
   unknown-portnum / admin-remote packets. Still RX-only.
4. **Stage 3 — TX (explicitly last, NOT proposed):** any Meshtastic TX
   needs a separate threat review, region gate (`UNSET` = no TX), duty
   caps, isolated identity store, and operator opt-in (`INSECURE-OPT-IN`).
   Never auto-enabled; never from the secure image.

- **Breaks legal or the +2 dBm hard constraint (NOT proposed):**
  raising TX for range parity; EU operation without a duty tracker;
  `override_frequency` / HAM-mode out-of-band TX; `SHORT_TURBO` 500 kHz
  where illegal.

## 6. Mandatory INSECURE strings (exact text, single-sourced)

- USB `status`: `"image":"meshtastic-compat-INSECURE"`,
  `"security":"INSECURE-shared-psk-no-fs"`.
- USB banner / host header:
  `meshtastic-compat-INSECURE: shared channel PSK decrypts all
  traffic, no forward secrecy, 7-hop flood, MQTT bridge leaks.`
- Enable-gate prompt (host): `Type INSECURE-OPT-IN to enable the
  Meshtastic-compat image. Private secure mesh remains the default.`

## 7. Acceptance gates (whenever implemented)

1. Secure image untouched: default build RF profile string, sync
   `0x12`, +2 dBm, 1-hop behavior, and all existing regression tests
   pass unchanged.
2. Compat image `status` shows `meshtastic-compat-INSECURE` and every
   UI/docs/USB surface carries the §6 strings.
3. `lora.region == UNSET` → zero TX (mirrors Meshtastic gate).
4. Interop smoke (two compat nodes + one real Meshtastic node at
   matched region/preset/channel): text both ways at +2 dBm bench
   range; oversize/unknown-portnum/admin-remote packets dropped with
   counters.
5. No secure keys in compat flash namespace and vice versa (wipe on
   cross-flash verified).

## Sources

- Meshtastic LoRa config (region/power/hop/modems):
  https://meshtastic.org/docs/configuration/radio/lora/
- Meshtastic channels (roles/PSK/uplink/downlink/precision):
  https://meshtastic.org/docs/configuration/radio/channels/
- Repo ground truth: `firmware/src/radio.rs` (RF/TX_POWER_DBM),
  `crates/mesh-core/src/{frame,security,relay}.rs`,
  `firmware/src/usb.rs` (IMAGE/status contract),
  `firmware/Cargo.toml` (radio feature), `three-pico-lora-plan.md`.
