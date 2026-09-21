# Radio test scripts

Run order: **regression first** (automated health + six-direction RF +
reject + silence), then the single-purpose scripts below for focused
diagnosis. The mesh scripts take no port arguments: boards are discovered
by USB VID:PID and identified by matched-ID `status` label (never ACM
numbers). One held `SerialSession` per port for the whole run (single
owner per port).

Verified 2026-09-21 bilateral topology (V3, 16 slots; A2<->C1 repaired):
A slot1 -> B (B slot1), B slot1 -> A (A slot1), B slot2 -> C (C slot2),
C slot2 -> B (B slot2), A slot2 -> C (C slot1), C slot1 -> A (A slot2).
`contacts` fingerprints are SHA256 of the peer signing public key, NOT a
shared pair secret -- scripts use explicit per-directed-edge slots and
never infer reciprocity from equal fingerprints.

## 0. Regression (automated three-node pass)

```sh
.venv/bin/python scripts/mesh_regression.py
```

No port arguments. Asserts: all three present, radio-secure, SX1276
`0x12`, provisioned + clock valid; per-leg TX slot present+unblocked
gate; all six directed legs above each `ACKNOWLEDGED` with exactly one
matching fresh-text `received` on the intended board/contact (no
duplicates, no wrong recipients; all interleaved exchange events
collected) and TX attempts within the send+relay bound; empty slot 3 on
A fails `BAD_REQUEST` with zero airtime; radios off + 40 s settle, then
a 10 s quiet window moves no counters. Exits 0 on `REGRESSION: PASS`, 1
otherwise. Radios are left OFF; re-enable per board before manual RF.
Needs the three paired boards above -- run the bilateral pairing
ceremony first if a leg reports a missing slot.

## 0a. All-directions (explicit six-edge check)

```sh
.venv/bin/python scripts/mesh_allways.py
.venv/bin/python scripts/mesh_allways.py --edge A:C=2:1 --edge C:A=1:2
```

Same discovery as regression. Defaults are the six directed edges
above; `--edge TX:RX=TXSLOT:RXSLOT` (slots 1..16, repeatable) overrides
one directed pair only. Per direction: TX slot present+unblocked,
`ACKNOWLEDGED`, exactly one fresh-text `received` on the intended
board/contact, nothing elsewhere. Time-syncs and enables radios first.
No pairing/block/delete ops. Exits 0 only when all six pass.

## 0b. Adversarial (limits, hostile text, protocol abuse)

```sh
.venv/bin/python scripts/mesh_adversarial.py
```

No port arguments. Directed B slot2 -> C slot2 with A radio-off (no
relay skew). Asserts: 1-char and 160-char boundary sends deliver
byte-intact exactly once on (C, contact 2); empty/161-char/out-of-range
contacts (0/99) and empty slot 3 fail `BAD_REQUEST` with zero airtime;
multi-byte UTF-8, quote/backslash/newline escapes, and JSON-lookalike
text round-trip byte-identical (firmware `quoted_escaped` passes
validated UTF-8 through; raw non-UTF-8 bytes over USB fail
`BAD_REQUEST` against id 0 with no airtime); blocked contact fails
`CONTACT_BLOCKED` with zero airtime then unblocks clean; 5-message burst
ACKs each with exact-once (C, contact 2) delivery in send order, no
duplicates/wrong recipients; parser still healthy after hostile inputs.
Radios stay ON for follow-up manual RF.

Retry posture is MAX_TX=3 with 12 s ACK waits, CAD-gated at +2 dBm --
adequate, no extra layers added.
Preconditions for all three: firmware flashed, antennas fitted, 1–3 m
spacing. **Hardware warnings (user-reported): one node has a homemade
cable antenna — expect it may fail; none of the radio-side solder joints
are trusted.** Before any TX: visually inspect every radio joint for
bridges/cold joints, multimeter-check continuity end-to-end per the plan
table, confirm no 3V3-to-GND short, and confirm an antenna is fitted on
every radio that will transmit. Never transmit without an antenna. Mark
which physical node (A/B/C) carries the homemade antenna and keep that
label in all results so a failure isolates to antenna vs wiring vs code.
The scripts send no RF beyond the firmware's own USB ops
(`status`, `time_set`, `radio_set`, `contacts`, `send`, `block`/`unblock`);
they never flash, reboot, or power-cycle hardware, and never pair or
delete contacts.

## 1. Smoke (USB alive on every node?)

```sh
python3 scripts/radio_smoke.py --ports "$A" "$B" "$C"
```

Mandatory per port: `{id,op:status}` replies with matching id, all required
fields (`board`, `firmware_version`, `image`, `provisioned`,
`radio_enabled`, `tx_power_dbm`, `rf_profile`, `counters`),
`tx_power_dbm == 2`, `rf_profile == 915000000/SF7/BW500/CR4-5/pre8/CRC/sync12`,
all seven counters present as integers, `radio_version == 0x12` (SX1276
`RegVersion`), plus a `time_status` reply. A radio-free image
(`image == "radio-free"` or `radio_available == false`, or
`RADIO_UNAVAILABLE`) FAILs here with a clear no-RF-hardware message: these
scripts cannot pass without RF hardware and never pass implicitly.

## 2. Link (each direction carries traffic?)

Default is the plaintext-lab `ping` (`--count` must be 1-3, rejected
otherwise):

```sh
python3 scripts/radio_link.py --tx "$A" --rx "$B" "$C" --count 1
python3 scripts/radio_link.py --tx "$B" --rx "$A" "$C" --count 1
python3 scripts/radio_link.py --tx "$C" --rx "$A" "$B" --count 1
```

Text-message variant (lab address shown; use `--contact-id N` once paired):

```sh
python3 scripts/radio_link.py --tx "$A" --rx "$C" \
  --text "A to C through B" --lab-address 3
```

Listener discipline: RX threads start and settle 0.5 s *before* TX, and the
default 50 s window covers the firmware retry budget (3 x 12 s ACK waits +
margin); `--window`/`--tx-timeout` below 40 s are rejected. PASS per
direction = exactly one matching `{"event":"received"}` (same packet/text;
ping additionally requires the pong count to equal `--count`) AND the TX
reply ok (`ping`) or `ACKNOWLEDGED` (`send`). Zero/duplicates/unrelated-only
receipts, and `UNCONFIRMED`, are FAIL. `RADIO_UNAVAILABLE` FAILs clearly.

## 3. Silence (idle network stays quiet?)

```sh
python3 scripts/radio_silence.py --ports "$A" "$B" "$C" --minutes 10
python3 scripts/radio_silence.py --ports "$A" --seconds 30  # quick check
```

Snapshots `status` counters (`tx_attempts`/`tx_ok`/`forwards`) with strict
presence/integer checks (a missing counter key FAILs instead of defaulting),
waits with a countdown, re-reads. PASS only if unchanged — there is no
heartbeat, so any delta is a FAIL with the moved counters printed. A
radio-free image (`RADIO_UNAVAILABLE`) FAILs clearly: no-radio silence is
not RF proof.

## Interpreting results

- Every script prints per-device `PASS`/`FAIL` lines plus a summary
  (`SMOKE: n/m PASS`), and exits 0 iff all pass.
- Missing/unresponsive ports FAIL fast with a hint instead of hanging:
  every read uses a short timeout.

## Troubleshooting

- **No serial after flashing**: confirm the CDC device enumerated (not the
  BOOTSEL volume), the USB task is running in the flashed image, a data
  cable is used, and host serial permissions are right (dialout/uucp group
  or udev rule). BOOTSEL remains the recovery path.
- **Radio version reads 0x00/0xFF**: power off and check wiring (physical
  pin numbers, common ground, VIN, CS, MISO) — not RF settings.
- **`UNCONFIRMED` on link test**: check `radio on`, antennas, spacing,
  and (for relayed paths) the middle node's relay state.

## When to run together

These scripts are ready to run on go-ahead when all boards are plugged in.
Tell the assistant when all three are connected and which ports are A/B/C,
and run the smoke → link → silence sequence together.
