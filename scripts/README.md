# Radio test scripts

Run order: **regression first** (automated health + pairwise RF + known-gap
assertions + silence), then the single-purpose scripts below for focused
diagnosis. Set `$A` `$B` `$C` to the stable serial paths of the three
labelled boards first (e.g. `A=/dev/ttyACM0`). Scripts take explicit ports
only — no hardcoded `/dev/ttyACM0` assumptions.

## 0. Regression (automated three-node pass)

```sh
.venv/bin/python scripts/mesh_regression.py
```

No port arguments: boards are discovered by USB VID:PID and identified by
USB serial → label via matched-ID `status` (never ACM numbers). One held
`SerialSession` per port for the whole run. Asserts: all three present,
radio-secure, SX1276 `0x12`, provisioned + clock valid; slot-present gate
before every send; B→C, C→B, A→B encrypted sends each `ACKNOWLEDGED` with
the peer's `received` text intact and TX attempts within the retry budget
(1–3); A→C empty slot fails `BAD_REQUEST` with zero airtime (known firmware
gap: no contact-eviction op, C 2/2 full); radios off + settled, then a quiet
window moves no counters. Exits 0 on `REGRESSION: PASS`, 1 on first failure
set. Radios are left OFF; re-enable per board before further manual RF.

## 0b. Adversarial (limits, hostile text, protocol abuse)

```sh
.venv/bin/python scripts/mesh_adversarial.py
```

Directed B→C with A radio-off (no relay skew). Asserts: 1-char and 160-char
boundary sends deliver byte-intact; empty/161-char/invalid contacts/blocked
contact fail with the exact error and zero airtime; multi-byte UTF-8, quote/
backslash/newline escapes, and JSON-lookalike text round-trip byte-identical
(firmware `quoted_escaped` passes validated UTF-8 through; raw non-UTF-8
bytes over USB fail `BAD_REQUEST` against id 0 with no airtime); 5-message
burst ACKs in order with intact texts. Radios stay ON for follow-up manual
RF. Verified 2026-09-21: `ADVERSARIAL: PASS`, `REGRESSION: PASS`.

Known firmware gaps (do not re-probe blindly): no contact-eviction USB op,
so A↔C cannot pair while C holds 2/2 contacts (A slot 2 empty,
`BAD_REQUEST`); retry posture is MAX_TX=3 with 12 s ACK waits, CAD-gated at
+2 dBm — adequate, no extra layers added.
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
(`status`, `time_status`, lab `ping`/`send`); they never flash, reboot, or
power-cycle hardware.

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
