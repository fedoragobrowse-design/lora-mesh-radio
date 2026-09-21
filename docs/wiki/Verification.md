# Verification

Run in order. Regression first; the focused scripts diagnose what it flags.

## 1. Host + firmware unit tests (no hardware)

```sh
cargo test -p mesh-core -p mesh-node --target x86_64-unknown-linux-gnu
# 60 core (frames, AEAD vectors, pairing codecs, relay, epochs) + 8 node
# (send/ACK, replay restore, V1→V3 + V2→V3 migration, version↔length binding)
.venv/bin/python -m unittest discover -s host/tests
```

## 2. Static image checks (no hardware)

```sh
cargo build -p mesh-firmware --target thumbv8m.main-none-eabihf --features radio --profile release
python3 -m meshctl elf check target/.../release/mesh-firmware   # no .elf suffix!
# PASS entry=0x10000129 reset=… stack=0x20080000 … (top 64KiB untouched)
```

## 3. Three-node RF regression (hardware)

```sh
.venv/bin/python scripts/mesh_regression.py
```

Discovers by VID:PID, identifies serial→label via `status`. Asserts all
three radio-secure SX1276 `0x12` provisioned clock-valid; B→C, C→B, A→B
`ACKNOWLEDGED` with peer text intact, TX within retry budget; A→C empty
slot `BAD_REQUEST` with zero airtime; radios off + quiet window moves no
counters. `REGRESSION: PASS`, radios left OFF.

## 4. Adversarial + focused scripts

```sh
.venv/bin/python scripts/mesh_adversarial.py   # 1/160-char edges, hostile text, burst order
python3 scripts/radio_smoke.py --ports $A $B $C
python3 scripts/radio_link.py --tx $A --rx $B $C --count 1
python3 scripts/radio_silence.py --ports $A $B $C --minutes 10
```

## Proven 2026-09-21

B→C id-ACKNOWLEDGED with `received` text intact; V2→V3 on-board migration
kept both pair fingerprints; 16-slot `contacts` lists all slots. Counters
(`tx_attempts/tx_ok/rx_ok/rx_crc_bad/auth_fail/replay_drop/forwards`) bound
every claim — attempts count own-send + relay + ACK TX; `auth_fail` vs
`rx_ok` separates airtime from auth-drop.
