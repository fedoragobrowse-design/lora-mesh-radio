# LoRa Mesh Radio — secure firmware + protocol for 3 private Pico 2 W nodes

Rust/Embassy RP2350 firmware, `no_std` protocol crates, and RF test scripts
for three Raspberry Pi Pico 2 W boards + Adafruit RFM95W #3072 breakouts.
US 915 MHz, private SX127x sync word `0x12`, every TX at **+2 dBm**
(SX1276 PA_BOOST minimum). The Python host tools live in
[`lora-mesh-app`](https://github.com/fedoragobrowse-design/lora-mesh-app).

## Status (2026-09-21, hardware-proven)

- 3 boards on radio-secure V3 (16 contact slots, persist V3, 3469 B record).
- RF proven: B→C `ACKNOWLEDGED` + matching `received`, text intact.
- 60 mesh-core + 8 mesh-node tests green; release ELF static checks PASS.

## Layout

- `crates/mesh-core/` — `no_std` protocol: framing, AEAD/KDF, pairing records,
  relay cache, epoch clock.
- `crates/mesh-node/` — transport-independent secure engine + persist encoding
  (+ `mesh-exerciser` native test harness).
- `firmware/` — Embassy RP2350 app: USB CDC, SX1276 driver, storage owner,
  radio policy gate. Build with `--features radio` for the radio-secure image.
- `scripts/` — RF regression + adversarial + smoke/link/silence harnesses.
- `docs/handoff/` — original handoff files (DOCX/XLSX/images/PDF, unchanged).
- `three-pico-lora-plan.md` — the full approved build plan (406 lines).
- `node-wiring.svg` — Pico ↔ RFM95W wiring diagram.
- `PROMPT_FOR_AGENT.md` — original agent brief.

## Build

```sh
cargo test -p mesh-core -p mesh-node --target x86_64-unknown-linux-gnu
cargo build -p mesh-firmware --target thumbv8m.main-none-eabihf --features radio --profile release
# real ELF output is target/.../release/mesh-firmware (no .elf suffix)
python3 -m meshctl elf check target/thumbv8m.main-none-eabihf/release/mesh-firmware
```

See the [wiki](../../wiki) for the full protocol reference.
