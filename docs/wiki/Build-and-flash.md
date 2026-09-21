# Build and flash

## Toolchain

Pinned: Rust 1.98.1 (`rust-toolchain.toml`), target
`thumbv8m.main-none-eabihf` (RP2350 secure ARM, one core),
`embassy-rp 0.10.0` (`rp235xa`, `time-driver`, `critical-section-impl`,
`executor-thread`), `lora-phy` at git rev `8a7851f`.
Host tests build for `x86_64-unknown-linux-gnu` — never force the embedded
target globally.

```sh
rustup target add thumbv8m.main-none-eabihf
```

## Images

| Feature flag | `image` | Behaviour |
|---|---|---|
| default (none) | `radio-free` | No SPI/GPIO init. `radio on`, `ping`, `send` → `RADIO_UNAVAILABLE`. Pairing/contacts/time work. |
| `--features radio` | `radio-secure` | Full SX1276 driver + RX/relay path. This is the field image. |

TRNG: async reads, `sample_count = 200`, all health checks on
(the embassy-rp 0.10.0 default of 25 starves under WFE sleep).

## Build

```sh
cargo test -p mesh-core -p mesh-node --target x86_64-unknown-linux-gnu
cargo build -p mesh-firmware --target thumbv8m.main-none-eabihf --features radio --profile release
```

The real ELF is `target/thumbv8m.main-none-eabihf/release/mesh-firmware`
(**no `.elf` suffix**; a stale `mesh-firmware.elf` from Sep 20 may sit
beside it — check `strings … | grep radio-` reads `radio-secure` and the
mtime is fresh before flashing).

```sh
python3 -m meshctl elf check target/thumbv8m.main-none-eabihf/release/mesh-firmware
# PASS entry=0x10000129 reset=0x10000129 stack=0x20080000 … (top 64KiB untouched)
python3 -m meshctl uf2 target/thumbv8m.main-none-eabihf/release/mesh-firmware --out fw.uf2
```

## Flash (no sudo)

1. Hold the board's BOOTSEL button while plugging USB. It appears as an
   `RP2350` mass-storage volume (by-id shows nothing serial-bearing).
2. `udisksctl mount -b /dev/sda1` (adjust device), then **copy directly**:
   `cp fw.uf2 /run/media/$USER/RP2350/ && sync`. (`meshctl flash` errors
   on AlreadyMounted; direct copy is the reliable path.)
3. The board reboots into the app: CDC serial re-enumerates as
   `usb-mesh_mesh-node_radio-secure_<SERIAL>-if00`.
4. Identify it: `meshctl --port /dev/ttyACMx status` → match label/serial.
   Never flash an unidentified device; never infer identity from ACM number.
