# Three Pico 2 W LoRa nodes — complete build and execution plan

## Context
Build and operate exactly three private LoRa messaging nodes from the user's existing hardware: three Raspberry Pi Pico 2 W boards and three Adafruit RFM95W #3072 breakouts. The Picos are connected to USB but have not been programmed or wired to radios. Execute every core roadmap phase, 0 through 5, with a wiring diagram, assembly instructions, concrete software contracts, and observable acceptance gates.

The user confirmed US operation, a private mesh only, and USB computers for typing/reading messages. The user additionally requires the **lowest supported transmit power**. This is a hard constraint for original messages, acknowledgements, retries, and relaying—not merely a startup default.

The user also requests Git initialization. Initialize the local repository before implementation; do not create a remote or publish private material.

## Grounding and source corrections
All four files were read in full: `PROMPT_FOR_AGENT.md`, `LoRa_Mesh_Project_Outline.docx`, `LoRa_Mesh_Complete_BOM.xlsx`, and `LoRa_Mesh_Adafruit_BOM.xlsx`. No firmware, host application, build configuration, or tests currently exist in this directory. Every implementation path below is a **new proposed path**, not a claim about existing code.

| Source material | How this plan uses it |
|---|---|
| Briefing and outline §§1–10, 13–15 | Preserve Rust/Embassy firmware, firmware-only cryptography, Python host tools, in-person pairing, managed flooding, rotating addresses, blocking, and the six ordered milestones. |
| Both BOMs and outline §4 | Replace the old one-Feather/two-Pico arrangement with three identical Pico 2 W + #3072 nodes. Three external radios, antennas, breadboards, and USB data cables are required. No Feather-specific wiring, charger, or NeoPixel assumptions. |
| Outline §11 | Meshtastic public interoperability is explicitly excluded by the user's selection. No public-mode implementation or public fallback. |
| Outline §12 and BOM extras | GPS, UWB, BLE tracking, wallet integration, anchor positioning, and extra radio hardware are excluded. Wi-Fi/Bluetooth on Pico 2 W remain uninitialized. |
| Outline clock/offline gaps | USB computers set UTC after cold boot. There is no RTC/GPS addition and no store-and-forward service. |
| Outline privacy/security claims | Correct rather than repeat the overclaims listed below. |

Read-only inspection found **two** RP2350 BOOTSEL USB devices (`2e8a:000f`), no USB serial ports, two unmounted boot volumes, and no `picotool`. The user has three boards; identify the third individually instead of assuming a fault or flashing by a stale `/dev/sdX` path. Rust/rustup/cargo and Python 3 are installed; only the native `x86_64-unknown-linux-gnu` Rust target is installed. No hardware was flashed, mounted, rewired, or rebooted during planning.

`git rev-parse --show-toplevel` reported that this directory is not a Git repository and has no enclosing repository. Git initialization is pending execution, not already performed.

Explicit corrections required by a working implementation:
- X25519 needs a private key and the peer's public key; two public keys alone cannot establish a secret. Ed25519 signatures implement the outline's public-key-verifiable challenge response.
- A four-byte packet ID and an expiring relay cache do not provide durable replay protection. Add authenticated sequence numbers and persisted receiver replay state.
- Authenticate immutable routing metadata and ACKs. Do not authenticate a mutable remaining-hop byte as if relays could recompute an endpoint's tag.
- An unpaired relay cannot verify another pair's AEAD tag. It performs bounded structural checks and forwards opaque bytes; endpoints authenticate.
- Rotating addresses remove a permanent address field, not all linkability. Timing, sizes, sequence behavior, RF characteristics, and the three-node topology still leak information. Do not use “the relay cannot link them” as a provable acceptance claim.
- A burned-in serial is an identifier, not a source of secret entropy. Never transmit it over LoRa; derive security from random keys.
- Pico 2 W has no built-in LiPo charger, battery-backed wall clock, keyboard, or display. The user-selected USB host workflow supplies input, output, and time.

## Approach — execute in this order
Each phase depends on the previous phase's gate. Host-independent frame/security code can be developed alongside hardware assembly, but never declare a later phase complete before exercising the earlier one on real radios. Do not substitute simulations for the three-radio milestones.

### First execution action — initialize Git
Run `git init -b main` in the project directory. If a repository has appeared since planning, preserve it and its existing branch/history instead of reinitializing or resetting it. Create `.gitignore` entries for `/target/`, `/.venv/`, `__pycache__/`, `*.py[cod]`, `/.mesh-local/`, and `/host/*.egg-info/`. Put pairing exchange images/records, diagnostic captures, exported identities and plaintext SQLite history beneath `.mesh-local/`; do not ignore `Cargo.lock`, source files, the original DOCX/XLSX handoff files, or the requested wiring diagram. Do not run `git add .`, commit, create a remote or push without a separate request; initializing Git does not authorize publication.

**Gate:** `git rev-parse --show-toplevel` returns this project directory; `git check-ignore .mesh-local/history.sqlite target/debug/example .venv/example` identifies the three private/generated paths. The four original handoff files remain unchanged.


### Step 1 — Inventory, identify, and make the bench safe
1. Label the physical boards and radio assemblies **A**, **B**, and **C**. These are local operator labels, not permanent on-air secure addresses.
2. Set aside one Pico 2 W, one Adafruit #3072, one 915 MHz antenna, one breadboard, and one appropriate USB **data** cable per node. Confirm the Pico's actual connector; official Pico 2 W uses micro-USB, not the Feather's USB-C cable assumed by the BOM. Check whether each board already has soldered headers; do not assume that a Pico 2 W ships with them fitted.
3. Use one matching antenna per radio: the existing 915 MHz spring antenna from the BOM, or the manufacturer's 915 MHz quarter-wave wire construction. Do not attach two antennas to one RF feed. Do not use a 433 MHz antenna. Install antennas before permitting any transmission.
4. Disconnect all power before soldering or moving jumpers. Solder the radio headers and antenna connection, and Pico headers if absent; inspect for bridges and cold joints. Use a ventilated soldering area and a nonconductive work surface.
5. Identify each USB board **one at a time** using BOOTSEL. Record the stable USB identifier/path beside A/B/C; do not rely on `/dev/ttyACM0` always meaning A. Try the third board alone with a known-good data cable and USB port if it does not enumerate. Do not erase or flash an unidentified device.
6. Use USB power only for initial assembly. No raw LiPo-to-GPIO connection, no connection to `3V3_EN`, and no 5 V connection to a Pico GPIO. The radios share ground with their own Pico; there are **no signal wires between nodes**.

**Gate:** three individually identified Pico 2 W boards, three correctly soldered #3072 breakouts with antennas, and no power/ground shorts. Programming may proceed without radios connected; radio transmission may not.

### Step 2 — Wire the same node three times
The authoritative connection list is the table below. It is a **logical wiring diagram**, not a representation of breakout pad order. On a Pico viewed component-side with USB at the top, physical pins 1–20 run down the left and pins 21–40 run up the right. Use the official pinout and printed GPIO labels rather than counting breadboard rows.

The accompanying reviewed vector diagram is [three-pico-lora-wiring.svg](local://three-pico-lora-wiring.svg). Keep the pin table and text diagram below authoritative if the session-local image is unavailable after context reset; recreate the same connections rather than guessing physical pad locations. During execution, save the user-requested diagram as `node-wiring.svg` at the project root.

```text
                       BUILD THREE IDENTICAL COPIES: A, B, C

 USB computer / USB power bank
                │ USB power (and data when attached to a computer)
                ▼
     ┌────────────────────────┐                  ┌─────────────────────────┐
     │ Raspberry Pi Pico 2 W  │                  │ Adafruit RFM95W #3072  │
     │                        │                  │ SX1276 LoRa breakout    │
     │ 3V3 OUT  physical 36   ├──── power ──────►│ VIN                     │
     │ GND      physical 38   ├──── ground ──────┤ GND                     │
     │ GP18     physical 24   ├──── SCK ────────►│ SCK                     │
     │ GP19     physical 25   ├──── MOSI ───────►│ MOSI                    │
     │ GP16     physical 21   │◄─── MISO ───────┤ MISO                    │
     │ GP17     physical 22   ├──── select ─────►│ CS                      │
     │ GP20     physical 26   ├──── reset ──────►│ RST                     │
     │ GP21     physical 27   │◄─── interrupt ──┤ G0 / DIO0               │
     └────────────────────────┘                  │                         │
                                                 │ ANT RF pad ── antenna  │
                                                 └─────────────────────────┘
             No Wi-Fi/Bluetooth setup. No GPS/UWB. No wires between A/B/C.
```

| Pico signal | Physical pin | #3072 connection | Function |
|---|---:|---|---|
| `3V3 OUT` | 36 | `VIN` | Regulated 3.3 V supply into the breakout's supported VIN input. |
| `GND` | 38 | `GND` | Common electrical reference. |
| `GP18` | 24 | `SCK` | SPI0 clock, Pico → radio. |
| `GP19` | 25 | `MOSI` | SPI0 transmit, Pico → radio. |
| `GP16` | 21 | `MISO` | SPI0 receive, radio → Pico. |
| `GP17` | 22 | `CS` | Active-low GPIO chip select. |
| `GP20` | 26 | `RST` | Active-low reset. |
| `GP21` | 27 | `G0` / `DIO0` | Radio interrupt. |

Only **DIO0/G0** is needed. The selected `GenericSx127xInterfaceVariant::new` uses it for RX-done, TX-done and CAD-done; CAD detection flags are read over SPI. Do not wire DIO1, which is unnecessary for this P2P protocol. Leave other unused breakout signals unconnected.

Power/reference details: Adafruit specifies VIN input 3.3–6 V and a supply capable of 150 mA; the Pico 2 W datasheet recommends keeping external 3V3 OUT load below 300 mA. One low-power breakout fits this allowance with no other attached peripherals. Its regulator output may be slightly below 3.3 V when VIN is 3.3 V; measure before diagnosing that normal dropout as a failure. Leave EN unconnected (internally pulled high); there is no need to invent another supply pin. For **SX1276** reset, use the driver's low reset pulse followed by high release. Do not copy the shared RFM69 guide's high-reset/low-run wording onto this different radio.

Assembly order:
1. Place the Pico across the breadboard center trench; ensure opposing pin rows are not shorted together. Place the breakout separately with each header pin in an independent breadboard strip.
2. Connect ground, then 3.3 V, then the six signal connections. Keep SPI wiring short and away from the antenna. If a breadboard rail is split, bridge only the intended same-voltage segments and verify continuity.
3. With power disconnected, check every signal end-to-end and check for a 3.3 V-to-ground short. Do not mistake GPIO number 18 for physical pin 18.
4. Power one node. Measure Pico `3V3 OUT` and the radio supply relative to ground; stop if the voltage is wrong, a component heats unexpectedly, or USB repeatedly disconnects. Do not fix resets by increasing voltage.
5. Disconnect power and repeat for the other two nodes. Start bench radio testing with antennas separated by roughly 1–3 m, not touching; this is a test arrangement, not a medical safe-distance claim.

**Gate:** all three match the table, each powers stably, and antennas are attached. Keep the wiring table embedded in this plan even when an SVG is supplied so the plan remains self-contained.

### Step 3 — Create the firmware and USB host foundation
There is no existing project implementation to extend. Create one small Rust workspace and one Python package; reuse upstream drivers and cryptographic libraries instead of writing replacements.

This table defines the final ownership boundaries, not a requirement to implement every module before the first USB flash. Step 3 establishes the workspace, board, minimal USB/status/provisioning and storage foundation; implement each radio/frame/security/relay behavior only in its phase below. Do not expose commands that return fabricated success before their phase exists.

| Proposed path | Responsibility |
|---|---|
| `Cargo.toml`, `rust-toolchain.toml` | Workspace and pinned compiler/dependency resolution. |
| `crates/mesh-core/src/{frame,security,pairing,relay,clock}.rs` | `no_std`, board-independent protocol and state machines; host-testable without a Pico. |
| `firmware/Cargo.toml`, `firmware/build.rs`, `firmware/memory.x`, `.cargo/config.toml` | RP2350 ARM build, boot metadata, and flash layout. Do not globally force the embedded target for host tests. |
| `firmware/src/{main,board,radio,storage,usb}.rs` | Embassy entry/tasks; fixed wiring; radio ownership; persisted secrets/counters; USB commands. |
| `host/pyproject.toml`, `host/meshctl/{__main__,serial_link,pairing,history}.py` | Python terminal interface, QR handling, contact labels and SQLite message history; no key agreement or message encryption in Python. |
| `crates/mesh-core/tests/` | Behavior tests for malformed frames, authentication, nonce/replay persistence, relay retries and epoch boundaries. |

Build target: `thumbv8m.main-none-eabihf`, RP2350 secure ARM execution, one core. Use `embassy-rp = 0.10.0` with `rp235xa`, `time-driver`, `critical-section-impl`, `executor-thread` and its default secure executable image definition; `embassy-executor = 0.10.0`, `embassy-time = 0.5.1`, `embassy-sync = 0.8.0`, `embassy-usb = 0.6.0`, and `embedded-hal-async = 1.0`. Copy the official RP235x boot/linker structure, not RP2040 boot2. Use the installed stable compiler if it meets these dependencies' MSRVs, then pin its exact version and the resolved Cargo.lock at the first successful build. No probe-rs runner or RTT-only logs: use picotool BOOTSEL flashing and USB CDC.
 
Pin `lora-phy` to git revision `8a7851f775596cd2b1c3075f6c02836cd3d7c6e8` from `https://github.com/lora-rs/lora-rs` (the inspected main revision). This contains SX1276 500 kHz errata fixes absent from older examples. Reuse `Sx127x::new`, `Config { chip: Sx1276, tcxo_used: false, tx_boost: true, rx_boost: false }`, `GenericSx127xInterfaceVariant::new(reset, dio0, None, None)`, and `LoRa::new(kind, false, Delay)`. The `false` private-network selection produces SX127x sync word `0x12`. Use `create_modulation_params(SpreadingFactor::_7, Bandwidth::_500KHz, CodingRate::_4_5, 915_000_000)`, explicit-header CRC-enabled TX/RX packet parameters, `prepare_for_cad`/`cad`, `prepare_for_tx(..., 2, payload)`/`tx`, and continuous receive. Do not use SX1262 register code, LoRaWAN RX windows, or unsupported SX127x duty-cycle receive.

Reuse Embassy `Spi::new` with SPI0, GP18/19/16 and DMA_CH0/1, wrapped in `embedded-hal-bus::spi::ExclusiveDevice` with GP17 CS. Bind the matching DMA interrupts. GPIO reset is GP20 output and IRQ is GP21 input; initialize outputs before enabling the driver. For USB, reuse `embassy_rp::usb::Driver`, `embassy_usb::Builder` and `CdcAcmClass`; upstream RP USB-serial and RP235x USB examples provide these patterns. USB serial uses the flash UID locally to produce stable device paths, never as an RF field.

Use fixed-capacity buffers; RustCrypto `chacha20poly1305` 0.10.1 (`default-features = false`, `AeadInPlace`), HKDF/SHA256/HMAC, and dalek Ed25519/X25519. For entropy use `embassy_rp::trng::Trng::new(p.TRNG, Irqs, trng::Config::default())` with TRNG_IRQ binding and `fill_bytes`; supply key bytes through library constructors rather than assuming incompatible rand_core versions interchange. Never seed keys from timestamps, labels, counters or GPIO. A TRNG initialization/fill failure disables provisioning and secure TX rather than falling back. Enable secret zeroization and disable unnecessary allocating/default features; no OS randomness in firmware.

Reuse `sequential-storage` 8.0.1's map over `embassy_rp::flash::Flash::<Async, 4194304>::new(p.FLASH, p.DMA_CH2, Irqs)` with the appropriate DMA interrupt binding. Reserve flash offsets `0x003F0000..0x00400000` (top 64 KiB of the Pico 2 W's 4 MiB); limit linker FLASH to `0x003F0000` bytes starting at `0x10000000`. Obtain the 8-byte local identity with `blocking_unique_id`. One task owns flash operations; do not cancel in-progress writes, run a second core during erase, or let updates erase this region. Flash pauses/missed receives are handled by bounded retries, not fabricated ACKs. The storage crate's CRC/power-loss recovery is not an anti-rollback or physical-tampering guarantee.

Persistent state: node signing key, private local identity/serial, up to two paired contacts, pair roots, peer identity, blocked flags, transmit reservation state, and replay windows. Up to two contacts is sufficient for every node in this exact three-node network. Use a versioned stored record and atomic contact-state replacement. New erased boards report `UNPROVISIONED`; provision explicitly. Unreadable existing identity/security state reports `STORAGE_FAULT`, disables secure endpoint operation, and requires an explicit fresh pairing/reset workflow—never quietly regenerate keys while retaining old peer relationships. Flash encryption/physical anti-rollback is not claimed.

One async task owns the radio and serializes RX/CAD/TX/reset transitions. USB parsing and endpoint processing communicate with it through bounded Embassy channels; use capacity 8 and return `BUSY` when full. Use 255-byte fixed radio buffers and cap UTF-8 text at **160 bytes**, rejecting oversize input rather than silently truncating or fragmenting it. Keep the radio operational without an attached USB terminal; USB disconnects must not hang the relay.

#### USB contract and operator commands
Expose newline-delimited UTF-8 JSON over USB CDC, at most 1024 bytes per command. Every request carries integer `id` and string `op`; replies carry matching `id`, `ok`, and either `result` or `error`. Asynchronous records use `event`. Discard an overlong line through its newline, report `LINE_TOO_LONG`, and resume. Treat USB as a trusted local administrative channel; do not expose private-key export operations.

USB operations use these exact firmware names/arguments after `id`/`op`: `status`, `contacts`; `provision` (`label` string A/B/C); `time_set` (`unix_seconds` u64); `time_status`; `radio_set` (`enabled` boolean); `radio_arm_next_boot`; `send` (`contact_id` u8 1-2, or lab `lab_address` u32 in plaintext-lab only); `block`/`unblock` (`contact_id` u8); `pair_offer`, `pair_proof`, `pair_confirm`; `pair_import` (`record_b64` unpadded base64url, `replace` boolean default false, plus transitional `lab_address` 1/2/3 required only in phases 2-3 secure images and removed in phase 4). Host names map locally to contact slots; `contacts` returns slot, label hint, signing-key fingerprint and blocked state, never pair roots, private identity bytes or private keys. Lab `ping` uses `count` 1-3 and exists only in `plaintext-lab`.

`pair_*` exports return `result.record_b64`; `pair_import` returns progress, transcript fingerprint, and `contact_id` only on activation. `send` final reply is `{"ok":true,"result":{"status":"ACKNOWLEDGED"}}` or `UNCONFIRMED`; local validation/cancellation returns `ok:false` with the exact error string from this plan (`BUSY`, `CHANNEL_BUSY`, `CONTACT_BLOCKED`, `TIME_UNSET`, `TIME_ROLLBACK`, `STORAGE_FAULT`, `RADIO_MUST_BE_OFF`, `BAD_REQUEST`, `UNKNOWN_OP`, `LINE_TOO_LONG`, `ALREADY_PROVISIONED`). Firmware keeps processing USB while a send awaits ACK. Valid incoming plaintext emits `{"event":"received","contact_id":N,"epoch":E,"sequence":S,"text":"..."}` after replay commit. `listen`/`chat` are host receive-loop modes, not firmware subscriptions. `status.result` contains `board`, `firmware_version`, `image` (`secure` or `plaintext-lab`), `provisioned`, `label`, `radio_enabled`, `armed_next_boot`, `tx_power_dbm` (always 2), `rf_profile` (`915000000/SF7/BW500/CR4-5/pre8/CRC/sync12`), `time_valid`, `epoch`, `contacts` summary, and `counters` (`tx_attempts`, `tx_ok`, `rx_ok`, `rx_crc_bad`, `auth_fail`, `replay_drop`, `forwards`). Malformed/unknown commands return `BAD_REQUEST`/`UNKNOWN_OP` with no state change.

Host CLI maps 1:1 onto those firmware ops in `python -m meshctl --port PORT ...` (`PORT` is the explicit serial path; one process per port):
- `status` -> `status`.
- `provision --label A` -> `provision`; existing state returns `ALREADY_PROVISIONED`.
- `time set` (reads host UTC, sends `time_set`) and `time status` (-> `time_status`).
- `radio on` / `radio off` -> `radio_set enabled true/false`; `radio arm-next-boot` -> `radio_arm_next_boot`. Cold boot default is RF-off except consumed one-shot arming.
- `ping --count 1` (lab only, 1-3) -> lab `ping`.
- `send --contact NAME --text TEXT` -> `send` with host-resolved `contact_id` (or `lab_address` in plaintext-lab); `chat`'s `/to NAME` uses the same resolution. Per-contact host mapping lives in `.mesh-local/host-contacts.json` (port path -> name -> contact_id); firmware slots stay authoritative for trust.
- `listen`, `chat` (with `/to`, `/block`, `/unblock`, `/status`, `/radio off`, `/quit`) are single-owner receive loops; second opener gets `PORT_BUSY`.
- `pair offer --out FILE.png`, `pair proof --out FILE.png`, `pair confirm --out FILE.png`, `pair import --file PEER.png --name NAME [--replace] [--lab-address N]` -> matching `pair_*` ops with decoded `record_b64`; import order is offer, proof, confirmation.
- `contacts`, `block NAME`, `unblock NAME` -> `contacts`, `block`, `unblock` with host-resolved IDs.

Use Python standard-library `argparse`, `json`, `sqlite3`, plus `pyserial`, `zxing-cpp`, Pillow and NumPy for QR image encode/decode. Generate PNG QR images and import scanned/saved PNGs; a camera is optional, not an unlisted required purchase. A direct local file transfer is allowed when both devices are physically present and the two people compare displayed fingerprints. Do not send setup over LoRa or an online QR service. Keep host history in user-only SQLite files; it contains plaintext and is not advertised as encrypted storage. Unknown/invalid QR records cause a visible error and no contact mutation.

### Step 4 — Phase 0: USB first, then radio bring-up
1. Install only the missing build target and chosen flash utility during execution. Use the official `picotool` Linux release or its documented build; verify `picotool version`. No SWD probe is required.
2. Build the minimal USB image, connect only A in BOOTSEL, inspect it with **Pico MCP `pico_status`**, flash with **`pico_flash`**, then inspect the new CDC device with **`pico_serial`**, following the concrete workflow in Verification. Expected: a CDC device appears and `status` returns the correct board/image identity. Repeat separately for B and C. No MicroPython installation, filesystem upload, or REPL is involved.
3. Add SPI0 mode 0 at 1 MHz, reset handling, CS initially high, DIO0 input/interrupt, and SX1276 chip detection. Read `RegVersion` (`0x42`), expecting `0x12` for this chip. `0x00`/`0xFF` means check power, ground, CS and MISO before attempting TX.
4. Configure one common profile: **915,000,000 Hz; SF7; BW500 kHz; coding rate 4/5; explicit header; 8-symbol preamble; hardware CRC enabled; normal IQ; private SX127x sync word 0x12**. BW500 keeps short-message airtime down and avoids casually assuming a stationary BW125 signal meets the US digital-modulation bandwidth rule. This is not a certification claim; see the RF gate below.
5. Set `const TX_POWER_DBM: i32 = 2` in `firmware/src/radio.rs`: **+2 dBm, nominally 1.58 mW**, the SX1276 PA_BOOST minimum used by the RFM95W antenna path. Keep `tx_boost = true`; the generic chip's negative-dBm RFO setting does not drive this module's connected antenna path. Do not use the Adafruit example's +13/+20 dBm, the product-page +5 dBm marketing range, or a requested negative value that the driver silently clamps.
6. All originals, ACKs, retries and forwards call the same private TX routine, which supplies `TX_POWER_DBM` to `prepare_for_tx`. No configurable power parameter or host override is exposed. The inspected driver's +2 dBm path selects PA_BOOST with OutputPower=0 and normal (not +20 dBm) PaDac. Verify emitted SPI register transactions in the driver-level test and report requested power on USB for hardware smoke checks; do not claim those logs are calibrated RF measurements. No continuous-wave/continuous-transmit API is exposed. Driver preparation/TX errors stop the attempt, never trigger an alternative high-power path.
7. Keep CAD before every packet. Manual `ping --count 1` from A must appear at B and C. Repeat with B and C as senders. Use only finite sample counts: three packets per sender for initial confidence, increasing only to diagnose an actual problem.

**RF gate:** verify the actual breakout/module documentation and antenna against applicable US Part 15 technical requirements. §15.247 digital modulation specifies at least 500 kHz measured 6 dB bandwidth; register bandwidth is not a measurement. §15.23's limited home-built authorization exception does not waive technical/interference obligations. If radiating compliance cannot be reasonably established, finish software/SPI/receive-only work and use a properly contained RF test arrangement with suitable RF expertise before outdoor transmission. Do not silently switch to higher power, an amateur-radio encryption workaround, or a different band.

**Gate:** all three pass USB/SPI detection; a manual A `ping` is printed at both B and C; each reverse direction also works; every observed TX preparation reports the same minimum PA setting. At idle, transmit count stays unchanged. Range is whatever this minimum-power configuration provides—not a promised kilometre figure.

Calculated airtime at this fixed profile is approximately **82.0 ms** for the maximum 207-byte secure DATA frame and **29.5 ms** for the 63-byte secure ACK. One DATA plus ACK through one relay totals approximately **223 ms of RF transmission across the three nodes**, excluding retries; CAD/backoff adds latency, not transmit airtime. These are calculated protocol values, not measured power/exposure results.

### Step 5 — Phase 1: plaintext framing and reliable direct chat
Use A/B first. Build this as a clearly marked `plaintext-lab` feature/image and print `INSECURE LAB IMAGE` on USB startup. The secure image must reject plaintext frames rather than downgrade.

Define one compact frame codec; all multibyte integers use **big-endian** order:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Version: `0` plaintext laboratory, `1` secure. |
| 1 | 1 | Flags: bit 0 `WANT_ACK`; other bits must be zero. |
| 2 | 4 | Destination address. |
| 6 | 4 | Source address. |
| 10 | 4 | Random packet ID. |
| 14 | 1 | Remaining relays: only `0` or `1` in this network. |
| 15 | 4 | UTC hour epoch, `floor(unix_seconds / 3600)`; lab may use zero. |
| 19 | 8 | Sequence within this directional contact/epoch. |
| 27 | 1 | Body length including authentication tag in secure mode. |
| 28 | variable | Plaintext lab body or ciphertext followed by its 16-byte tag. |
| final 2 | 2 | CRC-16/CCITT-FALSE of header and body, excluding the CRC itself. |

CRC parameters: polynomial `0x1021`, initial value `0xFFFF`, no reflection, final XOR `0`; `123456789` must produce `0x29B1`. Reject frames under 30 bytes, over 255 bytes, mismatched length, bad CRC, unknown version/flags, invalid hop count, or malformed body before using fields. Hardware CRC and this frame CRC detect corruption; neither authenticates a sender.

Bodies: `0x01 || UTF8(text)` for DATA (1–160 text bytes); `0x02 || referenced_epoch:u32 || referenced_seq:u64 || referenced_packet_id:u32` for ACK. DATA requires `WANT_ACK=1`; ACK requires zero and is never acknowledged. Secure DATA max frame length is **207 bytes**; secure ACK length is **63 bytes**. No broadcast chat or fragmentation is needed for this scope.

Use temporary local fixed addresses A=`1`, B=`2`, C=`3` through phases 1–3. In `plaintext-lab`, `provision --label A|B|C` selects the board's own lab address, and `send --contact A|B|C` / `/to A|B|C` resolves the peer directly without requiring a cryptographic contact. Reject any other name in this lab mode. In secure phases 2–3, names resolve only through paired contacts, whose temporary lab address is selected by the operator during offer import with `--lab-address 1|2|3`; do not trust the peer's host label as identity. Phase 4 removes both fixed-address configuration and `--lab-address` from the final secure image; all aliases then derive from the pair's stored identities/secrets. For direct testing set `remaining_relays=0`; mesh images use 1.

Reliability contract:
- At most one in-flight DATA per contact; a second `send` returns `BUSY`.
- At most **three actual DATA transmissions total**, separated by a 12-second ACK wait after TX completes. Retries send the identical encoded message, including nonce/ciphertext in secure mode. Never encrypt different content under an old sequence number.
- CAD backoff is finite: initial random 20–100 ms, maximum 5 CAD attempts per requested transmission, with backoff capped at 800 ms. If still busy, report `CHANNEL_BUSY`; do not transmit blindly.
- Receiver delivers a given message once and re-ACKs an authenticated retry without delivering it again. Sender reports `ACKNOWLEDGED` only after a matching peer ACK (cryptographically authenticated starting in phase 2). After the third timeout report `UNCONFIRMED`; automatic delivery attempts stop.
- New DATA is not automatically queued for offline delivery. A later operator resend is a new message with a new ID/sequence.

**Gate:** typed A→B and B→A messages work; dropping the first ACK causes a retry but not duplicate display; a powered-off receiver produces bounded attempts and `UNCONFIRMED`; corrupted and oversized frames are rejected. Everything is still explicitly insecure at this milestone.

### Step 6 — Phase 2: pairing, secure storage, and end-to-end encryption
Do this before enabling mesh forwarding. Implement the following concrete security design using vetted primitives; it is an educational protocol, not a claim of a professionally audited messenger.

#### In-person pairing, no on-air key exchange
Use long-term Ed25519 signing identity per Pico and a fresh ephemeral X25519 secret per pairing attempt. Generate all secrets/challenges on the Pico from the hardware RNG. X25519 private material and pair roots never reach Python. Reject non-contributory/all-zero X25519 results. Ed25519 verification uses the library's strict verification operation.

Pairing precondition: complete `radio off` on both participating boards first. Every pairing command rejects an enabled/pending-TX radio with `RADIO_MUST_BE_OFF`; pairing does not restart it automatically. Run `radio on` only after the exchange is complete. Allow only one pending pairing per board; repeated offer export returns the same offer until explicit cancellation or expiry. Base64url uses no padding; the same `LMESH1:` encoding applies to offer, proof and confirmation records.

1. Each Pico produces an offer: protocol version byte `1`, Ed25519 public key (32), ephemeral X25519 public key (32), random challenge (32). QR transport is ASCII `LMESH1:` plus base64url of the binary record, with record type byte `0x01` before the offer. Host displays its fingerprint and QR; the physically present peer imports it. Reject wrong lengths/types, self-pairing, duplicate signing identities, and more than two contacts. Replacing an existing contact requires an explicit `--replace`, not silent overwrite.
2. Order the two offers lexicographically by their Ed25519 public keys; call them L/R. Set `T = SHA256("LMESH-PAIR-v1" || offer_L || offer_R)` over the 97-byte offer payloads, excluding record-type bytes. Both random challenges are included. Derive the pair root with HKDF-SHA256: salt `T`, input the X25519 result, info `"LMESH-root-v1"`, output 32 bytes. All subsequent “derive from root with label” operations mean HKDF-SHA256 with no salt, root as input, that exact label as info, and 32-byte output. Derive directional setup keys with `"LMESH-setup-LR-v1"` and `"LMESH-setup-RL-v1"`.
3. Each Pico encrypts its 8-byte private identity/flash serial under its outgoing setup key using ChaCha20-Poly1305, all-zero 12-byte nonce (one proof only per fresh directional setup key), AAD `T || role_byte` (`0` L, `1` R). It signs `"LMESH-proof-v1" || T || role_byte || ciphertext_and_tag` using Ed25519. QR proof record: type `0x02`, `T` (32), role (1), ciphertext/tag (24), signature (64). Import verifies transcript, role, signature and AEAD before accepting the identity. Repeat exports return the exact original proof; never generate changed plaintext under this setup nonce.
4. Derive a confirmation key with info `"LMESH-confirm-v1"`. Confirmation record: type `0x03`, `T` (32), role (1), HMAC-SHA256 over `"LMESH-confirm-v1" || T || role || SHA256(proof_L || proof_R)`. Exchange over the same physical QR/file channel. A Pico activates the contact only after verifying the peer's proof and confirmation and durably saving state. The host shows the first 16 hex digits of `T` on both sides for human comparison; no automated trust acceptance on mismatch.
5. Pairing attempts expire after 10 minutes of monotonic time. Abort, failure, or restart discards temporary secrets and requires fresh offers. Never resume a partially committed pairing with fabricated proof state. A successful side may resend its saved public confirmation if the final transfer was interrupted; otherwise explicitly replace the contact with a fresh pairing on both sides.

All setup records fit within a single ordinary QR; the radio remains off throughout. Use A/B for the phase-2 milestone. **Before phase 3, pair A/C and B/C in person as well**, so each node has its two peers and the direct secure-link/permutation tests are executable. B holds its own A/B and B/C roots, never the A/C root.

#### Directional keys, deterministic nonces, and replay state
From the pair root derive 32-byte directional roots with HKDF info `"LMESH-traffic-LR-v1"` and `"LMESH-traffic-RL-v1"`, plus a fixed 32-byte pair address secret with `"LMESH-address-v1"`. These are separate uses, not one reused key. Derive each hourly traffic key from its directional root using HKDF-SHA256, no salt, info `"LMESH-hour-v1" || epoch_be32`.

For every newly encrypted DATA or ACK, nonce is `epoch_be32 || sequence_be64`. Sequence starts at zero for a new hour and is shared by outgoing DATA and ACKs within that contact/direction. Before using any sequence, reserve a block of 32 numbers in flash and wait for successful commit; after reboot skip every number in the last reserved block. Never decrease a stored highest transmit epoch, reset counters under an existing key, or permit a counter overflow. Fail with `TIME_ROLLBACK` or `STORAGE_FAULT` instead. Re-pairing creates fresh roots when state must be intentionally discarded. Time is therefore set from USB before encrypted messaging even though fixed addresses remain until phase 4.

AEAD associated data is `"LMESH-frame-v1" || header[0..14] || header[15..28]`; it excludes only the mutable hop byte and the recomputable CRC. It authenticates version, flags, both addresses, packet ID, epoch, sequence and body length. Relays may decrement hops and recompute CRC without holding a key. Tampering with hop count is an availability limitation; honest nodes bound forwarding, cryptography does not make a malicious relay obey TTL.

Receiver keeps **separate DATA and ACK replay windows** per contact for each of the three retained epochs: each window is `(highest_sequence, 64-bit received bitmap)` with an explicit empty state. Select the window only after AEAD authentication and body decoding; outgoing DATA/ACK still share one nonce allocator. This prevents a burst of ACKs from pushing a pending DATA retry out of its receive window. New valid DATA is committed before its receive event or ACK; already-seen authentic DATA may be re-ACKed but not redisplayed. Old/stale frames and forged packets cannot advance state. ACK acceptance also requires the referenced contact/epoch/sequence/packet-ID tuple to match a pending send; an unrelated valid ACK cannot acknowledge another message.

Persist a nondecreasing **receive-window anchor hour** per contact. Its retained slots are anchor−1, anchor, anchor+1. On trusted local hour advance, atomically retain overlapping windows, discard only older slots, persist retirement and the new anchor, and initialize genuinely new slots empty. Reject any clock setting below an existing anchor, including after reboot; corrections within an hour remain allowed. Do not advance this anchor from a received radio epoch. This rule prevents clock rollback from evicting a previously accepted future-hour frame and making it replayable later.

Every newly generated ACK uses the ACK sender's **current trusted local epoch**, newly allocated outgoing sequence/hourly key, fresh packet ID, and that epoch's source/destination aliases (or the temporary fixed aliases in phases 2–3). Only its encrypted reference tuple preserves the DATA's original epoch/sequence/ID. Do not construct a new ACK by copying the DATA's older envelope epoch. Re-ACK an authentic duplicate by creating a fresh ACK through the same allocator; ACKs never request ACKs.

A power cut after committing reception but before USB display can lose the UI event; do not promise crash-proof end-to-end exactly-once delivery or add an offline mailbox. `ACKNOWLEDGED` means the endpoint firmware accepted the message, not that a human read it. The plan protects nonce/replay state against ordinary reboot and interrupted writes; arbitrary flash rollback or extracted keys remain physical-compromise limitations.

**Gate:** paired A/B exchange authenticated ciphertext; no private keys leave the firmware; wrong keys, tampered immutable headers/payloads/tags and forged ACKs fail; unchanged retries deliver once; replay still fails after receiver reboot; transmitter reboot never reuses a key/nonce pair. Secure images reject version-0 plaintext.

### Step 7 — Phase 3: all three nodes relay, without shared contact keys
Every node runs the same peer firmware. “Relay B” describes its role in an A↔C experiment, not a special board type or a central server. Enable `remaining_relays=1` for outgoing mesh DATA and ACKs.

Managed flooding in `mesh-core::relay`:
1. On receive, check frame bounds, version/flags, physical/frame CRC and hop bounds. Try endpoint authentication for all matching local destination/source candidates. Only a successful authentication identifies local delivery/blocking; a truncated-address collision or unavailable local clock must not prevent otherwise valid opaque transit forwarding.
2. Derive a relay-cache key from the immutable header plus a hash of the body, excluding hops/CRC. Include content digest so a forged packet sharing a packet ID does not automatically suppress a different authentic frame.
3. Maintain 64 fixed cache entries expiring **8 seconds after first reception**, with oldest-expiry eviction when full. Duplicate observations do not extend expiration. Cache is for airtime suppression, not replay security. The 12-second endpoint retry interval intentionally outlives it, so a retry can traverse B after a lost DATA or ACK.
4. For a new eligible frame with hops 1, schedule one forward after a random 100–300 ms listen interval. Cancel only if a duplicate with a **lower remaining-hop value** proves another relay already forwarded; a duplicate at the same hop count is not that proof. Mark locally originated frames so an echo is not treated as a new message.
5. Immediately before actual TX perform CAD/backoff through the same minimum-power gate. Decrement hop to 0, recompute frame CRC, leave every ciphertext/tag/immutable byte unchanged, transmit once, and return to receive. Hops 0 frames may be delivered but never forwarded.
6. A successfully recognized endpoint does not also forward that same addressed message. Relays do not emit ACKs on behalf of the destination. Data/ACK priority uses the same bounded queue; prefer locally generated ACKs over queued DATA/forwards without starving already queued work.

CAD reduces collisions but cannot detect every interferer or solve hidden terminals. SNR-weighted delay is deliberately not required: the briefing permits deferring it, and randomized delay is sufficient for these three nodes. Do not add routing beacons, discovery chatter, next-hop tables, or adaptive TX power.

True relay experiment:
```text
Computer A --USB-- Node A  <---LoRa--->  Node B  <---LoRa--->  Node C --USB-- Computer C
                                           |
                                     USB power bank
                 A <---------------- no usable direct RF link ----------------> C
```
Use two complementary evidence runs. First, run all three on USB at the bench and capture B's forwarded immutable payload to prove byte-for-byte forwarding without A/C plaintext. Then perform the genuine out-of-range dependency test below with B on a power bank; A/C host logs and B off/on/off establish the physical path. **Implement `radio arm-next-boot` at this phase**, using the exact one-shot semantics defined in Step 9, before requiring hostless B. Arm B while on USB, transfer it to the bank, and switch it off by unplugging power; another on-cycle requires rearming. Do not claim RAM logs survive that cable-swap power cut, and do not claim to have captured B's physical field packets unless B actually had a USB capture connection. This needs no third computer: one computer suffices for the bench and the user's endpoint computers cover the field run.
- First prove A↔B and B↔C individually work at the minimum power.
- Move/reposition nodes or use existing walls/terrain until A↔C fails with B radio-off, while both B links still work. Keep antennas fitted; never remove an antenna to attenuate a transmitter.
- Turn armed B on and repeat the same A↔C exchange: C delivers once and A receives the matching ACK, proving both directions now work. Correlate this dependency result with the immutable-byte forwarding capture already obtained at the bench; do not claim a field capture from a bank-powered B with no data connection.
- Turn B off again: delivery becomes unconfirmed. Record locations, settings, RSSI/SNR and outcomes. A test-only firmware drop filter is useful for deterministic software tests but is **not** proof of physical range extension.
- Repeat with A or C as the middle relay to demonstrate equal peer capability. If the venue is too small to remove the direct link, report that physical acceptance is pending and use a larger/obstructed permitted test location; do not invent a pass.

**Gate:** a real relay-required A↔C exchange succeeds only with B participating; B has no A/C root and exposes no A/C plaintext. Losing the only relay predictably loses the route. No path redundancy is claimed for three nodes.

### Step 8 — Phase 4: hourly private addresses and honest clock handling
Replace fixed secure addresses with pair-specific derived addresses. Keep fixed A/B/C labels only in local USB/UI configuration.

For pair address secret `S`, node private identity `I` (8 bytes), and hour `E` (big-endian u32), define:
`address(I,S,E) = first_4_bytes(HMAC-SHA256(S, "LMESH-addr-v1" || I || E))`.
Do not reserve a broadcast value; every four-byte output is usable, avoiding a special-case truncation bias. The sender uses its identity for `From` and the peer identity for `To`. A node with two contacts has two pairwise aliases for that hour, not a universal alias shared with everyone. Only the hour changes; the shared secret is not transmitted or refreshed over LoRa.

Cache both identities' aliases for each contact for previous/current/next hour, recomputing only at time changes/epoch boundaries. Check the authenticated epoch and both address fields; address matches are only candidate selection, never proof of identity. If short aliases collide, try each candidate's directional key; reject if none authenticate.

Clock rules:
- Cold boot always starts `TIME_UNSET`; a stored timestamp is not a running RTC. Receive/forward remains possible when radio is enabled, but local secure send/decrypt requires trusted local UTC.
- `time set --utc now` uses the attached computer's clock, then a monotonic elapsed-time reference. It does not require internet on the Pico or the host at message time.
- Refuse changes below any persisted transmit epoch or receive-window anchor; atomically advance anchors/retirement with trusted hour changes. Correct the host time or explicitly establish fresh pair state if an intentionally advanced clock must be reset. Never discard a newer accepted receive slot merely to fit a backward-moving three-hour window.
- Accept incoming current/adjacent-hour frames only; never silently widen beyond ±1 hour or synchronize from unauthenticated radio traffic.
- Keep an in-flight retry's original frame/epoch through its bounded lifetime. A new message after the boundary gets new addresses/hourly key/counter allocation. Therefore a few old-hour packets can remain visible during retries; do not call that a rotation failure.

**Gate:** synthetic boundary tests plus a real-time/USB-driven bench boundary change both address fields for a contact; ±1-hour clocks work, ±2-hour clocks fail closed; a power-cycled endpoint asks for UTC instead of silently using epoch zero; an unsynchronized B still forwards. Capture contains no flash serial, signing key, permanent node label or fixed global address. Report metadata/privacy limitations instead of claiming anonymity.

Accelerated boundary/skew fixtures use laboratory images and disposable pair roots. Do not move a production contact's clock into the future and then reset its persisted counters to recover; use a real hour boundary, or explicitly replace the disposable pair with fresh roots and current time afterward.

### Step 9 — Phase 5: local blocking and lowest-emission field operation
1. Persist a `blocked` flag rather than deleting secrets needed to recognize rotating aliases. Coordinate block completion with the radio owner: cancel that contact's pending send/retry timer and queued endpoint DATA/ACK frames; resolve the pending send as `CONTACT_BLOCKED`. An already-on-air finite frame may finish before block completion; unrelated opaque forwarding continues. Authenticate before attributing an incoming candidate, then drop authentic blocked DATA without display or ACK. Do not let a later ACK complete canceled work. The block survives reboot/hour changes; unblocking never resumes canceled sends, only allows new ones.
2. Blocking a contact is not banning an RF transmitter. A LoRa frame names the original endpoint, not a trustworthy last-hop relay. Continue normal bounded opaque forwarding unless `radio off` is selected; do not claim a block stops jamming, unauthorized overhearing, or B silently refusing to relay.
3. Make USB status the authoritative indication. Pico 2 W's onboard LED is attached to the wireless chip, not the ordinary Pico GPIO25 LED; do not initialize a wireless subsystem solely to blink it. No extra LED/display purchase is necessary for the selected host-attached workflow.
4. `radio off` cancels unsent work and enters radio sleep; if a frame is already on air, wait only for that finite frame's TX completion, then sleep. No pending retry resumes after re-enabling. No periodic test pings, heartbeats, telemetry, background pairing or auto-power probing. Idle receiving/CAD is not an RF transmission.
5. Use USB computers for A/C and an existing USB power bank for B. Implement `radio arm-next-boot`: atomically persist a one-shot boolean and leave the current radio state unchanged. At the next boot, clear and commit the flag **before** enabling RX/relaying; a failed clear leaves RF off. `radio off` also clears any armed flag. Before unplugging B from its computer, run `radio arm-next-boot`, confirm `armed_next_boot=true`, then move it to its power bank. It forwards without UTC; another power cycle returns to RF-off unless explicitly rearmed. This avoids assuming a cable swap preserves power.
6. Mount in nonconductive enclosures with strain relief; keep antenna clear of metal and wiring, keep it attached, and avoid exposed breadboard contacts. Place nodes away from the body using USB cable length if desired; no numerical cancer-safe distance is asserted. Unplug/disable nodes when not testing.
7. Run short field exchanges and record successful/attempted deliveries, retry count, median/max ACK latency, RSSI/SNR, TX time, voltage/reset behavior and locations. Record battery capacity and measured runtime; do not infer runtime from RF output or assume a power bank stays on at low load. If it auto-shuts off, use an existing always-on/low-current-mode supply, not radio beacons as a keep-alive.

**Gate:** blocking persists across hour changes/reboot; unblocking restores messages; idle transmit count remains zero; every TX class uses +2 dBm; one-shot field arming works and fails safely; USB loss does not stop a powered relay; portable operation lasts for the duration actually measured. Standalone typed chat without a USB computer is not promised.

## Verification — commands and required evidence
All commands below are **execution instructions**, not commands already run. Work from the project directory. The new paths and CLI must be implemented as specified before invoking them.

### Preferred Pico MCP workflow
The user explicitly permits Pico MCP. `pico_status` was already used read-only during planning. During execution, use it before and after flashing; do not send a firmware image until only the intended Pico is connected in BOOTSEL. The `pico_flash` schema has no board selector, so physical isolation is mandatory.

1. Invoke `pico_status` with `{}` and confirm the one intended RP2350 boot device. A BOOTSEL device has no application serial port; that is expected.
2. Build the Rust ELF, copy it to `.mesh-local/mesh-firmware.elf`, and resolve that file to an absolute local path. Invoke `pico_flash` with `{"file":"ABSOLUTE_ELF_PATH","wait_seconds":3}` after installing picotool. This tool uses `picotool load -u -v -x`. The uppercase path token is replaced with the result of resolving the built file; it is not a filename to create literally.
3. Invoke `pico_status` again, then use its exact serial port in `pico_serial`: `{"port":"EXPLICIT_SERIAL_PATH","write":"{\"id\":1,\"op\":\"status\"}\n","read_seconds":2,"baud":115200}`. Omit `frame`: this project's USB contract is raw newline JSON, **not** the optional COBS framing mentioned in the tool's general description. Verify JSON reply ID 1, board identity, firmware revision and RF-off status.
4. Release/close any Python listener before MCP serial access. Never let the host application and MCP consume the same serial stream concurrently; use an explicit port when multiple programmed boards are attached.
5. If picotool installation is unavailable, use the verified fallback `cargo install elf2uf2-rs --version 2.2.0 --locked`, mount only the identified RP2350 BOOTSEL volume, then run `elf2uf2-rs deploy --family rp2350-arm-s .mesh-local/mesh-firmware.elf`. This fallback flashes directly rather than through MCP; retain MCP for status/serial afterward. Never use the converter's default RP2040 family. The deployed image is still the same Rust firmware.
6. Do not use `pico_exec`, `pico_file_put`, or MicroPython-oriented filesystem tools for this firmware. The Rust image is the program; USB CDC is the control channel. Manual BOOTSEL remains the recovery path because Embassy does not automatically implement Pico SDK's USB-reset protocol.

The direct picotool commands below are the manual fallback/equivalent, not a requirement to flash every image twice.


### Setup and flashing
```sh
rustup target add thumbv8m.main-none-eabihf
cargo build -p mesh-firmware --release --target thumbv8m.main-none-eabihf
picotool version
picotool info -a
picotool load -v target/thumbv8m.main-none-eabihf/release/mesh-firmware
picotool reboot
python3 -m venv .venv
.venv/bin/python -m pip install -e ./host
.venv/bin/python -m meshctl ports
```
Connect only the intended board in BOOTSEL during `picotool load`/`reboot`. If using UF2 instead, generate it with the official RP2350-capable `picotool uf2 convert` invocation confirmed from that installed version's help, then copy only to the identified RP2350 boot volume; do not use an RP2040-only converter. Do not assume `picotool -f` can reset an Embassy CDC application unless explicit compatible reboot support has been implemented. Manual BOOTSEL is the baseline.

`meshctl ports` lists serial device path, VID/PID and USB serial when available. Set shell variables `A`, `B`, `C` to the actual stable serial paths shown after identifying each physical board. Missing permissions should be reported with the required local USB/serial group/udev fix; do not run the application permanently as root.

```sh
.venv/bin/python -m meshctl --port "$A" status
.venv/bin/python -m meshctl --port "$A" provision --label A
.venv/bin/python -m meshctl --port "$A" time set --utc now
.venv/bin/python -m meshctl --port "$A" radio on
.venv/bin/python -m meshctl --port "$B" listen
```
Repeat provisioning/time/radio setup for each identified board; give each listener its own terminal/process. After pairing, a concrete smoke input is:
```sh
.venv/bin/python -m meshctl --port "$A" send --contact C --text "A to C through B"
```
Expected: C receives the exact text once; A eventually receives `ACKNOWLEDGED`; B logs only forwarding metadata/ciphertext, never that plaintext.

### Behavior tests and hardware evidence
Use `cargo test -p mesh-core --target x86_64-unknown-linux-gnu` for host-side protocol tests. Use an emulated NOR-flash test adapter only to inject deterministic interrupted-write boundaries; real flash/reboot smoke checks remain required. Do not create tests that merely assert source strings, field forwarding, or that mocks were called.

| Check | Concrete input/action | Required observable result |
|---|---|---|
| Node build | Wire each node from the table; query radio version | Three stable USB nodes; SX1276 `0x12`; correct supply readings. |
| Minimum power | Original DATA, ACK, retry, relay and power-cycle recovery | Driver-level SPI trace selects PA_BOOST/OutputPower=0/normal PaDac for each TX class; hardware logs request +2 dBm; no host power override exists. Logs/register transactions are not calibrated radiated-power measurements. |
| Silence | Leave all radios enabled and no user work for 10 minutes | No original/relay transmissions; counters unchanged. No heartbeat. |
| Manual bring-up | One A ping with B/C listening; then reverse senders | Correct short packet appears at both listeners each time. |
| Framing | CRC vector plus truncated/wrong-length/unknown-version frames | Exact CRC vector; deterministic rejection; no panic or oversized allocation. |
| Retry | Drop the first DATA or ACK with a lab-only injector | At most three sends, eventual success when path restored, one UI delivery; relay cache does not swallow all retries. |
| Timeout | Turn recipient off | Finite retries, then `UNCONFIRMED`; no background mailbox/retries. |
| Pairing | Correct QR round trip; altered public key/signature/challenge/proof | Correct peers activate; mismatched/replayed/transcript-swapped records do not; no LoRa TX during pairing. |
| Crypto | Flip one immutable header/ciphertext/tag bit, recomputing frame CRC | AEAD rejection, no display, no false ACK. Hop-only decrement remains decryptable. |
| Nonce persistence | Reset after reserve/before TX, after TX, during next reserve | No repeated `(directional hourly key, nonce)` for distinct plaintext; state faults never reset counters. |
| Replay persistence | Deliver/replay before and after reboot/cache expiry; insert more than 64 valid reverse-direction ACKs while one DATA retry is pending | No repeat application delivery; the DATA retry remains recognizable because ACKs have a separate receive window; bad tags never advance either bitmap. |
| Relay dependency | B off → armed/on → off with A/C unable to hear directly; separate USB bench capture | Unconfirmed → acknowledged → unconfirmed in the field; bench capture proves B forwards A's immutable ciphertext unchanged. |
| Rotation | Cross hour; introduce ±1h then ±2h skew; ACK old-hour DATA after sender has moved to the new hour | Addresses rotate; adjacent-hour receive works; two-hour skew fails; ACK uses its own current epoch but matches the original DATA reference. |
| Address collision | Supply deterministic two-contact collision fixture | Only the correct AEAD key identifies/delivers the message; no wrong-contact attribution. |
| Clock reset | Cold-reboot endpoint; set no time | `TIME_UNSET` blocks endpoint traffic; manual UTC restores it; relay mode still works. |
| Clock rollback | Accept next-hour DATA, reboot, then attempt to set a previous local hour and replay | Time setter rejects backward movement below the persisted anchor; no accepted replay window is lost/re-created. |
| Blocking | Block during an outstanding send/queued ACK, rotate hour, reboot, then send from that contact | Pending endpoint work is canceled with `CONTACT_BLOCKED`; no later retry/receive/ACK; unblock permits a fresh message without resuming canceled work. |
| Radio off/field arming | Arm once, power-cycle twice; disable during queued work | First boot permits relay, second boots RF-off; radio off clears queued retries and armed state, sleeping after any active packet completes. |
| Portable relay | Run B on USB power bank, A/C on computers | Same encrypted exchange without B host; report observed runtime and resets. |

Use separately compiled laboratory fault-injection hooks for dropped ACKs, captured-frame replay, synthetic time and register failures. Never ship raw frame injection, arbitrary time-warp, secrets logging, or plaintext fallback in the secure field image. Record firmware/dependency versions, board labels, RF settings, sample counts and actual outcomes with each phase gate. RF captures can come from B's firmware; a fourth radio, SDR, oscilloscope, or SWD debugger is not required by this plan. A multimeter is needed for meaningful supply/continuity checks; borrow one if it is not among the existing tools.

### Troubleshooting without increasing power
| Symptom | Next action |
|---|---|
| Third Pico missing / no boot drive | Test that board alone with a known-good data cable, hold BOOTSEL while plugging in, inspect with Pico MCP; no application serial is expected yet. |
| No serial after flashing | Verify RP2350 secure-ARM image definition, correct build target, USB task actually running, USB data cable and host permissions. BOOTSEL remains available for recovery. |
| Radio version 0x00/0xFF | Power off; check physical pin numbers, common ground, VIN, CS and MISO. Do not change RF settings or raise voltage/power. |
| Driver waits forever for TX/RX/CAD completion | Check GP21→G0/DIO0, IRQ binding and reset release. Missing IRQ is not a range problem. Bound operations with a local timeout and return a radio error; never add blind automatic retransmit loops. |
| SPI works but no packets | Compare every RF parameter and antenna connection; ensure `radio on`, +2 dBm PA_BOOST path, and matched BW500/SF7/profile. Move nodes closer before changing anything else. |
| Frames arrive but secure text does not | Check pair fingerprint, block state, UTC/epoch window, direction key and AAD/tag error counters. Do not fall back to plaintext. |
| Direct messages work, relay retries fail | Check hop=1, relay radio enabled, 8-second cache versus 12-second retry interval, reverse ACK route, and one-shot arming after a bank power cycle. |
| USB disconnects or power bank turns off | Check shorts, cable and supply stability; use the bank's low-current mode if available. Do not add RF keep-alive beacons. |


## Assumptions and contingencies
- Existing hardware includes three working #3072 radios and 915 MHz antennas as confirmed; no new radio/MCU purchase is planned. If inventory differs, stop at assembly and correct the inventory rather than substituting an electrically different board.
- All boards are Pico 2 W; the USB status only established two present at inspection. If a physical board is not Pico 2 W, use its real board/target rather than flashing the RP2350 image blindly.
- USB computers are trusted endpoints with locally usable clocks. They see typed/received plaintext. Headless means forwarding without a host, not composing messages without input hardware.
- Lowest supported power is mandatory. If the link fails, reposition nodes or shorten the route; do not increase power, add amplifiers, or silently lengthen high-SF airtime. A longer-range profile is not part of this plan.
- The selected RFM95W/SX1276 PA_BOOST minimum is nominal +2 dBm. Actual radiated/conducted power and compliance require suitable measurement to establish. Do not label the system cancer-proof or infer medical safety from configured dBm.
- Firmware upgrades preserve security storage. If an intentional whole-chip reset is necessary, require explicit confirmation, erase relationships, and freshly pair both ends; never restore old keys with reset nonce counters.
- A single relay is a single availability bottleneck. Radio interference, an offline contact, blocking and relay loss can all produce `UNCONFIRMED`; the firmware cannot reliably identify which occurred.

## Primary implementation references
- Project sources: all four files named in Grounding above, with roadmap §3, framing §5, handshake §6, relaying §7, rotation §8 and blocking §10 as the phase anchors.
- Adafruit #3072 product and board guide: https://www.adafruit.com/product/3072 and https://learn.adafruit.com/adafruit-rfm69hcw-and-rfm96-rfm95-rfm98-lora-packet-padio-breakouts
- Pico 2 W schematic/pin table: https://pip-assets.raspberrypi.com/categories/1088-raspberry-pi-pico-2-w/documents/RP-008306-DS-1-pico-2-w-schematic.pdf ; Pico 2 W datasheet: https://pip-assets.raspberrypi.com/categories/1088-raspberry-pi-pico-2-w/documents/RP-008304-DS-3-pico-2-w-datasheet.pdf
- Adafruit power/signal pin definitions and assembly: https://learn.adafruit.com/adafruit-rfm69hcw-and-rfm96-rfm95-rfm98-lora-packet-padio-breakouts/pinouts ; https://learn.adafruit.com/adafruit-rfm69hcw-and-rfm96-rfm95-rfm98-lora-packet-padio-breakouts/assembly
- Semtech PA/reset/LoRa registers: https://cdn-shop.adafruit.com/product-files/3179/sx1276_77_78_79.pdf ; HopeRF module pin/supply specification: https://cdn-learn.adafruit.com/assets/assets/000/031/659/original/RFM95_96_97_98W.pdf
- Verified no-picotool fallback CLI: https://github.com/JoNil/elf2uf2-rs
- Embassy RP235x board/build/USB examples: https://github.com/embassy-rs/embassy/tree/main/examples/rp235x ; CDC pattern: https://github.com/embassy-rs/embassy/blob/main/examples/rp/src/bin/usb_serial.rs
- RP2350 flash and TRNG APIs: https://docs.embassy.dev/embassy-rp/git/rp235xa/embassy_rp/flash/struct.Flash.html ; https://docs.embassy.dev/embassy-rp/git/rp235xa/embassy_rp/trng/index.html
- Pinned radio driver: https://github.com/lora-rs/lora-rs/tree/8a7851f775596cd2b1c3075f6c02836cd3d7c6e8/lora-phy ; public PHY API: https://docs.rs/lora-phy/latest/lora_phy/struct.LoRa.html
- SX1276 PA implementation: https://raw.githubusercontent.com/lora-rs/lora-rs/main/lora-phy/src/sx127x/sx1276.rs
- Official picotool, RP2040/RP2350 flashing and prebuilt tool links: https://github.com/raspberrypi/picotool
- ChaCha20Poly1305 in-place/no_std and security requirements: https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/
- X25519, Ed25519 and HKDF: https://docs.rs/x25519-dalek/latest/x25519_dalek/ ; https://docs.rs/ed25519-dalek/latest/ed25519_dalek/ ; https://docs.rs/hkdf/latest/hkdf/
- Flash journal behavior and limits: https://docs.rs/sequential-storage/latest/sequential_storage/
- QR library support: https://pypi.org/project/zxing-cpp/
- US rules text (Cornell's CFR mirror; direct eCFR access was blocked): https://www.law.cornell.edu/cfr/text/47/15.247 and https://www.law.cornell.edu/cfr/text/47/15.23
