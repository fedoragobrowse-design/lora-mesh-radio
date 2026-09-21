# Project Background: Off-Grid LoRa Mesh (Plan Mode Briefing)

You are entering plan mode on a hardware + firmware project. Read the attached
files before proposing a plan:

- `LoRa_Mesh_Project_Outline.docx` — the full design spec (24 pages). This is
  the source of truth for architecture, security design, and rationale. Read
  it in full before planning; do not skim only headings, since several
  sections record *why* a simpler-looking alternative was rejected.
- `LoRa_Mesh_Complete_BOM.xlsx` — full parts list including optional
  GPS/UWB additions for a later integration phase.
- `LoRa_Mesh_Adafruit_BOM.xlsx` — a leaner BOM split into "Essentials"
  (everything needed for a working 3-node mesh) and "Extras" (optional,
  cheapest-viable parts prioritized). Treat Essentials as the actual v1
  scope; Extras are future phases, not part of the initial build.

## One-paragraph summary

A from-scratch, off-grid, decentralized, end-to-end encrypted text-messaging
system over LoRa radios. Three physical nodes (1x Adafruit Feather RP2040
RFM95 + 2x Raspberry Pi Pico 2 W with RFM95W LoRa breakouts) form a mesh:
every node can relay for every other node, no internet/cell/server involved.
The defining principle is **zero trust in relays** — every intermediate node
is assumed hostile. Messages are encrypted end-to-end so relays can route
without ever being able to read content, and sender/receiver addresses
rotate hourly (keyed to a shared secret established via an in-person QR
handshake) so relays cannot link who is talking to whom over time.

## Hardware

- 3x SX1276-based LoRa radios (RFM95W chip family), US 915 MHz ISM band,
  unlicensed under FCC Part 15.
- MCUs: 1x Feather RP2040 (LoRa radio integrated on-board, headless — no
  screen, debug via USB serial + onboard LED), 2x Raspberry Pi Pico 2 W
  (RP2350, wired to a separate RFM95W breakout over SPI on a breadboard).
- Optional (Extras tier, later phase): GPS modules on each fixed node (for
  anchor-coordinate fixing and clock accuracy), and a Makerfabs ESP32 UWB
  DW3000 module per node (centimeter-precision ranging) — both tied to a
  separate "wallet tracker" project that reuses these same 3 nodes as fixed
  anchors. Do not build these into v1 firmware; the outline's §12 documents
  the integration but it is future scope.

## Software architecture (already decided — do not re-litigate without cause)

- **On-chip firmware: Rust + Embassy (async, no_std).** Chosen because it
  avoids GC pauses that could land inside a radio timing window, and because
  audited cryptography crates are available in this ecosystem. This is
  non-negotiable for anything that touches the radio directly.
- **Cryptography: ChaCha20-Poly1305 (RustCrypto crate), not AES-GCM.**
  Deliberately chosen over AES-GCM because the RP2040/RP2350 has no AES
  hardware acceleration, and a software AES-GCM implementation on this
  silicon is slower and harder to make constant-time (timing side-channel
  risk). ChaCha20 was designed for exactly this case. Do not substitute
  AES-GCM without a strong reason, and if you do, flag the constant-time
  concern explicitly.
- **Host-side logic (if a node has an attached computer): Python.**
  Contact list, message history, QR handshake UI, orchestration — anything
  NOT running directly on the microcontroller and NOT touching the radio.
  Never put encryption/decryption in the Python layer even on host-attached
  nodes — some nodes are bare microcontrollers with no host, so crypto must
  live in firmware regardless, and having two crypto implementations that
  must match byte-for-byte is a real risk. Keep ChaCha20-Poly1305 as the
  single implementation, in Rust, used by every node.

## Design principles to preserve in any plan

1. **Frame format (Layer 2)**: plaintext routing header (rotating To/From
   addresses, packet ID, hop limit, payload length, error check) wraps an
   opaque encrypted payload. Relays route on the header; they never decrypt
   the payload. See outline §5.
2. **Rotating addresses**: `rotating_address = shorten(hash(burned_in_serial
   + shared_random_32B + current_hour))`. The random component is FIXED and
   secret (shared once via QR handshake); only the hour changes. Do not
   redesign this to send fresh randomness per-message — that leaks the
   rotation input to relays and defeats the whole scheme. See outline §8.
3. **Handshake**: QR-code public key exchange done in person (never over
   radio), followed by challenge-response (nonce-based) to prove private-key
   possession before either side trusts the other. See outline §6.
4. **Mesh relaying**: managed flooding with listen-before-rebroadcast
   (duplicate suppression via packet ID) plus Channel Activity Detection
   (CSMA/CA) before any transmit, to avoid self-collisions between the 3
   nodes. SNR-weighted rebroadcast timing is a nice-to-have refinement, not
   required for v1. See outline §7.
5. **No global ban system, no automatic beaconing** — both were deliberately
   rejected as incompatible with the privacy/decentralization goals. Per-
   device local blocking is in scope; network-wide moderation is not. See
   outline §9–§10.
6. **Known open gaps — do not silently "fix" these without flagging it**:
   no store-and-forward for offline contacts (messages simply fail after a
   few retries if the recipient is unreachable), and node clock drift during
   long power-off periods needs an RTC or GPS to stay accurate for address
   rotation to keep working. See outline §5.1, §8.4, §14 (Risks).

## What plan mode should produce

A phased implementation plan following the outline's roadmap (§3):
Phase 0 (radio bring-up) → Phase 1 (plaintext 2-node messaging + frame
format) → Phase 2 (encryption + handshake) → Phase 3 (3-node mesh relay) →
Phase 4 (rotating addresses) → Phase 5 (blocking + field polish). Do not
skip ahead to later phases before earlier ones are demonstrably working —
each phase has an explicit milestone in the outline; use those as your
Definition of Done per phase.

If anything in the outline seems contradictory or underspecified once you
dig into implementation details, surface it as a question rather than
silently choosing an interpretation — several design decisions here were
deliberately debated and rejected alternatives are recorded for a reason.
