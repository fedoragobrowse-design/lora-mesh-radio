# Private 3-node LoRa mesh (Pico 2 W + RFM95W)

**Start here if you're new:** [How the mesh works](docs/how-it-works.html) —
plain-language tour of the whole project, no crypto or embedded background
needed. The one-page trust model is at the top; read that before buying parts.

**Easiest install:** [Web installer](web-installer/README.md) — pick the
`radio-secure` release, download the SHA-256-verified UF2, drag it onto the
`RPI-RP2` BOOTSEL drive. No Rust toolchain, no `sudo`. (Button-hold BOOTSEL
for now; a `reboot --bootsel` USB op is in tree, pending a reflash to reach
boards.)

## What this is

Three Raspberry Pi Pico 2 W boards + three SX1276 radio breakouts, speaking
an encrypted private protocol at 915 MHz. Messages are end-to-end encrypted
per contact pair (X25519 + hourly ChaCha20-Poly1305), relays forward without
holding keys, every transmission is +2 dBm (the radio's minimum).

## What this deliberately is not

Read this **before** buying parts — these are principled design choices, not
missing features:

- **No phone app.** You chat from a USB-connected computer (`meshctl`/chat).
- **No groups, no GPS, no Bluetooth.** Direct paired messages only.
- **No store-and-forward.** A message to an offline peer fails; nothing waits.
- **Short range on purpose.** +2 dBm reaches dozens of meters, not kilometers.
  If you want multi-km Meshtastic-style range, this project is not for you.
- **One board joins.** You need one board to talk to other people's boards.
  Three is only for testing relay behavior by yourself.
- **Through-hole soldering required** (radio breakout headers), plus basic
  comfort with a terminal. No soldering iron, no mesh.

If any of that is the thing you actually wanted, stop here — no hard feelings.

## Cost & commitment (honest version)

- 1 board + breakout + antenna to join; 3 of each to test relaying solo
  (plus a soldering iron if needed). Budget real money and a weekend;
  compare with one pre-assembled Meshtastic board that chats in an
  afternoon, and decide which project matches your goal.
- First payoff is fast (plug in → `status` answers in seconds), but the real
  ceremony — in-person QR pairing with fingerprint comparison, radios off —
  comes before your first encrypted message. That's the security design.

## Reference

Full protocol reference: [Meshtastic compatibility](docs/meshtastic-compat.md)
(decode-only, physics verdict: needs a second radio).
Hardware + wiring: `node-wiring.svg`.

## Quick start (owners)

```sh
# 1. Flash each board (web installer above, or BOOTSEL drag-drop).
# 2. One terminal per board:
python3 -m meshctl --port /dev/ttyACM0 status
# 3. Pair two boards in person (radios off), then:
python3 -m meshctl --port /dev/ttyACM0 radio on
python3 -m meshctl --port /dev/ttyACM0 send --contact B --text "hi"
```

Reference: [Meshtastic compatibility](docs/meshtastic-compat.md),
`node-wiring.svg`, `three-pico-lora-plan.md`.
Command help: `python3 -m meshctl --help`.

## Safety (standard RF due diligence, not danger)

- Always attach the antenna before transmitting — the radio firmware refuses
  to TX on the diagnostic image, but a secure image with no antenna can damage
  the power amplifier. Tug-test the U.FL connector.
- +2 dBm at 915 MHz with the stock antenna is the radio's quietest setting;
  this is not a substitute for calibrated measurement or certification if you
  modify the RF path. Unmodified, it's the same band/power class as countless
  hobby devices.

## Status & proof

Live-tested: 3 boards, all six directed links ACK, encrypted sends confirmed,
SX1276 v18 at +2 dBm SF7/BW500. See `docs/how-it-works.html` § proof.
Known limitations (audited, not hidden): flash secrets in plaintext
(physical possession = game over), no forward secrecy on hourly keys, host
message history in plaintext SQLite. Details in the trust model section.

Photos/video of the assembled boards: **TODO (owner action item)** — the
single most trust-building artifact still missing.
