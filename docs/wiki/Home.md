# Home

Private encrypted LoRa messaging across exactly three Raspberry Pi Pico 2 W
boards + Adafruit RFM95W #3072 breakouts. US 915 MHz, private sync word,
every transmission at +2 dBm. No Meshtastic, no Wi-Fi/Bluetooth, no GPS.

- Code: [lora-mesh-radio](https://github.com/fedoragobrowse-design/lora-mesh-radio)
  (firmware + protocol) and
  [lora-mesh-app](https://github.com/fedoragobrowse-design/lora-mesh-app)
  (host tools).
- Start here: [[Hardware]] → [[Wiring]] → [[Build-and-flash]] →
  [[Pairing-ceremony]] → [[Messaging]] → [[Verification]].
- Reference: [[Protocol]] · [[USB-contract]] · [[Storage-layout]] ·
  [[Error-catalog]] · [[CLI-reference]] · [[Glossary]].

## Choices that shape everything

- **Three nodes, A/B/C.** Operator labels only — never on-air identity.
  Aliases rotate hourly from pair secrets.
- **Host holds no keys.** Python moves opaque `LMESH1:` text; all crypto in Rust.
- **In-person pairing only.** QR PNGs + fingerprint read aloud. Nothing over RF.
- **16 contact slots** (`contact_id` 1–16), persist V3. V1/V2 2-slot records
  migrate on load. Full store pairs nothing new until a slot is deleted
  (`contact-delete`).
- **One in-flight DATA per contact**; second `send` returns `BUSY`.
- **Boards are USB serials, never ACM numbers.** `/dev/ttyACM0` moves;
  `..._SERIAL-if00` does not.
