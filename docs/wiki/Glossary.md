# Glossary

- **A/B/C** — operator labels for the three physical nodes. Local only.
- **`contact_id` (1–16)** — firmware slot number. Stable per pairing.
- **Contact name** — arbitrary local label (`alice`); never transmitted.
- **Fingerprint** — first 16 hex of the peer-key hash; compared aloud.
- **`T` (transcript)** — `SHA256("LMESH-PAIR-v1" || L || R)`; the pairing's
  shared fingerprint source.
- **Role L/R** — smaller/larger Ed25519 key; selects directional keys.
- **Epoch** — UTC hour number; rotates addresses + keys.
- **Alias** — 4-byte hourly address; candidate selector, not identity.
- **Nonce** — `epoch||seq`; reserved in flash before use, never reused.
- **Replay window** — highest-seq + 64-bit bitmap per (contact, epoch, kind).
- **Anchor** — persisted receive-epoch floor; trusted time only.
- **`LMESH1:`** — QR/file transport prefix + unpadded base64url record.
- **CAD** — channel-activity detection before every TX.
- **ACKNOWLEDGED / UNCONFIRMED** — send delivered / retries exhausted.
- **BOOTSEL** — RP2350 mass-storage flash mode (button + USB plug).
- **Radio-secure / radio-free** — `--features radio` on/off firmware images.
- **`PORT_BUSY`** — another process owns the serial port.
- **V3** — persist encoding, 16 slots, 3469 B. V1/V2 = 2-slot predecessors.
