# USB contract

Newline-delimited UTF-8 JSON, ≤1024 B per command line (overlong →
`LINE_TOO_LONG`, parser resyncs). Every request: integer `id` + string `op`.
Replies echo `id` with `ok` + `result`/`error`. Async records carry `event`.

```json
{"id": 1, "op": "send", "contact_id": 2, "text": "hello"}
{"id": 1, "ok": true, "result": {"status": "ACKNOWLEDGED"}}
{"event": "received", "contact_id": 2, "epoch": 497217, "sequence": 128, "text": "hello"}
{"id": 2, "ok": false, "error": "CONTACT_BLOCKED"}
```

## Ops

| op | params | reply |
|---|---|---|
| `status` | — | board, firmware_version, image, provisioned, label, radio_enabled/available, hardware, radio_version, armed_next_boot, tx_power_dbm, rf_profile, time_valid, epoch, contacts{count,blocked}, 7 counters |
| `contacts` | — | 16 × {contact_id, present, blocked, fingerprint (16 hex of peer-key hash)} |
| `provision` | `label` "A"/"B"/"C" | needs TRNG key from owner loop; `ALREADY_PROVISIONED` if set |
| `time_set` | `unix_seconds` u64 | epoch; rejects rollback below TX max/anchor |
| `time_status` | — | time_valid, unix_seconds, epoch |
| `radio_set` | `enabled` bool | gates policy + barrier; radio-free → `RADIO_UNAVAILABLE` |
| `radio_arm_next_boot` | — | one-shot relay arming, consumed once at boot |
| `ping` | `count` 1–3 | CAD-only liveness (radio image) |
| `send` | `contact_id` u8, `text` | `ACKNOWLEDGED` / `UNCONFIRMED` |
| `block` / `unblock` | `contact_id` | `{blocked:bool}` (+ cancels pending send) |
| `contact_delete` | `contact_id` | `{deleted:true}`; frees slot, syncs policy, barriers |
| `pair_offer` / `pair_proof` / `pair_confirm` | — | `{record_b64:"LMESH1:…"}` (TRNG-backed) |
| `pair_import` | `record_b64`, `replace` | progress + fingerprint; `contact_id` only on activation |

## Rules the host relies on

- Pairing requires radio off (`RADIO_MUST_BE_OFF` otherwise) and never transmits.
- Firmware answers USB while a send awaits its ACK (independent CDC tasks).
- Single-owner ports: second opener gets `PORT_BUSY` (flock).
- Fixed RF constants in every status: `tx_power_dbm: 2`,
  `rf_profile: 915000000/SF7/BW500/CR4-5/pre8/CRC/sync12`.
- `status.contacts` is a count summary; `contacts` lists the slots.
- Event interleave: `received` may arrive mid-exchange; matched by `id`.
