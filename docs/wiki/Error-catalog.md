# Error catalog

Exact strings — match on these, never on prose.

| Error | Meaning | Fix |
|---|---|---|
| `ACKNOWLEDGED` / `UNCONFIRMED` | send delivered / retries exhausted (not errors, `result.status`) | `UNCONFIRMED`: peer off, route down, relay missing, clock off |
| `BAD_REQUEST` | shape wrong: bad contact_id/text/record/slot | check slot present, text 1–160 UTF-8, record canonical |
| `BUSY` | one in-flight DATA per contact already | wait for ACK/timeout |
| `CHANNEL_BUSY` | radio command queue full (cap 8) | back off, retry |
| `CONTACT_BLOCKED` | slot blocked (send-side and TX-gate) | `unblock NAME` |
| `TIME_UNSET` | clock never set since boot | `time set --utc now` |
| `TIME_ROLLBACK` | new time below TX max or anchor | set correct UTC; never move backwards |
| `STORAGE_FAULT` | record unreadable; endpoint disabled | fresh pair/reset — keys never quietly regenerated |
| `UNPROVISIONED` | erased flash, no identity | `provision --label` |
| `RADIO_MUST_BE_OFF` | pairing op with radio on | `radio off` first |
| `RADIO_UNAVAILABLE` | radio-free image asked for RF | flash radio-secure image |
| `UNKNOWN_OP` | no such op | check spelling |
| `LINE_TOO_LONG` | >1024 B command line, discarded | shorten; parser already resynced |
| `ALREADY_PROVISIONED` | provision twice | — |
| `PORT_BUSY` | another process owns the port | stop app/chat/listen first |
| `NoSlot` → `BAD_REQUEST` | store full (16/16) | `contact-delete` a slot |
| `PairingAbsent`/`PairingExpired` → `BAD_REQUEST` | no/old pending attempt | fresh `pair offer`, import within 10 min |

## Exit codes (meshctl)

- `0` — success (`ACKNOWLEDGED` / command ok).
- `1` — local error, firmware `ok:false`, timeout, `PORT_BUSY`, invalid QR,
  `UNCONFIRMED`.
- `2` — CLI usage (argparse).
