# Storage layout

Top 64 KiB of the 4 MiB flash (`0x003F0000..0x00400000`); `memory.x` caps
code below it. One async owner, sequential-storage map, single key `0x01`.
Writes awaited, never cancelled. Buffer `PERSIST_LEN + 8`.

```
magic "LMSH"(4) ver(1) flags(1) label(1) uid(8) uid_set(1)
unix_seconds(8) tx_epoch(4) sign_set(1) sign_priv(32)
16 × contact(213 B):
  present(1) blocked(1) ed_peer(32) peer_identity(8) root(32) role(1)
  tx_next(8) tx_reserved(8) tx_epoch_max(4) anchor(4)
  win_epochs 3×u32(12) win_data 3×17 win_ack 3×17
  (window slot: highest u64 + bitmap u64 + empty u8; empty encodes e=1)
```

V3 total: 61 + 16×213 = **3469 B** — fits one 4 KiB erase page with header
room (a 32-slot record would be 6877 B and fail `ItemTooBig`, which is why
capacity is 16). V1/V2 records (2 slots, 487 B) migrate through
`migrate_to_v3` canonical re-encode; version binds to length.

## Durability contract

`Engine::pending_persist` → owner commits → `commit_ok` → only then the
frame/event leaves. Nonce blocks reserved before use (32 at a time, whole
last block skipped after reboot); RX/ACK commits precede delivery; contact
activation clears pending secrets after commit. Interrupted writes can never
reuse a nonce, clear a window, or resurrect a slot.

Cold boot: clock unset (stored seconds are a rollback floor only), radio
off, arm flag consumed once. Unknown magic/version → `Fault` (secure ops
disabled); erased → `Unprovisioned`. Never quiet key regeneration.
