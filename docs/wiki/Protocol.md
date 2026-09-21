# Protocol

## Frame (≤255 B on air, CRC-16/CCITT-FALSE)

```
ver(1) flags(1) dst(4) src(4) pkt_id(4) hops(1) epoch(4) seq(8) body_len(1) body(var) crc16(2)
```

- `ver`: 0 = plaintext lab, 1 = secure. Unknown → `UnknownVersion`.
- `flags`: only `WANT_ACK=0x01` valid; DATA requires it, ACK requires zero.
- `hops`: mesh images use 1, direct-test 0; >1 rejected. Relays forward
  `hops==1`→0 with recomputed CRC, all else untouched.
- `body_len` at offset 27 includes the 16-byte auth tag in secure mode.
- Bodies: `0x01 || UTF8(text)` DATA (1–160 B); `0x02 || epoch:u32 ||
  seq:u64 || pkt_id:u32` ACK (exactly 17 B). Secure DATA max 207 B total;
  secure ACK 63 B. No broadcast, no fragmentation.

Secure bodies stay opaque through `decode_frame` — endpoints authenticate,
then `validate_body` on the decrypted bytes.

## Key hierarchy (HKDF-SHA256 throughout)

```
X25519 ECDH ──salt=T──▶ pair root ("LMESH-root-v1")
  ├─ setup LR/RL ──▶ proofs (UID identities, Ed25519-signed)
  ├─ confirm key ──▶ mutual confirmation HMACs
  ├─ traffic LR/RL ──▶ hourly keys ("LMESH-hour-v1" || epoch)
  │     └─ address secret ──▶ 4-byte aliases ("LMESH-addr-v1", HMAC)
  └─ persisted per contact (root + peer keys + windows)
```

- Nonce: `epoch_be32 || seq_be64` (deterministic, never reused — reservation
  blocks committed before use, whole last block skipped after reboot).
- AAD: `"LMESH-frame-v1" || header[0..14] || header[15..28]` + body length.
- Aliases are candidate selectors only: every 4-byte match still requires
  AEAD success. Collisions possible; cryptography delivers, not the alias.

## Epochs and replay

- Hour epoch = `floor(unix_seconds / 3600)`; `u64::MAX`-adjacent hours that
  don't fit `u32` are rejected, never wrapped.
- Accept window ±1 hour; ±2 fails closed. Anchors move only with trusted
  local time — never from radio traffic.
- Per contact: 3 epoch slots × (DATA window + ACK window); each window is
  highest-seq + 64-bit bitmap. Duplicates re-ACK, stales drop + count.

## Relay (untrusted, keyless)

- Opaque forward only; endpoints authenticate. Cache key = SHA256 over the
  full immutable envelope (header minus hops/CRC + body) so a forged同-ID
  frame never suppresses an authentic one.
- 64 entries, 8 s TTL from first sight (never extended); 12 s endpoint retry
  outlives the cache so retries still traverse. Forward delay 100–300 ms
  jitter; cancel only on lower-hops duplicate.

## Persistence (V3, 3469 B, one flash page)

`LMSH` magic, version byte, flags, label, UID, clock, `persisted_tx_epoch`,
Ed25519 signing key, then 16 × 213 B contact slots (present/blocked, peer
keys, root, role, `tx_next`/`tx_reserved`, epoch max, anchor, 3× epochs +
DATA/ACK windows). V1/V2 2-slot records migrate via canonical re-encode
(zero-padding would Fault: empty windows encode `e=1`). Version binds to
length — cross-matches are `BadVersion`. Every visible effect commits to
flash **before** it happens; torn writes fail closed, never regenerate keys.
