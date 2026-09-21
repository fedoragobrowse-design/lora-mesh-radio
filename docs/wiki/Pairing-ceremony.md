# Pairing ceremony

In-person only. Both operators present, both boards `radio off`, QR PNGs
(or local file transfer) + fingerprints compared **aloud**. Nothing travels
over RF. One pending attempt per board; 10-minute expiry; abort restarts
with fresh offers. Replacing a slot needs explicit `--replace`.

## Record shapes (`LMESH1:` + unpadded base64url, strict canonical)

| Record | Type byte | Length | Contents |
|---|---|---|---|
| offer | `0x01` | 98 B | ver(1) + Ed25519 pub(32) + X25519 eph pub(32) + challenge(32) |
| proof | `0x02` | 122 B | T(32) + role(1) + ct/tag(24) + Ed25519 sig(64) |
| confirmation | `0x03` | 66 B | T(32) + role(1) + HMAC(32) |

Host validation rejects: wrong prefix, padding, illegal charset,
non-canonical trailing bits, wrong length/type, offer ver ≠ 1, role ∉ {0,1}.
Invalid records never mutate contacts.

## Cryptography (all in firmware; host only transports bytes)

- X25519 ECDH (contributory check; all-zero secret rejected) →
  pair root = HKDF-SHA256(salt=`T`, input=DH, info `LMESH-root-v1`).
- `T` = `SHA256("LMESH-PAIR-v1" || L || R)` over the two 97-byte offer
  payloads ordered by Ed25519 key. Smaller key plays role L.
- Setup keys `LMESH-setup-LR/RL-v1`; proof encrypts each board's 8-byte
  flash UID identity, signed `Ed25519("LMESH-proof-v1" || T || role || ct)`.
- Confirmation = `HMAC(confirm-key, "LMESH-confirm-v1" || T || role || digest)`
  over both proofs (L first).
- Roles select directional traffic keys `LMESH-traffic-LR/RL-v1` →
  hourly keys → 4-byte aliases (`LMESH-address-v1`).

## Steps (A↔B example)

```sh
# both boards, radio off first
meshctl --port $A radio off
meshctl --port $B radio off
# 1. offers
meshctl --port $A pair offer --out offer-A.png
meshctl --port $B pair offer --out offer-B.png
meshctl --port $B pair import --file offer-A.png --name alice
meshctl --port $A pair import --file offer-B.png --name bob
# compare the two transcript fingerprints aloud; abort on mismatch
# 2. proofs
meshctl --port $A pair proof --out proof-A.png
meshctl --port $B pair proof --out proof-B.png
meshctl --port $B pair import --file proof-A.png --name alice
meshctl --port $A pair import --file proof-B.png --name bob
# 3. confirmations (activates the contact slot)
meshctl --port $A pair confirm --out confirm-A.png
meshctl --port $B pair confirm --out confirm-B.png
meshctl --port $B pair import --file confirm-A.png --name alice
meshctl --port $A pair import --file confirm-B.png --name bob
# → "activated as id N" on both ends
```

`pair_import` returns progress + fingerprint; `contact_id` appears only on
activation. Names are arbitrary local labels (`--name alice`), never
transmitted, never trusted as identity. Duplicate signing identities and
self-pairing are rejected. Full store → `NoSlot`/`BAD_REQUEST` until
`contact-delete` frees a slot.
