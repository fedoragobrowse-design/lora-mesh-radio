# Messaging

## Preconditions (every send)

```sh
meshctl --port $A provision --label A   # once per board, A/B/C
meshctl --port $A time set --utc now    # cold boot is always TIME_UNSET
meshctl --port $A radio on
meshctl --port $A contacts              # slot present + unblocked?
```

## Send / receive

```sh
meshctl --port $A send --contact alice --text "hello"   # → ACKNOWLEDGED
meshctl --port $B listen                                # prints {"event":"received",...}
meshctl --port $B chat --contact A                      # interactive: /to /block /status /radio off /quit
meshctl tui                                             # all boards at once, Tab cycles
meshchat                                                # Tk three-pane GUI
```

- Text: 1–160 UTF-8 bytes, never truncated; oversize rejected.
- Final reply is `ACKNOWLEDGED` or `UNCONFIRMED` (3 tries × 12 s ACK waits
  exhausted — peer off, route down, relay missing).
- `received` events carry `contact_id`, `epoch`, `sequence`, `text` — after
  the replay commit, delivered exactly once (duplicates re-ACK silently).
- One in-flight DATA per contact; second `send` → `BUSY`.
- `block NAME` / `unblock NAME` gate a slot (blocks cancel pending sends);
  `contact-delete NAME` frees the slot on board + local mapping.

## What happens on air (per DATA)

1. `send_begin`: checks usable/provisioned/clock/slot/blocked/`BUSY`/text
   shape; reserves a 32-sequence nonce block to flash **first**.
2. `send_emit`: encrypts ChaCha20-Poly1305 (nonce = epoch||seq, AAD binds
   header + length) to 4-byte rotating aliases, `hops=1`, CRC-16.
3. Radio: CAD-gated single attempt at +2 dBm per try (≤5 CAD tries, backoff
   to 800 ms); waits 12 s for the ACK; retries byte-identical (`is_retry_echo`,
   never re-encrypts) up to MAX_TX=3.
4. Peer authenticates across 16 contacts × 3 epoch windows, validates the
   decrypted body, checks the replay window, commits, emits `received`,
   returns an authenticated ACK (63 B frame).
5. relays (any third node, `hops==1` only) forward opaque bytes with hops→0
   and recomputed CRC; 64-entry dedup cache, 8 s TTL, 100–300 ms jitter,
   duplicate-with-lower-hops cancels.

## History

Per-board SQLite under `.mesh-local/` (0600, plaintext — convenient, not
secure storage). `meshctl history --port P [--limit N]`.
