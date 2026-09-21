//! Managed flooding relay (Phase 3).
//!
//! Every node runs the same peer firmware; "relay" is a role in one
//! experiment, not a board type. Relays hold no contact keys: they run
//! bounded structural checks and forward opaque bytes. Endpoints
//! authenticate; cryptography never requires a relay to obey TTL.
//!
//! Rules implemented here:
//! - Relay-cache key covers both immutable header ranges (`frame[0..14]`
//!   and `frame[15..28]`) plus the body, excluding only the mutable hop
//!   byte and the recomputable CRC. Including the
//!   content digest means a forged frame sharing a packet ID does not
//!   suppress a different authentic frame at the cache layer.
//! - Cache entries expire 8 s after FIRST reception; duplicate
//!   observations never extend the lifetime. The 12 s endpoint retry
//!   interval intentionally outlives the cache so a retry can still
//!   traverse a relay after a lost DATA or ACK.
//! - Only `hops == 1` frames are forwarded (decremented to 0, CRC
//!   recomputed, every other byte untouched). A locally originated echo
//!   is never treated as new work, and an endpoint that consumed a frame
//!   does not also forward it.
//! - A pending forward is cancelled only when a duplicate proves another
//!   relay already forwarded — i.e. the duplicate shows a LOWER remaining
//!   hop count. A same-hop duplicate is just an echo, not proof.
//!
//! No RNG in this module: the 100–300 ms jittered listen delay is chosen
//! by the caller (firmware TRNG) and passed in / sanitized here.

use sha2::{Digest, Sha256};

use crate::frame::{crc16, decode_frame, Reject};

/// Number of fixed relay-cache entries.
pub const RELAY_CACHE_SIZE: usize = 64;
/// Cache entry lifetime in milliseconds, measured from first reception.
pub const RELAY_CACHE_TTL_MS: u64 = 8_000;
/// Minimum scheduled forward delay (caller jitter), milliseconds.
pub const FORWARD_DELAY_MIN_MS: u16 = 100;
/// Maximum scheduled forward delay (caller jitter), milliseconds.
pub const FORWARD_DELAY_MAX_MS: u16 = 300;

/// Clamp a caller-chosen forward jitter into the 100–300 ms band.
pub fn sanitize_jitter_ms(jitter_ms: u16) -> u16 {
    if jitter_ms < FORWARD_DELAY_MIN_MS {
        FORWARD_DELAY_MIN_MS
    } else if jitter_ms > FORWARD_DELAY_MAX_MS {
        FORWARD_DELAY_MAX_MS
    } else {
        jitter_ms
    }
}

/// Relay-cache key: `SHA256(header[0..14] || header[15..28] || body)`.
/// The complete immutable envelope distinguishes equal packet IDs, including
/// different epochs/sequences; only hops and CRC are excluded.
pub fn cache_key(header: &[u8; crate::frame::HEADER_LEN], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&header[..14]);
    h.update(&header[15..]);
    h.update(body);
    h.finalize().into()
}

/// Hash a complete header and its already-validated body without copying.
/// Returns `None` when the frame is shorter than the header.
pub fn cache_key_of_frame(frame: &[u8], body: &[u8]) -> Option<[u8; 32]> {
    let header = frame.get(..crate::frame::HEADER_LEN)?.try_into().ok()?;
    Some(cache_key(header, body))
}

/// Result of a cache observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observe {
    /// First reception inside the entry lifetime: eligible for forwarding.
    New,
    /// Already seen and still live: suppress, never extend the expiry.
    Duplicate,
}

#[derive(Clone, Copy)]
struct Entry {
    key: [u8; 32],
    expires_ms: u64,
    occupied: bool,
}

/// Fixed 64-entry airtime-suppression cache.
///
/// This cache is for airtime suppression only, NOT replay security:
/// endpoints keep separate authenticated replay windows. No allocation,
/// no iteration beyond 64 entries.
pub struct RelayCache {
    entries: [Entry; RELAY_CACHE_SIZE],
}

impl RelayCache {
    /// Empty cache. `const` so firmware can place it in static storage.
    pub const fn new() -> Self {
        Self {
            entries: [Entry {
                key: [0u8; 32],
                expires_ms: 0,
                occupied: false,
            }; RELAY_CACHE_SIZE],
        }
    }

    /// Observe a frame key at `now_ms`.
    ///
    /// A live entry with the same key reports [`Observe::Duplicate`] and
    /// keeps its original expiry. Otherwise the key is stored with expiry
    /// `now_ms + RELAY_CACHE_TTL_MS` and [`Observe::New`] is returned.
    /// Expired entries are reclaimed lazily during the scan; when every
    /// slot is live, the entry with the oldest expiry is evicted.
    pub fn observe(&mut self, key: &[u8; 32], now_ms: u64) -> Observe {
        for e in self.entries.iter_mut() {
            if !e.occupied {
                continue;
            }
            if now_ms >= e.expires_ms {
                // Lazy reclaim of expired entries.
                e.occupied = false;
                continue;
            }
            if &e.key == key {
                return Observe::Duplicate;
            }
        }
        // Insert: first free slot wins, else evict the oldest expiry.
        let mut victim = 0usize;
        let mut victim_expires = u64::MAX;
        let mut free = None;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.occupied {
                free = Some(i);
                break;
            }
            if e.expires_ms < victim_expires {
                victim_expires = e.expires_ms;
                victim = i;
            }
        }
        let slot = free.unwrap_or(victim);
        self.entries[slot] = Entry {
            key: *key,
            expires_ms: now_ms.saturating_add(RELAY_CACHE_TTL_MS),
            occupied: true,
        };
        Observe::New
    }

    /// Count of live (unexpired) entries at `now_ms`.
    pub fn live_count(&self, now_ms: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.occupied && now_ms < e.expires_ms)
            .count()
    }
}

/// Forwarding decision for a structurally valid, newly seen frame.
///
/// Only `hops == 1` frames are forwarded. A frame this node originated
/// (echo of our own TX) is never treated as new work, and an endpoint
/// that consumed the frame for local delivery never forwards it on.
pub fn should_forward(hops: u8, is_local_origin_echo: bool, is_locally_delivered: bool) -> bool {
    hops == 1 && !is_local_origin_echo && !is_locally_delivered
}

/// Whether a duplicate observation cancels a scheduled forward.
///
/// Cancel only when the duplicate carries a LOWER remaining-hop value —
/// proof another relay already forwarded it. A same-hop duplicate is a
/// mere echo and must not cancel our forward.
pub fn cancel_on_dup(dup_hops: u8, orig_hops: u8) -> bool {
    dup_hops < orig_hops
}

/// Rewrite a validated `hops == 1` frame for forwarding: decrement the
/// hop byte at offset 14 to 0, recompute the trailing CRC-16, and leave
/// every other byte (immutable header, ciphertext/tag, body length)
/// identical. Returns the frame length.
///
/// The input is fully validated first (length, version, flags, CRC), so
/// a corrupt or non-forwardable frame is rejected rather than relayed.
pub fn prepare_forward(frame: &[u8], out: &mut [u8]) -> Result<usize, Reject> {
    let (header, _) = decode_frame(frame)?;
    if header.hops != 1 {
        return Err(Reject::BadHops);
    }
    if out.len() < frame.len() {
        return Err(Reject::TooLong);
    }
    out[..frame.len()].copy_from_slice(frame);
    out[14] = 0;
    let crc = crc16(&out[..frame.len() - 2]);
    let n = frame.len();
    out[n - 2..n].copy_from_slice(&crc.to_be_bytes());
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{encode_data_body, encode_frame, Header, BODY_DATA};


    fn test_frame(hops: u8) -> ([u8; 255], usize) {
        let h = Header {
            version: 1,
            flags: 0x01,
            dst: 0xAABBCCDD,
            src: 0x11223344,
            packet_id: 0xDEADBEEF,
            hops,
            epoch: 500,
            sequence: 7,
        };
        let mut body = [0u8; 180];
        let blen = encode_data_body(b"hello relay", &mut body).unwrap();
        let mut frame = [0u8; 255];
        let n = encode_frame(&h, &body[..blen], &mut frame).unwrap();
        (frame, n)
    }

    #[test]
    fn cache_key_stable_and_content_sensitive() {
        let (frame, _) = test_frame(1);
        let header = frame[..28].try_into().unwrap();
        let a = cache_key(header, &[BODY_DATA, 1, 2, 3]);
        let c = cache_key(header, &[BODY_DATA, 1, 2, 4]);
        assert_ne!(a, c);
        // Forwarding changes hops and CRC but preserves the cache identity.
        let (frame, n) = test_frame(1);
        let mut fwd = [0u8; 255];
        let m = prepare_forward(&frame[..n], &mut fwd).unwrap();
        assert_eq!(n, m);
        let before = cache_key_of_frame(&frame[..n], &frame[28..n - 2]).unwrap();
        let after = cache_key_of_frame(&fwd[..m], &fwd[28..m - 2]).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn changed_immutable_envelope_is_not_suppressed() {
        let (frame, n) = test_frame(1);
        let original = cache_key_of_frame(&frame[..n], &frame[28..n - 2]).unwrap();
        // Epoch, sequence and body length are as immutable as addresses/ID.
        for byte in (0..14).chain(15..28) {
            let mut changed = frame;
            changed[byte] ^= 1;
            let key = cache_key_of_frame(&changed[..n], &changed[28..n - 2]).unwrap();
            let mut cache = RelayCache::new();
            assert_eq!(cache.observe(&original, 0), Observe::New);
            assert_eq!(cache.observe(&key, 1), Observe::New, "byte {byte}");
        }
    }

    #[test]
    fn cache_key_of_frame_rejects_short() {
        assert_eq!(cache_key_of_frame(&[0u8; 10], &[1]), None);
    }

    #[test]
    fn observe_dedup_and_expiry_boundary() {
        let mut c = RelayCache::new();
        let k = [9u8; 32];
        assert_eq!(c.observe(&k, 1_000), Observe::New);
        assert_eq!(c.observe(&k, 1_000), Observe::Duplicate);
        // Live until exactly first + 8000.
        assert_eq!(c.observe(&k, 1_000 + RELAY_CACHE_TTL_MS - 1), Observe::Duplicate);
        assert_eq!(c.observe(&k, 1_000 + RELAY_CACHE_TTL_MS), Observe::New);
        assert_eq!(c.live_count(1_000 + RELAY_CACHE_TTL_MS), 1);
    }

    #[test]
    fn duplicates_never_extend_expiry() {
        let mut c = RelayCache::new();
        let k = [5u8; 32];
        assert_eq!(c.observe(&k, 0), Observe::New);
        // Duplicate near the end of life must not push expiry out.
        assert_eq!(c.observe(&k, 7_000), Observe::Duplicate);
        assert_eq!(c.observe(&k, 8_000), Observe::New);
        // New window runs 8000..16000.
        assert_eq!(c.observe(&k, 8_001), Observe::Duplicate);
        assert_eq!(c.observe(&k, 15_999), Observe::Duplicate);
        assert_eq!(c.observe(&k, 16_000), Observe::New);
    }

    #[test]
    fn eviction_drops_oldest_expiry_when_full() {
        let mut c = RelayCache::new();
        let mut keys = [[0u8; 32]; RELAY_CACHE_SIZE];
        for (i, k) in keys.iter_mut().enumerate() {
            k[0] = i as u8;
            k[1] = (i >> 8) as u8;
            // Staggered first-reception times; all still live at t=2000.
            assert_eq!(c.observe(k, 1_000 + i as u64), Observe::New);
        }
        assert_eq!(c.live_count(2_000), RELAY_CACHE_SIZE);
        let fresh = [0xFFu8; 32];
        assert_eq!(c.observe(&fresh, 2_000), Observe::New);
        assert_eq!(c.live_count(2_000), RELAY_CACHE_SIZE);
        // Oldest expiry (keys[0], expires 9000) was evicted; keys[1] kept.
        // Check survivors first: re-inserting keys[0] would itself evict keys[1].
        assert_eq!(c.observe(&keys[1], 2_000), Observe::Duplicate);
        assert_eq!(c.observe(&fresh, 2_000), Observe::Duplicate);
        assert_eq!(c.observe(&keys[0], 2_000), Observe::New);
    }

    #[test]
    fn forward_decision_matrix() {
        // (hops, echo, delivered, expected)
        let cases: [(u8, bool, bool, bool); 7] = [
            (1, false, false, true),
            (1, true, false, false),
            (1, false, true, false),
            (1, true, true, false),
            (0, false, false, false),
            (2, false, false, false),
            (0, true, true, false),
        ];
        for (hops, echo, delivered, want) in cases {
            assert_eq!(
                should_forward(hops, echo, delivered),
                want,
                "hops={hops} echo={echo} delivered={delivered}"
            );
        }
    }

    #[test]
    fn cancel_only_on_lower_hop_duplicate() {
        assert!(cancel_on_dup(0, 1));
        assert!(!cancel_on_dup(1, 1));
        assert!(!cancel_on_dup(1, 0));
        assert!(!cancel_on_dup(0, 0));
    }

    #[test]
    fn prepare_forward_hop_only_change_with_valid_crc() {
        let (frame, n) = test_frame(1);
        let mut out = [0u8; 255];
        let m = prepare_forward(&frame[..n], &mut out).unwrap();
        assert_eq!(m, n);
        // Only the hop byte and the trailing CRC may change.
        for i in 0..n {
            if i == 14 || i == n - 2 || i == n - 1 {
                continue;
            }
            assert_eq!(out[i], frame[i], "byte {i} must be identical");
        }
        assert_eq!(out[14], 0);
        // Output is a structurally valid frame decodable afterwards.
        let (h, body) = decode_frame(&out[..m]).unwrap();
        assert_eq!(h.hops, 0);
        assert_eq!(h.version, 1);
        assert_eq!(h.dst, 0xAABBCCDD);
        assert_eq!(h.src, 0x11223344);
        assert_eq!(h.packet_id, 0xDEADBEEF);
        assert_eq!(h.epoch, 500);
        assert_eq!(h.sequence, 7);
        assert_eq!(body, &frame[28..n - 2]);
    }

    #[test]
    fn prepare_forward_rejects_bad_input() {
        let (frame, n) = test_frame(0);
        let mut out = [0u8; 255];
        assert_eq!(prepare_forward(&frame[..n], &mut out), Err(Reject::BadHops));
        // Corrupt CRC must not be laundered into a fresh valid frame.
        let (mut bad, bn) = test_frame(1);
        bad[bn - 1] ^= 0x01;
        assert_eq!(prepare_forward(&bad[..bn], &mut out), Err(Reject::BadCrc));
        // Undersized output buffer.
        let (good, gn) = test_frame(1);
        let mut tiny = [0u8; 10];
        assert_eq!(prepare_forward(&good[..gn], &mut tiny), Err(Reject::TooLong));
    }

    #[test]
    fn jitter_sanitized_to_band() {
        assert_eq!(sanitize_jitter_ms(0), 100);
        assert_eq!(sanitize_jitter_ms(99), 100);
        assert_eq!(sanitize_jitter_ms(100), 100);
        assert_eq!(sanitize_jitter_ms(200), 200);
        assert_eq!(sanitize_jitter_ms(300), 300);
        assert_eq!(sanitize_jitter_ms(301), 300);
        assert_eq!(sanitize_jitter_ms(u16::MAX), 300);
    }
}
