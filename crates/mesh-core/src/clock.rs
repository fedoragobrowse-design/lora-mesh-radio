//! Epoch clock rules, receive-window anchors, and hourly private addresses
//! (Phase 4).
//!
//! - Cold boot always starts `TIME_UNSET`; a stored timestamp is not a
//!   running RTC. Local secure send/decrypt requires trusted local UTC
//!   set from the USB computer; receive/forward can still run unsynced.
//! - Hour epoch is `floor(unix_seconds / 3600)`. Incoming frames are
//!   accepted only in the current or adjacent hour (±1); ±2 fails closed.
//! - Never advance the receive-window anchor from a received radio epoch:
//!   radio traffic is unauthenticated until AEAD passes and must not move
//!   persisted replay state. Anchors move only with trusted local time.
//! - Address matches are candidate selection only: trying each contact's
//!   directional key and requiring AEAD success decides identity. Short
//!   (4-byte) aliases can collide; cryptography, not the alias, delivers.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator for hourly pair addresses.
pub const ADDR_DOMAIN: &[u8] = b"LMESH-addr-v1";
/// Seconds per epoch hour.
pub const SECS_PER_HOUR: u64 = 3600;

/// UTC hour epoch: `floor(unix_seconds / 3600)`.
///
/// Reject unrepresentable hours rather than wrapping or pinning a running
/// clock to the last valid epoch.
pub fn epoch_of_unix(unix_seconds: u64) -> Option<u32> {
    u32::try_from(unix_seconds / SECS_PER_HOUR).ok()
}

/// Whether a received frame epoch is acceptable given the local epoch:
/// current or adjacent hour only (±1, saturating at 0).
pub fn in_accept_window(rx_epoch: u32, local_epoch: u32) -> bool {
    rx_epoch == local_epoch
        || rx_epoch.checked_add(1) == Some(local_epoch)
        || local_epoch.checked_add(1) == Some(rx_epoch)
}

/// Derive one hourly 4-byte alias:
/// `first_4(HMAC-SHA256(secret, "LMESH-addr-v1" || I || E_be32))`.
///
/// The sender uses its own identity for `From` and the peer identity for
/// `To`. Every 4-byte output is usable — no reserved/broadcast value, so
/// there is no special-case truncation bias.
pub fn derive_address(secret: &[u8; 32], identity: &[u8; 8], epoch: u32) -> [u8; 4] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key size");
    mac.update(ADDR_DOMAIN);
    mac.update(identity);
    mac.update(&epoch.to_be_bytes());
    let out = mac.finalize().into_bytes();
    [out[0], out[1], out[2], out[3]]
}

/// Rejection from the trusted time setter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeError {
    /// New local epoch is below the persisted transmit epoch or the
    /// receive-window anchor: moving back would risk nonce reuse or
    /// resurrect retired replay windows.
    Rollback,
}

/// Guard for `time_set`: reject any new epoch below the highest epoch we
/// have ever transmitted under (`persisted_tx_epoch`) or below the
/// receive-window anchor (`rx_anchor`). Corrections *within* the current
/// hour always pass, because the epoch is unchanged.
pub fn check_time_set(new_epoch: u32, persisted_tx_epoch: u32, rx_anchor: u32) -> Result<(), TimeError> {
    if new_epoch < persisted_tx_epoch || new_epoch < rx_anchor {
        return Err(TimeError::Rollback);
    }
    Ok(())
}

/// Is a candidate anchor move a legal forward advance from `old`?
/// Anchors never move backwards; callers persist the new anchor and the
/// window retirement atomically with the trusted hour change.
pub fn anchor_may_advance(old_anchor: u32, new_anchor: u32) -> bool {
    new_anchor >= old_anchor
}

/// One contact's cached hourly aliases: previous/current/next hour ×
/// (own, peer). Recomputed only at time changes/epoch boundaries, never
/// per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasCache {
    /// Epoch this cache was computed for (the "current" hour).
    pub epoch: u32,
    /// Own aliases for (anchor-1, anchor, anchor+1), saturating at 0.
    pub own: [[u8; 4]; 3],
    /// Peer aliases for (anchor-1, anchor, anchor+1), saturating at 0.
    pub peer: [[u8; 4]; 3],
    /// Whether the cache holds real values (`false` before first fill).
    pub valid: bool,
}

impl AliasCache {
    /// Empty cache; call [`AliasCache::refresh`] before use.
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            own: [[0u8; 4]; 3],
            peer: [[0u8; 4]; 3],
            valid: false,
        }
    }

    /// Recompute all six slots for `epoch` from the pair address secret.
    pub fn refresh(
        &mut self,
        secret: &[u8; 32],
        own_id: &[u8; 8],
        peer_id: &[u8; 8],
        epoch: u32,
    ) {
        let epochs = [
            epoch.saturating_sub(1),
            epoch,
            epoch.saturating_add(1),
        ];
        for (i, e) in epochs.iter().enumerate() {
            self.own[i] = derive_address(secret, own_id, *e);
            self.peer[i] = derive_address(secret, peer_id, *e);
        }
        self.epoch = epoch;
        self.valid = true;
    }

    /// Epochs covered by the three slots, in slot order.
    pub fn slot_epochs(&self) -> [u32; 3] {
        [
            self.epoch.saturating_sub(1),
            self.epoch,
            self.epoch.saturating_add(1),
        ]
    }

    /// Candidate selection: does `alias` match any cached slot?
    ///
    /// A match only selects which directional key to *try*; AEAD success
    /// decides delivery. Returns the matching slot index when found.
    pub fn find_slot(&self, alias: &[u8; 4]) -> Option<usize> {
        if !self.valid {
            return None;
        }
        for i in 0..3 {
            if &self.own[i] == alias || &self.peer[i] == alias {
                return Some(i);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_math_floor_and_boundaries() {
        assert_eq!(epoch_of_unix(0), Some(0));
        assert_eq!(epoch_of_unix(3599), Some(0));
        assert_eq!(epoch_of_unix(3600), Some(1));
        let first_invalid = (u32::MAX as u64 + 1) * SECS_PER_HOUR;
        assert_eq!(epoch_of_unix(first_invalid - 1), Some(u32::MAX));
        assert_eq!(epoch_of_unix(first_invalid), None);
        assert_eq!(epoch_of_unix(u64::MAX), None);
    }

    #[test]
    fn accept_window_plus_minus_one() {
        let local = 500u32;
        assert!(in_accept_window(500, local));
        assert!(in_accept_window(499, local));
        assert!(in_accept_window(501, local));
        assert!(!in_accept_window(498, local));
        assert!(!in_accept_window(502, local));
        assert!(!in_accept_window(0, local));
        assert!(!in_accept_window(u32::MAX, local));
    }

    #[test]
    fn accept_window_at_zero_and_max_edges() {
        // No wrap below zero: epoch 0 accepts only 0 and 1.
        assert!(in_accept_window(0, 0));
        assert!(in_accept_window(1, 0));
        assert!(!in_accept_window(2, 0));
        assert!(!in_accept_window(u32::MAX, 0));
        // At u32::MAX the "next hour" saturates; MAX itself still matches.
        assert!(in_accept_window(u32::MAX, u32::MAX));
        assert!(in_accept_window(u32::MAX - 1, u32::MAX));
        assert!(!in_accept_window(u32::MAX - 2, u32::MAX));
    }

    #[test]
    fn address_deterministic_and_rotates_hourly() {
        let secret = [0x42u8; 32];
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let a = derive_address(&secret, &id, 500);
        assert_eq!(a, derive_address(&secret, &id, 500));
        // Hour change rotates the alias.
        assert_ne!(a, derive_address(&secret, &id, 501));
        assert_ne!(a, derive_address(&secret, &id, 499));
        // Different identity, different alias.
        let other = [8, 7, 6, 5, 4, 3, 2, 1];
        assert_ne!(a, derive_address(&secret, &other, 500));
        // Different secret, different alias.
        let mut secret2 = [0x42u8; 32];
        secret2[0] = 0x43;
        assert_ne!(a, derive_address(&secret2, &id, 500));
        // No reserved value machinery: a fixed output is just bytes.
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn address_matches_reference_vector() {
        // Independent HMAC-SHA256 check of the construction.
        let secret = *b"0123456789abcdef0123456789abcdef";
        let id = *b"ABCDEFGH";
        let epoch = 77u32;
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(b"LMESH-addr-v1");
        mac.update(&id);
        mac.update(&epoch.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        assert_eq!(derive_address(&secret, &id, epoch), [tag[0], tag[1], tag[2], tag[3]]);
    }

    #[test]
    fn alias_cache_slots_and_refresh() {
        let secret = [0x11u8; 32];
        let own = *b"nodeAAAA";
        let peer = *b"nodeBBBB";
        let mut c = AliasCache::new();
        assert!(!c.valid);
        assert_eq!(c.find_slot(&[0, 0, 0, 0]), None);
        c.refresh(&secret, &own, &peer, 500);
        assert!(c.valid);
        assert_eq!(c.epoch, 500);
        assert_eq!(c.slot_epochs(), [499, 500, 501]);
        for (i, e) in [499u32, 500, 501].iter().enumerate() {
            assert_eq!(c.own[i], derive_address(&secret, &own, *e));
            assert_eq!(c.peer[i], derive_address(&secret, &peer, *e));
        }
        // Every cached alias is selectable; a non-member is not.
        for a in c.own.iter().chain(c.peer.iter()) {
            assert!(c.find_slot(a).is_some());
        }
        // Epoch change recomputes: stale epoch's slots are replaced.
        c.refresh(&secret, &own, &peer, 501);
        assert_eq!(c.slot_epochs(), [500, 501, 502]);
        assert_eq!(c.own[0], derive_address(&secret, &own, 500));
        assert_eq!(c.own[2], derive_address(&secret, &own, 502));
    }

    #[test]
    fn alias_cache_saturates_at_zero() {
        let secret = [0x22u8; 32];
        let mut c = AliasCache::new();
        c.refresh(&secret, b"nodeAAAA", b"nodeBBBB", 0);
        assert_eq!(c.slot_epochs(), [0, 0, 1]);
        assert_eq!(c.own[0], c.own[1]);
        assert_eq!(c.peer[0], c.peer[1]);
    }

    #[test]
    fn time_set_guards_and_in_hour_correction() {
        // Fresh state: anything goes.
        assert_eq!(check_time_set(500, 0, 0), Ok(()));
        // In-hour corrections (same epoch) always pass.
        assert_eq!(check_time_set(500, 500, 500), Ok(()));
        // Forward movement passes.
        assert_eq!(check_time_set(501, 500, 499), Ok(()));
        // Below persisted transmit epoch: rollback.
        assert_eq!(check_time_set(499, 500, 0), Err(TimeError::Rollback));
        // Below receive anchor: rollback, even if TX state is older.
        assert_eq!(check_time_set(499, 0, 500), Err(TimeError::Rollback));
        assert_eq!(check_time_set(500, 500, 501), Err(TimeError::Rollback));
        // Equal to both floors is fine (not below).
        assert_eq!(check_time_set(500, 500, 500), Ok(()));
    }

    #[test]
    fn anchor_advance_rules() {
        assert!(anchor_may_advance(500, 500));
        assert!(anchor_may_advance(500, 501));
        assert!(anchor_may_advance(500, 600));
        assert!(!anchor_may_advance(501, 500));
        assert!(!anchor_may_advance(1, 0));
    }
}
