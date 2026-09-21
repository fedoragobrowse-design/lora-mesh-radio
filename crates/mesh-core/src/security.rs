//! Phase-2 end-to-end security: pairing transcript/KDFs, frame AEAD,
//! deterministic nonces, replay windows, and receive-window anchors.
//!
//! No RNG here: firmware supplies fresh secrets/challenges from the TRNG;
//! tests use fixed vectors only.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::frame::{Header, TAG_LEN};

/// Offer payload: version(1) + Ed25519 pubkey(32) + X25519 pubkey(32) + challenge(32).
pub const OFFER_LEN: usize = 97;
/// AEAD nonce: epoch_be32 || seq_be64.
pub const NONCE_LEN: usize = 12;
/// AAD: 14 ("LMESH-frame-v1") + 14 (header[0..14]) + 13 (header[15..28]).
pub const AAD_LEN: usize = 41;

/// Pairing transcript domain, hashed with both 97-byte offer payloads.
pub const DOMAIN_PAIR: &[u8] = b"LMESH-PAIR-v1";
/// Frame AEAD associated-data prefix.
pub const DOMAIN_FRAME: &[u8] = b"LMESH-frame-v1";
/// HKDF info: X25519 result -> pair root (salt = transcript).
pub const LABEL_ROOT: &[u8] = b"LMESH-root-v1";
/// HKDF info strings for `derive_label` (no salt, pair root as input).
pub const LABEL_SETUP_LR: &[u8] = b"LMESH-setup-LR-v1";
pub const LABEL_SETUP_RL: &[u8] = b"LMESH-setup-RL-v1";
pub const LABEL_TRAFFIC_LR: &[u8] = b"LMESH-traffic-LR-v1";
pub const LABEL_TRAFFIC_RL: &[u8] = b"LMESH-traffic-RL-v1";
pub const LABEL_ADDRESS: &[u8] = b"LMESH-address-v1";
pub const LABEL_CONFIRM: &[u8] = b"LMESH-confirm-v1";
/// HKDF info prefix for hourly traffic keys; full info is this || epoch_be32.
pub const LABEL_HOUR: &[u8] = b"LMESH-hour-v1";

/// AEAD/KDF failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// An input or output buffer is too small.
    BufferTooSmall,
    /// Ciphertext/tag (or AAD) failed authentication.
    BadTag,
}

/// Order two 97-byte offer payloads lexicographically by their Ed25519
/// public keys (payload bytes 1..33; byte 0 is the version byte shared by
/// both offers). Returns `(L, R)`.
pub fn order_offers<'a>(
    a: &'a [u8; OFFER_LEN],
    b: &'a [u8; OFFER_LEN],
) -> (&'a [u8; OFFER_LEN], &'a [u8; OFFER_LEN]) {
    if a[1..33] <= b[1..33] {
        (a, b)
    } else {
        (b, a)
    }
}

/// Pairing transcript: `SHA256("LMESH-PAIR-v1" || l || r)` over the 97-byte
/// offer payloads (record-type bytes excluded).
pub fn transcript_t(l: &[u8; OFFER_LEN], r: &[u8; OFFER_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PAIR);
    h.update(l);
    h.update(r);
    let d = h.finalize();
    let mut t = [0u8; 32];
    t.copy_from_slice(&d);
    t
}

/// Pair root: HKDF-SHA256 with salt = transcript `t`, input = X25519
/// result, info = `"LMESH-root-v1"`, 32-byte output.
pub fn derive_root(dh: &[u8; 32], t: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&t[..]), &dh[..]);
    let mut out = [0u8; 32];
    hk.expand(LABEL_ROOT, &mut out)
        .expect("32-byte HKDF expand is infallible");
    out
}

/// Derive a 32-byte subkey from the pair root: HKDF-SHA256 with no salt,
/// root as input, and the caller-supplied label as info. Labels are the
/// `LABEL_*` constants (`LMESH-setup-LR-v1`, `LMESH-setup-RL-v1`,
/// `LMESH-traffic-LR-v1`, `LMESH-traffic-RL-v1`, `LMESH-address-v1`,
/// `LMESH-confirm-v1`).
pub fn derive_label(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &root[..]);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("32-byte HKDF expand is infallible");
    out
}

/// Hourly traffic key: HKDF-SHA256 with no salt, directional root as input,
/// info = `"LMESH-hour-v1" || epoch_be32`, 32-byte output.
pub fn hourly_key(dir_root: &[u8; 32], epoch: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &dir_root[..]);
    let eb = epoch.to_be_bytes();
    let mut out = [0u8; 32];
    hk.expand_multi_info(&[LABEL_HOUR, &eb[..]], &mut out)
        .expect("32-byte HKDF expand is infallible");
    out
}

/// Deterministic AEAD nonce: `epoch_be32 || seq_be64`.
pub fn nonce(epoch: u32, seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&epoch.to_be_bytes());
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Build the 41-byte AEAD associated data for a frame:
/// `"LMESH-frame-v1" || header[0..14] || header[15..28]`, i.e. version,
/// flags, dst, src, packet ID, epoch, sequence, and body length. The mutable
/// hop byte at header offset 14 and the recomputable CRC are excluded so
/// relays can decrement hops and recompute CRC without holding a key.
/// Tampering with any covered byte fails authentication.
pub fn frame_aad(h: &Header, body_len: u8) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..14].copy_from_slice(DOMAIN_FRAME);
    aad[14] = h.version;
    aad[15] = h.flags;
    aad[16..20].copy_from_slice(&h.dst.to_be_bytes());
    aad[20..24].copy_from_slice(&h.src.to_be_bytes());
    aad[24..28].copy_from_slice(&h.packet_id.to_be_bytes());
    aad[28..32].copy_from_slice(&h.epoch.to_be_bytes());
    aad[32..40].copy_from_slice(&h.sequence.to_be_bytes());
    aad[40] = body_len;
    aad
}

/// Encrypt `plaintext` with ChaCha20-Poly1305 into `out`, appending the
/// 16-byte tag. `out` must hold `plaintext.len() + 16` bytes. Returns the
/// total ciphertext+tag length on success.
pub fn encrypt_data(
    key: &[u8; 32],
    nonce12: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let total = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(CryptoError::BufferTooSmall)?;
    if out.len() < total {
        return Err(CryptoError::BufferTooSmall);
    }
    out[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce12[..]),
            aad,
            &mut out[..plaintext.len()],
        )
        .map_err(|_| CryptoError::BadTag)?;
    out[plaintext.len()..total].copy_from_slice(tag.as_slice());
    Ok(total)
}

/// Decrypt `ct_and_tag` (ciphertext followed by its 16-byte tag) into `out`.
/// `out` must hold `ct_and_tag.len() - 16` bytes. Returns the plaintext
/// length; any immutable-header/AAD, ciphertext, or tag tampering returns
/// `Err(CryptoError::BadTag)` and zeroizes the output prefix.
pub fn decrypt_data(
    key: &[u8; 32],
    nonce12: &[u8; NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if ct_and_tag.len() < TAG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let pt_len = ct_and_tag.len() - TAG_LEN;
    if out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }
    out[..pt_len].copy_from_slice(&ct_and_tag[..pt_len]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let tag = Tag::from_slice(&ct_and_tag[pt_len..]);
    match cipher.decrypt_in_place_detached(
        Nonce::from_slice(&nonce12[..]),
        aad,
        &mut out[..pt_len],
        tag,
    ) {
        Ok(()) => Ok(pt_len),
        Err(_) => {
            out[..pt_len].zeroize();
            Err(CryptoError::BadTag)
        }
    }
}

/// Outcome of offering a sequence number to a [`ReplayWindow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// First authenticated observation; commit delivery state.
    Accepted,
    /// Already seen; may be re-ACKed but must not be redisplayed.
    Duplicate,
    /// Older than the 64-entry window; drop.
    Stale,
}

/// Per-contact, per-epoch 64-entry replay window: `(highest_sequence,
/// 64-bit received bitmap)` with an explicit empty state.
///
/// The caller MUST keep SEPARATE instances for DATA and ACK traffic within
/// the same contact/direction: a burst of ACKs would otherwise push a
/// pending DATA retry out of a shared window. Outgoing DATA/ACK still share
/// one nonce allocator; only the receive windows are split.
#[derive(Debug, Clone, Copy)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    empty: bool,
}

impl ReplayWindow {
    /// Empty window; the first accepted sequence becomes `highest`.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            empty: true,
        }
    }

    /// Offer an authenticated, body-decoded sequence number. Only call
    /// after AEAD authentication succeeds; forged packets must never
    /// advance either bitmap.
    pub fn accept(&mut self, seq: u64) -> Verdict {
        if self.empty {
            self.empty = false;
            self.highest = seq;
            self.bitmap = 1;
            return Verdict::Accepted;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = seq;
            Verdict::Accepted
        } else {
            let back = self.highest - seq;
            if back >= 64 {
                Verdict::Stale
            } else {
                let bit = 1u64 << back;
                if self.bitmap & bit != 0 {
                    Verdict::Duplicate
                } else {
                    self.bitmap |= bit;
                    Verdict::Accepted
                }
            }
        }
    }

    /// Highest sequence observed so far (`None` while empty).
    pub fn highest(&self) -> Option<u64> {
        if self.empty {
            None
        } else {
            Some(self.highest)
        }
    }

    /// Whether no sequence has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    /// Raw received bitmap (bit 0 = highest).
    pub fn bitmap_bits(&self) -> u64 {
        self.bitmap
    }

    /// Rebuild a window from persisted `(highest, bitmap, empty)` triple.
    /// Malformed triples (empty with nonzero bits) fail closed to empty.
    pub fn restore(highest: u64, bitmap: u64, empty: bool) -> Self {
        if empty {
            Self::new()
        } else if bitmap == 0 {
            Self::new()
        } else {
            Self {
                highest,
                bitmap,
                empty: false,
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure to move the receive-window anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// `new_hour` is below the persisted anchor; clock rollback refused.
    Rollback,
}

/// Nondecreasing per-contact receive-window anchor hour. Retained slots are
/// anchor-1, anchor, anchor+1 (saturating at zero).
///
/// Call `trusted_advance` ONLY with the trusted local UTC hour. NEVER
/// advance from a received radio epoch: an attacker-controlled epoch must
/// not retire previously accepted future-hour windows (which would make
/// those frames replayable later).
#[derive(Debug, Clone, Copy)]
pub struct AnchorHours {
    anchor: u32,
}

impl AnchorHours {
    /// Wrap a persisted anchor (cold boot restores, never resets).
    pub fn new(anchor: u32) -> Self {
        Self { anchor }
    }

    /// Current anchor hour.
    pub fn anchor(&self) -> u32 {
        self.anchor
    }

    fn slots(anchor: u32) -> [u32; 3] {
        [
            anchor.saturating_sub(1),
            anchor,
            anchor.saturating_add(1),
        ]
    }

    /// Atomically move the anchor to `new_hour` (must be >= anchor) and
    /// return the genuinely new retained slots the caller must initialize
    /// empty. Overlapping slots are retained, only older slots discarded.
    /// A backward move returns `Err(AnchorError::Rollback)` with no state
    /// change.
    pub fn trusted_advance(
        &mut self,
        new_hour: u32,
    ) -> Result<heapless::Vec<u32, 3>, AnchorError> {
        if new_hour < self.anchor {
            return Err(AnchorError::Rollback);
        }
        let old = Self::slots(self.anchor);
        let new = Self::slots(new_hour);
        let mut init: heapless::Vec<u32, 3> = heapless::Vec::new();
        for s in new {
            if !old.contains(&s) && !init.contains(&s) {
                let _ = init.push(s);
            }
        }
        self.anchor = new_hour;
        Ok(init)
    }
}

/// Owned 32-byte secret (pair root, directional root, hourly key, ...).
/// Zeroizes on drop. Firmware MUST hold key material in this wrapper (or an
/// equivalent zeroizing holder), never in long-lived plain arrays.
/// It deliberately has no `Debug` implementation, so derived debug output
/// cannot accidentally log key bytes.
///
/// ```compile_fail
/// use mesh_core::security::Secret32;
/// let secret = Secret32::new([0x42; 32]);
/// println!("{secret:?}");
/// ```
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Wrap freshly derived or TRNG-supplied key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the secret bytes for AEAD/KDF use.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf as _HkdfCheck;
    use sha2::Sha256 as _Sha256Check;

    fn offer_a() -> [u8; OFFER_LEN] {
        let mut o = [0u8; OFFER_LEN];
        for (i, b) in o.iter_mut().enumerate() {
            *b = i as u8;
        }
        o
    }

    fn offer_b() -> [u8; OFFER_LEN] {
        let mut o = [0u8; OFFER_LEN];
        for (i, b) in o.iter_mut().enumerate() {
            *b = 0x80u8.wrapping_add(i as u8);
        }
        o
    }

    // Independent vectors (cross-checked with a Python HMAC/HKDF reference;
    // A = 0..97, B = 0x80.., L = A, R = B).
    const VEC_T: [u8; 32] = [
        0xA4, 0x96, 0xD1, 0xEB, 0x5E, 0x79, 0x15, 0xFA, 0xA4, 0x49, 0x64, 0x62,
        0x58, 0x8F, 0x81, 0x1A, 0xDC, 0xA2, 0x31, 0xCE, 0x26, 0xCC, 0xC1, 0x57,
        0xB4, 0x08, 0x08, 0x48, 0xA3, 0xE4, 0x2A, 0x4A,
    ];
    // dh[i] = 0xA0 + i.
    const VEC_DH: [u8; 32] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
        0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    ];
    const VEC_ROOT: [u8; 32] = [
        0xB1, 0xBF, 0x41, 0xBE, 0xF1, 0xDF, 0xCC, 0x89, 0xBB, 0x67, 0x16, 0xF9,
        0xE8, 0x40, 0x2B, 0xEC, 0x8C, 0xEA, 0xC5, 0xF2, 0x28, 0x3B, 0x71, 0xE4,
        0x35, 0x1A, 0xA8, 0x5F, 0x62, 0xA1, 0x61, 0x8B,
    ];
    const VEC_SETUP_LR: [u8; 32] = [
        0xE3, 0x6E, 0x65, 0x0D, 0xEC, 0x7E, 0x10, 0x38, 0x4F, 0x09, 0x4E, 0x55,
        0xF0, 0x9E, 0x59, 0x17, 0x38, 0x22, 0xF2, 0x49, 0x35, 0xF4, 0x18, 0x26,
        0x33, 0x23, 0x30, 0xA6, 0xD7, 0xC5, 0xBD, 0x27,
    ];
    const VEC_SETUP_RL: [u8; 32] = [
        0x52, 0xF9, 0x13, 0x48, 0x83, 0x89, 0xE8, 0xA6, 0xD0, 0xEF, 0x90, 0x25,
        0x18, 0xFD, 0xF1, 0xD4, 0x1A, 0xE2, 0x5F, 0x4B, 0x4C, 0x62, 0x86, 0x03,
        0x0A, 0x05, 0x4D, 0x67, 0xD9, 0x3B, 0x8B, 0x97,
    ];
    const VEC_TRAF_LR: [u8; 32] = [
        0x06, 0xDE, 0xF4, 0xCA, 0xC1, 0xF7, 0xBF, 0x00, 0x16, 0x05, 0xEB, 0x60,
        0x84, 0xAA, 0x06, 0x1C, 0x1E, 0x73, 0x54, 0x6F, 0x74, 0xA8, 0xAE, 0xCC,
        0x32, 0x21, 0x6E, 0xF9, 0xBE, 0xB2, 0x73, 0xB4,
    ];
    // hourly_key(VEC_TRAF_LR, 488000).
    const VEC_HOUR: [u8; 32] = [
        0x22, 0xDF, 0x50, 0xF6, 0x07, 0x3C, 0x7F, 0xC5, 0x98, 0x7B, 0x17, 0x86,
        0x9A, 0x2F, 0x79, 0x6D, 0xE0, 0x8C, 0x8D, 0xD2, 0xD3, 0x71, 0x3F, 0xD1,
        0x9A, 0xF6, 0x20, 0x5C, 0xC0, 0x69, 0xB5, 0x72,
    ];

    #[test]
    fn hkdf_wiring_matches_rfc5869_case1() {
        // RFC 5869 Test Case 1 (SHA-256): proves our Hkdf usage is sound.
        let ikm = [0x0bu8; 22];
        let mut salt = [0u8; 13];
        for (i, s) in salt.iter_mut().enumerate() {
            *s = i as u8;
        }
        let mut info = [0u8; 10];
        for (i, v) in info.iter_mut().enumerate() {
            *v = 0xF0 + i as u8;
        }
        let hk = _HkdfCheck::<_Sha256Check>::new(Some(&salt[..]), &ikm[..]);
        let mut okm = [0u8; 42];
        hk.expand(&info[..], &mut okm).unwrap();
        let expected: [u8; 42] = [
            0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A, 0x90, 0x43, 0x4F,
            0x64, 0xD0, 0x36, 0x2F, 0x2A, 0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A,
            0x5A, 0x4C, 0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF, 0x34,
            0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected);
    }

    #[test]
    fn order_offers_sorts_by_signing_key() {
        let a = offer_a();
        let b = offer_b();
        let (l, r) = order_offers(&a, &b);
        assert_eq!(l, &a);
        assert_eq!(r, &b);
        // Argument order must not matter.
        let (l2, r2) = order_offers(&b, &a);
        assert_eq!(l2, &a);
        assert_eq!(r2, &b);
    }
    #[test]
    fn order_offers_uses_full_signing_key() {
        // Identical offers except the last Ed25519 key byte (payload index
        // 32): the old `a[..32]` slice dropped exactly this byte and tied,
        // while `role_for` over the full 32-byte keys did not. Both must
        // agree on L/R or the transcript `T` disagrees.
        let a = offer_a();
        let mut b = offer_a();
        b[32] = a[32].wrapping_add(1);
        let (l, r) = order_offers(&a, &b);
        assert_eq!(l, &a);
        assert_eq!(r, &b);
        let (l2, r2) = order_offers(&b, &a);
        assert_eq!(l2, &a);
        assert_eq!(r2, &b);
        // `role_for` on the extracted Ed25519 keys must pick the same side.
        let mut ka = [0u8; 32];
        let mut kb = [0u8; 32];
        ka.copy_from_slice(&a[1..33]);
        kb.copy_from_slice(&b[1..33]);
        assert_eq!(crate::pairing::role_for(&ka, &kb), crate::pairing::ROLE_L);
        assert_eq!(crate::pairing::role_for(&kb, &ka), crate::pairing::ROLE_R);
    }

    #[test]
    fn transcript_matches_vector() {
        let a = offer_a();
        let b = offer_b();
        let (l, r) = order_offers(&a, &b);
        assert_eq!(transcript_t(l, r), VEC_T);
        // Transcript is ordered: swapping inputs changes it.
        assert_ne!(transcript_t(r, l), VEC_T);
    }

    #[test]
    fn kdf_chain_matches_vectors() {
        assert_eq!(derive_root(&VEC_DH, &VEC_T), VEC_ROOT);
        assert_eq!(derive_label(&VEC_ROOT, LABEL_SETUP_LR), VEC_SETUP_LR);
        assert_eq!(derive_label(&VEC_ROOT, LABEL_SETUP_RL), VEC_SETUP_RL);
        assert_eq!(derive_label(&VEC_ROOT, LABEL_TRAFFIC_LR), VEC_TRAF_LR);
        assert_eq!(hourly_key(&VEC_TRAF_LR, 488_000), VEC_HOUR);
    }

    #[test]
    fn kdf_domain_separation() {
        // Every label must derive a distinct subkey from the same root.
        let labels: [&[u8]; 6] = [
            LABEL_SETUP_LR,
            LABEL_SETUP_RL,
            LABEL_TRAFFIC_LR,
            LABEL_TRAFFIC_RL,
            LABEL_ADDRESS,
            LABEL_CONFIRM,
        ];
        let mut keys = [[0u8; 32]; 6];
        for (i, k) in keys.iter_mut().enumerate() {
            *k = derive_label(&VEC_ROOT, labels[i]);
        }
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(keys[i], keys[j], "labels {i} and {j} collide");
            }
        }
        // Hourly keys move with the epoch.
        assert_ne!(hourly_key(&VEC_TRAF_LR, 488_000), hourly_key(&VEC_TRAF_LR, 488_001));
        assert_eq!(hourly_key(&VEC_TRAF_LR, 488_000), hourly_key(&VEC_TRAF_LR, 488_000));
    }

    #[test]
    fn nonce_layout_is_epoch_be32_then_seq_be64() {
        assert_eq!(
            nonce(0x0011_2233, 0x0102_0304_0506_0708),
            [
                0x00, 0x11, 0x22, 0x33, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08
            ]
        );
        assert_eq!(nonce(0, 0), [0u8; NONCE_LEN]);
    }

    #[test]
    fn aad_vector_covers_all_but_hops() {
        let h = Header {
            version: 1,
            flags: 0x01,
            dst: 0x1122_3344,
            src: 0x5566_7788,
            packet_id: 0xAABB_CCDD,
            hops: 7,
            epoch: 0x0011_2233,
            sequence: 0x0102_0304_0506_0708,
        };
        let expected: [u8; AAD_LEN] = [
            0x4C, 0x4D, 0x45, 0x53, 0x48, 0x2D, 0x66, 0x72, 0x61, 0x6D, 0x65,
            0x2D, 0x76, 0x31, // "LMESH-frame-v1"
            0x01, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xAA,
            0xBB, 0xCC, 0xDD, // header[0..14]
            0x00, 0x11, 0x22, 0x33, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x21, // header[15..28], body_len 33
        ];
        assert_eq!(frame_aad(&h, 33), expected);
        // Hop-only changes leave the AAD identical (relays may decrement).
        let relayed = Header { hops: 0, ..h };
        assert_eq!(frame_aad(&relayed, 33), expected);
    }

    fn test_header() -> Header {
        Header {
            version: 1,
            flags: 0x01,
            dst: 0x0A0B_0C0D,
            src: 0x0102_0304,
            packet_id: 0xDEAD_BEEF,
            hops: 1,
            epoch: 7,
            sequence: 42,
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let h = test_header();
        let aad = frame_aad(&h, 9 + TAG_LEN as u8);
        let n12 = nonce(h.epoch, h.sequence);
        let pt = b"hello mesh";
        let mut ct = [0u8; 64];
        let n = encrypt_data(&VEC_HOUR, &n12, &aad, pt, &mut ct).unwrap();
        assert_eq!(n, pt.len() + TAG_LEN);
        let mut out = [0u8; 64];
        let m = decrypt_data(&VEC_HOUR, &n12, &aad, &ct[..n], &mut out).unwrap();
        assert_eq!(m, pt.len());
        assert_eq!(&out[..m], pt);
    }

    #[test]
    fn one_bit_tamper_anywhere_rejected() {
        let h = test_header();
        let aad = frame_aad(&h, 9 + TAG_LEN as u8);
        let n12 = nonce(h.epoch, h.sequence);
        let pt = b"tamper me";
        let mut ct = [0u8; 64];
        let n = encrypt_data(&VEC_HOUR, &n12, &aad, pt, &mut ct).unwrap();
        let mut out = [0u8; 64];

        // Ciphertext bit flip.
        let mut bad = ct;
        bad[0] ^= 0x01;
        assert_eq!(
            decrypt_data(&VEC_HOUR, &n12, &aad, &bad[..n], &mut out),
            Err(CryptoError::BadTag)
        );
        // Tag bit flip.
        let mut bad = ct;
        bad[n - 1] ^= 0x80;
        assert_eq!(
            decrypt_data(&VEC_HOUR, &n12, &aad, &bad[..n], &mut out),
            Err(CryptoError::BadTag)
        );
        // Immutable header byte flip (dst) with frame CRC conceptually
        // recomputed: AEAD must still fail.
        let mut bad_aad = aad;
        bad_aad[16] ^= 0x01;
        assert_eq!(
            decrypt_data(&VEC_HOUR, &n12, &bad_aad, &ct[..n], &mut out),
            Err(CryptoError::BadTag)
        );
        // Epoch/sequence/body_len flips fail too.
        for i in [28usize, 32, 40] {
            let mut bad_aad = aad;
            bad_aad[i] ^= 0x01;
            assert_eq!(
                decrypt_data(&VEC_HOUR, &n12, &bad_aad, &ct[..n], &mut out),
                Err(CryptoError::BadTag),
                "aad byte {i} tamper accepted"
            );
        }
        // Failed decrypt zeroizes the output prefix.
        assert!(out[..pt.len()].iter().all(|&b| b == 0));
    }

    #[test]
    fn hop_decrement_stays_decryptable() {
        let h = test_header();
        let aad_tx = frame_aad(&h, 9 + TAG_LEN as u8);
        let n12 = nonce(h.epoch, h.sequence);
        let pt = b"via relay";
        let mut ct = [0u8; 64];
        let n = encrypt_data(&VEC_HOUR, &n12, &aad_tx, pt, &mut ct).unwrap();
        // Relay decrements hops to 0; AAD is unchanged, decrypt succeeds.
        let fwd = Header { hops: 0, ..h };
        let aad_rx = frame_aad(&fwd, 9 + TAG_LEN as u8);
        let mut out = [0u8; 64];
        let m = decrypt_data(&VEC_HOUR, &n12, &aad_rx, &ct[..n], &mut out).unwrap();
        assert_eq!(&out[..m], pt);
    }

    #[test]
    fn window_accept_duplicate_stale() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.highest(), None);
        assert_eq!(w.accept(10), Verdict::Accepted);
        assert_eq!(w.highest(), Some(10));
        assert_eq!(w.accept(10), Verdict::Duplicate);
        // Out-of-order arrivals inside the window are accepted once.
        assert_eq!(w.accept(12), Verdict::Accepted);
        assert_eq!(w.accept(11), Verdict::Accepted);
        assert_eq!(w.accept(11), Verdict::Duplicate);
        // A jump beyond 64 entries evicts everything before it.
        assert_eq!(w.accept(100), Verdict::Accepted);
        assert_eq!(w.accept(12), Verdict::Stale);
        assert_eq!(w.accept(36), Verdict::Stale); // back = 64
        assert_eq!(w.accept(37), Verdict::Accepted); // back = 63, new
        assert_eq!(w.accept(37), Verdict::Duplicate);
    }

    #[test]
    fn data_and_ack_windows_are_independent() {
        // A 64+ burst of reverse-direction ACKs must not evict a pending
        // DATA retry: callers keep SEPARATE ReplayWindow instances.
        let mut data = ReplayWindow::new();
        let mut ack = ReplayWindow::new();
        assert_eq!(data.accept(5), Verdict::Accepted);
        for s in 0..70u64 {
            ack.accept(s);
        }
        // The ACK window has moved on (seq 5 is ancient history there)...
        assert_eq!(ack.accept(5), Verdict::Stale);
        // ...while the DATA window still recognizes its pending retry.
        assert_eq!(data.accept(5), Verdict::Duplicate);
    }

    #[test]
    fn anchor_advance_and_rollback() {
        let mut a = AnchorHours::new(100);
        // Same-hour advance initializes nothing.
        assert_eq!(a.trusted_advance(100).unwrap().as_slice(), &[]);
        assert_eq!(a.anchor(), 100);
        // +1 keeps overlap, initializes only the new top slot.
        assert_eq!(a.trusted_advance(101).unwrap().as_slice(), &[102]);
        assert_eq!(a.anchor(), 101);
        // A jump initializes every non-overlapping slot, ascending.
        assert_eq!(
            a.trusted_advance(103).unwrap().as_slice(),
            &[103, 104]
        );
        assert_eq!(a.anchor(), 103);
        // Backward moves fail closed with no state change.
        assert_eq!(a.trusted_advance(102), Err(AnchorError::Rollback));
        assert_eq!(a.trusted_advance(0), Err(AnchorError::Rollback));
        assert_eq!(a.anchor(), 103);
    }

    #[test]
    fn secret_zeroizes() {
        let mut s = Secret32::new(VEC_ROOT);
        assert_eq!(s.as_bytes(), &VEC_ROOT);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }
}
