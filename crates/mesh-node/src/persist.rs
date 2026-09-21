//! Backwards-compatibility contract (all future releases MUST honor):
//! - `PERSIST_MAGIC` + `PERSIST_VERSION` gate every record; unknown
//!   versions and length mismatches fail closed, never reinterpreted.
//! - V(n+1) decoders MUST accept V(n) record lengths (V1/V2 2-slot records
//!   migrate by zero-filling new slots, then canonical re-encode).
//! - `CONTACT_BYTES` grows by appending fields only; existing offsets are
//!   frozen. Add a migration test per version bump.
//! - Existing USB error strings are frozen wire contract (`CONTACT_BLOCKED`
//!   means the engine flag is set; stale-token cancel is `BUSY`).
//!
//! Byte-identical persisted node encoding shared by firmware
//! (sequential-storage value bytes) and the native exerciser (files).
//! Fixed-size, versioned, big-endian; unknown versions fail closed.
use crate::engine::MAX_CONTACTS;

pub const PERSIST_MAGIC: [u8; 4] = *b"LMSH";
pub const PERSIST_VERSION: u8 = 3;
pub const CONTACT_BYTES: usize = 1 + 1 + 32 + 8 + 32 + 1 + 8 + 8 + 4 + 4 + 12 + 3 * 17 + 3 * 17;
/// V2 (and V1) records held exactly 2 contacts; V3 holds MAX_CONTACTS.
/// Decoders accept both lengths and zero-fill the new slots on migrate.
pub const PERSIST_V2_LEN: usize = 4 + 1 + 1 + 1 + 8 + 1 + 8 + 4 + 1 + 32 + 2 * CONTACT_BYTES;
pub const PERSIST_LEN: usize =
    4 + 1 + 1 + 1 + 8 + 1 + 8 + 4 + 1 + 32 + MAX_CONTACTS * CONTACT_BYTES;
/// V3 layout: header + MAX_CONTACTS contact slots (16 x 213B = ~3.5 KiB, fits one 4 KiB flash page).
/// V1/V2 records (2 slots) migrate by zero-filling slots 2..15.

#[derive(Clone, Copy)]
pub struct PersistContact {
    pub present: bool,
    pub blocked: bool,
    pub ed_peer: [u8; 32],
    pub peer_identity: [u8; 8],
    pub root: [u8; 32],
    pub role: u8,
    pub tx_next: u64,
    pub tx_reserved: u64,
    pub tx_epoch_max: u32,
    pub anchor: u32,
    pub win_epochs: [u32; 3],
    /// Per slot: (highest, bitmap, empty).
    pub win_data: [(u64, u64, bool); 3],
    pub win_ack: [(u64, u64, bool); 3],
}

impl PersistContact {
    pub const fn empty() -> Self {
        Self {
            present: false,
            blocked: false,
            ed_peer: [0u8; 32],
            peer_identity: [0u8; 8],
            root: [0u8; 32],
            role: 0,
            tx_next: 0,
            tx_reserved: 0,
            tx_epoch_max: 0,
            anchor: 0,
            win_epochs: [0u32; 3],
            win_data: [(0, 0, true); 3],
            win_ack: [(0, 0, true); 3],
        }
    }
}

pub struct PersistView {
    pub provisioned: bool,
    pub label: u8,
    pub uid: [u8; 8],
    pub uid_set: bool,
    pub unix_seconds: u64,
    pub persisted_tx_epoch: u32,
    pub armed_next_boot: bool,
    pub sign_priv: [u8; 32],
    pub sign_set: bool,
    pub contacts: [PersistContact; MAX_CONTACTS],
}

impl PersistView {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provisioned: bool,
        label: u8,
        uid: [u8; 8],
        uid_set: bool,
        unix_seconds: u64,
        persisted_tx_epoch: u32,
        sign_priv: [u8; 32],
        sign_set: bool,
        contacts: [PersistContact; MAX_CONTACTS],
    ) -> Self {
        Self {
            provisioned,
            label,
            uid,
            uid_set,
            unix_seconds,
            persisted_tx_epoch,
            armed_next_boot: false,
            sign_priv,
            sign_set,
            contacts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistError {
    BadLength,
    BadMagic,
    BadVersion,
}

fn w8(out: &mut [u8], pos: &mut usize, v: u8) {
    out[*pos] = v;
    *pos += 1;
}

fn w32(out: &mut [u8], pos: &mut usize, v: u32) {
    out[*pos..*pos + 4].copy_from_slice(&v.to_be_bytes());
    *pos += 4;
}

fn w64(out: &mut [u8], pos: &mut usize, v: u64) {
    out[*pos..*pos + 8].copy_from_slice(&v.to_be_bytes());
    *pos += 8;
}

fn wbytes(out: &mut [u8], pos: &mut usize, b: &[u8]) {
    out[*pos..*pos + b.len()].copy_from_slice(b);
    *pos += b.len();
}

fn r8(inp: &[u8], pos: &mut usize) -> Result<u8, PersistError> {
    inp.get(*pos)
        .copied()
        .ok_or(PersistError::BadLength)
        .map(|v| {
            *pos += 1;
            v
        })
}

fn r32(inp: &[u8], pos: &mut usize) -> Result<u32, PersistError> {
    let b: [u8; 4] = inp
        .get(*pos..*pos + 4)
        .ok_or(PersistError::BadLength)?
        .try_into()
        .map_err(|_| PersistError::BadLength)?;
    *pos += 4;
    Ok(u32::from_be_bytes(b))
}

fn r64(inp: &[u8], pos: &mut usize) -> Result<u64, PersistError> {
    let b: [u8; 8] = inp
        .get(*pos..*pos + 8)
        .ok_or(PersistError::BadLength)?
        .try_into()
        .map_err(|_| PersistError::BadLength)?;
    *pos += 8;
    Ok(u64::from_be_bytes(b))
}

fn rbytes<const N: usize>(inp: &[u8], pos: &mut usize) -> Result<[u8; N], PersistError> {
    let b: [u8; N] = inp
        .get(*pos..*pos + N)
        .ok_or(PersistError::BadLength)?
        .try_into()
        .map_err(|_| PersistError::BadLength)?;
    *pos += N;
    Ok(b)
}

/// Encode `view` into `out` (must be `PERSIST_LEN`); returns bytes written.
pub fn encode_into(view: &PersistView, out: &mut [u8]) -> usize {
    debug_assert!(out.len() >= PERSIST_LEN);
    let mut p = 0;
    wbytes(out, &mut p, &PERSIST_MAGIC);
    w8(out, &mut p, PERSIST_VERSION);
    w8(
        out,
        &mut p,
        (view.provisioned as u8) | ((view.armed_next_boot as u8) << 1),
    );
    w8(out, &mut p, view.label);
    wbytes(out, &mut p, &view.uid);
    w8(out, &mut p, view.uid_set as u8);
    w64(out, &mut p, view.unix_seconds);
    w32(out, &mut p, view.persisted_tx_epoch);
    w8(out, &mut p, view.sign_set as u8);
    wbytes(out, &mut p, &view.sign_priv);
    for c in view.contacts.iter() {
        w8(out, &mut p, c.present as u8);
        w8(out, &mut p, c.blocked as u8);
        wbytes(out, &mut p, &c.ed_peer);
        wbytes(out, &mut p, &c.peer_identity);
        wbytes(out, &mut p, &c.root);
        w8(out, &mut p, c.role);
        w64(out, &mut p, c.tx_next);
        w64(out, &mut p, c.tx_reserved);
        w32(out, &mut p, c.tx_epoch_max);
        w32(out, &mut p, c.anchor);
        for e in c.win_epochs {
            w32(out, &mut p, e);
        }
        for (h, b, e) in c.win_data {
            w64(out, &mut p, h);
            w64(out, &mut p, b);
            w8(out, &mut p, e as u8);
        }
        for (h, b, e) in c.win_ack {
            w64(out, &mut p, h);
            w64(out, &mut p, b);
            w8(out, &mut p, e as u8);
        }
    }
    p
}

pub fn encode_persist(view: &PersistView) -> ([u8; PERSIST_LEN], usize) {
    let mut out = [0u8; PERSIST_LEN];
    let n = encode_into(view, &mut out);
    (out, n)
}

pub fn decode_persist(bytes: &[u8]) -> Result<OwnedView, PersistError> {
    decode_view(bytes).map(|v| OwnedView {
        provisioned: v.provisioned,
        armed_next_boot: v.armed_next_boot,
        label: v.label,
        uid: v.uid,
        uid_set: v.uid_set,
        unix_seconds: v.unix_seconds,
        persisted_tx_epoch: v.persisted_tx_epoch,
        sign_priv: v.sign_priv,
        sign_set: v.sign_set,
        contacts: v.contacts,
    })
}

/// Re-encode any accepted record (V1/V2/V3) as canonical V3 bytes.
/// Zero-padded migration buffers Fault (empty windows encode e=1, not 0),
/// so migrated records must pass through here before engine restore.
pub fn migrate_to_v3(bytes: &[u8]) -> Result<[u8; PERSIST_LEN], PersistError> {
    let owned = decode_persist(bytes)?;
    let view = PersistView {
        provisioned: owned.provisioned,
        armed_next_boot: owned.armed_next_boot,
        label: owned.label,
        uid: owned.uid,
        uid_set: owned.uid_set,
        unix_seconds: owned.unix_seconds,
        persisted_tx_epoch: owned.persisted_tx_epoch,
        sign_priv: owned.sign_priv,
        sign_set: owned.sign_set,
        contacts: owned.contacts,
    };
    Ok(encode_persist(&view).0)
}

pub struct OwnedView {
    pub provisioned: bool,
    pub armed_next_boot: bool,
    pub label: u8,
    pub uid: [u8; 8],
    pub uid_set: bool,
    pub unix_seconds: u64,
    pub persisted_tx_epoch: u32,
    pub sign_priv: [u8; 32],
    pub sign_set: bool,
    pub contacts: [PersistContact; MAX_CONTACTS],
}

pub struct Decoded<'a> {
    pub provisioned: bool,
    pub armed_next_boot: bool,
    pub label: u8,
    pub uid: [u8; 8],
    pub uid_set: bool,
    pub unix_seconds: u64,
    pub persisted_tx_epoch: u32,
    pub sign_priv: [u8; 32],
    pub sign_set: bool,
    pub contacts: [PersistContact; MAX_CONTACTS],
    pub _m: core::marker::PhantomData<&'a ()>,
}

pub fn decode_view(bytes: &[u8]) -> Result<Decoded<'_>, PersistError> {
    // Length selects slot count; version must match its own length.
    // V3 only at full length, V1/V2 only at 2-slot length. Anything else
    // (ver 3 in a short record, ver 1 in a long record) is BadVersion.
    let slots = if bytes.len() == PERSIST_LEN {
        MAX_CONTACTS
    } else if bytes.len() == PERSIST_V2_LEN {
        2
    } else {
        return Err(PersistError::BadLength);
    };
    let mut p = 0;
    let magic = rbytes::<4>(bytes, &mut p)?;
    if magic != PERSIST_MAGIC {
        return Err(PersistError::BadMagic);
    }
    let ver = r8(bytes, &mut p)?;
    let full = bytes.len() == PERSIST_LEN;
    if full != (ver == PERSIST_VERSION) || (ver != 1 && ver != 2 && ver != PERSIST_VERSION) {
        return Err(PersistError::BadVersion);
    }
    let flags = r8(bytes, &mut p)?;
    if flags & !(if ver == 1 { 1 } else { 3 }) != 0 {
        return Err(PersistError::BadVersion);
    }
    let provisioned = flags & 1 != 0;
    let armed_next_boot = flags & 2 != 0;
    let label = r8(bytes, &mut p)?;
    if label > 3 {
        return Err(PersistError::BadVersion);
    }
    let uid = rbytes::<8>(bytes, &mut p)?;
    let uid_set = r8(bytes, &mut p)? != 0;
    let unix_seconds = r64(bytes, &mut p)?;
    let persisted_tx_epoch = r32(bytes, &mut p)?;
    let sign_set = r8(bytes, &mut p)? != 0;
    let sign_priv = rbytes::<32>(bytes, &mut p)?;
    let mut contacts = [PersistContact::empty(); MAX_CONTACTS];
    for c in contacts.iter_mut().take(slots) {
        c.present = r8(bytes, &mut p)? != 0;
        c.blocked = r8(bytes, &mut p)? != 0;
        c.ed_peer = rbytes::<32>(bytes, &mut p)?;
        c.peer_identity = rbytes::<8>(bytes, &mut p)?;
        c.root = rbytes::<32>(bytes, &mut p)?;
        c.role = r8(bytes, &mut p)?;
        if c.role > 1 {
            return Err(PersistError::BadVersion);
        }
        c.tx_next = r64(bytes, &mut p)?;
        c.tx_reserved = r64(bytes, &mut p)?;
        if c.tx_reserved < c.tx_next {
            return Err(PersistError::BadVersion);
        }
        c.tx_epoch_max = r32(bytes, &mut p)?;
        c.anchor = r32(bytes, &mut p)?;
        for e in c.win_epochs.iter_mut() {
            *e = r32(bytes, &mut p)?;
        }
        for w in c.win_data.iter_mut() {
            let h = r64(bytes, &mut p)?;
            let b = r64(bytes, &mut p)?;
            let e = r8(bytes, &mut p)? != 0;
            if e && (h != 0 || b != 0) {
                return Err(PersistError::BadVersion);
            }
            if !e && b == 0 {
                return Err(PersistError::BadVersion);
            }
            *w = (h, b, e);
        }
        for w in c.win_ack.iter_mut() {
            let h = r64(bytes, &mut p)?;
            let b = r64(bytes, &mut p)?;
            let e = r8(bytes, &mut p)? != 0;
            if e && (h != 0 || b != 0) {
                return Err(PersistError::BadVersion);
            }
            if !e && b == 0 {
                return Err(PersistError::BadVersion);
            }
            *w = (h, b, e);
        }
        if !c.present
            && (c.blocked
                || c.ed_peer != [0u8; 32]
                || c.peer_identity != [0u8; 8]
                || c.root != [0u8; 32]
                || c.tx_next != 0
                || c.tx_reserved != 0
                || c.tx_epoch_max != 0
                || c.anchor != 0)
        {
            return Err(PersistError::BadVersion);
        }
    }
    if p != bytes.len() {
        return Err(PersistError::BadLength);
    }
    Ok(Decoded {
        provisioned,
        armed_next_boot,
        label,
        uid,
        uid_set,
        unix_seconds,
        persisted_tx_epoch,
        sign_priv,
        sign_set,
        contacts,
        _m: core::marker::PhantomData,
    })
}
