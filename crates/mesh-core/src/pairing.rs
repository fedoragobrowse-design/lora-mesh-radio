//! In-person pairing records (Phase 2): record layout + strict validation.
//!
//! This module owns the **bytes on the QR/file channel** and nothing else.
//! All Diffie-Hellman, AEAD, signature and KDF operations live in
//! `crate::security`; this module never touches secret key material beyond
//! copying caller-supplied public bytes into record buffers.
//!
//! Ceremony contract (enforced by the firmware/USB layers, documented here
//! so every caller shares the same assumptions):
//! - Radio-off precondition: both boards run `radio off` before any
//!   `pair_*` command. Pairing commands reject an enabled radio with
//!   `RADIO_MUST_BE_OFF` and never transmit over LoRa.
//! - One pending attempt per board: repeated offer export re-emits the same
//!   offer until explicit cancellation or 10-minute expiry
//!   ([`is_expired`]). Abort, failure or restart discards temporary secrets;
//!   resuming requires fresh offers.
//! - An operator flag named `--replace` exists, but the current firmware
//!   `import_offer` duplicate-identity guard fails closed before slot
//!   selection even when that flag is set, so it cannot renew the same peer
//!   in place today. Repair a stale slot with `contact_delete`, then a fresh
//!   offer with `replace=false`. This module never overwrites stored
//!   contacts itself.
//! - T comparison ceremony: both operators compare the [`transcript_fingerprint`]
//!   (first 16 hex digits of `T`) shown on each host. On mismatch the
//!   pairing is aborted, never auto-accepted.
//! - Proof and confirmation records are constructed by firmware from secrets
//!   held in flash/TRNG; the host only transports opaque `LMESH1:` text.
//!
//! Transcript note: `T` is derived from the two 97-byte **offer payloads**
//! (version + keys + challenge, no record-type bytes), ordered
//! lexicographically by Ed25519 public key. Use [`offer_record_payload`]
//! to recover the exact `T` input bytes from a decoded offer record.

use core::cmp::Ordering;

/// Protocol version byte carried as the first byte of every offer payload.
pub const OFFER_VERSION: u8 = 0x01;

/// Record type byte (first byte of the binary record, before base64url).
pub const RECORD_OFFER: u8 = 0x01;
/// Record type byte for proofs.
pub const RECORD_PROOF: u8 = 0x02;
/// Record type byte for confirmations.
pub const RECORD_CONFIRM: u8 = 0x03;

pub const ED_PUB_LEN: usize = 32;
pub const EPH_PUB_LEN: usize = 32;
pub const CHALLENGE_LEN: usize = 32;
/// Transcript hash length.
pub const T_LEN: usize = 32;
/// Proof ciphertext length (8-byte identity + 16-byte tag).
pub const PROOF_CT_LEN: usize = 24;
pub const SIG_LEN: usize = 64;
pub const MAC_LEN: usize = 32;

/// Offer payload: 1 (ver) + 32 (ed25519) + 32 (x25519 eph) + 32 (challenge).
pub const OFFER_PAYLOAD_LEN: usize = 97;
/// Offer record: 1 (type) + 97 (payload).
pub const OFFER_RECORD_LEN: usize = 98;
/// Proof record: 1 (type) + 32 (T) + 1 (role) + 24 (ct/tag) + 64 (sig).
pub const PROOF_RECORD_LEN: usize = 122;
/// Confirmation record: 1 (type) + 32 (T) + 1 (role) + 32 (hmac).
pub const CONFIRM_RECORD_LEN: usize = 66;

/// ASCII transport prefix: `LMESH1:` followed by base64url with no padding.
pub const TRANSPORT_PREFIX: &[u8] = b"LMESH1:";
/// Pending pairing attempts expire this many seconds after creation
/// (monotonic clock, not wall time).
pub const PAIRING_EXPIRY_SECS: u64 = 600;

/// Role byte: the lexicographically smaller Ed25519 key plays `L`.
pub const ROLE_L: u8 = 0;
/// Role byte: the lexicographically larger Ed25519 key plays `R`.
pub const ROLE_R: u8 = 1;

/// Strict validation failure for pairing record handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    /// Wrong record type byte.
    BadType,
    /// Wrong record/payload/base64 length.
    BadLength,
    /// ASCII transport does not start with `LMESH1:`.
    BadPrefix,
    /// Illegal base64url character, padding, or non-canonical trailing bits.
    BadCharset,
    /// Wrong offer payload version byte.
    BadVersion,
    /// Role byte is not 0 (`L`) or 1 (`R`).
    BadRole,
    /// Own and peer Ed25519 identities are identical.
    SelfPairing,
    /// Caller-supplied output buffer is too small.
    BufferTooSmall,
}

/// Offer fields: long-term signing key, fresh ephemeral key, fresh challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub ed_pub: [u8; ED_PUB_LEN],
    pub eph_pub: [u8; EPH_PUB_LEN],
    pub challenge: [u8; CHALLENGE_LEN],
}

/// Proof fields: transcript, role, encrypted identity, Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub t: [u8; T_LEN],
    pub role: u8,
    pub ct: [u8; PROOF_CT_LEN],
    pub sig: [u8; SIG_LEN],
}

/// Confirmation fields: transcript, role, HMAC over the proof transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub t: [u8; T_LEN],
    pub role: u8,
    pub mac: [u8; MAC_LEN],
}

/// Encode the 97-byte offer payload (no record-type byte): the exact bytes
/// that feed the transcript hash `T`.
pub fn encode_offer_payload(offer: &Offer, out: &mut [u8]) -> Result<usize, PairError> {
    if out.len() < OFFER_PAYLOAD_LEN {
        return Err(PairError::BufferTooSmall);
    }
    out[0] = OFFER_VERSION;
    out[1..1 + ED_PUB_LEN].copy_from_slice(&offer.ed_pub);
    out[1 + ED_PUB_LEN..1 + ED_PUB_LEN + EPH_PUB_LEN].copy_from_slice(&offer.eph_pub);
    out[1 + ED_PUB_LEN + EPH_PUB_LEN..OFFER_PAYLOAD_LEN].copy_from_slice(&offer.challenge);
    Ok(OFFER_PAYLOAD_LEN)
}

/// Strictly decode a 97-byte offer payload.
pub fn decode_offer_payload(bytes: &[u8]) -> Result<Offer, PairError> {
    if bytes.len() != OFFER_PAYLOAD_LEN {
        return Err(PairError::BadLength);
    }
    if bytes[0] != OFFER_VERSION {
        return Err(PairError::BadVersion);
    }
    let mut offer = Offer {
        ed_pub: [0u8; ED_PUB_LEN],
        eph_pub: [0u8; EPH_PUB_LEN],
        challenge: [0u8; CHALLENGE_LEN],
    };
    offer.ed_pub.copy_from_slice(&bytes[1..1 + ED_PUB_LEN]);
    offer
        .eph_pub
        .copy_from_slice(&bytes[1 + ED_PUB_LEN..1 + ED_PUB_LEN + EPH_PUB_LEN]);
    offer
        .challenge
        .copy_from_slice(&bytes[1 + ED_PUB_LEN + EPH_PUB_LEN..OFFER_PAYLOAD_LEN]);
    Ok(offer)
}

/// Encode the 98-byte offer record: type `0x01` followed by the payload.
pub fn encode_offer_record(offer: &Offer, out: &mut [u8]) -> Result<usize, PairError> {
    if out.len() < OFFER_RECORD_LEN {
        return Err(PairError::BufferTooSmall);
    }
    out[0] = RECORD_OFFER;
    encode_offer_payload(offer, &mut out[1..OFFER_RECORD_LEN])?;
    Ok(OFFER_RECORD_LEN)
}

/// Strictly decode a 98-byte offer record (checks length, then type).
pub fn decode_offer_record(record: &[u8]) -> Result<Offer, PairError> {
    if record.len() != OFFER_RECORD_LEN {
        return Err(PairError::BadLength);
    }
    if record[0] != RECORD_OFFER {
        return Err(PairError::BadType);
    }
    decode_offer_payload(&record[1..])
}

/// Borrow the 97-byte `T`-input payload from inside an offer record,
/// validating length and type first.
pub fn offer_record_payload(record: &[u8]) -> Result<&[u8], PairError> {
    if record.len() != OFFER_RECORD_LEN {
        return Err(PairError::BadLength);
    }
    if record[0] != RECORD_OFFER {
        return Err(PairError::BadType);
    }
    Ok(&record[1..])
}

/// Encode the 122-byte proof record.
pub fn encode_proof(proof: &Proof, out: &mut [u8]) -> Result<usize, PairError> {
    if proof.role != ROLE_L && proof.role != ROLE_R {
        return Err(PairError::BadRole);
    }
    if out.len() < PROOF_RECORD_LEN {
        return Err(PairError::BufferTooSmall);
    }
    out[0] = RECORD_PROOF;
    out[1..1 + T_LEN].copy_from_slice(&proof.t);
    out[1 + T_LEN] = proof.role;
    out[1 + T_LEN + 1..1 + T_LEN + 1 + PROOF_CT_LEN].copy_from_slice(&proof.ct);
    out[1 + T_LEN + 1 + PROOF_CT_LEN..PROOF_RECORD_LEN].copy_from_slice(&proof.sig);
    Ok(PROOF_RECORD_LEN)
}

/// Strictly decode a 122-byte proof record.
pub fn decode_proof(record: &[u8]) -> Result<Proof, PairError> {
    if record.len() != PROOF_RECORD_LEN {
        return Err(PairError::BadLength);
    }
    if record[0] != RECORD_PROOF {
        return Err(PairError::BadType);
    }
    let role = record[1 + T_LEN];
    if role != ROLE_L && role != ROLE_R {
        return Err(PairError::BadRole);
    }
    let mut proof = Proof {
        t: [0u8; T_LEN],
        role,
        ct: [0u8; PROOF_CT_LEN],
        sig: [0u8; SIG_LEN],
    };
    proof.t.copy_from_slice(&record[1..1 + T_LEN]);
    proof
        .ct
        .copy_from_slice(&record[1 + T_LEN + 1..1 + T_LEN + 1 + PROOF_CT_LEN]);
    proof
        .sig
        .copy_from_slice(&record[1 + T_LEN + 1 + PROOF_CT_LEN..PROOF_RECORD_LEN]);
    Ok(proof)
}

/// Encode the 66-byte confirmation record.
pub fn encode_confirmation(conf: &Confirmation, out: &mut [u8]) -> Result<usize, PairError> {
    if conf.role != ROLE_L && conf.role != ROLE_R {
        return Err(PairError::BadRole);
    }
    if out.len() < CONFIRM_RECORD_LEN {
        return Err(PairError::BufferTooSmall);
    }
    out[0] = RECORD_CONFIRM;
    out[1..1 + T_LEN].copy_from_slice(&conf.t);
    out[1 + T_LEN] = conf.role;
    out[1 + T_LEN + 1..CONFIRM_RECORD_LEN].copy_from_slice(&conf.mac);
    Ok(CONFIRM_RECORD_LEN)
}

/// Strictly decode a 66-byte confirmation record.
pub fn decode_confirmation(record: &[u8]) -> Result<Confirmation, PairError> {
    if record.len() != CONFIRM_RECORD_LEN {
        return Err(PairError::BadLength);
    }
    if record[0] != RECORD_CONFIRM {
        return Err(PairError::BadType);
    }
    let role = record[1 + T_LEN];
    if role != ROLE_L && role != ROLE_R {
        return Err(PairError::BadRole);
    }
    let mut conf = Confirmation {
        t: [0u8; T_LEN],
        role,
        mac: [0u8; MAC_LEN],
    };
    conf.t.copy_from_slice(&record[1..1 + T_LEN]);
    conf.mac
        .copy_from_slice(&record[1 + T_LEN + 1..CONFIRM_RECORD_LEN]);
    Ok(conf)
}

/// Determine this board's role: `0` (`L`) when its Ed25519 key is the
/// lexicographically smaller one, `1` (`R`) otherwise.
///
/// Callers MUST run [`check_not_self`] first; equal keys are not a valid
/// pair and this helper reports them as `R` (they compare non-less).
pub fn role_for(own_ed: &[u8; ED_PUB_LEN], peer_ed: &[u8; ED_PUB_LEN]) -> u8 {
    if own_ed.as_slice().cmp(peer_ed.as_slice()) == Ordering::Less {
        ROLE_L
    } else {
        ROLE_R
    }
}

/// Reject pairing a board with itself (identical Ed25519 identities).
pub fn check_not_self(
    own_ed: &[u8; ED_PUB_LEN],
    peer_ed: &[u8; ED_PUB_LEN],
) -> Result<(), PairError> {
    if own_ed == peer_ed {
        Err(PairError::SelfPairing)
    } else {
        Ok(())
    }
}

/// True once a pending attempt aged `PAIRING_EXPIRY_SECS` (600 s) or more.
/// A backwards monotonic reading (`now < start`) counts as not expired.
pub fn is_expired(start_mono_s: u64, now_mono_s: u64) -> bool {
    now_mono_s.saturating_sub(start_mono_s) >= PAIRING_EXPIRY_SECS
}

/// First 16 lowercase hex characters of `T` (raw transcript bytes `T[0..8]`)
/// for the human comparison ceremony. The return value is already ASCII hex;
/// callers must emit it verbatim and must not hex-encode it a second time.
pub fn transcript_fingerprint(t: &[u8; T_LEN]) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 8 {
        out[2 * i] = HEX[(t[i] >> 4) as usize];
        out[2 * i + 1] = HEX[(t[i] & 0x0f) as usize];
        i += 1;
    }
    out
}

// ---- base64url, no padding (hand-rolled; no new dependencies) ----

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Exact base64url length (no padding) for `n` input bytes.
pub const fn b64_encoded_len(n: usize) -> usize {
    (n * 4 + 2) / 3
}

/// Exact ASCII transport length (`LMESH1:` + base64url) for a record.
pub const fn transport_encoded_len(record_len: usize) -> usize {
    TRANSPORT_PREFIX.len() + b64_encoded_len(record_len)
}

/// Upper bound on decoded bytes for a base64url body of `body_len` chars.
pub const fn transport_decoded_max(body_len: usize) -> usize {
    (body_len / 4) * 3 + 3
}

fn b64_val(c: u8) -> Result<u8, PairError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(PairError::BadCharset),
    }
}

fn b64_encode_into(input: &[u8], out: &mut [u8]) -> Result<usize, PairError> {
    if out.len() < b64_encoded_len(input.len()) {
        return Err(PairError::BufferTooSmall);
    }
    let mut ip = 0;
    let mut op = 0;
    while ip + 3 <= input.len() {
        let n = ((input[ip] as u32) << 16) | ((input[ip + 1] as u32) << 8) | (input[ip + 2] as u32);
        out[op] = B64_ALPHABET[((n >> 18) & 63) as usize];
        out[op + 1] = B64_ALPHABET[((n >> 12) & 63) as usize];
        out[op + 2] = B64_ALPHABET[((n >> 6) & 63) as usize];
        out[op + 3] = B64_ALPHABET[(n & 63) as usize];
        ip += 3;
        op += 4;
    }
    let rem = input.len() - ip;
    if rem == 1 {
        let n = (input[ip] as u32) << 16;
        out[op] = B64_ALPHABET[((n >> 18) & 63) as usize];
        out[op + 1] = B64_ALPHABET[((n >> 12) & 63) as usize];
        op += 2;
    } else if rem == 2 {
        let n = ((input[ip] as u32) << 16) | ((input[ip + 1] as u32) << 8);
        out[op] = B64_ALPHABET[((n >> 18) & 63) as usize];
        out[op + 1] = B64_ALPHABET[((n >> 12) & 63) as usize];
        out[op + 2] = B64_ALPHABET[((n >> 6) & 63) as usize];
        op += 3;
    }
    Ok(op)
}

fn b64_decode_into(input: &[u8], out: &mut [u8]) -> Result<usize, PairError> {
    // Without padding, lengths of 4k+1 are unrepresentable.
    let tail = input.len() % 4;
    if tail == 1 {
        return Err(PairError::BadLength);
    }
    let main_len = input.len() - tail;
    let need = (main_len / 4) * 3
        + if tail == 2 {
            1
        } else if tail == 3 {
            2
        } else {
            0
        };
    if out.len() < need {
        return Err(PairError::BufferTooSmall);
    }
    let mut op: usize = 0;
    let mut ip: usize = 0;
    while ip < main_len {
        let a = b64_val(input[ip])?;
        let b = b64_val(input[ip + 1])?;
        let c = b64_val(input[ip + 2])?;
        let d = b64_val(input[ip + 3])?;
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out[op] = (n >> 16) as u8;
        out[op + 1] = (n >> 8) as u8;
        out[op + 2] = n as u8;
        op += 3;
        ip += 4;
    }
    if tail == 2 {
        let a = b64_val(input[ip])?;
        let b = b64_val(input[ip + 1])?;
        if b & 0x0f != 0 {
            return Err(PairError::BadCharset);
        }
        out[op] = ((a << 2) | (b >> 4)) as u8;
        op += 1;
    } else if tail == 3 {
        let a = b64_val(input[ip])?;
        let b = b64_val(input[ip + 1])?;
        let c = b64_val(input[ip + 2])?;
        if c & 0x03 != 0 {
            return Err(PairError::BadCharset);
        }
        out[op] = ((a << 2) | (b >> 4)) as u8;
        out[op + 1] = ((b & 0x0f) << 4) | ((c >> 2) & 0x0f);
        op += 2;
    }
    Ok(op)
}

/// Encode a binary record as ASCII transport text
/// (`LMESH1:` + base64url, no padding). Returns bytes written to `out`.
pub fn transport_encode(record: &[u8], out: &mut [u8]) -> Result<usize, PairError> {
    if record.is_empty() {
        return Err(PairError::BadLength);
    }
    if out.len() < transport_encoded_len(record.len()) {
        return Err(PairError::BufferTooSmall);
    }
    out[..TRANSPORT_PREFIX.len()].copy_from_slice(TRANSPORT_PREFIX);
    let n = b64_encode_into(record, &mut out[TRANSPORT_PREFIX.len()..])?;
    Ok(TRANSPORT_PREFIX.len() + n)
}

/// Strictly decode ASCII transport text back into raw record bytes
/// (validates prefix, charset, padding absence and length).
/// Returns the record length written to `out`; `out[0]` is the record type.
pub fn decode_transport(ascii: &[u8], out: &mut [u8]) -> Result<usize, PairError> {
    if ascii.len() < TRANSPORT_PREFIX.len() || &ascii[..TRANSPORT_PREFIX.len()] != TRANSPORT_PREFIX
    {
        return Err(PairError::BadPrefix);
    }
    let body = &ascii[TRANSPORT_PREFIX.len()..];
    if body.is_empty() {
        return Err(PairError::BadLength);
    }
    b64_decode_into(body, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> Offer {
        Offer {
            ed_pub: [0x11; ED_PUB_LEN],
            eph_pub: [0x22; EPH_PUB_LEN],
            challenge: [0x33; CHALLENGE_LEN],
        }
    }

    fn sample_proof() -> Proof {
        Proof {
            t: [0x44; T_LEN],
            role: ROLE_L,
            ct: [0x55; PROOF_CT_LEN],
            sig: [0x66; SIG_LEN],
        }
    }

    fn sample_confirm() -> Confirmation {
        Confirmation {
            t: [0x77; T_LEN],
            role: ROLE_R,
            mac: [0x88; MAC_LEN],
        }
    }

    fn ascii_str(buf: &[u8]) -> &str {
        core::str::from_utf8(buf).unwrap()
    }

    #[test]
    fn offer_record_round_trip() {
        let offer = sample_offer();
        let mut record = [0u8; OFFER_RECORD_LEN];
        assert_eq!(encode_offer_record(&offer, &mut record), Ok(98));
        assert_eq!(record[0], RECORD_OFFER);
        let back = decode_offer_record(&record).unwrap();
        assert_eq!(back, offer);
    }

    #[test]
    fn offer_payload_round_trip_matches_record_tail() {
        let offer = sample_offer();
        let mut payload = [0u8; OFFER_PAYLOAD_LEN];
        assert_eq!(encode_offer_payload(&offer, &mut payload), Ok(97));
        assert_eq!(payload[0], OFFER_VERSION);
        assert_eq!(decode_offer_payload(&payload), Ok(offer));

        let mut record = [0u8; OFFER_RECORD_LEN];
        encode_offer_record(&sample_offer(), &mut record).unwrap();
        assert_eq!(offer_record_payload(&record).unwrap(), &payload);
    }

    #[test]
    fn proof_round_trip() {
        let proof = sample_proof();
        let mut record = [0u8; PROOF_RECORD_LEN];
        assert_eq!(encode_proof(&proof, &mut record), Ok(122));
        assert_eq!(record[0], RECORD_PROOF);
        assert_eq!(record[1 + T_LEN], ROLE_L);
        assert_eq!(decode_proof(&record), Ok(proof));
    }

    #[test]
    fn confirm_round_trip() {
        let conf = sample_confirm();
        let mut record = [0u8; CONFIRM_RECORD_LEN];
        assert_eq!(encode_confirmation(&conf, &mut record), Ok(66));
        assert_eq!(record[0], RECORD_CONFIRM);
        assert_eq!(decode_confirmation(&record), Ok(conf));
    }

    #[test]
    fn transport_no_pad_vectors() {
        // 3 bytes -> 4 chars, exact multiple.
        let mut text = [0u8; 16];
        let n = transport_encode(&[0x01, 0x02, 0x03], &mut text).unwrap();
        assert_eq!(ascii_str(&text[..n]), "LMESH1:AQID");
        // 1 byte -> 2 chars, no padding.
        let n = transport_encode(&[0x01], &mut text).unwrap();
        assert_eq!(ascii_str(&text[..n]), "LMESH1:AQ");
        // 2 bytes -> 3 chars, no padding.
        let n = transport_encode(&[0x01, 0x02], &mut text).unwrap();
        assert_eq!(ascii_str(&text[..n]), "LMESH1:AQI");
        // URL-safe alphabet: 0xFF -> "_w", 0xFFFF -> "__8".
        let n = transport_encode(&[0xFF], &mut text).unwrap();
        assert_eq!(ascii_str(&text[..n]), "LMESH1:_w");
        let n = transport_encode(&[0xFF, 0xFF], &mut text).unwrap();
        assert_eq!(ascii_str(&text[..n]), "LMESH1:__8");
        // Every vector decodes back byte-for-byte.
        let mut raw = [0u8; 8];
        let vectors: [&[u8]; 5] = [
            &[0x01],
            &[0x01, 0x02],
            &[0x01, 0x02, 0x03],
            &[0xFF],
            &[0xFF, 0xFF],
        ];
        for v in vectors {
            let n = transport_encode(v, &mut text).unwrap();
            let m = decode_transport(&text[..n], &mut raw).unwrap();
            assert_eq!(&raw[..m], v);
        }

        // Full offer record survives transport with no '=' anywhere.
        let mut record = [0u8; OFFER_RECORD_LEN];
        encode_offer_record(&sample_offer(), &mut record).unwrap();
        let mut big_text = [0u8; 256];
        let n = transport_encode(&record, &mut big_text).unwrap();
        assert_eq!(n, transport_encoded_len(OFFER_RECORD_LEN));
        assert!(!big_text[..n].contains(&b'='));
        let mut back = [0u8; OFFER_RECORD_LEN];
        let m = decode_transport(&big_text[..n], &mut back).unwrap();
        assert_eq!(m, OFFER_RECORD_LEN);
        assert_eq!(&back[..m], &record);
    }

    #[test]
    fn transport_rejects_bad_prefix() {
        let mut raw = [0u8; 8];
        assert_eq!(
            decode_transport(b"XXXX:AQID", &mut raw),
            Err(PairError::BadPrefix)
        );
        assert_eq!(
            decode_transport(b"LMESH:AQID", &mut raw),
            Err(PairError::BadPrefix)
        );
        assert_eq!(
            decode_transport(b"LMESH", &mut raw),
            Err(PairError::BadPrefix)
        );
        assert_eq!(decode_transport(b"", &mut raw), Err(PairError::BadPrefix));
    }

    #[test]
    fn transport_rejects_bad_charset_and_padding() {
        let mut raw = [0u8; 16];
        assert_eq!(
            decode_transport(b"LMESH1:AQID!!!", &mut raw),
            Err(PairError::BadCharset)
        );
        // Padding is never emitted and never accepted.
        assert_eq!(
            decode_transport(b"LMESH1:AQID====", &mut raw),
            Err(PairError::BadCharset)
        );
        assert_eq!(
            decode_transport(b"LMESH1:AQID AQI", &mut raw),
            Err(PairError::BadCharset)
        );
        // Non-canonical trailing bits are rejected.
        assert_eq!(
            decode_transport(b"LMESH1:AR", &mut raw),
            Err(PairError::BadCharset)
        );
        assert_eq!(
            decode_transport(b"LMESH1:AQR", &mut raw),
            Err(PairError::BadCharset)
        );
    }

    #[test]
    fn transport_rejects_bad_body_length() {
        let mut raw = [0u8; 16];
        // 5 chars: 4k+1 is unrepresentable without padding.
        assert_eq!(
            decode_transport(b"LMESH1:ABCDE", &mut raw),
            Err(PairError::BadLength)
        );
        // Empty body carries no record.
        assert_eq!(
            decode_transport(b"LMESH1:", &mut raw),
            Err(PairError::BadLength)
        );
        // Empty record never encodes.
        let mut text = [0u8; 16];
        assert_eq!(transport_encode(&[], &mut text), Err(PairError::BadLength));
    }

    #[test]
    fn transport_rejects_small_buffers() {
        let mut tiny = [0u8; 4];
        assert_eq!(
            transport_encode(&[0x01, 0x02, 0x03], &mut tiny),
            Err(PairError::BufferTooSmall)
        );
        let mut raw = [0u8; 1];
        assert_eq!(
            decode_transport(b"LMESH1:AQID", &mut raw),
            Err(PairError::BufferTooSmall)
        );
    }

    #[test]
    fn rejects_self_pairing() {
        let key = [0x99; ED_PUB_LEN];
        assert_eq!(check_not_self(&key, &key), Err(PairError::SelfPairing));
        let other = [0x9A; ED_PUB_LEN];
        assert_eq!(check_not_self(&key, &other), Ok(()));
    }

    #[test]
    fn rejects_bad_offer_length_type_version() {
        let mut record = [0u8; OFFER_RECORD_LEN];
        encode_offer_record(&sample_offer(), &mut record).unwrap();
        assert_eq!(
            decode_offer_record(&record[..OFFER_RECORD_LEN - 1]),
            Err(PairError::BadLength)
        );
        let mut long = [0u8; OFFER_RECORD_LEN + 1];
        long[..OFFER_RECORD_LEN].copy_from_slice(&record);
        assert_eq!(decode_offer_record(&long), Err(PairError::BadLength));

        let mut wrong_type = record;
        wrong_type[0] = 0x09;
        assert_eq!(decode_offer_record(&wrong_type), Err(PairError::BadType));
        // A proof record fed to the offer decoder reports its type, not length.
        let mut proof_record = [0u8; PROOF_RECORD_LEN];
        encode_proof(&sample_proof(), &mut proof_record).unwrap();

        let mut wrong_ver = record;
        wrong_ver[1] = 0x07;
        assert_eq!(decode_offer_record(&wrong_ver), Err(PairError::BadVersion));
        assert_eq!(
            decode_offer_payload(&[0u8; OFFER_PAYLOAD_LEN - 1]),
            Err(PairError::BadLength)
        );
    }

    #[test]
    fn rejects_bad_proof_length_type_role() {
        let mut record = [0u8; PROOF_RECORD_LEN];
        encode_proof(&sample_proof(), &mut record).unwrap();
        assert_eq!(
            decode_proof(&record[..PROOF_RECORD_LEN - 1]),
            Err(PairError::BadLength)
        );
        let mut wrong_type = record;
        wrong_type[0] = RECORD_OFFER;
        assert_eq!(decode_proof(&wrong_type), Err(PairError::BadType));
        let mut bad_role = record;
        bad_role[1 + T_LEN] = 2;
        assert_eq!(decode_proof(&bad_role), Err(PairError::BadRole));

        let bad = Proof {
            role: 7,
            ..sample_proof()
        };
        let mut out = [0u8; PROOF_RECORD_LEN];
        assert_eq!(encode_proof(&bad, &mut out), Err(PairError::BadRole));
    }

    #[test]
    fn rejects_bad_confirm_length_type_role() {
        let mut record = [0u8; CONFIRM_RECORD_LEN];
        encode_confirmation(&sample_confirm(), &mut record).unwrap();
        assert_eq!(
            decode_confirmation(&record[..CONFIRM_RECORD_LEN - 1]),
            Err(PairError::BadLength)
        );
        let mut wrong_type = record;
        wrong_type[0] = RECORD_PROOF;
        assert_eq!(decode_confirmation(&wrong_type), Err(PairError::BadType));
        let mut bad_role = record;
        bad_role[1 + T_LEN] = 0xFF;
        assert_eq!(decode_confirmation(&bad_role), Err(PairError::BadRole));

        let bad = Confirmation {
            role: 3,
            ..sample_confirm()
        };
        let mut out = [0u8; CONFIRM_RECORD_LEN];
        assert_eq!(encode_confirmation(&bad, &mut out), Err(PairError::BadRole));
    }

    #[test]
    fn roles_follow_lexicographic_key_order() {
        let small = [0x01; ED_PUB_LEN];
        let large = [0x02; ED_PUB_LEN];
        assert_eq!(role_for(&small, &large), ROLE_L);
        assert_eq!(role_for(&large, &small), ROLE_R);
        // Order is decided by the first differing byte, not length or sum.
        let mut a = [0x00; ED_PUB_LEN];
        let mut b = [0x00; ED_PUB_LEN];
        a[31] = 0x01;
        b[0] = 0x01;
        assert_eq!(role_for(&a, &b), ROLE_L);
        assert_eq!(role_for(&b, &a), ROLE_R);
    }

    #[test]
    fn expiry_boundary_599_600_601() {
        assert!(!is_expired(1000, 1599));
        assert!(is_expired(1000, 1600));
        assert!(is_expired(1000, 1601));
        assert!(!is_expired(1000, 1000));
        // Backwards monotonic reading never reports expiry.
        assert!(!is_expired(2000, 1000));
    }

    #[test]
    fn fingerprint_vector() {
        let mut t = [0u8; T_LEN];
        t[..8].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]);
        assert_eq!(&transcript_fingerprint(&t), b"abcdef0123456789");
        let zero = [0u8; T_LEN];
        assert_eq!(&transcript_fingerprint(&zero), b"0000000000000000");
    }
}
