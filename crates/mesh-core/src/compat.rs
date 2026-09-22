//! INSECURE-only receive parser for Meshtastic over-the-air frames.
//!
//! INSECURE: Meshtastic compat traffic uses a shared channel PSK that
//! decrypts all traffic, has no forward secrecy, floods up to 7 hops, and
//! may leak via MQTT bridging. Anything decoded by this module MUST be
//! treated as public, unauthenticated, untrusted display bytes only.
//!
//! Scope (decode ONLY, behind the non-default `meshtastic` cargo feature):
//!
//! - Decode a raw Meshtastic `MeshPacket` payload (protobuf, `decoded`
//!   form only) into sender/destination/portnum bytes for display.
//! - NEVER encrypt, encode, or send as Meshtastic: this module has no
//!   `encode`/`send`/`encrypt` path by design.
//! - NEVER handle channel PSKs. Packets carrying the `encrypted` field
//!   yield `encrypted: true` with no payload access — there is
//!   deliberately no key/decrypt API here.
//! - NEVER touch the private secure mesh protocol (LMESH framing, X25519
//!   pairing, ChaCha20-Poly1305 traffic keys). No import from any secure
//!   module; `core` only.
//!
//! Caller contract (encrypted-path-only): compat bytes ride INSIDE the
//! existing encrypted LMESH DATA body and are handed to
//! [`parse_packet`] only after endpoint decryption. This module never
//! sees raw RF, never retunes the modem, and never bypasses the secure
//! frame path. RF capture (second, Meshtastic-tuned radio) and any
//! forwarding policy live outside this module.

use core::str;

/// INSECURE: Meshtastic broadcast destination (`^all` / `0xFFFFFFFF`).
pub const BROADCAST_ADDR: u32 = 0xFFFF_FFFF;

/// INSECURE: largest LoRa payload this parser accepts. Oversize input is
/// rejected, never truncated-and-decoded.
pub const MAX_COMPAT_FRAME_LEN: usize = 512;

/// INSECURE: text-message portnum (`TEXT_MESSAGE_APP`).
pub const PORT_TEXT: u32 = 1;
/// INSECURE: position portnum (`POSITION_APP`).
pub const PORT_POSITION: u32 = 3;

/// Decode failure modes. No payload data is exposed on error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatError {
    /// Input was empty.
    Empty,
    /// Input exceeded [`MAX_COMPAT_FRAME_LEN`].
    TooLong,
    /// No protobuf fields found.
    NoFields,
    /// Buffer ended mid-field.
    Truncated,
    /// Illegal protobuf tag (field number 0).
    BadTag,
    /// Varint exceeded 10 bytes / overflowed u64.
    VarintOverflow,
    /// Unsupported protobuf wire type (3, 4, 6, 7).
    UnsupportedWire,
    /// Duplicate `decoded` field or duplicate `Data` payload.
    Duplicate,
    /// Packet carried both `decoded` and `encrypted`.
    BothDecodedAndEncrypted,
    /// Packet carried neither `decoded` nor `encrypted`.
    NeitherDecodedNorEncrypted,
    /// Text payload is not valid UTF-8.
    BadUtf8,
    /// Text payload was empty.
    TextEmpty,
    /// Signed int32 varint out of range.
    Int32OutOfRange,
}

/// INSECURE: decoded `Data` envelope of one public packet. `payload` borrows
/// the input buffer; no allocation, no copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatData<'a> {
    /// Meshtastic `portnum` value.
    pub portnum: u32,
    /// Raw `payload` bytes (borrowed).
    pub payload: &'a [u8],
}

impl<'a> CompatData<'a> {
    /// INSECURE: interpret the payload as a text message. Validates UTF-8
    /// strictly (no lossy replacement); rejects empty payloads.
    pub fn text(&self) -> Result<&'a str, CompatError> {
        if self.payload.is_empty() {
            return Err(CompatError::TextEmpty);
        }
        str::from_utf8(self.payload).map_err(|_| CompatError::BadUtf8)
    }

    /// Best-effort `(latitude, longitude)` in degrees from a `POSITION_APP`
    /// payload. Only `latitude_i` (field 1, sfixed32) and `longitude_i`
    /// (field 2, sfixed32), scaled by 1e7, are extracted; `(None, None)`
    /// when neither is present. Other position fields are ignored.
    pub fn position(&self) -> (Option<f32>, Option<f32>) {
        let mut latitude: Option<f32> = None;
        let mut longitude: Option<f32> = None;
        let mut fields = ProtoFields::new(self.payload);
        loop {
            match fields.next() {
                None => break,
                Some(Err(_)) => break,
                Some(Ok((field_no, wire, value))) => {
                    if wire != Wire::Fixed32 {
                        continue;
                    }
                    let bits = match value {
                        FieldVal::Fixed32(b) => b,
                        _ => continue,
                    };
                    #[allow(clippy::cast_possible_wrap)]
                    let raw = bits as i32;
                    // f32 has 24-bit mantissa; 1e7-scaled i32 degrees lose
                    // sub-meter precision here — display-only, acceptable.
                    #[allow(clippy::cast_precision_loss)]
                    let deg = raw as f32 / 10_000_000.0;
                    if field_no == 1 && latitude.is_none() {
                        latitude = Some(deg);
                    } else if field_no == 2 && longitude.is_none() {
                        longitude = Some(deg);
                    }
                }
            }
        }
        (latitude, longitude)
    }
}

/// INSECURE: one decoded public Meshtastic `MeshPacket`. All slices borrow
/// the input buffer; `unknown_count` saturates at 255.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatPacket<'a> {
    /// `from` node id (fixed32 field 1).
    pub from_id: u32,
    /// `to` node id (fixed32 field 2).
    pub to_id: u32,
    /// Channel index (varint field 3).
    pub channel: u64,
    /// Packet id (fixed32 field 6).
    pub packet_id: u32,
    /// Remaining hop limit (varint field 9).
    pub hop_limit: u64,
    /// Original hop count (varint field 15).
    pub hop_start: u64,
    /// `want_ack` flag (varint field 10).
    pub want_ack: bool,
    /// `via_mqtt` flag (varint field 14).
    pub via_mqtt: bool,
    /// RX timestamp (fixed32 field 7; sender-local, unauthenticated).
    pub rx_time: u32,
    /// Raw RX SNR float bits (fixed32 field 8), if present.
    pub rx_snr_bits: Option<u32>,
    /// RX RSSI in dBm (varint field 12, int32), if present.
    pub rx_rssi: Option<i32>,
    /// Decoded `Data` envelope; `None` for channel-encrypted packets.
    pub data: Option<CompatData<'a>>,
    /// True when the packet carries the `encrypted` field (opaque by design).
    pub encrypted: bool,
    /// Length of the opaque `encrypted` bytes (0 for `decoded` packets).
    pub encrypted_len: usize,
    /// Count of skipped unknown field numbers (saturates at 255).
    pub unknown_count: u8,
}

/// INSECURE: display label for a Meshtastic `portnum` value. Unknown values
/// are display-only names, never dispatched.
#[must_use]
pub fn portnum_name(portnum: u32) -> &'static str {
    match portnum {
        0 => "UNKNOWN",
        1 => "TEXT_MESSAGE_APP",
        2 => "REMOTE_HARDWARE_APP",
        3 => "POSITION_APP",
        4 => "NODEINFO_APP",
        5 => "ROUTING_APP",
        6 => "ADMIN_APP",
        7 => "TEXT_MESSAGE_COMPRESSED_APP",
        8 => "WAYPOINT_APP",
        9 => "AUDIO_APP",
        10 => "DETECTION_SENSOR_APP",
        11 => "ALERT_APP",
        12 => "KEY_VERIFICATION_APP",
        13 => "REPLY_APP",
        14 => "IP_TUNNEL_APP",
        15 => "SERIAL_APP",
        16 => "STORE_FORWARD_APP",
        17 => "RANGE_TEST_APP",
        18 => "TELEMETRY_APP",
        19 => "ZPS_APP",
        20 => "ATAK_PLUGIN",
        21 => "MAP_REPORT_APP",
        22 => "POWERSTRESS_APP",
        32 => "PRIVATE_APP",
        33 => "ATAK_FORWARDER",
        64 => "SIMULATOR_APP",
        256 => "TRACEROUTE_APP",
        257 => "NEIGHBORINFO_APP",
        _ => "UNKNOWN",
    }
}

/// INSECURE: parse one raw Meshtastic payload into a public packet.
///
/// Only unencrypted (`decoded`) packets yield `data`. Packets carrying the
/// `encrypted` field yield `encrypted: true` with no payload access.
/// Returns [`CompatError`] on empty, oversize, or malformed input.
pub fn parse_packet(raw: &[u8]) -> Result<CompatPacket<'_>, CompatError> {
    if raw.is_empty() {
        return Err(CompatError::Empty);
    }
    if raw.len() > MAX_COMPAT_FRAME_LEN {
        return Err(CompatError::TooLong);
    }

    let mut pkt = CompatPacket {
        from_id: 0,
        to_id: 0,
        channel: 0,
        packet_id: 0,
        hop_limit: 0,
        hop_start: 0,
        want_ack: false,
        via_mqtt: false,
        rx_time: 0,
        rx_snr_bits: None,
        rx_rssi: None,
        data: None,
        encrypted: false,
        encrypted_len: 0,
        unknown_count: 0,
    };
    let mut fields = ProtoFields::new(raw);
    while let Some(item) = fields.next() {
        let (field_no, wire, value) = item?;
        match (field_no, wire) {
            (1, Wire::Fixed32) => pkt.from_id = fixed32(value),
            (2, Wire::Fixed32) => pkt.to_id = fixed32(value),
            (3, Wire::Varint) => pkt.channel = varint(value),
            (4, Wire::Len) => {
                if pkt.data.is_some() {
                    return Err(CompatError::Duplicate);
                }
                pkt.data = Some(parse_data(len_bytes(value))?);
            }
            (5, Wire::Len) => {
                pkt.encrypted = true;
                pkt.encrypted_len = len_bytes(value).len();
            }
            (6, Wire::Fixed32) => pkt.packet_id = fixed32(value),
            (7, Wire::Fixed32) => pkt.rx_time = fixed32(value),
            (8, Wire::Fixed32) => pkt.rx_snr_bits = Some(fixed32(value)),
            (9, Wire::Varint) => pkt.hop_limit = varint(value),
            (10, Wire::Varint) => pkt.want_ack = varint(value) != 0,
            (12, Wire::Varint) => pkt.rx_rssi = Some(varint_to_int32(varint(value))?),
            (14, Wire::Varint) => pkt.via_mqtt = varint(value) != 0,
            (15, Wire::Varint) => pkt.hop_start = varint(value),
            // 64-bit values are RX metadata, skipped silently (never stored).
            (_, Wire::Fixed64) => {}
            _ => {
                pkt.unknown_count = pkt.unknown_count.saturating_add(1);
            }
        }
    }
    if pkt.data.is_some() && pkt.encrypted {
        return Err(CompatError::BothDecodedAndEncrypted);
    }
    if pkt.data.is_none() && !pkt.encrypted {
        return Err(CompatError::NeitherDecodedNorEncrypted);
    }
    Ok(pkt)
}

/// INSECURE: like [`parse_packet`] but returns `None` instead of an error,
/// so a receive loop can count-and-drop undecodable RF noise.
#[must_use]
pub fn try_parse_packet(raw: &[u8]) -> Option<CompatPacket<'_>> {
    parse_packet(raw).ok()
}

/// Decode a `Data` protobuf envelope (internal helper). All non-payload
/// `Data` fields (want_response, dest, source, request/reply ids, emoji,
/// bitfield) are skipped: display only.
fn parse_data(buf: &[u8]) -> Result<CompatData<'_>, CompatError> {
    let mut portnum: u32 = 0;
    let mut payload: &[u8] = &[];
    let mut seen_payload = false;

    let mut fields = ProtoFields::new(buf);
    while let Some(item) = fields.next() {
        let (field_no, wire, value) = item?;
        match (field_no, wire) {
            (1, Wire::Varint) => {
                let v = varint(value);
                portnum = u32::try_from(v).unwrap_or(u32::MAX);
            }
            (2, Wire::Len) => {
                if seen_payload {
                    return Err(CompatError::Duplicate);
                }
                seen_payload = true;
                payload = len_bytes(value);
            }
            _ => {}
        }
    }
    if payload.len() > MAX_COMPAT_FRAME_LEN {
        return Err(CompatError::TooLong);
    }
    Ok(CompatData { portnum, payload })
}

/// Protobuf wire types relevant to Meshtastic packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Varint,
    Fixed64,
    Len,
    Fixed32,
}

/// A decoded protobuf field value. `Fixed64` values are skipped (RX
/// metadata, unused for display) and never materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldVal<'a> {
    Varint(u64),
    Len(&'a [u8]),
    Fixed32(u32),
}

fn varint(v: FieldVal<'_>) -> u64 {
    match v {
        FieldVal::Varint(n) => n,
        _ => 0,
    }
}

fn fixed32(v: FieldVal<'_>) -> u32 {
    match v {
        FieldVal::Fixed32(b) => b,
        _ => 0,
    }
}

fn len_bytes<'a>(v: FieldVal<'a>) -> &'a [u8] {
    match v {
        FieldVal::Len(b) => b,
        _ => &[],
    }
}

/// Interpret a protobuf int32 varint as signed (internal helper).
fn varint_to_int32(value: u64) -> Result<i32, CompatError> {
    let signed = (value as u64) & 0xFFFF_FFFF_FFFF_FFFF;
    #[allow(clippy::cast_possible_wrap)]
    let as_i64 = signed as i64;
    if as_i64 < i64::from(i32::MIN) || as_i64 > i64::from(i32::MAX) {
        return Err(CompatError::Int32OutOfRange);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(as_i64 as i32)
}

/// Zero-allocation protobuf field iterator over a borrowed buffer.
struct ProtoFields<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoFields<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for ProtoFields<'a> {
    type Item = Result<(u32, Wire, FieldVal<'a>), CompatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = match read_varint(self.buf, &mut self.pos) {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };
        let field_no = tag >> 3;
        let wire_bits = (tag & 0x07) as u8;
        if field_no == 0 || field_no > u64::from(u32::MAX) {
            return Some(Err(CompatError::BadTag));
        }
        #[allow(clippy::cast_possible_truncation)]
        let field_no = field_no as u32;
        match wire_bits {
            0 => {
                let v = match read_varint(self.buf, &mut self.pos) {
                    Ok(v) => v,
                    Err(e) => return Some(Err(e)),
                };
                Some(Ok((field_no, Wire::Varint, FieldVal::Varint(v))))
            }
            1 => {
                // 64-bit values (RX metadata) are skipped, never stored.
                if self.pos + 8 > self.buf.len() {
                    return Some(Err(CompatError::Truncated));
                }
                self.pos += 8;
                Some(Ok((field_no, Wire::Fixed64, FieldVal::Varint(0))))
            }
            2 => {
                let len = match read_varint(self.buf, &mut self.pos) {
                    Ok(v) => v,
                    Err(e) => return Some(Err(e)),
                };
                if len > self.buf.len() as u64 {
                    return Some(Err(CompatError::Truncated));
                }
                #[allow(clippy::cast_possible_truncation)]
                let len = len as usize;
                if self.pos + len > self.buf.len() {
                    return Some(Err(CompatError::Truncated));
                }
                let bytes = &self.buf[self.pos..self.pos + len];
                self.pos += len;
                Some(Ok((field_no, Wire::Len, FieldVal::Len(bytes))))
            }
            5 => {
                if self.pos + 4 > self.buf.len() {
                    return Some(Err(CompatError::Truncated));
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
                self.pos += 4;
                Some(Ok((
                    field_no,
                    Wire::Fixed32,
                    FieldVal::Fixed32(u32::from_le_bytes(b)),
                )))
            }
            _ => Some(Err(CompatError::UnsupportedWire)),
        }
    }
}

/// Read one protobuf varint at `*pos`, advancing past it (internal helper).
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, CompatError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return Err(CompatError::Truncated);
        }
        let byte = buf[*pos];
        *pos += 1;
        if shift >= 64 {
            return Err(CompatError::VarintOverflow);
        }
        if shift == 63 && byte & 0x7E != 0 {
            // Tenth byte carries only bit 63; higher bits mean >64-bit value.
            return Err(CompatError::VarintOverflow);
        }
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 70 {
            return Err(CompatError::VarintOverflow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-built MeshPacket: from=0x12345678 (f1 fixed32), to=broadcast
    // (f2 fixed32), decoded (f4) = Data{portnum=1, payload="Hi"},
    // id=0x2A (f6 fixed32).
    // 0D 78563412 | 15 FFFFFFFF | 22 06 080112024869 | 35 2A000000
    const TEXT_PKT: &[u8] = &[
        0x0D, 0x78, 0x56, 0x34, 0x12, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x22, 0x06, 0x08, 0x01, 0x12,
        0x02, 0x48, 0x69, 0x35, 0x2A, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn decodes_text_packet() {
        let pkt = parse_packet(TEXT_PKT).unwrap();
        assert_eq!(pkt.from_id, 0x1234_5678);
        assert_eq!(pkt.to_id, BROADCAST_ADDR);
        assert_eq!(pkt.packet_id, 0x2A);
        assert!(!pkt.encrypted);
        let data = pkt.data.unwrap();
        assert_eq!(data.portnum, PORT_TEXT);
        assert_eq!(data.text().unwrap(), "Hi");
        assert_eq!(portnum_name(data.portnum), "TEXT_MESSAGE_APP");
    }

    #[test]
    fn encrypted_packet_is_opaque() {
        // f5 (encrypted), 3 bytes: AA BB CC.
        let raw: &[u8] = &[0x2A, 0x03, 0xAA, 0xBB, 0xCC];
        let pkt = parse_packet(raw).unwrap();
        assert!(pkt.encrypted);
        assert_eq!(pkt.encrypted_len, 3);
        assert!(pkt.data.is_none());
    }

    #[test]
    fn rejects_empty_and_noise() {
        assert_eq!(parse_packet(&[]), Err(CompatError::Empty));
        assert!(try_parse_packet(&[0xFF, 0xFF, 0xFF]).is_none());
        // Both decoded and encrypted is rejected.
        let both: &[u8] = &[0x22, 0x00, 0x2A, 0x01, 0x00];
        assert_eq!(
            parse_packet(both),
            Err(CompatError::BothDecodedAndEncrypted)
        );
    }
}
