//! Compact frame codec (Phase 1). Big-endian multibyte integers.
//!
//! Layout: ver(1) flags(1) dst(4) src(4) pkt_id(4) hops(1) epoch(4)
//! seq(8) with body_len byte at offset 27, then body(var), crc16(2).
pub const HEADER_LEN: usize = 28;
pub const CRC_LEN: usize = 2;
pub const MIN_FRAME_LEN: usize = HEADER_LEN + CRC_LEN;
pub const MAX_FRAME_LEN: usize = 255;
pub const MAX_TEXT_LEN: usize = 160;

pub const VERSION_PLAINTEXT_LAB: u8 = 0;
pub const VERSION_SECURE: u8 = 1;

pub const FLAG_WANT_ACK: u8 = 0x01;
pub const FLAGS_VALID_MASK: u8 = FLAG_WANT_ACK;

pub const BODY_DATA: u8 = 0x01;
pub const BODY_ACK: u8 = 0x02;
pub const TAG_LEN: usize = 16;

/// Secure DATA max frame length: 28 header + 177 body + 2 CRC.
pub const SECURE_DATA_MAX: usize = 207;
/// Secure ACK length: 28 header + 33 body + 2 CRC.
pub const SECURE_ACK_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub dst: u32,
    pub src: u32,
    pub packet_id: u32,
    pub hops: u8,
    pub epoch: u32,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooShort,
    TooLong,
    LengthMismatch,
    BadCrc,
    UnknownVersion,
    BadFlags,
    BadHops,
    BadBody,
}

/// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF. `"123456789"` -> 0x29B1.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub fn encode_header(h: &Header, out: &mut [u8]) -> Result<usize, Reject> {
    if out.len() < HEADER_LEN {
        return Err(Reject::TooShort);
    }
    out[0] = h.version;
    out[1] = h.flags;
    out[2..6].copy_from_slice(&h.dst.to_be_bytes());
    out[6..10].copy_from_slice(&h.src.to_be_bytes());
    out[10..14].copy_from_slice(&h.packet_id.to_be_bytes());
    out[14] = h.hops;
    out[15..19].copy_from_slice(&h.epoch.to_be_bytes());
    out[19..27].copy_from_slice(&h.sequence.to_be_bytes());
    out[27] = 0;
    Ok(HEADER_LEN)
}

/// Encode a full frame. `body_len` byte at offset 27 includes the
/// 16-byte auth tag in secure mode. Returns total frame length.
pub fn encode_frame(h: &Header, body: &[u8], out: &mut [u8]) -> Result<usize, Reject> {
    let total = HEADER_LEN + body.len() + CRC_LEN;
    if total > MAX_FRAME_LEN || out.len() < total {
        return Err(Reject::TooLong);
    }
    encode_header(h, out)?;
    out[27] = body.len() as u8;
    out[HEADER_LEN..HEADER_LEN + body.len()].copy_from_slice(body);
    let crc = crc16(&out[..HEADER_LEN + body.len()]);
    out[HEADER_LEN + body.len()..total].copy_from_slice(&crc.to_be_bytes());
    Ok(total)
}

/// Validate and split a received frame, including plaintext-lab bodies.
/// Secure bodies remain opaque: endpoints must authenticate, then call
/// `validate_body` on the decrypted bytes before using their contents.
pub fn decode_frame(frame: &[u8]) -> Result<(Header, &[u8]), Reject> {
    if frame.len() < MIN_FRAME_LEN {
        return Err(Reject::TooShort);
    }
    if frame.len() > MAX_FRAME_LEN {
        return Err(Reject::TooLong);
    }
    if frame[0] != VERSION_PLAINTEXT_LAB && frame[0] != VERSION_SECURE {
        return Err(Reject::UnknownVersion);
    }
    if frame[1] & !FLAGS_VALID_MASK != 0 {
        return Err(Reject::BadFlags);
    }
    if frame[14] > 1 {
        return Err(Reject::BadHops);
    }
    let body_len = frame[27] as usize;
    if HEADER_LEN + body_len + CRC_LEN != frame.len() {
        return Err(Reject::LengthMismatch);
    }
    let body_end = 28 + body_len;
    let want = u16::from_be_bytes([frame[body_end], frame[body_end + 1]]);
    if crc16(&frame[..body_end]) != want {
        return Err(Reject::BadCrc);
    }
    let h = Header {
        version: frame[0],
        flags: frame[1],
        dst: u32::from_be_bytes(frame[2..6].try_into().unwrap()),
        src: u32::from_be_bytes(frame[6..10].try_into().unwrap()),
        packet_id: u32::from_be_bytes(frame[10..14].try_into().unwrap()),
        hops: frame[14],
        epoch: u32::from_be_bytes(frame[15..19].try_into().unwrap()),
        sequence: u64::from_be_bytes(frame[19..27].try_into().unwrap()),
    };
    let body = &frame[HEADER_LEN..body_end];
    if h.version == VERSION_PLAINTEXT_LAB {
        validate_body(h.flags, body)?;
    }
    Ok((h, body))
}

/// Validate a plaintext DATA/ACK body and its authenticated flag agreement.
pub fn validate_body(flags: u8, body: &[u8]) -> Result<(), Reject> {
    match body.first() {
        Some(&BODY_DATA) if flags == FLAG_WANT_ACK => {
            let text = &body[1..];
            if text.is_empty() || text.len() > MAX_TEXT_LEN || core::str::from_utf8(text).is_err() {
                return Err(Reject::BadBody);
            }
            Ok(())
        }
        Some(&BODY_ACK) if flags == 0 && body.len() == 17 => Ok(()),
        _ => Err(Reject::BadBody),
    }
}

/// Build a plaintext-lab DATA body: 0x01 || UTF-8, 1..=160 text bytes.
pub fn encode_data_body(text: &[u8], out: &mut [u8]) -> Result<usize, Reject> {
    if text.is_empty()
        || text.len() > MAX_TEXT_LEN
        || out.len() < 1 + text.len()
        || core::str::from_utf8(text).is_err()
    {
        return Err(Reject::BadBody);
    }
    out[0] = BODY_DATA;
    out[1..1 + text.len()].copy_from_slice(text);
    Ok(1 + text.len())
}

/// Build an ACK body: 0x02 || epoch u32 || seq u64 || packet_id u32.
pub fn encode_ack_body(epoch: u32, seq: u64, packet_id: u32, out: &mut [u8]) -> Result<usize, Reject> {
    if out.len() < 17 {
        return Err(Reject::BadBody);
    }
    out[0] = BODY_ACK;
    out[1..5].copy_from_slice(&epoch.to_be_bytes());
    out[5..13].copy_from_slice(&seq.to_be_bytes());
    out[13..17].copy_from_slice(&packet_id.to_be_bytes());
    Ok(17)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HEADER: Header = Header {
        version: VERSION_PLAINTEXT_LAB,
        flags: FLAG_WANT_ACK,
        dst: 2,
        src: 1,
        packet_id: 7,
        hops: 1,
        epoch: 500,
        sequence: 1,
    };

    #[test]
    fn short_header_output_is_rejected_without_partial_write() {
        for len in 0..HEADER_LEN {
            let mut out = [0xA5; HEADER_LEN];
            assert_eq!(encode_header(&HEADER, &mut out[..len]), Err(Reject::TooShort));
            assert_eq!(out, [0xA5; HEADER_LEN]);
        }
    }

    #[test]
    fn data_encoder_rejects_non_utf8_without_writing() {
        let mut out = [0xA5; 8];
        assert_eq!(encode_data_body(&[0xC0, 0xAF], &mut out), Err(Reject::BadBody));
        assert_eq!(out, [0xA5; 8]);
    }

    #[test]
    fn valid_crc_does_not_allow_malformed_lab_body() {
        let invalid: &[(u8, &[u8])] = &[
            (FLAG_WANT_ACK, &[]),
            (FLAG_WANT_ACK, &[BODY_DATA]),
            (FLAG_WANT_ACK, &[BODY_DATA, 0xFF]),
            (FLAG_WANT_ACK, &[0x03, b'a']),
            (0, &[BODY_DATA, b'a']),
            (0, &[BODY_ACK, 0]),
        ];
        let mut frame = [0; MAX_FRAME_LEN];
        for &(flags, body) in invalid {
            let header = Header { flags, ..HEADER };
            let n = encode_frame(&header, body, &mut frame).unwrap();
            assert_eq!(decode_frame(&frame[..n]), Err(Reject::BadBody));
        }
        let mut body = [b'x'; MAX_TEXT_LEN + 2];
        body[0] = BODY_DATA;
        let n = encode_frame(&HEADER, &body, &mut frame).unwrap();
        assert_eq!(decode_frame(&frame[..n]), Err(Reject::BadBody));

        let mut ack = [0; 18];
        encode_ack_body(500, 1, 7, &mut ack).unwrap();
        let n = encode_frame(&HEADER, &ack[..17], &mut frame).unwrap();
        assert_eq!(decode_frame(&frame[..n]), Err(Reject::BadBody));
        let header = Header { flags: 0, ..HEADER };
        let n = encode_frame(&header, &ack, &mut frame).unwrap();
        assert_eq!(decode_frame(&frame[..n]), Err(Reject::BadBody));
        let n = encode_frame(&header, &ack[..17], &mut frame).unwrap();
        assert_eq!(decode_frame(&frame[..n]), Ok((header, &ack[..17])));
    }

    #[test]
    fn secure_ciphertext_is_not_parsed_as_plaintext() {
        let header = Header { version: VERSION_SECURE, ..HEADER };
        let body = [0xFF; 32];
        let mut frame = [0; MAX_FRAME_LEN];
        let n = encode_frame(&header, &body, &mut frame).unwrap();
        assert_eq!(decode_frame(&frame[..n]), Ok((header, body.as_slice())));
        assert_eq!(validate_body(header.flags, &body), Err(Reject::BadBody));
    }

    #[test]
    fn crc_vector() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn round_trip() {
        let h = Header {
            version: 0,
            flags: FLAG_WANT_ACK,
            dst: 2,
            src: 1,
            packet_id: 0xDEAD_BEEF,
            hops: 0,
            epoch: 0,
            sequence: 7,
        };
        let mut body = [0u8; 32];
        let bl = encode_data_body(b"hello", &mut body).unwrap();
        let mut frame = [0u8; 255];
        let n = encode_frame(&h, &body[..bl], &mut frame).unwrap();
        let (h2, b2) = decode_frame(&frame[..n]).unwrap();
        assert_eq!(h, h2);
        assert_eq!(b2, &body[..bl]);
    }

    #[test]
    fn rejects_corrupt_and_malformed() {
        let h = Header {
            version: 0,
            flags: FLAG_WANT_ACK,
            dst: 2,
            src: 1,
            packet_id: 1,
            hops: 0,
            epoch: 0,
            sequence: 0,
        };
        let mut body = [0u8; 32];
        let bl = encode_data_body(b"hi", &mut body).unwrap();
        let mut frame = [0u8; 255];
        let n = encode_frame(&h, &body[..bl], &mut frame).unwrap();

        let mut bad = frame;
        bad[n - 1] ^= 0x01;
        assert_eq!(decode_frame(&bad[..n]), Err(Reject::BadCrc));

        assert_eq!(decode_frame(&frame[..10]), Err(Reject::TooShort));

        let mut bad = frame;
        bad[0] = 9;
        let mut bad2 = [0u8; 255];
        bad2[..n].copy_from_slice(&bad[..n]);
        // recompute crc so the version check fires first
        let c = crc16(&bad2[..n - 2]);
        bad2[n - 2..n].copy_from_slice(&c.to_be_bytes());
        assert_eq!(decode_frame(&bad2[..n]), Err(Reject::UnknownVersion));

        let mut bad = frame;
        bad[1] = 0x02;
        let mut bad3 = [0u8; 255];
        bad3[..n].copy_from_slice(&bad[..n]);
        let c = crc16(&bad3[..n - 2]);
        bad3[n - 2..n].copy_from_slice(&c.to_be_bytes());
        assert_eq!(decode_frame(&bad3[..n]), Err(Reject::BadFlags));

        let mut bad = frame;
        bad[14] = 2;
        let mut bad4 = [0u8; 255];
        bad4[..n].copy_from_slice(&bad[..n]);
        let c = crc16(&bad4[..n - 2]);
        bad4[n - 2..n].copy_from_slice(&c.to_be_bytes());
        assert_eq!(decode_frame(&bad4[..n]), Err(Reject::BadHops));

        assert_eq!(decode_frame(&frame[..n - 1]), Err(Reject::LengthMismatch));
    }

    #[test]
    fn oversize_text_rejected() {
        let mut body = [0u8; 200];
        assert_eq!(encode_data_body(&[b'x'; 161], &mut body), Err(Reject::BadBody));
        assert_eq!(encode_data_body(&[], &mut body), Err(Reject::BadBody));
    }

    #[test]
    fn ack_body_layout() {
        let mut out = [0u8; 17];
        assert_eq!(encode_ack_body(0x11223344, 0x0102030405060708, 0xAABBCCDD, &mut out), Ok(17));
        assert_eq!(out[0], BODY_ACK);
        assert_eq!(&out[1..5], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&out[13..17], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
