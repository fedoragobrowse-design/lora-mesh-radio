"""INSECURE-only receive parser for Meshtastic over-the-air frames.

INSECURE: Meshtastic compat traffic uses a shared channel PSK that
decrypts all traffic, has no forward secrecy, floods up to 7 hops, and
may leak via MQTT bridging. Anything decoded by this module MUST be
treated as public, unauthenticated, untrusted display text only.

Scope (receive-parse ONLY):

- Decode a raw LoRa payload captured by a SECOND radio tuned to
  Meshtastic parameters into sender/destination/portnum/text for
  display.
- NEVER encrypt, encode, or send as Meshtastic: this module has no
  ``encode``/``send``/``encrypt`` path by design.
- NEVER handle channel PSKs and NEVER import keys into the secure
  mesh path. Packets using channel encryption (``encrypted`` field) are
  reported as undecodable-by-design; no key API exists here.
- NEVER touch the private secure mesh protocol (LMESH framing, X25519
  pairing, ChaCha20-Poly1305 traffic keys). No import from any secure
  module; stdlib only.

Caller contract: pass the exact LoRa payload bytes delivered by the
second (Meshtastic-tuned) radio. RF capture, serial transport, and any
forwarding policy live outside this module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

__all__ = [
    "BROADCAST_ADDR",
    "MAX_FRAME_LEN",
    "MeshtasticParseError",
    "MeshtasticData",
    "MeshtasticPacket",
    "portnum_name",
    "parse_packet",
    "try_parse_packet",
    "format_packet",
]

#: INSECURE: Meshtastic broadcast destination (``^all`` / ``0xFFFFFFFF``).
BROADCAST_ADDR = 0xFFFFFFFF

#: INSECURE: largest LoRa payload this parser accepts. Oversize input is
#: rejected, never truncated-and-decoded.
MAX_FRAME_LEN = 512

#: INSECURE: known Meshtastic ``portnum`` values (subset used for display
#: labels; unknown values are reported as ``UNKNOWN(<n>)`` and dropped
#: to a length summary, never executed/dispatched).
_PORTNUM_NAMES = {
    0: "UNKNOWN_APP",
    1: "TEXT_MESSAGE_APP",
    2: "REMOTE_HARDWARE_APP",
    3: "POSITION_APP",
    4: "NODEINFO_APP",
    5: "ROUTING_APP",
    6: "ADMIN_APP",
    7: "TEXT_MESSAGE_COMPRESSED_APP",
    8: "WAYPOINT_APP",
    9: "AUDIO_APP",
    10: "DETECTION_SENSOR_APP",
    11: "ALERT_APP",
    12: "KEY_VERIFICATION_APP",
    32: "REPLY_APP",
    33: "IP_TUNNEL_APP",
    64: "SERIAL_APP",
    65: "STORE_FORWARD_APP",
    66: "RANGE_TEST_APP",
    67: "TELEMETRY_APP",
    68: "ZPS_APP",
    69: "SIMULATOR_APP",
    70: "TRACEROUTE_APP",
    71: "NEIGHBORINFO_APP",
    72: "ATAK_PLUGIN",
    73: "MAP_REPORT_APP",
    74: "POWERSTRESS_APP",
    256: "PRIVATE_APP",
    257: "ATAK_FORWARDER",
}

_TEXT_PORT = 1
_POSITION_PORT = 3


class MeshtasticParseError(ValueError):
    """INSECURE: raised when raw bytes are not a decodable public packet."""


@dataclass(frozen=True)
class MeshtasticData:
    """INSECURE: decoded ``Data`` envelope of one public packet."""

    portnum: int
    portname: str
    payload: bytes
    text: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    strings: tuple[str, ...] = ()


@dataclass(frozen=True)
class MeshtasticPacket:
    """INSECURE: one decoded public Meshtastic ``MeshPacket``."""

    from_id: int = 0
    to_id: int = 0
    channel: int = 0
    packet_id: int = 0
    hop_limit: int = 0
    hop_start: int = 0
    want_ack: bool = False
    via_mqtt: bool = False
    rx_time: int = 0
    rx_snr: float | None = None
    rx_rssi: int | None = None
    data: MeshtasticData | None = None
    encrypted: bool = False
    encrypted_len: int = 0
    unknown_fields: tuple[int, ...] = field(default=())


def portnum_name(portnum: int) -> str:
    """INSECURE: display label for a Meshtastic ``portnum`` value."""
    return _PORTNUM_NAMES.get(portnum, f"UNKNOWN({portnum})")


def parse_packet(raw: bytes | bytearray) -> MeshtasticPacket:
    """INSECURE: parse one raw LoRa payload into a public packet.

    Only unencrypted (``decoded``) packets yield ``data``. Packets
    carrying the ``encrypted`` field yield ``encrypted=True`` with no
    payload access — there is deliberately no key/decrypt API in this
    module. Raises :class:`MeshtasticParseError` on empty, oversize, or
    malformed input.
    """
    buf = bytes(raw)
    if not buf:
        raise MeshtasticParseError("empty frame")
    if len(buf) > MAX_FRAME_LEN:
        raise MeshtasticParseError(f"frame too long: {len(buf)} bytes")

    from_id = 0
    to_id = 0
    channel = 0
    packet_id = 0
    hop_limit = 0
    hop_start = 0
    want_ack = False
    via_mqtt = False
    rx_time = 0
    rx_snr: float | None = None
    rx_rssi: int | None = None
    data: MeshtasticData | None = None
    encrypted = False
    encrypted_len = 0
    unknown: list[int] = []
    seen_any = False

    for field_no, wire, value in _iter_fields(buf):
        seen_any = True
        if field_no == 1 and wire == 5:
            from_id = value
        elif field_no == 2 and wire == 5:
            to_id = value
        elif field_no == 3 and wire == 0:
            channel = value
        elif field_no == 4 and wire == 2:
            if data is not None:
                raise MeshtasticParseError("duplicate decoded field")
            data = _parse_data(value)
        elif field_no == 5 and wire == 2:
            encrypted = True
            encrypted_len = len(value)
        elif field_no == 6 and wire == 5:
            packet_id = value
        elif field_no == 7 and wire == 5:
            rx_time = value
        elif field_no == 8 and wire == 5:
            (rx_snr,) = struct.unpack("<f", value.to_bytes(4, "little"))
        elif field_no == 9 and wire == 0:
            hop_limit = value
        elif field_no == 10 and wire == 0:
            want_ack = bool(value)
        elif field_no == 12 and wire == 0:
            rx_rssi = _to_int32(value)
        elif field_no == 14 and wire == 0:
            via_mqtt = bool(value)
        elif field_no == 15 and wire == 0:
            hop_start = value
        else:
            unknown.append(field_no)

    if not seen_any:
        raise MeshtasticParseError("no protobuf fields found")
    if data is not None and encrypted:
        raise MeshtasticParseError("packet has both decoded and encrypted")
    if data is None and not encrypted:
        raise MeshtasticParseError("packet has neither decoded nor encrypted")

    return MeshtasticPacket(
        from_id=from_id,
        to_id=to_id,
        channel=channel,
        packet_id=packet_id,
        hop_limit=hop_limit,
        hop_start=hop_start,
        want_ack=want_ack,
        via_mqtt=via_mqtt,
        rx_time=rx_time,
        rx_snr=rx_snr,
        rx_rssi=rx_rssi,
        data=data,
        encrypted=encrypted,
        encrypted_len=encrypted_len,
        unknown_fields=tuple(unknown),
    )


def try_parse_packet(raw: bytes | bytearray) -> MeshtasticPacket | None:
    """INSECURE: like :func:`parse_packet` but returns ``None`` instead.

    Returns ``None`` (never raises) for empty/oversize/malformed input
    so a TUI receive loop can count-and-drop undecodable RF noise.
    """
    try:
        return parse_packet(raw)
    except (MeshtasticParseError, ValueError, struct.error, IndexError):
        return None


def format_packet(pkt: MeshtasticPacket) -> str:
    """INSECURE: render a parsed packet as one display line.

    Output is untrusted display text: the ``INSECURE`` prefix and the
    ``(shared channel; unauthenticated)`` marker MUST be preserved by
    any UI that shows this string.
    """
    head = (
        f"INSECURE meshtastic from={pkt.from_id:#010x} "
        f"to={pkt.to_id:#010x} ch={pkt.channel} "
        f"id={pkt.packet_id:#010x} "
        f"hop={pkt.hop_start}/{pkt.hop_limit} "
        f"(shared channel; unauthenticated)"
    )
    if pkt.via_mqtt:
        head += " [via-mqtt]"
    if pkt.encrypted or pkt.data is None:
        return f"{head} encrypted packet ({pkt.encrypted_len} B; not decrypted)"
    data = pkt.data
    if data.portnum == _TEXT_PORT and data.text is not None:
        return f"{head} {data.portname}: {data.text}"
    if data.portnum == _POSITION_PORT and (
        data.latitude is not None or data.longitude is not None
    ):
        return f"{head} {data.portname}: lat={data.latitude} lon={data.longitude}"
    if data.strings:
        preview = " | ".join(data.strings[:4])
        return f"{head} {data.portname} ({len(data.payload)} B): {preview}"
    return f"{head} {data.portname} ({len(data.payload)} B)"


def _parse_data(buf: bytes) -> MeshtasticData:
    """Decode a ``Data`` protobuf envelope (internal helper)."""
    portnum = 0
    payload = b""
    for field_no, wire, value in _iter_fields(buf):
        if field_no == 1 and wire == 0:
            portnum = value
        elif field_no == 2 and wire == 2:
            if payload:
                raise MeshtasticParseError("duplicate Data payload")
            payload = value
        # All other Data fields (want_response, dest, source,
        # request/reply ids, emoji, bitfield) are skipped: display only.

    name = portnum_name(portnum)
    text: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    strings: tuple[str, ...] = ()

    if portnum == _TEXT_PORT:
        text = _decode_text(payload)
    elif portnum == _POSITION_PORT:
        latitude, longitude = _decode_position(payload)
    elif payload:
        strings = _harvest_strings(payload)

    return MeshtasticData(
        portnum=portnum,
        portname=name,
        payload=payload,
        text=text,
        latitude=latitude,
        longitude=longitude,
        strings=strings,
    )


def _decode_text(payload: bytes) -> str:
    """Decode a TEXT_MESSAGE_APP payload as UTF-8 (internal helper)."""
    if not payload:
        raise MeshtasticParseError("empty text payload")
    if len(payload) > MAX_FRAME_LEN:
        raise MeshtasticParseError("text payload too long")
    return payload.decode("utf-8", errors="replace")


def _decode_position(payload: bytes) -> tuple[float | None, float | None]:
    """Best-effort lat/lon from a POSITION_APP payload (internal helper).

    Only ``latitude_i`` (field 1, sfixed32) and ``longitude_i``
    (field 2, sfixed32), scaled by 1e7, are extracted. ``(None, None)``
    is returned when neither field is present; other position fields
    are ignored.
    """
    latitude: float | None = None
    longitude: float | None = None
    for field_no, wire, value in _iter_fields(payload):
        if wire != 5:
            continue
        raw = struct.unpack("<i", value.to_bytes(4, "little"))[0]
        if field_no == 1 and latitude is None:
            latitude = raw / 1e7
        elif field_no == 2 and longitude is None:
            longitude = raw / 1e7
    return latitude, longitude


def _harvest_strings(payload: bytes, limit: int = 64) -> tuple[str, ...]:
    """Collect printable ASCII runs for display of opaque payloads.

    Heuristic only (internal helper): used to preview NODEINFO-style
    payloads without implementing their full protobuf schema. Runs
    shorter than 3 characters are ignored; at most ``limit`` total
    characters are returned across all runs.
    """
    runs: list[str] = []
    current: list[str] = []
    budget = limit

    def flush() -> None:
        nonlocal budget
        if len(current) >= 3 and budget > 0:
            run = "".join(current)[:budget]
            runs.append(run)
            budget -= len(run)
        current.clear()

    for byte in payload:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            flush()
    flush()
    return tuple(runs)


def _iter_fields(buf: bytes) -> object:
    """Yield ``(field_number, wire_type, value)`` protobuf fields.

    Internal generator. ``value`` is an ``int`` for varint (wire 0) and
    fixed32 (wire 5, little-endian unsigned), ``bytes`` for
    length-delimited (wire 2); 64-bit (wire 1) values are skipped. Any
    truncation or illegal tag raises :class:`MeshtasticParseError`.
    """
    pos = 0
    end = len(buf)
    while pos < end:
        tag, pos = _read_varint(buf, pos)
        field_no = tag >> 3
        wire = tag & 0x07
        if field_no == 0:
            raise MeshtasticParseError("bad protobuf tag")
        if wire == 0:
            value, pos = _read_varint(buf, pos)
            yield field_no, wire, value
        elif wire == 1:
            if pos + 8 > end:
                raise MeshtasticParseError("truncated 64-bit field")
            pos += 8  # RX metadata; value unused for display.
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > end:
                raise MeshtasticParseError("truncated length-delimited field")
            value = buf[pos : pos + length]
            pos += length
            yield field_no, wire, value
        elif wire == 5:
            if pos + 4 > end:
                raise MeshtasticParseError("truncated 32-bit field")
            value = int.from_bytes(buf[pos : pos + 4], "little")
            pos += 4
            yield field_no, wire, value
        else:
            raise MeshtasticParseError(f"unsupported wire type {wire}")


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read one protobuf varint at ``pos`` (internal helper)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise MeshtasticParseError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise MeshtasticParseError("varint overflow")


def _to_int32(value: int) -> int:
    """Interpret a protobuf int32 varint as signed (internal helper)."""
    value &= (1 << 64) - 1
    if value >= 1 << 63:
        value -= 1 << 64
    if value < -(1 << 31) or value >= 1 << 31:
        raise MeshtasticParseError("int32 out of range")
    return value
