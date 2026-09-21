"""QR transport for in-person pairing records (plan step 6).

Transport is ASCII ``LMESH1:`` plus **canonical unpadded base64url** of one
binary record. The host never interprets key material; it only validates
shape strictly and moves opaque bytes between firmware and QR PNG files:

- offer:        type ``0x01``, **98 bytes**  (1 ver + 32 ed + 32 eph + 32 chal)
- proof:        type ``0x02``, **122 bytes** (T32 + role + ct/tag24 + sig64)
- confirmation: type ``0x03``, **66 bytes**  (T32 + role + mac32)

Validation rejects (visible error, no contact mutation): wrong prefix,
padding characters, illegal charset, non-canonical trailing bits
(strict, mirroring ``mesh-core::pairing`` ``BadCharset``), wrong decoded
length, wrong type byte, offer version != ``1``, role byte not 0/1.
Where the record length is ambiguous (98/122/66 share no overlap) the
type byte selects; unknown types and anything else fail closed.

QR images use local ``zxing-cpp`` + Pillow + NumPy only (no online
service, no camera required): ``write_png`` encodes text to a PNG file,
``decode_file`` scans a PNG back to text. A direct local file transfer
is equally allowed when both operators are present; fingerprints must
still be compared aloud.
"""
from __future__ import annotations

import base64

PREFIX = "LMESH1:"

RECORD_OFFER = 0x01
RECORD_PROOF = 0x02
RECORD_CONFIRM = 0x03

OFFER_RECORD_LEN = 98
PROOF_RECORD_LEN = 122
CONFIRM_RECORD_LEN = 66

OFFER_VERSION = 0x01
ROLE_L = 0
ROLE_R = 1

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

_TYPE_LEN = {
    RECORD_OFFER: OFFER_RECORD_LEN,
    RECORD_PROOF: PROOF_RECORD_LEN,
    RECORD_CONFIRM: CONFIRM_RECORD_LEN,
}


def _canonical_b64url(body: str) -> bytes:
    """Strict unpadded base64url decode; mirrors firmware canonical checks."""
    if not body:
        raise ValueError("BAD_REQUEST: empty record body")
    if "=" in body:
        raise ValueError("BAD_REQUEST: padded base64 (unpadded base64url required)")
    for ch in body:
        if ch not in _B64_ALPHABET:
            raise ValueError(f"BAD_REQUEST: illegal base64url character {ch!r}")
    tail = len(body) % 4
    if tail == 1:
        raise ValueError("BAD_REQUEST: impossible base64url length")
    try:
        padded = body + "=" * ((4 - tail) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"BAD_REQUEST: malformed base64url ({exc})") from exc
    # Non-canonical trailing bits (encoder would emit zero there).
    full_quads, rem = divmod(len(body), 4)
    if rem == 2:
        last = _b64_val(body[-1])
        if last & 0x0F:
            raise ValueError("BAD_REQUEST: non-canonical base64url trailing bits")
    elif rem == 3:
        last = _b64_val(body[-1])
        if last & 0x03:
            raise ValueError("BAD_REQUEST: non-canonical base64url trailing bits")
    # Round-trip: re-encoding must reproduce the body exactly.
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != body:
        raise ValueError("BAD_REQUEST: non-canonical base64url encoding")
    _ = full_quads
    return raw


def _b64_val(ch: str) -> int:
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A")
    if "a" <= ch <= "z":
        return ord(ch) - ord("a") + 26
    if "0" <= ch <= "9":
        return ord(ch) - ord("0") + 52
    if ch == "-":
        return 62
    return 63  # ch == "_", validated by caller


def encode_record(raw: bytes) -> str:
    """Binary record -> ``LMESH1:`` transport text (unpadded)."""
    if not raw:
        raise ValueError("BAD_REQUEST: empty record")
    return PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")


def inspect_record(raw: bytes) -> str:
    """Classify a decoded record: ``offer``/``proof``/``confirmation``.

    Raises ``ValueError`` on any shape violation (length, type, offer
    version, role byte). No state is touched; callers surface the error
    visibly and mutate nothing.
    """
    if len(raw) == OFFER_RECORD_LEN and raw[0] == RECORD_OFFER:
        if raw[1] != OFFER_VERSION:
            raise ValueError("BAD_REQUEST: offer version != 1")
        return "offer"
    if len(raw) == PROOF_RECORD_LEN and raw[0] == RECORD_PROOF:
        if raw[1 + 32] not in (ROLE_L, ROLE_R):
            raise ValueError("BAD_REQUEST: proof role not 0/1")
        return "proof"
    if len(raw) == CONFIRM_RECORD_LEN and raw[0] == RECORD_CONFIRM:
        if raw[1 + 32] not in (ROLE_L, ROLE_R):
            raise ValueError("BAD_REQUEST: confirmation role not 0/1")
        return "confirmation"
    raise ValueError(
        "BAD_REQUEST: unknown record (length/type/version/role mismatch;"
        f" got len={len(raw)} type=0x{raw[0]:02x}" if raw else "BAD_REQUEST: empty record"
    )


def decode_record(text: str) -> bytes:
    """Transport text -> raw record bytes, strictly validated (typed)."""
    if not isinstance(text, str) or not text.startswith(PREFIX):
        raise ValueError("BAD_REQUEST: record must start with 'LMESH1:'")
    body = text[len(PREFIX):]
    raw = _canonical_b64url(body)
    kind = inspect_record(raw)
    expected = {
        "offer": OFFER_RECORD_LEN,
        "proof": PROOF_RECORD_LEN,
        "confirmation": CONFIRM_RECORD_LEN,
    }[kind]
    if len(raw) != expected:
        raise ValueError("BAD_REQUEST: record length mismatch")
    return raw


def decode_record_kind(text: str) -> tuple[bytes, str]:
    """Decode transport text and classify: ``(raw, kind)``."""
    raw = decode_record(text)
    return raw, inspect_record(raw)


def write_png(text: str, path: str, *, scale: int = 6) -> None:
    """Render ``text`` as a QR PNG at ``path`` (local libs only)."""
    import zxingcpp
    from PIL import Image

    try:
        barcode = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode)
        img = barcode.to_image(scale=scale)
        Image.fromarray(img).save(path)
    except ImportError:
        raise
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"QR PNG write failed: {exc}") from exc


def read_text_from_image(path: str) -> str:
    """Scan a QR PNG file back to its text payload (local libs only).

    A plain UTF-8 text file holding one ``LMESH1:`` record is also
    accepted (direct local file transfer when both operators are present
    and compare fingerprints aloud); QR decode is tried first so a real
    image always wins over a same-named text fallback.
    """
    try:
        import numpy as np
        import zxingcpp
        from PIL import Image
        img = Image.open(path).convert("L")
        barcodes = zxingcpp.read_barcodes(np.asarray(img))
        texts = [b.text for b in barcodes if getattr(b, "text", None)]
        if texts:
            for text in texts:
                if text.startswith(PREFIX):
                    return text
            return texts[0]
    except ImportError:
        pass
    except (OSError, ValueError):
        pass
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"BAD_REQUEST: cannot read pairing file ({exc})") from exc
    if text.startswith(PREFIX):
        return text.split()[0]
    raise ValueError("BAD_REQUEST: no QR code found in image")


def fingerprint_of_record_b64(record_b64: str) -> str:
    """First 16 hex chars of the transcript ``T`` for comparison ceremony.

    Only meaningful for proof/confirmation records (which carry ``T`` at
    bytes 1..33); offers identify by signing key instead, so this returns
    ``""`` for them rather than a misleading value.
    """
    import binascii

    raw = decode_record(record_b64)
    kind = inspect_record(raw)
    if kind == "offer":
        return ""
    return binascii.hexlify(raw[1:9]).decode("ascii")


def fingerprint_of_offer(record_b64: str) -> str:
    """Peer identity fingerprint: SHA256(Ed25519 public key), first 16 hex chars."""
    import hashlib

    raw = decode_record(record_b64)
    if inspect_record(raw) != "offer":
        return ""
    return hashlib.sha256(raw[2:34]).hexdigest()[:16]
