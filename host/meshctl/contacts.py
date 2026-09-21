"""Host-local contact names: operator labels, never on-air identity.

``.mesh-local/host-contacts.json`` maps board USB serial -> display name ->
firmware ``contact_id``. Firmware slots stay authoritative for trust; this
file is only a typing convenience so ``send --contact NAME`` does not
require memorizing slot numbers. USB serials are stable across reboots;
``/dev/ttyACM`` numbers are not, so device paths are never keys.

Names are arbitrary operator labels (``alice``, ``relay-2``, ``HQ``):
anything non-empty up to 32 chars except whitespace-only. The old ``A``/``B``/
``C`` lab convention still works as ordinary names, but nothing treats them
specially and no ``lab_address`` is ever transmitted (the secure firmware
image has no such field).

Entries are written **only** when a ``pair_import`` reply reports activation
(``contact_id`` present). Invalid records never mutate this file. User-only
file (0600). Contact names are local: they are never transmitted.
"""
from __future__ import annotations

import os

from . import local as _local

MAX_NAME_LEN = 32
MAX_CONTACTS = 16

# Legacy keys this install may still carry: device paths and by-id symlinks.
# Migrated to USB serials on first write; never written back.
_BY_ID_TAIL = "-if00"


def valid_name(name: str) -> bool:
    """Arbitrary operator label: non-empty, non-blank, <= 32 chars."""
    return bool(name) and bool(name.strip()) and len(name) <= MAX_NAME_LEN


def serial_from_key(key: str) -> str | None:
    """USB serial from a legacy mapping key, else None."""
    base = os.path.basename(key.rstrip("/"))
    if base.startswith("usb-") and base.endswith(_BY_ID_TAIL):
        core = base[4:-len(_BY_ID_TAIL)]
        parts = core.split("_")
        candidate = parts[-1]
        if candidate and all(c in "0123456789abcdef" for c in candidate):
            return candidate
    return None


def serial_for_port(port: str) -> str:
    """USB serial for a device path; falls back to the path itself.

    Mappings are keyed by serial. Callers pass ``--port`` values (device
    paths); this resolves them so moves across ``ttyACM`` numbers keep
    working. Unknown ports return the input unchanged (legacy entries).
    """
    try:
        import serial.tools.list_ports as _lp
    except ImportError:
        return port
    try:
        for cand in _lp.comports():
            if cand.device == port and cand.serial_number:
                return cand.serial_number
    except Exception:
        return port
    # by-id symlinks embed the serial in the filename.
    serial = serial_from_key(port)
    return serial if serial is not None else port


def load_mappings() -> dict:
    """Raw mapping object ``{usb_serial: {name: contact_id}}``.

    Legacy device-path/by-id keys are folded into serial entries on read
    (serial wins on conflict); the file is rewritten in the new form on the
    next :func:`set_contact` call.
    """
    raw = _local.read_json_object(_local.contacts_path())
    merged: dict[str, dict] = {}
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        serial = serial_from_key(key)
        if serial is None and "/" not in key and "\\" not in key:
            serial = key  # already a bare serial
        if serial is None:
            continue  # unparseable legacy path: drop
        slot = merged.setdefault(serial, {})
        for name, cid in entry.items():
            if not isinstance(name, str) or not valid_name(name):
                continue
            if isinstance(cid, bool) or not isinstance(cid, int):
                continue
            if cid < 1 or cid > MAX_CONTACTS:
                continue
            slot.setdefault(name, cid)
    return merged


def _key_for(board_or_serial: str) -> str:
    """Accept a USB serial or a legacy key; reduce legacy to serial."""
    serial = serial_from_key(board_or_serial)
    return serial if serial is not None else board_or_serial


def resolve_contact(board_or_serial: str, name: str) -> int | None:
    """Contact id for ``name`` on this board; None when unmapped/invalid."""
    if not valid_name(name):
        return None
    entry = load_mappings().get(_key_for(board_or_serial))
    if not isinstance(entry, dict):
        return None
    cid = entry.get(name)
    if isinstance(cid, bool) or not isinstance(cid, int):
        return None
    if cid < 1 or cid > MAX_CONTACTS:
        return None
    return cid


def name_for_id(board_or_serial: str, contact_id: int) -> str | None:
    """Reverse lookup: display name for a firmware contact id, if mapped."""
    if isinstance(contact_id, bool) or not isinstance(contact_id, int):
        return None
    entry = load_mappings().get(_key_for(board_or_serial))
    if not isinstance(entry, dict):
        return None
    for name, cid in entry.items():
        if isinstance(name, str) and cid == contact_id:
            return name
    return None


def names_for(board_or_serial: str) -> list[str]:
    """All mapped display names for this board (possibly empty)."""
    entry = load_mappings().get(_key_for(board_or_serial))
    if not isinstance(entry, dict):
        return []
    return [n for n in entry if isinstance(n, str)]


def set_contact(board_or_serial: str, name: str, contact_id: int) -> None:
    """Record an activated mapping. Call only on pair_import activation."""
    if not valid_name(name) or contact_id < 1 or contact_id > MAX_CONTACTS:
        raise ValueError("BAD_REQUEST")
    key = _key_for(board_or_serial)
    if "/" in key or "\\" in key:
        raise ValueError("board key must be a USB serial, not a device path")
    ports = load_mappings()
    entry = ports.get(key)
    if not isinstance(entry, dict):
        entry = {}
        ports[key] = entry
    entry[name] = contact_id
    _local.write_json_private(_local.contacts_path(), ports)


def drop_contact(board_or_serial: str, name: str, contact_id: int) -> None:
    """Remove a local mapping after board-side delete. No-op when absent."""
    key = _key_for(board_or_serial)
    ports = load_mappings()
    entry = ports.get(key)
    if not isinstance(entry, dict):
        return
    entry.pop(name, None)
    # Drop any other name pointing at the same freed slot.
    for other in [n for n, cid in entry.items() if cid == contact_id]:
        entry.pop(other, None)
    _local.write_json_private(_local.contacts_path(), ports)
