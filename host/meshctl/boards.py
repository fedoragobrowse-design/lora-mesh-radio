"""Board discovery: stable identity for three Pico nodes.

``ttyACM`` numbers move across reboots; USB serials do not. This module
resolves each board by USB serial (``..._SERIAL-if00`` in
``/dev/serial/by-id/``), probes one matched-ID ``status``, and reports
label/image/radio/counters. BOOTSEL mass-storage volumes are listed
separately (they expose no serial; exactly-one-volume is unambiguous).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

BY_ID_DIR = Path("/dev/serial/by-id")
MESH_VID_PID = ("2e8a", "0001")
BOOTSEL_VID_PID = ("2e8a", "000f")

# ``usb-mesh_mesh-node_radio-secure_<SERIAL>-if00`` (product part varies).
_BY_ID_RE = re.compile(r"usb-mesh_mesh-node_[^_]+_([0-9a-f]+)-if00$")


@dataclass
class Board:
    """One CDC application-mode node, addressed stably by USB serial."""

    serial: str
    device: str  # resolved /dev/ttyACM path (or by-id path when no tty)
    by_id: str
    label: str = ""
    image: str = ""
    firmware_version: str = ""
    provisioned: bool = False
    radio_available: bool = False
    radio_enabled: bool = False
    radio_version: int = 0
    epoch: int = 0
    time_valid: bool = False
    contacts: dict = field(default_factory=dict)
    counters: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class BootselVolume:
    """One RP2350 BOOTSEL mass-storage volume (no serial visible)."""

    dev: str  # e.g. /dev/sda1
    mount: str = ""  # mountpoint when mounted


def parse_serial_from_by_id(name: str) -> str | None:
    """USB serial from a by-id symlink name; None when not a mesh node."""
    match = _BY_ID_RE.search(name)
    return match.group(1) if match else None


def discover(by_id_dir: Path = BY_ID_DIR) -> list[Board]:
    """CDC mesh nodes sorted by serial. No device I/O, symlinks only."""
    boards: list[Board] = []
    try:
        entries = sorted(by_id_dir.iterdir())
    except OSError:
        return boards
    for entry in entries:
        serial = parse_serial_from_by_id(entry.name)
        if serial is None:
            continue
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        device = target if target.startswith("/") else f"/dev/{os.path.basename(target)}"
        boards.append(Board(serial=serial, device=device, by_id=str(entry)))
    boards.sort(key=lambda b: b.serial)
    return boards


def probe(board: Board, timeout: float = 5.0) -> Board:
    """Fill one board with a single matched-ID status (mutates, returns)."""
    from . import serial_link

    try:
        with serial_link.SerialSession(board.device) as session:
            reply, _ = session.exchange("status", None, timeout)
    except serial_link.PortBusyError:
        board.error = "PORT_BUSY"
        return board
    except (serial_link.TimeoutError, ValueError, RuntimeError, OSError) as exc:
        board.error = str(exc)
        return board
    if not reply.get("ok"):
        board.error = f"firmware error: {reply.get('error', 'UNKNOWN')}"
        return board
    result = reply.get("result", {})
    board.label = str(result.get("label", ""))
    board.image = str(result.get("image", ""))
    board.firmware_version = str(result.get("firmware_version", ""))
    board.provisioned = bool(result.get("provisioned", False))
    board.radio_available = bool(result.get("radio_available", False))
    board.radio_enabled = bool(result.get("radio_enabled", False))
    try:
        board.radio_version = int(result.get("radio_version", 0))
    except (TypeError, ValueError):
        board.radio_version = 0
    try:
        board.epoch = int(result.get("epoch", 0))
    except (TypeError, ValueError):
        board.epoch = 0
    board.time_valid = bool(result.get("time_valid", False))
    contacts = result.get("contacts", {})
    board.contacts = contacts if isinstance(contacts, dict) else {}
    counters = result.get("counters", {})
    board.counters = counters if isinstance(counters, dict) else {}
    return board


def probe_all(timeout: float = 5.0, by_id_dir: Path = BY_ID_DIR) -> list[Board]:
    """Discover + probe every CDC node (one status each)."""
    return [probe(board, timeout) for board in discover(by_id_dir)]


def find_board(boards: list[Board], key: str) -> Board | None:
    """Match by USB serial (prefix ok), label, or device path."""
    if not key:
        return None
    for board in boards:
        if board.serial.startswith(key):
            return board
        if board.label and key.upper() == board.label.upper():
            return board
        if key == board.device or key == board.by_id:
            return board
    return None


def bootsel_volumes() -> list[BootselVolume]:
    """RP2350 BOOTSEL block devices via lsblk (read-only, no sudo)."""
    import subprocess

    try:
        proc = subprocess.run(
            ["lsblk", "-rno", "NAME,MODEL"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    volumes: list[BootselVolume] = []
    for line in proc.stdout.splitlines():
        name, _, model = line.partition(" ")
        if "RP2350" in model.upper() and name and not name[-1].isdigit():
            # Whole disk (sda); first partition (sda1) holds the volume.
            volumes.append(BootselVolume(dev=f"/dev/{name}1"))
    return volumes


def bootsel_mounts() -> dict[str, str]:
    """Mounted RP2350 volumes: ``{dev: mountpoint}`` via /proc/mounts."""
    mounts: dict[str, str] = {}
    try:
        text = Path("/proc/mounts").read_text()
    except OSError:
        return mounts
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "RP2350" in parts[1]:
            mounts[parts[0]] = parts[1]
    return mounts
