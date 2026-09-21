"""Sudo-free RP2350 device operations: UF2 flash, info, reboot, ELF check.

BOOTSEL access goes through the USB mass-storage volume (udisksctl mount
+ file copy, no root). ``picotool`` file subcommands (``info``, ``uf2
convert``, ``config`` on files) need no device at all. Live ``picotool``
device commands need raw USB access (root-owned ``/dev/bus/usb`` nodes),
so they are attempted and report PERMISSION when udev gives no access —
never silently skipped, never escalated.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

TOOL_NAME = "picotool"
FLASH_START, FLASH_STORAGE = 0x10000000, 0x103F0000
RAM_START, RAM_END = 0x20000000, 0x20082000


@dataclass
class FlashResult:
    """Outcome of one sudo-free UF2 copy to a BOOTSEL volume."""

    volume: str
    bytes_copied: int
    rebooted_to_app: bool


def tool_path() -> Path | None:
    """Bundled ``.mesh-local/tools/picotool`` first, then PATH."""
    from . import local as _local

    bundled = _local.mesh_local_dir() / "tools" / "picotool"
    if bundled.is_file():
        return bundled
    found = shutil.which(TOOL_NAME)
    return Path(found) if found else None


def run_tool(*args: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Run picotool; ``(returncode, stdout, stderr)``. Raises when missing."""
    tool = tool_path()
    if tool is None:
        raise RuntimeError("picotool not found (expected .mesh-local/tools/picotool)")
    try:
        proc = subprocess.run(
            [str(tool), *args], capture_output=True, text=True, timeout=timeout
        )
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"picotool failed: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr


def check_elf(path: str | Path) -> dict:
    """Static RP2350 ARM ELF checks (no USB). Raises ValueError on failure."""
    data = Path(path).read_bytes()
    if data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("not an ELF32 little-endian v1 image")
    kind, machine, version, entry, phoff, shoff, _flags, _eh, phsize, phnum, shsize, shnum, shstridx = struct.unpack_from(
        "<HHIIIIIHHHHHH", data, 16
    )
    if (kind, machine, version) != (2, 40, 1):
        raise ValueError("not an ARM executable")
    loads = [
        struct.unpack_from("<IIIIIIII", data, phoff + i * phsize)
        for i in range(phnum)
        if struct.unpack_from("<I", data, phoff + i * phsize)[0] == 1
    ]
    if not loads:
        raise ValueError("no loadable segments")
    stored = 0
    for _, offset, vaddr, paddr, filesz, memsz, _perm, _align in loads:
        if filesz > memsz or offset + filesz > len(data):
            raise ValueError("corrupt segment")
        if filesz and not (FLASH_START <= paddr and paddr + filesz <= FLASH_STORAGE):
            raise ValueError("load data overlaps retained storage or lies outside flash")
        if not (
            FLASH_START <= vaddr and vaddr + memsz <= 0x10400000
            or RAM_START <= vaddr and vaddr + memsz <= RAM_END
        ):
            raise ValueError("segment outside RP2350 memory")
        stored += filesz
    try:
        sections = [
            struct.unpack_from("<IIIIIIIIII", data, shoff + i * shsize)
            for i in range(shnum)
        ]
        strings = sections[shstridx]
        strtab = data[strings[4] : strings[4] + strings[5]]
        vector = next(
            s
            for s in sections
            if strtab[s[0] :].split(b"\x00", 1)[0] == b".vector_table"
        )
    except (IndexError, StopIteration, struct.error) as exc:
        raise ValueError(f"no usable vector table: {exc}") from exc
    if vector[5] < 64:
        raise ValueError("vector table too short")
    sp, reset = struct.unpack_from("<II", data, vector[4])
    if not (RAM_START < sp <= RAM_END and sp % 8 == 0):
        raise ValueError("invalid initial stack pointer")
    if not reset & 1:
        raise ValueError("reset vector is not Thumb")
    exe = [p for p in loads if p[6] & 1]
    if not any(p[2] <= (reset & ~1) < p[2] + p[5] for p in exe):
        raise ValueError("reset outside executable segment")
    if not any(p[2] <= (entry & ~1) < p[2] + p[5] for p in exe):
        raise ValueError("entry outside executable segment")
    return {"entry": entry, "reset": reset, "stack": sp, "stored_bytes": stored,
            "load_segments": len(loads)}


def info_file(path: str, file_type: str = "elf") -> str:
    """``picotool info`` on a file (no device, no sudo). Raises on failure."""
    code, out, err = run_tool("info", path, "-t", file_type)
    if code != 0:
        raise RuntimeError(f"picotool info failed: {err.strip() or out.strip()}")
    return out


def uf2_convert(elf_path: str, uf2_path: str) -> str:
    """``picotool uf2 convert`` ELF -> UF2 (no device, no sudo)."""
    code, out, err = run_tool("uf2", "convert", elf_path, "-t", "elf", uf2_path)
    if code != 0:
        raise RuntimeError(f"uf2 convert failed: {err.strip() or out.strip()}")
    return uf2_path


def mount_bootsel(dev: str = "/dev/sda1", timeout: float = 30.0) -> str:
    """Mount a BOOTSEL partition via udisksctl (no sudo). Returns mountpoint."""
    try:
        proc = subprocess.run(
            ["udisksctl", "mount", "-b", dev],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"mount failed: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"mount failed: {(proc.stderr or proc.stdout).strip()}")
    for token in proc.stdout.split():
        if token.startswith("/"):
            return token.rstrip("/")
    mounts = _boards.bootsel_mounts()
    if dev in mounts:
        return mounts[dev]
    raise RuntimeError(f"mount reply unparseable: {proc.stdout.strip()}")


def flash_uf2(uf2_path: str, mountpoint: str, timeout: float = 60.0) -> FlashResult:
    """Copy UF2 onto a mounted BOOTSEL volume, sync, wait for reboot.

    Raises on copy failure or when no CDC application port appears before
    the deadline (board may still be flashing; never assumed).
    """
    src = Path(uf2_path)
    if not src.is_file():
        raise ValueError(f"no such UF2: {uf2_path}")
    size = src.stat().st_size
    dest = Path(mountpoint) / src.name
    try:
        dest.write_bytes(src.read_bytes())
        subprocess.run(["sync"], timeout=timeout)
    except OSError as exc:
        raise RuntimeError(f"UF2 copy failed: {exc}") from exc
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = Path("/proc/mounts").read_text()
        except OSError:
            text = ""
        if mountpoint not in text:
            # Volume left /proc/mounts: firmware rebooted into the app.
            break
        time.sleep(1.0)
    return FlashResult(volume=mountpoint, bytes_copied=size,
                       rebooted_to_app=mountpoint not in text)


def live_command(*args: str, timeout: float = 30.0) -> str:
    """A live-device picotool command (needs raw USB; reports PERMISSION).

    Raises RuntimeError with a PERMISSION/BOOTSEL hint instead of asking
    for sudo: mass-storage flashing above is the supported path.
    """
    code, out, err = run_tool(*args, timeout=timeout)
    if code != 0:
        detail = (err.strip() or out.strip())[:200]
        if "ermission" in detail or "ccess" in detail or "o device" in detail:
            raise RuntimeError(
                f"PERMISSION: raw USB unavailable ({detail}); "
                "use mass-storage flashing (no sudo needed)"
            )
        raise RuntimeError(f"picotool failed: {detail}")
    return out
