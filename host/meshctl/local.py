"""Project-local private state: everything under ``.mesh-local/``.

Pairing images/records, host contact mappings, plaintext SQLite history and
port locks live here so private material never lands in git (``.gitignore``
covers ``/.mesh-local/``). Files are created user-only (0600, dirs 0700);
history is plaintext and is never advertised as encrypted storage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

PLAN_MARKER = "three-pico-lora-plan.md"
ENV_OVERRIDE = "MESH_LOCAL_DIR"
DIR_MODE = 0o700
FILE_MODE = 0o600


def mesh_local_dir() -> Path:
    """Resolve ``.mesh-local/``: env override, else the project dir, else cwd."""
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        return _ensure_dir(Path(override))
    cur = Path.cwd()
    for parent in (cur, *cur.parents):
        if (parent / PLAN_MARKER).exists():
            return _ensure_dir(parent / ".mesh-local")
    return _ensure_dir(cur / ".mesh-local")


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass
    return path


def port_slug(port: str) -> str:
    """Filesystem-safe per-port stem; hash suffix avoids sanitizer collisions."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", port).strip("_") or "port"
    digest = hashlib.sha1(port.encode("utf-8")).hexdigest()[:8]
    return f"{slug}_{digest}"


def locks_dir() -> Path:
    return _ensure_dir(mesh_local_dir() / "locks")


def records_dir() -> Path:
    return _ensure_dir(mesh_local_dir() / "records")


def lock_path_for(port: str) -> Path:
    return locks_dir() / (port_slug(port) + ".lock")


def contacts_path() -> Path:
    return mesh_local_dir() / "host-contacts.json"


def history_path_for(port: str) -> Path:
    return mesh_local_dir() / f"history-{port_slug(port)}.sqlite3"


def write_private_bytes(path: Path, data: bytes) -> None:
    """Write user-only file (0600); never mutates caller buffers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, FILE_MODE)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, FILE_MODE)
    except OSError:
        pass


def read_json_object(path: Path) -> dict:
    """Read a JSON object file; missing file yields {}. Corrupt JSON raises."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except FileNotFoundError:
        return {}
    if not isinstance(obj, dict):
        raise ValueError(f"corrupt mapping file (not an object): {path}")
    return obj


def write_json_private(path: Path, obj: dict) -> None:
    payload = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_private_bytes(path, payload)
