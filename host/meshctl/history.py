"""User-only SQLite message history (plaintext; not encrypted storage).

One database per serial path under ``.mesh-local/`` so operators never
mix histories between boards. Files are created 0600; the plaintext
content is convenient local logging, never advertised as secure storage.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    contact TEXT NOT NULL,
    direction TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_unix INTEGER NOT NULL DEFAULT 0
);
"""

HISTORY_VERSION = 1



def open_history(path: str | Path) -> sqlite3.Connection:
    """Open (creating) a user-only history database at ``path``."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
        if "created_unix" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN created_unix INTEGER NOT NULL DEFAULT 0")
        conn.commit()
        # WAL sidecars inherit the umask, not the db mode; keep them private.
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.chmod(f"{path}{suffix}", 0o600)
            except OSError:
                pass
        return conn
    except BaseException:
        conn.close()
        raise


def record_message(
    conn: sqlite3.Connection,
    *,
    contact: str,
    direction: str,
    epoch: int,
    sequence: int,
    text: str,
) -> int:
    """Insert one row; returns its row id. Raises on bad fields."""
    if direction not in ("in", "out"):
        raise ValueError("BAD_REQUEST")
    if not contact or not isinstance(text, str):
        raise ValueError("BAD_REQUEST")
    if type(epoch) is not int or not 0 <= epoch < 2**32:
        raise ValueError("BAD_REQUEST")
    if type(sequence) is not int or not 0 <= sequence < 2**64:
        raise ValueError("BAD_REQUEST")
    # SQLite integers are signed; preserve all u64 bits rather than coercing
    # large sequence numbers to imprecise floating point or rejecting them.
    stored_sequence = sequence if sequence < 2**63 else sequence - 2**64
    import time as _time

    cur = conn.execute(
        "INSERT INTO messages (contact, direction, epoch, sequence, text, created_unix)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (contact, direction, epoch, stored_sequence, text, int(_time.time())),
    )
    conn.commit()
    return int(cur.lastrowid)


def recent_messages(conn: sqlite3.Connection, limit: int = 20) -> list[tuple]:
    """Newest-first ``(contact, direction, epoch, sequence, text)`` rows."""
    try:
        limit = min(max(int(limit), 1), 200)
    except (TypeError, ValueError):
        limit = 20
    rows = conn.execute(
        "SELECT contact, direction, epoch, sequence, text FROM messages"
        " ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    return [
        (contact, direction, epoch, sequence % 2**64, text)
        for contact, direction, epoch, sequence, text in rows
    ]
