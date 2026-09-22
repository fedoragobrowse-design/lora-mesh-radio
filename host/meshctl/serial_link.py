"""Newline-delimited JSON over USB CDC (plan USB contract, step 3).

Wire rules (mirror ``firmware/src/usb.rs``):
- One request per line, UTF-8, at most 1024 bytes including the newline.
  Every request carries integer ``id`` and string ``op``; replies echo the
  same ``id`` with ``ok`` plus ``result`` or ``error``. Async records carry
  ``event`` instead of ``id``/``ok``.
- IDs are monotonically increasing per connection (and per process for
  one-shot calls) so a deferred reply can be matched amid interleaved
  ``event`` records, stray wrong-``id`` replies and malformed lines.
- One process owns a port at a time via a ``.mesh-local/locks`` file;
  a second opener gets ``PORT_BUSY``. Single-shot calls hold the lock
  only for the transaction; ``listen``/``chat`` hold it for the session.
- Deadlines are bounded (default 5 s, sends up to 120 s); reads use 1 s
  chunks against a monotonic deadline so a silent peer cannot hang us.
- Caller dicts are never mutated: every body is copied before framing.

No key agreement or message encryption happens here; this module only
frames bytes. Third-party ``pyserial`` imports stay function-local so
pure-stdlib tooling (record validation, mapping logic) works without it.
"""
from __future__ import annotations

import json
import os
import threading
import time

BAUD = 115200
MAX_LINE_LEN = 1024
MAX_INBOUND_LEN = 4096
DEFAULT_TIMEOUT = 5.0
SEND_TIMEOUT = 60.0
MAX_TIMEOUT = 120.0
READ_CHUNK = 1.0

RADIO_UNAVAILABLE = "RADIO_UNAVAILABLE"
PORT_BUSY = "PORT_BUSY"


class PortBusyError(OSError):
    """A second process owns the port (single-owner receive loops)."""


class FirmwareError(RuntimeError):
    """Firmware answered ``ok:false``; ``str(exc)`` is the error string."""

    def __init__(self, error: str, reply: dict | None = None):
        super().__init__(error)
        self.error = error
        self.reply = reply or {}


class TimeoutError(RuntimeError):
    """No matching reply before the bounded deadline."""


_id_lock = threading.Lock()
_next_process_id = [1]


def next_process_id() -> int:
    """Monotonically increasing id for one-shot calls in this process."""
    with _id_lock:
        value = _next_process_id[0]
        _next_process_id[0] = value + 1 if value < 2**31 - 1 else 1
        return value


def encode_request(cmd_id: int, op: str, **params: object) -> bytes:
    """Frame one request line (copy of params; raises on overlong lines)."""
    body = {"id": cmd_id, "op": op}
    body.update(params)
    line = (json.dumps(body, ensure_ascii=False) + "\n").encode("utf-8")
    if len(line) > MAX_LINE_LEN + 1:
        raise ValueError("LINE_TOO_LONG")
    return line


def list_ports() -> list[str]:
    """Serial device paths (``meshctl ports`` convenience form)."""
    return [entry["device"] for entry in list_ports_detailed()]


def list_ports_detailed() -> list[dict]:
    """Device path plus VID/PID/USB serial when the OS reports them."""
    try:
        import serial.tools.list_ports
    except ImportError:
        return []
    out: list[dict] = []
    for cand in serial.tools.list_ports.comports():
        out.append(
            {
                "device": cand.device,
                "vid": f"{cand.vid:04x}" if cand.vid is not None else "",
                "pid": f"{cand.pid:04x}" if cand.pid is not None else "",
                "serial": cand.serial_number or "",
                "description": cand.description or "",
                "hwid": cand.hwid or "",
            }
        )
    return out


def _lock_path_for(port: str):
    from . import local as _local

    return _local.lock_path_for(port)


class PortLock:
    """Single-owner lock file for a serial path (``PORT_BUSY`` on clash)."""

    def __init__(self, port: str):
        self.port = port
        self.path = _lock_path_for(port)
        self._fd: int | None = None

    def acquire(self) -> None:
        import fcntl

        if self._fd is not None:
            raise PortBusyError(f"{PORT_BUSY}: {self.port}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PortBusyError(f"{PORT_BUSY}: {self.port}") from exc
            os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            # Never unlink: waiters must keep referring to the same inode.
            os.close(fd)

    def __enter__(self) -> "PortLock":
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


class SerialSession:
    """One owned port: lock held, serial open, monotonic ids, kept events.

    ``exchange`` sends one request and reads until the reply with the same
    ``id`` arrives, collecting interleaved ``event`` records (and stray
    wrong-``id``/malformed lines, preserved, never fatal) along the way.
    The input buffer is reset once at open, never per exchange, so events
    arriving between calls are not dropped.
    """

    def __init__(self, port: str, baud: int = BAUD):
        self.port = port
        self.baud = baud
        self._lock = PortLock(port)
        self._ser: object = None
        self._next_id = 1

    def __enter__(self) -> "SerialSession":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def open(self) -> "SerialSession":
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial not installed (pip install pyserial)") from exc
        self._lock.acquire()
        try:
            ser = serial.Serial(self.port, self.baud, timeout=READ_CHUNK)
            ser.write_timeout = 2.0
            try:
                ser.reset_input_buffer()
            except OSError:
                pass
            # Persistent read buffer: a partial line at the end of one call
            # is kept for the next call instead of being dropped, so the
            # event stream survives timeouts mid-line.
            self._pending = b""
        except Exception:
            self._lock.release()
            raise
        self._ser = ser
        self._discarding = False
        return self

    def close(self) -> None:
        ser, self._ser = self._ser, None
        try:
            if ser is not None:
                ser.close()
        finally:
            self._lock.release()

    def _take_id(self) -> int:
        value = self._next_id
        self._next_id = value + 1 if value < 2**31 - 1 else 1
        return value

    def exchange(
        self,
        op: str,
        params: dict | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> tuple[dict, list]:
        """Send ``op``; return ``(reply, events)`` with the matching ``id``.

        ``params`` is copied, never mutated. ``events`` holds every async
        record (and stray/malformed lines, preserved verbatim) seen while
        waiting. Raises :class:`TimeoutError` past the bounded deadline.
        """
        copied = dict(params) if params else {}
        cmd_id = self._take_id()
        return self.exchange_with_id(op, copied, cmd_id, timeout)

    def exchange_with_id(
        self,
        op: str,
        params: dict | None,
        cmd_id: int,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> tuple[dict, list]:
        copied = dict(params) if params else {}
        line = encode_request(cmd_id, op, **copied)
        ser = self._ser
        if ser is None:
            raise RuntimeError("session not open")
        timeout = min(max(timeout, 0.1), MAX_TIMEOUT)
        try:
            ser.write(line)
            ser.flush()
        except OSError as exc:
            raise TimeoutError(f"serial write error: {exc}") from exc
        events: list = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no reply within {timeout:g}s (id {cmd_id})")
            obj = self.read_next(remaining)
            if obj is None:
                continue
            if "event" not in obj and type(obj.get("id")) is int and obj["id"] == cmd_id:
                if type(obj.get("ok")) is bool:
                    return obj, events
            events.append(obj)

    def read_next(self, timeout: float = READ_CHUNK) -> dict | None:
        """Next parsed line for receive loops; None on quiet timeout.

        Replies to no outstanding request surface here too (late/stray),
        so callers can log rather than drop them.
        """
        ser = self._ser
        if ser is None:
            raise RuntimeError("session not open")
        deadline = time.monotonic() + min(max(timeout, 0.0), MAX_TIMEOUT)
        while True:
            if b"\n" in self._pending:
                raw, self._pending = self._pending.split(b"\n", 1)
                if self._discarding or len(raw) > MAX_INBOUND_LEN:
                    self._discarding = False
                    return {"_noise": "LINE_TOO_LONG"}
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    obj = json.loads(text)
                except ValueError:
                    return {"_noise": text[:160]}
                return obj if isinstance(obj, dict) else {"_noise": text[:160]}
            if self._discarding or len(self._pending) > MAX_INBOUND_LEN:
                self._discarding = True
                self._pending = b""
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                # Read a full chunk unconditionally: gating on in_waiting
                # starves the board's 64-byte USB TX (1-byte reads NAK-storm
                # the endpoint and the reply tail never arrives).
                ser.timeout = min(READ_CHUNK, remaining)
                self._pending += ser.read(1024)
            except OSError as exc:
                raise TimeoutError(f"serial error: {exc}") from exc


def _preserve_events(port: str, events: list) -> None:
    """File interleaved ``received`` events from one-shot calls.

    stdout stays clean for the command reply; the event stream still
    reaches history (and stderr) instead of being dropped.
    """
    import sys

    from . import history as _history
    from . import local as _local

    for evt in events:
        if not isinstance(evt, dict) or evt.get("event") != "received":
            continue
        try:
            contact = evt.get("contact_id")
            label = f"id{contact}" if isinstance(contact, int) else str(contact)
            conn = _history.open_history(_local.history_path_for(port))
            try:
                _history.record_message(
                    conn,
                    contact=label,
                    direction="in",
                    epoch=int(evt.get("epoch", 0)),
                    sequence=int(evt.get("sequence", 0)),
                    text=str(evt.get("text", "")),
                )
            finally:
                conn.close()
        except (ValueError, TypeError, OSError):
            pass
        print(json.dumps(evt, ensure_ascii=False), file=sys.stderr)


def request(port: str, body: dict, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """One owned transaction; returns the matching reply (compat wrapper).

    ``body`` is copied (callers keep their dict). Interleaved events are
    preserved to history/stderr; use :class:`SerialSession` directly when
    the caller wants them inline (``send``/``chat`` do).
    """
    copied = dict(body)
    op = copied.pop("op", "status")
    cmd_id = copied.pop("id", None)
    if not isinstance(cmd_id, int) or isinstance(cmd_id, bool):
        cmd_id = next_process_id()
    if not isinstance(op, str) or not op:
        raise ValueError("BAD_REQUEST")
    with SerialSession(port) as session:
        reply, events = session.exchange_with_id(op, copied, cmd_id, timeout)
    if events:
        _preserve_events(port, [e for e in events if isinstance(e, dict) and "event" in e])
    return reply
