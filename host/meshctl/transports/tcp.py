"""TCP transport: newline-JSON over WiFi (firmware TCP server, port 7777).

Byte-identical wire to USB CDC: :func:`encode_request` framing,
id-matched replies amid interleaved ``event`` records, monotonic ids,
monotonic deadlines. Single-owner holds per ``tcp:host:port`` lock
file, so a second process gets ``PORT_BUSY`` exactly like USB.

No key agreement or message encryption happens here; this module only
frames bytes, like :mod:`meshctl.serial_link`.
"""
from __future__ import annotations

import json
import socket
import time

from ..serial_link import (
    MAX_INBOUND_LEN,
    MAX_TIMEOUT,
    READ_CHUNK,
    PortLock,
    TimeoutError,
    encode_request,
)
from .base import DEFAULT_TCP_PORT


class TcpSession:
    """One owned TCP endpoint: lock held, socket open, monotonic ids.

    ``exchange`` sends one request and reads until the reply with the
    same ``id`` arrives, collecting interleaved ``event`` records (and
    stray wrong-``id``/malformed lines, preserved, never fatal) along
    the way. The read buffer persists across calls, so a partial line
    at the end of one call is kept for the next instead of dropped.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PORT):
        self.host = host
        self.port = int(port)
        self._lock = PortLock(f"tcp:{host}:{int(port)}")
        self._sock: socket.socket | None = None
        self._next_id = 1
        self._pending = b""
        self._discarding = False

    def __enter__(self) -> "TcpSession":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def open(self) -> "TcpSession":
        self._lock.acquire()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=READ_CHUNK)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._pending = b""
        except Exception:
            self._lock.release()
            raise
        self._sock = sock
        self._discarding = False
        return self

    def close(self) -> None:
        sock, self._sock = self._sock, None
        try:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        finally:
            self._lock.release()

    def write_line(self, line: bytes) -> None:
        """Write one framed request line (bus worker path)."""
        sock = self._sock
        if sock is None:
            raise RuntimeError("session not open")
        try:
            sock.sendall(line)
        except OSError as exc:
            raise TimeoutError(f"tcp write error: {exc}") from exc

    def _take_id(self) -> int:
        value = self._next_id
        self._next_id = value + 1 if value < 2**31 - 1 else 1
        return value

    def exchange(
        self,
        op: str,
        params: dict | None = None,
        timeout: float = 5.0,
    ) -> tuple[dict, list]:
        """Send ``op``; return ``(reply, events)`` with the matching ``id``.

        ``params`` is copied, never mutated. Raises :class:`TimeoutError`
        past the bounded deadline.
        """
        copied = dict(params) if params else {}
        cmd_id = self._take_id()
        return self.exchange_with_id(op, copied, cmd_id, timeout)

    def exchange_with_id(
        self,
        op: str,
        params: dict | None,
        cmd_id: int,
        timeout: float = 5.0,
    ) -> tuple[dict, list]:
        copied = dict(params) if params else {}
        line = encode_request(cmd_id, op, **copied)
        if self._sock is None:
            raise RuntimeError("session not open")
        timeout = min(max(timeout, 0.1), MAX_TIMEOUT)
        self.write_line(line)
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
        so callers can log rather than drop them. A closed peer raises
        :class:`TimeoutError` (a ``RuntimeError``), matching the serial
        disconnect surfacing the bus worker already handles.
        """
        sock = self._sock
        if sock is None:
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
                sock.settimeout(min(READ_CHUNK, remaining))
                chunk = sock.recv(1024)
            except socket.timeout:
                continue
            except OSError as exc:
                raise TimeoutError(f"tcp read error: {exc}") from exc
            if not chunk:
                raise TimeoutError("tcp connection closed by peer")
            self._pending += chunk
