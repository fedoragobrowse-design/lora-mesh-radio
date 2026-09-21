"""Single-owner CDC event bus shared by Tk and curses frontends."""
from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field

from . import contacts, serial_link
from .transports import DEFAULT_TCP_PORT, DEFAULT_TRANSPORT, open_session


@dataclass
class BusEvent:
    """One item for the UI poll loop, keyed by stable USB serial."""

    board: str
    kind: str
    text: str
    contact_id: int = 0
    epoch: int = 0
    sequence: int = 0


@dataclass
class BoardLink:
    serial: str
    device: str
    session: object
    label: str = ""
    commands: queue.Queue = field(default_factory=queue.Queue)
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class EventBus:
    """One worker per port owns all reads, writes and request deadlines."""

    def __init__(self) -> None:
        self.events: queue.Queue[BusEvent] = queue.Queue()
        self._links: dict[str, BoardLink] = {}
        self._lock = threading.Lock()

    def attach(self, serial: str, device: str, label: str = "",
               transport: str = DEFAULT_TRANSPORT,
               host: str = "127.0.0.1", tcp_port: int = DEFAULT_TCP_PORT) -> None:
        """Own one endpoint: USB serial path (default) or TCP over WiFi.

        ``transport`` selects ``usb`` (``device`` is the --port path) or
        ``tcp`` (``host``/``tcp_port`` target the firmware WiFi server,
        default 7777). One worker per endpoint owns all reads, writes
        and request deadlines, on either transport.
        """
        with self._lock:
            if serial in self._links:
                return
            endpoint = f"{host}:{tcp_port}" if transport == "tcp" else device
            try:
                session = open_session(transport, device=device, host=host, tcp_port=tcp_port)
            except (ValueError, RuntimeError, OSError) as exc:
                self.events.put(BusEvent(serial, "error", str(exc)))
                return
            link = BoardLink(serial, device, session, label)
            link.thread = threading.Thread(target=self._reader, args=(link,), daemon=True)
            self._links[serial] = link
            self.events.put(BusEvent(serial, "notice", f"attached {endpoint} ({label or serial[:8]})"))
            # Thread.start() never blocks, so starting under the lock keeps
            # attach/detach atomic: no gap where detach misses the thread.
            link.thread.start()

    def detach(self, serial: str) -> None:
        with self._lock:
            link = self._links.get(serial)
            if link is None:
                return
            link.stop.set()
        # Worker closes the port before detach returns; never close beneath read().
        if link.thread is not None:
            link.thread.join()
        self.events.put(BusEvent(serial, "notice", "detached"))

    def detach_all(self) -> None:
        with self._lock:
            serials = list(self._links)
        for serial in serials:
            self.detach(serial)

    def request(self, serial: str, op: str, params: dict | None = None,
                timeout: float = 5.0) -> None:
        copied = dict(params or {})
        try:
            serial_link.encode_request(1, op, **copied)
            timeout = min(max(float(timeout), 0.1), serial_link.MAX_TIMEOUT)
        except (TypeError, ValueError) as exc:
            self.events.put(BusEvent(serial, "error", str(exc)))
            return
        with self._lock:
            link = self._links.get(serial)
            if link is None or link.stop.is_set():
                self.events.put(BusEvent(serial, "error", "not attached"))
                return
            link.commands.put((op, copied, time.monotonic() + timeout))
    def poll(self) -> list[BusEvent]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out

    def _reader(self, link: BoardLink) -> None:
        pending = {}
        next_id = 1
        try:
            while not link.stop.is_set():
                # Expire on every iteration, including continuous receive traffic.
                now = time.monotonic()
                for cmd_id, (deadline, op, params) in list(pending.items()):
                    if now >= deadline:
                        del pending[cmd_id]
                        self.events.put(BusEvent(link.serial, "error", f"no reply (id {cmd_id}, {op})"))
                try:
                    op, params, deadline = link.commands.get_nowait()
                except queue.Empty:
                    pass
                else:
                    if time.monotonic() >= deadline:
                        self.events.put(BusEvent(link.serial, "error", f"request expired before write ({op})"))
                    else:
                        cmd_id = next_id
                        next_id = next_id + 1 if next_id < 2**31 - 1 else 1
                        line = serial_link.encode_request(cmd_id, op, **params)
                        link.session.write_line(line)
                        pending[cmd_id] = (deadline, op, params)
                obj = link.session.read_next(timeout=0.05)
                if obj is None:
                    continue
                if obj.get("event") == "received":
                    try:
                        event = BusEvent(link.serial, "received", str(obj.get("text", "")),
                                         int(obj.get("contact_id", 0)), int(obj.get("epoch", 0)),
                                         int(obj.get("sequence", 0)))
                    except (TypeError, ValueError):
                        self.events.put(BusEvent(link.serial, "error", "malformed received event"))
                    else:
                        self.events.put(event)
                    continue
                cmd_id = obj.get("id")
                if "event" not in obj and type(cmd_id) is int and type(obj.get("ok")) is bool and cmd_id in pending:
                    deadline, op, params = pending.pop(cmd_id)
                    if time.monotonic() >= deadline:
                        self.events.put(BusEvent(link.serial, "error", f"late reply (id {cmd_id}, {op})"))
                        continue
                    if op == "contact_delete" and obj["ok"] and obj.get("result", {}).get("deleted") is True:
                        cid = params.get("contact_id")
                        if isinstance(cid, bool) or not isinstance(cid, int):
                            self.events.put(BusEvent(link.serial, "error", "deleted on board; mapping cleanup skipped: bad contact_id"))
                        else:
                            try:
                                contacts.drop_contact(link.serial, "", cid)
                            except (ValueError, OSError) as exc:
                                self.events.put(BusEvent(link.serial, "error", f"deleted on board; mapping cleanup failed: {exc}"))
                    self.events.put(BusEvent(link.serial, "reply", json.dumps(obj, ensure_ascii=False)))
                else:
                    self.events.put(BusEvent(link.serial, "notice", json.dumps(obj, ensure_ascii=False)))
        except (OSError, RuntimeError, ValueError) as exc:
            self.events.put(BusEvent(link.serial, "error", f"serial error: {exc}"))
        finally:
            link.stop.set()
            for cmd_id, (_, op, _) in pending.items():
                self.events.put(BusEvent(link.serial, "error", f"disconnected before reply (id {cmd_id}, {op})"))
            try:
                link.session.close()
            finally:
                with self._lock:
                    if self._links.get(link.serial) is link:
                        del self._links[link.serial]
