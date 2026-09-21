"""Shared transport surface for the newline-JSON wire.

Every transport frames one request per line (UTF-8, at most 1024 bytes
plus the newline): ``{"id": N, "op": "...", ...params}``. Replies echo
``id`` with ``ok`` plus ``result``/``error``; async records carry
``event`` instead of ``id``/``ok``.

Transports:

- ``usb`` (default): USB CDC serial via :mod:`meshctl.serial_link`.
- ``tcp``: the same bytes over TCP to the firmware WiFi server
  (port 7777) via :mod:`meshctl.transports.tcp`.
- BLE is deferred: it is deliberately NOT built here. This package MUST
  NOT grow a ``ble`` transport without a new ticket (firmware has no
  BLE task and the private-mesh default stays USB-first).

Single-owner plus bounded deadlines hold on every transport: one
session owns its endpoint (lock file; a second opener gets
``PORT_BUSY``), request ids are monotonic per session, and every wait
runs against a monotonic deadline. See ``three-pico-lora-plan.md``.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

#: Selectable transports for ``meshctl --transport``.
TRANSPORTS = ("usb", "tcp")
#: Default keeps the proven private-mesh path: USB CDC.
DEFAULT_TRANSPORT = "usb"
#: Firmware WiFi TCP server port (mirrors ``firmware/src/wifi.rs``).
DEFAULT_TCP_PORT = 7777


@runtime_checkable
class Session(Protocol):
    """Structural surface every transport session provides."""

    def open(self) -> "Session":
        """Take endpoint ownership; raises ``PORT_BUSY`` on clash."""
        ...

    def close(self) -> None:
        """Release the endpoint; idempotent."""
        ...

    def write_line(self, line: bytes) -> None:
        """Write one framed request line (already newline-terminated)."""
        ...

    def read_next(self, timeout: float = 1.0) -> dict | None:
        """Next parsed record; ``None`` on quiet timeout.

        Overlong lines surface as ``{"_noise": "LINE_TOO_LONG"}`` and
        malformed/non-dict lines as ``{"_noise": ...}``; never fatal.
        """
        ...

    def exchange(
        self,
        op: str,
        params: dict | None = None,
        timeout: float = 5.0,
    ) -> tuple[dict, list]:
        """Send ``op``; return ``(reply, events)`` with the matching ``id``."""
        ...

    def exchange_with_id(
        self,
        op: str,
        params: dict | None,
        cmd_id: int,
        timeout: float = 5.0,
    ) -> tuple[dict, list]:
        """``exchange`` with a caller-chosen id (bus worker numbering)."""
        ...

    def __enter__(self) -> "Session": ...
    def __exit__(self, *exc: Any) -> None: ...
