"""Host transports: USB CDC (default) or TCP over WiFi.

``meshctl --transport usb|tcp`` selects; ``usb`` keeps the proven
private-mesh path. BLE is deferred and MUST NOT be added here without
a new ticket.
"""
from __future__ import annotations

from .base import DEFAULT_TCP_PORT, DEFAULT_TRANSPORT, TRANSPORTS
from .tcp import TcpSession
from .usb import UsbSession

__all__ = [
    "DEFAULT_TCP_PORT",
    "DEFAULT_TRANSPORT",
    "TRANSPORTS",
    "TcpSession",
    "UsbSession",
    "endpoint_label",
    "open_session",
]


def open_session(
    transport: str = DEFAULT_TRANSPORT,
    device: str = "",
    host: str = "127.0.0.1",
    tcp_port: int = DEFAULT_TCP_PORT,
) -> UsbSession | TcpSession:
    """Open one owned session for ``--transport usb|tcp``.

    USB takes the serial ``device`` path (``--port``); TCP takes the
    board ``host`` plus ``tcp_port`` (``--tcp-host``/``--tcp-port``,
    default 7777). Raises ``ValueError`` on an unknown transport,
    ``PORT_BUSY`` when the endpoint is owned elsewhere.
    """
    if transport == "usb":
        if not device:
            raise ValueError("--port is required for --transport usb")
        return UsbSession(device).open()
    if transport == "tcp":
        return TcpSession(host, tcp_port).open()
    raise ValueError(f"unknown transport {transport!r} (expected one of {TRANSPORTS})")


def endpoint_label(
    transport: str = DEFAULT_TRANSPORT,
    device: str = "",
    host: str = "127.0.0.1",
    tcp_port: int = DEFAULT_TCP_PORT,
) -> str:
    """Human/log label for the selected endpoint (locks, notices)."""
    if transport == "tcp":
        return f"{host}:{int(tcp_port)}"
    return device
