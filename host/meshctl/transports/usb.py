"""USB CDC transport: the default newline-JSON session."""
from __future__ import annotations

from .. import serial_link


class UsbSession(serial_link.SerialSession):
    """A USB session exposing the shared ``write_line`` primitive.

    Identical wire, ownership and deadlines to
    :class:`meshctl.serial_link.SerialSession`; the extra method lets
    the event bus write without touching serial privates.
    """

    def write_line(self, line: bytes) -> None:
        ser = self._ser
        if ser is None:
            raise RuntimeError("session not open")
        ser.write(line)
        ser.flush()


def open_session(device: str) -> UsbSession:
    """Open one owned USB session (``PORT_BUSY`` when owned elsewhere)."""
    return UsbSession(device).open()
