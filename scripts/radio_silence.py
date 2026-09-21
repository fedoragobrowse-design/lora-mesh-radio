#!/usr/bin/env python3
"""Radio silence test: counters must not move while the network idles.

Preconditions: firmware flashed on each board, antennas fitted, nodes spaced
1-3 m apart. This script only reads the firmware's own USB `status` counters
before and after a quiet window; it transmits nothing and never flashes,
reboots, or power-cycles hardware.

There is no heartbeat in the protocol, so tx_attempts/tx_ok/forwards must be
identical across the window. Any delta is a FAIL. A radio-free image reports
RADIO_UNAVAILABLE: this script FAILs clearly in that case (a no-radio build
cannot prove RF silence) instead of passing implicitly.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

BAUD = 115200
READ_TIMEOUT = 2.0
WATCHED = ("tx_attempts", "tx_ok", "forwards")
HINT = (
    "hint: check USB data cable, BOOTSEL vs CDC, and serial permissions "
    "(dialout/uucp group or udev rule)"
)
NO_RADIO_HINT = (
    "radio-free image: silence over RF cannot be proven without RF "
    "hardware; RADIO_UNAVAILABLE is expected here"
)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Assert no RF transmissions during an idle window."
    )
    p.add_argument(
        "--ports",
        nargs="+",
        action="append",
        default=[],
        metavar="PORT",
        help="serial port(s); repeatable. Falls back to $A $B $C env vars.",
    )
    p.add_argument(
        "--minutes",
        type=float,
        default=10.0,
        help="quiet window in minutes (default %(default)s)",
    )
    p.add_argument(
        "--seconds",
        type=float,
        default=None,
        help="quiet window in seconds; overrides --minutes (for quick checks)",
    )
    return p.parse_args(argv)


def resolve_ports(args) -> list:
    ports = [p for group in args.ports for p in group]
    if not ports:
        ports = [v for k in ("A", "B", "C") if (v := os.environ.get(k))]
    return list(dict.fromkeys(ports))


def get_counters(port: str):
    """Return (counters_dict, error_str). No tracebacks."""
    try:
        import serial
    except ImportError:
        return None, "pyserial not installed (pip install pyserial)"
    try:
        with serial.Serial(port, BAUD, timeout=READ_TIMEOUT) as ser:
            ser.reset_input_buffer()
            ser.write(json.dumps({"id": 1, "op": "status"}).encode() + b"\n")
            raw = ser.readline()
    except OSError as exc:
        return None, f"serial error: {exc}"
    if not raw:
        return None, "no reply within timeout"
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "non-JSON reply"
    if reply.get("id") != 1:
        return None, "reply id mismatch (expected 1)"
    if not reply.get("ok"):
        if reply.get("error") == "RADIO_UNAVAILABLE":
            return None, f"RADIO_UNAVAILABLE. {NO_RADIO_HINT}"
        return None, f"firmware error: {reply.get('error')}"
    result = reply.get("result") or {}
    if result.get("image") == "radio-free" or result.get("radio_available") is False:
        return None, f"radio-free image. {NO_RADIO_HINT}"
    counters = result.get("counters")
    if not isinstance(counters, dict):
        return None, "status has no counters object"
    # Strict snapshot: every watched counter must exist as an integer now,
    # so a missing key cannot hide a transmission later.
    missing = [k for k in WATCHED if k not in counters]
    if missing:
        return None, f"counters missing: {', '.join(missing)}"
    bad = [k for k in WATCHED if isinstance(counters[k], bool) or not isinstance(counters[k], int)]
    if bad:
        return None, f"counters not integers: {', '.join(bad)}"
    return {k: counters[k] for k in WATCHED}, None


def countdown(total: float) -> None:
    end = time.monotonic() + total
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        mins, secs = divmod(int(remaining) + 1, 60)
        print(f"\r  waiting {mins:02d}:{secs:02d} remaining...", end="", flush=True)
        time.sleep(min(1.0, remaining))
    print("\r  wait complete.                    ")


def main(argv=None) -> int:
    args = parse_args(argv)
    ports = resolve_ports(args)
    if not ports:
        print("FAIL: no ports given (--ports or $A/$B/$C)")
        return 1
    window = args.seconds if args.seconds is not None else args.minutes * 60
    if window <= 0:
        print("FAIL: window must be positive")
        return 1

    before, failed = {}, []
    for port in ports:
        counters, err = get_counters(port)
        if err is not None:
            print(f"FAIL {port}: baseline read: {err} {HINT}")
            failed.append(port)
        else:
            before[port] = counters
            print(f"  {port} baseline: {json.dumps(counters)}")

    if failed:
        print(f"SILENCE: 0/{len(ports)} PASS (baseline unreadable)")
        return 1

    print(f"SILENCE: watching {len(ports)} port(s) for {window:.0f}s...")
    try:
        countdown(window)
    except KeyboardInterrupt:
        print("\nFAIL: interrupted; window incomplete")
        return 1

    results = []
    for port in ports:
        counters, err = get_counters(port)
        if err is not None:
            results.append(False)
            print(f"FAIL {port}: re-read: {err} {HINT}")
            continue
        delta = {
            k: (counters.get(k), before[port].get(k))
            for k in set(counters) | set(before[port])
            if counters.get(k) != before[port].get(k)
        }
        if not delta:
            results.append(True)
            print(f"PASS {port}: counters unchanged (no transmissions)")
        else:
            results.append(False)
            print(f"FAIL {port}: counters moved: {json.dumps(delta)}")
    n = sum(results)
    print(f"SILENCE: {n}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
