#!/usr/bin/env python3
"""Radio smoke test: one USB status query per node, no RF beyond firmware ops.

Preconditions: firmware flashed on each board, antennas fitted, nodes spaced
1-3 m apart. This script only sends the firmware's own USB ops
(`status`, `time_status`); it issues no radio TX itself and never flashes,
reboots, or power-cycles hardware.

Mandatory per-port checks (any miss is FAIL, never an implicit pass):
`board`, `firmware_version`, `image`, `provisioned`, `radio_enabled`,
`tx_power_dbm == 2`, `rf_profile == 915000000/SF7/BW500/CR4-5/pre8/CRC/sync12`,
a `counters` object with all seven keys
(tx_attempts/tx_ok/rx_ok/rx_crc_bad/auth_fail/replay_drop/forwards), and
`radio_version == 0x12` (SX1276 RegVersion). A radio-free image
(`image == "radio-free"` or `radio_available == false`) FAILs here with
RADIO_UNAVAILABLE: RF scripts cannot pass without RF hardware.

Usage:
    python3 scripts/radio_smoke.py --ports /dev/ttyACM0 /dev/ttyACM1
    python3 scripts/radio_smoke.py --ports $A --ports $B --ports $C
    A=/dev/ttyACM0 B=/dev/ttyACM1 python3 scripts/radio_smoke.py

    Missing/unresponsive ports report FAIL with a hint and never hang:
    every read uses a short timeout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

BAUD = 115200
READ_TIMEOUT = 2.0
REQUIRED_STATUS_FIELDS = (
    "board",
    "firmware_version",
    "image",
    "provisioned",
    "radio_enabled",
    "tx_power_dbm",
    "rf_profile",
    "counters",
)
REQUIRED_COUNTERS = (
    "tx_attempts",
    "tx_ok",
    "rx_ok",
    "rx_crc_bad",
    "auth_fail",
    "replay_drop",
    "forwards",
)
EXPECTED_TX_POWER = 2
EXPECTED_RF_PROFILE = "915000000/SF7/BW500/CR4-5/pre8/CRC/sync12"
EXPECTED_RADIO_VERSION = 0x12
HINT = (
    "hint: check USB data cable (not charge-only), BOOTSEL vs CDC "
    "(board may need flashing / may be sitting in BOOTSEL), and serial "
    "permissions (dialout/uucp group or udev rule)"
)
NO_RADIO_HINT = (
    "radio-free image: this build has no RF hardware; "
    "RADIO_UNAVAILABLE is expected and RF scripts cannot pass"
)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Query status/time_status on each LoRa node USB port."
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
        "--timeout",
        type=float,
        default=READ_TIMEOUT,
        help="per-read timeout in seconds (default %(default)s)",
    )
    return p.parse_args(argv)


def resolve_ports(args) -> list:
    ports = [p for group in args.ports for p in group]
    if not ports:
        ports = [v for k in ("A", "B", "C") if (v := os.environ.get(k))]
    # De-duplicate, preserve order.
    return list(dict.fromkeys(ports))


def query(port: str, payload: dict, timeout: float):
    """Send one JSON request, return (reply_dict, error_str). No tracebacks."""
    try:
        import serial
    except ImportError:
        return None, "pyserial not installed (pip install pyserial)"
    try:
        with serial.Serial(port, BAUD, timeout=timeout) as ser:
            ser.reset_input_buffer()
            ser.write((json.dumps(payload) + "\n").encode("utf-8"))
            raw = ser.readline()
    except OSError as exc:
        return None, f"serial error: {exc}"
    if not raw:
        return None, "no reply within timeout"
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, f"non-JSON reply: {raw[:80]!r}"
    if not isinstance(reply, dict):
        return None, f"non-object reply: {raw[:80]!r}"
    return reply, None


def check_radio_version(result: dict) -> tuple[bool, str]:
    """SX1276 RegVersion must read 0x12; missing or other values FAIL."""
    raw = result.get("radio_version", result.get("radioVersion"))
    if raw is None:
        return False, "missing radio_version (expected 0x12 for SX1276)"
    if isinstance(raw, str):
        text = raw.strip().lower()
        try:
            value = int(text, 16) if text.startswith("0x") else int(text)
        except ValueError:
            return False, f"radio_version={raw!r} unreadable (expected 0x12)"
    elif isinstance(raw, bool) or not isinstance(raw, int):
        return False, f"radio_version={raw!r} unreadable (expected 0x12)"
    else:
        value = raw
    if value != EXPECTED_RADIO_VERSION:
        return False, (
            f"radio_version=0x{value:02x} (expected 0x12: "
            "0x00/0xFF means check power, ground, CS and MISO)"
        )
    return True, "radio_version=0x12 ok"


def check_port(port: str, timeout: float):
    """Return (passed: bool, detail_lines: list[str])."""
    details = []

    reply, err = query(port, {"id": 1, "op": "status"}, timeout)
    if err is not None:
        return False, [f"status: {err}", HINT]
    if reply.get("id") != 1:
        return False, ["status: reply id mismatch (expected 1)", HINT]
    if not reply.get("ok"):
        error = reply.get("error", "")
        if error == "RADIO_UNAVAILABLE":
            return False, [f"status: RADIO_UNAVAILABLE. {NO_RADIO_HINT}"]
        return False, [f"status: firmware error: {error}", HINT]
    result = reply.get("result")
    if not isinstance(result, dict):
        return False, ["status: missing result object", HINT]
    missing = [f for f in REQUIRED_STATUS_FIELDS if f not in result]
    if missing:
        return False, [f"status: missing fields: {', '.join(missing)}", HINT]
    if result.get("image") == "radio-free" or result.get("radio_available") is False:
        return False, [
            f"status: image={result.get('image')} radio_available={result.get('radio_available')}. "
            + NO_RADIO_HINT
        ]
    details.append(
        "status: board=%s image=%s provisioned=%s radio_enabled=%s"
        % (
            result.get("board"),
            result.get("image"),
            result.get("provisioned"),
            result.get("radio_enabled"),
        )
    )
    if result["tx_power_dbm"] != EXPECTED_TX_POWER:
        return (
            False,
            details
            + [f"status: tx_power_dbm={result['tx_power_dbm']} (expected 2)"],
        )
    details.append("status: tx_power_dbm=2 ok")
    if result["rf_profile"] != EXPECTED_RF_PROFILE:
        return (
            False,
            details + [f"status: rf_profile={result['rf_profile']!r} (expected {EXPECTED_RF_PROFILE!r})"],
        )
    details.append(f"status: rf_profile={EXPECTED_RF_PROFILE} ok")
    counters = result["counters"]
    if not isinstance(counters, dict):
        return False, details + ["status: counters is not an object"]
    missing_counters = [k for k in REQUIRED_COUNTERS if k not in counters]
    if missing_counters:
        return False, details + [f"status: counters missing: {', '.join(missing_counters)}"]
    bad = [k for k in REQUIRED_COUNTERS if isinstance(counters[k], bool) or not isinstance(counters[k], int)]
    if bad:
        return False, details + [f"status: counters not integers: {', '.join(bad)}"]
    details.append(f"status: counters ok: {json.dumps({k: counters[k] for k in REQUIRED_COUNTERS})}")
    ok, line = check_radio_version(result)
    details.append(f"status: {line}")
    if not ok:
        return False, details

    treply, terr = query(port, {"id": 2, "op": "time_status"}, timeout)
    if terr is not None:
        return False, details + [f"time_status: {terr}", HINT]
    if treply.get("id") != 2:
        return False, details + ["time_status: reply id mismatch (expected 2)", HINT]
    if not treply.get("ok"):
        return False, details + [
            f"time_status: firmware error: {treply.get('error')}",
            HINT,
        ]
    details.append(f"time_status: {json.dumps(treply.get('result'))}")
    return True, details


def main(argv=None) -> int:
    args = parse_args(argv)
    ports = resolve_ports(args)
    if not ports:
        print("FAIL: no ports given (--ports or $A/$B/$C)")
        return 1
    results = []
    for port in ports:
        ok, details = check_port(port, args.timeout)
        results.append(ok)
        print(("PASS" if ok else "FAIL") + f" {port}")
        for line in details:
            print(f"  {line}")
    n = sum(results)
    print(f"SMOKE: {n}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
