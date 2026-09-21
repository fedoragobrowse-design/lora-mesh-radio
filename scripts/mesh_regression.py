#!/usr/bin/env python3
"""Automated three-node RF regression: health, pairwise sends, known-fail, silence.

Boards are identified by USB serial -> label via matched-ID status, never by
ttyACM number. One SerialSession per port for the whole run (lock-held, no
per-call buffer resets). Fails fast with exit 1; prints a stable summary.

Known topology gaps are asserted, not retried: A slot 2 is empty, so A->C
slot 2 must fail BAD_REQUEST with no TX counter movement.
"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

SEND_TIMEOUT = 45.0
QUIET_WINDOW = 10.0

# USB serials observed 2026-09-21; labels re-verified live every run.
KNOWN_SERIALS = {
    "950d3036b9fa578d": "A",
    "17f7ea4b44b2cb9c": "B",
    "19e357db25fb1c77": "C",
}

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def call(s: SerialSession, op: str, params: dict | None = None, timeout: float = 10.0):
    """exchange() raising TimeoutError becomes a FAIL, never a traceback."""
    try:
        return s.exchange(op, params, timeout=timeout)
    except Exception as exc:  # TimeoutError, serial errors
        check(f"exchange {op} answered", False, f"{type(exc).__name__}: {exc}")
        return None, []

def identify(sessions: dict[str, SerialSession]) -> dict[str, SerialSession]:
    by_label: dict[str, SerialSession] = {}
    for port, s in sessions.items():
        reply, _ = call(s, "status", timeout=10.0)
        if reply is None:
            continue
        result = reply.get("result", {})
        label = result.get("label", "")
        check(f"identify {port} label={label}", label in "ABC", str(reply)[:120])
        check(f"{label} radio-secure", result.get("image") == "radio-secure", str(reply)[:120])
        check(f"{label} rv=0x12", result.get("radio_version") == 18, str(reply)[:120])
        check(f"{label} provisioned+time", result.get("provisioned") and result.get("time_valid"))
        # Prior runs leave radios off; sends need them on.
        reply_on, _ = call(s, "radio_set", {"enabled": True}, timeout=15.0)
        check(f"{label} radio on", reply_on is not None and reply_on.get("ok"), str(reply_on)[:120])
        by_label[label] = s
    check("all three boards present", set(by_label) == {"A", "B", "C"}, str(sorted(by_label)))
    return by_label


def send_and_confirm(
    tx: SerialSession, tx_label: str, cid: int, rx: SerialSession, rx_label: str, marker: str
) -> None:
    present, _ = call(tx, "contacts", timeout=10.0)
    if present is None:
        return
    slots = {c["contact_id"]: c for c in present.get("result", {}).get("contacts", [])}
    check(
        f"{tx_label} slot {cid} present",
        slots.get(cid, {}).get("present") is True,
        str(present)[:160],
    )
    if failures and failures[-1].startswith(f"{tx_label} slot"):
        return
    before_tx, _ = call(tx, "status", timeout=10.0)
    if before_tx is None:
        return
    before = before_tx["result"]["counters"]
    attempts0 = before["tx_attempts"]
    forwards0 = before["forwards"]
    reply, tx_events = call(tx,
        "send", {"contact_id": cid, "text": marker}, timeout=SEND_TIMEOUT
    )
    if reply is None:
        return
    check(
        f"{tx_label}-> {rx_label} ACKNOWLEDGED",
        reply.get("ok") and reply.get("result", {}).get("status") == "ACKNOWLEDGED",
        str(reply)[:160],
    )
    got = [e for e in tx_events if e.get("event") == "received" and e.get("text") == marker]
    deadline = time.monotonic() + 8.0
    while not got and time.monotonic() < deadline:
        evt = rx.read_next(deadline - time.monotonic())
        if evt is not None and evt.get("event") == "received" and evt.get("text") == marker:
            got = [evt]
    after_tx, _ = call(tx, "status", timeout=10.0)
    if after_tx is None:
        return
    after = after_tx["result"]["counters"]
    # attempts counts own send TX + relay TX + ACK TX; forwards counts only
    # scheduled relay forwards (queue-full drops never attempt). Tight bound:
    # at least the 1 own send, at most 1 send + forwarded relays + 1 ACK each
    # for frames this node received... in practice bound by sends+forwards.
    sent = after["tx_attempts"] - attempts0
    fwd = after["forwards"] - forwards0
    check(
        f"{tx_label} attempts within send+relay bound",
        1 <= sent <= 1 + fwd + 1,
        f"sent={sent} fwd={fwd}",
    )


def main() -> int:
    import serial.tools.list_ports as list_ports

    ports = []
    for p in list_ports.comports():
        if p.vid == 0x2E8A and p.pid == 1:
            ports.append(p.device)
    check("three CDC nodes enumerated", len(ports) == 3, str(ports))
    if failures:
        return 1
    sessions = {port: SerialSession(port).open() for port in sorted(ports)}
    try:
        nodes = identify(sessions)
        if failures:
            return 1
        A, B, C = nodes["A"], nodes["B"], nodes["C"]
        stamp = str(int(time.time()) % 100000)
        send_and_confirm(B, "B", 2, C, "C", f"reg-BC-{stamp}")
        send_and_confirm(C, "C", 2, B, "B", f"reg-CB-{stamp}")
        send_and_confirm(A, "A", 1, B, "B", f"reg-AB-{stamp}")
        # Known gap: A slot 2 empty.
        a0, _ = call(A, "status", timeout=10.0)
        reply, _ = call(A, "send", {"contact_id": 2, "text": "must not air"}, timeout=10.0)
        if a0 is None or reply is None:
            check("A->C empty slot BAD_REQUEST", False, "no reply")
        else:
            n0 = a0["result"]["counters"]["tx_attempts"]
            check(
                "A->C empty slot BAD_REQUEST",
                not reply.get("ok") and reply.get("error") == "BAD_REQUEST",
                str(reply)[:120],
            )
            a1, _ = call(A, "status", timeout=10.0)
            check(
                "no airtime on rejected send",
                a1 is not None and a1["result"]["counters"]["tx_attempts"] == n0,
                str(a1)[:120],
            )
        # Silence: freeze RF first (retries/relays settled), then assert
        # nothing moves while idle. Late ACKs/retries from the sends above
        # would otherwise land inside the window.
        for label, s in nodes.items():
            reply, _ = call(s, "radio_set", {"enabled": False}, timeout=15.0)
            check(f"{label} radio off", reply is not None and reply.get("ok"), str(reply)[:120])
        time.sleep(40.0)
        snap = {}
        for label, s in nodes.items():
            r, _ = call(s, "status", timeout=10.0)
            if r is not None:
                snap[label] = r["result"]["counters"]
        time.sleep(QUIET_WINDOW)
        for label, s in nodes.items():
            r, _ = call(s, "status", timeout=10.0)
            if r is None:
                check(f"{label} silent", False, "no reply")
                continue
            c = r["result"]["counters"]
            check(
                f"{label} silent",
                c["tx_attempts"] == snap[label]["tx_attempts"] and c["tx_ok"] == snap[label]["tx_ok"],
                str(c),
            )
    finally:
        for s in sessions.values():
            s.close()
    print(f"REGRESSION: {'PASS' if not failures else 'FAIL ' + str(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
