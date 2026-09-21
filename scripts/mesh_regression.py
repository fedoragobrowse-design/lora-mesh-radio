#!/usr/bin/env python3
"""Automated three-node RF regression: health, six-direction sends, reject, silence.

Boards are discovered by USB VID:PID and identified by matched-ID ``status``
label (A/B/C); USB serials are logged (stable identity, never ttyACM
numbering). One held ``SerialSession`` per port for the whole run (single
owner per port, no per-call buffer resets). Exits 1 on any FAIL.

Verified 2026-09-21 bilateral topology (V3, 16 slots):

  A slot1 -> B (B slot1), B slot1 -> A (A slot1),
  B slot2 -> C (C slot2), C slot2 -> B (B slot2),
  A slot2 -> C (C slot1), C slot1 -> A (A slot2).

Each leg requires TX slot present+unblocked, ``ACKNOWLEDGED``, and exactly
one matching ``received`` with the fresh marker on the intended board and
contact (no duplicates, no wrong recipients; all interleaved exchange
events are collected). Empty slot 3 on A must fail ``BAD_REQUEST`` with
zero airtime. Radios are left OFF after a 40 s settle plus a 10 s silent
window (tx_attempts/tx_ok/forwards unchanged).

CLI: ``.venv/bin/python scripts/mesh_regression.py`` (no args; needs the
three paired boards above -- run the bilateral pairing ceremony first if a
leg reports a missing slot).
"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

SEND_TIMEOUT = 45.0
QUIET_WINDOW = 10.0
# Post-ACK collective drain: must exceed one 12 s ACK wait plus relay
# jitter so late retries/duplicates still land inside the window.
DRAIN_WINDOW = 15.0
# Firmware retry budget (runtime MAX_TX): one initial TX + up to 2 retries.
MAX_TX_ATTEMPTS = 3

# USB serials are stable identity for logs only -- authority is the live
# ``status`` label, never ttyACM numbering or any expected table. Unknown
# or swapped hardware must log loudly but never FAIL here; the label,
# image, and slot-gate checks below are what FAIL.

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

def identify(
    sessions: dict[str, SerialSession], serial_by_port: dict[str, str]
) -> dict[str, SerialSession]:
    by_label: dict[str, SerialSession] = {}
    for port, s in sessions.items():
        serial = serial_by_port.get(port, "?")
        # Informational only: never FAIL on serial mismatch; a portability
        # refusal (unknown host, swapped cables) would otherwise block all
        # RF proof with no firmware signal. Labels + slot gates decide.
        print(f"port {port} usb-serial={serial}", flush=True)
        reply, events = call(s, "status", timeout=10.0)
        for e in events:
            if isinstance(e, dict) and e.get("event") == "received":
                check(f"{port} unexpected pre-run traffic", False, str(e)[:120])
        if reply is None:
            continue
        result = reply.get("result", {})
        label = result.get("label", "")
        check(f"identify {port} label={label}", label in "ABC", str(reply)[:120])
        if label not in "ABC":
            continue
        check(f"{label} radio-secure", result.get("image") == "radio-secure", str(reply)[:120])
        check(f"{label} rv=0x12", result.get("radio_version") == 18, str(reply)[:120])
        check(f"{label} provisioned+time", result.get("provisioned") and result.get("time_valid"))
        if label in by_label:
            check(f"duplicate label {label}", False, port)
            continue
        # Prior runs leave radios off; sends need them on.
        reply_on, _ = call(s, "radio_set", {"enabled": True}, timeout=15.0)
        check(f"{label} radio on", reply_on is not None and reply_on.get("ok"), str(reply_on)[:120])
        by_label[label] = s
    check("all three boards present", set(by_label) == {"A", "B", "C"}, str(sorted(by_label)))
    return by_label

def send_and_confirm(
    tx: SerialSession,
    tx_label: str,
    tx_cid: int,
    rx: SerialSession,
    rx_label: str,
    rx_cid: int,
    marker: str,
    nodes: dict[str, SerialSession],
) -> None:
    present, present_events = call(tx, "contacts", timeout=10.0)
    hits: list[tuple[str, object]] = []
    for e in present_events:
        if isinstance(e, dict) and e.get("event") == "received" and e.get("text") == marker:
            hits.append((tx_label, e.get("contact_id")))
    if present is None:
        return
    raw_slots = present.get("result", {}).get("contacts", [])
    slots = {c.get("contact_id"): c for c in raw_slots if isinstance(c, dict)}
    info = slots.get(tx_cid, {})
    slot_ok = info.get("present") is True and info.get("blocked") is not True
    check(
        f"{tx_label} slot {tx_cid} present for {rx_label}",
        slot_ok,
        str(info)[:160],
    )
    if not slot_ok:
        return
    before_tx, before_events = call(tx, "status", timeout=10.0)
    for e in before_events:
        if isinstance(e, dict) and e.get("event") == "received" and e.get("text") == marker:
            hits.append((tx_label, e.get("contact_id")))
    if before_tx is None:
        return
    before = before_tx.get("result", {}).get("counters", {})
    if not all(k in before for k in ("tx_attempts", "forwards")):
        check(f"{tx_label} counters present", False, str(before)[:120])
        return
    attempts0 = before["tx_attempts"]
    forwards0 = before["forwards"]
    reply, tx_events = call(tx,
        "send", {"contact_id": tx_cid, "text": marker}, timeout=SEND_TIMEOUT
    )
    for e in tx_events:
        if isinstance(e, dict) and e.get("event") == "received" and e.get("text") == marker:
            hits.append((tx_label, e.get("contact_id")))
    if reply is None:
        return
    check(
        f"{tx_label}->{rx_label} ACKNOWLEDGED",
        reply.get("ok") and reply.get("result", {}).get("status") == "ACKNOWLEDGED",
        str(reply)[:160],
    )
    # Drain every board (single owner per port, sequential reads) so
    # duplicates and wrong-recipient deliveries are seen, not missed.
    # TX-side echoes never satisfy the leg: only (rx_label, rx_cid) counts.
    deadline = time.monotonic() + DRAIN_WINDOW
    while time.monotonic() < deadline:
        for board_label, s in nodes.items():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                evt = s.read_next(max(0.1, min(1.0, remaining)))
            except Exception as exc:
                check(f"{board_label} drain", False, f"{type(exc).__name__}: {exc}")
                deadline = time.monotonic()
                break
            if evt is None:
                continue
            if (
                isinstance(evt, dict)
                and evt.get("event") == "received"
                and evt.get("text") == marker
            ):
                hits.append((board_label, evt.get("contact_id")))
    intended = [(b, c) for b, c in hits if b == rx_label and c == rx_cid]
    wrong = [(b, c) for b, c in hits if not (b == rx_label and c == rx_cid)]
    check(
        f"{rx_label} got {marker!r} on contact {rx_cid} once",
        len(intended) == 1 and not wrong,
        f"hits={hits}",
    )
    after_tx, _ = call(tx, "status", timeout=10.0)
    if after_tx is None:
        return
    after = after_tx.get("result", {}).get("counters", {})
    if not all(k in after for k in ("tx_attempts", "forwards")):
        check(f"{tx_label} counters present after", False, str(after)[:120])
        return
    # attempts counts every radio TX attempt: own send retries (up to
    # MAX_TX_ATTEMPTS), scheduled relay TX, and ACK TX. forwards counts
    # only scheduled relay forwards (queue-full drops never attempt), and
    # ACK TX never increments forwards. Bound: at least the 1 own send;
    # at most MAX_TX retries + one TX per scheduled forward + 1 ACK.
    sent = after["tx_attempts"] - attempts0
    fwd = after["forwards"] - forwards0
    check(
        f"{tx_label} attempts within send+relay bound",
        1 <= sent <= MAX_TX_ATTEMPTS + fwd + 1,
        f"sent={sent} fwd={fwd}",
    )


def main() -> int:
    import serial.tools.list_ports as list_ports

    found = [p for p in list_ports.comports() if p.vid == 0x2E8A and p.pid == 1]
    ports = sorted(p.device for p in found)
    serial_by_port = {p.device: (p.serial_number or "?") for p in found}
    # Port/serial logging lives in identify() (single print per board).
    check("three CDC nodes enumerated", len(ports) == 3, str(ports))
    if failures:
        return 1
    sessions: dict[str, SerialSession] = {}
    try:
        for port in ports:
            try:
                sessions[port] = SerialSession(port).open()
            except Exception as exc:
                check(f"open {port}", False, f"{type(exc).__name__}: {exc}")
                for s in sessions.values():
                    try:
                        s.close()
                    except Exception:
                        pass
                sessions.clear()
                return 1
        nodes = identify(sessions, serial_by_port)
        if failures:
            return 1
        A, B, C = nodes["A"], nodes["B"], nodes["C"]
        stamp = str(int(time.time()) % 100000)
        send_and_confirm(A, "A", 1, B, "B", 1, f"reg-AB-{stamp}", nodes)
        send_and_confirm(B, "B", 1, A, "A", 1, f"reg-BA-{stamp}", nodes)
        send_and_confirm(B, "B", 2, C, "C", 2, f"reg-BC-{stamp}", nodes)
        send_and_confirm(C, "C", 2, B, "B", 2, f"reg-CB-{stamp}", nodes)
        send_and_confirm(A, "A", 2, C, "C", 1, f"reg-AC-{stamp}", nodes)
        send_and_confirm(C, "C", 1, A, "A", 2, f"reg-CA-{stamp}", nodes)
        a0, a0_events = call(A, "status", timeout=10.0)
        reply, rej_events = call(A, "send", {"contact_id": 3, "text": "must not air"}, timeout=10.0)
        for e in list(a0_events) + list(rej_events):
            if isinstance(e, dict) and e.get("event") == "received":
                check("no stray delivery around rejected send", False, str(e)[:120])
        if a0 is None or reply is None:
            check("empty slot BAD_REQUEST", False, "no reply")
        else:
            n0 = a0.get("result", {}).get("counters", {}).get("tx_attempts")
            check(
                "empty slot BAD_REQUEST",
                not reply.get("ok") and reply.get("error") == "BAD_REQUEST",
                str(reply)[:120],
            )
            a1, _ = call(A, "status", timeout=10.0)
            check(
                "no airtime on rejected send",
                a1 is not None
                and a1.get("result", {}).get("counters", {}).get("tx_attempts") == n0,
                str(a1)[:120],
            )
        # Silence: freeze RF first (retries/relays settled), then assert
        # nothing moves while idle. Late ACKs/retries from the sends above
        # would otherwise land inside the window.
        for label, s in nodes.items():
            reply, off_events = call(s, "radio_set", {"enabled": False}, timeout=15.0)
            for e in off_events:
                if isinstance(e, dict) and e.get("event") == "received":
                    check(f"{label} no traffic on radio-off", False, str(e)[:120])
            check(f"{label} radio off", reply is not None and reply.get("ok"), str(reply)[:120])
        time.sleep(40.0)
        snap = {}
        for label, s in nodes.items():
            r, snap_events = call(s, "status", timeout=10.0)
            for e in snap_events:
                if isinstance(e, dict) and e.get("event") == "received":
                    check(f"{label} no late delivery before silence", False, str(e)[:120])
            counters = (r or {}).get("result", {}).get("counters", {})
            if r is None or not all(k in counters for k in ("tx_attempts", "tx_ok", "forwards")):
                check(f"{label} silence snapshot", False, str(r)[:120])
                continue
            snap[label] = counters
        time.sleep(QUIET_WINDOW)
        for label, s in nodes.items():
            r, quiet_events = call(s, "status", timeout=10.0)
            for e in quiet_events:
                if isinstance(e, dict) and e.get("event") == "received":
                    check(f"{label} no delivery during silence", False, str(e)[:120])
            if r is None or label not in snap:
                check(f"{label} silent", False, "no reply" if r is None else "no snapshot")
                continue
            c = r.get("result", {}).get("counters", {})
            check(
                f"{label} silent",
                c.get("tx_attempts") == snap[label].get("tx_attempts")
                and c.get("tx_ok") == snap[label].get("tx_ok")
                and c.get("forwards") == snap[label].get("forwards"),
                str(c),
            )
    finally:
        for s in sessions.values():
            try:
                s.close()
            except Exception:
                pass
    print(f"REGRESSION: {'PASS' if not failures else 'FAIL ' + str(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
