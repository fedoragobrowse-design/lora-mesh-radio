#!/usr/bin/env python3
"""All-directions live messaging check: six directed sends across A/B/C.

Discovery: boards are found by USB VID:PID (0x2E8A:0001) and identified by
matched-ID ``status`` label (A/B/C), never by ``/dev/ttyACM`` numbering.
One held ``SerialSession`` per port for the whole run (single owner per
port, no concurrent opens of the same device).

Default directed edges match the verified 2026-09-21 bilateral repair
(A2<->C1 activated, proof/confirm bilateral):

  A slot1 -> B (arrives B slot1)
  B slot1 -> A (arrives A slot1)
  B slot2 -> C (arrives C slot2)
  C slot2 -> B (arrives B slot2)
  A slot2 -> C (arrives C slot1)
  C slot1 -> A (arrives A slot2)

Override any directed edge explicitly; never infer reciprocity from equal
contact fingerprints (``contacts`` fingerprint is SHA256 of the peer
signing public key, NOT a shared pair secret)::

  .venv/bin/python scripts/mesh_allways.py --edge A:C=2:1 --edge C:A=1:2

Edge syntax is ``TX:RX=TXSLOT:RXSLOT`` (slots 1..16, TX != RX). Repeating
``--edge`` replaces that directed pair only; unmentioned pairs keep the
defaults above.

Acceptance per direction: TX slot present and unblocked, ``send`` replies
``ACKNOWLEDGED``, exactly one matching ``received`` with the fresh marker
text arrives on the intended board with the expected contact id, and the
same text appears nowhere else (no duplicates, no wrong recipients).
Any ACK miss, contact miss, duplicate, wrong recipient, timeout, or serial
error is a FAIL. Exits 0 only when all six pass, 1 otherwise.

No pairing, unpairing, block, or delete ops are issued here.
"""
from __future__ import annotations

import argparse
import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

SEND_TIMEOUT = 60.0
DRAIN_WINDOW = 10.0
MAX_CONTACTS = 16

DEFAULT_EDGES: list[tuple[str, int, str, int]] = [
    ("A", 1, "B", 1),
    ("B", 1, "A", 1),
    ("B", 2, "C", 2),
    ("C", 2, "B", 2),
    ("A", 2, "C", 1),
    ("C", 1, "A", 2),
]

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def call(s: SerialSession, op: str, params: dict | None = None, timeout: float = 10.0):
    """exchange() raising becomes a FAIL, never a traceback."""
    try:
        return s.exchange(op, params, timeout=timeout)
    except Exception as exc:  # TimeoutError, serial errors, PORT_BUSY
        check(f"exchange {op} answered", False, f"{type(exc).__name__}: {exc}")
        return None, []


def parse_edge(raw: str) -> tuple[str, int, str, int]:
    try:
        pair, slots = raw.split("=", 1)
        tx, rx = pair.replace(">", ":").split(":", 1)
        tx_slot_s, rx_slot_s = slots.split(":", 1)
        tx, rx = tx.strip().upper(), rx.strip().upper()
        tx_slot, rx_slot = int(tx_slot_s), int(rx_slot_s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--edge must be TX:RX=TXSLOT:RXSLOT (got {raw!r}, e.g. A:C=2:1)"
        )
    if tx not in "ABC" or rx not in "ABC" or tx == rx:
        raise argparse.ArgumentTypeError(f"--edge needs distinct A/B/C ends (got {raw!r})")
    if not (1 <= tx_slot <= MAX_CONTACTS and 1 <= rx_slot <= MAX_CONTACTS):
        raise argparse.ArgumentTypeError(f"--edge slots must be 1..{MAX_CONTACTS} (got {raw!r})")
    return (tx, tx_slot, rx, rx_slot)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--edge",
        action="append",
        default=[],
        help="override one directed edge as TX:RX=TXSLOT:RXSLOT (repeatable)",
    )
    p.add_argument("--send-timeout", type=float, default=SEND_TIMEOUT)
    p.add_argument("--drain", type=float, default=DRAIN_WINDOW)
    return p.parse_args(argv)


def resolve_edges(extra: list[str]) -> list[tuple[str, int, str, int]]:
    edges = list(DEFAULT_EDGES)
    for raw in extra:
        tx, tx_slot, rx, rx_slot = parse_edge(raw)
        edges = [e for e in edges if not (e[0] == tx and e[2] == rx)]
        edges.append((tx, tx_slot, rx, rx_slot))
    order = {(tx, rx): i for i, (tx, _, rx, _) in enumerate(DEFAULT_EDGES)}
    edges.sort(key=lambda e: order.get((e[0], e[2]), 99))
    return edges


def main(argv=None) -> int:
    import serial.tools.list_ports as list_ports

    args = parse_args(argv)
    try:
        edges = resolve_edges(args.edge)
    except argparse.ArgumentTypeError as exc:
        print(f"FAIL {exc}")
        return 1
    send_timeout = max(1.0, min(float(args.send_timeout), 120.0))
    drain_window = max(1.0, min(float(args.drain), 60.0))

    ports = [p.device for p in list_ports.comports() if p.vid == 0x2E8A and p.pid == 1]
    check("three CDC nodes enumerated", len(ports) == 3, str(ports))
    if failures:
        return 1

    sessions: dict[str, SerialSession] = {}
    try:
        for port in sorted(ports):
            try:
                sessions[port] = SerialSession(port).open()
            except Exception as exc:
                check(f"open {port}", False, f"{type(exc).__name__}: {exc}")
                return 1
        # Identify by live label; USB serials are stable, tty numbers are not.
        nodes: dict[str, SerialSession] = {}
        for port, s in sessions.items():
            reply, _ = call(s, "status", timeout=10.0)
            if reply is None:
                continue
            result = reply.get("result", {})
            label = result.get("label", "")
            check(f"identify {port} label={label}", label in "ABC", str(reply)[:120])
            if label not in "ABC":
                continue
            check(
                f"{label} radio-secure",
                result.get("image") == "radio-secure",
                str(reply)[:120],
            )
            check(f"{label} rv=0x12", result.get("radio_version") == 18, str(reply)[:120])
            check(
                f"{label} provisioned+time",
                bool(result.get("provisioned")) and bool(result.get("time_valid")),
            )
            if label in nodes:
                check(f"duplicate label {label}", False, port)
                continue
            nodes[label] = s
        check("all three boards present", set(nodes) == {"A", "B", "C"}, str(sorted(nodes)))
        if failures:
            return 1

        now = int(time.time())
        for label, s in nodes.items():
            reply, _ = call(s, "time_set", {"unix_seconds": now}, timeout=15.0)
            check(f"{label} time sync", reply is not None and reply.get("ok"), str(reply)[:120])
        for label, s in nodes.items():
            reply, _ = call(s, "radio_set", {"enabled": True}, timeout=15.0)
            check(f"{label} radio on", reply is not None and reply.get("ok"), str(reply)[:120])
        if failures:
            return 1
        assert set(nodes) == {"A", "B", "C"}

        stamp = int(time.time()) % 100000
        markers: dict[str, tuple[str, int, str, int]] = {}
        for i, (tx, tx_slot, rx, rx_slot) in enumerate(edges):
            text = f"all-{tx}{tx_slot}{rx}{rx_slot}-{stamp}-{i}"
            markers[text] = (tx, tx_slot, rx, rx_slot)
        observed: dict[str, list[tuple[str, object]]] = {m: [] for m in markers}

        def note(events: list, board_label: str) -> None:
            for e in events:
                if (
                    isinstance(e, dict)
                    and e.get("event") == "received"
                    and isinstance(e.get("text"), str)
                    and e.get("text") in observed
                ):
                    observed[e["text"]].append((board_label, e.get("contact_id")))

        acked: dict[str, bool] = {}
        for text, (tx, tx_slot, rx, rx_slot) in markers.items():
            tx_s = nodes[tx]
            present, present_events = call(tx_s, "contacts", timeout=10.0)
            note(present_events, tx)
            if present is None:
                check(f"{tx}->{rx} slot gate", False, "no contacts reply")
                continue
            slots = {
                c.get("contact_id"): c
                for c in present.get("result", {}).get("contacts", [])
                if isinstance(c, dict)
            }
            info = slots.get(tx_slot, {})
            slot_ok = info.get("present") is True and info.get("blocked") is not True
            check(
                f"{tx} slot {tx_slot} present for {rx}",
                slot_ok,
                str(info)[:120],
            )
            if not slot_ok:
                continue
            reply, tx_events = call(
                tx_s, "send", {"contact_id": tx_slot, "text": text}, timeout=send_timeout
            )
            note(tx_events, tx)
            if reply is None:
                check(f"{tx}->{rx} ACKNOWLEDGED", False, "no reply")
                acked[text] = False
                continue
            ack = reply.get("ok") and reply.get("result", {}).get("status") == "ACKNOWLEDGED"
            check(f"{tx}->{rx} slot{tx_slot} ACKNOWLEDGED", ack, str(reply)[:160])
            acked[text] = bool(ack)
        # One collective drain over every board (single owner per port,
        # sequential reads) AFTER all sends: late duplicates/wrong-recipient
        # deliveries landing after an early leg must still fail that leg.
        deadline = time.monotonic() + max(drain_window, 10.0)
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
                if isinstance(evt, dict) and evt.get("event") == "received":
                    if isinstance(evt.get("text"), str) and evt.get("text") in observed:
                        observed[evt["text"]].append((board_label, evt.get("contact_id")))
        passed = 0
        for text, (tx, tx_slot, rx, rx_slot) in markers.items():
            hits = observed.get(text, [])
            intended = [(b, c) for b, c in hits if b == rx and c == rx_slot]
            wrong = [(b, c) for b, c in hits if not (b == rx and c == rx_slot)]
            ok = acked.get(text) is True and len(intended) == 1 and not wrong
            check(
                f"{rx} got {text!r} on contact {rx_slot} once",
                ok,
                f"hits={hits}",
            )
            if ok:
                passed += 1

        print(f"delivered {passed}/{len(markers)}", flush=True)
        return 0 if not failures else 1
    finally:
        for s in sessions.values():
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
