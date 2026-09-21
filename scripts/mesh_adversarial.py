#!/usr/bin/env python3
"""Adversarial messaging: boundaries, hostile text, protocol abuse, bursts.

Boards discovered by USB VID:PID, identified by serial->label via status.
Radios enabled at start, left ON (manual RF follows). Fails fast per case
with exit 1; every reject asserts zero airtime delta.
"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

SEND_TIMEOUT = 45.0
failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def call(s: SerialSession, op: str, params: dict | None = None, timeout: float = 10.0):
    try:
        return s.exchange(op, params, timeout=timeout)
    except Exception as exc:
        check(f"exchange {op} answered", False, f"{type(exc).__name__}: {exc}")
        return None, []


def attempts(s: SerialSession) -> int:
    r, _ = call(s, "status", timeout=10.0)
    return r["result"]["counters"]["tx_attempts"] if r else -1


def expect_reject(s, label, op, params, err, tag):
    n0 = attempts(s)
    reply, _ = call(s, op, params, timeout=10.0)
    ok = reply is not None and not reply.get("ok") and reply.get("error") == err
    check(f"{label} {tag} -> {err}", ok, str(reply)[:140])
    check(f"{label} {tag} no airtime", attempts(s) == n0, f"n0={n0}")


def expect_send(tx, txl, cid, text, rx, rxl, tag):
    reply, _ = call(tx, "send", {"contact_id": cid, "text": text}, timeout=SEND_TIMEOUT)
    ok = reply is not None and reply.get("ok")
    status = (reply or {}).get("result", {}).get("status")
    check(f"{txl} {tag} ACKNOWLEDGED", ok and status == "ACKNOWLEDGED", str(reply)[:140])
    deadline = time.monotonic() + 8.0
    got = []
    while not got and time.monotonic() < deadline:
        evt = rx.read_next(deadline - time.monotonic())
        if evt is not None and evt.get("event") == "received" and evt.get("text") == text:
            got = [evt]
    check(f"{rxl} {tag} intact", len(got) == 1, f"events={len(got)}")


def isolate(nodes: dict[str, SerialSession], active: list[str]) -> None:
    """Radio-off everything outside `active` so directed sends see no relay."""
    for label, s in nodes.items():
        if label in active:
            continue
        reply, _ = call(s, "radio_set", {"enabled": False}, timeout=15.0)
        check(f"{label} isolated (radio off)", reply is not None and reply.get("ok"))


def main() -> int:
    import serial.tools.list_ports as list_ports

    ports = [p.device for p in list_ports.comports() if p.vid == 0x2E8A and p.pid == 1]
    check("three CDC nodes enumerated", len(ports) == 3, str(ports))
    if failures:
        return 1
    sessions = {port: SerialSession(port).open() for port in sorted(ports)}
    try:
        nodes: dict[str, SerialSession] = {}
        for port, s in sessions.items():
            reply, _ = call(s, "status", timeout=10.0)
            if reply is None:
                continue
            label = reply["result"].get("label", "?")
            nodes[label] = s
            on, _ = call(s, "radio_set", {"enabled": True}, timeout=15.0)
            check(f"{label} radio on", on is not None and on.get("ok"))
        if set(nodes) != {"A", "B", "C"}:
            check("all three identified", False, str(sorted(nodes)))
            return 1
        A, B, C = nodes["A"], nodes["B"], nodes["C"]
        stamp = str(int(time.time()) % 100000)

        # 1-4. Directed B->C with A isolated: no relay skew on oracles.
        isolate(nodes, ["B", "C"])
        # 1. Boundaries B->C slot 2.
        expect_send(B, "B", 2, "x", C, "C", "1-char")
        expect_send(B, "B", 2, "y" * 160, C, "C", "160-char")
        expect_reject(B, "B", "send", {"contact_id": 2, "text": ""}, "BAD_REQUEST", "empty")
        expect_reject(B, "B", "send", {"contact_id": 2, "text": "z" * 161}, "BAD_REQUEST", "161-char")
        # 2. UTF-8 + escaping.
        expect_send(B, "B", 2, "héllo wörld ✓ " + stamp, C, "C", "multibyte")
        expect_send(B, "B", 2, 'q"uote\\slash\nnewline ' + stamp, C, "C", "escapes")
        expect_send(B, "B", 2, '{"fake":"json"} ' + stamp, C, "C", "json-lookalike")
        # 3. Bad contacts.
        for cid in (0, 3, 99):
            expect_reject(B, "B", "send", {"contact_id": cid, "text": "no"}, "BAD_REQUEST", f"cid{cid}")
        # 3b. Invalid UTF-8 over raw USB: lone continuation bytes must be
        # BAD_REQUEST with no airtime (engine validate_body rejects).
        import serial as pyserial
        n0 = attempts(B)
        bport = [p for p, s in sessions.items() if s is B][0]
        sessions[bport].close()
        del sessions[bport]
        raw = pyserial.Serial(bport, 115200, timeout=6)
        raw.reset_input_buffer()
        raw.write(b'{"id":700,"op":"send","contact_id":2,"text":"bad\xff\xfe"}\n')
        import json as _json
        got = None
        t0 = time.monotonic()
        while time.monotonic() - t0 < 8:
            line = raw.readline()
            if not line:
                continue
            try:
                d = _json.loads(line)
            except ValueError:
                continue
            if d.get("id") in (700, 0):
                got = d
                break
        raw.close()
        # Raw \xff\xfe bytes are not valid JSON: the line parser rejects the
        # whole line against id 0 (not the request id -- it never parsed).
        ok = got is not None and got.get("error") == "BAD_REQUEST" and got.get("id") in (700, 0)
        check("B invalid-utf8 BAD_REQUEST", ok, str(got)[:120])
        from meshctl.serial_link import SerialSession as _SS
        sessions[bport] = _SS(bport).open()
        B = sessions[bport]
        check("B invalid-utf8 no airtime", attempts(B) == n0, "")

        # 4. Blocked contact: block C slot2 on B, send, unblock.
        rb, _ = call(B, "block", {"contact_id": 2}, timeout=10.0)
        check("B block slot2", rb is not None and rb.get("ok"), str(rb)[:120])
        expect_reject(B, "B", "send", {"contact_id": 2, "text": "blocked"}, "CONTACT_BLOCKED", "blocked")
        ru, _ = call(B, "unblock", {"contact_id": 2}, timeout=10.0)
        check("B unblock slot2", ru is not None and ru.get("ok"), str(ru)[:120])
        expect_send(B, "B", 2, f"unblocked-{stamp}", C, "C", "unblocked")

        # 5. Burst: 5 rapid B->C; each ACKs in order, texts intact.
        markers = [f"burst{i}-{stamp}" for i in range(5)]
        for m in markers:
            reply, _ = call(B, "send", {"contact_id": 2, "text": m}, timeout=SEND_TIMEOUT)
            check(f"B burst {m} ACK", reply is not None and reply.get("result", {}).get("status") == "ACKNOWLEDGED", str(reply)[:120])
        deadline = time.monotonic() + 20.0
        seen: list[str] = []
        while len(seen) < 5 and time.monotonic() < deadline:
            evt = C.read_next(deadline - time.monotonic())
            if evt is not None and evt.get("event") == "received" and evt.get("text") in markers:
                seen.append(evt["text"])
        check("C burst order+intact", seen == markers, str(seen))
        # 6. Liveness: parser still healthy after hostile inputs above.
        expect_send(B, "B", 2, f"post-hostile-{stamp}", C, "C", "post-hostile")
    finally:
        for s in sessions.values():
            s.close()
    print(f"ADVERSARIAL: {'PASS' if not failures else 'FAIL ' + str(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
