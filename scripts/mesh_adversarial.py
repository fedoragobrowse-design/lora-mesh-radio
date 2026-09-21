#!/usr/bin/env python3
"""Adversarial messaging: boundaries, hostile text, protocol abuse, bursts.

Boards discovered by USB VID:PID, identified by matched-ID ``status``
label (A/B/C); one held ``SerialSession`` per port (single owner per
port). Radios enabled at start, left ON (manual RF follows). Exits 1 on
any FAIL; every reject asserts zero airtime delta. Directed B2<->C2 edges
are exercised below (valid after the 2026-09-21 A/C repair on the V3
16-slot map A1<->B1, B2<->C2, A2<->C1). Bad-contact probes use
out-of-range ids 0/99 and the empty slot 3 everywhere (fail closed with
no airtime); no occupied slot is blocked or deleted here.

CLI: ``.venv/bin/python scripts/mesh_adversarial.py`` (no args; needs the
three paired boards above -- A radio-off, B/C radio-on isolation for the
directed B->C cases).
"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

SEND_TIMEOUT = 45.0
DRAIN_WINDOW = 10.0


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
    r, events = call(s, "status", timeout=10.0)
    for e in events:
        if isinstance(e, dict) and e.get("event") == "received":
            check("no stray traffic during airtime probe", False, str(e)[:120])
    return r["result"]["counters"]["tx_attempts"] if r else -1


def expect_reject(s, label, op, params, err, tag):
    n0 = attempts(s)
    reply, events = call(s, op, params, timeout=10.0)
    for e in events:
        if isinstance(e, dict) and e.get("event") == "received":
            check(f"{label} {tag} no delivery on reject", False, str(e)[:120])
    ok = reply is not None and not reply.get("ok") and reply.get("error") == err
    check(f"{label} {tag} -> {err}", ok, str(reply)[:140])
    check(f"{label} {tag} no airtime", attempts(s) == n0, f"n0={n0}")


def expect_send(tx, txl, tx_cid, text, rx, rxl, rx_cid, tag, nodes):
    # Slot gate first: blocked or missing slots must not air.
    present, present_events = call(tx, "contacts", timeout=10.0)
    hits: list[tuple[str, object]] = []
    for e in present_events:
        if isinstance(e, dict) and e.get("event") == "received" and e.get("text") == text:
            hits.append((txl, e.get("contact_id")))
    if present is None:
        check(f"{txl} {tag} slot gate", False, "no contacts reply")
        return
    info = {c["contact_id"]: c for c in present.get("result", {}).get("contacts", [])}.get(tx_cid, {})
    slot_ok = info.get("present") is True and info.get("blocked") is not True
    check(f"{txl} {tag} slot {tx_cid} present", slot_ok, str(info)[:140])
    if not slot_ok:
        return
    reply, tx_events = call(tx, "send", {"contact_id": tx_cid, "text": text}, timeout=SEND_TIMEOUT)
    for e in tx_events:
        if isinstance(e, dict) and e.get("event") == "received" and e.get("text") == text:
            hits.append((txl, e.get("contact_id")))
    ok = reply is not None and reply.get("ok")
    status = (reply or {}).get("result", {}).get("status")
    check(f"{txl} {tag} ACKNOWLEDGED", ok and status == "ACKNOWLEDGED", str(reply)[:140])
    # Drain every board (single owner per port, sequential reads);
    # TX-side echoes never satisfy the case: only (rxl, rx_cid) counts.
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
                and evt.get("text") == text
            ):
                hits.append((board_label, evt.get("contact_id")))
    intended = [(b, c) for b, c in hits if b == rxl and c == rx_cid]
    wrong = [(b, c) for b, c in hits if not (b == rxl and c == rx_cid)]
    check(f"{rxl} {tag} intact once on contact {rx_cid}", len(intended) == 1 and not wrong, f"hits={hits}")


def isolate(nodes: dict[str, SerialSession], active: list[str]) -> None:
    """Radio-off everything outside `active` so directed sends see no relay."""
    for label, s in nodes.items():
        if label in active:
            continue
        reply, events = call(s, "radio_set", {"enabled": False}, timeout=15.0)
        for e in events:
            if isinstance(e, dict) and e.get("event") == "received":
                check(f"{label} no traffic during isolate", False, str(e)[:120])
        check(f"{label} isolated (radio off)", reply is not None and reply.get("ok"))


def main() -> int:
    import serial.tools.list_ports as list_ports

    found = [p for p in list_ports.comports() if p.vid == 0x2E8A and p.pid == 1]
    ports = sorted(p.device for p in found)
    for p in found:
        print(f"port {p.device} usb-serial={p.serial_number}", flush=True)
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
        nodes: dict[str, SerialSession] = {}
        for port, s in sessions.items():
            reply, events = call(s, "status", timeout=10.0)
            for e in events:
                if isinstance(e, dict) and e.get("event") == "received":
                    check(f"{port} unexpected pre-run traffic", False, str(e)[:120])
            if reply is None:
                continue
            result = reply.get("result", {})
            label = result.get("label", "?")
            check(f"identify {port} label={label}", label in "ABC", str(reply)[:120])
            if label not in "ABC":
                continue
            check(f"{label} radio-secure", result.get("image") == "radio-secure", str(reply)[:120])
            check(f"{label} rv=0x12", result.get("radio_version") == 18, str(reply)[:120])
            check(f"{label} provisioned+time", bool(result.get("provisioned")) and bool(result.get("time_valid")))
            if label in nodes:
                check(f"duplicate label {label}", False, port)
                continue
            nodes[label] = s
            on, on_events = call(s, "radio_set", {"enabled": True}, timeout=15.0)
            for e in on_events:
                if isinstance(e, dict) and e.get("event") == "received":
                    check(f"{label} unexpected traffic on radio-on", False, str(e)[:120])
            check(f"{label} radio on", on is not None and on.get("ok"))
        if set(nodes) != {"A", "B", "C"}:
            check("all three identified", False, str(sorted(nodes)))
            return 1
        A, B, C = nodes["A"], nodes["B"], nodes["C"]
        stamp = str(int(time.time()) % 100000)

        # 1-4. Directed B->C with A isolated: no relay skew on oracles.
        isolate(nodes, ["B", "C"])
        # 1. Boundaries B slot2 -> C slot2.
        expect_send(B, "B", 2, "x", C, "C", 2, "1-char", nodes)
        expect_send(B, "B", 2, "y" * 160, C, "C", 2, "160-char", nodes)
        expect_reject(B, "B", "send", {"contact_id": 2, "text": ""}, "BAD_REQUEST", "empty")
        expect_reject(B, "B", "send", {"contact_id": 2, "text": "z" * 161}, "BAD_REQUEST", "161-char")
        # 2. UTF-8 + escaping.
        expect_send(B, "B", 2, "héllo wörld ✓ " + stamp, C, "C", 2, "multibyte", nodes)
        expect_send(B, "B", 2, 'q"uote\\slash\nnewline ' + stamp, C, "C", 2, "escapes", nodes)
        expect_send(B, "B", 2, '{"fake":"json"} ' + stamp, C, "C", 2, "json-lookalike", nodes)
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
        try:
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
        finally:
            raw.close()
        # Raw \xff\xfe bytes are not valid JSON: the line parser rejects the
        # whole line against id 0 (not the request id -- it never parsed).
        ok = got is not None and got.get("error") == "BAD_REQUEST" and got.get("id") in (700, 0)
        check("B invalid-utf8 BAD_REQUEST", ok, str(got)[:120])
        from meshctl.serial_link import SerialSession as _SS
        try:
            sessions[bport] = _SS(bport).open()
        except Exception as exc:
            check("B reopen after raw probe", False, f"{type(exc).__name__}: {exc}")
            return 1
        B = sessions[bport]
        nodes["B"] = B
        check("B invalid-utf8 no airtime", attempts(B) == n0, "")

        # 4. Blocked contact: block C slot2 on B, send, unblock.
        rb, _ = call(B, "block", {"contact_id": 2}, timeout=10.0)
        check("B block slot2", rb is not None and rb.get("ok"), str(rb)[:120])
        expect_reject(B, "B", "send", {"contact_id": 2, "text": "blocked"}, "CONTACT_BLOCKED", "blocked")
        ru, _ = call(B, "unblock", {"contact_id": 2}, timeout=10.0)
        check("B unblock slot2", ru is not None and ru.get("ok"), str(ru)[:120])
        expect_send(B, "B", 2, f"unblocked-{stamp}", C, "C", 2, "unblocked", nodes)

        # 5. Burst: 5 rapid B slot2 -> C slot2; each ACKs, then drain every
        # board (single owner per port, sequential reads). Each marker must
        # arrive exactly once on (C, contact 2) with no duplicates and no
        # wrong recipients; C-side arrival order must match send order.
        markers = [f"burst{i}-{stamp}" for i in range(5)]
        burst_hits: dict[str, list[tuple[str, object]]] = {m: [] for m in markers}
        c_first_seen: dict[str, int] = {}
        arrivals = 0
        for m in markers:
            reply, burst_events = call(B, "send", {"contact_id": 2, "text": m}, timeout=SEND_TIMEOUT)
            for e in burst_events:
                if isinstance(e, dict) and e.get("event") == "received" and e.get("text") in burst_hits:
                    burst_hits[e["text"]].append(("B", e.get("contact_id")))
            check(f"B burst {m} ACK", reply is not None and reply.get("result", {}).get("status") == "ACKNOWLEDGED", str(reply)[:120])
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            for board_label, s in nodes.items():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    evt = s.read_next(max(0.1, min(1.0, remaining)))
                except Exception as exc:
                    check(f"{board_label} burst drain", False, f"{type(exc).__name__}: {exc}")
                    deadline = time.monotonic()
                    break
                if evt is None:
                    continue
                if (
                    isinstance(evt, dict)
                    and evt.get("event") == "received"
                    and isinstance(evt.get("text"), str)
                    and evt.get("text") in burst_hits
                ):
                    burst_hits[evt["text"]].append((board_label, evt.get("contact_id")))
                    if board_label == "C" and evt.get("contact_id") == 2:
                        c_first_seen.setdefault(evt["text"], arrivals)
                        arrivals += 1
        burst_ok = True
        for m in markers:
            hits = burst_hits[m]
            intended = [(b, c) for b, c in hits if b == "C" and c == 2]
            wrong = [(b, c) for b, c in hits if not (b == "C" and c == 2)]
            if len(intended) != 1 or wrong:
                burst_ok = False
                check(f"C burst {m} once on contact 2", False, f"hits={hits}")
        order = sorted((m for m in markers if m in c_first_seen), key=lambda m: c_first_seen[m])
        check("C burst order+intact", burst_ok and order == markers, f"order={order} hits={ {m: burst_hits[m] for m in markers} }")
        # 6. Liveness: parser still healthy after hostile inputs above.
        expect_send(B, "B", 2, f"post-hostile-{stamp}", C, "C", 2, "post-hostile", nodes)
    finally:
        for s in sessions.values():
            s.close()
    print(f"ADVERSARIAL: {'PASS' if not failures else 'FAIL ' + str(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
