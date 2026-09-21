#!/usr/bin/env python3
"""Radio link test: TX one packet, confirm RX delivery + TX acknowledgement.

Preconditions: firmware flashed on each board, antennas fitted, nodes spaced
1-3 m apart. This script only drives the firmware's own USB ops (lab `ping`
or `send`); it performs no RF itself and never flashes, reboots, or
power-cycles hardware.

Listener discipline (why this script is strict):
- RX listener threads start and settle (0.5 s) *before* the TX byte goes
  out, so a fast delivery cannot race listener startup.
- The default 50 s window covers the firmware reliability contract: up to
  three DATA transmissions with a 12 s ACK wait each (3 x 12 s + airtime),
  so a slow retry still lands inside the window. Shortening the window
  below that budget risks a false FAIL on a legitimate late retry.
- RX matching requires *exactly one* `{"event":"received"}` per listener
  carrying the same sender/packet/text as the TX (ping: the pong count;
  send: the text). Zero receipts, duplicate receipts, or receipts for an
  unrelated packet/text are all FAIL. Unrelated event traffic is ignored
  but logged, never counted as delivery.
- A radio-free image (RADIO_UNAVAILABLE anywhere) FAILs clearly instead
  of passing implicitly: without RF there is no link to prove.

Default (no --text) uses the plaintext-lab `ping` op (count 1-3). With
--text it uses the `send` op; addressing must then be given explicitly via
--lab-address (plaintext-lab peer address) or --contact-id (paired contact).

Examples (run each direction; A->B,C first, then reverse senders):
    python3 scripts/radio_link.py --tx "$A" --rx "$B" "$C" --count 1
    python3 scripts/radio_link.py --tx "$B" --rx "$A" "$C" --count 1
    python3 scripts/radio_link.py --tx "$C" --rx "$A" "$B" --count 1
    python3 scripts/radio_link.py --tx "$A" --rx "$C" \\
        --text "A to C through B" --lab-address 3
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time

BAUD = 115200
TX_ID = 99
SETTLE_DELAY = 0.5
# Covers 3 x 12 s ACK waits + CAD/airtime margin; listener window must at
# least cover the sender's bounded retry deadline.
LISTEN_WINDOW = 50.0
TX_TIMEOUT = 60.0
RETRY_BUDGET = 40.0
HINT = (
    "hint: check USB data cable, BOOTSEL vs CDC, radio on (`radio on`), "
    "antennas fitted, 1-3 m spacing, and serial permissions"
)
NO_RADIO_HINT = "radio-free image: no RF hardware, so LINK cannot pass here"


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Send one lab ping/message from TX and watch RX ports.",
        epilog=(
            "examples:\n"
            '  %(prog)s --tx "$A" --rx "$B" "$C" --count 1\n'
            '  %(prog)s --tx "$B" --rx "$A" --count 1\n'
            '  %(prog)s --tx "$A" --rx "$C" --text "A to C through B"'
            " --lab-address 3"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--tx", required=True, metavar="PORT", help="sender port")
    p.add_argument(
        "--rx", nargs="+", required=True, metavar="PORT", help="listener port(s)"
    )
    p.add_argument(
        "--count",
        type=int,
        default=1,
        help="lab ping count, must be 1-3 (default %(default)s)",
    )
    p.add_argument("--text", default=None, help="message text (uses send op)")
    p.add_argument(
        "--lab-address", type=int, default=None, help="peer lab address for send"
    )
    p.add_argument(
        "--contact-id", type=int, default=None, help="paired contact id for send"
    )
    p.add_argument(
        "--window",
        type=float,
        default=LISTEN_WINDOW,
        help="listener window in seconds (default %(default)s; must cover the TX retry deadline)",
    )
    p.add_argument(
        "--tx-timeout",
        type=float,
        default=TX_TIMEOUT,
        help="max seconds to wait for TX reply (default %(default)s)",
    )
    return p.parse_args(argv)


def listen(port: str, window: float, stop: threading.Event, out: list) -> None:
    """Collect raw lines seen on port until window elapses or stop is set."""
    try:
        import serial
    except ImportError:
        out.append((port, "pyserial not installed"))
        return
    deadline = time.monotonic() + window
    try:
        with serial.Serial(port, BAUD, timeout=1.0) as ser:
            ser.reset_input_buffer()
            while time.monotonic() < deadline and not stop.is_set():
                try:
                    raw = ser.readline()
                except OSError as exc:
                    out.append((port, f"serial error: {exc}"))
                    return
                if raw:
                    out.append((port, raw.decode("utf-8", "replace").strip()))
    except OSError as exc:
        out.append((port, f"serial error: {exc}"))


def transmit(port: str, payload: dict, timeout: float):
    """Send request on port; return (reply_dict, error_str, extra_lines)."""
    try:
        import serial
    except ImportError:
        return None, "pyserial not installed (pip install pyserial)", []
    extra = []
    try:
        with serial.Serial(port, BAUD, timeout=1.0) as ser:
            ser.reset_input_buffer()
            ser.write((json.dumps(payload) + "\n").encode("utf-8"))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    raw = ser.readline()
                except OSError as exc:
                    return None, f"serial error: {exc}", extra
                if not raw:
                    continue
                text = raw.decode("utf-8", "replace").strip()
                try:
                    reply = json.loads(text)
                except ValueError:
                    extra.append(text)
                    continue
                if isinstance(reply, dict) and reply.get("id") == payload["id"]:
                    return reply, None, extra
                extra.append(text)
    except OSError as exc:
        return None, f"serial error: {exc}", extra
    return None, "no reply within timeout", extra


def received_events(lines: list) -> tuple[list, list]:
    """Split parsed lines into (received-events, unrelated-lines)."""
    hits, other = [], []
    for line in lines:
        try:
            obj = json.loads(line)
        except ValueError:
            other.append(line)
            continue
        if isinstance(obj, dict) and obj.get("event") == "received":
            hits.append(obj)
        else:
            other.append(line)
    return hits, other


def matching(events: list, marker: str | None) -> tuple[list, list]:
    """Partition received events into (matching, unrelated).

    A match must carry the TX text (send mode); ping mode accepts any
    received event but callers additionally require the pong count.
    """
    hits, other = [], []
    for evt in events:
        if marker is None:
            hits.append(evt)
        elif evt.get("text") == marker:
            hits.append(evt)
        else:
            other.append(evt)
    return hits, other


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.tx in args.rx:
        print("FAIL: --tx must not be one of --rx")
        return 1
    if args.count not in (1, 2, 3):
        print(f"FAIL: --count must be 1-3 (got {args.count})")
        return 1
    count = args.count

    if args.text is None:
        tx_payload: dict = {"id": TX_ID, "op": "ping", "count": count}
        marker = None
        mode = f"ping count={count}"
    else:
        if not args.text:
            print("FAIL: --text must not be empty")
            return 1
        if len(args.text.encode("utf-8")) > 160:
            print("FAIL: --text over 160 UTF-8 bytes (firmware rejects it)")
            return 1
        tx_payload = {"id": TX_ID, "op": "send", "text": args.text}
        if args.lab_address is not None:
            if args.lab_address not in (1, 2, 3):
                print("FAIL: --lab-address must be 1, 2 or 3")
                return 1
            tx_payload["lab_address"] = args.lab_address
        elif args.contact_id is not None:
            if args.contact_id not in (1, 2):
                print("FAIL: --contact-id must be 1 or 2")
                return 1
            tx_payload["contact_id"] = args.contact_id
        else:
            print(
                "FAIL: --text needs --lab-address (lab) or --contact-id (paired)"
            )
            return 1
        marker = args.text
        mode = "send"
    if args.window < RETRY_BUDGET:
        print(
            f"FAIL: --window {args.window:g}s is shorter than the sender retry "
            f"deadline ({RETRY_BUDGET:g}s); late retries would be missed"
        )
        return 1
    if args.tx_timeout < RETRY_BUDGET:
        print(
            f"FAIL: --tx-timeout {args.tx_timeout:g}s is shorter than the sender "
            f"retry deadline ({RETRY_BUDGET:g}s)"
        )
        return 1

    print(f"LINK: TX={args.tx} RX={args.rx} mode={mode}")
    stop = threading.Event()
    seen: list = []
    threads = [
        threading.Thread(
            target=listen, args=(port, args.window, stop, seen), daemon=True
        )
        for port in args.rx
    ]
    for t in threads:
        t.start()
    time.sleep(SETTLE_DELAY)  # listeners ready before the TX byte goes out
    reply, err, tx_extra = transmit(args.tx, tx_payload, args.tx_timeout)
    if reply is not None and not reply.get("ok") and reply.get("error") == "RADIO_UNAVAILABLE":
        print(f"FAIL TX {args.tx}: RADIO_UNAVAILABLE. {NO_RADIO_HINT}")
        stop.set()
        for t in threads:
            t.join(timeout=1.0)
        print("LINK: 0/1 PASS (no radio)")
        return 1
    for line in tx_extra:
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and obj.get("event") == "received":
            seen.append((args.tx, line))
    # Keep listeners for the full window so late retries are still caught.
    for t in threads:
        t.join(timeout=max(0.1, args.window))
    stop.set()
    tx_has_event = any(p == args.tx for p, _ in seen)

    results = []
    for port in args.rx:
        lines = [ln for p, ln in seen if p == port]
        if any(
            ln.startswith("serial error") or ln == "pyserial not installed"
            for ln in lines
        ):
            results.append(False)
            print(f"FAIL {args.tx} -> {port}: listener error: {lines} {HINT}")
            continue
        events, unrelated = received_events(lines)
        hits, others = matching(events, marker)
        for ln in unrelated[:3]:
            print(f"  note {port} unrelated traffic (not counted): {ln[:120]}")
        for evt in others[:3]:
            print(f"  note {port} unrelated event (not counted): {json.dumps(evt)[:120]}")
        if len(hits) == 0:
            results.append(False)
            if events:
                print(f"FAIL {args.tx} -> {port}: {len(events)} event(s) but none match the TX packet/text")
            else:
                print(f"FAIL {args.tx} -> {port}: nothing received")
        elif len(hits) == 1:
            results.append(True)
            print(f"PASS {args.tx} -> {port}: delivered once: {json.dumps(hits[0])[:160]}")
        else:
            results.append(False)
            print(
                f"FAIL {args.tx} -> {port}: duplicate delivery "
                f"({len(hits)} matching receipts)"
            )

    if err is not None:
        results.append(False)
        print(f"FAIL TX {args.tx}: {err} {HINT}")
    elif not reply.get("ok"):
        results.append(False)
        print(f"FAIL TX {args.tx}: firmware error: {reply.get('error')}")
    elif marker is None:
        got = (reply.get("result") or {}).get("count", reply.get("result"))
        if got == count:
            results.append(True)
            print(f"PASS TX {args.tx}: pong count={got}")
        else:
            results.append(False)
            print(f"FAIL TX {args.tx}: pong count={got!r} (expected {count})")
    else:
        status = (reply.get("result") or {}).get("status")
        if status == "ACKNOWLEDGED":
            results.append(True)
            print(f"PASS TX {args.tx}: ACKNOWLEDGED")
        else:
            results.append(False)
            print(f"FAIL TX {args.tx}: send status={status} (expected ACKNOWLEDGED)")
    for line in tx_extra[:5]:
        print(f"  TX extra: {line[:120]}")
    if tx_has_event:
        print(f"  note: TX port {args.tx} also emitted received event(s) (echo/own traffic)")

    n = sum(results)
    print(f"LINK: {n}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
