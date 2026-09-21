"""All-directions live messaging check: 6 sends across A/B/C, then collect."""
import json
import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402

DEVS = {"A": "/dev/ttyACM2", "B": "/dev/ttyACM1", "C": "/dev/ttyACM0"}
ROUNDS = [
    ("A", 1, "B", "all-A1"),
    ("B", 1, "A", "all-B1"),
    ("B", 2, "C", "all-B2"),
    ("C", 2, "B", "all-C2"),
    ("C", 1, "A", "all-C1"),
    ("A", 1, "C", "all-A2"),
]


def main() -> int:
    now = int(time.time())
    for label, dev in DEVS.items():
        with SerialSession(dev) as s:
            s.exchange("time_set", {"unix_seconds": now}, 15.0)
            s.exchange("radio_set", {"enabled": True}, 15.0)
    print("all synced + radio on", flush=True)
    sends = {}
    sessions = {label: SerialSession(dev).open() for label, dev in DEVS.items()}
    try:
        for tx, slot, rx, text in ROUNDS:
            r, _ = sessions[tx].exchange("send", {"contact_id": slot, "text": text}, 65.0)
            ok = r.get("ok") and r.get("result", {}).get("status") == "ACKNOWLEDGED"
            print(f"{tx}->{rx} slot{slot}: {'ACK' if ok else json.dumps(r)[:120]}", flush=True)
            sends[text] = rx
        got = {}
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and len(got) < len(ROUNDS):
            for label, s in sessions.items():
                e = s.read_next(1.0)
                if e and e.get("event") == "received" and e.get("text") in sends:
                    if e["text"] not in got:
                        got[e["text"]] = label
                        print(f"  {sends[e['text']]} got {e['text']!r} (id{e.get('contact_id')})", flush=True)
    finally:
        for s in sessions.values():
            s.close()
    print(f"delivered {len(got)}/{len(ROUNDS)}", flush=True)
    return 0 if len(got) == len(ROUNDS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
