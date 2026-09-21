"""C->A on the correct slot (C slot 2, fp a112647d); drain inline for proof."""
import json
import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402


def main() -> int:
    with SerialSession("/dev/ttyACM0") as c, SerialSession("/dev/ttyACM2") as a:
        before, _ = c.exchange("status", None, 15.0)
        rx0 = before["result"]["counters"]["rx_ok"]
        r, _ = c.exchange("send", {"contact_id": 2, "text": "fix-CA-1"}, 65.0)
        print("C->A send:", json.dumps(r)[:160], flush=True)
        if not (r.get("ok") and r.get("result", {}).get("status") == "ACKNOWLEDGED"):
            print("no ACK; not a direction bug, peer/route down", flush=True)
            return 1
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            for label, s in (("A", a), ("C", c)):
                e = s.read_next(max(0.1, deadline - time.monotonic()))
                if e and e.get("event") == "received" and e.get("text") == "fix-CA-1":
                    print(f"{label} got:", json.dumps(e)[:200], flush=True)
                    return 0
        after, _ = c.exchange("status", None, 15.0)
        print("C rx_ok delta:", after["result"]["counters"]["rx_ok"] - rx0, flush=True)
        print("ACK without received: check A rx_ok / relay path", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
