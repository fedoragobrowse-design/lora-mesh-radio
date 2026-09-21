"""A->C same-window (reverse of the failing direction)."""
import json
import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402


def main() -> int:
    with SerialSession("/dev/ttyACM2") as a, SerialSession("/dev/ttyACM0") as c:
        r, _ = a.exchange("send", {"contact_id": 1, "text": "retry-AC-1"}, 65.0)
        print("A->C send:", json.dumps(r)[:160], flush=True)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            e = c.read_next(deadline - time.monotonic())
            if e and e.get("event") == "received":
                print("C got:", json.dumps(e)[:200], flush=True)
                return 0
        print("C got nothing in window", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
