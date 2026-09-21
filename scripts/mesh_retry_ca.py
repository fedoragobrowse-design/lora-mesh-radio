"""Same-window C->A retry (C slot 1 -> A)."""
import json
import sys
import time

sys.path.insert(0, "host")

from meshctl.serial_link import SerialSession  # noqa: E402


def main() -> int:
    with SerialSession("/dev/ttyACM0") as c, SerialSession("/dev/ttyACM2") as a:
        r, _ = c.exchange("send", {"contact_id": 1, "text": "retry-CA-1"}, 65.0)
        print("C->A send:", json.dumps(r)[:160], flush=True)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            e = a.read_next(deadline - time.monotonic())
            if e and e.get("event") == "received":
                print("A got:", json.dumps(e)[:200], flush=True)
                return 0
        print("A got nothing in window", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
