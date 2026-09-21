"""Real PTY regressions: deletion acknowledgement, deadlines and disconnects."""
import json
import os
import pty
import select
import tempfile
import time
import unittest

from meshctl import contacts
from meshctl.bus import EventBus
from meshctl.serial_link import SerialSession


class EventBusTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        previous = os.environ.get("MESH_LOCAL_DIR")
        os.environ["MESH_LOCAL_DIR"] = directory.name
        self.addCleanup(directory.cleanup)
        def restore():
            if previous is None:
                os.environ.pop("MESH_LOCAL_DIR", None)
            else:
                os.environ["MESH_LOCAL_DIR"] = previous
        self.addCleanup(restore)
        self.master, slave = pty.openpty()
        self.port = os.ttyname(slave)
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, slave)
        self.bus = EventBus()
        self.addCleanup(self.bus.detach_all)
        self.bus.attach("board", self.port)
        self.bus.poll()
        contacts.set_contact("board", "peer", 2)

    def request(self, op, timeout=2):
        self.bus.request("board", op, {"contact_id": 2}, timeout)
        data = b""
        deadline = time.monotonic() + 2
        while b"\n" not in data:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "request did not reach PTY")
            self.assertTrue(select.select([self.master], [], [], remaining)[0])
            data += os.read(self.master, 4096)
        return json.loads(data)

    def emit(self, obj):
        os.write(self.master, (json.dumps(obj) + "\n").encode())

    def wait_event(self, kind):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            for event in self.bus.poll():
                if event.kind == kind:
                    return event
            time.sleep(.005)
        self.fail(f"missing {kind} event")

    def test_delete_mapping_requires_matching_success_reply(self):
        req = self.request("contact_delete")
        self.assertEqual(contacts.resolve_contact("board", "peer"), 2)
        self.emit({"id": req["id"] + 99, "ok": True, "result": {"deleted": True}})
        self.wait_event("notice")
        self.assertEqual(contacts.resolve_contact("board", "peer"), 2)
        self.emit({"id": req["id"], "ok": False, "error": "STORAGE_FAULT"})
        self.wait_event("reply")
        self.assertEqual(contacts.resolve_contact("board", "peer"), 2)
        req = self.request("contact_delete")
        self.emit({"id": req["id"], "ok": True, "result": {"deleted": True}})
        self.wait_event("reply")
        self.assertIsNone(contacts.resolve_contact("board", "peer"))

    def test_continuous_events_do_not_prevent_timeout_or_authorize_late_delete(self):
        req = self.request("contact_delete", timeout=.15)
        errors = []
        deadline = time.monotonic() + .8
        while time.monotonic() < deadline and not errors:
            self.emit({"event": "received", "contact_id": 1, "text": "traffic"})
            time.sleep(.005)
            errors.extend(e for e in self.bus.poll() if e.kind == "error")
        self.assertTrue(errors, "receive traffic prevented deadline expiry")
        self.emit({"id": req["id"], "ok": True, "result": {"deleted": True}})
        self.wait_event("notice")
        self.assertEqual(contacts.resolve_contact("board", "peer"), 2)

    def test_detach_preserves_mapping_and_releases_port_for_reattach(self):
        self.request("contact_delete")
        self.bus.detach("board")
        self.assertEqual(contacts.resolve_contact("board", "peer"), 2)
        with SerialSession(self.port) as session:
            self.emit({"event": "replacement-owner"})
            self.assertEqual(session.read_next(1), {"event": "replacement-owner"})
        self.bus.attach("board", self.port)
        self.bus.poll()
        req = self.request("status")
        self.emit({"id": req["id"], "ok": True, "result": {"label": "reattached"}})
        reply = json.loads(self.wait_event("reply").text)
        self.assertEqual(reply["result"]["label"], "reattached")


if __name__ == "__main__":
    unittest.main()
