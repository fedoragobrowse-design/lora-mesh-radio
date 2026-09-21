"""Real PTY regressions for ownership and lossless serial framing (not RF)."""
import json
import os
import pty
import select
import tempfile
import threading
import unittest

from meshctl.serial_link import PortBusyError, SerialSession


class SerialSessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        previous = os.environ.get("MESH_LOCAL_DIR")
        os.environ["MESH_LOCAL_DIR"] = self.directory.name
        def restore():
            if previous is None:
                os.environ.pop("MESH_LOCAL_DIR", None)
            else:
                os.environ["MESH_LOCAL_DIR"] = previous
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(restore)
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.port = os.ttyname(self.slave)
        self.session = SerialSession(self.port).open()
        self.addCleanup(self.session.close)

    def test_close_releases_port_and_is_idempotent(self):
        self.session.close()
        self.session.close()
        with SerialSession(self.port) as replacement:
            os.write(self.master, b'{"event":"ready"}\n')
            self.assertEqual(replacement.read_next(1), {"event": "ready"})

    def test_second_owner_in_same_process_is_rejected(self):
        other = SerialSession(self.port)
        self.addCleanup(other.close)
        with self.assertRaises(PortBusyError):
            other.open()
        os.write(self.master, b'{"event":"still-owned"}\n')
        self.assertEqual(self.session.read_next(1), {"event": "still-owned"})

    def test_reply_preserves_following_event(self):
        errors = []
        def respond():
            try:
                if not select.select([self.master], [], [], 2)[0]:
                    raise AssertionError("No request reached PTY")
                request = json.loads(os.read(self.master, 4096))
                reply = {"id": request["id"], "ok": True, "result": {"value": 9}}
                os.write(self.master, (json.dumps(reply) + '\n{"event":"after"}\n').encode())
            except Exception as error:
                errors.append(error)
        responder = threading.Thread(target=respond)
        responder.start()
        try:
            reply, events = self.session.exchange("status", timeout=2)
            self.assertEqual(reply["result"], {"value": 9})
            self.assertEqual(events, [])
            self.assertEqual(self.session.read_next(1), {"event": "after"})
        finally:
            responder.join(3)
        self.assertEqual(errors, [])

    def test_partial_line_survives_read_timeout(self):
        os.write(self.master, b'{"event":"par')
        self.assertIsNone(self.session.read_next(0.02))
        os.write(self.master, b'tial"}\n{"event":"next"}\n')
        self.assertEqual(self.session.read_next(1), {"event": "partial"})
        self.assertEqual(self.session.read_next(1), {"event": "next"})

    def test_oversized_record_cannot_inject_valid_suffix(self):
        os.write(self.master, b'x' * 5000)
        self.assertIsNone(self.session.read_next(0.02))
        os.write(self.master, b'{"event":"forged"}\n{"event":"real"}\n')
        self.assertEqual(self.session.read_next(1), {"_noise": "LINE_TOO_LONG"})
        self.assertEqual(self.session.read_next(1), {"event": "real"})


if __name__ == "__main__":
    unittest.main()
