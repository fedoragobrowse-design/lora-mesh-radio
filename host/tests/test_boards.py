"""Boards discovery: by-id symlinks only, no device I/O."""
import os
import tempfile
from pathlib import Path
import unittest

from meshctl import boards as _boards


class ParseTests(unittest.TestCase):
    def test_secure_and_free_names(self):
        self.assertEqual(
            _boards.parse_serial_from_by_id(
                "usb-mesh_mesh-node_radio-secure_19e357db25fb1c77-if00"),
            "19e357db25fb1c77",
        )
        self.assertEqual(
            _boards.parse_serial_from_by_id(
                "usb-mesh_mesh-node_radio-free_950d3036b9fa578d-if00"),
            "950d3036b9fa578d",
        )

    def test_non_mesh_rejected(self):
        self.assertIsNone(_boards.parse_serial_from_by_id("usb-Logitech_USB_Receiver-if00"))
        self.assertIsNone(_boards.parse_serial_from_by_id("usb-mesh_mesh-node_radio-secure_ZZZ-if00"))


class DiscoverTests(unittest.TestCase):
    def test_symlinks_resolve_sorted(self):
        with tempfile.TemporaryDirectory() as tmp:
            by_id = Path(tmp)
            (by_id / "usb-mesh_mesh-node_radio-secure_bbbb-if00").symlink_to("../ttyACM9")
            (by_id / "usb-mesh_mesh-node_radio-secure_aaaa-if00").symlink_to("/dev/ttyACM3")
            (by_id / "unrelated").symlink_to("/dev/ttyS0")
            found = _boards.discover(by_id)
            self.assertEqual([b.serial for b in found], ["aaaa", "bbbb"])
            self.assertEqual(found[0].device, "/dev/ttyACM3")
            self.assertEqual(found[1].device, "/dev/ttyACM9")

    def test_find_by_serial_label_device(self):
        boards = [
            _boards.Board(serial="aaaa", device="/dev/ttyACM0", by_id="x", label="A"),
            _boards.Board(serial="bbbb", device="/dev/ttyACM1", by_id="y", label="B"),
        ]
        self.assertIs(_boards.find_board(boards, "aa"), boards[0])
        self.assertIs(_boards.find_board(boards, "B"), boards[1])
        self.assertIs(_boards.find_board(boards, "/dev/ttyACM1"), boards[1])
        self.assertIsNone(_boards.find_board(boards, "zzz"))

    def test_missing_dir_is_empty(self):
        self.assertEqual(_boards.discover(Path("/nonexistent-boards-dir")), [])


if __name__ == "__main__":
    unittest.main()
