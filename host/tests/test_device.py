"""ELF checker: valid image passes, corrupt images fail closed."""
import struct
import tempfile
import unittest
from pathlib import Path

from meshctl import device as _device


def _minimal_elf() -> bytes:
    """Hand-built ELF32-LE ARM image for check_elf (no toolchain)."""
    ehsize, phsize, shsize = 52, 32, 40
    phnum, shnum = 1, 3
    phoff, shoff = ehsize, 128
    vector_fileoff, vector_size = 256, 64
    strtab_off = 512
    entry = 0x10000101
    sp, reset = 0x20080000, 0x10000101
    head = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        2, 40, 1, entry, phoff, shoff, 0, ehsize,
        phsize, phnum, shsize, shnum, 2,
    )
    body = bytearray(max(shoff + shnum * shsize, strtab_off + 32, vector_fileoff + 0x200))
    body[: len(head)] = head
    # LOAD: vector table + entry at vaddr 0x10000000, RX in flash.
    struct.pack_into("<IIIIIIII", body, phoff, 1, vector_fileoff, 0x10000000,
                     0x10000000, 0x200, 0x200, 5, 4)
    # Section 1: .vector_table contents; section 2: name string table.
    # ShNod32 fields: name, type, flags, addr, offset, size, link, info, align, entsize.
    struct.pack_into("<IIIIIIIIII", body, shoff + shsize, 1, 3, 0,
                     0, vector_fileoff, vector_size, 0, 0, 16, 0)
    struct.pack_into("<IIIIIIIIII", body, shoff + 2 * shsize, 0, 3, 0,
                     0, strtab_off, 16, 0, 0, 1, 0)
    if len(body) < 0x200 + 64:
        body += b"\x00" * (0x200 + 64 - len(body))
    body[vector_fileoff : vector_fileoff + 8] = struct.pack("<II", sp, reset)
    strtab = b"\x00.vector_table\x00"
    body[strtab_off : strtab_off + len(strtab)] = strtab
    return bytes(body)


class ElfTests(unittest.TestCase):
    def test_valid_minimal_image(self):
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
            tmp.write(_minimal_elf())
            path = tmp.name
        try:
            result = _device.check_elf(path)
        finally:
            Path(path).unlink()
        self.assertEqual(result["entry"], 0x10000101)
        self.assertEqual(result["load_segments"], 1)

    def test_not_elf_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
            tmp.write(b"definitely not an elf")
            path = tmp.name
        try:
            with self.assertRaises(ValueError):
                _device.check_elf(path)
        finally:
            Path(path).unlink()

    def test_flash_overlap_rejected(self):
        data = bytearray(_minimal_elf())
        # Move LOAD paddr into retained top-64KiB.
        struct.pack_into("<I", data, 52 + 8, 0x103F8000)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
            tmp.write(bytes(data))
            path = tmp.name
        try:
            with self.assertRaises(ValueError):
                _device.check_elf(path)
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
