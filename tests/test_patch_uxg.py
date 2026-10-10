import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch as override

from virtualization import patch_uxg


class UxgPatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "original"
        self.destination = self.directory / "adapted"
        self.metadata = self.directory / "adapted.json"
        data = bytearray(0x200)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 183)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<II6Q", data, 64, 1, 5, 0x100, patch_uxg.ADDRESS - 4,
                         0, 0x100, 0x100, 0x1000)
        data[0x104:0x10c] = patch_uxg.EXPECTED
        self.original = bytes(data)

    def invoke(self, original=None, result_hash=None):
        original = self.original if original is None else bytes(original)
        self.source.write_bytes(original)
        result = original[:0x104] + patch_uxg.REPLACEMENT + original[0x10c:]
        with override.object(patch_uxg, "SOURCE_SHA256", hashlib.sha256(original).hexdigest()), \
                override.object(patch_uxg, "RESULT_SHA256", result_hash or hashlib.sha256(result).hexdigest()):
            return patch_uxg.patch(self.source, self.destination)

    def test_only_eight_audited_bytes_change_and_both_hashes_recorded(self):
        report = self.invoke()
        result = self.destination.read_bytes()
        self.assertEqual(result[:0x104], self.original[:0x104])
        self.assertEqual(result[0x104:0x10c], patch_uxg.REPLACEMENT)
        self.assertEqual(result[0x10c:], self.original[0x10c:])
        self.assertEqual(report["changes"][0]["file_offset"], "0x104")
        self.assertEqual(report["source_sha256"], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(report["result_sha256"], hashlib.sha256(result).hexdigest())
        self.assertEqual(json.loads(self.metadata.read_text()), report)

    def test_unknown_source_is_rejected_without_output(self):
        self.source.write_bytes(self.original)
        with self.assertRaisesRegex(ValueError, "unknown UXG"):
            patch_uxg.patch(self.source, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.metadata.exists())

    def test_result_hash_guard_runs_before_any_write(self):
        with self.assertRaisesRegex(ValueError, "result hash"):
            self.invoke(result_hash="0" * 64)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.metadata.exists())

    def test_instruction_guard_is_independent_of_source_guard(self):
        damaged = bytearray(self.original)
        damaged[0x104] ^= 1
        with self.assertRaisesRegex(ValueError, "Unexpected instructions"):
            self.invoke(damaged)
        self.assertFalse(self.destination.exists())

    def test_malformed_headers_and_nonexecutable_segment_rejected(self):
        mutations = [(18, "<H", 62), (32, "<Q", 0xffff), (54, "<H", 8),
                     (68, "<I", 4), (64 + 32, "<Q", 0xffff)]
        for offset, encoding, value in mutations:
            data = bytearray(self.original)
            struct.pack_into(encoding, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.invoke(data)
            self.assertFalse(self.destination.exists())

    def test_existing_binary_or_report_is_preserved(self):
        for path in (self.destination, self.metadata):
            path.write_bytes(b"preserve")
            with self.assertRaisesRegex(ValueError, "already exists"):
                self.invoke()
            self.assertEqual(path.read_bytes(), b"preserve")
            path.unlink()


if __name__ == "__main__":
    unittest.main()
