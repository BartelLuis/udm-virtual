import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch as override

from virtualization import patch_cpss


class CpssPatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / 'original'
        self.destination = self.directory / 'adapted'
        data = bytearray(0x200)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 183)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<II6Q', data, 64, 1, 5, 0x100, 0x123400, 0, 0x100, 0x100, 0x1000)
        data[0x104:0x108] = bytes.fromhex('fd7bbaa9')
        self.original = bytes(data)
        self.source.write_bytes(self.original)
        self.test_patches = [(0x123404, bytes.fromhex('fd7bbaa9'), bytes.fromhex('c0035fd6'), 'Fixture')]

    def invoke(self, patches=None):
        with override.object(patch_cpss, 'SOURCE_SHA256', hashlib.sha256(self.original).hexdigest()):
            with override.object(patch_cpss, 'PATCHES', self.test_patches if patches is None else patches):
                return patch_cpss.patch(self.source, self.destination)

    def test_virtual_address_mapping_preserves_all_other_bytes(self):
        report = self.invoke()
        result = self.destination.read_bytes()
        self.assertEqual(result[:0x104], self.original[:0x104])
        self.assertEqual(result[0x104:0x108], bytes.fromhex('c0035fd6'))
        self.assertEqual(result[0x108:], self.original[0x108:])
        self.assertEqual(report['changes'][0]['file_offset'], '0x104')
        self.assertEqual(report['result_sha256'], hashlib.sha256(result).hexdigest())
        self.assertEqual(json.loads(self.destination.with_name('adapted.json').read_text()), report)

    def test_unknown_version_produces_no_output(self):
        with self.assertRaisesRegex(ValueError, 'unknown UDAPI'):
            patch_cpss.patch(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_matching_version_still_requires_expected_instructions(self):
        bad = [(0x123404, b'wrong', b'other', 'Fixture')]
        with self.assertRaisesRegex(ValueError, 'Unexpected instructions'):
            self.invoke(bad)
        self.assertFalse(self.destination.exists())

    def test_nonexecutable_or_outside_segment_is_rejected(self):
        bad = [(0x456700, b'abcd', b'efgh', 'Fixture')]
        with self.assertRaisesRegex(ValueError, 'Invalid patch location'):
            self.invoke(bad)
        self.assertFalse(self.destination.exists())

    def test_existing_binary_or_report_refuses_before_writing(self):
        for name in ('adapted', 'adapted.json'):
            path = self.directory / name
            path.write_bytes(b'preserve')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Destination already exists'):
                self.invoke()
            self.assertEqual(path.read_bytes(), b'preserve')
            if name.endswith('.json'):
                self.assertFalse(self.destination.exists())
            path.unlink()

    def test_branch_encoding_handles_forward_and_backward_targets(self):
        self.assertEqual(patch_cpss.branch(0x620480, 0x620578), bytes.fromhex('3e000014'))
        encoded = struct.unpack('<I', patch_cpss.branch(0x1000, 0xffc))[0]
        self.assertEqual(encoded, 0x17ffffff)
        with self.assertRaises(AssertionError):
            patch_cpss.branch(0x1000, 0x1001)


if __name__ == '__main__':
    unittest.main()
