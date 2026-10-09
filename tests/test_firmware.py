import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zlib

import firmware


def make_image(records=None, signed=True):
    """Independent small fixture writer for the documented UBNT layout."""
    if records is None:
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        elf[18:20] = struct.pack("<H", 183)
        records = [(b"FILE", "updater", bytes(elf)),
                   (b"PART", "rootfs", b"payload-with-FILE-and-ENDS-inside")]
    header = b"UBNT" + b"UDMEA4C.cn10k.v5.1.33".ljust(256, b"\0")
    image = header + struct.pack(">II", zlib.crc32(header), 0)
    for index, (magic, name, payload) in enumerate(records, 1):
        record = (magic + name.encode("ascii").ljust(16, b"\0") + bytes(12)
                  + struct.pack(">6I", 0, index, 0, 0, len(payload), len(payload) + 1024))
        image += record + payload + struct.pack(">II", zlib.crc32(record + payload), 0)
    return image + (b"ENDS" + bytes(range(256)) + bytes(4) if signed
                    else b"END." + struct.pack(">II", zlib.crc32(image), 0))


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "firmware.bin"

    def write(self, data):
        self.source.write_bytes(data)
        return self.source

    def test_real_structure_hashes_architecture_and_embedded_false_magic(self):
        data = make_image()
        report = firmware.inspect_firmware(self.write(data))
        self.assertEqual(report["model"], "UDMEA4C")
        self.assertEqual(report["architecture"], "aarch64")
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([p["name"] for p in report["partitions"]], ["updater", "rootfs"])
        self.assertEqual(report["partitions"][0]["data_offset"], 324)
        self.assertTrue(report["integrity"]["crc32_valid"])
        self.assertFalse(report["integrity"]["authenticity_verified"])
        self.assertFalse(report["trailer"]["signature_verified"])

    def test_unsigned_container_crc(self):
        report = firmware.inspect_firmware(self.write(make_image(signed=False)))
        self.assertTrue(report["trailer"]["crc32_valid"])
        image = bytearray(make_image(signed=False))
        image[-8] ^= 1
        with self.assertRaisesRegex(firmware.FirmwareError, "whole-container"):
            firmware.inspect_firmware(self.write(image))

    def test_bad_header_and_payload_crc(self):
        for offset, message in [(12, "firmware header"), (330, "payload updater")]:
            with self.subTest(offset=offset):
                image = bytearray(make_image())
                image[offset] ^= 1
                with self.assertRaisesRegex(firmware.FirmwareError, message):
                    firmware.inspect_firmware(self.write(image))

    def test_truncated_records_payload_and_signature(self):
        image = make_image()
        for end in [0, 4, 267, 270, 310, 330, len(image) - 264, len(image) - 1]:
            with self.subTest(end=end):
                with self.assertRaises(firmware.FirmwareError):
                    firmware.inspect_firmware(self.write(image[:end]))

    def test_invalid_lengths_are_rejected_before_reading_payload(self):
        image = bytearray(make_image())
        struct.pack_into(">II", image, 268 + 48, 0xFFFFFFFF, 0xFFFFFFFF)
        with self.assertRaisesRegex(firmware.FirmwareError, "Truncated payload"):
            firmware.inspect_firmware(self.write(image))

    def test_unknown_record_and_extra_trailer_data(self):
        image = bytearray(make_image())
        image[268:272] = b"BAD!"
        with self.assertRaisesRegex(firmware.FirmwareError, "Unknown record"):
            firmware.inspect_firmware(self.write(image))
        with self.assertRaisesRegex(firmware.FirmwareError, "trailing bytes"):
            firmware.inspect_firmware(self.write(make_image() + b"extra"))

    def test_duplicate_names_rejected_case_insensitively(self):
        image = make_image([(b"FILE", "rootfs", b"x"), (b"PART", "ROOTFS", b"y")])
        with self.assertRaisesRegex(firmware.FirmwareError, "Duplicate"):
            firmware.inspect_firmware(self.write(image))

    def test_extract_selected_payload_and_manifest(self):
        self.write(make_image())
        destination = self.root / "out"
        report = firmware.extract_firmware(self.source, destination, ["rootfs"])
        self.assertEqual((destination / "rootfs.bin").read_bytes(), b"payload-with-FILE-and-ENDS-inside")
        self.assertEqual(sorted(p.name for p in destination.iterdir()), ["manifest.json", "rootfs.bin"])
        self.assertEqual(json.loads((destination / "manifest.json").read_text()), report)

    def test_bad_crc_creates_no_output(self):
        image = bytearray(make_image())
        image[330] ^= 1
        self.write(image)
        destination = self.root / "out"
        with self.assertRaises(firmware.FirmwareError):
            firmware.extract_firmware(self.source, destination)
        self.assertFalse(destination.exists())

    def test_existing_destination_never_overwritten(self):
        self.write(make_image())
        destination = self.root / "out"
        destination.mkdir()
        sentinel = destination / "rootfs.bin"
        sentinel.write_bytes(b"keep")
        with self.assertRaisesRegex(firmware.FirmwareError, "already exists"):
            firmware.extract_firmware(self.source, destination)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_path_traversal_windows_devices_and_unsafe_names(self):
        for name in ["../escape", "..\\escape", "/absolute", "C:escape", "CON", "NUL.txt", "bad."]:
            with self.subTest(name=name):
                self.write(make_image([(b"FILE", name, b"data")]))
                destination = self.root / "out"
                with self.assertRaises(firmware.FirmwareError):
                    firmware.extract_firmware(self.source, destination)
                self.assertFalse(destination.exists())

    def test_unknown_selection_creates_no_output(self):
        self.write(make_image())
        with self.assertRaisesRegex(firmware.FirmwareError, "selection"):
            firmware.extract_firmware(self.source, self.root / "out", ["typo"])
        self.assertFalse((self.root / "out").exists())

    def test_streaming_with_small_chunks(self):
        data = make_image()
        with mock.patch.object(firmware, "CHUNK_SIZE", 7):
            report = firmware.inspect_firmware(self.write(data))
            extracted = firmware.extract_firmware(self.source, self.root / "out")
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(len(extracted["extracted"]), 2)
        self.assertEqual(report["architecture"], "aarch64")

    def test_extract_removes_only_its_own_files_after_io_failure(self):
        self.write(make_image())
        destination = self.root / "out"
        real_open = Path.open

        def failing_open(path, *args, **kwargs):
            if path.name == "rootfs.bin":
                raise OSError("simulated full disk")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", failing_open):
            with self.assertRaisesRegex(OSError, "full disk"):
                firmware.extract_firmware(self.source, destination)
        self.assertFalse(destination.exists())
        self.assertTrue(self.source.exists())

    def test_json_report_refuses_overwrite(self):
        self.write(make_image())
        report = self.root / "report.json"
        report.write_text("keep", encoding="utf-8")
        with mock.patch("sys.stderr"):
            code = firmware.main(["inspect", str(self.source), "--json", str(report)])
        self.assertEqual(code, 2)
        self.assertEqual(report.read_text(), "keep")

    def test_autodiscovery_requires_unique_bin(self):
        self.write(make_image())
        with mock.patch.object(Path, "cwd", return_value=self.root):
            self.assertEqual(firmware.discover_firmware(), self.source.resolve())
            (self.root / "other.bin").write_bytes(b"other")
            with self.assertRaisesRegex(firmware.FirmwareError, "found 2"):
                firmware.discover_firmware()


if __name__ == "__main__":
    unittest.main()
