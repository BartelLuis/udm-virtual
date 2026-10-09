import gzip
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import fit


def fdt(tree):
    """Small independent DTB writer for adversarial and positive fixtures."""
    strings = bytearray()
    structure = bytearray()
    names = {}

    def word(value):
        structure.extend(struct.pack(">I", value))

    def align():
        structure.extend(b"\0" * (-len(structure) % 4))

    def node(name, properties, children):
        word(1)
        structure.extend(name.encode() + b"\0")
        align()
        for key, value in properties.items():
            if key not in names:
                names[key] = len(strings)
                strings.extend(key.encode() + b"\0")
            word(3)
            word(len(value))
            word(names[key])
            structure.extend(value)
            align()
        for child in children:
            node(*child)
        word(2)

    node(*tree)
    word(9)
    header = struct.pack(">10I", fit.FDT_MAGIC, 56 + len(structure) + len(strings), 56,
                         56 + len(structure), 40, 17, 16, 0, len(strings), len(structure))
    return header + bytes(16) + structure + strings


def fixture(*, bad_hash=False, config=True, missing_config_end=False, bad_gzip=False):
    kernel = bytearray(128)
    kernel[56:60] = b"ARM\x64"
    if config:
        kernel.extend(b"IKCFG_ST" + gzip.compress(b"CONFIG_VIRTIO_NET=y\nCONFIG_VIRTIO_PCI=y\n", mtime=0))
        kernel.extend(b"BROKEN!!" if missing_config_end else b"IKCFG_ED")
    kernel = bytes(kernel)
    compressed_kernel = gzip.compress(kernel, mtime=0)
    if bad_gzip:
        compressed_kernel = compressed_kernel[:-4]
    hardware = fdt(("", {"model": b"Fixture board\0", "compatible": b"vendor,chip\0vendor,board\0"}, []))
    ramdisk = gzip.compress(b"fixture initramfs", mtime=0)

    def image(name, kind, data, compression, algorithm):
        properties = {"type": kind.encode() + b"\0", "arch": b"arm64\0", "os": b"linux\0",
                      "compression": compression.encode() + b"\0", "data": data}
        digest = hashlib.new(algorithm, data).digest()
        if bad_hash and kind == "kernel":
            digest = bytes(len(digest))
        children = [("hash-1", {"algo": algorithm.encode() + b"\0", "value": digest}, []),
                    ("signature-1", {"algo": b"sha256,rsa2048\0", "value": b"unverified"}, [])]
        return name, properties, children

    tree = ("", {}, [
        ("images", {}, [image("linux", "kernel", compressed_kernel, "gzip", "sha256"),
                        image("board", "flat_dt", hardware, "none", "sha1"),
                        image("init", "ramdisk", ramdisk, "none", "sha256")]),
        ("configurations", {"default": b"correct\0"}, [
            ("wrong", {"kernel": b"nonexistent\0"}, []),
            ("correct", {"kernel": b"linux\0", "fdt": b"board\0", "ramdisk": b"init\0"}, []),
        ]),
    ])
    return fdt(tree), kernel, hardware, ramdisk


class FitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "kernel.fit"
        self.output = self.directory / "prepared"

    def prepare(self, **kwargs):
        blob, kernel, hardware, ramdisk = fixture(**kwargs)
        self.source.write_bytes(blob)
        return fit.prepare_fit(self.source, self.output), (kernel, hardware, ramdisk)

    def test_default_selection_hashes_config_and_outputs(self):
        report, expected = self.prepare()
        self.assertEqual(report["default_configuration"], "correct")
        for name, data in zip(("Image", "hardware.dtb", "original-initramfs.gz"), expected):
            self.assertEqual((self.output / name).read_bytes(), data)
        self.assertEqual(report["hardware_compatible"], ["vendor,chip", "vendor,board"])
        self.assertEqual(report["kernel_features"]["CONFIG_VIRTIO_NET"], "y")
        self.assertEqual(report["kernel_features"]["CONFIG_ARM_GIC"], "n")
        self.assertFalse(report["authenticity_verified"])
        self.assertEqual(len(report["signatures"]), 3)
        self.assertTrue(all(not item["verified"] for item in report["signatures"]))
        self.assertEqual(json.loads((self.output / "fit-report.json").read_text()), report)

    def test_hash_corruption_refuses_all_outputs(self):
        with self.assertRaisesRegex(fit.FitError, "hash mismatch"):
            self.prepare(bad_hash=True)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        existing = self.output / "Image"
        existing.write_bytes(b"keep")
        with self.assertRaisesRegex(fit.FitError, "already exists"):
            self.prepare()
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_config_is_optional(self):
        report, _ = self.prepare(config=False)
        self.assertFalse(report["kernel_config_present"])
        self.assertFalse((self.output / "kernel.config").exists())

    def test_invalid_embedded_config_is_rejected(self):
        with self.assertRaisesRegex(fit.FitError, "IKCFG_ED"):
            self.prepare(missing_config_end=True)
        self.assertFalse(self.output.exists())

    def test_gzip_bomb_and_truncation_are_bounded(self):
        with patch.object(fit, "MAX_KERNEL_SIZE", 100):
            with self.assertRaisesRegex(fit.FitError, "size limit"):
                self.prepare()
        with self.assertRaisesRegex(fit.FitError, "Truncated gzip"):
            self.prepare(bad_gzip=True)
        self.assertFalse(self.output.exists())

    def test_header_bounds_alignment_and_overlap(self):
        original, *_ = fixture()
        for index, value in ((1, len(original) + 1), (2, 41), (3, 56), (4, len(original) + 8), (8, 0xffffffff)):
            malformed = bytearray(original)
            struct.pack_into(">I", malformed, index * 4, value)
            with self.subTest(header_index=index), self.assertRaises(fit.FitError):
                fit._parse_fdt(bytes(malformed))

    def test_structure_requires_balanced_nodes_and_final_end(self):
        original = fdt(("", {}, []))
        for position, token in ((56, 2), (64, 1), (68, 4), (56, 0xff)):
            malformed = bytearray(original)
            struct.pack_into(">I", malformed, position, token)
            with self.subTest(position=position, token=token), self.assertRaises(fit.FitError):
                fit._parse_fdt(bytes(malformed))

    def test_property_data_and_name_offsets_must_be_bounded(self):
        original = fdt(("", {"sample": b"x"}, []))
        for offset in (68, 72):
            malformed = bytearray(original)
            struct.pack_into(">I", malformed, offset, 0xffffffff)
            with self.subTest(offset=offset), self.assertRaises(fit.FitError):
                fit._parse_fdt(bytes(malformed))

    def test_duplicate_nodes_and_properties_are_rejected(self):
        duplicate = fdt(("", {}, [("same", {}, []), ("same", {}, [])]))
        with self.assertRaisesRegex(fit.FitError, "duplicate"):
            fit._parse_fdt(duplicate)
        original = bytearray(fdt(("", {"one": b"x", "two": b"y"}, [])))
        # Each one-byte property occupies 16 bytes; make the second name identical.
        struct.pack_into(">I", original, 88, 0)
        with self.assertRaisesRegex(fit.FitError, "duplicate"):
            fit._parse_fdt(bytes(original))


if __name__ == "__main__":
    unittest.main()
