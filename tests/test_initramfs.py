import gzip
from pathlib import Path
import stat
import tempfile
import unittest

from initramfs import patch_initramfs, read_newc, write_newc


class InitramfsTests(unittest.TestCase):
    def entry(self, name, data=b"old", nlink=1):
        fields = [1, stat.S_IFREG | 0o755, 0, 0, nlink, 0, 0, 0, 0, 0, 0, 0, 0]
        return name, fields, data

    def test_replace_init_preserve_hardlinks_and_data(self):
        entries = [self.entry("init"), self.entry("usr/bin/busybox", b"", 2), self.entry("usr/bin/sh", b"BINARY", 2)]
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            (d / "input.gz").write_bytes(gzip.compress(write_newc(entries)))
            (d / "init.sh").write_bytes(b"#!/bin/sh\necho lab\n")
            patch_initramfs(d / "input.gz", d / "init.sh", d / "out.gz")
            result = read_newc(gzip.decompress((d / "out.gz").read_bytes()))
            self.assertEqual(result[0][2], b"#!/bin/sh\necho lab\n")
            self.assertEqual(result[1:], read_newc(write_newc(entries))[1:])
            with self.assertRaises(FileExistsError):
                patch_initramfs(d / "input.gz", d / "init.sh", d / "out.gz")

    def test_truncated_and_trailing_archive_rejected(self):
        raw = write_newc([self.entry("init")])
        for data in (raw[:80], raw[:115], raw + b"OTHER"):
            with self.assertRaises(ValueError):
                read_newc(data)

    def test_path_traversal_rejected(self):
        for name in ("../bad", "/init", "a/../../bad"):
            with self.assertRaises(ValueError):
                read_newc(write_newc([self.entry(name)]))

    def test_multiple_init_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            (d / "input.gz").write_bytes(gzip.compress(write_newc([self.entry("init"), self.entry("./init")])))
            (d / "init.sh").write_text("#!/bin/sh\n")
            with self.assertRaises(ValueError):
                patch_initramfs(d / "input.gz", d / "init.sh", d / "out.gz")

    def test_duplicate_normalized_names_rejected(self):
        for alias in ("././init", "init/", "./init"):
            with self.assertRaises(ValueError):
                read_newc(write_newc([self.entry("init"), self.entry(alias)]))

    def test_payload_preserves_vendor_entries_and_creates_parents(self):
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            original = [self.entry('init'), self.entry('vendor-data', b'original')]
            (d / 'in.gz').write_bytes(gzip.compress(write_newc(original)))
            (d / 'init.sh').write_bytes(b'#!/bin/sh\n')
            patch_initramfs(d / 'in.gz', d / 'init.sh', d / 'out.gz',
                            {'udm-virtual/boot.sh': (0o755, b'#!/bin/bash\n')})
            entries = {name: (fields, data) for name, fields, data in
                       read_newc(gzip.decompress((d / 'out.gz').read_bytes()))}
            self.assertEqual(entries['vendor-data'][1], b'original')
            self.assertTrue(stat.S_ISDIR(entries['udm-virtual'][0][1]))
            self.assertEqual(entries['udm-virtual/boot.sh'][0][1], stat.S_IFREG | 0o755)

    def test_payload_rejects_replacement_traversal_and_non_directory_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            (d / 'in.gz').write_bytes(gzip.compress(write_newc([self.entry('init')])))
            (d / 'init.sh').write_bytes(b'#!/bin/sh\n')
            for path in ('init', 'init/child', '../escape', '/absolute', 'a/../b', 'a\\b', '.'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    patch_initramfs(d / 'in.gz', d / 'init.sh', d / 'out.gz',
                                    {path: (0o644, b'data')})
                self.assertFalse((d / 'out.gz').exists())


if __name__ == "__main__":
    unittest.main()
