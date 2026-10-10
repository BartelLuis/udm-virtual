"""Filesystem-only checks of the guarded UXG guest installation."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from virtualization import uxg_guest


@unittest.skipUnless(os.name == 'posix', 'Requires Linux filesystem semantics')
class UxgGuestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'proc').mkdir()
        (self.root / 'proc/mounts').write_text('overlay / overlay rw 0 0\n/dev/vda /mnt/.rofs squashfs ro 0 0\n/dev/vdb /mnt/.rwfs ext4 rw 0 0\n')
        for name in ('data', 'persistent'):
            (self.root / name).mkdir()
        self.payload = self.root / 'payload'
        self.payload.mkdir()
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        (self.runtime / 'ready').write_text('virtual=1\n')
        self.original, self.adapted, self.hook = b'original daemon', b'adapted daemon', b'original iommu hook'
        self.daemon = self.root / 'usr/bin/ubios-udapi-server'
        self.daemon.parent.mkdir(parents=True)
        self.daemon.write_bytes(self.original)
        self.hook_path = self.root / 'usr/lib/ubnt/hooks/system/bootup-top/01-bypass_eth_iommu.sh'
        self.hook_path.parent.mkdir(parents=True)
        self.hook_path.write_bytes(self.hook)
        hardware_units = {}
        for name in ('usd.service', 'create-sflash.service', 'nginx.service', 'nginx-debug.service', 'lighttpd.service'):
            unit = self.root / 'lib/systemd/system' / name
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_bytes(name.encode())
            hardware_units[name] = hashlib.sha256(unit.read_bytes()).hexdigest()
        for name in ('virtual-board.json', 'virtual.default', 'virtual.fallback'):
            (self.payload / name).write_text('{"fixture":true}\n')
        (self.payload / 'ubios-udapi-server.virtual').write_bytes(self.adapted)
        (self.payload / 'uxg-adaptation.json').write_text(json.dumps({
            'source_sha256': hashlib.sha256(self.original).hexdigest(),
            'result_sha256': hashlib.sha256(self.adapted).hexdigest(),
        }))
        for name, value in (
            ('RUNTIME', self.runtime), ('SOURCE_SHA256', hashlib.sha256(self.original).hexdigest()),
            ('IOMMU_SHA256', hashlib.sha256(self.hook).hexdigest()),
            ('HARDWARE_UNITS', hardware_units),
        ):
            replacement = patch.object(uxg_guest, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.guard = patch.object(uxg_guest, 'require_guest')
        self.require_guest = self.guard.start()
        self.addCleanup(self.guard.stop)

    def configure(self):
        uxg_guest.configure(self.root, self.payload)

    def test_installs_exact_profile_and_preserves_configured_state_on_repeat(self):
        self.configure()
        self.require_guest.assert_called_once_with('UXGENT')
        self.assertEqual(self.daemon.read_bytes(), self.adapted)
        self.assertEqual(self.hook_path.read_bytes(), uxg_guest.IOMMU_REPLACEMENT)
        for name in ('usd.service', 'create-sflash.service', 'nginx.service', 'nginx-debug.service', 'lighttpd.service'):
            self.assertEqual(os.readlink(self.root / 'etc/systemd/system' / name), '/dev/null')
        state = self.root / 'data/udapi-config/ubios-udapi-server/ubios-udapi-server.state'
        self.assertEqual(state.read_bytes(), (self.payload / 'virtual.default').read_bytes())
        state.write_bytes(b'configured by external controller')
        self.configure()
        self.assertEqual(state.read_bytes(), b'configured by external controller')

    def test_unknown_installed_daemon_is_rejected_before_mutation(self):
        self.daemon.write_bytes(b'new firmware')
        with self.assertRaisesRegex(ValueError, 'installed UXG'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), b'new firmware')
        self.assertEqual(self.hook_path.read_bytes(), self.hook)

    def test_missing_virtual_storage_cannot_disable_original_storage_manager(self):
        (self.root / 'proc/mounts').write_text('/dev/vda / ext4 rw 0 0\n')
        with self.assertRaisesRegex(ValueError, 'virtual storage mount'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)
        self.assertFalse((self.root / 'etc/systemd/system/usd.service').is_symlink())

    def test_unknown_hook_rejected_before_daemon_changes(self):
        self.hook_path.write_bytes(b'admin custom hook')
        with self.assertRaisesRegex(ValueError, 'IOMMU boot hook'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)

    def test_corrupt_payload_rejected(self):
        (self.payload / 'ubios-udapi-server.virtual').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'payload'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)

    def test_unknown_storage_service_rejected_before_daemon_changes(self):
        (self.root / 'lib/systemd/system/usd.service').write_bytes(b'new storage manager')
        with self.assertRaisesRegex(ValueError, 'physical service'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)

    def test_custom_storage_unit_preserved(self):
        unit = self.root / 'etc/systemd/system/usd.service'
        unit.parent.mkdir(parents=True)
        unit.write_bytes(b'custom admin unit')
        with self.assertRaisesRegex(ValueError, 'custom unit'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)
        self.assertEqual(unit.read_bytes(), b'custom admin unit')

    def test_requires_real_ready_file(self):
        (self.runtime / 'ready').unlink()
        (self.runtime / 'ready').symlink_to(self.daemon)
        with self.assertRaisesRegex(ValueError, 'HAL'):
            self.configure()
        self.assertEqual(self.daemon.read_bytes(), self.original)

    def test_atomic_write_refuses_symlink(self):
        link = self.root / 'alias'
        link.symlink_to(self.daemon)
        with self.assertRaisesRegex(ValueError, 'non-regular'):
            uxg_guest.atomic_write(link, b'bad', 0o755)
        self.assertEqual(self.daemon.read_bytes(), self.original)


if __name__ == '__main__':
    unittest.main()
