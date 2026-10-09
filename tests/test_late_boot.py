import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from virtualization import late_boot


# Exact original 5.1.33 hook: this fixture is also checked against its source
# SHA256 so an accidental change cannot silently broaden the allowed patch.
ORIGINAL = b'''#!/bin/bash
# [NETWORK-7788] PHY diag WA for 1G RJ45 ports (eth0/eth1)
# After reboot, PHY may have LED but no link due to MDIO errors.
# Loading phy_diag and reading a PHY register re-initializes the MDIO bus.

modprobe phy_diag

PHY_DIAG=/sys/kernel/debug/phy_diagnostics

# UDM-Beast 1G PHYs:
#   eth0 -> RPM0/LMAC0
#   eth1 -> RPM1/LMAC0
for rpm in 0 1; do
    echo "$rpm 0" > "$PHY_DIAG/phy"
    echo "c22 0 0" > "$PHY_DIAG/read_reg"
    echo "c22 0 1" > "$PHY_DIAG/read_reg"
done
'''


class LateBootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='udm-phy-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.hook = self.root / '01-phy-diag-wa'
        self.hook.write_bytes(ORIGINAL)
        self.other = self.root / '98-ustd-ready'
        self.other.write_bytes(b'original unaffected hook\n')
        self.runtime = self.root / 'run'
        self.runtime.mkdir()
        (self.runtime / 'ready').touch()
        self.module = self.root / 'not-loaded'
        for name, value in (('RUNTIME', self.runtime), ('MODULE', self.module)):
            patcher = mock.patch.object(late_boot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(late_boot, 'require_guest',
                                    return_value=['udm.mode=systemd', 'module_blacklist=phy_diag'])
        self.guard = patcher.start()
        self.addCleanup(patcher.stop)

    def test_original_hook_replaced_but_other_hooks_preserved_and_repeat_is_idempotent(self):
        self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(), late_boot.ORIGINAL_SHA256)
        self.assertTrue(late_boot.adapt_hook(self.hook))
        self.assertEqual(self.hook.read_bytes(), late_boot.REPLACEMENT)
        self.assertEqual(self.other.read_bytes(), b'original unaffected hook\n')
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.hook.stat().st_mode), 0o755)
        modified = self.hook.stat().st_mtime_ns
        self.assertFalse(late_boot.adapt_hook(self.hook))
        self.assertEqual(self.hook.stat().st_mtime_ns, modified)

    @unittest.skipUnless(os.name == 'posix', 'Requires a POSIX shell')
    def test_replacement_hook_executes_without_modprobe_or_device_access(self):
        late_boot.adapt_hook(self.hook)
        # Empty PATH ensures no external command, including modprobe, is used.
        result = subprocess.run(['/bin/sh', str(self.hook)], env={'PATH': ''},
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'UDM_VIRTUAL_PHY_DIAG_SKIPPED\n')
        self.assertEqual(result.stderr, '')

    def test_missing_or_ambiguous_kernel_module_block_refuses_to_patch(self):
        for options in ([], ['module_blacklist=other'],
                        ['module_blacklist=phy_diag', 'module_blacklist=other'],
                        ['module_blacklist=not_phy_diag']):
            with self.subTest(options=options):
                self.guard.return_value = options
                with self.assertRaisesRegex(ValueError, 'module_blacklist=phy_diag'):
                    late_boot.adapt_hook(self.hook)
                self.assertEqual(self.hook.read_bytes(), ORIGINAL)

    def test_changed_firmware_hook_is_rejected(self):
        self.hook.write_bytes(ORIGINAL + b'unknown new operation\n')
        with self.assertRaisesRegex(ValueError, 'Unsupported physical PHY hook SHA256'):
            late_boot.adapt_hook(self.hook)
        self.assertTrue(self.hook.read_bytes().endswith(b'unknown new operation\n'))

    def test_wrong_guest_missing_hal_or_loaded_module_refuses_changes(self):
        self.guard.side_effect = ValueError('wrong guest')
        with self.assertRaisesRegex(ValueError, 'wrong guest'):
            late_boot.adapt_hook(self.hook)
        self.guard.side_effect = None
        ready = self.runtime / 'ready'
        ready.unlink()
        with self.assertRaisesRegex(ValueError, 'HAL must be ready'):
            late_boot.adapt_hook(self.hook)
        ready.touch()
        self.module.mkdir()
        with self.assertRaisesRegex(ValueError, 'already loaded'):
            late_boot.adapt_hook(self.hook)
        self.assertEqual(self.hook.read_bytes(), ORIGINAL)

    def test_commit_failure_preserves_original_and_removes_temporary(self):
        with mock.patch.object(late_boot.os, 'replace', side_effect=OSError('commit failed')):
            with self.assertRaisesRegex(OSError, 'commit failed'):
                late_boot.adapt_hook(self.hook)
        self.assertEqual(self.hook.read_bytes(), ORIGINAL)
        self.assertEqual(list(self.root.glob('.udm-phy-hook-*')), [])

    @unittest.skipUnless(os.name == 'posix', 'Requires symbolic links')
    def test_symlink_hook_is_never_followed(self):
        self.hook.unlink()
        self.hook.symlink_to(self.other)
        with self.assertRaisesRegex(ValueError, 'ordinary file'):
            late_boot.adapt_hook(self.hook)
        self.assertEqual(self.other.read_bytes(), b'original unaffected hook\n')


if __name__ == '__main__':
    unittest.main()
