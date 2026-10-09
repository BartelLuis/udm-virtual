"""Guest migration boundaries, with real temporary files and synthetic hashes.

The streaming archive installer is exercised separately by test_patch_controller.
Here its narrow contract is substituted to inject failures around the atomic
file replacement. No mounts, firmware files, or running guests are modified.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from virtualization import controller_guest as guest


def digest(value):
    return hashlib.sha256(value).hexdigest()


POSIX = unittest.skipUnless(os.name == 'posix', 'POSIX mount, ownership and replacement semantics')


class GuestControllerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'overlay/lib/ace.jar'
        self.source.parent.mkdir(parents=True)
        self.lower = self.root / 'firmware with space'
        self.original = self.lower / 'usr/lib/unifi/lib/ace.jar'
        self.original.parent.mkdir(parents=True)
        self.payload = self.root / 'payload'
        self.payload.mkdir()
        self.mountinfo = self.root / 'mountinfo'
        self.original_bytes = b'known original firmware controller'
        self.previous_bytes = b'known previous native-port-only controller'
        self.result_bytes = b'known native-port and GCM controller'
        self.nested_bytes = b'checked adapted nested archive'
        self.original.write_bytes(self.original_bytes)
        self.source.write_bytes(self.previous_bytes)
        (self.payload / 'internal-dependencies.virtual.jar').write_bytes(self.nested_bytes)
        self.report = {
            'source_sha256': digest(self.original_bytes),
            'result_sha256': digest(self.result_bytes),
            'nested_result_sha256': digest(self.nested_bytes),
        }
        self.write_report()
        for name, value in (('SOURCE_SHA256', digest(self.original_bytes)),
                            ('PREVIOUS_SHA256', digest(self.previous_bytes))):
            guard = patch.object(guest, name, value)
            guard.start()
            self.addCleanup(guard.stop)
        if os.name == 'posix':
            self.write_mountinfo()

    def write_report(self):
        (self.payload / 'controller.json').write_text(json.dumps(self.report))

    def mount_line(self, *, point=None, mount_options='ro,relatime',
                   super_options='ro', filesystem='squashfs', device='/dev/vda',
                   root='/', devnum=None):
        point = self.lower if point is None else point
        escaped = str(point).replace('\\', '\\134').replace(' ', '\\040')
        number = self.original.stat().st_dev
        devnum = devnum or f'{os.major(number)}:{os.minor(number)}'
        return f'27 1 {devnum} {root} {escaped} {mount_options} - {filesystem} {device} {super_options}\n'

    def write_mountinfo(self, **options):
        self.mountinfo.write_text(self.mount_line(**options))

    def run_install(self):
        return guest.install_controller(self.payload, self.source, self.lower, self.mountinfo)

    def successful_installer(self, original, result, nested, nested_hash, result_hash):
        self.assertIn(original, (self.source, self.original))
        self.assertEqual(original.read_bytes(), self.original_bytes)
        self.assertFalse(result.exists())
        self.assertEqual(result.parent.parent, self.source.parent)
        self.assertEqual(nested.read_bytes(), self.nested_bytes)
        self.assertEqual(nested_hash, digest(self.nested_bytes))
        self.assertEqual(result_hash, digest(self.result_bytes))
        result.write_bytes(self.result_bytes)

    def assert_previous_untouched(self, before):
        self.assertEqual(self.source.read_bytes(), self.previous_bytes)
        after = self.source.stat()
        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                         (before.st_ino, before.st_mode, before.st_mtime_ns))
        self.assertFalse(list(self.source.parent.glob('.udm-virtual-*')))

    def test_unknown_overlay_is_refused_before_reading_lower_or_installing(self):
        self.source.write_bytes(b'unrecognized controller')
        before = self.source.stat()
        with patch.object(guest, 'readonly_original') as lower, patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported installed controller'):
                self.run_install()
            lower.assert_not_called()
            install.assert_not_called()
        self.assertEqual(self.source.read_bytes(), b'unrecognized controller')
        self.assertEqual(self.source.stat().st_ino, before.st_ino)

    def test_current_result_is_idempotent_without_lower_or_installer(self):
        self.source.write_bytes(self.result_bytes)
        before = self.source.stat()
        with patch.object(guest, 'readonly_original') as lower, patch.object(guest, 'install') as install:
            self.assertEqual(self.run_install(), 'already-installed')
            lower.assert_not_called()
            install.assert_not_called()
        self.assertEqual(self.source.stat().st_ino, before.st_ino)
        self.assertEqual(self.source.stat().st_mtime_ns, before.st_mtime_ns)

    def test_invalid_report_is_refused_without_destructive_overwrite(self):
        for key, value in (('source_sha256', '0' * 64), ('result_sha256', None),
                           ('result_sha256', 'A' * 64), ('result_sha256', 'b' * 63),
                           ('nested_result_sha256', []), ('nested_result_sha256', 'wrong')):
            with self.subTest(key=key, value=value):
                before = self.source.stat()
                report = dict(self.report, **{key: value})
                (self.payload / 'controller.json').write_text(json.dumps(report))
                with patch.object(guest, 'readonly_original') as lower, patch.object(guest, 'install') as install:
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported controller adaptation report'):
                        self.run_install()
                    lower.assert_not_called()
                    install.assert_not_called()
                self.assert_previous_untouched(before)

    @POSIX
    def test_fresh_original_installs_without_reading_lower(self):
        self.source.write_bytes(self.original_bytes)
        with patch.object(guest, 'readonly_original') as lower, \
                patch.object(guest, 'install', side_effect=self.successful_installer) as install:
            self.assertEqual(self.run_install(), 'installed')
            lower.assert_not_called()
            self.assertEqual(install.call_args.args[0], self.source)
        self.assertEqual(self.source.read_bytes(), self.result_bytes)
        self.assertFalse(list(self.source.parent.glob('.udm-virtual-*')))

    @POSIX
    def test_previous_migrates_from_readonly_original_and_atomically_preserves_attrs(self):
        if os.geteuid() == 0:
            os.chown(self.source, 1234, 1235)
        os.chmod(self.source, 0o640)
        os.utime(self.source, ns=(1_600_000_000_123456789, 1_600_000_001_987654321))
        before = self.source.stat()
        original_before = self.original.read_bytes()
        with self.source.open('rb') as old_descriptor, \
                patch.object(guest, 'install', side_effect=self.successful_installer) as install:
            self.assertEqual(self.run_install(), 'migrated-known-controller')
            self.assertEqual(install.call_args.args[0], self.original)
            after = self.source.stat()
            self.assertNotEqual(before.st_ino, after.st_ino)
            self.assertEqual(old_descriptor.read(), self.previous_bytes)
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode),
                          after.st_atime_ns, after.st_mtime_ns),
                         (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode),
                          before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.source.read_bytes(), self.result_bytes)
        self.assertEqual(self.original.read_bytes(), original_before)
        self.assertFalse(list(self.source.parent.glob('.udm-virtual-*')))

    @POSIX
    def test_failed_installer_keeps_source_and_cleans_partial_result(self):
        before = self.source.stat()
        def fail(original, result, *unused):
            result.write_bytes(b'partial output which must not be installed')
            raise ValueError('Injected archive validation failure')
        with patch.object(guest, 'install', side_effect=fail):
            with self.assertRaisesRegex(ValueError, 'Injected archive validation failure'):
                self.run_install()
        self.assert_previous_untouched(before)

    @POSIX
    def test_source_content_changed_during_install_is_not_overwritten(self):
        def concurrent_change(*args):
            self.successful_installer(*args)
            self.source.write_bytes(b'concurrent update')
        with patch.object(guest, 'install', side_effect=concurrent_change):
            with self.assertRaisesRegex(RuntimeError, 'changed during adaptation'):
                self.run_install()
        self.assertEqual(self.source.read_bytes(), b'concurrent update')
        self.assertFalse(list(self.source.parent.glob('.udm-virtual-*')))

    @POSIX
    def test_replace_failure_keeps_source_and_cleans_result(self):
        before = self.source.stat()
        with patch.object(guest, 'install', side_effect=self.successful_installer), \
                patch.object(guest.os, 'replace', side_effect=OSError('Injected rename failure')):
            with self.assertRaisesRegex(OSError, 'Injected rename failure'):
                self.run_install()
        self.assert_previous_untouched(before)

    @POSIX
    def test_failed_attribute_preservation_does_not_replace_source(self):
        for function in ('chown', 'chmod', 'utime', 'fsync'):
            with self.subTest(function=function):
                before = self.source.stat()
                with patch.object(guest, 'install', side_effect=self.successful_installer), \
                        patch.object(guest.os, function, side_effect=OSError('Injected metadata failure')):
                    with self.assertRaisesRegex(OSError, 'Injected metadata failure'):
                        self.run_install()
                self.assert_previous_untouched(before)

    @POSIX
    def test_tampered_lower_is_refused_without_install(self):
        self.original.write_bytes(b'tampered original')
        before = self.source.stat()
        with patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'original controller SHA256 mismatch'):
                self.run_install()
            install.assert_not_called()
        self.assert_previous_untouched(before)

    @POSIX
    def test_wrong_mount_attributes_and_filesystem_are_refused(self):
        cases = [dict(mount_options='rw,relatime'), dict(super_options='rw'),
                 dict(mount_options='ro,rw'), dict(super_options='ro,rw'),
                 dict(filesystem='ext4'), dict(device='/dev/vdb'),
                 dict(device='/dev/vda1'), dict(root='/some-subtree'),
                 dict(devnum='123:456')]
        for case in cases:
            with self.subTest(**case):
                before = self.source.stat()
                self.write_mountinfo(**case)
                with patch.object(guest, 'install') as install:
                    with self.assertRaises(RuntimeError):
                        self.run_install()
                    install.assert_not_called()
                self.assert_previous_untouched(before)

    @POSIX
    def test_missing_or_malformed_mountinfo_is_refused(self):
        for value in ('', 'malformed\n', self.mount_line().replace(' - ', ' ')):
            with self.subTest(value=value):
                before = self.source.stat()
                self.mountinfo.write_text(value)
                with patch.object(guest, 'install') as install:
                    with self.assertRaises(RuntimeError):
                        self.run_install()
                    install.assert_not_called()
                self.assert_previous_untouched(before)

    @POSIX
    def test_nested_directory_and_file_mounts_are_refused(self):
        for point in (self.original.parent, self.original):
            with self.subTest(point=point):
                before = self.source.stat()
                self.mountinfo.write_text(self.mount_line() + self.mount_line(point=point))
                with patch.object(guest, 'install') as install:
                    with self.assertRaisesRegex(RuntimeError, 'read-only firmware SquashFS mount'):
                        self.run_install()
                    install.assert_not_called()
                self.assert_previous_untouched(before)

    @POSIX
    def test_stacked_mountpoints_are_refused_regardless_of_line_order(self):
        good = self.mount_line()
        bad = self.mount_line(mount_options='rw', filesystem='ext4')
        for lines in (good + good, good + bad, bad + good):
            with self.subTest(lines=lines):
                before = self.source.stat()
                self.mountinfo.write_text(lines)
                with patch.object(guest, 'install') as install:
                    with self.assertRaisesRegex(RuntimeError, 'mount is ambiguous'):
                        self.run_install()
                    install.assert_not_called()
                self.assert_previous_untouched(before)

    @POSIX
    def test_unrelated_mounts_do_not_hide_valid_original(self):
        self.mountinfo.write_text(self.mount_line() + self.mount_line(point=self.lower / 'unrelated'))
        self.assertEqual(guest.readonly_original(self.lower, self.mountinfo), self.original)

    @POSIX
    def test_lower_file_symlink_is_refused_without_install(self):
        target = self.original.with_name('real.jar')
        self.original.rename(target)
        self.original.symlink_to(target)
        before = self.source.stat()
        with patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                self.run_install()
            install.assert_not_called()
        self.assert_previous_untouched(before)

    @POSIX
    def test_lower_root_symlink_is_refused(self):
        alias = self.root / 'lower-alias'
        alias.symlink_to(self.lower, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            guest.readonly_original(alias, self.mountinfo)

    @POSIX
    def test_lower_parent_component_symlink_is_refused(self):
        directory = self.lower / 'usr'
        target = self.lower / 'real-usr'
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)
        before = self.source.stat()
        with patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                self.run_install()
            install.assert_not_called()
        self.assert_previous_untouched(before)

    @POSIX
    def test_overlay_file_symlink_is_refused_before_hashing(self):
        target = self.source.with_name('real.jar')
        self.source.rename(target)
        self.source.symlink_to(target)
        with patch.object(guest, 'sha256') as hashing, patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'regular file without symlinks'):
                self.run_install()
            hashing.assert_not_called()
            install.assert_not_called()
        self.assertEqual(target.read_bytes(), self.previous_bytes)

    @POSIX
    def test_overlay_parent_symlink_is_refused_before_hashing(self):
        directory = self.source.parent
        target = directory.with_name('real-lib')
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)
        with patch.object(guest, 'sha256') as hashing, patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'regular file without symlinks'):
                self.run_install()
            hashing.assert_not_called()
            install.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.previous_bytes)

    def test_nonregular_overlay_is_refused_before_hashing(self):
        self.source.unlink()
        self.source.mkdir()
        with patch.object(guest, 'sha256') as hashing, patch.object(guest, 'install') as install:
            with self.assertRaisesRegex(RuntimeError, 'regular file without symlinks'):
                self.run_install()
            hashing.assert_not_called()
            install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
