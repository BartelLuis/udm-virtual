"""Filesystem-only checks for the guest DNS adaptation; no services are run."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from virtualization import dns_guest as helper


@unittest.skipUnless(os.name == 'posix', 'Requires Linux symlink and permission semantics')
class GuestDnsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='udm-dns-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def case_root(self, name):
        root = self.root / name
        (root / 'etc/systemd/system').mkdir(parents=True)
        return root

    def assert_masks(self, root):
        for name in ('dnsmasq', 'systemd-resolved'):
            path = root / 'etc/systemd/system' / (name + '.service')
            self.assertTrue(path.is_symlink())
            self.assertEqual(os.readlink(path), '/dev/null')

    def assert_native_resolver(self, root):
        path = root / 'etc/resolv.conf'
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.read_bytes(), b'nameserver 127.0.0.1\n')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(list((root / 'etc').glob('.resolv.conf.udm-*')), [])

    def snapshot(self, root):
        result = {}
        for parent, directories, files in os.walk(root, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                relative = str(path.relative_to(root))
                mode = stat.S_IMODE(path.lstat().st_mode)
                if path.is_symlink():
                    result[relative] = ('symlink', os.readlink(path), mode)
                elif path.is_file():
                    result[relative] = ('file', path.read_bytes(), mode)
                else:
                    result[relative] = ('directory', mode)
        return result

    def test_missing_resolver_creates_native_file_and_only_two_masks(self):
        self.assertTrue(helper.configure(self.root))
        self.assert_native_resolver(self.root)
        self.assert_masks(self.root)
        units = self.root / 'etc/systemd/system'
        self.assertEqual({p.name for p in units.iterdir()},
                         {'dnsmasq.service', 'systemd-resolved.service'})

    def test_standard_absolute_relative_and_broken_stubs_are_replaced_without_writing_target(self):
        cases = [(name, absolute, present)
                 for name in ('stub-resolv.conf', 'resolv.conf')
                 for absolute in (False, True) for present in (False, True)]
        for index, (name, absolute, present) in enumerate(cases):
            with self.subTest(name=name, absolute=absolute, target_exists=present):
                root = self.case_root(str(index))
                target = root / 'run/systemd/resolve' / name
                if present:
                    target.parent.mkdir(parents=True)
                    target.write_bytes(b'nameserver 127.0.0.53\n# existing systemd output\n')
                link = ('/run/systemd/resolve/' if absolute else '../run/systemd/resolve/') + name
                (root / 'etc/resolv.conf').symlink_to(link)
                self.assertTrue(helper.configure(root))
                self.assert_native_resolver(root)
                self.assert_masks(root)
                if present:
                    self.assertEqual(target.read_bytes(),
                                     b'nameserver 127.0.0.53\n# existing systemd output\n')
                else:
                    self.assertFalse(target.exists())

    def test_custom_regular_resolver_and_native_dns_files_and_units_are_preserved(self):
        root = self.case_root('custom')
        contents = {
            'etc/resolv.conf': b'search custom.example\nnameserver 192.0.2.53\n',
            'etc/resolv.dnsmasq': b'# original UDAPI upstream\nnameserver 192.0.2.54\n',
            'etc/systemd/system/udapi-server.service': b'[Service]\nExecStart=/usr/bin/ubios-udapi-server\n',
            'etc/systemd/system/dns-cache-db.service': b'[Service]\nExecStart=/usr/bin/dns-cache-db\n',
            'etc/systemd/system/dnsmasq@lan.service': b'[Service]\nExecStart=/custom/instance\n',
        }
        identities = {}
        for relative, content in contents.items():
            path = root / relative
            path.write_bytes(content)
            path.chmod(0o640)
            identities[relative] = path.stat().st_ino
        self.assertFalse(helper.configure(root))
        self.assert_masks(root)
        for relative, content in contents.items():
            path = root / relative
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_ino, identities[relative])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_custom_existing_and_dangling_resolver_symlinks_are_preserved(self):
        for index, (target, present) in enumerate((('../persistent/resolv.conf', True),
                                                  ('../persistent/missing.conf', False),
                                                  ('/custom/missing-resolver.conf', False))):
            with self.subTest(target=target, target_exists=present):
                root = self.case_root(str(index))
                real_target = root / 'persistent/resolv.conf'
                if present:
                    real_target.parent.mkdir()
                    real_target.write_bytes(b'nameserver 192.0.2.55\n')
                resolver = root / 'etc/resolv.conf'
                resolver.symlink_to(target)
                inode = resolver.lstat().st_ino
                self.assertFalse(helper.configure(root))
                self.assertEqual(os.readlink(resolver), target)
                self.assertEqual(resolver.lstat().st_ino, inode)
                self.assert_masks(root)
                if present:
                    self.assertEqual(real_target.read_bytes(), b'nameserver 192.0.2.55\n')

    def test_second_run_is_idempotent_without_replacing_existing_files(self):
        self.assertTrue(helper.configure(self.root))
        before = self.snapshot(self.root)
        paths = [self.root / 'etc/resolv.conf',
                 self.root / 'etc/systemd/system/dnsmasq.service',
                 self.root / 'etc/systemd/system/systemd-resolved.service']
        inodes = [path.lstat().st_ino for path in paths]
        self.assertFalse(helper.configure(self.root))
        self.assertEqual(self.snapshot(self.root), before)
        self.assertEqual([path.lstat().st_ino for path in paths], inodes)

    def test_custom_regular_dns_units_are_refused_before_any_mutation(self):
        for name in ('dnsmasq', 'systemd-resolved'):
            with self.subTest(unit=name):
                root = self.case_root(name)
                (root / 'etc/resolv.conf').symlink_to('/run/systemd/resolve/stub-resolv.conf')
                (root / 'etc/systemd/system' / (name + '.service')).write_text(
                    '[Service]\nExecStart=/custom/dns-owner\n')
                before = self.snapshot(root)
                with self.assertRaisesRegex(ValueError, 'custom DNS unit'):
                    helper.configure(root)
                self.assertEqual(self.snapshot(root), before)

    def test_custom_dns_unit_symlinks_including_dangling_links_are_refused_before_mutation(self):
        for index, (name, present) in enumerate((('dnsmasq', True), ('dnsmasq', False),
                                                ('systemd-resolved', True), ('systemd-resolved', False))):
            with self.subTest(unit=name, target_exists=present):
                root = self.case_root(str(index))
                target = root / 'custom-dns.service'
                if present:
                    target.write_text('[Service]\nExecStart=/custom/dns-owner\n')
                (root / 'etc/systemd/system' / (name + '.service')).symlink_to('../../../custom-dns.service')
                before = self.snapshot(root)
                with self.assertRaisesRegex(ValueError, 'custom DNS unit'):
                    helper.configure(root)
                self.assertEqual(self.snapshot(root), before)

    def test_vendor_unit_aliases_are_replaced_but_vendor_files_untouched(self):
        for index, prefix in enumerate(('/lib/systemd/system', '/usr/lib/systemd/system',
                                        '../../../lib/systemd/system')):
            with self.subTest(prefix=prefix):
                root = self.case_root(str(index))
                for name in ('dnsmasq', 'systemd-resolved'):
                    vendor = root / prefix.lstrip('/') / (name + '.service') if prefix.startswith('/') else root / 'lib/systemd/system' / (name + '.service')
                    vendor.parent.mkdir(parents=True, exist_ok=True)
                    vendor.write_bytes(b'[Service]\nExecStart=/vendor/original\n')
                    (root / 'etc/systemd/system' / (name + '.service')).symlink_to(prefix + '/' + name + '.service')
                self.assertTrue(helper.configure(root))
                self.assert_masks(root)
                for vendor in list((root / 'lib').rglob('*.service')) + list((root / 'usr/lib').rglob('*.service')):
                    self.assertEqual(vendor.read_bytes(), b'[Service]\nExecStart=/vendor/original\n')

    def test_failed_atomic_resolver_install_preserves_old_stub_and_removes_temporary_file(self):
        root = self.case_root('replace-failure')
        resolver = root / 'etc/resolv.conf'
        resolver.symlink_to('../run/systemd/resolve/stub-resolv.conf')
        replace = os.replace

        def fail_resolver_replace(source, destination):
            if Path(destination) == resolver:
                raise OSError('simulated resolver replacement failure')
            return replace(source, destination)

        with mock.patch.object(helper.os, 'replace', side_effect=fail_resolver_replace):
            with self.assertRaisesRegex(OSError, 'simulated resolver replacement failure'):
                helper.configure(root)
        self.assertEqual(os.readlink(resolver), '../run/systemd/resolve/stub-resolv.conf')
        self.assertEqual(list((root / 'etc').glob('.resolv.conf.udm-*')), [])
        self.assert_masks(root)


if __name__ == '__main__':
    unittest.main()
