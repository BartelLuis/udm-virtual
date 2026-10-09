"""Exercise synthetic archives/cache files only; never start firmware or Java."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from virtualization import controller_flat as flat


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FlatFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='udm-flat-test-')
        self.addCleanup(self.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'ace.jar'
        self.base = self.root / 'cache'
        self.indexed = [flat.INTERNAL_JAR] + ['BOOT-INF/lib/lib-%03d.jar' % i for i in range(151)]
        self.entries = {
            'META-INF/MANIFEST.MF': ('Manifest-Version: 1.0\r\n'
                                    'Main-Class: org.springframework.boot.loader.launch.JarLauncher\r\n'
                                    'Start-Class: ' + flat.MAIN_CLASS + '\r\n'
                                    'Spring-Boot-Version: ' + flat.BOOT_VERSION + '\r\n').encode(),
            flat.CLASSES + '/com/ubnt/ace/BootLauncher.class': b'opaque original class bytes',
            flat.CLASSES + '/product.properties': b'version=synthetic-test\n',
            flat.CLASSES + '/config/lookup.txt': b'resource content retained',
            flat.INDEX: ''.join('- "' + name + '"\n' for name in self.indexed).encode(),
            **{name: ('opaque, intact dependency ' + name).encode() for name in self.indexed},
            flat.TOOLS_JAR: b'opaque, intact tools dependency',
        }
        self.write_archive()

    def cleanup(self):
        if self.root.exists() and os.name == 'posix':
            for path in self.root.rglob('*'):
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o700)
        self.temporary.cleanup()

    def write_archive(self, extra=()):
        with zipfile.ZipFile(self.source, 'w') as archive:
            for name, value in self.entries.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, value)
            for info, data in extra:
                archive.writestr(info, data)
        self.controller = {'source_sha256': flat.ORIGINAL_SHA256,
                           'result_sha256': sha(self.source.read_bytes()),
                           'nested_member': flat.INTERNAL_JAR,
                           'nested_result_sha256': sha(self.entries[flat.INTERNAL_JAR])}

    def metadata(self):
        return flat.build_metadata(self.source, self.controller)


class FlatMetadataTests(FlatFixture, unittest.TestCase):
    def test_all_resources_and_opaque_jars_described_in_exact_index_order(self):
        metadata = self.metadata()
        self.assertEqual(metadata['classpath'], [flat.CLASSES, *self.indexed, flat.TOOLS_JAR])
        expected = set(self.entries) - {'META-INF/MANIFEST.MF'}
        self.assertEqual(set(metadata['files']), expected)
        for name, details in metadata['files'].items():
            self.assertEqual(details, {'size_bytes': len(self.entries[name]), 'sha256': sha(self.entries[name])})
        self.assertEqual(self.metadata(), metadata)
        self.assertFalse(self.base.exists())

    def test_unknown_original_adapted_and_nested_hashes_refused(self):
        for field in ('source_sha256', 'result_sha256', 'nested_result_sha256'):
            controller = dict(self.controller, **{field: '0' * 64})
            with self.subTest(field=field), self.assertRaises(ValueError):
                flat.build_metadata(self.source, controller)

    def test_traversal_special_files_and_aliases_refused(self):
        cases = [('../escape', stat.S_IFREG), ('/absolute', stat.S_IFREG),
                 ('BOOT-INF/classes/../../escape', stat.S_IFREG),
                 ('BOOT-INF/classes/link', stat.S_IFLNK), ('BOOT-INF/classes/fifo', stat.S_IFIFO),
                 ('BOOT-INF/classes/back\\slash', stat.S_IFREG),
                 ('BOOT-INF/classes/stream:other', stat.S_IFREG),
                 ('BOOT-INF/classes/product.properties', stat.S_IFREG),
                 ('BOOT-INF/classes/PRODUCT.properties', stat.S_IFREG)]
        for name, kind in cases:
            with self.subTest(name=name):
                info = zipfile.ZipInfo(name)
                # ZipInfo normalizes backslashes on Windows. Preserve the
                # adversarial raw member name before serializing the fixture.
                info.filename = name
                info.orig_filename = name
                info.external_attr = (kind | 0o644) << 16
                with mock.patch('warnings.warn'):
                    self.write_archive([(info, b'invalid')])
                self.assertIn(name.encode('utf-8'), self.source.read_bytes())
                with self.assertRaises(ValueError):
                    self.metadata()

    def test_missing_duplicate_and_unexpected_index_entries_refused(self):
        original = self.entries[flat.INDEX]
        for changed in (original.replace(self.indexed[0].encode(), b'BOOT-INF/lib/missing.jar'),
                        original.replace(self.indexed[0].encode(), self.indexed[1].encode()),
                        original + b'- "BOOT-INF/lib/extra.jar"\n'):
            with self.subTest(index=changed[:80]):
                self.entries[flat.INDEX] = changed
                self.write_archive()
                with self.assertRaises(ValueError):
                    self.metadata()

    def test_manifest_entrypoint_cannot_change(self):
        self.entries['META-INF/MANIFEST.MF'] = self.entries['META-INF/MANIFEST.MF'].replace(
            flat.MAIN_CLASS.encode(), b'example.OtherMain')
        self.write_archive()
        with self.assertRaisesRegex(ValueError, 'launcher manifest'):
            self.metadata()

    def test_prepare_default_does_not_read_metadata_or_touch_cache(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(flat, 'owned') as owned:
            self.assertEqual(flat.main(['prepare']), 0)
        owned.assert_not_called()
        self.assertFalse(self.base.exists())


@unittest.skipUnless(os.name == 'posix', 'Cache requires Linux ownership, permissions and flock')
class FlatCacheTests(FlatFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.owner = os.geteuid()

    def prepare(self, metadata=None):
        return flat.ensure_cache(self.source, metadata or self.metadata(), self.base, owner_uid=self.owner)

    def test_atomic_publication_exact_contents_permissions_and_reuse(self):
        metadata = self.metadata()
        destination = flat.cache_path(self.base, metadata)
        original_verify = flat.verify_cache

        def verify_before_publish(candidate, expected, **kwargs):
            if Path(candidate) != destination:
                self.assertFalse(destination.exists())
            return original_verify(candidate, expected, **kwargs)

        with mock.patch.object(flat, 'verify_cache', side_effect=verify_before_publish):
            actual = self.prepare(metadata)
        self.assertEqual(actual, destination)
        for name in metadata['files']:
            self.assertEqual((actual / name).read_bytes(), self.entries[name])
            self.assertEqual(stat.S_IMODE((actual / name).stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o555)
        inode = actual.stat().st_ino
        self.assertEqual(self.prepare(metadata).stat().st_ino, inode)
        self.assertEqual(list(self.base.glob('.extract-*')), [])

    def test_tampered_metadata_never_publishes_and_partial_tree_removed(self):
        metadata = copy.deepcopy(self.metadata())
        metadata['files'][flat.CLASSES + '/product.properties']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Extracted content mismatch'):
            self.prepare(metadata)
        self.assertFalse(flat.cache_path(self.base, metadata).exists())
        self.assertEqual(list(self.base.glob('.extract-*')), [])

    def test_publish_failure_leaves_no_partial_cache(self):
        metadata = self.metadata()
        with mock.patch.object(flat.os, 'rename', side_effect=OSError('simulated rename failure')):
            with self.assertRaisesRegex(OSError, 'rename failure'):
                self.prepare(metadata)
        self.assertFalse(flat.cache_path(self.base, metadata).exists())
        self.assertEqual(list(self.base.glob('.extract-*')), [])

    def test_classpath_order_mismatch_never_publishes(self):
        metadata = copy.deepcopy(self.metadata())
        metadata['classpath'][1:3] = reversed(metadata['classpath'][1:3])
        with self.assertRaisesRegex(ValueError, 'index order mismatch'):
            self.prepare(metadata)
        self.assertFalse(flat.cache_path(self.base, metadata).exists())
        self.assertEqual(list(self.base.glob('.extract-*')), [])

    def test_modified_missing_extra_writable_or_symlink_member_blocks_launch(self):
        for fault in ('modified', 'missing', 'extra', 'writable', 'symlink', 'marker'):
            with self.subTest(fault=fault):
                base = self.root / fault
                metadata = self.metadata()
                destination = flat.ensure_cache(self.source, metadata, base, owner_uid=self.owner)
                target = destination / flat.CLASSES / 'product.properties'
                if fault == 'modified':
                    target.chmod(0o644)
                    target.write_bytes(b'!' * target.stat().st_size)
                    target.chmod(0o444)
                elif fault == 'missing':
                    target.parent.chmod(0o755)
                    target.unlink()
                    target.parent.chmod(0o555)
                elif fault == 'extra':
                    destination.chmod(0o755)
                    (destination / 'extra.class').write_bytes(b'not in inventory')
                    (destination / 'extra.class').chmod(0o444)
                    destination.chmod(0o555)
                elif fault == 'writable':
                    target.chmod(0o644)
                elif fault == 'symlink':
                    target.parent.chmod(0o755)
                    target.unlink()
                    target.symlink_to(self.source)
                    target.parent.chmod(0o555)
                else:
                    marker = destination / flat.MARKER
                    marker.chmod(0o644)
                    marker.write_bytes(b'{}\n')
                    marker.chmod(0o444)
                execute = mock.Mock()
                with self.assertRaises(ValueError):
                    flat.launch(['-jar', str(flat.SOURCE)], metadata, self.source, base,
                                owner_uid=self.owner, execute=execute)
                execute.assert_not_called()

    def test_symlink_cache_root_and_unexpected_owner_refused(self):
        outside = self.root / 'outside'
        outside.mkdir()
        self.base.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'owned'):
            self.prepare()
        self.assertEqual(list(outside.iterdir()), [])
        self.base.unlink()
        with self.assertRaisesRegex(ValueError, 'owned'):
            flat.ensure_cache(self.source, self.metadata(), self.base, owner_uid=self.owner + 1)

    def test_unprivileged_launch_preserves_jvm_arguments_uses_exec_and_order(self):
        original = self.source.read_bytes()
        metadata = self.metadata()
        destination = self.prepare(metadata)
        args = ['-Dexample=two words', '-XX:+TieredCompilation', '-XX:TieredStopAtLevel=1',
                '--add-opens', 'java.base/java.lang=ALL-UNNAMED', '-jar', str(flat.SOURCE)]
        execute = mock.Mock()
        flat.launch(args, metadata, self.source, self.base, owner_uid=self.owner, execute=execute)
        expected = [flat.JAVA, *args[:-2], '-Dbase.dir=/usr/lib/unifi', '-cp',
                    ':'.join(str(destination / n) for n in metadata['classpath']), flat.MAIN_CLASS]
        execute.assert_called_once_with(flat.JAVA, expected)
        self.assertEqual(self.source.read_bytes(), original)

    def test_changed_source_and_nonterminal_invocation_never_execute(self):
        metadata = self.metadata()
        self.prepare(metadata)
        execute = mock.Mock()
        for args in ([], ['-jar', '/other.jar'], ['-jar', str(flat.SOURCE), 'extra']):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'terminal'):
                flat.launch(args, metadata, self.source, self.base, owner_uid=self.owner, execute=execute)
        self.source.write_bytes(b'firmware upgrade or corrupted archive')
        with self.assertRaisesRegex(ValueError, 'Installed controller hash mismatch'):
            flat.launch(['-jar', str(flat.SOURCE)], metadata, self.source, self.base,
                        owner_uid=self.owner, execute=execute)
        execute.assert_not_called()

    def test_guest_guard_and_hal_marker_prevent_preparation(self):
        from virtualization import hal_guest
        report = self.root / 'controller.json'
        report.write_text(json.dumps(dict(self.controller, flat=self.metadata())))
        with mock.patch.dict(os.environ, {'UDM_UNIFI_LAUNCH': 'flat'}), \
                mock.patch.object(flat, 'REPORT', report), mock.patch.object(flat, 'owned'), \
                mock.patch.object(flat, 'ensure_cache') as prepare, \
                mock.patch.object(hal_guest, 'require_guest', side_effect=ValueError('wrong guest')) as guard, \
                mock.patch.object(hal_guest, 'RUNTIME', self.root / 'run'), \
                mock.patch('sys.stderr'):
            self.assertEqual(flat.main(['prepare']), 1)
            prepare.assert_not_called()
            guard.side_effect = None
            self.assertEqual(flat.main(['prepare']), 1)
            prepare.assert_not_called()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0,
                         'Requires root solely to create root-owned cache and drop child privileges')
    def test_root_owned_readonly_cache_launches_after_child_drops_privileges(self):
        import pwd
        account = pwd.getpwnam('nobody')
        metadata = self.metadata()
        self.prepare(metadata)
        self.root.chmod(0o755)
        self.source.chmod(0o644)

        def drop_privileges():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        program = '''import json, os, sys
from virtualization import controller_flat as flat
value = json.load(sys.stdin)
assert os.geteuid() != 0
captured = []
flat.launch(['-Xmx512M', '-jar', str(flat.SOURCE)], value['metadata'],
            value['source'], value['base'], owner_uid=0,
            execute=lambda executable, arguments: captured.append(arguments))
print(json.dumps({'uid': os.geteuid(), 'command': captured[0]}))
'''
        result = subprocess.run([sys.executable, '-B', '-c', program],
                                input=json.dumps({'metadata': metadata, 'source': str(self.source),
                                                  'base': str(self.base)}),
                                text=True, capture_output=True, timeout=30,
                                cwd=Path(__file__).resolve().parents[1], preexec_fn=drop_privileges)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output['uid'], account.pw_uid)
        self.assertEqual(output['command'][:2], [flat.JAVA, '-Xmx512M'])
        self.assertEqual(output['command'][-1], flat.MAIN_CLASS)


if __name__ == '__main__':
    unittest.main()
