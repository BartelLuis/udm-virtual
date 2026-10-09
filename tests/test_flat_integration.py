"""Build wiring and shell argument tests; no firmware or Java is executed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from virtualization import build_payload as builder


ORIGINAL_UNIT = '''[Service]
User=unifi
WorkingDirectory=/usr/lib/unifi/
ExecStartPre=+/usr/sbin/unifi-network-service-helper init-uos
ExecStart=/usr/bin/java \\
    -Dspring.profiles.active=unifi-os \\
    $UNIFI_JVM_OPTS \\
    --add-opens java.base/java.lang=ALL-UNNAMED \\
    -jar /usr/lib/unifi/lib/ace.jar
ExecStartPost=/usr/sbin/unifi-network-service-helper service-started
'''


class BuildPayloadFlatIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='udm-flat-build-test-')
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name) / 'new-payload'
        self.description = {'schema': 1, 'source_sha256': 'adapted fixture hash',
                            'classpath': ['BOOT-INF/classes', 'BOOT-INF/lib/fixture.jar']}

    def extract(self, command, **kwargs):
        member = command[-1]
        if member == 'usr/lib/unifi/lib/ace.jar':
            kwargs['stdout'].write(b'original fixture archive')
            return subprocess.CompletedProcess(command, 0)
        if member == 'lib/systemd/system/unifi.service':
            data = ORIGINAL_UNIT.encode('utf-8')
        elif member == 'usr/bin/ubios-udapi-server':
            data = b'original daemon fixture'
        else:
            data = b'{}'
        return subprocess.CompletedProcess(command, 0, stdout=data)

    def patch_daemon(self, source, destination):
        destination.write_bytes(b'adapted daemon fixture')
        return {'status': 'fixture'}

    def patch_controller(self, source, destination, nested):
        self.assertEqual(source.read_bytes(), b'original fixture archive')
        destination.write_bytes(b'adapted controller fixture')
        nested.write_bytes(b'adapted nested fixture')
        return {'result_sha256': 'adapted fixture hash'}

    def describe(self, source, controller):
        self.assertEqual(source, self.output / 'ace.virtual.jar')
        self.assertEqual(source.read_bytes(), b'adapted controller fixture')
        self.assertEqual(controller['result_sha256'], 'adapted fixture hash')
        self.assertFalse((self.output / 'controller.json').exists())
        return self.description

    def build(self, metadata=None):
        with mock.patch.object(builder.shutil, 'which', return_value='/test/unsquashfs'), \
                mock.patch.object(builder.subprocess, 'run', side_effect=self.extract), \
                mock.patch.object(builder, 'patch', side_effect=self.patch_daemon), \
                mock.patch.object(builder, 'patch_controller', side_effect=self.patch_controller), \
                mock.patch.object(builder, 'build_metadata', side_effect=metadata or self.describe), \
                mock.patch.object(builder, 'generate_board', return_value={}), \
                mock.patch.object(builder, 'transform_state', return_value={}), \
                mock.patch.object(builder, 'test_policy', return_value={}):
            return builder.build_payload('synthetic-rootfs', self.output, builder.FIRMWARE_SHA256)

    def test_metadata_written_before_packaging_and_no_duplicate_application_cache(self):
        entries, report = self.build()
        packaged = json.loads(entries['udm-virtual/controller.json'][1])
        self.assertEqual(packaged['flat'], self.description)
        self.assertEqual(report['controller'], packaged)
        self.assertEqual(entries['udm-virtual/controller_flat.py'],
                         (0o644, (builder.BASE / 'controller_flat.py').read_bytes().replace(b'\r\n', b'\n')))
        self.assertEqual(entries['udm-virtual/java-tcg.sh'][0], 0o755)
        self.assertFalse(any('/controller-flat/' in name or name.endswith('/ace.virtual.jar') for name in entries))
        self.assertIn('udm-virtual/freeradius_cert.py', entries)
        self.assertIn('udm-virtual/freeradius-cert.service', entries)

    def test_generated_dropin_selects_flat_and_appends_prepare_preserving_vendor_options(self):
        entries, _ = self.build()
        dropin = entries['udm-virtual/unifi-tcg.conf'][1].decode('utf-8').replace('\r\n', '\n')
        lines = dropin.splitlines()
        self.assertIn('Environment=UDM_UNIFI_LAUNCH=flat', lines)
        self.assertIn('ExecStartPre=+/usr/bin/python3 /usr/lib/udm-virtual/controller_flat.py prepare', lines)
        self.assertNotIn('ExecStartPre=', lines)  # No reset: original init-uos still runs first.
        self.assertNotIn('ExecStartPost=', lines)
        original_start = ORIGINAL_UNIT[ORIGINAL_UNIT.index('ExecStart='):ORIGINAL_UNIT.index('ExecStartPost=')]
        expected = original_start.replace('/usr/bin/java ', '/usr/lib/udm-virtual/java-tcg.sh ', 1)
        self.assertTrue(dropin.endswith(expected))
        self.assertEqual(sum(line == 'ExecStart=' for line in lines), 1)

    def test_metadata_failure_prevents_packaged_controller_metadata(self):
        def refuse(*_):
            raise ValueError('unsupported archive layout')
        with self.assertRaisesRegex(ValueError, 'unsupported archive layout'):
            self.build(metadata=refuse)
        self.assertFalse((self.output / 'controller.json').exists())
        self.assertFalse((self.output / 'unifi-tcg.conf').exists())


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Requires host Bash')
class JavaWrapperTests(unittest.TestCase):
    def invoke(self, mode, arguments):
        environment = dict(os.environ)
        environment.pop('UDM_UNIFI_LAUNCH', None)
        if mode is not None:
            environment['UDM_UNIFI_LAUNCH'] = mode
        # The exec shell function captures the real wrapper's final argv. It
        # never starts the hardcoded Python helper, Java, or firmware services.
        capture = 'exec() { printf "%s\\0" "$@"; }; source "$1" "${@:2}"'
        return subprocess.run(['bash', '-c', capture, 'test-wrapper',
                               str(builder.BASE / 'java-tcg.sh'), *arguments],
                              env=environment, capture_output=True, timeout=10)

    def captured(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return [item.decode() for item in result.stdout.split(b'\0')[:-1]]

    def test_flat_mode_routes_to_helper_after_c1_conversion_with_exact_arguments(self):
        arguments = ['-Dexample=two words', '-XX:-TieredCompilation', '-Xmx512M',
                     '--add-opens', 'java.base/java.lang=ALL-UNNAMED',
                     '-jar', '/usr/lib/unifi/lib/ace.jar']
        self.assertEqual(self.captured(self.invoke('flat', arguments)),
                         ['/usr/bin/python3', '/usr/lib/udm-virtual/controller_flat.py', 'launch', '--',
                          '-Dexample=two words', '-XX:+TieredCompilation', '-XX:TieredStopAtLevel=1',
                          *arguments[2:]])

    def test_nested_override_and_unset_mode_keep_original_jar_launch(self):
        arguments = ['-XX:-TieredCompilation', '-Dexample=two words', '-jar', '/usr/lib/unifi/lib/ace.jar']
        for mode in ('nested', None):
            with self.subTest(mode=mode):
                self.assertEqual(self.captured(self.invoke(mode, arguments)),
                                 ['/usr/bin/java', '-XX:+TieredCompilation', '-XX:TieredStopAtLevel=1',
                                  *arguments[1:]])

    def test_empty_or_unknown_mode_refuses_without_starting_any_program(self):
        for mode in ('', 'auto', 'FLAT'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, ['-jar', '/usr/lib/unifi/lib/ace.jar'])
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'unknown UDM_UNIFI_LAUNCH mode', result.stderr)


if __name__ == '__main__':
    unittest.main()
