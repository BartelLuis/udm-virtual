import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from virtualization import freeradius_dh as helper


@unittest.skipUnless(os.name == 'posix', 'Guest helper requires Linux filesystem/signal semantics')
class DhParameterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='udm-dh-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'dh'
        self.runtime = self.root / 'run'
        self.runtime.mkdir()
        (self.runtime / 'ready').write_text('virtual=1\n')
        guard = mock.patch.object(helper, 'require_guest')
        self.guard = guard.start()
        self.addCleanup(guard.stop)
        runtime = mock.patch.object(helper, 'RUNTIME', self.runtime)
        runtime.start()
        self.addCleanup(runtime.stop)
        self.commands = []

    def openssl(self, command, **kwargs):
        self.commands.append(command)
        self.assertEqual(command[:2], ['/usr/bin/openssl', 'dhparam'])
        self.assertEqual(kwargs, {'check': True, 'stdin': subprocess.DEVNULL})
        if '-dsaparam' in command:
            temporary = Path(command[command.index('-out') + 1])
            self.assertEqual(temporary.parent, self.path.parent)
            self.assertNotEqual(temporary, self.path)
            self.assertEqual(command, [helper.OPENSSL, 'dhparam', '-dsaparam', '-out', str(temporary), '2048'])
            temporary.write_bytes(b'valid parameters')
        else:
            candidate = Path(command[command.index('-in') + 1])
            self.assertEqual(command[-2:], ['-check', '-noout'])
            if candidate.read_bytes() != b'valid parameters':
                raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    def assert_no_temporary(self):
        self.assertEqual(list(self.root.glob('.udm-dh-*')), [])

    def test_valid_existing_parameters_are_checked_and_not_regenerated(self):
        self.path.write_bytes(b'valid parameters')
        self.path.chmod(0o600)
        self.assertFalse(helper.ensure_parameters(self.path, run=self.openssl))
        self.assertEqual(len(self.commands), 1)
        self.assertIn('-check', self.commands[0])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        self.assert_no_temporary()

    def test_missing_empty_and_invalid_parameters_are_replaced_after_validation(self):
        for previous in (None, b'', b'invalid old parameters'):
            with self.subTest(previous=previous):
                self.path.unlink(missing_ok=True)
                if previous is not None:
                    self.path.write_bytes(previous)
                self.commands.clear()

                def checked(command, **kwargs):
                    # Original destination is unchanged throughout generation
                    # and the new file's validation, before atomic replacement.
                    self.assertEqual(self.path.read_bytes() if self.path.exists() else None, previous)
                    return self.openssl(command, **kwargs)

                self.assertTrue(helper.ensure_parameters(self.path, run=checked))
                self.assertEqual(self.path.read_bytes(), b'valid parameters')
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
                self.assertIn('-dsaparam', self.commands[-2])
                self.assertIn('-check', self.commands[-1])
                self.assert_no_temporary()

    def test_generation_error_preserves_old_file_and_cleans_partial_output(self):
        self.path.write_bytes(b'')

        def fail(command, **kwargs):
            Path(command[command.index('-out') + 1]).write_bytes(b'partial')
            raise subprocess.CalledProcessError(1, command)

        with self.assertRaises(subprocess.CalledProcessError):
            helper.ensure_parameters(self.path, run=fail)
        self.assertEqual(self.path.read_bytes(), b'')
        self.assert_no_temporary()

    def test_generated_invalid_parameters_never_replace_old_file(self):
        self.path.write_bytes(b'old invalid parameters')

        def invalid(command, **kwargs):
            if '-out' in command:
                Path(command[command.index('-out') + 1]).write_bytes(b'invalid new parameters')
                return subprocess.CompletedProcess(command, 0)
            raise subprocess.CalledProcessError(1, command)

        with self.assertRaisesRegex(ValueError, 'did not pass OpenSSL validation'):
            helper.ensure_parameters(self.path, run=invalid)
        self.assertEqual(self.path.read_bytes(), b'old invalid parameters')
        self.assert_no_temporary()

    def test_sigterm_cleans_temporary_and_restores_signal_handlers(self):
        self.path.write_bytes(b'')
        previous = signal.getsignal(signal.SIGTERM)

        def interrupted(command, **kwargs):
            Path(command[command.index('-out') + 1]).write_bytes(b'partial')
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        with self.assertRaises(helper.GenerationInterrupted):
            with helper.termination_signals():
                helper.ensure_parameters(self.path, run=interrupted)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(self.path.read_bytes(), b'')
        self.assert_no_temporary()

    def test_replace_failure_preserves_old_parameters(self):
        self.path.write_bytes(b'')
        with mock.patch.object(helper.os, 'replace', side_effect=OSError('replace failed')):
            with self.assertRaisesRegex(OSError, 'replace failed'):
                helper.ensure_parameters(self.path, run=self.openssl)
        self.assertEqual(self.path.read_bytes(), b'')
        self.assert_no_temporary()

    def test_guest_guard_and_missing_hal_marker_prevent_writes_or_openssl(self):
        run = mock.Mock()
        self.guard.side_effect = ValueError('not the original guest')
        with self.assertRaisesRegex(ValueError, 'original guest'):
            helper.ensure_parameters(self.path, run=run)
        self.guard.side_effect = None
        (self.runtime / 'ready').unlink()
        with self.assertRaisesRegex(ValueError, 'HAL must be ready'):
            helper.ensure_parameters(self.path, run=run)
        run.assert_not_called()
        self.assertFalse(self.path.exists())
        self.assert_no_temporary()

    def test_symlink_destination_is_not_followed(self):
        outside = self.root / 'unrelated'
        outside.write_bytes(b'keep me')
        self.path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'ordinary file'):
            helper.ensure_parameters(self.path, run=self.openssl)
        self.assertEqual(outside.read_bytes(), b'keep me')
        self.assertEqual(self.commands, [])

    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(), 'Requires host OpenSSL for a temporary parameter test')
    def test_real_openssl_generates_valid_2048_bit_dsa_parameters(self):
        # Native OpenSSL runs only in this isolated temporary test directory,
        # never in the builder and never against a real guest/host service file.
        def real_openssl(command, **kwargs):
            return subprocess.run(command, **kwargs, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=60)

        self.path.write_bytes(b'')
        self.assertTrue(helper.ensure_parameters(self.path, run=real_openssl))
        result = subprocess.run([helper.OPENSSL, 'dhparam', '-in', str(self.path), '-check', '-noout', '-text'],
                                check=True, text=True, capture_output=True, timeout=30)
        self.assertIn('(2048 bit)', result.stdout)
        self.assertFalse(helper.ensure_parameters(self.path, run=real_openssl))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        self.assert_no_temporary()


if __name__ == '__main__':
    unittest.main()
