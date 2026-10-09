import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from virtualization import freeradius_cert as helper


@unittest.skipUnless(os.name == 'posix', 'Guest helper requires Linux filesystem semantics')
class LocalCertificateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='udm-cert-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = self.root / 'private' / 'snakeoil.key'
        self.cert = self.root / 'certs' / 'snakeoil.pem'
        self.key.parent.mkdir()
        self.cert.parent.mkdir()
        self.template = self.root / 'ssleay.cnf'
        self.template.write_text('[req]\ndefault_bits=2048\nprompt=no\n'
                                 'distinguished_name=dn\nx509_extensions=ext\n'
                                 '[dn]\nCN=@HostName@\n[ext]\nbasicConstraints=CA:FALSE\n')
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        (self.runtime / 'ready').write_text('ready\n')
        self.guard = self.enter(mock.patch.object(helper, 'require_guest'))
        self.enter(mock.patch.object(helper, 'RUNTIME', self.runtime))
        self.enter(mock.patch.object(helper.socket, 'gethostname', return_value='udm-virtual'))
        self.chown = self.enter(mock.patch.object(helper.os, 'chown'))
        import grp
        self.enter(mock.patch.object(grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=103)))
        self.commands = []

    def enter(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def ensure(self, run=None):
        return helper.ensure_certificate(self.key, self.cert, self.template, run or self.openssl)

    def openssl(self, command, **kwargs):
        self.commands.append(command)
        self.assertEqual(command[0], helper.OPENSSL)
        self.assertEqual(kwargs, dict(check=True, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        stdout = b''
        if command[1] == 'req':
            self.assertEqual(command[4:11], ['-new', '-x509', '-days', '3650', '-nodes', '-sha256', '-out'])
            self.assertIn('CN=udm-virtual', Path(command[3]).read_text())
            if '-keyout' in command:
                Path(command[command.index('-keyout') + 1]).write_bytes(b'key:local')
                public = b'local'
            else:
                self.assertIn('-key', command)
                self.assertEqual(command[-2:], ['-passin', 'pass:'])
                public = Path(command[command.index('-key') + 1]).read_bytes().split(b':', 1)[1]
            Path(command[command.index('-out') + 1]).write_bytes(b'cert:' + public)
        else:
            data = Path(command[command.index('-in') + 1]).read_bytes()
            kind = b'key:' if command[1] == 'pkey' else b'cert:'
            if not data.startswith(kind):
                raise subprocess.CalledProcessError(1, command)
            if '-pubout' in command or '-pubkey' in command:
                stdout = b'public:' + data.split(b':', 1)[1]
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    def assert_clean(self):
        self.assertEqual(list(self.root.rglob('.udm-local-tls-*')), [])

    def test_existing_valid_pair_is_preserved_without_permission_or_content_changes(self):
        self.key.write_bytes(b'key:existing')
        self.cert.write_bytes(b'cert:existing')
        self.key.chmod(0o600)
        before = helper.fingerprint(self.key), helper.fingerprint(self.cert)
        self.assertFalse(self.ensure())
        self.assertEqual(before, (helper.fingerprint(self.key), helper.fingerprint(self.cert)))
        self.assertFalse(any(command[1] == 'req' for command in self.commands))
        self.chown.assert_not_called()

    def test_missing_or_empty_files_create_validated_pair_with_original_permissions(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                for path in (self.key, self.cert):
                    path.unlink(missing_ok=True)
                    if empty:
                        path.write_bytes(b'')
                self.assertTrue(self.ensure())
                self.assertEqual(self.key.read_bytes(), b'key:local')
                self.assertEqual(self.cert.read_bytes(), b'cert:local')
                self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o640)
                self.assertEqual(stat.S_IMODE(self.cert.stat().st_mode), 0o644)
                self.assertTrue(any(call.args[1:] == (0, 103)
                                    for call in self.chown.call_args_list))
                self.assert_clean()

    def test_existing_key_is_reused_when_certificate_missing(self):
        self.key.write_bytes(b'key:previous')
        before = helper.fingerprint(self.key)
        self.assertTrue(self.ensure())
        self.assertEqual(before, helper.fingerprint(self.key))
        self.assertEqual(self.cert.read_bytes(), b'cert:previous')
        req = next(command for command in self.commands if command[1] == 'req')
        self.assertNotIn('-keyout', req)
        self.assertEqual(req[req.index('-key') + 1], str(self.key))

    def test_existing_unmatched_certificate_or_invalid_material_is_never_overwritten(self):
        for key, cert in ((None, b'cert:existing'), (b'', b'cert:existing'),
                          (b'key:one', b'cert:two'), (b'invalid', None),
                          (b'key:existing', b'invalid')):
            with self.subTest(key=key, cert=cert):
                for path, value in ((self.key, key), (self.cert, cert)):
                    path.unlink(missing_ok=True)
                    if value is not None:
                        path.write_bytes(value)
                self.commands.clear()
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    self.ensure()
                self.assertEqual(self.key.read_bytes() if self.key.exists() else None, key)
                self.assertEqual(self.cert.read_bytes() if self.cert.exists() else None, cert)
                self.assertFalse(any(command[1] == 'req' for command in self.commands))
                self.assert_clean()

    def test_generation_failure_or_sigterm_never_commits_partial_output(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt):
                previous = signal.getsignal(signal.SIGTERM)

                def fail(command, **kwargs):
                    self.openssl(command, **kwargs)
                    if interrupt:
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                    raise subprocess.CalledProcessError(1, command)

                with self.assertRaises((subprocess.CalledProcessError, helper.GenerationInterrupted)):
                    with helper.termination_signals():
                        self.ensure(fail)
                self.assertFalse(self.key.exists())
                self.assertFalse(self.cert.exists())
                self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
                self.assert_clean()

    def test_validation_failure_preserves_empty_destinations(self):
        self.key.write_bytes(b'')
        self.cert.write_bytes(b'')

        def mismatch(command, **kwargs):
            result = self.openssl(command, **kwargs)
            if command[1] == 'x509':
                return subprocess.CompletedProcess(command, 0, stdout=b'wrong public key')
            return result

        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.ensure(mismatch)
        self.assertEqual(self.key.read_bytes(), b'')
        self.assertEqual(self.cert.read_bytes(), b'')
        self.assert_clean()

    def test_interruption_between_key_and_cert_commit_reuses_committed_key(self):
        link = os.link

        def fail_certificate(source, destination):
            if Path(destination) == self.cert:
                raise OSError('certificate commit interrupted')
            return link(source, destination)

        with mock.patch.object(helper.os, 'link', side_effect=fail_certificate):
            with self.assertRaisesRegex(OSError, 'commit interrupted'):
                self.ensure()
        before = helper.fingerprint(self.key)
        self.assertFalse(self.cert.exists())
        self.assert_clean()
        self.assertTrue(self.ensure())
        self.assertEqual(before, helper.fingerprint(self.key))
        self.assertEqual(self.cert.read_bytes(), b'cert:local')

    def test_concurrent_creation_is_preserved(self):
        def race(command, **kwargs):
            result = self.openssl(command, **kwargs)
            if command[1] == 'req':
                self.key.write_bytes(b'key:other process')
            return result

        with self.assertRaisesRegex(ValueError, 'changed during'):
            self.ensure(race)
        self.assertEqual(self.key.read_bytes(), b'key:other process')
        self.assertFalse(self.cert.exists())
        self.assert_clean()

    def test_guard_or_missing_hal_marker_prevents_openssl_and_writes(self):
        self.guard.side_effect = ValueError('wrong guest')
        with self.assertRaisesRegex(ValueError, 'wrong guest'):
            self.ensure()
        self.guard.side_effect = None
        (self.runtime / 'ready').unlink()
        with self.assertRaisesRegex(ValueError, 'HAL must be ready'):
            self.ensure()
        self.assertEqual(self.commands, [])
        self.assertFalse(self.key.exists())
        self.assertFalse(self.cert.exists())

    def test_symlink_destinations_are_rejected_without_touching_target(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'preserve')
        for path in (self.key, self.cert):
            with self.subTest(path=path):
                path.symlink_to(outside)
                with self.assertRaisesRegex(ValueError, 'symbolic link'):
                    self.ensure()
                path.unlink()
                self.assertEqual(outside.read_bytes(), b'preserve')
        self.assertEqual(self.commands, [])

    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(), 'Requires native OpenSSL in a temporary directory')
    def test_real_openssl_creates_and_reuses_local_2048_bit_pair(self):
        def native(command, **kwargs):
            return subprocess.run(command, **kwargs, timeout=60)

        self.assertTrue(self.ensure(native))
        certificate = subprocess.run([helper.OPENSSL, 'x509', '-in', str(self.cert), '-text', '-noout'],
                                     check=True, capture_output=True, text=True)
        self.assertIn('Public-Key: (2048 bit)', certificate.stdout)
        self.assertIn('sha256WithRSAEncryption', certificate.stdout)
        subprocess.run([helper.OPENSSL, 'verify', '-CAfile', str(self.cert), str(self.cert)],
                       check=True, capture_output=True)
        key_before = self.key.read_bytes()
        self.assertFalse(self.ensure(native))
        self.cert.unlink()
        self.assertTrue(self.ensure(native))
        self.assertEqual(self.key.read_bytes(), key_before)
        self.assert_clean()


if __name__ == '__main__':
    unittest.main()
