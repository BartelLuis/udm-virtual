#!/usr/bin/python3
"""Initialize the original local snakeoil TLS identity in the guarded guest.

The firmware's ssl-cert postinst normally creates these files, but they are
absent from the update filesystem. This is an ordinary self-signed local server
certificate, unrelated to device manufacturing credentials or account login.
"""
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

if __package__:
    from .hal_guest import require_guest, RUNTIME
    from .freeradius_dh import GenerationInterrupted, termination_signals
else:
    from hal_guest import require_guest, RUNTIME
    from freeradius_dh import GenerationInterrupted, termination_signals


KEY = Path('/etc/ssl/private/ssl-cert-snakeoil.key')
CERT = Path('/etc/ssl/certs/ssl-cert-snakeoil.pem')
TEMPLATE = Path('/usr/share/ssl-cert/ssleay.cnf')
OPENSSL = '/usr/bin/openssl'


def fingerprint(path):
    """Track an ordinary destination without following a symbolic link."""
    if path.is_symlink():
        raise ValueError('TLS destination must not be a symbolic link: ' + str(path))
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError('TLS destination must be an ordinary file: ' + str(path))
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_certificate(key=KEY, cert=CERT, template=TEMPLATE, run=None):
    require_guest()
    ready = RUNTIME / 'ready'
    if ready.is_symlink() or not ready.is_file():
        raise ValueError('Virtual HAL must be ready before initializing local TLS')
    key, cert, template = Path(key), Path(cert), Path(template)
    for path in (key, cert):
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise ValueError('Original TLS destination directory is missing or a symbolic link')
    before_key, before_cert = fingerprint(key), fingerprint(cert)
    has_key = before_key is not None and before_key[2] > 0
    has_cert = before_cert is not None and before_cert[2] > 0
    run = subprocess.run if run is None else run

    def openssl(*args):
        # Never print a private key. Only public-key commands emit captured
        # stdout; stdin is closed and -passin prevents an interactive prompt.
        return run([OPENSSL, *map(str, args)], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE).stdout

    def public_key(candidate):
        openssl('pkey', '-in', candidate, '-passin', 'pass:', '-check', '-noout')
        return openssl('pkey', '-in', candidate, '-passin', 'pass:', '-pubout')

    def certificate_key(candidate):
        return openssl('x509', '-in', candidate, '-pubkey', '-noout')

    key_public = public_key(key) if has_key else None
    cert_public = certificate_key(cert) if has_cert else None
    if has_cert:
        if not has_key or key_public != cert_public:
            raise ValueError('Existing local TLS certificate has no matching private key; preserving both files')
        return False

    if not template.is_file() or template.is_symlink():
        raise ValueError('Original ssl-cert template is missing or a symbolic link')
    hostname = socket.gethostname()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,63}', hostname):
        raise ValueError('Local hostname cannot be used in the original ssl-cert template')
    configuration = template.read_text().replace('@HostName@', hostname)
    configuration = configuration.replace('@SubjectAltName@', 'DNS:' + hostname)
    import grp
    group = grp.getgrnam('ssl-cert').gr_gid

    with tempfile.TemporaryDirectory(prefix='.udm-local-tls-', dir=key.parent) as private_dir:
        configuration_path = Path(private_dir) / 'ssleay.cnf'
        configuration_path.write_text(configuration)
        temporary_key = Path(private_dir) / 'key.pem'
        descriptor, name = tempfile.mkstemp(prefix='.udm-local-tls-', dir=cert.parent)
        temporary_cert = Path(name)
        os.close(descriptor)
        try:
            args = ['req', '-config', configuration_path, '-new', '-x509',
                    '-days', '3650', '-nodes', '-sha256', '-out', temporary_cert]
            args += ['-key', key, '-passin', 'pass:'] if has_key else ['-keyout', temporary_key]
            openssl(*args)
            generated_public = key_public if has_key else public_key(temporary_key)
            if certificate_key(temporary_cert) != generated_public:
                raise ValueError('Generated local TLS certificate does not match its private key')
            if fingerprint(key) != before_key or fingerprint(cert) != before_cert:
                raise ValueError('Local TLS files changed during initialization; preserving them')

            temporary_cert.chmod(0o644)
            os.chown(temporary_cert, 0, 0)
            with temporary_cert.open('rb') as stream:
                os.fsync(stream.fileno())
            if not has_key:
                temporary_key.chmod(0o640)
                os.chown(temporary_key, 0, group)
                with temporary_key.open('rb') as stream:
                    os.fsync(stream.fileno())
                # Commit the key first. If interrupted between these two
                # atomic replacements, the next run reuses this exact key.
                if before_key is None:
                    os.link(temporary_key, key)  # Refuse a concurrently created destination.
                else:
                    os.replace(temporary_key, key)  # Only an existing empty file.
                sync_directory(key.parent)
            if before_cert is None:
                os.link(temporary_cert, cert)
            else:
                os.replace(temporary_cert, cert)  # Only an existing empty file.
            sync_directory(cert.parent)
        finally:
            temporary_cert.unlink(missing_ok=True)
    return True


def main():
    try:
        with termination_signals():
            changed = ensure_certificate()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, GenerationInterrupted) as error:
        print('UDM_VIRTUAL_LOCAL_TLS_FAILURE: ' + str(error), file=sys.stderr, flush=True)
        return 128 + error.signum if isinstance(error, GenerationInterrupted) else 1
    print('UDM_VIRTUAL_LOCAL_TLS_READY: ' + ('initialized' if changed else 'existing pair checked'), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
