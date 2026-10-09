#!/usr/bin/python3
"""Create original FreeRADIUS DH parameters atomically in the guarded guest."""
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

if __package__:
    from .hal_guest import require_guest, RUNTIME
else:
    from hal_guest import require_guest, RUNTIME


DH_PATH = Path('/etc/freeradius/3.0/certs/dh')
OPENSSL = '/usr/bin/openssl'


class GenerationInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum
        super().__init__('DH parameter generation interrupted by signal ' + str(signum))


@contextmanager
def termination_signals():
    def interrupted(signum, frame):
        raise GenerationInterrupted(signum)

    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def ensure_parameters(path=DH_PATH, run=None):
    """Keep verified parameters or replace them only after a verified new file."""
    require_guest()  # root, exact original kernel, explicit mode and QEMU virt
    ready = RUNTIME / 'ready'
    if ready.is_symlink() or not ready.is_file():
        raise ValueError('Virtual HAL must be ready before generating DH parameters')
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('DH destination must be an ordinary file')
    if not path.parent.is_dir():
        raise ValueError('Original FreeRADIUS certificate directory is missing')
    run = subprocess.run if run is None else run

    def valid(candidate):
        if candidate.stat().st_size == 0:
            return False
        try:
            run([OPENSSL, 'dhparam', '-in', str(candidate), '-check', '-noout'],
                check=True, stdin=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            return False
        return True

    if path.exists() and valid(path):
        path.chmod(0o644)  # These are public parameters, not a private key.
        return False

    descriptor, name = tempfile.mkstemp(prefix='.udm-dh-', dir=path.parent)
    temporary = Path(name)
    os.close(descriptor)
    try:
        # Preserve the firmware's algorithm and size; only the output path and
        # atomic commit differ. subprocess.run kills/reaps its child when our
        # signal handler raises, then this finally block removes the temporary.
        run([OPENSSL, 'dhparam', '-dsaparam', '-out', str(temporary), '2048'],
            check=True, stdin=subprocess.DEVNULL)
        if not valid(temporary):
            raise ValueError('Generated DH parameters did not pass OpenSSL validation')
        temporary.chmod(0o644)
        with temporary.open('rb') as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def main():
    try:
        with termination_signals():
            changed = ensure_parameters()
    except (OSError, ValueError, subprocess.CalledProcessError, GenerationInterrupted) as error:
        print('UDM_VIRTUAL_DH_FAILURE: ' + str(error), file=sys.stderr, flush=True)
        return 128 + error.signum if isinstance(error, GenerationInterrupted) else 1
    print('UDM_VIRTUAL_DH_READY: ' + ('created and checked' if changed else 'existing parameters checked'),
          flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
