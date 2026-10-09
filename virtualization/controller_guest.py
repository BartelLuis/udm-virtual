"""Atomically install the exact native-port and authenticated GCM adaptation."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile

if __package__:
    from .patch_controller import install, sha256, SOURCE_SHA256
else:
    from patch_controller import install, sha256, SOURCE_SHA256


# Exact R3/R4 controller output, with only the native-port adaptation. A known
# older overlay is rebuilt from its original read-only firmware, never patched
# in place or treated as an arbitrary supported firmware update.
PREVIOUS_SHA256 = '49799062afc6e36778319ef4739c072f5adc4651d4a8638c19adfa8176507fc4'
SOURCE = Path('/usr/lib/unifi/lib/ace.jar')
LOWER_ROOT = Path('/mnt/.rofs')
MOUNTINFO = Path('/proc/self/mountinfo')


def mount_path(value):
    return re.sub(r'\\(040|011|012|134)', lambda item: chr(int(item.group(1), 8)), value)


def readonly_original(lower_root=LOWER_ROOT, mountinfo=MOUNTINFO):
    """Require the exact RO SquashFS mount, with no overriding nested mounts."""
    lower_root = Path(lower_root)
    original = lower_root / 'usr/lib/unifi/lib/ace.jar'
    if lower_root.resolve(strict=True) != lower_root.absolute() or original.resolve(strict=True) != original.absolute():
        raise RuntimeError('Original firmware path contains a symlink')
    if not stat.S_ISREG(original.lstat().st_mode):
        raise RuntimeError('Original controller is not a regular file')
    matches = []
    for line in Path(mountinfo).read_text().splitlines():
        before, separator, after = line.partition(' - ')
        left, right = before.split(), after.split()
        if not separator or len(left) < 6 or len(right) < 3:
            raise RuntimeError('Malformed mount information')
        point = Path(mount_path(left[4]))
        if point == original or point in original.parents:
            matches.append((len(point.parts), point, left, right))
    if not matches:
        raise RuntimeError('Original firmware mount is missing')
    _, point, left, right = max(matches, key=lambda item: item[0])
    if sum(item[1] == point for item in matches) != 1:
        raise RuntimeError('Original firmware mount is ambiguous')
    if (point != lower_root or left[3] != '/' or right[0] != 'squashfs'
            or mount_path(right[1]) != '/dev/vda'
            or 'ro' not in left[5].split(',') or 'rw' in left[5].split(',')
            or 'ro' not in right[2].split(',') or 'rw' in right[2].split(',')):
        raise RuntimeError('Original controller requires the read-only firmware SquashFS mount')
    if original.stat().st_dev != os.makedev(*map(int, left[2].split(':'))):
        raise RuntimeError('Original controller does not belong to the firmware mount')
    if sha256(original) != SOURCE_SHA256:
        raise RuntimeError('Read-only original controller SHA256 mismatch')
    return original


def install_controller(payload, source=SOURCE, lower_root=LOWER_ROOT, mountinfo=MOUNTINFO):
    payload, source = Path(payload), Path(source)
    report = json.loads((payload / 'controller.json').read_text())
    if report.get('source_sha256') != SOURCE_SHA256 or any(
            not isinstance(report.get(key), str) or not re.fullmatch('[0-9a-f]{64}', report[key])
            for key in ('result_sha256', 'nested_result_sha256')):
        raise RuntimeError('Unsupported controller adaptation report')
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or source.resolve(strict=True) != source.absolute():
        raise RuntimeError('Installed controller path must be a regular file without symlinks')
    current = sha256(source)
    if current == report['result_sha256']:
        return 'already-installed'
    if current == SOURCE_SHA256:
        original = source
        action = 'installed'
    elif current == PREVIOUS_SHA256:
        original = readonly_original(lower_root, mountinfo)
        action = 'migrated-known-controller'
    else:
        raise RuntimeError('Unsupported installed controller; update requires a new adaptation')
    with tempfile.TemporaryDirectory(prefix='.udm-virtual-', dir=source.parent) as directory:
        result = Path(directory) / 'ace.jar'
        install(original, result, payload / 'internal-dependencies.virtual.jar',
                report['nested_result_sha256'], report['result_sha256'])
        os.chown(result, metadata.st_uid, metadata.st_gid)
        os.chmod(result, stat.S_IMODE(metadata.st_mode))
        os.utime(result, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        with result.open('rb') as stream:
            os.fsync(stream.fileno())
        if sha256(source) != current:
            raise RuntimeError('Installed controller changed during adaptation')
        os.replace(result, source)
        directory_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return action


def main():
    if os.geteuid() != 0 or not Path('/run/udm-virtual/ready').is_file():
        raise RuntimeError('Virtual HAL must validate this guest first')
    payload = Path(__file__).resolve().parent
    action = install_controller(payload)
    print('UDM_VIRTUAL_CONTROLLER_READY: ' + action, flush=True)


if __name__ == '__main__':
    main()
