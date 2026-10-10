#!/usr/bin/python3
"""Install only the exact UXGENT adaptation in its original QEMU guest."""
import hashlib
import json
from pathlib import Path
import os
import tempfile

if __package__:
    from .hal_guest import require_guest, RUNTIME
else:
    from hal_guest import require_guest, RUNTIME

SOURCE_SHA256 = '7fa7f011c8b1dc03448c0e42b15af87feb775279c657fc7346ea3b3c43227d91'
IOMMU_SHA256 = '1d8cbd0aedb86ae326423b41aaa002790bcd203f7dc6e6069db4c7aa8fda304b'
IOMMU_REPLACEMENT = b'#!/bin/sh\n# VirtIO ports have no physical Marvell IOMMU bypass.\necho UXG_VIRTUAL_IOMMU_HOOK_SKIPPED\n'
HARDWARE_UNITS = {
    'usd.service': '8294abecb7e47d294ccce300bdd3bfcbfb6567083e5608e5d4c430f6506c6364',
    'create-sflash.service': '5854a7311a7f9423743543669a4b6c8bfba43e8360ffd094400e9c18a6f34ae1',
    # Generic first-boot presets compete with UXG's own Node HTTP/HTTPS server.
    'nginx.service': '043f6de8eda511a8d365536e4311eb2d1d43603faa369ace2cc522d44b4673f8',
    'nginx-debug.service': 'f4f32cc77a15cdbabc1ed217e5d0e96dc243c397e09bc48dafdf9f91d63faac0',
    'lighttpd.service': 'f064cf46d1f646532b0f34f88460da6925d4319de348cc67be3b016bd2ea456d',
}


def atomic_write(path, content, mode):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Refusing non-regular guest target: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.uxg-virtual-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def configure(root=Path('/'), payload=None):
    require_guest('UXGENT')
    if (RUNTIME / 'ready').is_symlink() or not (RUNTIME / 'ready').is_file():
        raise ValueError('Original virtual HAL must be initialized first')
    root = Path(root)
    mounts = [line.split() for line in (root / 'proc/mounts').read_text().splitlines()]
    for destination, filesystem, option in (('/', 'overlay', 'rw'), ('/mnt/.rofs', 'squashfs', 'ro'),
                                             ('/mnt/.rwfs', 'ext4', 'rw')):
        if not any(len(row) >= 4 and row[1:3] == [destination, filesystem] and option in row[3].split(',')
                   for row in mounts):
            raise ValueError('Required virtual storage mount is missing: ' + destination)
    if not all((root / name).is_dir() for name in ('data', 'persistent')):
        raise ValueError('Virtual persistent data directories are missing')
    payload = Path(payload) if payload else root / 'usr/lib/udm-virtual'
    report = json.loads((payload / 'uxg-adaptation.json').read_text())
    binary = (payload / 'ubios-udapi-server.virtual').read_bytes()
    adapted = hashlib.sha256(binary).hexdigest()
    if report['source_sha256'] != SOURCE_SHA256 or report['result_sha256'] != adapted:
        raise ValueError('Unsupported UXG adaptation payload')
    target = root / 'usr/bin/ubios-udapi-server'
    if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() not in (SOURCE_SHA256, adapted):
        raise ValueError('Unsupported installed UXG network daemon')
    hook = root / 'usr/lib/ubnt/hooks/system/bootup-top/01-bypass_eth_iommu.sh'
    content = hook.read_bytes()
    if hook.is_symlink() or (content != IOMMU_REPLACEMENT and hashlib.sha256(content).hexdigest() != IOMMU_SHA256):
        raise ValueError('Unsupported physical IOMMU boot hook')
    # The overlay already supplies persistence. The hardware storage manager
    # waits for physical partitions before local-fs.target; the flash creator
    # exposes SoC MMIO ioctls that QEMU cannot implement. Keep usdbd/uhwd and
    # all gateway services intact; do not synthesize storage-ready state.
    for name, expected in HARDWARE_UNITS.items():
        unit = root / 'lib/systemd/system' / name
        if unit.is_symlink() or hashlib.sha256(unit.read_bytes()).hexdigest() != expected:
            raise ValueError('Unsupported physical service: ' + name)
        mask = root / 'etc/systemd/system' / name
        if ((mask.exists() and not mask.is_symlink()) or
                (mask.is_symlink() and os.readlink(mask) != '/dev/null')):
            raise ValueError('Refusing to overwrite custom unit: ' + name)
    atomic_write(target, binary, 0o755)
    config = root / 'usr/share/ubios-udapi-server'
    for source, destination in (
        ('virtual-board.json', 'config-board/uxgent-ea3e.json'),
        ('virtual.default', 'uxg-ent-ea3e.default'),
        ('virtual.fallback', 'uxg-ent-ea3e.fallback'),
    ):
        atomic_write(config / destination, (payload / source).read_bytes(), 0o644)
    state = root / 'data/udapi-config/ubios-udapi-server/ubios-udapi-server.state'
    if not state.exists() and not state.is_symlink():
        atomic_write(state, (payload / 'virtual.default').read_bytes(), 0o600)
    atomic_write(hook, IOMMU_REPLACEMENT, 0o755)
    for name in HARDWARE_UNITS:
        mask = root / 'etc/systemd/system' / name
        mask.parent.mkdir(parents=True, exist_ok=True)
        if not mask.is_symlink():
            mask.symlink_to('/dev/null')


if __name__ == '__main__':
    configure()
    print('UXG_VIRTUAL_GUEST_READY')
