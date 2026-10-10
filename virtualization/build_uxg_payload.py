"""Build the exact UXG Enterprise 5.1.26 guest adaptation."""
import json
from pathlib import Path
import shutil
import subprocess

BASE = Path(__file__).resolve().parent
FIRMWARE_SHA256 = 'bedeac0a67329ec135025da352e490844be5aafd91a9c303ceba8fd8e424b4f0'


def build_payload(squashfs, output, firmware_sha256):
    if firmware_sha256 != FIRMWARE_SHA256:
        raise ValueError('UXG virtual profile requires the analyzed UXGENT 5.1.26 firmware SHA256')
    if shutil.which('unsquashfs') is None:
        raise ValueError('Virtual profile needs unsquashfs (squashfs-tools)')
    from .uxg_network import generate_profile
    from .patch_uxg import patch
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)

    def read(path):
        return subprocess.run(['unsquashfs', '-processors', '1', '-cat', str(squashfs), path],
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    original = output / 'ubios-udapi-server.original'
    original.write_bytes(read('usr/bin/ubios-udapi-server'))
    report = patch(original, output / 'ubios-udapi-server.virtual')
    config = 'usr/share/ubios-udapi-server/'
    board = json.loads(read(config + 'config-board/uxgent-ea3e.json'))
    default = json.loads(read(config + 'uxg-ent-ea3e.default'))
    fallback = json.loads(read(config + 'uxg-ent-ea3e.fallback'))
    network = generate_profile(board, default, fallback, firmware_sha256=firmware_sha256)
    for key, name in (('board', 'virtual-board.json'), ('default', 'virtual.default'), ('fallback', 'virtual.fallback')):
        (output / name).write_text(json.dumps(network[key], indent=2) + '\n')
    report['network'] = network['report']
    (output / 'uxg-adaptation.json').write_text(json.dumps(report, indent=2) + '\n')
    helpers = ('hal_guest.py', 'hal_eeprom.py', 'uxg_guest.py', 'dns_guest.py',
               'freeradius_dh.py', 'freeradius_cert.py', 'freeradius-cert.service', 'freeradius-cert.conf')
    for name in helpers:
        (output / name).write_bytes((BASE / name).read_bytes().replace(b'\r\n', b'\n'))
    (output / 'boot.sh').write_bytes((BASE / 'uxg_boot.sh').read_bytes().replace(b'\r\n', b'\n'))
    names = helpers + ('boot.sh', 'ubios-udapi-server.virtual', 'uxg-adaptation.json',
                       'virtual-board.json', 'virtual.default', 'virtual.fallback')
    entries = {'udm-virtual/' + name: (0o755 if name in ('boot.sh', 'ubios-udapi-server.virtual') else 0o644,
                                     (output / name).read_bytes()) for name in names}
    return entries, report
