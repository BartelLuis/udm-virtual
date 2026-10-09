"""Build a version-guarded adaptation using only files from the user's firmware."""
import json
from pathlib import Path
import shutil
import subprocess

from .network import generate_board, transform_state
from .patch_cpss import patch
from .patch_controller import patch as patch_controller
from .controller_flat import build_metadata
from validation.policy import test_policy

BASE = Path(__file__).resolve().parent
FIRMWARE_SHA256 = '31c8607480519ff164f1eacd4a8c021202afe99914ff56077df32c2d235b1734'


def build_payload(squashfs, output, firmware_sha256):
    if firmware_sha256 != FIRMWARE_SHA256:
        raise ValueError('Virtual profile supports only the analyzed UDMEA4C 5.1.33 firmware SHA256')
    if shutil.which('unsquashfs') is None:
        raise ValueError('Virtual profile needs unsquashfs (squashfs-tools)')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)

    def read(path):
        result = subprocess.run(['unsquashfs', '-cat', str(squashfs), path],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout

    original = output / 'ubios-udapi-server.original'
    original.write_bytes(read('usr/bin/ubios-udapi-server'))
    report = patch(original, output / 'ubios-udapi-server.virtual')
    controller_source = output / 'ace.original.jar'
    with controller_source.open('xb') as stream:
        subprocess.run(['unsquashfs', '-processors', '1', '-cat', str(squashfs),
                        'usr/lib/unifi/lib/ace.jar'], check=True, stdout=stream, stderr=subprocess.PIPE)
    controller = patch_controller(controller_source, output / 'ace.virtual.jar',
                                  output / 'internal-dependencies.virtual.jar')
    controller['flat'] = build_metadata(output / 'ace.virtual.jar', controller)
    (output / 'controller.json').write_text(json.dumps(controller, indent=2) + '\n')
    report['controller'] = controller
    unit = read('lib/systemd/system/unifi.service').decode('utf-8')
    start = unit.index('\nExecStart=/usr/bin/java ')
    end = unit.index('\nExecStartPost=', start)
    invocation = unit[start + 1:end].replace('ExecStart=/usr/bin/java ',
                                           'ExecStart=/usr/lib/udm-virtual/java-tcg.sh ', 1)
    (output / 'unifi-tcg.conf').write_text(
        '[Service]\nEnvironment=UDM_UNIFI_LAUNCH=flat\n'
        'ExecStartPre=+/usr/bin/python3 /usr/lib/udm-virtual/controller_flat.py prepare\n'
        'ExecStart=\n' + invocation + '\n')
    config = 'usr/share/ubios-udapi-server/'
    board = json.loads(read(config + 'config-board/udm-beast-ea4c.json'))
    (output / 'virtual-board.json').write_text(json.dumps(generate_board(board), indent=2) + '\n')
    for suffix in ('default', 'fallback'):
        state = json.loads(read(config + 'udm-beast-ea4c.' + suffix))
        (output / ('virtual.' + suffix)).write_text(json.dumps(transform_state(state), indent=2) + '\n')
    factory = json.loads((output / 'virtual.default').read_text())
    (output / 'validation.default').write_text(json.dumps(test_policy(factory), indent=2) + '\n')
    for name in ('hal_guest.py', 'hal_eeprom.py', 'boot.sh', 'patch_controller.py', 'controller_guest.py',
                 'controller_flat.py', 'late_boot.py',
                 'java-tcg.sh', 'freeradius_dh.py', 'freeradius_cert.py',
                 'freeradius-cert.service', 'freeradius-cert.conf'):
        (output / name).write_bytes((BASE / name).read_bytes().replace(b'\r\n', b'\n'))
    names = ('hal_guest.py', 'hal_eeprom.py', 'boot.sh', 'ubios-udapi-server.virtual',
             'virtual-board.json', 'virtual.default', 'virtual.fallback', 'validation.default',
             'patch_controller.py', 'controller_guest.py', 'controller_flat.py', 'late_boot.py', 'controller.json', 'internal-dependencies.virtual.jar',
             'java-tcg.sh', 'unifi-tcg.conf', 'freeradius_dh.py', 'freeradius_cert.py',
             'freeradius-cert.service', 'freeradius-cert.conf')
    entries = {'udm-virtual/' + name: (0o755 if name in ('boot.sh', 'ubios-udapi-server.virtual', 'java-tcg.sh') else 0o644,
                                     (output / name).read_bytes()) for name in names}
    return entries, report
