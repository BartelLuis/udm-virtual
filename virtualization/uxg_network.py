"""UXG Enterprise 5.1.26 network profile for six native VirtIO interfaces.

This model already uses UDAPI's native Linux switch driver. Keep switch0,
switch0.1, br0 and all original edge-port numbers so external-controller
provisioning can use the original model. No controller or authentication patch
is performed. The build must independently verify the supplied firmware digest.
"""
from copy import deepcopy
import hashlib
import json


FIRMWARE_SHA256 = 'bedeac0a67329ec135025da352e490844be5aafd91a9c303ceba8fd8e424b4f0'
BOARD_FILENAME = 'uxgent-ea3e.json'
DEFAULT_FILENAME = 'uxg-ent-ea3e.default'
FALLBACK_FILENAME = 'uxg-ent-ea3e.fallback'
NIC_COUNT = 6
NATIVE_INTERFACES = tuple('eth{}'.format(index) for index in range(NIC_COUNT))
WAN_INTERFACES = ('eth0', 'eth4')
LAN_INTERFACES = ('eth1', 'eth2', 'eth3', 'eth5')
PHYSICAL_ALIASES = {'eth0': 'eth4', 'eth1': 'eth5', 'eth4': 'eth0', 'eth5': 'eth1'}
HARDWARE_DESCRIPTORS = ('temperatures', 'fan-speeds', 'cpu', 'sfp-outlets')
SOURCE_JSON_SHA256 = {
    BOARD_FILENAME: 'b7af0d09a17f6360be7c910dc297877014a8b9198a9e4b4dc4a8fdac7dffc272',
    DEFAULT_FILENAME: '3038b5e2f61806edd99183f3d3ddd4154686b1a72a098d69b65b1fa81241d768',
    FALLBACK_FILENAME: 'a91249622dc4990a6579fbdd7b18efd18da69f2426a4a1a2ed60a3216834ff0e',
}


def canonical_sha256(document):
    """Hash parsed JSON independently of its original whitespace/key ordering."""
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode('utf-8')).hexdigest()


def _interfaces(document, extra):
    if not isinstance(document, dict) or not isinstance(document.get('interfaces'), list):
        raise ValueError('Expected an EA3E interface list')
    result = {}
    for item in document['interfaces']:
        if not isinstance(item, dict) or not isinstance(item.get('identification'), dict):
            raise ValueError('Expected interface identification')
        name = item['identification'].get('id')
        if not isinstance(name, str) or name in result:
            raise ValueError('Invalid or duplicate interface identifier')
        result[name] = item
    if set(result) != set(NATIVE_INTERFACES).union(extra):
        raise ValueError('EA3E requires exactly eth0 through eth5 and its original native topology')
    return result


def generate_board(original):
    """Copy the EA3E native board, removing only absent physical-port features."""
    interfaces = _interfaces(original, ('lo', 'switch0'))
    identity = original.get('identification', {})
    if any(identity.get(key) != value for key, value in {
            'id': 'uxg-ent', 'arch': 'cn9670', 'board-id': 'ea3e',
            'family-short': 'UXG', 'model-short': 'UXG Enterprise'}.items()):
        raise ValueError('Only the original EA3E UXG Enterprise board is supported')
    expected_switch = {
        'id': 'switch0', 'builtin-vlan': 0, 'max-vlan': 4094, 'driver': 'native',
        'cpu-ports': [{'interface': {'id': 'switch0'}, 'cpu-port': 6}],
        'edge-ports': [{'interface': {'id': name}, 'edge-port': index, 'cpu-port': 6}
                       for index, name in enumerate(NATIVE_INTERFACES)],
    }
    if original.get('switches') != [expected_switch]:
        raise ValueError('Expected the original EA3E six-port native switch and CPU port 6')
    if original.get('wan_ports') != [{'id': 'wan0', 'interface': 'eth0'},
                                     {'id': 'wan1', 'interface': 'eth4'}]:
        raise ValueError('Expected original EA3E WAN ports eth0 and eth4')
    if (interfaces['switch0']['identification'] != {
            'init-type': 'bridge', 'udapi-type': 'switch', 'id': 'switch0'}
            or interfaces['switch0'].get('bridge') != {'interfaces': [{'id': 'eth1'}]}):
        raise ValueError('Expected the original native switch0 bootstrap bridge')
    for name in NATIVE_INTERFACES:
        identification = interfaces[name]['identification']
        if identification.get('init-type') != 'ethernet' or identification.get('udapi-type') != 'ethernet':
            raise ValueError('EA3E ports must remain native Ethernet interfaces')
        if 'alias' in identification and identification['alias'] != PHYSICAL_ALIASES.get(name):
            raise ValueError('Unexpected EA3E physical port alias')
        if 'link-manager' in identification:
            raise ValueError('Unexpected physical link manager')
    if not isinstance(original.get('capabilities'), dict) or not isinstance(original.get('descriptors'), dict):
        raise ValueError('Expected original board capabilities and descriptors')

    board = deepcopy(original)
    board['capabilities']['hardware-offload-mode'] = 'not_supported'
    for item in board['interfaces']:
        if item['identification']['id'] in NATIVE_INTERFACES:
            item['identification'].pop('alias', None)
            # VirtIO has no pluggable SFP/PHY. Keep queue settings, native IDs
            # and switch membership; GE selects ordinary Ethernet handling.
            item['identification']['media'] = 'GE'
    for kind in HARDWARE_DESCRIPTORS:
        board['descriptors'][kind] = []
    return board


def transform_state(original):
    """Copy an original default/fallback, omitting physical SFP FEC settings.

    All topology, addressing, DHCP, WAN, firewall, NAT, adoption and setup
    settings are preserved. This is not a translator for arbitrary subsequent
    controller configuration.
    """
    interfaces = _interfaces(original, ('switch0', 'switch0.1', 'br0'))
    if (original.get('version') != 48 or original.get('versionFormat') != 'v2'
            or original.get('system', {}).get('hostname') != 'UXG-Enterprise'):
        raise ValueError('Expected an original EA3E version-48 default/fallback')
    expected_ports = [{'interface': {'id': name}, 'pvid': None if name in WAN_INTERFACES else 1,
                       'enabled': name not in WAN_INTERFACES} for name in NATIVE_INTERFACES]
    if interfaces['switch0'].get('switch') != {'vlanEnabled': True, 'ports': expected_ports}:
        raise ValueError('Expected original EA3E switch VLAN membership and WAN separation')
    if interfaces['switch0.1'].get('vlan') != {'id': 1, 'interface': {'id': 'switch0'}}:
        raise ValueError('Expected original switch0.1 VLAN')
    if interfaces['br0'].get('bridge') != {'id': 0, 'interfaces': [{'id': 'switch0.1'}]}:
        raise ValueError('Expected original br0 over switch0.1')
    state = deepcopy(original)
    for item in state['interfaces']:
        name = item['identification']['id']
        if name in NATIVE_INTERFACES and 'ethernet' in item:
            if not isinstance(item['ethernet'], dict):
                raise ValueError('Expected Ethernet settings object')
            item['ethernet'].pop('sfp', None)
            if not item['ethernet']:
                del item['ethernet']
    return state


def generate_profile(board, default, fallback, *, firmware_sha256):
    """Return board/default/fallback/report after exact release-content guards.

    The caller verifies the actual firmware file first and supplies its SHA256.
    This function additionally verifies all three original parsed JSON hashes;
    it rejects already modified profiles and other firmware revisions.
    """
    if firmware_sha256 != FIRMWARE_SHA256:
        raise ValueError('Unsupported UXG Enterprise firmware SHA256')
    inputs = {BOARD_FILENAME: board, DEFAULT_FILENAME: default, FALLBACK_FILENAME: fallback}
    input_hashes = {name: canonical_sha256(document) for name, document in inputs.items()}
    if input_hashes != SOURCE_JSON_SHA256:
        raise ValueError('UXG Enterprise source JSON hash mismatch')
    result = {'board': generate_board(board), 'default': transform_state(default),
              'fallback': transform_state(fallback)}
    result['report'] = {
        'profile': 'uxg-enterprise-native-six-port', 'firmware_sha256': firmware_sha256,
        'source_json_canonical_sha256': input_hashes,
        'output_json_canonical_sha256': {name: canonical_sha256(result[key]) for name, key in (
            (BOARD_FILENAME, 'board'), (DEFAULT_FILENAME, 'default'), (FALLBACK_FILENAME, 'fallback'))},
        'nic_count': NIC_COUNT, 'wan_interfaces': list(WAN_INTERFACES),
        'lan_interfaces': list(LAN_INTERFACES), 'switch_driver': 'native',
        'topology_preserved': ['switch0', 'switch0.1', 'br0'],
        'removed_physical_aliases': PHYSICAL_ALIASES.copy(),
        'omitted_hardware_descriptors': {kind: len(board['descriptors'].get(kind, []))
                                        for kind in HARDWARE_DESCRIPTORS},
        'sfp_settings_removed_from': ['eth2', 'eth3', 'eth4', 'eth5'],
        'services_firewall_nat_unchanged': True,
        'runtime_validation': 'Not performed by this static profile transformation',
    }
    return result
