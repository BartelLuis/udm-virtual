from copy import deepcopy
import unittest

from virtualization import uxg_network as network


def board_fixture():
    return {
        'identification': {'id': 'uxg-ent', 'arch': 'cn9670', 'board-id': 'ea3e',
                           'family-short': 'UXG', 'model-short': 'UXG Enterprise'},
        'capabilities': {'max-networks': 500, 'interfaces': [{'udapi-type': 'switch'}]},
        'wan_ports': [{'id': 'wan0', 'interface': 'eth0'}, {'id': 'wan1', 'interface': 'eth4'}],
        'switches': [{'id': 'switch0', 'builtin-vlan': 0, 'max-vlan': 4094, 'driver': 'native',
                      'cpu-ports': [{'interface': {'id': 'switch0'}, 'cpu-port': 6}],
                      'edge-ports': [{'interface': {'id': 'eth{}'.format(i)}, 'edge-port': i,
                                     'cpu-port': 6} for i in range(6)]}],
        'interfaces': [{'identification': {'id': 'lo', 'init-type': 'ethernet',
                                           'udapi-type': 'loopback'}}] + [
            {'identification': {'id': 'eth{}'.format(i), 'init-type': 'ethernet',
                                'udapi-type': 'ethernet', 'media': 'SFP28',
                                'settings': {'tx-queue-length': '10000'},
                                **({'alias': network.PHYSICAL_ALIASES['eth{}'.format(i)]}
                                   if 'eth{}'.format(i) in network.PHYSICAL_ALIASES else {})}}
            for i in range(6)] + [
                {'identification': {'id': 'switch0', 'init-type': 'bridge', 'udapi-type': 'switch'},
                 'bridge': {'interfaces': [{'id': 'eth1'}]}}],
        'bluetooth': {'service-uuid-factory-default': 'original'},
        'descriptors': {'storage': [{'path': '/data'}], 'temperatures': [{'path': '/sys/physical/temp'}],
                        'fan-speeds': [{'pwm-path': '/sys/physical/pwm'}],
                        'cpu': [{'path': '/sys/physical/cpu'}],
                        'sfp-outlets': [{'id': 'eth2', 'gpio': '507'}]},
    }


def state_fixture():
    return {
        'version': 48, 'versionFormat': 'v2', 'system': {'hostname': 'UXG-Enterprise'},
        'interfaces': [{'identification': {'id': 'eth{}'.format(i), 'type': 'ethernet'},
                        'status': {'enabled': True},
                        **({'addresses': [{'type': 'dynamic', 'origin': 'dhcp'}]} if i in (0, 4) else {}),
                        **({'ethernet': {'sfp': {'fec': 'none' if i < 4 else 'auto'}}} if i >= 2 else {})}
                       for i in range(6)] + [
            {'identification': {'id': 'switch0', 'type': 'switch'},
             'switch': {'vlanEnabled': True, 'ports': [
                 {'interface': {'id': 'eth{}'.format(i)}, 'pvid': None if i in (0, 4) else 1,
                  'enabled': i not in (0, 4)} for i in range(6)]}},
            {'identification': {'id': 'switch0.1', 'type': 'vlan'},
             'vlan': {'id': 1, 'interface': {'id': 'switch0'}}},
            {'identification': {'id': 'br0', 'type': 'bridge'},
             'bridge': {'id': 0, 'interfaces': [{'id': 'switch0.1'}]},
             'addresses': [{'cidr': '192.168.1.1/24'}]},
        ],
        'services': {'unifiNetwork': {'enabled': False}, 'dhcpServers': [{'enabled': True}],
                     'bleHTTPTransport': {'enabled': True}, 'wanFailover': {'enabled': True}},
        'firewall/filter': [{'config': {'name': 'FORWARD', 'policy': 'ACCEPT'},
                             'rules': [{'target': 'REJECT', 'inInterface': {'id': 'eth0'}}]}],
        'firewall/nat': [{'target': 'MASQUERADE', 'outInterface': {'id': 'eth0'}}],
        'versionDetail': {'interfaces': 43},
    }


class UxgNetworkTests(unittest.TestCase):
    def test_native_switch_numbering_and_bootstrap_are_preserved(self):
        original = board_fixture()
        snapshot = deepcopy(original)
        board = network.generate_board(original)
        self.assertEqual(original, snapshot)
        self.assertEqual(board['identification'], original['identification'])
        self.assertEqual(board['switches'], original['switches'])
        self.assertEqual(board['wan_ports'], original['wan_ports'])
        self.assertEqual(board['interfaces'][-1], original['interfaces'][-1])
        for item in board['interfaces'][1:-1]:
            self.assertEqual(item['identification']['media'], 'GE')
            self.assertNotIn('alias', item['identification'])
            self.assertEqual(item['identification']['settings'], {'tx-queue-length': '10000'})
        self.assertEqual(board['capabilities']['hardware-offload-mode'], 'not_supported')
        for name in network.HARDWARE_DESCRIPTORS:
            self.assertEqual(board['descriptors'][name], [])
        self.assertEqual(board['descriptors']['storage'], original['descriptors']['storage'])
        self.assertEqual(board['bluetooth'], original['bluetooth'])

    def test_sfp_removal_keeps_vlan_lan_wan_and_all_service_policies(self):
        original = state_fixture()
        original['interfaces'][2]['ethernet']['flowControl'] = True
        snapshot = deepcopy(original)
        state = network.transform_state(original)
        self.assertEqual(original, snapshot)
        for key in original.keys() - {'interfaces'}:
            self.assertEqual(state[key], original[key])
        self.assertEqual(state['interfaces'][6:], original['interfaces'][6:])
        for index in (0, 4):
            self.assertEqual(state['interfaces'][index]['addresses'], original['interfaces'][index]['addresses'])
        for item in state['interfaces']:
            self.assertNotIn('sfp', item.get('ethernet', {}))
        self.assertEqual(state['interfaces'][2]['ethernet'], {'flowControl': True})
        self.assertNotIn('ethernet', state['interfaces'][4])
        state['services']['unifiNetwork']['enabled'] = True
        self.assertFalse(original['services']['unifiNetwork']['enabled'])

    def test_wrong_board_driver_cpu_port_or_alias_is_rejected(self):
        mutations = (
            lambda b: b['identification'].update({'board-id': 'ea4c'}),
            lambda b: b['identification'].update({'arch': 'cn10k'}),
            lambda b: b['switches'][0].update({'driver': 'cpss'}),
            lambda b: b['switches'][0]['cpu-ports'][0].update({'cpu-port': 10}),
            lambda b: b['switches'][0]['edge-ports'][0].update({'edge-port': 5}),
            lambda b: b['interfaces'][1]['identification'].update({'alias': 'eth3'}),
            lambda b: b['wan_ports'][0].update({'interface': 'eth1'}),
        )
        for mutate in mutations:
            board = board_fixture()
            mutate(board)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                network.generate_board(board)

    def test_wrong_vlan_topology_and_wan_bridge_membership_are_rejected(self):
        mutations = (
            lambda s: s['interfaces'][6]['switch']['ports'][0].update({'enabled': True, 'pvid': 1}),
            lambda s: s['interfaces'][7]['vlan'].update({'id': 2}),
            lambda s: s['interfaces'][8]['bridge'].update({'interfaces': [{'id': 'eth0'}]}),
            lambda s: s['system'].update({'hostname': 'UDM-Beast'}),
        )
        for mutate in mutations:
            state = state_fixture()
            mutate(state)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                network.transform_state(state)

    def test_missing_duplicate_or_extra_nic_is_rejected(self):
        for fixture, transform in ((board_fixture, network.generate_board), (state_fixture, network.transform_state)):
            for mode in ('missing', 'duplicate', 'extra'):
                document = fixture()
                if mode == 'missing':
                    document['interfaces'] = [i for i in document['interfaces'] if i['identification']['id'] != 'eth4']
                else:
                    item = deepcopy(document['interfaces'][0])
                    if mode == 'extra':
                        item['identification']['id'] = 'eth6'
                    document['interfaces'].append(item)
                with self.subTest(transform=transform.__name__, mode=mode), self.assertRaises(ValueError):
                    transform(document)

    def test_pure_transformations_are_idempotent(self):
        board = network.generate_board(board_fixture())
        state = network.transform_state(state_fixture())
        self.assertEqual(network.generate_board(board), board)
        self.assertEqual(network.transform_state(state), state)

    def test_release_guards_reject_foreign_firmware_and_edited_source_documents(self):
        with self.assertRaisesRegex(ValueError, 'firmware SHA256'):
            network.generate_profile(board_fixture(), state_fixture(), state_fixture(), firmware_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'JSON hash mismatch'):
            network.generate_profile(board_fixture(), state_fixture(), state_fixture(),
                                     firmware_sha256=network.FIRMWARE_SHA256)


if __name__ == '__main__':
    unittest.main()
