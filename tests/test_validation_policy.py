import unittest
from copy import deepcopy
from validation.policy import test_policy


class ValidationPolicyTests(unittest.TestCase):
    def test_explicit_policy_preserves_factory_input_nat_and_other_chains(self):
        original = {'firewall/filter': [
            {'config': {'name': 'INPUT'}, 'rules': [{'target': 'DROP'}]},
            {'config': {'name': 'FORWARD', 'policy': 'ACCEPT'}, 'rules': [{'target': 'REJECT'}]},
        ], 'firewall/nat': [{'target': 'MASQUERADE'}], 'services': {'dhcpServers': [{'enabled': True}]}}
        before = deepcopy(original)
        actual = test_policy(original)
        self.assertEqual(original, before)
        self.assertEqual(actual['firewall/nat'], original['firewall/nat'])
        self.assertEqual(actual['services'], original['services'])
        self.assertEqual(actual['firewall/filter'][0], original['firewall/filter'][0])
        forward = actual['firewall/filter'][1]
        self.assertEqual(forward['config']['policy'], 'DROP')
        self.assertEqual(forward['rules'][1]['connectionState'], ['established', 'related'])
        self.assertEqual([r['outInterface']['id'] for r in forward['rules'][2:]], ['eth8', 'eth12'])
        self.assertTrue(all(r['inInterface']['id'] == 'br0' for r in forward['rules'][2:]))

    def test_missing_forward_is_rejected(self):
        with self.assertRaises(ValueError):
            test_policy({'firewall/filter': []})
