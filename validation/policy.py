"""Explicit IPv4 packet-test policy, separate from UniFi's factory setup policy."""
from copy import deepcopy


def test_policy(factory):
    state = deepcopy(factory)
    groups = state['firewall/filter']
    matches = [group for group in groups if group['config']['name'] == 'FORWARD']
    if len(matches) != 1:
        raise ValueError('Expected exactly one original FORWARD configuration')
    group = matches[0]
    group['config']['policy'] = 'DROP'
    group['rules'] = [
        {'target': 'DROP', 'connectionState': ['invalid'], 'ipVersion': 'v4only'},
        {'target': 'ACCEPT', 'connectionState': ['established', 'related'], 'ipVersion': 'v4only'},
    ]
    for wan in ('eth8', 'eth12'):
        group['rules'].append({'target': 'ACCEPT', 'inInterface': {'id': 'br0'},
                               'outInterface': {'id': wan}, 'source': {'address': '192.168.1.0/24'},
                               'ipVersion': 'v4only'})
    return state
