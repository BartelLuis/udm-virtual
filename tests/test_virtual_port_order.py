from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from virtualization import hal_guest


def interfaces(rotated=True):
    return [{'name': f'eth{(index + 6) % 14 if rotated else index}',
             'mac': f'02:55:44:4d:00:{index:02x}', 'driver': 'virtio_net',
             'up': False, 'addresses': [], 'master': None}
            for index in range(14)]


class InterfaceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='udm-net-snapshot-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rows = []
        self.drivers = {}
        for item in interfaces(rotated=False):
            self.add_interface(item['name'], item['mac'], item['mac'], 'virtio_net')

    def add_interface(self, name, sysfs_address, ip_address, driver, link_type='ether'):
        entry = self.directory / name
        entry.mkdir()
        (entry / 'address').write_text(sysfs_address + '\n')
        (entry / 'flags').write_text('0x1002\n')
        self.drivers[name] = driver
        self.rows.append({'ifname': name, 'address': ip_address, 'flags': ['BROADCAST'],
                          'addr_info': [], 'link_type': link_type})

    def snapshot(self):
        def resolve_driver(path, **kwargs):
            self.assertEqual(path.parts[-2:], ('device', 'driver'))
            return Path('/drivers') / self.drivers[path.parent.parent.name]
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(self.rows))
        with patch.object(hal_guest.subprocess, 'run', return_value=result), \
                patch.object(Path, 'resolve', autospec=True, side_effect=resolve_driver):
            return hal_guest.interface_snapshot(self.directory)

    def test_original_kernel_tunnel_addresses_do_not_fail_ethernet_snapshot(self):
        for name, link_type, address, raw in (
                ('ip_vti0', 'ipip', '0.0.0.0', '00:00:00:00'),
                ('sit0', 'sit', '0.0.0.0', '00:00:00:00'),
                ('ip6_vti0', 'tunnel6', '::', ':'.join(['00'] * 16)),
                ('ip6tnl0', 'tunnel6', '::', ':'.join(['00'] * 16)),
                ('ip6gre0', 'gre6', '::', ':'.join(['00'] * 16))):
            self.add_interface(name, raw, address, 'driver', link_type)
        snapshot = self.snapshot()
        self.assertEqual(len(snapshot), 19)
        ordered = hal_guest.interface_order(snapshot)
        self.assertEqual([entry['name'] for entry in ordered], [f'eth{i}' for i in range(14)])
        self.assertTrue(all(set(entry) == {'name', 'driver'} for entry in snapshot
                            if entry['driver'] != 'virtio_net'))

    def test_virtio_mac_mismatch_still_fails_and_names_the_interface(self):
        self.rows[8]['address'] = '02:55:44:4d:00:ff'
        with self.assertRaisesRegex(ValueError, 'MAC changed.*eth8.*sysfs=.*ip='):
            self.snapshot()

    def test_foreign_interface_names_still_prevent_port_collision(self):
        (self.directory / 'eth0').rename(self.directory / 'ens99')
        self.drivers['ens99'] = self.drivers.pop('eth0')
        self.rows[0]['ifname'] = 'ens99'
        self.add_interface('eth0', '00:00:00:00', '0.0.0.0', 'driver', 'ipip')
        with self.assertRaisesRegex(ValueError, 'non-VirtIO interface occupies'):
            hal_guest.interface_order(self.snapshot())


class PortOrderTests(unittest.TestCase):
    def invoke(self, entries, fail_at=(), options=None, nics=14, model="UDMEA4C"):
        self.live = {entry['name']: deepcopy(entry) for entry in entries}
        self.calls = []

        def read():
            return deepcopy(list(self.live.values()))

        def run(*args):
            self.calls.append(args)
            if len(self.calls) in fail_at:
                raise subprocess.CalledProcessError(1, args)
            self.assertEqual(args[:4], ('/sbin/ip', 'link', 'set', 'dev'))
            self.assertEqual(args[5], 'name')
            source, destination = args[4], args[6]
            if source not in self.live or destination in self.live:
                raise subprocess.CalledProcessError(1, args)
            item = self.live.pop(source)
            item['name'] = destination
            self.live[destination] = item

        with patch.object(hal_guest, 'require_guest', return_value=options if options is not None else
                          ['udm.mode=systemd', f'udm.nics={nics}']), \
                patch.object(Path, 'read_text', return_value='init\n'), \
                patch.object(Path, 'exists', return_value=False):
            return hal_guest.normalize_virtual_interfaces(read=read, run=run, nics=nics, model=model)

    def test_uxg_six_ports_use_same_collision_safe_rename_and_rollback(self):
        ports = interfaces(rotated=False)[:6]
        for index, item in enumerate(ports):
            item['name'] = f'eth{(index + 2) % 6}'
        self.assertEqual(self.invoke(ports, nics=6, model="UXGENT"), '02:55:44:4d:00:00')
        self.assertEqual(len(self.calls), 12)
        for index in range(6):
            self.assertEqual(self.live[f'eth{index}']['mac'], f'02:55:44:4d:00:{index:02x}')
        with self.assertRaisesRegex(ValueError, 'rolled back; aborting boot'):
            self.invoke(ports, fail_at=(9,), nics=6, model="UXGENT")
        self.assertEqual(self.live, {item['name']: item for item in ports})

    def test_permuted_ports_are_named_by_mac_in_two_phases(self):
        self.assertEqual(self.invoke(interfaces()), '02:55:44:4d:00:00')
        self.assertEqual(len(self.calls), 28)
        self.assertEqual([call[-1] for call in self.calls[:14]], [f'udmvtmp{i}' for i in range(14)])
        self.assertEqual([call[-1] for call in self.calls[14:]], [f'eth{i}' for i in range(14)])
        for index in range(14):
            self.assertEqual(self.live[f'eth{index}']['mac'], f'02:55:44:4d:00:{index:02x}')

    def test_correctly_named_active_guest_is_not_modified(self):
        ports = interfaces(rotated=False)
        ports[0].update(up=True, addresses=[{'family': 'inet', 'local': '192.168.1.1'}])
        self.assertEqual(self.invoke(ports), '02:55:44:4d:00:00')
        self.assertEqual(self.calls, [])

    def test_missing_duplicate_and_noncontiguous_macs_rejected_before_moves(self):
        missing = interfaces()[:-1]
        duplicate = interfaces()
        duplicate[-1]['mac'] = duplicate[0]['mac']
        gap = interfaces()
        gap[-1]['mac'] = '02:55:44:4d:00:ff'
        for ports in (missing, duplicate, gap):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                self.invoke(ports)
            self.assertEqual(self.calls, [])

    def test_global_and_multicast_macs_are_rejected(self):
        for mac in ('00:55:44:4d:00:00', '03:55:44:4d:00:00'):
            ports = interfaces()
            ports[0]['mac'] = mac
            with self.subTest(mac=mac), self.assertRaisesRegex(ValueError, 'locally administered'):
                self.invoke(ports)
            self.assertEqual(self.calls, [])

    def test_up_ip_configured_and_enslaved_ports_rejected_before_moves(self):
        for state in ({'up': True}, {'addresses': [{'family': 'inet6', 'local': 'fe80::1'}]},
                      {'master': 'br0'}, {'addresses': None}):
            ports = interfaces()
            ports[8].update(state)
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, 'up or configured'):
                self.invoke(ports)
            self.assertEqual(self.calls, [])

    def test_required_and_temporary_name_collisions_refused(self):
        for name in ('eth0', 'udmvtmp0'):
            ports = interfaces()
            for entry in ports:
                if entry['name'] == name:
                    entry['name'] = 'ens4'
            ports.append({'name': name, 'mac': '00:01:02:03:04:05', 'driver': 'other'})
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'occup'):
                self.invoke(ports)
            self.assertEqual(self.calls, [])

    def test_each_phase_failure_rolls_back_and_still_aborts(self):
        for step in (5, 18):
            ports = interfaces()
            with self.subTest(step=step), self.assertRaisesRegex(ValueError, 'rolled back; aborting boot'):
                self.invoke(ports, fail_at=(step,))
            self.assertEqual(self.live, {item['name']: item for item in ports})

    def test_rollback_failure_is_reported_and_boot_aborts(self):
        with self.assertRaisesRegex(ValueError, 'rollback incomplete.*aborting boot'):
            self.invoke(interfaces(), fail_at=(18, 19))

    def test_explicit_single_fourteen_port_boot_flag_is_required(self):
        for options in ([], ['udm.nics=2'], ['udm.nics=14', 'udm.nics=14']):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'udm.nics=14'):
                self.invoke(interfaces(), options=options)
            self.assertEqual(self.calls, [])

    def test_guest_guard_runs_before_read_or_mutation(self):
        with patch.object(hal_guest, 'require_guest', side_effect=ValueError('not QEMU')):
            with self.assertRaisesRegex(ValueError, 'not QEMU'):
                hal_guest.normalize_virtual_interfaces(
                    read=lambda: self.fail('Must not read host interfaces'),
                    run=lambda *args: self.fail('Must not mutate host interfaces'))


if __name__ == '__main__':
    unittest.main()
