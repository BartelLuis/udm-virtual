"""Linux/Bash integration tests using a temporary, simulated Proxmox host.

Run all cases in an isolated root test context, e.g. the existing WSL Debian:
  wsl -d Debian -u root -- python3 -m unittest discover -s tests -p test_proxmox.py -v
No actual qm/pvesm commands are run. Windows skips this Linux-only test module.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "proxmox-import.sh"
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_PVE'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'commands.jsonl').open('a') as out:
    out.write(json.dumps([name] + args) + '\n')
statepath = root / 'state.json'
state = json.loads(statepath.read_text()) if statepath.exists() else {'unused': {}, 'import_count': 0}
if name == 'pvesh':
    if '--output-format' not in args or args[args.index('--output-format') + 1] != 'json':
        sys.exit('Mock API requires explicit JSON output')
    if args[:2] == ['get', '/cluster/resources']:
        if '--type' not in args or args[args.index('--type') + 1] != 'vm':
            sys.exit('Mock resources API requires VM filtering')
        if os.environ.get('FAKE_RESOURCES_ERROR'):
            sys.exit(os.environ['FAKE_RESOURCES_ERROR'])
        print(os.environ.get('FAKE_RESOURCES_JSON', '[]'))
    elif args[:2] == ['get', '/cluster/nextid']:
        if os.environ.get('FAKE_NEXTID_ERROR'):
            sys.exit(os.environ['FAKE_NEXTID_ERROR'])
        requested = args[args.index('--vmid') + 1] if '--vmid' in args else '100'
        # Proxmox versions can encode this scalar as a JSON string or number.
        # The former exposed the old raw-string comparison bug on an empty host.
        print(os.environ.get('FAKE_NEXTID_JSON', json.dumps(requested)))
    else:
        sys.exit('Unexpected pvesh command: ' + repr(args))
elif name == 'pvesm':
    print('Name Type Status Total Used Available %')
    status = 'inactive' if os.environ.get('FAKE_STORAGE_OFFLINE') else 'active'
    print('local-lvm lvmthin ' + status + ' 999999999 0 999999999 0%')
elif name == 'ip':
    print(json.dumps([{'ifname': 'vmbr' + str(i), 'linkinfo': {'info_kind': 'bridge'}} for i in range(14)]))
elif name == 'qemu-system-aarch64':
    print('max cortex-a57' if '-cpu' in args else 'virt ARM Virtual Machine')
elif name == 'qemu-img':
    info = {'format': 'qcow2', 'virtual-size': 32 * 1024 ** 3}
    if os.environ.get('FAKE_BACKING'):
        info['backing-filename'] = '/unwanted/backing'
    print(json.dumps(info))
elif name == 'qm':
    if args[0] == 'create':
        if os.environ.get('FAKE_CREATE_FAIL'):
            sys.exit('VMID was claimed concurrently')
        state['create'] = args
    elif args[0] == 'showcmd':
        create = state['create']
        raw = create[create.index('--args') + 1]
        cpu = 'cortex-a57' if os.environ.get('FAKE_OLD_CPU') else 'max'
        machine = os.environ.get('FAKE_MACHINE', 'virt')
        print('/usr/bin/qemu-system-aarch64 -machine ' + machine + ' -cpu ' + cpu + ' ' + raw)
    elif args[0] == 'config':
        print('name: udm-beast-lab')
        for key, value in state['unused'].items():
            print(key + ': ' + value)
    elif args[:2] == ['disk', 'import']:
        if os.environ.get('FAKE_IMPORT_FAIL'):
            sys.exit('simulated import failure')
        number = state['import_count']
        state['unused']['unused' + str(number + 4)] = 'local-lvm:vm-' + args[2] + '-disk-' + str(number + 9)
        if os.environ.get('FAKE_AMBIGUOUS'):
            state['unused']['unused99'] = 'local-lvm:vm-' + args[2] + '-disk-99'
        state['import_count'] += 1
    elif args[0] == 'set':
        for option in ['--virtio0', '--virtio1']:
            if option in args:
                volume = args[args.index(option) + 1].split(',')[0]
                state['unused'] = {k: v for k, v in state['unused'].items() if v != volume}
                state[option] = volume
    else:
        sys.exit('Unexpected qm command: ' + repr(args))
    statepath.write_text(json.dumps(state))
else:
    sys.exit('Unexpected mock command ' + name)
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires Linux Bash")
class ProxmoxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="udm-proxmox-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets with spaces"
        self.assets.mkdir()
        kernel = bytearray(128)
        kernel[56:60] = b"ARM\x64"
        files = {"Image": bytes(kernel), "initramfs.gz": b"\x1f\x8btest-initramfs",
                 "rootfs.qcow2": b"QFI\xfbroot", "state.qcow2": b"QFI\xfbstate"}
        artifacts = {}
        for name, content in files.items():
            (self.assets / name).write_bytes(content)
            artifacts[name] = {"sha256": hashlib.sha256(content).hexdigest()}
        (self.assets / "manifest.json").write_text(json.dumps({
            "status": "experimental-boot-lab", "artifacts": artifacts}))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("qm", "pvesh", "pvesm", "ip", "qemu-img", "qemu-system-aarch64"):
            command = self.bin / name
            command.write_text(MOCK)
            command.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], FAKE_PVE=str(self.root))
        self.args = ["bash", str(SCRIPT), "--vmid", "991", "--storage", "local-lvm",
                     "--assets", str(self.assets), "--snippets-dir", str(self.root / "snippets"),
                     "--bridge", "vmbr0", "--bridge", "vmbr1"]

    def invoke(self, *extra, env=None):
        return subprocess.run(self.args + list(extra), env=env or self.env,
                              text=True, capture_output=True, timeout=20)

    def commands(self):
        path = self.root / "commands.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def set_requested_vmid(self, value):
        self.args[2:4] = [] if value is None else ['--vmid', str(value)]

    def execute_plan(self, result, env=None):
        self.assertEqual(result.returncode, 0, result.stderr)
        return subprocess.run(['bash'], input=result.stdout, env=env or self.env,
                              text=True, capture_output=True, timeout=20)

    def assert_no_vm_mutations(self):
        self.assertFalse(any(c[0] == 'qm' and c[1] in ('create', 'set', 'disk', 'start', 'destroy')
                             for c in self.commands()))
        self.assertFalse((self.root / 'snippets').exists())

    def assert_selected_vmid(self, vmid):
        vmid = str(vmid)
        state = json.loads((self.root / 'state.json').read_text())
        create = state['create']
        self.assertEqual(create[:2], ['create', vmid])
        target = self.root / 'snippets' / ('udm-beast-' + vmid)
        self.assertTrue((target / 'Image').is_file())
        self.assertIn(str(target / 'Image'), create[create.index('--args') + 1])
        self.assertEqual(state['--virtio0'], 'local-lvm:vm-' + vmid + '-disk-9')
        self.assertEqual(state['--virtio1'], 'local-lvm:vm-' + vmid + '-disk-10')
        imports = [c for c in self.commands() if c[:3] == ['qm', 'disk', 'import']]
        self.assertEqual(len(imports), 2)
        self.assertTrue(all(c[3] == vmid for c in imports))
        self.assertFalse(any(c[:2] == ['qm', 'start'] for c in self.commands()))
        first_mac = (0x020000000000 + (int(vmid) << 8)).to_bytes(6, 'big').hex(':')
        self.assertTrue(create[create.index('--net0') + 1].startswith('virtio=' + first_mac + ','))
        return create

    def virtual_profile(self):
        manifest_path = self.assets / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest.update(status='experimental-virtual-gateway', profile='virtual', nics=14)
        manifest_path.write_text(json.dumps(manifest))
        self.args = self.args[:-4]

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Printed plan applies as root')
    def test_virtual_profile_creates_fourteen_disconnected_assignable_ports(self):
        self.virtual_profile()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = self.execute_plan(result)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        create = json.loads((self.root / 'state.json').read_text())['create']
        base = int.from_bytes(bytes.fromhex('02000003df00'), 'big')
        for index in range(14):
            nic = create[create.index('--net' + str(index)) + 1]
            mac = (base + index).to_bytes(6, 'big').hex(':')
            self.assertEqual(nic, 'virtio=' + mac + ',link_down=1')
        self.assertIn('udm.mode=systemd', create[create.index('--args') + 1])
        self.assertIn('module_blacklist=phy_diag', create[create.index('--args') + 1])
        self.assertFalse(any(cmd[:2] == ['qm', 'start'] for cmd in self.commands()))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Printed plan applies as root')
    def test_virtual_port_mapping_only_connects_selected_bridges(self):
        self.virtual_profile()
        result = self.invoke('--port', '0=vmbr1', '--port', '8=vmbr0', '--connect')
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = self.execute_plan(result)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        create = json.loads((self.root / 'state.json').read_text())['create']
        self.assertIn(',bridge=vmbr1,link_down=0', create[create.index('--net0') + 1])
        self.assertIn(',bridge=vmbr0,link_down=0', create[create.index('--net8') + 1])
        self.assertNotIn('bridge=', create[create.index('--net1') + 1])
        self.assertIn('link_down=1', create[create.index('--net1') + 1])

    def test_virtual_port_mapping_rejects_duplicates_and_option_injection(self):
        self.virtual_profile()
        for extra in (['--port', '14=vmbr0'], ['--port', '0=vmbr0,tag=3'],
                      ['--port', '0=vmbr0', '--port', '0=vmbr1']):
            with self.subTest(extra=extra):
                result = self.invoke(*extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.commands(), [])

    def test_dry_run_is_default_and_changes_nothing(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--apply', result.stdout)
        self.assertIn('proxmox-import.sh', result.stdout)
        self.assertEqual(self.commands(), [])
        self.assertFalse((self.root / "snippets").exists())
        checked = subprocess.run(["bash", "-n"], input=result.stdout, text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_invalid_bridge_and_count_rejected(self):
        result = self.invoke("--bridge", "vmbr2,tag=123")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid bridge", result.stderr)
        result = self.invoke(*sum((["--bridge", "vmbr0"] for _ in range(13)), []))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("2..14", result.stderr)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Printed plan applies as root')
    def test_printed_plan_is_runnable_with_paths_containing_spaces(self):
        result = self.invoke('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = self.execute_plan(result)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        create = self.assert_selected_vmid(991)
        self.assertEqual(create[create.index('--arch') + 1], 'aarch64')
        self.assertEqual(create[create.index('--cpu') + 1], 'max')
        raw = create[create.index('--args') + 1]
        for expected in ('gic-version=3', 'udm.mode=shell', 'module_blacklist=phy_diag',
                         'initcall_blacklist=mrvl_swup_init,uart_redirect_init,mub_gen_init,portm_boot_cfg_init'):
            self.assertIn(expected, raw)
        self.assertIn('link_down=1', create[create.index('--net0') + 1])

    def test_integrity_failure_precedes_host_commands(self):
        (self.assets / "Image").write_bytes(b"changed")
        result = self.invoke("--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual(self.commands(), [])

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Printed plan applies as root')
    def test_system_mode_and_connect_are_explicit(self):
        result = self.invoke("--boot-mode", "system", "--connect")
        executed = self.execute_plan(result)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        create = self.assert_selected_vmid(991)
        self.assertIn('udm.mode=systemd', create[create.index('--args') + 1])
        self.assertIn('module_blacklist=phy_diag', create[create.index('--args') + 1])
        self.assertIn('link_down=0', create[create.index('--net0') + 1])

    def test_snippets_injection_rejected(self):
        result = self.invoke("--snippets-dir", "/tmp/unsafe'quote")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute path", result.stderr)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_apply_imports_actual_allocated_volumes_and_never_starts(self):
        result = self.invoke("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads((self.root / "state.json").read_text())
        self.assertEqual(state["--virtio0"], "local-lvm:vm-991-disk-9")
        self.assertEqual(state["--virtio1"], "local-lvm:vm-991-disk-10")
        commands = self.commands()
        self.assertFalse(any(command[:2] == ["qm", "start"] for command in commands))
        self.assertFalse(any(command[0] == "ip" and "set" in command for command in commands))
        self.assertTrue((self.root / "snippets" / "udm-beast-991" / "Image").exists())

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_empty_cluster_accepts_preferred_100_returned_as_json_string(self):
        self.set_requested_vmid(100)
        result = self.invoke('--apply', env=dict(self.env, FAKE_NEXTID_JSON='"100"'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_selected_vmid(100)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_omitted_vmid_selects_next_id_from_json_number(self):
        self.set_requested_vmid(None)
        result = self.invoke('--apply', env=dict(self.env, FAKE_NEXTID_JSON='1203'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_selected_vmid(1203)
        calls = [c for c in self.commands() if c[0] == 'pvesh']
        self.assertTrue(calls)
        self.assertTrue(all(c[2] == '/cluster/nextid' and '--vmid' not in c for c in calls))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_explicit_auto_selects_json_string_and_regenerates_fourteen_macs(self):
        self.virtual_profile()
        self.set_requested_vmid('auto')
        result = self.invoke('--apply', env=dict(self.env, FAKE_NEXTID_JSON='"4096"'))
        self.assertEqual(result.returncode, 0, result.stderr)
        create = self.assert_selected_vmid(4096)
        for index in range(14):
            mac = (0x020000000000 + (4096 << 8) + index).to_bytes(6, 'big').hex(':')
            self.assertEqual(create[create.index('--net' + str(index)) + 1],
                             'virtio=' + mac + ',link_down=1')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_occupied_lxc_id_falls_back_without_touching_its_snippets(self):
        self.set_requested_vmid(100)
        destination = self.root / 'snippets' / 'udm-beast-100'
        destination.mkdir(parents=True)
        marker = destination / 'Image'
        marker.write_bytes(b'existing guest kernel')
        resources = [{'type': 'lxc', 'vmid': 100, 'node': 'other-node', 'status': 'stopped'}]
        result = self.invoke('--apply', env=dict(self.env, FAKE_RESOURCES_JSON=json.dumps(resources),
                                                FAKE_NEXTID_JSON='"101"'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_selected_vmid(101)
        self.assertEqual(marker.read_bytes(), b'existing guest kernel')
        next_calls = [c for c in self.commands() if c[:3] == ['pvesh', 'get', '/cluster/nextid']]
        self.assertTrue(next_calls)
        self.assertTrue(all('--vmid' not in c for c in next_calls))
        self.assertIn('100', result.stderr)
        self.assertIn('101', result.stdout + result.stderr)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Printed plan applies as root')
    def test_printed_plan_resolves_new_cluster_collision_at_execution(self):
        self.set_requested_vmid(100)
        plan = self.invoke('--dry-run')
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertEqual(self.commands(), [])
        resources = [{'type': 'qemu', 'vmid': 100, 'node': 'other-node', 'template': 1}]
        executed = self.execute_plan(plan, env=dict(self.env, FAKE_RESOURCES_JSON=json.dumps(resources),
                                                   FAKE_NEXTID_JSON='102'))
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assert_selected_vmid(102)
        self.assertFalse((self.root / 'snippets' / 'udm-beast-100').exists())

    def test_auto_dry_run_defers_host_queries(self):
        self.set_requested_vmid(None)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--apply', result.stdout)
        self.assertEqual(self.commands(), [])
        self.assert_no_vm_mutations()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_api_failures_abort_before_mutation_instead_of_allocating_another_id(self):
        for key in ('FAKE_RESOURCES_ERROR', 'FAKE_NEXTID_ERROR'):
            with self.subTest(api=key):
                result = self.invoke('--apply', env=dict(self.env, **{key: 'cluster API unavailable'}))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cluster API unavailable', result.stderr)
                self.assert_no_vm_mutations()
                calls = [c for c in self.commands() if c[:3] == ['pvesh', 'get', '/cluster/nextid']]
                self.assertTrue(all('--vmid' in c for c in calls))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_invalid_nextid_json_never_reaches_mutation(self):
        self.set_requested_vmid('auto')
        for response in ('not json', 'null', 'true', '100.0', '{}', '[]', '99', '1000000000',
                         '"100; touch /tmp/unsafe"'):
            with self.subTest(response=response):
                result = self.invoke('--apply', env=dict(self.env, FAKE_NEXTID_JSON=response))
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_vm_mutations()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_malformed_cluster_inventory_does_not_assume_preferred_id_is_free(self):
        for response in ('not json', '{}', '[null]', '[{"type":"qemu","vmid":true}]',
                         '[{"type":"lxc","vmid":100.5}]', '[{"type":"qemu"}]'):
            with self.subTest(response=response):
                result = self.invoke('--apply', env=dict(self.env, FAKE_RESOURCES_JSON=response))
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_vm_mutations()
        self.assertFalse(any(c[:3] == ['pvesh', 'get', '/cluster/nextid'] for c in self.commands()))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_preferred_id_assertion_rejects_a_different_returned_id(self):
        result = self.invoke('--apply', env=dict(self.env, FAKE_NEXTID_JSON='"992"'))
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_vm_mutations()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_existing_selected_destination_is_preserved(self):
        self.set_requested_vmid('auto')
        destination = self.root / 'snippets' / 'udm-beast-100'
        destination.mkdir(parents=True)
        marker = destination / 'Image'
        marker.write_bytes(b'do not overwrite')
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already exists', result.stderr)
        self.assertEqual(marker.read_bytes(), b'do not overwrite')
        self.assertFalse(any(c[0] == 'qm' for c in self.commands()))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_create_race_does_not_retry_or_import_disks_into_another_vm(self):
        result = self.invoke('--apply', env=dict(self.env, FAKE_CREATE_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('VMID was claimed concurrently', result.stderr)
        commands = self.commands()
        self.assertEqual(len([c for c in commands if c[:2] == ['qm', 'create']]), 1)
        self.assertFalse(any(c[0] == 'qm' and c[1] in ('disk', 'set', 'start', 'destroy') for c in commands))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_host_preflight_failures_create_no_vm(self):
        for key in ("FAKE_STORAGE_OFFLINE", "FAKE_BACKING"):
            with self.subTest(key=key):
                result = self.invoke("--apply", env=dict(self.env, **{key: "1"}))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c[:2] == ["qm", "create"] for c in self.commands()))
                self.assertFalse((self.root / "snippets").exists())

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_old_cpu_support_fails_before_disk_import(self):
        result = self.invoke("--apply", env=dict(self.env, FAKE_OLD_CPU="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not honor ARM64", result.stderr)
        self.assertFalse(any(c[:3] == ["qm", "disk", "import"] for c in self.commands()))
        self.assertIn("nothing was automatically deleted or started", result.stderr)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_proxmox_virt_machine_alias_allows_disk_import(self):
        result = self.invoke('--apply', env=dict(self.env, FAKE_MACHINE='accel=tcg,type=virt+pve0'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_selected_vmid(991)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_versioned_proxmox_virt_machine_alias_allows_disk_import(self):
        result = self.invoke('--apply', env=dict(self.env, FAKE_MACHINE='accel=tcg,type=virt-11.0+pve0'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_selected_vmid(991)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Mock apply requires root test context')
    def test_non_arm_and_resembling_machine_aliases_fail_before_disk_import(self):
        for index, machine in enumerate(('q35', 'virt-other', 'q35+pve0')):
            with self.subTest(machine=machine):
                result = self.invoke('--vmid', str(991 + index), '--apply',
                                     env=dict(self.env, FAKE_MACHINE='accel=tcg,type=' + machine))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('qm did not select an ARM virt machine', result.stderr)
                self.assertFalse(any(c[:3] == ['qm', 'disk', 'import'] for c in self.commands()))
                self.assertIn('nothing was automatically deleted or started', result.stderr)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_ambiguous_import_never_attaches_guessed_disk(self):
        result = self.invoke("--apply", env=dict(self.env, FAKE_AMBIGUOUS="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertFalse(any(c[:2] == ["qm", "set"] for c in self.commands()))


if __name__ == "__main__":
    unittest.main()
