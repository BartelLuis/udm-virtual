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
    if os.environ.get('FAKE_OCCUPIED'):
        sys.exit('VMID already exists')
    print(args[args.index('--vmid') + 1])
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
        state['create'] = args
    elif args[0] == 'showcmd':
        create = state['create']
        raw = create[create.index('--args') + 1]
        cpu = 'cortex-a57' if os.environ.get('FAKE_OLD_CPU') else 'max'
        print('/usr/bin/qemu-system-aarch64 -machine virt -cpu ' + cpu + ' ' + raw)
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

    def virtual_profile(self):
        manifest_path = self.assets / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest.update(status='experimental-virtual-gateway', profile='virtual', nics=14)
        manifest_path.write_text(json.dumps(manifest))
        self.args = self.args[:-4]

    def test_virtual_profile_creates_fourteen_disconnected_assignable_ports(self):
        self.virtual_profile()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = subprocess.run(['bash'], input=result.stdout, env=self.env,
                                 text=True, capture_output=True, timeout=20)
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

    def test_virtual_port_mapping_only_connects_selected_bridges(self):
        self.virtual_profile()
        result = self.invoke('--port', '0=vmbr1', '--port', '8=vmbr0', '--connect')
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = subprocess.run(['bash'], input=result.stdout, env=self.env,
                                 text=True, capture_output=True, timeout=20)
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
        self.assertIn("--arch aarch64", result.stdout)
        self.assertIn("--cpu max", result.stdout)
        self.assertIn("gic-version=3", result.stdout)
        self.assertIn("udm.mode=shell", result.stdout)
        self.assertIn("module_blacklist=phy_diag", result.stdout)
        self.assertIn("initcall_blacklist=mrvl_swup_init\\,uart_redirect_init\\,mub_gen_init\\,portm_boot_cfg_init", result.stdout)
        self.assertIn("link_down=1", result.stdout)
        self.assertIn("virtio0", result.stdout)
        self.assertIn("virtio1", result.stdout)
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

    def test_printed_plan_is_runnable_with_paths_containing_spaces(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = subprocess.run(["bash"], input=result.stdout, env=self.env,
                                  text=True, capture_output=True, timeout=20)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        state = json.loads((self.root / "state.json").read_text())
        self.assertEqual(state["--virtio1"], "local-lvm:vm-991-disk-10")
        self.assertFalse(any(command[:2] == ["qm", "start"] for command in self.commands()))

    def test_integrity_failure_precedes_host_commands(self):
        (self.assets / "Image").write_bytes(b"changed")
        result = self.invoke("--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual(self.commands(), [])

    def test_system_mode_and_connect_are_explicit(self):
        result = self.invoke("--boot-mode", "system", "--connect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("udm.mode=systemd", result.stdout)
        self.assertIn("module_blacklist=phy_diag", result.stdout)
        self.assertIn("link_down=0", result.stdout)
        self.assertNotIn("qm start", result.stdout)

    def test_snippets_injection_and_existing_destination_rejected(self):
        result = self.invoke("--snippets-dir", "/tmp/unsafe'quote")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute path", result.stderr)
        destination = self.root / "snippets" / "udm-beast-991"
        destination.mkdir(parents=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)

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

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_host_preflight_failures_create_no_vm(self):
        for key in ("FAKE_OCCUPIED", "FAKE_STORAGE_OFFLINE", "FAKE_BACKING"):
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

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Mock apply requires root test context")
    def test_ambiguous_import_never_attaches_guessed_disk(self):
        result = self.invoke("--apply", env=dict(self.env, FAKE_AMBIGUOUS="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertFalse(any(c[:2] == ["qm", "set"] for c in self.commands()))


if __name__ == "__main__":
    unittest.main()
