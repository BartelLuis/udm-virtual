import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch


_SPEC = importlib.util.spec_from_file_location("run_lab", Path(__file__).resolve().parents[1] / "run-lab.py")
run_lab = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(run_lab)


class RunLabTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.assets = Path(self.temporary.name) / "assets"
        self.assets.mkdir()
        artifacts = {}
        for name in ("Image", "initramfs.gz", "rootfs.qcow2", "state.qcow2"):
            data = ("fixture " + name).encode()
            (self.assets / name).write_bytes(data)
            if name != "state.qcow2":
                artifacts[name] = {"sha256": hashlib.sha256(data).hexdigest()}
        self.manifest = {"status": "experimental-boot-lab", "artifacts": artifacts}
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        self.log = self.assets / "selftest.log"

    @staticmethod
    def options(command, name):
        return [command[index + 1] for index, value in enumerate(command[:-1]) if value == name]

    def use_uxg_manifest(self, **overrides):
        self.manifest.update(
            status="experimental-virtual-gateway", profile="virtual", model="UXGENT", nics=6,
            firmware_sha256="bedeac0a67329ec135025da352e490844be5aafd91a9c303ceba8fd8e424b4f0",
        )
        self.manifest.update(overrides)
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))

    def mock_selftest(self, output, returncode=0, timed_out=False):
        process = Mock(returncode=returncode)
        process.poll.return_value = None if timed_out else returncode
        if timed_out:
            process.wait.side_effect = [subprocess.TimeoutExpired(["qemu"], 7), returncode]
        else:
            process.wait.return_value = returncode

        def launch(*args, **kwargs):
            kwargs['stdout'].write(output)
            # Visible before wait() completes; no communicate() buffer is used.
            self.assertEqual(self.log.read_bytes(), output)
            return process

        with patch.object(run_lab.subprocess, "Popen", side_effect=launch) as popen:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = run_lab.run_selftest(["qemu", "fixture"], self.log, timeout=7)
        popen.assert_called_once_with(["qemu", "fixture"], stdin=subprocess.DEVNULL,
                                     stdout=popen.call_args.kwargs['stdout'], stderr=subprocess.STDOUT)
        self.assertTrue(popen.call_args.kwargs['stdout'].closed)
        process.communicate.assert_not_called()
        self.assertEqual(self.log.read_bytes(), output)
        return result, process

    def test_pass_requires_success_marker_and_clean_exit(self):
        result, process = self.mock_selftest(b"Booted\nUDM_LAB_SELFTEST_PASS\n")
        self.assertEqual(result, 0)
        process.wait.assert_called_once_with(timeout=7)
        process.kill.assert_not_called()

    def test_clean_exit_without_pass_and_pass_with_failed_exit_both_fail(self):
        for output, returncode in ((b"Normal poweroff\n", 0), (b"UDM_LAB_SELFTEST_PASS\n", 1)):
            with self.subTest(output=output, returncode=returncode):
                result, _ = self.mock_selftest(output, returncode)
                self.assertEqual(result, 1)

    def test_failure_init_failure_and_panic_override_pass(self):
        for marker in (b"UDM_LAB_SELFTEST_FAIL", b"UDM_LAB_INIT_FAILURE", b"Kernel panic"):
            with self.subTest(marker=marker):
                result, _ = self.mock_selftest(b"UDM_LAB_SELFTEST_PASS\n" + marker + b"\n")
                self.assertEqual(result, 1)

    def test_squashfs_read_error_before_later_pass_is_fatal(self):
        output = (b'[10.663211] I/O error, dev vda, sector 513396 op READ flags 0x800\n'
                  b'SQUASHFS error: Failed to read block 0xfaaea82: -5\n'
                  b'UDM_VIRTUAL_HAL_NATIVE_READY\nUDM_LAB_SELFTEST_PASS\n')
        result, _ = self.mock_selftest(output)
        self.assertEqual(result, 1)

    def test_timeout_kills_guest_keeps_log_and_rejects_even_pass(self):
        result, process = self.mock_selftest(b"UDM_LAB_SELFTEST_PASS\nStill running\n", timed_out=True)
        self.assertEqual(result, 1)
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)
        process.wait.assert_called_with()

    def test_keyboard_interrupt_kills_and_reaps_only_own_child(self):
        process = Mock(returncode=None)
        process.wait.side_effect = [KeyboardInterrupt, -9]
        process.poll.return_value = None
        with patch.object(run_lab.subprocess, 'Popen', return_value=process) as popen:
            with self.assertRaises(KeyboardInterrupt):
                run_lab.run_selftest(['qemu', 'fixture'], self.log, timeout=7)
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)
        process.wait.assert_called_with()
        self.assertTrue(popen.call_args.kwargs['stdout'].closed)

    def test_real_child_log_is_visible_while_child_is_running(self):
        # A tiny diagnostic process, not a VM or a simulated successful boot.
        release = self.assets / 'release-child'
        source = (
            'import os, pathlib, sys, time\n'
            'os.write(1, b"startup diagnostic visible now\\n")\n'
            'release = pathlib.Path(sys.argv[1])\n'
            'while not release.exists(): time.sleep(0.02)\n'
        )
        result = []
        errors = []

        def run():
            try:
                result.append(run_lab.run_selftest([sys.executable, '-c', source, str(release)],
                                                    self.log, timeout=10))
            except BaseException as exc:
                errors.append(exc)

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if self.log.exists() and self.log.read_bytes():
                        break
                    time.sleep(0.02)
                self.assertEqual(self.log.read_bytes(), b'startup diagnostic visible now\n')
                self.assertTrue(thread.is_alive(), 'Child should still be waiting for release')
            finally:
                release.touch()
                thread.join(timeout=15)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result, [1])  # Diagnostic text is never a PASS marker.

    def test_failed_guest_binary_console_bytes_are_preserved(self):
        result, _ = self.mock_selftest(b"\xff\xfe\x00UDM_LAB_SELFTEST_FAIL\n", returncode=1)
        self.assertEqual(result, 1)

    def test_original_disk_is_readonly_and_selftest_state_is_discarded(self):
        command = run_lab.command(self.assets, "selftest")
        drives = self.options(command, "-drive")
        self.assertEqual(len(drives), 2)
        root = next(item for item in drives if ",id=root," in item)
        state = next(item for item in drives if ",id=state," in item)
        self.assertIn("readonly=on", root.split(","))
        self.assertIn("snapshot=on", state.split(","))
        self.assertIn("format=qcow2", root.split(","))
        self.assertIn("format=qcow2", state.split(","))
        self.assertIn("virtio-blk-pci,drive=root", self.options(command, "-device"))
        self.assertIn("virtio-blk-pci,drive=state", self.options(command, "-device"))

    def test_shell_state_persists_unless_snapshot_requested(self):
        # The state disk is intentionally mutable, unlike immutable build artifacts.
        (self.assets / "state.qcow2").write_bytes(b"state changed by a previous boot")
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot):
                command = run_lab.command(self.assets, "shell", snapshot=snapshot)
                state = next(item for item in self.options(command, "-drive") if ",id=state," in item)
                self.assertEqual("snapshot=on" in state.split(","), snapshot)

    def test_all_nics_use_distinct_isolated_hubs(self):
        command = run_lab.command(self.assets, "selftest", nics=4)
        backends = self.options(command, "-netdev")
        self.assertEqual(backends, [f"hubport,id=port{i},hubid={i}" for i in range(4)])
        devices = [value for value in self.options(command, "-device") if value.startswith("virtio-net-pci,")]
        self.assertEqual(len(devices), 4)
        self.assertEqual(len({value.split("mac=")[1] for value in devices}), 4)
        self.assertFalse(any(value.startswith(("tap,", "user,", "bridge,")) for value in backends))
        self.assertIn("udm.nics=4", self.options(command, "-append")[0].split())

    def test_arm_boot_uses_gic3_and_disables_known_hardware_initcalls(self):
        command = run_lab.command(self.assets, "shell", memory=8192, cores=4)
        self.assertEqual(command[0], "qemu-system-aarch64")
        self.assertEqual(self.options(command, "-machine"), ["virt,gic-version=3"])
        self.assertEqual(self.options(command, "-accel"), ["tcg"])
        self.assertEqual(self.options(command, "-cpu"), ["max"])
        self.assertEqual(self.options(command, "-global"), [])
        self.assertEqual(self.options(command, "-m"), ["8192"])
        self.assertEqual(self.options(command, "-smp"), ["4"])
        self.assertEqual(self.options(command, "-device").count(
            "virtio-balloon-pci,free-page-reporting=on"), 1)
        boot_options = self.options(command, "-append")[0].split()
        blacklist = next(value.split("=", 1)[1] for value in boot_options if value.startswith("initcall_blacklist="))
        self.assertEqual(set(blacklist.split(",")), {"mrvl_swup_init", "uart_redirect_init", "mub_gen_init", "portm_boot_cfg_init"})
        self.assertTrue({"console=ttyAMA0", "root=/dev/vda", "state=/dev/vdb", "udm.mode=shell"}.issubset(boot_options))

    def test_cli_defaults_follow_manifest_status(self):
        for status, mode, count in (("experimental-boot-lab", "shell", 2),
                                    ("experimental-virtual-gateway", "systemd", 14)):
            with self.subTest(status=status):
                # The status is authoritative; optional profile metadata is absent.
                self.manifest["status"] = status
                (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
                with patch.object(run_lab.sys, "argv", ["run-lab.py", "--assets", str(self.assets)]):
                    with patch.object(run_lab.subprocess, "call", return_value=0) as launch:
                        self.assertEqual(run_lab.main(), 0)
                command = launch.call_args.args[0]
                options = self.options(command, "-append")[0].split()
                self.assertIn(f"udm.mode={mode}", options)
                self.assertIn(f"udm.nics={count}", options)
                self.assertIn("module_blacklist=phy_diag", options)
                self.assertEqual(len(self.options(command, "-netdev")), count)
                self.assertIn("virtio-balloon-pci,free-page-reporting=on", self.options(command, "-device"))

    def test_virtual_status_requires_fourteen_ports_without_profile_metadata(self):
        self.manifest["status"] = "experimental-virtual-gateway"
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "requires --nics 14"):
            run_lab.command(self.assets, "systemd", nics=2)
        # Explicit console/selftest modes retain the complete virtual port map.
        for mode in ("shell", "selftest", "systemd"):
            with self.subTest(mode=mode):
                command = run_lab.command(self.assets, mode)
                self.assertIn(f"udm.mode={mode}", self.options(command, "-append")[0].split())
                self.assertIn("module_blacklist=phy_diag", self.options(command, "-append")[0].split())
                self.assertEqual(len(self.options(command, "-netdev")), 14)
                state = next(item for item in self.options(command, "-drive") if ",id=state," in item)
                self.assertEqual("snapshot=on" in state.split(","), mode == "selftest")

    def test_uxg_cli_defaults_to_six_isolated_ports_with_confirmed_cn9670_blacklist(self):
        self.use_uxg_manifest()
        with patch.object(run_lab.sys, "argv", ["run-lab.py", "--assets", str(self.assets)]):
            with patch.object(run_lab.subprocess, "call", return_value=0) as launch:
                self.assertEqual(run_lab.main(), 0)
        launch.assert_called_once()
        command = launch.call_args.args[0]
        self.assertEqual(command[0], "qemu-system-aarch64")
        self.assertEqual(self.options(command, "-machine"), ["virt,gic-version=3"])
        self.assertEqual(self.options(command, "-accel"), ["tcg"])
        self.assertEqual(self.options(command, "-cpu"), ["max"])
        boot_options = self.options(command, "-append")[0].split()
        self.assertTrue({"console=ttyAMA0", "root=/dev/vda", "state=/dev/vdb",
                         "udm.mode=systemd", "udm.nics=6", "net.ifnames=0"}.issubset(boot_options))
        self.assertEqual([option for option in boot_options if option.startswith("initcall_blacklist=")],
                         ["initcall_blacklist=mrvl_swup_init,mub_gen_init,cpu_debug_init"])
        self.assertFalse(any(option.startswith("module_blacklist=") for option in boot_options))
        self.assertEqual(self.options(command, "-netdev"),
                         [f"hubport,id=port{i},hubid={i}" for i in range(6)])
        devices = [value for value in self.options(command, "-device")
                   if value.startswith("virtio-net-pci,")]
        self.assertEqual(devices, [f"virtio-net-pci,netdev=port{i},mac=02:55:44:4d:00:{i:02x}"
                                   for i in range(6)])

    def test_uxg_all_modes_keep_six_ports_and_disk_protection(self):
        self.use_uxg_manifest()
        for mode in ("shell", "selftest", "systemd"):
            for nics in (None, 6):
                with self.subTest(mode=mode, nics=nics):
                    command = run_lab.command(self.assets, mode, nics=nics)
                    self.assertEqual(self.options(command, "-cpu"), ["max"])
                    self.assertEqual(self.options(command, "-global"), ["max-arm-cpu.pauth=off"])
                    options = self.options(command, "-append")[0].split()
                    self.assertIn(f"udm.mode={mode}", options)
                    self.assertEqual([item for item in options if item.startswith("initcall_blacklist=")],
                                     ["initcall_blacklist=mrvl_swup_init,mub_gen_init,cpu_debug_init"])
                    self.assertFalse(any(item.startswith("module_blacklist=") for item in options))
                    self.assertEqual(len(self.options(command, "-netdev")), 6)
                    drives = self.options(command, "-drive")
                    root = next(item for item in drives if ",id=root," in item)
                    state = next(item for item in drives if ",id=state," in item)
                    self.assertIn("readonly=on", root.split(","))
                    self.assertEqual("snapshot=on" in state.split(","), mode == "selftest")

    def test_uxg_cli_provider_wan_mac_changes_only_port0_and_guest_option(self):
        self.use_uxg_manifest()
        with patch.object(run_lab.sys, "argv", ["run-lab.py", "--assets", str(self.assets),
                                               "--wan-mac", "00:50:56:01:1E:69"]):
            with patch.object(run_lab.subprocess, "call", return_value=0) as launch:
                self.assertEqual(run_lab.main(), 0)
        command = launch.call_args.args[0]
        options = self.options(command, "-append")[0].split()
        self.assertEqual([item for item in options if item.startswith("udm.wan_mac=")],
                         ["udm.wan_mac=00:50:56:01:1e:69"])
        devices = [item for item in self.options(command, "-device") if item.startswith("virtio-net-pci,")]
        self.assertEqual(devices[0], "virtio-net-pci,netdev=port0,mac=00:50:56:01:1e:69")
        self.assertEqual(devices[1:], [f"virtio-net-pci,netdev=port{i},mac=02:55:44:4d:00:{i:02x}"
                                      for i in range(1, 6)])
        default = run_lab.command(self.assets)
        self.assertFalse(any(item.startswith("udm.wan_mac=") for item in self.options(default, "-append")[0].split()))

    def test_uxg_invalid_or_colliding_wan_mac_is_rejected(self):
        self.use_uxg_manifest()
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:50:56:01:1e:69",
                    "00:50:56:01:1e", "00-50-56-01-1e-69", "0:50:56:01:1e:69",
                    "00:50:56:01:1e:69,bridge=vmbr0", "", True, "02:55:44:4d:00:03"):
            with self.subTest(mac=mac), self.assertRaises(ValueError):
                run_lab.command(self.assets, wan_mac=mac)

    def test_wan_mac_is_only_supported_for_uxg(self):
        for status in ("experimental-boot-lab", "experimental-virtual-gateway"):
            self.manifest["status"] = status
            (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "only for UXGENT"):
                run_lab.command(self.assets, wan_mac="00:50:56:01:1e:69")

    def test_uxg_wrong_requested_port_count_refuses_before_launch(self):
        self.use_uxg_manifest()
        for nics in (2, 5, 7, 14):
            with self.subTest(nics=nics):
                with patch.object(run_lab.sys, "argv", ["run-lab.py", "--assets", str(self.assets),
                                                       "--nics", str(nics)]):
                    with patch.object(run_lab.subprocess, "call") as launch:
                        with contextlib.redirect_stderr(io.StringIO()) as error:
                            with self.assertRaises(SystemExit):
                                run_lab.main()
                        self.assertIn("requires --nics 6", error.getvalue())
                        launch.assert_not_called()

    def test_uxg_missing_or_wrong_manifest_port_count_is_rejected(self):
        for count in (None, 2, 14, "6", 6.0, True):
            with self.subTest(count=count):
                self.use_uxg_manifest(nics=count)
                if count is None:
                    self.manifest.pop("nics")
                    (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
                with self.assertRaisesRegex(ValueError, "manifest requires nics 6"):
                    run_lab.command(self.assets)

    def test_uxg_requires_virtual_status_and_profile(self):
        for status, profile in (("experimental-boot-lab", "virtual"),
                                ("experimental-virtual-gateway", None),
                                ("experimental-virtual-gateway", "lab")):
            with self.subTest(status=status, profile=profile):
                self.use_uxg_manifest(status=status, profile=profile)
                with self.assertRaisesRegex(ValueError, "requires a virtual build manifest"):
                    run_lab.command(self.assets)

    def test_explicit_udm_model_preserves_legacy_command_for_both_statuses(self):
        for status in ("experimental-boot-lab", "experimental-virtual-gateway"):
            with self.subTest(status=status):
                self.manifest["status"] = status
                self.manifest.pop("model", None)
                (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
                legacy = run_lab.command(self.assets)
                self.manifest["model"] = "UDMEA4C"
                (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
                self.assertEqual(run_lab.command(self.assets), legacy)

    def test_unknown_model_is_rejected_before_artifact_access(self):
        # A model typo must not silently select UDM defaults or begin preparing a launch.
        (self.assets / "Image").unlink()
        for model in ("other", "uxgent", "", None, ["UXGENT"]):
            with self.subTest(model=model):
                self.manifest["model"] = model
                (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
                with self.assertRaisesRegex(ValueError, "Unsupported virtual model"):
                    run_lab.command(self.assets)

    def test_modified_build_artifacts_are_rejected_before_launch(self):
        for name in ("Image", "initramfs.gz", "rootfs.qcow2"):
            artifact = self.assets / name
            original = artifact.read_bytes()
            artifact.write_bytes(b"corrupted")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Build artifact changed"):
                run_lab.command(self.assets, "selftest")
            artifact.write_bytes(original)

    def test_unknown_manifest_and_qemu_option_delimiter_paths_rejected(self):
        self.manifest["status"] = "unknown"
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "Unknown build manifest"):
            run_lab.command(self.assets, "shell")
        with self.assertRaisesRegex(ValueError, "commas"):
            run_lab.command(self.assets / "unsafe,readonly=off", "shell")


if __name__ == "__main__":
    unittest.main()
