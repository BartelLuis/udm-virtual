import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock


PATH = Path(__file__).resolve().parents[1] / "validate-network.py"
SPEC = importlib.util.spec_from_file_location("validate_network_test_module", PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def base_command():
    command = ["qemu-system-aarch64", "-drive", "file=state.qcow2,if=none,id=state,format=qcow2,snapshot=on",
               "-serial", "mon:stdio", "-append", "udm.mode=systemd"]
    for index in range(14):
        command += ["-netdev", f"hubport,id=port{index},hubid={index}", "-device",
                    f"virtio-net-pci,netdev=port{index},mac=02:55:44:4d:00:{index:02x}"]
    return command


class CommandTests(unittest.TestCase):
    def test_explicit_test_policy_requires_snapshot_and_selects_guest_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            (assets / "manifest.json").write_text(json.dumps({"profile": "virtual"}))
            command = runner.build_command(assets, assets / "run", {"lan": 1, "wan": 2},
                                           factory=lambda *a, **kw: base_command(), test_policy=True)
            self.assertIn('udm.validation=firewall', command[command.index('-append') + 1])
            self.assertIn('snapshot=on', command[2])

    def test_only_lan_and_wan_changed_original_systemd_and_snapshot_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            (assets / "manifest.json").write_text(json.dumps({"profile": "virtual"}))
            original = base_command()
            factory = mock.Mock(return_value=original)
            command = runner.build_command(assets, assets / "run", {"lan": 23456, "wan": 23457}, factory=factory)
            factory.assert_called_once_with(assets.resolve(), "systemd", nics=14, memory=4096, cores=4, snapshot=True)
            self.assertEqual(original, base_command(), "Copied command must not mutate shared caller state")
            self.assertIn("socket,id=port0,connect=127.0.0.1:23456", command)
            self.assertIn("socket,id=port8,connect=127.0.0.1:23457", command)
            self.assertEqual(sum(value.startswith("hubport,") for value in command), 12)
            self.assertEqual(sum(value.startswith("virtio-net-pci,") for value in command), 14)
            self.assertIn("file:" + str(assets / "run/serial.log"), command)
            self.assertEqual(command[-2:], ["-monitor", "none"])

    def test_unexpected_host_backends_or_non_snapshot_state_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            (assets / "manifest.json").write_text(json.dumps({"profile": "virtual"}))
            for alteration in ("backend", "snapshot"):
                changed = base_command()
                if alteration == "backend":
                    changed[changed.index("-netdev") + 1] = "tap,id=port0,ifname=host0"
                else:
                    changed[2] = changed[2].replace(",snapshot=on", "")
                with self.subTest(alteration=alteration), self.assertRaises(ValueError):
                    runner.build_command(assets, assets / "run", {"lan": 1, "wan": 2},
                                         factory=lambda *args, **kwargs: changed)

    def test_boot_lab_profile_does_not_launch_network_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            (assets / "manifest.json").write_text(json.dumps({"profile": "boot-lab"}))
            factory = mock.Mock()
            with self.assertRaisesRegex(ValueError, "virtual"):
                runner.build_command(assets, assets / "run", {"lan": 1, "wan": 2}, factory=factory)
            factory.assert_not_called()


class ListenerTests(unittest.TestCase):
    def test_ports_remain_owned_on_loopback_until_connection(self):
        listeners = runner.reserve_listeners()
        try:
            addresses = [listener.getsockname() for listener in listeners.values()]
            self.assertEqual(len(set(addresses)), 2)
            self.assertTrue(all(address[0] == "127.0.0.1" and address[1] > 0 for address in addresses))
            # A second normal socket cannot take the reserved listen endpoint.
            for address in addresses:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as contender:
                    with self.assertRaises(OSError):
                        contender.bind(address)
            with socket.create_connection(addresses[0]) as connection:
                accepted, remote = listeners["lan"].accept()
                accepted.close()
                self.assertEqual(remote[0], "127.0.0.1")
        finally:
            for listener in listeners.values():
                listener.close()


class OwnershipTests(unittest.TestCase):
    def test_only_owned_process_terminated_and_reaped(self):
        process = mock.Mock()
        process.poll.return_value = None
        runner.stop_owned(process)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=10)
        process.kill.assert_not_called()

    def test_stubborn_owned_process_killed_after_bounded_wait(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-qemu", 10), 0]
        runner.stop_owned(process)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)

    def test_already_exited_process_is_not_signalled(self):
        process = mock.Mock()
        process.poll.return_value = 0
        runner.stop_owned(process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_probe_exception_still_stops_owned_qemu_and_writes_failure_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "validation"
            process = mock.Mock(pid=1234, returncode=-15)
            process.poll.return_value = None
            with mock.patch.object(runner, "reserve_listeners", return_value={}), \
                    mock.patch.object(runner, "build_command", return_value=["owned-qemu"]), \
                    mock.patch.object(runner.subprocess, "Popen", return_value=process), \
                    mock.patch.object(runner, "accept_peers", return_value={}), \
                    mock.patch.object(runner, "run_connected", side_effect=RuntimeError("probe failure")):
                result = runner.validate(Path(directory), output)
            self.assertFalse(result["passed"])
            self.assertEqual(result["failure"], "probe failure")
            self.assertEqual(result["owned_qemu_pid"], 1234)
            self.assertTrue((output / "report.json").is_file())
            self.assertTrue((output / "packets.pcap").is_file())
            process.terminate.assert_called_once_with()


class SerialReportTests(unittest.TestCase):
    def test_squashfs_read_error_overrides_successful_packet_checks_and_later_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'validation'
            serial = (b'SQUASHFS error: Failed to read block 0xfaaea82: -5\n'
                      b'UDM_VIRTUAL_HAL_NATIVE_READY\nUDM_LAB_SELFTEST_PASS\n')
            process = mock.Mock(pid=1234, returncode=-15)
            process.poll.return_value = None

            def successful_packet_checks(*args, **kwargs):
                (output / 'serial.log').write_bytes(serial)
                return {'passed': True, 'failure': None}

            with mock.patch.object(runner, 'reserve_listeners', return_value={}), \
                    mock.patch.object(runner, 'build_command', return_value=['owned-qemu']), \
                    mock.patch.object(runner.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(runner, 'accept_peers', return_value={}), \
                    mock.patch.object(runner, 'run_connected', side_effect=successful_packet_checks):
                result = runner.validate(Path(directory), output)
            self.assertFalse(result['passed'])
            self.assertEqual(result['serial_fatal_markers'], ['SQUASHFS error:'])
            self.assertIn('SQUASHFS error:', result['failure'])
            self.assertEqual(json.loads((output / 'report.json').read_text()), result)
            self.assertEqual((output / 'serial.log').read_bytes(), serial)
            process.terminate.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
