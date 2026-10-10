from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from virtualization import hal_guest


WAN = "00:50:56:01:1e:69"
IDENTITY = {"model": "UXGENT", "nics": 6, "mac": "02:55:44:4d:00:00",
            "uuid": "490af381-e496-499b-950b-0c19ba19f843", "credentials": "absent"}
OPTIONS = ["udm.mode=systemd", "udm.nics=6", "udm.wan_mac=" + WAN]


def ports():
    return [{"name": f"eth{(index + 2) % 6}", "driver": "virtio_net",
             "mac": WAN if index == 0 else f"02:55:44:4d:00:{index:02x}",
             "up": False, "addresses": [], "master": None} for index in range(6)]


def info():
    return "systemid=ea3e\nserialno=0255444d0000\nramsize=8053063680\ncpuid=000f0510\n" + "".join(
        f"eth{index}.macaddr=02:55:44:4d:00:{index:02x}\n" for index in range(6)) + "other=unchanged\n"


class WanOptionTests(unittest.TestCase):
    def test_override_requires_single_explicit_option_on_six_port_uxg(self):
        self.assertIsNone(hal_guest.wan_mac_option([], "UXGENT"))
        self.assertEqual(hal_guest.wan_mac_option(["udm.wan_mac=" + WAN.upper()], "UXGENT"), WAN)
        for options, model, nics in ((OPTIONS, "UDMEA4C", 14), (OPTIONS, "UXGENT", 5),
                                    (OPTIONS + [OPTIONS[-1]], "UXGENT", 6),
                                    (["udm.wan_mac"], "UXGENT", 6), (["udm.wan_mac="], "UXGENT", 6)):
            with self.subTest(options=options, model=model, nics=nics), self.assertRaises(ValueError):
                hal_guest.wan_mac_option(options, model, nics)

    def test_multicast_zero_and_malformed_network_addresses_rejected(self):
        for address in ("01:50:56:01:1e:69", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
                        "00:50:56:01:1e", "00:50:56:01:1e:69 extra", None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                hal_guest.validate_wan_mac(address, "UXGENT")


class WanOrderTests(unittest.TestCase):
    def test_network_wan_address_never_becomes_device_identity(self):
        ordered = hal_guest.interface_order(ports(), 6, WAN, "UXGENT")
        self.assertEqual(ordered[0]["mac"], WAN)
        self.assertEqual(hal_guest.identity_mac_from_ports(ordered, WAN), IDENTITY["mac"])
        self.assertEqual([item["mac"] for item in ordered[1:]],
                         [f"02:55:44:4d:00:{index:02x}" for index in range(1, 6)])
        with self.assertRaises(ValueError):
            hal_guest.interface_order(ports(), 6)

    def test_missing_duplicate_wan_and_bad_lan_block_rejected(self):
        malformed = []
        for index, address in ((0, "00:50:56:01:1e:68"), (1, WAN),
                               (3, "02:55:44:4d:00:04"), (3, "00:55:44:4d:00:03")):
            rows = ports()
            rows[index]["mac"] = address
            malformed.append(rows)
        rows = ports()
        for index in range(1, 6):
            rows[index]["mac"] = f"02:55:44:00:00:{index - 1:02x}"
        malformed.append(rows)
        for rows in malformed:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                hal_guest.interface_order(rows, 6, WAN, "UXGENT")

    def test_normalization_uses_explicit_wan_and_preserves_all_six_macs(self):
        live = {item["name"]: deepcopy(item) for item in ports()}
        calls = []

        def run(*args):
            calls.append(args)
            source, target = args[4], args[6]
            self.assertNotIn(target, live)
            item = live.pop(source)
            item["name"] = target
            live[target] = item

        with patch.object(hal_guest, "require_guest", return_value=OPTIONS), \
                patch.object(Path, "read_text", return_value="init\n"), \
                patch.object(Path, "exists", return_value=False):
            base = hal_guest.normalize_virtual_interfaces(
                read=lambda: deepcopy(list(live.values())), run=run, nics=6, model="UXGENT")
        self.assertEqual(base, IDENTITY["mac"])
        self.assertEqual(live["eth0"]["mac"], WAN)
        self.assertEqual(len(calls), 12)

    def test_sysfs_validation_accepts_override_only_on_eth0(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(6):
                entry = root / f"eth{index}"
                entry.mkdir()
                (entry / "address").write_text(WAN if index == 0 else f"02:55:44:4d:00:{index:02x}")
            with patch.object(Path, "resolve", return_value=Path("/drivers/virtio_net")):
                hal_guest.validate_interfaces(IDENTITY["mac"], 6, root, WAN, "UXGENT")
                with self.assertRaises(ValueError):
                    hal_guest.validate_interfaces(IDENTITY["mac"], 6, root)
                (root / "eth3/address").write_text(WAN)
                with self.assertRaises(ValueError):
                    hal_guest.validate_interfaces(IDENTITY["mac"], 6, root, WAN, "UXGENT")


class WanProcViewTests(unittest.TestCase):
    def test_only_eth0_public_value_changes(self):
        original = info()
        adapted = hal_guest.wan_system_info(original, IDENTITY, WAN)
        self.assertEqual(adapted, original.replace("eth0.macaddr=" + IDENTITY["mac"], "eth0.macaddr=" + WAN))
        self.assertEqual(adapted, hal_guest.wan_system_info(adapted, IDENTITY, WAN))
        self.assertIn("serialno=0255444d0000\n", adapted)
        self.assertIn("ramsize=8053063680\n", adapted)

    def test_wrong_identity_or_ambiguous_mac_fields_refused(self):
        for broken in (info().replace("ea3e", "ea4c"), info().replace("0255444d0000", "ffffffffffff"),
                       info() + "eth0.macaddr=" + WAN + "\n",
                       info().replace("eth3.macaddr=02:55:44:4d:00:03\n", ""),
                       info().replace("eth4.macaddr=02:55:44:4d:00:04", "eth4.macaddr=" + WAN)):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                hal_guest.wan_system_info(broken, IDENTITY, WAN)

    def test_install_binds_only_readonly_system_info_and_checks_kernel_option(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir()
            target = Path(directory) / "system.info"
            target.write_text(info())
            calls = []
            with patch.object(hal_guest, "require_guest", return_value=OPTIONS):
                hal_guest.install_wan_system_info(IDENTITY, WAN, runtime, target,
                                                  run=lambda *args: calls.append(args))
            source = runtime / "proc-system-info"
            self.assertEqual(source.read_text(), hal_guest.wan_system_info(info(), IDENTITY, WAN))
            self.assertEqual(calls, [("/bin/mount", "--bind", str(source), str(target)),
                                     ("/bin/mount", "-o", "remount,bind,ro", str(target))])
            self.assertEqual(target.read_text(), info())  # Mocked mount never edits original.
            source.chmod(0o600)
            source.unlink()
            with patch.object(hal_guest, "require_guest", return_value=OPTIONS[:2]):
                with self.assertRaisesRegex(ValueError, "explicit kernel option"):
                    hal_guest.install_wan_system_info(IDENTITY, WAN, runtime, target,
                                                      run=lambda *args: self.fail("No mount allowed"))
            self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
