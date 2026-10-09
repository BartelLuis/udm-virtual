import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import uuid

from virtualization.hal_eeprom import cyg_crc32, inspect_eeprom, make_eeprom, make_payload, spi_identity
from virtualization.hal_guest import install_spi_view, local_identity, validate_cli_identity


class EepromTests(unittest.TestCase):
    def test_descriptor_matches_native_driver_offsets(self):
        identity = uuid.UUID("490af381-e496-499b-950b-0c19ba19f843")
        raw, actual = make_eeprom(vm_uuid=identity)
        self.assertEqual(actual, identity)
        self.assertEqual(len(raw), 65536)
        self.assertEqual(raw[0x8000:0x8004], b"UBNT")
        self.assertEqual(struct.unpack_from(">IHHHHI", raw, 0x8008),
                         (100, 2, 1, 0x0777, 0xea4c, 1))
        self.assertEqual(raw[0x8018:0x801f], bytes.fromhex("0255444d00000e"))
        self.assertEqual(raw[0xe040:0xe048], hashlib.sha256(identity.bytes).digest()[:8])
        self.assertEqual(inspect_eeprom(raw)["mac"], "02:55:44:4d:00:00")
        self.assertEqual(raw[0xa000], 1)
        self.assertEqual(raw[0xa020:0xa028], bytes.fromhex("07770255444d0000"))
        self.assertFalse(any(raw[0xa001:0xa01e]))
        self.assertEqual(struct.unpack_from(">H", raw, 0xa01e)[0], 0xea4c)
        self.assertFalse(any(raw[0xa028:0xa02e]))
        self.assertFalse(any(raw[0xa043:0xe000]))
        jedec, spi_uid = spi_identity(identity)
        self.assertEqual(struct.unpack_from(">I", raw, 0xa02e)[0], jedec)
        self.assertEqual(raw[0xa032], 16)
        self.assertEqual(raw[0xa033:0xa043], spi_uid)

    def test_crc_agrees_with_independent_bitwise_accumulator(self):
        # Actual native cyg_crc32: reflected IEEE table, init=0/finalxor=0.
        payload = bytes(range(256))
        expected = 0
        for byte in payload:
            expected ^= byte
            for _ in range(8):
                expected = (expected >> 1) ^ (0xedb88320 if expected & 1 else 0)
        self.assertEqual(cyg_crc32(payload), expected)
        self.assertEqual(cyg_crc32(b""), 0)

    def test_legacy_cli_view_matches_modern_kernel_view(self):
        raw, _ = make_eeprom()
        self.assertEqual(raw[:12], bytes.fromhex("0255444d00000255444d0001"))
        self.assertEqual(struct.unpack_from(">HHI", raw, 12), (0xea4c, 0x0777, 1))
        self.assertEqual(raw[:6], raw[0x8018:0x801e])
        self.assertEqual(raw[0xa022:0xa028], raw[0:6])

    def test_bad_crc_and_truncated_eeprom_rejected(self):
        raw, _ = make_eeprom()
        damaged = bytearray(raw)
        damaged[0x8040] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            inspect_eeprom(damaged)
        with self.assertRaisesRegex(ValueError, "65536"):
            inspect_eeprom(raw[:-1])

    def test_credentials_must_stay_absent(self):
        raw, _ = make_eeprom()
        damaged = bytearray(raw)
        damaged[0xb000] = 1
        with self.assertRaisesRegex(ValueError, "[Cc]redential"):
            inspect_eeprom(damaged)

    def test_payload_reproducible_and_cli_serial_matches_kernel_mac(self):
        identity = uuid.UUID("490af381-e496-499b-950b-0c19ba19f843")
        first = make_payload(vm_uuid=identity)
        self.assertEqual(first, make_payload(vm_uuid=identity))
        self.assertEqual(first["proc-cpumidr"], b"0x410fd490\n")
        self.assertEqual(first["expected-serial"], b"0255444d0000\n")
        image = first["eeprom.bin"]
        self.assertEqual(int(first["spi-jedec-id"], 16), struct.unpack_from(">I", image, 0xa02e)[0])
        self.assertEqual(bytes.fromhex(first["spi-uid"].decode().strip()), image[0xa033:0xa043])
        self.assertIn(b'mtd0: 00010000 00010000 "EEPROM"', first["proc-mtd"])
        self.assertIn(b'mtd5: 00010000 00010000 "eeprom"', first["proc-mtd"])
        for name in first:
            self.assertNotIn("/", name)
            self.assertNotIn("..", name)

    def test_spi_identity_is_local_stable_and_changes_with_vm_uuid(self):
        first = uuid.UUID("490af381-e496-499b-950b-0c19ba19f843")
        second = uuid.UUID("490af381-e496-499b-950b-0c19ba19f844")
        self.assertEqual(spi_identity(first), spi_identity(first))
        self.assertNotEqual(spi_identity(first), spi_identity(second))
        self.assertEqual(len(spi_identity(first)[1]), 16)

    def test_physical_oui_multicast_overflow_and_bad_count_rejected(self):
        for mac in ["00:11:22:33:44:55", "03:11:22:33:44:55", "invalid", "02:55:44:ff:ff:ff"]:
            with self.subTest(mac=mac), self.assertRaises(ValueError):
                make_eeprom(mac=mac)
        for count in (0, 1, 15, 256):
            with self.subTest(count=count), self.assertRaises(ValueError):
                make_eeprom(nics=count)


class CliIdentityTests(unittest.TestCase):
    output = "board.sysid=0xea4c\nboard.shortname=UDMEA4C\nboard.serialno=0255444d0000\n"
    identity = {"mac": "02:55:44:4d:00:00"}

    def test_real_cli_output_accepted(self):
        validate_cli_identity(self.output, self.identity)

    def test_generic_fallback_and_bad_local_serial_rejected(self):
        for bad in (self.output.replace("0xea4c", "0x0000"),
                    self.output.replace("UDMEA4C", "ARMv8"),
                    self.output.replace("0255444d0000", "ffffffffffff"), ""):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                validate_cli_identity(bad, self.identity)


class SpiViewTests(unittest.TestCase):
    def test_only_empty_spi_class_gets_readonly_metadata_view(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            target = Path(directory) / "spi_master"
            runtime.mkdir()
            target.mkdir()
            payload = make_payload()
            for name in ("spi-jedec-id", "spi-uid"):
                (runtime / name).write_bytes(payload[name])
            commands = []
            install_spi_view(runtime, target, run=lambda *args: commands.append(args))
            device = runtime / "spi-master/spi0/spi0.0/spi-nor"
            self.assertEqual((device / "jedec_id").read_bytes(), payload["spi-jedec-id"])
            self.assertEqual((device / "uid").read_bytes(), payload["spi-uid"])
            self.assertEqual(commands, [
                ("/bin/mount", "--bind", str(runtime / "spi-master"), str(target)),
                ("/bin/mount", "-o", "remount,bind,ro", str(target)),
            ])
            if os.name != "nt":
                self.assertEqual((device / "uid").stat().st_mode & 0o777, 0o444)

    def test_populated_spi_class_is_never_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            target = Path(directory) / "spi_master"
            target.mkdir()
            (target / "spi-existing").mkdir()
            commands = []
            with self.assertRaisesRegex(ValueError, "empty"):
                install_spi_view(runtime, target, run=lambda *args: commands.append(args))
            self.assertEqual(commands, [])
            self.assertFalse(runtime.exists())


@unittest.skipIf(os.name == "nt", "Guest persistence semantics require Linux directory fsync")
class GuestIdentityTests(unittest.TestCase):
    def test_identity_persists_uuid_across_reboots(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "virtual" / "identity.json"
            first = local_identity("02:55:44:4d:00:00", 14, path)
            second = local_identity("02:55:44:4d:00:00", 14, path)
            self.assertEqual(first, second)
            self.assertEqual(uuid.UUID(first["uuid"]).version, 4)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())["credentials"], "absent")

    def test_mac_or_count_changes_do_not_replace_persistent_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            local_identity("02:55:44:4d:00:00", 14, path)
            before = path.read_bytes()
            for mac, count in (("02:55:44:4d:00:01", 14), ("02:55:44:4d:00:00", 2)):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    local_identity(mac, count, path)
                self.assertEqual(path.read_bytes(), before)

    def test_identity_symlink_and_global_mac_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            with self.assertRaisesRegex(ValueError, "locally administered"):
                local_identity("00:55:44:4d:00:00", 14, path)
            self.assertFalse(path.exists())
            path.symlink_to(Path(directory) / "unrelated")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                local_identity("02:55:44:4d:00:00", 14, path)


if __name__ == "__main__":
    unittest.main()
