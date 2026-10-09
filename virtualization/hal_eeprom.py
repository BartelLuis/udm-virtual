#!/usr/bin/env python3
"""Generate public board metadata for an isolated virtual UDM guest.

This is NOT an image for flashing a physical UDM. No manufacturer credentials,
certificates, real device serial, or production MAC OUI are included. The native
ubnthal 6.6.46-ui-cn10k module reads this EEPROM via ordinary kernel file I/O.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid
import zlib


def mac_bytes(value):
    if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
        raise ValueError("MAC requires six hexadecimal octets")
    base = bytes.fromhex(value.replace(":", ""))
    if base[0] & 3 != 2:
        raise ValueError("MAC must be locally administered and unicast")
    return base


def cyg_crc32(payload):
    """Native cyg_crc32 has initial accumulator zero and no final complement."""
    return zlib.crc32(payload, 0xffffffff) ^ 0xffffffff


def spi_identity(vm_uuid):
    """Derive PUBLIC emulated flash metadata, not a hardware-auth credential."""
    identity = uuid.UUID(str(vm_uuid))
    digest = hashlib.sha256(b"udm-virtual-spi-public-identity\0" + identity.bytes).digest()
    # A virtual chip identifier and UID. Neither is copied from a physical
    # device. Firmware compares these public values with its EEPROM record.
    jedec = int.from_bytes(digest[:3], "big") or 1
    return jedec, digest[3:19]


def make_eeprom(mac="02:55:44:4d:00:00", nics=14, vm_uuid=None):
    base = mac_bytes(mac)
    if not 2 <= nics <= 14:
        raise ValueError("Expected 2..14 virtual interfaces")
    if int.from_bytes(base[3:], "big") + nics > 0x1000000:
        raise ValueError("MAC block overflows low 24 bits")
    identity = uuid.UUID(str(vm_uuid)) if vm_uuid else uuid.uuid4()
    image = bytearray(65536)
    # Legacy public fallback: two MACs followed by board/vendor/BOM revision.
    image[:6] = base
    image[6:12] = (int.from_bytes(base, "big") + 1).to_bytes(6, "big")
    struct.pack_into(">HHI", image, 0xc, 0xea4c, 0x0777, 1)
    # Modern version-1 board descriptor at 0x8000. All fields are network order
    # except CRC, which the actual little-endian native module reads raw.
    start, length = 0x8000, 100
    image[start:start + 4] = b"UBNT"
    struct.pack_into(">IHHHHI", image, start + 8, length, 2, 1, 0x0777, 0xea4c, 1)
    image[start + 0x18:start + 0x1e] = base
    image[start + 0x1e] = nics
    crc = cyg_crc32(image[start + 12:start + 12 + length])
    struct.pack_into("<I", image, start + 4, crc)
    # ubnt-tools reads the serial through a separate public manufacturing
    # metadata record. Its serial is our LOCAL virtual MAC, not a genuine
    # appliance identity. No credentials, certificate, signature or token.
    image[0xa000] = 1
    struct.pack_into(">H", image, 0xa01e, 0xea4c)
    struct.pack_into(">H", image, 0xa020, 0x0777)
    image[0xa022:0xa028] = base
    jedec, spi_uid = spi_identity(identity)
    struct.pack_into(">I", image, 0xa02e, jedec)
    image[0xa032] = len(spi_uid)
    image[0xa033:0xa043] = spi_uid
    # Local uniqueness only. Native module derives its anonymized ID from this
    # and the local MAC. Credential-bearing regions remain zero.
    image[0xe040:0xe048] = hashlib.sha256(identity.bytes).digest()[:8]
    return bytes(image), identity


def inspect_eeprom(image):
    if len(image) != 65536:
        raise ValueError("EEPROM file must be exactly 65536 bytes")
    start = 0x8000
    if image[start:start + 4] != b"UBNT":
        raise ValueError("Missing descriptor magic")
    length, form, version, vendor, board, revision = struct.unpack_from(">IHHHHI", image, start + 8)
    if (length, form, version, vendor, board, revision) != (100, 2, 1, 0x0777, 0xea4c, 1):
        raise ValueError("Unexpected public board descriptor")
    if struct.unpack_from("<I", image, start + 4)[0] != cyg_crc32(image[start + 12:start + 12 + length]):
        raise ValueError("Descriptor CRC mismatch")
    mac = ":".join(f"{byte:02x}" for byte in image[start + 0x18:start + 0x1e])
    mac_bytes(mac)
    nics = image[start + 0x1e]
    if not 2 <= nics <= 14:
        raise ValueError("Unexpected NIC count")
    if (image[0xa000] != 1 or struct.unpack_from(">H", image, 0xa01e)[0] != 0xea4c
            or struct.unpack_from(">H", image, 0xa020)[0] != 0x0777):
        raise ValueError("Invalid public local serial record")
    if image[0xa022:0xa028] != image[start + 0x18:start + 0x1e]:
        raise ValueError("Public serial must equal locally administered virtual MAC")
    jedec = struct.unpack_from(">I", image, 0xa02e)[0]
    if not 0 < jedec <= 0xffffff or image[0xa032] != 16:
        raise ValueError("Invalid public virtual SPI identity")
    if any(image[0xa001:0xa01e]) or any(image[0xa028:0xa02e]) or any(image[0xa043:0xe000]):
        raise ValueError("Credential area must remain absent")
    return {"model": "UDMEA4C", "boardid": "ea4c", "boardrevision": revision,
            "mac": mac, "serial": image[0xa022:0xa028].hex(), "nics": nics,
            "spi_jedec_id": f"{jedec:08x}", "spi_uid": image[0xa033:0xa043].hex(),
            "credentials": "absent", "virtual": True}


def make_payload(mac="02:55:44:4d:00:00", nics=14, vm_uuid=None):
    """Return {simple filename: bytes} for initramfs embedding, no host actions.

    Preserve vm_uuid and mac in the VM manifest to rebuild the same identity.
    The adjacent hal_guest.py consumes this payload after mounting proc, sys,
    dev and run in the original firmware root, before systemd starts.
    """
    image, identity = make_eeprom(mac, nics, vm_uuid)
    manifest = inspect_eeprom(image)
    manifest.update({"status": "experimental-public-hardware-profile", "vm_uuid": str(identity),
                     "sha256": hashlib.sha256(image).hexdigest(),
                     "identity_origin": "locally-generated-virtual-machine",
                     "warning": "Regular file for isolated guest only; NEVER flash physical hardware"})
    payload = {
        "eeprom.bin": image,
        # Native ubnthal uses uppercase. Native UDAPI uses lowercase, with
        # mtdblock5 as fallback. Both are aliases of one read-only virtual file.
        "proc-mtd": (b'dev:    size   erasesize  name\nmtd0: 00010000 00010000 "EEPROM"\n'
                     b'mtd5: 00010000 00010000 "eeprom"\n'),
        # Parser compatibility view only; architectural registers are unchanged.
        "proc-cpumidr": b"0x410fd490\n",
        "expected-serial": (manifest["serial"] + "\n").encode("ascii"),
        "spi-jedec-id": (manifest["spi_jedec_id"] + "\n").encode("ascii"),
        "spi-uid": (manifest["spi_uid"] + "\n").encode("ascii"),
        "manifest.json": (json.dumps(manifest, indent=2) + "\n").encode("ascii"),
    }
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory")
    parser.add_argument("--mac", default="02:55:44:4d:00:00")
    parser.add_argument("--nics", type=int, default=14)
    parser.add_argument("--vm-uuid", type=uuid.UUID)
    args = parser.parse_args()
    payload = make_payload(args.mac, args.nics, args.vm_uuid)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in payload.items():
        (args.output / name).write_bytes(data)
    print(args.output)


if __name__ == "__main__":
    main()
