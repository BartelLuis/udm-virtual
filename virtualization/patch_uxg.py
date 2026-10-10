"""Adapt the physical A12 manufacturing check in exact UXGENT 5.1.26 UDAPI.

The original predicate reads manufacturing EEPROM and issues /dev/sflash
ioctls for the physical flash identity. QEMU virt does not emulate that SoC
device. Replace only that cached predicate with true for this explicit virtual
hardware build. This disables physical hardware attestation; it does not mint
manufacturer credentials or change user/account authentication. No CPSS,
network, firewall, routing, or controller-adoption code is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


SOURCE_SHA256 = "7fa7f011c8b1dc03448c0e42b15af87feb775279c657fc7346ea3b3c43227d91"
RESULT_SHA256 = "aa4fb660da680276389287a099ac0a0ac1cdc584aa396fb71156183f31b1f3ac"
ADDRESS = 0x5a4220
EXPECTED = bytes.fromhex("ffc301d1fd7b03a9")
REPLACEMENT = bytes.fromhex("20008052c0035fd6")  # mov w0, #1; ret


def _location(original):
    if (len(original) < 64 or original[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", original, 18)[0] != 183):
        raise ValueError("Expected ARM64 little-endian ELF64")
    phoff = struct.unpack_from("<Q", original, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", original, 54)
    if phsize < 56 or not phnum or phoff < 64 or phoff + phsize * phnum > len(original):
        raise ValueError("Invalid ELF program header bounds")
    positions = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, _, _ = struct.unpack_from(
            "<II6Q", original, phoff + index * phsize)
        if kind != 1:
            continue
        if offset + filesz > len(original):
            raise ValueError("ELF segment exceeds file bounds")
        if flags & 1 and vaddr <= ADDRESS and ADDRESS + len(EXPECTED) <= vaddr + filesz:
            positions.append(offset + ADDRESS - vaddr)
    if len(positions) != 1 or len(EXPECTED) != len(REPLACEMENT):
        raise ValueError("Invalid or ambiguous executable patch location")
    return positions[0]


def patch(source, destination):
    """Write a new adapted ELF and adjacent .json report, refusing overwrites."""
    source, destination = Path(source), Path(destination)
    report_path = destination.with_name(destination.name + ".json")
    if any(path.exists() or path.is_symlink() for path in (destination, report_path)):
        raise ValueError("Destination already exists")
    original = source.read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError("Refusing unknown UXG UDAPI binary; exact original firmware is required")
    position = _location(original)
    if original[position:position + len(EXPECTED)] != EXPECTED:
        raise ValueError("Unexpected instructions at " + hex(ADDRESS))
    result = original[:position] + REPLACEMENT + original[position + len(EXPECTED):]
    digest = hashlib.sha256(result).hexdigest()
    if digest != RESULT_SHA256:
        raise ValueError("Adapted binary does not match the pinned result hash")
    report = {
        "status": "experimental-virtual-hardware-adaptation",
        "model": "UXGENT", "firmware": "5.1.26",
        "source_sha256": SOURCE_SHA256, "result_sha256": digest,
        "source_size": len(original), "result_size": len(result),
        "changes": [{"virtual_address": hex(ADDRESS), "file_offset": hex(position),
                     "before": EXPECTED.hex(), "after": REPLACEMENT.hex(),
                     "purpose": "Disable the physical A12 manufacturing/flash-identity predicate for QEMU virt. "
                                "Manufacturer credentials and user authentication are unchanged."}],
    }
    # Reserve both names before populating either. A colliding report is not
    # allowed to leave a new executable behind, even if created concurrently.
    with destination.open("xb") as output:
        try:
            metadata = report_path.open("x", encoding="utf-8")
        except BaseException:
            output.close()
            destination.unlink()
            raise
        try:
            with metadata:
                output.write(result)
                json.dump(report, metadata, indent=2)
                metadata.write("\n")
            destination.chmod(0o755)
        except BaseException:
            output.close()
            destination.unlink()
            report_path.unlink()
            raise
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(patch(args.source, args.destination), indent=2))
