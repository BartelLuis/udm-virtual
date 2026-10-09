"""Research-only hardware adaptation of this exact original UDAPI ELF.

Preserves normal Linux interface management and firewall/routing code. Five
changes suppress initialization/queries for an absent CPSS ASIC, returning empty
ASIC port/FDB containers. One additional change disables the physical board's
A12 manufacturing-record attestation, which cannot succeed with virtual EEPROM
metadata. This does not create manufacturer credentials or alter user login.
Must be paired with the skeletal-switch native-netdev board configuration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA256 = 'ccdda14e798184b7e10c8385c6b85d46df82695a4c9a0ec50e849bfab00416ec'
RESULT_SHA256 = 'd2460e19ea0e2fc883e2393f0312822a260dd301a01344adc70d763e860c5e7b'


def branch(source, destination):
    delta = destination - source
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3ffffff))


PATCHES = [
    (0x5a7a5c, bytes.fromhex('ffc301d1fd7b03a9'), bytes.fromhex('20008052c0035fd6'),
     'Virtual hardware: replace the cached physical manufacturing-record attestation predicate with true. '
     'No manufacturer identity/signature is created; account authentication is unchanged.'),
    (0x61ab70, bytes.fromhex('fd7bbaa9'), bytes.fromhex('c0035fd6'),
     'Skip global CPSS hardware initialization; caller has set API vtable.'),
    (0x620480, bytes.fromhex('a1e3fff0'), branch(0x620480, 0x620578),
     'MTD constructor retains vtable and NULL implementation; use normal epilogue.'),
    (0x621248, bytes.fromhex('161040f9'), branch(0x621248, 0x62159c),
     'Return fully initialized empty CPSS port map; bypass hardware CPU/edge port construction.'),
    (0x6296fc, bytes.fromhex('c1025b38'), branch(0x6296fc, 0x6297bc),
     'Switch actor retains udapi::Switch and empty vector; skip ASIC writes and ASIC actor creation.'),
    (0x630280, bytes.fromhex('fd7bbaa9fc6f01a9fa6702a9'), bytes.fromhex('1f7d00a91f0900f9c0035fd6'),
     'Return empty ASIC FDB vector using original x8 result ABI; do not open CPSS shared cache.'),
]


def patch(source, destination):
    source, destination = Path(source), Path(destination)
    report_path = destination.with_name(destination.name + '.json')
    original = source.read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Refusing unknown UDAPI binary. This adaptation is tied to one exact ELF.')
    if any(path.exists() or path.is_symlink() for path in (destination, report_path)):
        raise ValueError('Destination already exists')
    if original[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', original, 18)[0] != 183:
        raise ValueError('Expected ARM64 little-endian ELF64')
    phoff = struct.unpack_from('<Q', original, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', original, 54)
    segments = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, _, _ = struct.unpack_from('<II6Q', original, phoff + index * phsize)
        if kind == 1 and flags & 1:
            segments.append((offset, vaddr, filesz))
    result = bytearray(original)
    changes = []
    for address, expected, replacement, purpose in PATCHES:
        positions = [offset + address - vaddr for offset, vaddr, size in segments
                     if vaddr <= address and address + len(expected) <= vaddr + size]
        if len(positions) != 1 or len(expected) != len(replacement):
            raise ValueError('Invalid patch location')
        position = positions[0]
        if original[position:position + len(expected)] != expected:
            raise ValueError('Unexpected instructions at ' + hex(address))
        result[position:position + len(expected)] = replacement
        changes.append({'virtual_address': hex(address), 'file_offset': hex(position),
                        'before': expected.hex(), 'after': replacement.hex(), 'purpose': purpose})
    with destination.open('xb') as handle:
        handle.write(result)
    destination.chmod(0o755)
    report = {'status': 'hardware-adaptation-candidate',
              'source_sha256': SOURCE_SHA256, 'result_sha256': hashlib.sha256(result).hexdigest(),
              'source_size': len(original), 'result_size': len(result), 'changes': changes}
    with report_path.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('destination')
    arguments = parser.parse_args()
    print(json.dumps(patch(arguments.source, arguments.destination), indent=2))
