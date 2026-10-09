"""Exact-version native-port and authenticated GCM cache adaptation.

Only ten invokevirtual constant-pool references in seedPortTable are changed.
The two existing instance helpers have the same owner, arguments and return
type. A second class reconciles the full device cache on every authenticated
GCM inform using the original setter. It retains the AES_GCM enum guard and
all cryptographic checks; the extra cache invalidation affects every GCM device.
Bytecode lengths, branch offsets and stack maps are preserved.

Build with patch(); ship its nested JAR, this script and returned hash metadata.
Install with install(): it streams the outer archive without recompressing any
unchanged entry, preserving Spring Boot's STORED nested libraries exactly.
"""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import zipfile
import zlib


SOURCE_SHA256 = '7b8decf39bb8787c29367901aff2a28fedff1571ecde5f9203be5ac61e04202d'
NESTED_SHA256 = '56507c3484f9babca9d735b9a295606230cc9c89e2ee22bf7926712bd6f9a83c'
CLASS_SHA256 = '4582e67a4893425e77bf6a88de1098df4d80d12eb980f49231f5a0793f9782f7'
RESULT_CLASS_SHA256 = '8bcb79ab64a10ceee28183a0993ebd7fd4f86490ed16fd8ffa320f47bf0f0f5f'
METHOD_SHA256 = '124464c5bc11303886b47a49a3db79cb689d5f6d31713aa450f4dc8a8e3124ff'
RESULT_METHOD_SHA256 = '13cde8af5e90617731038d3b1bcda3f4b6e4d37fd654b8511e595759703aeaaf'
NESTED_NAME = 'BOOT-INF/lib/internal-dependencies.jar'
CLASS_NAME = 'com/ubnt/data/NYCLZfielo.class'
CLASS_OWNER = CLASS_NAME[:-6]
HELPER_DESCRIPTOR = '(Ljava/lang/String;Ljava/lang/String;)Lcom/ubnt/data/pfELyUmQb;'
METHOD_OFFSET, METHOD_SIZE = 113425, 4801
PATCH_OFFSETS = (3040, 3055, 3070, 3085, 3100, 3115, 3134, 3149, 3164, 3179)
OLD_CALL, NEW_CALL = bytes.fromhex('b605b0'), bytes.fromhex('b60467')
GCM_CLASS_NAME = 'com/ubnt/service/devmgr/l/xTAqASU.class'
GCM_CLASS_SHA256 = '5a748cc3b39517274e7b5a80541b106c3a26db3366fc425efe578a935c0c432e'
GCM_RESULT_CLASS_SHA256 = 'eaec94b020bfae34ebd714e19fcb557b6fb0abffc07fe36cdaf98383fdb70126'
GCM_METHOD_NAME = 'bUGnmQhkcUmRE'
GCM_DESCRIPTOR = '(Ljava/lang/String;Lcom/ubnt/data/NYCLZfielo;Lcom/ubnt/net/VqUfr;)V'
GCM_CODE_OFFSET, GCM_CODE_SIZE, GCM_PATCH_OFFSET = 46604, 70, 14
GCM_CODE_SHA256 = 'c35dde869e2936d531a0bfee026d74fb272a3e089545b3935b06a444527ddb03'
GCM_RESULT_CODE_SHA256 = 'da49f0067f6bd91b42d8d3c38bde0613f79be90559493cd09bf761b9122b7375'
GCM_BEFORE, GCM_AFTER = bytes.fromhex('9a0037'), bytes.fromhex('570000')
GCM_STACK_MAP = bytes.fromhex('0001ff004500000000')


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def require_hash(data, expected, what):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Unsupported ' + what + ' SHA256')


def guard_archive(archive):
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError('Duplicate ZIP members refused')
    for info in archive.infolist():
        name = info.filename.upper()
        if info.flag_bits & 1:
            raise ValueError('Encrypted ZIP members refused')
        if name.startswith('META-INF/'):
            signature = name.endswith(('.SF', '.RSA', '.DSA', '.EC')) or name.startswith('META-INF/SIG-')
            # The exact source outer JAR contains this empty Spring Boot marker.
            # Preserve it; it has no signature data, digest or certificate.
            empty_boot_marker = info.filename == 'META-INF/BOOT.SF' and archive.read(info) == b''
            if signature and not empty_boot_marker:
                raise ValueError('Signed JAR refused: ' + info.filename)
            if name == 'META-INF/MANIFEST.MF' and b'-DIGEST' in archive.read(info).upper():
                raise ValueError('JAR manifest digests refused')


def constant_pool(data):
    if data[:4] != b'\xca\xfe\xba\xbe':
        raise ValueError('Expected JVM class file')
    count = struct.unpack_from('>H', data, 8)[0]
    pool, offset, index = {}, 10, 1
    widths = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4,
              11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        tag = data[offset]
        offset += 1
        if tag == 1:
            size = struct.unpack_from('>H', data, offset)[0]
            offset += 2
        else:
            if tag not in widths:
                raise ValueError('Unsupported constant-pool tag')
            size = widths[tag]
        if offset + size > len(data):
            raise ValueError('Truncated constant pool')
        pool[index] = (tag, data[offset:offset + size])
        offset += size
        index += 2 if tag in (5, 6) else 1
    return pool


def resolve_helper(pool, reference, tag=10):
    def item(index, tag):
        actual, value = pool[index]
        if actual != tag:
            raise ValueError('Unexpected constant-pool reference type')
        return value
    owner, name_type = struct.unpack('>HH', item(reference, tag))
    owner_name = struct.unpack('>H', item(owner, 7))[0]
    name, descriptor = struct.unpack('>HH', item(name_type, 12))
    return tuple(item(index, 1).decode('ascii') for index in (owner_name, name, descriptor))


def patch_class(original):
    require_hash(original, CLASS_SHA256, 'controller class')
    pool = constant_pool(original)
    old = resolve_helper(pool, int.from_bytes(OLD_CALL[1:], 'big'))
    new = resolve_helper(pool, int.from_bytes(NEW_CALL[1:], 'big'))
    if old != (CLASS_OWNER, 'lEkkVNXwpABkU', HELPER_DESCRIPTOR):
        raise ValueError('Unexpected switch helper')
    if new != (CLASS_OWNER, 'ROhmZrYJh', HELPER_DESCRIPTOR):
        raise ValueError('Unexpected native-interface helper')
    # Same invokevirtual opcode + owner + descriptor proves the same stack
    # consumption/production and receiver/argument count at every changed call.
    if OLD_CALL[0] != 0xb6 or NEW_CALL[0] != 0xb6 or len(OLD_CALL) != len(NEW_CALL):
        raise ValueError('Call opcode or length changed')
    method = original[METHOD_OFFSET:METHOD_OFFSET + METHOD_SIZE]
    require_hash(method, METHOD_SHA256, 'seedPortTable method')
    result = bytearray(original)
    for relative in PATCH_OFFSETS:
        offset = METHOD_OFFSET + relative
        if not 0 <= relative <= METHOD_SIZE - 3 or original[offset:offset + 3] != OLD_CALL:
            raise ValueError('Unexpected helper call at method offset ' + str(relative))
        result[offset:offset + 3] = NEW_CALL
    require_hash(result[METHOD_OFFSET:METHOD_OFFSET + METHOD_SIZE], RESULT_METHOD_SHA256, 'adapted method')
    require_hash(result, RESULT_CLASS_SHA256, 'adapted controller class')
    return bytes(result)


def patch_gcm_class(original):
    """Reconcile actual authenticated GCM capability; never set readiness/state.

    Fixed class, method and result hashes guard the offsets. The extra checks
    independently verify the public method, Code envelope, unchanged terminal
    frame and actual enum Fieldref without a Java parser dependency.
    """
    require_hash(original, GCM_CLASS_SHA256, 'GCM listener class')
    if original[4:8] != b'\0\0\0E':
        raise ValueError('Unexpected GCM listener class version')
    pool = constant_pool(original)

    def utf8(index):
        tag, data = pool[index]
        if tag != 1:
            raise ValueError('Unexpected GCM listener UTF8 reference')
        return data.decode('ascii')

    start, end = GCM_CODE_OFFSET, GCM_CODE_OFFSET + GCM_CODE_SIZE
    access, name, descriptor, attrs, code_attr, attr_size, stack, locals_, length = struct.unpack(
        '>HHHHHIHHI', original[start - 22:start])
    if ((access, attrs, stack, locals_, length, attr_size) != (1, 2, 4, 6, 70, 97)
            or (utf8(name), utf8(descriptor), utf8(code_attr)) !=
            (GCM_METHOD_NAME, GCM_DESCRIPTOR, 'Code')):
        raise ValueError('Unexpected GCM listener method envelope')
    code = original[start:end]
    require_hash(code, GCM_CODE_SHA256, 'GCM listener method')
    if (code[:2] != b'\x2d\xb2' or code[4:7] != b'\xa6\x00\x41'
            or code[GCM_PATCH_OFFSET:GCM_PATCH_OFFSET + 3] != GCM_BEFORE):
        raise ValueError('Unexpected GCM authentication enum guard or cache branch')
    enum_reference = int.from_bytes(code[2:4], 'big')
    if resolve_helper(pool, enum_reference, tag=9) != (
            'com/ubnt/net/VqUfr', 'ROhmZrYJh', 'Lcom/ubnt/net/VqUfr;'):
        raise ValueError('Unexpected authenticated AES_GCM enum identity')
    exceptions, attributes, frame_name, frame_size = struct.unpack('>HHHI', original[end:end + 10])
    if ((exceptions, attributes, frame_size) != (0, 1, len(GCM_STACK_MAP))
            or utf8(frame_name) != 'StackMapTable'
            or original[end + 10:end + 10 + frame_size] != GCM_STACK_MAP):
        raise ValueError('Unexpected GCM listener exception table or stack frame')
    # IFNE and POP both consume exactly one category-1 boolean. Two NOPs keep
    # every original offset and frame; the authenticated-mode guard still exits
    # at offset69 for CBC and never reaches the existing GCM setter in that case.
    result = bytearray(original)
    position = start + GCM_PATCH_OFFSET
    result[position:position + 3] = GCM_AFTER
    require_hash(result[start:end], GCM_RESULT_CODE_SHA256, 'adapted GCM listener method')
    require_hash(result, GCM_RESULT_CLASS_SHA256, 'adapted GCM listener class')
    return bytes(result)


def copy_bytes(source, destination, length):
    while length:
        block = source.read(min(length, 1024 * 1024))
        if not block:
            raise ValueError('Truncated ZIP source')
        destination.write(block)
        length -= len(block)


def replace_stored_member(source, destination, name, replacement):
    """Replace one ordinary STORED member, preserving other raw ZIP bytes.

    This deliberately rejects ZIP64, split archives, encrypted entries, ZIP
    preambles and target data descriptors. The exact firmware uses none of
    these. Only target CRC/sizes and central-directory offsets are rewritten.
    """
    source, destination, replacement = map(Path, (source, destination, replacement))
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination already exists')
    size, crc = replacement.stat().st_size, 0
    with replacement.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            crc = zlib.crc32(block, crc)
    with zipfile.ZipFile(source) as archive:
        guard_archive(archive)
        info = archive.getinfo(name)
        if info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 9:
            raise ValueError('Target must be unencrypted STORED ZIP without data descriptor')
        directory_offset = archive.start_dir
    with source.open('rb') as stream:
        if stream.read(4) != b'PK\x03\x04':
            raise ValueError('ZIP preambles refused')
        stream.seek(directory_offset)
        directory = bytearray()
        delta = size - info.compress_size
        while True:
            signature = stream.read(4)
            if signature != b'PK\x01\x02':
                break
            entry = bytearray(signature + stream.read(42))
            if len(entry) != 46:
                raise ValueError('Truncated central directory')
            filename_size, extra_size, comment_size, disk = struct.unpack_from('<4H', entry, 28)
            if disk or 0xffffffff in struct.unpack_from('<3I', entry, 16)[1:]:
                raise ValueError('ZIP64 or split archive refused')
            local_offset = struct.unpack_from('<I', entry, 42)[0]
            if local_offset == 0xffffffff:
                raise ValueError('ZIP64 offsets refused')
            if local_offset == info.header_offset:
                struct.pack_into('<3I', entry, 16, crc, size, size)
            elif local_offset > info.header_offset:
                struct.pack_into('<I', entry, 42, local_offset + delta)
            directory.extend(entry)
            directory.extend(stream.read(filename_size + extra_size + comment_size))
        if signature != b'PK\x05\x06':
            raise ValueError('Expected ordinary end of central directory')
        ending = bytearray(signature + stream.read(18))
        if len(ending) != 22 or any(struct.unpack_from('<2H', ending, 4)):
            raise ValueError('Split or truncated ZIP end refused')
        entries_disk, entries_total = struct.unpack_from('<2H', ending, 8)
        directory_size, recorded_offset = struct.unpack_from('<2I', ending, 12)
        if (entries_disk != entries_total or entries_total == 0xffff or
                directory_size != len(directory) or recorded_offset != directory_offset):
            raise ValueError('ZIP directory mismatch or ZIP64 refused')
        comment_size = struct.unpack_from('<H', ending, 20)[0]
        comment = stream.read(comment_size)
        if len(comment) != comment_size or stream.read(1):
            raise ValueError('Trailing or truncated ZIP data refused')
        struct.pack_into('<I', ending, 16, directory_offset + delta)
        stream.seek(info.header_offset)
        header = bytearray(stream.read(30))
        if header[:4] != b'PK\x03\x04':
            raise ValueError('Invalid local ZIP header')
        flags, compression = struct.unpack_from('<2H', header, 6)
        if flags & 9 or compression != zipfile.ZIP_STORED:
            raise ValueError('Unsupported local ZIP header')
        if struct.unpack_from('<3I', header, 14) != (info.CRC, info.compress_size, info.file_size):
            raise ValueError('Local ZIP size/CRC mismatch')
        filename_size, extra_size = struct.unpack_from('<2H', header, 26)
        name_extra = stream.read(filename_size + extra_size)
        if name_extra[:filename_size].decode('utf-8' if flags & 0x800 else 'cp437') != name:
            raise ValueError('Local ZIP filename mismatch')
        body_end = stream.tell() + info.compress_size
        if body_end > directory_offset or size >= 0xffffffff:
            raise ValueError('Unsupported ZIP bounds')
        struct.pack_into('<3I', header, 14, crc, size, size)
        with destination.open('xb') as output:
            stream.seek(0)
            copy_bytes(stream, output, info.header_offset)
            output.write(header)
            output.write(name_extra)
            with replacement.open('rb') as payload:
                copy_bytes(payload, output, size)
            stream.seek(body_end)
            copy_bytes(stream, output, directory_offset - body_end)
            output.write(directory)
            output.write(ending)
            output.write(comment)


def install(source, destination, nested, nested_sha256, result_sha256):
    """Guest-compatible streaming installation to a NEW file, never in-place."""
    if sha256(source) != SOURCE_SHA256:
        raise ValueError('Unsupported original ace.jar SHA256')
    if sha256(nested) != nested_sha256:
        raise ValueError('Unsupported adapted nested JAR SHA256')
    with zipfile.ZipFile(nested) as archive:
        guard_archive(archive)
        require_hash(archive.read(CLASS_NAME), RESULT_CLASS_SHA256, 'adapted controller class')
        require_hash(archive.read(GCM_CLASS_NAME), GCM_RESULT_CLASS_SHA256, 'adapted GCM listener class')
    replace_stored_member(source, destination, NESTED_NAME, nested)
    if result_sha256 and sha256(destination) != result_sha256:
        raise ValueError('Adapted ace.jar SHA256 mismatch; do not install output')
    return sha256(destination)


def patch(source, destination, nested_output=None):
    """Native build API; returns report and leaves the shippable nested JAR."""
    source, destination = Path(source), Path(destination)
    nested_output = Path(nested_output) if nested_output else destination.with_name(destination.name + '.internal.jar')
    report_path = destination.with_name(destination.name + '.json')
    for path in (destination, nested_output, report_path):
        if path.exists() or path.is_symlink():
            raise ValueError('Destination already exists: ' + str(path))
    if sha256(source) != SOURCE_SHA256:
        raise ValueError('Unsupported original ace.jar SHA256')
    with zipfile.ZipFile(source) as outer:
        guard_archive(outer)
        if outer.getinfo(NESTED_NAME).compress_type != zipfile.ZIP_STORED:
            raise ValueError('Spring Boot nested library must be STORED')
        original_nested = outer.read(NESTED_NAME)
    require_hash(original_nested, NESTED_SHA256, 'original nested JAR')
    with zipfile.ZipFile(io.BytesIO(original_nested)) as archive:
        guard_archive(archive)
        changed_classes = {CLASS_NAME: patch_class(archive.read(CLASS_NAME)),
                           GCM_CLASS_NAME: patch_gcm_class(archive.read(GCM_CLASS_NAME))}
        with nested_output.open('xb') as output, zipfile.ZipFile(output, 'w') as adapted:
            adapted.comment = archive.comment
            for info in archive.infolist():
                if info.filename in changed_classes:
                    adapted.writestr(copy.copy(info), changed_classes[info.filename])
                else:
                    with archive.open(info) as reader, adapted.open(copy.copy(info), 'w') as writer:
                        shutil.copyfileobj(reader, writer, 1024 * 1024)
    nested_digest = sha256(nested_output)
    result_digest = install(source, destination, nested_output, nested_digest, None)
    report = {
        'status': 'controller-port-and-gcm-cache-adaptation-candidate', 'source_sha256': SOURCE_SHA256,
        'result_sha256': result_digest, 'nested_member': NESTED_NAME,
        'nested_source_sha256': NESTED_SHA256, 'nested_result_sha256': nested_digest,
        'nested_artifact': nested_output.name, 'class': CLASS_NAME,
        'class_source_sha256': CLASS_SHA256, 'class_result_sha256': RESULT_CLASS_SHA256,
        'method': 'seedPortTable()Ljava/util/List;', 'method_source_sha256': METHOD_SHA256,
        'method_result_sha256': RESULT_METHOD_SHA256, 'method_size': METHOD_SIZE,
        'helper_descriptor': HELPER_DESCRIPTOR,
        'changes': [{'port': 'eth' + str(index + 2), 'method_offset': offset,
                     'before': OLD_CALL.hex(), 'after': NEW_CALL.hex()} for index, offset in enumerate(PATCH_OFFSETS)],
        'changed_classes': [CLASS_NAME, GCM_CLASS_NAME],
        'unlisted_classes_unchanged': True, 'nested_zip_storage_preserved': True,
        'gcm_cache': {
            'class': GCM_CLASS_NAME, 'class_source_sha256': GCM_CLASS_SHA256,
            'class_result_sha256': GCM_RESULT_CLASS_SHA256,
            'method': GCM_METHOD_NAME + GCM_DESCRIPTOR,
            'method_source_sha256': GCM_CODE_SHA256, 'method_result_sha256': GCM_RESULT_CODE_SHA256,
            'method_offset': GCM_PATCH_OFFSET, 'before': GCM_BEFORE.hex(), 'after': GCM_AFTER.hex(),
            'scope': 'All authenticated AES_GCM informs through the original listener',
            'cryptographic_checks_unchanged': True, 'readiness_and_state_setters_unchanged': True,
            'extra_minidevice_cache_invalidation_per_gcm_inform': True,
        },
        'ui_provisioning_verified': False,
    }
    with report_path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    builder = commands.add_parser('build')
    builder.add_argument('source', type=Path)
    builder.add_argument('destination', type=Path)
    builder.add_argument('--nested-output', type=Path)
    installer = commands.add_parser('install')
    installer.add_argument('source', type=Path)
    installer.add_argument('destination', type=Path)
    installer.add_argument('--nested', type=Path, required=True)
    installer.add_argument('--nested-sha256', required=True)
    installer.add_argument('--result-sha256', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            print(json.dumps(patch(args.source, args.destination, args.nested_output), indent=2))
        else:
            print(install(args.source, args.destination, args.nested, args.nested_sha256, args.result_sha256))
    except (OSError, ValueError, KeyError, IndexError, struct.error, zipfile.BadZipFile) as error:
        parser.exit(1, 'Controller adaptation refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
