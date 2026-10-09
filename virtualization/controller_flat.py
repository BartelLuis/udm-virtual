"""Hash-bound extraction and launch of the original controller in a virtual guest.

Build integration stores build_metadata() in controller.json['flat']. The
root ExecStartPre calls ``prepare``; java-tcg.sh may call ``launch -- JVM_ARGS``
after its existing C1 conversion. No firmware program executes at build time.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import zipfile

if __package__:
    from .patch_controller import SOURCE_SHA256 as ORIGINAL_SHA256
else:
    from patch_controller import SOURCE_SHA256 as ORIGINAL_SHA256


SCHEMA = 1
MAIN_CLASS = 'com.ubnt.ace.BootLauncher'
BOOT_VERSION = '3.5.12'
CLASSES = 'BOOT-INF/classes'
INDEX = 'BOOT-INF/classpath.idx'
TOOLS_JAR = 'BOOT-INF/lib/spring-boot-jarmode-tools-3.5.12.jar'
INTERNAL_JAR = 'BOOT-INF/lib/internal-dependencies.jar'
SOURCE = Path('/usr/lib/unifi/lib/ace.jar')
CACHE = Path('/var/cache/udm-virtual/controller-flat')
REPORT = Path(__file__).resolve().parent / 'controller.json'
MARKER = 'verified.json'
JAVA = '/usr/bin/java'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(stream):
    hashed = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hashed.update(block)
    return hashed.hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def safe_path(name):
    require(isinstance(name, str) and name and not name.startswith('/'), 'Unsafe archive path')
    require(not any(ord(c) < 32 or c in '\\:' for c in name), 'Unsafe archive path')
    parts = name.rstrip('/').split('/')
    require(all(p not in ('', '.', '..') and not p.endswith((' ', '.')) for p in parts),
            'Archive traversal or ambiguous path refused')
    return PurePosixPath(*parts)


def index_order(content):
    ordered = []
    for line in content.decode('utf-8').splitlines():
        match = re.fullmatch(r'- "([^"\r\n]+)"', line)
        require(match is not None, 'Invalid classpath index syntax')
        ordered.append(match.group(1))
    require(len(ordered) == 152 and len(set(ordered)) == 152, 'Expected 152 unique indexed JARs')
    return ordered


def validate_controller(controller):
    require(isinstance(controller, dict), 'Invalid controller report')
    require(controller.get('source_sha256') == ORIGINAL_SHA256, 'Unsupported original controller version')
    for key in ('result_sha256', 'nested_result_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', controller.get(key, '')) is not None,
                'Invalid controller hash: ' + key)
    require(controller.get('nested_member') == INTERNAL_JAR, 'Unexpected adapted nested member')


def validate_metadata(metadata, controller=None):
    require(isinstance(metadata, dict), 'Invalid flat metadata')
    if controller is not None:
        validate_controller(controller)
        require(metadata.get('source_sha256') == controller['result_sha256'], 'Flat/source version mismatch')
    require(metadata.get('schema') == SCHEMA and metadata.get('main_class') == MAIN_CLASS and
            metadata.get('spring_boot_version') == BOOT_VERSION, 'Unsupported flat layout')
    require(re.fullmatch('[0-9a-f]{64}', metadata.get('source_sha256', '')) is not None,
            'Invalid flat source hash')
    files = metadata.get('files')
    require(isinstance(files, dict), 'Missing flat file inventory')
    folded = set()
    libraries = set()
    for name, details in files.items():
        safe_path(name)
        require(not name.endswith('/') and name.casefold() not in folded, 'Duplicate/colliding flat path')
        folded.add(name.casefold())
        require(name == INDEX or name.startswith(CLASSES + '/') or
                (name.startswith('BOOT-INF/lib/') and name.count('/') == 2 and name.endswith('.jar')),
                'Unexpected flat file')
        if name.startswith('BOOT-INF/lib/'):
            libraries.add(name)
        require(isinstance(details, dict), 'Invalid flat file metadata')
        require(type(details.get('size_bytes')) is int and details['size_bytes'] >= 0 and
                re.fullmatch('[0-9a-f]{64}', details.get('sha256', '')) is not None,
                'Invalid flat file metadata')
    require(len(libraries) == 153 and INDEX in files and
            CLASSES + '/com/ubnt/ace/BootLauncher.class' in files, 'Incomplete flat inventory')
    paths = metadata.get('classpath')
    require(isinstance(paths, list) and len(paths) == 154 and paths[0] == CLASSES and
            paths[-1] == TOOLS_JAR and len(set(paths)) == 154 and set(paths[1:]) == libraries,
            'Invalid ordered flat classpath')
    if controller is not None:
        require(files[INTERNAL_JAR]['sha256'] == controller['nested_result_sha256'],
                'Adapted nested content mismatch')
    return metadata


def regular_source(path):
    require(stat.S_ISREG(Path(path).lstat().st_mode), 'Controller source must be an ordinary file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'Controller source must be an ordinary file')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def build_metadata(source, controller):
    """Read only: describe all original resources and intact dependency JARs."""
    validate_controller(controller)
    with regular_source(source) as stream:
        require(digest(stream) == controller['result_sha256'], 'Installed/archive controller hash mismatch')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            seen, folded, selected = set(), set(), []
            for info in archive.infolist():
                safe_path(info.orig_filename)
                require(info.orig_filename == info.filename, 'Truncated archive filename')
                require(info.filename not in seen and info.filename.casefold() not in folded,
                        'Duplicate/colliding archive member')
                seen.add(info.filename)
                folded.add(info.filename.casefold())
                kind = stat.S_IFMT(info.external_attr >> 16)
                require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not info.flag_bits & 1,
                        'Archive symlink, special file or encryption refused')
                require(not (kind == stat.S_IFDIR and not info.is_dir()) and
                        not (kind == stat.S_IFREG and info.is_dir()), 'Archive file type mismatch')
                if not info.is_dir() and (info.filename.startswith(CLASSES + '/') or
                                          info.filename.startswith('BOOT-INF/lib/') or info.filename == INDEX):
                    selected.append(info)
            manifest = archive.read('META-INF/MANIFEST.MF').decode('utf-8').replace('\r', '')
            fields = dict(line.split(': ', 1) for line in manifest.splitlines() if ': ' in line)
            require(fields.get('Start-Class') == MAIN_CLASS and fields.get('Spring-Boot-Version') == BOOT_VERSION and
                    fields.get('Main-Class') == 'org.springframework.boot.loader.launch.JarLauncher',
                    'Unexpected original launcher manifest')
            ordered = index_order(archive.read(INDEX))
            files = {}
            for info in selected:
                with archive.open(info) as member:
                    files[info.filename] = {'size_bytes': info.file_size, 'sha256': digest(member)}
            metadata = {'schema': SCHEMA, 'source_sha256': controller['result_sha256'],
                        'main_class': MAIN_CLASS, 'spring_boot_version': BOOT_VERSION,
                        'classpath': [CLASSES, *ordered, TOOLS_JAR], 'files': files}
        stream.seek(0)
        require(digest(stream) == controller['result_sha256'], 'Controller changed during inspection')
    return validate_metadata(metadata, controller)


def cache_path(base, metadata):
    return Path(base) / ('v' + str(SCHEMA) + '-' + metadata['source_sha256'])


def owned(path, owner_uid, *, directory=False, immutable=False):
    info = Path(path).lstat()
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    require(correct_type and info.st_uid == owner_uid and not info.st_mode & 0o022,
            'Cache path must be an owned, non-writable ordinary ' + ('directory: ' if directory else 'file: ') + str(path))
    if immutable:
        require(not info.st_mode & 0o222, 'Published cache must be read-only: ' + str(path))
    if not directory:
        require(info.st_nlink == 1, 'Cache hardlink refused: ' + str(path))
    return info


def make_base(path, owner_uid):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        make_base(path.parent, owner_uid)
        path.mkdir(mode=0o755)
    owned(path, owner_uid, directory=True)


def marker_bytes(metadata):
    return canonical({'schema': SCHEMA, 'source_sha256': metadata['source_sha256'],
                      'metadata_sha256': hashlib.sha256(canonical(metadata)).hexdigest()})


def verify_cache(destination, metadata, *, owner_uid=0):
    """Verify bytes and exact membership; never trust only the completion marker."""
    validate_metadata(metadata)
    destination = Path(destination)
    owned(destination.parent.parent, owner_uid, directory=True)
    owned(destination.parent, owner_uid, directory=True)
    owned(destination, owner_uid, directory=True, immutable=True)
    wanted = set(metadata['files']) | {MARKER}
    directories = {parent.as_posix() for name in wanted for parent in PurePosixPath(name).parents
                   if parent.as_posix() != '.'}
    found = set()
    for path in destination.rglob('*'):
        name = path.relative_to(destination).as_posix()
        if name in directories:
            owned(path, owner_uid, directory=True, immutable=True)
        else:
            require(name in wanted, 'Unexpected cache member: ' + name)
            owned(path, owner_uid, immutable=True)
            found.add(name)
    require(found == wanted, 'Missing cache member')
    require((destination / MARKER).read_bytes() == marker_bytes(metadata), 'Cache verification marker mismatch')
    for name, expected in metadata['files'].items():
        path = destination / name
        require(path.stat().st_size == expected['size_bytes'], 'Cache size mismatch: ' + name)
        with path.open('rb') as stream:
            require(digest(stream) == expected['sha256'], 'Cache content hash mismatch: ' + name)
    require(metadata['classpath'] == [CLASSES, *index_order((destination / INDEX).read_bytes()), TOOLS_JAR],
            'Cached classpath index order mismatch')
    return destination


@contextmanager
def cache_lock(base, owner_uid):
    import fcntl  # Guest/Linux only; build-time metadata inspection is portable.
    descriptor = os.open(Path(base) / '.prepare.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid and
                not info.st_mode & 0o077 and info.st_nlink == 1, 'Unsafe cache lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def ensure_cache(source, metadata, base=CACHE, *, owner_uid=0):
    """Publish a complete new immutable directory; refuse corrupt existing caches."""
    validate_metadata(metadata)
    base = Path(base)
    make_base(base, owner_uid)
    destination = cache_path(base, metadata)
    with cache_lock(base, owner_uid), regular_source(source) as source_stream:
        require(digest(source_stream) == metadata['source_sha256'], 'Installed controller hash mismatch')
        if destination.exists() or destination.is_symlink():
            return verify_cache(destination, metadata, owner_uid=owner_uid)
        temporary = Path(tempfile.mkdtemp(prefix='.extract-', dir=base))
        try:
            source_stream.seek(0)
            with zipfile.ZipFile(source_stream) as archive:
                for name, expected in metadata['files'].items():
                    target = temporary.joinpath(*safe_path(name).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(name) as member, target.open('xb') as output:
                        hashed, size = hashlib.sha256(), 0
                        for block in iter(lambda: member.read(1024 * 1024), b''):
                            output.write(block)
                            hashed.update(block)
                            size += len(block)
                        output.flush()
                        os.fsync(output.fileno())
                    require(size == expected['size_bytes'] and hashed.hexdigest() == expected['sha256'],
                            'Extracted content mismatch: ' + name)
            source_stream.seek(0)
            require(digest(source_stream) == metadata['source_sha256'], 'Controller changed during extraction')
            with (temporary / MARKER).open('xb') as marker:
                marker.write(marker_bytes(metadata))
                marker.flush()
                os.fsync(marker.fileno())
            for path in temporary.rglob('*'):
                path.chmod(0o555 if path.is_dir() else 0o444)
            temporary.chmod(0o555)
            verify_cache(temporary, metadata, owner_uid=owner_uid)
            # The root-owned parent and exclusive preparation lock prevent a
            # second preparer or the unprivileged service from replacing it.
            os.rename(temporary, destination)
            directory = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return destination
        finally:
            if temporary.exists():
                temporary.chmod(0o700)
                for path in temporary.rglob('*'):
                    if path.is_dir():
                        path.chmod(0o700)
                shutil.rmtree(temporary)


def launch(arguments, metadata, source=SOURCE, base=CACHE, *, owner_uid=0, execute=None):
    require(len(arguments) >= 2 and arguments[-2:] == ['-jar', str(SOURCE)],
            'Expected terminal -jar /usr/lib/unifi/lib/ace.jar')
    validate_metadata(metadata)
    with regular_source(source) as stream:
        require(digest(stream) == metadata['source_sha256'], 'Installed controller hash mismatch')
    owned(base, owner_uid, directory=True)
    destination = verify_cache(cache_path(base, metadata), metadata, owner_uid=owner_uid)
    classpath = ':'.join(str(destination / name) for name in metadata['classpath'])
    command = [JAVA, *arguments[:-2], '-Dbase.dir=/usr/lib/unifi', '-cp', classpath, MAIN_CLASS]
    (os.execv if execute is None else execute)(JAVA, command)


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        mode = os.environ.get('UDM_UNIFI_LAUNCH', 'nested')
        require(mode in ('nested', 'flat'), 'Unknown UDM_UNIFI_LAUNCH mode')
        require(arguments and arguments[0] in ('prepare', 'launch'), 'Expected prepare or launch')
        if arguments == ['prepare'] and mode == 'nested':
            return 0
        require(mode == 'flat', 'Flat launch was not selected')
        owned(REPORT, 0)
        controller = json.loads(REPORT.read_text(encoding='utf-8'))
        metadata = validate_metadata(controller.get('flat', {}), controller)
        if arguments == ['prepare']:
            if __package__:
                from .hal_guest import require_guest, RUNTIME
            else:
                from hal_guest import require_guest, RUNTIME
            require_guest()
            require(not (RUNTIME / 'ready').is_symlink() and (RUNTIME / 'ready').is_file(),
                    'Virtual HAL must be ready before preparing the controller cache')
            destination = ensure_cache(SOURCE, metadata)
            print('UDM_VIRTUAL_CONTROLLER_FLAT_READY: ' + str(destination), flush=True)
        else:
            require(arguments[:2] == ['launch', '--'], 'Expected launch -- JVM_ARGS')
            launch(arguments[2:], metadata)
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print('UDM_VIRTUAL_CONTROLLER_FLAT_FAILURE: ' + str(error), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
