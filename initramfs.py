"""Replace /init in a newc initramfs without unpacking firmware on the host."""
import gzip
from pathlib import Path
import posixpath
import stat

LIMIT = 128 * 1024 * 1024


def read_newc(data):
    pos = 0
    entries = []
    names = set()
    while pos + 110 <= len(data):
        head = data[pos:pos + 110]
        if head[:6] != b"070701":
            raise ValueError("Expected an unchecksummed newc archive")
        try:
            fields = [int(head[i:i + 8], 16) for i in range(6, 110, 8)]
        except ValueError as exc:
            raise ValueError("Invalid newc header") from exc
        size, namesize = fields[6], fields[11]
        if not 1 <= namesize <= 4096 or pos + 110 + namesize > len(data):
            raise ValueError("Invalid newc name length")
        rawname = data[pos + 110:pos + 110 + namesize]
        if rawname[-1:] != b"\0" or b"\0" in rawname[:-1]:
            raise ValueError("Invalid newc name")
        name = rawname[:-1].decode("utf-8")
        start = (pos + 110 + namesize + 3) & ~3
        end = start + size
        if end > len(data):
            raise ValueError("Truncated newc payload")
        if name == "TRAILER!!!":
            if size or any(data[(end + 3) & ~3:]):
                raise ValueError("Unexpected data after newc trailer")
            return entries
        if name.startswith("/") or ".." in name.split("/"):
            raise ValueError("Unsafe newc entry name")
        normalized = posixpath.normpath(name)
        if normalized in names:
            raise ValueError("Duplicate normalized newc entry name")
        names.add(normalized)
        entries.append((name, fields, data[start:end]))
        pos = (end + 3) & ~3
    raise ValueError("Missing newc trailer")


def write_newc(entries):
    result = bytearray()
    trailer = [0] * 13
    for name, original, payload in [*entries, ("TRAILER!!!", trailer, b"")]:
        fields = list(original)
        rawname = name.encode() + b"\0"
        fields[6], fields[11], fields[12] = len(payload), len(rawname), 0
        result.extend(b"070701" + b"".join(f"{v:08x}".encode() for v in fields))
        result.extend(rawname)
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(payload)
        result.extend(b"\0" * (-len(result) % 4))
    result.extend(b"\0" * (-len(result) % 512))
    return bytes(result)


def patch_initramfs(source, init_script, output, extra_files=None):
    with gzip.open(source, "rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("Initramfs exceeds 128 MiB")
    entries = read_newc(data)
    matches = [i for i, (name, _, _) in enumerate(entries) if posixpath.normpath(name) == "init"]
    if len(matches) != 1:
        raise ValueError("Expected exactly one /init")
    idx = matches[0]
    name, fields, _ = entries[idx]
    if not stat.S_ISREG(fields[1]) or fields[4] != 1:
        raise ValueError("/init must be a regular file without hardlinks")
    fields = list(fields)
    fields[1], fields[2], fields[3] = stat.S_IFREG | 0o755, 0, 0
    script = Path(init_script).read_bytes().replace(b"\r\n", b"\n")
    if not script.startswith(b"#!/bin/sh\n"):
        raise ValueError("Expected POSIX shell init script")
    entries[idx] = (name, fields, script)
    # Keep the original archive intact and append only explicit new payloads.
    # Parents are emitted first; never replace vendor files through this API.
    names = {posixpath.normpath(name) for name, _, _ in entries}
    inode = max(fields[0] for _, fields, _ in entries) + 1
    for path, (permissions, payload) in sorted((extra_files or {}).items()):
        if (not isinstance(path, str) or path.startswith('/') or
                posixpath.normpath(path) != path or path in ('', '.') or
                '..' in path.split('/') or '\\' in path or '\0' in path):
            raise ValueError('Unsafe initramfs addition path')
        if path in names:
            raise ValueError('Initramfs addition would replace an existing entry')
        if permissions not in (0o644, 0o755) or not isinstance(payload, bytes):
            raise ValueError('Invalid initramfs addition mode or payload')
        parts = path.split('/')
        for count in range(1, len(parts)):
            parent = '/'.join(parts[:count])
            if parent in names:
                entry = next(item for item in entries if posixpath.normpath(item[0]) == parent)
                if not stat.S_ISDIR(entry[1][1]):
                    raise ValueError('Initramfs addition parent is not a directory')
                continue
            fields = [inode, stat.S_IFDIR | 0o755, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
            inode += 1
            entries.append((parent, fields, b''))
            names.add(parent)
        fields = [inode, stat.S_IFREG | permissions, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        inode += 1
        entries.append((path, fields, payload))
        names.add(path)
    archive = write_newc(entries)
    if len(archive) > LIMIT:
        raise ValueError('Augmented initramfs exceeds 128 MiB')
    with Path(output).open("xb") as dest:
        with gzip.GzipFile(filename="", fileobj=dest, mode="wb", mtime=0) as zipped:
            zipped.write(archive)
