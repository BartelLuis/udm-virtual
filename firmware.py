#!/usr/bin/env python3
"""Read and extract UBNT update containers without executing their contents.

Only Python's standard library is required (Python 3.9+). The container layout
and CRC coverage follow Ubiquiti's published structures, as maintained in:
https://lxr.openwrt.org/source/firmware-utils/src/fw.h
https://lxr.openwrt.org/source/firmware-utils/src/mkfwimage.c

FILE and EXEC records use the same layout as PART in the supplied UDMEA4C
image. An ENDS signature is preserved/reported, but is NOT authenticated: this
tool does not have Ubiquiti's trusted public key. CRCs detect corruption only.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib


HEADER_SIZE = 268
RECORD_SIZE = 56
CHUNK_SIZE = 1024 * 1024
MAX_RECORDS = 1024


class FirmwareError(ValueError):
    """Malformed, unsupported, or unsafe firmware input."""


def discover_firmware(path=None):
    """Resolve an explicit input, or require exactly one *.bin in cwd."""
    if path is not None:
        return Path(path).resolve(strict=True)
    candidates = sorted(p for p in Path.cwd().glob("*.bin") if p.is_file())
    if len(candidates) != 1:
        raise FirmwareError(
            "Specify a firmware file: expected exactly one *.bin in the current "
            "directory, found {}.".format(len(candidates))
        )
    return candidates[0].resolve(strict=True)


def _cstring(raw, label):
    value, separator, padding = raw.partition(b"\0")
    if separator and any(padding):
        raise FirmwareError("Nonzero padding in {}.".format(label))
    try:
        result = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirmwareError("{} must be ASCII.".format(label)) from exc
    if not result or any(ord(c) < 32 or ord(c) > 126 for c in result):
        raise FirmwareError("Empty or non-printable {}.".format(label))
    return result


def _checked_crc(actual, expected, label):
    if actual != expected:
        raise FirmwareError(
            "CRC32 mismatch in {}: expected {:08x}, calculated {:08x}.".format(
                label, expected, actual
            )
        )


def _content_info(prefix):
    """Conservative metadata from the payload start, never a signature scan."""
    if prefix.startswith(b"\x7fELF") and len(prefix) >= 20:
        byte_order = {1: "little", 2: "big"}.get(prefix[5])
        machine = int.from_bytes(prefix[18:20], byte_order) if byte_order else None
        return {
            "format": "ELF",
            "bits": {1: 32, 2: 64}.get(prefix[4]),
            "byte_order": byte_order,
            "machine": machine,
            "architecture": {183: "aarch64", 62: "x86_64", 40: "arm", 8: "mips"}.get(machine),
        }
    if prefix.startswith(b"hsqs") and len(prefix) >= 96:
        compression = struct.unpack_from("<H", prefix, 20)[0]
        major, minor = struct.unpack_from("<HH", prefix, 28)
        return {
            "format": "SquashFS",
            "version": "{}.{}".format(major, minor),
            "compression_id": compression,
            "compression": {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}.get(compression, "unknown"),
            "bytes_used": struct.unpack_from("<Q", prefix, 40)[0],
        }
    if prefix.startswith(b"\xd0\x0d\xfe\xed") and len(prefix) >= 8:
        return {"format": "FDT/FIT", "declared_size_bytes": struct.unpack_from(">I", prefix, 4)[0]}
    if prefix.startswith(b"\x1f\x8b"):
        return {"format": "gzip"}
    return {"format": "unknown"}


class _Reader:
    def __init__(self, stream):
        self.stream = stream
        self.stat = os.fstat(stream.fileno())
        if not stat.S_ISREG(self.stat.st_mode):
            raise FirmwareError("Firmware input must be a regular file.")
        self.size = self.stat.st_size
        self.offset = 0
        self.sha256 = hashlib.sha256()
        self.crc32 = 0

    def read(self, length, label):
        if length < 0 or self.offset + length > self.size:
            raise FirmwareError("Truncated {} at offset {}.".format(label, self.offset))
        data = self.stream.read(length)
        if len(data) != length:
            raise FirmwareError("Unexpected EOF in {} at offset {}.".format(label, self.offset))
        self.offset += length
        self.sha256.update(data)
        self.crc32 = zlib.crc32(data, self.crc32)
        return data

    def assert_unchanged(self):
        current = os.fstat(self.stream.fileno())
        if (current.st_size, current.st_mtime_ns) != (self.stat.st_size, self.stat.st_mtime_ns):
            raise FirmwareError("Firmware changed while it was being read.")


def _inspect(stream, source):
    stream.seek(0)
    reader = _Reader(stream)
    header = reader.read(HEADER_SIZE, "UBNT header")
    if header[:4] != b"UBNT":
        raise FirmwareError("Not a UBNT update container (expected UBNT magic).")
    version = _cstring(header[4:260], "firmware version")
    expected, padding = struct.unpack_from(">II", header, 260)
    _checked_crc(zlib.crc32(header[:260]), expected, "firmware header")
    if padding:
        raise FirmwareError("Nonzero UBNT header padding.")
    partitions = []
    seen_names = set()
    trailer = None
    while reader.offset < reader.size:
        record_offset = reader.offset
        preceding_crc = reader.crc32
        magic = reader.read(4, "record magic")
        if magic in (b"END.", b"ENDS"):
            if not partitions:
                raise FirmwareError("Firmware contains no payload records.")
            length = 12 if magic == b"END." else 264
            tail = reader.read(length - 4, "end record")
            if any(tail[-4:]):
                raise FirmwareError("Nonzero end-record padding.")
            trailer = {
                "kind": magic.decode("ascii"), "record_offset": record_offset,
                "size_bytes": length, "signature_verified": False,
            }
            if magic == b"END.":
                expected = struct.unpack_from(">I", tail)[0]
                _checked_crc(preceding_crc, expected, "whole-container END. record")
                trailer.update(crc32="{:08x}".format(expected), crc32_valid=True,
                               authentication="unsigned")
            else:
                trailer.update(signature_size_bytes=256,
                               signature_sha256=hashlib.sha256(tail[:256]).hexdigest(),
                               authentication="RSA signature present; not verified")
            if reader.offset != reader.size:
                raise FirmwareError("Unexpected trailing bytes after end record.")
            break
        if magic not in (b"FILE", b"PART", b"EXEC"):
            raise FirmwareError("Unknown record magic {!r} at offset {}.".format(magic, record_offset))
        if len(partitions) >= MAX_RECORDS:
            raise FirmwareError("Too many payload records (limit {}).".format(MAX_RECORDS))
        raw = magic + reader.read(RECORD_SIZE - 4, "payload record header")
        name = _cstring(raw[4:20], "record name")
        if name.casefold() in seen_names:
            raise FirmwareError("Duplicate payload name: {}.".format(name))
        seen_names.add(name.casefold())
        if any(raw[20:32]):
            raise FirmwareError("Nonzero record padding in {}.".format(name))
        memaddr, index, baseaddr, entryaddr, length, capacity = struct.unpack_from(">6I", raw, 32)
        if not length or length > capacity:
            raise FirmwareError("Invalid payload/partition size for {}.".format(name))
        if reader.offset + length + 8 > reader.size:
            raise FirmwareError("Truncated payload or CRC trailer for {}.".format(name))
        data_offset = reader.offset
        checksum = zlib.crc32(raw)
        digest = hashlib.sha256()
        remaining = length
        prefix = b""
        while remaining:
            block = reader.read(min(CHUNK_SIZE, remaining), name)
            if len(prefix) < 96:
                prefix += block[:96 - len(prefix)]
            digest.update(block)
            checksum = zlib.crc32(block, checksum)
            remaining -= len(block)
        expected, padding = struct.unpack(">II", reader.read(8, "payload CRC trailer"))
        _checked_crc(checksum, expected, "payload {}".format(name))
        if padding:
            raise FirmwareError("Nonzero CRC padding for {}.".format(name))
        partitions.append({
            "name": name, "kind": magic.decode("ascii"), "index": index,
            "record_offset": record_offset, "data_offset": data_offset,
            "size_bytes": length, "partition_size_bytes": capacity,
            "memory_address": memaddr, "base_address": baseaddr, "entry_address": entryaddr,
            "sha256": digest.hexdigest(), "crc32": "{:08x}".format(expected),
            "crc32_valid": True, "content": _content_info(prefix),
        })
    if trailer is None:
        raise FirmwareError("Missing END. or ENDS record.")
    reader.assert_unchanged()
    identifiers = version.split(".")
    architectures = sorted({p["content"]["architecture"] for p in partitions
                            if p["content"].get("architecture")})
    return {
        "schema_version": 1, "source": str(source), "size_bytes": reader.size,
        "sha256": reader.sha256.hexdigest(), "format": "UBNT", "version": version,
        "model": identifiers[0], "platform": identifiers[1] if len(identifiers) > 1 else None,
        "architecture": architectures[0] if len(architectures) == 1 else None,
        "architecture_evidence": [p["name"] + " ELF header" for p in partitions
                                  if p["content"].get("architecture")],
        "header": {"size_bytes": HEADER_SIZE, "crc32": "{:08x}".format(
            struct.unpack_from(">I", header, 260)[0]), "crc32_valid": True},
        "partitions": partitions, "trailer": trailer,
        "integrity": {"crc32_valid": True, "authenticity_verified": False},
        "is_virtual_machine_disk": False,
    }


def inspect_firmware(path=None):
    """Return metadata and streamed SHA256s; reject malformed or corrupt input."""
    source = discover_firmware(path)
    with source.open("rb") as stream:
        return _inspect(stream, source)


def _safe_output_name(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or name.endswith("."):
        raise FirmwareError("Unsafe payload filename: {!r}.".format(name))
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update("{}{}".format(prefix, number) for prefix in ("COM", "LPT") for number in range(1, 10))
    if name.split(".")[0].upper() in reserved:
        raise FirmwareError("Reserved payload filename: {!r}.".format(name))
    return name + ".bin"


def extract_firmware(path, output, parts=None):
    """Validate everything, then extract payloads and manifest into a NEW dir.

    ``parts`` is an optional sequence of exact record names. Existing output
    directories are refused. No archive contents are unpacked or executed.
    """
    source = discover_firmware(path)
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise FirmwareError("Output directory already exists: {}.".format(destination))
    created = []
    made_directory = False
    with source.open("rb") as stream:
        report = _inspect(stream, source)
        original_stat = os.fstat(stream.fileno())
        requested = set(parts) if parts is not None else {p["name"] for p in report["partitions"]}
        available = {p["name"] for p in report["partitions"]}
        if not requested or requested - available:
            raise FirmwareError("Unknown or empty partition selection: {}.".format(
                ", ".join(sorted(requested - available))))
        selected = [p for p in report["partitions"] if p["name"] in requested]
        filenames = [_safe_output_name(p["name"]) for p in selected]
        try:
            destination.mkdir(parents=True, exist_ok=False)
            made_directory = True
            report["extracted"] = []
            for partition, filename in zip(selected, filenames):
                target = destination / filename
                stream.seek(partition["data_offset"])
                digest = hashlib.sha256()
                remaining = partition["size_bytes"]
                with target.open("xb") as out:
                    created.append(target)
                    while remaining:
                        block = stream.read(min(CHUNK_SIZE, remaining))
                        if not block:
                            raise FirmwareError("Firmware changed or was truncated during extraction.")
                        out.write(block)
                        digest.update(block)
                        remaining -= len(block)
                if digest.hexdigest() != partition["sha256"]:
                    raise FirmwareError("Firmware payload changed during extraction.")
                report["extracted"].append({"name": partition["name"], "file": filename,
                                            "sha256": partition["sha256"], "size_bytes": partition["size_bytes"]})
            current = os.fstat(stream.fileno())
            if (current.st_size, current.st_mtime_ns) != (original_stat.st_size, original_stat.st_mtime_ns):
                raise FirmwareError("Firmware changed during extraction.")
            manifest = destination / "manifest.json"
            with manifest.open("x", encoding="utf-8", newline="\n") as out:
                created.append(manifest)
                json.dump(report, out, indent=2, ensure_ascii=False)
                out.write("\n")
        except BaseException:
            # Remove only files created by this invocation; never recurse.
            for target in reversed(created):
                try:
                    target.unlink()
                except OSError:
                    pass
            if made_directory:
                try:
                    destination.rmdir()
                except OSError:
                    pass
            raise
    return report


def _summary(report):
    lines = ["Firmware: " + report["version"],
             "SHA256:   " + report["sha256"],
             "CPU:      " + (report["architecture"] or "not identified"),
             "CRC32:    header and all payload records valid",
             "Signature: " + report["trailer"]["authentication"],
             "This is a hardware update container, not a VM disk.", ""]
    for part in report["partitions"]:
        lines.append("{:<16} {:>12} bytes  {}".format(
            part["name"], part["size_bytes"], part["content"]["format"]))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Validate and inspect firmware")
    inspect.add_argument("file", nargs="?", help="Defaults to the only *.bin in the current directory")
    inspect.add_argument("--json", metavar="PATH", help="Write a NEW JSON report (use - for stdout)")
    extract = sub.add_parser("extract", help="Validate and extract firmware records")
    extract.add_argument("file", nargs="?")
    extract.add_argument("--output", required=True, metavar="DIR", help="New destination directory")
    extract.add_argument("--part", action="append", help="Record to extract; repeat for multiple (default: all)")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            if args.json and args.json != "-" and (Path(args.json).exists() or Path(args.json).is_symlink()):
                raise FirmwareError("Report already exists: {}.".format(args.json))
            report = inspect_firmware(args.file)
            if args.json == "-":
                print(json.dumps(report, indent=2, ensure_ascii=False))
                return 0
            if args.json:
                with Path(args.json).open("x", encoding="utf-8", newline="\n") as out:
                    json.dump(report, out, indent=2, ensure_ascii=False)
                    out.write("\n")
            print(_summary(report))
        else:
            report = extract_firmware(args.file, args.output, args.part)
            print(_summary(report))
            print("\nExtracted {} records to {}".format(len(report["extracted"]), Path(args.output).absolute()))
        return 0
    except (FirmwareError, OSError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
