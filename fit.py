#!/usr/bin/env python3
"""Extract a FIT's default ARM64 boot components, without executing firmware.

FDT/FIT layouts: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html
and https://fitspec.osfw.foundation/ . Hashes check integrity, not authenticity.
"""

import hashlib
import os
import json
from pathlib import Path
import re
import struct
import zlib


MAX_FIT_SIZE = 512 * 1024 * 1024
MAX_KERNEL_SIZE = 256 * 1024 * 1024
MAX_CONFIG_SIZE = 4 * 1024 * 1024
MAX_TOKENS = 200000
MAX_DEPTH = 128
FDT_MAGIC = 0xD00DFEED


class FitError(ValueError):
    """Malformed, unsupported, or unsafe FIT input."""


class _Node:
    def __init__(self, name):
        self.name = name
        self.props = {}
        self.children = {}


def _text(value, label):
    raw = bytes(value)
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        raise FitError("{} is not one NUL-terminated string.".format(label))
    try:
        return raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FitError("{} must be ASCII.".format(label)) from exc


def _prop_text(node, name, default=None):
    if name not in node.props:
        if default is not None:
            return default
        raise FitError("Missing {} in node {}.".format(name, node.name))
    return _text(node.props[name], name)


def _parse_fdt(blob):
    """Return root and total size after validating the complete FDT structure."""
    if len(blob) < 40 or len(blob) > MAX_FIT_SIZE:
        raise FitError("FDT size is outside supported bounds.")
    magic, total, off_struct, off_strings, off_reserve, version, compatible, _, size_strings, size_struct = struct.unpack_from(
        ">10I", blob
    )
    if magic != FDT_MAGIC or version < 17 or compatible > 17 or compatible > version:
        raise FitError("Unsupported FDT header/version.")
    if total < 40 or total > len(blob):
        raise FitError("FDT total size exceeds input bounds.")
    sections = [(0, 40)]
    for offset, size, label in ((off_struct, size_struct, "structure"), (off_strings, size_strings, "strings")):
        if offset < 40 or offset > total or size > total - offset:
            raise FitError("FDT {} section exceeds bounds.".format(label))
        sections.append((offset, offset + size))
    if off_struct % 4 or size_struct % 4 or off_reserve % 8 or off_reserve < 40:
        raise FitError("Misaligned FDT section.")
    cursor = off_reserve
    while True:
        if cursor + 16 > total:
            raise FitError("Unterminated FDT memory reservation map.")
        address, length = struct.unpack_from(">QQ", blob, cursor)
        cursor += 16
        if address == length == 0:
            break
        if cursor - off_reserve > 1024 * 1024:
            raise FitError("FDT memory reservation map is too large.")
    sections.append((off_reserve, cursor))
    sections.sort()
    if any(left[1] > right[0] for left, right in zip(sections, sections[1:])):
        raise FitError("Overlapping FDT sections.")
    strings = bytes(blob[off_strings:off_strings + size_strings])
    end = off_struct + size_struct
    cursor = off_struct
    stack = []
    root = None
    view = memoryview(blob)
    for _ in range(MAX_TOKENS):
        if cursor + 4 > end:
            raise FitError("FDT structure is missing its END token.")
        token = struct.unpack_from(">I", blob, cursor)[0]
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            terminator = blob.find(b"\0", cursor, end)
            if terminator < 0 or terminator - cursor > 255:
                raise FitError("Invalid FDT node name.")
            try:
                name = bytes(blob[cursor:terminator]).decode("ascii")
            except UnicodeDecodeError as exc:
                raise FitError("Non-ASCII FDT node name.") from exc
            if name and not re.fullmatch(r"[A-Za-z0-9,._+@-]+", name):
                raise FitError("Invalid FDT node name.")
            cursor = (terminator + 4) & ~3
            if cursor > end or len(stack) >= MAX_DEPTH:
                raise FitError("FDT node depth or bounds exceeded.")
            node = _Node(name)
            if stack:
                if not name or name in stack[-1].children:
                    raise FitError("Empty or duplicate FDT child node.")
                stack[-1].children[name] = node
            elif root is not None or name:
                raise FitError("FDT must contain exactly one unnamed root.")
            else:
                root = node
            stack.append(node)
        elif token == 2:  # FDT_END_NODE
            if not stack:
                raise FitError("Unbalanced FDT END_NODE token.")
            stack.pop()
        elif token == 3:  # FDT_PROP
            if not stack or stack[-1].children or cursor + 8 > end:
                raise FitError("FDT property is misplaced or truncated.")
            length, name_offset = struct.unpack_from(">II", blob, cursor)
            cursor += 8
            if name_offset >= len(strings) or length > end - cursor:
                raise FitError("FDT property exceeds bounds.")
            terminator = strings.find(b"\0", name_offset)
            if terminator < 0 or terminator - name_offset > 255:
                raise FitError("Invalid FDT property name offset.")
            name = _text(strings[name_offset:terminator + 1], "property name")
            if not name or name in stack[-1].props:
                raise FitError("Empty or duplicate FDT property.")
            stack[-1].props[name] = view[cursor:cursor + length]
            cursor = (cursor + length + 3) & ~3
            if cursor > end:
                raise FitError("FDT property padding exceeds bounds.")
        elif token == 4:  # FDT_NOP
            pass
        elif token == 9:  # FDT_END
            if stack or root is None or any(blob[cursor:end]):
                raise FitError("Unbalanced FDT tree or data after END token.")
            return root, total
        else:
            raise FitError("Unknown FDT token {}.".format(token))
    raise FitError("FDT token limit exceeded.")


def _gunzip(data, limit, allow_trailing=False):
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = decompressor.decompress(data, limit + 1)
    except zlib.error as exc:
        raise FitError("Invalid gzip stream: {}".format(exc)) from exc
    if len(decoded) > limit or decompressor.unconsumed_tail:
        raise FitError("Gzip decompression exceeds size limit.")
    if not decompressor.eof:
        raise FitError("Truncated gzip stream.")
    if decompressor.unused_data and not allow_trailing:
        raise FitError("Unexpected data after gzip stream.")
    return decoded, decompressor.unused_data


def _image_data(node, blob, total):
    external = {"data-offset", "data-position", "data-size"} & node.props.keys()
    if "data" in node.props:
        if external:
            raise FitError("Ambiguous inline and external FIT data.")
        return node.props["data"]
    if external:
        raise FitError("External FIT image data is not supported by this extractor.")
    raise FitError("Missing inline data in FIT image {}.".format(node.name))


def _verify_hashes(node, data):
    hashes = []
    for name, child in node.children.items():
        if not (name == "hash" or name.startswith(("hash-", "hash@"))):
            continue
        algorithm = _prop_text(child, "algo")
        if algorithm not in ("sha1", "sha256"):
            raise FitError("Unsupported FIT hash algorithm: {}.".format(algorithm))
        expected = bytes(child.props.get("value", b""))
        actual = hashlib.new(algorithm, data).digest()
        if expected != actual:
            raise FitError("{} hash mismatch for FIT image {}.".format(algorithm, node.name))
        hashes.append({"algorithm": algorithm, "value": actual.hex(), "verified": True})
    if not hashes:
        raise FitError("FIT image {} has no supported integrity hash.".format(node.name))
    return hashes


def _signatures(root):
    result = []
    pending = [("", root)]
    while pending:
        parent, node = pending.pop()
        path = parent + "/" + node.name if node.name else ""
        if node.name == "signature" or node.name.startswith(("signature-", "signature@")):
            result.append({"path": path, "algorithm": _prop_text(node, "algo", "unknown"), "verified": False})
        pending.extend((path, child) for child in node.children.values())
    return result


def _kernel_config(image):
    marker = image.find(b"IKCFG_ST")
    if marker < 0:
        return None
    config, trailing = _gunzip(image[marker + 8:], MAX_CONFIG_SIZE, allow_trailing=True)
    if not trailing.startswith(b"IKCFG_ED"):
        raise FitError("Embedded kernel configuration has no IKCFG_ED marker.")
    try:
        return config.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FitError("Embedded kernel configuration is not UTF-8.") from exc


def prepare_fit(fit_path, output_dir):
    """Validate and extract default FIT boot components into a NEW directory.

    Only selected images' SHA-1/SHA-256 hashes are checked. Neither FIT signatures
    nor publisher authenticity are verified. No input code is executed.
    """
    source = Path(fit_path)
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        raise FitError("Output directory already exists: {}".format(output))
    with source.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if not 40 <= size <= MAX_FIT_SIZE:
            raise FitError("Invalid FIT file size")
        blob = handle.read(size + 1)
        if len(blob) != size:
            raise FitError("FIT file changed while reading")
    root, total = _parse_fdt(blob)
    try:
        images = root.children["images"]
        configurations = root.children["configurations"]
        default = _prop_text(configurations, "default")
        configuration = configurations.children[default]
    except KeyError as exc:
        raise FitError("Missing FIT images/default configuration.") from exc
    report = {
        "source": str(source.resolve()),
        "source_sha256": hashlib.sha256(blob).hexdigest(),
        "default_configuration": default,
        "images": {},
        "signatures": _signatures(root),
        "authenticity_verified": False,
        "hash_scope": "selected default configuration images only",
        "warnings": ["Image hashes detect corruption; publisher signatures are not authenticated.",
                     "Extracted components do not prove UniFi routing or firewall compatibility."],
    }
    payloads = {}
    for kind, expected_type in (("kernel", "kernel"), ("fdt", "flat_dt"), ("ramdisk", "ramdisk")):
        reference = _prop_text(configuration, kind)
        try:
            node = images.children[reference]
        except KeyError as exc:
            raise FitError("Unknown {} image reference: {}.".format(kind, reference)) from exc
        if _prop_text(node, "type") != expected_type:
            raise FitError("Unexpected image type for {}.".format(kind))
        arch = _prop_text(node, "arch", "unspecified")
        if arch not in ("arm64", "unspecified") or (kind == "kernel" and arch != "arm64"):
            raise FitError("Selected {} image is not ARM64.".format(kind))
        data = _image_data(node, blob, total)
        compression = _prop_text(node, "compression")
        report["images"][kind] = {
            "node": reference, "architecture": arch, "compression": compression,
            "stored_bytes": len(data), "hashes": _verify_hashes(node, data),
        }
        if kind == "kernel":
            if _prop_text(node, "os") != "linux":
                raise FitError("Selected kernel is not Linux.")
            if compression == "gzip":
                data, _ = _gunzip(data, MAX_KERNEL_SIZE)
            elif compression != "none":
                raise FitError("Unsupported kernel compression: {}.".format(compression))
            if len(data) < 64 or len(data) > MAX_KERNEL_SIZE or bytes(data[56:60]) != b"ARM\x64":
                raise FitError("Kernel is not a bounded ARM64 Linux Image.")
            payloads["Image"] = bytes(data)
        elif kind == "fdt":
            if compression != "none":
                raise FitError("Compressed hardware DTB is unsupported.")
            hardware_root, _ = _parse_fdt(bytes(data))
            report["hardware_model"] = _prop_text(hardware_root, "model", "unknown")
            compatibles = bytes(hardware_root.props.get("compatible", b""))
            report["hardware_compatible"] = compatibles.rstrip(b"\0").decode("ascii", errors="replace").split("\0") if compatibles else []
            payloads["hardware.dtb"] = bytes(data)
        else:
            # A gzip cpio may intentionally be labelled compression=none in FIT.
            if compression not in ("gzip", "none") or bytes(data[:2]) != b"\x1f\x8b":
                raise FitError("Expected a gzip-compressed original initramfs.")
            _gunzip(data, MAX_KERNEL_SIZE)
            payloads["original-initramfs.gz"] = bytes(data)
    config = _kernel_config(payloads["Image"])
    report["kernel_config_present"] = config is not None
    if config is not None:
        payloads["kernel.config"] = config.encode("utf-8")
        values = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=(.*)$", config, re.MULTILINE))
        wanted = ("ARM64", "ARM_GIC", "ARM_GIC_V3", "SERIAL_AMBA_PL011", "SERIAL_AMBA_PL011_CONSOLE",
                  "VIRTIO", "VIRTIO_PCI", "VIRTIO_MMIO", "VIRTIO_BLK", "VIRTIO_NET", "SQUASHFS",
                  "SQUASHFS_XZ", "BLK_DEV_INITRD", "DEVTMPFS", "DEVTMPFS_MOUNT", "EXT4_FS")
        report["kernel_features"] = {"CONFIG_" + name: values.get("CONFIG_" + name, "n") for name in wanted}
    report["outputs"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in payloads.items()}
    output.mkdir(parents=True, exist_ok=False)
    for name, data in payloads.items():
        with (output / name).open("xb") as handle:
            handle.write(data)
    with (output / "fit-report.json").open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report
