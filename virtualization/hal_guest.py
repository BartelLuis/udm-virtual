#!/usr/bin/python3
"""Initialize original UniFi HAL inside the explicitly virtual guest only.

Run after mounting /proc, /sys, /dev and /run in the mounted firmware root,
before original systemd starts. Requires adjacent hal_eeprom.py, Python 3,
mount/insmod from the original guest, and a local unicast eth0 MAC. No device
credentials are generated, cloned or bypassed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

if __package__:
    from .hal_eeprom import inspect_eeprom, mac_bytes, make_eeprom, make_payload
else:
    from hal_eeprom import inspect_eeprom, mac_bytes, make_eeprom, make_payload


KERNEL = "6.6.46-ui-cn10k"
IDENTITY = Path("/data/udm-virtual/identity.json")
RUNTIME = Path("/run/udm-virtual")


def require_guest():
    if os.geteuid() != 0 or os.uname().release != KERNEL:
        raise ValueError("Requires root in the original 6.6.46-ui-cn10k guest kernel")
    options = Path("/proc/cmdline").read_text().split()
    if not any(option in ("udm.mode=shell", "udm.mode=selftest", "udm.mode=systemd") for option in options):
        raise ValueError("Requires an explicit experimental udm.mode boot")
    if b"linux,dummy-virt" not in Path("/proc/device-tree/compatible").read_bytes().split(b"\0"):
        raise ValueError("Requires an isolated QEMU virt machine")
    return options


def local_identity(mac, nics, path=IDENTITY):
    """Load or atomically create a persistent, explicitly virtual identity."""
    base = mac_bytes(mac)
    mac = ":".join(f"{byte:02x}" for byte in base)
    # Validate the entire block before persisting any state.
    make_eeprom(mac, nics, uuid.UUID(int=0))
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Virtual identity path must not be a symbolic link")
    if path.exists():
        value = json.loads(path.read_text(encoding="ascii"))
        if value.get("schema") != 1 or value.get("origin") != "locally-generated-virtual-machine":
            raise ValueError("Unrecognized persistent virtual identity")
        if value.get("mac") != mac or value.get("nics") != nics:
            raise ValueError("Persistent virtual identity does not match configured NIC MAC/count")
        uuid.UUID(value["uuid"])
        return value
    value = {"schema": 1, "origin": "locally-generated-virtual-machine", "uuid": str(uuid.uuid4()),
             "mac": mac, "nics": nics, "credentials": "absent"}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".identity-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # link() makes the complete file visible without overwriting an identity
        # created by another process or following an existing symbolic link.
        os.link(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.unlink(temporary)
    return value


def validate_interfaces(mac, nics, directory=Path("/sys/class/net")):
    base = int.from_bytes(mac_bytes(mac), "big")
    for index in range(nics):
        interface = directory / f"eth{index}"
        expected = ":".join(f"{byte:02x}" for byte in (base + index).to_bytes(6, "big"))
        actual = (interface / "address").read_text().strip().lower()
        if actual != expected:
            raise ValueError(f"eth{index} MAC {actual} differs from configured virtual block {expected}")
        if (interface / "device/driver").resolve().name != "virtio_net":
            raise ValueError(f"eth{index} is not a VirtIO interface")


def command(*args):
    subprocess.run(args, check=True)


def interface_snapshot(directory=Path('/sys/class/net')):
    """Read kernel names/MACs plus both IPv4 and IPv6 configuration."""
    result = subprocess.run(('/sbin/ip', '-json', 'address', 'show'),
                            check=True, text=True, capture_output=True)
    addresses = json.loads(result.stdout)
    if not isinstance(addresses, list):
        raise ValueError('Invalid interface address snapshot')
    by_name = {item['ifname']: item for item in addresses}
    if len(by_name) != len(addresses):
        raise ValueError('Duplicate interface in address snapshot')
    interfaces = []
    for entry in directory.iterdir():
        if entry.name not in by_name:
            raise ValueError('Interface changed while taking address snapshot: ' + entry.name)
        driver = (entry / 'device/driver').resolve().name
        if driver != 'virtio_net':
            # Original kernels also expose sit/ipip/IPv6 tunnel devices. Their
            # iproute2 "address" is an IP endpoint, not the sysfs hardware-address
            # representation. Only retain foreign names for collision checks.
            interfaces.append({'name': entry.name, 'driver': driver})
            continue
        status = by_name[entry.name]
        mac = (entry / 'address').read_text().strip().lower()
        if status.get('address', '').lower() != mac:
            raise ValueError('Interface MAC changed while taking address snapshot: '
                             + entry.name + ' (sysfs=' + mac + ', ip='
                             + str(status.get('address')) + ')')
        interfaces.append({'name': entry.name, 'mac': mac,
                           'driver': driver,
                           'up': bool(int((entry / 'flags').read_text().strip(), 0) & 1)
                                 or 'UP' in status.get('flags', []),
                           'addresses': status.get('addr_info'), 'master': status.get('master')})
    if {item['name'] for item in interfaces} != set(by_name):
        raise ValueError('Interface set changed while taking address snapshot')
    return interfaces


def interface_order(interfaces):
    """Validate the exact local fourteen-MAC block and compute its port order."""
    names = [item['name'] for item in interfaces]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate interface names')
    ports = [item for item in interfaces if item['driver'] == 'virtio_net']
    if len(ports) != 14:
        raise ValueError('Port ordering requires exactly fourteen VirtIO interfaces')
    for item in ports:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}', item['name']):
            raise ValueError('Unsupported interface name')
        mac_bytes(item['mac'])  # Every address must be local and unicast.
    ports.sort(key=lambda item: int.from_bytes(mac_bytes(item['mac']), 'big'))
    base = int.from_bytes(mac_bytes(ports[0]['mac']), 'big')
    if [int.from_bytes(mac_bytes(item['mac']), 'big') for item in ports] != list(range(base, base + 14)):
        raise ValueError('VirtIO MACs must be a unique contiguous fourteen-address block')
    if (base & 0xffffff) + 14 > 0x1000000:
        raise ValueError('MAC block overflows low 24 bits')
    wanted = {f'eth{index}' for index in range(14)}
    if wanted.intersection(set(names) - {item['name'] for item in ports}):
        raise ValueError('A non-VirtIO interface occupies a required ethN name')
    return ports


def require_unconfigured(ports):
    for item in ports:
        if item['up'] or item['addresses'] != [] or item['master'] is not None:
            raise ValueError('Refusing to rename an up or configured port: ' + item['name'])


def normalize_virtual_interfaces(read=None, run=None):
    """Correct PCI enumeration before HAL/systemd, never on an active network.

    Proxmox netN is encoded by base-MAC + N. All fourteen ports are first moved
    to reserved temporary names, then to ethN. A failure reverses completed
    moves where possible and ALWAYS aborts the boot, even after full rollback.
    """
    options = require_guest()
    if [option for option in options if option.startswith('udm.nics=')] != ['udm.nics=14']:
        raise ValueError('Port ordering requires the explicit udm.nics=14 guest flag')
    read = interface_snapshot if read is None else read
    run = command if run is None else run
    snapshot = read()
    ports = interface_order(snapshot)
    mac = ports[0]['mac'].lower()
    if all(item['name'] == f'eth{index}' for index, item in enumerate(ports)):
        return mac  # Idempotent: an already configured, correctly named guest is untouched.
    if (Path('/proc/1/comm').read_text().strip() == 'systemd' or
            Path('/run/systemd/system').exists() or (RUNTIME / 'ready').exists()):
        raise ValueError('Port renaming is only allowed before HAL and systemd start')
    require_unconfigured(ports)
    temporary = [f'udmvtmp{index}' for index in range(14)]
    if set(temporary).intersection(item['name'] for item in snapshot):
        raise ValueError('Reserved temporary interface names are already occupied')
    moves = []
    try:
        for item, target in zip(ports, temporary):
            run('/sbin/ip', 'link', 'set', 'dev', item['name'], 'name', target)
            moves.append((item['name'], target))
        for index, source in enumerate(temporary):
            target = f'eth{index}'
            run('/sbin/ip', 'link', 'set', 'dev', source, 'name', target)
            moves.append((source, target))
        actual = interface_order(read())
        if [item['name'] for item in actual] != [f'eth{index}' for index in range(14)]:
            raise ValueError('Post-rename port order verification failed')
        if [item['mac'] for item in actual] != [item['mac'] for item in ports]:
            raise ValueError('Post-rename MAC verification failed')
        require_unconfigured(actual)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        failed = []
        for source, target in reversed(moves):
            try:
                run('/sbin/ip', 'link', 'set', 'dev', target, 'name', source)
            except (OSError, subprocess.CalledProcessError):
                failed.append(target)
        state = 'rollback incomplete: ' + ', '.join(failed) if failed else 'completed moves rolled back'
        raise ValueError('Port renaming failed; ' + state + '; aborting boot') from error
    print('UDM_VIRTUAL_PORTS_ORDERED: MAC-derived eth0..eth13', flush=True)
    return mac


def require_empty_spi_class(target=Path("/sys/class/spi_master")):
    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
        raise ValueError("Public SPI view requires an existing empty /sys/class/spi_master directory")


def install_spi_view(runtime=RUNTIME, target=Path("/sys/class/spi_master"), run=command):
    """Provide only the public flash-identification paths read by native UDAPI.

    Never hide a populated controller class. This does not create hardware,
    flash devices, secret keys, or signed manufacturer data.
    """
    require_empty_spi_class(target)
    source = runtime / "spi-master"
    device = source / "spi0/spi0.0/spi-nor"
    device.mkdir(parents=True, mode=0o755)
    for source_name, destination_name in (("spi-jedec-id", "jedec_id"), ("spi-uid", "uid")):
        path = device / destination_name
        with path.open("xb") as stream:
            stream.write((runtime / source_name).read_bytes())
        path.chmod(0o444)
    run("/bin/mount", "--bind", str(source), str(target))
    run("/bin/mount", "-o", "remount,bind,ro", str(target))


def verify_native(identity):
    path = Path("/proc/ubnthal/system.info")
    values = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
    if values.get("systemid") != "ea4c" or values.get("serialno") != identity["mac"].replace(":", ""):
        raise ValueError("Native HAL did not identify the expected public model and local virtual serial")
    if not Path("/proc/ubnthal/status/IsDefault").is_file():
        raise ValueError("Native HAL status interface is missing")


def validate_cli_identity(output, identity):
    values = dict(line.strip().split("=", 1) for line in output.splitlines() if "=" in line)
    sysid = values.get("board.sysid", "")
    if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", sysid) or int(sysid, 16) != 0xea4c:
        raise ValueError("Original ubnt-tools did not identify public board sysid ea4c")
    if values.get("board.shortname") != "UDMEA4C":
        raise ValueError("Original ubnt-tools did not identify UDMEA4C")
    if values.get("board.serialno") != identity["mac"].replace(":", ""):
        raise ValueError("Original ubnt-tools did not identify the local virtual serial")


def refresh_cli_identity(identity):
    # Unprivileged original services rely on the root-created board-info cache.
    Path("/tmp/.board_info").unlink(missing_ok=True)
    result = subprocess.run(("/sbin/ubnt-tools", "id"), check=True, text=True, capture_output=True)
    validate_cli_identity(result.stdout, identity)
    if not Path("/tmp/.board_info").is_file():
        raise ValueError("Original ubnt-tools did not create its board identity cache")
    print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")


def setup(nics=None):
    options = require_guest()
    if nics is None:
        counts = [option.split("=", 1)[1] for option in options if option.startswith("udm.nics=")]
        if len(counts) > 1 or (counts and not re.fullmatch(r"[0-9]+", counts[0])):
            raise ValueError("Invalid udm.nics kernel option")
        nics = int(counts[0]) if counts else 14
    if not 2 <= nics <= 14:
        raise ValueError("Expected 2..14 virtual NICs")
    mac = (normalize_virtual_interfaces() if nics == 14 else
           Path("/sys/class/net/eth0/address").read_text().strip().lower())
    mac_bytes(mac)
    validate_interfaces(mac, nics)
    identity = local_identity(mac, nics)
    if (RUNTIME / "ready").is_file():
        verify_native(identity)
        refresh_cli_identity(identity)
        print("UDM_VIRTUAL_HAL_ALREADY_READY")
        return identity
    if Path("/proc/ubnthal").exists():
        raise ValueError("Another HAL already owns /proc/ubnthal; start with a fresh guest boot")
    targets = (Path("/dev/mtdblock0"), Path("/dev/mtdblock5"))
    if any(target.exists() or target.is_symlink() for target in targets):
        raise ValueError("Refusing to replace an existing EEPROM device or file")
    require_empty_spi_class()
    module_directory = Path("/lib/modules") / KERNEL / "updates"
    for name in ("ubnt_common.ko", "ubnthal.ko"):
        if not (module_directory / name).is_file():
            raise ValueError(f"Original firmware module missing: {name}")
    for name in ("mtd", "cpumidr"):
        if not (Path("/proc") / name).is_file():
            raise ValueError(f"Expected native /proc/{name} endpoint is missing")
    RUNTIME.mkdir(mode=0o755, exist_ok=False)
    payload = make_payload(mac, nics, identity["uuid"])
    inspect_eeprom(payload["eeprom.bin"])
    for name, data in payload.items():
        path = RUNTIME / name
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o444)
    # A regular file, never a block device and never a host flash operation.
    for target in targets:
        with target.open("xb"):
            pass
    for source, destination in (("eeprom.bin", "/dev/mtdblock0"), ("eeprom.bin", "/dev/mtdblock5"),
                                ("proc-mtd", "/proc/mtd"),
                                ("proc-cpumidr", "/proc/cpumidr")):
        command("/bin/mount", "--bind", str(RUNTIME / source), destination)
        command("/bin/mount", "-o", "remount,bind,ro", destination)
    install_spi_view()
    if not Path("/sys/module/ubnt_common").is_dir():
        command("/sbin/insmod", str(module_directory / "ubnt_common.ko"))
    command("/sbin/insmod", str(module_directory / "ubnthal.ko"))
    verify_native(identity)
    refresh_cli_identity(identity)
    (RUNTIME / "ready").write_text("virtual=1\ncredentials=absent\nmodule=original-firmware\n", encoding="ascii")
    print("UDM_VIRTUAL_HAL_NATIVE_READY")
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nics", type=int, choices=range(2, 15), help="Default: udm.nics, otherwise 14")
    args = parser.parse_args()
    try:
        setup(args.nics)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"UDM_VIRTUAL_HAL_FAILURE: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
