#!/usr/bin/env bash
# Import an experimental original-firmware ARM64 lab or virtual gateway.
# Sources for the VM configuration:
# https://github.com/proxmox/qemu-server/blob/master/src/PVE/QemuServer.pm
# https://github.com/proxmox/qemu-server/blob/master/src/PVE/QemuServer/CPUConfig.pm
# https://www.qemu.org/docs/master/system/arm/virt.html
set -Eeuo pipefail
export LC_ALL=C

usage() {
    cat <<'HELP'
Usage: bash proxmox-import.sh --storage STORAGE --assets DIR [OPTIONS]

Virtual gateway: --port 8=WAN_BRIDGE --port 0=LAN_BRIDGE [--port N=BRIDGE ...]
Boot laboratory: --bridge BRIDGE --bridge BRIDGE [--bridge BRIDGE ...]

Default: validate local assets and print an apply command; no Proxmox changes.
  --vmid ID|auto          Preferred VMID, default auto; occupied IDs fall back
                          to the next free cluster ID (including containers)
  --apply                 Create the stopped VM after checking this host
  --dry-run               Explicitly select the default command-plan mode
  --boot-mode shell|system Default: system for virtual builds, shell for lab builds
  --connect               Connect assigned NIC links; otherwise every link is down
  --port N=BRIDGE          Virtual profile: assign port netN (0..13) to a bridge
                          All fourteen ports are created; unassigned ports stay down
                          WAN: net8, WAN2: net12; other ports initially share LAN
  --memory MIB            RAM, default 8192 (minimum 1024)
  --cores N               Emulated cores, default 4 (1..16)
  --snippets-dir DIR      Kernel asset directory, default /var/lib/vz/snippets

Needs Image, initramfs.gz, rootfs.qcow2, state.qcow2 and manifest.json.
The manifest must have status experimental-boot-lab or
experimental-virtual-gateway and an artifacts map containing SHA256 hashes.
Virtual builds accept individual --port assignments, no assignments, or exactly
fourteen --bridge options in port order. Lab builds require 2..14 --bridge options.
Do not combine --port and --bridge. Existing host bridges are selected by name.
The script never starts the VM or edits host bridge configuration.
Keep all fourteen virtual-profile NICs and their generated MAC addresses;
change bridge/link settings only. The guest orders ports by this MAC block.
Kernel/initramfs files are local to this node and are not in VM disk backups.
HELP
}

die() { printf 'Error: %s\n' "$*" >&2; exit 2; }
need_value() { (( $# >= 2 )) && [[ -n $2 ]] || die "Missing value for $1"; }
original_args=("$@")
vmid=auto storage= assets= snippets=/var/lib/vz/snippets
memory=8192 cores=4 boot_mode= apply=0 connect=0
bridges=()
port_assignments=()
while (( $# )); do
    case "$1" in
        --vmid) need_value "$@"; vmid=$2; shift 2 ;;
        --storage) need_value "$@"; storage=$2; shift 2 ;;
        --assets) need_value "$@"; assets=$2; shift 2 ;;
        --bridge) need_value "$@"; bridges+=("$2"); shift 2 ;;
        --port) need_value "$@"; port_assignments+=("$2"); shift 2 ;;
        --memory) need_value "$@"; memory=$2; shift 2 ;;
        --cores) need_value "$@"; cores=$2; shift 2 ;;
        --boot-mode) need_value "$@"; boot_mode=$2; shift 2 ;;
        --snippets-dir) need_value "$@"; snippets=$2; shift 2 ;;
        --apply) apply=1; shift ;;
        --dry-run) apply=0; shift ;;
        --connect) connect=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ $vmid == auto || $vmid =~ ^[1-9][0-9]{2,8}$ ]] || die 'VMID must be auto or 100..999999999.'
[[ $storage =~ ^[A-Za-z][A-Za-z0-9_-]*$ ]] || die 'Specify a valid Proxmox storage ID.'
[[ $memory =~ ^[1-9][0-9]{3,6}$ ]] && (( memory >= 1024 && memory <= 1048576 )) || die 'Memory must be 1024..1048576 MiB.'
[[ $cores =~ ^[1-9][0-9]?$ ]] && (( cores <= 16 )) || die 'Cores must be 1..16.'
[[ -z $boot_mode || $boot_mode == shell || $boot_mode == system ]] || die 'Boot mode must be shell or system.'
for bridge in "${bridges[@]}"; do
    [[ $bridge =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]] || die "Invalid bridge name: $bridge"
done
command -v python3 >/dev/null || die 'python3 is required.'
[[ -d $assets ]] || die "Asset directory does not exist: $assets"
assets=$(cd -- "$assets" && pwd -P)
# This path becomes part of Proxmox's parsed QEMU args; keep its alphabet strict.
[[ $snippets =~ ^/[A-Za-z0-9_./-]+$ && $snippets != *'/../'* && $snippets != */.. ]] || die 'Snippets directory must be an absolute path without spaces or parent traversal.'
snippets=${snippets%/}
profile=$(python3 - "$assets" <<'PY'
import hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
try:
    manifest_path = root / 'manifest.json'
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError('manifest.json must be a regular file, not a symlink')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    status = manifest.get('status')
    if status not in ('experimental-boot-lab', 'experimental-virtual-gateway'):
        raise ValueError('unknown experimental manifest status')
    if status == 'experimental-virtual-gateway' and manifest.get('nics') != 14:
        raise ValueError('virtual profile requires fourteen ports')
    for name in ('Image', 'initramfs.gz', 'rootfs.qcow2', 'state.qcow2'):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(name + ' must be a regular file, not a symlink')
        expected = manifest.get('artifacts', {}).get(name, {}).get('sha256', '')
        if not isinstance(expected, str) or not re.fullmatch('[a-fA-F0-9]{64}', expected):
            raise ValueError('missing SHA256 for ' + name)
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            prefix = stream.read(64)
            digest.update(prefix)
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected.lower():
            raise ValueError('SHA256 mismatch: ' + name)
        if name == 'Image' and prefix[56:60] != b'ARM\x64':
            raise ValueError('Image is not an uncompressed ARM64 Linux kernel')
        if name == 'initramfs.gz' and prefix[:2] != b'\x1f\x8b':
            raise ValueError('initramfs.gz is not gzip data')
        if name.endswith('.qcow2') and prefix[:4] != b'QFI\xfb':
            raise ValueError(name + ' is not QCOW2')
    print('virtual' if status == 'experimental-virtual-gateway' else 'lab')
except (OSError, ValueError, TypeError, AttributeError) as exc:
    sys.exit('Asset validation failed: ' + str(exc))
PY
)

if [[ $profile == virtual ]]; then
    [[ -n $boot_mode ]] || boot_mode=system
    if (( ${#bridges[@]} )); then
        (( ${#bridges[@]} == 14 && ${#port_assignments[@]} == 0 )) || die 'Virtual profile: use --port N=BRIDGE or exactly fourteen --bridge options.'
    else
        for ((index=0; index<14; index++)); do bridges+=(""); done
        for assignment in "${port_assignments[@]}"; do
            [[ $assignment =~ ^([0-9]|1[0-3])=([A-Za-z0-9][A-Za-z0-9_.-]{0,14})$ ]] || die "Invalid port assignment: $assignment"
            index=${BASH_REMATCH[1]}
            [[ -z ${bridges[index]} ]] || die "Port net$index assigned more than once."
            bridges[index]=${BASH_REMATCH[2]}
        done
    fi
else
    [[ -n $boot_mode ]] || boot_mode=shell
    (( ${#port_assignments[@]} == 0 )) || die '--port requires the virtual profile.'
    (( ${#bridges[@]} >= 2 && ${#bridges[@]} <= 14 )) || die 'Specify 2..14 --bridge options in NIC order.'
fi

print_command() { printf '%q ' "$@"; printf '\n'; }
if (( ! apply )); then
    printf '# Local assets verified; this command performs the Proxmox host checks.\n'
    printf '# The free VMID is selected when the command runs, not reserved by this plan.\n'
    printf '# Creates a stopped VM; kernel/initramfs require separate backup.\n'
    printf 'set -euo pipefail\n'
    print_command cd -- "$PWD"
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    print_command bash "$script_dir/$(basename -- "${BASH_SOURCE[0]}")" "${original_args[@]}" --apply
    exit 0
fi

# Proxmox returns a JSON scalar, which may be a number or a quoted numeric
# string. Never compare its raw JSON representation against the requested ID.
select_vmid() {
    python3 - "$1" <<'PY'
import json, re, subprocess, sys

def api(path, *arguments):
    result = subprocess.run(['pvesh', 'get', path, *arguments, '--output-format', 'json'],
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Proxmox API ' + path + ' failed: ' + result.stderr.strip())
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise ValueError('Proxmox API ' + path + ' returned invalid JSON') from None

def parse_id(value):
    if type(value) not in (str, int) or not re.fullmatch(r'[1-9][0-9]{2,8}', str(value)):
        raise ValueError('Proxmox returned an invalid VMID; expected 100..999999999')
    return int(value)

try:
    preferred = None if sys.argv[1] == 'auto' else parse_id(sys.argv[1])
    occupied = set()
    if preferred is not None:
        resources = api('/cluster/resources', '--type', 'vm')
        if not isinstance(resources, list):
            raise ValueError('Proxmox cluster resources must be a JSON array')
        for resource in resources:
            if not isinstance(resource, dict) or resource.get('type') not in ('qemu', 'lxc', 'openvz'):
                raise ValueError('Proxmox returned an unexpected VM resource')
            occupied.add(parse_id(resource.get('vmid')))
    arguments = ('--vmid', str(preferred)) if preferred is not None and preferred not in occupied else ()
    selected = parse_id(api('/cluster/nextid', *arguments))
    if selected in occupied or (arguments and selected != preferred):
        raise ValueError('Proxmox returned an inconsistent free VMID; retry the import')
    if preferred is not None and preferred in occupied:
        print(f'Preferred VMID {preferred} is occupied; using free cluster VMID {selected}.', file=sys.stderr)
    else:
        print(f'Using free cluster VMID {selected}.', file=sys.stderr)
    print(selected)
except (OSError, ValueError) as error:
    sys.exit('VMID selection failed: ' + str(error))
PY
}

mode=$boot_mode
[[ $mode != system ]] || mode=systemd
# These board-only initcalls issue SMC calls to absent Marvell firmware on virt.
# This is a boot compatibility workaround, not switch/offload emulation.
blacklist=mrvl_swup_init,uart_redirect_init,mub_gen_init,portm_boot_cfg_init
cmdline="console=ttyAMA0 earlycon root=/dev/vda state=/dev/vdb udm.mode=$mode udm.nics=${#bridges[@]} net.ifnames=0 panic=-1 initcall_blacklist=$blacklist module_blacklist=phy_diag"
# PVE's machine schema does not expose gic-version. This additional -machine
# option sets that property on the virt machine selected by --machine above.
run() {
    print_command "$@" >&2
    "$@"
}

# Discover the volume from qm's actual unused-disk configuration. Never guess
# vm-ID-disk-0: storage backends and stale volumes can alter the allocated name.
import_disk() {
    local vm_id=$1 source_image=$2 store=$3 device=$4 extra=$5
    local before after volume
    before=$(qm config "$vm_id")
    qm disk import "$vm_id" "$source_image" "$store" --format raw
    after=$(qm config "$vm_id")
    volume=$(python3 -c '
import re, sys
def unused(config):
    return set(re.findall(r"^unused[0-9]+:\s*(\S+)\s*$", config, re.M))
added = unused(sys.argv[2]) - unused(sys.argv[1])
if len(added) != 1:
    sys.exit("Expected exactly one newly imported unused volume; inspect qm config manually")
volume = added.pop()
if not re.fullmatch(re.escape(sys.argv[3]) + r":[A-Za-z0-9_.+/-]+", volume):
    sys.exit("Unexpected imported volume identifier")
if not re.search(r"(?:^|/)vm-" + re.escape(sys.argv[4]) + r"-", volume.split(":", 1)[1]):
    sys.exit("Imported volume does not belong to this VM")
print(volume)
' "$before" "$after" "$store" "$vm_id")
    qm set "$vm_id" "--$device" "$volume,$extra"
}

check_launch() {
    local launch
    launch=$(qm showcmd "$1")
    python3 -c '
import re, shlex, sys
args = shlex.split(sys.argv[1])
def values(option):
    return [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == option]
if not any("qemu-system-aarch64" in arg for arg in args):
    sys.exit("qm did not select qemu-system-aarch64")
cpu = values("-cpu")
if len(cpu) != 1 or cpu[0].split(",")[0] != "max":
    sys.exit("This qemu-server does not honor ARM64 --cpu max; use a version with ARM CPU-model support (merged February 2026)")
machine = values("-machine")
if not machine or not any(re.fullmatch(r"(?:type=)?virt(?:-[0-9]+\.[0-9]+)?(?:\+pve[0-9]+)?", part) for value in machine for part in value.split(",")):
    sys.exit("qm did not select an ARM virt machine")
if "gic-version=3" not in [part for value in machine for part in value.split(",")]:
    sys.exit("qm did not preserve the tested GICv3 machine configuration")
if "-enable-kvm" in args or any("kvm" in value for value in values("-accel")) or any("accel=kvm" in value for value in machine):
    sys.exit("Unexpected KVM accelerator in cross-architecture VM")
if any("pflash" in value for value in values("-drive")) or values("-bios"):
    sys.exit("Unexpected firmware boot path: this VM needs direct kernel boot")
if values("-kernel") != [sys.argv[2] + "/Image"] or values("-initrd") != [sys.argv[2] + "/initramfs.gz"]:
    sys.exit("qm did not preserve the requested kernel/initramfs")
' "$launch" "$2"
}

preflight_host() {
    (( EUID == 0 )) || die '--apply must run as root on the Proxmox node.'
    for command in qm pvesm pvesh ip qemu-img qemu-system-aarch64 install; do
        command -v "$command" >/dev/null || die "Missing $command; install/configure the required Proxmox ARM64 emulator support first. This script does not install packages."
    done
    status=$(pvesm status --storage "$storage" --content images --enabled 1)
    python3 -c '
import sys
rows = [line.split() for line in sys.argv[1].splitlines()]
matches = [row for row in rows if row and row[0] == sys.argv[2]]
if len(matches) != 1 or len(matches[0]) < 3 or matches[0][2] != "active":
    sys.exit("Selected storage must be enabled, active and support VM images")
' "$status" "$storage"
    links=$(ip -json -details link show)
    python3 -c '
import json, sys
links = json.loads(sys.argv[1])
bridges = {link["ifname"] for link in links if link.get("linkinfo", {}).get("info_kind") in ("bridge", "openvswitch")}
missing = (set(sys.argv[2:]) - {""}) - bridges
if missing:
    sys.exit("Bridge devices do not exist on this node: " + ", ".join(sorted(missing)))
' "$links" "${bridges[@]}"
    cpu_help=$(qemu-system-aarch64 -cpu help)
    [[ $cpu_help =~ (^|[[:space:]])max($|[[:space:]]) ]] || die 'ARM64 QEMU does not offer CPU max.'
    machines=$(qemu-system-aarch64 -machine help)
    [[ $machines =~ (^|[[:space:]])virt($|[[:space:]]) ]] || die 'ARM64 QEMU does not offer machine virt.'
    for disk in rootfs.qcow2 state.qcow2; do
        info=$(qemu-img info -f qcow2 --output=json "$assets/$disk")
        python3 -c '
import json, sys
info = json.loads(sys.argv[1])
data = info.get("format-specific", {}).get("data", {})
if (info.get("format") != "qcow2" or info.get("backing-filename") or
        info.get("encrypted") or data.get("data-file") or info.get("virtual-size", 0) <= 0):
    sys.exit("Disk must be standalone unencrypted QCOW2 without an external data/backing file")
' "$info"
    done
}
preflight_host

# Resolve before building any paths, arguments or MACs from the ID. The API
# query does not reserve an ID; qm create still arbitrates concurrent imports.
vmid=$(select_vmid "$vmid")
target="$snippets/udm-beast-$vmid"
[[ ! -e $target && ! -L $target ]] || die "Kernel destination already exists: $target"
qemu_args="-machine gic-version=3 -kernel $target/Image -initrd $target/initramfs.gz -append '$cmdline'"
create=(qm create "$vmid" --name "udm-beast-$profile-$vmid" --arch aarch64
        --machine virt --cpu max --kvm 0 --bios seabios --ostype l26
        --memory "$memory" --cores "$cores" --sockets 1 --balloon 0
        --serial0 socket --vga serial0 --tablet 0 --hotplug 0 --onboot 0
        --vmgenid 0 --args "$qemu_args"
        --description 'Experimental original UniFi ARM64 guest; full UI provisioning remains unverified. Local kernel/initramfs are outside VM backups.')
link_down=$((1-connect))
for index in "${!bridges[@]}"; do
    printf -v mac '02:%02x:%02x:%02x:%02x:%02x' "$((vmid >> 24 & 255))" "$((vmid >> 16 & 255))" "$((vmid >> 8 & 255))" "$((vmid & 255))" "$index"
    if [[ -n ${bridges[index]} ]]; then
        create+=("--net$index" "virtio=$mac,bridge=${bridges[index]},link_down=$link_down")
    else
        create+=("--net$index" "virtio=$mac,link_down=1")
    fi
done
trap 'rc=$?; printf "Import stopped (exit %s). Inspect VM %s and %s for partial resources; nothing was automatically deleted or started.\n" "$rc" "$vmid" "$target" >&2; exit "$rc"' ERR

run mkdir -p -- "$snippets"
run mkdir -- "$target"
run install -m 0644 -- "$assets/Image" "$assets/initramfs.gz" "$assets/manifest.json" "$target/"
run "${create[@]}"
# Do this before disk allocation so unsupported PVE versions fail early.
run check_launch "$vmid" "$target"
run import_disk "$vmid" "$assets/rootfs.qcow2" "$storage" virtio0 'ro=1,cache=none'
run import_disk "$vmid" "$assets/state.qcow2" "$storage" virtio1 'cache=none,discard=on'
run qm set "$vmid" --boot order=virtio0
printf '\nCreated stopped VM %s. Assigned NIC links: %s. Boot mode: %s.\n' "$vmid" "$([[ $connect == 1 ]] && printf connected || printf disconnected)" "$boot_mode"
printf 'Unassigned NICs remain disconnected. Keep generated MAC addresses and all virtual-profile NICs.\n'
printf 'To inspect/start explicitly: qm config %s; qm start %s; qm terminal %s\n' "$vmid" "$vmid" "$vmid"
printf 'Retain %s separately from VM backups and copy it before migration.\n' "$target"
