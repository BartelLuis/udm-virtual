#!/usr/bin/env python3
"""Build the original ARM64 firmware into an experimental QEMU boot lab."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from firmware import discover_firmware, extract_firmware
from fit import prepare_fit
from initramfs import patch_initramfs

BASE = Path(__file__).resolve().parent


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*args):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run([str(arg) for arg in args], check=True)


def build(firmware, output, state_size, profile='lab'):
    if sys.platform != "linux":
        raise ValueError("Run under Linux or use build.ps1 to build through Debian WSL")
    for tool in ("qemu-img", "mke2fs"):
        if shutil.which(tool) is None:
            raise ValueError(f"Missing {tool}; install qemu-utils and e2fsprogs")
    if not 8 <= state_size <= 256:
        raise ValueError("State disk size must be 8..256 GiB")
    if profile not in ('lab', 'virtual'):
        raise ValueError('Unknown build profile')
    source = discover_firmware(firmware)
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    if shutil.disk_usage(output).free < 3 * 1024 ** 3:
        raise ValueError("Output filesystem needs at least 3 GiB free (avoid small /tmp RAM disks)")
    print("Checking and extracting original firmware ...", flush=True)
    report = extract_firmware(source, output / "source", parts=["kernel", "rootfs"])
    model = report['model']
    uxg = model == 'UXGENT'
    if (model, report['platform']) not in (('UDMEA4C', 'cn10k'), ('UXGENT', 'cn9670')):
        raise ValueError("Supported firmware models are UDMEA4C.cn10k and UXGENT.cn9670")
    if uxg and profile != 'virtual':
        raise ValueError('UXGENT requires --profile virtual')
    prepare_fit(output / "source/kernel.bin", output / "boot")
    shutil.copyfile(output / "boot/Image", output / "Image")
    payload, adaptation = None, None
    if profile == 'virtual':
        if uxg:
            from virtualization.build_uxg_payload import build_payload
        else:
            from virtualization.build_payload import build_payload
        payload, adaptation = build_payload(output / 'source/rootfs.bin', output / 'adaptation', report['sha256'])
    patch_initramfs(output / "boot/original-initramfs.gz", BASE / "guest-lab-init.sh", output / "initramfs.gz", payload)
    run("qemu-img", "convert", "-f", "raw", "-O", "qcow2", output / "source/rootfs.bin", output / "rootfs.qcow2")
    # Only create and format a new regular file; no loop device or host mount.
    # Linux temp storage preserves sparsity even when output is a Windows share.
    with tempfile.TemporaryDirectory(prefix="udm-beast-build-", dir="/var/tmp") as temp:
        raw = Path(temp) / "state.raw"
        with raw.open("xb") as stream:
            stream.truncate(state_size * 1024 ** 3)
        run("mke2fs", "-q", "-F", "-t", "ext4", "-L", "udm-lab-state", "-O", "^metadata_csum_seed,^orphan_file", raw)
        run("qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, output / "state.qcow2")
    artifacts = {name: {"sha256": sha256(output / name), "size_bytes": (output / name).stat().st_size}
                 for name in ("Image", "initramfs.gz", "rootfs.qcow2", "state.qcow2")}
    manifest = {
        "status": "experimental-boot-lab", "model": model, "firmware_version": report["version"],
        "firmware_sha256": report["sha256"], "architecture": "aarch64", "machine": "virt",
        "artifacts": artifacts, "state_size_gib": state_size,
        "changes": ["Original /init replaced with guest-lab-init.sh; remaining initramfs entries preserved",
                    "Original kernel and squashfs unchanged; separate writable ext4 overlay",
                    "Boot arguments skip mrvl_swup_init,uart_redirect_init,mub_gen_init,portm_boot_cfg_init; module_blacklist=phy_diag blocks physical PHY diagnostics",
                    "No emulation of proprietary board interfaces or Marvell switch/offload"],
        "gateway_verified": False,
        "signature_authenticated": False,
    }
    if profile == 'virtual' and uxg:
        manifest.update(status='experimental-virtual-gateway', profile='virtual', nics=6,
                        default_boot_mode='systemd', adaptation=adaptation,
                        wan_ports=[0, 4], lan_ports=[1, 2, 3, 5],
                        controller='external-unifi-network', adoption_verified=False,
                        cpu_model='max', cpu_properties={'pauth': False})
        manifest['changes'] = [
            'Original ARM64 kernel and read-only SquashFS; separate persistent ext4 overlay',
            'CN9670 initcall_blacklist=mrvl_swup_init,mub_gen_init,cpu_debug_init avoids physical SMC/MMIO initializers',
            'QEMU max-arm-cpu.pauth=off avoids a pointer-authentication fault in the original tm_crypto module during controller provisioning',
            'Original HAL modules use locally generated public UXGENT board metadata without manufacturing credentials',
            'Six VirtIO ports ordered by their local MAC block; original native Linux switch/VLAN topology',
            'Optional explicit WAN MAC preserves locally generated board identity and the other five port MACs',
            'Physical port aliases and unavailable board peripherals adapted for QEMU virt',
            'Physical storage manager and flash-device creator masked; persistence is supplied by the initramfs overlay',
            'Generic nginx and lighttpd preset units masked so the original UXG setup server owns HTTP/HTTPS; native UDAPI-managed web daemons retained',
            'Original UXG setup and external-controller adoption services retained; no integrated Network controller',
            'Native UDAPI DNS resolver, persistent FreeRADIUS initialization and extended TCG startup timeouts',
        ]
    elif profile == 'virtual':
        manifest.update(status='experimental-virtual-gateway', profile='virtual', nics=14,
                        default_boot_mode='systemd', adaptation=adaptation,
                        wan_ports=[8, 12], lan_ports=[i for i in range(14) if i not in (8, 12)])
        manifest['changes'][-1] = ('Original HAL modules read locally generated virtual EEPROM metadata; '
                                   'version-guarded CPSS adaptation uses native Linux interfaces; '
                                   'physical manufacturing-record attestation disabled for virtual hardware; '
                                   'board/default configurations and controller port table adapted for fourteen VirtIO ports')
        manifest['changes'].extend([
            'Original controller dependencies use a verified read-only extracted classpath and C1 compilation under TCG',
            'First boot validates or initializes local FreeRADIUS DH parameters and the local self-signed TLS certificate',
            'Only the hash-verified physical PHY diagnostic late-boot hook is skipped; other original late-boot hooks remain',
            'Reconcile the full controller device cache after every authenticated AES-GCM inform; original authentication and provisioning remain in effect',
            'Migrate only the exact previously supported controller overlay from its hash-verified original on the read-only firmware mount',
            'Mask first-boot preset DNS duplicates and use native UDAPI dnsmasq for an absent or systemd-managed guest resolver; preserve custom resolver files',
        ])
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built {output} ({manifest['status']}); runtime validation is a separate step.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--output", type=Path, default=Path("build"), help="New directory; existing directories are refused")
    parser.add_argument("--state-size-gib", type=int, default=32)
    parser.add_argument('--profile', choices=('lab', 'virtual'), default='lab')
    args = parser.parse_args()
    try:
        build(args.firmware, args.output, args.state_size_gib, args.profile)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
