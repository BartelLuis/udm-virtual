#!/usr/bin/env python3
"""Run locally with isolated NICs; use proxmox-import.sh for bridge assignment."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def command(assets, mode=None, nics=None, memory=4096, cores=2, snapshot=False):
    assets = Path(assets).resolve()
    if "," in str(assets):
        raise ValueError("QEMU asset path must not contain commas")
    manifest = json.loads((assets / "manifest.json").read_text())
    status = manifest.get("status")
    if status not in ("experimental-boot-lab", "experimental-virtual-gateway"):
        raise ValueError("Unknown build manifest")
    virtual = status == "experimental-virtual-gateway"
    if mode is None:
        mode = "systemd" if virtual else "shell"
    if nics is None:
        nics = 14 if virtual else 2
    if mode not in ("shell", "systemd", "selftest"):
        raise ValueError("Mode must be shell, systemd, or selftest")
    if not isinstance(nics, int) or not 2 <= nics <= 14:
        raise ValueError("Expected 2..14 virtual NICs")
    if virtual and nics != 14:
        raise ValueError("Virtual profile requires --nics 14")
    for name in ("Image", "initramfs.gz", "rootfs.qcow2"):
        with (assets / name).open("rb") as stream:
            hashed = hashlib.sha256()
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                hashed.update(block)
            digest = hashed.hexdigest()
        if digest != manifest["artifacts"][name]["sha256"]:
            raise ValueError(f"Build artifact changed: {name}")
    # State is writable and intentionally changes between boots.
    cmd = ["qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "max", "-accel", "tcg",
           "-smp", str(cores), "-m", str(memory), "-kernel", str(assets / "Image"),
           "-initrd", str(assets / "initramfs.gz"), "-append",
           f"console=ttyAMA0 earlycon root=/dev/vda state=/dev/vdb udm.mode={mode} udm.nics={nics} net.ifnames=0 panic=-1 "
           "initcall_blacklist=mrvl_swup_init,uart_redirect_init,mub_gen_init,portm_boot_cfg_init "
           "module_blacklist=phy_diag",
           "-drive", f"file={assets / 'rootfs.qcow2'},if=none,id=root,format=qcow2,readonly=on",
           "-device", "virtio-blk-pci,drive=root",
           "-drive", f"file={assets / 'state.qcow2'},if=none,id=state,format=qcow2" + (",snapshot=on" if snapshot or mode == "selftest" else ""),
           "-device", "virtio-blk-pci,drive=state",
           "-device", "virtio-balloon-pci,free-page-reporting=on",
           "-display", "none", "-serial", "mon:stdio", "-no-reboot"]
    for index in range(nics):
        cmd += ["-netdev", f"hubport,id=port{index},hubid={index}", "-device",
                f"virtio-net-pci,netdev=port{index},mac=02:55:44:4d:00:{index:02x}"]
    return cmd


def run_selftest(cmd, log, timeout=180):
    expired = False
    # The child writes directly to the file so a stalled boot remains observable
    # with tail, and serial output does not accumulate in a parent-side pipe.
    with Path(log).open('wb', buffering=0) as console:
        process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=console,
                                   stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
        finally:
            # Also runs on KeyboardInterrupt. Only this Popen child is stopped;
            # reap it before closing its log or propagating an interruption.
            if process.poll() is None:
                process.kill()
                process.wait()
    output = Path(log).read_bytes()
    passed = (not expired and process.returncode == 0 and b"UDM_LAB_SELFTEST_PASS" in output
              and all(marker not in output for marker in (b"UDM_LAB_SELFTEST_FAIL", b"UDM_LAB_INIT_FAILURE",
                                                         b"Kernel panic", b"SQUASHFS error:")))
    print(f"Selftest {'PASS' if passed else 'FAIL'}; log: {log}")
    if not passed:
        print(output[-6000:].decode(errors="replace"), file=sys.stderr)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=Path("build"))
    parser.add_argument("--mode", choices=("shell", "systemd", "selftest"),
                        help="Default: systemd for virtual builds, shell for lab builds")
    parser.add_argument("--nics", type=int, choices=range(2, 15),
                        help="Default: 14 for virtual builds, 2 for lab builds")
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--cores", type=int, default=2)
    parser.add_argument("--snapshot", action="store_true", help="Discard state changes after exit (automatic for selftest)")
    parser.add_argument("--log", type=Path, help="Selftest log destination (default: assets/selftest.log)")
    args = parser.parse_args()
    if args.memory < 2048 or not 1 <= args.cores <= 16:
        parser.error("Use at least 2048 MiB RAM and 1..16 CPUs")
    try:
        cmd = command(args.assets, args.mode, args.nics, args.memory, args.cores, args.snapshot)
        if args.mode == "selftest":
            return run_selftest(cmd, args.log or args.assets / "selftest.log")
        return subprocess.call(cmd)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(1, f"Lab failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
