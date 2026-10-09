#!/usr/bin/env python3
"""Boot an owned snapshot guest and validate its isolated original IPv4 gateway.

Requires QEMU and assets built with --profile virtual. No host interfaces,
bridges, TAP devices or Internet access are used. Guest state writes are
discarded. Logs and packet captures go into a new output directory.
"""
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import time
import uuid

from validation.netprobe import Capture, Peer, run_connected


BASE = Path(__file__).resolve().parent


def load_run_lab():
    spec = importlib.util.spec_from_file_location("udm_validation_run_lab", BASE / "run-lab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reserve_listeners():
    """Hold ephemeral loopback ports until QEMU connects: no release/rebind race."""
    listeners = {}
    try:
        for name in ("lan", "wan"):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners[name] = listener
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.2)
        return listeners
    except BaseException:
        for listener in listeners.values():
            listener.close()
        raise


def build_command(assets, output, ports, memory=4096, cores=4, factory=None, test_policy=False):
    assets, output = Path(assets).resolve(), Path(output).resolve()
    if "," in str(output):
        raise ValueError("QEMU log path must not contain commas")
    manifest = json.loads((assets / "manifest.json").read_text())
    if manifest.get("profile") != "virtual":
        raise ValueError("Network validation requires assets built with --profile virtual")
    if factory is None:
        factory = load_run_lab().command
    command = list(factory(assets, "systemd", nics=14, memory=memory, cores=cores, snapshot=True))
    changed, backends, serials = set(), set(), 0
    for index in range(len(command) - 1):
        if command[index] == "-netdev":
            value = command[index + 1]
            parts = value.split(",")
            fields = dict(part.split("=", 1) for part in parts[1:] if "=" in part)
            name = fields.get("id")
            if parts[0] != "hubport" or name in backends:
                raise ValueError("Base lab command must expose unique isolated hubport NICs")
            backends.add(name)
            if name in ("port0", "port8"):
                link = "lan" if name == "port0" else "wan"
                command[index + 1] = f"socket,id={name},connect=127.0.0.1:{ports[link]}"
                changed.add(name)
        elif command[index] == "-serial":
            command[index + 1] = "file:" + str(output / "serial.log")
            serials += 1
    if backends != {f"port{index}" for index in range(14)} or changed != {"port0", "port8"} or serials != 1:
        raise ValueError("Unexpected lab command NIC or serial layout")
    if not any("id=state," in arg and "snapshot=on" in arg for arg in command):
        raise ValueError("Base lab command did not enable snapshot state")
    if test_policy:
        command[command.index('-append') + 1] += ' udm.validation=firewall'
    command += ["-monitor", "none"]
    return command


def accept_peers(listeners, selector, process, deadline):
    peers = {}
    try:
        for name, listener in listeners.items():
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"Owned QEMU exited while connecting {name}: {process.returncode}")
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Owned QEMU did not connect its {name} Ethernet backend")
                try:
                    connection, address = listener.accept()
                    break
                except socket.timeout:
                    continue
            if address[0] != "127.0.0.1":
                connection.close()
                raise ValueError("Non-loopback packet peer refused")
            try:
                peers[name] = Peer(name, None, selector, connection=connection)
            except BaseException:
                connection.close()
                raise
        return peers
    except BaseException:
        for peer in peers.values():
            peer.close()
        raise


def stop_owned(process):
    """Only the directly created Popen object is ever signalled."""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def validate(assets, output, memory=4096, cores=4, timeout=600, drop_window=10, test_policy=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    listeners, peers, process, capture = {}, {}, None, None
    selector = selectors.DefaultSelector()
    report = {"passed": False, "failure": "Validation did not initialize"}
    started = time.monotonic()
    try:
        listeners = reserve_listeners()
        ports = {name: listener.getsockname()[1] for name, listener in listeners.items()}
        command = build_command(assets, output, ports, memory, cores, test_policy=test_policy)
        (output / "command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
        capture = Capture(output / "packets.pcap")
        with (output / "qemu.log").open("xb") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            started = time.monotonic()
            deadline = started + timeout
            peers = accept_peers(listeners, selector, process, min(deadline, started + 30))
            for listener in listeners.values():
                listener.close()
            listeners.clear()
            report = run_connected(peers, selector, capture, max(0, deadline - time.monotonic()), drop_window,
                                   process=process)
    except KeyboardInterrupt:
        report = {"passed": False, "failure": "Interrupted by user"}
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        report = {"passed": False, "failure": str(error)}
    finally:
        # Termination is restricted to the process launched above. There is no
        # PID discovery, process-name matching, or interaction with another VM.
        try:
            stop_owned(process)
        finally:
            for peer in peers.values():
                peer.close()
            for listener in listeners.values():
                listener.close()
            selector.close()
            if capture:
                capture.close()
    serial_path = output / "serial.log"
    serial = serial_path.read_bytes() if serial_path.is_file() else b""
    fatal_markers = [marker for marker in ("UDM_LAB_INIT_FAILURE", "UDM_VIRTUAL_HAL_FAILURE", "Kernel panic",
                                         "SQUASHFS error:")
                     if marker.encode() in serial]
    if fatal_markers:
        report["passed"] = False
        report["failure"] = "Guest boot failure: " + ", ".join(fatal_markers)
    if test_policy and b'UDM_VIRTUAL_VALIDATION_POLICY' not in serial:
        report['passed'] = False
        report['failure'] = 'Guest did not confirm the requested temporary validation policy'
    report.update({"timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "assets": str(Path(assets).resolve()), "snapshot_state": True,
                   "policy": 'explicit temporary IPv4 test policy' if test_policy else 'existing guest configuration',
                   "unifi_ui_provisioning_tested": False,
                   "owned_qemu_pid": process.pid if process is not None else None,
                   "owned_qemu_final_returncode": process.returncode if process is not None else None,
                   "total_elapsed_seconds": round(time.monotonic() - started, 3),
                   "serial_fatal_markers": fatal_markers,
                   "artifacts": {"serial": "serial.log", "qemu": "qemu.log", "packets": "packets.pcap",
                                 "command": "command.json"}})
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=Path("build"))
    parser.add_argument("--output", type=Path, help="New directory; default validation-runs/<timestamp>-<random>")
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--cores", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=600, help="Guest runtime, up to 600 seconds")
    parser.add_argument("--drop-window", type=float, default=10)
    parser.add_argument('--test-policy', action='store_true',
                        help='Use an explicit temporary IPv4 firewall policy in the discarded snapshot; factory setup remains unchanged')
    args = parser.parse_args()
    if args.memory < 2048 or not 1 <= args.cores <= 16:
        parser.error("Use at least 2048 MiB RAM and 1..16 cores")
    if not 5 <= args.drop_window < args.timeout <= 600:
        parser.error("Require 5 <= drop-window < timeout <= 600 seconds")
    output = args.output or Path("validation-runs") / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])
    try:
        result = validate(args.assets, output, args.memory, args.cores, args.timeout, args.drop_window, args.test_policy)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Validation failed: {error}\n")
    print(f"Network validation {'PASS' if result['passed'] else 'FAIL'}: {output / 'report.json'}")
    if result["failure"]:
        print(result["failure"], file=sys.stderr)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
