#!/usr/bin/env python3
"""Isolated original-gateway packet probe over QEMU socket Ethernet backends.

QEMU NICs: LAN eth0 socket listen=127.0.0.1:19000; WAN eth8 socket
listen=127.0.0.1:19008. This program opens only loopback TCP sockets. It does
not configure host networking, create TAP devices, or contact the Internet.
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import time


BROADCAST = b"\xff" * 6
LAN_MAC = bytes.fromhex("02cafe000002")
WAN_MAC = bytes.fromhex("02cafe000801")
WAN_SERVER = "198.18.0.1"
WAN_ROUTER = "198.18.0.2"
WAN_TARGET = "198.18.0.10"
MAGIC = b"\x63\x82\x53\x63"


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    value = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def ip_bytes(value):
    return socket.inet_aton(value)


def ethernet(destination, source, protocol, payload):
    return destination + source + struct.pack("!H", protocol) + payload


def ipv4(source, destination, protocol, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0,
                         ip_bytes(source), ip_bytes(destination))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def parse_ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError("Truncated or non-IPv4 packet")
    header_size, total = (packet[0] & 15) * 4, struct.unpack_from("!H", packet, 2)[0]
    if header_size < 20 or total < header_size or total > len(packet):
        raise ValueError("Invalid IPv4 bounds")
    if checksum(packet[:header_size]) != 0:
        raise ValueError("Invalid IPv4 header checksum")
    if struct.unpack_from("!H", packet, 6)[0] & 0x3fff:
        raise ValueError("Fragmented IPv4 packet unsupported")
    return socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20]), packet[9], packet[header_size:total]


def udp(source_port, destination_port, payload):
    # IPv4 permits checksum zero. Keep packet checks independent of offload.
    return struct.pack("!HHHH", source_port, destination_port, len(payload) + 8, 0) + payload


def parse_udp(packet):
    if len(packet) < 8:
        raise ValueError("Truncated UDP packet")
    source, destination, length, _ = struct.unpack_from("!4H", packet)
    if length < 8 or length > len(packet):
        raise ValueError("Invalid UDP bounds")
    return source, destination, packet[8:length]


def arp(operation, source_mac, source_ip, destination_mac, destination_ip):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, operation, source_mac, ip_bytes(source_ip),
                       destination_mac, ip_bytes(destination_ip))


def icmp(kind, identifier, sequence, payload):
    message = struct.pack("!BBHHH", kind, 0, 0, identifier, sequence) + payload
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def dhcp_options(values):
    return MAGIC + b"".join(bytes((key, len(value))) + value for key, value in values) + b"\xff"


def dhcp_message(operation, xid, mac, options, offered="0.0.0.0", server="0.0.0.0"):
    header = bytearray(236)
    struct.pack_into("!BBBBIHH", header, 0, operation, 1, 6, 0, xid, 0, 0x8000)
    header[16:20], header[20:24], header[28:34] = ip_bytes(offered), ip_bytes(server), mac
    return (bytes(header) + dhcp_options(options)).ljust(300, b"\0")


def parse_dhcp(packet):
    if len(packet) < 240 or packet[236:240] != MAGIC or packet[1:3] != b"\x01\x06":
        raise ValueError("Invalid DHCP/BOOTP Ethernet message")
    options, offset = {}, 240
    while offset < len(packet):
        code = packet[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        if offset >= len(packet) or offset + 1 + packet[offset] > len(packet):
            raise ValueError("Truncated DHCP option")
        length = packet[offset]
        offset += 1
        options[code] = packet[offset:offset + length]
        offset += length
    return {"operation": packet[0], "xid": struct.unpack_from("!I", packet, 4)[0],
            "mac": packet[28:34], "offered": socket.inet_ntoa(packet[16:20]), "options": options}


class Framing:
    """Incremental QEMU socket-net stream decoder; length excludes the prefix."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        frames = []
        while len(self.buffer) >= 4:
            length = struct.unpack_from("!I", self.buffer)[0]
            if not 14 <= length <= 65535:
                raise ValueError(f"Invalid QEMU Ethernet frame length {length}")
            if len(self.buffer) < length + 4:
                break
            frames.append(bytes(self.buffer[4:length + 4]))
            del self.buffer[:length + 4]
        return frames


class Peer:
    def __init__(self, name, port, selector, connection=None):
        self.name, self.selector = name, selector
        self.socket = connection if connection is not None else socket.create_connection(("127.0.0.1", port), timeout=5)
        self.socket.setblocking(False)
        self.decoder, self.pending = Framing(), bytearray()
        selector.register(self.socket, selectors.EVENT_READ, self)

    def send(self, frame):
        self.pending.extend(struct.pack("!I", len(frame)) + frame)
        if len(self.pending) > 4 * 1024 * 1024:
            raise RuntimeError(f"{self.name}: QEMU send queue stopped draining")
        self.selector.modify(self.socket, selectors.EVENT_READ | selectors.EVENT_WRITE, self)

    def flush(self):
        try:
            sent = self.socket.send(self.pending)
        except BlockingIOError:
            return
        del self.pending[:sent]
        if not self.pending:
            self.selector.modify(self.socket, selectors.EVENT_READ, self)

    def close(self):
        self.selector.unregister(self.socket)
        self.socket.close()


class Capture:
    def __init__(self, path):
        self.stream = Path(path).open("xb") if path else None
        if self.stream:
            self.stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write(self, frame):
        if self.stream:
            now = time.time()
            self.stream.write(struct.pack("<IIII", int(now), int(now % 1 * 1000000), len(frame), len(frame)))
            self.stream.write(frame)

    def close(self):
        if self.stream:
            self.stream.close()


class Probe:
    def __init__(self, peers, capture, lan_network="192.168.1.0/24", lan_gateway="192.168.1.1",
                 drop_window=10, clock=time.monotonic, emit=lambda value: print(value, flush=True)):
        self.peers, self.capture, self.clock, self.emit = peers, capture, clock, emit
        self.network, self.gateway = ipaddress.IPv4Network(lan_network), lan_gateway
        if ipaddress.IPv4Address(lan_gateway) not in self.network:
            raise ValueError("LAN gateway is outside expected LAN network")
        self.drop_window = drop_window
        self.xid = int.from_bytes(os.urandom(4), "big")
        self.cookie = os.urandom(12)
        self.lan_ip = self.offer = self.server = self.lan_router_mac = self.wan_router_mac = None
        self.checks = {key: False for key in ("lan_dhcp", "wan_dhcp", "lan_router_ping", "outbound_nat",
                                            "return_forwarding", "unsolicited_wan_blocked")}
        self.events, self.errors, self.last = [], [], {}
        self.counts = {"lan_received": 0, "wan_received": 0, "malformed_ignored": 0,
                       "unsolicited_sent": 0, "unsolicited_leaked": 0}
        self.started, self.block_started = clock(), None
        self.failure = None
        self.wan_ack_sent = False
        self.control_sent, self.control_returned = {}, {}
        self.last_unsolicited = None

    def event(self, name, **fields):
        record = {"event": name, "elapsed_seconds": round(self.clock() - self.started, 3), **fields}
        self.events.append(record)
        self.emit(json.dumps(record, sort_keys=True))

    def mark(self, name, **fields):
        if not self.checks[name]:
            self.checks[name] = True
            self.event(name, **fields)

    def send(self, link, frame):
        self.capture.write(frame)
        self.peers[link].send(frame)

    def send_ip(self, link, destination_mac, source_ip, destination_ip, protocol, payload):
        mac = LAN_MAC if link == "lan" else WAN_MAC
        self.send(link, ethernet(destination_mac, mac, 0x0800, ipv4(source_ip, destination_ip, protocol, payload)))

    def client_dhcp(self):
        options = [(53, b"\x03" if self.offer else b"\x01"), (61, b"\x01" + LAN_MAC),
                   (55, bytes((1, 3, 6, 51, 54)))]
        if self.offer:
            options += [(50, ip_bytes(self.offer)), (54, ip_bytes(self.server))]
        message = dhcp_message(1, self.xid, LAN_MAC, options)
        self.send_ip("lan", BROADCAST, "0.0.0.0", "255.255.255.255", 17, udp(68, 67, message))

    def server_dhcp(self, source_mac, message):
        kind = message["options"].get(53)
        if message["operation"] != 1 or kind not in (b"\x01", b"\x03", b"\x08"):
            return
        selected = message["options"].get(54)
        if selected is not None and selected != ip_bytes(WAN_SERVER):
            return
        self.wan_router_mac = message["mac"]
        options = [(53, b"\x02" if kind == b"\x01" else b"\x05"), (54, ip_bytes(WAN_SERVER)),
                   (1, ip_bytes("255.255.255.0")), (3, ip_bytes(WAN_SERVER)), (6, ip_bytes(WAN_SERVER)),
                   (51, struct.pack("!I", 86400)), (58, struct.pack("!I", 43200)), (59, struct.pack("!I", 75600))]
        reply = dhcp_message(2, message["xid"], message["mac"], options,
                             "0.0.0.0" if kind == b"\x08" else WAN_ROUTER, WAN_SERVER)
        self.send_ip("wan", BROADCAST, WAN_SERVER, "255.255.255.255", 17, udp(67, 68, reply))
        if kind == b"\x03":
            self.wan_ack_sent = True
            self.event("wan_dhcp_ack_sent", offered=WAN_ROUTER, client_mac=message["mac"].hex(":"))

    def receive(self, link, frame):
        self.capture.write(frame)
        self.counts[link + "_received"] += 1
        try:
            if len(frame) < 14:
                raise ValueError("Short Ethernet frame")
            destination, source, protocol = frame[:6], frame[6:12], struct.unpack_from("!H", frame, 12)[0]
            payload = frame[14:]
            if protocol == 0x0806:
                self.receive_arp(link, source, payload)
                return
            if protocol != 0x0800:
                return
            src, dst, protocol, payload = parse_ipv4(payload)
            if link == "wan" and src == WAN_ROUTER and self.wan_ack_sent:
                self.mark("wan_dhcp", observed_configured_address=src)
            if protocol == 17:
                source_port, destination_port, data = parse_udp(payload)
                if link == "wan" and (source_port, destination_port) == (68, 67):
                    self.server_dhcp(source, parse_dhcp(data))
                elif link == "lan" and (source_port, destination_port) == (67, 68):
                    self.receive_lan_dhcp(parse_dhcp(data))
            elif protocol == 1:
                self.receive_icmp(link, source, src, dst, payload)
        except (ValueError, struct.error, OSError) as error:
            self.counts["malformed_ignored"] += 1
            if len(self.errors) < 10:
                self.errors.append(str(error))

    def receive_arp(self, link, source_mac, packet):
        if len(packet) < 28:
            raise ValueError("Truncated ARP")
        htype, ptype, hlen, plen, operation, sender, sender_ip, target_mac, target_ip = struct.unpack_from("!HHBBH6s4s6s4s", packet)
        if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
            return
        sender_ip, target_ip = socket.inet_ntoa(sender_ip), socket.inet_ntoa(target_ip)
        if link == "lan" and sender_ip == self.gateway:
            self.lan_router_mac = sender
        elif link == "wan" and sender_ip == WAN_ROUTER:
            self.wan_router_mac = sender
            if self.wan_ack_sent:
                self.mark("wan_dhcp", observed_configured_address=sender_ip)
        ours = self.lan_ip == target_ip if link == "lan" else target_ip in (WAN_SERVER, WAN_TARGET)
        if operation == 1 and ours:
            mac = LAN_MAC if link == "lan" else WAN_MAC
            self.send(link, ethernet(sender, mac, 0x0806, arp(2, mac, target_ip, sender, sender_ip)))

    def receive_lan_dhcp(self, message):
        if message["operation"] != 2 or message["xid"] != self.xid or message["mac"] != LAN_MAC:
            return
        kind, options = message["options"].get(53), message["options"]
        if kind == b"\x06":
            self.offer = self.server = None
            self.event("lan_dhcp_nak")
            return
        if kind not in (b"\x02", b"\x05"):
            return
        address = ipaddress.IPv4Address(message["offered"])
        if address not in self.network or address in (self.network.network_address, self.network.broadcast_address):
            self.failure = f"LAN DHCP offered unexpected address {address}"
            return
        if kind == b"\x02" and not self.checks["lan_dhcp"]:
            if len(options.get(54, b"")) != 4:
                raise ValueError("LAN DHCP offer lacks server identifier")
            self.offer, self.server = str(address), socket.inet_ntoa(options[54])
            self.event("lan_dhcp_offer", address=self.offer, server=self.server)
            self.client_dhcp()
        elif kind == b"\x05":
            routers = options.get(3, b"")
            if len(routers) < 4 or socket.inet_ntoa(routers[:4]) != self.gateway:
                self.failure = "LAN DHCP did not provide expected gateway"
                return
            self.lan_ip = str(address)
            self.mark("lan_dhcp", address=self.lan_ip, gateway=self.gateway)

    def receive_icmp(self, link, source_mac, source, destination, packet):
        if len(packet) < 8 or checksum(packet) != 0:
            raise ValueError("Invalid ICMP echo/checksum")
        kind, code, _, identifier, sequence = struct.unpack_from("!BBHHH", packet)
        data = packet[8:]
        if code != 0:
            return
        if link == "wan" and kind == 8 and destination == WAN_TARGET and data in (
                b"UDM-NAT:" + self.cookie, b"UDM-CONTROL:" + self.cookie):
            self.wan_router_mac = source_mac
            if source != WAN_ROUTER:
                self.failure = f"Outbound packet was not translated: observed source {source}"
                self.event("nat_wrong_source", observed=source, expected=WAN_ROUTER)
                return
            self.mark("outbound_nat", observed_source=source, destination=destination)
            self.send_ip("wan", source_mac, WAN_TARGET, source, 1, icmp(0, identifier, sequence, data))
        elif link == "wan" and kind == 8 and destination in (WAN_SERVER, WAN_TARGET):
            self.send_ip("wan", source_mac, destination, source, 1, icmp(0, identifier, sequence, data))
        elif link == "lan" and kind == 0 and destination == self.lan_ip:
            if source == self.gateway and identifier == 0xc001 and data == b"UDM-LAN:" + self.cookie:
                self.mark("lan_router_ping", router=source)
            elif source == WAN_TARGET and identifier == 0xc002 and data == b"UDM-NAT:" + self.cookie:
                if self.checks["outbound_nat"]:
                    self.mark("return_forwarding", destination=destination)
            elif source == WAN_TARGET and identifier == 0xc003 and data == b"UDM-CONTROL:" + self.cookie:
                if sequence in self.control_sent:
                    self.control_returned[sequence] = self.control_sent[sequence]
        elif link == "lan" and source == WAN_TARGET and destination == self.lan_ip and kind == 8:
            if identifier == 0xd001 and data == b"UDM-UNSOLICITED:" + self.cookie:
                self.counts["unsolicited_leaked"] += 1
                self.failure = "Unsolicited WAN→LAN ICMP was forwarded; drop check failed"
                self.event("unsolicited_wan_leaked", source=source, destination=destination)

    def due(self, key, interval):
        now = self.clock()
        if now - self.last.get(key, -1e30) >= interval:
            self.last[key] = now
            return True
        return False

    def tick(self):
        if not self.checks["lan_dhcp"] and self.due("dhcp", 5):
            self.client_dhcp()
        if self.lan_ip and not self.lan_router_mac and self.due("arp", 1):
            self.send("lan", ethernet(BROADCAST, LAN_MAC, 0x0806,
                                      arp(1, LAN_MAC, self.lan_ip, b"\0" * 6, self.gateway)))
        if self.lan_ip and self.lan_router_mac:
            if not self.checks["lan_router_ping"] and self.due("router_ping", 2):
                self.send_ip("lan", self.lan_router_mac, self.lan_ip, self.gateway, 1,
                             icmp(8, 0xc001, 1, b"UDM-LAN:" + self.cookie))
            if self.wan_ack_sent and not self.checks["return_forwarding"] and self.due("nat_ping", 3):
                self.send_ip("lan", self.lan_router_mac, self.lan_ip, WAN_TARGET, 1,
                             icmp(8, 0xc002, 1, b"UDM-NAT:" + self.cookie))
        ready = all(self.checks[name] for name in self.checks if name != "unsolicited_wan_blocked")
        if ready and self.wan_router_mac:
            if self.block_started is None:
                self.block_started = self.clock()
                self.event("unsolicited_wan_check_begin", window_seconds=self.drop_window)
            if self.due("unsolicited", 1) and self.clock() - self.block_started < self.drop_window - 2:
                self.counts["unsolicited_sent"] += 1
                self.last_unsolicited = self.clock()
                self.send_ip("wan", self.wan_router_mac, WAN_TARGET, self.lan_ip, 1,
                             icmp(8, 0xd001, self.counts["unsolicited_sent"], b"UDM-UNSOLICITED:" + self.cookie))
            if self.due("drop_control", 2):
                sequence = len(self.control_sent) + 1
                self.control_sent[sequence] = self.clock()
                self.send_ip("lan", self.lan_router_mac, self.lan_ip, WAN_TARGET, 1,
                             icmp(8, 0xc003, sequence, b"UDM-CONTROL:" + self.cookie))
            if self.clock() - self.block_started >= self.drop_window and not self.failure:
                # A completed NAT round-trip sent after the final rejected
                # probe proves the guest and BOTH socket links kept processing.
                # Silence from a paused or overloaded VM is never a pass.
                positive_control = self.last_unsolicited is not None and any(
                    sent >= self.last_unsolicited for sent in self.control_returned.values())
                if (self.counts["unsolicited_sent"] >= 3 and not self.counts["unsolicited_leaked"]
                        and positive_control):
                    self.mark("unsolicited_wan_blocked", probes=self.counts["unsolicited_sent"],
                              observation_seconds=self.clock() - self.block_started,
                              subsequent_nat_roundtrip_verified=True)

    def report(self):
        return {"passed": all(self.checks.values()) and self.failure is None,
                "checks": self.checks, "failure": self.failure, "counts": self.counts,
                "lan_address": self.lan_ip, "wan_address": WAN_ROUTER,
                "events": self.events, "malformed_samples": self.errors,
                "drop_control_roundtrips": len(self.control_returned),
                "elapsed_seconds": round(self.clock() - self.started, 3),
                "scope": "Isolated IPv4 DHCP/ARP/ICMP/NAT and bounded unsolicited-ICMP drop probe; no throughput, DNS, TCP, UDP forwarding, IPv6 or Internet validation"}


def run_connected(peers, selector, capture, timeout=240, drop_window=10,
                  lan_network="192.168.1.0/24", lan_gateway="192.168.1.1", process=None):
    """Run a finite probe with already-owned Ethernet sockets; never spawn QEMU."""
    probe = Probe(peers, capture, lan_network, lan_gateway, drop_window)
    probe.event("connected", links=sorted(peers))
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline and not probe.failure:
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Owned QEMU exited before validation completed: {process.returncode}")
            for key, events in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                peer = key.data
                if events & selectors.EVENT_WRITE:
                    peer.flush()
                if events & selectors.EVENT_READ:
                    try:
                        data = peer.socket.recv(65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        raise ConnectionError(f"{peer.name} QEMU connection closed")
                    for frame in peer.decoder.feed(data):
                        probe.receive(peer.name, frame)
            probe.tick()
            if all(probe.checks.values()):
                break
        if not all(probe.checks.values()) and not probe.failure:
            probe.failure = "Timed out waiting for: " + ", ".join(name for name, passed in probe.checks.items() if not passed)
    except (OSError, ValueError, RuntimeError) as error:
        probe.failure = str(error)
    return probe.report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-port", type=int, default=19000)
    parser.add_argument("--wan-port", type=int, default=19008)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--drop-window", type=float, default=10)
    parser.add_argument("--lan-network", default="192.168.1.0/24")
    parser.add_argument("--lan-gateway", default="192.168.1.1")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, help="New Ethernet PCAP capturing both isolated links")
    args = parser.parse_args()
    if args.timeout <= args.drop_window or args.drop_window < 5:
        parser.error("Require timeout > drop-window >= 5 seconds")
    if args.lan_port == args.wan_port or any(not 1 <= port <= 65535 for port in (args.lan_port, args.wan_port)):
        parser.error("Require two distinct valid loopback TCP ports")
    if args.report.exists():
        parser.error("Report already exists; choose a new path")
    selector, peers, capture = selectors.DefaultSelector(), {}, None
    report = {"passed": False, "failure": "Probe did not initialize"}
    try:
        capture = Capture(args.pcap)
        for name, port in (("lan", args.lan_port), ("wan", args.wan_port)):
            peers[name] = Peer(name, port, selector)
        report = run_connected(peers, selector, capture, args.timeout, args.drop_window, args.lan_network, args.lan_gateway)
    except (OSError, ValueError, RuntimeError) as error:
        report["failure"] = str(error)
    finally:
        for peer in peers.values():
            peer.close()
        selector.close()
        if capture:
            capture.close()
    report["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"event": "result", "passed": report["passed"], "failure": report["failure"],
                      "report": str(args.report)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
