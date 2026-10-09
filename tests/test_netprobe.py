import socket
import struct
import unittest

from validation import netprobe as n


class CodecTests(unittest.TestCase):
    def test_checksum_known_vector_and_odd_payload(self):
        self.assertEqual(n.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        message = n.icmp(8, 12, 4, b"odd")
        self.assertEqual(n.checksum(message), 0)

    def test_stream_partial_prefix_partial_packet_and_coalesced_packets(self):
        decoder = n.Framing()
        first, second = b"a" * 60, b"b" * 64
        wire = struct.pack("!I", len(first)) + first + struct.pack("!I", len(second)) + second
        self.assertEqual(decoder.feed(wire[:2]), [])
        self.assertEqual(decoder.feed(wire[2:22]), [])
        self.assertEqual(decoder.feed(wire[22:]), [first, second])
        for size in (0, 13, 65536, 0xffffffff):
            with self.assertRaises(ValueError):
                n.Framing().feed(struct.pack("!I", size))

    def test_ipv4_bounds_checksum_and_fragment_rejection(self):
        raw = n.ipv4("192.168.1.9", "198.18.0.10", 1, n.icmp(8, 1, 1, b"hello"))
        self.assertEqual(n.parse_ipv4(raw)[:3], ("192.168.1.9", "198.18.0.10", 1))
        for damaged in (raw[:18], raw[:-1], raw[:8] + bytes([raw[8] ^ 1]) + raw[9:]):
            with self.assertRaises(ValueError):
                n.parse_ipv4(damaged)
        changed = bytearray(raw)
        changed[6:8] = b"\x20\x00"
        changed[10:12] = b"\0\0"
        changed[10:12] = struct.pack("!H", n.checksum(changed[:20]))
        with self.assertRaisesRegex(ValueError, "Fragmented"):
            n.parse_ipv4(bytes(changed))

    def test_dhcp_truncated_options_and_wrong_hardware_rejected(self):
        raw = n.dhcp_message(1, 123, n.LAN_MAC, [(53, b"\x01")])
        parsed = n.parse_dhcp(raw)
        self.assertEqual((parsed["xid"], parsed["mac"], parsed["options"][53]), (123, n.LAN_MAC, b"\x01"))
        for bad in (raw[:239], raw[:242], raw[:1] + b"\xff" + raw[2:]):
            with self.assertRaises(ValueError):
                n.parse_dhcp(bad)


class FakePeer:
    def __init__(self):
        self.sent = []

    def send(self, frame):
        self.sent.append(frame)


class FakeCapture:
    def write(self, frame):
        pass


class FlowTests(unittest.TestCase):
    router_lan = bytes.fromhex("0255444d0000")
    router_wan = bytes.fromhex("0255444d0008")
    client_ip = "192.168.1.50"

    def setUp(self):
        self.now = 100.0
        self.peers = {name: FakePeer() for name in ("lan", "wan")}
        self.probe = n.Probe(self.peers, FakeCapture(), clock=lambda: self.now, emit=lambda value: None)

    def incoming(self, link, source, destination, protocol, payload):
        srcmac = self.router_lan if link == "lan" else self.router_wan
        dstmac = n.LAN_MAC if link == "lan" else n.WAN_MAC
        self.probe.receive(link, n.ethernet(dstmac, srcmac, 0x800, n.ipv4(source, destination, protocol, payload)))

    def dhcp_complete(self):
        wan = n.dhcp_message(1, 777, self.router_wan, [(53, b"\x03")])
        self.incoming("wan", "0.0.0.0", "255.255.255.255", 17, n.udp(68, 67, wan))
        self.assertFalse(self.probe.checks["wan_dhcp"], "Sending ACK alone does not prove client configured address")
        self.probe.receive("wan", n.ethernet(n.BROADCAST, self.router_wan, 0x806,
                           n.arp(1, self.router_wan, n.WAN_ROUTER, b"\0" * 6, n.WAN_SERVER)))
        for kind in (b"\x02", b"\x05"):
            lan = n.dhcp_message(2, self.probe.xid, n.LAN_MAC,
                                 [(53, kind), (54, n.ip_bytes("192.168.1.1")), (3, n.ip_bytes("192.168.1.1"))],
                                 self.client_ip, "192.168.1.1")
            self.incoming("lan", "192.168.1.1", "255.255.255.255", 17, n.udp(67, 68, lan))
        self.probe.receive("lan", n.ethernet(n.LAN_MAC, self.router_lan, 0x806,
                           n.arp(2, self.router_lan, "192.168.1.1", n.LAN_MAC, self.client_ip)))
        self.incoming("lan", "192.168.1.1", self.client_ip, 1,
                      n.icmp(0, 0xc001, 1, b"UDM-LAN:" + self.probe.cookie))

    def forwarding_complete(self):
        self.dhcp_complete()
        self.incoming("wan", n.WAN_ROUTER, n.WAN_TARGET, 1,
                      n.icmp(8, 0xc002, 1, b"UDM-NAT:" + self.probe.cookie))
        self.incoming("lan", n.WAN_TARGET, self.client_ip, 1,
                      n.icmp(0, 0xc002, 1, b"UDM-NAT:" + self.probe.cookie))

    def test_full_positive_flow_requires_return_and_bounded_drop_observation(self):
        self.forwarding_complete()
        self.assertFalse(self.probe.report()["passed"])
        for second in range(11):
            self.now = 100 + second
            self.probe.tick()
            if self.probe.control_sent:
                sequence = max(self.probe.control_sent)
                self.incoming("wan", n.WAN_ROUTER, n.WAN_TARGET, 1,
                              n.icmp(8, 0xc003, sequence, b"UDM-CONTROL:" + self.probe.cookie))
                self.incoming("lan", n.WAN_TARGET, self.client_ip, 1,
                              n.icmp(0, 0xc003, sequence, b"UDM-CONTROL:" + self.probe.cookie))
        self.assertTrue(self.probe.report()["passed"])
        self.assertGreaterEqual(self.probe.counts["unsolicited_sent"], 3)
        wan_reply = [frame for frame in self.peers["wan"].sent if frame[12:14] == b"\x08\x00"]
        self.assertGreaterEqual(len(wan_reply), 4)

    def test_paused_guest_silence_cannot_pass_drop_check(self):
        self.forwarding_complete()
        for second in range(15):
            self.now = 100 + second
            self.probe.tick()
        self.assertGreaterEqual(self.probe.counts["unsolicited_sent"], 3)
        self.assertFalse(self.probe.checks["unsolicited_wan_blocked"])
        self.assertFalse(self.probe.report()["passed"])

    def test_missing_nat_and_unsolicited_forwarding_fail(self):
        self.dhcp_complete()
        self.incoming("wan", self.client_ip, n.WAN_TARGET, 1,
                      n.icmp(8, 0xc002, 1, b"UDM-NAT:" + self.probe.cookie))
        self.assertIn("not translated", self.probe.failure)
        self.assertFalse(self.probe.report()["passed"])
        self.setUp()
        self.forwarding_complete()
        self.probe.tick()
        self.incoming("lan", n.WAN_TARGET, self.client_ip, 1,
                      n.icmp(8, 0xd001, 1, b"UDM-UNSOLICITED:" + self.probe.cookie))
        self.assertIn("forwarded", self.probe.failure)
        self.assertFalse(self.probe.report()["passed"])

    def test_unrelated_echo_reply_cannot_satisfy_probe(self):
        self.dhcp_complete()
        self.incoming("wan", n.WAN_ROUTER, n.WAN_TARGET, 1, n.icmp(8, 0xc002, 1, b"unrelated"))
        self.incoming("lan", n.WAN_TARGET, self.client_ip, 1, n.icmp(0, 0xc002, 1, b"unrelated"))
        self.assertFalse(self.probe.checks["outbound_nat"])
        self.assertFalse(self.probe.checks["return_forwarding"])


if __name__ == "__main__":
    unittest.main()
