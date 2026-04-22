import unittest
from unittest.mock import patch

import features


class FakeIP:
    def __init__(self, src, dst, proto):
        self.src = src
        self.dst = dst
        self.proto = proto


class FakeTCP:
    def __init__(self, sport, dport, flags):
        self.sport = sport
        self.dport = dport
        self.flags = flags


class FakeUDP:
    def __init__(self, sport, dport):
        self.sport = sport
        self.dport = dport


class FakeICMP:
    def __init__(self, icmp_type, code):
        self.type = icmp_type
        self.code = code


class FakePacket:
    def __init__(self, layers, size=60, time_value=123.0):
        self.layers = layers
        self._size = size
        self.time = time_value

    def haslayer(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return self._size


class FeaturesTests(unittest.TestCase):
    def test_protocol_name_mappings(self):
        self.assertEqual(features._protocol_name(1), "ICMP")
        self.assertEqual(features._protocol_name(6), "TCP")
        self.assertEqual(features._protocol_name(17), "UDP")
        self.assertEqual(features._protocol_name(99), "99")

    def test_extract_packet_features_returns_none_without_ip(self):
        with patch.object(features, "IP", FakeIP):
            packet = FakePacket(layers={})
            self.assertIsNone(features.extract_packet_features(packet))

    def test_extract_packet_features_tcp(self):
        with patch.multiple(features, IP=FakeIP, TCP=FakeTCP, UDP=FakeUDP, ICMP=FakeICMP):
            packet = FakePacket(
                layers={
                    FakeIP: FakeIP("1.1.1.1", "2.2.2.2", 6),
                    FakeTCP: FakeTCP(12345, 80, "S"),
                },
                size=100,
                time_value=1.5,
            )
            result = features.extract_packet_features(packet)
            self.assertIsNotNone(result)
            self.assertEqual(result["protocol"], "TCP")
            self.assertEqual(result["src_port"], 12345)
            self.assertEqual(result["dst_port"], 80)
            self.assertEqual(result["tcp_flags"], "S")
            self.assertEqual(result["packet_size"], 100)

    def test_extract_packet_features_udp(self):
        with patch.multiple(features, IP=FakeIP, TCP=FakeTCP, UDP=FakeUDP, ICMP=FakeICMP):
            packet = FakePacket(
                layers={
                    FakeIP: FakeIP("3.3.3.3", "4.4.4.4", 17),
                    FakeUDP: FakeUDP(5353, 53),
                }
            )
            result = features.extract_packet_features(packet)
            self.assertIsNotNone(result)
            self.assertEqual(result["protocol"], "UDP")
            self.assertEqual(result["src_port"], 5353)
            self.assertEqual(result["dst_port"], 53)
            self.assertEqual(result["tcp_flags"], "")

    def test_extract_packet_features_icmp(self):
        with patch.multiple(features, IP=FakeIP, TCP=FakeTCP, UDP=FakeUDP, ICMP=FakeICMP):
            packet = FakePacket(
                layers={
                    FakeIP: FakeIP("5.5.5.5", "6.6.6.6", 1),
                    FakeICMP: FakeICMP(8, 0),
                }
            )
            result = features.extract_packet_features(packet)
            self.assertIsNotNone(result)
            self.assertEqual(result["protocol"], "ICMP")
            self.assertEqual(result["icmp_type"], 8)
            self.assertEqual(result["icmp_code"], 0)


if __name__ == "__main__":
    unittest.main()
