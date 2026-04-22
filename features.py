"""Packet feature extraction helpers."""

from typing import Any, Dict, Optional

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
except Exception:  # pragma: no cover - handled at runtime when Scapy is unavailable
    ICMP = IP = TCP = UDP = None  # type: ignore[assignment]

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def _protocol_name(proto_number: int) -> str:
    if proto_number == IPPROTO_ICMP:
        return "ICMP"
    if proto_number == IPPROTO_TCP:
        return "TCP"
    if proto_number == IPPROTO_UDP:
        return "UDP"
    return str(proto_number)


def extract_packet_features(packet: Any) -> Optional[Dict[str, Any]]:
    """Extract normalized packet features used by the detector."""
    if IP is None or not packet.haslayer(IP):  # type: ignore[attr-defined]
        return None

    ip_layer = packet[IP]
    features: Dict[str, Any] = {
        "timestamp": getattr(packet, "time", None),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": _protocol_name(int(ip_layer.proto)),
        "src_port": None,
        "dst_port": None,
        "tcp_flags": "",
        "packet_size": len(packet),
    }

    if TCP is not None and packet.haslayer(TCP):  # type: ignore[attr-defined]
        tcp_layer = packet[TCP]
        features["src_port"] = int(tcp_layer.sport)
        features["dst_port"] = int(tcp_layer.dport)
        features["tcp_flags"] = str(tcp_layer.flags)
    elif UDP is not None and packet.haslayer(UDP):  # type: ignore[attr-defined]
        udp_layer = packet[UDP]
        features["src_port"] = int(udp_layer.sport)
        features["dst_port"] = int(udp_layer.dport)
    elif ICMP is not None and packet.haslayer(ICMP):  # type: ignore[attr-defined]
        icmp_layer = packet[ICMP]
        features["icmp_type"] = int(icmp_layer.type)
        features["icmp_code"] = int(icmp_layer.code)

    return features
