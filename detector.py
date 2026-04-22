"""Rule-based detection engine for suspicious traffic patterns."""

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from config import DEFAULT_CONFIG, NIDSConfig


class Detector:
    """Detects port scans, SYN floods, and ICMP floods."""

    def __init__(self, config: NIDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self._port_activity: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._incomplete_handshakes: Dict[
            str, Deque[Tuple[float, Tuple[str, int, int]]]
        ] = defaultdict(deque)
        self._icmp_activity: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

    def process_packet(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return a list of alerts generated for a single packet."""
        if not features or "src_ip" not in features:
            return []

        ts = float(features.get("timestamp") or datetime.now(timezone.utc).timestamp())
        src_ip = str(features["src_ip"])
        alerts: List[Dict[str, Any]] = []

        port_alert = self._detect_port_scan(features, src_ip, ts)
        if port_alert is not None:
            alerts.append(port_alert)

        syn_alert = self._detect_syn_flood(features, src_ip, ts)
        if syn_alert is not None:
            alerts.append(syn_alert)

        icmp_alert = self._detect_icmp_flood(features, src_ip, ts)
        if icmp_alert is not None:
            alerts.append(icmp_alert)

        return alerts

    def _trim(self, events: Deque[Any], now: float) -> None:
        cutoff = now - self.config.time_window_seconds
        while events:
            first_item = events[0]
            first_ts = first_item[0] if isinstance(first_item, tuple) else first_item
            if first_ts >= cutoff:
                break
            events.popleft()

    def _should_alert(self, attack_type: str, src_ip: str, now: float) -> bool:
        key = (attack_type, src_ip)
        previous = self._last_alert_time.get(key, 0.0)
        if now - previous < self.config.time_window_seconds:
            return False
        self._last_alert_time[key] = now
        return True

    def _make_alert(self, attack_type: str, src_ip: str, detail: str) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": attack_type,
            "source_ip": src_ip,
            "detail": detail,
        }

    def _detect_port_scan(
        self, features: Dict[str, Any], src_ip: str, now: float
    ) -> Optional[Dict[str, Any]]:
        dst_port = features.get("dst_port")
        if dst_port is None:
            return None

        activity = self._port_activity[src_ip]
        activity.append((now, int(dst_port)))
        self._trim(activity, now)
        unique_ports = {port for _, port in activity}

        if (
            len(unique_ports) >= self.config.port_scan_threshold
            and self._should_alert("PORT_SCAN", src_ip, now)
        ):
            return self._make_alert(
                "PORT_SCAN",
                src_ip,
                (
                    f"Observed connections to {len(unique_ports)} unique ports "
                    f"in {self.config.time_window_seconds}s"
                ),
            )
        return None

    def _detect_syn_flood(
        self, features: Dict[str, Any], src_ip: str, now: float
    ) -> Optional[Dict[str, Any]]:
        if features.get("protocol") != "TCP":
            return None

        flags = str(features.get("tcp_flags") or "")
        dst_ip = features.get("dst_ip")
        src_port = features.get("src_port")
        dst_port = features.get("dst_port")

        if (
            "S" in flags
            and "A" not in flags
            and dst_ip is not None
            and src_port is not None
            and dst_port is not None
        ):
            self._incomplete_handshakes[src_ip].append(
                (now, (str(dst_ip), int(src_port), int(dst_port)))
            )

        if (
            "A" in flags
            and dst_ip is not None
            and src_port is not None
            and dst_port is not None
        ):
            initiator_ip = str(dst_ip)
            pending_for_initiator = self._incomplete_handshakes[initiator_ip]
            expected = (src_ip, int(dst_port), int(src_port))
            matched = False
            remaining_pending_syn: Deque[Tuple[float, Tuple[str, int, int]]] = deque()
            while pending_for_initiator:
                item = pending_for_initiator.popleft()
                if not matched and item[1] == expected:
                    matched = True
                    continue
                remaining_pending_syn.append(item)
            self._incomplete_handshakes[initiator_ip] = remaining_pending_syn

        pending = self._incomplete_handshakes[src_ip]
        self._trim(pending, now)
        pending_count = len(pending)

        if (
            pending_count >= self.config.syn_flood_threshold
            and self._should_alert("SYN_FLOOD", src_ip, now)
        ):
            return self._make_alert(
                "SYN_FLOOD",
                src_ip,
                (
                    f"High count of incomplete TCP handshakes ({pending_count}) "
                    f"within {self.config.time_window_seconds}s"
                ),
            )
        return None

    def _detect_icmp_flood(
        self, features: Dict[str, Any], src_ip: str, now: float
    ) -> Optional[Dict[str, Any]]:
        if features.get("protocol") != "ICMP":
            return None

        activity = self._icmp_activity[src_ip]
        activity.append(now)
        self._trim(activity, now)

        if (
            len(activity) >= self.config.icmp_flood_threshold
            and self._should_alert("ICMP_FLOOD", src_ip, now)
        ):
            return self._make_alert(
                "ICMP_FLOOD",
                src_ip,
                (
                    f"Observed {len(activity)} ICMP packets in "
                    f"{self.config.time_window_seconds}s"
                ),
            )
        return None
