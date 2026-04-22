"""Terminal alerting utilities."""

from typing import Any, Dict


class AlertManager:
    """Print real-time intrusion alerts to the terminal."""

    def send_alert(self, event: Dict[str, Any]) -> None:
        timestamp = event.get("timestamp", "unknown-time")
        attack_type = event.get("attack_type", "UNKNOWN")
        source_ip = event.get("source_ip", "unknown-source")
        detail = event.get("detail", "")
        print(f"[ALERT] {timestamp} | {attack_type} | src={source_ip} | {detail}")
