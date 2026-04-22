"""Configuration values for the NIDS runtime."""

from dataclasses import dataclass


@dataclass(frozen=True)
class NIDSConfig:
    """Container for detection thresholds and runtime options."""

    port_scan_threshold: int = 20
    syn_flood_threshold: int = 100
    icmp_flood_threshold: int = 100
    time_window_seconds: int = 10
    log_directory: str = "logs"
    json_log_file: str = "alerts.jsonl"
    csv_log_file: str = "alerts.csv"


DEFAULT_CONFIG = NIDSConfig()
