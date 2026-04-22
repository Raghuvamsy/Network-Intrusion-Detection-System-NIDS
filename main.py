"""Entry point for the Network Intrusion Detection System."""

import argparse
import os
import time
from typing import Any

from alerts import AlertManager
from detector import Detector
from features import extract_packet_features
from logger import EventLogger
from sniffer import PacketSniffer


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a rule-based NIDS using Scapy.")
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Network interface to sniff on (default: Scapy default interface).",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default=None,
        help="Optional BPF filter expression for packet capture.",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()

    detector = Detector()
    alerts = AlertManager()
    logger = EventLogger()

    def handle_packet(packet: Any) -> None:
        features = extract_packet_features(packet)
        if not features:
            return
        for event in detector.process_packet(features):
            alerts.send_alert(event)
            logger.log_event(event)

    # geteuid is only available on Unix-like platforms.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[WARNING] Packet capture may require root privileges. "
            "Try running with sudo."
        )

    sniffer = PacketSniffer(
        packet_handler=handle_packet,
        interface=args.interface,
        bpf_filter=args.filter,
    )

    try:
        print("[INFO] Starting NIDS packet capture. Press Ctrl+C to stop.")
        sniffer.start()
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping NIDS...")
    except Exception as exc:
        print(f"[ERROR] Unable to start NIDS: {exc}")
        return 1
    finally:
        sniffer.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
