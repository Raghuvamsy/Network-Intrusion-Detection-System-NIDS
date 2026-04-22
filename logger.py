"""Structured event logger for detected intrusions."""

import csv
import json
from pathlib import Path
from typing import Any, Dict

from config import DEFAULT_CONFIG, NIDSConfig


class EventLogger:
    """Write intrusion events to JSON lines and CSV files."""

    _csv_fields = ("timestamp", "attack_type", "source_ip", "detail")

    def __init__(self, config: NIDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.log_dir = Path(config.log_directory)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.json_path = self.log_dir / config.json_log_file
        self.csv_path = self.log_dir / config.csv_log_file
        self._ensure_csv_header()

    def _ensure_csv_header(self) -> None:
        if self.csv_path.exists():
            return
        with self.csv_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=self._csv_fields)
            writer.writeheader()

    def log_event(self, event: Dict[str, Any]) -> None:
        """Persist one event in both JSON and CSV formats."""
        normalized = {
            "timestamp": str(event.get("timestamp", "")),
            "attack_type": str(event.get("attack_type", "")),
            "source_ip": str(event.get("source_ip", "")),
            "detail": str(event.get("detail", "")),
        }
        self._write_json(normalized)
        self._write_csv(normalized)

    def _write_json(self, event: Dict[str, Any]) -> None:
        try:
            with self.json_path.open("a", encoding="utf-8") as json_file:
                json_file.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[LOGGER_ERROR] failed to write JSON log: {exc}")

    def _write_csv(self, event: Dict[str, Any]) -> None:
        try:
            with self.csv_path.open("a", encoding="utf-8", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=self._csv_fields)
                writer.writerow(event)
        except OSError as exc:
            print(f"[LOGGER_ERROR] failed to write CSV log: {exc}")
