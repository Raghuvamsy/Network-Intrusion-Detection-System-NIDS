# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System designed to monitor live network traffic, analyze packet-level data, and detect suspicious or malicious activities in real time.

---

## Overview

This NIDS monitors live network traffic and applies rule-based detection to identify:

- **Port scanning** – an IP probing many ports in a short time window
- **SYN flood** – a burst of TCP SYN packets without completing the handshake
- **ICMP flood** – unusually high ICMP (ping) traffic from a single source

Alerts are printed to the terminal in real time and persisted in structured log files (JSON Lines + CSV).

---

## Features

**Core Functionality**
- Live packet capture using Scapy
- Real-time traffic analysis
- Feature extraction from packets (IP, ports, protocol, TCP flags, packet size)
- Rule-based detection engine with configurable thresholds

**Attack Detection**
- Port scanning detection
- SYN flood detection (tracks incomplete TCP handshakes)
- ICMP flood detection

**Alerting and Logging**
- Real-time terminal alerts
- Structured logging (JSON Lines + CSV)
- Timestamped attack records

---

## System Architecture

```
Network Traffic → Packet Capture (sniffer.py)
              → Feature Extraction (features.py)
              → Detection Engine (detector.py)
              → Alert System (alerts.py) + Logging (logger.py)
```

---

## Project Structure

```
├── main.py        # Entry point – orchestrates all components
├── sniffer.py     # Packet capture using Scapy AsyncSniffer
├── features.py    # Extracts src/dst IP, ports, protocol, TCP flags, size
├── detector.py    # Rule-based detection engine
├── alerts.py      # Real-time terminal alerting
├── logger.py      # Writes events to logs/ in JSONL and CSV
├── config.py      # Detection thresholds and log paths
└── logs/          # Alert log files (auto-created on first run)
    ├── alerts.jsonl
    └── alerts.csv
```

---

## Prerequisites

- Python **3.8** or higher
- **Root / administrator privileges** (required by Scapy for raw packet capture)
- [Scapy](https://scapy.net/) library

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Raghuvamsy/Network-Intrusion-Detection-System-NIDS.git
cd Network-Intrusion-Detection-System-NIDS-

# 2. Install the only runtime dependency
pip install scapy
```

---

## How to Run

### Basic usage (capture on the default interface)

```bash
sudo python main.py
```

### Specify a network interface

```bash
sudo python main.py -i eth0
```

### Apply a BPF capture filter (e.g. only TCP traffic)

```bash
sudo python main.py -i eth0 -f "tcp"
```

### All command-line options

```
usage: main.py [-h] [-i INTERFACE] [-f FILTER]

options:
  -h, --help            show this help message and exit
  -i INTERFACE          Network interface to sniff on (default: Scapy default)
  -f FILTER             Optional BPF filter expression for packet capture
```

Press **Ctrl + C** to stop the system gracefully.

---

## Expected Terminal Output

When an attack is detected, an alert is printed immediately:

```
[INFO] Starting NIDS packet capture. Press Ctrl+C to stop.
[ALERT] 2026-04-19T17:39:46+00:00 | PORT_SCAN  | src=192.168.1.100 | Observed connections to 20 unique ports in 10s
[ALERT] 2026-04-19T17:39:46+00:00 | SYN_FLOOD  | src=172.16.0.50   | High count of incomplete TCP handshakes (100) within 10s
[ALERT] 2026-04-19T17:39:46+00:00 | ICMP_FLOOD | src=10.0.0.200    | Observed 100 ICMP packets in 10s
```

---

## Log Files

All events are written to the `logs/` directory automatically.

| File | Format | Description |
|------|--------|-------------|
| `logs/alerts.jsonl` | JSON Lines | One JSON object per alert |
| `logs/alerts.csv`   | CSV        | Tabular view with header row |

**Sample `alerts.jsonl` entry:**
```json
{
  "timestamp": "2026-04-19T17:39:46.477061+00:00",
  "attack_type": "PORT_SCAN",
  "source_ip": "192.168.1.100",
  "detail": "Observed connections to 20 unique ports in 10s"
}
```

---

## Configuring Detection Thresholds

Edit `config.py` to tune detection sensitivity:

```python
@dataclass(frozen=True)
class NIDSConfig:
    port_scan_threshold: int = 20    # unique dst ports from one src in time_window
    syn_flood_threshold: int = 100   # unanswered SYN packets from one src in time_window
    icmp_flood_threshold: int = 100  # ICMP packets from one src in time_window
    time_window_seconds: int = 10    # sliding detection window (seconds)
    log_directory: str = "logs"
    json_log_file: str = "alerts.jsonl"
    csv_log_file: str = "alerts.csv"
```

Pass a custom config at runtime by editing `main.py` where `Detector()` and `EventLogger()` are constructed:

```python
from config import NIDSConfig
cfg = NIDSConfig(port_scan_threshold=10, time_window_seconds=5)
detector = Detector(config=cfg)
logger   = EventLogger(config=cfg)
```

---

## Simulating Attacks (for testing)

Run these on a **separate machine** (or VM) while the NIDS is active on the target.

**Port Scan** (requires `nmap`)
```bash
nmap -sS <target-ip>
```

**SYN Flood** (requires `hping3`)
```bash
sudo hping3 -S --flood -p 80 <target-ip>
```

**ICMP Flood**
```bash
# Linux
ping -f <target-ip>

# macOS
sudo ping -i 0.0001 <target-ip>
```

---

## Detection Logic

| Attack | Detection Rule |
|--------|---------------|
| Port Scan | Source IP connects to >= `port_scan_threshold` **unique** destination ports within `time_window_seconds` |
| SYN Flood | Source IP has >= `syn_flood_threshold` unanswered SYN packets (no matching SYN-ACK response received) within `time_window_seconds` |
| ICMP Flood | Source IP sends >= `icmp_flood_threshold` ICMP packets within `time_window_seconds` |

---

## Technologies Used

- **Python 3.8+**
- **[Scapy](https://scapy.net/)** – packet capture and manipulation
- Standard library: `datetime`, `collections`, `json`, `csv`, `pathlib`, `argparse`

---

## Future Improvements

- Anomaly-based detection using machine learning
- Web dashboard for real-time visualization
- Custom rule definition language (Snort-like)
- Email / webhook alert notifications
- Performance optimisation for high-throughput networks

---

## Limitations

- Requires root / administrator privileges for raw packet capture
- Currently optimised for small to medium traffic environments
- Rule-based detection may not identify novel or unknown attack patterns

---

## Learning Outcomes

- Packet-level network analysis with Scapy
- Implementation of sliding-window intrusion detection rules
- Real-time data processing and structured logging
- Cybersecurity monitoring system design

---

## Author

Developed as a cybersecurity project to demonstrate practical intrusion detection capabilities and system design.
