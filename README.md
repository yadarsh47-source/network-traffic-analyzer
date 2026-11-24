# Network Traffic Analyzer

A Python-based network traffic analysis tool that reads PCAP files, extracts packet-level information, calculates network traffic statistics, detects potential TCP port-scanning activity, and generates security reports.

## Features

- **PCAP Analysis:** Reads offline PCAP and PCAPNG captures using Scapy.
- **Packet Inspection:** Extracts source IP, destination IP, transport protocol, source port, destination port, and packet length.
- **Traffic Statistics:** Calculates protocol distribution, packet counts by source IP, total traffic volume, and most active source IP.
- **Port-Scan Detection:** Identifies potential TCP port-scanning activity based on repeated SYN packets targeting multiple unique destination ports.
- **Security Reports:** Generates a text-based report containing traffic statistics and potential security findings.
- **Unit Testing:** Uses Python's unittest framework to verify application functionality.

## Project Structure

```text
network-traffic-analyzer/
│
├── data/
│   ├── sample_traffic.pcap
│   └── sample_port_scan.pcap
│
├── src/
│   ├── __init__.py
│   ├── traffic_analyzer.py
│   └── create_sample_pcap.py
│
├── reports/
│   └── .gitkeep
│
├── tests/
│   ├── __init__.py
│   └── test_traffic_analyzer.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

## Technologies Used

- Python
- Scapy
- unittest
- PCAP / PCAPNG

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yadarsh47-source/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

Run the analyzer:

```bash
python src/traffic_analyzer.py
```

By default, the application analyses:

```text
data/sample_traffic.pcap
```

To analyse another capture, change the `file_path` variable inside the `main()` function.

## Generate Synthetic PCAP Files

The project includes a script to generate sample network traffic for testing.

```bash
python src/create_sample_pcap.py
```

This creates synthetic normal traffic and port-scan-like traffic captures in the `data/` directory.

No packets are transmitted over a live network by this generator.

## Port-Scan Detection Logic

The application tracks TCP SYN packets by source IP and destination IP.

It flags potential port-scanning activity when a source-destination pair communicates with 10 or more unique destination ports through TCP SYN packets.

The detection threshold can be customised through the `detect_port_scans()` function.

This is a basic heuristic. The detection result is an indicator of potentially suspicious behaviour, not proof of a malicious attack.

## Security Report

The application generates:

```text
reports/security_report.txt
```

The report includes:

- Total packets analysed
- Protocol distribution
- Packet counts by source IP
- Total traffic volume
- Most active source IP
- Potential port-scan findings

## Running Unit Tests

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The tests cover:

- TCP, UDP and ICMP packet analysis
- Traffic statistics calculation
- Port-scan detection and threshold behaviour
- PCAP file loading and missing-file handling
- Security report generation

## Limitations

- Analyses offline packet captures only; does not perform live packet capture.
- Port-scan detection uses a basic threshold-based heuristic.
- Does not establish whether a flagged activity is malicious.
- Does not perform deep packet inspection or comprehensive application-layer analysis.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Use only packet captures that you own or are authorised to analyse.

## Author

Adarsh Yadav

GitHub: https://github.com/yadarsh47-source
