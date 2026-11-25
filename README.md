# Network Traffic Analyzer

A Python-based network traffic analysis tool that processes offline PCAP and PCAPNG files, extracts packet-level information, calculates network traffic statistics, detects potential TCP port-scanning activity, and generates security reports.

## Features

- **PCAP Analysis:** Reads offline PCAP and PCAPNG captures using Scapy.
- **Packet Inspection:** Extracts source IP, destination IP, protocol, source port, destination port, packet length, and TCP SYN information.
- **Traffic Statistics:** Calculates protocol distribution, packet counts by source IP, total packet count, total traffic volume, and most active source IP.
- **Port-Scan Detection:** Identifies potential TCP port-scanning activity based on initial SYN packets targeting multiple unique destination ports.
- **Security Reports:** Generates a text-based report containing traffic statistics and potential security findings.
- **Synthetic Traffic Generation:** Creates sample PCAP files for testing normal traffic analysis and port-scan detection.
- **Unit Testing:** Uses Python's `unittest` framework to verify application functionality.

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

Activate the virtual environment on Windows PowerShell:

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

By default, the application analyzes:

```text
data/sample_traffic.pcap
```

To analyze a different capture, modify the PCAP file path configured in the `main()` function of `src/traffic_analyzer.py`.

The analyzer processes the selected capture, calculates traffic statistics, checks for potential port-scanning activity, and generates a security report.

## Generate Synthetic PCAP Files

The project includes a script to generate synthetic network traffic for testing and demonstration.

```bash
python src/create_sample_pcap.py
```

This generates sample PCAP files containing normal traffic patterns and port-scan-like activity in the `data/` directory.

The generated traffic is synthetic and is not transmitted over a live network.

## Port-Scan Detection Logic

The application tracks initial TCP SYN packets using source IP and destination IP pairs.

Potential port-scanning activity is flagged when a source-destination pair targets 10 or more unique destination ports through initial TCP SYN packets.

The detection threshold can be customised through the `detect_port_scans()` function.

The analyzer excludes SYN-ACK packets from initial SYN-based scan tracking.

This detection mechanism uses a threshold-based heuristic. A flagged result indicates potentially suspicious behaviour and does not establish that an actual malicious attack has occurred.

## Security Report

The application generates a text-based report at:

```text
reports/security_report.txt
```

The report includes:

- Total packets analyzed
- Protocol distribution
- Packet counts by source IP
- Total traffic volume in bytes
- Most active source IP
- Potential port-scanning findings

## Running Unit Tests

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The test suite covers:

- TCP, UDP, ICMP and unknown protocol packet analysis
- TCP SYN and SYN-ACK classification
- Traffic statistics calculation
- Total packet and traffic volume calculations
- Port-scan detection
- Custom detection thresholds
- PCAP loading
- Missing and corrupted PCAP handling
- Security report generation

## Limitations

- Analyzes offline packet captures only and does not perform live packet capture.
- Port-scan detection relies on a basic threshold-based heuristic.
- Detected activity is not automatically classified as malicious.
- Does not perform deep packet inspection or comprehensive application-layer analysis.
- Detection results depend on the quality and scope of the analyzed capture.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Analyze only packet captures that you own or are authorized to examine.

## Author

**Adarsh Yadav**

GitHub: [yadarsh47-source](https://github.com/yadarsh47-source)