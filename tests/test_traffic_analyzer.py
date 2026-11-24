from src.traffic_analyzer import (
    load_packets,
    analyze_packets,
    calculate_statistics,
    detect_port_scans,
    generate_report
)

import tempfile
import os
import unittest
from scapy.all import IP, TCP, UDP, ICMP

from src.traffic_analyzer import (
    analyze_packets,
    calculate_statistics,
    detect_port_scans
)

class TestAnalyzePackets(unittest.TestCase):

    def test_analyze_tcp_packet(self):

        packet = (
            IP(src="192.168.1.10", dst="192.168.1.20") /
            TCP(sport=50000, dport=443, flags="S")
        )

        result = analyze_packets([packet])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source_ip"], "192.168.1.10")
        self.assertEqual(result[0]["destination_ip"], "192.168.1.20")
        self.assertEqual(result[0]["protocol"], "TCP")
        self.assertEqual(result[0]["destination_port"], 443)
        self.assertTrue(result[0]["is_syn"])

    def test_analyze_udp_packet(self):

        packet = (
            IP(src="192.168.1.10", dst="8.8.8.8") /
            UDP(sport=53000, dport=53)
        )

        result = analyze_packets([packet])

        self.assertEqual(result[0]["protocol"], "UDP")
        self.assertEqual(result[0]["source_port"], 53000)
        self.assertEqual(result[0]["destination_port"], 53)
        self.assertFalse(result[0]["is_syn"])

    def test_analyze_icmp_packet(self):

        packet = (
            IP(src="192.168.1.10", dst="192.168.1.1") /
            ICMP(type=8)
        )

        result = analyze_packets([packet])

        self.assertEqual(result[0]["protocol"], "ICMP")
        self.assertEqual(result[0]["source_port"], "N/A")
        self.assertEqual(result[0]["destination_port"], "N/A")


class TestCalculateStatistics(unittest.TestCase):

    def test_calculate_statistics(self):

        packets = [
            IP(src="192.168.1.10", dst="8.8.8.8") /
            UDP(sport=53000, dport=53),

            IP(src="192.168.1.10", dst="93.184.216.34") /
            TCP(sport=51524, dport=443, flags="S"),

            IP(src="192.168.1.20", dst="192.168.1.5") /
            TCP(sport=51525, dport=22, flags="S"),

            IP(src="192.168.1.10", dst="192.168.1.1") /
            ICMP(type=8)
        ]

        packet_records = analyze_packets(packets)

        statistics = calculate_statistics(packet_records)

        self.assertEqual(
            statistics["protocol_counts"]["TCP"], 2
        )

        self.assertEqual(
            statistics["protocol_counts"]["UDP"], 1
        )

        self.assertEqual(
            statistics["protocol_counts"]["ICMP"], 1
        )

        self.assertEqual(
            statistics["source_ip_counts"]["192.168.1.10"], 3
        )

        self.assertEqual(
            statistics["source_ip_counts"]["192.168.1.20"], 1
        )

        expected_bytes = sum(len(packet) for packet in packets)

        self.assertEqual(
            statistics["total_bytes"], expected_bytes
        )


class TestDetectPortScans(unittest.TestCase):

    def test_detect_port_scan(self):

        port_scan_tracker = {
            ("192.168.1.50", "192.168.1.5"): {
                21, 22, 23, 25, 53, 80,
                110, 143, 443, 445, 3306, 8080
            }
        }

        result = detect_port_scans(port_scan_tracker)

        self.assertEqual(len(result), 1)

        self.assertEqual(
            result[0]["source_ip"], "192.168.1.50"
        )

        self.assertEqual(
            result[0]["destination_ip"], "192.168.1.5"
        )

        self.assertEqual(
            result[0]["unique_ports"], 12
        )


    def test_no_port_scan_below_threshold(self):

        port_scan_tracker = {
            ("192.168.1.50", "192.168.1.5"): {
                21, 22, 80, 443
            }
        }

        result = detect_port_scans(port_scan_tracker)

        self.assertEqual(result, [])


    def test_custom_detection_threshold(self):

        port_scan_tracker = {
            ("192.168.1.50", "192.168.1.5"): {
                21, 22, 80, 443, 8080
            }
        }

        result = detect_port_scans(
            port_scan_tracker, threshold=5
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["unique_ports"], 5)


class TestLoadPackets(unittest.TestCase):

    def test_load_existing_pcap(self):

        packets = load_packets("data/sample_traffic.pcap")

        self.assertEqual(len(packets), 5)


    def test_load_missing_pcap(self):

        with self.assertRaises(FileNotFoundError):
            load_packets("data/nonexistent.pcap")


class TestGenerateReport(unittest.TestCase):

    def test_generate_normal_traffic_report(self):

        statistics = {
            "protocol_counts": {
                "TCP": 2,
                "UDP": 2,
                "ICMP": 1
            },
            "source_ip_counts": {
                "192.168.1.10": 3,
                "192.168.1.20": 1
            },
            "total_bytes": 216
        }

        suspicious_activity = []

        with tempfile.TemporaryDirectory() as temp_dir:

            report_path = os.path.join(
                temp_dir, "security_report.txt"
            )

            generate_report(
                statistics,
                suspicious_activity,
                report_path
            )

            self.assertTrue(os.path.exists(report_path))

            with open(report_path, "r") as report:
                content = report.read()

            self.assertIn("Total Packets Analysed: 5", content)
            self.assertIn("TCP: 2", content)
            self.assertIn("Total Traffic Volume: 216 bytes", content)
            self.assertIn(
                "No potential port scanning detected.", content
            )


    def test_generate_port_scan_report(self):

        statistics = {
            "protocol_counts": {
                "TCP": 12,
                "UDP": 0,
                "ICMP": 0
            },
            "source_ip_counts": {
                "192.168.1.50": 12
            },
            "total_bytes": 480
        }

        suspicious_activity = [
            {
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.5",
                "unique_ports": 12,
                "ports": [21, 22, 23, 25, 53, 80,
                          110, 143, 443, 445, 3306, 8080]
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:

            report_path = os.path.join(
                temp_dir, "security_report.txt"
            )

            generate_report(
                statistics,
                suspicious_activity,
                report_path
            )

            with open(report_path, "r") as report:
                content = report.read()

            self.assertIn("Source IP: 192.168.1.50", content)
            self.assertIn("Target IP: 192.168.1.5", content)
            self.assertIn("Unique Destination Ports: 12", content)
