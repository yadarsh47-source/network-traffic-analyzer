import io
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, PcapReader

def detect_port_scans(port_scan_tracker, threshold=10):

    suspicious_activity = []

    for key, ports in port_scan_tracker.items():

        if len(ports) >= threshold:
            source_ip, destination_ip = key

            suspicious_activity.append({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_ports": len(ports),
                "ports": sorted(ports)
            })

    return suspicious_activity


def load_packets(file_path):

    try:
        with open(file_path, "rb") as capture_file:
            file_data = capture_file.read()

        with PcapReader(io.BytesIO(file_data)) as capture_reader:
            packets = list(capture_reader)

        return packets

    except FileNotFoundError:
        raise

    except Exception as error:
        raise ValueError(f"Invalid or corrupted PCAP file: {error}")


def analyze_packets(packets):

    packet_records = []

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_length = len(packet)

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = int(packet[TCP].flags)

            is_syn = bool(
                (tcp_flags & 0x02) and
                not (tcp_flags & 0x10)
            )

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            is_syn = False

        elif ICMP in packet:
            protocol = "ICMP"
            source_port = "N/A"
            destination_port = "N/A"
            is_syn = False

        else:
            protocol = "Other"
            source_port = "N/A"
            destination_port = "N/A"
            is_syn = False

        packet_records.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_length": packet_length,
            "is_syn": is_syn
        })

    return packet_records

def calculate_statistics(packet_records):

    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0
    }

    source_ip_counts = {}
    port_scan_tracker = {}
    total_bytes = 0
    total_packets = len(packet_records)

    for record in packet_records:

        protocol = record["protocol"]
        source_ip = record["source_ip"]
        destination_ip = record["destination_ip"]
        packet_length = record["packet_length"]

        # Count protocols
        if protocol in protocol_counts:
            protocol_counts[protocol] += 1

        # Count packets by source IP
        source_ip_counts[source_ip] = (
            source_ip_counts.get(source_ip, 0) + 1
        )

        # Calculate total traffic volume
        total_bytes += packet_length

        # Track TCP SYN packets
        if protocol == "TCP" and record["is_syn"]:

            key = (source_ip, destination_ip)

            if key not in port_scan_tracker:
                port_scan_tracker[key] = set()

            port_scan_tracker[key].add(
                record["destination_port"]
            )

    return {
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "source_ip_counts": source_ip_counts,
        "total_bytes": total_bytes,
        "port_scan_tracker": port_scan_tracker
    }


def generate_report(statistics, suspicious_activity, output_path):

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w") as report:

        report.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
        report.write("=" * 50 + "\n\n")

        total_packets = statistics["total_packets"]

        report.write(f"Total Packets Analysed: {total_packets}\n")

        report.write("\nPROTOCOL DISTRIBUTION\n")
        report.write("-" * 30 + "\n")

        for protocol, count in statistics["protocol_counts"].items():
            report.write(f"{protocol}: {count}\n")

        report.write("\nPACKETS BY SOURCE IP\n")
        report.write("-" * 30 + "\n")

        for ip, count in statistics["source_ip_counts"].items():
            report.write(f"{ip}: {count}\n")

        report.write(
            f"\nTotal Traffic Volume: {statistics['total_bytes']} bytes\n"
        )

        source_counts = statistics["source_ip_counts"]

        if source_counts:
            most_active_ip = max(source_counts, key=source_counts.get)

            report.write(f"Most Active Source IP: {most_active_ip}\n")
            report.write(
                f"Packets from this IP: {source_counts[most_active_ip]}\n"
            )

        report.write("\nPOSSIBLE PORT SCAN ACTIVITY\n")
        report.write("-" * 30 + "\n")

        if suspicious_activity:

            for activity in suspicious_activity:
                report.write(
                    f"Source IP: {activity['source_ip']}\n"
                )
                report.write(
                    f"Target IP: {activity['destination_ip']}\n"
                )
                report.write(
                    f"Unique Destination Ports: {activity['unique_ports']}\n"
                )
                report.write(
                    f"Ports: {activity['ports']}\n\n"
                )

        else:
            report.write("No potential port scanning detected.\n")

    print("\nSecurity report generated:", output_path)

def main():

    file_path = "data/sample_traffic.pcap"

    try:
        packets = load_packets(file_path)

    except FileNotFoundError:
        print(f"Error: PCAP file not found: {file_path}")
        return

    except ValueError as error:
        print(error)
        return

    if not packets:
        print("Error: The PCAP file contains no packets.")
        return

    packet_records = analyze_packets(packets)

    print("Total packets:", len(packet_records))
    print("-" * 50)

    for number, record in enumerate(packet_records, start=1):

        print(f"\nPacket {number}")
        print("Source IP:", record["source_ip"])
        print("Destination IP:", record["destination_ip"])
        print("Protocol:", record["protocol"])
        print("Source Port:", record["source_port"])
        print("Destination Port:", record["destination_port"])
        print("Packet Length:", record["packet_length"], "bytes")

    statistics = calculate_statistics(packet_records)

    # Display traffic statistics
    protocol_counts = statistics["protocol_counts"]
    source_ip_counts = statistics["source_ip_counts"]
    total_bytes = statistics["total_bytes"]
    port_scan_tracker = statistics["port_scan_tracker"]

    print("\n" + "=" * 50)
    print("NETWORK TRAFFIC STATISTICS")
    print("=" * 50)

    print("\nProtocol Distribution:")
    for protocol, count in protocol_counts.items():
        print(protocol, ":", count)

    print("\nPackets by Source IP:")
    for ip, count in source_ip_counts.items():
        print(ip, ":", count)

    print("\nTotal Traffic Volume:", total_bytes, "bytes")

    if source_ip_counts:
        most_active_ip = max(source_ip_counts, key=source_ip_counts.get)
        print("Most Active Source IP:", most_active_ip)
        print("Packets from this IP:", source_ip_counts[most_active_ip])

    print("\nPossible Port Scan Activity:")
    print("-" * 50)

    suspicious_activity = detect_port_scans(port_scan_tracker)

    if suspicious_activity:
        for activity in suspicious_activity:
            print("Source IP:", activity["source_ip"])
            print("Target IP:", activity["destination_ip"])
            print("Unique destination ports:", activity["unique_ports"])
            print("Ports:", activity["ports"])
    else:
        print("No potential port scanning detected.")

    generate_report(
        statistics,
        suspicious_activity,
        "reports/security_report.txt"
    )

if __name__ == "__main__":
    main()