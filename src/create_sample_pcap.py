from scapy.all import IP, TCP, UDP, DNS, DNSQR, ICMP, Raw, wrpcap

packets = []

# 1. DNS query
dns_packet = (
    IP(src="192.168.1.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com"))
)

# 2. HTTPS-style TCP traffic
https_packet = (
    IP(src="192.168.1.10", dst="93.184.216.34") /
    TCP(sport=51524, dport=443, flags="S")
)

# 3. SSH-style TCP connection attempt
ssh_packet = (
    IP(src="192.168.1.20", dst="192.168.1.5") /
    TCP(sport=51525, dport=22, flags="S")
)

# 4. ICMP echo request
icmp_packet = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    ICMP(type=8)
)

# 5. UDP example
udp_packet = (
    IP(src="192.168.1.30", dst="192.168.1.40") /
    UDP(sport=40000, dport=123) /
    Raw(load=b"Sample NTP-like payload")
)

packets.extend([
    dns_packet,
    https_packet,
    ssh_packet,
    icmp_packet,
    udp_packet
])

wrpcap("data/sample_traffic.pcap", packets)

print("Sample PCAP file created successfully.")
print("Total packets:", len(packets))


# Generate a synthetic port-scan-like capture

scan_packets = []

source_ip = "192.168.1.50"
target_ip = "192.168.1.5"

target_ports = [
    21, 22, 23, 25, 53, 80,
    110, 143, 443, 445, 3306, 8080
]

for port in target_ports:
    packet = (
        IP(src=source_ip, dst=target_ip) /
        TCP(sport=50000, dport=port, flags="S")
    )

    scan_packets.append(packet)

wrpcap("data/sample_port_scan.pcap", scan_packets)

print("Synthetic port-scan capture created.")
print("Total scan packets:", len(scan_packets))
