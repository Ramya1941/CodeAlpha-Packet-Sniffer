from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import Counter

# Load captured packets
packets = rdpcap("captured_packets.pcap")

print("=" * 60)
print("           NETWORK TRAFFIC SUMMARY")
print("=" * 60)

print(f"\nTotal Packets: {len(packets)}")

# Counters
protocols = Counter()
source_ips = Counter()
destination_ips = Counter()
destination_ports = Counter()

tcp_syn = 0
tcp_syn_ack = 0
tcp_ack = 0
tcp_fin = 0

total_bytes = 0


# Analyze every packet
for packet in packets:

    total_bytes += len(packet)

    if packet.haslayer(IP):

        ip = packet[IP]

        source_ips[ip.src] += 1
        destination_ips[ip.dst] += 1

        # TCP
        if packet.haslayer(TCP):

            protocols["TCP"] += 1

            tcp = packet[TCP]

            destination_ports[tcp.dport] += 1

            flags = str(tcp.flags)

            if "S" in flags and "A" not in flags:
                tcp_syn += 1

            if "S" in flags and "A" in flags:
                tcp_syn_ack += 1

            if "A" in flags:
                tcp_ack += 1

            if "F" in flags:
                tcp_fin += 1

        # UDP
        elif packet.haslayer(UDP):

            protocols["UDP"] += 1

            udp = packet[UDP]

            destination_ports[udp.dport] += 1

        # ICMP
        elif packet.haslayer(ICMP):

            protocols["ICMP"] += 1

        else:

            protocols["Other"] += 1


# --------------------------------------------------
# Protocol statistics
# --------------------------------------------------

print("\n" + "-" * 60)
print("PROTOCOL STATISTICS")
print("-" * 60)

for protocol, count in protocols.most_common():
    print(f"{protocol:<10}: {count} packets")


# --------------------------------------------------
# Source IP statistics
# --------------------------------------------------

print("\n" + "-" * 60)
print("TOP SOURCE IPs")
print("-" * 60)

for ip, count in source_ips.most_common(10):
    print(f"{ip:<20}: {count} packets")


# --------------------------------------------------
# Destination IP statistics
# --------------------------------------------------

print("\n" + "-" * 60)
print("TOP DESTINATION IPs")
print("-" * 60)

for ip, count in destination_ips.most_common(10):
    print(f"{ip:<20}: {count} packets")


# --------------------------------------------------
# Port statistics
# --------------------------------------------------

print("\n" + "-" * 60)
print("TOP DESTINATION PORTS")
print("-" * 60)

for port, count in destination_ports.most_common(10):
    print(f"Port {port:<6}: {count} packets")


# --------------------------------------------------
# TCP statistics
# --------------------------------------------------

print("\n" + "-" * 60)
print("TCP CONNECTION STATISTICS")
print("-" * 60)

print(f"SYN packets     : {tcp_syn}")
print(f"SYN-ACK packets : {tcp_syn_ack}")
print(f"ACK packets     : {tcp_ack}")
print(f"FIN packets     : {tcp_fin}")


# --------------------------------------------------
# Total traffic
# --------------------------------------------------

print("\n" + "-" * 60)
print("TRAFFIC STATISTICS")
print("-" * 60)

print(f"Total data captured: {total_bytes} bytes")
print(f"Total data captured: {total_bytes / 1024:.2f} KB")


print("\n" + "=" * 60)
print("          ANALYSIS COMPLETED")
print("=" * 60)

