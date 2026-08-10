from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

print("=" * 70)
print("              NETWORK PACKET ANALYZER")
print("=" * 70)

# Load captured packets
packets = rdpcap("captured_packets.pcap")

print(f"\nTotal packets captured: {len(packets)}")

# Statistics
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

# Analyze packets
for number, packet in enumerate(packets, start=1):

    if not packet.haslayer(IP):
        other_count += 1
        continue

    ip = packet[IP]

    print("\n" + "-" * 70)
    print(f"Packet #{number}")

    print(f"Source IP       : {ip.src}")
    print(f"Destination IP  : {ip.dst}")

    # TCP
    if packet.haslayer(TCP):

        tcp_count += 1
        tcp = packet[TCP]

        print("Protocol        : TCP")
        print(f"Source Port     : {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"TCP Flags       : {tcp.flags}")

        if Raw in packet:
            payload = bytes(packet[Raw].load)

            print(f"Payload Size    : {len(payload)} bytes")
            print(f"Payload         : {payload[:100].hex(' ')}")
        else:
            print("Payload         : None")

    # UDP
    elif packet.haslayer(UDP):

        udp_count += 1
        udp = packet[UDP]

        print("Protocol        : UDP")
        print(f"Source Port     : {udp.sport}")
        print(f"Destination Port: {udp.dport}")

        if Raw in packet:
            payload = bytes(packet[Raw].load)

            print(f"Payload Size    : {len(payload)} bytes")
            print(f"Payload         : {payload[:100].hex(' ')}")
        else:
            print("Payload         : None")

    # ICMP
    elif packet.haslayer(ICMP):

        icmp_count += 1

        print("Protocol        : ICMP")

        if Raw in packet:
            payload = bytes(packet[Raw].load)

            print(f"Payload Size    : {len(payload)} bytes")
            print(f"Payload         : {payload[:100].hex(' ')}")
        else:
            print("Payload         : None")

    # Other IP protocols
    else:

        other_count += 1

        print(f"Protocol        : IP protocol {ip.proto}")

        if Raw in packet:
            payload = bytes(packet[Raw].load)

            print(f"Payload Size    : {len(payload)} bytes")
            print(f"Payload         : {payload[:100].hex(' ')}")
        else:
            print("Payload         : None")

    print(f"Packet Size     : {len(packet)} bytes")


# Final statistics
print("\n")
print("=" * 70)
print("                    SUMMARY")
print("=" * 70)

print(f"Total Packets : {len(packets)}")
print(f"TCP Packets   : {tcp_count}")
print(f"UDP Packets   : {udp_count}")
print(f"ICMP Packets  : {icmp_count}")
print(f"Other Packets : {other_count}")

print("=" * 70)
print("Analysis completed successfully.")
print("=" * 70)

