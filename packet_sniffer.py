from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_callback(packet):
    # Ignore packets that don't contain an IP layer
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    print("\n" + "=" * 60)
    print(f"Source IP       : {ip.src}")
    print(f"Destination IP  : {ip.dst}")

    # TCP packet
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        print("Protocol        : TCP")
        print(f"Source Port     : {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")

    # UDP packet
    elif packet.haslayer(UDP):
        udp = packet[UDP]

        print("Protocol        : UDP")
        print(f"Source Port     : {udp.sport}")
        print(f"Destination Port: {udp.dport}")

    # ICMP packet
    elif packet.haslayer(ICMP):
        print("Protocol        : ICMP")

    # Other IP protocol
    else:
        print(f"Protocol        : {ip.proto}")

    print(f"Packet Size     : {len(packet)} bytes")


print("=" * 60)
print("PYTHON PACKET SNIFFER")
print("=" * 60)
print("Starting packet capture...")
print("Press Ctrl+C to stop and save the packets.")
print()

# Start packet capture
packets = sniff(
    filter="ip",
    prn=packet_callback,
    store=True
)

# Save captured packets
print("\nCapture stopped.")
print(f"Total packets captured: {len(packets)}")

wrpcap("captured_packets.pcap", packets)

print("Packets saved successfully!")
print("File: captured_packets.pcap")
