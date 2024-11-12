from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        # Extract IP layer details
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Check for TCP or UDP protocols
        if packet.haslayer(TCP):
            layer_proto = "TCP"
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            layer_proto = "UDP"
            payload = bytes(packet[UDP].payload)
        else:
            layer_proto = "Other"
            payload = None

        # Display packet information
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {layer_proto}")
        if payload:
            print(f"Payload: {payload[:50]}...")  # Display the first 50 bytes of the payload for readability
        print("-" * 50)

# Capture packets on a specified interface (e.g., 'eth0') or default to all interfaces
print("Starting packet capture...")
sniff(prn=packet_callback, store=0)
