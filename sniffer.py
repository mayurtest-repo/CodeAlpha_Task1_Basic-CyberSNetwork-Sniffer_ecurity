import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Source Port: {src_port}, TCP Destination Port: {dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Source Port: {src_port}, UDP Destination Port: {dst_port}")

        print("\n")

# Specify the network interface to sniff on (e.g., "eth0" for Ethernet, "wlan0" for Wi-Fi)
network_interface = "eth0"

# Start sniffing
sniff(network_interface)
