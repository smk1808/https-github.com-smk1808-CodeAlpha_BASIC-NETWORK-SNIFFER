import scapy.all as scapy

def process_packet(packet):
    print(packet)

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# Start sniffing on the specified interface
sniffer('Wi-Fi')