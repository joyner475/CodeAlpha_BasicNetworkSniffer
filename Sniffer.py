from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    """Callback function that runs for every captured packet"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[+] Packet: {src_ip} → {dst_ip}")

        if TCP in packet:
            print(f"    Protocol : TCP")
            print(f"    Src Port : {packet[TCP].sport}")
            print(f"    Dst Port : {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Protocol : UDP")
            print(f"    Src Port : {packet[UDP].sport}")
            print(f"    Dst Port : {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    Protocol : ICMP")
            print(f"    Type     : {packet[ICMP].type}")

def main():
    print("=" * 10)
    print("Simple Network Packet Sniffer")
    print("Press Ctrl+C to stop")
    print("=" * 10)

    # store=False → don't keep packets in memory (good for long captures)
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()