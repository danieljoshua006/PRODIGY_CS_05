from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n📦 Packet Captured:")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"🔹 Source IP: {ip_layer.src}")
        print(f"🔹 Destination IP: {ip_layer.dst}")
        print(f"🔹 Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("🔸 Protocol Type: TCP")
            print(f"  ↳ Source Port: {packet[TCP].sport}")
            print(f"  ↳ Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("🔸 Protocol Type: UDP")
            print(f"  ↳ Source Port: {packet[UDP].sport}")
            print(f"  ↳ Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                print(f"📝 Payload Data: {payload[:100]}")  # Truncate payload
            except:
                print("⚠️ Payload could not be decoded.")
    else:
        print("⚠️ Non-IP Packet")

def main():
    print("🔍 ProDigy Infotech - Network Packet Analyzer")
    print("Press Ctrl+C to stop sniffing...\n")
    
    # Start sniffing
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
