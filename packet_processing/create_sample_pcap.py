import os
from scapy.all import IP, TCP, UDP, Raw, wrpcap

def generate_sample_pcap(output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    packets = []
    
    # Packet 1: HTTP GET request (Normal traffic sample)
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    pkt1 = IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=49152, dport=80)/Raw(load=http_payload)
    packets.append(pkt1)
    
    # Packet 2: DNS Query (Normal UDP sample)
    dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    pkt2 = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=5353, dport=53)/Raw(load=dns_payload)
    packets.append(pkt2)
    
    # Packet 3: Simulated Malicious Payload (Binary exploit string)
    attack_payload = b"NOPNOPNOP\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    pkt3 = IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=4444, dport=8080)/Raw(load=attack_payload)
    packets.append(pkt3)
    
    wrpcap(output_path, packets)
    print(f"[SUCCESS] Sample PCAP created at: {output_path}")
    print(f"Generated {len(packets)} packets with raw byte payloads.")

if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "pcap", "sample.pcap")
    generate_sample_pcap(os.path.abspath(target))
