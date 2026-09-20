import os
from pathlib import Path
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import config


def generate_sample_pcap(output_path: str = None, num_packets: int = 100) -> str:
    """
    Generates a realistic sample PCAP file containing benign and attack traffic packets
    for testing the IDS ingestion and detection pipeline.
    """
    if output_path is None:
        output_path = str(config.SAMPLE_PCAP_DIR / "sample_traffic.pcap")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    packets = []

    # 1. Benign Traffic (HTTP, DNS)
    for i in range(25):
        pkt = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=1024 + i, dport=80, flags="PA") / (
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
            + b"X" * (50 + i * 5)
        )
        packets.append(pkt)

    # 2. DDoS-SYN_Flood Traffic
    for i in range(25):
        pkt = IP(src=f"10.0.0.{i % 250 + 1}", dst="192.168.1.1") / TCP(sport=20000 + i, dport=80, flags="S") / (
            b"\x00\x00\x00\x00\x00\x00\x00\x00SYN_FLOOD_PAYLOAD_TEST_" + bytes([i % 256]) * 60
        )
        packets.append(pkt)

    # 3. DDoS-UDP_Flood Traffic
    for i in range(25):
        pkt = IP(src=f"172.16.0.{i % 250 + 1}", dst="192.168.1.1") / UDP(sport=30000 + i, dport=53) / (
            b"UDP_FLOOD_VECTOR_CIC_IOT_2023_PAYLOAD_" + bytes([(i * 7) % 256]) * 100
        )
        packets.append(pkt)

    # 4. Mirai / Recon / Spoofing Traffic
    for i in range(25):
        pkt = IP(src="192.168.1.200", dst="192.168.1.1") / ICMP() / (
            b"MIRAI_BOTNET_C2_COMMAND_PING_SEQ_" + str(i).encode() + b"\x00" * 40
        )
        packets.append(pkt)

    scapy.wrpcap(output_path, packets)
    print(f"[+] Generated sample PCAP with {len(packets)} packets at: {output_path}")
    return output_path


if __name__ == "__main__":
    generate_sample_pcap()
