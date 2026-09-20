import os
from scapy.all import rdpcap, Raw

def extract_payloads_from_pcap(pcap_path):
    """
    Reads a PCAP file and extracts raw byte payloads from each packet.
    """
    if not os.path.exists(pcap_path):
        print(f"[ERROR] PCAP file not found: {pcap_path}")
        return []

    print(f"=== Reading PCAP File: {os.path.basename(pcap_path)} ===")
    packets = rdpcap(pcap_path)
    print(f"Total Packets Captured: {len(packets)}\n")

    extracted_payloads = []

    for idx, pkt in enumerate(packets, start=1):
        print(f"--- Packet #{idx} ---")
        
        # Check if packet contains a Raw payload layer
        if pkt.haslayer(Raw):
            raw_payload = pkt[Raw].load  # Extract raw payload bytes
            byte_values = list(raw_payload)  # Convert byte sequence to integers (0-255)
            payload_len = len(byte_values)
            
            extracted_payloads.append(byte_values)
            
            print(f"Status        : Payload Extracted")
            print(f"Payload Length: {payload_len} bytes")
            print(f"Byte Values   : {byte_values[:15]}... (first 15 bytes)")
            
            # Try decoding text representation for HTTP/readable payloads
            try:
                text_preview = raw_payload[:40].decode('utf-8', errors='ignore').strip()
                print(f"Text Preview  : '{text_preview}'")
            except Exception:
                pass
        else:
            print("Status        : No Raw Payload found (Header-only packet)")
        
        print()

    print(f"=== Extraction Complete: {len(extracted_payloads)} payloads extracted ===")
    return extracted_payloads

if __name__ == "__main__":
    sample_pcap = os.path.join(os.path.dirname(__file__), "..", "pcap", "sample.pcap")
    extract_payloads_from_pcap(os.path.abspath(sample_pcap))
