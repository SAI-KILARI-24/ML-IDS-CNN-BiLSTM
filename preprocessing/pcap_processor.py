import os
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


class PCAPProcessor:
    """
    PCAP Processing module powered by Scapy.
    Extracts packets, metadata, and raw payload byte sequences.
    """

    @staticmethod
    def validate_pcap(file_path: str) -> Tuple[bool, str]:
        """
        Validates if the target file exists, is readable, and is non-empty.
        """
        p = Path(file_path)
        if not p.exists():
            return False, f"File not found: {file_path}"
        if not p.is_file():
            return False, f"Path is not a valid file: {file_path}"
        if p.stat().st_size == 0:
            return False, f"PCAP file is empty (0 bytes): {file_path}"
        
        valid_exts = [".pcap", ".pcapng", ".cap"]
        if p.suffix.lower() not in valid_exts:
            return False, f"Invalid file extension '{p.suffix}'. Expected one of {valid_exts}"
        
        return True, "Valid PCAP file"

    def process_pcap(self, file_path: str, max_packets: int = None) -> Dict[str, Any]:
        """
        Reads a PCAP file and extracts packet details and raw payloads.

        Returns:
            Dict containing:
            - success: bool
            - message: str
            - file_info: dict (name, size_mb, total_packets, payload_packets)
            - packets: list of dicts with extracted packet data and raw payload bytes
        """
        is_valid, err_msg = self.validate_pcap(file_path)
        if not is_valid:
            return {"success": False, "message": err_msg, "file_info": {}, "packets": []}

        try:
            # Load packets via Scapy
            scapy_packets = scapy.rdpcap(file_path)
        except Exception as e:
            return {
                "success": False,
                "message": f"Scapy failed to parse PCAP file: {str(e)}",
                "file_info": {},
                "packets": []
            }

        total_packets = len(scapy_packets)
        extracted_packets = []
        payload_count = 0

        for i, pkt in enumerate(scapy_packets):
            if max_packets and i >= max_packets:
                break

            # Metadata extraction
            ts = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            src_ip = "N/A"
            dst_ip = "N/A"
            proto = "Other"

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                if pkt.haslayer(TCP):
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
            elif pkt.haslayer(scapy.ARP):
                src_ip = pkt[scapy.ARP].psrc
                dst_ip = pkt[scapy.ARP].pdst
                proto = "ARP"

            # Raw payload extraction
            raw_payload = b""
            if pkt.haslayer(Raw):
                raw_payload = bytes(pkt[Raw].load)
            elif pkt.haslayer(IP):
                # Fallback: raw payload from IP layer onwards
                raw_payload = bytes(pkt[IP])

            payload_len = len(raw_payload)
            if payload_len > 0:
                payload_count += 1

            extracted_packets.append({
                "packet_id": i + 1,
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": str(proto),
                "total_len": len(pkt),
                "payload_bytes": raw_payload,
                "payload_len": payload_len
            })

        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)

        return {
            "success": True,
            "message": f"Successfully processed {len(extracted_packets)} packets from {Path(file_path).name}",
            "file_info": {
                "file_name": Path(file_path).name,
                "file_size_mb": round(file_size_mb, 4),
                "total_packets": total_packets,
                "packets_analyzed": len(extracted_packets),
                "packets_with_payload": payload_count
            },
            "packets": extracted_packets
        }
