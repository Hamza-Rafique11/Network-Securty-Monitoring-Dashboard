#!/usr/bin/env python3
"""
PCAP Analyzer Module - NetSecDashboard
Reads and parses network packet capture files (.pcap) using Scapy (pure Python).
Provides:
- Packet count, total transfer volumes, protocol distributions
- Traffic flow tracking for Top Talkers estimation
- Threat analysis on ports, payloads and scan sweep attempts
- Standard-library fallback parsing if Scapy is missing
"""

import os
import sys

# Threat lists for analysis
THREAT_PORTS = {
    21: "FTP (Plaintext credentials visible)",
    23: "Telnet (Insecure access protocol)",
    445: "SMB (EternalBlue exploit surface)",
    1433: "MSSQL (Database targeting)",
    3389: "RDP (Bruteforce active)",
    4444: "Metasploit / Reverse Shell Default",
    6667: "IRC Default Botnet Command Control",
    8080: "Proxy / Alternative HTTP Admin Panel"
}

# Suspicious payload signatures
SUSPICIOUS_SIGNATURES = [
    b"Nmap",b"sqlmap",b"cat /etc/passwd",b"cmd.exe",b"/bin/sh",b"Wget",b"curl",b"powershell"
]

def analyze_pcap_with_scapy(pcap_path):
    """
    Parses PCAP using Scapy library.
    Returns standard summary reports.
    """
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
    import collections

    stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0},
        "ip_sources": collections.Counter(),
        "ip_dests": collections.Counter(),
        "ip_pairs": collections.Counter(),
        "src_port_scan_attempts": collections.defaultdict(set), # IP -> set of ports scanned
        "suspicious_ports_traffic": [],
        "suspicious_payloads": [],
        "timeline_bytes": collections.defaultdict(int), # Sec -> bytes
        "ip_bytes": collections.defaultdict(int), # IP -> bytes transferred
    }

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[-] PCAP Read Error with Scapy: {e}")
        return None

    stats["total_packets"] = len(packets)

    for i, pkt in enumerate(packets):
        # Accumulate size
        pkt_len = len(pkt)
        stats["total_bytes"] += pkt_len

        # Analyze timeline (relative time helper)
        pkt_time = int(pkt.time)
        stats["timeline_bytes"][pkt_time] += pkt_len

        # Check layers
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst

            stats["ip_sources"][src] += 1
            stats["ip_dests"][dst] += 1
            stats["ip_pairs"][(src, dst)] += 1
            stats["ip_bytes"][src] += pkt_len

            # Check protocols
            if pkt.haslayer(TCP):
                stats["protocols"]["TCP"] += 1
                tcp_layer = pkt[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport

                # Track port scanning: record target destination ports
                stats["src_port_scan_attempts"][src].add(dport)

                # Flag hostile ports usage
                if dport in THREAT_PORTS:
                    stats["suspicious_ports_traffic"].append({
                        "packet_idx": i,
                        "src_ip": src,
                        "dst_ip": dst,
                        "port": dport,
                        "reason": THREAT_PORTS[dport],
                        "protocol": "TCP"
                    })

                # Payload Inspection
                payload_raw = bytes(tcp_layer.payload)
                for sig in SUSPICIOUS_SIGNATURES:
                    if sig in payload_raw:
                        stats["suspicious_payloads"].append({
                            "packet_idx": i,
                            "src_ip": src,
                            "dst_ip": dst,
                            "signature": sig.decode('utf-8', errors='ignore'),
                            "protocol": "TCP"
                        })

            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport

                # DNS special class inside UDP
                if pkt.haslayer(DNS) or sport == 53 or dport == 53:
                    stats["protocols"]["DNS"] += 1
                else:
                    stats["protocols"]["UDP"] += 1

                # Flag hostile ports in UDP
                if dport in THREAT_PORTS:
                    stats["suspicious_ports_traffic"].append({
                        "packet_idx": i,
                        "src_ip": src,
                        "dst_ip": dst,
                        "port": dport,
                        "reason": THREAT_PORTS[dport],
                        "protocol": "UDP"
                    })
            elif pkt.haslayer(ICMP):
                stats["protocols"]["ICMP"] += 1
            else:
                stats["protocols"]["Other"] += 1
        else:
            stats["protocols"]["Other"] += 1

    return stats


def analyze_pcap_fallback_raw(pcap_path):
    """
    Standard library pure-binary fallback reader for PCAPs.
    Reads global header and packet lengths without demanding any pip install.
    This guarantees 100% offline uptime and no crashes.
    """
    import struct
    import collections

    stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0},
        "ip_sources": collections.Counter(),
        "ip_dests": collections.Counter(),
        "ip_pairs": collections.Counter(),
        "src_port_scan_attempts": collections.defaultdict(set),
        "suspicious_ports_traffic": [],
        "suspicious_payloads": [],
        "timeline_bytes": collections.defaultdict(int),
        "ip_bytes": collections.defaultdict(int)
    }

    if not os.path.exists(pcap_path):
        return stats

    try:
        with open(pcap_path, "rb") as f:
            # Read 24-byte global header
            global_header = f.read(24)
            if len(global_header) < 24:
                return stats
            
            # Verify magic number for endianness
            magic = global_header[0:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                little_endian = True
            elif magic == b"\xa1\xb2\xc3\xd4":
                little_endian = False
            else:
                # Unexpected magic, parsing arbitrary packets
                little_endian = True

            while True:
                # Read 16-byte packet header (timestamp sec, ts usec, capture len, original len)
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                if little_endian:
                    sec, usec, cap_len, orig_len = struct.unpack("<IIII", pkt_hdr)
                else:
                    sec, usec, cap_len, orig_len = struct.unpack(">IIII", pkt_hdr)

                # Guard in case PCAP corrupts
                if cap_len > 65535 or cap_len == 0:
                    break

                pkt_data = f.read(cap_len)
                if len(pkt_data) < cap_len:
                    break

                stats["total_packets"] += 1
                stats["total_bytes"] += orig_len
                stats["timeline_bytes"][sec] += orig_len

                # Check if IPv4 header exists (Offset 14 for standard ethernet frame)
                if len(pkt_data) > 34 and pkt_data[12:14] == b"\x08\x00": # EthType = IPv4
                    ip_header = pkt_data[14:34]
                    proto = ip_header[9]
                    
                    # Convert source/destination bytes to IP strings
                    src_ip = ".".join(map(str, ip_header[12:16]))
                    dst_ip = ".".join(map(str, ip_header[16:20]))
                    
                    stats["ip_sources"][src_ip] += 1
                    stats["ip_dests"][dst_ip] += 1
                    stats["ip_pairs"][(src_ip, dst_ip)] += 1
                    stats["ip_bytes"][src_ip] += orig_len

                    # Protocol mappings
                    if proto == 6:  # TCP
                        stats["protocols"]["TCP"] += 1
                        if len(pkt_data) >= 54:
                            sport = int.from_bytes(pkt_data[34:36], byteorder='big')
                            dport = int.from_bytes(pkt_data[36:38], byteorder='big')
                            stats["src_port_scan_attempts"][src_ip].add(dport)

                            if dport in THREAT_PORTS:
                                stats["suspicious_ports_traffic"].append({
                                    "packet_idx": stats["total_packets"] - 1,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "port": dport,
                                    "reason": THREAT_PORTS[dport],
                                    "protocol": "TCP"
                                })

                            # Payload inspection on TCP
                            payload = pkt_data[54:]
                            for sig in SUSPICIOUS_SIGNATURES:
                                if sig in payload:
                                    stats["suspicious_payloads"].append({
                                        "packet_idx": stats["total_packets"] - 1,
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "signature": sig.decode('utf-8', errors='ignore'),
                                        "protocol": "TCP"
                                    })
                    elif proto == 17: # UDP
                        if len(pkt_data) >= 42:
                            sport = int.from_bytes(pkt_data[34:36], byteorder='big')
                            dport = int.from_bytes(pkt_data[36:38], byteorder='big')
                            
                            if sport == 53 or dport == 53:
                                stats["protocols"]["DNS"] += 1
                            else:
                                stats["protocols"]["UDP"] += 1

                            if dport in THREAT_PORTS:
                                stats["suspicious_ports_traffic"].append({
                                    "packet_idx": stats["total_packets"] - 1,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "port": dport,
                                    "reason": THREAT_PORTS[dport],
                                    "protocol": "UDP"
                                })
                    elif proto == 1:  # ICMP
                        stats["protocols"]["ICMP"] += 1
                    else:
                        stats["protocols"]["Other"] += 1
                else:
                    stats["protocols"]["Other"] += 1

    except Exception as e:
        print(f"[-] PCAP Binary Fallback Read Error: {e}")

    return stats


def analyze_pcap(pcap_path):
    """
    Main entry analyzer. Attempts to use Scapy first, 
    on Scapy import/runtime failure fallback to raw binary reader.
    """
    # Check if Scapy is available
    scapy_available = False
    try:
        import scapy
        scapy_available = True
    except ImportError:
        pass

    if scapy_available:
        stats = analyze_pcap_with_scapy(pcap_path)
        if stats:
            return stats
        # If Scapy failed at runtime for some weird reason, fallback
        print("[!] Scapy failed at runtime. Attempting binary raw parsing...")
    
    return analyze_pcap_fallback_raw(pcap_path)


if __name__ == "__main__":
    # Test execution
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    test_pcap_path = os.path.join(parent_dir, "data", "sample_capture.pcap")

    if os.path.exists(test_pcap_path):
        results = analyze_pcap(test_pcap_path)
        print("=== PCAP ANALYSIS REPORT (SELF-TEST) ===")
        print(f"Total Packets: {results['total_packets']}")
        print(f"Total Bytes: {results['total_bytes']} bytes")
        print(f"Protocols: {results['protocols']}")
        print(f"Top 3 Sources: {results['ip_sources'].most_common(3)}")
        print(f"Suspicious Port Hits: {len(results['suspicious_ports_traffic'])}")
    else:
        print("Please run data_generator.py first to seed datasets.")
