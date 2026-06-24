#!/usr/bin/env python3
"""
Simulated Data Generator - NetSecDashboard
Generates realistic fake log files (.log) and PCAP files for offline safety testing.
Outputs:
- sample_ids.log (Snort format IDS alerts)
- sample_firewall.log (Firewall ALLOW/DENY logs)
- sample_dns.log (DNS queries with benign/malicious domains)
- sample_capture.pcap (A real PCAP file containing actual IP/TCP/UDP/ICMP packets)
"""

import os
import random
import time
from datetime import datetime, timedelta

# List of suspicious/malicious domains for interest
MALICIOUS_DOMAINS = [
    "evil.ru", "malware-c2.xyz", "super-stealer.co", "hacker-botnet.net",
    "ransomware-gate.cc", "cred-harvest.org", "phishing-bank.com"
]

BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "wikipedia.org",
    "stackoverflow.com", "python.org", "aws.amazon.com", "netflix.com"
]

POTENTIAL_ATTACKERS = [
    "192.168.1.5", "103.20.15.4", "198.51.100.12", "185.220.101.5", "45.227.254.10"
]

INTERNAL_HOISTS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.105", "10.0.0.5"
]

def generate_ids_alerts(output_path, count=220):
    """Generates over 200 Snort-format IDS alerts."""
    categories = [
        {"sig_id": "1000001", "name": "ET SCAN Nmap SYN Scan", "class": "Attempted Information Leak", "priority": 2, "proto": "TCP"},
        {"sig_id": "1000002", "name": "ET MALWARE Evil C2 DNS Lookup", "class": "A Network Trojan was Detected", "priority": 1, "proto": "UDP"},
        {"sig_id": "1000003", "name": "ET WEB_SPECIFIC_APPS Suspicious Admin Panel Access Attempt", "class": "Web Application Attack", "priority": 2, "proto": "TCP"},
        {"sig_id": "1000004", "name": "ET DOS Exploit Attempt (EternalBlue style)", "class": "Attempted Administrator Privilege Gain", "priority": 1, "proto": "TCP"},
        {"sig_id": "1000005", "name": "ET DECRYPT SSH Bruteforce login successful", "class": "Suspicious Login Activity", "priority": 1, "proto": "TCP"},
        {"sig_id": "1000006", "name": "ET POLICY Cryptomining pool activity detected", "class": "Potential Corporate Policy Violation", "priority": 3, "proto": "TCP"},
        {"sig_id": "1000007", "name": "ET MALWARE Generic Adware traffic", "class": "A Network Trojan was Detected", "priority": 3, "proto": "TCP"}
    ]

    base_time = datetime.now() - timedelta(hours=24)
    lines = []

    for i in range(count):
        cat = random.choice(categories)
        timestamp = (base_time + timedelta(seconds=i * random.randint(150, 450))).strftime("%m/%d-%H:%M:%S.%f")
        
        # Determine source/destination based on alert type
        if "SCAN" in cat["name"] or "Bruteforce" in cat["name"] or "DOS" in cat["name"]:
            src = random.choice(POTENTIAL_ATTACKERS)
            dst = random.choice(INTERNAL_HOISTS)
            src_port = random.randint(1024, 65535)
            dst_port = 80 if "WEB" in cat["name"] else (22 if "SSH" in cat["name"] else (445 if "DOS" in cat["name"] else 80))
        else: # Malware beacons / Cryptominer outbound
            src = random.choice(INTERNAL_HOISTS)
            dst = random.choice(POTENTIAL_ATTACKERS)
            src_port = random.randint(1024, 65535)
            dst_port = 4444 if "C2" in cat["name"] else (80 if "Adware" in cat["name"] else 8333)

        # Snort Alert Format:
        # [timestamp] [**] [gen_id:sig_id:rev_id] sig_name [**] [Classification: class] [Priority: priority] {proto} src:sport -> dst:dport
        line = f"{timestamp} [**] [1:{cat['sig_id']}:1] {cat['name']} [**] [Classification: {cat['class']}] [Priority: {cat['priority']}] {{{cat['proto']}}} {src}:{src_port} -> {dst}:{dst_port}\n"
        lines.append(line)

    # Sort alerts chronologically
    lines.sort()

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"[+] Generated {len(lines)} IDS alerts at: {output_path}")

def generate_firewall_logs(output_path, count=550):
    """Generates over 500 Firewall ALLOW/DENY logs."""
    base_time = datetime.now() - timedelta(hours=24)
    lines = []

    for i in range(count):
        timestamp = (base_time + timedelta(seconds=i * random.randint(40, 160))).strftime("%Y-%m-%d %H:%M:%S")
        action = "DENY" if random.random() < 0.25 else "ALLOW"  # ~25% blocks
        
        if action == "DENY":
            src = random.choice(POTENTIAL_ATTACKERS + ["192.168.1.105"])
            dst = random.choice(INTERNAL_HOISTS + ["10.0.0.1"])
            src_port = random.randint(1024, 65535)
            # Denies target security ports (SSH 22, Telnet 23, SMB 445, RDP 3389, custom ports like 4444)
            dst_port = random.choice([22, 23, 445, 1433, 3389, 4444, 8080])
            proto = "TCP" if random.random() < 0.9 else "UDP"
        else:
            src = random.choice(INTERNAL_HOISTS)
            dst = random.choice(["8.8.8.8", "1.1.1.1", "192.30.253.112", "142.250.74.46"]) # Benign outer servers
            src_port = random.randint(32768, 65535)
            dst_port = random.choice([53, 80, 443])
            proto = "TCP" if dst_port in [80, 443] else "UDP"

        # Format: TIMESTAMP ACTION PROTO SRC:SPORT -> DST:DPORT
        line = f"{timestamp} {action} {proto} {src}:{src_port} -> {dst}:{dst_port}\n"
        lines.append(line)

    # Sort
    lines.sort()

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"[+] Generated {len(lines)} firewall logs at: {output_path}")

def generate_dns_logs(output_path, count=120):
    """Generates over 100 DNS logs with suspicious lookup patterns."""
    base_time = datetime.now() - timedelta(hours=24)
    lines = []

    for i in range(count):
        timestamp = (base_time + timedelta(seconds=i * random.randint(300, 700))).strftime("%Y-%m-%dT%H:%M:%S")
        client = random.choice(INTERNAL_HOISTS)
        
        # Inject suspicious domains on ~20% of requests
        if random.random() < 0.22:
            domain = random.choice(MALICIOUS_DOMAINS)
            qtype = "A" if random.random() < 0.8 else "TXT" # TXT is common for C2 bypasses
        else:
            domain = random.choice(BENIGN_DOMAINS)
            qtype = "A" if random.random() < 0.9 else "AAAA"

        # Format: TIMESTAMP CLIENT DOMAIN QTYPE
        line = f"{timestamp} {client} {domain} {qtype}\n"
        lines.append(line)

    lines.sort()

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"[+] Generated {len(lines)} DNS query logs at: {output_path}")

def generate_pcap_scapy(output_path):
    """Generates a valid .pcap file with mixed TCP/UDP/ICMP/DNS packets using Scapy."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, wrpcap
        print("[*] Generating real PCAP file using Scapy...")
    except ImportError:
        print("[!] Scapy is not installed. Creating a mocked PCAP by writing a standard PCAP byte structure...")
        generate_mock_pcap_bytes(output_path)
        return

    packets = []
    
    # 1. DNS Queries and Resolves (Benign and Malicious)
    for domain in BENIGN_DOMAINS[:3] + MALICIOUS_DOMAINS[:2]:
        src_ip = random.choice(INTERNAL_HOISTS)
        # Query Packet
        q_pkt = (Ether()/
                 IP(src=src_ip, dst="8.8.8.8")/
                 UDP(sport=random.randint(49152, 65535), dport=53)/
                 DNS(rd=1, qd=DNSQR(qname=domain)))
        # Response Packet
        r_pkt = (Ether()/
                 IP(src="8.8.8.8", dst=src_ip)/
                 UDP(sport=53, dport=q_pkt[UDP].sport)/
                 DNS(id=q_pkt[DNS].id, qr=1, aa=1, qd=DNSQR(qname=domain)))
        packets.extend([q_pkt, r_pkt])

    # 2. Simulated Port Scan (Nmap SYN scan sweep)
    # Attacker 192.168.1.5 scans victim 10.0.0.5 on various ports
    scan_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 4444, 8080]
    for port in scan_ports:
        # SYN request
        syn_pkt = (Ether()/
                   IP(src="192.168.1.5", dst="10.0.0.5")/
                   TCP(sport=random.randint(30000, 60000), dport=port, flags="S"))
        packets.append(syn_pkt)
        
        # Victim's reply: Closed ports send RST, open port (80) replies SYN+ACK
        if port == 80:
            ack_pkt = (Ether()/
                       IP(src="10.0.0.5", dst="192.168.1.5")/
                       TCP(sport=port, dport=syn_pkt[TCP].sport, flags="SA"))
            # Attacker's RST or ACK (concluding host scanning)
            rst_pkt = (Ether()/
                       IP(src="192.168.1.5", dst="10.0.0.5")/
                       TCP(sport=syn_pkt[TCP].sport, dport=port, flags="R"))
            packets.extend([ack_pkt, rst_pkt])
        else:
            # Closed port RST+ACK
            rst_pkt = (Ether()/
                       IP(src="10.0.0.5", dst="192.168.1.5")/
                       TCP(sport=port, dport=syn_pkt[TCP].sport, flags="RA"))
            packets.append(rst_pkt)

    # 3. Normal HTTP Traffic
    # Handshake
    http_client = "192.168.1.100"
    web_server = "142.250.74.46" # Google IP
    sport = random.randint(50000, 55000)
    
    syn = Ether()/IP(src=http_client, dst=web_server)/TCP(sport=sport, dport=80, flags="S")
    syn_ack = Ether()/IP(src=web_server, dst=http_client)/TCP(sport=80, dport=sport, flags="SA")
    ack = Ether()/IP(src=http_client, dst=web_server)/TCP(sport=sport, dport=80, flags="A")
    packets.extend([syn, syn_ack, ack])
    
    # HTTP GET Request (Mock Payload)
    payload = "GET /index.html HTTP/1.1\r\nHost: google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    get_req = Ether()/IP(src=http_client, dst=web_server)/TCP(sport=sport, dport=80, flags="PA")/payload
    
    # HTTP Response Client Ack and response
    resp_ack = Ether()/IP(src=web_server, dst=http_client)/TCP(sport=80, dport=sport, flags="A")
    resp_data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body><h1>It Works!</h1></body></html>"
    resp_pkt = Ether()/IP(src=web_server, dst=http_client)/TCP(sport=80, dport=sport, flags="PA")/resp_data
    packets.extend([get_req, resp_ack, resp_pkt])

    # 4. ICMP Activity (Ping sweep / troubleshooting)
    for internal in INTERNAL_HOISTS[:3]:
        # Echo request
        ping_req = Ether()/IP(src=internal, dst="8.8.8.8")/ICMP(type=8, code=0)
        # Echo reply
        ping_rep = Ether()/IP(src="8.8.8.8", dst=internal)/ICMP(type=0, code=0)
        packets.extend([ping_req, ping_rep])

    # 5. Some random background UDP flow
    for _ in range(30):
        udp_flow = (Ether()/
                    IP(src="192.168.1.102", dst="192.168.1.255")/
                    UDP(sport=137, dport=137)/  # NetBIOS
                    b"\x82\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        packets.append(udp_flow)

    # Write packets to PCAP using Scapy
    wrpcap(output_path, packets)
    print(f"[+] Successfully generated actual PCAP with {len(packets)} packets at: {output_path}")

def generate_mock_pcap_bytes(output_path):
    """
    Creates a valid PCAP file format from raw byte headers.
    This guarantees a functional PCAP without demanding external libraries.
    """
    # Global header
    # Magic Number (4B) | Major (2B) | Minor (2B) | TimeZone (4B) | SigFlags (4B) | SnapLen (4B) | LinkType (4B)
    pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    
    # Let's write a series of mock packets (each requires dynamic timestamps and network headers)
    packets_data = []

    # Injecting packet loops
    base_secs = int(time.time()) - 86400
    
    # We will generate 80 mock packets of static types to make sure analyzer reads something
    for i in range(120):
        sec = base_secs + i * random.randint(20, 100)
        usec = random.randint(1000, 999999)
        
        # Craft mock packet payload (Ethernet / IP / TCP )
        # Ether Header: 14 bytes, IP Header: 20 bytes, TCP Header: 20 bytes
        src_ip = bytes([192, 168, 1, random.choice([100, 101, 102, 105, 5])])
        dst_ip = bytes([10, 0, 0, 5]) if src_ip[3] == 5 else bytes([142, 250, 74, 46])
        
        ethernet = b"\x00\x0c\x29\x3e\x41\x11\x00\x0c\x29\x1f\x12\x15\x08\x00" # IPv4
        ip_header = bytearray(b"\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00") # TCP
        ip_header.extend(src_ip)
        ip_header.extend(dst_ip)
        
        # Simple checksum patch is not strict in simple PCAP readers, but header length is 20
        sport = random.randint(1024, 65535)
        dport = 80 if src_ip[3] != 5 else 4444
        tcp_header = bytearray()
        tcp_header.extend(sport.to_bytes(2, byteorder='big'))
        tcp_header.extend(dport.to_bytes(2, byteorder='big'))
        tcp_header.extend(b"\x00\x00\x00\x01\x00\x00\x00\x01\x50\x02\x0b\xb8\x00\x00\x00\x00")
        
        packet_payload = ethernet + ip_header + tcp_header
        cap_len = len(packet_payload)
        orig_len = cap_len
        
        # Packet header: TsSec (4B) | TsUsec (4B) | InclLen (4B) | OrigLen (4B)
        pkt_header = (
            sec.to_bytes(4, byteorder='little') +
            usec.to_bytes(4, byteorder='little') +
            cap_len.to_bytes(4, byteorder='little') +
            orig_len.to_bytes(4, byteorder='little')
        )
        packets_data.append(pkt_header + packet_payload)

    with open(output_path, "wb") as f:
        f.write(pcap_header)
        for p in packets_data:
            f.write(p)
            
    print(f"[+] Successfully generated mock global byte PCAP with {len(packets_data)} packets at: {output_path}")

def generate_all(directory_path):
    """Utility to build all fake files inside targeted folder."""
    os.makedirs(directory_path, exist_ok=True)
    
    ids_path = os.path.join(directory_path, "sample_ids.log")
    fw_path = os.path.join(directory_path, "sample_firewall.log")
    dns_path = os.path.join(directory_path, "sample_dns.log")
    pcap_path = os.path.join(directory_path, "sample_capture.pcap")

    generate_ids_alerts(ids_path)
    generate_firewall_logs(fw_path)
    generate_dns_logs(dns_path)
    
    # Try generating using scapy first, fallback to mock bytes
    generate_pcap_scapy(pcap_path)
    print("[+] All sample datasets successfully generated!\n")

if __name__ == "__main__":
    # If run standalone, build files in a local sibling 'data' folder
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_data_dir = os.path.join(base_dir, "data")
    generate_all(target_data_dir)
