#!/usr/bin/env python3
"""
Log Parser Module - NetSecDashboard
Provides regex-based parsing services to ingest flat log files into standardized python collections.
Handles:
- Snort IDS Logs: Ingests alert descriptions, priorities, ips and ports.
- Firewall Logs: Ingests ALLOW/DENY traffic flows.
- DNS Logs: Ingests query timestamps, local hosts and target domains.
"""

import os
import re
from datetime import datetime

# Regex rules for high performance parsing
# Snort IDS Format: 06/14-10:05:05.123456 [**] [1:1000001:1] ET SCAN Nmap SYN Scan [**] [Classification: class] [Priority: pri] {TCP} 192.168.1.5:port -> 10.0.0.5:port
IDS_REGEX = re.compile(
    r'^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
    r'\[\d+:(?P<sig_id>\d+):\d+\]\s+(?P<description>.+?)\s+\[\*\*\]\s+'
    r'(?:\[Classification:\s*(?P<classification>.+?)\]\s+)?'
    r'\[Priority:\s*(?P<priority>\d+)\]\s+'
    r'\{(?P<protocol>\w+)\}\s+'
    r'(?P<src_ip>[\w\.\:]+)\:(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\w\.\:]+)\:(?P<dst_port>\d+)'
)

# Firewall Format: 2026-06-14 10:05:05 ALLOW TCP 192.168.1.100:54632 -> 8.8.8.8:53
FW_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>ALLOW|DENY)\s+'
    r'(?P<protocol>\w+)\s+'
    r'(?P<src_ip>[\w\.\:]+)\:(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\w\.\:]+)\:(?P<dst_port>\d+)'
)

# DNS Format: 2026-06-14T10:05:10 192.168.1.105 evil.ru A
DNS_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+'
    r'(?P<client_ip>[\w\.\:]+)\s+'
    r'(?P<domain>[\w\-\.]+)\s+'
    r'(?P<qtype>\w+)'
)

def parse_ids_log(file_path):
    """
    Parses Snort or Suricata format log files.
    Returns list of parsed alert dicts.
    """
    alerts = []
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return alerts

    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            match = IDS_REGEX.match(line)
            if match:
                data = match.groupdict()
                # Parse timestamp into friendly format
                try:
                    # Snort uses format "MM/DD-hh:mm:ss.ffffff" (e.g. 06/14-10:05:05.123456)
                    # We append current year as snort doesn't write years
                    current_year = datetime.now().year
                    ts_str = f"{current_year}/{data['timestamp']}"
                    dt = datetime.strptime(ts_str, "%Y/%m/%d-%H:%M:%S.%f")
                    data["formatted_time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    data["formatted_time"] = data["timestamp"]

                # Translate numerical alerts priority to verbal severity levels 
                priority = int(data["priority"])
                if priority == 1:
                    severity = "Critical"
                elif priority == 2:
                    severity = "High"
                elif priority == 3:
                    severity = "Medium"
                else:
                    severity = "Low"
                
                data["severity"] = severity
                data["line_num"] = idx
                alerts.append(data)
            else:
                # Fallback parser if regex has tiny mismatch but has core features
                if "[**]" in line:
                    try:
                        parts = line.split(" ")
                        data = {
                            "timestamp": parts[0],
                            "formatted_time": parts[0],
                            "description": line.split("[**]")[2].strip().split("[")[0].strip(),
                            "severity": "High" if "Priority: 1" in line else "Medium",
                            "priority": "1" if "Priority: 1" in line else "2",
                            "protocol": "TCP" if "{TCP}" in line else "UDP",
                            "src_ip": line.split("}")[-1].split("->")[0].strip().split(":")[0],
                            "src_port": line.split("}")[-1].split("->")[0].strip().split(":")[1],
                            "dst_ip": line.split("->")[-1].strip().split(":")[0],
                            "dst_port": line.split("->")[-1].strip().split(":")[1],
                            "classification": "Potentially Suspicious Traffic",
                            "line_num": idx
                        }
                        alerts.append(data)
                    except Exception:
                        pass # Ignore parsing anomalies
    return alerts

def parse_firewall_log(file_path):
    """
    Parses firewall log lines (ALLOW/DENY actions).
    """
    logs = []
    if not os.path.exists(file_path):
        return logs

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = FW_REGEX.match(line)
            if match:
                logs.append(match.groupdict())
    return logs

def parse_dns_log(file_path):
    """
    Parses DNS query log files.
    """
    queries = []
    if not os.path.exists(file_path):
        return queries

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = DNS_REGEX.match(line)
            if match:
                queries.append(match.groupdict())
    return queries

if __name__ == "__main__":
    # Self testing
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    test_ids_path = os.path.join(parent_dir, "data", "sample_ids.log")
    
    if os.path.exists(test_ids_path):
        parsed = parse_ids_log(test_ids_path)
        print(f"[Parsed test] successfully extracted {len(parsed)} alerts.")
        if parsed:
            print(f"Sample Alert: {parsed[0]}")
    else:
        print("Please run data_generator.py first to seed datasets.")
