#!/usr/bin/env python3
"""
Alert Engine Module - NetSecDashboard
Correlates security alerts and logs. Implements analytical filters:
- Maps Snort IDS alerts to unified alerts and assigns Severity (Critical/High/Medium/Low)
- Scans DNS queries for threat domain matches
- Analyzes firewall block events for scan sweep behavior
- Evaluates Top Talkers and scores their aggregate danger level out of 100
"""

import collections

# Known Indicators of Compromise (IoCs)
MALICIOUS_DOMAINS = [
    "evil.ru", "malware-c2.xyz", "super-stealer.co", "hacker-botnet.net",
    "ransomware-gate.cc", "cred-harvest.org", "phishing-bank.com"
]

SUSPICIOUS_IPS = [
    "103.20.15.4", "198.51.100.12", "185.220.101.5", "45.227.254.10"
]

def map_severity(priority):
    """Translates Snort alerts Priority (1-3) into standard high-contrast verbal categories."""
    p_int = int(priority)
    if p_int == 1:
        return "Critical"
    elif p_int == 2:
        return "High"
    elif p_int == 3:
        return "Medium"
    else:
        return "Low"

def correlate_events(ids_alerts, firewall_logs, dns_logs, pcap_stats=None):
    """
    Applies custom logic across different datasets to output a prioritized lists of alerts.
    """
    all_correlated = []

    # 1. Digest Snort IDS alerts (these are pre-tagged alerts)
    for idx, alert in enumerate(ids_alerts):
        all_correlated.append({
            "timestamp": alert.get("formatted_time", alert.get("timestamp")),
            "severity": alert.get("severity", "Medium"),
            "category": "IDS Alert",
            "source_ip": alert.get("src_ip"),
            "dest_ip": alert.get("dst_ip"),
            "protocol": alert.get("protocol"),
            "description": alert.get("description"),
            "details": f"IDS Class: {alert.get('classification', 'N/A')} | Port: {alert.get('src_port')} -> {alert.get('dst_port')}"
        })

    # 2. Extract DNS Threat alerts from DNS Queries
    for dns in dns_logs:
        domain = dns.get("domain", "").lower()
        if any(bad in domain for bad in MALICIOUS_DOMAINS):
            all_correlated.append({
                "timestamp": dns.get("timestamp").replace("T", " "),
                "severity": "Critical" if "c2" in domain or "ransomware" in domain else "High",
                "category": "DNS Threat",
                "source_ip": dns.get("client_ip"),
                "dest_ip": "8.8.8.8 (DNS)",
                "protocol": "UDP",
                "description": f"Indicator of Compromise (IoC) Lookup: {domain}",
                "details": f"Host queried a blacklisted domain. QType: {dns.get('qtype')}"
            })

    # 3. Analyze Firewall Logs for Denial Sweeps (potential scans/bruteforce)
    denies_by_src = collections.defaultdict(list)
    for log in firewall_logs:
        if log.get("action") == "DENY":
            src = log.get("src_ip")
            denies_by_src[src].append(log)

    for src, logs in denies_by_src.items():
        if len(logs) >= 5: # Threshold of block counts to generate alert
            severity = "High" if src in SUSPICIOUS_IPS else "Medium"
            time_sorted = sorted(logs, key=lambda x: x.get("timestamp"))
            start_t = time_sorted[0].get("timestamp")
            end_t = time_sorted[-1].get("timestamp")
            
            # List of target ports to summarize in alert details
            scanned_ports = list(set([l.get("dst_port") for l in logs]))[:5]
            ports_summary = ", ".join(map(str, scanned_ports))
            if len(scanned_ports) > 5:
                ports_summary += "..."

            all_correlated.append({
                "timestamp": end_t,
                "severity": severity,
                "category": "Firewall Block Sweep",
                "source_ip": src,
                "dest_ip": "Multiple Internal Hosts",
                "protocol": "TCP/UDP",
                "description": f"Excessive blocks ({len(logs)} events) - Potential Port Scan or Bruteforce Connection Sweep",
                "details": f"Sweep observed between {start_t} and {end_t}. Ports targeted: {ports_summary}"
            })

    # 4. Integrate PCAP suspicious metrics if provided
    if pcap_stats:
        # Port scans detected by PCAP Analyzer
        for src, ports in pcap_stats.get("src_port_scan_attempts", {}).items():
            if len(ports) >= 5:
                all_correlated.append({
                    "timestamp": "PCAP Capture Window",
                    "severity": "High",
                    "category": "PCAP Discovery",
                    "source_ip": src,
                    "dest_ip": "Local Networks",
                    "protocol": "TCP",
                    "description": f"PCAP Sweep: host targeted {len(ports)} different ports",
                    "details": f"Active scans observed in PCAP. Target list of ports: {sorted(list(ports))[:10]}"
                })
        
        # Suspicious Ports traffic
        for flow in pcap_stats.get("suspicious_ports_traffic", [])[:15]: # Limit noise
            all_correlated.append({
                "timestamp": "PCAP Capture Window",
                "severity": "High" if flow["port"] in [4444, 6667] else "Medium",
                "category": "Hostile Port Traffic",
                "source_ip": flow["src_ip"],
                "dest_ip": flow["dst_ip"],
                "protocol": flow["protocol"],
                "description": f"Traffic identified on hostile port {flow['port']} ({flow['reason']})",
                "details": f"Scapy raw stream check. Port corresponds to a dangerous Trojan or Tool interface."
            })

    # Sort all alerts chronologically (descending for panel display)
    def alert_time_key(x):
        ts = x.get("timestamp")
        if not ts or "Window" in ts:
            return "1970-01-01 00:00:00"
        return ts

    all_correlated.sort(key=alert_time_key, reverse=True)
    return all_correlated

def calculate_top_talkers(ids_alerts, firewall_logs, dns_logs, pcap_stats=None, limit=10):
    """
    Computes packet activity weight and evaluates a comprehensive Threat Score for each unique IP.
    Score: 0 to 100, where 100 is highly critical.
    """
    ip_activity = collections.defaultdict(lambda: {
        "packets": 0, "ids_hits": 0, "fw_blocks": 0, "dns_malicious": 0, "scanned_ports": set()
    })

    # Accumulate from IDS Alerts
    for alert in ids_alerts:
        src = alert.get("src_ip")
        dst = alert.get("dst_ip")
        if src:
            ip_activity[src]["ids_hits"] += 1
            ip_activity[src]["packets"] += 1
        if dst:
            ip_activity[dst]["packets"] += 1

    # Accumulate from Firewall Logs
    for log in firewall_logs:
        src = log.get("src_ip")
        dst = log.get("dst_ip")
        action = log.get("action")
        if src:
            ip_activity[src]["packets"] += 1
            if action == "DENY":
                ip_activity[src]["fw_blocks"] += 1
                ip_activity[src]["scanned_ports"].add(log.get("dst_port"))
        if dst:
            ip_activity[dst]["packets"] += 1

    # Accumulate from DNS logs
    for dns in dns_logs:
        client = dns.get("client_ip")
        domain = dns.get("domain", "").lower()
        if client:
            ip_activity[client]["packets"] += 1
            if any(bad in domain for bad in MALICIOUS_DOMAINS):
                ip_activity[client]["dns_malicious"] += 1

    # Integrate PCAP stats
    if pcap_stats:
        for ip, count in pcap_stats.get("ip_sources", {}).items():
            ip_activity[ip]["packets"] += count
        for src, ports in pcap_stats.get("src_port_scan_attempts", {}).items():
            ip_activity[src]["scanned_ports"].update(ports)

    # Calculate Threat Score for each IP
    talkers = []
    for ip, record in ip_activity.items():
        # Score Formula:
        # Base threat value
        score = 0
        if ip in SUSPICIOUS_IPS:
            score += 35  # Blacklisted reputation base score

        score += record["ids_hits"] * 8         # 8 points per IDS alert
        score += record["fw_blocks"] * 2        # 2 points per firewall deny block
        score += record["dns_malicious"] * 25    # 25 points per malicious C2 domain lookup

        # Port scanning behavior
        unique_ports = len(record["scanned_ports"])
        if unique_ports >= 5:
            score += 25
        elif unique_ports > 0:
            score += unique_ports * 3

        # Clamp score between 0 and 100
        score = min(max(score, 0), 100)

        # Estimate Role label
        role = "Internal Host"
        if ip.startswith("192.168.1.") or ip.startswith("10."):
            role = "Internal Client"
            if ip in ["192.168.1.1", "10.0.0.1"]:
                role = "Gateway / DC"
        else:
            role = "External Host"
            if ip in SUSPICIOUS_IPS:
                role = "Known Threat Adversary"

        talkers.append({
            "ip": ip,
            "role": role,
            "packet_count": record["packets"],
            "ids_alerts": record["ids_hits"],
            "fw_denies": record["fw_blocks"],
            "threat_score": score
        })

    # Sort descending by threat score, then by packet count
    talkers.sort(key=lambda x: (x["threat_score"], x["packet_count"]), reverse=True)
    return talkers[:limit]
