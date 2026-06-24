#!/usr/bin/env python3
"""
Report Generator Module - NetSecDashboard
Autonomously drafts Incident Analysis Reports summarizing security posture, 
timeline milestones, Indicators of Compromise (IoCs), and analyst suggestions.
Supports:
- PDF format output using the 'fpdf2' library
- Secondary text (.txt) fallback write in case of missing libraries
"""

import os
from datetime import datetime

class INCIDENT_PDF_REPORT:
    """Class to encapsulate PDF generation to prevent global scope pollution."""
    
    def __init__(self, metadata, alerts, top_talkers):
        self.metadata = metadata
        self.alerts = alerts
        self.top_talkers = top_talkers

    def build_pdf(self, output_filepath):
        try:
            from fpdf import FPDF
        except ImportError:
            raise ImportError("fpdf2 library not found")

        # Define custom FPDF class with page headers and footers
        class SOC_PDF(FPDF):
            def header(self):
                # Header Blue/Gray band
                self.set_fill_color(26, 36, 43) # Slate Navy
                self.rect(0, 0, 210, 32, 'F')
                
                # Title
                self.set_text_color(255, 255, 255)
                self.set_font('helvetica', 'B', 16)
                self.cell(0, -2, 'NETSEC DASHBOARD - INCIDENT ACCOUNTABILITY REPORT', ln=True, align='C')
                
                # Subtitle
                self.set_font('helvetica', 'I', 10)
                self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Confidential SOC Report', ln=True, align='C')
                self.ln(12)

            def footer(self):
                # Back to standard font
                self.set_y(-18)
                self.set_font('helvetica', 'I', 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - Security Operations Center Internal Use Only', align='C')

        # Instantiate PDF
        pdf = SOC_PDF()
        pdf.alias_nb_pages()
        pdf.set_margins(15, 35, 15)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        
        # 1. SECTION: Executive Summary
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(41, 128, 185) # Accent Navy Blue
        pdf.cell(0, 10, '1. Executive Posture Summary', ln=True)
        pdf.line(15, pdf.get_y() + 1, 195, pdf.get_y() + 1)
        pdf.ln(4)
        
        pdf.set_font('helvetica', '', 10)
        pdf.set_text_color(40, 40, 40)
        
        crit_count = sum(1 for a in self.alerts if a['severity'] == 'Critical')
        high_count = sum(1 for a in self.alerts if a['severity'] == 'High')
        total_alerts = len(self.alerts)
        
        summary_text = (
            f"During the continuous active monitoring window, the Security Operations Center (SOC) "
            f"monitoring system ingested several network event logs and parsed PCAP capture evidence. "
            f"A total of {total_alerts} security alerts were generated, containing {crit_count} Critical-severity "
            f"events and {high_count} High-severity events. The telemetry datasets confirm the existence "
            f"of multiple active attack vectors targeting internal subnets, specifically an automated reconnaissance "
            f"port-scan scan sweep, DNS lookups contacting malicious Command and Control (C2) domains (e.g., evil.ru), "
            f"and firewall rule violations attempting brute-force lateral access."
        )
        pdf.multi_cell(0, 5, summary_text)
        pdf.ln(4)
        
        # Stats summary bullets
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 6, "Key Security Indicators Captured:", ln=True)
        pdf.set_font('helvetica', '', 10)
        pdf.cell(10)
        pdf.cell(0, 5, f"- Total Alerts Recorded: {total_alerts}", ln=True)
        pdf.cell(10)
        pdf.cell(0, 5, f"- Critical Threats Identified: {crit_count} (Immediate Action Required)", ln=True)
        pdf.cell(10)
        pdf.cell(0, 5, f"- Active Adversaries Tracked: {sum(1 for t in self.top_talkers if t['threat_score'] >= 60)} hosts with threat score >= 60", ln=True)
        pdf.cell(10)
        pdf.cell(0, 5, f"- Bandwidth Consumed in Capture: {self.metadata.get('pcap_bytes', 0):,} bytes across {self.metadata.get('pcap_packets', 0)} packet captures.", ln=True)
        pdf.ln(5)

        # 2. SECTION: Indicators of compromise (IoCs)
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(41, 128, 185)
        pdf.cell(0, 10, '2. Identified Indicators of Compromise (IoCs)', ln=True)
        pdf.line(15, pdf.get_y() + 1, 195, pdf.get_y() + 1)
        pdf.ln(4)

        # Draw Table Headers
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_fill_color(240, 240, 240)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(35, 7, 'Threat IP', 1, 0, 'C', fill=True)
        pdf.cell(50, 7, 'Role / Classification', 1, 0, 'C', fill=True)
        pdf.cell(30, 7, 'Packets Handled', 1, 0, 'C', fill=True)
        pdf.cell(30, 7, 'IDS Highlights', 1, 0, 'C', fill=True)
        pdf.cell(35, 7, 'Threat Score (0-100)', 1, 1, 'C', fill=True)

        pdf.set_font('helvetica', '', 9)
        for talker in self.top_talkers[:6]: # Top 6 threat talkers
            pdf.cell(35, 6, talker['ip'], 1, 0, 'C')
            pdf.cell(50, 6, talker['role'], 1, 0, 'L')
            pdf.cell(30, 6, str(talker['packet_count']), 1, 0, 'C')
            pdf.cell(30, 6, str(talker['ids_alerts']), 1, 0, 'C')
            
            # High-threat score highlights as red
            score = talker['threat_score']
            if score >= 70:
                pdf.set_fill_color(254, 237, 238) # Light red
                pdf.set_text_color(192, 57, 43)
                pdf.cell(35, 6, f"{score} [HIGH]", 1, 1, 'C', fill=True)
            elif score >= 40:
                pdf.set_fill_color(255, 248, 230) # Light orange
                pdf.set_text_color(211, 84, 0)
                pdf.cell(35, 6, f"{score} [MED]", 1, 1, 'C', fill=True)
            else:
                pdf.set_fill_color(255, 255, 255)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(35, 6, f"{score}", 1, 1, 'C')
            # Reset colors
            pdf.set_text_color(40, 40, 40)
        
        pdf.ln(5)

        # 3. SECTION: Timeline Audit Feed
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(41, 128, 185)
        pdf.cell(0, 10, '3. Critical Incident Timeline Insights', ln=True)
        pdf.line(15, pdf.get_y() + 1, 195, pdf.get_y() + 1)
        pdf.ln(4)

        # Render top 10 chronologically sorted alerts
        pdf.set_font('helvetica', 'B', 8)
        pdf.set_fill_color(240, 244, 248) # Ice blue
        pdf.cell(35, 6, 'Timestamp', 1, 0, 'C', fill=True)
        pdf.cell(18, 6, 'Severity', 1, 0, 'C', fill=True)
        pdf.cell(35, 6, 'Adversary (Src IP)', 1, 0, 'C', fill=True)
        pdf.cell(92, 6, 'Alert Trigger Explanation', 1, 1, 'C', fill=True)

        pdf.set_font('helvetica', '', 8)
        # Select important or worst alerts to list up to 10
        timeline_alerts = [a for a in self.alerts if a['severity'] in ['Critical', 'High', 'Medium']][:12]
        for alert in timeline_alerts:
            pdf.cell(35, 5, alert['timestamp'][:19], 1, 0, 'C')
            
            # Severity color coding
            sev = alert['severity']
            if sev == 'Critical':
                pdf.set_fill_color(231, 76, 60)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(18, 5, 'Critical', 1, 0, 'C', fill=True)
            elif sev == 'High':
                pdf.set_fill_color(230, 126, 34)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(18, 5, 'High', 1, 0, 'C', fill=True)
            else:
                pdf.set_fill_color(241, 196, 15)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(18, 5, 'Medium', 1, 0, 'C', fill=True)
            
            pdf.set_text_color(50, 50, 50)
            pdf.cell(35, 5, alert['source_ip'], 1, 0, 'C')
            
            desc_text = f"{alert['category']}: {alert['description']}"
            if len(desc_text) > 55:
                desc_text = desc_text[:52] + "..."
            pdf.cell(92, 5, desc_text, 1, 1, 'L')

        pdf.ln(5)

        # 4. SECTION: Analyst Suggestions
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(41, 128, 185)
        pdf.cell(0, 10, '4. Mitigation & Patch Recommendations', ln=True)
        pdf.line(15, pdf.get_y() + 1, 195, pdf.get_y() + 1)
        pdf.ln(4)

        pdf.set_font('helvetica', '', 9.5)
        recommendations = [
            "1. Network Isolation: Move threat actors like 192.168.1.5 immediately into an isolated quarantine VLAN. Drop their route bindings to mitigate ongoing brute-force port reviews.",
            "2. Block Blacklisted IPs: Add foreign malicious routers (103.20.15.4, 185.220.101.5, 198.51.100.12) to the perimeter Border Gateway Protocol edge lists and null-route traffic.",
            "3. DNS Cloaking & Sinkholing: Set local DNS servers to sinkhole evil.ru, malware-c2.xyz, and relative indicators to point to the secure telemetry sandbox. Intercept internal host infections.",
            "4. Credential Purge: Since SSH Bruteforce triggers occurred on internal clients, perform an immediate forced credential cycle on all active server accounts, specifically host 192.168.1.100.",
            "5. Apply EternalBlue Updates: Install relative patches against Windows Server SMB vulnerabilities (MS17-010) on internal servers to mitigate EternalBlue lateral propagation threats."
        ]
        
        for rec in recommendations:
            pdf.multi_cell(0, 4.5, rec)
            pdf.ln(1)

        pdf.ln(3)
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 5, "Incident Analyst Sign-off Verification:", ln=True)
        pdf.ln(1)
        pdf.set_font('helvetica', '', 9)
        pdf.cell(0, 5, "Certified SecOps Lead: __________________________             Date: ________________________", ln=True)

        pdf.output(output_filepath)
        print(f"[+] PDF Incident Report created successfully at: {output_filepath}")

def generate_text_report(output_filepath, metadata, alerts, top_talkers):
    """Fallback plain text printer if fpdf is absent."""
    crit_count = sum(1 for a in alerts if a['severity'] == 'Critical')
    high_count = sum(1 for a in alerts if a['severity'] == 'High')
    med_count = sum(1 for a in alerts if a['severity'] == 'Medium')

    report = []
    report.append("="*80)
    report.append("              NETSEC DASHBOARD - EXECUTIVE INCIDENT REPORT (TEXT)")
    report.append(f"              Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("="*80)
    report.append("\n[1] EXECUTIVE SECURITY POSTURE SUMMARY")
    report.append("-"*80)
    
    summary = (
        f"The Security Operations Center (SOC) alert correlation system compiled telemetry data\n"
        f"across local system logs, firewall sweeps, and PCAP data files.\n"
        f"A total of {len(alerts)} alerts were processed:\n"
        f" - Critical: {crit_count}\n"
        f" - High: {high_count}\n"
        f" - Medium: {med_count}\n"
        f"Active physical PCAP captured {metadata.get('pcap_packets', 0)} frames totaling {metadata.get('pcap_bytes', 0):,} bytes of data.\n"
        f"Substantial security alerts confirm active intrusions including reconnaissance SYN scans,\n"
        f"SSH logins originating from malicious hosts, and malicious external DNS connections."
    )
    report.append(summary)

    report.append("\n[2] HOST REPUTATION ANALYSIS & REPUTATION RATINGS")
    report.append("-"*80)
    report.append(f"{'HOST IP':<18} | {'NETWORK ROLE':<30} | {'PACKETS':<8} | {'ALERT COUNT':<10} | {'THREAT SCORE'}")
    report.append("-"*80)
    for t in top_talkers[:8]:
        report.append(f"{t['ip']:<18} | {t['role']:<30} | {t['packet_count']:<8} | {t['ids_alerts']:<10} | {t['threat_score']}/100")

    report.append("\n[3] CHRONOLOGICAL HISTORICAL SECURITY MILESTONES (TOP 12)")
    report.append("-"*80)
    report.append(f"{'TIMESTAMP':<19} | {'SEVERITY':<8} | {'SOURCE IP':<15} | {'DESCRIPTION':<35}")
    report.append("-"*80)
    for a in alerts[:12]:
        report.append(f"{a['timestamp'][:19]:<19} | {a['severity']:<8} | {a['source_ip']:<15} | {a['description'][:35]}")

    report.append("\n[4] SECOPS ACTIONABLE MITIGATION STEPS")
    report.append("-"*80)
    report.append("1. Network Isolation: Quarantine host 192.168.1.5 immediately into isolated VLAN.")
    report.append("2. Outer Blockades: Block foreign command controllers (103.20.15.4, 185.220.101.5) on firewall CLI.")
    report.append("3. DNS Null-routing: Redefine internal DNS rules to null route queries to evil.ru.")
    report.append("4. Credential Rotation: SSH Bruteforce success warrants a forced host password cycle.")
    report.append("5. SMB Patching: Apply KB security updates against EternalBlue (CVE-2017-0144) locally.")
    report.append("\n" + "="*80)

    # Write report
    with open(output_filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
        
    print(f"[+] Plain text fallback report completed at: {output_filepath}")

def generate_incident_report(output_dir, metadata, alerts, top_talkers):
    """
    Main trigger endpoint. Tries writing handsome PDF, 
    if fpdf is failing write clean raw text fallback.
    """
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, "incident_report.pdf")
    txt_path = os.path.join(output_dir, "incident_report.txt")

    # Generate txt fallback anyway since users might appreciate plain text summaries
    generate_text_report(txt_path, metadata, alerts, top_talkers)

    try:
        reporter = INCIDENT_PDF_REPORT(metadata, alerts, top_talkers)
        reporter.build_pdf(pdf_path)
        return True, pdf_path
    except Exception as e:
        print(f"[-] Could not compile PDF report: {e}. TEXT report remains available.")
        return False, txt_path

if __name__ == "__main__":
    # Self testing
    test_meta = {"pcap_packets": 250, "pcap_bytes": 142050}
    test_alerts = [
        {"timestamp": "2026-06-14 10:05:00", "severity": "Critical", "category": "IDS", "source_ip": "192.168.1.5", "dest_ip": "10.0.0.5", "protocol": "TCP", "description": "EternalBlue Exploit Attempt"},
        {"timestamp": "2026-06-14 10:05:30", "severity": "High", "category": "DNS Threat", "source_ip": "192.168.1.100", "dest_ip": "8.8.8.8", "protocol": "UDP", "description": "C2 query to evil.ru"}
    ]
    test_talkers = [
        {"ip": "192.168.1.5", "role": "Internal Intruder", "packet_count": 520, "ids_alerts": 5, "fw_denies": 20, "threat_score": 95},
        {"ip": "103.20.15.4", "role": "Known Malicious Adversary", "packet_count": 120, "ids_alerts": 1, "fw_denies": 12, "threat_score": 75}
    ]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    generate_incident_report(parent_dir, test_meta, test_alerts, test_talkers)
