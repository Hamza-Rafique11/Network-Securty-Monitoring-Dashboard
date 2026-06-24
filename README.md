# 🛡️ NetSecDashboard

### SOC-Style End-to-End Security Monitoring Dashboard using Logs and PCAP Evidence

NetSecDashboard is a desktop Security Operations Center (SOC) investigation board. It consumes, parses, correlates, and analyzes standard log telemetry and packet capture (PCAP) data to flag network intrusions. It compiles findings into a standardized executive report (PDF and plain-text formats) ready for forensic signature.

Designed to operate **100% offline**, this application requires no database backends, external APIs, or internet connectivity. It comes equipped with an autonomous network generator that seeds over 200+ IDS alerts, 500+ firewall transactions, 100+ DNS query records, and a custom network PCAP sequence instantly on first run.

---

## 🎯 Architecture & Project Structure

The project conforms to a modular and extendable Model-View-Controller style structure:

```
NetSecDashboard/
├── main.py                  # Master entry point — discovers data, triggers generator, initiates UI
├── requirements.txt         # Pip installations list
├── README.md                # System setup documentation (this file)
├── data/                    # Ingestion databank (Created on first run)
│   ├── sample_ids.log       # Snort signature-format IDS alerts log
│   ├── sample_firewall.log  # Firewall ALLOW/DENY transactions log
│   ├── sample_dns.log       # Local system DNS lookup query log
│   └── sample_capture.pcap  # Live raw PCAP file consisting of real network headers
├── modules/
│   ├── data_generator.py    # Auto-seeds the data/ folder with dense simulated files
│   ├── log_parser.py        # High-performance regex engine for Snort, Firewall and DNS styles
│   ├── pcap_analyzer.py     # Binary-level or Scapy-driven PCAP packet parser
│   ├── alert_engine.py      # Correlates firewall denials, blacklisted DNS and IDS signatures
│   └── report_generator.py  # Incident PDF compiles via FPDF2 or fell back as .txt formats
└── ui/
    ├── dashboard.py         # Primary GUI layout, style theme, metrics bindings and triggers
    ├── alert_table.py       # Scrollable, color-tag severity ranked alerts ttk Treeview
    └── charts.py            # Embedded Matplotlib (or Tkinter Canvas fallback) panel
```

---

## 🎨 Master Panels Breakdown

The dashboard exposes four critical investigative modules:

1. **Panel 1 — Live Alert Feed**
   * A high-density grid showing Timestamp | Severity | Category | Source IP | Dest IP | Protocol | Description. Only critical details are grouped and auto-highlighted using bright threat indicators (Red for Critical, Orange for High, Yellow for Medium, Green for Low). Left-clicking lists exact payload packets, forensic advice checklists, and troubleshooting instructions inside the inspection bar.
2. **Panel 2 — Traffic Overview Charts**
   * Features a double-charts grid: a Pie Chart visualizing protocol percentages (TCP, UDP, ICMP, DNS) from the PCAP analysis, and a Bar Chart tracking alert density hour-by-hour over the last 24h.
3. **Panel 3 — Top Talkers**
   * An IP reputation card evaluating unique IPs and giving them an unified composite Threat Score (0 to 100) based on multiple telemetry factors (Nmap port sweeping, blacklisted C2 queries, IDS triggers).
4. **Panel 4 — Incident Summary narrative**
   * Provides a continuous narrative assessment summarizing core affected hosts, highest-scoring threats, and actionable defense solutions. Clicking "Export Standard PDF Audit Report" compiles a pristine security document directly into your directory!

---

## ⚡ Quick Start: Setup and Execution (Windows 11)

### Prerequisites

* Python 3.10+ installed and added to your system `PATH`.
* JetBrains PyCharm (Community or Professional Edition).

### Step 1: Clone or Extract the Dashboard
Ensure the files reside under a unified parent folder named `NetSecDashboard`.

### Step 2: Open in PyCharm
1. Open PyCharm, click **Open**, and navigate to the `NetSecDashboard` directory.
2. PyCharm will automatically detect or ask to configure a virtual environment (Virtualenv). Accept and configure a new Python 3.10+ environment.

### Step 3: Open terminal and Install Dependencies
Open the Terminal inside PyCharm (typically available at the bottom panel) and run:

```bash
pip install -r requirements.txt
```

*Note: This downloads `scapy`, `matplotlib`, and `fpdf2`.*

### Step 4: Run the Application
In your PyCharm terminal or standard Windows PowerShell console, execute:

```bash
python main.py
```

On your **very first run**:
1. The application will detect that the `data/` folder is empty or absent.
2. It will auto-trigger `modules/data_generator.py` which creates the realistic cyber defense datasets instantly.
3. The Tkinter GUI desktop panel will slide open and discover your local `./data/` folder.
4. Simply click **⚡ Run Analysis** to start parsing, correlation, charting, and reporting!

---

## 🛡️ Telemetry Processing Mechanics (Algorithms)

To achieve maximum enterprise stability, every component was created with robust fallback handlers to maintain 100% execution uptime even under highly unconfigured runtimes:

* **PCAP Analyzer Fallback**: If the WinPcap/Npcap subsystem or Scapy driver is missing or failing, the `pcap_analyzer.py` invokes a specialized pure-Python binary byte-scanner. This reads the global PCAP file headers and unpacks timestamps, packet sizes, and IP transport layers manually via struct unpack overlays!
* **Charts Draw Fallback**: If Matplotlib package dependencies fail to compile, the GUI falls back to vector-plotting shapes directly onto a raw Tkinter canvas element, creating a beautiful native bar and pie rendering complete with legends.
* **FPDF Report Fallback**: If `fpdf2` fails of some reason, the report compilations generate a beautiful high-fidelity chronological plain-text summary audit (`incident_report.txt`) directly in the parent directory!

---

Developed for Security Analysts by Security Operations Center Engineers. Stay safe, Analyst! 🛡️
