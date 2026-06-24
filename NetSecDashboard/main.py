#!/usr/bin/env python3
"""
NetSecDashboard - SOC-style End-to-End Security Monitoring Dashboard
Main desktop entry point. Auto-discovers and seeds simulated datasets on first run.

Developed for Windows 11 under PyCharm. Runs natively with:
python main.py
"""

import os
import sys

# Append parent directories to PATH to ensure clean local modules resolution
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from modules.data_generator import generate_all
from ui.dashboard import NetSecSOCDashboard

def bootstrap_application():
    """
    Checks if datasets exist. If they do not, triggers the 
    simulated data generator so the application runs standalone.
    """
    data_dir = os.path.join(current_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    
    required_files = [
        "sample_ids.log",
        "sample_firewall.log",
        "sample_dns.log",
        "sample_capture.pcap"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(data_dir, f))]
    
    if missing_files:
        print("[*] Missing default simulated datasets. Bootstrapping data generator to create realistic telemetry log and PCAP files...")
        try:
            generate_all(data_dir)
            print("[+] Default simulated context seeded successfully!")
        except Exception as e:
            print(f"[-] Data generation failed on boot: {e}. Dashboard will request manual folder selection.")
    else:
        print("[+] Discovered existing standard data logs inside '/data'. Ready for ingestion.")

def main():
    # Bootstrap data
    bootstrap_application()
    
    # Init main SOC panel GUI
    print("[*] Launching NetSecDashboard GUI workspace Console...")
    try:
        app = NetSecSOCDashboard()
        app.mainloop()
        print("[+] Application closed clean. Stay safe, Analyst!")
    except Exception as e:
        print(f"[-] Could not launch the Tkinter graphical canvas: {e}")
        print("    Ensure you are running inside a graphical shell environment with Tkinter support.")
        print("\n=== SYSTEM REQUIREMENTS GUIDES ===")
        print("- Verify Tkinter is installed: python -m tkinter")
        print("- Build and run standard pip utilities: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
