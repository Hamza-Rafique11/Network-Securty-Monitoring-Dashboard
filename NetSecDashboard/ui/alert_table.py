#!/usr/bin/env python3
"""
Alert Table Widget - NetSecDashboard
Implements a scrollable ttk.Treeview designed to display real-time network alerts.
Features:
- Column sorting on headers
- Color tags representing severity (Red=Critical, Orange=High, Yellow=Medium, Green=Low)
- Style mapping overrides to fix Tkinter Treeview row color issues on modern Windows/OS themes
- Expandable slide detail viewer triggered on double-clicking rows
"""

import tkinter as tk
from tkinter import ttk

class AlertTableFrame(ttk.Frame):
    def __init__(self, parent, on_select_callback=None, **kwargs):
        super().__init__(parent, **kwargs)
        self.on_select_callback = on_select_callback
        
        # Grid weight configuration
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        self._setup_style_mapping()
        self._build_widgets()

    def _setup_style_mapping(self):
        """
        Overrides the ttk theme mappings. On Windows, ttk Treeviews often do not 
        respect tag background options due to default theme override limitations.
        """
        style = ttk.Style()
        # Ensure 'clam' or relative default is customized or mapped
        current_theme = style.theme_use()
        
        # Override map for selection state to ensure color visibility matches
        style.map('Treeview', 
            background=[('selected', '#1a242b')],
            foreground=[('selected', '#ffffff')]
        )

    def _build_widgets(self):
        # Create a container frame of treeview + scrollbar
        container = ttk.Frame(self)
        container.grid(row=0, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        cols = ("Timestamp", "Severity", "Category", "Source IP", "Dest IP", "Protocol", "Description")
        self.tree = ttk.Treeview(container, columns=cols, show="headings", selectmode="browse")
        
        # Set headings and configure sorting on click
        for col in cols:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_column(c, False))
            if col == "Timestamp":
                self.tree.column(col, width=130, anchor="center")
            elif col == "Severity":
                self.tree.column(col, width=80, anchor="center")
            elif col == "Category":
                self.tree.column(col, width=110, anchor="center")
            elif col in ["Source IP", "Dest IP"]:
                self.tree.column(col, width=110, anchor="center")
            elif col == "Protocol":
                self.tree.column(col, width=60, anchor="center")
            else:
                self.tree.column(col, width=280, anchor="w")

        # Scrollbar mapping
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Set Colors Tags
        # High contrast palette matching industrial SOC systems
        self.tree.tag_configure("Critical", background="#fadbd8", foreground="#78281f") # Soft Red
        self.tree.tag_configure("High", background="#fdebd0", foreground="#7e5109")     # Soft Orange
        self.tree.tag_configure("Medium", background="#fcf3cf", foreground="#7d6608")   # Soft Yellow
        self.tree.tag_configure("Low", background="#d4efdf", foreground="#145a32")      # Soft Green

        # Binding selection callback index
        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)

    def populate(self, alerts):
        """Populates the rows of the table with correlated alerts list."""
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.alerts_map = {} # Map Treeview items to alert dictionaries
        for idx, alert in enumerate(alerts):
            item_id = self.tree.insert(
                "", "end",
                values=(
                    alert.get("timestamp", "")[:19],
                    alert.get("severity", ""),
                    alert.get("category", ""),
                    alert.get("source_ip", ""),
                    alert.get("dest_ip", ""),
                    alert.get("protocol", ""),
                    alert.get("description", "")
                ),
                tags=(alert.get("severity", "Medium"),)
            )
            self.alerts_map[item_id] = alert

    def _on_row_selected(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        alert_data = self.alerts_map.get(item_id)
        if alert_data and self.on_select_callback:
            self.on_select_callback(alert_data)

    def _sort_column(self, col, reverse):
        """Grid column sorting algorithm on text selection."""
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        
        # Sort values
        try:
            # Try to sort numeric values if possible
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)

        # Rearrange items
        for index, (val, k) in enumerate(l):
            self.tree.move(k, "", index)

        # Toggle sorting direction
        self.tree.heading(col, command=lambda: self._sort_column(col, not reverse))


if __name__ == "__main__":
    # Test harness
    root = tk.Tk()
    root.title("Alert Table Test harness")
    root.geometry("800x400")

    widget = AlertTableFrame(root, on_select_callback=lambda x: print(f"Selected: {x}"))
    widget.pack(fill="both", expand=True, padx=10, pady=10)

    test_data = [
        {"timestamp": "2026-06-14 10:05:00", "severity": "Critical", "category": "IDS Alert", "source_ip": "19.168.1.5", "dest_ip": "10.0.0.5", "protocol": "TCP", "description": "Metasploit Shell inbound"},
        {"timestamp": "2026-06-14 10:05:01", "severity": "High", "category": "DNS Threat", "source_ip": "19.168.1.100", "dest_ip": "8.8.8.8", "protocol": "UDP", "description": "beacon to malware-c2.xyz"},
        {"timestamp": "2026-06-14 10:05:02", "severity": "Medium", "category": "Firewall", "source_ip": "103.20.15.4", "dest_ip": "192.168.1.100", "protocol": "TCP", "description": "Firewall Block Sweep"},
        {"timestamp": "2026-06-14 10:05:03", "severity": "Low", "category": "IDS Alert", "source_ip": "192.168.1.101", "dest_ip": "8.8.8.8", "protocol": "ICMP", "description": "Echo Request Ping"}
    ]
    widget.populate(test_data)
    root.mainloop()
