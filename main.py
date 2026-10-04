"""
main.py
=======
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
A professional, beginner-friendly desktop packet sniffer with graphical
and command-line interfaces, real-time packet analysis, protocol classification,
multi-criteria filtering, and secure metadata export.

Author: CodeAlpha Cyber Security Intern
Organization: CodeAlpha Cyber Security
"""

import argparse
import os
import queue
import sys
import threading
import time
from typing import Any, Dict, List, Optional

# Tkinter GUI Imports
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont

from packet_analyzer import (
    analyze_packet,
    matches_filter,
    get_protocol_explanation,
    PacketInfo,
)
from interface_manager import InterfaceManager
from sniffer import NetworkSniffer
from export_manager import export_to_csv, export_to_json


class SnifferGUI:
    """Main graphical user interface application for Basic Network Sniffer."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Basic Network Sniffer | CodeAlpha Cybersecurity Internship (Task 1)")
        self.root.geometry("1180x820")
        self.root.minsize(980, 680)

        # Application state
        self.packet_queue: queue.Queue = queue.Queue()
        self.sniffer = NetworkSniffer(packet_queue=self.packet_queue)
        self.captured_packets: List[PacketInfo] = []
        self.displayed_packet_ids: set = set()
        self.selected_packet: Optional[PacketInfo] = None
        self.interfaces: List[Dict[str, Any]] = []
        self.auto_scroll_enabled = tk.BooleanVar(value=True)
        self.enable_payload_var = tk.BooleanVar(value=False)
        self.is_admin_mode = InterfaceManager.is_admin()
        self.npcap_present = InterfaceManager.is_npcap_available()

        # Filter state
        self.filter_protocol_var = tk.StringVar(value="ALL")
        self.filter_ip_var = tk.StringVar(value="")
        self.filter_port_var = tk.StringVar(value="")
        self.filter_search_var = tk.StringVar(value="")
        self.packet_limit_var = tk.StringVar(value="0")

        # Styling
        self._setup_styles()

        # Build UI Components
        self._build_header()
        self._build_control_panel()
        self._build_stats_panel()
        self._build_filter_bar()
        self._build_main_split_panes()
        self._build_bottom_toolbar()

        # Populate interfaces
        self._refresh_interfaces()

        # Start periodic queue polling loop for thread-safe UI updates
        self.root.after(100, self._process_packet_queue)
        self.root.after(500, self._update_live_stats)

        # Handle clean window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self) -> None:
        """Configure modern ttk styles and fonts."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Color palette
        self.COLOR_BG = "#f4f6f9"
        self.COLOR_HEADER = "#1a2530"
        self.COLOR_ACCENT = "#0d6efd"
        self.COLOR_SUCCESS = "#198754"
        self.COLOR_DANGER = "#dc3545"
        self.COLOR_WARNING = "#ffc107"
        self.COLOR_TEXT = "#212529"
        self.COLOR_MUTED = "#6c757d"
        self.COLOR_PANEL = "#ffffff"

        self.root.configure(bg=self.COLOR_BG)

        # Treeview styling
        style.configure(
            "Treeview",
            background="#ffffff",
            foreground="#212529",
            rowheight=24,
            font=("Segoe UI", 9),
            fieldbackground="#ffffff",
        )
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#e9ecef")
        style.map("Treeview", background=[("selected", "#cfe2ff")], foreground=[("selected", "#084298")])

        # Notebook styling
        style.configure("TNotebook", background=self.COLOR_BG)
        style.configure("TNotebook.Tab", font=("Segoe UI", 9, "bold"), padding=[10, 4])

    def _build_header(self) -> None:
        """Top banner with project identity and system status badges."""
        header_frame = tk.Frame(self.root, bg=self.COLOR_HEADER, padx=16, pady=10)
        header_frame.pack(fill=tk.X)

        title_box = tk.Frame(header_frame, bg=self.COLOR_HEADER)
        title_box.pack(side=tk.LEFT, fill=tk.Y)

        title_lbl = tk.Label(
            title_box,
            text="🛡️ Basic Network Sniffer",
            font=("Segoe UI", 16, "bold"),
            fg="#ffffff",
            bg=self.COLOR_HEADER,
        )
        title_lbl.pack(anchor=tk.W)

        subtitle_lbl = tk.Label(
            title_box,
            text="CodeAlpha Cyber Security Internship | Task 1: Packet Capture & Protocol Analysis",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg=self.COLOR_HEADER,
        )
        subtitle_lbl.pack(anchor=tk.W)

        # Right badges: Admin Status and Driver Status
        badge_box = tk.Frame(header_frame, bg=self.COLOR_HEADER)
        badge_box.pack(side=tk.RIGHT, fill=tk.Y)

        # Admin Badge
        admin_text = "🔒 Admin Mode: Active" if self.is_admin_mode else "⚠️ User Mode (Admin Recommended)"
        admin_bg = "#198754" if self.is_admin_mode else "#d97706"
        admin_badge = tk.Label(
            badge_box,
            text=admin_text,
            font=("Segoe UI", 8, "bold"),
            fg="#ffffff",
            bg=admin_bg,
            padx=8,
            pady=3,
            relief=tk.FLAT,
        )
        admin_badge.pack(side=tk.RIGHT, padx=4)

        # Npcap Badge
        pcap_text = "✓ Npcap Ready" if self.npcap_present else "✗ Npcap Driver Missing"
        pcap_bg = "#0d6efd" if self.npcap_present else "#dc3545"
        pcap_badge = tk.Label(
            badge_box,
            text=pcap_text,
            font=("Segoe UI", 8, "bold"),
            fg="#ffffff",
            bg=pcap_bg,
            padx=8,
            pady=3,
            relief=tk.FLAT,
        )
        pcap_badge.pack(side=tk.RIGHT, padx=4)

    def _build_control_panel(self) -> None:
        """Interface selection, capture start/stop controls, and packet limit."""
        control_frame = tk.LabelFrame(
            self.root,
            text=" Capture Controls & Interface Configuration ",
            font=("Segoe UI", 9, "bold"),
            bg=self.COLOR_PANEL,
            padx=12,
            pady=8,
        )
        control_frame.pack(fill=tk.X, padx=12, pady=6)

        # Top row: Interface Selection
        row1 = tk.Frame(control_frame, bg=self.COLOR_PANEL)
        row1.pack(fill=tk.X, pady=3)

        tk.Label(
            row1,
            text="Network Interface:",
            font=("Segoe UI", 9, "bold"),
            bg=self.COLOR_PANEL,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.iface_combo = ttk.Combobox(row1, state="readonly", width=55, font=("Segoe UI", 9))
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 6), fill=tk.X, expand=True)

        refresh_btn = ttk.Button(row1, text="🔄 Refresh", command=self._refresh_interfaces, width=10)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 12))

        # Packet limit
        tk.Label(
            row1,
            text="Packet Limit (0=No Limit):",
            font=("Segoe UI", 9),
            bg=self.COLOR_PANEL,
        ).pack(side=tk.LEFT, padx=(0, 4))

        limit_entry = ttk.Entry(row1, textvariable=self.packet_limit_var, width=8, font=("Segoe UI", 9))
        limit_entry.pack(side=tk.LEFT, padx=(0, 12))

        # Payload toggle checkbox (Safe by default)
        payload_chk = ttk.Checkbutton(
            row1,
            text="Enable Payload Preview (64 bytes hex)",
            variable=self.enable_payload_var,
        )
        payload_chk.pack(side=tk.LEFT, padx=(0, 12))

        # Bottom row: Action Buttons and Status Label
        row2 = tk.Frame(control_frame, bg=self.COLOR_PANEL)
        row2.pack(fill=tk.X, pady=(6, 2))

        self.start_btn = tk.Button(
            row2,
            text="▶ Start Capture",
            font=("Segoe UI", 10, "bold"),
            bg="#198754",
            fg="#ffffff",
            activebackground="#157347",
            activeforeground="#ffffff",
            padx=14,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.start_capture,
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = tk.Button(
            row2,
            text="⏹ Stop Capture",
            font=("Segoe UI", 10, "bold"),
            bg="#6c757d",
            fg="#ffffff",
            activebackground="#5c636a",
            activeforeground="#ffffff",
            padx=14,
            pady=4,
            relief=tk.FLAT,
            state=tk.DISABLED,
            command=self.stop_capture,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 14))

        # Status text
        self.status_icon = tk.Label(row2, text="⚪", font=("Segoe UI", 12), bg=self.COLOR_PANEL)
        self.status_icon.pack(side=tk.LEFT, padx=(0, 4))

        self.status_lbl = tk.Label(
            row2,
            text="Ready. Select an interface and click 'Start Capture'.",
            font=("Segoe UI", 9),
            fg="#495057",
            bg=self.COLOR_PANEL,
        )
        self.status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _build_stats_panel(self) -> None:
        """Real-time statistical indicators for total and protocol breakdown."""
        stats_frame = tk.Frame(self.root, bg=self.COLOR_BG)
        stats_frame.pack(fill=tk.X, padx=12, pady=(0, 4))

        self.stat_labels: Dict[str, tk.Label] = {}
        metrics = [
            ("Total Packets", "0", "#0d6efd"),
            ("TCP", "0", "#6f42c1"),
            ("UDP", "0", "#d63384"),
            ("ICMP", "0", "#fd7e14"),
            ("DNS", "0", "#20c997"),
            ("HTTPS/TLS", "0", "#198754"),
            ("HTTP", "0", "#0dcaf0"),
            ("Rate (pkt/s)", "0.0", "#495057"),
        ]

        for label_text, default_val, accent_color in metrics:
            card = tk.Frame(stats_frame, bg="#ffffff", relief=tk.SOLID, bd=1)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)

            t_lbl = tk.Label(card, text=label_text, font=("Segoe UI", 8), fg="#6c757d", bg="#ffffff")
            t_lbl.pack(anchor=tk.CENTER, pady=(2, 0))

            v_lbl = tk.Label(
                card,
                text=default_val,
                font=("Segoe UI", 10, "bold"),
                fg=accent_color,
                bg="#ffffff",
            )
            v_lbl.pack(anchor=tk.CENTER, pady=(0, 2))
            self.stat_labels[label_text] = v_lbl

    def _build_filter_bar(self) -> None:
        """Interactive filter row to dynamically search and subset packets."""
        filter_frame = tk.Frame(self.root, bg=self.COLOR_BG)
        filter_frame.pack(fill=tk.X, padx=12, pady=4)

        # Protocol Filter Combobox
        tk.Label(filter_frame, text="Protocol:", font=("Segoe UI", 9, "bold"), bg=self.COLOR_BG).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        proto_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_protocol_var,
            values=["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTPS", "HTTP", "ARP", "OTHER"],
            state="readonly",
            width=8,
            font=("Segoe UI", 9),
        )
        proto_combo.pack(side=tk.LEFT, padx=(0, 8))
        proto_combo.bind("<<ComboboxSelected>>", lambda e: self._reapply_filters())

        # IP Filter
        tk.Label(filter_frame, text="IP Address:", font=("Segoe UI", 9), bg=self.COLOR_BG).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ip_entry = ttk.Entry(filter_frame, textvariable=self.filter_ip_var, width=14, font=("Segoe UI", 9))
        ip_entry.pack(side=tk.LEFT, padx=(0, 8))
        ip_entry.bind("<KeyRelease>", lambda e: self._reapply_filters())

        # Port Filter
        tk.Label(filter_frame, text="Port:", font=("Segoe UI", 9), bg=self.COLOR_BG).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        port_entry = ttk.Entry(filter_frame, textvariable=self.filter_port_var, width=8, font=("Segoe UI", 9))
        port_entry.pack(side=tk.LEFT, padx=(0, 8))
        port_entry.bind("<KeyRelease>", lambda e: self._reapply_filters())

        # Quick Text Search
        tk.Label(filter_frame, text="Search:", font=("Segoe UI", 9), bg=self.COLOR_BG).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        search_entry = ttk.Entry(filter_frame, textvariable=self.filter_search_var, width=20, font=("Segoe UI", 9))
        search_entry.pack(side=tk.LEFT, padx=(0, 8))
        search_entry.bind("<KeyRelease>", lambda e: self._reapply_filters())

        # Reset Filter Button
        reset_btn = ttk.Button(filter_frame, text="Clear Filters", command=self._reset_filters)
        reset_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Auto-scroll Toggle
        scroll_chk = ttk.Checkbutton(filter_frame, text="Auto-scroll", variable=self.auto_scroll_enabled)
        scroll_chk.pack(side=tk.RIGHT)

    def _build_main_split_panes(self) -> None:
        """Scrollable packet table in the upper pane and details notebook below."""
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # 1. Top Pane: Packet Table
        table_container = ttk.Frame(self.paned_window)
        self.paned_window.add(table_container, weight=3)

        columns = ("id", "time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "info")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="#", anchor=tk.CENTER)
        self.tree.heading("time", text="Timestamp", anchor=tk.W)
        self.tree.heading("src_ip", text="Source IP", anchor=tk.W)
        self.tree.heading("src_port", text="Src Port", anchor=tk.CENTER)
        self.tree.heading("dst_ip", text="Destination IP", anchor=tk.W)
        self.tree.heading("dst_port", text="Dst Port", anchor=tk.CENTER)
        self.tree.heading("protocol", text="Protocol", anchor=tk.CENTER)
        self.tree.heading("length", text="Length (B)", anchor=tk.E)
        self.tree.heading("info", text="Summary / Details", anchor=tk.W)

        self.tree.column("id", width=50, minwidth=40, anchor=tk.CENTER)
        self.tree.column("time", width=140, minwidth=120)
        self.tree.column("src_ip", width=140, minwidth=110)
        self.tree.column("src_port", width=65, minwidth=55, anchor=tk.CENTER)
        self.tree.column("dst_ip", width=140, minwidth=110)
        self.tree.column("dst_port", width=65, minwidth=55, anchor=tk.CENTER)
        self.tree.column("protocol", width=80, minwidth=65, anchor=tk.CENTER)
        self.tree.column("length", width=75, minwidth=60, anchor=tk.E)
        self.tree.column("info", width=380, minwidth=250)

        # Scrollbars
        y_scroll = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        # 2. Bottom Pane: Details Notebook (Tabs: Layer Inspection, Payload, Protocol Theory)
        details_container = ttk.Frame(self.paned_window)
        self.paned_window.add(details_container, weight=2)

        self.notebook = ttk.Notebook(details_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Layer Breakdown Tree
        tab_layers = ttk.Frame(self.notebook)
        self.notebook.add(tab_layers, text="📋 Packet Details & Layer Breakdown")

        self.details_tree = ttk.Treeview(tab_layers, columns=("value",), show="tree headings")
        self.details_tree.heading("#0", text="Layer / Field Name", anchor=tk.W)
        self.details_tree.heading("value", text="Field Value / Dissection", anchor=tk.W)
        self.details_tree.column("#0", width=280)
        self.details_tree.column("value", width=600)

        detail_scroll = ttk.Scrollbar(tab_layers, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=detail_scroll.set)
        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 2: Limited Payload Preview
        tab_payload = ttk.Frame(self.notebook)
        self.notebook.add(tab_payload, text="🔍 Payload Preview (Hex/ASCII)")

        self.payload_txt = tk.Text(
            tab_payload,
            font=("Consolas", 10),
            bg="#f8f9fa",
            fg="#212529",
            wrap=tk.NONE,
            padx=8,
            pady=8,
        )
        payload_scroll_y = ttk.Scrollbar(tab_payload, orient=tk.VERTICAL, command=self.payload_txt.yview)
        payload_scroll_x = ttk.Scrollbar(tab_payload, orient=tk.HORIZONTAL, command=self.payload_txt.xview)
        self.payload_txt.configure(yscrollcommand=payload_scroll_y.set, xscrollcommand=payload_scroll_x.set)

        self.payload_txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        payload_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        payload_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Tab 3: Educational Protocol Explanations
        tab_edu = ttk.Frame(self.notebook)
        self.notebook.add(tab_edu, text="💡 Protocol Analysis & Security Notes")

        self.edu_txt = tk.Text(
            tab_edu,
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#212529",
            wrap=tk.WORD,
            padx=14,
            pady=10,
        )
        edu_scroll = ttk.Scrollbar(tab_edu, orient=tk.VERTICAL, command=self.edu_txt.yview)
        self.edu_txt.configure(yscrollcommand=edu_scroll.set)
        self.edu_txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        edu_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate initial educational guide
        self._set_default_educational_text()

    def _build_bottom_toolbar(self) -> None:
        """Bottom action buttons: Clear, Export CSV, Export JSON, Help, and session summary."""
        bottom_frame = tk.Frame(self.root, bg=self.COLOR_BG, padx=12, pady=6)
        bottom_frame.pack(fill=tk.X)

        clear_btn = ttk.Button(bottom_frame, text="🗑️ Clear Results", command=self.clear_results)
        clear_btn.pack(side=tk.LEFT, padx=(0, 6))

        export_csv_btn = ttk.Button(bottom_frame, text="💾 Export to CSV", command=self.export_csv)
        export_csv_btn.pack(side=tk.LEFT, padx=(0, 6))

        export_json_btn = ttk.Button(bottom_frame, text="📄 Export to JSON", command=self.export_json)
        export_json_btn.pack(side=tk.LEFT, padx=(0, 12))

        help_btn = ttk.Button(bottom_frame, text="❓ Help & Testing Guide", command=self._show_help_dialog)
        help_btn.pack(side=tk.LEFT)

        self.footer_lbl = tk.Label(
            bottom_frame,
            text="Displaying 0 of 0 packets",
            font=("Segoe UI", 9, "italic"),
            fg=self.COLOR_MUTED,
            bg=self.COLOR_BG,
        )
        self.footer_lbl.pack(side=tk.RIGHT)

    def _set_default_educational_text(self) -> None:
        """Initial guide displayed in the protocol theory tab."""
        guide = (
            "Network Protocol Fundamentals for Cyber Security Students\n"
            "==========================================================\n\n"
            "• IPv4 & IPv6: Network layer protocols responsible for logical addressing and packet routing across networks. "
            "IPv4 uses 32-bit addresses and TTL (Time to Live) to prevent infinite loops. IPv6 uses 128-bit addresses and Hop Limit.\n\n"
            "• TCP (Transmission Control Protocol): Reliable, connection-oriented transport layer protocol. "
            "Guarantees delivery using sequence numbers and acknowledgments. Initiated by the 3-Way Handshake (SYN -> SYN/ACK -> ACK).\n\n"
            "• UDP (User Datagram Protocol): Lightweight, connectionless transport protocol. Does not guarantee packet arrival "
            "or ordering, but offers minimal latency for DNS queries and real-time streaming.\n\n"
            "• DNS (Domain Name System): Resolves human-readable names (e.g., example.com) to numeric IP addresses. "
            "Commonly operates over UDP port 53. DNS transactions consist of queries and resource records (Answers).\n\n"
            "• HTTPS / TLS: Encrypted web traffic over TCP port 443. While metadata (IPs, ports, packet size, timing) "
            "is visible to network sniffers, the application payload remains cryptographically protected.\n\n"
            "• ICMP (Internet Control Message Protocol): Diagnostic protocol used for network troubleshooting (e.g., ping Echo Requests).\n\n"
            "Select any captured packet above to view an in-depth breakdown of its specific protocol headers and attributes."
        )
        self.edu_txt.delete("1.0", tk.END)
        self.edu_txt.insert(tk.END, guide)

    def _refresh_interfaces(self) -> None:
        """Scan system for available network adapters."""
        self.interfaces = InterfaceManager.get_interfaces()
        names = [iface["display_name"] for iface in self.interfaces]
        self.iface_combo["values"] = names

        if names:
            default_iface = InterfaceManager.get_default_interface()
            if default_iface:
                idx = next((i for i, ifc in enumerate(self.interfaces) if ifc["name"] == default_iface["name"]), 0)
                self.iface_combo.current(idx)
            else:
                self.iface_combo.current(0)
        else:
            self.iface_combo.set("No capture interfaces found")

    def start_capture(self) -> None:
        """Initiate background packet sniffing."""
        if not self.interfaces:
            messagebox.showerror("Error", "No network interfaces available for packet capture.")
            return

        current_idx = self.iface_combo.current()
        if current_idx < 0 or current_idx >= len(self.interfaces):
            messagebox.showerror("Error", "Please select a valid network interface from the dropdown.")
            return

        selected = self.interfaces[current_idx]
        scapy_iface = selected["id"]

        # Parse packet limit
        try:
            limit = int(self.packet_limit_var.get().strip() or "0")
            limit = max(0, limit)
        except ValueError:
            messagebox.showerror("Invalid Input", "Packet limit must be a non-negative integer (e.g., 0 for no limit).")
            return

        # Start sniffer
        success = self.sniffer.start_capture(
            iface=scapy_iface,
            packet_limit=limit,
            enable_payload=self.enable_payload_var.get(),
            on_status_change=self._on_sniffer_status_change,
            on_error=self._on_sniffer_error,
        )

        if success:
            self.start_btn.config(state=tk.DISABLED, bg="#6c757d")
            self.stop_btn.config(state=tk.NORMAL, bg="#dc3545", cursor="hand2")
            self.status_icon.config(text="🟢", fg="#198754")
            self.status_lbl.config(
                text=f"Capturing traffic on {selected['name']}... (Limit: {'None' if limit == 0 else limit})"
            )

    def stop_capture(self) -> None:
        """Stop packet capture cleanly."""
        self.sniffer.stop_capture()
        self.start_btn.config(state=tk.NORMAL, bg="#198754")
        self.stop_btn.config(state=tk.DISABLED, bg="#6c757d", cursor="default")
        self.status_icon.config(text="⚪", fg="#6c757d")
        self.status_lbl.config(text="Capture stopped.")

    def _on_sniffer_status_change(self, msg: str) -> None:
        """Thread callback for sniffer status messages."""
        self.root.after(0, lambda: self.status_lbl.config(text=msg))

    def _on_sniffer_error(self, err_msg: str) -> None:
        """Thread callback when sniffer encounters an error."""
        def handle():
            self.stop_capture()
            self.status_icon.config(text="🔴", fg="#dc3545")
            self.status_lbl.config(text=f"Error: {err_msg}")
            messagebox.showerror("Capture Error", err_msg)
        self.root.after(0, handle)

    def _process_packet_queue(self) -> None:
        """
        Drain the packet queue and insert newly captured packets into table.
        Processes up to 50 packets per invocation to keep GUI responsive.
        """
        max_batch = 50
        count = 0
        added_to_tree = False

        while not self.packet_queue.empty() and count < max_batch:
            pkt: PacketInfo = self.packet_queue.get_nowait()
            self.captured_packets.append(pkt)
            count += 1

            # Check if matches current filter
            if matches_filter(
                pkt,
                protocol_filter=self.filter_protocol_var.get(),
                ip_filter=self.filter_ip_var.get(),
                port_filter=self.filter_port_var.get(),
                search_text=self.filter_search_var.get(),
            ):
                self._insert_packet_row(pkt)
                added_to_tree = True

        if added_to_tree and self.auto_scroll_enabled.get():
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

        self._update_footer_label()

        # Reschedule next polling cycle
        self.root.after(100, self._process_packet_queue)

    def _insert_packet_row(self, pkt: PacketInfo) -> None:
        """Insert a packet entry into the Treeview."""
        self.displayed_packet_ids.add(pkt.packet_id)
        self.tree.insert(
            "",
            tk.END,
            iid=str(pkt.packet_id),
            values=(
                pkt.packet_id,
                pkt.timestamp,
                pkt.src_ip,
                pkt.src_port if pkt.src_port is not None else "-",
                pkt.dst_ip,
                pkt.dst_port if pkt.dst_port is not None else "-",
                pkt.protocol,
                pkt.length,
                pkt.summary,
            ),
        )

    def _update_live_stats(self) -> None:
        """Update statistics cards on the UI."""
        stats = self.sniffer.get_stats_snapshot()
        total = stats.get("total_packets", 0)
        pps = stats.get("packets_per_second", 0.0)
        protos = stats.get("protocols", {})

        if "Total Packets" in self.stat_labels:
            self.stat_labels["Total Packets"].config(text=str(total))
        if "TCP" in self.stat_labels:
            self.stat_labels["TCP"].config(text=str(protos.get("TCP", 0)))
        if "UDP" in self.stat_labels:
            self.stat_labels["UDP"].config(text=str(protos.get("UDP", 0)))
        if "ICMP" in self.stat_labels:
            self.stat_labels["ICMP"].config(text=str(protos.get("ICMP", 0)))
        if "DNS" in self.stat_labels:
            self.stat_labels["DNS"].config(text=str(protos.get("DNS", 0)))
        if "HTTPS/TLS" in self.stat_labels:
            self.stat_labels["HTTPS/TLS"].config(text=str(protos.get("HTTPS", 0)))
        if "HTTP" in self.stat_labels:
            self.stat_labels["HTTP"].config(text=str(protos.get("HTTP", 0)))
        if "Rate (pkt/s)" in self.stat_labels:
            self.stat_labels["Rate (pkt/s)"].config(text=f"{pps:.1f}")

        # If sniffer stopped automatically because of packet limit
        if not self.sniffer.is_capturing and self.stop_btn["state"] == tk.NORMAL:
            self.stop_capture()

        self.root.after(500, self._update_live_stats)

    def _reapply_filters(self) -> None:
        """Clear and rebuild table rows matching active filter parameters."""
        self.tree.delete(*self.tree.get_children())
        self.displayed_packet_ids.clear()

        proto = self.filter_protocol_var.get()
        ip_q = self.filter_ip_var.get()
        port_q = self.filter_port_var.get()
        search_q = self.filter_search_var.get()

        for pkt in self.captured_packets:
            if matches_filter(
                pkt,
                protocol_filter=proto,
                ip_filter=ip_q,
                port_filter=port_q,
                search_text=search_q,
            ):
                self._insert_packet_row(pkt)

        self._update_footer_label()

    def _reset_filters(self) -> None:
        """Clear all filter inputs and restore full table."""
        self.filter_protocol_var.set("ALL")
        self.filter_ip_var.set("")
        self.filter_port_var.set("")
        self.filter_search_var.set("")
        self._reapply_filters()

    def _update_footer_label(self) -> None:
        """Update counter at bottom showing displayed vs total packets."""
        displayed = len(self.displayed_packet_ids)
        total = len(self.captured_packets)
        self.footer_lbl.config(text=f"Displaying {displayed} of {total} captured packets")

    def _on_packet_selected(self, event: Any) -> None:
        """Display comprehensive layer dissection and analysis for selected packet."""
        selection = self.tree.selection()
        if not selection:
            return

        pkt_id_str = selection[0]
        try:
            pkt_id = int(pkt_id_str)
        except ValueError:
            return

        # Find packet
        pkt = next((p for p in self.captured_packets if p.packet_id == pkt_id), None)
        if not pkt:
            return

        self.selected_packet = pkt

        # 1. Update Layer Breakdown Tree
        self.details_tree.delete(*self.details_tree.get_children())

        # Top Node: Frame Summary
        root_node = self.details_tree.insert(
            "",
            tk.END,
            text=f"Frame {pkt.packet_id}: {pkt.length} bytes on wire",
            values=(f"Captured at {pkt.timestamp}",),
            open=True,
        )

        for layer_name, fields in pkt.layer_details.items():
            layer_node = self.details_tree.insert(
                root_node,
                tk.END,
                text=f"Layer: {layer_name}",
                values=(f"{len(fields)} fields",),
                open=True,
            )
            for k, v in fields.items():
                self.details_tree.insert(layer_node, tk.END, text=f"  {k}", values=(str(v),))

        # 2. Update Payload Tab
        self.payload_txt.delete("1.0", tk.END)
        if pkt.payload_preview:
            self.payload_txt.insert(tk.END, pkt.payload_preview)
        else:
            self.payload_txt.insert(
                tk.END,
                "[Payload preview disabled by default for privacy and security]\n"
                "Enable 'Enable Payload Preview' in capture controls to view hex/ASCII dumps.",
            )

        # 3. Update Educational Theory Tab
        self.edu_txt.delete("1.0", tk.END)
        explanation = get_protocol_explanation(pkt.protocol)
        theory_content = (
            f"Protocol Analysis: {pkt.protocol}\n"
            f"{'=' * (20 + len(pkt.protocol))}\n\n"
            f"{explanation}\n\n"
            f"Packet Context Breakdown:\n"
            f"------------------------\n"
            f"• Source:        {pkt.src_ip}" + (f":{pkt.src_port}" if pkt.src_port else "") + "\n"
            f"• Destination:   {pkt.dst_ip}" + (f":{pkt.dst_port}" if pkt.dst_port else "") + "\n"
            f"• Protocol Flow: {pkt.protocol_detail or pkt.protocol}\n"
            f"• IP Version:    {pkt.ip_version}\n"
            f"• Packet Size:   {pkt.length} bytes\n"
        )
        if pkt.ttl is not None:
            theory_content += f"• TTL / Hop:     {pkt.ttl} (Prevents infinite looping in routed networks)\n"
        if pkt.tcp_flags:
            theory_content += f"• TCP Flags:     {pkt.tcp_flags}\n"
        if pkt.dns_info:
            theory_content += f"• DNS Info:      {pkt.dns_info}\n"
        if pkt.icmp_info:
            theory_content += f"• ICMP Info:     {pkt.icmp_info}\n"

        theory_content += (
            "\nCyber Security & Ethical Considerations:\n"
            "---------------------------------------\n"
            "• Metadata analysis allows network defenders to detect anomalous traffic flows without invading payload privacy.\n"
            "• Unencrypted protocols (e.g. HTTP, standard DNS) expose communication details to any passive observer on the network.\n"
            "• Modern protocols like HTTPS/TLS safeguard message integrity and secrecy via cryptographic ciphers."
        )
        self.edu_txt.insert(tk.END, theory_content)

    def clear_results(self) -> None:
        """Clear all captured packets and reset UI state."""
        if self.sniffer.is_capturing:
            messagebox.showinfo("Information", "Please stop capture before clearing results.")
            return

        self.captured_packets.clear()
        self.displayed_packet_ids.clear()
        self.tree.delete(*self.tree.get_children())
        self.details_tree.delete(*self.details_tree.get_children())
        self.payload_txt.delete("1.0", tk.END)
        self._set_default_educational_text()
        self.sniffer.reset_stats()
        self._update_live_stats()
        self._update_footer_label()

    def export_csv(self) -> None:
        """Prompt user for destination and export metadata to CSV."""
        if not self.captured_packets:
            messagebox.showinfo("Export CSV", "No captured packets available to export.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")],
            title="Export Captured Packet Metadata to CSV",
            initialfile=f"packets_export_{int(time.time())}.csv",
        )
        if not filename:
            return

        include_payload = self.enable_payload_var.get()
        success, msg = export_to_csv(self.captured_packets, filename, include_payload=include_payload)
        if success:
            messagebox.showinfo("Export Successful", msg)
        else:
            messagebox.showerror("Export Failed", msg)

    def export_json(self) -> None:
        """Prompt user for destination and export metadata to JSON."""
        if not self.captured_packets:
            messagebox.showinfo("Export JSON", "No captured packets available to export.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON File", "*.json"), ("All Files", "*.*")],
            title="Export Captured Packet Metadata to JSON",
            initialfile=f"packets_export_{int(time.time())}.json",
        )
        if not filename:
            return

        include_payload = self.enable_payload_var.get()
        success, msg = export_to_json(self.captured_packets, filename, include_payload=include_payload)
        if success:
            messagebox.showinfo("Export Successful", msg)
        else:
            messagebox.showerror("Export Failed", msg)

    def _show_help_dialog(self) -> None:
        """Display help dialog with manual test steps for internship demonstration."""
        help_text = (
            "CodeAlpha Basic Network Sniffer - User & Testing Guide\n"
            "====================================================\n\n"
            "1. How to Capture Traffic:\n"
            "   • Select your active network adapter (e.g. Wi-Fi) from the dropdown.\n"
            "   • Click 'Start Capture'. Live packets will populate the table.\n"
            "   • Click 'Stop Capture' to pause collection.\n\n"
            "2. How to Generate Test Traffic (Run in PowerShell / CMD):\n"
            "   • ICMP (Ping):   ping 1.1.1.1\n"
            "   • DNS Lookup:    nslookup example.com\n"
            "   • HTTPS Web:     curl.exe https://example.com\n\n"
            "3. Filtering & Analysis:\n"
            "   • Choose a protocol from the dropdown to focus on DNS, TCP, ICMP, etc.\n"
            "   • Click any row in the table to view the 3-tab details panel below.\n\n"
            "4. Exporting Data:\n"
            "   • Use 'Export to CSV' or 'Export to JSON' to save metadata for reports.\n\n"
            "Responsible Use Note: Only monitor networks you own or are authorized to inspect."
        )
        messagebox.showinfo("User & Testing Guide", help_text)

    def _on_close(self) -> None:
        """Clean shutdown handler."""
        if self.sniffer.is_capturing:
            self.sniffer.stop_capture()
        self.root.destroy()


def run_cli_mode(interface_name: Optional[str] = None, count: int = 10, payload: bool = False) -> None:
    """Fallback interactive Command Line Interface for terminal environments."""
    print("=" * 72)
    print("  Basic Network Sniffer (CLI Mode) | CodeAlpha Cybersecurity Task 1")
    print("=" * 72)

    ifaces = InterfaceManager.get_interfaces()
    if not ifaces:
        print("[!] No network interfaces found. Please check Npcap driver.")
        return

    target_iface = None
    if interface_name:
        for ifc in ifaces:
            if interface_name.lower() in ifc["name"].lower():
                target_iface = ifc
                break

    if not target_iface:
        target_iface = InterfaceManager.get_default_interface() or ifaces[0]

    print(f"[*] Selected Interface: {target_iface['display_name']}")
    print(f"[*] Admin Mode:         {InterfaceManager.is_admin()}")
    print(f"[*] Npcap Available:    {InterfaceManager.is_npcap_available()}")
    print(f"[*] Target Packet Count:{count if count > 0 else 'Unlimited (Ctrl+C to stop)'}")
    print(f"[*] Payload Inspection: {'Enabled' if payload else 'Disabled (Default)'}")
    print("-" * 72)
    print(f"{'#':<4} {'Time':<12} {'Protocol':<8} {'Source':<21} {'Destination':<21} {'Len':<5}")
    print("-" * 72)

    captured_list: List[PacketInfo] = []
    sniffer = NetworkSniffer()

    def on_packet(pkt: PacketInfo) -> None:
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
        print(f"{pkt.packet_id:<4} {pkt.timestamp[11:23]:<12} {pkt.protocol:<8} {src:<21} {dst:<21} {pkt.length:<5}")
        captured_list.append(pkt)

    try:
        sniffer.start_capture(
            iface=target_iface["id"],
            packet_limit=count,
            enable_payload=payload,
            on_packet_analyzed=on_packet,
        )

        while sniffer.is_capturing:
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture (User interrupted)...")
        sniffer.stop_capture()

    stats = sniffer.get_stats_snapshot()
    print("-" * 72)
    print(f"[*] Total Packets Captured: {stats['total_packets']}")
    print(f"[*] Protocols: {dict(stats['protocols'])}")
    print(f"[*] Session Duration: {stats['duration_seconds']}s ({stats['packets_per_second']} pkt/s)")

    if captured_list:
        csv_path = f"cli_export_{int(time.time())}.csv"
        success, msg = export_to_csv(captured_list, csv_path, include_payload=payload)
        if success:
            print(f"[*] Automatically exported session metadata to: {csv_path}")


def main() -> None:
    """Application entry point with CLI argument support."""
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer - Task 1")
    parser.add_argument("--cli", action="store_true", help="Launch in interactive terminal CLI mode")
    parser.add_argument("--iface", type=str, default=None, help="Interface name or partial match for CLI mode")
    parser.add_argument("--count", type=int, default=10, help="Packet capture limit in CLI mode (default 10)")
    parser.add_argument("--payload", action="store_true", help="Enable 64-byte payload preview")
    args = parser.parse_args()

    if args.cli:
        run_cli_mode(interface_name=args.iface, count=args.count, payload=args.payload)
        return

    # Attempt GUI launch
    try:
        root = tk.Tk()
        app = SnifferGUI(root)
        root.mainloop()
    except tk.TclError as tcl_err:
        print(f"[!] Tkinter GUI could not be initialized ({tcl_err}).", file=sys.stderr)
        print("[*] Falling back to CLI mode...", file=sys.stderr)
        run_cli_mode(interface_name=args.iface, count=args.count, payload=args.payload)


if __name__ == "__main__":
    main()
