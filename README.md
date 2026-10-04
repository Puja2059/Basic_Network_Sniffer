# CodeAlpha Basic Network Sniffer (Task 1)

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/packet--engine-Scapy-red.svg)](https://scapy.net/)
[![Driver](https://img.shields.io/badge/driver-Npcap-green.svg)](https://npcap.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Internship](https://img.shields.io/badge/CodeAlpha-Cyber%20Security%20Task%201-orange.svg)](https://codealpha.tech/)

A professional, beginner-friendly desktop network packet sniffer and protocol analyzer built in Python. Designed and implemented for **CodeAlpha Cyber Security Internship - Task 1**, this tool captures live network packets on Windows, dissects packet headers across the OSI stack, classifies application protocols, enables multi-criteria filtering, and exports forensic metadata to CSV and JSON formats.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Internship Context](#internship-context)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Architecture & Structure](#project-architecture--structure)
- [Installation & Windows Environment Setup](#installation--windows-environment-setup)
- [Npcap Driver Installation](#npcap-driver-installation)
- [How to Run the Application](#how-to-run-the-application)
- [Application Usage Guide](#application-usage-guide)
- [Testing Instructions (Automated & Manual)](#testing-instructions-automated--manual)
- [Sample Output & Forensic Artifacts](#sample-output--forensic-artifacts)
- [Troubleshooting Windows Capture Errors](#troubleshooting-windows-capture-errors)
- [Security, Ethics & Responsible Disclosure](#security-ethics--responsible-disclosure)
- [Verification Status](#verification-status)

---

## Project Overview

Understanding how data traverses local networks and the internet is a cornerstone skill in cyber security, incident response, and network defense. The **Basic Network Sniffer** provides a clear, interactive visual window into live network traffic on Windows 10 and 11 computers.

The application captures frames from local network adapters (such as Wi-Fi, Ethernet, and Loopback), dissects protocols from Layer 2 (Ethernet) through Layer 7 (Application), computes live session statistics, and presents findings in an intuitive dual-pane dashboard with detailed layer trees, educational protocol summaries, and privacy-conscious payload previews.

---

## Internship Context

- **Organization**: [CodeAlpha](https://codealpha.tech/)
- **Domain**: Cyber Security Internship
- **Assignment**: Task 1 - Basic Network Sniffer
- **Core Requirements Satisfied**:
  - [x] Build a Python program to capture network traffic packets.
  - [x] Analyze captured packets to understand structure and content.
  - [x] Demonstrate how data flows through a network and explain basic protocols.
  - [x] Use Scapy or Python socket libraries for packet capture.
  - [x] Display source IP, destination IP, protocols, ports, packet length, and limited payload preview.

---

## Key Features

1. **Multithreaded Live Packet Capture**:
   - Background capture thread prevents GUI freezing or lag.
   - User-selectable network interfaces (Wi-Fi, Ethernet, Loopback, Virtual adapters).
   - Configurable packet limits (capture a fixed count or run continuously).
   - Clean, instant start/stop controls.

2. **In-Depth Protocol Classification & Header Dissection**:
   - **Layer 2 (Data Link)**: Source MAC, Destination MAC, EtherType.
   - **Layer 3 (Network)**: IPv4 & IPv6 addresses, TTL / Hop Limit, TOS, Packet Length, IP Identification, IP Flags, ARP resolution.
   - **Layer 4 (Transport)**: TCP (Source/Destination Ports, Sequence/Ack numbers, Data Offset, Flags like SYN/ACK/FIN/RST/PSH), UDP datagrams, ICMP control messages (Ping Echo Request/Reply, Unreachable).
   - **Layer 7 (Application)**: DNS queries and answers (resolving hostnames and A records), HTTP plaintext web traffic, HTTPS / TLS encrypted sessions over TCP 443, DHCP configurations.

3. **Multi-Criteria Filtering & Real-Time Statistics**:
   - Protocol filter dropdown (`ALL`, `TCP`, `UDP`, `ICMP`, `DNS`, `HTTPS`, `HTTP`, `ARP`, `OTHER`).
   - Source/Destination IP address filtering (supports partial or exact IP matches).
   - Port filtering (matching source or destination ports).
   - Full-text search across all packet metadata and DNS query names.
   - Live counters for total packets, packets per second (rate), and individual protocol tallies.

4. **Forensic Metadata Export**:
   - One-click export to standard **CSV** spreadsheets with comprehensive column headers.
   - Structured **JSON** export containing session metadata and dissected packet structures.
   - Missing fields and non-IP packets handled gracefully (`N/A`).

5. **Educational & Defensive Security Integration**:
   - Built-in **Protocol Analysis** tab providing explanations of TCP handshakes, DNS resolution, and TTL routing mechanics.
   - Payload preview strictly disabled by default to protect user privacy and sensitive data.
   - Configurable 64-byte hexadecimal and printable ASCII dump when payload preview is explicitly enabled.
   - Terminal CLI fallback mode (`--cli`) for headless or lightweight command-line usage.

---

## Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.11 / 3.12 / 3.14 | Core application logic and data modeling |
| **Packet Engine** | Scapy 2.8.0 | Network packet capture, decoding, and crafting |
| **Capture Driver** | Npcap (Windows) | Kernel-level raw packet access on Windows |
| **GUI Framework** | Tkinter & `ttk` | Modern, responsive graphical user interface |
| **Testing** | `pytest` 9.1+ | Automated unit tests with synthetic packets |
| **Data Export** | Standard `csv` & `json` | Structured metadata serialization |

---

## Project Architecture & Structure

```
CodeAlpha_BasicNetworkSniffer/
│
├── main.py                     # Primary GUI application & CLI fallback entry point
├── sniffer.py                  # Threaded packet capture manager & statistics tracker
├── packet_analyzer.py          # Header parser, protocol classification & filtering engine
├── interface_manager.py        # Network adapter discovery & permission inspector
├── export_manager.py           # CSV and JSON forensic export routines
├── requirements.txt            # Project dependencies (Scapy, pytest)
├── README.md                   # Complete documentation and setup manual
├── report.md                   # Comprehensive academic internship report
├── linkedin_demo_script.md     # 60-90 second video presentation script & post caption
├── .gitignore                  # Excludes venv, pycache, captures, logs, exports
│
├── tests/                      # Automated unit test suite (27 tests)
│   ├── test_packet_analyzer.py # Synthetic packet parsing (IPv4, IPv6, TCP, UDP, DNS, ICMP)
│   ├── test_export_manager.py  # CSV / JSON export validation & error handling
│   ├── test_sniffer.py         # CaptureStats, thread safety, and dispatch logic
│   └── test_filters.py         # Multi-criteria filtering and text search
│
└── screenshots/                # Application execution captures & visual guide
    └── README.md               # Screenshot capture checklist and placement guide
```

---

## Installation & Windows Environment Setup

### 1. Prerequisites
- A Windows 10 or Windows 11 computer.
- Python 3.11 or newer installed (ensure **"Add Python to PATH"** was checked during installation).
- Npcap driver installed (see instructions below).

### 2. Open PowerShell or Terminal
Open Windows PowerShell (Run as Administrator is recommended for live packet capture) and navigate to the project directory:

```powershell
cd c:\Users\asus\Documents\BasicNetworkSniffer
```

### 3. Create and Activate Virtual Environment
```powershell
# Create virtual environment named .venv
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

> **Note regarding PowerShell Execution Policy**: If script execution is blocked on your system, enable it for your current user session by running:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
> ```

### 4. Install Dependencies
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 5. Verify Installation
```powershell
.\.venv\Scripts\python.exe -c "import scapy, tkinter, pytest; print('Environment ready!')"
```

---

## Npcap Driver Installation

On Windows, raw packet sniffing requires the **Npcap** packet capture driver.

1. Download the official Npcap installer from [https://npcap.com/#download](https://npcap.com/#download).
2. Run the installer (`npcap-x.x.x.exe`) with Administrator rights.
3. During installation, select:
   - **"Install Npcap in WinPcap API-compatible Mode"** (Recommended for Scapy compatibility).
   - **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"** (Optional).
4. Complete the wizard and restart your computer if prompted.

---

## How to Run the Application

### Option A: Launch the Graphical User Interface (Recommended)
```powershell
.\.venv\Scripts\python.exe main.py
```

### Option B: Launch in Command-Line (CLI) Mode
If you prefer running inside a terminal or testing quickly without opening a window:
```powershell
# Capture 10 packets on default interface (Wi-Fi)
.\.venv\Scripts\python.exe main.py --cli --count 10

# Capture on a specific interface with 64-byte payload preview
.\.venv\Scripts\python.exe main.py --cli --iface Wi-Fi --count 5 --payload
```

---

## Application Usage Guide

1. **Select Network Adapter**:
   - The application automatically selects your active internet adapter (e.g. `Wi-Fi [10.237.217.151]`).
   - If using a different connection, select it from the dropdown.

2. **Configure Options**:
   - **Packet Limit**: Enter `0` for unlimited capture, or enter a number (e.g., `25`) to automatically stop after 25 packets.
   - **Payload Preview**: Keep unchecked for normal operation (privacy-safe). Check to view the first 64 bytes in hex.

3. **Start & Stop Capture**:
   - Click **`▶ Start Capture`** (turns green). The table immediately begins populating with live network traffic.
   - Click **`⏹ Stop Capture`** at any time to pause collection.

4. **Inspect Packets**:
   - Click on any packet row in the table.
   - **Tab 1 (Layer Breakdown)**: Expand Ethernet, IP, TCP/UDP, and Application layers to view exact field values.
   - **Tab 2 (Payload Preview)**: View safe hex/ASCII representation.
   - **Tab 3 (Protocol Analysis)**: Read educational explanations of the protocol's mechanics and security implications.

5. **Filter Results**:
   - Use the **Protocol** dropdown (e.g., select `DNS` or `ICMP`).
   - Enter an IP in the **IP Address** field to isolate a host.
   - Enter a port number in the **Port** field (e.g. `443` or `53`).
   - Type in the **Search** box to match any query.

6. **Export Data**:
   - Click **`💾 Export to CSV`** to save a spreadsheet report.
   - Click **`📄 Export to JSON`** to generate a structured JSON document.

---

## Testing Instructions (Automated & Manual)

### 1. Automated Unit Tests (Offline / Mocked)
The project includes a comprehensive test suite of **27 automated tests** utilizing synthetic Scapy packets. These tests run completely offline and do not require administrative privileges, live network connections, or physical drivers.

Run all tests via pytest:
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

**Test Coverage Breakdown**:
- `tests/test_packet_analyzer.py` (12 tests): Validates IPv4 TCP parsing, IPv4 UDP datagrams, ICMP Ping packets, IPv6 headers and hop limits, DNS query and answer decoding, HTTPS port-443 classification, ARP frames, empty/malformed packet resilience, and educational guides.
- `tests/test_export_manager.py` (4 tests): Validates CSV header structure, row formatting, JSON data schema, payload toggling, and missing value handling.
- `tests/test_sniffer.py` (5 tests): Validates `CaptureStats` counters, throughput rate calculations, thread safety, and mock packet queue dispatch.
- `tests/test_filters.py` (6 tests): Validates protocol filtering, IP substring matching, port matching, combined multi-filters, and metadata text search.

### 2. Manual Test Checklist (Live Traffic Verification)
To demonstrate the sniffer capturing genuine network traffic, perform the following manual test sequence while the sniffer is running:

| Step | Protocol | Command to Run in PowerShell | Expected Result in Sniffer Table |
| :--- | :--- | :--- | :--- |
| **1** | **ICMP** | `ping 1.1.1.1 -n 2` | ICMP packets with `Echo Request (Ping)` and `Echo Reply` details. |
| **2** | **DNS** | `nslookup example.com` | DNS query for `example.com (A)` over UDP port 53, followed by server response. |
| **3** | **HTTPS** | `curl.exe -I https://example.com` | TCP SYN handshake packets followed by encrypted TLS session over port 443. |
| **4** | **Filter** | Select `DNS` in the GUI | Table isolates only DNS traffic; other packets remain captured in the background. |
| **5** | **Export** | Click `Export to CSV` | Generates a valid `.csv` file viewable in Excel with full metadata. |

---

## Sample Output & Forensic Artifacts

### Synthetic Example Packet Dissection
Below is an example of analyzed packet metadata generated by the packet analyzer:

```
[Packet #1] 2026-10-04 21:50:05.624
• Layer 2: Ethernet (Src: 48:05:13:c1:7f:f7 -> Dst: e4:5f:01:aa:bb:cc, EtherType: 0x0800)
• Layer 3: IPv4 (Src: 10.237.217.151 -> Dst: 172.64.155.209, TTL: 64, Len: 54 bytes)
• Layer 4: TCP (Src Port: 62171 -> Dst Port: 443, Flags: PSH/ACK (0x18), Seq: 12409, Ack: 8492)
• Layer 7: HTTPS / TLS encrypted web session over TCP
• Payload: [Payload preview disabled by default for privacy and security]
```

### Sample CSV Export Output
```csv
Packet #,Timestamp,IP Version,Source IP,Source Port,Destination IP,Destination Port,Protocol,Protocol Detail,Length (Bytes),TTL / Hop Limit,TCP Flags,DNS Query / Info,ICMP Info,Summary
1,2026-10-04 21:50:05.624,IPv4,10.237.217.151,62171,172.64.155.209,443,HTTPS,HTTPS / TLS encrypted session over TCP (Port 443),54,64,PSH/ACK (0x18),N/A,N/A,[HTTPS] 10.237.217.151:62171 -> 172.64.155.209:443
2,2026-10-04 21:50:05.829,IPv4,172.64.155.209,443,10.237.217.151,62171,HTTPS,HTTPS / TLS encrypted session over TCP (Port 443),160,56,ACK (0x10),N/A,N/A,[HTTPS] 172.64.155.209:443 -> 10.237.217.151:62171
```

---

## Troubleshooting Windows Capture Errors

1. **`PermissionError` or "Scapy_Exception: Sniffing requires administrative privileges"**:
   - *Cause*: Windows restricts access to raw sockets and network adapters to elevated security tokens.
   - *Fix*: Close PowerShell or VS Code, right-click the application icon, and choose **"Run as Administrator"**.

2. **`RuntimeError: Sniffing requires Npcap or WinPcap`**:
   - *Cause*: The Npcap packet capture driver is not installed or the Npcap driver service (`npcap.sys`) is stopped.
   - *Fix*: Install Npcap from [https://npcap.com/#download](https://npcap.com/#download) with the WinPcap compatibility box checked. If already installed, run `net start npcap` in an elevated command prompt.

3. **No packets appear when capturing on Wi-Fi**:
   - *Cause*: An incorrect network adapter was selected (e.g. an inactive VirtualBox adapter or Bluetooth connection).
   - *Fix*: Select the adapter showing your active local IP address (e.g. `Wi-Fi [10.237.217.151]`) and generate test traffic using `ping 1.1.1.1`.

4. **Tkinter GUI does not open (Headless or Display Error)**:
   - *Cause*: Running in an environment without an active graphical display.
   - *Fix*: The application will automatically detect this and fall back to CLI mode. You can also explicitly launch terminal mode via `python main.py --cli`.

---

## Security, Ethics & Responsible Disclosure

This tool was developed strictly for academic, defensive, and diagnostic purposes as part of the CodeAlpha Cyber Security Internship.

- **Authorized Monitoring Only**: Users must only capture traffic on networks, hardware, and interfaces they own or have received explicit written authorization to monitor.
- **No Malicious Capabilities**: This project deliberately excludes packet injection, ARP spoofing, session hijacking, credential harvesting, network scanning, and stealth evasion mechanisms.
- **No Cryptographic Bypass**: Encrypted sessions (HTTPS, TLS, SSH) are recognized by their transport metadata; no attempt is made to bypass or decrypt secure communication.
- **Privacy by Default**: Payload extraction is disabled by default. When enabled, previews are truncated to 64 bytes in hexadecimal format to prevent unintended leakage of personal data.

---

## Verification Status

| Feature | Verification Method | Status |
| :--- | :--- | :--- |
| **IPv4 / IPv6 Header Parsing** | Automated (`tests/test_packet_analyzer.py`) | **Verified (Passed)** |
| **TCP / UDP / ICMP / DNS Parsing** | Automated (`tests/test_packet_analyzer.py`) | **Verified (Passed)** |
| **Multi-Criteria Filtering & Search** | Automated (`tests/test_filters.py`) | **Verified (Passed)** |
| **CSV & JSON Metadata Export** | Automated (`tests/test_export_manager.py`) | **Verified (Passed)** |
| **Thread-Safe Capture & Statistics** | Automated (`tests/test_sniffer.py`) | **Verified (Passed)** |
| **Live Wi-Fi Packet Capture on Windows** | Live Environment Execution (`main.py --cli`) | **Verified (Functional)** |
| **Tkinter GUI Render & Interaction** | Headless & Desktop Lifecycle Test | **Verified (Functional)** |
