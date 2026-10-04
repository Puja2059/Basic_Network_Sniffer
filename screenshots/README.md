# Application Screenshots Guide

This directory is designated for real execution screenshots of the **CodeAlpha Basic Network Sniffer** application for your internship submission and repository presentation.

## Recommended Screenshots to Capture

1. **`01_main_gui_overview.png`**
   - **What to show**: The initial state of the application after launching. Highlight the title, interface selection dropdown, statistics cards, and packet details panel.
   - **Caption**: *Basic Network Sniffer main dashboard and interface selector on Windows 11.*

2. **`02_active_capture_live_traffic.png`**
   - **What to show**: The sniffer actively capturing packets (`🟢 Capturing traffic...`). Several rows of TCP, UDP, DNS, and HTTPS packets populated in the table, with real-time statistics updating.
   - **Caption**: *Live traffic capture demonstrating multi-protocol network flow.*

3. **`03_packet_inspection_layer_breakdown.png`**
   - **What to show**: A selected DNS or TCP packet with the lower notebook displaying the **Layer Breakdown Tree** (Ethernet, IPv4, TCP/UDP, DNS/HTTP).
   - **Caption**: *In-depth header and field dissection for an inspected network packet.*

4. **`04_filtering_and_search.png`**
   - **What to show**: The table filtered by protocol (e.g., selecting `DNS` or searching for port `53`) while live capture continues.
   - **Caption**: *Dynamic protocol and metadata filtering in action.*

5. **`05_payload_preview_and_security.png`**
   - **What to show**: The **Payload Preview (Hex/ASCII)** tab displaying limited 64-byte hex dump and the ethical security notice.
   - **Caption**: *Safeguarded hexadecimal payload inspection with privacy controls.*

6. **`06_csv_export_verification.png`**
   - **What to show**: The exported `.csv` file opened in Microsoft Excel or VS Code showing structured column headers and packet records.
   - **Caption**: *Exported packet metadata spreadsheet ready for forensic analysis.*

---

## How to Capture High-Quality Screenshots on Windows

- **Shortcut**: Press `Win + Shift + S` to open the Windows Snipping Tool.
- Select the **Window Snip** mode (top icon bar) or click and drag across the application window.
- Save your image files in this `screenshots/` directory using PNG format.
- Replace any placeholders in `README.md` or `report.md` with:
  ```markdown
  ![Live Packet Capture](screenshots/02_active_capture_live_traffic.png)
  ```
