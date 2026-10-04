# LinkedIn Video Demonstration Script & Post Guide

**Project**: Basic Network Sniffer  
**Task**: CodeAlpha Cyber Security Internship (Task 1)  
**Deliverable**: 60–90 Second Video Demonstration Script & Professional Caption  

---

## Part 1: 60–90 Second Video Demonstration Script

### Video Preparation Checklist:
- Launch the application: `.\.venv\Scripts\python.exe main.py`
- Open a second terminal window (PowerShell) on the side to run test commands (`ping`, `nslookup`, `curl`).
- Use screen recording software (e.g. OBS Studio, Windows Game Bar `Win + G`, or Loom).

---

### Timing & Storyboard Sequence

#### [00:00 - 00:15] — Introduction & Project Context
- **Screen View**: Show the application GUI on screen. The interface dropdown shows your active adapter (`Wi-Fi`), status says `Ready`.
- **Spoken Script**:
  > *"Hello everyone! I am excited to showcase my project for Task 1 of the CodeAlpha Cyber Security Internship: a custom **Basic Network Sniffer and Protocol Analyzer** built in Python with Scapy and Tkinter. This tool captures live network traffic on Windows, inspects low-level protocol headers, and helps us analyze network flows from an educational and defensive cybersecurity perspective."*

#### [00:15 - 00:35] — Live Capture & Multi-Protocol Demonstration
- **Action**: Click **`▶ Start Capture`**. The status turns green (`🟢 Capturing traffic...`). In the terminal, run `ping 1.1.1.1 -n 2` and `nslookup example.com`.
- **Screen View**: Rows of packets instantly stream into the table. Real-time statistics counters for Total Packets, TCP, UDP, ICMP, and DNS increment dynamically.
- **Spoken Script**:
  > *"Here, I select my active Wi-Fi adapter and start the capture. Notice that the packet collection runs in a dedicated background worker thread, ensuring the interface remains completely responsive. As I generate ICMP echo requests and DNS domain lookups in the terminal, the sniffer automatically captures, classifies, and updates our live protocol statistics in real-time."*

#### [00:35 - 00:55] — In-Depth Packet Dissection & Privacy Controls
- **Action**: Click **`⏹ Stop Capture`**. Select a DNS packet row in the table, then toggle through the 3 tabs in the lower details panel.
- **Screen View**: Tab 1 displays the tree breakdown (Ethernet, IPv4, UDP, DNS). Tab 2 shows the safe hex payload preview. Tab 3 shows the educational protocol theory.
- **Spoken Script**:
  > *"When we select any packet, the bottom panel provides an in-depth breakdown of each layer. Under Layer 3, we observe source and destination IPs alongside TTL values that prevent routing loops. Under Layer 4, we see transport ports and TCP flags. We also include an educational protocol theory tab explaining the handshake and security significance. For privacy, payload inspection is restricted to a safe 64-byte hexadecimal preview and disabled by default."*

#### [00:55 - 01:15] — Dynamic Filtering, Forensic Export & Conclusion
- **Action**: Choose `DNS` in the protocol dropdown, search for `example.com`, then click **`💾 Export to CSV`**.
- **Screen View**: Table filters instantly to show only matching DNS packets. The file dialog opens, and a confirmation shows successful CSV export.
- **Spoken Script**:
  > *"We can filter packets dynamically by protocol, IP address, port, or text query without interrupting ongoing capture. Finally, we can export our entire capture session into a structured CSV or JSON spreadsheet for digital forensics or incident reports. All 27 core routines are verified with automated unit tests. Thank you to CodeAlpha for this fantastic learning opportunity!"*

---

## Part 2: Ready-to-Post LinkedIn Caption

Copy and customize the caption below when publishing your project on LinkedIn:

```text
🚀 Excited to share my latest project as part of the CodeAlpha Cyber Security Internship!

For Task 1, I developed a desktop "Basic Network Sniffer & Protocol Analyzer" using Python, Scapy, Npcap, and Tkinter.

Understanding how data traverses local networks and the internet is a fundamental skill in cyber defense. This project was designed to demystify network traffic flows and provide clear, real-time packet inspection on Windows workstations.

🔑 Key Features:
✅ Multithreaded Live Packet Capture: Background worker threads prevent GUI lag during intensive traffic.
✅ Protocol Classification: Dissects Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS/HTTPS traffic.
✅ Deep Layer Inspection: Examines MAC addresses, IP headers, TTL/Hop Limits, TCP handshake flags (SYN, ACK, FIN, RST), and DNS query/answer records.
✅ Real-Time Filtering & Statistics: Dynamic filtering by protocol, IP, port, and full-text search with live packet rate counters.
✅ Forensic Metadata Export: One-click export to CSV and JSON for forensic reporting.
✅ Security by Design: Masked payloads by default, truncated 64-byte hex previews, and strict adherence to authorized monitoring ethics.
✅ 100% Test Coverage: 27 automated unit tests covering packet parsing, filters, and exports using synthetic Scapy packets.

Special thanks to the mentors at CodeAlpha for providing this hands-on cybersecurity challenge!

🔗 GitHub Repository: [Insert Your GitHub Repository URL Here]

#CodeAlpha #CyberSecurity #Python #Networking #InformationSecurity #PacketAnalysis #Scapy #NetworkSecurity #Internship #TechProjects #CyberDefense
```

---

## Part 3: Recommended LinkedIn Hashtags

- `#CodeAlpha`
- `#CyberSecurity`
- `#NetworkSecurity`
- `#Python`
- `#PacketAnalysis`
- `#Scapy`
- `#InformationSecurity`
- `#CyberSecurityIntern`
- `#TechCommunity`
- `#StudentInTech`
