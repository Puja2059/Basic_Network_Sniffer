# Internship Technical Project Report

**Task Title**: Task 1 - Basic Network Sniffer  
**Internship Program**: Cyber Security Internship  
**Organization**: CodeAlpha  
**Domain**: Network Security & Packet Forensics  

---

### Student Information
- **Student Name**: `[Insert Your Name Here]`  
- **College / University**: `[Insert College / University Name Here]`  
- **Degree / Major**: `[e.g., B.Tech in Computer Science / Information Security]`  
- **Internship Period**: `[e.g., October 2026 - November 2026]`  
- **Submission Date**: `[Insert Date of Submission]`  
- **Supervisor / Mentor**: CodeAlpha Cyber Security Technical Team  

---

## 1. Abstract

Network packet sniffing and traffic analysis are foundational competencies in modern cybersecurity, incident response, network monitoring, and defensive operations. This project documents the design, architecture, implementation, and evaluation of **Basic Network Sniffer**, an application developed for **CodeAlpha Cyber Security Internship (Task 1)**.

Built on Python 3, Scapy, Npcap, and Tkinter, the application provides a structured, responsive environment for capturing raw network packets on Windows, dissecting multi-layered protocol headers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and DNS), calculating live network metrics, executing real-time multi-criteria filtering, and exporting forensic session data into standard CSV and JSON formats. The system is designed with strict adherence to defensive and ethical security principles: promiscuous data harvesting and credential extraction are prohibited, payload previews are strictly truncated and disabled by default, and cryptographic TLS sessions are recognized without attempting decryption. The implementation is verified through an automated test suite comprising 27 unit tests and validated via live traffic capture on Windows 11.

---

## 2. Introduction

Every digital communication across local networks and the global internet relies on packetized data transmission governed by layered network architecture models, specifically the OSI 7-Layer Reference Model and the TCP/IP stack. As data travels from sender to receiver, each layer encapsulates the data with specific headers that direct routing, enforce delivery reliability, manage flow control, and identify application endpoints.

In cybersecurity, the ability to observe, capture, and analyze these packets is critical for detecting unauthorized activity, diagnosing network failures, identifying malicious command-and-control communication, and verifying cryptographic posture. The objective of this project is to construct a beginner-friendly yet professionally designed packet sniffer that provides clear insight into these network flows on Windows workstations.

---

## 3. Problem Statement

Many enterprise network analysis utilities, such as Wireshark or tcpdump, while exceptionally powerful, present complex interfaces, overwhelming volumes of raw binary data, and steep learning curves for students and junior security analysts. Furthermore, standard user-space applications often struggle with Windows packet capture nuances due to operating system driver restrictions and thread-blocking issues in graphical environments.

There is a defined need for an educational, reliable, and secure packet inspection tool that:
1. Seamlessly interfaces with Windows packet capture drivers (Npcap) without freezing user interfaces.
2. Dissects key protocol layers into human-readable structures.
3. Provides immediate educational context regarding protocol functions and security significance.
4. Upholds privacy by preventing unintended disclosure of personal data or plaintext payloads.

---

## 4. Project Objectives

The project accomplishes the following technical goals:
- **Packet Ingestion**: Capture live packets from user-selected network adapters on Windows using Scapy and Npcap.
- **Protocol Classification**: Parse and classify packets across Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and HTTPS/TLS.
- **Responsive Architecture**: Decouple packet sniffing from GUI rendering using a multithreaded queue-based producer-consumer pattern.
- **Dynamic Search & Filtering**: Provide non-blocking filtering by protocol, IP address, port number, and full-text metadata search.
- **Forensic Export**: Provide structured CSV and JSON export routines for packet metadata.
- **Verification & Testing**: Validate all core parsing and export logic through automated unit tests with synthetic packets.

---

## 5. Tools and Technologies

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Programming Language** | Python 3.11 / 3.14 | High-level language offering robust networking and data processing libraries. |
| **Packet Engine** | Scapy 2.8.0 | Powerful Python-based packet manipulation, dissection, and crafting framework. |
| **Packet Capture Driver** | Npcap (Windows) | Modern NDIS 6 packet capture driver for Windows supporting raw packet injection and sniffing. |
| **User Interface** | Tkinter / `ttk` | Built-in cross-platform graphical toolkit utilizing styled ttk widgets. |
| **Test Automation** | `pytest` 9.1+ | Unit testing framework for executing automated test suites. |
| **Serialization** | Python `csv` & `json` | Standard-library modules for exporting structured forensic metadata. |

---

## 6. System Design and Workflow

The application follows a modular, decoupled architecture comprising four core components:

```
+-------------------------------------------------------------------------+
|                              USER INTERFACE                             |
|        Tkinter Desktop GUI (SnifferGUI)  /  Terminal CLI Fallback       |
+------------------------------------+------------------------------------+
                                     |
               (Polls Analyzed Packets every 100ms via Queue)
                                     |
+------------------------------------+------------------------------------+
|                         BACKGROUND SNIFFER                              |
|   NetworkSniffer (sniffer.py) - Background Worker Daemon Thread         |
|   - Scapy sniff() loop with 500ms timeout slices                        |
|   - CaptureStats tracker (Packets, Bytes, Protocols, Rates)             |
+------------------------------------+------------------------------------+
                                     |
                (Dissects Raw Packets into Structured Data)
                                     |
+------------------------------------+------------------------------------+
|                          PACKET ANALYZER                                |
|   analyze_packet() (packet_analyzer.py)                                 |
|   - Ethernet, IPv4, IPv6, ARP Dissection                               |
|   - TCP / UDP / ICMP / DNS Layer Parsing                                |
|   - Protocol Classification (DNS, HTTP, HTTPS, TCP, UDP, ICMP)         |
|   - Safeguarded 64-byte Hex/ASCII Payload Truncation                    |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  DATA EXPORT & INTERFACE MANAGEMENT                     |
|   - export_manager.py: CSV and JSON serialization                       |
|   - interface_manager.py: Npcap detection, Adapter discovery, Admin check|
+-------------------------------------------------------------------------+
```

### Operational Workflow:
1. **Discovery**: `InterfaceManager` queries system adapters via Scapy's `conf.ifaces`, resolves friendly names, identifies IP addresses, and checks administrator permissions.
2. **Initialization**: The user selects an adapter and specifies optional capture limits.
3. **Capture Execution**: `NetworkSniffer` spawns a background thread running `sniff()` with non-blocking timeout slices, ensuring immediate responsiveness when the user requests a stop.
4. **Dissection & Queueing**: Raw frames are dissected into `PacketInfo` objects by `analyze_packet()` and pushed into a thread-safe `queue.Queue`.
5. **Rendering & Filtration**: The UI periodically pulls packets from the queue, checks active filter criteria (`matches_filter()`), and updates the Treeview and live statistics cards.
6. **Detailed Inspection**: Selecting a packet renders its full layer breakdown, payload preview, and protocol theory in the lower tabbed notebook.
7. **Export**: Filtered or complete capture sessions are saved to CSV or JSON formats.

---

## 7. Implementation Details

### A. Modular File Structure
- `main.py`: Coordinates the GUI, binds events, manages state, and provides terminal CLI fallback.
- `sniffer.py`: Manages the packet capture lifecycle, thread termination events, and real-time statistics counters.
- `packet_analyzer.py`: Contains the `PacketInfo` data model, Scapy layer dissection logic, TCP flag decoders, DNS query extractors, and filter algorithms.
- `interface_manager.py`: Interrogates Windows network adapters and permissions.
- `export_manager.py`: Formats and writes CSV and JSON metadata files.

### B. Thread-Safe Producer-Consumer Pattern
In graphical applications, blocking calls such as packet sniffing freeze the event loop, causing the OS to report the window as unresponsive. To eliminate this:
- The capture loop operates in a daemon `threading.Thread`.
- Communication between the worker thread and the Tkinter main loop is conducted strictly through a thread-safe `queue.Queue`.
- The GUI utilizes `root.after(100, self._process_packet_queue)` to process up to 50 packets per cycle, ensuring smooth scrolling and interaction even under heavy packet arrival rates.

---

## 8. Network Protocol Explanations

To satisfy the internship requirement of explaining fundamental protocol mechanisms and network data flow:

### 1. IPv4 and IPv6 (Internet Protocol)
- **IPv4**: Layer 3 protocol utilizing 32-bit addresses (e.g., `192.168.1.1`). Key header fields include Time to Live (**TTL**), which decrements at each routing hop to prevent infinite packet loops, and **Protocol ID** (e.g., 6 for TCP, 17 for UDP, 1 for ICMP).
- **IPv6**: Next-generation 128-bit addressing format designed to resolve IPv4 address exhaustion. Replaces TTL with **Hop Limit** and streamlines header complexity for faster routing.

### 2. TCP (Transmission Control Protocol)
- **Characteristics**: Connection-oriented, reliable, byte-stream protocol.
- **3-Way Handshake**:
  1. `Client -> Server`: **SYN** (Synchronize sequence numbers).
  2. `Server -> Client`: **SYN-ACK** (Acknowledge client sequence and synchronize server sequence).
  3. `Client -> Server`: **ACK** (Acknowledge server sequence; connection established).
- **Header Flags**:
  - `SYN` (0x02): Connection initiation.
  - `ACK` (0x10): Acknowledgment field valid.
  - `FIN` (0x01): Clean connection termination.
  - `RST` (0x04): Hard connection reset due to error or closed port.
  - `PSH` (0x08): Push data directly to application without buffer delay.

### 3. UDP (User Datagram Protocol)
- **Characteristics**: Connectionless, lightweight transport protocol.
- **Function**: Transfers datagrams without establishing prior sessions, guaranteeing packet order, or retransmitting lost packets. Used where low latency is prioritized over reliability (e.g., DNS, VoIP, video streaming).

### 4. DNS (Domain Name System)
- **Role**: Application-layer protocol resolving human-readable domain names (e.g., `example.com`) to numeric IP addresses.
- **Transport**: Operates primarily over UDP port 53 for speed, utilizing TCP port 53 for oversized responses (>512 bytes) or zone transfers.
- **Structure**: Contains Question Records (`DNSQR`) specifying query name and record type (`A`, `AAAA`, `MX`, etc.) and Resource Records (`DNSRR`) returning resolved IP addresses.

### 5. ICMP (Internet Control Message Protocol)
- **Role**: Network-layer diagnostic and error-reporting protocol.
- **Common Types**:
  - `Type 8, Code 0`: Echo Request (Ping).
  - `Type 0, Code 0`: Echo Reply (Ping response).
  - `Type 3`: Destination Unreachable.
  - `Type 11`: Time Exceeded (TTL expired in transit; utilized by `traceroute`).

### 6. Transport Ports and Endpoints
- Ports are 16-bit integers (0 to 65535) identifying specific software processes on a host:
  - **Well-Known Ports** (0–1023): HTTP (80), HTTPS (443), DNS (53), SSH (22), DHCP (67/68).
  - **Registered Ports** (1024–49151): Database services, proprietary protocols.
  - **Dynamic / Ephemeral Ports** (49152–65535): Allocated dynamically by operating systems as source ports for outbound client connections.

### 7. Packet Length and Payloads
- **Length**: Total frame or IP packet size in bytes. Network interfaces enforce a Maximum Transmission Unit (**MTU**), typically 1500 bytes for standard Ethernet.
- **Payload**: The actual data conveyed above the transport headers. In defensive packet sniffing, payload inspection must be handled with care to prevent unauthorized exposure of passwords, tokens, or personal messages.

---

## 9. Testing Methodology

The testing strategy combined automated unit testing with live environmental validation:

### A. Automated Unit Testing
- Implemented in `tests/` using `pytest`.
- Employs **synthetic Scapy packets** created entirely in memory.
- Completely decoupled from physical hardware, network access, or Windows driver privileges.
- Validates 27 distinct assertions across header parsing, missing attributes, export serialization, and filter combinations.

### B. Live Functional Testing
- Performed on a Windows 11 host with an active Wi-Fi adapter.
- Verified capture of real packets generated by built-in system tools:
  - `ping 1.1.1.1` (ICMP validation).
  - `nslookup example.com` (DNS query/answer validation).
  - `curl.exe https://example.com` (TCP handshake and HTTPS TLS session validation).

---

## 10. Results and Observations

### A. Automated Test Execution Results
Execution of the test suite yielded a 100% pass rate:
```
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.6.0
collected 27 items

tests/test_export_manager.py::TestExportManager::test_csv_export_default_headers_and_values PASSED
tests/test_export_manager.py::TestExportManager::test_csv_export_with_payload_option PASSED
tests/test_export_manager.py::TestExportManager::test_json_export_structure PASSED
tests/test_export_manager.py::TestExportManager::test_export_invalid_path_error_handling PASSED
tests/test_filters.py::TestPacketFilters::test_filter_all_protocol PASSED
tests/test_filters.py::TestPacketFilters::test_filter_specific_protocols PASSED
tests/test_filters.py::TestPacketFilters::test_filter_by_ip_partial_and_exact PASSED
tests/test_filters.py::TestPacketFilters::test_filter_by_port PASSED
tests/test_filters.py::TestPacketFilters::test_combined_filters PASSED
tests/test_filters.py::TestPacketFilters::test_text_search_query PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_ipv4_tcp_packet_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_ipv4_udp_packet_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_ipv4_icmp_packet_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_ipv6_packet_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_dns_query_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_dns_response_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_https_tls_classification PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_arp_packet_parsing PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_payload_preview_security_defaults PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_malformed_and_empty_packet_handling PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_filtering_logic PASSED
tests/test_packet_analyzer.py::TestPacketAnalyzer::test_protocol_explanations PASSED
tests/test_sniffer.py::TestCaptureStats::test_stats_initialization PASSED
tests/test_sniffer.py::TestCaptureStats::test_stats_aggregation_and_reset PASSED
tests/test_sniffer.py::TestNetworkSnifferMock::test_sniffer_init PASSED
tests/test_sniffer.py::TestNetworkSnifferMock::test_packet_handler_mock_dispatch PASSED
tests/test_sniffer.py::TestNetworkSnifferMock::test_start_and_stop_state_transitions PASSED

============================= 27 passed in 0.51s ==============================
```

### B. Live Execution Observations
- **Interface Enumeration**: Successfully identified 10 local network devices, prioritizing active Wi-Fi (`10.237.217.151`) matching Scapy's default route.
- **Throughput & Responsiveness**: Average packet ingestion rate sustained between 5 and 30 packets per second with negligible UI latency.
- **Protocol Distribution**: `[Insert personal capture summary observations here, e.g., 65% HTTPS, 20% TCP ACK, 10% DNS, 5% ICMP]`.
- **Export Integrity**: Exported CSV and JSON files opened cleanly in Microsoft Excel and text editors without formatting or encoding errors.

---

## 11. Limitations

1. **Encrypted Payloads**: The application correctly classifies HTTPS/TLS traffic but cannot decrypt ciphertext payloads, which is standard for non-intrusive network sniffers.
2. **High-Speed Saturation**: As a Python application, capturing at gigabit line rates (1 Gbps+) without hardware filtering or C-level packet ring buffers will eventually lead to dropped frames.
3. **Windows Driver Dependency**: Raw packet sniffing on Windows relies on the Npcap kernel driver; systems lacking Npcap will fail to capture physical adapter frames.
4. **Non-Promiscuous Mode**: By default, modern switched Wi-Fi networks only deliver unicast traffic addressed to the local machine's MAC address plus broadcast/multicast packets.

---

## 12. Security and Ethical Considerations

The design and usage of network sniffing technology demand strict adherence to legal and ethical standards:

- **Authorization Principle**: Packet sniffing must never be executed on unauthorized networks, corporate Wi-Fi, university networks, or third-party infrastructure without explicit written permission from network owners.
- **Defense vs. Offense**: This application is strictly an analysis tool. It includes no features for packet forging, ARP spoofing, session injection, or Denial of Service (DoS).
- **Privacy Protections**: Payloads are masked by default to protect confidentiality. When enabled, previews are truncated to 64 bytes to permit header diagnostic inspection while limiting exposure of private communication data.
- **Compliance**: Adheres to standard cybersecurity codes of ethics (e.g., ACM Code of Ethics and (ISC)² Code of Professional Ethics).

---

## 13. Conclusion

The **Basic Network Sniffer** successfully fulfills all objectives set forth in Task 1 of the CodeAlpha Cyber Security Internship. The application delivers a reliable, multithreaded network sniffer tailored for Windows environments, featuring an intuitive graphical user interface, comprehensive protocol classification, multi-criteria filtering, and metadata export capabilities.

Through rigorous automated unit testing and real-world network traffic capture, the project demonstrates an end-to-end understanding of TCP/IP communication, socket drivers, threading models, and defensive cybersecurity principles.

---

## 14. Future Enhancements

Potential extensions for future iterations include:
1. **PCAP File Ingestion & Replay**: Ability to load and inspect offline `.pcap` files recorded from Wireshark.
2. **BPF (Berkeley Packet Filter) Expression Builder**: A graphical visual builder for creating custom BPF syntax (e.g. `tcp port 80 and not host 10.0.0.1`).
3. **GeoIP Host Resolution**: Offline integration with MaxMind GeoLite2 databases to display the geographic country and ASN of remote IP addresses.
4. **Anomaly Alerting**: Basic heuristic threshold rules to flag potential SYN floods, abnormal port scans, or DNS tunneling patterns.

---

## 15. References

1. **Python Software Foundation**. (2026). *The Python Standard Library Documentation*. Retrieved from [https://docs.python.org/3/](https://docs.python.org/3/)
2. **Biondi, P., & Scapy Contributors**. (2026). *Scapy: Interactive Packet Manipulation Program and Library*. Retrieved from [https://scapy.net/](https://scapy.net/)
3. **Insecure.Com LLC / Nmap Project**. (2026). *Npcap: Windows Packet Capture Library & Driver*. Retrieved from [https://npcap.com/](https://npcap.com/)
4. **Postel, J. (RFC Editor)**. (1981). *RFC 793: Transmission Control Protocol (TCP)*. Internet Engineering Task Force (IETF).
5. **Postel, J. (RFC Editor)**. (1980). *RFC 768: User Datagram Protocol (UDP)*. Internet Engineering Task Force (IETF).
6. **Mockapetris, P. (RFC Editor)**. (1987). *RFC 1035: Domain Names - Implementation and Specification*. Internet Engineering Task Force (IETF).
7. **CodeAlpha**. (2026). *Cyber Security Internship Guidelines & Task Syllabus*. Retrieved from [https://codealpha.tech/](https://codealpha.tech/)
