# Network Packet Sniffer & Protocol Analyzer

A Python-based network packet sniffer and protocol analyzer built with **Scapy and Tkinter**. Capture live network traffic, inspect packet headers across multiple OSI layers, filter protocols, explore security-related protocol information, and export packet metadata to CSV or JSON.

**Project:** Basic Network Sniffer
**Category:** Cybersecurity | Network Security | Network Monitoring
**Status:** Educational Portfolio Project

---

## Overview

Network packet analysis is an important skill in network troubleshooting, Security Operations Center (SOC) monitoring, incident response, and defensive cybersecurity.

This project provides a graphical interface for capturing and analyzing network packets in real time. It allows users to inspect protocol headers, examine transport-layer information, filter captured traffic, view protocol-specific security notes, and export packet metadata for further analysis.

The application is designed to strengthen practical understanding of the OSI model, TCP/IP networking, packet capture, and network monitoring.

## Key Features

* **Real-Time Packet Capture:** Capture network traffic using Scapy.
* **Multi-Layer Packet Analysis:** Inspect Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ARP information.
* **Protocol Classification:** Identify and classify common protocols, including DNS, HTTP, and HTTPS/TLS.
* **Packet Filtering:** Filter captured traffic by protocol, IP address, port, and searchable packet metadata.
* **Protocol Analysis & Security Notes:** Display educational explanations and security context for analyzed protocols.
* **Live Statistics:** Monitor packet counts and protocol statistics during capture.
* **Threaded Processing:** Use a background capture thread and thread-safe queue to keep the GUI responsive.
* **Data Export:** Export packet metadata to CSV and JSON.
* **Payload Privacy:** Payload inspection is disabled by default.
* **Graphical Interface:** Interact with captured traffic through a Tkinter desktop application.
* **CLI Support:** Run packet capture from the command line.
* **Automated Testing:** Validate core functionality using Pytest and synthetic Scapy packets.

---

## Screenshots

### 1. Live Capture Dashboard & Real-Time Traffic

![Live Capture Dashboard](screenshots/live-capture-dashboard.jpg)

The dashboard displays live network traffic alongside protocol statistics. This example shows 122 captured packets, including HTTPS, QUIC, and DNS traffic.

**Demonstrates:**

* Live packet table
* Real-time protocol counters
* Capture session statistics
* Packet selection and inspection

### 2. Layer 2 & Layer 3 Packet Dissection

![Layer 2 and Layer 3 Packet Dissection](screenshots/layer2-layer3-dissection.jpg)

Inspect Ethernet and IPv4 headers to understand how packets are structured at the data-link and network layers.

**Demonstrates:**

* Ethernet source and destination MAC addresses
* EtherType
* IPv4 header length
* Total packet length
* Identification field and IP flags

### 3. Layer 4 Transport Dissection — UDP/DNS

![Layer 4 UDP DNS Dissection](screenshots/layer4-udp-dns-dissection.jpg)

Explore UDP transport headers associated with DNS traffic.

**Demonstrates:**

* IPv4 protocol identifier for UDP
* UDP source and destination ports
* UDP length
* UDP checksum
* Relationship between network, transport, and application protocols

### 4. Protocol Filtering in Action

![Protocol Filtering](screenshots/protocol-filtering.jpg)

Filter the captured packet buffer to focus on DNS traffic instead of reviewing the entire capture session.

**Demonstrates:**

* Protocol selection
* DNS packet isolation
* Easier inspection of relevant network traffic

### 5. Protocol Intelligence & Security Context

![Protocol Analysis and Security Notes](screenshots/protocol-analysis-security-notes.jpg)

The Protocol Analysis & Security Notes section provides educational explanations of observed protocol behavior. This example shows DNS query information and security context for an observed domain.

**Demonstrates:**

* DNS query information
* Protocol-specific analysis
* Educational security explanations
* Practical connection between packet inspection and network-security concepts

### 6. Automated Testing — 27 Tests Passing

![Automated Tests](screenshots/automated-tests-27-passing.png)

The project includes an automated Pytest suite that uses synthetic Scapy packets to validate core functionality without relying entirely on unpredictable live network traffic.

**Demonstrates:**

* Automated packet-analysis tests
* Protocol-handling verification
* Filtering and export testing
* Repeatable validation of core components

---

## Supported Protocols

| Network Layer / Category        | Protocols or Features      |
| ------------------------------- | -------------------------- |
| Data Link — Layer 2             | Ethernet                   |
| Network — Layer 3               | IPv4, IPv6, ARP, ICMP      |
| Transport — Layer 4             | TCP, UDP                   |
| Application / Protocol Analysis | DNS, HTTP, HTTPS/TLS, DHCP |
| Data Export                     | CSV, JSON                  |

**Note:** Supported protocol analysis does not mean every protocol will appear in every live capture. Actual traffic depends on network activity, the selected interface, and the protocol characteristics available for analysis.

---

## How It Works

The application follows a modular packet-processing workflow:

1. **Network Interface Selection:** Detect and select an available network adapter.
2. **Packet Capture:** Scapy captures packets from the selected interface.
3. **Background Processing:** A capture thread receives packets independently of the graphical interface.
4. **Thread-Safe Queue:** Captured packets are passed to the application for processing.
5. **Packet Analysis:** The analyzer extracts packet headers, classifies protocols, and prepares packet details.
6. **GUI Display:** The Tkinter interface displays captured packets, statistics, filtering options, and detailed protocol information.
7. **Export:** Packet metadata can be exported to CSV or JSON.

### Architecture

```text
Network Interface
       |
       v
Scapy Packet Capture
       |
       v
Background Capture Thread
       |
       v
Thread-Safe Packet Queue
       |
       v
Packet Analyzer
       |
       +---- Ethernet
       +---- IPv4 / IPv6
       +---- TCP / UDP
       +---- ICMP / ARP
       +---- DNS / HTTP / HTTPS-TLS
       |
       v
Tkinter GUI
       |
       +---- Live Packet Table
       +---- Packet Details
       +---- Protocol Analysis
       +---- Filtering and Statistics
       |
       v
CSV / JSON Export
```

### Why Threading Is Used

Packet capture runs in a background thread while captured packets are passed through a thread-safe queue. This separates packet collection from GUI updates and helps prevent the Tkinter interface from becoming unresponsive during capture.

---

## Technology Stack

| Technology    | Purpose                                    |
| ------------- | ------------------------------------------ |
| Python        | Core application logic                     |
| Scapy         | Packet capture and packet-layer inspection |
| Tkinter / ttk | Graphical user interface                   |
| Pytest        | Automated testing                          |
| Npcap         | Windows packet-capture support             |
| CSV / JSON    | Structured packet metadata export          |

---

## Installation

### Prerequisites

* Windows 10 or Windows 11
* Python installed and available through the terminal
* Npcap for live packet capture on Windows
* Administrator privileges when required by the capture environment

### 1. Clone the Repository

```powershell
git clone https://github.com/Puja2059/Basic_Network_Sniffer.git
cd Basic_Network_Sniffer
```

### 2. Create a Virtual Environment

```powershell
python -m venv .venv
```

Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can temporarily allow script execution in the current terminal:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

Then activate the environment again.

### 3. Install Dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Install Npcap

Install Npcap from the official website:

https://npcap.com/

Follow the installer instructions. Administrator privileges may be necessary to capture traffic from certain interfaces.

---

## Running the Application

### Graphical Interface

Launch the application from the project directory:

```powershell
python main.py
```

The GUI allows you to select a network interface, configure capture settings, start and stop capture, inspect packet headers, filter traffic, and export results.

### Command-Line Interface

Capture 10 packets:

```powershell
python main.py --cli --count 10
```

Capture packets from a specific interface:

```powershell
python main.py --cli --iface Wi-Fi --count 5
```

Enable payload preview for a limited capture:

```powershell
python main.py --cli --iface Wi-Fi --count 5 --payload
```

Use the interface name detected on your system. Available interface names can vary by computer and network configuration.

---

## Using the Application

### 1. Select a Network Interface

Choose the active Wi-Fi, Ethernet, or other supported interface from the available adapters.

### 2. Start Packet Capture

Start the capture session and observe packets as they arrive. The interface displays packet information and live statistics.

### 3. Inspect Packet Headers

Select a packet to view its available protocol layers and header fields, including Ethernet, IPv4/IPv6, TCP, UDP, and other supported protocols.

### 4. Analyze Protocol Information

Open the Protocol Analysis & Security Notes section to explore protocol-specific information and educational security context.

### 5. Filter Captured Traffic

Use the available filters to isolate relevant packets by protocol, IP address, port, or searchable metadata.

Examples of traffic worth inspecting include:

* DNS traffic on port 53
* HTTPS connections commonly using port 443
* HTTP traffic commonly using port 80
* ICMP packets generated during authorized connectivity tests

Port numbers are useful indicators but do not independently guarantee protocol identity.

### 6. Export Packet Metadata

Export captured packet information to CSV or JSON for later review or programmatic processing.

---

## Testing

The project has **27 automated Pytest tests passing** in the current verified test run.

Run the test suite from the repository root:

```powershell
python -m pytest tests/ -v
```

The tests use synthetic Scapy packets to verify core functionality without depending on live network traffic.

Test coverage includes packet analysis, protocol handling, filtering, capture-related behavior, statistics, and export functionality.

> The passing result refers to the current verified test run. Re-run the suite after making code changes to confirm that the tests still pass.

---

## Privacy & Security

Network packet captures may contain sensitive information. This project follows a metadata-focused approach for normal operation.

* Payload inspection is disabled by default.
* Payload inspection requires explicit user action.
* Packet headers and metadata are used for basic analysis.
* Captured traffic may contain IP addresses, MAC addresses, domain names, and other potentially sensitive information.
* Exported files should be handled and stored securely.

### HTTPS/TLS Considerations

HTTPS/TLS traffic is generally encrypted at the application-data level. This tool can inspect available packet headers and classify traffic based on available characteristics, but it does not decrypt HTTPS/TLS application data.

### Responsible Use

Use the application only on networks you own, systems you control, or environments where you have explicit authorization to monitor traffic.

---

## Limitations

This project is an educational packet analyzer and is not intended to replace a full network-forensics or enterprise-monitoring platform.

Current limitations include:

* Live capture may require elevated privileges.
* Windows packet capture depends on a compatible capture driver such as Npcap.
* HTTPS/TLS application data remains encrypted.
* Protocol classification may rely on port numbers and packet characteristics.
* The protocols visible in a capture depend on actual network activity.
* The application does not provide all the advanced analysis capabilities available in tools such as Wireshark.

---

## Learning Outcomes

This project provided practical experience with:

* OSI and TCP/IP networking concepts
* Ethernet, IPv4, and IPv6 packet structures
* TCP and UDP header analysis
* DNS, HTTP, and HTTPS/TLS traffic classification
* ARP and ICMP analysis
* Packet capture using Scapy
* Threaded processing and thread-safe queues
* GUI development with Tkinter
* Network traffic filtering
* CSV and JSON data export
* Automated testing with Pytest
* Privacy-conscious packet handling

These concepts are relevant to network troubleshooting, defensive cybersecurity, SOC monitoring, and incident-response fundamentals.

---

## Future Improvements

Potential improvements include:

* PCAP file import and export
* Additional protocol dissectors
* More advanced packet-search options
* Enhanced traffic visualization
* Improved capture-session management
* Expanded automated test coverage
* Additional security-oriented packet analysis

---

## Author

**Puja Bhatt**

Computer Engineering | Cybersecurity & Network Security

GitHub: https://github.com/Puja2059

Project Repository: https://github.com/Puja2059/Basic_Network_Sniffer

---

## Disclaimer

This project is intended for educational, defensive, and authorized network-monitoring purposes only. Do not capture or inspect network traffic without appropriate authorization.

---

## License

Refer to the repository's license file, if present, for the applicable terms of use.
