<img width="1916" height="1002" alt="Live_Capture" src="https://github.com/user-attachments/assets/f1744b6f-fe58-42c8-8e1a-3f9a728bf27a" /># Network Packet Sniffer & Protocol Analyzer

A Python-based desktop network packet sniffer and protocol analyzer built with **Scapy and Tkinter**. The application captures live network traffic, analyzes packet headers across multiple OSI layers, classifies common protocols, provides real-time filtering and statistics, and exports packet metadata to CSV and JSON.

> **Cybersecurity Portfolio Project — Network Monitoring & Packet Analysis**

---

## Overview

Understanding how network traffic moves between systems is a fundamental skill in **network security, SOC operations, incident response, and network troubleshooting**.

This project provides a practical, visual way to inspect live network traffic on Windows. It captures packets from a selected network interface, dissects their protocol headers, displays packet-level information in real time, and provides educational security context for analyzed protocols.

The application is designed as an **educational and defensive network-analysis tool**, not as a replacement for professional tools such as Wireshark.

### What this project demonstrates

* Live packet capture
* OSI-layer packet dissection
* TCP/IP protocol analysis
* DNS and HTTPS/TLS traffic classification
* Network traffic filtering
* Real-time packet statistics
* Threaded packet processing
* CSV/JSON metadata export
* Privacy-conscious payload handling
* Automated testing using synthetic Scapy packets
* Windows network-interface and Npcap integration

---

## Screenshots

### 1. Live Capture Dashboard

![Live Capture Dashboard](live_capture.png)
)

**Real-time network traffic capture**

The dashboard displays live captured traffic together with protocol statistics. This example contains **122 captured packets**, including HTTPS, QUIC, and DNS traffic.

The interface provides:

* Live packet table
* Protocol counters
* Packet count
* Capture controls
* Packet selection
* Detailed packet analysis

---

### 2. Layer 2 & Layer 3 Packet Dissection

![Layer 2 and Layer 3 Packet Dissection](screenshots/Screenshot%202026-10-05%20184048.jpg)

**Ethernet and IPv4 header analysis**

A selected packet can be expanded to inspect individual protocol fields.

The example demonstrates:

* Ethernet source MAC
* Ethernet destination MAC
* EtherType
* IPv4 header length
* Total packet length
* Identification field
* IP flags

This provides visibility into how packet information is structured across the lower network layers.

---

### 3. Layer 4 Transport Dissection — UDP/DNS

![UDP DNS Packet Dissection](screenshots/image_066337.jpg)

**UDP transport-layer analysis**

The selected DNS packet demonstrates the relationship between IPv4 and UDP:

* IPv4 Protocol ID `17`
* UDP source port
* UDP destination port `53`
* UDP length
* UDP checksum

This helps visualize how application protocols such as DNS are transported over UDP.

---

### 4. Protocol Filtering

![Protocol Filtering](screenshots/image_066d99.jpg)

**Real-time packet filtering**

The protocol filter can isolate specific traffic from the captured packet buffer.

In this example, selecting **DNS** isolates the DNS packets from the larger capture session.

Additional filtering options include:

* Protocol
* Source/destination IP
* Port
* Full-text packet metadata search

---

### 5. Protocol Intelligence & Security Context

![Protocol Analysis and Security Notes](screenshots/image_066df9.jpg)

**Protocol analysis and security-oriented explanations**

The application includes a dedicated analysis section that explains the behavior and security relevance of detected protocols.

For example, DNS analysis can display the observed query domain and provide contextual information about DNS resolution and potential security considerations.

This feature is intended to connect **packet-level observations with fundamental network-security concepts**.

---

### 6. Automated Testing

![Automated Tests](screenshots/image_066a3d.png)

**27 automated tests passing**

The project includes a Pytest test suite using synthetic Scapy packets to validate packet parsing, filtering, statistics, export functionality, and protocol handling.

The tests can run without requiring live network capture.

---

## Key Features

### 1. Real-Time Packet Capture

* Captures live traffic using **Scapy**
* Supports selectable network interfaces
* Background capture thread keeps the GUI responsive
* Supports fixed packet counts or continuous capture
* Start/stop capture controls
* Live packet statistics

### 2. Multi-Layer Packet Analysis

The analyzer processes packet information across multiple layers:

**Layer 2 — Data Link**

* Ethernet
* Source MAC
* Destination MAC
* EtherType
* ARP

**Layer 3 — Network**

* IPv4
* IPv6
* Source/destination IP
* TTL / Hop Limit
* TOS
* Packet length
* IP identification
* IP flags
* ICMP

**Layer 4 — Transport**

* TCP
* UDP
* Source/destination ports
* TCP sequence and acknowledgement numbers
* TCP flags
* Data offset
* UDP length and checksum

**Application / Protocol Analysis**

* DNS
* HTTP
* HTTPS/TLS
* DHCP
* Protocol-specific explanations

---

## Supported Protocols

| Layer       | Protocol  | Support |
| ----------- | --------- | ------- |
| Layer 2     | Ethernet  | ✅       |
| Layer 2     | ARP       | ✅       |
| Layer 3     | IPv4      | ✅       |
| Layer 3     | IPv6      | ✅       |
| Layer 3     | ICMP      | ✅       |
| Layer 4     | TCP       | ✅       |
| Layer 4     | UDP       | ✅       |
| Application | DNS       | ✅       |
| Application | HTTP      | ✅       |
| Application | HTTPS/TLS | ✅       |
| Application | DHCP      | ✅       |

> **Note:** Protocol support in the analyzer does not mean every protocol will appear in every live capture. The traffic visible depends on the network activity occurring during the capture session.

---

## Protocol Filtering & Search

Captured traffic can be filtered using multiple criteria.

### Available filters

* Protocol
* IP address
* Port
* Full-text metadata search
* DNS query names

Example protocol filters include:

```text
ALL
TCP
UDP
ICMP
DNS
HTTPS
HTTP
ARP
OTHER
```

Filters operate on the captured packet buffer while packet capture can continue in the background.

---

## Packet Payload Privacy

Payload inspection is **disabled by default**.

This is intentional because captured network traffic may contain sensitive information.

When explicitly enabled, the application can display a limited payload representation including:

* Hexadecimal data
* Printable ASCII
* Up to the configured preview size

The default behavior prioritizes **metadata and protocol analysis over unnecessary payload exposure**.

---

## Architecture

```text
                    Network Interface
                           │
                           ▼
                    Scapy Packet Capture
                           │
                           ▼
                 Background Capture Thread
                           │
                           ▼
                 Thread-Safe Packet Queue
                           │
                           ▼
                    Packet Analyzer
                           │
          ┌────────────────┼────────────────┐
          │                │                │
      Ethernet        IPv4 / IPv6       ARP / ICMP
          │                │                │
          └────────────────┼────────────────┘
                           │
                     TCP / UDP
                           │
                           ▼
                Protocol Classification
                           │
            ┌──────────────┼──────────────┐
            │              │              │
           DNS            HTTP       HTTPS / TLS
            │              │              │
            └──────────────┼──────────────┘
                           │
                           ▼
                     Tkinter GUI
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     Packet Table    Packet Details     Statistics
          │                │                │
          └─
```
