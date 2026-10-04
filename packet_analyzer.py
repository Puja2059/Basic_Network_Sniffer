"""
packet_analyzer.py
==================
Packet analysis engine for CodeAlpha Basic Network Sniffer.
Inspects and parses network packets captured by Scapy into structured,
human-readable metadata while maintaining educational context and
defensive cybersecurity principles.

Author: CodeAlpha Cyber Security Intern
Project: Basic Network Sniffer (Task 1)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import scapy.all as scapy
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR


@dataclass
class PacketInfo:
    """Structured container for analyzed packet metadata."""
    packet_id: int
    timestamp: str
    time_epoch: float
    ip_version: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    protocol_detail: str = ""
    length: int = 0
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    dns_info: Optional[str] = None
    icmp_info: Optional[str] = None
    payload_preview: Optional[str] = None
    summary: str = ""
    layer_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self, include_payload: bool = False) -> Dict[str, Any]:
        """Convert metadata to dictionary for export or serialization."""
        data = {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "ip_version": self.ip_version,
            "src_ip": self.src_ip,
            "src_port": self.src_port if self.src_port is not None else "N/A",
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port if self.dst_port is not None else "N/A",
            "protocol": self.protocol,
            "protocol_detail": self.protocol_detail,
            "length": self.length,
            "ttl": self.ttl if self.ttl is not None else "N/A",
            "tcp_flags": self.tcp_flags if self.tcp_flags else "N/A",
            "dns_info": self.dns_info if self.dns_info else "N/A",
            "icmp_info": self.icmp_info if self.icmp_info else "N/A",
            "summary": self.summary,
        }
        if include_payload and self.payload_preview:
            data["payload_preview"] = self.payload_preview
        return data


# TCP Flags mapping for human-readable breakdown
TCP_FLAG_MAP = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

# Educational protocol guide for students and internship demonstrations
PROTOCOL_EXPLANATIONS = {
    "TCP": (
        "Transmission Control Protocol (TCP): Connection-oriented, reliable transport protocol. "
        "Uses a 3-way handshake (SYN -> SYN-ACK -> ACK) to establish sessions and guarantees "
        "in-order packet delivery using sequence numbers and acknowledgments."
    ),
    "UDP": (
        "User Datagram Protocol (UDP): Connectionless, lightweight transport protocol. "
        "Does not guarantee delivery, order, or error recovery, making it ideal for low-latency "
        "applications like DNS lookups, video streaming, and voice calls."
    ),
    "ICMP": (
        "Internet Control Message Protocol (ICMP): Network layer management protocol used for "
        "diagnostics and error reporting. Common tools include ping (Echo Request Type 8 / Reply Type 0) "
        "and traceroute (TTL Exceeded)."
    ),
    "DNS": (
        "Domain Name System (DNS): Application-layer service resolving human-readable hostnames "
        "(e.g., example.com) to IP addresses. Operates predominantly over UDP port 53 for speed, "
        "falling back to TCP port 53 for zone transfers or oversized responses."
    ),
    "HTTPS": (
        "Hypertext Transfer Protocol Secure (HTTPS): HTTP communication encrypted using TLS/SSL "
        "typically over TCP port 443. Protects confidentiality and integrity of web traffic; "
        "payload contents cannot and should not be decrypted by basic packet sniffers."
    ),
    "HTTP": (
        "Hypertext Transfer Protocol (HTTP): Unencrypted application layer protocol for web content, "
        "conventionally running over TCP port 80. Headers and data are transmitted in plaintext."
    ),
    "ARP": (
        "Address Resolution Protocol (ARP): Layer 2 resolution protocol mapping IP addresses to "
        "hardware MAC addresses on a local Ethernet broadcast domain."
    ),
    "OTHER": (
        "General network traffic that does not fall into standard TCP/UDP/ICMP/DNS classifications. "
        "May include IGMP, multicast, routing protocols, or encapsulated tunneling traffic."
    ),
}


def decode_tcp_flags(flags_val: Any) -> str:
    """Convert TCP flags integer or Scapy FlagValue into readable names."""
    if flags_val is None:
        return "None"
    try:
        val = int(flags_val)
        active = [name for bit, name in TCP_FLAG_MAP.items() if val & bit]
        if active:
            return f"{'/'.join(active)} (0x{val:02X})"
        return f"None (0x{val:02X})"
    except Exception:
        return str(flags_val)


def format_hex_ascii(payload_bytes: bytes, max_bytes: int = 64) -> str:
    """
    Format payload bytes safely as a two-column hex dump and printable ASCII.
    Trims payload to `max_bytes` to prevent memory bloat and protect privacy.
    """
    if not payload_bytes:
        return "Empty Payload"

    data = payload_bytes[:max_bytes]
    lines: List[str] = []
    chunk_size = 16

    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        hex_parts = [f"{b:02X}" for b in chunk]
        hex_str = " ".join(hex_parts).ljust(48)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_str}  |{ascii_str}|")

    if len(payload_bytes) > max_bytes:
        lines.append(f"... ({len(payload_bytes) - max_bytes} bytes omitted for security/performance)")

    return "\n".join(lines)


def parse_dns_layer(packet: Any) -> Optional[str]:
    """Extract query and answer information from a DNS layer safely."""
    try:
        if not packet.haslayer(DNS):
            return None
        dns_layer = packet[DNS]
        parts: List[str] = []

        # Check for DNS Query
        if packet.haslayer(DNSQR):
            qr = packet[DNSQR]
            qname = qr.qname.decode("utf-8", errors="replace") if hasattr(qr.qname, "decode") else str(qr.qname)
            qtype_id = qr.qtype
            qtype_name = scapy.DNS_TYPES.get(qtype_id, str(qtype_id)) if hasattr(scapy, "DNS_TYPES") else str(qtype_id)
            parts.append(f"Query: {qname.rstrip('.')} ({qtype_name})")

        # Check for DNS Answers
        if packet.haslayer(DNSRR):
            rr = packet[DNSRR]
            rdata = getattr(rr, "rdata", None)
            if rdata is not None:
                if hasattr(rdata, "decode"):
                    rdata = rdata.decode("utf-8", errors="replace")
                parts.append(f"Answer: {rdata}")

        return " | ".join(parts) if parts else "DNS Message"
    except Exception as e:
        return f"DNS Message (Parse Error: {e})"


def parse_icmp_layer(packet: Any) -> Optional[str]:
    """Extract ICMP type and code details."""
    try:
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            type_names = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request (Ping)",
                11: "Time Exceeded",
            }
            name = type_names.get(icmp.type, f"Type {icmp.type}")
            return f"{name} (Type={icmp.type}, Code={icmp.code})"
        elif packet.haslayer(_ICMPv6):
            icmp6 = packet[_ICMPv6]
            return f"ICMPv6 (Type={getattr(icmp6, 'type', 'N/A')}, Code={getattr(icmp6, 'code', 'N/A')})"
    except Exception:
        return "ICMP Message"
    return None


def analyze_packet(
    packet: Any,
    packet_id: int = 1,
    enable_payload: bool = False,
    max_payload_bytes: int = 64,
) -> PacketInfo:
    """
    Main entry point for packet analysis.
    Takes a raw Scapy packet and constructs a validated, human-readable PacketInfo object.
    Gracefully handles missing headers, corrupted data, and non-IP traffic.
    """
    # Timestamp calculation
    try:
        epoch_time = float(getattr(packet, "time", datetime.now().timestamp()))
        dt = datetime.fromtimestamp(epoch_time)
        timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        epoch_time = datetime.now().timestamp()
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")

    packet_len = len(packet)
    layer_details: Dict[str, Dict[str, Any]] = {}

    # Layer 2: Ethernet / Hardware
    src_mac = "N/A"
    dst_mac = "N/A"
    # Layer 2: Ethernet / Hardware
    src_mac = "N/A"
    dst_mac = "N/A"
    if packet.haslayer(Ether):
        eth = packet[Ether]
        src_mac = getattr(eth, "src", "N/A")
        dst_mac = getattr(eth, "dst", "N/A")
        eth_type = getattr(eth, "type", None)
        layer_details["Ethernet"] = {
            "Source MAC": src_mac,
            "Destination MAC": dst_mac,
            "EtherType": f"0x{eth_type:04X}" if eth_type is not None else "N/A",
        }

    # Layer 3: Network (IPv4, IPv6, ARP)
    ip_version = "Non-IP"
    src_ip = "N/A"
    dst_ip = "N/A"
    ttl: Optional[int] = None

    if packet.haslayer(IP):
        ip = packet[IP]
        ip_version = "IPv4"
        src_ip = getattr(ip, "src", "N/A")
        dst_ip = getattr(ip, "dst", "N/A")
        ttl = getattr(ip, "ttl", None)
        ihl_val = getattr(ip, "ihl", None)
        tos_val = getattr(ip, "tos", None)
        len_val = getattr(ip, "len", None)
        id_val = getattr(ip, "id", None)
        layer_details["IPv4"] = {
            "Version": 4,
            "Header Length": f"{ihl_val * 4} bytes" if ihl_val is not None else "20 bytes (default)",
            "Type of Service (TOS)": f"0x{tos_val:02X}" if tos_val is not None else "0x00",
            "Total Length": f"{len_val} bytes" if len_val is not None else f"{packet_len} bytes",
            "Identification": f"0x{id_val:04X}" if id_val is not None else "N/A",
            "Flags": str(getattr(ip, "flags", "0")),
            "Time to Live (TTL)": ttl if ttl is not None else "N/A",
            "Protocol ID": getattr(ip, "proto", "N/A"),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
        }
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        ip_version = "IPv6"
        src_ip = getattr(ipv6, "src", "N/A")
        dst_ip = getattr(ipv6, "dst", "N/A")
        ttl = getattr(ipv6, "hlim", None)
        layer_details["IPv6"] = {
            "Version": 6,
            "Traffic Class": getattr(ipv6, "tc", 0),
            "Flow Label": getattr(ipv6, "fl", 0),
            "Payload Length": getattr(ipv6, "plen", packet_len),
            "Next Header": getattr(ipv6, "nh", "N/A"),
            "Hop Limit": ttl if ttl is not None else "N/A",
            "Source IP": src_ip,
            "Destination IP": dst_ip,
        }
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        ip_version = "ARP"
        src_ip = getattr(arp, "psrc", "N/A")
        dst_ip = getattr(arp, "pdst", "N/A")
        layer_details["ARP"] = {
            "Hardware Type": getattr(arp, "hwtype", "N/A"),
            "Protocol Type": f"0x{getattr(arp, 'ptype', 0):04X}",
            "Operation": "Who-has (Request)" if getattr(arp, "op", 0) == 1 else "Is-at (Reply)" if getattr(arp, "op", 0) == 2 else str(getattr(arp, "op", "N/A")),
            "Sender MAC": getattr(arp, "hwsrc", "N/A"),
            "Sender IP": src_ip,
            "Target MAC": getattr(arp, "hwdst", "N/A"),
            "Target IP": dst_ip,
        }

    # Layer 4: Transport (TCP, UDP, ICMP) & Layer 7: Application
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol = "OTHER"
    protocol_detail = ""
    tcp_flags: Optional[str] = None
    dns_info: Optional[str] = None
    icmp_info: Optional[str] = None
    raw_payload: bytes = b""

    # Check DNS first (DNS can run over UDP or TCP)
    is_dns = packet.haslayer(DNS)

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = getattr(tcp, "sport", None)
        dst_port = getattr(tcp, "dport", None)
        tcp_flags = decode_tcp_flags(getattr(tcp, "flags", None))
        protocol = "TCP"
        protocol_detail = f"TCP (Ports: {src_port} -> {dst_port}, Flags: {tcp_flags})"

        dataofs_val = getattr(tcp, "dataofs", None)
        chksum_val = getattr(tcp, "chksum", None)
        layer_details["TCP"] = {
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Sequence Number": getattr(tcp, "seq", "N/A"),
            "Acknowledgment Number": getattr(tcp, "ack", "N/A"),
            "Data Offset": f"{dataofs_val * 4} bytes" if dataofs_val is not None else "20 bytes (default)",
            "Flags": tcp_flags,
            "Window Size": getattr(tcp, "window", "N/A"),
            "Checksum": f"0x{chksum_val:04X}" if chksum_val is not None else "N/A",
        }

        # Identify application layer on top of TCP
        if is_dns or src_port == 53 or dst_port == 53:
            protocol = "DNS"
            dns_info = parse_dns_layer(packet)
            protocol_detail = f"DNS over TCP (Port 53) - {dns_info or 'Query/Response'}"
        elif src_port in (443, 8443) or dst_port in (443, 8443):
            protocol = "HTTPS"
            protocol_detail = f"HTTPS / TLS encrypted session over TCP (Port {443 if 443 in (src_port, dst_port) else dst_port})"
        elif src_port in (80, 8080) or dst_port in (80, 8080):
            protocol = "HTTP"
            protocol_detail = f"HTTP plaintext web traffic over TCP (Port {80 if 80 in (src_port, dst_port) else dst_port})"

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = getattr(udp, "sport", None)
        dst_port = getattr(udp, "dport", None)
        protocol = "UDP"
        protocol_detail = f"UDP datagram (Ports: {src_port} -> {dst_port})"

        chksum_val = getattr(udp, "chksum", None)
        udp_len = getattr(udp, "len", None)
        layer_details["UDP"] = {
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Length": f"{udp_len} bytes" if udp_len is not None else f"{packet_len} bytes",
            "Checksum": f"0x{chksum_val:04X}" if chksum_val is not None else "N/A",
        }

        # Identify application layer on top of UDP
        if is_dns or src_port in (53, 5353) or dst_port in (53, 5353):
            protocol = "DNS"
            dns_info = parse_dns_layer(packet)
            protocol_detail = f"DNS over UDP (Port {dst_port if dst_port in (53, 5353) else src_port}) - {dns_info or 'Query/Response'}"
        elif src_port == 443 or dst_port == 443:
            protocol = "HTTPS"
            protocol_detail = "QUIC / HTTP/3 secure UDP traffic (Port 443)"
        elif src_port in (67, 68) or dst_port in (67, 68):
            protocol = "DHCP"
            protocol_detail = f"DHCP Network Configuration (Ports {src_port}->{dst_port})"

    elif packet.haslayer(ICMP) or packet.haslayer(_ICMPv6):
        protocol = "ICMP"
        icmp_info = parse_icmp_layer(packet)
        protocol_detail = icmp_info or "ICMP Control Message"
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_chksum = getattr(icmp, "chksum", None)
            layer_details["ICMP"] = {
                "Type": getattr(icmp, "type", "N/A"),
                "Code": getattr(icmp, "code", "N/A"),
                "Checksum": f"0x{icmp_chksum:04X}" if icmp_chksum is not None else "N/A",
                "Description": icmp_info,
            }

    elif packet.haslayer(ARP):
        protocol = "ARP"
        protocol_detail = layer_details.get("ARP", {}).get("Operation", "ARP Request/Reply")

    else:
        protocol = "OTHER"
        protocol_detail = f"Protocols present: {', '.join(layer.__name__ for layer in packet.layers())}"

    # Extract Raw payload data safely
    if packet.haslayer(scapy.Raw):
        try:
            raw_payload = bytes(packet[scapy.Raw].load)
        except Exception:
            raw_payload = b""
    elif hasattr(packet, "payload") and packet.payload:
        try:
            curr = packet.payload
            while hasattr(curr, "payload") and curr.payload and not isinstance(curr.payload, scapy.packet.NoPayload):
                curr = curr.payload
            if hasattr(curr, "load"):
                raw_payload = bytes(curr.load)
            elif isinstance(curr, (bytes, bytearray)):
                raw_payload = bytes(curr)
        except Exception:
            raw_payload = b""

    # Payload Preview (Strictly limited and disabled by default for privacy/security)
    payload_preview: Optional[str] = None
    if enable_payload and raw_payload:
        payload_preview = format_hex_ascii(raw_payload, max_bytes=max_payload_bytes)
    elif not enable_payload:
        payload_preview = "[Payload preview disabled by default for privacy and security]"
    else:
        payload_preview = "[No additional payload data]"

    # Summary string for the table
    summary_str = f"[{protocol}] {src_ip}"
    if src_port:
        summary_str += f":{src_port}"
    summary_str += f" -> {dst_ip}"
    if dst_port:
        summary_str += f":{dst_port}"
    if protocol_detail and protocol not in ("TCP", "UDP"):
        summary_str += f" | {protocol_detail}"

    return PacketInfo(
        packet_id=packet_id,
        timestamp=timestamp_str,
        time_epoch=epoch_time,
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        protocol_detail=protocol_detail,
        length=packet_len,
        ttl=ttl,
        tcp_flags=tcp_flags,
        dns_info=dns_info,
        icmp_info=icmp_info,
        payload_preview=payload_preview,
        summary=summary_str,
        layer_details=layer_details,
    )


def matches_filter(
    packet_info: PacketInfo,
    protocol_filter: str = "ALL",
    ip_filter: str = "",
    port_filter: str = "",
    search_text: str = "",
) -> bool:
    """
    Evaluate whether a packet matches the user's active filter criteria.
    Filtering is non-destructive and operates on in-memory packet metadata.
    """
    # 1. Protocol filter
    proto_norm = protocol_filter.strip().upper()
    if proto_norm and proto_norm != "ALL":
        if proto_norm == "DNS":
            if packet_info.protocol != "DNS":
                return False
        elif proto_norm == "HTTP":
            if packet_info.protocol != "HTTP":
                return False
        elif proto_norm == "HTTPS":
            if packet_info.protocol != "HTTPS":
                return False
        elif proto_norm == "ICMP":
            if packet_info.protocol != "ICMP":
                return False
        elif proto_norm == "TCP":
            # Show TCP packets or protocols running on TCP
            if packet_info.protocol not in ("TCP", "HTTP", "HTTPS"):
                return False
        elif proto_norm == "UDP":
            # Show UDP packets or protocols running on UDP
            if packet_info.protocol not in ("UDP", "DNS", "DHCP"):
                return False
        elif proto_norm == "ARP":
            if packet_info.protocol != "ARP":
                return False
        else:
            if proto_norm not in packet_info.protocol.upper():
                return False

    # 2. IP filter (checks both source and destination)
    ip_query = ip_filter.strip()
    if ip_query:
        src = packet_info.src_ip.lower()
        dst = packet_info.dst_ip.lower()
        q = ip_query.lower()
        if q not in src and q not in dst:
            return False

    # 3. Port filter (checks both source and destination ports)
    port_query = port_filter.strip()
    if port_query:
        try:
            port_num = int(port_query)
            if packet_info.src_port != port_num and packet_info.dst_port != port_num:
                return False
        except ValueError:
            # Non-integer port query
            return False

    # 4. General search text across all visible fields
    search_q = search_text.strip().lower()
    if search_q:
        haystack = " ".join(
            [
                str(packet_info.packet_id),
                packet_info.timestamp,
                packet_info.src_ip,
                str(packet_info.src_port or ""),
                packet_info.dst_ip,
                str(packet_info.dst_port or ""),
                packet_info.protocol,
                packet_info.protocol_detail,
                packet_info.summary,
                packet_info.dns_info or "",
                packet_info.icmp_info or "",
                packet_info.tcp_flags or "",
            ]
        ).lower()
        if search_q not in haystack:
            return False

    return True


def get_protocol_explanation(protocol: str) -> str:
    """Retrieve educational breakdown of a given protocol for students."""
    return PROTOCOL_EXPLANATIONS.get(
        protocol.upper(),
        f"{protocol}: Standard network protocol. Inspect packet headers and transport layer ports to examine data flow."
    )
