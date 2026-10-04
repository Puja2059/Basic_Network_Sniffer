"""
tests/test_packet_analyzer.py
=============================
Automated unit tests for packet_analyzer.py using synthetic Scapy packets.
Tests do not require live network capture, permissions, or hardware drivers.

Author: CodeAlpha Cyber Security Intern
"""

import pytest
from datetime import datetime
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from packet_analyzer import (
    analyze_packet,
    decode_tcp_flags,
    format_hex_ascii,
    matches_filter,
    get_protocol_explanation,
    PacketInfo,
)


class TestPacketAnalyzer:
    """Test suite for packet analysis with synthetic Scapy packets."""

    def test_ipv4_tcp_packet_parsing(self):
        """Verify parsing of synthetic IPv4 TCP packet with SYN flag."""
        pkt = Ether() / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64) / TCP(sport=54321, dport=80, flags="S")
        info = analyze_packet(pkt, packet_id=1)

        assert info.packet_id == 1
        assert info.ip_version == "IPv4"
        assert info.src_ip == "192.168.1.50"
        assert info.dst_ip == "93.184.216.34"
        assert info.src_port == 54321
        assert info.dst_port == 80
        assert info.protocol in ("TCP", "HTTP")  # Port 80 can be flagged HTTP
        assert info.ttl == 64
        assert "SYN" in (info.tcp_flags or "")
        assert info.length > 0
        assert "IPv4" in info.layer_details
        assert "TCP" in info.layer_details

    def test_ipv4_udp_packet_parsing(self):
        """Verify parsing of synthetic IPv4 UDP datagram."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / UDP(sport=4000, dport=5000)
        info = analyze_packet(pkt, packet_id=2)

        assert info.packet_id == 2
        assert info.ip_version == "IPv4"
        assert info.src_ip == "10.0.0.1"
        assert info.dst_ip == "10.0.0.2"
        assert info.src_port == 4000
        assert info.dst_port == 5000
        assert info.protocol == "UDP"
        assert info.ttl == 128
        assert info.tcp_flags is None
        assert "UDP" in info.layer_details

    def test_ipv4_icmp_packet_parsing(self):
        """Verify parsing of synthetic ICMP Echo Request (Ping)."""
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8", ttl=56) / ICMP(type=8, code=0)
        info = analyze_packet(pkt, packet_id=3)

        assert info.packet_id == 3
        assert info.ip_version == "IPv4"
        assert info.src_ip == "192.168.1.10"
        assert info.dst_ip == "8.8.8.8"
        assert info.src_port is None
        assert info.dst_port is None
        assert info.protocol == "ICMP"
        assert "Echo Request" in (info.icmp_info or "")
        assert info.ttl == 56

    def test_ipv6_packet_parsing(self):
        """Verify parsing of IPv6 packet and hop limit."""
        pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64) / UDP(sport=1234, dport=5678)
        info = analyze_packet(pkt, packet_id=4)

        assert info.packet_id == 4
        assert info.ip_version == "IPv6"
        assert info.src_ip == "2001:db8::1"
        assert info.dst_ip == "2001:db8::2"
        assert info.ttl == 64  # Hop limit mapped to ttl attribute
        assert info.protocol == "UDP"
        assert "IPv6" in info.layer_details

    def test_dns_query_parsing(self):
        """Verify extraction of DNS query name and query type."""
        pkt = (
            Ether()
            / IP(src="192.168.1.15", dst="8.8.8.8")
            / UDP(sport=53210, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
        info = analyze_packet(pkt, packet_id=5)

        assert info.protocol == "DNS"
        assert info.dns_info is not None
        assert "example.com" in info.dns_info
        assert "Query" in info.dns_info

    def test_dns_response_parsing(self):
        """Verify extraction of DNS query response with answer record."""
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.15")
            / UDP(sport=53, dport=53210)
            / DNS(
                qr=1,
                qd=DNSQR(qname="example.com", qtype="A"),
                an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
            )
        )
        info = analyze_packet(pkt, packet_id=6)

        assert info.protocol == "DNS"
        assert info.dns_info is not None
        assert "93.184.216.34" in info.dns_info

    def test_https_tls_classification(self):
        """Verify TCP port 443 packets are classified as HTTPS."""
        pkt = Ether() / IP(src="10.0.0.5", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="A")
        info = analyze_packet(pkt, packet_id=7)

        assert info.protocol == "HTTPS"
        assert "HTTPS" in info.protocol_detail

    def test_arp_packet_parsing(self):
        """Verify ARP request parsing without IP layer."""
        pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.254")
        info = analyze_packet(pkt, packet_id=8)

        assert info.protocol == "ARP"
        assert info.ip_version == "ARP"
        assert info.src_ip == "192.168.1.1"
        assert info.dst_ip == "192.168.1.254"
        assert info.src_port is None
        assert info.dst_port is None
        assert "ARP" in info.layer_details

    def test_payload_preview_security_defaults(self):
        """Verify payload preview is disabled by default for privacy/security."""
        payload_data = b"GET /admin/secret HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80) / payload_data

        # Disabled by default
        info_default = analyze_packet(pkt, packet_id=9, enable_payload=False)
        assert "disabled by default" in (info_default.payload_preview or "")
        assert "GET /admin/secret" not in (info_default.payload_preview or "")

        # Enabled explicitly
        info_enabled = analyze_packet(pkt, packet_id=10, enable_payload=True, max_payload_bytes=32)
        assert info_enabled.payload_preview is not None
        assert "47 45 54" in info_enabled.payload_preview  # "GET" in hex
        assert "GET" in info_enabled.payload_preview

    def test_malformed_and_empty_packet_handling(self):
        """Ensure analyzer does not crash on bare raw bytes or empty packets."""
        bare_pkt = Ether()
        info = analyze_packet(bare_pkt, packet_id=11)
        assert info.packet_id == 11
        assert info.protocol in ("OTHER", "None")
        assert info.src_ip == "N/A"
        assert info.dst_ip == "N/A"

    def test_filtering_logic(self):
        """Verify protocol, IP, port, and text search filters."""
        pkt = Ether() / IP(src="172.16.0.4", dst="172.16.0.100") / TCP(sport=8080, dport=443, flags="PA")
        info = analyze_packet(pkt, packet_id=12)

        # Protocol filter
        assert matches_filter(info, protocol_filter="ALL")
        assert matches_filter(info, protocol_filter="HTTPS")
        assert not matches_filter(info, protocol_filter="ICMP")
        assert not matches_filter(info, protocol_filter="UDP")

        # IP filter
        assert matches_filter(info, ip_filter="172.16.0.4")
        assert matches_filter(info, ip_filter="172.16.0.100")
        assert not matches_filter(info, ip_filter="192.168.1.1")

        # Port filter
        assert matches_filter(info, port_filter="443")
        assert matches_filter(info, port_filter="8080")
        assert not matches_filter(info, port_filter="53")

        # Search query across metadata
        assert matches_filter(info, search_text="172.16")
        assert matches_filter(info, search_text="443")
        assert not matches_filter(info, search_text="nonexistent_string_123")

    def test_protocol_explanations(self):
        """Verify educational explanations are available for core protocols."""
        for proto in ["TCP", "UDP", "ICMP", "DNS", "HTTPS", "HTTP", "ARP"]:
            text = get_protocol_explanation(proto)
            assert len(text) > 20
            assert proto in text
