"""
tests/test_filters.py
=====================
Automated unit tests for packet filtering and search operations.
Validates multi-criteria filtering: protocol, IP, port, and full-text search.

Author: CodeAlpha Cyber Security Intern
"""

import pytest
from packet_analyzer import PacketInfo, matches_filter


@pytest.fixture
def test_packets():
    """Create a suite of packets for filter testing."""
    return [
        PacketInfo(
            packet_id=1,
            timestamp="2026-10-04 10:00:00.100",
            time_epoch=1791093600.1,
            ip_version="IPv4",
            src_ip="192.168.1.100",
            dst_ip="1.1.1.1",
            src_port=53535,
            dst_port=53,
            protocol="DNS",
            protocol_detail="DNS over UDP",
            length=80,
            summary="[DNS] 192.168.1.100:53535 -> 1.1.1.1:53",
            dns_info="Query: cloudflare.com (A)",
        ),
        PacketInfo(
            packet_id=2,
            timestamp="2026-10-04 10:00:01.200",
            time_epoch=1791093601.2,
            ip_version="IPv4",
            src_ip="192.168.1.100",
            dst_ip="142.250.190.46",
            src_port=54000,
            dst_port=443,
            protocol="HTTPS",
            protocol_detail="HTTPS / TLS over TCP",
            length=1200,
            summary="[HTTPS] 192.168.1.100:54000 -> 142.250.190.46:443",
        ),
        PacketInfo(
            packet_id=3,
            timestamp="2026-10-04 10:00:02.300",
            time_epoch=1791093602.3,
            ip_version="IPv4",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            protocol_detail="Echo Request (Ping)",
            length=64,
            summary="[ICMP] 192.168.1.100 -> 8.8.8.8",
            icmp_info="Echo Request (Type=8, Code=0)",
        ),
        PacketInfo(
            packet_id=4,
            timestamp="2026-10-04 10:00:03.400",
            time_epoch=1791093603.4,
            ip_version="IPv4",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=52123,
            dst_port=80,
            protocol="HTTP",
            protocol_detail="HTTP plaintext web traffic",
            length=450,
            summary="[HTTP] 10.0.0.5:52123 -> 10.0.0.1:80",
        ),
    ]


class TestPacketFilters:
    """Test suite for filtering functions."""

    def test_filter_all_protocol(self, test_packets):
        """ALL protocol returns every packet."""
        matched = [p for p in test_packets if matches_filter(p, protocol_filter="ALL")]
        assert len(matched) == 4

    def test_filter_specific_protocols(self, test_packets):
        """Specific protocol filters match correct subset."""
        dns_matches = [p for p in test_packets if matches_filter(p, protocol_filter="DNS")]
        assert len(dns_matches) == 1
        assert dns_matches[0].packet_id == 1

        icmp_matches = [p for p in test_packets if matches_filter(p, protocol_filter="ICMP")]
        assert len(icmp_matches) == 1
        assert icmp_matches[0].packet_id == 3

        https_matches = [p for p in test_packets if matches_filter(p, protocol_filter="HTTPS")]
        assert len(https_matches) == 1
        assert https_matches[0].packet_id == 2

    def test_filter_by_ip_partial_and_exact(self, test_packets):
        """IP filter matches source or destination with substring matching."""
        # Matches all 3 packets with 192.168.1.100
        matches = [p for p in test_packets if matches_filter(p, ip_filter="192.168.1.100")]
        assert len(matches) == 3

        # Matches only packet 4
        matches_10 = [p for p in test_packets if matches_filter(p, ip_filter="10.0.0.5")]
        assert len(matches_10) == 1
        assert matches_10[0].packet_id == 4

        # Nonexistent IP
        matches_none = [p for p in test_packets if matches_filter(p, ip_filter="172.16.99.99")]
        assert len(matches_none) == 0

    def test_filter_by_port(self, test_packets):
        """Port filter matches either src_port or dst_port."""
        matches_53 = [p for p in test_packets if matches_filter(p, port_filter="53")]
        assert len(matches_53) == 1
        assert matches_53[0].protocol == "DNS"

        matches_443 = [p for p in test_packets if matches_filter(p, port_filter="443")]
        assert len(matches_443) == 1
        assert matches_443[0].protocol == "HTTPS"

        # ICMP packet has no ports
        matches_icmp = [p for p in test_packets if matches_filter(p, port_filter="0")]
        assert len(matches_icmp) == 0

    def test_combined_filters(self, test_packets):
        """Combined protocol + IP + port filtering."""
        # Match HTTPS traffic with 192.168.1.100 on port 443
        res = [
            p
            for p in test_packets
            if matches_filter(p, protocol_filter="HTTPS", ip_filter="192.168.1", port_filter="443")
        ]
        assert len(res) == 1
        assert res[0].packet_id == 2

        # Combined filter that yields no results
        res_empty = [
            p
            for p in test_packets
            if matches_filter(p, protocol_filter="DNS", ip_filter="192.168.1", port_filter="443")
        ]
        assert len(res_empty) == 0

    def test_text_search_query(self, test_packets):
        """Search query looks through dns_info, icmp_info, and metadata."""
        cloudflare_match = [p for p in test_packets if matches_filter(p, search_text="cloudflare")]
        assert len(cloudflare_match) == 1
        assert cloudflare_match[0].packet_id == 1

        ping_match = [p for p in test_packets if matches_filter(p, search_text="Ping")]
        assert len(ping_match) == 1
        assert ping_match[0].packet_id == 3
