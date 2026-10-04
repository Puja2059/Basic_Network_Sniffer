"""
tests/test_export_manager.py
============================
Automated unit tests for export_manager.py (CSV and JSON export).
Uses temporary test files and synthetic PacketInfo objects.

Author: CodeAlpha Cyber Security Intern
"""

import csv
import json
import os
import tempfile
import pytest
from packet_analyzer import PacketInfo
from export_manager import export_to_csv, export_to_json, CSV_HEADERS, CSV_HEADERS_WITH_PAYLOAD


@pytest.fixture
def sample_packets():
    """Create a diverse fixture of synthetic PacketInfo objects."""
    p1 = PacketInfo(
        packet_id=1,
        timestamp="2026-10-04 12:00:01.123",
        time_epoch=1791100801.123,
        ip_version="IPv4",
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=80,
        protocol="HTTP",
        protocol_detail="HTTP plaintext web traffic over TCP (Port 80)",
        length=74,
        ttl=64,
        tcp_flags="SYN (0x02)",
        dns_info=None,
        icmp_info=None,
        payload_preview="[Payload preview disabled by default]",
        summary="[HTTP] 192.168.1.10:54321 -> 93.184.216.34:80",
    )
    p2 = PacketInfo(
        packet_id=2,
        timestamp="2026-10-04 12:00:02.456",
        time_epoch=1791100802.456,
        ip_version="IPv4",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=52000,
        dst_port=53,
        protocol="DNS",
        protocol_detail="DNS over UDP (Port 53) - Query: example.com (A)",
        length=62,
        ttl=128,
        tcp_flags=None,
        dns_info="Query: example.com (A)",
        icmp_info=None,
        payload_preview="0000  00 01 01 00  |....|",
        summary="[DNS] 192.168.1.10:52000 -> 8.8.8.8:53 | Query: example.com",
    )
    p3 = PacketInfo(
        packet_id=3,
        timestamp="2026-10-04 12:00:03.789",
        time_epoch=1791100803.789,
        ip_version="Non-IP",
        src_ip="192.168.1.1",
        dst_ip="192.168.1.254",
        src_port=None,
        dst_port=None,
        protocol="ARP",
        protocol_detail="Who-has (Request)",
        length=42,
        ttl=None,
        tcp_flags=None,
        dns_info=None,
        icmp_info=None,
        payload_preview=None,
        summary="[ARP] 192.168.1.1 -> 192.168.1.254 | Who-has",
    )
    return [p1, p2, p3]


class TestExportManager:
    """Test suite for CSV and JSON export routines."""

    def test_csv_export_default_headers_and_values(self, sample_packets):
        """Verify CSV export produces correct column headers and row count without payload."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            temp_path = tf.name

        try:
            success, msg = export_to_csv(sample_packets, temp_path, include_payload=False)
            assert success is True
            assert "Successfully exported" in msg

            with open(temp_path, mode="r", newline="", encoding="utf-8") as f:
                reader = list(csv.reader(f))

            # Validate header row
            assert reader[0] == CSV_HEADERS
            # 1 header + 3 data rows
            assert len(reader) == 4

            # Validate row 1
            row1 = reader[1]
            assert row1[0] == "1"
            assert row1[2] == "IPv4"
            assert row1[3] == "192.168.1.10"
            assert row1[4] == "54321"
            assert row1[5] == "93.184.216.34"
            assert row1[6] == "80"
            assert row1[7] == "HTTP"

            # Validate row 3 (ARP with N/A ports)
            row3 = reader[3]
            assert row3[0] == "3"
            assert row3[4] == "N/A"
            assert row3[6] == "N/A"
            assert row3[10] == "N/A"  # TTL
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_csv_export_with_payload_option(self, sample_packets):
        """Verify CSV export includes payload preview column when explicitly requested."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            temp_path = tf.name

        try:
            success, _ = export_to_csv(sample_packets, temp_path, include_payload=True)
            assert success is True

            with open(temp_path, mode="r", newline="", encoding="utf-8") as f:
                reader = list(csv.reader(f))

            assert reader[0] == CSV_HEADERS_WITH_PAYLOAD
            assert "Payload Preview (Hex)" in reader[0][-1]
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_json_export_structure(self, sample_packets):
        """Verify JSON export has expected top-level schema and packet list."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            success, msg = export_to_json(sample_packets, temp_path, include_payload=False)
            assert success is True
            assert os.path.exists(temp_path)

            with open(temp_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["total_packets"] == 3
            assert data["payload_included"] is False
            assert "application" in data
            assert len(data["packets"]) == 3
            assert data["packets"][0]["src_ip"] == "192.168.1.10"
            assert data["packets"][1]["protocol"] == "DNS"
            assert data["packets"][2]["protocol"] == "ARP"
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_export_invalid_path_error_handling(self, sample_packets):
        """Ensure empty or invalid paths return failure without unhandled crash."""
        success_csv, msg_csv = export_to_csv(sample_packets, "")
        assert success_csv is False
        assert "empty" in msg_csv.lower()

        success_json, msg_json = export_to_json(sample_packets, "")
        assert success_json is False
        assert "empty" in msg_json.lower()
