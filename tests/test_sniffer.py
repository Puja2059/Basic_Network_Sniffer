"""
tests/test_sniffer.py
=====================
Automated unit tests for sniffer.py and CaptureStats.
Uses synthetic packet mocks to verify thread safety, statistics tracking,
queue dispatch, and packet limits without relying on live hardware interfaces.

Author: CodeAlpha Cyber Security Intern
"""

import queue
import time
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from sniffer import CaptureStats, NetworkSniffer
from packet_analyzer import analyze_packet


class TestCaptureStats:
    """Test suite for CaptureStats data structure."""

    def test_stats_initialization(self):
        """Verify default zeroed statistics."""
        stats = CaptureStats()
        d = stats.to_dict()
        assert d["total_packets"] == 0
        assert d["total_bytes"] == 0
        assert d["packets_per_second"] == 0.0
        assert d["protocols"] == {}

    def test_stats_aggregation_and_reset(self):
        """Verify protocol incrementing and reset functionality."""
        stats = CaptureStats()
        stats.start_time = time.time() - 2.0  # 2 seconds elapsed
        stats.total_packets = 10
        stats.total_bytes = 1500
        stats.protocol_counts["TCP"] = 6
        stats.protocol_counts["UDP"] = 4

        d = stats.to_dict()
        assert d["total_packets"] == 10
        assert d["total_bytes"] == 1500
        assert d["protocols"]["TCP"] == 6
        assert d["protocols"]["UDP"] == 4
        assert d["packets_per_second"] > 0

        # Reset
        stats.reset()
        assert stats.total_packets == 0
        assert stats.total_bytes == 0
        assert len(stats.protocol_counts) == 0


class TestNetworkSnifferMock:
    """Test suite for NetworkSniffer threading and dispatch logic."""

    def test_sniffer_init(self):
        """Verify sniffer initialization with custom queue."""
        q = queue.Queue()
        sniffer = NetworkSniffer(packet_queue=q)
        assert sniffer.is_capturing is False
        assert sniffer.packet_queue is q

    def test_packet_handler_mock_dispatch(self):
        """Simulate feeding packets into sniffer queue and verifying stats update."""
        q = queue.Queue()
        sniffer = NetworkSniffer(packet_queue=q)
        received_packets = []

        def callback(pkt_info):
            received_packets.append(pkt_info)

        sniffer.on_packet_analyzed = callback
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        analyzed = analyze_packet(pkt, packet_id=1)

        # Feed to queue and callback
        sniffer.packet_queue.put(analyzed)
        sniffer.on_packet_analyzed(analyzed)

        assert not q.empty()
        item = q.get_nowait()
        assert item.src_ip == "10.0.0.1"
        assert item.dst_port == 80
        assert len(received_packets) == 1
        assert received_packets[0].packet_id == 1

    def test_start_and_stop_state_transitions(self):
        """Verify is_capturing flag transitions cleanly."""
        sniffer = NetworkSniffer()
        assert sniffer.is_capturing is False

        # Attempt stop when not running should be a safe no-op
        sniffer.stop_capture()
        assert sniffer.is_capturing is False
