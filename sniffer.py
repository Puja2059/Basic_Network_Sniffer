"""
sniffer.py
==========
Background packet capture engine for CodeAlpha Basic Network Sniffer.
Orchestrates threaded live packet collection using Scapy, manages lifecycle
events (start, pause, stop), and coordinates thread-safe packet dispatch
and real-time protocol statistics.

Author: CodeAlpha Cyber Security Intern
Project: Basic Network Sniffer (Task 1)
"""

from collections import defaultdict
from dataclasses import dataclass, field
import queue
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional
import scapy.all as scapy
from scapy.all import sniff

from packet_analyzer import analyze_packet, PacketInfo


@dataclass
class CaptureStats:
    """Thread-safe statistics tracking for live capture sessions."""
    total_packets: int = 0
    total_bytes: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def reset(self) -> None:
        """Reset all statistics counters."""
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None
        self.protocol_counts.clear()

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary for UI consumption."""
        duration = 0.0
        if self.start_time:
            end = self.end_time or time.time()
            duration = max(0.0, end - self.start_time)

        pps = round(self.total_packets / duration, 1) if duration > 0 else 0.0

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(duration, 1),
            "packets_per_second": pps,
            "protocols": dict(self.protocol_counts),
        }


class NetworkSniffer:
    """
    Multithreaded packet capture manager.
    Runs non-blocking packet capture in a background worker thread
    to ensure the user interface remains completely responsive.
    """

    def __init__(self, packet_queue: Optional[queue.Queue] = None):
        self.packet_queue: queue.Queue = packet_queue if packet_queue is not None else queue.Queue()
        self.stats = CaptureStats()
        self._stats_lock = threading.Lock()

        # Threading controls
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._is_capturing = False

        # Configuration
        self.selected_iface: Any = None
        self.packet_limit: int = 0  # 0 means unlimited
        self.enable_payload: bool = False
        self.max_payload_bytes: int = 64
        self.bpf_filter: Optional[str] = None

        # Callbacks
        self.on_packet_analyzed: Optional[Callable[[PacketInfo], None]] = None
        self.on_status_change: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

    @property
    def is_capturing(self) -> bool:
        """Check if packet capture is currently active."""
        return self._is_capturing

    def start_capture(
        self,
        iface: Any,
        packet_limit: int = 0,
        enable_payload: bool = False,
        max_payload_bytes: int = 64,
        bpf_filter: Optional[str] = None,
        on_packet_analyzed: Optional[Callable[[PacketInfo], None]] = None,
        on_status_change: Optional[Callable[[str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """
        Start capturing packets in a background thread.
        Returns True if capture thread was launched successfully.
        """
        if self._is_capturing:
            if self.on_status_change:
                self.on_status_change("Capture already in progress.")
            return False

        self.selected_iface = iface
        self.packet_limit = max(0, packet_limit)
        self.enable_payload = enable_payload
        self.max_payload_bytes = max_payload_bytes
        self.bpf_filter = bpf_filter.strip() if bpf_filter else None
        self.on_packet_analyzed = on_packet_analyzed
        self.on_status_change = on_status_change
        self.on_error = on_error

        # Reset capture thread control event
        self._stop_event.clear()
        self._is_capturing = True

        with self._stats_lock:
            self.stats.start_time = time.time()
            self.stats.end_time = None

        if self.on_status_change:
            iface_label = getattr(iface, "name", str(iface))
            self.on_status_change(f"Capturing on {iface_label}...")

        # Spawn background capture worker
        self._capture_thread = threading.Thread(
            target=self._worker_loop,
            name="SnifferWorkerThread",
            daemon=True,
        )
        self._capture_thread.start()
        return True

    def stop_capture(self) -> None:
        """Signal the capture thread to stop and finalize session statistics."""
        if not self._is_capturing:
            return

        self._stop_event.set()
        self._is_capturing = False

        with self._stats_lock:
            self.stats.end_time = time.time()

        if self.on_status_change:
            self.on_status_change("Capture stopped.")

    def reset_stats(self) -> None:
        """Clear session statistics."""
        with self._stats_lock:
            self.stats.reset()

    def get_stats_snapshot(self) -> Dict[str, Any]:
        """Thread-safe snapshot of capture statistics."""
        with self._stats_lock:
            return self.stats.to_dict()

    def _worker_loop(self) -> None:
        """
        Core worker execution loop.
        Uses Scapy's sniff() with short timeouts to maintain high responsiveness
        to user stop requests while efficiently capturing traffic.
        """
        packet_counter = 0

        def packet_handler(raw_pkt: Any) -> None:
            nonlocal packet_counter
            if self._stop_event.is_set():
                return

            packet_counter += 1
            pkt_len = len(raw_pkt)

            # Analyze packet
            try:
                analyzed = analyze_packet(
                    raw_pkt,
                    packet_id=packet_counter,
                    enable_payload=self.enable_payload,
                    max_payload_bytes=self.max_payload_bytes,
                )
            except Exception as parse_err:
                print(f"[Warning] Failed to analyze packet: {parse_err}", file=sys.stderr)
                return

            # Update stats under lock
            with self._stats_lock:
                self.stats.total_packets += 1
                self.stats.total_bytes += pkt_len
                self.stats.protocol_counts[analyzed.protocol] += 1

            # Dispatch to queue and callback
            self.packet_queue.put(analyzed)
            if self.on_packet_analyzed:
                try:
                    self.on_packet_analyzed(analyzed)
                except Exception:
                    pass

            # Check limit
            if self.packet_limit > 0 and packet_counter >= self.packet_limit:
                self._stop_event.set()

        try:
            while not self._stop_event.is_set():
                if self.packet_limit > 0 and packet_counter >= self.packet_limit:
                    break

                sniff_kwargs: Dict[str, Any] = {
                    "timeout": 0.5,  # Unblocks every 500ms to evaluate stop event
                    "count": 10,
                    "store": False,
                    "prn": packet_handler,
                }
                if self.selected_iface:
                    sniff_kwargs["iface"] = self.selected_iface
                if self.bpf_filter:
                    sniff_kwargs["filter"] = self.bpf_filter

                sniff(**sniff_kwargs)

        except PermissionError:
            err_msg = (
                "Capture Error: Permission Denied. "
                "Raw packet sniffing requires elevated privileges. "
                "Please run PowerShell / CMD as Administrator."
            )
            if self.on_error:
                self.on_error(err_msg)
        except Exception as e:
            err_msg = f"Capture Exception on interface: {e}"
            if self.on_error:
                self.on_error(err_msg)
        finally:
            self._is_capturing = False
            with self._stats_lock:
                if not self.stats.end_time:
                    self.stats.end_time = time.time()

            if self.on_status_change:
                status_txt = f"Stopped. Captured {packet_counter} packets."
                if self.packet_limit > 0 and packet_counter >= self.packet_limit:
                    status_txt = f"Limit reached ({self.packet_limit} packets). Stopped."
                self.on_status_change(status_txt)
