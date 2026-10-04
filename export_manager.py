"""
export_manager.py
=================
Data export services for CodeAlpha Basic Network Sniffer.
Exports captured packet metadata to CSV and JSON formats while adhering
to security, privacy, and data-integrity best practices.

Author: CodeAlpha Cyber Security Intern
Project: Basic Network Sniffer (Task 1)
"""

import csv
import json
import os
from datetime import datetime
from typing import List, Tuple
from packet_analyzer import PacketInfo


CSV_HEADERS = [
    "Packet #",
    "Timestamp",
    "IP Version",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Protocol Detail",
    "Length (Bytes)",
    "TTL / Hop Limit",
    "TCP Flags",
    "DNS Query / Info",
    "ICMP Info",
    "Summary",
]

CSV_HEADERS_WITH_PAYLOAD = CSV_HEADERS + ["Payload Preview (Hex)"]


def export_to_csv(
    packets: List[PacketInfo],
    filepath: str,
    include_payload: bool = False,
) -> Tuple[bool, str]:
    """
    Export a list of PacketInfo objects to a formatted CSV file.
    Payload content is excluded by default for security and privacy.

    Returns:
        (success: bool, message: str)
    """
    if not filepath:
        return False, "Export error: Target filepath cannot be empty."

    try:
        # Ensure parent directory exists
        parent_dir = os.path.dirname(os.path.abspath(filepath))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        headers = CSV_HEADERS_WITH_PAYLOAD if include_payload else CSV_HEADERS

        with open(filepath, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(headers)

            for pkt in packets:
                row = [
                    pkt.packet_id,
                    pkt.timestamp,
                    pkt.ip_version,
                    pkt.src_ip,
                    pkt.src_port if pkt.src_port is not None else "N/A",
                    pkt.dst_ip,
                    pkt.dst_port if pkt.dst_port is not None else "N/A",
                    pkt.protocol,
                    pkt.protocol_detail,
                    pkt.length,
                    pkt.ttl if pkt.ttl is not None else "N/A",
                    pkt.tcp_flags if pkt.tcp_flags else "N/A",
                    pkt.dns_info if pkt.dns_info else "N/A",
                    pkt.icmp_info if pkt.icmp_info else "N/A",
                    pkt.summary,
                ]
                if include_payload:
                    row.append(pkt.payload_preview or "N/A")
                writer.writerow(row)

        return True, f"Successfully exported {len(packets)} packets to CSV: {os.path.basename(filepath)}"
    except PermissionError:
        return False, f"Permission denied writing to: {filepath}"
    except Exception as e:
        return False, f"CSV Export Failed: {str(e)}"


def export_to_json(
    packets: List[PacketInfo],
    filepath: str,
    include_payload: bool = False,
) -> Tuple[bool, str]:
    """
    Export packet metadata to structured JSON format.

    Returns:
        (success: bool, message: str)
    """
    if not filepath:
        return False, "Export error: Target filepath cannot be empty."

    try:
        parent_dir = os.path.dirname(os.path.abspath(filepath))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        export_data = {
            "application": "CodeAlpha Basic Network Sniffer",
            "task": "CodeAlpha Cyber Security Internship Task 1",
            "exported_at": datetime.now().isoformat(),
            "total_packets": len(packets),
            "payload_included": include_payload,
            "packets": [pkt.to_dict(include_payload=include_payload) for pkt in packets],
        }

        with open(filepath, mode="w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return True, f"Successfully exported {len(packets)} packets to JSON: {os.path.basename(filepath)}"
    except PermissionError:
        return False, f"Permission denied writing to: {filepath}"
    except Exception as e:
        return False, f"JSON Export Failed: {str(e)}"
