"""
interface_manager.py
====================
Network interface discovery and environment inspection for CodeAlpha Basic Network Sniffer.
Identifies active network adapters, resolves Windows friendly names and Npcap device paths,
and detects administrative capture permissions.

Author: CodeAlpha Cyber Security Intern
Project: Basic Network Sniffer (Task 1)
"""

import ctypes
import os
import platform
import sys
from typing import Dict, List, Optional
import scapy.all as scapy
from scapy.all import conf


class InterfaceManager:
    """Manages discovery and validation of network capture interfaces."""

    @staticmethod
    def is_admin() -> bool:
        """
        Check if current process has Administrator privileges.
        Windows requires elevated permissions or Npcap driver access for raw packet capture.
        """
        try:
            if platform.system() == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    @staticmethod
    def is_npcap_available() -> bool:
        """Check if Npcap / WinPcap packet driver is detected by Scapy."""
        return bool(getattr(conf, "use_pcap", False))

    @staticmethod
    def get_interfaces() -> List[Dict[str, str]]:
        """
        Discover all available network interfaces on the host.
        Returns a sorted list of dictionaries containing:
          - id: Interface object or device name for Scapy sniff
          - name: Friendly name (e.g. 'Wi-Fi')
          - description: Hardware description
          - ip: Assigned IP address
          - mac: Physical MAC address
          - display_name: Clean formatted string for GUI dropdown
          - is_active: Whether it currently holds a non-loopback, non-APIPA IP
        """
        interfaces: List[Dict[str, str]] = []

        try:
            # Query Scapy interface dictionary
            if hasattr(conf, "ifaces"):
                for dev_key, iface in conf.ifaces.items():
                    name = str(getattr(iface, "name", dev_key))
                    desc = str(getattr(iface, "description", ""))
                    ip = str(getattr(iface, "ip", ""))
                    mac = str(getattr(iface, "mac", ""))
                    pcap_name = str(getattr(iface, "pcap_name", dev_key))

                    # Filter out purely internal WAN Miniports that cannot capture real traffic
                    # unless no other interfaces exist
                    is_wan = "WAN Miniport" in desc

                    # Check if interface has active IPv4 connectivity
                    is_active = bool(ip and not ip.startswith("169.254.") and ip != "0.0.0.0")

                    # Construct friendly display name for GUI dropdown
                    display_parts = [name]
                    if ip:
                        display_parts.append(f"[{ip}]")
                    if desc and desc != name and not is_wan:
                        display_parts.append(f"- {desc}")

                    display_name = " ".join(display_parts)

                    interfaces.append(
                        {
                            "id": iface,  # Store Scapy interface object for direct sniff use
                            "dev_name": pcap_name or dev_key,
                            "name": name,
                            "description": desc,
                            "ip": ip,
                            "mac": mac,
                            "display_name": display_name,
                            "is_active": is_active,
                            "is_wan": is_wan,
                        }
                    )
        except Exception as e:
            # Fallback if conf.ifaces encounters an error
            print(f"[Warning] Interface enumeration error: {e}", file=sys.stderr)

        # Sort interfaces so active interfaces (e.g., Wi-Fi, Ethernet with IP) appear first
        interfaces.sort(key=lambda x: (not x["is_active"], x["is_wan"], x["name"]))

        return interfaces

    @classmethod
    def get_default_interface(cls) -> Optional[Dict[str, str]]:
        """
        Identify the most suitable default capture interface.
        Prefers active internet-connected adapter (e.g. Wi-Fi, Ethernet).
        """
        all_ifaces = cls.get_interfaces()
        if not all_ifaces:
            return None

        # 1. Match against Scapy's selected default routing interface (conf.iface)
        try:
            default_scapy_name = getattr(conf.iface, "name", "")
            for iface in all_ifaces:
                if default_scapy_name and (iface["name"] == default_scapy_name or iface["dev_name"] == default_scapy_name):
                    return iface
        except Exception:
            pass

        # 2. Search for active non-virtual adapter (deprioritizing VirtualBox / Host-only)
        for iface in all_ifaces:
            desc_lower = iface["description"].lower()
            if iface["is_active"] and "virtual" not in desc_lower and "loopback" not in iface["name"].lower():
                return iface

        # 3. Search for any active non-loopback adapter
        for iface in all_ifaces:
            if iface["is_active"] and "loopback" not in iface["name"].lower():
                return iface

        # 4. Search for any interface with an IP
        for iface in all_ifaces:
            if iface["ip"] and iface["ip"] != "127.0.0.1":
                return iface

        # 5. Return the first available interface
        return all_ifaces[0]
