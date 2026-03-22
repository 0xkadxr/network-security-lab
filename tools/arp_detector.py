#!/usr/bin/env python3
"""
ARP Spoofing Detector

Monitors the network for ARP spoofing attacks by tracking MAC-to-IP
address bindings and detecting anomalies such as duplicate IP addresses,
rapid MAC changes, and gratuitous ARP floods.

Usage:
    python arp_detector.py --gateway-ip 192.168.1.1 --gateway-mac aa:bb:cc:dd:ee:ff

WARNING: Requires root/administrator privileges.
         Only monitor networks you own or have explicit authorization.
"""

import socket
import struct
import sys
import time
import subprocess
import re
import argparse
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ARP operation codes
ARP_REQUEST = 1
ARP_REPLY = 2

# Ethernet type for ARP
ETH_TYPE_ARP = 0x0806


class ARPDetector:
    """Monitor and detect ARP spoofing attacks on the local network."""

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
    ):
        """
        Initialize the ARP spoofing detector.

        Args:
            interface: Network interface to monitor (Linux only).
            gateway_ip: IP address of the default gateway.
            gateway_mac: Known legitimate MAC address of the gateway.
        """
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower() if gateway_mac else None
        self._running = False
        self._lock = threading.Lock()
        self._console = Console() if RICH_AVAILABLE else None

        # ARP table: IP -> {mac, first_seen, last_seen, count}
        self.arp_table: Dict[str, Dict] = {}
        # Alert history
        self.alerts: List[Dict] = []
        # MAC change history: IP -> [(old_mac, new_mac, timestamp)]
        self.mac_changes: Dict[str, List[Tuple]] = {}

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger("arp_detector")

    def start_monitoring(self) -> None:
        """
        Begin monitoring the network for ARP anomalies.

        Opens a raw socket to capture ARP frames and inspects each one
        for signs of spoofing. Runs until stop_monitoring() is called
        or interrupted with Ctrl+C.
        """
        self._running = True

        # Seed the ARP table with the current system table
        system_table = self.get_arp_table()
        for ip, mac in system_table.items():
            self.arp_table[ip] = {
                "mac": mac,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "count": 1,
            }

        self.logger.info("ARP monitoring started")
        if self.gateway_ip and self.gateway_mac:
            self.logger.info(
                f"Gateway: {self.gateway_ip} ({self.gateway_mac})"
            )

        try:
            if sys.platform == "win32":
                self._monitor_windows()
            else:
                self._monitor_linux()
        except PermissionError:
            self.logger.error(
                "Root/administrator privileges required for ARP monitoring."
            )
        except KeyboardInterrupt:
            self.stop_monitoring()

    def _monitor_linux(self) -> None:
        """Capture ARP packets on Linux using AF_PACKET."""
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_TYPE_ARP)
        )
        if self.interface:
            sock.bind((self.interface, 0))
        sock.settimeout(1.0)

        while self._running:
            try:
                raw_data, _ = sock.recvfrom(65535)
                self._process_arp_frame(raw_data)
            except socket.timeout:
                continue

        sock.close()

    def _monitor_windows(self) -> None:
        """
        Monitor ARP table changes on Windows.

        Windows does not easily support raw ARP capture, so we poll
        the system ARP table periodically for changes.
        """
        self.logger.info("Windows mode: polling ARP table every 2 seconds")

        while self._running:
            current_table = self.get_arp_table()
            for ip, mac in current_table.items():
                if ip in self.arp_table:
                    old_mac = self.arp_table[ip]["mac"]
                    if old_mac != mac:
                        self._handle_mac_change(ip, old_mac, mac)
                    self.arp_table[ip]["last_seen"] = datetime.now().isoformat()
                    self.arp_table[ip]["count"] += 1
                else:
                    self.arp_table[ip] = {
                        "mac": mac,
                        "first_seen": datetime.now().isoformat(),
                        "last_seen": datetime.now().isoformat(),
                        "count": 1,
                    }
            time.sleep(2)

    def _process_arp_frame(self, data: bytes) -> None:
        """Parse and analyze an ARP Ethernet frame."""
        if len(data) < 42:  # 14 (eth) + 28 (arp)
            return

        # Ethernet header
        eth_dst = data[0:6]
        eth_src = data[6:12]
        eth_type = struct.unpack("!H", data[12:14])[0]

        if eth_type != ETH_TYPE_ARP:
            return

        # ARP header
        arp_data = data[14:]
        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack(
            "!HHBBH", arp_data[:8]
        )

        sender_mac = ":".join(f"{b:02x}" for b in arp_data[8:14])
        sender_ip = socket.inet_ntoa(arp_data[14:18])
        target_mac = ":".join(f"{b:02x}" for b in arp_data[18:24])
        target_ip = socket.inet_ntoa(arp_data[24:28])

        arp_info = {
            "opcode": opcode,
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
            "timestamp": datetime.now().isoformat(),
        }

        self.detect_spoofing(arp_info)

    def detect_spoofing(self, arp_info: Dict) -> bool:
        """
        Analyze an ARP packet for signs of spoofing.

        Checks for:
        - Gateway MAC address changes (strongest indicator)
        - Any IP-to-MAC mapping changes
        - Gratuitous ARP floods
        - Duplicate IP address claims

        Args:
            arp_info: Parsed ARP packet fields.

        Returns:
            True if spoofing was detected.
        """
        sender_ip = arp_info["sender_ip"]
        sender_mac = arp_info["sender_mac"]
        spoofing_detected = False

        # Check 1: Gateway impersonation
        if self.gateway_ip and sender_ip == self.gateway_ip:
            if self.gateway_mac and sender_mac != self.gateway_mac:
                self.alert(
                    f"CRITICAL: Gateway spoofing detected! "
                    f"{self.gateway_ip} claimed by {sender_mac} "
                    f"(real: {self.gateway_mac})",
                    severity="critical",
                )
                spoofing_detected = True

        # Check 2: MAC address change for known IP
        with self._lock:
            if sender_ip in self.arp_table:
                known_mac = self.arp_table[sender_ip]["mac"]
                if known_mac != sender_mac:
                    self._handle_mac_change(sender_ip, known_mac, sender_mac)
                    spoofing_detected = True

                self.arp_table[sender_ip]["last_seen"] = arp_info["timestamp"]
                self.arp_table[sender_ip]["count"] += 1
            else:
                self.arp_table[sender_ip] = {
                    "mac": sender_mac,
                    "first_seen": arp_info["timestamp"],
                    "last_seen": arp_info["timestamp"],
                    "count": 1,
                }

        # Check 3: Gratuitous ARP flood detection
        if sender_ip in self.arp_table:
            entry = self.arp_table[sender_ip]
            if entry["count"] > 50:
                first = datetime.fromisoformat(entry["first_seen"])
                elapsed = (datetime.now() - first).total_seconds()
                if elapsed > 0 and entry["count"] / elapsed > 10:
                    self.alert(
                        f"WARNING: ARP flood from {sender_ip} ({sender_mac}) "
                        f"- {entry['count']} packets in {elapsed:.0f}s",
                        severity="warning",
                    )

        # Check 4: Duplicate IP detection (different MACs for same IP in replies)
        if arp_info["opcode"] == ARP_REPLY:
            for ip, entry in self.arp_table.items():
                if ip != sender_ip and entry["mac"] == sender_mac:
                    self.alert(
                        f"WARNING: MAC {sender_mac} claims both "
                        f"{ip} and {sender_ip}",
                        severity="warning",
                    )

        return spoofing_detected

    def _handle_mac_change(self, ip: str, old_mac: str, new_mac: str) -> None:
        """Record and alert on a MAC address change for an IP."""
        timestamp = datetime.now().isoformat()

        if ip not in self.mac_changes:
            self.mac_changes[ip] = []
        self.mac_changes[ip].append((old_mac, new_mac, timestamp))

        self.alert(
            f"MAC change for {ip}: {old_mac} -> {new_mac}",
            severity="warning",
        )

        # Update the table
        self.arp_table[ip]["mac"] = new_mac
        self.arp_table[ip]["last_seen"] = timestamp

    def get_arp_table(self) -> Dict[str, str]:
        """
        Read the current ARP table from the operating system.

        Returns:
            Dictionary mapping IP addresses to MAC addresses.
        """
        table = {}

        try:
            if sys.platform == "win32":
                output = subprocess.check_output(
                    ["arp", "-a"], text=True, stderr=subprocess.DEVNULL
                )
                # Parse Windows arp -a output
                for line in output.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}-[\da-f]{2}-[\da-f]{2}"
                        r"-[\da-f]{2}-[\da-f]{2}-[\da-f]{2})",
                        line,
                        re.IGNORECASE,
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace("-", ":").lower()
                        if mac != "ff:ff:ff:ff:ff:ff":
                            table[ip] = mac
            else:
                output = subprocess.check_output(
                    ["arp", "-n"], text=True, stderr=subprocess.DEVNULL
                )
                for line in output.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+\w+\s+"
                        r"([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:"
                        r"[\da-f]{2}:[\da-f]{2}:[\da-f]{2})",
                        line,
                        re.IGNORECASE,
                    )
                    if match:
                        table[match.group(1)] = match.group(2).lower()

        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("Could not read system ARP table")

        return table

    def alert(self, message: str, severity: str = "info") -> None:
        """
        Log and display a security alert.

        Args:
            message: Alert message text.
            severity: Alert level ('info', 'warning', 'critical').
        """
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "message": message,
        }
        self.alerts.append(alert_entry)

        if severity == "critical":
            self.logger.critical(message)
        elif severity == "warning":
            self.logger.warning(message)
        else:
            self.logger.info(message)

        if RICH_AVAILABLE and self._console:
            color_map = {
                "critical": "bold red",
                "warning": "yellow",
                "info": "cyan",
            }
            style = color_map.get(severity, "white")
            self._console.print(
                f"[{style}][{severity.upper()}] {message}[/{style}]"
            )

    def stop_monitoring(self) -> None:
        """Stop the ARP monitoring loop."""
        self._running = False
        self.logger.info("ARP monitoring stopped")

    def display_arp_table(self) -> None:
        """Print the current tracked ARP table."""
        if RICH_AVAILABLE and self._console:
            table = Table(title="Tracked ARP Table", show_header=True)
            table.add_column("IP Address", style="cyan")
            table.add_column("MAC Address", style="green")
            table.add_column("First Seen")
            table.add_column("Last Seen")
            table.add_column("Packets", justify="right")

            for ip in sorted(self.arp_table.keys()):
                entry = self.arp_table[ip]
                mac_style = "green"
                if self.gateway_ip and ip == self.gateway_ip:
                    if self.gateway_mac and entry["mac"] != self.gateway_mac:
                        mac_style = "bold red"
                    else:
                        mac_style = "bold cyan"
                table.add_row(
                    ip,
                    f"[{mac_style}]{entry['mac']}[/{mac_style}]",
                    entry["first_seen"][11:19],
                    entry["last_seen"][11:19],
                    str(entry["count"]),
                )
            self._console.print(table)
        else:
            print("\nTracked ARP Table:")
            print(f"{'IP Address':<18} {'MAC Address':<20} {'Packets':>8}")
            print("-" * 50)
            for ip in sorted(self.arp_table.keys()):
                entry = self.arp_table[ip]
                print(f"{ip:<18} {entry['mac']:<20} {entry['count']:>8}")

    def get_alert_summary(self) -> Dict:
        """Return a summary of all recorded alerts by severity."""
        summary = {"critical": 0, "warning": 0, "info": 0, "total": len(self.alerts)}
        for a in self.alerts:
            summary[a["severity"]] = summary.get(a["severity"], 0) + 1
        return summary


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Detector - Educational Tool",
        epilog="Example: python arp_detector.py --gateway-ip 192.168.1.1 --gateway-mac aa:bb:cc:dd:ee:ff",
    )
    parser.add_argument("--interface", "-i", help="Network interface (Linux)")
    parser.add_argument("--gateway-ip", "-g", help="Gateway IP address")
    parser.add_argument("--gateway-mac", "-m", help="Gateway MAC address")
    args = parser.parse_args()

    detector = ARPDetector(args.interface, args.gateway_ip, args.gateway_mac)

    print("=" * 60)
    print("  ARP Spoofing Detector")
    print("  Press Ctrl+C to stop monitoring")
    print("=" * 60)

    # Display current ARP table
    detector.display_arp_table()
    print()

    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        pass
    finally:
        detector.stop_monitoring()
        print()
        detector.display_arp_table()
        summary = detector.get_alert_summary()
        print(f"\nAlert Summary: {summary['total']} total "
              f"({summary['critical']} critical, {summary['warning']} warnings)")


if __name__ == "__main__":
    main()
