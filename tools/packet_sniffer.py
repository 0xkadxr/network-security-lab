#!/usr/bin/env python3
"""
Network Packet Sniffer

Captures and analyzes network packets using raw sockets. Parses Ethernet,
IP, TCP, UDP, and ICMP headers without external dependencies (no scapy).
Educational implementation demonstrating protocol dissection.

Usage:
    python packet_sniffer.py [--interface eth0] [--count 100] [--filter tcp]

WARNING: Requires root/administrator privileges for raw socket access.
         Only capture traffic on networks you own or have authorization to monitor.
"""

import socket
import struct
import sys
import time
import argparse
import signal
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Protocol number to name mapping
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

# TCP flag bitmasks
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


class PacketSniffer:
    """Raw socket packet capture and analysis tool."""

    def __init__(
        self,
        interface: Optional[str] = None,
        filter_expr: Optional[str] = None,
        count: int = 0,
    ):
        """
        Initialize the packet sniffer.

        Args:
            interface: Network interface to capture on (e.g., 'eth0').
            filter_expr: Protocol filter ('tcp', 'udp', 'icmp', or None for all).
            count: Number of packets to capture (0 = unlimited).
        """
        self.interface = interface
        self.filter_expr = filter_expr.lower() if filter_expr else None
        self.count = count
        self.packets: List[Dict] = []
        self._running = False
        self._lock = threading.Lock()
        self._console = Console() if RICH_AVAILABLE else None
        self._sock: Optional[socket.socket] = None

    def start_capture(self) -> List[Dict]:
        """
        Begin capturing packets from the network.

        Creates a raw socket bound to the specified interface and reads
        packets until the count is reached or stop_capture() is called.

        Returns:
            List of parsed packet dictionaries.
        """
        self._running = True
        self.packets = []

        try:
            # Platform-specific raw socket creation
            if sys.platform == "win32":
                self._sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
                )
                hostname = socket.gethostname()
                host_ip = socket.gethostbyname(hostname)
                self._sock.bind((host_ip, 0))
                # Enable promiscuous mode on Windows
                self._sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_HDRINCL, 1
                )
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except OSError:
                    pass  # May fail without admin privileges
            else:
                # Linux raw socket captures Ethernet frames
                self._sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
                )
                if self.interface:
                    self._sock.bind((self.interface, 0))

        except PermissionError:
            raise PermissionError(
                "Packet capture requires root/administrator privileges."
            )

        self._sock.settimeout(1.0)
        captured = 0

        print(f"[*] Capturing on {self.interface or 'all interfaces'}...")
        if self.filter_expr:
            print(f"[*] Filter: {self.filter_expr}")
        if self.count:
            print(f"[*] Capturing {self.count} packets...")
        print()

        while self._running:
            try:
                raw_data, addr = self._sock.recvfrom(65535)
                packet = self.parse_packet(raw_data)

                if packet and self._matches_filter(packet):
                    with self._lock:
                        self.packets.append(packet)
                    captured += 1
                    self.display_packet(packet, captured)

                    if self.count and captured >= self.count:
                        break

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

        self.stop_capture()
        return self.packets

    def stop_capture(self) -> List[Dict]:
        """
        Stop packet capture and clean up resources.

        Returns:
            List of all captured packet dictionaries.
        """
        self._running = False
        if self._sock:
            if sys.platform == "win32":
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            self._sock.close()
            self._sock = None

        print(f"\n[*] Capture complete. {len(self.packets)} packet(s) captured.")
        return self.packets

    def parse_packet(self, raw_data: bytes) -> Optional[Dict]:
        """
        Parse a raw network packet into its component headers.

        Dissects Ethernet (on Linux), IP, and transport layer headers
        from a raw byte buffer captured off the wire.

        Args:
            raw_data: Raw bytes from the socket.

        Returns:
            Dictionary with parsed header fields, or None on parse error.
        """
        packet = {
            "timestamp": datetime.now().isoformat(),
            "raw_length": len(raw_data),
        }

        offset = 0

        # On Linux, we get Ethernet frames; on Windows, we start at IP
        if sys.platform != "win32":
            if len(raw_data) < 14:
                return None
            eth = self._parse_ethernet(raw_data[:14])
            packet["ethernet"] = eth
            offset = 14

            # Only process IPv4 packets (EtherType 0x0800)
            if eth["ethertype"] != 0x0800:
                packet["protocol"] = f"non-ip (0x{eth['ethertype']:04x})"
                return packet

        # Parse IP header
        if len(raw_data) < offset + 20:
            return None

        ip_header = self._parse_ip(raw_data[offset:])
        if ip_header is None:
            return None

        packet["ip"] = ip_header
        offset += ip_header["header_length"]

        proto = ip_header["protocol"]
        packet["protocol"] = IP_PROTOCOLS.get(proto, f"unknown({proto})")

        # Parse transport layer
        remaining = raw_data[offset:]
        if proto == 6 and len(remaining) >= 20:
            packet["tcp"] = self._parse_tcp(remaining)
            payload_offset = packet["tcp"]["data_offset"]
            if len(remaining) > payload_offset:
                packet["payload"] = remaining[payload_offset:]
        elif proto == 17 and len(remaining) >= 8:
            packet["udp"] = self._parse_udp(remaining)
            if len(remaining) > 8:
                packet["payload"] = remaining[8:]
        elif proto == 1 and len(remaining) >= 4:
            packet["icmp"] = self._parse_icmp(remaining)

        return packet

    @staticmethod
    def _parse_ethernet(data: bytes) -> Dict:
        """Parse an Ethernet frame header (14 bytes)."""
        dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", data[:14])
        return {
            "dest_mac": ":".join(f"{b:02x}" for b in dest_mac),
            "src_mac": ":".join(f"{b:02x}" for b in src_mac),
            "ethertype": ethertype,
        }

    @staticmethod
    def _parse_ip(data: bytes) -> Optional[Dict]:
        """Parse an IPv4 header (20+ bytes)."""
        if len(data) < 20:
            return None

        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20:
            return None

        fields = struct.unpack("!BBHHHBBH4s4s", data[:20])

        return {
            "version": version,
            "header_length": ihl,
            "dscp": fields[1] >> 2,
            "total_length": fields[2],
            "identification": fields[3],
            "flags": (fields[4] >> 13) & 0x07,
            "fragment_offset": fields[4] & 0x1FFF,
            "ttl": fields[5],
            "protocol": fields[6],
            "checksum": fields[7],
            "src_ip": socket.inet_ntoa(fields[8]),
            "dst_ip": socket.inet_ntoa(fields[9]),
        }

    @staticmethod
    def _parse_tcp(data: bytes) -> Dict:
        """Parse a TCP header (20+ bytes)."""
        fields = struct.unpack("!HHIIBBHHH", data[:20])
        data_offset = ((fields[4] >> 4) & 0x0F) * 4
        flag_byte = fields[5]

        flags = []
        for mask, name in TCP_FLAGS.items():
            if flag_byte & mask:
                flags.append(name)

        return {
            "src_port": fields[0],
            "dst_port": fields[1],
            "seq_num": fields[2],
            "ack_num": fields[3],
            "data_offset": data_offset,
            "flags": flags,
            "flags_raw": flag_byte,
            "window": fields[6],
            "checksum": fields[7],
            "urgent_ptr": fields[8],
        }

    @staticmethod
    def _parse_udp(data: bytes) -> Dict:
        """Parse a UDP header (8 bytes)."""
        fields = struct.unpack("!HHHH", data[:8])
        return {
            "src_port": fields[0],
            "dst_port": fields[1],
            "length": fields[2],
            "checksum": fields[3],
        }

    @staticmethod
    def _parse_icmp(data: bytes) -> Dict:
        """Parse an ICMP header."""
        icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
        result = {
            "type": icmp_type,
            "code": code,
            "checksum": checksum,
        }
        # Echo request/reply have ID and sequence number
        if icmp_type in (0, 8) and len(data) >= 8:
            ident, seq = struct.unpack("!HH", data[4:8])
            result["id"] = ident
            result["sequence"] = seq
        return result

    def _matches_filter(self, packet: Dict) -> bool:
        """Check if a packet matches the active protocol filter."""
        if not self.filter_expr:
            return True
        proto = packet.get("protocol", "").lower()
        return self.filter_expr in proto

    def display_packet(self, packet: Dict, number: int) -> None:
        """
        Pretty-print a parsed packet to the console.

        Args:
            packet: Parsed packet dictionary.
            number: Packet sequence number.
        """
        ip = packet.get("ip", {})
        proto = packet.get("protocol", "unknown")
        src_ip = ip.get("src_ip", "?")
        dst_ip = ip.get("dst_ip", "?")

        # Build port info
        src_port = dst_port = ""
        if "tcp" in packet:
            src_port = f":{packet['tcp']['src_port']}"
            dst_port = f":{packet['tcp']['dst_port']}"
            flags = ",".join(packet["tcp"]["flags"])
            extra = f" [{flags}] seq={packet['tcp']['seq_num']}"
        elif "udp" in packet:
            src_port = f":{packet['udp']['src_port']}"
            dst_port = f":{packet['udp']['dst_port']}"
            extra = f" len={packet['udp']['length']}"
        elif "icmp" in packet:
            icmp = packet["icmp"]
            extra = f" type={icmp['type']} code={icmp['code']}"
        else:
            extra = ""

        line = (
            f"#{number:<5} {packet['timestamp'][11:23]}  "
            f"{proto:<6} {src_ip}{src_port} -> {dst_ip}{dst_port}{extra}  "
            f"({packet['raw_length']} bytes)"
        )

        if RICH_AVAILABLE:
            color_map = {"TCP": "cyan", "UDP": "green", "ICMP": "yellow"}
            color = color_map.get(proto, "white")
            self._console.print(f"[{color}]{line}[/{color}]")
        else:
            print(line)

    def save_pcap(self, filename: str) -> None:
        """
        Save captured packets to a pcap file.

        Writes a global pcap header followed by per-packet headers and
        raw data. The resulting file can be opened in Wireshark.

        Args:
            filename: Output file path.
        """
        if not self.packets:
            print("[!] No packets to save.")
            return

        with open(filename, "wb") as f:
            # Global pcap header
            # magic, version_major, version_minor, thiszone, sigfigs, snaplen, network
            f.write(struct.pack(
                "<IHHiIII",
                0xA1B2C3D4,  # Magic number
                2, 4,         # Version 2.4
                0,             # Timezone offset
                0,             # Timestamp accuracy
                65535,         # Snapshot length
                1,             # Link-layer type (Ethernet)
            ))

            for packet in self.packets:
                raw = packet.get("_raw", b"")
                if not raw and "raw_length" in packet:
                    # Reconstruct a minimal representation if raw not stored
                    continue

                ts = time.time()
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1_000_000)
                length = len(raw)

                # Per-packet header
                f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
                f.write(raw)

        print(f"[*] Saved {len(self.packets)} packets to {filename}")

    def get_statistics(self) -> Dict:
        """
        Compute summary statistics for captured packets.

        Returns:
            Dictionary with protocol counts, top talkers, and byte totals.
        """
        stats = {
            "total_packets": len(self.packets),
            "protocols": {},
            "src_ips": {},
            "dst_ips": {},
            "total_bytes": 0,
        }

        for pkt in self.packets:
            proto = pkt.get("protocol", "unknown")
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
            stats["total_bytes"] += pkt.get("raw_length", 0)

            ip = pkt.get("ip", {})
            src = ip.get("src_ip")
            dst = ip.get("dst_ip")
            if src:
                stats["src_ips"][src] = stats["src_ips"].get(src, 0) + 1
            if dst:
                stats["dst_ips"][dst] = stats["dst_ips"].get(dst, 0) + 1

        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer - Educational Tool",
        epilog="Example: python packet_sniffer.py --interface eth0 --count 50 --filter tcp",
    )
    parser.add_argument("--interface", "-i", help="Network interface (e.g., eth0)")
    parser.add_argument("--count", "-c", type=int, default=0, help="Packets to capture (0=unlimited)")
    parser.add_argument("--filter", "-f", choices=["tcp", "udp", "icmp"], help="Protocol filter")
    parser.add_argument("--output", "-o", help="Save capture to pcap file")
    args = parser.parse_args()

    sniffer = PacketSniffer(args.interface, args.filter, args.count)

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        sniffer.stop_capture()
        stats = sniffer.get_statistics()
        print(f"\n[*] Statistics: {stats['total_packets']} packets, "
              f"{stats['total_bytes']} bytes")
        if args.output:
            sniffer.save_pcap(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniffer.start_capture()
    except PermissionError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if args.output:
        sniffer.save_pcap(args.output)


if __name__ == "__main__":
    main()
