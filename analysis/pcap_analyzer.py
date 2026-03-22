#!/usr/bin/env python3
"""
PCAP File Analyzer

Reads and analyzes pcap capture files. Provides protocol distribution,
top talkers, connection summaries, and basic anomaly detection.

Usage:
    python pcap_analyzer.py capture.pcap [--top 10] [--anomalies]
"""

import struct
import socket
import sys
import argparse
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Pcap magic numbers
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1

# IP protocol numbers
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}

# TCP flags
TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
    0x10: "ACK", 0x20: "URG",
}


class PcapAnalyzer:
    """Analyze pcap capture files for network traffic insights."""

    def __init__(self):
        self.packets: List[Dict] = []
        self.file_info: Dict = {}
        self._console = Console() if RICH_AVAILABLE else None

    def load_pcap(self, filename: str) -> List[Dict]:
        """
        Read and parse a pcap file into a list of packet dictionaries.

        Supports standard pcap format (libpcap). Parses Ethernet, IP,
        TCP, and UDP headers from each captured frame.

        Args:
            filename: Path to the pcap file.

        Returns:
            List of parsed packet dictionaries.

        Raises:
            FileNotFoundError: If the pcap file does not exist.
            ValueError: If the file is not a valid pcap.
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        self.packets = []

        with open(filename, "rb") as f:
            # Read global header (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                raise ValueError("File too small to be a valid pcap")

            magic = struct.unpack("<I", global_header[:4])[0]

            if magic == PCAP_MAGIC_LE:
                endian = "<"
            elif magic == PCAP_MAGIC_BE:
                endian = ">"
            else:
                raise ValueError(
                    f"Invalid pcap magic: 0x{struct.unpack('<I', global_header[:4])[0]:08x}"
                )

            version_major, version_minor = struct.unpack(
                f"{endian}HH", global_header[4:8]
            )
            _, _, snaplen, link_type = struct.unpack(
                f"{endian}iIII", global_header[8:24]
            )

            self.file_info = {
                "filename": filename,
                "version": f"{version_major}.{version_minor}",
                "snaplen": snaplen,
                "link_type": link_type,
                "filesize": os.path.getsize(filename),
            }

            # Read packets
            pkt_num = 0
            while True:
                # Packet header (16 bytes)
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{endian}IIII", pkt_header
                )

                raw_data = f.read(incl_len)
                if len(raw_data) < incl_len:
                    break

                pkt_num += 1
                timestamp = ts_sec + ts_usec / 1_000_000
                packet = self._parse_packet(raw_data, timestamp, pkt_num, link_type)
                if packet:
                    packet["original_length"] = orig_len
                    self.packets.append(packet)

        self.file_info["packet_count"] = len(self.packets)
        return self.packets

    def _parse_packet(
        self, data: bytes, timestamp: float, number: int, link_type: int
    ) -> Optional[Dict]:
        """Parse a raw packet from the pcap data."""
        packet = {
            "number": number,
            "timestamp": timestamp,
            "time_str": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3],
            "length": len(data),
        }

        offset = 0

        # Ethernet (link_type 1)
        if link_type == 1:
            if len(data) < 14:
                return packet
            dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
            src_mac = ":".join(f"{b:02x}" for b in data[6:12])
            ethertype = struct.unpack("!H", data[12:14])[0]
            packet["src_mac"] = src_mac
            packet["dst_mac"] = dst_mac
            packet["ethertype"] = ethertype
            offset = 14

            if ethertype != 0x0800:  # Not IPv4
                packet["protocol"] = f"0x{ethertype:04x}"
                return packet

        # Raw IP (link_type 101)
        # offset stays 0

        # Parse IP header
        if len(data) < offset + 20:
            return packet

        version_ihl = data[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20:
            packet["protocol"] = "non-ipv4"
            return packet

        ip_fields = struct.unpack("!BBHHHBBH4s4s", data[offset : offset + 20])
        packet["src_ip"] = socket.inet_ntoa(ip_fields[8])
        packet["dst_ip"] = socket.inet_ntoa(ip_fields[9])
        packet["ttl"] = ip_fields[5]
        packet["ip_id"] = ip_fields[3]

        proto_num = ip_fields[6]
        packet["protocol"] = PROTOCOLS.get(proto_num, f"proto-{proto_num}")
        packet["protocol_num"] = proto_num

        transport_offset = offset + ihl

        # TCP
        if proto_num == 6 and len(data) >= transport_offset + 20:
            tcp = struct.unpack("!HHIIBBHHH", data[transport_offset : transport_offset + 20])
            packet["src_port"] = tcp[0]
            packet["dst_port"] = tcp[1]
            packet["tcp_seq"] = tcp[2]
            packet["tcp_ack"] = tcp[3]
            flag_byte = tcp[5]
            packet["tcp_flags"] = [
                name for mask, name in TCP_FLAGS.items() if flag_byte & mask
            ]
            packet["tcp_window"] = tcp[6]

        # UDP
        elif proto_num == 17 and len(data) >= transport_offset + 8:
            udp = struct.unpack("!HHHH", data[transport_offset : transport_offset + 8])
            packet["src_port"] = udp[0]
            packet["dst_port"] = udp[1]
            packet["udp_length"] = udp[2]

        # ICMP
        elif proto_num == 1 and len(data) >= transport_offset + 4:
            icmp_type, icmp_code = struct.unpack(
                "!BB", data[transport_offset : transport_offset + 2]
            )
            packet["icmp_type"] = icmp_type
            packet["icmp_code"] = icmp_code

        return packet

    def protocol_distribution(self, packets: Optional[List[Dict]] = None) -> Dict[str, int]:
        """
        Count packets by protocol.

        Args:
            packets: Packet list (uses loaded packets if None).

        Returns:
            Dictionary mapping protocol names to packet counts.
        """
        pkts = packets or self.packets
        counter = Counter(p.get("protocol", "unknown") for p in pkts)
        return dict(counter.most_common())

    def top_talkers(self, packets: Optional[List[Dict]] = None, n: int = 10) -> List[Dict]:
        """
        Find the most active IP addresses by packet count and byte volume.

        Args:
            packets: Packet list (uses loaded packets if None).
            n: Number of top talkers to return.

        Returns:
            List of dictionaries with IP, packet count, and byte count.
        """
        pkts = packets or self.packets
        ip_packets: Counter = Counter()
        ip_bytes: Counter = Counter()

        for p in pkts:
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            length = p.get("length", 0)

            if src:
                ip_packets[src] += 1
                ip_bytes[src] += length
            if dst:
                ip_packets[dst] += 1
                ip_bytes[dst] += length

        results = []
        for ip, count in ip_packets.most_common(n):
            results.append({
                "ip": ip,
                "packets": count,
                "bytes": ip_bytes[ip],
            })

        return results

    def connection_summary(self, packets: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Summarize TCP connections (unique src:port -> dst:port flows).

        Args:
            packets: Packet list (uses loaded packets if None).

        Returns:
            List of connection summaries with packet counts and flags seen.
        """
        pkts = packets or self.packets
        connections: Dict[str, Dict] = {}

        for p in pkts:
            if p.get("protocol") != "TCP":
                continue

            src = p.get("src_ip", "?")
            dst = p.get("dst_ip", "?")
            sport = p.get("src_port", 0)
            dport = p.get("dst_port", 0)

            # Normalize connection key (smaller IP:port first)
            key = tuple(sorted([(src, sport), (dst, dport)]))
            key_str = f"{key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}"

            if key_str not in connections:
                connections[key_str] = {
                    "connection": key_str,
                    "packets": 0,
                    "bytes": 0,
                    "flags_seen": set(),
                    "first_seen": p.get("time_str", ""),
                    "last_seen": p.get("time_str", ""),
                }

            conn = connections[key_str]
            conn["packets"] += 1
            conn["bytes"] += p.get("length", 0)
            conn["flags_seen"].update(p.get("tcp_flags", []))
            conn["last_seen"] = p.get("time_str", "")

        # Convert sets to sorted lists for serialization
        result = sorted(connections.values(), key=lambda c: c["packets"], reverse=True)
        for c in result:
            c["flags_seen"] = sorted(c["flags_seen"])

        return result

    def detect_anomalies(self, packets: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Perform basic anomaly detection on captured traffic.

        Checks for:
        - Port scan patterns (single source hitting many destination ports)
        - SYN flood indicators (high SYN-to-SYN/ACK ratio)
        - Unusual TTL values (potential spoofing or tunneling)
        - Large ICMP packets (potential exfiltration or ping of death)
        - DNS amplification indicators

        Args:
            packets: Packet list (uses loaded packets if None).

        Returns:
            List of anomaly dictionaries with type, severity, and description.
        """
        pkts = packets or self.packets
        anomalies = []

        # Track per-source stats
        src_dst_ports: Dict[str, set] = defaultdict(set)
        syn_count: Dict[str, int] = defaultdict(int)
        synack_count: Dict[str, int] = defaultdict(int)
        ttl_values: Dict[str, set] = defaultdict(set)

        for p in pkts:
            src = p.get("src_ip", "")
            dst = p.get("dst_ip", "")
            dst_port = p.get("dst_port")
            flags = p.get("tcp_flags", [])
            ttl = p.get("ttl")

            if src and dst_port:
                src_dst_ports[src].add((dst, dst_port))

            if "SYN" in flags and "ACK" not in flags:
                syn_count[src] += 1
            if "SYN" in flags and "ACK" in flags:
                synack_count[dst] += 1

            if src and ttl:
                ttl_values[src].add(ttl)

            # Large ICMP
            if p.get("protocol") == "ICMP" and p.get("length", 0) > 1000:
                anomalies.append({
                    "type": "large_icmp",
                    "severity": "medium",
                    "source": src,
                    "description": f"Large ICMP packet ({p['length']} bytes) from {src} to {dst}",
                })

            # DNS amplification check (large DNS responses)
            if (p.get("protocol") == "UDP" and p.get("src_port") == 53
                    and p.get("length", 0) > 512):
                anomalies.append({
                    "type": "dns_amplification",
                    "severity": "medium",
                    "source": src,
                    "description": f"Large DNS response ({p['length']} bytes) from {src}",
                })

        # Port scan detection (more than 20 unique destination ports)
        for src, dst_ports in src_dst_ports.items():
            unique_ports = len(set(dp for _, dp in dst_ports))
            if unique_ports > 20:
                anomalies.append({
                    "type": "port_scan",
                    "severity": "high",
                    "source": src,
                    "description": (
                        f"Potential port scan from {src}: "
                        f"{unique_ports} unique destination ports"
                    ),
                })

        # SYN flood detection
        for src, count in syn_count.items():
            ack_count = synack_count.get(src, 0)
            if count > 50 and (ack_count == 0 or count / max(ack_count, 1) > 5):
                anomalies.append({
                    "type": "syn_flood",
                    "severity": "high",
                    "source": src,
                    "description": (
                        f"Potential SYN flood from {src}: "
                        f"{count} SYNs, {ack_count} SYN/ACKs"
                    ),
                })

        # TTL anomaly (multiple TTLs from same source)
        for src, ttls in ttl_values.items():
            if len(ttls) > 3:
                anomalies.append({
                    "type": "ttl_anomaly",
                    "severity": "low",
                    "source": src,
                    "description": (
                        f"Multiple TTL values from {src}: {sorted(ttls)} "
                        f"(possible spoofing or load balancing)"
                    ),
                })

        return anomalies

    def display_summary(self) -> None:
        """Print a comprehensive analysis summary."""
        if not self.packets:
            print("[!] No packets loaded.")
            return

        protos = self.protocol_distribution()
        talkers = self.top_talkers(n=10)
        anomalies = self.detect_anomalies()

        if RICH_AVAILABLE and self._console:
            self._console.print(f"\n[bold]File:[/bold] {self.file_info.get('filename')}")
            self._console.print(f"[bold]Packets:[/bold] {len(self.packets)}")
            self._console.print()

            # Protocol table
            pt = Table(title="Protocol Distribution", show_header=True)
            pt.add_column("Protocol", style="cyan")
            pt.add_column("Packets", justify="right")
            pt.add_column("Percentage", justify="right")
            for proto, count in protos.items():
                pct = count / len(self.packets) * 100
                pt.add_row(proto, str(count), f"{pct:.1f}%")
            self._console.print(pt)

            # Top talkers table
            tt = Table(title="Top Talkers", show_header=True)
            tt.add_column("IP Address", style="green")
            tt.add_column("Packets", justify="right")
            tt.add_column("Bytes", justify="right")
            for t in talkers:
                tt.add_row(t["ip"], str(t["packets"]), f"{t['bytes']:,}")
            self._console.print(tt)

            # Anomalies
            if anomalies:
                at = Table(title="Anomalies Detected", show_header=True)
                at.add_column("Severity", style="red")
                at.add_column("Type")
                at.add_column("Source", style="yellow")
                at.add_column("Description")
                for a in anomalies:
                    at.add_row(a["severity"].upper(), a["type"], a["source"], a["description"])
                self._console.print(at)
            else:
                self._console.print("[green]No anomalies detected.[/green]")
        else:
            print(f"\nFile: {self.file_info.get('filename')}")
            print(f"Packets: {len(self.packets)}")
            print("\nProtocol Distribution:")
            for proto, count in protos.items():
                pct = count / len(self.packets) * 100
                print(f"  {proto:<10} {count:>8}  ({pct:.1f}%)")
            print("\nTop Talkers:")
            for t in talkers:
                print(f"  {t['ip']:<18} {t['packets']:>8} pkts  {t['bytes']:>12,} bytes")
            if anomalies:
                print(f"\nAnomalies ({len(anomalies)}):")
                for a in anomalies:
                    print(f"  [{a['severity'].upper()}] {a['description']}")


def main():
    parser = argparse.ArgumentParser(
        description="PCAP File Analyzer - Educational Tool",
        epilog="Example: python pcap_analyzer.py capture.pcap --top 10 --anomalies",
    )
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--top", "-t", type=int, default=10, help="Number of top talkers")
    parser.add_argument("--connections", "-c", action="store_true", help="Show TCP connections")
    parser.add_argument("--anomalies", "-a", action="store_true", help="Run anomaly detection")
    args = parser.parse_args()

    analyzer = PcapAnalyzer()

    print(f"[*] Loading {args.pcap}...")
    try:
        packets = analyzer.load_pcap(args.pcap)
        print(f"[*] Loaded {len(packets)} packets")
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    analyzer.display_summary()

    if args.connections:
        connections = analyzer.connection_summary()
        print(f"\nTCP Connections ({len(connections)}):")
        for c in connections[:20]:
            flags = ", ".join(c["flags_seen"])
            print(f"  {c['connection']}  {c['packets']} pkts  [{flags}]")

    if args.anomalies:
        anomalies = analyzer.detect_anomalies()
        print(f"\nAnomalies: {len(anomalies)} found")
        for a in anomalies:
            print(f"  [{a['severity'].upper()}] {a['description']}")


if __name__ == "__main__":
    main()
