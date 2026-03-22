#!/usr/bin/env python3
"""
Traffic Statistics Module

Computes network traffic statistics from parsed packet data including
bandwidth utilization, flow analysis, and time-series metrics.

Usage:
    python traffic_stats.py capture.pcap [--interval 60]
"""

import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class TrafficStats:
    """Compute and display traffic statistics from packet captures."""

    def __init__(self, packets: Optional[List[Dict]] = None):
        """
        Initialize with a list of parsed packet dictionaries.

        Args:
            packets: List of packet dicts (from PcapAnalyzer.load_pcap).
        """
        self.packets = packets or []
        self._console = Console() if RICH_AVAILABLE else None

    def bandwidth_over_time(self, interval: float = 1.0) -> List[Dict]:
        """
        Calculate bandwidth usage in time intervals.

        Groups packets into fixed-duration buckets and sums the bytes
        in each to produce a throughput timeline.

        Args:
            interval: Bucket duration in seconds.

        Returns:
            List of dicts with time, bytes, packets, and bits_per_sec.
        """
        if not self.packets:
            return []

        start_time = self.packets[0].get("timestamp", 0)
        buckets: Dict[int, Dict] = defaultdict(
            lambda: {"bytes": 0, "packets": 0}
        )

        for pkt in self.packets:
            ts = pkt.get("timestamp", 0)
            bucket_idx = int((ts - start_time) / interval)
            buckets[bucket_idx]["bytes"] += pkt.get("length", 0)
            buckets[bucket_idx]["packets"] += 1

        if not buckets:
            return []

        max_bucket = max(buckets.keys())
        results = []
        for i in range(max_bucket + 1):
            b = buckets.get(i, {"bytes": 0, "packets": 0})
            results.append({
                "time_offset": i * interval,
                "bytes": b["bytes"],
                "packets": b["packets"],
                "bits_per_sec": (b["bytes"] * 8) / interval,
                "mbps": (b["bytes"] * 8) / interval / 1_000_000,
            })

        return results

    def flow_table(self) -> List[Dict]:
        """
        Build a 5-tuple flow table from the packet data.

        Groups packets by (src_ip, dst_ip, src_port, dst_port, protocol)
        and computes per-flow statistics.

        Returns:
            List of flow dictionaries sorted by byte count (descending).
        """
        flows: Dict[str, Dict] = {}

        for pkt in self.packets:
            src = pkt.get("src_ip", "")
            dst = pkt.get("dst_ip", "")
            sport = pkt.get("src_port", 0)
            dport = pkt.get("dst_port", 0)
            proto = pkt.get("protocol", "?")

            if not src or not dst:
                continue

            key = f"{src}:{sport}->{dst}:{dport}/{proto}"

            if key not in flows:
                flows[key] = {
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": proto,
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": pkt.get("timestamp", 0),
                    "last_seen": pkt.get("timestamp", 0),
                }

            flow = flows[key]
            flow["packets"] += 1
            flow["bytes"] += pkt.get("length", 0)
            flow["last_seen"] = pkt.get("timestamp", 0)

        result = sorted(flows.values(), key=lambda f: f["bytes"], reverse=True)

        for flow in result:
            duration = flow["last_seen"] - flow["first_seen"]
            flow["duration"] = max(duration, 0.001)
            flow["avg_bps"] = (flow["bytes"] * 8) / flow["duration"]

        return result

    def port_statistics(self) -> Dict[str, List[Tuple[int, int]]]:
        """
        Count traffic by destination port, split by protocol.

        Returns:
            Dictionary with 'tcp' and 'udp' keys, each containing a
            list of (port, packet_count) tuples sorted by count.
        """
        tcp_ports: Counter = Counter()
        udp_ports: Counter = Counter()

        for pkt in self.packets:
            dport = pkt.get("dst_port")
            if dport is None:
                continue

            if pkt.get("protocol") == "TCP":
                tcp_ports[dport] += 1
            elif pkt.get("protocol") == "UDP":
                udp_ports[dport] += 1

        return {
            "tcp": tcp_ports.most_common(20),
            "udp": udp_ports.most_common(20),
        }

    def conversation_matrix(self, top_n: int = 15) -> List[Dict]:
        """
        Build a conversation matrix of IP pairs.

        Args:
            top_n: Number of top conversations to return.

        Returns:
            List of conversation dictionaries sorted by total bytes.
        """
        conversations: Dict[str, Dict] = {}

        for pkt in self.packets:
            src = pkt.get("src_ip")
            dst = pkt.get("dst_ip")
            if not src or not dst:
                continue

            # Normalize key (alphabetical order)
            pair = tuple(sorted([src, dst]))
            key = f"{pair[0]} <-> {pair[1]}"

            if key not in conversations:
                conversations[key] = {
                    "ip_a": pair[0],
                    "ip_b": pair[1],
                    "packets_a_to_b": 0,
                    "packets_b_to_a": 0,
                    "bytes_a_to_b": 0,
                    "bytes_b_to_a": 0,
                }

            conv = conversations[key]
            length = pkt.get("length", 0)

            if src == pair[0]:
                conv["packets_a_to_b"] += 1
                conv["bytes_a_to_b"] += length
            else:
                conv["packets_b_to_a"] += 1
                conv["bytes_b_to_a"] += length

        result = sorted(
            conversations.values(),
            key=lambda c: c["bytes_a_to_b"] + c["bytes_b_to_a"],
            reverse=True,
        )

        for conv in result:
            conv["total_packets"] = conv["packets_a_to_b"] + conv["packets_b_to_a"]
            conv["total_bytes"] = conv["bytes_a_to_b"] + conv["bytes_b_to_a"]

        return result[:top_n]

    def summary(self) -> Dict:
        """
        Compute an overall traffic summary.

        Returns:
            Dictionary with total packets, bytes, duration, average throughput,
            unique IPs, and protocol breakdown.
        """
        if not self.packets:
            return {"total_packets": 0}

        total_bytes = sum(p.get("length", 0) for p in self.packets)
        timestamps = [p.get("timestamp", 0) for p in self.packets if p.get("timestamp")]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

        src_ips = set(p.get("src_ip") for p in self.packets if p.get("src_ip"))
        dst_ips = set(p.get("dst_ip") for p in self.packets if p.get("dst_ip"))
        all_ips = src_ips | dst_ips

        protos = Counter(p.get("protocol", "unknown") for p in self.packets)

        return {
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 3),
            "avg_bps": (total_bytes * 8) / max(duration, 0.001),
            "avg_pps": len(self.packets) / max(duration, 0.001),
            "unique_ips": len(all_ips),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "protocols": dict(protos.most_common()),
            "avg_packet_size": total_bytes / len(self.packets) if self.packets else 0,
        }

    def display(self) -> None:
        """Print a comprehensive statistics report."""
        stats = self.summary()

        if not stats.get("total_packets"):
            print("[!] No packet data available.")
            return

        if RICH_AVAILABLE and self._console:
            self._console.print("\n[bold]Traffic Statistics Summary[/bold]")
            self._console.print(f"  Packets:   {stats['total_packets']:,}")
            self._console.print(f"  Bytes:     {stats['total_bytes']:,}")
            self._console.print(f"  Duration:  {stats['duration_seconds']:.3f}s")
            self._console.print(f"  Avg Rate:  {stats['avg_bps']/1_000_000:.2f} Mbps")
            self._console.print(f"  Unique IPs: {stats['unique_ips']}")
            self._console.print()

            # Port statistics
            ports = self.port_statistics()
            if ports["tcp"]:
                pt = Table(title="Top TCP Destination Ports", show_header=True)
                pt.add_column("Port", style="cyan", justify="right")
                pt.add_column("Packets", justify="right")
                for port, count in ports["tcp"][:10]:
                    pt.add_row(str(port), str(count))
                self._console.print(pt)

            # Conversations
            convos = self.conversation_matrix(10)
            if convos:
                ct = Table(title="Top Conversations", show_header=True)
                ct.add_column("IP A", style="green")
                ct.add_column("IP B", style="green")
                ct.add_column("Packets", justify="right")
                ct.add_column("Bytes", justify="right")
                for c in convos:
                    ct.add_row(
                        c["ip_a"], c["ip_b"],
                        str(c["total_packets"]),
                        f"{c['total_bytes']:,}",
                    )
                self._console.print(ct)
        else:
            print(f"\nTraffic Statistics Summary")
            print(f"  Packets:    {stats['total_packets']:,}")
            print(f"  Bytes:      {stats['total_bytes']:,}")
            print(f"  Duration:   {stats['duration_seconds']:.3f}s")
            print(f"  Avg Rate:   {stats['avg_bps']/1_000_000:.2f} Mbps")
            print(f"  Unique IPs: {stats['unique_ips']}")

            ports = self.port_statistics()
            if ports["tcp"]:
                print("\nTop TCP Ports:")
                for port, count in ports["tcp"][:10]:
                    print(f"  {port:>6}  {count:>8} packets")


def main():
    parser = argparse.ArgumentParser(description="Traffic Statistics Analyzer")
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--interval", "-i", type=float, default=1.0, help="Time interval for bandwidth stats")
    args = parser.parse_args()

    # Import pcap analyzer for loading
    from pcap_analyzer import PcapAnalyzer

    analyzer = PcapAnalyzer()
    try:
        packets = analyzer.load_pcap(args.pcap)
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    stats = TrafficStats(packets)
    stats.display()

    # Bandwidth over time
    bw = stats.bandwidth_over_time(args.interval)
    if bw:
        print(f"\nBandwidth ({args.interval}s intervals):")
        for b in bw[:30]:
            bar = "#" * int(b["mbps"] * 10)
            print(f"  {b['time_offset']:>8.1f}s  {b['mbps']:.2f} Mbps  {bar}")


if __name__ == "__main__":
    main()
