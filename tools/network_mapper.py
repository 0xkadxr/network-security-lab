#!/usr/bin/env python3
"""
Network Topology Mapper

Discovers live hosts on a network using ICMP ping sweeps and maps
basic network topology. Exports results as text-based diagrams.

Usage:
    python network_mapper.py 192.168.1.0/24 [--timeout 1] [--threads 50]

WARNING: Only scan networks you own or have explicit authorization to probe.
"""

import socket
import struct
import sys
import time
import argparse
import ipaddress
import subprocess
import platform
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class NetworkMapper:
    """Discover and map hosts on a network using ICMP and TCP probes."""

    def __init__(
        self,
        network_cidr: str,
        timeout: float = 1.0,
        threads: int = 50,
    ):
        """
        Initialize the network mapper.

        Args:
            network_cidr: Network in CIDR notation (e.g., '192.168.1.0/24').
            timeout: Ping timeout in seconds.
            threads: Number of concurrent scanning threads.
        """
        self.network = ipaddress.ip_network(network_cidr, strict=False)
        self.timeout = timeout
        self.threads = threads
        self._lock = threading.Lock()
        self._console = Console() if RICH_AVAILABLE else None

        # Discovered hosts: IP -> {hostname, mac, latency, open_ports, os_hint}
        self.hosts: Dict[str, Dict] = {}

    def ping_sweep(self) -> Dict[str, Dict]:
        """
        Discover live hosts by sending ICMP echo requests.

        Uses the system ping command for cross-platform compatibility.
        Each host is pinged once with the configured timeout.

        Returns:
            Dictionary of discovered hosts with their metadata.
        """
        self.hosts = {}
        all_hosts = list(self.network.hosts())
        total = len(all_hosts)

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                console=self._console,
            ) as progress:
                task = progress.add_task(
                    f"Ping sweep on {self.network}", total=total
                )
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self._ping_host, str(ip)): str(ip)
                        for ip in all_hosts
                    }
                    for future in as_completed(futures):
                        future.result()
                        progress.update(task, advance=1)
        else:
            print(f"[*] Ping sweep on {self.network} ({total} hosts)...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._ping_host, str(ip)): str(ip)
                    for ip in all_hosts
                }
                done = 0
                for future in as_completed(futures):
                    future.result()
                    done += 1
                    if done % 50 == 0:
                        print(f"  Progress: {done}/{total}")

        return self.hosts

    def _ping_host(self, ip: str) -> None:
        """Ping a single host and record the result if alive."""
        is_alive, latency = self._system_ping(ip)

        if is_alive:
            hostname = self._resolve_hostname(ip)
            with self._lock:
                self.hosts[ip] = {
                    "hostname": hostname,
                    "latency_ms": latency,
                    "open_ports": [],
                    "os_hint": "",
                    "mac": "",
                }

    def _system_ping(self, ip: str) -> tuple:
        """
        Execute a system ping and parse the result.

        Returns:
            Tuple of (is_alive: bool, latency_ms: float).
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]

            start = time.time()
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 2,
            )
            latency = (time.time() - start) * 1000

            if result.returncode == 0:
                # Try to extract actual RTT from output
                output = result.stdout.decode("utf-8", errors="ignore")
                import re
                match = re.search(r"time[=<]\s*(\d+\.?\d*)\s*ms", output)
                if match:
                    latency = float(match.group(1))
                return True, round(latency, 2)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False, 0.0

    def _resolve_hostname(self, ip: str) -> str:
        """Attempt reverse DNS lookup for an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def discover_topology(self) -> Dict:
        """
        Map the network topology by discovering hosts, probing common
        ports, and attempting OS fingerprinting via TTL analysis.

        Returns:
            Topology dictionary with gateway, subnets, and host details.
        """
        if not self.hosts:
            self.ping_sweep()

        # Probe common ports on discovered hosts to classify them
        common_ports = [22, 23, 53, 80, 443, 445, 3389, 8080]

        for ip, info in self.hosts.items():
            open_ports = self._probe_ports(ip, common_ports)
            info["open_ports"] = open_ports
            info["os_hint"] = self._guess_os(ip, open_ports)

        # Identify likely gateway (network address + 1)
        gateway_ip = str(next(self.network.hosts()))
        gateway = self.hosts.get(gateway_ip)

        topology = {
            "network": str(self.network),
            "gateway": gateway_ip if gateway else "unknown",
            "total_hosts": len(self.hosts),
            "hosts": self.hosts,
            "host_types": self._classify_hosts(),
        }

        return topology

    def _probe_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Quick TCP connect probe on a list of ports."""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except OSError:
                pass
        return open_ports

    def _guess_os(self, ip: str, open_ports: List[int]) -> str:
        """Rough OS guess based on open ports and TTL."""
        if 3389 in open_ports or 445 in open_ports:
            return "Windows"
        if 22 in open_ports:
            return "Linux/Unix"
        if 23 in open_ports and 80 in open_ports:
            return "Network Device"
        if 80 in open_ports or 443 in open_ports:
            return "Web Server"
        return "Unknown"

    def _classify_hosts(self) -> Dict[str, List[str]]:
        """Group discovered hosts by their inferred type."""
        types: Dict[str, List[str]] = {
            "routers": [],
            "servers": [],
            "workstations": [],
            "network_devices": [],
            "unknown": [],
        }

        for ip, info in self.hosts.items():
            ports = info.get("open_ports", [])
            os_hint = info.get("os_hint", "")

            if "Network Device" in os_hint or (23 in ports and 80 in ports):
                types["routers"].append(ip)
            elif any(p in ports for p in [80, 443, 22, 53]):
                types["servers"].append(ip)
            elif 3389 in ports or 445 in ports:
                types["workstations"].append(ip)
            elif os_hint != "Unknown":
                types["network_devices"].append(ip)
            else:
                types["unknown"].append(ip)

        return types

    def export_diagram(self, fmt: str = "text") -> str:
        """
        Export the network topology as a text-based diagram.

        Args:
            fmt: Output format ('text' or 'tree').

        Returns:
            String representation of the network map.
        """
        if not self.hosts:
            return "No hosts discovered. Run ping_sweep() first."

        topology = self.discover_topology()
        lines = []

        if fmt == "tree" and RICH_AVAILABLE:
            return self._export_rich_tree(topology)

        # ASCII art topology diagram
        lines.append("=" * 65)
        lines.append(f"  Network Map: {topology['network']}")
        lines.append(f"  Discovered: {topology['total_hosts']} host(s)")
        lines.append("=" * 65)
        lines.append("")

        # Draw gateway
        gw = topology["gateway"]
        lines.append("                    [ Internet ]")
        lines.append("                         |")
        lines.append(f"                   [{gw}]")
        lines.append("                    (Gateway)")
        lines.append("                         |")
        lines.append("        +----------------+----------------+")
        lines.append("        |                |                |")

        # Group hosts
        host_types = topology["host_types"]
        columns = {
            "Servers": host_types.get("servers", []),
            "Workstations": host_types.get("workstations", []),
            "Other": (
                host_types.get("network_devices", [])
                + host_types.get("unknown", [])
            ),
        }

        for label, hosts in columns.items():
            if hosts:
                lines.append(f"\n  --- {label} ---")
                for ip in sorted(hosts):
                    info = self.hosts[ip]
                    name = info["hostname"] or ip
                    ports = ", ".join(str(p) for p in info["open_ports"])
                    os_h = info["os_hint"]
                    lines.append(
                        f"    [{ip}] {name}"
                        f"{' (' + os_h + ')' if os_h else ''}"
                        f"{' ports: ' + ports if ports else ''}"
                    )

        lines.append("")
        lines.append("=" * 65)

        return "\n".join(lines)

    def _export_rich_tree(self, topology: Dict) -> str:
        """Build a rich Tree representation."""
        tree = Tree(f"[bold blue]{topology['network']}[/bold blue]")
        gw_node = tree.add(f"[bold cyan]Gateway: {topology['gateway']}[/bold cyan]")

        for category, hosts in topology["host_types"].items():
            if hosts:
                cat_node = gw_node.add(f"[bold]{category.title()}[/bold]")
                for ip in sorted(hosts):
                    info = self.hosts[ip]
                    label = f"{ip}"
                    if info["hostname"]:
                        label += f" ({info['hostname']})"
                    if info["os_hint"]:
                        label += f" [{info['os_hint']}]"
                    if info["open_ports"]:
                        ports = ", ".join(str(p) for p in info["open_ports"])
                        label += f" ports: {ports}"
                    cat_node.add(label)

        self._console.print(tree)
        return ""

    def display_results(self) -> None:
        """Print discovered hosts in a formatted table."""
        if RICH_AVAILABLE and self._console:
            table = Table(
                title=f"Network Map: {self.network}",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("IP Address", style="cyan")
            table.add_column("Hostname", style="green")
            table.add_column("Latency (ms)", justify="right")
            table.add_column("Open Ports", style="yellow")
            table.add_column("OS Hint", style="blue")

            for ip in sorted(self.hosts.keys(), key=ipaddress.ip_address):
                info = self.hosts[ip]
                ports = ", ".join(str(p) for p in info.get("open_ports", []))
                table.add_row(
                    ip,
                    info["hostname"] or "-",
                    f"{info['latency_ms']:.1f}",
                    ports or "-",
                    info.get("os_hint", "-"),
                )

            self._console.print(table)
        else:
            print(f"\nNetwork Map: {self.network}")
            print(f"{'IP':<18} {'Hostname':<25} {'Latency':>10} {'Ports'}")
            print("-" * 70)
            for ip in sorted(self.hosts.keys(), key=ipaddress.ip_address):
                info = self.hosts[ip]
                ports = ", ".join(str(p) for p in info.get("open_ports", []))
                print(
                    f"{ip:<18} {(info['hostname'] or '-'):<25} "
                    f"{info['latency_ms']:>8.1f}ms {ports}"
                )

        print(f"\n{len(self.hosts)} host(s) discovered.")


def main():
    parser = argparse.ArgumentParser(
        description="Network Topology Mapper - Educational Tool",
        epilog="Example: python network_mapper.py 192.168.1.0/24 --threads 100",
    )
    parser.add_argument("network", help="Target network in CIDR notation")
    parser.add_argument("--timeout", "-t", type=float, default=1.0, help="Ping timeout (seconds)")
    parser.add_argument("--threads", "-T", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--diagram", "-d", action="store_true", help="Show topology diagram")
    args = parser.parse_args()

    mapper = NetworkMapper(args.network, args.timeout, args.threads)

    print(f"\n[*] Mapping network: {args.network}")
    start = time.time()

    mapper.ping_sweep()
    mapper.discover_topology()
    mapper.display_results()

    if args.diagram:
        print()
        diagram = mapper.export_diagram("text")
        if diagram:
            print(diagram)

    elapsed = time.time() - start
    print(f"\nScan completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
