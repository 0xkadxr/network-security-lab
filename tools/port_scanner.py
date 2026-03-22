#!/usr/bin/env python3
"""
TCP/UDP Port Scanner with Service Detection

A multi-threaded port scanner supporting TCP connect, SYN half-open,
and UDP scanning modes. Includes service identification via banner
grabbing and well-known port mapping.

Usage:
    python port_scanner.py <target> [--ports 1-1024] [--threads 100] [--timeout 2]

WARNING: Only scan networks you own or have explicit permission to test.
"""

import socket
import struct
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Well-known port to service mapping
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp",
    194: "irc", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 520: "rip",
    523: "ibm-db2", 530: "rpc", 543: "klogin", 544: "kshell",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 902: "vmware", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1434: "mssql-udp",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 3306: "mysql", 3389: "rdp", 3690: "svn",
    5060: "sip", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6667: "irc", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9090: "zeus-admin",
    9200: "elasticsearch", 27017: "mongodb",
}


class PortScanner:
    """Multi-threaded port scanner with TCP, SYN, and UDP scanning modes."""

    def __init__(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        threads: int = 100,
    ):
        """
        Initialize the port scanner.

        Args:
            target: Target hostname or IP address.
            ports: List of ports to scan. Defaults to top 1024 ports.
            timeout: Socket timeout in seconds.
            threads: Number of concurrent threads.
        """
        self.target = target
        self.target_ip = self._resolve_target(target)
        self.ports = ports or list(range(1, 1025))
        self.timeout = timeout
        self.threads = threads
        self.results: Dict[int, Dict] = {}
        self._lock = threading.Lock()
        self._console = Console() if RICH_AVAILABLE else None

    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {target}")

    def tcp_scan(self) -> Dict[int, Dict]:
        """
        Perform a TCP connect scan on all configured ports.

        Creates a full TCP connection to each port to determine if it is
        open, closed, or filtered. This is the most reliable but also
        the most detectable scanning method.

        Returns:
            Dictionary mapping port numbers to their scan results.
        """
        self.results = {}
        total = len(self.ports)

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
                    f"TCP scanning {self.target_ip}", total=total
                )
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self._tcp_probe, port): port
                        for port in self.ports
                    }
                    for future in as_completed(futures):
                        future.result()
                        progress.update(task, advance=1)
        else:
            print(f"[*] TCP scanning {self.target_ip} ({total} ports)...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._tcp_probe, port): port
                    for port in self.ports
                }
                for future in as_completed(futures):
                    future.result()

        return self.results

    def _tcp_probe(self, port: int) -> None:
        """Probe a single port using TCP connect."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = {"port": port, "protocol": "tcp", "state": "closed", "service": ""}

        try:
            code = sock.connect_ex((self.target_ip, port))
            if code == 0:
                result["state"] = "open"
                result["service"] = self.detect_service(port, sock)
        except socket.timeout:
            result["state"] = "filtered"
        except OSError:
            result["state"] = "filtered"
        finally:
            sock.close()

        if result["state"] != "closed":
            with self._lock:
                self.results[port] = result

    def syn_scan(self) -> Dict[int, Dict]:
        """
        Perform a SYN half-open scan (requires root/admin privileges).

        Sends a SYN packet and analyzes the response without completing
        the three-way handshake. This is stealthier than a full connect
        scan because the connection is never fully established.

        Returns:
            Dictionary mapping port numbers to their scan results.

        Raises:
            PermissionError: If not running with root/admin privileges.
        """
        self.results = {}

        try:
            raw_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
        except PermissionError:
            raise PermissionError(
                "SYN scan requires root/administrator privileges. "
                "Use tcp_scan() as an alternative or run with elevated permissions."
            )

        raw_sock.settimeout(self.timeout)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        source_port = 44321

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold yellow]{task.description}"),
                BarColumn(),
                console=self._console,
            ) as progress:
                task = progress.add_task(
                    f"SYN scanning {self.target_ip}", total=len(self.ports)
                )
                for port in self.ports:
                    self._syn_probe(raw_sock, port, source_port)
                    progress.update(task, advance=1)
        else:
            print(f"[*] SYN scanning {self.target_ip}...")
            for port in self.ports:
                self._syn_probe(raw_sock, port, source_port)

        raw_sock.close()
        return self.results

    def _syn_probe(self, raw_sock: socket.socket, port: int, src_port: int) -> None:
        """Send a SYN packet and check for SYN-ACK response."""
        packet = self._build_syn_packet(self.target_ip, port, src_port)
        result = {"port": port, "protocol": "tcp", "state": "filtered", "service": ""}

        try:
            raw_sock.sendto(packet, (self.target_ip, 0))
            response = raw_sock.recv(1024)

            if len(response) >= 40:
                tcp_header = response[20:40]
                flags = tcp_header[13]
                syn_flag = (flags >> 1) & 1
                ack_flag = (flags >> 4) & 1
                rst_flag = (flags >> 2) & 1

                if syn_flag and ack_flag:
                    result["state"] = "open"
                    result["service"] = COMMON_SERVICES.get(port, "unknown")
                elif rst_flag:
                    result["state"] = "closed"
        except socket.timeout:
            result["state"] = "filtered"
        except OSError:
            pass

        if result["state"] == "open":
            with self._lock:
                self.results[port] = result

    def _build_syn_packet(self, dest_ip: str, dest_port: int, src_port: int) -> bytes:
        """Build a raw TCP SYN packet."""
        # TCP header fields
        seq_num = 0
        ack_num = 0
        data_offset = 5  # 5 * 4 = 20 bytes (no options)
        flags = 0x02  # SYN flag
        window = socket.htons(5840)
        checksum = 0
        urgent_ptr = 0

        offset_flags = (data_offset << 12) | flags
        tcp_header = struct.pack(
            "!HHIIHHH",
            src_port,
            dest_port,
            seq_num,
            ack_num,
            offset_flags,
            window,
            checksum,
        )
        tcp_header += struct.pack("!H", urgent_ptr)

        # Pseudo header for checksum calculation
        src_ip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
        dst_ip = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        pseudo_header = struct.pack(
            "!4s4sBBH", src_ip, dst_ip, placeholder, protocol, tcp_length
        )
        checksum = self._checksum(pseudo_header + tcp_header)

        tcp_header = struct.pack(
            "!HHIIHHH",
            src_port,
            dest_port,
            seq_num,
            ack_num,
            offset_flags,
            window,
            checksum,
        )
        tcp_header += struct.pack("!H", urgent_ptr)

        return tcp_header

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Calculate the Internet checksum (RFC 1071)."""
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    def udp_scan(self) -> Dict[int, Dict]:
        """
        Perform a UDP scan on all configured ports.

        Sends empty UDP datagrams and interprets ICMP responses to
        determine port state. UDP scanning is slower and less reliable
        than TCP scanning because open ports may not respond.

        Returns:
            Dictionary mapping port numbers to their scan results.
        """
        self.results = {}

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]{task.description}"),
                BarColumn(),
                console=self._console,
            ) as progress:
                task = progress.add_task(
                    f"UDP scanning {self.target_ip}", total=len(self.ports)
                )
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self._udp_probe, port): port
                        for port in self.ports
                    }
                    for future in as_completed(futures):
                        future.result()
                        progress.update(task, advance=1)
        else:
            print(f"[*] UDP scanning {self.target_ip}...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._udp_probe, port): port
                    for port in self.ports
                }
                for future in as_completed(futures):
                    future.result()

        return self.results

    def _udp_probe(self, port: int) -> None:
        """Probe a single port using UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        result = {
            "port": port,
            "protocol": "udp",
            "state": "open|filtered",
            "service": "",
        }

        try:
            sock.sendto(b"\x00", (self.target_ip, port))
            data, _ = sock.recvfrom(1024)
            result["state"] = "open"
            result["service"] = COMMON_SERVICES.get(port, "unknown")
        except socket.timeout:
            # No response could mean open or filtered
            result["state"] = "open|filtered"
            result["service"] = COMMON_SERVICES.get(port, "")
        except ConnectionResetError:
            # ICMP port unreachable -> closed
            result["state"] = "closed"
        except OSError:
            result["state"] = "filtered"
        finally:
            sock.close()

        if result["state"] != "closed":
            with self._lock:
                self.results[port] = result

    def scan_range(self, start: int, end: int) -> Dict[int, Dict]:
        """
        Scan a specific range of ports using TCP connect scan.

        Args:
            start: Starting port number (inclusive).
            end: Ending port number (inclusive).

        Returns:
            Dictionary mapping port numbers to their scan results.
        """
        self.ports = list(range(start, end + 1))
        return self.tcp_scan()

    def detect_service(self, port: int, sock: Optional[socket.socket] = None) -> str:
        """
        Identify the service running on a port via banner grabbing.

        Attempts to read a banner from the connected socket first. If no
        banner is available, falls back to the well-known port mapping.

        Args:
            port: The port number to identify.
            sock: An optional already-connected socket to read from.

        Returns:
            The identified service name.
        """
        # Try banner grabbing first
        if sock:
            try:
                sock.settimeout(1.0)
                # Send a probe for HTTP-like services
                if port in (80, 8080, 8000, 8443, 443):
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    return self._parse_banner(banner, port)
            except (socket.timeout, OSError):
                pass

        return COMMON_SERVICES.get(port, "unknown")

    @staticmethod
    def _parse_banner(banner: str, port: int) -> str:
        """Extract service name from a banner string."""
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return f"ssh ({banner.split(chr(10))[0][:40]})"
        if "http" in banner_lower:
            return "http"
        if "ftp" in banner_lower:
            return "ftp"
        if "smtp" in banner_lower:
            return "smtp"
        if "mysql" in banner_lower:
            return "mysql"
        if "postgresql" in banner_lower:
            return "postgresql"
        return COMMON_SERVICES.get(port, banner[:30])

    def display_results(self) -> None:
        """Display scan results in a formatted table."""
        open_ports = {
            k: v
            for k, v in sorted(self.results.items())
            if v["state"] in ("open", "open|filtered")
        }

        if RICH_AVAILABLE:
            table = Table(
                title=f"Scan Results for {self.target} ({self.target_ip})",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("State", style="green")
            table.add_column("Protocol", style="blue")
            table.add_column("Service", style="yellow")

            for port, info in open_ports.items():
                state_style = "green" if info["state"] == "open" else "yellow"
                table.add_row(
                    str(port),
                    f"[{state_style}]{info['state']}[/{state_style}]",
                    info["protocol"],
                    info["service"],
                )

            self._console.print()
            self._console.print(table)
            self._console.print(
                f"\n[bold]{len(open_ports)}[/bold] open port(s) found "
                f"out of [bold]{len(self.ports)}[/bold] scanned."
            )
        else:
            print(f"\nScan Results for {self.target} ({self.target_ip})")
            print("-" * 60)
            print(f"{'PORT':<10} {'STATE':<15} {'PROTO':<8} {'SERVICE'}")
            print("-" * 60)
            for port, info in open_ports.items():
                print(
                    f"{port:<10} {info['state']:<15} {info['protocol']:<8} "
                    f"{info['service']}"
                )
            print("-" * 60)
            print(f"{len(open_ports)} open port(s) out of {len(self.ports)} scanned.")


def parse_ports(port_str: str) -> List[int]:
    """Parse a port specification string like '22,80,443' or '1-1024'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner - Educational Tool",
        epilog="Example: python port_scanner.py 192.168.1.1 --ports 1-1024 --threads 50",
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports", "-p", default="1-1024", help="Ports to scan (e.g., 22,80,443 or 1-1024)"
    )
    parser.add_argument("--timeout", "-t", type=float, default=2.0, help="Timeout in seconds")
    parser.add_argument("--threads", "-T", type=int, default=100, help="Number of threads")
    parser.add_argument(
        "--scan-type",
        "-s",
        choices=["tcp", "syn", "udp"],
        default="tcp",
        help="Scan type (default: tcp)",
    )
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = PortScanner(args.target, ports, args.timeout, args.threads)

    print(f"\nStarting scan against {args.target}")
    print(f"Scan type: {args.scan_type.upper()} | Ports: {len(ports)} | Threads: {args.threads}")
    print(f"{'=' * 60}\n")

    start_time = time.time()

    if args.scan_type == "tcp":
        scanner.tcp_scan()
    elif args.scan_type == "syn":
        scanner.syn_scan()
    elif args.scan_type == "udp":
        scanner.udp_scan()

    elapsed = time.time() - start_time
    scanner.display_results()
    print(f"\nScan completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
