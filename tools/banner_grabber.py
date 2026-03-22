#!/usr/bin/env python3
"""
Service Banner Grabber

Connects to network services and reads their initial banners to
identify running software and versions. Supports protocol-specific
probes for HTTP, FTP, SMTP, SSH, and other common services.

Usage:
    python banner_grabber.py <host> [--ports 21,22,80,443] [--timeout 5]

WARNING: Only probe services on hosts you own or have explicit authorization to test.
"""

import socket
import ssl
import sys
import argparse
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Protocol-specific probes sent to trigger banner responses
SERVICE_PROBES = {
    "http": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "https": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "ftp": None,       # FTP sends banner on connect
    "ssh": None,       # SSH sends banner on connect
    "smtp": None,      # SMTP sends banner on connect
    "pop3": None,      # POP3 sends banner on connect
    "imap": None,      # IMAP sends banner on connect
    "mysql": None,     # MySQL sends greeting on connect
    "redis": b"INFO\r\n",
    "http-proxy": b"HEAD / HTTP/1.0\r\n\r\n",
    "rtsp": b"DESCRIBE rtsp://{host}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
}

# Common ports and their expected services
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Patterns to identify services from banners
SERVICE_SIGNATURES = [
    (re.compile(r"SSH-[\d.]+-(.+)", re.I), "SSH"),
    (re.compile(r"220.*FTP", re.I), "FTP"),
    (re.compile(r"220.*SMTP", re.I), "SMTP"),
    (re.compile(r"220.*ESMTP", re.I), "SMTP"),
    (re.compile(r"\+OK.*POP3", re.I), "POP3"),
    (re.compile(r"\* OK.*IMAP", re.I), "IMAP"),
    (re.compile(r"HTTP/[\d.]+\s+\d+", re.I), "HTTP"),
    (re.compile(r"Server:\s*(.+)", re.I), "HTTP Server"),
    (re.compile(r"MySQL", re.I), "MySQL"),
    (re.compile(r"PostgreSQL", re.I), "PostgreSQL"),
    (re.compile(r"redis_version:(.+)", re.I), "Redis"),
    (re.compile(r"MongoDB", re.I), "MongoDB"),
    (re.compile(r"Microsoft.*RDP", re.I), "RDP"),
    (re.compile(r"VNC", re.I), "VNC"),
    (re.compile(r"OpenSSH", re.I), "OpenSSH"),
    (re.compile(r"Apache", re.I), "Apache"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"Microsoft-IIS", re.I), "IIS"),
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"Exim", re.I), "Exim"),
    (re.compile(r"Dovecot", re.I), "Dovecot"),
]


class BannerGrabber:
    """Grab and identify service banners from network hosts."""

    def __init__(self, timeout: float = 5.0, threads: int = 20):
        """
        Initialize the banner grabber.

        Args:
            timeout: Connection and read timeout in seconds.
            threads: Number of concurrent grabbing threads.
        """
        self.timeout = timeout
        self.threads = threads
        self._console = Console() if RICH_AVAILABLE else None

    def grab_banner(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> Dict:
        """
        Connect to a host:port and read the service banner.

        For services that send a banner on connect (SSH, FTP, SMTP),
        simply reads after connecting. For HTTP and similar protocols,
        sends the appropriate probe first.

        Args:
            host: Target hostname or IP.
            port: Target port number.
            timeout: Override default timeout for this connection.

        Returns:
            Dictionary with banner text, identified service, and metadata.
        """
        timeout = timeout or self.timeout
        result = {
            "host": host,
            "port": port,
            "banner": "",
            "service": "",
            "version": "",
            "ssl": False,
            "error": "",
        }

        # Determine if we should use SSL
        use_ssl = port in (443, 465, 636, 993, 995, 8443)
        expected_service = COMMON_PORTS.get(port, "unknown")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            if use_ssl:
                result["ssl"] = True
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

                # Extract SSL certificate info
                try:
                    cert = sock.getpeercert(binary_form=False)
                    if cert:
                        result["ssl_cert"] = {
                            "subject": str(cert.get("subject", "")),
                            "issuer": str(cert.get("issuer", "")),
                            "expires": cert.get("notAfter", ""),
                        }
                except Exception:
                    pass

            # Get the appropriate probe
            probe = self._get_probe(expected_service, host)

            if probe:
                sock.send(probe)

            # Read the banner
            banner_data = b""
            try:
                banner_data = sock.recv(4096)
            except socket.timeout:
                pass

            sock.close()

            if banner_data:
                banner = banner_data.decode("utf-8", errors="replace").strip()
                result["banner"] = banner[:500]  # Limit banner size
                service_info = self.identify_service(banner)
                result["service"] = service_info["service"]
                result["version"] = service_info["version"]
            else:
                result["service"] = expected_service
                result["banner"] = "(no banner)"

        except ConnectionRefusedError:
            result["error"] = "Connection refused"
        except socket.timeout:
            result["error"] = "Connection timed out"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
        except OSError as e:
            result["error"] = str(e)

        return result

    def _get_probe(self, service: str, host: str) -> Optional[bytes]:
        """Get the protocol-specific probe for a service."""
        probe = SERVICE_PROBES.get(service)
        if probe is not None and b"{host}" in probe:
            probe = probe.replace(b"{host}", host.encode("ascii"))
        return probe

    def identify_service(self, banner: str) -> Dict:
        """
        Match a banner string against known service signatures.

        Args:
            banner: Raw banner text from the service.

        Returns:
            Dictionary with 'service' and 'version' keys.
        """
        result = {"service": "unknown", "version": ""}

        for pattern, service_name in SERVICE_SIGNATURES:
            match = pattern.search(banner)
            if match:
                result["service"] = service_name
                if match.groups():
                    result["version"] = match.group(1).strip()
                break

        # Try to extract version from common patterns
        if not result["version"]:
            version_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)*", banner)
            if version_match:
                result["version"] = version_match.group()

        return result

    def scan_common_ports(self, host: str) -> List[Dict]:
        """
        Grab banners from all common service ports on a host.

        Args:
            host: Target hostname or IP.

        Returns:
            List of banner results for all responsive ports.
        """
        results = []
        ports = sorted(COMMON_PORTS.keys())

        print(f"[*] Scanning {len(ports)} common ports on {host}...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.grab_banner, host, port): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if not result["error"]:
                    results.append(result)
                    print(
                        f"  [+] {result['port']:>5}/tcp  "
                        f"{result['service']:<15} "
                        f"{result['version']}"
                    )

        return sorted(results, key=lambda r: r["port"])

    def scan_ports(self, host: str, ports: List[int]) -> List[Dict]:
        """
        Grab banners from a specific list of ports.

        Args:
            host: Target hostname or IP.
            ports: List of port numbers to probe.

        Returns:
            List of banner results.
        """
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.grab_banner, host, port): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if not result["error"]:
                    results.append(result)

        return sorted(results, key=lambda r: r["port"])

    def display_results(self, results: List[Dict]) -> None:
        """Pretty-print banner grabbing results."""
        if not results:
            print("[!] No banners retrieved.")
            return

        if RICH_AVAILABLE and self._console:
            table = Table(
                title="Banner Grab Results",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("Service", style="green")
            table.add_column("Version", style="yellow")
            table.add_column("SSL", justify="center")
            table.add_column("Banner (truncated)", style="dim", max_width=50)

            for r in results:
                ssl_icon = "[green]Yes[/green]" if r["ssl"] else "-"
                banner_short = r["banner"][:80].replace("\n", " ").replace("\r", "")
                table.add_row(
                    str(r["port"]),
                    r["service"],
                    r["version"],
                    ssl_icon,
                    banner_short,
                )

            self._console.print(table)
        else:
            print(f"\n{'Port':<8} {'Service':<15} {'Version':<20} {'Banner'}")
            print("-" * 75)
            for r in results:
                banner_short = r["banner"][:40].replace("\n", " ").replace("\r", "")
                print(
                    f"{r['port']:<8} {r['service']:<15} "
                    f"{r['version']:<20} {banner_short}"
                )

        print(f"\n{len(results)} service(s) identified.")


def main():
    parser = argparse.ArgumentParser(
        description="Service Banner Grabber - Educational Tool",
        epilog="Example: python banner_grabber.py 192.168.1.1 --ports 22,80,443",
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("--ports", "-p", help="Comma-separated ports (default: common ports)")
    parser.add_argument("--timeout", "-t", type=float, default=5.0, help="Timeout in seconds")
    parser.add_argument("--threads", "-T", type=int, default=20, help="Concurrent threads")
    args = parser.parse_args()

    grabber = BannerGrabber(args.timeout, args.threads)

    print(f"\n[*] Banner Grabber targeting {args.host}")
    start = time.time()

    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
        results = grabber.scan_ports(args.host, ports)
    else:
        results = grabber.scan_common_ports(args.host)

    grabber.display_results(results)
    elapsed = time.time() - start
    print(f"Completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
