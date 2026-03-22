#!/usr/bin/env python3
"""
DNS Resolver and Enumeration Tool

Performs DNS lookups, reverse resolution, zone transfer attempts,
and subdomain enumeration. Implements the DNS protocol using raw
sockets and struct for educational purposes.

Usage:
    python dns_resolver.py example.com [--type A] [--enumerate] [--wordlist subdomains.txt]

WARNING: Only perform DNS enumeration against domains you own or have authorization to test.
"""

import socket
import struct
import random
import sys
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# DNS record type codes
RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "AXFR": 252,
    "ANY": 255,
}

RECORD_TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}

# DNS response codes
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# Default DNS server
DEFAULT_DNS = "8.8.8.8"
DNS_PORT = 53


class DNSResolver:
    """DNS resolver implementing the DNS protocol with struct and sockets."""

    def __init__(self, dns_server: str = DEFAULT_DNS, timeout: float = 5.0):
        """
        Initialize the DNS resolver.

        Args:
            dns_server: DNS server IP address to query.
            timeout: Query timeout in seconds.
        """
        self.dns_server = dns_server
        self.timeout = timeout
        self._console = Console() if RICH_AVAILABLE else None

    def resolve(self, domain: str, record_type: str = "A") -> List[Dict]:
        """
        Resolve a domain name for the specified record type.

        Builds and sends a DNS query packet, then parses the response
        to extract answer records.

        Args:
            domain: Domain name to resolve.
            record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA).

        Returns:
            List of answer record dictionaries.
        """
        qtype = RECORD_TYPES.get(record_type.upper())
        if qtype is None:
            raise ValueError(f"Unsupported record type: {record_type}")

        query = self._build_query(domain, qtype)
        response = self._send_query(query)

        if response is None:
            return []

        return self._parse_response(response)

    def resolve_all(self, domain: str) -> Dict[str, List[Dict]]:
        """
        Query a domain for all common record types.

        Args:
            domain: Domain name to resolve.

        Returns:
            Dictionary mapping record type names to lists of answers.
        """
        results = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            answers = self.resolve(domain, rtype)
            if answers:
                results[rtype] = answers
        return results

    def reverse_lookup(self, ip: str) -> List[Dict]:
        """
        Perform a reverse DNS lookup (PTR record) for an IP address.

        Converts the IP to the in-addr.arpa format and queries for
        PTR records.

        Args:
            ip: IPv4 address to look up.

        Returns:
            List of PTR record dictionaries.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address: {ip}")

        arpa_domain = ".".join(reversed(parts)) + ".in-addr.arpa"
        return self.resolve(arpa_domain, "PTR")

    def zone_transfer(self, domain: str, nameserver: Optional[str] = None) -> List[Dict]:
        """
        Attempt a DNS zone transfer (AXFR) against a nameserver.

        Zone transfers return all records for a domain when the server
        is misconfigured to allow them. Most properly configured servers
        will refuse this request.

        Args:
            domain: Domain to request zone transfer for.
            nameserver: Nameserver to query (uses domain NS if None).

        Returns:
            List of all records if the transfer succeeds, empty list otherwise.
        """
        # Find nameserver if not specified
        if nameserver is None:
            ns_records = self.resolve(domain, "NS")
            if not ns_records:
                print(f"[!] No NS records found for {domain}")
                return []
            nameserver = ns_records[0]["data"]
            # Resolve the nameserver hostname to IP
            ns_ips = self.resolve(nameserver, "A")
            if ns_ips:
                nameserver = ns_ips[0]["data"]

        print(f"[*] Attempting zone transfer for {domain} from {nameserver}...")

        # AXFR uses TCP
        query = self._build_query(domain, RECORD_TYPES["AXFR"])

        # Prepend 2-byte length for TCP DNS
        tcp_query = struct.pack("!H", len(query)) + query

        records = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((nameserver, DNS_PORT))
            sock.send(tcp_query)

            # Read response
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk

            sock.close()

            if len(data) > 2:
                # Skip TCP length prefix
                response = data[2:]
                records = self._parse_response(response)
                if records:
                    print(f"[+] Zone transfer successful! {len(records)} records.")
                else:
                    print("[!] Zone transfer refused or empty response.")
            else:
                print("[!] Zone transfer refused by server.")

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"[!] Zone transfer failed: {e}")

        return records

    def subdomain_enum(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        threads: int = 20,
    ) -> List[Dict]:
        """
        Enumerate subdomains by brute-forcing DNS lookups.

        Args:
            domain: Base domain to enumerate subdomains for.
            wordlist: List of subdomain prefixes to try.
            threads: Number of concurrent lookup threads.

        Returns:
            List of discovered subdomains with their IP addresses.
        """
        if wordlist is None:
            wordlist = self._default_wordlist()

        found = []
        total = len(wordlist)

        print(f"[*] Enumerating subdomains for {domain} ({total} candidates)...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for prefix in wordlist:
                subdomain = f"{prefix}.{domain}"
                futures[executor.submit(self._check_subdomain, subdomain)] = subdomain

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    print(f"  [+] {result['subdomain']} -> {result['ip']}")

        print(f"\n[*] Found {len(found)} subdomain(s).")
        return found

    def _check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Check if a subdomain resolves to an IP address."""
        try:
            answers = self.resolve(subdomain, "A")
            if answers:
                return {
                    "subdomain": subdomain,
                    "ip": answers[0]["data"],
                    "all_ips": [a["data"] for a in answers],
                }
        except Exception:
            pass
        return None

    def _build_query(self, domain: str, qtype: int) -> bytes:
        """
        Build a DNS query packet.

        Constructs the 12-byte header and the question section
        according to RFC 1035.

        Args:
            domain: Domain name to query.
            qtype: DNS record type code.

        Returns:
            Raw bytes of the DNS query packet.
        """
        # Header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        transaction_id = random.randint(0, 0xFFFF)
        flags = 0x0100  # Standard query, recursion desired
        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            flags,
            1,  # questions
            0,  # answers
            0,  # authority
            0,  # additional
        )

        # Question section: QNAME, QTYPE, QCLASS
        qname = self._encode_domain(domain)
        question = qname + struct.pack("!HH", qtype, 1)  # IN class

        return header + question

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        """Encode a domain name into DNS wire format (length-prefixed labels)."""
        encoded = b""
        for label in domain.rstrip(".").split("."):
            encoded += struct.pack("B", len(label)) + label.encode("ascii")
        encoded += b"\x00"  # Root label
        return encoded

    def _send_query(self, query: bytes) -> Optional[bytes]:
        """Send a DNS query via UDP and return the response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query, (self.dns_server, DNS_PORT))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
        except socket.timeout:
            return None
        except OSError:
            return None

    def _parse_response(self, data: bytes) -> List[Dict]:
        """
        Parse a DNS response packet into answer records.

        Args:
            data: Raw DNS response bytes.

        Returns:
            List of parsed answer record dictionaries.
        """
        if len(data) < 12:
            return []

        # Parse header
        (tx_id, flags, qd_count, an_count,
         ns_count, ar_count) = struct.unpack("!HHHHHH", data[:12])

        rcode = flags & 0x0F
        if rcode != 0:
            return []

        offset = 12

        # Skip question section
        for _ in range(qd_count):
            _, offset = self._decode_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        # Parse answer section
        answers = []
        for _ in range(an_count):
            record, offset = self._parse_record(data, offset)
            if record:
                answers.append(record)

        return answers

    def _parse_record(self, data: bytes, offset: int) -> Tuple[Optional[Dict], int]:
        """Parse a single DNS resource record."""
        if offset >= len(data):
            return None, offset

        name, offset = self._decode_name(data, offset)

        if offset + 10 > len(data):
            return None, offset

        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", data[offset : offset + 10]
        )
        offset += 10

        rdata = data[offset : offset + rdlength]
        offset += rdlength

        record = {
            "name": name,
            "type": RECORD_TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
            "type_code": rtype,
            "ttl": ttl,
            "class": rclass,
            "data": self._parse_rdata(rtype, rdata, data, offset - rdlength),
        }

        return record, offset

    def _parse_rdata(self, rtype: int, rdata: bytes, full_data: bytes, rdata_offset: int) -> str:
        """Parse record-type-specific data."""
        if rtype == 1 and len(rdata) == 4:  # A
            return socket.inet_ntoa(rdata)
        elif rtype == 28 and len(rdata) == 16:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            name, _ = self._decode_name(full_data, rdata_offset)
            return name
        elif rtype == 15 and len(rdata) >= 2:  # MX
            preference = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = self._decode_name(full_data, rdata_offset + 2)
            return f"{preference} {exchange}"
        elif rtype == 16:  # TXT
            texts = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                texts.append(rdata[pos : pos + length].decode("utf-8", errors="replace"))
                pos += length
            return " ".join(texts)
        elif rtype == 6:  # SOA
            mname, pos = self._decode_name(full_data, rdata_offset)
            rname, pos = self._decode_name(full_data, pos)
            if pos + 20 <= len(full_data):
                serial, refresh, retry, expire, minimum = struct.unpack(
                    "!IIIII", full_data[pos : pos + 20]
                )
                return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            return f"{mname} {rname}"
        else:
            return rdata.hex()

    def _decode_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """
        Decode a DNS domain name with pointer compression support.

        Handles both inline labels and compressed pointers as specified
        in RFC 1035 section 4.1.4.
        """
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 10
        jumps = 0

        while offset < len(data):
            length = data[offset]

            if length == 0:
                if not jumped:
                    offset += 1
                break

            # Check for pointer (top 2 bits set)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0]
                pointer &= 0x3FFF
                if not jumped:
                    offset += 2
                jumped = True
                offset_save = offset
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    break
                if jumped:
                    offset_save_used = True
                continue

            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

        name = ".".join(labels) if labels else ""

        if jumped:
            return name, original_offset + 2 if (data[original_offset] & 0xC0) == 0xC0 else offset
        return name, offset

    @staticmethod
    def _default_wordlist() -> List[str]:
        """Return a default subdomain wordlist for enumeration."""
        return [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
            "mx", "mx1", "mx2", "relay",
            "api", "app", "dev", "staging", "test", "beta", "demo",
            "admin", "portal", "login", "auth", "sso",
            "vpn", "remote", "gateway", "proxy",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "cdn", "static", "assets", "media", "img", "images",
            "git", "svn", "repo", "ci", "jenkins", "build",
            "monitor", "status", "health", "nagios", "grafana",
            "docs", "wiki", "help", "support", "blog",
            "shop", "store", "cart", "pay", "billing",
            "cloud", "aws", "azure", "gcp",
            "internal", "intranet", "corp", "office",
            "backup", "bak", "old", "new", "v2",
        ]

    def display_results(self, domain: str, results: Dict[str, List[Dict]]) -> None:
        """Pretty-print DNS resolution results."""
        if RICH_AVAILABLE and self._console:
            table = Table(
                title=f"DNS Records for {domain}",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Type", style="cyan", width=8)
            table.add_column("Name", style="green")
            table.add_column("TTL", justify="right")
            table.add_column("Data", style="yellow")

            for rtype, records in results.items():
                for rec in records:
                    table.add_row(
                        rec["type"],
                        rec["name"],
                        str(rec["ttl"]),
                        rec["data"],
                    )

            self._console.print(table)
        else:
            print(f"\nDNS Records for {domain}")
            print("-" * 70)
            print(f"{'Type':<8} {'Name':<30} {'TTL':>8}  {'Data'}")
            print("-" * 70)
            for rtype, records in results.items():
                for rec in records:
                    print(
                        f"{rec['type']:<8} {rec['name']:<30} "
                        f"{rec['ttl']:>8}  {rec['data']}"
                    )


def main():
    parser = argparse.ArgumentParser(
        description="DNS Resolver & Enumeration Tool - Educational",
        epilog="Example: python dns_resolver.py example.com --all --enumerate",
    )
    parser.add_argument("domain", help="Domain to resolve")
    parser.add_argument("--type", "-t", default="A", help="Record type (A, AAAA, MX, NS, TXT, etc.)")
    parser.add_argument("--all", "-a", action="store_true", help="Query all common record types")
    parser.add_argument("--reverse", "-r", action="store_true", help="Reverse lookup (input is an IP)")
    parser.add_argument("--enumerate", "-e", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--zone-transfer", "-z", action="store_true", help="Attempt zone transfer")
    parser.add_argument("--wordlist", "-w", help="Subdomain wordlist file")
    parser.add_argument("--dns-server", "-s", default=DEFAULT_DNS, help="DNS server to query")
    parser.add_argument("--threads", "-T", type=int, default=20, help="Threads for enumeration")
    args = parser.parse_args()

    resolver = DNSResolver(args.dns_server)

    if args.reverse:
        print(f"\n[*] Reverse lookup for {args.domain}")
        results = resolver.reverse_lookup(args.domain)
        for r in results:
            print(f"  {r['data']}")
    elif args.all:
        results = resolver.resolve_all(args.domain)
        resolver.display_results(args.domain, results)
    elif args.zone_transfer:
        records = resolver.zone_transfer(args.domain)
        for r in records:
            print(f"  {r['type']:<8} {r['name']:<30} {r['data']}")
    elif args.enumerate:
        wordlist = None
        if args.wordlist:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        resolver.subdomain_enum(args.domain, wordlist, args.threads)
    else:
        results = resolver.resolve(args.domain, args.type)
        if results:
            resolver.display_results(args.domain, {args.type: results})
        else:
            print(f"[!] No {args.type} records found for {args.domain}")


if __name__ == "__main__":
    main()
