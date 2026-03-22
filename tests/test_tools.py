"""
Unit tests for network security tools.

These tests validate parsing logic, data structures, and utility functions
without requiring network access or elevated privileges.
"""

import struct
import socket
import os
import sys
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.port_scanner import PortScanner, parse_ports, COMMON_SERVICES
from tools.dns_resolver import DNSResolver, RECORD_TYPES
from tools.banner_grabber import BannerGrabber, SERVICE_SIGNATURES
from tools.packet_sniffer import PacketSniffer, TCP_FLAGS, IP_PROTOCOLS
from tools.arp_detector import ARPDetector
from tools.network_mapper import NetworkMapper
from analysis.pcap_analyzer import PcapAnalyzer
from analysis.traffic_stats import TrafficStats


# ──────────────────────────────────────────────
# Port Scanner Tests
# ──────────────────────────────────────────────

class TestPortScanner:
    """Tests for PortScanner utility methods."""

    def test_parse_ports_single(self):
        assert parse_ports("80") == [80]

    def test_parse_ports_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_parse_ports_range(self):
        result = parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_parse_ports_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_parse_ports_deduplication(self):
        result = parse_ports("80,80,80")
        assert result == [80]

    def test_common_services_mapping(self):
        assert COMMON_SERVICES[22] == "ssh"
        assert COMMON_SERVICES[80] == "http"
        assert COMMON_SERVICES[443] == "https"
        assert COMMON_SERVICES[3306] == "mysql"

    def test_scanner_init_with_ip(self):
        scanner = PortScanner("127.0.0.1", [80], timeout=1.0)
        assert scanner.target_ip == "127.0.0.1"
        assert scanner.ports == [80]
        assert scanner.timeout == 1.0

    def test_scanner_default_ports(self):
        scanner = PortScanner("127.0.0.1")
        assert len(scanner.ports) == 1024
        assert scanner.ports[0] == 1
        assert scanner.ports[-1] == 1024

    def test_scanner_invalid_host(self):
        with pytest.raises(ValueError, match="Cannot resolve"):
            PortScanner("this.host.definitely.does.not.exist.invalid")

    def test_checksum_calculation(self):
        """Verify Internet checksum on known data."""
        data = b"\x00\x01\x00\x02\x00\x03\x00\x04"
        result = PortScanner._checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_parse_banner_ssh(self):
        banner = "SSH-2.0-OpenSSH_8.9"
        result = PortScanner._parse_banner(banner, 22)
        assert "ssh" in result.lower()

    def test_parse_banner_http(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx"
        result = PortScanner._parse_banner(banner, 80)
        assert result == "http"


# ──────────────────────────────────────────────
# DNS Resolver Tests
# ──────────────────────────────────────────────

class TestDNSResolver:
    """Tests for DNS protocol encoding and decoding."""

    def test_record_types_defined(self):
        assert RECORD_TYPES["A"] == 1
        assert RECORD_TYPES["AAAA"] == 28
        assert RECORD_TYPES["MX"] == 15
        assert RECORD_TYPES["NS"] == 2
        assert RECORD_TYPES["TXT"] == 16

    def test_encode_domain(self):
        encoded = DNSResolver._encode_domain("example.com")
        # Should be: \x07example\x03com\x00
        assert encoded == b"\x07example\x03com\x00"

    def test_encode_domain_subdomain(self):
        encoded = DNSResolver._encode_domain("www.example.com")
        assert encoded == b"\x03www\x07example\x03com\x00"

    def test_encode_domain_trailing_dot(self):
        encoded = DNSResolver._encode_domain("example.com.")
        assert encoded == b"\x07example\x03com\x00"

    def test_build_query_structure(self):
        resolver = DNSResolver()
        query = resolver._build_query("example.com", 1)  # A record
        # Header is 12 bytes + QNAME + 4 bytes (QTYPE + QCLASS)
        assert len(query) >= 12
        # Check QDCOUNT = 1
        qdcount = struct.unpack("!H", query[4:6])[0]
        assert qdcount == 1

    def test_build_query_flags(self):
        resolver = DNSResolver()
        query = resolver._build_query("test.com", 1)
        flags = struct.unpack("!H", query[2:4])[0]
        # Standard query with recursion desired
        assert flags == 0x0100

    def test_default_wordlist(self):
        wordlist = DNSResolver._default_wordlist()
        assert isinstance(wordlist, list)
        assert len(wordlist) > 20
        assert "www" in wordlist
        assert "mail" in wordlist
        assert "api" in wordlist

    def test_unsupported_record_type(self):
        resolver = DNSResolver()
        with pytest.raises(ValueError, match="Unsupported"):
            resolver.resolve("example.com", "INVALID")


# ──────────────────────────────────────────────
# Banner Grabber Tests
# ──────────────────────────────────────────────

class TestBannerGrabber:
    """Tests for banner identification logic."""

    def test_identify_ssh(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert result["service"] == "SSH"
        assert "OpenSSH" in result["version"]

    def test_identify_http_nginx(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
        assert result["service"] == "HTTP"

    def test_identify_ftp(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("220 ProFTPD 1.3.6 Server ready")
        assert result["service"] == "FTP"

    def test_identify_smtp(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("220 mail.example.com ESMTP Postfix")
        assert result["service"] == "SMTP"

    def test_identify_mysql(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("MySQL 8.0.32")
        assert result["service"] == "MySQL"

    def test_identify_unknown(self):
        grabber = BannerGrabber()
        result = grabber.identify_service("some random banner text")
        assert result["service"] == "unknown"

    def test_common_ports_defined(self):
        from tools.banner_grabber import COMMON_PORTS
        assert 22 in COMMON_PORTS
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS


# ──────────────────────────────────────────────
# Packet Sniffer Tests
# ──────────────────────────────────────────────

class TestPacketSniffer:
    """Tests for packet parsing logic."""

    def test_parse_ethernet(self):
        # Construct a 14-byte Ethernet header
        eth_data = (
            b"\xff\xff\xff\xff\xff\xff"  # Destination MAC (broadcast)
            b"\xaa\xbb\xcc\xdd\xee\xff"  # Source MAC
            b"\x08\x00"                    # EtherType (IPv4)
        )
        result = PacketSniffer._parse_ethernet(eth_data)
        assert result["dest_mac"] == "ff:ff:ff:ff:ff:ff"
        assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["ethertype"] == 0x0800

    def test_parse_ip_header(self):
        # Minimal valid IPv4 header (20 bytes)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,         # Version 4, IHL 5
            0x00,         # DSCP/ECN
            40,           # Total length
            0x1234,       # Identification
            0x0000,       # Flags/Fragment
            64,           # TTL
            6,            # Protocol (TCP)
            0x0000,       # Checksum
            socket.inet_aton("192.168.1.1"),
            socket.inet_aton("10.0.0.1"),
        )
        result = PacketSniffer._parse_ip(ip_header)
        assert result is not None
        assert result["version"] == 4
        assert result["src_ip"] == "192.168.1.1"
        assert result["dst_ip"] == "10.0.0.1"
        assert result["ttl"] == 64
        assert result["protocol"] == 6

    def test_parse_tcp_header(self):
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            12345,   # Source port
            80,      # Destination port
            100,     # Sequence number
            0,       # Ack number
            0x50,    # Data offset (5 words)
            0x12,    # Flags: SYN+ACK
            65535,   # Window
            0,       # Checksum
            0,       # Urgent pointer
        )
        result = PacketSniffer._parse_tcp(tcp_header)
        assert result["src_port"] == 12345
        assert result["dst_port"] == 80
        assert "SYN" in result["flags"]
        assert "ACK" in result["flags"]

    def test_parse_udp_header(self):
        udp_header = struct.pack("!HHHH", 53, 1024, 100, 0)
        result = PacketSniffer._parse_udp(udp_header)
        assert result["src_port"] == 53
        assert result["dst_port"] == 1024
        assert result["length"] == 100

    def test_parse_icmp_header(self):
        icmp_data = struct.pack("!BBH", 8, 0, 0)  # Echo request
        result = PacketSniffer._parse_icmp(icmp_data)
        assert result["type"] == 8
        assert result["code"] == 0

    def test_ip_protocols_mapping(self):
        assert IP_PROTOCOLS[6] == "TCP"
        assert IP_PROTOCOLS[17] == "UDP"
        assert IP_PROTOCOLS[1] == "ICMP"

    def test_tcp_flags_mapping(self):
        assert TCP_FLAGS[0x02] == "SYN"
        assert TCP_FLAGS[0x10] == "ACK"
        assert TCP_FLAGS[0x01] == "FIN"


# ──────────────────────────────────────────────
# ARP Detector Tests
# ──────────────────────────────────────────────

class TestARPDetector:
    """Tests for ARP detection logic."""

    def test_init(self):
        detector = ARPDetector(
            gateway_ip="192.168.1.1",
            gateway_mac="AA:BB:CC:DD:EE:FF",
        )
        assert detector.gateway_ip == "192.168.1.1"
        assert detector.gateway_mac == "aa:bb:cc:dd:ee:ff"

    def test_detect_gateway_spoofing(self):
        detector = ARPDetector(
            gateway_ip="192.168.1.1",
            gateway_mac="aa:bb:cc:dd:ee:ff",
        )
        arp_info = {
            "opcode": 2,
            "sender_mac": "11:22:33:44:55:66",
            "sender_ip": "192.168.1.1",
            "target_mac": "ff:ff:ff:ff:ff:ff",
            "target_ip": "192.168.1.100",
            "timestamp": "2024-01-01T00:00:00",
        }
        result = detector.detect_spoofing(arp_info)
        assert result is True
        assert len(detector.alerts) > 0
        assert detector.alerts[0]["severity"] == "critical"

    def test_no_spoofing_legitimate(self):
        detector = ARPDetector(
            gateway_ip="192.168.1.1",
            gateway_mac="aa:bb:cc:dd:ee:ff",
        )
        arp_info = {
            "opcode": 2,
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "sender_ip": "192.168.1.1",
            "target_mac": "11:22:33:44:55:66",
            "target_ip": "192.168.1.100",
            "timestamp": "2024-01-01T00:00:00",
        }
        result = detector.detect_spoofing(arp_info)
        assert result is False

    def test_mac_change_detection(self):
        detector = ARPDetector()
        # First ARP from an IP
        arp1 = {
            "opcode": 2,
            "sender_mac": "aa:bb:cc:dd:ee:01",
            "sender_ip": "10.0.0.5",
            "target_mac": "ff:ff:ff:ff:ff:ff",
            "target_ip": "10.0.0.1",
            "timestamp": "2024-01-01T00:00:00",
        }
        detector.detect_spoofing(arp1)

        # Same IP, different MAC
        arp2 = {
            "opcode": 2,
            "sender_mac": "aa:bb:cc:dd:ee:02",
            "sender_ip": "10.0.0.5",
            "target_mac": "ff:ff:ff:ff:ff:ff",
            "target_ip": "10.0.0.1",
            "timestamp": "2024-01-01T00:00:01",
        }
        result = detector.detect_spoofing(arp2)
        assert result is True

    def test_alert_summary(self):
        detector = ARPDetector()
        detector.alert("test critical", severity="critical")
        detector.alert("test warning", severity="warning")
        detector.alert("test info", severity="info")
        summary = detector.get_alert_summary()
        assert summary["total"] == 3
        assert summary["critical"] == 1
        assert summary["warning"] == 1


# ──────────────────────────────────────────────
# Network Mapper Tests
# ──────────────────────────────────────────────

class TestNetworkMapper:
    """Tests for network mapper utility methods."""

    def test_init_cidr(self):
        mapper = NetworkMapper("192.168.1.0/24")
        assert str(mapper.network) == "192.168.1.0/24"

    def test_init_strict_false(self):
        # Should not raise even with host bits set
        mapper = NetworkMapper("192.168.1.50/24")
        assert str(mapper.network) == "192.168.1.0/24"

    def test_host_count(self):
        mapper = NetworkMapper("10.0.0.0/24")
        hosts = list(mapper.network.hosts())
        assert len(hosts) == 254

    def test_small_network(self):
        mapper = NetworkMapper("10.0.0.0/30")
        hosts = list(mapper.network.hosts())
        assert len(hosts) == 2


# ──────────────────────────────────────────────
# PCAP Analyzer Tests
# ──────────────────────────────────────────────

class TestPcapAnalyzer:
    """Tests for pcap analysis methods."""

    def _make_packets(self) -> List:
        """Create sample packet data for testing."""
        return [
            {
                "number": 1, "timestamp": 1000.0, "length": 100,
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "protocol": "TCP", "src_port": 12345, "dst_port": 80,
                "tcp_flags": ["SYN"], "time_str": "00:00:00.000",
            },
            {
                "number": 2, "timestamp": 1000.1, "length": 60,
                "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                "protocol": "TCP", "src_port": 80, "dst_port": 12345,
                "tcp_flags": ["SYN", "ACK"], "time_str": "00:00:00.100",
            },
            {
                "number": 3, "timestamp": 1000.2, "length": 200,
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3",
                "protocol": "UDP", "src_port": 5000, "dst_port": 53,
                "time_str": "00:00:00.200",
            },
            {
                "number": 4, "timestamp": 1000.3, "length": 64,
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "protocol": "ICMP", "icmp_type": 8, "icmp_code": 0,
                "time_str": "00:00:00.300",
            },
        ]

    def test_protocol_distribution(self):
        analyzer = PcapAnalyzer()
        analyzer.packets = self._make_packets()
        dist = analyzer.protocol_distribution()
        assert dist["TCP"] == 2
        assert dist["UDP"] == 1
        assert dist["ICMP"] == 1

    def test_top_talkers(self):
        analyzer = PcapAnalyzer()
        analyzer.packets = self._make_packets()
        talkers = analyzer.top_talkers(n=3)
        # 10.0.0.1 appears in all 4 packets as src or dst
        assert talkers[0]["ip"] == "10.0.0.1"
        assert talkers[0]["packets"] == 4

    def test_connection_summary(self):
        analyzer = PcapAnalyzer()
        analyzer.packets = self._make_packets()
        conns = analyzer.connection_summary()
        assert len(conns) == 1  # Only 1 TCP connection pair
        assert conns[0]["packets"] == 2

    def test_detect_anomalies_clean(self):
        analyzer = PcapAnalyzer()
        analyzer.packets = self._make_packets()
        anomalies = analyzer.detect_anomalies()
        # Small dataset should not trigger anomalies
        assert isinstance(anomalies, list)

    def test_load_nonexistent_file(self):
        analyzer = PcapAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.load_pcap("/nonexistent/file.pcap")


# ──────────────────────────────────────────────
# Traffic Stats Tests
# ──────────────────────────────────────────────

class TestTrafficStats:
    """Tests for traffic statistics computation."""

    def _make_packets(self) -> List:
        return [
            {"timestamp": 1000.0, "length": 100, "src_ip": "10.0.0.1",
             "dst_ip": "10.0.0.2", "protocol": "TCP", "dst_port": 80},
            {"timestamp": 1000.5, "length": 200, "src_ip": "10.0.0.2",
             "dst_ip": "10.0.0.1", "protocol": "TCP", "dst_port": 12345},
            {"timestamp": 1001.0, "length": 150, "src_ip": "10.0.0.1",
             "dst_ip": "10.0.0.3", "protocol": "UDP", "dst_port": 53},
        ]

    def test_summary(self):
        stats = TrafficStats(self._make_packets())
        s = stats.summary()
        assert s["total_packets"] == 3
        assert s["total_bytes"] == 450
        assert s["unique_ips"] == 3

    def test_bandwidth_over_time(self):
        stats = TrafficStats(self._make_packets())
        bw = stats.bandwidth_over_time(interval=1.0)
        assert len(bw) >= 1
        # First second should have packets
        assert bw[0]["packets"] >= 1

    def test_flow_table(self):
        stats = TrafficStats(self._make_packets())
        flows = stats.flow_table()
        assert len(flows) == 3  # 3 unique flows

    def test_port_statistics(self):
        stats = TrafficStats(self._make_packets())
        ports = stats.port_statistics()
        assert "tcp" in ports
        assert "udp" in ports

    def test_conversation_matrix(self):
        stats = TrafficStats(self._make_packets())
        convos = stats.conversation_matrix()
        assert len(convos) >= 1

    def test_empty_packets(self):
        stats = TrafficStats([])
        s = stats.summary()
        assert s["total_packets"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
