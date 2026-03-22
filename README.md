# Network Security Lab

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

Network security tools and Cisco lab configurations. Port scanning, packet analysis, ARP spoofing detection, and hands-on networking labs with QoS and VPN.

> **Educational Disclaimer:** These tools are built for learning purposes. Only use them on networks you own or have explicit written authorization to test. Unauthorized network scanning and packet capture may violate laws in your jurisdiction.

## Tools

| Tool | Description |
|------|-------------|
| [Port Scanner](tools/port_scanner.py) | Multi-threaded TCP/UDP/SYN port scanner with service detection |
| [Packet Sniffer](tools/packet_sniffer.py) | Raw socket packet capture and protocol dissection |
| [ARP Detector](tools/arp_detector.py) | ARP spoofing and MAC-IP anomaly detection |
| [Network Mapper](tools/network_mapper.py) | ICMP ping sweep and topology discovery |
| [DNS Resolver](tools/dns_resolver.py) | DNS lookup, zone transfer, and subdomain enumeration |
| [Banner Grabber](tools/banner_grabber.py) | Service banner grabbing and identification |

## Labs

Hands-on Cisco IOS lab exercises with topology diagrams and full device configurations.

| Lab | Topic | Difficulty |
|-----|-------|------------|
| [Lab 01](labs/lab01-basic-config/) | Basic Router/Switch Configuration | Beginner |
| [Lab 02](labs/lab02-vlan-config/) | VLAN Configuration & Inter-VLAN Routing | Intermediate |
| [Lab 03](labs/lab03-acl-firewall/) | Access Control Lists & Firewall Rules | Intermediate |
| [Lab 04](labs/lab04-qos/) | QoS - Classification, Queuing, Policing | Advanced |
| [Lab 05](labs/lab05-vpn-ipsec/) | Site-to-Site VPN with IPSec | Advanced |

### Lab Topology Example (Lab 02 - VLANs)

```
                         [R1]
                        G0/0.10 (10.0.10.1)
                        G0/0.20 (10.0.20.1)
                        G0/0.30 (10.0.30.1)
                          |
                       (trunk)
                          |
              +---------[SW1]---------+
              |        (trunk)        |
              |           |           |
           [SW2]       [SW3]       [SW4]
            |  |        |  |        |  |
          PC1  PC2    PC3  PC4    PC5  PC6
         V10  V20    V10  V20    V10  V30
```

## Analysis

| Module | Description |
|--------|-------------|
| [PCAP Analyzer](analysis/pcap_analyzer.py) | Protocol stats, top talkers, anomaly detection |
| [Traffic Stats](analysis/traffic_stats.py) | Bandwidth analysis, flow tables, conversations |

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Root/administrator privileges (required for raw sockets: packet sniffer, SYN scan, ARP monitor)
- Cisco Packet Tracer 8.x or GNS3 (for lab exercises)

### Installation

```bash
git clone https://github.com/kadirou12333/network-security-lab.git
cd network-security-lab
pip install -r requirements.txt
```

### Usage Examples

**Port Scanner** -- scan the top 1024 ports on a target:

```bash
python tools/port_scanner.py 192.168.1.1 --ports 1-1024 --threads 100

# SYN scan (requires root)
sudo python tools/port_scanner.py 192.168.1.1 --scan-type syn --ports 1-1024

# UDP scan
python tools/port_scanner.py 192.168.1.1 --scan-type udp --ports 53,123,161
```

**Packet Sniffer** -- capture 50 TCP packets:

```bash
# Linux
sudo python tools/packet_sniffer.py --interface eth0 --count 50 --filter tcp

# Windows (run as Administrator)
python tools/packet_sniffer.py --count 50 --filter tcp --output capture.pcap
```

**ARP Spoofing Detector** -- monitor for ARP attacks:

```bash
sudo python tools/arp_detector.py \
  --gateway-ip 192.168.1.1 \
  --gateway-mac aa:bb:cc:dd:ee:ff \
  --interface eth0
```

**Network Mapper** -- discover hosts on a subnet:

```bash
python tools/network_mapper.py 192.168.1.0/24 --threads 100 --diagram
```

**DNS Resolver** -- enumerate records and subdomains:

```bash
# Query all record types
python tools/dns_resolver.py example.com --all

# Subdomain enumeration
python tools/dns_resolver.py example.com --enumerate --threads 30

# Reverse lookup
python tools/dns_resolver.py 8.8.8.8 --reverse
```

**Banner Grabber** -- identify services:

```bash
python tools/banner_grabber.py 192.168.1.1 --ports 22,80,443,3306
```

**PCAP Analyzer** -- analyze a capture file:

```bash
python analysis/pcap_analyzer.py capture.pcap --top 10 --anomalies --connections
```

## Screenshots

The tools produce rich terminal output when the `rich` library is installed:

- **Port Scanner:** Colored table showing open ports, protocols, and detected services with a progress bar during scanning.
- **Packet Sniffer:** Real-time color-coded packet display with protocol highlighting (TCP=cyan, UDP=green, ICMP=yellow).
- **ARP Detector:** Live alert panel with severity coloring (red=critical, yellow=warning) and a tracked ARP table.
- **Network Mapper:** ASCII topology diagram with host classification and an interactive results table.
- **DNS Resolver:** Formatted record tables with type, TTL, and data columns.
- **PCAP Analyzer:** Multi-section report with protocol distribution, top talkers, and anomaly alerts.

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
network-security-lab/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── tools/                     # Security tools
│   ├── port_scanner.py
│   ├── packet_sniffer.py
│   ├── arp_detector.py
│   ├── network_mapper.py
│   ├── dns_resolver.py
│   └── banner_grabber.py
├── labs/                      # Cisco IOS lab exercises
│   ├── lab01-basic-config/
│   ├── lab02-vlan-config/
│   ├── lab03-acl-firewall/
│   ├── lab04-qos/
│   └── lab05-vpn-ipsec/
├── analysis/                  # Traffic analysis modules
│   ├── pcap_analyzer.py
│   └── traffic_stats.py
└── tests/
    └── test_tools.py
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -m 'Add new tool'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
