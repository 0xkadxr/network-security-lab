# Lab 05: Site-to-Site VPN with IPSec

## Objective

Configure a site-to-site IPSec VPN tunnel between two Cisco routers to securely connect remote offices over the internet. Implement IKEv1 Phase 1 and Phase 2 negotiations with AES-256 encryption.

## Topology

```
  [LAN A]                                           [LAN B]
 10.0.1.0/24                                      10.0.2.0/24
     |                                                 |
   [SW1]                                             [SW2]
     |                                                 |
   [R1]---------(Internet/ISP)----------[R2]
  G0/0: 10.0.1.1                      G0/0: 10.0.2.1
  G0/1: 203.0.113.1    ============   G0/1: 198.51.100.1
                     IPSec Tunnel
                     Tunnel0: 10.10.10.1 <-> 10.10.10.2
```

## VPN Parameters

| Parameter | Value |
|-----------|-------|
| IKE Version | IKEv1 |
| Phase 1 Encryption | AES-256 |
| Phase 1 Hash | SHA-256 |
| Phase 1 DH Group | 14 (2048-bit) |
| Phase 1 Lifetime | 86400 seconds (24 hours) |
| Phase 2 Encryption | AES-256 |
| Phase 2 Hash | SHA-256 |
| Phase 2 Lifetime | 3600 seconds (1 hour) |
| Pre-shared Key | VPNSecretKey2024! |
| PFS | Group 14 |

## Steps

### 1. Configure ISAKMP (IKE Phase 1)

```
crypto isakmp policy 10
  encryption aes 256
  hash sha256
  authentication pre-share
  group 14
  lifetime 86400
```

### 2. Set Pre-shared Key

```
crypto isakmp key VPNSecretKey2024! address <peer-ip>
```

### 3. Configure IPSec Transform Set (Phase 2)

```
crypto ipsec transform-set AES256-SHA esp-aes 256 esp-sha256-hmac
  mode tunnel
```

### 4. Define Interesting Traffic (Crypto ACL)

```
access-list 100 permit ip 10.0.1.0 0.0.0.255 10.0.2.0 0.0.0.255
```

### 5. Create Crypto Map

```
crypto map SITE-TO-SITE 10 ipsec-isakmp
  set peer <peer-ip>
  set transform-set AES256-SHA
  set pfs group14
  match address 100
```

### 6. Apply Crypto Map to WAN Interface

```
interface GigabitEthernet0/1
  crypto map SITE-TO-SITE
```

See [config.md](config.md) for complete configurations for both routers.

## Verification

```
! Check IKE Phase 1
show crypto isakmp sa

! Check IPSec Phase 2
show crypto ipsec sa

! Check crypto map
show crypto map

! Test connectivity through the tunnel
ping 10.0.2.10 source 10.0.1.1

! Verify encryption counters increase
show crypto ipsec sa | include pkts
```

## Troubleshooting

- If Phase 1 fails: verify pre-shared keys match, check ISAKMP policy parameters
- If Phase 2 fails: verify transform sets match, check crypto ACLs are mirrors
- Use `debug crypto isakmp` and `debug crypto ipsec` for detailed negotiation logs
- Ensure interesting traffic ACLs are symmetric (R1 mirror of R2)
- Check that NAT is not interfering (use NAT exemption if needed)
- Verify routing to peer WAN IP is correct
