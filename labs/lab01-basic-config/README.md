# Lab 01: Basic Router and Switch Configuration

## Objective

Configure basic settings on a Cisco router and switch, including hostnames, passwords, IP addressing, and SSH access. Verify connectivity between devices.

## Topology

```
    [PC1] ---- [SW1] ---- [R1] ---- [SW2] ---- [PC2]
  10.0.1.10    VLAN1    G0/0  G0/1    VLAN1    10.0.2.10
             10.0.1.1          10.0.2.1       10.0.2.1
```

## Equipment

- 1x Cisco 2911 Router (R1)
- 2x Cisco 2960 Switch (SW1, SW2)
- 2x PC (PC1, PC2)
- Straight-through Ethernet cables

## IP Addressing Table

| Device | Interface | IP Address | Subnet Mask | Default Gateway |
|--------|-----------|------------|-------------|-----------------|
| R1 | G0/0 | 10.0.1.1 | 255.255.255.0 | - |
| R1 | G0/1 | 10.0.2.1 | 255.255.255.0 | - |
| SW1 | VLAN 1 | 10.0.1.2 | 255.255.255.0 | 10.0.1.1 |
| SW2 | VLAN 1 | 10.0.2.2 | 255.255.255.0 | 10.0.2.1 |
| PC1 | NIC | 10.0.1.10 | 255.255.255.0 | 10.0.1.1 |
| PC2 | NIC | 10.0.2.10 | 255.255.255.0 | 10.0.2.1 |

## Steps

### 1. Configure Router R1

```
enable
configure terminal
hostname R1
no ip domain-lookup
enable secret class
line console 0
  password cisco
  login
  logging synchronous
line vty 0 4
  password cisco
  login
  transport input ssh
banner motd #Authorized Access Only#
```

### 2. Configure Interfaces

```
interface GigabitEthernet0/0
  ip address 10.0.1.1 255.255.255.0
  no shutdown
interface GigabitEthernet0/1
  ip address 10.0.2.1 255.255.255.0
  no shutdown
```

### 3. Configure SSH

```
ip domain-name lab.local
crypto key generate rsa general-keys modulus 2048
username admin privilege 15 secret admin123
line vty 0 4
  login local
  transport input ssh
ip ssh version 2
```

### 4. Configure Switches

See [config.md](config.md) for full switch configurations.

### 5. Configure PCs

- PC1: IP 10.0.1.10/24, Gateway 10.0.1.1
- PC2: IP 10.0.2.10/24, Gateway 10.0.2.1

## Verification

```
! On R1
show ip interface brief
show running-config
show ip route

! On PC1
ping 10.0.1.1
ping 10.0.2.10

! On PC2
ping 10.0.2.1
ping 10.0.1.10
```

## Troubleshooting

- If pings fail, verify interfaces are `up/up` with `show ip interface brief`
- Ensure `no shutdown` was applied to all router interfaces
- Check that PC default gateways are set correctly
- Verify cables are connected to the correct ports
