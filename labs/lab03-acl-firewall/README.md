# Lab 03: Access Control Lists and Firewall Rules

## Objective

Implement standard and extended ACLs to control traffic flow between network segments. Configure a zone-based firewall policy on a Cisco router.

## Topology

```
   [Internet]
       |
     [R1] ---- DMZ (172.16.1.0/24)
       |          [Web Server 172.16.1.10]
       |          [DNS Server 172.16.1.20]
       |
     [R2]
      / \
     /   \
  [SW1] [SW2]
    |      |
  LAN A  LAN B
 10.0.1.0  10.0.2.0
  /24       /24
```

## Security Policy

1. LAN A (Engineering) can access all internal resources and the internet
2. LAN B (Guest) can only access the internet, not internal networks
3. DMZ servers are accessible from the internet on HTTP (80) and DNS (53) only
4. Management access (SSH) to routers from LAN A only
5. ICMP is allowed from internal networks to DMZ but blocked from internet

## IP Addressing

| Device | Interface | IP Address | Zone |
|--------|-----------|------------|------|
| R1 | G0/0 | 203.0.113.1/30 | Outside |
| R1 | G0/1 | 172.16.1.1/24 | DMZ |
| R1 | G0/2 | 10.0.0.1/30 | Inside |
| R2 | G0/0 | 10.0.0.2/30 | - |
| R2 | G0/1 | 10.0.1.1/24 | LAN A |
| R2 | G0/2 | 10.0.2.1/24 | LAN B |

## Steps

### 1. Standard ACL - Restrict SSH Access

```
access-list 10 permit 10.0.1.0 0.0.0.255
access-list 10 deny any log

line vty 0 4
  access-class 10 in
```

### 2. Extended ACL - DMZ Protection

```
ip access-list extended DMZ-IN
  permit tcp any host 172.16.1.10 eq 80
  permit tcp any host 172.16.1.10 eq 443
  permit udp any host 172.16.1.20 eq 53
  permit icmp 10.0.0.0 0.0.255.255 172.16.1.0 0.0.0.255
  deny ip any any log
```

### 3. Extended ACL - Guest Restrictions

```
ip access-list extended GUEST-OUT
  permit tcp 10.0.2.0 0.0.0.255 any eq 80
  permit tcp 10.0.2.0 0.0.0.255 any eq 443
  permit udp 10.0.2.0 0.0.0.255 any eq 53
  deny ip 10.0.2.0 0.0.0.255 10.0.0.0 0.0.255.255
  deny ip 10.0.2.0 0.0.0.255 172.16.0.0 0.15.255.255
  permit ip any any
```

### 4. Apply ACLs to Interfaces

See [config.md](config.md) for complete interface configurations.

## Verification

```
show access-lists
show ip interface (check ACL applied)

! Test from LAN A - should succeed
ping 172.16.1.10
ssh -l admin 10.0.0.1

! Test from LAN B - should fail to internal
ping 172.16.1.10       ! Denied
ping 8.8.8.8           ! Allowed
```

## Troubleshooting

- Use `show access-lists` to check hit counters
- Add `log` keyword to ACL entries for debugging
- Remember ACLs are processed top-down; order matters
- Verify ACL is applied in the correct direction (in/out)
- Check that implicit `deny any` is not blocking needed traffic
