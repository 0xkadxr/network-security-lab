# Lab 05 - VPN IPSec Configurations

## Router R1 (Site A)

```
! =============================================
! R1 - Site A VPN Gateway
! =============================================
enable
configure terminal

hostname R1-SiteA

! =============================================
! Interface Configuration
! =============================================
interface GigabitEthernet0/0
  description LAN A
  ip address 10.0.1.1 255.255.255.0
  ip nat inside
  no shutdown

interface GigabitEthernet0/1
  description WAN - Internet
  ip address 203.0.113.1 255.255.255.252
  ip nat outside
  no shutdown

! =============================================
! IKE Phase 1 - ISAKMP Policy
! =============================================
crypto isakmp policy 10
  encryption aes 256
  hash sha256
  authentication pre-share
  group 14
  lifetime 86400

! Pre-shared key for peer R2
crypto isakmp key VPNSecretKey2024! address 198.51.100.1

! =============================================
! IKE Phase 2 - IPSec Transform Set
! =============================================
crypto ipsec transform-set AES256-SHA esp-aes 256 esp-sha256-hmac
  mode tunnel

! IPSec security association lifetime
crypto ipsec security-association lifetime seconds 3600
crypto ipsec security-association lifetime kilobytes 4096000

! =============================================
! Crypto ACL - Interesting Traffic
! =============================================
ip access-list extended VPN-TRAFFIC
  remark Traffic to encrypt through VPN tunnel
  permit ip 10.0.1.0 0.0.0.255 10.0.2.0 0.0.0.255

! =============================================
! Crypto Map
! =============================================
crypto map SITE-TO-SITE 10 ipsec-isakmp
  description VPN tunnel to Site B (R2)
  set peer 198.51.100.1
  set transform-set AES256-SHA
  set pfs group14
  set security-association lifetime seconds 3600
  match address VPN-TRAFFIC

! Apply crypto map to WAN interface
interface GigabitEthernet0/1
  crypto map SITE-TO-SITE

! =============================================
! NAT Configuration (exempt VPN traffic)
! =============================================
ip access-list extended NAT-ACL
  remark Do NOT NAT VPN traffic
  deny ip 10.0.1.0 0.0.0.255 10.0.2.0 0.0.0.255
  remark NAT everything else going to internet
  permit ip 10.0.1.0 0.0.0.255 any

ip nat inside source list NAT-ACL interface GigabitEthernet0/1 overload

! =============================================
! Routing
! =============================================
ip route 0.0.0.0 0.0.0.0 203.0.113.2
! Route to remote LAN via tunnel (will be encrypted)
ip route 10.0.2.0 255.255.255.0 203.0.113.2

! =============================================
! Security Hardening
! =============================================
! Disable CDP on WAN
interface GigabitEthernet0/1
  no cdp enable

! SSH access
ip domain-name vpn-site-a.local
crypto key generate rsa general-keys modulus 2048
username admin privilege 15 secret AdminPass123!
ip ssh version 2

line vty 0 4
  login local
  transport input ssh
  exec-timeout 5 0

access-list 10 permit 10.0.1.0 0.0.0.255
line vty 0 4
  access-class 10 in

! Logging
logging buffered 16384
logging trap informational

end
write memory
```

## Router R2 (Site B)

```
! =============================================
! R2 - Site B VPN Gateway
! =============================================
enable
configure terminal

hostname R2-SiteB

! =============================================
! Interface Configuration
! =============================================
interface GigabitEthernet0/0
  description LAN B
  ip address 10.0.2.1 255.255.255.0
  ip nat inside
  no shutdown

interface GigabitEthernet0/1
  description WAN - Internet
  ip address 198.51.100.1 255.255.255.252
  ip nat outside
  no shutdown

! =============================================
! IKE Phase 1 - ISAKMP Policy
! =============================================
crypto isakmp policy 10
  encryption aes 256
  hash sha256
  authentication pre-share
  group 14
  lifetime 86400

! Pre-shared key for peer R1
crypto isakmp key VPNSecretKey2024! address 203.0.113.1

! =============================================
! IKE Phase 2 - IPSec Transform Set
! =============================================
crypto ipsec transform-set AES256-SHA esp-aes 256 esp-sha256-hmac
  mode tunnel

crypto ipsec security-association lifetime seconds 3600
crypto ipsec security-association lifetime kilobytes 4096000

! =============================================
! Crypto ACL - Mirror of R1
! =============================================
ip access-list extended VPN-TRAFFIC
  remark Traffic to encrypt through VPN tunnel
  permit ip 10.0.2.0 0.0.0.255 10.0.1.0 0.0.0.255

! =============================================
! Crypto Map
! =============================================
crypto map SITE-TO-SITE 10 ipsec-isakmp
  description VPN tunnel to Site A (R1)
  set peer 203.0.113.1
  set transform-set AES256-SHA
  set pfs group14
  set security-association lifetime seconds 3600
  match address VPN-TRAFFIC

! Apply crypto map to WAN interface
interface GigabitEthernet0/1
  crypto map SITE-TO-SITE

! =============================================
! NAT Configuration (exempt VPN traffic)
! =============================================
ip access-list extended NAT-ACL
  deny ip 10.0.2.0 0.0.0.255 10.0.1.0 0.0.0.255
  permit ip 10.0.2.0 0.0.0.255 any

ip nat inside source list NAT-ACL interface GigabitEthernet0/1 overload

! =============================================
! Routing
! =============================================
ip route 0.0.0.0 0.0.0.0 198.51.100.2
ip route 10.0.1.0 255.255.255.0 198.51.100.2

! =============================================
! Security Hardening
! =============================================
interface GigabitEthernet0/1
  no cdp enable

ip domain-name vpn-site-b.local
crypto key generate rsa general-keys modulus 2048
username admin privilege 15 secret AdminPass123!
ip ssh version 2

line vty 0 4
  login local
  transport input ssh
  exec-timeout 5 0

access-list 10 permit 10.0.2.0 0.0.0.255
line vty 0 4
  access-class 10 in

logging buffered 16384
logging trap informational

end
write memory
```

## Verification Commands

```
! ---- On both routers ----

! Check IKE Phase 1 Security Associations
show crypto isakmp sa
! Expected: QM_IDLE state = Phase 1 successful

! Check IPSec Phase 2 Security Associations
show crypto ipsec sa
! Look for: #pkts encaps / #pkts decaps increasing

! Verify crypto map binding
show crypto map

! Detailed tunnel statistics
show crypto ipsec sa detail

! Check IKE Phase 1 policy
show crypto isakmp policy

! Test the tunnel (from R1)
ping 10.0.2.1 source 10.0.1.1

! Then verify packets were encrypted
show crypto ipsec sa | include pkts
! encaps and decaps counters should increase

! Debugging (use with caution)
debug crypto isakmp
debug crypto ipsec
```
