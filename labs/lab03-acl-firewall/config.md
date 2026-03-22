# Lab 03 - ACL and Firewall Configurations

## Router R1 (Edge/Firewall)

```
! =============================================
! R1 - Edge Router with ACLs
! =============================================
enable
configure terminal

hostname R1

! Interface configuration
interface GigabitEthernet0/0
  description WAN - Internet
  ip address 203.0.113.1 255.255.255.252
  ip access-group OUTSIDE-IN in
  no shutdown

interface GigabitEthernet0/1
  description DMZ Segment
  ip address 172.16.1.1 255.255.255.0
  ip access-group DMZ-IN in
  no shutdown

interface GigabitEthernet0/2
  description Link to R2
  ip address 10.0.0.1 255.255.255.252
  no shutdown

! =============================================
! Standard ACL - SSH Access Control
! =============================================
access-list 10 remark Allow SSH from Engineering LAN only
access-list 10 permit 10.0.1.0 0.0.0.255
access-list 10 deny any log

line vty 0 4
  access-class 10 in
  login local
  transport input ssh

! =============================================
! Extended ACL - Outside to DMZ
! =============================================
ip access-list extended OUTSIDE-IN
  remark Allow HTTP/HTTPS to web server
  permit tcp any host 172.16.1.10 eq 80
  permit tcp any host 172.16.1.10 eq 443
  remark Allow DNS queries to DNS server
  permit udp any host 172.16.1.20 eq 53
  remark Allow established connections back
  permit tcp any any established
  remark Block everything else from outside
  deny ip any any log

! =============================================
! Extended ACL - DMZ inbound
! =============================================
ip access-list extended DMZ-IN
  remark Allow DNS server to query external DNS
  permit udp host 172.16.1.20 any eq 53
  remark Allow web server responses
  permit tcp host 172.16.1.10 any established
  remark Block DMZ from reaching internal networks
  deny ip 172.16.1.0 0.0.0.255 10.0.0.0 0.255.255.255 log
  remark Allow DMZ to internet for updates
  permit tcp 172.16.1.0 0.0.0.255 any eq 80
  permit tcp 172.16.1.0 0.0.0.255 any eq 443
  deny ip any any log

! =============================================
! NAT configuration
! =============================================
ip nat inside source list NAT-POOL interface GigabitEthernet0/0 overload
ip nat inside source static tcp 172.16.1.10 80 203.0.113.1 80
ip nat inside source static tcp 172.16.1.10 443 203.0.113.1 443
ip nat inside source static udp 172.16.1.20 53 203.0.113.1 53

ip access-list extended NAT-POOL
  permit ip 10.0.0.0 0.0.255.255 any
  permit ip 172.16.1.0 0.0.0.255 any

interface GigabitEthernet0/0
  ip nat outside
interface GigabitEthernet0/1
  ip nat inside
interface GigabitEthernet0/2
  ip nat inside

! Static routes
ip route 10.0.1.0 255.255.255.0 10.0.0.2
ip route 10.0.2.0 255.255.255.0 10.0.0.2
ip route 0.0.0.0 0.0.0.0 203.0.113.2

! Logging
logging buffered 16384
logging trap warnings

end
write memory
```

## Router R2 (Internal Distribution)

```
! =============================================
! R2 - Internal Router with Guest ACL
! =============================================
enable
configure terminal

hostname R2

interface GigabitEthernet0/0
  description Link to R1
  ip address 10.0.0.2 255.255.255.252
  no shutdown

interface GigabitEthernet0/1
  description LAN A - Engineering
  ip address 10.0.1.1 255.255.255.0
  no shutdown

interface GigabitEthernet0/2
  description LAN B - Guest Network
  ip address 10.0.2.1 255.255.255.0
  ip access-group GUEST-OUT in
  no shutdown

! =============================================
! Extended ACL - Guest Network Restrictions
! =============================================
ip access-list extended GUEST-OUT
  remark Allow guest DNS lookups
  permit udp 10.0.2.0 0.0.0.255 any eq 53
  remark Allow guest HTTP/HTTPS to internet
  permit tcp 10.0.2.0 0.0.0.255 any eq 80
  permit tcp 10.0.2.0 0.0.0.255 any eq 443
  remark Block guest access to internal networks
  deny ip 10.0.2.0 0.0.0.255 10.0.0.0 0.0.255.255 log
  deny ip 10.0.2.0 0.0.0.255 10.0.1.0 0.0.0.255 log
  deny ip 10.0.2.0 0.0.0.255 172.16.0.0 0.15.255.255 log
  remark Allow return traffic
  permit ip any any

! =============================================
! Standard ACL - SSH restriction
! =============================================
access-list 10 permit 10.0.1.0 0.0.0.255
access-list 10 deny any log

line vty 0 4
  access-class 10 in
  login local
  transport input ssh

! Default route
ip route 0.0.0.0 0.0.0.0 10.0.0.1

end
write memory
```
