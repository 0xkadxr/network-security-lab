# Lab 01 - Device Configurations

## Router R1

```
! =============================================
! Router R1 - Full Configuration
! =============================================
enable
configure terminal

hostname R1
no ip domain-lookup

! Security settings
enable secret class
service password-encryption

! Console access
line console 0
  password cisco
  login
  logging synchronous
  exec-timeout 5 0

! VTY lines for remote access
line vty 0 4
  login local
  transport input ssh
  exec-timeout 5 0

! Banner
banner motd #
===========================================
   WARNING: Authorized Access Only
   All activity is monitored and logged
===========================================
#

! Interface configuration
interface GigabitEthernet0/0
  description Link to SW1 - LAN A
  ip address 10.0.1.1 255.255.255.0
  no shutdown

interface GigabitEthernet0/1
  description Link to SW2 - LAN B
  ip address 10.0.2.1 255.255.255.0
  no shutdown

! SSH configuration
ip domain-name lab.local
crypto key generate rsa general-keys modulus 2048
username admin privilege 15 secret admin123
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3

end
write memory
```

## Switch SW1

```
! =============================================
! Switch SW1 - Full Configuration
! =============================================
enable
configure terminal

hostname SW1
no ip domain-lookup

enable secret class
service password-encryption

line console 0
  password cisco
  login
  logging synchronous

line vty 0 15
  password cisco
  login
  transport input ssh

banner motd #Authorized Access Only#

! Management VLAN IP
interface Vlan1
  ip address 10.0.1.2 255.255.255.0
  no shutdown

ip default-gateway 10.0.1.1

! Port security on access ports
interface FastEthernet0/1
  description Link to PC1
  switchport mode access
  switchport port-security
  switchport port-security maximum 1
  switchport port-security violation shutdown
  spanning-tree portfast

interface GigabitEthernet0/1
  description Uplink to R1 G0/0

end
write memory
```

## Switch SW2

```
! =============================================
! Switch SW2 - Full Configuration
! =============================================
enable
configure terminal

hostname SW2
no ip domain-lookup

enable secret class
service password-encryption

line console 0
  password cisco
  login
  logging synchronous

line vty 0 15
  password cisco
  login
  transport input ssh

banner motd #Authorized Access Only#

interface Vlan1
  ip address 10.0.2.2 255.255.255.0
  no shutdown

ip default-gateway 10.0.2.1

interface FastEthernet0/1
  description Link to PC2
  switchport mode access
  switchport port-security
  switchport port-security maximum 1
  switchport port-security violation shutdown
  spanning-tree portfast

interface GigabitEthernet0/1
  description Uplink to R1 G0/1

end
write memory
```
