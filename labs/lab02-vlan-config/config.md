# Lab 02 - VLAN Configurations

## Router R1 (Router-on-a-Stick)

```
! =============================================
! R1 - Inter-VLAN Routing Configuration
! =============================================
enable
configure terminal

hostname R1

interface GigabitEthernet0/0
  description Trunk to SW1
  no shutdown

interface GigabitEthernet0/0.10
  description Engineering VLAN
  encapsulation dot1Q 10
  ip address 10.0.10.1 255.255.255.0

interface GigabitEthernet0/0.20
  description Sales VLAN
  encapsulation dot1Q 20
  ip address 10.0.20.1 255.255.255.0

interface GigabitEthernet0/0.30
  description Management VLAN
  encapsulation dot1Q 30
  ip address 10.0.30.1 255.255.255.0

interface GigabitEthernet0/0.99
  description Native VLAN
  encapsulation dot1Q 99 native

end
write memory
```

## Switch SW1 (Core/Distribution)

```
! =============================================
! SW1 - Core Switch Configuration
! =============================================
enable
configure terminal

hostname SW1

! Create VLANs
vlan 10
  name Engineering
vlan 20
  name Sales
vlan 30
  name Management
vlan 99
  name Native

! Trunk to Router R1
interface GigabitEthernet0/1
  description Trunk to R1 G0/0
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

! Trunk to SW2
interface GigabitEthernet0/2
  description Trunk to SW2
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

! Trunk to SW3
interface FastEthernet0/23
  description Trunk to SW3
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

! Trunk to SW4
interface FastEthernet0/24
  description Trunk to SW4
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

! Management interface
interface Vlan30
  ip address 10.0.30.2 255.255.255.0
  no shutdown

ip default-gateway 10.0.30.1

! Disable unused ports
interface range FastEthernet0/1-22
  shutdown

end
write memory
```

## Switch SW2 (Access)

```
! =============================================
! SW2 - Access Switch Configuration
! =============================================
enable
configure terminal

hostname SW2

vlan 10
  name Engineering
vlan 20
  name Sales
vlan 30
  name Management
vlan 99
  name Native

! Trunk to SW1
interface GigabitEthernet0/1
  description Trunk to SW1
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

! Access ports
interface FastEthernet0/1
  description PC1 - Engineering
  switchport mode access
  switchport access vlan 10
  switchport port-security
  switchport port-security maximum 1
  switchport port-security violation shutdown
  spanning-tree portfast

interface FastEthernet0/2
  description PC2 - Sales
  switchport mode access
  switchport access vlan 20
  switchport port-security
  switchport port-security maximum 1
  switchport port-security violation shutdown
  spanning-tree portfast

! Disable unused ports
interface range FastEthernet0/3-24
  switchport mode access
  switchport access vlan 99
  shutdown

interface Vlan30
  ip address 10.0.30.3 255.255.255.0
  no shutdown

ip default-gateway 10.0.30.1

end
write memory
```

## Switch SW3 (Access)

```
! =============================================
! SW3 - Access Switch Configuration
! =============================================
enable
configure terminal

hostname SW3

vlan 10
  name Engineering
vlan 20
  name Sales
vlan 30
  name Management
vlan 99
  name Native

interface GigabitEthernet0/1
  description Trunk to SW1
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

interface FastEthernet0/1
  description PC3 - Engineering
  switchport mode access
  switchport access vlan 10
  spanning-tree portfast

interface FastEthernet0/2
  description PC4 - Sales
  switchport mode access
  switchport access vlan 20
  spanning-tree portfast

interface range FastEthernet0/3-24
  switchport mode access
  switchport access vlan 99
  shutdown

interface Vlan30
  ip address 10.0.30.4 255.255.255.0
  no shutdown

ip default-gateway 10.0.30.1

end
write memory
```

## Switch SW4 (Access)

```
! =============================================
! SW4 - Access Switch Configuration
! =============================================
enable
configure terminal

hostname SW4

vlan 10
  name Engineering
vlan 20
  name Sales
vlan 30
  name Management
vlan 99
  name Native

interface GigabitEthernet0/1
  description Trunk to SW1
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99

interface FastEthernet0/1
  description PC5 - Engineering
  switchport mode access
  switchport access vlan 10
  spanning-tree portfast

interface FastEthernet0/2
  description PC6 - Management
  switchport mode access
  switchport access vlan 30
  spanning-tree portfast

interface range FastEthernet0/3-24
  switchport mode access
  switchport access vlan 99
  shutdown

interface Vlan30
  ip address 10.0.30.5 255.255.255.0
  no shutdown

ip default-gateway 10.0.30.1

end
write memory
```
