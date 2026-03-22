# Lab 04 - QoS Configurations

## Router R1 (QoS Edge)

```
! =============================================
! R1 - QoS Classification and Queuing
! =============================================
enable
configure terminal

hostname R1

! =============================================
! Interface Configuration
! =============================================
interface GigabitEthernet0/0
  description LAN - Access Layer
  ip address 10.0.1.1 255.255.255.0
  no shutdown

interface Serial0/0/0
  description WAN Link to R2 (10 Mbps)
  ip address 192.168.12.1 255.255.255.252
  bandwidth 10000
  clock rate 10000000
  no shutdown

! =============================================
! Class Maps - Traffic Classification
! =============================================
class-map match-any VOICE
  description VoIP bearer traffic
  match ip dscp ef
  match ip dscp cs5

class-map match-any VOICE-SIGNALING
  description VoIP signaling (SIP, SCCP)
  match ip dscp cs3
  match ip dscp af31

class-map match-any VIDEO
  description Video conferencing
  match ip dscp af41
  match ip dscp af42
  match ip dscp af43

class-map match-any BUSINESS-DATA
  description Critical business applications
  match ip dscp af21
  match ip dscp af22
  match protocol http
  match protocol https
  match protocol sqlnet

class-map match-any MANAGEMENT
  description Network management traffic
  match ip dscp cs2
  match protocol ssh
  match protocol snmp
  match protocol syslog
  match protocol ntp

class-map match-any SCAVENGER
  description Low priority / bulk traffic
  match ip dscp cs1
  match protocol bittorrent

! =============================================
! Policy Map - Marking (LAN ingress)
! =============================================
policy-map MARK-TRAFFIC
  class VOICE
    set ip dscp ef
  class VIDEO
    set ip dscp af41
  class BUSINESS-DATA
    set ip dscp af21
  class MANAGEMENT
    set ip dscp cs2
  class SCAVENGER
    set ip dscp cs1
  class class-default
    set ip dscp default

! =============================================
! Policy Map - WAN Queuing (output)
! =============================================
policy-map WAN-QOS
  class VOICE
    priority 3000
    ! Low Latency Queue - strict priority
    ! Guaranteed 3 Mbps, policed to prevent starvation
  class VOICE-SIGNALING
    bandwidth 200
    ! Signaling gets modest guaranteed bandwidth
  class VIDEO
    bandwidth 2500
    random-detect dscp-based
    ! WRED drops af43 before af42 before af41
  class BUSINESS-DATA
    bandwidth 2500
    random-detect
    ! Weighted Random Early Detection for congestion
  class MANAGEMENT
    bandwidth 500
  class SCAVENGER
    bandwidth 300
    ! Minimal bandwidth for low priority traffic
  class class-default
    bandwidth 1000
    random-detect
    ! Best effort with WRED

! =============================================
! Policing - Ingress Rate Limiting
! =============================================
policy-map POLICE-INGRESS
  class VOICE
    police 3000000 conform-action transmit exceed-action drop
  class VIDEO
    police 5000000 conform-action transmit exceed-action set-dscp-transmit af43
  class class-default
    police 8000000 conform-action transmit exceed-action set-dscp-transmit default

! =============================================
! Apply Policies to Interfaces
! =============================================
interface GigabitEthernet0/0
  service-policy input MARK-TRAFFIC

interface Serial0/0/0
  service-policy output WAN-QOS

! Static route
ip route 10.0.2.0 255.255.255.0 192.168.12.2

end
write memory
```

## Router R2 (Remote Site)

```
! =============================================
! R2 - Remote Site QoS
! =============================================
enable
configure terminal

hostname R2

interface Serial0/0/0
  description WAN Link to R1
  ip address 192.168.12.2 255.255.255.252
  bandwidth 10000
  no shutdown

interface GigabitEthernet0/0
  description Server Farm LAN
  ip address 10.0.2.1 255.255.255.0
  no shutdown

! Mirror QoS policy for return traffic
class-map match-any VOICE
  match ip dscp ef
class-map match-any VIDEO
  match ip dscp af41
  match ip dscp af42
class-map match-any BUSINESS-DATA
  match ip dscp af21
class-map match-any MANAGEMENT
  match ip dscp cs2

policy-map WAN-QOS-RETURN
  class VOICE
    priority 3000
  class VIDEO
    bandwidth 2500
    random-detect dscp-based
  class BUSINESS-DATA
    bandwidth 2500
    random-detect
  class MANAGEMENT
    bandwidth 500
  class class-default
    bandwidth 1500
    random-detect

interface Serial0/0/0
  service-policy output WAN-QOS-RETURN

ip route 10.0.1.0 255.255.255.0 192.168.12.1

end
write memory
```

## Switch SW1 (Access Layer Marking)

```
! =============================================
! SW1 - Trust and Marking Configuration
! =============================================
enable
configure terminal

hostname SW1

! Enable QoS globally
mls qos

! VoIP Phone port - trust DSCP from phone
interface FastEthernet0/1
  description VoIP Phone
  switchport mode access
  switchport access vlan 1
  switchport voice vlan 100
  mls qos trust device cisco-phone
  mls qos trust dscp
  spanning-tree portfast

! PC port - mark to AF21
interface FastEthernet0/2
  description Data PC
  switchport mode access
  switchport access vlan 1
  mls qos trust dscp
  spanning-tree portfast

! Video endpoint - trust DSCP
interface FastEthernet0/3
  description Video Endpoint
  switchport mode access
  switchport access vlan 1
  mls qos trust dscp
  spanning-tree portfast

! Uplink to R1
interface GigabitEthernet0/1
  description Uplink to R1
  switchport mode access
  mls qos trust dscp

end
write memory
```
