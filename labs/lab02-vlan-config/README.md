# Lab 02: VLAN Configuration and Inter-VLAN Routing

## Objective

Create VLANs on layer 2 switches, configure trunk links, and implement inter-VLAN routing using a router-on-a-stick topology.

## Topology

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

## VLAN Table

| VLAN ID | Name | Network | Gateway |
|---------|------|---------|---------|
| 10 | Engineering | 10.0.10.0/24 | 10.0.10.1 |
| 20 | Sales | 10.0.20.0/24 | 10.0.20.1 |
| 30 | Management | 10.0.30.0/24 | 10.0.30.1 |
| 99 | Native | - | - |

## IP Addressing

| Device | VLAN | IP Address | Gateway |
|--------|------|------------|---------|
| PC1 | 10 | 10.0.10.11 | 10.0.10.1 |
| PC2 | 20 | 10.0.20.11 | 10.0.20.1 |
| PC3 | 10 | 10.0.10.12 | 10.0.10.1 |
| PC4 | 20 | 10.0.20.12 | 10.0.20.1 |
| PC5 | 10 | 10.0.10.13 | 10.0.10.1 |
| PC6 | 30 | 10.0.30.11 | 10.0.30.1 |

## Steps

### 1. Create VLANs on All Switches

```
vlan 10
  name Engineering
vlan 20
  name Sales
vlan 30
  name Management
vlan 99
  name Native
```

### 2. Assign Access Ports

```
! SW2
interface Fa0/1
  switchport mode access
  switchport access vlan 10
interface Fa0/2
  switchport mode access
  switchport access vlan 20
```

### 3. Configure Trunk Links

```
interface Gi0/1
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 10,20,30,99
```

### 4. Configure Router Sub-interfaces

```
interface G0/0.10
  encapsulation dot1Q 10
  ip address 10.0.10.1 255.255.255.0
interface G0/0.20
  encapsulation dot1Q 20
  ip address 10.0.20.1 255.255.255.0
interface G0/0.30
  encapsulation dot1Q 30
  ip address 10.0.30.1 255.255.255.0
```

## Verification

```
show vlan brief
show interfaces trunk
show ip interface brief
ping 10.0.20.11    ! From VLAN 10 PC to VLAN 20 PC (inter-VLAN)
```

## Troubleshooting

- Verify trunk links are up: `show interfaces trunk`
- Check VLAN assignments: `show vlan brief`
- Ensure sub-interfaces match VLAN IDs
- Confirm native VLAN matches on both sides of the trunk
- Check that `no shutdown` is on the physical G0/0 interface
