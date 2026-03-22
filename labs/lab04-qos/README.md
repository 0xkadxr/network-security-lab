# Lab 04: Quality of Service (QoS)

## Objective

Implement QoS policies for traffic classification, marking, queuing, and policing on a Cisco router. Prioritize voice and video traffic while managing bandwidth for data and best-effort traffic.

## Topology

```
  [VoIP Phone]    [PC - Data]    [Video Endpoint]
      |               |                |
   10.0.1.50      10.0.1.100       10.0.1.200
      |               |                |
  +---+---------------+----------------+---+
  |               [SW1]                    |
  +-------------------+--------------------+
                      |
                   (100 Mbps)
                      |
                    [R1] -----(WAN 10 Mbps)------ [R2] --- [Server Farm]
                 10.0.1.1                       10.0.2.1     10.0.2.0/24
```

## QoS Policy

| Traffic Class | DSCP | Bandwidth | Queue |
|--------------|------|-----------|-------|
| Voice (RTP) | EF (46) | 30% (3 Mbps) | Priority (LLQ) |
| Video | AF41 (34) | 25% (2.5 Mbps) | CBWFQ |
| Business Data | AF21 (18) | 25% (2.5 Mbps) | CBWFQ |
| Management (SSH, SNMP) | CS2 (16) | 5% (500 Kbps) | CBWFQ |
| Best Effort | 0 | 15% (1.5 Mbps) | Default |

## Steps

### 1. Define Class Maps

```
class-map match-any VOICE
  match ip dscp ef
  match ip dscp cs5
class-map match-any VIDEO
  match ip dscp af41
  match ip dscp af42
class-map match-any BUSINESS-DATA
  match ip dscp af21
  match protocol http
  match protocol https
class-map match-any MANAGEMENT
  match ip dscp cs2
  match protocol ssh
  match protocol snmp
```

### 2. Create Policy Map

```
policy-map WAN-QOS
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
```

### 3. Apply to WAN Interface

```
interface Serial0/0/0
  service-policy output WAN-QOS
```

### 4. Configure Traffic Marking at the Access Layer

See [config.md](config.md) for complete QoS configurations.

## Verification

```
show policy-map interface Serial0/0/0
show class-map
show policy-map
show mls qos interface
```

## Troubleshooting

- Verify class-maps match expected traffic: `show class-map`
- Check policy-map counters for packet classification: `show policy-map interface`
- Ensure DSCP markings are not being reset at layer 3 boundaries
- Use `debug ip cef` carefully to trace packet marking
- Verify total bandwidth allocation does not exceed interface speed
