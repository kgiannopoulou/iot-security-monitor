# Detection Rules

All rules live in [`iotmon/detections.py`](../iotmon/detections.py). Their
thresholds are in [`iotmon/default.toml`](../iotmon/default.toml) and can be
overridden with `--config my.toml`. The design rationale and the test
scenarios are in the [Week 3 write-up](03-detection-engine.md).

Design principles:

* **Thresholds over time windows, not "if port == X".** Every rule counts
  something (ports, hosts, connections, failures, bytes) inside a window
  and compares it with a threshold. Where it makes sense, that threshold
  comes from the device's own learned behaviour.
* **Packet time, not wall-clock time.** Every window uses packet timestamps,
  so replaying a pcap produces exactly the alerts a live run would have.
* **A frozen baseline.** Behaviour is learned during a learning period (or
  from a trusted capture) and then only compared against. An attack never
  becomes part of "normal".
* **One state machine per rule**, fed one packet at a time, with bounded memory
  (sliding windows, capped history).
* **Cooldowns** stop one ongoing event from producing hundreds of alerts.
* **Each rule owns one question.** A port scan also produces many refused
  connections and a high connection rate. The failed-connection rule only
  counts failures against the *same* service, and the connection-rate rule
  stays quiet for a source already flagged as scanning.
* **Zero alerts on the baseline, and on activity just under the thresholds,
  are tested requirements** (`test_baseline_is_quiet`,
  `near-miss-below-thresholds` scenario).

| ID | Rule | Severity | ATT&CK (Enterprise / ICS) |
|---|---|---|---|
| **DET-001** | `new_device` | medium | T1200 Hardware Additions / T0848 Rogue Master |
| **DET-002** | `port_scan` | high (scan/sweep), medium (ARP sweep) | T1046 Network Service Discovery, T1018 Remote System Discovery / T0846 |
| **DET-003** | `connection_rate` | medium | T1499 Endpoint Denial of Service / T0814 |
| **DET-004** | `suspicious_port` | medium (outside baseline), per port up to critical (high-risk service) | T1021 Remote Services / T0886 |
| **DET-005** | `external_connection` | medium, high (local-only device, direct-to-IP, fan-out) | T1071 Application Layer Protocol / T0869 |
| DET-006 | `traffic_spike` | high | T1498 Network Denial of Service / T0814 |
| DET-007 | `failed_connections` | medium (refused), high (MQTT auth) | T1110 Brute Force / T0812 Default Credentials |
| DET-008 | `device_change` | high (IP conflict), low (IP change) | T1557.002 ARP Cache Poisoning, T1036 Masquerading / T0830 Adversary-in-the-Middle |

DET-001 to DET-005 are the core rules. DET-006 to DET-008 add evidence to
the same incidents: volume, brute force, address spoofing.

Every alert is written to `alerts.jsonl` as an evidence record:

```json
{"timestamp": "2026-10-07T10:35:10.280Z", "rule": "DET-002", "rule_name": "port_scan", "severity": "HIGH",
 "source_ip": "192.168.1.66", "destination_ip": "192.168.1.22",
 "description": "Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22",
 "mitre": "T1046 Network Service Discovery / ICS T0846",
 "ports_observed": 15, "sample_ports": [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 554],
 "window_s": 60.0, "threshold": 15}
```

---

## The behavioural baseline

DET-003, DET-004 and DET-005 compare traffic with a per-device profile
([`iotmon/baseline.py`](../iotmon/baseline.py)):

| Field | Learned from | Used by |
|---|---|---|
| `client_ports` | service ports of conversations the device opened | DET-004 |
| `server_ports` | service ports the device answered on | DET-004 |
| `external_peers` | internet hosts the device opened conversations to | DET-005 |
| `peak_connections` | most connection attempts it made in any 60 s window | DET-003 |

**Learning.** Without `--baseline`, the first 120 s of every capture are the
learning period (`[baseline] learning_period_s`). With `--baseline FILE`, a
missing file is learned the same way and saved; an existing file is loaded
and frozen. `iotmon baseline learn trusted.pcap` learns from a whole capture
you trust, which is the right choice for a real deployment: two minutes do
not cover a nightly backup or a weekly firmware check.

**Limits.** Profiles are keyed by IP: fine for statically addressed OT
devices, and address changes are DET-008's job. Devices first seen after the
learning period have no profile. DET-001 reports them, and DET-004/005 then
fall back to their non-baseline checks (the high-risk port list, and "no
baseline" as a DET-005 reason). Behaviour that only happens rarely, and not
during the baseline, will alert once. That is intended, because on a static
network a new behaviour is worth a look.

## DET-001 `new_device`

**Logic.** The inventory reports the first packet from an unseen MAC (or IP
when there is no Ethernet header). With an **asset register** loaded
(`--inventory`, Week 2), any device not in the register alerts on its first
packet, and is saved as `pending` so it alerts once rather than on every run.
Without a register, devices seen during the **learning period** (the first
60 s) form the baseline. Devices in `known_devices` never alert. The alert
carries IP, MAC, vendor and the first packet seen
([Week 2 write-up](02-device-inventory.md)).

**Why it works on IoT/OT.** These networks are small and static. A new MAC is
rare and always worth a look: a contractor laptop, a rogue Raspberry Pi, a
replaced sensor.

**False positives.** Replaced hardware and phones that randomise their MAC
(shown as "locally administered"). For long-running deployments, build the
asset register with `iotmon inventory learn` from trusted traffic instead of
relying on the learning period.

## DET-002 `port_scan`

**Logic.** Per source, keep a 60 s sliding window of probes. A probe is a TCP
SYN without ACK, or a UDP packet sent *to* a service port. Three patterns:

| Pattern | Condition (defaults) | Evidence |
|---|---|---|
| Vertical scan | ≥ 15 distinct ports on one host | `ports_observed`, `sample_ports` |
| Horizontal sweep | the same port on ≥ 8 distinct hosts | `hosts_observed` |
| ARP sweep | ARP requests for ≥ 12 distinct addresses | `addresses_observed` |

**Why these numbers.** Normal IoT devices talk to a handful of fixed peers
on one or two ports. In the baseline the busiest device (the camera) touches
4 service ports in total, so 15 distinct ports on *one* host in a minute
leaves a wide margin. The near-miss scenario probes 12 ports and stays
silent.

**False positives.** Vulnerability scanners and asset-discovery tools (allow
them by source in a future allowlist), and NMS polling many hosts on SNMP/161
(horizontal). UDP replies from servers (DNS answers going to many ephemeral
ports) are excluded by the "sent *to* a service port" rule. This is covered by
`test_dns_server_replies_are_not_a_scan`.

**Evasion / limits.** Slow scans (one port every 10 s) stay under the window.
This is tested and documented as a known gap. A longer second window with a
higher threshold would catch them.

## DET-003 `connection_rate`

**Logic.** Count connection *attempts* per source device in a 60 s sliding
window: a TCP SYN, or the first packet of a new UDP conversation. Alert when

```
attempts >= max(min_connections, peak_factor × learned peak)       defaults: 20, 5×
```

The learned peak is the device's busiest 60 s during the baseline.

**Why both terms.** The floor (20) stops devices with a near-zero baseline
from alerting on a handful of reconnects. A sensor with one persistent MQTT
session has a peak of 0 or 1, and 5× that is meaningless. The factor makes
busy devices (a gateway, a camera polling many services) alert relative to
their own normal, not a global number. In the sample capture the camera's
peak is 4, so it would need 20; a device with a peak of 10 would need 50.

**What it catches that the others miss.** A reconnect storm or flood against
*one* service: same peer, same port, valid credentials. There is no scan (one
port), no failure (connections succeed), and too little volume for DET-006.
This is how a crashed firmware loop, a misconfigured client or an
application-layer DoS against a PLC or broker looks.

**Deferring to DET-002.** A scan is also a burst of attempts. Sources that
DET-002 flagged within `scan_suppress_s` (300 s) are not reported again here.

**False positives.** Legitimate bursts the baseline did not see: a device
reboot reconnecting many sessions, a mass firmware rollout. Learn the
baseline over a longer trusted capture.

## DET-004 `suspicious_port`: communication with unusual ports

**Logic.** Only **established** sessions count: the client completed the TCP
handshake (its ACK after the SYN-ACK), or a UDP service replied. Half-open
probes and refused attempts are DET-002's and DET-007's. The port is unusual
if either is true:

1. **Outside the device's baseline:** the client never connected to this port,
   or the server never answered on it, during the learning period (medium).
   This is the main check, and it needs no port list: the temperature sensor
   that only ever spoke MQTT opening HTTP to the camera is unusual, even though
   HTTP is a normal protocol.
2. **High-risk service**, baseline or not: ports with no business on an IoT
   network. Severity per port:

| Port | Service | Severity | Why |
|---|---|---|---|
| 23, 2323 | Telnet | high | Cleartext logins; the Mirai botnet's entry point |
| 21 | FTP | medium | Cleartext credentials |
| 69 | TFTP | medium | Unauthenticated firmware/config transfer |
| 445 / 3389 | SMB / RDP | medium | IT lateral movement into OT |
| 5555 | ADB | high | Root shell on Android-based devices |
| 7547 | TR-069 | medium | Remote management; mass-exploited in 2016 |
| 4444 | Metasploit default | critical | Default handler port |
| 6667 | IRC | critical | Classic botnet command-and-control |

The list sets *how bad* an established session is; the baseline decides
whether a session on any other port is unusual at all. The evidence lists the
reasons and the device's usual ports. Extra check: **plaintext MQTT (1883) to
a public IP address** is a medium alert, because telemetry and credentials
are leaving the site unencrypted.

**Note** the alert is useful in both directions. "Admin → camera:23" tells you
the camera *exposes* Telnet. "Camera → internet:6667" tells you the camera is
*doing* something it never should.

## DET-005 `external_connection`: unexpected external connection

**Logic.** A lab device opens a conversation to an **external** address: not
in `lab_networks`, not in `internal_networks` (RFC 1918 by default), and not
multicast, broadcast, link-local or loopback. It is unexpected if the
address is not among the device's learned `external_peers`.

| Condition | Severity |
|---|---|
| Device talked to the internet during the baseline, address resolved by DNS in the last 10 min | medium |
| Device **never** talked to the internet during the baseline (local-only sensor) | high |
| No DNS answer gave the device this address (**direct-to-IP**, typical of malware) | high |
| ≥ 10 distinct unexpected hosts in 300 s (**fan-out**) | high, one alert |

Per device, at most 3 individual hosts are reported per 300 s before the
fan-out alert takes over, so a device spraying the internet produces 4
alerts, not 400.

**Why DNS correlation.** The monitor records which addresses each device
received in DNS answers. Legitimate IoT cloud traffic almost always starts
with a lookup (`api.smartplug.example` → 203.0.113.50). Bots often connect
to hard-coded IPs. The DNS name is also the best evidence an analyst can get
for encrypted traffic.

**False positives.** Cloud services behind CDNs or rotating address pools
(a new IP for the same name). The DNS name in the evidence makes these quick
to triage. A future version could allow by domain instead of by address.

## DET-006 `traffic_spike`

**Logic.** For every local IP, separately for transmit and receive: sum bytes
and packets per 10 s bucket. When a bucket closes, compare it with that
device's own last 30 buckets (empty buckets count as zero). Alert when

```
value > max(mean + 4·σ,  5·mean,  floor)        floor = 50 kB or 500 packets
```

A spike is **not added to the history**, so an ongoing flood cannot teach the
baseline that floods are normal.

**Why three thresholds.** `mean + 4σ` adapts to bursty devices (the camera
uploads 20 kB every 30 s, so its σ is large). `5·mean` stops near-constant
devices from alerting on tiny wobbles (σ ≈ 0). The absolute floor ignores
statistically large but operationally meaningless changes, such as a sensor
going from 300 to 900 bytes.

**False positives.** Firmware updates, video streams starting, backups.
These are real changes in behaviour, and worth knowing about on a static
network.

## DET-007 `failed_connections`

**Logic.** Track every outstanding SYN. A failure is:

* `RST` from the server in reply to a SYN: **refused**,
* no SYN-ACK within 5 s: **no reply** (filtered or down),
* ICMP port-unreachable: **port unreachable**,
* MQTT `CONNACK` with a non-zero return code: **MQTT auth** (wrong credentials).

Failures are counted per *(client, server, port)*. Alert at ≥ 10 failures in
60 s, or ≥ 5 refused MQTT logins (high).

**Why per service.** It separates "someone keeps trying *this* service"
(brute force, or a misconfigured device stuck in a retry loop, which is also
worth fixing) from "someone touches *many* services" (a scan).

**MQTT specifics.** The broker's refusal is cleartext on port 1883, so the
monitor sees authentication failures without any broker logs. With MQTT over
TLS this signal moves to the broker's log, a good argument for pulling broker
logs into the pipeline later.

## DET-008 `device_change`

**Logic.** Watches the binding between MAC and IP addresses.
*IP conflict* (high): an IP already bound to one MAC is used by a different
MAC, as a sender in an ARP reply or as the source of an IP packet. That is
what ARP spoofing looks like from a SPAN port: the attacker announces "the
gateway's IP is at my MAC". *IP change* (low): a known MAC appears on a new
IP, either within the capture or compared with the asset register.

**Why it works on IoT/OT.** OT devices are mostly statically addressed, so
address changes are rare, and a second MAC for a PLC's or broker's IP is
either a man-in-the-middle or a misconfiguration that will break the process
anyway.

**False positives.** DHCP renewals (hence low severity for changes). A
device that moved keeps its old IP binding for the rest of the run, so a new
device reusing that address raises a conflict. Traffic routed from another
subnet carries the router's MAC, so monitor one layer-2 segment per sensor.
Validated live in the Docker lab with gratuitous ARP
([lab guide](lab-setup.md#asset-register-week-2)).

---

## Validating the rules

| Evidence | How |
|---|---|
| Unit tests per rule, positive *and* negative cases | `pytest tests/test_detections.py` |
| One controlled scenario per core rule, plus a near miss, each triggering exactly its rules | `python tools/run_scenarios.py`, `pytest tests/test_scenarios.py` |
| Full kill chain on the sample capture, exact alert list | `pytest tests/test_end_to_end.py` |
| Five minutes of normal traffic raise zero alerts | `test_baseline_is_quiet` |
| Live, against real containers | `python tools/lab_scenarios.py` ([lab guide](lab-setup.md#detection-scenarios-week-3)) |

Sample capture result:

```
10:35:00  [ALERT MEDIUM]   DET-001 new_device: New IoT device detected: 192.168.1.66 (Raspberry Pi Foundation)
10:35:00  [ALERT MEDIUM]   DET-002 port_scan: ARP sweep from 192.168.1.66
10:35:10  [ALERT HIGH]     DET-002 port_scan: Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22
10:35:30  [ALERT HIGH]     DET-004 suspicious_port: TELNET session 192.168.1.66 -> 192.168.1.22:23
10:35:52  [ALERT MEDIUM]   DET-007 failed_connections: Repeated failed connections: 192.168.1.66 -> 192.168.1.21:23 (10x)
10:36:06  [ALERT HIGH]     DET-007 failed_connections: MQTT authentication failures: 192.168.1.66 refused 5x by broker 192.168.1.10
10:36:35  [ALERT MEDIUM]   DET-005 external_connection: Unexpected external connection: 192.168.1.22 -> 198.51.100.23:6667 (cnc.badbot.example)
10:36:35  [ALERT CRITICAL] DET-004 suspicious_port: IRC session 192.168.1.22 -> 198.51.100.23:6667
10:36:40  [ALERT HIGH]     DET-005 external_connection: Unexpected external connection: 192.168.1.22 -> 198.51.100.77:53
10:36:40  [ALERT MEDIUM]   DET-003 connection_rate: Abnormal connection rate: 192.168.1.22 opened 20 connections in 60s (baseline peak 4)
10:36:50  [ALERT HIGH]     DET-006 traffic_spike: Traffic spike: 192.168.1.22 sent 591,031 bytes in 10s (baseline 9,027)
```

Read top to bottom, this is the incident timeline: a rogue device joins,
discovers hosts, scans the camera, logs in over Telnet, gets refused by the
plug, tries to guess MQTT credentials. Then the camera starts acting like a
bot: it resolves and joins an IRC C2 server, and floods an external host
by IP, visible as a new destination, a connection burst and a volume spike.
