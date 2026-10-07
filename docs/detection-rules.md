# Detection Rules

All rules live in [`iotmon/detections.py`](../iotmon/detections.py). Their
thresholds are in [`iotmon/default.toml`](../iotmon/default.toml) and can be
overridden with `--config my.toml`.

Design principles:

* **Packet time, not wall-clock time.** Every window uses packet timestamps,
  so replaying a pcap produces exactly the alerts a live run would have.
* **One state machine per rule**, fed one packet at a time, with bounded memory
  (sliding windows, capped history).
* **Cooldowns** stop one ongoing event from producing hundreds of alerts.
* **Each rule owns one question.** A port scan also produces many refused
  connections, but the failed-connection rule only counts failures against the
  *same* service. Scans stay the scan rule's job, and one event raises one alert.
* **Zero alerts on the baseline is a tested requirement**
  (`tests/test_end_to_end.py::test_baseline_is_quiet`).

| Rule | Severity | ATT&CK (Enterprise / ICS) |
|---|---|---|
| `port_scan` | high (scan/sweep), medium (ARP sweep) | T1046 Network Service Discovery, T1018 Remote System Discovery / T0846 |
| `new_device` | medium | T1200 Hardware Additions / T0848 Rogue Master |
| `traffic_spike` | high | T1498 Network Denial of Service / T0814 |
| `suspicious_port` | per port (medium to critical) | T1021 Remote Services / T0886 |
| `failed_connections` | medium (refused), high (MQTT auth) | T1110 Brute Force / T0812 Default Credentials |

---

## `port_scan`

**Logic.** Per source, keep a 60 s sliding window of probes. A probe is a TCP
SYN without ACK, or a UDP packet sent *to* a service port. Three patterns:

| Pattern | Condition (defaults) |
|---|---|
| Vertical scan | ≥ 15 distinct ports on one host |
| Horizontal sweep | the same port on ≥ 8 distinct hosts |
| ARP sweep | ARP requests for ≥ 12 distinct addresses |

**Why it works on IoT.** Normal IoT devices talk to a handful of fixed peers
on one or two ports. Fifteen ports in a minute has no legitimate place on the
network except during an authorised vulnerability scan.

**False positives.** Vulnerability scanners and asset-discovery tools (allow
them by source in a future allowlist), and NMS polling many hosts on SNMP/161
(horizontal). UDP replies from servers (DNS answers going to many ephemeral
ports) are excluded by the "sent *to* a service port" rule. This is covered by
`test_dns_server_replies_are_not_a_scan`.

**Evasion / limits.** Slow scans (one port every 10 s) stay under the window.
This is tested and documented as a known gap. A longer second window with a
higher threshold would catch them.

## `new_device`

**Logic.** The inventory reports the first packet from an unseen MAC (or IP
when there is no Ethernet header). Devices seen during the **learning period**
(the first 60 s) form the baseline. Devices in `known_devices` never alert.
Everything else raises an alert with its MAC vendor.

**Why it works on IoT/OT.** These networks are small and static. A new MAC is
rare and always worth a look: a contractor laptop, a rogue Raspberry Pi, a
replaced sensor.

**False positives.** Replaced hardware, DHCP churn, and phones that randomise
their MAC (shown as "locally administered"). For long-running deployments,
pre-populate `known_devices` instead of relying on the learning period.

## `traffic_spike`

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

## `suspicious_port`

**Logic.** Alert when a session is **established** (a SYN-ACK is seen) on a
port with no business on an IoT network. A bare SYN is not enough, because
attempts against closed ports are the scan rule's job. Default list (edit in
the config):

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

Extra check: **plaintext MQTT (1883) to a public IP address** is a medium
alert, because telemetry and credentials are leaving the site unencrypted.

**Note** the alert is useful in both directions. "Admin → camera:23" tells you
the camera *exposes* Telnet. "Camera → internet:6667" tells you the camera is
*doing* something it never should.

## `failed_connections`

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

---

## Validating the rules

| Evidence | How |
|---|---|
| Unit tests per rule, positive *and* negative cases | `pytest tests/test_detections.py` |
| Full kill chain on the sample capture, exact alert list | `pytest tests/test_end_to_end.py` |
| Five minutes of normal traffic raise zero alerts | `test_baseline_is_quiet` |
| Live, against real containers | `suspicious_port` fired on a single Telnet connection to the lab camera; baseline lab traffic raised no alerts (see the [lab guide](lab-setup.md)) |

Sample capture result:

```
10:35:00  [ALERT MEDIUM]   new_device: New device on network: 192.168.1.66 (Raspberry Pi Foundation)
10:35:00  [ALERT MEDIUM]   port_scan: ARP sweep from 192.168.1.66
10:35:10  [ALERT HIGH]     suspicious_port: TELNET session 192.168.1.66 -> 192.168.1.22:23
10:35:10  [ALERT HIGH]     port_scan: Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22
10:35:52  [ALERT MEDIUM]   failed_connections: Repeated failed connections: 192.168.1.66 -> 192.168.1.21:23 (10x)
10:36:06  [ALERT HIGH]     failed_connections: MQTT authentication failures: 192.168.1.66 refused 5x by broker 192.168.1.10
10:36:35  [ALERT CRITICAL] suspicious_port: IRC session 192.168.1.22 -> 198.51.100.23:6667
10:36:50  [ALERT HIGH]     traffic_spike: Traffic spike: 192.168.1.22 sent 591,031 bytes in 10s (baseline 9,027)
```

Read top to bottom, this is the incident timeline: a rogue device joins,
discovers hosts, finds Telnet on the camera, gets refused by the plug, tries
to guess MQTT credentials, and then the camera starts acting like a bot
(C2 check-in, flood).
