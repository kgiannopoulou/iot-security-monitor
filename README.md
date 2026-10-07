# IoT Security Monitoring System

A passive network monitor for IoT / OT networks, written in Python. It captures
traffic (live or from a pcap), decodes it down to the MQTT topic and DNS
query, builds a device inventory, runs five detection rules, stores the
results in SQLite / JSONL / CSV, and shows them on a web dashboard.

It comes with a Docker lab of simulated IoT devices to monitor, and a
deterministic sample capture of a Mirai-style intrusion that every rule is
tested against.

![Dashboard showing the sample capture](docs/images/dashboard.png)

```
IoT / OT devices ──▶ Python monitor ──▶ Detection engine ──▶ Logging / alerts ──▶ Dashboard
 (Docker lab or       capture, parse,     port scans, new       SQLite, JSONL,       devices, alerts,
  pcap file)          flows, inventory    devices, spikes,      CSV                  traffic, severity
                                          risky ports, failures
```

## What it demonstrates

| Skill | Where |
|---|---|
| **Python development** | Clean package with a CLI, typed dataclasses, 30 pytest tests, a Flask API ([`iotmon/`](iotmon)) |
| **Networking** | Layer-by-layer parsing (Ethernet → ARP/IP → TCP/UDP → MQTT/DNS/HTTP), flows vs packets, SPAN-style capture. Explained in **[Week 1: what the monitor sees and why](docs/01-networking-foundation.md)** |
| **Detection engineering** | Five stateful rules with sliding windows, adaptive baselines, cooldowns, ATT&CK mapping, documented false positives and blind spots, tested for zero alerts on baseline traffic ([rules](docs/detection-rules.md)) |
| **IoT / OT security** | MQTT authentication monitoring, exposed Telnet, rogue-device detection, botnet C2 and flood behaviour, OUI vendor fingerprinting |

## Quick start (no Docker, no admin rights)

```bash
pip install -r requirements.txt
python -m iotmon read samples/iot-lab.pcap        # packet table + alerts
python -m iotmon report                           # devices, top flows, alerts
python -m iotmon dashboard                        # http://127.0.0.1:8080
```

Output (abridged, `--utc`):

```
TIME      SOURCE           DESTINATION      PROTOCOL  PORT  APP       INFO
10:30:02  192.168.1.20     192.168.1.10     TCP       1883  MQTT      CONNECT id=temp-sensor-01 user=devices
10:30:02  192.168.1.10     192.168.1.20     TCP       1883  MQTT      CONNACK accepted
10:30:05  192.168.1.20     192.168.1.10     TCP       1883  MQTT      PUBLISH factory/line1/temp
10:30:15  192.168.1.21     192.168.1.1      UDP         53  DNS       query api.smartplug.example
10:30:15  192.168.1.1      192.168.1.21     UDP         53  DNS       answer api.smartplug.example -> 203.0.113.50
10:30:15  192.168.1.21     203.0.113.50     TCP        443  HTTPS     TLS record, 606 bytes (encrypted)
...
10:35:00  [ALERT MEDIUM]   new_device: New device on network: 192.168.1.66 (Raspberry Pi Foundation)
10:35:00  [ALERT MEDIUM]   port_scan: ARP sweep from 192.168.1.66
10:35:10  [ALERT HIGH]     suspicious_port: TELNET session 192.168.1.66 -> 192.168.1.22:23
10:35:10  [ALERT HIGH]     port_scan: Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22
10:35:52  [ALERT MEDIUM]   failed_connections: Repeated failed connections: 192.168.1.66 -> 192.168.1.21:23 (10x)
10:36:06  [ALERT HIGH]     failed_connections: MQTT authentication failures: 192.168.1.66 refused 5x by broker 192.168.1.10
10:36:35  [ALERT CRITICAL] suspicious_port: IRC session 192.168.1.22 -> 198.51.100.23:6667
10:36:50  [ALERT HIGH]     traffic_spike: Traffic spike: 192.168.1.22 sent 591,031 bytes in 10s (baseline 9,027)

3546 packets, 7 devices, 8 alerts
```

Full outputs are in [`docs/sample-output/`](docs/sample-output).

## Live lab (Docker)

```bash
cd lab
docker compose up -d --build          # broker, 3 IoT devices, cloud, DNS, admin, monitor, dashboard
# http://localhost:8080
```

The monitor sniffs the lab's bridge (`iotlab0`) from the host network
namespace, the container equivalent of a switch SPAN port. Details and a
live detection check are in the [lab guide](docs/lab-setup.md).

![Dashboard on the live Docker lab](docs/images/dashboard-live-lab.png)

## CLI

| Command | Purpose |
|---|---|
| `iotmon read FILE.pcap` | Analyse a capture. `-q` alerts only, `--csv` also write every packet, `--utc`, `-c N` |
| `iotmon live -i IFACE` | Capture live (root / `CAP_NET_RAW`; Npcap on Windows). `-f 'bpf filter'`, `-t SECONDS` |
| `iotmon report` | Devices, top flows, and alerts from the database |
| `iotmon dashboard` | Web dashboard on `127.0.0.1:8080` |

Common options: `--config my.toml` (override any threshold in
[`default.toml`](iotmon/default.toml)), `--db PATH`, `--append`, `--no-store`.

Outputs (default `data/`): `iotmon.db` (SQLite: alerts, devices, flows,
per-minute traffic), `alerts.jsonl` (SIEM-ready), `packets.csv` (with `--csv`).

## Detection rules

| Rule | Fires on | ATT&CK |
|---|---|---|
| `port_scan` | ≥ 15 ports on one host, one port on ≥ 8 hosts, or ARP for ≥ 12 addresses, within 60 s | T1046, T1018 / ICS T0846 |
| `new_device` | Unknown MAC after the 60 s learning period | T1200 / ICS T0848 |
| `traffic_spike` | Device tx/rx per 10 s > max(mean + 4σ, 5×mean, 50 kB) of its own history | T1498 / ICS T0814 |
| `suspicious_port` | *Established* session on Telnet, IRC, ADB, TR-069…; plaintext MQTT to the internet | T1021 / ICS T0886 |
| `failed_connections` | ≥ 10 refused/unanswered connections to one service, or ≥ 5 MQTT login refusals | T1110 / ICS T0812 |

Logic, tuning, false positives, and known gaps: [docs/detection-rules.md](docs/detection-rules.md).

## Project layout

```
iotmon/               the monitor (capture, parser, flows, inventory, detections, storage, dashboard, cli)
lab/                  Docker lab: Mosquitto broker, dnsmasq, simulated devices, monitor + dashboard
samples/iot-lab.pcap  8-minute synthetic capture: 5 min baseline, then the intrusion
tools/                generate_sample_pcap.py (deterministic: same bytes every run)
tests/                parser, per-rule, end-to-end and dashboard tests
docs/                 Week 1 networking write-up, architecture, rules, lab guide, roadmap
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

These cover parsing of every supported protocol, positive and negative cases
for each rule, the full intrusion timeline producing exactly the expected 8
alerts, **zero alerts during the 5-minute baseline**, storage outputs, and the
dashboard API.

## Documentation

1. [Week 1: Networking foundation and what the monitor sees](docs/01-networking-foundation.md)
2. [Architecture](docs/architecture.md)
3. [Detection rules](docs/detection-rules.md)
4. [Lab setup](docs/lab-setup.md)
5. [Roadmap](docs/roadmap.md)

## Scope

Built for monitoring my own lab network and simulated devices. The sample
capture is synthetic and uses only private (RFC 1918) and documentation
(RFC 5737) address ranges.

Related projects: [OT/ICS Cybersecurity Lab](https://github.com/kgiannopoulou/ot-ics-cybersecurity-lab) ·
[Smart Factory Threat Assessment](https://github.com/kgiannopoulou/smart-factory-threat-assessment)

## License

MIT
