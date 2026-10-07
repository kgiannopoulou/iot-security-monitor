# Architecture

```
  pcap file ──┐                      ┌──▶ Inventory   (devices: MAC, vendor, role, connections) ◀─▶ inventory.json
              ├─▶ capture ─▶ parser ─┼──▶ FlowTable   (bidirectional conversations)
  interface ──┘   (scapy)  (Packet-  ├──▶ Detection   (6 rules, packet-time windows) ──▶ alerts
                            Record)  │      Engine
                                     └──▶ Printer     (terminal table + coloured alerts)
                                                │
                                   Storage ◀────┘  SQLite (alerts, devices, flows, traffic/min)
                                      │            alerts.jsonl  (one JSON object per alert)
                                      │            packets.csv   (optional, --csv)
                                      ▼
                               Flask dashboard  (read-only, separate process)
```

## Modules

| Module | Responsibility |
|---|---|
| `capture.py` | `read_pcap()` and `sniff_live()`. Both yield `PacketRecord`s, so everything downstream is identical for replay and live capture. Live capture runs scapy's `AsyncSniffer` in its own thread and hands packets over through a queue. |
| `parser.py` | scapy packet → `PacketRecord`: link, network, transport, application. Decodes MQTT (CONNECT/CONNACK/PUBLISH/SUBSCRIBE), DNS, HTTP, NTP, ICMP, and labels TLS as encrypted. Never raises on malformed payloads. |
| `models.py` | `PacketRecord`, `Alert`, the known-services table, the service-port rule. |
| `flows.py` | Groups packets into client→server flows with idle expiry and TCP state (ESTABLISHED / CLOSED / REJECTED / NO-REPLY). |
| `inventory.py` | Passive asset inventory: MAC-keyed devices, OUI vendor lookup, role inference from offered services and MQTT behaviour, connection counts, MAC/IP binding changes. |
| `assets.py` | Persistent asset register (`data/inventory.json`): known devices keyed by MAC with status approved / pending, merged after each run (replay-safe), saved every 30 s during live capture. See [Week 2](02-device-inventory.md). |
| `detections.py` | `DetectionEngine` plus six `Detector` subclasses. See [detection-rules.md](detection-rules.md). |
| `storage.py` | SQLite in WAL mode (writer and dashboard reader coexist), JSONL alerts for SIEM ingestion, optional CSV. Writes are batched and committed every 2 s. |
| `pipeline.py` | `Monitor`: wires the stages together and flushes state on exit. |
| `dashboard/` | Flask app plus one HTML page. JSON API (`/api/summary`, `/api/alerts`, `/api/devices`, `/api/traffic`, `/api/flows`); the page polls it every 5 s. |
| `cli.py` | `read`, `live`, `report`, `inventory` (learn / show / approve), `dashboard` sub-commands. |

## Key decisions

**scapy for parsing.** It dissects MQTT, DNS, and HTTP out of the box and
reads pcap without libpcap (so it works on Windows). It is slow, roughly
thousands of packets per second, which is fine for an IoT segment. A
production sensor would use Zeek or Suricata for parsing and keep this
detection layer.

**Packet timestamps drive all windows.** This makes detections deterministic
and testable: the end-to-end test replays a capture and asserts the exact alert
list.

**Single SQLite file between monitor and dashboard.** No message broker or
database server to run. WAL mode lets the dashboard read while the monitor
writes. The dashboard opens the file read-only.

**Synthetic, deterministic sample capture.** `tools/generate_sample_pcap.py`
builds the capture packet by packet with a fixed seed and start time, so it is
byte-identical on every run. A test checks the committed file matches the
generator. All addresses are RFC 1918 (lab) or RFC 5737 (documentation-only)
ranges.

## Data model (SQLite)

| Table | Contents |
|---|---|
| `alerts` | ts, rule, severity, title, src, dst, mitre, details (JSON) |
| `devices` | key (MAC), ips, vendor, name, role, first/last seen, packet/byte counters, protocols, services |
| `flows` | 5-tuple, app, first/last seen, duration, packets, bytes per direction, state |
| `traffic` | per minute × application protocol: packets, bytes (feeds the chart) |

`alerts.jsonl` has one alert per line with an ISO-8601 `time` field, ready
for Filebeat / Wazuh / Splunk ingestion.
