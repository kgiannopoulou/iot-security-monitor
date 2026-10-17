# SIEM integration and structured logs

## Three ways in

| | How | Format | Good for |
| --- | --- | --- | --- |
| **Ship the file** | a log shipper tails `data/alerts.jsonl` or `--ecs-file` | JSON lines | Wazuh agent, Filebeat / Elastic Agent, Splunk UF |
| **Forward** | `--syslog HOST:PORT` on `read` / `live` | RFC 5424 syslog, CEF or ECS-JSON body, UDP or TCP | ArcSight, QRadar, Sentinel (CEF connector), rsyslog / syslog-ng |
| **Export** | `iotmon alerts export --format ecs\|cef` | NDJSON / CEF lines | One-off loads, an incident ticket, a report |

```sh
iotmon live -i eth0 -q --ecs-file /var/log/iotmon/alerts.ecs.ndjson
iotmon live -i eth0 -q --syslog siem.example:514 --syslog-format cef
iotmon alerts export --status active --format ecs -o active-alerts.ndjson
```

Forwarding is best-effort and never blocks monitoring: if the collector is unreachable the error
goes to the operational log and capture continues; `alerts.jsonl` and SQLite still have every alert.

## Elastic Common Schema

`--ecs-file` and `--format ecs` produce ECS 8 documents, so alerts sit next to other IDS data with no
ingest pipeline:

```json
{"@timestamp": "2026-10-07T10:35:10.280Z", "message": "Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22",
 "event": {"kind": "alert", "category": ["network", "intrusion_detection"], "type": ["info"],
           "module": "iotmon", "dataset": "iotmon.alert", "severity": 4, "risk_score": 79.2},
 "rule": {"id": "DET-002", "name": "port_scan", "category": "IoT/OT network"},
 "source": {"ip": "192.168.1.66"}, "destination": {"ip": "192.168.1.22"},
 "threat": {"framework": "MITRE ATT&CK", "technique": {"id": ["T1046"], "name": ["Network Service Discovery"]}},
 "observer": {"type": "ids", "vendor": "iotmon", "product": "IoT Security Monitor", "version": "0.2.0"},
 "labels": {"severity": "high", "confidence": "high"},
 "iotmon": {"alert_id": 3, "status": "open", "confidence": 0.99, "details": {"ports_observed": 15, "...": "..."}}}
```

`event.severity` is 1–5 (info → critical); `event.risk_score` combines severity and confidence
(0–100), so a SIEM can sort a queue by both.

## CEF over syslog

```
<163>1 2026-10-07T10:35:10.280Z sensor-1 iotmon - DET-002 - CEF:0|iotmon|IoT Security Monitor|0.2.0|DET-002|port_scan|8|rt=1791369310280 src=192.168.1.66 dst=192.168.1.22 msg=Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22 cat=T1046 cs1Label=mitre cs1=T1046 Network Service Discovery cfp1Label=confidence cfp1=0.99 externalId=3
```

Facility local4; syslog severity from the alert (critical → 2, high → 3, medium → 4, low → 5,
info → 6); MSGID is the rule ID. CEF severity: info 1, low 3, medium 5, high 8, critical 10. Header
and extension values are escaped per the CEF spec (`|`, `\`, `=`, newlines).

## Example configurations

[`examples/siem/`](../examples/siem):

| File | |
| --- | --- |
| [`filebeat.yml`](../examples/siem/filebeat.yml) | Filebeat → Elasticsearch, from `--ecs-file` (already ECS, so fields go straight to the root) |
| [`wazuh/ossec.conf.snippet.xml`](../examples/siem/wazuh/ossec.conf.snippet.xml) + [`wazuh/local_rules.xml`](../examples/siem/wazuh/local_rules.xml) | Wazuh agent reads `alerts.jsonl`; manager rules map severity to rule levels, raise high-confidence alerts a level, and tag ATT&CK techniques |
| [`splunk/inputs.conf`](../examples/siem/splunk/inputs.conf) + [`splunk/props.conf`](../examples/siem/splunk/props.conf) | Splunk UF on `alerts.jsonl` (CIM field aliases), or CEF over UDP |
| [`rsyslog-iotmon.conf`](../examples/siem/rsyslog-iotmon.conf) | rsyslog collector filing iotmon's syslog messages |

The output formats are covered by tests (field mapping, CEF escaping, a real UDP syslog round trip,
the exports). The shipper and SIEM configurations are reference examples: they follow each product's
documented format but are not run in this repository's CI.

## Structured operational logs

Alerts are the product; the logs are about the monitor itself — what ran, with which rules, how
fast, and what went wrong. Off by default (the terminal output doesn't change); `--log-format json`
writes one JSON object per line to stderr or `--log-file`:

```sh
iotmon read samples/iot-lab.pcap -q --log-format json --log-file data/iotmon.log
```

```json
{"ts":"2026-10-17T12:02:11.418Z","level":"info","logger":"iotmon","event":"run started","mode":"read","source":"samples/iot-lab.pcap","rules":15,"enabled_rules":15,"inventory":null,"baseline":null,"syslog":null}
{"ts":"2026-10-17T12:02:11.902Z","level":"warning","logger":"iotmon","event":"alert","rule_id":"DET-002","rule":"port_scan","severity":"high","confidence":0.99,"src":"192.168.1.66","dst":"192.168.1.22","title":"Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22","packet_ts":1791369310.28}
{"ts":"2026-10-17T12:02:12.640Z","level":"info","logger":"iotmon","event":"run finished","packets":3546,"alerts":12,"devices":7,"seconds":1.22,"packets_per_s":2906.6,"alerts_by_severity":{"medium":6,"high":5,"critical":1}}
```

`--log-format text` gives the same events as `key=value` lines. A failing alert sink (SIEM down)
logs `"event":"alert sink failed"` at error level.
