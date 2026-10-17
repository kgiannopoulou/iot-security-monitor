# Custom rules and confidence scoring

## Custom rules (YAML, no Python)

The fifteen built-in rules ([detection-rules.md](detection-rules.md)) are detectors with state and
learned baselines. Site-specific rules are usually simpler, so they can be written as data:

```yaml
custom_rules:
  - id: CUS-001
    name: Telnet attempt inside the IoT network
    severity: high
    confidence: 0.85
    attack: ["T1021 Remote Services", "T1110 Brute Force"]
    match:                       # every condition must hold (AND)
      protocol: TCP
      dst_port: [23, 2323]       # a list means any of these (OR)
      src_net: 192.168.1.0/24
      new_connection: true       # SYN / first packet of a flow only
```

```sh
iotmon read samples/iot-lab.pcap -q --custom-rules rules/custom_rules.example.yaml
iotmon rules --custom-rules rules/custom_rules.example.yaml -v
iotmon rules validate my_rules.yaml          # exit 1 if invalid: use it in CI
```

or point a site config at the file: `custom_rules: my_rules.yaml` (relative to the config).

### Match conditions

| Condition | Matches when |
| --- | --- |
| `protocol` | `TCP`, `UDP`, `ICMP`, `ARP`… (one or a list) |
| `app` | the decoded application protocol: `MQTT`, `DNS`, `HTTP`, `MODBUS`, `TELNET`… |
| `dst_port` / `not_dst_port` | destination port in / not in the list |
| `src_net` / `dst_net` / `not_src_net` / `not_dst_net` | address in / not in these IPs or CIDR networks |
| `src_zone` / `dst_zone` | OT zone from the site policy (`OT`, `IT`) |
| `direction` | `internal` (local → local), `outbound` (local → internet), `inbound` |
| `new_connection` | `true`: only the packet that opens a connection (TCP SYN, first UDP packet of a flow) |
| `info_contains` | case-insensitive text in the decoded detail: DNS name, MQTT topic, HTTP request line |
| `min_length` | packet length at least this many bytes |

### Thresholds

Without `threshold`, every match alerts (once per source per `cooldown_s`, default 300 s). With it,
the rule counts matches per group in a sliding window:

```yaml
    threshold:
      count: 3          # alert at the 3rd …
      window_s: 60      # … within 60 seconds
      group_by: src     # per source (or dst, src_dst)
      distinct: dst     # count distinct destinations, not packets (or dst_port, src, info)
```

### Validation

Rule files — the custom ones *and* `rules/detection_rules.yaml` — are validated against
[`rules/schema/rules.schema.json`](../rules/schema/rules.schema.json) (JSON Schema 2020-12) when they
are loaded. Every problem is reported with its path, and the monitor refuses to start rather than run
with a rule that would silently never fire:

```
$ iotmon rules validate bad.yaml
invalid bad.yaml: 5 problems
  custom_rules[0].id: 'CUS-1' does not match '^CUS-[0-9]{3}$'
  custom_rules[0].match: Additional properties are not allowed ('dst_prot' was unexpected)
  custom_rules[0].name: 'x' is too short
  custom_rules[0].severity: 'severe' is not one of ['info', 'low', 'medium', 'high', 'critical']
  custom_rules[0].match.src_net: '999.1.1.0/24' is not an IP address or network
```

Beyond the schema: duplicate rule IDs and malformed networks are errors too. Editors that support
JSON Schema for YAML (VS Code with the YAML extension) can use the schema file for completion.

On the sample capture the three enabled example rules fire on the attack — Telnet from the rogue Pi
(CUS-001), the camera's IRC C2 session (CUS-002), and the camera fanning out to new internet hosts
(CUS-003) — and the built-in results are unchanged (12 alerts).

## Confidence scoring

Severity says how bad an alert would be; **confidence** says how sure the monitor is that it's real.
Every alert gets a score from 0 to 1 and a level (high ≥ 0.75, medium ≥ 0.5, low), with the reasons
([`confidence.py`](../src/iotmon/confidence.py)):

| Factor | Effect |
| --- | --- |
| Rule prior (`confidence:` per rule in the rule file) | Starting point: how often the rule is right. Modbus writes from an unapproved client 0.9; traffic spikes 0.4 |
| Margin over a closed-window threshold | +0.15 at ≥ 3×, +0.05 at ≥ 1.5× (counting rules fire at the threshold, so no penalty for "just over") |
| Unknown source | +0.10 when the source isn't an approved asset (or, without a register, appeared after learning) |
| Corroboration | +0.10 when the same source raised a different rule in the last 10 minutes |
| Still learning | −0.10 while the baseline is being learned |

```
$ iotmon alert 4
SECURITY ALERT
Alert ID:     ALT-0004
Severity:     HIGH
Confidence:   0.80 (high)
...
Why this confidence:
  rule prior 0.60
  +0.10 source is not an approved asset
  +0.10 same source also raised DET-001, DET-002
```

It shows in the terminal, `iotmon alerts` (CONF column), the alert card, exports, `alerts.jsonl`, the
ECS/CEF output and the structured logs.

**Does it separate real from benign?** Four benign look-alike scenarios
([`generate_scenarios.py`](../tools/generate_scenarios.py)) are tested next to the attacks: a broker
restart (looks like a reconnect storm) and a gateway reboot (an NTP/DNS burst) stay silent; a camera
firmware download (traffic spike, 0.55) and an admin's SSH maintenance session (unusual port, 0.60)
do alert — real false positives — but never with high confidence. The tests require exactly that,
and that attacks score higher on average than the look-alikes. On the sample intrusion, every alert
from the rogue device after its first one scores high (0.80–0.99), because it is unknown and raises
several rules.

The priors are judgement, calibrated on the scenarios and the live lab's three false positives, not
on a labelled dataset; a real deployment would tune them from triage outcomes (`iotmon alerts fp`).
