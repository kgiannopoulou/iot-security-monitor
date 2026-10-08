# Design Decisions

Why the monitor is built the way it is, written as the questions an
interviewer or reviewer would ask. Each answer gives the decision, the
alternatives, and the trade-off I accepted.

---

### Why passive monitoring instead of scanning the devices?

Because on OT networks active scanning can break things. Fragile embedded
stacks have crashed under nmap scans, and a PLC that faults stops a
production line. A passive monitor never sends a packet, so it can't cause
an outage, and it can't be noticed by an attacker either. The cost is that
it only knows what devices *say*: a device that never transmits is
invisible. Week 3 showed exactly that, when the Docker gateway was silent
until it had to answer an ICMP error (see [lessons learned](lessons-learned.md)).

### Where does the monitor sit, and why there?

On a copy of the traffic: a switch SPAN/mirror port on a real network, and
the host side of the Docker bridge (`iotlab0`) in the lab. That is the only
place it sees device-to-device traffic as well as traffic to the internet.
A monitor on the internet gateway would miss the lateral movement (the
port scan, the Telnet brute force between devices), which is the part of
an IoT intrusion that matters most. [Week 1, section 9](01-networking-foundation.md).

### Why per-device baselines instead of fixed thresholds?

Because "normal" differs by an order of magnitude between devices. The
motor drive publishes 60 MQTT messages a minute; the temperature sensor
publishes 12. A fixed threshold either misses the sensor being abused or
alerts on the drive all day. So the core rules compare each device with
its own learned behaviour (ports, peers, peak rates, topics) and use a
fixed floor only to stop very quiet devices alerting on noise:
`max(20, 5 × the device's busiest minute)`. Both numbers are explainable,
and the scenarios test them from both sides (the attack fires, the near
miss at 80% doesn't).

### Why freeze the baseline after learning?

An adaptive baseline can be trained. An attacker who ramps up slowly
teaches the monitor that their traffic is normal. A frozen baseline makes
the attacker's traffic stand out forever, at the cost of false positives
when the legitimate network changes, which then needs a deliberate
re-learn (`iotmon baseline learn` from a reviewed capture). On OT
networks, where change is rare and planned, that trade-off is right. On an
office network it probably wouldn't be.

### Why key devices by MAC and not by IP?

IPs move (DHCP); the network card doesn't. Keying by MAC also makes two
attacks visible that IP-keyed tracking hides: ARP spoofing (one IP
suddenly claimed by a second MAC, DET-008) and a device that changes its
IP to evade an allowlist. The limit: MACs can be spoofed and only exist on
the local segment, which is another reason the monitor sits on the
segment and not upstream.

### Why do time windows use packet timestamps and not the clock?

Determinism. With packet time, replaying the same capture always produces
the same alerts, so the tests can assert the exact list of twelve, and a
capture from last week is analysed as if it were live. With wall-clock
time, replay speed would change the results. The only wall-clock times in
the system are operational: when a run started, and when an analyst
triaged an alert.

### Why scapy, when Zeek and Suricata exist?

Learning and portability. scapy dissects MQTT, DNS and HTTP out of the box,
reads pcaps on Windows without libpcap, and lets me write the parser
layer by layer, which was the point of Week 1. It is slow (thousands of
packets per second), which is plenty for an IoT segment. If this ran in
production I would let Zeek or Suricata do the parsing and keep this
project's detection, baseline and posture layers on top of their logs.

### Why SQLite and not Elasticsearch or PostgreSQL?

Zero setup. One file, no server, and it ships with Python. WAL mode lets
the monitor write while the dashboard reads, even from separate
containers. It is the right size for one sensor. For many sensors, the
plan is to ship `alerts.jsonl` (one JSON evidence record per line,
already in a SIEM-friendly shape) to Wazuh or Elastic, and keep SQLite as
the local view.

### Why is the security posture a rule and not a risk score?

Because a rule can be explained in one sentence, and a score can't. "AT
RISK because there is an active high-severity alert" survives the
question "why?". "Risk 73" doesn't. A weighted score is used only where
ranking is the point (which device to look at first), and even there the
weights are simple (critical 10, high 5, medium 2, low 1; the device that
did it counts double the device it was done to).

### Why does an acknowledged alert still count towards the posture?

Acknowledging means "someone is investigating", not "the risk is gone".
If acknowledging cleared the posture, the fastest way to a green
dashboard would be to click *Ack* on everything. Only *resolved* and
*false positive* stop an alert from counting, and both take a note
explaining why.

### Why are the rules in a YAML file?

Separation of what an analyst tunes from what a developer changes. The
rule IDs, names, thresholds and windows, enabled flags and ATT&CK mappings
live in [`rules/detection_rules.yaml`](../rules/detection_rules.yaml);
the logic stays in Python. A site overrides only what it needs
(`lab/monitor.yaml` changes two keys). Documentation in a data file rots,
so a test replays every capture and fails if an alert's severity or ATT&CK
technique isn't declared for its rule. YAML rather than TOML because it is
what detection content usually looks like (Sigma, Wazuh, Elastic rules),
and it allows a comment on every threshold.

### Why a synthetic sample capture and no attacker container?

Safety and reproducibility. The sample capture is generated packet by
packet with a fixed seed, so it is byte-identical on every run, and a test
checks that the committed file matches the generator. It uses only
private and documentation address ranges. In the live lab, the attacks
run from inside existing containers (a short-lived "rogue" Pi, the sensor
playing a compromised device) and nothing leaves the lab network. No
offensive tooling is shipped.

### Why a src layout?

So the tests run against the installed package, not against whatever
happens to be in the working directory. It also makes the boundary clear:
`src/iotmon/` is the product, and `tools/`, `simulator/`, `lab/` and
`tests/` support it.

### Why is the dashboard plain HTML and JavaScript, not React?

Because the job is clarity, not interactivity. One HTML page, one chart
library from a CDN, a JSON API, and polling every five seconds. It loads
instantly, has nothing to build, and the whole front end can be read in
one sitting. The one write endpoint (alert triage) only accepts JSON and
checks the `Origin` header, so another website can't change alerts
through the analyst's browser.
