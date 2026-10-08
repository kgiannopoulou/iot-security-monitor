# Week 2: Device Discovery and Asset Inventory

**Milestone:** build an inventory automatically from observed traffic, and
raise an event when a device the network has never seen before appears.

Week 1 answered "what does the monitor see?". Week 2 turns those packets into
security information: *which devices are on this network, what do they do,
and is anything here that should not be?* Asset visibility comes first in
every OT security framework. IEC 62443-2-1, NIST SP 800-82, and the CISA
"Foundations for OT Cybersecurity: Asset Inventory Guidance" all start with
it, because you cannot defend a device you do not know exists.

Every example below is real `iotmon` output. The full transcript is in
[`sample-output/week2-inventory.txt`](sample-output/week2-inventory.txt).

---

## 1. What identifies a device

| Identifier | Where it comes from | Stable? | Used for |
|---|---|---|---|
| **MAC address** | Ethernet header, every frame on the local segment | Yes, per network card (unless randomised) | **The asset key** |
| IP address | IP header, ARP | No: DHCP leases expire, admins re-address | Current location, shown to the analyst |
| OUI (first 3 MAC bytes) | Derived from the MAC | Yes | Vendor: Espressif, Hikvision, Raspberry Pi… |
| Locally-administered bit | 2nd-lowest bit of the first MAC byte | Yes | Flags VMs, containers, randomised phone MACs |
| MQTT client ID, DNS names | Application payloads | Mostly | Human-readable name (`temp-sensor-01`) |
| Ports it answers on | SYN-ACKs and replies from a service port | Mostly | Role: broker, DNS server, camera… |

The inventory is keyed by **MAC**, not IP. An IP is where a device is right
now; a MAC is which device it is. If the inventory were keyed by IP, a sensor
renewing its DHCP lease would look like one device leaving and a new one
arriving, and an attacker who took over a known device's IP would look like
that trusted device.

The catch: MACs are only visible **on the local layer-2 segment**. A router
rewrites the source MAC to its own on every packet it forwards, so the
monitor has to sit on the same switch or VLAN as the devices it inventories
(the SPAN-port placement from [Week 1, section 9](01-networking-foundation.md#9-where-the-monitor-sits-and-why-it-sees-everything)).

## 2. The inventory record

For every device, `iotmon` maintains this record (from `inventory show --json`,
keyed by IP the way the brief asked for):

```json
"192.168.1.20": {
  "ips": ["192.168.1.20"],
  "mac": "24:0a:c4:00:00:20",
  "vendor": "Espressif (ESP32/ESP8266)",
  "name": "temp-sensor-01",
  "role": "MQTT client (sensor/actuator)",
  "first_seen": "2026-10-07T10:30:01+00:00",
  "last_seen": "2026-10-07T10:37:55+00:00",
  "protocols": ["ARP", "MQTT", "NTP"],
  "services": [],
  "connections": 2,
  "packets": 200,
  "bytes": 14120,
  "status": "approved",
  "key": "24:0a:c4:00:00:20"
}
```

How each field is filled, all passively (the monitor never sends a packet):

| Field | Rule |
|---|---|
| `first_seen` / `last_seen` | Timestamp of the first and latest packet the device *sent* |
| `protocols` | Application protocols it actually spoke. Bare SYNs and RSTs are ignored, otherwise a port scan would "teach" the scanner dozens of protocols |
| `services` | Ports it *answered* on, so a reply from port 1883 makes it an MQTT broker |
| `connections` | Conversations (flows) it took part in, as client or server. A flow is opened by the first packet of a new client-socket/server-socket pair, which is why the temperature sensor has only 2 (one NTP exchange, one long MQTT session) |
| `role` | Inferred from services first (MQTT broker, DNS server, camera with Telnet + web UI), then behaviour (publishes MQTT → sensor/actuator) |
| `name` | MQTT client ID from its CONNECT packet |
| `status` | `approved` / `pending` / `new` (see section 3) |

`connections` is a useful shape metric. In the sample capture the smart plug
has 30, because it opens a new HTTPS session to its cloud each check-in. The
IP camera has 19 during the baseline and **2,465** after it is infected and
starts flooding a target. The count alone tells you its behaviour changed.

## 3. Remembering devices: the asset register

The Week 1 monitor learned what "normal" looks like for 60 seconds every time
it started. That has two problems: a device that joins during those 60 seconds
is silently trusted, and a restart forgets everything.

Week 2 adds a persistent **asset register**, `data/inventory.json`:

```
            trusted capture                           any capture / live
                  │                                          │
     iotmon inventory learn ──▶  inventory.json  ◀──▶  iotmon read|live --inventory
                                  (approved,                 │
                                   pending)                  ├─ device not in register?  → new_device alert, saved as pending
                                       ▲                     └─ known MAC on a new IP?   → device_change alert
                                       │
                          iotmon inventory approve <MAC|IP>   (analyst reviews pending devices)
```

| Status | Meaning |
|---|---|
| `approved` | Expected on this network: learned from trusted traffic, or approved by an analyst |
| `pending` | Seen and alerted once, not yet reviewed. It does **not** alert again on every run; it shows up in `inventory show` until someone decides |
| `new` | First seen in the current run (dashboard only; saved as `pending`) |

With a register loaded there is **no learning period**: a device that is not
in it alerts on its very first packet. When the register is empty (first
start of the live lab) it bootstraps itself: devices seen in the learning
period are saved as approved and anything later is pending. Counters
accumulate across runs, but replaying the same traffic twice does not double
them.

### The workflow on the sample capture

The sample capture is 5 minutes of normal lab traffic followed by a rogue
Raspberry Pi joining at 10:35:00. Learn the baseline from the first 290
seconds:

```
$ python -m iotmon inventory learn samples/iot-lab.pcap --duration 290
learned 6 devices from 556 packets; 6 new, register data/inventory.json now holds 6 assets
```

Replay the whole capture against it:

```
$ python -m iotmon read samples/iot-lab.pcap -q --utc --inventory
10:35:00  [ALERT MEDIUM] new_device: New IoT device detected: 192.168.1.66 (Raspberry Pi Foundation)
          IP:            192.168.1.66
          MAC:           b8:27:eb:00:00:66
          Vendor:        Raspberry Pi Foundation
          First packet:  who-has 192.168.1.1 tell 192.168.1.66
10:35:00  [ALERT MEDIUM] port_scan: ARP sweep from 192.168.1.66
...
asset register data/inventory.json: 7 assets, added: 1 pending
```

The register now shows the intruder waiting for review:

```
$ python -m iotmon inventory show
IP              MAC               VENDOR                     ROLE                             PROTOCOLS                 CONN  FIRST SEEN (UTC)     LAST SEEN (UTC)      STATUS
192.168.1.21    24:0a:c4:00:00:21 Espressif (ESP32/ESP8266)  MQTT client (sensor/actuator)    ARP,DNS,HTTPS,MQTT,NTP      30  2026-10-07 10:30:01  2026-10-07 10:37:53  approved
192.168.1.1     50:c7:bf:00:00:01 TP-Link                    DNS server                       ARP,DNS,NTP                 17  2026-10-07 10:30:01  2026-10-07 10:37:15  approved
192.168.1.20    24:0a:c4:00:00:20 Espressif (ESP32/ESP8266)  MQTT client (sensor/actuator)    ARP,MQTT,NTP                 2  2026-10-07 10:30:01  2026-10-07 10:37:55  approved
192.168.1.10    dc:a6:32:00:00:10 Raspberry Pi Trading       MQTT broker                      ARP,MQTT                    10  2026-10-07 10:30:01  2026-10-07 10:37:55  approved
192.168.1.22    44:19:b6:00:00:22 Hikvision                  IP camera / embedded web device  ARP,DNS,HTTP,HTTPS,IRC,N  2465  2026-10-07 10:30:04  2026-10-07 10:37:50  approved
192.168.1.5     3c:52:82:00:00:05 HP                         client                           ARP,HTTP,NTP                 9  2026-10-07 10:30:06  2026-10-07 10:37:40  approved
192.168.1.66    b8:27:eb:00:00:66 Raspberry Pi Foundation    unclassified                     ARP,MQTT,TELNET             64  2026-10-07 10:35:00  2026-10-07 10:36:10  pending

7 assets, 1 pending review
```

Read as an analyst would: a Raspberry Pi nobody registered, which spoke only
ARP, MQTT and Telnet (no DNS, no NTP, unlike every real device here), and has
no role because it offered no services. It was a scanner, not a sensor. Also
note the camera's protocols now include **IRC**: the register keeps the
evidence of the compromise even after the capture ends.

## 4. Inventory events

| Event | Trigger | Severity | Why it matters |
|---|---|---|---|
| `new_device` | MAC not in the register (or, without one, first seen after the learning period) | medium | Rogue hardware, contractor laptop, replaced sensor. ATT&CK T1200, ICS T0848 |
| `device_change` IP conflict | An IP already bound to one MAC is claimed by a **different** MAC | high | The signature of ARP spoofing: the attacker tells everyone "the gateway's IP is at my MAC" to sit in the middle (T1557.002 / ICS T0830). Also catches plain address clashes, which break OT devices anyway |
| `device_change` IP change | A known MAC appears on a different IP, within the capture or compared with the register | low | Usually DHCP. Worth seeing in OT, where PLCs and HMIs are normally statically addressed and a move is a change-management event |

Inventory events print as a block with everything needed for triage,
mirroring the format in the project brief:

```
10:35:00  [ALERT MEDIUM] new_device: New IoT device detected: 192.168.1.66 (Raspberry Pi Foundation)
          IP:            192.168.1.66
          MAC:           b8:27:eb:00:00:66
          Vendor:        Raspberry Pi Foundation
          First packet:  who-has 192.168.1.1 tell 192.168.1.66
```

The same fields go into `alerts.jsonl` (`details.ip`, `details.mac`,
`details.vendor`) for a SIEM, and the dashboard's device table gains
**Connections** and **Status** columns, with unreviewed devices highlighted.

## 5. Limits of passive inventory

| Limit | Effect | Mitigation |
|---|---|---|
| Silent devices | A device that never transmits is never inventoried | Passive is the safe choice for OT, where active scans can crash fragile PLCs. Complement it with a scheduled, gentle ARP scan or the switch's MAC table |
| MAC randomisation | Phones and some laptops rotate MACs, so each new MAC looks like a new device | Shown as "locally administered" in the vendor column; rare on IoT/OT devices |
| MAC spoofing | An attacker can clone an approved device's MAC | Then they also need its IP, which raises an IP conflict while the real device is up. Port security / 802.1X on the switch is the real control |
| Routed traffic | Beyond a router, every device shares the router's MAC | Monitor per L2 segment, or add DHCP/switch data |
| Old IPs stay bound | After a DHCP move, the old IP still maps to the device for the rest of the run, so a new device reusing it can raise a conflict | Low cost in static OT networks; documented false positive |

## 6. Live lab check

In the Docker lab the monitor runs with `--inventory /data/inventory.json`,
so the register survives restarts. On a clean start the 7 lab devices were
learned and approved in the first minute. Then a rogue container joined, and
a second container sent gratuitous ARP replies claiming the MQTT broker's IP:

```
07:07:57  [ALERT MEDIUM] new_device: New IoT device detected: 172.28.0.77 (locally administered (virtual / randomised))
          IP:            172.28.0.77
          MAC:           ca:30:56:c9:5d:12
          Vendor:        locally administered (virtual / randomised)
          First packet:  who-has 172.28.0.77 tell 172.28.0.77
07:08:00  [ALERT MEDIUM] new_device: New IoT device detected: 172.28.0.79 (locally administered (virtual / randomised))
07:08:01  [ALERT HIGH] device_change: IP conflict: 172.28.0.10 claimed by ea:70:f0:99:43:66, already used by dc:a6:32:00:00:10
          IP:            172.28.0.10
          MAC:           ea:70:f0:99:43:66
          Previous MAC:  dc:a6:32:00:00:10
```

The ARP spoofer is visible twice: as a new device, and as a second MAC for
the broker's address. Commands and full output are in the
[lab guide](lab-setup.md#asset-register-week-2) and
[`sample-output/live-lab-week2.txt`](sample-output/live-lab-week2.txt).

## 7. How it is built

| Piece | Where |
|---|---|
| Per-run inventory, connection counting, address-change tracking | [`src/iotmon/inventory.py`](../src/iotmon/inventory.py) |
| Persistent register: load, merge (replay-safe), approve, save | [`src/iotmon/assets.py`](../src/iotmon/assets.py) |
| `new_device` (register-aware) and `device_change` rules | [`src/iotmon/detections.py`](../src/iotmon/detections.py) |
| `inventory learn / show / approve`, `--inventory` on `read` / `live` | [`src/iotmon/cli.py`](../src/iotmon/cli.py) |
| Tests: record fields, ARP-spoofing conflict, IP change, register round trip, bootstrap, replay safety, old-database upgrade, the full learn → detect → approve workflow | [`tests/test_inventory.py`](../tests/test_inventory.py) |

## Self-check

- Why is the asset key a MAC address and not an IP, and where does that break down?
- Which packet told the monitor that 192.168.1.10 is an MQTT broker?
- Why do bare SYN packets not add protocols to a device's record?
- What does an IP conflict look like on the wire during ARP spoofing, and which of the two MACs is the attacker?
- Why is passive discovery preferred over an `nmap` sweep on an OT network?
