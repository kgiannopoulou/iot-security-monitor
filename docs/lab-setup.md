# Lab Setup (Docker)

Everything runs on one machine in an isolated Docker bridge network,
`172.28.0.0/24`. No hardware needed.

| Container | IP | MAC (pinned to a real vendor OUI) | Role |
|---|---|---|---|
| `broker` | 172.28.0.10 | `dc:a6:32:…` Raspberry Pi | Mosquitto MQTT broker, authentication required |
| `dns` | 172.28.0.53 | random | dnsmasq, answers only `*.lab` names, no upstream |
| `temp-sensor` | 172.28.0.20 | `24:0a:c4:…` Espressif | Publishes `factory/line1/temp` every 5 s |
| `smart-plug` | 172.28.0.21 | `24:0a:c4:…` Espressif | Publishes power every 10 s, subscribes to commands, cloud check-in every 60 s |
| `ip-camera` | 172.28.0.22 | `44:19:b6:…` Hikvision | Web UI on :80, **Telnet exposed on :23** (always refuses logins), uploads snapshots every 30 s |
| `cloud` | 172.28.0.30 | random | "Vendor cloud" HTTP API |
| `admin` | 172.28.0.5 | random | Workstation opening the camera UI every 60 s |
| `monitor` | host network | | `iotmon live -i iotlab0`, writes `data/lab/iotmon.db` |
| `dashboard` | 127.0.0.1:8080 | | Reads the same database; alert triage is its only write |

## Run

```bash
cd lab
docker compose up -d --build
# dashboard: http://localhost:8080
docker compose logs -f monitor
```

Inspect from the command line (the `MSYS_NO_PATHCONV=1` prefix is only needed
in Git Bash on Windows):

```bash
docker compose exec dashboard python -m iotmon report --db /data/iotmon.db
docker compose exec dashboard python -m iotmon status --db /data/iotmon.db      # posture (Week 5)
docker compose exec dashboard python -m iotmon alerts ack 4 --note "..." --db /data/iotmon.db
```

Watch the raw packet table for 30 seconds:

```bash
docker compose run --rm monitor live -i iotlab0 -t 30 --no-store
```

Stop and remove:

```bash
docker compose down
```

## How the monitor sees the traffic

The compose file names the bridge `iotlab0`
(`com.docker.network.bridge.name`). The monitor container uses
`network_mode: host` and `NET_RAW`/`NET_ADMIN` capabilities, so it captures on
the host side of the bridge and sees every frame between containers, like a
SPAN port. On Docker Desktop (Windows/macOS), "host" means the Docker Linux
VM, which is where the bridge lives, so this works there too. The full
explanation is in [Week 1, §9](01-networking-foundation.md#9-where-the-monitor-sits-and-why-it-sees-everything).

## Verifying a detection live

The camera intentionally exposes Telnet, so a single connection to it should
raise a `suspicious_port` alert within seconds:

```bash
docker compose exec admin python -c \
  "import socket; s = socket.create_connection(('172.28.0.22', 23), timeout=3); print(s.recv(64))"
```

Result in this lab (2026-10-07):

```
ALERTS
  2026-10-07 06:33:58  HIGH     suspicious_port    TELNET session 172.28.0.5 -> 172.28.0.22:23
```

Normal lab traffic over the same run raised no other alerts.

## Asset register (Week 2)

The monitor runs with `--inventory /data/inventory.json`, so the register
lives in `data/lab/inventory.json` on the host and survives restarts. On the
first start it is empty: the devices seen in the first 60 s are saved as
`approved`, and anything that appears later raises `new_device` and is saved
as `pending`. The register is saved every 30 s and on `docker compose stop`.

Add a device nobody approved, and a container that claims the broker's IP
with gratuitous ARP replies (ARP spoofing):

```bash
docker run --rm --network iot-lab_iotlab --ip 172.28.0.77 alpine:3.20 ping -c 3 172.28.0.10

MSYS_NO_PATHCONV=1 docker run --rm --network iot-lab_iotlab --ip 172.28.0.79 --cap-add NET_RAW \
  --entrypoint python iot-lab-monitor -c "
from scapy.all import ARP, Ether, sendp, get_if_hwaddr
me = get_if_hwaddr('eth0')
sendp(Ether(src=me, dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, hwsrc=me, psrc='172.28.0.10',
      hwdst='ff:ff:ff:ff:ff:ff', pdst='172.28.0.10'), iface='eth0', count=3, inter=0.5)"
```

Result in this lab (2026-10-07, full output in
[`sample-output/live-lab-week2.txt`](sample-output/live-lab-week2.txt)):

```
07:07:57  [ALERT MEDIUM] new_device: New IoT device detected: 172.28.0.77 (locally administered (virtual / randomised))
07:08:00  [ALERT MEDIUM] new_device: New IoT device detected: 172.28.0.79 (locally administered (virtual / randomised))
07:08:01  [ALERT HIGH] device_change: IP conflict: 172.28.0.10 claimed by ea:70:f0:99:43:66, already used by dc:a6:32:00:00:10
```

Review and approve from the host (stop the lab first, or run it inside the
container). The register is plain JSON:

```bash
python -m iotmon inventory show --inventory data/lab/inventory.json
python -m iotmon inventory approve 172.28.0.77 --inventory data/lab/inventory.json
```

Do not open `data/lab/iotmon.db` from Windows while the lab is running.
SQLite's WAL shared memory does not work across the Docker Desktop file-share
boundary, so a host-side connection can checkpoint away the containers' WAL.
Query it through the dashboard API or `docker compose exec dashboard` instead.

## MQTT telemetry (Week 4)

The simulated devices publish harmless telemetry to the Mosquitto broker:

| Device | Client ID | Topic | Example value | Every |
|---|---|---|---|---|
| `temp-sensor` (172.28.0.20) | `temp-sensor-01` | `factory/temperature` | `24.6` | 5 s |
| `motor-drive` (172.28.0.23, Siemens OUI) | `motor-drive-01` | `factory/pressure`, `factory/motor/rpm` | `1.8`, `1450` | 2 s |
| `smart-plug` (172.28.0.21) | `smart-plug-01` | `factory/line1/plug/power` (subscribes to `.../cmd`) | `{"w": 41.2, "on": true}` | 10 s |

See what the monitor sees at the protocol level (run inside the container,
for the WAL reason above):

```bash
docker compose exec dashboard python -m iotmon mqtt --db /data/iotmon.db
```

Or open the MQTT clients and topics tables on the dashboard.

## Detection scenarios (Week 3 and 4)

The monitor also runs with `--baseline /data/baseline.json` and the lab's
own config, [`lab/monitor.toml`](../lab/monitor.toml). On a fresh start it
learns each device's normal behaviour during the first 120 s and saves it
to `data/lab/baseline.json`. Once that file exists, run the controlled
scenarios:

```bash
python tools/lab_scenarios.py                                   # all eight, about two minutes
python tools/lab_scenarios.py --only det-003-connection-flood   # one
```

| Scenario | Runs in | Action | Must fire |
|---|---|---|---|
| `det-001-new-device` | new container, Raspberry Pi MAC, 172.28.0.66 | one connection to the broker | DET-001 |
| `det-002-port-scan` | same rogue container | TCP connect scan of 30 broker ports | DET-002 |
| `det-003-connection-flood` | `temp-sensor` (compromised) | 30 broker connections in about 10 s | DET-003 |
| `det-004-unusual-port` | `temp-sensor` | camera web UI, then camera Telnet | DET-004 |
| `det-005-external-connection` | `temp-sensor` | TCP to 198.51.100.23:8883 with **TTL 1** | DET-005 |
| `det-009-new-mqtt-client` | `admin` | MQTT client `mqtt-explorer-4f2a` subscribes to `#` for 6 s | DET-004, DET-009 |
| `det-009-message-burst` | `temp-sensor` | 150 publishes to `factory/temperature` in 15 s | DET-009 |
| `det-009-topic-spoofing` | `temp-sensor` | publishes `factory/motor/rpm = 0` (the motor drive's topic) | DET-009 |

The attack code is [`lab/scenarios/attacks.py`](../lab/scenarios/attacks.py)
(standard library only, piped into the containers). Every target is a lab
address. The single off-lab connection is sent with TTL 1, so the lab
gateway drops it and nothing leaves the lab.

DET-001 fires only once per MAC: the rogue device is then in the register as
`pending`. To repeat the full run, stop the lab and start again from an
empty `data/lab/`. Results from 2026-10-07 (5/5 passed, plus the gateway
finding from the first run): [`sample-output/live-lab-week3.txt`](sample-output/live-lab-week3.txt)
and the [Week 3 write-up](03-detection-engine.md#6-the-scenarios-live-in-the-docker-lab).

The full kill chain (ARP sweep, brute force, botnet C2, flood) is exercised
by the bundled sample capture. See
[detection-rules.md](detection-rules.md#validating-the-rules).

## Notes

* Devices that connected to the broker *before* the monitor started show no
  name. The name comes from the MQTT `CONNECT` client ID, which is only sent
  once per session. Restart a device (`docker compose restart temp-sensor`)
  to see it appear.
* The lab broker's password (`devices` / `S3nsor!2026`) is a lab-only
  credential baked into `lab/broker/Dockerfile`.
* Keep all testing inside this lab network.
