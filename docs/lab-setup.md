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
| `dashboard` | 127.0.0.1:8080 | | Reads the same database |

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

## Full detection set

The full detection set (scan, rogue device, brute force, flood) is exercised
by the bundled sample capture instead of live traffic. See
[detection-rules.md](detection-rules.md#validating-the-rules).

## Notes

* Devices that connected to the broker *before* the monitor started show no
  name. The name comes from the MQTT `CONNECT` client ID, which is only sent
  once per session. Restart a device (`docker compose restart temp-sensor`)
  to see it appear.
* The lab broker's password (`devices` / `S3nsor!2026`) is a lab-only
  credential baked into `lab/broker/Dockerfile`.
* Keep all testing inside this lab network.
