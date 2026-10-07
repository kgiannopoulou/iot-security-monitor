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
