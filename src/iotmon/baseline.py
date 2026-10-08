"""Behavioural baseline: what each lab device normally does.

The anomaly rules (DET-003 connection rate, DET-004 unusual ports, DET-005
unexpected external connections) do not ask "is this port bad?" but "is this
normal *for this device*?". The answer comes from a profile per device:

    client_ports    service ports it connects to       sensor: {1883, 53}
    server_ports    ports it answers on                camera: {80}
    external_peers  internet hosts it talks to         plug: {203.0.113.50}
    peak_connections  most new connections it opened in any one window
    mqtt_*          client IDs it connected to the broker with, topics it
                    published and subscribed to, most messages per window

A profile is learned from traffic during a learning period (the first
minutes of a capture, or a whole trusted capture with `iotmon baseline
learn`) and then frozen: later traffic is compared with it, never added to
it, so an attack cannot teach the baseline that attacks are normal.

Profiles are keyed by IP address: the rules see IPs, and IoT/OT devices are
mostly statically addressed (address changes are the device_change rule's
job).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_BASELINE = "data/baseline.json"


@dataclass(slots=True)
class DeviceProfile:
    client_ports: set = field(default_factory=set)
    server_ports: set = field(default_factory=set)
    external_peers: set = field(default_factory=set)
    peak_connections: int = 0
    mqtt_client_ids: set = field(default_factory=set)
    mqtt_publish: set = field(default_factory=set)
    mqtt_subscribe: set = field(default_factory=set)
    peak_mqtt_messages: int = 0
    modbus_servers: set = field(default_factory=set)   # PLCs this client talked to
    modbus_functions: set = field(default_factory=set)  # function names used as a client
    modbus_wrote: bool = False                          # issued a write during the baseline
    peak_modbus_requests: int = 0

    def as_dict(self) -> dict:
        d = {"client_ports": sorted(self.client_ports), "server_ports": sorted(self.server_ports),
             "external_peers": sorted(self.external_peers), "peak_connections": self.peak_connections}
        if self.mqtt_client_ids or self.mqtt_publish or self.mqtt_subscribe:
            d.update({"mqtt_client_ids": sorted(self.mqtt_client_ids), "mqtt_publish": sorted(self.mqtt_publish),
                      "mqtt_subscribe": sorted(self.mqtt_subscribe),
                      "peak_mqtt_messages": self.peak_mqtt_messages})
        if self.modbus_servers or self.modbus_functions:
            d.update({"modbus_servers": sorted(self.modbus_servers),
                      "modbus_functions": sorted(self.modbus_functions),
                      "modbus_wrote": self.modbus_wrote, "peak_modbus_requests": self.peak_modbus_requests})
        return d


class Baseline:
    def __init__(self, path: str | Path | None = None, learning_period: float = 120.0,
                 window: float = 60.0):
        self.path = Path(path) if path else None
        self.learning_period = learning_period
        self.window = window  # connection-rate window the peaks were measured over
        self.devices: dict[str, DeviceProfile] = {}
        self.learn_all = False  # `baseline learn`: the whole capture is trusted
        self.learned: dict = {}
        if self.path and self.path.exists():
            self._load()
        # A profile loaded from disk is frozen: no learning period.
        self.frozen = bool(self.devices)

    def __len__(self) -> int:
        return len(self.devices)

    def __contains__(self, ip: str) -> bool:
        return ip in self.devices

    def get(self, ip: str | None) -> DeviceProfile | None:
        return self.devices.get(ip or "")

    def is_learning(self, elapsed: float) -> bool:
        if self.frozen:
            return False
        return self.learn_all or elapsed < self.learning_period

    # -- learning ---------------------------------------------------------- #
    def observe_session(self, client: str, server: str, port: int | None, client_local: bool,
                        server_local: bool, server_external: bool) -> None:
        if port is None:
            return
        if client_local:
            prof = self.devices.setdefault(client, DeviceProfile())
            prof.client_ports.add(port)
            if server_external:
                prof.external_peers.add(server)
        if server_local:
            self.devices.setdefault(server, DeviceProfile()).server_ports.add(port)

    def observe_rate(self, client: str, connections: int) -> None:
        prof = self.devices.setdefault(client, DeviceProfile())
        prof.peak_connections = max(prof.peak_connections, connections)

    def observe_mqtt(self, kind: str, ip: str, client_id: str, topic: str) -> None:
        prof = self.devices.setdefault(ip, DeviceProfile())
        if kind == "connect" and client_id:
            prof.mqtt_client_ids.add(client_id)
        elif kind == "publish":
            prof.mqtt_publish.add(topic)
        elif kind == "subscribe":
            prof.mqtt_subscribe.add(topic)

    def observe_mqtt_rate(self, ip: str, messages: int) -> None:
        prof = self.devices.setdefault(ip, DeviceProfile())
        prof.peak_mqtt_messages = max(prof.peak_mqtt_messages, messages)

    def observe_modbus(self, client: str, server: str, func_name: str, write: bool) -> None:
        prof = self.devices.setdefault(client, DeviceProfile())
        prof.modbus_servers.add(server)
        prof.modbus_functions.add(func_name)
        prof.modbus_wrote = prof.modbus_wrote or write

    def observe_modbus_rate(self, ip: str, requests: int) -> None:
        prof = self.devices.setdefault(ip, DeviceProfile())
        prof.peak_modbus_requests = max(prof.peak_modbus_requests, requests)

    def topic_owners(self, topic: str) -> set[str]:
        """Devices that published this topic during the baseline."""
        return {ip for ip, p in self.devices.items() if topic in p.mqtt_publish}

    def mark_learned(self, start: float, end: float, packets: int) -> None:
        def iso(ts):
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")
        self.learned = {"start": iso(start), "end": iso(end), "packets": packets}

    # -- persistence ------------------------------------------------------- #
    def _load(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.window = float(data.get("window_s", self.window))
        self.learned = data.get("learned_from", {})
        for ip, d in data.get("devices", {}).items():
            self.devices[ip] = DeviceProfile(set(d.get("client_ports", [])), set(d.get("server_ports", [])),
                                             set(d.get("external_peers", [])), int(d.get("peak_connections", 0)),
                                             set(d.get("mqtt_client_ids", [])), set(d.get("mqtt_publish", [])),
                                             set(d.get("mqtt_subscribe", [])), int(d.get("peak_mqtt_messages", 0)),
                                             set(d.get("modbus_servers", [])), set(d.get("modbus_functions", [])),
                                             bool(d.get("modbus_wrote", False)), int(d.get("peak_modbus_requests", 0)))

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"learned_from": self.learned, "window_s": self.window,
                "devices": {ip: p.as_dict() for ip, p in sorted(self.devices.items(), key=_ip_sort)}}
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _ip_sort(item):
    ip = item[0]
    try:
        return (0, tuple(int(x) for x in ip.split(".")))
    except ValueError:
        return (1, ip)
