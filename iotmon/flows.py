"""Group packets into bidirectional flows (conversations).

A *packet* is one frame on the wire. A *flow* is every packet exchanged
between the same client socket and server socket, in both directions, until
it goes idle. Flows are what you reason about ("the sensor kept one MQTT
session open for 5 minutes"); packets are what you actually capture.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import PacketRecord


@dataclass(slots=True)
class Flow:
    protocol: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    app: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0
    packets_c2s: int = 0
    packets_s2c: int = 0
    flags: set = field(default_factory=set)

    @property
    def key(self) -> tuple:
        return (self.protocol, self.client_ip, self.client_port, self.server_ip, self.server_port)

    @property
    def state(self) -> str:
        if self.protocol != "TCP":
            return "BIDIRECTIONAL" if self.packets_s2c else "ONE-WAY"
        seen = "".join(self.flags)
        if "SA" in self.flags:
            return "CLOSED" if ("F" in seen or "R" in seen) else "ESTABLISHED"
        if "R" in seen:
            return "REJECTED"
        return "NO-REPLY"

    def as_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "app": self.app,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.last_seen - self.first_seen, 3),
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_c2s": self.packets_c2s,
            "packets_s2c": self.packets_s2c,
            "state": self.state,
        }


class FlowTable:
    def __init__(self, idle_timeout: float = 60.0):
        self.idle_timeout = idle_timeout
        self.active: dict[tuple, Flow] = {}
        self._last_sweep = 0.0

    def update(self, rec: PacketRecord) -> list[Flow]:
        """Account for one packet; return flows that expired as a result."""
        expired = []
        if rec.ts - self._last_sweep >= 5:
            expired = self.expire(rec.ts)
            self._last_sweep = rec.ts

        if rec.protocol not in ("TCP", "UDP") or not rec.src_ip or not rec.dst_ip:
            return expired

        if rec.is_response:
            key = (rec.protocol, rec.dst_ip, rec.dport, rec.src_ip, rec.sport)
            from_client = False
        else:
            key = (rec.protocol, rec.src_ip, rec.sport, rec.dst_ip, rec.dport)
            from_client = True

        flow = self.active.get(key)
        if flow is None:
            flow = Flow(*key, app=rec.app, first_seen=rec.ts, last_seen=rec.ts)
            self.active[key] = flow
        flow.last_seen = rec.ts
        flow.packets += 1
        flow.bytes += rec.length
        if from_client:
            flow.packets_c2s += 1
        else:
            flow.packets_s2c += 1
        if rec.tcp_flags:
            flow.flags.add(rec.tcp_flags)
        if rec.app and not flow.app:
            flow.app = rec.app
        return expired

    def expire(self, now: float) -> list[Flow]:
        done = [k for k, f in self.active.items() if now - f.last_seen > self.idle_timeout]
        return [self.active.pop(k) for k in done]

    def drain(self) -> list[Flow]:
        flows = list(self.active.values())
        self.active.clear()
        return flows
