"""Detection engine.

Every detector is a small state machine fed one PacketRecord at a time.
Time windows use the *packet* timestamp, never the wall clock, so replaying
a pcap gives exactly the same alerts as watching the traffic live.
"""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from .models import KNOWN_SERVICES, Alert, PacketRecord

if TYPE_CHECKING:
    from .inventory import Device, Inventory


class Context:
    """What the pipeline knows when a detector sees a packet."""

    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.new_device: Device | None = None
        self.first_ts: float | None = None


class Detector:
    name = "base"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.cooldown = float(cfg.get("cooldown_s", 300))
        self._last_fired: dict[tuple, float] = {}

    def on_packet(self, rec: PacketRecord, ctx: Context) -> list[Alert]:
        return []

    def flush(self, ctx: Context) -> list[Alert]:
        """Called once at the end of a capture to close open windows."""
        return []

    def _should_fire(self, key: tuple, ts: float) -> bool:
        last = self._last_fired.get(key)
        if last is not None and ts - last < self.cooldown:
            return False
        self._last_fired[key] = ts
        return True


# --------------------------------------------------------------------------- #
class PortScanDetector(Detector):
    """Many distinct ports on one host (vertical), one port on many hosts
    (horizontal sweep), or ARP requests for many addresses (ARP sweep), from
    a single source inside a sliding window."""

    name = "port_scan"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.window = float(cfg.get("window_s", 60))
        self.vertical = int(cfg.get("vertical_threshold", 15))
        self.horizontal = int(cfg.get("horizontal_threshold", 8))
        self.arp = int(cfg.get("arp_threshold", 12))
        self.probes: dict[str, deque] = defaultdict(deque)  # src -> (ts, dst, port)
        self.arps: dict[str, deque] = defaultdict(deque)  # src -> (ts, target)

    @staticmethod
    def _trim(dq: deque, now: float, window: float) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def on_packet(self, rec, ctx):
        alerts = []
        if rec.protocol == "ARP" and rec.meta.get("arp_op") == "request":
            dq = self.arps[rec.src_ip]
            dq.append((rec.ts, rec.dst_ip))
            self._trim(dq, rec.ts, self.window)
            targets = {t for _, t in dq}
            if len(targets) >= self.arp and self._should_fire((rec.src_ip, "arp"), rec.ts):
                alerts.append(Alert(
                    rec.ts, self.name, "medium", f"ARP sweep from {rec.src_ip}",
                    src=rec.src_ip, mitre="T1018 Remote System Discovery / ICS T0846",
                    details={"targets": len(targets), "window_s": self.window, "mac": rec.src_mac},
                ))
            return alerts

        probe = rec.is_syn or (rec.protocol == "UDP" and not rec.is_response)
        if not probe or not rec.src_ip:
            return alerts
        dq = self.probes[rec.src_ip]
        dq.append((rec.ts, rec.dst_ip, rec.dport))
        self._trim(dq, rec.ts, self.window)

        ports_on_dst = {p for _, d, p in dq if d == rec.dst_ip}
        if len(ports_on_dst) >= self.vertical and self._should_fire((rec.src_ip, rec.dst_ip, "v"), rec.ts):
            alerts.append(Alert(
                rec.ts, self.name, "high", f"Port scan: {rec.src_ip} probed {len(ports_on_dst)} ports on {rec.dst_ip}",
                src=rec.src_ip, dst=rec.dst_ip, mitre="T1046 Network Service Discovery / ICS T0846",
                details={"distinct_ports": len(ports_on_dst), "sample_ports": sorted(ports_on_dst)[:20],
                         "window_s": self.window},
            ))
        hosts_on_port = {d for _, d, p in dq if p == rec.dport}
        if len(hosts_on_port) >= self.horizontal and self._should_fire((rec.src_ip, rec.dport, "h"), rec.ts):
            alerts.append(Alert(
                rec.ts, self.name, "high",
                f"Host sweep: {rec.src_ip} probed port {rec.dport} on {len(hosts_on_port)} hosts",
                src=rec.src_ip, mitre="T1046 Network Service Discovery / ICS T0846",
                details={"port": rec.dport, "distinct_hosts": len(hosts_on_port), "window_s": self.window},
            ))
        return alerts


# --------------------------------------------------------------------------- #
class NewDeviceDetector(Detector):
    """A device appears that is not in the known-device list and was not seen
    during the initial learning period."""

    name = "new_device"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.learning = float(cfg.get("learning_period_s", 60))
        self.known = {k.lower() for k in cfg.get("known_devices", [])}

    def on_packet(self, rec, ctx):
        dev = ctx.new_device
        if dev is None or ctx.first_ts is None:
            return []
        if rec.ts - ctx.first_ts < self.learning:
            return []
        if (dev.mac and dev.mac in self.known) or rec.src_ip in self.known:
            return []
        return [Alert(
            rec.ts, self.name, "medium", f"New device on network: {rec.src_ip} ({dev.vendor})",
            src=rec.src_ip, mitre="T1200 Hardware Additions / ICS T0848 Rogue Master",
            details={"mac": dev.mac, "vendor": dev.vendor, "first_packet": rec.info or rec.protocol},
        )]


# --------------------------------------------------------------------------- #
class TrafficSpikeDetector(Detector):
    """Per-device transmit/receive volume per time bucket, compared with that
    device's own recent history (mean + k * standard deviation)."""

    name = "traffic_spike"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.bucket = float(cfg.get("bucket_s", 10))
        self.history_len = int(cfg.get("history_buckets", 30))
        self.min_history = int(cfg.get("min_history", 6))
        self.k = float(cfg.get("stddev_factor", 4.0))
        self.ratio = float(cfg.get("min_ratio", 5.0))
        self.min_bytes = int(cfg.get("min_bytes", 50_000))
        self.min_packets = int(cfg.get("min_packets", 500))
        # (ip, direction) -> [bucket_index, bytes, packets]
        self.current: dict[tuple, list] = {}
        self.history: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=self.history_len))

    def on_packet(self, rec, ctx):
        alerts = []
        idx = int(rec.ts // self.bucket)
        for ip, direction in ((rec.src_ip, "tx"), (rec.dst_ip, "rx")):
            if not ctx.inventory.is_local(ip):
                continue
            key = (ip, direction)
            cur = self.current.get(key)
            if cur is None:
                self.current[key] = [idx, rec.length, 1]
                continue
            if cur[0] != idx:
                alerts += self._close_bucket(key, cur)
                # Silent buckets are real data points (zero traffic).
                for _ in range(min(idx - cur[0] - 1, self.history_len)):
                    self.history[key].append((0, 0))
                self.current[key] = cur = [idx, 0, 0]
            cur[1] += rec.length
            cur[2] += 1
        return alerts

    def flush(self, ctx):
        alerts = []
        for key, cur in list(self.current.items()):
            alerts += self._close_bucket(key, cur)
        self.current.clear()
        return alerts

    def _close_bucket(self, key: tuple, cur: list) -> list[Alert]:
        idx, nbytes, npkts = cur
        hist = self.history[key]
        if len(hist) < self.min_history:
            hist.append((nbytes, npkts))
            return []
        for value, i, floor, unit in ((nbytes, 0, self.min_bytes, "bytes"),
                                      (npkts, 1, self.min_packets, "packets")):
            series = [h[i] for h in hist]
            mean = sum(series) / len(series)
            std = math.sqrt(sum((x - mean) ** 2 for x in series) / len(series))
            threshold = max(mean + self.k * std, mean * self.ratio, floor)
            if value > threshold:
                # A spike is not added to the history, so it cannot poison the baseline.
                return self._alert(key, idx, value, unit, mean, std, threshold)
        hist.append((nbytes, npkts))
        return []

    def _alert(self, key, idx, value, unit, mean, std, threshold) -> list[Alert]:
        ip, direction = key
        ts = (idx + 1) * self.bucket
        if not self._should_fire(key, ts):
            return []
        verb = "sent" if direction == "tx" else "received"
        return [Alert(
            ts, self.name, "high",
            f"Traffic spike: {ip} {verb} {value:,} {unit} in {self.bucket:g}s (baseline {mean:,.0f})",
            src=ip if direction == "tx" else None,
            dst=ip if direction == "rx" else None,
            mitre="T1498 Network Denial of Service / ICS T0814",
            details={"direction": direction, "unit": unit, "value": value,
                     "baseline_mean": round(mean, 1), "baseline_std": round(std, 1),
                     "threshold": round(threshold, 1), "bucket_s": self.bucket},
        )]


# --------------------------------------------------------------------------- #
class SuspiciousPortDetector(Detector):
    """A session is *established* on a port that has no business on an IoT
    network (Telnet, IRC, ADB, ...), or plaintext MQTT leaves the lab."""

    name = "suspicious_port"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.ports = {int(p): sev for p, sev in cfg.get("ports", {}).items()}
        self.cooldown = float(cfg.get("cooldown_s", 600))

    def on_packet(self, rec, ctx):
        if rec.protocol == "TCP" and rec.is_synack and rec.sport in self.ports:
            server, client, port = rec.src_ip, rec.dst_ip, rec.sport
        elif rec.protocol == "UDP" and not rec.is_response and rec.dport in self.ports:
            server, client, port = rec.dst_ip, rec.src_ip, rec.dport
        elif (rec.protocol == "TCP" and rec.is_syn and rec.dport == 1883
              and ctx.inventory.is_local(rec.src_ip) and not ctx.inventory.is_local(rec.dst_ip)
              and _is_public(rec.dst_ip)):
            if self._should_fire((rec.src_ip, rec.dst_ip, 1883), rec.ts):
                return [Alert(rec.ts, self.name, "medium",
                              f"Unencrypted MQTT from {rec.src_ip} to external host {rec.dst_ip}",
                              src=rec.src_ip, dst=rec.dst_ip, mitre="T1071 Application Layer Protocol",
                              details={"port": 1883, "advice": "use MQTT over TLS (8883)"})]
            return []
        else:
            return []

        if not self._should_fire((client, server, port), rec.ts):
            return []
        service = KNOWN_SERVICES.get(port, str(port))
        return [Alert(
            rec.ts, self.name, self.ports[port],
            f"{service} session {client} -> {server}:{port}",
            src=client, dst=server, mitre="T1021 Remote Services / ICS T0886",
            details={"port": port, "service": service,
                     "exposed_by": server, "local_server": ctx.inventory.is_local(server)},
        )]


def _is_public(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- #
class FailedConnectionDetector(Detector):
    """Repeated failures against the *same* service: TCP connections refused
    (RST) or unanswered, ICMP port unreachable, and MQTT CONNACK refusals
    (wrong credentials). Many failures across many ports is a scan and is
    left to PortScanDetector."""

    name = "failed_connections"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.window = float(cfg.get("window_s", 60))
        self.threshold = int(cfg.get("threshold", 10))
        self.mqtt_threshold = int(cfg.get("mqtt_auth_threshold", 5))
        self.syn_timeout = float(cfg.get("syn_timeout_s", 5))
        self.pending: dict[tuple, float] = {}  # (client, cport, server, sport) -> ts
        self.failures: dict[tuple, deque] = defaultdict(deque)
        self._last_sweep = 0.0

    def on_packet(self, rec, ctx):
        alerts = []
        if rec.ts - self._last_sweep >= 1:
            alerts += self._expire_pending(rec.ts)
            self._last_sweep = rec.ts

        if rec.is_syn:
            self.pending[(rec.src_ip, rec.sport, rec.dst_ip, rec.dport)] = rec.ts
        elif rec.is_synack:
            self.pending.pop((rec.dst_ip, rec.dport, rec.src_ip, rec.sport), None)
        elif rec.is_rst:
            if self.pending.pop((rec.dst_ip, rec.dport, rec.src_ip, rec.sport), None) is not None:
                alerts += self._fail(rec.dst_ip, rec.src_ip, rec.sport, "refused", rec.ts)
        elif rec.protocol == "ICMP" and "unreachable_port" in rec.meta:
            alerts += self._fail(rec.dst_ip, rec.src_ip, rec.meta["unreachable_port"], "port unreachable", rec.ts)

        code = rec.meta.get("mqtt_retcode")
        if code:  # non-zero CONNACK: broker refused the client
            alerts += self._fail(rec.dst_ip, rec.src_ip, rec.sport, "mqtt auth", rec.ts)
        return alerts

    def _expire_pending(self, now: float) -> list[Alert]:
        alerts = []
        for key, ts in list(self.pending.items()):
            if now - ts > self.syn_timeout:
                del self.pending[key]
                client, _, server, port = key
                alerts += self._fail(client, server, port, "no reply", ts)
        return alerts

    def _fail(self, client, server, port, reason, ts) -> list[Alert]:
        mqtt = reason == "mqtt auth"
        key = (client, server, port, mqtt)
        dq = self.failures[key]
        dq.append((ts, reason))
        while dq and ts - dq[0][0] > self.window:
            dq.popleft()
        limit = self.mqtt_threshold if mqtt else self.threshold
        if len(dq) < limit or not self._should_fire(key, ts):
            return []
        if mqtt:
            return [Alert(ts, self.name, "high",
                          f"MQTT authentication failures: {client} refused {len(dq)}x by broker {server}",
                          src=client, dst=server, mitre="T1110 Brute Force / ICS T0812 Default Credentials",
                          details={"failures": len(dq), "window_s": self.window, "port": port})]
        reasons = sorted({r for _, r in dq})
        return [Alert(ts, self.name, "medium",
                      f"Repeated failed connections: {client} -> {server}:{port} ({len(dq)}x)",
                      src=client, dst=server, mitre="T1110 Brute Force",
                      details={"failures": len(dq), "reasons": reasons, "window_s": self.window, "port": port})]


DETECTORS = {
    cls.name: cls
    for cls in (PortScanDetector, NewDeviceDetector, TrafficSpikeDetector,
                SuspiciousPortDetector, FailedConnectionDetector)
}


class DetectionEngine:
    def __init__(self, config: dict, inventory: Inventory):
        self.ctx = Context(inventory)
        self.detectors: list[Detector] = []
        for name, cls in DETECTORS.items():
            cfg = config.get(name, {})
            if cfg.get("enabled", True):
                self.detectors.append(cls(cfg))

    def process(self, rec: PacketRecord, new_device: Device | None) -> list[Alert]:
        if self.ctx.first_ts is None:
            self.ctx.first_ts = rec.ts
        self.ctx.new_device = new_device
        alerts = []
        for det in self.detectors:
            alerts += det.on_packet(rec, self.ctx)
        return alerts

    def flush(self) -> list[Alert]:
        alerts = []
        for det in self.detectors:
            alerts += det.flush(self.ctx)
        return alerts
