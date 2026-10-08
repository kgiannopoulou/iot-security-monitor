"""Detection engine.

Every detector is a small state machine fed one PacketRecord at a time.
Time windows use the *packet* timestamp, never the wall clock, so replaying
a pcap gives exactly the same alerts as watching the traffic live.

    DET-001  new_device           New/unrecognized device
    DET-002  port_scan            Port scanning behaviour
    DET-003  connection_rate      Abnormal connection rate
    DET-004  suspicious_port      Communication with unusual ports
    DET-005  external_connection  Unexpected external connection
    DET-006  traffic_spike        Traffic volume spike
    DET-007  failed_connections   Repeated failed connections
    DET-008  device_change        Device address change (IP conflict / change)
    DET-009  mqtt_activity        Abnormal MQTT activity (new client, burst, topic, subscription)
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict, deque
from typing import TYPE_CHECKING

from .baseline import Baseline
from .models import KNOWN_SERVICES, Alert, PacketRecord
from .mqtt import MqttTracker, wildcard_scope

if TYPE_CHECKING:
    from .assets import AssetRegister
    from .flows import Flow
    from .inventory import Device, Inventory


class Context:
    """What the pipeline knows when a detector sees a packet."""

    def __init__(self, inventory: Inventory, assets: AssetRegister | None = None,
                 baseline: Baseline | None = None):
        self.inventory = inventory
        self.assets = assets  # persistent asset register, when one was loaded
        self.baseline = baseline if baseline is not None else Baseline()
        self.learning = False  # still inside the baseline learning period
        self.new_device: Device | None = None
        self.new_flow: Flow | None = None  # conversation opened by this packet
        self.attempt = False  # this packet is a client opening a connection (TCP SYN / new UDP flow)
        self.first_ts: float | None = None
        self.fired: dict[tuple[str, str | None], float] = {}  # (rule, src) -> last alert time
        self.mqtt = MqttTracker()  # broker-level view; .events holds this packet's MQTT events

    def recently_fired(self, rule: str, src: str | None, within: float, now: float) -> bool:
        ts = self.fired.get((rule, src))
        return ts is not None and now - ts <= within


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
                    details={"addresses_observed": len(targets), "window_s": self.window, "threshold": self.arp,
                             "mac": rec.src_mac},
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
                details={"ports_observed": len(ports_on_dst), "sample_ports": sorted(ports_on_dst)[:20],
                         "window_s": self.window, "threshold": self.vertical},
            ))
        hosts_on_port = {d for _, d, p in dq if p == rec.dport}
        if len(hosts_on_port) >= self.horizontal and self._should_fire((rec.src_ip, rec.dport, "h"), rec.ts):
            alerts.append(Alert(
                rec.ts, self.name, "high",
                f"Host sweep: {rec.src_ip} probed port {rec.dport} on {len(hosts_on_port)} hosts",
                src=rec.src_ip, mitre="T1046 Network Service Discovery / ICS T0846",
                details={"port": rec.dport, "hosts_observed": len(hosts_on_port), "window_s": self.window,
                         "threshold": self.horizontal},
            ))
        return alerts


# --------------------------------------------------------------------------- #
class NewDeviceDetector(Detector):
    """A device appears that is not in the asset register / known-device list.

    With an asset register loaded, anything not in it is new, from the first
    packet. Without one, devices seen during the initial learning period form
    the baseline."""

    name = "new_device"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.learning = float(cfg.get("learning_period_s", 60))
        self.known = {k.lower() for k in cfg.get("known_devices", [])}

    def on_packet(self, rec, ctx):
        dev = ctx.new_device
        if dev is None or ctx.first_ts is None:
            return []
        if ctx.assets is not None:
            if dev.key in ctx.assets:
                return []
        elif rec.ts - ctx.first_ts < self.learning:
            return []
        if (dev.mac and dev.mac in self.known) or rec.src_ip in self.known:
            return []
        return [Alert(
            rec.ts, self.name, "medium", f"New IoT device detected: {rec.src_ip} ({dev.vendor})",
            src=rec.src_ip, mitre="T1200 Hardware Additions / ICS T0848 Rogue Master",
            details={"ip": rec.src_ip, "mac": dev.mac, "vendor": dev.vendor,
                     "first_packet": rec.info or rec.protocol},
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
class ConnectionRateDetector(Detector):
    """DET-003: a device opens far more connections per window than it did
    during the baseline. Counts connection *attempts* (TCP SYN, new UDP
    conversation) per source in a sliding window and compares the count with
    the device's own learned peak:

        alert when  count >= max(min_connections, peak_factor * learned peak)

    Many attempts spread over many ports or hosts is a scan: once DET-002 has
    flagged a source, its connection rate is already explained and stays quiet.
    """

    name = "connection_rate"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.window = float(cfg.get("window_s", 60))
        self.floor = int(cfg.get("min_connections", 20))
        self.factor = float(cfg.get("peak_factor", 5.0))
        self.scan_quiet = float(cfg.get("scan_suppress_s", 300))
        self.recent: dict[str, deque] = defaultdict(deque)  # src -> (ts, dst, port)

    def on_packet(self, rec, ctx):
        if not ctx.attempt or not ctx.inventory.is_local(rec.src_ip):
            return []
        dq = self.recent[rec.src_ip]
        dq.append((rec.ts, rec.dst_ip, rec.dport))
        while dq and rec.ts - dq[0][0] > self.window:
            dq.popleft()
        count = len(dq)
        prof = None if ctx.learning else ctx.baseline.get(rec.src_ip)
        peak = prof.peak_connections if prof else 0
        threshold = max(self.floor, math.ceil(self.factor * peak))
        # A trusted capture (`baseline learn`) is learned whatever the rate.
        if ctx.learning and (count < threshold or ctx.baseline.learn_all):
            ctx.baseline.observe_rate(rec.src_ip, count)
            return []
        if count < threshold:
            return []
        # Above the floor during a learning period: anomalous, and never learned.
        if ctx.recently_fired("port_scan", rec.src_ip, self.scan_quiet, rec.ts):
            return []
        if not self._should_fire((rec.src_ip,), rec.ts):
            return []
        targets = Counter(f"{d}:{p}" for _, d, p in dq)
        return [Alert(
            rec.ts, self.name, "medium",
            f"Abnormal connection rate: {rec.src_ip} opened {count} connections in {self.window:g}s "
            f"(baseline peak {peak})",
            src=rec.src_ip, dst=targets.most_common(1)[0][0].rsplit(":", 1)[0],
            mitre="T1499 Endpoint Denial of Service / ICS T0814 Denial of Service",
            details={"connections": count, "window_s": self.window, "baseline_peak": peak,
                     "threshold": threshold, "distinct_targets": len(targets),
                     "top_targets": [f"{t} x{n}" for t, n in targets.most_common(5)],
                     "has_baseline": prof is not None},
        )]


# --------------------------------------------------------------------------- #
class SuspiciousPortDetector(Detector):
    """DET-004: a session is *established* (TCP handshake completed, or a UDP
    service replied) on a port that is unusual, for one of two reasons:

    * the port is outside the device's learned profile: a client that never
      used it, or a server that never answered on it (medium), or
    * the port is on a short list of services with no business on an IoT
      network: Telnet, IRC, ADB, ... (severity per port, baseline or not).

    Attempts that never complete (closed ports, half-open scans) are left to
    DET-002 and DET-007. Plaintext MQTT to a public address is also flagged.
    """

    name = "suspicious_port"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.ports = {int(p): sev for p, sev in cfg.get("ports", {}).items()}
        self.cooldown = float(cfg.get("cooldown_s", 600))
        self.unusual_severity = cfg.get("unusual_severity", "medium")
        self.handshakes: dict[tuple, float] = {}  # (client, cport, server, sport) -> SYN-ACK time

    def on_packet(self, rec, ctx):
        if rec.protocol == "TCP":
            if (rec.is_syn and rec.dport == 1883 and ctx.inventory.is_local(rec.src_ip)
                    and not ctx.inventory.is_local(rec.dst_ip) and _is_public(rec.dst_ip)):
                return self._plain_mqtt(rec)
            if rec.is_synack:
                self.handshakes[(rec.dst_ip, rec.dport, rec.src_ip, rec.sport)] = rec.ts
                if len(self.handshakes) > 10_000:
                    self.handshakes = {k: t for k, t in self.handshakes.items() if rec.ts - t < 60}
                return []
            key = (rec.src_ip, rec.sport, rec.dst_ip, rec.dport)
            if key not in self.handshakes:
                return []
            del self.handshakes[key]
            if rec.is_rst or "A" not in rec.tcp_flags:
                return []  # half-open: the client reset instead of completing the handshake
            client, server, port = rec.src_ip, rec.dst_ip, rec.dport
        elif rec.protocol == "UDP" and rec.is_response:
            client, server, port = rec.dst_ip, rec.src_ip, rec.sport
        else:
            return []
        return self._session(rec, ctx, client, server, port)

    def _session(self, rec, ctx, client, server, port) -> list[Alert]:
        severity = self.ports.get(port)
        reasons = ["high-risk service"] if severity else []
        details = {}
        if not ctx.learning:
            cprof = ctx.baseline.get(client) if ctx.inventory.is_local(client) else None
            sprof = ctx.baseline.get(server) if ctx.inventory.is_local(server) else None
            if cprof is not None and port not in cprof.client_ports:
                reasons.append(f"{client} never connected to port {port} during the baseline")
                details["client_usual_ports"] = sorted(cprof.client_ports)
            if sprof is not None and port not in sprof.server_ports:
                reasons.append(f"{server} never answered on port {port} during the baseline")
                details["server_usual_ports"] = sorted(sprof.server_ports)
        if not reasons:
            return []
        if not self._should_fire((client, server, port), rec.ts):
            return []
        service = KNOWN_SERVICES.get(port, str(port))
        if severity:
            title = f"{service} session {client} -> {server}:{port}"
        else:
            severity = self.unusual_severity
            title = f"Unusual port: {client} -> {server}:{port} ({service}), outside the baseline"
        return [Alert(
            rec.ts, self.name, severity, title,
            src=client, dst=server, mitre="T1021 Remote Services / ICS T0886",
            details={"port": port, "service": service, "protocol": rec.protocol, "reasons": reasons,
                     **details, "exposed_by": server, "local_server": ctx.inventory.is_local(server)},
        )]

    def _plain_mqtt(self, rec) -> list[Alert]:
        if not self._should_fire((rec.src_ip, rec.dst_ip, 1883), rec.ts):
            return []
        return [Alert(rec.ts, self.name, "medium",
                      f"Unencrypted MQTT from {rec.src_ip} to external host {rec.dst_ip}",
                      src=rec.src_ip, dst=rec.dst_ip, mitre="T1071 Application Layer Protocol",
                      details={"port": 1883, "reasons": ["plaintext MQTT leaving the site"],
                               "advice": "use MQTT over TLS (8883)"})]


# --------------------------------------------------------------------------- #
class ExternalConnectionDetector(Detector):
    """DET-005: a lab device opens a connection to an internet host that is not
    among the external peers it talked to during the baseline.

    Severity is raised to high when the device never talked to the internet
    at all during the baseline (a sensor that only speaks to the local
    broker), or when the address was not obtained from a DNS answer in the
    last dns_window_s (malware often connects straight to an IP). Contacting
    fanout_threshold or more unexpected hosts within fanout_window_s raises one
    high "fan-out" alert; until then at most host_alerts hosts per device and
    window are reported one by one, so a spreading device cannot flood the
    alert queue.
    """

    name = "external_connection"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.dns_window = float(cfg.get("dns_window_s", 600))
        self.fanout_window = float(cfg.get("fanout_window_s", 300))
        self.fanout = int(cfg.get("fanout_threshold", 10))
        self.host_alerts = int(cfg.get("host_alerts", 3))
        self.reported: dict[str, deque] = defaultdict(deque)  # client -> times of per-host alerts
        self.resolved: dict[tuple[str, str], tuple[float, str]] = {}  # (client, ip) -> (ts, name)
        self.unexpected: dict[str, dict[str, float]] = defaultdict(dict)  # client -> {ip: last seen}

    def on_packet(self, rec, ctx):
        answers = rec.meta.get("dns_answers")
        if answers and rec.dst_ip:
            for ip in answers:
                self.resolved[(rec.dst_ip, ip)] = (rec.ts, rec.meta.get("dns_name", ""))
            if len(self.resolved) > 50_000:
                self.resolved = {k: v for k, v in self.resolved.items() if rec.ts - v[0] <= self.dns_window}
            return []
        if not ctx.attempt or ctx.learning:
            return []
        client, server = rec.src_ip, rec.dst_ip
        if not ctx.inventory.is_local(client) or not ctx.inventory.is_external(server):
            return []
        prof = ctx.baseline.get(client)
        if prof is not None and server in prof.external_peers:
            return []

        seen = self.unexpected[client]
        seen[server] = rec.ts
        for ip, ts in list(seen.items()):
            if rec.ts - ts > self.fanout_window:
                del seen[ip]
        if len(seen) >= self.fanout and self._should_fire((client, "fanout"), rec.ts):
            return [Alert(
                rec.ts, self.name, "high",
                f"External fan-out: {client} contacted {len(seen)} unexpected internet hosts "
                f"in {self.fanout_window:g}s",
                src=client, mitre="T1071 Application Layer Protocol",
                details={"destinations_observed": len(seen), "window_s": self.fanout_window,
                         "threshold": self.fanout, "sample_destinations": sorted(seen)[:20]},
            )]
        if rec.ts - self._last_fired.get((client, "fanout"), -math.inf) < self.cooldown:
            return []  # already reported as fan-out
        reported = self.reported[client]
        while reported and rec.ts - reported[0] > self.fanout_window:
            reported.popleft()
        if len(reported) >= self.host_alerts or not self._should_fire((client, server), rec.ts):
            return []
        reported.append(rec.ts)

        hit = self.resolved.get((client, server))
        name = hit[1] if hit and rec.ts - hit[0] <= self.dns_window else None
        local_only = prof is not None and not prof.external_peers
        if prof is None:
            reasons = ["device has no baseline"]
        elif local_only:
            reasons = ["device never talked to the internet during the baseline"]
        else:
            reasons = ["destination is not one of the device's usual external peers"]
        if name is None:
            reasons.append("no DNS lookup for this address (direct-to-IP connection)")
        return [Alert(
            rec.ts, self.name, "high" if local_only or name is None else "medium",
            f"Unexpected external connection: {client} -> {server}:{rec.dport}" + (f" ({name})" if name else ""),
            src=client, dst=server, mitre="T1071 Application Layer Protocol / ICS T0869",
            details={"port": rec.dport, "protocol": rec.protocol, "dns_name": name, "reasons": reasons,
                     "usual_external_peers": sorted(prof.external_peers) if prof else [],
                     "unexpected_destinations_in_window": len(seen), "window_s": self.fanout_window},
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


# --------------------------------------------------------------------------- #
class DeviceChangeDetector(Detector):
    """Changes to a known device's addressing.

    ip_conflict  an IP already bound to one MAC is claimed by another MAC:
                 ARP spoofing / man-in-the-middle, or an address clash.
    ip_change    a known MAC shows up on a different IP than before (within
                 this run, or compared with the asset register): DHCP churn,
                 re-addressing, or a device being moved to impersonate another.
    """

    name = "device_change"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.ip_change_severity = cfg.get("ip_change_severity", "low")
        self.learning = float(cfg.get("learning_period_s", 0))
        self._checked: set[str] = set()  # register comparison done once per device

    def on_packet(self, rec, ctx):
        alerts = []
        if ctx.first_ts is not None and rec.ts - ctx.first_ts < self.learning:
            return alerts
        for kind, dev, ip, other in ctx.inventory.changes:
            if kind == "ip_conflict" and self._should_fire(("conflict", ip), rec.ts):
                alerts.append(Alert(
                    rec.ts, self.name, "high",
                    f"IP conflict: {ip} claimed by {dev.mac}, already used by {other.mac}",
                    src=ip, mitre="T1557.002 ARP Cache Poisoning / ICS T0830 Adversary-in-the-Middle",
                    details={"ip": ip, "mac": dev.mac, "vendor": dev.vendor,
                             "previous_mac": other.mac, "previous_vendor": other.vendor,
                             "packet": rec.info or rec.protocol},
                ))
            elif kind == "ip_change" and self._should_fire(("change", dev.key, ip), rec.ts):
                alerts.append(self._ip_change(rec, dev, ip, other))

        dev = ctx.inventory.lookup(rec.src_ip)
        if ctx.assets is not None and dev is not None and dev.key not in self._checked:
            self._checked.add(dev.key)
            asset = ctx.assets.get(dev.key)
            if asset and asset["ip"] and rec.src_ip not in asset["ips"]:
                alerts.append(self._ip_change(rec, dev, rec.src_ip, asset["ips"], source="asset register"))
        return alerts

    def _ip_change(self, rec, dev, ip, previous, source="this capture"):
        return Alert(
            rec.ts, self.name, self.ip_change_severity,
            f"Device changed IP: {dev.mac or dev.key} now {ip} (was {', '.join(previous)})",
            src=ip, mitre="T1036 Masquerading",
            details={"ip": ip, "mac": dev.mac, "vendor": dev.vendor, "name": dev.name,
                     "previous_ips": list(previous), "compared_with": source},
        )


# Order matters where one rule defers to another: port_scan runs before
# connection_rate, which stays quiet for sources already flagged as scanning.
# --------------------------------------------------------------------------- #
class MqttActivityDetector(Detector):
    """DET-009: MQTT behaviour that differs from the baseline, seen at the
    protocol level rather than as TCP connections:

    new client     a host connects to the broker that never used MQTT during
                   the baseline, or with a client ID it never used
    message burst  publishes per window >= max(min_messages, peak_factor x
                   the client's learned peak) on its existing session
    topic          a client publishes to a topic it never used (medium), or
                   to a topic only *other* devices published (high: spoofed
                   telemetry or commands)
    subscription   a subscription the client never made; a wildcard that
                   matches every topic ("#") or broker internals ($SYS) is
                   medium, other new subscriptions low
    """

    name = "mqtt_activity"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.cooldown = float(cfg.get("cooldown_s", 600))
        self.window = float(cfg.get("window_s", 60))
        self.floor = int(cfg.get("min_messages", 30))
        self.factor = float(cfg.get("peak_factor", 5.0))
        self.topic_alerts = int(cfg.get("topic_alerts", 3))
        self.recent: dict[str, deque] = defaultdict(deque)  # ip -> (ts, topic) of publishes
        self.reported: dict[str, deque] = defaultdict(deque)  # ip -> times of topic alerts

    def on_packet(self, rec, ctx):
        alerts = []
        for ev in ctx.mqtt.events:
            if ev.kind == "publish":
                alerts += self._rate(rec, ev, ctx)
                if not ctx.learning:
                    alerts += self._topic(rec, ev, ctx)
            elif ctx.learning:
                continue
            elif ev.kind == "connect":
                alerts += self._connect(rec, ev, ctx)
            elif ev.kind == "subscribe":
                alerts += self._subscribe(rec, ev, ctx)
        return alerts

    def _alert(self, rec, ev, severity, title, mitre, **details) -> Alert:
        return Alert(rec.ts, self.name, severity, title, src=ev.ip, dst=ev.broker, mitre=mitre,
                     details={"client": ev.client, **details})

    def _connect(self, rec, ev, ctx):
        prof = ctx.baseline.get(ev.ip)
        used_mqtt = prof is not None and bool(prof.mqtt_client_ids or prof.mqtt_publish or prof.mqtt_subscribe)
        if not used_mqtt:
            reason = "host never used MQTT during the baseline"
        elif prof.mqtt_client_ids and ev.client not in prof.mqtt_client_ids:
            reason = f"client ID never used by this host (usual: {', '.join(sorted(prof.mqtt_client_ids))})"
        else:
            return []
        if not self._should_fire((ev.ip, "connect"), rec.ts):
            return []
        return [self._alert(rec, ev, "medium",
                            f"New MQTT client: {ev.ip} connected to broker {ev.broker} as '{ev.client}'",
                            "T0886 Remote Services / T0883 Internet Accessible Device (ICS)",
                            reasons=[reason], username=rec.meta.get("mqtt_username", ""),
                            usual_client_ids=sorted(prof.mqtt_client_ids) if prof else [])]

    def _rate(self, rec, ev, ctx):
        dq = self.recent[ev.ip]
        dq.append((rec.ts, ev.topic))
        while dq and rec.ts - dq[0][0] > self.window:
            dq.popleft()
        count = len(dq)
        prof = None if ctx.learning else ctx.baseline.get(ev.ip)
        peak = prof.peak_mqtt_messages if prof else 0
        threshold = max(self.floor, math.ceil(self.factor * peak))
        # Unlike connection attempts (DET-003), a high steady message rate is a
        # normal property of a telemetry device, so the learning period learns
        # whatever rate it sees and never alerts. Found live: the motor drive
        # publishes 60 messages a minute, above the floor.
        if ctx.learning:
            ctx.baseline.observe_mqtt_rate(ev.ip, count)
            return []
        if count < threshold or not self._should_fire((ev.ip, "rate"), rec.ts):
            return []
        topics = Counter(t for _, t in dq)
        return [self._alert(rec, ev, "medium",
                            f"MQTT message burst: {ev.ip} published {count} messages in {self.window:g}s "
                            f"(baseline peak {peak})",
                            "T0806 Brute Force I/O / T0814 Denial of Service (ICS)",
                            messages=count, window_s=self.window, baseline_peak=peak, threshold=threshold,
                            top_topics=[f"{t} x{n}" for t, n in topics.most_common(5)])]

    def _topic(self, rec, ev, ctx):
        prof = ctx.baseline.get(ev.ip)
        if prof is not None and ev.topic in prof.mqtt_publish:
            return []
        owners = ctx.baseline.topic_owners(ev.topic) - {ev.ip}
        reported = self.reported[ev.ip]
        while reported and rec.ts - reported[0] > self.cooldown:
            reported.popleft()
        if len(reported) >= self.topic_alerts or not self._should_fire((ev.ip, "topic", ev.topic), rec.ts):
            return []
        reported.append(rec.ts)
        if owners:
            return [self._alert(rec, ev, "high",
                                f"MQTT topic spoofing: {ev.ip} published to '{ev.topic}', "
                                f"normally published only by {', '.join(sorted(owners))}",
                                "T0856 Spoof Reporting Message / T0855 Unauthorized Command Message (ICS)",
                                topic=ev.topic, value=ev.value, usual_publishers=sorted(owners),
                                usual_topics=sorted(prof.mqtt_publish) if prof else [])]
        return [self._alert(rec, ev, "medium",
                            f"New MQTT topic: {ev.ip} published to '{ev.topic}', outside the baseline",
                            "T0855 Unauthorized Command Message (ICS)",
                            topic=ev.topic, value=ev.value, usual_topics=sorted(prof.mqtt_publish) if prof else [])]

    def _subscribe(self, rec, ev, ctx):
        prof = ctx.baseline.get(ev.ip)
        if prof is not None and ev.topic in prof.mqtt_subscribe:
            return []
        scope = wildcard_scope(ev.topic)
        if not self._should_fire((ev.ip, "sub", ev.topic), rec.ts):
            return []
        if scope in ("all", "broker"):
            what = "every topic" if scope == "all" else "broker internals"
            return [self._alert(rec, ev, "medium",
                                f"Broad MQTT subscription: {ev.ip} subscribed to '{ev.topic}' ({what})",
                                "T0801 Monitor Process State / T0861 Point & Tag Identification (ICS)",
                                topic=ev.topic, scope=scope,
                                usual_subscriptions=sorted(prof.mqtt_subscribe) if prof else [])]
        return [self._alert(rec, ev, "low",
                            f"New MQTT subscription: {ev.ip} subscribed to '{ev.topic}'",
                            "T0801 Monitor Process State (ICS)",
                            topic=ev.topic, scope=scope or "single topic",
                            usual_subscriptions=sorted(prof.mqtt_subscribe) if prof else [])]


DETECTORS = {
    cls.name: cls
    for cls in (NewDeviceDetector, PortScanDetector, ConnectionRateDetector, SuspiciousPortDetector,
                ExternalConnectionDetector, TrafficSpikeDetector, FailedConnectionDetector,
                DeviceChangeDetector, MqttActivityDetector)
}


class DetectionEngine:
    def __init__(self, config: dict, inventory: Inventory, assets: AssetRegister | None = None,
                 baseline: Baseline | None = None):
        self.ctx = Context(inventory, assets, baseline)
        self.detectors: list[Detector] = []
        for name, cls in DETECTORS.items():
            cfg = config.get(name, {})
            if cfg.get("enabled", True):
                self.detectors.append(cls(cfg))

    def process(self, rec: PacketRecord, new_device: Device | None, new_flow: Flow | None = None) -> list[Alert]:
        ctx = self.ctx
        if ctx.first_ts is None:
            ctx.first_ts = rec.ts
        ctx.learning = ctx.baseline.is_learning(rec.ts - ctx.first_ts)
        ctx.new_device = new_device
        ctx.new_flow = new_flow
        ctx.attempt = (new_flow is not None and new_flow.client_ip == rec.src_ip
                       and (rec.is_syn or rec.protocol == "UDP"))
        if ctx.learning and new_flow is not None:
            inv = ctx.inventory
            ctx.baseline.observe_session(new_flow.client_ip, new_flow.server_ip, new_flow.server_port,
                                         inv.is_local(new_flow.client_ip), inv.is_local(new_flow.server_ip),
                                         inv.is_external(new_flow.server_ip))
        for ev in ctx.mqtt.update(rec):
            if ctx.learning and ev.kind in ("connect", "publish", "subscribe"):
                client_id = "" if ev.client.endswith(")") else ev.client
                ctx.baseline.observe_mqtt(ev.kind, ev.ip, client_id, ev.topic)
        alerts = []
        for det in self.detectors:
            found = det.on_packet(rec, ctx)
            for a in found:
                ctx.fired[(a.rule, a.src)] = a.ts
            alerts += found
        return alerts

    def flush(self) -> list[Alert]:
        alerts = []
        for det in self.detectors:
            alerts += det.flush(self.ctx)
        return alerts
