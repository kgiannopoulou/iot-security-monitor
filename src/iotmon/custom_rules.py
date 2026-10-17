"""Custom detection rules, written in YAML instead of Python.

The built-in rules (DET-001..015) are detectors with state and learned
baselines. Most site-specific rules are simpler: "Telnet from anything in
the IoT VLAN", "any traffic from the camera to the PLC network", "more than
5 DNS lookups of *.ru from one device in a minute". A custom rule file
(--custom-rules FILE, or `custom_rules:` in a site config) declares them:

    custom_rules:
      - id: CUS-001
        name: Telnet attempt from an IoT device
        severity: high
        confidence: 0.85
        attack: ["T1021 Remote Services"]
        match:                       # every condition must hold (AND)
          protocol: TCP
          dst_port: [23, 2323]       # a list means any of these (OR)
          src_net: 192.168.1.0/24
          new_connection: true       # SYN / first packet of a flow only
        threshold:                   # optional: N matches per window
          count: 3
          window_s: 60
          group_by: src

Files are validated against rules/schema/rules.schema.json before anything
runs, so a typo is an error with its path ("custom_rules[2].match.dst_prot:
additional property"), not a rule that silently never fires.
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Alert, register_extra_rule

if TYPE_CHECKING:
    from .detections import Context
    from .models import PacketRecord

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "rules" / "schema" / "rules.schema.json"


class RuleFileError(ValueError):
    """A rule file that doesn't match the schema; .errors lists every problem."""

    def __init__(self, source: str, errors: list[str]):
        self.errors = errors
        super().__init__(f"{source}: {len(errors)} problem{'s' if len(errors) != 1 else ''}\n  "
                         + "\n  ".join(errors))


def _schema() -> dict:
    path = SCHEMA_PATH
    if not path.exists():  # installed elsewhere: IOTMON_HOME layout
        from .config import HOME

        path = HOME / "rules" / "schema" / "rules.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate(document: dict, source: str = "rule file") -> None:
    """Raise RuleFileError listing every schema violation (with its path)."""
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(_schema())
    errors = []
    for err in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        path = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path).lstrip(".")
        errors.append(f"{path or '(top level)'}: {err.message}")
    rules = document.get("custom_rules") or [] if isinstance(document, dict) else []
    seen: set[str] = set()
    for i, r in enumerate(rules):
        if isinstance(r, dict) and r.get("id") in seen:
            errors.append(f"custom_rules[{i}].id: duplicate rule id {r['id']}")
        if isinstance(r, dict):
            seen.add(r.get("id"))
            for key in ("src_net", "dst_net", "not_src_net", "not_dst_net"):
                for net in _as_list((r.get("match") or {}).get(key)):
                    try:
                        ipaddress.ip_network(str(net), strict=False)
                    except ValueError:
                        errors.append(f"custom_rules[{i}].match.{key}: {net!r} is not an IP address or network")
    if errors:
        raise RuleFileError(source, errors)


def load(path: str | Path) -> list[dict]:
    """Read and validate a custom rule file; returns its rules."""
    from .config import _read

    document = _read(path) or {}
    validate(document, str(path))
    return document.get("custom_rules") or []


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class Matcher:
    """The `match:` block, compiled once."""

    def __init__(self, match: dict):
        self.protocol = {str(p).upper() for p in _as_list(match.get("protocol"))}
        self.app = {str(a).upper() for a in _as_list(match.get("app"))}
        self.dst_port = set(_as_list(match.get("dst_port")))
        self.not_dst_port = set(_as_list(match.get("not_dst_port")))
        nets = lambda key: [ipaddress.ip_network(str(n), strict=False) for n in _as_list(match.get(key))]  # noqa: E731
        self.src_net, self.dst_net = nets("src_net"), nets("dst_net")
        self.not_src_net, self.not_dst_net = nets("not_src_net"), nets("not_dst_net")
        self.src_zone = {str(z).upper() for z in _as_list(match.get("src_zone"))}
        self.dst_zone = {str(z).upper() for z in _as_list(match.get("dst_zone"))}
        self.direction = match.get("direction")
        self.new_connection = match.get("new_connection")
        self.info = (match.get("info_contains") or "").lower()
        self.min_length = match.get("min_length")

    @staticmethod
    def _in(ip: str | None, nets) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in nets)

    def __call__(self, rec: PacketRecord, ctx: Context) -> bool:
        if self.protocol and rec.protocol.upper() not in self.protocol:
            return False
        if self.app and (rec.app or "").upper() not in self.app:
            return False
        if self.dst_port and rec.dport not in self.dst_port:
            return False
        if self.not_dst_port and rec.dport in self.not_dst_port:
            return False
        if self.src_net and not self._in(rec.src_ip, self.src_net):
            return False
        if self.dst_net and not self._in(rec.dst_ip, self.dst_net):
            return False
        if self.not_src_net and self._in(rec.src_ip, self.not_src_net):
            return False
        if self.not_dst_net and self._in(rec.dst_ip, self.not_dst_net):
            return False
        if self.src_zone and (ctx.policy.zone_of(rec.src_ip) or "").upper() not in self.src_zone:
            return False
        if self.dst_zone and (ctx.policy.zone_of(rec.dst_ip) or "").upper() not in self.dst_zone:
            return False
        if self.direction:
            inv = ctx.inventory
            src_local, dst_local = inv.is_local(rec.src_ip), inv.is_local(rec.dst_ip)
            if self.direction == "internal" and not (src_local and dst_local):
                return False
            if self.direction == "outbound" and not (src_local and inv.is_external(rec.dst_ip)):
                return False
            if self.direction == "inbound" and not (inv.is_external(rec.src_ip) and dst_local):
                return False
        if self.new_connection is not None and bool(ctx.attempt) != self.new_connection:
            return False
        if self.info and self.info not in (rec.info or "").lower():
            return False
        if self.min_length is not None and rec.length < self.min_length:
            return False
        return True


class CustomRuleDetector:
    """One custom rule. Same interface as detections.Detector."""

    def __init__(self, rule: dict):
        self.rule = rule
        self.id = rule["id"]
        self.name = f"custom:{self.id}"
        self.match = Matcher(rule["match"])
        self.threshold = rule.get("threshold")
        self.cooldown = float(rule.get("cooldown_s", 300))
        self._last_fired: dict[tuple, float] = {}
        self._windows: dict[tuple, deque] = defaultdict(deque)
        register_extra_rule(self.name, rule)

    def _group(self, rec) -> tuple:
        by = (self.threshold or {}).get("group_by", "src")
        return {"src": (rec.src_ip,), "dst": (rec.dst_ip,), "src_dst": (rec.src_ip, rec.dst_ip)}[by]

    def on_packet(self, rec: PacketRecord, ctx: Context) -> list[Alert]:
        if not self.match(rec, ctx):
            return []
        key = self._group(rec)
        details = {"custom_rule": self.id, "protocol": rec.protocol, "dst_port": rec.dport, "app": rec.app}
        if self.threshold:
            window = float(self.threshold["window_s"])
            dq = self._windows[key]
            field = self.threshold.get("distinct")
            value = {"dst": rec.dst_ip, "dst_port": rec.dport, "src": rec.src_ip, "info": rec.info}.get(field, 1)
            dq.append((rec.ts, value))
            while dq and rec.ts - dq[0][0] > window:
                dq.popleft()
            observed = len({v for _, v in dq}) if field else len(dq)
            if observed < self.threshold["count"]:
                return []
            details.update({"count": observed, "threshold": self.threshold["count"], "window_s": window})
            if field:
                details["distinct"] = field
        last = self._last_fired.get(key)
        if last is not None and rec.ts - last < self.cooldown:
            return []
        self._last_fired[key] = rec.ts
        what = f"{rec.src_ip or rec.src_mac} -> {rec.dst_ip or rec.dst_mac}" + (f":{rec.dport}" if rec.dport else "")
        title = f"{self.rule['name']}: {what}"
        if self.threshold:
            title += f" ({details['count']} in {details['window_s']:g}s)"
        return [Alert(rec.ts, self.name, self.rule["severity"], title, src=rec.src_ip, dst=rec.dst_ip,
                      mitre=", ".join(self.rule.get("attack", [])), details=details)]

    def flush(self, ctx: Context) -> list[Alert]:
        return []
