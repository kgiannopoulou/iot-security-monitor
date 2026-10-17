"""SIEM integration: alerts as Elastic Common Schema (ECS) JSON or ArcSight
CEF, and a syslog forwarder (RFC 5424 over UDP or TCP).

Three ways to get alerts into a SIEM, from least to most moving parts:

    1. ship data/alerts.jsonl with a log shipper (Filebeat, Wazuh agent,
       Splunk UF): one JSON object per alert, written as it fires
    2. export:   iotmon alerts export --format ecs|cef -o alerts.ndjson
    3. forward:  iotmon live -i eth0 --syslog siem.example:514 --syslog-format cef

Example shipper / SIEM configurations are in examples/siem/ and the
walk-through in docs/siem-integration.md.
"""

from __future__ import annotations

import json
import re
import socket
from datetime import datetime, timezone

from . import __version__
from .confidence import label as confidence_label
from .models import Alert, rule_meta

# Severity on each scale. ECS event.severity is numeric (higher = worse);
# CEF uses 0-10; syslog severities count down from 0 = emergency.
SEVERITY_NUM = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
LOCAL4 = 20  # syslog facility for security tools that don't have their own

TECHNIQUE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b\s*([^,/;]*)")


def alert_row(alert: Alert, alert_id: int | None = None) -> dict:
    """A live Alert in the same shape as a stored alert row (state.query_alerts)."""
    return {"id": alert_id, "ts": alert.ts, "rule": alert.rule, "rule_id": alert.rule_id,
            "severity": alert.severity, "title": alert.title, "src": alert.src, "dst": alert.dst,
            "mitre": alert.mitre, "details": alert.details, "confidence": alert.confidence, "status": "open"}


def techniques(row: dict) -> list[dict]:
    """ATT&CK techniques named in the alert (or, failing that, its rule)."""
    text = row.get("mitre") or ", ".join(rule_meta(row.get("rule") or "").get("attack", []))
    out, seen = [], set()
    for tid, name in TECHNIQUE.findall(text or ""):
        if tid not in seen:
            seen.add(tid)
            out.append({"id": tid, "name": name.strip().rstrip("(").strip()})
    return out


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_ecs(row: dict) -> dict:
    """One alert as an ECS 8.x document."""
    details = row.get("details") or {}
    if isinstance(details, str):
        details = json.loads(details)
    sev = (row.get("severity") or "medium").lower()
    tech = techniques(row)
    doc = {
        "@timestamp": _iso(row["ts"]),
        "message": row.get("title"),
        "event": {
            "kind": "alert", "category": ["network", "intrusion_detection"], "type": ["info"],
            "module": "iotmon", "dataset": "iotmon.alert", "severity": SEVERITY_NUM.get(sev, 3),
            "risk_score": round(100 * (row.get("confidence") or 0) * SEVERITY_NUM.get(sev, 3) / 5, 1),
        },
        "rule": {"id": row.get("rule_id"), "name": row.get("rule"), "category": "IoT/OT network"},
        "observer": {"type": "ids", "vendor": "iotmon", "product": "IoT Security Monitor", "version": __version__},
        "log": {"level": sev},
        "labels": {"severity": sev},
        "iotmon": {"alert_id": row.get("id"), "status": row.get("status"), "details": details},
    }
    if row.get("src"):
        doc["source"] = {"ip": row["src"]}
    if row.get("dst"):
        doc["destination"] = {"ip": row["dst"]}
        port = details.get("dst_port") or details.get("port")
        if isinstance(port, int):
            doc["destination"]["port"] = port
    if row.get("confidence") is not None:
        doc["labels"]["confidence"] = confidence_label(row["confidence"])
        doc["iotmon"]["confidence"] = row["confidence"]
    if tech:
        doc["threat"] = {"framework": "MITRE ATT&CK",
                         "technique": {"id": [t["id"] for t in tech], "name": [t["name"] for t in tech]}}
    return doc


def _cef_header(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(value) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def to_cef(row: dict) -> str:
    """One alert as a CEF:0 line (ArcSight, QRadar, Sentinel, most SIEMs)."""
    details = row.get("details") or {}
    if isinstance(details, str):
        details = json.loads(details)
    sev = (row.get("severity") or "medium").lower()
    ext = {"rt": int(row["ts"] * 1000), "src": row.get("src"), "dst": row.get("dst")}
    port = details.get("dst_port") or details.get("port")
    if isinstance(port, int):
        ext["dpt"] = port
    ext["msg"] = row.get("title")
    ext["cat"] = "/".join(t["id"] for t in techniques(row)) or None
    ext["cs1Label"], ext["cs1"] = "mitre", row.get("mitre") or None
    if row.get("confidence") is not None:
        ext["cfp1Label"], ext["cfp1"] = "confidence", row["confidence"]
    if row.get("id") is not None:
        ext["externalId"] = row["id"]
    header = ["CEF:0", "iotmon", "IoT Security Monitor", __version__, row.get("rule_id") or row.get("rule"),
              row.get("rule") or "", CEF_SEVERITY.get(sev, 5)]
    return ("|".join(_cef_header(h) for h in header) + "|"
            + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v is not None))


class SyslogForwarder:
    """Sends each alert to a syslog collector as it fires (RFC 5424 framing,
    CEF or ECS-JSON body). UDP by default; TCP uses octet counting (RFC 6587)."""

    def __init__(self, target: str, fmt: str = "cef", protocol: str = "udp", hostname: str | None = None):
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"--syslog expects HOST:PORT, got {target!r}")
        self.address = (host, int(port))
        self.fmt = fmt
        self.protocol = protocol
        self.hostname = hostname or socket.gethostname()
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, kind)
        if protocol == "tcp":
            self.sock.connect(self.address)
        self.sent = 0

    def format(self, row: dict) -> bytes:
        sev = (row.get("severity") or "medium").lower()
        pri = LOCAL4 * 8 + SYSLOG_SEVERITY.get(sev, 4)
        body = to_cef(row) if self.fmt == "cef" else json.dumps(to_ecs(row), separators=(",", ":"))
        msg = f"<{pri}>1 {_iso(row['ts'])} {self.hostname} iotmon - {row.get('rule_id') or '-'} - {body}"
        data = msg.encode("utf-8")
        return f"{len(data)} ".encode() + data if self.protocol == "tcp" else data

    def alert(self, alert: Alert) -> None:
        data = self.format(alert_row(alert))
        if self.protocol == "udp":
            self.sock.sendto(data, self.address)
        else:
            self.sock.sendall(data)
        self.sent += 1

    def close(self) -> None:
        self.sock.close()


class EcsFileSink:
    """Appends each alert as one ECS JSON line (NDJSON) to a file a log
    shipper tails: Filebeat / Elastic Agent, the Wazuh agent, Splunk UF."""

    def __init__(self, path: str):
        self.file = open(path, "a", encoding="utf-8")

    def alert(self, alert: Alert) -> None:
        self.file.write(json.dumps(to_ecs(alert_row(alert)), separators=(",", ":")) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()
