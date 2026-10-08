"""Security state: the numbers and the verdict behind `iotmon status` and
the dashboard (Week 5).

Everything is computed from the SQLite database, so the terminal and the
web page always agree. The posture is a plain rule, not a score:

    CRITICAL  an active critical alert
    AT RISK   an active high alert
    WATCH     active medium/low alerts, or devices not approved in the asset register
    OK        nothing that needs attention
    NO DATA   nothing analysed yet

"Active" means open or acknowledged: acknowledging an alert says someone is
on it, not that the risk is gone. Only resolved or false-positive alerts
stop counting.
"""

from __future__ import annotations

import csv
import json
import sqlite3
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import SEVERITIES, rule_id
from .storage import ACTIVE_STATUSES

SEVERITY_ORDER = tuple(reversed(SEVERITIES))  # critical first
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
UNREVIEWED = ("pending", "new")  # asset-register statuses that need a decision
LIVE_STALE_S = 30  # a live run that has not committed for this long has stopped

_ACTIVE = f"status IN ({','.join(repr(s) for s in ACTIVE_STATUSES)})"


def connect_ro(db_path: str | Path) -> sqlite3.Connection | None:
    if not Path(db_path).exists():
        return None
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _rows(con: sqlite3.Connection | None, sql: str, args: tuple = ()) -> list[dict]:
    if con is None:
        return []
    try:
        return [dict(r) for r in con.execute(sql, args)]
    except sqlite3.OperationalError:  # table or column from a later week missing
        return []


def query_alerts(con: sqlite3.Connection | None, severity: str | None = None, status: str | None = None,
                 rule: str | None = None, ip: str | None = None, since: float | None = None,
                 limit: int = 200) -> list[dict]:
    """Alerts newest first. `status` may be a triage status or 'active'.
    `rule` matches the rule ID (DET-002) or name (port_scan)."""
    where, args = [], []
    if severity:
        where.append("severity = ?")
        args.append(severity.lower())
    if status == "active":
        where.append(_ACTIVE)
    elif status:
        where.append("status = ?")
        args.append(status)
    if rule:
        where.append("(rule_id = ? OR rule = ?)")
        args += [rule.upper(), rule]
    if ip:
        where.append("(src = ? OR dst = ?)")
        args += [ip, ip]
    if since is not None:
        where.append("ts >= ?")
        args.append(since)
    sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")
    rows = _rows(con, sql + " ORDER BY ts DESC, id DESC LIMIT ?", (*args, limit))
    for r in rows:
        r["details"] = json.loads(r.get("details") or "{}")
        r.setdefault("status", "open")
    return rows


def _device_risk(devices: list[dict], active: list[dict]) -> list[dict]:
    """Rank devices by the active alerts that name them.

    The device that did something (alert source) gets the full severity
    weight, the device it was done to (destination) half: a scanned camera
    matters, the Raspberry Pi doing the scanning matters more.
    """
    by_ip = {ip: d for d in devices for ip in (d.get("ips") or "").split(",") if ip}
    risk: dict[str, dict] = {}
    for a in active:
        for ip, factor in ((a.get("src"), 1.0), (a.get("dst"), 0.5)):
            d = by_ip.get(ip)
            if d is None:
                continue
            r = risk.setdefault(d["key"], {
                "key": d["key"], "ips": d["ips"], "mac": d.get("mac"), "vendor": d.get("vendor"),
                "role": d.get("role"), "status": d.get("status") or "", "alerts": 0, "score": 0.0,
                "top_severity": "low", "rules": []})
            if a["id"] in r.setdefault("_seen", set()):
                continue  # src and dst are the same device
            r["_seen"].add(a["id"])
            r["alerts"] += 1
            r["score"] += SEVERITY_WEIGHT.get(a["severity"], 1) * factor
            if SEVERITIES.index(a["severity"]) > SEVERITIES.index(r["top_severity"]):
                r["top_severity"] = a["severity"]
            if a.get("rule_id") and a["rule_id"] not in r["rules"]:
                r["rules"].append(a["rule_id"])
    out = sorted(risk.values(), key=lambda r: (-r["score"], r["ips"]))
    for r in out:
        r.pop("_seen")
        r["rules"].sort()
    return out


def _run_info(con) -> dict | None:
    runs = _rows(con, "SELECT * FROM runs ORDER BY id DESC LIMIT 1")
    if not runs:
        return None
    run = runs[0]
    run["active"] = run["ended"] is None and time.time() - (run["updated"] or 0) < LIVE_STALE_S
    run["count"] = _rows(con, "SELECT COUNT(*) n FROM runs")[0]["n"]
    return run


def security_state(db_path: str | Path, recent: int = 10) -> dict:
    con = connect_ro(db_path)
    try:
        traffic = _rows(con, "SELECT COALESCE(SUM(packets),0) packets, COALESCE(SUM(bytes),0) bytes,"
                             " MIN(minute) first, MAX(minute) last FROM traffic")
        traffic = traffic[0] if traffic else {"packets": 0, "bytes": 0, "first": None, "last": None}
        devices = _rows(con, "SELECT * FROM devices ORDER BY first_seen")
        alerts = _rows(con, "SELECT * FROM alerts ORDER BY ts")
        for a in alerts:  # databases from before Week 3 / Week 5 lack these columns
            a["status"] = a.get("status") or "open"
            a["rule_id"] = a.get("rule_id") or rule_id(a["rule"])
        run = _run_info(con)
        recent_alerts = query_alerts(con, limit=recent)
    finally:
        if con is not None:
            con.close()

    active = [a for a in alerts if a["status"] in ACTIVE_STATUSES]
    by_severity = [{"severity": s,
                    "count": sum(a["severity"] == s for a in alerts),
                    "open": sum(a["severity"] == s for a in active)} for s in SEVERITY_ORDER]
    rules: dict[tuple, dict] = {}
    for a in alerts:
        r = rules.setdefault((a["rule_id"] or "", a["rule"]), {"rule_id": a["rule_id"], "rule": a["rule"],
                                                                 "n": 0, "open": 0})
        r["n"] += 1
        r["open"] += a["status"] in ACTIVE_STATUSES
    by_status = {s: sum(a["status"] == s for a in alerts) for s in ("open", "acknowledged", "resolved",
                                                                     "false_positive")}
    unreviewed = [d for d in devices if d.get("status") in UNREVIEWED]
    risky = _device_risk(devices, active)

    state = {
        "devices": len(devices),
        "devices_unreviewed": len(unreviewed),
        "packets": traffic["packets"],
        "bytes": traffic["bytes"],
        "first": traffic["first"],
        "last": traffic["last"],
        "alerts": len(alerts),
        "alerts_active": len(active),
        "high": sum(a["severity"] in ("high", "critical") for a in alerts),
        "high_active": sum(a["severity"] in ("high", "critical") for a in active),
        "by_severity": by_severity,
        "by_rule": sorted(rules.values(), key=lambda r: (r["rule_id"] or "", r["rule"])),
        "by_status": by_status,
        "risky_devices": risky,
        "recent_alerts": recent_alerts,
        "run": run,
    }
    state["posture"] = posture(state, active, unreviewed)
    return state


def posture(state: dict, active: list[dict], unreviewed: list[dict]) -> dict:
    count = {s: sum(a["severity"] == s for a in active) for s in SEVERITIES}
    reasons: list[str] = []

    def describe(sev: str) -> None:
        rules = sorted({f"{a['rule_id']} {a['rule']}" for a in active if a["severity"] == sev})
        n = count[sev]
        reasons.append(f"{n} active {sev} alert{'s' if n != 1 else ''}: {', '.join(rules)}")

    if not state["packets"] and not state["alerts"] and not state["devices"]:
        return {"level": "NO DATA", "reasons": ["Nothing analysed yet: run `iotmon read` or `iotmon live`."]}
    for sev in SEVERITY_ORDER:
        if count[sev]:
            describe(sev)
    if unreviewed:
        ips = ", ".join(d["ips"] for d in unreviewed[:5]) + (" ..." if len(unreviewed) > 5 else "")
        n = len(unreviewed)
        reasons.append(f"{n} device{'s' if n != 1 else ''} not approved in the asset register: {ips}")
    if state["risky_devices"]:
        top = state["risky_devices"][0]
        reasons.append(f"Most affected device: {top['ips']} ({top['vendor']}), "
                       f"{top['alerts']} active alert{'s' if top['alerts'] != 1 else ''}")
    closed = state["by_status"]["resolved"] + state["by_status"]["false_positive"]
    if closed:
        reasons.append(f"{closed} alert{'s' if closed != 1 else ''} already triaged as resolved or false positive")

    if count["critical"]:
        level = "CRITICAL"
    elif count["high"]:
        level = "AT RISK"
    elif active or unreviewed:
        level = "WATCH"
    else:
        level = "OK"
        reasons.insert(0, "No active alerts and every device is approved (or no asset register is in use).")
    return {"level": level, "reasons": reasons}


# -- terminal rendering ------------------------------------------------------ #
LEVEL_COLOUR = {"CRITICAL": "\033[1;31m", "AT RISK": "\033[31m", "WATCH": "\033[33m", "OK": "\033[32m"}
SEV_COLOUR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def render_text(state: dict, utc: bool = False, colour: bool = False, width: int = 78,
                ascii: bool = False) -> str:
    """The terminal dashboard: headline numbers, why, which devices, and recent alerts.
    `ascii` swaps the box-drawing rule for dashes on consoles that cannot print it."""
    tz = timezone.utc if utc else None

    def t(ts, fmt="%H:%M:%S"):
        return datetime.fromtimestamp(ts, tz=tz).strftime(fmt) if ts is not None else "-"

    def paint(text, code):
        return f"{code}{text}{RESET}" if colour and code else text

    rule = ("-" if ascii else "─") * width
    level = state["posture"]["level"]
    lines = []
    title = "IOT SECURITY MONITOR"
    tag = f"posture: {level}"
    lines.append(title + " " * max(1, width - len(title) - len(tag)) + paint(tag, LEVEL_COLOUR.get(level)))
    lines.append(rule)

    def row(label, value, extra=""):
        lines.append(f"{label:<28}{value:>12}" + (f"   {extra}" if extra else ""))

    unrev = state["devices_unreviewed"]
    row("Devices monitored", f"{state['devices']:,}", f"{unrev} not approved" if unrev else "")
    row("Packets analyzed", f"{state['packets']:,}", _fmt_bytes(state["bytes"]) if state["packets"] else "")
    row("Security alerts", f"{state['alerts']:,}", f"{state['alerts_active']} active" if state["alerts"] else "")
    row("High-severity alerts", f"{state['high']:,}", f"{state['high_active']} active" if state["high"] else "")
    if state["first"] is not None:
        span = f"{t(state['first'], '%Y-%m-%d %H:%M')} - {t(state['last'] + 60, '%H:%M')}{' UTC' if utc else ''}"
        row("Traffic window", "", span)
    run = state["run"]
    if run:
        what = f"{run['mode']} {run['source'] or ''}".strip()
        when = "running" if run["active"] else ("finished" if run["ended"] else "stopped")
        row("Last run", f"#{run['id']}", _fit(f"{what} ({when}, {run['packets']:,} packets)", width - 43))

    lines += ["", f"Why {level}", rule]
    for r in state["posture"]["reasons"]:
        lines += textwrap.wrap(r, width, initial_indent="  - ", subsequent_indent="    ")

    if state["risky_devices"]:
        lines += ["", "Devices needing attention", rule]
        lines.append(f"  {'IP':<15} {'VENDOR':<26} {'ALERTS':>6}  {'WORST':<9} RULES")
        for d in state["risky_devices"][:5]:
            worst = paint(f"{d['top_severity'].upper():<9}", SEV_COLOUR.get(d["top_severity"]))
            lines.append(f"  {d['ips'][:15]:<15} {(d['vendor'] or '')[:26]:<26} {d['alerts']:>6}  "
                         f"{worst} {_fit(', '.join(d['rules']), width - 63)}")

    lines += ["", "Recent Alerts", rule]
    if not state["recent_alerts"]:
        lines.append("  none")
    for a in state["recent_alerts"]:
        sev = paint(f"{a['severity'].upper():<8}", SEV_COLOUR.get(a["severity"]))
        status = "" if a["status"] == "open" else f"  [{a['status']}]"
        title = _fit(a["title"], width - 35 - len(status))
        lines.append(f"  {a['id']:>4} {t(a['ts'])}  {sev} {a['rule_id'] or '':<8} {title}{status}")
    return "\n".join(lines)


def _fit(text: str, room: int) -> str:
    return text if len(text) <= room else text[:max(room - 3, 0)] + "..."


def _fmt_bytes(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.1f} kB" if n >= 1e3 else f"{n} B"


# -- export ------------------------------------------------------------------ #
EXPORT_FIELDS = ["id", "timestamp", "rule_id", "rule", "severity", "status", "src", "dst", "title", "mitre",
                 "note", "details"]


def export_rows(alerts: list[dict]) -> list[dict]:
    """Alerts (as returned by query_alerts) as flat export records, oldest first."""
    return [{**{k: a.get(k) for k in EXPORT_FIELDS},
             "timestamp": datetime.fromtimestamp(a["ts"], tz=timezone.utc).isoformat(timespec="seconds"),
             "details": json.dumps(a["details"], sort_keys=True)} for a in reversed(alerts)]


def write_csv(alerts: list[dict], out) -> int:
    rows = export_rows(alerts)
    w = csv.DictWriter(out, fieldnames=EXPORT_FIELDS)
    w.writeheader()
    w.writerows(rows)
    return len(rows)
