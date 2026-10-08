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
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
ACTIONABLE = ("low", "medium", "high", "critical")  # everything above INFO
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
                "top_severity": "info", "rules": []})
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

    actionable = [a for a in active if a["severity"] in ACTIONABLE]  # INFO never escalates the posture
    if count["critical"]:
        level = "CRITICAL"
    elif count["high"]:
        level = "AT RISK"
    elif actionable or unreviewed:
        level = "WATCH"
    else:
        level = "OK"
        reasons.insert(0, "No active alerts and every device is approved (or no asset register is in use).")
    return {"level": level, "reasons": reasons}


# -- terminal rendering ------------------------------------------------------ #
LEVEL_COLOUR = {"CRITICAL": "\033[1;31m", "AT RISK": "\033[31m", "WATCH": "\033[33m", "OK": "\033[32m"}
SEV_COLOUR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
              "info": "\033[90m"}
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


# -- risk model (Week 8) ---------------------------------------------------- #
# A documented, project-specific heuristic (NOT a universal standard): an
# asset's intrinsic exposure (its stored risk_score: zone, role, open
# services, internet exposure) plus points for the active alerts that name it.
RISK_STATUS = (("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 20), ("INFO", 0))
# rule ID -> (label shown in the breakdown, points). Deduplicated by label.
ALERT_RISK = {
    "DET-001": ("Unrecognised device", 15), "DET-010": ("Unrecognised OT asset", 20),
    "DET-002": ("Scanning activity", 30), "DET-003": ("Abnormal connection rate", 15),
    "DET-004": ("Suspicious service", 25), "DET-005": ("External connection", 40),
    "DET-006": ("Traffic spike", 20), "DET-007": ("Repeated failures / brute force", 20),
    "DET-008": ("Address change / spoofing", 20), "DET-009": ("Abnormal MQTT activity", 15),
    "DET-011": ("Unauthorized PLC access", 30), "DET-012": ("Cross-zone (IT->OT) access", 25),
    "DET-013": ("Unexpected protocol in OT", 20), "DET-014": ("Abnormal Modbus rate", 15),
    "DET-015": ("OT device reaching internet", 40),
}


def risk_status(score: int) -> str:
    for status, floor in RISK_STATUS:
        if score >= floor:
            return status
    return "INFO"


def enrich_risk(device: dict, device_alerts: list[dict]) -> dict:
    """Combine an asset's base exposure with its active alerts into a 0-100
    score, a status band, and a breakdown the analyst can read."""
    base = int(device.get("risk_score") or 0)
    breakdown = [{"reason": "Base exposure (zone, role, services)", "points": base}]
    best: dict[str, int] = {}
    for a in device_alerts:
        rid = a.get("rule_id") or ""
        if rid not in ALERT_RISK:
            continue
        label, points = ALERT_RISK[rid]
        if rid == "DET-011" and a.get("details", {}).get("write"):
            label, points = "Unauthorized PLC write", 40
        best[label] = max(best.get(label, 0), points)
    for label, points in sorted(best.items(), key=lambda kv: -kv[1]):
        breakdown.append({"reason": label, "points": points})
    score = min(100, base + sum(best.values()))
    return {"score": score, "status": risk_status(score), "base": base, "breakdown": breakdown}


# -- analyst alert view (Week 8) -------------------------------------------- #
DEFAULT_PROTO = {"mqtt_activity": "MQTT", "unauthorized_modbus": "Modbus/TCP", "modbus_rate": "Modbus/TCP",
                 "ot_segmentation": "Modbus/TCP", "ot_new_asset": "Modbus/TCP"}


def _device_card(con, ip: str | None, active: list[dict]) -> dict | None:
    if not ip:
        return None
    rows = _rows(con, "SELECT * FROM devices WHERE ',' || ips || ',' LIKE '%,' || ? || ',%'", (ip,))
    dev = rows[0] if rows else {"ips": ip, "risk_score": 0}
    mine = [a for a in active if a.get("src") == ip or a.get("dst") == ip]
    return {"ip": ip, "name": dev.get("name") or "", "role": dev.get("role") or "",
            "zone": dev.get("zone") or "", "device_type": dev.get("device_type") or "",
            "vendor": dev.get("vendor") or "", "risk": enrich_risk(dev, mine)}


def _protocol(a: dict) -> str:
    d = a.get("details", {})
    if d.get("app"):
        return d["app"]
    if d.get("protocol") and d["protocol"] not in ("TCP", "UDP"):
        return d["protocol"]
    return DEFAULT_PROTO.get(a.get("rule"), d.get("protocol") or "")


def alert_detail(db_path, alert_id: int) -> dict | None:
    """The full investigation card for one alert: labelled source and
    destination, protocol, reason, ATT&CK and the recommended response."""
    from .models import rule_meta

    con = connect_ro(db_path)
    if con is None:
        return None
    try:
        rows = _rows(con, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not rows:
            return None
        a = rows[0]
        a["details"] = json.loads(a.get("details") or "{}")
        a["rule_id"] = a.get("rule_id") or ""
        active = [dict(r, details=json.loads(r.get("details") or "{}"))
                  for r in _rows(con, f"SELECT * FROM alerts WHERE {_ACTIVE}")]
        run = _rows(con, "SELECT * FROM runs WHERE id = ?", (a.get("run_id"),))
        meta = rule_meta(a.get("rule") or a["rule_id"])
        src = _device_card(con, a.get("src"), active)
        dst = _device_card(con, a.get("dst"), active)
        source = run[0]["source"] if run else None
        pcap = bool(source and source not in (None, "") and run[0]["mode"] == "read"
                    and Path(source).exists())
        return {
            "id": alert_id, "alert_ref": f"ALT-{alert_id:04d}",
            "ts": a["ts"], "severity": a["severity"], "status": a.get("status", "open"),
            "rule_id": a["rule_id"], "rule": a.get("rule"), "title": a.get("title"),
            "note": a.get("note"), "protocol": _protocol(a), "mitre": a.get("mitre") or "",
            "attack": meta.get("attack", []), "response": meta.get("response", []),
            "description": meta.get("description", "").strip(),
            "source": src, "destination": dst, "evidence": a["details"],
            "pcap": {"available": pcap, "capture": source if pcap else None},
        }
    finally:
        con.close()


def render_alert_card(d: dict, utc: bool = False, colour: bool = False, width: int = 64,
                      ascii: bool = False) -> str:
    tz = timezone.utc if utc else None
    rule_line = ("-" if ascii else "─") * width

    def paint(t, code):
        return f"{code}{t}{RESET}" if colour and code else t

    def endpoint(label, c):
        if not c:
            return [f"{label}:", "  (not a tracked device)"]
        tag = f"  risk {c['risk']['score']}/100 {c['risk']['status']}"
        bits = [b for b in (c["device_type"], c["role"], c["zone"] and f"{c['zone']} zone") if b]
        return [f"{label}:", f"  {c['ip']}" + (f"  {c['name']}" if c["name"] else ""),
                f"  {' / '.join(bits)}" if bits else "", tag]

    L = ["SECURITY ALERT", rule_line,
         f"{'Alert ID:':<14}{d['alert_ref']}",
         f"{'Severity:':<14}" + paint(d["severity"].upper(), SEV_COLOUR.get(d["severity"])),
         f"{'Rule:':<14}{d['rule_id']}  {d['rule']}",
         f"{'Time:':<14}{datetime.fromtimestamp(d['ts'], tz=tz).strftime('%Y-%m-%d %H:%M:%S')}",
         f"{'Status:':<14}{d['status']}", ""]
    L += endpoint("Source", d["source"]) + [""]
    L += endpoint("Destination", d["destination"]) + [""]
    if d["protocol"]:
        L += [f"{'Protocol:':<14}{d['protocol']}", ""]
    L += ["Reason:"] + textwrap.wrap(d["title"], width, initial_indent="  ", subsequent_indent="  ")
    if d["response"]:
        L += ["", "Recommended action:"] + [f"  {i}. {s}" for i, s in enumerate(d["response"], 1)]
    if d["attack"]:
        L += ["", "MITRE ATT&CK:"] + [f"  - {t}" for t in d["attack"]]
    if d["pcap"]["available"]:
        L += ["", f"PCAP: {d['pcap']['capture']}  (iotmon pcap {d['id']} -o alert.pcap)"]
    return "\n".join(x for x in L if x is not None)


# -- security report (Week 8) ----------------------------------------------- #
OT_TYPES = {"PLC", "HMI", "EWS"}
IOT_TYPES = {"MQTT broker", "IoT sensor/actuator", "IP camera"}


def _classify(dev: dict) -> str:
    if dev.get("zone") == "OT" or dev.get("device_type") in OT_TYPES:
        return "ot"
    if dev.get("device_type") in IOT_TYPES or "MQTT" in (dev.get("protocols") or ""):
        return "iot"
    return "unknown"


def security_report(db_path) -> dict:
    con = connect_ro(db_path)
    try:
        devices = _rows(con, "SELECT * FROM devices")
        alerts = [dict(r, details=json.loads(r.get("details") or "{}"))
                  for r in _rows(con, "SELECT * FROM alerts")]
        traffic = _rows(con, "SELECT COALESCE(SUM(packets),0) p, COALESCE(SUM(bytes),0) b,"
                             " MIN(minute) first, MAX(minute) last FROM traffic")[0]
        runs = _rows(con, "SELECT * FROM runs ORDER BY id")
        active = [a for a in alerts if a.get("status", "open") in ACTIVE_STATUSES]
    finally:
        if con is not None:
            con.close()

    kinds = {"iot": 0, "ot": 0, "unknown": 0}
    for d in devices:
        kinds[_classify(d)] += 1
    by_sev = {s: sum(a["severity"] == s for a in alerts) for s in SEVERITY_ORDER}

    most_active = max(devices, key=lambda d: (d.get("packets_sent", 0) or 0) + (d.get("packets_recv", 0) or 0),
                      default=None)
    ranked = []
    for d in devices:
        ips = {ip for ip in (d.get("ips") or "").split(",") if ip}
        mine = [a for a in active if a.get("src") in ips or a.get("dst") in ips]
        ranked.append((d, enrich_risk(d, mine)))
    highest = max(ranked, key=lambda dr: dr[1]["score"], default=None)
    rule_counts: dict[tuple, int] = {}
    for a in alerts:
        rule_counts[(a.get("rule_id") or "", a.get("rule") or "")] = rule_counts.get(
            (a.get("rule_id") or "", a.get("rule") or ""), 0) + 1
    top = max(rule_counts.items(), key=lambda kv: kv[1], default=None)

    def who(d):
        return (d.get("name") or d.get("ips") or "?") if d else "-"

    return {
        "period": {"first": traffic["first"], "last": traffic["last"],
                   "started": runs[0]["started"] if runs else None,
                   "ended": runs[-1]["ended"] if runs else None, "runs": len(runs)},
        "assets": {"total": len(devices), **kinds},
        "traffic": {"packets": traffic["p"], "bytes": traffic["b"]},
        "alerts": {"total": len(alerts), "active": len(active), "by_severity": by_sev},
        "most_active": {"who": who(most_active), "ip": most_active.get("ips") if most_active else None,
                        "packets": ((most_active.get("packets_sent", 0) or 0)
                                    + (most_active.get("packets_recv", 0) or 0)) if most_active else 0},
        "highest_risk": {"who": who(highest[0]), "ip": highest[0].get("ips"),
                         "device_type": highest[0].get("device_type"),
                         **highest[1]} if highest else None,
        "top_detection": {"rule_id": top[0][0], "rule": top[0][1], "count": top[1]} if top else None,
    }


def _fmt_period(p: dict, utc: bool) -> str:
    tz = timezone.utc if utc else None
    if p["first"] is None:
        return "no traffic recorded"
    f = datetime.fromtimestamp(p["first"], tz=tz).strftime("%Y-%m-%d %H:%M")
    t = datetime.fromtimestamp(p["last"] + 60, tz=tz).strftime("%H:%M")
    return f"{f} - {t}{' UTC' if utc else ''}"


def render_report(r: dict, utc: bool = False, width: int = 60) -> str:
    rule = "=" * width
    sev = r["alerts"]["by_severity"]
    L = ["IoT/OT SECURITY REPORT", rule, "",
         "Monitoring period", f"  {_fmt_period(r['period'], utc)}", "",
         f"Assets discovered:        {r['assets']['total']:>8}",
         f"  IoT devices:            {r['assets']['iot']:>8}",
         f"  OT devices:             {r['assets']['ot']:>8}",
         f"  Unknown devices:        {r['assets']['unknown']:>8}", "",
         f"Traffic analyzed:         {r['traffic']['packets']:>8,}  ({_fmt_bytes(r['traffic']['bytes'])})", "",
         "Alerts", "-" * width,
         f"  Critical:               {sev['critical']:>8}",
         f"  High:                   {sev['high']:>8}",
         f"  Medium:                 {sev['medium']:>8}",
         f"  Low:                    {sev['low']:>8}",
         f"  Info:                   {sev['info']:>8}", ""]
    if r["most_active"]["ip"]:
        L += ["Most Active Asset", f"  {_lbl(r['most_active']['who'], r['most_active']['ip'])}"
              f"  {r['most_active']['packets']:,} packets", ""]
    hr = r["highest_risk"]
    if hr:
        L += ["Highest Risk Asset", f"  {_lbl(hr['who'], hr['ip'])}  {hr['device_type'] or ''}".rstrip(),
              f"  Risk Score: {hr['score']}/100  {hr['status']}"]
        for b in hr["breakdown"]:
            if b["points"]:
                L.append(f"    {b['reason']:<34} +{b['points']}")
        L.append("")
    if r["top_detection"]:
        td = r["top_detection"]
        L += ["Top Detection", f"  {td['rule_id']} {td['rule']}  ({td['count']} alerts)"]
    return "\n".join(L)


def render_report_md(r: dict, utc: bool = False) -> str:
    sev = r["alerts"]["by_severity"]
    hr = r["highest_risk"]
    lines = [
        "# IoT/OT Security Report", "",
        f"**Monitoring period:** {_fmt_period(r['period'], utc)}", "",
        "## Assets", "",
        "| | Count |", "|---|---|",
        f"| Assets discovered | {r['assets']['total']} |",
        f"| IoT devices | {r['assets']['iot']} |",
        f"| OT devices | {r['assets']['ot']} |",
        f"| Unknown devices | {r['assets']['unknown']} |", "",
        f"**Traffic analyzed:** {r['traffic']['packets']:,} packets ({_fmt_bytes(r['traffic']['bytes'])})", "",
        "## Alerts", "",
        "| Severity | Count |", "|---|---|",
        f"| Critical | {sev['critical']} |", f"| High | {sev['high']} |", f"| Medium | {sev['medium']} |",
        f"| Low | {sev['low']} |", f"| Info | {sev['info']} |", "",
    ]
    if r["most_active"]["ip"]:
        lines += [f"**Most active asset:** {_lbl(r['most_active']['who'], r['most_active']['ip'])}, "
                  f"{r['most_active']['packets']:,} packets", ""]
    if hr:
        lines += [f"**Highest risk asset:** {_lbl(hr['who'], hr['ip'])} — **{hr['score']}/100 {hr['status']}**", "",
                  "| Factor | Points |", "|---|---|"]
        lines += [f"| {b['reason']} | +{b['points']} |" for b in hr["breakdown"] if b["points"]]
        lines += [""]
    if r["top_detection"]:
        td = r["top_detection"]
        lines += [f"**Top detection:** {td['rule_id']} {td['rule']} ({td['count']} alerts)"]
    return "\n".join(lines) + "\n"


def render_report_html(r: dict, utc: bool = False) -> str:
    sev = r["alerts"]["by_severity"]
    hr = r["highest_risk"]
    chips = "".join(
        f'<span class="chip {s}"><b>{sev[s]}</b> {s}</span>' for s in SEVERITY_ORDER)
    rows = ""
    if hr:
        rows = "".join(f"<tr><td>{b['reason']}</td><td>+{b['points']}</td></tr>"
                       for b in hr["breakdown"] if b["points"])
    gen = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_block = ""
    if hr:
        risk_block = (f"<h2>Highest-risk asset</h2><p class='big'>{_esc(hr['who'])} "
                      f"<span class='muted'>({_esc(hr['ip'])})</span></p>"
                      f"<p><span class='score {hr['status'].lower()}'>{hr['score']}/100 · {hr['status']}</span></p>"
                      f"<table class='bd'>{rows}</table>")
    most = ""
    if r["most_active"]["ip"]:
        most = (f"<h2>Most active asset</h2><p class='big'>{_esc(r['most_active']['who'])} "
                f"<span class='muted'>({_esc(r['most_active']['ip'])})</span></p>"
                f"<p>{r['most_active']['packets']:,} packets</p>")
    top = ""
    if r["top_detection"]:
        td = r["top_detection"]
        top = f"<h2>Top detection</h2><p class='big'>{td['rule_id']} {_esc(td['rule'])}</p><p>{td['count']} alerts</p>"
    a = r["assets"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>IoT/OT Security Report</title>
<style>
:root{{--ink:#0b0b0b;--muted:#6b6a66;--line:#e1e0d9;--card:#fff;--bg:#f6f6f3;
--critical:#d03b3b;--high:#ec835a;--medium:#fab219;--low:#3a86c8;--info:#8a8a8a;--good:#0ca30c}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:32px}}
.wrap{{max-width:760px;margin:0 auto}}h1{{font-size:24px;margin:0 0 4px}}
.sub{{color:var(--muted);margin:0 0 24px}}.grid{{display:grid;gap:16px;grid-template-columns:1fr 1fr}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}}
.card.full{{grid-column:1/-1}}h2{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;
color:var(--muted);margin:0 0 10px}}.big{{font-size:20px;font-weight:600;margin:4px 0}}
.muted{{color:var(--muted);font-weight:400}}.nums{{display:flex;gap:28px;flex-wrap:wrap}}
.nums div span{{display:block;font-size:28px;font-weight:700}}.nums div small{{color:var(--muted)}}
.chips{{display:flex;gap:8px;flex-wrap:wrap}}.chip{{padding:4px 10px;border-radius:999px;
border:1px solid var(--line);font-size:13px}}.chip b{{font-variant-numeric:tabular-nums}}
.chip.critical{{border-color:var(--critical);color:var(--critical)}}.chip.high{{border-color:var(--high);color:var(--high)}}
.chip.medium{{border-color:var(--medium);color:#8a6400}}.chip.low{{border-color:var(--low);color:var(--low)}}
.chip.info{{color:var(--info)}}.score{{font-weight:700;padding:3px 10px;border-radius:6px;color:#fff}}
.score.critical{{background:var(--critical)}}.score.high{{background:var(--high)}}.score.medium{{background:var(--medium)}}
.score.low{{background:var(--low)}}.score.info{{background:var(--info)}}
table.bd{{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px}}
table.bd td{{border-top:1px solid var(--line);padding:5px 0}}table.bd td:last-child{{text-align:right;color:var(--muted)}}
@media(max-width:620px){{.grid{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<h1>IoT / OT Security Report</h1>
<p class="sub">Monitoring period: {_fmt_period(r['period'], utc)} · generated {gen}</p>
<div class="grid">
<div class="card"><h2>Assets discovered</h2><div class="nums">
<div><span>{a['total']}</span><small>total</small></div>
<div><span>{a['iot']}</span><small>IoT</small></div>
<div><span>{a['ot']}</span><small>OT</small></div>
<div><span>{a['unknown']}</span><small>unknown</small></div></div></div>
<div class="card"><h2>Traffic analyzed</h2><p class="big">{r['traffic']['packets']:,}</p>
<p class="muted">packets · {_fmt_bytes(r['traffic']['bytes'])}</p></div>
<div class="card full"><h2>Alerts ({r['alerts']['total']} total, {r['alerts']['active']} active)</h2>
<div class="chips">{chips}</div></div>
<div class="card">{most or '<h2>Most active asset</h2><p class="muted">-</p>'}</div>
<div class="card">{risk_block or '<h2>Highest-risk asset</h2><p class="muted">-</p>'}</div>
<div class="card full">{top or '<h2>Top detection</h2><p class="muted">-</p>'}</div>
</div></div></body></html>"""


def _esc(s) -> str:
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _lbl(who, ip) -> str:
    """'<name> (<ip>)' when the asset has a name, else just the IP."""
    return f"{who} ({ip})" if who and who != ip else str(ip)
