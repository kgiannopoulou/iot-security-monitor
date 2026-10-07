"""Read-only Flask dashboard over the monitor's SQLite database.

The monitor writes, the dashboard reads (SQLite WAL mode allows both at
once), so the dashboard can run in a separate process or container.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template, request

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def create_app(db_path: str | Path) -> Flask:
    app = Flask(__name__)
    db_path = str(db_path)

    def query(sql: str, args: tuple = ()) -> list[dict]:
        if not Path(db_path).exists():
            return []
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in con.execute(sql, args)]
        except sqlite3.OperationalError:  # tables not created yet
            return []
        finally:
            con.close()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/summary")
    def summary():
        sev = {r["severity"]: r["n"] for r in query("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
        traffic = query("SELECT COALESCE(SUM(packets),0) packets, COALESCE(SUM(bytes),0) bytes,"
                        " MIN(minute) first, MAX(minute) last FROM traffic")
        devices = query("SELECT COUNT(*) n FROM devices")
        rules = query("SELECT rule_id, rule, COUNT(*) n FROM alerts GROUP BY rule_id, rule ORDER BY rule_id")
        return jsonify({
            "devices": devices[0]["n"] if devices else 0,
            "packets": traffic[0]["packets"] if traffic else 0,
            "bytes": traffic[0]["bytes"] if traffic else 0,
            "first": traffic[0]["first"] if traffic else None,
            "last": traffic[0]["last"] if traffic else None,
            "alerts": sum(sev.values()),
            "by_severity": [{"severity": s, "count": sev.get(s, 0)} for s in SEVERITY_ORDER],
            "by_rule": rules,
        })

    @app.get("/api/alerts")
    def alerts():
        limit = min(int(request.args.get("limit", 200)), 1000)
        rows = query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
        for r in rows:
            r["details"] = json.loads(r["details"] or "{}")
        return jsonify(rows)

    @app.get("/api/devices")
    def devices():
        return jsonify(query("SELECT * FROM devices ORDER BY first_seen"))

    @app.get("/api/traffic")
    def traffic():
        """Per-minute packet counts by application protocol."""
        rows = query("SELECT minute, app, packets, bytes FROM traffic ORDER BY minute")
        minutes = sorted({r["minute"] for r in rows})
        index = {m: i for i, m in enumerate(minutes)}
        series: dict[str, list[int]] = {}
        for r in rows:
            series.setdefault(r["app"], [0] * len(minutes))[index[r["minute"]]] += r["packets"]
        return jsonify({"minutes": minutes, "series": series})

    @app.get("/api/mqtt")
    def mqtt():
        """MQTT clients and topics (Week 4)."""
        return jsonify({
            "clients": query("SELECT * FROM mqtt_clients ORDER BY broker, ip, key"),
            "topics": query("SELECT * FROM mqtt_topics ORDER BY topic"),
        })

    @app.get("/api/flows")
    def flows():
        return jsonify(query("SELECT * FROM flows ORDER BY bytes DESC LIMIT 25"))

    return app
