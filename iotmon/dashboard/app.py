"""Flask dashboard over the monitor's SQLite database.

The monitor writes, the dashboard reads (SQLite WAL mode allows both at
once), so the dashboard can run in a separate process or container. Its
only write is alert triage (Week 5), which `--read-only` turns off.
"""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, abort, jsonify, render_template, request

from ..state import connect_ro, query_alerts, security_state, write_csv
from ..storage import ALERT_STATUSES, set_alert_status



def create_app(db_path: str | Path, read_only: bool = False) -> Flask:
    app = Flask(__name__)
    db_path = str(db_path)

    def query(sql: str, args: tuple = ()) -> list[dict]:
        con = connect_ro(db_path)
        if con is None:
            return []
        try:
            return [dict(r) for r in con.execute(sql, args)]
        except sqlite3.OperationalError:  # tables not created yet
            return []
        finally:
            con.close()

    def filtered_alerts(limit: int) -> list[dict]:
        a = request.args
        con = connect_ro(db_path)
        if con is None:
            return []
        try:
            return query_alerts(con, a.get("severity") or None, a.get("status") or None, a.get("rule") or None,
                                a.get("ip") or None, limit=limit)
        finally:
            con.close()

    @app.get("/")
    def index():
        return render_template("index.html", read_only=read_only)

    @app.get("/api/state")
    def state():
        """Posture, headline numbers, devices needing attention, recent alerts (Week 5)."""
        return jsonify({**security_state(db_path), "read_only": read_only})

    @app.get("/api/summary")
    def summary():
        s = security_state(db_path, recent=0)
        return jsonify({
            "devices": s["devices"],
            "packets": s["packets"],
            "bytes": s["bytes"],
            "first": s["first"],
            "last": s["last"],
            "alerts": s["alerts"],
            "alerts_active": s["alerts_active"],
            "posture": s["posture"]["level"],
            "by_severity": [{"severity": x["severity"], "count": x["count"]} for x in s["by_severity"]],
            "by_rule": [{"rule_id": r["rule_id"], "rule": r["rule"], "n": r["n"]} for r in s["by_rule"]],
        })

    @app.get("/api/alerts")
    def alerts():
        """Newest first. Filters: severity, status (or 'active'), rule (ID or name), ip."""
        return jsonify(filtered_alerts(min(int(request.args.get("limit", 200)), 1000)))

    @app.get("/api/alerts.csv")
    def alerts_csv():
        out = io.StringIO()
        write_csv(filtered_alerts(10**9), out)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=iotmon-alerts.csv"})

    @app.post("/api/alerts/<int:alert_id>")
    def triage(alert_id: int):
        """Set an alert's triage status: {"status": "acknowledged", "note": "..."}."""
        if read_only:
            abort(403, "dashboard is read-only")
        # A JSON body cannot be sent cross-site without a CORS preflight, which
        # this app never answers, so a malicious page cannot triage alerts.
        if not request.is_json:
            abort(415, "send application/json")
        origin = request.headers.get("Origin")
        if origin and urlsplit(origin).netloc != request.host:
            abort(403, "cross-origin request")
        body = request.get_json(silent=True) or {}
        status = body.get("status")
        if status not in ALERT_STATUSES:
            abort(400, f"status must be one of {', '.join(ALERT_STATUSES)}")
        note = body.get("note")
        if note is not None:
            note = str(note).strip()[:500] or None
        if not Path(db_path).exists() or not set_alert_status(db_path, [alert_id], status, note):
            abort(404, f"no alert {alert_id}")
        return jsonify(query("SELECT id, status, note, updated FROM alerts WHERE id = ?", (alert_id,))[0])

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

    @app.get("/api/runs")
    def runs():
        """Monitoring runs, newest first (Week 5)."""
        return jsonify(query("SELECT * FROM runs ORDER BY id DESC LIMIT 50"))

    return app
