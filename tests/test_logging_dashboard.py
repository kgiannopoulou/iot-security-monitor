"""Week 5: SQLite log (runs, triage, schema upgrade, retention), security
posture, `iotmon status` / `alerts` / `db` commands, and the dashboard API."""

import csv
import io
import json
import sqlite3
from pathlib import Path

import pytest

from iotmon.cli import main
from iotmon.config import load_config
from iotmon.dashboard.app import create_app
from iotmon.models import Alert, PacketRecord
from iotmon.pipeline import Monitor
from iotmon.state import render_text, security_state
from iotmon.storage import SCHEMA_VERSION, Storage, open_db, prune, set_alert_status

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "iot-lab.pcap"

CAMERA = dict(src_ip="192.168.1.22", src_mac="44:19:b6:00:00:22")
PI = dict(src_ip="192.168.1.66", src_mac="b8:27:eb:00:00:66")


def _db(tmp_path, alerts, status: dict[str, str] | None = None) -> Path:
    """A small database: two devices, the given alerts, optional asset statuses."""
    db = tmp_path / "t.db"
    mon = Monitor(load_config(), Storage(db, reset=True, mode="read", source="unit"))
    for i, dev in enumerate((CAMERA, PI)):
        mon.process(PacketRecord(ts=60 + i, protocol="UDP", length=100, dst_ip="192.168.1.1",
                                 sport=123, dport=123, app="NTP", **dev))
    for d in mon.inventory.devices.values():
        d.status = (status or {}).get(min(d.ips), "")
    mon._emit(alerts)
    mon.close()
    return db


@pytest.fixture(scope="module")
def sample_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("sample") / "iotmon.db"
    assert main(["read", str(SAMPLE), "-q", "--db", str(db)]) == 0
    return db


# -- storage --------------------------------------------------------------- #
def test_run_is_recorded(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan", src="192.168.1.66")])
    run = sqlite3.connect(db).execute("SELECT mode, source, packets, alerts, first_packet, last_packet,"
                                      " ended IS NOT NULL FROM runs").fetchone()
    assert run == ("read", "unit", 2, 1, 60.0, 61.0, 1)


def test_alerts_start_open_and_are_triaged(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan", src="192.168.1.66"),
                        Alert(71, "new_device", "medium", "new", src="192.168.1.66")])
    assert set_alert_status(db, [1, 2, 99], "acknowledged", note="on it", now=1000) == [1, 2]
    assert set_alert_status(db, [2], "resolved", now=1001) == [2]  # note kept when none given
    rows = sqlite3.connect(db).execute("SELECT id, status, note, updated FROM alerts ORDER BY id").fetchall()
    assert rows == [(1, "acknowledged", "on it", 1000.0), (2, "resolved", "on it", 1001.0)]
    with pytest.raises(ValueError):
        set_alert_status(db, [1], "ignored")


def test_week4_database_is_upgraded(tmp_path):
    """A database written before Week 5 gains the new columns and table, keeping its rows."""
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, rule TEXT NOT NULL,
            rule_id TEXT, severity TEXT NOT NULL, title TEXT NOT NULL, src TEXT, dst TEXT, mitre TEXT, details TEXT);
        INSERT INTO alerts (ts, rule, rule_id, severity, title) VALUES (1, 'port_scan', 'DET-002', 'high', 'old');
    """)
    con.close()
    assert security_state(db)["alerts_active"] == 1  # readable before the upgrade
    open_db(db).close()
    con = sqlite3.connect(db)
    assert con.execute("SELECT status, note FROM alerts").fetchone() == ("open", None)
    assert con.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_prune_keeps_inventory(tmp_path):
    db = _db(tmp_path, [Alert(30, "port_scan", "high", "old"), Alert(130, "port_scan", "high", "new")])
    assert prune(db, before=100)["alerts"] == 1
    con = sqlite3.connect(db)
    assert [r[0] for r in con.execute("SELECT title FROM alerts")] == ["new"]
    assert con.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2


def test_reset_starts_a_fresh_log(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan")])
    Storage(db, reset=True).close()
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


# -- posture ----------------------------------------------------------------- #
def test_posture_levels(tmp_path):
    assert security_state(tmp_path / "missing.db")["posture"]["level"] == "NO DATA"
    (tmp_path / "a").mkdir()
    assert security_state(_db(tmp_path / "a", []))["posture"]["level"] == "OK"
    (tmp_path / "b").mkdir()
    db = _db(tmp_path / "b", [], status={"192.168.1.66": "pending", "192.168.1.22": "approved"})
    s = security_state(db)
    assert s["posture"]["level"] == "WATCH" and s["devices_unreviewed"] == 1
    assert "192.168.1.66" in s["posture"]["reasons"][0]
    (tmp_path / "c").mkdir()
    db = _db(tmp_path / "c", [Alert(70, "suspicious_port", "critical", "irc", src="192.168.1.22"),
                              Alert(71, "port_scan", "high", "scan", src="192.168.1.66", dst="192.168.1.22")])
    assert security_state(db)["posture"]["level"] == "CRITICAL"
    set_alert_status(db, [1], "false_positive")
    assert security_state(db)["posture"]["level"] == "AT RISK"
    set_alert_status(db, [2], "acknowledged")  # acknowledged is still active
    assert security_state(db)["posture"]["level"] == "AT RISK"
    set_alert_status(db, [2], "resolved")
    s = security_state(db)
    assert s["posture"]["level"] == "OK" and s["alerts"] == 2 and s["alerts_active"] == 0


def test_device_risk_weights_source_over_destination(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan", src="192.168.1.66", dst="192.168.1.22"),
                        Alert(71, "new_device", "medium", "new", src="192.168.1.66", dst="192.168.1.66")])
    risky = security_state(db)["risky_devices"]
    assert [(d["ips"], d["alerts"], d["score"], d["top_severity"]) for d in risky] == [
        ("192.168.1.66", 2, 7.0, "high"),     # 5 (src, high) + 2 (src, medium), counted once
        ("192.168.1.22", 1, 2.5, "high")]     # half of 5 as the target
    assert risky[0]["rules"] == ["DET-001", "DET-002"]


def test_sample_capture_state(sample_db):
    s = security_state(sample_db)
    assert (s["devices"], s["packets"], s["alerts"], s["high"]) == (7, 3546, 12, 6)
    assert s["posture"]["level"] == "CRITICAL"
    assert s["risky_devices"][0]["ips"] == "192.168.1.22"
    assert s["run"]["source"].endswith("iot-lab.pcap") and s["run"]["ended"] is not None
    text = render_text(s, utc=True, width=100)
    for line in ("IOT SECURITY MONITOR", "Devices monitored", "Packets analyzed                   3,546",
                 "Security alerts", "High-severity alerts", "Recent Alerts", "posture: CRITICAL"):
        assert line in text
    assert max(len(line) for line in text.splitlines()) <= 100


# -- CLI --------------------------------------------------------------------- #
def test_cli_status_alerts_and_triage(sample_db, capsys, tmp_path):
    db = ["--db", str(sample_db)]
    assert main(["status", *db, "--width", "90"]) == 0
    assert "posture: CRITICAL" in capsys.readouterr().out

    assert main(["alerts", *db, "--severity", "critical", "--json"]) == 0
    crit = json.loads(capsys.readouterr().out)
    assert [a["rule_id"] for a in crit] == ["DET-004"]

    assert main(["alerts", "fp", str(crit[0]["id"]), "--note", "lab test", *db]) == 0
    assert main(["alerts", "ack", "999", *db]) == 1
    capsys.readouterr()
    assert main(["alerts", "list", *db, "--status", "false_positive"]) == 0
    out = capsys.readouterr().out
    assert "false_positive" in out and "note: lab test" in out
    assert main(["status", *db, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["posture"]["level"] == "AT RISK"

    out_csv = tmp_path / "a.csv"
    assert main(["alerts", "export", *db, "--rule", "port_scan", "-o", str(out_csv)]) == 0
    rows = list(csv.DictReader(out_csv.open(encoding="utf-8")))
    assert [r["rule_id"] for r in rows] == ["DET-002", "DET-002"] and rows[0]["timestamp"] < rows[1]["timestamp"]
    assert isinstance(json.loads(rows[0]["details"]), dict)

    assert main(["db", "info", *db]) == 0
    out = capsys.readouterr().out
    assert f"schema     version {SCHEMA_VERSION}" in out and "iot-lab.pcap" in out


# -- dashboard API ----------------------------------------------------------- #
def test_dashboard_state_filters_and_triage(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan", src="192.168.1.66"),
                        Alert(71, "new_device", "medium", "new", src="192.168.1.66"),
                        Alert(72, "traffic_spike", "high", "spike", src="192.168.1.22")])
    client = create_app(db).test_client()
    s = client.get("/api/state").get_json()
    assert s["posture"]["level"] == "AT RISK" and s["high_active"] == 2 and s["read_only"] is False
    assert [a["id"] for a in client.get("/api/alerts?severity=high").get_json()] == [3, 1]
    assert [a["id"] for a in client.get("/api/alerts?rule=DET-001").get_json()] == [2]
    assert [a["id"] for a in client.get("/api/alerts?ip=192.168.1.22").get_json()] == [3]

    r = client.post("/api/alerts/3", json={"status": "false_positive", "note": "backup job"})
    assert r.status_code == 200 and r.get_json()["status"] == "false_positive"
    assert [a["id"] for a in client.get("/api/alerts?status=active").get_json()] == [2, 1]
    assert client.post("/api/alerts/3", json={"status": "bogus"}).status_code == 400
    assert client.post("/api/alerts/42", json={"status": "resolved"}).status_code == 404
    # cross-site protection: no form posts, no foreign origins
    assert client.post("/api/alerts/1", data={"status": "resolved"}).status_code == 415
    assert client.post("/api/alerts/1", json={"status": "resolved"},
                       headers={"Origin": "http://evil.example"}).status_code == 403

    rows = list(csv.DictReader(io.StringIO(client.get("/api/alerts.csv?status=false_positive").get_data(as_text=True))))
    assert [(r["id"], r["note"]) for r in rows] == [("3", "backup job")]
    assert client.get("/api/runs").get_json()[0]["source"] == "unit"
    assert b"Devices monitored" in client.get("/").data


def test_read_only_dashboard(tmp_path):
    db = _db(tmp_path, [Alert(70, "port_scan", "high", "scan")])
    client = create_app(db, read_only=True).test_client()
    assert client.post("/api/alerts/1", json={"status": "resolved"}).status_code == 403
    assert client.get("/api/state").get_json()["read_only"] is True
    assert b"const READ_ONLY = true" in client.get("/").data
